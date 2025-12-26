/* r2ghidra - LGPL - Copyright 2019-2022 - thestr4ng3r, pancake */

#include "R2TypeFactory.h"
#include "R2Architecture.h"

#include <r_core.h>

// TODO(full-type-resolution):
// - Enable R2G_USE_CTYPE and wire r_parse_ctype in build files.
// - Implement fromCType for arrays, function pointers, and qualifier scoping.
// - Improve base-type signedness/alias mapping (size_t, ssize_t, uintptr_t, etc).
// - Prefer structured r2 type APIs over raw sdb parsing when available.
// - Add caching to avoid repeated type parsing/conversion.
#define R2G_USE_CTYPE 0
#if R2G_USE_CTYPE
#include <r_parse.h>
#endif
#include "R2Utils.h"

R2TypeFactory::R2TypeFactory(R2Architecture *arch) : TypeFactory (arch), arch (arch) {
#if R2G_USE_CTYPE
	ctype = r_parse_ctype_new ();
	if (!ctype) {
		throw LowlevelError ("Failed to create RParseCType");
	}
#endif
}

R2TypeFactory::~R2TypeFactory() {
//	r_parse_ctype_free(ctype);
}


std::vector<std::string> splitSdbArray(const std::string& str) {
	std::stringstream ss (str);
	std::string token;
	std::vector<std::string> r;
	while (std::getline (ss, token, SDB_RS)) {
		r.push_back (token);
	}
	return r;
}

static type_metatype formatToMeta(const char *fmt) {
	if (!fmt || !fmt[0]) {
		return TYPE_UNKNOWN;
	}
	switch (fmt[0]) {
	case 'd':
	case 'i':
	case 'c':
		return TYPE_INT;
	case 'u':
	case 'x':
	case 'o':
	case 'p':
		return TYPE_UINT;
	case 'f':
	case 'F':
		return TYPE_FLOAT;
	default:
		return TYPE_UNKNOWN;
	}
}

Datatype *R2TypeFactory::queryR2Base(const string &n) {
	RCoreLock core(arch->getCore());
	Sdb *sdb = core->anal->sdb_types;
	ut64 bits = r_type_get_bitsize(sdb, n.c_str());
	if (!bits || (bits % 8) != 0) {
		return nullptr;
	}
	int4 size = bits / 8;
	type_metatype meta = formatToMeta(r_type_format(sdb, n.c_str()));
	Datatype *base = getBase(size, meta);
	if (!base && meta != TYPE_UNKNOWN) {
		base = getBase(size, TYPE_UNKNOWN);
	}
	if (!base) {
		return nullptr;
	}
	Datatype *typedefd = getTypedef(base, n, 0, 0);
	setName(typedefd, n); // ensure typedef shows up by name
	setName(base, base->getName());
	return typedefd;
}

Datatype *R2TypeFactory::queryR2Struct(const string &n, std::set<std::string> &stackTypes) {
	RCoreLock core(arch->getCore ());
	Sdb *sdb = core->anal->sdb_types;

	// TODO: We REALLY need an API for this in r2
	const char *members = sdb_const_get (sdb, ("struct." + n).c_str (), nullptr);
	if (!members) {
		return nullptr;
	}
	std::vector<TypeField> fields;
	try {
		TypeStruct *r = getTypeStruct(n);
		std::stringstream membersStream(members);
		std::string memberName;
		while(std::getline(membersStream, memberName, SDB_RS)) {
			const char *memberContents = sdb_const_get(sdb, ("struct." + n + "." + memberName).c_str(), nullptr);
			if (!memberContents) {
				continue;
			}
			auto memberTokens = splitSdbArray (memberContents);
			if (memberTokens.size() < 3) {
				continue;
			}
			auto memberTypeName = memberTokens[0];
			for (size_t i = 1; i < memberTokens.size () - 2; i++) {
				memberTypeName += "," + memberTokens[i];
			}
			int4 offset = std::stoi (memberTokens[memberTokens.size () - 2]);
			int4 elements = std::stoi (memberTokens[memberTokens.size () - 1]);
			Datatype *memberType = fromCString (memberTypeName, nullptr, &stackTypes);
			if (!memberType) {
				arch->addWarning ("Failed to match type " + memberTypeName + " of member " + memberName + " in struct " + n);
				continue;
			}
			if (elements > 0) {
				memberType = getTypeArray (elements, memberType);
			}
			TypeField tf = {
				(int4)offset, // id = offset by default
				(int4)offset, // Currently, this is 0 most of the time: member->offset,
				memberTypeName, // std::string(member->name),
				memberType
			};
                        fields.push_back(tf);
		}

		if (fields.empty ()) {
			arch->addWarning ("Struct " + n + " has no fields.");
			return nullptr;
		}
		setFields (fields, r, 0, 0, 0);
		return r;
	} catch (std::invalid_argument &e) {
		arch->addWarning ("Failed to load struct " + n + " from sdb.");
		return nullptr;
	}
}

Datatype *R2TypeFactory::queryR2Enum(const string &n) {
	RCoreLock core (arch->getCore ());
	RList *members = r_type_get_enum (core->anal->sdb_types, n.c_str ());
	if (!members) {
		return nullptr;
	}

	std::vector<std::string> namelist;
	std::vector<uintb> vallist;
	std::vector<bool> assignlist;

	r_list_foreach_cpp <RTypeEnum>(members, [&](RTypeEnum *member) {
		if (!member->name || !member->val) {
			return;
		}
		uintb val = std::stoull (member->val, nullptr, 0);
		namelist.push_back (member->name);
		vallist.push_back (val);
		assignlist.push_back (true); // all enum values from r2 have explicit values
	});
	r_list_free (members);

	if (namelist.empty()) {
		return nullptr;
	}
	try {
		auto enumType = getTypeEnum(n);
		map<uintb,string> namemap;
		TypeEnum::assignValues(namemap,namelist,vallist,assignlist,enumType);
		setEnumValues(namemap, enumType);
		return enumType;
	} catch (LowlevelError &e) {
		arch->addWarning("Failed to load " + n);
		return nullptr;
	}
}

Datatype *R2TypeFactory::queryR2Typedef(const string &n, std::set<std::string> &stackTypes) {
	RCoreLock core(arch->getCore());
	Sdb *sdb = core->anal->sdb_types;
	const char *target = sdb_const_get (sdb, ("typedef." + n).c_str (), nullptr);
	if(!target) {
		return nullptr;
	}
	Datatype *resolved = fromCString (target, nullptr, &stackTypes);
	if (!resolved) {
		return nullptr;
	}
	//Datatype *typedefd = resolved->clone ();
	Datatype *typedefd = getTypedef (resolved, n, 0, 0);
	setName (typedefd, n); // this removes the old name from the nametree
	setName (resolved, resolved->getName()); // add the old name back
	return typedefd;
	//return nullptr;
}

Datatype *R2TypeFactory::queryR2(const string &n, std::set<std::string> &stackTypes) {
	if (stackTypes.find (n) != stackTypes.end ()) {
		arch->addWarning("Recursion detected while creating type " + n);
		return nullptr;
	}
	stackTypes.insert (n);

	RCoreLock core (arch->getCore ());
	int kind = r_type_kind (core->anal->sdb_types, n.c_str ());
	switch (kind) {
	case R_TYPE_BASIC:
		return queryR2Base(n);
	case R_TYPE_STRUCT:
		return queryR2Struct (n, stackTypes);
	case R_TYPE_ENUM:
		return queryR2Enum (n);
	case R_TYPE_TYPEDEF:
		return queryR2Typedef (n, stackTypes);
	default:
		return nullptr;
	}
}

Datatype *R2TypeFactory::findById(const string &n, uint8 id, int4 sz, std::set<std::string> &stackTypes) {
	// resolve basic types
	Datatype *r = TypeFactory::findById (n, id, sz);
	if (r == nullptr) {
		r = queryR2 (n, stackTypes);
	}
	if (r == nullptr) {
		const bool needs_parse =
			n.find('*') != std::string::npos ||
			n.rfind("const ", 0) == 0 ||
			n.rfind("volatile ", 0) == 0 ||
			n.rfind("struct ", 0) == 0 ||
			n.rfind("enum ", 0) == 0 ||
			n.rfind("union ", 0) == 0;
		if (needs_parse) {
			r = fromCString (n, nullptr, &stackTypes);
		}
	}
	return r;
}

// overriden call
Datatype *R2TypeFactory::findById(const string &n, uint8 id, int4 sz) {
	std::set<std::string> stackTypes; // to detect recursion
	return findById (n, id, sz, stackTypes);
}

Datatype *R2TypeFactory::fromCString(const string &str, string *error, std::set<std::string> *stackTypes) {
#if R2G_USE_CTYPE
	char *error_cstr = nullptr;
	RParseCTypeType *type = r_parse_ctype_parse (ctype, str.c_str (), &error_cstr);
	if (error) {
		*error = error_cstr ? error_cstr : "";
	}
	if (type) {
		Datatype *r = fromCType (type, error, stackTypes);
		r_parse_ctype_type_free (type);
		return r;
	}
#else
	auto trim = [](const std::string &in) -> std::string {
		const auto start = in.find_first_not_of(" \t\n\r");
		if (start == std::string::npos) {
			return "";
		}
		const auto end = in.find_last_not_of(" \t\n\r");
		return in.substr(start, end - start + 1);
	};
	auto normalize = [](const std::string &in) -> std::string {
		std::stringstream ss(in);
		std::string token;
		std::string out;
		while (ss >> token) {
			if (!out.empty()) {
				out += " ";
			}
			out += token;
		}
		return out;
	};
	auto strip_prefix = [](std::string &in, const std::string &prefix) {
		if (in.rfind(prefix, 0) == 0) {
			in = in.substr(prefix.size());
			return true;
		}
		return false;
	};

	std::string type_str = normalize(trim(str));
	if (type_str.empty()) {
		return nullptr;
	}

	int ptr_depth = 0;
	while (!type_str.empty()) {
		type_str = trim(type_str);
		if (!type_str.empty() && type_str.back() == '*') {
			type_str.pop_back();
			ptr_depth++;
			continue;
		}
		break;
	}

	bool stripped = true;
	while (stripped) {
		stripped = false;
		stripped |= strip_prefix(type_str, "const ");
		stripped |= strip_prefix(type_str, "volatile ");
	}
	type_str = normalize(trim(type_str));

	if (type_str.rfind("struct ", 0) == 0) {
		type_str = trim(type_str.substr(sizeof("struct ") - 1));
	} else if (type_str.rfind("enum ", 0) == 0) {
		type_str = trim(type_str.substr(sizeof("enum ") - 1));
	} else if (type_str.rfind("union ", 0) == 0) {
		type_str = trim(type_str.substr(sizeof("union ") - 1));
	}

	Datatype *base = nullptr;
	if (type_str == "void") {
		base = getTypeVoid();
	} else {
		base = stackTypes ? findByName(type_str, *stackTypes) : findByName(type_str);
	}
	if (!base) {
		if (error) {
			*error = "Unknown type identifier " + type_str;
		}
		return nullptr;
	}

	auto space = arch->getDefaultCodeSpace();
	Datatype *result = base;
	for (int i = 0; i < ptr_depth; i++) {
		result = getTypePointer(space->getAddrSize(), result, space->getWordSize());
	}
	return result;
#endif
}

#if 0
Datatype *R2TypeFactory::fromCType(const RParseCTypeType *ctype, string *error, std::set<std::string> *stackTypes)
{
	switch(ctype->kind)
	{
		case R_PARSE_CTYPE_TYPE_KIND_IDENTIFIER:
		{
			if(ctype->identifier.kind == R_PARSE_CTYPE_IDENTIFIER_KIND_UNION)
			{
				if(error)
					*error = "Union types not supported in Decompiler";
				return nullptr;
			}

			Datatype *r = stackTypes ? findByName(ctype->identifier.name, *stackTypes) : findByName(ctype->identifier.name);
			if(!r)
			{
				if(error)
					*error = "Unknown type identifier " + std::string(ctype->identifier.name);
				return nullptr;
			}
			if(ctype->identifier.kind == R_PARSE_CTYPE_IDENTIFIER_KIND_STRUCT && r->getMetatype() != TYPE_STRUCT)
			{
				if(error)
					*error = "Type identifier " + std::string(ctype->identifier.name) + " is not the name of a struct";
				return nullptr;
			}
			if(ctype->identifier.kind == R_PARSE_CTYPE_IDENTIFIER_KIND_ENUM && !r->isEnumType())
			{
				if(error)
					*error = "Type identifier " + std::string(ctype->identifier.name) + " is not the name of an enum";
				return nullptr;
			}
			return r;
		}
		case R_PARSE_CTYPE_TYPE_KIND_POINTER:
		{
			Datatype *sub = fromCType(ctype->pointer.type, error, stackTypes);
			if(!sub)
				return nullptr;
			auto space = arch->getDefaultCodeSpace();
			return this->getTypePointer(space->getAddrSize(), sub, space->getWordSize());
		}
		case R_PARSE_CTYPE_TYPE_KIND_ARRAY:
		{
			Datatype *sub = fromCType(ctype->array.type, error, stackTypes);
			if(!sub)
				return nullptr;
			return this->getTypeArray(ctype->array.count, sub);
		}
	}
	return nullptr;
}
#endif
