/* r2ghidra - LGPL - Copyright 2019-2022 - thestr4ng3r, pancake */

#include "R2TypeFactory.h"
#include "R2Architecture.h"

#include <r_core.h>

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
	// TODO: load from r2?
	setCoreType ("void", 1, TYPE_VOID, false);
	setCoreType ("bool", 1, TYPE_BOOL, false);
	setCoreType ("uint8_t", 1, TYPE_UINT, false);
	setCoreType ("uint16_t", 2, TYPE_UINT, false);
	setCoreType ("uint32_t", 4, TYPE_UINT, false);
	setCoreType ("uint64_t", 8, TYPE_UINT, false);
	setCoreType ("char", 1, TYPE_INT, true);
	setCoreType ("int8_t", 1, TYPE_INT, false);
	setCoreType ("int16_t", 2, TYPE_INT, false);
	setCoreType ("int32_t", 4, TYPE_INT, false);
	setCoreType ("int64_t", 8, TYPE_INT, false);
	setCoreType ("float", 4, TYPE_FLOAT, false);
	setCoreType ("double", 8, TYPE_FLOAT, false);
	setCoreType ("float16", 16 ,TYPE_FLOAT, false);

	setCoreType ("uchar", 1, TYPE_UNKNOWN, false);
	setCoreType ("ushort", 2, TYPE_UNKNOWN, false);
	setCoreType ("uint", 4, TYPE_UNKNOWN, false);
	setCoreType ("ulong", 8, TYPE_UNKNOWN, false);

	setCoreType ("code", 1, TYPE_CODE, false);
	setCoreType ("wchar", 2, TYPE_INT, true);
	setCoreType ("char", 1, TYPE_INT, true);
	setCoreType ("char16_t", 2, TYPE_INT, true);
	setCoreType ("char32_t", 4, TYPE_INT, true);
	cacheCoreTypes ();
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
			fields.push_back ({
				offset,
				memberName,
				memberType
			});
		}

		if (fields.empty ()) {
			arch->addWarning ("Struct " + n + " has no fields.");
			return nullptr;
		}
		setFields (fields, r, 0, 0);
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
		setEnumValues(namelist, vallist, assignlist, enumType);
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
	Datatype *typedefd = resolved->clone ();
	setName (typedefd, n); // this removes the old name from the nametree
	setName (resolved, resolved->getName()); // add the old name back
	return typedefd;
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
	if (r != nullptr) {
		return r;
	}
	r = queryR2 (n, stackTypes);
	return (r != nullptr)? r: queryR2 (n, stackTypes);
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
	return nullptr;
#else
	return stackTypes ? findByName (str.c_str(), *stackTypes) : findByName (str.c_str ());
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
