/* r2ghidra - LGPL - Copyright 2019-2022 - thestr4ng3r, pancake */

#include "R2TypeFactory.h"
#include "R2Architecture.h"
#include "fspec.hh"

#include <r_core.h>
#include <cstring>
#include <sstream>

// Compatibility for older radare2 versions that don't have these type kinds
#ifndef R_TYPE_BASIC
#define R_TYPE_BASIC 0
#endif
#ifndef R_TYPE_FUNCTION
#define R_TYPE_FUNCTION 5
#endif

// Use radare2's C type parsing API (r_type_parse_ctype) for builtin types
#define R2G_USE_CTYPE 1
#include "R2Utils.h"

R2TypeFactory::R2TypeFactory(R2Architecture *arch) : TypeFactory (arch), arch (arch) {
}

R2TypeFactory::~R2TypeFactory() {
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

static std::string trim_ws(const std::string &in) {
	const auto start = in.find_first_not_of(" \t\n\r");
	if (start == std::string::npos) {
		return "";
	}
	const auto end = in.find_last_not_of(" \t\n\r");
	return in.substr(start, end - start + 1);
}

static std::string normalize_ws(const std::string &in) {
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
}

// Struct to hold builtin type info
struct BuiltinTypeSpec {
	int4 size = 0;
	type_metatype meta = TYPE_UNKNOWN;
};

#if R2_ABIVERSION >= 55
// Use radare2's r_type_parse_ctype API (r2 >= 5.9.9)
static bool get_builtin_spec(const R2TypeFactory *factory, const std::string &name, BuiltinTypeSpec &spec) {
	int ptr_size = factory->getSizeOfPointer();
	int long_size = factory->getSizeOfLong();
	int int_size = factory->getSizeOfInt();
	RTypeCTypeInfo *info = r_type_parse_ctype (name.c_str(), ptr_size, long_size, int_size);
	if (info) {
		spec.size = info->size;
		switch (info->base) {
		case R_TYPE_CTYPE_INT:
			spec.meta = info->sign ? TYPE_INT : TYPE_UINT;
			break;
		case R_TYPE_CTYPE_FLOAT:
			spec.meta = TYPE_FLOAT;
			break;
		case R_TYPE_CTYPE_VOID:
			spec.meta = TYPE_VOID;
			break;
		default:
			spec.meta = TYPE_UNKNOWN;
			break;
		}
		free (info);
		return true;
	}
	return false;
}
#else
static bool get_builtin_spec(const R2TypeFactory *factory, const std::string &name, BuiltinTypeSpec &spec) {
	return false;
}
#endif

static Datatype *make_typedef(R2TypeFactory *factory, Datatype *base, const std::string &name) {
	Datatype *typedefd = factory->getTypedef(base, name, 0, 0);
	factory->setName(typedefd, name);
	factory->setName(base, base->getName());
	return typedefd;
}

static std::string make_tmp_typename(const std::string &type_str) {
	ut32 hash = r_str_hash(type_str.c_str());
	std::stringstream ss;
	ss << "__r2ghidra_t_" << std::hex << hash;
	return ss.str();
}

Datatype *R2TypeFactory::queryR2Base(const string &n) {
	RCoreLock core(arch->getCore());
	Sdb *sdb = core->anal->sdb_types;
	int4 size = 0;
	type_metatype meta = TYPE_UNKNOWN;
	BuiltinTypeSpec builtin;
	if (get_builtin_spec(this, n, builtin)) {
		size = builtin.size;
		meta = builtin.meta;
	} else {
		ut64 bits = r_type_get_bitsize(sdb, n.c_str());
		if (!bits || (bits % 8) != 0) {
			return nullptr;
		}
		size = bits / 8;
		meta = formatToMeta(r_type_format(sdb, n.c_str()));
	}
	Datatype *base = getBase(size, meta);
	if (!base && meta != TYPE_UNKNOWN) {
		base = getBase(size, TYPE_UNKNOWN);
	}
	if (!base) {
		return nullptr;
	}
	return make_typedef(this, base, n);
}

Datatype *R2TypeFactory::queryR2Struct(const string &n, std::set<std::string> &stackTypes) {
	RCoreLock core(arch->getCore ());
	Sdb *sdb = core->anal->sdb_types;

	// TODO: We REALLY need an API for this in r2
	const char *members = sdb_const_get (sdb, ("struct." + n).c_str (), nullptr);
	if (!members) {
		const char *alias = sdb_const_get (sdb, ("typedef." + n).c_str (), nullptr);
		return alias ? queryR2Typedef(n, stackTypes) : nullptr;
	}
	struct FieldInfo {
		std::string name;
		Datatype *type;
		int4 offset;
		FieldInfo() : type(nullptr), offset(0) {}
	};
	std::vector<FieldInfo> fieldInfos;
	std::vector<TypeField> fields;
	bool relayout = false;
	int4 lastOffset = -1;
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
			int4 align = memberType->getAlignment();
			if (align > 1 && (offset % align) != 0) {
				relayout = true;
			}
			if (lastOffset >= 0 && offset < lastOffset) {
				relayout = true;
			}
			lastOffset = offset;
			FieldInfo info;
			info.name = memberName;
			info.type = memberType;
			info.offset = offset;
			fieldInfos.push_back(info);
		}

		if (fieldInfos.empty ()) {
			arch->addWarning ("Struct " + n + " has no fields.");
			return nullptr;
		}
		if (relayout) {
			arch->addWarning ("Struct " + n + " has unaligned offsets; re-layouting fields.");
			int4 off = 0;
			for (auto &fi : fieldInfos) {
				int4 align = fi.type ? fi.type->getAlignment() : 1;
				if (align <= 0) {
					align = 1;
				}
				int4 rem = off % align;
				if (rem) {
					off += (align - rem);
				}
				fi.offset = off;
				if (fi.type) {
					off += fi.type->getSize();
				}
			}
		}
		for (const auto &fi : fieldInfos) {
			TypeField tf = {
				fi.offset, // id = offset by default
				fi.offset,
				fi.name,
				fi.type
			};
			fields.push_back(tf);
		}
		int4 maxAlign = 1;
		int4 structSize = 0;
		for (const auto &tf : fields) {
			if (tf.type) {
				int4 a = tf.type->getAlignment();
				if (a > maxAlign) {
					maxAlign = a;
				}
				int4 end = tf.offset + tf.type->getSize();
				if (end > structSize) {
					structSize = end;
				}
			}
		}
		if (maxAlign > 0) {
			int4 rem = structSize % maxAlign;
			if (rem) {
				structSize += (maxAlign - rem);
			}
		}
		setFields (fields, r, structSize, maxAlign, 0);
		return r;
	} catch (std::invalid_argument &e) {
		arch->addWarning ("Failed to load struct " + n + " from sdb.");
		return nullptr;
	}
}

Datatype *R2TypeFactory::queryR2Union(const string &n, std::set<std::string> &stackTypes) {
	RCoreLock core(arch->getCore ());
	Sdb *sdb = core->anal->sdb_types;

	const char *members = sdb_const_get (sdb, ("union." + n).c_str (), nullptr);
	std::string prefix = "union.";
	if (!members) {
		members = sdb_const_get (sdb, ("struct." + n).c_str (), nullptr);
		prefix = "struct.";
	}
	if (!members) {
		const char *alias = sdb_const_get (sdb, ("typedef." + n).c_str (), nullptr);
		return alias ? queryR2Typedef(n, stackTypes) : nullptr;
	}
	std::vector<TypeField> fields;
	try {
		TypeUnion *r = getTypeUnion(n);
		std::stringstream membersStream(members);
		std::string memberName;
		while(std::getline(membersStream, memberName, SDB_RS)) {
			const char *memberContents = sdb_const_get(sdb, (prefix + n + "." + memberName).c_str(), nullptr);
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
				arch->addWarning ("Failed to match type " + memberTypeName + " of member " + memberName + " in union " + n);
				continue;
			}
			if (elements > 0) {
				memberType = getTypeArray (elements, memberType);
			}
			TypeField tf = {
				(int4)offset,
				(int4)offset,
				memberName,
				memberType
			};
			fields.push_back(tf);
		}

		if (fields.empty ()) {
			arch->addWarning ("Union " + n + " has no fields.");
			return nullptr;
		}
		int4 maxAlign = 1;
		int4 unionSize = 0;
		for (const auto &tf : fields) {
			if (tf.type) {
				int4 a = tf.type->getAlignment();
				if (a > maxAlign) {
					maxAlign = a;
				}
				int4 sz = tf.type->getSize();
				if (sz > unionSize) {
					unionSize = sz;
				}
			}
		}
		if (maxAlign > 0) {
			int4 rem = unionSize % maxAlign;
			if (rem) {
				unionSize += (maxAlign - rem);
			}
		}
		setFields (fields, r, unionSize, maxAlign, 0);
		return r;
	} catch (std::invalid_argument &e) {
		arch->addWarning ("Failed to load union " + n + " from sdb.");
		return nullptr;
	}
}

Datatype *R2TypeFactory::queryR2Enum(const string &n, std::set<std::string> &stackTypes) {
	RCoreLock core (arch->getCore ());
	RList *members = r_type_get_enum (core->anal->sdb_types, n.c_str ());
	if (!members) {
		Sdb *sdb = core->anal->sdb_types;
		const char *alias = sdb_const_get (sdb, ("typedef." + n).c_str (), nullptr);
		return alias ? queryR2Typedef(n, stackTypes) : nullptr;
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

Datatype *R2TypeFactory::queryR2Function(const string &n, std::set<std::string> &stackTypes) {
	RCoreLock core(arch->getCore());
	Sdb *sdb = core->anal->sdb_types;

	const char *ret = r_type_func_ret(sdb, n.c_str());
	int arg_count = r_type_func_args_count(sdb, n.c_str());
	if (!ret && arg_count <= 0) {
		return nullptr;
	}

	PrototypePieces proto;
	if (!arch->defaultfp) {
		return getTypeCode();
	}
	proto.model = arch->defaultfp;
	proto.name = n;
	proto.firstVarArgSlot = -1;
	proto.outtype = ret ? fromCString(ret, nullptr, &stackTypes) : getTypeVoid();
	if (!proto.outtype) {
		proto.outtype = getTypeVoid();
	}

	for (int i = 0; i < arg_count; i++) {
		char *arg_type = r_type_func_args_type(sdb, n.c_str(), i);
		if (arg_type && !strcmp(arg_type, "...")) {
			proto.firstVarArgSlot = proto.intypes.size();
			free(arg_type);
			continue;
		}

		Datatype *arg = nullptr;
		if (arg_type && *arg_type) {
			arg = fromCString(arg_type, nullptr, &stackTypes);
		}
		if (!arg) {
			arg = getBase(1, TYPE_UNKNOWN);
		}
		proto.intypes.push_back(arg);

		const char *arg_name = r_type_func_args_name(sdb, n.c_str(), i);
		proto.innames.push_back(arg_name ? arg_name : "");

		if (arg_type) {
			free(arg_type);
		}
	}

	return getTypeCode(proto);
}

Datatype *R2TypeFactory::queryR2Typedef(const string &n, std::set<std::string> &stackTypes) {
	RCoreLock core(arch->getCore());
	Sdb *sdb = core->anal->sdb_types;
	const char *target = sdb_const_get (sdb, ("typedef." + n).c_str (), nullptr);
	if(!target) {
		return nullptr;
	}
	if (r_str_startswith(target, "func.")) {
		std::string func_name = target + strlen("func.");
		Datatype *resolved = queryR2Function(func_name, stackTypes);
		if (!resolved) {
			return nullptr;
		}
		Datatype *typedefd = getTypedef (resolved, n, 0, 0);
		setName (typedefd, n); // this removes the old name from the nametree
		setName (resolved, resolved->getName()); // add the old name back
		return typedefd;
	}
	Datatype *resolved = fromCString (target, nullptr, &stackTypes);
	if (!resolved) {
		return nullptr;
	}
	Datatype *typedefd = getTypedef (resolved, n, 0, 0);
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
	case R_TYPE_BASIC:
		return queryR2Base(n);
	case R_TYPE_STRUCT:
		return queryR2Struct (n, stackTypes);
	case R_TYPE_UNION:
		return queryR2Union (n, stackTypes);
	case R_TYPE_ENUM:
		return queryR2Enum (n, stackTypes);
	case R_TYPE_TYPEDEF:
		return queryR2Typedef (n, stackTypes);
	case R_TYPE_FUNCTION:
		return queryR2Function (n, stackTypes);
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
			n.rfind("union ", 0) == 0 ||
			n.rfind("func.", 0) == 0;
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
	std::set<std::string> localStack;
	std::set<std::string> *stack = stackTypes ? stackTypes : &localStack;
	std::string type_str = normalize_ws(trim_ws(str));
	if (type_str.empty()) {
		return nullptr;
	}

	if (r_str_startswith(type_str.c_str(), "func.")) {
		std::string func_name = type_str.substr(strlen("func."));
		Datatype *fn = queryR2Function(func_name, *stack);
		if (fn) {
			return fn;
		}
	}

	auto strip_prefix = [](std::string &in, const std::string &prefix) {
		if (in.rfind(prefix, 0) == 0) {
			in = in.substr(prefix.size());
			return true;
		}
		return false;
	};

	std::string manual = type_str;
	int ptr_depth = 0;
	while (!manual.empty()) {
		manual = trim_ws(manual);
		if (!manual.empty() && manual.back() == '*') {
			manual.pop_back();
			ptr_depth++;
			continue;
		}
		break;
	}

	bool stripped = true;
	while (stripped) {
		stripped = false;
		stripped |= strip_prefix(manual, "const ");
		stripped |= strip_prefix(manual, "volatile ");
	}
	manual = normalize_ws(trim_ws(manual));

	if (manual.rfind("struct ", 0) == 0) {
		manual = trim_ws(manual.substr(sizeof("struct ") - 1));
	} else if (manual.rfind("enum ", 0) == 0) {
		manual = trim_ws(manual.substr(sizeof("enum ") - 1));
	} else if (manual.rfind("union ", 0) == 0) {
		manual = trim_ws(manual.substr(sizeof("union ") - 1));
	}

	Datatype *base = nullptr;
	if (manual == "void") {
		base = getTypeVoid();
	} else {
		base = findByName(manual, *stack);
		if (!base) {
			base = queryR2(manual, *stack);
		}
		if (!base) {
			BuiltinTypeSpec builtin;
			if (get_builtin_spec(this, manual, builtin)) {
				Datatype *builtin_base = getBase(builtin.size, builtin.meta);
				if (!builtin_base && builtin.meta != TYPE_UNKNOWN) {
					builtin_base = getBase(builtin.size, TYPE_UNKNOWN);
				}
				if (builtin_base) {
					base = make_typedef(this, builtin_base, manual);
				}
			}
		}
	}
	if (base) {
		auto space = arch->getDefaultCodeSpace();
		Datatype *result = base;
		for (int i = 0; i < ptr_depth; i++) {
			result = getTypePointer(space->getAddrSize(), result, space->getWordSize());
		}
		return result;
	}

	std::string parse_error;
#if R2G_USE_CTYPE
	std::string tmp_name = make_tmp_typename(type_str);
	{
		RCoreLock core(arch->getCore());
		if (r_type_kind(core->anal->sdb_types, tmp_name.c_str()) == R_TYPE_INVALID) {
			std::string decl = "typedef " + type_str + " " + tmp_name + ";";
			char *error_cstr = nullptr;
			char *out = r_anal_cparse(core->anal, decl.c_str(), &error_cstr);
			if (out) {
				r_anal_save_parsed_type(core->anal, out);
				free(out);
			}
			if (error_cstr) {
				parse_error = error_cstr;
				free(error_cstr);
			}
		}
	}
	Datatype *parsed = queryR2(tmp_name, *stack);
	if (parsed) {
		return parsed;
	}
#endif
	if (error) {
		*error = !parse_error.empty() ? parse_error : "Unknown type identifier " + manual;
	}
	return nullptr;
}
