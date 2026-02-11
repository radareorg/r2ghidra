/* r2ghidra - LGPL - Copyright 2019-2022 - thestr4ng3r, pancake */

#include "R2TypeFactory.h"
#include "R2Architecture.h"
#include "fspec.hh"

#include <r_core.h>
#include <cctype>
#include <cstring>
#include <sstream>

// Compatibility for older radare2 versions that don't have these type kinds
#ifndef R_TYPE_BASIC
#define R_TYPE_BASIC 0
#endif
#ifndef R_TYPE_FUNCTION
#define R_TYPE_FUNCTION 5
#endif

// TODO(full-type-resolution):
// - Handle declarators that need identifier placement (arrays, function pointers) when wrapping r_anal_cparse.
// - Improve base-type signedness/alias mapping (size_t, ssize_t, uintptr_t, etc).
// - Prefer structured r2 type APIs over raw sdb parsing when available.
// - Add caching to avoid repeated type parsing/conversion.
// - Drop manual libc arg typing in tests once r2 auto-applies known signatures (printf, malloc, strcmp, ...).
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

static std::string to_lower_ascii(const std::string &in) {
	std::string out;
	out.reserve(in.size());
	for (unsigned char ch : in) {
		out.push_back(static_cast<char>(std::tolower(ch)));
	}
	return out;
}

static bool ends_with(const std::string &str, const std::string &suffix) {
	if (suffix.size() > str.size()) {
		return false;
	}
	return str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

static bool parse_bits_suffix(const std::string &name, const std::string &prefix, int4 &size_out) {
	if (!r_str_startswith(name.c_str(), prefix.c_str())) {
		return false;
	}
	std::string rest = name.substr(prefix.size());
	if (ends_with(rest, "_t")) {
		rest = rest.substr(0, rest.size() - 2);
	}
	if (rest.empty()) {
		return false;
	}
	for (char ch : rest) {
		if (!std::isdigit(static_cast<unsigned char>(ch))) {
			return false;
		}
	}
	int bits = std::stoi(rest);
	if (bits <= 0 || (bits % 8) != 0) {
		return false;
	}
	size_out = bits / 8;
	return true;
}

struct BuiltinTypeSpec {
	int4 size = 0;
	type_metatype meta = TYPE_UNKNOWN;
};

static bool get_builtin_spec(const R2TypeFactory *factory, const std::string &name, BuiltinTypeSpec &spec) {
	const std::string lower = to_lower_ascii(name);

	if (lower == "size_t" || lower == "uintptr_t") {
		spec.size = factory->getSizeOfPointer();
		spec.meta = TYPE_UINT;
		return true;
	}
	if (lower == "ssize_t" || lower == "intptr_t" || lower == "ptrdiff_t") {
		spec.size = factory->getSizeOfPointer();
		spec.meta = TYPE_INT;
		return true;
	}
	if (lower == "bool" || lower == "_bool") {
		spec.size = 1;
		spec.meta = TYPE_BOOL;
		return true;
	}
	if (lower == "wchar_t") {
		spec.size = factory->getSizeOfWChar();
		spec.meta = TYPE_INT;
		return true;
	}
	if (lower == "uchar") {
		spec.size = factory->getSizeOfChar();
		spec.meta = TYPE_UINT;
		return true;
	}
	if (lower == "schar") {
		spec.size = factory->getSizeOfChar();
		spec.meta = TYPE_INT;
		return true;
	}
	if (lower == "ulonglong") {
		spec.size = 8;
		spec.meta = TYPE_UINT;
		return true;
	}
	if (lower == "longlong") {
		spec.size = 8;
		spec.meta = TYPE_INT;
		return true;
	}

	int4 size = 0;
	if (parse_bits_suffix(lower, "uint", size) ||
		parse_bits_suffix(lower, "ut", size) ||
		parse_bits_suffix(lower, "u", size)) {
		spec.size = size;
		spec.meta = TYPE_UINT;
		return true;
	}
	if (parse_bits_suffix(lower, "int", size) ||
		parse_bits_suffix(lower, "st", size) ||
		parse_bits_suffix(lower, "s", size)) {
		spec.size = size;
		spec.meta = TYPE_INT;
		return true;
	}

	std::stringstream ss(lower);
	std::string token;
	bool is_unsigned = false;
	bool is_signed = false;
	bool is_short = false;
	bool is_char = false;
	bool is_int = false;
	bool is_float = false;
	bool is_double = false;
	bool is_bool = false;
	bool is_wchar = false;
	int long_count = 0;
	while (ss >> token) {
		if (token == "const" || token == "volatile" || token == "restrict") {
			continue;
		}
		if (token == "unsigned") {
			is_unsigned = true;
			continue;
		}
		if (token == "signed") {
			is_signed = true;
			continue;
		}
		if (token == "short") {
			is_short = true;
			continue;
		}
		if (token == "long") {
			long_count++;
			continue;
		}
		if (token == "char") {
			is_char = true;
			continue;
		}
		if (token == "int") {
			is_int = true;
			continue;
		}
		if (token == "float") {
			is_float = true;
			continue;
		}
		if (token == "double") {
			is_double = true;
			continue;
		}
		if (token == "bool" || token == "_bool") {
			is_bool = true;
			continue;
		}
		if (token == "wchar_t") {
			is_wchar = true;
			continue;
		}
		return false;
	}

	if (is_bool) {
		spec.size = 1;
		spec.meta = TYPE_BOOL;
		return true;
	}
	if (is_wchar) {
		spec.size = factory->getSizeOfWChar();
		spec.meta = TYPE_INT;
		return true;
	}
	if (is_float || is_double) {
		spec.meta = TYPE_FLOAT;
		if (is_float) {
			spec.size = 4;
		} else if (long_count > 0) {
			spec.size = 16;
		} else {
			spec.size = 8;
		}
		return true;
	}
	if (is_char) {
		spec.size = factory->getSizeOfChar();
		spec.meta = is_unsigned ? TYPE_UINT : TYPE_INT;
		return true;
	}
	if (is_short) {
		spec.size = 2;
		spec.meta = is_unsigned ? TYPE_UINT : TYPE_INT;
		return true;
	}
	if (long_count >= 2) {
		spec.size = 8;
		spec.meta = is_unsigned ? TYPE_UINT : TYPE_INT;
		return true;
	}
	if (long_count == 1) {
		spec.size = factory->getSizeOfLong();
		spec.meta = is_unsigned ? TYPE_UINT : TYPE_INT;
		return true;
	}
	if (is_int || is_unsigned || is_signed) {
		spec.size = factory->getSizeOfInt();
		spec.meta = is_unsigned ? TYPE_UINT : TYPE_INT;
		return true;
	}
	return false;
}

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
	if (n.empty()) {
		return nullptr;
	}
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
	if (r == nullptr && n.empty()) {
		int4 fallback_size = (sz > 0) ? sz : 1;
		return getBase(fallback_size, TYPE_UNKNOWN);
	}
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
	// Fallback to a basic type if the type cannot be resolved
	if (r == nullptr) {
		int4 fallback_size = (sz > 0) ? sz : getSizeOfInt();
		r = getBase(fallback_size, TYPE_INT);
		if (r) {
			std::stringstream ss;
			ss << "Unable to resolve type '" << n << "', using int" << (fallback_size * 8) << "_t instead";
			arch->addWarning(ss.str());
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
