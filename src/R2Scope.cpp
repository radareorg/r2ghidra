/* r2ghidra- LGPL - Copyright 2019-2026 - thestr4ng3r, pancake, 0verflowme */

#include "R2Architecture.h"
#include "R2TypeFactory.h"
#include "R2Scope.h"

#include <functional>
#include <funcdata.hh>

#include <r_version.h>
#include <r_anal.h>
#include <r_core.h>

#include "R2Utils.h"

R2Scope::R2Scope(R2Architecture *arch)
		: Scope (0, "", arch, this),
		  arch (arch),
		  cache (new ScopeInternal (0, "radare2-internal", arch, this)),
		  next_id (new uint8) {
	*next_id = 1;
}

R2Scope::~R2Scope() {
	delete cache;
}

Scope *R2Scope::buildSubScope(uint8 id, const string &nm) {
	return new ScopeInternal(id, nm, arch);
}

static std::string hex(ut64 v) {
	std::stringstream ss;
	ss << "0x" << std::hex << v;
	return ss.str ();
}

static Element *child(Element *el, const std::string &name, const std::map<std::string, std::string> &attrs = {}) {
	auto child = new Element (el);
	child->setName (name);
	el->addChild (child);
	for (const auto &attr : attrs) {
		child->addAttribute (attr.first, attr.second);
	}
	return child;
}

static Element *childAddr(Element *el, const std::string &name, const Address &addr) {
	return child(el, name, {
		{ "space", addr.getSpace()->getName () },
		{ "offset", hex(addr.getOffset ()) }
	});
}

static Element *childType(Element *el, Datatype *type) {
	auto pointer = dynamic_cast<TypePointer *>(type);
	if (pointer) {
		Element *r = child (el, "type", {
			{ "name", type->getName () },
			{ "size", to_string (pointer->getSize ()) },
			{ "metatype", "ptr" }
		});
		childType (r, pointer->getPtrTo ());
		return r;
	}

	auto array = dynamic_cast<TypeArray *>(type);
	if (array) {
		Element *r = child (el, "type", {
			{ "name", "" },
			{ "size", to_string (array->getSize ()) },
			{ "arraysize", to_string (array->numElements ()) },
			{ "metatype", "array" }
		});
		childType (r, array->getBase());
		return nullptr;
	}

	return child (el, "typeref", {
		{ "name", type->getName () },
		{ "id", hex (type->getId ()) }
	});
}

static std::string to_string(const char *str) {
	return std::string (str ? str : "(null)");
}

static bool is_structured_type(Datatype *type) {
	if (!type) {
		return false;
	}
	if (Datatype *td = type->getTypedef()) {
		return is_structured_type(td);
	}
	if (type->isEnumType()) {
		return true;
	}
	switch (type->getMetatype()) {
	case TYPE_STRUCT:
	case TYPE_UNION:
		return true;
	default:
		break;
	}
	if (auto ptr = dynamic_cast<TypePointer *>(type)) {
		return is_structured_type(ptr->getPtrTo());
	}
	if (auto arr = dynamic_cast<TypeArray *>(type)) {
		return is_structured_type(arr->getBase());
	}
	return false;
}

struct FunctionVars {
	RCore *core;
	R2Architecture *arch;
	RAnalFunction *fcn;
	ProtoModel *proto;
	int4 extraPop;
	int default_size;
	ParamActive params;
	RangeList ranges;
	std::map<RAnalVar *, Datatype *> types;
	bool have_arg_vars = false, enabled;

	FunctionVars(RCore *core, R2Architecture *arch, RAnalFunction *fcn, ProtoModel *proto, int4 extraPop, int default_size)
		: core (core), arch (arch), fcn (fcn), proto (proto), extraPop (extraPop), default_size (default_size),
		  params (false), enabled (r_config_get_b (core->config, "r2ghidra.vars")) {
		collect ();
	}
	int4 paramSize(RAnalVar *var, Datatype *type) const {
		int4 size = type->getSize ();
		return var->kind == R_ANAL_VAR_KIND_REG && size < default_size ? default_size : size;
	}
	Datatype *varType(RAnalVar *var) {
		std::string typeError;
		Datatype *type = var->type ? arch->getTypeFactory ()->fromCString (var->type, &typeError) : nullptr;
		if (!type) {
			arch->addWarning ("Failed to match type " + to_string (var->type) + " for variable " + to_string (var->name) + " to Decompiler type: " + typeError);
			type = arch->types->getBase (default_size, TYPE_UNKNOWN);
		}
		if (type && type->getSize () < 1) {
			arch->addWarning ("Type " + type->getName () + " of variable " + to_string (var->name) + " has size 0");
			return nullptr;
		}
		return type;
	}
	Address addr(RAnalVar *var, bool warn_on_fail) {
		switch (var->kind) {
		case R_ANAL_VAR_KIND_BPV:
		{
			auto stackSpace = arch->getStackSpace ();
			int delta = var->delta + fcn->bp_off - extraPop;
			uintb off = delta >= 0 ? delta : stackSpace->getHighest () + delta + 1;
			return Address (stackSpace, off);
		}
		case R_ANAL_VAR_KIND_REG:
		{
			RRegItem *reg = r_reg_index_get (core->anal->reg, var->delta);
			if (!reg) {
				if (warn_on_fail) {
					arch->addWarning ("Register for arg " + to_string (var->name) + " not found");
				}
				return Address ();
			}
			auto ret = arch->registerAddressFromR2Reg (reg->name);
			if (ret.isInvalid () && warn_on_fail) {
				arch->addWarning ("Failed to match register " + to_string (var->name) + " for arg " + to_string (var->name));
			}
			return ret;
		}
		case R_ANAL_VAR_KIND_SPV:
			if (warn_on_fail) {
				arch->addWarning ("Var " + to_string (var->name) + " is stack pointer based, which is not supported for decompilation.");
			}
			return Address ();
		default:
			if (warn_on_fail) {
				arch->addWarning ("Failed to get address for var " + to_string (var->name));
			}
			return Address ();
		}
	}
	template<typename Callback>
	void foreachVar(Callback cb) {
		if (!enabled) {
			return;
		}
		for (RAnalVarKind kind : { R_ANAL_VAR_KIND_REG, R_ANAL_VAR_KIND_BPV, R_ANAL_VAR_KIND_SPV }) {
			RAnalVar **it;
			R_VEC_FOREACH (&fcn->vars, it) {
				RAnalVar *var = *it;
				if (var && var->kind == kind) {
					cb (var);
				}
			}
		}
	}
	void collect() {
		foreachVar ([&](RAnalVar *var) {
			Datatype *type = varType (var);
			if (!type) {
				return;
			}
			types[var] = type;
			if (!var->isarg) {
				return;
			}
			have_arg_vars = true;
			Address a = addr (var, true);
			if (a.isInvalid ()) {
				return;
			}
			int4 size = paramSize (var, type);
			params.registerTrial (a, size);
			int4 i = params.whichTrial (a, size);
			params.getTrial (i).markActive ();
			params.getTrial (i).markUsed ();
		});
	}
	bool overlaps(Address &a, uintb last) const {
		for (const auto &range : ranges) {
			if (range.getSpace () == a.getSpace () && range.getFirst () <= last && range.getLast () >= a.getOffset ()) {
				return true;
			}
		}
		return false;
	}
	int4 paramIndex(Address &a, int4 size, RAnalVar *var) {
		if (proto && !proto->possibleInputParam (a, size)) {
			arch->addWarning ("Removing arg " + to_string (var->name) + " because it doesn't fit into ProtoModel");
			return -1;
		}
		int4 trialIndex = params.whichTrial (a, size);
		if (trialIndex < 0) {
			arch->addWarning ("Failed to determine arg index of " + to_string (var->name));
			return -1;
		}
		int4 index = 0;
		for (int4 i = 0; i < trialIndex; i++) {
			if (params.getTrial (i).isUsed ()) {
				index++;
			}
		}
		return index;
	}
	Element *emitSymbol(Element *symbollistElement, const std::string &name, Datatype *type, const Address &a,
			const char *typelock, const char *readonly, const char *cat, int4 index,
			bool add_reg_range, const std::function<void(Element *)> &childRegRange) {
		auto mapsymElement = child (symbollistElement, "mapsym");
		auto symbolElement = child (mapsymElement, "symbol", {
			{ "name", name },
			{ "typelock", typelock },
			{ "namelock", "true" },
			{ "readonly", readonly },
			{ "cat", cat }
		});
		if (index >= 0) {
			symbolElement->addAttribute ("index", to_string (index));
		}
		childType (symbolElement, type);
		childAddr (mapsymElement, "addr", a);
		auto rangelist = child (mapsymElement, "rangelist");
		if (add_reg_range) {
			childRegRange (rangelist);
		}
		return symbolElement;
	}
	void emit(Element *symbollistElement, bool used_sig_args, const std::function<void(Element *)> &childRegRange) {
		std::vector<Element *> argsByIndex;
		foreachVar ([&](RAnalVar *var) {
			if (used_sig_args && var->isarg) {
				return;
			}
			auto it = types.find (var);
			if (it == types.end ()) {
				return;
			}
			Datatype *type = it->second;
			Address a = addr (var, var->isarg);
			if (a.isInvalid ()) {
				return;
			}
			uintb last = a.getOffset () + type->getSize () - 1;
			if (last < a.getOffset ()) {
				arch->addWarning ("Variable " + to_string (var->name) + " extends beyond the stackframe. Try changing its type to something smaller.");
				return;
			}
			bool typelock = true;
			if (overlaps (a, last)) {
				arch->addWarning ("Detected overlap for variable " + to_string (var->name));
				if (var->isarg) {
					return;
				}
				typelock = false;
			}

			int4 index = var->isarg ? paramIndex (a, paramSize (var, type), var) : -1;
			if (var->isarg && index < 0) {
				return;
			}
			ranges.insertRange (a.getSpace (), a.getOffset (), last);

			Element *symbolElement = emitSymbol (symbollistElement, var->name, type, a,
				typelock ? "true" : "false", "true", var->isarg ? "0" : "-1", index,
				var->isarg && var->kind == R_ANAL_VAR_KIND_REG, childRegRange);
			if (var->isarg) {
				if (argsByIndex.size () < index + 1) {
					argsByIndex.resize (index + 1, nullptr);
				}
				argsByIndex[index] = symbolElement;
			}
		});
		emitPlaceholders (symbollistElement, argsByIndex, childRegRange);
	}
	void emitPlaceholders(Element *symbollistElement, const std::vector<Element *> &argsByIndex,
			const std::function<void(Element *)> &childRegRange) {
		for (size_t i = 0; i < argsByIndex.size (); i++) {
			if (argsByIndex[i]) {
				continue;
			}
			auto trial = params.getTrial (i);
			Datatype *type = arch->types->getBase (trial.getSize (), TYPE_UNKNOWN);
			if (!type) {
				continue;
			}
			emitSymbol (symbollistElement, "noname_" + to_string (i), type, trial.getAddress (),
				"true", "false", "0", i, trial.getAddress ().getSpace () != arch->translate->getStackSpace (),
				childRegRange);
		}
	}
};

#if R2_ABIVERSION >= 50
struct SigArg {
	std::string name;
	Datatype *type;
};

static Datatype *resolveFunctionSignatureReturnType(R2Architecture *arch, const char *fcn_name) {
	Datatype *sig_ret_type = nullptr;

	RCoreLock core_lock (arch->getCore ());
	Sdb *tdb = core_lock->anal->sdb_types;
	char *fname = r_type_func_guess (tdb, fcn_name);
	if (fname && r_type_func_exist (tdb, fname)) {
		const char *ret_name = r_type_func_ret (tdb, fname);
		if (R_STR_ISNOTEMPTY (ret_name)) {
			std::string typeError;
			sig_ret_type = arch->getTypeFactory ()->fromCString (ret_name, &typeError);
			if (!sig_ret_type) {
				arch->addWarning ("Failed to match return type " + to_string (ret_name) + " for function " + to_string (fcn_name) + ": " + typeError);
			}
		}
	}
	free (fname);

	return sig_ret_type;
}

// Helper function to process function signature from radare2's type database
// and emit parameter symbols to the decompiler
static void processFunctionSignature(
	R2Architecture *arch,
	const char *fcn_name,
	ProtoModel *proto,
	int default_size,
	Datatype *sig_ret_type,
	bool have_arg_vars,
	Element *symbollistElement,
	RangeList &varRanges,
	bool &used_sig_args,
	bool &have_sig_proto,
	PrototypePieces &sig_proto,
	std::function<void(Element *)> childRegRange)
{
	std::vector<SigArg> sig_args;
	int4 sig_first_vararg = -1;

	{
		RCoreLock core_lock (arch->getCore ());
		Sdb *tdb = core_lock->anal->sdb_types;
		char *fname = r_type_func_guess (tdb, fcn_name);
		if (fname && r_type_func_exist (tdb, fname)) {
			const int argc = r_type_func_args_count (tdb, fname);
			for (int i = 0; i < argc; i++) {
				char *arg_type = r_type_func_args_type (tdb, fname, i);
				if (!arg_type) {
					continue;
				}
				std::string arg_type_str = arg_type;
				free (arg_type);
				if (arg_type_str == "...") {
					sig_first_vararg = i;
					break;
				}

				const char *arg_name = r_type_func_args_name (tdb, fname, i);
				std::string name = (R_STR_ISNOTEMPTY (arg_name))
					? std::string (arg_name)
					: ("arg" + to_string (i));

				std::string typeError;
				Datatype *type = arch->getTypeFactory ()->fromCString (arg_type_str.c_str (), &typeError);
				if (!type) {
					arch->addWarning ("Failed to match arg type " + arg_type_str + " for function " + to_string (fcn_name) + ": " + typeError);
					type = arch->types->getBase (default_size, TYPE_UNKNOWN);
				}
				if (type && type->getSize () > 0) {
					sig_args.push_back ({name, type});
				}
			}
		}
		free (fname);
	}

	if (sig_args.empty ()) {
		return;
	}

	PrototypePieces protoPieces;
	protoPieces.model = proto;
	protoPieces.name = fcn_name;
	protoPieces.outtype = sig_ret_type ? sig_ret_type : arch->types->getBase (default_size, TYPE_UNKNOWN);
	protoPieces.firstVarArgSlot = sig_first_vararg;
	for (const auto &arg : sig_args) {
		protoPieces.intypes.push_back (arg.type);
		protoPieces.innames.push_back (arg.name);
	}
	bool sig_has_structured = is_structured_type (protoPieces.outtype);
	if (!sig_has_structured) {
		for (const auto &arg : sig_args) {
			if (is_structured_type (arg.type)) {
				sig_has_structured = true;
				break;
			}
		}
	}
	have_sig_proto = sig_has_structured;
	if (have_sig_proto) {
		sig_proto = protoPieces;
	}

	std::vector<ParameterPieces> pieces;
	try {
		proto->assignParameterStorage (protoPieces, pieces, true);
	} catch (const LowlevelError &err) {
		arch->addWarning ("Failed to assign parameter storage for " + to_string (fcn_name) + ": " + err.explain);
		pieces.clear ();
	}

	bool sig_has_stack = false;
	for (size_t i = 1; i < pieces.size (); i++) {
		auto &piece = pieces[i];
		if (piece.flags & ParameterPieces::hiddenretparm) {
			continue;
		}
		if (piece.addr.isInvalid ()) {
			continue;
		}
		if (piece.addr.getSpace () == arch->translate->getStackSpace ()) {
			sig_has_stack = true;
			break;
		}
	}
	if (!pieces.empty () && !(sig_has_stack && have_arg_vars)) {
		used_sig_args = true;
	}
	if (used_sig_args) {
		size_t sig_index = 0;
		for (size_t i = 1; i < pieces.size () && sig_index < sig_args.size (); i++) {
			auto &piece = pieces[i];
			if (piece.flags & ParameterPieces::hiddenretparm) {
				continue;
			}
			if (piece.addr.isInvalid ()) {
				continue;
			}

			const auto &arg = sig_args[sig_index++];
			auto mapsymElement = child (symbollistElement, "mapsym");
			auto symbolElement = child (mapsymElement, "symbol", {
				{ "name", arg.name },
				{ "typelock", "true" },
				{ "namelock", "true" },
				{ "readonly", "true" },
				{ "cat", "0" },
				{ "index", to_string (sig_index - 1) }
			});

			childType (symbolElement, arg.type);
			childAddr (mapsymElement, "addr", piece.addr);

			uintb last = piece.addr.getOffset ();
			if (arg.type && arg.type->getSize () > 0) {
				last += arg.type->getSize () - 1;
			}
			if (last >= piece.addr.getOffset ()) {
				varRanges.insertRange (piece.addr.getSpace (), piece.addr.getOffset (), last);
			}

			auto rangelist = child (mapsymElement, "rangelist");
			if (piece.addr.getSpace () != arch->translate->getStackSpace ()) {
				childRegRange (rangelist);
			}
		}
	}
}
#endif

FunctionSymbol *R2Scope::registerFunction(RAnalFunction *fcn) const {
	// lol globals
	RCoreLock core (arch->getCore ());

	const char *archName = r_config_get (core->config, "asm.arch");
	if (archName != nullptr && !strcmp (archName, "r2ghidra")) {
		archName = r_config_get (core->config, "asm.cpu");
	}
	const std::string r2Arch (archName);

	// We use xml here, because the public interface for Functions
	// doesn't let us set up the scope parenting as we need it :-(

	Document doc;
	doc.setName ("mapsym");

	if (fcn->bits == 16 && !r2Arch.compare ("arm")) {
		ContextDatabase *cdb = arch->getContextDatabase ();
		cdb->setVariable ("TMode", Address (arch->getDefaultCodeSpace (), fcn->addr), 1);
	}

	const char *fcn_name = fcn->name;
	if (core->flags->realnames) {
		const RList *flags = r_flag_get_list (core->flags, fcn->addr);
		if (flags) {
			RListIter *iter;
			void *pos;
			r_list_foreach (flags, iter, pos) {
				auto flag = reinterpret_cast<RFlagItem *>(pos);
				if (flag->space && flag->space->name && !strcmp(flag->space->name, R_FLAGS_FS_SECTIONS)) {
					continue;
				}
				// if (!strcmp(flag->name, fcn->name) && flag->realname && *flag->realname)
				if (R_STR_ISNOTEMPTY (flag->realname)) {
					fcn_name = flag->realname;
					break;
				}
			}
		}
	}

	auto functionElement = child (&doc, "function", {
		{ "name", fcn_name },
		{ "size", "1" },
		{ "id", hex (makeId()) }
	});

	childAddr (functionElement, "addr", Address(arch->getDefaultCodeSpace(), fcn->addr));

	auto localDbElement = child (functionElement, "localdb", {
		{ "lock", "false" },
		{ "main", "stack" }
	});

	auto scopeElement = child(localDbElement, "scope", {
		{ "name", fcn_name }
	});

	auto parentElement = child(scopeElement, "parent", {
		{"id", hex (uniqueId)}
	});
	child (parentElement, "val");
	child (scopeElement, "rangelist");

	auto symbollistElement = child(scopeElement, "symbollist");

#define CALLCONV(x) (x)->callconv
	ProtoModel *proto = CALLCONV(fcn) ? arch->protoModelFromR2CC(CALLCONV(fcn)) : nullptr;
	if (!proto) {
		if (CALLCONV(fcn)) {
			arch->addWarning ("Matching calling convention " + to_string(CALLCONV(fcn)) + " of function " + to_string(fcn_name) + " failed, args may be inaccurate.");
		} else {
			arch->addWarning ("Function " + to_string(fcn_name) + " has no calling convention set, args may be inaccurate.");
		}
	}

	int4 extraPop = proto ? proto->getExtraPop () : arch->translate->getDefaultSize ();
	if (extraPop == ProtoModel::extrapop_unknown) {
		extraPop = arch->translate->getDefaultSize ();
	}

	const int default_size = core->anal->config->bits / 8;
	bool used_sig_args = false;
	bool have_sig_proto = false;
	PrototypePieces sig_proto;

	FunctionVars vars (core, arch, fcn, proto, extraPop, default_size);

	if (proto) {
		proto->deriveInputMap(&vars.params);
	}

	auto childRegRange = [&](Element *e) {
		// For reg args, add a range just before the function
		// This prevents the arg to be assigned as a local variable in the decompiled function,
		// which can make the code confusing to read.
		// (Ghidra does the same)
		Address rangeAddr(arch->getDefaultCodeSpace(), fcn->addr > 0 ? fcn->addr - 1 : 0);
		child(e, "range", {
				{ "space", rangeAddr.getSpace()->getName() },
				{ "first", hex(rangeAddr.getOffset()) },
				{ "last", hex(rangeAddr.getOffset()) }
		});
	};

#if R2_ABIVERSION >= 50
	Datatype *sig_ret_type = resolveFunctionSignatureReturnType (arch, fcn_name);
	if (proto) {
		processFunctionSignature (arch, fcn_name, proto, default_size, sig_ret_type, vars.have_arg_vars,
			symbollistElement, vars.ranges, used_sig_args, have_sig_proto, sig_proto, childRegRange);
	}
#endif

	vars.emit (symbollistElement, used_sig_args, childRegRange);

	auto prototypeElement = child(functionElement, "prototype", {
		{ "extrapop", to_string(extraPop) },
		{ "model", proto ? proto->getName() : "unknown" }
	});

	Address returnAddr(arch->getSpaceByName("register"), 0);
	bool returnFound = false;
	if (proto) {
		for (auto it = proto->effectBegin (); it != proto->effectEnd(); it++) {
			if (it->getType() == EffectRecord::return_address) {
				returnAddr = it->getAddress();
				returnFound = true;
				break;
			}
		}
		//if (!returnFound)
		//	arch->addWarning("Failed to find return address in ProtoModel");
	}
	// TODO: should we try to get the return address from r2's cc?

	auto returnsymElement = child(prototypeElement, "returnsym");
	childAddr (returnsymElement, "addr", returnAddr);

#if R2_ABIVERSION >= 50
	std::string return_type_name = sig_ret_type ? sig_ret_type->getName () : "uint";
	child (returnsymElement, "typeref", {
		{ "name", return_type_name }
	});
#else
	child (returnsymElement, "typeref", {
		{ "name", "uint" }
	});
#endif

	child (&doc, "addr", {
		{ "space", arch->getDefaultCodeSpace()->getName() },
		{ "offset", hex(fcn->addr) }
	});

	child (&doc, "rangelist");

	XmlDecode dec(arch, &doc);
	auto sym = cache->addMapSym (dec);
	auto funcsym = dynamic_cast<FunctionSymbol *>(sym);
	if (funcsym && have_sig_proto && sig_proto.model) {
		Funcdata *fd = funcsym->getFunction();
		if (fd) {
			fd->getFuncProto().setPieces(sig_proto);
		}
	}
	return funcsym;
}

Symbol *R2Scope::registerFlag(RFlagItem *flag) const {
	RCoreLock core (arch->getCore ());

	uint4 attr = Varnode::namelock | Varnode::typelock;
	Datatype *type = nullptr;
	// retrieve string from r2
	if (flag->space && std::string (R_FLAGS_FS_STRINGS) == flag->space->name) {
		RBinString *str = nullptr;
		RListIter *iter;
		void *pos;
		r_list_foreach (core->bin->binfiles, iter, pos) {
			auto bf = reinterpret_cast<RBinFile *>(pos);
			RBinObject *bo = bf->bo;
			if (!bo) {
				continue;
			}

			void *s = ht_up_find (bo->strings_db, flag->addr, nullptr);
			if (s) {
				str = reinterpret_cast<RBinString *>(s);
				break;
			}
		}
		Datatype *ptype;
		const char *tn = "char";
		if (str) {
			switch (str->type) {
			case R_STRING_TYPE_WIDE:
				tn = "char16_t";
				break;
			case R_STRING_TYPE_WIDE32:
				tn = "char32_t";
				break;
			}
		}
		ptype = arch->types->findByName (tn);
		int4 sz = static_cast<int4>(flag->size) / ptype->getSize ();
		type = arch->types->getTypeArray (sz, ptype);
		attr |= Varnode::readonly;
	}

	// TODO: more types
	if (!type) {
		type = arch->types->getTypeCode();
	}

	// Check whether flags should be displayed by their real name
	const char *name = (core->flags->realnames && flag->realname) ? flag->realname : flag->name;

	const ut64 at = flag->addr;
	SymbolEntry *entry = cache->addSymbol (name, type, Address (arch->getDefaultCodeSpace(), at), Address());
	if (entry == nullptr) {
		return nullptr;
	}

	auto symbol = entry->getSymbol ();
	cache->setAttribute (symbol, attr);

	return symbol;
}

static Datatype *formatCharToType(TypeFactory *types, char fmt, int default_size) {
	switch (fmt) {
	case 'b': return types->getBase (1, TYPE_UINT);
	case 'c': return types->getBase (1, TYPE_INT);
	case 'w': return types->getBase (2, TYPE_UINT);
	case 'W': return types->getBase (2, TYPE_INT);
	case 'd': return types->getBase (4, TYPE_INT);
	case 'x': return types->getBase (4, TYPE_UINT);
	case 'i': return types->getBase (4, TYPE_INT);
	case 'q': return types->getBase (8, TYPE_INT);
	case 'Q': return types->getBase (8, TYPE_UINT);
	case 'f': return types->getBase (4, TYPE_FLOAT);
	case 'F': return types->getBase (8, TYPE_FLOAT);
	case 'p':
	case '*':
		return types->getBase (default_size, TYPE_UINT);
	default:
		return nullptr;
	}
}

Symbol *R2Scope::registerGlobalVar(RFlagItem *glob, const char *type_str) const {
	RCoreLock core (arch->getCore ());
	uint4 attr = Varnode::namelock | Varnode::typelock;

	ut64 addr = glob->addr;

	Datatype *type = nullptr;
	std::string typeError;
	const int default_size = core->anal->config->bits / 8;

	type = arch->getTypeFactory ()->fromCString (type_str, &typeError);
	if (!type && type_str && type_str[0]) {
		type = formatCharToType (arch->types, type_str[0], default_size);
	}
	if (!type) {
		arch->addWarning ("Failed to create type for global variable "
			+ to_string (glob->name) + ", using default int");
		type = arch->types->getBase (default_size, TYPE_INT);
	}
	if (!type) {
		return nullptr;
	}

	const char *name = (core->flags->realnames && glob->realname)
		? glob->realname : glob->name;
	SymbolEntry *entry = cache->addSymbol (name, type,
		Address (arch->getDefaultCodeSpace (), addr), Address ());
	if (!entry) {
		return nullptr;
	}
	auto symbol = entry->getSymbol ();
	cache->setAttribute (symbol, attr);
	return symbol;
}

Symbol *R2Scope::queryR2Absolute(ut64 addr, bool contain) const {
	RCoreLock core (arch->getCore ());

	RAnalFunction *fcn = r_anal_get_function_at (core->anal, addr);
	// This can cause functions to be registered twice (hello-arm test)
	if (!fcn && contain) {
		RList *fcns = r_anal_get_functions_in (core->anal, addr);
		if (!r_list_empty (fcns)) {
			fcn = reinterpret_cast<RAnalFunction *>(r_list_first (fcns));
		}
		r_list_free (fcns);
	}
	if (fcn) {
		return registerFunction (fcn);
	}

	RFlagItem *glob = r_anal_global_get (core->anal, addr);
	if (glob) {
		const char *type_str = r_anal_global_get_type (core->anal, addr);
		if (type_str) {
			return registerGlobalVar (glob, type_str);
		}
	}

	// TODO: correctly handle contain for flags
	const RList *flags = r_flag_get_list (core->flags, addr);
	if (flags) {
		RListIter *iter;
		void *pos;
		r_list_foreach (flags, iter, pos) {
			auto flag = reinterpret_cast<RFlagItem *>(pos);
			if (flag->space && flag->space->name && !strcmp (flag->space->name, R_FLAGS_FS_SECTIONS)) {
				continue;
			}
			return registerFlag (flag);
		}
	}
	return nullptr;
}

Symbol *R2Scope::queryR2(const Address &addr, bool contain) const {
	if (addr.getSpace() == arch->getDefaultCodeSpace() || addr.getSpace() == arch->getDefaultDataSpace()) {
		return queryR2Absolute (addr.getOffset(), contain);
	}
	return nullptr;
}

LabSymbol *R2Scope::queryR2FunctionLabel(const Address &addr) const {
	RCoreLock core (arch->getCore ());

	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr.getOffset(), R_ANAL_FCN_TYPE_NULL);
	if (!fcn) {
		return nullptr;
	}
	const char *label = r_anal_function_get_label_at (fcn, addr.getOffset());
	if (label != nullptr) {
		return cache->addCodeLabel (addr, label);
	}
	return nullptr;
}

SymbolEntry *R2Scope::findAddr(const Address &addr, const Address &usepoint) const {
	SymbolEntry *entry = cache->findAddr(addr,usepoint);
	if (entry) {
		return entry->getAddr() == addr ? entry : nullptr;
	}
	entry = cache->findContainer(addr, 1, Address());
	if (entry) { // Address is already queried, but symbol doesn't start at our address
		return nullptr;
	}
	Symbol *sym = queryR2(addr, false);
	entry = sym ? sym->getMapEntry(addr) : nullptr;

	return (entry && entry->getAddr() == addr) ? entry : nullptr;
}

SymbolEntry *R2Scope::findContainer(const Address &addr, int4 size, const Address &usepoint) const {
	SymbolEntry *entry = cache->findClosestFit (addr, size, usepoint);
	if (!entry) {
		Symbol *sym = queryR2 (addr, true);
		entry = sym ? sym->getMapEntry (addr) : nullptr;
	}
	if (entry) {
		// Entry contains addr, does it contain addr+size
		uintb last = entry->getAddr().getOffset() + entry->getSize() - 1;
		if (last < addr.getOffset() + size - 1) {
			return nullptr;
		}
	}
	return entry;
}

Funcdata *R2Scope::findFunction(const Address &addr) const {
	Funcdata *fd = cache->findFunction(addr);
	if (fd) {
		return fd;
	}
	// Check if this address has already been queried,
	// (returning a symbol other than a function_symbol)
	if (cache->findContainer(addr, 1, Address ())) {
		return nullptr;
	}
	auto at = queryR2 (addr, false);
	FunctionSymbol *sym = dynamic_cast<FunctionSymbol *>(at);
	if (sym != nullptr) {
		return sym->getFunction ();
	}
	return nullptr;
}

ExternRefSymbol *R2Scope::findExternalRef(const Address &addr) const {
	ExternRefSymbol *sym = cache->findExternalRef (addr);
	if (sym) {
		return sym;
	}
	// Check if this address has already been queried,
	// (returning a symbol other than an external ref symbol)
	if (cache->findContainer (addr, 1, Address())) {
		return nullptr;
	}
	return dynamic_cast<ExternRefSymbol *>(queryR2 (addr, false));
}

LabSymbol *R2Scope::findCodeLabel(const Address &addr) const {
	LabSymbol *sym = cache->findCodeLabel (addr);
	if (sym != nullptr) {
		return sym;
	}
	// Check if this address has already been queried,
	// (returning a symbol other than a code label)
	SymbolEntry *entry = cache->findAddr (addr, Address());
	if (entry != nullptr) {
		return queryR2FunctionLabel (addr);
	}
	return nullptr;
}

Funcdata *R2Scope::resolveExternalRefFunction(ExternRefSymbol *sym) const {
	return sym? queryFunction (sym->getRefAddr()): nullptr;
}
