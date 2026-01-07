/* r2ghidra- LGPL - Copyright 2019-2026 - thestr4ng3r, pancake, 0verflowme */

#include "R2Architecture.h"
#include "R2TypeFactory.h"
#include "R2Scope.h"

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

// AITODO this function is VERY large, prepare a smart strategy to reduce LOCs and complexity and split the logic into separate functions if possible

struct FunctionMetadata {
	std::string name;
	ut64 addr;
	int4 extraPop;
	ProtoModel *proto;
	Document doc;
	Element *functionElement;
	Element *symbollistElement;
	Element *prototypeElement;
	Element *returnsymElement;
};

FunctionMetadata R2Scope::processFunctionMetadata(RAnalFunction *fcn) const {
	FunctionMetadata meta;

	// lol globals
	RCoreLock core (arch->getCore ());

	const char *archName = r_config_get (core->config, "asm.arch");
	if (archName != nullptr && !strcmp (archName, "r2ghidra")) {
		archName = r_config_get (core->config, "asm.cpu");
	}
	const std::string r2Arch (archName);

	// We use xml here, because the public interface for Functions
	// doesn't let us set up the scope parenting as we need it :-(

	meta.doc.setName ("mapsym");

	if (fcn->bits == 16 && !r2Arch.compare ("arm")) {
		ContextDatabase *cdb = arch->getContextDatabase ();
		cdb->setVariable ("TMode", Address (arch->getDefaultCodeSpace (), fcn->addr), 1);
	}

	meta.name = fcn->name;
	meta.addr = fcn->addr;

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
				if (R_STR_ISNOTEMPTY (flag->realname)) {
					meta.name = flag->realname;
					break;
				}
			}
		}
	}

#if R2_VERSION_NUMBER >= 50909
#define CALLCONV(x) (x)->callconv
#else
#define CALLCONV(x) (x)->cc
#endif
	meta.proto = CALLCONV(fcn) ? arch->protoModelFromR2CC(CALLCONV(fcn)) : nullptr;
	if (!meta.proto) {
		if (CALLCONV(fcn)) {
			arch->addWarning ("Matching calling convention " + to_string(CALLCONV(fcn)) + " of function " + meta.name + " failed, args may be inaccurate.");
		} else {
			arch->addWarning ("Function " + meta.name + " has no calling convention set, args may be inaccurate.");
		}
	}

	meta.extraPop = meta.proto ? meta.proto->getExtraPop () : arch->translate->getDefaultSize ();
	if (meta.extraPop == ProtoModel::extrapop_unknown) {
		meta.extraPop = arch->translate->getDefaultSize ();
	}

	// Create basic XML structure
	meta.functionElement = child (&meta.doc, "function", {
		{ "name", meta.name },
		{ "size", "1" },
		{ "id", hex (makeId()) }
	});

	childAddr (meta.functionElement, "addr", Address(arch->getDefaultCodeSpace(), meta.addr));

	auto localDbElement = child (meta.functionElement, "localdb", {
		{ "lock", "false" },
		{ "main", "stack" }
	});

	auto scopeElement = child(localDbElement, "scope", {
		{ "name", meta.name }
	});

	auto parentElement = child(scopeElement, "parent", {
		{"id", hex (uniqueId)}
	});
	child (parentElement, "val");
	child (scopeElement, "rangelist");

	meta.symbollistElement = child(scopeElement, "symbollist");

	return meta;
}

VariableData R2Scope::processVariableData(RAnalFunction *fcn, const FunctionMetadata &meta, RangeList &varRanges) const {
	VariableData data;
	data.params = ParamActive(false);
	data.vars = nullptr;
	data.have_arg_vars = false;

	RCoreLock core (arch->getCore ());

	if (r_config_get_b (core->config, "r2ghidra.vars")) {
		data.vars = r_anal_var_all_list (core->anal, fcn);
	}
	auto stackSpace = arch->getStackSpace ();

	auto addrForVar = [&](RAnalVar *var, bool warn_on_fail) {
		switch (var->kind) {
		case R_ANAL_VAR_KIND_BPV:
		{
			uintb off;
			// For arguments passed on stack, delta is positive (based on BP)
			// For local variables, delta is negative
			// The stack space coordinates are: 0 = return address, then arguments, then locals below
			int delta = var->delta + fcn->bp_off - meta.extraPop;
			// Ensure we don't wrap around with incorrect offset calculation
			if (delta >= 0) {
				off = delta;
			} else {
				off = stackSpace->getHighest() + delta + 1;
			}
			return Address(stackSpace, off);
		}
		case R_ANAL_VAR_KIND_REG:
		{
			RRegItem *reg = r_reg_index_get(core->anal->reg, var->delta);
			if (!reg) {
				if (warn_on_fail) {
					arch->addWarning("Register for arg " + to_string(var->name) + " not found");
				}
				return Address();
			}
			auto ret = arch->registerAddressFromR2Reg(reg->name);
			if (ret.isInvalid() && warn_on_fail) {
				arch->addWarning ("Failed to match register " + to_string(var->name) + " for arg " + to_string(var->name));
			}
			return ret;
		}
		case R_ANAL_VAR_KIND_SPV:
			if (warn_on_fail) {
				arch->addWarning("Var " + to_string(var->name) + " is stack pointer based, which is not supported for decompilation.");
			}
			return Address();
		default:
			if (warn_on_fail) {
				arch->addWarning("Failed to get address for var " + to_string(var->name));
			}
			return Address();
		}
	};

	const int default_size = core->anal->config->bits / 8;

	if (data.vars) {
		r_list_foreach_cpp<RAnalVar>(data.vars, [&](RAnalVar *var) {
			std::string typeError;
			Datatype *type = var->type ? arch->getTypeFactory()->fromCString(var->type, &typeError) : nullptr;
			if (!type) {
				arch->addWarning("Failed to match type " + to_string(var->type) + " for variable " + to_string(var->name) + " to Decompiler type: " + typeError);
				type = arch->types->getBase(default_size, TYPE_UNKNOWN);
				if (!type)
					return;
			}
			if (type->getSize() < 1) {
				arch->addWarning("Type " + type->getName () + " of variable " + to_string(var->name) + " has size 0");
				return;
			}
			data.var_types[var] = type;

			if (!var->isarg) {
				return;
			}
			data.have_arg_vars = true;
			auto addr = addrForVar(var, true);
			if (addr.isInvalid()) {
				return;
			}
			int4 paramSize = type->getSize();
			if (var->kind == R_ANAL_VAR_KIND_REG && paramSize < default_size) {
				paramSize = default_size;
			}
			data.params.registerTrial(addr, paramSize);
			int4 i = data.params.whichTrial(addr, paramSize);
			data.params.getTrial(i).markActive();
			data.params.getTrial(i).markUsed();
		});
	}

	if (meta.proto) {
		meta.proto->deriveInputMap(&data.params);
	}

	return data;
}

struct SignatureData {
	bool used_sig_args;
	bool have_sig_proto;
	PrototypePieces sig_proto;
};

SignatureData R2Scope::processSignatureData(RAnalFunction *fcn, const FunctionMetadata &meta, const VariableData &varData) const {
	SignatureData sigData = {};

#if R2_ABIVERSION >= 50
	if (meta.proto) {
		struct SigArg {
			std::string name;
			Datatype *type;
		};
		std::vector<SigArg> sig_args;
		int4 sig_first_vararg = -1;
		Datatype *sig_ret_type = nullptr;

		{
			RCoreLock core_lock (arch->getCore ());
			Sdb *tdb = core_lock->anal->sdb_types;
			char *fcn_name_dup = strdup (meta.name.c_str());
			char *fname = r_type_func_guess (tdb, fcn_name_dup);
			if (fname && r_type_func_exist (tdb, fname)) {
				const char *ret_name = r_type_func_ret (tdb, fname);
				if (R_STR_ISNOTEMPTY (ret_name)) {
					std::string typeError;
					sig_ret_type = arch->getTypeFactory()->fromCString(ret_name, &typeError);
					if (!sig_ret_type) {
						arch->addWarning("Failed to match return type " + to_string(ret_name) + " for function " + meta.name);
					}
				}

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
						: ("arg" + to_string(i));

					std::string typeError;
					Datatype *type = arch->getTypeFactory()->fromCString(arg_type_str.c_str(), &typeError);
					if (type) {
						if (type->getSize() > 0) {
							sig_args.push_back({name, type});
						}
					} else {
						arch->addWarning("Failed to match arg type " + arg_type_str + " for function " + meta.name + ": " + typeError);
						type = arch->types->getBase(arch->translate->getDefaultSize(), TYPE_UNKNOWN);
					}
				}
			}
			free (fcn_name_dup);
			free (fname);
		}

		if (!sig_args.empty()) {
			PrototypePieces protoPieces;
			protoPieces.model = meta.proto;
			protoPieces.name = meta.name;
			protoPieces.outtype = sig_ret_type ? sig_ret_type : arch->types->getBase(arch->translate->getDefaultSize(), TYPE_UNKNOWN);
			protoPieces.firstVarArgSlot = sig_first_vararg;
			for (const auto &arg : sig_args) {
				protoPieces.intypes.push_back (arg.type);
				protoPieces.innames.push_back (arg.name);
			}
			bool sig_has_structured = is_structured_type(protoPieces.outtype);
			if (!sig_has_structured) {
				for (const auto &arg : sig_args) {
					if (is_structured_type(arg.type)) {
						sig_has_structured = true;
						break;
					}
				}
			}
			sigData.have_sig_proto = sig_has_structured;
			if (sigData.have_sig_proto) {
				sigData.sig_proto = protoPieces;
			}

			std::vector<ParameterPieces> pieces;
			try {
				meta.proto->assignParameterStorage (protoPieces, pieces, true);
			} catch (const LowlevelError &err) {
				arch->addWarning("Failed to assign parameter storage for " + meta.name + ": " + err.explain);
				pieces.clear();
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
				if (piece.addr.getSpace() == arch->translate->getStackSpace()) {
					sig_has_stack = true;
					break;
				}
			}
			if (!pieces.empty() && !(sig_has_stack && varData.have_arg_vars)) {
				sigData.used_sig_args = true;
			}
		}
	}
#endif

	return sigData;
}

Address R2Scope::calculateVariableAddress(RAnalVar *var, RAnalFunction *fcn, int4 extraPop) const {
	RCoreLock core (arch->getCore ());
	auto stackSpace = arch->getStackSpace ();

	switch (var->kind) {
	case R_ANAL_VAR_KIND_BPV:
	{
		uintb off;
		// For arguments passed on stack, delta is positive (based on BP)
		// For local variables, delta is negative
		// The stack space coordinates are: 0 = return address, then arguments, then locals below
		int delta = var->delta + fcn->bp_off - extraPop;
		// Ensure we don't wrap around with incorrect offset calculation
		if (delta >= 0) {
			off = delta;
		} else {
			off = stackSpace->getHighest() + delta + 1;
		}
		return Address(stackSpace, off);
	}
	case R_ANAL_VAR_KIND_REG:
	{
		RRegItem *reg = r_reg_index_get(core->anal->reg, var->delta);
		if (!reg) {
			return Address();
		}
		return arch->registerAddressFromR2Reg(reg->name);
	}
	case R_ANAL_VAR_KIND_SPV:
		return Address(); // Not supported
	default:
		return Address();
	}
}

bool R2Scope::checkVariableOverlap(const Address &addr, uint4 size, const RangeList &varRanges) const {
	for (const auto &range : varRanges) {
		if (range.getSpace() != addr.getSpace()) {
			continue;
		}
		if (range.getFirst() > (addr.getOffset() + size - 1)) {
			continue;
		}
		if (range.getLast() < addr.getOffset()) {
			continue;
		}
		return true;
	}
	return false;
}

int4 R2Scope::calculateParamIndex(const Address &addr, Datatype *type, ParamActive &params, int4 defaultSize) const {
	int4 paramSize = type->getSize();
	if (paramSize < defaultSize) {
		paramSize = defaultSize;
	}
	int4 paramTrialIndex = params.whichTrial(addr, paramSize);
	if (paramTrialIndex < 0) {
		return -1;
	}
	int4 paramIndex = 0;
	for (int4 i = 0; i < paramTrialIndex; i++) {
		if (!params.getTrial(i).isUsed()) {
			continue;
		}
		paramIndex++;
	}
	return paramIndex;
}

FunctionSymbol *R2Scope::registerFunction(RAnalFunction *fcn) const {
	// Process function metadata and create basic structure
	FunctionMetadata meta = processFunctionMetadata(fcn);

	RangeList varRanges; // to check for overlaps
	VariableData varData = processVariableData(fcn, meta, varRanges);

	// Process signature prototype if available
	SignatureData sigData = processSignatureData(fcn, meta, varData);

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

	// Handle signature-based arguments if available
#if R2_ABIVERSION >= 50
	if (sigData.used_sig_args && sigData.have_sig_proto) {
		// Build XML for signature arguments
		// This would require additional extraction logic
		// For now, continue with variable-based approach
	}
#endif
	// Process variables and build XML
	if (varData.vars) {
		std::vector<Element *> argsByIndex;
		const int default_size = arch->translate->getDefaultSize();

		r_list_foreach_cpp<RAnalVar>(varData.vars, [&](RAnalVar *var) {
			if (sigData.used_sig_args && var->isarg) {
				return;
			}
			auto type_it = varData.var_types.find(var);
			if (type_it == varData.var_types.end())
				return;
			Datatype *type = type_it->second;
			bool typelock = true;

			Address addr = calculateVariableAddress(var, fcn, meta.extraPop);
			if (addr.isInvalid()) {
				if (var->isarg) {
					arch->addWarning("Failed to get address for var " + to_string(var->name));
				}
				return;
			}

			uintb last = addr.getOffset();
			if (type->getSize() > 0) {
				last += type->getSize() - 1;
			}
			if (last < addr.getOffset()) {
				arch->addWarning("Variable " + to_string(var->name) + " extends beyond the stackframe. Try changing its type to something smaller.");
				return;
			}

			bool overlap = checkVariableOverlap(addr, type->getSize(), varRanges);
			if (overlap) {
				arch->addWarning ("Detected overlap for variable " + to_string(var->name));
				if (var->isarg) { // Can't have args with typelock=false, otherwise we get segfaults in the Decompiler
					return;
				}
				typelock = false;
			}

			int4 paramIndex = -1;
			if (var->isarg) {
				if (meta.proto && !meta.proto->possibleInputParam(addr, type->getSize())) {
					// Prevent segfaults in the Decompiler
					arch->addWarning ("Removing arg " + to_string(var->name) + " because it doesn't fit into ProtoModel");
					return;
				}
				paramIndex = calculateParamIndex(addr, type, varData.params, default_size);
				if (paramIndex < 0) {
					arch->addWarning ("Failed to determine arg index of " + to_string(var->name));
					return;
				}
			}

			varRanges.insertRange(addr.getSpace(), addr.getOffset(), last);

			auto mapsymElement = child(meta.symbollistElement, "mapsym");
			auto symbolElement = child(mapsymElement, "symbol", {
				{ "name", var->name },
				{ "typelock", typelock ? "true" : "false" },
				{ "namelock", "true" },
				{ "readonly", "true" },
				{ "cat", var->isarg ? "0" : "-1" }
			});

			if (var->isarg) {
				if (argsByIndex.size() < paramIndex + 1) {
					argsByIndex.resize(paramIndex + 1, nullptr);
				}
				argsByIndex[paramIndex] = symbolElement;
				symbolElement->addAttribute("index", to_string(paramIndex));
			}

			childType(symbolElement, type);
			childAddr(mapsymElement, "addr", addr);

			auto rangelist = child(mapsymElement, "rangelist");
			if (var->isarg && var->kind == R_ANAL_VAR_KIND_REG)
				childRegRange(rangelist);
		});

		r_list_free(varData.vars);
	}

	// Create prototype element
	meta.prototypeElement = child(meta.functionElement, "prototype", {
		{ "extrapop", to_string(meta.extraPop) },
		{ "model", meta.proto ? meta.proto->getName() : "unknown" }
	});

	// Handle return type
	Address returnAddr(arch->getSpaceByName("register"), 0);
	meta.returnsymElement = child(meta.prototypeElement, "returnsym");
	childAddr(meta.returnsymElement, "addr", returnAddr);

#if R2_ABIVERSION >= 50
	// Get return type from radare2 function signature if available
	const char *ret_type = nullptr;
	{
		RCoreLock core_lock (arch->getCore ());
		Sdb *tdb = core_lock->anal->sdb_types;
		char *fcn_name_dup = strdup (meta.name.c_str());
		char *fname = r_type_func_guess (tdb, fcn_name_dup);
		if (fname && r_type_func_exist (tdb, fname)) {
			ret_type = r_type_func_ret (tdb, fname);
		}
		free (fcn_name_dup);
		free (fname);
	}

	// Use detected return type or fall back to default
	const char *return_type_name = R_STR_ISNOTEMPTY (ret_type) ? ret_type : "uint";
	child (meta.returnsymElement, "typeref", {
		{ "name", return_type_name }
	});
#else
	child (meta.returnsymElement, "typeref", {
		{ "name", "uint" }
	});
#endif

	child (&meta.doc, "addr", {
		{ "space", arch->getDefaultCodeSpace()->getName() },
		{ "offset", hex(fcn->addr) }
	});

	child (&meta.doc, "rangelist");

	XmlDecode dec(arch, &meta.doc);
	auto sym = cache->addMapSym (dec);
	auto funcsym = dynamic_cast<FunctionSymbol *>(sym);
	if (funcsym && sigData.have_sig_proto && sigData.sig_proto.model) {
		Funcdata *fd = funcsym->getFunction();
		if (fd) {
			fd->getFuncProto().setPieces(sigData.sig_proto);
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
#if R2_VERSION_NUMBER >= 50909
			void *s = ht_up_find (bo->strings_db, flag->addr, nullptr);
#else
			void *s = ht_up_find (bo->strings_db, flag->offset, nullptr);
#endif
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

#if R2_VERSION_NUMBER >= 50909
	const ut64 at = flag->addr;
#else
	const ut64 at = flag->offset;
#endif
	SymbolEntry *entry = cache->addSymbol (name, type, Address (arch->getDefaultCodeSpace(), at), Address());
	if (entry == nullptr) {
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
	// TODO: register more things
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
	if (fcn != nullptr) {
		const char *label = r_anal_function_get_label_at (fcn, addr.getOffset());
		if (label != nullptr) {
			return cache->addCodeLabel (addr, label);
		}
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
