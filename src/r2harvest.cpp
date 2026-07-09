// SPDX-FileCopyrightText: 2026 pancake
// SPDX-License-Identifier: LGPL-3.0-only

#include "r2harvest.h"
#include "R2TypeFactory.h"

#include <funcdata.hh>
#include <fspec.hh>
#include <database.hh>

#include <set>

static bool IsGhidraAutoSuffix(const std::string &name, size_t pos) {
	return pos < name.size () && name.find_first_not_of ("0123456789abcdef", pos) == std::string::npos;
}

// generated names are not flagged undefined; match every ScopeInternal::buildVariableName pattern
static bool IsGhidraAutoName(const std::string &name) {
	static const struct { const char *prefix; bool hexSuffix; } prefixes[] = {
		{ "in_", false },
		{ "unaff_", false },
		{ "extraout_", false },
		{ "param_", true },
		{ "local_", true }
	};
	for (const auto &p : prefixes) {
		const size_t n = strlen (p.prefix);
		if (name.compare (0, n, p.prefix) == 0) {
			return !p.hexSuffix || IsGhidraAutoSuffix (name, n);
		}
	}
	// type-prefixed forms like iVar1, puVar2, auStack_28, iStack_10
	for (const char *marker : { "Var", "Stack" }) {
		size_t m = name.find (marker);
		if (m == std::string::npos || name.find_first_not_of ("abcdefghijklmnopqrstuvwxyz") != m) {
			continue;
		}
		size_t pos = m + strlen (marker);
		if (pos < name.size () && name[pos] == '_') {
			pos++;
		}
		if (IsGhidraAutoSuffix (name, pos)) {
			return true;
		}
	}
	return false;
}

static void HarvestStorage(R2Architecture &arch, const Address &a, int4 size, int4 defaultSize, HarvestVar &out) {
	if (a.isInvalid ()) {
		return;
	}
	if (a.getSpace () == arch.getStackSpace ()) {
		out.onStack = true;
		out.stackOff = a.getOffset ();
		return;
	}
	std::string reg = arch.registerNameFromAddress (a, size);
	if (reg.empty () && arch.translate->isBigEndian () && size > 0 && size < defaultSize) {
		// undo the BE low-order placement of sub-width register args
		reg = arch.registerNameFromAddress (Address (a.getSpace (), a.getOffset () - (defaultSize - size)), defaultSize);
	}
	if (!reg.empty ()) {
		out.regNames.push_back (reg);
	}
	if (size > 0 && size < defaultSize) {
		// r2 vars live on the full-width register name
		std::string full = arch.registerNameFromAddress (a, defaultSize);
		if (!full.empty () && full != reg) {
			out.regNames.push_back (full);
		}
	}
}

static void FillHarvestVar(R2Architecture &arch, const std::string &name, bool nameUndefined, Datatype *type, const Address &addr, int4 size, int4 defaultSize, HarvestVar &out) {
	if (!nameUndefined && !IsGhidraAutoName (name)) {
		out.name = name;
		out.nameDefined = true;
	}
	out.type = R2TypeFactory::toCString (type);
	HarvestStorage (arch, addr, size, defaultSize, out);
}

void HarvestFuncdata(R2Architecture &arch, Funcdata *func, Harvest &out) {
	const int4 defaultSize = arch.translate->getDefaultSize ();
	out.stackHighest = arch.getStackSpace ()->getHighest ();
	FuncProto &proto = func->getFuncProto ();
	out.extraPop = proto.getExtraPop ();
	if (out.extraPop == ProtoModel::extrapop_unknown) {
		out.extraPop = defaultSize;
	}
	out.proto.valid = true;
	out.proto.dotdotdot = proto.isDotdotdot ();
	out.proto.noreturn = proto.isNoReturn ();
	out.proto.retType = R2TypeFactory::toCString (proto.getOutputType ());
	for (int4 i = 0; i < proto.numParams (); i++) {
		ProtoParameter *param = proto.getParam (i);
		if (!param || param->isHiddenReturn ()) {
			continue;
		}
		HarvestVar hv;
		FillHarvestVar (arch, param->getName (), param->isNameUndefined (), param->getType (), param->getAddress (), param->getSize (), defaultSize, hv);
		out.proto.params.push_back (hv);
	}
	ScopeLocal *scope = func->getScopeLocal ();
	if (!scope) {
		return;
	}
	for (MapIterator it = scope->begin (); it != scope->end (); ++it) {
		const SymbolEntry *entry = *it;
		if (!entry || entry->isPiece ()) {
			continue;
		}
		Symbol *sym = entry->getSymbol ();
		if (!sym || sym->getName ().empty () || sym->getCategory () != Symbol::no_category) {
			continue;
		}
		if (dynamic_cast<FunctionSymbol *> (sym) || dynamic_cast<LabSymbol *> (sym)) {
			continue;
		}
		HarvestVar hv;
		FillHarvestVar (arch, sym->getName (), sym->isNameUndefined (), sym->getType (), entry->getAddr (), entry->getSize (), defaultSize, hv);
		if ((!hv.onStack && hv.regNames.empty ()) || (hv.type.empty () && !hv.nameDefined)) {
			continue;
		}
		out.locals.push_back (hv);
	}
}

static bool TypeParseable(RAnal *anal, const std::string &type) {
	const size_t end = type.find_last_not_of ("* ");
	if (end == std::string::npos) {
		return false;
	}
	const std::string base = type.substr (0, end + 1);
	return base == "void" || r_type_kind (anal->sdb_types, base.c_str ()) != R_TYPE_INVALID;
}

static RAnalVar *MatchRegVar(RCore *core, RAnalFunction *fcn, const std::string &regName) {
	RRegItem *ri = r_reg_get (core->anal->reg, regName.c_str (), -1);
	if (!ri) {
		return nullptr;
	}
	const int index = ri->index;
	r_unref (ri);
	return r_anal_function_get_var (fcn, R_ANAL_VAR_KIND_REG, index);
}

static RAnalVar *MatchVar(RCore *core, RAnalFunction *fcn, const HarvestVar &hv, const Harvest &h) {
	if (!hv.regNames.empty ()) {
		for (const std::string &regName : hv.regNames) {
			RAnalVar *var = MatchRegVar (core, fcn, regName);
			if (var) {
				return var;
			}
		}
		return nullptr;
	}
	if (!hv.onStack) {
		return nullptr;
	}
	// invert the stack mapping from FunctionVars::addr: negative deltas wrap to the top of the stack space
	st64 gdelta = (hv.stackOff > h.stackHighest / 2)
		? (st64)hv.stackOff - (st64)h.stackHighest - 1
		: (st64)hv.stackOff;
	int delta = (int)(gdelta - fcn->bp_off + h.extraPop);
	return r_anal_function_get_var (fcn, R_ANAL_VAR_KIND_BPV, delta);
}

static void WriteVar(RCore *core, RAnalFunction *fcn, const HarvestVar &hv, const Harvest &h, std::set<RAnalVar *> &seen, int *types, int *names) {
	RAnalVar *var = MatchVar (core, fcn, hv, h);
	if (!var) {
		R_LOG_DEBUG ("pdgw: no r2 variable matches %s", hv.name.c_str ());
		return;
	}
	// params and locals can share storage; the first (param) view wins
	if (!seen.insert (var).second) {
		return;
	}
	if (!hv.type.empty () && (!var->type || hv.type != var->type)) {
		if (TypeParseable (core->anal, hv.type)) {
			r_anal_var_set_type (core->anal, var, hv.type.c_str ());
			(*types)++;
		} else {
			R_LOG_DEBUG ("pdgw: skipping unknown type %s", hv.type.c_str ());
		}
	}
	if (hv.nameDefined && var->name && hv.name != var->name) {
		if (r_anal_var_rename (core->anal, var, hv.name.c_str ())) {
			(*names)++;
		}
	}
}

static void param_free(void *p) {
	RAnalFunctionParam *fp = (RAnalFunctionParam *)p;
	if (fp) {
		free (fp->name);
		free (fp->type);
		free (fp);
	}
}

static bool WriteSignature(RCore *core, RAnalFunction *fcn, const Harvest &h) {
	RAnalFunctionSignature *cur = r_anal_function_get_signature (fcn);
	const char *curRet = (cur && R_STR_ISNOTEMPTY (cur->ret_type)) ? cur->ret_type : NULL;
	std::string ret = h.proto.retType;
	if (ret.empty () || !TypeParseable (core->anal, ret)) {
		ret = curRet ? curRet : "void";
	} else if (ret == "void" && curRet && strcmp (curRet, "void")) {
		// the decompiler demotes unused return values to void; never lose a known return type
		ret = curRet;
	}
	RAnalFunctionSignature sig = {};
	sig.ret_type = (char *)ret.c_str ();
	sig.callconv = (char *)fcn->callconv;
	sig.noreturn = h.proto.noreturn || fcn->is_noreturn;
	sig.params = r_list_newf (param_free);
	bool complete = true;
	int idx = 0;
	for (const HarvestVar &hv : h.proto.params) {
		if (hv.type.empty () || !TypeParseable (core->anal, hv.type)) {
			complete = false;
			break;
		}
		RAnalFunctionParam *fp = R_NEW0 (RAnalFunctionParam);
		std::string pname = hv.name;
		if (!hv.nameDefined) {
			RAnalVar *var = MatchVar (core, fcn, hv, h);
			pname = (var && var->name) ? var->name : "arg" + std::to_string (idx + 1);
		}
		fp->name = strdup (pname.c_str ());
		fp->type = strdup (hv.type.c_str ());
		r_list_append (sig.params, fp);
		idx++;
	}
	if (complete && h.proto.dotdotdot) {
		RAnalFunctionParam *fp = R_NEW0 (RAnalFunctionParam);
		fp->type = strdup ("...");
		r_list_append (sig.params, fp);
	}
	bool changed = !cur;
	if (complete && cur) {
		changed = !cur->ret_type || ret != cur->ret_type
			|| r_list_length (cur->params) != r_list_length (sig.params);
		for (int i = 0; !changed && i < r_list_length (sig.params); i++) {
			RAnalFunctionParam *pa = (RAnalFunctionParam *)r_list_get_n (cur->params, i);
			RAnalFunctionParam *pb = (RAnalFunctionParam *)r_list_get_n (sig.params, i);
			if (strcmp (r_str_get (pa->type), r_str_get (pb->type)) || strcmp (r_str_get (pa->name), r_str_get (pb->name))) {
				changed = true;
			}
		}
	}
	bool applied = false;
	if (complete && changed) {
		applied = r_anal_function_set_signature (core->anal, fcn, &sig);
		if (!applied) {
			R_LOG_DEBUG ("pdgw: signature rejected by the type parser");
		}
	} else if (!complete) {
		R_LOG_DEBUG ("pdgw: incomplete parameter types, not writing the signature");
	}
	r_list_free (sig.params);
	r_anal_function_signature_free (cur);
	return applied;
}

void WriteHarvest(RCore *core, RAnalFunction *fcn, const Harvest &h, bool writeVars, bool writeSig) {
	int types = 0, names = 0;
	bool sig = false;
	if (writeVars) {
		std::set<RAnalVar *> seen;
		for (const HarvestVar &hv : h.proto.params) {
			WriteVar (core, fcn, hv, h, seen, &types, &names);
		}
		for (const HarvestVar &hv : h.locals) {
			WriteVar (core, fcn, hv, h, seen, &types, &names);
		}
	}
	if (writeSig && h.proto.valid) {
		sig = WriteSignature (core, fcn, h);
	}
	if (types || names || sig) {
		R_LOG_INFO ("pdgw: wrote %d types, %d names%s", types, names, sig ? ", signature" : "");
	} else {
		R_LOG_INFO ("pdgw: no changes");
	}
}
