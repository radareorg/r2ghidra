// SPDX-FileCopyrightText: 2019-2026 thestr4ng3r, pancake
// SPDX-License-Identifier: LGPL-3.0-only

#include "R2Architecture.h"
#include "R2TypeFactory.h"
#include "CodeXMLParse.h"
#include "PrettyXmlEncode.h"
#include "R2PrintC.h"
#include "SleighAsm.h"
#include "ArchMap.h"
#include "PcodeFixupPreprocessor.h"
#include "R2Utils.h"
#include "r2ghidra.h"
#include <r_core.h>

// Windows clash
#ifdef restrict
#undef restrict
#endif

#include <libdecomp.hh>

#if R2__UNIX__
#include <errno.h>
#include <sys/wait.h>
#endif

#include <vector>
#include <set>
#include <mutex>

#undef DEBUG_EXCEPTIONS

typedef bool (*ConfigVarCb)(void *user, void *data);

struct ConfigVar {
private:
	static std::vector<const ConfigVar *> vars_all;
	const std::string name;
	const char * const defval;
	const char * const desc;
	ConfigVarCb callback;
public:
	ConfigVar(const char *var, const char *defval, const char *desc, ConfigVarCb callback = nullptr)
		: name(std::string("r2ghidra") + "." + var), defval(defval), desc(desc), callback(callback) { vars_all.push_back(this); }

	const char *GetName() const { return name.c_str (); }
	const char *GetDefault () const { return defval; }
	const char *GetDesc() const { return desc; }
	ConfigVarCb GetCallback() const	{ return callback; }

	ut64 GetInt(RConfig *cfg) const	{ return r_config_get_i (cfg, name.c_str ()); }
	bool GetBool(RConfig *cfg) const { return GetInt (cfg) != 0; }
	std::string GetString(RConfig *cfg) const { return r_config_get (cfg, name.c_str ()); }
	void Set(RConfig *cfg, const char *s) const { r_config_set (cfg, name.c_str (), s); }
	static const std::vector<const ConfigVar *> &GetAll() { return vars_all; }
};

std::vector<const ConfigVar *> ConfigVar::vars_all;

std::string findGhidraCompiler(RCore *core, const char *bin_compiler);
bool SleighHomeConfig(void *user, void *data);
bool ConfigCompiler(void *user, void *data);

#define CV static const ConfigVar
CV cfg_var_sleighhome ("sleighhome",  "",         "SLEIGHHOME", SleighHomeConfig);
CV cfg_var_sleighid   ("lang",        "",         "Custom Sleigh ID to override auto-detection (e.g. x86:LE:32:default)");
CV cfg_var_anal       ("vars",        "true",     "Honor local variable / argument analysis from r2");
CV cfg_var_cmt_cpp    ("cmt.cpp",     "true",     "C++ comment style");
CV cfg_var_cmt_indent ("cmt.indent",  "4",        "Comment indent");
#if 0
CV cfg_var_nl_brace   ("nl.brace",    "false",    "Newline before opening '{'");
CV cfg_var_nl_else    ("nl.else",     "false",    "Newline before else");
#endif
CV cfg_var_indent     ("indent",      "4",        "Indent increment");
CV cfg_var_linelen    ("linelen",     "120",      "Max line length");
CV cfg_var_maximplref ("maximplref",  "2",        "Maximum number of references to an expression before showing an explicit variable.");
CV cfg_var_rawptr     ("rawptr",      "true",     "Show unknown globals as raw addresses instead of variables");
CV cfg_var_verbose    ("verbose",     "false",    "Show verbose warning messages while decompiling");
CV cfg_var_casts      ("casts",       "false",    "Show type casts where needed");
CV cfg_var_fixups     ("fixups",      "false",    "Apply pcode fixups");
CV cfg_var_varargs    ("varargs",     "false",    "Recover printf-family varargs from literal format strings");
CV cfg_var_roprop     ("roprop",      "0",        "Propagate read-only constants (0,1,2,3,4)");
CV cfg_var_timeout    ("timeout",     "0",        "Run decompilation in a separate process and kill it after a specific time");
CV cfg_var_compiler   ("compiler",    "default",  "Select compiler for calling conventions", ConfigCompiler);
CV cfg_var_apply_vars ("apply.vars",  "true",     "pdgw: apply recovered variable names and types");
CV cfg_var_apply_sig  ("apply.sig",   "true",     "pdgw: apply the recovered function signature");


static std::recursive_mutex decompiler_mutex;

class DecompilerLock {
private:
	RCore *_core;
public:
	DecompilerLock(RCore *core) : _core (core) {
		if (!decompiler_mutex.try_lock()) {
			void *bed = r_cons_sleep_begin (_core->cons);
			decompiler_mutex.lock ();
			r_cons_sleep_end (_core->cons, bed);
		}
	}

	~DecompilerLock() {
		decompiler_mutex.unlock ();
	}
};

static const char* r2ghidra_help[] = {
	"Usage: " "pdg", "", "# Native Ghidra decompiler plugin",
	"pd:g", "[?]", "# Decompile current function with the Ghidra decompiler",
	"pd:g*", "", "# Decompiled code is returned to r2 as comment",
	"pd:ga", "", "# Side by side two column disasm and decompilation",
	"pd:gd", "", "# Dump the debug XML Dump",
	"pd:gj", "", "# Dump the current decompiled function as JSON",
	"pd:go", "", "# Decompile current function side by side with offsets",
	"pd:gp", "", "# Switch to RAsm and RAnal plugins driven by SLEIGH from Ghidra",
	"pd:gs", "", "# Display loaded Sleigh Languages (alias for pdgL)",
	"pd:gsd", " N", "# Disassemble N instructions with Sleigh and print pcode",
	"pd:gss", "", "# Display automatically matched Sleigh Language ID",
	"pd:gw", "", "# Decompile and apply recovered names, types and signature into r2",
	"pd:gx", "", "# Dump the XML of the current decompiled function",
	"Environment:", "", "",
	"%SLEIGHHOME" , "", "# Path to ghidra sleigh directory (same as r2ghidra.sleighhome)",
	NULL
};
static void PrintUsage(const RCore *const core) {
	r_cons_cmd_help (core->cons, r2ghidra_help, core->print->flags & R_PRINT_FLAGS_COLOR);
}

enum class DecompileMode {
	DEFAULT,
	XML,
	DEBUG_XML,
	OFFSET,
	STATEMENTS,
	DISASM,
	JSON,
	APPLY
};

static void ApplyPrintCConfig(RConfig *cfg, PrintC *print_c) {
	if (!print_c) {
		return;
	}
	if (cfg_var_cmt_cpp.GetBool (cfg)) {
		print_c->setCPlusPlusStyleComments ();
	} else {
		print_c->setCStyleComments ();
	}
#if 0
	print_c->setSpaceAfterComma(true);
	print_c->setNewlineBeforeOpeningBrace(cfg_var_nl_brace.GetBool(cfg));
	print_c->setNewlineBeforeElse(cfg_var_nl_else.GetBool(cfg));
	print_c->setNewlineAfterPrototype(false);
#endif
	print_c->setIndentIncrement (cfg_var_indent.GetInt (cfg));
	print_c->setLineCommentIndent (cfg_var_cmt_indent.GetInt (cfg));
	print_c->setMaxLineSize (cfg_var_linelen.GetInt (cfg));
}

static void seedGlobalPointerRegister(R2Architecture &arch, RCore *core, RAnalFunction *function) {
	RArchConfig *acfg = core->rasm->config;
	const char *regname = NULL;
	ut64 value = r_config_get_i (core->config, "anal.gp");
	if (r_str_startswith (acfg->arch, "mips")) {
		// mips recomputes gp from t9 in the PIC prologue, so seed t9 (callee entry by ABI), not =GP
		regname = "t9";
		value = function->addr;
	} else {
		regname = r_reg_alias_getname (core->anal->reg, R_REG_ALIAS_GP);
		if (!regname && r_str_startswith (acfg->arch, "ppc")) {
			// ppc64 TOC base and ppc32 small-data base both live in r2
			regname = "r2";
		}
	}
	if (!regname || !value || value == UT64_MAX) {
		return;
	}
	VarnodeData reg;
	try {
		reg = arch.translate->getRegister (regname);
	} catch (const LowlevelError &) {
		return;
	}
	AddrSpace *space = arch.getDefaultCodeSpace ();
	ContextDatabase *cdb = arch.getContextDatabase ();
	r_list_foreach_cpp<RAnalBlock> (function->bbs, [&](RAnalBlock *bb) {
		TrackedSet &tset = cdb->createSet (Address (space, bb->addr), Address (space, bb->addr + bb->size));
		tset.push_back ({ reg, value });
	});
}

struct HarvestVar {
	std::string name;
	std::string type; // "" = don't retype
	std::string regName; // non-empty = register storage
	std::string regNameFull; // full-width register at the same offset (r2 vars live on the wide name)
	uintb stackOff = 0;
	bool onStack = false;
	bool nameDefined = false;
};

struct HarvestProto {
	bool valid = false;
	std::string retType; // "" = keep the current return type
	bool dotdotdot = false;
	bool noreturn = false;
	std::vector<HarvestVar> params;
};

struct Harvest {
	HarvestProto proto;
	std::vector<HarvestVar> locals;
	int4 extraPop = 0;
	uintb stackHighest = 0;
};

static bool IsGhidraAutoSuffix(const std::string &name, size_t pos) {
	return pos < name.size () && name.find_first_not_of ("0123456789abcdef", pos) == std::string::npos;
}

// generated names are not flagged undefined; match every ScopeInternal::buildVariableName pattern
static bool IsGhidraAutoName(const std::string &name) {
	if (name.compare (0, strlen ("in_"), "in_") == 0
			|| name.compare (0, strlen ("unaff_"), "unaff_") == 0
			|| name.compare (0, strlen ("extraout_"), "extraout_") == 0) {
		return true;
	}
	if (name.compare (0, strlen ("param_"), "param_") == 0) {
		return IsGhidraAutoSuffix (name, strlen ("param_"));
	}
	if (name.compare (0, strlen ("local_"), "local_") == 0) {
		return IsGhidraAutoSuffix (name, strlen ("local_"));
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
	out.regName = arch.registerNameFromAddress (a, size);
	if (out.regName.empty () && arch.translate->isBigEndian () && size > 0 && size < defaultSize) {
		// undo the BE low-order placement of sub-width register args
		out.regName = arch.registerNameFromAddress (Address (a.getSpace (), a.getOffset () - (defaultSize - size)), defaultSize);
	}
	if (size > 0 && size < defaultSize) {
		out.regNameFull = arch.registerNameFromAddress (a, defaultSize);
	}
}

// copy the recovered prototype and locals into plain data so nothing references the arch after teardown
static void HarvestFuncdata(R2Architecture &arch, Funcdata *func, Harvest &out) {
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
		if (!param->isNameUndefined () && !IsGhidraAutoName (param->getName ())) {
			hv.name = param->getName ();
			hv.nameDefined = true;
		}
		hv.type = R2TypeFactory::toCString (param->getType ());
		HarvestStorage (arch, param->getAddress (), param->getSize (), defaultSize, hv);
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
		if (!sym->isNameUndefined () && !IsGhidraAutoName (sym->getName ())) {
			hv.name = sym->getName ();
			hv.nameDefined = true;
		}
		hv.type = R2TypeFactory::toCString (sym->getType ());
		HarvestStorage (arch, entry->getAddr (), entry->getSize (), defaultSize, hv);
		if ((!hv.onStack && hv.regName.empty () && hv.regNameFull.empty ()) || (hv.type.empty () && !hv.nameDefined)) {
			continue;
		}
		out.locals.push_back (hv);
	}
}

static bool TypeParseable(RAnal *anal, const std::string &type) {
	std::string base = type;
	while (!base.empty () && (base.back () == '*' || base.back () == ' ')) {
		base.pop_back ();
	}
	if (base.empty ()) {
		return false;
	}
	if (base == "void") {
		return true;
	}
	return r_type_kind (anal->sdb_types, base.c_str ()) != R_TYPE_INVALID;
}

static RAnalVar *MatchRegVar(RCore *core, RAnalFunction *fcn, const std::string &regName) {
	if (regName.empty ()) {
		return nullptr;
	}
	RRegItem *ri = r_reg_get (core->anal->reg, regName.c_str (), -1);
	if (!ri) {
		return nullptr;
	}
	const int index = ri->index;
	r_unref (ri);
	return r_anal_function_get_var (fcn, R_ANAL_VAR_KIND_REG, index);
}

static RAnalVar *MatchVar(RCore *core, RAnalFunction *fcn, const HarvestVar &hv, const Harvest &h) {
	if (!hv.regName.empty () || !hv.regNameFull.empty ()) {
		RAnalVar *var = MatchRegVar (core, fcn, hv.regName);
		return var ? var : MatchRegVar (core, fcn, hv.regNameFull);
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

static void ApplyVar(RCore *core, RAnalFunction *fcn, const HarvestVar &hv, const Harvest &h, std::set<RAnalVar *> &seen, int *types, int *names) {
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

static bool ApplySignature(RCore *core, RAnalFunction *fcn, const Harvest &h) {
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
		R_LOG_DEBUG ("pdgw: incomplete parameter types, not applying the signature");
	}
	r_list_free (sig.params);
	r_anal_function_signature_free (cur);
	return applied;
}

static void ApplyHarvest(RCore *core, RAnalFunction *fcn, const Harvest &h) {
	int types = 0, names = 0;
	bool sig = false;
	if (cfg_var_apply_vars.GetBool (core->config)) {
		std::set<RAnalVar *> seen;
		for (const HarvestVar &hv : h.proto.params) {
			ApplyVar (core, fcn, hv, h, seen, &types, &names);
		}
		for (const HarvestVar &hv : h.locals) {
			ApplyVar (core, fcn, hv, h, seen, &types, &names);
		}
	}
	if (cfg_var_apply_sig.GetBool (core->config) && h.proto.valid) {
		sig = ApplySignature (core, fcn, h);
	}
	if (types || names || sig) {
		r_cons_printf (core->cons, "pdgw: applied %d types, %d names%s\n", types, names, sig ? ", signature" : "");
	} else {
		r_cons_printf (core->cons, "pdgw: no changes\n");
	}
}

static void Decompile(RCore *core, ut64 addr, DecompileMode mode, std::stringstream &out_stream, RCodeMeta **out_code, Harvest *out_harvest = nullptr) {
	RAnalFunction *function = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL);
	if (!function) {
		throw LowlevelError ("No function at this offset");
	}
	R2Architecture arch (core, cfg_var_sleighid.GetString (core->config));
	DocumentStorage store = DocumentStorage ();
	arch.max_implied_ref = cfg_var_maximplref.GetInt (core->config);
	arch.readonlypropagate = cfg_var_roprop.GetBool (core->config);
	arch.setRawPtr (cfg_var_rawptr.GetBool (core->config));
	arch.init (store);

	auto faddr = Address(arch.getDefaultCodeSpace (), function->addr);
	Funcdata *func = arch.symboltab->getGlobalScope ()->findFunction(faddr);
	arch.print->setOutputStream (&out_stream);
	arch.setPrintLanguage ("r2-c-language");
	auto r2c = dynamic_cast<R2PrintC *>(arch.print);
	bool showCasts = cfg_var_casts.GetBool (core->config);
	r2c->setOptionNoCasts (!showCasts);
	ApplyPrintCConfig (core->config, dynamic_cast<PrintC *>(arch.print));
	if (func == nullptr) {
		throw LowlevelError ("No function in Scope");
	}
	seedGlobalPointerRegister (arch, core, function);
	arch.getCore()->sleepBegin ();
	auto action = arch.allacts.getCurrent ();

	if (cfg_var_fixups.GetBool (core->config)) {
		PcodeFixupPreprocessor::fixupSharedReturnJumpToRelocs(function, func, core, arch);
	}
	PcodeFixupPreprocessor::fixupNoreturnCallsBeforeData(function, func, core, arch);
	PcodeFixupPreprocessor::fixupResolvedIndirectCalls(function, func, core, arch);
	if (cfg_var_varargs.GetBool (core->config)) {
		PcodeFixupPreprocessor::fixupVariadicFormatCalls(function, func, core, arch);
	}

	int res;
#ifndef DEBUG_EXCEPTIONS
	try {
#endif
		action->reset (*func);
		res = action->perform (*func);
#ifndef DEBUG_EXCEPTIONS
	} catch (const LowlevelError &error) {
		arch.getCore()->sleepEndForce ();
		throw error;
	}
#endif
	arch.getCore()->sleepEnd ();
	if (res < 0) {
		R_LOG_WARN ("break");
	}
	if (cfg_var_verbose.GetBool (core->config)) {
		for (const auto &warning : arch.getWarnings()) {
			func->warningHeader("[r2ghidra] " + warning);
		}
	}
	if (mode == DecompileMode::APPLY) {
		if (out_harvest) {
			HarvestFuncdata (arch, func, *out_harvest);
		}
		return;
	}
	switch (mode) {
	case DecompileMode::XML:
	case DecompileMode::DEFAULT:
	case DecompileMode::JSON:
	case DecompileMode::OFFSET:
	case DecompileMode::DISASM:
	case DecompileMode::STATEMENTS:
		arch.print->setMarkup(true);
		break;
	default:
		break;
	}
	if (mode == DecompileMode::XML) {
		out_stream << "<result><function>";
		{
		//func->encode (out_stream);
		//PrettyXmlEncode enc(out_stream);
		XmlEncode enc(out_stream);
		func->encode(enc, 0, true);
		}
		out_stream << "</function><code>";
	}
	switch (mode) {
	case DecompileMode::XML:
	case DecompileMode::DEFAULT:
	case DecompileMode::JSON:
	case DecompileMode::OFFSET:
	case DecompileMode::STATEMENTS:
	case DecompileMode::DISASM:
		// XXX: Can docFunction return unindented xml??
		arch.print->docFunction(func);
		if (mode != DecompileMode::XML) {
			*out_code = ParseCodeXML(func, out_stream.str().c_str ());
			if (!*out_code) {
				std::cout << out_stream.str().c_str () << std::endl;
				throw LowlevelError ("Failed to parse XML code from Decompiler");
			}
		}
		break;
	case DecompileMode::DEBUG_XML:
		{
		XmlEncode enc(out_stream);
		arch.encode(enc);
		}
		break;
	default:
		break;
	}
}

R_API RCodeMeta *r2ghidra_decompile_annotated_code(RCore *core, ut64 addr) {
	DecompilerLock lock(core);
	RCodeMeta *code = nullptr;
#ifndef DEBUG_EXCEPTIONS
	try {
#endif
		std::stringstream out_stream;
		Decompile (core, addr, DecompileMode::DEFAULT, out_stream, &code);
		return code;
#ifndef DEBUG_EXCEPTIONS
	} catch (const LowlevelError &error) {
		std::string s = "Ghidra Decompiler Error: " + error.explain;
 		code = r_codemeta_new (s.c_str ());
		// Push an annotation with: range = full string, type = error
		// For this, we have to modify RCodeMeta to have one more type; for errors
		return code;
	}
#endif
}

static void DecompileCmd (RCore *core, DecompileMode mode) {
	DecompilerLock lock(core);

#ifndef DEBUG_EXCEPTIONS
	try {
#endif
		RCodeMeta *code = nullptr;
		std::stringstream out_stream;
		Harvest harvest;
		Decompile (core, core->addr, mode, out_stream, &code, mode == DecompileMode::APPLY ? &harvest : nullptr);
		switch (mode) {
		case DecompileMode::APPLY:
			{
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->addr, R_ANAL_FCN_TYPE_NULL);
				if (fcn) {
					ApplyHarvest (core, fcn, harvest);
				}
			}
			break;
		case DecompileMode::DISASM:
			{
#if defined(R2_ABIVERSION) && R2_ABIVERSION >= 40
				RVecCodeMetaOffset *offsets = r_codemeta_line_offsets (code);
				char *s = r_codemeta_print_disasm (code, offsets, core->anal);
				r_cons_print (core->cons, s);
				free (s);
				RVecCodeMetaOffset_free (offsets);
#else
				RVector *offsets = r_codemeta_line_offsets (code);
				char *s = r_codemeta_print_disasm (code, offsets, core->anal);
				r_cons_print (core->cons, s);
				free (s);
				r_vector_free (offsets);
#endif
			}
			break;
		case DecompileMode::OFFSET:
			{
#if defined(R2_ABIVERSION) && R2_ABIVERSION >= 40
				RVecCodeMetaOffset *offsets = r_codemeta_line_offsets (code);
#if R2_VERSION_NUMBER >= 60003
				char *s = r_codemeta_print2 (code, offsets, core->anal);
#else
				char *s = r_codemeta_print (code, offsets);
#endif
				r_cons_print (core->cons, s);
				free (s);
				RVecCodeMetaOffset_free (offsets);
#else
				RVector *offsets = r_codemeta_line_offsets (code);
#if R2_VERSION_NUMBER >= 60003
				char *s = r_codemeta_print2 (code, offsets, core->anal);
#else
				char *s = r_codemeta_print (code, offsets);
#endif
				r_cons_print (core->cons, s);
				free (s);
				r_vector_free (offsets);
#endif
			}
			break;
		case DecompileMode::DEFAULT:
			{
#if R2_VERSION_NUMBER >= 60003
				char *s = r_codemeta_print2 (code, nullptr, core->anal);
#else
				char *s = r_codemeta_print (code, nullptr);
#endif
				r_cons_print (core->cons, s);
				free (s);
			}
			break;
		case DecompileMode::STATEMENTS:
			{
				char *s = r_codemeta_print_comment_cmds (code);
				r_cons_print (core->cons, s);
				free (s);
			}
			break;
		case DecompileMode::JSON:
			{
				char *s = r_codemeta_print_json (code);
				r_cons_println (core->cons, s);
				free (s);
			}
			break;
		case DecompileMode::XML:
			out_stream << "</code></result>";
			// fallthrough
		default:
			r_cons_printf (core->cons, "%s\n", out_stream.str().c_str ());
			break;
		}
		r_codemeta_free (code);
#ifndef DEBUG_EXCEPTIONS
	} catch (const LowlevelError &error) {
		std::string s = "Ghidra Decompiler Error: " + error.explain;
		if (mode == DecompileMode::JSON) {
			PJ *pj = pj_new ();
			if (pj) {
				pj_o (pj);
				pj_k (pj, "errors");
				pj_a (pj);
				pj_s (pj, s.c_str ());
				pj_end (pj);
				pj_end (pj);
				r_cons_printf (core->cons, "%s\n", pj_string (pj));
				pj_free (pj);
			}
		} else {
			R_LOG_WARN ("%s", s.c_str ());
		}
	}
#endif
}

// see sleighexample.cc
class AssemblyRaw : public AssemblyEmit {
public:
	void dump(const Address &addr, const string &mnem, const string &body) override {
		std::stringstream ss;
		addr.printRaw (ss);
		ss << ": " << mnem << ' ' << body;
		r_cons_gprintf ("%s\n", ss.str().c_str ());
	}
};

class PcodeRawOut : public PcodeEmit {
private:
	const Translate *trans = nullptr;

	void print_vardata(ostream &s, VarnodeData &data) {
		AddrSpace *space = data.space;
		if (space->getName() == "register" || space->getName() == "mem") {
			s << space->getTrans()->getRegisterName(data.space, data.offset, data.size);
		} else if (space->getName() == "ram") {
			switch (data.size) {
			case 1: s << "byte_ptr("; break;
			case 2: s << "word_ptr("; break;
			case 4: s << "dword_ptr("; break;
			case 8: s << "qword_ptr("; break;
			}
			space->printRaw(s, data.offset);
			s << ')';
		} else if (space->getName() == "const") {
			static_cast<ConstantSpace *>(space)->printRaw(s, data.offset);
		} else if (space->getName() == "unique") {
			s << '(' << data.space->getName() << ',';
			data.space->printOffset(s, data.offset);
			s << ',' << dec << data.size << ')';
		} else if (space->getName() == "DATA") {
			s << '(' << data.space->getName() << ',';
			data.space->printOffset(s,data.offset);
			s << ',' << dec << data.size << ')';
		} else {
			s << '(' << data.space->getName() << ',';
			data.space->printOffset(s, data.offset);
			s << ',' << dec << data.size << ')';
		}
	}

public:
	PcodeRawOut(const Translate *t): trans(t) {}

	void dump(const Address &addr, OpCode opc, VarnodeData *outvar, VarnodeData *vars, int4 isize) override {
		std::stringstream ss;
		bool is_store = (opc == CPUI_STORE && isize == 3);
		if (outvar) {
			print_vardata (ss,*outvar);
			ss << " = ";
		}
		ss << get_opname(opc);
		// Possibly check for a code reference or a space reference
		ss << ' ';
		int4 print_isize = is_store ? 2 : isize;
		// For indirect case in SleighBuilder::dump(OpTpl *op)'s "vn->isDynamic(*walker)" branch.
		if (print_isize > 1 && vars[0].size == sizeof(AddrSpace *) && vars[0].space->getName() == "const"
				&& (vars[0].offset >> 24) == ((uintb)vars[1].space >> 24) && trans == ((AddrSpace*)vars[0].offset)->getTrans())
		{
			ss << ((AddrSpace*)vars[0].offset)->getName();
			ss << '[';
			print_vardata (ss, vars[1]);
			ss << ']';
			for (int4 i = 2; i < print_isize; i++) {
				ss << ", ";
				print_vardata (ss, vars[i]);
			}
		} else {
			print_vardata (ss, vars[0]);
			for (int4 i = 1; i < print_isize; i++) {
				ss << ", ";
				print_vardata (ss, vars[i]);
			}
		}
		if (is_store) {
			ss << " = ";
			print_vardata (ss, vars[2]);
		}
		r_cons_gprintf ("    %s\n", ss.str().c_str ());
	}
};

static void Disassemble(RCore *core, ut64 ops) {
	if (!ops) {
		ops = 10; // random default value
	}
	R2Architecture arch (core, cfg_var_sleighid.GetString (core->config));
	DocumentStorage store;
	arch.init (store);

	const Translate *trans = arch.translate;
	PcodeRawOut emit (arch.translate);
	AssemblyRaw assememit;

	Address addr (trans->getDefaultCodeSpace(), core->addr);
	for (ut64 i = 0; i < ops; i++) {
		try {
			trans->printAssembly (assememit, addr);
			auto length = trans->oneInstruction (emit, addr);
			addr = addr + length;
		} catch (const BadDataError &error) {
			std::stringstream ss;
			addr.printRaw (ss);
			R_LOG_ERROR ("%s: invalid", ss.str ().c_str ());
			addr = addr + trans->getAlignment();
		}
	}
}

static void SetInitialSleighHome(RConfig *cfg) {
	if (!cfg_var_sleighhome.GetString (cfg).empty()) {
		return;
	}
	try {
		std::string path = SleighAsm::getSleighHome (cfg);
		cfg_var_sleighhome.Set (cfg, path.c_str ());
	} catch (LowlevelError &err) {
		// eprintf ("Cannot find sleigh in the default path\n");
	}
}

static void ListSleighLangs(RCore *core) {
	DecompilerLock lock(core);
	R2Architecture::collectSpecFiles (std::cerr);
	auto langs = R2Architecture::getLanguageDescriptions ();
	if (langs.empty()) {
		R_LOG_ERROR ("No languages available, make sure %s is set correctly!", cfg_var_sleighhome.GetName ());
		return;
	}
	std::vector<std::string> ids;
	std::transform (langs.begin(), langs.end (), std::back_inserter(ids), [](const LanguageDescription &lang) {
		return lang.getId ();
	});
	std::sort (ids.begin (), ids.end ());
	std::for_each (ids.begin (), ids.end (), [core](const std::string &id) {
		r_cons_printf (core->cons, "%s\n", id.c_str ());
	});
}

static void PrintAutoSleighLang(RCore *core) {
	DecompilerLock lock (core);
	try {
		auto id = SleighIdFromCore (core);
		r_cons_printf (core->cons, "%s\n", id.c_str ());
	} catch (LowlevelError &e) {
		R_LOG_WARN ("%s", e.explain.c_str ());
	}
}

static void EnablePlugin(RCore *core) {
	auto id = SleighIdFromCore (core);
	r_config_set (core->config, "r2ghidra.lang", id.c_str ());
	r_config_set (core->config, "asm.cpu", id.c_str ());
	r_config_set (core->config, "asm.arch", "r2ghidra");
	r_config_set (core->config, "anal.arch", "r2ghidra");
}

static void runcmd(RCore *core, const char *input) {
	switch (*input) {
	case 'd': // "pdgd"
		DecompileCmd (core, DecompileMode::DEBUG_XML);
		break;
	case '\0': // "pdg"
		DecompileCmd (core, DecompileMode::DEFAULT);
		break;
	case 'x': // "pdgx"
		DecompileCmd (core, DecompileMode::XML);
		break;
	case 'j': // "pdgj"
		DecompileCmd (core, DecompileMode::JSON);
		break;
	case 'o': // "pdgo"
		DecompileCmd (core, DecompileMode::OFFSET);
		break;
	case '*': // "pdg*"
		DecompileCmd (core, DecompileMode::STATEMENTS);
		break;
	case 'L': // "pdgL"
	case 's': // "pdgs"
		switch (input[1]) {
		case 's': // "pdgss"
			PrintAutoSleighLang (core);
			break;
		case 'd': // "pdgsd"
			Disassemble (core, r_num_math (core->num, input + 2));
			break;
		default:
			ListSleighLangs (core);
			break;
		}
		break;
	case 'a': // "pdga"
		DecompileCmd (core, DecompileMode::DISASM);
		break;
	case 'w': // "pdgw"
		DecompileCmd (core, DecompileMode::APPLY);
		break;
	case 'p': // "pdgp"
		EnablePlugin (core);
		break;
	default:
		PrintUsage (core);
		break;
	}
}

static void _cmd(RCore *core, const char *input) {
	int timeout = r_config_get_i (core->config, "r2ghidra.timeout");
	if (*input == 'w') {
		// pdgw writes into the r2 DB; a forked child would lose the writes
		runcmd (core, input);
		return;
	}
	if (timeout > 0) {
#if R2__UNIX__
		// TODO: note that first execution is slower than the rest. and forking loses the cache
		int fds[2];
		if (pipe (fds) != 0) {
			R_LOG_ERROR ("Cannot pipe");
			return;
		}
		pid_t pid = r_sys_fork ();
		if (pid < 0) {
			R_LOG_ERROR ("Cannot fork");
			return;
		}
		if (pid == 0) {
			close (fds[0]);
			runcmd (core, input);
			r_cons_flush (core->cons);
			fflush (stdout);
			write (fds[1], "\x12", 1);
			exit (0);
		} else {
			fd_set rfds;
			struct timeval tv;
			int wstatus = 0;
			tv.tv_sec = timeout / 1000;
			tv.tv_usec = (timeout - (tv.tv_sec * 1000)) * 1000;
			FD_ZERO (&rfds);
			FD_SET (fds[0], &rfds);
			// keeping our copy of the write end open would suppress eof from a crashed child until the timeout expires
			close (fds[1]);
			if (select (fds[0] + 1, &rfds, NULL, NULL, &tv) > 0) {
				char ch = 0;
				if (read (fds[0], &ch, 1) != 1 || ch != 0x12) {
					R_LOG_ERROR ("Decompiler process died unexpectedly");
				}
			} else {
				eprintf ("Timeout\n");
				kill (pid, 9);
			}
			while (waitpid (pid, &wstatus, 0) == -1 && errno == EINTR) {
			}
			fflush (stderr);
			fflush (stdout);
			close (fds[0]);
		}
#else
		R_LOG_WARN ("r2ghidra.timeout is not supported outside UNIX systems.");
		runcmd (core, input);
#endif
	} else {
		runcmd (core, input);
	}
}

extern "C" bool r2ghidra_core_cmd(RCorePluginSession *cps, const char *input) {
	RCore *core = cps->core;
	if (!strcmp (input, "pd:?")) {
		r_core_cmd_help_match (core, r2ghidra_help, (char*)"pd:g");
		return false;
	}
	if (r_str_startswith (input, "pd:g")) {
		_cmd (core, input + strlen ("pd:g"));
		return true;
	}
	// TODO: deprecate at some point
	if (r_str_startswith (input, "pdg")) {
		_cmd (core, input + strlen ("pdg"));
		return true;
	}
	return false;
}

bool ConfigCompiler(void *user, void *data) {
	RCore *core = (RCore *) user;
	std::lock_guard<std::recursive_mutex> lock(decompiler_mutex);
	auto node = reinterpret_cast<RConfigNode *>(data);
	if (!strcmp (node->value, "?")) {
		auto c = findGhidraCompiler (core, node->value);
		// eprintf ("list compilers%c", 10);
		return false;
	} else {
		auto c = findGhidraCompiler (core, node->value);
		free (node->value);
		node->value = strdup (c.c_str());
		// eprintf ("%s%c", c.c_str(), 10);
		// print c.c_str()
	}
	return true;
}

bool SleighHomeConfig(void */* user */, void *data) {
	std::lock_guard<std::recursive_mutex> lock(decompiler_mutex);
	RConfigNode *node = reinterpret_cast<RConfigNode *>(data);
	SleighArchitecture::shutdown ();
	SleighArchitecture::specpaths = FileManage ();
	if (R_STR_ISNOTEMPTY (node->value)) {
		SleighArchitecture::scanForSleighDirectories (node->value);
	}
	return true;
}

extern "C" RArchPlugin r_arch_plugin_ghidra;

extern "C" bool r2ghidra_core_init(RCorePluginSession *cps) {
	std::lock_guard<std::recursive_mutex> lock(decompiler_mutex);
	startDecompilerLibrary (nullptr);
	RCore *core = reinterpret_cast<RCore *>(cps->core);
	r_arch_plugin_add (core->anal->arch, &r_arch_plugin_ghidra);
	RConfig *cfg = core->config;
	r_config_lock (cfg, false);
	for (const auto var : ConfigVar::GetAll ()) {
		RConfigNode *node = var->GetCallback()
			? r_config_set_cb (cfg, var->GetName (), var->GetDefault (), var->GetCallback ())
			: r_config_set (cfg, var->GetName (), var->GetDefault ());
		r_config_node_desc (node, var->GetDesc ());
	}
	r_config_lock (cfg, true);
	SetInitialSleighHome (cfg);
	return true;
}

extern "C" bool r2ghidra_core_fini(RCorePluginSession *cps, const char *cmd) {
	std::lock_guard<std::recursive_mutex> lock (decompiler_mutex);
	shutdownDecompilerLibrary ();
	return true;
}
