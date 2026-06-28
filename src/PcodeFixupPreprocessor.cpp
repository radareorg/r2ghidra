// SPDX-FileCopyrightText: 2025-2026 pancake
// SPDX-License-Identifier: LGPL-3.0-only

#include "PcodeFixupPreprocessor.h"
#include "R2LoadImage.h"
#include "R2TypeFactory.h"
#include "R2Utils.h"

#include <funcdata.hh>
#include <flow.hh>
#include <override.hh>
#include <database.hh>
#include <fspec.hh>
#include <type.hh>

#include <r_core.h>
#include <r_anal.h>
#include <r_core.h>
#include <r_bin.h>

#include <functional>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

using namespace ghidra;

static bool is_import_name(const char * R_NONNULL name) {
	return r_str_startswith (name, "imp.")
		|| r_str_startswith (name, "sym.imp.")
		|| r_str_startswith (name, "loc.imp.")
		|| r_str_startswith (name, "plt.")
		|| r_str_startswith (name, "rsym.")
		|| r_str_startswith (name, "reloc.");
}

// match any import-named flag at addr (an ARM veneer is both loc.imp.foo and rsym.foo)
static const char *import_flag_at(RCore *core, ut64 addr) {
	const RList *flags = r_flag_get_list (core->flags, addr);
	if (!flags) {
		return nullptr;
	}
	RListIter *iter;
	void *pos;
	r_list_foreach (flags, iter, pos) {
		RFlagItem *f = reinterpret_cast<RFlagItem *>(pos);
		if (f->name && is_import_name (f->name)) {
			return f->name;
		}
	}
	return nullptr;
}

// strip prefixes/version decorations to the bare libc name (sym.imp.printf, sub.printf, loc.N.plt_call.printf__GLIBC)
static std::string normalize_callee(const char *raw) {
	if (!raw) {
		return std::string ();
	}
	std::string n (raw);
	for (const char *deco : { "@@", "@", "__GLIBC" }) {
		const size_t at = n.find (deco);
		if (at != std::string::npos) {
			n.erase (at);
		}
	}
	const size_t pc = n.find (".plt_call.");
	if (pc != std::string::npos) {
		return n.substr (pc + strlen (".plt_call."));
	}
	const size_t dot = n.rfind ('.');
	return (dot != std::string::npos)? n.substr (dot + 1): n;
}

#if !defined(R2_ABIVERSION) || R2_ABIVERSION < 69
R_VEC_TYPE (RVecAnalRef, RAnalRef);
#endif

static std::string first_reg_from_values(RVecRArchValue *values) {
	RArchValue *val = RVecRArchValue_at (values, 0);
	return (val && val->reg)? std::string (val->reg): std::string ();
}

static std::string first_reg_from_opex(RAnalOp *op) {
	const char *opex = r_strbuf_get (&op->opex);
	if (R_STR_ISEMPTY (opex)) {
		return std::string ();
	}
	const char *type = strstr (opex, "\"type\":\"reg\"");
	if (!type) {
		return std::string ();
	}
	const char *value = strstr (type, "\"value\":\"");
	if (!value) {
		return std::string ();
	}
	value += strlen ("\"value\":\"");
	const char *end = strchr (value, '"');
	if (!end || end <= value) {
		return std::string ();
	}
	return std::string (value, end - value);
}

static bool op_writes_first_reg(RAnalOp *op) {
	switch (op->type & R_ANAL_OP_TYPE_MASK) {
	case R_ANAL_OP_TYPE_LOAD:
	case R_ANAL_OP_TYPE_MOV:
	case R_ANAL_OP_TYPE_ADD:
	case R_ANAL_OP_TYPE_SUB:
	case R_ANAL_OP_TYPE_LEA:
	case R_ANAL_OP_TYPE_AND:
	case R_ANAL_OP_TYPE_OR:
	case R_ANAL_OP_TYPE_XOR:
	case R_ANAL_OP_TYPE_NOT:
		return true;
	default:
		return false;
	}
}

static std::string op_first_reg(RAnalOp *op, bool dst) {
	std::string reg = first_reg_from_values (dst? &op->dsts: &op->srcs);
	if (!reg.empty ()) {
		return reg;
	}
	if (dst && !op_writes_first_reg (op)) {
		return std::string ();
	}
	return first_reg_from_opex (op);
}

static bool is_indirect_reg_call(RAnalOp *op) {
	const ut32 base_type = op->type & R_ANAL_OP_TYPE_MASK;
	return base_type == R_ANAL_OP_TYPE_UCALL && (op->type & R_ANAL_OP_TYPE_REG);
}

// per-basic-block register dataflow: track which reg holds each `defs` value (keyed by defining op addr), invoking onOp on every instruction
static void walk_bb_regflow(RCore *core, RAnalFunction *fn,
		const std::unordered_map<ut64, ut64> &defs,
		const std::function<void(RAnalOp *, std::unordered_map<std::string, ut64> &)> &onOp) {
	RListIter *iter;
	void *pos;
	r_list_foreach (fn->bbs, iter, pos) {
		RAnalBlock *bb = reinterpret_cast<RAnalBlock *> (pos);
		std::unordered_map<std::string, ut64> regs;
		for (int i = 0; i < bb->ninstr; i++) {
			ut64 at = r_anal_bb_opaddr_i (bb, i);
			RAnalOp *op = r_core_anal_op (core, at, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_VAL | R_ARCH_OP_MASK_OPEX);
			if (!op) {
				continue;
			}
			onOp (op, regs);
			std::string dst = op_first_reg (op, true);
			if (!dst.empty ()) {
				const std::string key = tolower (dst);
				auto d = defs.find (op->addr);
				if (d != defs.end ()) {
					regs[key] = d->second;
				} else {
					regs.erase (key);
				}
			}
			r_anal_op_free (op);
		}
	}
}

void PcodeFixupPreprocessor::fixupSharedReturnJumpToRelocs(RAnalFunction *r2Func, Funcdata *ghFunc, RCore *core, R2Architecture &arch) {
	RVecAnalRef *refs = r_anal_function_get_refs (r2Func);
	RAnalRef *refi;
	auto space = arch.getDefaultCodeSpace();
#if 0
	auto ops = ghFunc->getBasicBlocks();
#endif
	if (r2Func->is_noreturn) {
		ghFunc->getFuncProto().setNoReturn(true);
	}
	R_VEC_FOREACH (refs, refi) {
		const char *impname = import_flag_at (core, refi->addr);
		if (!impname) {
			continue;
		}
		RAnalOp *op = r_core_anal_op (core, refi->at, 0);
		if (!op) {
			continue;
		}
		// a tail-branch into an import veneer reads as a returning call
		if (op->type == R_ANAL_OP_TYPE_JMP) {
			Address callAddr (space, refi->at);
			R_LOG_INFO ("OverridingCallReturn %s", normalize_callee (impname).c_str ());
			ghFunc->getOverride().insertFlowOverride(callAddr, Override::CALL_RETURN);
		}
		r_anal_op_free (op);
	}
	RVecAnalRef_free (refs);
}

static bool has_data_xref_at(RCore *core, ut64 addr) {
	RVecAnalRef *xrefs = r_anal_xrefs_get (core->anal, addr);
	if (!xrefs) {
		return false;
	}
	bool found = false;
	RAnalRef *xi;
	R_VEC_FOREACH (xrefs, xi) {
		if (R_ANAL_REF_TYPE_MASK (xi->type) == R_ANAL_REF_TYPE_DATA) {
			found = true;
			break;
		}
	}
	RVecAnalRef_free (xrefs);
	return found;
}

// A call followed by a literal pool (data xref target) does not return; truncate flow so pdg stops instead of decoding the pool as code and emitting halt_baddata().
void PcodeFixupPreprocessor::fixupNoreturnCallsBeforeData(RAnalFunction *r2Func, Funcdata *ghFunc, RCore *core, R2Architecture &arch) {
	auto space = arch.getDefaultCodeSpace ();
	const ut64 fcnMax = r_anal_function_max_addr (r2Func);
	r_list_foreach_cpp<RAnalBlock> (r2Func->bbs, [&](RAnalBlock *bb) {
		ut64 addr = bb->addr;
		const ut64 bbend = bb->addr + bb->size;
		while (addr < bbend) {
			RAnalOp *op = r_core_anal_op (core, addr, R_ARCH_OP_MASK_BASIC);
			if (!op) {
				break;
			}
			const int size = op->size;
			const ut32 type = op->type & R_ANAL_OP_TYPE_MASK;
			r_anal_op_free (op);
			if (size < 1) {
				break;
			}
			const ut64 next = addr + size;
			if ((type == R_ANAL_OP_TYPE_CALL || type == R_ANAL_OP_TYPE_UCALL)
					&& next <= fcnMax && has_data_xref_at (core, next)) {
				ghFunc->getOverride ().insertFlowOverride (Address (space, addr), Override::CALL_RETURN);
			}
			addr = next;
		}
	});
}

void PcodeFixupPreprocessor::fixupResolvedIndirectCalls(RAnalFunction *r2Func, Funcdata *ghFunc, RCore *core, R2Architecture &arch) {
	RVecAnalRef *refs = r_anal_function_get_refs (r2Func);
	if (!refs) {
		return;
	}

	std::unordered_map<ut64, ut64> icod_refs;
	RAnalRef *refi;
	R_VEC_FOREACH (refs, refi) {
		if (R_ANAL_REF_TYPE_MASK (refi->type) == R_ANAL_REF_TYPE_ICOD && refi->addr != UT64_MAX) {
			icod_refs[refi->at] = refi->addr;
		}
	}
	if (icod_refs.empty ()) {
		RVecAnalRef_free (refs);
		return;
	}
	RVecAnalRef_free (refs);

	auto space = arch.getDefaultCodeSpace ();
	walk_bb_regflow (core, r2Func, icod_refs,
		[&](RAnalOp *op, std::unordered_map<std::string, ut64> &regs) {
			if (!is_indirect_reg_call (op)) {
				return;
			}
			auto target = regs.find (tolower (op_first_reg (op, false)));
			if (target != regs.end ()) {
				ghFunc->getOverride ().insertIndirectOverride (
					Address (space, op->addr),
					Address (space, target->second));
			}
		});
}

static bool is_printf_family(const char *name) {
	static const char *fam[] = { "printf", "fprintf", "sprintf", "snprintf", "dprintf" };
	for (const char *f : fam) {
		if (!strcmp (name, f)) {
			return true;
		}
	}
	return false;
}

static std::string resolve_callee_name(RCore *core, ut64 target) {
	const char *imp = import_flag_at (core, target);
	if (imp) {
		return normalize_callee (imp);
	}
	RAnalFunction *f = r_anal_get_fcn_in (core->anal, target, R_ANAL_FCN_TYPE_NULL);
	if (f && f->name) {
		return normalize_callee (f->name);
	}
	return std::string ();
}

struct VariadicSig {
	int firstVararg = -1;
	std::vector<std::string> fixedTypes;
	std::vector<std::string> fixedNames;
	std::string ret;
};

static bool parse_variadic_sig(Sdb *tdb, const char *callee, VariadicSig &sig) {
	char *fname = r_type_func_guess (tdb, callee);
	if (!fname) {
		return false;
	}
	bool ok = false;
	if (r_type_func_exist (tdb, fname)) {
		const int argc = r_type_func_args_count (tdb, fname);
		for (int i = 0; i < argc; i++) {
			// the vararg slot is stored as `,...` so the "..." marker lands in the name, not the type
			const char *an = r_type_func_args_name (tdb, fname, i);
			char *at = r_type_func_args_type (tdb, fname, i);
			const bool isVararg = (an && !strcmp (an, "...")) || (at && !strcmp (at, "..."));
			if (isVararg) {
				sig.firstVararg = i;
				free (at);
				break;
			}
			sig.fixedTypes.push_back (at? at: "");
			sig.fixedNames.push_back (R_STR_ISNOTEMPTY (an)? std::string (an): ("arg" + std::to_string (i)));
			free (at);
		}
		if (sig.firstVararg >= 0) {
			const char *r = r_type_func_ret (tdb, fname);
			sig.ret = r? r: "";
			ok = true;
		}
	}
	free (fname);
	return ok;
}

static bool read_format_string(RCore *core, ut64 addr, std::string &out) {
	const char *mstr = r_meta_get_string (core->anal, R_META_TYPE_STRING, addr);
	if (mstr) {
		char *raw = strdup (mstr);
		if (!raw) {
			return false;
		}
		r_str_unescape (raw);
		out = raw;
		free (raw);
		return true;
	}
	char buf[512];
	if (!r_io_read_at (core->io, addr, (ut8 *) buf, sizeof (buf) - 1)) {
		return false;
	}
	buf[sizeof (buf) - 1] = 0;
	int i = 0;
	for (; i < (int) sizeof (buf) - 1; i++) {
		const unsigned char c = (unsigned char) buf[i];
		if (c == 0) {
			break;
		}
		if (c != '\t' && c != '\n' && c != '\r' && (c < 0x20 || c > 0x7e)) {
			return false;
		}
	}
	if (i == 0 || buf[i] != 0) {
		return false;
	}
	out.assign (buf, i);
	return true;
}

// false on any conversion we can't model, so the caller skips the override
static bool parse_format_conversions(const char *fmt, std::vector<std::string> &out) {
	for (const char *p = fmt; *p; p++) {
		if (*p != '%') {
			continue;
		}
		p++;
		if (*p == '%') {
			continue;
		}
		if (*p == '\0') {
			return false;
		}
		const char *q = p;
		while (*q >= '0' && *q <= '9') {
			q++;
		}
		if (*q == '$') {
			return false; // positional %m$ unsupported
		}
		while (*p && strchr ("-+ #0'", *p)) {
			p++;
		}
		if (*p == '*') {
			out.push_back ("int");
			p++;
		} else {
			while (*p >= '0' && *p <= '9') {
				p++;
			}
		}
		if (*p == '.') {
			p++;
			if (*p == '*') {
				out.push_back ("int");
				p++;
			} else {
				while (*p >= '0' && *p <= '9') {
					p++;
				}
			}
		}
		int isize = 4;     // default-promoted int
		bool longdbl = false;
		if (*p == 'h') {
			p++;
			if (*p == 'h') {
				p++;
			}
		} else if (*p == 'l') {
			p++;
			if (*p == 'l') {
				p++;
				isize = 8;
			} else {
				isize = 0; // long
			}
		} else if (*p == 'L') {
			p++;
			longdbl = true;
		} else if (*p == 'j' || *p == 'q') {
			p++;
			isize = 8;
		} else if (*p == 'z' || *p == 't') {
			p++;
			isize = 0;
		}
		switch (*p) {
		case 'd': case 'i':
			out.push_back (isize == 8? "long long": isize == 0? "long": "int");
			break;
		case 'u': case 'o': case 'x': case 'X':
			out.push_back (isize == 8? "unsigned long long": isize == 0? "unsigned long": "unsigned int");
			break;
		case 'c':
			out.push_back ("int");
			break;
		case 's':
			out.push_back ("char *");
			break;
		case 'p':
			out.push_back ("void *");
			break;
		case 'n':
			out.push_back ("int *");
			break;
		case 'f': case 'F': case 'e': case 'E': case 'g': case 'G': case 'a': case 'A':
			out.push_back (longdbl? "long double": "double");
			break;
		default:
			return false;
		}
	}
	return true;
}

static FuncProto *build_locked_proto(R2Architecture &arch, const char *cc, const char *callee,
		const VariadicSig &sig, const std::vector<std::string> &convs) {
	ProtoModel *model = cc? arch.protoModelFromR2CC (cc): nullptr;
	if (!model) {
		model = arch.defaultfp;
	}
	if (!model) {
		return nullptr;
	}
	const int4 asz = arch.getDefaultCodeSpace ()->getAddrSize ();
	std::string err;

	PrototypePieces pp;
	pp.model = model;
	pp.name = callee;
	pp.firstVarArgSlot = -1; // locked, not varargs => all params wired (bypasses the liveness trim)
	pp.outtype = !sig.ret.empty ()? arch.getTypeFactory ()->fromCString (sig.ret.c_str (), &err): nullptr;
	if (!pp.outtype) {
		pp.outtype = arch.types->getBase (4, TYPE_INT);
	}
	for (size_t i = 0; i < sig.fixedTypes.size (); i++) {
		Datatype *t = arch.getTypeFactory ()->fromCString (sig.fixedTypes[i].c_str (), &err);
		if (!t) {
			t = arch.types->getBase (asz, TYPE_UNKNOWN);
		}
		pp.intypes.push_back (t);
		pp.innames.push_back (sig.fixedNames[i]);
	}
	int vi = 0;
	for (const std::string &cs : convs) {
		Datatype *t = arch.getTypeFactory ()->fromCString (cs.c_str (), &err);
		if (!t) {
			return nullptr;
		}
		pp.intypes.push_back (t);
		pp.innames.push_back ("va" + std::to_string (vi++));
	}

	FuncProto *fp = new FuncProto ();
	fp->setInternal (model, arch.types->getTypeVoid ());
	try {
		fp->setPieces (pp);
	} catch (const LowlevelError &) {
		delete fp;
		return nullptr;
	}
	return fp;
}

static void override_format_call(RCore *core, R2Architecture &arch, Funcdata *ghFunc, Sdb *tdb,
		const std::unordered_map<std::string, ut64> &reg_strings, RAnalOp *op, AddrSpace *space) {
	const std::string callee = resolve_callee_name (core, op->jump);
	if (callee.empty () || !is_printf_family (callee.c_str ())) {
		return;
	}
	VariadicSig sig;
	if (!parse_variadic_sig (tdb, callee.c_str (), sig) || sig.firstVararg < 1) {
		return;
	}
	const char *cc = r_anal_cc_func (core->anal, callee.c_str ());
	if (!cc) {
		cc = r_anal_cc_default (core->anal);
	}
	const char *freg = r_anal_cc_argloc (core->anal, cc, sig.firstVararg - 1, 0, 0);
	auto it = freg? reg_strings.find (tolower (freg)): reg_strings.end ();
	if (it == reg_strings.end ()) {
		return;
	}
	std::string fmt;
	std::vector<std::string> convs;
	if (!read_format_string (core, it->second, fmt) || !parse_format_conversions (fmt.c_str (), convs)) {
		return;
	}
	FuncProto *fp = build_locked_proto (arch, cc, callee.c_str (), sig, convs);
	if (fp) {
		ghFunc->getOverride ().insertProtoOverride (Address (space, op->addr), fp);
	}
}

// Ghidra trims trailing varargs by register liveness; force the exact count/types from the literal format via a locked non-dotdotdot proto override so all get wired.
void PcodeFixupPreprocessor::fixupVariadicFormatCalls(RAnalFunction *r2Func, Funcdata *ghFunc, RCore *core, R2Architecture &arch) {
	RVecAnalRef *refs = r_anal_function_get_refs (r2Func);
	if (!refs) {
		return;
	}
	// the string-load ref is STRN on x86 (emu.str) but DATA on ppc64 (TOC-relative); take either when the target carries string metadata
	std::unordered_map<ut64, ut64> strn_at;
	RAnalRef *refi;
	R_VEC_FOREACH (refs, refi) {
		if (refi->addr == UT64_MAX) {
			continue;
		}
		const int rt = R_ANAL_REF_TYPE_MASK (refi->type);
		if (rt != R_ANAL_REF_TYPE_STRN && rt != R_ANAL_REF_TYPE_DATA) {
			continue;
		}
		if (rt == R_ANAL_REF_TYPE_DATA && !r_meta_get_string (core->anal, R_META_TYPE_STRING, refi->addr)) {
			continue;
		}
		strn_at[refi->at] = refi->addr;
	}
	RVecAnalRef_free (refs);
	if (strn_at.empty ()) {
		return;
	}

	Sdb *tdb = core->anal->sdb_types;
	auto space = arch.getDefaultCodeSpace ();
	walk_bb_regflow (core, r2Func, strn_at,
		[&](RAnalOp *op, std::unordered_map<std::string, ut64> &regs) {
			if ((op->type & R_ANAL_OP_TYPE_MASK) == R_ANAL_OP_TYPE_CALL && op->jump != UT64_MAX) {
				override_format_call (core, arch, ghFunc, tdb, regs, op, space);
			}
		});
}
