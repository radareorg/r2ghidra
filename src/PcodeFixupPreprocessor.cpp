/* r2ghidra - LGPL - Copyright 2025-2026 - pancake */

#include "PcodeFixupPreprocessor.h"
#include "R2LoadImage.h"

#include <funcdata.hh>
#include <flow.hh>
#include <override.hh>
#include <database.hh>

#include <r_core.h>
#include <r_anal.h>
#include <r_core.h>
#include <r_bin.h>

#include <map>
#include <string>
#include <unordered_map>
#include <vector>

using namespace ghidra;

static bool is_import_name(const char * R_NONNULL name) {
	return r_str_startswith (name, "imp.")
		|| r_str_startswith (name, "sym.imp.")
		|| r_str_startswith (name, "plt.")
		|| r_str_startswith (name, "reloc.");
}

// Helper to extract base function name from an import
static const char* extractLibcFuncName(const char *importName) {
	const char *last_dot = r_str_lchr (importName, '.');
	if (last_dot) {
		return last_dot + 1;
	}
	return nullptr;
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
		// R_LOG_INFO ("refi 0x%"PFMT64x"", refi->addr);
		RFlagItem *f = r_flag_get_at (core->flags, refi->addr, true);
		if (f) {
			if (is_import_name (f->name)) {
				RAnalOp *op = r_core_anal_op (core, refi->at, 0);
				if (!op) {
					continue;
				}
				bool isCallRet = (op->type == R_ANAL_OP_TYPE_JMP);
				// isCallRet = true;
				if (isCallRet) {
					// apply only if its a jump ref?
					// Address callAddr (space, refi->addr); // address of FUNCTION
					Address callAddr (space, refi->at); // address of CALL
					R_LOG_INFO ("OverridingCallReturn %s", extractLibcFuncName (f->name));
					ghFunc->getOverride().insertFlowOverride(callAddr, Override::CALL_RETURN);
				}
				r_anal_op_free (op);
			}
		}
	}
	RVecAnalRef_free (refs);
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
	RListIter *iter;
	void *pos;
	r_list_foreach (r2Func->bbs, iter, pos) {
		RAnalBlock *bb = reinterpret_cast<RAnalBlock *> (pos);
		std::unordered_map<std::string, ut64> reg_targets;
		for (int i = 0; i < bb->ninstr; i++) {
			ut64 at = r_anal_bb_opaddr_i (bb, i);
			RAnalOp *op = r_core_anal_op (core, at, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_VAL | R_ARCH_OP_MASK_OPEX);
			if (!op) {
				continue;
			}
			if (is_indirect_reg_call (op)) {
				std::string reg = op_first_reg (op, false);
				auto target = reg_targets.find (reg);
				if (target != reg_targets.end ()) {
					ghFunc->getOverride ().insertIndirectOverride (
						Address (space, op->addr),
						Address (space, target->second));
				}
			}

			std::string dst = op_first_reg (op, true);
			if (!dst.empty ()) {
				auto ref = icod_refs.find (op->addr);
				if (ref != icod_refs.end ()) {
					reg_targets[dst] = ref->second;
				} else {
					reg_targets.erase (dst);
				}
			}
			r_anal_op_free (op);
		}
	}
}
