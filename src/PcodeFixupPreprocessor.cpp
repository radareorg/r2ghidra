// SPDX-FileCopyrightText: 2025-2026 pancake
// SPDX-License-Identifier: LGPL-3.0-only

#include "PcodeFixupPreprocessor.h"
#include "R2LoadImage.h"
#include "R2Utils.h"

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
			R_LOG_INFO ("OverridingCallReturn %s", extractLibcFuncName (impname));
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
