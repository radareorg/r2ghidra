/* r2ghidra - LGPL - Copyright 2025 - pancake */

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
}
