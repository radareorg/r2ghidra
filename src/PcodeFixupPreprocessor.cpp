/* r2ghidra - LGPL - Copyright 2024 */

#include "R2LoadImage.h"
#include "R2Utils.h"
#include "PcodeFixupPreprocessor.h"

#include <funcdata.hh>
#include <flow.hh>
#include <override.hh>

using namespace ghidra;

void PcodeFixupPreprocessor::fixupSharedReturnJumpToRelocs(RAnalFunction *function, Funcdata *func, RCore *core, R2Architecture &arch)
{
	RList *xrefs = r_anal_function_get_xrefs_from(function);
	if (!xrefs) {
		return;
	}

	RListIter *it;
	RAnalXRef *xref;
	r_list_foreach (xrefs, it, xref) {
		// To ensure the instruction is a `jmp` instruction
		if (xref->type == R_ANAL_REF_TYPE_CODE) {
			// If the target location is an imported function, then do the patch
			RBinReloc *reloc = r_core_get_reloc_to(core, xref->to);
			if (reloc != NULL && reloc->import != NULL) {
				func->getOverride().insertFlowOverride(Address(arch.getDefaultCodeSpace(), xref->from), Override::CALL_RETURN);
			}
		}
	}
	r_list_free(xrefs);
}