#ifndef PCODE_PREPROCESSOR_H
#define PCODE_PREPROCESSOR_H

#include "R2Architecture.h"

#include <r_core.h>

class PcodeFixupPreprocessor
{
	public:
		static void fixupSharedReturnJumpToRelocs(RAnalFunction *function, ghidra::Funcdata *func, RCore *core, R2Architecture &arch);
		static bool applyFunctionSignature(const char *funcName, const ghidra::Address &addr, R2Architecture &arch);
};

#endif
