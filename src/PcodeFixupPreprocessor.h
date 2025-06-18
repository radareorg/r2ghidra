/* r2ghidra - LGPL - Copyright 2024 */

#ifndef PCODE_PREPROCESSOR_H
#define PCODE_PREPROCESSOR_H

#include "R2Architecture.h"

#include <r_core.h>

class PcodeFixupPreprocessor
{
	public:
		static void fixupSharedReturnJumpToRelocs(RAnalFunction *function, ghidra::Funcdata *func, RCore *core, R2Architecture &arch);
};

#endif