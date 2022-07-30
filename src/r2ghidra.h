#ifndef R2GHIDRA_H
#define R2GHIDRA_H

#define R_LOG_ORIGIN "r2ghidra"

#include <r_core.h>

R_API RCodeMeta *r2ghidra_decompile_annotated_code(RCore *core, ut64 addr);

#endif //R2GHIDRA_H
