/* r2ghidra - LGPL - Copyright 2019-2021 - thestr4ng3r, pancake */

#ifndef R2GHIDRA_CODEXMLPARSE_H
#define R2GHIDRA_CODEXMLPARSE_H

#include <r_anal.h>

class Funcdata;

R_API RCodeMeta *ParseCodeXML(Funcdata *func, const char *xml);

#endif //R2GHIDRA_CODEXMLPARSE_H
