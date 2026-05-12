// SPDX-FileCopyrightText: 2019-2023 thestr4ng3r, pancake
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef R2GHIDRA_CODEXMLPARSE_H
#define R2GHIDRA_CODEXMLPARSE_H

#include <funcdata.hh>
#include <r_anal.h>

//using namespace ghidra;

//class Funcdata;

R_API RCodeMeta *ParseCodeXML(ghidra::Funcdata *func, const char *xml);

#endif //R2GHIDRA_CODEXMLPARSE_H
