// SPDX-FileCopyrightText: 2019-2026 thestr4ng3r, pancake
// SPDX-License-Identifier: LGPL-3.0-only

#include <r_core.h>
#include "../config.h"

extern bool r2ghidra_core_fini(RCorePluginSession *cps);
extern bool r2ghidra_core_init(RCorePluginSession *cps);
extern bool r2ghidra_core_cmd(RCorePluginSession *cps, const char *cmd);

RCorePlugin r_core_plugin_ghidra = {
	.meta = {
		.name = "r2ghidra",
		.desc = "Ghidra decompiler with pdg command",
		.license = "LGPL-3.0-only",
		.author = "thestr4ng3r, pancake",
		.version = R2GHIDRA_VERSION,
	},
	.call = r2ghidra_core_cmd,
	.init = r2ghidra_core_init,
	.fini = r2ghidra_core_fini
};

#ifndef CORELIB
#ifdef __cplusplus
extern "C"
#endif
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_ghidra,
	.version = R2_VERSION,
	.free = NULL,
	.abiversion = R2_ABIVERSION,
	.pkgname = "r2ghidra"
};
#endif
