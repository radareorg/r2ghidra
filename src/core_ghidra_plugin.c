#include <r_core.h>

extern int r2ghidra_core_fini(void *user, const char *cmd);
extern int r2ghidra_core_init(void *user, const char *cmd);
extern int r2ghidra_core_cmd(void *user, const char *input);

RCorePlugin r_core_plugin_ghidra = {
#if R2_VERSION_NUMBER > 50808
	.meta = {
		.name = "r2ghidra",
		.desc = "Ghidra decompiler with pdg command",
		.license = "GPL3",
		.author = "thestr4ng3r, pancake",
	},
#else
	.name = "r2ghidra",
	.desc = "Ghidra decompiler with pdg command",
	.license = "GPL3",
	.author = "thestr4ng3r, pancake",
#endif
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
#if R2_VERSION_NUMBER >= 40200
	.pkgname = "r2ghidra"
#endif
};
#endif
