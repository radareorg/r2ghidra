/* r2ghidra - LGPL - Copyright 2019 - thestr4ng3r */

#ifndef R2GHIDRA_ARCHMAP_H
#define R2GHIDRA_ARCHMAP_H

#include <sleigh_arch.hh>

#include <r_core.h>

#include <string>

/**
 * Match sleigh id from whatever is currently configured.
 * For regular r2 plugins, guess the matching sleigh id,
 * for the specific sleigh plugin, same as SleighIdFromSleighAsmConfig()
 */
std::string SleighIdFromCore(RCore *core);

/**
 * Match sleigh id from sleigh-plugin specific settings (asm.cpu)
 */
std::string SleighIdFromSleighAsmConfig(RCore *core, const char *cpu, int bits, bool bigendian, const vector<LanguageDescription> &langs);
// XXX find a better name, this is used from SleigAsm/asm plugin
int ai(RCore *core, std::string cpu, int query);

#endif
