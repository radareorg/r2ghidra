// SPDX-FileCopyrightText: 2019-2026 thestr4ng3r, pancake
// SPDX-License-Identifier: LGPL-3.0-only

#include "ArchMap.h"
#include <error.hh>
#include "R2Architecture.h"
#include "R2Utils.h"
#include <cstring>
#include <map>
#include <functional>

using namespace ghidra;

std::string CompilerFromCore(RCore *core);

template<typename T> class BaseMapper {
	private:
		const std::function<T(RCore *)> func;
	public:
		BaseMapper(const std::function<T(RCore *)> &func) : func(func) {}
		BaseMapper(const T constant) : func([constant](RCore *core) { return constant; }) {}
		T Map(RCore *core) const { return func(core); }
};

template<typename T> class Mapper;
template<> class Mapper<ut64> : public BaseMapper<ut64> { public: using BaseMapper<ut64>::BaseMapper; };
template<> class Mapper<bool> : public BaseMapper<bool> { public: using BaseMapper<bool>::BaseMapper; };
template<> class Mapper<int> : public BaseMapper<int> { public: using BaseMapper<int>::BaseMapper; };

template<> class Mapper<std::string> : public BaseMapper<std::string> {
	public:
		using BaseMapper<std::string>::BaseMapper;
		Mapper(const char *constant) : BaseMapper<std::string>([constant](RCore *core) { return std::string(constant); }) {}
};

// Shorthand macros for cleaner map initialization to please C++20
#define S(x) Mapper<std::string>(x)
#define B(x) Mapper<ut64>(x)
#define E(x) Mapper<bool>(x)

static const Mapper<bool> big_endian_mapper_default = std::function<bool(RCore *)>([](RCore *core) {
	return core? r_config_get_b (core->config, "cfg.bigendian"): false;
});
static const Mapper<ut64> bits_mapper_default = std::function<ut64(RCore *)>([](RCore *core) {
	return core? (ut64)r_config_get_i (core->config, "asm.bits"): R_SYS_BITS;
});

class ArchMapper {
	private:
		const Mapper<std::string> arch;
		const Mapper<std::string> flavor;
		const Mapper<bool> big_endian;
		const Mapper<ut64> bits;

	public:
		const int minopsz;
		const int maxopsz;
	public:
		ArchMapper (
				const Mapper<std::string> arch,
				const Mapper<std::string> flavor = S("default"),
				const Mapper<ut64> bits = bits_mapper_default,
				const Mapper<bool> big_endian = big_endian_mapper_default,
				const int minopsz = 0,
				const int maxopsz = 0)
			: arch (arch)
			, flavor (flavor)
			, bits (bits)
			, big_endian (big_endian)
			, minopsz(minopsz)
			, maxopsz(maxopsz) {}

		std::string Map(RCore *core) const {
			return arch.Map(core)
				+ ":" + (big_endian.Map(core) ? "BE" : "LE")
				+ ":" + to_string(bits.Map(core))
				+ ":" + flavor.Map(core)
				+ ":" + CompilerFromCore(core);
		}
};

#define BITS (core? r_config_get_i(core->config, "asm.bits"): R_SYS_BITS)
#define CUSTOM_BASEID(lambda) std::function<std::string(RCore *)>([]lambda)
#define CUSTOM_FLAVOR(lambda) std::function<std::string(RCore *)>([]lambda)
#define CUSTOM_BITS(lambda) std::function<ut64(RCore *)>([]lambda)
#define CUSTOM_MINOPSZ(lambda) std::function<int(RCore *)>([]lambda)
#define CUSTOM_MAXOPSZ(lambda) std::function<int(RCore *)>([]lambda)

static std::string DalvikFlavorFromCore(RCore *core) {
	if (!core) {
		return "DEX_Base";
	}
	RBinInfo *info = r_bin_get_info (core->bin);
	if (!info || !info->arch || strcmp (info->arch, "dalvik")) {
		return "DEX_Base";
	}
	const char *version = info->bclass;
	if (!version) {
		return "DEX_Base";
	}
	if (!strncmp (version, "041", 3)) {
		return "DEX_Android13";
	}
	if (!strncmp (version, "040", 3)) {
		return "DEX_Android10";
	}
	if (!strncmp (version, "039", 3)) {
		return "DEX_Pie";
	}
	if (!strncmp (version, "038", 3)) {
		return "DEX_Oreo";
	}
	if (!strncmp (version, "037", 3)) {
		return "DEX_Nougat";
	}
	return "DEX_Base";
}

static std::string PpcFlavorFromCore(RCore *core) {
	if (r_config_get_i (core->config, "asm.bits") == 64) {
		// A2ALT decodes isel and keeps 64-bit addressing; identical to default on non-isel ppc64
		return "A2ALT";
	}
	// ppc asm.cpu only accepts ppc/vle/ps, so the EMB apuinfo cpu is reachable only via bin info
	RBinInfo *info = r_bin_get_info (core->bin);
	const char *cpu = info? info->cpu: NULL;
	if (cpu && (!strcmp (cpu, "e500") || !strcmp (cpu, "e500mc") || !strcmp (cpu, "4xx"))) {
		R_LOG_INFO ("Selecting PowerPC sleigh variant '%s' from bin info cpu", cpu);
		return cpu;
	}
	return "default";
}

// keys = asm.arch values
static const std::map<std::string, ArchMapper> arch_map = {
	{ "x86", {
		"x86",
		CUSTOM_FLAVOR((RCore *core) {
			return (BITS == 16)? "Real Mode": "default";
		}), bits_mapper_default, E(false), 1, 16
	}},
	{ "mips", { S("MIPS"), S("default"), bits_mapper_default, big_endian_mapper_default, 4, 4 }},
	{ "dalvik", { S("Dalvik"), CUSTOM_FLAVOR((RCore *core) {
		return DalvikFlavorFromCore (core);
	}), B(32), E(false), 2, 10 }},
	{ "hexagon", { S("hexagon"), S("default"), B(32), E(false) } },
	{ "wasm", { S("wasm"), S("default"), B(32) } },
	{ "6502", { S("6502"), S("default"), B(16) } },
	{ "65c02", { S("65c02"), S("default"), B(16) } },
	{ "loongarch", {
		S("Loongarch"),
		CUSTOM_FLAVOR ((RCore *core) {
			return BITS == 32 ? "ilp32d" : "lp64d";
		}),
		CUSTOM_BITS ((RCore *core) {
			return BITS == 32 ? 32 : 64;
		}),
		E(false), 4, 4
	}},
	{ "java", { S("JVM"), S("default"), bits_mapper_default, E(true) } },
	{ "hppa", { S("pa-risc") } },
	{ "riscv", { S("RISCV") } },
	{ "toy", { S("Toy") } },
	{ "ppc", {
		S("PowerPC"),
		CUSTOM_FLAVOR ((RCore *core) {
			return PpcFlavorFromCore (core);
		})
	} },
	{ "8051", { S("8051"), S("default"), B(16), E(true) }},
	{ "6800", { S("6809"), S("default"), B(16), E(true) } },
	{ "6801", { S("6809"), S("default"), B(16), E(true) } },
	{ "6803", { S("6809"), S("default"), B(16), E(true) } },
	{ "6805", { S("6805"), S("default"), B(16), E(true) } },
	{ "6808", { S("6809"), S("default"), B(16), E(true) } },
	{ "6809", { S("6809"), S("default"), B(16), E(true) } },
	{ "6309", { S("H6309"), S("default"), B(16), E(true) } },
	{ "h6309", { S("H6309"), S("default"), B(16), E(true) } },
	{ "m680x", {
		CUSTOM_BASEID ((RCore *core) {
			const char *cpu = core? r_config_get (core->config, "asm.cpu"): nullptr;
			std::string cpuname = cpu? tolower (cpu): std::string ();
			if (cpuname == "6805") {
				return "6805";
			}
			if (cpuname == "6309" || cpuname == "h6309") {
				return "H6309";
			}
			return "6809";
		}),
		S("default"), B(16), E(true)
	}},
	{ "cr16", { S("CR16C") } },
	{ "m16c", {
		CUSTOM_BASEID ((RCore *core) {
			const char *cpu = core? r_config_get (core->config, "asm.cpu"): nullptr;
			std::string cpuname = cpu? tolower (cpu): std::string ();
			if (cpuname == "m16c80" || cpuname == "m16c_80" || cpuname == "m16c/80") {
				return "M16C/80";
			}
			return "M16C/60";
		}),
		S("default"), B(16), E(false)
	}},
	{ "m16c60", { S("M16C/60"), S("default"), B(16), E(false) } },
	{ "m16c80", { S("M16C/80"), S("default"), B(16), E(false) } },
	{ "mcs96", { S("MCS96"), S("default"), B(16) } },
	{ "m8c", { S("M8C"), S("default"), B(16), E(true) } },
	{ "pic24", { S("PIC-24F"), S("default"), B(24) } },
	{ "z80", { S("z80"), S("default"), B(8) } },
	{ "xtensa", { S("Xtensa"), S("default"), B(32) } },
	{ "sparc", { S("sparc") } },
	{ "stm8", { S("STM8"), S("default"), B(16), E(true) } },
	{ "sh", { S("SuperH4") } },
	{ "msp430", { S("TI_MSP430") } },
	{ "m68k", {
		S("68000"),
		CUSTOM_FLAVOR ((RCore *core) {
			const char *cpu = r_config_get (core->config, "asm.cpu");
			if (cpu != nullptr) {
				if (std::string("68020") == cpu) {
					return "MC68020";
				}
				if (std::string("68030") == cpu) {
					return "MC68030";
				}
				if (std::string("68060") == cpu) {
					return "Coldfire"; // may not be accurate!!
				}
			}
			return "default";
		}),
		B(32) } },
	{ "tricore", {
		S("tricore"),
		CUSTOM_FLAVOR ((RCore *core) {
			const char *cpu = r_config_get(core->config, "asm.cpu");
			if (cpu != nullptr) {
				if (std::string("tc29x") == cpu || std::string("tc172x") == cpu || std::string("tc176x") == cpu) {
					return cpu;
				}
			}
			return "default";
		}),
		B(32) } },
	{ "arm", {
	 	CUSTOM_BASEID ((RCore *core) {
			return BITS == 64 ? "AARCH64" : "ARM";
		}),
		CUSTOM_FLAVOR ((RCore *core) {
			return BITS == 64 ? "v8A" : "v7";
		}),
		CUSTOM_BITS ((RCore *core) {
			return BITS == 64 ? 64 : 32;
		}),
		big_endian_mapper_default, 2, 4
	}},
	{ "avr", {
		CUSTOM_BASEID ((RCore *core) {
			return BITS == 32 ? "avr32a" : "avr8";
		}),
		S("default"),
		CUSTOM_BITS ((RCore *core) {
			return BITS == 32 ? 32 : 16;
		})}},

	{ "v850", {
		CUSTOM_BASEID ((RCore *core) {
			return "V850";
		}),
		S("default"),
		CUSTOM_BITS((RCore *core) {
			return 32;
		}),
		E(false),
		2, 6
	}},
	{ "bpf", { S("BPF"), S("default"), B(32), E(false) } },
	{ "ebpf", { S("eBPF"), S("default"), B(32), E(false) } },
	{ "sbpf", { S("sBPF"), S("default"), B(64), E(false) } }
};

const char *ghidraCompilers[] = {
	"6502.default",
	"68000.default",
	"6805.default",
	"8048.default",
	"8051.Archimedes",
	"8051.default",
	"8085.default",
	"AARCH64.Visual Studio",
	"AARCH64.default",
	"ARM.Visual Studio",
	"ARM.default",
	"AppleSilicon.default",
	"CP1600.default",
	"CR16.default",
	"Dalvik.default",
	"HC05.default",
	"HC08.default",
	"HCS08.default",
	"HCS12.default",
	"JVM.default",
	"MCS96.default",
	"PIC24.default",
	"STM8.default",
	"SparcV9.default",
	"SuperH4.Visual Studio",
	"SuperH4.default",
	"TI_MSP430.default",
	"V850.default",
	"avr32a.default",
	"avr8.gcc",
	"avr8.iarV1",
	"avr8.imgCraftV8",
	"hexagon.default",
	"m8c.default",
	"mips.Visual Studio",
	"mips.default",
	"mips.n32",
	"mips.o32",
	"mips.o64",
	"old/v01stuff/toy.default",
	"pa-risc.default",
	"pic12c5xx.default",
	"pic16.default",
	"pic16c5x.default",
	"pic17c7xx.default",
	"pic18.default",
	"ppc.Mac OS X",
	"ppc.Visual Studio",
	"ppc.default",
	"riscv.gcc",
	"superh.default",
	"toy.default",
	"toy.posStack",
	"tricore.default",
	"x86.Borland C++",
	"x86.Delphi",
	"x86.Visual Studio",
	"x86.clang",
	"x86.default",
	"x86.gcc",
	"z80.default",
	NULL
};

// short names for the cspecs that are awkward to type via `e r2ghidra.compiler=`
static const std::map<std::string, std::string> compiler_alias = {
	{ "vs", "Visual Studio" },
	{ "msvc", "Visual Studio" },
	{ "windows", "Visual Studio" },
	{ "mach0", "Mac OS X" },
	{ "macos", "Mac OS X" },
	{ "osx", "Mac OS X" },
};

static const std::map<std::string, std::string> compiler_map = {
	{ "elf", "gcc" },
	{ "pe", "Visual Studio" },
	{ "mach0", "clang" },
};

std::string findGhidraCompiler(RCore *core, const char *bin_compiler) {
	const char *arch = r_config_get (core->config, "asm.arch");
	if (R_STR_ISEMPTY (arch)) {
		return std::string("default");
	}
	if (!strcmp (arch, "r2ghidra")) {
		arch = r_config_get (core->config, "asm.cpu");
	}
	
	char *a = strdup (arch);
	// take arch name by splitting by the dot.
	char *dot = strchr (a, '.');
	if (dot) {
		*dot = 0;
	}
	// asm.arch "arm" is "ARM" (32-bit) or "AARCH64" (64-bit) in Ghidra's processor naming
	if (!strcmp (a, "arm")) {
		free (a);
		a = strdup (r_config_get_i (core->config, "asm.bits") == 64? "AARCH64": "ARM");
	}
	char *b = r_str_newf ("%s.", a);
	free (a);
	const char *uc = bin_compiler;
	if (!strcmp (uc, "?")) {
		for (int i = 0; ghidraCompilers[i]; i++) {
			if (r_str_startswith (ghidraCompilers[i], b)) {
				const char *c = ghidraCompilers[i] + strlen (b);
				r_cons_printf (core->cons, "%s\n", c);
			}
		}
		free (b);
		return std::string("default");
	}
	if (R_STR_ISEMPTY (bin_compiler) || !strcmp (uc, "default")) {
		bin_compiler = uc;
	}
	auto ali = compiler_alias.find (tolower (bin_compiler));
	if (ali != compiler_alias.end ()) {
		bin_compiler = ali->second.c_str ();
	}
	const char *goodcompiler = NULL;
	for (int i = 0; ghidraCompilers[i]; i++) {
		if (r_str_startswith (ghidraCompilers[i], b)) {
			const char *c = ghidraCompilers[i] + strlen (b);
			goodcompiler = c;
			if (R_STR_ISEMPTY (bin_compiler) || !r_str_casecmp (c, bin_compiler)) {
				break;
			}
		}
	}
	free (b);
	if (goodcompiler != NULL) {
		return std::string(goodcompiler);
	}
	if (r_str_startswith (arch, "x86")) {
		return std::string("gcc");
	}
	return std::string("default");
}

std::string CompilerFromCore(RCore *core) {
	if (core == nullptr) {
		return "gcc";
	}
	// an explicit r2ghidra.compiler selects the cspec; "default" defers to the binary
	const char *want = r_config_get (core->config, "r2ghidra.compiler");
	if (R_STR_ISNOTEMPTY (want) && strcmp (want, "default")) {
		return findGhidraCompiler (core, want);
	}
	RBinInfo *info = r_bin_get_info (core->bin);
	if (!info || !info->rclass) {
		return std::string ();
	}
	if (R_STR_ISNOTEMPTY (info->compiler)) {
		// the bin's compiler string ("GCC: (GNU) 9.2.0") is not a cspec name; normalize it
		return findGhidraCompiler (core, info->compiler);
	}
	auto comp_it = compiler_map.find (info->rclass);
	if (comp_it == compiler_map.end ()) {
		return std::string ();
	}
	return comp_it->second;
}

std::string SleighIdFromCore(RCore *core) {
	if (core == nullptr) {
		return "gcc";
	}
	R2Architecture::collectSpecFiles (std::cerr);
	auto langs = R2Architecture::getLanguageDescriptions ();
	if (langs.empty ()) {
		R_LOG_ERROR ("No languages available, make sure r2ghidra.sleighhome is set properly");
		return "gcc";
	}
	const char *arch = r_config_get (core->config, "asm.arch");
	if (!strcmp (arch, "r2ghidra")) {
		RArchConfig *ac = core->rasm->config;
		return SleighIdFromSleighAsmConfig (core, ac->cpu, ac->bits, ac->big_endian, langs);
	}
	auto arch_it = arch_map.find (arch);
	if (arch_it == arch_map.end ()) {
		throw LowlevelError ("Could not match asm.arch " + std::string(arch) + " to sleigh arch.");
	}
	return arch_it->second.Map (core);
}

int ai(RCore *core, std::string cpu, int query) {
	size_t pos = cpu.find(":");
	std::string cpuname = tolower ((pos != string::npos)? cpu.substr(0, pos): cpu);
	auto arch_it = arch_map.find(cpuname);
	if (arch_it == arch_map.end()) {
		return 1; // throw LowlevelError("Could not match asm.arch " + std::string(arch) + " to sleigh arch.");
	}
	const ArchMapper *am = &arch_it->second;
	// auto res = arch_it->second.Map(core);
	switch (query) {
	case R_ARCH_INFO_MINOP_SIZE:
		return am->minopsz;
	case R_ARCH_INFO_MAXOP_SIZE:
		return am->maxopsz;
	// case R_ANAL_ARCHINFO_ALIGN: return am->align; // proc.align;
	}
	return 1;
}

std::string SleighIdFromSleighAsmConfig(RCore *core, const char *cpu, int bits, bool bigendian, const vector<LanguageDescription> &langs) {
	const char *colon = strchr (cpu, ':');
	if (colon != nullptr && colon[1] != '\0') {
		// complete id specified
		return cpu;
	}
	auto arch_it = arch_map.find(cpu);
	if (arch_it != arch_map.end()) {
		return arch_it->second.Map (core);
	}
	// short form if possible
	std::string low_cpu = tolower (cpu);
	for (const auto &lang : langs) {
		auto proc = lang.getProcessor();
		if (tolower (proc) == low_cpu) {
			return proc
				+ ":" + (bigendian ? "BE" : "LE")
				+ ":" + to_string (bits)
				+ ":" + "default";
		}
	}
	return cpu;
}
