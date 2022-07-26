/* r2ghidra - LGPL - Copyright 2019-2022 - thestr4ng3r, pancake */

#include "ArchMap.h"
#include <error.hh>
#include "R2Architecture.h"
#include "R2Utils.h"
#include <map>
#include <functional>

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
		Mapper<std::string>(const char *constant) : BaseMapper([constant](RCore *core) { return constant; }) {}
};

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
				const Mapper<std::string> flavor = "default",
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

// keys = asm.arch values
static const std::map<std::string, ArchMapper> arch_map = {
	{ "x86", {
		"x86",
		CUSTOM_FLAVOR((RCore *core) {
			return (BITS == 16)? "Real Mode": "default";
		}), bits_mapper_default, false, 1, 16
	}},
	{ "mips", { "MIPS", "default",
		bits_mapper_default, big_endian_mapper_default, 4, 4
	}},
	{ "dalvik", { "Dalvik", "default", 32, false, 2, 10 }},
	{ "tricore", { "tricore", "default", 32, true } },
	{ "hexagon", { "hexagon", "default", 32, false } },
	{ "wasm", { "wasm", "default", 32 } },
	{ "6502", { "6502", "default", 16 } },
	{ "65c02", { "65c02", "default", 16 } },
	{ "java", { "JVM", "default", bits_mapper_default, true } },
	{ "hppa", { "pa-risc" } },
	{ "riscv", { "RISCV" } },
	{ "toy", { "Toy" } },
	{ "ppc", { "PowerPC" } },
	{ "8051", { "8051", "default", 16, true }},
	{ "6805", { "6805" } },
	{ "cr16", { "CR16C" } },
	{ "mcs96", { "MCS96", "default", 16 } },
	{ "m8c", { "M8C", "default", 16 } },
	{ "pic24", { "PIC-24F", "default", 24 } },
	{ "z80", { "z80", "default", 8 } },
	{ "sparc", { "sparc" } },
	{ "stm8", { "STM8" } },
	{ "sh", { "SuperH4" } },
	{ "msp430", { "TI_MSP430" } },
	{ "m68k", {
		"68000",
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
		32 } },
	{ "tricore", {
		"tricore",
		CUSTOM_FLAVOR ((RCore *core) {
			const char *cpu = r_config_get(core->config, "asm.cpu");
			if (cpu != nullptr) {
				if (std::string("tc29x") == cpu || std::string("tc172x") == cpu || std::string("tc176x") == cpu) {
					return cpu;
				}
			}
			return "default";
		}),
		32 } },
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
		"default",
		CUSTOM_BITS ((RCore *core) {
			return BITS == 32 ? 32 : 16;
		})}},

	{ "v850", {
		CUSTOM_BASEID ((RCore *core) {
			return "V850";
		}),
		"default",
		CUSTOM_BITS((RCore *core) {
			return 32;
		}),
		false,
		2, 6
	}}
};

#if 0
Supported compiler profiles. r2 should have a configuration option for that:

For X86:
* default
* clang
* gcc
* Borland C++
* Visual Studio
* Delphi

```
# list all arch.compiler from ghidra
$ cd ghidra-native
$ git grep 'compiler name=' | grep ldefs| cut -d '"' -f 1,2 |cut -d '/' -f 6- |sed -e 's,",.,' | cut -d . -f1,3|sort -u

6502.default
68000.default
6805.default
8048.default
8051.Archimedes
8051.default
8085.default
AARCH64.Visual Studio
AARCH64.default
ARM.Visual Studio
ARM.default
AppleSilicon.default
CP1600.default
CR16.default
Dalvik.default
HC05.default
HC08.default
HCS08.default
HCS12.default
JVM.default
MCS96.default
PIC24.default
STM8.default
SparcV9.default
SuperH4.Visual Studio
SuperH4.default
TI_MSP430.default
V850.default
avr32a.default
avr8.gcc
avr8.iarV1
avr8.imgCraftV8
hexagon.default
m8c.default
mips.Visual Studio
mips.default
mips.n32
mips.o32
mips.o64
old/v01stuff/toy.default
pa-risc.default
pic12c5xx.default
pic16.default
pic16c5x.default
pic17c7xx.default
pic18.default
ppc.Mac OS X
ppc.Visual Studio
ppc.default
riscv.gcc
superh.default
toy.default
toy.posStack
tricore.default
x86.Borland C++
x86.Delphi
x86.Visual Studio
x86.clang
x86.default
x86.gcc
z80.default


# list all compiler support from ghidra

$ git grep compiler' name=' | cut -d '"' -f 2|sort -u
Archimedes
Borland C++
Delphi
Mac OS X
Sleigh-PowerPC 32-bit
Visual Studio
clang
default
gcc
iarV1
imgCraftV8
n32
o32
o64
pointer16
pointer32
pointer64
posStack
```
#endif
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

static const std::map<std::string, std::string> compiler_alias = {
	{ "vs", "Visual Studio" },
	{ "mach0", "Mac OS X" },
};

static const std::map<std::string, std::string> compiler_map = {
	{ "elf", "gcc" },
	{ "pe", "Visual Studio" },
	// { "mach0", "clang" },
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
	char *b = r_str_newf ("%s.", a);
	const char *uc = bin_compiler; // r_config_get (core->config, "r2ghidra.compiler");
	if (!strcmp (uc, "?")) {
		for (int i = 0; ghidraCompilers[i]; i++) {
			if (r_str_startswith (ghidraCompilers[i], b)) {
				const char *c = ghidraCompilers[i] + strlen (b);
				r_cons_printf ("%s\n", c);
			}
		}
		free (b);
		return std::string("default");
	}
	if (R_STR_ISEMPTY (bin_compiler) || !strcmp (uc, "default")) {
		bin_compiler = uc;
	}
	const char *goodcompiler = NULL;
	for (int i = 0; ghidraCompilers[i]; i++) {
		if (r_str_startswith (ghidraCompilers[i], b)) {
			const char *c = ghidraCompilers[i] + strlen (b);
			goodcompiler = c;
			if (R_STR_ISEMPTY (bin_compiler) || !r_str_casecmp (c, bin_compiler)) {
				break;
			}
			//eprintf ("-> %s\n", c);
		}
	}
	free (b);
	free (a);
	if (goodcompiler != NULL) {
		return std::string(goodcompiler);
	}
	if (r_str_startswith (arch, "x86")) {
		return std::string("gcc");
	}
	return std::string("default");
/*
		if (!r_str_startswith (arch, "x86")) {
			"x86.Borland C++",
			"x86.Delphi",
			"x86.Visual Studio",
			"x86.clang",
			"x86.default",
			"x86.gcc",
			"z80.default",
		}
*/
}

std::string CompilerFromCore(RCore *core) {
	if (!core) {
		return "gcc";
	}
	RBinInfo *info = r_bin_get_info (core->bin);
	if (!info || !info->rclass) {
		return std::string ();
	}
	if (R_STR_ISNOTEMPTY (info->compiler)) {
		auto gcompiler = findGhidraCompiler(core, info->compiler);
		return std::string(info->compiler);
	}
	auto comp_it = compiler_map.find (info->rclass);
	if (comp_it == compiler_map.end ()) {
		return std::string ();
	}
	return comp_it->second;
}

std::string SleighIdFromCore(RCore *core) {
	if (!core) {
		return "gcc";
	}
#if 1
	R2Architecture::collectSpecFiles (std::cerr);
	auto langs = R2Architecture::getLanguageDescriptions ();
#else
	SleighArchitecture::collectSpecFiles (std::cerr);
	auto langs = SleighArchitecture::getLanguageDescriptions ();
#endif
	if (langs.empty ()) {
		R_LOG_ERROR ("No languages available, make sure r2ghidra.sleighhome is set properly");
		return "gcc";
	}
	const char *arch = r_config_get (core->config, "asm.arch");
	if (!strcmp (arch, "r2ghidra")) {
#if R2_VERSION_NUMBER >= 50609
		RArchConfig *ac = core->rasm->config;
		return SleighIdFromSleighAsmConfig (core, ac->cpu, ac->bits, ac->big_endian, langs);
#else
		return SleighIdFromSleighAsmConfig (core, core->rasm->cpu, core->rasm->bits, core->rasm->big_endian, langs);
#endif
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
	case R_ANAL_ARCHINFO_MIN_OP_SIZE:
		return am->minopsz;
	case R_ANAL_ARCHINFO_MAX_OP_SIZE:
		return am->maxopsz;
	// case R_ANAL_ARCHINFO_ALIGN: return am->align; // proc.align;
	}
	return 1;
}

std::string SleighIdFromSleighAsmConfig(RCore *core, const char *cpu, int bits, bool bigendian, const vector<LanguageDescription> &langs) {
	const char *colon = strchr (cpu, ':');
	if (colon != nullptr && colon[1] != '\0' && colon[1] != '\0') {
		// complete id specified
		return cpu;
	}
	auto arch_it = arch_map.find(cpu);
	if (arch_it != arch_map.end()) {
		return arch_it->second.Map (core);
	}
	const ArchMapper *am = &arch_it->second;
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
