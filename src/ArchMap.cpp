/* r2ghidra - LGPL - Copyright 2019-2023 - thestr4ng3r, pancake */

#include "ArchMap.h"
#include <error.hh>
#include "R2Architecture.h"
#include "R2Utils.h"
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
	{ "xtensa", { "Xtensa", "default", 32 } },
	{ "sparc", { "sparc" } },
	{ "stm8", { "STM8", "default", 16, true } },
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
	}},
	{ "bpf", { "BPF", "default", 32, false } },
	{ "ebpf", { "eBPF", "default", 32, false } },
	{ "sbpf", { "sBPF", "default", 64, false } }
};

static const std::map<std::string, std::string> compiler_map = {
	{ "elf", "gcc" },
	{ "pe", "windows" },
	{ "mach0", "clang" }
};

std::string CompilerFromCore(RCore *core) {
	if (core == nullptr) {
		return "gcc";
	}
	RBinInfo *info = r_bin_get_info (core->bin);
	if (!info || !info->rclass) {
		return std::string ();
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
#if R2_VERSION_NUMBER >= 50909
	case R_ARCH_INFO_MINOP_SIZE:
		return am->minopsz;
	case R_ARCH_INFO_MAXOP_SIZE:
		return am->maxopsz;
#else
	case R_ARCH_INFO_MIN_OP_SIZE:
		return am->minopsz;
	case R_ARCH_INFO_MAX_OP_SIZE:
		return am->maxopsz;
#endif
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
