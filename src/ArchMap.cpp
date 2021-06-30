/* r2ghidra - LGPL - Copyright 2019-2021 - thestr4ng3r, pancake */

#include "ArchMap.h"
#include <error.hh>
#include <map>
#include <functional>

std::string CompilerFromCore(RCore *core);

template<typename T>
class BaseMapper
{
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

template<> class Mapper<std::string> : public BaseMapper<std::string>
{
	public:
		using BaseMapper<std::string>::BaseMapper;
		Mapper<std::string>(const char *constant) : BaseMapper([constant](RCore *core) { return constant; }) {}
};

static const Mapper<bool> big_endian_mapper_default = std::function<bool(RCore *)>([](RCore *core) { return r_config_get_i(core->config, "cfg.bigendian") != 0; });
static const Mapper<ut64> bits_mapper_default = std::function<ut64(RCore *)>([](RCore *core) { return r_config_get_i(core->config, "asm.bits"); });

class ArchMapper
{
	private:
		const Mapper<std::string> arch;
		const Mapper<std::string> flavor;
		const Mapper<bool> big_endian;
		const Mapper<ut64> bits;

	public:
		const int minopsz;
		const int maxopsz;
	public:
		ArchMapper(
				const Mapper<std::string> arch,
				const Mapper<std::string> flavor = "default",
				const Mapper<ut64> bits = bits_mapper_default,
				const Mapper<bool> big_endian = big_endian_mapper_default,
				const int minopsz = 0,
				const int maxopsz = 0)
			: arch(arch), flavor(flavor), bits(bits), big_endian(big_endian), minopsz(minopsz), maxopsz(maxopsz) {}

		std::string Map(RCore *core) const
		{
			return arch.Map(core)
				+ ":" + (big_endian.Map(core) ? "BE" : "LE")
				+ ":" + to_string(bits.Map(core))
				+ ":" + flavor.Map(core)
				+ ":" + CompilerFromCore(core);
		}
};

#define BITS (r_config_get_i(core->config, "asm.bits"))
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
			return BITS == 16 ? "Real Mode" : "default";
		}), bits_mapper_default, false, 1, 16
	}},
	{ "mips", { "MIPS", "default",
		bits_mapper_default, big_endian_mapper_default, 4, 4
	}},
	{ "dalvik", { "Dalvik", "default",
		bits_mapper_default, big_endian_mapper_default, 2, 10
	}},
	{ "tricore", { "tricore", "default", 32, true } },
	{ "6502", { "6502", "default", 16 } },
	{ "java", { "JVM", "default", bits_mapper_default, true } },
	{ "hppa", { "pa-risc" } },
	{ "toy", { "Toy" } },
	{ "ppc", { "PowerPC" } },
	{ "8051", { "8051" } },
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
		CUSTOM_FLAVOR((RCore *core) {
			const char *cpu = r_config_get(core->config, "asm.cpu");
			if(!cpu)
				return "default";
			if(strcmp(cpu, "68020") == 0)
				return "MC68020";
			if(strcmp(cpu, "68030") == 0)
				return "MC68030";
			if(strcmp(cpu, "68060") == 0)
				return "Coldfire"; // may not be accurate!!
			return "default";
		}),
		32 } },
	{ "tricore", {
		"tricore",
		CUSTOM_FLAVOR((RCore *core) {
			const char *cpu = r_config_get(core->config, "asm.cpu");
			if(!cpu)
				return "default";
			if(strcmp(cpu, "tc29x") == 0)
				return "tc29x";
			if(strcmp(cpu, "tc172x") == 0)
				return "tc172x";
			if(strcmp(cpu, "tc176x") == 0)
				return "tc176x";
			return "default";
		}),
		32 } },
	{ "arm", {
	 	CUSTOM_BASEID((RCore *core) {
			return BITS == 64 ? "AARCH64" : "ARM";
		}),
		CUSTOM_FLAVOR((RCore *core) {
			return BITS == 64 ? "v8A" : "v7";
		}),
		CUSTOM_BITS((RCore *core) {
			return BITS == 64 ? 64 : 32;
		}),
		false, 2, 4
	}},
	{ "avr", {
		CUSTOM_BASEID((RCore *core) {
			return BITS == 32 ? "avr32a" : "avr8";
		}),
		"default",
		CUSTOM_BITS((RCore *core) {
			return BITS == 32 ? 32 : 16;
		})}},

	{ "v850", {
		CUSTOM_BASEID((RCore *core) {
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

static const std::map<std::string, std::string> compiler_map = {
	{ "elf", "gcc" },
	{ "pe", "windows" },
	{ "mach0", "gcc" }
};

std::string CompilerFromCore(RCore *core)
{
	RBinInfo *info = r_bin_get_info(core->bin);
	if (!info || !info->rclass)
		return std::string();

	auto comp_it = compiler_map.find(info->rclass);
	if(comp_it == compiler_map.end())
		return std::string();

	return comp_it->second;
}

std::string SleighIdFromCore(RCore *core)
{
	SleighArchitecture::collectSpecFiles(std::cerr);
	auto langs = SleighArchitecture::getLanguageDescriptions();
	const char *arch = r_config_get(core->config, "asm.arch");
	if(!strcmp(arch, "r2ghidra"))
		return SleighIdFromSleighAsmConfig(core->rasm->cpu, core->rasm->bits, core->rasm->big_endian, langs);
	auto arch_it = arch_map.find(arch);
	if(arch_it == arch_map.end())
		throw LowlevelError("Could not match asm.arch " + std::string(arch) + " to sleigh arch.");
	return arch_it->second.Map(core);
}

std::string StrToLower(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });
    return s;
}

int ai(RCore *core, std::string cpu, int query) {
	size_t pos = cpu.find(":");
	std::string cpuname = (pos != string::npos)
		? StrToLower(cpu.substr(0, pos))
		: StrToLower(cpu);
	auto arch_it = arch_map.find(cpuname);
	if(arch_it == arch_map.end()) {
		return 1; // throw LowlevelError("Could not match asm.arch " + std::string(arch) + " to sleigh arch.");
	}
	const ArchMapper *am = &arch_it->second;
	// auto res = arch_it->second.Map(core);
	switch (query) {
	case R_ANAL_ARCHINFO_MIN_OP_SIZE:
		return am->minopsz;
	case R_ANAL_ARCHINFO_MAX_OP_SIZE:
		return am->maxopsz;
	// case R_ANAL_ARCHINFO_ALIGN:
	//	return proc.align;
	}
	return 1;
}

std::string SleighIdFromSleighAsmConfig(const char *cpu, int bits, bool bigendian, const vector<LanguageDescription> &langs)
{
	if(std::string(cpu).find(':') != string::npos) {// complete id specified
		return cpu;
	}
	// short form if possible
	std::string low_cpu = StrToLower(cpu);
	for(const auto &lang : langs)
	{
		auto proc = lang.getProcessor();
		if(StrToLower(proc) == low_cpu)
		{
			return proc 
				+ ":" + (bigendian ? "BE" : "LE")
				+ ":" + to_string(bits)
				+ ":" + "default";
		}
	}
	return cpu;
}
