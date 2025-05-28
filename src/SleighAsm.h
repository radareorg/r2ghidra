/* r2ghidra - LGPL - Copyright 2020-2021 - FXTi */

#ifndef R2GHIDRA_SLEIGHASM_H
#define R2GHIDRA_SLEIGHASM_H

#include <string>
#include <vector>
#include <r_core.h>
#include <unordered_map>
#include "architecture.hh"
#include "sleigh_arch.hh"
#include "SleighInstruction.h"

class AsmLoadImage : public ghidra::LoadImage {
private:
	RIO *io = nullptr;

public:
	AsmLoadImage(RIO *io): ghidra::LoadImage("radare2_program"), io(io) {}
	virtual void loadFill(ghidra::uint1 *ptr, ghidra::int4 size, const ghidra::Address &addr) {
		r_io_read_at (io, addr.getOffset(), ptr, size);
	}
	virtual std::string getArchType(void) const {
		return "radare2";
	}
	virtual void adjustVma(long adjust) {
		throw ghidra::LowlevelError ("Cannot adjust radare2 virtual memory");
	}
};

class SleighAsm;

class AssemblySlg : public ghidra::AssemblyEmit {
private:
	SleighAsm *sasm = nullptr;
public:
	char *str = nullptr;

	AssemblySlg(SleighAsm *s): sasm(s) {}

	void dump(const ghidra::Address &addr, const std::string &mnem, const std::string &body) override;

	~AssemblySlg() {
		free (str);
	}
};

struct PcodeOperand {
	PcodeOperand(ghidra::uintb offset, ghidra::uint4 size): type(RAM), offset(offset), size(size) {}
	PcodeOperand(ghidra::uintb number): type(CONSTANT), number(number), size(0) {}
	PcodeOperand(const std::string &name, ghidra::uint4 size): type(REGISTER), name(name), size(size) {}
	virtual ~PcodeOperand() {
		if (type == REGISTER) {
			using namespace std;
			name.~string();
		}
	}

	union {
		std::string name;
		ghidra::uintb offset;
		ghidra::uintb number;
	};
	ghidra::uint4 size;

	enum {
		REGISTER,
		RAM,
		CONSTANT,
		UNIQUE
	} type;

	PcodeOperand(const PcodeOperand &rhs) {
		type = rhs.type;
		size = rhs.size;

		switch (type) {
		case REGISTER: name = rhs.name; break;
		case UNIQUE: /* Same as RAM */
		case RAM: offset = rhs.offset; break;
		case CONSTANT: number = rhs.number; break;
		default: throw ghidra::LowlevelError("Unexpected type of PcodeOperand found in operator==.");
		}
	}

	bool operator==(const PcodeOperand &rhs) const {
		if (type != rhs.type) {
			return false;
		}
		switch (type) {
		case REGISTER: return name == rhs.name;
		case UNIQUE: /* Same as RAM */
		case RAM: return offset == rhs.offset && size == rhs.size;
		case CONSTANT: return number == rhs.number;
		default: throw ghidra::LowlevelError("Unexpected type of PcodeOperand found in operator==.");
		}
	}
	bool is_unique() const { return type == UNIQUE; }
	bool is_const() const { return type == CONSTANT; }
	bool is_ram() const { return type == RAM; }
	bool is_reg() const { return type == REGISTER; }
};

std::ostream &operator<<(std::ostream &s, const PcodeOperand &arg);

typedef ghidra::OpCode PcodeOpType;

struct Pcodeop {
	PcodeOpType type;

	PcodeOperand *output = nullptr;
	PcodeOperand *input0 = nullptr;
	PcodeOperand *input1 = nullptr;
	/* input2 for STORE will use output to save memory space */

	Pcodeop(PcodeOpType opc, PcodeOperand *in0, PcodeOperand *in1, PcodeOperand *out):
	    type(opc), input0(in0), input1(in1), output(out) {
	}

	void fini() {
		if (output) {
			delete output;
		}
		if (input0) {
			delete input0;
		}
		if (input1) {
			delete input1;
		}
	}
};

std::ostream &operator<<(std::ostream &s, const Pcodeop &op);

struct UniquePcodeOperand: public PcodeOperand {
	const Pcodeop *def = nullptr;
	UniquePcodeOperand(const PcodeOperand *from): PcodeOperand(*from) {}
	~UniquePcodeOperand() = default;
};

class PcodeSlg : public ghidra::PcodeEmit {
private:
	SleighAsm *sanal = nullptr;

	PcodeOperand *parse_vardata(ghidra::VarnodeData &data);

public:
	std::vector<Pcodeop> pcodes;

	PcodeSlg(SleighAsm *s): sanal(s) {}

	void dump(const ghidra::Address &addr, ghidra::OpCode opc, ghidra::VarnodeData *outvar, ghidra::VarnodeData *vars, ghidra::int4 isize) override {
		PcodeOperand *out = nullptr, *in0 = nullptr, *in1 = nullptr;

		if (opc == ghidra::CPUI_CALLOTHER) {
			isize = isize > 2? 2: isize;
		}
		switch (isize) {
		case 3: out = parse_vardata (vars[2]); // Only for STORE
		case 2: in1 = parse_vardata (vars[1]);
		case 1: in0 = parse_vardata (vars[0]);
		case 0: break;
		default: throw ghidra::LowlevelError ("Unexpexted isize in PcodeSlg::dump()");
		}

		if (outvar) {
			out = parse_vardata (*outvar);
		}
		pcodes.push_back (Pcodeop(opc, in0, in1, out));
	}

	~PcodeSlg() {
		while (!pcodes.empty()) {
			pcodes.back().fini();
			pcodes.pop_back();
		}
	}
};

struct R2Reg {
	std::string name;
	ut64 size;
	ut64 offset;
};

class R2Sleigh;

class SleighAsm {
private:
	AsmLoadImage loader;
	ghidra::ContextInternal context;
	ghidra::DocumentStorage docstorage;
	ghidra::FileManage specpaths;
	std::vector<ghidra::LanguageDescription> description;
	int languageindex;

	void initInner(RIO *io, std::string sleigh_id);
	void initRegMapping(void);
	void collectSpecfiles(void);
	void scanSleigh(const std::string &rootpath);
	void resolveArch(const std::string &archid);
	void buildSpecfile(ghidra::DocumentStorage &store);
	void parseProcConfig(ghidra::DocumentStorage &store);
	void parseCompConfig(ghidra::DocumentStorage &store);
	void loadLanguageDescription(const std::string &specfile);

public:
	static std::string getSleighHome(RConfig *cfg);
	R2Sleigh trans;
	std::string sleigh_id;
	int alignment = 1;
	int minopsz = 1;
	int maxopsz = 1;
	std::string pc_name;
	std::string sp_name;
	std::vector<std::string> arg_names; // default ABI's function args
	std::vector<std::string> ret_names; // default ABI's function retvals
	std::unordered_map<std::string, std::string> reg_group;
	// To satisfy radare2's rule: reg name has to be lowercase.
	std::unordered_map<std::string, std::string> reg_mapping;
	SleighAsm(): loader(nullptr), trans(nullptr, nullptr) {}
	void init(const char *cpu, int bits, bool bigendian, RIO *io, RConfig *cfg);
	int disassemble(RAnalOp *op, unsigned long long offset);
	int genOpcode(PcodeSlg &pcode_slg, ghidra::Address &addr);
	std::vector<R2Reg> getRegs(void);
	static RConfig *getConfig(RCore *c);
	static RConfig *getConfig(RAnal *a);
	void check(ut64 offset, const ut8 *buf, int len);
};

#endif // R2GHIDRA_SLEIGHASM_H
