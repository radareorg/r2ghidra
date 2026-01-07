/* r2ghidra - LGPL - Copyright 2020-2026 - pancake, FXTi */

#include "SleighAsm.h"
#include "SleighAnalValue.h"
#include "ArchMap.h"

#include <r_lib.h>
#include <r_anal.h>

#include <algorithm>
#include <cfloat>
#include <cmath>
#include <cfenv>

// XXX dont use globals
static SleighAsm *sanal = nullptr;
#if R2_VERSION_NUMBER < 50909
extern "C" RCore *Gcore;
#endif

static char *slid(RCore *core, const char *cpu, int bits, bool be) {
	R_LOG_DEBUG ("slid (%s:%d:%d)", cpu, bits, be);
	if (core == nullptr) {
		R_LOG_ERROR ("cannot slid with nul core");
		return NULL;
	}
	if (sanal == nullptr) {
		sanal = new SleighAsm ();
	}
	if (!strchr (cpu, ':')) {
		auto langs = SleighArchitecture::getLanguageDescriptions ();
		std::string res = SleighIdFromSleighAsmConfig (core, cpu, bits, be, langs);
		return strdup (res.c_str ());
	}
	return strdup (cpu);
}

static char *slid_arch(RAnal *anal) {
#if R2_VERSION_NUMBER >= 50609
	// const char *cp = anal->config->cpu;
	const char *cp = anal->config->cpu;
	int bi = anal->config->bits;
	bool be = anal->config->big_endian;
#else
	const char *cp = anal->cpu;
	int bi = anal->bits;
	bool be = anal->big_endian;
#endif
	if (R_STR_ISEMPTY (cp)) {
		return nullptr;
	}
	char *cpu = slid ((RCore*)anal->coreb.core, cp, bi, be);
	try {
		sanal->init (cpu, bi, be, anal? anal->iob.io: nullptr, SleighAsm::getConfig (anal));
	} catch (const LowlevelError &e) {
		R_FREE (cpu);
		std::cerr << "SleightInit " << e.explain << std::endl;
		return nullptr;
	}
	return cpu;
}

#if R2_VERSION_NUMBER >= 50809

extern "C" int archinfo(RArchSession *as, ut32 query) {
	R_RETURN_VAL_IF_FAIL (as, 1);
#if R2_VERSION_NUMBER >= 50909
	RBin *bin = (RBin*)as->arch->binb.bin;
	RIO *io = (RIO*)bin->iob.io;
	RCore *Gcore = (RCore *)io->coreb.core;
#endif
	char *arch = slid_arch (Gcore->anal); // is this initializing sanal global ptr?
	if (sanal != nullptr) {
		switch (query) {
#if R2_VERSION_NUMBER >= 50909
		case R_ARCH_INFO_MAXOP_SIZE:
			return sanal->maxopsz;
		case R_ARCH_INFO_MINOP_SIZE:
			return sanal->minopsz;
#else
		case R_ARCH_INFO_MAX_OP_SIZE:
			return sanal->maxopsz;
		case R_ARCH_INFO_MIN_OP_SIZE:
			return sanal->minopsz;
#endif
		case R_ARCH_INFO_CODE_ALIGN:
		case R_ARCH_INFO_DATA_ALIGN:
			return sanal->alignment;
		}
	}
	return 1;
}
#else
extern "C" int archinfo(RAnal *anal, int query) {
	// This is to check if RCore plugin set cpu properly.
	R_RETURN_VAL_IF_FAIL (anal, -1);
	if (R_STR_ISEMPTY (anal->config->cpu)) {
		return -1;
	}
	char *arch = slid_arch (anal);
	switch (query) {
	case R_ANAL_ARCHINFO_MAX_OP_SIZE:
		return sanal->maxopsz;
	case R_ANAL_ARCHINFO_MIN_OP_SIZE:
		return sanal->minopsz;
	case R_ANAL_ARCHINFO_ALIGN:
		return sanal->alignment;
	}

	return -1;
}
#endif

static std::vector<std::string> string_split(const std::string &s) {
	std::vector<std::string> tokens;
	for (ut64 i = 0; i < s.size();) {
		std::string tmp;
		while (i < s.size() && !std::isalnum(s[i])) {
			i++;
		}
		while (i < s.size() && std::isalnum(s[i])) {
			tmp.push_back(s[i++]);
		}
		tokens.emplace_back(tmp);
	}
	return tokens;
}

static inline bool reg_set_has(const std::unordered_set<std::string> &reg_set, const SleighAnalValue &value) {
	if (!value.is_reg()) {
		return false;
	}
	if (value.reg && reg_set.find (value.reg) != reg_set.end()) {
		return true;
	}
	if (value.regdelta && reg_set.find (value.regdelta) != reg_set.end()) {
		return true;
	}
	return false;
}

/* After some consideration, I decide to classify mov operation:
 * R_ANAL_OP_TYPE_STORE:
 *     CONST -> MEM (Key: STORE)
 *     CONST -> MEM (Key: COPY)
 *     REG -> MEM (Key: STORE)
 *     REG -> MEM (Key: COPY)
 * R_ANAL_OP_TYPE_LOAD:
 *     MEM -> REG (Key: LOAD)
 *     MEM -> REG (Key: COPY)
 * R_ANAL_OP_TYPE_MOV:
 *     REG   -> REG (Key: COPY)
 *     CONST -> REG (Key: COPY)
 *     CONST -> MEM (Key: STORE)
 *     MEM   -> MEM (Key: LOAD & STORE) // Never happen as far as I know
 */

static ut32 anal_type_MOV(RAnal *anal, RAnalOp *anal_op, const std::vector<Pcodeop> &raw_ops,
                          const std::unordered_set<std::string> &reg_set) {
	const ut32 this_type = R_ANAL_OP_TYPE_MOV;
	const PcodeOpType key_pcode_copy = CPUI_COPY;
	const PcodeOpType key_pcode_store = CPUI_STORE;
	SleighAnalValue in0, out;
	in0.invalid(); out.invalid();
	std::vector<SleighAnalValue> outs;

	for (auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); iter++) {
		if (iter->type == key_pcode_copy) {
			if (iter->output) {
				outs = SleighAnalValue::resolve_out (anal, iter, raw_ops.cend(), iter->output);
			}
			auto p = outs.cbegin();
			for (; p != outs.cend() && !reg_set_has(reg_set, *p); p++) {}
			if (p != outs.cend()) {
				out = *p;
				if (iter->input0) {
					in0 = SleighAnalValue::resolve_arg (anal, iter->input0);
				}
				if (in0.is_valid() && (in0.is_imm() || reg_set_has(reg_set, in0))) {
					anal_op->type = this_type;
#if R2_VERSION_NUMBER >= 50709
#pragma message("anal srcs/dsts is disabled from now on")
#else
					anal_op->src[0] = in0.dup ();
					anal_op->dst = out.dup ();
#endif
					return this_type;
				}
			}
		}
		if (iter->type == key_pcode_store) {
			if (iter->output) {
				in0 = SleighAnalValue::resolve_arg (anal, iter->output);
			}
			if (iter->input1) {
				out = SleighAnalValue::resolve_arg (anal, iter->input1);
			}
			if (in0.is_valid() && out.is_valid() && in0.is_imm()) {
				out.mem(iter->output->size);
				anal_op->type = this_type;
#if R2_VERSION_NUMBER >= 50709
#pragma warning("anal srcs/dsts is disabled from now on")
#else
				anal_op->src[0] = in0.dup ();
				anal_op->dst = out.dup ();
#endif
				return this_type;
			}
		}
	}

	return 0;
}

static ut32 anal_type_LOAD(RAnal *anal, RAnalOp *anal_op, const std::vector<Pcodeop> &raw_ops,
                           const std::unordered_set<std::string> &reg_set) {
	/*
	 * R_ANAL_OP_TYPE_LOAD:
	 *     MEM -> REG (Key: LOAD)
	 *     MEM -> REG (Key: COPY)
	 */
	const ut32 this_type = R_ANAL_OP_TYPE_LOAD;
	const PcodeOpType key_pcode_load = CPUI_LOAD;
	const PcodeOpType key_pcode_copy = CPUI_COPY;
	SleighAnalValue in0, out;
	in0.invalid(); out.invalid();
	std::vector<SleighAnalValue> outs;

	for (auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); iter++) {
		if (iter->type == key_pcode_load || iter->type == key_pcode_copy) {
			if (iter->output) {
				outs = SleighAnalValue::resolve_out (anal, iter, raw_ops.cend(), iter->output);
			}
			auto p = outs.cbegin();
			for (; p != outs.cend() && !reg_set_has(reg_set, *p); p++) {
				// nothing
			}
			if (p != outs.cend ()) {
				out = *p;
				if (iter->type == key_pcode_load? iter->input1: iter->input0) {
					in0 = SleighAnalValue::resolve_arg (anal,
					                  iter->type == key_pcode_load? iter->input1: iter->input0);
					if (iter->type == key_pcode_load && in0.is_valid()) {
						in0.mem(iter->output->size);
					}
				}

				if (in0.is_valid() && in0.is_mem()) {
					anal_op->type = this_type;
#if R2_VERSION_NUMBER >= 50709
#pragma warning("anal srcs/dsts is disabled from now on")
#else
					anal_op->src[0] = in0.dup ();
					anal_op->dst = out.dup ();
#endif
					return this_type;
				}
			}
		}
	}

	return 0;
}

static ut32 anal_type_STORE(RAnal *anal, RAnalOp *anal_op, const std::vector<Pcodeop> &raw_ops,
                            const std::unordered_set<std::string> &reg_set) {
	/*
	 * R_ANAL_OP_TYPE_STORE:
	 *     CONST -> MEM (Key: STORE)
	 *     CONST -> MEM (Key: COPY)
	 *     REG -> MEM (Key: STORE)
	 *     REG -> MEM (Key: COPY)
	 */
	const ut32 this_type = R_ANAL_OP_TYPE_STORE;
	const PcodeOpType key_pcode_store = CPUI_STORE;
	const PcodeOpType key_pcode_copy = CPUI_COPY;
	SleighAnalValue in0, out;
	in0.invalid(); out.invalid();
	std::vector<SleighAnalValue> outs;

	for (auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); iter++) {
		if (iter->type == key_pcode_store) {
			if (iter->output && iter->input1) {
				in0 = SleighAnalValue::resolve_arg (anal, iter->output);

			}
			if (!in0.is_valid() || !(in0.is_imm() || reg_set_has(reg_set, in0))) {
				continue;
			}
			out = SleighAnalValue::resolve_arg (anal, iter->input1);
			if (out.is_valid()) {
				out.mem(iter->output->size);
				anal_op->type = this_type;
#if R2_VERSION_NUMBER >= 50709
#pragma warning("anal srcs/dsts is disabled from now on")
#else
				anal_op->src[0] = in0.dup ();
				anal_op->dst = out.dup ();
#endif
				return this_type;
			}
		}

		if (iter->type == key_pcode_copy) {
			if (iter->input0 && iter->output) {
				in0 = SleighAnalValue::resolve_arg (anal, iter->input0);
			}
			if (!in0.is_valid() || !(in0.is_imm() || reg_set_has(reg_set, in0))) {
				continue;
			}
			outs = SleighAnalValue::resolve_out (anal, iter, raw_ops.cend(), iter->output);

			auto p = outs.cbegin();
			for (; p != outs.cend(); p++) {
				out = *p;
				if (out.is_valid() && out.is_mem()) {
					anal_op->type = this_type;
#if R2_VERSION_NUMBER >= 50709
#pragma warning("anal srcs/dsts is disabled from now on")
#else
					anal_op->src[0] = in0.dup ();
					anal_op->dst = out.dup ();
#endif
					return this_type;
				}
			}
		}
	}
	return 0;
}

static ut32 anal_type_XSWI(RAnal *anal, RAnalOp *anal_op, const std::vector<Pcodeop> &raw_ops, const std::unordered_set<std::string> &reg_set) {
	// R_ANAL_OP_TYPE_CSWI
	// R_ANAL_OP_TYPE_SWI
	const PcodeOpType key_pcode_callother = CPUI_CALLOTHER;
	const PcodeOpType key_pcode_cbranch = CPUI_CBRANCH;
	bool has_cbranch = false;

	for (auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); iter++) {
		if (iter->type == key_pcode_cbranch) {
			has_cbranch = true;
		}
		if (iter->type == key_pcode_callother) {
			if (iter->input1) {
				anal_op->val = iter->input1->number;
			}
			anal_op->type = has_cbranch? R_ANAL_OP_TYPE_CSWI: R_ANAL_OP_TYPE_SWI;
			return anal_op->type;
		}
	}

	return 0;
}

static ut32 anal_type_XPUSH(RAnal *anal, RAnalOp *anal_op, const std::vector<Pcodeop> &raw_ops,
                            const std::unordered_set<std::string> &reg_set) {
	// R_ANAL_OP_TYPE_UPUSH
	// R_ANAL_OP_TYPE_RPUSH
	// R_ANAL_OP_TYPE_PUSH
	const PcodeOpType key_pcode = CPUI_STORE;
	SleighAnalValue out, in;
	out.invalid(); in.invalid();

	for (auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); iter++) {
		if (iter->type == key_pcode) {
			if (iter->input1) {
				out = SleighAnalValue::resolve_arg (anal, iter->input1);
			}
			if (!out.is_valid()) {
				continue;
			}
			out.mem (iter->output->size);
#if R2_VERSION_NUMBER >= 50809
			if ((out.reg && sanal->reg_mapping[sanal->sp_name] == out.reg) ||
			   (out.regdelta && sanal->reg_mapping[sanal->sp_name] == out.regdelta))
#else
			if ((out.reg && sanal->reg_mapping[sanal->sp_name] == out.reg->name) ||
			   (out.regdelta && sanal->reg_mapping[sanal->sp_name] == out.regdelta->name))
#endif
			{
				anal_op->type = R_ANAL_OP_TYPE_UPUSH;
				anal_op->stackop = R_ANAL_STACK_INC;

				if (iter->output) {
					in = SleighAnalValue::resolve_arg (anal, iter->output);
				}
				if (!in.is_valid()) {
					continue;
				}
				if (reg_set_has(reg_set, in)) {
					anal_op->type = R_ANAL_OP_TYPE_RPUSH;
				}
#if R2_VERSION_NUMBER >= 50709
#pragma warning("anal srcs/dsts is disabled from now on")
#else
				anal_op->src[0] = in.dup ();
				anal_op->dst = out.dup ();
#endif
				return anal_op->type;
			}
		}
	}

	return 0;
}

static ut32 anal_type_POP(RAnal *anal, RAnalOp *anal_op, const std::vector<Pcodeop> &raw_ops,
                          const std::unordered_set<std::string> &reg_set) {
	ut32 this_type = R_ANAL_OP_TYPE_POP;
	const PcodeOpType key_pcode = CPUI_LOAD;
	SleighAnalValue in0, out;
	in0.invalid(); out.invalid();
	std::vector<SleighAnalValue> outs;

	for (auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); iter++) {
		if (iter->type == key_pcode) {
			if (iter->input1) {
				in0 = SleighAnalValue::resolve_arg (anal, iter->input1);
			}
			if (!in0.is_valid()) {
				continue;
			}
			// dispose 0x0,  { lp }, [lp]
#if R2_VERSION_NUMBER >= 50809
			if (in0.reg && !strcmp ("lp", in0.reg))
#else
			if (in0.reg && !strcmp ("lp", in0.reg->name))
#endif
			{
				anal_op->type = R_ANAL_OP_TYPE_RET;
#if R2_VERSION_NUMBER >= 50709
#pragma warning("anal srcs/dsts is disabled from now on")
#else
				anal_op->src[0] = in0.dup ();
#endif
				return this_type;
			}

#if R2_VERSION_NUMBER >= 50809
			if ((in0.reg && std::string("lr") == in0.reg) || (in0.regdelta && sanal->reg_mapping[sanal->sp_name] == in0.regdelta))
#else
			if ((in0.reg && std::string("lr") == in0.reg->name) || (in0.regdelta && sanal->reg_mapping[sanal->sp_name] == in0.regdelta->name))
#endif
			{
				if (iter->output) {
					outs = SleighAnalValue::resolve_out (anal, iter, raw_ops.cend(), iter->output);
				}
				auto p = outs.cbegin();
				for (; p != outs.cend() && !reg_set_has(reg_set, *p); p++) {
				}
				if (p == outs.cend()) {
					continue;
				}
				out = *p;

				anal_op->type = this_type;
				anal_op->stackop = R_ANAL_STACK_INC;
#if R2_VERSION_NUMBER >= 50709
#pragma warning("anal srcs/dsts is disabled from now on")
#else
				anal_op->dst = out.dup ();
				anal_op->src[0] = in0.dup ();
#endif
				return this_type;
			}
		}
	}

	return 0;
}

static ut32 anal_type_XCMP(RAnal *anal, RAnalOp *anal_op, const std::vector<Pcodeop> &raw_ops,
                           const std::unordered_set<std::string> &reg_set) {
	// R_ANAL_OP_TYPE_CMP
	// R_ANAL_OP_TYPE_ACMP
	const PcodeOpType key_pcode_sub = CPUI_INT_SUB;
	const PcodeOpType key_pcode_and = CPUI_INT_AND;
	const PcodeOpType key_pcode_equal = CPUI_INT_EQUAL;
	SleighAnalValue in0, in1;
	in0.invalid(); in1.invalid ();
	uintb unique_off = 0;
	PcodeOpType key_pcode = CPUI_MAX;
	bool has_candidate = false;
	PcodeOpType candidate_pcode = CPUI_MAX;
	anal_op->val = UT64_MAX;
	for (auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); iter++) {
		if (iter->type == CPUI_COPY && anal_op->val == UT64_MAX) {
			if (iter->input0->number > 0 && iter->input0->is_const ()) {
				anal_op->val = iter->input0->number;
			}
			continue;
		}
		if (iter->type == key_pcode_sub || iter->type == key_pcode_and) {
			if (iter->input0) {
				in0 = SleighAnalValue::resolve_arg (anal, iter->input0);
			}
			if (iter->input1) {
				in1 = SleighAnalValue::resolve_arg (anal, iter->input1);
			}
			if ((in0.is_valid() && reg_set_has(reg_set, in0)) || (in1.is_valid() && reg_set_has(reg_set, in1))) {
				if (iter->output && iter->output->is_unique()) {
					unique_off = iter->output->offset;
					key_pcode = iter->type;
					has_candidate = true;
					candidate_pcode = iter->type;
				}
			}
		}
		if (unique_off && iter->type == key_pcode_equal) {
			if (!iter->input0 || !iter->input1) {
				continue;
			}
			if (iter->input0->is_const() && iter->input1->is_unique()) {
				if (iter->input0->number != 0 || iter->input1->offset != unique_off) {
					continue;
				}
			} else if (iter->input0->is_unique() && iter->input1->is_const()) {
				// cmp 0x3, r6
				if (iter->input1->number != 0 || iter->input0->offset != unique_off) {
					continue;
				}
			} else {
				continue;
			}
			anal_op->type = key_pcode == key_pcode_sub? R_ANAL_OP_TYPE_CMP: R_ANAL_OP_TYPE_ACMP;
			// anal_op->cond = R_ANAL_COND_EQ; Should I enable this? I think sub can judge equal and
			// less or more.
#if R2_VERSION_NUMBER >= 50709
#pragma warning("anal srcs/dsts is disabled from now on")
#else
			anal_op->src[0] = in0.dup ();
			anal_op->src[1] = in1.dup ();
#endif
			return anal_op->type;
		}
	}

	if (has_candidate) {
		anal_op->type = candidate_pcode == key_pcode_and? R_ANAL_OP_TYPE_ACMP: R_ANAL_OP_TYPE_CMP;
		return anal_op->type;
	}

	return 0;
}

static ut32 anal_type_XXX(RAnal *anal, RAnalOp *anal_op, const std::vector<Pcodeop> &raw_ops,
                              const std::unordered_set<std::string> &reg_set) {
	// R_ANAL_OP_TYPE_ADD
	// R_ANAL_OP_TYPE_SUB
	// R_ANAL_OP_TYPE_MUL
	// R_ANAL_OP_TYPE_DIV
	// R_ANAL_OP_TYPE_MOD
	// R_ANAL_OP_TYPE_OR
	// R_ANAL_OP_TYPE_AND
	// R_ANAL_OP_TYPE_XOR
	// R_ANAL_OP_TYPE_SHR
	// R_ANAL_OP_TYPE_SHL
	// R_ANAL_OP_TYPE_SAR
	SleighAnalValue in0, in1, out;
	in0.invalid(); in1.invalid(); out.invalid();
	std::vector<SleighAnalValue> outs;

	for (auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); iter++) {
		switch (iter->type) {
		case CPUI_INT_ADD:
		case CPUI_INT_SUB:
		case CPUI_INT_MULT:
		case CPUI_INT_DIV:
		case CPUI_INT_REM:
		case CPUI_INT_SREM:
		case CPUI_INT_OR:
		case CPUI_INT_AND:
		case CPUI_INT_XOR:
		case CPUI_INT_RIGHT:
		case CPUI_INT_LEFT:
		case CPUI_INT_SRIGHT:
			{
			if (iter->input0 && iter->input1) {
				in0 = SleighAnalValue::resolve_arg (anal, iter->input0);
				in1 = SleighAnalValue::resolve_arg (anal, iter->input1);
			}

			if ((in0.is_valid() && reg_set_has(reg_set, in0)) || (in1.is_valid() && reg_set_has(reg_set, in1))) {
				if (iter->output) {
					outs = SleighAnalValue::resolve_out (anal, iter, raw_ops.cend(), iter->output);
				}
				auto p = outs.cbegin();
				for (; p != outs.cend() && !reg_set_has(reg_set, *p); p++) {}
				if (p != outs.cend()) {
					out = *p;

					switch (iter->type) {
					case CPUI_INT_ADD: anal_op->type = R_ANAL_OP_TYPE_ADD; break;
					case CPUI_INT_SUB: anal_op->type = R_ANAL_OP_TYPE_SUB; break;
					case CPUI_INT_MULT: anal_op->type = R_ANAL_OP_TYPE_MUL; break;
					case CPUI_INT_DIV: anal_op->type = R_ANAL_OP_TYPE_DIV; break;
					case CPUI_INT_REM:
					case CPUI_INT_SREM: anal_op->type = R_ANAL_OP_TYPE_MOD; break;
					case CPUI_INT_OR: anal_op->type = R_ANAL_OP_TYPE_OR; break;
					case CPUI_INT_AND: anal_op->type = R_ANAL_OP_TYPE_AND; break;
					case CPUI_INT_XOR: anal_op->type = R_ANAL_OP_TYPE_XOR; break;
					case CPUI_INT_RIGHT: anal_op->type = R_ANAL_OP_TYPE_SHR; break;
					case CPUI_INT_LEFT: anal_op->type = R_ANAL_OP_TYPE_SHL; break;
					case CPUI_INT_SRIGHT: anal_op->type = R_ANAL_OP_TYPE_SAR; break;
					default: break;
					}
#if R2_VERSION_NUMBER >= 50709
#pragma warning("anal srcs/dsts is disabled from now on")
#else
					anal_op->src[0] = in0.dup ();
					anal_op->src[1] = in1.dup ();
					anal_op->dst = out.dup ();
#endif
					return anal_op->type;
				}
			}
			}
			break;
		default:
			break;
		}
	}

	return 0;
}

static ut32 anal_type_NOR(RAnal *anal, RAnalOp *anal_op, const std::vector<Pcodeop> &raw_ops,
		const std::unordered_set<std::string> &reg_set) {
	const ut32 this_type = R_ANAL_OP_TYPE_NOR;
	const PcodeOpType key_pcode_or = CPUI_INT_OR;
	const PcodeOpType key_pcode_negate = CPUI_INT_NEGATE;
	SleighAnalValue in0, in1, out;
	in0.invalid(); in1.invalid(); out.invalid();
	std::vector<SleighAnalValue> outs;
	uintb unique_off = 0;

	for (auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); iter++) {
		if (iter->type == key_pcode_or) {
			if (iter->input0 && iter->input1) {
				in0 = SleighAnalValue::resolve_arg (anal, iter->input0);
				in1 = SleighAnalValue::resolve_arg (anal, iter->input1);
			}

			if ((in0.is_valid() && reg_set_has(reg_set, in0)) || (in1.is_valid() && reg_set_has(reg_set, in1))) {
				if (iter->output && iter->output->is_unique()) {
					unique_off = iter->output->offset;
					continue;
				}
			}
		}
		if (unique_off && iter->type == key_pcode_negate) {
			if (iter->input0 && iter->input0->is_unique() && iter->input0->offset == unique_off) {
				if (iter->output) {
					outs = SleighAnalValue::resolve_out (anal, iter, raw_ops.cend(), iter->output);
				}
				auto p = outs.cbegin();
				for (; p != outs.cend() && !reg_set_has(reg_set, *p); p++) {
					// just loop
				}
				if (p != outs.cend()) {
					out = *p;
					anal_op->type = this_type;
#if R2_VERSION_NUMBER >= 50709
#pragma warning("anal srcs/dsts is disabled from now on")
#else
					anal_op->src[0] = in0.dup ();
					anal_op->src[1] = in1.dup ();
					anal_op->dst = out.dup ();
#endif
					return this_type;
				}
			}
		}
	}

	return 0;
}

static ut32 anal_type_NOT(RAnal *anal, RAnalOp *anal_op, const std::vector<Pcodeop> &raw_ops,
                          const std::unordered_set<std::string> &reg_set) {
	const ut32 this_type = R_ANAL_OP_TYPE_NOT;
	const PcodeOpType key_pcode = CPUI_INT_NEGATE;
	SleighAnalValue in0, out;
	in0.invalid(); out.invalid();
	std::vector<SleighAnalValue> outs;
	uintb unique_off = 0;

	for (auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); iter++) {
		if (iter->type == key_pcode) {
			if (iter->input0) {
				in0 = SleighAnalValue::resolve_arg (anal, iter->input0);
			}
			if (in0.is_valid() && reg_set_has(reg_set, in0)) {
				if (iter->output) {
					outs = SleighAnalValue::resolve_out (anal, iter, raw_ops.cend(), iter->output);
				}
				auto p = outs.cbegin();
				for (; p != outs.cend() && !reg_set_has(reg_set, *p); p++) {}
				if (p != outs.cend()) {
					out = *p;
					anal_op->type = this_type;
#if R2_VERSION_NUMBER >= 50709
#pragma warning("anal srcs/dsts is disabled from now on")
#else
					anal_op->src[0] = in0.dup ();
					anal_op->dst = out.dup ();
#endif
					return this_type;
				}
			}
		}
	}

	return 0;
}

static ut32 anal_type_XCHG(RAnal *anal, RAnalOp *anal_op, const std::vector<Pcodeop> &raw_ops,
		const std::unordered_set<std::string> &reg_set) {
	const ut32 this_type = R_ANAL_OP_TYPE_XCHG;
	const PcodeOpType key_pcode = CPUI_COPY;
	std::vector<decltype(raw_ops.cbegin())> copy_vec;

	for (auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); iter++) {
		if (iter->type == key_pcode) {
			copy_vec.emplace_back(iter);
		}
	}
	if (copy_vec.size() == 3) {
		if (!(*copy_vec[0]->input0 == *copy_vec[1]->output)) {
			goto fail;
		}
		if (!(*copy_vec[0]->output == *copy_vec[2]->input0)) {
			goto fail;
		}
		if (!(*copy_vec[1]->input0 == *copy_vec[2]->output)) {
			goto fail;
		}
		anal_op->type = this_type;
#if R2_VERSION_NUMBER >= 50709
#pragma warning("anal srcs/dsts is disabled from now on");
#else
		anal_op->src[0] = SleighAnalValue::resolve_arg (anal, copy_vec[0]->input0).dup ();
		anal_op->dst = SleighAnalValue::resolve_arg (anal, copy_vec[2]->output).dup ();
#endif
		return this_type;
	}

fail:
	return 0;
}

static ut32 anal_type_SINGLE(RAnal *anal, RAnalOp *anal_op, const std::vector<Pcodeop> &raw_ops,
                             const std::unordered_set<std::string> &reg_set) {
	// R_ANAL_OP_TYPE_CAST
	// R_ANAL_OP_TYPE_NEW
	// R_ANAL_OP_TYPE_ABS
	for (auto iter = raw_ops.cbegin(); iter != raw_ops.cend(); iter++) {
		switch (iter->type) {
		case CPUI_CAST: anal_op->type = R_ANAL_OP_TYPE_CAST; return anal_op->type;
		case CPUI_NEW: anal_op->type = R_ANAL_OP_TYPE_NEW; return anal_op->type;
		case CPUI_FLOAT_ABS: anal_op->type = R_ANAL_OP_TYPE_ABS; return anal_op->type;
		default: break;
		}
	}

	return 0;
}

static void anal_type(RAnal *anal, RAnalOp *anal_op, PcodeSlg &pcode_slg, AssemblySlg &assem) {
	std::vector<std::string> args = string_split(assem.str);
	std::unordered_set<std::string> reg_set;
	std::map<VarnodeData, std::string> reglist;
	sanal->trans.getAllRegisters(reglist);
	for (auto iter = args.cbegin(); iter != args.cend(); iter++) {
		for (auto p = reglist.cbegin (); p != reglist.cend(); p++) {
			if (sanal->reg_mapping[p->second] == *iter) {
				reg_set.insert (*iter);
				break;
			}
		}
	}

	std::unordered_map<uintb, const Pcodeop *> midvar_op;
	for (auto pco = pcode_slg.pcodes.begin(); pco != pcode_slg.pcodes.end(); pco++) {
		if (pco->input0 && pco->input0->is_unique()) {
			UniquePcodeOperand *tmp = new UniquePcodeOperand(pco->input0);
			delete pco->input0;
			pco->input0 = (PcodeOperand *)tmp;
			tmp->def = midvar_op[tmp->offset];
		}
		if (pco->input1 && pco->input1->is_unique()) {
			UniquePcodeOperand *tmp = new UniquePcodeOperand(pco->input1);
			delete pco->input1;
			pco->input1 = (PcodeOperand *)tmp;
			tmp->def = midvar_op[tmp->offset];
		}
		if (pco->type != CPUI_STORE) {
			// You should know this case:
			// (unique, 0xffff, 4) = INT_ADD (unique, 0xffff, 4), 2
			// Even unique varnode can be overwritten!
			// Here midvar_op will always track the latest define place.
			if (pco->output && pco->output->is_unique()) {
				midvar_op[pco->output->offset] = &(*pco);
			}
		} else {
			if (pco->output && pco->output->is_unique()) {
				UniquePcodeOperand *tmp = new UniquePcodeOperand(pco->output);
				delete pco->output;
				pco->output = (PcodeOperand *)tmp;
				tmp->def = midvar_op[tmp->offset];
			}
		}
	}

	anal_op->type = R_ANAL_OP_TYPE_UNK;
	if (anal_type_XCHG (anal, anal_op, pcode_slg.pcodes, reg_set)) {
		return;
	}
	if (anal_type_SINGLE (anal, anal_op, pcode_slg.pcodes, reg_set)) {
		return;
	}
	if (anal_type_XSWI (anal, anal_op, pcode_slg.pcodes, reg_set)) {
		return;
	}
	if (anal_type_XCMP (anal, anal_op, pcode_slg.pcodes, reg_set)) {
		return;
	}
	if (anal_type_NOR (anal, anal_op, pcode_slg.pcodes, reg_set)) {
		return;
	}
	if (anal_type_XPUSH (anal, anal_op, pcode_slg.pcodes, reg_set)) {
		return;
	}
	if (anal_type_POP (anal, anal_op, pcode_slg.pcodes, reg_set)) {
		return;
	}
	if (anal_type_STORE (anal, anal_op, pcode_slg.pcodes, reg_set)) {
		return;
	}
	if (anal_type_LOAD (anal, anal_op, pcode_slg.pcodes, reg_set)) {
		return;
	}
	if (anal_type_XXX (anal, anal_op, pcode_slg.pcodes, reg_set)) {
		return;
	}
	if (anal_type_NOT (anal, anal_op, pcode_slg.pcodes, reg_set)) {
		return;
	}
	if (anal_type_MOV (anal, anal_op, pcode_slg.pcodes, reg_set)) {
		return;
	}
	return;
}

static char *getIndirectReg(SleighInstruction *ins, bool &isRefed) {
	VarnodeData data = ins->getIndirectInvar();
	isRefed = data.size & 0x80000000;
	if (isRefed) {
		data.size &= ~0x80000000;
	}
	AddrSpace *space = data.space;
	if (space->getName() == "register") {
		auto index = space->getTrans()->getRegisterName(data.space, data.offset, data.size);
		return strdup (sanal->reg_mapping[index].c_str());
	}
	return nullptr;
}

static int index_of_unique(const std::vector<PcodeOperand *> &esil_stack, const PcodeOperand *arg) {
	int index = 1;
	for (auto iter = esil_stack.crbegin(); iter != esil_stack.crend(); iter++, index++) {
		if (*iter && **iter == *arg) {
			return index;
		}
	}
	return -1;
}

static void sleigh_esil(RAnal *a, RAnalOp *anal_op, ut64 addr, const ut8 *data, int len, const std::vector<Pcodeop> &Pcodes) {
	std::vector<PcodeOperand *> esil_stack;
	std::stringstream ss;

	auto print_if_unique = [&esil_stack, &ss](const PcodeOperand *arg, int offset = 0) -> bool {
		if (arg->is_unique()) {
			int index = index_of_unique(esil_stack, arg);
			if (-1 == index) {
				throw LowlevelError(
				    "print_if_unique: Can't find required unique varnodes in stack.");
			}
			ss << index + offset << ",PICK";
			return true;
		}
		return false;
	};

	auto print_operand = [&esil_stack, &ss](const PcodeOperand *arg, int offset = 0, bool is_float = false) -> bool {
		if (arg->is_unique()) {
			int index = index_of_unique(esil_stack, arg);
			if (-1 == index) {
				throw LowlevelError(
				    "print_if_unique: Can't find required unique varnodes in stack.");
			}
			if (index + offset > 1) {
				ss << index + offset << ",PICK";
			} else {
				ss << "DUP";
			}
		} else {
			if (!arg->is_ram()) {
				// idky but these NUMs are actually necessary
				ss << *arg << (arg->is_reg()? ",NUM": "");
			} else {
				ss << *arg << ",[" << arg->size << "]";
			}
		}
		if (is_float && arg->size != 8) {
			ss << "," << arg->size << ",SWAP,F2D";
		}
		return true;
	};
	
	auto push_stack = [&esil_stack](PcodeOperand *arg = nullptr) {
		if (arg == nullptr) {
			throw LowlevelError("push_stack: arg is nullptr.");
		}
		esil_stack.push_back (arg);
	};

	for (auto iter = Pcodes.cbegin(); iter != Pcodes.cend(); iter++) {
		switch (iter->type) {
		// FIXME: Maybe some of P-codes below can be processed
		// In dalvik: 0x00000234: array_length 0x1008,0x1008
		//                v2 = CPOOLREF v2, 0x0, 0x6
		case CPUI_CPOOLREF:
		case CPUI_CALLOTHER:
		case CPUI_NEW:
		case CPUI_SEGMENTOP:
		case CPUI_INSERT:
		case CPUI_EXTRACT: /* Above don't have explicit definition */
		case CPUI_MULTIEQUAL:
		case CPUI_INDIRECT:
		case CPUI_CAST:
		case CPUI_PTRADD:
		case CPUI_PTRSUB: /* Above are not raw P-code */
		branch_in_pcodes:
			// ss << ",CLEAR,TODO";
			ss.str("");
			esil_stack.clear();
			iter = --Pcodes.cend(); // Jump out
			break;

		case CPUI_INT_ZEXT:
		case CPUI_INT_SEXT:
		{
			if (iter->input0 && iter->output) {
				ss << ",";
				print_operand (iter->input0);
				if (iter->type == CPUI_INT_SEXT) {
					ss << "," << iter->input0->size * 8 << ",SWAP,~";
					ss << "," << iter->output->size * 8 << ",1,<<,1,SWAP,-,&";
				}

				if (iter->output->is_unique()) {
					push_stack(iter->output);
				} else {
					ss << "," << *iter->output << ",=";
				}
			} else {
				throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
			}
			break;
		}

		case CPUI_COPY:
		{
			if (iter->input0 && iter->output) {
				ss << ",";
				print_operand (iter->input0);

				if (iter->output->is_unique()) {
					push_stack(iter->output);
				} else if (iter->output->is_ram()) {
					ss << "," << *iter->output << ",=[" << iter->output->size << "]";
				} else {
					ss << "," << *iter->output << ",=";
				}
			} else {
				throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
			}
			break;
		}
		case CPUI_LOAD:
		{
			if (iter->input0 && iter->input1 && iter->output) {
				ss << ",";
				print_operand (iter->input1);
				if (iter->input0->is_const() &&
				   ((AddrSpace *)iter->input0->offset)->getWordSize() != 1)
					ss << "," << ((AddrSpace *)iter->input0->offset)->getWordSize() << ",*";
				ss << ",[" << iter->output->size << "]";
				if (iter->output->is_unique()) {
					push_stack(iter->output);
				} else {
					ss << "," << *iter->output << ",=";
				}
			} else {
				throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
			}
			break;
		}

		case CPUI_STORE:
		{
			if (iter->input0 && iter->input1 && iter->output) {
				ss << ",";
				print_operand (iter->output);

				ss << ",";
				if (!print_if_unique(iter->input1, 1))
					ss << *iter->input1;
				if (iter->input0->is_const() &&
				   ((AddrSpace *)iter->input0->offset)->getWordSize() != 1)
					ss << "," << ((AddrSpace *)iter->input0->offset)->getWordSize() << ",*";
				ss << ",=[" << iter->output->size << "]";
			} else {
				throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
			}
			break;
		}

		// TODO: CPUI_BRANCH can jump in the other P-codes of instruction
		// Three P-codes below are all indirect style
		case CPUI_RETURN:
		case CPUI_CALLIND:
		case CPUI_BRANCHIND: // Actually, I have some suspect about this.
		// End here.
		case CPUI_CALL:
		case CPUI_BRANCH:
		{
			if (iter->input0)
			{
				if (iter->input0->is_const())
					// throw LowlevelError("Sleigh_esil: const input case of BRANCH appear.");
					// This means conditional jump in P-codes
					goto branch_in_pcodes;
				ss << ",";
				if (!print_if_unique(iter->input0))
					ss << *iter->input0;

				ss << "," << sanal->reg_mapping[sanal->pc_name] << ",=";
			} else {
				throw LowlevelError ("sleigh_esil: arguments of Pcodes are not well inited.");
			}
			break;
		}
		case CPUI_CBRANCH:
		{
			if (iter->input0 && iter->input1) {
				ss << ",";
				print_operand (iter->input1);

				ss << ",?{";

				if (iter->input0->is_const ()) {
					// throw LowlevelError("Sleigh_esil: const input case of BRANCH appear.");
					// This means conditional jump in P-codes
					goto branch_in_pcodes;
				}
				ss << ",";
				if (!print_if_unique (iter->input0)) {
					ss << *iter->input0;
				}

				ss << "," << sanal->reg_mapping[sanal->pc_name] << ",=,}";
			} else {
				throw LowlevelError ("sleigh_esil: arguments of Pcodes are not well inited.");
			}
			break;
		case CPUI_PIECE:
			if (iter->input0 && iter->input1 && iter->output) {
				ss << ",";
				print_operand (iter->input0);
				ss << "," << iter->input1->size * 8 << ",SWAP,<<,";
				print_operand (iter->input1, 1);

				ss << ",|";
				if (iter->output->is_unique())
					push_stack(iter->output);
				else
					ss << "," << *iter->output << ",=";
			} else {
				throw LowlevelError ("sleigh_esil: arguments of Pcodes are not well inited.");
			}
			break;
		}
		case CPUI_SUBPIECE:
			if (iter->input0 && iter->input1 && iter->output) {
				ss << ",";
				print_operand (iter->input0);
				if (!iter->input1->is_const ())
					throw LowlevelError ("sleigh_esil: input1 is not consts in SUBPIECE.");
				ss << "," << iter->input1->number * 8 << ",SWAP,>>";

				if (iter->output->size < iter->input0->size + iter->input1->number) {
					ss << ",1," << iter->output->size * 8 << ",1,<<,-,&";
				}
				if (iter->output->is_unique()) {
					push_stack(iter->output);
				} else {
					ss << "," << *iter->output << ",=";
				}
			} else {
				throw LowlevelError ("sleigh_esil: arguments of Pcodes are not well inited.");
			}
			break;
		case CPUI_FLOAT_EQUAL:
		case CPUI_FLOAT_NOTEQUAL:
		case CPUI_FLOAT_LESS:
		case CPUI_FLOAT_LESSEQUAL:
		case CPUI_FLOAT_ADD:
		case CPUI_FLOAT_SUB:
		case CPUI_FLOAT_MULT:
		case CPUI_FLOAT_DIV:
			if (iter->input0 && iter->input1 && iter->output) {
				ss << ",";
				print_operand (iter->input1, 0, true);

				ss << ",";
				print_operand (iter->input0, 1, true);

				ss << ",";
				switch (iter->type)
				{
					case CPUI_FLOAT_EQUAL: ss << "F=="; break;
					case CPUI_FLOAT_NOTEQUAL: ss << "F!="; break;
					case CPUI_FLOAT_LESS: ss << "F<"; break;
					case CPUI_FLOAT_LESSEQUAL: ss << "F<="; break;
					case CPUI_FLOAT_ADD: ss << "F+"; break;
					case CPUI_FLOAT_SUB: ss << "F-"; break;
					case CPUI_FLOAT_MULT: ss << "F*"; break;
					case CPUI_FLOAT_DIV: ss << "F/"; break;
				}

				if (iter->output->size != 1 && iter->output->size != 8) 
					ss << "," << iter->output->size << ",SWAP,D2F";

				if (iter->output->is_unique())
					push_stack(iter->output);
				else
					ss << "," << *iter->output << ",=";
			} else {
				throw LowlevelError ("sleigh_esil: arguments of Pcodes are not well inited.");
			}
			break;
		case CPUI_INT_LESS:
		case CPUI_INT_SLESS:
		case CPUI_INT_LESSEQUAL:
		case CPUI_INT_SLESSEQUAL:
		case CPUI_INT_NOTEQUAL:
		case CPUI_INT_EQUAL:
		{
			if (iter->input0 && iter->input1 && iter->output)
			{
				ss << ",";
				print_operand (iter->input1);

				ss << ",";
				print_operand (iter->input0, 1);

				ss << ",";
				switch (iter->type)
				{
					case CPUI_INT_SLESS:
						ss << iter->input0->size * 8 << ",SWAP,~,SWAP,"
						   << iter->input1->size * 8 << ",SWAP,~,SWAP,";
					case CPUI_INT_LESS: ss << "<"; break;
					case CPUI_INT_SLESSEQUAL:
						ss << iter->input0->size * 8 << ",SWAP,~,SWAP,"
						   << iter->input1->size * 8 << ",SWAP,~,SWAP,";
					case CPUI_INT_LESSEQUAL: ss << "<="; break;
					case CPUI_INT_NOTEQUAL: ss << "-,!,!"; break;
					case CPUI_INT_EQUAL: ss << "-,!"; break;
				}
				if (iter->output->is_unique()) {
					push_stack(iter->output);
				} else {
					ss << "," << *iter->output << ",=";
				}
			} else {
				throw LowlevelError ("sleigh_esil: arguments of Pcodes are not well inited.");
			}
			break;
		}
		case CPUI_INT_MULT:
		case CPUI_INT_DIV:
		case CPUI_INT_REM:
		case CPUI_INT_SDIV:
		case CPUI_INT_SREM:
		case CPUI_BOOL_XOR:
		case CPUI_INT_XOR:
		case CPUI_BOOL_AND:
		case CPUI_INT_AND:
		case CPUI_BOOL_OR:
		case CPUI_INT_OR:
		case CPUI_INT_LEFT:
		case CPUI_INT_RIGHT:
		case CPUI_INT_SRIGHT:
		case CPUI_INT_SUB:
		case CPUI_INT_ADD:
			if (iter->input0 && iter->input1 && iter->output) {
				ss << ",";
				print_operand (iter->input1);

				ss << ",";
				print_operand (iter->input0, 1);
				ss << ",";
				switch (iter->type)
				{
					case CPUI_INT_MULT: ss << "*"; break;
					// If divide by zero happen, give out 0
					case CPUI_INT_DIV: ss << "SWAP,DUP,!,?{,1,|,SWAP,0,&,},/"; break;
					case CPUI_INT_REM: ss << "SWAP,DUP,!,?{,1,|,SWAP,0,&,},%"; break;
					case CPUI_INT_SDIV: 
						ss << iter->input0->size * 8 << ",SWAP,~"; 
						ss << ",SWAP," << iter->input1->size * 8 << ",SWAP,~"; 
						ss << ",DUP,!,?{,1,|,SWAP,0,&,},~/"; 
						break;
					case CPUI_INT_SREM:
						ss << iter->input0->size * 8 << ",SWAP,~"; 
						ss << ",SWAP," << iter->input1->size * 8 << ",SWAP,~"; 
						ss << ",DUP,!,?{,1,|,SWAP,0,&,},~%"; 
						break;
					case CPUI_INT_SUB: ss << "-"; break;
					case CPUI_INT_ADD: ss << "+"; break;
					case CPUI_BOOL_XOR:
					case CPUI_INT_XOR: ss << "^"; break;
					case CPUI_BOOL_AND:
					case CPUI_INT_AND: ss << "&"; break;
					case CPUI_BOOL_OR:
					case CPUI_INT_OR: ss << "|"; break;
					case CPUI_INT_LEFT: ss << "<<"; break;
					case CPUI_INT_RIGHT: ss << ">>"; break;
					case CPUI_INT_SRIGHT:
						ss << iter->input0->size * 8 << ",SWAP,~,>>>>";
						break;
				}
				ss << ",1," << iter->output->size * 8 << ",1,<<,-,&";

				if (iter->output->is_unique())
					push_stack(iter->output);
				else
					ss << "," << *iter->output << ",=";
			} else {
				throw LowlevelError ("sleigh_esil: arguments of Pcodes are not well inited.");
			}
			break;
		case CPUI_INT_CARRY:
			if (iter->input0 && iter->input1 && iter->output) {
				ss << ",";
				print_operand (iter->input0);

				ss << ",";
				print_operand (iter->input1, 1);

				ss << ",+," << iter->input0->size * 8 << ",1,<<,1,SWAP,-,&";

				ss << ",";
				print_operand (iter->input0, 1);

				ss << ",>";

				if (iter->output->is_unique()) {
					push_stack(iter->output);
				} else {
					ss << "," << *iter->output << ",=";
				}
			} else {
				throw LowlevelError ("sleigh_esil: arguments of Pcodes are not well inited.");
			}
			break;
		case CPUI_INT_SCARRY:
			if (iter->input0 && iter->input1 && iter->output) {
				ss << ",";
				print_operand (iter->input0);
				ss << "," << iter->input0->size * 8 - 1 << ",SWAP,>>,1,&";
				ss << ",DUP,";
				print_operand (iter->input1, 2);

				ss << "," << iter->input1->size * 8 - 1 << ",SWAP,>>,1,&";

				ss << ",^,1,^,SWAP";

				ss << ",";
				print_operand (iter->input0, 2);

				ss << ",";
				print_operand (iter->input0, 3);
				ss << ",+," << iter->input0->size * 8 - 1 << ",SWAP,>>,1,&"; // (a^b^1), a, c
				ss << ",^,&";
				if (iter->output->is_unique()) {
					push_stack(iter->output);
				} else {
					ss << "," << *iter->output << ",=";
				}
			} else {
				throw LowlevelError ("sleigh_esil: arguments of Pcodes are not well inited.");
			}
			break;
		case CPUI_INT_SBORROW:
			if (iter->input0 && iter->input1 && iter->output) {
				ss << ",";
				print_operand (iter->input1);

				ss << ",";
				print_operand (iter->input0, 1);

				ss << ",-," << iter->input0->size * 8 - 1 << ",SWAP,>>,1,&";

				ss << ",DUP,";
				print_operand (iter->input1, 2);

				ss << "," << iter->input1->size * 8 - 1 << ",SWAP,>>,1,&";

				ss << ",^,1,^,SWAP";

				ss << ",";
				print_operand (iter->input0, 2);

				ss << "," << iter->input0->size * 8 - 1 << ",SWAP,>>,1,&"; // (r^b^1), a, r

				ss << ",^,&";

				if (iter->output->is_unique()) {
					push_stack(iter->output);
				} else {
					ss << "," << *iter->output << ",=";
				}
			} else {
				throw LowlevelError ("sleigh_esil: arguments of Pcodes are not well inited.");
			}
			break;
		case CPUI_BOOL_NEGATE:
		case CPUI_INT_NEGATE:
		case CPUI_INT_2COMP:
			if (iter->input0 && iter->output) {
				ss << ",";
				print_operand (iter->input0);

				if (iter->type == CPUI_BOOL_NEGATE) {
					ss << ",!";
				} else {
					ss << ",1," << iter->output->size * 8 << ",1,<<,-,^";
					ss << ((iter->type == CPUI_INT_2COMP)? ",1,+": "");
				}
				if (iter->output->is_unique()) {
					push_stack(iter->output);
				} else {
					ss << "," << *iter->output << ",=";
				}
			} else {
				throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
			}
			break;
		case CPUI_POPCOUNT:
			if (iter->input0 && iter->output) {
				ss << ",";
				print_operand (iter->input0);
				ss << ",POPCOUNT";
				if (iter->output->is_unique()) {
					push_stack (iter->output);
				} else {
					ss << "," << *iter->output << ",=";
				}
			} else {
				throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
			}
			break;
		case CPUI_FLOAT_INT2FLOAT:
			if (iter->input0 && iter->output) {
				ss << ",";
				print_operand (iter->input0);
				ss << ",I2D";
				if (iter->output->size != 8) {
					ss << "," << iter->output->size << ",SWAP,D2F";
				}
				if (iter->output->is_unique()) {
					push_stack (iter->output);
				} else {
					ss << "," << *iter->output << ",=";
				}
			} else {
				throw LowlevelError("sleigh_esil: arguments of Pcodes are not well inited.");
			}
			break;
		case CPUI_FLOAT_NAN:
		case CPUI_FLOAT_TRUNC:
		case CPUI_FLOAT_CEIL:
		case CPUI_FLOAT_FLOOR:
		case CPUI_FLOAT_ROUND:
		case CPUI_FLOAT_SQRT:
		case CPUI_FLOAT_ABS:
		case CPUI_FLOAT_NEG:
		case CPUI_FLOAT_FLOAT2FLOAT:
			if (!iter->input0 || !iter->output) {
				throw LowlevelError ("sleigh_esil: arguments of Pcodes are not well inited.");
			}
			ss << ",";
			print_operand (iter->input0, 0, true);

			switch (iter->type) {
			case CPUI_FLOAT_NAN: ss << ",NAN"; break;
			case CPUI_FLOAT_TRUNC:
				     ss << ",D2I,1," << iter->output->size * 8 << ",1,<<,-,&";
				     break;
			case CPUI_FLOAT_CEIL: ss << ",CEIL"; break;
			case CPUI_FLOAT_FLOOR: ss << ",FLOOR"; break;
			case CPUI_FLOAT_ROUND: ss << ",ROUND"; break;
			case CPUI_FLOAT_SQRT: ss << ",SQRT"; break;
			case CPUI_FLOAT_ABS: ss << ",0,I2D,F<=,!,?{,-F,}"; break;
			case CPUI_FLOAT_NEG: ss << ",-F"; break;
			case CPUI_FLOAT_FLOAT2FLOAT: /* same as below */ break;
			}
			if (iter->output->size != 8) {
				switch (iter->type) {
				case CPUI_FLOAT_CEIL:
				case CPUI_FLOAT_FLOOR:
				case CPUI_FLOAT_ROUND:
				case CPUI_FLOAT_SQRT:
				case CPUI_FLOAT_ABS:
				case CPUI_FLOAT_NEG:
				case CPUI_FLOAT_FLOAT2FLOAT:
					ss << "," << iter->output->size << ",SWAP,D2F";
					break;
				}
			}
			if (iter->output->is_unique()) {
				push_stack(iter->output);
			} else {
				ss << "," << *iter->output << ",=";
			}
			break;
		}
	}

	// std::cerr << hex << anal_op->addr << " " << ss.str() << endl;
	esilprintf (anal_op, "%s", ss.str()[0] == ','? ss.str().c_str() + 1: ss.str().c_str());
}

#if 0
/* Not in use for now. */
static bool anal_type_NOP(const std::vector<Pcodeop> &Pcodes) {
	// All p-codes have no side affects.
	for (auto iter = Pcodes.cbegin(); iter != Pcodes.cend(); iter++) {
		if (iter->type == CPUI_STORE) {
			return false;
		}
		if (iter->output && !iter->output->is_unique()) {
			return false;
		}
	}
	return true;
}
#endif

extern "C" int sleigh_op(RAnal *a, RAnalOp *anal_op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
	char *arch = slid_arch (a);
	if (!arch) {
		return -1;
	}
	try {
#if R2_VERSION_NUMBER >= 50609
		sanal->init (arch, a->config->bits, a->config->big_endian, a? a->iob.io : nullptr, SleighAsm::getConfig(a));
#else
		sanal->init (arch, a->bits, a->big_endian, a? a->iob.io : nullptr, SleighAsm::getConfig(a));
#endif
		R_FREE (arch);

		AssemblySlg assem(sanal);
		Address at(sanal->trans.getDefaultCodeSpace(), addr);

		if (1) { // mask & R_ANAL_OP_MASK_DISASM) {
			try {
				int size = sanal->trans.printAssembly (assem, at);
				anal_op->size = size;
				anal_op->mnemonic = strdup (assem.str);
				r_str_case (anal_op->mnemonic, false);
			} catch (LowlevelError &err) {
				anal_op->mnemonic = strdup ("error");
			}
		}

		anal_op->addr = addr;
		anal_op->sign = true;
		anal_op->type = R_ANAL_OP_TYPE_ILL;

		PcodeSlg pcode_slg (sanal);
		sanal->check(addr, data, len);
		try {
			anal_op->size = sanal->genOpcode (pcode_slg, at);
		} catch (BadDataError &err) {
			anal_op->mnemonic = strdup ("bad");
		} catch (UnimplError &err) {
			anal_op->mnemonic = strdup ("unimpl");
		} catch (LowlevelError &err) {
			// ignored
		}
		if ((anal_op->size < 1) || (sanal->trans.printAssembly(assem, at) < 1)) {
			return anal_op->size; // When current place has no available code, return ILL.
		}
		if (pcode_slg.pcodes.empty()) { // NOP case
			anal_op->type = R_ANAL_OP_TYPE_NOP;
			esilprintf (anal_op, "%s", "");
			return anal_op->size;
		}

		SleighInstruction *ins = sanal->trans.getInstruction(at);
		if (ins == nullptr) {
			return -1;
		}
		FlowType ftype = ins->getFlowType();
		bool isRefed = false;

		// std::cerr << caddr << " " << ins.printFlowType(ftype) << std::endl;
		if (ftype != FlowType::FALL_THROUGH) {
			switch (ftype) {
			case FlowType::TERMINATOR:
				// Stack info could be added
				anal_op->type = R_ANAL_OP_TYPE_RET;
				anal_op->eob = true;
				break;
			case FlowType::CONDITIONAL_TERMINATOR:
				anal_op->type = R_ANAL_OP_TYPE_CRET;
				anal_op->fail = ins->getFallThrough().getOffset();
				anal_op->eob = true;
				break;
			case FlowType::JUMP_TERMINATOR: anal_op->eob = true;
			case FlowType::UNCONDITIONAL_JUMP:
				anal_op->type = R_ANAL_OP_TYPE_JMP;
				{
					auto flows = ins->getFlows();
					if (flows.size() > 0) {
						anal_op->jump = flows.begin()->getOffset();
					}
					anal_op->fail = UT64_MAX;
				}
				break;
			case FlowType::COMPUTED_JUMP:
			{
				char *reg = getIndirectReg(ins, isRefed);
				if (reg) {
					if (isRefed) {
						anal_op->type = R_ANAL_OP_TYPE_MJMP;
						anal_op->ireg = reg;
					} else {
						anal_op->type = R_ANAL_OP_TYPE_RJMP;
						anal_op->reg = reg;
					}
				} else {
					anal_op->type = R_ANAL_OP_TYPE_IJMP;
				}
				break;
			}
			case FlowType::CONDITIONAL_COMPUTED_JUMP:
			{
				char *reg = getIndirectReg(ins, isRefed);
				if (reg) {
					if (isRefed) {
						anal_op->type = R_ANAL_OP_TYPE_MCJMP;
						anal_op->ireg = reg;
					} else {
						anal_op->type = R_ANAL_OP_TYPE_RCJMP;
						anal_op->reg = reg;
					}
				} else {
					anal_op->type = R_ANAL_OP_TYPE_UCJMP;
				}
				anal_op->fail = ins->getFallThrough().getOffset();
				break;
			}
			case FlowType::CONDITIONAL_JUMP:
				anal_op->type = R_ANAL_OP_TYPE_CJMP;
				anal_op->jump = ins->getFlows().begin()->getOffset();
				anal_op->fail = ins->getFallThrough().getOffset();
				break;
			case FlowType::CALL_TERMINATOR: anal_op->eob = true;
			case FlowType::UNCONDITIONAL_CALL:
				anal_op->type = R_ANAL_OP_TYPE_CALL;
				anal_op->jump = ins->getFlows().begin()->getOffset();
				anal_op->fail = ins->getFallThrough().getOffset();
				break;
			case FlowType::CONDITIONAL_COMPUTED_CALL:
			{
				char *reg = getIndirectReg (ins, isRefed);
				if (reg) {
					if (isRefed) {
						anal_op->ireg = reg;
					} else {
						anal_op->reg = reg;
					}
				}
				anal_op->type = R_ANAL_OP_TYPE_UCCALL;
				anal_op->fail = ins->getFallThrough().getOffset();
				break;
			}
			case FlowType::CONDITIONAL_CALL:
				anal_op->type |= R_ANAL_OP_TYPE_CCALL;
				anal_op->jump = ins->getFlows().begin()->getOffset();
				anal_op->fail = ins->getFallThrough().getOffset();
				break;
			case FlowType::COMPUTED_CALL_TERMINATOR:
				anal_op->eob = true;
				// fallthrough
			case FlowType::COMPUTED_CALL: // for some reason ghidra's computed calls are actually jmps :facepalm:
			{
				char *reg = getIndirectReg (ins, isRefed);
				if (reg) {
					if (isRefed) {
						anal_op->type = R_ANAL_OP_TYPE_RJMP;
						anal_op->eob = true;
						anal_op->ireg = reg;
					} else {
						anal_op->type = R_ANAL_OP_TYPE_IRJMP;
						anal_op->eob = true;
						anal_op->reg = reg;
					}
				} else {
					anal_op->type = R_ANAL_OP_TYPE_ICALL;
				}
				anal_op->fail = ins->getFallThrough ().getOffset();
				break;
			}
			default:
				throw LowlevelError("Unexpected FlowType occured in sleigh_op");
			}
		} else {
			anal_type (a, anal_op, pcode_slg, assem);
#if 0
			switch (anal_op->type) {
			case R_ANAL_OP_TYPE_IRCALL: std::cerr << caddr << ": R_ANAL_OP_TYPE_IRCALL"; break;
			case R_ANAL_OP_TYPE_RET: std::cerr << caddr << ": R_ANAL_OP_TYPE_RET"; break;
			case R_ANAL_OP_TYPE_ABS: std::cerr << caddr << ": R_ANAL_OP_TYPE_ABS"; break;
			case R_ANAL_OP_TYPE_CRET: std::cerr << caddr << ": R_ANAL_OP_TYPE_CRET"; break;
			case R_ANAL_OP_TYPE_IJMP: std::cerr << caddr << ": R_ANAL_OP_TYPE_IJMP"; break;
			case R_ANAL_OP_TYPE_RPUSH: std::cerr << caddr << ": R_ANAL_OP_TYPE_RPUSH"; break;
			case R_ANAL_OP_TYPE_NOP: std::cerr << caddr << ": R_ANAL_OP_TYPE_NOP"; break;
			case R_ANAL_OP_TYPE_SAR: std::cerr << caddr << ": R_ANAL_OP_TYPE_SAR"; break;
			case R_ANAL_OP_TYPE_NOT: std::cerr << caddr << ": R_ANAL_OP_TYPE_NOT"; break;
			case R_ANAL_OP_TYPE_CALL: std::cerr << caddr << ": R_ANAL_OP_TYPE_CALL"; break;
			case R_ANAL_OP_TYPE_UPUSH: std::cerr << caddr << ": R_ANAL_OP_TYPE_UPUSH"; break;
			case R_ANAL_OP_TYPE_LOAD: std::cerr << caddr << ": R_ANAL_OP_TYPE_LOAD"; break;
			case R_ANAL_OP_TYPE_XCHG: std::cerr << caddr << ": R_ANAL_OP_TYPE_XCHG"; break;
			case R_ANAL_OP_TYPE_RCJMP: std::cerr << caddr << ": R_ANAL_OP_TYPE_RCJMP"; break;
			case R_ANAL_OP_TYPE_CAST: std::cerr << caddr << ": R_ANAL_OP_TYPE_CAST"; break;
			case R_ANAL_OP_TYPE_UCJMP: std::cerr << caddr << ": R_ANAL_OP_TYPE_UCJMP"; break;
			case R_ANAL_OP_TYPE_MOV: std::cerr << caddr << ": R_ANAL_OP_TYPE_MOV"; break;
			case R_ANAL_OP_TYPE_OR: std::cerr << caddr << ": R_ANAL_OP_TYPE_OR"; break;
			case R_ANAL_OP_TYPE_SHR: std::cerr << caddr << ": R_ANAL_OP_TYPE_SHR"; break;
			case R_ANAL_OP_TYPE_XOR: std::cerr << caddr << ": R_ANAL_OP_TYPE_XOR"; break;
			case R_ANAL_OP_TYPE_SHL: std::cerr << caddr << ": R_ANAL_OP_TYPE_SHL"; break;
			case R_ANAL_OP_TYPE_JMP: std::cerr << caddr << ": R_ANAL_OP_TYPE_JMP"; break;
			case R_ANAL_OP_TYPE_ILL: std::cerr << caddr << ": R_ANAL_OP_TYPE_ILL"; break;
			case R_ANAL_OP_TYPE_AND: std::cerr << caddr << ": R_ANAL_OP_TYPE_AND"; break;
			case R_ANAL_OP_TYPE_SUB: std::cerr << caddr << ": R_ANAL_OP_TYPE_SUB"; break;
			case R_ANAL_OP_TYPE_DIV: std::cerr << caddr << ": R_ANAL_OP_TYPE_DIV"; break;
			case R_ANAL_OP_TYPE_UNK: std::cerr << caddr << ": R_ANAL_OP_TYPE_UNK"; break;
			case R_ANAL_OP_TYPE_CJMP: std::cerr << caddr << ": R_ANAL_OP_TYPE_CJMP"; break;
			case R_ANAL_OP_TYPE_MCJMP: std::cerr << caddr << ": R_ANAL_OP_TYPE_MCJMP"; break;
			case R_ANAL_OP_TYPE_UCCALL: std::cerr << caddr << ": R_ANAL_OP_TYPE_UCCALL"; break;
			case R_ANAL_OP_TYPE_MJMP: std::cerr << caddr << ": R_ANAL_OP_TYPE_MJMP"; break;
			case R_ANAL_OP_TYPE_NEW: std::cerr << caddr << ": R_ANAL_OP_TYPE_NEW"; break;
			case R_ANAL_OP_TYPE_IRJMP: std::cerr << caddr << ": R_ANAL_OP_TYPE_IRJMP"; break;
			case R_ANAL_OP_TYPE_ADD: std::cerr << caddr << ": R_ANAL_OP_TYPE_ADD"; break;
			case R_ANAL_OP_TYPE_POP: std::cerr << caddr << ": R_ANAL_OP_TYPE_POP"; break;
			case R_ANAL_OP_TYPE_MOD: std::cerr << caddr << ": R_ANAL_OP_TYPE_MOD"; break;
			case R_ANAL_OP_TYPE_STORE: std::cerr << caddr << ": R_ANAL_OP_TYPE_STORE"; break;
			case R_ANAL_OP_TYPE_NOR: std::cerr << caddr << ": R_ANAL_OP_TYPE_NOR"; break;
			case R_ANAL_OP_TYPE_ICALL: std::cerr << caddr << ": R_ANAL_OP_TYPE_ICALL"; break;
			case R_ANAL_OP_TYPE_MUL: std::cerr << caddr << ": R_ANAL_OP_TYPE_MUL"; break;
			}
			if (anal_op->val && anal_op->val != -1) {
				std::cerr << " val: " << anal_op->val << std::endl;
			} else {
#if R2_VERSION_NUMBER >= 50709
#pragma warning("anal srcs/dsts is disabled from now on")
#else
				if (anal_op->dst) {
					std::cerr << " dst: ";
					char *tmp = r_anal_value_to_string (anal_op->dst);
					std::cerr << tmp;
					free (tmp);
				}
				if (anal_op->src[0]) {
					std::cerr << " in0: ";
					char *tmp = r_anal_value_to_string (anal_op->src[0]);
					std::cerr << tmp;
					free (tmp);
				}
				if (anal_op->src[1]) {
					std::cerr << " in1: ";
					char *tmp = r_anal_value_to_string (anal_op->src[1]);
					std::cerr << tmp;
					free (tmp);
				}
#endif
				std::cerr << std::endl;
			}
#endif
		}
		if (mask & R_ARCH_OP_MASK_ESIL) {
			sleigh_esil (a, anal_op, addr, data, len, pcode_slg.pcodes);
		}
		return anal_op->size;
	} catch (const LowlevelError &e) {
		R_FREE (arch);
		return 0;
	}
}

extern "C" bool sleigh_decode(RArchSession *as, RAnalOp *aop, RArchDecodeMask mask) {
	REsil *esil = as->arch->esil;
#if R2_VERSION_NUMBER >= 50909
	RBin *bin = (RBin*)as->arch->binb.bin;
	RIO *io = (RIO*)bin->iob.io;
	RCore *Gcore = (RCore *)io->coreb.core;
#else
	RIO *io = Gcore->io;
	RBin *bin = Gcore->bin;
#endif
	RAnal *anal = Gcore->anal;
	if (bin != nullptr && esil != nullptr) {
		io = bin->iob.io;
		anal = esil->anal;
		// sanal->init (cpu, bi, be, anal? anal->iob.io: nullptr, SleighAsm::getConfig (anal));
	}
	return sleigh_op (anal, aop, aop->addr, aop->bytes, aop->size, (RAnalOpMask)mask) > 0;
}

/*
 * By 2020-05-24, there are 17 kinds of group of registers in SLEIGH.
 * I map them to r_reg.h's RRegisterType:
 * R_REG_TYPE_XMM:
 * R_REG_TYPE_SEG:
 * R_REG_TYPE_DRX: DEBUG
 * R_REG_TYPE_FPU: ST FPU
 * R_REG_TYPE_MMX: MMX
 * R_REG_TYPE_YMM: AVX VSX
 * R_REG_TYPE_FLG: FLAGS Flags
 * R_REG_TYPE_GPR: PC Cx DCR STATUS SVE CONTROL SPR SPR_UNNAMED Alt NEON
 */
static const char *r_reg_type_arr[] = {
	"PC",  "Cx",          "DCR", "STATUS", "SVE",   "CONTROL",
	"SPR", "SPR_UNNAMED", "Alt", "NEON",   "FLAGS", "Flags",
	"AVX", "MMX",         "ST",  "FPU",    "DEBUG", "VSX", nullptr
};

static const char *r_reg_string_arr[] = {
	"gpr", "drx", "drx", "drx", "drx", "drx",
	"drx", "gpr", "gpr", "gpr", "flg", "flg",
	"vec256", "vec64", "fpu", "fpu", "drx", "vec256", nullptr
};

static int get_reg_type(const std::string &name) {
	auto p = sanal->reg_mapping.cbegin();
	for (; p != sanal->reg_mapping.cend() && p->second != name; p++) {
	}
	if (p == sanal->reg_mapping.cend()) {
		throw LowlevelError("get_reg_type: reg doesn't exist.");
	}
	const std::string &group = sanal->reg_group[p->first];

	if (group. empty()) {
		return R_REG_TYPE_GPR;
	}
	for (size_t i = 0; r_reg_type_arr[i]; i++) {
		if (group == r_reg_type_arr[i]) {
			const char *curr = r_reg_string_arr[i];
			switch (curr[0] | curr[1] << 8) {
			case 'g' | 'p' << 8: return R_REG_TYPE_GPR;
			case 'd' | 'r' << 8: return R_REG_TYPE_DRX;
			case 'f' | 'p' << 8: return R_REG_TYPE_FPU;
			case 'v' | 'e' << 8:
				switch (curr[3]) {
				case '6':
					return R_REG_TYPE_VEC64;
				case '1':
					return R_REG_TYPE_VEC128;
				case '2':
					return R_REG_TYPE_VEC256;
				}
				break;
			case 'f' | 'l' << 8: return R_REG_TYPE_FLG;
			case 's' | 'e' << 8: return R_REG_TYPE_SEG;
			}
		}
	}
	return -1;
}

static void append_hardcoded_regs(std::stringstream &buf, const std::string &arch, bool little, int bits) {
	if (arch.size() < 3) {
		throw LowlevelError("append_hardcoded_regs: Unexpected arch name.");
	}

	switch (arch[0] | arch[1] << 8 | arch[2] << 16) {
	case ('A' | 'R' << 8 | 'M' << 16): // ARM
	case ('A' | 'A' << 8 | 'R' << 16): // AARCH64
		if (bits == 64) {
			buf << "=SN\t" << "x16" << "\n" << "=BP\t" << "x29" << "\n";
		} else {
			buf << "=SN\t" << "r7" << "\n" << "=BP\t" << "r11" << "\n";
		}
		break;
	// case ('a' | 'v' << 8 | 'r' << 16): // avr8
	case ('a' | 'v' << 8 | 'r' << 16): // avr32
		buf << "=BP\t" << "y" << "\n";
		break;
	case ('6' | '8' << 8 | '0' << 16): // 68000
		buf << "=BP\t" << "a6" << "\n";
		break;
	case ('R' | 'I' << 8 | 'S' << 16): // RISCV
		buf << "=BP\t" << "s0" << "\n";
		break;
	case ('M' | 'I' << 8 | 'P' << 16): // MIPS
		buf << "=SN\t" << "v0" << "\n" << "=BP\t" << "f30" << "\n";
		break;
	case ('D' | 'a' << 8 | 'l' << 16): // Dalvik
		buf << "=SN\t" << "v0" << "\n" << "=BP\t" << "bp" << "\n";
		break;
	case ('P' | 'o' << 8 | 'w' << 16): // PowerPC
		if (bits == 32)
			buf << "=SN\t" << "r3" << "\n" << "=BP\t" << "r31" << "\n";
		break;
	case ('v' | '8' << 8 | '5' << 16): // V850
			buf << "=SN\t" << "r0" << "\n" << "=BP\t" << "psw" << "\n";
		break;
	case ('x' | '8' << 8 | '6' << 16): // x86
		if (bits == 16) {
			buf << "=SN\t" << "ah" << "\n" << "=BP\t" << "bp" << "\n";
		} else if (bits == 32) {
			buf << "=SN\t" << "eax" << "\n" << "=BP\t" << "ebp" << "\n";
		} else if (bits == 64) {
			buf << "=SN\t" << "rax" << "\n" << "=BP\t" << "rbp" << "\n";
		}
		break;
	case ('s' | 'p' << 8 | 'a' << 16): // sparc
		buf << "=BP\t" << "fp" << "\n";
		break;
	case ('V' | '8' << 8 | '5' << 16): // V850
		buf << "=SN\t" << "r6" << "\n" << "=BP\t" << "sp" << "\n";
		break;
	// case ('6' | '8' << 8 | '0' << 16): // 6809
	// case ('6' | '8' << 8 | '0' << 16): // 6805
	// case ('P' | 'I' << 8 | 'C' << 16): // PIC-24H
	// case ('P' | 'I' << 8 | 'C' << 16): // PIC-24F
	// case ('P' | 'I' << 8 | 'C' << 16): // PIC-24E
	// case ('P' | 'I' << 8 | 'C' << 16): // PIC-18
	// case ('P' | 'I' << 8 | 'C' << 16): // PIC-17
	// case ('P' | 'I' << 8 | 'C' << 16): // PIC-16
	case ('P' | 'I' << 8 | 'C' << 16): // PIC-12
	// case ('d' | 's' << 8 | 'P' << 16): // dsPIC33F
	// case ('d' | 's' << 8 | 'P' << 16): // dsPIC33E
	// case ('d' | 's' << 8 | 'P' << 16): // dsPIC33C
	case ('d' | 's' << 8 | 'P' << 16): // dsPIC30F
	// case ('z' | '1' << 8 | '8' << 16): // z182
	case ('z' | '1' << 8 | '8' << 16): // z180
	// case ('T' | 'I' << 8 | '_' << 16): // TI_MSP430X
	case ('T' | 'I' << 8 | '_' << 16): // TI_MSP430
	case ('p' | 'a' << 8 | '-' << 16): // pa-risc
	case ('8' | '0' << 8 | '8' << 16): // 8085
	// case ('H' | 'C' << 8 | 'S' << 16): // HCS12
	case ('H' | 'C' << 8 | 'S' << 16): // HCS08
	// case ('H' | 'C' << 8 | '0' << 16): // HC08
	case ('H' | 'C' << 8 | '0' << 16): // HC05
	case ('6' | '5' << 8 | '0' << 16): // 6502
	// case ('S' | 'u' << 8 | 'p' << 16): // SuperH
	case ('S' | 'u' << 8 | 'p' << 16): // SuperH4
	case ('T' | 'o' << 8 | 'y' << 16): // Toy
	case ('C' | 'P' << 8 | '1' << 16): // CP1600
	case ('J' | 'V' << 8 | 'M' << 16): // JVM
	case ('t' | 'r' << 8 | 'i' << 16): // tricore
	case ('z' | '8' << 8 | '0' << 16): // z80
	case ('8' | '0' << 8 | '5' << 16): // 8051
	case ('8' | '0' << 8 | '2' << 16): // 80251
	case ('M' | 'o' << 8 | 'd' << 16): // Mode
	case ('C' | 'R' << 8 | '1' << 16): // CR16C
	case ('8' | '0' << 8 | '3' << 16): // 80390
	case ('D' | 'A' << 8 | 'T' << 16): // DATA
	case ('z' | '8' << 8 | '4' << 16): // z8401x
	case ('8' | '0' << 8 | '4' << 16): // 8048
	case ('w' | 'a' << 8 | 's' << 16): // wasm
	case ('M' | 'C' << 8 | 'S' << 16): // MCS96
	case ('M' | 'a' << 8 | 'n' << 16): // Management
	case ('S' | 'T' << 8 | 'M' << 16): // STM8
		break;
	default:
		R_LOG_WARN ("This architecture is not fully supported. Expect things");
		break;
	}
}

static std::string regtype_name(const char *cpu, const std::string &regname) {
	if (r_str_startswith (cpu, "x86")) {
		if (regname.find ("cr") != -1) {
			return "drx";
		}
		if (regname.find ("ia32") != -1) {
			return "drx";
		}
		if (regname.find ("bnd") == 0) {
			return "fpu";
		}
		if (regname.find ("_offset") != -1) {
			return "seg";
		}
		if (regname.find ("tr_addr") != -1) {
			return "drx";
		}
		if (regname.find ("mm") != -1) {
			return "mmx";
		}
	}
	return "gpr";
}

extern "C" char *r2ghidra_regs(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, nullptr);
#if R2_VERSION_NUMBER >= 50909
	RBin *bin = (RBin*)as->arch->binb.bin;
	RIO *io = (RIO*)bin->iob.io;
	RCore *Gcore = (RCore *)io->coreb.core;
#endif
	const char *cpu = r_config_get (Gcore->config, "asm.cpu"); // (as->config != nullptr)? as->config->cpu: "arm";

	if (R_STR_ISEMPTY (cpu)) {
		return nullptr;
	}
	// slid-arch finds and initializes the plugin, needs a better name
	char *sa = slid_arch (Gcore->anal);
	if (!sa) {
		return nullptr;
	}
	free (sa);

	auto reg_list = sanal->getRegs();
	std::stringstream buf;

	for (auto p = reg_list.begin(); p != reg_list.end(); p++) {
		const std::string &group = sanal->reg_group[p->name];
		const std::string &regname = sanal->reg_mapping[p->name];
		const std::string &regtype = regtype_name (cpu, regname);
		if (group.empty()) {
			buf << regtype << "\t" << regname << "\t." << p->size * 8 << "\t"
				    << p->offset << "\t" << "0\n";
				continue;
			}
			for (size_t i = 0;; i++) {
				if (!r_reg_type_arr[i]) {
					R_LOG_WARN ("Unexpected register group(%s) from SLEIGH, abort", group.c_str());
					return nullptr;
				}
				if (group == r_reg_type_arr[i]) {
					buf << r_reg_string_arr[i] << '\t';
					break;
				}
			}
			buf << sanal->reg_mapping[p->name] << "\t." << p->size * 8 << "\t" << p->offset << "\t" << "0\n";
		}
		if (!sanal->pc_name.empty()) {
			buf << "=PC\t" << sanal->reg_mapping[sanal->pc_name] << '\n';
		}
		if (!sanal->sp_name.empty()) {
			buf << "=SP\t" << sanal->reg_mapping[sanal->sp_name] << '\n';
		}
		for (unsigned i = 0; i != sanal->arg_names.size() && i <= 9; i++) {
			buf << "=A" << i << '\t' << sanal->reg_mapping[sanal->arg_names[i]] << '\n';
		}
		for (unsigned i = 0; i != sanal->ret_names.size() && i <= 3; i++) {
			buf << "=R" << i << '\t' << sanal->reg_mapping[sanal->ret_names[i]] << '\n';
		}

	ut64 pp = 0;
	string arch = sanal->sleigh_id.substr(pp, sanal->sleigh_id.find (':', pp) - pp);
	pp = sanal->sleigh_id.find (':', pp) + 1;
	bool little = sanal->sleigh_id.substr(pp, sanal->sleigh_id.find (':', pp) - pp) == "LE";
	pp = sanal->sleigh_id.find (':', pp) + 1;
	int bits = std::stoi (sanal->sleigh_id.substr(pp, sanal->sleigh_id.find (':', pp) - pp));
	pp = sanal->sleigh_id.find (':', pp) + 1;

	append_hardcoded_regs (buf, arch, little, bits);

	const std::string &res = buf.str ();
	// fprintf(stderr, "%s\n", res.c_str());
	return strdup (res.c_str ());
}

static constexpr int ESIL_PARM_FLOAT = 127; // Avoid conflict

static bool esil_pushnum_float(REsil *esil, long double num) {
	char str[64];
	snprintf (str, sizeof (str) - 1, "%.*LeF", DECIMAL_DIG, num);
	return r_esil_push (esil, str);
}

static bool sleigh_esil_consts_pick(REsil *esil) {
	if (!esil || !esil->stack) {
		return false;
	}
	char *idx = r_esil_pop (esil);
	ut64 i;
	int ret = false;

	if (R_ESIL_PARM_REG == r_esil_get_parm_type(esil, idx)) {
		R_LOG_DEBUG ("sleigh_esil_consts_pick: argument is consts only");
		goto end;
	}
	if (!idx || !r_esil_get_parm(esil, idx, &i)) {
		R_LOG_DEBUG ("esil_pick: invalid index number");
		goto end;
	}
	if (esil->stackptr < i) {
		R_LOG_DEBUG ("esil_pick: index out of stack bounds.");
		goto end;
	}
	if (!esil->stack[esil->stackptr - i]) {
		R_LOG_DEBUG ("esil_pick: undefined element.");
		goto end;
	}
	if (!r_esil_push (esil, esil->stack[esil->stackptr - i])) {
		R_LOG_DEBUG ("ESIL stack is full.");
		esil->trap = 1;
		esil->trap_code = 1;
		goto end;
	}
	ret = true;
end:
	free (idx);
	return ret;
}

static bool sleigh_esil_popcount(REsil *esil) {
	bool ret = false;
	ut64 s, res = 0;
	char *src = r_esil_pop (esil);
	if (src) {
		if (r_esil_get_parm (esil, src, &s)) {
			while (s) {
				s &= s - 1;
				++res;
			}
			ret = r_esil_pushnum (esil, res);
		} else {
			R_LOG_DEBUG ("sleigh_esil_popcount: invalid parameters.");
		}
		free (src);
	} else {
		R_LOG_DEBUG ("sleigh_esil_popcount: fail to get element from stack.");
	}
	return ret;
}


extern "C" int esil_sleigh_init(REsil *esil) {
	if (!esil) {
		return false;
	}
#if R2_VERSION_NUMBER >= 50909
	r_esil_set_op (esil, "PICK", sleigh_esil_consts_pick, 1, 0, R_ESIL_OP_TYPE_CUSTOM, "");
	r_esil_set_op (esil, "POPCOUNT", sleigh_esil_popcount, 1, 2, R_ESIL_OP_TYPE_CUSTOM, "");
#else
	// Only consts-only version PICK will meet my demand
	r_esil_set_op (esil, "PICK", sleigh_esil_consts_pick, 1, 0, R_ESIL_OP_TYPE_CUSTOM);
	r_esil_set_op (esil, "POPCOUNT", sleigh_esil_popcount, 1, 2, R_ESIL_OP_TYPE_CUSTOM);
#endif
	return true;
}

extern "C" bool sanal_init(void *p) {
	if (sanal == nullptr) {
		sanal = new SleighAsm ();
	}
	return true;
}

extern "C" int esil_sleigh_fini(REsil *esil) {
	// float_mem.clear();
	return true;
}

extern "C" bool r2ghidra_esilcb(RArchSession *as, RArchEsilAction action) {
	REsil *esil = as->arch->esil;
	if (!esil) {
		R_LOG_ERROR ("esil is null");
		return false;
	}
	switch (action) {
	case R_ARCH_ESIL_ACTION_INIT:
		return esil_sleigh_init (esil);
	case R_ARCH_ESIL_ACTION_FINI:
		return esil_sleigh_fini (esil);
	default:
		R_LOG_WARN ("Unhandled ArchEsil action");
		break;
	}
	return false;
}

extern "C" bool sanal_fini(void *p) {
	if (sanal) {
		delete sanal;
		sanal = nullptr;
	}
	return true;
}

extern "C" RList *r2ghidra_preludes(RArchSession *as) {
	RListIter *iter;
	void *_plugin;
	const char *cpu = as->config->cpu;
	// reuse r2 preludes
	if (R_STR_ISNOTEMPTY (cpu)) {
		r_list_foreach (as->arch->plugins, iter, _plugin) {
			RArchPlugin *plugin = (RArchPlugin*)_plugin;
			if (plugin->preludes && plugin->meta.name && !strcmp (plugin->meta.name, cpu)) {
				return plugin->preludes (as);
			}
		}
	}
	return NULL;
}
