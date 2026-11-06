// SPDX-FileCopyrightText: 2020-2026 pancake, FXTi
// SPDX-License-Identifier: LGPL-3.0-only

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
	const char *cp = anal->config->cpu;
	int bi = anal->config->bits;
	bool be = anal->config->big_endian;
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

extern "C" int archinfo(RArchSession *as, ut32 query) {
	R_RETURN_VAL_IF_FAIL (as, 1);
	RBin *bin = (RBin*)as->arch->binb.bin;
	RIO *io = (RIO*)bin->iob.io;
	RCore *Gcore = (RCore *)io->coreb.core;
	char *arch = slid_arch (Gcore->anal); // is this initializing sanal global ptr?
	int ret = 1;
	if (sanal != nullptr) {
		switch (query) {
		case R_ARCH_INFO_MAXOP_SIZE:
			ret = sanal->maxopsz;
			break;
		case R_ARCH_INFO_MINOP_SIZE:
			ret = sanal->minopsz;
			break;
		case R_ARCH_INFO_CODE_ALIGN:
		case R_ARCH_INFO_DATA_ALIGN:
			ret = sanal->alignment;
			break;
		}
	}
	R_FREE (arch);
	return ret;
}

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
			if ((out.reg && sanal->reg_mapping[sanal->sp_name] == out.reg) ||
			   (out.regdelta && sanal->reg_mapping[sanal->sp_name] == out.regdelta))
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
			if (in0.reg && !strcmp ("lp", in0.reg))
			{
				anal_op->type = R_ANAL_OP_TYPE_RET;
				return this_type;
			}

			if ((in0.reg && std::string("lr") == in0.reg) || (in0.regdelta && sanal->reg_mapping[sanal->sp_name] == in0.regdelta))
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
	sanal->trans->getAllRegisters(reglist);
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

// Translate P-code into r2 ESIL using only the operations r2 implements.
// ESIL is reverse polish with the left operand on top of the stack, so "b,a,-"
// computes a - b and "bits,value,~" sign extends value. P-code temporaries are
// inlined as expressions and all the writes are deferred to the end, so every
// value is computed from the state before the instruction, then the registers,
// memory and pc are written in program order. A conditional branch skips the
// pcodes after it, those are guarded by the negated condition until the paths
// merge again at the target of a forward branch inside the instruction.
class SleighEsil {
public:
	explicit SleighEsil(int bits): bits(bits) {}
	std::string translate(const std::vector<Pcodeop> &pcodes);

private:
	struct Unsupported {};
	struct Write {
		enum { REG, MEM, PC } kind;
		const PcodeOperand *reg; // REG
		std::string value;
		std::string addr; // MEM
		uint4 size; // MEM
		std::string guard; // MEM and PC, empty when unconditional
	};
	int bits;
	std::map<uintb, std::string> uniques;
	std::vector<Write> writes;
	// condition to execute the current pcode, empty when unconditional
	std::string guard;
	// no path reaches the current pcode
	bool dead = false;
	// guards of the forward branches to each pcode index
	std::map<size_t, std::vector<std::string>> labels;
	size_t index = 0;
	size_t count = 0;

	static std::string num(uintb n) {
		return std::to_string (n);
	}
	static std::string binop(const std::string &a, const std::string &b, const char *op) {
		return b + "," + a + "," + op;
	}
	static std::string unop(const std::string &a, const char *op) {
		return a + "," + op;
	}
	static std::string hex(uintb n) {
		std::stringstream ss;
		ss << "0x" << std::hex << n;
		return ss.str ();
	}
	static std::string mask(const std::string &v, uint4 size) {
		return size >= 8? v: binop (v, hex ((1ULL << (size * 8)) - 1), "&");
	}
	static std::string sext(const std::string &v, uint4 size) {
		return size >= 8? v: num (size * 8) + "," + v + ",~";
	}
	// r2 compares at the size of register operands, compare 64 bit numbers instead
	// and flip the sign bits for the unsigned 64 bit comparisons
	static std::string ucmp(const std::string &a, const std::string &b, uint4 size, const char *op) {
		if (size < 8) {
			return binop (snapshot (a), snapshot (b), op);
		}
		const char *sign = "0x8000000000000000";
		return binop (binop (a, sign, "^"), binop (b, sign, "^"), op);
	}
	static std::string scmp(const std::string &a, const std::string &b, uint4 size, const char *op) {
		return binop (snapshot (sext (a, size)), snapshot (sext (b, size)), op);
	}
	static std::string to_double(const std::string &v, uint4 size) {
		return size == 8? v: num (size * 8) + "," + v + ",F2D";
	}
	// a when the 0 or 1 condition g is set, b otherwise
	static std::string select(const std::string &g, const std::string &a, const std::string &b) {
		const std::string all = binop ("0", g, "-");
		return binop (binop (binop (a, b, "^"), all, "&"), b, "^");
	}
	static std::string both(const std::string &g, const std::string &c) {
		return g.empty ()? c: binop (g, c, "&");
	}
	static std::string either(const std::string &g, const std::string &c) {
		return g.empty () || c.empty ()? "": binop (g, c, "|");
	}
	static std::string from_double(const std::string &v, uint4 size) {
		return size == 8? v: num (size * 8) + "," + v + ",D2F";
	}
	// division by zero gives 0 without raising the esil trap
	static std::string divide(const std::string &a, const std::string &b, const char *op) {
		const std::string nonzero = binop (b, unop (b, "!"), "|");
		return binop (binop (a, nonzero, op), unop (unop (b, "!"), "!"), "*");
	}
	// a bare register is read when it is consumed, and its size changes how
	// r2 compares it, take its value as a number
	static std::string snapshot(const std::string &v) {
		if (v.find (',') == std::string::npos && !isdigit ((unsigned char)v[0])) {
			return v + ",NUM";
		}
		return v;
	}
	static void check_size(const PcodeOperand *arg) {
		if (arg->size > 8) {
			throw Unsupported ();
		}
	}
	static bool overlaps(const PcodeOperand *a, const PcodeOperand *b) {
		return a->reg_offset < b->reg_offset + b->size && b->reg_offset < a->reg_offset + a->size;
	}
	static bool contains(const PcodeOperand *outer, const PcodeOperand *inner) {
		return outer->reg_offset <= inner->reg_offset &&
			inner->reg_offset + inner->size <= outer->reg_offset + outer->size;
	}

	std::string read(const PcodeOperand *arg);
	std::string read_reg(const PcodeOperand *arg);
	static void check_mem_size(uint4 size);
	std::string load(const std::string &addr, uint4 size);
	std::string address(const PcodeOperand *space, const PcodeOperand *offset);
	std::string asr(const std::string &a, const std::string &b, uint4 size);
	void write(const PcodeOperand *out, const std::string &value);
	void write_mem(const std::string &addr, const std::string &value, uint4 size);
	void write_pc(const std::string &target, const std::string &cond);
	void jump(const PcodeOperand *offset, const std::string &cond);
	void translate_op(const Pcodeop &op);
};

std::string SleighEsil::read(const PcodeOperand *arg) {
	switch (arg->type) {
	case PcodeOperand::CONSTANT:
		return num (arg->number);
	case PcodeOperand::UNIQUE: {
		check_size (arg);
		auto it = uniques.find (arg->offset);
		if (it == uniques.end ()) {
			throw Unsupported ();
		}
		return it->second;
	}
	case PcodeOperand::RAM:
		return load (num (arg->offset), arg->size);
	case PcodeOperand::REGISTER:
		return read_reg (arg);
	}
	throw Unsupported ();
}

std::string SleighEsil::read_reg(const PcodeOperand *arg) {
	check_size (arg);
	if (arg->name.empty ()) {
		throw Unsupported ();
	}
	for (auto w = writes.crbegin (); w != writes.crend (); w++) {
		if (w->kind != Write::REG || !overlaps (w->reg, arg)) {
			continue;
		}
		if (!contains (w->reg, arg)) {
			throw Unsupported ();
		}
		const PcodeOperand *reg = w->reg;
		const uintb shift = reg->reg_big_endian
			? (reg->reg_offset + reg->size) - (arg->reg_offset + arg->size)
			: arg->reg_offset - reg->reg_offset;
		const std::string value = shift? binop (w->value, num (shift * 8), ">>"): w->value;
		return arg->size < reg->size? mask (value, arg->size): value;
	}
	return arg->name;
}

void SleighEsil::check_mem_size(uint4 size) {
	switch (size) {
	case 1: case 2: case 3: case 4: case 8:
		return;
	}
	throw Unsupported ();
}

// a load after a store in the same instruction reads the stored value
std::string SleighEsil::load(const std::string &addr, uint4 size) {
	check_mem_size (size);
	for (auto w = writes.crbegin (); w != writes.crend (); w++) {
		if (w->kind != Write::MEM) {
			continue;
		}
		if (w->addr != addr || w->size != size) {
			// the addresses may alias
			throw Unsupported ();
		}
		if (w->guard.empty ()) {
			return w->value;
		}
		return select (w->guard, w->value, addr + ",[" + num (size) + "]");
	}
	return addr + ",[" + num (size) + "]";
}

std::string SleighEsil::address(const PcodeOperand *space, const PcodeOperand *offset) {
	std::string addr = read (offset);
	if (space->is_const ()) {
		const int4 wordsize = ((AddrSpace *)space->offset)->getWordSize ();
		if (wordsize != 1) {
			addr = binop (addr, num (wordsize), "*");
		}
	}
	return addr;
}

// r2 narrows ASR to 32 bits when asm.bits is 32, wider values shift by hand
std::string SleighEsil::asr(const std::string &a, const std::string &b, uint4 size) {
	const std::string value = sext (a, size);
	if (bits != 32 || size <= 4) {
		return binop (value, b, "ASR");
	}
	const std::string fill = binop ("0", binop (value, "63", ">>"), "-");
	return binop (binop (value, b, ">>"), binop (fill, binop ("64", b, "-"), "<<"), "|");
}

void SleighEsil::write(const PcodeOperand *out, const std::string &value) {
	switch (out->type) {
	case PcodeOperand::UNIQUE: {
		auto it = uniques.find (out->offset);
		uniques[out->offset] = guard.empty () || it == uniques.end ()? value: select (guard, value, it->second);
		return;
	}
	case PcodeOperand::REGISTER: {
		check_size (out);
		if (out->name.empty ()) {
			throw Unsupported ();
		}
		const std::string reg_value = guard.empty ()? value: select (guard, value, read_reg (out));
		// earlier writes to the same bits are dead, reads already inlined their values
		writes.erase (std::remove_if (writes.begin (), writes.end (), [out](const Write &w) {
			return w.kind == Write::REG && contains (out, w.reg);
		}), writes.end ());
		writes.push_back ({Write::REG, out, reg_value, "", 0, ""});
		return;
	}
	case PcodeOperand::RAM:
		write_mem (num (out->offset), value, out->size);
		return;
	default:
		throw Unsupported ();
	}
}

void SleighEsil::write_mem(const std::string &addr, const std::string &value, uint4 size) {
	check_mem_size (size);
	writes.push_back ({Write::MEM, nullptr, value, addr, size, guard});
}

// the pcodes after a branch only run when it is not taken
void SleighEsil::write_pc(const std::string &target, const std::string &cond) {
	writes.push_back ({Write::PC, nullptr, target, "", 0, both (guard, cond)});
	if (cond.empty ()) {
		dead = true;
	} else {
		guard = both (guard, unop (cond, "!"));
	}
}

// a constant target is a relative jump between the pcodes of the instruction
void SleighEsil::jump(const PcodeOperand *offset, const std::string &cond) {
	const int shift = offset->size > 0 && offset->size < 8? 64 - offset->size * 8: 0;
	const intb delta = (intb)(offset->number << shift) >> shift;
	if (delta <= 0 || index + delta > count) {
		// loops can not be expressed
		throw Unsupported ();
	}
	labels[index + delta].push_back (both (guard, cond));
	if (cond.empty ()) {
		dead = true;
	} else {
		guard = both (guard, unop (cond, "!"));
	}
}

void SleighEsil::translate_op(const Pcodeop &op) {
	const PcodeOperand *in0 = op.input0;
	const PcodeOperand *in1 = op.input1;
	const PcodeOperand *out = op.output;
	const bool unary = in0 && out;
	const bool binary = unary && in1;
	switch (op.type) {
	case CPUI_COPY:
	case CPUI_INT_ZEXT:
		if (!unary) break;
		write (out, read (in0));
		return;
	case CPUI_INT_SEXT:
		if (!unary) break;
		write (out, mask (sext (read (in0), in0->size), out->size));
		return;
	case CPUI_LOAD:
		if (!binary) break;
		write (out, load (address (in0, in1), out->size));
		return;
	case CPUI_STORE: {
		// the stored value is kept in the output field
		if (!binary) break;
		write_mem (address (in0, in1), read (out), out->size);
		return;
	}
	case CPUI_BRANCH:
	case CPUI_CALL:
		if (!in0) break;
		if (in0->is_const ()) {
			jump (in0, "");
			return;
		}
		write_pc (in0->is_ram ()? num (in0->offset): read (in0), "");
		return;
	case CPUI_BRANCHIND:
	case CPUI_CALLIND:
	case CPUI_RETURN:
		if (!in0) break;
		write_pc (read (in0), "");
		return;
	case CPUI_CBRANCH: {
		if (!in0 || !in1) break;
		const std::string cond = unop (unop (read (in1), "!"), "!");
		if (in0->is_const ()) {
			jump (in0, cond);
		} else {
			write_pc (in0->is_ram ()? num (in0->offset): read (in0), cond);
		}
		return;
	}
	case CPUI_PIECE:
		if (!binary) break;
		write (out, binop (binop (read (in0), num (in1->size * 8), "<<"), read (in1), "|"));
		return;
	case CPUI_SUBPIECE: {
		if (!binary || !in1->is_const ()) break;
		std::string value = read (in0);
		if (in1->number) {
			value = binop (value, num (in1->number * 8), ">>");
		}
		write (out, mask (value, out->size));
		return;
	}
	case CPUI_INT_ADD:
	case CPUI_INT_SUB:
	case CPUI_INT_MULT:
	case CPUI_INT_XOR:
	case CPUI_INT_AND:
	case CPUI_INT_OR:
	case CPUI_INT_LEFT:
	case CPUI_INT_RIGHT:
	case CPUI_BOOL_XOR:
	case CPUI_BOOL_AND:
	case CPUI_BOOL_OR: {
		if (!binary) break;
		const char *esil_op = nullptr;
		switch (op.type) {
		case CPUI_INT_ADD: esil_op = "+"; break;
		case CPUI_INT_SUB: esil_op = "-"; break;
		case CPUI_INT_MULT: esil_op = "*"; break;
		case CPUI_INT_XOR: case CPUI_BOOL_XOR: esil_op = "^"; break;
		case CPUI_INT_AND: case CPUI_BOOL_AND: esil_op = "&"; break;
		case CPUI_INT_OR: case CPUI_BOOL_OR: esil_op = "|"; break;
		case CPUI_INT_LEFT: esil_op = "<<"; break;
		default: esil_op = ">>"; break;
		}
		write (out, mask (binop (read (in0), read (in1), esil_op), out->size));
		return;
	}
	case CPUI_INT_SRIGHT:
		if (!binary) break;
		write (out, mask (asr (read (in0), read (in1), in0->size), out->size));
		return;
	case CPUI_INT_DIV:
	case CPUI_INT_REM:
		if (!binary) break;
		write (out, mask (divide (read (in0), read (in1), op.type == CPUI_INT_DIV? "/": "%"), out->size));
		return;
	case CPUI_INT_SDIV:
	case CPUI_INT_SREM:
		if (!binary) break;
		write (out, mask (divide (sext (read (in0), in0->size), sext (read (in1), in1->size),
			op.type == CPUI_INT_SDIV? "~/": "~%"), out->size));
		return;
	case CPUI_INT_EQUAL:
		if (!binary) break;
		write (out, unop (binop (read (in0), read (in1), "-"), "!"));
		return;
	case CPUI_INT_NOTEQUAL:
		if (!binary) break;
		write (out, unop (unop (binop (read (in0), read (in1), "-"), "!"), "!"));
		return;
	case CPUI_INT_LESS:
		if (!binary) break;
		write (out, ucmp (read (in0), read (in1), in0->size, "<"));
		return;
	case CPUI_INT_LESSEQUAL:
		if (!binary) break;
		write (out, ucmp (read (in0), read (in1), in0->size, "<="));
		return;
	case CPUI_INT_SLESS:
		if (!binary) break;
		write (out, scmp (read (in0), read (in1), in0->size, "<"));
		return;
	case CPUI_INT_SLESSEQUAL:
		if (!binary) break;
		write (out, scmp (read (in0), read (in1), in0->size, "<="));
		return;
	case CPUI_INT_CARRY: {
		if (!binary) break;
		const std::string a = read (in0);
		write (out, ucmp (mask (binop (a, read (in1), "+"), in0->size), a, in0->size, "<"));
		return;
	}
	case CPUI_INT_SCARRY:
	case CPUI_INT_SBORROW: {
		// signed overflow when the sign of the result is not the expected one
		if (!binary) break;
		const std::string a = read (in0);
		const std::string b = read (in1);
		const bool add = op.type == CPUI_INT_SCARRY;
		const std::string res = mask (binop (a, b, add? "+": "-"), in0->size);
		const std::string overflow = add
			? binop (binop (a, res, "^"), binop (b, res, "^"), "&")
			: binop (binop (a, b, "^"), binop (a, res, "^"), "&");
		write (out, binop (binop (overflow, num (in0->size * 8 - 1), ">>"), "1", "&"));
		return;
	}
	case CPUI_INT_NEGATE:
		if (!unary) break;
		write (out, binop (read (in0), out->size >= 8? "0xffffffffffffffff": num ((1ULL << (out->size * 8)) - 1), "^"));
		return;
	case CPUI_INT_2COMP:
		if (!unary) break;
		write (out, mask (binop ("0", read (in0), "-"), out->size));
		return;
	case CPUI_BOOL_NEGATE:
		if (!unary) break;
		write (out, unop (read (in0), "!"));
		return;
	case CPUI_POPCOUNT:
		if (!unary) break;
		write (out, unop (read (in0), "POPCNT"));
		return;
	case CPUI_LZCOUNT:
		if (!unary) break;
		write (out, num (in0->size * 8) + "," + read (in0) + ",CLZ");
		return;
	case CPUI_FLOAT_EQUAL:
	case CPUI_FLOAT_NOTEQUAL:
	case CPUI_FLOAT_LESS:
	case CPUI_FLOAT_LESSEQUAL:
	case CPUI_FLOAT_ADD:
	case CPUI_FLOAT_SUB:
	case CPUI_FLOAT_MULT:
	case CPUI_FLOAT_DIV: {
		if (!binary) break;
		const char *esil_op = nullptr;
		bool compare = true;
		switch (op.type) {
		case CPUI_FLOAT_EQUAL: esil_op = "F=="; break;
		case CPUI_FLOAT_NOTEQUAL: esil_op = "F!="; break;
		case CPUI_FLOAT_LESS: esil_op = "F<"; break;
		case CPUI_FLOAT_LESSEQUAL: esil_op = "F<="; break;
		case CPUI_FLOAT_ADD: esil_op = "F+"; compare = false; break;
		case CPUI_FLOAT_SUB: esil_op = "F-"; compare = false; break;
		case CPUI_FLOAT_MULT: esil_op = "F*"; compare = false; break;
		default: esil_op = "F/"; compare = false; break;
		}
		const std::string res = binop (to_double (read (in0), in0->size), to_double (read (in1), in1->size), esil_op);
		write (out, compare? res: from_double (res, out->size));
		return;
	}
	case CPUI_FLOAT_INT2FLOAT:
		if (!unary) break;
		write (out, from_double (unop (sext (read (in0), in0->size), "I2D"), out->size));
		return;
	case CPUI_FLOAT_FLOAT2FLOAT:
		if (!unary) break;
		write (out, from_double (to_double (read (in0), in0->size), out->size));
		return;
	case CPUI_FLOAT_TRUNC:
		if (!unary) break;
		write (out, mask (unop (to_double (read (in0), in0->size), "D2I"), out->size));
		return;
	case CPUI_FLOAT_NAN:
		if (!unary) break;
		write (out, unop (to_double (read (in0), in0->size), "NAN"));
		return;
	case CPUI_FLOAT_ABS:
		if (!unary) break;
		write (out, from_double (binop (to_double (read (in0), in0->size), "0x7fffffffffffffff", "&"), out->size));
		return;
	case CPUI_FLOAT_NEG:
	case CPUI_FLOAT_CEIL:
	case CPUI_FLOAT_FLOOR:
	case CPUI_FLOAT_ROUND:
	case CPUI_FLOAT_SQRT: {
		if (!unary) break;
		const char *esil_op = nullptr;
		switch (op.type) {
		case CPUI_FLOAT_NEG: esil_op = "-F"; break;
		case CPUI_FLOAT_CEIL: esil_op = "CEIL"; break;
		case CPUI_FLOAT_FLOOR: esil_op = "FLOOR"; break;
		case CPUI_FLOAT_ROUND: esil_op = "ROUND"; break;
		default: esil_op = "SQRT"; break;
		}
		write (out, from_double (unop (to_double (read (in0), in0->size), esil_op), out->size));
		return;
	}
	default:
		// CALLOTHER, CPOOLREF, NEW, SEGMENTOP, INSERT, EXTRACT and the non raw pcodes
		break;
	}
	throw Unsupported ();
}

std::string SleighEsil::translate(const std::vector<Pcodeop> &pcodes) {
	try {
		count = pcodes.size ();
		for (index = 0; index < count; index++) {
			auto label = labels.find (index);
			if (label != labels.end ()) {
				// the paths merge, run when any of them reaches here
				std::string merged = dead? label->second.front (): guard;
				for (const auto &g : label->second) {
					merged = either (merged, g);
				}
				guard = merged;
				dead = false;
				labels.erase (label);
			}
			if (!dead) {
				translate_op (pcodes[index]);
			}
		}
	} catch (const Unsupported &) {
		return "";
	}
	// push the values of the last write first, so the writes pop them in program order
	std::vector<std::string> words;
	for (auto w = writes.crbegin (); w != writes.crend (); w++) {
		words.push_back (snapshot (w->value));
		if (w->kind == Write::MEM) {
			words.push_back (snapshot (w->addr));
		}
		if (!w->guard.empty ()) {
			words.push_back (w->guard);
		}
	}
	const std::string &pc = sanal->reg_mapping[sanal->pc_name];
	for (const auto &w : writes) {
		std::string word;
		switch (w.kind) {
		case Write::REG: word = w.reg->name + ",="; break;
		case Write::MEM: word = "=[" + num (w.size) + "]"; break;
		case Write::PC: word = pc + ",="; break;
		}
		if (!w.guard.empty ()) {
			// drop the values when the condition is not met
			word = "?{," + word + ",}{,POP" + (w.kind == Write::MEM? ",POP": "") + ",}";
		}
		words.push_back (word);
	}
	std::string esil;
	for (const auto &word : words) {
		if (!esil.empty ()) {
			esil += ",";
		}
		esil += word;
	}
	return esil;
}

static void sleigh_esil(RAnal *a, RAnalOp *anal_op, ut64 addr, const ut8 *data, int len, const std::vector<Pcodeop> &Pcodes) {
	SleighEsil translator (a->config->bits);
	esilprintf (anal_op, "%s", translator.translate (Pcodes).c_str ());
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
		sanal->init (arch, a->config->bits, a->config->big_endian, a? a->iob.io : nullptr, SleighAsm::getConfig(a));
		R_FREE (arch);

		AssemblySlg assem(sanal);
		Address at(sanal->trans->getDefaultCodeSpace(), addr);

		if (1) { // mask & R_ANAL_OP_MASK_DISASM) {
			try {
				int size = sanal->trans->printAssembly (assem, at);
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
		if ((anal_op->size < 1) || (sanal->trans->printAssembly(assem, at) < 1)) {
			return anal_op->size; // When current place has no available code, return ILL.
		}
		if (pcode_slg.pcodes.empty()) { // NOP case
			anal_op->type = R_ANAL_OP_TYPE_NOP;
			esilprintf (anal_op, "%s", "");
			return anal_op->size;
		}

		SleighInstruction *ins = sanal->trans->getInstruction(at);
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
				{
					auto flows = ins->getFlows();
					if (!flows.empty()) {
						anal_op->jump = flows.begin()->getOffset();
					}
				}
				anal_op->fail = ins->getFallThrough().getOffset();
				break;
			case FlowType::CALL_TERMINATOR: anal_op->eob = true;
			case FlowType::UNCONDITIONAL_CALL:
				anal_op->type = R_ANAL_OP_TYPE_CALL;
				{
					auto flows = ins->getFlows();
					if (!flows.empty()) {
						anal_op->jump = flows.begin()->getOffset();
					}
				}
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
				{
					auto flows = ins->getFlows();
					if (!flows.empty()) {
						anal_op->jump = flows.begin()->getOffset();
					}
				}
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
	RBin *bin = (RBin*)as->arch->binb.bin;
	RIO *io = (RIO*)bin->iob.io;
	RCore *Gcore = (RCore *)io->coreb.core;
	RAnal *anal = Gcore->anal;
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

static const char *regtype_name(const char *cpu, const std::string &regname, ut64 bits) {
	if (!r_str_ncasecmp (cpu, "x86", 3)) {
		if (regname.find ("cr") != std::string::npos) {
			return "drx";
		}
		if (regname.find ("ia32") != std::string::npos) {
			return "drx";
		}
		if (regname.find ("bnd") == 0) {
			return "fpu";
		}
		if (regname.find ("_offset") != std::string::npos) {
			return "seg";
		}
		if (regname.find ("tr_addr") != std::string::npos) {
			return "drx";
		}
		if (regname.find ("mm") != std::string::npos) {
			// r2 has no "mmx" type, and the narrower views must share one arena to alias
			switch (bits) {
			case 512: return "vec512";
			case 256: return "vec256@vec512";
			case 128: return "vec128@vec512";
			default: return "vec64@vec512";
			}
		}
	}
	return "gpr";
}

extern "C" char *r2ghidra_regs(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, nullptr);
	RBin *bin = (RBin*)as->arch->binb.bin;
	RIO *io = (RIO*)bin->iob.io;
	RCore *Gcore = (RCore *)io->coreb.core;
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
		const ut64 bits = p->size * 8;
		if (group.empty()) {
			buf << regtype_name (cpu, regname, bits) << '\t';
		} else {
			size_t i;
			for (i = 0; r_reg_type_arr[i]; i++) {
				if (group == r_reg_type_arr[i]) {
					buf << r_reg_string_arr[i] << '\t';
					break;
				}
			}
			if (!r_reg_type_arr[i]) {
				R_LOG_WARN ("Unexpected register group(%s) from SLEIGH, abort", group.c_str());
				return nullptr;
			}
		}
		buf << regname << "\t." << bits << "\t" << p->offset << "\t" << "0\n";
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

extern "C" int esil_sleigh_init(REsil *esil) {
	if (!esil) {
		return false;
	}
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

#if R2_ABIVERSION >= 109
extern "C" bool r2ghidra_esilcb(RArchSession *as, REsil *esil, RArchEsilAction action) {
#else
extern "C" bool r2ghidra_esilcb(RArchSession *as, RArchEsilAction action) {
	REsil *esil = as->arch->esil;
#endif
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
#if R2_ABIVERSION >= 84
		r_list_foreach (as->arch->libstore->plugins, iter, _plugin) {
#else
		r_list_foreach (as->arch->plugins, iter, _plugin) {
#endif
			RArchPlugin *plugin = (RArchPlugin*)_plugin;
			if (plugin->preludes && plugin->meta.name && !r_str_casecmp (plugin->meta.name, cpu)) {
				return plugin->preludes (as);
			}
		}
	}
	return NULL;
}
