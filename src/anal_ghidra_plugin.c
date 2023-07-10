/* r2ghidra - LGPL - Copyright 2020-2023 - pancake */

#include <r_lib.h>
#include <r_anal.h>
#include <r_arch.h>

#if R2_VERSION_NUMBER >= 50709
#define RAnalEsil REsil
#endif

extern bool sanal_init(void *p);
extern bool sanal_fini(void *p);
extern RList *anal_preludes(RAnal *anal);

#if R2_VERSION_NUMBER >= 50809
extern int archinfo(RArchSession *as, ut32 query);
extern RList *r2ghidra_preludes(RArchSession *as);
extern char *r2ghidra_regs(RArchSession *as);
extern bool r2ghidra_esilcb(RArchSession *as, RArchEsilAction action);
// extern bool sleigh_decode(RArchSession *as, RAnal *a, RAnalOp *anal_op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask);
extern char *get_reg_profile(RAnal *anal);
static bool sleigh_decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask);

RArchPlugin r_arch_plugin_ghidra = {
	.meta = {
		.name = "r2ghidra",
		.desc = "SLEIGH Disassembler from Ghidra",
		.license = "GPL3",
		.author = "FXTi, pancake",
		.version = R2_VERSION,
	},
	.arch = "sleigh",
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.cpus = "6502,6805,8051,arm,avr,cr16,dalvik,hppa,java,m68k,m8c,mips,mcs96,msp430,pic24,ppc,sh,sparc,stm8,tricore,toy,v850,wasm,x86,z80",
	.bits = 0,
	.init = &sanal_init,
	.fini = &sanal_fini,
	.info = &archinfo,
	.preludes = r2ghidra_preludes,
	.decode = &sleigh_decode,
	.regs = &r2ghidra_regs,
	.esilcb = r2ghidra_esilcb,
	.mnemonics = NULL,
};
#else

extern int archinfo(RAnal *anal, ut32 query);
extern RList *r2ghidra_preludes(RAnal *anal);
extern char *get_reg_profile(RAnal *anal);
extern int sleigh_op(RAnal *a, RAnalOp *anal_op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask);
extern int esil_sleigh_fini(RAnalEsil *esil);
extern int esil_sleigh_init(RAnalEsil *esil);
RAnalPlugin r_anal_plugin_ghidra = {
	.name = "r2ghidra",
	.desc = "SLEIGH Disassembler from Ghidra",
	.license = "GPL3",
	.arch = "sleigh",
	.author = "FXTi, pancake",
	.version = R2_VERSION,
#if R2_VERSION_NUMBER >= 50609
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
#endif
	.cpus = "6502,6805,8051,arm,avr,cr16,dalvik,hppa,java,m68k,m8c,mips,mcs96,msp430,pic24,ppc,sh,sparc,stm8,tricore,toy,v850,wasm,x86,z80",
	.bits = 0,
	.esil = true,
	.fileformat_type = 0,
	.init = &sanal_init,
	.fini = &sanal_fini,
	.archinfo = &archinfo,
	.preludes = anal_preludes,
	.op = &sleigh_op,
	.get_reg_profile = &get_reg_profile,
	.esil_init = esil_sleigh_init,
	.esil_fini = esil_sleigh_fini,
#if R2_VERSION_NUMBER >= 50609
	.mnemonics = NULL,
#endif
};
#endif
