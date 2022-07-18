/* r2ghidra - LGPL - Copyright 2020-2022 - pancake */

#include <r_lib.h>
#include <r_anal.h>

extern int sanal_init(void *p);
extern int sanal_fini(void *p);
extern int archinfo(RAnal *anal, int query);
extern int sleigh_op(RAnal *a, RAnalOp *anal_op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask);
extern char *get_reg_profile(RAnal *anal);
extern int esil_sleigh_fini(RAnalEsil *esil);
extern int esil_sleigh_init(RAnalEsil *esil);
extern RList *anal_preludes(RAnal *anal);

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
	.cpus = "6502,6805,8051,arm,avr,cr16,dalvik,hppa,java,m68k,m8c,mips,mcs96,msp430,pic24,ppc,sh,sparc,stm8,tricore,toy,v850,x86,z80",
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

#if 0

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_ghidra,
	.version = R2_VERSION,
	.pkgname = "r2ghidra"
};
#endif

#endif
