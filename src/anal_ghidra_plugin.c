/* r2ghidra - LGPL - Copyright 2020-2026 - pancake */

#include <r_lib.h>
#include <r_anal.h>
#include <r_arch.h>

extern int archinfo(RArchSession *as, ut32 query);
extern bool sanal_init(RArchSession *as);
extern bool sanal_fini(RArchSession *as);
extern RList *r2ghidra_preludes(RArchSession *as);
extern int archinfo(RArchSession *as, ut32 query);
extern char *r2ghidra_regs(RArchSession *as);
extern bool r2ghidra_esilcb(RArchSession *as, RArchEsilAction action);
extern char *get_reg_profile(RAnal *anal);
bool sleigh_decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask);

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
	.cpus = "6502,6805,8051,arm,avr,cr16,dalvik,hppa,java,m68k,m8c,mips,mcs96,msp430,pic24,ppc,sh,sparc,stm8,tricore,toy,v850,wasm,x86,z80,xtensa",
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
