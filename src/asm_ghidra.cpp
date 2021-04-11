/* r2ghidra - LGPL - Copyright 2020-2021 - FXTi, pancake */

#include <r_lib.h>
#include <r_asm.h>
#include "SleighAsm.h"

static SleighAsm *sasm = nullptr;
static RIO *rio = nullptr;

//#define DEBUG_EXCEPTIONS

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len)
{
	int r = 0;

	if(!a->cpu)
		return r;

#ifndef DEBUG_EXCEPTIONS
	try
	{
#endif
		RBin *bin = a->binb.bin;

		if(!bin)
		{
			if(!rio)
			{
				rio = r_io_new();
				if (!sasm) {
					sasm = new SleighAsm();
				}
				sasm->sleigh_id.clear(); // For newly created RIO, refresh SleighAsm.
			}
			else
				r_io_close_all(rio);

			RBuffer *tmp_buf = r_buf_new_with_bytes(buf, len);
			r_io_open_buffer(rio, tmp_buf, R_PERM_RWX, 0);
			r_buf_free(tmp_buf);
		}

		if (!sasm) {
			sasm = new SleighAsm();
		}
		sasm->init(a->cpu, a->bits, a->big_endian, bin? bin->iob.io : rio, SleighAsm::getConfig(a));
		sasm->check(bin? a->pc : 0, buf, len);
		r = sasm->disassemble(op, bin? a->pc : 0);
#ifndef DEBUG_EXCEPTIONS
	}
	catch(const LowlevelError &e)
	{
		r_strbuf_set(&op->buf_asm, e.explain.c_str());
		r = 1;
	}
#endif

	op->size = r;
	return r;
}

static bool fini(void *p)
{
	if (sasm) {
		delete sasm;
		sasm = nullptr;
	}
	if (rio) {
		r_io_free(rio);
		rio = nullptr;
	}
	return true;
}

#if __WINDOWS__
// this is not really a windows issue, but GCC/CLANG support
// designed initializers as a C++ extension and its better
// to not blindly fill structs
#define KV(x, y) y
#else
#define KV(x, y) x = y
#endif

static RAsmPlugin r_asm_plugin_ghidra = {
	KV(.name, "r2ghidra"),
	KV(.arch, "sleigh"),
	KV(.author, "FXTi"),
	KV(.version, nullptr),
	KV(.cpus, "6502,arm,avr,dalvik,hppa,java,m68k,mips,msp430,ppc,sh,sparc,sparc,tricore,v850,x86");
	KV(.desc, "SLEIGH Disassembler from Ghidra"),
	KV(.license, "GPL3"),
	KV(.user, nullptr),
	KV(.bits, 8 | 16 | 32 | 64),
	KV(.endian, 0),
	KV(.init, nullptr),
	KV(.fini, &fini),
	KV(.disassemble, &disassemble),
	KV(.assemble, nullptr),
	KV(.modify, nullptr),
	KV(.mnemonics, nullptr),
	KV(.features, nullptr)
};

#ifndef CORELIB
#ifdef __cplusplus
extern "C" {
#endif
R_API RLibStruct radare_plugin = {
	KV(.type, R_LIB_TYPE_ASM),
	KV(.data, &r_asm_plugin_ghidra),
	KV(.version, R2_VERSION),
	KV(.free, nullptr),
	KV(.pkgname, "r2ghidra")
};
#ifdef __cplusplus
}
#endif
#endif
