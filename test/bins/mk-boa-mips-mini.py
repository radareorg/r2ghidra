#!/usr/bin/env python3
import struct
import sys
from pathlib import Path


BASE = 0x400000
FILE_SIZE = 0x1000
PHOFF = 0x34
PHNUM = 5
INTERP_OFF = 0x100
DYN_OFF = 0x120
HASH_OFF = 0x220
SYMTAB_OFF = 0x280
STRTAB_OFF = 0x320
GOT_OFF = 0x3c0
CURRENT_TIME_OFF = 0x400
MAIN_OFF = 0x500
ISFILE_OFF = 0x580
UMASK_STUB_OFF = 0x600
TIME_STUB_OFF = 0x610
STAT_STUB_OFF = 0x620
GP = 0x408000


def p16(value):
    return struct.pack(">H", value & 0xffff)


def p32(value):
    return struct.pack(">I", value & 0xffffffff)


def vaddr(offset):
    return BASE + offset


def phdr(ptype, offset, vaddr_, filesz, memsz, flags, align):
    return b"".join([
        p32(ptype),
        p32(offset),
        p32(vaddr_),
        p32(vaddr_),
        p32(filesz),
        p32(memsz),
        p32(flags),
        p32(align),
    ])


def sym(name, value, size, bind, typ, shndx):
    return b"".join([
        p32(name),
        p32(value),
        p32(size),
        bytes([(bind << 4) | typ, 0]),
        p16(shndx),
    ])


def addiu(rt, rs, imm):
    return 0x24000000 | (rs << 21) | (rt << 16) | (imm & 0xffff)


def lw(rt, off, base):
    return 0x8c000000 | (base << 21) | (rt << 16) | (off & 0xffff)


def sw(rt, off, base):
    return 0xac000000 | (base << 21) | (rt << 16) | (off & 0xffff)


def instrs(words):
    return b"".join(p32(word) for word in words)


def gp_prologue(func):
    disp = GP - func
    hi = (disp + 0x8000) >> 16
    return [
        0x3c1c0000 | (hi & 0xffff),  # lui gp, hi(_gp - func)
        addiu(28, 28, disp),         # addiu gp, gp, lo(_gp - func)
        0x0399e021,                  # addu gp, gp, t9
    ]


def write_at(buf, offset, data):
    buf[offset:offset + len(data)] = data


def build():
    buf = bytearray(FILE_SIZE)
    interp = b"/lib/ld-uClibc.so.0\0"

    ident = b"\x7fELF" + bytes([1, 2, 1, 0]) + bytes(8)
    ehdr = b"".join([
        ident,
        p16(2),
        p16(8),
        p32(1),
        p32(vaddr(MAIN_OFF)),
        p32(PHOFF),
        p32(0),
        p32(0x1007),
        p16(52),
        p16(32),
        p16(PHNUM),
        p16(0),
        p16(0),
        p16(0),
    ])
    write_at(buf, 0, ehdr)

    phdrs = b"".join([
        phdr(6, PHOFF, vaddr(PHOFF), 32 * PHNUM, 32 * PHNUM, 4, 4),
        phdr(3, INTERP_OFF, vaddr(INTERP_OFF), len(interp), len(interp), 4, 1),
        phdr(0x70000000, 0, 0, 0, 0, 7, 16),
        phdr(1, 0, BASE, FILE_SIZE, FILE_SIZE, 7, 0x1000),
        phdr(2, DYN_OFF, vaddr(DYN_OFF), 0x100, 0x100, 7, 4),
    ])
    write_at(buf, PHOFF, phdrs)
    write_at(buf, INTERP_OFF, interp)

    names = [
        b"",
        b"_gp",
        b"_GLOBAL_OFFSET_TABLE_",
        b"main",
        b"isFileExist",
        b"current_time",
        b"umask",
        b"time",
        b"stat",
        b"libc.so.0",
    ]
    strtab = bytearray()
    name_offsets = []
    for name in names:
        name_offsets.append(len(strtab))
        strtab += name + b"\0"
    write_at(buf, STRTAB_OFF, strtab)

    shn_undef = 0
    shn_abs = 0xfff1
    stb_global = 1
    stt_notype = 0
    stt_object = 1
    stt_func = 2
    syms = [
        sym(0, 0, 0, 0, 0, shn_undef),
        sym(name_offsets[1], GP, 0, stb_global, stt_notype, shn_abs),
        sym(name_offsets[2], vaddr(GOT_OFF), 0, stb_global, stt_object, shn_abs),
        sym(name_offsets[3], vaddr(MAIN_OFF), 0x60, stb_global, stt_func, shn_abs),
        sym(name_offsets[4], vaddr(ISFILE_OFF), 0x40, stb_global, stt_func, shn_abs),
        sym(name_offsets[5], vaddr(CURRENT_TIME_OFF), 4, stb_global, stt_object, shn_abs),
        sym(name_offsets[6], vaddr(UMASK_STUB_OFF), 16, stb_global, stt_func, shn_undef),
        sym(name_offsets[7], vaddr(TIME_STUB_OFF), 16, stb_global, stt_func, shn_undef),
        sym(name_offsets[8], vaddr(STAT_STUB_OFF), 16, stb_global, stt_func, shn_undef),
    ]
    write_at(buf, SYMTAB_OFF, b"".join(syms))

    nsyms = len(syms)
    elf_hash = p32(1) + p32(nsyms) + p32(0) + b"".join(p32(0) for _ in range(nsyms))
    write_at(buf, HASH_OFF, elf_hash)

    got_values = [
        0,
        0x80000000,
        vaddr(CURRENT_TIME_OFF),
        vaddr(UMASK_STUB_OFF),
        vaddr(TIME_STUB_OFF),
        vaddr(STAT_STUB_OFF),
    ]
    for i, value in enumerate(got_values):
        write_at(buf, GOT_OFF + i * 4, p32(value))

    dynamic = [
        (1, name_offsets[9]),          # DT_NEEDED
        (0x0c, vaddr(MAIN_OFF)),       # DT_INIT
        (0x0d, vaddr(STAT_STUB_OFF) + 0x10),
        (4, vaddr(HASH_OFF)),          # DT_HASH
        (5, vaddr(STRTAB_OFF)),        # DT_STRTAB
        (6, vaddr(SYMTAB_OFF)),        # DT_SYMTAB
        (10, len(strtab)),             # DT_STRSZ
        (11, 16),                      # DT_SYMENT
        (3, vaddr(GOT_OFF)),           # DT_PLTGOT
        (17, 0),                       # DT_REL
        (18, 0),                       # DT_RELSZ
        (19, 8),                       # DT_RELENT
        (0x70000001, 1),               # DT_MIPS_RLD_VERSION
        (0x70000005, 2),               # DT_MIPS_FLAGS
        (0x70000006, BASE),            # DT_MIPS_BASE_ADDRESS
        (0x7000000a, 2),               # DT_MIPS_LOCAL_GOTNO
        (0x70000011, nsyms),           # DT_MIPS_SYMTABNO
        (0x70000013, 5),               # DT_MIPS_GOTSYM
        (0, 0),
    ]
    write_at(buf, DYN_OFF, b"".join(p32(tag) + p32(value) for tag, value in dynamic))

    main = vaddr(MAIN_OFF)
    is_file = vaddr(ISFILE_OFF)
    got_current_time = vaddr(GOT_OFF + 8)
    got_umask = vaddr(GOT_OFF + 12)
    got_time = vaddr(GOT_OFF + 16)
    got_stat = vaddr(GOT_OFF + 20)

    main_words = gp_prologue(main) + [
        addiu(29, 29, -0x50),
        sw(31, 0x48, 29),
        sw(19, 0x44, 29),
        sw(18, 0x40, 29),
        sw(28, 0x18, 29),
        lw(25, got_umask - GP, 28),
        0x00809821,  # move s3, a0
        addiu(4, 0, 0x3f),
        0x0320f809,  # jalr t9
        0x00a09021,  # move s2, a1
        lw(28, 0x18, 29),
        0,
        lw(25, got_time - GP, 28),
        lw(4, got_current_time - GP, 28),
        0x0320f809,
        0,
        lw(28, 0x18, 29),
        lw(31, 0x48, 29),
        0x03e00008,  # jr ra
        addiu(29, 29, 0x50),
    ]
    write_at(buf, MAIN_OFF, instrs(main_words))

    is_file_words = gp_prologue(is_file) + [
        addiu(29, 29, -0xb8),
        sw(31, 0xb0, 29),
        sw(28, 0x10, 29),
        lw(25, got_stat - GP, 28),
        0,
        0x0320f809,
        addiu(5, 29, 0x18),
        lw(28, 0x10, 29),
        lw(31, 0xb0, 29),
        0x00021027,  # nor v0, zero, v0
        0x000217c2,  # srl v0, v0, 0x1f
        0x03e00008,
        addiu(29, 29, 0xb8),
    ]
    write_at(buf, ISFILE_OFF, instrs(is_file_words))

    stub = instrs([0x03e00008, 0, 0, 0])
    write_at(buf, UMASK_STUB_OFF, stub)
    write_at(buf, TIME_STUB_OFF, stub)
    write_at(buf, STAT_STUB_OFF, stub)
    return buf


def main():
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("elf/boa-mips-mini")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(build())


if __name__ == "__main__":
    main()
