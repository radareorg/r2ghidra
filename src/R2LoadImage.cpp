/* r2ghidra - LGPL - Copyright 2019-2021 - pancake, thestr4ng3r */

#include "R2LoadImage.h"
#include "R2Utils.h"
#include "R2Architecture.h"

R2LoadImage::R2LoadImage(RCoreMutex *coreMutex, AddrSpaceManager *addr_space_manager) : LoadImage("radare2_program"),
	coreMutex(coreMutex),
	addr_space_manager(addr_space_manager)
{
	// nothing to do
}

void R2LoadImage::loadFill(uint1 *ptr, int4 size, const Address &addr) {
	RCoreLock core (coreMutex);
	r_io_read_at (core->io, addr.getOffset(), ptr, size);
}

string R2LoadImage::getArchType() const {
	return "radare2";
}

void R2LoadImage::adjustVma(long adjust) {
	throw LowlevelError("Cannot adjust radare2 virtual memory");
}
static bool isptr(ut64 *p) {
	if (!*p) return true;
/*
if (*p < 0x1000) {
	return false;
}
*/
	return (*p != UT64_MAX);
	// return (*p >= 0x100003a54 && *p < 0x10000fa54);
}

void R2LoadImage::getReadonly(RangeList &list) const {
	RCoreLock core(coreMutex);
	bool roprop = r_config_get_b (core->config, "r2ghidra.roprop");
	// RCore *core = coreMutex->RCore();
	// consider ANY address as resolable as a flag by r2
	// this is used by the ropropagate code which follows
	// pointers and replaces them with strings or flags
	// in the decompilation. NULL is not considered.
	if (roprop) {
		bool fullro = r_config_get_b (core->config, "r2ghidra.roprop.full");
		bool roptr = r_config_get_b (core->config, "r2ghidra.roprop.ptr");
		auto space = addr_space_manager->getDefaultCodeSpace ();
		if (fullro) {
			// full
			list.insertRange(space, 0x1000, ST64_MAX - 1);
		} else {
			// roptr
			if (roptr) {
				// find ranges with pointers
				RIOMapRef *mapref;
				RListIter *iter;
				RIO *io = core->io;
				RIOBank *bank = r_io_bank_get (io, io->bank);
				r_list_foreach_cpp<RIOMapRef>(bank->maprefs, [&](RIOMapRef *mapref) {
					RIOMap *map = r_io_map_get (io, mapref->id);
					ut64 begin = r_io_map_begin (map);
					ut64 end = r_io_map_end (map);
					if (map->perm & R_PERM_W) {
						return;
					}
					ut64 fin = end - begin;
					if (fin > 0xffffff) {
						list.insertRange(space, begin, end);
						return;
					}
					ut8 *buf = (ut8 *)malloc (fin);
					if (!buf) {
						list.insertRange(space, begin, end);
						return;
					}
					r_io_read_at (io, begin, buf, fin);
					ut64 base = begin;
					ut64 basefin = begin;
					ut8 *data = buf;
					bool hasdata = false;
					int inc = (core->rasm->config->bits == 64)? 8: 4;
					for (int i = 0; i < fin; i += inc) {
						basefin = begin + i;
						if (isptr ((ut64 *)(data + i))) {
							// eprintf ("valid %llx\n", data[i]);
							hasdata = true;
						} else {
							if (hasdata) {
								// eprintf ("0 append %llx %llx because of 0x%llx\n", base, basefin, *((ut64*)(data +i)));
								list.insertRange(space, base, basefin); // begin, end);
								hasdata = false;
								base = basefin;
							}
						}
					}
					free (buf);
					if (hasdata) {
						// eprintf ("1 append %llx %llx\n", base, basefin);
						list.insertRange(space, base, basefin);
					}
				});
			} else {
				// ro maps when r2ghidra.roprop.ptr is false and r2ghidra.roprop is true
				RIOMapRef *mapref;
				RListIter *iter;
				RIO *io = core->io;
				RIOBank *bank = r_io_bank_get (io, io->bank);
				r_list_foreach_cpp<RIOMapRef>(bank->maprefs, [&](RIOMapRef *mapref) {
					RIOMap *map = r_io_map_get (io, mapref->id);
					ut64 begin = r_io_map_begin (map);
					ut64 end = r_io_map_end (map);
					if (map->perm & R_PERM_W) {
						return;
					}
					list.insertRange(space, begin, end);
				});
			}
		}
	}
}
