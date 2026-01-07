/* r2ghidra - LGPL - Copyright 2019-2026 - pancake */

#include "R2Architecture.h"
#include "R2LoadImage.h"
#include "R2Utils.h"

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
	//if (!*p) return false;
	if (*p < 0x1000) {
		return false;
	}
	return (*p != UT64_MAX);
}

static void addRangesWithPointers(RCoreLock &core, RangeList &list, AddrSpace *space) {
	RIOMapRef *mapref;
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
					if (base > 0) {
						list.insertRange(space, base, basefin); // begin, end);
					}
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
}

void R2LoadImage::getReadonly(RangeList &list) const {
	RCoreLock core(coreMutex);
	int roprop = r_config_get_i (core->config, "r2ghidra.roprop");
	if (roprop > 0) {
		auto space = addr_space_manager->getDefaultCodeSpace ();
		switch (roprop) {
		case 1:
			break;
		case 2:
			// find ranges with pointers
			addRangesWithPointers(core, list, space);
			break;
		case 3:
			{
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
			break;
		case 4:
			list.insertRange(space, 0x1000, ST64_MAX - 1);
			break;
		default:
			list.insertRange(space, 0, UT64_MAX - 1);
			break;
		}
	}
}
