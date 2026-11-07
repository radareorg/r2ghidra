// SPDX-FileCopyrightText: 2019-2026 pancake
// SPDX-License-Identifier: LGPL-3.0-only

#include "R2Architecture.h"
#include "R2LoadImage.h"
#include "R2Utils.h"

#include <memory>
#include <new>

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
static void addRangesWithPointers(RIO *io, RangeList &list, AddrSpace *space, ut64 begin, int size, int bits) {
	std::unique_ptr<ut8[]> buf (new (std::nothrow) ut8[size]);
	if (!buf) {
		return;
	}
	const int nread = r_io_nread_at (io, begin, buf.get (), size);
	const int width = bits / 8;
	const ut64 maxptr = bits == 64? UT64_MAX: UT32_MAX;
	int start = 0;
	int i = 0;
	for (; i <= nread - width; i += width) {
		const ut64 ptr = r_read_ble (buf.get () + i, space->isBigEndian (), bits);
		if (ptr < 0x1000 || ptr == maxptr) {
			if (start < i) {
				list.insertRange (space, begin + start, begin + i - 1);
			}
			start = i + width;
		}
	}
	if (start < i) {
		list.insertRange (space, begin + start, begin + i - 1);
	}
}

static void addReadonlyMapRanges(RCoreLock &core, RangeList &list, AddrSpace *space, bool scan) {
	RIO *io = core->io;
	RIOBank *bank = r_io_bank_get (io, io->bank);
	if (!io->va || !bank) {
		return;
	}
	// The submap tree only includes ranges visible after applying map priority.
	r_io_bank_drain (io, io->bank);
	const int bits = core->rasm->config->bits == 64? 64: 32;
	const int width = bits / 8;
	RRBNode *node;
	RIOSubMap *submap;
	r_crbtree_foreach (bank->submaps, node, RIOSubMap, submap) {
		RIOMap *map = r_io_map_get_by_ref (io, &submap->mapref);
		if (!map || !(map->perm & R_PERM_R) || (map->perm & R_PERM_W)) {
			continue;
		}
		const ut64 begin = r_io_map_begin (submap);
		const ut64 size = r_io_map_size (submap);
		if (scan && size <= 0xffffff) {
			const ut64 misalignment = (begin - r_io_map_begin (map)) % width;
			const ut64 skip = misalignment? width - misalignment: 0;
			if (size >= skip + width) {
				addRangesWithPointers (io, list, space, begin + skip, size - skip, bits);
			}
		} else {
			list.insertRange (space, begin, r_io_map_to (submap));
		}
	}
}

// the loader fills relocation targets in at runtime, so their on-disk bytes are not constants
static void removeRelocRanges(RCoreLock &core, RangeList &list, AddrSpace *space) {
#if R2_ABIVERSION >= 136
	RVecRBinReloc *relocs = r_bin_get_relocs (core->bin);
#else
	RRBTree *relocs = r_bin_get_relocs (core->bin);
#endif
	if (!relocs) {
		return;
	}
	const ut64 width = (core->rasm->config->bits == 64)? 8: 4;
	auto removeRelocRange = [&list, space, width](const RBinReloc *reloc) {
		const ut64 at = reloc->vaddr;
		if (at && at != UT64_MAX) {
			list.removeRange (space, at, at + width - 1);
		}
	};
	RBinReloc *reloc;
#if R2_ABIVERSION >= 136
	R_VEC_FOREACH (relocs, reloc) {
		removeRelocRange (reloc);
	}
#else
	RRBNode *node;
	r_crbtree_foreach (relocs, node, RBinReloc, reloc) {
		removeRelocRange (reloc);
	}
#endif
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
		case 3:
			addReadonlyMapRanges (core, list, space, roprop == 2);
			break;
		case 4:
			list.insertRange(space, 0x1000, ST64_MAX - 1);
			break;
		default:
			list.insertRange(space, 0, UT64_MAX - 1);
			break;
		}
		removeRelocRanges (core, list, space);
	}
}
