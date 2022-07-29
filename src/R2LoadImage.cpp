/* r2ghidra - LGPL - Copyright 2019-2021 - pancake, thestr4ng3r */

#include "R2LoadImage.h"
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

void R2LoadImage::getReadonly(RangeList &list) const {
	// consider ANY address as resolable as a flag by r2
	// this is used by the ropropagate code which follows
	// pointers and replaces them with strings or flags
	// in the decompilation. NULL is not considered.
eprintf ("JEJEJ A %p\n", addr_space_manager);
	auto space = addr_space_manager->getDefaultCodeSpace();
	list.insertRange(space, 0x1000, UT64_MAX);
}
