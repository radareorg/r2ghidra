/* r2ghidra - LGPL - Copyright 2019-2021 - thestr4ng3r */

#ifndef R2GHIDRA_R2LOADIMAGE_H
#define R2GHIDRA_R2LOADIMAGE_H

#include "loadimage.hh"

#include <r_core.h>

// Windows defines LoadImage to LoadImageA
#ifdef LoadImage
#undef LoadImage
#endif

using namespace ghidra;
class RCoreMutex;

class R2LoadImage : public LoadImage {
private:
	RCoreMutex *const coreMutex;
	AddrSpaceManager *addr_space_manager;

public:
	explicit R2LoadImage(RCoreMutex *coreMutex, AddrSpaceManager *addr_space_manager);

	void loadFill(uint1 *ptr, int4 size, const Address &addr) override;
	string getArchType() const override;
	void adjustVma(long adjust) override;
	void getReadonly(RangeList &list) const override;
};

#endif //R2GHIDRA_R2LOADIMAGE_H
