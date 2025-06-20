/* r2ghidra - LGPL - Copyright 2019-2021 - thestr4ng3r */

#ifndef R2GHIDRA_R2LOADIMAGE_H
#define R2GHIDRA_R2LOADIMAGE_H


// Windows defines LoadImage to LoadImageA
#include <r_core.h>
#ifdef LoadImage
#undef LoadImage
#endif

#include "loadimage.hh"

// using namespace ghidra;
class RCoreMutex;

class R2LoadImage : public ghidra::LoadImage {
private:
	RCoreMutex *const coreMutex;
	ghidra::AddrSpaceManager *addr_space_manager;

public:
	explicit R2LoadImage(RCoreMutex *coreMutex, ghidra::AddrSpaceManager *addr_space_manager);

	void loadFill(ghidra::uint1 *ptr, ghidra::int4 size, const ghidra::Address &addr) override;
	std::string getArchType() const override;
	void adjustVma(long adjust) override;
	void getReadonly(ghidra::RangeList &list) const override;
};

#endif //R2GHIDRA_R2LOADIMAGE_H
