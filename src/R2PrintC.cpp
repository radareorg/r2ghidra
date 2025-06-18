/* r2ghidra - LGPL - Copyright 2019-2024 - thestr4ng3r, pancake */

#include "R2PrintC.h"
#include "RCoreMutex.h"

#include <varnode.hh>
#include <architecture.hh>

using namespace ghidra;

// Constructing this registers the capability
R2PrintCCapability R2PrintCCapability::inst;

R2PrintCCapability::R2PrintCCapability(void) {
	name = "r2-c-language";
	isdefault = false;
}

PrintLanguage *R2PrintCCapability::buildLanguage(Architecture *glb) {
	return new R2PrintC (glb, name);
}

R2PrintC::R2PrintC(Architecture *g, const string &nm) : PrintC(g, nm) {
 	option_NULL = true;
	option_space_after_comma = true;
	option_convention = true;
	option_hide_exts = true;
	option_inplace_ops = false;
	option_unplaced = false;
	option_newline_before_else = true;
	option_newline_after_prototype = true;
}

void R2PrintC::setOptionNoCasts(bool nc) {
	option_nocasts = nc;
}

#if 0
void R2PrintC::opCast(const PcodeOp *op)
{
	// do nothing
fprintf (stderr, "opCast%c", 10);
}
#endif

void R2PrintC::pushUnnamedLocation(const Address &addr, const Varnode *vn, const PcodeOp *op) {
//	option_nocasts = true;
	// print (*(type *)0x0000...) instead of ram00000...
	AddrSpace *space = addr.getSpace ();
	if (space->getType() == IPTR_PROCESSOR) {
		pushOp (&dereference, op);
		auto type = glb->types->getTypePointer (space->getAddrSize (), vn->getType (), space->getWordSize ());
		// pushConstant (addr.getOffset (), type, vn, op);
		pushConstant(addr.getOffset(),type,vartoken,vn, op);
	} else {
		PrintC::pushUnnamedLocation (addr,vn, op);
	}
}

std::string R2PrintC::genericFunctionName(const Address &addr) {
	auto arch = dynamic_cast<R2Architecture *>(glb);
	if (arch) {
		RCoreLock core(arch->getCore());
		RFlagItem *flag = r_flag_get_at(core->flags, addr.getOffset(), false);
		if (flag) {
			if (core->flags->realnames && flag->realname) {
				return flag->realname;
			}
			return flag->name;
		}
	}
	return PrintC::genericFunctionName(addr);
}

/*
void R2PrintC::push_integer(uintb val,int4 sz,bool sign,tagtype tag, const Varnode *vn,const PcodeOp *op) {
}

void R2PrintC::pushConstant(uintb val,const Datatype *ct,tagtype tag, const Varnode *vn, const PcodeOp *op) {
}
*/
