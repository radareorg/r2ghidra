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
// Inline loads from stack of constants recorded by opStore
// Inline loads from stack of constants recorded by opStore
void R2PrintC::opLoad(const PcodeOp *op) {
    // PcodeOp LOAD: input[0]=memory state, input[1]=address
    const Varnode *addrVN = op->getIn(1);
    AddrSpace *stackSp = glb->getStackSpace();
    if (addrVN->getSpace() == stackSp) {
        uintb offset = addrVN->getOffset();
        auto it = constMap.find(offset);
        if (it != constMap.end()) {
            // Inline the recorded constant value
            uintb val = it->second;
            const Datatype *type = op->getOut()->getType();
            pushConstant(val, type, vartoken, op->getOut(), op);
            return;
        }
    }
    PrintC::opLoad(op);
}

R2PrintC::R2PrintC(Architecture *g, const string &nm) : PrintC(g, nm) {
 	option_NULL = true;
// option_space_after_comma = true;
// 	option_nocasts = true;
option_convention = true;
option_hide_exts = true;
option_inplace_ops = false;
///  option_nocasts = false;
///  option_NULL = false;
///  option_unplaced = false;
///  option_space_after_comma = false;
///  option_newline_before_else = true;
///  option_newline_before_opening_brace = false;
///  option_newline_after_prototype = true;
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
// Skip printing of raw stores of constant or pointer arguments to the stack
void R2PrintC::opStore(const PcodeOp *op) {
    // PcodeOp STORE: input[0]=memory state, input[1]=address, input[2]=value
    // Record STORE of constant into stack: argument setup
    const Varnode *destVN = op->getIn(1);
    const Varnode *valVN = op->getIn(2);
    AddrSpace *stackSp = glb->getStackSpace();
    // Only inline constant pointers stored into the stack frame
    if (destVN->getSpace() == stackSp && valVN->isConstant() && valVN->getType()->getMetatype() == TYPE_PTR) {
        uintb off = destVN->getOffset();
        constMap[off] = valVN->getOffset();
        // skip printing this store
        return;
    }
    PrintC::opStore(op);
}

/*
void R2PrintC::push_integer(uintb val,int4 sz,bool sign,tagtype tag, const Varnode *vn,const PcodeOp *op) {
}

void R2PrintC::pushConstant(uintb val,const Datatype *ct,tagtype tag, const Varnode *vn, const PcodeOp *op) {
}
*/
