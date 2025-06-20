/* r2ghidra - LGPL - Copyright 2019-2025 - thestr4ng3r, pancake */

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
	// unplaced option is necessary to show the inline ::user2 comments defined from radare2
	option_unplaced = false;
//	option_space_after_comma = true;
// 	option_nocasts = true;
///  option_convention = true;
///  option_hide_exts = true;
///  option_inplace_ops = false;
///  option_nocasts = false;
///  option_NULL = false;
///  option_space_after_comma = false;
///  option_newline_before_else = true;
///  option_newline_before_opening_brace = false;
///  option_newline_after_prototype = true;
// Default r2ghidra C printer options:
#if 0
	setNULLPrinting(true);                             // print NULL keyword for null pointers
	setNoCastPrinting(false);                          // show C casts by default
	setInplaceOps(false);                              // disable in-place operators (+=, *=, etc.)
	setConvention(true);                               // include calling convention in function prototypes
	setHideImpliedExts(true);                          // hide implied zero/sign extensions (ZEXT/SEXT)
	setCStyleComments();                               // use C-style /* */ comments
	setMaxLineSize(80);                                // wrap lines at 80 characters
	setIndentIncrement(2);                             // indent 2 spaces per nested block
	setLineCommentIndent(0);                           // align line comments with code
	setCommentStyle("c");                            // use traditional C comment style
	setBraceFormatFunction(Emit::skip_line);           // function opening brace on a separate line
	setBraceFormatIfElse(Emit::same_line);             // if/else opening brace on same line
	setBraceFormatLoop(Emit::same_line);               // loop opening brace on same line
	setBraceFormatSwitch(Emit::same_line);             // switch opening brace on same line
	setNamespaceStrategy(PrintLanguage::MINIMAL_NAMESPACES); // minimal namespace qualifiers
#endif
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

/*
void R2PrintC::push_integer(uintb val,int4 sz,bool sign,tagtype tag, const Varnode *vn,const PcodeOp *op) {
}

void R2PrintC::pushConstant(uintb val,const Datatype *ct,tagtype tag, const Varnode *vn, const PcodeOp *op) {
}
*/
