/* r2ghidra - LGPL - Copyright 2025 - pancake */

#include "R2LoadImage.h"
#include "PcodeFixupPreprocessor.h"
#include "R2Architecture.h"
#include "R2TypeFactory.h"

#include <funcdata.hh>
#include <r_core.h>
#include <flow.hh>
#include <override.hh>
#include <fspec.hh>
#include <fspec.hh>
#include <database.hh>
#include <r_anal.h>
#include <r_core.h>
#include <r_bin.h>
#include <map>
#include <string>
#include <vector>
#include <strings.h>  // For strcasecmp function

using namespace ghidra;

static bool is_import_name(const char * R_NONNULL name) {
	return r_str_startswith (name, "imp.")
		|| r_str_startswith (name, "sym.imp.")
		|| r_str_startswith (name, "plt.")
		|| r_str_startswith (name, "reloc.");
}

// Helper to extract base function name from an import
static const char* extractLibcFuncName(const char *importName) {
	const char *last_dot = r_str_lchr (importName, '.');
	if (last_dot) {
		return last_dot + 1;
	}
	return nullptr;
}

R_VEC_TYPE (RVecAnalRef, RAnalRef);

void PcodeFixupPreprocessor::fixupSharedReturnJumpToRelocs(RAnalFunction *r2Func, Funcdata *ghFunc, RCore *core, R2Architecture &arch) {
	RVecAnalRef *refs = r_anal_function_get_refs (r2Func);
	RAnalRef *refi;
	auto space = arch.getDefaultCodeSpace();
#if 0
	auto ops = ghFunc->getBasicBlocks();
#endif
	if (r2Func->is_noreturn) {
		ghFunc->getFuncProto().setNoReturn(true);
	}
	R_VEC_FOREACH (refs, refi) {
		// R_LOG_INFO ("refi 0x%"PFMT64x"", refi->addr);
		RFlagItem *f = r_flag_get_at (core->flags, refi->addr, true);
		if (f) {
			if (1 && is_import_name (f->name)) {
				RAnalOp *op = r_core_anal_op (core, refi->at, 0);
				// Differentiate tail-call jumps from calls
				bool isTailCall = (op->type == R_ANAL_OP_TYPE_JMP);
				bool isCall = (op->type == R_ANAL_OP_TYPE_CALL);
				Address callAddr (space, refi->at);
				if (isTailCall) {
					R_LOG_INFO ("OverridingTailCallReturn %s", extractLibcFuncName (f->name));
					ghFunc->getOverride().insertFlowOverride(callAddr, Override::CALL_RETURN);
				}
				if (isCall) {
					R_LOG_INFO ("OverridingCallReturn %s", extractLibcFuncName (f->name)); // disabled flow override logging
                // Insert branch override (CALL/RETURN)
                // ghFunc->getOverride().insertFlowOverride(callAddr, Override::CALL_RETURN); // disabled flow override
                // Also apply simple hardcoded prototype for printf/exit
                const char *basename = extractLibcFuncName(f->name);
                if (basename) {
                    // Build raw prototype pieces
                    ProtoModel *pm = arch.protoModelFromR2CC("cdecl");
                    PrototypePieces pieces;
                    pieces.model = pm;
                    pieces.name = basename;
                    if (!strcmp(basename, "printf")) {
                        // int printf(const char *format, ...);
                        // Set return type to int
                        auto *tf = arch.getTypeFactory();
                        // Use unnamed base int type
                        Datatype *intType = tf->getBase(
                            tf->getSizeOfInt(), TYPE_INT);
                        pieces.outtype = intType;
                        // Build argument type: char *
                        auto space = arch.getDefaultCodeSpace();
                        // Use unnamed base char type (size 1, TYPE_INT)
                        Datatype *charType = tf->getBase(1, TYPE_INT);
                        Datatype *fmtType = tf->getTypePointer(
                            space->getAddrSize(), charType, space->getWordSize());
                        pieces.intypes.push_back(fmtType);
                        pieces.innames.push_back("format");
                        // Varargs start after named parameters
                        pieces.firstVarArgSlot = (int)pieces.intypes.size();
                    }
                    else if (!strcmp(basename, "scanf")) {
                        // int scanf(const char *format, ...);
                        auto *tf2 = arch.getTypeFactory();
                        Datatype *intType2 = tf2->getBase(tf2->getSizeOfInt(), TYPE_INT);
                        pieces.outtype = intType2;
                        auto space2 = arch.getDefaultCodeSpace();
                        Datatype *charType2 = tf2->getBase(1, TYPE_INT);
                        Datatype *fmtType2 = tf2->getTypePointer(space2->getAddrSize(), charType2, space2->getWordSize());
                        pieces.intypes.push_back(fmtType2);
                        pieces.innames.push_back("format");
                        pieces.firstVarArgSlot = (int)pieces.intypes.size();
                    }
                    else if (!strcmp(basename, "sscanf")) {
                        // int sscanf(const char *str, const char *format, ...);
                        auto *tf2 = arch.getTypeFactory();
                        Datatype *intType2 = tf2->getBase(tf2->getSizeOfInt(), TYPE_INT);
                        pieces.outtype = intType2;
                        auto space2 = arch.getDefaultCodeSpace();
                        Datatype *charType2 = tf2->getBase(1, TYPE_INT);
                        Datatype *ptrType2 = tf2->getTypePointer(space2->getAddrSize(), charType2, space2->getWordSize());
                        pieces.intypes.push_back(ptrType2);
                        pieces.innames.push_back("str");
                        pieces.intypes.push_back(ptrType2);
                        pieces.innames.push_back("format");
                        pieces.firstVarArgSlot = (int)pieces.intypes.size();
                    }
#if 0
                    else if (!strcmp(basename, "exit")) {
                        // void exit(int status);
                        Datatype *voidType = arch.getTypeFactory()->getTypeVoid();
                        pieces.outtype = voidType;
                        Datatype *intType2 = arch.getTypeFactory()->getBase(arch.getTypeFactory()->getSizeOfInt(), TYPE_INT, "int");
                        pieces.intypes.push_back(intType2);
                        pieces.innames.push_back("status");
                        pieces.firstVarArgSlot = -1;
                    }
#endif
                    // Only attach if we have a valid prototype
                    if (!pieces.intypes.empty() || pieces.outtype) {
                        FuncProto *fp = new FuncProto();
                        fp->setInternal(pm, pieces.outtype);
                        fp->setPieces(pieces);
                        ghFunc->getOverride().insertProtoOverride(callAddr, fp);
                    }
                }
				}
				r_anal_op_free (op);
			}
		}
	}
}
