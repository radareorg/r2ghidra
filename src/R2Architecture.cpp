/* r2ghidra - LGPL - Copyright 2019-2022 - thestr4ng3r, pancake */

#include "R2LoadImage.h"
#include "R2Scope.h"
#include "R2Architecture.h"
#include "R2TypeFactory.h"
#include "R2CommentDatabase.h"
#include "R2Utils.h"
#include "ArchMap.h"

#include <funcdata.hh>
#include <coreaction.hh>

#include <iostream>
#include <cassert>

// maps radare2 calling conventions to decompiler proto models
static const std::map<std::string, std::string> cc_map = {
	{ "cdecl", "__cdecl" },
	{ "fastcall", "__fastcall" },
	{ "ms", "__fastcall" },
	{ "stdcall", "__stdcall" },
	{ "cdecl-thiscall-ms", "__thiscall" },
	{ "sh32", "__stdcall" },
	{ "amd64", "__stdcall" },
	{ "arm64", "__cdecl" },
	{ "arm32", "__stdcall" },
	{ "arm16", "__stdcall" } /* not actually __stdcall */
};

std::string FilenameFromCore(RCore *core) {
	if (core && core->bin && core->bin->file) {
		return core->bin->file;
	}
	return std::string();
}

R2Architecture::R2Architecture(RCore *core, const std::string &sleigh_id)
	: SleighArchitecture (FilenameFromCore (core), sleigh_id.empty () ? SleighIdFromCore (core) : sleigh_id, &cout),
	coreMutex (core) {
}

ProtoModel *R2Architecture::protoModelFromR2CC(const char *cc) {
	auto it = cc_map.find (cc);
	if (it == cc_map.end ()) {
		return nullptr;
	}
	auto protoIt = protoModels.find (it->second);
	if (protoIt == protoModels.end ()) {
		return nullptr;
	}
	return protoIt->second;
}

static std::string lowercase(std::string str) {
	std::transform (str.begin (), str.end (), str.begin (), [](int c){
		if (c >= 'A' && c <= 'Z') {
			return c - ('A' - 'a');
		}
		return c;
	});
	return str;
}

void R2Architecture::loadRegisters(const Translate *translate) {
	registers = {};
	if (!translate) {
		return;
	}
	std::map<VarnodeData, std::string> regs;
	translate->getAllRegisters(regs);
	for (const auto &reg : regs) {
		registers[reg.second] = reg.first;
		auto lower = lowercase(reg.second);
		// as a fallback we also map all registers as lowercase
		if (registers.find(lower) == registers.end()) {
			registers[lower] = reg.first;
		}
	}
}

Address R2Architecture::registerAddressFromR2Reg(const char *regname) {
	loadRegisters (translate);
	auto it = registers.find (regname);
	if (it == registers.end ()) {
		it = registers.find (lowercase (regname));
	}
	if (it == registers.end ()) {
		return Address (); // not found, invalid addr
	}
	return it->second.getAddr ();
}

Translate *R2Architecture::buildTranslator(DocumentStorage &store) {
	Translate *ret = SleighArchitecture::buildTranslator (store);
	loadRegisters(ret);
	return ret;
}

ContextDatabase *R2Architecture::getContextDatabase() {
	return context;
}

void R2Architecture::postSpecFile() {
	RCoreLock core(getCore());
	r_list_foreach_cpp<RAnalFunction>(core->anal->fcns, [&](RAnalFunction *func) {
		if (func->is_noreturn) {
			// Configure noreturn functions
			Funcdata *infd = symboltab->getGlobalScope()->queryFunction(Address(getDefaultCodeSpace(), func->addr));
			if (!infd) {
				return;
			}
			infd->getFuncProto ().setNoReturn(true);
		}
	});
}

void R2Architecture::buildAction(DocumentStorage &store) {
	parseExtraRules (store);	// Look for any additional rules
	allacts.universalAction (this);
	allacts.resetDefaults ();
	if (rawptr) {
		allacts.cloneGroup ("decompile", "decompile-deuglified");
		allacts.removeFromGroup ("decompile-deuglified", "fixateglobals"); // this action (ActionMapGlobals) will create these ugly uRam0x12345s
		allacts.setCurrent ("decompile-deuglified");
	}
}

void R2Architecture::buildLoader(DocumentStorage &store) {
	RCoreLock core (getCore ());
	collectSpecFiles (*errorstream);
	loader = new R2LoadImage (getCore ());
}

Scope *R2Architecture::buildDatabase(DocumentStorage &store) {
	symboltab = new Database (this, false);
	Scope *globalscope = new R2Scope (this);
	symboltab->attachScope (globalscope, nullptr);
	return globalscope;
}

void R2Architecture::buildTypegrp(DocumentStorage &store) {
	r2TypeFactory_ = new R2TypeFactory (this);
	types = r2TypeFactory_;
}

void R2Architecture::buildCommentDB(DocumentStorage &store) {
	commentdb = new R2CommentDatabase (this);
}
