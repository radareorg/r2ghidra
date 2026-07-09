// SPDX-FileCopyrightText: 2026 pancake
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef R2GHIDRA_R2HARVEST_H
#define R2GHIDRA_R2HARVEST_H

#include "R2Architecture.h"

#include <r_core.h>
#include <string>
#include <vector>

struct HarvestVar {
	std::string name;
	std::string type; // "" = don't retype
	std::vector<std::string> regNames; // candidate registers, best match first; non-empty = register storage
	uintb stackOff = 0;
	bool onStack = false;
	bool nameDefined = false;
};

struct HarvestProto {
	bool valid = false;
	std::string retType; // "" = keep the current return type
	bool dotdotdot = false;
	bool noreturn = false;
	std::vector<HarvestVar> params;
};

struct Harvest {
	HarvestProto proto;
	std::vector<HarvestVar> locals;
	int4 extraPop = 0;
	uintb stackHighest = 0;
};

// copy the recovered prototype and locals into plain data so nothing references the arch after teardown
void HarvestFuncdata(R2Architecture &arch, ghidra::Funcdata *func, Harvest &out);
void WriteHarvest(RCore *core, RAnalFunction *fcn, const Harvest &h, bool writeVars, bool writeSig);

#endif
