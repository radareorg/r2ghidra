/* r2ghidra - LGPL - Copyright 2019-2025 - thestr4ng3r, pancake */

#include "RCoreMutex.h"
#include <r_cons.h>

RCoreMutex::RCoreMutex(RCore *core) : caffeine_level(1), bed(nullptr), _core(core) {
}

void RCoreMutex::sleepEnd() {
	if (caffeine_level < 0) {
		return;
	}
	caffeine_level++;
	if (caffeine_level == 1) {
		r_cons_sleep_end (_core->cons, bed);
		bed = nullptr;
	}
}

void RCoreMutex::sleepEndForce() {
	if (caffeine_level) {
		return;
	}
	sleepEnd ();
}

void RCoreMutex::sleepBegin() {
	if (caffeine_level <= 0) {
		return;
	}
	caffeine_level--;
	if (caffeine_level == 0) {
		bed = r_cons_sleep_begin (_core->cons);
	}
}
