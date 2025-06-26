/* r2ghidra - LGPL - Copyright 2019-2025 - thestr4ng3r, pancake */

#include "RCoreMutex.h"
#include <r_cons.h>

#include <cassert>

RCoreMutex::RCoreMutex(RCore *core) : caffeine_level(1), bed(nullptr), _core(core) {
}

void RCoreMutex::sleepEnd() {
	assert(caffeine_level >= 0);
	caffeine_level++;
	if (caffeine_level == 1) {
#if R2_VERSION_NUMBER >= 50909
		r_cons_sleep_end (_core->cons, bed);
#else
		r_cons_sleep_end (bed);
#endif
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
	assert (caffeine_level > 0);
	caffeine_level--;
	if (caffeine_level == 0) {
#if R2_VERSION_NUMBER >= 50909
		bed = r_cons_sleep_begin (_core->cons);
#else
		bed = r_cons_sleep_begin ();
#endif
	}
}
