// SPDX-FileCopyrightText: 2026 pancake
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef R2GHIDRA_R2TYPECOMPAT_H
#define R2GHIDRA_R2TYPECOMPAT_H

#include <cctype>
#include <r_util.h>
#include <r_lib.h>

// abi 143 made the count a query: a missing or malformed args key is unknown
static inline bool countargs(Sdb *tdb, const char *name, int *argc) {
#if R2_ABIVERSION >= 143
	return r_type_func_args_count (tdb, name, argc);
#else
	while (!sdb_const_get (tdb, name, 0) && r_str_startswith (name, "__")) {
		name += 2;
	}
	const char *args = sdb_const_getf (tdb, nullptr, "func.%s.args", name);
	if (!args || !isdigit ((ut8)*args)) {
		return false;
	}
	char *end;
	const ut64 count = strtoull (args, &end, 0);
	if (*end || count > ST32_MAX) {
		return false;
	}
	*argc = (int)count;
	return true;
#endif
}

#endif // R2GHIDRA_R2TYPECOMPAT_H
