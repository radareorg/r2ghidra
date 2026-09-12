// SPDX-FileCopyrightText: 2026 pancake
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef R2GHIDRA_R2FLAGCOMPAT_H
#define R2GHIDRA_R2FLAGCOMPAT_H

#include <r_flag.h>
#include <r_lib.h>

template<typename Predicate>
static RFlagItem *r2ghidra_flag_find_at(RFlag *flags, ut64 addr, const Predicate &predicate) {
	// The vector API landed in 6.2.3-dev while the ABI was still 142. Keep the
	// feature check so those snapshots remain distinguishable from 6.2.2.
#if R2_ABIVERSION >= 143 || defined(r_flag_item_vec_foreach)
	const RVecFlagItemPtr *items = r_flag_get_vec (flags, addr);
	RFlagItem **iter;
	RFlagItem *item;
	r_flag_item_vec_foreach (items, iter, item) {
#else
	const RList *items = r_flag_get_list (flags, addr);
	RListIter *iter;
	void *pos;
	r_list_foreach (items, iter, pos) {
		RFlagItem *item = reinterpret_cast<RFlagItem *>(pos);
#endif
		if (predicate (item)) {
			return item;
		}
	}
	return nullptr;
}

#endif // R2GHIDRA_R2FLAGCOMPAT_H
