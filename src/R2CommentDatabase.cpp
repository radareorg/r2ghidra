/* r2ghidra - LGPL - Copyright 2019-2021 - thestr4ng3r, pancake */

#include "R2CommentDatabase.h"
#include "R2Architecture.h"

#include <r_core.h>

R2CommentDatabase::R2CommentDatabase(R2Architecture *arch) : arch (arch), cache_filled (false) {
}

void R2CommentDatabase::fillCache(const Address &fad) const {
	RCoreLock core(arch->getCore());

	RAnalFunction *fcn = r_anal_get_function_at(core->anal, fad.getOffset());
	if (fcn == nullptr) {
		RList *fcns = r_anal_get_functions_in (core->anal, fad.getOffset());
		if (!r_list_empty (fcns)) {
			fcn = reinterpret_cast<RAnalFunction *>(r_list_first (fcns));
		}
		r_list_free (fcns);
		if (fcn == nullptr) {
			return;
		}
	}
	ut64 min_addr = r_anal_function_min_addr (fcn);
	ut64 size = r_anal_function_linear_size (fcn);
	if (size < 1) {
		return;
	}
	RVecIntervalNodePtr *nodes = r_meta_get_all_intersect (core->anal, min_addr, size, R_META_TYPE_COMMENT);
	if (nodes) {
		RIntervalNode **it;
		R_VEC_FOREACH (nodes, it) {
			RIntervalNode *node = *it;
			RAnalMetaItem *meta = reinterpret_cast<RAnalMetaItem *>(node->data);
			if (!meta || !meta->str) {
				continue;
			}
			if (!r_anal_function_contains (fcn, node->start)) {
				continue;
			}
			cache.addCommentNoDuplicate (
				Comment::user2, fad, Address (arch->getDefaultCodeSpace (), node->start), meta->str);
			// cache.addComment (Comment::header, fad, Address (arch->getDefaultCodeSpace (), node->start), meta->str);
		}
		RVecIntervalNodePtr_free (nodes);
	}
	cache_filled = true;
}

void R2CommentDatabase::clear() {
	cache.clear ();
	cache_filled = false;
}

void R2CommentDatabase::clearType(const Address &fad, uint4 tp) {
	cache.clearType (fad, tp);
}

void R2CommentDatabase::addComment(uint4 tp, const Address &fad, const Address &ad, const string &txt) {
	cache.addComment (tp, fad, ad, txt);
}

bool R2CommentDatabase::addCommentNoDuplicate(uint4 tp, const Address &fad, const Address &ad, const string &txt) {
	return cache.addCommentNoDuplicate (tp, fad, ad, txt);
}

CommentSet::const_iterator R2CommentDatabase::beginComment(const Address &fad) const {
	fillCache (fad);
	return cache.beginComment (fad);
}

CommentSet::const_iterator R2CommentDatabase::endComment(const Address &fad) const {
	return cache.endComment (fad);
}
