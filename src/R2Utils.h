// SPDX-FileCopyrightText: 2019-2023 thestr4ng3r, pancake
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef R2GHIDRA_R2UTILS_H
#define R2GHIDRA_R2UTILS_H

#include <r_anal.h>
#include <r_lib.h>

typedef struct r_list_t RList;
typedef struct r_list_iter_t RListIter;

static inline bool r_anal_function_is_noreturn_cpp(const RAnalFunction *function) {
#if R2_ABIVERSION >= 183
	return (function->attrs & R_ANAL_FCN_ATTR_NORETURN) != 0;
#else
	return function->is_noreturn;
#endif
}

#if R2_ABIVERSION >= 163
static inline bool r_anal_function_is_inline_cpp(RAnalFunction *function) {
#if R2_ABIVERSION >= 183
	return (function->attrs & R_ANAL_FCN_ATTR_INLINE) != 0;
#else
	return r_anal_function_is_inline (function);
#endif
}
#endif

template<typename T, typename F> void r_list_foreach_cpp(RList *list, const F &cb) {
	for (RListIter *it = list->head; it; it = it->n) {
		cb (reinterpret_cast<T *>(it->data));
	}
}

template<typename F> void r_anal_function_bbs_foreach_cpp(RAnalFunction *function, const F &cb) {
#if R2_ABIVERSION >= 168
	RAnalBlock **it;
	R_VEC_FOREACH (&function->bbs, it) {
		cb (*it);
	}
#else
	r_list_foreach_cpp<RAnalBlock> (function->bbs, cb);
#endif
}

template<typename T, typename F> void r_interval_tree_foreach_cpp(RIntervalTree *tree, const F &cb) {
	RIntervalTreeIter it;
	for (it = r_rbtree_first (&(tree)->root->node); r_rbtree_iter_has (&it); r_rbtree_iter_next (&(it))) {
		RIntervalNode *node = r_interval_tree_iter_get (&it);
		cb (node, reinterpret_cast<T *>(node->data));
	}
}

static inline std::string tolower(std::string str) {
	std::transform (str.begin (), str.end (), str.begin (), [](unsigned char c) {
		return static_cast<char>(std::tolower (c));
	});
	return str;
}

static inline std::string hex(ut64 v) {
	std::stringstream ss;
	ss << "0x" << std::hex << v;
	return ss.str ();
}

static inline ghidra::Element *child(ghidra::Element *el, const std::string &name, const std::map<std::string, std::string> &attrs = {}) {
	auto c = new ghidra::Element (el);
	c->setName (name);
	el->addChild (c);
	for (const auto &attr : attrs) {
		c->addAttribute (attr.first, attr.second);
	}
	return c;
}

#endif
