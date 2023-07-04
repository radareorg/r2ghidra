/* r2ghidra - LGPL - Copyright 2019-2023 - thestr4ng3r, pancake */

#ifndef R2GHIDRA_R2UTILS_H
#define R2GHIDRA_R2UTILS_H

typedef struct r_list_t RList;
typedef struct r_list_iter_t RListIter;

template<typename T, typename F> void r_list_foreach_cpp(RList *list, const F &cb) {
	for (RListIter *it = list->head; it; it = it->n) {
		cb (reinterpret_cast<T *>(it->data));
	}
}

template<typename T, typename F> void r_interval_tree_foreach_cpp(RIntervalTree *tree, const F &cb) {
	RIntervalTreeIter it;
	for (it = r_rbtree_first (&(tree)->root->node); r_rbtree_iter_has (&it); r_rbtree_iter_next (&(it))) {
		RIntervalNode *node = r_interval_tree_iter_get (&it);
		cb (node, reinterpret_cast<T *>(node->data));
	}
}

static inline std::string tolower(std::string str) {
	std::transform (str.begin (), str.end (), str.begin (), [](int c) {
		return tolower (c);
	});
	return str;
}

#endif
