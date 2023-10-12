#pragma once

#define rb_parent(r)	((struct rb_node*)((r)->__rb_parent_color & ~3))

/* 'empty' nodes are nodes that are known not to be inserted in an rbtree */
#define RB_EMPTY_NODE(node) \
	((node)->__rb_parent_color == (ULONG_PTR)(node))

struct rb_node* rb_prev(const struct rb_node* node);
struct rb_node* rb_last(const struct rb_root* root);
struct rb_node* rb_next(const struct rb_node* node);