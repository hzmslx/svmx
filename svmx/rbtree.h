#pragma once

#define rb_parent(r)	((struct rb_node*)((r)->__rb_parent_color & ~3))

/* 'empty' nodes are nodes that are known not to be inserted in an rbtree */
#define RB_EMPTY_NODE(node) \
	((node)->__rb_parent_color == (ULONG_PTR)(node))

struct rb_node* rb_prev(const struct rb_node* node);
struct rb_node* rb_last(const struct rb_root* root);
struct rb_node* rb_next(const struct rb_node* node);
void rb_erase(struct rb_node* node, struct rb_root* root);

/* Fast replacement of a single node without remove/rebalance/add/rebalance */
extern void rb_replace_node(struct rb_node* victim, struct rb_node* new,
	struct rb_root* root);

static inline void rb_link_node(struct rb_node* node, struct rb_node* parent,
	struct rb_node** rb_link) {
	node->__rb_parent_color = (ULONG_PTR)parent;
	node->rb_left = node->rb_right = NULL;

	*rb_link = node;
}

void rb_insert_color(struct rb_node*, struct rb_root*);