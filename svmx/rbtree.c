#include "pch.h"
#include "rbtree.h"

#pragma warning(push)
#pragma warning(disable:4706)
struct rb_node* rb_prev(const struct rb_node* node) {
	struct rb_node* parent;

	if (RB_EMPTY_NODE(node))
		return NULL;

	/*
	* If we have a left-hand child, go down and then right as far
	* as we can.
	*/
	if (node->rb_left) {
		node = node->rb_left;
		while (node->rb_right)
			node = node->rb_right;
		return (struct rb_node*)node;
	}

	/*
	* No left-hand children. Go up till we find an ancestor which
	* is a right-hand child of its parent.
	*/
	while ((parent = rb_parent(node)) && node == parent->rb_left)
		node = parent;

	return parent;
}
#pragma warning(pop)

struct rb_node* rb_last(const struct rb_root* root) {
	struct rb_node* n;

	n = root->rb_node;
	if (!n)
		return NULL;
	while (n->rb_right)
		n = n->rb_right;
	return n;
}

#pragma warning(push)
#pragma warning(disable:4706)
struct rb_node* rb_next(const struct rb_node* node) {
	struct rb_node* parent;

	if (RB_EMPTY_NODE(node))
		return NULL;

	/*
	* If we have a right-hand child, go down and then left as far
	* as we can.
	*/
	if (node->rb_right) {
		node = node->rb_right;
		while (node->rb_left)
			node = node->rb_left;
		return (struct rb_node*)node;
	}

	/*
	* No right-hand children. Everything down and left is smaller than us,
	* so any 'next' node must be in the general direction of our parent.
	* Go up the tree; any time the ancestor is a right-hand child of its
	* parent, keep going up. First time it's a left-hand child of its
	* parent, said parent is our 'next' node.
	*/
	while ((parent = rb_parent(node)) && node == parent->rb_right)
		node = parent;

	return parent;
}
#pragma warning(pop)