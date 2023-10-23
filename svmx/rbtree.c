#include "pch.h"
#include "rbtree.h"
#include "rbtree_augmented.h"

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

static inline void dummy_propagate(struct rb_node* node, struct rb_node* stop) 
{
	UNREFERENCED_PARAMETER(node);
	UNREFERENCED_PARAMETER(stop);
}

static inline void dummy_copy(struct rb_node* old, struct rb_node* new) {
	UNREFERENCED_PARAMETER(old);
	UNREFERENCED_PARAMETER(new);
}
static inline void dummy_rotate(struct rb_node* old, struct rb_node* new) {
	UNREFERENCED_PARAMETER(old);
	UNREFERENCED_PARAMETER(new);
}

static const struct rb_augment_callbacks dummy_callbacks = {
	.propagate = dummy_propagate,
	.copy = dummy_copy,
	.rotate = dummy_rotate
};

/*
* Helper function for rotations:
* - old's parent and color get assigned to new
* - old gets assigned new as a parent and 'color' as a color.
*/
static inline void
__rb_rotate_set_parents(struct rb_node* old, struct rb_node* new,
	struct rb_root* root, int color) {
	struct rb_node* parent = rb_parent(old);
	new->__rb_parent_color = old->__rb_parent_color;
	rb_set_parent_color(old, new, color);
	__rb_change_child(old, new, parent, root);
}

static inline void rb_set_black(struct rb_node* rb) {
	rb->__rb_parent_color += RB_BLACK;
}

static inline void
____rb_erase_color(struct rb_node* parent,struct rb_root* root,
	void (*augment_rotate)(struct rb_node* old,struct rb_node* new)) {
	struct rb_node* node = NULL, * sibling, * tmp1, * tmp2;

	while (TRUE)
	{
		/*
		 * Loop invariants:
		 * - node is black (or NULL on first iteration)
		 * - node is not the root (parent is not NULL)
		 * - All leaf paths going through parent and node have a
		 *   black node count that is 1 lower than other leaf paths.
		 */
		sibling = parent->rb_right;
		if (node != sibling) { /* node == parent->rb_left */
			if (rb_is_red(sibling)) {
				/*
				* Case 1 - left rotate at parent
				* 
				*     P               S
				*    / \             / \
				*   N   s    -->    p   Sr
				*      / \         / \
				*     Sl  Sr      N   Sl
				*/
				tmp1 = sibling->rb_left;
				parent->rb_right = tmp1;
				sibling->rb_left = parent;
				rb_set_parent_color(tmp1, parent, RB_BLACK);
				__rb_rotate_set_parents(parent, sibling, root,
					RB_RED);
				augment_rotate(parent, sibling);
				sibling = tmp1;
			}
			tmp1 = sibling->rb_right;
			if (!tmp1 || rb_is_black(tmp1)) {
				tmp2 = sibling->rb_left;
				if (!tmp2 || rb_is_black(tmp2)) {
					/*
					 * Case 2 - sibling color flip
					 * (p could be either color here)
					 *
					 *    (p)           (p)
					 *    / \           / \
					 *   N   S    -->  N   s
					 *      / \           / \
					 *     Sl  Sr        Sl  Sr
					 *
					 * This leaves us violating 5) which
					 * can be fixed by flipping p to black
					 * if it was red, or by recursing at p.
					 * p is red when coming from Case 1.
					 */
					rb_set_parent_color(sibling, parent,
						RB_RED);
					if (rb_is_red(parent))
						rb_set_black(parent);
					else {
						node = parent;
						parent = rb_parent(node);
						if (parent)
							continue;
					}
					break;
				}

				tmp1 = tmp2->rb_right;
				sibling->rb_left = tmp1;
				tmp2->rb_right = sibling;
				parent->rb_right = tmp2;
				if (tmp1)
					rb_set_parent_color(tmp1, sibling,
						RB_BLACK);
				augment_rotate(sibling, tmp2);
				tmp1 = sibling;
				sibling = tmp2;
			}

			tmp2 = sibling->rb_left;
			parent->rb_right = tmp2;
			sibling->rb_left = parent;
			rb_set_parent_color(tmp1, sibling, RB_BLACK);
			if (tmp2)
				rb_set_parent(tmp2, parent);
			__rb_rotate_set_parents(parent, sibling, root,
				RB_BLACK);
			augment_rotate(parent, sibling);
			break;
		}
		else {
			sibling = parent->rb_left;
			if (rb_is_red(sibling)) {
				/* Case 1 - right rotate at parent */
				tmp1 = sibling->rb_right;
				parent->rb_left = tmp1;
				sibling->rb_right = parent;
				rb_set_parent_color(tmp1, parent, RB_BLACK);
				__rb_rotate_set_parents(parent, sibling, root,
					RB_RED);
				augment_rotate(parent, sibling);
				sibling = tmp1;
			}
			tmp1 = sibling->rb_left;
			if (!tmp1 || rb_is_black(tmp1)) {
				tmp2 = sibling->rb_right;
				if (!tmp2 || rb_is_black(tmp2)) {
					/* Case 2 - sibling color flip */
					rb_set_parent_color(sibling, parent,
						RB_RED);
					if (rb_is_red(parent))
						rb_set_black(parent);
					else {
						node = parent;
						parent = rb_parent(node);
						if (parent)
							continue;
					}
					break;
				}
				/* Case 3 - left rotate at sibling */
				tmp1 = tmp2->rb_left;
				sibling->rb_right = tmp1;
				tmp2->rb_left = sibling;
				parent->rb_left = tmp2;
				if (tmp1)
					rb_set_parent_color(tmp1, sibling,
						RB_BLACK);
				augment_rotate(sibling, tmp2);
				tmp1 = sibling;
				sibling = tmp2;
			}
			/* Case 4 - right rotate at parent + color flips */
			tmp2 = sibling->rb_right;
			parent->rb_left = tmp2;
			sibling->rb_right = parent;
			rb_set_parent_color(tmp1, sibling, RB_BLACK);
			if (tmp2)
				rb_set_parent(tmp2, parent);
			__rb_rotate_set_parents(parent, sibling, root,
				RB_BLACK);
			augment_rotate(parent, sibling);
			break;
		}
	}
}

void rb_erase(struct rb_node* node, struct rb_root* root) {
	struct rb_node* rebalance;
	rebalance = __rb_erase_augmented(node, root, &dummy_callbacks);
	if (rebalance)
		____rb_erase_color(rebalance, root, dummy_rotate);
}