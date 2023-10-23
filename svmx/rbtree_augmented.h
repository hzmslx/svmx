#pragma once

struct rb_augment_callbacks {
	void (*propagate)(struct rb_node* node, struct rb_node* stop);
	void (*copy)(struct rb_node* old, struct rb_node* new);
	void (*rotate)(struct rb_node* old, struct rb_node* new);
};

#define RB_RED		0
#define RB_BLACK	1

#define __rb_parent(pc)		((struct rb_node*)(pc & ~3))

#define __rb_color(pc)		((pc) & 1)
#define __rb_is_black(pc)	__rb_color(pc)
#define __rb_is_red(pc)		(!__rb_color(pc))
#define rb_color(rb)		__rb_color((rb)->__rb_parent_color)
#define rb_is_red(rb)		__rb_is_red((rb)->__rb_parent_color)
#define rb_is_black(rb)		__rb_is_black((rb)->__rb_parent_color)

static inline void rb_set_parent(struct rb_node* rb, struct rb_node* p)
{
	rb->__rb_parent_color = rb_color(rb) + (ULONG_PTR)p;
}

static inline void rb_set_parent_color(struct rb_node* rb,
	struct rb_node* p, int color) {
	rb->__rb_parent_color = (ULONG_PTR)p + color;
}

static inline void
__rb_change_child(struct rb_node* old, struct rb_node* new,
	struct rb_node* parent, struct rb_root* root) {
	if (parent) {
		if (parent->rb_left == old)
			parent->rb_left = new;
		else
			parent->rb_right = new;
	}
	else {
		root->rb_node = new;
	}
}

static struct rb_node*
__rb_erase_augmented(struct rb_node* node, struct rb_root* root,
	const struct rb_augment_callbacks* augment) {
	struct rb_node* child = node->rb_right;
	struct rb_node* tmp = node->rb_left;
	struct rb_node* parent = NULL, * rebalance = NULL;
	ULONG_PTR pc;

	if (!tmp) {
		/*
		* Case 1: node to earse has no more than 1 child (easy!)
		* 
		* Note that if there is one child it must be red due to 5)
		* and node must be black due to 4). We adjust colors locally
		* so as to bypass __rb_erase_color() later on.
		*/
		pc = node->__rb_parent_color;
		parent = __rb_parent(pc);
		__rb_change_child(node, child, parent, root);
		if (child) {
			child->__rb_parent_color = pc;
			rebalance = NULL;
		}
		else {
			rebalance = __rb_is_black(pc) ? parent : NULL;
		}
		tmp = parent;
	}
	else if (!child) {
		/* Still case 1, but this time the child is node->rb_left */
		tmp->__rb_parent_color = pc = node->__rb_parent_color;
		parent = __rb_parent(pc);
		__rb_change_child(node, tmp, parent, root);
		rebalance = NULL;
		tmp = parent;
	}
	else {
		struct rb_node* successor = child, * child2 = NULL;

		tmp = child->rb_left;
		if (!tmp) {
			/*
			* Case 2: node's successor is its right child
			* 
			*     (n)		   (s)
			*	 /   \	      /   \
			*  (x)   (y) -> (x)	  (y)
			*		/             /
			*     (p)           (p)
			*     /             /
			*   (s)	          (c)
			*	  \
			*     (c)
			*/
			do
			{
				parent = successor;
				successor = tmp;
				tmp = tmp->rb_left;
			} while (tmp);
			child2 = successor->rb_right;
			parent->rb_left = child2;
			successor->rb_right = child;
			rb_set_parent(child, successor);

			augment->copy(node, successor);
			augment->propagate(parent, successor);
		}

		tmp = node->rb_left;
		successor->rb_left = tmp;
		rb_set_parent(tmp, successor);

		pc = node->__rb_parent_color;
		tmp = __rb_parent(pc);
		__rb_change_child(node, successor, tmp, root);

		if (child2) {
			rb_set_parent_color(child2, parent, RB_BLACK);
			rebalance = NULL;
		}
		else {
			rebalance = rb_is_black(successor) ? parent : NULL;
		}
		successor->__rb_parent_color = pc;
		tmp = successor;
	}

	augment->propagate(tmp, NULL);
	return rebalance;
}