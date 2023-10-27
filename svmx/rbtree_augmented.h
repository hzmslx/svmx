#pragma once

/*
* 增强型红黑树是一种在每个结点里存储了“一些”附加数据的红黑树
*/
struct rb_augment_callbacks {
	void (*propagate)(struct rb_node* node, struct rb_node* stop);
	void (*copy)(struct rb_node* old, struct rb_node* new);
	void (*rotate)(struct rb_node* old, struct rb_node* new);
};

#define RB_RED		0
#define RB_BLACK	1

// 获得双亲结点的地址
#define __rb_parent(pc)		((struct rb_node*)(pc & ~3))

// 获得颜色属性
#define __rb_color(pc)		((pc) & 1)
#define __rb_is_black(pc)	__rb_color(pc)
#define __rb_is_red(pc)		(!__rb_color(pc))
#define rb_color(rb)		__rb_color((rb)->__rb_parent_color)
// 判断颜色属性是否为红色
#define rb_is_red(rb)		__rb_is_red((rb)->__rb_parent_color)
// 判断颜色属性是否为黑色
#define rb_is_black(rb)		__rb_is_black((rb)->__rb_parent_color)

// 设置结点的双亲结点的首地址和颜色
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
	// 待删除结点的右子树
	struct rb_node* child = node->rb_right;
	// 待删除结点的左子树
	struct rb_node* tmp = node->rb_left;
	struct rb_node* parent = NULL, * rebalance = NULL;
	ULONG_PTR pc;

	if (!tmp) { /* 待删除结点无左子树 */
		/*
		* Case 1: node to earse has no more than 1 child (easy!)
		* 
		* Note that if there is one child it must be red due to 5)
		* and node must be black due to 4). We adjust colors locally
		* so as to bypass __rb_erase_color() later on.
		*/
		pc = node->__rb_parent_color;
		parent = __rb_parent(pc);
		/*
		* 让node的右子树成为node父节点的子树，替代node的位置
		* 二叉排序树的特性不变
		*/ 
		__rb_change_child(node, child, parent, root);
		if (child) {
			/*
			* 待删除结点仅有右子树，由性质5推出右子树必为红色结点
			* 由性质4，进一步推出待删除结点的颜色为黑色
			* 将右子树的颜色设置为node结点的颜色，即黑色
			*/
			child->__rb_parent_color = pc;
			/*
			* 此时红黑树不需要再进行平衡操作
			*/ 
			rebalance = NULL;
		}
		else {
			/*
			* 待删除结点无右子树，
			* 1.如果待删除结点为黑色，那么删除后可能会不满足性质5，
			* 所以需要再平衡
			* 2.如果待删除结点为红色，那么删除后不会违反性质5，
			* 不需要进行平衡操作
			*/ 
			rebalance = __rb_is_black(pc) ? parent : NULL;
		}
		tmp = parent;
	}
	else if (!child) { // 待删除结点仅有左子树
		/*
		* Still case 1, but this time the child is node->rb_left 
		* 由性质5可推出，左子树为红色结点
		* 由性质4可知，待删除结点颜色为黑色
		*/
		// 将左子树颜色设置为黑色
		tmp->__rb_parent_color = pc = node->__rb_parent_color;
		// 删除结点
		parent = __rb_parent(pc);
		__rb_change_child(node, tmp, parent, root);
		// 删除后不再需要进行平衡操作
		rebalance = NULL;
		tmp = parent;
	}
	else {
		/*
		* 待删除结点存在左右子树,需要确定待删除结点的直接后继 
		* 找到后用以替代待删除结点，然后再删除直接后继
		* 
		*/
		struct rb_node* successor = child, * child2 = NULL;

		tmp = child->rb_left;
		if (!tmp) { // 后继结点没有左子树
			/*
			* Case 2: node's successor is its right child
			* 
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
			
			// 此处使用parent记录下直接后继，并未实际执行替换操作
			parent = successor;
			// child2为直接后继的右子树
			child2 = successor->rb_right;

			augment->copy(node, successor);
		}
		else {// 后继结点的左子树非空
			/*
			 * Case 3: node's successor is leftmost under
			 * node's right child subtree
			 *
			 *    (n)          (s)
			 *    / \          / \
			 *  (x) (y)  ->  (x) (y)
			 *      /            /
			 *    (p)          (p)
			 *    /            /
			 *  (s)          (c)
			 *    \
			 *    (c)
			 */
			/*
			* 找到待删除结点右子树中最左下的结点
			*/
			do
			{
				parent = successor;
				successor = tmp;
				tmp = tmp->rb_left;
			} while (tmp);
			// child2为直接后继的右子树
			child2 = successor->rb_right;

			parent->rb_left = child2;

			successor->rb_right = child;

			rb_set_parent(child, successor);

			augment->copy(node, successor);
			augment->propagate(parent, successor);
		}

		/* 将N的左子树移植到S结点 */
		tmp = node->rb_left;
		successor->rb_left = tmp;
		rb_set_parent(tmp, successor);

		/* N的父节点与S建立关系 */
		pc = node->__rb_parent_color;
		tmp = __rb_parent(pc);
		__rb_change_child(node, successor, tmp, root);

		if (child2) { // 直接后继有右子树
			rb_set_parent_color(child2, parent, RB_BLACK);
			rebalance = NULL;
		}
		else {
			/*
			* 若直接后继为黑色结点，删掉一个黑色结点将违反性质5
			* 需要进行红黑树的平衡操作
			*/
			rebalance = rb_is_black(successor) ? parent : NULL;
		}
		successor->__rb_parent_color = pc;
		tmp = successor;
	}

	augment->propagate(tmp, NULL);
	return rebalance;
}