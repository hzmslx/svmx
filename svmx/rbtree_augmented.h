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

// 设置节点颜色
static inline void rb_set_parent_color(struct rb_node* rb,
	struct rb_node* p, int color) {
	rb->__rb_parent_color = (ULONG_PTR)p + color;
}

// 更换孩子结点
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
	// 待删除结点的右孩子
	struct rb_node* child = node->rb_right;
	// 待删除结点的左孩子
	struct rb_node* tmp = node->rb_left;
	struct rb_node* parent = NULL, * rebalance = NULL;
	ULONG_PTR pc;

	if (!tmp) { /* 待删除结点无左孩子 */
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
			* 待删除结点仅有右孩子，
			* 由性质5推出右孩子必为红色结点
			* 由性质4，进一步推出待删除结点的颜色为黑色
			* 将右孩子的颜色设置为node结点的颜色，即黑色
			*/
			child->__rb_parent_color = pc;
			/*
			* 此时红黑树不需要再进行平衡操作
			*/ 
			rebalance = NULL;
		}
		else {
			/*
			* 走到这里意味着待删除结点没有孩子结点
			* 1.如果待删除结点为黑色，破坏了性质5，需要再平衡
			* 2.如果待删除结点为红色，那么删除后不会违反性质5，
			* 不需要进行平衡操作
			*/ 
			rebalance = __rb_is_black(pc) ? parent : NULL;
		}
		tmp = parent;
	}
	else if (!child) { // 待删除结点仅有左孩子
		/*
		* Still case 1, but this time the child is node->rb_left 
		* 由性质5可推出，左孩子为红色结点
		* 由性质4可知，待删除结点颜色为黑色
		*/
		// 将左孩子颜色设置为黑色
		// 左孩子的父节点修改为待删除结点的父节点
		tmp->__rb_parent_color = pc = node->__rb_parent_color;
		// 获得待删除结点的父节点地址
		parent = __rb_parent(pc);
		// 修改其子节点为待删除结点的左孩子
		__rb_change_child(node, tmp, parent, root);
		// 替代后不再需要进行平衡操作
		rebalance = NULL;
		tmp = parent;
	}
	else {
		/*
		* 待删除结点存在左右孩子,需要确定待删除结点的直接后继
		* 也就是右子树中值最小的结点，
		* 换句话说就是右子树中第一个被访问的结点
		* 找到后用以替代待删除结点，然后再删除直接后继
		*/
		struct rb_node* successor = child, * child2 = NULL;

		tmp = child->rb_left;
		if (!tmp) { // 后继结点就是待删除结点的右孩子
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
			// child2为直接后继的右孩子
			child2 = successor->rb_right;

			augment->copy(node, successor);
		}
		else {
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
			// child2为直接后继的右孩子
			child2 = successor->rb_right;

			/*
			* 在二叉排序树中删除直接后继结点
			*/ 
			parent->rb_left = child2;

			// 直接后继的右孩子设置为待删除结点的右孩子
			successor->rb_right = child;

			// 直接后继成为待删除结点的右孩子的双亲结点
			rb_set_parent(child, successor);

			augment->copy(node, successor);
			augment->propagate(parent, successor);
		}

		/* 获取待删除结点的左孩子 */
		tmp = node->rb_left;
		// 直接后继的左孩子修改为待删除结点的左孩子
		successor->rb_left = tmp;
		// 设置待删除结点的左孩子的双亲结点为直接后继
		rb_set_parent(tmp, successor);

		/* 获取待删除结点的双亲结点 */
		pc = node->__rb_parent_color;
		tmp = __rb_parent(pc);
		/*
		* 将直接后继连接到待删除结点的父节点上
		*/
		__rb_change_child(node, successor, tmp, root);

		if (child2) { // 直接后继有右孩子
			/*
			* 由性质5可知,该右孩子为红色；由性质4可知,直接后继是黑色
			* 直接后继被删除后，违反性质5，因此需将右孩子设置为黑色
			*/
			rb_set_parent_color(child2, parent, RB_BLACK);
			// 至此达到平衡，不需要进一步平衡处理
			rebalance = NULL;
		}
		else {
			/*
			* 若直接后继为黑色结点，删掉一个黑色结点将违反性质5
			* 需要进行红黑树的平衡操作
			* 
			* 替换的情况下，如果直接后继是红色，对平衡无影响
			* 如果直接后继为黑色，右子树将不平衡，因此需要平衡处理
			*/
			rebalance = rb_is_black(successor) ? parent : NULL;
		}
		// 直接后继的双亲设置为待删除结点的双亲
		successor->__rb_parent_color = pc;
		tmp = successor;
	}

	augment->propagate(tmp, NULL);
	// 待平衡的结点
	return rebalance;
}