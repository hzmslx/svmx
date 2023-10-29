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

// 扩展旋转函数
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
	// 获取old的父节点
	struct rb_node* parent = rb_parent(old);

	new->__rb_parent_color = old->__rb_parent_color;
	rb_set_parent_color(old, new, color);
	// 把父节点的孩子结点old替换成new
	__rb_change_child(old, new, parent, root);
}

static inline void rb_set_black(struct rb_node* rb) {
	rb->__rb_parent_color += RB_BLACK;
}

/* @parent: 待平衡结点， root是红黑树的根节点 */
static inline void
____rb_erase_color(struct rb_node* parent, struct rb_root* root,
	void (*augment_rotate)(struct rb_node* old, struct rb_node* new)) {
	NT_ASSERT(parent != NULL);
	struct rb_node* node = NULL, * sibling, * tmp1, * tmp2;


	while (TRUE)
	{
		/*
		 * Loop invariants:（循环条件）
		 * - node is black (or NULL on first iteration)
		 * - node is not the root (parent is not NULL)
		 * - All leaf paths going through parent and node have a
		 *   black node count that is 1 lower than other leaf paths.
		 *   （所有经过parent和node结点的路径中的黑色结点数量比其他路径都少1个）
		 */
		sibling = parent->rb_right;
		if (node != sibling) { /* node == parent->rb_left */
			// 删除左子结点将导致不平衡
			if (rb_is_red(sibling)) {// 右孩子为红色
				/*
				* Case 1 - left rotate at parent
				*
				*     P               S
				*    / \             / \
				*   N   s    -->    p   Sr
				*      / \         / \
				*     Sl  Sr      N   Sl
				*/
				/*
				* 因为s为红色，根据性质4，Sl和Sr必为黑色
				* 进行左旋操作
				*/
				tmp1 = sibling->rb_left;
				parent->rb_right = tmp1;
				sibling->rb_left = parent;
				// 将Sl的父节点设置为p,Sl的颜色为黑色
				rb_set_parent_color(tmp1, parent, RB_BLACK);
				// 节点p由黑转红，结点s由红转黑
				__rb_rotate_set_parents(parent, sibling, root,
					RB_RED);

				augment_rotate(parent, sibling);
				sibling = tmp1;
			}
			/*
			* 如果经过上面的if处理，则待平衡结点已为红色
			* Sl为黑色
			*
			* 否则，带平衡结点的右孩子(S)本身就为黑色，此时待平衡结点
			* 的颜色未知
			*/
			tmp1 = sibling->rb_right;
			if (!tmp1 || rb_is_black(tmp1)) {
				// 以下处理Sr为空或者黑色的情况
				tmp2 = sibling->rb_left;
				// 如果Sl是空或者黑色
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
					 // S -> s
					rb_set_parent_color(sibling, parent,
						RB_RED);
					if (rb_is_red(parent)) {
						/*
						*		 p			 P
						*		/ \			/ \
						*	   N   s  -->  N   s
						*	      / \         / \
						*        Sl  Sr      Sl  Sr
						*/
						// 违反性质4，所以 p -> P, 达到平衡
						rb_set_black(parent);
					}
					else {
						/*
						* 如果待平衡结点已经是黑色，则不能简单的将
						* 其颜色设置为红色，
						* 这可能与其父节点的颜色一样，违反性质4
						*/
						// 将待平衡结点设置为node
						node = parent;
						// 取出其父结点
						parent = rb_parent(node);
						/*
						* 如果存在父结点则跳回函数进行调整
						*/
						if (parent)
							continue;
						// 如果待平衡结点已经是树根了，则不需要处理
					}
					break;
				}

				/*
				* 以下表明sl存在且为红色
				* Sr为空或者黑色
				* 由性质4可知,S为黑色
				*/
				/*
				 * Case 3 - right rotate at sibling
				 * (p could be either color here)
				 *
				 *   (p)           (p)
				 *   / \           / \
				 *  N   S    -->  N   sl
				 *     / \             \
				 *    sl  Sr            S
				 *                       \
				 *                        Sr
				 *
				 * Note: p might be red, and then both
				 * p and sl are red after rotation(which
				 * breaks property 4). This is fixed in
				 * Case 4 (in __rb_rotate_set_parents()
				 *         which set sl the color of p
				 *         and set p RB_BLACK)
				 *
				 *   (p)            (sl)
				 *   / \            /  \
				 *  N   sl   -->   P    S
				 *       \        /      \
				 *        S      N        Sr
				 *         \
				 *          Sr
				 */

				 /*
				 *   (p)           (p)
				 *   / \           / \
				 *  N   S    -->  N   sl
				 *     / \             \
				 *    sl  Sr            S
				 *      \			   / \
				 *       X            X  Sr
				 *
				 */
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
			/*
			 * Case 4 - left rotate at parent + color flips
			 * (p and sl could be either color here.
			 *  After rotation, p becomes black, s acquires
			 *  p's color, and sl keeps its color)
			 *
			 *      (p)             (s)
			 *      / \             / \
			 *     N   S     -->   P   Sr
			 *        / \         / \
			 *      (sl) sr      N  (sl)
			 */

			tmp2 = sibling->rb_left;
			parent->rb_right = tmp2;
			sibling->rb_left = parent;
			// 设置Sr为黑色
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
			// 兄弟结点为红色
			if (rb_is_red(sibling)) {
				/* Case 1 - right rotate at parent */
				/*
				*		P            S
				*      / \          / \
				*	  s   N   ->  SL   p
				*    / \              / \
				*   SL SR            SR  N
				*/
				tmp1 = sibling->rb_right;
				parent->rb_left = tmp1;
				sibling->rb_right = parent;
				// 设置tmp1的颜色和父节点
				rb_set_parent_color(tmp1, parent, RB_BLACK);
				__rb_rotate_set_parents(parent, sibling, root,
					RB_RED);

				augment_rotate(parent, sibling);
				sibling = tmp1;
			}
			/* 获取兄弟节点的左孩子 */
			tmp1 = sibling->rb_left;
			// 兄弟节点没有左孩子或者左孩子是黑色
			if (!tmp1 || rb_is_black(tmp1)) {
				// 兄弟节点的右孩子
				tmp2 = sibling->rb_right;
				// 右孩子不存在或者右孩子是黑色
				if (!tmp2 || rb_is_black(tmp2)) {
					/* Case 2 - sibling color flip */
					// 设置兄弟节点为红色
					rb_set_parent_color(sibling, parent,
						RB_RED);
					NT_ASSERT(parent != NULL);
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
				/*
				*		P            P
				*	   / \          / \
				*	  S   N   ->   sr  N
				*      \          /
				*       sr       S
				*		/		  \
				*	   X		   X
				*/
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
			/*
			*			P             S
			*		   / \           / \
			*         S   N     ->  SL  P
			*		 / \               / \
			*       sl  sr            sr  N
			*/
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

// 删除红黑树结点
void rb_erase(struct rb_node* node, struct rb_root* root) {
	struct rb_node* rebalance;
	// 二叉排序树的删除
	rebalance = __rb_erase_augmented(node, root, &dummy_callbacks);
	if (rebalance) // 恢复红黑树的特性
		____rb_erase_color(rebalance, root, dummy_rotate);
}

void rb_replace_node(struct rb_node* victim, struct rb_node* new,
	struct rb_root* root) {
	struct rb_node* parent = rb_parent(victim);

	/* Copy the pointers/colour from the victim to the replacement */
	*new = *victim;

	/* Set the surrounding nodes to point to the replacement */
	if (victim->rb_left)
		rb_set_parent(victim->rb_left, new);
	if (victim->rb_right)
		rb_set_parent(victim->rb_right, new);
	__rb_change_child(victim, new, parent, root);
}

// 求红节点父节点，因为红色表示颜色的位是0.
static inline struct rb_node* rb_red_parent(struct rb_node* red) {
	return (struct rb_node*)red->__rb_parent_color;
}

/*
* 插入节点后旋转和颜色调整的内部函数
*/
static inline void
__rb_insert(struct rb_node* node, struct rb_root* root,
	void (*augment_rotate)(struct rb_node* old, struct rb_node* new)) {
	
	struct rb_node* parent = rb_red_parent(node), * gparent, * tmp;

	while (TRUE)
	{
		/*
		* Loop invariant: node is red.(node是红色节点）
		*/
		if (!parent) {
			/*
			* The inserted node is root. Either this is the
			* first node, or we recursed at Case 1 below and
			* are no longer violating 4).
			*/
			rb_set_parent_color(node, NULL, RB_BLACK);
			break;
		}

		// 父节点是黑色，插入一个红色结点，不会破坏平衡
		/*
		* If there is a black parent, we are done.
		* Otherwise, take some corrective action as,
		* per 4), we don't want a red root or two 
		* consecutive red nodes.
		*/
		if (rb_is_black(parent))
			break;

		// parent这里一定是红色节点,
		// 由性质4可知,gparent一定是黑色
		gparent = rb_red_parent(parent);

		tmp = gparent->rb_right;
		if (parent != tmp) {
			if (tmp && rb_is_red(tmp)) {
				/*
				* Case 1 - node's uncle is red (color flips).
				*
				*		G			g
				*      / \         / \
				*     p   u  -->  P   U
				*    /           /
				*   n           n
				*
				* However, since g's parent might be red, and
				* 4) does not allow this, we need to recurse
				* at g.
				*/
				rb_set_parent_color(tmp, gparent, RB_BLACK);
				rb_set_parent_color(parent, gparent, RB_BLACK);

				// 递归向上新一轮处理
				node = gparent;
				parent = rb_parent(node);
				rb_set_parent_color(node, parent, RB_RED);
				continue;
			}

			tmp = parent->rb_right;
			if (node == tmp) {
				/*
				* Case 2 - node's uncle is black and node is
				* the parent's right child (left rotate at parent).
				*		G			G
				*	   / \         / \
				*     p   U       n   U
				*      \         / 
				*       n       p
				* This still leaves us in violation 4), the
				* continuation into Case 3 will fix that.
				*/
				tmp = node->rb_left;
				parent->rb_right = tmp;
				node->rb_left = parent;
				if (tmp)
					rb_set_parent_color(tmp, parent,
						RB_BLACK);
				rb_set_parent_color(parent, node, RB_RED);
				augment_rotate(parent, node);
				parent = node;
				tmp = node->rb_right;
			}

			/*
			* Case 3 - node's uncle is black and node is
			* the parent's left child (right rotate at gparent)
			* 
			*		G			P
			*      / \         / \
			*     p   U  -->  n   g
			*    /                 \
			*   n                   U
			*/
			gparent->rb_left = tmp;
			parent->rb_right = gparent;
			if (tmp)
				rb_set_parent_color(tmp, gparent, RB_BLACK);
			__rb_rotate_set_parents(gparent, parent, root, RB_RED);
			augment_rotate(gparent, parent);
			break;
		}
		else {
			tmp = gparent->rb_left;
			if (tmp && rb_is_red(tmp)) {
				/* Case 1 - color flips */
				rb_set_parent_color(tmp, gparent, RB_BLACK);
				rb_set_parent_color(parent, gparent, RB_BLACK);
				node = gparent;
				parent = rb_parent(node);
				rb_set_parent_color(node, parent, RB_RED);
				continue;
			}

			tmp = parent->rb_left;
			if (node == tmp) {
				/* Case 2 - right rotate at parent */
				tmp = node->rb_right;
				parent->rb_left = tmp;
				node->rb_right= parent;
				if (tmp)
					rb_set_parent_color(tmp, parent,
						RB_BLACK);
				rb_set_parent_color(parent, node, RB_RED);
				augment_rotate(parent, node);
				parent = node;
				tmp = node->rb_left;
			}

			/* Case 3 - left rotate at gparent */
			gparent->rb_right = tmp; /* == parent->rb_left */
			parent->rb_left = gparent;
			if (tmp)
				rb_set_parent_color(tmp, gparent, RB_BLACK);
			__rb_rotate_set_parents(gparent, parent, root, RB_RED);
			augment_rotate(gparent, parent);
			break;
		}
	}
}

// 对于插入的节点进行旋转和颜色调整
void rb_insert_color(struct rb_node* node, struct rb_root* root) {
	// 约定新插入的节点是红色的，减少处理情形
	__rb_insert(node, root, dummy_rotate);
}