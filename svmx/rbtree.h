#pragma once

// 取父节点地址
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

// 节点插入操作
static inline void rb_link_node(struct rb_node* node, struct rb_node* parent,
	struct rb_node** rb_link) {
	// 为新节点设置父节点
	node->__rb_parent_color = (ULONG_PTR)parent;
	// 初始化左右子树为空
	node->rb_left = node->rb_right = NULL;
	// 把父节点对应的子树指向新节点
	*rb_link = node;
}

// 节点调整
void rb_insert_color(struct rb_node*, struct rb_root*);