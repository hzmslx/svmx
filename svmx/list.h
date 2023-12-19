#pragma once
#include "pch.h"


#define HLIST_HEAD_INIT {.first = NULL }
#define HLIST_HEAD(name) struct hlist_head name = {.first = NULL}
#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)
static inline void INIT_HLIST_NODE(struct hlist_node* h)
{
	h->next = NULL;
	h->pprev = NULL;
}

// 判断结点是否一级在hash表中
static inline int hlist_unhashed(const struct hlist_node* h)
{
	return !h->pprev;
}

static inline void __hlist_del(struct hlist_node* n)
{
	// 获取指向待删除结点的下一个普通结点的指针
	struct hlist_node* next = n->next;
	// 获取待删除节点的pprev域
	struct hlist_node** pprev = n->pprev;

	// 令其指向下一个节点
	*pprev = next;
	if (next) // 如果该节点不为空
		next->pprev = pprev;
}

static inline void hlist_del(struct hlist_node* n) {
	__hlist_del(n);
	n->next = NULL;
	n->pprev = NULL;
}

#define hlist_entry(ptr,type,member) CONTAINING_RECORD(ptr,type,member)

#define hlist_entry_safe(ptr,type,member) \
	(  \
	   ptr ? hlist_entry(ptr,type, member) : NULL \
	)

// 将结点n插在头结点h之后
static inline void hlist_add_head(struct hlist_node* n, struct hlist_head* h)
{
	struct hlist_node* first = h->first;
	// 指向下一个结点或NULL
	n->next = first;
	// first指向非空，则后继结点的pprev指向前驱结点的next地址
	if (first)
		first->pprev = &n->next;
	h->first = n;
	n->pprev = &h->first;
}

// 将结点n插在next结点的前面
static inline void hlist_add_before(struct hlist_node* n,
	struct hlist_node* next) {
	n->pprev = next->pprev;
	n->next = next;
	next->pprev = &n->next;
	*(n->pprev) = n;
}

/*
* add a new entry after the one specified
* @n: new entry to be added
* @prev: hlist node to add it after, which must be non-NULL
*/
static inline void hlist_add_behind(struct hlist_node* n,
	struct hlist_node* prev) {
	n->next = prev->next;
	prev->next = n;
	n->pprev = &prev->next;

	if (n->next)
		n->next->pprev = &n->next;
}

/*
* Is the specified hlist_head structure an empty hlist ?
* @h: Sturcture to check.
*/ 
static inline int hlist_empty(const struct hlist_head* h)
{
	return !h->first;
}

static inline void hlist_del_init(struct hlist_node* n)
{
	if (!hlist_unhashed(n)) {
		__hlist_del(n);
		INIT_HLIST_NODE(n);
	}
}
