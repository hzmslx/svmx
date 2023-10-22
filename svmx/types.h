#pragma once


typedef _Bool			bool;

typedef		__u8		uint8_t;
typedef		__u16		uint16_t;
typedef		__u32		uint32_t;


typedef		__u64		uint64_t;
typedef		__u64		u_int64_t;

typedef unsigned char		unchar;
typedef unsigned short		ushort;
typedef unsigned int		uint;


typedef long long		s64;

// hash桶的头结点
struct hlist_head {
	struct hlist_node* first;
};

// hash桶的普通结点
struct hlist_node {
	struct hlist_node* next, ** pprev;
};