#pragma once

struct interval_tree_node {
	struct rb_node rb;
	ULONG_PTR start;/* Start of interval */
	ULONG_PTR last;	/* Last location _in_ interval */
	ULONG_PTR __subtree_last;
};