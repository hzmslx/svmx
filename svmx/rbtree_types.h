#pragma once


struct rb_node {
	ULONG_PTR __rb_parent_color;
	struct rb_node* rb_right;
	struct rb_node* rb_left;
};

struct rb_root {
	struct rb_node* rb_node;
};

/*
* Leftmost-cached rbtrees.
* 
* We do not cache the rightmost node based on footprint
* size vs number of petential users that could benefit
* from O(1) rb_last(). Just not worth it, users that want
* this feature can always implement the logic explicitly.
* Furthermore, users that want to cache both pointers may
* find it a bit asymmetric, but that's ok.
*/
struct rb_root_cached {
	struct rb_root rb_root;
	struct rb_node* rb_leftmost;
};

#define RB_ROOT (struct rb_root) {NULL,}
#define RB_ROOT_CACHED (struct rb_root_cached) {{NULL,},NULL}