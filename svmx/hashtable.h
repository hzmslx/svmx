#pragma once

/*
* 
* Statically sized hash table implementation
* (C) 2023	VirtualCC
*/

#define DECLARE_HASHTABLE(name,bits) \
	struct hlist_head name[1<<(bits)]

static int ilog2(unsigned long v) {
	int l = 0;
	while ((1UL << 1) < v)
		l++;
	return l;
}

#define HASH_SIZE(name) (ARRAYSIZE(name))
#define HASH_BITS(name) (int)ilog2(HASH_SIZE(name))



/* Use hash_32 when possible to allow for fast 32bit hashing in 64bit kernels. */
#define hash_min(val, bits)							\
	(sizeof(val) <= 4 ? hash_32(val, bits) : hash_long(val, bits))

#define hash_for_each_possible(name, obj, member, key)			\
	hlist_for_each_entry(obj, &name[hash_min(key, HASH_BITS(name))], member)