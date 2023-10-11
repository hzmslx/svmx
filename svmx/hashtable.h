#pragma once

/*
* 
* Statically sized hash table implementation
* (C) 2023	VirtualCC
*/

#define DECLARE_HASHTABLE(name,bits) \
	LIST_ENTRY name[1<<(bits)]