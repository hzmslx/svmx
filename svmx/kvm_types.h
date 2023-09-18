#pragma once
#include "int-ll64.h"

/*
 * Address types:
 *
 *  gva - guest virtual address
 *  gpa - guest physical address
 *  gfn - guest frame number
 *  hva - host virtual address
 *  hpa - host physical address
 *  hfn - host frame number
 */

typedef ULONG_PTR  gva_t;
typedef u64        gpa_t;
typedef ULONG_PTR  gfn_t;

typedef ULONG_PTR  hva_t;
typedef u64        hpa_t;
typedef ULONG_PTR  hfn_t;

typedef hfn_t kvm_pfn_t;

struct gfn_to_hva_cache {
	u64 generation;
	gpa_t gpa;
	ULONG_PTR hva;
	ULONG_PTR len;
	struct kvm_memory_slot* memslot;
};

#define HALT_POLL_HIST_COUNT			32

struct kvm_vcpu_stat_generic {
	u64 halt_successful_poll;
	u64 halt_attempted_poll;
	u64 halt_poll_invalid;
	u64 halt_wakeup;
	u64 halt_poll_success_ns;
	u64 halt_poll_fail_ns;
	u64 halt_wait_ns;
	u64 halt_poll_success_hist[HALT_POLL_HIST_COUNT];
	u64 halt_poll_fail_hist[HALT_POLL_HIST_COUNT];
	u64 halt_wait_hist[HALT_POLL_HIST_COUNT];
	u64 blocking;
};

#define KVM_STATS_NAME_SIZE	48

#define INVALID_GPA	(~(gpa_t)0)

#define KVM_ARCH_NR_OBJS_PER_MEMORY_CACHE 40

/*
* Memory caches are used to preallocate memory ahead of various MMU flows,
* e.g. page fault handlers. Gracefully handling allocation failures deep in
* MMU flows is problematic, as is triggering reclaim, I/O, etc... while
* holding MMU locks.
* 
* The @capacity field and @objects array are lazily initialized when the cache
* is topped up (__kvm_mmu_topup_memory_cache()).
*/
struct kvm_mmu_memory_cache {
	MEMORY_CACHING_TYPE cache_type;
	PVOID kmem_cache;
	int capacity;
	int nobjs;
	void** objects;
};