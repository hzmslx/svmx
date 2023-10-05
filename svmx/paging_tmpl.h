
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * This module enables machines with Intel VT-x extensions to run virtual
 * machines without emulation or binary translation.
 *
 * MMU support
 *
 * Copyright (C) 2006 Qumranet, Inc.
 * Copyright 2010 Red Hat, Inc. and/or its affiliates.
 *
 * Authors:
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *   Avi Kivity   <avi@qumranet.com>
 */

 /*
  * The MMU needs to be able to access/walk 32-bit and 64-bit guest page tables,
  * as well as guest EPT tables, so the code in this file is compiled thrice,
  * once per guest PTE type.  The per-type defines are #undef'd at the end.
  */



#if PTTYPE == 64
	#define pt_element_t u64
	#define guest_walker guest_walker64
	#define FNAME(name)	paging##64_##name
	#define PT_LEVEL_BITS 9
	#define PT_GUEST_DIRTY_SHIFT PT_DIRTY_SHIFT
	#define PT_GUEST_ACCESSED_SHIFT PT_ACCESSED_SHIFT
	#define PT_HAVE_ACCESSED_DIRTY(mmu)	TRUE
#ifdef AMD64
	#define PT_MAX_FULL_LEVELS PT64_ROOT_MAX_LEVEL
#else
	#define PT_MAX_FULL_LEVELS 2
#endif
#elif PTTYPE == 32
	#define pt_element_t u32
	#define guest_walker guest_walker32
	#define FNAME(name) paging##32_##name
	#define PT_LEVEL_BITS 10
	#define PT_MAX_FULL_LEVELS	2
	#define PT_GUEST_DIRTY_SHIFT PT_DIRTY_SHIFT
	#define PT_GUEST_ACCESSED_SHIFT	PT_ACCESSED_SHIFT
	#define PT_HAVE_ACCESSED_DIRTY(mmu) TRUE

	#define PT32_DIR_PSE36_SIZE 4
	#define PT32_DIR_PSE36_SHIFT 13
	#define PT32_DIR_PSE36_MASK \
		(((1ULL << PT32_DIR_PSE36_SIZE) - 1) << PT32_DIR_PSE36_SHIFT)	
#elif PTTYPE == PTTYPE_EPT
	#define pt_element_t u64
	#define guest_walker guest_walkerEPT
	#define FNAME(name)	ept_##name
	/* 每级页表索引占用9 bit */
	#define PT_LEVEL_BITS 9
	#define PT_GUEST_DIRTY_SHIFT 9
	#define PT_GUEST_ACCESSED_SHIFT 8
	#define PT_HAVE_ACCESSED_DIRTY(mmu) (!(mmu)->cpu_role.base.ad_disabled)
	#define PT_MAX_FULL_LEVELS	PT64_ROOT_MAX_LEVEL
#else
	#error Invalid PTTYPE value
#endif


/* Common logic, but per-type values. These also need to be undefined. */
#define PT_BASE_ADDR_MASK	((pt_element_t)(((1ULL << 52) - 1) & ~(u64)(PAGE_SIZE - 1)))
#define PT_LVL_ADDR_MASK(lvl)	__PT_LVL_ADDR_MASK(PT_BASE_ADDR_MASK, lvl, PT_LEVEL_BITS)
#define PT_LVL_OFFSET_MASK(lvl)	__PT_LVL_OFFSET_MASK(PT_BASE_ADDR_MASK, lvl, PT_LEVEL_BITS)
/* 得到addr在level页表下的索引值 */
#define PT_INDEX(addr, lvl)	__PT_INDEX(addr, lvl, PT_LEVEL_BITS)

#define PT_GUEST_DIRTY_MASK		(1 << PT_GUEST_DIRTY_SHIFT)
#define PT_GUEST_ACCESSED_MASK	(1 << PT_GUEST_ACCESSED_SHIFT)

#define gpte_to_gfn_lvl FNAME(gpte_to_gfn_lvl)
#define gpte_to_gfn(pte) gpte_to_gfn_lvl((pte),PG_LEVEL_4K)

/*
* The guest_walker structure emulates the behavior of the hardware page
* table walker.
*/
struct guest_walker {
	int level;
	unsigned max_level;
	gfn_t table_gfn[PT_MAX_FULL_LEVELS];
	pt_element_t ptes[PT_MAX_FULL_LEVELS];
	pt_element_t prefetch_ptes[PTE_PREFETCH_NUM];
	gpa_t pte_gpa[PT_MAX_FULL_LEVELS];
	// 原指用户空间的指针
	pt_element_t* ptep_user[PT_MAX_FULL_LEVELS];
	bool pte_writable[PT_MAX_FULL_LEVELS];
	unsigned int pt_access[PT_MAX_FULL_LEVELS];
	unsigned int pte_access;
	gfn_t gfn;
	struct x86_exception fault;
};

#if PTTYPE == 32
static inline gfn_t pse36_gfn_delta(u32 gpte)
{
	int shift = 32 - PT32_DIR_PSE36_SHIFT - PAGE_SHIFT;

	return (gpte & PT32_DIR_PSE36_MASK) << shift;
}
#endif

#pragma warning(push)
#pragma warning(disable:4310)
static gfn_t gpte_to_gfn_lvl(pt_element_t gpte, int lvl) {
	return (gpte & PT_LVL_ADDR_MASK(lvl)) >> PAGE_SHIFT;
}
#pragma warning(pop)

static inline void FNAME(protect_clean_gpte)(struct kvm_mmu* mmu, unsigned* access,
	unsigned gpte) {
	unsigned mask;

	UNREFERENCED_PARAMETER(mmu);
	UNREFERENCED_PARAMETER(gpte);

	/* dirty bit is not supported, so no need to track it */
	if (!PT_HAVE_ACCESSED_DIRTY(mmu))
		return;

	mask = ~ACC_WRITE_MASK;
	/* Allow write access to dirty gptes */
	mask |= (gpte >> (PT_GUEST_DIRTY_SHIFT - PT_WRITABLE_SHIFT)) &
		PT_WRITABLE_MASK;
	*access &= mask;
}

static inline int FNAME(is_present_gpte)(unsigned long pte) {
#if PTTYPE != PTTYPE_EPT
	return pte & PT_PRESENT_MASK;
#else
	return pte & 7;
#endif
}

static bool FNAME(is_bad_mt_xwr)(struct rsvd_bits_validate* rsvd_check, u64 gpte) {
	UNREFERENCED_PARAMETER(rsvd_check);
	UNREFERENCED_PARAMETER(gpte);
#if PTTYPE != PTTYPE_EPT
	return FALSE;
#else
	return __is_bad_mt_xwr(rsvd_check, gpte);
#endif
}

static bool FNAME(is_rsvd_bits_set)(struct kvm_mmu* mmu, u64 gpte, int level) {
	return __is_rsvd_bits_set(&mmu->guest_rsvd_check, gpte, level) ||
		FNAME(is_bad_mt_xwr)(&mmu->guest_rsvd_check, gpte);
}

/*
* Fetch a guest pte for a guest virtual address, or for an L2's GPA.
*/
static int FNAME(walk_addr_generic)(struct guest_walker* walker,
	struct kvm_vcpu* vcpu, struct kvm_mmu* mmu,
	gpa_t addr, u64 access) {
	UNREFERENCED_PARAMETER(walker);
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(mmu);
	UNREFERENCED_PARAMETER(addr);
	UNREFERENCED_PARAMETER(access);


	return 0;
}


/* Note @addr is a GPA when gva_to_gpa() translates an L2 GPA to an L1 GPA. */
static gpa_t FNAME(gva_to_gpa)(struct kvm_vcpu* vcpu, struct kvm_mmu* mmu,
	gpa_t addr, u64 access,
	struct x86_exception* exception)
{
	struct guest_walker walker;
	gpa_t gpa = INVALID_GPA;
	int r;

	r = FNAME(walk_addr_generic)(&walker, vcpu, mmu, addr, access);

	if (r) {
		gpa = gfn_to_gpa(walker.gfn);
		gpa |= addr & ~PAGE_MASK;
	}
	else if (exception)
		*exception = walker.fault;

	return gpa;
}


#undef pt_element_t
#undef guest_walker
#undef FNAME
#undef PT_BASE_ADDR_MASK
#undef PT_INDEX
#undef PT_LVL_ADDR_MASK
#undef PT_LVL_OFFSET_MASK
#undef PT_LEVEL_BITS
#undef PT_MAX_FULL_LEVELS
#undef gpte_to_gfn
#undef gpte_to_gfn_lvl
#undef PT_GUEST_ACCESSED_MASK
#undef PT_GUEST_DIRTY_MASK
#undef PT_GUEST_DIRTY_SHIFT
#undef PT_GUEST_ACCESSED_SHIFT
#undef PT_HAVE_ACCESSED_DIRTY
