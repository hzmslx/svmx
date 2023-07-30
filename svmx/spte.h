#pragma once
#include "pgtable_types.h"
#include "mmu_internal.h"

#define ACC_EXEC_MASK    1
#define ACC_WRITE_MASK   PT_WRITABLE_MASK
#define ACC_USER_MASK    PT_USER_MASK
#define ACC_ALL          (ACC_EXEC_MASK | ACC_WRITE_MASK | ACC_USER_MASK)

extern u64 shadow_accessed_mask;

/*
 * A MMU present SPTE is backed by actual memory and may or may not be present
 * in hardware.  E.g. MMIO SPTEs are not considered present.  Use bit 11, as it
 * is ignored by all flavors of SPTEs and checking a low bit often generates
 * better code than for a high bit, e.g. 56+.  MMU present checks are pervasive
 * enough that the improved code generation is noticeable in KVM's footprint.
 */
#define SPTE_MMU_PRESENT_MASK		BIT_ULL(11)
/*
 * Returns true if A/D bits are supported in hardware and are enabled by KVM.
 * When enabled, KVM uses A/D bits for all non-nested MMUs.  Because L1 can
 * disable A/D bits in EPTP12, SP and SPTE variants are needed to handle the
 * scenario where KVM is using A/D bits for L1, but not L2.
 */
static inline bool kvm_ad_enabled(void)
{
	return !!shadow_accessed_mask;
}

static inline bool is_large_pte(u64 pte)
{
	return pte & PT_PAGE_SIZE_MASK;
}

static inline bool is_last_spte(u64 pte, int level)
{
	return (level == PG_LEVEL_4K) || is_large_pte(pte);
}

#ifdef CONFIG_DYNAMIC_PHYSICAL_MASK
#define SPTE_BASE_ADDR_MASK (physical_mask & ~(u64)(PAGE_SIZE-1))
#else
#define SPTE_BASE_ADDR_MASK (((1ULL << 52) - 1) & ~(u64)(PAGE_SIZE-1))
#endif

static inline bool is_shadow_present_pte(u64 pte)
{
	return !!(pte & SPTE_MMU_PRESENT_MASK);
}