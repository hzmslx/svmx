#pragma once
#include "pgtable_types.h"
#include "mmu_internal.h"

#define ACC_EXEC_MASK    1
#define ACC_WRITE_MASK   PT_WRITABLE_MASK
#define ACC_USER_MASK    PT_USER_MASK
#define ACC_ALL          (ACC_EXEC_MASK | ACC_WRITE_MASK | ACC_USER_MASK)

extern u64 shadow_accessed_mask;


#define SPTE_LEVEL_BITS			9
#define SPTE_LEVEL_SHIFT(level)		__PT_LEVEL_SHIFT(level, SPTE_LEVEL_BITS)
#define SPTE_INDEX(address, level)	__PT_INDEX(address, level, SPTE_LEVEL_BITS)
#define SPTE_ENT_PER_PAGE		__PT_ENT_PER_PAGE(SPTE_LEVEL_BITS)

/*
 * A MMU present SPTE is backed by actual memory and may or may not be present
 * in hardware.  E.g. MMIO SPTEs are not considered present.  Use bit 11, as it
 * is ignored by all flavors of SPTEs and checking a low bit often generates
 * better code than for a high bit, e.g. 56+.  MMU present checks are pervasive
 * enough that the improved code generation is noticeable in KVM's footprint.
 */
#define SPTE_MMU_PRESENT_MASK		BIT_ULL(11)

 /*
  * TDP SPTES (more specifically, EPT SPTEs) may not have A/D bits, and may also
  * be restricted to using write-protection (for L2 when CPU dirty logging, i.e.
  * PML, is enabled).  Use bits 52 and 53 to hold the type of A/D tracking that
  * is must be employed for a given TDP SPTE.
  *
  * Note, the "enabled" mask must be '0', as bits 62:52 are _reserved_ for PAE
  * paging, including NPT PAE.  This scheme works because legacy shadow paging
  * is guaranteed to have A/D bits and write-protection is forced only for
  * TDP with CPU dirty logging (PML).  If NPT ever gains PML-like support, it
  * must be restricted to 64-bit KVM.
  */
#define SPTE_TDP_AD_SHIFT		52
#define SPTE_TDP_AD_MASK		(3ULL << SPTE_TDP_AD_SHIFT)
#define SPTE_TDP_AD_ENABLED		(0ULL << SPTE_TDP_AD_SHIFT)
#define SPTE_TDP_AD_DISABLED		(1ULL << SPTE_TDP_AD_SHIFT)
#define SPTE_TDP_AD_WRPROT_ONLY		(2ULL << SPTE_TDP_AD_SHIFT)


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

/*
 * Low ignored bits are at a premium for EPT, use high ignored bits, taking care
 * to not overlap the A/D type mask or the saved access bits of access-tracked
 * SPTEs when A/D bits are disabled.
 */
#define EPT_SPTE_HOST_WRITABLE		BIT_ULL(57)
#define EPT_SPTE_MMU_WRITABLE		BIT_ULL(58)

 /*
  * {DEFAULT,EPT}_SPTE_{HOST,MMU}_WRITABLE are used to keep track of why a given
  * SPTE is write-protected. See is_writable_pte() for details.
  */

  /* Bits 9 and 10 are ignored by all non-EPT PTEs. */
#define DEFAULT_SPTE_HOST_WRITABLE	BIT_ULL(9)
#define DEFAULT_SPTE_MMU_WRITABLE	BIT_ULL(10)

static inline bool __is_bad_mt_xwr(struct rsvd_bits_validate* rsvd_check,
	u64 pte) {
	return rsvd_check->bad_mt_xwr & BIT_ULL(pte & 0x3f);
}

static inline u64 get_rsvd_bits(struct rsvd_bits_validate* rsvd_check, u64 pte,
	int level) {
	int bit7 = (pte >> 7) & 1;

	return rsvd_check->rsvd_bits_mask[bit7][level - 1];
}

static inline bool __is_rsvd_bits_set(struct rsvd_bits_validate* rsvd_check,
	u64 pte, int level) {
	return pte & get_rsvd_bits(rsvd_check, pte, level);
}

static inline struct kvm_mmu_page* to_shadow_page(hpa_t shadow_page) {
	PHYSICAL_ADDRESS physical_addr = {0};
	physical_addr.QuadPart = shadow_page;
	return MmGetVirtualForPhysical(physical_addr);
}

static struct kvm_mmu_page* spte_to_child_sp(u64 spte) {
	return to_shadow_page(spte & SPTE_BASE_ADDR_MASK);
}

static inline bool is_mmio_spte(u64 pte) {
	return !!(pte & SPTE_MMU_PRESENT_MASK);
}

void kvm_mmu_spte_module_init(void);
void kvm_mmu_reset_all_pte_masks(void);


/*
 * The SPTE MMIO mask must NOT overlap the MMIO generation bits or the
 * MMU-present bit.  The generation obviously co-exists with the magic MMIO
 * mask/value, and MMIO SPTEs are considered !MMU-present.
 *
 * The SPTE MMIO mask is allowed to use hardware "present" bits (i.e. all EPT
 * RWX bits), all physical address bits (legal PA bits are used for "fast" MMIO
 * and so they're off-limits for generation; additional checks ensure the mask
 * doesn't overlap legal PA bits), and bit 63 (carved out for future usage).
 */
#define SPTE_MMIO_ALLOWED_MASK (BIT_ULL(63) | GENMASK_ULL(51, 12) | GENMASK_ULL(2, 0))




static inline bool is_rsvd_spte(struct rsvd_bits_validate* rsvd_check,
	u64 spte, int level) {
	return __is_bad_mt_xwr(rsvd_check, spte) ||
		__is_rsvd_bits_set(rsvd_check, spte, level);
}