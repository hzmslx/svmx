#pragma once
#include "pgtable_types.h"
#include "mmu_internal.h"

#define ACC_EXEC_MASK    1
#define ACC_WRITE_MASK   PT_WRITABLE_MASK
#define ACC_USER_MASK    PT_USER_MASK
#define ACC_ALL          (ACC_EXEC_MASK | ACC_WRITE_MASK | ACC_USER_MASK)

#define MMIO_SPTE_GEN_LOW_START		3
#define MMIO_SPTE_GEN_LOW_END		10

#define MMIO_SPTE_GEN_HIGH_START	52
#define MMIO_SPTE_GEN_HIGH_END		62

#define MMIO_SPTE_GEN_LOW_MASK		GENMASK_ULL(MMIO_SPTE_GEN_LOW_END, \
						    MMIO_SPTE_GEN_LOW_START)
#define MMIO_SPTE_GEN_HIGH_MASK		GENMASK_ULL(MMIO_SPTE_GEN_HIGH_END, \
						    MMIO_SPTE_GEN_HIGH_START)

#define MMIO_SPTE_GEN_LOW_BITS		(MMIO_SPTE_GEN_LOW_END - MMIO_SPTE_GEN_LOW_START + 1)
#define MMIO_SPTE_GEN_HIGH_BITS		(MMIO_SPTE_GEN_HIGH_END - MMIO_SPTE_GEN_HIGH_START + 1)

#define MMIO_SPTE_GEN_LOW_SHIFT		(MMIO_SPTE_GEN_LOW_START - 0)
#define MMIO_SPTE_GEN_HIGH_SHIFT	(MMIO_SPTE_GEN_HIGH_START - MMIO_SPTE_GEN_LOW_BITS)

#define MMIO_SPTE_GEN_MASK		GENMASK_ULL(MMIO_SPTE_GEN_LOW_BITS + MMIO_SPTE_GEN_HIGH_BITS - 1, 0)

extern u64 shadow_host_writable_mask;
extern u64 shadow_mmu_writable_mask;
extern u64 shadow_nx_mask;
extern u64 shadow_x_mask; /* mutual exclusive with nx_mask */
extern u64 shadow_user_mask;
extern u64 shadow_accessed_mask;
extern u64 shadow_dirty_mask;
extern u64 shadow_mmio_value;
extern u64 shadow_mmio_mask;
extern u64 shadow_mmio_access_mask;
extern u64 shadow_present_mask;
extern u64 shadow_memtype_mask;
extern u64 shadow_me_value;
extern u64 shadow_me_mask;

/*
 * SPTEs in MMUs without A/D bits are marked with SPTE_TDP_AD_DISABLED;
 * shadow_acc_track_mask is the set of bits to be cleared in non-accessed
 * pages.
 */
extern u64 shadow_acc_track_mask;

/*
 * This mask must be set on all non-zero Non-Present or Reserved SPTEs in order
 * to guard against L1TF attacks.
 */
extern u64 shadow_nonpresent_or_rsvd_mask;

/*
 * The number of high-order 1 bits to use in the mask above.
 */
#define SHADOW_NONPRESENT_OR_RSVD_MASK_LEN 5

/* The mask for the R/X bits in EPT PTEs */
#define SPTE_EPT_READABLE_MASK			0x1ull
#define SPTE_EPT_EXECUTABLE_MASK		0x4ull

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
  * The mask/shift to use for saving the original R/X bits when marking the PTE
  * as not-present for access tracking purposes. We do not save the W bit as the
  * PTEs being access tracked also need to be dirty tracked, so the W bit will be
  * restored only when a write is attempted to the page.  This mask obviously
  * must not overlap the A/D type mask.
  */
#define SHADOW_ACC_TRACK_SAVED_BITS_MASK (SPTE_EPT_READABLE_MASK | \
					  SPTE_EPT_EXECUTABLE_MASK)
#define SHADOW_ACC_TRACK_SAVED_BITS_SHIFT 54
#define SHADOW_ACC_TRACK_SAVED_MASK	(SHADOW_ACC_TRACK_SAVED_BITS_MASK << \
					 SHADOW_ACC_TRACK_SAVED_BITS_SHIFT)

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
/*
* 判断pte是否是大页的最后一级
*/
static inline bool is_large_pte(u64 pte)
{
	return pte & PT_PAGE_SIZE_MASK;
}

/*
* 判断pte是否是影子页表的叶子页表表项
*/
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

static inline kvm_pfn_t spte_to_pfn(u64 pte) {
	return (pte & SPTE_BASE_ADDR_MASK) >> PAGE_SHIFT;
}

/*
 * If a thread running without exclusive control of the MMU lock must perform a
 * multi-part operation on an SPTE, it can set the SPTE to REMOVED_SPTE as a
 * non-present intermediate value. Other threads which encounter this value
 * should not modify the SPTE.
 *
 * Use a semi-arbitrary value that doesn't set RWX bits, i.e. is not-present on
 * both AMD and Intel CPUs, and doesn't set PFN bits, i.e. doesn't create a L1TF
 * vulnerability.  Use only low bits to avoid 64-bit immediates.
 *
 * Only used by the TDP MMU.
 */
#define REMOVED_SPTE	0x5a0ULL


static inline bool is_removed_spte(u64 spte) {
	return spte == REMOVED_SPTE;
}

static inline struct kvm_mmu_page* sptep_to_sp(u64* sptep) {
	PHYSICAL_ADDRESS physical = MmGetPhysicalAddress(sptep);
	return to_shadow_page(physical.QuadPart);
}

static inline bool is_executable_pte(u64 spte)
{
	return (spte & (shadow_x_mask | shadow_nx_mask)) == shadow_x_mask;
}

static inline bool is_writable_pte(ULONG_PTR pte) {
	return pte & PT_WRITABLE_MASK;
}

static inline bool spte_ad_enabled(u64 spte) {
	return (spte & SPTE_TDP_AD_MASK) != SPTE_TDP_AD_DISABLED;
}

static inline bool is_access_track_spte(u64 spte) {
	return !spte_ad_enabled(spte) && (spte & shadow_acc_track_mask) == 0;
}

/* Restore an acc-track PTE back to a regular PTE */
static inline u64 restore_acc_track_spte(u64 spte) {
	u64 saved_bits = (spte >> SHADOW_ACC_TRACK_SAVED_BITS_SHIFT)
		& SHADOW_ACC_TRACK_SAVED_BITS_MASK;

	spte &= ~shadow_acc_track_mask;
	spte &= ~(SHADOW_ACC_TRACK_SAVED_BITS_MASK <<
		SHADOW_ACC_TRACK_SAVED_BITS_SHIFT);
	spte |= saved_bits;

	return spte;
}

static inline bool is_mmu_writable_spte(u64 spte)
{
	return spte & shadow_mmu_writable_mask;
}

/* Get an SPTE's index into its parent's page table (and the spt array). */
static inline int spte_index(u64* sptep)
{
	return ((ULONG_PTR)sptep / sizeof(*sptep)) & (SPTE_ENT_PER_PAGE - 1);
}

u64 make_nonleaf_spte(u64* child_pt, bool ad_disabled);

static inline bool sp_ad_disabled(struct kvm_mmu_page* sp) {
	return !!sp->role.ad_disabled;
}



u64 make_mmio_spte(struct kvm_vcpu* vcpu, u64 gfn, unsigned int access);

bool make_spte(struct kvm_vcpu* vcpu, struct kvm_mmu_page* sp,
	const struct kvm_memory_slot* slot,
	unsigned int pte_access, gfn_t gfn, kvm_pfn_t pfn,
	u64 old_spte, bool prefetch, bool can_unsync,
	bool host_writable, u64* new_spte);

static inline u64 spte_shadow_accessed_mask(u64 spte) {
	return spte_ad_enabled(spte) ? shadow_accessed_mask : 0;
}

static inline u64 spte_shadow_dirty_mask(u64 spte) {
	return spte_ad_enabled(spte) ? shadow_dirty_mask : 0;
}

static inline bool is_dirty_spte(u64 spte) {
	u64 dirty_mask = spte_shadow_dirty_mask(spte);

	return dirty_mask ? spte & dirty_mask : spte & PT_WRITABLE_MASK;
}