#include "pch.h"
#include "mmu.h"
#include "spte.h"
#include "vmx.h"

u64 shadow_host_writable_mask;
u64 shadow_mmu_writable_mask;
u64 shadow_nx_mask;
u64 shadow_x_mask; /* mutual exclusive with nx_mask */
u64 shadow_user_mask;
u64 shadow_accessed_mask;
u64 shadow_dirty_mask;
u64 shadow_mmio_value;
u64 shadow_mmio_mask;
u64 shadow_mmio_access_mask;
u64 shadow_present_mask;
u64 shadow_memtype_mask;
u64 shadow_me_value;
u64 shadow_me_mask;
u64 shadow_acc_track_mask;

u64 shadow_nonpresent_or_rsvd_mask;
u64 shadow_nonpresent_or_rsvd_lower_gfn_mask;

u8 shadow_phys_bits;

void kvm_mmu_set_ept_masks(bool has_ad_bits, bool has_exec_only) {
	shadow_user_mask = VMX_EPT_READABLE_MASK;
	shadow_accessed_mask = has_ad_bits ? VMX_EPT_ACCESS_BIT : 0ull;
	shadow_dirty_mask = has_ad_bits ? VMX_EPT_DIRTY_BIT : 0ull;
	shadow_nx_mask = 0ull;
	shadow_x_mask = VMX_EPT_EXECUTABLE_MASK;
	shadow_present_mask = has_exec_only ? 0ull : VMX_EPT_READABLE_MASK;

	/*
	* EPT overrides the host MTRRs, and so KVM must program the desired
	* memtype directly into the SPTEs. Note, this mask is just the mask
	* of all bits that factor into the memtype, the actual memtype must be
	* dynamically calculated, e.g. to ensure host MMIO is mapped UC.
	*/
	shadow_memtype_mask = VMX_EPT_MT_MASK | VMX_EPT_IPAT_BIT;
	shadow_acc_track_mask = VMX_EPT_RWX_MASK;
	shadow_host_writable_mask = EPT_SPTE_HOST_WRITABLE;
	shadow_mmu_writable_mask = EPT_SPTE_MMU_WRITABLE;

	/*
	* EPT Misconfigurations are generated if the value of bits 2:0
	* of an EPT paging-structure entry is 110b (write/execute).
	*/
	kvm_mmu_set_mmio_spte_mask(VMX_EPT_MISCONFIG_WX_VALUE,
		VMX_EPT_RWX_MASK, 0);
}

void kvm_mmu_set_mmio_spte_mask(u64 mmio_value, u64 mmio_mask, u64 access_mask) {
	UNREFERENCED_PARAMETER(mmio_value);
	UNREFERENCED_PARAMETER(mmio_mask);
	UNREFERENCED_PARAMETER(access_mask);
}