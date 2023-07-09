#include "pch.h"
#include "mmu.h"
#include "kvm_host.h"


/*
 * When setting this variable to true it enables Two-Dimensional-Paging
 * where the hardware walks 2 page tables:
 * 1. the guest-virtual to guest-physical
 * 2. while doing 1. it walks guest-physical to host-physical
 * If the hardware supports that we don't need to do shadow paging.
 */
bool tdp_enabled = FALSE;

#define RMAP_EXT 4

struct kvm_rmap_desc {
	u64* sptes[RMAP_EXT];
	struct kvm_rmap_desc* more;
};

static PMDL pte_chain_cache_mdl;
static PMDL rmap_desc_cache_mdl;
static PMDL mmu_page_header_mdl;

static PVOID pte_chain_cache;
static PVOID rmap_desc_cache;
static PVOID mmu_page_header_cache;

static u64 shadow_trap_nonpresent_pte;
static u64 shadow_notrap_nonpresent_pte;
static u64 shadow_base_present_pte;
static u64 shadow_nx_mask;
static u64 shadow_x_mask;	/* mutual exclusive with nx_mask */
static u64 shadow_user_mask;
static u64 shadow_accessed_mask;
static u64 shadow_dirty_mask;

NTSTATUS kvm_mmu_module_init() {
	NTSTATUS status = STATUS_SUCCESS;
	do
	{
		
		pte_chain_cache_mdl = IoAllocateMdl(NULL, sizeof(struct kvm_pte_chain),
			FALSE, FALSE, NULL);
		if (!pte_chain_cache_mdl)
			break;
		pte_chain_cache = MmMapLockedPagesSpecifyCache(pte_chain_cache_mdl,
			KernelMode,
			MmNonCached,
			NULL,
			FALSE,
			NormalPagePriority);
		if (!pte_chain_cache) {
			status = STATUS_NO_MEMORY;
			break;
		}
		
		rmap_desc_cache_mdl = IoAllocateMdl(NULL, sizeof(struct kvm_rmap_desc),
			FALSE, FALSE, NULL);
		if (!rmap_desc_cache_mdl) {
			status = STATUS_NO_MEMORY;
			break;
		}
		rmap_desc_cache = MmMapLockedPagesSpecifyCache(rmap_desc_cache_mdl,
			KernelMode,
			MmNonCached,
			NULL,
			FALSE,
			NormalPagePriority);
		if (!rmap_desc_cache) {
			status = STATUS_NO_MEMORY;
			break;
		}

		mmu_page_header_mdl = IoAllocateMdl(NULL, sizeof(struct kvm_rmap_desc),
			FALSE, FALSE, NULL);
		if (!mmu_page_header_mdl) {
			status = STATUS_NO_MEMORY;
			break;
		}
		mmu_page_header_cache = MmMapLockedPagesSpecifyCache(mmu_page_header_mdl,
			KernelMode,
			MmNonCached,
			NULL,
			FALSE,
			NormalPagePriority);
		if (!mmu_page_header_cache) {
			status = STATUS_NO_MEMORY;
			break;
		}

		return STATUS_SUCCESS;
	} while (FALSE);

	if (!NT_SUCCESS(status)) {
		if (pte_chain_cache_mdl != NULL) {
			if (pte_chain_cache != NULL) {
				MmUnmapLockedPages(pte_chain_cache, pte_chain_cache_mdl);
			}
			IoFreeMdl(pte_chain_cache_mdl);
		}
		
		if (rmap_desc_cache_mdl != NULL) {
			if (rmap_desc_cache != NULL) {
				MmUnmapLockedPages(rmap_desc_cache, rmap_desc_cache_mdl);
			}
			IoFreeMdl(rmap_desc_cache_mdl);
		}

		if (mmu_page_header_mdl != NULL) {
			if (mmu_page_header_cache != NULL) {
				MmUnmapLockedPages(mmu_page_header_cache, mmu_page_header_mdl);
			}
			IoFreeMdl(mmu_page_header_mdl);
		}
	}

	return status;
}

void kvm_mmu_set_nonpresent_ptes(u64 trap_pte, u64 notrap_pte) {
	shadow_trap_nonpresent_pte = trap_pte;
	shadow_notrap_nonpresent_pte = notrap_pte;
}

void kvm_mmu_set_base_ptes(u64 base_pte) {
	shadow_base_present_pte = base_pte;
}

void kvm_mmu_set_mask_ptes(u64 user_mask, u64 accessed_mask,
	u64 dirty_mask, u64 nx_mask, u64 x_mask) {
	shadow_user_mask = user_mask;
	shadow_accessed_mask = accessed_mask;
	shadow_dirty_mask = dirty_mask;
	shadow_nx_mask = nx_mask;
	shadow_x_mask = x_mask;
}

void kvm_enable_tdp() {
	tdp_enabled = TRUE;
}

void kvm_disable_tdp() {
	tdp_enabled = FALSE;
}