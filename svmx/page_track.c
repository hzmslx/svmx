#include "pch.h"
#include "kvm_host.h"
#include "kvm_page_track.h"
#include "mmu.h"
#include "mmu_internal.h"

bool kvm_page_track_write_tracking_enabled(struct kvm* kvm)
{
	return !tdp_enabled || kvm_shadow_root_allocated(kvm);
}

static inline bool page_track_mode_is_valid(enum kvm_page_track_mode mode) {
	if (mode < 0 || mode >= KVM_PAGE_TRACK_MAX)
		return FALSE;

	return TRUE;
}

int kvm_page_track_create_memslot(struct kvm* kvm,
	struct kvm_memory_slot* slot,
	ULONG_PTR npages) {
	UNREFERENCED_PARAMETER(kvm);
	UNREFERENCED_PARAMETER(slot);
	UNREFERENCED_PARAMETER(npages);

	// int i;

	/*for (i = 0; i < KVM_PAGE_TRACK_MAX; i++) {
		if(i == KVM_PAGE_TRACK_WRITE && 
			!kvm_page_track_)
	}*/

	return 0;
}

/*
* check if the corresponding access on the specified guest page is tracked.
*/
bool kvm_slot_page_track_is_active(struct kvm* kvm,
	const struct kvm_memory_slot* slot,
	gfn_t gfn, enum kvm_page_track_mode mode) {
	gfn_t index;

	if (!page_track_mode_is_valid(mode))
		return FALSE;

	if (!slot)
		return FALSE;

	if (mode == KVM_PAGE_TRACK_WRITE &&
		!kvm_page_track_write_tracking_enabled(kvm))
		return FALSE;

	index = gfn_to_index(gfn, slot->base_gfn, PG_LEVEL_4K);
	return !!slot->arch.gfn_track[mode][index];
}