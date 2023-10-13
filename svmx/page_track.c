#include "pch.h"
#include "kvm_host.h"
#include "kvm_page_track.h"
#include "mmu.h"
#include "mmu_internal.h"


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