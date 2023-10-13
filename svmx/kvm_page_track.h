#pragma once

enum kvm_page_track_mode {
	KVM_PAGE_TRACK_WRITE,
	KVM_PAGE_TRACK_MAX,
};

int kvm_page_track_create_memslot(struct kvm* kvm,
	struct kvm_memory_slot* slot,
	ULONG_PTR npages);