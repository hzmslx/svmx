#pragma once

enum kvm_page_track_mode {
	KVM_PAGE_TRACK_WRITE,
	KVM_PAGE_TRACK_MAX,
};

int kvm_page_track_create_memslot(struct kvm* kvm,
	struct kvm_memory_slot* slot,
	ULONG_PTR npages);
bool kvm_slot_page_track_is_active(struct kvm* kvm,
	const struct kvm_memory_slot* slot,
	gfn_t gfn, enum kvm_page_track_mode mode);
bool kvm_page_track_write_tracking_enabled(struct kvm* kvm);