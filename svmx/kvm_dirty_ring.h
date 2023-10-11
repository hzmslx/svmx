#pragma once

static inline bool kvm_use_dirty_bitmap(struct kvm* kvm) {
	UNREFERENCED_PARAMETER(kvm);
	return TRUE;
}