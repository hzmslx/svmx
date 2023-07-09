#pragma once

struct kvm_segment {
	__u64 base;
	__u32 limit;
	__u16 selector;
	__u8  type;
	__u8  present, dpl, db, s, l, g, avl;
	__u8  unusable;
	__u8  padding;
};

struct kvm_run {
	/* in */
	__u8 request_interrupt_window;

};

/* for KVM_SET_GUEST_DEBUG */
struct kvm_guest_debug_arch {
	__u64 debugreg[8];
};

struct kvm_guest_debug {
	__u32 control;
	__u32 pad;
	struct kvm_guest_debug_arch arch;
};

