#pragma once

#define KVM_DEVICE 0x8000

#define KVM_GET_API_VERSION		CTL_CODE(KVM_DEVICE,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define KVM_CREATE_VM			CTL_CODE(KVM_DEVICE,0x801,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define KVM_CHECK_EXTENSION		CTL_CODE(KVM_DEVICE,0x802,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define KVM_GET_VCPU_MMPA_SIZE	CTL_CODE(KVM_DEVICE,0x803,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define KVM_TRACE_ENABLE		CTL_CODE(KVM_DEVICE,0x804,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define KVM_TRACE_PAUSE			CTL_CODE(KVM_DEVICE,0x805,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define KVM_TRACE_DISABLE		CTL_CODE(KVM_DEVICE,0x806,METHOD_BUFFERED,FILE_ANY_ACCESS)

struct trace_print_flags {
	unsigned long		mask;
	const char* name;
};

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

#define KVM_GUESTDBG_USE_SW_BP		0x00010000
#define KVM_GUESTDBG_USE_HW_BP		0x00020000
#define KVM_GUESTDBG_INJECT_DB		0x00040000
#define KVM_GUESTDBG_INJECT_BP		0x00080000

/* for KVM_SET_GUEST_DEBUG */
struct kvm_guest_debug_arch {
	__u64 debugreg[8];
};

struct kvm_guest_debug {
	__u32 control;
	__u32 pad;
	struct kvm_guest_debug_arch arch;
};

struct kvm_msr_entry {
	__u32 index;
	__u32 reserved;
	__u64 data;
};