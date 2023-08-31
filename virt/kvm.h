#pragma once

#define KVM_API_VERSION 1

typedef unsigned long long __u64;

/* for KVM_GET_REGS and KVM_SET_REGS */
struct kvm_regs {
	/* out (KVM_GET_REGS) / in (KVM_SET_REGS) */
	__u64 rax, rbx, rcx, rdx;
	__u64 rsi, rdi, rsp, rbp;
	__u64 r8, r9, r10, r11;
	__u64 r12, r13, r14, r15;
	__u64 rip, rflags;
};


int kvm_init();