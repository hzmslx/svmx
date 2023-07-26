#pragma once

void kvm_init_msr_list();



static bool mmu_is_nested(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return FALSE;
}

static inline bool kvm_mwait_in_guest(struct kvm* kvm)
{
	return kvm->arch.mwait_in_guest;
}

static inline bool kvm_hlt_in_guest(struct kvm* kvm)
{
	return kvm->arch.hlt_in_guest;
}
