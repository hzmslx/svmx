#include "pch.h"
#include "tdp_mmu.h"

/* Initializes the TDP MMU for the VM, if enabled. */
int kvm_mmu_init_tdp_mmu(struct kvm* kvm)
{
	UNREFERENCED_PARAMETER(kvm);
	
	return 1;
}

void kvm_mmu_uninit_tdp_mmu(struct kvm* kvm) {
	UNREFERENCED_PARAMETER(kvm);
}

hpa_t kvm_tdp_mmu_get_vcpu_root_hpa(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return 0;
}