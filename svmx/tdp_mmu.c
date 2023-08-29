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