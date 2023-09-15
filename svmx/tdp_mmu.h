#pragma once
#include "kvm_host.h"

int kvm_mmu_init_tdp_mmu(struct kvm* kvm);
void kvm_mmu_uninit_tdp_mmu(struct kvm* kvm);
hpa_t kvm_tdp_mmu_get_vcpu_root_hpa(struct kvm_vcpu* vcpu);

