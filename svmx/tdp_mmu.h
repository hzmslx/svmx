#pragma once
#include "kvm_host.h"

int kvm_mmu_init_tdp_mmu(struct kvm* kvm);
void kvm_mmu_uninit_tdp_mmu(struct kvm* kvm);
hpa_t kvm_tdp_mmu_get_vcpu_root_hpa(struct kvm_vcpu* vcpu);

static inline bool kvm_tdp_mmu_get_root(struct kvm_mmu_page* root) {
	bool ret = root->tdp_mmu_root_count == 0 ? FALSE : TRUE;
	if (ret) {
		InterlockedAdd(&root->tdp_mmu_root_count, 1);
	}
	return ret;
}

void kvm_tdp_mmu_put_root(struct kvm* kvm, struct kvm_mmu_page* root,
	bool shared);

