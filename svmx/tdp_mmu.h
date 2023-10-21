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

int kvm_tdp_mmu_get_walk(struct kvm_vcpu* vcpu, u64 addr, 
	u64* sptes,int* root_level);


#ifdef AMD64
static inline bool is_tdp_mmu_page(struct kvm_mmu_page* sp) {
	return sp->tdp_mmu_page;
}
#else
static inline bool is_tdp_mmu_page(struct kvm_mmu_page* sp) {
	UNREFERENCED_PARAMETER(sp);
	return FALSE;
}
#endif // AMD64

int kvm_tdp_mmu_map(struct kvm_vcpu* vcpu, struct kvm_page_fault* fault);
u64* kvm_tdp_mmu_fast_pf_get_last_sptep(struct kvm_vcpu* vcpu, u64 addr,
	u64* spte);
