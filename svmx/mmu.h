#pragma once
#include "kvm_cache_regs.h"

#define PT_WRITABLE_SHIFT 1

#define PT_PRESENT_MASK (1ULL << 0)
#define PT_WRITABLE_MASK (1ULL << PT_WRITABLE_SHIFT)
#define PT_USER_MASK (1ULL << 2)
#define PT_PWT_MASK (1ULL << 3)
#define PT_PCD_MASK (1ULL << 4)
#define PT_ACCESSED_SHIFT 5
#define PT_ACCESSED_MASK (1ULL << PT_ACCESSED_SHIFT)
#define PT_DIRTY_MASK (1ULL << 6)
#define PT_PAGE_SIZE_MASK (1ULL << 7)
#define PT_PAT_MASK (1ULL << 7)
#define PT_GLOBAL_MASK (1ULL << 8)
#define PT64_NX_SHIFT 63
#define PT64_NX_MASK (1ULL << PT64_NX_SHIFT)

#define PT64_ROOT_LEVEL 4
#define PT32_ROOT_LEVEL 2
#define PT32E_ROOT_LEVEL 3

#define KVM_MMU_CR4_ROLE_BITS (X86_CR4_PSE | X86_CR4_PAE | X86_CR4_LA57 | \
			       X86_CR4_SMEP | X86_CR4_SMAP | X86_CR4_PKE)

#define KVM_MMU_CR0_ROLE_BITS (X86_CR0_PG | X86_CR0_WP)

void kvm_init_mmu(struct kvm_vcpu* vcpu);

int kvm_mmu_load(struct kvm_vcpu* vcpu);

static inline int kvm_mmu_reload(struct kvm_vcpu* vcpu)
{
	return kvm_mmu_load(vcpu);
}

gpa_t translate_nested_gpa(struct kvm_vcpu* vcpu, gpa_t gpa, u64 access,
	struct x86_exception* exception);

static inline gpa_t kvm_translate_gpa(struct kvm_vcpu* vcpu,
	struct kvm_mmu* mmu,
	gpa_t gpa, u64 access,
	struct x86_exception* exception)
{
	if (mmu != &vcpu->arch.nested_mmu)
		return gpa;
	return translate_nested_gpa(vcpu, gpa, access, exception);
}

int kvm_tdp_page_fault(struct kvm_vcpu* vcpu, struct kvm_page_fault* fault);

static inline void kvm_mmu_load_pgd(struct kvm_vcpu* vcpu) {
	u64 root_hpa = vcpu->arch.mmu->root.hpa;

	if (!VALID_PAGE(root_hpa))
		return;

	kvm_x86_ops.load_mmu_pgd(vcpu, root_hpa,
		vcpu->arch.mmu->root_role.level);
}

static inline unsigned long kvm_get_pcid(struct kvm_vcpu* vcpu, gpa_t cr3)
{
	return kvm_is_cr4_bit_set(vcpu, X86_CR4_PCIDE)
		? cr3 & X86_CR3_PCID_MASK
		: 0;
}

static inline unsigned long kvm_get_active_pcid(struct kvm_vcpu* vcpu)
{
	return kvm_get_pcid(vcpu, kvm_read_cr3(vcpu));
}

int kvm_mmu_post_init_vm(struct kvm* kvm);
void kvm_mmu_pre_destroy_vm(struct kvm* kvm);

