#include "pch.h"
#include "mmu.h"

// ³õÊ¼»¯ mtrr Á´±í
void kvm_vcpu_mtrr_init(struct kvm_vcpu* vcpu) {
	InitializeListHead(&vcpu->arch.mtrr_state.head);
}