#pragma once

void kvm_init_msr_list();



static bool mmu_is_nested(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return FALSE;
}
