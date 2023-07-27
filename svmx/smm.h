#pragma once

static inline bool is_smm(struct kvm_vcpu* vcpu) { 
	UNREFERENCED_PARAMETER(vcpu);
	return FALSE; 
}