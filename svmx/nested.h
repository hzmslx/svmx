#pragma once
#include "vmcs12.h"
#include "vmx.h"
#include "svm.h"

static inline struct vmcs12* get_vmcs12(struct kvm_vcpu* vcpu)
{
	return to_vmx(vcpu)->nested.cached_vmcs12;
}

/*
 * if fixed0[i] == 1: val[i] must be 1
 * if fixed1[i] == 0: val[i] must be 0
 */
static inline bool fixed_bits_valid(u64 val, u64 fixed0, u64 fixed1)
{
	return ((val & fixed1) | fixed0) == val;
}

static inline bool nested_host_cr0_valid(struct kvm_vcpu* vcpu, ULONG_PTR val)
{
	u64 fixed0 = to_vmx(vcpu)->nested.msrs.cr0_fixed0;
	u64 fixed1 = to_vmx(vcpu)->nested.msrs.cr0_fixed1;

	return fixed_bits_valid(val, fixed0, fixed1);
}

static inline bool nested_cr4_valid(struct kvm_vcpu* vcpu, ULONG_PTR val)
{
	u64 fixed0 = to_vmx(vcpu)->nested.msrs.cr4_fixed0;
	u64 fixed1 = to_vmx(vcpu)->nested.msrs.cr4_fixed1;

	return fixed_bits_valid(val, fixed0, fixed1) &&
		__kvm_is_valid_cr4(vcpu, val);
}

void recalc_intercepts(struct vcpu_svm* svm);
int vmx_get_vmx_msr(struct nested_vmx_msrs* msrs, u32 msr_index, u64* pdata);

static inline u64 nested_ept_get_eptp(struct kvm_vcpu* vcpu)
{
	/* return the page table to be shadowed - in our case, EPT12 */
	return get_vmcs12(vcpu)->ept_pointer;
}

static inline bool nested_ept_ad_enabled(struct kvm_vcpu* vcpu)
{
	return nested_ept_get_eptp(vcpu) & VMX_EPTP_AD_ENABLE_BIT;
}
