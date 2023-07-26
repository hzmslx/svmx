#pragma once
#include "x86.h"
#include "pmu.h"

extern int pt_mode;

#define PT_MODE_SYSTEM		0
#define PT_MODE_HOST_GUEST	1

struct nested_vmx_msrs {
	/*
	 * We only store the "true" versions of the VMX capability MSRs. We
	 * generate the "non-true" versions by setting the must-be-1 bits
	 * according to the SDM.
	 */
	u32 procbased_ctls_low;
	u32 procbased_ctls_high;
	u32 secondary_ctls_low;
	u32 secondary_ctls_high;
	u32 pinbased_ctls_low;
	u32 pinbased_ctls_high;
	u32 exit_ctls_low;
	u32 exit_ctls_high;
	u32 entry_ctls_low;
	u32 entry_ctls_high;
	u32 misc_low;
	u32 misc_high;
	u32 ept_caps;
	u32 vpid_caps;
	u64 basic;
	u64 cr0_fixed0;
	u64 cr0_fixed1;
	u64 cr4_fixed0;
	u64 cr4_fixed1;
	u64 vmcs_enum;
	u64 vmfunc_controls;
};

struct vmcs_config {
	int size;
	u32 basic_cap;
	u32 revision_id;
	u32 pin_based_exec_ctrl;
	u32 cpu_based_exec_ctrl;
	u32 cpu_based_2nd_exec_ctrl;
	u64 cpu_based_3rd_exec_ctrl;
	u32 vmexit_ctrl;
	u32 vmentry_ctrl;
	u64 misc;
	struct nested_vmx_msrs nested;
};

extern struct vmcs_config vmcs_config;

static bool cpu_has_secondary_exec_ctrls(void) {
	return vmcs_config.cpu_based_exec_ctrl &
		CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
}

static bool cpu_has_vmx_vmfunc(void) {
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_ENABLE_VMFUNC;
}

static bool cpu_has_vmx_xsaves(void) {
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_XSAVES;
}

static inline bool cpu_has_vmx_encls_vmexit(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_ENCLS_EXITING;
}

static inline bool cpu_has_load_perf_global_ctrl(void)
{
	return vmcs_config.vmentry_ctrl & VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL;
}

static bool vmx_pt_mode_is_host_guest(void) {
	return pt_mode == PT_MODE_HOST_GUEST;
}

static inline bool cpu_has_vmx_tpr_shadow(void)
{
	return vmcs_config.cpu_based_exec_ctrl & CPU_BASED_TPR_SHADOW;
}

static inline bool cpu_need_tpr_shadow(struct kvm_vcpu* vcpu)
{
	return cpu_has_vmx_tpr_shadow() && lapic_in_kernel(vcpu);
}