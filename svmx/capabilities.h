#pragma once
#include "x86.h"
#include "pmu.h"

extern int pt_mode;

#define PT_MODE_SYSTEM		0
#define PT_MODE_HOST_GUEST	1




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

struct vmx_capability {
	u32 ept;
	u32 vpid;
};

extern struct vmcs_config vmcs_config;
extern struct vmx_capability vmx_capability;

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



static inline bool cpu_has_vmx_tpr_shadow(void)
{
	return vmcs_config.cpu_based_exec_ctrl & CPU_BASED_TPR_SHADOW;
}

/*
 * Processor Trace can operate in one of three modes:
 *  a. system-wide: trace both host/guest and output to host buffer
 *  b. host-only:   only trace host and output to host buffer
 *  c. host-guest:  trace host and guest simultaneously and output to their
 *                  respective buffer
 *
 * KVM currently only supports (a) and (c).
 */
static inline bool vmx_pt_mode_is_system(void)
{
	return pt_mode == PT_MODE_SYSTEM;
}
static bool vmx_pt_mode_is_host_guest(void) {
	return pt_mode == PT_MODE_HOST_GUEST;
}

static inline bool cpu_need_tpr_shadow(struct kvm_vcpu* vcpu)
{
	return cpu_has_vmx_tpr_shadow() && lapic_in_kernel(vcpu);
}

// cpu «∑Ò÷ß≥÷invvpid
static inline bool cpu_has_vmx_invvpid(void)
{
	return vmx_capability.vpid & VMX_VPID_INVVPID_BIT;
}

static inline bool cpu_has_vmx_ept_4levels(void)
{
	return vmx_capability.ept & VMX_EPT_PAGE_WALK_4_BIT;
}

static inline bool cpu_has_vmx_ept_mt_wb(void)
{
	return vmx_capability.ept & VMX_EPTP_WB_BIT;
}

static inline bool cpu_has_vmx_ept_ad_bits(void)
{
	return vmx_capability.ept & VMX_EPT_AD_BIT;
}

static inline bool cpu_has_tertiary_exec_ctrls(void) {
	return vmcs_config.cpu_based_exec_ctrl &
		CPU_BASED_ACTIVATE_TERTIARY_CONTROLS;
}

static inline bool cpu_has_vmx_rdtscp(void) {
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_ENABLE_RDTSCP;
}

static inline bool cpu_has_vmx_invpcid(void) {
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_ENABLE_INVPCID;
}

static inline bool cpu_has_vmx_rdrand(void) {
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_RDRAND_EXITING;
}

static inline bool cpu_has_vmx_rdseed(void) {
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_RDSEED_EXITING;
}

static inline bool cpu_has_vmx_waitpkg(void) {
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_ENABLE_USR_WAIT_PAUSE;
}