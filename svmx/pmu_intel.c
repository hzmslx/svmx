#include "pch.h"
#include "pmu.h"

static bool intel_hw_event_available(struct kvm_pmc* pmc) {
	UNREFERENCED_PARAMETER(pmc);

	return FALSE;
}

/* check if a PMC is enabled by comparing it with globl_ctrl bits. */
static bool intel_pmc_is_enabled(struct kvm_pmc* pmc) {
	UNREFERENCED_PARAMETER(pmc);

	return FALSE;
}

static struct kvm_pmc* intel_pmc_idx_to_pmc(struct kvm_pmu* pmu, int pmc_idx) {
	UNREFERENCED_PARAMETER(pmu);
	UNREFERENCED_PARAMETER(pmc_idx);

	return NULL;
}

static struct kvm_pmc* intel_rdpmc_ecx_to_pmc(struct kvm_vcpu* vcpu,
	unsigned int idx, u64* mask) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(idx);
	UNREFERENCED_PARAMETER(mask);

	return NULL;
}

static struct kvm_pmc* intel_msr_idx_to_pmc(struct kvm_vcpu* vcpu, u32 msr) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(msr);

	return NULL;
}

static bool intel_is_valid_rdpmc_ecx(struct kvm_vcpu* vcpu, unsigned int idx) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(idx);
	return FALSE;
}

static bool intel_is_valid_msr(struct kvm_vcpu* vcpu, u32 msr) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(msr);

	return FALSE;
}

static int intel_pmu_get_msr(struct kvm_vcpu* vcpu, struct msr_data* msr_info) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(msr_info);

	return 0;
}

static int intel_pmu_set_msr(struct kvm_vcpu* vcpu, struct msr_data* msr_info) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(msr_info);

	return 1;
}

static void intel_pmu_refresh(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
}

static void intel_pmu_init(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
}

static void intel_pmu_reset(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);

}

static void intel_pmu_deliver_pmi(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);

}

static void intel_pmu_cleanup(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);

}

struct kvm_pmu_ops intel_pmu_ops  = {
	.hw_event_available = intel_hw_event_available,
	.pmc_is_enabled = intel_pmc_is_enabled,
	.pmc_idx_to_pmc = intel_pmc_idx_to_pmc,
	.rdpmc_ecx_to_pmc = intel_rdpmc_ecx_to_pmc,
	.msr_idx_to_pmc = intel_msr_idx_to_pmc,
	.is_valid_rdpmc_ecx = intel_is_valid_rdpmc_ecx,
	.is_valid_msr = intel_is_valid_msr,
	.get_msr = intel_pmu_get_msr,
	.set_msr = intel_pmu_set_msr,
	.refresh = intel_pmu_refresh,
	.init = intel_pmu_init,
	.reset = intel_pmu_reset,
	.deliver_pmi = intel_pmu_deliver_pmi,
	.cleanup = intel_pmu_cleanup,
	.MAX_NR_GP_COUNTERS = KVM_INTEL_PMC_MAX_GENERIC,
};