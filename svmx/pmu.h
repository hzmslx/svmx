#pragma once
#include "perf_event.h"

struct kvm_pmu_ops {
	bool (*hw_event_available)(struct kvm_pmc* pmc);
	bool (*pmc_is_enabled)(struct kvm_pmc* pmc);
	struct kvm_pmc* (*pmc_idx_to_pmc)(struct kvm_pmu* pmu, int pmc_idx);
	struct kvm_pmc* (*rdpmc_ecx_to_pmc)(struct kvm_vcpu* vcpu,
		unsigned int idx, u64* mask);
	struct kvm_pmc* (*msr_idx_to_pmc)(struct kvm_vcpu* vcpu, u32 msr);
	bool (*is_valid_rdpmc_ecx)(struct kvm_vcpu* vcpu, unsigned int idx);
	bool (*is_valid_msr)(struct kvm_vcpu* vcpu, u32 msr);
	int (*get_msr)(struct kvm_vcpu* vcpu, struct msr_data* msr_info);
	int (*set_msr)(struct kvm_vcpu* vcpu, struct msr_data* msr_info);
	void (*refresh)(struct kvm_vcpu* vcpu);
	void (*init)(struct kvm_vcpu* vcpu);
	void (*reset)(struct kvm_vcpu* vcpu);
	void (*deliver_pmi)(struct kvm_vcpu* vcpu);
	void (*cleanup)(struct kvm_vcpu* vcpu);

	const u64 EVENTSEL_EVENT;
	const int MAX_NR_GP_COUNTERS;
};

extern struct kvm_pmu_ops intel_pmu_ops;
extern struct kvm_pmu_ops amd_pmu_ops;

extern bool enable_pmu;
extern struct x86_pmu_capability kvm_pmu_cap;

static void kvm_init_pmu_capability(const struct kvm_pmu_ops* pmu_ops) {


	if (!enable_pmu) {
		memset(&kvm_pmu_cap, 0, sizeof(kvm_pmu_cap));
		return;
	}

	kvm_pmu_cap.version = min(kvm_pmu_cap.version, 2);
	kvm_pmu_cap.num_counters_gp = min(kvm_pmu_cap.num_counters_gp,
		pmu_ops->MAX_NR_GP_COUNTERS);

}