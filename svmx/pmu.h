#pragma once


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