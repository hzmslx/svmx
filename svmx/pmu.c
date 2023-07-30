#include "pch.h"
#include "pmu.h"


struct kvm_pmu_ops amd_pmu_ops = {
	.MAX_NR_GP_COUNTERS = KVM_AMD_PMC_MAX_GENERIC,
};