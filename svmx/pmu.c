#include "pch.h"
#include "pmu.h"
#include "perf_event.h"

struct x86_pmu_capability kvm_pmu_cap;

struct kvm_pmu_ops amd_pmu_ops = {
	.MAX_NR_GP_COUNTERS = KVM_AMD_PMC_MAX_GENERIC,
};