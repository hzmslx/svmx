#include "pch.h"
#include "cpuid.h"
#include "kvm_host.h"
#include "mmu.h"
#include "lapic.h"
#include "pmu.h"

static void kvm_vcpu_after_set_cpuid(struct kvm_vcpu* vcpu) {
	/* Invoke the vendor callback only after the above state is updated. */
	kvm_x86_ops.vcpu_after_set_cpuid(vcpu);
}

void kvm_set_cpu_caps(void) {

}