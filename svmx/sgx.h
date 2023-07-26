#pragma once
#include "kvm_host.h"
#include "capabilities.h"
#include "vmx_ops.h"

static void vmx_write_encls_bitmap(struct kvm_vcpu* vcpu,
	struct vmcs12* vmcs12) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(vmcs12);
	/* Nothing to do if hardware doesn't support SGX */
	if (cpu_has_vmx_encls_vmexit())
		vmcs_write64(ENCLS_EXITING_BITMAP, (u64)-1);
}