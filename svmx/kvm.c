#include "pch.h"
#include "kvm.h"
#include "kvm_host.h"

/*
* Kernel-based Virtual Machine driver for Windows
* 
* This module enables machines with Intel VT-x extensions to run virtual
* machines without emulation or binary translation.
* 
* 
*/
PMDL kvm_vcpu_cache_mdl;

PVOID kvm_vcpu_cache;

static bool largepages_enabled = TRUE;


NTSTATUS kvm_init(void* opaque, unsigned int vcpu_size) {
	NTSTATUS status = STATUS_SUCCESS;
	
	UNREFERENCED_PARAMETER(vcpu_size);

	do
	{
		status = kvm_arch_init(opaque);
		if (!NT_SUCCESS(status)) {
			break;
		}

		status = kvm_arch_hardware_setup();
		if (!NT_SUCCESS(status)) {
			break;
		}

		kvm_vcpu_cache_mdl = IoAllocateMdl(NULL, sizeof(struct kvm_pte_chain),
			FALSE, FALSE, NULL);
		if (!kvm_vcpu_cache_mdl) {
			status = STATUS_NO_MEMORY;
			break;
		}
		kvm_vcpu_cache = MmMapLockedPagesSpecifyCache(kvm_vcpu_cache_mdl,
			KernelMode,
			MmNonCached,
			NULL,
			FALSE,
			NormalPagePriority);
		if (!kvm_vcpu_cache) {
			status = STATUS_NO_MEMORY;
			break;
		}

		
		return STATUS_SUCCESS;
	} while (FALSE);
	
	if (!NT_SUCCESS(status)) {
		if (kvm_vcpu_cache_mdl != NULL) {
			if (kvm_vcpu_cache != NULL) {
				MmUnlockPages(kvm_vcpu_cache_mdl);
			}
			IoFreeMdl(kvm_vcpu_cache_mdl);
		}
	}

	return status;
}

void kvm_disable_largepages() {
	largepages_enabled = FALSE;
}

void kvm_exit() {

}