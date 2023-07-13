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


int kvm_init(unsigned vcpu_size, unsigned vcpu_align){
	UNREFERENCED_PARAMETER(vcpu_align);
	UNREFERENCED_PARAMETER(vcpu_size);
	NTSTATUS status = STATUS_SUCCESS;
	


	return status;
}

void kvm_disable_largepages() {
	largepages_enabled = FALSE;
}

void kvm_exit() {

}