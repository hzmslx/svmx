#include "pch.h"
#include "kvm_host.h"
#include "kvm.h"
#include "kvm_mm.h"

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

KMUTEX kvm_lock;

static int kvm_usage_count = 0;

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

NTSTATUS kvm_dev_ioctl_create_vm(unsigned long type) {
	struct kvm* kvm;

	kvm = kvm_create_vm(type);
	if (!kvm) {
		return STATUS_UNSUCCESSFUL;
	}
	return STATUS_SUCCESS;
}

static int __hardware_enable_nolock(void) {
	
	if (kvm_arch_hardware_enable()) {
		return -1;
	}

	return 0;
}

static void hardware_enable_nolock(void* failed) {
	UNREFERENCED_PARAMETER(failed);
	__hardware_enable_nolock();
}

ULONG_PTR EnableHardware(
	_In_ ULONG_PTR Argument
) {
	UNREFERENCED_PARAMETER(Argument);
	hardware_enable_nolock(NULL);
	return 0;
}

static NTSTATUS hardware_enable_all(void) {
	NTSTATUS status = STATUS_SUCCESS;

	KeWaitForSingleObject(&kvm_lock, Executive, KernelMode, FALSE, NULL);

	kvm_usage_count++;
	if (kvm_usage_count == 1) {
		KeIpiGenericCall(EnableHardware, 0);
	}

	KeReleaseMutex(&kvm_lock, FALSE);

	return status;
}

struct kvm* kvm_create_vm(unsigned long type) {
	UNREFERENCED_PARAMETER(type);
	struct kvm* kvm = kvm_arch_alloc_vm();

	if (!kvm)
		return NULL;


	KVM_MMU_LOCK_INIT(kvm);
	KeInitializeMutex(&kvm->lock, 0);
	KeInitializeMutex(&kvm->irq_lock, 0);

	NTSTATUS status;

	status = hardware_enable_all();

	return kvm;
}