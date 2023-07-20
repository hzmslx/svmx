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

bool kvm_rebooting;


int kvm_init(unsigned vcpu_size, unsigned vcpu_align){
	UNREFERENCED_PARAMETER(vcpu_align);
	UNREFERENCED_PARAMETER(vcpu_size);
	NTSTATUS status = STATUS_SUCCESS;
	
	KeInitializeMutex(&kvm_lock, 0);

	return status;
}

void kvm_disable_largepages() {
	largepages_enabled = FALSE;
}

void kvm_exit(void) {
	


}

NTSTATUS kvm_dev_ioctl_create_vm(unsigned long type) {
	struct kvm* kvm;

	// the main implementation of creating vm
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
	// we increment the count only here
	kvm_usage_count++;
	if (kvm_usage_count == 1) {
		// 只有第一次才会调用
		// for each cpu
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
	// enable the hardware
	status = hardware_enable_all();

	return kvm;
}

static int kvm_offline_cpu(unsigned int cpu)
{
	UNREFERENCED_PARAMETER(cpu);
	KeWaitForSingleObject(&kvm_lock, Executive, KernelMode, FALSE, NULL);
	if (kvm_usage_count)
		hardware_enable_nolock(NULL);
	KeReleaseMutex(&kvm_lock, FALSE);
}


static int kvm_suspend(void) {
	/*
	* Secondary CPUs and CPU hotplug are disabled across the suspend/resume
	* callbacks, i.e. no need to acquire kvm_lock to ensure the usage count
	* is stable.  Assert that kvm_lock is not held to ensure the system
	* isn't suspended while KVM is enabling hardware.  Hardware enabling
	* can be preempted, but the task cannot be frozen until it has dropped
	* all locks (userspace tasks are frozen via a fake signal).
	*/
	if (kvm_usage_count)
		hardware_enable_nolock(NULL);

	return 0;
}

static ULONG_PTR DisableHardware(
	_In_ ULONG_PTR Argument
) {
	UNREFERENCED_PARAMETER(Argument);
	kvm_arch_hardware_disable();
	return 0;
}

static void hardware_disable_all_nolock(void) {
	// 当前虚拟机不再使用,所以减一
	kvm_usage_count--;
	// 系统中没有虚拟机时,关闭硬件虚拟化功能
	if (!kvm_usage_count)
		KeIpiGenericCall(DisableHardware, 0);
}

static void hardware_disable_all(void) {
	KeWaitForSingleObject(&kvm_lock, Executive, KernelMode, FALSE, NULL);
	hardware_disable_all_nolock();
	KeReleaseMutex(&kvm_lock, FALSE);
}

static void kvm_destroy_vm(struct kvm* kvm) {
	UNREFERENCED_PARAMETER(kvm);
	hardware_disable_all();
}

void kvm_put_kvm(struct kvm* kvm) {
	UNREFERENCED_PARAMETER(kvm);
	
}

static void hardware_disable_nolock(void* junk) {
	UNREFERENCED_PARAMETER(junk);
	/*
	* Note, hardware_disable_all_nolock() tells all online CPUs to disable
	* hardware, not just CPUs that successfully enabled hardware!
	*/
	kvm_arch_hardware_disable();
}

static void kvm_shutdown(void) {
	/*
	* Disable hardware virtualization and set kvm_rebooting to indicate
	* that KVM has asynchronously disabled hardware virtualization, i.e.
	* that relevant errors and exceptions aren't entirely unexpected.
	* Some flavors of hardware virtualization need to be disabled before
	* transferring control to firmware (to perform shutdown/reboot), e.g.
	* on x86, virtualization can block INIT interrupts, which are used by
	* firmware to pull APs back under firmware control.  Note, this path
	* is used for both shutdown and reboot scenarios, i.e. neither name is
	* 100% comprehensive.
	*/
	kvm_rebooting = TRUE;
	hardware_disable_nolock(NULL);
}

static void kvm_resume(void) {
	if (kvm_usage_count)
		__hardware_enable_nolock();
}