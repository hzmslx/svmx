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
LIST_ENTRY vm_list;

static int kvm_usage_count = 0;

static bool largepages_enabled = TRUE;

bool kvm_rebooting;

bool* hardware_enabled = NULL;

struct kvm* g_kvm = NULL;

static ULONG s_vcpu_size;


int kvm_init(unsigned vcpu_size, unsigned vcpu_align) {
	UNREFERENCED_PARAMETER(vcpu_align);
	NTSTATUS status = STATUS_SUCCESS;

	s_vcpu_size = vcpu_size;

	KeInitializeMutex(&kvm_lock, 0);
	InitializeListHead(&vm_list);

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
	

	g_kvm = kvm;
	return STATUS_SUCCESS;
}

static int __hardware_enable_nolock(void) {
	int cpu = KeGetCurrentNodeNumber();
	if (hardware_enabled[cpu])
		return 0;

	if (kvm_arch_hardware_enable()) {
		return -1;
	}

	hardware_enabled[cpu] = TRUE;
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
	// 开启硬件虚拟化功能
	hardware_enable_nolock(NULL);
	return 0;
}

// 针对每个cpu执行hardware_enable_nolock
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
	int i, j;
	/*
	 * 分配 kvm 结构体, 一个虚拟机对应一个 kvm 结构, 其中包括了虚拟机中的
	 * 关键信息, 比如内存、中断、VCPU、总线等信息, 该结构体也是 kvm 的关键结
	 * 构体之一
	 */
	struct kvm* kvm = kvm_arch_alloc_vm();

	if (!kvm)
		return NULL;

	KVM_MMU_LOCK_INIT(kvm);
	KeInitializeMutex(&kvm->lock, 0);
	KeInitializeMutex(&kvm->irq_lock, 0);
	KeInitializeMutex(&kvm->slots_loc, 0);
	KeInitializeMutex(&kvm->slots_arch_lock, 0);
	kvm->max_vcpus = KeQueryActiveProcessorCount(0);
	
	sprintf_s(kvm->stats_id, sizeof(kvm->stats_id), "kvm-%d",
		HandleToUlong(PsGetCurrentProcessId()));




	for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++) {
		for (j = 0; j < 2; j++) {

		}
	}


	NTSTATUS status;
	status = kvm_arch_init_vm(kvm, type);

	// enable the hardware
	// 调用架构相关的kvm_x86_ops->hardware_enable()接口进行硬件使能
	status = hardware_enable_all();

	status = kvm_arch_post_init_vm(kvm);


	KeWaitForSingleObject(&kvm_lock, Executive, KernelMode, FALSE, NULL);
	// 将新创建的虚拟机加入KVM的虚拟机列表
	InsertHeadList(&vm_list, &kvm->vm_list);
	KeReleaseMutex(&kvm_lock, FALSE);

	SIZE_T size = sizeof(void*) * KeQueryActiveProcessorCount(0);
	kvm->vcpu_array = ExAllocatePoolWithTag(NonPagedPool,
		size,DRIVER_TAG);
	if (!kvm->vcpu_array) {
		ExFreePool(kvm);
		kvm = NULL;
		return NULL;
	}
	RtlZeroMemory(kvm->vcpu_array, size);

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
	KeWaitForSingleObject(&kvm_lock, Executive, KernelMode, FALSE, NULL);
	RemoveEntryList(&kvm->vm_list);
	KeReleaseMutex(&kvm_lock, FALSE);
	kvm_arch_pre_destroy_vm(kvm);

	kvm_arch_destroy_vm(kvm);

	hardware_disable_all();
}

void kvm_put_kvm(struct kvm* kvm) {
	kvm_destroy_vm(kvm);
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

static void kvm_vcpu_init(struct kvm_vcpu* vcpu, struct kvm* kvm, unsigned id) {
	KeInitializeMutex(&vcpu->mutex, 0);
	vcpu->cpu = -1;
	vcpu->kvm = kvm;
	vcpu->vcpu_id = id;
	vcpu->pid = 0;
	vcpu->preempted = FALSE;
	vcpu->ready = FALSE;
	vcpu->last_used_slot = NULL;

	sprintf_s(vcpu->stats_id, sizeof(vcpu->stats_id), "vcpu-%d", id);
}

int kvm_vm_ioctl_create_vcpu(struct kvm* kvm, u32 id) {
	int r;
	struct kvm_vcpu* vcpu = NULL;
	void* page = NULL;

	do
	{
		KeWaitForSingleObject(&kvm->lock, Executive, KernelMode, FALSE, NULL);
		if (kvm->created_vcpus >= kvm->max_vcpus) {
			KeReleaseMutex(&kvm->lock, FALSE);
			return STATUS_INVALID_PARAMETER;
		}

		r = kvm_arch_vcpu_precreate(kvm, id);
		if (r) {
			KeReleaseMutex(&kvm->lock, FALSE);
			return r;
		}

		kvm->created_vcpus++;
		KeReleaseMutex(&kvm->lock, FALSE);

		vcpu = ExAllocatePoolWithTag(NonPagedPool, s_vcpu_size, DRIVER_TAG);
		if (!vcpu) {
			r = STATUS_NO_MEMORY;
			break;
		}

		page = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, DRIVER_TAG);
		if (!page) {
			r = STATUS_NO_MEMORY;
			break;
		}
		RtlZeroMemory(page, PAGE_SIZE);
		vcpu->run = page;

		kvm_vcpu_init(vcpu, kvm, id);


		// 创建 vcpu 结构, 架构相关
		r = kvm_arch_vcpu_create(vcpu);
		if (r) {
			break;
		}

		kvm_arch_vcpu_postcreate(vcpu);

		kvm->vcpu_array[id] = vcpu;
		return r;
	} while (FALSE);


	if (!NT_SUCCESS(r)) {
		if (vcpu != NULL) {
			ExFreePool(vcpu);
		}
		if (page != NULL) {
			ExFreePool(page);
		}
	}

	return r;
}

void vcpu_load(struct kvm_vcpu* vcpu) {
	int cpu = vcpu->vcpu_id;
	kvm_arch_vcpu_load(vcpu, cpu);
}

ULONG_PTR RunKvm(ULONG_PTR Arg) {
	UNREFERENCED_PARAMETER(Arg);
	KIRQL irql = KeGetCurrentIrql();
	LogErr("irql: 0x%x\n", irql);
	int cpu = KeGetCurrentProcessorNumber();
	struct kvm_vcpu* vcpu = g_kvm->vcpu_array[cpu];
	int run_ret = kvm_arch_vcpu_ioctl_run(vcpu);
	int r = STATUS_SUCCESS;
	if (run_ret < 0) {
		// error: kvm run failed
	}
	struct kvm_run* run = vcpu->run;
	r = kvm_arch_handle_exit(vcpu, run);
	return r;
}

long kvm_vcpu_ioctl(unsigned int ioctl, PIRP Irp) {
	UNREFERENCED_PARAMETER(Irp);
	NTSTATUS status = STATUS_INVALID_PARAMETER;
	switch (ioctl)
	{
		case KVM_RUN:
		{
			ULONG_PTR r = KeIpiGenericCall(RunKvm, 0);
			status = (NTSTATUS)r;
			break;
		}
		

		default:
			break;
	}

	return status;
}

kvm_pfn_t __gfn_to_pfn_memslot(const struct kvm_memory_slot* slot, gfn_t gfn,
	bool atomic, bool interruptible, bool* async,
	bool write_fault, bool* writable, hva_t* hva) {
	UNREFERENCED_PARAMETER(slot);
	UNREFERENCED_PARAMETER(gfn);
	UNREFERENCED_PARAMETER(atomic);
	UNREFERENCED_PARAMETER(interruptible);
	UNREFERENCED_PARAMETER(async);
	UNREFERENCED_PARAMETER(write_fault);
	UNREFERENCED_PARAMETER(writable);
	UNREFERENCED_PARAMETER(hva);

	return 0;
}

static int kvm_vm_ioctl_set_memory_region(struct kvm* kvm,
	struct kvm_userspace_memory_region* mem)
{
	if ((u16)mem->slot >= KVM_USER_MEM_SLOTS)
		return STATUS_INVALID_PARAMETER;

	return kvm_set_memory_region(kvm, mem);
}

static long kvm_vm_ioctl(unsigned int ioctl, unsigned long arg) {
	UNREFERENCED_PARAMETER(arg);
	int r = 0;

	switch (ioctl)
	{

		// 建立 guest 物理地址空间中的内存区域与 qemu-kvm 虚拟地址空间中的内存区域的映射
		case KVM_SET_USER_MEMORY_REGION:
		{


			break;
		}

		default:
			break;
	}

	return r;
}

int kvm_set_memory_region(struct kvm* kvm,
	const struct kvm_userspace_memory_region* mem) {
	UNREFERENCED_PARAMETER(kvm);
	UNREFERENCED_PARAMETER(mem);
	int r = 0;

	return r;
}

/*
 * Allocate some memory and give it an address in the guest physical address
 * space.
 *
 * Discontiguous memory is allowed, mostly for framebuffers.
 *
 * Must be called holding kvm->slots_lock for write.
 */
int __kvm_set_memory_region(struct kvm* kvm,
	const struct kvm_userspace_memory_region* mem) {
	UNREFERENCED_PARAMETER(kvm);
	UNREFERENCED_PARAMETER(mem);

	return 0;
}

/*
 * Replace @old with @new in the inactive memslots.
 *
 * With NULL @old this simply adds @new.
 * With NULL @new this simply removes @old.
 *
 * If @new is non-NULL its hva_node[slots_idx] range has to be set
 * appropriately.
 */
static void kvm_replace_memslot(struct kvm* kvm,
	struct kvm_memory_slot* old,
	struct kvm_memory_slot* new) {
	UNREFERENCED_PARAMETER(kvm);
	UNREFERENCED_PARAMETER(old);
	UNREFERENCED_PARAMETER(new);
}

/*
 * Activate @new, which must be installed in the inactive slots by the caller,
 * by swapping the active slots and then propagating @new to @old once @old is
 * unreachable and can be safely modified.
 *
 * With NULL @old this simply adds @new to @active (while swapping the sets).
 * With NULL @new this simply removes @old from @active and frees it
 * (while also swapping the sets).
 */
static void kvm_activate_memslot(struct kvm* kvm,
	struct kvm_memory_slot* old,
	struct kvm_memory_slot* new)
{
	UNREFERENCED_PARAMETER(kvm);
	UNREFERENCED_PARAMETER(old);
	UNREFERENCED_PARAMETER(new);
}

static void kvm_delete_memslot(struct kvm* kvm,
	struct kvm_memory_slot* old,
	struct kvm_memory_slot* invalid_slot)
{
	/*
	 * Remove the old memslot (in the inactive memslots) by passing NULL as
	 * the "new" slot, and for the invalid version in the active slots.
	 */
	kvm_replace_memslot(kvm, old, NULL);
	kvm_activate_memslot(kvm, invalid_slot, NULL);
}


/* This does not remove the slot from struct kvm_memslots data structures */
static void kvm_free_memslot(struct kvm* kvm, struct kvm_memory_slot* slot)
{
	UNREFERENCED_PARAMETER(kvm);
	UNREFERENCED_PARAMETER(slot);
}

static int kvm_set_memslot(struct kvm* kvm,
	struct kvm_memory_slot* old,
	struct kvm_memory_slot* new,
	enum kvm_mr_change change) {
	UNREFERENCED_PARAMETER(kvm);
	UNREFERENCED_PARAMETER(old);
	UNREFERENCED_PARAMETER(new);
	UNREFERENCED_PARAMETER(change);

	return 0;
}

void vcpu_put(struct kvm_vcpu* vcpu) {
	kvm_arch_vcpu_put(vcpu);
}

/*
 * Emulate a vCPU halt condition, e.g. HLT on x86, WFI on arm, etc...  If halt
 * polling is enabled, busy wait for a short time before blocking to avoid the
 * expensive block+unblock sequence if a wake event arrives soon after the vCPU
 * is halted.
 */
void kvm_vcpu_halt(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
}

/*
 * Block the vCPU until the vCPU is runnable, an event arrives, or a signal is
 * pending.  This is mostly used when halting a vCPU, but may also be used
 * directly for other vCPU non-runnable states, e.g. x86's Wait-For-SIPI.
 */
bool kvm_vcpu_block(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	bool waited = FALSE;

	return waited;
}

int kvm_arch_handle_exit(struct kvm_vcpu* vcpu, struct kvm_run* run) {
	UNREFERENCED_PARAMETER(vcpu);
	int ret = STATUS_UNSUCCESSFUL;

	switch (run->exit_reason)
	{
		case KVM_EXIT_FAIL_ENTRY:
			cpu_emergency_vmxoff();
			break;
		default:
			break;
	}

	return ret;
}

static void kvm_vcpu_destroy(struct kvm_vcpu* vcpu) {
	kvm_arch_vcpu_destroy(vcpu);

}

void kvm_destroy_vcpus(struct kvm* kvm) {
	UNREFERENCED_PARAMETER(kvm);
	ULONG count = KeGetCurrentProcessorNumber();
	struct kvm_vcpu* vcpu;
	for (ULONG i = 0; i < count; i++) {
		vcpu = g_kvm->vcpu_array[i];
		kvm_vcpu_destroy(vcpu);
	}
	
}