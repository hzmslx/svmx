#include "pch.h"
#include "kvm_host.h"
#include "kvm.h"
#include "kvm_mm.h"
#include "x86.h"

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
	int cpu = KeGetCurrentProcessorNumber();
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

static void hardware_disable_nolock(void* junk) {
	UNREFERENCED_PARAMETER(junk);
	int cpu = KeGetCurrentProcessorNumber();
	if (!hardware_enabled[cpu])
		return;

	/*
	* Note, hardware_disable_all_nolock() tells all online CPUs to disable
	* hardware, not just CPUs that successfully enabled hardware!
	*/
	kvm_arch_hardware_disable();

	hardware_enabled[cpu] = FALSE;
}

static void hardware_disable_all_nolock(void) {
	// 当前虚拟机不再使用,所以减一
	kvm_usage_count--;
	// 系统中没有虚拟机时,关闭硬件虚拟化功能
	if (!kvm_usage_count)
		hardware_disable_nolock(NULL);
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

// 虚拟机创建vcpu的ioctl调用的入口函数
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
		RtlZeroMemory(vcpu, s_vcpu_size);

		page = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, DRIVER_TAG);
		if (!page) {
			r = STATUS_NO_MEMORY;
			break;
		}
		RtlZeroMemory(page, PAGE_SIZE);
		vcpu->run = page;
		// 初始化vmx中的vcpu结构
		kvm_vcpu_init(vcpu, kvm, id);


		// 初始化kvm_vcpu_arch结构体, 架构相关
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
	int run_ret = vm_save_state(vcpu);
	if (run_ret < 0) {
		// error: kvm run failed
		struct kvm_run* run = vcpu->run;
		run_ret = kvm_arch_handle_exit(vcpu, run);
	}
	return run_ret;
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
			struct kvm_userspace_memory_region kvm_userspace_mem;
			r = kvm_vm_ioctl_set_memory_region(g_kvm, &kvm_userspace_mem);
			break;
		}

		default:
			break;
	}

	return r;
}

int kvm_set_memory_region(struct kvm* kvm,
	const struct kvm_userspace_memory_region* mem) {
	int r = 0;
	KeWaitForSingleObject(&kvm->slots_loc, Executive, KernelMode, FALSE, NULL);
	r = __kvm_set_memory_region(kvm, mem);
	KeReleaseMutex(&kvm->slots_loc, FALSE);
	return r;
}

static int check_memory_region_flags(const struct kvm_userspace_memory_region* mem) {
	u32 valid_flags = KVM_MEM_LOG_DIRTY_PAGES;

	valid_flags |= KVM_MEM_READONLY;

	if (mem->flags & ~valid_flags)
		return STATUS_INVALID_PARAMETER;

	return STATUS_SUCCESS;
}

static bool kvm_check_memslot_overlap(struct kvm_memslots* slots, int id,
	gfn_t start, gfn_t end) {
	UNREFERENCED_PARAMETER(slots);
	UNREFERENCED_PARAMETER(id);
	UNREFERENCED_PARAMETER(start);
	UNREFERENCED_PARAMETER(end);
	// struct kvm_memslot_iter iter;

	return FALSE;
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
	struct kvm_memory_slot* old, * new;
	struct kvm_memslots* slots;
	enum kvm_mr_change change;
	ULONG_PTR npages;
	gfn_t base_gfn;
	u16 as_id, id;
	int r;

	r = check_memory_region_flags(mem);
	if (r)
		return r;

	as_id = mem->slot >> 16;
	id = (u16)mem->slot;

	/* General sanity checks */
	// 要求以页为单位
	if ((mem->memory_size & (PAGE_SIZE - 1)) ||
		(mem->memory_size != (ULONG_PTR)mem->memory_size))
		return STATUS_INVALID_PARAMETER;
	// 要求页对齐
	if (mem->guest_phys_addr & (PAGE_SIZE - 1))
		return STATUS_INVALID_PARAMETER;
	// 保证线性地址页对齐
	if ((mem->userspace_addr & (PAGE_SIZE - 1)))
		return STATUS_INVALID_PARAMETER;
	if (as_id >= KVM_ADDRESS_SPACE_NUM || id >= KVM_MEM_SLOTS_NUM)
		return STATUS_INVALID_PARAMETER;
	if (mem->guest_phys_addr + mem->memory_size < mem->guest_phys_addr)
		return STATUS_INVALID_PARAMETER;
	if ((mem->memory_size >> PAGE_SHIFT) > KVM_MEM_MAX_NR_PAGES)
		return STATUS_INVALID_PARAMETER;

	slots = __kvm_memslots(kvm, as_id);

	/*
	* Note, the old memslot (and the pointer itself!) may be invalidated
	* and/or destroyed by kvm_set_memslot().
	*/
	old = id_to_memslot(slots, id);

	if (!mem->memory_size) {
		if (!old || !old->npages)
			return STATUS_INVALID_PARAMETER;

		if (kvm->nr_memslot_pages < old->npages)
			return STATUS_UNSUCCESSFUL;

		return kvm_set_memslot(kvm, old, NULL, KVM_MR_DELETE);
	}

	base_gfn = (mem->guest_phys_addr >> PAGE_SHIFT);
	npages = (mem->memory_size >> PAGE_SHIFT);

	if (!old || !old->npages) {
		change = KVM_MR_CREATE;

		/*
		* To simplify KVM internals, the total number of pages across
		* all memslots must fit in an unsigned long.
		*/
		if ((kvm->nr_memslot_pages + npages) < kvm->nr_memslot_pages)
			return STATUS_INVALID_PARAMETER;
	}
	else { /* Modify an existing slot. */
		if ((mem->userspace_addr != old->userspace_addr) ||
			(npages != old->npages) ||
			((mem->flags ^ old->flags) & KVM_MEM_READONLY))
			return STATUS_INVALID_PARAMETER;

		if (base_gfn != old->base_gfn)
			change = KVM_MR_MOVE; // 内存平移
		else if (mem->flags != old->flags)
			change = KVM_MR_FLAGS_ONLY;// 修改属性
		else /* Nothing to change */
			return 0;
	}

	if ((change == KVM_MR_CREATE || change == KVM_MR_MOVE) &&
		kvm_check_memslot_overlap(slots, id, base_gfn, base_gfn + npages))
		return STATUS_ALREADY_COMMITTED;

	/* Allocate a slot that will persist in the memslot. */
	new = ExAllocatePoolWithTag(NonPagedPool, sizeof(*new), DRIVER_TAG);
	if (!new) {
		return STATUS_NO_MEMORY;
	}

	new->as_id = as_id;
	new->id = id;
	new->base_gfn = base_gfn;
	new->npages = npages;
	new->flags = mem->flags;
	new->userspace_addr = mem->userspace_addr;

	r = kvm_set_memslot(kvm, old, new, change);
	if (r)
		ExFreePool(new);

	return r;
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
	ULONG count = KeQueryActiveProcessorCount(0);
	struct kvm_vcpu* vcpu;
	for (ULONG i = 0; i < count; i++) {
		vcpu = g_kvm->vcpu_array[i];
		kvm_vcpu_destroy(vcpu);
	}
	
}

int kvm_mmu_topup_memory_cache(struct kvm_mmu_memory_cache* mc, int min) {
	return __kvm_mmu_topup_memory_cache(mc, 
		KVM_ARCH_NR_OBJS_PER_MEMORY_CACHE, min);
}

static void* mmu_memory_cache_alloc_obj(struct kvm_mmu_memory_cache* mc) {
	UNREFERENCED_PARAMETER(mc);
	void* obj = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, DRIVER_TAG);
	if (obj != NULL)
		RtlZeroMemory(obj, PAGE_SIZE);
	return obj;
}

int __kvm_mmu_topup_memory_cache(struct kvm_mmu_memory_cache* mc, int capacity, int min){
	void* obj;

	if (mc->nobjs >= min)
		return STATUS_SUCCESS;

	if (!mc->objects) {
		if (!capacity)
			return STATUS_IO_DEVICE_ERROR;

		mc->objects = ExAllocatePoolWithTag(NonPagedPool, 
			sizeof(void*) * capacity,DRIVER_TAG);
		if (!mc->objects)
			return STATUS_NO_MEMORY;

		mc->capacity = capacity;
	}

	/* It is illegal to request a different capacity across topups. */
	if (mc->capacity != capacity)
		return STATUS_IO_DEVICE_ERROR;

	while (mc->nobjs < mc->capacity) {
		obj = mmu_memory_cache_alloc_obj(mc);
		if (!obj)
			return mc->nobjs >= min ? STATUS_SUCCESS : STATUS_NO_MEMORY;
		mc->objects[mc->nobjs++] = obj;
	}

	return STATUS_SUCCESS;
}

void* kvm_mmu_memory_cache_alloc(struct kvm_mmu_memory_cache* mc) {
	void* p;

	if (!mc->nobjs)
		p = mmu_memory_cache_alloc_obj(mc);
	else
		p = mc->objects[--mc->nobjs];
	return p;
}