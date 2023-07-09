#include "pch.h"
#include "x86.h"
#include "kvm_host.h"
#include "kvm_para.h"
#include "mmu.h"

/* EFER defaults:
* - enable syscall per default because its emulated by KVM
* - enable LME and LMA per default on 64 bit KVM
*/
#ifdef _WIN64
static u64 efer_reserved_bits = 0xfffffffffffffafeULL;
#else
static u64 efer_reserved_bits = 0xfffffffffffffffeULL;
#endif

struct kvm_x86_ops* kvm_x86_ops;


/*
 * List of msr numbers which we expose to userspace through KVM_GET_MSRS
 * and KVM_SET_MSRS, and KVM_GET_MSR_INDEX_LIST.
 *
 * This list is modified at module load time to reflect the
 * capabilities of the host cpu.
 */
static u32 msrs_to_save[] = {
	MSR_IA32_SYSENTER_CS, MSR_IA32_SYSENTER_ESP, MSR_IA32_SYSENTER_EIP,
	MSR_K6_STAR,
#ifdef _WIN64
	MSR_CSTAR, MSR_KERNEL_GS_BASE, MSR_SYSCALL_MASK, MSR_LSTAR,
#endif
	MSR_IA32_TSC, MSR_KVM_SYSTEM_TIME, MSR_KVM_WALL_CLOCK,
	MSR_IA32_PERF_STATUS, MSR_IA32_CR_PAT, MSR_VM_HSAVE_PA
};

NTSTATUS kvm_arch_init(void* opaque) {
	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(opaque);
	
	struct kvm_x86_ops* ops = (struct kvm_x86_ops*)opaque;

	do
	{
		if (kvm_x86_ops) {
			Log(KERN_ERR, "kvm: aready loaded the other module\n");
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		if (!ops->cpu_has_kvm_support()) {
			Log(KERN_ERR, "kvm: no hardware support\n");
			status = STATUS_NOT_SUPPORTED;
			break;
		}

		if (ops->disabled_by_bios()) {
			Log(KERN_ERR, "kvm: disabled by bios\n");
			status = STATUS_NOT_SUPPORTED;
			break;
		}

		status = kvm_mmu_module_init();
		if (!NT_SUCCESS(status))
			break;

		kvm_init_msr_list();

		kvm_x86_ops = ops;
		kvm_mmu_set_nonpresent_ptes(0ull, 0ull);
		kvm_mmu_set_base_ptes(PT_PRESENT_MASK);
		kvm_mmu_set_mask_ptes(PT_USER_MASK, PT_ACCESSED_MASK,
			PT_DIRTY_MASK, PT64_NX_MASK, 0);

		return STATUS_SUCCESS;
	} while (FALSE);
	
	

	return status;
}

void kvm_init_msr_list() {
	u64 dummy;
	unsigned i, j;

	for (i = j = 0; i < ARRAYSIZE(msrs_to_save); i++) {
		dummy = __readmsr(msrs_to_save[i]);
		if (j < i)
			msrs_to_save[j] = msrs_to_save[i];
		j++;
	}
	
}

NTSTATUS kvm_arch_hardware_setup() {
	return kvm_x86_ops->hardware_setup();
}

void kvm_arch_check_processor_compat(void* rtn) {
	kvm_x86_ops->check_processor_compatibility(rtn);
}

void kvm_enable_efer_bits(u64 mask) {
	efer_reserved_bits &= ~mask;
}