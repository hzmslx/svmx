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

struct kvm_x86_ops kvm_x86_ops;
bool allow_smaller_maxphyaddr = 0;


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
	return STATUS_SUCCESS;
}

void kvm_arch_check_processor_compat() {
	kvm_x86_ops.check_processor_compatibility();
}

void kvm_enable_efer_bits(u64 mask) {
	efer_reserved_bits &= ~mask;
}

void kvm_arch_hardware_enable(void* garbage) {
	UNREFERENCED_PARAMETER(garbage);
	kvm_x86_ops.hardware_enable();
}

void kvm_get_segment(struct kvm_vcpu* vcpu,
	struct kvm_segment* var, int seg)
{
	kvm_x86_ops.get_segment(vcpu, var, seg);
}

void kvm_get_cs_db_l_bits(struct kvm_vcpu* vcpu, int* db, int* l)
{
	struct kvm_segment cs;

	kvm_get_segment(vcpu, &cs, VCPU_SREG_CS);
	*db = cs.db;
	*l = cs.l;
}

NTSTATUS __kvm_x86_vendor_init(struct kvm_x86_init_ops* ops) {
	UNREFERENCED_PARAMETER(ops);

	if (kvm_x86_ops.hardware_enable) {
		LogError("Already loaeded vendor module\n");
		return STATUS_UNSUCCESSFUL;
	}

	
	return STATUS_SUCCESS;
}

NTSTATUS kvm_x86_vendor_init(struct kvm_x86_init_ops* ops) {
	NTSTATUS status;
	status = __kvm_x86_vendor_init(ops);
	return status;
}

void kvm_x86_vendor_exit(void) {

}