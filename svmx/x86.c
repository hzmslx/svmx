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

KMUTEX vendor_module_lock;

u64 host_efer;


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

void kvm_arch_check_processor_compat() {
	kvm_x86_ops.check_processor_compatibility();
}

void kvm_enable_efer_bits(u64 mask) {
	efer_reserved_bits &= ~mask;
}

int kvm_arch_hardware_enable(void) {
	int ret;

	// open the hardware feature
	ret = kvm_x86_ops.hardware_enable();
	if (ret != 0)
		return ret;

	return 0;
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

static inline void kvm_ops_update(struct kvm_x86_init_ops* ops) {
	memcpy(&kvm_x86_ops, ops->runtime_ops, sizeof(kvm_x86_ops));
}

static int kvm_x86_check_processor_compatibility(void) {
	return kvm_x86_ops.check_processor_compatibility();
}

static void kvm_x86_check_cpu_compat(void* ret) {
	*(int*)ret = kvm_x86_check_processor_compatibility();
}

static ULONG_PTR CheckCpuCompat(
	_In_ ULONG_PTR Argument
) {
	UNREFERENCED_PARAMETER(Argument);
	int ret = 0;
	kvm_x86_check_cpu_compat(&ret);
	return 0;
}

NTSTATUS __kvm_x86_vendor_init(struct kvm_x86_init_ops* ops) {
	u64 host_pat;
	NTSTATUS status = STATUS_SUCCESS;

	if (kvm_x86_ops.hardware_enable) {
		LogErr("Already loaeded vendor module\n");
		return STATUS_UNSUCCESSFUL;
	}

	/*
	* KVM assumes that PAT entry '0' encodes WB memtype and simply zeroes
	* the PAT bits in SPTEs.  Bail if PAT[0] is programmed to something
	* other than WB.  Note, EPT doesn't utilize the PAT, but don't bother
	* with an exception.  PAT[0] is set to WB on RESET and also by the
	* kernel, i.e. failure indicates a kernel bug or broken firmware.
	*/
	host_pat = __readmsr(MSR_IA32_CR_PAT);
	
	host_efer = __readmsr(MSR_EFER);

	bool out_mmu_exit = FALSE;
	do
	{
		status = ops->hardware_setup();
		if (!NT_SUCCESS(status)) {
			out_mmu_exit = TRUE;
			break;
		}

		kvm_ops_update(ops);

		KeIpiGenericCall(CheckCpuCompat, 0);

	} while (FALSE);
	
	if (out_mmu_exit) {
		
	}
	
	return status;
}

NTSTATUS kvm_x86_vendor_init(struct kvm_x86_init_ops* ops) {
	NTSTATUS status;
	KeWaitForSingleObject(&vendor_module_lock, Executive, 
		KernelMode, FALSE, NULL);
	status = __kvm_x86_vendor_init(ops);
	KeReleaseMutex(&vendor_module_lock, FALSE);
	return status;
}

void kvm_x86_vendor_exit(void) {

	kvm_x86_ops.hardware_unsetup();

	KeWaitForSingleObject(&vendor_module_lock, Executive, 
		KernelMode, FALSE, NULL);
	kvm_x86_ops.hardware_enable = NULL;
	KeReleaseMutex(&vendor_module_lock, FALSE);
}

void kvm_arch_hardware_disable(void) {
	kvm_x86_ops.hardware_disable();
}

static void hardware_disable_nolock(void* junk) {
	UNREFERENCED_PARAMETER(junk);
	/*
	* Note, hardware_disable_all_nolock() tells all online CPUs to disable
	* hardware, not just CPUs that successfully enabled hardware!
	*/

	kvm_arch_hardware_disable();
}

static bool kvm_vcpu_running(struct kvm_vcpu* vcpu) {
	return (vcpu->arch.mp_state == KVM_MP_STATE_RUNNABLE &&
		!vcpu->arch.apf.halted);
}

/*
 * Called within kvm->srcu read side.
 * Returns 1 to let vcpu_run() continue the guest execution loop without
 * exiting to the userspace.  Otherwise, the value will be returned to the
 * userspace.
 */
static int vcpu_enter_guest(struct kvm_vcpu* vcpu)
{
	UNREFERENCED_PARAMETER(vcpu);
	int r = 0;
	
	fastpath_t exit_fastpath;

	for (;;) {
		/*
		* Assert that vCPU vs. VM APICv state is consistent.  An APICv
		* update must kick and wait for all vCPUs before toggling the
		* per-VM state, and responsing vCPUs must wait for the update
		* to complete before servicing KVM_REQ_APICV_UPDATE.
		*/
		exit_fastpath = kvm_x86_ops.vcpu_run(vcpu);
		if (exit_fastpath != EXIT_FASTPATH_REENTER_GUEST)
			break;
		
	}

	// vmexit的处理
	r = kvm_x86_ops.handle_exit(vcpu, exit_fastpath);

	return r;
}

/* Called within kvm->srcu read side.  */
static int vcpu_block(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);

	return 1;
}

static int vcpu_run(struct kvm_vcpu* vcpu) {
	int r = 0;

	vcpu->arch.l1tf_flush_l1d = TRUE;

	for (;;) {
		/*
		* If another guest vCPU requests a PV TLB flush in the middle
		* of instruction emulation, the rest of the emulation could
		* use a stale page translation. Assume that any code after
		* this point can start executing an instruction.
		*/
		vcpu->arch.at_instruction_boundary = FALSE;
		if (kvm_vcpu_running(vcpu)) {
			r = vcpu_enter_guest(vcpu);
		}
		else {
			r = vcpu_block(vcpu);
		}

		if (r <= 0)
			break;
	}

	return r;
}

int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu* vcpu) {
	int r;

	// 死循环进入vcpu_enter_guest
	r = vcpu_run(vcpu);

	return r;
}

int kvm_arch_vcpu_create(struct kvm_vcpu* vcpu) {
	int r;

	// 创建vcpu
	r = kvm_x86_ops.vcpu_create(vcpu);

	// 加载vcpu
	vcpu_load(vcpu);

	return r;
}

void kvm_arch_vcpu_load(struct kvm_vcpu* vcpu, int cpu) {
	kvm_x86_ops.vcpu_load(vcpu, cpu);
}