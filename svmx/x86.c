#include "pch.h"
#include "x86.h"
#include "kvm_host.h"
#include "kvm_para.h"
#include "mmu.h"
#include "kvm_cache_regs.h"

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

bool enable_vmware_backdoor = FALSE;

static u64 cr4_reserved_bits = CR4_RESERVED_BITS;

bool enable_apicv = TRUE;

u32 kvm_nr_uret_msrs;

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

static void update_cr8_intercept(struct kvm_vcpu* vcpu);


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

	// 主要设置相关寄存器和标记，使cpu进入虚拟化相关模式
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

#define KVM_MAX_MCE_BANKS 32

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
	int r = 0;
	
	fastpath_t exit_fastpath;

	/* 进入guest 模式前先处理相关挂起的请求 */
	if (kvm_request_pending(vcpu)) {

		
	}

	

	// 加载mmu
	r = kvm_mmu_reload(vcpu);

	// 准备陷入到guest
	kvm_x86_ops.prepare_switch_to_guest(vcpu);



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
	
	// vmexit的处理,处理虚拟机异常
	r = kvm_x86_ops.handle_exit(vcpu, exit_fastpath);

	return r;
}

static inline bool kvm_vcpu_has_events(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return FALSE;
}

int kvm_arch_vcpu_runnable(struct kvm_vcpu* vcpu) {
	return kvm_vcpu_running(vcpu) || kvm_vcpu_has_events(vcpu);
}

/* Called within kvm->srcu read side.  */
static int vcpu_block(struct kvm_vcpu* vcpu) {
	
	if (!kvm_arch_vcpu_runnable(vcpu)) {

		if (vcpu->arch.mp_state == KVM_MP_STATE_HALTED)
			kvm_vcpu_halt(vcpu);
		else
			kvm_vcpu_block(vcpu);

		/*
		 * If the vCPU is not runnable, a signal or another host event
		 * of some kind is pending; service it without changing the
		 * vCPU's activity state.
		 */
		if (!kvm_arch_vcpu_runnable(vcpu))
			return 1;
	}

	switch (vcpu->arch.mp_state) {
		case KVM_MP_STATE_HALTED:
		case KVM_MP_STATE_AP_RESET_HOLD:
			vcpu->arch.pv.pv_unhalted = FALSE;
			vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
			__fallthrough;
		case KVM_MP_STATE_RUNNABLE:
			vcpu->arch.apf.halted = FALSE;
			break;
		case KVM_MP_STATE_INIT_RECEIVED:
			break;
		default:
			break;
	}

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
		// 判断vcpu 状态
		if (kvm_vcpu_running(vcpu)) {
			// vcpu进入guest模式
			r = vcpu_enter_guest(vcpu);
		}
		else {
			r = vcpu_block(vcpu);
		}

		// 只有运行异常的时候才退出循环
		if (r <= 0)
			break;
	}

	return r;
}

// 运行 vcpu (即运行虚拟机）的入口函数
int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu* vcpu) {
	int r;
	struct kvm_run* kvm_run = vcpu->run;

	// KVM 虚拟机 vcpu 数据结构载入物理 cpu
	vcpu_load(vcpu);
	kvm_run->flags = 0;

	if (vcpu->arch.mp_state == KVM_MP_STATE_UNINITIALIZED) {
		
	}

	r = kvm_x86_ops.vcpu_pre_run(vcpu);
	if (r <= 0)
		goto out;

	// 死循环进入vcpu_enter_guest
	r = vcpu_run(vcpu);

out:

	return r;
}

int kvm_arch_vcpu_create(struct kvm_vcpu* vcpu) {
	int r;

	vcpu->arch.last_vmentry_cpu = -1;
	vcpu->arch.regs_avail = ~0ul;
	vcpu->arch.regs_dirty = ~0ul;

	vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;

	r = kvm_mmu_create(vcpu);
	if (r < 0)
		return r;

	vcpu->arch.mcg_cap = KVM_MAX_MCE_BANKS;

	vcpu->arch.pat = MSR_IA32_CR_PAT_DEFAULT;

	// 创建vcpu
	r = kvm_x86_ops.vcpu_create(vcpu);

	// 加载vcpu
	vcpu_load(vcpu);
	kvm_vcpu_reset(vcpu, FALSE);
	kvm_init_mmu(vcpu);
	vcpu_put(vcpu);

	return r;
}

void kvm_arch_vcpu_load(struct kvm_vcpu* vcpu, int cpu) {
	kvm_x86_ops.vcpu_load(vcpu, cpu);
}

static void kvm_vcpu_write_tsc_offset(struct kvm_vcpu* vcpu, u64 l1_offset)
{
	vcpu->arch.l1_tsc_offset = l1_offset;

	kvm_x86_ops.write_tsc_offset(vcpu, vcpu->arch.l1_tsc_offset);
}

int kvm_set_cr0(struct kvm_vcpu* vcpu, unsigned long cr0) {
	
	cr0 |= X86_CR0_ET;

#ifdef _WIN64
	if (cr0 & 0xffffffff00000000UL)
		return 1;
#endif // _WIN64

	cr0 &= ~CR0_RESERVED_BITS;

	// NW 为 1，表明Not Write-through
	// 则 CD (Cache Disable) 也必须为 1
	// 否则出错 即不回写却有 memory cache(NW=1, CD=0), 显然有问题
	if ((cr0 & X86_CR0_NW) && !(cr0 & X86_CR0_CD))
		return 1;
	// PG 为 1, 表明开启 分页
	// 分页打开, 那就必须打开保护模式, 即 PE 必须为 1
	// 否则出错
	if ((cr0 & X86_CR0_PG) && !(cr0 & X86_CR0_PE))
		return 1;

	// 当 CR1.PCIDE = 1 时, 如果 guest 试图清位 CR0.PG, 则报错
	if (!(cr0 & X86_CR0_PG) &&
		(is_64_bit_mode(vcpu) || kvm_is_cr4_bit_set(vcpu, X86_CR4_PCIDE)))
		return 1;

	kvm_x86_ops.set_cr0(vcpu, cr0);

	return 0;
}

bool __kvm_is_valid_cr4(struct kvm_vcpu* vcpu, unsigned long cr4)
{
	// 如果guest尝试设置cr4值中任何一个保留位，则cr4值无效
	if (cr4 & cr4_reserved_bits)
		return FALSE;
	// guest 保留位，不能为1，否则无效
	if (cr4 & vcpu->arch.cr4_guest_rsvd_bits)
		return FALSE;

	return TRUE;
}

static bool kvm_is_valid_cr4(struct kvm_vcpu* vcpu, unsigned long cr4)
{
	return __kvm_is_valid_cr4(vcpu, cr4) &&
		kvm_x86_ops.is_valid_cr4(vcpu, cr4);
}

/*
 * Load the pae pdptrs.  Return 1 if they are all valid, 0 otherwise.
 */
int load_pdptrs(struct kvm_vcpu* vcpu, unsigned long cr3)
{
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(cr3);

	/*
	 * If the MMU is nested, CR3 holds an L2 GPA and needs to be translated
	 * to an L1 GPA.
	 */


	/* Note the offset, PDPTRs are 32 byte aligned when using PAE paging. */




	/*
	 * Marking VCPU_EXREG_PDPTR dirty doesn't work for !tdp_enabled.
	 * Shadow page roots need to be reconstructed instead.
	 */



	return 1;
}

int kvm_set_cr4(struct kvm_vcpu* vcpu, unsigned long cr4) {
	unsigned long old_cr4 = kvm_read_cr4(vcpu);

	// 判断cr4是否有效，无效则报错
	if (!kvm_is_valid_cr4(vcpu, cr4))
		return 1;

	// vcpu属于长模式
	if (is_long_mode(vcpu)) {
		// 虚拟机在长模式，但是CR4的PAE没有打开
		if (!(cr4 & X86_CR4_PAE))
			return 1;
		if ((cr4 ^ old_cr4) & X86_CR4_LA57)
			return 1;
	}// 非长模式，vcpu打开了分页模式，并且打开了PAE模式
	else if (is_paging(vcpu) && (cr4 & X86_CR4_PAE)
		&& ((cr4 ^ old_cr4) & X86_CR4_PDPTR_BITS)
		&& !load_pdptrs(vcpu, kvm_read_cr3(vcpu)))
		return 1;
	// PCIDE开启但是原值没有开启
	if ((cr4 & X86_CR4_PCIDE) && !(old_cr4 & X86_CR4_PCIDE)) {
		/* PCID can not be enabled when cr3[11:0]!=000H or EFER.LMA=0 */
		if ((kvm_read_cr3(vcpu) & X86_CR3_PCID_MASK) || !is_long_mode(vcpu))
			return 1;
	}

	kvm_x86_ops.set_cr4(vcpu, cr4);

	return 0;
}

void kvm_lmsw(struct kvm_vcpu* vcpu, unsigned long msw)
{
	(void)kvm_set_cr0(vcpu, kvm_read_cr0_bits(vcpu, ~0x0eul) | (msw & 0x0f));
}

static void update_cr8_intercept(struct kvm_vcpu* vcpu) {
	int max_irr, tpr;

	if (!kvm_x86_ops.update_cr8_intercept)
		return;

	if (!lapic_in_kernel(vcpu))
		return;

	if (vcpu->arch.apic->apicv_active)
		return;

	if (!vcpu->arch.apic->vapic_addr)
		max_irr = kvm_lapic_find_highest_irr(vcpu);
	else
		max_irr = -1;

	if (max_irr != -1)
		max_irr >>= 4;

	tpr = (int)kvm_lapic_get_cr8(vcpu);
}

static void vcpu_load_eoi_exitmap(struct kvm_vcpu* vcpu)
{
	UNREFERENCED_PARAMETER(vcpu);
	
}

void kvm_vcpu_reset(struct kvm_vcpu* vcpu, bool init_event) {
	unsigned long old_cr0 = kvm_read_cr0(vcpu);
	unsigned long new_cr0;

	vcpu->arch.dr7 = DR7_FIXED_1;
	kvm_update_dr7(vcpu);

	vcpu->arch.apf.halted = FALSE;

	/* All GPRs except RDX (handled below) are zeroed on RESET/INIT. */
	memset(vcpu->arch.regs, 0, sizeof(vcpu->arch.regs));
	kvm_register_mark_dirty(vcpu, VCPU_REGS_RSP);

	/*
	* CR0.CD/NW are set on RESET, preserved on INIT.  Note, some versions
	* of Intel's SDM list CD/NW as being set on INIT, but they contradict
	* (or qualify) that with a footnote stating that CD/NW are preserved.
	*/
	new_cr0 = X86_CR0_ET;
	if (init_event)
		new_cr0 |= (old_cr0 & (X86_CR0_NW | X86_CR0_CD));
	else
		new_cr0 |= X86_CR0_NW | X86_CR0_CD;
	new_cr0 = X86_CR0_ET;

	kvm_x86_ops.set_cr0(vcpu, new_cr0);
	kvm_x86_ops.set_cr4(vcpu, 0);
	kvm_x86_ops.set_efer(vcpu, 0);

}

static u64 kvm_get_arch_capabilities(void)
{
	u64 data = 0;

	/*
	 * If nx_huge_pages is enabled, KVM's shadow paging will ensure that
	 * the nested hypervisor runs with NX huge pages.  If it is not,
	 * L1 is anyway vulnerable to ITLB_MULTIHIT exploits from other
	 * L1 guests, so it need not worry about its own (L2) guests.
	 */
	data |= ARCH_CAP_PSCHANGE_MC_NO;

	/*
	 * If we're doing cache flushes (either "always" or "cond")
	 * we will do one whenever the guest does a vmlaunch/vmresume.
	 * If an outer hypervisor is doing the cache flush for us
	 * (VMENTER_L1D_FLUSH_NESTED_VM), we can safely pass that
	 * capability to the guest too, and if EPT is disabled we're not
	 * vulnerable.  Overall, only VMENTER_L1D_FLUSH_NEVER will
	 * require a nested hypervisor to do a flush of its own.
	 */




	return data;
}

static int kvm_get_msr_feature(struct kvm_msr_entry* msr)
{
	switch (msr->index) {
	case MSR_IA32_ARCH_CAPABILITIES:
		msr->data = kvm_get_arch_capabilities();
		break;
	case MSR_IA32_PERF_CAPABILITIES:
	{

		break;
	}
	case MSR_IA32_UCODE_REV:
		msr->data = __readmsr(msr->index);
		break;
	default:
		return kvm_x86_ops.get_msr_feature(msr);
	}
	return 0;
}

long kvm_arch_dev_ioctl(unsigned int ioctl, unsigned long arg) {
	UNREFERENCED_PARAMETER(arg);
	long r = 0;

	switch (ioctl)
	{
	case KVM_GET_MSR_FEATURE_INDEX_LIST:
		r = 0;
		break;

	case KVM_GET_SUPPORTED_CPUID:

		break;
	default:
		r = STATUS_INVALID_PARAMETER;
		break;
	}

	return r;
}

int kvm_emulate_rdmsr(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return 0;
}

int kvm_emulate_wrmsr(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return 0;
}

int kvm_emulate_halt(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return 0;
}

int kvm_emulate_invd(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return 0;
}

int kvm_emulate_rdpmc(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return 0;
}

int kvm_emulate_hypercall(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return 0;
}

int kvm_emulate_wbinvd(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return 0;
}

int kvm_emulate_xsetbv(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return 0;
}

int kvm_emulate_mwait(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return 0;
}

int kvm_emulate_monitor(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return 0;
}

int kvm_handle_invalid_op(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return 0;
}

static inline bool kvm_vcpu_exit_request(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return FALSE;
}

fastpath_t handle_fastpath_set_msr_irqoff(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);

	return EXIT_FASTPATH_NONE;
}

void kvm_inject_page_fault(struct kvm_vcpu* vcpu, 
	struct x86_exception* fault) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(fault);
}

gpa_t translate_nested_gpa(struct kvm_vcpu* vcpu, gpa_t gpa, u64 access,
	struct x86_exception* exception)
{
	struct kvm_mmu* mmu = vcpu->arch.mmu;
	gpa_t t_gpa;


	/* NPT walks are always user-walks */
	access |= PFERR_USER_MASK;
	t_gpa = mmu->gva_to_gpa(vcpu, mmu, gpa, access, exception);

	return t_gpa;
}

void kvm_arch_memslots_updated(struct kvm* kvm, u64 gen) {
	UNREFERENCED_PARAMETER(kvm);
	UNREFERENCED_PARAMETER(gen);
}

int kvm_arch_prepare_memory_region(struct kvm* kvm,
	const struct kvm_memory_slot* old,
	struct kvm_memory_slot* new,
	enum kvm_mr_change change) {
	UNREFERENCED_PARAMETER(kvm);
	UNREFERENCED_PARAMETER(old);
	UNREFERENCED_PARAMETER(new);
	UNREFERENCED_PARAMETER(change);

	return 0;
}

static int kvm_alloc_memslot_metadata(struct kvm* kvm,
	struct kvm_memory_slot* slot) {
	UNREFERENCED_PARAMETER(kvm);
	UNREFERENCED_PARAMETER(slot);

	return 0;
}

void kvm_arch_commit_memory_region(struct kvm* kvm,
	struct kvm_memory_slot* old,
	const struct kvm_memory_slot* new,
	enum kvm_mr_change change) {
	UNREFERENCED_PARAMETER(kvm);
	UNREFERENCED_PARAMETER(old);
	UNREFERENCED_PARAMETER(new);
	UNREFERENCED_PARAMETER(change);
}

void kvm_arch_vcpu_put(struct kvm_vcpu* vcpu) {
	
	kvm_x86_ops.vcpu_put(vcpu);

}

void kvm_arch_vcpu_postcreate(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
}

int x86_emulate_instruction(struct kvm_vcpu* vcpu, gpa_t cr2_or_gpa,
	int emulation_type, void* insn, int insn_len) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(cr2_or_gpa);
	UNREFERENCED_PARAMETER(emulation_type);
	UNREFERENCED_PARAMETER(insn);
	UNREFERENCED_PARAMETER(insn_len);
	return 0;
}

void kvm_update_dr7(struct kvm_vcpu* vcpu) {
	unsigned long dr7;

	if (vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP)
		dr7 = vcpu->arch.guest_debug_dr7;
	else
		dr7 = vcpu->arch.dr7;

	kvm_x86_ops.set_dr7(vcpu, dr7);
	vcpu->arch.switch_db_regs &= ~KVM_DEBUGREG_BP_ENABLED;
	if (dr7 & DR7_BP_EN_MASK)
		vcpu->arch.switch_db_regs |= KVM_DEBUGREG_BP_ENABLED;
}

long kvm_arch_vcpu_ioctl(unsigned int ioctl, unsigned long arg) {
	UNREFERENCED_PARAMETER(arg);
	switch (ioctl)
	{
	case KVM_SET_SREGS2:

		break;
	default:
		break;
	}

	return 0;
}

static inline ULONG_PTR kvm_rip_read(struct kvm_vcpu* vcpu)
{
	return kvm_register_read_raw(vcpu, VCPU_REGS_RIP);
}

static ULONG_PTR get_segment_base(struct kvm_vcpu* vcpu, int seg)
{
	return kvm_x86_ops.get_segment_base(vcpu, seg);
}

ULONG_PTR kvm_get_linear_rip(struct kvm_vcpu* vcpu)
{
	/* Can't read the RIP when guest state is protected, just return 0 */
	if (vcpu->arch.guest_state_protected)
		return 0;

	if (is_64_bit_mode(vcpu))
		return kvm_rip_read(vcpu);
	return (u32)(get_segment_base(vcpu, VCPU_SREG_CS) +
		kvm_rip_read(vcpu));
}

bool kvm_is_linear_rip(struct kvm_vcpu* vcpu, unsigned long linear_rip)
{
	return kvm_get_linear_rip(vcpu) == linear_rip;
}

static void __kvm_set_rflags(struct kvm_vcpu* vcpu, unsigned long rflags)
{
	if (vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP &&
		kvm_is_linear_rip(vcpu, vcpu->arch.singlestep_rip))
		rflags |= X86_EFLAGS_TF;
	kvm_x86_ops.set_rflags(vcpu, rflags);
}

void kvm_set_rflags(struct kvm_vcpu* vcpu, unsigned long rflags) {
	__kvm_set_rflags(vcpu, rflags);
}

void kvm_set_segment(struct kvm_vcpu* vcpu,
	struct kvm_segment* var, int seg)
{
	kvm_x86_ops.set_segment(vcpu, var, seg);
}

static int __set_sregs_common(struct kvm_vcpu* vcpu, struct kvm_sregs* sregs,
	int* mmu_reset_needed, bool update_pdptrs)
{
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(sregs);
	UNREFERENCED_PARAMETER(mmu_reset_needed);
	UNREFERENCED_PARAMETER(update_pdptrs);

	

	return 0;
}

static int __set_sregs(struct kvm_vcpu* vcpu, struct kvm_sregs* sregs)
{
	int mmu_reset_needed = 0;
	int ret = __set_sregs_common(vcpu, sregs, &mmu_reset_needed, TRUE);

	if (ret)
		return ret;

	return 0;
}

static void __set_regs(struct kvm_vcpu* vcpu, struct kvm_regs* regs) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(regs);
}

int kvm_arch_vcpu_ioctl_set_sregs(struct kvm_vcpu* vcpu,
	struct kvm_sregs* sregs)
{
	int ret;

	vcpu_load(vcpu);
	ret = __set_sregs(vcpu, sregs);
	vcpu_put(vcpu);
	return ret;
}

int kvm_arch_vcpu_ioctl_set_regs(struct kvm_vcpu* vcpu, struct kvm_regs* regs) {
	vcpu_load(vcpu);
	__set_regs(vcpu, regs);
	vcpu_put(vcpu);
	return 0;
}

int kvm_arch_init_vm(struct kvm* kvm, unsigned long type) {
	int ret = 0;

	if (type)
		return STATUS_INVALID_PARAMETER;

	bool out_page_track = FALSE;
	bool out_uninit_mmu = FALSE;
	do
	{
		ret = kvm_mmu_init_vm(kvm);
		if (ret) {
			out_page_track = TRUE;
			break;
		}

		ret = kvm_x86_ops.vm_init(kvm);
		if (ret) {
			out_uninit_mmu = TRUE;
			break;
		}

		return 0;
	} while (FALSE);

	if (out_uninit_mmu) {
		kvm_mmu_uninit_vm(kvm);
	}

	if (out_page_track) {
		
	}

	return ret;
}

int kvm_arch_post_init_vm(struct kvm* kvm) {
	return kvm_mmu_post_init_vm(kvm);
}

int kvm_arch_vcpu_precreate(struct kvm* kvm, unsigned int id) {
	UNREFERENCED_PARAMETER(id);
	return kvm_x86_ops.vcpu_precreate(kvm);
}

static inline void __kvm_arch_free_vm(struct kvm* kvm) {
	ExFreePool(kvm);
}

void kvm_arch_free_vm(struct kvm* kvm) {
	__kvm_arch_free_vm(kvm);
}

void kvm_arch_pre_destroy_vm(struct kvm* kvm) {
	kvm_mmu_pre_destroy_vm(kvm);
}

void kvm_arch_destroy_vm(struct kvm* kvm) {

	kvm_x86_ops.vm_destroy(kvm);
}


void kvm_arch_async_page_present(struct kvm_vcpu* vcpu,
	struct kvm_async_pf* work) {
	UNREFERENCED_PARAMETER(work);

	vcpu->arch.apf.halted = FALSE;
	vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
}