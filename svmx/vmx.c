#include "pch.h"
#include "vmx.h"
#include "kvm_emulate.h"
#include "mtrr.h"
#include "pmu.h"
#include "desc.h"
#include "capabilities.h"
#include "processor.h"
#include "vmcs12.h"
#include "run_flags.h"
#include "vmx_ops.h"


static int bypass_guest_pf = 1;
static int enable_vpid = 1;
static int enable_ept = 1;
static int enable_unrestricted_guest = 1;
static int flexpriority_enabled = 1;

static unsigned long* vmx_io_bitmap_a_page;
static unsigned long* vmx_io_bitmap_b_page;
static unsigned long* vmx_msr_bitmap_legacy_page;
static unsigned long* vmx_msr_bitmap_longmode_page;
static unsigned long vmx_vpid_bitmap_buf[VMX_NR_VPIDS];

static RTL_BITMAP vmx_io_bitmap_a;
static RTL_BITMAP vmx_io_bitmap_b;
static RTL_BITMAP vmx_msr_bitmap_legacy;
static RTL_BITMAP vmx_msr_bitmap_longmode;
static RTL_BITMAP vmx_vpid_bitmap;

static unsigned long host_idt_base;

/* Guest_tsc -> host_tsc conversion requires 64-bit division.  */
static int cpu_preemption_timer_multi;
static bool enable_preemption_timer = TRUE;



struct vmcs_config {
	int size;
	u32 basic_cap;
	u32 revision_id;
	u32 pin_based_exec_ctrl;
	u32 cpu_based_exec_ctrl;
	u32 cpu_based_2nd_exec_ctrl;
	u64 cpu_based_3rd_exec_ctrl;
	u32 vmexit_ctrl;
	u32 vmentry_ctrl;
	u64 misc;
	struct nested_vmx_msrs nested;
};

static struct vmx_capability {
	u32 ept;
	u32 vpid;
} vmx_capability;

struct vmcs_config  vmcs_config;
struct vmx_capability vmx_capability;

// vmxon 区域
struct vmcs** vmxarea;
// 每个物理逻辑 cpu 一个 current vmcs 指针
struct vmcs** current_vmcs;

static const struct trace_print_flags vmx_exit_reasons_str[] = {
	{ EXIT_REASON_EXCEPTION_NMI,           "exception" },
	{ EXIT_REASON_EXTERNAL_INTERRUPT,      "ext_irq" },
	{ EXIT_REASON_TRIPLE_FAULT,            "triple_fault" },
	{ EXIT_REASON_NMI_WINDOW,              "nmi_window" },
	{ EXIT_REASON_IO_INSTRUCTION,          "io_instruction" },
	{ EXIT_REASON_CR_ACCESS,               "cr_access" },
	{ EXIT_REASON_DR_ACCESS,               "dr_access" },
	{ EXIT_REASON_CPUID,                   "cpuid" },
	{ EXIT_REASON_MSR_READ,                "rdmsr" },
	{ EXIT_REASON_MSR_WRITE,               "wrmsr" },
	{ EXIT_REASON_PENDING_INTERRUPT,       "interrupt_window" },
	{ EXIT_REASON_HLT,                     "halt" },
	{ EXIT_REASON_INVLPG,                  "invlpg" },
	{ EXIT_REASON_VMCALL,                  "hypercall" },
	{ EXIT_REASON_TPR_BELOW_THRESHOLD,     "tpr_below_thres" },
	{ EXIT_REASON_APIC_ACCESS,             "apic_access" },
	{ EXIT_REASON_WBINVD,                  "wbinvd" },
	{ EXIT_REASON_TASK_SWITCH,             "task_switch" },
	{ EXIT_REASON_EPT_VIOLATION,           "ept_violation" },
	{ (unsigned long)-1, NULL }
};

/*
 * Comment's format: document - errata name - stepping - processor name.
 * Refer from
 * https://www.virtualbox.org/svn/vbox/trunk/src/VBox/VMM/VMMR0/HMR0.cpp
 */
static u32 vmx_preemption_cpu_tfms[] = {
	/* 323344.pdf - BA86   - D0 - Xeon 7500 Series */
	0x000206E6,
	/* 323056.pdf - AAX65  - C2 - Xeon L3406 */
	/* 322814.pdf - AAT59  - C2 - i7-600, i5-500, i5-400 and i3-300 Mobile */
	/* 322911.pdf - AAU65  - C2 - i5-600, i3-500 Desktop and Pentium G6950 */
	0x00020652,
	/* 322911.pdf - AAU65  - K0 - i5-600, i3-500 Desktop and Pentium G6950 */
	0x00020655,
	/* 322373.pdf - AAO95  - B1 - Xeon 3400 Series */
	/* 322166.pdf - AAN92  - B1 - i7-800 and i5-700 Desktop */
	/*
	 * 320767.pdf - AAP86  - B1 -
	 * i7-900 Mobile Extreme, i7-800 and i7-700 Mobile
	 */
	0x000106E5,
	/* 321333.pdf - AAM126 - C0 - Xeon 3500 */
	0x000106A0,
	/* 321333.pdf - AAM126 - C1 - Xeon 3500 */
	0x000106A1,
	/* 320836.pdf - AAJ124 - C0 - i7-900 Desktop Extreme and i7-900 Desktop */
	0x000106A4,
	/* 321333.pdf - AAM126 - D0 - Xeon 3500 */
	/* 321324.pdf - AAK139 - D0 - Xeon 5500 */
	/* 320836.pdf - AAJ124 - D0 - i7-900 Extreme and i7-900 Desktop */
   0x000106A5,
   /* Xeon E3-1220 V2 */
  0x000306A8,
};

/* Storage for pre module init parameter parsing */
static enum vmx_l1d_flush_state vmentry_l1d_flush_param = VMENTER_L1D_FLUSH_AUTO;

void ept_sync_global();

extern bool allow_smaller_maxphyaddr;

void vmx_disable_intercept_for_msr(u32 msr, bool longmode_only);
void __vmx_disable_intercept_for_msr(PRTL_BITMAP msr_bitmap, u32 msr);




void vmcs_writel(unsigned long field, unsigned long val);
void vmcs_write16(unsigned long field, u16 value);
void vmcs_write32(unsigned long field, u32 value);



struct kvm_vcpu* vmx_create_vcpu(struct kvm* kvm, unsigned int id);
void vmx_free_vcpu(struct kvm_vcpu* vcpu);
struct vcpu_vmx* to_vmx(struct kvm_vcpu* vcpu);

void hardware_disable(void* garbage);
void vmx_save_host_state(struct kvm_vcpu* vcpu);
int set_guest_debug(struct kvm_vcpu* vcpu, struct kvm_guest_debug* dbg);
u64 vmx_get_segment_base(struct kvm_vcpu* vcpu, int seg);
void vmx_get_segment(struct kvm_vcpu* vcpu,
	struct kvm_segment* var, int seg);
void vmx_set_segment(struct kvm_vcpu* vcpu,
	struct kvm_segment* var, int seg);
int vmx_get_cpl(struct kvm_vcpu* vcpu);
void vmx_get_cs_db_l_bits(struct kvm_vcpu* vcpu, int* db, int* l);
void vmx_decache_cr4_guest_bits(struct kvm_vcpu* vcpu);
void vmx_set_cr0(struct kvm_vcpu* vcpu, unsigned long cr0);
void vmx_set_cr3(struct kvm_vcpu* vcpu, unsigned long cr3);
void vmx_set_cr4(struct kvm_vcpu* vcpu, unsigned long cr4);
void vmx_set_efer(struct kvm_vcpu* vcpu, u64 efer);
void vmx_get_idt(struct kvm_vcpu* vcpu, struct descriptor_table* dt);
void vmx_set_idt(struct kvm_vcpu* vcpu, struct descriptor_table* dt);
void vmx_get_gdt(struct kvm_vcpu* vcpu, struct descriptor_table* dt);
void vmx_set_gdt(struct kvm_vcpu* vcpu, struct descriptor_table* dt);
void vmx_cache_reg(struct kvm_vcpu* vcpu, enum kvm_reg reg);
unsigned long vmx_get_rflags(struct kvm_vcpu* vcpu);
void vmx_set_rflags(struct kvm_vcpu* vcpu, unsigned long rflags);
void vmx_flush_tlb(struct kvm_vcpu* vcpu);
void skip_emulated_instruction(struct kvm_vcpu* vcpu);
void vmx_set_interrupt_shadow(struct kvm_vcpu* vcpu, int mask);
u32 vmx_get_interrupt_shadow(struct kvm_vcpu* vcpu, int mask);
void vmx_patch_hypercall(struct kvm_vcpu* vcpu, unsigned char* hypercall);
void vmx_inject_irq(struct kvm_vcpu* vcpu);
void vmx_inject_nmi(struct kvm_vcpu* vcpu);
void vmx_queue_exception(struct kvm_vcpu* vcpu, unsigned nr,
	bool has_error_code, u32 error_code);
int vmx_interrupt_allowed(struct kvm_vcpu* vcpu);
int vmx_nmi_allowed(struct kvm_vcpu* vcpu);
void enable_nmi_window(struct kvm_vcpu* vcpu);
void enable_irq_window(struct kvm_vcpu* vcpu);
void update_cr8_intercept(struct kvm_vcpu* vcpu, int tpr, int irr);
int vmx_set_tss_addr(struct kvm* kvm, unsigned int addr);
int get_ept_level();
u64 vmx_get_mt_mask(struct kvm_vcpu* vcpu, gfn_t gfn, bool is_mmio);
bool vmx_gb_page_enable();



/*
* Reads an msr value (of 'msr_index') into 'pdata'.
* Return 0 on success, non-0 otherwise.
* Assumes vcpu_load() was already called.
*/
NTSTATUS vmx_get_msr(struct kvm_vcpu* vcpu, u32 msr_index, u64* pdata);

/*
 * Writes msr value into into the appropriate "register".
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
NTSTATUS vmx_set_msr(struct kvm_vcpu* vcpu, u32 msr_index, u64 data);

NTSTATUS adjust_vmx_controls(u32 ctl_min, u32 ctl_opt, u32 msr, u32* result) {
	u32 vmx_msr_low, vmx_msr_high;
	u32 ctl = ctl_min | ctl_opt;

	u64 vmx_msr = __readmsr(msr);
	// allowed 0-setting
	vmx_msr_low = (u32)vmx_msr;
	// allowed 1-setting
	vmx_msr_high = vmx_msr >> 32;

	// 高位：为1表明允许为1，所以为0，则不能为1
	ctl &= vmx_msr_high;/* bit == 0 in high word ==> must be zero */
	// 低位：为0表明允许为0，所以为1，则不能为0
	ctl |= vmx_msr_low;/* bit == 1 in low word  ==> must be one  */

	// 确保最小值
	/* Ensure minimum (required) set of control bits are supported. */
	if (ctl_min & ~ctl)
		return STATUS_NOT_SUPPORTED;

	*result = ctl;
	return STATUS_SUCCESS;
}

static u64 adjust_vmx_controls64(u64 ctl_opt, u32 msr)
{
	u64 allowed;

	allowed = __readmsr(msr);

	return ctl_opt & allowed;
}

/*
 * There is no X86_FEATURE for SGX yet, but anyway we need to query CPUID
 * directly instead of going through cpu_has(), to ensure KVM is trapping
 * ENCLS whenever it's supported in hardware.  It does not matter whether
 * the host OS supports or has enabled SGX.
 */
static bool cpu_has_sgx(void) {
	return cpuid_eax(0) >= 0x12 && (cpuid_eax(0x12) & BIT(0));
}

static bool cpu_has_broken_vmx_preemption_timer(void) {
	u32 eax = cpuid_eax(0x00000001), i;

	/* Clear the reserved bits */
	eax &= ~(0x3U << 14 | 0xfU << 28);
	for (i = 0; i < ARRAYSIZE(vmx_preemption_cpu_tfms); i++)
		if (eax == vmx_preemption_cpu_tfms[i])
			return TRUE;

	return FALSE;
}

static bool cpu_has_vmx_preemption_timer(void) {
	return vmcs_config.pin_based_exec_ctrl &
		PIN_BASED_VMX_PREEMPTION_TIMER;
}

static NTSTATUS setup_vmcs_config(struct vmcs_config* vmcs_conf,
	struct vmx_capability* vmx_cap) {
	int i = 0;
	NTSTATUS status = STATUS_SUCCESS;
	u32 vmx_msr_low, vmx_msr_high;
	u32 _pin_based_exec_control = 0;
	u32 _cpu_based_exec_control = 0;
	u32 _cpu_based_2nd_exec_control = 0;
	u64 _cpu_based_3rd_exec_control = 0;
	u32 _vmexit_control = 0;
	u32 _vmentry_control = 0;
	u64 misc_msr;

	/*
	 * LOAD/SAVE_DEBUG_CONTROLS are absent because both are mandatory.
	 * SAVE_IA32_PAT and SAVE_IA32_EFER are absent because KVM always
	 * intercepts writes to PAT and EFER, i.e. never enables those controls.
	 */
	struct {
		u32 entry_control;
		u32 exit_control;
	}const vmcs_entry_exit_pairs[] = {
		{ VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL,	VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL },
		{ VM_ENTRY_LOAD_IA32_PAT,		VM_EXIT_LOAD_IA32_PAT },
		{ VM_ENTRY_LOAD_IA32_EFER,		VM_EXIT_LOAD_IA32_EFER },
		{ VM_ENTRY_LOAD_BNDCFGS,		VM_EXIT_CLEAR_BNDCFGS },
		{ VM_ENTRY_LOAD_IA32_RTIT_CTL,		VM_EXIT_CLEAR_IA32_RTIT_CTL },
	};

	memset(vmcs_conf, 0, sizeof(*vmcs_conf));

	// 调整得到所有可用功能
	if (adjust_vmx_controls(KVM_REQUIRED_VMX_CPU_BASED_VM_EXEC_CONTROL,
		KVM_OPTIONAL_VMX_CPU_BASED_VM_EXEC_CONTROL,
		MSR_IA32_VMX_PROCBASED_CTLS,
		&_cpu_based_exec_control))
		return STATUS_UNSUCCESSFUL;

	if (_cpu_based_exec_control & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) {
		if (adjust_vmx_controls(KVM_REQUIRED_VMX_SECONDARY_VM_EXEC_CONTROL,
			KVM_OPTIONAL_VMX_SECONDARY_VM_EXEC_CONTROL,
			MSR_IA32_VMX_PROCBASED_CTLS2,
			&_cpu_based_2nd_exec_control))
			return STATUS_UNSUCCESSFUL;
	}

#ifndef _WIN64
	if (!(_cpu_based_2nd_exec_control &
		SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES))
		_cpu_based_exec_control &= ~CPU_BASED_TPR_SHADOW;
#endif

	if (!(_cpu_based_exec_control & CPU_BASED_TPR_SHADOW))
		_cpu_based_2nd_exec_control &= ~(
			SECONDARY_EXEC_APIC_REGISTER_VIRT |
			SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE |
			SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY);

	rdmsr(MSR_IA32_VMX_EPT_VPID_CAP, vmx_cap->ept, vmx_cap->vpid);

	if (!(_cpu_based_2nd_exec_control & SECONDARY_EXEC_ENABLE_EPT) &&
		vmx_cap->ept) {

		vmx_cap->ept = 0;
	}
	if (!(_cpu_based_2nd_exec_control & SECONDARY_EXEC_ENABLE_VPID) &&
		vmx_cap->vpid) {

		vmx_cap->vpid = 0;
	}

	if (!cpu_has_sgx())
		_cpu_based_2nd_exec_control &= ~SECONDARY_EXEC_ENCLS_EXITING;

	if (_cpu_based_exec_control & CPU_BASED_ACTIVATE_TERTIARY_CONTROLS)
		_cpu_based_3rd_exec_control =
		adjust_vmx_controls64(KVM_OPTIONAL_VMX_TERTIARY_VM_EXEC_CONTROL,
			MSR_IA32_VMX_PROCBASED_CTLS3);

	if (adjust_vmx_controls(KVM_REQUIRED_VMX_VM_EXIT_CONTROLS,
		KVM_OPTIONAL_VMX_VM_EXIT_CONTROLS,
		MSR_IA32_VMX_EXIT_CTLS,
		&_vmexit_control))
		return STATUS_UNSUCCESSFUL;

	if (adjust_vmx_controls(KVM_REQUIRED_VMX_PIN_BASED_VM_EXEC_CONTROL,
		KVM_OPTIONAL_VMX_PIN_BASED_VM_EXEC_CONTROL,
		MSR_IA32_VMX_PINBASED_CTLS,
		&_pin_based_exec_control))
		return STATUS_UNSUCCESSFUL;

	if (cpu_has_broken_vmx_preemption_timer())
		_pin_based_exec_control &= ~PIN_BASED_VMX_PREEMPTION_TIMER;
	if (!(_cpu_based_2nd_exec_control &
		SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY))
		_pin_based_exec_control &= ~PIN_BASED_POSTED_INTR;

	if (adjust_vmx_controls(KVM_REQUIRED_VMX_VM_ENTRY_CONTROLS,
		KVM_OPTIONAL_VMX_VM_ENTRY_CONTROLS,
		MSR_IA32_VMX_ENTRY_CTLS,
		&_vmentry_control))
		return STATUS_UNSUCCESSFUL;

	for (i = 0; i < ARRAYSIZE(vmcs_entry_exit_pairs); i++) {
		u32 n_ctrl = vmcs_entry_exit_pairs[i].entry_control;
		u32 x_ctrl = vmcs_entry_exit_pairs[i].exit_control;

		if (!(_vmentry_control & n_ctrl) == !(_vmexit_control & x_ctrl))
			continue;

		_vmentry_control &= ~n_ctrl;
		_vmexit_control &= ~x_ctrl;
	}

	// 获取基本能力
	rdmsr(MSR_IA32_VMX_BASIC, vmx_msr_low, vmx_msr_high);

	/*IA-32 SDM Vol 3B: VMCS size is never greater than 4kb. */
	// bits[44:32] (13bits)
	// VMCS的大小不会大于4KB
	if ((vmx_msr_high & 0x1fff) > PAGE_SIZE)
		return STATUS_UNSUCCESSFUL;

#ifdef _WIN64
	/* IA-32 SDM Vol 3B: 64-bit CPUs always have VMX_BASIC_MSR[48]==0. */
	// 处理bit 48, 为64位的情况
	// 64位cpu的VMX_BASIC_MSR[48]必须为0
	if (vmx_msr_high & (1u << 16))
		return STATUS_UNSUCCESSFUL;
#endif

	/* Require Write-Back (WB) memory type for VMCS accesses. */
	// bits[53:50]
	// 内存类型必须是WB
	if (((vmx_msr_high >> 18) & 15) != 6)
		return STATUS_UNSUCCESSFUL;

	misc_msr = __readmsr(MSR_IA32_VMX_MISC);

	// 得到vmcs区域和vmxon区域的大小
	vmcs_conf->size = vmx_msr_high & 0x1fff;
	vmcs_conf->basic_cap = vmx_msr_high & ~0x1fff;

	vmcs_conf->revision_id = vmx_msr_low;

	vmcs_conf->pin_based_exec_ctrl = _pin_based_exec_control;
	vmcs_conf->cpu_based_exec_ctrl = _cpu_based_exec_control;
	vmcs_conf->cpu_based_2nd_exec_ctrl = _cpu_based_2nd_exec_control;
	vmcs_conf->cpu_based_3rd_exec_ctrl = _cpu_based_3rd_exec_control;
	vmcs_conf->vmexit_ctrl = _vmexit_control;
	vmcs_conf->vmentry_ctrl = _vmentry_control;


	vmcs_conf->misc = misc_msr;


	return status;
}

static NTSTATUS vmx_check_processor_compat(void) {
	struct vmcs_config vmcs_conf;
	struct vmx_capability vmx_cap;
	// 检测是否支持vmx
	if (!kvm_is_vmx_supported())
		return STATUS_UNSUCCESSFUL;

	// 基本信息检测
	if (setup_vmcs_config(&vmcs_conf, &vmx_cap) < 0) {
		return STATUS_UNSUCCESSFUL;
	}

	if (memcmp(&vmcs_config, &vmcs_conf, sizeof(struct vmcs_config))) {
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

void free_vmcs(struct vmcs* vmcs) {
	MmFreeContiguousMemory(vmcs);
}

static void free_kvm_area(void)
{
	int cpu;
	int processors = KeQueryActiveProcessorCount(NULL);
	for (cpu = 0; cpu < processors; cpu++) {
		free_vmcs(vmxarea[cpu]);
	}
}

static void vmx_hardware_unsetup(void) {
	free_kvm_area();
}

static int kvm_cpu_vmxon(u64 vmxon_pointer) {
	// enable the cr4's vmxe bit
	__writecr4(__readcr4() | X86_CR4_VMXE);
	__vmx_on(&vmxon_pointer);// open the vmx mode
	return 0;
}

static int vmx_hardware_enable(void) {
	u64 phys_addr = 0;
	int r;

	

	struct vmcs* vmcs = vmxarea[KeGetCurrentProcessorNumber()];
	// 获取物理地址
	PHYSICAL_ADDRESS physical = MmGetPhysicalAddress(vmcs);
	phys_addr = physical.QuadPart;
	r = kvm_cpu_vmxon(phys_addr);
	if (r) {
		return r;
	}

	if (enable_ept) {

	}

	return 0;
}

static void vmx_hardware_disable(void) {

	if (cpu_vmxoff())
		NT_ASSERT(FALSE);

}

/*
 * The kvm parameter can be NULL (module initialization, or invocation before
 * VM creation). Be sure to check the kvm parameter before using it.
 */
static bool vmx_has_emulated_msr(struct kvm* kvm, u32 index)
{
	UNREFERENCED_PARAMETER(kvm);
	UNREFERENCED_PARAMETER(index);
	return FALSE;
}

#define L1TF_MSG_SMT "L1TF CPU bug present and SMT on, data leak possible. See CVE-2018-3646 and https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/l1tf.html for details.\n"
#define L1TF_MSG_L1D "L1TF CPU bug present and virtualization mitigation disabled, data leak possible. See CVE-2018-3646 and https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/l1tf.html for details.\n"

static int vmx_vm_init(struct kvm* kvm) {
	UNREFERENCED_PARAMETER(kvm);

	return 0;
}

static void vmx_vm_destroy(struct kvm* kvm) {
	UNREFERENCED_PARAMETER(kvm);
}

static int vmx_vcpu_precreate(struct kvm* kvm) {
	UNREFERENCED_PARAMETER(kvm);
	return 0;
}

static NTSTATUS vmx_vcpu_create(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	NTSTATUS status;
	struct vcpu_vmx* vmx;

	vmx = to_vmx(vcpu);
	status = alloc_loaded_vmcs(&vmx->vmcs01);

	vmx->loaded_vmcs = &vmx->vmcs01;


	return STATUS_SUCCESS;
}

static void vmx_vcpu_free(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
}

static void vmx_vcpu_reset(struct kvm_vcpu* vcpu, bool init_event) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(init_event);
}

void vmx_prepare_switch_to_guest(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
}

/*
 * Switches to specified vcpu, until a matching vcpu_put(), but assumes
 * vcpu mutex is already taken.
 */
static void vmx_vcpu_load(struct kvm_vcpu* vcpu, int cpu) {

	vmx_vcpu_load_vmcs(vcpu, cpu, NULL);

}

static void vmx_vcpu_put(struct kvm_vcpu* vcpu,int cpu) {
	// struct vcpu_vmx* vmx = to_vmx(vcpu);

	vmx_vcpu_load_vmcs(vcpu, cpu, NULL);
}

static int vmx_vcpu_pre_run(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return 1;
}

/*
 * Check if MSR is intercepted for currently loaded MSR bitmap.
 */
static bool msr_write_intercepted(struct vcpu_vmx* vmx, u32 msr)
{
	UNREFERENCED_PARAMETER(msr);
	if (!(exec_controls_get(vmx) & CPU_BASED_USE_MSR_BITMAPS))
		return TRUE;

	// return vmx_test_msr_bitmap_write(vmx->loaded_vmcs->msr_bitmap, msr);
	return FALSE;
}

unsigned int __vmx_vcpu_run_flags(struct vcpu_vmx* vmx) {
	unsigned int flags = 0;

	if (vmx->loaded_vmcs->launched)
		flags |= VMX_RUN_VMRESUME;

	/*
	* If writes to the SPEC_CTRL MSR aren't intercepted, the guest is free
	* to change it directly without causing a vmexit.  In that case read
	* it after vmexit and store it in vmx->spec_ctrl.
	*/
	if (!msr_write_intercepted(vmx, MSR_IA32_SPEC_CTRL))
		flags |= VMX_RUN_SAVE_SPEC_CTRL;

	return flags;
}

static void vmx_vcpu_enter_exit(struct kvm_vcpu* vcpu,
	unsigned int flags) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(flags);
}

static fastpath_t vmx_vcpu_run(struct kvm_vcpu* vcpu) {
	struct vcpu_vmx* vmx = to_vmx(vcpu);

	vmx_vcpu_enter_exit(vcpu, __vmx_vcpu_run_flags(vmx));

	return EXIT_FASTPATH_NONE;
}

/*
 * The guest has exited.  See if we can fix it or if we need userspace
 * assistance.
 */
// __vmx_vcpu_run返回 0 表明是 VM-exit, 返回1表明是 VM-Fail
static int __vmx_handle_exit(struct kvm_vcpu* vcpu, fastpath_t exit_fastpath)
{
	UNREFERENCED_PARAMETER(exit_fastpath);
	struct vcpu_vmx* vmx = to_vmx(vcpu);
	//union vmx_exit_reason exit_reason = vmx->exit_reason;
	//u32 vectoring_info = vmx->idt_vectoring_info;
	//u16 exit_handler_index;

	if (vmx->fail) {
		
		vcpu->run->exit_reason = KVM_EXIT_FAIL_ENTRY;
		vcpu->run->fail_entry.hardware_entry_failure_reason
			= vmcs_read32(VM_INSTRUCTION_ERROR);
		vcpu->run->fail_entry.cpu = vcpu->arch.last_vmentry_cpu;
		return 0;
	}

	return 0;
}

static int vmx_handle_exit(struct kvm_vcpu* vcpu, fastpath_t exit_fastpath) {
	int ret = __vmx_handle_exit(vcpu, exit_fastpath);

	return ret;
}



static struct kvm_x86_ops vmx_x86_ops = {
	.check_processor_compatibility = vmx_check_processor_compat,

	.hardware_unsetup = vmx_hardware_unsetup,

	.hardware_enable = vmx_hardware_enable,
	.hardware_disable = vmx_hardware_disable,
	.has_emulated_msr = vmx_has_emulated_msr,

	.vm_size = sizeof(struct kvm_vmx),
	.vm_init = vmx_vm_init,
	.vm_destroy = vmx_vm_destroy,

	.vcpu_precreate = vmx_vcpu_precreate,
	.vcpu_create = vmx_vcpu_create,
	.vcpu_free = vmx_vcpu_free,
	.vcpu_reset = vmx_vcpu_reset,

	.prepare_switch_to_guest = vmx_prepare_switch_to_guest,
	.vcpu_load = vmx_vcpu_load,
	.vcpu_put = vmx_vcpu_put,


	.vcpu_pre_run = vmx_vcpu_pre_run,
	.vcpu_run = vmx_vcpu_run,
	.handle_exit = vmx_handle_exit,

};

static struct kvm_x86_init_ops vmx_init_ops = {
	.hardware_setup = hardware_setup,
	.handle_intel_pt_intr = NULL,

	.runtime_ops = &vmx_x86_ops,
	.pmu_ops = &intel_pmu_ops,
};






void vmx_setup_fb_clear_ctrl() {

}



int cpu_has_kvm_support() {
	return cpu_has_vmx();
}

int vmx_disabled_by_bios() {
	u64 msr;

	msr = __readmsr(MSR_IA32_FEATURE_CONTROL);
	return (msr & (FEATURE_CONTROL_LOCKED |
		FEATURE_CONTROL_VMXON_ENABLED))
		== FEATURE_CONTROL_LOCKED;
	/* locked but not enabled */
}

static int cpu_has_vmx_vpid() {
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_ENABLE_VPID;
}


int cpu_has_vmx_ept() {
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_ENABLE_EPT;
}

int cpu_has_vmx_unrestricted_guest() {
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_UNRESTRICTED_GUEST;
}

int cpu_has_vmx_tpr_shadow() {
	return vmcs_config.cpu_based_2nd_exec_ctrl & CPU_BASED_TPR_SHADOW;
}

bool cpu_has_vmx_virtualize_apic_accesses() {
	return vmcs_config.cpu_based_2nd_exec_ctrl & 
		SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES;
}

bool cpu_has_vmx_flexpriority() {
	return cpu_has_vmx_tpr_shadow() &&
		cpu_has_vmx_virtualize_apic_accesses();
}

bool cpu_has_vmx_ept_2m_page() {
	return !!(vmx_capability.ept & VMX_EPT_2MB_PAGE_BIT);
}

struct vmcs* alloc_vmcs_cpu(bool shadow,int node) {
	struct vmcs* vmcs = NULL;

	LARGE_INTEGER lowAddress;
	LARGE_INTEGER highAddress;
	LARGE_INTEGER boundary;

	lowAddress.QuadPart = 0ull;
	highAddress.QuadPart = ~0ull;
	// 4KB边界对齐
	boundary.QuadPart = PAGE_SIZE;

	vmcs = MmAllocateContiguousMemorySpecifyCacheNode(PAGE_SIZE,
		lowAddress, highAddress, boundary, MmCached, node);
	if (!vmcs)
		return NULL;

	RtlZeroMemory(vmcs, vmcs_config.size);

	/* KVM supports Enlightened VMCS v1 only */


	// revision id 等于 IA32_VMX_BASIC[31:0]
	vmcs->hdr.revision_id = vmcs_config.revision_id;

	if (shadow)
		vmcs->hdr.shadow_vmcs = 1;

	return vmcs;
}

struct vmcs* alloc_vmcs(bool shadow) {
	UNREFERENCED_PARAMETER(shadow);
	return NULL;
}




NTSTATUS alloc_kvm_area() {
	int cpu = 0;
	int processors = KeQueryActiveProcessorCount(NULL);
	// for each cpu
	for (cpu; cpu < processors; cpu++) {
		struct vmcs* vmcs;
		// 分配 vmcs 结构体, 实际上就是 vmxon 域
		vmcs = alloc_vmcs_cpu(FALSE, KeGetCurrentNodeNumber());
		if (!vmcs) {
			free_kvm_area();
			return 1;
		}
		vmxarea[cpu] = vmcs;
	}
	

	return STATUS_SUCCESS;
}

NTSTATUS hardware_setup() {
	NTSTATUS status = STATUS_SUCCESS;
	struct desc_ptr dt;

	store_idt(&dt);
	host_idt_base = dt.address;


	status = setup_vmcs_config(&vmcs_config, &vmx_capability);
	if (!NT_SUCCESS(status))
		return status;

	if (ExIsProcessorFeaturePresent(PF_NX_ENABLED)) {
		kvm_enable_efer_bits(EFER_NX);
	}

	if (!cpu_has_vmx_preemption_timer())
		enable_preemption_timer = FALSE;

	if (enable_preemption_timer) {
		u64 use_timer_freq = 5000ULL * 1000 * 1000;

		cpu_preemption_timer_multi =
			vmcs_config.misc & VMX_MISC_PREEMPTION_TIMER_RATE_MASK;

		/*
		* KVM "disables" the preemption timer by setting it to its max
		* value.  Don't use the timer if it might cause spurious exits
		* at a rate faster than 0.1 Hz (of uninterrupted guest time).
		*/
		if (use_timer_freq > 0xffffffffu / 10)
			enable_preemption_timer = FALSE;
	}

	status = alloc_kvm_area();

	return status;
}



void hardware_unsetup() {
	free_kvm_area();
}

void hardware_enable() {
	u64 old;

	old = __readmsr(MSR_IA32_FEATURE_CONTROL);
	if ((old & (FEATURE_CONTROL_LOCKED |
		FEATURE_CONTROL_VMXON_ENABLED))
		!= (FEATURE_CONTROL_LOCKED |
			FEATURE_CONTROL_VMXON_ENABLED)) {
		__writemsr(MSR_IA32_FEATURE_CONTROL, old |
			FEATURE_CONTROL_LOCKED | FEATURE_CONTROL_VMXON_ENABLED);
	}
	__writecr4(__readcr4() | X86_CR4_VMXE);/* FIXME: not cpu hotplug safe */
}

void __vcpu_clear(void* arg) {
	UNREFERENCED_PARAMETER(arg);
	// struct vcpu_vmx* vmx = arg;
	
	
}

void vmclear_local_vcpus() {

}

void hardware_disable(void* garbage) {
	UNREFERENCED_PARAMETER(garbage);


}

bool report_flexpriority() {
	return flexpriority_enabled;
}

struct kvm_vcpu* vmx_create_vcpu(struct kvm* kvm, unsigned int id) {
	UNREFERENCED_PARAMETER(kvm);
	UNREFERENCED_PARAMETER(id);
	
	return NULL;
}


void vmx_free_vcpu(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
}

struct vcpu_vmx* to_vmx(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return NULL;
}


void vmx_save_host_state(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);

	

}



void __vmx_load_host_state(struct vcpu_vmx* vmx) {
	UNREFERENCED_PARAMETER(vmx);

}



int set_guest_debug(struct kvm_vcpu* vcpu, struct kvm_guest_debug* dbg) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(dbg);

	return 0;
}

NTSTATUS vmx_get_msr(struct kvm_vcpu* vcpu, u32 msr_index, u64* pdata) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(msr_index);
	UNREFERENCED_PARAMETER(pdata);

	return STATUS_SUCCESS;
}

NTSTATUS vmx_set_msr(struct kvm_vcpu* vcpu, u32 msr_index, u64 data) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(msr_index);
	UNREFERENCED_PARAMETER(data);
	NTSTATUS status = STATUS_SUCCESS;

	return status;
}

u64 vmx_get_segment_base(struct kvm_vcpu* vcpu, int seg) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(seg);

	return 0;
}

void vmx_set_segment(struct kvm_vcpu* vcpu,
	struct kvm_segment* var, int seg) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(var);
	UNREFERENCED_PARAMETER(seg);

}



int vmx_get_cpl(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);

	return vmcs_read16(GUEST_CS_SELECTOR) & 3;
}

void vmx_get_cs_db_l_bits(struct kvm_vcpu* vcpu, int* db, int* l) {
	UNREFERENCED_PARAMETER(vcpu);
	u32 ar = vmcs_read32(GUEST_CS_AR_BYTES);

	*db = (ar >> 14) & 1;
	*l = (ar >> 13) & 1;
}

void vmx_decache_cr4_guest_bits(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
}

void vmx_set_cr0(struct kvm_vcpu* vcpu, unsigned long cr0) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(cr0);


}

void vmx_set_cr3(struct kvm_vcpu* vcpu, unsigned long cr3) {
	UNREFERENCED_PARAMETER(vcpu);
	unsigned long guest_cr3;

	guest_cr3 = cr3;
	if (enable_ept) {
		
	}

}

void vmx_set_cr4(struct kvm_vcpu* vcpu, unsigned long cr4) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(cr4);
	
	if (enable_ept) {

	}

	
}

void vmx_set_efer(struct kvm_vcpu* vcpu, u64 efer) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(efer);
}

void vmx_get_idt(struct kvm_vcpu* vcpu, struct descriptor_table* dt) {
	UNREFERENCED_PARAMETER(vcpu);
	dt->limit = vmcs_read16(GUEST_IDTR_LIMIT);
	dt->base = vmcs_readl(GUEST_IDTR_BASE);
}

void vmx_set_idt(struct kvm_vcpu* vcpu, struct descriptor_table* dt) {
	UNREFERENCED_PARAMETER(vcpu);
	vmcs_write32(GUEST_IDTR_LIMIT, dt->limit);
	vmcs_writel(GUEST_IDTR_BASE, dt->base);
}

void vmx_get_gdt(struct kvm_vcpu* vcpu, struct descriptor_table* dt) {
	UNREFERENCED_PARAMETER(vcpu);
	dt->limit = vmcs_read16(GUEST_GDTR_LIMIT);
	dt->base = vmcs_readl(GUEST_GDTR_BASE);
}

void vmx_set_gdt(struct kvm_vcpu* vcpu, struct descriptor_table* dt) {
	UNREFERENCED_PARAMETER(vcpu);
	vmcs_write32(GUEST_GDTR_LIMIT, dt->limit);
	vmcs_writel(GUEST_GDTR_BASE, dt->base);
}

void vmx_cache_reg(struct kvm_vcpu* vcpu, enum kvm_reg reg) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(reg);
}

unsigned long vmx_get_rflags(struct kvm_vcpu* vcpu) {
	unsigned long rflags;

	rflags = vmcs_readl(GUEST_RFLAGS);
	if (to_vmx(vcpu)->rmode.vm86_active)
		rflags &= ~(unsigned long)(X86_EFLAGS_IOPL | X86_EFLAGS_VM);
	return rflags;
}

void vmx_set_rflags(struct kvm_vcpu* vcpu, unsigned long rflags) {
	if (to_vmx(vcpu)->rmode.vm86_active)
		rflags |= X86_EFLAGS_IOPL | X86_EFLAGS_VM;
	vmcs_writel(GUEST_RFLAGS, rflags);
}

void vmx_flush_tlb(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	
}




void skip_emulated_instruction(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
}

void vmx_set_interrupt_shadow(struct kvm_vcpu* vcpu, int mask) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(mask);
}

u32 vmx_get_interrupt_shadow(struct kvm_vcpu* vcpu, int mask) {
	UNREFERENCED_PARAMETER(vcpu);
	u32 interruptibility = vmcs_read32(GUEST_INTERRUPTIBILITY_INFO);
	int ret = 0;
	
	if (interruptibility & GUEST_INTR_STATE_STI)
		ret |= X86_SHADOW_INT_STI;
	if (interruptibility & GUEST_INTR_STATE_MOV_SS)
		ret |= X86_SHADOW_INT_MOV_SS;

	return ret & mask;
}

void vmx_patch_hypercall(struct kvm_vcpu* vcpu, unsigned char* hypercall) {
	UNREFERENCED_PARAMETER(vcpu);
	/*
	* Patch in the VMCALL instruction
	*/
	hypercall[0] = 0x0f;
	hypercall[1] = 0x01;
	hypercall[2] = 0xc1; /* vmcall */
}

void vmx_inject_irq(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
}

void vmx_inject_nmi(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
		INTR_TYPE_NMI_INTR | INTR_INFO_VALID_MASK | NMI_VECTOR);
}

void vmx_queue_exception(struct kvm_vcpu* vcpu, unsigned nr,
	bool has_error_code, u32 error_code) {
	struct vcpu_vmx* vmx = to_vmx(vcpu);
	u32 intr_info = nr | INTR_INFO_VALID_MASK;

	if (has_error_code) {
		vmcs_write32(VM_ENTRY_EXCEPTION_ERROR_CODE, error_code);
		intr_info |= INTR_INFO_DELIVER_CODE_MASK;
	}

	if (vmx->rmode.vm86_active) {

	}

	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, intr_info);
}

int vmx_interrupt_allowed(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return (vmcs_readl(GUEST_RFLAGS) & X86_EFLAGS_IF) &&
		!(vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) &
			(GUEST_INTR_STATE_STI | GUEST_INTR_STATE_MOV_SS));
}

int vmx_nmi_allowed(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);

	return !(vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) &
		(GUEST_INTR_STATE_STI | GUEST_INTR_STATE_MOV_SS |
			GUEST_INTR_STATE_NMI));
}

int cpu_has_virtual_nmis() {
	return vmcs_config.pin_based_exec_ctrl & PIN_BASED_VIRTUAL_NMIS;
}

void enable_nmi_window(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);

}

void enable_irq_window(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	
}

void update_cr8_intercept(struct kvm_vcpu* vcpu, int tpr, int irr) {
	UNREFERENCED_PARAMETER(vcpu);
	if (irr == -1 || tpr < irr) {
		vmcs_write32(TPR_THRESHOLD, 0);
		return;
	}

	vmcs_write32(TPR_THRESHOLD, irr);
}

int vmx_set_tss_addr(struct kvm* kvm, unsigned int addr) {
	UNREFERENCED_PARAMETER(kvm);
	UNREFERENCED_PARAMETER(addr);


	return 0;
}

int get_ept_level() {
	return VMX_EPT_DEFAULT_GAW + 1;
}

u64 vmx_get_mt_mask(struct kvm_vcpu* vcpu, gfn_t gfn, bool is_mmio) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(gfn);
	u64 ret;

	/* For VT-d and EPT combination
	 * 1. MMIO: always map as UC
	 * 2. EPT with VT-d:
	 *   a. VT-d without snooping control feature: can't guarantee the
	 *	result, try to trust guest.
	 *   b. VT-d with snooping control feature: snooping control feature of
	 *	VT-d engine can guarantee the cache correctness. Just set it
	 *	to WB to keep consistent with host. So the same as item 3.
	 * 3. EPT without VT-d: always map as WB and set IGMT=1 to keep
	 *    consistent with host MTRR
	 */
	if (is_mmio)
		ret = MTRR_TYPE_UNCACHABLE << VMX_EPT_MT_EPTE_SHIFT;

	return 0;
}

bool vmx_gb_page_enable() {
	return FALSE;
}

void vmx_get_segment(struct kvm_vcpu* vcpu,
	struct kvm_segment* var, int seg) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(var);
	UNREFERENCED_PARAMETER(seg);
}

void vmx_disable_intercept_for_msr(u32 msr, bool longmode_only) {
	if (!longmode_only)
		__vmx_disable_intercept_for_msr(&vmx_msr_bitmap_legacy, msr);
	__vmx_disable_intercept_for_msr(&vmx_msr_bitmap_longmode, msr);
}

void __vmx_disable_intercept_for_msr(PRTL_BITMAP msr_bitmap, u32 msr) {
	UNREFERENCED_PARAMETER(msr_bitmap);
	// int f = sizeof(unsigned long);

	if (!cpu_has_vmx_msr_bitmap())
		return;

	/*
	 * See Intel PRM Vol. 3, 20.6.9 (MSR-Bitmap Address). Early manuals
	 * have the write-low and read-high bitmap offsets the wrong way round.
	 * We can control MSRs 0x00000000-0x00001fff and 0xc0000000-0xc0001fff.
	 */
	if (msr <= 0x1fff) {
		
	}
	else if ((msr >= 0xc0000000) && (msr <= 0xc0001fff)) {
		msr &= 0x1fff;
	}
}

int cpu_has_vmx_msr_bitmap() {
	return vmcs_config.cpu_based_exec_ctrl & CPU_BASED_USE_MSR_BITMAPS;
}

int cpu_has_vmx_invept_global() {
	return !!(vmx_capability.ept & VMX_EPT_EXTENT_GLOBAL_BIT);
}

void ept_sync_global() {
	if (cpu_has_vmx_invept_global()) {

	}


}

static void vmx_cleanup_l1d_flush(void) {

}

static void __vmx_exit(void) {
	allow_smaller_maxphyaddr = FALSE;


	vmx_cleanup_l1d_flush();
}

void vmx_exit(void) {
	kvm_exit();
	kvm_x86_vendor_exit();
	

	__vmx_exit();
}

bool kvm_is_vmx_supported() {
	if (!cpu_has_vmx()) {
		Log(KERN_ERR, "VMX not supported by CPU %d\n", KeGetCurrentProcessorNumber());
		return FALSE;
	}

	if (!cpu_is_enabled_vmx()) {
		Log(KERN_ERR, "VMX not enabled (by BIOS) in MSR_IA32_FEAT_CTL on CPU %d\n",
			KeGetCurrentProcessorNumber());
		return FALSE;
	}
	
	return TRUE;
}

void hv_init_evmcs() {

}

NTSTATUS vmx_setup_l1d_flush(enum vmx_l1d_flush_state l1tf) {
	UNREFERENCED_PARAMETER(l1tf);

	return STATUS_SUCCESS;
}





NTSTATUS vmx_init() {
	NTSTATUS status = STATUS_SUCCESS;

	// check the cpu whether support vmx or not
	if (!kvm_is_vmx_supported())
		return STATUS_NOT_SUPPORTED;

	/*
	* Note, hv_init_evmcs() touches only VMX knobs, i.e. there's nothing
	* to unwind if a later step fails.
	*/
	hv_init_evmcs();

	status = kvm_x86_vendor_init(&vmx_init_ops);
	if (!NT_SUCCESS(status))
		return status;

	bool err_l1d_flush = FALSE;
	bool err_kvm_init = FALSE;
	do
	{
		/*
		* Must be called after common x86 init so enable_ept is properly set
		* up. Hand the parameter mitigation value in which was stored in
		* the pre module init parser. If no parameter was given, it will
		* contain 'auto' which will be turned into the default 'cond'
		* mitigation mode.
		*/
		status = vmx_setup_l1d_flush(vmentry_l1d_flush_param);
		if (!NT_SUCCESS(status)) {
			err_l1d_flush = TRUE;
			break;
		}
		vmx_setup_fb_clear_ctrl();


		/*
		* Shadow paging doesn't have a (further) performance penalty
		* from GUEST_MAXPHYADDR < HOST_MAXPHYADDR so enable it
		* by default
		*/
		if (!enable_ept)
			allow_smaller_maxphyaddr = TRUE;

		/*
		* 
		* Common KVM initialization _must_ come last, after this,/dev/kvm is
		* exposed to userspace!
		*/
		status = kvm_init(sizeof(struct vcpu_vmx), __alignof(struct vcpu_vmx));

		if (!NT_SUCCESS(status)) {
			err_kvm_init = TRUE;
			break;
		}

	} while (FALSE);

	if (err_kvm_init) {
		__vmx_exit();
	}
	if (err_l1d_flush) {
		kvm_x86_vendor_exit();
	}

	return status;
}

int alloc_loaded_vmcs(struct loaded_vmcs* loaded_vmcs) {
	loaded_vmcs->vmcs = alloc_vmcs(FALSE);
	if (!loaded_vmcs->vmcs)
		return STATUS_NO_MEMORY;

	NTSTATUS status = STATUS_SUCCESS;
	vmcs_clear(loaded_vmcs->vmcs);

	loaded_vmcs->shadow_vmcs = NULL;
	loaded_vmcs->hv_timer_soft_disabled = FALSE;
	loaded_vmcs->cpu = -1;
	loaded_vmcs->launched = 0;

	do
	{
		if (cpu_has_vmx_msr_bitmap()) {
			unsigned long* msr_bitmap_page = (unsigned long*)ExAllocatePoolWithTag(PagedPool, PAGE_SIZE, DRIVER_TAG);
			if (!msr_bitmap_page) {
				status = STATUS_NO_MEMORY;
				break;
			}
			RtlInitializeBitMap(&loaded_vmcs->msr_bitmap, msr_bitmap_page, PAGE_SIZE * CHAR_BIT);
		}
	} while (FALSE);

	memset(&loaded_vmcs->host_state, 0, 
		sizeof(struct vmcs_host_state));
	memset(&loaded_vmcs->controls_shadow, 0,
		sizeof(struct vmcs_controls_shadow));

	return status;
}

void vmx_vcpu_load_vmcs(struct kvm_vcpu* vcpu, int cpu,
	struct loaded_vmcs* buddy) {
	UNREFERENCED_PARAMETER(buddy);
	struct vcpu_vmx* vmx = to_vmx(vcpu);
	bool already_loaded = vmx->loaded_vmcs->cpu == cpu;
	struct vmcs* prev;

	// 判断是否以及加载
	if (!already_loaded) {

	}

	prev = current_vmcs[cpu];
	if (prev != vmx->loaded_vmcs->vmcs) {
		current_vmcs[cpu] = vmx->loaded_vmcs->vmcs;
		vmcs_load(vmx->loaded_vmcs->vmcs);
	}

	if (!already_loaded) {
		vmx->loaded_vmcs->cpu = cpu;
	}
}