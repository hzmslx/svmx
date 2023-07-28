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
#include "sgx.h"
#include "nested.h"
#include "kvm_cache_regs.h"
#include "cpuid.h"
#include "smm.h"
#include "irq_vectors.h"

#define VMX_XSS_EXIT_BITMAP 0

static int bypass_guest_pf = 1;
static int enable_vpid = 1;
static int enable_ept = 1;
static int enable_unrestricted_guest = 1;
static int flexpriority_enabled = 1;

bool enable_pml = 1;

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

static bool dump_invalid_vmcs = 0;

LIST_ENTRY* loaded_vmcss_on_cpu;

extern bool enable_apicv;

/* Default is SYSTEM mode, 1 for host-guest mode */
int pt_mode = PT_MODE_SYSTEM;

#define KVM_VM_CR0_ALWAYS_OFF (X86_CR0_NW | X86_CR0_CD)



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


static void vmx_vcpu_reset(struct kvm_vcpu* vcpu, bool init_event);

void vmcs_writel(unsigned long field, unsigned long val);
void vmcs_write32(unsigned long field, u32 value);



void vmx_free_vcpu(struct kvm_vcpu* vcpu);

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

static void __loaded_vmcs_clear(void* arg) {
	struct loaded_vmcs* loaded_vmcs = arg;
	int cpu = KeGetCurrentProcessorNumber();
	if (current_vmcs[cpu] == loaded_vmcs->vmcs) {
		current_vmcs[cpu] = NULL;
	}
	vmcs_clear(loaded_vmcs->vmcs);

	RemoveEntryList(&loaded_vmcs->loaded_vmcss_on_cpu_link);

	loaded_vmcs->cpu = -1;
	loaded_vmcs->launched = 0;


}

static void vmclear_local_loaded_vmcss(void) {
	int cpu = KeGetCurrentProcessorNumber();
	struct loaded_vmcs* v;

	PLIST_ENTRY pListHead = &loaded_vmcss_on_cpu[cpu];
	PLIST_ENTRY nextEntry = pListHead->Flink;

	while (nextEntry != pListHead) {
		v = CONTAINING_RECORD(nextEntry, struct loaded_vmcs, loaded_vmcss_on_cpu_link);
		__loaded_vmcs_clear(v);
	}
}

static void vmx_hardware_disable(void) {
	vmclear_local_loaded_vmcss();

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
	// 分配并初始化这个vcpu对应的vmcs01
	// 需要4K对齐
	status = alloc_loaded_vmcs(&vmx->vmcs01);

	vmx->loaded_vmcs = &vmx->vmcs01;


	return STATUS_SUCCESS;
}

static void vmx_vcpu_free(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
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

static u32 vmx_secondary_exec_control(struct vcpu_vmx* vmx);
static void vmcs_set_secondary_exec_control(struct vcpu_vmx* vmx, u32 new_ctl)
{
	/*
	 * These bits in the secondary execution controls field
	 * are dynamic, the others are mostly based on the hypervisor
	 * architecture and the guest's CPUID.  Do not touch the
	 * dynamic bits.
	 */
	u32 mask =
		SECONDARY_EXEC_SHADOW_VMCS |
		SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE |
		SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES |
		SECONDARY_EXEC_DESC;

	u32 cur_ctl = secondary_exec_controls_get(vmx);

	secondary_exec_controls_set(vmx, (new_ctl & ~mask) | (cur_ctl & mask));
}

static void vmx_vcpu_after_set_cpuid(struct kvm_vcpu* vcpu) {
	struct vcpu_vmx* vmx = to_vmx(vcpu);

	if (cpu_has_secondary_exec_ctrls())
		vmcs_set_secondary_exec_control(vmx,
			vmx_secondary_exec_control(vmx));
}

static void vmx_write_tsc_offset(struct kvm_vcpu* vcpu, u64 offset)
{
	UNREFERENCED_PARAMETER(vcpu);
	vmcs_write64(TSC_OFFSET, offset);
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

	.vcpu_after_set_cpuid = vmx_vcpu_after_set_cpuid,

	.prepare_switch_to_guest = vmx_prepare_switch_to_guest,
	.vcpu_load = vmx_vcpu_load,
	.vcpu_put = vmx_vcpu_put,


	.vcpu_pre_run = vmx_vcpu_pre_run,
	.vcpu_run = vmx_vcpu_run,
	.handle_exit = vmx_handle_exit,

	.write_tsc_offset = vmx_write_tsc_offset,
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
	return alloc_vmcs_cpu(shadow, KeGetCurrentNodeNumber());
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

	if (!cpu_has_vmx_flexpriority())
		flexpriority_enabled = 0;

	/*
	* set_apic_access_page_addr() is used to reload apic access
	* page upon invalidation.  No need to do anything if not
	* using the APIC_ACCESS_ADDR VMCS field.
	*/
	if (!flexpriority_enabled)
		vmx_x86_ops.set_apic_access_page_addr = NULL;

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


void vmx_free_vcpu(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
}

struct vcpu_vmx* to_vmx(struct kvm_vcpu* vcpu) {
	return CONTAINING_RECORD(vcpu, struct vcpu_vmx, vcpu);
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



static inline bool is_unrestricted_guest(struct kvm_vcpu* vcpu)
{
	return enable_unrestricted_guest && (!is_guest_mode(vcpu) ||
		(secondary_exec_controls_get(to_vmx(vcpu)) &
			SECONDARY_EXEC_UNRESTRICTED_GUEST));
}

void vmx_set_cr0(struct kvm_vcpu* vcpu, unsigned long cr0) {
	//struct vcpu_vmx* vmx = to_vmx(vcpu);
	unsigned long hw_cr0, old_cr0_pg;
	//u32 tmp;

	old_cr0_pg = kvm_read_cr0_bits(vcpu, X86_CR0_PG);
	hw_cr0 = (cr0 & ~KVM_VM_CR0_ALWAYS_OFF);
	if (is_unrestricted_guest(vcpu)) {
		hw_cr0 |= KVM_VM_CR0_ALWAYS_ON_UNRESTRICTED_GUEST;
	}
	else {
		hw_cr0 |= KVM_VM_CR0_ALWAYS_ON;
		if (!enable_ept)
			hw_cr0 |= X86_CR0_WP;


	}

	vmcs_writel(CR0_READ_SHADOW, cr0);
	vmcs_writel(GUEST_CR0, hw_cr0);
	vcpu->arch.cr0 = cr0;


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
	// unsigned long old_cr4 = vcpu->arch.cr4;

	/*
	* Pass through host's Machine Check Enable value to hw_cr4, which
	* is in force while we are in guest mode.  Do not let guests control
	* this bit, even if host CR4.MCE == 0.
	*/
	unsigned long hw_cr4;

	hw_cr4 = (cr4 & ~X86_CR4_MCE);

	if (enable_ept) {

	}

	vmcs_writel(CR4_READ_SHADOW, cr4);
	vmcs_writel(GUEST_CR4, hw_cr4);
	
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


		ULONG count = KeQueryActiveProcessorCount(0);
		loaded_vmcss_on_cpu = ExAllocatePoolZero(NonPagedPool,
			count * sizeof(LIST_ENTRY), DRIVER_TAG);
		if (!loaded_vmcss_on_cpu) {
			status = STATUS_NO_MEMORY;
			break;
		}
		for (ULONG i = 0; i < count; i++) {
			InitializeListHead(&loaded_vmcss_on_cpu[i]);
		}

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

	if (loaded_vmcss_on_cpu) {
		ExFreePool(loaded_vmcss_on_cpu);
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
			unsigned long* msr_bitmap = (unsigned long*)ExAllocatePoolZero(PagedPool, PAGE_SIZE, DRIVER_TAG);
			if (!msr_bitmap) {
				status = STATUS_NO_MEMORY;
				break;
			}
			loaded_vmcs->msr_bitmap = msr_bitmap;
		}
	} while (FALSE);

	memset(&loaded_vmcs->host_state, 0, 
		sizeof(struct vmcs_host_state));
	memset(&loaded_vmcs->controls_shadow, 0,
		sizeof(struct vmcs_controls_shadow));

	InitializeListHead(&loaded_vmcs->loaded_vmcss_on_cpu_link);

	return status;
}

void vmx_vcpu_load_vmcs(struct kvm_vcpu* vcpu, int cpu,
	struct loaded_vmcs* buddy) {
	UNREFERENCED_PARAMETER(buddy);
	// vcpu_vmx 是vcpu的一个运行环境，这个和vcpu是一对一的
	struct vcpu_vmx* vmx = to_vmx(vcpu);
	bool already_loaded = vmx->loaded_vmcs->cpu == cpu;
	struct vmcs* prev;

	// 判断是否已经加载
	if (!already_loaded) {
		// 清理当前vcpu使用的vmcs,强制初始化为inactive状态
		loaded_vmcs_clear(vmx->loaded_vmcs);
		// 添加到新cpu的loaded_vmcs链表
		PLIST_ENTRY pEntry = &loaded_vmcss_on_cpu[KeGetCurrentProcessorNumber()];
		InsertHeadList(&vmx->loaded_vmcs->loaded_vmcss_on_cpu_link,
			pEntry);
	}

	prev = current_vmcs[cpu];
	// 当前vcpu正在使用的vmcs和指定cpu的current_vmcs不相等时需要
	// 进行加载
	if (prev != vmx->loaded_vmcs->vmcs) {
		current_vmcs[cpu] = vmx->loaded_vmcs->vmcs;
		// 调用vmptrld
		vmcs_load(vmx->loaded_vmcs->vmcs);
	}

	if (!already_loaded) {
		// 设置cpu
		vmx->loaded_vmcs->cpu = cpu;
	}
}



ULONG_PTR
RunOnTargetCore(
	_In_ ULONG_PTR Argument
) {
	struct loaded_vmcs* loaded_vmcs = (struct loaded_vmcs*)Argument;
	int cpu = KeGetCurrentProcessorNumber();
	if (cpu != loaded_vmcs->cpu) {
		return 1;
	}
	__loaded_vmcs_clear(loaded_vmcs);
	return 0;
}



void loaded_vmcs_clear(struct loaded_vmcs* loaded_vmcs) {
	int cpu = loaded_vmcs->cpu;

	if (cpu != -1) {
		KeIpiGenericCall(RunOnTargetCore, (ULONG_PTR)loaded_vmcs);
	}
}

void dump_vmcs(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	u32 vmentry_ctl, vmexit_ctl;
	u32 cpu_based_exec_ctrl, pin_based_exec_ctrl, secondary_exec_control;
	unsigned long cr4;
	
	if (!dump_invalid_vmcs) {
		return;
	}

	vmentry_ctl = vmcs_read32(VM_ENTRY_CONTROLS);
	vmexit_ctl = vmcs_read32(VM_EXIT_CONTROLS);
	cpu_based_exec_ctrl = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	pin_based_exec_ctrl = vmcs_read32(PIN_BASED_VM_EXEC_CONTROL);
	cr4 = vmcs_readl(GUEST_CR4);

	if (cpu_has_vmx_ept()) {
		LogErr("PDPTR0 = 0x%016llx PDPTR1 = 0x%016llx\n",
			vmcs_read64(GUEST_PDPTR0), vmcs_read64(GUEST_PDPTR1));
		LogErr("PDPTR2 = 0x%16llx PDPTR3 = 0x%016llx\n",
			vmcs_read64(GUEST_PDPTR2), vmcs_read64(GUEST_PDPTR3));
	}

	if (vmentry_ctl & VM_ENTRY_LOAD_IA32_EFER)
		LogErr("EFER= 0x%016llx\n", vmcs_read64(GUEST_IA32_EFER));
	if (vmentry_ctl & VM_ENTRY_LOAD_IA32_PAT)
		LogErr("PAT = 0x%016llx\n", vmcs_read64(GUEST_IA32_PAT));
	if (cpu_has_load_perf_global_ctrl() &&
		vmentry_ctl & VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL)
		LogErr("PerfGlobCtl = 0x%016llx\n",
			vmcs_read64(GUEST_IA32_PERF_GLOBAL_CTRL));
	if (vmentry_ctl & VM_ENTRY_LOAD_BNDCFGS)
		LogErr("BndCfgs = 0x%016llx\n", vmcs_read64(GUEST_BNDCFGS));




	if (cpu_has_secondary_exec_ctrls())
		secondary_exec_control = vmcs_read32(SECONDARY_VM_EXEC_CONTROL);
	else
		secondary_exec_control = 0;


	LogErr("*** Host State ***\n");

	if (vmexit_ctl & VM_EXIT_LOAD_IA32_EFER)
		LogErr("EFER= 0x%016llx\n", vmcs_read64(HOST_IA32_EFER));
	if (vmentry_ctl & VM_EXIT_LOAD_IA32_PAT)
		LogErr("PAT = 0x%016llx\n", vmcs_read64(HOST_IA32_PAT));
	if (cpu_has_load_perf_global_ctrl() &&
		vmexit_ctl & VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL)
		LogErr("PerfGlobCtl = 0x%016llx\n",
			vmcs_read64(HOST_IA32_PERF_GLOBAL_CTRL));

	if (secondary_exec_control & SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY)
		LogErr("InterruptStatus = %04x\n",
			vmcs_read16(GUEST_INTR_STATUS));


	if (secondary_exec_control & SECONDARY_EXEC_TSC_SCALING)
		LogErr("TSC Multiplier = 0x%016llx\n",
			vmcs_read64(TSC_MULTIPLIER));
	if (cpu_based_exec_ctrl & CPU_BASED_TPR_SHADOW) {
		if (secondary_exec_control & SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY) {
			u16 status = vmcs_read16(GUEST_INTR_STATUS);
			LogErr("SVI|RVI = %02X|%02x ", status >> 8, status & 0xFF);
		}
		LogErr("TPM Threshold = 0x%02x\n", vmcs_read32(TPR_THRESHOLD));
		if (secondary_exec_control & SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES)
			LogErr("APIC-access addr = 0x%016llx ",
				vmcs_read64(APIC_ACCESS_ADDR));
	}

	if (pin_based_exec_ctrl & PIN_BASED_POSTED_INTR)
		LogErr("PostedIntrVec = 0x%02x\n", vmcs_read16(POSTED_INTR_NV));
	if ((secondary_exec_control & SECONDARY_EXEC_ENABLE_EPT))
		LogErr("EPT pointer = 0x%016llx\n", vmcs_read64(EPT_POINTER));
	if (secondary_exec_control & SECONDARY_EXEC_PAUSE_LOOP_EXITING)
		LogErr("PLE Gap=%08x Window=%08x\n",
			vmcs_read32(PLE_GAP), vmcs_read32(PLE_WINDOW));
	if (secondary_exec_control & SECONDARY_EXEC_ENABLE_VPID)
		LogErr("Virtual processor ID = 0x%04x\n",
			vmcs_read16(VIRTUAL_PROCESSOR_ID));
}

static u32 vmx_pin_based_exec_ctrl(struct vcpu_vmx* vmx) {
	UNREFERENCED_PARAMETER(vmx);
	u32 pin_based_exec_ctrl = vmcs_config.pin_based_exec_ctrl;

	// 清掉功能
	pin_based_exec_ctrl &= ~PIN_BASED_POSTED_INTR;

	pin_based_exec_ctrl &= ~PIN_BASED_VIRTUAL_NMIS;

	pin_based_exec_ctrl &= ~PIN_BASED_VMX_PREEMPTION_TIMER;
	
	return pin_based_exec_ctrl;
}

static u32 vmx_exec_control(struct vcpu_vmx* vmx)
{
	u32 exec_control = vmcs_config.cpu_based_exec_ctrl;

	/*
	 * Not used by KVM, but fully supported for nesting, i.e. are allowed in
	 * vmcs12 and propagated to vmcs02 when set in vmcs12.
	 */
	exec_control &= ~(CPU_BASED_RDTSC_EXITING |
		CPU_BASED_USE_IO_BITMAPS |
		CPU_BASED_MONITOR_TRAP_FLAG |
		CPU_BASED_PAUSE_EXITING);

	/* INTR_WINDOW_EXITING and NMI_WINDOW_EXITING are toggled dynamically */
	exec_control &= ~(CPU_BASED_INTR_WINDOW_EXITING |
		CPU_BASED_NMI_WINDOW_EXITING);

	if (vmx->vcpu.arch.switch_db_regs & KVM_DEBUGREG_WONT_EXIT)
		exec_control &= ~CPU_BASED_MOV_DR_EXITING;

	//if (!cpu_need_tpr_shadow(&vmx->vcpu))
	exec_control &= ~CPU_BASED_TPR_SHADOW;

#ifdef _WIN64
	if (exec_control & CPU_BASED_TPR_SHADOW)
		exec_control &= ~(CPU_BASED_CR8_LOAD_EXITING |
			CPU_BASED_CR8_STORE_EXITING);
	else
		exec_control |= CPU_BASED_CR8_STORE_EXITING |
		CPU_BASED_CR8_LOAD_EXITING;
#endif
	/* No need to intercept CR3 access or INVPLG when using EPT. */
	if (enable_ept)
		exec_control &= ~(CPU_BASED_CR3_LOAD_EXITING |
			CPU_BASED_CR3_STORE_EXITING |
			CPU_BASED_INVLPG_EXITING);
	if (kvm_mwait_in_guest(vmx->vcpu.kvm))
		exec_control &= ~(CPU_BASED_MWAIT_EXITING |
			CPU_BASED_MONITOR_EXITING);
	if (kvm_hlt_in_guest(vmx->vcpu.kvm))
		exec_control &= ~CPU_BASED_HLT_EXITING;
	return exec_control;
}

static u32 vmx_secondary_exec_control(struct vcpu_vmx* vmx) {
	UNREFERENCED_PARAMETER(vmx);
	u32 exec_control = vmcs_config.cpu_based_2nd_exec_ctrl;

	return exec_control;
}

static void init_vmcs(struct vcpu_vmx* vmx) {

	if (cpu_has_vmx_msr_bitmap()) {
		PHYSICAL_ADDRESS physical = MmGetPhysicalAddress(vmx->vmcs01.msr_bitmap);
		u64 phys_addr = physical.QuadPart;
		vmcs_write64(MSR_BITMAP, phys_addr);
	}


	/* Control */
	pin_controls_set(vmx, vmx_pin_based_exec_ctrl(vmx));

	exec_controls_set(vmx, vmx_exec_control(vmx));

	if (cpu_has_secondary_exec_ctrls())
		secondary_exec_controls_set(vmx, vmx_secondary_exec_control(vmx));

	if (enable_apicv && lapic_in_kernel(&vmx->vcpu)) {
		vmcs_write64(EOI_EXIT_BITMAP0, 0);
		vmcs_write64(EOI_EXIT_BITMAP1, 0);
		vmcs_write64(EOI_EXIT_BITMAP2, 0);
		vmcs_write64(EOI_EXIT_BITMAP3, 0);

		vmcs_write16(GUEST_INTR_STATUS, 0);
		vmcs_write16(POSTED_INTR_NV, POSTED_INTR_VECTOR);

	}


	if (cpu_has_vmx_xsaves())
		vmcs_write64(XSS_EXIT_BITMAP, VMX_XSS_EXIT_BITMAP);

	if (enable_pml) {
		PHYSICAL_ADDRESS physical = MmGetPhysicalAddress(vmx->pml_pg);
		u64 phys_addr = physical.QuadPart;
		vmcs_write64(PML_ADDRESS, phys_addr);
	}

	vmcs_write32(CR3_TARGET_COUNT, 0); /* 22.2.1 */

	vmx_write_encls_bitmap(&vmx->vcpu, NULL);

	if (cpu_has_vmx_vmfunc()) {
		vmcs_write64(VM_FUNCTION_CONTROL, 0);
	}

	if (vmcs_config.vmentry_ctrl & VM_ENTRY_LOAD_IA32_PAT)
		vmcs_write64(GUEST_IA32_PAT, vmx->vcpu.arch.pat);

	vmx->vcpu.arch.cr0_guest_owned_bits = vmx_l1_guest_owned_cr0_bits();
	vmcs_writel(CR0_GUEST_HOST_MASK, ~vmx->vcpu.arch.cr0_guest_owned_bits);

	if (vmx_pt_mode_is_host_guest()) {
		memset(&vmx->pt_desc, 0, sizeof(vmx->pt_desc));
		/* Bit[6~0] are forced to 1, writes are ignored. */
		vmx->pt_desc.guest.output_mask = 0x7F;
		vmcs_write64(GUEST_IA32_RTIT_CTL, 0);
	}

	// use TPR shadow 开启
	if (cpu_has_vmx_tpr_shadow()) {
		vmcs_write64(VIRTUAL_APIC_PAGE_ADDR, 0);
		
		vmcs_write32(TPR_THRESHOLD, 0);
	}
}

static void __vmx_vcpu_reset(struct kvm_vcpu* vcpu) {
	struct vcpu_vmx* vmx = to_vmx(vcpu);

	init_vmcs(vmx);
}

static void vmx_vcpu_reset(struct kvm_vcpu* vcpu, bool init_event) {
	struct vcpu_vmx* vmx = to_vmx(vcpu);

	if (!init_event)
		__vmx_vcpu_reset(vcpu);

	vmx->rmode.vm86_active = 0;
}

void vmx_ept_load_pdptrs(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	// struct kvm_mmu* mmu = vcpu->arch.walk_mmu;

	
	
}

static void vmx_refresh_apicv_exec_ctrl(struct kvm_vcpu* vcpu) {
	struct vcpu_vmx* vmx = to_vmx(vcpu);

	pin_controls_set(vmx, vmx_pin_based_exec_ctrl(vmx));

}

void vmx_update_exception_bitmap(struct kvm_vcpu* vcpu) {
	u32 eb;

	// PF,UD,MC,DB,AC异常
	eb = (1u << PF_VECTOR) | (1u << UD_VECTOR) | (1u << MC_VECTOR) |
		(1u << DB_VECTOR) | (1u << AC_VECTOR);

	/*
	* Guest access to VMware backdoor ports could legitimately
	* trigger #GP because of TSS I/O permission bitmap.
	* We intercept those #GP and allow access to them anyway
	* as VMware does.
	*/
	if (enable_vmware_backdoor)
		eb |= (1u << GP_VECTOR);
	// guest debug 模式
	if ((vcpu->guest_debug &
		(KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP)) ==
		(KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP)) {
		eb |= 1u << BP_VECTOR;
	}
	// 实模式
	if (to_vmx(vcpu)->rmode.vm86_active)
		eb = (u32)~0;
	// 如果不需要拦截pf异常，则清理pf
	if (!vmx_need_pf_intercept(vcpu))
		eb &= ~(1u << PF_VECTOR);

	/* When we are running a nested L2 guest and L1 specified for it a
	* certain exception bitmap, we must trap the same exceptions and pass
	* them to L1. When running L2, we will only handle the exceptions
	* specified above if L1 did not want them.
	*/
	// 嵌套
	if (is_guest_mode(vcpu))
		eb |= get_vmcs12(vcpu)->exception_bitmap;
	else {
		int mask = 0, match = 0;

		if (enable_ept && (eb & (1u << PF_VECTOR))) {
			/*
			 * If EPT is enabled, #PF is currently only intercepted
			 * if MAXPHYADDR is smaller on the guest than on the
			 * host.  In that case we only care about present,
			 * non-reserved faults.  For vmcs02, however, PFEC_MASK
			 * and PFEC_MATCH are set in prepare_vmcs02_rare.
			 */
			mask = PFERR_PRESENT_MASK | PFERR_RSVD_MASK;
			match = PFERR_PRESENT_MASK;
		}
		vmcs_write32(PAGE_FAULT_ERROR_CODE_MASK, mask);
		vmcs_write32(PAGE_FAULT_ERROR_CODE_MATCH, match);
	}

	/*
	 * Disabling xfd interception indicates that dynamic xfeatures
	 * might be used in the guest. Always trap #NM in this case
	 * to save guest xfd_err timely.
	 */
	if (vcpu->arch.xfd_no_write_intercept)
		eb |= (1u << NM_VECTOR);

	// 写入vmcs的VM-execution 控制字段
	vmcs_write32(EXCEPTION_BITMAP, eb);
}

bool vmx_need_pf_intercept(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	if (!enable_ept)
		return TRUE;

	return allow_smaller_maxphyaddr;
}

unsigned long vmx_l1_guest_owned_cr0_bits(void)
{
	unsigned long bits = KVM_POSSIBLE_CR0_GUEST_BITS;

	/*
	 * CR0.WP needs to be intercepted when KVM is shadowing legacy paging
	 * in order to construct shadow PTEs with the correct protections.
	 * Note!  CR0.WP technically can be passed through to the guest if
	 * paging is disabled, but checking CR0.PG would generate a cyclical
	 * dependency of sorts due to forcing the caller to ensure CR0 holds
	 * the correct value prior to determining which CR0 bits can be owned
	 * by L1.  Keep it simple and limit the optimization to EPT.
	 */
	if (!enable_ept)
		bits &= ~X86_CR0_WP;
	return bits;
}

void set_cr4_guest_host_mask(struct vcpu_vmx* vmx) {
	struct kvm_vcpu* vcpu = &vmx->vcpu;

	vcpu->arch.cr4_guest_owned_bits = KVM_POSSIBLE_CR4_GUEST_BITS &
		~vcpu->arch.cr4_guest_rsvd_bits;

	if (!enable_ept) {
		vcpu->arch.cr4_guest_owned_bits &= ~X86_CR4_TLBFLUSH_BITS;
		vcpu->arch.cr4_guest_owned_bits &= ~X86_CR4_PDPTR_BITS;
	}
	if (is_guest_mode(&vmx->vcpu))
		vcpu->arch.cr4_guest_owned_bits &=
		~get_vmcs12(vcpu)->cr4_guest_host_mask;

	vmcs_writel(CR4_GUEST_HOST_MASK, ~vcpu->arch.cr4_guest_owned_bits);
}

/* called to set cr0 as appropriate for a mov-to-cr0 exit. */
static int handle_set_cr0(struct kvm_vcpu* vcpu, unsigned long val) {
	if (is_guest_mode(vcpu)) {

	}
	else {
		if (to_vmx(vcpu)->nested.vmxon &&
			!nested_host_cr0_valid(vcpu, val))
			return 0;

		return kvm_set_cr0(vcpu, val);
	}
}

static int handle_cr(struct kvm_vcpu* vcpu) {
	unsigned long exit_qualification, val;
	int cr;
	int reg;
	int err;

	exit_qualification = vmx_get_exit_qual(vcpu);
	cr = exit_qualification & 15;
	reg = (exit_qualification >> 8) & 15;
	switch ((exit_qualification>>4)&3)
	{
	case 0:/* mov to cr*/
		val = kvm_register_read(vcpu, reg);
		switch (cr)
		{
		case 0:
			err = handle_set_cr0(vcpu, val);
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	return 0;
}

static int handle_set_cr4(struct kvm_vcpu* vcpu, unsigned long val) {
	if (is_guest_mode(vcpu)) {

	}
	else
		return kvm_set_cr4(vcpu, val);
}

static void vmx_set_cpu_caps(void) {
	kvm_set_cpu_caps();
}

static bool vmx_is_valid_cr4(struct kvm_vcpu* vcpu, unsigned long cr4)
{
	/*
	 * We operate under the default treatment of SMM, so VMX cannot be
	 * enabled under SMM.  Note, whether or not VMXE is allowed at all,
	 * i.e. is a reserved bit, is handled by common x86 code.
	 */
	// SMM 下不能启用VMXE
	if ((cr4 & X86_CR4_VMXE) && is_smm(vcpu))
		return FALSE;

	// 嵌套
	if (to_vmx(vcpu)->nested.vmxon && !nested_cr4_valid(vcpu, cr4))
		return FALSE;

	return TRUE;
}

static void vmx_set_apic_access_page_addr(struct kvm_vcpu* vcpu) {

	/* Defer reload until vmcs01 is the current VMCS. */
	if (is_guest_mode(vcpu)) {
		to_vmx(vcpu)->nested.reload_vmcs01_apic_access_page = TRUE;
		return;
	}
	
	// 如果没有开启 virtual APIC accesses
	if (!(secondary_exec_controls_get(to_vmx(vcpu)) &
		SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES))
		return;
}