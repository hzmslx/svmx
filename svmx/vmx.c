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
#include "mmu.h"
#include "hyperv.h"

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


/* Guest_tsc -> host_tsc conversion requires 64-bit division.  */
static int cpu_preemption_timer_multi;
static bool enable_preemption_timer = TRUE;

static bool dump_invalid_vmcs = TRUE;

/*
* 每个物理逻辑cpu一个链表，表示相应cpu上加载过的vmcs
*/
LIST_ENTRY* loaded_vmcss_on_cpu;

extern bool enable_apicv;

/* Default is SYSTEM mode, 1 for host-guest mode */
int pt_mode = PT_MODE_SYSTEM;

#define KVM_VM_CR0_ALWAYS_OFF (X86_CR0_NW | X86_CR0_CD)


extern u32 kvm_nr_uret_msrs;


struct vmcs_config  vmcs_config;
struct vmx_capability vmx_capability;

bool enable_ept_ad_bits = 1;

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

static bool emulate_invalid_guest_state = TRUE;
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

static bool nested = 1;

/* Storage for pre module init parameter parsing */
static enum vmx_l1d_flush_state vmentry_l1d_flush_param = VMENTER_L1D_FLUSH_AUTO;

void ept_sync_global();

extern bool allow_smaller_maxphyaddr;

void vmx_disable_intercept_for_msr(u32 msr, bool longmode_only);
void __vmx_disable_intercept_for_msr(PRTL_BITMAP msr_bitmap, u32 msr);


static void vmx_vcpu_reset(struct kvm_vcpu* vcpu, bool init_event);

void vmcs_writel(unsigned long field, ULONG_PTR val);
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
void vmx_set_cr0(struct kvm_vcpu* vcpu, ULONG_PTR cr0);
void vmx_set_cr3(struct kvm_vcpu* vcpu, ULONG_PTR cr3);
void vmx_set_cr4(struct kvm_vcpu* vcpu, ULONG_PTR cr4);
int vmx_set_efer(struct kvm_vcpu* vcpu, u64 efer);
void vmx_get_idt(struct kvm_vcpu* vcpu, struct desc_ptr* dt);
void vmx_set_idt(struct kvm_vcpu* vcpu, struct desc_ptr* dt);
void vmx_get_gdt(struct kvm_vcpu* vcpu, struct desc_ptr* dt);
void vmx_set_gdt(struct kvm_vcpu* vcpu, struct desc_ptr* dt);
void vmx_cache_reg(struct kvm_vcpu* vcpu, enum kvm_reg reg);
ULONG_PTR vmx_get_rflags(struct kvm_vcpu* vcpu);
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
 * Writes msr value into the appropriate "register".
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
static int vmx_set_msr(struct kvm_vcpu* vcpu, struct msr_data* msr_info);

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

// 建立全局变量vmcs_config和vmx_capability
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
	/*
	* vmptrld指令会检查vmcs指针是否为vmxon指针
	* open the vmx mode
	*/
	__vmx_on(&vmxon_pointer);
	return 0;
}

static int vmx_hardware_enable(void) {
	int cpu = KeGetCurrentProcessorNumber();
	u64 phys_addr = 0;
	int r;


	u64 cr4 = __readcr4();
	if (cr4 & X86_CR4_VMXE)
		return -1;

	/*
	* vol 3c 24.8 RESTRICTIONS ON VMX OPERATION
	* 
	* Ensure bits in CR0 and CR4 are valid in VMX operation:
	* - Bit X is 1 in _FIXED0: bit X is fixed to 1 in CRx.
	* - Bit X is 1 in _FIXED1: bit X is fixed to 0 in CRx.
	*/
	ULONG_PTR cr0;
	cr0 = __readcr0();
	cr0 &= __readmsr(MSR_IA32_VMX_CR0_FIXED1);
	cr0 |= __readmsr(MSR_IA32_VMX_CR0_FIXED0);
	__writecr0(cr0);

	cr4 &= __readmsr(MSR_IA32_VMX_CR4_FIXED1);
	cr4 |= __readmsr(MSR_IA32_VMX_CR4_FIXED0);
	__writecr4(cr4);

	struct vmcs* vmcs = vmxarea[cpu];
	// 获取物理地址
	PHYSICAL_ADDRESS physical = MmGetPhysicalAddress(vmcs);
	phys_addr = physical.QuadPart;
	// 打开VMX操作模式
	r = kvm_cpu_vmxon(phys_addr);
	if (r) {
		return r;
	}

	if (enable_ept) {

	}

	return 0;
}

#define VMX_SEGMENT_FIELD(seg)					\
	[VCPU_SREG_##seg] = {                                   \
		.selector = GUEST_##seg##_SELECTOR,		\
		.base = GUEST_##seg##_BASE,		   	\
		.limit = GUEST_##seg##_LIMIT,		   	\
		.ar_bytes = GUEST_##seg##_AR_BYTES,	   	\
	}

static const struct kvm_vmx_segment_field {
	unsigned selector;
	unsigned base;
	unsigned limit;
	unsigned ar_bytes;
} kvm_vmx_segment_fields[] = {
	VMX_SEGMENT_FIELD(CS),
	VMX_SEGMENT_FIELD(DS),
	VMX_SEGMENT_FIELD(ES),
	VMX_SEGMENT_FIELD(FS),
	VMX_SEGMENT_FIELD(GS),
	VMX_SEGMENT_FIELD(SS),
	VMX_SEGMENT_FIELD(TR),
	VMX_SEGMENT_FIELD(LDTR),
};

static ULONG_PTR host_idt_base;

static inline void vmx_segment_cache_clear(struct vcpu_vmx* vmx)
{
	vmx->segment_cache.bitmask = 0;
}

static void __loaded_vmcs_clear(void* arg) {
	struct loaded_vmcs* loaded_vmcs = arg;
	int cpu = KeGetCurrentProcessorNumber();
	if (current_vmcs[cpu] == loaded_vmcs->vmcs) {
		current_vmcs[cpu] = NULL;
	}
	vmcs_clear(loaded_vmcs->vmcs);
	if (loaded_vmcs->shadow_vmcs && loaded_vmcs->launched)
		vmcs_clear(loaded_vmcs->shadow_vmcs);

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

	cpu_vmxoff();

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
	
	vmx->vmcs01.vcpu_id = vcpu->vcpu_id;
	
	// 分配并初始化这个vcpu对应的vmcs01
	// 需要4K对齐
	/* vmcs 的分配 */
	status = alloc_loaded_vmcs(&vmx->vmcs01);
	if (!NT_SUCCESS(status))
		return status;

	vmx->loaded_vmcs = &vmx->vmcs01;


	return STATUS_SUCCESS;
}

static void vmx_vcpu_free(struct kvm_vcpu* vcpu) {
	struct vcpu_vmx* vmx = to_vmx(vcpu);
	free_loaded_vmcs(vmx->loaded_vmcs);
}


// 保存host的当前状态
void vmx_prepare_switch_to_guest(struct kvm_vcpu* vcpu) {
	struct vcpu_vmx* vmx = to_vmx(vcpu);
	struct vmcs_host_state* host_state;

	ULONG_PTR fs_base, gs_base;
	u16 fs_sel, gs_sel;
	u32 i;


	vmx->req_immediate_exit = FALSE;

	/*
	 * Note that guest MSRs to be saved/restored can also be changed
	 * when guest state is loaded. This happens when guest transitions
	 * to/from long-mode by setting MSR_EFER.LMA.
	 */
	if (!vmx->guest_state_loaded) {
		vmx->guest_uret_msrs_loaded = TRUE;
		for (i = 0; i < kvm_nr_uret_msrs; ++i) {
			if (!vmx->guest_uret_msrs[i].load_into_hardware)
				continue;


		}
	}

	host_state = &vmx->loaded_vmcs->host_state;

	/*
	 * Set host fs and gs selectors.  Unfortunately, 22.2.3 does not
	 * allow segment selectors with cpl > 0 or ti == 1.
	 */
	
#ifdef _WIN64
	fs_sel = vmx_get_fs();
	gs_sel = vmx_get_gs();

	fs_base = _readfsbase_u64();
	gs_base = _readgsbase_u64();
#else


#endif // _WIN64

	vmx_set_host_fs_gs(host_state, fs_sel, gs_sel, fs_base, gs_base);
	vmx->guest_state_loaded = TRUE;
}

void vmx_set_host_fs_gs(struct vmcs_host_state* host, u16 fs_sel, u16 gs_sel,
	ULONG_PTR fs_base, ULONG_PTR gs_base) {
	if (fs_sel != host->fs_sel) {
		if (!(fs_sel & 7))
			vmcs_write16(HOST_FS_SELECTOR, fs_sel);
		else
			vmcs_write16(HOST_FS_SELECTOR, 0);
		host->fs_sel = fs_sel;
	}
	if (gs_sel != host->gs_sel) {
		if (!(gs_sel & 7)) {
			vmcs_write16(HOST_FS_SELECTOR, fs_sel);
		}
		else
			vmcs_write16(HOST_FS_SELECTOR, 0);
	}
	if (fs_base != host->fs_base) {
		vmcs_writel(HOST_FS_BASE, fs_base);
		host->fs_base = fs_base;
	}
	if (gs_base != host->gs_base) {
		vmcs_writel(HOST_GS_BASE, gs_base);
		host->gs_base = gs_base;
	}
}

/*
 * Switches to specified vcpu, until a matching vcpu_put(), but assumes
 * vcpu mutex is already taken.
 */
// 加载vcpu的信息，切换到指定cpu，进入到vmx模式
static void vmx_vcpu_load(struct kvm_vcpu* vcpu, int cpu) {
	
	vmx_vcpu_load_vmcs(vcpu, cpu, NULL);

}

static void vmx_prepare_switch_to_host(struct vcpu_vmx* vmx) {
	struct vmcs_host_state* host_state;

	if (!vmx->guest_state_loaded)
		return;

	host_state = &vmx->loaded_vmcs->host_state;

	++vmx->vcpu.stat.host_state_reload;

	vmx->msr_guest_kernel_gs_base = __readmsr(MSR_KERNEL_GS_BASE);

	if (host_state->ldt_sel || (host_state->gs_sel & 7)) {
		
	}

	vmx->guest_state_loaded = FALSE;
	vmx->guest_uret_msrs_loaded = FALSE;
}

// vmx_vcpu_load的反运算
static void vmx_vcpu_put(struct kvm_vcpu* vcpu) {
	

	vmx_prepare_switch_to_host(to_vmx(vcpu));
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

static inline u32 vmx_get_intr_info(struct kvm_vcpu* vcpu) {
	struct  vcpu_vmx* vmx = to_vmx(vcpu);

	if (!kvm_register_test_and_mark_available(vcpu, VCPU_EXREG_EXIT_INFO_2))
		vmx->exit_intr_info = vmcs_read32(VM_EXIT_INTR_INFO);

	return vmx->exit_intr_info;
}

static void vmx_vcpu_enter_exit(struct kvm_vcpu* vcpu,
	unsigned int flags) {
	struct vcpu_vmx* vmx = to_vmx(vcpu);

	if (vcpu->arch.cr2 != __readcr2())
		vmx_set_cr2(vcpu->arch.cr2);

	vmx->fail = __vmx_vcpu_run(vmx, (ULONG_PTR*)&vcpu->arch.regs, flags);

	vcpu->arch.cr2 = __readcr2();

	if (vmx->fail)
		vmx->exit_reason.full = 0xdead;
	else
		vmx->exit_reason.full = vmcs_read32(VM_EXIT_REASON);

	if(vmx->exit_reason.basic == EXIT_REASON_EXCEPTION_NMI &&
		is_nmi(vmx_get_intr_info(vcpu))) {
		
	}
	
}

static fastpath_t handle_fastpath_preemption_timer(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return EXIT_FASTPATH_NONE;
}

static fastpath_t vmx_exit_handlers_fastpath(struct kvm_vcpu* vcpu) {
	switch (to_vmx(vcpu)->exit_reason.basic) {
	case EXIT_REASON_MSR_WRITE:
		return handle_fastpath_set_msr_irqoff(vcpu);
	case EXIT_REASON_PREEMPTION_TIMER:
		return handle_fastpath_preemption_timer(vcpu);
	default:
		return EXIT_FASTPATH_NONE;
	}
}

extern ULONG_PTR Lclear_regs;

// 运行虚拟机，进入guest模式，即non root 模式
static fastpath_t vmx_vcpu_run(struct kvm_vcpu* vcpu) {
	struct vcpu_vmx* vmx = to_vmx(vcpu);
	ULONG_PTR cr3, cr4;

	if (kvm_register_is_dirty(vcpu, VCPU_REGS_RSP))
		vmcs_writel(GUEST_RSP, vcpu->arch.regs[VCPU_REGS_RSP]);
	if (kvm_register_is_dirty(vcpu, VCPU_REGS_RIP))
		vmcs_writel(GUEST_RIP, vcpu->arch.regs[VCPU_REGS_RIP]);
	vcpu->arch.regs_dirty = 0;

	/*
	* Refresh vmcs.HOST_CR3 if necessary.
	*/
	cr3 = __readcr3();
	if (cr3 != vmx->loaded_vmcs->host_state.cr3) {
		vmcs_writel(HOST_CR3, cr3);
		vmx->loaded_vmcs->host_state.cr3 = cr3;
	}

	cr4 = __readcr4();
	if (cr4 != vmx->loaded_vmcs->host_state.cr4) {
		vmcs_writel(HOST_CR4, cr4);
		vmx->loaded_vmcs->host_state.cr4 = cr4;
	}

	/* When KVM_DEBUGREG_WONT_EXIT, dr6 is accessible in guest */
	if (vcpu->arch.switch_db_regs & KVM_DEBUGREG_WONT_EXIT)
		__writedr(6, vcpu->arch.dr6);

	/* When single-stepping over STI and MOV SS, we must clear the
	 * corresponding interruptibility bits in the guest state. Otherwise
	 * vmentry fails as it then expects bit 14 (BS) in pending debug
	 * exceptions being set, but that's not correct for the guest debugging
	 * case. 
	 */
	// 单步调试时，需要禁用 guest 中断
	if (vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP)
		vmx_set_interrupt_shadow(vcpu, 0);

	vmx_vcpu_enter_exit(vcpu, __vmx_vcpu_run_flags(vmx));

	/* MSR_IA32_DEBUGCTLMSR is zeroed on vmexit. Restore it if needed */
	if (vmx->host_debugctlmsr)
		__writemsr(MSR_IA32_DEBUGCTLMSR, vmx->host_debugctlmsr);

	
	vcpu->arch.regs_avail &= ~VMX_REGS_LAZY_LOAD_SET;

	if (is_guest_mode(vcpu)) {
		/*
		* Track VMLAUNCH/VMRESUME that have made past guest state
		* checking.
		*/
		if (vmx->nested.nested_run_pending &&
			!vmx->exit_reason.failed_vmentry)
			++vcpu->stat.nested_run;

		vmx->nested.nested_run_pending = 0;
	}

	vmx->idt_vectoring_info = 0;

	if (vmx->fail)
		return EXIT_FASTPATH_NONE;

	if (vmx->exit_reason.basic == EXIT_REASON_MCE_DURING_VMENTRY)
		kvm_machine_check();

	if (!vmx->exit_reason.failed_vmentry)
		vmx->idt_vectoring_info = vmcs_read32(IDT_VECTORING_INFO_FIELD);

	if (vmx->exit_reason.failed_vmentry)
		return EXIT_FASTPATH_NONE;

	// 设置已经 vmlaunch
	vmx->loaded_vmcs->launched = 1;

	if (is_guest_mode(vcpu))
		return EXIT_FASTPATH_NONE;

	return vmx_exit_handlers_fastpath(vcpu);
}

static int handle_exception_nmi(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return 0;
}

static int handle_external_interrupt(struct kvm_vcpu* vcpu)
{
	UNREFERENCED_PARAMETER(vcpu);
	++vcpu->stat.irq_exits;
	return 1;
}

static int handle_triple_fault(struct kvm_vcpu* vcpu)
{
	vcpu->run->exit_reason = KVM_EXIT_SHUTDOWN;
	return 0;
}

static int handle_nmi_window(struct kvm_vcpu* vcpu)
{
	exec_controls_clearbit(to_vmx(vcpu), CPU_BASED_NMI_WINDOW_EXITING);
	++vcpu->stat.nmi_window_exits;

	return 1;
}

static int handle_io(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);

	return 0;
}

static int handle_dr(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);

	return 0;
}

static int handle_interrupt_window(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);

	return 1;
}

static int handle_invlpg(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return 0;
}

/*
 * When nested=0, all VMX instruction VM Exits filter here.  The handlers
 * are overwritten by nested_vmx_setup() when nested=1.
 */
static int handle_vmx_instruction(struct kvm_vcpu* vcpu)
{
	UNREFERENCED_PARAMETER(vcpu);
	return 1;
}

static int handle_tpr_below_threshold(struct kvm_vcpu* vcpu)
{
	UNREFERENCED_PARAMETER(vcpu);
	return 1;
}

static int handle_apic_access(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return 0;
}

static int handle_apic_write(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return 0;
}

static int handle_apic_eoi_induced(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return 0;
}

static int handle_task_switch(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return 0;
}

static int handle_machine_check(struct kvm_vcpu* vcpu)
{
	UNREFERENCED_PARAMETER(vcpu);
	/* handled by vmx_vcpu_run() */
	return 1;
}

static int handle_desc(struct kvm_vcpu* vcpu)
{
	UNREFERENCED_PARAMETER(vcpu);
	return 0;
}

static int handle_ept_violation(struct kvm_vcpu* vcpu) {
	unsigned long exit_qualification;
	gpa_t gpa;
	u64 error_code;

	exit_qualification = vmx_get_exit_qual(vcpu);

	gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);

	/* Is it a read fault? */
	error_code = (exit_qualification & EPT_VIOLATION_ACC_READ)
		? PFERR_USER_MASK : 0;
	/* Is it a write fault? */
	error_code |= (exit_qualification & EPT_VIOLATION_ACC_WRITE)
		? PFERR_WRITE_MASK : 0;
	/* Is it a fetch fault? */
	error_code |= (exit_qualification & EPT_VIOLATION_ACC_INSTR)
		? PFERR_FETCH_MASK : 0;
	/* ept page table entry is present? */
	error_code |= (exit_qualification & EPT_VIOLATION_RWX_MASK)
		? PFERR_PRESENT_MASK : 0;

	error_code |= (exit_qualification & EPT_VIOLATION_GVA_TRANSLATED) != 0 ?
		PFERR_GUEST_FINAL_MASK : PFERR_GUEST_PAGE_MASK;

	return kvm_mmu_page_fault(vcpu, gpa, error_code, NULL, 0);
}

static int handle_ept_misconfig(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return 0;
}

static int handle_preemption_timer(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return 0;
}

/*
 * Indicate a busy-waiting vcpu in spinlock. We do not enable the PAUSE
 * exiting, so only get here on cpu with PAUSE-Loop-Exiting.
 */
static int handle_pause(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return 0;
}

static int handle_monitor_trap(struct kvm_vcpu* vcpu)
{
	UNREFERENCED_PARAMETER(vcpu);
	return 1;
}

static int handle_pml_full(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return 1;
}

static int handle_invpcid(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return 1;
}

static int handle_encls(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return 1;
}

static int handle_bus_lock_vmexit(struct kvm_vcpu* vcpu)
{
	/*
	 * Hardware may or may not set the BUS_LOCK_DETECTED flag on BUS_LOCK
	 * VM-Exits. Unconditionally set the flag here and leave the handling to
	 * vmx_handle_exit().
	 */
	to_vmx(vcpu)->exit_reason.bus_lock_detected = TRUE;
	return 1;
}


static int handle_notify(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return 1;
}

static int handle_cr(struct kvm_vcpu* vcpu);
/*
 * The exit handlers return 1 if the exit was handled fully and guest execution
 * may resume.  Otherwise they set the kvm_run parameter to indicate what needs
 * to be done to userspace and return 0.
 */
static int (*kvm_vmx_exit_handlers[])(struct kvm_vcpu* vcpu) = {
	[EXIT_REASON_EXCEPTION_NMI] = handle_exception_nmi,
	[EXIT_REASON_EXTERNAL_INTERRUPT] = handle_external_interrupt,
	[EXIT_REASON_TRIPLE_FAULT] = handle_triple_fault,
	[EXIT_REASON_NMI_WINDOW] = handle_nmi_window,
	// 访问了 IO 设备
	[EXIT_REASON_IO_INSTRUCTION] = handle_io,
	// 访问了 CR 寄存器，地址寄存器
	[EXIT_REASON_CR_ACCESS] = handle_cr,
	// 访问了调试寄存器
	[EXIT_REASON_DR_ACCESS] = handle_dr,
	[EXIT_REASON_CPUID] = kvm_emulate_cpuid,
	[EXIT_REASON_MSR_READ] = kvm_emulate_rdmsr,
	[EXIT_REASON_MSR_WRITE] = kvm_emulate_wrmsr,
	[EXIT_REASON_INTERRUPT_WINDOW] = handle_interrupt_window,
	// guest 执行了hlt指令
	[EXIT_REASON_HLT] = kvm_emulate_halt,
	[EXIT_REASON_INVD] = kvm_emulate_invd,
	[EXIT_REASON_INVLPG] = handle_invlpg,
	[EXIT_REASON_RDPMC] = kvm_emulate_rdpmc,
	[EXIT_REASON_VMCALL] = kvm_emulate_hypercall,
	[EXIT_REASON_VMCLEAR] = handle_vmx_instruction,
	[EXIT_REASON_VMLAUNCH] = handle_vmx_instruction,
	[EXIT_REASON_VMPTRLD] = handle_vmx_instruction,
	[EXIT_REASON_VMPTRST] = handle_vmx_instruction,
	[EXIT_REASON_VMREAD] = handle_vmx_instruction,
	[EXIT_REASON_VMRESUME] = handle_vmx_instruction,
	[EXIT_REASON_VMWRITE] = handle_vmx_instruction,
	[EXIT_REASON_VMOFF] = handle_vmx_instruction,
	[EXIT_REASON_VMON] = handle_vmx_instruction,
	[EXIT_REASON_TPR_BELOW_THRESHOLD] = handle_tpr_below_threshold,
	// 访问了 APIC
	[EXIT_REASON_APIC_ACCESS] = handle_apic_access,
	[EXIT_REASON_APIC_WRITE] = handle_apic_write,
	[EXIT_REASON_EOI_INDUCED] = handle_apic_eoi_induced,
	[EXIT_REASON_WBINVD] = kvm_emulate_wbinvd,
	[EXIT_REASON_XSETBV] = kvm_emulate_xsetbv,
	// 进程切换
	[EXIT_REASON_TASK_SWITCH] = handle_task_switch,
	[EXIT_REASON_MCE_DURING_VMENTRY] = handle_machine_check,
	[EXIT_REASON_GDTR_IDTR] = handle_desc,
	[EXIT_REASON_LDTR_TR] = handle_desc,
	[EXIT_REASON_EPT_VIOLATION] = handle_ept_violation,
	[EXIT_REASON_EPT_MISCONFIG] = handle_ept_misconfig,
	// 执行了暂停指令
	[EXIT_REASON_PAUSE_INSTRUCTION] = handle_pause,
	[EXIT_REASON_MWAIT_INSTRUCTION] = kvm_emulate_mwait,
	[EXIT_REASON_MONITOR_TRAP_FLAG] = handle_monitor_trap,
	[EXIT_REASON_MONITOR_INSTRUCTION] = kvm_emulate_monitor,
	[EXIT_REASON_INVEPT] = handle_vmx_instruction,
	[EXIT_REASON_INVVPID] = handle_vmx_instruction,
	[EXIT_REASON_RDRAND] = kvm_handle_invalid_op,
	[EXIT_REASON_RDSEED] = kvm_handle_invalid_op,
	[EXIT_REASON_PML_FULL] = handle_pml_full,
	[EXIT_REASON_INVPCID] = handle_invpcid,
	[EXIT_REASON_VMFUNC] = handle_vmx_instruction,
	[EXIT_REASON_PREEMPTION_TIMER] = handle_preemption_timer,
	[EXIT_REASON_ENCLS] = handle_encls,
	[EXIT_REASON_BUS_LOCK] = handle_bus_lock_vmexit,
	[EXIT_REASON_NOTIFY] = handle_notify,
};

static const u32 kvm_vmx_max_exit_handlers =
ARRAYSIZE(kvm_vmx_exit_handlers);

static void vmx_flush_pml_buffer(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
}

/*
 * The guest has exited.  See if we can fix it or if we need userspace
 * assistance.
 */
// __vmx_vcpu_run返回 0 表明是 VM-exit, 返回1表明是 VM-Fail
static int __vmx_handle_exit(struct kvm_vcpu* vcpu, fastpath_t exit_fastpath)
{
	struct vcpu_vmx* vmx = to_vmx(vcpu);
	union vmx_exit_reason exit_reason = vmx->exit_reason;
	// u32 vectoring_info = vmx->idt_vectoring_info;
	u16 exit_handler_index;

	/*
	 * Flush logged GPAs PML buffer, this will make dirty_bitmap more
	 * updated. Another good is, in kvm_vm_ioctl_get_dirty_log, before
	 * querying dirty_bitmap, we only need to kick all vcpus out of guest
	 * mode as if vcpus is in root mode, the PML buffer must has been
	 * flushed already.  Note, PML is never enabled in hardware while
	 * running L2.
	 */
	if (enable_pml && !is_guest_mode(vcpu))
		vmx_flush_pml_buffer(vcpu);

	if (is_guest_mode(vcpu)) {
		/*
		 * PML is never enabled when running L2, bail immediately if a
		 * PML full exit occurs as something is horribly wrong.
		 */
		if (exit_reason.basic == EXIT_REASON_PML_FULL)
			goto unexpected_vmexit;

	}

	/* If guest state is invalid, starting emulating. L2 is handled above. */
	

	if (exit_reason.failed_vmentry) {
		dump_vmcs(vcpu);
		vcpu->run->exit_reason = KVM_EXIT_FAIL_ENTRY;
		vcpu->run->fail_entry.hardware_entry_failure_reason
			= exit_reason.full;
		vcpu->run->fail_entry.cpu = vcpu->arch.last_vmentry_cpu;
		return 0;
	}

	if (vmx->fail) {
		dump_vmcs(vcpu);
		vcpu->run->exit_reason = KVM_EXIT_FAIL_ENTRY;
		vcpu->run->fail_entry.hardware_entry_failure_reason
			= vmcs_read32(VM_INSTRUCTION_ERROR);
		vcpu->run->fail_entry.cpu = vcpu->arch.last_vmentry_cpu;
		return 0;
	}


	if (exit_fastpath != EXIT_FASTPATH_NONE)
		return 1;

	if (exit_reason.basic >= kvm_vmx_max_exit_handlers)
		goto unexpected_vmexit;

	exit_handler_index = (u16)exit_reason.basic;

	return kvm_vmx_exit_handlers[exit_handler_index](vcpu);

unexpected_vmexit:
	dump_vmcs(vcpu);
	vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
	

	return 0;
}

static int vmx_handle_exit(struct kvm_vcpu* vcpu, fastpath_t exit_fastpath) {
	int ret = __vmx_handle_exit(vcpu, exit_fastpath);

	/*
	* Exit to user space when bus lock detected to inform that there is
	* a bus lock in guest.
	* 
	*/
	if (to_vmx(vcpu)->exit_reason.bus_lock_detected) {
		if (ret > 0)
			vcpu->run->exit_reason = KVM_EXIT_X86_BUS_LOCK;

		vcpu->run->flags |= KVM_RUN_X86_BUS_LOCK;
		return 0;
	}
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

	/* xsaves_enabled is recomputed in vmx_compute_secondary_exec_control(). */
	vcpu->arch.xsaves_enabled = FALSE;

	if (cpu_has_secondary_exec_ctrls())
		vmcs_set_secondary_exec_control(vmx,
			vmx_secondary_exec_control(vmx));
}

static void vmx_write_tsc_offset(struct kvm_vcpu* vcpu, u64 offset)
{
	UNREFERENCED_PARAMETER(vcpu);
	vmcs_write64(TSC_OFFSET, offset);
}

static void vmx_set_dr7(struct kvm_vcpu* vcpu, ULONG_PTR val)
{
	UNREFERENCED_PARAMETER(vcpu);
	vmcs_writel(GUEST_DR7, val);
}

static void vmx_handle_exit_irqoff(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
}

static void vmx_load_mmu_pgd(struct kvm_vcpu* vcpu, hpa_t root_hpa,
	int root_level);

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

	.set_cr0 = vmx_set_cr0,
	.set_cr4 = vmx_set_cr4,
	.set_efer = vmx_set_efer,
	.set_dr7 = vmx_set_dr7,
	.cache_reg = vmx_cache_reg,
	.get_segment_base = vmx_get_segment_base,
	.set_idt = vmx_set_idt,
	.get_idt = vmx_get_idt,
	.set_gdt = vmx_set_gdt,
	.get_gdt = vmx_get_gdt,


	.vcpu_pre_run = vmx_vcpu_pre_run,
	.vcpu_run = vmx_vcpu_run,
	.handle_exit = vmx_handle_exit,

	.write_tsc_offset = vmx_write_tsc_offset,

	.load_mmu_pgd = vmx_load_mmu_pgd,


	.handle_exit_irqoff = vmx_handle_exit_irqoff,
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

// cpu是否支持vpid
static int cpu_has_vmx_vpid() {
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_ENABLE_VPID;
}

// cpu是否支持ept
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
		lowAddress, highAddress, boundary, MmNonCached, node);
	if (!vmcs)
		return NULL;

	RtlZeroMemory(vmcs, vmcs_config.size);

	/* KVM supports Enlightened VMCS v1 only */


	/* 
	* vmcs区域首DWORD值必须符合VMCS ID
	* revision id 等于 IA32_VMX_BASIC[31:0]
	*/ 
	vmcs->hdr.revision_id = vmcs_config.revision_id;

	if (shadow)
		vmcs->hdr.shadow_vmcs = 1;

	return vmcs;
}

// 分配一个页面用于vmcs
struct vmcs* alloc_vmcs(bool shadow) {
	return alloc_vmcs_cpu(shadow, KeGetCurrentNodeNumber());
}



// 为每个cpu分配一个struct vmcs
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

	if (!cpu_has_vmx_ept() ||
		!cpu_has_vmx_ept_4levels() ||
		!cpu_has_vmx_ept_mt_wb() ||
		!cpu_has_vmx_invept_global())
		enable_ept = 0;

	/* NX support is require for shadow paging. */
	if (!enable_ept) {
		return STATUS_NOT_SUPPORTED;
	}

	if (!cpu_has_vmx_ept_ad_bits() || !enable_ept)
		enable_ept_ad_bits = 0;




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

static int vmx_set_msr(struct kvm_vcpu* vcpu, struct msr_data* msr_info) {
	UNREFERENCED_PARAMETER(vcpu);

	//struct vcpu_vmx* vmx = to_vmx(vcpu);
	//struct vmx_uret_msr* msr;
	int ret = 0;
	u32 msr_index = msr_info->index;
	u64 data = msr_info->data;

	switch (msr_index)
	{

#ifdef _WIN64
	case MSR_FS_BASE:

		__vmx_vmwrite(GUEST_FS_BASE, data);
		break;
	case MSR_GS_BASE:

		__vmx_vmwrite(GUEST_GS_BASE, data);
		break;
#endif
	case MSR_IA32_SYSENTER_CS:
		if (is_guest_mode(vcpu))
			get_vmcs12(vcpu)->guest_sysenter_cs = (u32)data;
		vmcs_write32(GUEST_SYSENTER_CS, (u32)data);
		break;
	case MSR_IA32_SYSENTER_EIP:
		vmcs_writel(GUEST_SYSENTER_EIP, data);
		break;
	case MSR_IA32_SYSENTER_ESP:
		vmcs_writel(GUEST_SYSENTER_ESP, data);
		break;

	default:
		break;
	}

	return ret;
}

u64 vmx_get_segment_base(struct kvm_vcpu* vcpu, int seg) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(seg);

	return 0;
}

void vmx_set_segment(struct kvm_vcpu* vcpu,
	struct kvm_segment* var, int seg) {
	__vmx_set_segment(vcpu, var, seg);
	
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

static void enter_pmode(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
}

static void enter_rmode(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
}

#ifdef _WIN64
static void enter_lmode(struct kvm_vcpu* vcpu)
{
	UNREFERENCED_PARAMETER(vcpu);
}
#endif

void vmx_set_cr0(struct kvm_vcpu* vcpu, ULONG_PTR cr0) {
	struct vcpu_vmx* vmx = to_vmx(vcpu);
	ULONG_PTR hw_cr0, old_cr0_pg;
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

		if (vmx->rmode.vm86_active && (cr0 & X86_CR0_PE))
			enter_pmode(vcpu);

		if (!vmx->rmode.vm86_active && !(cr0 & X86_CR0_PE))
			enter_rmode(vcpu);
	}

	vmcs_writel(CR0_READ_SHADOW, cr0);
	vmcs_writel(GUEST_CR0, hw_cr0);
	vcpu->arch.cr0 = cr0;


#ifdef  _WIN64
	if (vcpu->arch.efer & EFER_LME) {
		if (!old_cr0_pg && (cr0 & X86_CR0_PG))
			enter_lmode(vcpu);
		else if (old_cr0_pg && !(cr0 & X86_CR0_PG))
			enter_lmode(vcpu);
	}
#endif //  _WIN64


}

void vmx_set_cr3(struct kvm_vcpu* vcpu, ULONG_PTR cr3) {
	UNREFERENCED_PARAMETER(vcpu);
	ULONG_PTR guest_cr3;

	guest_cr3 = cr3;
	if (enable_ept) {
		
	}

}

#define KVM_VM_CR4_ALWAYS_ON_UNRESTRICTED_GUEST X86_CR4_VMXE
#define KVM_PMODE_VM_CR4_ALWAYS_ON (X86_CR4_PAE | X86_CR4_VMXE)
#define KVM_RMODE_VM_CR4_ALWAYS_ON (X86_CR4_VME | X86_CR4_PAE | X86_CR4_VMXE)

void vmx_set_cr4(struct kvm_vcpu* vcpu, ULONG_PTR cr4) {
	//unsigned long old_cr4 = vcpu->arch.cr4;
	struct vcpu_vmx* vmx = to_vmx(vcpu);

	/*
	* Pass through host's Machine Check Enable value to hw_cr4, which
	* is in force while we are in guest mode.  Do not let guests control
	* this bit, even if host CR4.MCE == 0.vmx_set_cr4(
	*/
	unsigned long hw_cr4;

	hw_cr4 = cr4 & ~X86_CR4_MCE;
	if (is_unrestricted_guest(vcpu))
		hw_cr4 |= KVM_VM_CR4_ALWAYS_ON_UNRESTRICTED_GUEST;
	else if (vmx->rmode.vm86_active)
		hw_cr4 |= KVM_RMODE_VM_CR4_ALWAYS_ON;
	else
		hw_cr4 |= KVM_PMODE_VM_CR4_ALWAYS_ON;


	vcpu->arch.cr4 = cr4;

	if (!is_unrestricted_guest(vcpu)) {
		if (enable_ept) {

		}
	}
	

	vmcs_writel(CR4_READ_SHADOW, cr4);
	vmcs_writel(GUEST_CR4, hw_cr4);
	
	//if ((cr4 ^ old_cr4) & (X86_CR4_OSXSAVE | X86_CR4_PKE))
	//	kvm_update_cpuid_runtime(vcpu);
}

int vmx_set_efer(struct kvm_vcpu* vcpu, u64 efer) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(efer);

	return 0;
}

void vmx_get_idt(struct kvm_vcpu* vcpu, struct desc_ptr* dt) {
	UNREFERENCED_PARAMETER(vcpu);
	dt->size = vmcs_read16(GUEST_IDTR_LIMIT);
	dt->address = vmcs_readl(GUEST_IDTR_BASE);
}

void vmx_set_idt(struct kvm_vcpu* vcpu, struct desc_ptr* dt) {
	UNREFERENCED_PARAMETER(vcpu);
	vmcs_write32(GUEST_IDTR_LIMIT, dt->size);
	vmcs_writel(GUEST_IDTR_BASE, dt->address);
}

void vmx_get_gdt(struct kvm_vcpu* vcpu, struct desc_ptr* dt) {
	UNREFERENCED_PARAMETER(vcpu);
	dt->size = vmcs_read16(GUEST_GDTR_LIMIT);
	dt->address = vmcs_readl(GUEST_GDTR_BASE);
}

void vmx_set_gdt(struct kvm_vcpu* vcpu, struct desc_ptr* dt) {
	UNREFERENCED_PARAMETER(vcpu);
	vmcs_write32(GUEST_GDTR_LIMIT, dt->size);
	vmcs_writel(GUEST_GDTR_BASE, dt->address);
}



void vmx_cache_reg(struct kvm_vcpu* vcpu, enum kvm_reg reg) {
	ULONG_PTR guest_owned_bits;

	kvm_register_mark_available(vcpu, reg);

	switch (reg)
	{
	case VCPU_REGS_RSP:
		vcpu->arch.regs[VCPU_REGS_RSP] = vmcs_readl(GUEST_RSP);
		break;
	case VCPU_REGS_RIP:
		vcpu->arch.regs[VCPU_REGS_RIP] = vmcs_readl(GUEST_RIP);
		break;
	case VCPU_EXREG_PDPTR:
		if (enable_ept)
			ept_save_pdptrs(vcpu);
		break;
	case VCPU_EXREG_CR0:
		guest_owned_bits = vcpu->arch.cr0_guest_owned_bits;

		vcpu->arch.cr0 &= ~guest_owned_bits;
		vcpu->arch.cr0 |= vmcs_readl(GUEST_CR0) & guest_owned_bits;
		break;
	case VCPU_EXREG_CR3:
		/*
		 * When intercepting CR3 loads, e.g. for shadowing paging, KVM's
		 * CR3 is loaded into hardware, not the guest's CR3.
		 */
		if (!(exec_controls_get(to_vmx(vcpu)) & CPU_BASED_CR3_LOAD_EXITING))
			vcpu->arch.cr3 = vmcs_readl(GUEST_CR3);
		break;
	case VCPU_EXREG_CR4:
		guest_owned_bits = vcpu->arch.cr4_guest_owned_bits;

		vcpu->arch.cr4 &= ~guest_owned_bits;
		vcpu->arch.cr4 |= vmcs_readl(GUEST_CR4) & guest_owned_bits;
		break;
	default:
		break;
	}
}

ULONG_PTR vmx_get_rflags(struct kvm_vcpu* vcpu) {
	ULONG_PTR rflags;

	rflags = vmcs_readl(GUEST_RFLAGS);
	if (to_vmx(vcpu)->rmode.vm86_active)
		rflags &= ~(ULONG_PTR)(X86_EFLAGS_IOPL | X86_EFLAGS_VM);
	return rflags;
}

void vmx_set_rflags(struct kvm_vcpu* vcpu, unsigned long rflags) {
	struct vcpu_vmx* vmx = to_vmx(vcpu);
	ULONG_PTR old_rflags;

	if (is_unrestricted_guest(vcpu)) {
		kvm_register_mark_available(vcpu, VCPU_EXREG_RFLAGS);
		vmx->rflags = rflags;
		vmcs_writel(GUEST_RFLAGS, rflags);
		return;
	}

	old_rflags = vmx_get_rflags(vcpu);
	vmx->rflags = rflags;
	if (vmx->rmode.vm86_active) {
		vmx->rmode.save_rflags = rflags;
		rflags |= X86_EFLAGS_IOPL | X86_EFLAGS_VM;
	}
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

static bool vmx_segment_cache_test_set(struct vcpu_vmx* vmx, unsigned seg,
	unsigned field)
{
	bool ret;
	u32 mask = 1 << (seg * SEG_FIELD_NR + field);

	if (!kvm_register_is_available(&vmx->vcpu, VCPU_EXREG_SEGMENTS)) {
		kvm_register_mark_available(&vmx->vcpu, VCPU_EXREG_SEGMENTS);
		vmx->segment_cache.bitmask = 0;
	}
	ret = vmx->segment_cache.bitmask & mask;
	vmx->segment_cache.bitmask |= mask;
	return ret;
}

static u16 vmx_read_guest_seg_selector(struct vcpu_vmx* vmx, unsigned seg)
{
	u16* p = &vmx->segment_cache.seg[seg].selector;

	if (!vmx_segment_cache_test_set(vmx, seg, SEG_FIELD_SEL))
		*p = vmcs_read16(kvm_vmx_segment_fields[seg].selector);
	return *p;
}

static ULONG_PTR vmx_read_guest_seg_base(struct vcpu_vmx* vmx, unsigned seg)
{
	ULONG_PTR* p = &vmx->segment_cache.seg[seg].base;

	if (!vmx_segment_cache_test_set(vmx, seg, SEG_FIELD_BASE))
		*p = vmcs_readl(kvm_vmx_segment_fields[seg].base);
	return *p;
}

static u32 vmx_read_guest_seg_limit(struct vcpu_vmx* vmx, unsigned seg)
{
	u32* p = &vmx->segment_cache.seg[seg].limit;

	if (!vmx_segment_cache_test_set(vmx, seg, SEG_FIELD_LIMIT))
		*p = vmcs_read32(kvm_vmx_segment_fields[seg].limit);
	return *p;
}

static u32 vmx_read_guest_seg_ar(struct vcpu_vmx* vmx, unsigned seg)
{
	u32* p = &vmx->segment_cache.seg[seg].ar;

	if (!vmx_segment_cache_test_set(vmx, seg, SEG_FIELD_AR))
		*p = vmcs_read32(kvm_vmx_segment_fields[seg].ar_bytes);
	return *p;
}

void vmx_get_segment(struct kvm_vcpu* vcpu,
	struct kvm_segment* var, int seg) {
	struct vcpu_vmx* vmx = to_vmx(vcpu);
	u32 ar;

	if (vmx->rmode.vm86_active && seg != VCPU_SREG_LDTR) {
		*var = vmx->rmode.segs[seg];
		if (seg == VCPU_SREG_TR
			|| var->selector == vmx_read_guest_seg_selector(vmx, seg))
			return;
		var->base = vmx_read_guest_seg_base(vmx, seg);
		var->selector = vmx_read_guest_seg_selector(vmx, seg);
		return;
	}
	var->base = vmx_read_guest_seg_base(vmx, seg);
	var->limit = vmx_read_guest_seg_limit(vmx, seg);
	var->selector = vmx_read_guest_seg_selector(vmx, seg);
	ar = vmx_read_guest_seg_ar(vmx, seg);
	var->unusable = (ar >> 16) & 1;
	var->type = ar & 15;
	var->s = (ar >> 4) & 1;
	var->dpl = (ar >> 5) & 3;
	/*
	 * Some userspaces do not preserve unusable property. Since usable
	 * segment has to be present according to VMX spec we can use present
	 * property to amend userspace bug by making unusable segment always
	 * nonpresent. vmx_segment_access_rights() already marks nonpresent
	 * segment as unusable.
	 */
	var->present = !var->unusable;
	var->avl = (ar >> 12) & 1;
	var->l = (ar >> 13) & 1;
	var->db = (ar >> 14) & 1;
	var->g = (ar >> 15) & 1;
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

		return status;
	} while (FALSE);

	// error handler
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

ULONG_PTR VmcsClearOnSpecificCore(ULONG_PTR arg) {
	struct loaded_vmcs* loaded_vmcs = (struct loaded_vmcs* )arg;
	int cpu = KeGetCurrentProcessorNumber();
	if(cpu == loaded_vmcs->vcpu_id)
		vmcs_clear(loaded_vmcs->vmcs);
	return 0;
}

// loaded_vmcs的分配以及初始化
int alloc_loaded_vmcs(struct loaded_vmcs* loaded_vmcs) {
	loaded_vmcs->vmcs = alloc_vmcs(FALSE);
	if (!loaded_vmcs->vmcs)
		return STATUS_NO_MEMORY;

	NTSTATUS status = STATUS_SUCCESS;

	// 调用 vmclear
	KeIpiGenericCall(VmcsClearOnSpecificCore, (ULONG_PTR)loaded_vmcs);

	loaded_vmcs->shadow_vmcs = NULL;
	loaded_vmcs->hv_timer_soft_disabled = FALSE;
	loaded_vmcs->cpu = -1;
	loaded_vmcs->launched = 0;

	do
	{
		if (cpu_has_vmx_msr_bitmap()) {
			// 分配msr_bitmap页面
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

ULONG_PTR VmcsLoadOnSpecificCore(ULONG_PTR Arg) {
	struct loaded_vmcs* loaded_vmcs = (struct loaded_vmcs*)Arg;
	int vcpu_id = KeGetCurrentProcessorNumber();
	if (vcpu_id == loaded_vmcs->vcpu_id) {
		// 调用vmptrld指令将目标VMCS加载为current-VMCS
		vmcs_load(loaded_vmcs->vmcs);
	}
	return 0;
}

static uint32_t x86_segment_base(x86_segment_descriptor* desc) {
	return (uint32_t)((desc->base2 << 24) | (desc->base1 << 16) | desc->base0);
}

static ULONG_PTR get_segment_base(ULONG_PTR gdt_base, USHORT selector) {
	x86_segment_selector sel = { selector };

	if (sel.ti == LDT_SEL) {
		x86_segment_selector ldt_sel = { vmx_sldt() };
		x86_segment_descriptor* desc = (x86_segment_descriptor*)(gdt_base +
			ldt_sel.index * sizeof(x86_segment_descriptor));
		uint32_t ldt_base = x86_segment_base(desc);
		desc = (x86_segment_descriptor*)(ldt_base + sel.index * sizeof(x86_segment_descriptor));
		return x86_segment_base(desc);
	}
	else {
		x86_segment_descriptor* desc = (x86_segment_descriptor*)(gdt_base +
			sel.index * sizeof(x86_segment_descriptor));
		return x86_segment_base(desc);
	}

}

// 加载vmcs
void vmx_vcpu_load_vmcs(struct kvm_vcpu* vcpu, int cpu,
	struct loaded_vmcs* buddy) {
	UNREFERENCED_PARAMETER(buddy);
	// vcpu_vmx 是vcpu的一个运行环境，这个和vcpu是一对一的
	struct vcpu_vmx* vmx = to_vmx(vcpu);
	// 是否已经加载
	bool already_loaded = vmx->loaded_vmcs->cpu == cpu;
	struct vmcs* prev;

	// 判断是否已经加载
	if (!already_loaded) {
		/*
		* 没有加载时，调用vmclear命令，用于对该vmcs区域初始化
		* 包括将数据填充到vmcs区域和将vmcs状态置为clear
		*/
		loaded_vmcs_clear(vmx->loaded_vmcs);

		// 插入到相应cpu上的loaded_vmcs链表
		InsertHeadList(&loaded_vmcss_on_cpu[cpu], 
			&vmx->loaded_vmcs->loaded_vmcss_on_cpu_link);
	}

	prev = current_vmcs[cpu];
	// 当前vcpu正在使用的vmcs和指定cpu的current_vmcs不相等时需要
	// 进行加载
	if (prev != vmx->loaded_vmcs->vmcs) {
		// 赋值cpu的current_vmcs
		current_vmcs[cpu] = vmx->loaded_vmcs->vmcs;
		// 加载这个vmcs为current-VMCS
		KeIpiGenericCall(VmcsLoadOnSpecificCore, (ULONG_PTR)vmx->loaded_vmcs);
	}

	if (!already_loaded) { // 未加载时的执行逻辑
		struct desc_ptr gdt;
		vmx_sgdt(&gdt);
		uint16_t sel = vmx_str();
		ULONG_PTR base = get_segment_base(gdt.address, sel);
		/*
		 * per-cpu TSS and GDT ?, so set these when switching
		 * processors.  See 22.2.4.
		 */
		vmcs_writel(HOST_TR_BASE, base);
		vmcs_writel(HOST_GDTR_BASE, gdt.address);

		// 关联cpu
		vmx->loaded_vmcs->cpu = cpu;
	}
}



ULONG_PTR
RunOnTargetCore(
	_In_ ULONG_PTR Argument
) {
	struct loaded_vmcs* loaded_vmcs = (struct loaded_vmcs*)Argument;
	int vcpu_id = KeGetCurrentProcessorNumber();
	if (vcpu_id != loaded_vmcs->vcpu_id) {
		return 1;
	}
	int cpu = loaded_vmcs->cpu;
	if (cpu != -1)
		__loaded_vmcs_clear(loaded_vmcs);
	return 0;
}



void loaded_vmcs_clear(struct loaded_vmcs* loaded_vmcs) {
	int cpu = loaded_vmcs->cpu;

	if (cpu != -1) {
		KeIpiGenericCall(RunOnTargetCore, (ULONG_PTR)loaded_vmcs);
	}
}

static void vmx_dump_sel(char* name, uint32_t sel) {
	LogErr("%s sel=0x%04x, attr=0x%05x, limit=0x%08x, base=0x%016lx\n",
		name, vmcs_read16(sel),
		vmcs_read32(sel + GUEST_ES_AR_BYTES - GUEST_ES_SELECTOR),
		vmcs_read32(sel + GUEST_ES_LIMIT - GUEST_ES_SELECTOR),
		vmcs_readl(sel + GUEST_ES_BASE - GUEST_ES_SELECTOR));
}

static void vmx_dump_dtsel(char* name, uint32_t limit) {
	LogErr("%s				limit=0x%08x, base=0x%016lx\n",
		name, vmcs_read32(limit),
		vmcs_readl(limit + GUEST_GDTR_BASE - GUEST_GDTR_LIMIT));
}

void dump_vmcs(struct kvm_vcpu* vcpu) {
	struct vcpu_vmx* vmx = to_vmx(vcpu);
	u32 vmentry_ctl, vmexit_ctl;
	u32 cpu_based_exec_ctrl, pin_based_exec_ctrl, secondary_exec_control;
	u64 tertiary_exec_control;
	ULONG_PTR cr4;
	
	if (!dump_invalid_vmcs) {
		return;
	}

	vmentry_ctl = vmcs_read32(VM_ENTRY_CONTROLS);
	vmexit_ctl = vmcs_read32(VM_EXIT_CONTROLS);
	cpu_based_exec_ctrl = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	pin_based_exec_ctrl = vmcs_read32(PIN_BASED_VM_EXEC_CONTROL);
	cr4 = vmcs_readl(GUEST_CR4);

	if (cpu_has_secondary_exec_ctrls())
		secondary_exec_control = vmcs_read32(SECONDARY_VM_EXEC_CONTROL);
	else
		secondary_exec_control = 0;

	if (cpu_has_tertiary_exec_ctrls())
		tertiary_exec_control = vmcs_read64(TERTIARY_VM_EXEC_CONTROL);
	else
		tertiary_exec_control = 0;

	LogErr("VMCS %p, last attempted VM-entry on CPU %d\n",
		vmx->loaded_vmcs->vmcs, vcpu->arch.last_vmentry_cpu);
	LogErr("*** Guest State ***\n");
	LogErr("CR0: actual=0x%016lx,shadow=0x%016lx,gh_mask=%016lx\n",
		vmcs_readl(GUEST_CR0), vmcs_readl(CR0_READ_SHADOW),
		vmcs_readl(CR0_GUEST_HOST_MASK));
	LogErr("CR4: actual=0x%016lx,shadow=0x%016lx,gh_mask=%016lx\n",
		vmcs_readl(GUEST_CR4), vmcs_readl(CR4_READ_SHADOW),
		vmcs_readl(CR4_GUEST_HOST_MASK));
	LogErr("CR3 = 0x%016lx\n", vmcs_readl(GUEST_CR3));
	if (cpu_has_vmx_ept()) {
		LogErr("PDPTR0 = 0x%016llx PDPTR1 = 0x%016llx\n",
			vmcs_read64(GUEST_PDPTR0), vmcs_read64(GUEST_PDPTR1));
		LogErr("PDPTR2 = 0x%016llx PDPTR3 = 0x%016llx\n",
			vmcs_read64(GUEST_PDPTR2), vmcs_read64(GUEST_PDPTR3));
	}
	LogErr("RSP = 0x%016lx RIP = 0x%016lx\n",
		vmcs_readl(GUEST_RIP), vmcs_readl(GUEST_RIP));
	LogErr("RFLAGS=0x%08lx		DR7 = 0x%016lx\n",
		vmcs_readl(GUEST_RFLAGS), vmcs_readl(GUEST_DR7));
	LogErr("Sysenter RSP=%016lx CS:RIP=%04x:%016lx\n",
		vmcs_readl(GUEST_SYSENTER_ESP),
		vmcs_read32(GUEST_SYSENTER_CS), vmcs_readl(GUEST_SYSENTER_EIP));
	vmx_dump_sel("CS:  ", GUEST_CS_SELECTOR);
	vmx_dump_sel("DS:  ", GUEST_DS_SELECTOR);
	vmx_dump_sel("SS:  ", GUEST_SS_SELECTOR);
	vmx_dump_sel("ES:  ", GUEST_ES_SELECTOR);
	vmx_dump_sel("FS:  ", GUEST_FS_SELECTOR);
	vmx_dump_sel("GS:  ", GUEST_GS_SELECTOR);
	vmx_dump_dtsel("GDTR:", GUEST_GDTR_LIMIT);
	vmx_dump_sel("LDTR:", GUEST_LDTR_SELECTOR);
	vmx_dump_dtsel("IDTR:", GUEST_IDTR_LIMIT);
	vmx_dump_sel("TR:  ", GUEST_TR_SELECTOR);

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



	LogErr("*** Host State ***\n");
	LogErr("RIP = 0x%016lx RSP = 0x%016lx\n",
		vmcs_readl(HOST_RIP), vmcs_readl(HOST_RSP));
	LogErr("CS=%04x SS=%04x DS=%04x ES=%04x FS=%04x GS=%04x TR=%04x\n",
		vmcs_read16(HOST_CS_SELECTOR), vmcs_read16(HOST_SS_SELECTOR),
		vmcs_read16(HOST_DS_SELECTOR), vmcs_read16(HOST_ES_SELECTOR),
		vmcs_read16(HOST_FS_SELECTOR), vmcs_read16(HOST_GS_SELECTOR),
		vmcs_read16(HOST_TR_SELECTOR));
	LogErr("FSBase=%016lx GSBase=%016lx TRBase=%016lx\n",
		vmcs_readl(HOST_FS_BASE), vmcs_readl(HOST_GS_BASE),
		vmcs_readl(HOST_TR_BASE));
	LogErr("GDTBase=%016lx IDTBase=%016lx\n",
		vmcs_readl(HOST_GDTR_BASE), vmcs_readl(HOST_IDTR_BASE));
	LogErr("CR0=%016lx CR3=%016lx CR4=%016lx\n",
		vmcs_readl(HOST_CR0), vmcs_readl(HOST_CR3),
		vmcs_readl(HOST_CR4));
	LogErr("Sysenter RSP=%016lx CS:RIP=%04x:%016lx\n",
		vmcs_readl(HOST_IA32_SYSENTER_ESP),
		vmcs_read32(HOST_IA32_SYSENTER_CS),
		vmcs_readl(HOST_IA32_SYSENTER_EIP));
	if (vmexit_ctl & VM_EXIT_LOAD_IA32_EFER)
		LogErr("EFER= 0x%016llx\n", vmcs_read64(HOST_IA32_EFER));
	if (vmentry_ctl & VM_EXIT_LOAD_IA32_PAT)
		LogErr("PAT = 0x%016llx\n", vmcs_read64(HOST_IA32_PAT));
	if (cpu_has_load_perf_global_ctrl() &&
		vmexit_ctl & VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL)
		LogErr("PerfGlobCtl = 0x%016llx\n",
			vmcs_read64(HOST_IA32_PERF_GLOBAL_CTRL));

	LogErr("*** Control State ***\n");
	LogErr("CPUBased=0x%08x SecondaryExec=0x%08x TertiaryExec=0x%016llx\n",
		cpu_based_exec_ctrl, secondary_exec_control, tertiary_exec_control);
	LogErr("PinBased=0x%08x EntryControls=%08x ExitControls=%08x\n",
		pin_based_exec_ctrl, vmentry_ctl, vmexit_ctl);
	LogErr("ExceptionBitmap=%08x PFECmask=%08x PFECmatch=%08x\n",
		vmcs_read32(EXCEPTION_BITMAP),
		vmcs_read32(PAGE_FAULT_ERROR_CODE_MASK),
		vmcs_read32(PAGE_FAULT_ERROR_CODE_MATCH));
	LogErr("VMEntry: intr_info=%08x errcode=%08x ilen=%08x\n",
		vmcs_read32(VM_ENTRY_INTR_INFO_FIELD),
		vmcs_read32(VM_ENTRY_EXCEPTION_ERROR_CODE),
		vmcs_read32(VM_ENTRY_INSTRUCTION_LEN));
	LogErr("VMExit: intr_info=%08x errcode=%08x ilen=%08x\n",
		vmcs_read32(VM_EXIT_INTR_INFO),
		vmcs_read32(VM_EXIT_INTR_ERROR_CODE),
		vmcs_read32(VM_EXIT_INSTRUCTION_LEN));
	LogErr("        reason=%08x qualification=%016lx\n",
		vmcs_read32(VM_EXIT_REASON), vmcs_readl(EXIT_QUALIFICATION));
	LogErr("IDTVectoring: info=%08x errcode=%08x\n",
		vmcs_read32(IDT_VECTORING_INFO_FIELD),
		vmcs_read32(IDT_VECTORING_ERROR_CODE));
	LogErr("TSC Offset = 0x%016llx\n", vmcs_read64(TSC_OFFSET));
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
			LogErr("APIC-access addr = 0x%016llx \n",
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

	if (!cpu_need_tpr_shadow(&vmx->vcpu))
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

static u32 vmx_vmexit_ctrl(void) {
	u32 vmexit_ctrl = vmcs_config.vmexit_ctrl;

	/*
	 * Not used by KVM and never set in vmcs01 or vmcs02, but emulated for
	 * nested virtualization and thus allowed to be set in vmcs12.
	 */
	vmexit_ctrl &= ~(VM_EXIT_SAVE_IA32_PAT | VM_EXIT_SAVE_IA32_EFER |
		VM_EXIT_SAVE_VMX_PREEMPTION_TIMER);

	if (vmx_pt_mode_is_system())
		vmexit_ctrl &= ~(VM_EXIT_PT_CONCEAL_PIP | 
			VM_EXIT_CLEAR_IA32_RTIT_CTL);

	/* Loading of EFER and PERF_GLOBAL_CTRL are toggled dynamically */
	return vmexit_ctrl &
		~(VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL | VM_EXIT_LOAD_IA32_EFER);
}

static u32 vmx_vmentry_ctrl(void) {
	u32 vmentry_ctrl = vmcs_config.vmentry_ctrl;

	if (vmx_pt_mode_is_system())
		vmentry_ctrl &= ~(VM_ENTRY_PT_CONCEAL_PIP |
			VM_ENTRY_LOAD_IA32_RTIT_CTL);

	/*
	 * IA32e mode, and loading of EFER and PERF_GLOBAL_CTRL are toggled dynamically.
	 */
	vmentry_ctrl &= ~(VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL |
		VM_ENTRY_LOAD_IA32_EFER |
		VM_ENTRY_IA32E_MODE);

	return vmentry_ctrl;
}

static void init_vmcs(struct vcpu_vmx* vmx) {

	if (cpu_has_vmx_msr_bitmap()) {
		PHYSICAL_ADDRESS physical = MmGetPhysicalAddress(vmx->vmcs01.msr_bitmap);
		u64 phys_addr = physical.QuadPart;
		vmcs_write64(MSR_BITMAP, phys_addr);
	}

	vmcs_write64(VMCS_LINK_POINTER, INVALID_GPA);

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

	vmcs_write32(PAGE_FAULT_ERROR_CODE_MASK, 0);
	vmcs_write32(PAGE_FAULT_ERROR_CODE_MATCH, 0);
	vmcs_write32(CR3_TARGET_COUNT, 0); /* 22.2.1 */

	vmcs_write16(HOST_FS_SELECTOR, 0); /* 22.2.4 */
	vmcs_write16(HOST_GS_SELECTOR, 0); /* 22.2.4 */
	vmx_set_constant_host_state(vmx);

	vmcs_writel(HOST_FS_BASE, __readmsr(MSR_FS_BASE)); /* 22.2.4 */
	vmcs_writel(HOST_GS_BASE, __readmsr(MSR_GS_BASE)); /* 22.2.4 */

	vmcs_write32(VM_EXIT_MSR_STORE_COUNT, 0);
	vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, 0);

	vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, 0);

	if (cpu_has_vmx_xsaves())
		vmcs_write64(XSS_EXIT_BITMAP, VMX_XSS_EXIT_BITMAP);

	if (enable_pml) {
		PHYSICAL_ADDRESS physical = MmGetPhysicalAddress(vmx->pml_pg);
		u64 phys_addr = physical.QuadPart;
		vmcs_write64(PML_ADDRESS, phys_addr);
	}

	vmx_write_encls_bitmap(&vmx->vcpu, NULL);

	if (cpu_has_vmx_vmfunc()) {
		vmcs_write64(VM_FUNCTION_CONTROL, 0);
	}

	if (vmcs_config.vmentry_ctrl & VM_ENTRY_LOAD_IA32_PAT)
		vmcs_write64(GUEST_IA32_PAT, vmx->vcpu.arch.pat);

	vm_exit_controls_set(vmx, vmx_vmexit_ctrl());

	/* 22.2.1, 20.8.1 */
	vm_entry_controls_set(vmx, vmx_vmentry_ctrl());

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

	u64 cs = __readmsr(MSR_IA32_SYSENTER_CS);
	vmcs_write32(GUEST_SYSENTER_CS, (u32)cs);
	vmcs_writel(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
	vmcs_writel(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
	u64 value = __readmsr(MSR_IA32_DEBUGCTLMSR);
	value &= 0xFFFFFFFF;
	vmcs_write64(GUEST_IA32_DEBUGCTL, value);
	value = __readmsr(MSR_IA32_DEBUGCTLMSR);
	value >>= 32;
	
	

	vmcs_writel(GUEST_RIP, Lclear_regs);
}




static void __vmx_vcpu_reset(struct kvm_vcpu* vcpu) {
	struct vcpu_vmx* vmx = to_vmx(vcpu);

	struct desc_ptr dt;
	__sidt(&dt);
	vmx_set_idt(vcpu, &dt);
	vmx_sgdt(&dt);
	vmx_set_gdt(vcpu, &dt);

	ULONG_PTR rflags = __readeflags();
	vmx_set_rflags(vcpu, (ULONG)rflags);

	struct kvm_segment var;
	var.selector = vmx_str();
	var.base = get_segment_base(dt.address, var.selector);
	vmx_set_segment(vcpu, &var, VCPU_SREG_TR);

	init_vmcs(vmx);

	vmx->nested.posted_intr_nv = (u16)-1;
	vmx->nested.vmxon_ptr = INVALID_GPA;
	vmx->nested.current_vmptr = INVALID_GPA;
	vmx->nested.hv_evmcs_vmptr = (gpa_t)EVMPTR_INVALID;

	vcpu->arch.microcode_version = 0x100000000ULL;
	vmx->msr_ia32_feature_control_valid_bits = FEAT_CTL_LOCKED;

	/*
	 * Enforce invariant: pi_desc.nv is always either POSTED_INTR_VECTOR
	 * or POSTED_INTR_WAKEUP_VECTOR.
	 */
	vmx->pi_desc.nv = POSTED_INTR_VECTOR;
	vmx->pi_desc.sn = 1;
}



static void seg_setup(int seg) {
	const struct kvm_vmx_segment_field* sf = &kvm_vmx_segment_fields[seg];
	unsigned int ar;

	vmcs_write16(sf->selector, 0);
	vmcs_writel(sf->base, 0);
	vmcs_write32(sf->limit, 0xffff);
	ar = 0x93;
	if (seg == VCPU_SREG_CS)
		ar |= 0x08; /* code segment */

	vmcs_write32(sf->ar_bytes, ar);
}

static void vmx_vcpu_reset(struct kvm_vcpu* vcpu, bool init_event) {
	struct vcpu_vmx* vmx = to_vmx(vcpu);

	if (!init_event)
		__vmx_vcpu_reset(vcpu);

	vmx->rmode.vm86_active = 0;

	// set guest segment fields
	seg_setup(VCPU_SREG_CS);
	vmcs_write16(GUEST_CS_SELECTOR, 0xf000);
	vmcs_writel(GUEST_CS_BASE, 0xffff0000ul);

	seg_setup(VCPU_SREG_DS);
	seg_setup(VCPU_SREG_ES);
	seg_setup(VCPU_SREG_FS);
	seg_setup(VCPU_SREG_GS);
	seg_setup(VCPU_SREG_SS);

	vmcs_write16(GUEST_TR_SELECTOR, 0);
	vmcs_writel(GUEST_TR_BASE, 0);
	vmcs_write32(GUEST_TR_LIMIT, 0xffff);
	vmcs_write32(GUEST_TR_AR_BYTES, 0x008b);

	vmcs_write16(GUEST_LDTR_SELECTOR, 0);
	vmcs_writel(GUEST_LDTR_BASE, 0);
	vmcs_write32(GUEST_LDTR_LIMIT, 0xffff);
	vmcs_write32(GUEST_LDTR_AR_BYTES, 0x00082);

	vmcs_write64(GUEST_FS_BASE, __readmsr(MSR_FS_BASE));
	vmcs_write64(GUEST_GS_BASE, __readmsr(MSR_GS_BASE));

	vmcs_write32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
	vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0);


	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0); /* 22.2.1 */


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

static int vmx_get_msr_feature(struct kvm_msr_entry* msr)
{
	if (msr->index >= KVM_FIRST_EMULATED_VMX_MSR
		&& msr->index <= KVM_LAST_EMULATED_VMX_MSR) {
		if (!nested)
			return 1;
	}
	switch (msr->index) {
		return vmx_get_vmx_msr(&vmcs_config.nested, msr->index, &msr->data);
	default:
		return KVM_MSR_RET_INVALID;
	}
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

		return 0;
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

/*	__vmx_vcpu_run 里调用的
 *	rcx -> vmx
 *  rdx -> host_rsp
 */
void vmx_update_host_rsp(struct vcpu_vmx* vmx, ULONG_PTR host_rsp) {
	if (host_rsp != vmx->loaded_vmcs->host_state.rsp) {
		vmx->loaded_vmcs->host_state.rsp = host_rsp;
		vmcs_writel(HOST_RSP, host_rsp);
	}
}

static void vmx_load_mmu_pgd(struct kvm_vcpu* vcpu, hpa_t root_hpa,
	int root_level) {
	struct kvm* kvm = vcpu->kvm;
	bool update_guest_cr3 = TRUE;
	ULONG_PTR guest_cr3 = 0;
	u64 eptp;

	if (enable_ept) {
		eptp = construct_eptp(vcpu, root_hpa, root_level);
		vmcs_write64(EPT_POINTER, eptp);

		if (!enable_unrestricted_guest && !is_paging(vcpu))
			guest_cr3 = (unsigned long)to_kvm_vmx(kvm)->ept_identity_map_addr;
		else if (kvm_register_is_dirty(vcpu, VCPU_EXREG_CR3))
			guest_cr3 = vcpu->arch.cr3;
		else /* vmcs.GUEST_CR3 is already up-to-date. */
			update_guest_cr3 = FALSE;
		vmx_ept_load_pdptrs(vcpu);
	}
	else {
		guest_cr3 = (unsigned long)(root_hpa | kvm_get_active_pcid(vcpu));
	}

	if (update_guest_cr3)
		vmcs_writel(GUEST_CR3, guest_cr3);
}



void vmx_set_constant_host_state(struct vcpu_vmx* vmx) {

	u64 cr0, cr3, cr4;
	cr0 = __readcr0();
	vmcs_write64(HOST_CR0, cr0);	/* 22.2.3 */

	/*
	 * Save the most likely value for this task's CR3 in the VMCS.
	 * We can't use __get_current_cr3_fast() because we're not atomic.
	 */
	cr3 = __readcr3();
	vmcs_write64(HOST_CR3, cr3); /* 22.2.3  FIXME: shadow tables */
	vmx->loaded_vmcs->host_state.cr3 = cr3;

	/* Save the most likely value for this task's CR4 in the VMCS. */
	cr4 = __readcr4();
	vmcs_write64(HOST_CR4, cr4); /* 22.2.3, 22.2.5 */
	vmx->loaded_vmcs->host_state.cr4 = cr4;


	vmcs_write16(HOST_CS_SELECTOR, vmx_get_cs());
#ifdef _WIN64
	vmcs_write16(HOST_DS_SELECTOR, vmx_get_ds());
	vmcs_write16(HOST_ES_SELECTOR, vmx_get_es());
	
#else
	
#endif // WIN64
	vmcs_write16(HOST_SS_SELECTOR, vmx_get_ss()); /* 22.2.4 */
	vmcs_write16(HOST_TR_SELECTOR, vmx_str()); /* 22.2.4 */


	vmcs_writel(HOST_IDTR_BASE, host_idt_base); /* 22.2.4 */

	vmcs_writel(HOST_RIP, (ULONG_PTR)vmx_vmexit); /* 22.2.5 */

	vmcs_write32(HOST_IA32_SYSENTER_CS, (u32)__readmsr(HOST_IA32_SYSENTER_CS));

	/*
	 * SYSENTER is used for 32-bit system calls on either 32-bit or
	 * 64-bit kernels.  It is always zero If neither is allowed, otherwise
	 * vmx_vcpu_load_vmcs loads it with the per-CPU entry stack (and may
	 * have already done so!).
	 */
	vmcs_writel(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));

	vmcs_writel(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));  /* 22.2.3 */

}

void ept_save_pdptrs(struct kvm_vcpu* vcpu)
{
	struct kvm_mmu* mmu = vcpu->arch.walk_mmu;

	if (!is_pae_paging(vcpu))
		return;

	mmu->pdptrs[0] = vmcs_read64(GUEST_PDPTR0);
	mmu->pdptrs[1] = vmcs_read64(GUEST_PDPTR1);
	mmu->pdptrs[2] = vmcs_read64(GUEST_PDPTR2);
	mmu->pdptrs[3] = vmcs_read64(GUEST_PDPTR3);


	kvm_register_mark_available(vcpu, VCPU_EXREG_PDPTR);
}

u64 construct_eptp(struct kvm_vcpu* vcpu, hpa_t root_hpa, int root_level) {
	u64 eptp = VMX_EPTP_MT_WB;

	eptp |= (root_level == 5) ? VMX_EPTP_PWL_5 : VMX_EPTP_PWL_4;

	if (enable_ept_ad_bits &&
		(!is_guest_mode(vcpu) || nested_ept_ad_enabled(vcpu)))
		eptp |= VMX_EPTP_AD_ENABLE_BIT;
	eptp |= root_hpa;

	return eptp;
}

static u32 vmx_segment_access_rights(struct kvm_segment* var)
{
	u32 ar;

	ar = var->type & 15;
	ar |= (var->s & 1) << 4;
	ar |= (var->dpl & 3) << 5;
	ar |= (var->present & 1) << 7;
	ar |= (var->avl & 1) << 12;
	ar |= (var->l & 1) << 13;
	ar |= (var->db & 1) << 14;
	ar |= (var->g & 1) << 15;
	ar |= (var->unusable || !var->present) << 16;

	return ar;
}

static void fix_rmode_seg(int seg, struct kvm_segment* save) {
	const struct kvm_vmx_segment_field* sf = &kvm_vmx_segment_fields[seg];
	struct kvm_segment var = *save;

	var.dpl = 0x3;
	if (seg == VCPU_SREG_CS)
		var.type = 0x3;

	if (!emulate_invalid_guest_state) {
		var.selector = (uint16_t)(var.base >> 4);
		var.base = var.base & 0xffff0;
		var.limit = 0xffff;
		var.g = 0;
		var.db = 0;
		var.present = 1;
		var.s = 1;
		var.l = 0;
		var.unusable = 0;
		var.type = 0x3;
		var.avl = 0;
	}

	vmcs_write16(sf->selector, var.selector);
	vmcs_writel(sf->base, var.base);
	vmcs_write32(sf->limit, var.limit);
	vmcs_write32(sf->ar_bytes, vmx_segment_access_rights(&var));
}

void __vmx_set_segment(struct kvm_vcpu* vcpu, struct kvm_segment* var, 
	int seg) {
	struct vcpu_vmx* vmx = to_vmx(vcpu);
	const struct kvm_vmx_segment_field* sf = &kvm_vmx_segment_fields[seg];

	vmx_segment_cache_clear(vmx);

	if (vmx->rmode.vm86_active && seg != VCPU_SREG_LDTR) {
		vmx->rmode.segs[seg] = *var;
		if (seg == VCPU_SREG_TR)
			vmcs_write16(sf->selector, var->selector);
		else if (var->s)
			fix_rmode_seg(seg, &vmx->rmode.segs[seg]);
	}

	vmcs_writel(sf->base, var->base);
	vmcs_write32(sf->limit, var->limit);
	vmcs_write16(sf->selector, var->selector);

	/*
	 *   Fix the "Accessed" bit in AR field of segment registers for older
	 * qemu binaries.
	 *   IA32 arch specifies that at the time of processor reset the
	 * "Accessed" bit in the AR field of segment registers is 1. And qemu
	 * is setting it to 0 in the userland code. This causes invalid guest
	 * state vmexit when "unrestricted guest" mode is turned on.
	 *    Fix for this setup issue in cpu_reset is being pushed in the qemu
	 * tree. Newer qemu binaries with that qemu fix would not need this
	 * kvm hack.
	 */
	if (is_unrestricted_guest(vcpu) && (seg != VCPU_SREG_LDTR))
		var->type |= 0x1; /* Accessed */

	vmcs_write32(sf->ar_bytes, vmx_segment_access_rights(var));
}

void vmx_spec_ctrl_restore_host(struct vcpu_vmx* vmx, unsigned int flags) {
	
	if (flags & VMX_RUN_SAVE_SPEC_CTRL)
		vmx->spec_ctrl = __readmsr(MSR_IA32_SPEC_CTRL);

	ULONG_PTR hardware_entry_failure_reason =
		vmcs_read32(VM_INSTRUCTION_ERROR);

	if (hardware_entry_failure_reason) {
		LogErr("KVM: entry failed, hardware error: 0x%x\n", hardware_entry_failure_reason);
		dump_vmcs(&vmx->vcpu);
	}
}

/*
* Free a VMCS, but before that VMCLEAR it on the CPU where it was last loaded
*/
void free_loaded_vmcs(struct loaded_vmcs* loaded_vmcs) {
	if (!loaded_vmcs->vmcs)
		return;

	loaded_vmcs_clear(loaded_vmcs);
	free_vmcs(loaded_vmcs->vmcs);
	loaded_vmcs->vmcs = NULL;
	if (loaded_vmcs->msr_bitmap)
		ExFreePool(loaded_vmcs->msr_bitmap);
}