#include "pch.h"
#include "vmx.h"
#include "kvm_emulate.h"
#include "mtrr.h"

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

struct vmcs {
	u32 revision_id;
	u32 abort;
	char data[ANYSIZE_ARRAY];
};

struct vcpu_vmx {
	struct kvm_vcpu       vcpu;
	//struct list_head      local_vcpus_link;
	unsigned long         host_rsp;
	int                   launched;
	u8                    fail;
	u32                   idt_vectoring_info;
	struct kvm_msr_entry* guest_msrs;
	struct kvm_msr_entry* host_msrs;
	int                   nmsrs;
	int                   save_nmsrs;
	int                   msr_offset_efer;
#ifdef _WIN64
	int                   msr_offset_kernel_gs_base;
#endif
	struct vmcs* vmcs;
	struct {
		int           loaded;
		u16           fs_sel, gs_sel, ldt_sel;
		int           gs_ldt_reload_needed;
		int           fs_reload_needed;
		int           guest_efer_loaded;
	} host_state;
	struct {
		int vm86_active;
		u8 save_iopl;
		struct kvm_save_segment {
			u16 selector;
			unsigned long base;
			u32 limit;
			u32 ar;
		} tr, es, ds, fs, gs;
		struct {
			bool pending;
			u8 vector;
			unsigned rip;
		} irq;
	} rmode;
	int vpid;
	bool emulation_required;
	// enum emulation_result invalid_state_emulation_result;

	/* Support for vnmi-less CPUs */
	int soft_vnmi_blocked;
	// ktime_t entry_time;
	s64 vnmi_blocked_time;
	u32 exit_reason;
};

static struct vmcs_config {
	int size;
	int order;
	u32 revision_id;
	u32 pin_based_exec_ctrl;
	u32 cpu_based_exec_ctrl;
	u32 cpu_based_2nd_exec_ctrl;
	u32 vmexit_ctrl;
	u32 vmentry_ctrl;
} vmcs_config;

static struct vmx_capability {
	u32 ept;
	u32 vpid;
} vmx_capability;



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

void ept_sync_global();

void vmx_disable_intercept_for_msr(u32 msr, bool longmode_only);
void __vmx_disable_intercept_for_msr(PRTL_BITMAP msr_bitmap, u32 msr);

unsigned long vmcs_readl(unsigned long field);
u16 vmcs_read16(unsigned long field);
u32 vmcs_read32(unsigned long field);


void vmcs_writel(unsigned long field, unsigned long val);
void vmcs_write16(unsigned long field, u16 value);
void vmcs_write32(unsigned long field, u32 value);

struct kvm_vcpu* vmx_create_vcpu(struct kvm* kvm, unsigned int id);
void vmx_free_vcpu(struct kvm_vcpu* vcpu);
struct vcpu_vmx* to_vmx(struct kvm_vcpu* vcpu);
NTSTATUS vmx_vcpu_reset(struct kvm_vcpu* vcpu);
void hardware_disable(void* garbage);
void vmx_save_host_state(struct kvm_vcpu* vcpu);
void vmx_vcpu_put(struct kvm_vcpu* vcpu);
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
void vmx_vcpu_run(struct kvm_vcpu* vcpu, struct kvm_run* kvm_run);
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
 * The guest has exited.  See if we can fix it or if we need userspace
 * assistance.
 */
int vmx_handle_exit(struct kvm_run* kvm_run, struct kvm_vcpu* vcpu);

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

/*
* Switches to specified vcpu, until a matching vcpu_put(), but assumes
* vcpu mutex is already taken.
*/
void vmx_vcpu_load(struct kvm_vcpu* vcpu, int cpu);

static struct kvm_x86_ops vmx_x86_ops = {
	.cpu_has_kvm_support = cpu_has_kvm_support,
	.disabled_by_bios = vmx_disabled_by_bios,
	.hardware_setup = hardware_setup,
	.hardware_unsetup = hardware_unsetup,
	.check_processor_compatibility = vmx_check_processor_compat,
	.hardware_enable = hardware_enable,
	.hardware_disable = hardware_disable,
	.cpu_has_accelerated_tpr = report_flexpriority,

	.vcpu_create = vmx_create_vcpu,
	.vcpu_free = vmx_free_vcpu,
	.vcpu_reset = vmx_vcpu_reset,

	.prepare_guest_switch = vmx_save_host_state,
	.vcpu_load = vmx_vcpu_load,
	.vcpu_put = vmx_vcpu_put,

	.set_guest_debug = set_guest_debug,
	.get_msr = vmx_get_msr,
	.set_msr = vmx_set_msr,
	.get_segment_base = vmx_get_segment_base,
	.get_segment = vmx_get_segment,
	.set_segment = vmx_set_segment,
	.get_cpl = vmx_get_cpl,
	.get_cs_db_l_bits = vmx_get_cs_db_l_bits,
	.decache_cr4_guest_bits = vmx_decache_cr4_guest_bits,
	.set_cr0 = vmx_set_cr0,
	.set_cr3 = vmx_set_cr3,
	.set_cr4 = vmx_set_cr4,
	.set_efer = vmx_set_efer,
	.get_idt = vmx_get_idt,
	.set_idt = vmx_set_idt,
	.get_gdt = vmx_get_gdt,
	.set_gdt = vmx_set_gdt,
	.cache_reg = vmx_cache_reg,
	.get_rflags = vmx_get_rflags,
	.set_rflags = vmx_set_rflags,

	.tlb_flush = vmx_flush_tlb,

	.run = vmx_vcpu_run,
	.handle_exit = vmx_handle_exit,
	.skip_emulated_instruction = skip_emulated_instruction,
	.set_interrupt_shadow = vmx_set_interrupt_shadow,
	.get_interrupt_shadow = vmx_get_interrupt_shadow,
	.patch_hypercall = vmx_patch_hypercall,
	.set_irq = vmx_inject_irq,
	.set_nmi = vmx_inject_nmi,
	.queue_exception = vmx_queue_exception,
	.interrupt_allowed = vmx_interrupt_allowed,
	.nmi_allowed = vmx_nmi_allowed,
	.enable_nmi_window = enable_nmi_window,
	.enable_irq_window = enable_irq_window,
	.update_cr8_intercept = update_cr8_intercept,

	.set_tss_addr = vmx_set_tss_addr,
	.get_tdp_level = get_ept_level,
	.get_mt_mask = vmx_get_mt_mask,

	.exit_reasons_str = vmx_exit_reasons_str,
	.gb_page_enable = vmx_gb_page_enable,
};

NTSTATUS setup_vmcs_config(struct vmcs_config* vmcs_conf);

NTSTATUS vmx_init() {
	NTSTATUS status = STATUS_SUCCESS;

	

	vmx_io_bitmap_a_page = (unsigned long*)ExAllocatePoolWithTag(PagedPool, PAGE_SIZE, DRIVER_TAG);
	if (!vmx_io_bitmap_a_page)
		return STATUS_NO_MEMORY;
	RtlInitializeBitMap(&vmx_io_bitmap_a, vmx_io_bitmap_a_page, PAGE_SIZE * CHAR_BIT);

	do
	{
		vmx_io_bitmap_b_page = (unsigned long*)ExAllocatePoolWithTag(PagedPool, PAGE_SIZE, DRIVER_TAG);
		if (!vmx_io_bitmap_b_page) {
			status = STATUS_NO_MEMORY;
			break;
		}
		RtlInitializeBitMap(&vmx_io_bitmap_b, vmx_io_bitmap_b_page, PAGE_SIZE * CHAR_BIT);

		vmx_msr_bitmap_legacy_page = (unsigned long*)ExAllocatePoolWithTag(PagedPool, PAGE_SIZE, DRIVER_TAG);
		if (!vmx_msr_bitmap_legacy_page) {
			status = STATUS_NO_MEMORY;
			break;
		}
		RtlInitializeBitMap(&vmx_msr_bitmap_legacy, vmx_msr_bitmap_legacy_page, PAGE_SIZE * CHAR_BIT);

		vmx_msr_bitmap_longmode_page = (unsigned long*)ExAllocatePoolWithTag(PagedPool, PAGE_SIZE, DRIVER_TAG);
		if (!vmx_msr_bitmap_longmode_page) {
			status = STATUS_NO_MEMORY;
			break;
		}
		RtlInitializeBitMap(&vmx_msr_bitmap_longmode, vmx_msr_bitmap_longmode_page, PAGE_SIZE * CHAR_BIT);

		/*
		 * Allow direct access to the PC debug port (it is often used for I/O
		 * delays, but the vmexits simply slow things down
		 */
		memset(vmx_io_bitmap_a_page, 0xff, PAGE_SIZE);
		RtlClearBit(&vmx_io_bitmap_a, 0x80);

		memset(vmx_io_bitmap_b_page, 0xff, PAGE_SIZE);

		memset(vmx_msr_bitmap_legacy_page, 0xff, PAGE_SIZE);
		memset(vmx_msr_bitmap_longmode_page, 0xff, PAGE_SIZE);

		RtlInitializeBitMap(&vmx_vpid_bitmap, vmx_vpid_bitmap_buf, VMX_NR_VPIDS * CHAR_BIT);

		RtlSetBit(&vmx_vpid_bitmap, 0); /* 0 is reserved for host */

		status = kvm_init(&kvm_x86_ops, sizeof(struct vcpu_vmx));
		if (!NT_SUCCESS(status))
			break;

		vmx_disable_intercept_for_msr(MSR_FS_BASE, FALSE);
		vmx_disable_intercept_for_msr(MSR_GS_BASE, FALSE);
		vmx_disable_intercept_for_msr(MSR_KERNEL_GS_BASE, FALSE);
		vmx_disable_intercept_for_msr(MSR_IA32_SYSENTER_CS, FALSE);
		vmx_disable_intercept_for_msr(MSR_IA32_SYSENTER_ESP, FALSE);
		vmx_disable_intercept_for_msr(MSR_IA32_SYSENTER_EIP, FALSE);

		if (enable_ept) {
			bypass_guest_pf = 0;
			kvm_mmu_set_base_ptes(VMX_EPT_READABLE_MASK |
				VMX_EPT_WRITABLE_MASK);
			kvm_mmu_set_mask_ptes(0ull, 0ull, 0ull, 0ull,
				VMX_EPT_EXECUTABLE_MASK);
			kvm_enable_tdp();
		}
		else {
			kvm_disable_tdp();
		}

		if (bypass_guest_pf)
			kvm_mmu_set_nonpresent_ptes(~0xffeull, 0ull);

		ept_sync_global();

		return STATUS_SUCCESS;
	} while (FALSE);


	if (!NT_SUCCESS(status)) {
		if (vmx_io_bitmap_a_page) {
			ExFreePool(vmx_io_bitmap_a_page);
		}
		if (vmx_msr_bitmap_legacy_page) {
			ExFreePool(vmx_msr_bitmap_legacy_page);
		}
		if (vmx_msr_bitmap_longmode_page) {
			ExFreePool(vmx_msr_bitmap_longmode_page);
		}
		return status;
	}

	return status;
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



NTSTATUS adjust_vmx_controls(u32 ctl_min, u32 ctl_opt, u32 msr, u32* result) {
	u32 vmx_msr_low, vmx_msr_high;
	u32 ctl = ctl_min | ctl_opt;

	u64 vmx_msr = __readmsr(msr);
	vmx_msr_low = (u32)vmx_msr;
	vmx_msr_high = vmx_msr >> 32;
	
	ctl &= vmx_msr_high;/* bit == 0 in high word ==> must be zero */
	ctl |= vmx_msr_low;/* bit == 1 in low word  ==> must be one  */

	/* Ensure minimum (required) set of control bits are supported. */
	if (ctl_min & ~ctl)
		return STATUS_NOT_SUPPORTED;

	*result = ctl;
	return STATUS_SUCCESS;
}

NTSTATUS setup_vmcs_config(struct vmcs_config* vmcs_conf) {
	u32 vmx_msr_low, vmx_msr_high;
	u32 min, opt, min2, opt2;
	u32 _pin_based_exec_control = 0;
	u32 _cpu_based_exec_control = 0;
	u32 _cpu_based_2nd_exec_control = 0;
	u32 _vmexit_control = 0;
	u32 _vmentry_control = 0;

	min = PIN_BASED_EXT_INTR_MASK | PIN_BASED_NMI_EXITING;
	opt = PIN_BASED_VIRTUAL_NMIS;
	NTSTATUS status = adjust_vmx_controls(min, opt, MSR_IA32_VMX_PINBASED_CTLS,
		&_pin_based_exec_control);
	if (!NT_SUCCESS(status))
		return status;

	min = CPU_BASED_HLT_EXITING |
#ifdef _WIN64
		CPU_BASED_CR8_LOAD_EXITING |
		CPU_BASED_CR8_STORE_EXITING |
#endif
		CPU_BASED_CR3_LOAD_EXITING |
		CPU_BASED_CR3_STORE_EXITING |
		CPU_BASED_USE_IO_BITMAPS |
		CPU_BASED_MOV_DR_EXITING |
		CPU_BASED_USE_TSC_OFFSETING |
		CPU_BASED_INVLPG_EXITING;
	opt = CPU_BASED_TPR_SHADOW |
		CPU_BASED_USE_MSR_BITMAPS |
		CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
	status = adjust_vmx_controls(min, opt, MSR_IA32_VMX_PROCBASED_CTLS,
		&_cpu_based_exec_control);
	if (!NT_SUCCESS(status))
		return status;

#ifdef _WIN64
	if ((_cpu_based_exec_control & CPU_BASED_TPR_SHADOW))
		_cpu_based_exec_control &= ~CPU_BASED_CR8_LOAD_EXITING &
		~CPU_BASED_CR8_STORE_EXITING;
#endif
	if (_cpu_based_exec_control & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) {
		min2 = 0;
		opt2 = SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES |
			SECONDARY_EXEC_WBINVD_EXITING |
			SECONDARY_EXEC_ENABLE_VPID |
			SECONDARY_EXEC_ENABLE_EPT |
			SECONDARY_EXEC_UNRESTRICTED_GUEST;

		status = adjust_vmx_controls(min2, opt2,
			MSR_IA32_VMX_PROCBASED_CTLS2,
			&_cpu_based_2nd_exec_control);
		if (!NT_SUCCESS(status))
			return status;
	}

#ifdef _WIN64
	if (!(_cpu_based_2nd_exec_control &
		SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES))
		_cpu_based_exec_control &= ~CPU_BASED_TPR_SHADOW;
#endif // _WIN64
	if (_cpu_based_2nd_exec_control & SECONDARY_EXEC_ENABLE_EPT) {
		/* CR3 accesses and invlpg don't need to cause VM Exits when EPT
		   enabled */
		_cpu_based_exec_control &= ~(CPU_BASED_CR3_LOAD_EXITING |
			CPU_BASED_CR3_STORE_EXITING |
			CPU_BASED_INVLPG_EXITING);
		rdmsr(MSR_IA32_VMX_EPT_VPID_CAP,
			vmx_capability.ept, vmx_capability.vpid);
	}

	min = 0;
#ifdef _WIN64
	min |= VM_EXIT_HOST_ADDR_SPACE_SIZE;
#endif
	opt = VM_EXIT_SAVE_IA32_PAT | VM_EXIT_LOAD_IA32_PAT;
	status = adjust_vmx_controls(min, opt, MSR_IA32_VMX_EXIT_CTLS,
		&_vmexit_control);
	if (!NT_SUCCESS(status))
		return STATUS_UNSUCCESSFUL;

	min = 0;
	opt = VM_ENTRY_LOAD_IA32_PAT;
	status = adjust_vmx_controls(min, opt, MSR_IA32_VMX_ENTRY_CTLS,
		&_vmentry_control);
	if (!NT_SUCCESS(status))
		return STATUS_UNSUCCESSFUL;

	rdmsr(MSR_IA32_VMX_BASIC, vmx_msr_low, vmx_msr_high);

	/* IA-32 SDM Vol 3B: VMCS size is never greater than 4kB. */
	if ((vmx_msr_high & 0x1fff) > PAGE_SIZE)
		return STATUS_UNSUCCESSFUL;

#ifdef _WIN64
	/* IA-32 SDM Vol 3B: 64-bit CPUs always have VMX_BASIC_MSR[48]==0. */
	if (vmx_msr_high & (1u << 16))
		return STATUS_UNSUCCESSFUL;
#endif

	/* Require Write-Back (WB) memory type for VMCS accesses. */
	if (((vmx_msr_high >> 18) & 15) != 6)
		return STATUS_UNSUCCESSFUL;

	vmcs_conf->size = vmx_msr_high & 0x1fff;
	vmcs_conf->revision_id = vmx_msr_low;

	vmcs_conf->pin_based_exec_ctrl = _pin_based_exec_control;
	vmcs_conf->cpu_based_exec_ctrl = _cpu_based_exec_control;
	vmcs_conf->cpu_based_2nd_exec_ctrl = _cpu_based_2nd_exec_control;
	vmcs_conf->vmexit_ctrl = _vmexit_control;
	vmcs_conf->vmentry_ctrl = _vmentry_control;

	return STATUS_SUCCESS;
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

struct vmcs* alloc_vmcs_cpu() {
	struct vmcs* vmcs = NULL;

	return vmcs;
}

struct vmcs* alloc_vmcs() {
	return NULL;
}

NTSTATUS alloc_kvm_area() {


	return STATUS_SUCCESS;
}

NTSTATUS hardware_setup() {
	NTSTATUS status = STATUS_SUCCESS;

	status = setup_vmcs_config(&vmcs_config);
	if (!NT_SUCCESS(status))
		return status;

	if (ExIsProcessorFeaturePresent(PF_NX_ENABLED)) {
		kvm_enable_efer_bits(EFER_NX);
	}

	if (!cpu_has_vmx_vpid())
		enable_vpid = 0;

	if (!cpu_has_vmx_ept()) {
		enable_ept = 0;
		enable_unrestricted_guest = 0;
	}

	if (!cpu_has_vmx_unrestricted_guest())
		enable_unrestricted_guest = 0;

	if (!cpu_has_vmx_flexpriority())
		flexpriority_enabled = 0;

	if (!cpu_has_vmx_tpr_shadow())
		kvm_x86_ops->update_cr8_intercept = NULL;

	if (enable_ept && !cpu_has_vmx_ept_2m_page())
		kvm_disable_largepages();

	status = alloc_kvm_area();

	return status;
}

void free_vmcs(struct vmcs* vmcs) {
	UNREFERENCED_PARAMETER(vmcs);
}

void free_kvm_area() {

}

void hardware_unsetup() {
	free_kvm_area();
}

void vmx_check_processor_compat(void* rtn) {
	struct vmcs_config vmcs_conf;

	*(int*)rtn = 0;
	NTSTATUS status = setup_vmcs_config(&vmcs_conf);
	if (!NT_SUCCESS(status)) {
		*(int*)rtn = STATUS_UNSUCCESSFUL;
	}
	if (memcmp(&vmcs_conf, &vmcs_conf, sizeof(struct vmcs_config)) != 0) {
		Log(KERN_ERR, "kvm CPU %d feature inconsistency!\n",KeGetCurrentProcessorNumber());
		*(int*)rtn = STATUS_UNSUCCESSFUL;
	}
}

void hardware_enable(void* junk) {
	UNREFERENCED_PARAMETER(junk);
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

NTSTATUS vmx_vcpu_reset(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	NTSTATUS status = STATUS_SUCCESS;

	return status;
}

void vmx_save_host_state(struct kvm_vcpu* vcpu) {
	struct vcpu_vmx* vmx = to_vmx(vcpu);

	if (vmx->host_state.loaded)
		return;

}

void vmx_vcpu_load(struct kvm_vcpu* vcpu, int cpu) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(cpu);
}

void __vmx_load_host_state(struct vcpu_vmx* vmx) {

	if (!vmx->host_state.loaded)
		return;
}

void vmx_vcpu_put(struct kvm_vcpu* vcpu) {
	__vmx_load_host_state(to_vmx(vcpu));
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

unsigned long vmcs_readl(unsigned long field) {
	UNREFERENCED_PARAMETER(field);
	return 0;
}

u16 vmcs_read16(unsigned long field) {
	return (u16)vmcs_readl(field);
}

u32 vmcs_read32(unsigned long field) {
	return (u32)vmcs_readl(field);
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
	vcpu->arch.cr4 &= KVM_GUEST_CR4_MASK;
	vcpu->arch.cr4 |= vmcs_readl(GUEST_CR4) & ~KVM_GUEST_CR4_MASK;
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

	vcpu->arch.cr4 = cr4;
	if (enable_ept) {

	}

	
}

void vmcs_writel(unsigned long field, unsigned long val) {
	UNREFERENCED_PARAMETER(field);
	UNREFERENCED_PARAMETER(val);
}

void vmcs_write16(unsigned long field, u16 value) {
	vmcs_writel(field, value);
}

void vmcs_write32(unsigned long field, u32 value) {
	vmcs_writel(field, value);
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

void vmx_vcpu_run(struct kvm_vcpu* vcpu, struct kvm_run* kvm_run) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(kvm_run);
}

int vmx_handle_exit(struct kvm_run* kvm_run, struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(kvm_run);
	UNREFERENCED_PARAMETER(vcpu);

	return 0;
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
	if (!cpu_has_virtual_nmis() && to_vmx(vcpu)->soft_vnmi_blocked)
		return 0;

	return !(vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) &
		(GUEST_INTR_STATE_STI | GUEST_INTR_STATE_MOV_SS |
			GUEST_INTR_STATE_NMI));
}

int cpu_has_virtual_nmis() {
	return vmcs_config.pin_based_exec_ctrl & PIN_BASED_VIRTUAL_NMIS;
}

void enable_nmi_window(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	u32 cpu_based_vm_exec_control;

	if (!cpu_has_virtual_nmis()) {
		
		return;
	}

	cpu_based_vm_exec_control = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	cpu_based_vm_exec_control |= CPU_BASED_VIRTUAL_NMI_PENDING;
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control);
}

void enable_irq_window(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	u32 cpu_based_vm_exec_control;

	cpu_based_vm_exec_control = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	cpu_based_vm_exec_control |= CPU_BASED_VIRTUAL_INTR_PENDING;
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control);
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

void vmx_exit() {

	
}

bool kvm_is_vmx_supported() {
	if (!cpu_has_vmx()) {
		Log(KERN_ERR, "VMX not supported by CPU %d\n", KeGetCurrentProcessorNumber());
		return FALSE;
	}

	
	
	return TRUE;
}