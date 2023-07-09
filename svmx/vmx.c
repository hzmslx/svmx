#include "pch.h"
#include "vmx.h"

static int enable_vpid = 1;

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

static struct kvm_x86_ops vmx_x86_ops = {
	.cpu_has_kvm_support = cpu_has_kvm_support,
	/*.disabled_by_bios = vmx_disabled_by_bios,
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
	.gb_page_enable = vmx_gb_page_enable,*/
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

		// status = kvm_init(&kvm_x86_ops,)

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



	return status;
}