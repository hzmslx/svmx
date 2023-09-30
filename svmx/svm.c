#include "pch.h"
#include "svm.h"
#include "virtext.h"
#include "kvm_emulate.h"
#include "mmu.h"
#include "pmu.h"
#include "nested.h"
#include "cpuid.h"

static const u32 host_save_user_msrs[] = {
#ifdef _WIN64
	MSR_STAR, MSR_LSTAR, MSR_CSTAR, MSR_SYSCALL_MASK, MSR_KERNEL_GS_BASE,
	MSR_FS_BASE,
#endif
	MSR_IA32_SYSENTER_CS, MSR_IA32_SYSENTER_ESP, MSR_IA32_SYSENTER_EIP,
};

#define NR_HOST_SAVE_USER_MSRS ARRAYSIZE(host_save_user_msrs)

struct nested_state {
	struct vmcb* hsave;
	u64 hsave_msr;
	u64 vmcb;

	/* These are the merged vectors */
	u32* msrpm;

	/* gpa pointers to the real vectors */
	u64 vmcb_msrpm;

	/* cache for intercepts of the guest */
	u16 intercept_cr_read;
	u16 intercept_cr_write;
	u16 intercept_dr_read;
	u16 intercept_dr_write;
	u32 intercept_exceptions;
	u64 intercept;

};



#if defined _WIN64
static bool npt_enabled = TRUE;
#else
static bool npt_enabled = FALSE;
#endif
static int npt = 1;

static int nested = 1;

/** Disable SVM on the current CPU
 *
 * You should call this only if cpu_has_svm() returned true.
 */
void cpu_svm_disable();
struct vcpu_svm* to_svm(struct kvm_vcpu* vcpu);
struct vmcb_seg* svm_seg(struct kvm_vcpu* vcpu, int seg);
void force_new_asid(struct kvm_vcpu* vcpu);


#define SEG_TYPE_LDT 2
#define SEG_TYPE_BUSY_TSS16 3

static const struct trace_print_flags svm_exit_reasons_str[] = {
	{ SVM_EXIT_READ_CR0,           		"read_cr0" },
	{ SVM_EXIT_READ_CR3,	      		"read_cr3" },
	{ SVM_EXIT_READ_CR4,	      		"read_cr4" },
	{ SVM_EXIT_READ_CR8,  	      		"read_cr8" },
	{ SVM_EXIT_WRITE_CR0,          		"write_cr0" },
	{ SVM_EXIT_WRITE_CR3,	      		"write_cr3" },
	{ SVM_EXIT_WRITE_CR4,          		"write_cr4" },
	{ SVM_EXIT_WRITE_CR8, 	      		"write_cr8" },
	{ SVM_EXIT_READ_DR0, 	      		"read_dr0" },
	{ SVM_EXIT_READ_DR1,	      		"read_dr1" },
	{ SVM_EXIT_READ_DR2,	      		"read_dr2" },
	{ SVM_EXIT_READ_DR3,	      		"read_dr3" },
	{ SVM_EXIT_WRITE_DR0,	      		"write_dr0" },
	{ SVM_EXIT_WRITE_DR1,	      		"write_dr1" },
	{ SVM_EXIT_WRITE_DR2,	      		"write_dr2" },
	{ SVM_EXIT_WRITE_DR3,	      		"write_dr3" },
	{ SVM_EXIT_WRITE_DR5,	      		"write_dr5" },
	{ SVM_EXIT_WRITE_DR7,	      		"write_dr7" },
	{ SVM_EXIT_EXCP_BASE + DB_VECTOR,	"DB excp" },
	{ SVM_EXIT_EXCP_BASE + BP_VECTOR,	"BP excp" },
	{ SVM_EXIT_EXCP_BASE + UD_VECTOR,	"UD excp" },
	{ SVM_EXIT_EXCP_BASE + PF_VECTOR,	"PF excp" },
	{ SVM_EXIT_EXCP_BASE + NM_VECTOR,	"NM excp" },
	{ SVM_EXIT_EXCP_BASE + MC_VECTOR,	"MC excp" },
	{ SVM_EXIT_INTR,			"interrupt" },
	{ SVM_EXIT_NMI,				"nmi" },
	{ SVM_EXIT_SMI,				"smi" },
	{ SVM_EXIT_INIT,			"init" },
	{ SVM_EXIT_VINTR,			"vintr" },
	{ SVM_EXIT_CPUID,			"cpuid" },
	{ SVM_EXIT_INVD,			"invd" },
	{ SVM_EXIT_HLT,				"hlt" },
	{ SVM_EXIT_INVLPG,			"invlpg" },
	{ SVM_EXIT_INVLPGA,			"invlpga" },
	{ SVM_EXIT_IOIO,			"io" },
	{ SVM_EXIT_MSR,				"msr" },
	{ SVM_EXIT_TASK_SWITCH,			"task_switch" },
	{ SVM_EXIT_SHUTDOWN,			"shutdown" },
	{ SVM_EXIT_VMRUN,			"vmrun" },
	{ SVM_EXIT_VMMCALL,			"hypercall" },
	{ SVM_EXIT_VMLOAD,			"vmload" },
	{ SVM_EXIT_VMSAVE,			"vmsave" },
	{ SVM_EXIT_STGI,			"stgi" },
	{ SVM_EXIT_CLGI,			"clgi" },
	{ SVM_EXIT_SKINIT,			"skinit" },
	{ SVM_EXIT_WBINVD,			"wbinvd" },
	{ SVM_EXIT_MONITOR,			"monitor" },
	{ SVM_EXIT_MWAIT,			"mwait" },
	{ SVM_EXIT_NPF,				"npf" },
	{ (unsigned long)-1ll, NULL }
};

int has_svm();
int is_disabled();
static NTSTATUS svm_hardware_setup(void);
int svm_hardware_enable(void);
void svm_hardware_disable(void* garbage);
bool svm_cpu_has_accelerated_tpr();
struct kvm_vcpu* svm_create_vcpu(struct kvm* kvm, unsigned int id);
void svm_free_vcpu(struct kvm_vcpu* vcpu);
NTSTATUS svm_vcpu_reset(struct kvm_vcpu* vcpu);
void svm_prepare_guest_switch(struct kvm_vcpu* vcpu);
void svm_vcpu_load(struct kvm_vcpu* vcpu, int cpu);
void svm_vcpu_put(struct kvm_vcpu* vcpu);
int svm_guest_debug(struct kvm_vcpu* vcpu, struct kvm_guest_debug* dbg);
NTSTATUS svm_get_msr(struct kvm_vcpu* vcpu, unsigned ecx, u64* data);
NTSTATUS svm_set_msr(struct kvm_vcpu* vcpu, unsigned ecx, u64 data);
u64 svm_get_segment_base(struct kvm_vcpu* vcpu, int seg);
void svm_get_segment(struct kvm_vcpu* vcpu,
	struct kvm_segment* var, int seg);
void svm_set_segment(struct kvm_vcpu* vcpu,
	struct kvm_segment* var, int seg);
int svm_get_cpl(struct kvm_vcpu* vcpu);
void svm_decache_cr4_guest_bits(struct kvm_vcpu* vcpu);
void svm_set_cr0(struct kvm_vcpu* vcpu, unsigned long cr0);
void svm_set_cr3(struct kvm_vcpu* vcpu, unsigned long root);
void svm_set_cr4(struct kvm_vcpu* vcpu, unsigned long cr4);
void svm_set_efer(struct kvm_vcpu* vcpu, u64 efer);
void svm_get_idt(struct kvm_vcpu* vcpu, struct desc_ptr* dt);
void svm_set_idt(struct kvm_vcpu* vcpu, struct desc_ptr* dt);
void svm_get_gdt(struct kvm_vcpu* vcpu, struct desc_ptr* dt);
void svm_set_gdt(struct kvm_vcpu* vcpu, struct desc_ptr* dt);
unsigned long svm_get_dr(struct kvm_vcpu* vcpu, int dr);
void svm_set_dr(struct kvm_vcpu* vcpu, int dr, unsigned long value,
	int* exception);
void svm_cache_reg(struct kvm_vcpu* vcpu, enum kvm_reg reg);
unsigned long svm_get_rflags(struct kvm_vcpu* vcpu);
void svm_set_rflags(struct kvm_vcpu* vcpu, unsigned long rflags);
void svm_flush_tlb(struct kvm_vcpu* vcpu);
void svm_vcpu_run(struct kvm_vcpu* vcpu, struct kvm_run* kvm_run);
int handle_exit(struct kvm_run* kvm_run, struct kvm_vcpu* vcpu);
void svm_set_interrupt_shadow(struct kvm_vcpu* vcpu, int mask);
u32 svm_get_interrupt_shadow(struct kvm_vcpu* vcpu, int mask);
void svm_patch_hypercall(struct kvm_vcpu* vcpu, unsigned char* hypercall);
void svm_set_irq(struct kvm_vcpu* vcpu);
void svm_inject_nmi(struct kvm_vcpu* vcpu);
void svm_queue_exception(struct kvm_vcpu* vcpu, unsigned nr,
	bool has_error_code, u32 error_code);
int svm_interrupt_allowed(struct kvm_vcpu* vcpu);
int svm_nmi_allowed(struct kvm_vcpu* vcpu);
static void enable_nmi_window(struct kvm_vcpu* vcpu);
static void enable_irq_window(struct kvm_vcpu* vcpu);
static void update_cr8_intercept(struct kvm_vcpu* vcpu, int tpr, int irr);
int svm_set_tss_addr(struct kvm* kvm, unsigned int addr);
int get_npt_level();
u64 svm_get_mt_mask(struct kvm_vcpu* vcpu, gfn_t gfn, bool is_mmio);
bool svm_gb_page_enable(void);
void svm_hardware_unsetup(void);

static NTSTATUS svm_check_processor_compat(void)
{
	/*if (!kvm_is_svm_supported())
		return STATUS_UNSUCCESSFUL;*/

	return STATUS_SUCCESS;
}

static struct kvm_x86_ops svm_x86_ops = {
	.check_processor_compatibility = svm_check_processor_compat,

	.hardware_unsetup = svm_hardware_unsetup,
	.hardware_enable = svm_hardware_enable,
};

int has_svm() {
	const char* msg;

	if (!cpu_has_svm(&msg)) {
		Log(KERN_INFO, "has_svm: %s\n", msg);
		return 0;
	}

	return 1;
}

static bool kvm_is_svm_supported(void) {
	int cpu = KeGetCurrentProcessorNumber();
	const char* msg;
	u64 vm_cr;
	
	if (!cpu_has_svm(&msg)) {
		LogErr("SVM not supported by CPU %d, %s\n", cpu, msg);
		return FALSE;
	}

	vm_cr = __readmsr(MSR_VM_CR);
	if (vm_cr & (1 << SVM_VM_CR_SVM_DISABLE)) {
		LogErr("SVM disabled (by BIOS) in MSR_VM_CR on cpu %d\n", cpu);
		return FALSE;
	}

	return TRUE;
}

static struct kvm_x86_init_ops svm_init_ops = {
	.hardware_setup = svm_hardware_setup,

	.runtime_ops = &svm_x86_ops,
	.pmu_ops = &amd_pmu_ops,
};

NTSTATUS svm_init() {
	NTSTATUS status = STATUS_SUCCESS;

	if (!kvm_is_svm_supported())
		return STATUS_NOT_SUPPORTED;

	status = kvm_x86_vendor_init(&svm_init_ops);
	if (!NT_SUCCESS(status))
		return status;

	bool err_kvm_init = FALSE;
	do
	{
		status = kvm_init(sizeof(struct vcpu_svm), __alignof(struct vcpu_svm));
		if (!NT_SUCCESS(status)) {
			err_kvm_init = TRUE;
			status = STATUS_UNSUCCESSFUL;
			break;
		}
	} while (FALSE);

	if (err_kvm_init)
		kvm_x86_vendor_exit();

	return status;
}

int is_disabled() {
	u64 vm_cr;

	vm_cr = __readmsr(MSR_VM_CR);
	if (vm_cr & (1 << SVM_VM_CR_SVM_DISABLE))
		return 1;

	return 0;
}





int svm_hardware_enable(void) {
	struct svm_cpu_data* sd;
	uint64_t efer;
	int me = KeGetCurrentProcessorNumber();
	efer = __readmsr(MSR_EFER);
	if (efer & EFER_SVME)
		return STATUS_UNSUCCESSFUL;

	sd = &svm_data[me];
	sd->asid_generation = 1;


	__writemsr(MSR_EFER, efer | EFER_SVME);

	__writemsr(MSR_VM_HSAVE_PA, sd->save_area_pa);

	return STATUS_SUCCESS;
}

void svm_hardware_disable(void* garbage) {
	UNREFERENCED_PARAMETER(garbage);
	cpu_svm_disable();
}

void cpu_svm_disable() {
	u64 efer;

	__writemsr(MSR_VM_HSAVE_PA, 0);
	efer = __readmsr(MSR_EFER);
	__writemsr(MSR_EFER, efer & ~EFER_SVME);
}

bool svm_cpu_has_accelerated_tpr() {
	return FALSE;
}

struct kvm_vcpu* svm_create_vcpu(struct kvm* kvm, unsigned int id) {
	UNREFERENCED_PARAMETER(kvm);
	UNREFERENCED_PARAMETER(id);

	return NULL;
}

void svm_free_vcpu(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
}

struct vcpu_svm* to_svm(struct kvm_vcpu* vcpu) {
	return CONTAINING_RECORD(vcpu, struct vcpu_svm, vcpu);
}

static void init_vmcb(struct kvm_vcpu* vcpu);
NTSTATUS svm_vcpu_reset(struct kvm_vcpu* vcpu) {
	struct vcpu_svm* svm = to_svm(vcpu);

	svm->spec_ctrl = 0;
	svm->virt_spec_ctrl = 0;

	init_vmcb(vcpu);

	return 0;
}

void svm_prepare_guest_switch(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
}

void svm_vcpu_load(struct kvm_vcpu* vcpu, int cpu) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(cpu);
}

void svm_vcpu_put(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
}

int svm_guest_debug(struct kvm_vcpu* vcpu, struct kvm_guest_debug* dbg) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(dbg);

	return 0;
}

NTSTATUS svm_get_msr(struct kvm_vcpu* vcpu, unsigned ecx, u64* data) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(ecx);
	UNREFERENCED_PARAMETER(data);

	return 0;
}

NTSTATUS svm_set_msr(struct kvm_vcpu* vcpu, unsigned ecx, u64 data) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(ecx);
	UNREFERENCED_PARAMETER(data);

	return 0;
}

u64 svm_get_segment_base(struct kvm_vcpu* vcpu, int seg) {
	struct vmcb_seg* s = svm_seg(vcpu, seg);

	return s->base;
}

struct vmcb_seg* svm_seg(struct kvm_vcpu* vcpu, int seg) {
	struct vmcb_save_area* save = &to_svm(vcpu)->vmcb->save;

	switch (seg) {
	case VCPU_SREG_CS: return &save->cs;
	case VCPU_SREG_DS: return &save->ds;
	case VCPU_SREG_ES: return &save->es;
	case VCPU_SREG_FS: return &save->fs;
	case VCPU_SREG_GS: return &save->gs;
	case VCPU_SREG_SS: return &save->ss;
	case VCPU_SREG_TR: return &save->tr;
	case VCPU_SREG_LDTR: return &save->ldtr;
	}

	return NULL;
}

void svm_get_segment(struct kvm_vcpu* vcpu,
	struct kvm_segment* var, int seg) {
	struct vmcb_seg* s = svm_seg(vcpu, seg);

	var->base = s->base;
	var->limit = s->limit;
	var->type = s->attrib & SVM_SELECTOR_TYPE_MASK;
	var->s = (s->attrib >> SVM_SELECTOR_S_SHIFT) & 1;
	var->dpl = (s->attrib >> SVM_SELECTOR_DPL_SHIFT) & 3;
	var->present = (s->attrib >> SVM_SELECTOR_P_SHIFT) & 1;
	var->avl = (s->attrib >> SVM_SELECTOR_AVL_SHIFT) & 1;
	var->l = (s->attrib >> SVM_SELECTOR_L_SHIFT) & 1;
	var->db = (s->attrib >> SVM_SELECTOR_DB_SHIFT) & 1;
	var->g = (s->attrib >> SVM_SELECTOR_G_SHIFT) & 1;

	/* AMD's VMCB does not have an explicit unusable field, so emulate it
	 * for cross vendor migration purposes by "not present"
	 */
	var->unusable = !var->present || (var->type == 0);


}

void svm_set_segment(struct kvm_vcpu* vcpu,
	struct kvm_segment* var, int seg) {
	struct vcpu_svm* svm = to_svm(vcpu);
	struct vmcb_seg* s = svm_seg(vcpu, seg);

	s->base = var->base;
	s->limit = var->limit;
	s->selector = var->selector;
	if (var->unusable)
		s->attrib = 0;
	else {
		s->attrib = (var->type & SVM_SELECTOR_TYPE_MASK);
		s->attrib |= (var->s & 1) << SVM_SELECTOR_S_SHIFT;
		s->attrib |= (var->dpl & 3) << SVM_SELECTOR_DPL_SHIFT;
		s->attrib |= (var->present & 1) << SVM_SELECTOR_P_SHIFT;
		s->attrib |= (var->avl & 1) << SVM_SELECTOR_AVL_SHIFT;
		s->attrib |= (var->l & 1) << SVM_SELECTOR_L_SHIFT;
		s->attrib |= (var->db & 1) << SVM_SELECTOR_DB_SHIFT;
		s->attrib |= (var->g & 1) << SVM_SELECTOR_G_SHIFT;
	}
	if (seg == VCPU_SREG_CS)
		svm->vmcb->save.cpl
		= (svm->vmcb->save.cs.attrib
			>> SVM_SELECTOR_DPL_SHIFT) & 3;
}

int svm_get_cpl(struct kvm_vcpu* vcpu) {
	struct vmcb_save_area* save = &to_svm(vcpu)->vmcb->save;

	return save->cpl;
}

void svm_decache_cr4_guest_bits(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
}

void svm_set_cr0(struct kvm_vcpu* vcpu, unsigned long cr0) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(cr0);
}

void svm_set_cr3(struct kvm_vcpu* vcpu, unsigned long root) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(root);
}

void svm_set_cr4(struct kvm_vcpu* vcpu, unsigned long cr4) {
	// unsigned long host_cr4_mce = __readcr4() & X86_CR4_MCE;
	// u64 old_cr4 = to_svm(vcpu)->vmcb->save.cr4;


	to_svm(vcpu)->vmcb->save.cr4 = cr4;
}

void svm_set_efer(struct kvm_vcpu* vcpu, u64 efer) {
	if (!npt_enabled && !(efer & EFER_LMA))
		efer &= ~EFER_LME;

	to_svm(vcpu)->vmcb->save.efer = efer | EFER_SVME;
	
}

void svm_get_idt(struct kvm_vcpu* vcpu, struct desc_ptr* dt) {
	struct vcpu_svm* svm = to_svm(vcpu);

	dt->size = (u16)svm->vmcb->save.idtr.limit;
	dt->address = (unsigned long)svm->vmcb->save.idtr.base;
}

void svm_set_idt(struct kvm_vcpu* vcpu, struct desc_ptr* dt) {
	struct vcpu_svm* svm = to_svm(vcpu);

	svm->vmcb->save.idtr.limit = dt->size;
	svm->vmcb->save.idtr.base = dt->address;
}

void svm_get_gdt(struct kvm_vcpu* vcpu, struct desc_ptr* dt) {
	struct vcpu_svm* svm = to_svm(vcpu);

	dt->size = (u16)svm->vmcb->save.gdtr.limit;
	dt->address = (ULONG_PTR)svm->vmcb->save.gdtr.base;
}

void svm_set_gdt(struct kvm_vcpu* vcpu, struct desc_ptr* dt)
{
	struct vcpu_svm* svm = to_svm(vcpu);

	svm->vmcb->save.gdtr.limit = dt->size;
	svm->vmcb->save.gdtr.base = dt->address;
}

unsigned long svm_get_dr(struct kvm_vcpu* vcpu, int dr) {
	UNREFERENCED_PARAMETER(vcpu);

	switch (dr)
	{
	
	case 7:
		
		break;
	default:
		
		break;
	}

	return 0;
}

void svm_set_dr(struct kvm_vcpu* vcpu, int dr, unsigned long value,
	int* exception) {
	UNREFERENCED_PARAMETER(vcpu);

	*exception = 0;

	switch (dr)
	{

	case 4:
	case 5:
	
		return;

	case 6:
		if (value & 0xffffffff00000000ULL) {
			*exception = GP_VECTOR;
			return;
		}
		
		return;
	default:
		
		/* FIXME: Possible case? */
		Log(KERN_DEBUG, "%s: unexpected dr %u\n",
			__func__, dr);
		*exception = UD_VECTOR;
		return;
	}
}

void svm_cache_reg(struct kvm_vcpu* vcpu, enum kvm_reg reg)
{
	UNREFERENCED_PARAMETER(vcpu);
	switch (reg) {
	case VCPU_EXREG_PDPTR:
		// BUG_ON(!npt_enabled);
		// load_pdptrs(vcpu, vcpu->arch.cr3);
		break;
	default:
		return;
	}
}

unsigned long svm_get_rflags(struct kvm_vcpu* vcpu)
{
	return (unsigned long)to_svm(vcpu)->vmcb->save.rflags;
}

void svm_set_rflags(struct kvm_vcpu* vcpu, unsigned long rflags)
{
	to_svm(vcpu)->vmcb->save.rflags = rflags;
}


void svm_vcpu_run(struct kvm_vcpu* vcpu, struct kvm_run* kvm_run) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(kvm_run);
}



int handle_exit(struct kvm_run* kvm_run, struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(kvm_run);
	UNREFERENCED_PARAMETER(vcpu);


	return 1;
}

static void skip_emulated_instruction(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
}

void svm_set_interrupt_shadow(struct kvm_vcpu* vcpu, int mask)
{
	struct vcpu_svm* svm = to_svm(vcpu);

	if (mask == 0)
		svm->vmcb->control.int_state &= ~SVM_INTERRUPT_SHADOW_MASK;
	else
		svm->vmcb->control.int_state |= SVM_INTERRUPT_SHADOW_MASK;

}



u32 svm_get_interrupt_shadow(struct kvm_vcpu* vcpu, int mask)
{
	struct vcpu_svm* svm = to_svm(vcpu);
	u32 ret = 0;

	if (svm->vmcb->control.int_state & SVM_INTERRUPT_SHADOW_MASK)
		ret |= X86_SHADOW_INT_STI | X86_SHADOW_INT_MOV_SS;
	return ret & mask;
}

void svm_patch_hypercall(struct kvm_vcpu* vcpu, unsigned char* hypercall)
{
	UNREFERENCED_PARAMETER(vcpu);
	/*
	 * Patch in the VMMCALL instruction:
	 */
	hypercall[0] = 0x0f;
	hypercall[1] = 0x01;
	hypercall[2] = 0xd9;/* vmmcall */
}

void svm_set_irq(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
}

void svm_inject_nmi(struct kvm_vcpu* vcpu)
{
	struct vcpu_svm* svm = to_svm(vcpu);

	svm->vmcb->control.event_inj = (u32)(SVM_EVTINJ_VALID | SVM_EVTINJ_TYPE_NMI);
	

	
}

void svm_queue_exception(struct kvm_vcpu* vcpu, unsigned nr,
	bool has_error_code, u32 error_code)
{
	struct vcpu_svm* svm = to_svm(vcpu);

	/* If we are within a nested VM we'd better #VMEXIT and let the
	   guest handle the exception */
	/*if (nested_svm_check_exception(svm, nr, has_error_code, error_code))
		return;*/

	svm->vmcb->control.event_inj = nr
		| SVM_EVTINJ_VALID
		| (has_error_code ? SVM_EVTINJ_VALID_ERR : 0)
		| SVM_EVTINJ_TYPE_EXEPT;
	svm->vmcb->control.event_inj_err = error_code;
}

int svm_interrupt_allowed(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);

	return 1;
}

int svm_nmi_allowed(struct kvm_vcpu* vcpu)
{
	UNREFERENCED_PARAMETER(vcpu);
	return FALSE;
}

static void enable_nmi_window(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
}

static void enable_irq_window(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
}

static void update_cr8_intercept(struct kvm_vcpu* vcpu, int tpr, int irr)
{
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(tpr);


	if (irr == -1)
		return;

}

int svm_set_tss_addr(struct kvm* kvm, unsigned int addr) {
	UNREFERENCED_PARAMETER(kvm);
	UNREFERENCED_PARAMETER(addr);
	return 0;
}

int get_npt_level() {
#ifdef  AMD64
	return PT64_ROOT_4LEVEL;
#else
	return PT32E_ROOT_LEVEL;
#endif //  _WIN64

}

u64 svm_get_mt_mask(struct kvm_vcpu* vcpu, gfn_t gfn, bool is_mmio) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(gfn);
	UNREFERENCED_PARAMETER(is_mmio);
	return 0;
}

bool svm_gb_page_enable(void)
{
	return TRUE;
}

void svm_hardware_unsetup(void) {

}

void svm_exit() {
	kvm_exit();
	kvm_x86_vendor_exit();
}


static int svm_vcpu_create(struct kvm_vcpu* vcpu) {
	struct vcpu_svm* svm;
	void* vmcb01_page;
	
	int err;

	svm = to_svm(vcpu);

	err = STATUS_NO_MEMORY;
	
	do
	{
		LARGE_INTEGER lowAddress;
		LARGE_INTEGER highAddress;
		LARGE_INTEGER boundary;

		lowAddress.QuadPart = 0ull;
		highAddress.QuadPart = ~0ull;
		// 4KB边界对齐
		boundary.QuadPart = PAGE_SIZE;

		vmcb01_page = MmAllocateContiguousMemorySpecifyCacheNode(PAGE_SIZE,
			lowAddress, highAddress, boundary, MmCached, 
			KeGetCurrentNodeNumber());
		if (!vmcb01_page) {
			break;
		}
		PHYSICAL_ADDRESS physical = MmGetPhysicalAddress(vmcb01_page);
		svm->vmcb01.ptr = vmcb01_page;
		svm->vmcb01.pa = physical.QuadPart; // 物理地址

		
		return STATUS_SUCCESS;
	} while (FALSE);

	return err;
}


static void svm_vcpu_enter_exit(struct kvm_vcpu* vcpu, bool spec_ctrl_intercepted) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(spec_ctrl_intercepted);


	
	
}

// 对于所有的物理cpu，进行svm相关初始化
static int svm_cpu_init(int cpu) {
	struct svm_cpu_data* sd = &svm_data[cpu];
	int ret = STATUS_NO_MEMORY;

	memset(sd, 0, sizeof(struct svm_cpu_data));
	
	return ret;
}

static ULONG_PTR InitSvmData(
	_In_ ULONG_PTR Argument
) {
	UNREFERENCED_PARAMETER(Argument);
	int cpu = KeGetCurrentProcessorNumber();
	svm_cpu_init(cpu);
	return 0;
}

static NTSTATUS svm_hardware_setup(void) {
	KeIpiGenericCall(InitSvmData, 0);

	return STATUS_SUCCESS;
}

static void init_seg(struct vmcb_seg* seg)
{
	seg->selector = 0;
	seg->attrib = SVM_SELECTOR_P_MASK | SVM_SELECTOR_S_MASK |
		SVM_SELECTOR_WRITE_MASK; /* Read/Write Data Segment */
	seg->limit = 0xffff;
	seg->base = 0;
}

static void init_sys_seg(struct vmcb_seg* seg, uint32_t type)
{
	seg->selector = 0;
	seg->attrib = (u16)(SVM_SELECTOR_P_MASK | type);
	seg->limit = 0xffff;
	seg->base = 0;
}

static inline void vmcb_clr_intercept(struct vmcb_control_area* control,
	u32 bit)
{
	UNREFERENCED_PARAMETER(control);
	UNREFERENCED_PARAMETER(bit);
}

static inline void svm_clr_intercept(struct vcpu_svm* svm, int bit)
{
	struct vmcb* vmcb = svm->vmcb01.ptr;

	vmcb_clr_intercept(&vmcb->control, bit);

	recalc_intercepts(svm);
}

static void init_vmcb(struct kvm_vcpu* vcpu) {
	struct vcpu_svm* svm = to_svm(vcpu);
	struct vmcb* vmcb = svm->vmcb01.ptr;
	struct vmcb_control_area* control = &vmcb->control;
	struct vmcb_save_area* save = &vmcb->save;

	svm_set_intercept(svm, INTERCEPT_CR0_READ);
	svm_set_intercept(svm, INTERCEPT_CR3_READ);
	svm_set_intercept(svm, INTERCEPT_CR4_READ);
	svm_set_intercept(svm, INTERCEPT_CR0_WRITE);
	svm_set_intercept(svm, INTERCEPT_CR3_WRITE);
	svm_set_intercept(svm, INTERCEPT_CR4_WRITE);


	control->int_ctl = V_INTR_MASKING_MASK;

	init_seg(&save->es);
	init_seg(&save->ss);
	init_seg(&save->ds);
	init_seg(&save->fs);
	init_seg(&save->gs);

	save->cs.selector = 0xf000;
	save->cs.base = 0xffff0000;
	save->cs.attrib = SVM_SELECTOR_READ_MASK | SVM_SELECTOR_P_MASK |
		SVM_SELECTOR_S_MASK | SVM_SELECTOR_CODE_MASK;
	save->cs.limit = 0xffff;

	save->gdtr.base = 0;
	save->gdtr.limit = 0xffff;
	save->idtr.base = 0;
	save->idtr.limit = 0xffff;

	init_sys_seg(&save->ldtr, SEG_TYPE_LDT);
	init_sys_seg(&save->tr, SEG_TYPE_BUSY_TSS16);

	if (npt_enabled) {
		/* Setup VMCB for Nested Paging */
		control->nested_ctl |= SVM_NESTED_CTL_NP_ENABLE;
		svm_clr_intercept(svm, INTERCEPT_INVLPG);
		svm_clr_intercept(svm, INTERCEPT_CR3_READ);
		svm_clr_intercept(svm, INTERCEPT_CR3_WRITE);
		save->g_pat = vcpu->arch.pat;
		save->cr3 = 0;
	}
}

static inline void svm_set_intercept(struct vcpu_svm* svm, int bit) {
	struct vmcb* vmcb = svm->vmcb01.ptr;

	vmcb_set_intercept(&vmcb->control, bit);

	recalc_intercepts(svm);
}

/*
 * The default MMIO mask is a single bit (excluding the present bit),
 * which could conflict with the memory encryption bit. Check for
 * memory encryption support and override the default MMIO mask if
 * memory encryption is enabled.
 */
static void svm_adjust_mmio_mask(void) {
	unsigned int enc_bit;
	u64 msr;

	/* If there is no memory encryption support, use existing mask */
	if (cpuid_eax(0x80000000) < 0x8000001f)
		return;

	/* If memory encryption is not enabled, use existing mask */
	msr = __readmsr(MSR_AMD64_SYSCFG);
	if (!(msr & MSR_AMD64_SYSCFG_MEM_ENCRYPT))
		return;

	enc_bit = cpuid_ebx(0x8000001f) & 0x3f;
	/*
	 * If the mask bit location is below 52, then some bits above the
	 * physical addressing limit will always be reserved, so use the
	 * rsvd_bits() function to generate the mask. This mask, along with
	 * the present bit, will be used to generate a page fault with
	 * PFER.RSV = 1.
	 *
	 * If the mask bit location is 52 (or above), then clear the mask.
	 */

}

static void svm_set_cpu_caps(void) {
	kvm_set_cpu_caps();

	/* CPUID 0x80000001 and 0x8000000A (SVM features) */
	if (nested) {

	}

	/* CPUID 0x80000008 */


	/* AMD PMU PERFCTR_CORE CPUID */



	/* CPUID 0x8000001F (SME/SEV features) */

}