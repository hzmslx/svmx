#include "pch.h"
#include "svm.h"
#include "virtext.h"
#include "kvm_emulate.h"
#include "mmu.h"


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

struct vcpu_svm {
	struct kvm_vcpu vcpu;
	struct vmcb* vmcb;
	unsigned long vmcb_pa;
	struct svm_cpu_data* svm_data;
	uint64_t asid_generation;
	uint64_t sysenter_esp;
	uint64_t sysenter_eip;

	u64 next_rip;

	u64 host_user_msrs[NR_HOST_SAVE_USER_MSRS];
	u64 host_gs_base;

	u32* msrpm;

	struct nested_state nested;
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
NTSTATUS svm_hardware_setup();
void svm_hardware_enable(void* garbage);
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
void svm_get_idt(struct kvm_vcpu* vcpu, struct descriptor_table* dt);
void svm_set_idt(struct kvm_vcpu* vcpu, struct descriptor_table* dt);
void svm_get_gdt(struct kvm_vcpu* vcpu, struct descriptor_table* dt);
void svm_set_gdt(struct kvm_vcpu* vcpu, struct descriptor_table* dt);
unsigned long svm_get_dr(struct kvm_vcpu* vcpu, int dr);
void svm_set_dr(struct kvm_vcpu* vcpu, int dr, unsigned long value,
	int* exception);
void svm_cache_reg(struct kvm_vcpu* vcpu, enum kvm_reg reg);
unsigned long svm_get_rflags(struct kvm_vcpu* vcpu);
void svm_set_rflags(struct kvm_vcpu* vcpu, unsigned long rflags);
void svm_flush_tlb(struct kvm_vcpu* vcpu);
void svm_vcpu_run(struct kvm_vcpu* vcpu, struct kvm_run* kvm_run);
int handle_exit(struct kvm_run* kvm_run, struct kvm_vcpu* vcpu);
static void skip_emulated_instruction(struct kvm_vcpu* vcpu);
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
};

int has_svm() {
	const char* msg;

	if (!cpu_has_svm(&msg)) {
		Log(KERN_INFO, "has_svm: %s\n", msg);
		return 0;
	}

	return 1;
}

NTSTATUS svm_init() {
	NTSTATUS status = STATUS_SUCCESS;

	return status;
}

int is_disabled() {
	u64 vm_cr;

	vm_cr = __readmsr(MSR_VM_CR);
	if (vm_cr & (1 << SVM_VM_CR_SVM_DISABLE))
		return 1;

	return 0;
}

NTSTATUS svm_hardware_setup() {
	NTSTATUS status = STATUS_SUCCESS;


	return status;
}



void svm_hardware_enable(void* garbage) {
	UNREFERENCED_PARAMETER(garbage);


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
	UNREFERENCED_PARAMETER(vcpu);

	return NULL;
}

NTSTATUS svm_vcpu_reset(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);

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
	vcpu->arch.shadow_efer = efer;
}

void svm_get_idt(struct kvm_vcpu* vcpu, struct descriptor_table* dt) {
	struct vcpu_svm* svm = to_svm(vcpu);

	dt->limit = (u16)svm->vmcb->save.idtr.limit;
	dt->base = (unsigned long)svm->vmcb->save.idtr.base;
}

void svm_set_idt(struct kvm_vcpu* vcpu, struct descriptor_table* dt) {
	struct vcpu_svm* svm = to_svm(vcpu);

	svm->vmcb->save.idtr.limit = dt->limit;
	svm->vmcb->save.idtr.base = dt->base;
}

void svm_get_gdt(struct kvm_vcpu* vcpu, struct descriptor_table* dt) {
	struct vcpu_svm* svm = to_svm(vcpu);

	dt->limit = (u16)svm->vmcb->save.gdtr.limit;
	dt->base = (unsigned long)svm->vmcb->save.gdtr.base;
}

void svm_set_gdt(struct kvm_vcpu* vcpu, struct descriptor_table* dt)
{
	struct vcpu_svm* svm = to_svm(vcpu);

	svm->vmcb->save.gdtr.limit = dt->limit;
	svm->vmcb->save.gdtr.base = dt->base;
}

unsigned long svm_get_dr(struct kvm_vcpu* vcpu, int dr) {
	struct vcpu_svm* svm = to_svm(vcpu);
	unsigned long val;

	switch (dr)
	{
	
	case 7:
		if (vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP)
			val = vcpu->arch.dr7;
		else
			val = (unsigned long)svm->vmcb->save.dr7;
		break;
	default:
		val = 0;
	}

	return val;
}

void svm_set_dr(struct kvm_vcpu* vcpu, int dr, unsigned long value,
	int* exception) {
	UNREFERENCED_PARAMETER(vcpu);

	*exception = 0;

	switch (dr)
	{

	case 4:
	case 5:
		if (vcpu->arch.cr4 & X86_CR4_DE)
			*exception = UD_VECTOR;
		return;

	case 6:
		if (value & 0xffffffff00000000ULL) {
			*exception = GP_VECTOR;
			return;
		}
		vcpu->arch.dr6 = (value & DR6_VOLATILE) | DR6_FIXED_1;
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

void svm_flush_tlb(struct kvm_vcpu* vcpu)
{
	force_new_asid(vcpu);
}

void force_new_asid(struct kvm_vcpu* vcpu) {
	to_svm(vcpu)->asid_generation--;
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
	vcpu->arch.hflags |= HF_NMI_MASK;
	svm->vmcb->control.intercept |= (1UL << INTERCEPT_IRET);
	
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
	struct vcpu_svm* svm = to_svm(vcpu);
	struct vmcb* vmcb = svm->vmcb;
	return !(vmcb->control.int_state & SVM_INTERRUPT_SHADOW_MASK) &&
		!(svm->vcpu.arch.hflags & HF_NMI_MASK);
}

static void enable_nmi_window(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
}

static void enable_irq_window(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
}

static void update_cr8_intercept(struct kvm_vcpu* vcpu, int tpr, int irr)
{
	struct vcpu_svm* svm = to_svm(vcpu);

	if (irr == -1)
		return;

	if (tpr >= irr)
		svm->vmcb->control.intercept_cr_write |= INTERCEPT_CR8_MASK;
}

int svm_set_tss_addr(struct kvm* kvm, unsigned int addr) {
	UNREFERENCED_PARAMETER(kvm);
	UNREFERENCED_PARAMETER(addr);
	return 0;
}

int get_npt_level() {
#ifdef  _WIN64
	return PT64_ROOT_LEVEL;
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
}