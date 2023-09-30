#pragma once
#include "kvm_cache_regs.h"
#include "mmu.h"

extern bool enable_vmware_backdoor;

extern struct kvm_caps kvm_caps;

void kvm_init_msr_list();

static inline bool kvm_mwait_in_guest(struct kvm* kvm)
{
	return kvm->arch.mwait_in_guest;
}

static inline bool kvm_hlt_in_guest(struct kvm* kvm)
{
	return kvm->arch.hlt_in_guest;
}

static inline unsigned long kvm_register_read(struct kvm_vcpu* vcpu, int reg)
{
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(reg);
	/*unsigned long val = kvm_register_read_raw(vcpu, reg);

	return is_64_bit_mode(vcpu) ? val : (u32)val;*/
	return 0;
}

static inline bool is_long_mode(struct kvm_vcpu* vcpu)
{
#ifdef _WIN64
	return !!(vcpu->arch.efer & EFER_LMA);
#else
	return false;
#endif
}

/*
 * The first...last VMX feature MSRs that are emulated by KVM.  This may or may
 * not cover all known VMX MSRs, as KVM doesn't emulate an MSR until there's an
 * associated feature that KVM supports for nested virtualization.
 */
#define KVM_FIRST_EMULATED_VMX_MSR	MSR_IA32_VMX_BASIC
#define KVM_LAST_EMULATED_VMX_MSR	MSR_IA32_VMX_VMFUNC

 /*
  * Internal error codes that are used to indicate that MSR emulation encountered
  * an error that should result in #GP in the guest, unless userspace
  * handles it.
  */
#define  KVM_MSR_RET_INVALID	2	/* in-kernel MSR emulation #GP condition */
#define  KVM_MSR_RET_FILTERED	3	/* #GP due to userspace MSR filter */

static inline bool is_64_bit_mode(struct kvm_vcpu* vcpu)
{
	int cs_db, cs_l;


	if (!is_long_mode(vcpu))
		return FALSE;
	kvm_x86_ops.get_cs_db_l_bits(vcpu, &cs_db, &cs_l);
	return cs_l;
}

static inline bool is_pae(struct kvm_vcpu* vcpu)
{
	return kvm_is_cr4_bit_set(vcpu, X86_CR4_PAE);
}

static inline bool is_paging(struct kvm_vcpu* vcpu)
{
	return kvm_is_cr0_bit_set(vcpu, X86_CR0_PG);
}

static inline bool is_pae_paging(struct kvm_vcpu* vcpu)
{
	return !is_long_mode(vcpu) && is_pae(vcpu) && is_paging(vcpu);
}

bool __kvm_is_valid_cr4(struct kvm_vcpu* vcpu, ULONG_PTR cr4);

fastpath_t handle_fastpath_set_msr_irqoff(struct kvm_vcpu* vcpu);

#define MSR_IA32_CR_PAT_DEFAULT  0x0007040600070406ULL


static inline bool mmu_is_nested(struct kvm_vcpu* vcpu)
{
	return vcpu->arch.walk_mmu == &vcpu->arch.nested_mmu;
}

int x86_emulate_instruction(struct kvm_vcpu* vcpu, gpa_t cr2_or_gpa,
	int emulation_type, void* insn, int insn_len);


static inline void kvm_machine_check(void) {
	
}

static inline bool kvm_notify_vmexit_enabled(struct kvm* kvm) {
	return kvm->arch.notify_vmexit_flags & KVM_X86_NOTIFY_VMEXIT_ENABLED;
}

void kvm_vcpu_mtrr_init(struct kvm_vcpu* vcpu);
int kvm_x86_init(void);
bool kvm_vcpu_exit_request(struct kvm_vcpu* vcpu);

static inline bool vcpu_match_mmio_gen(struct kvm_vcpu* vcpu) {
	return vcpu->arch.mmio_gen == kvm_memslots(vcpu->kvm)->generation;
}

static inline bool vcpu_match_mmio_gva(struct kvm_vcpu* vcpu,
	ULONG_PTR gva) {
	if (vcpu_match_mmio_gen(vcpu) && vcpu->arch.mmio_gva &&
		vcpu->arch.mmio_gva == (gva & PAGE_MASK))
		return TRUE;

	return FALSE;
}

static inline bool vcpu_match_mmio_gpa(struct kvm_vcpu* vcpu,
	gpa_t gpa)
{
	if (vcpu_match_mmio_gen(vcpu) && vcpu->arch.mmio_gfn &&
		vcpu->arch.mmio_gfn == gpa >> PAGE_SHIFT)
		return TRUE;

	return FALSE;
}