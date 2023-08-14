#pragma once

#include "kvm_host.h"

#define KVM_POSSIBLE_CR0_GUEST_BITS	(X86_CR0_TS | X86_CR0_WP)
#define KVM_POSSIBLE_CR4_GUEST_BITS				  \
	(X86_CR4_PVI | X86_CR4_DE | X86_CR4_PCE | X86_CR4_OSFXSR  \
	 | X86_CR4_OSXMMEXCPT | X86_CR4_PGE | X86_CR4_TSD | X86_CR4_FSGSBASE)

#define X86_CR0_PDPTR_BITS    (X86_CR0_CD | X86_CR0_NW | X86_CR0_PG)
#define X86_CR4_TLBFLUSH_BITS (X86_CR4_PGE | X86_CR4_PCIDE | X86_CR4_PAE | X86_CR4_SMEP)
#define X86_CR4_PDPTR_BITS    (X86_CR4_PGE | X86_CR4_PSE | X86_CR4_PAE | X86_CR4_SMEP)

/*
 * avail  dirty
 * 0	  0	  register in VMCS/VMCB
 * 0	  1	  *INVALID*
 * 1	  0	  register in vcpu->arch
 * 1	  1	  register in vcpu->arch, needs to be stored back
 */
static inline bool kvm_register_is_available(struct kvm_vcpu* vcpu,
	enum kvm_reg reg)
{
	return _bittest((LONG*)&vcpu->arch.regs_avail, reg);
}

static inline bool is_guest_mode(struct kvm_vcpu* vcpu)
{
	return vcpu->arch.hflags & HF_GUEST_MASK;
}

static inline ulong kvm_read_cr0_bits(struct kvm_vcpu* vcpu, ulong mask) {
	ulong tmask = mask & KVM_POSSIBLE_CR0_GUEST_BITS;
	if ((tmask & vcpu->arch.cr0_guest_owned_bits) &&
		!kvm_register_is_available(vcpu, VCPU_EXREG_CR0))
		kvm_x86_ops.cache_reg(vcpu, VCPU_EXREG_CR0);
	return vcpu->arch.cr0 & mask;
}

static inline ulong kvm_read_cr0(struct kvm_vcpu* vcpu)
{
	return kvm_read_cr0_bits(vcpu, ~0UL);
}

static inline ulong kvm_read_cr4_bits(struct kvm_vcpu* vcpu, ulong mask)
{
	ulong tmask = mask & KVM_POSSIBLE_CR4_GUEST_BITS;
	if ((tmask & vcpu->arch.cr4_guest_owned_bits) &&
		!kvm_register_is_available(vcpu, VCPU_EXREG_CR4))
		kvm_x86_ops.cache_reg(vcpu, VCPU_EXREG_CR4);
	return vcpu->arch.cr4 & mask;
}

static bool kvm_is_cr4_bit_set(struct kvm_vcpu* vcpu,
	unsigned long cr4_bit)
{
	return !!kvm_read_cr4_bits(vcpu, cr4_bit);
}

static inline ulong kvm_read_cr4(struct kvm_vcpu* vcpu)
{
	return kvm_read_cr4_bits(vcpu, ~0UL);
}

static bool kvm_is_cr0_bit_set(struct kvm_vcpu* vcpu,
	unsigned long cr0_bit)
{
	return !!kvm_read_cr0_bits(vcpu, cr0_bit);
}

static inline ulong kvm_read_cr3(struct kvm_vcpu* vcpu)
{
	if (!kvm_register_is_available(vcpu, VCPU_EXREG_CR3))
		kvm_x86_ops.cache_reg(vcpu, VCPU_EXREG_CR3);
	return vcpu->arch.cr3;
}

static inline u64 kvm_pdptr_read(struct kvm_vcpu* vcpu, int index)
{
	

	if (!kvm_register_is_available(vcpu, VCPU_EXREG_PDPTR))
		kvm_x86_ops.cache_reg(vcpu, VCPU_EXREG_PDPTR);

	return vcpu->arch.walk_mmu->pdptrs[index];
}

static inline void kvm_register_mark_available(struct kvm_vcpu* vcpu,
	enum kvm_reg reg) {
	BitTestAndSet((LONG*)&vcpu->arch.regs_avail, reg);
}

static inline bool kvm_register_is_dirty(struct kvm_vcpu* vcpu,
	enum kvm_reg reg)
{
	return _bittest((LONG*)&vcpu->arch.regs_dirty, reg);
}

/*
 * The "raw" register helpers are only for cases where the full 64 bits of a
 * register are read/written irrespective of current vCPU mode.  In other words,
 * odds are good you shouldn't be using the raw variants.
 */
static inline unsigned long kvm_register_read_raw(struct kvm_vcpu* vcpu, int reg)
{
	if (!kvm_register_is_available(vcpu, reg))
		kvm_x86_ops.cache_reg(vcpu, reg);

	return vcpu->arch.regs[reg];
}