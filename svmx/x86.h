#pragma once
#include "kvm_cache_regs.h"

extern bool enable_vmware_backdoor;

void kvm_init_msr_list();



static bool mmu_is_nested(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	return FALSE;
}

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

static inline bool is_64_bit_mode(struct kvm_vcpu* vcpu)
{
	int cs_db, cs_l;


	if (!is_long_mode(vcpu))
		return FALSE;
	kvm_x86_ops.get_cs_db_l_bits(vcpu, &cs_db, &cs_l);
	return cs_l;
}

static inline bool is_paging(struct kvm_vcpu* vcpu)
{
	return kvm_is_cr0_bit_set(vcpu, X86_CR0_PG);
}

bool __kvm_is_valid_cr4(struct kvm_vcpu* vcpu, unsigned long cr4);
