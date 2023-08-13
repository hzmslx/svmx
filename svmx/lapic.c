#include "pch.h"
#include "lapic.h"
#include "kvm.h"
#include "kvm_cache_regs.h"
#include "x86.h"
#include "cpuid.h"
#include "apicdef.h"


u64 kvm_lapic_get_cr8(struct kvm_vcpu* vcpu)
{
	u64 tpr;

	tpr = (u64)kvm_lapic_get_reg(vcpu->arch.apic, APIC_TASKPRI);

	return (tpr & 0xf0) >> 4;
}

static int find_highest_vector(void* bitmap)
{
	UNREFERENCED_PARAMETER(bitmap);

	return -1;
}



static inline int apic_find_highest_irr(struct kvm_lapic* apic)
{
	int result = -1;

	/*
	 * Note that irr_pending is just a hint. It will be always
	 * true with virtual interrupt delivery enabled.
	 */
	if (!apic->irr_pending)
		return -1;

	

	return result;
}

int kvm_lapic_find_highest_irr(struct kvm_vcpu* vcpu)
{
	/* This may race with setting of irr in __apic_accept_irq() and
	 * value returned may be wrong, but kvm_vcpu_kick() in __apic_accept_irq
	 * will cause vmexit immediately and the value will be recalculated
	 * on the next vmentry.
	 */
	return apic_find_highest_irr(vcpu->arch.apic);
}

int kvm_create_lapic(struct kvm_vcpu* vcpu, int timer_advance_ns) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(timer_advance_ns);
	return 0;
}