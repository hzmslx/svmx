#pragma once
#include "kvm_host.h"
#include "mmu.h"



/*
 * Unlike regular MMU roots, PAE "roots", a.k.a. PDPTEs/PDPTRs, have a PRESENT
 * bit, and thus are guaranteed to be non-zero when valid.  And, when a guest
 * PDPTR is !PRESENT, its corresponding PAE root cannot be set to INVALID_PAGE,
 * as the CPU would treat that as PRESENT PDPTR with reserved bits set.  Use
 * '0' instead of INVALID_PAGE to indicate an invalid PAE root.
 */
#define INVALID_PAE_ROOT	0
#define IS_VALID_PAE_ROOT(x)	(!!(x))



/*
 * Return values of handle_mmio_page_fault(), mmu.page_fault(), fast_page_fault(),
 * and of course kvm_mmu_do_page_fault().
 *
 * RET_PF_CONTINUE: So far, so good, keep handling the page fault.
 * RET_PF_RETRY: let CPU fault again on the address.
 * RET_PF_EMULATE: mmio page fault, emulate the instruction directly.
 * RET_PF_INVALID: the spte is invalid, let the real page fault path update it.
 * RET_PF_FIXED: The faulting entry has been fixed.
 * RET_PF_SPURIOUS: The faulting entry was already fixed, e.g. by another vCPU.
 *
 * Any names added to this enum should be exported to userspace for use in
 * tracepoints via TRACE_DEFINE_ENUM() in mmutrace.h
 *
 * Note, all values must be greater than or equal to zero so as not to encroach
 * on -errno return values.  Somewhat arbitrarily use '0' for CONTINUE, which
 * will allow for efficient machine code when checking for CONTINUE, e.g.
 * "TEST %rax, %rax, JNZ", as all "stop!" values are non-zero.
 */
enum {
	RET_PF_CONTINUE = 0,
	RET_PF_RETRY,
	RET_PF_EMULATE,
	RET_PF_INVALID,
	RET_PF_FIXED,
	RET_PF_SPURIOUS,
};

extern int nx_huge_pages;
static inline bool is_nx_huge_page_enabled(struct kvm* kvm)
{
	return nx_huge_pages && !kvm->arch.disable_nx_huge_pages;
}

static inline int kvm_mmu_do_page_fault(struct kvm_vcpu* vcpu, gpa_t cr2_or_gpa,
	u32 err, bool prefetch, int* emulation_type) {
	struct kvm_page_fault fault = {
		.addr = cr2_or_gpa,
		.error_code = err,
		.exec = err & PFERR_FETCH_MASK,
		.write = err & PFERR_WRITE_MASK,
		.present = err & PFERR_PRESENT_MASK,
		.rsvd = err & PFERR_RSVD_MASK,
		.user = err & PFERR_USER_MASK,
		.prefetch = prefetch,
		.is_tdp = vcpu->arch.mmu->page_fault == kvm_tdp_page_fault ? 1 : 0,
		.nx_huge_page_workaround_enabled =
			is_nx_huge_page_enabled(vcpu->kvm),

		.max_level = KVM_MAX_HUGEPAGE_LEVEL,
		.req_level = PG_LEVEL_4K,
		.goal_level = PG_LEVEL_4K,
	};
	int r;

	if (vcpu->arch.mmu->root_role.direct) {
		fault.gfn = (gfn_t)(fault.addr >> PAGE_SHIFT);
	}

	/*
	 * Async #PF "faults", a.k.a. prefetch faults, are not faults from the
	 * guest perspective and have already been counted at the time of the
	 * original fault.
	 */
	if (!prefetch)
		vcpu->stat.pf_taken++;

	if (fault.is_tdp) {
		r = kvm_tdp_page_fault(vcpu, &fault);
	}
	else
		r = vcpu->arch.mmu->page_fault(vcpu, &fault);

	if (fault.write_fault_to_shadow_pgtable && emulation_type)
		*emulation_type |= EMULTYPE_WRITE_PF_TO_SP;

	return r;
}


