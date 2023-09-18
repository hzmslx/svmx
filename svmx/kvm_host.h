#pragma once
#include "pch.h"
#include "kvm.h"
#include "kvm_types.h"
#include "processor-flags.h"
#include "desc_defs.h"
#include "kvm_emulate.h"
#include "lapic.h"
#include "types.h"
#include "kvm_page_track.h"
#include "pgtable_types.h"
#include "mtrr.h"


#define KVM_GUEST_CR0_MASK_UNRESTRICTED_GUEST				\
	(X86_CR0_WP | X86_CR0_NE | X86_CR0_NW | X86_CR0_CD)
#define KVM_GUEST_CR0_MASK						\
	(KVM_GUEST_CR0_MASK_UNRESTRICTED_GUEST | X86_CR0_PG | X86_CR0_PE)
#define KVM_VM_CR0_ALWAYS_ON_UNRESTRICTED_GUEST				\
	(X86_CR0_WP | X86_CR0_NE | X86_CR0_TS | X86_CR0_MP)
#define KVM_VM_CR0_ALWAYS_ON						\
	(KVM_VM_CR0_ALWAYS_ON_UNRESTRICTED_GUEST | X86_CR0_PG | X86_CR0_PE)
#define KVM_GUEST_CR4_MASK						\
	(X86_CR4_VME | X86_CR4_PSE | X86_CR4_PAE | X86_CR4_PGE | X86_CR4_VMXE)
#define KVM_PMODE_VM_CR4_ALWAYS_ON (X86_CR4_PAE | X86_CR4_VMXE)
#define KVM_RMODE_VM_CR4_ALWAYS_ON (X86_CR4_VME | X86_CR4_PAE | X86_CR4_VMXE)

/* KVM Hugepage definitions for x86 */
#define KVM_MAX_HUGEPAGE_LEVEL	PG_LEVEL_1G
#define KVM_NR_PAGE_SIZES	(KVM_MAX_HUGEPAGE_LEVEL - PG_LEVEL_4K + 1)
#define KVM_HPAGE_GFN_SHIFT(x)	(((x) - 1) * 9)
#define KVM_HPAGE_SHIFT(x)	(PAGE_SHIFT + KVM_HPAGE_GFN_SHIFT(x))
#define KVM_HPAGE_SIZE(x)	(1UL << KVM_HPAGE_SHIFT(x))
#define KVM_HPAGE_MASK(x)	(~(KVM_HPAGE_SIZE(x) - 1))
#define KVM_PAGES_PER_HPAGE(x)	(KVM_HPAGE_SIZE(x) / PAGE_SIZE)

#define DE_VECTOR 0
#define DB_VECTOR 1
#define BP_VECTOR 3
#define OF_VECTOR 4
#define BR_VECTOR 5
#define UD_VECTOR 6
#define NM_VECTOR 7
#define DF_VECTOR 8
#define TS_VECTOR 10
#define NP_VECTOR 11
#define SS_VECTOR 12
#define GP_VECTOR 13
#define PF_VECTOR 14
#define MF_VECTOR 16
#define AC_VECTOR 17
#define MC_VECTOR 18
#define XM_VECTOR 19
#define VE_VECTOR 20

/*Deliver mode, defined for ioapic.c*/
#define dest_Fixed IOSAPIC_FIXED
#define dest_LowestPrio IOSAPIC_LOWEST_PRIORITY

#define NMI_VECTOR      		2
#define ExtINT_VECTOR       		0
#define NULL_VECTOR     		(-1)
#define IA64_SPURIOUS_INT_VECTOR    	0x0f

#define VCPU_LID(v) (((u64)(v)->vcpu_id) << 24)

/* For vcpu->arch.iommu_flags */
#define KVM_IOMMU_CACHE_COHERENCY	0x1

#define NR_PTE_CHAIN_ENTRIES 5

struct kvm_pte_chain {
	u64* parent_ptes[NR_PTE_CHAIN_ENTRIES];
	RTL_DYNAMIC_HASH_TABLE_ENTRY link;
};

#ifndef KVM_ADDRESS_SPACE_NUM
#define KVM_ADDRESS_SPACE_NUM	1
#endif

enum kvm_reg {
	VCPU_REGS_RAX = 0,
	VCPU_REGS_RCX = 1,
	VCPU_REGS_RDX = 2,
	VCPU_REGS_RBX = 3,
	VCPU_REGS_RSP = 4,
	VCPU_REGS_RBP = 5,
	VCPU_REGS_RSI = 6,
	VCPU_REGS_RDI = 7,
#ifdef _WIN64
	VCPU_REGS_R8 = 8,
	VCPU_REGS_R9 = 9,
	VCPU_REGS_R10 = 10,
	VCPU_REGS_R11 = 11,
	VCPU_REGS_R12 = 12,
	VCPU_REGS_R13 = 13,
	VCPU_REGS_R14 = 14,
	VCPU_REGS_R15 = 15,
#endif
	VCPU_REGS_RIP,
	NR_VCPU_REGS,

	VCPU_EXREG_PDPTR = NR_VCPU_REGS,
	VCPU_EXREG_CR0,
	VCPU_EXREG_CR3,
	VCPU_EXREG_CR4,
	VCPU_EXREG_RFLAGS,
	VCPU_EXREG_SEGMENTS,
	VCPU_EXREG_EXIT_INFO_1,
	VCPU_EXREG_EXIT_INFO_2,
};

enum {
	VCPU_SREG_ES,
	VCPU_SREG_CS,
	VCPU_SREG_SS,
	VCPU_SREG_DS,
	VCPU_SREG_FS,
	VCPU_SREG_GS,
	VCPU_SREG_TR,
	VCPU_SREG_LDTR,
};

#define KVM_NR_MEM_OBJS 40

enum exit_fastpath_completion {
	EXIT_FASTPATH_NONE,
	EXIT_FASTPATH_REENTER_GUEST,
	EXIT_FASTPATH_EXIT_HANDLED,
};
typedef enum exit_fastpath_completion fastpath_t;


#define INVALID_PAGE (~(hpa_t)0)
#define VALID_PAGE(x) ((x) != INVALID_PAGE)

#define CR4_RESERVED_BITS                                               \
	(~(unsigned long)(X86_CR4_VME | X86_CR4_PVI | X86_CR4_TSD | X86_CR4_DE\
			  | X86_CR4_PSE | X86_CR4_PAE | X86_CR4_MCE     \
			  | X86_CR4_PGE | X86_CR4_PCE | X86_CR4_OSFXSR | X86_CR4_PCIDE \
			  | X86_CR4_OSXSAVE | X86_CR4_SMEP | X86_CR4_FSGSBASE \
			  | X86_CR4_OSXMMEXCPT | X86_CR4_LA57 | X86_CR4_VMXE \
			  | X86_CR4_SMAP | X86_CR4_PKE | X86_CR4_UMIP))









#define KVM_NR_FIXED_MTRR_REGION 88

#define KVM_NR_VAR_MTRR 8

#define KVM_NR_DB_REGS	4

#define DR6_BD		(1 << 13)
#define DR6_BS		(1 << 14)
#define DR6_FIXED_1	0xffff0ff0
#define DR6_VOLATILE	0x0000e00f

#define DR7_BP_EN_MASK	0x000000ff
#define DR7_GE		(1 << 9)
#define DR7_GD		(1 << 13)
#define DR7_FIXED_1	0x00000400
#define DR7_VOLATILE	0xffff23ff

#define HF_GIF_MASK		(1 << 0)
#define HF_HIF_MASK		(1 << 1)
#define HF_VINTR_MASK		(1 << 2)
#define HF_NMI_MASK		(1 << 3)
#define HF_IRET_MASK		(1 << 4)

#define CR0_RESERVED_BITS                                               \
	(~(unsigned long)(X86_CR0_PE | X86_CR0_MP | X86_CR0_EM | X86_CR0_TS \
			  | X86_CR0_ET | X86_CR0_NE | X86_CR0_WP | X86_CR0_AM \
			  | X86_CR0_NW | X86_CR0_CD | X86_CR0_PG))


enum vcpu_sysreg {
	__INVALID_SYSREG__,   /* 0 is reserved as an invalid value */
	MPIDR_EL1,	/* MultiProcessor Affinity Register */
	CLIDR_EL1,	/* Cache Level ID Register */
	CSSELR_EL1,	/* Cache Size Selection Register */
	SCTLR_EL1,	/* System Control Register */
	ACTLR_EL1,	/* Auxiliary Control Register */
	CPACR_EL1,	/* Coprocessor Access Control */
	ZCR_EL1,	/* SVE Control */
	TTBR0_EL1,	/* Translation Table Base Register 0 */
	TTBR1_EL1,	/* Translation Table Base Register 1 */
	TCR_EL1,	/* Translation Control Register */
	ESR_EL1,	/* Exception Syndrome Register */
	AFSR0_EL1,	/* Auxiliary Fault Status Register 0 */
	AFSR1_EL1,	/* Auxiliary Fault Status Register 1 */
	FAR_EL1,	/* Fault Address Register */
	MAIR_EL1,	/* Memory Attribute Indirection Register */
	VBAR_EL1,	/* Vector Base Address Register */
	CONTEXTIDR_EL1,	/* Context ID Register */
	TPIDR_EL0,	/* Thread ID, User R/W */
	TPIDRRO_EL0,	/* Thread ID, User R/O */
	TPIDR_EL1,	/* Thread ID, Privileged */
	AMAIR_EL1,	/* Aux Memory Attribute Indirection Register */
	CNTKCTL_EL1,	/* Timer Control Register (EL1) */
	PAR_EL1,	/* Physical Address Register */
	MDSCR_EL1,	/* Monitor Debug System Control Register */
	MDCCINT_EL1,	/* Monitor Debug Comms Channel Interrupt Enable Reg */
	OSLSR_EL1,	/* OS Lock Status Register */
	DISR_EL1,	/* Deferred Interrupt Status Register */

	/* Performance Monitors Registers */
	PMCR_EL0,	/* Control Register */
	PMSELR_EL0,	/* Event Counter Selection Register */
	PMEVCNTR0_EL0,	/* Event Counter Register (0-30) */
	PMEVCNTR30_EL0 = PMEVCNTR0_EL0 + 30,
	PMCCNTR_EL0,	/* Cycle Counter Register */
	PMEVTYPER0_EL0,	/* Event Type Register (0-30) */
	PMEVTYPER30_EL0 = PMEVTYPER0_EL0 + 30,
	PMCCFILTR_EL0,	/* Cycle Count Filter Register */
	PMCNTENSET_EL0,	/* Count Enable Set Register */
	PMINTENSET_EL1,	/* Interrupt Enable Set Register */
	PMOVSSET_EL0,	/* Overflow Flag Status Set Register */
	PMUSERENR_EL0,	/* User Enable Register */

	/* Pointer Authentication Registers in a strict increasing order. */
	APIAKEYLO_EL1,
	APIAKEYHI_EL1,
	APIBKEYLO_EL1,
	APIBKEYHI_EL1,
	APDAKEYLO_EL1,
	APDAKEYHI_EL1,
	APDBKEYLO_EL1,
	APDBKEYHI_EL1,
	APGAKEYLO_EL1,
	APGAKEYHI_EL1,

	ELR_EL1,
	SP_EL1,
	SPSR_EL1,

	CNTVOFF_EL2,
	CNTV_CVAL_EL0,
	CNTV_CTL_EL0,
	CNTP_CVAL_EL0,
	CNTP_CTL_EL0,

	/* Memory Tagging Extension registers */
	RGSR_EL1,	/* Random Allocation Tag Seed Register */
	GCR_EL1,	/* Tag Control Register */
	TFSR_EL1,	/* Tag Fault Status Register (EL1) */
	TFSRE0_EL1,	/* Tag Fault Status Register (EL0) */

	/* 32bit specific registers. */
	DACR32_EL2,	/* Domain Access Control Register */
	IFSR32_EL2,	/* Instruction Fault Status Register */
	FPEXC32_EL2,	/* Floating-Point Exception Control Register */
	DBGVCR32_EL2,	/* Debug Vector Catch Register */

	/* EL2 registers */
	VPIDR_EL2,	/* Virtualization Processor ID Register */
	VMPIDR_EL2,	/* Virtualization Multiprocessor ID Register */
	SCTLR_EL2,	/* System Control Register (EL2) */
	ACTLR_EL2,	/* Auxiliary Control Register (EL2) */
	HCR_EL2,	/* Hypervisor Configuration Register */
	MDCR_EL2,	/* Monitor Debug Configuration Register (EL2) */
	CPTR_EL2,	/* Architectural Feature Trap Register (EL2) */
	HSTR_EL2,	/* Hypervisor System Trap Register */
	HACR_EL2,	/* Hypervisor Auxiliary Control Register */
	TTBR0_EL2,	/* Translation Table Base Register 0 (EL2) */
	TTBR1_EL2,	/* Translation Table Base Register 1 (EL2) */
	TCR_EL2,	/* Translation Control Register (EL2) */
	VTTBR_EL2,	/* Virtualization Translation Table Base Register */
	VTCR_EL2,	/* Virtualization Translation Control Register */
	SPSR_EL2,	/* EL2 saved program status register */
	ELR_EL2,	/* EL2 exception link register */
	AFSR0_EL2,	/* Auxiliary Fault Status Register 0 (EL2) */
	AFSR1_EL2,	/* Auxiliary Fault Status Register 1 (EL2) */
	ESR_EL2,	/* Exception Syndrome Register (EL2) */
	FAR_EL2,	/* Fault Address Register (EL2) */
	HPFAR_EL2,	/* Hypervisor IPA Fault Address Register */
	MAIR_EL2,	/* Memory Attribute Indirection Register (EL2) */
	AMAIR_EL2,	/* Auxiliary Memory Attribute Indirection Register (EL2) */
	VBAR_EL2,	/* Vector Base Address Register (EL2) */
	RVBAR_EL2,	/* Reset Vector Base Address Register */
	CONTEXTIDR_EL2,	/* Context ID Register (EL2) */
	TPIDR_EL2,	/* EL2 Software Thread ID Register */
	CNTHCTL_EL2,	/* Counter-timer Hypervisor Control register */
	SP_EL2,		/* EL2 Stack Pointer */
	CNTHP_CTL_EL2,
	CNTHP_CVAL_EL2,
	CNTHV_CTL_EL2,
	CNTHV_CVAL_EL2,

	NR_SYS_REGS	/* Nothing after this line! */
};

struct kvm_arch_async_pf {
	ULONG_PTR pfault_token;
};

struct kvm_async_pf {
	struct kvm_vcpu* vcpu;
	struct mm_struct* mm;
	gpa_t cr2_or_gpa;
	ULONG_PTR addr;
	struct kvm_arch_async_pf arch;
	bool   wakeup_all;
	bool notpresent_injected;
};


enum {
	// host 模式
	OUTSIDE_GUEST_MODE,
	// 虚拟机模式
	IN_GUEST_MODE,
	// 表明 ipi 将很快发生
	EXITING_GUEST_MODE,
	READING_SHADOW_PAGE_TABLES,
};



struct msr_data {
	bool host_initiated;
	u32 index;
	u64 data;
};


#define PFERR_PRESENT_BIT 0
#define PFERR_WRITE_BIT 1
#define PFERR_USER_BIT 2
#define PFERR_RSVD_BIT 3
#define PFERR_FETCH_BIT 4
#define PFERR_PK_BIT 5
#define PFERR_SGX_BIT 15
#define PFERR_GUEST_FINAL_BIT 32
#define PFERR_GUEST_PAGE_BIT 33
#define PFERR_IMPLICIT_ACCESS_BIT 48


#define PFERR_PRESENT_MASK	BIT(PFERR_PRESENT_BIT)
#define PFERR_WRITE_MASK	BIT(PFERR_WRITE_BIT)
#define PFERR_USER_MASK		BIT(PFERR_USER_BIT)
#define PFERR_RSVD_MASK		BIT(PFERR_RSVD_BIT)
#define PFERR_FETCH_MASK	BIT(PFERR_FETCH_BIT)
#define PFERR_PK_MASK		BIT(PFERR_PK_BIT)
#define PFERR_SGX_MASK		BIT(PFERR_SGX_BIT)
#define PFERR_GUEST_FINAL_MASK	BIT_ULL(PFERR_GUEST_FINAL_BIT)
#define PFERR_GUEST_PAGE_MASK	BIT_ULL(PFERR_GUEST_PAGE_BIT)
#define PFERR_IMPLICIT_ACCESS	BIT_ULL(PFERR_IMPLICIT_ACCESS_BIT)

#define PFERR_NESTED_GUEST_PAGE (PFERR_GUEST_PAGE_MASK |	\
				 PFERR_WRITE_MASK |		\
				 PFERR_PRESENT_MASK)

struct kvm_cpu_context {
	

	u64	spsr_abt;
	u64	spsr_und;
	u64	spsr_irq;
	u64	spsr_fiq;

	

	u64 sys_regs[NR_SYS_REGS];

	struct kvm_vcpu* __hyp_running_vcpu;
};

struct kvm_host_map {
	/*
	 * Only valid if the 'pfn' is managed by the host kernel (i.e. There is
	 * a 'struct page' for it. When using mem= kernel parameter some memory
	 * can be used as guest memory but they are not managed by host
	 * kernel).
	 * If 'pfn' is not managed by the host kernel, this field is
	 * initialized to KVM_UNMAPPED_PAGE.
	 */
	struct page* page;
	void* hva;
	kvm_pfn_t pfn;
	kvm_pfn_t gfn;
};

enum pmc_type {
	KVM_PMC_GP = 0,
	KVM_PMC_FIXED,
};



#define PT64_ROOT_MAX_LEVEL 5

struct rsvd_bits_validate {
	u64 rsvd_bits_mask[2][PT64_ROOT_MAX_LEVEL];
	u64 bad_mt_xwr;
};


/*
 * kvm_mmu_extended_role complements kvm_mmu_page_role, tracking properties
 * relevant to the current MMU configuration.   When loading CR0, CR4, or EFER,
 * including on nested transitions, if nothing in the full role changes then
 * MMU re-configuration can be skipped. @valid bit is set on first usage so we
 * don't treat all-zero structure as valid data.
 *
 * The properties that are tracked in the extended role but not the page role
 * are for things that either (a) do not affect the validity of the shadow page
 * or (b) are indirectly reflected in the shadow page's role.  For example,
 * CR4.PKE only affects permission checks for software walks of the guest page
 * tables (because KVM doesn't support Protection Keys with shadow paging), and
 * CR0.PG, CR4.PAE, and CR4.PSE are indirectly reflected in role.level.
 *
 * Note, SMEP and SMAP are not redundant with sm*p_andnot_wp in the page role.
 * If CR0.WP=1, KVM can reuse shadow pages for the guest regardless of SMEP and
 * SMAP, but the MMU's permission checks for software walks need to be SMEP and
 * SMAP aware regardless of CR0.WP.
 */
union kvm_mmu_extended_role {
	u32 word;
	struct {
		unsigned int valid : 1;
		unsigned int execonly : 1;
		unsigned int cr4_pse : 1;
		unsigned int cr4_pke : 1;
		unsigned int cr4_smap : 1;
		unsigned int cr4_smep : 1;
		unsigned int cr4_la57 : 1;
		unsigned int efer_lma : 1;
	};
};

#define KVM_MMU_NUM_PREV_ROOTS 3
#define KVM_MMU_ROOT_INFO_INVALID \
	((struct kvm_mmu_root_info) { .pgd = INVALID_PAGE, .hpa = INVALID_PAGE })

/*
 * kvm_mmu_page_role tracks the properties of a shadow page (where shadow page
 * also includes TDP pages) to determine whether or not a page can be used in
 * the given MMU context.  This is a subset of the overall kvm_cpu_role to
 * minimize the size of kvm_memory_slot.arch.gfn_track, i.e. allows allocating
 * 2 bytes per gfn instead of 4 bytes per gfn.
 *
 * Upper-level shadow pages having gptes are tracked for write-protection via
 * gfn_track.  As above, gfn_track is a 16 bit counter, so KVM must not create
 * more than 2^16-1 upper-level shadow pages at a single gfn, otherwise
 * gfn_track will overflow and explosions will ensure.
 *
 * A unique shadow page (SP) for a gfn is created if and only if an existing SP
 * cannot be reused.  The ability to reuse a SP is tracked by its role, which
 * incorporates various mode bits and properties of the SP.  Roughly speaking,
 * the number of unique SPs that can theoretically be created is 2^n, where n
 * is the number of bits that are used to compute the role.
 *
 * But, even though there are 19 bits in the mask below, not all combinations
 * of modes and flags are possible:
 *
 *   - invalid shadow pages are not accounted, so the bits are effectively 18
 *
 *   - quadrant will only be used if has_4_byte_gpte=1 (non-PAE paging);
 *     execonly and ad_disabled are only used for nested EPT which has
 *     has_4_byte_gpte=0.  Therefore, 2 bits are always unused.
 *
 *   - the 4 bits of level are effectively limited to the values 2/3/4/5,
 *     as 4k SPs are not tracked (allowed to go unsync).  In addition non-PAE
 *     paging has exactly one upper level, making level completely redundant
 *     when has_4_byte_gpte=1.
 *
 *   - on top of this, smep_andnot_wp and smap_andnot_wp are only set if
 *     cr0_wp=0, therefore these three bits only give rise to 5 possibilities.
 *
 * Therefore, the maximum number of possible upper-level shadow pages for a
 * single gfn is a bit less than 2^13.
 */
union kvm_mmu_page_role {
	u32 word;
	struct {
		unsigned level : 4;
		unsigned has_4_byte_gpte : 1;
		unsigned quadrant : 2;
		unsigned direct : 1;
		unsigned access : 3;
		unsigned invalid : 1;
		unsigned efer_nx : 1;
		unsigned cr0_wp : 1;
		unsigned smep_andnot_wp : 1;
		unsigned smap_andnot_wp : 1;
		unsigned ad_disabled : 1;
		unsigned guest_mode : 1;
		unsigned passthrough : 1;
		unsigned : 5;

		/*
		 * This is left at the top of the word so that
		 * kvm_memslots_for_spte_role can extract it with a
		 * simple shift.  While there is room, give it a whole
		 * byte so it is also faster to load it from memory.
		 */
		unsigned smm : 8;
	};
};

union kvm_cpu_role {
	u64 as_u64;
	struct {
		union kvm_mmu_page_role base;
		union kvm_mmu_extended_role ext;
	};
};


struct kvm_pmc {
	enum pmc_type type;
	u8 idx;
	bool is_paused;
	bool intr;
	u64 counter;
	u64 prev_counter;
	u64 eventsel;
	struct perf_event* perf_event;
	struct kvm_vcpu* vcpu;
	/*
	 * only for creating or reusing perf_event,
	 * eventsel value for general purpose counters,
	 * ctrl value for fixed counters.
	 */
	u64 current_config;
};

/* More counters may conflict with other existing Architectural MSRs */
#define KVM_INTEL_PMC_MAX_GENERIC	8
#define MSR_ARCH_PERFMON_PERFCTR_MAX	(MSR_ARCH_PERFMON_PERFCTR0 + KVM_INTEL_PMC_MAX_GENERIC - 1)
#define MSR_ARCH_PERFMON_EVENTSEL_MAX	(MSR_ARCH_PERFMON_EVENTSEL0 + KVM_INTEL_PMC_MAX_GENERIC - 1)
#define KVM_PMC_MAX_FIXED	3
#define MSR_ARCH_PERFMON_FIXED_CTR_MAX	(MSR_ARCH_PERFMON_FIXED_CTR0 + KVM_PMC_MAX_FIXED - 1)
#define KVM_AMD_PMC_MAX_GENERIC	6
struct kvm_pmu {
	u8 version;
	unsigned nr_arch_gp_counters;
	unsigned nr_arch_fixed_counters;
	unsigned available_event_types;
	u64 fixed_ctr_ctrl;
	u64 fixed_ctr_ctrl_mask;
	u64 global_ctrl;
	u64 global_status;
	u64 counter_bitmask[2];
	u64 global_ctrl_mask;
	u64 global_ovf_ctrl_mask;
	u64 reserved_bits;
	u64 raw_event_mask;
	struct kvm_pmc gp_counters[KVM_INTEL_PMC_MAX_GENERIC];
	struct kvm_pmc fixed_counters[KVM_PMC_MAX_FIXED];

	/*
	 * Overlay the bitmap with a 64-bit atomic so that all bits can be
	 * set in a single access, e.g. to reprogram all counters when the PMU
	 * filter changes.
	 */


	u64 ds_area;
	u64 pebs_enable;
	u64 pebs_enable_mask;
	u64 pebs_data_cfg;
	u64 pebs_data_cfg_mask;

	/*
	 * If a guest counter is cross-mapped to host counter with different
	 * index, its PEBS capability will be temporarily disabled.
	 *
	 * The user should make sure that this mask is updated
	 * after disabling interrupts and before perf_guest_get_msrs();
	 */
	u64 host_cross_mapped_mask;

	/*
	 * The gate to release perf_events not marked in
	 * pmc_in_use only once in a vcpu time slice.
	 */
	bool need_cleanup;

	/*
	 * The total number of programmed perf_events and it helps to avoid
	 * redundant check before cleanup if guest don't use vPMU at all.
	 */
	u8 event_count;
};

struct kvm_mmu_root_info {
	gpa_t pgd;
	hpa_t hpa;
};

struct kvm_mmu_page {
	/*
	 * Note, "link" through "spt" fit in a single 64 byte cache line on
	 * 64-bit kernels, keep it that way unless there's a reason not to.
	 */


	bool tdp_mmu_page;
	bool unsync;
	u8 mmu_valid_gen;

	/*
	 * The shadow page can't be replaced by an equivalent huge page
	 * because it is being used to map an executable page in the guest
	 * and the NX huge page mitigation is enabled.
	 */
	bool nx_huge_page_disallowed;

	/*
	 * The following two entries are used to key the shadow page in the
	 * hash table.
	 */

	gfn_t gfn;

	u64* spt;

	/*
	 * Stores the result of the guest translation being shadowed by each
	 * SPTE.  KVM shadows two types of guest translations: nGPA -> GPA
	 * (shadow EPT/NPT) and GVA -> GPA (traditional shadow paging). In both
	 * cases the result of the translation is a GPA and a set of access
	 * constraints.
	 *
	 * The GFN is stored in the upper bits (PAGE_SHIFT) and the shadowed
	 * access permissions are stored in the lower bits. Note, for
	 * convenience and uniformity across guests, the access permissions are
	 * stored in KVM format (e.g.  ACC_EXEC_MASK) not the raw guest format.
	 */
	u64* shadowed_translation;

	/* Currently serving as active root */

	unsigned int unsync_children;


	/*
	 * Tracks shadow pages that, if zapped, would allow KVM to create an NX
	 * huge page.  A shadow page will have nx_huge_page_disallowed set but
	 * not be on the list if a huge page is disallowed for other reasons,
	 * e.g. because KVM is shadowing a PTE at the same gfn, the memslot
	 * isn't properly aligned, etc...
	 */

#ifndef AMD64
	 /*
	  * Used out of the mmu-lock to avoid reading spte values while an
	  * update is in progress; see the comments in __get_spte_lockless().
	  */
	int clear_spte_count;
#endif

	/* Number of writes since the last time traversal visited this page.  */
	// atomic_t write_flooding_count;

#ifdef AMD64
	/* Used for freeing the page asynchronously if it is a TDP MMU page. */
	
#endif
};

struct kvm_page_fault {
	/* arguments to kvm_mmu_do_page_fault.  */
	const gpa_t addr;
	const u32 error_code;
	const bool prefetch;

	/* Derived from error_code.  */
	const bool exec;
	const bool write;
	const bool present;
	const bool rsvd;
	const bool user;

	/* Derived from mmu and global state.  */
	const bool is_tdp;
	const bool nx_huge_page_workaround_enabled;

	/*
	 * Whether a >4KB mapping can be created or is forbidden due to NX
	 * hugepages.
	 */
	bool huge_page_disallowed;

	/*
	 * Maximum page size that can be created for this fault; input to
	 * FNAME(fetch), direct_map() and kvm_tdp_mmu_map().
	 */
	u8 max_level;

	/*
	 * Page size that can be created based on the max_level and the
	 * page size used by the host mapping.
	 */
	u8 req_level;

	/*
	 * Page size that will be created based on the req_level and
	 * huge_page_disallowed.
	 */
	u8 goal_level;

	/* Shifted addr, or result of guest page table walk if addr is a gva.  */
	gfn_t gfn;

	/* The memslot containing gfn. May be NULL. */
	struct kvm_memory_slot* slot;

	/* Outputs of kvm_faultin_pfn.  */
	unsigned long mmu_seq;
	// kvm_pfn_t pfn;
	hva_t hva;
	bool map_writable;

	/*
	 * Indicates the guest is trying to write a gfn that contains one or
	 * more of the PTEs used to translate the write itself, i.e. the access
	 * is changing its own translation in the guest page tables.
	 */
	bool write_fault_to_shadow_pgtable;
};

/*
 * x86 supports 4 paging modes (5-level 64-bit, 4-level 64-bit, 3-level 32-bit,
 * and 2-level 32-bit).  The kvm_mmu structure abstracts the details of the
 * current mmu mode.
 */
struct kvm_mmu {
	ULONG_PTR (*get_guest_pgd)(struct kvm_vcpu* vcpu);
	u64(*get_pdptr)(struct kvm_vcpu* vcpu, int index);
	int (*page_fault)(struct kvm_vcpu* vcpu, struct kvm_page_fault* fault);
	void (*inject_page_fault)(struct kvm_vcpu* vcpu,
		struct x86_exception* fault);
	gpa_t(*gva_to_gpa)(struct kvm_vcpu* vcpu, struct kvm_mmu* mmu,
		gpa_t gva_or_gpa, u64 access,
		struct x86_exception* exception);
	int (*sync_spte)(struct kvm_vcpu* vcpu,
		struct kvm_mmu_page* sp, int i);
	struct kvm_mmu_root_info root;
	union kvm_cpu_role cpu_role;
	union kvm_mmu_page_role root_role;

	/*
	* The pkru_mask indicates if protection key checks are needed.  It
	* consists of 16 domains indexed by page fault error code bits [4:1],
	* with PFEC.RSVD replaced by ACC_USER_MASK from the page tables.
	* Each domain has 2 bits which are ANDed with AD and WD from PKRU.
	*/
	u32 pkru_mask;

	struct kvm_mmu_root_info prev_roots[KVM_MMU_NUM_PREV_ROOTS];

	/*
	 * Bitmap; bit set = permission fault
	 * Byte index: page fault error code [4:1]
	 * Bit index: pte permissions in ACC_* format
	 */
	u8 permissions[16];

	u64* pae_root;
	u64* pml4_root;
	u64* pml5_root;

	/*
	 * check zero bits on shadow page table entries, these
	 * bits include not only hardware reserved bits but also
	 * the bits spte never used.
	 */
	struct rsvd_bits_validate shadow_zero_check;

	struct rsvd_bits_validate guest_rsvd_check;

	u64 pdptrs[4]; /* pae */
};

struct kvm_vcpu_stat {
	struct kvm_vcpu_stat_generic generic;
	u64 pf_taken;
	u64 pf_fixed;
	u64 pf_emulate;
	u64 pf_spurious;
	u64 pf_fast;
	u64 pf_mmio_spte_created;
	u64 pf_guest;
	u64 tlb_flush;
	u64 invlpg;

	u64 exits;
	u64 io_exits;
	u64 mmio_exits;
	u64 signal_exits;
	u64 irq_window_exits;
	u64 nmi_window_exits;
	u64 l1d_flush;
	u64 halt_exits;
	u64 request_irq_exits;
	u64 irq_exits;
	u64 host_state_reload;
	u64 fpu_reload;
	u64 insn_emulation;
	u64 insn_emulation_fail;
	u64 hypercalls;
	u64 irq_injections;
	u64 nmi_injections;
	u64 req_event;
	u64 nested_run;
	u64 directed_yield_attempted;
	u64 directed_yield_successful;
	u64 preemption_reported;
	u64 preemption_other;
	u64 guest_mode;
	u64 notify_window_exits;
};

struct kvm_memslots {
	u64 generation;


	/*
	 * The mapping table from slot id to memslot.
	 *
	 * 7-bit bucket count matches the size of the old id to index array for
	 * 512 slots, while giving good performance with this slot count.
	 * Higher bucket counts bring only small performance improvements but
	 * always result in higher memory usage (even for lower memslot counts).
	 */

	int node_idx;
};

struct kvm_rmap_head {
	unsigned long val;
};

struct kvm_lpage_info {
	int disallow_lpage;
};

struct kvm_arch_memory_slot {
	struct kvm_rmap_head* rmap[KVM_NR_PAGE_SIZES];
	struct kvm_lpage_info* lpage_info[KVM_NR_PAGE_SIZES - 1];
	unsigned short* gfn_track[KVM_PAGE_TRACK_MAX];
};

#ifndef KVM_INTERNAL_MEM_SLOTS
#define KVM_INTERNAL_MEM_SLOTS 0
#endif
#define KVM_MEM_SLOTS_NUM SHRT_MAX
#define KVM_USER_MEM_SLOTS (KVM_MEM_SLOTS_NUM - KVM_INTERNAL_MEM_SLOTS)
/*
 * Since at idle each memslot belongs to two memslot sets it has to contain
 * two embedded nodes for each data structure that it forms a part of.
 *
 * Two memslot sets (one active and one inactive) are necessary so the VM
 * continues to run on one memslot set while the other is being modified.
 *
 * These two memslot sets normally point to the same set of memslots.
 * They can, however, be desynchronized when performing a memslot management
 * operation by replacing the memslot to be modified by its copy.
 * After the operation is complete, both memslot sets once again point to
 * the same, common set of memslot data.
 *
 * The memslots themselves are independent of each other so they can be
 * individually added or deleted.
 */
struct kvm_memory_slot {
	gfn_t base_gfn;
	unsigned long npages;
	unsigned long* dirty_bitmap;
	struct kvm_arch_memory_slot arch;
	unsigned long userspace_addr;
	u32 flags;
	short id;
	u16 as_id;
};

struct kvm_mtrr_range {
	u64 base;
	u64 mask;
	LIST_ENTRY node;
};

struct kvm_mtrr {
	struct kvm_mtrr_range var_ranges[KVM_NR_VAR_MTRR];
	mtrr_type fixed_ranges[KVM_NR_FIXED_MTRR_REGION];
	u64 deftype;

	LIST_ENTRY head;
};

struct kvm_vcpu_arch {
	/*
	 * rip and regs accesses must go through
	 * kvm_{register,rip}_{read,write} functions.
	 */
	ULONG_PTR regs[NR_VCPU_REGS];
	u32 regs_avail;
	u32 regs_dirty;
	// 类似这些寄存器就是用来缓存真正的cpu值的
	ULONG_PTR cr0;
	ULONG_PTR cr0_guest_owned_bits;
	ULONG_PTR cr2;
	ULONG_PTR cr3;
	ULONG_PTR cr4;
	ULONG_PTR cr4_guest_owned_bits;
	ULONG_PTR cr4_guest_rsvd_bits;
	ULONG_PTR cr8;
	u32 host_pkru;
	u32 pkru;
	u32 hflags;
	u64 efer;
	u64 apic_base;
	struct kvm_lapic* apic;    /* kernel irqchip context */
	bool load_eoi_exitmap_pending;

	unsigned long apic_attention;

	int mp_state;
	u64 ia32_misc_enable_msr;
	u64 smbase;
	u64 smi_count;
	bool at_instruction_boundary;
	bool tpr_access_reporting;
	bool xsaves_enabled;
	bool xfd_no_write_intercept;
	u64 ia32_xss;
	u64 microcode_version;
	u64 arch_capabilities;
	u64 perf_capabilities;

	/*
	 * Paging state of the vcpu
	 *
	 * If the vcpu runs in guest mode with two level paging this still saves
	 * the paging mode of the l1 guest. This context is always used to
	 * handle faults.
	 */
	// 内存管理直接操作函数
	struct kvm_mmu* mmu;

	/* Non-nested MMU for L1 */
	// 非嵌套情况下的虚拟机mmu
	struct kvm_mmu root_mmu;

	/* L1 MMU when running nested */
	// 嵌套情况下的L1的mmu
	struct kvm_mmu guest_mmu;

	/*
	 * Paging state of an L2 guest (used for nested npt)
	 *
	 * This context will save all necessary information to walk page tables
	 * of an L2 guest. This context is only initialized for page table
	 * walking and not for faulting since we never handle l2 page faults on
	 * the host.
	 */
	struct kvm_mmu nested_mmu;

	/*
	 * Pointer to the mmu context currently used for
	 * gva_to_gpa translations.
	 */
	// 用于GVA转换成GPA
	struct kvm_mmu* walk_mmu;



	/*
	 * QEMU userspace and the guest each have their own FPU state.
	 * In vcpu_run, we switch between the user and guest FPU contexts.
	 * While running a VCPU, the VCPU thread will have the guest FPU
	 * context.
	 *
	 * Note that while the PKRU state lives inside the fpu registers,
	 * it is switched out separately at VMENTER and VMEXIT time. The
	 * "guest_fpstate" state here contains the guest FPU context, with the
	 * host PRKU bits.
	 */


	u64 xcr0;
	u64 guest_supported_xcr0;


	void* pio_data;
	void* sev_pio_data;
	unsigned sev_pio_count;

	u8 event_exit_inst_len;

	bool exception_from_userspace;

	/* Exceptions to be injected to the guest. */

	/* Exception VM-Exits to be synthesized to L1. */


	struct kvm_queued_interrupt {
		bool injected;
		bool soft;
		u8 nr;
	} interrupt;

	int halt_request; /* real mode on Intel only */

	int cpuid_nent;
	struct kvm_cpuid_entry2* cpuid_entries;


	u64 reserved_gpa_bits;
	int maxphyaddr;

	/* emulate context */
	// KVM的软件模拟模式，也就是没有vmx的情况
	struct x86_emulate_ctxt* emulate_ctxt;
	bool emulate_regs_need_sync_to_vcpu;
	bool emulate_regs_need_sync_from_vcpu;
	int (*complete_userspace_io)(struct kvm_vcpu* vcpu);

	gpa_t time;

	unsigned int hw_tsc_khz;

	/* set guest stopped flag in pvclock flags field */
	bool pvclock_set_guest_stopped_request;

	struct {
		u8 preempted;
		u64 msr_val;
		u64 last_steal;

	} st;

	u64 l1_tsc_offset;
	u64 tsc_offset; /* current tsc offset */
	u64 last_guest_tsc;
	u64 last_host_tsc;
	u64 tsc_offset_adjustment;
	u64 this_tsc_nsec;
	u64 this_tsc_write;
	u64 this_tsc_generation;
	bool tsc_catchup;
	bool tsc_always_catchup;
	s8 virtual_tsc_shift;
	u32 virtual_tsc_mult;
	u32 virtual_tsc_khz;
	s64 ia32_tsc_adjust_msr;
	u64 msr_ia32_power_ctl;
	u64 l1_tsc_scaling_ratio;
	u64 tsc_scaling_ratio; /* current scaling ratio */


	/* Number of NMIs pending injection, not including hardware vNMIs. */
	unsigned int nmi_pending;
	bool nmi_injected;    /* Trying to inject an NMI this entry */
	bool smi_pending;    /* SMI queued after currently running handler */
	u8 handling_intr_from_guest;

	struct kvm_mtrr mtrr_state;
	u64 pat;

	unsigned switch_db_regs;
	unsigned long db[KVM_NR_DB_REGS];
	unsigned long dr6;
	unsigned long dr7;
	unsigned long eff_db[KVM_NR_DB_REGS];
	unsigned long guest_debug_dr7;
	u64 msr_platform_info;
	u64 msr_misc_features_enables;

	u64 mcg_cap;
	u64 mcg_status;
	u64 mcg_ctl;
	u64 mcg_ext_ctl;
	u64* mce_banks;
	u64* mci_ctl2_banks;

	/* Cache MMIO info */
	u64 mmio_gva;
	unsigned mmio_access;
	gfn_t mmio_gfn;
	u64 mmio_gen;

	struct kvm_pmu pmu;

	/* used for guest single stepping over the given code position */
	unsigned long singlestep_rip;

	bool hyperv_enabled;
	struct kvm_vcpu_hv* hyperv;




	unsigned long last_retry_eip;
	unsigned long last_retry_addr;

	struct {
		bool halted;

		u64 msr_en_val; /* MSR_KVM_ASYNC_PF_EN */
		u64 msr_int_val; /* MSR_KVM_ASYNC_PF_INT */
		u16 vec;
		u32 id;
		bool send_user_only;
		u32 host_apf_flags;
		bool delivery_as_pf_vmexit;
		bool pageready_pending;
	} apf;// async page fault

	/* OSVW MSRs (AMD only) */
	struct {
		u64 length;
		u64 status;
	} osvw;



	u64 msr_kvm_poll_control;

	/* set at EPT violation at this point */
	unsigned long exit_qualification;

	/* pv related host specific info */
	// 不支持vmx下的模拟虚拟化
	struct {
		bool pv_unhalted;
	} pv;

	int pending_ioapic_eoi;
	int pending_external_vector;

	/* be preempted when it's in kernel-mode(cpl=0) */
	bool preempted_in_kernel;

	/* Flush the L1 Data cache for L1TF mitigation on VMENTER */
	bool l1tf_flush_l1d;

	/* Host CPU on which VM-entry was most recently attempted */
	int last_vmentry_cpu;

	/* AMD MSRC001_0015 Hardware Configuration */
	u64 msr_hwcr;

	/* pv related cpuid info */
	struct {
		/*
		 * value of the eax register in the KVM_CPUID_FEATURES CPUID
		 * leaf.
		 */
		u32 features;

		/*
		 * indicates whether pv emulation should be disabled if features
		 * are not present in the guest's cpuid
		 */
		bool enforce;
	} pv_cpuid;

	/* Protected Guests */
	bool guest_state_protected;

	/*
	 * Set when PDPTS were loaded directly by the userspace without
	 * reading the guest memory
	 */
	bool pdptrs_from_userspace;
};

void vcpu_put(struct kvm_vcpu* vcpu);


static inline
struct kvm_memory_slot* id_to_memslot(struct kvm_memslots* slots, int id)
{
	UNREFERENCED_PARAMETER(slots);
	UNREFERENCED_PARAMETER(id);


	return NULL;
}

struct kvm_vcpu {
	// 指向vcpu所属的虚拟机对应的kvm结构
	struct kvm* kvm;

	int cpu;
	// 用于唯一标识该vcpu
	int vcpu_id; /* id given by userspace at creation */
	int vcpu_idx; /* index into kvm->vcpu_array */
	int ____srcu_idx; /* Don't use this directly.  You've been warned. */

	int mode;
	u64 requests;
	unsigned long guest_debug;

	KMUTEX mutex;

	// 执行虚拟机对应的kvm_run结构，运行时的状态
	struct kvm_run* run;

	ULONG pid;

	int sigset_active;

	unsigned int halt_poll_ns;
	bool valid_wakeup;


	bool preempted;
	bool ready;
	// 架构相关部分
	struct kvm_vcpu_arch arch;
	// vcpu状态信息
	struct kvm_vcpu_stat stat;
	char stats_id[KVM_STATS_NAME_SIZE];

	/*
	 * The most recently used memslot by this vCPU and the slots generation
	 * for which it is valid.
	 * No wraparound protection is needed since generations won't overflow in
	 * thousands of years, even assuming 1M memslot operations per second.
	 */
	struct kvm_memory_slot* last_used_slot;
	u64 last_used_slot_gen;
};

enum {
	KVM_DEBUGREG_BP_ENABLED = 1,
	KVM_DEBUGREG_WONT_EXIT = 2,
};

// 针对不同硬件架构
struct kvm_x86_ops {
	const char* name;

	NTSTATUS (*check_processor_compatibility)(void);

	int (*hardware_enable)(void);
	void (*hardware_disable)(void);
	void (*hardware_unsetup)(void);
	bool (*has_emulated_msr)(struct kvm* kvm, u32 index);
	void (*vcpu_after_set_cpuid)(struct kvm_vcpu* vcpu);

	unsigned int vm_size;
	int (*vm_init)(struct kvm* kvm);
	void (*vm_destroy)(struct kvm* kvm);

	/* Create, but do not attach this VCPU */
	int (*vcpu_precreate)(struct kvm* kvm);
	NTSTATUS (*vcpu_create)(struct kvm_vcpu* vcpu);
	void (*vcpu_free)(struct kvm_vcpu* vcpu);
	void (*vcpu_reset)(struct kvm_vcpu* vcpu, bool init_event);

	void (*prepare_switch_to_guest)(struct kvm_vcpu* vcpu);
	void (*vcpu_load)(struct kvm_vcpu* vcpu, int cpu);
	void (*vcpu_put)(struct kvm_vcpu* vcpu);

	void (*update_exception_bitmap)(struct kvm_vcpu* vcpu);
	int (*get_msr)(struct kvm_vcpu* vcpu, struct msr_data* msr);
	int (*set_msr)(struct kvm_vcpu* vcpu, struct msr_data* msr);
	u64(*get_segment_base)(struct kvm_vcpu* vcpu, int seg);
	void (*get_segment)(struct kvm_vcpu* vcpu,
		struct kvm_segment* var, int seg);
	int (*get_cpl)(struct kvm_vcpu* vcpu);
	void (*set_segment)(struct kvm_vcpu* vcpu,
		struct kvm_segment* var, int seg);
	void (*get_cs_db_l_bits)(struct kvm_vcpu* vcpu, int* db, int* l);
	void (*set_cr0)(struct kvm_vcpu* vcpu, ULONG_PTR cr0);
	void (*post_set_cr3)(struct kvm_vcpu* vcpu, ULONG_PTR cr3);
	bool (*is_valid_cr4)(struct kvm_vcpu* vcpu, ULONG_PTR cr0);
	void (*set_cr4)(struct kvm_vcpu* vcpu, ULONG_PTR cr4);
	int (*set_efer)(struct kvm_vcpu* vcpu, u64 efer);
	void (*get_idt)(struct kvm_vcpu* vcpu, struct desc_ptr* dt);
	void (*set_idt)(struct kvm_vcpu* vcpu, struct desc_ptr* dt);
	void (*get_gdt)(struct kvm_vcpu* vcpu, struct desc_ptr* dt);
	void (*set_gdt)(struct kvm_vcpu* vcpu, struct desc_ptr* dt);
	void (*sync_dirty_debug_regs)(struct kvm_vcpu* vcpu);
	void (*set_dr7)(struct kvm_vcpu* vcpu, ULONG_PTR value);
	void (*cache_reg)(struct kvm_vcpu* vcpu, enum kvm_reg reg);
	ULONG_PTR(*get_rflags)(struct kvm_vcpu* vcpu);
	void (*set_rflags)(struct kvm_vcpu* vcpu, ULONG_PTR rflags);
	bool (*get_if_flag)(struct kvm_vcpu* vcpu);

	void (*flush_tlb_all)(struct kvm_vcpu* vcpu);
	void (*flush_tlb_current)(struct kvm_vcpu* vcpu);
	int  (*flush_remote_tlbs)(struct kvm* kvm);
	int  (*flush_remote_tlbs_range)(struct kvm* kvm, gfn_t gfn,
		gfn_t nr_pages);

	/*
	 * Flush any TLB entries associated with the given GVA.
	 * Does not need to flush GPA->HPA mappings.
	 * Can potentially get non-canonical addresses through INVLPGs, which
	 * the implementation may choose to ignore if appropriate.
	 */
	void (*flush_tlb_gva)(struct kvm_vcpu* vcpu, gva_t addr);

	/*
	 * Flush any TLB entries created by the guest.  Like tlb_flush_gva(),
	 * does not need to flush GPA->HPA mappings.
	 */
	void (*flush_tlb_guest)(struct kvm_vcpu* vcpu);

	int (*vcpu_pre_run)(struct kvm_vcpu* vcpu);
	enum exit_fastpath_completion(*vcpu_run)(struct kvm_vcpu* vcpu);
	int (*handle_exit)(struct kvm_vcpu* vcpu,
		enum exit_fastpath_completion exit_fastpath);
	int (*skip_emulated_instruction)(struct kvm_vcpu* vcpu);
	void (*update_emulated_instruction)(struct kvm_vcpu* vcpu);
	void (*set_interrupt_shadow)(struct kvm_vcpu* vcpu, int mask);
	u32(*get_interrupt_shadow)(struct kvm_vcpu* vcpu);
	void (*patch_hypercall)(struct kvm_vcpu* vcpu,
		unsigned char* hypercall_addr);
	void (*inject_irq)(struct kvm_vcpu* vcpu, bool reinjected);
	void (*inject_nmi)(struct kvm_vcpu* vcpu);
	void (*inject_exception)(struct kvm_vcpu* vcpu);
	void (*cancel_injection)(struct kvm_vcpu* vcpu);
	int (*interrupt_allowed)(struct kvm_vcpu* vcpu, bool for_injection);
	int (*nmi_allowed)(struct kvm_vcpu* vcpu, bool for_injection);
	bool (*get_nmi_mask)(struct kvm_vcpu* vcpu);
	void (*set_nmi_mask)(struct kvm_vcpu* vcpu, bool masked);
	/* Whether or not a virtual NMI is pending in hardware. */
	bool (*is_vnmi_pending)(struct kvm_vcpu* vcpu);
	/*
	 * Attempt to pend a virtual NMI in harware.  Returns %true on success
	 * to allow using static_call_ret0 as the fallback.
	 */
	bool (*set_vnmi_pending)(struct kvm_vcpu* vcpu);
	void (*enable_nmi_window)(struct kvm_vcpu* vcpu);
	void (*enable_irq_window)(struct kvm_vcpu* vcpu);
	void (*update_cr8_intercept)(struct kvm_vcpu* vcpu, int tpr, int irr);
	//bool (*check_apicv_inhibit_reasons)(enum kvm_apicv_inhibit reason);
	const ULONG_PTR required_apicv_inhibits;
	bool allow_apicv_in_x2apic_without_x2apic_virtualization;
	void (*refresh_apicv_exec_ctrl)(struct kvm_vcpu* vcpu);
	void (*hwapic_irr_update)(struct kvm_vcpu* vcpu, int max_irr);
	void (*hwapic_isr_update)(int isr);
	bool (*guest_apic_has_interrupt)(struct kvm_vcpu* vcpu);
	void (*load_eoi_exitmap)(struct kvm_vcpu* vcpu, u64* eoi_exit_bitmap);
	void (*set_virtual_apic_mode)(struct kvm_vcpu* vcpu);
	void (*set_apic_access_page_addr)(struct kvm_vcpu* vcpu);
	void (*deliver_interrupt)(struct kvm_lapic* apic, int delivery_mode,
		int trig_mode, int vector);
	int (*sync_pir_to_irr)(struct kvm_vcpu* vcpu);
	int (*set_tss_addr)(struct kvm* kvm, unsigned int addr);
	int (*set_identity_map_addr)(struct kvm* kvm, u64 ident_addr);
	u8(*get_mt_mask)(struct kvm_vcpu* vcpu, gfn_t gfn, bool is_mmio);

	void (*load_mmu_pgd)(struct kvm_vcpu* vcpu, hpa_t root_hpa,
		int root_level);

	bool (*has_wbinvd_exit)(void);

	u64(*get_l2_tsc_offset)(struct kvm_vcpu* vcpu);
	u64(*get_l2_tsc_multiplier)(struct kvm_vcpu* vcpu);
	void (*write_tsc_offset)(struct kvm_vcpu* vcpu, u64 offset);
	void (*write_tsc_multiplier)(struct kvm_vcpu* vcpu, u64 multiplier);

	/*
	 * Retrieve somewhat arbitrary exit information.  Intended to
	 * be used only from within tracepoints or error paths.
	 */
	void (*get_exit_info)(struct kvm_vcpu* vcpu, u32* reason,
		u64* info1, u64* info2,
		u32* exit_int_info, u32* exit_int_info_err_code);

	int (*check_intercept)(struct kvm_vcpu* vcpu,
		struct x86_instruction_info* info,
		enum x86_intercept_stage stage,
		struct x86_exception* exception);
	void (*handle_exit_irqoff)(struct kvm_vcpu* vcpu);

	void (*request_immediate_exit)(struct kvm_vcpu* vcpu);

	void (*sched_in)(struct kvm_vcpu* kvm, int cpu);

	/*
	 * Size of the CPU's dirty log buffer, i.e. VMX's PML buffer.  A zero
	 * value indicates CPU dirty logging is unsupported or disabled.
	 */
	int cpu_dirty_log_size;
	void (*update_cpu_dirty_logging)(struct kvm_vcpu* vcpu);

	const struct kvm_x86_nested_ops* nested_ops;

	void (*vcpu_blocking)(struct kvm_vcpu* vcpu);
	void (*vcpu_unblocking)(struct kvm_vcpu* vcpu);

	int (*pi_update_irte)(struct kvm* kvm, unsigned int host_irq,
		uint32_t guest_irq, bool set);
	void (*pi_start_assignment)(struct kvm* kvm);
	void (*apicv_post_state_restore)(struct kvm_vcpu* vcpu);
	bool (*dy_apicv_has_pending_interrupt)(struct kvm_vcpu* vcpu);

	int (*set_hv_timer)(struct kvm_vcpu* vcpu, u64 guest_deadline_tsc,
		bool* expired);
	void (*cancel_hv_timer)(struct kvm_vcpu* vcpu);

	void (*setup_mce)(struct kvm_vcpu* vcpu);

#ifdef CONFIG_KVM_SMM
	int (*smi_allowed)(struct kvm_vcpu* vcpu, bool for_injection);
	int (*enter_smm)(struct kvm_vcpu* vcpu, union kvm_smram* smram);
	int (*leave_smm)(struct kvm_vcpu* vcpu, const union kvm_smram* smram);
	void (*enable_smi_window)(struct kvm_vcpu* vcpu);
#endif

	//int (*mem_enc_register_region)(struct kvm* kvm, struct kvm_enc_region* argp);
	//int (*mem_enc_unregister_region)(struct kvm* kvm, struct kvm_enc_region* argp);
	int (*vm_copy_enc_context_from)(struct kvm* kvm, unsigned int source_fd);
	int (*vm_move_enc_context_from)(struct kvm* kvm, unsigned int source_fd);
	void (*guest_memory_reclaimed)(struct kvm* kvm);

	int (*get_msr_feature)(struct kvm_msr_entry* entry);

	bool (*can_emulate_instruction)(struct kvm_vcpu* vcpu, int emul_type,
		void* insn, int insn_len);

	bool (*apic_init_signal_blocked)(struct kvm_vcpu* vcpu);
	int (*enable_l2_tlb_flush)(struct kvm_vcpu* vcpu);

	void (*migrate_timers)(struct kvm_vcpu* vcpu);
	void (*msr_filter_changed)(struct kvm_vcpu* vcpu);
	int (*complete_emulated_msr)(struct kvm_vcpu* vcpu, int err);

	void (*vcpu_deliver_sipi_vector)(struct kvm_vcpu* vcpu, u8 vector);

	/*
	 * Returns vCPU specific APICv inhibit reasons
	 */
	ULONG_PTR (*vcpu_get_apicv_inhibit_reasons)(struct kvm_vcpu* vcpu);
};

enum kvm_mr_change {
	KVM_MR_CREATE,
	KVM_MR_DELETE,
	KVM_MR_MOVE,
	KVM_MR_FLAGS_ONLY,
};

void kvm_arch_memslots_updated(struct kvm* kvm, u64 gen);
int kvm_arch_prepare_memory_region(struct kvm* kvm,
	const struct kvm_memory_slot* old,
	struct kvm_memory_slot* new,
	enum kvm_mr_change change);
void kvm_arch_commit_memory_region(struct kvm* kvm,
	struct kvm_memory_slot* old,
	const struct kvm_memory_slot* new,
	enum kvm_mr_change change);

int kvm_set_memory_region(struct kvm* kvm,
	const struct kvm_userspace_memory_region* mem);
int __kvm_set_memory_region(struct kvm* kvm,
	const struct kvm_userspace_memory_region* mem);
struct kvm_arch {
	unsigned long n_used_mmu_pages;
	unsigned long n_requested_mmu_pages;
	unsigned long n_max_mmu_pages;
	unsigned int indirect_shadow_pages;
	u8 mmu_valid_gen;

	/*
	 * A list of kvm_mmu_page structs that, if zapped, could possibly be
	 * replaced by an NX huge page.  A shadow page is on this list if its
	 * existence disallows an NX huge page (nx_huge_page_disallowed is set)
	 * and there are no other conditions that prevent a huge page, e.g.
	 * the backing host page is huge, dirtly logging is not enabled for its
	 * memslot, etc...  Note, zapping shadow pages on this list doesn't
	 * guarantee an NX huge page will be created in its stead, e.g. if the
	 * guest attempts to execute from the region then KVM obviously can't
	 * create an NX huge page (without hanging the guest).
	 */

	/*
	 * Protects marking pages unsync during page faults, as TDP MMU page
	 * faults only take mmu_lock for read.  For simplicity, the unsync
	 * pages lock is always taken when marking pages unsync regardless of
	 * whether mmu_lock is held for read or write.
	 */



	bool iommu_noncoherent;


	struct kvm_pic* vpic;
	struct kvm_ioapic* vioapic;
	struct kvm_pit* vpit;





	bool apic_access_memslot_enabled;
	bool apic_access_memslot_inhibited;

	/* Protects apicv_inhibit_reasons */

	unsigned long apicv_inhibit_reasons;

	gpa_t wall_clock;

	bool mwait_in_guest;
	bool hlt_in_guest;
	bool pause_in_guest;
	bool cstate_in_guest;

	unsigned long irq_sources_bitmap;
	s64 kvmclock_offset;

	/*
	 * This also protects nr_vcpus_matched_tsc which is read from a
	 * preemption-disabled region, so it must be a raw spinlock.
	 */

	u64 last_tsc_nsec;
	u64 last_tsc_write;
	u32 last_tsc_khz;
	u64 last_tsc_offset;
	u64 cur_tsc_nsec;
	u64 cur_tsc_write;
	u64 cur_tsc_offset;
	u64 cur_tsc_generation;
	int nr_vcpus_matched_tsc;

	u32 default_tsc_khz;


	bool use_master_clock;
	u64 master_kernel_ns;
	u64 master_cycle_now;


	/* reads protected by irq_srcu, writes by irq_lock */




	bool backwards_tsc_observed;
	bool boot_vcpu_runs_old_kvmclock;
	u32 bsp_vcpu_id;

	u64 disabled_quirks;


	u8 nr_reserved_ioapic_pins;

	bool disabled_lapic_found;

	bool x2apic_format;
	bool x2apic_broadcast_quirk_disabled;

	bool guest_can_read_msr_platform_info;
	bool exception_payload_enabled;

	bool triple_fault_event;

	bool bus_lock_detection_enabled;
	bool enable_pmu;

	u32 notify_window;
	u32 notify_vmexit_flags;
	/*
	 * If exit_on_emulation_error is set, and the in-kernel instruction
	 * emulator fails to emulate an instruction, allow userspace
	 * the opportunity to look at it.
	 */
	bool exit_on_emulation_error;

	/* Deflect RDMSR and WRMSR to user space when they trigger a #GP */
	u32 user_space_msr_mask;


	u32 hypercall_exit_enabled;

	/* Guest can access the SGX PROVISIONKEY. */
	bool sgx_provisioning_allowed;




#ifdef _WIN64
	/* The number of TDP MMU pages across all roots. */


	/*
	 * List of struct kvm_mmu_pages being used as roots.
	 * All struct kvm_mmu_pages in the list should have
	 * tdp_mmu_page set.
	 *
	 * For reads, this list is protected by:
	 *	the MMU lock in read mode + RCU or
	 *	the MMU lock in write mode
	 *
	 * For writes, this list is protected by:
	 *	the MMU lock in read mode + the tdp_mmu_pages_lock or
	 *	the MMU lock in write mode
	 *
	 * Roots will remain in the list until their tdp_mmu_root_count
	 * drops to zero, at which point the thread that decremented the
	 * count to zero should removed the root from the list and clean
	 * it up, freeing the root after an RCU grace period.
	 */


	/*
	 * Protects accesses to the following fields when the MMU lock
	 * is held in read mode:
	 *  - tdp_mmu_roots (above)
	 *  - the link field of kvm_mmu_page structs used by the TDP MMU
	 *  - possible_nx_huge_pages;
	 *  - the possible_nx_huge_page_link field of kvm_mmu_page structs used
	 *    by the TDP MMU
	 * It is acceptable, but not necessary, to acquire this lock when
	 * the thread holds the MMU lock in write mode.
	 */

#endif /* CONFIG_X86_64 */

	/*
	 * If set, at least one shadow root has been allocated. This flag
	 * is used as one input when determining whether certain memslot
	 * related allocations are necessary.
	 */
	bool shadow_root_allocated;


	/*
	 * VM-scope maximum vCPU ID. Used to determine the size of structures
	 * that increase along with the maximum vCPU ID, in which case, using
	 * the global KVM_MAX_VCPU_IDS may lead to significant memory waste.
	 */
	u32 max_vcpu_ids;

	bool disable_nx_huge_pages;

	/*
	 * Memory caches used to allocate shadow pages when performing eager
	 * page splitting. No need for a shadowed_info_cache since eager page
	 * splitting only allocates direct shadow pages.
	 *
	 * Protected by kvm->slots_lock.
	 */


	/*
	 * Memory cache used to allocate pte_list_desc structs while splitting
	 * huge pages. In the worst case, to split one huge page, 512
	 * pte_list_desc structs are needed to add each lower level leaf sptep
	 * to the rmap plus 1 to extend the parent_ptes rmap of the lower level
	 * page table.
	 *
	 * Protected by kvm->slots_lock.
	 */

};

struct kvm {
	ERESOURCE mmu_lock;

	// 内存槽操作锁
	KMUTEX slots_loc;
	/*
	 * Protects the arch-specific fields of struct kvm_memory_slots in
	 * use by the VM. To be used under the slots_lock (above) or in a
	 * kvm->srcu critical section where acquiring the slots_lock would
	 * lead to deadlock with the synchronize_srcu in
	 * kvm_swap_active_memslots().
	 */
	KMUTEX slots_arch_lock;

	unsigned long nr_memslot_pages;
	/* The two memslot sets - active and inactive (per address space) */
	struct kvm_memslots __memslots[KVM_ADDRESS_SPACE_NUM][2];
	/* The current active memslot set for each address space */
	struct kvm_memslots* memslots[KVM_ADDRESS_SPACE_NUM];/* 模拟的内存条模型 */
	struct kvm_vcpu** vcpu_array;
	/*
	 * Protected by slots_lock, but can be read outside if an
	 * incorrect answer is acceptable.
	 */


	 /* Used to wait for completion of MMU notifiers.  */

	unsigned long mn_active_invalidate_count;


	/* For management / invalidation of gfn_to_pfn_caches */


	/*
	 * created_vcpus is protected by kvm->lock, and is incremented
	 * at the beginning of KVM_CREATE_VCPU.  online_vcpus is only
	 * incremented after storing the kvm_vcpu pointer in vcpus,
	 * and is accessed atomically.
	 */

	// host上vm管理链表
	LIST_ENTRY vm_list;

	int max_vcpus;
	int created_vcpus;
	int last_boosted_vcpu;

	KMUTEX lock;

	// host arch 的一些参数
	struct kvm_arch arch;
	struct kvm_vcpu_stat stat;
	char stats_id[KVM_STATS_NAME_SIZE];


	KMUTEX irq_lock;





	u64 manual_dirty_log_protect;
	struct dentry* debugfs_dentry;
	struct kvm_stat_data** debugfs_stat_data;


	bool override_halt_poll_ns;
	unsigned int max_halt_poll_ns;
	u32 dirty_ring_size;
	bool dirty_ring_with_bitmap;
	bool vm_bugged;
	bool vm_dead;


};



struct kvm_x86_init_ops {
	NTSTATUS (*hardware_setup)();
	unsigned int (*handle_intel_pt_intr)(void);

	struct kvm_x86_ops* runtime_ops;
	struct kvm_pmu_ops* pmu_ops;
};

extern struct kvm_x86_ops kvm_x86_ops;

int kvm_init(unsigned vcpu_size, unsigned vcpu_align);
void kvm_exit(void);

int kvm_arch_hardware_enable(void);

void kvm_get_cs_db_l_bits(struct kvm_vcpu* vcpu, int* db, int* l);



NTSTATUS kvm_mmu_module_init();


void kvm_arch_check_processor_compat();

void kvm_enable_efer_bits(u64);

void kvm_mmu_set_nonpresent_ptes(u64 trap_pte, u64 notrap_pte);
void kvm_mmu_set_base_ptes(u64 base_pte);
void kvm_mmu_set_mask_ptes(u64 user_mask, u64 accessed_mask,
	u64 dirty_mask, u64 nx_mask, u64 x_mask);

void kvm_disable_largepages();

void kvm_enable_tdp();
void kvm_disable_tdp();
NTSTATUS kvm_x86_vendor_init(struct kvm_x86_init_ops* ops);
void kvm_x86_vendor_exit(void);

static struct kvm* kvm_arch_alloc_vm(void) {
	struct kvm* kvm = ExAllocatePoolWithTag(NonPagedPool, kvm_x86_ops.vm_size, DRIVER_TAG);
	if (kvm != NULL) {
		RtlZeroMemory(kvm, kvm_x86_ops.vm_size);
	}
	return kvm;
}

void kvm_arch_hardware_disable(void);
void kvm_put_kvm(struct kvm* kvm);
int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu* vcpu);
int kvm_arch_vcpu_create(struct kvm_vcpu* vcpu);

void vcpu_load(struct kvm_vcpu* vcpu);
void kvm_arch_vcpu_load(struct kvm_vcpu* vcpu, int cpu);

#define HF_GUEST_MASK		(1 << 0) /* VCPU is in guest-mode */

int kvm_set_cr0(struct kvm_vcpu* vcpu, ULONG_PTR cr0);
int kvm_set_cr4(struct kvm_vcpu* vcpu, ULONG_PTR cr4);

void kvm_lmsw(struct kvm_vcpu* vcpu, ULONG_PTR msw);

static inline bool kvm_request_pending(struct kvm_vcpu* vcpu)
{
	return vcpu->requests;
}

void kvm_vcpu_reset(struct kvm_vcpu* vcpu, bool init_event);

// mmu 相关硬件判断和全局变量
void kvm_configure_mmu(bool enable_tdp, int tdp_forced_root_level,
	int tdp_max_root_level, int tdp_huge_page_level);
long kvm_arch_dev_ioctl(unsigned int ioctl, unsigned long arg);

int kvm_emulate_cpuid(struct kvm_vcpu* vcpu);
int kvm_emulate_rdmsr(struct kvm_vcpu* vcpu);
int kvm_emulate_wrmsr(struct kvm_vcpu* vcpu);
int kvm_emulate_halt(struct kvm_vcpu* vcpu);
int kvm_emulate_invd(struct kvm_vcpu* vcpu);
int kvm_emulate_rdpmc(struct kvm_vcpu* vcpu);
int kvm_emulate_hypercall(struct kvm_vcpu* vcpu);
int kvm_emulate_wbinvd(struct kvm_vcpu* vcpu);
int kvm_emulate_xsetbv(struct kvm_vcpu* vcpu);
int kvm_emulate_mwait(struct kvm_vcpu* vcpu);
int kvm_emulate_monitor(struct kvm_vcpu* vcpu);
int kvm_handle_invalid_op(struct kvm_vcpu* vcpu);

void kvm_inject_page_fault(struct kvm_vcpu* vcpu, struct x86_exception* fault);
kvm_pfn_t __gfn_to_pfn_memslot(const struct kvm_memory_slot* slot, gfn_t gfn,
	bool atomic, bool interruptible, bool* async,
	bool write_fault, bool* writable, hva_t* hva);

static inline ULONG_PTR
__gfn_to_hva_memslot(const struct kvm_memory_slot* slot, gfn_t gfn)
{
	/*
	 * The index was checked originally in search_memslots.  To avoid
	 * that a malicious guest builds a Spectre gadget out of e.g. page
	 * table walks, do not let the processor speculate loads outside
	 * the guest's registered memslots.
	 */
	ULONG_PTR offset = gfn - slot->base_gfn;
	
	return slot->userspace_addr + offset * PAGE_SIZE;
}

// 初始化MMU的函数
int kvm_mmu_create(struct kvm_vcpu* vcpu);

int kvm_mmu_page_fault(struct kvm_vcpu* vcpu, gpa_t cr2_or_gpa, u64 error_code,
	void* insn, int insn_len);

void kvm_arch_vcpu_put(struct kvm_vcpu* vcpu);
void kvm_arch_vcpu_postcreate(struct kvm_vcpu* vcpu);

/*
 * EMULTYPE_NO_DECODE - Set when re-emulating an instruction (after completing
 *			userspace I/O) to indicate that the emulation context
 *			should be reused as is, i.e. skip initialization of
 *			emulation context, instruction fetch and decode.
 *
 * EMULTYPE_TRAP_UD - Set when emulating an intercepted #UD from hardware.
 *		      Indicates that only select instructions (tagged with
 *		      EmulateOnUD) should be emulated (to minimize the emulator
 *		      attack surface).  See also EMULTYPE_TRAP_UD_FORCED.
 *
 * EMULTYPE_SKIP - Set when emulating solely to skip an instruction, i.e. to
 *		   decode the instruction length.  For use *only* by
 *		   kvm_x86_ops.skip_emulated_instruction() implementations if
 *		   EMULTYPE_COMPLETE_USER_EXIT is not set.
 *
 * EMULTYPE_ALLOW_RETRY_PF - Set when the emulator should resume the guest to
 *			     retry native execution under certain conditions,
 *			     Can only be set in conjunction with EMULTYPE_PF.
 *
 * EMULTYPE_TRAP_UD_FORCED - Set when emulating an intercepted #UD that was
 *			     triggered by KVM's magic "force emulation" prefix,
 *			     which is opt in via module param (off by default).
 *			     Bypasses EmulateOnUD restriction despite emulating
 *			     due to an intercepted #UD (see EMULTYPE_TRAP_UD).
 *			     Used to test the full emulator from userspace.
 *
 * EMULTYPE_VMWARE_GP - Set when emulating an intercepted #GP for VMware
 *			backdoor emulation, which is opt in via module param.
 *			VMware backdoor emulation handles select instructions
 *			and reinjects the #GP for all other cases.
 *
 * EMULTYPE_PF - Set when emulating MMIO by way of an intercepted #PF, in which
 *		 case the CR2/GPA value pass on the stack is valid.
 *
 * EMULTYPE_COMPLETE_USER_EXIT - Set when the emulator should update interruptibility
 *				 state and inject single-step #DBs after skipping
 *				 an instruction (after completing userspace I/O).
 *
 * EMULTYPE_WRITE_PF_TO_SP - Set when emulating an intercepted page fault that
 *			     is attempting to write a gfn that contains one or
 *			     more of the PTEs used to translate the write itself,
 *			     and the owning page table is being shadowed by KVM.
 *			     If emulation of the faulting instruction fails and
 *			     this flag is set, KVM will exit to userspace instead
 *			     of retrying emulation as KVM cannot make forward
 *			     progress.
 *
 *			     If emulation fails for a write to guest page tables,
 *			     KVM unprotects (zaps) the shadow page for the target
 *			     gfn and resumes the guest to retry the non-emulatable
 *			     instruction (on hardware).  Unprotecting the gfn
 *			     doesn't allow forward progress for a self-changing
 *			     access because doing so also zaps the translation for
 *			     the gfn, i.e. retrying the instruction will hit a
 *			     !PRESENT fault, which results in a new shadow page
 *			     and sends KVM back to square one.
 */
#define EMULTYPE_NO_DECODE	    (1 << 0)
#define EMULTYPE_TRAP_UD	    (1 << 1)
#define EMULTYPE_SKIP		    (1 << 2)
#define EMULTYPE_ALLOW_RETRY_PF	    (1 << 3)
#define EMULTYPE_TRAP_UD_FORCED	    (1 << 4)
#define EMULTYPE_VMWARE_GP	    (1 << 5)
#define EMULTYPE_PF		    (1 << 6)
#define EMULTYPE_COMPLETE_USER_EXIT (1 << 7)
#define EMULTYPE_WRITE_PF_TO_SP	    (1 << 8)

void kvm_update_dr7(struct kvm_vcpu* vcpu);
long kvm_arch_vcpu_ioctl(unsigned int ioctl, unsigned long arg);

void kvm_set_rflags(struct kvm_vcpu* vcpu, unsigned long rflags);
bool kvm_is_linear_rip(struct kvm_vcpu* vcpu, unsigned long linear_rip);
ULONG_PTR kvm_get_linear_rip(struct kvm_vcpu* vcpu);
void kvm_set_segment(struct kvm_vcpu* vcpu, struct kvm_segment* var, int seg);
int kvm_arch_vcpu_ioctl_set_sregs(struct kvm_vcpu* vcpu,
	struct kvm_sregs* sregs);
int kvm_arch_vcpu_ioctl_set_regs(struct kvm_vcpu* vcpu, struct kvm_regs* regs);
int kvm_arch_init_vm(struct kvm* kvm, unsigned long type);
int kvm_mmu_init_vm(struct kvm* kvm);
void kvm_mmu_uninit_vm(struct kvm* kvm);
int kvm_arch_post_init_vm(struct kvm* kvm);
int kvm_arch_vcpu_precreate(struct kvm* kvm, unsigned int id);

void kvm_arch_free_vm(struct kvm* kvm);
void kvm_arch_pre_destroy_vm(struct kvm* kvm);
void kvm_arch_destroy_vm(struct kvm* kvm);

long kvm_vcpu_ioctl(unsigned int ioctl, PIRP Irp);
int kvm_arch_vcpu_runnable(struct kvm_vcpu* vcpu);
void kvm_vcpu_halt(struct kvm_vcpu* vcpu);
bool kvm_vcpu_block(struct kvm_vcpu* vcpu);
void kvm_arch_async_page_present(struct kvm_vcpu* vcpu,
	struct kvm_async_pf* work);

int kvm_arch_handle_exit(struct kvm_vcpu* vcpu, struct kvm_run* run);

void kvm_destroy_vcpus(struct kvm* kvm);
void kvm_arch_vcpu_destroy(struct kvm_vcpu* vcpu);

static inline gpa_t gfn_to_gpa(gfn_t gfn) {
	return (gpa_t)gfn << PAGE_SHIFT;
}

int kvm_mmu_topup_memory_cache(struct kvm_mmu_memory_cache* mc, int min);
int __kvm_mmu_topup_memory_cache(struct kvm_mmu_memory_cache* mc, int capacity, int min);
