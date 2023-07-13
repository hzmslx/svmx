#pragma once
#include "kvm.h"
#include "kvm_types.h"
#include "processor-flags.h"
#include "desc_ptr.h"
#include "kvm_emulate.h"

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
#define KVM_NR_PAGE_SIZES	3
#define KVM_HPAGE_SHIFT(x)	(PAGE_SHIFT + (((x) - 1) * 9))
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
#define MC_VECTOR 18

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
	NR_VCPU_REGS
};

enum kvm_reg_ex {
	VCPU_EXREG_PDPTR = NR_VCPU_REGS,
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

struct kvm_vcpu_arch {
	u64 host_tsc;
	/*
	 * rip and regs accesses must go through
	 * kvm_{register,rip}_{read,write} functions.
	 */
	unsigned long regs[NR_VCPU_REGS];
	u32 regs_avail;
	u32 regs_dirty;

	unsigned long cr0;
	unsigned long cr2;
	unsigned long cr3;
	unsigned long cr4;
	unsigned long cr8;
	u32 hflags;
	u64 pdptrs[4]; /* pae */
	u64 shadow_efer;
	u64 apic_base;
	struct kvm_lapic* apic;    /* kernel irqchip context */
	// int32_t apic_arb_prio;
	int mp_state;
	int sipi_vector;
	u64 ia32_misc_enable_msr;
	bool tpr_access_reporting;

	//struct kvm_mmu mmu;
	/* only needed in kvm_pv_mmu_op() path, but it's hot so
	 * put it here to avoid allocation */
	//struct kvm_pv_mmu_op_buffer mmu_op_buffer;

	//struct kvm_mmu_memory_cache mmu_pte_chain_cache;
	//struct kvm_mmu_memory_cache mmu_rmap_desc_cache;
	//struct kvm_mmu_memory_cache mmu_page_cache;
	//struct kvm_mmu_memory_cache mmu_page_header_cache;

	gfn_t last_pt_write_gfn;
	int   last_pt_write_count;
	u64* last_pte_updated;
	gfn_t last_pte_gfn;

	struct {
		//gfn_t gfn;	/* presumed gfn during guest pte update */
		//pfn_t pfn;	/* pfn corresponding to that gfn */
		unsigned long mmu_seq;
	} update_pte;

	//struct i387_fxsave_struct host_fx_image;
	//struct i387_fxsave_struct guest_fx_image;

	gva_t mmio_fault_cr2;
	//struct kvm_pio_request pio;
	void* pio_data;

	u8 event_exit_inst_len;

	struct kvm_queued_exception {
		bool pending;
		bool has_error_code;
		u8 nr;
		u32 error_code;
	} exception;

	struct kvm_queued_interrupt {
		bool pending;
		bool soft;
		u8 nr;
	} interrupt;

	int halt_request; /* real mode on Intel only */

	int cpuid_nent;
	//struct kvm_cpuid_entry2 cpuid_entries[KVM_MAX_CPUID_ENTRIES];
	/* emulate context */

	//struct x86_emulate_ctxt emulate_ctxt;

	gpa_t time;
	//struct pvclock_vcpu_time_info hv_clock;
	unsigned int hv_clock_tsc_khz;
	unsigned int time_offset;
	struct page* time_page;

	bool singlestep; /* guest is single stepped by KVM */
	bool nmi_pending;
	bool nmi_injected;

	//struct mtrr_state_type mtrr_state;
	u32 pat;

	int switch_db_regs;
	//unsigned long db[KVM_NR_DB_REGS];
	unsigned long dr6;
	unsigned long dr7;
	//unsigned long eff_db[KVM_NR_DB_REGS];

	u64 mcg_cap;
	u64 mcg_status;
	u64 mcg_ctl;
	u64* mce_banks;
};

struct kvm_vcpu {
	struct kvm* kvm;

	int vcpu_id;
	//struct mutex mutex;
	int   cpu;
	struct kvm_run* run;
	unsigned long requests;
	unsigned long guest_debug;
	int fpu_active;
	int guest_fpu_loaded;
	//wait_queue_head_t wq;
	int sigset_active;
	//sigset_t sigset;
	//struct kvm_vcpu_stat stat;

#ifdef CONFIG_HAS_IOMEM
	int mmio_needed;
	int mmio_read_completed;
	int mmio_is_write;
	int mmio_size;
	unsigned char mmio_data[8];
	gpa_t mmio_phys_addr;
#endif

	struct kvm_vcpu_arch arch;
};

struct kvm {
	int nmemslots;
};

struct msr_data {
	bool host_initiated;
	u32 index;
	u64 data;
};

#include <pshpack1.h>
struct descriptor_table {
	u16 limit;
	unsigned long base;
};
#include <poppack.h>

struct kvm_x86_ops {
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
	int (*vcpu_create)(struct kvm_vcpu* vcpu);
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
	void (*set_cr0)(struct kvm_vcpu* vcpu, unsigned long cr0);
	void (*post_set_cr3)(struct kvm_vcpu* vcpu, unsigned long cr3);
	bool (*is_valid_cr4)(struct kvm_vcpu* vcpu, unsigned long cr0);
	void (*set_cr4)(struct kvm_vcpu* vcpu, unsigned long cr4);
	int (*set_efer)(struct kvm_vcpu* vcpu, u64 efer);
	void (*get_idt)(struct kvm_vcpu* vcpu, struct desc_ptr* dt);
	void (*set_idt)(struct kvm_vcpu* vcpu, struct desc_ptr* dt);
	void (*get_gdt)(struct kvm_vcpu* vcpu, struct desc_ptr* dt);
	void (*set_gdt)(struct kvm_vcpu* vcpu, struct desc_ptr* dt);
	void (*sync_dirty_debug_regs)(struct kvm_vcpu* vcpu);
	void (*set_dr7)(struct kvm_vcpu* vcpu, unsigned long value);
	void (*cache_reg)(struct kvm_vcpu* vcpu, enum kvm_reg reg);
	unsigned long (*get_rflags)(struct kvm_vcpu* vcpu);
	void (*set_rflags)(struct kvm_vcpu* vcpu, unsigned long rflags);
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
	const unsigned long required_apicv_inhibits;
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
	unsigned long (*vcpu_get_apicv_inhibit_reasons)(struct kvm_vcpu* vcpu);
};

enum pmc_type {
	KVM_PMC_GP = 0,
	KVM_PMC_FIXED,
};

struct kvm_pmc {
	enum pmc_type type;
	u8 idx;
	bool is_paused;
	bool intr;
	u64 counter;
	u64 prev_counter;
	u64 eventsel;
	//struct perf_event* perf_event;
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
#define KVM_PMC_MAX_FIXED	3

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
	//struct irq_work irq_work;

	/*
	 * Overlay the bitmap with a 64-bit atomic so that all bits can be
	 * set in a single access, e.g. to reprogram all counters when the PMU
	 * filter changes.
	 */
	//union {
	//	//DECLARE_BITMAP(reprogram_pmi, X86_PMC_IDX_MAX);
	//	//atomic64_t __reprogram_pmi;
	//};
	//DECLARE_BITMAP(all_valid_pmc_idx, X86_PMC_IDX_MAX);
	//DECLARE_BITMAP(pmc_in_use, X86_PMC_IDX_MAX);

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

struct kvm_x86_init_ops {
	NTSTATUS (*hardware_setup)();
	unsigned int (*handle_intel_pt_intr)(void);

	struct kvm_x86_ops* runtime_ops;
	struct kvm_pmu_ops* pmu_ops;
};

extern struct kvm_x86_ops kvm_x86_ops;

int kvm_init(unsigned vcpu_size, unsigned vcpu_align);
void kvm_exit();


void kvm_arch_hardware_enable(void* garbage);

void kvm_get_cs_db_l_bits(struct kvm_vcpu* vcpu, int* db, int* l);



NTSTATUS kvm_mmu_module_init();

NTSTATUS kvm_arch_hardware_setup();
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
