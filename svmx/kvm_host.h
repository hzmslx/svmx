#pragma once
#include "kvm.h"
#include "kvm_types.h"
#include "processor-flags.h"

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

#include <pshpack1.h>
struct descriptor_table {
	u16 limit;
	unsigned long base;
};
#include <poppack.h>

struct kvm_x86_ops {
	int (*cpu_has_kvm_support)();			/* __init */
	int (*disabled_by_bios)();				/* __init */
	void (*hardware_enable)(void* dummy);	/* __init */
	void (*hardware_disable)(void* dummy);	
	void (*check_processor_compatibility)(void* rtn);
	NTSTATUS(*hardware_setup)();				/* __init */
	void (*hardware_unsetup)();				/* __exit */
	bool (*cpu_has_accelerated_tpr)();

	/* Create, but do not attach this VCPU */
	struct kvm_vcpu* (*vcpu_create)(struct kvm* kvm, unsigned id);
	void (*vcpu_free)(struct kvm_vcpu* vcpu);
	NTSTATUS (*vcpu_reset)(struct kvm_vcpu* vcpu);

	void (*prepare_guest_switch)(struct kvm_vcpu* vcpu);
	void (*vcpu_load)(struct kvm_vcpu* vcpu, int cpu);
	void (*vcpu_put)(struct kvm_vcpu* vcpu);

	int (*set_guest_debug)(struct kvm_vcpu* vcpu,
		struct kvm_guest_debug* dbg);
	NTSTATUS (*get_msr)(struct kvm_vcpu* vcpu, u32 msr_index, u64* pdata);
	NTSTATUS (*set_msr)(struct kvm_vcpu* vcpu, u32 msr_index, u64 data);
	u64(*get_segment_base)(struct kvm_vcpu* vcpu, int seg);
	void (*get_segment)(struct kvm_vcpu* vcpu,
		struct kvm_segment* var, int seg);
	int (*get_cpl)(struct kvm_vcpu* vcpu);
	void (*set_segment)(struct kvm_vcpu* vcpu,
		struct kvm_segment* var, int seg);
	void (*get_cs_db_l_bits)(struct kvm_vcpu* vcpu, int* db, int* l);
	void (*decache_cr4_guest_bits)(struct kvm_vcpu* vcpu);
	void (*set_cr0)(struct kvm_vcpu* vcpu, unsigned long cr0);
	void (*set_cr3)(struct kvm_vcpu* vcpu, unsigned long cr3);
	void (*set_cr4)(struct kvm_vcpu* vcpu, unsigned long cr4);
	void (*set_efer)(struct kvm_vcpu* vcpu, u64 efer);
	void (*get_idt)(struct kvm_vcpu* vcpu, struct descriptor_table* dt);
	void (*set_idt)(struct kvm_vcpu* vcpu, struct descriptor_table* dt);
	void (*get_gdt)(struct kvm_vcpu* vcpu, struct descriptor_table* dt);
	void (*set_gdt)(struct kvm_vcpu* vcpu, struct descriptor_table* dt);
	unsigned long (*get_dr)(struct kvm_vcpu* vcpu, int dr);
	void (*set_dr)(struct kvm_vcpu* vcpu, int dr, unsigned long value,
		int* exception);
	void (*cache_reg)(struct kvm_vcpu* vcpu, enum kvm_reg reg);
	unsigned long (*get_rflags)(struct kvm_vcpu* vcpu);
	void (*set_rflags)(struct kvm_vcpu* vcpu, unsigned long rflags);

	void (*tlb_flush)(struct kvm_vcpu* vcpu);

	void (*run)(struct kvm_vcpu* vcpu, struct kvm_run* run);
	int (*handle_exit)(struct kvm_run* run, struct kvm_vcpu* vcpu);
	void (*skip_emulated_instruction)(struct kvm_vcpu* vcpu);
	void (*set_interrupt_shadow)(struct kvm_vcpu* vcpu, int mask);
	u32(*get_interrupt_shadow)(struct kvm_vcpu* vcpu, int mask);
	void (*patch_hypercall)(struct kvm_vcpu* vcpu,
		unsigned char* hypercall_addr);
	void (*set_irq)(struct kvm_vcpu* vcpu);
	void (*set_nmi)(struct kvm_vcpu* vcpu);
	void (*queue_exception)(struct kvm_vcpu* vcpu, unsigned nr,
		bool has_error_code, u32 error_code);
	int (*interrupt_allowed)(struct kvm_vcpu* vcpu);
	int (*nmi_allowed)(struct kvm_vcpu* vcpu);
	void (*enable_nmi_window)(struct kvm_vcpu* vcpu);
	void (*enable_irq_window)(struct kvm_vcpu* vcpu);
	void (*update_cr8_intercept)(struct kvm_vcpu* vcpu, int tpr, int irr);
	int (*set_tss_addr)(struct kvm* kvm, unsigned int addr);
	int (*get_tdp_level)();
	u64(*get_mt_mask)(struct kvm_vcpu* vcpu, gfn_t gfn, bool is_mmio);
	bool (*gb_page_enable)();

	const struct trace_print_flags* exit_reasons_str;
};

extern struct kvm_x86_ops* kvm_x86_ops;

NTSTATUS kvm_init(void* opaque, unsigned int vcpu_size);

NTSTATUS kvm_arch_init(void* opaque);
void kvm_arch_hardware_enable(void* garbage);


NTSTATUS kvm_mmu_module_init();

NTSTATUS kvm_arch_hardware_setup();
void kvm_arch_check_processor_compat(void* rtn);

void kvm_enable_efer_bits(u64);

void kvm_mmu_set_nonpresent_ptes(u64 trap_pte, u64 notrap_pte);
void kvm_mmu_set_base_ptes(u64 base_pte);
void kvm_mmu_set_mask_ptes(u64 user_mask, u64 accessed_mask,
	u64 dirty_mask, u64 nx_mask, u64 x_mask);

void kvm_disable_largepages();
