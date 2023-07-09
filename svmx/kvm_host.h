#pragma once
#include "kvm.h"
#include "kvm_types.h"

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
	int (*hardware_setup)();				/* __init */
	void (*hardware_unsetup)();				/* __exit */
	bool (*cpu_has_accelerated_tpr)();

	/* Create, but do not attach this VCPU */
	struct kvm_vcpu* (*vcpu_create)(struct kvm* kvm, unsigned id);
	void (*vcpu_free)(struct kvm_vcpu* vcpu);
	int (*vcpu_reset)(struct kvm_vcpu* vcpu);

	void (*prepare_guest_switch)(struct kvm_vcpu* vcpu);
	void (*vcpu_load)(struct kvm_vcpu* vcpu, int cpu);
	void (*vcpu_put)(struct kvm_vcpu* vcpu);

	int (*set_guest_debug)(struct kvm_vcpu* vcpu,
		struct kvm_guest_debug* dbg);
	int (*get_msr)(struct kvm_vcpu* vcpu, u32 msr_index, u64* pdata);
	int (*set_msr)(struct kvm_vcpu* vcpu, u32 msr_index, u64 data);
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
	int (*get_tdp_level)(void);
	u64(*get_mt_mask)(struct kvm_vcpu* vcpu, gfn_t gfn, bool is_mmio);
	bool (*gb_page_enable)(void);

	const struct trace_print_flags* exit_reasons_str;
};

NTSTATUS kvm_init(void* opaque, unsigned int vcpu_size);

NTSTATUS kvm_arch_init(void* opaque);

NTSTATUS kvm_mmu_module_init();

NTSTATUS kvm_arch_hardware_setup();
void kvm_arch_check_processor_compat(void* rtn);

void kvm_enable_efer_bits(u64);

void kvm_mmu_set_nonpresent_ptes(u64 trap_pte, u64 notrap_pte);
void kvm_mmu_set_base_ptes(u64 base_pte);
void kvm_mmu_set_mask_ptes(u64 user_mask, u64 accessed_mask,
	u64 dirty_mask, u64 nx_mask, u64 x_mask);
