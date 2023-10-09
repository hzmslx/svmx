#pragma once
#include "svmx.h"


#define KVM_API_VERSION 1

#pragma warning(disable:4201)

#define KVM_EXIT_UNKNOWN          0
#define KVM_EXIT_EXCEPTION        1
#define KVM_EXIT_IO               2
#define KVM_EXIT_HYPERCALL        3
#define KVM_EXIT_DEBUG            4
#define KVM_EXIT_HLT              5
#define KVM_EXIT_MMIO             6
#define KVM_EXIT_IRQ_WINDOW_OPEN  7
#define KVM_EXIT_SHUTDOWN         8
#define KVM_EXIT_FAIL_ENTRY       9
#define KVM_EXIT_INTR             10
#define KVM_EXIT_SET_TPR          11
#define KVM_EXIT_TPR_ACCESS       12
#define KVM_EXIT_S390_SIEIC       13
#define KVM_EXIT_S390_RESET       14
#define KVM_EXIT_DCR              15 /* deprecated */
#define KVM_EXIT_NMI              16
#define KVM_EXIT_INTERNAL_ERROR   17
#define KVM_EXIT_OSI              18
#define KVM_EXIT_PAPR_HCALL	  19
#define KVM_EXIT_S390_UCONTROL	  20
#define KVM_EXIT_WATCHDOG         21
#define KVM_EXIT_S390_TSCH        22
#define KVM_EXIT_EPR              23
#define KVM_EXIT_SYSTEM_EVENT     24
#define KVM_EXIT_S390_STSI        25
#define KVM_EXIT_IOAPIC_EOI       26
#define KVM_EXIT_HYPERV           27
#define KVM_EXIT_ARM_NISV         28
#define KVM_EXIT_X86_RDMSR        29
#define KVM_EXIT_X86_WRMSR        30
#define KVM_EXIT_DIRTY_RING_FULL  31
#define KVM_EXIT_AP_RESET_HOLD    32
#define KVM_EXIT_X86_BUS_LOCK     33
#define KVM_EXIT_XEN              34
#define KVM_EXIT_RISCV_SBI        35
#define KVM_EXIT_RISCV_CSR        36
#define KVM_EXIT_NOTIFY           37





/* Architectural interrupt line count. */
#define KVM_NR_INTERRUPTS 256

struct trace_print_flags {
	unsigned long		mask;
	const char* name;
};

struct kvm_segment {
	__u64 base;
	__u32 limit;
	__u16 selector;
	__u8  type;
	__u8  present, dpl, db, s, l, g, avl;
	__u8  unusable;
	__u8  padding;
};

/*
 * The bit 0 ~ bit 15 of kvm_userspace_memory_region::flags are visible for
 * userspace, other bits are reserved for kvm internal use which are defined
 * in include/linux/kvm_host.h.
 */
#define KVM_MEM_LOG_DIRTY_PAGES	(1UL << 0)
#define KVM_MEM_READONLY	(1UL << 1)

/* for KVM_SET_USER_MEMORY_REGION */
struct kvm_userspace_memory_region {
	__u32 slot; // slot编号
	__u32 flags; // 标志位，例如是否追踪脏页、是否可用等
	__u64 guest_phys_addr;// guest的物理地址起始位置，即GPA
	__u64 memory_size; /* 内存大小，单位bytes */
	__u64 userspace_addr; /* start of the userspace allocated memory, 即HVA */
};

/* for KVM_RUN */
struct kvm_run {
	/* in */
	/*
	* Request that KVM_RUN return when it becomes possible to inject external
	* interrupts into the guest. Useful in conjunction with KVM_INTERRUPT.
	*/
	__u8 request_interrupt_window;
	/*
	* This field is polled once when KVM_RUN starts; if non-zero, KVM_RUN
	* exits immediately.
	*/
	__u8 immediate_exit;
	__u8 padding1[6];

	/* out */
	/*
	* When KVM_RUN has returned successfully (return value 0), this informs
	* application code why KVM_RUN has returned. Allowable values for this
	* field are detailed below.
	*/
	__u32 exit_reason;
	__u8 ready_for_interrupt_injection;
	__u8 if_flag;
	__u16 flags;

	/* in (per_kvm_run), out (post_kvm_run) */
	__u64 cr8;
	__u64 apic_base;


	union {
		/* KVM_EXIT_UNKNOWN */
		struct {
			__u64 hardware_exit_reason;
		}hw;
		/* KVM_EXIT_FAIL_ENTRY */
		struct {
			__u64 hardware_entry_failure_reason;
			__u32 cpu;
		} fail_entry;
		/* KVM_EXIT_EXCEPTION */
		struct {
			__u32 exception;
			__u32 error_code;
		}ex;

	};
};

/* for KVM_GET_REGS and KVM_SET_REGS */
struct kvm_regs {
	/* out (KVM_GET_REGS) / in (KVM_SET_REGS) */
	__u64 rax, rbx, rcx, rdx;
	__u64 rsi, rdi, rsp, rbp;
	__u64 r8, r9, r10, r11;
	__u64 r12, r13, r14, r15;
	__u64 rip, rflags;
};

#define KVM_GUESTDBG_USE_SW_BP		0x00010000
#define KVM_GUESTDBG_USE_HW_BP		0x00020000
#define KVM_GUESTDBG_INJECT_DB		0x00040000
#define KVM_GUESTDBG_INJECT_BP		0x00080000

/* for KVM_SET_GUEST_DEBUG */

#define KVM_GUESTDBG_ENABLE		0x00000001
#define KVM_GUESTDBG_SINGLESTEP		0x00000002

struct kvm_guest_debug_arch {
	__u64 debugreg[8];
};

struct kvm_guest_debug {
	__u32 control;
	__u32 pad;
	struct kvm_guest_debug_arch arch;
};

struct kvm_msr_entry {
	__u32 index;
	__u32 reserved;
	__u64 data;
};

/* for KVM_SET_MP_STATE */

/* not all states are valid on all architectures */
#define KVM_MP_STATE_RUNNABLE          0
#define KVM_MP_STATE_UNINITIALIZED     1
#define KVM_MP_STATE_INIT_RECEIVED     2
#define KVM_MP_STATE_HALTED            3
#define KVM_MP_STATE_SIPI_RECEIVED     4
#define KVM_MP_STATE_STOPPED           5
#define KVM_MP_STATE_CHECK_STOP        6
#define KVM_MP_STATE_OPERATING         7
#define KVM_MP_STATE_LOAD              8
#define KVM_MP_STATE_AP_RESET_HOLD     9
#define KVM_MP_STATE_SUSPENDED         10

NTSTATUS kvm_dev_ioctl_create_vm(unsigned long type);
struct kvm* kvm_create_vm(unsigned long type);

struct kvm_dtable {
	__u64 base;
	__u16 limit;
	__u16 padding[3];
};

/* for KVM_GET_SREGS and KVM_SET_SREGS */
struct kvm_sregs {
	/* out (KVM_GET_SREGS) / in (KVM_SET_SREGS) */
	struct kvm_segment cs, ds, es, fs, gs, ss;
	struct kvm_segment tr, ldt;
	struct kvm_dtable gdt, idt;
	__u64 cr0, cr2, cr3, cr4, cr8;
	__u64 efer;
	__u64 apic_base;
	__u64 interrupt_bitmap[(KVM_NR_INTERRUPTS + 63) / 64];
};

/*
 * Creates some virtual cpus.  Good luck creating more than one.
 */
int kvm_vm_ioctl_create_vcpu(struct kvm* kvm, u32 id);



/*
* Extension capability list.
*/
#define KVM_CAP_IRQCHIP	  0
#define KVM_CAP_HLT	  1
#define KVM_CAP_MMU_SHADOW_CACHE_CONTROL 2
#define KVM_CAP_USER_MEMORY 3
#define KVM_CAP_SET_TSS_ADDR 4
#define KVM_CAP_VAPIC 6
#define KVM_CAP_EXT_CPUID 7
#define KVM_CAP_CLOCKSOURCE 8
#define KVM_CAP_NR_VCPUS 9       /* returns recommended max vcpus per vm */
#define KVM_CAP_NR_MEMSLOTS 10   /* returns max memory slots per vm */
#define KVM_CAP_PIT 11
#define KVM_CAP_NOP_IO_DELAY 12
#define KVM_CAP_PV_MMU 13
#define KVM_CAP_MP_STATE 14
#define KVM_CAP_COALESCED_MMIO 15
#define KVM_CAP_SYNC_MMU 16  /* Changes to host mmap are reflected in guest */
#define KVM_CAP_IOMMU 18
/* Another bug in KVM_SET_USER_MEMORY_REGION fixed: */
#define KVM_CAP_JOIN_MEMORY_REGIONS_WORKS 30
#ifdef __KVM_HAVE_MCE
#define KVM_CAP_MCE 31
#endif
#define KVM_CAP_IRQFD 32
#ifdef __KVM_HAVE_PIT
#define KVM_CAP_PIT2 33
#endif
#define KVM_CAP_SET_BOOT_CPU_ID 34
#ifdef __KVM_HAVE_PIT_STATE2
#define KVM_CAP_PIT_STATE2 35
#endif
#define KVM_CAP_IOEVENTFD 36
#define KVM_CAP_SET_IDENTITY_MAP_ADDR 37
#ifdef __KVM_HAVE_XEN_HVM
#define KVM_CAP_XEN_HVM 38
#endif
#define KVM_CAP_ADJUST_CLOCK 39
#define KVM_CAP_INTERNAL_ERROR_DATA 40
#ifdef __KVM_HAVE_VCPU_EVENTS
#define KVM_CAP_VCPU_EVENTS 41
#endif
#define KVM_CAP_S390_PSW 42
#define KVM_CAP_PPC_SEGSTATE 43
#define KVM_CAP_HYPERV 44
#define KVM_CAP_HYPERV_VAPIC 45
#define KVM_CAP_HYPERV_SPIN 46
#define KVM_CAP_PCI_SEGMENT 47
#define KVM_CAP_PPC_PAIRED_SINGLES 48
#define KVM_CAP_INTR_SHADOW 49
#ifdef __KVM_HAVE_DEBUGREGS
#define KVM_CAP_DEBUGREGS 50
#endif
#define KVM_CAP_X86_ROBUST_SINGLESTEP 51
#define KVM_CAP_PPC_OSI 52
#define KVM_CAP_PPC_UNSET_IRQ 53
#define KVM_CAP_ENABLE_CAP 54
#ifdef __KVM_HAVE_XSAVE
#define KVM_CAP_XSAVE 55
#endif
#ifdef __KVM_HAVE_XCRS
#define KVM_CAP_XCRS 56
#endif
#define KVM_CAP_PPC_GET_PVINFO 57
#define KVM_CAP_PPC_IRQ_LEVEL 58
#define KVM_CAP_ASYNC_PF 59
#define KVM_CAP_TSC_CONTROL 60
#define KVM_CAP_GET_TSC_KHZ 61
#define KVM_CAP_PPC_BOOKE_SREGS 62
#define KVM_CAP_SPAPR_TCE 63
#define KVM_CAP_PPC_SMT 64
#define KVM_CAP_PPC_RMA	65
#define KVM_CAP_MAX_VCPUS 66       /* returns max vcpus per vm */
#define KVM_CAP_PPC_HIOR 67
#define KVM_CAP_PPC_PAPR 68

#define KVM_CAP_ONE_REG 70
#define KVM_CAP_S390_GMAP 71
#define KVM_CAP_TSC_DEADLINE_TIMER 72
#define KVM_CAP_S390_UCONTROL 73
#define KVM_CAP_SYNC_REGS 74
#define KVM_CAP_PCI_2_3 75
#define KVM_CAP_KVMCLOCK_CTRL 76
#define KVM_CAP_SIGNAL_MSI 77
#define KVM_CAP_PPC_GET_SMMU_INFO 78
#define KVM_CAP_S390_COW 79
#define KVM_CAP_PPC_ALLOC_HTAB 80
#define KVM_CAP_READONLY_MEM 81
#define KVM_CAP_IRQFD_RESAMPLE 82
#define KVM_CAP_PPC_BOOKE_WATCHDOG 83
#define KVM_CAP_PPC_HTAB_FD 84


#define KVM_CAP_ARM_PSCI 87
#define KVM_CAP_ARM_SET_DEVICE_ADDR 88
#define KVM_CAP_DEVICE_CTRL 89

#define KVM_CAP_PPC_RTAS 91

#define KVM_CAP_ARM_EL1_32BIT 93
#define KVM_CAP_SPAPR_MULTITCE 94
#define KVM_CAP_EXT_EMUL_CPUID 95
#define KVM_CAP_HYPERV_TIME 96
#define KVM_CAP_IOAPIC_POLARITY_IGNORED 97
#define KVM_CAP_ENABLE_CAP_VM 98

#define KVM_CAP_IOEVENTFD_NO_LENGTH 100
#define KVM_CAP_VM_ATTRIBUTES 101


#define KVM_CAP_CHECK_EXTENSION_VM 105




#define KVM_CAP_DISABLE_QUIRKS 116
#define KVM_CAP_X86_SMM 117
#define KVM_CAP_MULTI_ADDRESS_SPACE 118
#define KVM_CAP_GUEST_DEBUG_HW_BPS 119
#define KVM_CAP_GUEST_DEBUG_HW_WPS 120
/*
* Create a local apic for each processor in the kernel.
*/
#define KVM_CAP_SPLIT_IRQCHIP 121
#define KVM_CAP_IOEVENTFD_ANY_LENGTH 122
#define KVM_CAP_HYPERV_SYNIC 123

#define KVM_CAP_SPAPR_TCE_64 125

#define KVM_CAP_VCPU_ATTRIBUTES 127
#define KVM_CAP_MAX_VCPU_ID 128
#define KVM_CAP_X2APIC_API 129

#define KVM_CAP_MSI_DEVID 131

#define KVM_CAP_SPAPR_RESIZE_HPT 133

#define KVM_CAP_IMMEDIATE_EXIT 136

#define KVM_CAP_SPAPR_TCE_VFIO 142
#define KVM_CAP_X86_DISABLE_EXITS 143
#define KVM_CAP_ARM_USER_IRQ 144
#define KVM_CAP_S390_CMMA_MIGRATION 145

#define KVM_CAP_HYPERV_SYNIC2 148
#define KVM_CAP_HYPERV_VP_INDEX 149

#define KVM_CAP_PPC_GET_CPU_CHAR 151

#define KVM_CAP_GET_MSR_FEATURES 153
#define KVM_CAP_HYPERV_EVENTFD 154
#define KVM_CAP_HYPERV_TLBFLUSH 155

#define KVM_CAP_NESTED_STATE 157

#define KVM_CAP_MSR_PLATFORM_INFO 159

#define KVM_CAP_HYPERV_SEND_IPI 161
#define KVM_CAP_COALESCED_PIO 162
#define KVM_CAP_HYPERV_ENLIGHTENED_VMCS 163
#define KVM_CAP_EXCEPTION_PAYLOAD 164
#define KVM_CAP_ARM_VM_IPA_SIZE 165
#define KVM_CAP_MANUAL_DIRTY_LOG_PROTECT 166 /* Obsolete */
#define KVM_CAP_HYPERV_CPUID 167
#define KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2 168


#define KVM_CAP_PMU_EVENT_FILTER 173
#define KVM_CAP_ARM_IRQ_LINE_LAYOUT_2 174
#define KVM_CAP_HYPERV_DIRECT_TLBFLUSH 175
#define KVM_CAP_PPC_GUEST_DEBUG_SSTEP 176
#define KVM_CAP_ARM_NISV_TO_USER 177
#define KVM_CAP_ARM_INJECT_EXT_DABT 178


#define KVM_CAP_HALT_POLL 182
#define KVM_CAP_ASYNC_PF_INT 183
#define KVM_CAP_LAST_CPU 184
#define KVM_CAP_SMALLER_MAXPHYADDR 185

#define KVM_CAP_STEAL_TIME 187
#define KVM_CAP_X86_USER_SPACE_MSR 188
#define KVM_CAP_X86_MSR_FILTER 189
#define KVM_CAP_ENFORCE_PV_FEATURE_CPUID 190
#define KVM_CAP_SYS_HYPERV_CPUID 191
#define KVM_CAP_DIRTY_LOG_RING 192
#define KVM_CAP_X86_BUS_LOCK_EXIT 193

#define KVM_CAP_SET_GUEST_DEBUG2 195
#define KVM_CAP_SGX_ATTRIBUTE 196
#define KVM_CAP_VM_COPY_ENC_CONTEXT_FROM 197
#define KVM_CAP_PTP_KVM 198
#define KVM_CAP_HYPERV_ENFORCE_CPUID 199
#define KVM_CAP_SREGS2 200
#define KVM_CAP_EXIT_HYPERCALL 201

#define KVM_CAP_BINARY_STATS_FD 203
#define KVM_CAP_EXIT_ON_EMULATION_FAILURE 204

#define KVM_CAP_VM_MOVE_ENC_CONTEXT_FROM 206
#define KVM_CAP_VM_GPA_BITS 207
#define KVM_CAP_XSAVE2 208
#define KVM_CAP_SYS_ATTRIBUTES 209
#define KVM_CAP_PPC_AIL_MODE_3 210
#define KVM_CAP_S390_MEM_OP_EXTENSION 211
#define KVM_CAP_PMU_CAPABILITY 212
#define KVM_CAP_DISABLE_QUIRKS2 213
#define KVM_CAP_VM_TSC_CONTROL 214
#define KVM_CAP_SYSTEM_EVENT_DATA 215
#define KVM_CAP_ARM_SYSTEM_SUSPEND 216
#define KVM_CAP_S390_PROTECTED_DUMP 217
#define KVM_CAP_X86_TRIPLE_FAULT_EVENT 218
#define KVM_CAP_X86_NOTIFY_VMEXIT 219
#define KVM_CAP_VM_DISABLE_NX_HUGE_PAGES 220
#define KVM_CAP_S390_ZPCI_OP 221
#define KVM_CAP_S390_CPU_TOPOLOGY 222
#define KVM_CAP_DIRTY_LOG_RING_ACQ_REL 223
#define KVM_CAP_S390_PROTECTED_ASYNC_DISABLE 224
#define KVM_CAP_DIRTY_LOG_RING_WITH_BITMAP 225
#define KVM_CAP_PMU_EVENT_MASKED_EVENTS 226
#define KVM_CAP_COUNTER_OFFSET 227

#define KVM_RUN_X86_BUS_LOCK     (1 << 1)

/* Available with KVM_CAP_X86_NOTIFY_VMEXIT */
#define KVM_X86_NOTIFY_VMEXIT_ENABLED		(1ULL << 0)
#define KVM_X86_NOTIFY_VMEXIT_USER		(1ULL << 1)