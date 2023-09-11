#pragma once
/*
* vmx.h VMX Architecture related definitions
* Copyright (c) 2004, Intel Corporation.
* 
*/
#include "kvm_host.h"
#include "kvm.h"
#include "intel_pt.h"
#include "vmcs.h"
#include "posted_intr.h"
#include "desc_defs.h"
#include "vmxfeatures.h"
#include "vmx_ops.h"
#include "kvm_cache_regs.h"

enum segment_cache_field {
	SEG_FIELD_SEL = 0,
	SEG_FIELD_BASE = 1,
	SEG_FIELD_LIMIT = 2,
	SEG_FIELD_AR = 3,

	SEG_FIELD_NR = 4
};

#define VMX_EXIT_REASONS_FAILED_VMENTRY         0x80000000
#define VMX_EXIT_REASONS_SGX_ENCLAVE_MODE	0x08000000

#define EXIT_REASON_EXCEPTION_NMI       0
#define EXIT_REASON_EXTERNAL_INTERRUPT  1
#define EXIT_REASON_TRIPLE_FAULT        2
#define EXIT_REASON_INIT_SIGNAL			3
#define EXIT_REASON_SIPI_SIGNAL         4

#define EXIT_REASON_INTERRUPT_WINDOW    7
#define EXIT_REASON_NMI_WINDOW          8
#define EXIT_REASON_TASK_SWITCH         9
#define EXIT_REASON_CPUID               10
#define EXIT_REASON_HLT                 12
#define EXIT_REASON_INVD                13
#define EXIT_REASON_INVLPG              14
#define EXIT_REASON_RDPMC               15
#define EXIT_REASON_RDTSC               16
#define EXIT_REASON_VMCALL              18
#define EXIT_REASON_VMCLEAR             19
#define EXIT_REASON_VMLAUNCH            20
#define EXIT_REASON_VMPTRLD             21
#define EXIT_REASON_VMPTRST             22
#define EXIT_REASON_VMREAD              23
#define EXIT_REASON_VMRESUME            24
#define EXIT_REASON_VMWRITE             25
#define EXIT_REASON_VMOFF               26
#define EXIT_REASON_VMON                27
#define EXIT_REASON_CR_ACCESS           28
#define EXIT_REASON_DR_ACCESS           29
#define EXIT_REASON_IO_INSTRUCTION      30
#define EXIT_REASON_MSR_READ            31
#define EXIT_REASON_MSR_WRITE           32
#define EXIT_REASON_INVALID_STATE       33
#define EXIT_REASON_MSR_LOAD_FAIL       34
#define EXIT_REASON_MWAIT_INSTRUCTION   36
#define EXIT_REASON_MONITOR_TRAP_FLAG   37
#define EXIT_REASON_MONITOR_INSTRUCTION 39
#define EXIT_REASON_PAUSE_INSTRUCTION   40
#define EXIT_REASON_MCE_DURING_VMENTRY  41
#define EXIT_REASON_TPR_BELOW_THRESHOLD 43
#define EXIT_REASON_APIC_ACCESS         44
#define EXIT_REASON_EOI_INDUCED         45
#define EXIT_REASON_GDTR_IDTR           46
#define EXIT_REASON_LDTR_TR             47
#define EXIT_REASON_EPT_VIOLATION       48
#define EXIT_REASON_EPT_MISCONFIG       49
#define EXIT_REASON_INVEPT              50
#define EXIT_REASON_RDTSCP              51
#define EXIT_REASON_PREEMPTION_TIMER    52
#define EXIT_REASON_INVVPID             53
#define EXIT_REASON_WBINVD              54
#define EXIT_REASON_XSETBV              55
#define EXIT_REASON_APIC_WRITE          56
#define EXIT_REASON_RDRAND              57
#define EXIT_REASON_INVPCID             58
#define EXIT_REASON_VMFUNC              59
#define EXIT_REASON_ENCLS               60
#define EXIT_REASON_RDSEED              61
#define EXIT_REASON_PML_FULL            62
#define EXIT_REASON_XSAVES              63
#define EXIT_REASON_XRSTORS             64
#define EXIT_REASON_UMWAIT              67
#define EXIT_REASON_TPAUSE              68
#define EXIT_REASON_BUS_LOCK            74
#define EXIT_REASON_NOTIFY              75

#define VMCS_CONTROL_BIT(x)	BIT(VMX_FEATURE_##x & 0x1f)

/*
 * Definitions of Tertiary Processor-Based VM-Execution Controls.
 */
#define TERTIARY_EXEC_IPI_VIRT			VMCS_CONTROL_BIT(IPI_VIRT)


#define PIN_BASED_ALWAYSON_WITHOUT_TRUE_MSR	0x00000016

/*
* Definitions of Primary Processor-Based VM-Execution Controls.
*/
#define CPU_BASED_INTR_WINDOW_EXITING           VMCS_CONTROL_BIT(INTR_WINDOW_EXITING)
#define CPU_BASED_USE_TSC_OFFSETTING            VMCS_CONTROL_BIT(USE_TSC_OFFSETTING)
#define CPU_BASED_HLT_EXITING                   VMCS_CONTROL_BIT(HLT_EXITING)
#define CPU_BASED_INVLPG_EXITING                VMCS_CONTROL_BIT(INVLPG_EXITING)
#define CPU_BASED_MWAIT_EXITING                 VMCS_CONTROL_BIT(MWAIT_EXITING)
#define CPU_BASED_RDPMC_EXITING                 VMCS_CONTROL_BIT(RDPMC_EXITING)
#define CPU_BASED_RDTSC_EXITING                 VMCS_CONTROL_BIT(RDTSC_EXITING)
#define CPU_BASED_CR3_LOAD_EXITING		VMCS_CONTROL_BIT(CR3_LOAD_EXITING)
#define CPU_BASED_CR3_STORE_EXITING		VMCS_CONTROL_BIT(CR3_STORE_EXITING)
#define CPU_BASED_ACTIVATE_TERTIARY_CONTROLS	VMCS_CONTROL_BIT(TERTIARY_CONTROLS)
#define CPU_BASED_CR8_LOAD_EXITING              VMCS_CONTROL_BIT(CR8_LOAD_EXITING)
#define CPU_BASED_CR8_STORE_EXITING             VMCS_CONTROL_BIT(CR8_STORE_EXITING)
#define CPU_BASED_TPR_SHADOW                    VMCS_CONTROL_BIT(VIRTUAL_TPR)
#define CPU_BASED_NMI_WINDOW_EXITING		VMCS_CONTROL_BIT(NMI_WINDOW_EXITING)
#define CPU_BASED_MOV_DR_EXITING                VMCS_CONTROL_BIT(MOV_DR_EXITING)
#define CPU_BASED_UNCOND_IO_EXITING             VMCS_CONTROL_BIT(UNCOND_IO_EXITING)
#define CPU_BASED_USE_IO_BITMAPS                VMCS_CONTROL_BIT(USE_IO_BITMAPS)
#define CPU_BASED_MONITOR_TRAP_FLAG             VMCS_CONTROL_BIT(MONITOR_TRAP_FLAG)
#define CPU_BASED_USE_MSR_BITMAPS               VMCS_CONTROL_BIT(USE_MSR_BITMAPS)
#define CPU_BASED_MONITOR_EXITING               VMCS_CONTROL_BIT(MONITOR_EXITING)
#define CPU_BASED_PAUSE_EXITING                 VMCS_CONTROL_BIT(PAUSE_EXITING)
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS   VMCS_CONTROL_BIT(SEC_CONTROLS)

#define CPU_BASED_ALWAYSON_WITHOUT_TRUE_MSR	0x0401e172


struct nested_vmx_msrs {
	/*
	 * We only store the "true" versions of the VMX capability MSRs. We
	 * generate the "non-true" versions by setting the must-be-1 bits
	 * according to the SDM.
	 */
	u32 procbased_ctls_low;
	u32 procbased_ctls_high;
	u32 secondary_ctls_low;
	u32 secondary_ctls_high;
	u32 pinbased_ctls_low;
	u32 pinbased_ctls_high;
	u32 exit_ctls_low;
	u32 exit_ctls_high;
	u32 entry_ctls_low;
	u32 entry_ctls_high;
	u32 misc_low;
	u32 misc_high;
	u32 ept_caps;
	u32 vpid_caps;
	u64 basic;
	u64 cr0_fixed0;
	u64 cr0_fixed1;
	u64 cr4_fixed0;
	u64 cr4_fixed1;
	u64 vmcs_enum;
	u64 vmfunc_controls;
};

/* VMCS Encodings */
enum vmcs_field {
	VIRTUAL_PROCESSOR_ID = 0x00000000,
	POSTED_INTR_NV = 0x00000002,
	LAST_PID_POINTER_INDEX = 0x00000008,
	GUEST_ES_SELECTOR = 0x00000800,
	GUEST_CS_SELECTOR = 0x00000802,
	GUEST_SS_SELECTOR = 0x00000804,
	GUEST_DS_SELECTOR = 0x00000806,
	GUEST_FS_SELECTOR = 0x00000808,
	GUEST_GS_SELECTOR = 0x0000080a,
	GUEST_LDTR_SELECTOR = 0x0000080c,
	GUEST_TR_SELECTOR = 0x0000080e,
	GUEST_INTR_STATUS = 0x00000810,
	GUEST_PML_INDEX = 0x00000812,
	HOST_ES_SELECTOR = 0x00000c00,
	HOST_CS_SELECTOR = 0x00000c02,
	HOST_SS_SELECTOR = 0x00000c04,
	HOST_DS_SELECTOR = 0x00000c06,
	HOST_FS_SELECTOR = 0x00000c08,
	HOST_GS_SELECTOR = 0x00000c0a,
	HOST_TR_SELECTOR = 0x00000c0c,
	IO_BITMAP_A = 0x00002000,
	IO_BITMAP_A_HIGH = 0x00002001,
	IO_BITMAP_B = 0x00002002,
	IO_BITMAP_B_HIGH = 0x00002003,
	MSR_BITMAP = 0x00002004,
	MSR_BITMAP_HIGH = 0x00002005,
	VM_EXIT_MSR_STORE_ADDR = 0x00002006,
	VM_EXIT_MSR_STORE_ADDR_HIGH = 0x00002007,
	VM_EXIT_MSR_LOAD_ADDR = 0x00002008,
	VM_EXIT_MSR_LOAD_ADDR_HIGH = 0x00002009,
	VM_ENTRY_MSR_LOAD_ADDR = 0x0000200a,
	VM_ENTRY_MSR_LOAD_ADDR_HIGH = 0x0000200b,
	PML_ADDRESS = 0x0000200e,
	PML_ADDRESS_HIGH = 0x0000200f,
	TSC_OFFSET = 0x00002010,
	TSC_OFFSET_HIGH = 0x00002011,
	VIRTUAL_APIC_PAGE_ADDR = 0x00002012,
	VIRTUAL_APIC_PAGE_ADDR_HIGH = 0x00002013,
	APIC_ACCESS_ADDR = 0x00002014,
	APIC_ACCESS_ADDR_HIGH = 0x00002015,
	POSTED_INTR_DESC_ADDR = 0x00002016,
	POSTED_INTR_DESC_ADDR_HIGH = 0x00002017,
	VM_FUNCTION_CONTROL = 0x00002018,
	VM_FUNCTION_CONTROL_HIGH = 0x00002019,
	EPT_POINTER = 0x0000201a,
	EPT_POINTER_HIGH = 0x0000201b,
	EOI_EXIT_BITMAP0 = 0x0000201c,
	EOI_EXIT_BITMAP0_HIGH = 0x0000201d,
	EOI_EXIT_BITMAP1 = 0x0000201e,
	EOI_EXIT_BITMAP1_HIGH = 0x0000201f,
	EOI_EXIT_BITMAP2 = 0x00002020,
	EOI_EXIT_BITMAP2_HIGH = 0x00002021,
	EOI_EXIT_BITMAP3 = 0x00002022,
	EOI_EXIT_BITMAP3_HIGH = 0x00002023,
	EPTP_LIST_ADDRESS = 0x00002024,
	EPTP_LIST_ADDRESS_HIGH = 0x00002025,
	VMREAD_BITMAP = 0x00002026,
	VMREAD_BITMAP_HIGH = 0x00002027,
	VMWRITE_BITMAP = 0x00002028,
	VMWRITE_BITMAP_HIGH = 0x00002029,
	XSS_EXIT_BITMAP = 0x0000202C,
	XSS_EXIT_BITMAP_HIGH = 0x0000202D,
	ENCLS_EXITING_BITMAP = 0x0000202E,
	ENCLS_EXITING_BITMAP_HIGH = 0x0000202F,
	TSC_MULTIPLIER = 0x00002032,
	TSC_MULTIPLIER_HIGH = 0x00002033,
	TERTIARY_VM_EXEC_CONTROL = 0x00002034,
	TERTIARY_VM_EXEC_CONTROL_HIGH = 0x00002035,
	PID_POINTER_TABLE = 0x00002042,
	PID_POINTER_TABLE_HIGH = 0x00002043,
	GUEST_PHYSICAL_ADDRESS = 0x00002400,
	GUEST_PHYSICAL_ADDRESS_HIGH = 0x00002401,
	VMCS_LINK_POINTER = 0x00002800,
	VMCS_LINK_POINTER_HIGH = 0x00002801,
	GUEST_IA32_DEBUGCTL = 0x00002802,
	GUEST_IA32_DEBUGCTL_HIGH = 0x00002803,
	GUEST_IA32_PAT = 0x00002804,
	GUEST_IA32_PAT_HIGH = 0x00002805,
	GUEST_IA32_EFER = 0x00002806,
	GUEST_IA32_EFER_HIGH = 0x00002807,
	GUEST_IA32_PERF_GLOBAL_CTRL = 0x00002808,
	GUEST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x00002809,
	GUEST_PDPTR0 = 0x0000280a,
	GUEST_PDPTR0_HIGH = 0x0000280b,
	GUEST_PDPTR1 = 0x0000280c,
	GUEST_PDPTR1_HIGH = 0x0000280d,
	GUEST_PDPTR2 = 0x0000280e,
	GUEST_PDPTR2_HIGH = 0x0000280f,
	GUEST_PDPTR3 = 0x00002810,
	GUEST_PDPTR3_HIGH = 0x00002811,
	GUEST_BNDCFGS = 0x00002812,
	GUEST_BNDCFGS_HIGH = 0x00002813,
	GUEST_IA32_RTIT_CTL = 0x00002814,
	GUEST_IA32_RTIT_CTL_HIGH = 0x00002815,
	HOST_IA32_PAT = 0x00002c00,
	HOST_IA32_PAT_HIGH = 0x00002c01,
	HOST_IA32_EFER = 0x00002c02,
	HOST_IA32_EFER_HIGH = 0x00002c03,
	HOST_IA32_PERF_GLOBAL_CTRL = 0x00002c04,
	HOST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x00002c05,
	PIN_BASED_VM_EXEC_CONTROL = 0x00004000,
	CPU_BASED_VM_EXEC_CONTROL = 0x00004002,
	EXCEPTION_BITMAP = 0x00004004,
	PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
	PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
	CR3_TARGET_COUNT = 0x0000400a,
	VM_EXIT_CONTROLS = 0x0000400c,
	VM_EXIT_MSR_STORE_COUNT = 0x0000400e,
	VM_EXIT_MSR_LOAD_COUNT = 0x00004010,
	VM_ENTRY_CONTROLS = 0x00004012,
	VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,
	VM_ENTRY_INTR_INFO_FIELD = 0x00004016,
	VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018,
	VM_ENTRY_INSTRUCTION_LEN = 0x0000401a,
	TPR_THRESHOLD = 0x0000401c,
	SECONDARY_VM_EXEC_CONTROL = 0x0000401e,
	PLE_GAP = 0x00004020,
	PLE_WINDOW = 0x00004022,
	NOTIFY_WINDOW = 0x00004024,
	VM_INSTRUCTION_ERROR = 0x00004400,
	VM_EXIT_REASON = 0x00004402,
	VM_EXIT_INTR_INFO = 0x00004404,
	VM_EXIT_INTR_ERROR_CODE = 0x00004406,
	IDT_VECTORING_INFO_FIELD = 0x00004408,
	IDT_VECTORING_ERROR_CODE = 0x0000440a,
	VM_EXIT_INSTRUCTION_LEN = 0x0000440c,
	VMX_INSTRUCTION_INFO = 0x0000440e,
	GUEST_ES_LIMIT = 0x00004800,
	GUEST_CS_LIMIT = 0x00004802,
	GUEST_SS_LIMIT = 0x00004804,
	GUEST_DS_LIMIT = 0x00004806,
	GUEST_FS_LIMIT = 0x00004808,
	GUEST_GS_LIMIT = 0x0000480a,
	GUEST_LDTR_LIMIT = 0x0000480c,
	GUEST_TR_LIMIT = 0x0000480e,
	GUEST_GDTR_LIMIT = 0x00004810,
	GUEST_IDTR_LIMIT = 0x00004812,
	GUEST_ES_AR_BYTES = 0x00004814,
	GUEST_CS_AR_BYTES = 0x00004816,
	GUEST_SS_AR_BYTES = 0x00004818,
	GUEST_DS_AR_BYTES = 0x0000481a,
	GUEST_FS_AR_BYTES = 0x0000481c,
	GUEST_GS_AR_BYTES = 0x0000481e,
	GUEST_LDTR_AR_BYTES = 0x00004820,
	GUEST_TR_AR_BYTES = 0x00004822,
	GUEST_INTERRUPTIBILITY_INFO = 0x00004824,
	GUEST_ACTIVITY_STATE = 0x00004826,
	GUEST_SYSENTER_CS = 0x0000482A,
	VMX_PREEMPTION_TIMER_VALUE = 0x0000482E,
	HOST_IA32_SYSENTER_CS = 0x00004c00,
	CR0_GUEST_HOST_MASK = 0x00006000,
	CR4_GUEST_HOST_MASK = 0x00006002,
	CR0_READ_SHADOW = 0x00006004,
	CR4_READ_SHADOW = 0x00006006,
	CR3_TARGET_VALUE0 = 0x00006008,
	CR3_TARGET_VALUE1 = 0x0000600a,
	CR3_TARGET_VALUE2 = 0x0000600c,
	CR3_TARGET_VALUE3 = 0x0000600e,
	EXIT_QUALIFICATION = 0x00006400,
	GUEST_LINEAR_ADDRESS = 0x0000640a,
	GUEST_CR0 = 0x00006800,
	GUEST_CR3 = 0x00006802,
	GUEST_CR4 = 0x00006804,
	GUEST_ES_BASE = 0x00006806,
	GUEST_CS_BASE = 0x00006808,
	GUEST_SS_BASE = 0x0000680a,
	GUEST_DS_BASE = 0x0000680c,
	GUEST_FS_BASE = 0x0000680e,
	GUEST_GS_BASE = 0x00006810,
	GUEST_LDTR_BASE = 0x00006812,
	GUEST_TR_BASE = 0x00006814,
	GUEST_GDTR_BASE = 0x00006816,
	GUEST_IDTR_BASE = 0x00006818,
	GUEST_DR7 = 0x0000681a,
	GUEST_RSP = 0x0000681c,
	GUEST_RIP = 0x0000681e,
	GUEST_RFLAGS = 0x00006820,
	GUEST_PENDING_DBG_EXCEPTIONS = 0x00006822,
	GUEST_SYSENTER_ESP = 0x00006824,
	GUEST_SYSENTER_EIP = 0x00006826,
	HOST_CR0 = 0x00006c00,
	HOST_CR3 = 0x00006c02,
	HOST_CR4 = 0x00006c04,
	HOST_FS_BASE = 0x00006c06,
	HOST_GS_BASE = 0x00006c08,
	HOST_TR_BASE = 0x00006c0a,
	HOST_GDTR_BASE = 0x00006c0c,
	HOST_IDTR_BASE = 0x00006c0e,
	HOST_IA32_SYSENTER_ESP = 0x00006c10,
	HOST_IA32_SYSENTER_EIP = 0x00006c12,
	HOST_RSP = 0x00006c14,
	HOST_RIP = 0x00006c16,
};

/* GUEST_INTERRUPTIBILITY_INFO flags. */
#define GUEST_INTR_STATE_STI		0x00000001
#define GUEST_INTR_STATE_MOV_SS		0x00000002
#define GUEST_INTR_STATE_SMI		0x00000004
#define GUEST_INTR_STATE_NMI		0x00000008




/* GUEST_ACTIVITY_STATE flags */
#define GUEST_ACTIVITY_ACTIVE		0
#define GUEST_ACTIVITY_HLT		1
#define GUEST_ACTIVITY_SHUTDOWN		2
#define GUEST_ACTIVITY_WAIT_SIPI	3

 /*
  * Definitions of Secondary Processor-Based VM-Execution Controls.
  */
#define SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES VMCS_CONTROL_BIT(VIRT_APIC_ACCESSES)
/*
* 启用EPT机制，由此产生GPA和HPA两个概念
* 由于这两种物理地址的出现，在guest内部的线性地址过程中又产生了与这两种物理地址
* 相对应的页转换表结构
* 1. guest paging-structure
* 2. EPT paging-structure
* guest-physical address和host-physical address的产生是为了实现CPU的内存虚拟化管理
*/
#define SECONDARY_EXEC_ENABLE_EPT               VMCS_CONTROL_BIT(EPT)
/*
* VMX non-root operation 内使用LGDT,LIDT,LTR，SGDT，SIDT，SLDT以及STR指令来访问描述
* 符表寄存器将产生VM-exit
*/
#define SECONDARY_EXEC_DESC			VMCS_CONTROL_BIT(DESC_EXITING)
/*
* VMX non-root operation内允许使用RDTSCP指令，否则执行RDTSCP指令将产生#UD异常
*/
#define SECONDARY_EXEC_ENABLE_RDTSCP		VMCS_CONTROL_BIT(RDTSCP)
#define SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE   VMCS_CONTROL_BIT(VIRTUAL_X2APIC)
/*
* 允许为线性地址转换cache提供一个VPID值
* 线性地址转换cache能缓存两类信息：
* (1) EPT机制未使用时，线性地址转换为物理地址的linear mappings
* (2) EPT机制使用时，线性地址转换为HPA的combined mappings
* VPID为每个虚拟处理器定义了一个虚拟处理器域的概念
* 即每次VM-entry时，为虚拟处理器在virtual processor identifier字段中提供一个VPID值。
* 这个VPID值将对应该虚拟处理器下的所有线性地址转换cache.
* INVVPID指令可以用来刷新VPID值对应的所有线性地址转换cache，包括线性映射及合并映射
*/
#define SECONDARY_EXEC_ENABLE_VPID              VMCS_CONTROL_BIT(VPID)
#define SECONDARY_EXEC_WBINVD_EXITING		VMCS_CONTROL_BIT(WBINVD_EXITING)
#define SECONDARY_EXEC_UNRESTRICTED_GUEST	VMCS_CONTROL_BIT(UNRESTRICTED_GUEST)
#define SECONDARY_EXEC_APIC_REGISTER_VIRT       VMCS_CONTROL_BIT(APIC_REGISTER_VIRT)
#define SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY    VMCS_CONTROL_BIT(VIRT_INTR_DELIVERY)
#define SECONDARY_EXEC_PAUSE_LOOP_EXITING	VMCS_CONTROL_BIT(PAUSE_LOOP_EXITING)
#define SECONDARY_EXEC_RDRAND_EXITING		VMCS_CONTROL_BIT(RDRAND_EXITING)
/*
* 在VMX non-root operation 中允许执行invpcid指令，否则将产生#UD异常
*/
#define SECONDARY_EXEC_ENABLE_INVPCID		VMCS_CONTROL_BIT(INVPCID)
#define SECONDARY_EXEC_ENABLE_VMFUNC            VMCS_CONTROL_BIT(VMFUNC)
#define SECONDARY_EXEC_SHADOW_VMCS              VMCS_CONTROL_BIT(SHADOW_VMCS)
#define SECONDARY_EXEC_ENCLS_EXITING		VMCS_CONTROL_BIT(ENCLS_EXITING)
#define SECONDARY_EXEC_RDSEED_EXITING		VMCS_CONTROL_BIT(RDSEED_EXITING)
#define SECONDARY_EXEC_ENABLE_PML               VMCS_CONTROL_BIT(PAGE_MOD_LOGGING)
#define SECONDARY_EXEC_PT_CONCEAL_VMX		VMCS_CONTROL_BIT(PT_CONCEAL_VMX)
/*
* 在VMX non-root operation 中允许执行xsave/xrstors指令，否则将产生#UD异常
*/
#define SECONDARY_EXEC_XSAVES			VMCS_CONTROL_BIT(XSAVES)
#define SECONDARY_EXEC_MODE_BASED_EPT_EXEC	VMCS_CONTROL_BIT(MODE_BASED_EPT_EXEC)
#define SECONDARY_EXEC_PT_USE_GPA		VMCS_CONTROL_BIT(PT_USE_GPA)
#define SECONDARY_EXEC_TSC_SCALING              VMCS_CONTROL_BIT(TSC_SCALING)
#define SECONDARY_EXEC_ENABLE_USR_WAIT_PAUSE	VMCS_CONTROL_BIT(USR_WAIT_PAUSE)
#define SECONDARY_EXEC_BUS_LOCK_DETECTION	VMCS_CONTROL_BIT(BUS_LOCK_DETECTION)
#define SECONDARY_EXEC_NOTIFY_VM_EXITING	VMCS_CONTROL_BIT(NOTIFY_VM_EXITING)


#define PIN_BASED_EXT_INTR_MASK                 VMCS_CONTROL_BIT(INTR_EXITING)
#define PIN_BASED_NMI_EXITING                   VMCS_CONTROL_BIT(NMI_EXITING)
#define PIN_BASED_VIRTUAL_NMIS                  VMCS_CONTROL_BIT(VIRTUAL_NMIS)
#define PIN_BASED_VMX_PREEMPTION_TIMER          VMCS_CONTROL_BIT(PREEMPTION_TIMER)
#define PIN_BASED_POSTED_INTR                   VMCS_CONTROL_BIT(POSTED_INTR)

#define VM_EXIT_SAVE_DEBUG_CONTROLS             0x00000004
#define VM_EXIT_HOST_ADDR_SPACE_SIZE            0x00000200
#define VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL      0x00001000
#define VM_EXIT_ACK_INTR_ON_EXIT                0x00008000
#define VM_EXIT_SAVE_IA32_PAT			0x00040000
#define VM_EXIT_LOAD_IA32_PAT			0x00080000
#define VM_EXIT_SAVE_IA32_EFER                  0x00100000
#define VM_EXIT_LOAD_IA32_EFER                  0x00200000
#define VM_EXIT_SAVE_VMX_PREEMPTION_TIMER       0x00400000
#define VM_EXIT_CLEAR_BNDCFGS                   0x00800000
#define VM_EXIT_PT_CONCEAL_PIP			0x01000000
#define VM_EXIT_CLEAR_IA32_RTIT_CTL		0x02000000


#define VM_EXIT_ALWAYSON_WITHOUT_TRUE_MSR	0x00036dff

#define VM_ENTRY_IA32E_MODE                     0x00000200
#define VM_ENTRY_SMM                            0x00000400
#define VM_ENTRY_DEACT_DUAL_MONITOR             0x00000800
#define VM_ENTRY_LOAD_IA32_PAT			0x00004000

#define VM_ENTRY_ALWAYSON_WITHOUT_TRUE_MSR	0x000011ff

#define VMX_EPT_EXTENT_INDIVIDUAL_ADDR		0
#define VMX_EPT_EXTENT_CONTEXT			1
#define VMX_EPT_EXTENT_GLOBAL			2

#define VMX_EPT_EXECUTE_ONLY_BIT		(1ull)
#define VMX_EPT_PAGE_WALK_4_BIT			(1ull << 6)
#define VMX_EPTP_UC_BIT				(1ull << 8)
#define VMX_EPTP_WB_BIT				(1ull << 14)
#define VMX_EPT_2MB_PAGE_BIT			(1ull << 16)
#define VMX_EPT_AD_BIT				    (1ull << 21)
#define VMX_EPT_EXTENT_INDIVIDUAL_BIT		(1ull << 24)
#define VMX_EPT_EXTENT_CONTEXT_BIT		(1ull << 25)
#define VMX_EPT_EXTENT_GLOBAL_BIT		(1ull << 26)

#define VMX_EPT_DEFAULT_GAW			3
#define VMX_EPT_MAX_GAW				0x4
#define VMX_EPT_MT_EPTE_SHIFT			3
#define VMX_EPT_GAW_EPTP_SHIFT			3
#define VMX_EPT_DEFAULT_MT			0x6ull
#define VMX_EPT_READABLE_MASK			0x1ull
#define VMX_EPT_WRITABLE_MASK			0x2ull
#define VMX_EPT_EXECUTABLE_MASK			0x4ull
#define VMX_EPT_IGMT_BIT    			(1ull << 6)

#define VMX_EPT_IDENTITY_PAGETABLE_ADDR		0xfffbc000ul

#define VMX_NR_VPIDS				(1 << 16)



#define VM_EXIT_SAVE_DEBUG_CONTROLS             0x00000004
#define VM_EXIT_HOST_ADDR_SPACE_SIZE            0x00000200
#define VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL      0x00001000
#define VM_EXIT_ACK_INTR_ON_EXIT                0x00008000
#define VM_EXIT_SAVE_IA32_PAT			0x00040000
#define VM_EXIT_LOAD_IA32_PAT			0x00080000
#define VM_EXIT_SAVE_IA32_EFER                  0x00100000
#define VM_EXIT_LOAD_IA32_EFER                  0x00200000
#define VM_EXIT_SAVE_VMX_PREEMPTION_TIMER       0x00400000
#define VM_EXIT_CLEAR_BNDCFGS                   0x00800000
#define VM_EXIT_PT_CONCEAL_PIP			0x01000000
#define VM_EXIT_CLEAR_IA32_RTIT_CTL		0x02000000

#define VM_EXIT_ALWAYSON_WITHOUT_TRUE_MSR	0x00036dff

#define VM_ENTRY_LOAD_DEBUG_CONTROLS            0x00000004
#define VM_ENTRY_IA32E_MODE                     0x00000200
#define VM_ENTRY_SMM                            0x00000400
#define VM_ENTRY_DEACT_DUAL_MONITOR             0x00000800
#define VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL     0x00002000
#define VM_ENTRY_LOAD_IA32_PAT			0x00004000
#define VM_ENTRY_LOAD_IA32_EFER                 0x00008000
#define VM_ENTRY_LOAD_BNDCFGS                   0x00010000
#define VM_ENTRY_PT_CONCEAL_PIP			0x00020000
#define VM_ENTRY_LOAD_IA32_RTIT_CTL		0x00040000

enum vmx_l1d_flush_state {
	VMENTER_L1D_FLUSH_AUTO,
	VMENTER_L1D_FLUSH_NEVER,
	VMENTER_L1D_FLUSH_COND,
	VMENTER_L1D_FLUSH_ALWAYS,
	VMENTER_L1D_FLUSH_EPT_DISABLED,
	VMENTER_L1D_FLUSH_NOT_REQUIRED,
};




#define VMX_VPID_INVVPID_BIT                    (1ull << 0) /* (32 - 32) */
#define VMX_VPID_EXTENT_INDIVIDUAL_ADDR_BIT     (1ull << 8) /* (40 - 32) */
#define VMX_VPID_EXTENT_SINGLE_CONTEXT_BIT      (1ull << 9) /* (41 - 32) */
#define VMX_VPID_EXTENT_GLOBAL_CONTEXT_BIT      (1ull << 10) /* (42 - 32) */
#define VMX_VPID_EXTENT_SINGLE_NON_GLOBAL_BIT   (1ull << 11) /* (43 - 32) */

#define VMX_EPT_MT_EPTE_SHIFT			3
#define VMX_EPTP_PWL_MASK			0x38ull
#define VMX_EPTP_PWL_4				0x18ull
#define VMX_EPTP_PWL_5				0x20ull
#define VMX_EPTP_AD_ENABLE_BIT			(1ull << 6)
#define VMX_EPTP_MT_MASK			0x7ull
#define VMX_EPTP_MT_WB				0x6ull
#define VMX_EPTP_MT_UC				0x0ull
#define VMX_EPT_READABLE_MASK			0x1ull
#define VMX_EPT_WRITABLE_MASK			0x2ull
#define VMX_EPT_EXECUTABLE_MASK			0x4ull
#define VMX_EPT_IPAT_BIT    			(1ull << 6)
#define VMX_EPT_ACCESS_BIT			(1ull << 8)
#define VMX_EPT_DIRTY_BIT			(1ull << 9)
#define VMX_EPT_RWX_MASK                        (VMX_EPT_READABLE_MASK |       \
						 VMX_EPT_WRITABLE_MASK |       \
						 VMX_EPT_EXECUTABLE_MASK)
#define VMX_EPT_MT_MASK				(7ull << VMX_EPT_MT_EPTE_SHIFT)


#define __KVM_REQUIRED_VMX_CPU_BASED_VM_EXEC_CONTROL			\
	(CPU_BASED_HLT_EXITING |					\
	 CPU_BASED_CR3_LOAD_EXITING |					\
	 CPU_BASED_CR3_STORE_EXITING |					\
	 CPU_BASED_UNCOND_IO_EXITING |					\
	 CPU_BASED_MOV_DR_EXITING |					\
	 CPU_BASED_USE_TSC_OFFSETTING |					\
	 CPU_BASED_MWAIT_EXITING |					\
	 CPU_BASED_MONITOR_EXITING |					\
	 CPU_BASED_INVLPG_EXITING |					\
	 CPU_BASED_RDPMC_EXITING |					\
	 CPU_BASED_INTR_WINDOW_EXITING)

#ifdef _WIN64
#define MAX_NR_USER_RETURN_MSRS	7
#else
#define MAX_NR_USER_RETURN_MSRS	4
#endif

#ifdef _WIN64
	#define KVM_REQUIRED_VMX_CPU_BASED_VM_EXEC_CONTROL		\
		(__KVM_REQUIRED_VMX_CPU_BASED_VM_EXEC_CONTROL |		\
		 CPU_BASED_CR8_LOAD_EXITING |				\
		 CPU_BASED_CR8_STORE_EXITING)
#else
	#define KVM_REQUIRED_VMX_CPU_BASED_VM_EXEC_CONTROL		\
		__KVM_REQUIRED_VMX_CPU_BASED_VM_EXEC_CONTROL
#endif

#define KVM_OPTIONAL_VMX_CPU_BASED_VM_EXEC_CONTROL			\
	(CPU_BASED_RDTSC_EXITING |					\
	 CPU_BASED_TPR_SHADOW |						\
	 CPU_BASED_USE_IO_BITMAPS |					\
	 CPU_BASED_MONITOR_TRAP_FLAG |					\
	 CPU_BASED_USE_MSR_BITMAPS |					\
	 CPU_BASED_NMI_WINDOW_EXITING |					\
	 CPU_BASED_PAUSE_EXITING |					\
	 CPU_BASED_ACTIVATE_SECONDARY_CONTROLS |			\
	 CPU_BASED_ACTIVATE_TERTIARY_CONTROLS)

#define KVM_REQUIRED_VMX_SECONDARY_VM_EXEC_CONTROL 0
#define KVM_OPTIONAL_VMX_SECONDARY_VM_EXEC_CONTROL			\
	(SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES |			\
	 SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE |			\
	 SECONDARY_EXEC_WBINVD_EXITING |				\
	 SECONDARY_EXEC_ENABLE_VPID |					\
	 SECONDARY_EXEC_ENABLE_EPT |					\
	 SECONDARY_EXEC_UNRESTRICTED_GUEST |				\
	 SECONDARY_EXEC_PAUSE_LOOP_EXITING |				\
	 SECONDARY_EXEC_DESC |						\
	 SECONDARY_EXEC_ENABLE_RDTSCP |					\
	 SECONDARY_EXEC_ENABLE_INVPCID |				\
	 SECONDARY_EXEC_APIC_REGISTER_VIRT |				\
	 SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY |				\
	 SECONDARY_EXEC_SHADOW_VMCS |					\
	 SECONDARY_EXEC_XSAVES |					\
	 SECONDARY_EXEC_RDSEED_EXITING |				\
	 SECONDARY_EXEC_RDRAND_EXITING |				\
	 SECONDARY_EXEC_ENABLE_PML |					\
	 SECONDARY_EXEC_TSC_SCALING |					\
	 SECONDARY_EXEC_ENABLE_USR_WAIT_PAUSE |				\
	 SECONDARY_EXEC_PT_USE_GPA |					\
	 SECONDARY_EXEC_PT_CONCEAL_VMX |				\
	 SECONDARY_EXEC_ENABLE_VMFUNC |					\
	 SECONDARY_EXEC_BUS_LOCK_DETECTION |				\
	 SECONDARY_EXEC_NOTIFY_VM_EXITING |				\
	 SECONDARY_EXEC_ENCLS_EXITING)

#define KVM_REQUIRED_VMX_TERTIARY_VM_EXEC_CONTROL 0
#define KVM_OPTIONAL_VMX_TERTIARY_VM_EXEC_CONTROL			\
	(TERTIARY_EXEC_IPI_VIRT)

#define __KVM_REQUIRED_VMX_VM_EXIT_CONTROLS				\
	(VM_EXIT_SAVE_DEBUG_CONTROLS |					\
	 VM_EXIT_ACK_INTR_ON_EXIT)
#ifdef _WIN64
#define KVM_REQUIRED_VMX_VM_EXIT_CONTROLS			\
		(__KVM_REQUIRED_VMX_VM_EXIT_CONTROLS |			\
		 VM_EXIT_HOST_ADDR_SPACE_SIZE)
#else
#define KVM_REQUIRED_VMX_VM_EXIT_CONTROLS			\
		__KVM_REQUIRED_VMX_VM_EXIT_CONTROLS
#endif
#define KVM_OPTIONAL_VMX_VM_EXIT_CONTROLS				\
	      (VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL |			\
	       VM_EXIT_SAVE_IA32_PAT |					\
	       VM_EXIT_LOAD_IA32_PAT |					\
	       VM_EXIT_SAVE_IA32_EFER |					\
	       VM_EXIT_SAVE_VMX_PREEMPTION_TIMER |			\
	       VM_EXIT_LOAD_IA32_EFER |					\
	       VM_EXIT_CLEAR_BNDCFGS |					\
	       VM_EXIT_PT_CONCEAL_PIP |					\
	       VM_EXIT_CLEAR_IA32_RTIT_CTL)



#define KVM_REQUIRED_VMX_PIN_BASED_VM_EXEC_CONTROL			\
	(PIN_BASED_EXT_INTR_MASK |					\
	 PIN_BASED_NMI_EXITING)
#define KVM_OPTIONAL_VMX_PIN_BASED_VM_EXEC_CONTROL			\
	(PIN_BASED_VIRTUAL_NMIS |					\
	 PIN_BASED_POSTED_INTR |					\
	 PIN_BASED_VMX_PREEMPTION_TIMER)

#define __KVM_REQUIRED_VMX_VM_ENTRY_CONTROLS				\
	(VM_ENTRY_LOAD_DEBUG_CONTROLS)
#ifdef _WIN64
#define KVM_REQUIRED_VMX_VM_ENTRY_CONTROLS			\
		(__KVM_REQUIRED_VMX_VM_ENTRY_CONTROLS |			\
		 VM_ENTRY_IA32E_MODE)
#else
#define KVM_REQUIRED_VMX_VM_ENTRY_CONTROLS			\
		__KVM_REQUIRED_VMX_VM_ENTRY_CONTROLS
#endif
#define KVM_OPTIONAL_VMX_VM_ENTRY_CONTROLS				\
	(VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL |				\
	 VM_ENTRY_LOAD_IA32_PAT |					\
	 VM_ENTRY_LOAD_IA32_EFER |					\
	 VM_ENTRY_LOAD_BNDCFGS |					\
	 VM_ENTRY_PT_CONCEAL_PIP |					\
	 VM_ENTRY_LOAD_IA32_RTIT_CTL)

#define VMX_MISC_PREEMPTION_TIMER_RATE_MASK	0x0000001f
#define VMX_MISC_SAVE_EFER_LMA			0x00000020
#define VMX_MISC_ACTIVITY_HLT			0x00000040
#define VMX_MISC_ACTIVITY_WAIT_SIPI		0x00000100
#define VMX_MISC_ZERO_LEN_INS			0x40000000
#define VMX_MISC_MSR_LIST_MULTIPLIER		512

#define VMX_EPT_RWX_MASK                        (VMX_EPT_READABLE_MASK |       \
						 VMX_EPT_WRITABLE_MASK |       \
						 VMX_EPT_EXECUTABLE_MASK)

/*
 * VMX_REGS_LAZY_LOAD_SET - The set of registers that will be updated in the
 * cache on demand.  Other registers not listed here are synced to
 * the cache immediately after VM-Exit.
 */
#define VMX_REGS_LAZY_LOAD_SET	((1 << VCPU_REGS_RIP) |         \
				(1 << VCPU_REGS_RSP) |          \
				(1 << VCPU_EXREG_RFLAGS) |      \
				(1 << VCPU_EXREG_PDPTR) |       \
				(1 << VCPU_EXREG_SEGMENTS) |    \
				(1 << VCPU_EXREG_CR0) |         \
				(1 << VCPU_EXREG_CR3) |         \
				(1 << VCPU_EXREG_CR4) |         \
				(1 << VCPU_EXREG_EXIT_INFO_1) | \
				(1 << VCPU_EXREG_EXIT_INFO_2))


/*
 * Exit Qualifications for EPT Violations
 */
#define EPT_VIOLATION_ACC_READ_BIT	0
#define EPT_VIOLATION_ACC_WRITE_BIT	1
#define EPT_VIOLATION_ACC_INSTR_BIT	2
#define EPT_VIOLATION_RWX_SHIFT		3
#define EPT_VIOLATION_GVA_IS_VALID_BIT	7
#define EPT_VIOLATION_GVA_TRANSLATED_BIT 8
#define EPT_VIOLATION_ACC_READ		(1 << EPT_VIOLATION_ACC_READ_BIT)
#define EPT_VIOLATION_ACC_WRITE		(1 << EPT_VIOLATION_ACC_WRITE_BIT)
#define EPT_VIOLATION_ACC_INSTR		(1 << EPT_VIOLATION_ACC_INSTR_BIT)
#define EPT_VIOLATION_RWX_MASK		(VMX_EPT_RWX_MASK << EPT_VIOLATION_RWX_SHIFT)
#define EPT_VIOLATION_GVA_IS_VALID	(1 << EPT_VIOLATION_GVA_IS_VALID_BIT)
#define EPT_VIOLATION_GVA_TRANSLATED	(1 << EPT_VIOLATION_GVA_TRANSLATED_BIT)

 /*
  * Exit Qualifications for NOTIFY VM EXIT
  */
#define NOTIFY_VM_CONTEXT_INVALID     BIT(0)

struct vmx_uret_msr {
	bool load_into_hardware;
	u64 data;
	u64 mask;
};

union vmx_exit_reason {
	struct {
		u32	basic : 16;
		u32	reserved16 : 1;
		u32	reserved17 : 1;
		u32	reserved18 : 1;
		u32	reserved19 : 1;
		u32	reserved20 : 1;
		u32	reserved21 : 1;
		u32	reserved22 : 1;
		u32	reserved23 : 1;
		u32	reserved24 : 1;
		u32	reserved25 : 1;
		u32	bus_lock_detected : 1;
		u32	enclave_mode : 1;
		u32	smi_pending_mtf : 1;
		u32	smi_from_vmx_root : 1;
		u32	reserved30 : 1;
		u32	failed_vmentry : 1;
	};
	u32 full;
};

/* The mask to use to trigger an EPT Misconfiguration in order to track MMIO */
#define VMX_EPT_MISCONFIG_WX_VALUE		(VMX_EPT_WRITABLE_MASK |       \
						 VMX_EPT_EXECUTABLE_MASK)

#define VMX_EPT_IDENTITY_PAGETABLE_ADDR		0xfffbc000ul

#include <pshpck16.h>
struct vmx_msr_entry {
	u32 index;
	u32 reserved;
	u64 value;
};
#include <poppack.h>

#define MAX_NR_LOADSTORE_MSRS	8

struct vmx_msrs {
	unsigned int		nr;
	struct vmx_msr_entry	val[MAX_NR_LOADSTORE_MSRS];
};


#define RTIT_ADDR_RANGE		4

struct pt_ctx {
	u64 ctl;
	u64 status;
	u64 output_base;
	u64 output_mask;
	u64 cr3_match;
	u64 addr_a[RTIT_ADDR_RANGE];
	u64 addr_b[RTIT_ADDR_RANGE];
};

struct pt_desc {
	u64 ctl_bitmask;
	u32 num_address_ranges;
	u32 caps[PT_CPUID_REGS_NUM * PT_CPUID_LEAVES];
	struct pt_ctx host;
	struct pt_ctx guest;
};


/*
 * The nested_vmx structure is part of vcpu_vmx, and holds information we need
 * for correct emulation of VMX (i.e., nested VMX) on this vcpu.
 */
struct nested_vmx {
	/* Has the level1 guest done vmxon? */
	bool vmxon;
	gpa_t vmxon_ptr;
	bool pml_full;

	/* The guest-physical address of the current VMCS L1 keeps for L2 */
	gpa_t current_vmptr;
	/*
	 * Cache of the guest's VMCS, existing outside of guest memory.
	 * Loaded from guest memory during VMPTRLD. Flushed to guest
	 * memory during VMCLEAR and VMPTRLD.
	 */
	struct vmcs12* cached_vmcs12;
	/*
	 * Cache of the guest's shadow VMCS, existing outside of guest
	 * memory. Loaded from guest memory during VM entry. Flushed
	 * to guest memory during VM exit.
	 */
	struct vmcs12* cached_shadow_vmcs12;

	/*
	 * GPA to HVA cache for accessing vmcs12->vmcs_link_pointer
	 */
	struct gfn_to_hva_cache shadow_vmcs12_cache;

	/*
	 * GPA to HVA cache for VMCS12
	 */
	struct gfn_to_hva_cache vmcs12_cache;

	/*
	 * Indicates if the shadow vmcs or enlightened vmcs must be updated
	 * with the data held by struct vmcs12.
	 */
	bool need_vmcs12_to_shadow_sync;
	bool dirty_vmcs12;

	/*
	 * Indicates whether MSR bitmap for L2 needs to be rebuilt due to
	 * changes in MSR bitmap for L1 or switching to a different L2. Note,
	 * this flag can only be used reliably in conjunction with a paravirt L1
	 * which informs L0 whether any changes to MSR bitmap for L2 were done
	 * on its side.
	 */
	bool force_msr_bitmap_recalc;

	/*
	 * Indicates lazily loaded guest state has not yet been decached from
	 * vmcs02.
	 */
	bool need_sync_vmcs02_to_vmcs12_rare;

	/*
	 * vmcs02 has been initialized, i.e. state that is constant for
	 * vmcs02 has been written to the backing VMCS.  Initialization
	 * is delayed until L1 actually attempts to run a nested VM.
	 */
	bool vmcs02_initialized;

	bool change_vmcs01_virtual_apic_mode;
	bool reload_vmcs01_apic_access_page;
	bool update_vmcs01_cpu_dirty_logging;
	bool update_vmcs01_apicv_status;

	/*
	 * Enlightened VMCS has been enabled. It does not mean that L1 has to
	 * use it. However, VMX features available to L1 will be limited based
	 * on what the enlightened VMCS supports.
	 */
	bool enlightened_vmcs_enabled;

	/* L2 must run next, and mustn't decide to exit to L1. */
	bool nested_run_pending;

	/* Pending MTF VM-exit into L1.  */
	bool mtf_pending;

	struct loaded_vmcs vmcs02;

	/*
	 * Guest pages referred to in the vmcs02 with host-physical
	 * pointers, so we must keep them pinned while L2 runs.
	 */
	struct kvm_host_map apic_access_page_map;
	struct kvm_host_map virtual_apic_map;
	struct kvm_host_map pi_desc_map;

	struct kvm_host_map msr_bitmap_map;

	struct pi_desc* pi_desc;
	bool pi_pending;
	u16 posted_intr_nv;

	u64 preemption_timer_deadline;
	bool has_preemption_timer_deadline;
	bool preemption_timer_expired;

	/*
	 * Used to snapshot MSRs that are conditionally loaded on VM-Enter in
	 * order to propagate the guest's pre-VM-Enter value into vmcs02.  For
	 * emulation of VMLAUNCH/VMRESUME, the snapshot will be of L1's value.
	 * For KVM_SET_NESTED_STATE, the snapshot is of L2's value, _if_
	 * userspace restores MSRs before nested state.  If userspace restores
	 * MSRs after nested state, the snapshot holds garbage, but KVM can't
	 * detect that, and the garbage value in vmcs02 will be overwritten by
	 * MSR restoration in any case.
	 */
	u64 pre_vmenter_debugctl;
	u64 pre_vmenter_bndcfgs;

	/* to migrate it to L1 if L2 writes to L1's CR8 directly */
	int l1_tpr_threshold;

	u16 vpid02;
	u16 last_vpid;

	struct nested_vmx_msrs msrs;

	/* SMM related state */
	struct {
		/* in VMX operation on SMM entry? */
		bool vmxon;
		/* in guest mode on SMM entry? */
		bool guest_mode;
	} smm;

	gpa_t hv_evmcs_vmptr;
	struct kvm_host_map hv_evmcs_map;
	struct hv_enlightened_vmcs* hv_evmcs;
};

struct vcpu_vmx {
	struct kvm_vcpu vcpu;
	u8                    fail;
	u8		      x2apic_msr_bitmap_mode;

	/*
	 * If true, host state has been stored in vmx->loaded_vmcs for
	 * the CPU registers that only need to be switched when transitioning
	 * to/from the kernel, and the registers have been loaded with guest
	 * values.  If false, host state is loaded in the CPU registers
	 * and vmx->loaded_vmcs->host_state is invalid.
	 */
	bool		      guest_state_loaded;

	unsigned long         exit_qualification;
	u32                   exit_intr_info;
	u32                   idt_vectoring_info;
	ULONG_PTR                 rflags;

	/*
	 * User return MSRs are always emulated when enabled in the guest, but
	 * only loaded into hardware when necessary, e.g. SYSCALL #UDs outside
	 * of 64-bit mode or if EFER.SCE=1, thus the SYSCALL MSRs don't need to
	 * be loaded into hardware if those conditions aren't met.
	 */
	struct vmx_uret_msr   guest_uret_msrs[MAX_NR_USER_RETURN_MSRS];
	bool                  guest_uret_msrs_loaded;
#ifdef _WIN64
	u64		      msr_host_kernel_gs_base;
	u64		      msr_guest_kernel_gs_base;
#endif

	u64		      spec_ctrl;
	u32		      msr_ia32_umwait_control;

	/*
	 * loaded_vmcs points to the VMCS currently used in this vcpu. For a
	 * non-nested (L1) guest, it always points to vmcs01. For a nested
	 * guest (L2), it points to a different VMCS.
	 */
	struct loaded_vmcs    vmcs01;
	struct loaded_vmcs* loaded_vmcs;

	struct msr_autoload {
		struct vmx_msrs guest;
		struct vmx_msrs host;
	} msr_autoload;

	struct msr_autostore {
		struct vmx_msrs guest;
	} msr_autostore;

	struct {
		int vm86_active;
		ULONG_PTR save_rflags;
		struct kvm_segment segs[8];
	} rmode;
	struct {
		u32 bitmask; /* 4 bits per segment (1 bit per field) */
		struct kvm_save_segment {
			u16 selector;
			ULONG_PTR base;
			u32 limit;
			u32 ar;
		} seg[8];
	} segment_cache;
	ULONG vpid;
	bool emulation_required;

	union vmx_exit_reason exit_reason;

	/* Posted interrupt descriptor */
	struct pi_desc pi_desc;

	/* Used if this vCPU is waiting for PI notification wakeup. */

	/* Support for a guest hypervisor (nested VMX) */
	struct nested_vmx nested;

	/* Dynamic PLE window. */
	unsigned int ple_window;
	bool ple_window_dirty;

	bool req_immediate_exit;

	/* Support for PML */
#define PML_ENTITY_NUM		512
	struct page* pml_pg;

	/* apic deadline value in host tsc */
	u64 hv_deadline_tsc;

	unsigned long host_debugctlmsr;

	/*
	 * Only bits masked by msr_ia32_feature_control_valid_bits can be set in
	 * msr_ia32_feature_control. FEAT_CTL_LOCKED is always included
	 * in msr_ia32_feature_control_valid_bits.
	 */
	u64 msr_ia32_feature_control;
	u64 msr_ia32_feature_control_valid_bits;
	/* SGX Launch Control public key hash */
	u64 msr_ia32_sgxlepubkeyhash[4];
	u64 msr_ia32_mcu_opt_ctrl;
	bool disable_fb_clear;

	struct pt_desc pt_desc;
	//struct lbr_desc lbr_desc;

	/* Save desired MSR intercept (read: pass-through) state */
#define MAX_POSSIBLE_PASSTHROUGH_MSRS	16
};

struct kvm_vmx {
	struct kvm kvm;

	unsigned int tss_addr;
	bool ept_identity_pagetable_done;
	gpa_t ept_identity_map_addr;
	/* Posted Interrupt Descriptor (PID) table for IPI virtualization */
	u64* pid_table;
};



/*
 * Note, early Intel manuals have the write-low and read-high bitmap offsets
 * the wrong way round.  The bitmaps control MSRs 0x00000000-0x00001fff and
 * 0xc0000000-0xc0001fff.  The former (low) uses bytes 0-0x3ff for reads and
 * 0x800-0xbff for writes.  The latter (high) uses 0x400-0x7ff for reads and
 * 0xc00-0xfff for writes.  MSRs not covered by either of the ranges always
 * VM-Exit.
 */
//#define __BUILD_VMX_MSR_BITMAP_HELPER(rtype, action, bitop, access, base)      \
//static inline rtype vmx_##action##_msr_bitmap_##access(unsigned long *bitmap,  \
//						       u32 msr)		       \
//{									       \
//	int f = sizeof(unsigned long);					       \
//									       \
//	if (msr <= 0x1fff)						       \
//		return bitop##_bit(msr, bitmap + base / f);		       \
//	else if ((msr >= 0xc0000000) && (msr <= 0xc0001fff))		       \
//		return bitop##_bit(msr & 0x1fff, bitmap + (base + 0x400) / f); \
//	return (rtype)TRUE;						       \
//}
//#define BUILD_VMX_MSR_BITMAP_HELPERS(ret_type, action, bitop)		       \
//	__BUILD_VMX_MSR_BITMAP_HELPER(ret_type, action, bitop, read,  0x0)     \
//	__BUILD_VMX_MSR_BITMAP_HELPER(ret_type, action, bitop, write, 0x800)
//
//BUILD_VMX_MSR_BITMAP_HELPERS(bool, test, test)
//BUILD_VMX_MSR_BITMAP_HELPERS(bool, clear, __clear)
//BUILD_VMX_MSR_BITMAP_HELPERS(bool, set, __set)
//
//static inline u8 vmx_get_rvi(void)
//{
//	return vmcs_read16(GUEST_INTR_STATUS) & 0xff;
//}

#define __KVM_REQUIRED_VMX_VM_ENTRY_CONTROLS				\
	(VM_ENTRY_LOAD_DEBUG_CONTROLS)
#ifdef _WIN64
#define KVM_REQUIRED_VMX_VM_ENTRY_CONTROLS			\
		(__KVM_REQUIRED_VMX_VM_ENTRY_CONTROLS |			\
		 VM_ENTRY_IA32E_MODE)
#else
#define KVM_REQUIRED_VMX_VM_ENTRY_CONTROLS			\
		__KVM_REQUIRED_VMX_VM_ENTRY_CONTROLS
#endif
#define KVM_OPTIONAL_VMX_VM_ENTRY_CONTROLS				\
	(VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL |				\
	 VM_ENTRY_LOAD_IA32_PAT |					\
	 VM_ENTRY_LOAD_IA32_EFER |					\
	 VM_ENTRY_LOAD_BNDCFGS |					\
	 VM_ENTRY_PT_CONCEAL_PIP |					\
	 VM_ENTRY_LOAD_IA32_RTIT_CTL)

#define __KVM_REQUIRED_VMX_VM_EXIT_CONTROLS				\
	(VM_EXIT_SAVE_DEBUG_CONTROLS |					\
	 VM_EXIT_ACK_INTR_ON_EXIT)
#ifdef _WIN64
#define KVM_REQUIRED_VMX_VM_EXIT_CONTROLS			\
		(__KVM_REQUIRED_VMX_VM_EXIT_CONTROLS |			\
		 VM_EXIT_HOST_ADDR_SPACE_SIZE)
#else
#define KVM_REQUIRED_VMX_VM_EXIT_CONTROLS			\
		__KVM_REQUIRED_VMX_VM_EXIT_CONTROLS
#endif
#define KVM_OPTIONAL_VMX_VM_EXIT_CONTROLS				\
	      (VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL |			\
	       VM_EXIT_SAVE_IA32_PAT |					\
	       VM_EXIT_LOAD_IA32_PAT |					\
	       VM_EXIT_SAVE_IA32_EFER |					\
	       VM_EXIT_SAVE_VMX_PREEMPTION_TIMER |			\
	       VM_EXIT_LOAD_IA32_EFER |					\
	       VM_EXIT_CLEAR_BNDCFGS |					\
	       VM_EXIT_PT_CONCEAL_PIP |					\
	       VM_EXIT_CLEAR_IA32_RTIT_CTL)

#define KVM_REQUIRED_VMX_PIN_BASED_VM_EXEC_CONTROL			\
	(PIN_BASED_EXT_INTR_MASK |					\
	 PIN_BASED_NMI_EXITING)
#define KVM_OPTIONAL_VMX_PIN_BASED_VM_EXEC_CONTROL			\
	(PIN_BASED_VIRTUAL_NMIS |					\
	 PIN_BASED_POSTED_INTR |					\
	 PIN_BASED_VMX_PREEMPTION_TIMER)

#define __KVM_REQUIRED_VMX_CPU_BASED_VM_EXEC_CONTROL			\
	(CPU_BASED_HLT_EXITING |					\
	 CPU_BASED_CR3_LOAD_EXITING |					\
	 CPU_BASED_CR3_STORE_EXITING |					\
	 CPU_BASED_UNCOND_IO_EXITING |					\
	 CPU_BASED_MOV_DR_EXITING |					\
	 CPU_BASED_USE_TSC_OFFSETTING |					\
	 CPU_BASED_MWAIT_EXITING |					\
	 CPU_BASED_MONITOR_EXITING |					\
	 CPU_BASED_INVLPG_EXITING |					\
	 CPU_BASED_RDPMC_EXITING |					\
	 CPU_BASED_INTR_WINDOW_EXITING)

#ifdef _WIN64
#define KVM_REQUIRED_VMX_CPU_BASED_VM_EXEC_CONTROL		\
		(__KVM_REQUIRED_VMX_CPU_BASED_VM_EXEC_CONTROL |		\
		 CPU_BASED_CR8_LOAD_EXITING |				\
		 CPU_BASED_CR8_STORE_EXITING)
#else
#define KVM_REQUIRED_VMX_CPU_BASED_VM_EXEC_CONTROL		\
		__KVM_REQUIRED_VMX_CPU_BASED_VM_EXEC_CONTROL
#endif

#define KVM_OPTIONAL_VMX_CPU_BASED_VM_EXEC_CONTROL			\
	(CPU_BASED_RDTSC_EXITING |					\
	 CPU_BASED_TPR_SHADOW |						\
	 CPU_BASED_USE_IO_BITMAPS |					\
	 CPU_BASED_MONITOR_TRAP_FLAG |					\
	 CPU_BASED_USE_MSR_BITMAPS |					\
	 CPU_BASED_NMI_WINDOW_EXITING |					\
	 CPU_BASED_PAUSE_EXITING |					\
	 CPU_BASED_ACTIVATE_SECONDARY_CONTROLS |			\
	 CPU_BASED_ACTIVATE_TERTIARY_CONTROLS)

#define KVM_REQUIRED_VMX_SECONDARY_VM_EXEC_CONTROL 0
#define KVM_OPTIONAL_VMX_SECONDARY_VM_EXEC_CONTROL			\
	(SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES |			\
	 SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE |			\
	 SECONDARY_EXEC_WBINVD_EXITING |				\
	 SECONDARY_EXEC_ENABLE_VPID |					\
	 SECONDARY_EXEC_ENABLE_EPT |					\
	 SECONDARY_EXEC_UNRESTRICTED_GUEST |				\
	 SECONDARY_EXEC_PAUSE_LOOP_EXITING |				\
	 SECONDARY_EXEC_DESC |						\
	 SECONDARY_EXEC_ENABLE_RDTSCP |					\
	 SECONDARY_EXEC_ENABLE_INVPCID |				\
	 SECONDARY_EXEC_APIC_REGISTER_VIRT |				\
	 SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY |				\
	 SECONDARY_EXEC_SHADOW_VMCS |					\
	 SECONDARY_EXEC_XSAVES |					\
	 SECONDARY_EXEC_RDSEED_EXITING |				\
	 SECONDARY_EXEC_RDRAND_EXITING |				\
	 SECONDARY_EXEC_ENABLE_PML |					\
	 SECONDARY_EXEC_TSC_SCALING |					\
	 SECONDARY_EXEC_ENABLE_USR_WAIT_PAUSE |				\
	 SECONDARY_EXEC_PT_USE_GPA |					\
	 SECONDARY_EXEC_PT_CONCEAL_VMX |				\
	 SECONDARY_EXEC_ENABLE_VMFUNC |					\
	 SECONDARY_EXEC_BUS_LOCK_DETECTION |				\
	 SECONDARY_EXEC_NOTIFY_VM_EXITING |				\
	 SECONDARY_EXEC_ENCLS_EXITING)

#define KVM_REQUIRED_VMX_TERTIARY_VM_EXEC_CONTROL 0
#define KVM_OPTIONAL_VMX_TERTIARY_VM_EXEC_CONTROL			\
	(TERTIARY_EXEC_IPI_VIRT)

#define BUILD_CONTROLS_SHADOW(lname, uname, bits)						\
static inline void lname##_controls_set(struct vcpu_vmx *vmx, u##bits val)			\
{												\
	if (vmx->loaded_vmcs->controls_shadow.lname != val) {					\
		vmcs_write##bits(uname, val);							\
		vmx->loaded_vmcs->controls_shadow.lname = val;					\
	}											\
}												\
static inline u##bits __##lname##_controls_get(struct loaded_vmcs *vmcs)			\
{												\
	return vmcs->controls_shadow.lname;							\
}												\
static inline u##bits lname##_controls_get(struct vcpu_vmx *vmx)				\
{												\
	return __##lname##_controls_get(vmx->loaded_vmcs);					\
}												\
static void lname##_controls_setbit(struct vcpu_vmx *vmx, u##bits val)		\
{												\
	lname##_controls_set(vmx, lname##_controls_get(vmx) | val);				\
}												\
static void lname##_controls_clearbit(struct vcpu_vmx *vmx, u##bits val)	\
{												\
	lname##_controls_set(vmx, lname##_controls_get(vmx) & ~val);				\
}
BUILD_CONTROLS_SHADOW(vm_entry, VM_ENTRY_CONTROLS, 32)
BUILD_CONTROLS_SHADOW(vm_exit, VM_EXIT_CONTROLS, 32)
BUILD_CONTROLS_SHADOW(pin, PIN_BASED_VM_EXEC_CONTROL, 32)
BUILD_CONTROLS_SHADOW(exec, CPU_BASED_VM_EXEC_CONTROL, 32)
BUILD_CONTROLS_SHADOW(secondary_exec, SECONDARY_VM_EXEC_CONTROL, 32)
BUILD_CONTROLS_SHADOW(tertiary_exec, TERTIARY_VM_EXEC_CONTROL, 64)

void ept_save_pdptrs(struct kvm_vcpu* vcpu);



NTSTATUS vmx_init();
void vmx_exit(void);

bool kvm_is_vmx_supported();
int cpu_has_kvm_support();
int cpu_has_virtual_nmis();
int cpu_has_vmx_msr_bitmap();
int cpu_has_vmx_invept_global();
int cpu_has_vmx_io_bitmap();

int vmx_disabled_by_bios();

NTSTATUS hardware_setup();
void hardware_unsetup();
void hardware_enable();

bool report_flexpriority();

void hv_init_evmcs();

NTSTATUS vmx_setup_l1d_flush(enum vmx_l1d_flush_state l1tf);

void vmx_prepare_switch_to_guest(struct kvm_vcpu* vcpu);

int alloc_loaded_vmcs(struct loaded_vmcs* loaded_vmcs);
void vmx_vcpu_load_vmcs(struct kvm_vcpu* vcpu, int cpu,
	struct loaded_vmcs* buddy);
void loaded_vmcs_clear(struct loaded_vmcs* loaded_vmcs);

void dump_vmcs(struct kvm_vcpu* vcpu);

void vmx_update_exception_bitmap(struct kvm_vcpu* vcpu);

bool vmx_need_pf_intercept(struct kvm_vcpu* vcpu);

struct vcpu_vmx* to_vmx(struct kvm_vcpu* vcpu);

unsigned long vmx_l1_guest_owned_cr0_bits(void);
void set_cr4_guest_host_mask(struct vcpu_vmx* vmx);

static unsigned long vmx_get_exit_qual(struct kvm_vcpu* vcpu) {
	struct vcpu_vmx* vmx = to_vmx(vcpu);

	return vmx->exit_qualification;
}

void vmx_prepare_switch_to_guest(struct kvm_vcpu* vcpu);
void vmx_update_host_rsp(struct vcpu_vmx* vmx, ULONG_PTR host_rsp);

bool __vmx_vcpu_run(struct vcpu_vmx* vmx, ULONG_PTR* regs,
	unsigned int flags);

void vmx_set_constant_host_state(struct vcpu_vmx* vmx);

USHORT vmx_get_es();
USHORT vmx_get_cs();
USHORT vmx_get_ss();
USHORT vmx_get_ds();
USHORT vmx_get_fs();

void vmx_set_host_fs_gs(struct vmcs_host_state* host, u16 fs_sel, u16 gs_sel,
	ULONG_PTR fs_base, ULONG_PTR gs_base);

USHORT vmx_get_gs();

u64 construct_eptp(struct kvm_vcpu* vcpu, hpa_t root_hpa, int root_level);


static inline struct kvm_vmx* to_kvm_vmx(struct kvm* kvm) {
	return CONTAINING_RECORD(kvm, struct kvm_vmx, kvm);
}

void vmx_sgdt(struct desc_ptr* dt);

void __vmx_set_segment(struct kvm_vcpu* vcpu, struct kvm_segment* var, int seg);

USHORT vmx_str();
USHORT vmx_sldt();

#define GDT_SEL     0
#define LDT_SEL     1

#include <pshpack1.h>
typedef struct x86_segment_selector {
	union {
		uint16_t sel;
		struct {
			uint16_t rpl : 2;
			uint16_t ti : 1;
			uint16_t index : 13;
		};
	};
}x86_segment_selector;

typedef struct x86_segment_descriptor {
	uint64_t limit0 : 16;
	uint64_t    base0 : 16;
	uint64_t    base1 : 8;
	uint64_t    type : 4;
	uint64_t    s : 1;
	uint64_t    dpl : 2;
	uint64_t    p : 1;
	uint64_t    limit1 : 4;
	uint64_t    avl : 1;
	uint64_t    l : 1;
	uint64_t    db : 1;
	uint64_t    g : 1;
	uint64_t    base2 : 8;
}x86_segment_descriptor;

#include <poppack.h>

void vmx_vmexit(void);

void vmx_spec_ctrl_restore_host(struct vcpu_vmx* vmx, unsigned int flags);


void vmx_set_cr2(ULONG_PTR cr2);

static inline bool kvm_register_test_and_mark_available(struct kvm_vcpu* vcpu,
	enum kvm_reg reg) {
	return _bittestandset((LONG*)&vcpu->arch.regs_avail, reg);
}

void free_loaded_vmcs(struct loaded_vmcs* loaded_vmcs);

ULONG allocate_vpid(void);