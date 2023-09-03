#pragma once


struct vmcs_hdr {
	u32 revision_id : 31;
	u32 shadow_vmcs : 1;
};
// vmcs 具体结构分配由硬件实现, 程序员只需要通过 VMWRITE 和 VMREAD 指令去访问.
struct vmcs {
	struct vmcs_hdr hdr;
	u32 abort;
	char data[];
};

/*
 * vmcs_host_state tracks registers that are loaded from the VMCS on VMEXIT
 * and whose values change infrequently, but are not constant.  I.e. this is
 * used as a write-through cache of the corresponding VMCS fields.
 */
struct vmcs_host_state {
	u64 cr3;	/* May not match real cr3 */
	u64 cr4;	/* May not match real cr4 */
	ULONG_PTR gs_base;
	ULONG_PTR fs_base;
	ULONG_PTR rsp;

	u16           fs_sel, gs_sel, ldt_sel;
#ifdef _WIN64
	u16           ds_sel, es_sel;
#endif
};

struct vmcs_controls_shadow {
	u32 vm_entry;
	u32 vm_exit;
	u32 pin;
	u32 exec;
	u32 secondary_exec;
	u64 tertiary_exec;
};

/*
 * Track a VMCS that may be loaded on a certain CPU. If it is (cpu!=-1), also
 * remember whether it was VMLAUNCHed, and maintain a linked list of all VMCSs
 * loaded on this CPU (so we can clear them if the CPU goes down).
 */
struct loaded_vmcs {
	struct vmcs* vmcs; // vcpu对应的VMCS
	struct vmcs* shadow_vmcs;
	int cpu; // 上一次运行的cpu编号
	bool launched; // 是否被这个cpu加载
	bool nmi_known_unmasked;
	bool hv_timer_soft_disabled;
	/* Support for vnmi-less CPUs */
	int soft_vnmi_blocked;
	s64 vnmi_blocked_time;
	unsigned long* msr_bitmap;
	LIST_ENTRY loaded_vmcss_on_cpu_link;/* 这个cpu上的所有 vmcs链表 */
	struct vmcs_host_state host_state;
	struct vmcs_controls_shadow controls_shadow;
	int vcpu_id;
};

/*
 * Interruption-information format
 */
#define INTR_INFO_VECTOR_MASK           0xff            /* 7:0 */
#define INTR_INFO_INTR_TYPE_MASK        0x700           /* 10:8 */
#define INTR_INFO_DELIVER_CODE_MASK     0x800           /* 11 */
#define INTR_INFO_UNBLOCK_NMI		0x1000		/* 12 */
#define INTR_INFO_VALID_MASK            0x80000000      /* 31 */
#define INTR_INFO_RESVD_BITS_MASK       0x7ffff000

#define VECTORING_INFO_VECTOR_MASK           	INTR_INFO_VECTOR_MASK
#define VECTORING_INFO_TYPE_MASK        	INTR_INFO_INTR_TYPE_MASK
#define VECTORING_INFO_DELIVER_CODE_MASK    	INTR_INFO_DELIVER_CODE_MASK
#define VECTORING_INFO_VALID_MASK       	INTR_INFO_VALID_MASK

#define INTR_TYPE_EXT_INTR              (0 << 8) /* external interrupt */
#define INTR_TYPE_NMI_INTR		(2 << 8) /* NMI */
#define INTR_TYPE_HARD_EXCEPTION	(3 << 8) /* processor exception */
#define INTR_TYPE_SOFT_INTR             (4 << 8) /* software interrupt */
#define INTR_TYPE_SOFT_EXCEPTION	(6 << 8) /* software exception */

static bool is_intr_type(u32 intr_info, u32 type) {
	const u32 mask = INTR_INFO_VALID_MASK | INTR_INFO_INTR_TYPE_MASK;

	return (intr_info & mask) == (INTR_INFO_VALID_MASK | type);
}

static bool is_nmi(u32 intr_info) {
	return is_intr_type(intr_info, INTR_TYPE_NMI_INTR);
}