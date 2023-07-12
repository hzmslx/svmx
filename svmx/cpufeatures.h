#pragma once

/*
 * Auxiliary flags: Linux defined - For features scattered in various
 * CPUID levels like 0x6, 0xA etc, word 7.
 *
 * Reuse free bits when adding new feature flags!
 */
#define X86_FEATURE_RING3MWAIT		( 7*32+ 0) /* Ring 3 MONITOR/MWAIT instructions */
#define X86_FEATURE_CPUID_FAULT		( 7*32+ 1) /* Intel CPUID faulting */
#define X86_FEATURE_CPB			( 7*32+ 2) /* AMD Core Performance Boost */
#define X86_FEATURE_EPB			( 7*32+ 3) /* IA32_ENERGY_PERF_BIAS support */
#define X86_FEATURE_CAT_L3		( 7*32+ 4) /* Cache Allocation Technology L3 */
#define X86_FEATURE_CAT_L2		( 7*32+ 5) /* Cache Allocation Technology L2 */
#define X86_FEATURE_CDP_L3		( 7*32+ 6) /* Code and Data Prioritization L3 */
#define X86_FEATURE_INVPCID_SINGLE	( 7*32+ 7) /* Effectively INVPCID && CR4.PCIDE=1 */
#define X86_FEATURE_HW_PSTATE		( 7*32+ 8) /* AMD HW-PState */
#define X86_FEATURE_PROC_FEEDBACK	( 7*32+ 9) /* AMD ProcFeedbackInterface */
#define X86_FEATURE_XCOMPACTED		( 7*32+10) /* "" Use compacted XSTATE (XSAVES or XSAVEC) */
#define X86_FEATURE_PTI			( 7*32+11) /* Kernel Page Table Isolation enabled */
#define X86_FEATURE_KERNEL_IBRS		( 7*32+12) /* "" Set/clear IBRS on kernel entry/exit */
#define X86_FEATURE_RSB_VMEXIT		( 7*32+13) /* "" Fill RSB on VM-Exit */
#define X86_FEATURE_INTEL_PPIN		( 7*32+14) /* Intel Processor Inventory Number */
#define X86_FEATURE_CDP_L2		( 7*32+15) /* Code and Data Prioritization L2 */
#define X86_FEATURE_MSR_SPEC_CTRL	( 7*32+16) /* "" MSR SPEC_CTRL is implemented */
#define X86_FEATURE_SSBD		( 7*32+17) /* Speculative Store Bypass Disable */
#define X86_FEATURE_MBA			( 7*32+18) /* Memory Bandwidth Allocation */
#define X86_FEATURE_RSB_CTXSW		( 7*32+19) /* "" Fill RSB on context switches */
#define X86_FEATURE_PERFMON_V2		( 7*32+20) /* AMD Performance Monitoring Version 2 */
#define X86_FEATURE_USE_IBPB		( 7*32+21) /* "" Indirect Branch Prediction Barrier enabled */
#define X86_FEATURE_USE_IBRS_FW		( 7*32+22) /* "" Use IBRS during runtime firmware calls */
#define X86_FEATURE_SPEC_STORE_BYPASS_DISABLE	( 7*32+23) /* "" Disable Speculative Store Bypass. */
#define X86_FEATURE_LS_CFG_SSBD		( 7*32+24)  /* "" AMD SSBD implementation via LS_CFG MSR */
#define X86_FEATURE_IBRS		( 7*32+25) /* Indirect Branch Restricted Speculation */
#define X86_FEATURE_IBPB		( 7*32+26) /* Indirect Branch Prediction Barrier */
#define X86_FEATURE_STIBP		( 7*32+27) /* Single Thread Indirect Branch Predictors */
#define X86_FEATURE_ZEN			(7*32+28) /* "" CPU based on Zen microarchitecture */
#define X86_FEATURE_L1TF_PTEINV		( 7*32+29) /* "" L1TF workaround PTE inversion */
#define X86_FEATURE_IBRS_ENHANCED	( 7*32+30) /* Enhanced IBRS */
#define X86_FEATURE_MSR_IA32_FEAT_CTL	( 7*32+31) /* "" MSR IA32_FEAT_CTL configured */

/* Intel-defined CPU features, CPUID level 0x00000001 (ECX), word 4 */
#define X86_FEATURE_XMM3		( 4*32+ 0) /* "pni" SSE-3 */
#define X86_FEATURE_PCLMULQDQ		( 4*32+ 1) /* PCLMULQDQ instruction */
#define X86_FEATURE_DTES64		( 4*32+ 2) /* 64-bit Debug Store */
#define X86_FEATURE_MWAIT		( 4*32+ 3) /* "monitor" MONITOR/MWAIT support */
#define X86_FEATURE_DSCPL		( 4*32+ 4) /* "ds_cpl" CPL-qualified (filtered) Debug Store */
#define X86_FEATURE_VMX			( 4*32+ 5) /* Hardware virtualization */
#define X86_FEATURE_SMX			( 4*32+ 6) /* Safer Mode eXtensions */
#define X86_FEATURE_EST			( 4*32+ 7) /* Enhanced SpeedStep */
#define X86_FEATURE_TM2			( 4*32+ 8) /* Thermal Monitor 2 */
#define X86_FEATURE_SSSE3		( 4*32+ 9) /* Supplemental SSE-3 */
#define X86_FEATURE_CID			( 4*32+10) /* Context ID */
#define X86_FEATURE_SDBG		( 4*32+11) /* Silicon Debug */
#define X86_FEATURE_FMA			( 4*32+12) /* Fused multiply-add */
#define X86_FEATURE_CX16		( 4*32+13) /* CMPXCHG16B instruction */
#define X86_FEATURE_XTPR		( 4*32+14) /* Send Task Priority Messages */
#define X86_FEATURE_PDCM		( 4*32+15) /* Perf/Debug Capabilities MSR */
#define X86_FEATURE_PCID		( 4*32+17) /* Process Context Identifiers */
#define X86_FEATURE_DCA			( 4*32+18) /* Direct Cache Access */
#define X86_FEATURE_XMM4_1		( 4*32+19) /* "sse4_1" SSE-4.1 */
#define X86_FEATURE_XMM4_2		( 4*32+20) /* "sse4_2" SSE-4.2 */
#define X86_FEATURE_X2APIC		( 4*32+21) /* X2APIC */
#define X86_FEATURE_MOVBE		( 4*32+22) /* MOVBE instruction */
#define X86_FEATURE_POPCNT		( 4*32+23) /* POPCNT instruction */
#define X86_FEATURE_TSC_DEADLINE_TIMER	( 4*32+24) /* TSC deadline timer */
#define X86_FEATURE_AES			( 4*32+25) /* AES instructions */
#define X86_FEATURE_XSAVE		( 4*32+26) /* XSAVE/XRSTOR/XSETBV/XGETBV instructions */
#define X86_FEATURE_OSXSAVE		( 4*32+27) /* "" XSAVE instruction enabled in the OS */
#define X86_FEATURE_AVX			( 4*32+28) /* Advanced Vector Extensions */
#define X86_FEATURE_F16C		( 4*32+29) /* 16-bit FP conversions */
#define X86_FEATURE_RDRAND		( 4*32+30) /* RDRAND instruction */
#define X86_FEATURE_HYPERVISOR		( 4*32+31) /* Running on a hypervisor */