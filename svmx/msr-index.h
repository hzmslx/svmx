#pragma once
#include "processor-flags.h"

/* CPU model specific register (MSR) numbers */

/* K8 MSRs */
#define MSR_K8_TOP_MEM1			0xc001001a
#define MSR_K8_TOP_MEM2			0xc001001d
#define MSR_AMD64_SYSCFG		0xc0010010
#define MSR_AMD64_SYSCFG_MEM_ENCRYPT_BIT	23
#define MSR_AMD64_SYSCFG_MEM_ENCRYPT	BIT_ULL(MSR_AMD64_SYSCFG_MEM_ENCRYPT_BIT)
#define MSR_K8_INT_PENDING_MSG		0xc0010055

/* x86-64 specific MSRs */
#define MSR_EFER		0xc0000080 /* extended feature register */
#define MSR_STAR		0xc0000081 /* legacy mode SYSCALL target */
#define MSR_LSTAR		0xc0000082 /* long mode SYSCALL target */
#define MSR_CSTAR		0xc0000083 /* compat mode SYSCALL target */
#define MSR_SYSCALL_MASK	0xc0000084 /* EFLAGS mask for syscall */
#define MSR_FS_BASE		0xc0000100 /* 64bit FS base */
#define MSR_GS_BASE		0xc0000101 /* 64bit GS base */
#define MSR_KERNEL_GS_BASE	0xc0000102 /* SwapGS GS shadow */

/* EFER bits: */
#define _EFER_SCE		0  /* SYSCALL/SYSRET */
#define _EFER_LME		8  /* Long mode enable */
#define _EFER_LMA		10 /* Long mode active (read-only) */
#define _EFER_NX		11 /* No execute enable */
#define _EFER_SVME		12 /* Enable virtualization */
#define _EFER_FFXSR		14 /* Enable Fast FXSAVE/FXRSTOR */

#define EFER_SCE		(1<<_EFER_SCE)
#define EFER_LME		(1<<_EFER_LME)
#define EFER_LMA		(1<<_EFER_LMA)
#define EFER_NX			(1<<_EFER_NX)
#define EFER_SVME		(1<<_EFER_SVME)
#define EFER_FFXSR		(1<<_EFER_FFXSR)

/* Intel MSRs. Some also available on other CPUs */

#define MSR_TEST_CTRL				0x00000033
#define MSR_TEST_CTRL_SPLIT_LOCK_DETECT_BIT	29
#define MSR_TEST_CTRL_SPLIT_LOCK_DETECT		BIT(MSR_TEST_CTRL_SPLIT_LOCK_DETECT_BIT)

#define MSR_IA32_SPEC_CTRL		0x00000048 /* Speculation Control */
#define SPEC_CTRL_IBRS			BIT(0)	   /* Indirect Branch Restricted Speculation */
#define SPEC_CTRL_STIBP_SHIFT		1	   /* Single Thread Indirect Branch Predictor (STIBP) bit */
#define SPEC_CTRL_STIBP			BIT(SPEC_CTRL_STIBP_SHIFT)	/* STIBP mask */
#define SPEC_CTRL_SSBD_SHIFT		2	   /* Speculative Store Bypass Disable bit */
#define SPEC_CTRL_SSBD			BIT(SPEC_CTRL_SSBD_SHIFT)	/* Speculative Store Bypass Disable */
#define SPEC_CTRL_RRSBA_DIS_S_SHIFT	6	   /* Disable RRSBA behavior */
#define SPEC_CTRL_RRSBA_DIS_S		BIT(SPEC_CTRL_RRSBA_DIS_S_SHIFT)

/* Intel MSRs. Some also available on other CPUs */
#define MSR_IA32_PERFCTR0		0x000000c1
#define MSR_IA32_PERFCTR1		0x000000c2
#define MSR_FSB_FREQ			0x000000cd

#define MSR_MTRRcap			0x000000fe
#define MSR_IA32_BBL_CR_CTL		0x00000119

#define MSR_IA32_SYSENTER_CS		0x00000174
#define MSR_IA32_SYSENTER_ESP		0x00000175
#define MSR_IA32_SYSENTER_EIP		0x00000176

#define MSR_IA32_MCG_CAP		0x00000179
#define MSR_IA32_MCG_STATUS		0x0000017a
#define MSR_IA32_MCG_CTL		0x0000017b

#define MSR_IA32_PEBS_ENABLE		0x000003f1
#define MSR_IA32_DS_AREA		0x00000600
#define MSR_IA32_PERF_CAPABILITIES	0x00000345

#define MSR_MTRRfix64K_00000		0x00000250
#define MSR_MTRRfix16K_80000		0x00000258
#define MSR_MTRRfix16K_A0000		0x00000259
#define MSR_MTRRfix4K_C0000		0x00000268
#define MSR_MTRRfix4K_C8000		0x00000269
#define MSR_MTRRfix4K_D0000		0x0000026a
#define MSR_MTRRfix4K_D8000		0x0000026b
#define MSR_MTRRfix4K_E0000		0x0000026c
#define MSR_MTRRfix4K_E8000		0x0000026d
#define MSR_MTRRfix4K_F0000		0x0000026e
#define MSR_MTRRfix4K_F8000		0x0000026f
#define MSR_MTRRdefType			0x000002ff

#define MSR_IA32_CR_PAT			0x00000277

#define MSR_IA32_DEBUGCTLMSR		0x000001d9
#define MSR_IA32_LASTBRANCHFROMIP	0x000001db
#define MSR_IA32_LASTBRANCHTOIP		0x000001dc
#define MSR_IA32_LASTINTFROMIP		0x000001dd
#define MSR_IA32_LASTINTTOIP		0x000001de

#define MSR_IA32_SYSENTER_CS		0x00000174
#define MSR_IA32_SYSENTER_ESP		0x00000175
#define MSR_IA32_SYSENTER_EIP		0x00000176


/* K6 MSRs */
#define MSR_K6_EFER			0xc0000080
#define MSR_K6_STAR			0xc0000081
#define MSR_K6_WHCR			0xc0000082
#define MSR_K6_UWCCR		0xc0000085
#define MSR_K6_EPMR			0xc0000086
#define MSR_K6_PSOR			0xc0000087
#define MSR_K6_PFIR			0xc0000088

/* Intel defined MSRs. */
#define MSR_IA32_P5_MC_ADDR		0x00000000
#define MSR_IA32_P5_MC_TYPE		0x00000001
#define MSR_IA32_TSC			0x00000010
#define MSR_IA32_PLATFORM_ID		0x00000017
#define MSR_IA32_EBL_CR_POWERON		0x0000002a
#define MSR_IA32_FEATURE_CONTROL        0x0000003a

#define FEATURE_CONTROL_LOCKED		(1<<0)
#define FEATURE_CONTROL_VMXON_ENABLED	(1<<2)

#define MSR_IA32_APICBASE		0x0000001b
#define MSR_IA32_APICBASE_BSP		(1<<8)
#define MSR_IA32_APICBASE_ENABLE	(1<<11)
#define MSR_IA32_APICBASE_BASE		(0xfffff<<12)

#define MSR_IA32_UCODE_WRITE		0x00000079
#define MSR_IA32_UCODE_REV		0x0000008b

#define MSR_IA32_PERF_STATUS		0x00000198
#define MSR_IA32_PERF_CTL		0x00000199

#define MSR_IA32_MPERF			0x000000e7
#define MSR_IA32_APERF			0x000000e8

#define MSR_IA32_THERM_CONTROL		0x0000019a
#define MSR_IA32_THERM_INTERRUPT	0x0000019b

#define THERM_INT_LOW_ENABLE		(1 << 0)
#define THERM_INT_HIGH_ENABLE		(1 << 1)

#define MSR_IA32_THERM_STATUS		0x0000019c

#define THERM_STATUS_PROCHOT		(1 << 0)

#define MSR_THERM2_CTL			0x0000019d

#define MSR_THERM2_CTL_TM_SELECT	(1ULL << 16)

#define MSR_IA32_MISC_ENABLE		0x000001a0

/* Intel VT MSRs */
#define MSR_IA32_VMX_BASIC              0x00000480
#define MSR_IA32_VMX_PINBASED_CTLS      0x00000481
#define MSR_IA32_VMX_PROCBASED_CTLS     0x00000482
#define MSR_IA32_VMX_EXIT_CTLS          0x00000483
#define MSR_IA32_VMX_ENTRY_CTLS         0x00000484
#define MSR_IA32_VMX_MISC               0x00000485
#define MSR_IA32_VMX_CR0_FIXED0         0x00000486
#define MSR_IA32_VMX_CR0_FIXED1         0x00000487
#define MSR_IA32_VMX_CR4_FIXED0         0x00000488
#define MSR_IA32_VMX_CR4_FIXED1         0x00000489
#define MSR_IA32_VMX_VMCS_ENUM          0x0000048a
#define MSR_IA32_VMX_PROCBASED_CTLS2    0x0000048b
#define MSR_IA32_VMX_EPT_VPID_CAP       0x0000048c
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS  0x0000048d
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS 0x0000048e
#define MSR_IA32_VMX_TRUE_EXIT_CTLS      0x0000048f
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS     0x00000490
#define MSR_IA32_VMX_VMFUNC             0x00000491
#define MSR_IA32_VMX_PROCBASED_CTLS3	0x00000492

#define MSR_IA32_ARCH_CAPABILITIES	0x0000010a
#define ARCH_CAP_RDCL_NO		BIT(0)	/* Not susceptible to Meltdown */
#define ARCH_CAP_IBRS_ALL		BIT(1)	/* Enhanced IBRS support */
#define ARCH_CAP_RSBA			BIT(2)	/* RET may use alternative branch predictors */
#define ARCH_CAP_SKIP_VMENTRY_L1DFLUSH	BIT(3)	/* Skip L1D flush on vmentry */
#define ARCH_CAP_SSB_NO			BIT(4)	/*
						 * Not susceptible to Speculative Store Bypass
						 * attack, so no Speculative Store Bypass
						 * control required.
						 */
#define ARCH_CAP_MDS_NO			BIT(5)   /*
						  * Not susceptible to
						  * Microarchitectural Data
						  * Sampling (MDS) vulnerabilities.
						  */
#define ARCH_CAP_PSCHANGE_MC_NO		BIT(6)	 /*
						  * The processor is not susceptible to a
						  * machine check error due to modifying the
						  * code page size along with either the
						  * physical address or cache type
						  * without TLB invalidation.
						  */
#define ARCH_CAP_TSX_CTRL_MSR		BIT(7)	/* MSR for TSX control is available. */
#define ARCH_CAP_TAA_NO			BIT(8)	/*
						 * Not susceptible to
						 * TSX Async Abort (TAA) vulnerabilities.
						 */
#define ARCH_CAP_SBDR_SSDP_NO		BIT(13)	/*
						 * Not susceptible to SBDR and SSDP
						 * variants of Processor MMIO stale data
						 * vulnerabilities.
						 */
#define ARCH_CAP_FBSDP_NO		BIT(14)	/*
						 * Not susceptible to FBSDP variant of
						 * Processor MMIO stale data
						 * vulnerabilities.
						 */
#define ARCH_CAP_PSDP_NO		BIT(15)	/*
						 * Not susceptible to PSDP variant of
						 * Processor MMIO stale data
						 * vulnerabilities.
						 */
#define ARCH_CAP_FB_CLEAR		BIT(17)	/*
						 * VERW clears CPU fill buffer
						 * even on MDS_NO CPUs.
						 */
#define ARCH_CAP_FB_CLEAR_CTRL		BIT(18)	/*
						 * MSR_IA32_MCU_OPT_CTRL[FB_CLEAR_DIS]
						 * bit available to control VERW
						 * behavior.
						 */
#define ARCH_CAP_RRSBA			BIT(19)	/*
						 * Indicates RET may use predictors
						 * other than the RSB. With eIBRS
						 * enabled predictions in kernel mode
						 * are restricted to targets in
						 * kernel.
						 */
#define ARCH_CAP_PBRSB_NO		BIT(24)	/*
						 * Not susceptible to Post-Barrier
						 * Return Stack Buffer Predictions.
						 */

#define ARCH_CAP_XAPIC_DISABLE		BIT(21)	/*
						 * IA32_XAPIC_DISABLE_STATUS MSR
						 * supported
						 */

/* AMD-V MSRs */

#define MSR_VM_CR                       0xc0010114
#define MSR_VM_IGNNE                    0xc0010115
#define MSR_VM_HSAVE_PA                 0xc0010117

/* Referred to as IA32_FEATURE_CONTROL in Intel's SDM. */
#define MSR_IA32_FEAT_CTL		0x0000003a
#define FEAT_CTL_LOCKED				BIT(0)
#define FEAT_CTL_VMX_ENABLED_INSIDE_SMX		BIT(1)
#define FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX	BIT(2)
#define FEAT_CTL_SGX_LC_ENABLED			BIT(17)
#define FEAT_CTL_SGX_ENABLED			BIT(18)
#define FEAT_CTL_LMCE_ENABLED			BIT(20)

#define MSR_IA32_XFD			0x000001c4
#define MSR_IA32_XFD_ERR		0x000001c5
#define MSR_IA32_XSS			0x00000da0