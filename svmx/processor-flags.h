#pragma once

#define __AC(X,Y)	(X##Y)
#define _AC(X,Y)	__AC(X,Y)
#define _AT(T,X)	((T)(X))
#define _UL(x)		(_AC(x, UL))
#define _BITUL(x)	(_UL(1) << (x))
/*
 * EFLAGS bits
 */
#define X86_EFLAGS_CF	0x00000001 /* Carry Flag */
#define X86_EFLAGS_PF	0x00000004 /* Parity Flag */
#define X86_EFLAGS_AF	0x00000010 /* Auxillary carry Flag */
#define X86_EFLAGS_ZF	0x00000040 /* Zero Flag */
#define X86_EFLAGS_SF	0x00000080 /* Sign Flag */
#define X86_EFLAGS_TF	0x00000100 /* Trap Flag */
#define X86_EFLAGS_IF	0x00000200 /* Interrupt Flag */
#define X86_EFLAGS_DF	0x00000400 /* Direction Flag */
#define X86_EFLAGS_OF	0x00000800 /* Overflow Flag */
#define X86_EFLAGS_IOPL	0x00003000 /* IOPL mask */
#define X86_EFLAGS_NT	0x00004000 /* Nested Task */
#define X86_EFLAGS_RF	0x00010000 /* Resume Flag */
#define X86_EFLAGS_VM	0x00020000 /* Virtual Mode */
#define X86_EFLAGS_AC	0x00040000 /* Alignment Check */
#define X86_EFLAGS_VIF	0x00080000 /* Virtual Interrupt Flag */
#define X86_EFLAGS_VIP	0x00100000 /* Virtual Interrupt Pending */
#define X86_EFLAGS_ID	0x00200000 /* CPUID detection flag */

/*
 * Basic CPU control in CR0
 */
#define X86_CR0_PE	0x00000001 /* Protection Enable */
#define X86_CR0_MP	0x00000002 /* Monitor Coprocessor */
#define X86_CR0_EM	0x00000004 /* Emulation */
#define X86_CR0_TS	0x00000008 /* Task Switched */
#define X86_CR0_ET	0x00000010 /* Extension Type */
#define X86_CR0_NE	0x00000020 /* Numeric Error */
#define X86_CR0_WP	0x00010000 /* Write Protect */
#define X86_CR0_AM	0x00040000 /* Alignment Mask */
#define X86_CR0_NW	0x20000000 /* Not Write-through */
#define X86_CR0_CD	0x40000000 /* Cache Disable */
#define X86_CR0_PG	0x80000000 /* Paging */

 /*
  * Intel CPU features in CR4
  */
#define X86_CR4_VME_BIT		0 /* enable vm86 extensions */
#define X86_CR4_VME		_BITUL(X86_CR4_VME_BIT)
#define X86_CR4_PVI_BIT		1 /* virtual interrupts flag enable */
#define X86_CR4_PVI		_BITUL(X86_CR4_PVI_BIT)
#define X86_CR4_TSD_BIT		2 /* disable time stamp at ipl 3 */
#define X86_CR4_TSD		_BITUL(X86_CR4_TSD_BIT)
#define X86_CR4_DE_BIT		3 /* enable debugging extensions */
#define X86_CR4_DE		_BITUL(X86_CR4_DE_BIT)
#define X86_CR4_PSE_BIT		4 /* enable page size extensions */
#define X86_CR4_PSE		_BITUL(X86_CR4_PSE_BIT)
#define X86_CR4_PAE_BIT		5 /* enable physical address extensions */
#define X86_CR4_PAE		_BITUL(X86_CR4_PAE_BIT)
#define X86_CR4_MCE_BIT		6 /* Machine check enable */
#define X86_CR4_MCE		_BITUL(X86_CR4_MCE_BIT)
#define X86_CR4_PGE_BIT		7 /* enable global pages */
#define X86_CR4_PGE		_BITUL(X86_CR4_PGE_BIT)
#define X86_CR4_PCE_BIT		8 /* enable performance counters at ipl 3 */
#define X86_CR4_PCE		_BITUL(X86_CR4_PCE_BIT)
#define X86_CR4_OSFXSR_BIT	9 /* enable fast FPU save and restore */
#define X86_CR4_OSFXSR		_BITUL(X86_CR4_OSFXSR_BIT)
#define X86_CR4_OSXMMEXCPT_BIT	10 /* enable unmasked SSE exceptions */
#define X86_CR4_OSXMMEXCPT	_BITUL(X86_CR4_OSXMMEXCPT_BIT)
#define X86_CR4_UMIP_BIT	11 /* enable UMIP support */
#define X86_CR4_UMIP		_BITUL(X86_CR4_UMIP_BIT)
#define X86_CR4_LA57_BIT	12 /* enable 5-level page tables */
#define X86_CR4_LA57		_BITUL(X86_CR4_LA57_BIT)
#define X86_CR4_VMXE_BIT	13 /* enable VMX virtualization */
#define X86_CR4_VMXE		_BITUL(X86_CR4_VMXE_BIT)
#define X86_CR4_SMXE_BIT	14 /* enable safer mode (TXT) */
#define X86_CR4_SMXE		_BITUL(X86_CR4_SMXE_BIT)
#define X86_CR4_FSGSBASE_BIT	16 /* enable RDWRFSGS support */
#define X86_CR4_FSGSBASE	_BITUL(X86_CR4_FSGSBASE_BIT)
#define X86_CR4_PCIDE_BIT	17 /* enable PCID support */
#define X86_CR4_PCIDE		_BITUL(X86_CR4_PCIDE_BIT)
#define X86_CR4_OSXSAVE_BIT	18 /* enable xsave and xrestore */
#define X86_CR4_OSXSAVE		_BITUL(X86_CR4_OSXSAVE_BIT)
#define X86_CR4_SMEP_BIT	20 /* enable SMEP support */
#define X86_CR4_SMEP		_BITUL(X86_CR4_SMEP_BIT)
#define X86_CR4_SMAP_BIT	21 /* enable SMAP support */
#define X86_CR4_SMAP		_BITUL(X86_CR4_SMAP_BIT)
#define X86_CR4_PKE_BIT		22 /* enable Protection Keys support */
#define X86_CR4_PKE		_BITUL(X86_CR4_PKE_BIT)
#define X86_CR4_CET_BIT		23 /* enable Control-flow Enforcement Technology */
#define X86_CR4_CET		_BITUL(X86_CR4_CET_BIT)
#define X86_CR4_LAM_SUP_BIT	28 /* LAM for supervisor pointers */
#define X86_CR4_LAM_SUP		_BITUL(X86_CR4_LAM_SUP_BIT)