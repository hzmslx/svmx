#pragma once


#define X86_SHADOW_INT_MOV_SS  1
#define X86_SHADOW_INT_STI     2


struct x86_exception {
	u8 vector;
	bool error_code_valid;
	u16 error_code;
	bool nested_page_fault;
	u64 address; /* cr2 or nested page fault gpa */
	u8 async_page_fault;
};

/*
 * This struct is used to carry enough information from the instruction
 * decoder to main KVM so that a decision can be made whether the
 * instruction needs to be intercepted or not.
 */
struct x86_instruction_info {
	u8  intercept;          /* which intercept                      */
	u8  rep_prefix;         /* rep prefix?                          */
	u8  modrm_mod;		/* mod part of modrm			*/
	u8  modrm_reg;          /* index of register used               */
	u8  modrm_rm;		/* rm part of modrm			*/
	u64 src_val;            /* value of source operand              */
	u64 dst_val;            /* value of destination operand         */
	u8  src_bytes;          /* size of source operand               */
	u8  dst_bytes;          /* size of destination operand          */
	u8  ad_bytes;           /* size of src/dst address              */
	u64 next_rip;           /* rip following the instruction        */
};

enum x86_intercept_stage {
	X86_ICTP_NONE = 0,   /* Allow zero-init to not match anything */
	X86_ICPT_PRE_EXCEPT,
	X86_ICPT_POST_EXCEPT,
	X86_ICPT_POST_MEMACCESS,
};