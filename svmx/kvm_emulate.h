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

/*
 * The emulator's _regs array tracks only the GPRs, i.e. excludes RIP.  RIP is
 * tracked/accessed via _eip, and except for RIP relative addressing, which
 * also uses _eip, RIP cannot be a register operand nor can it be an operand in
 * a ModRM or SIB byte.
 */
#ifdef _WIN64
#define NR_EMULATOR_GPRS	16
#else
#define NR_EMULATOR_GPRS	8
#endif

/* Type, address-of, and value of an instruction's operand. */
struct operand {
	enum { OP_REG, OP_MEM, OP_MEM_STR, OP_IMM, OP_XMM, OP_MM, OP_NONE } type;
	unsigned int bytes;
	unsigned int count;
	union {
		unsigned long orig_val;
		u64 orig_val64;
	};
	union {
		unsigned long* reg;
		struct segmented_address {
			ULONG_PTR ea;
			unsigned seg;
		} mem;
		unsigned xmm;
		unsigned mm;
	} addr;
	union {
		unsigned long val;
		u64 val64;
		u64 mm_val;
		void* data;
	};
};

struct fetch_cache {
	u8 data[15];
	u8* ptr;
	u8* end;
};

struct read_cache {
	u8 data[1024];
	unsigned long pos;
	unsigned long end;
};

struct x86_emulate_ctxt {
	void* vcpu;
	const struct x86_emulate_ops* ops;

	/* Register state before/after emulation. */
	unsigned long eflags;
	unsigned long eip; /* eip before instruction emulation */
	/* Emulated execution mode, represented by an X86EMUL_MODE value. */
	enum x86emul_mode mode;

	/* interruptibility state, as a result of execution of STI or MOV SS */
	int interruptibility;

	bool perm_ok; /* do not check permissions if true */
	bool tf;	/* TF value before instruction (after for syscall/sysret) */

	bool have_exception;
	struct x86_exception exception;

	/* GPA available */
	bool gpa_available;
	gpa_t gpa_val;

	/*
	 * decode cache
	 */

	 /* current opcode length in bytes */
	u8 opcode_len;
	u8 b;
	u8 intercept;
	u8 op_bytes;
	u8 ad_bytes;
	union {
		int (*execute)(struct x86_emulate_ctxt* ctxt);
	};
	int (*check_perm)(struct x86_emulate_ctxt* ctxt);

	bool rip_relative;
	u8 rex_prefix;
	u8 lock_prefix;
	u8 rep_prefix;
	/* bitmaps of registers in _regs[] that can be read */
	u16 regs_valid;
	/* bitmaps of registers in _regs[] that have been written */
	u16 regs_dirty;
	/* modrm */
	u8 modrm;
	u8 modrm_mod;
	u8 modrm_reg;
	u8 modrm_rm;
	u8 modrm_seg;
	u8 seg_override;
	u64 d;
	unsigned long _eip;

	/* Here begins the usercopy section. */
	struct operand src;
	struct operand src2;
	struct operand dst;
	struct operand memop;
	unsigned long _regs[NR_EMULATOR_GPRS];
	struct operand* memopp;
	struct fetch_cache fetch;
	struct read_cache io_read;
	struct read_cache mem_read;
	bool is_branch;
};

// Èí¼þÄ£Äâº¯Êý
struct x86_emulate_ops {
	void (*vm_bugged)(struct x86_emulate_ctxt* ctxt);
	/*
	 * read_gpr: read a general purpose register (rax - r15)
	 *
	 * @reg: gpr number.
	 */
	ULONG_PTR(*read_gpr)(struct x86_emulate_ctxt* ctxt, unsigned reg);
	/*
	 * write_gpr: write a general purpose register (rax - r15)
	 *
	 * @reg: gpr number.
	 * @val: value to write.
	 */
	void (*write_gpr)(struct x86_emulate_ctxt* ctxt, unsigned reg, ULONG_PTR val);
	/*
	 * read_std: Read bytes of standard (non-emulated/special) memory.
	 *           Used for descriptor reading.
	 *  @addr:  [IN ] Linear address from which to read.
	 *  @val:   [OUT] Value read from memory, zero-extended to 'u_long'.
	 *  @bytes: [IN ] Number of bytes to read from memory.
	 *  @system:[IN ] Whether the access is forced to be at CPL0.
	 */
	int (*read_std)(struct x86_emulate_ctxt* ctxt,
		unsigned long addr, void* val,
		unsigned int bytes,
		struct x86_exception* fault, bool system);

	/*
	 * write_std: Write bytes of standard (non-emulated/special) memory.
	 *            Used for descriptor writing.
	 *  @addr:  [IN ] Linear address to which to write.
	 *  @val:   [OUT] Value write to memory, zero-extended to 'u_long'.
	 *  @bytes: [IN ] Number of bytes to write to memory.
	 *  @system:[IN ] Whether the access is forced to be at CPL0.
	 */
	int (*write_std)(struct x86_emulate_ctxt* ctxt,
		unsigned long addr, void* val, unsigned int bytes,
		struct x86_exception* fault, bool system);
	/*
	 * fetch: Read bytes of standard (non-emulated/special) memory.
	 *        Used for instruction fetch.
	 *  @addr:  [IN ] Linear address from which to read.
	 *  @val:   [OUT] Value read from memory, zero-extended to 'u_long'.
	 *  @bytes: [IN ] Number of bytes to read from memory.
	 */
	int (*fetch)(struct x86_emulate_ctxt* ctxt,
		unsigned long addr, void* val, unsigned int bytes,
		struct x86_exception* fault);

	/*
	 * read_emulated: Read bytes from emulated/special memory area.
	 *  @addr:  [IN ] Linear address from which to read.
	 *  @val:   [OUT] Value read from memory, zero-extended to 'u_long'.
	 *  @bytes: [IN ] Number of bytes to read from memory.
	 */
	int (*read_emulated)(struct x86_emulate_ctxt* ctxt,
		unsigned long addr, void* val, unsigned int bytes,
		struct x86_exception* fault);

	/*
	 * write_emulated: Write bytes to emulated/special memory area.
	 *  @addr:  [IN ] Linear address to which to write.
	 *  @val:   [IN ] Value to write to memory (low-order bytes used as
	 *                required).
	 *  @bytes: [IN ] Number of bytes to write to memory.
	 */
	int (*write_emulated)(struct x86_emulate_ctxt* ctxt,
		unsigned long addr, const void* val,
		unsigned int bytes,
		struct x86_exception* fault);

	/*
	 * cmpxchg_emulated: Emulate an atomic (LOCKed) CMPXCHG operation on an
	 *                   emulated/special memory area.
	 *  @addr:  [IN ] Linear address to access.
	 *  @old:   [IN ] Value expected to be current at @addr.
	 *  @new:   [IN ] Value to write to @addr.
	 *  @bytes: [IN ] Number of bytes to access using CMPXCHG.
	 */
	int (*cmpxchg_emulated)(struct x86_emulate_ctxt* ctxt,
		unsigned long addr,
		const void* old,
		const void* new,
		unsigned int bytes,
		struct x86_exception* fault);
	void (*invlpg)(struct x86_emulate_ctxt* ctxt, ULONG_PTR addr);

	int (*pio_in_emulated)(struct x86_emulate_ctxt* ctxt,
		int size, unsigned short port, void* val,
		unsigned int count);

	int (*pio_out_emulated)(struct x86_emulate_ctxt* ctxt,
		int size, unsigned short port, const void* val,
		unsigned int count);

	bool (*get_segment)(struct x86_emulate_ctxt* ctxt, u16* selector,
		struct desc_struct* desc, u32* base3, int seg);
	void (*set_segment)(struct x86_emulate_ctxt* ctxt, u16 selector,
		struct desc_struct* desc, u32 base3, int seg);
	unsigned long (*get_cached_segment_base)(struct x86_emulate_ctxt* ctxt,
		int seg);
	void (*get_gdt)(struct x86_emulate_ctxt* ctxt, struct desc_ptr* dt);
	void (*get_idt)(struct x86_emulate_ctxt* ctxt, struct desc_ptr* dt);
	void (*set_gdt)(struct x86_emulate_ctxt* ctxt, struct desc_ptr* dt);
	void (*set_idt)(struct x86_emulate_ctxt* ctxt, struct desc_ptr* dt);
	ULONG_PTR(*get_cr)(struct x86_emulate_ctxt* ctxt, int cr);
	int (*set_cr)(struct x86_emulate_ctxt* ctxt, int cr, ULONG_PTR val);
	int (*cpl)(struct x86_emulate_ctxt* ctxt);
	void (*get_dr)(struct x86_emulate_ctxt* ctxt, int dr, ULONG_PTR* dest);
	int (*set_dr)(struct x86_emulate_ctxt* ctxt, int dr, ULONG_PTR value);
	int (*set_msr_with_filter)(struct x86_emulate_ctxt* ctxt, u32 msr_index, u64 data);
	int (*get_msr_with_filter)(struct x86_emulate_ctxt* ctxt, u32 msr_index, u64* pdata);
	int (*get_msr)(struct x86_emulate_ctxt* ctxt, u32 msr_index, u64* pdata);
	int (*check_pmc)(struct x86_emulate_ctxt* ctxt, u32 pmc);
	int (*read_pmc)(struct x86_emulate_ctxt* ctxt, u32 pmc, u64* pdata);
	void (*halt)(struct x86_emulate_ctxt* ctxt);
	void (*wbinvd)(struct x86_emulate_ctxt* ctxt);
	int (*fix_hypercall)(struct x86_emulate_ctxt* ctxt);
	int (*intercept)(struct x86_emulate_ctxt* ctxt,
		struct x86_instruction_info* info,
		enum x86_intercept_stage stage);

	bool (*get_cpuid)(struct x86_emulate_ctxt* ctxt, u32* eax, u32* ebx,
		u32* ecx, u32* edx, bool exact_only);
	bool (*guest_has_long_mode)(struct x86_emulate_ctxt* ctxt);
	bool (*guest_has_movbe)(struct x86_emulate_ctxt* ctxt);
	bool (*guest_has_fxsr)(struct x86_emulate_ctxt* ctxt);
	bool (*guest_has_rdpid)(struct x86_emulate_ctxt* ctxt);

	void (*set_nmi_mask)(struct x86_emulate_ctxt* ctxt, bool masked);

	bool (*is_smm)(struct x86_emulate_ctxt* ctxt);
	bool (*is_guest_mode)(struct x86_emulate_ctxt* ctxt);
	int (*leave_smm)(struct x86_emulate_ctxt* ctxt);
	void (*triple_fault)(struct x86_emulate_ctxt* ctxt);
	int (*set_xcr)(struct x86_emulate_ctxt* ctxt, u32 index, u64 xcr);
};