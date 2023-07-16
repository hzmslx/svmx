#pragma once

struct kvm_page_fault {
	/* arguments to kvm_mmu_do_page_fault.  */
	const gpa_t addr;
	const u32 error_code;
	const bool prefetch;

	/* Derived from error_code.  */
	const bool exec;
	const bool write;
	const bool present;
	const bool rsvd;
	const bool user;

	/* Derived from mmu and global state.  */
	const bool is_tdp;
	const bool nx_huge_page_workaround_enabled;

	/*
	 * Whether a >4KB mapping can be created or is forbidden due to NX
	 * hugepages.
	 */
	bool huge_page_disallowed;

	/*
	 * Maximum page size that can be created for this fault; input to
	 * FNAME(fetch), direct_map() and kvm_tdp_mmu_map().
	 */
	u8 max_level;

	/*
	 * Page size that can be created based on the max_level and the
	 * page size used by the host mapping.
	 */
	u8 req_level;

	/*
	 * Page size that will be created based on the req_level and
	 * huge_page_disallowed.
	 */
	u8 goal_level;

	/* Shifted addr, or result of guest page table walk if addr is a gva.  */
	gfn_t gfn;

	/* The memslot containing gfn. May be NULL. */
	struct kvm_memory_slot* slot;

	/* Outputs of kvm_faultin_pfn.  */
	unsigned long mmu_seq;
	// kvm_pfn_t pfn;
	hva_t hva;
	bool map_writable;

	/*
	 * Indicates the guest is trying to write a gfn that contains one or
	 * more of the PTEs used to translate the write itself, i.e. the access
	 * is changing its own translation in the guest page tables.
	 */
	bool write_fault_to_shadow_pgtable;
};

struct kvm_mmu_page {
	/*
	 * Note, "link" through "spt" fit in a single 64 byte cache line on
	 * 64-bit kernels, keep it that way unless there's a reason not to.
	 */


	bool tdp_mmu_page;
	bool unsync;
	u8 mmu_valid_gen;

	/*
	 * The shadow page can't be replaced by an equivalent huge page
	 * because it is being used to map an executable page in the guest
	 * and the NX huge page mitigation is enabled.
	 */
	bool nx_huge_page_disallowed;

	/*
	 * The following two entries are used to key the shadow page in the
	 * hash table.
	 */
	
	gfn_t gfn;

	u64* spt;

	/*
	 * Stores the result of the guest translation being shadowed by each
	 * SPTE.  KVM shadows two types of guest translations: nGPA -> GPA
	 * (shadow EPT/NPT) and GVA -> GPA (traditional shadow paging). In both
	 * cases the result of the translation is a GPA and a set of access
	 * constraints.
	 *
	 * The GFN is stored in the upper bits (PAGE_SHIFT) and the shadowed
	 * access permissions are stored in the lower bits. Note, for
	 * convenience and uniformity across guests, the access permissions are
	 * stored in KVM format (e.g.  ACC_EXEC_MASK) not the raw guest format.
	 */
	u64* shadowed_translation;

	/* Currently serving as active root */

	unsigned int unsync_children;


	/*
	 * Tracks shadow pages that, if zapped, would allow KVM to create an NX
	 * huge page.  A shadow page will have nx_huge_page_disallowed set but
	 * not be on the list if a huge page is disallowed for other reasons,
	 * e.g. because KVM is shadowing a PTE at the same gfn, the memslot
	 * isn't properly aligned, etc...
	 */
	
#ifdef CONFIG_X86_32
	/*
	 * Used out of the mmu-lock to avoid reading spte values while an
	 * update is in progress; see the comments in __get_spte_lockless().
	 */
	int clear_spte_count;
#endif

	/* Number of writes since the last time traversal visited this page.  */
	// atomic_t write_flooding_count;

#ifdef CONFIG_X86_64
	/* Used for freeing the page asynchronously if it is a TDP MMU page. */
	struct rcu_head rcu_head;
#endif
};