#include "pch.h"
#include "mmu_internal.h"
#include "mmu.h"
#include "pgtable_types.h"
#include "spte.h"
#include "cpuid.h"
#include "kvm_cache_regs.h"
#include "x86.h"
#include "kvm_host.h"
#include "smm.h"
#include "tdp_mmu.h"



int nx_huge_pages = -1;

/*
 * When setting this variable to true it enables Two-Dimensional-Paging
 * where the hardware walks 2 page tables:
 * 1. the guest-virtual to guest-physical
 * 2. while doing 1. it walks guest-physical to host-physical
 * If the hardware supports that we don't need to do shadow paging.
 */
bool tdp_enabled = TRUE;

static int max_huge_page_level;
static int tdp_root_level;
static int max_tdp_level;

#define RMAP_EXT 4

struct kvm_rmap_desc {
	u64* sptes[RMAP_EXT];
	struct kvm_rmap_desc* more;
};

static PMDL pte_list_desc_cache_mdl;
static PMDL rmap_desc_cache_mdl;
static PMDL mmu_page_header_mdl;

static PVOID pte_list_desc_cache;
static PVOID rmap_desc_cache;
static PVOID mmu_page_header_cache;



static bool tdp_mmu_allowed = TRUE;
#ifdef AMD64
bool tdp_mmu_enabled = TRUE;
#endif // 


struct kvm_mmu_role_regs {
	const ULONG_PTR cr0;
	const ULONG_PTR cr4;
	const u64 efer;
};

#define PTE_PREFETCH_NUM		8


#define PTTYPE 64
#include "paging_tmpl.h"
#undef PTTYPE

#define PTTYPE 32
#include "paging_tmpl.h"
#undef PTTYPE

#define PTTYPE_EPT 18 /* arbitrary */
#define PTTYPE PTTYPE_EPT
#include "paging_tmpl.h"
#undef PTTYPE

/* make pte_list_desc fit well in cache lines */
#define PTE_LIST_EXT 14

/**
 * lower_32_bits - return bits 0-31 of a number
 * @n: the number we're accessing
 */
#define lower_32_bits(n) ((u32)((n) & 0xffffffff))

/*
 * struct pte_list_desc is the core data structure used to implement a custom
 * list for tracking a set of related SPTEs, e.g. all the SPTEs that map a
 * given GFN when used in the context of rmaps.  Using a custom list allows KVM
 * to optimize for the common case where many GFNs will have at most a handful
 * of SPTEs pointing at them, i.e. allows packing multiple SPTEs into a small
 * memory footprint, which in turn improves runtime performance by exploiting
 * cache locality.
 *
 * A list is comprised of one or more pte_list_desc objects (descriptors).
 * Each individual descriptor stores up to PTE_LIST_EXT SPTEs.  If a descriptor
 * is full and a new SPTEs needs to be added, a new descriptor is allocated and
 * becomes the head of the list.  This means that by definitions, all tail
 * descriptors are full.
 *
 * Note, the meta data fields are deliberately placed at the start of the
 * structure to optimize the cacheline layout; accessing the descriptor will
 * touch only a single cacheline so long as @spte_count<=6 (or if only the
 * descriptors metadata is accessed).
 */
struct pte_list_desc {
	struct pte_list_desc* more;
	/* The number of PTEs stored in _this_ descriptor. */
	u32 spte_count;
	/* The number of PTEs stored in all tails of this descriptor. */
	u32 tail_count;
	u64* sptes[PTE_LIST_EXT];
};

static void mmu_destroy_caches(void) {
	if (pte_list_desc_cache != NULL) {
		MmUnmapLockedPages(pte_list_desc_cache, pte_list_desc_cache_mdl);
	}
	if (pte_list_desc_cache_mdl != NULL) {
		IoFreeMdl(pte_list_desc_cache_mdl);
	}
	if (mmu_page_header_cache != NULL) {
		MmUnmapLockedPages(mmu_page_header_cache, mmu_page_header_mdl);
	}
	if (mmu_page_header_mdl != NULL) {
		IoFreeMdl(mmu_page_header_mdl);
	}
}

/*
* The bluk of the MMU initialization is deferred until the vendor module is
* loaded as many of the masks/values may be modified by VMX or SVM, i.e. need
* to be reset when a potentially different vendor module is loaded.
*/
int kvm_mmu_vendor_module_init(void) {
	NTSTATUS status = STATUS_NO_MEMORY;

	kvm_mmu_reset_all_pte_masks();

	do
	{
		pte_list_desc_cache_mdl = IoAllocateMdl(NULL, sizeof(struct pte_list_desc),
			FALSE, FALSE, NULL);
		if (!pte_list_desc_cache_mdl)
			break;
		// 申请缓存用于反向映射
		pte_list_desc_cache = MmMapLockedPagesSpecifyCache(pte_list_desc_cache_mdl,
			KernelMode,
			MmNonCached,
			NULL,
			FALSE,
			NormalPagePriority);
		if (!pte_list_desc_cache) {
			break;
		}

		mmu_page_header_mdl = IoAllocateMdl(NULL, sizeof(struct kvm_rmap_desc),
			FALSE, FALSE, NULL);
		if (!mmu_page_header_mdl) {
			status = STATUS_NO_MEMORY;
			break;
		}
		// 申请缓存，用于分配struct kvm_mmu_page
		mmu_page_header_cache = MmMapLockedPagesSpecifyCache(mmu_page_header_mdl,
			KernelMode,
			MmNonCached,
			NULL,
			FALSE,
			NormalPagePriority);
		if (!mmu_page_header_cache) {
			status = STATUS_NO_MEMORY;
			break;
		}

		return STATUS_SUCCESS;
	} while (FALSE);


	mmu_destroy_caches();
	return status;
}


struct kvm_shadow_walk_iterator {
	u64 addr;// 寻找的 guest os 物理地址
	hpa_t shadow_addr; // 指向下一个要找的EPT页表基地址
	u64* sptep;// 当前页表中要使用的表项
	int level; // 当前查找所处的页表级别
	unsigned index; // 对应于gaddr的表项在当前页表的索引
};

void kvm_mmu_set_mask_ptes(u64 user_mask, u64 accessed_mask,
	u64 dirty_mask, u64 nx_mask, u64 x_mask) {
	shadow_user_mask = user_mask;
	shadow_accessed_mask = accessed_mask;
	shadow_dirty_mask = dirty_mask;
	shadow_nx_mask = nx_mask;
	shadow_x_mask = x_mask;
}

void kvm_enable_tdp() {
	tdp_enabled = TRUE;
}

void kvm_disable_tdp() {
	tdp_enabled = FALSE;
}



static struct kvm_mmu_role_regs vcpu_to_role_regs(struct kvm_vcpu* vcpu) {
	struct kvm_mmu_role_regs regs = {
		.cr0 = kvm_read_cr0_bits(vcpu, KVM_MMU_CR0_ROLE_BITS),
		.cr4 = kvm_read_cr4_bits(vcpu, KVM_MMU_CR4_ROLE_BITS),
		.efer = vcpu->arch.efer,
	};

	return regs;
}

static union kvm_cpu_role kvm_calc_cpu_role(struct kvm_vcpu* vcpu,
	const struct kvm_mmu_role_regs* regs) {
	UNREFERENCED_PARAMETER(regs);
	union kvm_cpu_role role = { 0 };

	role.base.access = ACC_ALL;
	role.base.smm = is_smm(vcpu);

	return role;
}

static void init_kvm_nested_mmu(struct kvm_vcpu* vcpu,
	union kvm_cpu_role new_mode) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(new_mode);
}

static void init_kvm_softmmu(struct kvm_vcpu* vcpu,
	union kvm_cpu_role cpu_role) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(cpu_role);
}


// 初始化mmu相关的全局变量
void kvm_configure_mmu(bool enable_tdp, int tdp_forced_root_level,
	int tdp_max_root_level, int tdp_huge_page_level) {
	tdp_enabled = enable_tdp;
	tdp_root_level = tdp_forced_root_level;
	max_tdp_level = tdp_max_root_level;

#ifdef _WIN64
	tdp_mmu_enabled = tdp_mmu_allowed && tdp_enabled;
#endif // _WIN64
	/*
	 * max_huge_page_level reflects KVM's MMU capabilities irrespective
	 * of kernel support, e.g. KVM may be capable of using 1GB pages when
	 * the kernel is not.  But, KVM never creates a page size greater than
	 * what is used by the kernel for any given HVA, i.e. the kernel's
	 * capabilities are ultimately consulted by kvm_mmu_hugepage_adjust().
	 */
	if (tdp_enabled)
		max_huge_page_level = tdp_huge_page_level;
	else
		max_huge_page_level = PG_LEVEL_2M;
}

// 分配相关的缓存
static int mmu_topup_memory_caches(struct kvm_vcpu* vcpu,
	bool maybe_indirect) {
	int r = 0;

	/* 1 rmap, 1 parent PTE per level, and the prefetched rmaps. */
	r = kvm_mmu_topup_memory_cache(&vcpu->arch.mmu_pte_list_desc_cache,
		1 + PT64_ROOT_MAX_LEVEL + PTE_PREFETCH_NUM);
	if (r)
		return r;
	r = kvm_mmu_topup_memory_cache(&vcpu->arch.mmu_shadow_page_cache,
		PT64_ROOT_MAX_LEVEL);
	if (r)
		return r;


	if (maybe_indirect) {
		r = kvm_mmu_topup_memory_cache(&vcpu->arch.mmu_shadowed_info_cache,
			PT64_ROOT_MAX_LEVEL);
		if (r)
			return r;
	}

	return kvm_mmu_topup_memory_cache(&vcpu->arch.mmu_page_header_cache,
		PT64_ROOT_MAX_LEVEL);
}

static int mmu_alloc_special_roots(struct kvm_vcpu* vcpu) {
	struct kvm_mmu* mmu = vcpu->arch.mmu;
	bool need_pml5 = mmu->root_role.level > PT64_ROOT_4LEVEL;
	u64* pml5_root = NULL;
	u64* pml4_root = NULL;
	u64* pae_root = NULL;

	/*
	* When shadowing 32-bit or PAE NPT with 64-bit NPT, the PML4 and PDP
	* tables are allocated and initialized at root creation as there is no
	* equivalent level in the guest's NPT to shadow. Allocate the tables
	* on demand, as running a 32-bit L1 VMM on 64-bit KVM is very rare.
	*/
	if (mmu->root_role.direct ||
		mmu->cpu_role.base.level >= PT64_ROOT_4LEVEL ||
		mmu->root_role.level < PT64_ROOT_4LEVEL)
		return 0;

	/*
	* NPT, the only paging mode that uses this horror, uses a fixed number
	* of levels for the shadow page tables, e.g. all MMUs are 4-level or
	* all MMUs are 5-level. Thus, this can safely require that pml5_root
	* is allocated if the other roots are valid and pml5 is needed, as any
	* prior MMU would also have required pml5.
	*/
	if (mmu->pae_root && mmu->pml4_root && (!need_pml5 || mmu->pml5_root))
		return 0;

	/*
	* The special roots should always be allocated in correct. Yell and
	* bail if KVM ends up in a state where only one of the roots is valid.
	*/
	if (!tdp_enabled || mmu->pae_root || mmu->pml4_root ||
		(need_pml5 && mmu->pml5_root))
		return STATUS_IO_DEVICE_ERROR;

	/*
	* Unlike 32-bit NPT, the PDP table doesn't need to be in low mem, and
	* doesn't need to be decrypted.
	*/
	pae_root = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, DRIVER_TAG);
	if (!pae_root)
		return STATUS_NO_MEMORY;
	RtlZeroMemory(pae_root, PAGE_SIZE);
	
	pml4_root = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, DRIVER_TAG);
	if (!pml4_root)
		goto err_pml4;
	RtlZeroMemory(pml4_root, PAGE_SIZE);
	
	if (need_pml5) {
		pml5_root = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, DRIVER_TAG);
		if (!pml5_root)
			goto err_pml5;
		RtlZeroMemory(pml5_root, PAGE_SIZE);
	}

	mmu->pae_root = pae_root;
	mmu->pml4_root = pml4_root;
	mmu->pml5_root = pml5_root;

	return STATUS_SUCCESS;

err_pml5:
	ExFreePool(pml4_root);
err_pml4:
	ExFreePool(pae_root);
	return STATUS_NO_MEMORY;
}

static ULONG_PTR kvm_mmu_available_pages(struct kvm* kvm) {
	if (kvm->arch.n_max_mmu_pages > kvm->arch.n_used_mmu_pages)
		return kvm->arch.n_max_mmu_pages -
		kvm->arch.n_used_mmu_pages;

	return 0;
}


#define KVM_PAGE_ARRAY_NR 16

struct kvm_mmu_pages {
	struct mmu_page_and_offset {
		struct kvm_mmu_page* sp;
		UINT idx;
	}page[KVM_PAGE_ARRAY_NR];
	UINT nr;
};

struct mmu_page_path {
	struct kvm_mmu_page* parent[PT64_ROOT_MAX_LEVEL];
	UINT idx[PT64_ROOT_MAX_LEVEL];
};

static int mmu_pages_add(struct kvm_mmu_pages* pvec, struct kvm_mmu_page* sp,
	int idx) {
	UINT i;

	if (sp->unsync)
		for (i = 0; i < pvec->nr; i++)
			if (pvec->page[i].sp == sp)
				return 0;

	pvec->page[pvec->nr].sp = sp;
	pvec->page[pvec->nr].idx = idx;
	pvec->nr++;
	return (pvec->nr == KVM_PAGE_ARRAY_NR);
}

static void clear_unsync_child_bit(struct kvm_mmu_page* sp, int idx) {
	--sp->unsync_children;
	RtlClearBit(&sp->unsync_child_bitmap, idx);
}

static int __mmu_unsync_walk(struct kvm_mmu_page* sp,
	struct kvm_mmu_pages* pvec) {
	int i = 0xFFFFFFFF;
	int ret;
	int nr_unsync_leaf = 0;
	ULONG idx = 0;

	do
	{
		i = RtlFindSetBits(&sp->unsync_child_bitmap, 1, idx);
		if (0xFFFFFFFF == i)
			break;
		idx = i + 1;

		struct kvm_mmu_page* child;
		u64 ent = sp->spt[i];

		if (!is_shadow_present_pte(ent) || is_large_pte(ent)) {
			clear_unsync_child_bit(sp, i);
			continue;
		}
		
		child = spte_to_child_sp(ent);

		if (child->unsync_children) {
			if (mmu_pages_add(pvec, child, i))
				return STATUS_NO_MEMORY;

			ret = __mmu_unsync_walk(child, pvec);
			if (!ret) {
				clear_unsync_child_bit(sp, i);
				continue;
			}
			else if (ret > 0) {
				nr_unsync_leaf += ret;
			}
			else
				return ret;
		}
		else if (child->unsync) {
			nr_unsync_leaf++;
			if (mmu_pages_add(pvec, child, i))
				return STATUS_NO_MEMORY;
		}
		else
			clear_unsync_child_bit(sp, i);

	} while (TRUE);
	
	

	return nr_unsync_leaf;
}

#define INVALID_INDEX (-1)

static int mmu_unsync_walk(struct kvm_mmu_page* sp,
	struct kvm_mmu_pages* pvec) {
	pvec->nr = 0;
	if (!sp->unsync_children)
		return 0;

	mmu_pages_add(pvec, sp, INVALID_INDEX);
	return __mmu_unsync_walk(sp, pvec);
}



static int mmu_pages_next(struct kvm_mmu_pages* pvec,
	struct mmu_page_path* parents,
	int i) {
	UINT n;

	for (n = i + 1; n < pvec->nr; n++) {
		struct kvm_mmu_page* sp = pvec->page[n].sp;
		UINT idx = pvec->page[n].idx;
		int level = sp->role.level;

		parents->idx[level - 1] = idx;
		if (level == PG_LEVEL_4K)
			break;

		parents->parent[level - 2] = sp;
	}

	return n;
}

static int mmu_pages_first(struct kvm_mmu_pages* pvec,
	struct mmu_page_path* parents) {
	struct kvm_mmu_page* sp;
	int level;

	if (pvec->nr == 0)
		return 0;

	sp = pvec->page[0].sp;
	level = sp->role.level;

	parents->parent[level - 2] = sp;

	/*
	* Also set up a sentinel. Futher entries in pvec are all
	* children of sp, so this element is never overwritten.
	*/
	parents->parent[level - 1] = NULL;
	return mmu_pages_next(pvec, parents, 0);
}

#define for_each_sp(pvec, sp, parents, i)			\
		for (i = mmu_pages_first(&pvec, &parents);	\
			i < pvec.nr;	\
			i = mmu_pages_next(&pvec, &parents, i))

static void mmu_pages_clear_parents(struct mmu_page_path* parents) {
	struct kvm_mmu_page* sp;
	UINT level = 0;

	do
	{
		UINT idx = parents->idx[level];
		sp = parents->parent[level];
		if (!sp)
			return;

		clear_unsync_child_bit(sp, idx);
		level++;
	} while (!sp->unsync_children);
}





static bool kvm_mmu_prepare_zap_page(struct kvm* kvm, struct kvm_mmu_page* sp,
	PLIST_ENTRY invalid_list) {
	int nr_zapped;

	__kvm_mmu_prepare_zap_page(kvm, sp, invalid_list, &nr_zapped);
	return nr_zapped;
}

static int mmu_zap_unsync_children(struct kvm* kvm,
	struct kvm_mmu_page* parent,
	PLIST_ENTRY invalid_list) {
	UINT i;
	int zapped = 0;
	struct mmu_page_path parents;
	struct kvm_mmu_pages pages;

	if (parent->role.level == PG_LEVEL_4K)
		return 0;

	while (mmu_unsync_walk(parent, &pages)) {
		struct kvm_mmu_page* sp;

		for_each_sp(pages, sp, parents, i) {
			sp = pages.page[i].sp;
			kvm_mmu_prepare_zap_page(kvm, sp, invalid_list);
			mmu_pages_clear_parents(&parents);
			zapped++;
		}
	}


	return zapped;
}

/* Returns the number of zapped non-leaf child shadow pages. */
static int mmu_page_zap_pte(struct kvm* kvm, struct kvm_mmu_page* sp,
	u64* spte, PLIST_ENTRY invalid_list) {
	u64 pte;
	struct kvm_mmu_page* child;

	pte = *spte;
	if (is_shadow_present_pte(pte)) {
		if (is_last_spte(pte, sp->role.level)) {

		}
		else {
			child = spte_to_child_sp(pte);
			
			/*
			* Recursively zap nested TDP SPs, parentless SPs are
			* unlikely to be used again in the near future. This
			* avoids retaining a large number of stale nested SPs.
			*/
			if (tdp_enabled && invalid_list &&
				child->role.guest_mode) {
				return kvm_mmu_prepare_zap_page(kvm, child,
					invalid_list);
			}
		}
	}
	else if (is_mmio_spte(pte)) {

	}
	return 0;
}

static int kvm_mmu_page_unlink_children(struct kvm* kvm,
	struct kvm_mmu_page* sp,
	PLIST_ENTRY invalid_list) {
	int zapped = 0;

	for (int i = 0; i < SPTE_ENT_PER_PAGE; ++i) {
		zapped += mmu_page_zap_pte(kvm, sp, sp->spt + i, invalid_list);
	}

	return zapped;
}

bool __kvm_mmu_prepare_zap_page(struct kvm* kvm,
	struct kvm_mmu_page* sp,
	PLIST_ENTRY invalid_list,
	int* nr_zapped) {
	bool list_unstable;
	// bool zapped_root = FALSE;

	++kvm->stat.mmu_shadow_zapped;
	*nr_zapped = mmu_zap_unsync_children(kvm, sp, invalid_list);
	*nr_zapped += kvm_mmu_page_unlink_children(kvm, sp, invalid_list);
	

	/* Zapping children means active_mmu_pages has become unstable. */
	list_unstable = *nr_zapped;

	/*
	* Make the request to free obsolete roots after marking the root
	* invalid, otherwise other vCPUs may not see it as invalid.
	*/

	return list_unstable;
}

static void kvm_mmu_free_shadow_page(struct kvm_mmu_page* sp) {
	hlist_del(&sp->hash_link);
	RemoveEntryList(&sp->link);
	ExFreePool(sp->spt);
	if (!sp->role.direct)
		ExFreePool(sp->shadowed_translation);
}

static void kvm_mmu_commit_zap_page(struct kvm* kvm,
	PLIST_ENTRY invalid_list) {
	struct kvm_mmu_page* sp;

	if (IsListEmpty(invalid_list))
		return;

	PLIST_ENTRY pListHead = &kvm->arch.active_mmu_pages;
	PLIST_ENTRY pEntry = pListHead->Blink;
	while (pEntry != pListHead) {
		sp = CONTAINING_RECORD(pEntry, struct kvm_mmu_page, link);
		kvm_mmu_free_shadow_page(sp);
	}
}

static ULONG kvm_mmu_zap_oldest_mmu_pages(struct kvm* kvm,
	ULONG_PTR nr_to_zap) {
	ULONG total_zapped = 0;
	struct kvm_mmu_page* sp;

	LIST_ENTRY invalid_list;
	bool unstable;
	int nr_zapped;

	if (IsListEmpty(&kvm->arch.active_mmu_pages))
		return 0;
	PLIST_ENTRY pListHead = NULL;
	PLIST_ENTRY pEntry = NULL;

restart:
	pListHead = &kvm->arch.active_mmu_pages;
	pEntry = pListHead->Blink;
	while (pEntry != pListHead) {
		sp = CONTAINING_RECORD(pEntry, struct kvm_mmu_page, link);
		/*
		* Don't zap active root pages, the page itself can't be freed
		* and zapping it will just force vCPUs to realloc and reload.
		*/
		if (sp->root_count)
			continue;

		unstable = __kvm_mmu_prepare_zap_page(kvm, sp, &invalid_list,
			&nr_zapped);

		total_zapped += nr_zapped;
		if (total_zapped >= nr_to_zap)
			break;

		if (unstable)
			goto restart;
	}

	kvm_mmu_commit_zap_page(kvm, &invalid_list);

	kvm->stat.mmu_recycled += total_zapped;
	return total_zapped;
}

static int make_mmu_pages_available(struct kvm_vcpu* vcpu) {
	ULONG_PTR avail = kvm_mmu_available_pages(vcpu->kvm);
	if (avail >= KVM_MIN_FREE_MMU_PAGES)
		return 0;

	kvm_mmu_zap_oldest_mmu_pages(vcpu->kvm, KVM_REFILL_PAGES - avail);

	if (!kvm_mmu_available_pages(vcpu->kvm))
		return STATUS_NO_MEMORY;
	
	return 0;
}

static int mmu_alloc_direct_roots(struct kvm_vcpu* vcpu) {
	struct kvm_mmu* mmu = vcpu->arch.mmu;
	UINT shadow_root_level = mmu->root_role.level;
	hpa_t root;
	unsigned i;
	int r = 0;

	do
	{
		r = make_mmu_pages_available(vcpu);
		if (r < 0)
			break;

		// 根据当前vcpu的分页模式建立ept顶层页表的管理结构
		if (tdp_mmu_enabled) {
			root = kvm_tdp_mmu_get_vcpu_root_hpa(vcpu);
			// 影子页表页物理地址, 即 EPTP
			mmu->root.hpa = root;
		}
		else if (shadow_root_level >= PT64_ROOT_4LEVEL) {

		}
		else if (shadow_root_level == PT32E_ROOT_LEVEL) {


			for (i = 0; i < 4; ++i) {

			}

		}
		else {

		}

		/* root.pgd is ignored for direct MMUs. */
		mmu->root.pgd = 0;

	} while (FALSE);
	
	

	return r;
}

static int mmu_alloc_shadow_roots(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);
	//struct kvm_mmu* mmu = vcpu->arch.mmu;
	//u64 pdptrs[4], pm_mask;
	//gfn_t root_gfn, root_pgd;
	//int quadrant, i;
	int r = 0;
	//hpa_t root;

	return r;
}

int kvm_mmu_load(struct kvm_vcpu* vcpu) {
	int r = 0;

	do
	{
		// 分配mmu_pte_list_desc_cache和mmu_page_header_cache等
		r = mmu_topup_memory_caches(vcpu, !vcpu->arch.mmu->root_role.direct);
		if (r)
			break;
		r = mmu_alloc_special_roots(vcpu);
		if (r)
			break;
		// 初始化根目录的页面
		if (vcpu->arch.mmu->root_role.direct)
			r = mmu_alloc_direct_roots(vcpu);
		else
			r = mmu_alloc_shadow_roots(vcpu);
		if (r)
			break;
		
		// 加载pgd,即cr3
		kvm_mmu_load_pgd(vcpu);

		/*
		* Flush any TLB entries for the new root, the provenance of  the root
		* is unknown. Even if KVM ensures there are no stale TLB entries
		* for a freed root, in theory hypervisor could have left 
		* stale entries. Flusing on alloc also allows KVM to skip the TLB
		* flush when freeing a root (see kvm_tdp_mmu_put_root())
		*/
		kvm_x86_ops.flush_tlb_current(vcpu);
	} while (FALSE);
	

	return r;
}

static inline int kvm_mmu_get_tdp_level(struct kvm_vcpu* vcpu)
{
	/* tdp_root_level is architecture forced level, use it if nonzero */
	if (tdp_root_level)
		return tdp_root_level;

	/* Use 5-level TDP if and only if it's useful/necessary. */
	if (max_tdp_level == 5 && cpuid_maxphyaddr(vcpu) <= 48)
		return 4;

	return max_tdp_level;
}

static union kvm_mmu_page_role
kvm_calc_tdp_mmu_root_page_role(struct kvm_vcpu* vcpu,
	union kvm_cpu_role cpu_role)
{
	union kvm_mmu_page_role role = { 0 };

	role.access = ACC_ALL;
	role.cr0_wp = TRUE;
	role.efer_nx = TRUE;
	role.smm = cpu_role.base.smm;
	role.guest_mode = cpu_role.base.guest_mode;
	role.ad_disabled = !kvm_ad_enabled();
	role.level = kvm_mmu_get_tdp_level(vcpu);
	role.direct = TRUE;
	role.has_4_byte_gpte = FALSE;

	return role;
}

static ULONG_PTR get_guest_cr3(struct kvm_vcpu* vcpu)
{
	return kvm_read_cr3(vcpu);
}

static gpa_t nonpaging_gva_to_gpa(struct kvm_vcpu* vcpu, struct kvm_mmu* mmu,
	gpa_t vaddr, u64 access,
	struct x86_exception* exception)
{
	if (exception)
		exception->error_code = 0;
	return kvm_translate_gpa(vcpu, mmu, vaddr, access, exception);
}

static inline bool is_cr0_pg(struct kvm_mmu* mmu)
{
	return mmu->cpu_role.base.level > 0;
}

static inline bool is_cr4_pae(struct kvm_mmu* mmu) {
	return !mmu->cpu_role.base.has_4_byte_gpte;
}

static int is_cpuid_PSE36(void) {
	return 1;
}

static void __reset_rsvds_bits_mask(struct rsvd_bits_validate* rsvd_check,
	u64 pa_bits_rsvd, int level, bool nx, bool gbpages, bool pse, bool amd) {
	u64 gbpages_bit_rsvd = 0;
	u64 nonleaf_bit8_rsvd = 0;
	u64 high_bits_rsvd;

	rsvd_check->bad_mt_xwr = 0;

	if (!gbpages)
		gbpages_bit_rsvd = rsvd_bits(7, 7);

	if (level == PT32E_ROOT_LEVEL)
		high_bits_rsvd = pa_bits_rsvd & rsvd_bits(0, 62);
	else
		high_bits_rsvd = pa_bits_rsvd & rsvd_bits(0, 51);

	/* Note, NX doesn't exist in PDPTEs, this is handled below. */
	if (!nx)
		high_bits_rsvd |= rsvd_bits(63, 63);

	/*
	* Non-leaf PML4Es and PDPEs reserve bit 8 (which would be the G bit for
	* leaf entries) on AMD CPUs only.
	*/
	if (amd)
		nonleaf_bit8_rsvd = rsvd_bits(8, 8);

	switch (level)
	{
		case PT32_ROOT_LEVEL:
			/* no rsvd bits for 2 level 4K page table entries */
			rsvd_check->rsvd_bits_mask[0][1] = 0;
			rsvd_check->rsvd_bits_mask[0][0] = 0;
			rsvd_check->rsvd_bits_mask[1][0] =
				rsvd_check->rsvd_bits_mask[0][0];

			if (!pse) {
				rsvd_check->rsvd_bits_mask[1][1] = 0;
				break;
			}

			if (is_cpuid_PSE36())
				/* 36bits PSE 4MB page */
				rsvd_check->rsvd_bits_mask[1][1] = rsvd_bits(17, 21);
			else
				/* 32 bits PSE 4MB page */
				rsvd_check->rsvd_bits_mask[1][1] = rsvd_bits(13, 21);
			break;
		default:
			break;
	}
}

static void reset_guest_rsvds_bits_mask(struct kvm_vcpu* vcpu,
	struct kvm_mmu* context) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(context);
}

static void reset_guest_paging_metadata(struct kvm_vcpu* vcpu,
	struct kvm_mmu* mmu) {
	UNREFERENCED_PARAMETER(vcpu);
	if (!is_cr0_pg(mmu))
		return;

	reset_guest_paging_metadata(vcpu, mmu);
}

// EPT的初始化,基本上就是填充vcpu->arch.root_mmu结构体
static void init_kvm_tdp_mmu(struct kvm_vcpu* vcpu,
	union kvm_cpu_role cpu_role) {
	struct kvm_mmu* context = &vcpu->arch.root_mmu;
	union kvm_mmu_page_role root_role = kvm_calc_tdp_mmu_root_page_role(vcpu, cpu_role);

	if (cpu_role.as_u64 == context->cpu_role.as_u64 &&
		root_role.word == context->root_role.word)
		return;

	context->cpu_role.as_u64 = cpu_role.as_u64;
	context->root_role.word = root_role.word;
	context->page_fault = kvm_tdp_page_fault;
	context->sync_spte = NULL;
	context->get_guest_pgd = get_guest_cr3;
	context->get_pdptr = kvm_pdptr_read;
	context->inject_page_fault = kvm_inject_page_fault;

	if (!is_cr0_pg(context))
		context->gva_to_gpa = nonpaging_gva_to_gpa;
	else if (is_cr4_pae(context))
		context->gva_to_gpa = paging64_gva_to_gpa;
	else
		context->gva_to_gpa = paging32_gva_to_gpa;

	
}

// mmu的初始化
void kvm_init_mmu(struct kvm_vcpu* vcpu) {
	struct kvm_mmu_role_regs regs = vcpu_to_role_regs(vcpu);
	union kvm_cpu_role cpu_role = kvm_calc_cpu_role(vcpu, &regs);

	if (mmu_is_nested(vcpu)) // 嵌套虚拟化
		init_kvm_nested_mmu(vcpu, cpu_role);
	else if (tdp_enabled) // 是否支持EPT
		init_kvm_tdp_mmu(vcpu, cpu_role);
	else // 影子页表
		init_kvm_softmmu(vcpu, cpu_role);
}

static void shadow_walk_init_using_root(struct kvm_shadow_walk_iterator* iterator,
	struct kvm_vcpu* vcpu, hpa_t root,
	u64 addr) {
	/* 把要索引的地址赋值给addr */
	iterator->addr = addr;
	// 初始化时，指向EPT Pointer的基地址
	iterator->shadow_addr = root;
	// 影子页表级数
	iterator->level = vcpu->arch.mmu->root_role.level;

	if (iterator->level >= PT64_ROOT_4LEVEL &&
		vcpu->arch.mmu->cpu_role.base.level < PT64_ROOT_4LEVEL &&
		!vcpu->arch.mmu->root_role.direct)
		iterator->level = PT32E_ROOT_LEVEL;

	if (iterator->level == PT32E_ROOT_LEVEL) {
		/*
		* prev_root is currently only used for 64-bits hosts. So only
		* the active root_hpa is valid here.
		*/
		iterator->shadow_addr = vcpu->arch.mmu->pae_root[(addr >> 30) & 3];
		iterator->shadow_addr &= SPTE_BASE_ADDR_MASK;
		--iterator->level;
		if (!iterator->shadow_addr)
			iterator->level = 0;
	}
}

/*
* 负责初始化iterator结构，准备遍历EPT页表
* @addr 是发生EPT violation的guest物理地址
* @vcpu 是发生EPT violation的vcpu
* @iterator 迭代器
*/
static void shadow_walk_init(struct kvm_shadow_walk_iterator* iterator,
	struct kvm_vcpu* vcpu, u64 addr)
{
	shadow_walk_init_using_root(iterator, vcpu, vcpu->arch.mmu->root.hpa,
		addr);
}

/*
* 检查当前页表是否还需要遍历当前页表
*/
static bool shadow_walk_okay(struct kvm_shadow_walk_iterator* iterator)
{
	/*
	* 当level小于1的时候说明已经遍历完最后一个级别，也就不需要遍历了
	*/
	if (iterator->level < PG_LEVEL_4K)
		return FALSE;

	/*
	* 得到addr在当前level级页表中表项的索引值
	*/
	iterator->index = SPTE_INDEX(iterator->addr, iterator->level);
	PHYSICAL_ADDRESS physical;
	// shadow_addr指向当前level级页表的基地址
	physical.QuadPart = iterator->shadow_addr;
	/*
	 * 通过加上偏移index得到对应的页表项地址，
	 * 表项中会指向下一级页表的地址
	 */
	iterator->sptep = ((u64*)MmGetVirtualForPhysical(physical))
		+ iterator->index;

	return TRUE;
}

/*
* 处理完了当前级别页表，取得下一级页表。
*/
static void __shadow_walk_next(struct kvm_shadow_walk_iterator* iterator,
	u64 spte) {
	/*
	* 如果当前页表项已经是叶子页表项，直接处理level=0
	* 以便在shadow_walk_okay中退出
	*/
	if (!is_shadow_present_pte(spte) || is_last_spte(spte, iterator->level)) {
		iterator->level = 0;
		return;
	}

	/*
	* 不是最后一级页表的页表项的话
	* 从SPTE中取出下一级影子页表的基地址，记录到shadow_addr
	* 此处得到的是下一级页表的物理地址
	*/
	iterator->shadow_addr = spte & SPTE_BASE_ADDR_MASK;
	// 因为到了下一级页表，页表级别也相应减1。
	--iterator->level;
}

static void shadow_walk_next(struct kvm_shadow_walk_iterator* iterator)
{
	__shadow_walk_next(iterator, *iterator->sptep);
}

#define for_each_shadow_entry(_vcpu, _addr, _walker)            \
	for (shadow_walk_init(&(_walker), _vcpu, _addr);	\
	     shadow_walk_okay(&(_walker));			\
	     shadow_walk_next(&(_walker)))

/*
* 用于设置影子页表项
*/
static int mmu_set_spte(struct kvm_vcpu* vcpu, struct kvm_memory_slot* slot,
	u64* sptep, unsigned int pte_access, gfn_t gfn,
	kvm_pfn_t pfn, struct kvm_page_fault* fault) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(slot);
	UNREFERENCED_PARAMETER(sptep);
	UNREFERENCED_PARAMETER(pte_access);
	UNREFERENCED_PARAMETER(gfn);
	UNREFERENCED_PARAMETER(pfn);
	UNREFERENCED_PARAMETER(fault);
	int ret = RET_PF_FIXED;

	return ret;
}

static union kvm_mmu_page_role kvm_mmu_child_role(u64* sptep, bool direct,
	unsigned int access) {
	struct kvm_mmu_page* parent_sp = sptep_to_sp(sptep);
	union kvm_mmu_page_role role;

	role = parent_sp->role;
	role.level--;
	role.access = access;
	role.direct = direct;
	role.passthrough = 0;

	if (role.has_4_byte_gpte) {
		role.quadrant = spte_index(sptep) & 1;
	}

	return role;
}

/* Caches used when allocating a new shadow page. */
struct shadow_page_caches {
	struct kvm_mmu_memory_cache* page_header_cache;
	struct kvm_mmu_memory_cache* shadow_page_cache;
	struct kvm_mmu_memory_cache* shadowed_info_cache;
};

static unsigned kvm_page_table_hashfn(gfn_t gfn) {
	UNREFERENCED_PARAMETER(gfn);

	return 0;
}

/* Note, @vcpu may be NULL if @role.direct is true; see kvm_mmu_find_shadow_page. */
static struct kvm_mmu_page* __kvm_mmu_get_shadow_page(struct kvm* kvm,
	struct kvm_vcpu* vcpu,
	struct shadow_page_caches* caches,
	gfn_t gfn,
	union kvm_mmu_page_role role)
{
	UNREFERENCED_PARAMETER(kvm);
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(caches);
	UNREFERENCED_PARAMETER(gfn);
	UNREFERENCED_PARAMETER(role);
	//struct hlist_head* sp_list;
	struct kvm_mmu_page* sp = NULL;
	/*bool created = FALSE;

	sp_list = &kvm->arch.mmu_page_hash[kvm_page_table_hashfn(gfn)];

	sp = kvm_mmu_find_shadow_page(kvm, vcpu, gfn, sp_list, role);
	if (!sp) {
		created = TRUE;
		sp = kvm_mmu_alloc_shadow_page(kvm, caches, gfn, sp_list, role);
	}*/

	
	return sp;
}

static struct kvm_mmu_page* kvm_mmu_get_shadow_page(struct kvm_vcpu* vcpu,
	gfn_t gfn,
	union kvm_mmu_page_role role) {
	struct shadow_page_caches caches = {
		.page_header_cache = &vcpu->arch.mmu_page_header_cache,
		.shadow_page_cache = &vcpu->arch.mmu_shadow_page_cache,
		.shadowed_info_cache = &vcpu->arch.mmu_shadowed_info_cache,
	};

	return __kvm_mmu_get_shadow_page(vcpu->kvm, vcpu, &caches, gfn, role);
}

static struct kvm_mmu_page* kvm_mmu_get_child_sp(struct kvm_vcpu* vcpu,
	u64* sptep, gfn_t gfn,
	bool direct, unsigned int access) {
	union kvm_mmu_page_role role;

	if (is_shadow_present_pte(*sptep) && !is_large_pte(*sptep))
		return (struct kvm_mmu_page*)STATUS_ALREADY_COMMITTED;

	role = kvm_mmu_child_role(sptep, direct, access);
	return kvm_mmu_get_shadow_page(vcpu, gfn, role);
}

static void drop_spte(struct kvm* kvm, u64* sptep) {
	UNREFERENCED_PARAMETER(kvm);
	UNREFERENCED_PARAMETER(sptep);
}

static void drop_large_spte(struct kvm* kvm, u64* sptep, bool flush) {
	struct kvm_mmu_page* sp;

	sp = sptep_to_sp(sptep);

	drop_spte(kvm, sptep);

	if (flush) {

	}
}

static void mmu_spte_set(u64* sptep, u64 new_spte) {
	*sptep = new_spte;
}

static void mmu_page_add_parent_pte(struct kvm_mmu_memory_cache* cache,
	struct kvm_mmu_page* sp, u64* parent_pte) {
	UNREFERENCED_PARAMETER(cache);
	UNREFERENCED_PARAMETER(sp);
	if (!parent_pte)
		return;

	
}

static void __link_shadow_page(struct kvm* kvm,
	struct kvm_mmu_memory_cache* cache, u64* sptep,
	struct kvm_mmu_page* sp, bool flush) {
	UNREFERENCED_PARAMETER(cache);
	u64 spte;

	if (is_shadow_present_pte(*sptep))
		drop_large_spte(kvm, sptep, flush);

	spte = make_nonleaf_spte(sp->spt, sp_ad_disabled(sp));
	
	// 设置页表项(sptep)指向下一级页表页(spte)
	mmu_spte_set(sptep, spte);


}

/*
* 将新分配出来的下一级影子页表的地址填写到本级对应的SPTE中
*/
static void link_shadow_page(struct kvm_vcpu* vcpu, u64* sptep,
	struct kvm_mmu_page* sp) {
	__link_shadow_page(vcpu->kvm, &vcpu->arch.mmu_pte_list_desc_cache, sptep, sp, TRUE);
}


/*
* 完成EPT页表的构造，并在最后一级页表项中将gfn同pfn映射起来
*/
static int direct_map(struct kvm_vcpu* vcpu, struct kvm_page_fault* fault) {
	struct kvm_shadow_walk_iterator it;
	struct kvm_mmu_page* sp;
	int ret;
	gfn_t base_gfn = fault->gfn;

	kvm_mmu_hugepage_adjust(vcpu, fault);

	for_each_shadow_entry(vcpu, fault->addr, it) {
		/*
		* We cannot overwrite existing page tables with an NX
		* large page, as the leaf could be executable.
		*/
		if (fault->nx_huge_page_workaround_enabled)
			disallowed_hugepage_adjust(fault, *it.sptep, it.level);
		
		base_gfn = gfn_round_for_level(fault->gfn, it.level);
		if (it.level == fault->goal_level)
			break;
		
		sp = kvm_mmu_get_child_sp(vcpu, it.sptep, base_gfn, TRUE, ACC_ALL);
		if (sp == LongToPtr(STATUS_ALREADY_COMMITTED)) {
			continue;
		}

		link_shadow_page(vcpu, it.sptep, sp);
	}

	if (it.level != fault->goal_level)
		return STATUS_FAIL_CHECK;

	ret = mmu_set_spte(vcpu, fault->slot, it.sptep, ACC_ALL,
		base_gfn, fault->pfn, fault);
	if (ret == RET_PF_SPURIOUS)
		return ret;

	
	return 0;
}

static bool page_fault_can_be_fast(struct kvm_page_fault* fault) {
	/*
	* Page faults with reserved bits set, i.e. faults on MMIO SPTEs, only
	* reach the common page fault handler if the SPTE has an invalid MMIO
	* generation number. Refreshing the MMIO generation needs to go down
	* the slow path. Note, EPT Misconfigs do NOT set the PRESENT flag!
	*/
	if (fault->rsvd)
		return FALSE;

	/*
	* #PF can be fast if:
	* 
	* 1. The shadow page table entry is not present and A/D bits are
	* disabled _by KVM_, which could mean that the fault is potentially
	* caused by access tracking (if enabled). If A/D bits are enabled
	* by KVM, but disabled by L1 for L2, KVM is forced to disable A/D
	* bits for L2 and employ access tracking, but the fast page fault
	* mechanism only supports direct MMUs.
	* 2. The shadow page table entry is present, the access is a write,
	* and no reserved bits are set (MMIO_SPTEs cannot be "fixed"), i.e.
	* the fault was caused by a write-protection violation. If the 
	* SPTE is MMU-writable (determined later), the fault can be fixed
	* by setting the Writable bit, which can be done out of mmu_lock.
	*/
	if (!fault->present)
		return !kvm_ad_enabled();

	/*
	* Note, instruction fetches and writes are mutally exclusive, ignore
	* the "exec" flag.
	*/
	return fault->write;
}

/*
* Returns the last level spte pointer of the shadow page walk for the given
* gpa, and sets *spte to the spte value. This spte may be non-present. If no
* walk could be performed, returns NULL and *spte does not contain valid data.
* 
* Contract:
* - Must be called between walk_shadow_page_lockless_{begin,end}.
* - The returned sptep must not be used after walk_shadow_page_lockless_end.
*/
static u64* fast_pf_get_last_sptep(struct kvm_vcpu* vcpu, gpa_t gpa, u64* spte)
{
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(gpa);
	UNREFERENCED_PARAMETER(spte);
	return NULL;
}



static bool is_access_allowed(struct kvm_page_fault* fault, u64 spte) {
	if (fault->exec)
		return is_executable_pte(spte);

	if (fault->write)
		return is_writable_pte(spte);

	/* Fault was on Read access */
	return spte & PT_PRESENT_MASK;
}

/*
 * Returns one of RET_PF_INVALID, RET_PF_FIXED or RET_PF_SPURIOUS.
 */
static int fast_page_fault(struct kvm_vcpu* vcpu,
	struct kvm_page_fault* fault) {
	struct kvm_mmu_page* sp;
	int ret = RET_PF_INVALID;
	u64 spte = 0ull;
	u64* sptep = NULL;
	uint retry_count = 0;

	if (!page_fault_can_be_fast(fault))
		return ret;

	do
	{
		u64 new_spte;

		if (tdp_mmu_enabled)
			sptep = kvm_tdp_mmu_fast_pf_get_last_sptep(vcpu, fault->addr, &spte);
		else
			sptep = fast_pf_get_last_sptep(vcpu, fault->addr, &spte);
		
		if (!is_shadow_present_pte(spte))
			break;

		sp = sptep_to_sp(sptep);
		if (!is_last_spte(spte, sp->role.level))
			break;

		/*
		* 
		*/
		if (is_access_allowed(fault, spte)) {
			ret = RET_PF_SPURIOUS;
			break;
		}

		new_spte = spte;

		/*
		* KVM only supports fixing page faults outside of MMU lock for
		* direct MMUs, nested MMUs are always indirect, and KVM always
		* uses A/D bits for non-nested MMUs. Thus, if A/D bits are
		* enabled, the SPTE can't be an access-tracked SPTE.
		*/
		if (!kvm_ad_enabled() && is_access_track_spte(spte))
			new_spte = restore_acc_track_spte(new_spte);

		if (fault->write && is_mmu_writable_spte(spte)) {
			new_spte |= PT_WRITABLE_MASK;

			
		}

		if (new_spte == spte ||
			!is_access_allowed(fault, new_spte))
			break;


		if (++retry_count > 4) {
			// Fast #PF retrying more than 4 times.
			break;
		}
	} while (TRUE);

	return RET_PF_INVALID;
}

static int direct_page_fault(struct kvm_vcpu* vcpu, 
	struct kvm_page_fault* fault) {
	int r;

	r = fast_page_fault(vcpu, fault);
	if (r != RET_PF_INVALID)
		return r;

	// 分配缓存池
	r = mmu_topup_memory_caches(vcpu, FALSE);
	if (r)
		return r;

	r = RET_PF_RETRY;


	r = direct_map(vcpu, fault);
	

	return r;
}

static bool page_fault_handle_page_track(struct kvm_vcpu* vcpu,
	struct kvm_page_fault* fault) {
	UNREFERENCED_PARAMETER(vcpu);
	if (fault->rsvd)
		return FALSE;

	if (!fault->present || !fault->write)
		return FALSE;

	/*
	* guest is writing the page which is write tracked which can
	* not be fixed by page fault handler.
	*/
	
	return FALSE;
}

static bool is_obsolete_sp(struct kvm* kvm, struct kvm_mmu_page* sp) {
	if (sp->role.invalid)
		return TRUE;

	/* TDP MMU pages do not use the MMU generation. */
	return !is_tdp_mmu_page(sp) &&
		sp->mmu_valid_gen != kvm->arch.mmu_valid_gen;
}

/*
* Returns true if the page fault is stale and needs to be retried, i.e. if the
* root was invalidated by a memslot update or a relevant mmu_notifier fired.
*/
static bool is_page_fault_stale(struct kvm_vcpu* vcpu,
	struct kvm_page_fault* fault) {
	struct kvm_mmu_page* sp = to_shadow_page(vcpu->arch.mmu->root.hpa);
	
	/* Special roots, e.g. pae_root, are not backed by shadow pages. */
	if (sp && is_obsolete_sp(vcpu->kvm, sp))
		return TRUE;

	/*
	* Roots without an associated shadow page are considered invalid if
	* there is a pending request to free obsolete roots. The request is
	* only a hint that the current root _may_ be obsolete and needs to be
	* reloaded, e.g. if the guest frees a PGD that KVM is tracking as a previous
	* root, then __kvm_mmu_prepare_zap_page() signals all vCPUs
	* to reload even if no vCPU is actively using the root.
	*/
	

	return fault->slot &&
		mmu_invalidate_retry_hva(vcpu->kvm, fault->mmu_seq, fault->hva);
}

#ifdef AMD64
static int kvm_tdp_mmu_page_fault(struct kvm_vcpu* vcpu,
	struct kvm_page_fault* fault) {
	int r;

	if (page_fault_handle_page_track(vcpu, fault))
		return RET_PF_EMULATE;

	// 快速处理一个简单的page fault
	r = fast_page_fault(vcpu, fault);
	if (r != RET_PF_INVALID)
		return r;

	r = mmu_topup_memory_caches(vcpu, FALSE);
	if (r)
		return r;

	r = RET_PF_RETRY;

	if (is_page_fault_stale(vcpu, fault))
		goto out_unlock;

	r = kvm_tdp_mmu_map(vcpu, fault);

out_unlock:

	
	return r;
}
#endif // AMD64

// 建立页表项
int kvm_tdp_page_fault(struct kvm_vcpu* vcpu, struct kvm_page_fault* fault) {
	/*
	 * If the guest's MTRRs may be used to compute the "real" memtype,
	 * restrict the mapping level to ensure KVM uses a consistent memtype
	 * across the entire mapping.  If the host MTRRs are ignored by TDP
	 * (shadow_memtype_mask is non-zero), and the VM has non-coherent DMA
	 * (DMA doesn't snoop CPU caches), KVM's ABI is to honor the memtype
	 * from the guest's MTRRs so that guest accesses to memory that is
	 * DMA'd aren't cached against the guest's wishes.
	 *
	 * Note, KVM may still ultimately ignore guest MTRRs for certain PFNs,
	 * e.g. KVM will force UC memtype for host MMIO.
	 */

#ifdef AMD64
	if (tdp_mmu_enabled)
		return kvm_tdp_mmu_page_fault(vcpu, fault);
#endif // AMD64


	return direct_page_fault(vcpu, fault);
}





static int __kvm_mmu_create(struct kvm_vcpu* vcpu, struct kvm_mmu* mmu) {
	void* page;
	int i;

	mmu->root.hpa = INVALID_PAGE;
	mmu->root.pgd = 0;
	for (i = 0; i < KVM_MMU_NUM_PREV_ROOTS; i++) {
		mmu->prev_roots[i] = KVM_MMU_ROOT_INFO_INVALID;
	}

	/* vcpu->arch.guest_mmu isn't used when !tdp_enabled. */
	if (!tdp_enabled && mmu == &vcpu->arch.guest_mmu)
		return 0;

	/*
	 * When using PAE paging, the four PDPTEs are treated as 'root' pages,
	 * while the PDP table is a per-vCPU construct that's allocated at MMU
	 * creation.  When emulating 32-bit mode, cr3 is only 32 bits even on
	 * x86_64.  Therefore we need to allocate the PDP table in the first
	 * 4GB of memory, which happens to fit the DMA32 zone.  TDP paging
	 * generally doesn't use PAE paging and can skip allocating the PDP
	 * table.  The main exception, handled here, is SVM's 32-bit NPT.  The
	 * other exception is for shadowing L1's 32-bit or PAE NPT on 64-bit
	 * KVM; that horror is handled on-demand by mmu_alloc_special_roots().
	 */
	if (tdp_enabled && kvm_mmu_get_tdp_level(vcpu) > PT32E_ROOT_LEVEL)
		return 0;

	page = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, DRIVER_TAG);
	if (!page)
		return STATUS_NO_MEMORY;
	RtlZeroMemory(page, PAGE_SIZE);

	mmu->pae_root = page;

	/*
	* CR3 is only 32 bits when PAE paging is used, thus it's impossible to
	* get the CPU to treat the PDPTEs as encrypted. Decrypt the page so
	* that KVM's writes and the CPU's reads get along. Note, this is
	* only necessary when using shadow paging, as 64-bit NPT can get at
	* the C-bit even when shadowing 32-bit NPT, and SME isn't supported
	* by 32-bit kernels (when KVM itself uses 32-bit NPT).
	*/

	for (i = 0; i < 4; ++i)
		mmu->pae_root[i] = INVALID_PAE_ROOT;

	return STATUS_SUCCESS;
}

static void free_mmu_pages(struct kvm_mmu* mmu) {
	ExFreePool(mmu->pae_root);
	ExFreePool(mmu->pml4_root);
	ExFreePool(mmu->pml5_root);
}

// 创建mmu
int kvm_mmu_create(struct kvm_vcpu* vcpu) {
	int ret;

	vcpu->arch.mmu_pte_list_desc_cache.kmem_cache = pte_list_desc_cache;
	
	vcpu->arch.mmu_page_header_cache.kmem_cache = mmu_page_header_cache;

	// walk_mmu和mmu是等价的
	vcpu->arch.mmu = &vcpu->arch.root_mmu;
	vcpu->arch.walk_mmu = &vcpu->arch.root_mmu;

	// guest_mmu 是嵌套的情况下，L1虚拟机mmu
	ret = __kvm_mmu_create(vcpu, &vcpu->arch.guest_mmu);
	if (ret)
		return ret;

	bool fail_allocate_root = FALSE;
	do
	{
		// 非嵌套情况下的虚拟机mmu
		ret = __kvm_mmu_create(vcpu, &vcpu->arch.root_mmu);
		if (ret) {
			fail_allocate_root = TRUE;
			break;
		}

		return ret;
	} while (FALSE);

	if (fail_allocate_root)
		free_mmu_pages(&vcpu->arch.guest_mmu);

	return ret;
}






static int mmu_first_shadow_root_alloc(struct kvm* kvm) {
	UNREFERENCED_PARAMETER(kvm);

	return 0;
}

static bool mmio_info_in_cache(struct kvm_vcpu* vcpu, u64 addr, 
	bool direct) {
	/*
	* A nested guest cannot use the MMIO cache if it is using nested
	* page tables, because cr2 is a nGPA while the cache stores GPAs.
	*/
	if (mmu_is_nested(vcpu))
		return FALSE;

	if (direct)
		return vcpu_match_mmio_gpa(vcpu, addr);

	return vcpu_match_mmio_gva(vcpu, addr);
}

static inline bool is_tdp_mmu_active(struct kvm_vcpu* vcpu) {
	return tdp_mmu_enabled && vcpu->arch.mmu->root_role.direct;
}

/*
* Return the level of the lowest level SPTE added to sptes.
* That SPTE may be non-present.
*/
static int get_walk(struct kvm_vcpu* vcpu, u64 addr, 
	u64* sptes, int* root_level) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(addr);
	UNREFERENCED_PARAMETER(sptes);
	UNREFERENCED_PARAMETER(root_level);
	int leaf = -1;

	return leaf;
}

/* return true if reserved bit(s) are detected on a valid, non-MMIO SPTE. */
static bool get_mmio_spte(struct kvm_vcpu* vcpu, u64 addr, u64* sptep)
{
	u64 sptes[PT64_ROOT_MAX_LEVEL + 1];
	struct rsvd_bits_validate* rsvd_check;
	int root, leaf, level;
	bool reserved = FALSE;

	if (is_tdp_mmu_active(vcpu)) {
		leaf = kvm_tdp_mmu_get_walk(vcpu, addr, sptes, &root);
	}
	else
		leaf = get_walk(vcpu, addr, sptes, &root);

	if (leaf < 0) {
		*sptep = 0ull;
		return reserved;
	}

	rsvd_check = &vcpu->arch.mmu->shadow_zero_check;

	for (level = root; level >= leaf; level--) {
		reserved |= is_rsvd_spte(rsvd_check, sptes[level], level);
	}

	*sptep = sptes[leaf];

	return reserved;
}

static int handle_mmio_page_fault(struct kvm_vcpu* vcpu, 
	u64 addr, bool direct) {
	u64 spte;
	bool reserved;

	if (mmio_info_in_cache(vcpu, addr, direct))
		return RET_PF_EMULATE;

	reserved = get_mmio_spte(vcpu, addr, &spte);

	/*
	* If the page table is zapped by other cpus, let CPU fault again on
	* the address
	*/
	return RET_PF_RETRY;
}

/*
* 处理page fault异常
*/
int kvm_mmu_page_fault(struct kvm_vcpu* vcpu, gpa_t cr2_or_gpa, u64 error_code,
	void* insn, int insn_len) {
	int r, emulation_type = EMULTYPE_PF;
	bool direct = (bool)vcpu->arch.mmu->root_role.direct;

	if (!VALID_PAGE(vcpu->arch.mmu->root.hpa))
		return RET_PF_RETRY;

	r = RET_PF_INVALID;
	// 判断是否是mmio引起的退出
	if (error_code & PFERR_RSVD_MASK) {
		// mmio引起的退出,会从handle_ept_misconfig调用过来
		r = handle_mmio_page_fault(vcpu, cr2_or_gpa, direct);
		if (r == RET_PF_EMULATE)
			goto emulate;
	}

	if (r == RET_PF_INVALID) {
		// EPT页表项无效
		r = kvm_mmu_do_page_fault(vcpu, cr2_or_gpa,
			lower_32_bits(error_code), FALSE,
			&emulation_type);
	}

	if (r < 0)
		return r;
	if (r != RET_PF_EMULATE)
		return 1;

emulate:
	return x86_emulate_instruction(vcpu, cr2_or_gpa,
		emulation_type, insn, insn_len);
}




int kvm_mmu_init_vm(struct kvm* kvm) {
	int r;

	if (tdp_mmu_enabled) {
		r = kvm_mmu_init_tdp_mmu(kvm);
		if (r < 0)
			return r;
	}



	return 0;
}

void kvm_mmu_uninit_vm(struct kvm* kvm) {
	if (tdp_mmu_enabled)
		kvm_mmu_uninit_tdp_mmu(kvm);
}

int kvm_mmu_post_init_vm(struct kvm* kvm) {
	UNREFERENCED_PARAMETER(kvm);
	return 0;
}

void kvm_mmu_pre_destroy_vm(struct kvm* kvm) {
	UNREFERENCED_PARAMETER(kvm);
}

void kvm_mmu_destroy(struct kvm_vcpu* vcpu) {
	kvm_mmu_unload(vcpu);

}

void kvm_mmu_unload(struct kvm_vcpu* vcpu) {
	struct kvm* kvm = vcpu->kvm;
	UNREFERENCED_PARAMETER(kvm);
	
}

static void mmu_free_root_page(struct kvm* kvm, hpa_t* root_hpa,
	PLIST_ENTRY invalid_list) {
	UNREFERENCED_PARAMETER(kvm);
	UNREFERENCED_PARAMETER(invalid_list);

	struct kvm_mmu_page* sp;
	if (!VALID_PAGE(*root_hpa))
		return;

	/*
	* The "root" may be a special root, e.g. a PAE entry, treat it as a
	* SPTE to ensure any non-PA bits are dropped.
	*/
	sp = spte_to_child_sp(*root_hpa);
	if (!sp)
		return;

	/*if (is_tdp_mmu_page(sp))
		kvm_tdp_mmu_put_root(kvm, sp, FALSE);
	else if (!--sp->root_count && sp->role.invalid)
		kvm_mmu_prepare_zap_page(kvm, sp, invalid_list);*/

	*root_hpa = INVALID_PAGE;
}

void kvm_mmu_free_roots(struct kvm* kvm, struct kvm_mmu* mmu,
	ULONG roots_to_free) {
	int i;
	bool free_active_root;
	LIST_ENTRY invalid_list;

	InitializeListHead(&invalid_list);

	/* Before acquiring the MMU lock, see if we need 
		to do any real work. */
	free_active_root = (roots_to_free & KVM_MMU_ROOT_CURRENT)
		&& VALID_PAGE(mmu->root.hpa);

	if (!free_active_root) {
		for (i = 0; i < KVM_MMU_NUM_PREV_ROOTS; i++)
			if ((roots_to_free & KVM_MMU_ROOT_PREVIOUS(i)) &&
				VALID_PAGE(mmu->prev_roots[i].hpa))
				break;

		if (i == KVM_MMU_NUM_PREV_ROOTS)
			return;
	}
	
	// write lock


	for (i = 0; i < KVM_MMU_NUM_PREV_ROOTS; i++) {
		if (roots_to_free & KVM_MMU_ROOT_PREVIOUS(i))
			mmu_free_root_page(kvm, &mmu->prev_roots[i].hpa,
				&invalid_list);
	}
}

void kvm_mmu_x86_module_init(void) {

	/*
	* Snapshot userspac's desire to enable the TDP MMU. Whether or not
	* the TDP MMU is actually enabled is determined in kvm_configure_mmu()
	* when the vendor module is loaded.
	*/
	tdp_mmu_allowed = tdp_mmu_enabled;


}

void kvm_mmu_hugepage_adjust(struct kvm_vcpu* vcpu, struct kvm_page_fault* fault) {
	UNREFERENCED_PARAMETER(vcpu);
	//struct kvm_memory_slot* slot = fault->slot;
	//kvm_pfn_t mask;

	fault->huge_page_disallowed = fault->exec && fault->nx_huge_page_workaround_enabled;
	
	if (fault->max_level == PG_LEVEL_4K)
		return;

	if (is_error_noslot_pfn(fault->pfn))
		return;

	
}

void disallowed_hugepage_adjust(struct kvm_page_fault* fault, u64 spte, int cur_level) {
	if (cur_level > PG_LEVEL_4K &&
		cur_level == fault->goal_level &&
		is_shadow_present_pte(spte) &&
		!is_large_pte(spte) &&
		spte_to_child_sp(spte)->nx_huge_page_disallowed) {
		/*
		* A small SPTE exists for this pfn, buf FNAME(fetch),
		* direct_map(), or kvm_tdp_mmu_map() would like to create a
		* large PTE instead: just force them to go down another level,
		* patching back for them into pfn the next 9 bits of the
		* address.
		*/
		u64 page_mask = KVM_PAGES_PER_HPAGE(cur_level) -
			KVM_PAGES_PER_HPAGE(cur_level - 1);
		fault->pfn |= fault->gfn & page_mask;
		fault->goal_level--;
	}
}

void kvm_mmu_change_mmu_pages(struct kvm* kvm, ULONG_PTR goal_nr_mmu_pages) {
	UNREFERENCED_PARAMETER(kvm);
	ExEnterCriticalRegionAndAcquireResourceExclusive(&kvm->mmu_lock);

	if (kvm->arch.n_used_mmu_pages > goal_nr_mmu_pages) {
		kvm_mmu_zap_oldest_mmu_pages(kvm, kvm->arch.n_used_mmu_pages -
			goal_nr_mmu_pages);
		goal_nr_mmu_pages = kvm->arch.n_used_mmu_pages;
	}
	
	kvm->arch.n_max_mmu_pages = goal_nr_mmu_pages;

	ExReleaseResourceAndLeaveCriticalRegion(&kvm->mmu_lock);
}