#include "pch.h"
#include "tdp_mmu.h"
#include "mmu_internal.h"
#include "tdp_iter.h"

/* Initializes the TDP MMU for the VM, if enabled. */
int kvm_mmu_init_tdp_mmu(struct kvm* kvm)
{
	// work queue

	InitializeListHead(&kvm->arch.tdp_mmu_roots);
	
	return 1;
}

void kvm_mmu_uninit_tdp_mmu(struct kvm* kvm) {
	UNREFERENCED_PARAMETER(kvm);
}

static struct kvm_mmu_page* tdp_mmu_alloc_sp(struct kvm_vcpu* vcpu) {
	struct kvm_mmu_page* sp;

	sp = kvm_mmu_memory_cache_alloc(&vcpu->arch.mmu_page_header_cache);
	sp->spt = kvm_mmu_memory_cache_alloc(&vcpu->arch.mmu_shadow_page_cache);

	return sp;
}

static void tdp_mmu_init_sp(struct kvm_mmu_page* sp, tdp_ptep_t sptep,
	gfn_t gfn, union kvm_mmu_page_role role) {
	InitializeListHead(&sp->possible_nx_huge_page_link);

	sp->role = role;
	sp->gfn = gfn;
	sp->ptep = sptep;
	sp->tdp_mmu_page = TRUE;
}

hpa_t kvm_tdp_mmu_get_vcpu_root_hpa(struct kvm_vcpu* vcpu) {
	union kvm_mmu_page_role role = vcpu->arch.mmu->root_role;
	struct kvm* kvm = vcpu->kvm;
	struct kvm_mmu_page* root;
	PHYSICAL_ADDRESS physical = { 0 };

	/*
	* Check for an existing root before allocating a new one. Note, the
	* role check prevents consuming an invalid root.
	*/

	int as_id = kvm_mmu_role_as_id(role);
	
	PLIST_ENTRY head = &kvm->arch.tdp_mmu_roots;
	for (PLIST_ENTRY next = head->Flink; next != head; next = next->Flink) {
		root = CONTAINING_RECORD(next, struct kvm_mmu_page, link);
		if (kvm_mmu_page_as_id(root) != as_id) {

		}
		else {
			if (root->role.word == role.word &&
				kvm_tdp_mmu_get_root(root))
				goto out;
		}
	}

	root = tdp_mmu_alloc_sp(vcpu);
	tdp_mmu_init_sp(root, NULL, 0, role);

	/*
	* TDP MMU roots are kept until they are expilicity invalidated, either
	* by a memslot update or by the destruction of the VM. Initialize the
	* refcount to two; one reference for the vCPU, and one reference for
	* the TDP MMU itself, which is held until the root is invalidated and
	* is ultimately put by tdp_mmu_zap_root_work()
	*/
	InterlockedExchange(&root->tdp_mmu_root_count, 2);

	// spin_lock
	InsertHeadList(&kvm->arch.tdp_mmu_roots, &root->link);
	// spin_unlock

	

out:
	
	physical = MmGetPhysicalAddress(root);
	return physical.QuadPart;
}

void kvm_tdp_mmu_put_root(struct kvm* kvm, struct kvm_mmu_page* root,
	bool shared) {
	UNREFERENCED_PARAMETER(kvm);
	UNREFERENCED_PARAMETER(shared);

	InterlockedDecrement(&root->tdp_mmu_root_count);
	bool is_zero = root->tdp_mmu_root_count == 0 ? TRUE : FALSE;
	if (!is_zero)
		return;
	// spin_lock
	RemoveEntryList(&root->link);
	// spin_unlock

	
}

/*
* Return the level of the lowest level SPTE added to sptes.
* That SPTE may be non-present.
* 
* Must be called between kvm_tdp_mmu_walk_lockless_{begin,end}.
*/
int kvm_tdp_mmu_get_walk(struct kvm_vcpu* vcpu, u64 addr,
	u64* sptes, int* root_level) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(addr);
	UNREFERENCED_PARAMETER(sptes);
	UNREFERENCED_PARAMETER(root_level);
	int leaf = -1;
	
	return leaf;
}


#define tdp_mmu_for_each_pte(_iter,_mmu,_start,_end) \
	for_each_tdp_pte(_iter,to_shadow_page(_mmu->root.hpa),_start,_end)

/*
* Installs a last-level SPTE to handle a TDP page fault.
* (NTP/EPT violation/misconfiguration)
*/
static int tdp_mmu_map_handle_target_level(struct kvm_vcpu* vcpu,
	struct kvm_page_fault* fault,
	struct tdp_iter* iter) {
	struct kvm_mmu_page* sp = sptep_to_sp(iter->sptep);
	u64 new_spte;
	int ret = RET_PF_FIXED;
	bool wrprot = FALSE;

	if (sp->role.level != fault->goal_level)
		return RET_PF_RETRY;

	if (!fault->slot)
		new_spte = make_mmio_spte(vcpu, iter->gfn, ACC_ALL);
	else
		wrprot = make_spte(vcpu, sp, fault->slot, ACC_ALL,
			iter->gfn, fault->pfn, iter->old_spte, fault->prefetch,
			TRUE, fault->map_writable, &new_spte);



	return ret;
}

static void tdp_mmu_init_child_sp(struct kvm_mmu_page* child_sp,
	struct tdp_iter* iter) {
	struct kvm_mmu_page* parent_sp;
	union kvm_mmu_page_role role;
	
	parent_sp = sptep_to_sp(iter->sptep);

	role = parent_sp->role;
	role.level--;

	tdp_mmu_init_sp(child_sp, iter->sptep, iter->gfn, role);
}

static void handle_removed_pt(struct kvm* kvm, tdp_ptep_t pt, bool shared);

static void handle_changed_spte(struct kvm* kvm, int as_id, gfn_t gfn,
	u64 old_spte, u64 new_spte, int level,
	bool shared) {
	UNREFERENCED_PARAMETER(gfn);
	UNREFERENCED_PARAMETER(as_id);

	bool was_present = is_shadow_present_pte(old_spte);
	bool is_present = is_shadow_present_pte(new_spte);
	bool was_leaf = was_present && is_last_spte(old_spte, level);
	bool is_leaf = is_present && is_last_spte(new_spte, level);
	bool pfn_changed = spte_to_pfn(old_spte) != spte_to_pfn(new_spte);

	if (was_leaf && is_leaf && pfn_changed) {
		/*
		* Crash the host to prevent error propagation and guest data
		* corruption.
		*/
		KeBugCheckEx(DRIVER_VIOLATION, 0, 0, 0, 0);
	}

	if (old_spte == new_spte)
		return;

	if (!was_present && !is_present) {
		return;
	}

	if (is_leaf != was_leaf)
		kvm_update_page_stats(kvm, level, is_leaf ? 1 : -1);

	if (was_leaf && is_dirty_spte(old_spte) &&
		(!is_present || !is_dirty_spte(new_spte) || pfn_changed)) {
		
	}

	if(was_present && !was_leaf &&
		(is_leaf || !is_present || pfn_changed))
		handle_removed_pt(kvm, spte_to_child_pt(old_spte, level), shared);


}

static void handle_removed_pt(struct kvm* kvm, tdp_ptep_t pt, bool shared) {
	struct kvm_mmu_page* sp = sptep_to_sp(pt);
	int level = sp->role.level;
	gfn_t base_gfn = sp->gfn;
	int i;
	
	for (i = 0; i < SPTE_ENT_PER_PAGE; i++) {
		tdp_ptep_t sptep = pt + i;
		gfn_t gfn = base_gfn + i * KVM_PAGES_PER_HPAGE(level);
		u64 old_spte;

		if (shared) {
			for (;;) {
				old_spte = kvm_tdp_mmu_write_spte_atomic(sptep, REMOVED_SPTE);
				if (!is_removed_spte(old_spte))
					break;
			}
		}
		else {
			old_spte = kvm_tdp_mmu_read_spte(sptep);
		}
		handle_changed_spte(kvm, kvm_mmu_page_as_id(sp), gfn,
			old_spte, REMOVED_SPTE, level, shared);
	}
}



static inline int tdp_mmu_set_spte_atomic(struct kvm* kvm,
	struct tdp_iter* iter, u64 new_spte) {
	u64* sptep = iter->sptep;

	InterlockedCompareExchange64((LONG64 volatile*)sptep, iter->old_spte, new_spte);

	handle_changed_spte(kvm, iter->as_id, iter->gfn, iter->old_spte,
		new_spte, iter->level, TRUE);

	return 0;
}

static u64 tdp_mmu_set_spte(struct kvm* kvm, int as_id, tdp_ptep_t sptep,
	u64 old_spte, u64 new_spte, gfn_t gfn, int level) {
	old_spte = kvm_tdp_mmu_write_spte(sptep, old_spte, new_spte, level);

	handle_changed_spte(kvm, as_id, gfn, old_spte, new_spte, level, FALSE);
	return old_spte;
}

static inline void tdp_mmu_iter_set_spte(struct kvm* kvm, struct tdp_iter* iter,
	u64 new_spte) {
	iter->old_spte = tdp_mmu_set_spte(kvm, iter->as_id, iter->sptep,
		iter->old_spte, new_spte,
		iter->gfn, iter->level);
}

static void tdp_account_mmu_page(struct kvm* kvm, struct kvm_mmu_page* sp) {
	UNREFERENCED_PARAMETER(sp);
	InterlockedIncrement64(&kvm->arch.tdp_mmu_pages);
}

/*
 * tdp_mmu_link_sp - Replace the given spte with an spte pointing to the
 * provided page table.
 *
 * @kvm: kvm instance
 * @iter: a tdp_iter instance currently on the SPTE that should be set
 * @sp: The new TDP page table to install.
 * @shared: This operation is running under the MMU lock in read mode.
 *
 * Returns: 0 if the new page table was installed. Non-0 if the page table
 *          could not be installed (e.g. the atomic compare-exchange failed).
 */
static int tdp_mmu_link_sp(struct kvm* kvm, struct tdp_iter* iter,
	struct kvm_mmu_page* sp, bool shared) {
	u64 spte = make_nonleaf_spte(sp->spt, !kvm_ad_enabled());
	int ret = 0;

	if (shared) {
		ret = tdp_mmu_set_spte_atomic(kvm, iter, spte);
	}
	else {
		tdp_mmu_iter_set_spte(kvm, iter, spte);
	}

	tdp_account_mmu_page(kvm, sp);

	return 0;
}

/* Note: the caller is responsible for initializing @sp. */
static int tdp_mmu_split_huge_page(struct kvm* kvm, struct tdp_iter* iter,
	struct kvm_mmu_page* sp, bool shared) {
	UNREFERENCED_PARAMETER(kvm);
	UNREFERENCED_PARAMETER(iter);
	UNREFERENCED_PARAMETER(sp);
	UNREFERENCED_PARAMETER(shared);

	int ret;

	ret = tdp_mmu_link_sp(kvm, iter, sp, shared);

	return ret;
}

static void tdp_mmu_free_sp(struct kvm_mmu_page* sp) {
	ExFreePool(sp->spt);
}

/*
* Handle a TDP page fault (NPT/EPT violation/misconfiguration) by installing
* page tables and SPTEs to translate the faulting guest physical address.
*/
int kvm_tdp_mmu_map(struct kvm_vcpu* vcpu, struct kvm_page_fault* fault) {
	struct kvm_mmu* mmu = vcpu->arch.mmu;
	struct kvm* kvm = vcpu->kvm;
	struct tdp_iter iter;
	struct kvm_mmu_page* sp;
	int ret = RET_PF_RETRY;

	// 得到请求地址所使用的level
	kvm_mmu_hugepage_adjust(vcpu, fault);

	// 遍历所有页表中addr对应的页表项spte
	tdp_mmu_for_each_pte(iter, mmu, fault->gfn, fault->gfn + 1) {
		int r;

		if (fault->nx_huge_page_workaround_enabled)
			disallowed_hugepage_adjust(fault, iter.old_spte, iter.level);

		/*
		* If SPTE has been frozen by another thread, just give up and
		* retry, avoiding unnecessary page table allocation and free.
		*/
		if (is_removed_spte(iter.old_spte))
			goto retry;
		
		/*
		* entry 的 level 和请求的 level 相等, 说明该 entry 引起的 violation
		* 即该 entry 对应的下级页或者页表不在内存中, 或者直接为 NULL.
		*/ 
		if (iter.level == fault->goal_level)
			goto map_target_level;

		/* Step down into the lower level page table if it exists. */
		if (is_shadow_present_pte(iter.old_spte) &&
			!is_large_pte(iter.old_spte))
			continue;

		/*
		* The SPTE is either non-present or points to a huge page that
		* needs to be split.
		*/
		sp = tdp_mmu_alloc_sp(vcpu);
		tdp_mmu_init_child_sp(sp, &iter);

		sp->nx_huge_page_disallowed = fault->huge_page_disallowed;

		if (is_shadow_present_pte(iter.old_spte))
			r = tdp_mmu_split_huge_page(kvm, &iter, sp, TRUE);
		else
			// 将新分配出来的下一级影子页表页的地址填写该 entry 对应的 SPTE(it.sptep)中
			r = tdp_mmu_link_sp(kvm, &iter, sp, TRUE);

		/*
		* Force the guest to retry if installing an upper level SPTE
		* failed, e.g. because a different task modified the SPTE.
		*/
		if (r) {
			tdp_mmu_free_sp(sp);
			goto retry;
		}

		if (fault->huge_page_disallowed &&
			fault->req_level >= iter.level) {
			KIRQL irql;
			KeAcquireSpinLock(&kvm->arch.tdp_mmu_pages_lock, &irql);

			KeReleaseSpinLock(&kvm->arch.tdp_mmu_pages_lock, irql);
		}
	}

	/*
	* The walk aborted before reaching the target level, e.g. because the
	* iterator detected an upper level SPTE was frozen during traversal. 
	*/
	
	goto retry;

map_target_level:
	ret = tdp_mmu_map_handle_target_level(vcpu, fault, &iter);

retry:


	return ret;
}

/*
* Returns the last level spte pointer of the shadow page walk for the given
* gpa, and sets *spte to the spte value. This spte may be non-present. If no walk
* could be performed, returns NULL and *spte does not contain valid data.
* 
* Contract:
*  - Must be called between kvm_tdp_mmu_walk_lockless_{begin,end}
*  - The returned sptep must not be used after kvm_tdp_mmu_walk_lockless_end.
* 
* WARNING: This function is only intended to be called during fast_page_fault.
*/
u64* kvm_tdp_mmu_fast_pf_get_last_sptep(struct kvm_vcpu* vcpu, u64 addr,
	u64* spte) {
	struct tdp_iter iter;
	struct kvm_mmu* mmu = vcpu->arch.mmu;
	gfn_t gfn = addr >> PAGE_SHIFT;
	tdp_ptep_t sptep = NULL;

	tdp_mmu_for_each_pte(iter, mmu, gfn, gfn + 1) {
		*spte = iter.old_spte;
		sptep = iter.sptep;
	}
	
	if (sptep != NULL) {
		return sptep;
	}
	else
		return NULL;
}