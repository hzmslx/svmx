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
	// root->spt指向影子页表页的地址
	physical = MmGetPhysicalAddress(root->spt);
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
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(fault);
	UNREFERENCED_PARAMETER(iter);
	int ret = RET_PF_FIXED;

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
	UNREFERENCED_PARAMETER(kvm);
	UNREFERENCED_PARAMETER(iter);
	UNREFERENCED_PARAMETER(sp);
	UNREFERENCED_PARAMETER(shared);


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

	kvm_mmu_hugepage_adjust(vcpu, fault);

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