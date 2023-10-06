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
	return physical.QuadPart >> PAGE_SHIFT;
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