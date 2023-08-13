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

int nx_huge_pages = -1;

/*
 * When setting this variable to true it enables Two-Dimensional-Paging
 * where the hardware walks 2 page tables:
 * 1. the guest-virtual to guest-physical
 * 2. while doing 1. it walks guest-physical to host-physical
 * If the hardware supports that we don't need to do shadow paging.
 */
bool tdp_enabled = FALSE;

static int max_huge_page_level;
static int tdp_root_level;
static int max_tdp_level;

#define RMAP_EXT 4

struct kvm_rmap_desc {
	u64* sptes[RMAP_EXT];
	struct kvm_rmap_desc* more;
};

static PMDL pte_chain_cache_mdl;
static PMDL rmap_desc_cache_mdl;
static PMDL mmu_page_header_mdl;

static PVOID pte_chain_cache;
static PVOID rmap_desc_cache;
static PVOID mmu_page_header_cache;

static u64 shadow_trap_nonpresent_pte;
static u64 shadow_notrap_nonpresent_pte;
static u64 shadow_base_present_pte;
static u64 shadow_nx_mask;
static u64 shadow_x_mask;	/* mutual exclusive with nx_mask */
static u64 shadow_user_mask;
u64 shadow_accessed_mask;
static u64 shadow_dirty_mask;

static bool tdp_mmu_allowed;
#ifdef _WIN64
bool tdp_mmu_enabled = TRUE;
#endif // 


struct kvm_mmu_role_regs {
	const unsigned long cr0;
	const unsigned long cr4;
	const u64 efer;
};

NTSTATUS kvm_mmu_module_init() {
	NTSTATUS status = STATUS_SUCCESS;
	do
	{
		
		pte_chain_cache_mdl = IoAllocateMdl(NULL, sizeof(struct kvm_pte_chain),
			FALSE, FALSE, NULL);
		if (!pte_chain_cache_mdl)
			break;
		pte_chain_cache = MmMapLockedPagesSpecifyCache(pte_chain_cache_mdl,
			KernelMode,
			MmNonCached,
			NULL,
			FALSE,
			NormalPagePriority);
		if (!pte_chain_cache) {
			status = STATUS_NO_MEMORY;
			break;
		}
		
		rmap_desc_cache_mdl = IoAllocateMdl(NULL, sizeof(struct kvm_rmap_desc),
			FALSE, FALSE, NULL);
		if (!rmap_desc_cache_mdl) {
			status = STATUS_NO_MEMORY;
			break;
		}
		rmap_desc_cache = MmMapLockedPagesSpecifyCache(rmap_desc_cache_mdl,
			KernelMode,
			MmNonCached,
			NULL,
			FALSE,
			NormalPagePriority);
		if (!rmap_desc_cache) {
			status = STATUS_NO_MEMORY;
			break;
		}

		mmu_page_header_mdl = IoAllocateMdl(NULL, sizeof(struct kvm_rmap_desc),
			FALSE, FALSE, NULL);
		if (!mmu_page_header_mdl) {
			status = STATUS_NO_MEMORY;
			break;
		}
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

	if (!NT_SUCCESS(status)) {
		if (pte_chain_cache_mdl != NULL) {
			if (pte_chain_cache != NULL) {
				MmUnmapLockedPages(pte_chain_cache, pte_chain_cache_mdl);
			}
			IoFreeMdl(pte_chain_cache_mdl);
		}
		
		if (rmap_desc_cache_mdl != NULL) {
			if (rmap_desc_cache != NULL) {
				MmUnmapLockedPages(rmap_desc_cache, rmap_desc_cache_mdl);
			}
			IoFreeMdl(rmap_desc_cache_mdl);
		}

		if (mmu_page_header_mdl != NULL) {
			if (mmu_page_header_cache != NULL) {
				MmUnmapLockedPages(mmu_page_header_cache, mmu_page_header_mdl);
			}
			IoFreeMdl(mmu_page_header_mdl);
		}
	}

	return status;
}

void kvm_mmu_set_nonpresent_ptes(u64 trap_pte, u64 notrap_pte) {
	shadow_trap_nonpresent_pte = trap_pte;
	shadow_notrap_nonpresent_pte = notrap_pte;
}

void kvm_mmu_set_base_ptes(u64 base_pte) {
	shadow_base_present_pte = base_pte;
}

struct kvm_shadow_walk_iterator {
	u64 addr;
	hpa_t shadow_addr;
	u64* sptep;
	int level;
	unsigned index;
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

int kvm_mmu_load(struct kvm_vcpu* vcpu) {
	

	kvm_mmu_load_pgd(vcpu);

	return 0;
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

static unsigned long get_guest_cr3(struct kvm_vcpu* vcpu)
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

// EPTµÄ³õÊ¼»¯
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

}

void kvm_init_mmu(struct kvm_vcpu* vcpu) {
	struct kvm_mmu_role_regs regs = vcpu_to_role_regs(vcpu);
	union kvm_cpu_role cpu_role = kvm_calc_cpu_role(vcpu, &regs);

	if (mmu_is_nested(vcpu))
		init_kvm_nested_mmu(vcpu, cpu_role);
	else if (tdp_enabled)
		init_kvm_tdp_mmu(vcpu, cpu_role);
	else
		init_kvm_softmmu(vcpu, cpu_role);
}

static int direct_page_fault(struct kvm_vcpu* vcpu, 
	struct kvm_page_fault* fault) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(fault);
	return RET_PF_EMULATE;
}

#ifdef AMD64
static int kvm_tdp_mmu_page_fault(struct kvm_vcpu* vcpu,
	struct kvm_page_fault* fault) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(fault);

	return 0;
}
#endif // AMD64


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

static int mmu_topup_memory_caches(struct kvm_vcpu* vcpu, 
	bool maybe_indirect) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(maybe_indirect);
	return 0;
}

/*
 * Returns one of RET_PF_INVALID, RET_PF_FIXED or RET_PF_SPURIOUS.
 */
static int fast_page_fault(struct kvm_vcpu* vcpu, 
	struct kvm_page_fault* fault) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(fault);

	return RET_PF_INVALID;
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

	mmu->pae_root = page;

	for (i = 0; i < 4; ++i)
		mmu->pae_root[i] = INVALID_PAE_ROOT;

	return STATUS_SUCCESS;
}

static void free_mmu_pages(struct kvm_mmu* mmu) {
	ExFreePool(mmu->pae_root);
	ExFreePool(mmu->pml4_root);
	ExFreePool(mmu->pml5_root);
}

int kvm_mmu_create(struct kvm_vcpu* vcpu) {
	int ret;

	vcpu->arch.mmu = &vcpu->arch.root_mmu;
	vcpu->arch.walk_mmu = &vcpu->arch.root_mmu;

	ret = __kvm_mmu_create(vcpu, &vcpu->arch.guest_mmu);
	if (ret)
		return ret;

	bool fail_allocate_root = FALSE;
	do
	{
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

static void shadow_walk_init_using_root(struct kvm_shadow_walk_iterator* iterator,
	struct kvm_vcpu* vcpu, hpa_t root,
	u64 addr) {
	UNREFERENCED_PARAMETER(iterator);
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(root);
	UNREFERENCED_PARAMETER(addr);
}

static void shadow_walk_init(struct kvm_shadow_walk_iterator* iterator,
	struct kvm_vcpu* vcpu, u64 addr)
{
	shadow_walk_init_using_root(iterator, vcpu, vcpu->arch.mmu->root.hpa,
		addr);
}

static bool shadow_walk_okay(struct kvm_shadow_walk_iterator* iterator)
{
	if (iterator->level < PG_LEVEL_4K)
		return FALSE;

	
	
	return TRUE;
}

static void __shadow_walk_next(struct kvm_shadow_walk_iterator* iterator,
	u64 spte) {
	if (!is_shadow_present_pte(spte) || is_last_spte(spte, iterator->level)) {
		iterator->level = 0;
		return;
	}

	iterator->shadow_addr = spte & SPTE_BASE_ADDR_MASK;
	--iterator->level;
}


static int mmu_alloc_direct_roots(struct kvm_vcpu* vcpu) {
	UNREFERENCED_PARAMETER(vcpu);

	return 0;
}

static int mmu_first_shadow_root_alloc(struct kvm* kvm) {
	UNREFERENCED_PARAMETER(kvm);

	return 0;
}

/**
 * lower_32_bits - return bits 0-31 of a number
 * @n: the number we're accessing
 */
#define lower_32_bits(n) ((u32)((n) & 0xffffffff))

int kvm_mmu_page_fault(struct kvm_vcpu* vcpu, gpa_t cr2_or_gpa, u64 error_code,
	void* insn, int insn_len) {
	int r, emulation_type = EMULTYPE_PF;

	if (!VALID_PAGE(vcpu->arch.mmu->root.hpa))
		return RET_PF_RETRY;

	r = RET_PF_INVALID;
	if (error_code & PFERR_RSVD_MASK) {
		
		if (r == RET_PF_EMULATE)
			goto emulate;
	}

	if (r == RET_PF_INVALID) {
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

	return 0;
}

static void link_shadow_page(struct kvm_vcpu* vcpu, u64* sptep,
	struct kvm_mmu_page* sp) {
	UNREFERENCED_PARAMETER(vcpu);
	UNREFERENCED_PARAMETER(sptep);
	UNREFERENCED_PARAMETER(sp);
	
}

