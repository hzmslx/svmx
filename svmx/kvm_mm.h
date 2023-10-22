#pragma once


#define KVM_MMU_LOCK_INIT	ExInitializeResourceLite(&(kvm)->mmu_lock);

kvm_pfn_t hva_to_pfn(ULONG_PTR addr, bool atomic, bool interruptible,
	bool* async, bool write_fault, bool* writable);