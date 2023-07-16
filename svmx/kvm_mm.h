#pragma once


#define KVM_MMU_LOCK_INIT	ExInitializeResourceLite(&(kvm)->mmu_lock);