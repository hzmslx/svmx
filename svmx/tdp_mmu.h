#pragma once
#include "kvm_host.h"

int kvm_mmu_init_tdp_mmu(struct kvm* kvm);
void kvm_mmu_uninit_tdp_mmu(struct kvm* kvm);

