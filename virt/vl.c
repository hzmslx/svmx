#include "pch.h"
#include "kvm.h"

void virt_init(int argc, char* argv[]) {
	kvm_init();
}