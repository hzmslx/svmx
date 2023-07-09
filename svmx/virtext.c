#include "pch.h"
#include "virtext.h"
#include "processor.h"
#include "bitops.h"

int cpu_has_vmx() {
	unsigned long ecx = cpuid_ecx(1);
	return test_bit(5, &ecx);/* CPUID.1:ECX.VMX[bit 5] -> VT */
}