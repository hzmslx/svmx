#include "pch.h"
#include "virtext.h"
#include "cpuid.h"
#include "bitops.h"
#include "ntexapi.h"
#include "svm.h"



int cpu_has_vmx() {
	unsigned long ecx = cpuid_ecx(1);
	return _bittest((const LONG*)&ecx, 5); /* CPUID.1:ECX.VMX[bit 5] -> VT */
}

bool cpu_is_enabled_vmx() {
	u64 msr_ia32_feature_control = __readmsr(MSR_IA32_FEATURE_CONTROL);
	return  _bittest((const LONG*)&msr_ia32_feature_control, 0);
}

int cpu_has_svm(const char** msg) {
	int eax = cpuid_eax(0x80000000);
	if (eax < SVM_CPUID_FUNC) {
		if (msg)
			*msg = "can't execute cpuid_8000000a";
		return 0;
	}

	int ecx = cpuid_ecx(0x80000001);
	if (!(ecx & (1 << SVM_CPUID_FEATURE_SHIFT))) {
		if (msg)
			*msg = "svm not available";
		return 0;
	}

	return 1;
}