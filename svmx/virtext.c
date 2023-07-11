#include "pch.h"
#include "virtext.h"
#include "processor.h"
#include "bitops.h"
#include "ntexapi.h"
#include "svm.h"


int cpu_has_vmx() {
	unsigned long ecx = cpuid_ecx(1);
	return test_bit(5, &ecx);/* CPUID.1:ECX.VMX[bit 5] -> VT */
}

int cpu_has_svm(const char** msg) {
	SYSTEM_PROCESSOR_INFORMATION info;
	NTSTATUS status = ZwQuerySystemInformation(SystemProcessorInformation,
		&info, sizeof(info), NULL);
	if (!NT_SUCCESS(status)) {
		if (msg)
			*msg = "can't get the processor information";
		return 0;
	}

	if (info.ProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64) {
		if (msg)
			*msg = "not amd";
		return 0;
	}


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