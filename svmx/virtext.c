#include "pch.h"
#include "virtext.h"
#include "processor.h"
#include "bitops.h"
#include "ntexapi.h"


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
			*msg = "cannot get the processor information";
		return 0;
	}

	return 0;
}