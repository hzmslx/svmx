#include "pch.h"
#include "processor.h"

unsigned int cpuid_ecx(unsigned int op) {

	int cpuInfo[4];// eax,ebx,ecx,edx

	// Basic CPUID Information
	CpuIdEx(cpuInfo, op, 0);
	
	return cpuInfo[2];
}

unsigned int cpuid_eax(unsigned int op) {
	int cpuInfo[4];// eax,ebx,ecx,edx

	// Basic CPUID Information
	CpuIdEx(cpuInfo, op, 0);

	return cpuInfo[0];
}

unsigned int cpuid_ebx(unsigned int op) {
	int cpuInfo[4];// eax,ebx,ecx,edx

	// Basic CPUID Information
	CpuIdEx(cpuInfo, op, 0);

	return cpuInfo[1];
}

unsigned int cpuid_edx(unsigned int op) {
	int cpuInfo[4];// eax,ebx,ecx,edx

	// Basic CPUID Information
	CpuIdEx(cpuInfo, op, 0);

	return cpuInfo[3];
}