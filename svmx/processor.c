#include "pch.h"
#include "processor.h"

unsigned int cpuid_ecx(unsigned int op) {

	int cpuInfo[4];// eax,ebx,ecx,edx

	// Basic CPUID Information
	CpuIdEx(cpuInfo, op, 0);
	
	return cpuInfo[2];
}