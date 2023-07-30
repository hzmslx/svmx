#pragma once

void kvm_set_cpu_caps(void);


static unsigned int cpuid_ecx(unsigned int op) {

	int cpuInfo[4];// eax,ebx,ecx,edx

	// Basic CPUID Information
	CpuIdEx(cpuInfo, op, 0);

	return cpuInfo[2];
}

static unsigned int cpuid_eax(unsigned int op) {
	int cpuInfo[4];// eax,ebx,ecx,edx

	CpuIdEx(cpuInfo, op, 0);

	return cpuInfo[0];
}

static unsigned int cpuid_ebx(unsigned int op) {
	int cpuInfo[4];// eax,ebx,ecx,edx

	CpuIdEx(cpuInfo, op, 0);

	return cpuInfo[1];
}

static unsigned int cpuid_edx(unsigned int op) {
	int cpuInfo[4];// eax,ebx,ecx,edx

	CpuIdEx(cpuInfo, op, 0);

	return cpuInfo[3];
}

static inline int cpuid_maxphyaddr(struct kvm_vcpu* vcpu)
{
	return vcpu->arch.maxphyaddr;
}