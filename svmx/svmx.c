#include "pch.h"
#include "ntexapi.h"
#include "vmx.h"
#include "svm.h"

extern KMUTEX vendor_module_lock;

DRIVER_UNLOAD DriverUnload;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status = STATUS_SUCCESS;

	DriverObject->DriverUnload = DriverUnload;

	KeInitializeMutex(&vendor_module_lock, 0);
	
	int cpuInfo[4];
	CpuIdEx(cpuInfo, 0, 0);
	char brand[13] = { 0 };
	memcpy_s(brand, 4, &cpuInfo[1], 4);
	memcpy_s(brand + 4, 4,&cpuInfo[3], 4);
	memcpy_s(brand + 8, 4, &cpuInfo[2], 4);
	if (strcmp(brand,"GenuineIntel") == 0) {
		status = vmx_init();
	}
	else if (strcmp(brand, "AuthenticAMD") == 0) {
		status = svm_init();
	}
	else {
		status = STATUS_NOT_SUPPORTED;
	}

	return status;
}