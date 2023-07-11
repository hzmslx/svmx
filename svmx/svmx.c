#include "pch.h"
#include "ntexapi.h"
#include "vmx.h"
#include "svm.h"

DRIVER_UNLOAD DriverUnload;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status = STATUS_SUCCESS;

	DriverObject->DriverUnload = DriverUnload;

	SYSTEM_PROCESSOR_INFORMATION info;
	status = ZwQuerySystemInformation(SystemProcessorInformation,
		&info, sizeof(info), NULL);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	switch (info.ProcessorArchitecture)
	{
	case PROCESSOR_ARCHITECTURE_INTEL:
		status = vmx_init();
		break;

	case PROCESSOR_ARCHITECTURE_AMD64:
		status = svm_init();
		break;

	default:
		status = STATUS_NOT_SUPPORTED;
		break;
	}

	return status;
}