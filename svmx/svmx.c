#include "pch.h"
#include "ntexapi.h"
#include "vmx.h"
#include "svm.h"

extern KMUTEX vendor_module_lock;
extern struct vmcs* vmxarea;

DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH DriverDeviceControl;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
	if (vmxarea != NULL) {
		ExFreePool(vmxarea);
	}
	UNICODE_STRING linkName = RTL_CONSTANT_STRING(L"\\??\\KVM");
	IoDeleteSymbolicLink(&linkName);
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status = STATUS_SUCCESS;

	DriverObject->DriverUnload = DriverUnload;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;

	KeInitializeMutex(&vendor_module_lock, 0);
	
	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\KVM");
	PDEVICE_OBJECT DeviceObject;

	status = IoCreateDevice(DriverObject, 0, &devName,
		FILE_DEVICE_UNKNOWN, 0, TRUE, &DeviceObject);
	if (!NT_SUCCESS(status))
		return status;

	UNICODE_STRING linkName = RTL_CONSTANT_STRING(L"\\??\\KVM");
	status = IoCreateSymbolicLink(&linkName, &devName);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(DeviceObject);
		return status;
	}

	
	int cpuInfo[4];
	CpuIdEx(cpuInfo, 0, 0);
	char brand[13] = { 0 };
	memcpy_s(brand, 4, &cpuInfo[1], 4);
	memcpy_s(brand + 4, 4,&cpuInfo[3], 4);
	memcpy_s(brand + 8, 4, &cpuInfo[2], 4);
	if (strcmp(brand,"GenuineIntel") == 0) {
		ULONG count = KeQueryActiveProcessorCount(0);
		vmxarea = ExAllocatePoolZero(NonPagedPool, count * sizeof(struct vmcs*),
			DRIVER_TAG);
		if (vmxarea == NULL) {
			IoDeleteSymbolicLink(&linkName);
			IoDeleteDevice(DeviceObject);
			return status;
		}
		status = vmx_init();
	}
	else if (strcmp(brand, "AuthenticAMD") == 0) {
		status = svm_init();
	}
	else {
		status = STATUS_NOT_SUPPORTED;
	}

	if (!NT_SUCCESS(status)) {
		ExFreePool(vmxarea);
		vmxarea = NULL;
		IoDeleteSymbolicLink(&linkName);
		IoDeleteDevice(DeviceObject);
	}

	return status;
}

NTSTATUS DriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	NTSTATUS status = STATUS_SUCCESS;

	ULONG ioctl = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl.IoControlCode;
	switch (ioctl)
	{
	case KVM_GET_API_VERSION:

		break;

	case KVM_CREATE_VM:
		status = kvm_dev_ioctl_create_vm(0);
		break;

	case KVM_CHECK_EXTENSION:

		break;

	case KVM_GET_VCPU_MMPA_SIZE:

		break;
	case KVM_TRACE_ENABLE:
	case KVM_TRACE_PAUSE:
	case KVM_TRACE_DISABLE:
		status = STATUS_NOT_SUPPORTED;
		break;
	default:

		break;
	}
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}