#include "pch.h"
#include "ntexapi.h"
#include "vmx.h"
#include "svm.h"

extern KMUTEX vendor_module_lock;
extern struct vmcs** vmxarea;
extern struct vmcs** current_vmcs;
extern bool* hardware_enabled;
extern struct kvm* g_kvm;

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH DriverDeviceControl;

_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH DriverCreateClose;

_Dispatch_type_(IRP_MJ_SHUTDOWN)
DRIVER_DISPATCH DriverShutdown;

bool g_vmx_init = FALSE;
bool g_svm_init = FALSE;



VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
	if (g_vmx_init) {
		vmx_exit();
	}
	else if (g_svm_init) {
		svm_exit();
	}
	if (vmxarea != NULL) {
		ExFreePool(vmxarea);
	}
	if (current_vmcs != NULL) {
		ExFreePool(current_vmcs);
	}
	UNICODE_STRING linkName = RTL_CONSTANT_STRING(L"\\??\\KVM");
	IoDeleteSymbolicLink(&linkName);
	IoDeleteDevice(DriverObject->DeviceObject);

}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	DriverObject->DriverUnload = DriverUnload;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = DriverShutdown;

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

	ULONG count = KeQueryActiveProcessorCount(0);
	ULONG len = count * sizeof(bool);
	hardware_enabled = ExAllocatePoolWithTag(NonPagedPool,len,
		DRIVER_TAG);
	if (hardware_enabled == NULL) {
		status = STATUS_NO_MEMORY;
		IoDeleteSymbolicLink(&linkName);
		IoDeleteDevice(DeviceObject);
		return status;
	}
	RtlZeroMemory(hardware_enabled, len);

	int cpuInfo[4];
	CpuIdEx(cpuInfo, 0, 0);
	char brand[13] = { 0 };
	memcpy_s(brand, 4, &cpuInfo[1], 4);
	memcpy_s(brand + 4, 4, &cpuInfo[3], 4);
	memcpy_s(brand + 8, 4, &cpuInfo[2], 4);
	if (strcmp(brand, "GenuineIntel") == 0) {
		ULONG size = count * sizeof(struct vmcs*);
		vmxarea = ExAllocatePoolWithTag(NonPagedPool,size,
			DRIVER_TAG);
		if (vmxarea == NULL) {
			status = STATUS_NO_MEMORY;
			IoDeleteSymbolicLink(&linkName);
			IoDeleteDevice(DeviceObject);
			return status;
		}
		RtlZeroMemory(vmxarea, size);
		current_vmcs = ExAllocatePoolWithTag(NonPagedPool, size,
			DRIVER_TAG);
		if (current_vmcs == NULL) {
			status = STATUS_NO_MEMORY;
			ExFreePool(vmxarea);
			vmxarea = NULL;
			IoDeleteSymbolicLink(&linkName);
			IoDeleteDevice(DeviceObject);
			return status;
		}
		RtlZeroMemory(current_vmcs, size);
		// module initialize
		status = vmx_init();
		if (NT_SUCCESS(status))
			g_vmx_init = TRUE;
	}
	else if (strcmp(brand, "AuthenticAMD") == 0) {
		status = svm_init();
		if (NT_SUCCESS(status))
			g_svm_init = TRUE;
	}
	else {
		status = STATUS_NOT_SUPPORTED;
	}

	if (!NT_SUCCESS(status)) {
		ExFreePool(vmxarea);
		ExFreePool(current_vmcs);
		vmxarea = NULL;
		current_vmcs = NULL;
		IoDeleteSymbolicLink(&linkName);
		IoDeleteDevice(DeviceObject);
	}

	return status;
}

// kvm ioctl entry
NTSTATUS DriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	NTSTATUS status = STATUS_SUCCESS;
	ULONG len = 0;

	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
	ULONG ioctl = irpStack->Parameters.DeviceIoControl.IoControlCode;
	switch (ioctl)
	{
		case KVM_GET_API_VERSION:
			if (Irp->AssociatedIrp.SystemBuffer == NULL) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			if (irpStack->Parameters.DeviceIoControl.OutputBufferLength
				< sizeof(USHORT)) {
				status = STATUS_BUFFER_TOO_SMALL;
				break;
			}
			*(USHORT*)Irp->AssociatedIrp.SystemBuffer = KVM_API_VERSION;
			len = sizeof(USHORT);
			break;

		case KVM_CREATE_VM:
			// create virtual machine
			status = kvm_dev_ioctl_create_vm(0);
			break;

		case KVM_CHECK_EXTENSION:
			
			break;

		case KVM_GET_VCPU_MMAP_SIZE:
			if (Irp->AssociatedIrp.SystemBuffer == NULL) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			if (irpStack->Parameters.DeviceIoControl.OutputBufferLength
				< sizeof(ULONG)) {
				status = STATUS_BUFFER_TOO_SMALL;
				break;
			}
			*(ULONG*)Irp->AssociatedIrp.SystemBuffer = PAGE_SIZE;
			len = sizeof(ULONG);
			break;
		case KVM_TRACE_ENABLE:
		case KVM_TRACE_PAUSE:
		case KVM_TRACE_DISABLE:
			status = STATUS_NOT_SUPPORTED;
			break;

		// kvm_vm_ioctl
		case KVM_CREATE_VCPU:
		{
			ULONG count = KeQueryActiveProcessorCount(0);
			for (ULONG cpu = 0; cpu < count; ++cpu) {
				status = kvm_vm_ioctl_create_vcpu(g_kvm, cpu);
				if (!NT_SUCCESS(status))
					break;
			}
			break;
		}

		case KVM_RELEASE_VM:
		{
			kvm_put_kvm(g_kvm);
			break;
		}

		case KVM_SET_USER_MEMORY_REGION:
			kvm_vm_ioctl(ioctl, (ULONG_PTR)Irp->AssociatedIrp.SystemBuffer);
			break;
		
		default:
			status = kvm_vcpu_ioctl(ioctl, Irp);
			break;
	}
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = len;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status, ULONG_PTR info) {
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS DriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	return CompleteRequest(Irp, STATUS_SUCCESS, 0);
}

NTSTATUS DriverShutdown(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	return CompleteRequest(Irp, STATUS_SUCCESS, 0);
}