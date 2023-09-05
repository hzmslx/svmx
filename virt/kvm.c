#include "pch.h"
#include "kvm.h"

int Error(const char* text) {
	printf("%s (%d)\n", text, GetLastError());
	return 1;
}

int kvm_init() {
	int ret = 0;
	HANDLE hDevice = CreateFile(L"\\\\.\\KVM", GENERIC_READ | GENERIC_WRITE,
		0, NULL, OPEN_EXISTING, 0, NULL);
	if (hDevice == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "Could not access KVM kernel module %m\n");
		ret = -errno;
		goto err;
	}
	USHORT version = 0;
	DWORD bytes;
	// 判断内核KVM驱动和当前virt版本是否兼容
	/* Make sure we have the stable version of the API */
	if (!DeviceIoControl(hDevice, KVM_GET_API_VERSION, NULL, 0,
		&version, sizeof(version), &bytes, NULL)) {
		ret = GetLastError();
		Error("Failed to get api version");
		goto err;
	}
	if (version < KVM_API_VERSION) {
		ret = -EINVAL;
		fprintf(stderr, "kvm version too old\n");
		goto err;
	}

	if (version > KVM_API_VERSION) {
		ret = -EINVAL;
		fprintf(stderr, "kvm version not supported\n");
		goto err;
	}
	// 创建虚拟机
	if (!DeviceIoControl(hDevice, KVM_CREATE_VM, NULL, 0,
		NULL, 0, &bytes, NULL)) {
		ret = GetLastError();
		Error("Failed to create vm");
		goto err;
	}

	if (!DeviceIoControl(hDevice, KVM_CREATE_VCPU, NULL, 0,
		NULL, 0, &bytes, NULL)) {
		ret = -errno;
		Error("Failed to create vcpu");
		goto release_vm;
	}
	ULONG mapSize = 0;
	if (!DeviceIoControl(hDevice, KVM_GET_VCPU_MMAP_SIZE, 0, NULL, &mapSize, sizeof(mapSize),
		&bytes, NULL)) {
		ret = GetLastError();
		Error("Failed to get mmap size");
		goto release_vm;
	}
	 
	if (!DeviceIoControl(hDevice, KVM_RUN, NULL, 0, NULL, 0, &bytes, NULL)) {
		ret = GetLastError();
		Error("Failed to run");
		goto release_vm;
	}



release_vm:
	if (!DeviceIoControl(hDevice, KVM_RELEASE_VM, NULL, 0, NULL, 0, &bytes, NULL)) {
		ret = GetLastError();
		Error("Failed to release vcpu");
		goto err;
	}

	return 0;
err:

	if (hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
	}

	return ret;
}