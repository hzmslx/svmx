// virt.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>
#include <wil/resource.h>
#include "..\svmx\svmx.h"

int Usage() {
    printf("virt.exe <command> [args]\n");
    printf("Commands:\n");
    printf("\tcreate (create a vm)\n");

    return 0;
}

int Error(const char* text) {
    printf("%s (%d)\n", text, GetLastError());
    return 1;
}

int main(int argc,wchar_t* argv[]){
    if (argc < 2)
        return Usage();

    auto const cmd = argv[1];

    wil::unique_hfile hDevice(::CreateFile(L"\\\\.\\KVM", GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING, 0, nullptr));
    if (hDevice.get() == INVALID_HANDLE_VALUE)
        return Error("Failed to open device");

    DWORD bytes;
    if (_wcsicmp(cmd, L"create") == 0) {
        if (!DeviceIoControl(hDevice.get(), KVM_CREATE_VM, nullptr, 0,
            nullptr, 0, &bytes, nullptr)) {
            Error("Failed in create vm");
        }
        printf("Create vm successfully");
    }

    return 0;
}


