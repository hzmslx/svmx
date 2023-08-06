// virt.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include "pch.h"


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

int wmain(int argc,char* argv[]){
    if (argc < 2)
        return Usage();

    auto const cmd = argv[1];



    return 0;
}


