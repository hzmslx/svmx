// virt.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include "pch.h"
#include "sysemu.h"


int Usage() {
    printf("virt.exe <command> [args]\n");
    printf("Commands:\n");
    printf("\tcreate (create a vm)\n");
    
    return 0;
}



int wmain(int argc,char* argv[]){
    auto const cmd = argv[1];
    
    virt_init(argc, argv);
    system("pause");
    return 0;
}


