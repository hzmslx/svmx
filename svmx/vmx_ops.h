#pragma once
#include "pch.h"
#include "kvm_types.h"
#include "vmx.h"
#include "vmcs.h"
#include "x86.h"

static ULONG_PTR vmcs_readl(ULONG_PTR field) {
	ULONG_PTR value;
	__vmx_vmread(field, &value);
	return value;
}

static void vmcs_writel(unsigned long field, ULONG_PTR value) {
	__vmx_vmwrite(field, value);
}

static void __vmcs_writel(unsigned long field, ULONG_PTR value){
	__vmx_vmwrite(field, value);
}

static void vmcs_write16(unsigned long field, u16 value)
{
	__vmcs_writel(field, value);
}

static void vmcs_write32(unsigned long field, u32 value)
{
	__vmcs_writel(field, value);
}

static void vmcs_write64(unsigned long field, u64 value)
{
	__vmx_vmwrite(field, value);
}

static u16 vmcs_read16(unsigned long field) {
	size_t value;
	__vmx_vmread(field, &value);
	return (u16)value;
}

static u32 vmcs_read32(unsigned long field) {
	size_t value;
	__vmx_vmread(field, &value);
	return (u32)value;
}

static u64 vmcs_read64(unsigned long field) {
	size_t value;
	__vmx_vmread(field, &value);
	return value;
}

/*
* 根据提供的64位vmcs指针，对vmcs区域进行一些初始化工作，并将
* 目标vmcs的状态设置为clear。
*/
static inline void vmcs_clear(struct vmcs* vmcs) {
	PHYSICAL_ADDRESS physical = MmGetPhysicalAddress(vmcs);
	u64 phys_addr = physical.QuadPart;
	/*
	* 如果在执行vmclear指令前已经加载过当前vmcs指针，并且vmclear指令的目标vmcs是
	* current-VMCS，则会设置current-VMCS pointer为FFFFFFF_FFFFFFFFH值
	*/
	__vmx_vmclear(&phys_addr);
}

/*
* 从内存中加载一个64位物理地址作为 current-VMCS pointer
*/
static void vmcs_load(struct vmcs* vmcs) {
	PHYSICAL_ADDRESS physical = MmGetPhysicalAddress(vmcs);
	u64 phys_addr = physical.QuadPart;
	/*
	* 执行这条指令将更新 current-VMCS pointer值，在指令未执行成功
	* 时，current-VMCS pointer 将维持原有值。
	*/
	__vmx_vmptrld(&phys_addr);
}