#pragma once
#include "pch.h"
#include "kvm_types.h"
#include "vmx.h"
#include "vmcs.h"
#include "x86.h"

static unsigned long vmcs_readl(unsigned long field) {
	size_t value;
	__vmx_vmread(field, &value);
	return (u32)value;
}

static void vmcs_writel(unsigned long field, unsigned long value) {
	__vmx_vmwrite(field, value);
}

static void __vmcs_writel(unsigned long field, unsigned long value)
{
	__vmx_vmwrite(field, value);
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