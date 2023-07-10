#pragma once

/*
 * CPUID functions returning a single datum
 */
unsigned int cpuid_eax(unsigned int op);
unsigned int cpuid_ebx(unsigned int op);
unsigned int cpuid_ecx(unsigned int op);
unsigned int cpuid_edx(unsigned int op);