#pragma once

/*
* CPU virtualization extension handling
* 
* 
*/


/*
* VMX functions
*/
int cpu_has_vmx();

/*
* SVM functions
*/

/** Check if the CPU has SVM support
 *
 * You can use the 'msg' arg to get a message describing the problem,
 * if the function returns zero. Simply pass NULL if you are not interested
 * on the messages.
 */
int cpu_has_svm(const char** msg);

bool cpu_is_enabled_vmx();

static ULONG_PTR DisableHardware(
	_In_ ULONG_PTR Argument
) {
	UNREFERENCED_PARAMETER(Argument);
	__vmx_off();
	__writecr4(__readcr4() & ~X86_CR4_VMXE);
	return 0;
}
/**
 * cpu_vmxoff() - Disable VMX on the current CPU
 *
 * Disable VMX and clear CR4.VMXE (even if VMXOFF faults)
 *
 * Note, VMXOFF causes a #UD if the CPU is !post-VMXON, but it's impossible to
 * atomically track post-VMXON state, e.g. this may be called in NMI context.
 * Eat all faults as all other faults on VMXOFF faults are mode related, i.e.
 * faults are guaranteed to be due to the !post-VMXON check unless the CPU is
 * magically in RM, VM86, compat mode, or at CPL>0.
 */
static int cpu_vmxoff(void) {
	KeIpiGenericCall(DisableHardware, 0);

	return 0;
}