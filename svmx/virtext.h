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