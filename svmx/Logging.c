#include "pch.h"
#include "Logging.h"

// IRQL <= DIRQL
/*
Device IRQL - a range of levels used for hardware interrupts 
(
3 to 11 on x64/ARM/ARM64, 
3 to 26 on x86
).
*/

ULONG Log(ULONG level, PCSTR format, ...) {
	va_list list;
	va_start(list, format);
	return vDbgPrintExWithPrefix(DRIVER_PREFIX, DPFLTR_IHVDRIVER_ID, level, format, list);
}

ULONG LogError(PCSTR format, ...) {
	va_list list;
	va_start(list, format);
	return vDbgPrintExWithPrefix(DRIVER_PREFIX, DPFLTR_IHVDRIVER_ID, KERN_ERR, format, list);
}