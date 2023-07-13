#include "pch.h"
#include "Logging.h"

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