#include "pch.h"
#include "sysemu.h"

void virt_init_subsystems(void) {
	module_call_init(MODULE_INIT_QOM);
}