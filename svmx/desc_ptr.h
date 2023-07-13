#pragma once

#include <pshpack1.h>
struct desc_ptr {
	unsigned short size;
	unsigned long address;
};
#include <poppack.h>