#pragma once
#include "pch.h"
#include "desc_defs.h"

static inline void store_idt(struct desc_ptr* dtr)
{
	__sidt(dtr);
}