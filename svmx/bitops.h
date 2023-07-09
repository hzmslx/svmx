#pragma once

static inline int test_bit(int nr, const volatile void* addr) {
	return (1UL & (((const int*)addr)[nr >> 5] >> (nr & 31))) != 0UL;
}