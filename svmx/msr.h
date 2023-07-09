#pragma once


#define rdmsr(msr, val1, val2)					\
do {								\
	u64 __val = __readmsr((msr));			\
	(val1) = (u32)__val;					\
	(val2) = (u32)(__val >> 32);				\
} while (0)