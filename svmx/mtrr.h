#pragma once

/* MTRR memory types, which are defined in SDM */
/*  These are the region types  */
#define MTRR_TYPE_UNCACHABLE 0
#define MTRR_TYPE_WRCOMB     1
/*#define MTRR_TYPE_         2*/
/*#define MTRR_TYPE_         3*/
#define MTRR_TYPE_WRTHROUGH  4
#define MTRR_TYPE_WRPROT     5
#define MTRR_TYPE_WRBACK     6
#define MTRR_NUM_TYPES       7

/*
 * Invalid MTRR memory type.  mtrr_type_lookup() returns this value when
 * MTRRs are disabled.  Note, this value is allocated from the reserved
 * values (0x7-0xff) of the MTRR memory types.
 */
#define MTRR_TYPE_INVALID    0xff

 /* In the Intel processor's MTRR interface, the MTRR type is always held in
	an 8 bit field: */
typedef __u8 mtrr_type;