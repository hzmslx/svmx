#pragma once

/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * This module enables machines with Intel VT-x extensions to run virtual
 * machines without emulation or binary translation.
 *
 * MMU support
 *
 * Copyright (C) 2006 Qumranet, Inc.
 * Copyright 2010 Red Hat, Inc. and/or its affiliates.
 *
 * Authors:
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *   Avi Kivity   <avi@qumranet.com>
 */

 /*
  * The MMU needs to be able to access/walk 32-bit and 64-bit guest page tables,
  * as well as guest EPT tables, so the code in this file is compiled thrice,
  * once per guest PTE type.  The per-type defines are #undef'd at the end.
  */

#if PTTYPE == 64
#define pt_element_t u64
#define guest_walker guest_walker64
#define FNAME(name)	paging##64_##name
#define PT_LEVEL_BITS 9
#define PT_GUEST_DIRTY_SHIFT PT_DIRTY_SHIFT
#define PT_GUEST_ACCESSED_SHIFT PT_ACCESSED_SHIFT
#elif PTTYPE == 32

#elif PTTYPE == PTTYPE_EPT

#else

#endif


/* Common logic, but per-type values. These also need to be undefined. */
