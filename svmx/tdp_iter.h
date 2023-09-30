#pragma once

#include "kvm_host.h"
#include "mmu.h"
#include "spte.h"

/*
* A TDP iterator performs a pre-order walk over a TDP paging structure.
*/
struct tdp_iter {
	/*
	* The iterator will traverse the paging structure towards the mapping
	* for this GFN.
	*/
	gfn_t next_last_level_gfn;

};