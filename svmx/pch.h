#pragma once
#include <ntifs.h>
#include <minwindef.h>
#include <ntstrsafe.h>
#include <limits.h>
#include <intrin.h>
#include "int-ll64.h"
#include "types.h"
#include "Logging.h"
#include "msr-index.h"

#define DRIVER_TAG	'xmvs'

#define __AC(X,Y)	(X##Y)
#define _AC(X,Y)	__AC(X,Y)
#define _AT(T,X)	((T)(X))
#define _UL(x)		(_AC(x, UL))
#define _ULL(x)		(_AC(x, ULL))
#define _BITUL(x)	(_UL(1) << (x))

#define UL(x)		(_UL(x))
#define ULL(x)		(_ULL(x))

#define BIT(nr)		(UL(1) << (nr))
#define BIT_ULL(nr)		(ULL(1) << (nr))

#include "kvm_host.h"
#include "virtext.h"
#include "msr.h"
#include "processor-flags.h"





#pragma warning(disable:4200)
#pragma warning(disable:4201)