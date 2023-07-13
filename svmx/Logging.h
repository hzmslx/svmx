#pragma once

static const ULONG KERN_EMERG = 0;
static const ULONG KERN_ALERT = 1;
static const ULONG KERN_CRIT = 2;
static const ULONG KERN_ERR = 3;
static const ULONG KERN_WARNING = 4;
static const ULONG KERN_NOTICE = 5;
static const ULONG KERN_INFO = 6;
static const ULONG KERN_DEBUG = 7;


#ifndef DRIVER_PREFIX
#define DRIVER_PREFIX "[Log]: " // Prefix to be added to the log lib
#endif // !DRIVER_PREFIX

ULONG Log(ULONG level, PCSTR format, ...);
ULONG LogError(PCSTR format, ...);