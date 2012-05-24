/*
 * OS Abstraction Layer
 *
 * Copyright (C) 2010, Broadcom Corporation
 * All Rights Reserved.
 * 
 * THIS SOFTWARE IS OFFERED "AS IS", AND BROADCOM GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 *
 * $Id: osl.h,v 13.45.2.2 2010-08-31 00:29:57 Exp $
 */

#ifndef _osl_h_
#define _osl_h_

typedef struct osl_info osl_t;
typedef struct osl_dmainfo osldma_t;

#define OSL_PKTTAG_SZ	32 

typedef void (*pktfree_cb_fn_t)(void *ctx, void *pkt, unsigned int status);

typedef unsigned int (*osl_rreg_fn_t)(void *ctx, void *reg, unsigned int size);
typedef void  (*osl_wreg_fn_t)(void *ctx, void *reg, unsigned int val, unsigned int size);

#ifdef __mips__
#define PREF_LOAD		0
#define PREF_STORE		1
#define PREF_LOAD_STREAMED	4
#define PREF_STORE_STREAMED	5
#define PREF_LOAD_RETAINED	6
#define PREF_STORE_RETAINED	7
#define PREF_WBACK_INV		25
#define PREF_PREPARE4STORE	30

#define MAKE_PREFETCH_FN(hint) \
static inline void prefetch_##hint(const void *addr) \
{ \
	__asm__ __volatile__(\
	"       .set    mips4           \n" \
	"       pref    %0, (%1)        \n" \
	"       .set    mips0           \n" \
	: \
	: "i" (hint), "r" (addr)); \
}

#define MAKE_PREFETCH_RANGE_FN(hint) \
static inline void prefetch_range_##hint(const void *addr, int len) \
{ \
	int size = len; \
	while (size > 0) { \
		prefetch_##hint(addr); \
		size -= 32; \
	} \
}

MAKE_PREFETCH_FN(PREF_LOAD)
MAKE_PREFETCH_RANGE_FN(PREF_LOAD)
MAKE_PREFETCH_FN(PREF_STORE)
MAKE_PREFETCH_RANGE_FN(PREF_STORE)
MAKE_PREFETCH_FN(PREF_LOAD_STREAMED)
MAKE_PREFETCH_RANGE_FN(PREF_LOAD_STREAMED)
MAKE_PREFETCH_FN(PREF_STORE_STREAMED)
MAKE_PREFETCH_RANGE_FN(PREF_STORE_STREAMED)
MAKE_PREFETCH_FN(PREF_LOAD_RETAINED)
MAKE_PREFETCH_RANGE_FN(PREF_LOAD_RETAINED)
MAKE_PREFETCH_FN(PREF_STORE_RETAINED)
MAKE_PREFETCH_RANGE_FN(PREF_STORE_RETAINED)
#endif 

#include <linux_osl.h>

#ifndef PKTDBG_TRACE
#define PKTDBG_TRACE(osh, pkt, bit)
#endif

#define	SET_REG(osh, r, mask, val)	W_REG((osh), (r), ((R_REG((osh), r) & ~(mask)) | (val)))

#ifndef AND_REG
#define AND_REG(osh, r, v)		W_REG(osh, (r), R_REG(osh, r) & (v))
#endif   

#ifndef OR_REG
#define OR_REG(osh, r, v)		W_REG(osh, (r), R_REG(osh, r) | (v))
#endif   

#if !defined(OSL_SYSUPTIME)
#define OSL_SYSUPTIME() (0)
#define OSL_SYSUPTIME_SUPPORT FALSE
#else
#define OSL_SYSUPTIME_SUPPORT TRUE
#endif 

#endif	
