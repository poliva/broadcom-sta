/*
 * Misc system wide definitions
 *
 * Copyright (C) 2010, Broadcom Corporation
 * All Rights Reserved.
 * 
 * THIS SOFTWARE IS OFFERED "AS IS", AND BROADCOM GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 *
 * $Id: bcmdefs.h,v 13.69 2010-01-15 01:14:00 Exp $
 */

#ifndef	_bcmdefs_h_
#define	_bcmdefs_h_

#define BCM_REFERENCE(data)	((void)data)

#define bcmreclaimed 		0
#define BCMATTACHDATA(_data)	_data
#define BCMATTACHFN(_fn)	_fn
#define BCMPREATTACHDATA(_data)	_data
#define BCMPREATTACHFN(_fn)	_fn
#define BCMINITDATA(_data)	_data
#define BCMINITFN(_fn)		_fn
#define BCMUNINITFN(_fn)	_fn
#define	BCMNMIATTACHFN(_fn)	_fn
#define	BCMNMIATTACHDATA(_data)	_data
#define BCMOVERLAY0DATA(_sym)	_sym
#define BCMOVERLAY0FN(_fn)	_fn
#define BCMOVERLAY1DATA(_sym)	_sym
#define BCMOVERLAY1FN(_fn)	_fn
#define BCMOVERLAYERRFN(_fn)	_fn
#define CONST	const
#define BCMFASTPATH

#define BCMROMDATA(_data)	_data
#define BCMROMDAT_NAME(_data)	_data
#define BCMROMFN(_fn)		_fn
#define BCMROMFN_NAME(_fn)	_fn
#define STATIC	static
#define BCMROMDAT_ARYSIZ(data)	ARRAYSIZE(data)
#define BCMROMDAT_SIZEOF(data)	sizeof(data)
#define BCMROMDAT_APATCH(data)
#define BCMROMDAT_SPATCH(data)

#define	SI_BUS			0	
#define	PCI_BUS			1	
#define	PCMCIA_BUS		2	
#define SDIO_BUS		3	
#define JTAG_BUS		4	
#define USB_BUS			5	
#define SPI_BUS			6	
#define RPC_BUS			7	

#ifdef BCMBUSTYPE
#define BUSTYPE(bus) 	(BCMBUSTYPE)
#else
#define BUSTYPE(bus) 	(bus)
#endif

#ifdef BCMCHIPTYPE
#define CHIPTYPE(bus) 	(BCMCHIPTYPE)
#else
#define CHIPTYPE(bus) 	(bus)
#endif

#define SPROMBUS	(PCI_BUS)

#define CHIPID(chip)	(chip)

#ifdef BCMCHIPREV
#define CHIPREV(rev)	(BCMCHIPREV)
#else
#define CHIPREV(rev)	(rev)
#endif

#define DMADDR_MASK_32 0x0		
#define DMADDR_MASK_30 0xc0000000	
#define DMADDR_MASK_0  0xffffffff	

#define	DMADDRWIDTH_30  30 
#define	DMADDRWIDTH_32  32 
#define	DMADDRWIDTH_63  63 
#define	DMADDRWIDTH_64  64 

#ifdef BCMDMA64OSL
typedef struct {
	uint32 loaddr;
	uint32 hiaddr;
} dma64addr_t;

typedef dma64addr_t dmaaddr_t;
#define PHYSADDRHI(_pa) ((_pa).hiaddr)
#define PHYSADDRHISET(_pa, _val) \
	do { \
		(_pa).hiaddr = (_val);		\
	} while (0)
#define PHYSADDRLO(_pa) ((_pa).loaddr)
#define PHYSADDRLOSET(_pa, _val) \
	do { \
		(_pa).loaddr = (_val);		\
	} while (0)

#else
typedef unsigned long dmaaddr_t;
#define PHYSADDRHI(_pa) (0)
#define PHYSADDRHISET(_pa, _val)
#define PHYSADDRLO(_pa) ((_pa))
#define PHYSADDRLOSET(_pa, _val) \
	do { \
		(_pa) = (_val);			\
	} while (0)
#endif 

typedef struct  {
	dmaaddr_t addr;
	uint32	  length;
} hnddma_seg_t;

#define MAX_DMA_SEGS 4

typedef struct {
	void *oshdmah; 
	uint origsize; 
	uint nsegs;
	hnddma_seg_t segs[MAX_DMA_SEGS];
} hnddma_seg_map_t;

#if defined(BCM_RPC_NOCOPY) || defined(BCM_RCP_TXNOCOPY)

#define BCMEXTRAHDROOM 220
#else
#define BCMEXTRAHDROOM 172
#endif

#define BCMDONGLEHDRSZ 12
#define BCMDONGLEPADSZ 16

#define BCMDONGLEOVERHEAD	(BCMDONGLEHDRSZ + BCMDONGLEPADSZ)

#ifdef BCMDBG

#ifndef BCMDBG_ERR
#define BCMDBG_ERR
#endif 

#ifndef BCMDBG_ASSERT
#define BCMDBG_ASSERT
#endif 

#endif 

#if defined(BCMDBG_ASSERT)
#define BCMASSERT_SUPPORT
#endif 

#define BITFIELD_MASK(width) \
		(((unsigned)1 << (width)) - 1)
#define GFIELD(val, field) \
		(((val) >> field ## _S) & field ## _M)
#define SFIELD(val, field, bits) \
		(((val) & (~(field ## _M << field ## _S))) | \
		 ((unsigned)(bits) << field ## _S))

#undef	BCMSPACE
#define bcmspace	FALSE	

#define	MAXSZ_NVRAM_VARS	4096

#define LOCATOR_EXTERN static

#endif 
