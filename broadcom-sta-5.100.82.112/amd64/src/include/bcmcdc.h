/*
 * CDC network driver ioctl/indication encoding
 * Broadcom 802.11abg Networking Device Driver
 *
 * Definitions subject to change without notice.
 *
 * Copyright (C) 2010, Broadcom Corporation
 * All Rights Reserved.
 * 
 * THIS SOFTWARE IS OFFERED "AS IS", AND BROADCOM GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 *
 * $Id: bcmcdc.h,v 13.25 2009-09-23 22:40:26 Exp $
 */

#ifndef _bcmcdc_h_
#define	_bcmcdc_h_
#include <proto/ethernet.h>

typedef struct cdc_ioctl {
	uint32 cmd;      
	uint32 len;      
	uint32 flags;    
	uint32 status;   
} cdc_ioctl_t;

#define CDC_MAX_MSG_SIZE   ETHER_MAX_LEN

#define CDCL_IOC_OUTLEN_MASK   0x0000FFFF  

#define CDCL_IOC_OUTLEN_SHIFT  0
#define CDCL_IOC_INLEN_MASK    0xFFFF0000   
#define CDCL_IOC_INLEN_SHIFT   16

#define CDCF_IOC_ERROR		0x01	
#define CDCF_IOC_SET		0x02	
#define CDCF_IOC_IF_MASK	0xF000	
#define CDCF_IOC_IF_SHIFT	12
#define CDCF_IOC_ID_MASK	0xFFFF0000	
#define CDCF_IOC_ID_SHIFT	16		

#define CDC_IOC_IF_IDX(flags)	(((flags) & CDCF_IOC_IF_MASK) >> CDCF_IOC_IF_SHIFT)
#define CDC_IOC_ID(flags)	(((flags) & CDCF_IOC_ID_MASK) >> CDCF_IOC_ID_SHIFT)

#define CDC_GET_IF_IDX(hdr) \
	((int)((((hdr)->flags) & CDCF_IOC_IF_MASK) >> CDCF_IOC_IF_SHIFT))
#define CDC_SET_IF_IDX(hdr, idx) \
	((hdr)->flags = (((hdr)->flags & ~CDCF_IOC_IF_MASK) | ((idx) << CDCF_IOC_IF_SHIFT)))

#define	BDC_HEADER_LEN		4

#define BDC_PROTO_VER		2	

#define BDC_FLAG_VER_MASK	0xf0	
#define BDC_FLAG_VER_SHIFT	4	

#define BDC_FLAG__UNUSED	0x03	
#define BDC_FLAG_SUM_GOOD	0x04	
#define BDC_FLAG_SUM_NEEDED	0x08	

#define BDC_PRIORITY_MASK	0x7

#define BDC_FLAG2_IF_MASK	0x0f	
#define BDC_FLAG2_IF_SHIFT	0

#define BDC_GET_IF_IDX(hdr) \
	((int)((((hdr)->flags2) & BDC_FLAG2_IF_MASK) >> BDC_FLAG2_IF_SHIFT))
#define BDC_SET_IF_IDX(hdr, idx) \
	((hdr)->flags2 = (((hdr)->flags2 & ~BDC_FLAG2_IF_MASK) | ((idx) << BDC_FLAG2_IF_SHIFT)))

struct bdc_header {
	uint8	flags;			
	uint8	priority;		
	uint8	flags2;
	uint8	dataOffset;		
};

#define BDC_PROTO_VER_1		1	

#endif 
