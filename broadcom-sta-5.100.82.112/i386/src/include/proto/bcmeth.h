/*
 * Broadcom Ethernettype  protocol definitions
 *
 * Copyright (C) 2010, Broadcom Corporation
 * All Rights Reserved.
 * 
 * THIS SOFTWARE IS OFFERED "AS IS", AND BROADCOM GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 *
 * $Id: bcmeth.h,v 9.12 2009-12-29 19:57:18 Exp $
 */

#ifndef _BCMETH_H_
#define _BCMETH_H_

#ifndef _TYPEDEFS_H_
#include <typedefs.h>
#endif

#include <packed_section_start.h>

typedef BWL_PRE_PACKED_STRUCT struct bcmeth_hdr
{
	uint16	subtype;	
	uint16	length;
	uint8	version;	
	uint8	oui[3];		

	uint16	usr_subtype;
} BWL_POST_PACKED_STRUCT bcmeth_hdr_t;

#include <packed_section_end.h>

#endif	
