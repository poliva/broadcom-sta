/*
 * Key management related declarations
 * and exported functions for
 * Broadcom 802.11abg Networking Device Driver
 *
 * Copyright (C) 2010, Broadcom Corporation
 * All Rights Reserved.
 * 
 * THIS SOFTWARE IS OFFERED "AS IS", AND BROADCOM GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 *
 * $Id: wlc_key.h,v 1.64.8.4 2010-06-09 02:22:27 Exp $
 */

#ifndef _wlc_key_h_
#define _wlc_key_h_

typedef struct wsec_iv {
	uint32		hi;	
	uint16		lo;	
} wsec_iv_t;

#if defined(MFP)
#define WLC_NUMRXIVS	17	
#define WLC_MFP_IVIDX	16	
#else
#define WLC_NUMRXIVS	16	
#endif 

typedef struct wsec_key {
	struct ether_addr ea;		
	uint8		idx;		
	uint8		id;		
	uint8		algo;		
	uint8		rcmta;		
	uint16		flags;		
	uint8 		algo_hw;	
	uint8 		aes_mode;	
	int8		iv_len;		
	int8		icv_len;	
	uint32		len;		

	uint8		data[DOT11_MAX_KEY_SIZE];	
	wsec_iv_t	rxiv[WLC_NUMRXIVS];		
	wsec_iv_t	txiv;		

#ifdef GTK_RESET
	bool		gtk_plumbed;
#endif 
} wsec_key_t;

#endif 
