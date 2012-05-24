/*
 * Minimal debug/trace/assert driver definitions for
 * Broadcom 802.11 Networking Adapter.
 *
 * Copyright (C) 2010, Broadcom Corporation
 * All Rights Reserved.
 * 
 * THIS SOFTWARE IS OFFERED "AS IS", AND BROADCOM GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 *
 * $Id: wl_dbg.h,v 1.116.8.8 2010-08-17 18:46:22 Exp $
 */

#ifndef _wl_dbg_h_
#define _wl_dbg_h_

extern uint32 wl_msg_level;
extern uint32 wl_msg_level2;

#define WL_PRINT(args)		printf args

#ifdef BCMDBG

#define	WL_NONE(args)		do {if (wl_msg_level & 0) WL_PRINT(args);} while (0)

#define	WL_ERROR(args)		do {if (wl_msg_level & WL_ERROR_VAL) WL_PRINT(args);} while (0)
#define	WL_TRACE(args)		do {if (wl_msg_level & WL_TRACE_VAL) WL_PRINT(args);} while (0)

#else	

#define WL_NONE(args)

#ifdef BCMDBG_ERR
#define	WL_ERROR(args)		WL_PRINT(args)
#else
#define	WL_ERROR(args)
#endif 
#define	WL_TRACE(args)
#define WL_APSTA_UPDN(args)
#define WL_APSTA_RX(args)
#define WL_WSEC(args)
#define WL_WSEC_DUMP(args)

#endif 

extern uint32 wl_msg_level;
extern uint32 wl_msg_level2;
#endif 
