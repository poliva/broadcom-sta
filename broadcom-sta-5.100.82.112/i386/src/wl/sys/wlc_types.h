/*
 * Forward declarations for commonly used wl driver structs
 *
 * Copyright (C) 2010, Broadcom Corporation
 * All Rights Reserved.
 * 
 * THIS SOFTWARE IS OFFERED "AS IS", AND BROADCOM GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 *
 * $Id: wlc_types.h,v 1.7.10.3 2010-04-23 18:02:20 Exp $
 */

#ifndef _wlc_types_h_
#define _wlc_types_h_

typedef struct wlc_info wlc_info_t;
typedef struct wlc_hw_info wlc_hw_info_t;
typedef struct wlc_if wlc_if_t;
typedef struct wl_if wl_if_t;
typedef struct led_info led_info_t;
typedef struct bmac_led bmac_led_t;
typedef struct bmac_led_info bmac_led_info_t;
typedef struct seq_cmds_info wlc_seq_cmds_info_t;
typedef struct wlc_ccx ccx_t;
typedef struct wlc_ccx_rm ccx_rm_t;
typedef struct apps_wlc_psinfo apps_wlc_psinfo_t;
typedef struct scb_module scb_module_t;
typedef struct ba_info ba_info_t;
typedef struct wlc_frminfo wlc_frminfo_t;
typedef struct amsdu_info amsdu_info_t;
typedef struct cram_info cram_info_t;
typedef struct wlc_extlog_info wlc_extlog_info_t;
typedef struct wlc_txq_info wlc_txq_info_t;
typedef struct _wlc_hwtimer_to wlc_hwtimer_to_t;
typedef struct wlc_cac wlc_cac_t;
typedef struct ampdu_info ampdu_info_t;
typedef struct ratesel_info ratesel_info_t;
typedef struct wlc_ap_info wlc_ap_info_t;
typedef struct wlc_scan_info wlc_scan_info_t;
typedef struct dpt_info dpt_info_t;
typedef struct wlc_auth_info wlc_auth_info_t;
#ifdef WLBDD
typedef struct bdd_info bdd_info_t;
#endif
#ifdef WLP2P
typedef struct p2p_info p2p_info_t;
#endif
#ifdef WLMCHAN
typedef struct mchan_info mchan_info_t;
typedef struct wlc_mchan_context wlc_mchan_context_t;
#endif
typedef struct wowl_info wowl_info_t;
typedef struct wlc_plt_info wlc_plt_pub_t;
typedef struct supplicant supplicant_t;
typedef struct authenticator authenticator_t;
typedef struct antsel_info antsel_info_t;
typedef struct lmac_info lmac_info_t;
typedef struct bmac_pmq bmac_pmq_t;
#ifdef WMF
typedef struct wlc_wmf_instance wlc_wmf_instance_t;
typedef struct wmf_info wmf_info_t;
#endif
typedef struct wlc_rrm_info wlc_rrm_info_t;
typedef struct rm_info rm_info_t;

struct d11init;

#ifndef _hnddma_pub_
#define _hnddma_pub_
typedef const struct hnddma_pub hnddma_t;
#endif 

#endif	
