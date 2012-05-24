/*
 * Linux-specific portion of Broadcom 802.11abg Networking Device Driver
 * cfg80211 interface
 *
 * Copyright (C) 2010, Broadcom Corporation
 * All Rights Reserved.
 * 
 * THIS SOFTWARE IS OFFERED "AS IS", AND BROADCOM GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 *
 * $Id: wl_cfg80211.h,v 1.1.8.1 2011-01-26 00:57:46 Exp $
 */

#ifndef _wl_cfg80211_h_
#define _wl_cfg80211_h_

#include <net/cfg80211.h>
#include <wlioctl.h>

struct wl_conf;
struct wl_priv;
struct wl_security;

#define htod32(i) i
#define htod16(i) i
#define dtoh32(i) i
#define dtoh16(i) i
#define htodchanspec(i) i
#define dtohchanspec(i) i
#define dtoh32(i) i
#define dtoh16(i) i

#define WL_DBGMSG_ENABLE

#define WL_DBG_NONE	0
#define WL_DBG_DBG 	(1 << 2)
#define WL_DBG_INFO	(1 << 1)
#define WL_DBG_ERR	(1 << 0)
#define WL_DBG_MASK ((WL_DBG_DBG | WL_DBG_INFO | WL_DBG_ERR) << 1)

#if defined(WL_DBGMSG_ENABLE)
#define	WL_DBG(args)								\
do {									\
	if (wl_dbg_level & WL_DBG_DBG) {			\
		printk(KERN_ERR "DEBUG @%s :", __func__);	\
		printk args;							\
	}									\
} while (0)
#else				
#define	WL_DBG(args)
#endif				

#define	WL_ERR(args)									\
do {										\
	if (wl_dbg_level & WL_DBG_ERR) {				\
		if (net_ratelimit()) {						\
			printk(KERN_ERR "ERROR @%s : ", __func__);	\
			printk args;						\
		} 								\
	}									\
} while (0)

#define	WL_INF(args)									\
do {										\
	if (wl_dbg_level & WL_DBG_INFO) {				\
		if (net_ratelimit()) {						\
			printk(KERN_ERR "INFO @%s : ", __func__);	\
			printk args;						\
		}								\
	}									\
} while (0)

#define WL_NUM_SCAN_MAX		1
#define WL_NUM_PMKIDS_MAX	MAXPMKID	
#define WL_SCAN_BUF_BASE 		(16*1024)
#define WL_TLV_INFO_MAX 		1024
#define WL_BSS_INFO_MAX			2048
#define WL_ASSOC_INFO_MAX	512
#define WL_IOCTL_LEN_MAX	1024
#define WL_EXTRA_BUF_MAX	2048
#define WL_AP_MAX	256	

enum wl_status {
	WL_STATUS_READY,
	WL_STATUS_SCANNING,
	WL_STATUS_SCAN_ABORTING,
	WL_STATUS_CONNECTING,
	WL_STATUS_CONNECTED
};

enum wl_mode {
	WL_MODE_BSS,
	WL_MODE_IBSS,
	WL_MODE_AP
};

struct beacon_proberesp {
	__le64 timestamp;
	__le16 beacon_int;
	__le16 capab_info;
	u8 variable[0];
} __attribute__ ((packed));

struct wl_conf {
	u32 mode;		
	u32 frag_threshold;
	u32 rts_threshold;
	u32 retry_short;
	u32 retry_long;
	s32 tx_power;
	struct ieee80211_channel channel;
};

struct wl_event_loop {
	s32(*handler[WLC_E_LAST]) (struct wl_priv *wl, struct net_device *ndev,
	                           const wl_event_msg_t *e, void *data);
};

struct wl_cfg80211_bss_info {
	u16 band;
	u16 channel;
	s16 rssi;
	u16 frame_len;
	u8 frame_buf[1];
};

struct wl_scan_req {
	struct wlc_ssid ssid;
};

struct wl_ie {
	u16 offset;
	u8 buf[WL_TLV_INFO_MAX];
};

struct wl_event_q {
	struct list_head eq_list;
	u32 etype;
	wl_event_msg_t emsg;
	s8 edata[1];
};

struct wl_security {
	u32 wpa_versions;
	u32 auth_type;
	u32 cipher_pairwise;
	u32 cipher_group;
	u32 wpa_auth;
};

struct wl_profile {
	struct wlc_ssid ssid;
	u8 bssid[ETHER_ADDR_LEN];
	struct wl_security sec;
	bool active;
};

struct wl_connect_info {
	u8 *req_ie;
	s32 req_ie_len;
	u8 *resp_ie;
	s32 resp_ie_len;
};

struct wl_assoc_ielen {
	u32 req_len;
	u32 resp_len;
};

struct wl_pmk_list {
	pmkid_list_t pmkids;
	pmkid_t foo[MAXPMKID - 1];
};

struct wl_priv {
	struct wireless_dev *wdev;	
	struct wl_conf *conf;	
	struct cfg80211_scan_request *scan_request;	
	struct wl_event_loop el;	
	struct list_head eq_list;	
	spinlock_t eq_lock;	
	struct wl_scan_req *scan_req_int;	
	struct wl_ie ie;	 
	struct ether_addr bssid;	
	struct semaphore event_sync;	
	struct wl_profile *profile;	
	struct wl_connect_info conn_info;	
	struct wl_pmk_list *pmk_list;	
	struct task_struct *event_tsk;	
	unsigned long status;		
	bool active_scan;	
	bool link_up;		
	u8 *ioctl_buf;	
	u8 *extra_buf;	
	u8 ci[0] __attribute__ ((__aligned__(NETDEV_ALIGN)));
};

#define wl_to_dev(w) (wiphy_dev(wl->wdev->wiphy))
#define wl_to_wiphy(w) (w->wdev->wiphy)
#define wiphy_to_wl(w) ((struct wl_priv *)(wiphy_priv(w)))
#define wl_to_wdev(w) (w->wdev)
#define wdev_to_wl(w) ((struct wl_priv *)(wdev_priv(w)))
#define wl_to_ndev(w) (w->wdev->netdev)
#define ndev_to_wl(n) (wdev_to_wl(n->ieee80211_ptr))
#define wl_to_sr(w) (w->scan_req_int)
#define wl_to_ie(w) (&w->ie)
#define wl_to_conn(w) (&w->conn_info)

static inline struct wl_bss_info *next_bss(struct wl_scan_results *list, struct wl_bss_info *bss)
{
	return bss = bss ? (struct wl_bss_info *)((unsigned long)bss +
	             dtoh32(bss->length)) : list->bss_info;
}

#define for_each_bss(list, bss, __i)	\
	for (__i = 0; __i < list->count && __i < WL_AP_MAX; __i++, bss = next_bss(list, bss))

extern s32 wl_cfg80211_attach(struct net_device *ndev, struct device *dev);
extern void wl_cfg80211_detach(struct net_device *ndev);

extern void wl_cfg80211_event(struct net_device *ndev, const wl_event_msg_t *e, void *data);
extern s32 wl_cfg80211_up(struct net_device *ndev);
extern s32 wl_cfg80211_down(struct net_device *ndev);

#endif 
