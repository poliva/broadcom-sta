/*
 * Linux-specific portion of
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
 * $Id: wl_linux.c,v 1.524.2.40.2.15 2011-02-09 02:28:28 Exp $
 */

#define LINUX_PORT

#define __UNDEF_NO_VERSION__

#include <typedefs.h>
#include <linuxver.h>
#include <osl.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 14)
#include <linux/module.h>
#endif

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/ethtool.h>
#include <linux/completion.h>
#include <linux/pci_ids.h>
#define WLC_MAXBSSCFG		1	

#include <asm/system.h>
#include <asm/io.h>
#include <asm/irq.h>
#include <asm/pgtable.h>
#include <asm/uaccess.h>
#include <asm/unaligned.h>

#include <proto/802.1d.h>

#include <epivers.h>
#include <bcmendian.h>
#include <proto/ethernet.h>
#include <bcmutils.h>
#include <pcicfg.h>
#include <wlioctl.h>
#include <wlc_key.h>

typedef const struct si_pub	si_t;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 4, 5)
#error "No support for Kernel Rev <= 2.4.5, As the older kernel revs doesn't support Tasklets"
#endif

#include <wlc_pub.h>
#include <wl_dbg.h>
#include <wlc_ethereal.h>
#include <proto/ieee80211_radiotap.h>

#include <wl_iw.h>
#ifdef USE_IW
struct iw_statistics *wl_get_wireless_stats(struct net_device *dev);
#endif

#include <wl_export.h>

#include <wl_linux.h>

#ifdef WL_THREAD
#include <linux/kthread.h>
#endif 

#if defined(USE_CFG80211)
#include <wl_cfg80211.h>
#endif

static void wl_timer(ulong data);
static void _wl_timer(wl_timer_t *t);

static int wl_monitor_start(struct sk_buff *skb, struct net_device *dev);

#ifdef WL_ALL_PASSIVE
static void wl_start_txqwork(struct wl_task *task);
static void wl_txq_free(wl_info_t *wl);
#define TXQ_LOCK(_wl)	spin_lock_bh(&(_wl)->txq_lock)
#define TXQ_UNLOCK(_wl)	spin_unlock_bh(&(_wl)->txq_lock)

static void wl_set_multicast_list_workitem(struct work_struct *work);

static void wl_timer_task(wl_task_t *task);
static void wl_dpc_rxwork(struct wl_task *task);
#else

#endif 

static int wl_reg_proc_entry(wl_info_t *wl);

static int wl_linux_watchdog(void *ctx);
static
int wl_found = 0;

struct ieee80211_tkip_data {
#define TKIP_KEY_LEN 32
	u8 key[TKIP_KEY_LEN];
	int key_set;

	u32 tx_iv32;
	u16 tx_iv16;
	u16 tx_ttak[5];
	int tx_phase1_done;

	u32 rx_iv32;
	u16 rx_iv16;
	u16 rx_ttak[5];
	int rx_phase1_done;
	u32 rx_iv32_new;
	u16 rx_iv16_new;

	u32 dot11RSNAStatsTKIPReplays;
	u32 dot11RSNAStatsTKIPICVErrors;
	u32 dot11RSNAStatsTKIPLocalMICFailures;

	int key_idx;

	struct crypto_tfm *tfm_arc4;
	struct crypto_tfm *tfm_michael;

	u8 rx_hdr[16], tx_hdr[16];
};

#define	WL_INFO(dev)		((wl_info_t*)(WL_DEV_IF(dev)->wl))	

static int wl_open(struct net_device *dev);
static int wl_close(struct net_device *dev);
#ifdef WL_THREAD
static int wl_start_wlthread(struct sk_buff *skb, struct net_device *dev);
#else
static int BCMFASTPATH wl_start(struct sk_buff *skb, struct net_device *dev);
#endif
static int wl_start_int(wl_info_t *wl, wl_if_t *wlif, struct sk_buff *skb);

static struct net_device_stats *wl_get_stats(struct net_device *dev);
static int wl_set_mac_address(struct net_device *dev, void *addr);
static void wl_set_multicast_list(struct net_device *dev);
static void _wl_set_multicast_list(struct net_device *dev);
static int wl_ethtool(wl_info_t *wl, void *uaddr, wl_if_t *wlif);
#ifdef NAPI_POLL
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
static int wl_poll(struct napi_struct *napi, int budget);
#else
static int wl_poll(struct net_device *dev, int *budget);
#endif 
#else 
static void wl_dpc(ulong data);
#endif 
static void wl_link_up(wl_info_t *wl, char * ifname);
static void wl_link_down(wl_info_t *wl, char *ifname);
static int wl_schedule_task(wl_info_t *wl, void (*fn)(struct wl_task *), void *context);
#ifdef WL_THREAD
static int wl_start_enqueue_wlthread(wl_info_t *wl, struct sk_buff *skb);
#endif 
#if defined(BCMDBG)
static int wl_dump(wl_info_t *wl, struct bcmstrbuf *b);
#endif 
static struct wl_if *wl_alloc_if(wl_info_t *wl, int iftype, uint unit, struct wlc_if* wlc_if);
static void wl_free_if(wl_info_t *wl, wl_if_t *wlif);
static void wl_get_driver_info(struct net_device *dev, struct ethtool_drvinfo *info);

#if defined(WL_CONFIG_RFKILL)
#include <linux/rfkill.h>
static int wl_init_rfkill(wl_info_t *wl);
static void wl_uninit_rfkill(wl_info_t *wl);
static int wl_set_radio_block(void *data, bool blocked);
static void wl_report_radio_state(wl_info_t *wl);
#endif

MODULE_LICENSE("MIXED/Proprietary");

static struct pci_device_id wl_id_table[] = {
	{ PCI_VENDOR_ID_BROADCOM, 0x4311, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 }, 
	{ PCI_VENDOR_ID_BROADCOM, 0x4312, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 }, 
	{ PCI_VENDOR_ID_BROADCOM, 0x4313, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 }, 
	{ PCI_VENDOR_ID_BROADCOM, 0x4315, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 }, 
	{ PCI_VENDOR_ID_BROADCOM, 0x4328, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 }, 
	{ PCI_VENDOR_ID_BROADCOM, 0x4329, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 }, 
	{ PCI_VENDOR_ID_BROADCOM, 0x432a, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 }, 
	{ PCI_VENDOR_ID_BROADCOM, 0x432b, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 }, 
	{ PCI_VENDOR_ID_BROADCOM, 0x432c, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 }, 
	{ PCI_VENDOR_ID_BROADCOM, 0x432d, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 }, 
	{ PCI_VENDOR_ID_BROADCOM, 0x4353, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 }, 
	{ PCI_VENDOR_ID_BROADCOM, 0xA99D, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 }, 
	{ PCI_VENDOR_ID_BROADCOM, 0x4357, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 }, 
	{ PCI_VENDOR_ID_BROADCOM, 0x4727, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 }, 
	{ PCI_VENDOR_ID_BROADCOM, 0x4358, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 }, 
	{ PCI_VENDOR_ID_BROADCOM, 0x4359, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 }, 
	{ PCI_VENDOR_ID_BROADCOM, 0x435a, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 }, 
	{ PCI_VENDOR_ID_BROADCOM, 0x0576, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 }, 
	{ 0 }
};
MODULE_DEVICE_TABLE(pci, wl_id_table);

#ifdef BCMDBG
static int msglevel = 0xdeadbeef;
module_param(msglevel, int, 0);
static int msglevel2 = 0xdeadbeef;
module_param(msglevel2, int, 0);
static int phymsglevel = 0xdeadbeef;
module_param(phymsglevel, int, 0);
#endif 

#if defined(WL_ALL_PASSIVE)

#ifdef WLP2P
static int passivemode = 1;
module_param(passivemode, int, 1);
#else
static int passivemode = 0;
module_param(passivemode, int, 0);
#endif 
#endif 

static int oneonly = 0;
module_param(oneonly, int, 0);

static int piomode = 0;
module_param(piomode, int, 0);

static int instance_base = 0;	
module_param(instance_base, int, 0);

#if defined(BCMDBG)
static struct ether_addr local_ea;
static char *macaddr = NULL;
module_param(macaddr, charp, S_IRUGO);
#endif

static int nompc = 0;
module_param(nompc, int, 0);

#ifdef quote_str
#undef quote_str
#endif 
#ifdef to_str
#undef to_str
#endif 
#define to_str(s) #s
#define quote_str(s) to_str(s)

#ifndef BRCM_WLAN_IFNAME
#define BRCM_WLAN_IFNAME wlan%d
#endif

static char name[IFNAMSIZ] = quote_str(BRCM_WLAN_IFNAME);

module_param_string(name, name, IFNAMSIZ, 0);

#define WL_RADIOTAP_BRCM_SNS	0x01
#define WL_RADIOTAP_BRCM_MCS	0x00000001

#define	IEEE80211_RADIOTAP_HTMOD_40		0x01
#define	IEEE80211_RADIOTAP_HTMOD_SGI		0x02
#define	IEEE80211_RADIOTAP_HTMOD_GF		0x04
#define	IEEE80211_RADIOTAP_HTMOD_LDPC		0x08
#define	IEEE80211_RADIOTAP_HTMOD_STBC_MASK	0x30
#define	IEEE80211_RADIOTAP_HTMOD_STBC_SHIFT	4

struct wl_radiotap_legacy {
	struct ieee80211_radiotap_header	ieee_radiotap;
	uint32       tsft_h;
	uint32       tsft_l;
	uint8        flags;
	uint8        rate;
	uint16       channel_freq;
	uint16       channel_flags;
	uint8        signal;
	uint8        noise;
	uint8        antenna;
} __attribute__((__packed__));

struct wl_radiotap_ht {
	struct ieee80211_radiotap_header        ieee_radiotap;
	uint32_t				it_present_ext;
	uint32_t	pad1;
	uint32		tsft_h;
	uint32		tsft_l;
	u_int8_t        flags;
	u_int8_t        pad2;
	u_int16_t       channel_freq;
	u_int16_t       channel_flags;
	u_int8_t        signal;
	u_int8_t        noise;
	u_int8_t        antenna;
	u_int8_t        pad3;
	u_int8_t	vend_oui[3];
	u_int8_t	vend_sns;
	u_int16_t	vend_skip_len;
	u_int8_t	mcs;
	u_int8_t	htflags;
} __attribute__((packed));

#define WL_RADIOTAP_PRESENT_LEGACY			\
	((1 << IEEE80211_RADIOTAP_TSFT) |		\
	 (1 << IEEE80211_RADIOTAP_RATE) |		\
	 (1 << IEEE80211_RADIOTAP_CHANNEL) |		\
	 (1 << IEEE80211_RADIOTAP_DBM_ANTSIGNAL) |	\
	 (1 << IEEE80211_RADIOTAP_DBM_ANTNOISE) |	\
	 (1 << IEEE80211_RADIOTAP_FLAGS) |		\
	 (1 << IEEE80211_RADIOTAP_ANTENNA))

#define WL_RADIOTAP_PRESENT_HT				\
	((1 << IEEE80211_RADIOTAP_TSFT) |		\
	 (1 << IEEE80211_RADIOTAP_FLAGS) |		\
	 (1 << IEEE80211_RADIOTAP_CHANNEL) |		\
	 (1 << IEEE80211_RADIOTAP_DBM_ANTSIGNAL) |	\
	 (1 << IEEE80211_RADIOTAP_DBM_ANTNOISE) |	\
	 (1 << IEEE80211_RADIOTAP_ANTENNA) |		\
	 (1 << IEEE80211_RADIOTAP_VENDOR_NAMESPACE) |	\
	 (1 << IEEE80211_RADIOTAP_EXT))

#ifndef ARPHRD_IEEE80211_RADIOTAP
#define ARPHRD_IEEE80211_RADIOTAP 803
#endif

#ifndef	SRCBASE
#define	SRCBASE "."
#endif

#if WIRELESS_EXT >= 19 || LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
static struct ethtool_ops wl_ethtool_ops =
#else
static const struct ethtool_ops wl_ethtool_ops =
#endif 
{
	.get_drvinfo = wl_get_driver_info
};
#endif 
#ifdef WL_THREAD
static int wl_thread_dpc_wlthread(void *data)
{
	wl_info_t *wl = (wl_info_t *) data;

	current->flags |= PF_NOFREEZE;

	while (1) {
		wait_event_interruptible_timeout
		(wl->thread_wqh,
			skb_queue_len(&wl->rpc_queue) ||
			skb_queue_len(&wl->tx_queue),
			1);

		if (kthread_should_stop())
			break;

		wl_rpcq_dispatch_wlthread(wl);
		wl_start_txqwork_wlthread(wl);
	}

	skb_queue_purge(&wl->tx_queue);
	skb_queue_purge(&wl->rpc_queue);

	return 0;
}
#endif 

#if defined(WL_USE_NETDEV_OPS)

static const struct net_device_ops wl_netdev_ops =
{
	.ndo_open = wl_open,
	.ndo_stop = wl_close,
#ifdef WL_THREAD
	.ndo_start_xmit = wl_start_wlthread,
#else
	.ndo_start_xmit = wl_start,
#endif
	.ndo_get_stats = wl_get_stats,
	.ndo_set_mac_address = wl_set_mac_address,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
	.ndo_set_rx_mode = wl_set_multicast_list,
#else
	.ndo_set_multicast_list = wl_set_multicast_list,
#endif
	.ndo_do_ioctl = wl_ioctl
};

static const struct net_device_ops wl_netdev_monitor_ops =
{
	.ndo_start_xmit = wl_monitor_start,
	.ndo_get_stats = wl_get_stats,
	.ndo_do_ioctl = wl_ioctl
};
#endif 

static
void wl_if_setup(struct net_device *dev)
{
#if defined(WL_USE_NETDEV_OPS)
	dev->netdev_ops = &wl_netdev_ops;
#else
	dev->open = wl_open;
	dev->stop = wl_close;
#ifdef WL_THREAD
	dev->hard_start_xmit = wl_start_wlthread;
#else
	dev->hard_start_xmit = wl_start;
#endif
	dev->get_stats = wl_get_stats;
	dev->set_mac_address = wl_set_mac_address;
	dev->set_multicast_list = wl_set_multicast_list;
	dev->do_ioctl = wl_ioctl;
#endif 
#ifdef NAPI_POLL
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
	{
		struct wl_info *wl = WL_INFO(dev);

		netif_napi_add(dev, &wl->napi, wl_poll, 64);
		napi_enable(&wl->napi);
	}
#else
	dev->poll = wl_poll;
	dev->weight = 64;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 21)
	netif_poll_enable(dev);
#endif 
#endif  
#endif 

#ifdef USE_IW
#if WIRELESS_EXT < 19
	dev->get_wireless_stats = wl_get_wireless_stats;
#endif
#if WIRELESS_EXT > 12
	dev->wireless_handlers = (struct iw_handler_def *) &wl_iw_handler_def;
#endif
#if WIRELESS_EXT >= 19 || LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
	dev->ethtool_ops = &wl_ethtool_ops;
#endif
#endif 

#if defined(USE_CFG80211) && LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
	dev->ethtool_ops = &wl_ethtool_ops;
#endif 

}

static wl_info_t *
wl_attach(uint16 vendor, uint16 device, ulong regs, uint bustype, void *btparam, uint irq)
{
	struct net_device *dev;
	wl_if_t *wlif;
	wl_info_t *wl;
	osl_t *osh;
	int unit, err;
#if defined(USE_CFG80211)
	struct device *parentdev;
#endif

	unit = wl_found + instance_base;
	err = 0;

	if (unit < 0) {
		WL_ERROR(("wl%d: unit number overflow, exiting\n", unit));
		return NULL;
	}

	if (oneonly && (unit != instance_base)) {
		WL_ERROR(("wl%d: wl_attach: oneonly is set, exiting\n", unit));
		return NULL;
	}

	osh = osl_attach(btparam, bustype, TRUE);
	ASSERT(osh);

	if ((wl = (wl_info_t*) MALLOC(osh, sizeof(wl_info_t))) == NULL) {
		WL_ERROR(("wl%d: malloc wl_info_t, out of memory, malloced %d bytes\n", unit,
			MALLOCED(osh)));
		osl_detach(osh);
		return NULL;
	}
	bzero(wl, sizeof(wl_info_t));

	wl->osh = osh;
	wl->unit = unit;
	atomic_set(&wl->callbacks, 0);

#ifdef WL_ALL_PASSIVE
	wl->all_dispatch_mode = (passivemode == 0) ? TRUE : FALSE;
	if (WL_ALL_PASSIVE_ENAB(wl)) {

		MY_INIT_WORK(&wl->txq_task.work, (work_func_t)wl_start_txqwork);
		wl->txq_task.context = wl;
		wl->txq_dispatched = FALSE;
		wl->txq_head = wl->txq_tail = NULL;

		MY_INIT_WORK(&wl->multicast_task.work, (work_func_t)wl_set_multicast_list_workitem);

		MY_INIT_WORK(&wl->wl_dpc_task.work, (work_func_t)wl_dpc_rxwork);
		wl->wl_dpc_task.context = wl;
	}
#endif  

	wlif = wl_alloc_if(wl, WL_IFTYPE_BSS, unit, NULL);
	if (!wlif) {
		WL_ERROR(("wl%d: wl_alloc_if failed\n", unit));
		MFREE(osh, wl, sizeof(wl_info_t));
		osl_detach(osh);
		return NULL;
	}

	dev = wlif->dev;
	wl->dev = dev;
	wl_if_setup(dev);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
	wlif = netdev_priv(dev);
#endif

	dev->base_addr = regs;

	WL_TRACE(("wl%d: Bus: ", unit));
	if (bustype == PCMCIA_BUS) {

		wl->piomode = TRUE;
		WL_TRACE(("PCMCIA\n"));
	} else if (bustype == PCI_BUS) {

		wl->piomode = piomode;
		WL_TRACE(("PCI/%s\n", wl->piomode ? "PIO" : "DMA"));
	}
	else if (bustype == RPC_BUS) {

	} else {
		bustype = PCI_BUS;
		WL_TRACE(("force to PCI\n"));
	}
	wl->bcm_bustype = bustype;

	if ((wl->regsva = ioremap_nocache(dev->base_addr, PCI_BAR0_WINSZ)) == NULL) {
		WL_ERROR(("wl%d: ioremap() failed\n", unit));
		goto fail;
	}

	spin_lock_init(&wl->lock);
	spin_lock_init(&wl->isr_lock);

	if (WL_ALL_PASSIVE_ENAB(wl)) {
#ifdef WL_ALL_PASSIVE
		spin_lock_init(&wl->txq_lock);
#endif 
		sema_init(&wl->sem, 1);
	}

	if (!(wl->wlc = wlc_attach((void *) wl, vendor, device, unit, wl->piomode,
		osh, wl->regsva, wl->bcm_bustype, btparam, &err))) {
		printf("%s: %s driver failed with code %d\n", dev->name, EPI_VERSION_STR, err);
		goto fail;
	}
	wl->pub = wlc_pub(wl->wlc);

	if (nompc) {
		if (wlc_iovar_setint(wl->wlc, "mpc", 0)) {
			WL_ERROR(("wl%d: Error setting MPC variable to 0\n", unit));
		}
	}

	wlc_iovar_setint(wl->wlc, "scan_passive_time", 170);

	wlc_iovar_setint(wl->wlc, "qtxpower", 23 * 4);

#ifdef BCMDBG
	if (macaddr != NULL) {  
		int err;

		WL_ERROR(("wl%d: setting MAC ADDRESS %s\n", unit, macaddr));
		bcm_ether_atoe(macaddr, &local_ea);

		err = wlc_iovar_op(wl->wlc, "cur_etheraddr", NULL, 0, &local_ea,
			ETHER_ADDR_LEN, IOV_SET, NULL);
		if (err)
			WL_ERROR(("wl%d: Error setting MAC ADDRESS\n", unit));
	}
#endif	
	bcopy(&wl->pub->cur_etheraddr, dev->dev_addr, ETHER_ADDR_LEN);

#ifndef NAPI_POLL

	tasklet_init(&wl->tasklet, wl_dpc, (ulong)wl);
#endif

	{
		if (request_irq(irq, wl_isr, IRQF_SHARED, dev->name, wl)) {
			WL_ERROR(("wl%d: request_irq() failed\n", unit));
			goto fail;
		}
		dev->irq = irq;
	}

#if defined(USE_IW)
	WL_ERROR(("Using Wireless Extension\n"));
#endif

#if defined(USE_CFG80211)
	parentdev = NULL;
	if (wl->bcm_bustype == PCI_BUS) {
		parentdev = &((struct pci_dev *)btparam)->dev;
	}
	if (parentdev) {
		if (wl_cfg80211_attach(dev, parentdev)) {
			goto fail;
		}
	}
	else {
		WL_ERROR(("unsupported bus type\n"));
		goto fail;
	}
#else
	if (wl->bcm_bustype == PCI_BUS) {
		struct pci_dev *pci_dev = (struct pci_dev *)btparam;
		if (pci_dev != NULL)
			SET_NETDEV_DEV(dev, &pci_dev->dev);
	}
#endif 

	if (register_netdev(dev)) {
		WL_ERROR(("wl%d: register_netdev() failed\n", unit));
		goto fail;
	}
	wlif->dev_registed = TRUE;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 14)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
	wl->tkipmodops = lib80211_get_crypto_ops("TKIP");
	if (wl->tkipmodops == NULL) {
		request_module("lib80211_crypt_tkip");
		wl->tkipmodops = lib80211_get_crypto_ops("TKIP");
	}
#else
	wl->tkipmodops = ieee80211_get_crypto_ops("TKIP");
	if (wl->tkipmodops == NULL) {
		request_module("ieee80211_crypt_tkip");
		wl->tkipmodops = ieee80211_get_crypto_ops("TKIP");
	}
#endif 
#endif 
#ifdef USE_IW
	wlif->iw.wlinfo = (void *)wl;
#endif

#if defined(WL_CONFIG_RFKILL)
	if (wl_init_rfkill(wl) < 0)
		WL_ERROR(("%s: init_rfkill_failure\n", __FUNCTION__));
#endif

	if (wlc_iovar_setint(wl->wlc, "leddc", 0xa0000)) {
		WL_ERROR(("wl%d: Error setting led duty-cycle\n", unit));
	}
	if (wlc_set(wl->wlc, WLC_SET_PM, PM_FAST)) {
		WL_ERROR(("wl%d: Error setting PM variable to FAST PS\n", unit));
	}

	if (wlc_iovar_setint(wl->wlc, "vlan_mode", OFF)) {
		WL_ERROR(("wl%d: Error setting vlan mode OFF\n", unit));
	}

	if (wlc_set(wl->wlc, WLC_SET_INFRA, 1)) {
		WL_ERROR(("wl%d: Error setting infra_mode to infrastructure\n", unit));
	}

#ifdef DEFAULT_EAPVER_AP

	if (wlc_iovar_setint(wl->wlc, "sup_wpa2_eapver", -1)) {
		WL_ERROR(("wl%d: Error setting sup_wpa2_eapver \n", unit));
	}
	if (wlc_iovar_setint(wl->wlc, "sup_m3sec_ok", 1)) {
		WL_ERROR(("wl%d: Error setting sup_m3sec_ok \n", unit));
	}
#endif 
#ifdef DISABLE_HT_RATE_FOR_WEP_TKIP

	if (wlc_iovar_setint(wl->wlc, "ht_wsec_restrict", 0x3)) {
		WL_ERROR(("wl%d: Error setting ht_wsec_restrict \n", unit));
	}
#endif 

	wlc_module_register(wl->pub, NULL, "linux", wl, NULL, wl_linux_watchdog, NULL);

#ifdef BCMDBG
	wlc_dump_register(wl->pub, "wl", (dump_fn_t)wl_dump, (void *)wl);
#endif

	wl_reg_proc_entry(wl);

	printf("%s: Broadcom BCM%04x 802.11 Hybrid Wireless Controller " EPI_VERSION_STR,
		dev->name, device);

#ifdef BCMDBG
	printf(" (Compiled in " SRCBASE " at " __TIME__ " on " __DATE__ ")");
#endif 
	printf("\n");

	wl_found++;
	return wl;

fail:
	wl_free(wl);
	return NULL;
}

static void __devexit wl_remove(struct pci_dev *pdev);

int __devinit
wl_pci_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	int rc;
	wl_info_t *wl;
	uint32 val;

	WL_TRACE(("%s: bus %d slot %d func %d irq %d\n", __FUNCTION__,
	          pdev->bus->number, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn), pdev->irq));

	if ((pdev->vendor != PCI_VENDOR_ID_BROADCOM) ||
	    (((pdev->device & 0xff00) != 0x4300) &&
		(pdev->device != 0x576) &&
	     ((pdev->device & 0xff00) != 0x4700) &&
	     ((pdev->device < 43000) || (pdev->device > 43999)))) {
		WL_TRACE(("%s: unsupported vendor %x device %x\n", __FUNCTION__,
		          pdev->vendor, pdev->device));
		return (-ENODEV);
	}

	rc = pci_enable_device(pdev);
	if (rc) {
		WL_ERROR(("%s: Cannot enable device %d-%d_%d\n", __FUNCTION__,
		          pdev->bus->number, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn)));
		return (-ENODEV);
	}
	pci_set_master(pdev);

	pci_read_config_dword(pdev, 0x40, &val);
	if ((val & 0x0000ff00) != 0)
		pci_write_config_dword(pdev, 0x40, val & 0xffff00ff);

	wl = wl_attach(pdev->vendor, pdev->device, pci_resource_start(pdev, 0), PCI_BUS, pdev,
		pdev->irq);
	if (!wl)
		return -ENODEV;

	pci_set_drvdata(pdev, wl);

	return 0;
}

static int
wl_suspend(struct pci_dev *pdev, DRV_SUSPEND_STATE_TYPE state)
{
	wl_info_t *wl = (wl_info_t *) pci_get_drvdata(pdev);

	WL_TRACE(("wl: wl_suspend\n"));

	wl = (wl_info_t *) pci_get_drvdata(pdev);
	if (!wl) {
		WL_ERROR(("wl: wl_suspend: pci_get_drvdata failed\n"));
		return -ENODEV;
	}

	WL_LOCK(wl);
	WL_APSTA_UPDN(("wl%d (%s): wl_suspend() -> wl_down()\n", wl->pub->unit, wl->dev->name));
	wl_down(wl);
	wl->pub->hw_up = FALSE;
	WL_UNLOCK(wl);
	PCI_SAVE_STATE(pdev, wl->pci_psstate);
	pci_disable_device(pdev);
	return pci_set_power_state(pdev, PCI_D3hot);
}

static int
wl_resume(struct pci_dev *pdev)
{
	wl_info_t *wl = (wl_info_t *) pci_get_drvdata(pdev);
	int err = 0;
	uint32 val;

	WL_TRACE(("wl: wl_resume\n"));

	if (!wl) {
		WL_ERROR(("wl: wl_resume: pci_get_drvdata failed\n"));
	        return -ENODEV;
	}

	err = pci_set_power_state(pdev, PCI_D0);
	if (err)
		return err;

	PCI_RESTORE_STATE(pdev, wl->pci_psstate);

	err = pci_enable_device(pdev);
	if (err)
		return err;

	pci_set_master(pdev);

	pci_read_config_dword(pdev, 0x40, &val);
	if ((val & 0x0000ff00) != 0)
		pci_write_config_dword(pdev, 0x40, val & 0xffff00ff);

	WL_LOCK(wl);
	WL_APSTA_UPDN(("wl%d: (%s): wl_resume() -> wl_up()\n", wl->pub->unit, wl->dev->name));
	err = wl_up(wl);
	WL_UNLOCK(wl);

	return (err);
}

static void __devexit
wl_remove(struct pci_dev *pdev)
{
	wl_info_t *wl = (wl_info_t *) pci_get_drvdata(pdev);

	if (!wl) {
		WL_ERROR(("wl: wl_remove: pci_get_drvdata failed\n"));
		return;
	}
	if (!wlc_chipmatch(pdev->vendor, pdev->device)) {
		WL_ERROR(("wl: wl_remove: wlc_chipmatch failed\n"));
		return;
	}

	WL_LOCK(wl);
	WL_APSTA_UPDN(("wl%d (%s): wl_remove() -> wl_down()\n", wl->pub->unit, wl->dev->name));
	wl_down(wl);
	WL_UNLOCK(wl);

	wl_free(wl);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
}

static struct pci_driver wl_pci_driver = {
	name:		"wl",
	probe:		wl_pci_probe,
	suspend:	wl_suspend,
	resume:		wl_resume,
	remove:		__devexit_p(wl_remove),
	id_table:	wl_id_table,
	};

#define	wl_read_nvram_file() do {} while (0)

#define usbap_parse_nvram()	do {} while (0)

static int __init
wl_module_init(void)
{
	int error = -ENODEV;

#ifdef BCMDBG
	if (msglevel != 0xdeadbeef)
		wl_msg_level = msglevel;
	else {
		char *var = getvar(NULL, "wl_msglevel");
		if (var)
			wl_msg_level = bcm_strtoul(var, NULL, 0);
	}
	printf("%s: msglevel set to 0x%x\n", __FUNCTION__, wl_msg_level);
	if (msglevel2 != 0xdeadbeef)
		wl_msg_level2 = msglevel2;
	else {
		char *var = getvar(NULL, "wl_msglevel2");
		if (var)
			wl_msg_level2 = bcm_strtoul(var, NULL, 0);
	}
	printf("%s: msglevel2 set to 0x%x\n", __FUNCTION__, wl_msg_level2);
	{
		extern uint32 phyhal_msg_level;

		if (phymsglevel != 0xdeadbeef)
			phyhal_msg_level = phymsglevel;
		else {
			char *var = getvar(NULL, "phy_msglevel");
			if (var)
				phyhal_msg_level = bcm_strtoul(var, NULL, 0);
		}
		printf("%s: phymsglevel set to 0x%x\n", __FUNCTION__, phyhal_msg_level);
	}
#if defined(WL_ALL_PASSIVE)
	{
		char *var = getvar(NULL, "wl_dispatch_mode");
		if (var)
			passivemode = bcm_strtoul(var, NULL, 0);
		printf("%s: dhssivemode set to 0x%x\n", __FUNCTION__, passivemode);
	}
#endif 
#endif 

	if (!(error = pci_module_init(&wl_pci_driver)))
		return (0);

	return (error);
}

static void __exit
wl_module_exit(void)
{

	pci_unregister_driver(&wl_pci_driver);

}

module_init(wl_module_init);
module_exit(wl_module_exit);

void
wl_free(wl_info_t *wl)
{
	wl_timer_t *t, *next;
	osl_t *osh;

	WL_TRACE(("wl: wl_free\n"));
	{
		if (wl->dev && wl->dev->irq)
			free_irq(wl->dev->irq, wl);
	}

#if defined(WL_CONFIG_RFKILL)
	wl_uninit_rfkill(wl);
#endif

#ifdef NAPI_POLL
	clear_bit(__LINK_STATE_START, &wl->dev->state);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
	napi_disable(&wl->napi);
#elif  LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 21)
	netif_poll_disable(wl->dev);
#endif 	
#endif 

	if (wl->dev) {
		wl_free_if(wl, WL_DEV_IF(wl->dev));
		wl->dev = NULL;
	}

#ifndef NAPI_POLL

	tasklet_kill(&wl->tasklet);
#endif
	if (wl->pub) {
		wlc_module_unregister(wl->pub, "linux", wl);
	}

	if (wl->wlc) {

		{
		char tmp1[128];
		sprintf(tmp1, "%s%d", HYBRID_PROC, wl->pub->unit);
		remove_proc_entry(tmp1, 0);
		}

		wlc_detach(wl->wlc);
		wl->wlc = NULL;
		wl->pub = NULL;
	}

	while (atomic_read(&wl->callbacks) > 0)
		schedule();

	for (t = wl->timers; t; t = next) {
		next = t->next;
#ifdef BCMDBG
		if (t->name)
			MFREE(wl->osh, t->name, strlen(t->name) + 1);
#endif
		MFREE(wl->osh, t, sizeof(wl_timer_t));
	}

	if (wl->monitor_dev) {
		wl_free_if(wl, WL_DEV_IF(wl->monitor_dev));
		wl->monitor_dev = NULL;
	}

	osh = wl->osh;

	if (wl->regsva && BUSTYPE(wl->bcm_bustype) != SDIO_BUS &&
	    BUSTYPE(wl->bcm_bustype) != JTAG_BUS) {
		iounmap((void*)wl->regsva);
	}
	wl->regsva = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 14)

	if (wl->tkipmodops != NULL) {
		int idx;
		if (wl->tkip_ucast_data) {
			wl->tkipmodops->deinit(wl->tkip_ucast_data);
			wl->tkip_ucast_data = NULL;
		}
		for (idx = 0; idx < NUM_GROUP_KEYS; idx++) {
			if (wl->tkip_bcast_data[idx]) {
				wl->tkipmodops->deinit(wl->tkip_bcast_data[idx]);
				wl->tkip_bcast_data[idx] = NULL;
			}
		}
	}
#endif 

#ifdef WL_ALL_PASSIVE
	if (WL_ALL_PASSIVE_ENAB(wl))
		wl_txq_free(wl);
#endif 

	MFREE(osh, wl, sizeof(wl_info_t));

	if (MALLOCED(osh)) {
		printf("Memory leak of bytes %d\n", MALLOCED(osh));
		ASSERT(0);
	}

	osl_detach(osh);
}

static int
wl_open(struct net_device *dev)
{
	wl_info_t *wl;
	int error = 0;

	if (!dev)
		return -ENETDOWN;

	wl = WL_INFO(dev);

	WL_TRACE(("wl%d: wl_open\n", wl->pub->unit));

	WL_LOCK(wl);
	WL_APSTA_UPDN(("wl%d: (%s): wl_open() -> wl_up()\n",
	               wl->pub->unit, wl->dev->name));

	error = wl_up(wl);
	if (!error) {
		error = wlc_set(wl->wlc, WLC_SET_PROMISC, (dev->flags & IFF_PROMISC));
	}
	WL_UNLOCK(wl);

	if (!error)
		OLD_MOD_INC_USE_COUNT;

#if defined(USE_CFG80211)
	if (wl_cfg80211_up(dev)) {
		WL_ERROR(("%s: failed to bring up cfg80211\n", __func__));
		return -1;
	}
#endif

	return (error? -ENODEV: 0);
}

static int
wl_close(struct net_device *dev)
{
	wl_info_t *wl;

	if (!dev)
		return -ENETDOWN;

#if defined(USE_CFG80211)
	wl_cfg80211_down(dev);
#endif

	wl = WL_INFO(dev);

	WL_TRACE(("wl%d: wl_close\n", wl->pub->unit));

	WL_LOCK(wl);
	WL_APSTA_UPDN(("wl%d (%s): wl_close() -> wl_down()\n",
		wl->pub->unit, wl->dev->name));
	wl_down(wl);
	WL_UNLOCK(wl);

	OLD_MOD_DEC_USE_COUNT;

	return (0);
}

static int BCMFASTPATH
wl_start_int(wl_info_t *wl, wl_if_t *wlif, struct sk_buff *skb)
{
	void *pkt;

	WL_TRACE(("wl%d: wl_start: len %d summed %d\n", wl->pub->unit, skb->len, skb->ip_summed));

	WL_LOCK(wl);

	if ((pkt = PKTFRMNATIVE(wl->osh, skb)) == NULL) {
		WL_ERROR(("wl%d: PKTFRMNATIVE failed!\n", wl->pub->unit));
		WLCNTINCR(wl->pub->_cnt->txnobuf);
		PKTFREE(wl->osh, skb, TRUE);
		WL_UNLOCK(wl);
		return 0;
	}

	if (WME_ENAB(wl->pub) && (PKTPRIO(pkt) == 0))
		pktsetprio(pkt, FALSE);

	wlc_sendpkt(wl->wlc, pkt, wlif->wlcif);

	WL_UNLOCK(wl);

	return (0);
}

void
wl_txflowcontrol(wl_info_t *wl, struct wl_if *wlif, bool state, int prio)
{
	struct net_device *dev;

	ASSERT(prio == ALLPRIO);

	if (wlif == NULL)
		dev = wl->dev;
	else
		dev = wlif->dev;

	if (state == ON)
		netif_stop_queue(dev);
	else
		netif_wake_queue(dev);
}

static int
wl_schedule_task(wl_info_t *wl, void (*fn)(struct wl_task *task), void *context)
{
	wl_task_t *task;

	WL_TRACE(("wl%d: wl_schedule_task\n", wl->pub->unit));

	if (!(task = MALLOC(wl->osh, sizeof(wl_task_t)))) {
		WL_ERROR(("wl%d: wl_schedule_task: out of memory, malloced %d bytes\n",
			wl->pub->unit, MALLOCED(wl->osh)));
		return -ENOMEM;
	}

	MY_INIT_WORK(&task->work, (work_func_t)fn);
	task->context = context;

	if (!schedule_work(&task->work)) {
		WL_ERROR(("wl%d: schedule_work() failed\n", wl->pub->unit));
		MFREE(wl->osh, task, sizeof(wl_task_t));
		return -ENOMEM;
	}

	atomic_inc(&wl->callbacks);

	return 0;
}

static struct wl_if *
wl_alloc_if(wl_info_t *wl, int iftype, uint subunit, struct wlc_if* wlcif)
{
	struct net_device *dev;
	wl_if_t *wlif;
	wl_if_t *p;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29))
	if (!(wlif = MALLOC(wl->osh, sizeof(wl_if_t)))) {
		WL_ERROR(("wl%d: wl_alloc_if: out of memory, malloced %d bytes\n",
		          (wl->pub)?wl->pub->unit:subunit, MALLOCED(wl->osh)));
		return NULL;
	}
	bzero(wlif, sizeof(wl_if_t));
#endif 

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24))
	if (!(dev = MALLOC(wl->osh, sizeof(struct net_device)))) {
		MFREE(wl->osh, wlif, sizeof(wl_if_t));
		WL_ERROR(("wl%d: wl_alloc_if: out of memory, malloced %d bytes\n",
		          (wl->pub)?wl->pub->unit:subunit, MALLOCED(wl->osh)));
		return NULL;
	}
	bzero(dev, sizeof(struct net_device));
	ether_setup(dev);
	strncpy(dev->name, name, IFNAMSIZ);
#else
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29))

	dev = alloc_netdev(sizeof(wl_if_t), name, ether_setup);
	wlif = netdev_priv(dev);
	if (!dev) {
#else
	dev = alloc_netdev(0, name, ether_setup);
	if (!dev) {
		MFREE(wl->osh, wlif, sizeof(wl_if_t));
#endif 
		WL_ERROR(("wl%d: wl_alloc_if: out of memory, alloc_netdev\n",
			(wl->pub)?wl->pub->unit:subunit));
		return NULL;
	}
#endif 

	wlif->dev = dev;
	wlif->wl = wl;
	wlif->wlcif = wlcif;
	wlif->subunit = subunit;
	wlif->if_type = iftype;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
	dev->priv = wlif;
#endif

	if (iftype != WL_IFTYPE_MON && wl->dev && netif_queue_stopped(wl->dev))
		netif_stop_queue(dev);

	if (wl->if_list == NULL)
		wl->if_list = wlif;
	else {
		p = wl->if_list;
		while (p->next != NULL)
			p = p->next;
		p->next = wlif;
	}
	return wlif;
}

static void
wl_free_if(wl_info_t *wl, wl_if_t *wlif)
{
	wl_if_t *p;

	if (wlif->dev_registed) {
		unregister_netdev(wlif->dev);
	}

#if defined(USE_CFG80211)
	if (wlif->if_type != WL_IFTYPE_MON)
		wl_cfg80211_detach(wlif->dev);
#endif

	p = wl->if_list;
	if (p == wlif)
		wl->if_list = p->next;
	else {
		while (p != NULL && p->next != wlif)
			p = p->next;
		if (p != NULL)
			p->next = p->next->next;
	}

	if (wlif->dev) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24))
		MFREE(wl->osh, wlif->dev, sizeof(struct net_device));
#else
		free_netdev(wlif->dev);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29))
		return;
#endif	
#endif	
	}
	MFREE(wl->osh, wlif, sizeof(wl_if_t));
}

char *
wl_ifname(wl_info_t *wl, wl_if_t *wlif)
{
	if (wlif)
		return wlif->dev->name;
	else
		return wl->dev->name;
}

void
wl_init(wl_info_t *wl)
{
	WL_TRACE(("wl%d: wl_init\n", wl->pub->unit));

	wl_reset(wl);

	wlc_init(wl->wlc);
}

uint
wl_reset(wl_info_t *wl)
{
	WL_TRACE(("wl%d: wl_reset\n", wl->pub->unit));

	wlc_reset(wl->wlc);

	wl->resched = 0;

	return (0);
}

void BCMFASTPATH
wl_intrson(wl_info_t *wl)
{
	unsigned long flags = 0;

	INT_LOCK(wl, flags);
	wlc_intrson(wl->wlc);
	INT_UNLOCK(wl, flags);
}

bool
wl_alloc_dma_resources(wl_info_t *wl, uint addrwidth)
{
	return TRUE;
}

uint32 BCMFASTPATH
wl_intrsoff(wl_info_t *wl)
{
	unsigned long flags = 0;
	uint32 status;

	INT_LOCK(wl, flags);
	status = wlc_intrsoff(wl->wlc);
	INT_UNLOCK(wl, flags);
	return status;
}

void
wl_intrsrestore(wl_info_t *wl, uint32 macintmask)
{
	unsigned long flags = 0;

	INT_LOCK(wl, flags);
	wlc_intrsrestore(wl->wlc, macintmask);
	INT_UNLOCK(wl, flags);
}

int
wl_up(wl_info_t *wl)
{
	int error = 0;

	WL_TRACE(("wl%d: wl_up\n", wl->pub->unit));

	if (wl->pub->up)
		return (0);

	error = wlc_up(wl->wlc);

	if (!error) {
		wl_if_t *wlif;

		for (wlif = wl->if_list; wlif != NULL; wlif = wlif->next) {
			wl_txflowcontrol(wl, wlif, OFF, ALLPRIO);
		}
	}

#ifdef NAPI_POLL
	set_bit(__LINK_STATE_START, &wl->dev->state);
#endif 

	return (error);
}

void
wl_down(wl_info_t *wl)
{
	wl_if_t *wlif;
	int monitor = 0;
	uint callbacks, ret_val = 0;

	WL_TRACE(("wl%d: wl_down\n", wl->pub->unit));

	for (wlif = wl->if_list; wlif != NULL; wlif = wlif->next) {
		netif_down(wlif->dev);
		netif_stop_queue(wlif->dev);
	}

	if (wl->monitor_dev) {
		ret_val = wlc_ioctl(wl->wlc, WLC_SET_MONITOR, &monitor, sizeof(int), NULL);
		if (ret_val != BCME_OK) {
			WL_ERROR(("%s: Disabling MONITOR failed %d\n", __FUNCTION__, ret_val));
		}
	}

	ret_val = wlc_down(wl->wlc);
	callbacks = atomic_read(&wl->callbacks) - ret_val;

	WL_UNLOCK(wl);

#ifdef WL_ALL_PASSIVE
	if (WL_ALL_PASSIVE_ENAB(wl)) {
		int i = 0;
		for (i = 0; (atomic_read(&wl->callbacks) > callbacks) && i < 10000; i++) {
			schedule();
			flush_scheduled_work();
		}
	}
	else
#endif 
	{

		SPINWAIT((atomic_read(&wl->callbacks) > callbacks), 100 * 1000);
	}

	WL_LOCK(wl);
}

static int
wl_toe_get(wl_info_t *wl, uint32 *toe_ol)
{
	if (wlc_iovar_getint(wl->wlc, "toe_ol", toe_ol) != 0)
		return -EOPNOTSUPP;

	return 0;
}

static int
wl_toe_set(wl_info_t *wl, uint32 toe_ol)
{
	if (wlc_iovar_setint(wl->wlc, "toe_ol", toe_ol) != 0)
		return -EOPNOTSUPP;

	if (wlc_iovar_setint(wl->wlc, "toe", (toe_ol != 0)) != 0)
		return -EOPNOTSUPP;

	return 0;
}

static void
wl_get_driver_info(struct net_device *dev, struct ethtool_drvinfo *info)
{
	wl_info_t *wl = WL_INFO(dev);
	bzero(info, sizeof(struct ethtool_drvinfo));
	sprintf(info->driver, "wl%d", wl->pub->unit);
	strcpy(info->version, EPI_VERSION_STR);
}

static int
wl_ethtool(wl_info_t *wl, void *uaddr, wl_if_t *wlif)
{
	struct ethtool_drvinfo info;
	struct ethtool_value edata;
	uint32 cmd;
	uint32 toe_cmpnt = 0, csum_dir;
	int ret;

	if (!wl || !wl->pub || !wl->wlc)
		return -ENODEV;

	WL_TRACE(("wl%d: %s\n", wl->pub->unit, __FUNCTION__));
	if (copy_from_user(&cmd, uaddr, sizeof(uint32)))
		return (-EFAULT);

	switch (cmd) {
	case ETHTOOL_GDRVINFO:
		if (!wl->dev)
			return -ENETDOWN;

		wl_get_driver_info(wl->dev, &info);
		info.cmd = cmd;
		if (copy_to_user(uaddr, &info, sizeof(info)))
			return (-EFAULT);
		break;

	case ETHTOOL_GRXCSUM:
	case ETHTOOL_GTXCSUM:
		if ((ret = wl_toe_get(wl, &toe_cmpnt)) < 0)
			return ret;

		csum_dir = (cmd == ETHTOOL_GTXCSUM) ? TOE_TX_CSUM_OL : TOE_RX_CSUM_OL;

		edata.cmd = cmd;
		edata.data = (toe_cmpnt & csum_dir) ? 1 : 0;

		if (copy_to_user(uaddr, &edata, sizeof(edata)))
			return (-EFAULT);
		break;

	case ETHTOOL_SRXCSUM:
	case ETHTOOL_STXCSUM:
		if (copy_from_user(&edata, uaddr, sizeof(edata)))
			return (-EFAULT);

		if ((ret = wl_toe_get(wl, &toe_cmpnt)) < 0)
			return ret;

		csum_dir = (cmd == ETHTOOL_STXCSUM) ? TOE_TX_CSUM_OL : TOE_RX_CSUM_OL;

		if (edata.data != 0)
			toe_cmpnt |= csum_dir;
		else
			toe_cmpnt &= ~csum_dir;

		if ((ret = wl_toe_set(wl, toe_cmpnt)) < 0)
			return ret;

		if (cmd == ETHTOOL_STXCSUM) {
			if (!wl->dev)
				return -ENETDOWN;
			if (edata.data)
				wl->dev->features |= NETIF_F_IP_CSUM;
			else
				wl->dev->features &= ~NETIF_F_IP_CSUM;
		}

		break;

	default:
		return (-EOPNOTSUPP);

	}

	return (0);
}

int
wl_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	wl_info_t *wl;
	wl_if_t *wlif;
	void *buf = NULL;
	wl_ioctl_t ioc;
	int bcmerror;

	if (!dev)
		return -ENETDOWN;

	wl = WL_INFO(dev);
	wlif = WL_DEV_IF(dev);
	if (wlif == NULL || wl == NULL)
		return -ENETDOWN;

	bcmerror = 0;

	WL_TRACE(("wl%d: wl_ioctl: cmd 0x%x\n", wl->pub->unit, cmd));

#ifdef CONFIG_PREEMPT
	if (preempt_count())
		WL_ERROR(("wl%d: wl_ioctl: cmd = 0x%x, preempt_count=%d\n",
			wl->pub->unit, cmd, preempt_count()));
#endif

#ifdef USE_IW

	if ((cmd >= SIOCIWFIRST) && (cmd <= SIOCIWLAST)) {

		return wl_iw_ioctl(dev, ifr, cmd);
	}
#endif 

	if (cmd == SIOCETHTOOL)
		return (wl_ethtool(wl, (void*)ifr->ifr_data, wlif));

	switch (cmd) {
		case SIOCDEVPRIVATE :
			break;
		default:
			bcmerror = BCME_UNSUPPORTED;
			goto done2;
	}

	if (copy_from_user(&ioc, ifr->ifr_data, sizeof(wl_ioctl_t))) {
		bcmerror = BCME_BADADDR;
		goto done2;
	}

	if (segment_eq(get_fs(), KERNEL_DS))
		buf = ioc.buf;

	else if (ioc.buf) {
		if (!(buf = (void *) MALLOC(wl->osh, MAX(ioc.len, WLC_IOCTL_MAXLEN)))) {
			bcmerror = BCME_NORESOURCE;
			goto done2;
		}

		if (copy_from_user(buf, ioc.buf, ioc.len)) {
			bcmerror = BCME_BADADDR;
			goto done1;
		}
	}

	WL_LOCK(wl);
	if (!capable(CAP_NET_ADMIN)) {
		bcmerror = BCME_EPERM;
	} else {
		bcmerror = wlc_ioctl(wl->wlc, ioc.cmd, buf, ioc.len, wlif->wlcif);
	}
	WL_UNLOCK(wl);

done1:
	if (ioc.buf && (ioc.buf != buf)) {
		if (copy_to_user(ioc.buf, buf, ioc.len))
			bcmerror = BCME_BADADDR;
		MFREE(wl->osh, buf, MAX(ioc.len, WLC_IOCTL_MAXLEN));
	}

done2:
	ASSERT(VALID_BCMERROR(bcmerror));
	if (bcmerror != 0)
		wl->pub->bcmerror = bcmerror;
	return (OSL_ERROR(bcmerror));
}

static struct net_device_stats*
wl_get_stats(struct net_device *dev)
{
	struct net_device_stats *stats_watchdog = NULL;
	struct net_device_stats *stats = NULL;
	wl_info_t *wl;

	if (!dev)
		return NULL;

	if ((wl = WL_INFO(dev)) == NULL)
		return NULL;

	if (!(wl->pub))
		return NULL;

	WL_TRACE(("wl%d: wl_get_stats\n", wl->pub->unit));

	if ((stats = &wl->stats) == NULL)
		return NULL;

	ASSERT(wl->stats_id < 2);
	stats_watchdog = &wl->stats_watchdog[wl->stats_id];

	memcpy(stats, stats_watchdog, sizeof(struct net_device_stats));
	return (stats);
}

#ifdef USE_IW
struct iw_statistics *
wl_get_wireless_stats(struct net_device *dev)
{
	int res = 0;
	wl_info_t *wl;
	wl_if_t *wlif;
	struct iw_statistics *wstats = NULL;
	struct iw_statistics *wstats_watchdog = NULL;
	int phy_noise, rssi;

	if (!dev)
		return NULL;

	wl = WL_INFO(dev);
	wlif = WL_DEV_IF(dev);

	WL_TRACE(("wl%d: wl_get_wireless_stats\n", wl->pub->unit));

	wstats = &wl->wstats;
	ASSERT(wl->stats_id < 2);
	wstats_watchdog = &wl->wstats_watchdog[wl->stats_id];

	phy_noise = wl->phy_noise;
#if WIRELESS_EXT > 11
	wstats->discard.nwid = 0;
	wstats->discard.code = wstats_watchdog->discard.code;
	wstats->discard.fragment = wstats_watchdog->discard.fragment;
	wstats->discard.retries = wstats_watchdog->discard.retries;
	wstats->discard.misc = wstats_watchdog->discard.misc;

	wstats->miss.beacon = 0;
#endif 

	if (AP_ENAB(wl->pub))
		rssi = 0;
	else {
		scb_val_t scb;
		res = wlc_ioctl(wl->wlc, WLC_GET_RSSI, &scb, sizeof(int), wlif->wlcif);
		if (res) {
			WL_ERROR(("wl%d: %s: WLC_GET_RSSI failed (%d)\n",
				wl->pub->unit, __FUNCTION__, res));
			return NULL;
		}
		rssi = scb.val;
	}

	if (rssi <= WLC_RSSI_NO_SIGNAL)
		wstats->qual.qual = 0;
	else if (rssi <= WLC_RSSI_VERY_LOW)
		wstats->qual.qual = 1;
	else if (rssi <= WLC_RSSI_LOW)
		wstats->qual.qual = 2;
	else if (rssi <= WLC_RSSI_GOOD)
		wstats->qual.qual = 3;
	else if (rssi <= WLC_RSSI_VERY_GOOD)
		wstats->qual.qual = 4;
	else
		wstats->qual.qual = 5;

	wstats->qual.level = 0x100 + rssi;
	wstats->qual.noise = 0x100 + phy_noise;
#if WIRELESS_EXT > 18
	wstats->qual.updated |= (IW_QUAL_ALL_UPDATED | IW_QUAL_DBM);
#else
	wstats->qual.updated |= 7;
#endif 

	return wstats;
}
#endif 

static int
wl_set_mac_address(struct net_device *dev, void *addr)
{
	int err = 0;
	wl_info_t *wl;
	struct sockaddr *sa = (struct sockaddr *) addr;

	if (!dev)
		return -ENETDOWN;

	wl = WL_INFO(dev);

	WL_TRACE(("wl%d: wl_set_mac_address\n", wl->pub->unit));

	WL_LOCK(wl);

	bcopy(sa->sa_data, dev->dev_addr, ETHER_ADDR_LEN);
	err = wlc_iovar_op(wl->wlc, "cur_etheraddr", NULL, 0, sa->sa_data, ETHER_ADDR_LEN,
		IOV_SET, (WL_DEV_IF(dev))->wlcif);
	WL_UNLOCK(wl);
	if (err)
		WL_ERROR(("wl%d: wl_set_mac_address: error setting MAC addr override\n",
			wl->pub->unit));
	return err;
}

static void
wl_set_multicast_list(struct net_device *dev)
{
	if (!WL_ALL_PASSIVE_ENAB((wl_info_t *)WL_INFO(dev)))
		_wl_set_multicast_list(dev);
#ifdef WL_ALL_PASSIVE
	else {
		wl_info_t *wl = WL_INFO(dev);
		wl->multicast_task.context = dev;

		if (schedule_work(&wl->multicast_task.work)) {

			atomic_inc(&wl->callbacks);
		}
	}
#endif 
}

static void
_wl_set_multicast_list(struct net_device *dev)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 34)
	struct dev_mc_list *mclist;
#else
	struct netdev_hw_addr   *ha;
	int num;
#endif
	wl_info_t *wl;
	int i, buflen;
	struct maclist *maclist;
	bool allmulti;

	if (!dev)
		return;
	wl = WL_INFO(dev);

	WL_TRACE(("wl%d: wl_set_multicast_list\n", wl->pub->unit));

	if (wl->pub->up) {
		allmulti = (dev->flags & IFF_ALLMULTI)? TRUE: FALSE;

		buflen = sizeof(struct maclist) + (MAXMULTILIST * ETHER_ADDR_LEN);

		if ((maclist = MALLOC(wl->pub->osh, buflen)) == NULL) {
			return;
		}

		i = 0;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 34)
		for (mclist = dev->mc_list; mclist && (i < dev->mc_count); mclist = mclist->next) {
			if (i >= MAXMULTILIST) {
				allmulti = TRUE;
				i = 0;
				break;
			}
			bcopy(mclist->dmi_addr, &maclist->ea[i++], ETHER_ADDR_LEN);
		}
#else
		num = min_t(int, netdev_mc_count(dev), MAXMULTILIST);
		netdev_for_each_mc_addr(ha, dev) {
			if (i >= num) {
				allmulti = TRUE;
				i = 0;
				break;
			}
			bcopy(ha->addr,  &maclist->ea[i++], ETHER_ADDR_LEN);
		}
#endif 
		maclist->count = i;

		WL_LOCK(wl);

		wlc_iovar_setint(wl->wlc, "allmulti", allmulti);
		wlc_set(wl->wlc, WLC_SET_PROMISC, (dev->flags & IFF_PROMISC));

		wlc_iovar_op(wl->wlc, "mcast_list", NULL, 0, maclist, buflen, IOV_SET, NULL);

		WL_UNLOCK(wl);
		MFREE(wl->pub->osh, maclist, buflen);
	}

}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20)
irqreturn_t BCMFASTPATH
wl_isr(int irq, void *dev_id)
#else
irqreturn_t BCMFASTPATH
wl_isr(int irq, void *dev_id, struct pt_regs *ptregs)
#endif 
{
	wl_info_t *wl;
	bool ours, wantdpc;
	unsigned long flags;

	wl = (wl_info_t*) dev_id;

	WL_ISRLOCK(wl, flags);

	if ((ours = wlc_isr(wl->wlc, &wantdpc))) {

		if (wantdpc) {

			ASSERT(wl->resched == FALSE);
#ifdef NAPI_POLL

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
			napi_schedule(&wl->napi);
#else
			netif_rx_schedule(wl->dev);
#endif 
#else 
#ifdef WL_ALL_PASSIVE
			if (WL_ALL_PASSIVE_ENAB(wl)) {
				if (schedule_work(&wl->wl_dpc_task.work))
					atomic_inc(&wl->callbacks);
				else
					ASSERT(0);
			} else
#endif 
			tasklet_schedule(&wl->tasklet);
#endif 
		}
	}

	WL_ISRUNLOCK(wl, flags);

	return IRQ_RETVAL(ours);
}

#ifdef NAPI_POLL
static int BCMFASTPATH
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
wl_poll(struct napi_struct *napi, int budget)
#else
wl_poll(struct net_device *dev, int *budget)
#endif 
#else 
static void BCMFASTPATH
wl_dpc(ulong data)
#endif 
{
	wl_info_t *wl;

#ifdef NAPI_POLL
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
	wl = (wl_info_t *)container_of(napi, wl_info_t, napi);
	wl->pub->tunables->rxbnd = min(RXBND, budget);
#else
	wl = WL_INFO(dev);
	wl->pub->tunables->rxbnd = min(RXBND, *budget);
	ASSERT(wl->pub->tunables->rxbnd <= dev->quota);
#endif 	
#else 

	wl = (wl_info_t *)data;

	WL_LOCK(wl);
#endif 

	if (wl->pub->up) {
		if (wl->resched) {
			unsigned long flags = 0;
			INT_LOCK(wl, flags);
			wlc_intrsupd(wl->wlc);
			INT_UNLOCK(wl, flags);
		}

		wl->resched = wlc_dpc(wl->wlc, TRUE);
	}

	if (!wl->pub->up) {
#ifdef WL_ALL_PASSIVE

		if ((WL_ALL_PASSIVE_ENAB(wl))) {
			atomic_dec(&wl->callbacks);
		}
#endif 
		goto done;
	}

#ifndef NAPI_POLL
#ifdef WL_ALL_PASSIVE
	if (wl->resched) {
		if (!(WL_ALL_PASSIVE_ENAB(wl)))
			tasklet_schedule(&wl->tasklet);
		else
			if (!schedule_work(&wl->wl_dpc_task.work))

				ASSERT(0);
	}
	else {

		if (WL_ALL_PASSIVE_ENAB(wl))
			atomic_dec(&wl->callbacks);
		wl_intrson(wl);
	}
#else 
	if (wl->resched)
		tasklet_schedule(&wl->tasklet);
	else {

		wl_intrson(wl);
	}
#endif 

done:
	WL_UNLOCK(wl);
	return;
#else 

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
	WL_TRACE(("wl%d: wl_poll: rxbnd %d budget %d processed %d\n",
		wl->pub->unit, wl->pub->rxbnd, budget, wl->pub->processed));

	ASSERT(wl->pub->processed <= wl->pub->tunables->rxbnd);

	if (!wl->resched) {
		napi_complete(&wl->napi);

		wl_intrson(wl);
	}
	return wl->pub->processed;
done:
	return 0;

#else 
	WL_TRACE(("wl%d: wl_poll: rxbnd %d quota %d budget %d processed %d\n",
	          wl->pub->unit, wl->pub->rxbnd, dev->quota,
	          *budget, wl->pub->processed));

	ASSERT(wl->pub->processed <= wl->pub->tunables->rxbnd);

	*budget -= wl->pub->processed;
	dev->quota -= wl->pub->processed;

	if (wl->resched)

		return 1;

	netif_rx_complete(dev);

	wl_intrson(wl);
done:
	return 0;
#endif 
#endif 
}

#if defined(WL_ALL_PASSIVE)
static void
wl_dpc_rxwork(struct wl_task *task)
{
	wl_info_t *wl = (wl_info_t *)task->context;
	WL_TRACE(("wl%d: %s\n", wl->pub->unit, __FUNCTION__));

	wl_dpc((unsigned long)wl);
	return;
}
#endif 

static inline int32
wl_ctf_forward(wl_info_t *wl, struct sk_buff *skb)
{

	return (BCME_ERROR);
}

void BCMFASTPATH
wl_sendup(wl_info_t *wl, wl_if_t *wlif, void *p, int numpkt)
{
	struct sk_buff *skb;

	WL_TRACE(("wl%d: wl_sendup: %d bytes\n", wl->pub->unit, PKTLEN(wl->osh, p)));

	if (wlif) {

		if (!netif_device_present(wlif->dev)) {
			WL_ERROR(("wl%d: wl_sendup: interface not ready\n", wl->pub->unit));
			PKTFREE(wl->osh, p, FALSE);
			return;
		}

		skb = PKTTONATIVE(wl->osh, p);
		skb->dev = wlif->dev;
	} else {

		skb = PKTTONATIVE(wl->osh, p);
		skb->dev = wl->dev;
	}

	skb->protocol = eth_type_trans(skb, skb->dev);
	if (!ISALIGNED((uintptr)skb->data, 4)) {
		WL_ERROR(("Unaligned assert. skb %p. skb->data %p.\n", skb, skb->data));
		if (wlif) {
			WL_ERROR(("wl_sendup: dev name is %s (wlif) \n", wlif->dev->name));
			WL_ERROR(("wl_sendup: hard header len  %d (wlif) \n",
				wlif->dev->hard_header_len));
		}
		WL_ERROR(("wl_sendup: dev name is %s (wl) \n", wl->dev->name));
		WL_ERROR(("wl_sendup: hard header len %d (wl) \n", wl->dev->hard_header_len));
		ASSERT(ISALIGNED((uintptr)skb->data, 4));
	}

	WL_APSTA_RX(("wl%d: wl_sendup(): pkt %p summed %d on interface %p (%s)\n",
		wl->pub->unit, p, skb->ip_summed, wlif, skb->dev->name));

#ifdef NAPI_POLL
	netif_receive_skb(skb);
#else 
	netif_rx(skb);
#endif 
}

void
wl_dump_ver(wl_info_t *wl, struct bcmstrbuf *b)
{
	bcm_bprintf(b, "wl%d: %s %s version %s\n", wl->pub->unit,
		__DATE__, __TIME__, EPI_VERSION_STR);
}

#if defined(BCMDBG)
static int
wl_dump(wl_info_t *wl, struct bcmstrbuf *b)
{
	wl_if_t *p;
	int i;

	wl_dump_ver(wl, b);

	bcm_bprintf(b, "name %s dev %p tbusy %d callbacks %d malloced %d\n",
	       wl->dev->name, wl->dev, (uint)netif_queue_stopped(wl->dev),
	       atomic_read(&wl->callbacks), MALLOCED(wl->osh));

	p = wl->if_list;
	if (p)
		p = p->next;
	for (i = 0; p != NULL; p = p->next, i++) {
		if ((i % 4) == 0) {
			if (i != 0)
				bcm_bprintf(b, "\n");
			bcm_bprintf(b, "Interfaces:");
		}
		bcm_bprintf(b, " name %s dev %p", p->dev->name, p->dev);
	}
	if (i)
		bcm_bprintf(b, "\n");

	return 0;
}
#endif	

static void
wl_link_up(wl_info_t *wl, char *ifname)
{
	WL_ERROR(("wl%d: link up (%s)\n", wl->pub->unit, ifname));
}

static void
wl_link_down(wl_info_t *wl, char *ifname)
{
	WL_ERROR(("wl%d: link down (%s)\n", wl->pub->unit, ifname));
}

void
wl_event(wl_info_t *wl, char *ifname, wlc_event_t *e)
{
#ifdef USE_IW
	wl_iw_event(wl->dev, &(e->event), e->data);
#endif 

#if defined(USE_CFG80211)
	wl_cfg80211_event(wl->dev, &(e->event), e->data);
#endif

	switch (e->event.event_type) {
	case WLC_E_LINK:
	case WLC_E_NDIS_LINK:
		if (e->event.flags&WLC_EVENT_MSG_LINK)
			wl_link_up(wl, ifname);
		else
			wl_link_down(wl, ifname);
		break;
#if defined(WL_CONFIG_RFKILL)
	case WLC_E_RADIO: {
		mbool i;
		if (wlc_get(wl->wlc, WLC_GET_RADIO, &i) < 0)
			WL_ERROR(("%s: WLC_GET_RADIO failed\n", __FUNCTION__));
		if (wl->last_phyind == (mbool)(i & WL_RADIO_HW_DISABLE))
			break;

		wl->last_phyind = (mbool)(i & WL_RADIO_HW_DISABLE);

		WL_ERROR(("wl%d: Radio hardware state changed to %d\n", wl->pub->unit, i));
		wl_report_radio_state(wl);
		break;
	}
#else
	case WLC_E_RADIO:
		break;
#endif 
	}
}

void
wl_event_sync(wl_info_t *wl, char *ifname, wlc_event_t *e)
{
}

#ifndef WL_THREAD
static int BCMFASTPATH
wl_start(struct sk_buff *skb, struct net_device *dev)
{
	wl_if_t *wlif;
	wl_info_t *wl;

	if (!dev)
		return -ENETDOWN;

	wlif = WL_DEV_IF(dev);
	wl = WL_INFO(dev);

	if (!WL_ALL_PASSIVE_ENAB(wl))
		return wl_start_int(wl, wlif, skb);
#ifdef WL_ALL_PASSIVE
	else {
		skb->prev = NULL;

		TXQ_LOCK(wl);
		if (wl->txq_head == NULL)
			wl->txq_head = skb;
		else {
			wl->txq_tail->prev = skb;
		}
		wl->txq_tail = skb;

		if (wl->txq_dispatched == FALSE) {
			wl->txq_dispatched = TRUE;

			if (schedule_work(&wl->txq_task.work)) {
				atomic_inc(&wl->callbacks);
			} else {
				WL_ERROR(("wl%d: wl_start/schedule_work failed\n", wl->pub->unit));
				wl->txq_dispatched = FALSE;
			}
		}

		TXQ_UNLOCK(wl);
	}
#endif 

	return (0);
}
#endif 

#ifdef WL_ALL_PASSIVE
static void
wl_start_txqwork(struct wl_task *task)
{
	wl_info_t *wl = (wl_info_t *)task->context;
	struct sk_buff *skb;
	uint count = 0;

	WL_TRACE(("wl%d: wl_start_txqwork\n", wl->pub->unit));

	TXQ_LOCK(wl);
	while (wl->txq_head) {
		skb = wl->txq_head;
		wl->txq_head = skb->prev;
		skb->prev = NULL;
		if (wl->txq_head == NULL)
			wl->txq_tail = NULL;
		TXQ_UNLOCK(wl);

		wl_start_int(wl, WL_DEV_IF(skb->dev), skb);

		if (++count >= 10)
			break;

		TXQ_LOCK(wl);
	}

	if (count >= 10) {
		if (!schedule_work(&wl->txq_task.work)) {
			WL_ERROR(("wl%d: wl_start/schedule_work failed\n", wl->pub->unit));
			atomic_dec(&wl->callbacks);
		}
	} else {
		wl->txq_dispatched = FALSE;
		TXQ_UNLOCK(wl);
		atomic_dec(&wl->callbacks);
	}

	return;
}

static void
wl_txq_free(wl_info_t *wl)
{
	struct sk_buff *skb;

	if (wl->txq_head == NULL) {
		ASSERT(wl->txq_tail == NULL);
		return;
	}

	while (wl->txq_head) {
		skb = wl->txq_head;
		wl->txq_head = skb->prev;
		PKTFREE(wl->osh, skb, TRUE);
	}

	wl->txq_tail = NULL;
}
#endif 

#ifdef WL_ALL_PASSIVE
static void
wl_set_multicast_list_workitem(struct work_struct *work)
{
	wl_task_t *task = (wl_task_t *)work;
	struct net_device *dev = (struct net_device*)task->context;
	wl_info_t *wl;

	wl = WL_INFO(dev);

	atomic_dec(&wl->callbacks);

	_wl_set_multicast_list(dev);
}

static void
wl_timer_task(wl_task_t *task)
{
	wl_timer_t *t = (wl_timer_t *)task->context;

	_wl_timer(t);
	MFREE(t->wl->osh, task, sizeof(wl_task_t));

	atomic_dec(&t->wl->callbacks);
}
#endif 

static void
wl_timer(ulong data)
{
	wl_timer_t *t = (wl_timer_t *)data;

	if (!WL_ALL_PASSIVE_ENAB(t->wl))
		_wl_timer(t);
#ifdef WL_ALL_PASSIVE
	else
		wl_schedule_task(t->wl, wl_timer_task, t);
#endif 	
}

static void
_wl_timer(wl_timer_t *t)
{
	wl_info_t *wl = t->wl;

	WL_LOCK(wl);

	if (t->set && (!timer_pending(&t->timer))) {
		if (t->periodic) {
			t->timer.expires = jiffies + t->ms*HZ/1000;
			atomic_inc(&wl->callbacks);
			add_timer(&t->timer);
			t->set = TRUE;
		} else
			t->set = FALSE;

		t->fn(t->arg);
#ifdef BCMDBG
		wlc_update_perf_stats(wl->wlc, WLC_PERF_STATS_TMR_DPC);
		t->ticks++;
#endif

	}

	atomic_dec(&wl->callbacks);

	WL_UNLOCK(wl);
}

wl_timer_t *
wl_init_timer(wl_info_t *wl, void (*fn)(void *arg), void *arg, const char *name)
{
	wl_timer_t *t;

	t = (wl_timer_t*)MALLOC(wl->osh, sizeof(wl_timer_t));

	if (t == NULL) {
		WL_ERROR(("wl%d: wl_init_timer: out of memory, malloced %d bytes\n",
		          wl->unit, MALLOCED(wl->osh)));
		return 0;
	}

	bzero(t, sizeof(wl_timer_t));

	init_timer(&t->timer);
	t->timer.data = (ulong) t;
	t->timer.function = wl_timer;
	t->wl = wl;
	t->fn = fn;
	t->arg = arg;
	t->next = wl->timers;
	wl->timers = t;

#ifdef BCMDBG
	if ((t->name = MALLOC(wl->osh, strlen(name) + 1)))
		strcpy(t->name, name);
#endif

	return t;
}

void
wl_add_timer(wl_info_t *wl, wl_timer_t *t, uint ms, int periodic)
{
#ifdef BCMDBG
	if (t->set) {
		WL_ERROR(("%s: Already set. Name: %s, per %d\n",
			__FUNCTION__, t->name, periodic));
	}
#endif

	t->ms = ms;
	t->periodic = (bool) periodic;

	if (t->set)
		return;

	t->set = TRUE;
	t->timer.expires = jiffies + ms*HZ/1000;

	atomic_inc(&wl->callbacks);
	add_timer(&t->timer);
}

bool
wl_del_timer(wl_info_t *wl, wl_timer_t *t)
{
	ASSERT(t);
	if (t->set) {
		t->set = FALSE;
		if (!del_timer(&t->timer)) {
#ifdef BCMDBG
			WL_INFORM(("wl%d: Failed to delete timer %s\n", wl->unit, t->name));
#endif
			return FALSE;
		}
		atomic_dec(&wl->callbacks);
	}

	return TRUE;
}

void
wl_free_timer(wl_info_t *wl, wl_timer_t *t)
{
	wl_timer_t *tmp;

	wl_del_timer(wl, t);

	if (wl->timers == t) {
		wl->timers = wl->timers->next;
#ifdef BCMDBG
		if (t->name)
			MFREE(wl->osh, t->name, strlen(t->name) + 1);
#endif
		MFREE(wl->osh, t, sizeof(wl_timer_t));
		return;

	}

	tmp = wl->timers;
	while (tmp) {
		if (tmp->next == t) {
			tmp->next = t->next;
#ifdef BCMDBG
			if (t->name)
				MFREE(wl->osh, t->name, strlen(t->name) + 1);
#endif
			MFREE(wl->osh, t, sizeof(wl_timer_t));
			return;
		}
		tmp = tmp->next;
	}

}

void
wl_monitor(wl_info_t *wl, wl_rxsts_t *rxsts, void *p)
{
	struct sk_buff *oskb = (struct sk_buff *)p;
	struct sk_buff *skb;
	uchar *pdata;
	uint len;

	len = 0;
	skb = NULL;
	WL_TRACE(("wl%d: wl_monitor\n", wl->pub->unit));

	if (!wl->monitor_dev)
		return;

	if (wl->monitor_type == ARPHRD_IEEE80211_PRISM) {
		p80211msg_t *phdr;

		len = sizeof(p80211msg_t) + oskb->len - D11_PHY_HDR_LEN;
		if ((skb = dev_alloc_skb(len)) == NULL)
			return;

		skb_put(skb, len);
		phdr = (p80211msg_t*)skb->data;

		phdr->msgcode = WL_MON_FRAME;
		phdr->msglen = sizeof(p80211msg_t);
		strcpy(phdr->devname, wl->dev->name);

		phdr->hosttime.did = WL_MON_FRAME_HOSTTIME;
		phdr->hosttime.status = P80211ITEM_OK;
		phdr->hosttime.len = 4;
		phdr->hosttime.data = jiffies;

		phdr->channel.did = WL_MON_FRAME_CHANNEL;
		phdr->channel.status = P80211ITEM_NO_VALUE;
		phdr->channel.len = 4;
		phdr->channel.data = 0;

		phdr->signal.did = WL_MON_FRAME_SIGNAL;
		phdr->signal.status = P80211ITEM_OK;
		phdr->signal.len = 4;

		phdr->signal.data = rxsts->preamble;

		phdr->noise.did = WL_MON_FRAME_NOISE;
		phdr->noise.status = P80211ITEM_NO_VALUE;
		phdr->noise.len = 4;
		phdr->noise.data = 0;

		phdr->rate.did = WL_MON_FRAME_RATE;
		phdr->rate.status = P80211ITEM_OK;
		phdr->rate.len = 4;
		phdr->rate.data = rxsts->datarate;

		phdr->istx.did = WL_MON_FRAME_ISTX;
		phdr->istx.status = P80211ITEM_NO_VALUE;
		phdr->istx.len = 4;
		phdr->istx.data = 0;

		phdr->mactime.did = WL_MON_FRAME_MACTIME;
		phdr->mactime.status = P80211ITEM_OK;
		phdr->mactime.len = 4;
		phdr->mactime.data = rxsts->mactime;

		phdr->rssi.did = WL_MON_FRAME_RSSI;
		phdr->rssi.status = P80211ITEM_OK;
		phdr->rssi.len = 4;
		phdr->rssi.data = rxsts->signal;		

		phdr->sq.did = WL_MON_FRAME_SQ;
		phdr->sq.status = P80211ITEM_OK;
		phdr->sq.len = 4;
		phdr->sq.data = rxsts->sq;

		phdr->frmlen.did = WL_MON_FRAME_FRMLEN;
		phdr->frmlen.status = P80211ITEM_OK;
		phdr->frmlen.status = P80211ITEM_OK;
		phdr->frmlen.len = 4;
		phdr->frmlen.data = rxsts->pktlength;

		pdata = skb->data + sizeof(p80211msg_t);
		bcopy(oskb->data + D11_PHY_HDR_LEN, pdata, oskb->len - D11_PHY_HDR_LEN);

	} else if (wl->monitor_type == ARPHRD_IEEE80211_RADIOTAP) {
		int channel_frequency;
		uint16 channel_flags;
		uint8 flags;
		uint16 rtap_len;
		struct dot11_header * mac_header;
		uint16 fc;

		if (rxsts->datarate != 0)
			rtap_len = sizeof(struct wl_radiotap_legacy);
		else
			rtap_len = sizeof(struct wl_radiotap_ht);

		len = rtap_len + (oskb->len - D11_PHY_HDR_LEN);
		if ((skb = dev_alloc_skb(len)) == NULL)
			return;

		skb_put(skb, len);

		if (CHSPEC_IS2G(rxsts->chanspec)) {
			channel_flags = IEEE80211_CHAN_2GHZ;
			channel_frequency = wf_channel2mhz(CHSPEC_CHANNEL(rxsts->chanspec),
			                                   WF_CHAN_FACTOR_2_4_G);
		} else {
			channel_flags = IEEE80211_CHAN_5GHZ;
			channel_frequency = wf_channel2mhz(CHSPEC_CHANNEL(rxsts->chanspec),
			                                   WF_CHAN_FACTOR_5_G);
		}

		mac_header = (struct dot11_header *)(oskb->data + D11_PHY_HDR_LEN);
		fc = ntoh16(mac_header->fc);

		flags = IEEE80211_RADIOTAP_F_FCS;

		if (rxsts->preamble == WL_RXS_PREAMBLE_SHORT)
			flags |= IEEE80211_RADIOTAP_F_SHORTPRE;

		if (fc & (FC_WEP >> FC_WEP_SHIFT))
			flags |= IEEE80211_RADIOTAP_F_WEP;

		if (fc & (FC_MOREFRAG >> FC_MOREFRAG_SHIFT))
			flags |= IEEE80211_RADIOTAP_F_FRAG;

		if (rxsts->pkterror & WL_RXS_CRC_ERROR)
			flags |= IEEE80211_RADIOTAP_F_BADFCS;

		if (rxsts->datarate != 0) {
			struct wl_radiotap_legacy *rtl = (struct wl_radiotap_legacy*)skb->data;

			rtl->ieee_radiotap.it_version = 0;
			rtl->ieee_radiotap.it_pad = 0;
			rtl->ieee_radiotap.it_len = HTOL16(rtap_len);
			rtl->ieee_radiotap.it_present = HTOL32(WL_RADIOTAP_PRESENT_LEGACY);

			rtl->tsft_l = htol32(rxsts->mactime);
			rtl->flags = flags;
			rtl->rate = rxsts->datarate;
			rtl->channel_freq = HTOL16(channel_frequency);
			rtl->channel_flags = HTOL16(channel_flags);
			rtl->signal = (int8)rxsts->signal;
			rtl->noise = (int8)rxsts->noise;
			rtl->antenna = rxsts->antenna;
		} else {
			struct wl_radiotap_ht *rtht = (struct wl_radiotap_ht*)skb->data;

			rtht->ieee_radiotap.it_version = 0;
			rtht->ieee_radiotap.it_pad = 0;
			rtht->ieee_radiotap.it_len = HTOL16(rtap_len);
			rtht->ieee_radiotap.it_present = HTOL32(WL_RADIOTAP_PRESENT_HT);
			rtht->it_present_ext = HTOL32(WL_RADIOTAP_BRCM_MCS);

			rtht->pad1 = 0;
			rtht->tsft_l = htol32(rxsts->mactime);
			rtht->flags = flags;
			rtht->pad2 = 0;
			rtht->channel_freq = HTOL16(channel_frequency);
			rtht->channel_flags = HTOL16(channel_flags);
			rtht->signal = (int8)rxsts->signal;
			rtht->noise = (int8)rxsts->noise;
			rtht->antenna = rxsts->antenna;

			rtht->pad3 = 0;
			memcpy(rtht->vend_oui, "\x00\x10\x18", 3);
			rtht->vend_sns = WL_RADIOTAP_BRCM_SNS;
			rtht->vend_skip_len = 2;

			rtht->mcs = rxsts->mcs;
			rtht->htflags = 0;
			if (rxsts->htflags & WL_RXS_HTF_40)
				   rtht->htflags |= IEEE80211_RADIOTAP_HTMOD_40;
			if (rxsts->htflags & WL_RXS_HTF_SGI)
				   rtht->htflags |= IEEE80211_RADIOTAP_HTMOD_SGI;
			if (rxsts->preamble & WL_RXS_PREAMBLE_HT_GF)
				   rtht->htflags |= IEEE80211_RADIOTAP_HTMOD_GF;
			if (rxsts->htflags & WL_RXS_HTF_LDPC)
				   rtht->htflags |= IEEE80211_RADIOTAP_HTMOD_LDPC;
			rtht->htflags |=
				(rxsts->htflags & WL_RXS_HTF_STBC_MASK) <<
				IEEE80211_RADIOTAP_HTMOD_STBC_SHIFT;
		}

		pdata = skb->data + rtap_len;
		bcopy(oskb->data + D11_PHY_HDR_LEN, pdata, oskb->len - D11_PHY_HDR_LEN);
	}

	skb->dev = wl->monitor_dev;
	skb->dev->last_rx = jiffies;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 22)
	skb_reset_mac_header(skb);
#else
	skb->mac.raw = skb->data;
#endif
	skb->ip_summed = CHECKSUM_NONE;
	skb->pkt_type = PACKET_OTHERHOST;
	skb->protocol = htons(ETH_P_80211_RAW);

#ifdef NAPI_POLL
	netif_receive_skb(skb);
#else 
	netif_rx(skb);
#endif 
}

static int
wl_monitor_start(struct sk_buff *skb, struct net_device *dev)
{
	wl_info_t *wl;

	wl = WL_DEV_IF(dev)->wl;
	PKTFREE(wl->osh, skb, FALSE);
	return 0;
}

static void
wl_add_monitor(wl_task_t *task)
{
	wl_info_t *wl = (wl_info_t *) task->context;
	struct net_device *dev;
	wl_if_t *wlif;

	ASSERT(wl);
	WL_LOCK(wl);
	WL_TRACE(("wl%d: wl_add_monitor\n", wl->pub->unit));

	if (wl->monitor_dev)
		goto done;

	wlif = wl_alloc_if(wl, WL_IFTYPE_MON, wl->pub->unit, NULL);
	if (!wlif) {
		WL_ERROR(("wl%d: wl_add_monitor: alloc wlif failed\n", wl->pub->unit));
		goto done;
	}

	dev = wlif->dev;
	wl->monitor_dev = dev;

	bcopy(wl->dev->dev_addr, dev->dev_addr, ETHER_ADDR_LEN);
	dev->flags = wl->dev->flags;
	dev->type = wl->monitor_type;
	if (wl->monitor_type == ARPHRD_IEEE80211_PRISM) {
		sprintf(dev->name, "prism%d", wl->pub->unit);
	} else {
		sprintf(dev->name, "radiotap%d", wl->pub->unit);
	}

#if defined(WL_USE_NETDEV_OPS)
	dev->netdev_ops = &wl_netdev_monitor_ops;
#else
	dev->hard_start_xmit = wl_monitor_start;
	dev->do_ioctl = wl_ioctl;
	dev->get_stats = wl_get_stats;
#endif 

	WL_UNLOCK(wl);
	if (register_netdev(dev)) {
		WL_ERROR(("wl%d: wl_add_monitor, register_netdev failed for \"%s\"\n",
			wl->pub->unit, wl->monitor_dev->name));
		wl->monitor_dev = NULL;
		wl_free_if(wl, wlif);
	} else
		wlif->dev_registed = TRUE;
	WL_LOCK(wl);
done:
	MFREE(wl->osh, task, sizeof(wl_task_t));
	atomic_dec(&wl->callbacks);
	WL_UNLOCK(wl);
}

static void
wl_del_monitor(wl_task_t *task)
{
	wl_info_t *wl = (wl_info_t *) task->context;
	struct net_device *dev;
	wl_if_t *wlif = NULL;

	ASSERT(wl);
	WL_LOCK(wl);
	WL_TRACE(("wl%d: wl_del_monitor\n", wl->pub->unit));
	dev = wl->monitor_dev;
	if (!dev)
		goto done;
	wlif = WL_DEV_IF(dev);
	ASSERT(wlif);
	wl->monitor_dev = NULL;
	WL_UNLOCK(wl);
	wl_free_if(wl, wlif);
	WL_LOCK(wl);
done:
	MFREE(wl->osh, task, sizeof(wl_task_t));
	WL_UNLOCK(wl);
	atomic_dec(&wl->callbacks);
}

void
wl_set_monitor(wl_info_t *wl, int val)
{
	WL_TRACE(("wl%d: wl_set_monitor: val %d\n", wl->pub->unit, val));

	if (val && !wl->monitor_dev) {
		if (val == 1)
			wl->monitor_type = ARPHRD_IEEE80211_PRISM;
		else if (val == 2)
			wl->monitor_type = ARPHRD_IEEE80211_RADIOTAP;
		else {
			WL_ERROR(("monitor type %d not supported\n", val));
			ASSERT(0);
		}

		(void) wl_schedule_task(wl, wl_add_monitor, wl);
	} else if (!val && wl->monitor_dev) {
		(void) wl_schedule_task(wl, wl_del_monitor, wl);
	}
}

#if LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 15)
const char *
print_tainted()
{
	return "";
}
#endif	

struct net_device *
wl_netdev_get(wl_info_t *wl)
{
	return wl->dev;
}

int
wl_set_pktlen(osl_t *osh, void *p, int len)
{
	PKTSETLEN(osh, p, len);
	return len;
}

void *
wl_get_pktbuffer(osl_t *osh, int len)
{
	return (PKTGET(osh, len, FALSE));
}

uint
wl_buf_to_pktcopy(osl_t *osh, void *p, uchar *buf, int len, uint offset)
{
	if (PKTLEN(osh, p) < len + offset)
		return 0;
	bcopy(buf, (char *)PKTDATA(osh, p) + offset, len);
	return len;
}

int
wl_tkip_miccheck(wl_info_t *wl, void *p, int hdr_len, bool group_key, int key_index)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 14)
	struct sk_buff *skb = (struct sk_buff *)p;
	skb->dev = wl->dev;

	if (wl->tkipmodops) {
		if (group_key && wl->tkip_bcast_data[key_index])
			return (wl->tkipmodops->decrypt_msdu(skb, key_index, hdr_len,
				wl->tkip_bcast_data[key_index]));
		else if (!group_key && wl->tkip_ucast_data)
			return (wl->tkipmodops->decrypt_msdu(skb, key_index, hdr_len,
				wl->tkip_ucast_data));
	}
#endif 
	WL_ERROR(("%s: No tkip mod ops\n", __FUNCTION__));
	return -1;

}

int
wl_tkip_micadd(wl_info_t *wl, void *p, int hdr_len)
{
	int error = -1;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 14)
	struct sk_buff *skb = (struct sk_buff *)p;
	skb->dev = wl->dev;

	if (wl->tkipmodops) {
		if (wl->tkip_ucast_data)
			error = wl->tkipmodops->encrypt_msdu(skb, hdr_len, wl->tkip_ucast_data);
		if (error)
			WL_ERROR(("Error encrypting MSDU %d\n", error));
	}
	else
#endif 
		WL_ERROR(("%s: No tkip mod ops\n", __FUNCTION__));
	return error;
}

int
wl_tkip_encrypt(wl_info_t *wl, void *p, int hdr_len)
{
	int error = -1;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 14)
	struct sk_buff *skb = (struct sk_buff *)p;
	skb->dev = wl->dev;

	if (wl->tkipmodops) {
		if (wl->tkip_ucast_data)
			error = wl->tkipmodops->encrypt_mpdu(skb, hdr_len, wl->tkip_ucast_data);
		if (error) {
			WL_ERROR(("Error encrypting MPDU %d\n", error));
		}
	}
	else
#endif 
		WL_ERROR(("%s: No tkip mod ops\n", __FUNCTION__));
	return error;

}

int
wl_tkip_decrypt(wl_info_t *wl, void *p, int hdr_len, bool group_key)
{
	int err = -1;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 14)
	struct sk_buff *skb = (struct sk_buff *)p;
	uint8 *pos;
	uint8 key_idx = 0;

	if (group_key) {
		skb->dev = wl->dev;
		pos = skb->data + hdr_len;
		key_idx = pos[3];
		key_idx >>= 6;
		WL_ERROR(("%s: Invalid key_idx %d\n", __FUNCTION__, key_idx));
		ASSERT(key_idx < NUM_GROUP_KEYS);
	}

	if (wl->tkipmodops) {
		if (group_key && key_idx < NUM_GROUP_KEYS && wl->tkip_bcast_data[key_idx])
			err = wl->tkipmodops->decrypt_mpdu(skb, hdr_len,
				wl->tkip_bcast_data[key_idx]);
		else if (!group_key && wl->tkip_ucast_data)
			err = wl->tkipmodops->decrypt_mpdu(skb, hdr_len, wl->tkip_ucast_data);
	}
	else
		WL_ERROR(("%s: No tkip mod ops\n", __FUNCTION__));

#endif 

	return err;
}

int
wl_tkip_keyset(wl_info_t *wl, wsec_key_t *key)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 14)
	bool group_key = FALSE;
	uchar	rxseq[IW_ENCODE_SEQ_MAX_SIZE];

	if (key->len != 0) {
		WL_WSEC(("%s: Key Length is Not zero\n", __FUNCTION__));
		if (key->algo != CRYPTO_ALGO_TKIP) {
			WL_WSEC(("%s: Algo is Not TKIP %d\n", __FUNCTION__, key->algo));
			return 0;
		}
		WL_WSEC(("%s: Trying to set a key in TKIP Mod\n", __FUNCTION__));
	}
	else
		WL_WSEC(("%s: Trying to Remove a Key from TKIP Mod\n", __FUNCTION__));

	if (ETHER_ISNULLADDR(&key->ea) || ETHER_ISBCAST(&key->ea)) {
		group_key = TRUE;
		WL_WSEC(("Group Key index %d\n", key->id));
	}
	else
		WL_WSEC(("Unicast Key index %d\n", key->id));

	if (wl->tkipmodops) {
		uint8 keybuf[8];
		if (group_key) {
			if (key->len) {
				if (!wl->tkip_bcast_data[key->id]) {
					WL_WSEC(("Init TKIP Bcast Module\n"));
					WL_UNLOCK(wl);
					wl->tkip_bcast_data[key->id] =
						wl->tkipmodops->init(key->id);
					WL_LOCK(wl);
				}
				if (wl->tkip_bcast_data[key->id]) {
					WL_WSEC(("TKIP SET BROADCAST KEY******************\n"));
					bzero(rxseq, IW_ENCODE_SEQ_MAX_SIZE);
					bcopy(&key->rxiv, rxseq, 6);
					bcopy(&key->data[24], keybuf, sizeof(keybuf));
					bcopy(&key->data[16], &key->data[24], sizeof(keybuf));
					bcopy(keybuf, &key->data[16], sizeof(keybuf));
					wl->tkipmodops->set_key(&key->data, key->len,
						(uint8 *)&key->rxiv, wl->tkip_bcast_data[key->id]);
				}
			}
			else {
				if (wl->tkip_bcast_data[key->id]) {
					WL_WSEC(("Deinit TKIP Bcast Module\n"));
					wl->tkipmodops->deinit(wl->tkip_bcast_data[key->id]);
					wl->tkip_bcast_data[key->id] = NULL;
				}
			}
		}
		else {
			if (key->len) {
				if (!wl->tkip_ucast_data) {
					WL_WSEC(("Init TKIP Ucast Module\n"));
					WL_UNLOCK(wl);
					wl->tkip_ucast_data = wl->tkipmodops->init(key->id);
					WL_LOCK(wl);
				}
				if (wl->tkip_ucast_data) {
					WL_WSEC(("TKIP SET UNICAST KEY******************\n"));
					bzero(rxseq, IW_ENCODE_SEQ_MAX_SIZE);
					bcopy(&key->rxiv, rxseq, 6);
					bcopy(&key->data[24], keybuf, sizeof(keybuf));
					bcopy(&key->data[16], &key->data[24], sizeof(keybuf));
					bcopy(keybuf, &key->data[16], sizeof(keybuf));
					wl->tkipmodops->set_key(&key->data, key->len,
						(uint8 *)&key->rxiv, wl->tkip_ucast_data);
				}
			}
			else {
				if (wl->tkip_ucast_data) {
					WL_WSEC(("Deinit TKIP Ucast Module\n"));
					wl->tkipmodops->deinit(wl->tkip_ucast_data);
					wl->tkip_ucast_data = NULL;
				}
			}
		}
	}
	else
#endif 
		WL_WSEC(("%s: No tkip mod ops\n", __FUNCTION__));
	return 0;
}

void
wl_tkip_printstats(wl_info_t *wl, bool group_key)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 14)
	char debug_buf[512];
	int idx;
	if (wl->tkipmodops) {
		if (group_key) {
			for (idx = 0; idx < NUM_GROUP_KEYS; idx++) {
				if (wl->tkip_bcast_data[idx])
					wl->tkipmodops->print_stats(debug_buf,
						wl->tkip_bcast_data[idx]);
			}
		} else if (!group_key && wl->tkip_ucast_data)
			wl->tkipmodops->print_stats(debug_buf, wl->tkip_ucast_data);
		else
			return;
		printk("%s: TKIP stats from module: %s\n", debug_buf, group_key?"Bcast":"Ucast");
	}
#endif 
}

#if defined(WL_CONFIG_RFKILL)   

static int
wl_set_radio_block(void *data, bool blocked)
{
	wl_info_t *wl = data;
	uint32 radioval;

	radioval = WL_RADIO_SW_DISABLE << 16 | blocked;

	WL_LOCK(wl);

	if (wlc_set(wl->wlc, WLC_SET_RADIO, radioval) < 0) {
		WL_ERROR(("%s: SET_RADIO failed\n", __FUNCTION__));
		return 1;
	}

	WL_UNLOCK(wl);

	return 0;
}

static const struct rfkill_ops bcmwl_rfkill_ops = {
	.set_block = wl_set_radio_block,
};

static int
wl_init_rfkill(wl_info_t *wl)
{
	int status;

	snprintf(wl->wl_rfkill.rfkill_name, sizeof(wl->wl_rfkill.rfkill_name),
	"brcmwl-%d", wl->pub->unit);

	wl->wl_rfkill.rfkill = rfkill_alloc(wl->wl_rfkill.rfkill_name, &wl->dev->dev,
	RFKILL_TYPE_WLAN, &bcmwl_rfkill_ops, wl);

	if (!wl->wl_rfkill.rfkill) {
		WL_ERROR(("%s: RFKILL: Failed to allocate rfkill\n", __FUNCTION__));
		return -ENOMEM;
	}

	if (wlc_get(wl->wlc, WLC_GET_RADIO, &status) < 0) {
		WL_ERROR(("%s: WLC_GET_RADIO failed\n", __FUNCTION__));
		return 1;
	}

	rfkill_init_sw_state(wl->wl_rfkill.rfkill, status);

	if (rfkill_register(wl->wl_rfkill.rfkill)) {
		WL_ERROR(("%s: rfkill_register failed! \n", __FUNCTION__));
		rfkill_destroy(wl->wl_rfkill.rfkill);
		return 2;
	}

	WL_ERROR(("%s: rfkill registered\n", __FUNCTION__));
	wl->wl_rfkill.registered = TRUE;
	return 0;
}

static void
wl_uninit_rfkill(wl_info_t *wl)
{
	if (wl->wl_rfkill.registered) {
		rfkill_unregister(wl->wl_rfkill.rfkill);
		rfkill_destroy(wl->wl_rfkill.rfkill);
		wl->wl_rfkill.registered = FALSE;
		wl->wl_rfkill.rfkill = NULL;
	}
}

static void
wl_report_radio_state(wl_info_t *wl)
{

	rfkill_set_hw_state(wl->wl_rfkill.rfkill, wl->last_phyind != 0);
}

#endif 

static int
wl_linux_watchdog(void *ctx)
{
	wl_info_t *wl = (wl_info_t *) ctx;
	struct net_device_stats *stats = NULL;
	uint id;
#ifdef USE_IW
	struct iw_statistics *wstats = NULL;
	int phy_noise;
#endif

	if (wl->pub->up) {
		ASSERT(wl->stats_id < 2);

		id = 1 - wl->stats_id;

		stats = &wl->stats_watchdog[id];
#ifdef USE_IW
		wstats = &wl->wstats_watchdog[id];
#endif
		stats->rx_packets = WLCNTVAL(wl->pub->_cnt->rxframe);
		stats->tx_packets = WLCNTVAL(wl->pub->_cnt->txframe);
		stats->rx_bytes = WLCNTVAL(wl->pub->_cnt->rxbyte);
		stats->tx_bytes = WLCNTVAL(wl->pub->_cnt->txbyte);
		stats->rx_errors = WLCNTVAL(wl->pub->_cnt->rxerror);
		stats->tx_errors = WLCNTVAL(wl->pub->_cnt->txerror);
		stats->collisions = 0;

		stats->rx_length_errors = 0;
		stats->rx_over_errors = WLCNTVAL(wl->pub->_cnt->rxoflo);
		stats->rx_crc_errors = WLCNTVAL(wl->pub->_cnt->rxcrc);
		stats->rx_frame_errors = 0;
		stats->rx_fifo_errors = WLCNTVAL(wl->pub->_cnt->rxoflo);
		stats->rx_missed_errors = 0;

		stats->tx_fifo_errors = WLCNTVAL(wl->pub->_cnt->txuflo);
#ifdef USE_IW
#if WIRELESS_EXT > 11
		wstats->discard.nwid = 0;
		wstats->discard.code = WLCNTVAL(wl->pub->_cnt->rxundec);
		wstats->discard.fragment = WLCNTVAL(wl->pub->_cnt->rxfragerr);
		wstats->discard.retries = WLCNTVAL(wl->pub->_cnt->txfail);
		wstats->discard.misc = WLCNTVAL(wl->pub->_cnt->rxrunt) +
			WLCNTVAL(wl->pub->_cnt->rxgiant);

		wstats->miss.beacon = 0;
#endif 
#endif 

		wl->stats_id = id;

#ifdef USE_IW
		if (!wlc_get(wl->wlc, WLC_GET_PHY_NOISE, &phy_noise))
			wl->phy_noise = phy_noise;
#endif 
	}

	return 0;
}

static int
wl_proc_read(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	wl_info_t * wl = (wl_info_t *)data;
	int bcmerror, to_user;
	int len;

	if (offset > 0) {
		*eof = 1;
		return 0;
	}

	if (!length) {
		WL_ERROR(("%s: Not enough return buf space\n", __FUNCTION__));
		return 0;
	}
	WL_LOCK(wl);
	bcmerror = wlc_ioctl(wl->wlc, WLC_GET_MONITOR, &to_user, sizeof(int), NULL);
	len = sprintf(buffer, "%d\n", to_user);
	WL_UNLOCK(wl);
	return len;
}

static int
wl_proc_write(struct file *filp, const char __user *buff, unsigned long length, void *data)
{
	wl_info_t * wl = (wl_info_t *)data;
	int from_user = 0;
	int bcmerror;

	if (length == 0 || length > 2) {

		WL_ERROR(("%s: Invalid data length\n", __FUNCTION__));
		return -EIO;
	}
	if (copy_from_user(&from_user, buff, 1)) {
		WL_ERROR(("%s: copy from user failed\n", __FUNCTION__));
		return -EIO;
	}

	if (from_user >= 0x30)
		from_user -= 0x30;

	WL_LOCK(wl);
	bcmerror = wlc_ioctl(wl->wlc, WLC_SET_MONITOR, &from_user, sizeof(int), NULL);
	WL_UNLOCK(wl);

	if (bcmerror < 0) {
		WL_ERROR(("%s: SET_MONITOR failed with %d\n", __FUNCTION__, bcmerror));
		return -EIO;
	}
	return length;
}

static int
wl_reg_proc_entry(wl_info_t *wl)
{
	char tmp[32];
	sprintf(tmp, "%s%d", HYBRID_PROC, wl->pub->unit);
	if ((wl->proc_entry = create_proc_entry(tmp, 0644, NULL)) == NULL) {
		WL_ERROR(("%s: create_proc_entry %s failed\n", __FUNCTION__, tmp));
		ASSERT(0);
		return -1;
	}
	wl->proc_entry->read_proc = wl_proc_read;
	wl->proc_entry->write_proc = wl_proc_write;
	wl->proc_entry->data = wl;
	return 0;
}
