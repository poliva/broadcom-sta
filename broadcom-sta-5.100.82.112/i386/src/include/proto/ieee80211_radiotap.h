/* $FreeBSD: src/sys/net80211/ieee80211_radiotap.h,v 1.11 2007/12/13 01:23:40 sam Exp $ */

#ifndef _NET80211_IEEE80211_RADIOTAP_H_
#define _NET80211_IEEE80211_RADIOTAP_H_

#if defined(__KERNEL__) || defined(_KERNEL)
#ifndef DLT_IEEE802_11_RADIO
#define	DLT_IEEE802_11_RADIO	127	
#endif
#endif 

#define	IEEE80211_RADIOTAP_HDRLEN	64

struct ieee80211_radiotap_header {
	uint8_t		it_version;	
	uint8_t		it_pad;
	uint16_t	it_len;		
	uint32_t	it_present;	
} __packed;

enum ieee80211_radiotap_type {
	IEEE80211_RADIOTAP_TSFT = 0,
	IEEE80211_RADIOTAP_FLAGS = 1,
	IEEE80211_RADIOTAP_RATE = 2,
	IEEE80211_RADIOTAP_CHANNEL = 3,
	IEEE80211_RADIOTAP_FHSS = 4,
	IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5,
	IEEE80211_RADIOTAP_DBM_ANTNOISE = 6,
	IEEE80211_RADIOTAP_LOCK_QUALITY = 7,
	IEEE80211_RADIOTAP_TX_ATTENUATION = 8,
	IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9,
	IEEE80211_RADIOTAP_DBM_TX_POWER = 10,
	IEEE80211_RADIOTAP_ANTENNA = 11,
	IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12,
	IEEE80211_RADIOTAP_DB_ANTNOISE = 13,

	IEEE80211_RADIOTAP_TXFLAGS = 15,
	IEEE80211_RADIOTAP_RETRIES = 17,
	IEEE80211_RADIOTAP_XCHANNEL = 18,
	IEEE80211_RADIOTAP_RATE_MCS = 19,
	IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE = 29,
	IEEE80211_RADIOTAP_VENDOR_NAMESPACE = 30,
	IEEE80211_RADIOTAP_EXT = 31,
	};

#ifndef _KERNEL

#define	IEEE80211_CHAN_TURBO	0x00000010 
#define	IEEE80211_CHAN_CCK	0x00000020 
#define	IEEE80211_CHAN_OFDM	0x00000040 
#define	IEEE80211_CHAN_2GHZ	0x00000080 
#define	IEEE80211_CHAN_5GHZ	0x00000100 
#define	IEEE80211_CHAN_PASSIVE	0x00000200 
#define	IEEE80211_CHAN_DYN	0x00000400 
#define	IEEE80211_CHAN_GFSK	0x00000800 
#define	IEEE80211_CHAN_GSM	0x00001000 
#define	IEEE80211_CHAN_STURBO	0x00002000 
#define	IEEE80211_CHAN_HALF	0x00004000 
#define	IEEE80211_CHAN_QUARTER	0x00008000 
#define	IEEE80211_CHAN_HT20	0x00010000 
#define	IEEE80211_CHAN_HT40U	0x00020000 
#define	IEEE80211_CHAN_HT40D	0x00040000 
#endif 

#define	IEEE80211_RADIOTAP_F_CFP	0x01	
#define	IEEE80211_RADIOTAP_F_SHORTPRE	0x02	
#define	IEEE80211_RADIOTAP_F_WEP	0x04	
#define	IEEE80211_RADIOTAP_F_FRAG	0x08	
#define	IEEE80211_RADIOTAP_F_FCS	0x10	
#define	IEEE80211_RADIOTAP_F_DATAPAD	0x20	
#define	IEEE80211_RADIOTAP_F_BADFCS	0x40	

#define IEEE80211_RADIOTAP_RATE_MCS_40MHZ   0x01 
#define IEEE80211_RADIOTAP_RATE_MCS_SHORT_GI    0x02 

#define IEEE80211_RADIOTAP_TXF_FAIL	0x0001	
#define IEEE80211_RADIOTAP_TXF_CTS	0x0002	
#define IEEE80211_RADIOTAP_TXF_RTSCTS	0x0004	
#define IEEE80211_RADIOTAP_TXF_NOACK	0x0008	
#define IEEE80211_RADIOTAP_TXF_SEQOVR	0x0010	

#endif 
