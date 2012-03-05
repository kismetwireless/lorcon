/*
    This file is part of lorcon

    lorcon is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    lorcon is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with lorcon; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    Copyright (c) 2005 dragorn and Joshua Wright
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef SYS_LINUX

#include "mwnginject.h"
#include "wtinject.h"
#include "ifcontrol_linux.h"
#include "madwifing_control.h"
#include "tx80211_errno.h"

int tx80211_madwifing_init(struct tx80211 *in_tx)
{
	in_tx->capabilities = tx80211_madwifing_capabilities();
	in_tx->open_callthrough = &madwifing_open;
	in_tx->close_callthrough = &madwifing_close;
	in_tx->setmode_callthrough = &wtinj_setmode;
	in_tx->getmode_callthrough = &wtinj_getmode;
	in_tx->getchan_callthrough = &wtinj_getchannel;
	in_tx->setchan_callthrough = &wtinj_setchannel;
	in_tx->txpacket_callthrough = &madwifing_send;
	in_tx->setfuncmode_callthrough = &madwifing_setfuncmode;
	in_tx->selfack_callthrough = &madwifing_selfack;

	in_tx->extra = NULL;

	return 0;
}

int tx80211_madwifing_capabilities()
{
	/* madwifi-ng does not allow seq# spoofing at the moment */
	return (TX80211_CAP_SNIFF | TX80211_CAP_TRANSMIT |
	/* The card allows SEQ spoofing, but the driver prevents it. Need
	   to figure out how to change driver appropriately to re-enable */
	/*	TX80211_CAP_SEQ |  */
		TX80211_CAP_BSSTIME |
		TX80211_CAP_FRAG | TX80211_CAP_CTRL | 
		TX80211_CAP_DURID | TX80211_CAP_SNIFFACK | 
		TX80211_CAP_DSSSTX | TX80211_CAP_OFDMTX |
		TX80211_CAP_SELFACK | TX80211_CAP_SETRATE |
		TX80211_CAP_SETMODULATION);
}


int madwifing_open(struct tx80211 *in_tx)
{
	/* This always "succeeds" because we don't open until we set funcmode.
	 * Thanks, vaps.  Ugh.
	 */
	return 0;
}

int madwifing_close(struct tx80211 *in_tx)
{
	/* We always succeed at closing so we don't check.
	 * Close the injector normally, then if we use the ptr hack to indicate we're
	 * a self-made vap, destroy it too */
	wtinj_close(in_tx);

	/* if we have a saved interface, pull it back into ifname */
	if (in_tx->extra != NULL) {
		madwifing_destroy_vap(in_tx->ifname, in_tx->errstr);
		snprintf(in_tx->ifname, IFNAMSIZ, "%s", in_tx->extra);
		free(in_tx->extra);
		in_tx->extra = NULL;
	}

	return 0;
}

int madwifing_setfuncmode(struct tx80211 *wtinj, int funcmode)
{
	struct madwifi_vaps *vaplist = NULL;
	int n;

	if (funcmode == TX80211_FUNCMODE_RFMON ||
		funcmode == TX80211_FUNCMODE_INJECT ||
		funcmode == TX80211_FUNCMODE_INJMON) {

		/*
		 * If we weren't passed a rfmon vap already... This will fail
		 * for the master interface it doesn't get a /sys entry
		 */
		if (madwifing_setdevtype(wtinj->ifname, ARPHDR_RADIOTAP, 
				wtinj->errstr) != 0) {
			if (wtinj->extra != NULL) {
				/* If we've got a cached controller name, swap to it */
				snprintf(wtinj->ifname, IFNAMSIZ, "%s", wtinj->extra);
			}

			vaplist = madwifing_list_vaps(wtinj->ifname, wtinj->errstr);
			if (vaplist != NULL) {
				for (n = 0; n < vaplist->vaplen; n++) {
					if (madwifing_destroy_vap(vaplist->vaplist[n], wtinj->errstr) < 0) {
						madwifing_free_vaps(vaplist);
						return -1;
					}
				}
				madwifing_free_vaps(vaplist);
			}


			/* If we haven't remembered a controlling interface before, remember it now */
			if (wtinj->extra == NULL) {
				wtinj->extra = strdup(wtinj->ifname);
			}

			/* Build the vap and put the name into ifname */
			if (madwifing_build_vap(wtinj->ifname, wtinj->errstr, "lorcon", wtinj->ifname, 
									IEEE80211_M_MONITOR, IEEE80211_CLONE_BSSID) < 0) {
				free(wtinj->extra);
				wtinj->extra = NULL;
				return -1;
			}

		} 


		if (wtinj_open(wtinj) != 0) {
			return -1;
		}
	}

	return 0;
}

int madwifing_send(struct tx80211 *in_tx, struct tx80211_packet *in_pkt)
{
	struct tx80211_packet mwng_pkt;
	struct tx80211_radiotap_header *rtaphdr;
	uint8_t *pkt;
	int len, channel, sendcount;

	memset(&mwng_pkt, 0, sizeof(mwng_pkt));
	len = (in_pkt->plen + TX80211_RTAP_LEN);

	pkt = malloc(len);
	if (pkt == NULL) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX, 
				"Unable to allocate memory buffer "
				"for send function");
		return -1;
	}

	memset(pkt, 0, len);

	channel = tx80211_getchannel(in_tx);

	/* Setup radiotap header */
	rtaphdr = (struct tx80211_radiotap_header *)pkt;
	rtaphdr->it_version = 0;
	rtaphdr->it_pad = 0;
	rtaphdr->it_len = tx80211_le16(TX80211_RTAP_LEN);
	rtaphdr->it_present = tx80211_le32(TX80211_RTAP_PRESENT);
	rtaphdr->wr_flags = 0;
	rtaphdr->wr_rate = in_pkt->txrate; /* 0 if not set for default */
	rtaphdr->wr_chan_freq = tx80211_chan2mhz(channel);

	switch(in_pkt->modulation) {
		case TX80211_MOD_DEFAULT:
			rtaphdr->wr_chan_flags = 0;
			break;
		case TX80211_MOD_DSSS:
			rtaphdr->wr_chan_flags =
				tx80211_le16(TX80211_RTAP_CHAN_B);
			break;
		case TX80211_MOD_OFDM:
			/* OFDM can be 802.11g or 802.11a */
			if (channel <= 14) {
				/* 802.11g network */
				rtaphdr->wr_chan_flags = 
					tx80211_le16(TX80211_RTAP_CHAN_G);
			} else {
				rtaphdr->wr_chan_flags = 
					tx80211_le16(TX80211_RTAP_CHAN_A);
			}
			break;
		case TX80211_MOD_TURBO:
			/* Turbo can be 802.11g or 802.11a */
			if (channel <= 14) {
				/* 802.11g network */
				rtaphdr->wr_chan_flags = 
					tx80211_le16(TX80211_RTAP_CHAN_TG);
			} else {
				rtaphdr->wr_chan_flags = 
					tx80211_le16(TX80211_RTAP_CHAN_TA);
			}
			break;
		default:
			snprintf(in_tx->errstr, TX80211_STATUS_MAX, 
					"Unsupported modulation mechanism "
					"specified in send function.");
			return TX80211_ENOTSUPP;
	}

	memcpy(pkt + TX80211_RTAP_LEN, in_pkt->packet, in_pkt->plen);

	mwng_pkt.packet = pkt;
	mwng_pkt.plen = len;

	sendcount = wtinj_send(in_tx, &mwng_pkt);
	free(pkt);

	if (sendcount < 0) {
		return TX80211_ENOTX;
	} else if (sendcount != mwng_pkt.plen) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX,
			"Error sending packet data, partial write.");
		return TX80211_EPARTTX;
	} else {
		return (sendcount);
	}
}

/* 
 * Change the local interface to the specified MAC address to let the 
 * Atheros chip ACK for us.
 * Procedure is:
 *   + Delete all VAPs
 *   + ifconfig wifi0 down
 *   + SIOCSIFHWADDR
 *   + Create new VAP
 *   + ifconfig lor0 up
 */
int madwifing_selfack(struct tx80211 *in_tx, uint8_t *addr)
{
	struct madwifi_vaps *vaplist = NULL;
	int n;

	if (in_tx->extra == NULL) {
		/* User specified sub-interface, not master; 
		 * This doesn't help us
		 */
                snprintf(in_tx->errstr, TX80211_STATUS_MAX,
				"MADWIFI SelfACK: Cannot set MAC address for "
				"sub-interface, must specify master name");
		return TX80211_ENOTSUPP;
	}

	/* Close the socket for the interface */
	wtinj_close(in_tx);

	/* Get a list of all VAP's (should be only one) */
	vaplist = madwifing_list_vaps(in_tx->extra, in_tx->errstr);

	/* Delete all VAPs */
	if (vaplist != NULL) {
		for (n = 0; n < vaplist->vaplen; n++) {
			if (madwifing_destroy_vap(vaplist->vaplist[n], 
					in_tx->errstr) < 0) {
				madwifing_free_vaps(vaplist);
				return -1;
			}
		}
		madwifing_free_vaps(vaplist);
	}

	if (ifconfig_ifupdown(in_tx->extra, in_tx->errstr, 
			TX80211_IFDOWN) < 0) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX,
			"MADWIFI SelfACK: Failed to place interface %d in the "
			"DOWN state before changing MAC address.", 
			in_tx->ifname);
		return -1;
	}
	
	if (ifconfig_set_hwaddr(in_tx->extra, in_tx->errstr, addr) < 0) {
		/* Retain message from set_hwaddr */
		return -1;
	}

	if (ifconfig_ifupdown(in_tx->extra, in_tx->errstr, TX80211_IFUP) < 0) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX,
			"MADWIFI SelfACK: Failed to place interface %d in the "
			"UP state after changing MAC address.", 
			in_tx->extra);
		return -1;
	}

	/* Build the vap and put the name into ifname */
	if (madwifing_build_vap(in_tx->extra, in_tx->errstr, "lorcon", 
			in_tx->ifname, IEEE80211_M_MONITOR,
			IEEE80211_CLONE_BSSID) < 0) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX,
				"MADWIFI SelfACK: Failed to build a new VAP");
		return -1;
	}

	if (ifconfig_ifupdown(in_tx->ifname, in_tx->errstr, 
			TX80211_IFUP) < 0) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX,
			"MADWIFI SelfACK: Failed to place interface %s"
			"in the UP state after changing MAC address.",
			in_tx->ifname);
		return -1;
	}

	if (wtinj_open(in_tx) != 0) {
		return -1;
	}

	return 0;
}


#endif /* linux */
