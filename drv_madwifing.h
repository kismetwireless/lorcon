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

#ifndef __MWNGINJECT_H__
#define __MWNGINJECT_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef SYS_LINUX

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <net/if_arp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <sys/types.h>

#ifdef HAVE_LINUX_WIRELESS
#include <linux/types.h>
#include <linux/if.h>
#include <linux/wireless.h>
#else
#include <net/if.h>
#endif

#include <net/ethernet.h>
#include <netpacket/packet.h>

#include "wtinject.h"

enum mwng_ieee80211_phymode {
	MWNG_IEEE80211_MODE_AUTO     = 0,    /* autoselect */
	MWNG_IEEE80211_MODE_11A      = 1,    /* 5GHz, OFDM */
	MWNG_IEEE80211_MODE_11B      = 2,    /* 2GHz, CCK */
	MWNG_IEEE80211_MODE_11G      = 3,    /* 2GHz, OFDM */
	MWNG_IEEE80211_MODE_FH       = 4,    /* 2GHz, GFSK */
	MWNG_IEEE80211_MODE_TURBO_A  = 5,    /* 5GHz, OFDM, 2x clock dynamic turbo */
	MWNG_IEEE80211_MODE_TURBO_G  = 6,    /* 2GHz, OFDM, 2x clock  dynamic turbo*/
};


int tx80211_madwifing_init(struct tx80211 *in_tx);
int tx80211_madwifing_capabilities();
int madwifing_open(struct tx80211 *in_tx);
int madwifing_send(struct tx80211 *in_tx, struct tx80211_packet *in_pkt);
int madwifing_setfuncmode(struct tx80211 *in_tx, int funcmode);
int madwifing_close(struct tx80211 *in_tx);
int madwifing_selfack(struct tx80211 *in_tx, uint8_t *addr);

#endif /* linux */

#endif
