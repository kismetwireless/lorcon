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

#include "config.h"
#include "drv_mac80211.h"

#if defined(SYS_LINUX) && defined(HAVE_LINUX_WIRELESS) && defined(HAVE_LIBNL)

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

#include <linux/types.h>
#include <linux/if.h>
#include <linux/wireless.h>

#include <net/ethernet.h>
#include <netpacket/packet.h>

#define ETH_P_80211_RAW        (ETH_P_ECONET + 1)

#include "ifcontrol_linux.h"
#include "nl80211_control.h"
#include "lorcon_int.h"
#include "lorcon_packasm.h"
#include "lorcon_endian.h"

#ifndef IEEE80211_RADIOTAP_FLAGS
#define IEEE80211_RADIOTAP_FLAGS    (1 << 1)
#endif

#ifndef IEEE80211_RADIOTAP_F_FRAG
#define IEEE80211_RADIOTAP_F_FRAG	0x08
#endif

#ifndef IEEE80211_RADIOTAP_TX_FLAGS
#define IEEE80211_RADIOTAP_TX_FLAGS     (1 << 15)
#define IEEE80211_RADIOTAP_F_TX_CTS     0x0002
#define IEEE80211_RADIOTAP_F_TX_RTS     0x0004
#define IEEE80211_RADIOTAP_F_TX_NOACK   0x0008
#endif

#ifndef IEEE80211_RADIOTAP_DATA_RETRIES
#define IEEE80211_RADIOTAP_DATA_RETRIES (1 << 16)
#endif

/* Define the MCS transmit flags if we don't know them */
#ifndef IEEE80211_RADIOTAP_MCS
#define IEEE80211_RADIOTAP_MCS          (1 << 19)
#define IEEE80211_RADIOTAP_MCS_HAVE_BW  0x01
#define IEEE80211_RADIOTAP_MCS_HAVE_MCS 0x02
#define IEEE80211_RADIOTAP_MCS_HAVE_GI  0x04
#define IEEE80211_RADIOTAP_MCS_BW_MASK  0x03
#define IEEE80211_RADIOTAP_MCS_BW_20    0
#define IEEE80211_RADIOTAP_MCS_BW_40    1
#define IEEE80211_RADIOTAP_MCS_BW_20L   2
#define IEEE80211_RADIOTAP_MCS_BW_20U   3
#define IEEE80211_RADIOTAP_MCS_SGI      0x04
#endif

/* netlink channel modes */
#define NL80211_CHAN_NO_HT              0
#define NL80211_CHAN_HT20               1
#define NL80211_CHAN_HT40MINUS          2
#define NL80211_CHAN_HT40PLUS           3

/* netlink channel widths */
#define NL80211_CHAN_WIDTH_20_NOHT      0
#define NL80211_CHAN_WIDTH_20           1
#define NL80211_CHAN_WIDTH_40           2
#define NL80211_CHAN_WIDTH_80           3
#define NL80211_CHAN_WIDTH_80P80        4
#define NL80211_CHAN_WIDTH_160          5
#define NL80211_CHAN_WIDTH_5            6
#define NL80211_CHAN_WIDTH_10           7

struct mac80211_lorcon {
	void *nlhandle;
    int nl80211id;
    int ifidx;
};

/* Monitor, inject, and injmon are all the same method, open a new vap */
int mac80211_openmon_cb(lorcon_t *context) {
	char *parent;
	char pcaperr[PCAP_ERRBUF_SIZE];
	struct mac80211_lorcon *extras = (struct mac80211_lorcon *) context->auxptr;
	/* short flags; */
	struct ifreq if_req;
	struct sockaddr_ll sa_ll;
	int optval;
	socklen_t optlen;
    char vifname[MAX_IFNAME_LEN];

    unsigned int num_flags = 2;
    unsigned int fi;
    unsigned int flags[2];

    /* We always set these */
    fi = 0;
    flags[fi++] = nl80211_mntr_flag_control;
    flags[fi++] = nl80211_mntr_flag_otherbss;

    if (context->vapname == NULL) {
        // Some versions of Linux don't like interface names that are longer than 15 bytes.  
        // Appending `mon` to the end of the interface is accounted for with the +3
        if (strlen(context->ifname) + 3 >= 16) {
            // Alert the user that we're about to mangle the VAP name
            fprintf(stdout, "[+] Interface name is too long.  Attempting to use monX\n");

            // Flag to tell if a valid name could be found
            int found = 0;
            
            // Walk through up to 10 interface names (0-9).  Using more than that would require
            // a little more C code. 
            // TODO: Not sure if the same VAP name can be used twice safely, so creating a new one
            //       each time.  This will eventually cause an exhaustion of monX names unless the
            //       old interface name is cleaned up, or the device unplugged.
            for (char index_num = '0'; index_num <= '9'; index_num++) {
                // My C sucks, so here's my janky way of setting a string up
                char temp_name[5];
                temp_name[0] = 'm';
                temp_name[1] = 'o';
                temp_name[2] = 'n';
                temp_name[3] = index_num;

                // Always add a NULL terminator
                temp_name[4] = '\0';

                fprintf(stdout, "[+] Attempting to use VAP name \"%s\"\n", temp_name);

                // Ask the OS if this interface exists
                // TODO: Attempt to create a VAP from here and see if it fails?  Would likely be more
                //       useful as it wouldn't increment monX names until the end of time (or 9...)
                if(ifconfig_get_sysdriver(temp_name) == NULL) {
                    // If the interface name was not found, then that means the name is available

                    snprintf(vifname, MAX_IFNAME_LEN, "%s", temp_name);
                    fprintf(stdout, "[+] Using monitor interface name \"%s\"\n", temp_name);
                    found = 1;
                    break;
                } else {
                    fprintf(stdout, "[+] VAP name \"%s\" already exists\n", temp_name);
                }
            }

            if (found == 0) {
                fprintf(stderr, "[!] Could not create a valid VAP name\n");
                fprintf(stdout, "[*] Delete the monX interfaces, or try unplugging, and replugging the device\n");
                exit(-1);
            }
        } else {
            snprintf(vifname, MAX_IFNAME_LEN, "%smon", context->ifname);
        }

        context->vapname = strdup(vifname);
	}

	if ((parent = nl80211_find_parent(context->vapname)) == NULL) {
		if (nl80211_createvif(context->ifname, context->vapname, flags, 
                    num_flags, context->errstr) < 0) {
			free(parent);
			return -1;
		}
	} 

	free(parent);

	if (ifconfig_delta_flags(context->vapname, context->errstr,
							 (IFF_UP | IFF_RUNNING | IFF_PROMISC)) < 0) {
		return -1;
	}

	if (nl80211_connect(context->vapname, &(extras->nlhandle), &(extras->nl80211id),
						&(extras->ifidx), context->errstr) < 0) {
		return -1;
	}

	pcaperr[0] = '\0';

	if ((context->pcap = pcap_open_live(context->vapname, LORCON_MAX_PACKET_LEN, 
										1, context->timeout_ms, pcaperr)) == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "%s", pcaperr);
		return -1;
	}

	context->capture_fd = pcap_get_selectable_fd(context->pcap);

	context->dlt = pcap_datalink(context->pcap);

	context->inject_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (context->inject_fd < 0) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "failed to create injection "
				 "socket: %s", strerror(errno));
		nl80211_disconnect(extras->nlhandle);
		pcap_close(context->pcap);
		return -1;
	}

	memset(&if_req, 0, sizeof(if_req));
	memcpy(if_req.ifr_name, context->vapname, IFNAMSIZ);
	if_req.ifr_name[IFNAMSIZ - 1] = 0;
	if (ioctl(context->inject_fd, SIOCGIFINDEX, &if_req) < 0) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "failed to get interface idex: %s",
				 strerror(errno));
		close(context->inject_fd);
		pcap_close(context->pcap);
		nl80211_disconnect(extras->nlhandle);
		return -1;
	}

	memset(&sa_ll, 0, sizeof(sa_ll));
	sa_ll.sll_family = AF_PACKET;
	sa_ll.sll_protocol = htons(ETH_P_ALL);
	sa_ll.sll_ifindex = if_req.ifr_ifindex;

	if (bind(context->inject_fd, (struct sockaddr *) &sa_ll, sizeof(sa_ll)) != 0) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "failed to bind injection "
				 "socket: %s", strerror(errno));
		close(context->inject_fd);
		pcap_close(context->pcap);
		nl80211_disconnect(extras->nlhandle);
		return -1;
	}

	optlen = sizeof(optval);
	optval = 20;
	if (setsockopt(context->inject_fd, SOL_SOCKET, SO_PRIORITY, &optval, optlen)) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "failed to set priority on "
				 "injection socket: %s", strerror(errno));
		close(context->inject_fd);
		pcap_close(context->pcap);
		nl80211_disconnect(extras->nlhandle);
		return -1;
	}

	return 1;
}

int mac80211_setchan_cb(lorcon_t *context, int channel) {
	struct mac80211_lorcon *extras = (struct mac80211_lorcon *) context->auxptr;

	if (nl80211_setchannel_cache(extras->ifidx, extras->nlhandle, extras->nl80211id,
                channel, 0, context->errstr) < 0) {
		return -1;
	}

	return 0;
}

int mac80211_getchan_cb(lorcon_t *context) {
	int ch;

	if ((ch = iwconfig_get_channel(context->vapname, context->errstr)) < 0) {
		// Fall back to parent if vap doesn't act right (mac80211 seems to do this)
		if ((ch = iwconfig_get_channel(context->ifname, context->errstr)) < 0)
			return -1;
	}

	return ch;
}

int mac80211_setchan_ht_cb(lorcon_t *context, lorcon_channel_t *channel) {
	struct mac80211_lorcon *extras = (struct mac80211_lorcon *) context->auxptr;

    int nlflags = 0;

    switch (channel->type) {
        case LORCON_CHANNEL_HT20:
            nlflags = NL80211_CHAN_HT20;
            break;
        case LORCON_CHANNEL_HT40M:
        case LORCON_CHANNEL_HT40P:
            nlflags = NL80211_CHAN_WIDTH_40;
            break;
        case LORCON_CHANNEL_VHT80:
            nlflags = NL80211_CHAN_WIDTH_80;
            break;
        case LORCON_CHANNEL_VHT160:
            nlflags = NL80211_CHAN_WIDTH_160;
            break;
        case LORCON_CHANNEL_5MHZ:
            nlflags = NL80211_CHAN_WIDTH_5;
            break;
        case LORCON_CHANNEL_10MHZ:
            nlflags = NL80211_CHAN_WIDTH_10;
            break;
    }


	if (nl80211_setfrequency_cache(extras->ifidx, extras->nlhandle, extras->nl80211id,
                channel->channel, nlflags, channel->center_freq_1, channel->center_freq_2,
                context->errstr) < 0) {
		return -1;
	}

	return 0;
}

int mac80211_getmac_cb(lorcon_t *context, uint8_t **mac) {
	/* 802.11 MACs are always 6 */
	uint8_t int_mac[6];

	if (ifconfig_get_hwaddr(context->vapname, context->errstr, int_mac) < 0) {
		return -1;
	}

	(*mac) = malloc(sizeof(uint8_t) * 6);

	memcpy(*mac, int_mac, 6);

	return 6;
}

int mac80211_setmac_cb(lorcon_t *context, int mac_len, uint8_t *mac) {
	short flags;

	/* 802.11 MACs are always 6 */
	if (mac_len != 6) {
		snprintf(context->errstr, LORCON_STATUS_MAX, 
				 "MAC passed to mac80211 driver on %s not 6 bytes, all "
				 "802.11 MACs must be 6 bytes", context->vapname);
		return -1;
	}

	if (ifconfig_ifupdown(context->vapname, context->errstr, 0) < 0)
		return -1;

	if (ifconfig_set_hwaddr(context->vapname, context->errstr, mac) < 0)
		return -1;

	if (ifconfig_ifupdown(context->vapname, context->errstr, 1) < 0)
		return -1;

	return 0;
}

int mac80211_sendpacket(lorcon_t *context, lorcon_packet_t *packet) {
	int ret;

    /* Easiest to make structs and pack them here than 
     * try to do it runtime */
    typedef struct __attribute__((packed)) {
        uint16_t version;
        uint16_t length;
        uint32_t bitmap;
        uint8_t flags;
    } _basic_rtap_hdr;

    _basic_rtap_hdr basic_rtap_hdr = {
        .version = 0,
        .length = lorcon_le16(sizeof(_basic_rtap_hdr)),
        .bitmap = lorcon_le32(IEEE80211_RADIOTAP_FLAGS),
        .flags = IEEE80211_RADIOTAP_F_FRAG
    };


    typedef struct __attribute__((packed)) { 
        uint16_t version;
        uint16_t length;
        uint32_t bitmap;
        uint8_t flags;
        uint8_t mcs_known;
        uint8_t mcs_flags;
        uint8_t mcs_mcs;
    } _mcs_rtap_hdr;

    _mcs_rtap_hdr mcs_rtap_hdr = {
        .version = 0,
        .length = lorcon_le16(sizeof(_mcs_rtap_hdr)),
        .bitmap = lorcon_le32(IEEE80211_RADIOTAP_FLAGS | IEEE80211_RADIOTAP_MCS),
        .flags = IEEE80211_RADIOTAP_F_FRAG,
        .mcs_known = IEEE80211_RADIOTAP_MCS_HAVE_BW | 
            IEEE80211_RADIOTAP_MCS_HAVE_MCS | 
            IEEE80211_RADIOTAP_MCS_HAVE_GI,
        .mcs_flags = 0,
        .mcs_mcs = 0
    };


    uint8_t *rtap_hdr;

#if 0
	u_char rtap_hdr[] = {
		0x00, 0x00, /* version */
		0x0e, 0x00, /* Length */
		0x02, 0xc0, 0x00, 0x00, /* Bitmap TX flags, RX flags*/
		IEEE80211_RADIOTAP_F_FRAG, /* rtap-level flags */
		/* pad */
		0x00,
		/* rx and tx set to inject */
		0x00, 0x00, /* RX flags */
		0x00, 0x00, /* TX flags */
	};
#endif

	u_char *bytes;
	int len, freebytes;
    int rtap_len;

	struct iovec iov[2];

	struct msghdr msg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = iov,
		.msg_iovlen = 2,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = 0,
	};

    if (packet->set_tx_mcs) {
        rtap_hdr = (uint8_t *) &mcs_rtap_hdr;
        rtap_len = sizeof(mcs_rtap_hdr);

        if (packet->tx_mcs_short_guard) {
            mcs_rtap_hdr.mcs_flags |= IEEE80211_RADIOTAP_MCS_SGI;
        }

        if (packet->tx_mcs_40mhz) {
            mcs_rtap_hdr.mcs_flags |= IEEE80211_RADIOTAP_MCS_BW_40;
        }

        mcs_rtap_hdr.mcs_mcs = (uint8_t) packet->tx_mcs_rate;
    } else {
        rtap_hdr = (uint8_t *) &basic_rtap_hdr;
        rtap_len = sizeof(basic_rtap_hdr);
    }

	if (packet->lcpa != NULL) {
		len = lcpa_size(packet->lcpa);
		freebytes = 1;
		bytes = (u_char *) malloc(sizeof(u_char) * len);
		lcpa_freeze(packet->lcpa, bytes);
	} else if (packet->packet_header != NULL) {
		freebytes = 0;
		len = packet->length_header;
		bytes = (u_char *) packet->packet_header;
	} else {
		freebytes = 0;
		len = packet->length;
		bytes = (u_char *) packet->packet_raw;
	}

	iov[0].iov_base = rtap_hdr;
	iov[0].iov_len = rtap_len;
	iov[1].iov_base = bytes;
	iov[1].iov_len = len;

	/*
	if (encrypt)
		rtap_hdr[8] |= IEEE80211_RADIOTAP_F_WEP;
	*/

	ret = sendmsg(context->inject_fd, &msg, 0);

	snprintf(context->errstr, LORCON_STATUS_MAX, "drv_mac80211 failed "
			 "to send packet: %s", strerror(errno));

	if (freebytes)
		free(bytes);
	
	return ret;
}

int mac80211_ifconfig_cb(lorcon_t *context, int up) {
	return ifconfig_ifupdown(context->vapname, context->errstr, up);
}

int drv_mac80211_init(lorcon_t *context) {
	struct mac80211_lorcon *extras = 
		(struct mac80211_lorcon *) malloc(sizeof(struct mac80211_lorcon));

	memset(extras, 0, sizeof(struct mac80211_lorcon));

	context->openinject_cb = mac80211_openmon_cb;
	context->openmon_cb = mac80211_openmon_cb;
	context->openinjmon_cb = mac80211_openmon_cb;

	context->ifconfig_cb = mac80211_ifconfig_cb;

	context->sendpacket_cb = mac80211_sendpacket;

	context->setchan_cb = mac80211_setchan_cb;
	context->getchan_cb = mac80211_getchan_cb;

    context->setchan_ht_cb = mac80211_setchan_ht_cb;

	context->getmac_cb = mac80211_getmac_cb;
	context->setmac_cb = mac80211_setmac_cb;

	context->auxptr = extras;

	return 1;
}

int drv_mac80211_probe(const char *interface) {
	/* key driver detection entirely off the phy80211 /sys attribute */
	if (ifconfig_get_sysattr(interface, "phy80211"))
		return 1;

	return 0;
}

lorcon_driver_t *drv_mac80211_listdriver(lorcon_driver_t *head) {
	lorcon_driver_t *d = (lorcon_driver_t *) malloc(sizeof(lorcon_driver_t));

	d->name = strdup("mac80211");
	d->details = strdup("Linux mac80211 kernel drivers, includes all in-kernel "
						"drivers on modern systems");
	d->init_func = drv_mac80211_init;
	d->probe_func = drv_mac80211_probe;

	d->next = head;

	return d;
}

#endif


