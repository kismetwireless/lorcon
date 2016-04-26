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
#include "drv_file.h"

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "lorcon_int.h"

struct rtfile_extra_lorcon {
    struct timeval last_ts;
};

/* Monitor, inject, and injmon are all the same method, open a new vap */
int file_openmon_cb(lorcon_t *context) {
	char pcaperr[PCAP_ERRBUF_SIZE];
    struct stat buf;

    if (stat(context->ifname, &buf) < 0) {
        snprintf(context->errstr, LORCON_STATUS_MAX, "%s", strerror(errno));
    }

	pcaperr[0] = '\0';

	if ((context->pcap = pcap_open_offline(context->ifname, pcaperr)) == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "%s", pcaperr);
		return -1;
	}

	context->capture_fd = pcap_get_selectable_fd(context->pcap);

	context->dlt = pcap_datalink(context->pcap);

	context->inject_fd = -1;

	return 1;
}

int file_sendbytes(lorcon_t *context, int length, u_char *bytes) {
    snprintf(context->errstr, LORCON_STATUS_MAX, "cannot inject on files");

    return -1;
}

int rtfile_pcap_handler(u_char *user, const struct pcap_pkthdr *h, 
        const u_char *bytes) {
    lorcon_t *context = (lorcon_t *) user;
    struct rtfile_extra_lorcon *extra = 
        (struct rtfile_extra_lorcon *) context->auxptr;
    unsigned long delay_usec = 0;

    /* First packet, do nothing */
    if (extra->last_ts.tv_sec == 0) {
        extra->last_ts.tv_sec = h->ts.tv_sec;
        extra->last_ts.tv_usec = h->ts.tv_usec;
        return 0;
    }

    /* Calculate the difference in time between the last packet and
     * this one */
    delay_usec = (h->ts.tv_sec - extra->last_ts.tv_sec) * 1000000L;

    if (h->ts.tv_usec < extra->last_ts.tv_usec) {
        delay_usec += (1000000L - extra->last_ts.tv_usec) + h->ts.tv_usec;
    } else {
        delay_usec += h->ts.tv_usec - extra->last_ts.tv_usec;
    }

    extra->last_ts.tv_sec = h->ts.tv_sec;
    extra->last_ts.tv_usec = h->ts.tv_usec;

    usleep(delay_usec);

    return 0;
}

int drv_file_probe(const char *interface) {
    struct stat buf;

    if (stat(interface, &buf) == 0) 
        return 1;

	return 0;
}

int drv_file_init(lorcon_t *context) {
	context->openmon_cb = file_openmon_cb;
	context->openinjmon_cb = file_openmon_cb;

	return 1;
}

int drv_rtfile_init(lorcon_t *context) {
    struct rtfile_extra_lorcon *rtf_extra;

	context->openmon_cb = file_openmon_cb;
	context->openinjmon_cb = file_openmon_cb;
    context->pcap_handler_cb = rtfile_pcap_handler;

    rtf_extra = 
        (struct rtfile_extra_lorcon *) malloc(sizeof(struct rtfile_extra_lorcon));

    rtf_extra->last_ts.tv_sec = 0;
    rtf_extra->last_ts.tv_usec = 0;

    context->auxptr = rtf_extra;

	return 1;
}

lorcon_driver_t *drv_file_listdriver(lorcon_driver_t *head) {
	lorcon_driver_t *d = (lorcon_driver_t *) malloc(sizeof(lorcon_driver_t));
	lorcon_driver_t *rtd = (lorcon_driver_t *) malloc(sizeof(lorcon_driver_t));

	d->name = strdup("file");
	d->details = strdup("PCAP file source");
	d->init_func = drv_file_init;
	d->probe_func = drv_file_probe;
	d->next = head;

	rtd->name = strdup("rtfile");
	rtd->details = strdup("Real-time PCAP file source");
	rtd->init_func = drv_rtfile_init;
	rtd->probe_func = drv_file_probe;
	rtd->next = d;

	return rtd;
}

