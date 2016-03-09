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

/* Monitor, inject, and injmon are all the same method, open a new vap */
int file_openmon_cb(lorcon_t *context) {
	char pcaperr[PCAP_ERRBUF_SIZE];
	struct mac80211_lorcon *extras = (struct mac80211_lorcon *) context->auxptr;
	short flags;
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

lorcon_driver_t *drv_file_listdriver(lorcon_driver_t *head) {
	lorcon_driver_t *d = (lorcon_driver_t *) malloc(sizeof(lorcon_driver_t));

	d->name = strdup("file");
	d->details = strdup("PCAP file source");
	d->init_func = drv_file_init;
	d->probe_func = drv_file_probe;

	d->next = head;

	return d;
}

