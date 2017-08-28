/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
      but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "config.h"

#ifndef __NL80211_CONFIG__
#define __NL80211_CONFIG__

/* Use our own defines in case we don't have nl80211 */
#define nl80211_mntr_flag_none		0
#define nl80211_mntr_flag_fcsfail	1
#define nl80211_mntr_flag_plcpfail	2
#define nl80211_mntr_flag_control	3
#define nl80211_mntr_flag_otherbss	4
#define nl80211_mntr_flag_cookframe	5

int nl80211_connect(const char *interface, void **nl_sock, int *nl80211_id, 
        int *if_index, char *errstr);
void nl80211_disconnect(void *nl_sock);

/* Create monitor vap */
int nl80211_createvif(const char *interface, const char *newinterface, 
        unsigned int *in_flags, unsigned int flags_sz, char *errstr);

/* Set channel or frequency.  Callers should prefer the cache_ option using nl80211_connect 
 * when setting multiple channels */
int nl80211_setchannel(const char *interface, int channel, unsigned int chmode, char *errstr);
int nl80211_setchannel_cache(int ifidx, void *nl_sock, int nl80211_id,
        int channel, unsigned int chmode, char *errstr);

/* Set complex frequency */
int mac80211_setfrequency(const char *interface, unsigned int control_freq,
        unsigned int chan_width, unsigned int center_freq1, unsigned int center_freq2,
        char *errstr);
int mac80211_setfrequency_cache(int ifidx, void *nl_sock, int nl80211_id, 
        unsigned int control_freq, unsigned int chan_width, unsigned int center_freq1, 
        unsigned int center_freq2, char *errstr);

// Caller is expected to free return
char *nl80211_find_parent(const char *interface);

#define NL80211_CHANLIST_NO_INTERFACE		-2
#define NL80211_CHANLIST_NOT_NL80211		-3
#define NL80211_CHANLIST_GENERIC			-4
int nl80211_get_chanlist(const char *interface, int *ret_num_chans,
						 int **ret_chan_list, char *errstr);

#endif


