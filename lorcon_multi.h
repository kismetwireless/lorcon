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

*/

/* LORCON MULTI
 *
 * LM allows simultaneous sniffing on multiple interfaces.  Currently the
 * only supported mechanism for processing packets is lorcon_multi_loop()
 * which operates in the same fashion as pcap_loop().
 *
 * LM currently only functions on interfaces which present a pollable 
 * file descriptor.
 */

#ifndef __LORCON_MULTI_H__
#define __LORCON_MULTI_H__

#include <stdint.h>

struct lorcon;
typedef struct lorcon lorcon_t;

struct lorcon_multi_interface;
typedef struct lorcon_multi_interface lorcon_multi_interface_t;

struct lorcon_multi;
typedef struct lorcon_multi lorcon_multi_t;

const char *lorcon_multi_get_error(lorcon_multi_t *ctx);

struct lorcon_packet;

typedef void (*lorcon_handler)(lorcon_t *, struct lorcon_packet *, unsigned char *user);

/* Create a multi-interface context */
lorcon_multi_t *lorcon_multi_create();

/* Destroy a multi-context, and optionally shut down any interfaces used in it */
void lorcon_multi_free(lorcon_multi_t *ctx, int free_interfaces);

/* Add an existing lorcon interface to a multi.  0 on success, negative on failure */
int lorcon_multi_add_interface(lorcon_multi_t *ctx, lorcon_t *lorcon_intf);
/* Remove an interface from a multi */
void lorcon_multi_del_interface(lorcon_multi_t *ctx, lorcon_t *lorcon_intf,
        int free_interface);
/* Iterate interfaces */
lorcon_multi_interface_t *lorcon_multi_get_interfaces(lorcon_multi_t *ctx);
lorcon_multi_interface_t *lorcon_multi_get_next_interface(lorcon_multi_t *ctx,
        lorcon_multi_interface_t *intf);
lorcon_t *lorcon_multi_interface_get_lorcon(lorcon_multi_interface_t *intf);

/* Callback for interface failure.  On failure, interfaces are removed from the
 * multi group, but may be re-added by this callback. 
 * If there are no interfaces left at the next loop, lorcon_loop will exit.
 */
typedef void (*lorcon_multi_error_handler)(lorcon_multi_t *ctx, 
        lorcon_t *lorcon_interface, void *aux);
void lorcon_multi_set_interface_error_handler(lorcon_multi_t *ctx, 
        lorcon_t *lorcon_interface, 
        lorcon_multi_error_handler handler, void *aux);
void lorcon_multi_remove_interface_error_handler(lorcon_multi_t *ctx, 
        lorcon_t *lorcon_interface);

/* Enter a blocking capture loop for `count' packets */
int lorcon_multi_loop(lorcon_multi_t *ctx, int count, lorcon_handler callback,
        unsigned char *user);

#endif
