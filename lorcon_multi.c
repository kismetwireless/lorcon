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

#include <malloc.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "lorcon.h"
#include "lorcon_int.h"
#include "lorcon_multi.h"
#include "lorcon_multi_int.h"

const char *lorcon_multi_get_error(lorcon_multi_t *ctx) {
    return ctx->errstr;
}

lorcon_multi_t *lorcon_multi_create() {
    lorcon_multi_t *r = (lorcon_multi_t *) malloc(sizeof(lorcon_multi_t));

    if (r == NULL)
        return NULL;

    r->interfaces = NULL;
    r->errstr[0] = 0;
    r->handler_cb = NULL;
    r->handler_user = NULL;

    return r;
}

void lorcon_multi_free(lorcon_multi_t *ctx, int free_interfaces) {
    lorcon_multi_interface_t *ib, *i = ctx->interfaces;

    while (i) {
        ib = i->next;

        if (free_interfaces) 
            lorcon_free(i->lorcon_intf);

        free(i);

        i = ib;
    }

    free(ctx);
}

int lorcon_multi_add_interface(lorcon_multi_t *ctx, lorcon_t *lorcon_intf) {
    lorcon_multi_interface_t *i = 
        (lorcon_multi_interface_t *) malloc(sizeof(lorcon_multi_interface_t));

    if (i == NULL)  {
        snprintf(ctx->errstr, LORCON_STATUS_MAX, "Out of memory");
        return -1;
    }

    i->next = ctx->interfaces;
    i->lorcon_intf = lorcon_intf;
    ctx->interfaces = i;
    return 0;
}

void lorcon_multi_del_interface(lorcon_multi_t *ctx, lorcon_t *lorcon_intf,
        int free_interface) {
    lorcon_multi_interface_t *pi = NULL, *i = ctx->interfaces;

    while (i != NULL) {
        if (i->lorcon_intf == lorcon_intf) {
            if (pi == NULL)
                ctx->interfaces = i->next;
            else
                pi->next = i->next;

            if (free_interface)
                lorcon_free(i->lorcon_intf);

            free(i);
            
            return;
        }

        pi = i;
        i = i->next;
    }
}

lorcon_multi_interface_t *lorcon_multi_get_interfaces(lorcon_multi_t *ctx) {
    return ctx->interfaces;
}

lorcon_multi_interface_t *lorcon_multi_get_next_interface(lorcon_multi_t *ctx,
        lorcon_multi_interface_t *intf) {
    if (intf == NULL)
        return ctx->interfaces;

    return intf->next;
}

lorcon_t *lorcon_multi_interface_get_lorcon(lorcon_multi_interface_t *intf) {
    return intf->lorcon_intf;
}

int lorcon_multi_loop(lorcon_multi_t *ctx, int count, lorcon_handler callback,
        u_char *user) {
    int packets = 0;
    fd_set rset;
    int maxfd = 0;
    int r;
    lorcon_multi_interface_t *intf = NULL;

    if (ctx->interfaces == NULL) {
        snprintf(ctx->errstr, LORCON_STATUS_MAX, 
                "Cannot multi_loop with no interfaces");
        return -1;
    }

    while (packets < count || count <= 0) {
        FD_ZERO(&rset);
        maxfd = 0;

        while ((intf = lorcon_multi_get_next_interface(ctx, intf))) {
            int fd = lorcon_get_selectable_fd(intf->lorcon_intf);

            if (fd < 0) {
                lorcon_multi_del_interface(ctx, intf->lorcon_intf, 0);

                if (intf->error_handler != NULL) {
                    (*(intf->error_handler))(ctx, intf->lorcon_intf, intf->error_aux);
                }

                /* reset loop */
                intf = NULL;
                continue;
            }

            FD_SET(fd, &rset);

            if (maxfd < fd)
                maxfd = fd;

        }

        if (maxfd == 0) {
            fprintf(stderr, "lorcon_multi_loop no interfaces with packets left\n");
            return 0;
        }

        /* Blocking select */
        if (select(maxfd + 1, &rset, NULL, NULL, NULL) < 0) {
            if (errno != EINTR && errno != EAGAIN) {
                snprintf(ctx->errstr, LORCON_STATUS_MAX,
                        "select fail: %s", strerror(errno));
                return -1;
            }
        }

        intf = NULL;
        while ((intf = lorcon_multi_get_next_interface(ctx, intf))) {
            int fd = lorcon_get_selectable_fd(intf->lorcon_intf);

            if (fd < 0) {
                lorcon_multi_del_interface(ctx, intf->lorcon_intf, 0);

                if (intf->error_handler != NULL) {
                    (*(intf->error_handler))(ctx, intf->lorcon_intf, intf->error_aux);
                }

                /* reset loop */
                intf = NULL;

                continue;
            }

            if (FD_ISSET(fd, &rset)) {
                r = lorcon_dispatch(intf->lorcon_intf, 1, callback, user);

                if (r <= 0) {
                    /*
                    snprintf(ctx->errstr, LORCON_STATUS_MAX,
                            "%s failed dispatch",
                            lorcon_get_capiface(intf->lorcon_intf));
                    return -1; 
                    */

                    fprintf(stderr, "Interface stopped reporting packets, removing "
                            "from multicap: %s\n", 
                            lorcon_get_capiface(intf->lorcon_intf));
                    lorcon_multi_del_interface(ctx, intf->lorcon_intf, 0);

                    if (intf->error_handler != NULL) {
                        (*(intf->error_handler))(ctx, intf->lorcon_intf, intf->error_aux);
                    }

                    /* reset loop */
                    intf = NULL;
                    continue;
                }

                packets++;
            }
        }

    }

    return packets;
}

void lorcon_multi_set_interface_error_handler(lorcon_multi_t *ctx,
        lorcon_t *lorcon_interface, lorcon_multi_error_handler handler, 
        void *aux) {
    lorcon_multi_interface_t *intf = NULL;

    while ((intf = lorcon_multi_get_next_interface(ctx, intf))) {
        if (intf->lorcon_intf == lorcon_interface) {
            intf->error_handler = handler;
            intf->error_aux = aux;
            return;
        }
    }
}

void lorcon_multi_remove_interface_error_handler(lorcon_multi_t *ctx, 
        lorcon_t *lorcon_interface) {
    lorcon_multi_interface_t *intf = NULL;

    while ((intf = lorcon_multi_get_next_interface(ctx, intf))) {
        if (intf->lorcon_intf == lorcon_interface) {
            intf->error_handler = NULL;
            intf->error_aux = NULL;
            return;
        }
    }
}


