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

#ifndef __LORCON_MULTI_INT_H__
#define __LORCON_MULTI_INT_H__

#include <stdint.h>
#include "lorcon.h"
#include "lorcon_multi.h"

struct lorcon_multi_interface {
    struct lorcon_multi_interface *next;
    lorcon_t *lorcon_intf;

    lorcon_multi_error_handler error_handler;
    void *error_aux;
};

struct lorcon_multi {
    struct lorcon_multi_interface *interfaces;

	char errstr[LORCON_STATUS_MAX];
   
    /* Callback */
	lorcon_handler handler_cb;
	void *handler_user;
};

#endif

