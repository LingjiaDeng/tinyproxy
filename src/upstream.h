/* tinyproxy - A fast light-weight HTTP proxy
 * Copyright (C) 1998 Steven Young <sdyoung@miranda.org>
 * Copyright (C) 1999 Robert James Kaes <rjkaes@users.sourceforge.net>
 * Copyright (C) 2009 Michael Adam <obnox@samba.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * Routines for handling the list of upstream proxies.
 */

#ifndef _TINYPROXY_UPSTREAM_H_
#define _TINYPROXY_UPSTREAM_H_

#include "common.h"

/*
 * Even if upstream support is not compiled into tinyproxy, this
 * structure still needs to be defined.
 */
struct upstream;
struct upstream_config {
        struct upstream* list;
};

struct upstream_info {
        char *host;
        int port;
};

#ifdef UPSTREAM_SUPPORT
extern struct upstream_config* init_upstream_config(void);
extern void upstream_add (const char *host, int port, const char *domain,
                          struct upstream_config* up_config);
extern struct upstream_info* upstream_get (char *host, struct upstream_config *up_config);
extern void free_upstream_info (struct upstream_info* up_info);
extern void free_upstream_config (struct upstream_config *up_config);
#endif /* UPSTREAM_SUPPORT */

#endif /* _TINYPROXY_UPSTREAM_H_ */
