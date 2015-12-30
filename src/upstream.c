/* tinyproxy - A fast light-weight HTTP proxy
 * Copyright (C) 1998 Steven Young <sdyoung@miranda.org>
 * Copyright (C) 1999-2005 Robert James Kaes <rjkaes@users.sourceforge.net>
 * Copyright (C) 2000 Chris Lightfoot <chris@ex-parrot.com>
 * Copyright (C) 2002 Petr Lampa <lampa@fit.vutbr.cz>
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

#include "upstream.h"
#include "heap.h"
#include "log.h"

#include <limits.h>

#ifdef UPSTREAM_SUPPORT

struct upstream {
        struct upstream *next;
        char *domain;           /* optional */
        char *host;
        int port;
        in_addr_t ip, mask;
};

/**
 * Construct an upstream struct from input data.
 */
static struct upstream *upstream_build (const char *host, int port, const char *domain)
{
        char *ptr;
        struct upstream *up;

        up = (struct upstream *) safemalloc (sizeof (struct upstream));
        if (!up) {
                log_message (LOG_ERR,
                             "Unable to allocate memory in upstream_build()");
                return NULL;
        }

        up->host = up->domain = NULL;
        up->ip = up->mask = 0;

        if (domain == NULL) {
                if (!host || host[0] == '\0' || port < 1) {
                        log_message (LOG_WARNING,
                                     "Nonsense upstream rule: invalid host or port");
                        goto fail;
                }

                up->host = safestrdup (host);
                up->port = port;

                log_message (LOG_INFO, "Added upstream %s:%d for [default]",
                             host, port);
        } else if (host == NULL) {
                if (!domain || domain[0] == '\0') {
                        log_message (LOG_WARNING,
                                     "Nonsense no-upstream rule: empty domain");
                        goto fail;
                }

                ptr = strchr (domain, '/');
                if (ptr) {
                        struct in_addr addrstruct;

                        *ptr = '\0';
                        if (inet_aton (domain, &addrstruct) != 0) {
                                up->ip = ntohl (addrstruct.s_addr);
                                *ptr++ = '/';

                                if (strchr (ptr, '.')) {
                                        if (inet_aton (ptr, &addrstruct) != 0)
                                                up->mask =
                                                    ntohl (addrstruct.s_addr);
                                } else {
                                        up->mask =
                                            ~((1 << (32 - atoi (ptr))) - 1);
                                }
                        }
                } else {
                        up->domain = safestrdup (domain);
                }

                log_message (LOG_INFO, "Added no-upstream for %s", domain);
        } else {
                if (!host || host[0] == '\0' || port < 1 || !domain
                    || domain == '\0') {
                        log_message (LOG_WARNING,
                                     "Nonsense upstream rule: invalid parameters");
                        goto fail;
                }

                up->host = safestrdup (host);
                up->port = port;
                up->domain = safestrdup (domain);

                log_message (LOG_INFO, "Added upstream %s:%d for %s",
                             host, port, domain);
        }

        return up;

fail:
        safefree (up->host);
        safefree (up->domain);
        safefree (up);

        return NULL;
}

struct upstream_config* init_upstream_config(void)
{
        struct upstream_config* up_config;

        up_config = (struct upstream_config *) safemalloc (sizeof (struct upstream_config));
        up_config->list = NULL;
        up_config->proxy = px_proxy_factory_new();

        return up_config;
}

/*
 * Add an entry to the upstream list
 */
void upstream_add (const char *host, int port, const char *domain,
                   struct upstream_config* up_config)
{
        struct upstream *up;

        up = upstream_build (host, port, domain);
        if (up == NULL) {
                return;
        }

        if (!up->domain && !up->ip) {   /* always add default to end */
                struct upstream *tmp = up_config->list;

                while (tmp) {
                        if (!tmp->domain && !tmp->ip) {
                                log_message (LOG_WARNING,
                                             "Duplicate default upstream");
                                goto upstream_cleanup;
                        }

                        if (!tmp->next) {
                                up->next = NULL;
                                tmp->next = up;
                                return;
                        }

                        tmp = tmp->next;
                }
        }

        up->next = up_config->list;
        up_config->list = up;

        return;

upstream_cleanup:
        safefree (up->host);
        safefree (up->domain);
        safefree (up);

        return;
}

static const char HTTP_PRE[] = "http://";
static const int HTTP_PRE_LENGTH = (sizeof(HTTP_PRE)/sizeof(HTTP_PRE[0])) - 1;

static const char DIRECT_PROXY[] = "direct://";

static struct upstream_info *detect_proxy (pxProxyFactory* factory, const char* host)
{
        struct upstream_info *ret = NULL;
        int proxy_resolved = 0;
        char **proxies = NULL, **proxy_ptr = NULL;
        const int host_str_len = HTTP_PRE_LENGTH + strlen(host) + 1;
        char *host_str = (char*) safemalloc (host_str_len);

        snprintf (host_str, host_str_len, "%s%s", HTTP_PRE, host);
        proxies = px_proxy_factory_get_proxies (factory, host_str);
        proxy_ptr = proxies;
        while (*proxy_ptr) {
                int proxy_len = 0;
                if (proxy_resolved) {
                        free (*proxy_ptr);
                } else if ((proxy_len = strlen (*proxy_ptr)) > HTTP_PRE_LENGTH &&
                           !strncmp (*proxy_ptr, HTTP_PRE, HTTP_PRE_LENGTH) &&
                           NULL == strchr (*proxy_ptr, '@')) {
                        /* If this is a HTTP proxy, without any username/password auth, then we support it */
                        char* host_port = strdup (*proxy_ptr + HTTP_PRE_LENGTH);
                        char* colon_pos = strchr (host_port, ':');
                        ret = (struct upstream_info*) safemalloc (sizeof (struct upstream_info));
                        ret->port = 80;
                        if (colon_pos) {
                                long port_num = strtol (colon_pos + 1, NULL, 10);
                                *colon_pos = '\0'; /* truncate host */
                                if (port_num <= 0 || port_num > USHRT_MAX) {
                                        port_num = 80;
                                }
                                ret->port = (int) port_num;
                        }
                        ret->host = host_port;
                        proxy_resolved = 1;
                } else if (! strcmp (*proxy_ptr, DIRECT_PROXY)) {
                        /* ret stays NULL */
                        proxy_resolved = 1;
                        free (*proxy_ptr);
                } else {
                        free (*proxy_ptr);
                }
                proxy_ptr ++;
        }

        free (proxies);
        return ret;
}

/*
 * Check if a host is in the upstream list
 */
struct upstream_info *upstream_get (char *host, struct upstream_config *up_config)
{
        in_addr_t my_ip = INADDR_NONE;
        struct upstream* up = up_config->list;

        while (up) {
                if (up->domain) {
                        if (strcasecmp (host, up->domain) == 0)
                                break;  /* exact match */

                        if (up->domain[0] == '.') {
                                char *dot = strchr (host, '.');

                                if (!dot && !up->domain[1])
                                        break;  /* local host matches "." */

                                while (dot && strcasecmp (dot, up->domain))
                                        dot = strchr (dot + 1, '.');

                                if (dot)
                                        break;  /* subdomain match */
                        }
                } else if (up->ip) {
                        if (my_ip == INADDR_NONE)
                                my_ip = ntohl (inet_addr (host));

                        if ((my_ip & up->mask) == up->ip)
                                break;
                } else {
                        break;  /* No domain or IP, default upstream */
                }

                up = up->next;
        }

        if (up && up->host && !strcmp (up->host, "detect")) {
                struct upstream_info *ret = detect_proxy (up_config->proxy, host);
                if (ret) {
                        log_message (LOG_INFO, "Detected upstream proxy %s:%d for %s",
                                     ret->host, ret->port, host);
                } else {
                        log_message (LOG_INFO, "Detected no upstream proxy for %s", host);
                }
                return ret;
        }

        if (up && (!up->host || !up->port))
                up = NULL;

        if (up) {
                struct upstream_info *ret = (struct upstream_info*) safemalloc (sizeof (struct upstream_info));
                ret->host = safestrdup (up->host);
                ret->port = up->port;

                log_message (LOG_INFO, "Found upstream proxy %s:%d for %s",
                             ret->host, ret->port, host);
                return ret;
        } else {
                log_message (LOG_INFO, "No upstream proxy for %s", host);
                return NULL;
        }
}

void free_upstream_info (struct upstream_info *up_info)
{
        safefree (up_info->host);
        safefree (up_info);
}

void free_upstream_config (struct upstream_config *up_config)
{
        struct upstream* up = up_config->list;
        while (up) {
                struct upstream *tmp = up;
                up = up->next;
                safefree (tmp->domain);
                safefree (tmp->host);
                safefree (tmp);
        }
        px_proxy_factory_free (up_config->proxy);
        safefree (up_config);
}

#endif
