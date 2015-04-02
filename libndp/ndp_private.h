/*
 *   ndp_private.h - Neighbour discovery library private header
 *   Copyright (C) 2013-2015 Jiri Pirko <jiri@resnulli.us>
 *
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _NDP_PRIVATE_H_
#define _NDP_PRIVATE_H_

#include <stdarg.h>
#include <syslog.h>
#include <ndp.h>

#include "list.h"

#define NDP_EXPORT __attribute__ ((visibility("default")))

/**
 * SECTION: ndp
 * @short_description: libndp context
 */

struct ndp {
	int sock;
	void (*log_fn)(struct ndp *ndp, int priority,
		       const char *file, int line, const char *fn,
		       const char *format, va_list args);
	int log_priority;
	struct list_item msgrcv_handler_list;
};

/**
 * SECTION: logging
 * @short_description: libndp logging facility
 */

void ndp_log(struct ndp *ndp, int priority,
	     const char *file, int line, const char *fn,
	     const char *format, ...);

static inline void __attribute__((always_inline, format(printf, 2, 3)))
ndp_log_null(struct ndp *ndp, const char *format, ...) {}

#define ndp_log_cond(ndp, prio, arg...)					\
	do {								\
		if (ndp_get_log_priority(ndp) >= prio)			\
			ndp_log(ndp, prio, __FILE__, __LINE__,		\
				__FUNCTION__, ## arg);			\
	} while (0)

#ifdef ENABLE_LOGGING
#  ifdef ENABLE_DEBUG
#    define dbg(ndp, arg...) ndp_log_cond(ndp, LOG_DEBUG, ## arg)
#  else
#    define dbg(ndp, arg...) ndp_log_null(ndp, ## arg)
#  endif
#  define info(ndp, arg...) ndp_log_cond(ndp, LOG_INFO, ## arg)
#  define warn(ndp, arg...) ndp_log_cond(ndp, LOG_WARNING, ## arg)
#  define err(ndp, arg...) ndp_log_cond(ndp, LOG_ERR, ## arg)
#else
#  define dbg(ndp, arg...) ndp_log_null(ndp, ## arg)
#  define info(ndp, arg...) ndp_log_null(ndp, ## arg)
#  define warn(ndp, arg...) ndp_log_null(ndp, ## arg)
#  define err(ndp, arg...) ndp_log_null(ndp, ## arg)
#endif

/**
 * SECTION: netinet/icmp6.h addendum
 * @short_description: defines and structs missing from netinet/icmp6.h
 */

#define __ND_OPT_ROUTE_INFO 24 /* rfc4191 */
#define __ND_OPT_RDNSS 25 /* rfc6106 */
#define __ND_OPT_DNSSL 31 /* rfc6106 */

struct __nd_opt_route_info { /* route information */
	uint8_t		nd_opt_ri_type;
	uint8_t		nd_opt_ri_len;
	uint8_t		nd_opt_ri_prefix_len;
	uint8_t		nd_opt_ri_prf_reserved;
	uint32_t	nd_opt_ri_lifetime;
	char		nd_opt_ri_prefix[0];
};

struct __nd_opt_rdnss { /* Recursive DNS Server */
	uint8_t		nd_opt_rdnss_type;
	uint8_t		nd_opt_rdnss_len;
	uint16_t	nd_opt_rdnss_reserved;
	uint32_t	nd_opt_rdnss_lifetime;
	char		nd_opt_rdnss_addresses[0];
};

struct __nd_opt_dnssl { /* DNS Search List */
	uint8_t		nd_opt_dnssl_type;
	uint8_t		nd_opt_dnssl_len;
	uint16_t	nd_opt_dnssl_reserved;
	uint32_t	nd_opt_dnssl_lifetime;
	char		nd_opt_dnssl_domains[0];
};


#endif /* _NDP_PRIVATE_H_ */
