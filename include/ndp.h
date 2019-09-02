/*
 *   ndp.h - Neighbour discovery library
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

#ifndef _NDP_H_
#define _NDP_H_

#include <stdarg.h>
#include <stdbool.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ndp;

void ndp_set_log_fn(struct ndp *ndp,
		    void (*log_fn)(struct ndp *ndp, int priority,
				   const char *file, int line, const char *fn,
				   const char *format, va_list args));
int ndp_get_log_priority(struct ndp *ndp);
void ndp_set_log_priority(struct ndp *ndp, int priority);

struct ndp_msg;
struct ndp_msgrs;
struct ndp_msgra;
struct ndp_msgns;
struct ndp_msgna;
struct ndp_msgr;

enum ndp_msg_type {
	NDP_MSG_RS, /* Router Solicitation */
	NDP_MSG_RA, /* Router Advertisement */
	NDP_MSG_NS, /* Neighbor Solicitation */
	NDP_MSG_NA, /* Neighbor Advertisement */
	NDP_MSG_R, /* Redirect */
	NDP_MSG_ALL, /* Matches all */
};

#define ND_OPT_NORMAL       0x0000    /* default, no change to ND message */
#define ND_OPT_NA_UNSOL     0x0001    /* Unsolicited Neighbour Advertisement */

enum ndp_route_preference {
	NDP_ROUTE_PREF_LOW = 3,
	NDP_ROUTE_PREF_MEDIUM = 0,
	NDP_ROUTE_PREF_HIGH = 1,
};

int ndp_msg_new(struct ndp_msg **p_msg, enum ndp_msg_type msg_type);
void ndp_msg_destroy(struct ndp_msg *msg);
void *ndp_msg_payload(struct ndp_msg *msg);
size_t ndp_msg_payload_maxlen(struct ndp_msg *msg);
size_t ndp_msg_payload_len(struct ndp_msg *msg);
void ndp_msg_payload_len_set(struct ndp_msg *msg, size_t len);
void *ndp_msg_payload_opts(struct ndp_msg *msg);
size_t ndp_msg_payload_opts_len(struct ndp_msg *msg);
struct ndp_msgrs *ndp_msgrs(struct ndp_msg *msg);
struct ndp_msgra *ndp_msgra(struct ndp_msg *msg);
struct ndp_msgns *ndp_msgns(struct ndp_msg *msg);
struct ndp_msgna *ndp_msgna(struct ndp_msg *msg);
struct ndp_msgr *ndp_msgr(struct ndp_msg *msg);
enum ndp_msg_type ndp_msg_type(struct ndp_msg *msg);
struct in6_addr *ndp_msg_addrto(struct ndp_msg *msg);
uint32_t ndp_msg_ifindex(struct ndp_msg *msg);
void ndp_msg_ifindex_set(struct ndp_msg *msg, uint32_t ifindex);
void ndp_msg_target_set(struct ndp_msg *msg, struct in6_addr *target);
void ndp_msg_dest_set(struct ndp_msg *msg, struct in6_addr *dest);
void ndp_msg_opt_set(struct ndp_msg *msg);
int ndp_msg_send(struct ndp *ndp, struct ndp_msg *msg);
int ndp_msg_send_with_flags(struct ndp *ndp, struct ndp_msg *msg, uint8_t flags);

uint8_t ndp_msgra_curhoplimit(struct ndp_msgra *msgra);
void ndp_msgra_curhoplimit_set(struct ndp_msgra *msgra, uint8_t curhoplimit);
bool ndp_msgra_flag_managed(struct ndp_msgra *msgra);
void ndp_msgra_flag_managed_set(struct ndp_msgra *msgra, bool flag_managed);
bool ndp_msgra_flag_other(struct ndp_msgra *msgra);
void ndp_msgra_flag_other_set(struct ndp_msgra *msgra, bool flag_other);
bool ndp_msgra_flag_home_agent(struct ndp_msgra *msgra);
void ndp_msgra_flag_home_agent_set(struct ndp_msgra *msgra,
				   bool flag_home_agent);
enum ndp_route_preference ndp_msgra_route_preference(struct ndp_msgra *msgra);
void ndp_msgra_route_preference_set(struct ndp_msgra *msgra,
				    enum ndp_route_preference pref);
uint16_t ndp_msgra_router_lifetime(struct ndp_msgra *msgra);
void ndp_msgra_router_lifetime_set(struct ndp_msgra *msgra,
				   uint16_t router_lifetime);
uint32_t ndp_msgra_reachable_time(struct ndp_msgra *msgra);
void ndp_msgra_reachable_time_set(struct ndp_msgra *msgra,
				  uint32_t reachable_time);
uint32_t ndp_msgra_retransmit_time(struct ndp_msgra *msgra);
void ndp_msgra_retransmit_time_set(struct ndp_msgra *msgra,
				   uint32_t retransmit_time);

bool ndp_msgna_flag_router(struct ndp_msgna *msgna);
void ndp_msgna_flag_router_set(struct ndp_msgna *msgna, bool flag_router);
bool ndp_msgna_flag_solicited(struct ndp_msgna *msgna);
void ndp_msgna_flag_solicited_set(struct ndp_msgna *msgna,
				  bool flag_solicited);
bool ndp_msgna_flag_override(struct ndp_msgna *msgna);
void ndp_msgna_flag_override_set(struct ndp_msgna *msgna, bool flag_override);

enum ndp_msg_opt_type {
	NDP_MSG_OPT_SLLADDR, /* Source Link-layer Address */
	NDP_MSG_OPT_TLLADDR, /* Target Link-layer Address */
	NDP_MSG_OPT_PREFIX, /* Prefix Information */
	NDP_MSG_OPT_REDIR, /* Redirected Header */
	NDP_MSG_OPT_MTU, /* MTU */
	NDP_MSG_OPT_ROUTE, /* Route Information */
	NDP_MSG_OPT_RDNSS, /* Recursive DNS Server */
	NDP_MSG_OPT_DNSSL, /* DNS Search List */
};

int ndp_msg_next_opt_offset(struct ndp_msg *msg, int offset,
			    enum ndp_msg_opt_type opt_type);

#define ndp_msg_opt_for_each_offset(offset, msg, type)			\
	for (offset = ndp_msg_next_opt_offset(msg, -1, type);		\
	     offset != -1;						\
	     offset = ndp_msg_next_opt_offset(msg, offset, type))

unsigned char *ndp_msg_opt_slladdr(struct ndp_msg *msg, int offset);
size_t ndp_msg_opt_slladdr_len(struct ndp_msg *msg, int offset);
unsigned char *ndp_msg_opt_tlladdr(struct ndp_msg *msg, int offset);
size_t ndp_msg_opt_tlladdr_len(struct ndp_msg *msg, int offset);

struct in6_addr *ndp_msg_opt_prefix(struct ndp_msg *msg, int offset);
uint8_t ndp_msg_opt_prefix_len(struct ndp_msg *msg, int offset);
uint32_t ndp_msg_opt_prefix_valid_time(struct ndp_msg *msg, int offset);
uint32_t ndp_msg_opt_prefix_preferred_time(struct ndp_msg *msg, int offset);
bool ndp_msg_opt_prefix_flag_on_link(struct ndp_msg *msg, int offset);
bool ndp_msg_opt_prefix_flag_auto_addr_conf(struct ndp_msg *msg, int offset);
bool ndp_msg_opt_prefix_flag_router_addr(struct ndp_msg *msg, int offset);

uint32_t ndp_msg_opt_mtu(struct ndp_msg *msg, int offset);

struct in6_addr *ndp_msg_opt_route_prefix(struct ndp_msg *msg, int offset);
uint8_t ndp_msg_opt_route_prefix_len(struct ndp_msg *msg, int offset);
uint32_t ndp_msg_opt_route_lifetime(struct ndp_msg *msg, int offset);
enum ndp_route_preference
ndp_msg_opt_route_preference(struct ndp_msg *msg, int offset);

uint32_t ndp_msg_opt_rdnss_lifetime(struct ndp_msg *msg, int offset);
struct in6_addr *ndp_msg_opt_rdnss_addr(struct ndp_msg *msg, int offset,
					int addr_index);

#define ndp_msg_opt_rdnss_for_each_addr(addr, addr_index, msg, offset)	\
	for (addr_index = 0,						\
	     addr = ndp_msg_opt_rdnss_addr(msg, offset, addr_index);	\
	     addr;							\
	     addr = ndp_msg_opt_rdnss_addr(msg, offset, ++addr_index))

uint32_t ndp_msg_opt_dnssl_lifetime(struct ndp_msg *msg, int offset);
char *ndp_msg_opt_dnssl_domain(struct ndp_msg *msg, int offset,
			       int domain_index);

#define ndp_msg_opt_dnssl_for_each_domain(domain, domain_index, msg, offset)	\
	for (domain_index = 0,							\
	     domain = ndp_msg_opt_dnssl_domain(msg, offset, domain_index);	\
	     domain;								\
	     domain = ndp_msg_opt_dnssl_domain(msg, offset, ++domain_index))

typedef int (*ndp_msgrcv_handler_func_t)(struct ndp *ndp, struct ndp_msg *msg,
					 void *priv);
int ndp_msgrcv_handler_register(struct ndp *ndp, ndp_msgrcv_handler_func_t func,
				enum ndp_msg_type msg_type, uint32_t ifindex,
				void *priv);
void ndp_msgrcv_handler_unregister(struct ndp *ndp, ndp_msgrcv_handler_func_t func,
				   enum ndp_msg_type msg_type, uint32_t ifindex,
				   void *priv);

int ndp_get_eventfd(struct ndp *ndp);
int ndp_call_eventfd_handler(struct ndp *ndp);
int ndp_callall_eventfd_handler(struct ndp *ndp);

int ndp_open(struct ndp **p_ndp);
void ndp_close(struct ndp *ndp);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _NDP_H_ */
