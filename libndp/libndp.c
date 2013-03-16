/*
 *   libndp.c - Neighbour discovery library
 *   Copyright (C) 2013 Jiri Pirko <jiri@resnulli.us>
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netdb.h>
#include <net/ethernet.h>
#include <ndp.h>

#include "ndp_private.h"
#include "list.h"

/**
 * SECTION: logging
 * @short_description: libndp logging facility
 */
void ndp_log(struct ndp *ndp, int priority,
	     const char *file, int line, const char *fn,
	     const char *format, ...)
{
	va_list args;

	va_start(args, format);
	ndp->log_fn(ndp, priority, file, line, fn, format, args);
	va_end(args);
}

static void log_stderr(struct ndp *ndp, int priority,
		       const char *file, int line, const char *fn,
		       const char *format, va_list args)
{
	fprintf(stderr, "libndp: %s: ", fn);
	vfprintf(stderr, format, args);
	fprintf(stderr, "\n");
}

static int log_priority(const char *priority)
{
	char *endptr;
	int prio;

	prio = strtol(priority, &endptr, 10);
	if (endptr[0] == '\0' || isspace(endptr[0]))
		return prio;
	if (strncmp(priority, "err", 3) == 0)
		return LOG_ERR;
	if (strncmp(priority, "info", 4) == 0)
		return LOG_INFO;
	if (strncmp(priority, "debug", 5) == 0)
		return LOG_DEBUG;
	return 0;
}

/**
 * ndp_set_log_fn:
 * @ndp: libndp library context
 * @log_fn: function to be called for logging messages
 *
 * The built-in logging writes to stderr. It can be
 * overridden by a custom function, to plug log messages
 * into the user's logging functionality.
 **/
NDP_EXPORT
void ndp_set_log_fn(struct ndp *ndp,
		    void (*log_fn)(struct ndp *ndp, int priority,
				   const char *file, int line, const char *fn,
				   const char *format, va_list args))
{
	ndp->log_fn = log_fn;
	dbg(ndp, "Custom logging function %p registered.", log_fn);
}

/**
 * ndp_get_log_priority:
 * @ndp: libndp library context
 *
 * Returns: the current logging priority.
 **/
NDP_EXPORT
int ndp_get_log_priority(struct ndp *ndp)
{
	return ndp->log_priority;
}

/**
 * ndp_set_log_priority:
 * @ndp: libndp library context
 * @priority: the new logging priority
 *
 * Set the current logging priority. The value controls which messages
 * are logged.
 **/
NDP_EXPORT
void ndp_set_log_priority(struct ndp *ndp, int priority)
{
	ndp->log_priority = priority;
}


/**
 * SECTION: helpers
 * @short_description: various internal helper functions
 */

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static void *myzalloc(size_t size)
{
	return calloc(1, size);
}

static int myrecvfrom6(int sockfd, void *buf, size_t *buflen, int flags,
		       struct sockaddr_in6 *src_addr, uint32_t *ifindex)
{
	unsigned char cbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
	struct iovec iovec;
	struct msghdr msghdr;
	struct cmsghdr *cmsghdr;
	ssize_t len;

	iovec.iov_len = *buflen;
	iovec.iov_base = buf;
	memset(&msghdr, 0, sizeof(msghdr));
	msghdr.msg_name = src_addr;
	msghdr.msg_namelen = sizeof(*src_addr);
	msghdr.msg_iov = &iovec;
	msghdr.msg_iovlen = 1;
	msghdr.msg_control = cbuf;
	msghdr.msg_controllen = sizeof(cbuf);

	len = recvmsg(sockfd, &msghdr, 0);
	if (len == -1)
		return -errno;
	*buflen = len;

	/* Set ifindex to scope_id now. But since scope_id gets not
	 * set by kernel for linklocal addresses, use pktinfo to obtain that
	 * value right after.
	 */
	*ifindex = src_addr->sin6_scope_id;
        for (cmsghdr = CMSG_FIRSTHDR(&msghdr); cmsghdr;
	     cmsghdr = CMSG_NXTHDR(&msghdr, cmsghdr)) {
		if (cmsghdr->cmsg_level == IPPROTO_IPV6 &&
		    cmsghdr->cmsg_type == IPV6_PKTINFO &&
		    cmsghdr->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo))) {
			struct in6_pktinfo *pktinfo;

			pktinfo = (struct in6_pktinfo *) CMSG_DATA(cmsghdr);
			*ifindex = pktinfo->ipi6_ifindex;
		}
	}

	return 0;
}

static char *ndp_str_sin6(struct ndp *ndp, struct sockaddr_in6 *addr)
{
	static char buf[NI_MAXHOST];
	int err;

	err = getnameinfo((struct sockaddr *) addr, sizeof(*addr),
			  buf, sizeof(buf), NULL, 0, NI_NUMERICHOST);
	if (err) {
		err(ndp, "getnameinfo failed: %s", gai_strerror(err));
		return NULL;
	}
	return buf;
}


/**
 * SECTION: NDP implementation
 * @short_description: functions that actually implements NDP
 */

static int ndp_sock_open(struct ndp *ndp)
{
	int sock;
	//struct icmp6_filter flt;
	int ret;
	int err;
	int val;

	sock = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (sock == -1) {
		err(ndp, "Failed to create ICMP6 socket.");
		return -errno;
	}

	val = 1;
	ret = setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO,
			 &val, sizeof(val));
	if (ret == -1) {
		err(ndp, "Failed to setsockopt IPV6_RECVPKTINFO.");
		err = -errno;
		goto close_sock;
	}

	ndp->sock = sock;
	return 0;
close_sock:
	close(sock);
	return err;
}

static void ndp_sock_close(struct ndp *ndp)
{
	close(ndp->sock);
}

struct ndp_msgrs {
};

struct ndp_msgra {
	struct nd_router_advert *ra;
	struct {
		bool		present;
		unsigned char	addr[ETH_ALEN];
	} opt_source_linkaddr;
	struct {
		bool		present;
		unsigned char	addr[ETH_ALEN];
	} opt_target_linkaddr;
	struct {
		bool		present;
		struct in6_addr	prefix;
		uint8_t		prefix_len;
		uint32_t	valid_time;
		uint32_t	preferred_time;
		bool		flag_onlink;
		bool		flag_auto;
		bool		flag_raddr;
	} opt_prefix;
	struct {
		bool		present;
		uint32_t	mtu;
	} opt_mtu;
};

/**
 * ndp_msgra_curhoplimit:
 * @msgra: RA message structure
 *
 * Get RA curhoplimit.
 *
 * Returns: curhoplimit.
 **/
NDP_EXPORT
uint8_t ndp_msgra_curhoplimit(struct ndp_msgra *msgra)
{
	return msgra->ra->nd_ra_curhoplimit;
}

/**
 * ndp_msgra_curhoplimit_set:
 * @msgra: RA message structure
 *
 * Set RA curhoplimit.
 **/
NDP_EXPORT
void ndp_msgra_curhoplimit_set(struct ndp_msgra *msgra, uint8_t curhoplimit)
{
	msgra->ra->nd_ra_curhoplimit = curhoplimit;
}

/**
 * ndp_msgra_flag_managed:
 * @msgra: RA message structure
 *
 * Get RA managed flag.
 *
 * Returns: managed flag.
 **/
NDP_EXPORT
bool ndp_msgra_flag_managed(struct ndp_msgra *msgra)
{
	return msgra->ra->nd_ra_flags_reserved & ND_RA_FLAG_MANAGED;
}

/**
 * ndp_msgra_flag_managed_set:
 * @msgra: RA message structure
 *
 * Set RA managed flag.
 **/
NDP_EXPORT
void ndp_msgra_flag_managed_set(struct ndp_msgra *msgra, bool flag_managed)
{
	if (flag_managed)
		msgra->ra->nd_ra_flags_reserved |= ND_RA_FLAG_MANAGED;
	else
		msgra->ra->nd_ra_flags_reserved &= ~ND_RA_FLAG_MANAGED;
}

/**
 * ndp_msgra_flag_other:
 * @msgra: RA message structure
 *
 * Get RA other flag.
 *
 * Returns: other flag.
 **/
NDP_EXPORT
bool ndp_msgra_flag_other(struct ndp_msgra *msgra)
{
	return msgra->ra->nd_ra_flags_reserved & ND_RA_FLAG_OTHER;
}

/**
 * ndp_msgra_flag_other_set:
 * @msgra: RA message structure
 *
 * Set RA other flag.
 **/
NDP_EXPORT
void ndp_msgra_flag_other_set(struct ndp_msgra *msgra, bool flag_other)
{
	if (flag_other)
		msgra->ra->nd_ra_flags_reserved |= ND_RA_FLAG_OTHER;
	else
		msgra->ra->nd_ra_flags_reserved &= ~ND_RA_FLAG_OTHER;
}

/**
 * ndp_msgra_flag_home_agent:
 * @msgra: RA message structure
 *
 * Get RA home_agent flag.
 *
 * Returns: home_agent flag.
 **/
NDP_EXPORT
bool ndp_msgra_flag_home_agent(struct ndp_msgra *msgra)
{
	return msgra->ra->nd_ra_flags_reserved & ND_RA_FLAG_HOME_AGENT;
}

/**
 * ndp_msgra_flag_home_agent_set:
 * @msgra: RA message structure
 *
 * Set RA home_agent flag.
 **/
NDP_EXPORT
void ndp_msgra_flag_home_agent_set(struct ndp_msgra *msgra,
				   bool flag_home_agent)
{
	if (flag_home_agent)
		msgra->ra->nd_ra_flags_reserved |= ND_RA_FLAG_HOME_AGENT;
	else
		msgra->ra->nd_ra_flags_reserved &= ~ND_RA_FLAG_HOME_AGENT;
}

/**
 * ndp_msgra_router_lifetime:
 * @msgra: RA message structure
 *
 * Get RA router lifetime.
 *
 * Returns: router lifetime in seconds.
 **/
NDP_EXPORT
uint16_t ndp_msgra_router_lifetime(struct ndp_msgra *msgra)
{
	return ntohs(msgra->ra->nd_ra_router_lifetime);
}

/**
 * ndp_msgra_router_lifetime_set:
 * @msgra: RA message structure
 *
 * Set RA router lifetime.
 **/
NDP_EXPORT
void ndp_msgra_router_lifetime_set(struct ndp_msgra *msgra,
				   uint16_t router_lifetime)
{
	msgra->ra->nd_ra_router_lifetime = htons(router_lifetime);
}

/**
 * ndp_msgra_reachable_time:
 * @msgra: RA message structure
 *
 * Get RA reachable time.
 *
 * Returns: reachable time in milliseconds.
 **/
NDP_EXPORT
uint32_t ndp_msgra_reachable_time(struct ndp_msgra *msgra)
{
	return ntohl(msgra->ra->nd_ra_reachable);
}

/**
 * ndp_msgra_reachable_time_set:
 * @msgra: RA message structure
 *
 * Set RA reachable time.
 **/
NDP_EXPORT
void ndp_msgra_reachable_time_set(struct ndp_msgra *msgra,
				  uint32_t reachable_time)
{
	msgra->ra->nd_ra_reachable = htonl(reachable_time);
}

/**
 * ndp_msgra_retransmit_time:
 * @msgra: RA message structure
 *
 * Get RA retransmit time.
 *
 * Returns: retransmit time in milliseconds.
 **/
NDP_EXPORT
uint32_t ndp_msgra_retransmit_time(struct ndp_msgra *msgra)
{
	return ntohl(msgra->ra->nd_ra_retransmit);
}

/**
 * ndp_msgra_retransmit_time_set:
 * @msgra: RA message structure
 *
 * Set RA retransmit time.
 **/
NDP_EXPORT
void ndp_msgra_retransmit_time_set(struct ndp_msgra *msgra,
				   uint32_t retransmit_time)
{
	msgra->ra->nd_ra_retransmit = htonl(retransmit_time);
}

/**
 * ndp_msgra_opt_source_linkaddr_present:
 * @msgra: RA message structure
 *
 * Find out if source linkaddr option is present.
 *
 * Returns: true if option is present.
 **/
NDP_EXPORT
bool ndp_msgra_opt_source_linkaddr_present(struct ndp_msgra *msgra)
{
	return msgra->opt_source_linkaddr.present;
}

/**
 * ndp_msgra_opt_source_linkaddr:
 * @msgra: RA message structure
 *
 * Get source linkaddr. User should check if source linkaddr option is
 * present before calling this.
 *
 * Returns: pointer to source linkaddr.
 **/
NDP_EXPORT
unsigned char *ndp_msgra_opt_source_linkaddr(struct ndp_msgra *msgra)
{
	return msgra->opt_source_linkaddr.addr;
}

/**
 * ndp_msgra_opt_source_linkaddr_len:
 * @msgra: RA message structure
 *
 * Get source linkaddr length. User should check if source linkaddr option is
 * present before calling this.
 *
 * Returns: source linkaddr length.
 **/
NDP_EXPORT
size_t ndp_msgra_opt_source_linkaddr_len(struct ndp_msgra *msgra)
{
	return sizeof(msgra->opt_source_linkaddr.addr);
}

/**
 * ndp_msgra_opt_target_linkaddr_present:
 * @msgra: RA message structure
 *
 * Find out if target linkaddr option is present.
 *
 * Returns: true if option is present.
 **/
NDP_EXPORT
bool ndp_msgra_opt_target_linkaddr_present(struct ndp_msgra *msgra)
{
	return msgra->opt_target_linkaddr.present;
}

/**
 * ndp_msgra_opt_target_linkaddr:
 * @msgra: RA message structure
 *
 * Get target linkaddr. User should check if target linkaddr option is
 * present before calling this.
 *
 * Returns: pointer to target linkaddr.
 **/
NDP_EXPORT
unsigned char *ndp_msgra_opt_target_linkaddr(struct ndp_msgra *msgra)
{
	return msgra->opt_target_linkaddr.addr;
}

/**
 * ndp_msgra_opt_target_linkaddr_len:
 * @msgra: RA message structure
 *
 * Get target linkaddr length. User should check if target linkaddr option is
 * present before calling this.
 *
 * Returns: target linkaddr length.
 **/
NDP_EXPORT
size_t ndp_msgra_opt_target_linkaddr_len(struct ndp_msgra *msgra)
{
	return sizeof(msgra->opt_target_linkaddr.addr);
}

/**
 * ndp_msgra_opt_prefix_present:
 * @msgra: RA message structure
 *
 * Find out if prefix option is present.
 *
 * Returns: true if option is present.
 **/
NDP_EXPORT
bool ndp_msgra_opt_prefix_present(struct ndp_msgra *msgra)
{
	return msgra->opt_prefix.present;
}

/**
 * ndp_msgra_opt_prefix:
 * @msgra: RA message structure
 *
 * Get prefix addr. User should check if prefix option is present before
 * calling this.
 *
 * Returns: pointer to address.
 **/
NDP_EXPORT
struct in6_addr *ndp_msgra_opt_prefix(struct ndp_msgra *msgra)
{
	return &msgra->opt_prefix.prefix;
}

/**
 * ndp_msgra_opt_prefix_len:
 * @msgra: RA message structure
 *
 * Get prefix length. User should check if prefix option is present before
 * calling this.
 *
 * Returns: length of prefix.
 **/
NDP_EXPORT
uint8_t ndp_msgra_opt_prefix_len(struct ndp_msgra *msgra)
{
	return msgra->opt_prefix.prefix_len;
}

/**
 * ndp_msgra_opt_prefix_valid_time:
 * @msgra: RA message structure
 *
 * Get prefix valid time. User should check if prefix option is present
 * before calling this.
 *
 * Returns: valid time in seconds, (uint32_t) -1 means infinity.
 **/
NDP_EXPORT
uint32_t ndp_msgra_opt_prefix_valid_time(struct ndp_msgra *msgra)
{
	return msgra->opt_prefix.valid_time;
}

/**
 * ndp_msgra_opt_prefix_preferred_time:
 * @msgra: RA message structure
 *
 * Get prefix preferred time. User should check if prefix option is present
 * before calling this.
 *
 * Returns: preferred time in seconds, (uint32_t) -1 means infinity.
 **/
NDP_EXPORT
uint32_t ndp_msgra_opt_prefix_preferred_time(struct ndp_msgra *msgra)
{
	return msgra->opt_prefix.preferred_time;
}

/**
 * ndp_msgra_opt_mtu_present:
 * @msgra: RA message structure
 *
 * Find out if mtu option is present.
 *
 * Returns: true if option is present.
 **/
NDP_EXPORT
bool ndp_msgra_opt_mtu_present(struct ndp_msgra *msgra)
{
	return msgra->opt_mtu.present;
}

/**
 * ndp_msgra_opt_mtu:
 * @msgra: RA message structure
 *
 * Get MTU. User should check if mtu option is present before calling this.
 *
 * Returns: MTU.
 **/
NDP_EXPORT
uint32_t ndp_msgra_opt_mtu(struct ndp_msgra *msgra)
{
	return msgra->opt_mtu.mtu;
}

struct ndp_msgns {
};

struct ndp_msgna {
};

struct ndp_msgr {
};

struct ndp_msg {
#define NDP_MSG_BUFLEN 1500
	unsigned char			buf[NDP_MSG_BUFLEN];
	size_t				len;
	struct in6_addr			addrto;
	uint32_t			ifindex;
	enum ndp_msg_type		type;
	struct icmp6_hdr *		icmp6_hdr;
	unsigned char *			opts_start; /* pointer to buf at the
						       place where opts start */
	union {
		struct ndp_msgrs	rs;
		struct ndp_msgra	ra;
		struct ndp_msgns	ns;
		struct ndp_msgna	na;
		struct ndp_msgr		r;
	} nd_msg;
};

struct ndp_msg_type_info {
	uint8_t raw_type;
	size_t raw_struct_size;
};

static struct ndp_msg_type_info ndp_msg_type_info_list[] =
{
	[NDP_MSG_RS] = {
		.raw_type = ND_ROUTER_SOLICIT,
		.raw_struct_size = sizeof(struct nd_router_solicit),
	},
	[NDP_MSG_RA] = {
		.raw_type = ND_ROUTER_ADVERT,
		.raw_struct_size = sizeof(struct nd_router_advert),
	},
	[NDP_MSG_NS] = {
		.raw_type = ND_NEIGHBOR_SOLICIT,
		.raw_struct_size = sizeof(struct nd_neighbor_solicit),
	},
	[NDP_MSG_NA] = {
		.raw_type = ND_NEIGHBOR_ADVERT,
		.raw_struct_size = sizeof(struct nd_neighbor_advert),
	},
	[NDP_MSG_R] = {
		.raw_type = ND_REDIRECT,
		.raw_struct_size = sizeof(struct nd_redirect),
	},
};

#define NDP_MSG_TYPE_LIST_SIZE ARRAY_SIZE(ndp_msg_type_info_list)

struct ndp_msg_type_info *ndp_msg_type_info(enum ndp_msg_type msg_type)
{
	return &ndp_msg_type_info_list[msg_type];
}

static int ndp_msg_type_by_raw_type(enum ndp_msg_type *p_msg_type,
				    uint8_t raw_type)
{
	int i;

	for (i = 0; i < NDP_MSG_TYPE_LIST_SIZE; i++) {
		if (ndp_msg_type_info(i)->raw_type == raw_type) {
			*p_msg_type = i;
			return 0;
		}
	}
	return -ENOENT;
}

static struct ndp_msg *ndp_msg_alloc(void)
{
	struct ndp_msg *msg;

	msg = myzalloc(sizeof(*msg));
	if (!msg)
		return NULL;
	msg->len = sizeof(msg->buf);
	msg->icmp6_hdr = (struct icmp6_hdr *) msg->buf;
	return msg;
}

static void ndp_msg_init(struct ndp_msg *msg, enum ndp_msg_type msg_type)
{
	msg->type = msg_type;
	msg->opts_start = msg->buf +
			  ndp_msg_type_info(msg_type)->raw_struct_size;
}

/**
 * ndp_msg_new:
 * @p_msg: pointer where new message structure address will be stored
 * @msg_type: message type
 *
 * Allocate new message structure of a specified type and initialize it.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
NDP_EXPORT
int ndp_msg_new(struct ndp_msg **p_msg, enum ndp_msg_type msg_type)
{
	struct ndp_msg *msg;

	if (msg_type == NDP_MSG_ALL)
		return -EINVAL;
	msg = ndp_msg_alloc();
	if (!msg)
		return -ENOMEM;
	ndp_msg_init(msg, msg_type);
	return 0;
}

/**
 * ndp_msg_destroy:
 *
 * Destroy message structure.
 **/
NDP_EXPORT
void ndp_msg_destroy(struct ndp_msg *msg)
{
	free(msg);
}

/**
 * ndp_msg_payload:
 * @msg: message structure
 *
 * Get raw Neighbour discovery packet data.
 *
 * Returns: pointer to raw data.
 **/
NDP_EXPORT
void *ndp_msg_payload(struct ndp_msg *msg)
{
	return msg->buf;
}

/**
 * ndp_msg_payload_len:
 * @msg: message structure
 *
 * Get raw Neighbour discovery packet data length.
 *
 * Returns: length in bytes.
 **/
NDP_EXPORT
size_t ndp_msg_payload_len(struct ndp_msg *msg)
{
	return msg->len;
}

/**
 * ndp_msg_payload_len_set:
 * @msg: message structure
 *
 * Set raw Neighbour discovery packet data length.
 **/
NDP_EXPORT
void ndp_msg_payload_len_set(struct ndp_msg *msg, size_t len)
{
	if (len > sizeof(msg->buf))
		len = sizeof(msg->buf);
	msg->len = len;
}

/**
 * ndp_msg_payload_opts:
 * @msg: message structure
 *
 * Get raw Neighbour discovery packet options part data.
 *
 * Returns: pointer to raw data.
 **/
NDP_EXPORT
void *ndp_msg_payload_opts(struct ndp_msg *msg)
{
	return msg->opts_start;
}

/**
 * ndp_msg_payload_opts_len:
 * @msg: message structure
 *
 * Get raw Neighbour discovery packet options part data length.
 *
 * Returns: length in bytes.
 **/
NDP_EXPORT
size_t ndp_msg_payload_opts_len(struct ndp_msg *msg)
{
	return msg->len - (msg->opts_start - msg->buf);
}

/**
 * ndp_msgrs:
 * @msg: message structure
 *
 * Get RS message structure by passed @msg.
 *
 * Returns: RS message structure or NULL in case the message is not of type RS.
 **/
NDP_EXPORT
struct ndp_msgrs *ndp_msgrs(struct ndp_msg *msg)
{
	if (ndp_msg_type(msg) != NDP_MSG_RS)
		return NULL;
	return &msg->nd_msg.rs;
}

/**
 * ndp_msgra:
 * @msg: message structure
 *
 * Get RA message structure by passed @msg.
 *
 * Returns: RA message structure or NULL in case the message is not of type RA.
 **/
NDP_EXPORT
struct ndp_msgra *ndp_msgra(struct ndp_msg *msg)
{
	if (ndp_msg_type(msg) != NDP_MSG_RA)
		return NULL;
	return &msg->nd_msg.ra;
}

/**
 * ndp_msgns:
 * @msg: message structure
 *
 * Get NS message structure by passed @msg.
 *
 * Returns: NS message structure or NULL in case the message is not of type NS.
 **/
NDP_EXPORT
struct ndp_msgns *ndp_msgns(struct ndp_msg *msg)
{
	if (ndp_msg_type(msg) != NDP_MSG_NS)
		return NULL;
	return &msg->nd_msg.ns;
}

/**
 * ndp_msgna:
 * @msg: message structure
 *
 * Get NA message structure by passed @msg.
 *
 * Returns: NA message structure or NULL in case the message is not of type NA.
 **/
NDP_EXPORT
struct ndp_msgna *ndp_msgna(struct ndp_msg *msg)
{
	if (ndp_msg_type(msg) != NDP_MSG_NA)
		return NULL;
	return &msg->nd_msg.na;
}

/**
 * ndp_msgr:
 * @msg: message structure
 *
 * Get R message structure by passed @msg.
 *
 * Returns: R message structure or NULL in case the message is not of type R.
 **/
NDP_EXPORT
struct ndp_msgr *ndp_msgr(struct ndp_msg *msg)
{
	if (ndp_msg_type(msg) != NDP_MSG_R)
		return NULL;
	return &msg->nd_msg.r;
}

/**
 * ndp_msg_type:
 * @msg: message structure
 *
 * Get type of message.
 *
 * Returns: Message type
 **/
NDP_EXPORT
enum ndp_msg_type ndp_msg_type(struct ndp_msg *msg)
{
	return msg->type;
}

/**
 * ndp_msg_addrto:
 * @msg: message structure
 *
 * Get "to address" of message.
 *
 * Returns: pointer to address.
 **/
NDP_EXPORT
struct in6_addr *ndp_msg_addrto(struct ndp_msg *msg)
{
	return &msg->addrto;
}

/**
 * ndp_msg_ifindex:
 * @msg: message structure
 *
 * Get interface index of message.
 *
 * Returns: Inteface index
 **/
NDP_EXPORT
uint32_t ndp_msg_ifindex(struct ndp_msg *msg)
{
	return msg->ifindex;
}

static int ndp_call_handlers(struct ndp *ndp, struct ndp_msg *msg);

static int ndp_process_rs(struct ndp *ndp, struct ndp_msg *msg)
{
	//struct ndp_msgrs msgrs = ndp_msgrs(msg);
	size_t len = ndp_msg_payload_len(msg);

	dbg(ndp, "rcvd RS, len: %luB", len);
	return ndp_call_handlers(ndp, msg);;
}

static int ndp_process_ra_opt(struct ndp_msgra *msgra, unsigned char *opt_data,
			      uint8_t opt_type, uint8_t opt_len)
{
	if (opt_type == ND_OPT_SOURCE_LINKADDR) {
		if (opt_len != 8)
			return 0; /* unsupported address length */
		memcpy(msgra->opt_source_linkaddr.addr, &opt_data[2],
		       sizeof(msgra->opt_source_linkaddr));
		msgra->opt_source_linkaddr.present = true;
	} else if (opt_type == ND_OPT_TARGET_LINKADDR) {
		if (opt_len != 8)
			return 0; /* unsupported address length */
		memcpy(msgra->opt_target_linkaddr.addr, &opt_data[2],
		       sizeof(msgra->opt_target_linkaddr));
		msgra->opt_target_linkaddr.present = true;
	} else if (opt_type == ND_OPT_PREFIX_INFORMATION) {
		struct nd_opt_prefix_info *pi;

		pi = (struct nd_opt_prefix_info *) opt_data;
		msgra->opt_prefix.prefix = pi->nd_opt_pi_prefix;
		msgra->opt_prefix.prefix_len = pi->nd_opt_pi_prefix_len;
		msgra->opt_prefix.valid_time = ntohl(pi->nd_opt_pi_valid_time);
		msgra->opt_prefix.preferred_time =
			ntohl(pi->nd_opt_pi_preferred_time);
		msgra->opt_prefix.flag_onlink =
			pi->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_ONLINK;
		msgra->opt_prefix.flag_auto =
			pi->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_AUTO;
		msgra->opt_prefix.flag_raddr =
			pi->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_RADDR;
		msgra->opt_prefix.present = true;
	} else if (opt_type == ND_OPT_MTU) {
		struct nd_opt_mtu *mtu;

		mtu = (struct nd_opt_mtu *) opt_data;
		msgra->opt_mtu.mtu = ntohl(mtu->nd_opt_mtu_mtu);
		msgra->opt_mtu.present = true;
	}
	return 0;
}

static int ndp_process_ra(struct ndp *ndp, struct ndp_msg *msg)
{
	struct ndp_msgra *msgra = ndp_msgra(msg);
	size_t len = ndp_msg_payload_len(msg);
	unsigned char *ptr;

	dbg(ndp, "rcvd RA, len: %luB", len);
	if (len < sizeof(msgra->ra)) {
		warn(ndp, "rcvd RA packet too short (%luB)", len);
		return 0;
	}
	msgra->ra = ndp_msg_payload(msg);

	ptr = ndp_msg_payload_opts(msg);
	len = ndp_msg_payload_opts_len(msg);
	while (len > 0) {
		int err;
		uint8_t opt_type = ptr[0];
		uint8_t opt_len = ptr[1] << 3; /* convert to bytes */

		if (!opt_len || len < opt_len)
			break;
		err = ndp_process_ra_opt(msgra, ptr, opt_type, opt_len);
		if (err)
			return err;
		ptr += opt_len;
		len -= opt_len;
	}

	return ndp_call_handlers(ndp, msg);;
}

static int ndp_process_ns(struct ndp *ndp, struct ndp_msg *msg)
{
	//struct ndp_msgns msgns = ndp_msgns(msg);
	size_t len = ndp_msg_payload_len(msg);

	dbg(ndp, "rcvd NS, len: %luB", len);
	return ndp_call_handlers(ndp, msg);;
}

static int ndp_process_na(struct ndp *ndp, struct ndp_msg *msg)
{
	//struct ndp_msgna msgna = ndp_msgna(msg);
	size_t len = ndp_msg_payload_len(msg);

	dbg(ndp, "rcvd NA, len: %luB", len);
	return ndp_call_handlers(ndp, msg);;
}

static int ndp_process_r(struct ndp *ndp, struct ndp_msg *msg)
{
	//struct ndp_msgr msgr = ndp_msgr(msg);
	size_t len = ndp_msg_payload_len(msg);

	dbg(ndp, "rcvd R, len: %luB", len);
	return ndp_call_handlers(ndp, msg);;
}

static int ndp_sock_recv(struct ndp *ndp)
{
	struct sockaddr_in6 src_addr;
	uint32_t ifindex = ifindex;
	struct ndp_msg *msg;
	enum ndp_msg_type msg_type;
	size_t len = sizeof(msg->buf);
	int err;

	msg = ndp_msg_alloc();
	if (!msg)
		return -ENOMEM;

	err = myrecvfrom6(ndp->sock, msg->buf, &len, 0, &src_addr, &ifindex);
	if (err) {
		err(ndp, "Failed to receive message");
		goto free_msg;
	}
	dbg(ndp, "rcvd from: %s, ifindex: %u",
		 ndp_str_sin6(ndp, &src_addr), ifindex);

	msg->addrto = src_addr.sin6_addr;
	msg->ifindex = ifindex;
	ndp_msg_payload_len_set(msg, len);

	if (len < sizeof(*msg->icmp6_hdr)) {
		warn(ndp, "rcvd icmp6 packet too short (%luB)", len);
		err = 0;
		goto free_msg;
	}
	err = ndp_msg_type_by_raw_type(&msg_type, msg->icmp6_hdr->icmp6_type);
	if (err)
		goto free_msg;
	ndp_msg_init(msg, msg_type);

	switch (msg->icmp6_hdr->icmp6_type) {
	case ND_ROUTER_SOLICIT:
		err = ndp_process_rs(ndp, msg);
		break;
	case ND_ROUTER_ADVERT:
		err = ndp_process_ra(ndp, msg);
		break;
	case ND_NEIGHBOR_SOLICIT:
		err = ndp_process_ns(ndp, msg);
		break;
	case ND_NEIGHBOR_ADVERT:
		err = ndp_process_na(ndp, msg);
	case ND_REDIRECT:
		err = ndp_process_r(ndp, msg);
		break;
	}

free_msg:
	ndp_msg_destroy(msg);
	return err;
}


/**
 * SECTION: msgrcv handler
 * @short_description: msgrcv handler and related stuff
 */

struct ndp_msgrcv_handler_item {
	struct list_item			list;
	ndp_msgrcv_handler_func_t		func;
	enum ndp_msg_type			msg_type;
	uint32_t				ifindex;
	void *					priv;
};

static struct ndp_msgrcv_handler_item *
ndp_find_msgrcv_handler_item(struct ndp *ndp,
			     ndp_msgrcv_handler_func_t func,
			     enum ndp_msg_type msg_type, uint32_t ifindex,
			     void *priv)
{
	struct ndp_msgrcv_handler_item *handler_item;

	list_for_each_node_entry(handler_item, &ndp->msgrcv_handler_list, list)
		if (handler_item->func == func &&
		    handler_item->msg_type == msg_type &&
		    handler_item->ifindex == ifindex &&
		    handler_item->priv == priv)
			return handler_item;
	return NULL;
}

static int ndp_call_handlers(struct ndp *ndp, struct ndp_msg *msg)
{
	struct ndp_msgrcv_handler_item *handler_item;
	int err;

	list_for_each_node_entry(handler_item,
				 &ndp->msgrcv_handler_list, list) {
		if (handler_item->msg_type != NDP_MSG_ALL &&
		    handler_item->msg_type != msg->type)
			continue;
		if (handler_item->ifindex &&
		    handler_item->ifindex != msg->ifindex)
			continue;
		err = handler_item->func(ndp, msg, handler_item->priv);
		if (err)
			return err;
	}
	return 0;
}

/**
 * ndp_msgrcv_handler_register:
 * @ndp: libndp library context
 * @func: handler function for received messages
 * @msg_type: message type to match
 * @ifindex: interface index to match
 * @priv: func private data
 *
 * Registers custom @func handler which is going to be called when
 * specified @msg_type is received. If one wants the function to be
 * called for all message types, pass NDP_MSG_ALL,
 * Note that @ifindex can be set to filter only messages received on
 * specified interface. For @func to be called for messages received on
 * all interfaces, just set 0.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
NDP_EXPORT
int ndp_msgrcv_handler_register(struct ndp *ndp, ndp_msgrcv_handler_func_t func,
				enum ndp_msg_type msg_type, uint32_t ifindex,
				void *priv)
{
	struct ndp_msgrcv_handler_item *handler_item;

	if (ndp_find_msgrcv_handler_item(ndp, func, msg_type,
					 ifindex, priv))
		return -EEXIST;
	if (!func)
		return -EINVAL;
	handler_item = malloc(sizeof(*handler_item));
	if (!handler_item)
		return -ENOMEM;
	handler_item->func = func;
	handler_item->msg_type = msg_type;
	handler_item->ifindex = ifindex;
	handler_item->priv = priv;
	list_add_tail(&ndp->msgrcv_handler_list, &handler_item->list);
	return 0;
}

/**
 * ndp_msgrcv_handler_unregister:
 * @ndp: libndp library context
 * @func: handler function for received messages
 * @msg_type: message type to match
 * @ifindex: interface index to match
 * @priv: func private data
 *
 * Unregisters custom @func handler.
 *
 **/
NDP_EXPORT
void ndp_msgrcv_handler_unregister(struct ndp *ndp, ndp_msgrcv_handler_func_t func,
				   enum ndp_msg_type msg_type, uint32_t ifindex,
				   void *priv)
{
	struct ndp_msgrcv_handler_item *handler_item;

	handler_item = ndp_find_msgrcv_handler_item(ndp, func, msg_type,
						    ifindex, priv);
	if (!handler_item)
		return;
	list_del(&handler_item->list);
	free(handler_item);
}


/**
 * SECTION: event fd
 * @short_description: event filedescriptor related stuff
 */

struct ndp_eventfd {
	int (*get_fd)(struct ndp *ndp);
	int (*event_handler)(struct ndp *ndp);
};

static int ndp_sock_fd(struct ndp *ndp)
{
	return ndp->sock;
}

static struct ndp_eventfd ndp_eventfd = {
	.get_fd = ndp_sock_fd,
	.event_handler = ndp_sock_recv,
};

/**
 * ndp_get_next_eventfd:
 * @ndp: libndp library context
 * @eventfd: eventfd structure
 *
 * Get next eventfd in list.
 *
 * Returns: eventfd next to @eventfd passed.
 **/
NDP_EXPORT
struct ndp_eventfd *ndp_get_next_eventfd(struct ndp *ndp,
					 struct ndp_eventfd *eventfd)
{
	if (eventfd)
		return NULL;
	return &ndp_eventfd;
}

/**
 * ndp_get_eventfd_fd:
 * @ndp: libndp library context
 * @eventfd: eventfd structure
 *
 * Get eventfd filedesctiptor.
 *
 * Returns: fd.
 **/
NDP_EXPORT
int ndp_get_eventfd_fd(struct ndp *ndp, struct ndp_eventfd *eventfd)
{
	return eventfd->get_fd(ndp);
}

/**
 * ndp_call_eventfd_handler:
 * @ndp: libndp library context
 * @eventfd: eventfd structure
 *
 * Call eventfd handler.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
NDP_EXPORT
int ndp_call_eventfd_handler(struct ndp *ndp, struct ndp_eventfd *eventfd)
{
	return eventfd->event_handler(ndp);
}


/**
 * SECTION: Exported context functions
 * @short_description: Core context functions exported to user
 */

/**
 * ndp_open:
 * @p_ndp: pointer where new libndp library context address will be stored
 *
 * Allocates and initializes library context, opens raw socket.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
NDP_EXPORT
int ndp_open(struct ndp **p_ndp)
{
	struct ndp *ndp;
	const char *env;
	int err;

	ndp = myzalloc(sizeof(*ndp));
	if (!ndp)
		return -ENOMEM;
	ndp->log_fn = log_stderr;
	ndp->log_priority = LOG_ERR;
	/* environment overwrites config */
	env = getenv("NDP_LOG");
	if (env != NULL)
		ndp_set_log_priority(ndp, log_priority(env));

	dbg(ndp, "ndp context %p created.", ndp);
	dbg(ndp, "log_priority=%d", ndp->log_priority);

	list_init(&ndp->msgrcv_handler_list);
	err = ndp_sock_open(ndp);
	if (err)
		goto free_ndp;

	*p_ndp = ndp;
	return 0;
free_ndp:
	free(ndp);
	return err;
}

/**
 * ndp_close:
 * @ndp: libndp library context
 *
 * Do library context cleanup.
 **/
NDP_EXPORT
void ndp_close(struct ndp *ndp)
{
	ndp_sock_close(ndp);
	free(ndp);
}

