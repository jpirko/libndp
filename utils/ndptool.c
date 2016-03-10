/*
 *   ndptool.c - Neighbour discovery tool
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ndp.h>

enum verbosity_level {
	VERB1,
	VERB2,
	VERB3,
	VERB4,
};

#define DEFAULT_VERB VERB1
static int g_verbosity = DEFAULT_VERB;

static uint8_t flags = ND_OPT_NORMAL;

#define pr_err(args...) fprintf(stderr, ##args)
#define pr_outx(verb_level, args...)			\
	do {						\
		if (verb_level <= g_verbosity)		\
			fprintf(stdout, ##args);	\
	} while (0)
#define pr_out(args...) pr_outx(DEFAULT_VERB, ##args)
#define pr_out2(args...) pr_outx(VERB2, ##args)
#define pr_out3(args...) pr_outx(VERB3, ##args)
#define pr_out4(args...) pr_outx(VERB4, ##args)

static void empty_signal_handler(int signal)
{
}

static int run_main_loop(struct ndp *ndp)
{
	fd_set rfds;
	fd_set rfds_tmp;
	int fdmax;
	int ret;
	struct sigaction siginfo;
	sigset_t mask;
	int ndp_fd;
	int err = 0;

	sigemptyset(&siginfo.sa_mask);
	siginfo.sa_flags = 0;
	siginfo.sa_handler = empty_signal_handler;
	ret = sigaction(SIGINT, &siginfo, NULL);
	if (ret == -1) {
		pr_err("Failed to set SIGINT handler\n");
		return -errno;
	}
	ret = sigaction(SIGQUIT, &siginfo, NULL);
	if (ret == -1) {
		pr_err("Failed to set SIGQUIT handler\n");
		return -errno;
	}
	ret = sigaction(SIGTERM, &siginfo, NULL);
	if (ret == -1) {
		pr_err("Failed to set SIGTERM handler\n");
		return -errno;
	}

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGQUIT);
	sigaddset(&mask, SIGTERM);

	ret = sigprocmask(SIG_BLOCK, &mask, NULL);
	if (ret == -1) {
		pr_err("Failed to set blocked signals\n");
		return -errno;
	}

	sigemptyset(&mask);

	FD_ZERO(&rfds);
	ndp_fd = ndp_get_eventfd(ndp);
	FD_SET(ndp_fd, &rfds);
	fdmax = ndp_fd + 1;

	for (;;) {
		rfds_tmp = rfds;
		ret = pselect(fdmax, &rfds_tmp, NULL, NULL, NULL, &mask);
		if (ret == -1) {
			if (errno == EINTR) {
				goto out;
			}
			pr_err("Select failed\n");
			err = -errno;
			goto out;
		}
		if (FD_ISSET(ndp_fd, &rfds_tmp)) {
			err = ndp_call_eventfd_handler(ndp);
			if (err) {
				pr_err("ndp eventfd handler call failed\n");
				return err;
			}
		}
	}
out:
	return err;
}

static void print_help(const char *argv0) {
	pr_out(
            "%s [options] command\n"
            "\t-h --help                Show this help\n"
            "\t-v --verbose             Increase output verbosity\n"
            "\t-t --msg-type=TYPE       Specify message type\n"
	    "\t                         (\"rs\", \"ra\", \"ns\", \"na\")\n"
            "\t-i --ifname=IFNAME       Specify interface name\n"
            "\t-U --unsolicited         Send Unsolicited NA\n"
	    "Available commands:\n"
	    "\tmonitor\n"
	    "\tsend\n",
            argv0);
}

static const char *str_in6_addr(struct in6_addr *addr)
{
	static char buf[INET6_ADDRSTRLEN];

	return inet_ntop(AF_INET6, addr, buf, sizeof(buf));
}

static void pr_out_hwaddr(unsigned char *hwaddr, size_t len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (i)
			pr_out(":");
		pr_out("%02x", hwaddr[i]);
	}
	pr_out("\n");
}

static void pr_out_route_preference(enum ndp_route_preference pref)
{
	switch (pref) {
	case NDP_ROUTE_PREF_LOW:
		pr_out("low");
		break;
	case NDP_ROUTE_PREF_MEDIUM:
		pr_out("medium");
		break;
	case NDP_ROUTE_PREF_HIGH:
		pr_out("high");
		break;
	}
}

static void pr_out_lft(uint32_t lifetime)
{
	if (lifetime == (uint32_t) -1)
		pr_out("infinity");
	else
		pr_out("%us", lifetime);
}

static int msgrcv_handler_func(struct ndp *ndp, struct ndp_msg *msg, void *priv)
{
	char ifname[IF_NAMESIZE];
	enum ndp_msg_type msg_type = ndp_msg_type(msg);
	int offset;

	if_indextoname(ndp_msg_ifindex(msg), ifname);
	pr_out("NDP payload len %zu, from addr: %s, iface: %s\n",
	       ndp_msg_payload_len(msg),
	       str_in6_addr(ndp_msg_addrto(msg)), ifname);
	if (msg_type == NDP_MSG_RS) {
		pr_out("  Type: RS\n");
	} else if (msg_type == NDP_MSG_RA) {
		struct ndp_msgra *msgra = ndp_msgra(msg);

		pr_out("  Type: RA\n");
		pr_out("  Hop limit: %u\n", ndp_msgra_curhoplimit(msgra));
		pr_out("  Managed address configuration: %s\n",
		       ndp_msgra_flag_managed(msgra) ? "yes" : "no");
		pr_out("  Other configuration: %s\n",
		       ndp_msgra_flag_other(msgra) ? "yes" : "no");
		pr_out("  Default router preference: ");
		pr_out_route_preference(ndp_msgra_route_preference(msgra));
		pr_out("\n");
		pr_out("  Router lifetime: %us\n",
		       ndp_msgra_router_lifetime(msgra));
		pr_out("  Reachable time: ");
		if (ndp_msgra_reachable_time(msgra)) {
			pr_out("%ums\n",
			       ndp_msgra_reachable_time(msgra));
		} else {
			pr_out("unspecified\n");
		}
		pr_out("  Retransmit time: ");
		if (ndp_msgra_retransmit_time(msgra)) {
			pr_out("%ums\n",
			       ndp_msgra_retransmit_time(msgra));
		} else {
			pr_out("unspecified\n");
		}

		ndp_msg_opt_for_each_offset(offset, msg, NDP_MSG_OPT_SLLADDR) {
			pr_out("  Source linkaddr: ");
			pr_out_hwaddr(ndp_msg_opt_slladdr(msg, offset),
				      ndp_msg_opt_slladdr_len(msg, offset));
		}
		ndp_msg_opt_for_each_offset(offset, msg, NDP_MSG_OPT_TLLADDR) {
			pr_out("  Target linkaddr: ");
			pr_out_hwaddr(ndp_msg_opt_tlladdr(msg, offset),
				      ndp_msg_opt_tlladdr_len(msg, offset));
		}
		ndp_msg_opt_for_each_offset(offset, msg, NDP_MSG_OPT_PREFIX) {
			uint32_t valid_time;
			uint32_t preferred_time;

			valid_time = ndp_msg_opt_prefix_valid_time(msg, offset);
			preferred_time = ndp_msg_opt_prefix_preferred_time(msg, offset);
			pr_out("  Prefix: %s/%u",
			       str_in6_addr(ndp_msg_opt_prefix(msg, offset)),
			       ndp_msg_opt_prefix_len(msg, offset));
			pr_out(", valid_time: ");
			if (valid_time == (uint32_t) -1)
				pr_out("infinity");
			else
				pr_out("%us", valid_time);
			pr_out(", preferred_time: ");
			if (preferred_time == (uint32_t) -1)
				pr_out("infinity");
			else
				pr_out("%us", preferred_time);
			pr_out(", on_link: %s",
			       ndp_msg_opt_prefix_flag_on_link(msg, offset) ? "yes" : "no");
			pr_out(", autonomous_addr_conf: %s",
			       ndp_msg_opt_prefix_flag_auto_addr_conf(msg, offset) ? "yes" : "no");
			pr_out(", router_addr: %s",
			       ndp_msg_opt_prefix_flag_router_addr(msg, offset) ? "yes" : "no");
			pr_out("\n");
		}
		ndp_msg_opt_for_each_offset(offset, msg, NDP_MSG_OPT_MTU)
			pr_out("  MTU: %u\n", ndp_msg_opt_mtu(msg, offset));
		ndp_msg_opt_for_each_offset(offset, msg, NDP_MSG_OPT_ROUTE) {
			pr_out("  Route: %s/%u",
			       str_in6_addr(ndp_msg_opt_route_prefix(msg, offset)),
			       ndp_msg_opt_route_prefix_len(msg, offset));
			pr_out(", lifetime: ");
			pr_out_lft(ndp_msg_opt_route_lifetime(msg, offset));
			pr_out(", preference: ");
			pr_out_route_preference(ndp_msg_opt_route_preference(msg, offset));
			pr_out("\n");
		}
		ndp_msg_opt_for_each_offset(offset, msg, NDP_MSG_OPT_RDNSS) {
			static struct in6_addr *addr;
			int addr_index;

			pr_out("  Recursive DNS Servers: ");
			ndp_msg_opt_rdnss_for_each_addr(addr, addr_index, msg, offset) {
				if (addr_index != 0)
					pr_out(", ");
				pr_out("%s", str_in6_addr(addr));
			}
			pr_out(", lifetime: ");
			pr_out_lft(ndp_msg_opt_rdnss_lifetime(msg, offset));
			pr_out("\n");
		}
		ndp_msg_opt_for_each_offset(offset, msg, NDP_MSG_OPT_DNSSL) {
			char *domain;
			int domain_index;

			pr_out("  DNS Search List: ");
			ndp_msg_opt_dnssl_for_each_domain(domain, domain_index, msg, offset) {
				if (domain_index != 0)
					pr_out(" ");
				pr_out("%s", domain);
			}
			pr_out(", lifetime: ");
			pr_out_lft(ndp_msg_opt_rdnss_lifetime(msg, offset));
			pr_out("\n");
		}
	} else if (msg_type == NDP_MSG_NS) {
		pr_out("  Type: NS\n");
	} else if (msg_type == NDP_MSG_NA) {
		pr_out("  Type: NA\n");
	} else if (msg_type == NDP_MSG_R) {
		pr_out("  Type: R\n");
	} else {
		return 0;
	}
	return 0;
}

static int run_cmd_monitor(struct ndp *ndp, enum ndp_msg_type msg_type,
			   uint32_t ifindex)
{
	int err;

	err = ndp_msgrcv_handler_register(ndp, &msgrcv_handler_func, msg_type,
					  ifindex, NULL);
	if (err) {
		pr_err("Failed to register msgrcv handler\n");
		return err;
	}
	err = run_main_loop(ndp);
	ndp_msgrcv_handler_unregister(ndp, &msgrcv_handler_func, msg_type,
				      ifindex, NULL);
	return err;
}

static int run_cmd_send(struct ndp *ndp, enum ndp_msg_type msg_type,
			uint32_t ifindex)
{
	struct ndp_msg *msg;
	int err;

	err = ndp_msg_new(&msg, msg_type);
	if (err) {
		pr_err("Failed to create message\n");
		return err;
	}
	ndp_msg_ifindex_set(msg, ifindex);

	err = ndp_msg_send_with_flags(ndp, msg, flags);
	if (err) {
		pr_err("Failed to send message\n");
		goto msg_destroy;
	}

msg_destroy:
	ndp_msg_destroy(msg);
	return err;
}


static int get_msg_type(enum ndp_msg_type *p_msg_type, char *msgtypestr)
{
	if (!msgtypestr)
		*p_msg_type = NDP_MSG_ALL;
	else if (!strcmp(msgtypestr, "rs"))
		*p_msg_type = NDP_MSG_RS;
	else if (!strcmp(msgtypestr, "ra"))
		*p_msg_type = NDP_MSG_RA;
	else if (!strcmp(msgtypestr, "ns"))
		*p_msg_type = NDP_MSG_NS;
	else if (!strcmp(msgtypestr, "na"))
		*p_msg_type = NDP_MSG_NA;
	else if (!strcmp(msgtypestr, "r"))
		*p_msg_type = NDP_MSG_R;
	else
		return -EINVAL;
	return 0;
}

int main(int argc, char **argv)
{
	char *argv0 = argv[0];
	static const struct option long_options[] = {
		{ "help",	no_argument,		NULL, 'h' },
		{ "verbose",	no_argument,		NULL, 'v' },
		{ "msg-type",	required_argument,	NULL, 't' },
		{ "ifname",	required_argument,	NULL, 'i' },
		{ "unsolicited",no_argument,		NULL, 'U' },
		{ NULL, 0, NULL, 0 }
	};
	int opt;
	struct ndp *ndp;
	char *msgtypestr = NULL;
	enum ndp_msg_type msg_type;
	char *ifname = NULL;
	uint32_t ifindex;
	char *cmd_name;
	int err;
	int res = EXIT_FAILURE;

	while ((opt = getopt_long(argc, argv, "hvt:i:U",
				  long_options, NULL)) >= 0) {

		switch(opt) {
		case 'h':
			print_help(argv0);
			return EXIT_SUCCESS;
		case 'v':
			g_verbosity++;
			break;
		case 't':
			free(msgtypestr);
			msgtypestr = strdup(optarg);
			break;
		case 'i':
			free(ifname);
			ifname = strdup(optarg);
			break;
		case 'U':
			flags |= ND_OPT_NA_UNSOL;
			break;
		case '?':
			pr_err("unknown option.\n");
			print_help(argv0);
			return EXIT_FAILURE;
		default:
			pr_err("unknown option \"%c\".\n", opt);
			print_help(argv0);
			return EXIT_FAILURE;
		}
	}

	if (optind >= argc) {
		pr_err("No command specified.\n");
		print_help(argv0);
		goto errout;
	}

	argv += optind;
	cmd_name = *argv++;
	argc -= optind + 1;

	ifindex = 0;
	if (ifname) {
		ifindex = if_nametoindex(ifname);
		if (!ifindex) {
			pr_err("Interface \"%s\" does not exist\n", ifname);
			goto errout;
		}
	}

	err = get_msg_type(&msg_type, msgtypestr);
	if (err) {
		pr_err("Invalid message type \"%s\" selected\n", msgtypestr);
		print_help(argv0);
		goto errout;
	}

	err = ndp_open(&ndp);
	if (err) {
		pr_err("Failed to open ndp: %s\n", strerror(-err));
		goto errout;
	}

	if (!strncmp(cmd_name, "monitor", strlen(cmd_name))) {
		err = run_cmd_monitor(ndp, msg_type, ifindex);
	} else if (!strncmp(cmd_name, "send", strlen(cmd_name))) {
		bool all_ok = true;

		if (msg_type == NDP_MSG_ALL) {
			pr_err("Message type must be selected\n");
			all_ok = false;
		}
		if (!ifindex) {
			pr_err("Interface name must be selected\n");
			all_ok = false;
		}
		if (!all_ok) {
			print_help(argv0);
			goto errout;
		}
		err = run_cmd_send(ndp, msg_type, ifindex);
	} else {
		pr_err("Unknown command \"%s\"\n", cmd_name);
		goto ndp_close;
	}

	if (err) {
		pr_err("Command failed \"%s\"\n", strerror(-err));
		goto ndp_close;
	}

	res = EXIT_SUCCESS;

ndp_close:
	ndp_close(ndp);
errout:
	return res;
}
