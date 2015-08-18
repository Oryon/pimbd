/*
 * Author: Pierre Pfister <pierre pfister at darou.fr>
 *
 * Copyright 2015 Deutsche Telekom AG
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "rtnl.h"

#include <stdlib.h>
#include <string.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#include "utils.h"

#define RTNL_RETRY 5000
#define RTNL_RESEND 50
#define RTNL_RESEND_N 5
#define RTNL_TO 1000
#define RTNL_BUFFSIZ 16384
#define RTNL_ROUTE_DEFLT_METRIC 1024

#define rtnl_set_timer(rtnl, ms) \
	if(uloop_timeout_set(&(rtnl)->to, ms)) \
		L_ERR("Could not set netlink retry timer ! We are doomed...");

#define rtnl_cancel_timer(rtnl) \
	if((rtnl)->to.pending) \
		uloop_timeout_cancel(&(rtnl)->to);

/************ iface config specific ***********/

#define RTNL_IFACE_ALL (IFACE_FLAG_UP | IFACE_FLAG_EXISTS)

int rtnl_iface_config(rtnl rt, char *ifname, int ifindex, bool up)
{
	char create = (ifindex != -1) || up;
	iface i = iface_get_byname(rt->igs, ifname, create);
	if(!i)
		return (create)?-1:0;

	i->ifindex = ifindex;
	iface_set_flags(NULL, i, (i->flags & ~RTNL_IFACE_ALL) |
			((up)?IFACE_FLAG_UP:0) | ((ifindex != -1)?IFACE_FLAG_EXISTS:0));

	return 0;
}

/************ rtnl specifics *************/

int rtnl_dump_request(rtnl rt, int type, void *req, size_t len)
{
	struct sockaddr_nl nladdr = {
			.nl_family = AF_NETLINK,
	};
	struct nlmsghdr nlh = {
			.nlmsg_len = NLMSG_LENGTH(len),
			.nlmsg_type = type,
			.nlmsg_flags = NLM_F_DUMP|NLM_F_REQUEST,
			.nlmsg_pid = 0,
			.nlmsg_seq = ++rt->nlmsg_seq,
	};
	struct iovec iov[2] = {
			{ .iov_base = &nlh, .iov_len = sizeof(nlh) },
			{ .iov_base = req, .iov_len = len }
	};
	struct msghdr msg = {
			.msg_name = &nladdr,
			.msg_namelen = 	sizeof(nladdr),
			.msg_iov = iov,
			.msg_iovlen = 2,
	};

	if(sendmsg(rt->fd.fd, &msg, 0) < 0)
		return -1;

	return 0;
}

static int rtnl_state_next(rtnl rt)
{
	struct rtmsg rtmsg;
	struct ifaddrmsg addrmsg;
	/* The message is a reply from one of the bootstrap dump requests. */
	switch (rt->state) {
	case RTNL_S_WAITING_LINKS:
		memset(&addrmsg, 0, sizeof(addrmsg));
		addrmsg.ifa_family = AF_UNSPEC;
		if(rtnl_dump_request(rt, RTM_GETADDR, &addrmsg, sizeof(addrmsg))) {
			L_ERR("Could not send a rtnetlink request !");
			return -1;
		}
		rt->state = RTNL_S_WAITING_ADDR;
		rtnl_set_timer(rt, RTNL_TO);
		break;
	case RTNL_S_WAITING_ADDR:
	case RTNL_S_WAITING_RT4:
		memset(&rtmsg, 0, sizeof(rtmsg));
		rtmsg.rtm_family = (rt->state == RTNL_S_WAITING_ADDR)?AF_INET:AF_INET6;
		rtmsg.rtm_table = RT_TABLE_MAIN;
		if(rtnl_dump_request(rt, RTM_GETROUTE, &rtmsg, sizeof(rtmsg))) {
			L_ERR("Could not send a rtnetlink request !");
			return -1;
		}
		rt->state = (rt->state == RTNL_S_WAITING_ADDR)?RTNL_S_WAITING_RT4:RTNL_S_WAITING_RT6;
		rtnl_set_timer(rt, RTNL_TO);
		break;
	case RTNL_S_WAITING_RT6:
		rt->state = RTNL_S_UP;
		rtnl_cancel_timer(rt);
		L_INFO("rtnetlink asynchronous initialization completed successfully");
		break;
	default:
		break;
	}
	return 0;
}

int rtnl_setup_socket(rtnl rt) {
	L_INFO("Setting up rtnetlink socket");

	if((rt->fd.fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1)
		return -1;

	struct sockaddr_nl addr = {
			.nl_family = AF_NETLINK,
			.nl_pad = 0,
			.nl_pid = 0,
			.nl_groups = RTMGRP_LINK | RTMGRP_IPV6_IFADDR | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE | RTMGRP_NOTIFY,
	};

	struct ifinfomsg imsg = {
			.ifi_family = AF_UNSPEC
	};
	size_t len = sizeof(imsg);

	if (bind(rt->fd.fd, (struct sockaddr*) &addr, sizeof(addr)) ||
			uloop_fd_add(&rt->fd, ULOOP_READ | ULOOP_EDGE_TRIGGER) ||
			rtnl_dump_request(rt, RTM_GETLINK, &imsg, len)) {
		close(rt->fd.fd);
		return -1;
	}

	rtnl_set_timer(rt, RTNL_TO);
	rt->state = RTNL_S_WAITING_LINKS;
	return 0;
}

static int rtnl_setup(rtnl rt) {
	rtnl_cancel_timer(rt);
	rt->tentatives = 0;
	if(rtnl_setup_socket(rt)) {
		L_ERR("Could not setup rtnetlink socket. Will retry in %d ms.", RTNL_RETRY);
		rtnl_set_timer(rt, RTNL_RETRY);
		return -1;
	}
	return 0;
}

static void rtnl_teardown(rtnl rt) {

	//todo: Teardown ifaces + routes

	uloop_timeout_cancel(&rt->to);
	if(rt->state != RTNL_S_DOWN) {
		uloop_fd_delete(&rt->fd);
		close(rt->fd.fd);
	}
	rt->state = RTNL_S_DOWN;
}

static void rtnl_reset(rtnl rt) {
	L_WARN("Resetting rtnetlink");
	rtnl_teardown(rt);
	rtnl_set_timer(rt, RTNL_RETRY);
}

static int rtnl_parse_rtattr(struct rtattr *db[], size_t max, struct rtattr *rta, size_t len) {
	for(; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		if(rta->rta_type <= max)
			db[rta->rta_type] = rta;
	}
	if(len) {
		L_ERR("rattr lenght mistmatch %d %d len", (int) len, (int) rta->rta_len);
		return -1;
	}
	return 0;
}

static int rtnl_rcv_link(rtnl rt, struct nlmsghdr *hdr)
{
	struct ifinfomsg *ifi;
	struct rtattr *rtas[IFLA_MAX+1] = {0};
	size_t datalen = hdr->nlmsg_len - NLMSG_ALIGN(sizeof(*hdr));

	if(datalen < sizeof(*ifi))
			return -1;

	ifi = NLMSG_DATA(hdr);
	if((datalen > NLMSG_ALIGN(sizeof(*ifi))) &&
			rtnl_parse_rtattr(rtas, IFLA_MAX, IFLA_RTA(ifi),
			datalen - NLMSG_ALIGN(sizeof(*ifi)))) {
		return -1;
	}

	if(!rtas[IFLA_IFNAME]) {
		L_ERR("rtnetlink ifinfomsg with no interface name (index %d)", ifi->ifi_index);
		return -1; //todo: Handle this better. Handle iface name change.
	}

	if(hdr->nlmsg_type == RTM_DELLINK) {
		rtnl_iface_config(rt, RTA_DATA(rtas[IFLA_IFNAME]), -1, 0);
	} else {
		rtnl_iface_config(rt, RTA_DATA(rtas[IFLA_IFNAME]), ifi->ifi_index, !!(ifi->ifi_flags & IFF_UP));
	}
	return 0;
}

static int rtnl_rcv_addr(rtnl rt, struct nlmsghdr *hdr)
{
	struct ifaddrmsg *addrmsg;
	struct in6_addr addr;
	uint8_t plen;
	struct rtattr *rtas[IFA_MAX+1] = {0};
	size_t datalen = hdr->nlmsg_len - NLMSG_ALIGN(sizeof(*hdr));

	if(datalen < sizeof(*addrmsg))
		return -1;

	addrmsg = NLMSG_DATA(hdr);
	if((datalen > NLMSG_ALIGN(sizeof(*addrmsg))) &&
			rtnl_parse_rtattr(rtas, IFA_MAX, IFA_RTA(addrmsg),
					datalen - NLMSG_ALIGN(sizeof(*addrmsg)))) {
		return -1;
	}

	if(!rtas[IFA_ADDRESS]) {
		L_ERR("rtnetlink ifaddrmsg with no address");
		return -1;
	}

	addr_get(addrmsg->ifa_family, &addr, RTA_DATA(rtas[IFA_ADDRESS]));
	plen = addrmsg->ifa_prefixlen;
	if(addrmsg->ifa_family == AF_INET)
		plen += 96;

	rib_addrmod(rt->rib, &addr, plen, addrmsg->ifa_index, hdr->nlmsg_type == RTM_DELADDR);
	return 0;
}

static int rtnl_rcv_route(rtnl rt, struct nlmsghdr *hdr)
{
	struct rtmsg *rtmsg;
	struct rtattr *rtas[RTA_MAX+1] = {0};
	struct in6_addr dst, src, gw;
	int metric = 0x10000;
	size_t datalen = hdr->nlmsg_len - NLMSG_ALIGN(sizeof(*hdr));
	if(datalen < sizeof(*rtmsg))
			return -1;

	rtmsg = NLMSG_DATA(hdr);
	if((datalen > NLMSG_ALIGN(sizeof(*hdr))) &&
			rtnl_parse_rtattr(rtas, RTA_MAX, RTM_RTA(rtmsg),
						datalen - NLMSG_ALIGN(sizeof(*rtmsg)))) {
		return -1;
	}

	if(!rtas[RTA_TABLE] || *((int *)RTA_DATA(rtas[RTA_TABLE])) != RT_TABLE_MAIN) {
		return 0;
	}

	switch (rtmsg->rtm_type) {
	case RTN_UNICAST:
	case RTN_LOCAL:
		break;
	default:
		L_DEBUG("Ignoring route update of type %d", rtmsg->rtm_type);
		return 0;
	}

	if((rtmsg->rtm_dst_len && !rtas[RTA_DST]) ||
			(rtmsg->rtm_src_len && !rtas[RTA_SRC]) ||
			!rtas[RTA_OIF]) {
		return -1;
	}

	if(rtas[RTA_GATEWAY])
		addr_get(rtmsg->rtm_family, &gw, RTA_DATA(rtas[RTA_GATEWAY]));

	if(rtas[RTA_PRIORITY]) /* Yes, this is not RTA_METRICS. wtflinuxseriously. */
		metric = *((int *)RTA_DATA(rtas[RTA_PRIORITY]));

	prefix_get(rtmsg->rtm_family, &dst, &rtmsg->rtm_dst_len, rtmsg->rtm_dst_len?RTA_DATA(rtas[RTA_DST]):NULL, rtmsg->rtm_dst_len);
	prefix_get(rtmsg->rtm_family, &src, &rtmsg->rtm_src_len, rtmsg->rtm_src_len?RTA_DATA(rtas[RTA_SRC]):NULL, rtmsg->rtm_src_len);

	rib_routemod(rt->rib, &src, rtmsg->rtm_src_len,
			&dst, rtmsg->rtm_dst_len,
			*((int *)RTA_DATA(rtas[RTA_OIF])), rtas[RTA_GATEWAY]?&gw:NULL,
					metric, hdr->nlmsg_type == RTM_DELROUTE);

	return 0;
}

static int rtnl_rcv_error(__unused rtnl rt, struct nlmsghdr *hdr, int *error)
{
	struct nlmsgerr *err = NLMSG_DATA(hdr);
	size_t datalen = hdr->nlmsg_len - NLMSG_ALIGN(sizeof(*hdr));

	if(datalen < sizeof(*err))
		return -1;

	L_ERR("rtnetlink error packet: %d %s",err->error, strerror(-err->error));
	*error = err->error;
	return 0;
}

static int rtnl_rcv_nlmsg(rtnl rt, struct nlmsghdr *hdr)
{
	int ret, error = 0;
	switch (hdr->nlmsg_type) {
	case NLMSG_DONE:
		return 0;
		break;
	case NLMSG_ERROR:
		if((ret = rtnl_rcv_error(rt, hdr, &error)))
			return ret;
		break;
	case RTM_NEWROUTE:
	case RTM_DELROUTE:
		if((ret = rtnl_rcv_route(rt, hdr)))
			return ret;
		break;
	case RTM_NEWLINK:
	case RTM_DELLINK:
		if((ret = rtnl_rcv_link(rt, hdr)))
			return ret;
		break;
	case RTM_NEWADDR:
	case RTM_DELADDR:
		if((ret = rtnl_rcv_addr(rt, hdr)))
			return ret;
		break;
	default:
		L_WARN("Unknwon rtnetlink type %d", hdr->nlmsg_type);
		break;
	}

	if(!(hdr->nlmsg_flags & RTM_F_NOTIFY) &&
			(hdr->nlmsg_seq == rt->nlmsg_seq)) {
		if(error) {
			if(error != -EBUSY) //Only EBUSY can trigger a later send
				return -1;

			if(rt->state == RTNL_S_WAITING_LINKS) {
				rtnl_reset(rt);
			} else {
				L_WARN("rtnetlink will retry initialization later");
				rtnl_set_timer(rt, RTNL_RESEND);
			}
			return 0;
		} else {
			rt->tentatives = 0;
			return rtnl_state_next(rt);
		}
	}
	return 0;
}

static void rtnl_rcv(rtnl rt)
{
	uint8_t buff[RTNL_BUFFSIZ];
	ssize_t len;
	struct nlmsghdr *hdr;
	while(1) {
		if((len = recv(rt->fd.fd, buff, RTNL_BUFFSIZ, MSG_DONTWAIT)) < 0) {
			if(errno != EAGAIN) {
				L_ERR("rtnetlink recv error: %s", strerror(errno));
				rtnl_reset(rt);
			}
			return;
		}

		for(hdr = (struct nlmsghdr *) buff;
				len > 0;
				len -= NLMSG_ALIGN(hdr->nlmsg_len),
						hdr = (struct nlmsghdr *) (((uint8_t *) hdr) + NLMSG_ALIGN(hdr->nlmsg_len))) {
			if((sizeof(*hdr) > (size_t)len) || (hdr->nlmsg_len > (size_t)len)) {
				L_ERR("rtnetlink buffer too small (%d Vs %d)", (int) hdr->nlmsg_len, (int) len);
				//todo: Should use a flag to avoid that.
				break;
			}
			if(rtnl_rcv_nlmsg(rt, hdr)) {
				L_ERR("rtnetlink message parsing error");
				rtnl_reset(rt);
				return;
			}
			if(rt->state == RTNL_S_DOWN) { //Was reset by something
				return;
			}
		}
	}
}


static void rtnl_fd_cb(struct uloop_fd *fd, unsigned int events)
{
	rtnl rt = container_of(fd, rtnl_s, fd);
	if(events & (EPOLLERR | EPOLLHUP)) {
		L_ERR("rtnetlink file descriptor error (%u).", events);
		rtnl_reset(rt);
	} else if (events & EPOLLIN) {
		rtnl_rcv(rt);
	} else if(events) {
		L_WARN("Unexpected rtnetlink event (%u)", events);
	}
}

static void rtnl_to_cb(struct uloop_timeout *to) {
	rtnl rt = container_of(to, rtnl_s, to);
	switch (rt->state) {
		case RTNL_S_DOWN:
			rtnl_setup(rt);
			break;
		case RTNL_S_WAITING_LINKS:
			L_WARN("rtnetlink request timeouted.");
			rtnl_reset(rt);
			break;
		case RTNL_S_WAITING_ADDR:
		case RTNL_S_WAITING_RT4:
		case RTNL_S_WAITING_RT6:
			if(rt->tentatives > RTNL_RESEND_N) {
				rtnl_reset(rt);
			} else {
				rt->tentatives++;
				rt->state--;
				rtnl_state_next(rt);
			}
			break;
		case RTNL_S_UP:
			//Should not happen
			break;
		default:
			break;
	}
}


int rtnl_init(rtnl rt, ifgroups igs, rib rib)
{
	rt->igs = igs;
	rt->rib = rib;
	rt->to.cb = rtnl_to_cb;
	rt->to.pending = 0;
	rt->fd.registered = 0;
	rt->fd.fd = -1;
	rt->fd.cb = rtnl_fd_cb;
	rt->nlmsg_seq = 0;
	rt->state = RTNL_S_DOWN;
	if(rtnl_setup(rt)) {
		rtnl_cancel_timer(rt);
		return -1;
	}
	return 0;
};


