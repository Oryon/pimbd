/*
 * Authors: Pierre Pfister <pierre pfister at darou.fr>
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

#include "pim.h"

#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>

#include "pim_group.h"
#include "pim_proto.h"
#include "pim_neigh.h"
#include "pim_rpa.h"
#include "pim_jp.h"
#include "utils.h"

#define PIM_IF_RETRY_DELAY 20000
#define PIM_RECV_BUFFLEN 2000
#define PIM_SET_LOOPBACK 0

#define PIM_DROP(iface, src, reason, ...) do {L_NOTICE("Packet dropped from %s on %s: "reason, ADDR_REPR(src), iface->ifname, ##__VA_ARGS__); return; }while(0)

static void pim_iface_setup(pim p, iface i);

static void pim_iface_recv_msg(iface i, uint8_t *buff, ssize_t len, struct sockaddr_in6 *src)
{
	if(len <= (ssize_t) sizeof(struct pp_header))
		PIM_DROP(i, &src->sin6_addr, "Too small for PIM header");

	struct pp_header *hdr = (struct pp_header *) buff;
	if(PP_HEADER_VERSION(hdr) != PP_VERSION)
		PIM_DROP(i, &src->sin6_addr, "Invalid version %d", PP_HEADER_VERSION(hdr));

	switch(PP_HEADER_TYPE(hdr)) {
	case PPT_HELLO:
		pimn_rcv_hello(i, buff, len, &src->sin6_addr);
		break;
	case PPT_DF_ELECTION:
		pim_dfe_rcv(i, buff, len, &src->sin6_addr);
		break;
	case PPT_JOIN_PRUNE:
		pim_group_rcv_joinprune(i, buff, len, &src->sin6_addr);
		break;
		//todo: Other packets types
	default:
		L_NOTICE("Unknown PIM message type %d", PP_HEADER_TYPE(hdr));
	}
}

static void pim_iface_recv(iface i)
{
	struct sockaddr_in6 src;
	socklen_t addrlen = sizeof(src);
	uint8_t buff[PIM_RECV_BUFFLEN];
	ssize_t len;
rcv:
	if((len = recvfrom(i->pim.socket.fd, buff, PIM_RECV_BUFFLEN, MSG_DONTWAIT, (struct sockaddr *)&src, &addrlen)) <= 0 ||
			len == PIM_RECV_BUFFLEN) {
		if(errno == EAGAIN)
			return;
		L_WARN("Could not receive PIM packet on %s: %s",i->ifname, strerror(errno));
		return;
	}
	//L_DEBUG("Received packet of length %d from %s on iface %s", (int) len, ADDR_REPR(&src.sin6_addr), i->ifname);
	pim_iface_recv_msg(i, buff, len, &src);
	goto rcv;
}

int pim_iface_sendto(iface i, void *data, size_t len, struct in6_addr *dst)
{
	if(!i->lladdr){
		L_ERR("Can't send PIM packet on %s because I don't have a link-local address.", i->ifname);
		return -1;
	}
	struct sockaddr_in6 in = {
			.sin6_addr = *dst,
			.sin6_family = AF_INET6,
	};

	struct iovec iov[1] = {
			{.iov_base = data, .iov_len = len}
	};

	struct in6_pktinfo *pkt;
	char buf[CMSG_SPACE(sizeof(*pkt))] = {}; //Init for valgrind
	struct msghdr msg = {
			.msg_iov = iov,
			.msg_iovlen = 1,
			.msg_name = &in,
			.msg_namelen = sizeof(in),
			.msg_control = buf,
			.msg_controllen = sizeof(buf),
	};

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(*pkt));
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_PKTINFO;
	pkt = (struct in6_pktinfo *)CMSG_DATA(cmsg);
	pkt->ipi6_addr = i->lladdr->addr;
	pkt->ipi6_ifindex = i->ifindex;

	ssize_t res = sendmsg(i->pim.socket.fd, &msg, MSG_DONTWAIT);
	if(res < 0) {
		L_WARN("Sendto error %s", strerror(errno));
	} else if(res != (ssize_t) len) {
		L_WARN("Sendto error: Sent %d bytes instead of %d", (int) res, (int) len);
	}
	return res != (ssize_t) len;
}


static void pim_iface_timer_to(struct uloop_timeout *to)
{
	iface i = container_of(to, iface_s, pim.timer);
	pim_iface_setup(i->pim.p, i);
}

static void pim_iface_socket_cb(struct uloop_fd *u, unsigned int events)
{
	iface i = container_of(u, iface_s, pim.socket);
	if(events & (EPOLLERR | EPOLLHUP)) {
		L_ERR("PIM socket error (%u).", events);
		pim_iface_reset(i->pim.p, i);
	} else if (events & EPOLLIN) {
		pim_iface_recv(i);
	} else if(events) {
		L_WARN("Unexpected PIM socket event (%u)", events);
	}
}

static int pim_iface_setup_socket(iface i)
{
	int hoplimit, cs, fd;
#ifdef PIM_SET_LOOPBACK
	int lo = PIM_SET_LOOPBACK;
#endif
	struct ipv6_mreq mreq;
	if((fd = socket(AF_INET6, SOCK_RAW, IPPROTO_PIM)) == -1)
		return -1;

	hoplimit = 1;
	cs = 2;
	mreq.ipv6mr_multiaddr = pp_all_routers;
	mreq.ipv6mr_interface = i->ifindex;
	i->pim.socket.cb = pim_iface_socket_cb;
	i->pim.socket.fd = fd;
	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, i->ifname, strlen(i->ifname)) ||
			setsockopt(fd, IPPROTO_RAW, IPV6_CHECKSUM, &cs, sizeof(cs)) ||
#ifdef PIM_SET_LOOPBACK
			setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &lo, sizeof(lo)) ||
#endif
			setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hoplimit, sizeof(hoplimit)) ||
			setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) ||
			uloop_fd_add(&i->pim.socket, ULOOP_READ | ULOOP_EDGE_TRIGGER)) {
		close(fd);
		return -1;
	}
	return 0;
}

static void pim_iface_teardown_socket(iface i)
{
	uloop_fd_delete(&i->pim.socket);
	uloop_timeout_cancel(&i->pim.timer);
	close(i->pim.socket.fd);
}

static void pim_iface_setstate(iface i, int state)
{
	if(!i->pim.state)
		iface_ref(i);

	i->pim.state = state;

	if(!i->pim.state)
		iface_unref(i);
}

static void pim_iface_ssbidir_changes(iface i)
{
	if(!PIM_IF_RUNNING(i))
		return;

	if(PIM_IF_SSBIDIR(i)) {
		L_INFO("Turning SSBIDIR ON on %s", i->ifname);
	} else {
		L_INFO("Turning SSBIDIR OFF on %s", i->ifname);
	}
	//Send immediate hello with changes option
	pimn_iface_send_hello(i);
	pim_group_ssbidir_changed(i);
}

static void pim_iface_setup_schedule(iface i)
{
	int state = uloop_timeout_set(&i->pim.timer, PIM_IF_RETRY_DELAY)?PIM_IF_NONE:PIM_IF_TRYING;
	pim_iface_setstate(i, state);
}

static void pim_iface_setup(pim p, iface i)
{
	switch (i->pim.state) {
		case PIM_IF_TRYING:
			uloop_timeout_cancel(&i->pim.timer);
			break;
		case PIM_IF_NONE:
			i->pim.p = p;
			i->pim.timer.cb = pim_iface_timer_to;
			i->pim.timer.pending = 0;
			break;
		default:
			return;
	}
	//Find an available index
	pim_if_t index;
	for(index = 1; index <= PIM_N_IFACES; index++) {
		if(!p->ifaces[index]) {
			p->ifaces[index] = i;
			i->pim.pim_index = index;
			break;
		}
	}
	if(!i->pim.pim_index) {
		L_WARN("Could not setup pim on %s: Too many (%d) PIM interfaces", i->ifname, PIM_N_IFACES);
		goto err;
	}

	//Setup the rest
	if(pim_group_iface_setup(i)) {
		L_WARN("Could not setup mrib on %s", i->ifname);
		goto err_group;
	} else if(pim_iface_setup_socket(i)) {
		L_WARN("Could not setup pim on %s", i->ifname);
		goto err_sock;
	} else if(pimn_iface_setup(i)) { //Setup neighboring
		L_WARN("Could not setup PIM neighboring subsystem on %s", i->ifname);
		goto err_neigh;
	} else if(pim_rpa_iface_setup(i)) {
		L_WARN("Could not setup PIM rpa subsystem on %s", i->ifname);
		goto err_rpa;
	} else {
		pim_iface_setstate(i, PIM_IF_READY);
	}

	pim_group_iface_start(p, i);
	return;

err_rpa:
	pimn_iface_teardown(i);
err_neigh:
	pim_iface_teardown_socket(i);
err_sock:
	pim_group_iface_teardown(i);
err_group:
	p->ifaces[i->pim.pim_index] = NULL;
	i->pim.pim_index = 0;
err:
	pim_iface_setup_schedule(i);
}

static void pim_iface_teardown(iface i)
{
	switch (i->pim.state) {
		case PIM_IF_READY:
			L_INFO("pim teardown on interface %s", i->ifname);
			pim_rpa_iface_teardown(i);
			pimn_iface_teardown(i);
			pim_group_iface_teardown(i);
			pim_iface_teardown_socket(i);
			i->pim.p->ifaces[i->pim.pim_index] = NULL;
			i->pim.pim_index = 0;
			//no break
		case PIM_IF_TRYING:
			uloop_timeout_cancel(&i->pim.timer);
			pim_iface_setstate(i, PIM_IF_NONE);
			break;
		default:
			break;
	}
}

void pim_iface_reset(pim p, iface i)
{
	L_WARN("Resetting pim on interface %s", i->ifname);
	pim_iface_teardown(i);
	pim_iface_setup(p, i);
}

static void pim_iface_event(ifgroups_user user, iface i, iface_flags changed_flags)
{
	pim p = container_of(user, pim_s, ifgroups_user);
	PIM_IF_CAN_SETUP(i)?pim_iface_setup(p, i):pim_iface_teardown(i);
	if((changed_flags & IFACE_FLAG_SSBIDIR) && !(changed_flags & IFACE_FLAG_PIM))
		pim_iface_ssbidir_changes(i); //Change in SSBIDIR configuration
}

static void pim_rib_cb(rib_user u, rib_entry e, int del)
{
	pim p = container_of(u, pim_s, rib_user);
	pim_rpa_rib_update(p, e, del);
}

int pim_init(pim pim, ifgroups ifgroups, conf conf, rib rib)
{
	pim->conf = conf;
	pim->ifgroups = ifgroups;
	pim->rib = rib;
	pim->ifgroups_user.if_cb = pim_iface_event;
	pim->rib_user.route_cb = pim_rib_cb;
	pim->rib_user.addr_cb = NULL;
	memset(pim->ifaces, 0, sizeof(pim->ifaces));
	if(pim_rpa_init(pim))
		return -1;
	ifgroups_subscribe(ifgroups, &pim->ifgroups_user);
	rib_register(pim->rib, &pim->rib_user);
	pim_jp_init(pim);
	INIT_LIST_HEAD(&pim->controllers);
	pim->ctl_timer.pending = 0;
	return 0;
}

