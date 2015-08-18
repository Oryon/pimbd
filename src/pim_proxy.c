/*
 * Authors: Mohammed Hawari <mohammed at hawari.fr>
 *          Pierre Pfister <pierre pfister at darou.fr>
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

#include "pim_proxy.h"

#include <libubox/usock.h>
#include <unistd.h>
#include <errno.h>

#include "ifgroup_s.h"
#include "listener.h"
#include "pim_group.h"

#define PIM_PROXY_RETRY 10000

#define PIM_PROXY_CAN_SETUP(i) (!((~(i)->flags) & (IFACE_FLAG_PROXY | IFACE_FLAG_EXISTS | IFACE_FLAG_UP)))

#define proxy_iface_from_client(cl) container_of((cl) - cl->id, iface_s, proxy.clients[0])


static pim_proxy_client pim_proxy_available_client(iface i)
{
	pim_proxy_client cl;
	for(cl = i->proxy.clients; cl < i->proxy.clients + PIM_PROXY_CLIENTS; cl++) {
		if(!cl->ufd.fd.fd)
			return cl;
	}
	return NULL;
}

static void pim_proxy_update_G_S_rpt(pim_proxy_client cl, ifgsource ifgs, int prune)
{
	uint32_t mask = 1 << cl->id;
	uint32_t val = prune?0xffffffff:0;
	if(!((val ^ ifgs->proxy_prune) & mask))
		return;

	if(!ifgs->proxy_prune)
		ifgsource_ref(ifgs);

	ifgs->proxy_prune = (ifgs->proxy_prune & ~mask) | (val & mask);
	listener_update_G_S(ifgs, LISTENER_PIM_PROXY, !!ifgs->proxy_join, !(ifgs->proxy_join || (ifgs->ig->proxy_join & ~ifgs->proxy_prune)));
	mrib_flush(&ifgs->ig->iface->proxy.mrib_user, &ifgs->gs->group->addr, 128, &ifgs->gs->source->addr);

	if(!ifgs->proxy_prune)
		ifgsource_unref(ifgs);
}

static void pim_proxy_update_G_S(pim_proxy_client cl, ifgsource ifgs, int join)
{
	uint32_t mask = 1 << cl->id;
	uint32_t val = join?0xffffffff:0;
	if(!((val ^ ifgs->proxy_join) & mask))
		return;

	if(!ifgs->proxy_join)
		ifgsource_ref(ifgs);

	ifgs->proxy_join = (ifgs->proxy_join & ~mask) | (val & mask);
	listener_update_G_S(ifgs, LISTENER_PIM_PROXY, !!ifgs->proxy_join, !(ifgs->proxy_join || (ifgs->ig->proxy_join & ~ifgs->proxy_prune)));
	mrib_flush(&ifgs->ig->iface->proxy.mrib_user, &ifgs->gs->group->addr, 128, &ifgs->gs->source->addr);

	if(!ifgs->proxy_join)
		ifgsource_unref(ifgs);
}

static void pim_proxy_update_G(pim_proxy_client cl, ifgroup ig, int join)
{
	uint32_t mask = 1 << cl->id;
	uint32_t val = join?0xffffffff:0;
	if(!((val ^ ig->proxy_join) & mask))
		return;

	if(!ig->proxy_join)
		ifgroup_ref(ig);

	ig->proxy_join = (ig->proxy_join & ~mask) | (val & mask);
	listener_update_G(ig, LISTENER_PIM_PROXY, !!ig->proxy_join);
	mrib_flush(&ig->iface->proxy.mrib_user, &ig->group->addr, 128, NULL);

	ifgsource ifgs, ifgs2;
	ifgroups_for_each_source_in_ig_safe(ig, ifgs, ifgs2) {
		if(!ifgs->proxy_join)
			listener_update_G_S(ifgs, LISTENER_PIM_PROXY, !!ifgs->proxy_join, !(ifgs->proxy_join || (ifgs->ig->proxy_join & ~ifgs->proxy_prune)));
	}

	if(!ig->proxy_join)
		ifgroup_unref(ig);
}

static void pim_proxy_client_teardown(pim_proxy_client cl)
{
	iface i = proxy_iface_from_client(cl);

	L_DEBUG("Proxy client teardown [%s]:%d", ADDR_REPR(&cl->addr), cl->port);

	//Remove all client state
	ifgroup ig, ig2;
	ifgsource ifgs, ifgs2;
	ifgroups_for_each_in_iface_safe(i, ig, ig2) {
		ifgroup_ref(ig);
		ifgroups_for_each_source_in_ig_safe(ig, ifgs, ifgs2) {
			ifgsource_ref(ifgs);
			pim_proxy_update_G_S(cl, ifgs, 0);
			pim_proxy_update_G_S_rpt(cl, ifgs, 0);
			ifgsource_unref(ifgs);
		}
		pim_proxy_update_G(cl, ig, 0);
		ifgroup_unref(ig);
	}

	ustream_free(&cl->ufd.stream);
	close(cl->ufd.fd.fd);
	cl->ufd.fd.fd = 0;
}

static int pim_proxy_parse_update(iface i, pim_proxy_client cl, char *buff)
{
	struct pp_group *ppg = (struct pp_group *)buff;
	uint8_t plen;
	size_t len = cl->hdr.length;
	struct pp_source *pps;
	struct in6_addr grp, src;
	uint16_t *num_sources;
	ifgroup ig;
	ifgsource igs;

	while(len) {
		//L_DEBUG("Remaining length %u", len);
		if(!(num_sources = PP_GROUP_SHIFT(ppg, len)) || len < 2)
			goto err;

		*num_sources = ntohs(*num_sources);
		L_DEBUG("num_sources %d", *num_sources);
		len -= 2;
		pps = (struct pp_source *)(num_sources + 1);

		pp_group_get(&grp, &plen, ppg);
		if(plen != 128) {
			L_WARN("Group length is not 128");
			goto err;
		}

		if(!(ig = ifgroup_get(i, group_get(i->ifgroups, &grp, true), true))) {
			L_WARN("Could not create ifgroup %s", ADDR_REPR(&grp));
			goto err;
		}

		ifgroup_ref(ig);

		L_DEBUG("Received proxy update for group %s - %u sources", ADDR_REPR(&grp), *num_sources);

		while(*num_sources) {
			uint8_t *state;
			if(!(state = (uint8_t *)PP_SOURCE_SHIFT(pps, len)) || len < 1) {
				L_DEBUG("Message too short");
				goto gerr;
			}


			pp_source_get(&src, &plen, pps);
			if(PP_SOURCE_WILDCARD(pps)) {
				if(*state != PIM_PROXY_JOIN && *state != PIM_PROXY_NOINFO) {
					L_DEBUG("(*,G) can only be JOIN or NO INFO");
					goto gerr;
				}

				L_DEBUG(" - Proxy %s"IFGROUP_L, (*state == PIM_PROXY_JOIN)?"JOIN":"NOINFO", IFGROUP_LA(ig));
				pim_proxy_update_G(cl, ig, *state == PIM_PROXY_JOIN);
			} else {
				if(plen != 128) {
					L_WARN("Source length is not 128");
					goto gerr;
				}

				if(!(igs = ifgsource_get2(i, ig->group, source_get(i->ifgroups, &src, true), true))) {
					L_WARN("Could not create ifgsource %s", ADDR_REPR(&src));
					goto gerr;
				}

				ifgsource_ref(igs);
				if(PP_SOURCE_RPT(pps)) {
					if(*state != PIM_PROXY_PRUNE && *state != PIM_PROXY_NOINFO) {
						L_DEBUG("(S,G,rt) can only be PRUNE or NO INFO");
						goto gerr;
					}

					L_DEBUG(" - Proxy rpt %s"IFGSOURCE_L, (*state == PIM_PROXY_PRUNE)?"PRUNE":"NOINFO", IFGSOURCE_LA(igs));
					pim_proxy_update_G_S_rpt(cl, igs, (*state == PIM_PROXY_PRUNE));
				} else {
					if(*state != PIM_PROXY_JOIN && *state != PIM_PROXY_NOINFO) {
						L_DEBUG("(S,G) can only be JOIN or NO INFO");
						goto gerr;
					}

					L_DEBUG(" - Proxy %s"IFGSOURCE_L, (*state == PIM_PROXY_JOIN)?"JOIN":"NOINFO", IFGSOURCE_LA(igs));
					pim_proxy_update_G_S(cl, igs, (*state == PIM_PROXY_JOIN));
				}
				ifgsource_unref(igs);
			}

			(*num_sources)--;
			pps = (struct pp_source *)(state + 1);
			len--;
		}
		ifgroup_unref(ig);

		//Next is actually a group
		ppg = (struct pp_group *)pps;
	}

	return 0;
gerr:
	ifgroup_unref(ig);
err:
return -1;
}

static void pim_proxy_notify_read(struct ustream *s, __unused int bytes_new)
{
	pim_proxy_client cl = container_of(s, pim_proxy_client_s, ufd.stream);
	iface i = proxy_iface_from_client(cl);

	if (s->eof && !ustream_pending_data(s, 0)) {
		pim_proxy_client_teardown(cl);
		return;
	}

	while(ustream_pending_data(s, 0)) {
		if(!cl->hdr_set) {
			if(ustream_pending_data(s, 0) < 4)
				return;
			if(ustream_read(s, (char *)&cl->hdr, 4) != 4) {
				L_ERR("ustream_read(header) returned too few characters (1)");
				pim_proxy_client_teardown(cl);
				return;
			}
			cl->hdr.type = ntohs(cl->hdr.type);
			cl->hdr.length = ntohs(cl->hdr.length);
			cl->hdr_set = 1;
		}

		char *msg = NULL;
		if(cl->hdr.length) {
			if(ustream_pending_data(s, 0) < cl->hdr.length)
				return;

			if(!(msg = malloc(cl->hdr.length))) {
				L_ERR("pim_proxy_notify_read could not allocate buffer for incoming message");
				pim_proxy_client_teardown(cl);
				return;
			}

			if(ustream_read(s, msg, cl->hdr.length) != cl->hdr.length) {
				L_ERR("ustream_read(buff) returned too few characters !");
				free(msg);
				pim_proxy_client_teardown(cl);
				return;
			}
		}

		switch (cl->hdr.type) {
			case PIM_PROXYMSG_KA:
				L_DEBUG("Received Keep-Alive");
				break;
			case PIM_PROXYMSG_UPDATE:
				L_DEBUG("Received Update of length %d", cl->hdr.length);
				if(pim_proxy_parse_update(i, cl, msg)) {
					L_WARN("Parse error in client proxy ctl message");
					free(msg);
					pim_proxy_client_teardown(cl);
					return;
				}
				break;
			default:
				L_DEBUG("Received Invalid Message Type (%d)", cl->hdr.type);
				break;
		}

		cl->hdr_set = 0;
		free(msg);
	}
}

static void pim_proxy_notify_state(struct ustream *s)
{
	pim_proxy_client cl = container_of(s, pim_proxy_client_s, ufd.stream);
	if (s->eof && !ustream_pending_data(s, 0))
		pim_proxy_client_teardown(cl);
}

static void pim_proxy_server_cb(struct uloop_fd *fd, __unused unsigned int events)
{
	pim_proxy_client cl;
	iface i = container_of(fd, iface_s, proxy.server_fd);
	int sfd;
	struct sockaddr_in6 sockaddr;
	socklen_t len = sizeof(struct sockaddr_in6);
	if((sfd = accept(i->proxy.server_fd.fd, (struct sockaddr *) &sockaddr, &len)) < 0) {
		L_ERR("accept() error: %s", strerror(errno));
		return;
	}

	if(!(cl = pim_proxy_available_client(i))) {
		L_ERR("Proxy[%s] has too many clients", i->ifname);
		close(sfd);
		return;
	}

	if(sockaddr.sin6_family == AF_INET6) {
		cl->port = ntohs(sockaddr.sin6_port);
		addr_cpy(&cl->addr, &sockaddr.sin6_addr);
	} else if(sockaddr.sin6_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&sockaddr;
		cl->port = ntohs(sin->sin_port);
		addr_map(&cl->addr, &sin->sin_addr);
	} else {
		L_ERR("Unknown address family %d", sockaddr.sin6_family);
		close(sfd);
		return;
	}

	cl->hdr_set = 0;
	cl->ufd.stream.notify_read = pim_proxy_notify_read;
	cl->ufd.stream.notify_state = pim_proxy_notify_state;
	ustream_fd_init(&cl->ufd, sfd);
	L_INFO("Proxy client from [%s]:%d connected to %s proxy", ADDR_REPR(&cl->addr), cl->port, i->ifname);
}

static void pim_proxy_mrib_cb(struct mrib_user *user, const struct in6_addr *g_addr,
		const struct in6_addr *s_addr, mrib_filter *filter)
{
	iface inc = container_of(user, struct iface_struct, proxy.mrib_user);
	group g;
	source s;
	ifgsource ifgs;
	L_DEBUG("PIM Proxy mrib callback for (%s, %s) on %s", ADDR_REPR(g_addr),
			ADDR_REPR(s_addr), inc->ifname);

	if(IN6_IS_ADDR_LINKLOCAL(s_addr)) {
		L_INFO("Packet source address in link local...");
		return;
	}

	if(!(g = group_get(inc->proxy.p->igs, g_addr, 1)) ||
			!(s = source_get(inc->proxy.p->igs, s_addr, 1)) ||
			!(ifgs = ifgsource_get2(inc, g, s, 1))) {
		L_ERR("Could not allocate memory !");
		return;
	}

	if(ifgs->proxy_join ||
			(ifgs->ig->proxy_join & (~ifgs->proxy_prune))) {
		if(inc->proxy.p->pim)
			pim_mrib_forward_upstream(inc->proxy.p->pim, inc, ifgs->gs, filter);
		pim_mrib_forward_downstream(inc, ifgs->gs, filter);
	}

	ifgsource_clean_maybe(ifgs);
}

static void pim_proxy_iface_setup(pim_proxy p, iface i);

static void pim_proxy_to(struct uloop_timeout *to)
{
	iface i = container_of(to, iface_s, proxy.timer);
	pim_proxy_iface_setup(i->proxy.p, i);
}

static void pim_proxy_iface_setup(pim_proxy p, iface i)
{
	if(i->proxy.server_fd.fd || i->proxy.timer.pending) //Already setup
		return;

	i->proxy.p = p;
	i->proxy.timer.cb = pim_proxy_to;
	i->proxy.server_fd.cb = pim_proxy_server_cb;
	uint8_t n;
	for(n=0; n<PIM_PROXY_CLIENTS; n++)
		i->proxy.clients[n].id = n;

	char port[20];
	sprintf(port, "%d", i->proxy_port);
	int err;
	if((err = mrib_attach_user(&i->proxy.mrib_user, i->ifindex, pim_proxy_mrib_cb))) {
		L_ERR("Could not setup proxy on iface %s [%s]:%s (mrib register returned: %s)",
				i->ifname, ADDR_REPR(&i->proxy_addr), port, strerror(-err));
		uloop_timeout_set(&i->proxy.timer, PIM_PROXY_RETRY);
		return;
	}

	if((i->proxy.server_fd.fd = usock(USOCK_TCP | USOCK_SERVER, ADDR_REPR(&i->proxy_addr), port)) < 0) {
		L_ERR("Could not setup proxy on iface %s [%s]:%s ", i->ifname, ADDR_REPR(&i->proxy_addr), port);
		mrib_detach_user(&i->proxy.mrib_user);
		i->proxy.server_fd.fd = 0;
		uloop_timeout_set(&i->proxy.timer, PIM_PROXY_RETRY);
	} else {
		L_INFO("Opened proxy server socket on %s port %s", ADDR_REPR(&i->proxy_addr), port);
		uloop_fd_add(&i->proxy.server_fd, ULOOP_READ);
	}
}

static void pim_proxy_iface_teardown(iface i)
{
	uloop_timeout_cancel(&i->proxy.timer);
	if(i->proxy.server_fd.fd) {
		//todo: Teardown all clients
		uloop_fd_delete(&i->proxy.server_fd);
		close(i->proxy.server_fd.fd);
		i->proxy.server_fd.fd = 0;
		mrib_detach_user(&i->proxy.mrib_user);
	}
}


static void pim_proxy_iface_cb(ifgroups_user user, iface i,
__unused iface_flags changed_flags) {
	pim_proxy p = container_of(user, pim_proxy_s, ifgroup_user);
	if (PIM_PROXY_CAN_SETUP(i)) {
		pim_proxy_iface_setup(p, i);
	} else {
		pim_proxy_iface_teardown(i);
	}
}

void pim_proxy_init(pim_proxy p, ifgroups igs, pim pim) {
	L_DEBUG("Init PIM Proxy - %p igs %p", p, igs);
	p->igs = igs;
	p->ifgroup_user.if_cb = pim_proxy_iface_cb;
	ifgroups_subscribe(igs, &p->ifgroup_user);
	p->pim = pim;
}

