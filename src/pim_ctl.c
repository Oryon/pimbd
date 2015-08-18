/*
 * Author: Mohammed Hawari <mohammed at hawari.fr >
 *         Pierre Pfister <pierre.pfister at darou.fr>
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

#include "pim_ctl.h"

#include <libubox/ustream.h>
#include <libubox/usock.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "pim_proxy.h"
#include "pim_proto.h"

#define PIM_CTL_CONNECT_RETRY_TIME 10000
#define PIM_CTL_KA_TIME 15000
#define PIM_CTL_UPDATE_DELAY 200

//#define PIM_CTL_ALLOW_DUPLICATES //Same daemon can have multiple instances to the same destination (for testing)
#define PIM_CTL_MSG_SIZE 1200

#define pim_ctl_error(ctl, errstr, ...) do{ \
	L_ERR("Proxy Controller error ("PIM_CTL_L"): "errstr, PIM_CTL_LA(ctl), ##__VA_ARGS__); \
	pim_ctl_teardown(ctl);\
	uloop_timeout_set(&(ctl)->timer, PIM_CTL_CONNECT_RETRY_TIME); \
} while(0)

static void pim_ctl_teardown(pim_ctl ctl)
{
	if(ctl->ufd.fd.fd) {
		ustream_free(&ctl->ufd.stream);
		close(ctl->ufd.fd.fd);
		ctl->ufd.fd.fd = 0;
	}
	uloop_timeout_cancel(&ctl->timer);
}

static int pim_ctl_send_state(pim_ctl ctl, group g)
{
	gsource gs;
	char buff[PIM_CTL_MSG_SIZE];
	struct pim_proxy_msg *msg = (struct pim_proxy_msg *) buff;
	bool redo;

restart:
	redo = 0;
	msg->type = htons(PIM_PROXYMSG_UPDATE);
	msg->length = 0;

	char *ptr = msg->value;
	size_t len = PIM_CTL_MSG_SIZE - sizeof(*msg);
	uint16_t *num_sources;

	pp_group_set((struct pp_group *)ptr, &g->addr, 128, 0);
	ptr = PP_GROUP_SHIFT((struct pp_group *)ptr, len);

	num_sources = (uint16_t *)ptr;
	*num_sources = 0;
	ptr += 2;
	len -= 2;

#define add_state(s) (*((uint8_t *)ptr) = (s), len--, ptr++)

	if(g->ctl_joined) {
		pp_source_set((struct pp_source *)ptr, &g->addr, 128, PP_SOURCE_FLAG_WILDCARD);
		ptr = PP_SOURCE_SHIFT((struct pp_source *)ptr, len);
		add_state(PIM_PROXY_JOIN);
		(*num_sources)++;
		L_DEBUG(" CTL Init JOIN"GROUP_L, GROUP_LA(g));
	}
	ifgroups_for_each_source_in_group(g, gs)
	{
		if(len < 50) {
			//A bit rough, but should work.
			redo = 1;
			goto send;
		}

		if(gs->ctl_joined) {
			pp_source_set((struct pp_source *)ptr, &gs->source->addr, 128, 0);
			ptr = PP_SOURCE_SHIFT((struct pp_source *)ptr, len);
			add_state(PIM_PROXY_JOIN);
			(*num_sources)++;
			L_DEBUG(" CTL Init JOIN"GSOURCE_L, GSOURCE_LA(gs));
		}
		if(gs->ctl_pruned) {
			pp_source_set((struct pp_source *)ptr, &gs->source->addr, 128, PP_SOURCE_FLAG_RPT);
			ptr = PP_SOURCE_SHIFT((struct pp_source *)ptr, len);
			add_state(PIM_PROXY_PRUNE);
			(*num_sources)++;
			L_DEBUG(" CTL Init PRUNE"GSOURCE_L" rpt", GSOURCE_LA(gs));
		}
	}

send:

	//Send message
	len = PIM_CTL_MSG_SIZE - len;
	if(*num_sources != 0) {
		L_DEBUG("Sending Init Update with %u sources (%d data bytes)", *num_sources, (int)(len - sizeof(*msg)));
		*num_sources = htons(*num_sources);
		msg->length = htons(len - sizeof(*msg));
		if(ustream_write(&ctl->ufd.stream, (char *)msg, (int)len, 0) != (int)len) {
			pim_ctl_error(ctl, "Could not send update: (%s)", strerror(errno));
			return -1;
		}
	}

	if(redo)
		goto restart;

	return 0;
}

static void pim_ctl_setup(pim_ctl ctl)
{
	char port[10];
	int fd;
	uloop_timeout_cancel(&ctl->timer);

	sprintf(port, "%d", (int)ctl->port);
	if ((fd = usock(USOCK_TCP | USOCK_NONBLOCK, ADDR_REPR(&ctl->addr), port)) < 0) {
		pim_ctl_error(ctl, "Could not open socket (%s)", strerror(errno));
	} else {
		L_DEBUG("Opened proxy controller connection to [%s]:%s", ADDR_REPR(&ctl->addr), port);
		ustream_fd_init(&ctl->ufd, fd);
		uloop_timeout_set(&ctl->timer, PIM_CTL_KA_TIME);
		group g;
		ifgroups_for_each_group(ctl->pim->ifgroups, g) {
			if(pim_ctl_send_state(ctl, g))
				return;
		}
	}
}

static void pim_ctl_notify_state(struct ustream *s)
{
	pim_ctl ctl = container_of(s, pim_ctl_s, ufd.stream);
	pim_ctl_error(ctl, "Socket state error");
}

static void pim_ctl_timeout(struct uloop_timeout *to)
{
	pim_ctl ctl = container_of(to, pim_ctl_s, timer);
	int len;
	if(ctl->ufd.fd.fd) {
		struct pim_proxy_msg ka;
		ka.type = htons(PIM_PROXYMSG_KA);
		ka.length = 0;
		if((len = ustream_write(&ctl->ufd.stream, (const char *)&ka, sizeof(ka), 0)) != sizeof(ka)) {
			pim_ctl_error(ctl, "Could not write to socket (%s)", strerror(errno));
		} else {
			L_DEBUG("Sent Keep-Alive");
			uloop_timeout_set(&ctl->timer, PIM_CTL_KA_TIME);
		}
	} else {
		pim_ctl_setup(ctl);
	}
}

static pim_ctl pim_ctl_get(pim p, struct in6_addr *a, in_port_t port)
{
	pim_ctl ctl;
	pim_for_each_ctl(p, ctl) {
		if(ctl->port == port && !addr_cmp(&ctl->addr, a))
			return ctl;
	}
	return NULL;
}

static pim_ctl pim_ctl_create(pim p, struct in6_addr *a, in_port_t port)
{
	pim_ctl ctl;
	if(!(ctl = calloc(1, sizeof(*ctl)))) {
		L_ERR("Could not allocate proxy controller structure for [%s]:%u", ADDR_REPR(a), port);
		return NULL;
	}

	addr_cpy(&ctl->addr, a);
	ctl->port = port;
	list_add(&ctl->le, &p->controllers);
	ctl->ufd.fd.fd = 0;
	ctl->pim = p;
	ctl->ufd.stream.notify_state = pim_ctl_notify_state;
	ctl->timer.cb = pim_ctl_timeout;
	return ctl;
}

int pim_ctl_add_proxy(pim p, struct in6_addr *a,in_port_t port)
{
	pim_ctl ctl;
	if(
#ifndef PIM_CTL_ALLOW_DUPLICATES
			(ctl = pim_ctl_get(p, a , port)) ||
#endif
			!(ctl = pim_ctl_create(p, a, port)))
		return -1;

	L_INFO("Adding proxy controller "PIM_CTL_L, PIM_CTL_LA(ctl));
	pim_ctl_setup(ctl);
	return 0;
}

void pim_ctl_del_proxy(pim p, struct in6_addr *a,in_port_t port)
{
	pim_ctl ctl;
	if((ctl = pim_ctl_get(p, a , port))) {
		L_INFO("Removing proxy controller "PIM_CTL_L, PIM_CTL_LA(ctl));
		pim_ctl_teardown(ctl);
		list_del(&ctl->le);
		free(ctl);
	}
}

int pim_ctl_join_G(pim p, group g) {
	pim_rpa rpa;
	ifgroup ig;
	if(g->pim_upstream)
		return 1;

	if(!(rpa = pim_rpa_get(p, g)) || !rpa->dfe ||
			rpa->dfe->mod != PIM_DFEM_RPL_ACTIVE ||
			!(ig = ifgroup_get(rpa->dfe->iface, g, 0)))
		return 0;

	return (ig->pim_downstream != PIM_NONE || // + DownstreamJPState(G,I)
			ig->conf_local_exclude || // + Configured interface Join(*,G)
			ig->pim_local_exclude);  // + local_receiver_include(G,I) (BIDIR mode);
}

int pim_ctl_join_G_S(pim p, gsource gs) {
	pim_rpa rpa;
	ifgsource ifgs;
	if(pim_ctl_join_G(p, gs->group))
		return 0;

	if(gs->pim_upstream)
		return 1;

	if(!(rpa = pim_rpa_get(p, gs->group)) || !rpa->dfe ||
			rpa->dfe->mod != PIM_DFEM_RPL_ACTIVE ||
			!(ifgs = ifgsource_get2(rpa->dfe->iface, gs->group, gs->source, 0)))
		return 0;

	return (ifgs->pim_downstream != PIM_NONE ||
			ifgs->pim_local_include);
}

int pim_ctl_prune_G_S(pim p, gsource gs) {
	pim_rpa rpa;
	ifgsource ifgs;
	if(!pim_ctl_join_G(p, gs->group) ||
			pim_ctl_join_G_S(p, gs))
		return 0;

	if(gs->pim_upstream_rpt)
		return 1;

	if(!(rpa = pim_rpa_get(p, gs->group)) || !rpa->dfe ||
			rpa->dfe->mod != PIM_DFEM_RPL_ACTIVE ||
			!(ifgs = ifgsource_get2(rpa->dfe->iface, gs->group, gs->source, 0)))
		return 0;

	if((ifgs->ig->pim_downstream && (ifgs->pim_downstream_rpt != PIM_PRUNE)) ||
			(ifgs->ig->pim_local_exclude && !ifgs->pim_local_exclude))
		return 0;

	return 1;
}

/* This part is ugly. It will require some refactoring */
void pim_ctl_send_update(pim p, group g) //When ctl is set, function sends the current state to this proxy only
{
	L_DEBUG("pim_ctl_send_update %s", ADDR_REPR(&g->addr));
	gsource gs, gs2;
	char buff[PIM_CTL_MSG_SIZE];
	struct pim_proxy_msg *msg = (struct pim_proxy_msg *) buff;
	bool redo;
	int state;

restart:
	redo = 0;
	msg->type = htons(PIM_PROXYMSG_UPDATE);
	msg->length = 0;

	char *ptr = msg->value;
	size_t len = PIM_CTL_MSG_SIZE - sizeof(*msg);
	uint16_t *num_sources;

	pp_group_set((struct pp_group *)ptr, &g->addr, 128, 0);
	ptr = PP_GROUP_SHIFT((struct pp_group *)ptr, len);

	num_sources = (uint16_t *)ptr;
	*num_sources = 0;
	ptr += 2;
	len -= 2;

#define add_state(s) (*((uint8_t *)ptr) = (s), len--, ptr++)

	group_ref(g);
	state = pim_ctl_join_G(p, g);
	if(g->ctl_joined != state) {
		pp_source_set((struct pp_source *)ptr, &g->addr, 128, PP_SOURCE_FLAG_WILDCARD);
		ptr = PP_SOURCE_SHIFT((struct pp_source *)ptr, len);
		add_state(state?PIM_PROXY_JOIN:PIM_PROXY_NOINFO);
		(*num_sources)++;
		L_DEBUG(" CTL Update %s"GROUP_L, state?"JOIN":"NOINFO", GROUP_LA(g));

		g->ctl_joined = state;
		if(g->ctl_joined)
			group_ref(g);
		else
			group_unref(g);
	}
	ifgroups_for_each_source_in_group_safe(g, gs, gs2)
	{
		if(len < 50) {
			//A bit rough, but should work.
			redo = 1;
			goto send;
		}

		gsource_ref(gs);
		state = pim_ctl_join_G_S(p, gs);
		if(gs->ctl_joined != state) {
			pp_source_set((struct pp_source *)ptr, &gs->source->addr, 128, 0);
			ptr = PP_SOURCE_SHIFT((struct pp_source *)ptr, len);
			add_state(state?PIM_PROXY_JOIN:PIM_PROXY_NOINFO);
			(*num_sources)++;
			L_DEBUG(" CTL Update %s"GSOURCE_L, state?"JOIN":"NOINFO", GSOURCE_LA(gs));

			gs->ctl_joined = state;
			if(gs->ctl_joined)
				gsource_ref(gs);
			else
				gsource_unref(gs);
		}
		state = pim_ctl_prune_G_S(p, gs);
		if(gs->ctl_pruned != state) {
			pp_source_set((struct pp_addr *)ptr, &gs->source->addr, 128, PP_SOURCE_FLAG_RPT);
			ptr = PP_SOURCE_SHIFT((struct pp_source *)ptr, len);
			add_state(state?PIM_PROXY_PRUNE:PIM_PROXY_NOINFO);
			(*num_sources)++;
			L_DEBUG(" CTL Update %s"GSOURCE_L" rpt", state?"PRUNE":"NOINFO", GSOURCE_LA(gs));

			gs->ctl_pruned = state;
			if(gs->ctl_pruned)
				gsource_ref(gs);
			else
				gsource_unref(gs);
		}
		gsource_unref(gs);
	}

send:
	group_unref(g);

	//Send message
	len = PIM_CTL_MSG_SIZE - len;
	if(*num_sources != 0) {
		*num_sources = htons(*num_sources);
		msg->length = htons(len - sizeof(*msg));
		pim_ctl ctl;
		pim_for_each_ctl(p, ctl) {
			if(ctl->ufd.fd.fd && (ustream_write(&ctl->ufd.stream, (char *)msg, (int)len, 0) != (int)len)) {
				pim_ctl_error(ctl, "Could not send update: (%s)", strerror(errno));
			}
		}
	}

	if(redo)
		goto restart;
}

void pim_ctl_update_to(struct uloop_timeout *to)
{
	pim p = container_of(to, pim_s, ctl_timer);
	L_DEBUG("PIM controller update");
	group g, g2;
	ifgroups_for_each_group_safe(p->ifgroups, g, g2) {
		if(g->ctl_updated) {
			g->ctl_updated = 0;
			pim_ctl_send_update(p, g);
		}
	}
}

void pim_ctl_update(pim p, group g)
{
	L_DEBUG("pim_ctl_update %s", ADDR_REPR(&g->addr));
	g->ctl_updated = 1;
	if(!p->ctl_timer.pending) {
		p->ctl_timer.cb = pim_ctl_update_to;
		uloop_timeout_set(&p->ctl_timer, PIM_CTL_UPDATE_DELAY);
	}
}

void pim_ctl_update_maybe_G(pim p, group g)
{
	if(!g->ctl_updated && pim_ctl_join_G(p, g) != g->ctl_joined)
		pim_ctl_update(p, g);
}

void pim_ctl_update_maybe_G_S(pim p, gsource gs)
{
	if(!gs->group->ctl_updated &&
			(pim_ctl_join_G_S(p, gs) != gs->ctl_joined ||
			pim_ctl_prune_G_S(p, gs) != gs->ctl_pruned))
		pim_ctl_update(p, gs->group);
}
