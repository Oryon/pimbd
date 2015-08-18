/*
 * Author: Pierre Pfister <pierre.pfister at darou.fr>
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

#include "pimbd.h"
#include "pim_neigh.h"
#include "pim_proto.h"
#include "pim_group.h"
#include "pim.h"
#include "conf.h"
#include "utils.h"
#include "pim_jp.h"

#define PIM_DROP(iface, src, reason, ...) \
	do {L_NOTICE("Packet dropped from %s on %s: "reason, ADDR_REPR(src), iface->ifname, ##__VA_ARGS__); return; }while(0)

static void pimn_hto(struct uloop_timeout *to);
static void pimn_thto(struct uloop_timeout *to);
pim_neigh pimn_neighbor_create(iface i, struct in6_addr *addr);
void pimn_neighbor_destroy(pim_neigh n);

static int pimn_iface_send_deadhello(iface i)
{
	//L_DEBUG("Sending PIM Goodbye");
	uint32_t alloc[64 >> 2];
	size_t avail = 64;
	struct pp_hello_opt *opt;
	struct pp_header *hdr = (struct pp_header *)alloc;
	hdr->rsv = 0;
	PP_HEADER_SET(hdr, PP_VERSION, PPT_HELLO);

	opt = PP_HEADER_DATA(hdr, avail);
	struct pp_hello_holdtime *ht = PPH_OPT_DATA(opt);
	PPH_OPT_SET(opt, PPHT_HOLDTIME, sizeof(*ht));
	PPH_HT_SET(ht, 0);

	avail -= PPH_OPT_TOT_LENGTH(opt);
	size_t len = 64 - avail;
	i->pim.neigh.hello_counter = 0;
	return pim_iface_sendto(i, alloc, len, &pp_all_routers);
}

int pimn_iface_setup(iface i)
{
	L_INFO("Setting up PIM neighboring subsystem on interface %s", i->ifname);
	INIT_LIST_HEAD(&i->pim.neigh.neighs);
	i->pim.neigh.genid = random();
	i->pim.neigh.hello_counter = 0;
	i->pim.neigh.hto.cb = pimn_hto;
	i->pim.neigh.hto.pending = false;
	i->pim.neigh.thto.cb = pimn_thto;
	i->pim.neigh.thto.pending = false;
	int delay = random() % conf_get_ifvalue(i->pim.p->conf, i, CIFV_PIM_TRIGGERED_HELLO_DELAY_MS);
	if(uloop_timeout_set(&i->pim.neigh.hto, delay))
		return -1;

	return 0;
}

void pimn_iface_teardown(iface i)
{
	L_INFO("Tearing down PIM neighboring subsystem on interface %s", i->ifname);
	uloop_timeout_cancel(&i->pim.neigh.hto);

	pim_neigh n, n2;
	list_for_each_entry_safe(n, n2, &i->pim.neigh.neighs, le) {
		pimn_neighbor_destroy(n);
	}

	pimn_iface_send_deadhello(i);
}

int pimn_iface_send_hello(iface i)
{
	uint32_t alloc[64 >> 2] = {};//Init for valgrind...
	size_t avail = 64;
	struct pp_hello_opt *opt;
	struct pp_header *hdr = (struct pp_header *)alloc;
	hdr->rsv = 0;
	PP_HEADER_SET(hdr, PP_VERSION, PPT_HELLO);

	opt = PP_HEADER_DATA(hdr, avail);
	struct pp_hello_drp *drp = PPH_OPT_DATA(opt);
	PPH_OPT_SET(opt, PPHT_DR_PRIORITY, sizeof(*drp));
	PPH_DRP_SET(drp, conf_get_ifvalue(i->pim.p->conf, i, CIFV_PIM_DR_PRIORITY));

	opt = PPH_OPT_NEXT(opt, avail);
	struct pp_hello_genid *genid = PPH_OPT_DATA(opt);
	PPH_OPT_SET(opt, PPHT_GENERATION_ID, sizeof(*genid));
	PPH_GENID_SET(genid, i->pim.neigh.genid);

	uint16_t holdtime = conf_get_ifvalue(i->pim.p->conf, i, CIFV_PIM_HOLDTIME_S);
	if(holdtime != PP_HOLDTIME_DEFAULT_S) {
		opt = PPH_OPT_NEXT(opt, avail);
		struct pp_hello_holdtime *ht = PPH_OPT_DATA(opt);
		PPH_OPT_SET(opt, PPHT_HOLDTIME, sizeof(*ht));
		PPH_HT_SET(ht, holdtime);
	}

	//BIDIR capable
	opt = PPH_OPT_NEXT(opt, avail);
	PPH_OPT_SET(opt, PPHT_BIDIR_CAP, 0);

	if(PIM_IF_SSBIDIR(i)) { //SSBIDIR capable on that interface
		opt = PPH_OPT_NEXT(opt, avail);
		PPH_OPT_SET(opt, PPHT_SSBIDIR_CAP, 0);
	}

	avail -= PPH_OPT_TOT_LENGTH(opt);
	size_t len = 64 - avail;
	if(pim_iface_sendto(i, alloc, len, &pp_all_routers)) {
		return -1;
	}
	i->pim.neigh.hello_counter++;
	pim_neigh neigh;
	list_for_each_entry(neigh, &i->pim.neigh.neighs, le) {
		neigh->sent_hello = 1;
	}
	if(i->pim.neigh.hello_counter == 1)
		pim_rpa_sent_first_hello(i);
	return 0;
}

//Schedule a triggered hello
static int pimn_schedule_triggered_hello(iface i)
{
	if(i->pim.neigh.thto.pending)
		return 0;
	int delay = random() % conf_get_ifvalue(i->pim.p->conf, i, CIFV_PIM_TRIGGERED_HELLO_DELAY_MS);
	if(uloop_timeout_set(&i->pim.neigh.thto, delay))
		return -1;
	return 0;
}

//Triggered hello timer
static void pimn_thto(struct uloop_timeout *to)
{
	iface i = container_of(to, iface_s, pim.neigh.thto);
	L_DEBUG("Sending triggered HELLO on %s", i->ifname);
	pimn_iface_send_hello(i);
}

//Periodic hello timer
static void pimn_hto(struct uloop_timeout *to)
{
	iface i = container_of(to, iface_s, pim.neigh.hto);
	if(pimn_iface_send_hello(i) ||
			uloop_timeout_set(to, conf_get_ifvalue(i->pim.p->conf, i, CIFV_PIM_HELLO_PERIOD_MS))) {
		L_WARN("Could not send hello message !");
		pim_iface_reset(i->pim.p, i);
	} else {
		//L_DEBUG("Sending hello #%d on %s", i->pim.neigh.hello_counter, i->ifname);
	}
}

void pimn_rcv_hello(iface i, uint8_t *data, size_t len, struct in6_addr *src) {
	//L_DEBUG("Received hello packet on %s from %s", i->ifname, ADDR_REPR(src));
	struct pp_hello_drp *drp = NULL;
	struct pp_hello_holdtime *ht = NULL;
	bool bidir = false;
	bool ssbidir = false;
	struct pp_hello_genid *genid = NULL;
	size_t avail;

	/* Parse Hello message */
	struct pp_hello_opt *opt;
	for(avail = len, opt = PP_HEADER_DATA(data, avail);
			opt && PPH_OPT_OK(opt, avail);
			opt = PPH_OPT_NEXT(opt, avail)) {
		switch(PPH_OPT_TYPE(opt)) {
		case PPHT_BIDIR_CAP:
			if(PPH_OPT_LENGTH(opt))
				PIM_DROP(i, src, "Malformed BIDIR_CAP option");
			bidir = true;
			break;
		case PPHT_SSBIDIR_CAP:
			if(PPH_OPT_LENGTH(opt))
				PIM_DROP(i, src, "Malformed BIDIR_CAP option");
			ssbidir = true;
			break;
		case PPHT_GENERATION_ID:
			if(PPH_OPT_LENGTH(opt) < sizeof(*genid))
				PIM_DROP(i, src, "Malformed GENID option");
			genid = PPH_OPT_DATA(opt);
			break;
		case PPHT_DR_PRIORITY:
			if(PPH_OPT_LENGTH(opt) < sizeof(*drp))
				PIM_DROP(i, src, "Malformed DR_PRIORITY option");
			drp = PPH_OPT_DATA(opt);
			break;
		case PPHT_HOLDTIME:
			if(PPH_OPT_LENGTH(opt) < sizeof(*ht))
				PIM_DROP(i, src, "Malformed HOLDTIME option");
			ht = PPH_OPT_DATA(opt);
			break;
		default:
			PIM_DROP(i, src, "Unknown option %d", PPH_OPT_TYPE(opt));
			break;
		}
	}

	pim_neigh n;
	bool created = false;
get_neigh:
	if(!(n = pimn_neighbor_get(i, src))) {
		if(!bidir) //No need to create it
			return;

		if(!(n = pimn_neighbor_create(i, src))) {
			pim_iface_reset(i->pim.p, i);
			return;
		} else {
			created = true;
			n->genid = genid?PPH_GENID_GET(genid):0;
			pimn_schedule_triggered_hello(i); //Schedule new hello when a new neighbor is discovered
		}
	} else if(genid && n->genid != PPH_GENID_GET(genid)) {
		pimn_neighbor_destroy(n); //todo: Should be done more gracefuly.
		goto get_neigh;
	}

	if(created || ssbidir != n->ssbidir_cap) {
		n->ssbidir_cap = ssbidir;
		pim_group_neigh_ssbidir_changed(i, n);
	}

	if(!bidir) {
		pimn_neighbor_destroy(n);
		return;
	}

	uint16_t holdtime = ht?PPH_HT_GET(ht):PP_HOLDTIME_DEFAULT_S;
	if(holdtime == PP_HOLDTIME_MAX_S) {
		uloop_timeout_cancel(&n->holdto);
	} else if(!holdtime) {
		pimn_neighbor_destroy(n);
		return;
	} else {
		uloop_timeout_set(&n->holdto, ((int)holdtime) * PIMBD_TIME_PER_SECOND);
	}

	n->drp = drp?PPH_DRP_GET(drp):PP_DR_PRIORITY;
}

void pimn_neighbor_destroy(pim_neigh n)
{
	L_INFO("Destroying "PIM_NEIGH_P, PIM_NEIGH_PA(n));
	uloop_timeout_cancel(&n->holdto);
	list_del(&n->le);
	pim_jp_dead_neighbor(n->i->pim.p, n); //JP first cause rpa_dead will trigger JP updates
	pim_rpa_dead_neighbor(n->i->pim.p, n);
	pim_group_neigh_ssbidir_changed(n->i, NULL);
	free(n);
}

void pimn_holdto(struct uloop_timeout *to)
{
	pim_neigh n = container_of(to, pim_neigh_s, holdto);
	pimn_neighbor_destroy(n);
}

pim_neigh pimn_neighbor_create(iface i, struct in6_addr *addr)
{
	pim_neigh n;
	if(!(n = malloc(sizeof(*n))))
		return NULL;

	addr_cpy(&n->addr, addr);
	n->i = i;
	n->genid = 0;
	n->drp = 0;
	n->holdto.pending = false;
	n->holdto.cb = pimn_holdto;
	n->sent_hello = 0;
	list_add(&n->le, &i->pim.neigh.neighs);
	L_INFO("Created "PIM_NEIGH_P, PIM_NEIGH_PA(n));
	pim_rpa_new_neighbor(n);
	return n;
}

pim_neigh pimn_neighbor_get(iface i, struct in6_addr *addr)
{
	pim_neigh n;
	list_for_each_entry(n, &i->pim.neigh.neighs, le) {
		if(!addr_cmp(addr, &n->addr))
			return n;
	}
	return NULL;
}

int pimn_send_hello_maybe(pim_neigh n)
{
	if(!n->sent_hello) {
		L_DEBUG("Sending immediate hello before sending message to "PIM_NEIGH_P, PIM_NEIGH_PA(n));
		return pimn_iface_send_hello(n->i);
	}
	return 0;
}
