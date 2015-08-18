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


#include "pim_rpa.h"
#include "pimbd.h"
#include "conf.h"
#include "pim_proto.h"
#include "pim_group.h"
#include "pim_jp.h"

pim_if_t __pim_rpa_index;
pim_dfe __pim_rpa_dfe;
pim_rpa __pim_rpa_rpa;

#define pim_for_each_rpa_safe(p, rpa, rpa2) avl_for_each_element_safe(&(p)->rpas, rpa, ne, rpa2)

#define pim_for_each_group_range_safe(rpa, g, g2) list_for_each_entry_safe(g, g2, &(rpa)->groups, le)

#define pim_for_each_dfe_in_iface(i, dfe) \
		pim_for_each_rpa((i)->pim.p, __pim_rpa_rpa) \
			if((dfe = __pim_rpa_rpa->dfes[i->pim.pim_index]))

#define GR_L "group range %s"
#define GR_LA(gr) PREFIX_REPR(&(gr)->group, (gr)->len)

#define DFE_OPLOW(iface) (int) (rand_i(0.5, 1) * conf_get_ifvalue(iface->pim.p->conf, iface, CIFV_PIM_DFE_OFFER_PERIOD_MS))

#define PIM_RPA_ONLINK(rpa, iface) ((rpa)->path && (rpa)->path->onlink && ((rpa)->path->oif == (iface)->ifindex))
#define PIM_DFE_IS_DF(dfe) ((dfe)->state == PIM_DFE_WIN || (dfe)->state ==PIM_DFE_BACKOFF)

#define PIM_RPA_PANIC_RETRY 3000

//#define DFE_DEBUG(...)
#define DFE_DEBUG(...) L_DEBUG(__VA_ARGS__)

const char *pim_dfe_state_str[PIM_DFE_BACKOFF + 1] = {
		"OFFER", "LOSE", "WINNER", "BACKOFF"
};

const char *pim_dfe_mod_str[PIM_DFEM_RPL_ACTIVE + 1] = {
		"NONE", "ELECTION", "RPL-PASSIVE", "RPL-ACTIVE",
};

#define PIM_DFE_NO_PATH(dfe) (!dfe->rpa->path || (dfe->rpa->path->oif == dfe->iface->ifindex))

static void pim_rpa_gr_delete(pim p, pim_rpa rpa, group_range gr);

static void pim_dfe_path_changed(pim_dfe dfe, rib_entry old);
static int pim_dfe_create(pim_rpa rpa, iface i);
static void pim_dfe_destroy(pim_dfe dfe);
static int pim_dfe_df_failure(pim_dfe dfe);
static void pim_rpa_update_prefix(pim p, struct in6_addr *prefix, uint8_t plen);
static void pim_rpa_update_path(pim p, pim_rpa rpa);
static int pim_dfe_set_mod(pim_dfe dfe, enum pim_dfe_mod mod);
static int pim_dfe_update_mod(pim_dfe dfe);
static void pim_rpa_set_upstream_dfe(pim p, pim_rpa rpa, pim_dfe dfe);

static void pim_dfe_timeout(struct uloop_timeout *to);
static void pim_panic_timeout(struct uloop_timeout *to);

static void pim_dfe_metric_set(struct pp_df_metric *m, rib_entry e, iface i)
{
	if(!e || e->oif == i->ifindex) {
		PP_DF_METRIC_SET(m, UINT32_MAX, UINT32_MAX);
	} else {
		PP_DF_METRIC_SET(m, RIB_ROUTE_PREFERENCE(e), e->metric);
	}
}

static int pim_rpa_cmp(const void *k1, const void *k2, __unused void *ptr)
{
	return addr_cmp(k1, k2);
}

int pim_rpa_init(pim p)
{
	avl_init(&p->rpas, pim_rpa_cmp, false, NULL);
	return 0;
}

pim_rpa pim_rpa_find(pim p, const struct in6_addr *group, uint8_t masklen)
{
	pim_rpa rpa;
	group_range gr;
	pim_for_each_rpa(p, rpa) {
		if(rpa->running) {
			pim_for_each_group_range(rpa, gr) {
				if(prefix_contains_p(&gr->group, gr->len, group, masklen))
					return rpa;
			}
		}
	}
	return NULL;
}

static void pim_rpa_start(pim p, pim_rpa rpa)
{
	if(rpa->running)
		return;

	L_DEBUG(RPA_L": start", RPA_LA(rpa));
	rpa->running = true;
	//Create a dfe for each iface where PIM is running
	iface i;
	ifgroups_for_each_iface(p->ifgroups, i) {
		if(PIM_IF_RUNNING(i))
			pim_dfe_create(rpa, i);
	}
	//Update rpa path
	pim_rpa_update_path(p, rpa);
	//Update groups
	group_range gr;
	pim_for_each_group_range(rpa, gr) {
		pim_rpa_update_prefix(p, &gr->group, gr->len);
	}
}

static void pim_rpa_stop(pim p, pim_rpa rpa)
{
	if(!rpa->running)
		return;

	L_DEBUG(RPA_L": stop", RPA_LA(rpa));
	rpa->running = false;
	rpa->path = NULL;
	//Update groups
	group_range gr;
	pim_for_each_group_range(rpa, gr)
		pim_rpa_update_prefix(p, &gr->group, gr->len);

	//Delete all dfes attached to this rpa
	pim_rpa_set_upstream_dfe(p, rpa, NULL);
	pim_dfe dfe;
	pim_for_each_dfe_in_rpa(rpa, dfe)
		pim_dfe_destroy(dfe);
}

static void pim_rpa_delete(pim p, pim_rpa rpa)
{
	pim_rpa_stop(p, rpa);
	L_DEBUG("Deleting "RPA_L, RPA_LA(rpa));
	//Unlink the rpa from pim
	avl_delete(&p->rpas, &rpa->ne);
	free(rpa);
}

/* Update rpa activity state, possibly delete it. */
static void pim_rpa_update_state(pim p, pim_rpa rpa)
{
	if(list_empty(&rpa->groups)) {
		pim_rpa_stop(p, rpa);
		if(!rpa->rpl_jp)//No configuration saved
			pim_rpa_delete(p, rpa);
	} else {
		pim_rpa_start(p, rpa);
	}
}

static void pim_rpa_set_upstream_dfe(pim p, pim_rpa rpa, pim_dfe dfe)
{
	if(dfe == rpa->dfe)
		return;

	pim_neigh old_df = rpa->dfe?rpa->dfe->df:NULL;
	pim_neigh new_df = dfe?dfe->df:NULL;

	rpa->dfe = dfe;
	if(new_df != old_df) //Update the upstream
		pim_group_upstream_df_update(p, rpa, old_df);
}

static void pim_rpa_update_path(pim p, pim_rpa rpa)
{
	rib_entry e = rib_lookup(p->rib, NULL, &rpa->addr);
	rib_entry old;
	pim_dfe dfe;
	iface i;
	if(e != rpa->path) { //Path changed
		if(e) {
			L_DEBUG("rpa "RPA_L" path changed to "RIB_ENTRY_L,
				RPA_LA(rpa), RIB_ENTRY_LA(e));
		} else {
			L_DEBUG("rpa "RPA_L" path changed to null", RPA_LA(rpa));
		}

		old = rpa->path;
		rpa->path = e;
		i = rpa->path?iface_get_byindex(p->ifgroups, e->oif, false):NULL;
		dfe = i?pim_dfe_find(i, rpa):NULL;
		pim_rpa_set_upstream_dfe(p, rpa, dfe);

		//DFE state machine path changed
		pim_for_each_dfe_in_rpa(rpa, dfe) {
			pim_dfe_path_changed(dfe, old);
		}
	}
}

static void pim_rpa_update_prefix(pim p, struct in6_addr *prefix, uint8_t plen)
{
	pim_rpa old, new;
	group g, g2;

	L_DEBUG("RPA configuration change for prefix %s", PREFIX_REPR(prefix, plen));

	ifgroups_for_each_group_safe(p->ifgroups, g, g2) {
		if(prefix_contains(prefix, plen, &g->addr)) {
			old = g->pim_rpa_set?g->pim_rpa:NULL;
			new = pim_rpa_get_update(p, g);
			if(new != old)
				pim_group_rpa_update(p, g, old);
		}
	}
}

static pim_rpa pim_rpa_goc(pim p, struct in6_addr *addr, bool create)
{
	struct avl_node *n = avl_find(&p->rpas, addr);
	pim_rpa r;
	if(n)
		return container_of(n, pim_rpa_s, ne);

	if(!create || !(r = malloc(sizeof(*r))))
		return NULL;

	r->running = 0;
	r->path = NULL;
	r->addr = *addr;
	r->rpl_jp = 0;
	r->dfe = NULL;
	memset(r->dfes, 0, sizeof(r->dfes));
	INIT_LIST_HEAD(&r->groups);
	r->ne.key = &r->addr;
	avl_insert(&p->rpas, &r->ne);
	L_DEBUG("Adding "RPA_L, RPA_LA(r));
	return r;
}

static void pim_rpa_gr_delete(pim p, pim_rpa rpa, group_range gr)
{
	L_DEBUG("Deleting "GR_L" from "RPA_L, GR_LA(gr), RPA_LA(rpa));
	list_del(&gr->le);
	//RPA is modified group rpas may need to be updated
	pim_rpa_update_prefix(p, &gr->group, gr->len);
	free(gr);
	pim_rpa_update_state(p, rpa); //Delete maybe
}

static group_range pim_rpa_gr_goc(pim p, pim_rpa rpa, const struct in6_addr *group,
		uint8_t len, bool create)
{
	group_range gr;
	struct in6_addr can;
	prefix_can(&can, &len, group, len);
	pim_for_each_group_range(rpa, gr) {
		if(gr->len == len && !addr_cmp(&can, &gr->group))
			return gr;
	}

	if(!create || !(gr = malloc(sizeof(*gr))))
		return NULL;

	gr->group = can;
	gr->len = len;
	gr->to_delete = false;
	gr->rpa = rpa;
	list_add(&gr->le, &rpa->groups);
	pim_rpa_update_prefix(p, &gr->group, gr->len);
	pim_rpa_update_state(p, rpa); //Start maybe

	L_DEBUG("Adding "GR_L" to "RPA_L, GR_LA(gr), RPA_LA(rpa));
	return gr;
}

int pim_rpa_add(pim p, struct in6_addr *rpa, const struct in6_addr *group, uint8_t len)
{
	pim_rpa r;
	group_range gr;
	if(!(r = pim_rpa_goc(p, rpa, true)) ||
			!(gr = pim_rpa_gr_goc(p, r, group, len, true)))
		return -1;

	gr->to_delete = false;
	return 0;
}

void pim_rpa_del(pim p, struct in6_addr *rpa, const struct in6_addr *group, uint8_t len)
{
	pim_rpa r;
	group_range gr;
	if(!(r = pim_rpa_goc(p, rpa, false)) ||
			!(gr = pim_rpa_gr_goc(p, r, group, len, false)))
		return;

	pim_rpa_gr_delete(p, r, gr);
	return;
}

void pim_rpa_update(pim p, struct in6_addr *rpa_addr)
{
	pim_rpa rpa;
	if(!(rpa = pim_rpa_goc(p, rpa_addr, false)))
		return;

	group_range gr;
	pim_for_each_group_range(rpa, gr) {
		gr->to_delete = true;
	}
}

void pim_rpa_flush(pim p, struct in6_addr *rpa_addr)
{
	pim_rpa rpa;
	if(!(rpa = pim_rpa_goc(p, rpa_addr, false)))
		return;

	group_range gr, gr2;
	pim_for_each_group_range_safe(rpa, gr, gr2) {
		if(gr->to_delete)
			pim_rpa_gr_delete(p, rpa, gr);
	}
}


int pim_rpa_set_rpl_jp(pim p, struct in6_addr *rpa, bool rpl_jp)
{
	pim_rpa r;
	if(!(r = pim_rpa_goc(p, rpa, rpl_jp)))
		return rpl_jp?-1:0;

	if(rpl_jp == r->rpl_jp)
		return 0;

	r->rpl_jp = rpl_jp;
	L_DEBUG("RP Link "RPA_L" Join/Prune activity -> %s", RPA_LA(r), rpl_jp?"true":"false");

	pim_dfe dfe;
	pim_for_each_dfe_in_rpa(r, dfe) {
		pim_dfe_update_mod(dfe);
	}

	pim_rpa_update_state(p, r); //Delete maybe
	return 0;
}

void pim_rpa_dead_neighbor(__unused pim p, pim_neigh neigh) {

	/* For each dfe in the iface, we need to check */
	pim_dfe dfe;
	pim_for_each_dfe_in_iface(neigh->i, dfe) {
		if(dfe->df == neigh)
			pim_dfe_df_failure(dfe);
	}
}

static void pim_dfe_set_is_df(pim_dfe dfe, int is_df)
{
	if(dfe->is_df != is_df) {
		dfe->is_df = is_df;
		pim_group_is_df_change(dfe);
	}
}
#define pim_dfe_update_is_df(dfe) pim_dfe_set_is_df(dfe, PIM_DFE_IS_DF(dfe)?1:0)

static void pim_dfe_set_state(pim_dfe dfe, unsigned int state)
{
	if(dfe->state != state) {
		L_NOTICE(DFE_L" State -> %s", DFE_LA(dfe), pim_dfe_state_str[state]);
		dfe->state = state;
		pim_dfe_update_is_df(dfe);
	}
}

static void pim_dfe_set_df(pim_dfe dfe, pim_neigh df, const struct pp_df_metric *metric)
{
	pim_neigh old = NULL;
	if(dfe->df != df) {
		old = dfe->df;
		dfe->df = df;
		L_NOTICE(DFE_L" Designated Forwarder -> %s", DFE_LA(dfe), df?ADDR_REPR(&df->addr):"NULL");
		if(dfe == dfe->rpa->dfe)
			pim_group_upstream_df_update(dfe->iface->pim.p, dfe->rpa, old);
	}

	if(metric)
		dfe->df_metric = *metric;
}

pim_rpa pim_rpa_get_update(pim p, group g)
{
	g->pim_rpa = pim_rpa_find(p, &g->addr, 128);
	g->pim_rpa_set = 1;
	return g->pim_rpa;
}

static void pim_dfe_panic(pim_dfe dfe)
{
	L_ERR("Critical error for "DFE_L, DFE_LA(dfe));
	pim_dfe_set_mod(dfe, PIM_DFEM_NONE);
	L_ERR(DFE_L " will be reset in %dms", DFE_LA(dfe), PIM_RPA_PANIC_RETRY);
	dfe->timer.cb = pim_panic_timeout;
	uloop_timeout_set(&dfe->timer, PIM_RPA_PANIC_RETRY);
}

static int pim_dfe_timer_set(pim_dfe dfe, int delay, int cancel)
{
	dfe->timer.cb = pim_dfe_timeout;
	if((cancel || !dfe->timer.pending || (uloop_timeout_remaining(&dfe->timer) > delay)) &&
			uloop_timeout_set(&dfe->timer, delay)) {
		L_ERR("Can't set timeout for "DFE_L, DFE_LA(dfe));
		pim_dfe_panic(dfe);
		return -1;
	}
	return 0;
}

static int pim_dfe_set_mod(pim_dfe dfe, enum pim_dfe_mod mod)
{
	if(mod == dfe->mod)
		return 0;

	//timer is used in ELECTION and NONE (in case of panic) state only
	uloop_timeout_cancel(&dfe->timer);

	//Set new mod
	dfe->mod = mod;
	L_NOTICE(DFE_L" Mod -> %s", DFE_LA(dfe), pim_dfe_mod_str[mod]);

	switch (dfe->mod) {
	case PIM_DFEM_NONE:
		pim_dfe_set_is_df(dfe, 0);
		pim_dfe_set_df(dfe, NULL, NULL);
		break;
	case PIM_DFEM_RPL_ACTIVE:
	case PIM_DFEM_RPL_PASSIVE:
		pim_dfe_set_is_df(dfe, 0);
		pim_dfe_set_df(dfe, (dfe->mod == PIM_DFEM_RPL_ACTIVE)?&dfe->vneigh:NULL, NULL);
		break;
	case PIM_DFEM_ELECTION:
		dfe->state = PIM_DFE_LOSE;
		pim_dfe_set_df(dfe, NULL, NULL);
		pim_dfe_set_state(dfe, PIM_DFE_OFFER);
		dfe->message_counter = 0;
		pim_dfe_timer_set(dfe, DFE_OPLOW(dfe->iface), 1);
		break;
	default:
		break;
	}
	return 1;
}

static int pim_dfe_update_mod(pim_dfe dfe)
{
	if(!dfe->rpa->running || !dfe->iface->pim.neigh.hello_counter) {
		return pim_dfe_set_mod(dfe, PIM_DFEM_NONE);
	} else if(PIM_RPA_ONLINK(dfe->rpa, dfe->iface)) {
		return pim_dfe_set_mod(dfe, dfe->rpa->rpl_jp?PIM_DFEM_RPL_ACTIVE:PIM_DFEM_RPL_PASSIVE);
	} else {
		return pim_dfe_set_mod(dfe, PIM_DFEM_ELECTION);
	}
}

static void pim_panic_timeout(struct uloop_timeout *to)
{
	pim_dfe dfe = container_of(to, pim_dfe_s, timer);
	pim_dfe_update_mod(dfe);
}

void pim_rpa_sent_first_hello(iface i)
{
	pim_rpa rpa;
	pim_for_each_rpa(i->pim.p, rpa) {
		pim_dfe dfe = pim_dfe_find(i, rpa);
		if(dfe)
			pim_dfe_update_mod(dfe);
	}
}

static void pim_dfe_restart(pim_dfe dfe)
{
	pim_dfe_set_state(dfe, PIM_DFE_OFFER);
	pim_dfe_set_df(dfe, NULL, NULL);
	dfe->message_counter = 0;
	pim_dfe_timer_set(dfe, DFE_OPLOW(dfe->iface), 1);
}

static uint8_t *pim_dfe_header_set(pim_dfe dfe, uint8_t *packet, size_t len, enum pp_df_type type)
{
	struct pp_header *hdr = (struct pp_header *)packet;
	PP_HEADER_SET(hdr, PP_VERSION, PPT_DF_ELECTION);
	PP_DF_HEADER_SET(hdr, type);
	struct pp_addr *addr = PP_HEADER_DATA(hdr, len);
	pp_addr_set(addr, &dfe->rpa->addr);
	struct pp_df_hdr *df_hdr = PP_ADDR_SHIFT(addr, len);

	pim_dfe_metric_set(&df_hdr->sender_metric, dfe->rpa->path, dfe->iface);
	return PP_SHIFT(df_hdr, len, sizeof(*df_hdr));
}

static int pim_dfe_send_pass(pim_dfe dfe)
{
	uint8_t packet[128];
	struct pp_addr *addr = (struct pp_addr *)pim_dfe_header_set(dfe, packet, 128, PP_DFT_PASS);
	size_t len = packet + 128 - (uint8_t *)addr;
	pp_addr_set(addr, &dfe->best->addr);
	struct pp_df_pass *pass = PP_SHIFT(addr, len, PP_ADDR_LEN(addr));
	pass->new_metric = dfe->best_metric;
	PP_SHIFT(packet, len, sizeof(*pass));

	DFE_DEBUG("Sending pass on iface %s for %s", dfe->iface->ifname, ADDR_REPR(&dfe->best->addr));
	return pim_iface_sendto(dfe->iface, packet, 128 - len, &pp_all_routers);
}

static int pim_dfe_send_backoff(pim_dfe dfe, int interval)
{
	uint8_t packet[128];
	struct pp_addr *addr = (struct pp_addr *)pim_dfe_header_set(dfe, packet, 128, PP_DFT_BACKOFF);
	size_t len = packet + 128 - (uint8_t *)addr;
	pp_addr_set(addr, &dfe->best->addr);
	struct pp_df_backoff *backoff = PP_SHIFT(addr, len, PP_ADDR_LEN(addr));
	backoff->offer_metric = dfe->best_metric;
	PP_SHIFT(packet, len, sizeof(*backoff));
	PP_DF_BACKOFF_INTERVAL_SET(backoff, interval);

	DFE_DEBUG("Sending backoff on iface %s for %s", dfe->iface->ifname, ADDR_REPR(&dfe->best->addr));
	return pim_iface_sendto(dfe->iface, packet, 128 - len, &pp_all_routers);
}

static int pim_dfe_df_failure(pim_dfe dfe) {
	if(dfe->state == PIM_DFE_LOSE) {
		L_DEBUG(DFE_L" Designated Forwarder Failure", DFE_LA(dfe));
		pim_dfe_restart(dfe);
	} else {
		pim_dfe_set_df(dfe, NULL, NULL);
	}
	return 0;
}

static void pim_dfe_send_next_winoffer(pim_dfe dfe, int chain)
{
	uint8_t packet[128] = {}; //Init for valgrind
	uint8_t *end = pim_dfe_header_set(dfe, packet, 128, (dfe->state == PIM_DFE_WIN)?PP_DFT_WINNER:PP_DFT_OFFER);
	DFE_DEBUG("Sending %s on iface %s", (dfe->state == PIM_DFE_WIN)?"winner":"offer", dfe->iface->ifname);
	if(pim_iface_sendto(dfe->iface, packet, end - packet, &pp_all_routers)) {
		L_ERR("Can't send offer for "DFE_L, DFE_LA(dfe));
		pim_dfe_panic(dfe);
	} else if(chain && !pim_dfe_timer_set(dfe, DFE_OPLOW(dfe->iface), 1)) {
		dfe->message_counter++;
	}
}

static void pim_dfe_timeout(struct uloop_timeout *to)
{
	pim_dfe dfe = container_of(to, pim_dfe_s, timer);
	pim p = dfe->iface->pim.p;

	switch (dfe->state) {
	case PIM_DFE_LOSE:
		break;
	case PIM_DFE_OFFER:
		if(dfe->message_counter < conf_get_ifvalue(p->conf, dfe->iface, CIFV_PIM_DFE_ROBUSTNESS)) {
			pim_dfe_send_next_winoffer(dfe, 1);
		} else if(!PIM_DFE_NO_PATH(dfe)) { //There is a path to rpa
			pim_dfe_set_state(dfe, PIM_DFE_WIN);
			pim_dfe_set_df(dfe, NULL, NULL);
			pim_dfe_send_next_winoffer(dfe, 0);
		} else { //There is no path to rpa
			pim_dfe_set_state(dfe, PIM_DFE_LOSE);
			pim_dfe_set_df(dfe, NULL, NULL);
		}
		break;
	case PIM_DFE_WIN:
		if(dfe->message_counter < conf_get_ifvalue(p->conf, dfe->iface, CIFV_PIM_DFE_ROBUSTNESS)) {
			pim_dfe_send_next_winoffer(dfe, 1);
		}
		break;
	case PIM_DFE_BACKOFF:
		if(pim_dfe_send_pass(dfe)) {
			L_ERR("Can't send pass for "DFE_L, DFE_LA(dfe));
			pim_dfe_panic(dfe);
		} else {
			pim_dfe_set_state(dfe, PIM_DFE_LOSE);
			pim_dfe_set_df(dfe, dfe->best, &dfe->best_metric);
			dfe->best = NULL;
		}
		break;
	}
}

static void pim_dfe_rcv_offer(pim_dfe dfe, pim_neigh n, struct pp_df_hdr *df_hdr)
{
	pim p = dfe->iface->pim.p;
	struct pp_df_metric own;
	int backoff, cmp;
	pim_dfe_metric_set(&own, dfe->rpa->path, dfe->iface);
	cmp = pp_df_metric_cmp(&df_hdr->sender_metric, &n->addr, &own, &dfe->iface->lladdr->addr);
	if(cmp > 0) {
		DFE_DEBUG(DFE_L" Received better offer from "PIM_NEIGH_P, DFE_LA(dfe), PIM_NEIGH_PA(n));
		switch (dfe->state) {
		case PIM_DFE_LOSE:
		case PIM_DFE_OFFER:
			pim_dfe_set_state(dfe, PIM_DFE_OFFER);
			dfe->message_counter = 0;
			pim_dfe_timer_set(dfe,
					conf_get_ifvalue(p->conf, dfe->iface, CIFV_PIM_DFE_OFFER_PERIOD_MS) *
					conf_get_ifvalue(p->conf, dfe->iface, CIFV_PIM_DFE_ROBUSTNESS), 1);
			break;
		case PIM_DFE_WIN:
		case PIM_DFE_BACKOFF:
			pim_dfe_set_state(dfe, PIM_DFE_BACKOFF);
			backoff = conf_get_ifvalue(p->conf, dfe->iface, CIFV_PIM_DFE_BACKOFF_PERIOD_MS);
			dfe->best = n;
			dfe->best_metric = df_hdr->sender_metric;
			if(pim_dfe_send_backoff(dfe, backoff))
				pim_dfe_panic(dfe);
			else
				pim_dfe_timer_set(dfe, backoff, 1);
			break;
		}
	} else if(cmp < 0) {
		DFE_DEBUG(DFE_L" Received worse offer from "PIM_NEIGH_P, DFE_LA(dfe), PIM_NEIGH_PA(n));
		switch (dfe->state) {
		case PIM_DFE_OFFER:
		case PIM_DFE_LOSE:
			pim_dfe_set_state(dfe, PIM_DFE_OFFER);
			dfe->message_counter = 0;
			pim_dfe_timer_set(dfe, DFE_OPLOW(dfe->iface), 0);
			break;
		case PIM_DFE_BACKOFF:
			pim_dfe_set_state(dfe, PIM_DFE_WIN);
			uloop_timeout_cancel(&dfe->timer);
			//no break;
		case PIM_DFE_WIN:
			pim_dfe_send_next_winoffer(dfe, 0);
			break;
		}
	}
}

static void pim_dfe_rcv_worse_passwinbackoff(pim_dfe dfe, pim_neigh from, const struct pp_df_metric *from_metric)
{
	pim_dfe_set_state(dfe, PIM_DFE_OFFER);
	dfe->message_counter = 0;
	pim_dfe_set_df(dfe, from, from_metric);
	pim_dfe_timer_set(dfe, DFE_OPLOW(dfe->iface), 0);
}

static void pim_dfe_rcv_backoff(pim_dfe dfe, pim_neigh n, struct pp_df_hdr *df_hdr, uint8_t *buff, size_t len)
{
	pim p = dfe->iface->pim.p;
	struct pp_addr *a = (struct pp_addr *)buff;
	struct in6_addr offering_addr;
	struct pp_df_backoff *backoff;
	if(!(backoff = PP_ADDR_SHIFT(a, len)) ||
			pp_addr_get(&offering_addr, a) ||
			len < sizeof(*backoff)) {
		L_NOTICE("Malformed backoff packet");
		return;
	}

	if(RIB_ADDR_LOCAL(p->rib, &offering_addr, dfe->iface->ifindex)) {
		DFE_DEBUG(DFE_L" Received Backoff for us from "PIM_NEIGH_P, DFE_LA(dfe), PIM_NEIGH_PA(n));
		if(dfe->state == PIM_DFE_OFFER) {
			dfe->message_counter = 0;
			pim_dfe_timer_set(dfe, PP_DF_BACKOFF_INTERVAL(backoff) + DFE_OPLOW(dfe->iface), 1);
		} else {
			pim_dfe_set_df(dfe, n, &df_hdr->sender_metric);
			dfe->message_counter = 0;
			pim_dfe_timer_set(dfe, DFE_OPLOW(dfe->iface), 1);
		}
	} else {
		struct pp_df_metric own;
		pim_dfe_metric_set(&own, dfe->rpa->path, dfe->iface);
		int cmp = pp_df_metric_cmp(&backoff->offer_metric, &offering_addr, &own, &dfe->iface->lladdr->addr);
		if(cmp > 0) {
			DFE_DEBUG(DFE_L" Received better Backoff from "PIM_NEIGH_P, DFE_LA(dfe), PIM_NEIGH_PA(n));
			if(dfe->state == PIM_DFE_OFFER) {
				dfe->message_counter = 0;
				pim_dfe_timer_set(dfe, PP_DF_BACKOFF_INTERVAL(backoff) + DFE_OPLOW(dfe->iface), 1);
			} else {
				pim_dfe_set_state(dfe, PIM_DFE_LOSE);
				uloop_timeout_cancel(&dfe->timer);
				pim_dfe_set_df(dfe, n, &df_hdr->sender_metric);
			}
		} else if(cmp < 0) {
			DFE_DEBUG(DFE_L" Received worse Backoff from "PIM_NEIGH_P, DFE_LA(dfe), PIM_NEIGH_PA(n));
			pim_dfe_rcv_worse_passwinbackoff(dfe, n, &df_hdr->sender_metric);
		}
	}
}

static void pim_dfe_rcv_better_passwin(pim_dfe dfe, pim_neigh new_df, const struct pp_df_metric *new_metric)
{
	pim_dfe_set_state(dfe, PIM_DFE_LOSE);
	pim_dfe_set_df(dfe, new_df, new_metric);
	uloop_timeout_cancel(&dfe->timer);
}

static void pim_dfe_rcv_pass(pim_dfe dfe, pim_neigh n, struct pp_df_hdr *df_hdr, uint8_t *buff, size_t len)
{
	pim p = dfe->iface->pim.p;
	struct pp_addr *a = (struct pp_addr *)buff;
	struct in6_addr new_addr;
	struct pp_df_pass *pass;
	if(!(pass = PP_ADDR_SHIFT(a, len)) ||
			pp_addr_get(&new_addr, a) ||
			len < sizeof(*pass))
		return;

	if(RIB_ADDR_LOCAL(p->rib, &new_addr, dfe->iface->ifindex)) {
		DFE_DEBUG(DFE_L" Received Pass for us from "PIM_NEIGH_P, DFE_LA(dfe), PIM_NEIGH_PA(n));
		if(dfe->state == PIM_DFE_OFFER) {
			uloop_timeout_cancel(&dfe->timer);
			pim_dfe_set_state(dfe, PIM_DFE_WIN);
			pim_dfe_set_df(dfe, NULL, NULL);
		} else {
			pim_dfe_set_state(dfe, PIM_DFE_OFFER);
			dfe->message_counter = 0;
			pim_dfe_set_df(dfe, n, &df_hdr->sender_metric);
			pim_dfe_timer_set(dfe, DFE_OPLOW(dfe->iface), 1);
		}
	} else {
		pim_neigh new;
		if(!(new = pimn_neighbor_get(dfe->iface, &new_addr))) {
			L_WARN("Received pass from "PIM_NEIGH_P" with unknown target %s", PIM_NEIGH_PA(n), ADDR_REPR(&new_addr));
			return;
		}

		struct pp_df_metric own;
		pim_dfe_metric_set(&own, dfe->rpa->path, dfe->iface);
		int cmp = pp_df_metric_cmp(&pass->new_metric, &new_addr, &own, &dfe->iface->lladdr->addr);
		if(cmp > 0) {
			DFE_DEBUG(DFE_L" Received better Pass from "PIM_NEIGH_P, DFE_LA(dfe), PIM_NEIGH_PA(n));
			pim_dfe_rcv_better_passwin(dfe, new, &pass->new_metric);
		} else if(cmp < 0) {
			DFE_DEBUG(DFE_L" Received worse Pass from "PIM_NEIGH_P, DFE_LA(dfe), PIM_NEIGH_PA(n));
			pim_dfe_rcv_worse_passwinbackoff(dfe, new, &pass->new_metric);
		}
	}
}

static void pim_dfe_rcv_winner(pim_dfe dfe, pim_neigh n, struct pp_df_hdr *df_hdr)
{
	struct pp_df_metric own;
	pim_dfe_metric_set(&own, dfe->rpa->path, dfe->iface);
	int cmp = pp_df_metric_cmp(&df_hdr->sender_metric, &n->addr, &own, &dfe->iface->lladdr->addr);
	if(cmp > 0) {
		pim_dfe_rcv_better_passwin(dfe, n, &df_hdr->sender_metric);
	} else {
		pim_dfe_rcv_worse_passwinbackoff(dfe, n, &df_hdr->sender_metric);
	}
}

/* Called when rpa rib path is changed */
static void pim_dfe_path_changed(pim_dfe dfe, rib_entry old)
{
	struct pp_df_metric before, after;
	pim_dfe_metric_set(&after, dfe->rpa->path, dfe->iface);
	pim_dfe_metric_set(&before, old, dfe->iface);
	L_DEBUG(DFE_L" Best route changed with metric "
			PP_DF_METRIC_L" -> "PP_DF_METRIC_L, DFE_LA(dfe),
			PP_DF_METRIC_LA(&before), PP_DF_METRIC_LA(&after));

	if(pim_dfe_update_mod(dfe))
		return;

	if(dfe->mod != PIM_DFEM_ELECTION)
		return;

	L_DEBUG(DFE_L" Election Event: Route Changed (Current state is %s)",
			 DFE_LA(dfe), pim_dfe_state_str[dfe->state]);
	switch (dfe->state) {
		case PIM_DFE_BACKOFF:
			if(dfe->rpa->path) {
				if(pp_df_metric_cmp(&after, NULL, &dfe->best_metric, NULL) > 0) {
					DFE_DEBUG(DFE_L" Metric to RPA is better", DFE_LA(dfe));
					//New metric is better than best router
					pim_dfe_set_state(dfe, PIM_DFE_WIN);
					uloop_timeout_cancel(&dfe->timer);
				}
			} else if(old) { //Path to rpa is lost
				L_DEBUG(DFE_L" Path to RPA was lost", DFE_LA(dfe));
				pim_dfe_restart(dfe);
			}
			break;
		case PIM_DFE_WIN:
			if(dfe->rpa->path) {
				//We had a route if we were winner
				if(pp_df_metric_cmp(&after, NULL, &before, NULL) < 0) {
					DFE_DEBUG(DFE_L" Metric to RPA is worse", DFE_LA(dfe));
					dfe->message_counter = 0;
					pim_dfe_timer_set(dfe, DFE_OPLOW(dfe->iface), 1); //May destroy the dfe
				}
			} else if(old) {
				L_DEBUG(DFE_L" Path to RPA was lost", DFE_LA(dfe));
				pim_dfe_restart(dfe);
			}
			break;
		case PIM_DFE_LOSE:
			if((!dfe->df && !PP_DF_METRIC_IS_INFINITE(&after)) ||  //No df at all, any route will do
					(dfe->df && (pp_df_metric_cmp(&after, NULL, &dfe->df_metric, NULL) > 0))) {
				DFE_DEBUG(DFE_L" New route is better than current best", DFE_LA(dfe));
				pim_dfe_restart(dfe);
			}
			break;
		case PIM_DFE_OFFER:
			if(pp_df_metric_cmp(&after, NULL, &before, NULL) < 0) {
				DFE_DEBUG(DFE_L" New route is worse", DFE_LA(dfe));
				dfe->message_counter = 0;
				pim_dfe_timer_set(dfe, DFE_OPLOW(dfe->iface), 0);
			}
			break;
	}
}

void pim_dfe_rcv(iface i, uint8_t *buff, size_t len, struct in6_addr *from)
{
	struct pp_header *hdr = (struct pp_header *)buff;
	struct pp_addr *pp_rpa;
	struct in6_addr rpaddr;
	struct pp_df_hdr *df_hdr;
	pim_neigh neigh;
	pim_rpa rpa;
	pim_dfe dfe;

	if(!(neigh = pimn_neighbor_get(i, from))) {
		L_NOTICE("Ignoring DFE packet from unknown neighbor %s on iface %s", ADDR_REPR(from), i->ifname);
		return;
	}

	if(!(pp_rpa = PP_HEADER_DATA(hdr, len)) ||
			pp_addr_get(&rpaddr, pp_rpa) ||
			!(df_hdr = PP_SHIFT(pp_rpa, len, PP_ADDR_LEN(pp_rpa))) ||
			!(buff = PP_SHIFT(df_hdr, len, sizeof(*df_hdr)))) {
		L_NOTICE("Malformed DFE packet from "PIM_NEIGH_P, PIM_NEIGH_PA(neigh));
		return;
	}

	if(!(rpa = pim_rpa_goc(i->pim.p, &rpaddr, false))) {
		L_NOTICE("Ignoring DFE packet for unmanaged rpa %s from "PIM_NEIGH_P, ADDR_REPR(&rpaddr), PIM_NEIGH_PA(neigh));
		//todo: Maybe create it temporarily ?
		return;
	}

	if(!(dfe = pim_dfe_find(i, rpa))) {
		L_ERR("Can't find associated dfe "RPA_L, RPA_LA(rpa));
		return;
	}

	if(dfe->mod != PIM_DFEM_ELECTION) {
		L_DEBUG("Ignoring message from "PIM_NEIGH_P" for non-election "DFE_L, PIM_NEIGH_PA(neigh), DFE_LA(dfe));
		return;
	}

	L_DEBUG("Received DFE packet from "PIM_NEIGH_P" on iface %s of subtype %d",PIM_NEIGH_PA(neigh), i->ifname, PP_DF_SUBTYPE(hdr));
	switch (PP_DF_SUBTYPE(hdr)) {
		case PP_DFT_OFFER:
			pim_dfe_rcv_offer(dfe, neigh, df_hdr);
			break;
		case PP_DFT_BACKOFF:
			pim_dfe_rcv_backoff(dfe, neigh, df_hdr, buff, len);
			break;
		case PP_DFT_PASS:
			pim_dfe_rcv_pass(dfe, neigh, df_hdr, buff, len);
			break;
		case PP_DFT_WINNER:
			pim_dfe_rcv_winner(dfe, neigh, df_hdr);
			break;
		default:
			L_NOTICE("Unknown DFE subtype %d from "PIM_NEIGH_P" on iface %s", PP_DF_SUBTYPE(hdr), PIM_NEIGH_PA(neigh), i->ifname);
			break;
	}
}

static void pim_dfe_destroy(pim_dfe dfe)
{
	L_NOTICE("Destroying "DFE_L, DFE_LA(dfe));
	// Cancel timeout is necessary when it follows a panic.
	// State is then NONE, and therefore not updated.
	uloop_timeout_cancel(&dfe->timer);
	pim_dfe_set_mod(dfe, PIM_DFEM_NONE);
	dfe->rpa->dfes[dfe->iface->pim.pim_index] = NULL;
	if(dfe == dfe->rpa->dfe)
		pim_rpa_set_upstream_dfe(dfe->iface->pim.p, dfe->rpa, NULL);
	list_del(&dfe->vneigh.le);
	pim_jp_dead_neighbor(dfe->iface->pim.p, &dfe->vneigh); //Remove references to the virtual neighbor
	free(dfe);
}

/* DFE Management */
static int pim_dfe_create(pim_rpa rpa, iface i)
{
	pim_dfe dfe;
	if(!(dfe = calloc(1, sizeof(*dfe))))
		return -1;

	dfe->mod = PIM_DFEM_NONE;
	dfe->is_df = 0;
	dfe->iface = i;
	dfe->rpa = rpa;

	//Initialize virtual neighbor
	dfe->vneigh.addr = dfe->rpa->addr;
	dfe->vneigh.sent_hello = 1;
	dfe->vneigh.i = dfe->iface;
	dfe->vneigh.ssbidir_cap = 1;
	list_add(&dfe->vneigh.le, &i->pim.rpa_vneighs);
	rpa->dfes[i->pim.pim_index] = dfe;
	L_NOTICE("Creating "DFE_L, DFE_LA(dfe));

	pim_dfe_update_mod(dfe);
	if(rpa->path && (dfe->iface->ifindex == rpa->path->oif)) //This dfe becomes the upstream
		pim_rpa_set_upstream_dfe(i->pim.p, rpa, dfe);
	return 0;
}

int pim_rpa_iface_setup(iface i)
{
	//Initialize
	INIT_LIST_HEAD(&i->pim.rpa_vneighs);

	//Create dfes
	pim_rpa rpa;
	pim_for_each_rpa(i->pim.p, rpa) {
		if(rpa->running)
			pim_dfe_create(rpa, i); //todo: Uncaught error
	}
	return 0;
}

void pim_rpa_iface_teardown(iface i)
{
	pim_dfe dfe;
	pim_for_each_dfe_in_iface(i, dfe)
		pim_dfe_destroy(dfe);
}

void pim_rpa_rib_update(pim p, rib_entry e, __unused int del)
{
	pim_rpa rpa;
	pim_for_each_rpa(p, rpa) {
		if(rpa->running && prefix_contains(&e->dst, e->dst_plen, &rpa->addr))
			pim_rpa_update_path(p, rpa);
	}
}

/* Not really specified in the specs, but when a new neighbor
 * is discovered, and if we are winner, we need to tell him. */
void pim_rpa_new_neighbor(pim_neigh neigh)
{
	pim_dfe dfe;
	pim_for_each_dfe_in_iface(neigh->i, dfe) {
		//This isn't really good according to the specs.
		//Maybe we should create a temporary neighbor when we ear a DFE message.
		if(dfe->mod == PIM_DFEM_ELECTION)
			pim_dfe_send_next_winoffer(dfe, 0);
	}
}
