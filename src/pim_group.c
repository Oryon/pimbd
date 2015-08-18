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

#include "pim_group.h"

#include "pim_ctl.h"
#include "pim_proto.h"
#include "pim_neigh.h"
#include "pim_rpa.h"
#include "pim_jp.h"
#include "ifgroup.h"
#include "mrib.h"

static void pim_downstream_G_set_state(pim p, ifgroup ig, unsigned int state);

#define LOG_PACKET(action, iface, src, reason, ...) \
		{L_NOTICE("Packet dropped from %s on %s: "reason, src?ADDR_REPR(src):"self", iface->ifname, ##__VA_ARGS__); action;}
//do {L_NOTICE("Packet dropped from %s on %s: "reason, ADDR_REPR(src), iface->ifname, ##__VA_ARGS__); action; }while(0)

#define T_SUPPRESSED(conf, iface) (int) (conf_get_ifvalue(conf, iface, CIFV_PIM_US_T_PERIODIC_MS) * 1000 * (rand_i(1.1, 1.4)))
#define T_OVERRIDE(conf, iface) (int) (conf_get_ifvalue(conf, iface, CIFV_PIM_JP_OVERRIDE_INTERVAL_MS) * (rand_i(0, 0.9)))

#define T_UPDATE 10 //Todo: Make it a configuration variable

/*
 * Routing computation
 */

void pim_mrib_forward_upstream(pim p, iface inc, gsource gs, mrib_filter *filter)
{
	pim_rpa rpa = pim_rpa_get(p, gs->group);
	iface upstream;
	if(!rpa || !(upstream = rpa->dfe?rpa->dfe->iface:NULL)) {
		L_DEBUG("Forward "GSOURCE_L": No PIM upstream", GSOURCE_LA(gs));
		return;
	}
	if(inc == upstream) {
		L_DEBUG("Forward "GSOURCE_L": PIM Upstream is Input Iface", GSOURCE_LA(gs));
		return;
	}
	L_DEBUG("Forward "GSOURCE_L": Add upstream %s", GSOURCE_LA(gs), upstream->ifname);
	mrib_filter_add(filter, &upstream->pim.mrib_user);
}

void pim_mrib_forward_downstream(iface inc, gsource gs, mrib_filter *filter)
{
	//Forward downstream
	ifgroup ig;
	ifgsource ifgs;
	pim_dfe dfe2;
	ifgroups_for_each_in_group(gs->group, ig) {
		if(ig->iface == inc || //Incoming interface
				!(dfe2 = pim_dfe_get(ig)) || //No election state for this interface
				!dfe2->is_df) //Not the DF
			continue;

		ifgs = ifgsource_get(ig, gs, 0);
		if(((ig->pim_downstream != PIM_NONE) && (!ifgs || !(ifgs->pim_downstream_rpt == PIM_PRUNE))) ||  // + DownstreamJPState(G,I) todo: && !rpt
				(ig->conf_local_exclude) || // + Configured interface Join(*,G) todo: && !conf exclude
				(ig->pim_local_exclude && (!ifgs || !ifgs->pim_local_exclude)) || //+ local_receiver_exclude(G,I)
				(ifgs && ifgs->pim_local_include) || //+ local_receiver_include
				(ifgs && ifgs->pim_downstream)
		) {
			L_DEBUG("Forward "GSOURCE_L": Add upstream %s", GSOURCE_LA(gs), ig->iface->ifname);
			mrib_filter_add(filter, &ig->iface->pim.mrib_user);
		}
	}
}

static void pim_mrib_cb(struct mrib_user *user, const struct in6_addr *g_addr,
		const struct in6_addr *s_addr, mrib_filter *filter)
{
	iface inc = container_of(user, iface_s, pim.mrib_user);
	pim p = inc->pim.p;
	group g;
	source s;
	gsource gs;
	L_DEBUG("PIM mrib callback for (%s, %s) on %s", ADDR_REPR(g_addr), ADDR_REPR(s_addr), inc->ifname);

	if(IN6_IS_ADDR_LINKLOCAL(s_addr)) {
		L_INFO("Packet source address in link local...");
		return;
	}

	if(!(g = group_get(p->ifgroups, g_addr, 1)) ||
			!(s = source_get(p->ifgroups, s_addr, 1)) ||
			!(gs = gsource_get(g, s, 1))) {
		L_ERR("Could not allocate memory !");
		return;
	}

	//Downstream to upstream
	pim_rpa rpa = pim_rpa_get(p, g);
	if(!rpa) { //No rpa for that source
		L_INFO("Can't route group %s because no rpa is associated with it", ADDR_REPR(g_addr));
		return;
	}
	pim_dfe dfe = pim_dfe_find(inc, rpa);
	if(!dfe) {
		L_ERR("No election state for "RPA_L" on %s", RPA_LA(rpa), inc->ifname);
		return;
	}

	if(dfe->is_df)
		pim_mrib_forward_upstream(p, inc, gs, filter);

	pim_mrib_forward_downstream(inc, gs, filter);

	gsource_clean_maybe(gs);
}

static void pim_mrib_flush_groups(pim p, const struct in6_addr *g, uint8_t len, const struct in6_addr *s)
{
	iface i;
	L_DEBUG("Flushing mroutes to %s from %s", PREFIX_REPR(g, len), s?ADDR_REPR(s):"any");
	ifgroups_for_each_iface(p->ifgroups, i) {
		if(PIM_IF_RUNNING(i))
			mrib_flush(&i->pim.mrib_user, g, len, s);
	}
}

//Flush routing state for a whole rpa
static void pim_mrib_flush_rpa_iface(iface i, pim_rpa rpa)
{
	group_range gr;
	L_DEBUG("Flushing mroutes for "RPA_L" on %s", RPA_LA(rpa), i->ifname);
	pim_for_each_group_range(rpa, gr) {
		mrib_flush(&i->pim.mrib_user, &gr->group, gr->len, NULL);
	}
}

static void pim_mrib_flush_rpa_full(pim p, pim_rpa rpa)
{
	iface i;
	ifgroups_for_each_iface(p->ifgroups, i) {
		if(PIM_IF_RUNNING(i))
			pim_mrib_flush_rpa_iface(i, rpa);
	}
}

/*
 * Upstream getter
 */

pim_neigh pim_group_upstream_df(pim p, group g)
{
	pim_rpa rpa;
	return ((rpa = pim_rpa_get(p, g)) && rpa->dfe)?rpa->dfe->df:NULL;
}

static void pim_upstream_G_set(pim p, group g, unsigned int state);
static int pim_upstream_G(pim p, group g);
#define pim_upstream_G_update(p, g) pim_upstream_G_set(p, g, pim_upstream_G(p, g))

static void pim_upstream_G_S_set(pim p, gsource gs, unsigned int state);
static int pim_upstream_G_S(pim p, gsource gs);
#define pim_upstream_G_S_update(p, gs) pim_upstream_G_S_set(p, gs, pim_upstream_G_S(p, gs))

static void pim_upstream_G_S_rpt_set(pim p, gsource gs, unsigned int state);
static int pim_upstream_G_S_rpt(pim p, gsource gs);
#define pim_upstream_G_S_rpt_update(p, gs) pim_upstream_G_S_rpt_set(p, gs, pim_upstream_G_S_rpt(p, gs))

/*
 * (*,G) state
 */

static void pim_upstream_G_set(pim p, group g, unsigned int state) {
	if(state == g->pim_upstream)
		return;

	L_NOTICE("upstream_G"GROUP_L" -> %s", GROUP_LA(g), state?"JOIN":"NONE");

	if(!g->pim_upstream)
		group_ref(g);

	g->pim_upstream = state;
	pim_jp_update_G(p, g, PIM_JP_UPDATE_JD, pimbd_time(), T_UPDATE);
	pim_ctl_update_maybe_G(p, g);

	//(*,G) => !(S,G)
	//!(*,G) => !(S,G,rpt)
	//Update (G,S) and (G,S,rpt)
	gsource gs, gs2;
	ifgroups_for_each_source_in_group_safe(g, gs, gs2) {
		gsource_ref(gs);
		pim_upstream_G_S_update(p, gs);
		pim_upstream_G_S_rpt_update(p, gs);
		gsource_unref(gs);
	}

	if(!g->pim_upstream)
		group_unref(g);
}

static int pim_upstream_G(pim p, group g)
{
	pim_neigh udf;
	if(!((udf = pim_group_upstream_df(p, g))) ||
			g->conf_join_desired == PIM_PRUNE)
		return 0;

	if(g->conf_join_desired == PIM_JOIN || //By configuration
			(g->pim_jd_source_count && (!PIM_IF_SSBIDIR(udf->i) || !udf->ssbidir_cap))) //Some (S,G) is joined, but bidir disabled
		return 1;

	ifgroup ig;
	pim_dfe dfe;
	ifgroups_for_each_in_group(g, ig) {
		if(ig->iface != udf->i && // - RPF_interface(RPA(G))
				(dfe = pim_dfe_get(ig)) &&
				dfe->is_df && //I am DF
				(ig->pim_downstream != PIM_NONE || // + DownstreamJPState(G,I)
						ig->conf_local_exclude || // + Configured interface Join(*,G)
						ig->pim_local_exclude)  // + local_receiver_include(G,I) (BIDIR mode)
		)
			return 1;
	}
	return 0;
}

static void pim_upstream_G_rcv_joinprune(pim p, group g, int prune, iface i)
{
	if(g->pim_upstream == PIM_NONE)
		return;

	L_DEBUG("Received upstream %s for group "GROUP_L, prune?"PRUNE":"JOIN", GROUP_LA(g));

	if(prune) {
		pim_jp_update_G(p, g, PIM_JP_OVERRIDE, pimbd_time(), T_OVERRIDE(p->conf, i));
		if(g->pim_upstream) {
			gsource gs;
			ifgroups_for_each_source_in_group(g, gs)
				if(gs->pim_upstream_rpt)
					pim_jp_update_G_S_rpt(p, gs, PIM_JP_CANCEL_OT, pimbd_time(), 0);
		}
	} else {
		pim_jp_update_G(p, g, PIM_JP_SUPPRESS, pimbd_time(), T_SUPPRESSED(p->conf, i));
	}
}

/*
 * Downstream state machine
 */

static void pim_downstream_G_expiry_to(struct uloop_timeout *to)
{
	ifgroup ig = container_of(to, ifgroup_s, pim_expiry_timer);
	L_DEBUG("Downstream expiry timeout for ifgroup "IFGROUP_L, IFGROUP_LA(ig));
	pim_downstream_G_set_state(ig->iface->pim.p, ig, PIM_NONE);
}

static void pim_downstream_G_pp_to(struct uloop_timeout *to)
{
	ifgroup ig = container_of(to, ifgroup_s, pim_pp_timer);
	pim p = ig->iface->pim.p;
	L_DEBUG("Downstream prune pending timeout for ifgroup"IFGROUP_L, IFGROUP_LA(ig));
	//todo: Send prune echo
	pim_downstream_G_set_state(p, ig, PIM_NONE);
}

static void pim_downstream_G_set_state(pim p, ifgroup ig, unsigned int state)
{
	if(ig->pim_downstream == state)
		return;

	L_NOTICE("downstream_G"IFGROUP_L" -> %s", IFGROUP_LA(ig), (state == PIM_JOIN)?"JOIN":((state == PIM_PRUNEPENDING)?"PRUNE_PENDING":"NONE"));

	if(!ig->pim_downstream) {
		ifgroup_ref(ig);
		ig->pim_downstream = state;
		ig->pim_expiry_timer.pending = false;
		ig->pim_expiry_timer.cb = pim_downstream_G_expiry_to;
		ig->pim_pp_timer.pending = false;
		ig->pim_pp_timer.cb = pim_downstream_G_pp_to;
		pim_upstream_G_update(p, ig->group); //Always update, maybe we were DF and are not anymore
		pim_ctl_update_maybe_G(p, ig->group);
		pim_mrib_flush_groups(p, &ig->group->addr, 128, NULL);
	} else if(!state) {
		ig->pim_downstream = 0;
		uloop_timeout_cancel(&ig->pim_pp_timer);
		uloop_timeout_cancel(&ig->pim_expiry_timer);
		pim_upstream_G_update(p, ig->group);
		pim_ctl_update_maybe_G(p, ig->group);
		pim_mrib_flush_groups(p, &ig->group->addr, 128, NULL);
		ifgroup_unref(ig);
	} else { //Prunepending to/from join
		ig->pim_downstream = state;
	}
}

#define pim_downstream_G_set_expiry(p, ig, time) if(uloop_timeout_set(&(ig)->pim_expiry_timer, time)) pim_downstream_G_set_state(p, ig, PIM_NONE)
#define pim_downstream_G_set_pp_timer(p, ig) if(uloop_timeout_set(&(ig)->pim_pp_timer, \
		conf_get_ifvalue((ig)->iface->pim.p->conf, (ig)->iface, CIFV_PIM_JP_OVERRIDE_INTERVAL_MS))) pim_downstream_G_set_state(p, ig, PIM_NONE)

/*
 * Local Receiver state machine
 */

static void pim_local_include_G_set_state(pim p, ifgroup ig, char exclude)
{
	exclude = !!exclude; //1 or 0
	if(exclude == ig->pim_local_exclude)
		return;

	L_DEBUG("local_receiver_exclude_G"IFGROUP_L" -> %s",IFGROUP_LA(ig), exclude?"true":"false");

	if(exclude)
		ifgroup_ref(ig);

	ig->pim_local_exclude = exclude;
	pim_upstream_G_update(p, ig->group); //Upstream may change
	pim_ctl_update_maybe_G(p, ig->group);
	pim_mrib_flush_groups(p, &ig->group->addr, 128, NULL);

	if(!(exclude))
		ifgroup_unref(ig);
}


/*
 * (S,G,rpt) state
 */

static void pim_upstream_G_S_rpt_set(pim p, gsource gs, unsigned int state)
{
	if(gs->pim_upstream_rpt == state)
		return;

	if(!gs->pim_upstream_rpt)
		gsource_ref(gs);

	L_NOTICE("upstream_G_S_rpt"GSOURCE_L" -> %s", GSOURCE_LA(gs), state?"PRUNE":"NONE");
	gs->pim_upstream_rpt = state;

	pim_jp_update_G_S_rpt(p, gs, PIM_JP_UPDATE_JD, pimbd_time(), T_UPDATE);
	pim_ctl_update_maybe_G_S(p, gs);

	if(!gs->pim_upstream_rpt)
		gsource_unref(gs);
}

static int pim_upstream_G_S_rpt(pim p, gsource gs)
{
	pim_neigh udf;
	if(!gs->group->pim_upstream || //Never (S,G,rpt) if not (*,G)
			!(udf = pim_group_upstream_df(p, gs->group)) || //Need upstream (this is always false because (*,G)
			!PIM_IF_SSBIDIR(udf->i) || //Upstream iface is not bidir
			!udf->i->pim.ssbidir_neighs) //All neighbors are not bidir
		return 0;
	//Prune is valid here

	// When (*,G) is joined by configuration,
	// only (S,G,rpt) by conf. can revoke it.
	if(gs->conf_join_desired == PIM_PRUNE)
		return 1;

	if(gs->group->conf_join_desired == PIM_JOIN || //Joined the whole group by configuration
			gs->pim_join_desired) //Someone wants (S,G)
		return 0;

	//At least one downstream interface requests (*,G) and does not prune (S,G,rpt)
	ifgsource ifgs;
	pim_dfe dfe;
	ifgroups_for_each_iface_in_gsource(gs, ifgs) {
		if(ifgs->ig->iface != udf->i && //Not upstream interface
				(dfe = pim_dfe_get(ifgs->ig)) && dfe->is_df &&
				((ifgs->ig->pim_downstream && (ifgs->pim_downstream_rpt != PIM_PRUNE)) ||
									(ifgs->ig->pim_local_exclude && !ifgs->pim_local_exclude)))
			return 0;
	}

	return 1;
}

static void pim_local_exclude_G_S_set_state(pim p, ifgsource ifgs, char exclude)
{
	if(exclude == ifgs->pim_local_exclude)
		return;

	if(!ifgs->pim_local_exclude)
		ifgsource_ref(ifgs);

	L_DEBUG("PIM local_exclude"IFGSOURCE_L" -> %s", IFGSOURCE_LA(ifgs), exclude?"true":"false");
	ifgs->pim_local_exclude = exclude;

	pim_upstream_G_S_rpt_update(p, ifgs->gs);
	pim_ctl_update_maybe_G_S(p, ifgs->gs);
	pim_mrib_flush_groups(p, &ifgs->gs->group->addr, 128, &ifgs->gs->source->addr);

	if(!ifgs->pim_local_exclude)
		ifgsource_unref(ifgs);
}

static void pim_upstream_G_S_rpt_rcv_joinprune(pim p, gsource gs, int prune, iface i)
{
	if(prune) {
		if(gs->pim_upstream_rpt) {
			pim_jp_update_G_S_rpt(p, gs, PIM_JP_CANCEL_OT, pimbd_time(), 0);
		} else if(gs->group->pim_upstream) {
			pim_jp_update_G_S_rpt(p, gs, PIM_JP_OVERRIDE, pimbd_time(), T_OVERRIDE(p->conf, i));
		}
	} else {
		if(gs->pim_upstream_rpt) {
			pim_jp_update_G_S_rpt(p, gs, PIM_JP_SUPPRESS, pimbd_time(), T_SUPPRESSED(p->conf, i));
		} else if(gs->group->pim_upstream) {
			pim_jp_update_G_S_rpt(p, gs, PIM_JP_CANCEL_OT, pimbd_time(), 0);
		}
	}
}

static void pim_downstream_G_S_rpt_set_state(pim p, ifgsource ifgs, unsigned int state);

static void pim_downstream_G_S_rpt_expiry_to(struct uloop_timeout *to)
{
	ifgsource ifgs = container_of(to, ifgsource_s, pim_rpt_expiry_timer);
	L_DEBUG("Downstream rpt expiry timeout for ifgsource "IFGSOURCE_L, IFGSOURCE_LA(ifgs));
	pim_downstream_G_S_rpt_set_state(ifgs->ig->iface->pim.p, ifgs, PIM_NONE);
}

static void pim_downstream_G_S_rpt_pp_to(struct uloop_timeout *to)
{
	ifgsource ifgs = container_of(to, ifgsource_s, pim_rpt_pp_timer);
	L_DEBUG("Downstream rpt prune pending timeout for ifgsource"IFGSOURCE_L, IFGSOURCE_LA(ifgs));
	//todo: Send prune echo
	pim_downstream_G_S_rpt_set_state(ifgs->ig->iface->pim.p, ifgs, PIM_PRUNE);
}

static void pim_downstream_G_S_rpt_set_state(pim p, ifgsource ifgs, unsigned int state)
{
	if(ifgs->pim_downstream_rpt == state)
		return;

	L_NOTICE("downstream_G_S_rpt"IFGSOURCE_L" -> %s", IFGSOURCE_LA(ifgs), (state == PIM_PRUNE)?"PRUNE":((state == PIM_PRUNEPENDING)?"PRUNE_PENDING":"NONE"));

	ifgsource_ref(ifgs);
	if(!ifgs->pim_downstream_rpt) {
		ifgsource_ref(ifgs);
		ifgs->pim_downstream_rpt = state;
		ifgs->pim_rpt_expiry_timer.pending = false;
		ifgs->pim_rpt_expiry_timer.cb = pim_downstream_G_S_rpt_expiry_to;
		ifgs->pim_rpt_pp_timer.pending = false;
		ifgs->pim_rpt_pp_timer.cb = pim_downstream_G_S_rpt_pp_to;
	} else if(!state) {
		ifgs->pim_downstream_rpt = 0;
		uloop_timeout_cancel(&ifgs->pim_rpt_pp_timer);
		uloop_timeout_cancel(&ifgs->pim_rpt_expiry_timer);
		ifgsource_unref(ifgs);
	} else { //Prunepending to/from prune
		ifgs->pim_downstream_rpt = state;
	}
	pim_upstream_G_S_rpt_update(p, ifgs->gs);
	pim_ctl_update_maybe_G_S(p, ifgs->gs);
	pim_mrib_flush_groups(p, &ifgs->gs->group->addr, 128, &ifgs->gs->source->addr);
	ifgsource_unref(ifgs);
}

#define pim_downstream_G_S_rpt_set_expiry(p, ifgs, time) if(uloop_timeout_set(&(ifgs)->pim_rpt_expiry_timer, time)) pim_downstream_G_S_rpt_set_state(p, ifgs, PIM_NONE)
#define pim_downstream_G_S_rpt_set_pp_timer(p, ifgs) if(uloop_timeout_set(&(ifgs)->pim_rpt_pp_timer, \
		conf_get_ifvalue((ifgs)->ig->iface->pim.p->conf, (ifgs)->ig->iface, CIFV_PIM_JP_OVERRIDE_INTERVAL_MS))) pim_downstream_G_S_rpt_set_state(p, ifgs, PIM_NONE)


/*
 * (S,G) state
 */

static void pim_upstream_G_S_set(pim p, gsource gs, unsigned int state)
{
	if(gs->pim_upstream == state)
		return;

	if(!gs->pim_upstream)
		gsource_ref(gs);

	L_NOTICE("upstream_G_S"GSOURCE_L" -> %s", GSOURCE_LA(gs), state?"JOIN":"NONE");
	gs->pim_upstream = state;

	pim_jp_update_G_S(p, gs, PIM_JP_UPDATE_JD, pimbd_time(), T_UPDATE);
	pim_ctl_update_maybe_G_S(p, gs);

	if(!gs->pim_upstream)
		gsource_unref(gs);
}

static int pim_upstream_G_S(pim p, gsource gs)
{
	pim_neigh udf;
	return gs->pim_join_desired && //Someone wants G_S specifically
			!gs->group->pim_upstream && //No-one wants the whole group
			(udf = pim_group_upstream_df(p, gs->group)) && //Upstream router exists
			udf->ssbidir_cap && //Upstream is ssbidir capable
			PIM_IF_SSBIDIR(udf->i); //Upstream iface iss ssbidir capable
}

static void pim_join_desired_G_S_set(pim p, gsource gs, unsigned int state)
{
	if(gs->pim_join_desired ==  state)
		return;

	L_NOTICE("join_desired_G_S"GSOURCE_L" -> %s", GSOURCE_LA(gs), state?"JOIN":"NONE");

	if(!gs->pim_join_desired)
		gsource_ref(gs);

	gs->pim_join_desired = state;
	pim_upstream_G_S_update(p, gs);

	/* Increment or decrement source ctr
	 * It is used in BIDIR backward compatibility mode
	 */
	gs->group->pim_jd_source_count += state?1:-1;
	if((state && gs->group->pim_jd_source_count == 1) ||
			(!state && !gs->group->pim_jd_source_count))
		pim_upstream_G_update(p, gs->group);

	pim_upstream_G_S_rpt_update(p, gs); //(S,G) may prevent (S,G,rpt)

	if(!gs->pim_join_desired)
		gsource_unref(gs);
}

static int pim_join_desired_G_S(pim p, gsource gs)
{
	pim_neigh udf;
	if(!(udf = pim_group_upstream_df(p, gs->group)))
		return 0;

	if(gs->conf_join_desired)
		return (gs->conf_join_desired == PIM_JOIN)?1:0;

	ifgsource ifgs;
	pim_dfe dfe;
	ifgroups_for_each_iface_in_gsource(gs, ifgs) {
		if(ifgs->ig->iface != udf->i && //Not upstream interface
				(dfe = pim_dfe_get(ifgs->ig)) && dfe->is_df && //We are DF on downstream iface
				(ifgs->pim_downstream != PIM_NONE ||
						ifgs->pim_local_include)
		)
			return 1;
	}
	return 0;
}

#define pim_join_desired_G_S_update(p, gs) pim_join_desired_G_S_set(p, gs, pim_join_desired_G_S(p, gs))

static void pim_upstream_G_S_rcv_joinprune(pim p, gsource gs, int prune, iface i)
{
	if(gs->pim_upstream == PIM_NONE)
		return;

	L_DEBUG("Received upstream %s for group "GSOURCE_L, prune?"PRUNE":"JOIN", GSOURCE_LA(gs));

	if(prune) {
		pim_jp_update_G_S(p, gs, PIM_JP_OVERRIDE, pimbd_time(), T_OVERRIDE(p->conf, i));
	} else {
		pim_jp_update_G_S(p, gs, PIM_JP_SUPPRESS, pimbd_time(), T_SUPPRESSED(p->conf, i));
	}
}

/*
 * Downstream state machine
 */

static void pim_downstream_G_S_set_state(pim p, ifgsource ifgs, unsigned int state);

static void pim_downstream_G_S_expiry_to(struct uloop_timeout *to)
{
	ifgsource ifgs = container_of(to, ifgsource_s, pim_expiry_timer);
	L_DEBUG("Downstream expiry timeout for ifgsource "IFGSOURCE_L, IFGSOURCE_LA(ifgs));
	pim_downstream_G_S_set_state(ifgs->ig->iface->pim.p, ifgs, PIM_NONE);
}

static void pim_downstream_G_S_pp_to(struct uloop_timeout *to)
{
	ifgsource ifgs = container_of(to, ifgsource_s, pim_pp_timer);
	L_DEBUG("Downstream prune pending timeout for ifgsource"IFGSOURCE_L, IFGSOURCE_LA(ifgs));
	//todo: Send prune echo
	pim_downstream_G_S_set_state(ifgs->ig->iface->pim.p, ifgs, PIM_NONE);
}

static void pim_downstream_G_S_set_state(pim p, ifgsource ifgs, unsigned int state)
{
	if(ifgs->pim_downstream == state)
		return;

	L_NOTICE("downstream_G_S"IFGSOURCE_L" -> %s", IFGSOURCE_LA(ifgs), (state == PIM_JOIN)?"JOIN":((state == PIM_PRUNEPENDING)?"PRUNE_PENDING":"NONE"));

	if(!ifgs->pim_downstream) {
		ifgsource_ref(ifgs);
		ifgs->pim_downstream = state;
		ifgs->pim_expiry_timer.pending = false;
		ifgs->pim_expiry_timer.cb = pim_downstream_G_S_expiry_to;
		ifgs->pim_pp_timer.pending = false;
		ifgs->pim_pp_timer.cb = pim_downstream_G_S_pp_to;
		pim_join_desired_G_S_update(p, ifgs->gs); //Always update, maybe we were DF and are not anymore
		pim_ctl_update_maybe_G_S(p, ifgs->gs);
		pim_mrib_flush_groups(p, &ifgs->gs->group->addr, 128, &ifgs->gs->source->addr);
	} else if(!state) {
		ifgs->pim_downstream = 0;
		uloop_timeout_cancel(&ifgs->pim_pp_timer);
		uloop_timeout_cancel(&ifgs->pim_expiry_timer);
		pim_join_desired_G_S_update(p, ifgs->gs);
		pim_ctl_update_maybe_G_S(p, ifgs->gs);
		pim_mrib_flush_groups(p, &ifgs->gs->group->addr, 128, &ifgs->gs->source->addr);
		ifgsource_unref(ifgs);
	} else { //Prunepending to/from join
		ifgs->pim_downstream = state;
	}
}

#define pim_downstream_G_S_set_expiry(p, ifgs, time) if(uloop_timeout_set(&(ifgs)->pim_expiry_timer, time)) pim_downstream_G_S_set_state(p, ifgs, PIM_NONE)
#define pim_downstream_G_S_set_pp_timer(p, ifgs) if(uloop_timeout_set(&(ifgs)->pim_pp_timer, \
		conf_get_ifvalue((ifgs)->ig->iface->pim.p->conf, (ifgs)->ig->iface, CIFV_PIM_JP_OVERRIDE_INTERVAL_MS))) pim_downstream_G_S_set_state(p, ifgs, PIM_NONE)

static void pim_local_include_G_S_set_state(pim p, ifgsource ifgs, char include)
{
	if(include == ifgs->pim_local_include)
		return;

	if(!ifgs->pim_local_include)
		ifgsource_ref(ifgs);

	L_DEBUG("PIM local_include"IFGSOURCE_L" -> %s", IFGSOURCE_LA(ifgs), include?"true":"false");
	ifgs->pim_local_include = include;

	pim_join_desired_G_S_update(p, ifgs->gs);
	pim_ctl_update_maybe_G_S(p, ifgs->gs);
	pim_mrib_flush_groups(p, &ifgs->gs->group->addr, 128, &ifgs->gs->source->addr);
	if(!ifgs->pim_local_include)
		ifgsource_unref(ifgs);
}

/*
 * External calls/events
 */

void pim_group_rcv_joinprune_G(ifgroup ig, int prune, uint16_t holdtime_s)
{
	pim p = ig->iface->pim.p;

	L_DEBUG("Received %s for ifgroup "IFGROUP_L, prune?"PRUNE":"JOIN", IFGROUP_LA(ig));

	if(prune) {
		switch (ig->pim_downstream) {
		case PIM_NONE:
		case PIM_PRUNEPENDING:
			break;
		case PIM_JOIN:
			if(pimn_has2neigh(ig->iface)) {
				pim_downstream_G_set_state(p, ig, PIM_PRUNEPENDING);
				pim_downstream_G_set_pp_timer(p, ig);
			} else {
				pim_downstream_G_set_state(p, ig, PIM_NONE);
			}
			break;
		default:
			break;
		}
	} else {
		switch (ig->pim_downstream) {
		case PIM_PRUNEPENDING:
			uloop_timeout_cancel(&ig->pim_pp_timer);
			//no break
		case PIM_JOIN:
		case PIM_NONE:
			pim_downstream_G_set_state(p, ig, PIM_JOIN);
			pim_downstream_G_set_expiry(p, ig,
					(holdtime_s == PP_JP_HOLDTIME_MAX)?
							PP_JP_HOLDTIME_FOREVER_MS:
							((int)holdtime_s) * 1000);
			break;
		default:
			break;
		}
	}
}

void pim_group_rcv_joinprune_G_S(ifgsource ifgs, int prune, uint16_t holdtime_s)
{
	pim p = ifgs->ig->iface->pim.p;
	L_DEBUG("Received %s for ifgsource "IFGSOURCE_L, prune?"PRUNE":"JOIN", IFGSOURCE_LA(ifgs));

	if(prune) {
		if(ifgs->pim_downstream == PIM_JOIN) {
			if(pimn_has2neigh(ifgs->ig->iface)) {
				pim_downstream_G_S_set_state(p, ifgs, PIM_PRUNEPENDING);
				pim_downstream_G_S_set_pp_timer(p, ifgs);
			} else {
				pim_downstream_G_S_set_state(p, ifgs, PIM_NONE);
			}
		}
	} else {
		if(ifgs->pim_downstream == PIM_PRUNEPENDING)
			uloop_timeout_cancel(&ifgs->pim_pp_timer);

		pim_downstream_G_S_set_state(p, ifgs, PIM_JOIN);
		pim_downstream_G_S_set_expiry(p, ifgs,
				(holdtime_s == PP_JP_HOLDTIME_MAX)?
						PP_JP_HOLDTIME_FOREVER_MS:
						((int)holdtime_s) * 1000);
	}
}

void pim_group_rcv_joinprune_G_S_rpt(ifgsource ifgs, int prune, uint16_t holdtime_s)
{
	pim p = ifgs->ig->iface->pim.p;
	L_DEBUG("Received RPT %s for ifgsource "IFGSOURCE_L, prune?"PRUNE":"JOIN", IFGSOURCE_LA(ifgs));

	if(prune) {
		if(ifgs->pim_downstream_rpt == PIM_NONE) {
			if(pimn_has2neigh(ifgs->ig->iface)) {
				pim_downstream_G_S_rpt_set_state(p, ifgs, PIM_PRUNEPENDING);
				pim_downstream_G_S_rpt_set_pp_timer(p, ifgs);
			} else {
				pim_downstream_G_S_rpt_set_state(p, ifgs, PIM_PRUNE);
			}
			pim_downstream_G_S_rpt_set_expiry(p, ifgs,
					(holdtime_s == PP_JP_HOLDTIME_MAX)?
							PP_JP_HOLDTIME_FOREVER_MS:
							((int)holdtime_s) * 1000);
		} else if ((ifgs->pim_downstream_rpt == PIM_PRUNEPENDING) && ifgs->pim_saw_rpt_prune) {
			//This is rather weird in the RFC as it does not happen in non-temporary state
			int time = (holdtime_s == PP_JP_HOLDTIME_MAX)?PP_JP_HOLDTIME_FOREVER_MS:
					((int)holdtime_s) * 1000;
			if(time > uloop_timeout_remaining(&ifgs->pim_rpt_expiry_timer))
				pim_downstream_G_S_rpt_set_expiry(p, ifgs, time);
		}
	} else {
		pim_downstream_G_S_rpt_set_state(p, ifgs, PIM_NONE);
	}
}

void pim_group_is_df_change(pim_dfe dfe)
{
	ifgroup ig, ig2;
	ifgsource ifgs, ifgs2;
	pim p = dfe->iface->pim.p;
	if(!dfe->is_df) {
		//Not df anymore, router shouldn't forward for downstream subscribers
		//It is rather weird to flush state like this, but these are the specs so...
		ifgroups_for_each_in_iface_safe(dfe->iface, ig, ig2) {
			if(dfe == pim_dfe_get(ig)) {
				ifgroup_ref(ig);
				pim_downstream_G_set_state(p, ig, PIM_NONE); //Lose state because we are not DF anymore
				ifgroups_for_each_source_in_ig_safe(ig, ifgs, ifgs2) {
					ifgsource_ref(ifgs);
					pim_downstream_G_S_set_state(p, ifgs, PIM_NONE);
					pim_downstream_G_S_rpt_set_state(p, ifgs, PIM_NONE);
					ifgsource_unref(ifgs);
				}
				ifgroup_unref(ig);
			}
		}
	} else {
		//Router is DFE, so it should start relaying traffic for it
		ifgroups_for_each_in_iface(dfe->iface, ig) {
			if(dfe == pim_dfe_get(ig)) {
				/* When becoming df, we need to update everything in case we have local join
				   on the interface. There probably are some filtering conditions which could be
				   added for efficiency. */
				ifgroup_ref(ig);
				pim_upstream_G_update(p, ig->group);
				ifgroups_for_each_source_in_ig_safe(ig, ifgs, ifgs2) {
					ifgsource_ref(ifgs);
					pim_upstream_G_S_update(p, ifgs->gs);
					pim_upstream_G_S_rpt_update(p, ifgs->gs);
					ifgsource_unref(ifgs);
				}
				ifgroup_unref(ig);
			}
		}
	}
	pim_mrib_flush_rpa_full(dfe->iface->pim.p, dfe->rpa);
}

void pim_group_upstream_df_update(pim p, pim_rpa rpa, __unused pim_neigh old)
{
	group g, g2;
	gsource gs, gs2;
	L_DEBUG("Upstream DF change for rpa %s "PIM_NEIGH_P" -> "PIM_NEIGH_P,
			ADDR_REPR(&rpa->addr),
			PIM_NEIGH_PA(old),
			PIM_NEIGH_PA(rpa->dfe?rpa->dfe->df:NULL));
	pimbd_time_t now = pimbd_time();
	ifgroups_for_each_group_safe(p->ifgroups, g, g2) {
		//We only change DF for groups that use the corresponding RPA
		if(pim_rpa_get(p, g) == rpa) {
			group_ref(g);
			pim_upstream_G_update(p, g); //Join desired requires a df
			pim_jp_update_G(p, g, PIM_JP_UPDATE_DF, now, T_UPDATE);

			ifgroups_for_each_source_in_group_safe(g, gs, gs2) {
				gsource_ref(gs);
				pim_join_desired_G_S_update(p, gs); //Join desired requires a df
				pim_jp_update_G_S(p, gs, PIM_JP_UPDATE_DF, now, T_UPDATE);
				pim_upstream_G_S_rpt_update(p, gs); //Join desired requires a df
				pim_jp_update_G_S_rpt(p, gs, PIM_JP_UPDATE_DF, now, T_UPDATE);
				gsource_unref(gs);
			}
			group_unref(g);
		}
	}
}

static ifgroup pim_group_ifgroup_get(pim p, iface i, struct in6_addr *gr)
{
	group g;
	ifgroup ig;
	if(!(g = group_get(p->ifgroups, gr, true))) {
		L_ERR("Could not create group %s on %s", ADDR_REPR(gr), i->ifname);
		return NULL;
	}

	if(!pim_rpa_get(p, g)) {
		L_WARN("No RPA for group %s", ADDR_REPR(gr));
		group_clean_maybe(g);
		return NULL;
	}

	if(!(ig = ifgroup_get(i, g, true))) { //Create the ig
		L_ERR("Could not create ifgroup %s on %s", ADDR_REPR(gr), i->ifname);
		group_clean_maybe(g);
		return NULL;
	}

	if(!pim_dfe_get(ig)) {
		L_ERR("Could not find dfe for group %s on %s", ADDR_REPR(gr), i->ifname);
		ifgroup_clean_maybe(ig);
		return NULL;
	}

	return ig;
}

void pim_group_rcv_joinprune(iface i, const uint8_t *buff, size_t len, struct in6_addr *from)
{
	const struct pp_header *hdr = (struct pp_header *)buff;
	const struct pp_addr *upstream_neigh;
	struct in6_addr upstream_addr, group_addr, source_addr;
	const struct pp_jp *jp_hdr;
	ifgroup ig;
	ifgsource ifgs, ifgs2;
	int n_groups, n_sources, skip_group, prune, for_us, g_joined;
	const struct pp_group *pp_group;
	const struct pp_jp_group *jp_group;
	uint8_t group_plen, source_plen;
	const struct pp_source *source;
	uint16_t holdtime_s;
	pim_neigh udf = NULL;
	pim_dfe dfe;

	L_DEBUG("Receiving Join/Prune of length %d from %s on %s", (int) len, from?ADDR_REPR(from):"self", i->ifname);

	if(!(upstream_neigh = PP_SHIFT(buff, len, sizeof(*hdr))) ||  // Check PIM header
			!(jp_hdr = PP_ADDR_SHIFT(upstream_neigh, len)) ||    // Check length for upstream address
			pp_addr_get(&upstream_addr, upstream_neigh) ||       // Get upstream address
			!(buff = PP_SHIFT(jp_hdr, len, sizeof(*jp_hdr))))    // Check J/P header length
		LOG_PACKET(return, i, from, "Invalid packet format");

	for_us = from && RIB_ADDR_LOCAL(i->pim.p->rib, &upstream_addr, i->ifindex);

	if(from && !pimn_neighbor_get(i, from))
		LOG_PACKET(return, i, from, "No neighbor with such address");

	holdtime_s = PP_JP_HOLDTIME_GET(jp_hdr);

	for(n_groups = jp_hdr->num_groups; n_groups; n_groups--) {
		pp_group = (struct pp_group *)buff; //Get the next pp_group
		skip_group = false;
		if(!(jp_group = PP_GROUP_SHIFT(pp_group, len)) ||               // Check group length
				!(buff = PP_SHIFT(jp_group, len, sizeof(*jp_group))) || // Check group J/P header
				pp_group_get(&group_addr, &group_plen, pp_group))       // Get group address
			LOG_PACKET(return, i, from, "Packet too short for Join/Prune group");

		if(group_plen != 128)
			LOG_PACKET(skip_group = true, i, from, "Group ranges are not supported. Blame the developer.");
		//todo: Support that (requires changing logic in group state, use prefixes instead of groups...)

		if(!PP_GROUP_BIDIR(pp_group)) //Only support PIM BIDIR for now
			LOG_PACKET(skip_group = true, i, from, "This version only supports BIDIR PIM");

		if(!(ig = pim_group_ifgroup_get(i->pim.p, i, &group_addr)))
			LOG_PACKET(skip_group = true, i, from, "Could not find group %s on %s", PREFIX_REPR(&group_addr, group_plen), i->ifname);

		dfe = NULL;
		if(ig) {
			ifgroup_ref(ig);
			udf = pim_group_upstream_df(i->pim.p, ig->group);
			if(!udf || (udf->i != i) || addr_cmp(&udf->addr, &upstream_addr))
				udf = NULL;

			if(udf)
				dfe = pim_dfe_get(ig);

			if(!(for_us || (dfe && dfe->mod == PIM_DFEM_RPL_ACTIVE)) &&
					!(from && udf)) //We don't care about this group
				skip_group = 1;
		}

		n_sources = PP_JP_GROUP_JOINED(jp_group);
		prune = false;
		g_joined = false;
		do {
			while(n_sources--) {
				source = (struct pp_source *)buff;
				if(!(buff = PP_SOURCE_SHIFT(source, len)))
					LOG_PACKET(return, i, from, "Packet too short for source");

				if(skip_group)
					continue;

				if(pp_source_get(&source_addr, &source_plen, source)) //Get the source prefix (which is actually RPA's)
					LOG_PACKET(continue, i, from, "Invalid source format");

				if(source_plen != 128)
					LOG_PACKET(continue, i, from, "Only handle 128 bits long source prefixes. Blame the developer.");

				if(PP_SOURCE_WILDCARD(source)) { //(*,G) record
					if(!PP_SOURCE_RPT(source))
						LOG_PACKET(continue, i, from, "Wildcard Join/Prune with rpt bit unset");

					if(source_plen != 128 || addr_cmp(&pim_rpa_get(i->pim.p, ig->group)->addr, &source_addr))
						LOG_PACKET(continue, i, from, "RPA address do not match");

					if(for_us || (dfe && dfe->mod == PIM_DFEM_RPL_ACTIVE)) { //Receive a joinprune for us
						pim_group_rcv_joinprune_G(ig, prune, holdtime_s);
						if(!prune)
							g_joined = 1;
					}

					if(from && udf) //JP to df on upstream iface
						pim_upstream_G_rcv_joinprune(i->pim.p, ig->group, prune, ig->iface);
				} else {
					ifgsource ifgs;
					if(!PIM_IF_SSBIDIR(i))
						LOG_PACKET(continue, i, from, "SSBIDIR disabled on %s", i->ifname);

					if(!(ifgs = ifgsource_get(ig, gsource_get(ig->group, source_get(i->ifgroups, &source_addr, 1), 1), 1)))
						LOG_PACKET(continue, i, from, "Memory allocation failed (ifgsource).");

					ifgsource_ref(ifgs);

					if (!PP_SOURCE_RPT(source)) { //(S,G) record
						if(for_us || (dfe && dfe->mod == PIM_DFEM_RPL_ACTIVE))
							pim_group_rcv_joinprune_G_S(ifgs, prune, holdtime_s);

						if(from && udf) //JP to df on upstream iface
							pim_upstream_G_S_rcv_joinprune(i->pim.p, ifgs->gs, prune, ig->iface);
					} else { //(S,G,rpt) record
						if(for_us || (dfe && dfe->mod == PIM_DFEM_RPL_ACTIVE)) {
							if(g_joined && prune)
								ifgs->pim_saw_rpt_prune = 1; //Must be before rcv_joinprune, as it is used
							pim_group_rcv_joinprune_G_S_rpt(ifgs, prune, holdtime_s);
						}

						if(from && udf) //JP to df on upstream iface
							pim_upstream_G_S_rpt_rcv_joinprune(i->pim.p, ifgs->gs, prune, ig->iface);
					}

					ifgsource_unref(ifgs);
				}
			}

			n_sources = PP_JP_GROUP_PRUNED(jp_group);
		} while((prune = !prune)); //This loop is executed twice. First with prune = false, then with prune = true.

		//Clean temporary rpt state
		if(g_joined && PIM_IF_SSBIDIR(i)) {
			ifgroups_for_each_source_in_ig_safe(ig, ifgs, ifgs2) {
				if(!ifgs->pim_saw_rpt_prune) {
					pim_downstream_G_S_rpt_set_state(i->pim.p, ifgs, PIM_NONE);
				} else {
					ifgs->pim_saw_rpt_prune = 0;
				}
			}
		}

		if(ig)
			ifgroup_unref(ig);
	}
}

/* Called when the rpa changed */
void pim_group_rpa_update(pim p, group g, pim_rpa old)
{
	pim_rpa rpa = pim_rpa_get(p, g);
	if(!rpa) {
		ifgroup ig, ig2;
		ifgsource ifgs, ifgs2;
		group_ref(g); //Secure the group to avoid removal
		ifgroups_for_each_in_group_safe(g, ig, ig2) {
			ifgroup_ref(ig);
			pim_downstream_G_set_state(p, ig, PIM_NONE); //Remove downstream state.
			ifgroups_for_each_source_in_ig_safe(ig, ifgs, ifgs2) {
				ifgsource_ref(ifgs);
				pim_downstream_G_S_set_state(p, ifgs, PIM_NONE);
				pim_downstream_G_S_rpt_set_state(p, ifgs, PIM_NONE);
				ifgsource_unref(ifgs);
			}
			ifgroup_unref(ig);
		}
		group_unref(g);
	} else if(((old && old->dfe)?(old->dfe->df):NULL) != ((rpa->dfe)?(rpa->dfe->df):NULL)) {
		gsource gs, gs2;
		pimbd_time_t now = pimbd_time();
		//Different df
		group_ref(g); //Secure the group to avoid removal
		pim_upstream_G_update(p, g); //Join desired requires a df
		pim_jp_update_G(p, g, PIM_JP_UPDATE_DF, now, T_UPDATE);

		ifgroups_for_each_source_in_group_safe(g, gs, gs2) {
			gsource_ref(gs);
			pim_join_desired_G_S_update(p, gs);
			pim_jp_update_G_S(p, gs, PIM_JP_UPDATE_DF, now, T_UPDATE);
			pim_upstream_G_S_rpt_update(p, gs);
			pim_jp_update_G_S_rpt(p, gs, PIM_JP_UPDATE_DF, now, T_UPDATE);
			gsource_unref(gs);
		}
		group_unref(g);
	}
	pim_mrib_flush_groups(p, &g->addr, 128, NULL);
}

void pim_group_ssbidir_neighs_set(iface i, bool cap)
{
	if(i->pim.ssbidir_neighs == cap)
		return;

	L_INFO("PIM link all neighs ssbidir capable -> %s", cap?"true":"false");
	i->pim.ssbidir_neighs = cap;

	//Update (S,G,rpt) states (only one to use ssbidir_neighs)
	group g, g2;
	gsource gs, gs2;
	pim_neigh df;
	ifgroups_for_each_group_safe(i->ifgroups, g, g2)
		//!df || !df->i->ssbidir_neighs => !(S,G,rpt)
		if((df = pim_group_upstream_df(i->pim.p, g)) && df->i == i)
			ifgroups_for_each_source_in_group_safe(g, gs, gs2)
				pim_upstream_G_S_rpt_update(i->pim.p, gs);
}

void pim_group_neigh_ssbidir_changed(iface i, pim_neigh n)
{
	if(n)
		L_DEBUG(PIM_NEIGH_P" ssbidir capable -> %s", PIM_NEIGH_PA(n), n->ssbidir_cap?"true":"false");

	if(n && PIM_IF_SSBIDIR(i)) { //Iface is ssbidir enabled
		//Update all groups and gsources for which n is upstream df
		group g, g2;
		pim_neigh udf;
		ifgroups_for_each_group_safe(i->ifgroups, g, g2) {
			if(!(udf = pim_group_upstream_df(i->pim.p, g)) || (udf != n))
				continue;
			group_ref(g);
			gsource gs, gs2;
			ifgroups_for_each_source_in_group_safe(g, gs, gs2) {
				pim_upstream_G_S_update(i->pim.p, gs);
			}
			pim_upstream_G_update(i->pim.p, g);
			group_unref(g);
		}
	}

	if(n && !n->ssbidir_cap) {
		pim_group_ssbidir_neighs_set(i, 0);
	} else {
		pim_for_each_neigh_in_iface(i, n) {
			if(!n->ssbidir_cap) {
				pim_group_ssbidir_neighs_set(i, 0);
				return;
			}
		}
		pim_group_ssbidir_neighs_set(i, 1);
	}
}

void pim_group_ssbidir_changed(iface i)
{
	// Interface i becomes ssbidir enabled or is not  anymore.

	if(!PIM_IF_SSBIDIR(i)) {
		// Remove pim downstream state on that interface.
		ifgroup ig, ig2;
		ifgsource ifgs, ifgs2;
		ifgroups_for_each_in_iface_safe(i, ig, ig2) {
			ifgroups_for_each_source_in_ig_safe(ig, ifgs, ifgs2) {
				ifgroup_ref(ig);
				pim_downstream_G_S_set_state(i->pim.p, ifgs, PIM_NONE);
				pim_downstream_G_S_rpt_set_state(i->pim.p, ifgs, PIM_NONE);
				ifgroup_unref(ig);
			}
		}
	}

	//Update upstream state when there is an upstream neighbor
	pim_neigh udf;
	group g, g2;
	ifgroups_for_each_group_safe(i->ifgroups, g, g2) {
		if(!(udf = pim_group_upstream_df(i->pim.p, g)) || (udf->i != i))
			continue;

		group_ref(g);
		pim_upstream_G_update(i->pim.p, g);
		gsource gs, gs2;
		ifgroups_for_each_source_in_group_safe(g, gs, gs2) {
			gsource_ref(gs);
			pim_upstream_G_S_update(i->pim.p, gs);
			pim_upstream_G_S_rpt_update(i->pim.p, gs);
			gsource_unref(gs);
		}
		group_unref(g);
	}
}

void pim_group_conf_changed(pim p, group g)
{
	if(!pim_rpa_get(p, g))
		return;

	pim_upstream_G_update(p, g);

	//(S,G,rpt) uses group's conf to know whether to override
	gsource gs, gs2;
	ifgroups_for_each_source_in_group_safe(g, gs, gs2)
		pim_upstream_G_S_rpt_update(p, gs);

	pim_mrib_flush_groups(p, &g->addr, 128, NULL);
}

void pim_ifgroup_conf_changed(pim p, ifgroup ig)
{
	if(!pim_rpa_get(p, (ig)->group))
		return;

	pim_upstream_G_update(p, ig->group);
	pim_mrib_flush_groups(p, &ig->group->addr, 128, NULL);
}

void pim_gsource_conf_changed(pim p, gsource gs)
{
	if(!pim_rpa_get(p, (gs)->group))
		return;

	gsource_ref(gs);
	pim_join_desired_G_S_update(p, gs);
	pim_upstream_G_S_rpt_update(p, gs);
	gsource_unref(gs);
	pim_mrib_flush_groups(p, &gs->group->addr, 128, &gs->source->addr);
}

//Called by querier when an ifgroup link join state is changed
static void pim_group_querier_cb(__unused struct querier_user_iface *user,
		ifgroup ig,
		pimbd_time_t now)
{
	ifgsource ifgs, ifgs2;

	pim p = ig->iface->pim.p;
	char exclude = groups_receiver_exclude_G(ig, now);
	pim_local_include_G_set_state(p, ig, exclude);
	ifgroups_for_each_source_in_ig_safe(ig, ifgs, ifgs2) {
		ifgsource_ref(ifgs);
		pim_local_include_G_S_set_state(p, ifgs, !exclude && groups_receiver_include_G_S(ifgs, now));
		pim_local_exclude_G_S_set_state(p, ifgs, exclude && groups_receiver_exclude_G_S(ifgs, now));
		ifgsource_unref(ifgs);
	}
}

void pim_group_iface_start(__unused pim p, iface i)
{
	pimbd_time_t now = pimbd_time();
	ifgroup ig;
	pim_group_neigh_ssbidir_changed(i, NULL);
	ifgroups_for_each_in_iface(i, ig) {
		pim_group_querier_cb(&i->pim.querier_user, ig, now);
	}
}

int pim_group_iface_setup(iface i)
{
	int ret;
	if((ret = mrib_attach_user(&i->pim.mrib_user, i->ifindex, pim_mrib_cb)))
		return ret;

	querier_attach(&i->pim.querier_user, i, pim_group_querier_cb);
	return 0;
}

void pim_group_iface_teardown(iface i)
{
	querier_detach(&i->pim.querier_user);
	mrib_detach_user(&i->pim.mrib_user);
}

