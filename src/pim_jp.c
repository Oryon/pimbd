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

#include "pim_jp.h"

#include "pim_group.h"

#define min(a,b) (((a)>(b))?(b):(a))
#define max(a,b) (((a)<(b))?(b):(a))

#define PIM_JP_NOEVENT_TIMEOUT 3600000 //1hour

#define PIM_JP_MSG_MAX_SIZE 1300

#define PIM_JP_INTERVAL_TOL_ABS 1000
#define PIM_JP_INTERVAL_TOL_FACTOR 10

#define JP_DEBUG(txt, ...) L_DEBUG("Join/Prune "txt, ##__VA_ARGS__)

struct jp_packet {
	uint8_t buff[PIM_JP_MSG_MAX_SIZE + 100];
	size_t len;    //Available length from ptr to end
	size_t ok_len; //Last group written length
	uint8_t *ptr;  //Current writing position
	struct pp_jp *jp; //Packet jp (or NULL if packet not set)
	struct pp_jp_group *grp;  //Group header (or NULL if not set yet)
	bool group_added;
	uint16_t pending_joins;
	uint16_t pending_prunes;
};


static void pim_jpp_init(struct jp_packet *p, pim_neigh n)
{
	struct pp_header *hdr;
	struct pp_addr *upstream;
	JP_DEBUG("- To "PIM_NEIGH_P, PIM_NEIGH_PA(n));

	p->len = PIM_JP_MSG_MAX_SIZE;
	p->grp = NULL;
	p->ok_len = PIM_JP_MSG_MAX_SIZE;

	/* We don't check length, assuming PIM_JP_MSG_MAX_SIZE is enough for header. */
	hdr = (struct pp_header *)p->buff;
	PP_HEADER_SET(hdr, PP_VERSION, PPT_JOIN_PRUNE);
	upstream = PP_SHIFT(hdr, p->len, sizeof(*hdr));
	pp_addr_set(upstream, &n->addr);
	p->jp = PP_ADDR_SHIFT(upstream, p->len);
	/* Group Count is set to 0 and incremented afterward. */
	pp_jp_set(p->jp, 0, conf_get_ifvalue(n->i->pim.p->conf, n->i, CIFV_PIM_US_JP_HOLDTIME_S));
	p->ptr = PP_SHIFT(p->jp, p->len, sizeof(*p->jp));
}

#define pim_jpp_empty(p) (!(p)->jp || !(p)->jp->num_groups)

static void pim_jpp_xmit(struct jp_packet *p, pim_neigh n)
{
	if(pim_jpp_empty(p))
		return;

	pimn_send_hello_maybe(n); //Send a hello, maybe, if the neighbor just appeared.
	L_DEBUG("Sending Join/Prune to of length %d to "PIM_NEIGH_P" containing %d groups",
			(int) (PIM_JP_MSG_MAX_SIZE - p->ok_len),
			PIM_NEIGH_PA(n), (int) p->jp->num_groups);
	if(pim_iface_sendto(n->i, p->buff, PIM_JP_MSG_MAX_SIZE - p->ok_len, &pp_all_routers))
		L_ERR("Join/Prune uncaught send error. A packet could not be sent.");

	//Packet loopback for rare cases where we want to listen to what happens on an iface
	pim_group_rcv_joinprune(n->i, p->buff, PIM_JP_MSG_MAX_SIZE - p->ok_len, NULL);

	p->jp = NULL;
	p->grp = NULL;
}

static int pim_jpp_insert_group(struct jp_packet *p, pim_neigh n, group g)
{
	struct pp_group * group;

	if(!p->jp)
		pim_jpp_init(p, n);
	else if(p->jp->num_groups == UINT8_MAX)
		return -1;

	group = (struct pp_group *)p->ptr;

	/* Write group address */
	pp_group_set(group, &g->addr, 128, PP_GROUP_FLAG_BIDIR);
	if(!(p->grp = PP_GROUP_SHIFT(group, p->len)))
		return -1;

	/* Set group header */
	PP_JP_GROUP_SET(p->grp, 0, 0);
	if(!(p->ptr = PP_SHIFT(p->grp, p->len, sizeof(*p->grp))))
		return -1;

	JP_DEBUG("-- Group %s", ADDR_REPR(&g->addr));
	p->pending_joins = 0;
	p->pending_prunes = 0;
	p->group_added = false;

	return 0;
}

static void pim_jpp_commit(struct jp_packet *p)
{
	if(p->grp && (p->pending_joins || p->pending_prunes)) {
		if(!p->group_added) {
			p->jp->num_groups++;
			p->group_added = true;
		}
		p->grp->n_joined = htons(ntohs(p->grp->n_joined) + p->pending_joins);
		p->grp->n_pruned = htons(ntohs(p->grp->n_pruned) + p->pending_prunes);
		p->ok_len = p->len;
		p->pending_joins = 0;
		p->pending_prunes = 0;
	}
}

static int pim_jpp_insert_wildcard(struct jp_packet *p, pim_neigh n, group g, bool join)
{
	struct pp_source *src;
	if(!p->grp && pim_jpp_insert_group(p, n, g))
		return -1;

	uint16_t *ctr = join?&p->pending_joins:&p->pending_prunes;
	if(*ctr == UINT16_MAX)
		return -1;

	src = (struct pp_source *) p->ptr;

	/* Put rpa_addr in wildcard source */
	pp_source_set(src, &g->jp_prev_rpa, 128,
			PP_SOURCE_FLAG_RPT|PP_SOURCE_FLAG_WILDCARD);
	if(!(p->ptr = PP_SOURCE_SHIFT(src, p->len)))
		return -1;

	JP_DEBUG("---- %s(*,%s)", join?"Join":"Prune", ADDR_REPR(&g->addr));
	(*ctr)++;
	return 0;
}

static int pim_jpp_insert_source(struct jp_packet *p, pim_neigh n, gsource gs, bool join, bool rpt)
{
	struct pp_source *src;
	if(!p->grp && pim_jpp_insert_group(p, n, gs->group))
		return -1;

	uint16_t *ctr = join?&p->pending_joins:&p->pending_prunes;
	if(*ctr == UINT16_MAX)
		return -1;

	src = (struct pp_source *) p->ptr;
	pp_source_set(src, &gs->source->addr, 128, rpt?PP_SOURCE_FLAG_RPT:0);
	if(!(p->ptr = PP_SOURCE_SHIFT(src, p->len)))
		return -1;

	JP_DEBUG("---- %s(%s,%s%s)", join?"Join":"Prune", ADDR_REPR(&gs->source->addr), ADDR_REPR(&gs->group->addr), rpt?",rpt":"");
	(*ctr)++;
	return 0;
}

static void pim_jp_send_neighbor(pim p, pim_neigh n)
{
	L_DEBUG("Sending Join/Prune to "PIM_NEIGH_P, PIM_NEIGH_PA(n));
	struct jp_packet packet;
	packet.jp = NULL;
	packet.grp = NULL;

	group g;
	gsource gs;
	pim_rpa rpa;
	bool current_df;

	/*
	 * State is sent in the following order
	 * Join(S,G,rpt)
	 * Join(S,G)
	 * ---------------- The two following can't be cut
	 * Join(*,G)
	 * Prune(S,G,rpt)
	 * ----------------
	 * Prune(S,G)
	 * Prune(*,G)
	 *
	 */

	ifgroups_for_each_group(p->ifgroups, g) {
		packet.grp = NULL;

		pim_dfe udfe = ((rpa = pim_rpa_get(p, g)))?rpa->dfe:NULL;
		if(udfe && udfe->df == n) {
			current_df = true;
		} else if (g->jp_prev_df == n) {
			current_df = false;
		} else {
			continue;
		}

		if(!current_df)
			goto prunes;

		if(g->jp_to_send && g->pim_upstream) //never send Join(S,G) or Join(S,G,rpt) if Join(*,G)
			goto retry_join;

		//Join(S,G,rpt) are only sent to df when overriding
		ifgroups_for_each_source_in_group(g, gs) {
			if(gs->jp_rpt_to_send && !gs->pim_upstream_rpt) {
join_rpt:
				if(pim_jpp_insert_source(&packet, n, gs, 1, 1)) {
					pim_jpp_xmit(&packet, n);
					goto join_rpt;
				}
				pim_jpp_commit(&packet);
			}
		}

		//Join(S,G)
		ifgroups_for_each_source_in_group(g, gs) {
			if(gs->jp_to_send && gs->pim_upstream) { //We should join
join_source:
				if(pim_jpp_insert_source(&packet, n, gs, 1, 0)) {
					pim_jpp_xmit(&packet, n);
					goto join_source;
				}
				pim_jpp_commit(&packet);
			}
		}

		//Join(*,G)
retry_join:
		if(g->jp_to_send && g->pim_upstream) {
			g->jp_prev_rpa = rpa->addr;

			//Try to insert group
			if(pim_jpp_insert_wildcard(&packet, n, g, current_df && g->pim_upstream)) {
				pim_jpp_xmit(&packet, n);
				goto retry_join;
			}
		}

		//Prune(S,G,rpt)
		ifgroups_for_each_source_in_group(g, gs) {
			if(gs->pim_upstream_rpt && (gs->jp_rpt_to_send || !gs->jp_rpt_next)) {
prune_rpt:
				if(pim_jpp_insert_source(&packet, n, gs, 0, 1)) {
					pim_jpp_xmit(&packet, n);
					goto prune_rpt;
				}
			}
		}

		//End of uncutable Join(*,G) + Prune(S,G,rpt)
		pim_jpp_commit(&packet);

prunes:
		//Prune(S,G)
		ifgroups_for_each_source_in_group(g, gs) {
			if(gs->jp_to_send && (!current_df || !gs->pim_upstream)) { //We should prune
prune_source:
				if(pim_jpp_insert_source(&packet, n, gs, 0, 0)) {
					pim_jpp_xmit(&packet, n);
					goto prune_source;
				}
				pim_jpp_commit(&packet); //We can send from there
			}
		}

		//Prune(*,G)
		if(g->jp_to_send && (!current_df || !g->pim_upstream)) {
			g->jp_prev_rpa = rpa->addr;
retry_prune:
			if(pim_jpp_insert_wildcard(&packet, n, g, 0)) {
				pim_jpp_xmit(&packet, n);
				goto retry_prune;
			}
			pim_jpp_commit(&packet);
		}

		packet.grp = NULL;
	}

	if(!pim_jpp_empty(&packet))
		pim_jpp_xmit(&packet, n);
}

static void pim_jp_timeout(struct uloop_timeout *to)
{
	L_DEBUG("PIM Join/Prune Timeout");

	pim p = container_of(to, pim_s, jp_timer);
	pimbd_time_t now = pimbd_time();
	pimbd_time_t next_event = now + PIM_JP_NOEVENT_TIMEOUT;
	group g, g2;
	gsource gs, gs2;
	pim_neigh df;
	iface i;

	//See to what neighbors we have to send
	ifgroups_for_each_group(p->ifgroups, g) {
		if(g->jp_next && g->jp_next <= now) //Must send this one
			goto send_jp;

		//In case no ASM, look at SSM
		ifgroups_for_each_source_in_group(g, gs)
			if((gs->jp_next && gs->jp_next <= now) ||
					(gs->jp_rpt_next && gs->jp_rpt_next <= now))
				goto send_jp;

		continue;
send_jp:
		if(g->jp_prev_df)
			g->jp_prev_df->send_jp = 1;
		if((df = pim_group_upstream_df(p, g)))
			df->send_jp = 1;
	}

	//See which we will send
	ifgroups_for_each_group(p->ifgroups, g) {
		//If we send to a new DF, we also need to send to the previous one.
		//So we need both bf to be sent something.
		if((g->jp_prev_df && !g->jp_prev_df->send_jp) ||
				((df = pim_group_upstream_df(p, g)) && !df->send_jp))
			continue;

		if(g->jp_next && //Scheduled transmit
				g->jp_next <= now + g->jp_tolerance) //Tolerate a small delay
			g->jp_to_send = 1;

		//Do SSM
		ifgroups_for_each_source_in_group(g, gs) {
			if(gs->jp_next && gs->jp_next <= now + gs->jp_tolerance) {
				gs->jp_to_send = 1;
				L_DEBUG("to_send "GSOURCE_L, GSOURCE_LA(gs)); //todo: remove
			}
			if(gs->jp_rpt_next && (gs->jp_rpt_next <= now + gs->jp_rpt_tolerance)) {
				gs->jp_rpt_to_send = 1;
				L_DEBUG("to_send rpt "GSOURCE_L, GSOURCE_LA(gs)); //todo: remove
			}
		}
	}

	//Now let's send for all neighbor's that have send_jp set
	ifgroups_for_each_iface(p->ifgroups, i) {
		if(!PIM_IF_RUNNING(i))
			continue;
		pim_for_each_neigh_in_iface(i, df) {
			if(df->send_jp) {
				pim_jp_send_neighbor(p, df);
				df->send_jp = 0;
			}
		}
		list_for_each_entry(df, &i->pim.rpa_vneighs, le) { //Send to virtual RP neighbors
			if(df->send_jp) {
				pim_jp_send_neighbor(p, df);
				df->send_jp = 0;
			}
		}
	}

	//Commit sent jps
	uint32_t shift = (uint32_t) rand_i(0, 1000); //Introduce the same shift for all JP sent at the same time
	ifgroups_for_each_group_safe(p->ifgroups, g, g2) {

		group_ref(g);
		df = pim_group_upstream_df(p, g);
		g->jp_prev_df = NULL;
		//Commit (*,G)
		if(g->jp_to_send) {
			if(g->pim_upstream)
				g->jp_prev_df = df;
			g->jp_to_send = 0;
			g->jp_joined = g->pim_upstream;
			if(g->jp_joined) {
				int interval = conf_get_ifvalue(p->conf,
						df->i, CIFV_PIM_US_T_PERIODIC_MS);
				g->jp_tolerance = min(PIM_JP_INTERVAL_TOL_ABS, interval / PIM_JP_INTERVAL_TOL_FACTOR);
				g->jp_next = now + interval + min(shift, g->jp_tolerance);
				next_event = min(next_event, g->jp_next);
			} else {
				g->jp_next = 0;
				group_unref(g);
			}
		} else if(g->jp_next) {
			next_event = min(next_event, g->jp_next);
		}

		//Commit (S,G)
		ifgroups_for_each_source_in_group_safe(g, gs, gs2) {
			if(gs->jp_to_send) {
				if(gs->pim_upstream)
					g->jp_prev_df = df;
				gs->jp_to_send = 0;
				gs->jp_joined = gs->pim_upstream;
				if(gs->jp_joined) {
					int interval = conf_get_ifvalue(p->conf,
							df->i, CIFV_PIM_US_T_PERIODIC_MS);
					gs->jp_tolerance = min(PIM_JP_INTERVAL_TOL_ABS, interval / PIM_JP_INTERVAL_TOL_FACTOR);
					gs->jp_next = now + interval + min(shift, gs->jp_tolerance);
					next_event = min(next_event, gs->jp_next);
				} else {
					gs->jp_next = 0;
					gsource_unref(gs);
				}
			} else if (gs->jp_next) {
				next_event = min(next_event, gs->jp_next);
			}
		}

		//Commit (S,G,rpt)
		ifgroups_for_each_source_in_group_safe(g, gs, gs2) {
			if(gs->jp_rpt_to_send) {
				if(gs->pim_upstream_rpt)
					g->jp_prev_df = df;
				gs->jp_rpt_to_send = 0;
				gs->jp_pruned = !!gs->pim_upstream_rpt;
				gs->jp_rpt_next = 0;
				if(!gs->jp_pruned)
					gsource_unref(gs);
			} else if(gs->jp_rpt_next) {
				next_event = min(next_event, gs->jp_rpt_next);
			}
		}
		group_unref(g);
	}

	uloop_timeout_set(to, next_event - now + 2);
}

void pim_jp_update_G_S_rpt(pim p, gsource gs, enum pim_jp_mod mod, pimbd_time_t now, uint32_t delay)
{
	pimbd_time_t event = now + delay;

	if(!gs->jp_rpt_next && !gs->jp_pruned)
		gsource_ref(gs);

	switch (mod) {
		case PIM_JP_UPDATE_DF:
			if(gs->jp_pruned) { //If currently pruned
				gs->jp_rpt_next = gs->jp_rpt_next?min(gs->jp_rpt_next, event):event;
				gs->jp_rpt_tolerance = 100000; //Do it asap
			}
			break;
		case PIM_JP_UPDATE_JD:
			if((!!gs->pim_upstream_rpt) != gs->jp_pruned) {
				gs->jp_rpt_next = gs->jp_rpt_next?min(gs->jp_rpt_next, event):event;
				gs->jp_rpt_tolerance = 100000; //Do it asap
			}
			break;
		case PIM_JP_OVERRIDE:
			if(!gs->jp_pruned && !gs->pim_upstream_rpt && gs->group->jp_joined) {
				//We want (*,G) and not prune (S,G,rpt) (and there is not pending update needed)
				gs->jp_rpt_next = gs->jp_rpt_next?min(event, gs->jp_rpt_next):event; //Send a Join(S,G,rpt) soon
				gs->jp_tolerance = 1000; //Arbitrary value todo change ?
			}
			break;
		case PIM_JP_SUPPRESS:
			if(gs->jp_pruned && gs->pim_upstream_rpt) {
				//When no update is required and we currently joined
				gs->jp_rpt_next = max(event, gs->jp_rpt_next);
				gs->jp_tolerance = 1000; //Arbitrary value todo change ?
			}
			break;
		case PIM_JP_CANCEL_OT:
			if(gs->jp_pruned == gs->pim_upstream_rpt) { //No update to do
				gs->jp_rpt_next = 0;
			}
			break;
		default:
			break;
	}

	if((gs->jp_rpt_next == event) && //If we updated
			(!p->jp_timer.pending || (uloop_timeout_remaining(&p->jp_timer) > (int)delay))) {
		uloop_timeout_set(&p->jp_timer, delay);
	}

	if(!gs->jp_rpt_next && !gs->jp_pruned)
		gsource_unref(gs);
}

void pim_jp_update_G_S(pim p, gsource gs, enum pim_jp_mod mod, pimbd_time_t now, uint32_t delay)
{
	pimbd_time_t event = now + delay;

	if(!gs->jp_next) {
		gs->jp_joined = 0;
		gsource_ref(gs);
	}

	switch (mod) {
	case PIM_JP_UPDATE_DF:
		if(gs->jp_joined) {
			gs->jp_next = gs->jp_next?min(gs->jp_next, event):event;
			gs->jp_tolerance = 100000; //Do it asap
		}
		break;
	case PIM_JP_UPDATE_JD:
		//Upstream state was changed
		if(gs->pim_upstream != gs->jp_joined) {
			gs->jp_next = gs->jp_next?min(gs->jp_next, event):event;
			gs->jp_tolerance = 100000; //Do it asap
		}
		break;
	case PIM_JP_OVERRIDE:
		if(gs->jp_joined && gs->pim_upstream) {
			//When no update is required and we currently joined
			gs->jp_next = min(event, gs->jp_next);
			//Do not change previous tolerance
		}
		break;
	case PIM_JP_SUPPRESS:
		if(gs->jp_joined && gs->pim_upstream) {
			//When no update is required and we currently joined
			gs->jp_next = max(event, gs->jp_next);
			//Do not change previous tolerance
		}
		break;
	default:
		break;
	}

	if((gs->jp_next == event) && //If we updated
			(!p->jp_timer.pending || (uloop_timeout_remaining(&p->jp_timer) > (int)delay))) {
		uloop_timeout_set(&p->jp_timer, delay);
	}

	if(!gs->jp_next)
		gsource_unref(gs);
}

void pim_jp_update_G(pim p, group g, enum pim_jp_mod mod, pimbd_time_t now, uint32_t delay)
{
	pimbd_time_t event = now + delay;

	if(!g->jp_next) {
		g->jp_joined = 0;
		g->jp_prev_df = 0;
		group_ref(g);
	}

	switch (mod) {
		case PIM_JP_UPDATE_DF:
			//DF was changed. If joined, we need to update asap.
			if(g->jp_joined) {
				g->jp_next = g->jp_next?min(g->jp_next, event):event;
				g->jp_tolerance = 100000; //Do it asap
			}
			gsource gs, gs2;
			ifgroups_for_each_source_in_group_safe(g, gs, gs2) //Update SSM too
				pim_jp_update_G_S(p, gs, PIM_JP_UPDATE_DF, now, delay);
			break;
		case PIM_JP_UPDATE_JD:
			//Upstream state was changed
			if(g->pim_upstream != (unsigned int)g->jp_joined) {
				g->jp_next = g->jp_next?min(g->jp_next, event):event;
				g->jp_tolerance = 100000; //Do it asap
			}
			break;
		case PIM_JP_OVERRIDE:
			if(g->jp_joined && g->pim_upstream) {
				//When no update is required and we currently joined
				g->jp_next = min(event, g->jp_next);
				//Do not change previous tolerance
			}
			break;
		case PIM_JP_SUPPRESS:
			if(g->jp_joined && g->pim_upstream) {
				//When no update is required and we currently joined
				g->jp_next = max(event, g->jp_next);
				//Do not change previous tolerance
			}
			break;
		default:
			break;
	}

	if((g->jp_next == event) && //If we updated
			(!p->jp_timer.pending || (uloop_timeout_remaining(&p->jp_timer) > (int)delay))) {
		uloop_timeout_set(&p->jp_timer, delay);
	}

	if(!g->jp_next)
		group_unref(g);
}

void pim_jp_dead_neighbor(pim p, pim_neigh n)
{
	//Need to remove references to the dead neighbor
	group g;
	ifgroups_for_each_group(p->ifgroups, g) {
		if(g->jp_prev_df == n)
			g->jp_prev_df = NULL;
	}
}


void pim_jp_init(pim p)
{
	p->jp_timer.pending = 0;
	p->jp_timer.cb = pim_jp_timeout;
}
