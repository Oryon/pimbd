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

#include "monitor.h"
#include "pim_rpa.h"
#include "rib.h"
#include "pim_ctl.h"
#include "pim_proxy.h"

#include <libubox/blobmsg.h>

void monitor_add_rib_entry(struct blob_buf *reply, const char *name, rib_entry e) {
	void *rib_table = blobmsg_open_table(reply, name);
	blobmsg_add_string(reply, "from", PREFIX_REPR(&e->src, e->src_plen));
	blobmsg_add_string(reply, "to", PREFIX_REPR(&e->dst, e->dst_plen));
	if(!e->onlink)
		blobmsg_add_string(reply, "via", ADDR_REPR(&e->nexthop));
	blobmsg_add_u32(reply, "metric", e->metric);
	blobmsg_add_u32(reply, "ifindex", e->oif);
	blobmsg_add_u8(reply, "onlink", !!e->onlink);

	char ifname[IFNAMSIZ+1];
	if(if_indextoname(e->oif, ifname))
		blobmsg_add_string(reply, "ifname", ifname);

	blobmsg_close_table(reply, rib_table);
}

int monitor_rpa(struct ipc_user *u, __unused char *data,
		__unused size_t len, struct blob_buf *reply)
{
	monitor m = container_of(u, monitor_s, ipc_users[MONITOR_IPC_RPA]);
	void *t = ipc_open_reply(reply);
	void *rpas_arr = blobmsg_open_array(reply, "rpas");

	pim_rpa rpa;
	pim_for_each_rpa(m->pim, rpa) {
		void *rpa_table = blobmsg_open_table(reply, NULL);

		//Address
		blobmsg_add_string(reply, "rpa", ADDR_REPR(&rpa->addr));

		//List group ranges
		void *grs_array = blobmsg_open_array(reply, "groups");
		group_range gr;
		pim_for_each_group_range(rpa, gr)
			blobmsg_add_string(reply, NULL, PREFIX_REPR(&gr->group, gr->len));
		blobmsg_close_array(reply, grs_array);

		//Upstream information
		blobmsg_add_string(reply, "upstream_iface", (rpa->dfe)?rpa->dfe->iface->ifname:"none");
		if(rpa->path)
			monitor_add_rib_entry(reply, "upstream_route", rpa->path);

		//Election states
		void *dfes_array = blobmsg_open_array(reply, "elections");
		pim_dfe dfe;
		pim_for_each_dfe_in_rpa(rpa, dfe) {
			void *dfe_c = blobmsg_open_table(reply, NULL);
			blobmsg_add_string(reply, "iface", dfe->iface->ifname);
			blobmsg_add_string(reply, "mod", pim_dfe_mod_str[dfe->mod]);
			blobmsg_add_string(reply, "state", pim_dfe_state_str[dfe->state]);
			blobmsg_add_string(reply, "df", dfe->df?ADDR_REPR(&dfe->df->addr):"none");
			blobmsg_close_table(reply, dfe_c);
		}
		blobmsg_close_array(reply, dfes_array);

		blobmsg_close_table(reply, rpa_table);
	}

	blobmsg_close_array(reply, rpas_arr);
	ipc_close_reply(reply, t);
	return 0;
}

int monitor_rib(struct ipc_user *u, __unused char *data,
		__unused size_t len, struct blob_buf *reply)
{
	monitor m = container_of(u, monitor_s, ipc_users[MONITOR_IPC_RIB]);
	void *t = ipc_open_reply(reply);
	void *rib_arr = blobmsg_open_array(reply, "rib");

	rib_entry e;
	rib rib = m->pim->rib;
	avl_for_each_element_reverse(&rib->entries, e, in_rib)
		monitor_add_rib_entry(reply, NULL, e);

	blobmsg_close_array(reply, rib_arr);
	ipc_close_reply(reply, t);
	return 0;
}

int monitor_link(struct ipc_user *u, __unused char *data,
		__unused size_t len, struct blob_buf *reply)
{
	monitor m = container_of(u, monitor_s, ipc_users[MONITOR_IPC_IF]);
	void *t = ipc_open_reply(reply);
	void *rib_arr = blobmsg_open_array(reply, "ifaces");

	iface i;
	ifgroups_for_each_iface(m->igs, i) {
		void *if_table = blobmsg_open_table(reply, NULL);
		blobmsg_add_string(reply, "ifname", i->ifname);
		blobmsg_add_u32(reply, "ifindex", i->ifindex);

		//PIM info
		void *pim_table = blobmsg_open_table(reply, "pim");
		blobmsg_add_string(reply, "state", (i->pim.state == PIM_IF_NONE)?"none":
				(i->pim.state == PIM_IF_TRYING)?"trying":"ready");
		if(i->pim.state == PIM_IF_READY) {
			blobmsg_add_u8(reply, "ssbidir", !!(i->flags & IFACE_FLAG_SSBIDIR));
			pim_neigh n;
			void *pim_neigh_array = blobmsg_open_array(reply, "neighbors");

			//PIM neighbors
			pim_for_each_neigh_in_iface(i, n) {
				void *neigh_table = blobmsg_open_table(reply, NULL);
				blobmsg_add_string(reply, "address", ADDR_REPR(&n->addr));
				blobmsg_add_u8(reply, "ssbidir_capable", !!n->ssbidir_cap);
				blobmsg_close_table(reply, neigh_table);
			}

			blobmsg_close_array(reply, pim_neigh_array);
		}
		blobmsg_close_table(reply, pim_table);

		//Proxies
		if(i->flags & IFACE_FLAG_PROXY) {
			blobmsg_add_string(reply, "proxy_address", ADDR_REPR(&i->proxy_addr));
			blobmsg_add_u16(reply, "proxy_port", i->proxy_port);
			blobmsg_add_string(reply, "server_state", i->proxy.server_fd.fd?"Ready":"Error");
			void *cls = blobmsg_open_array(reply, "clients");
			uint8_t n;
			for(n=0; n<PIM_PROXY_CLIENTS; n++) {
				pim_proxy_client client = &i->proxy.clients[n];
				if(client->ufd.fd.fd) {
					void *cl = blobmsg_open_table(reply, NULL);
					blobmsg_add_string(reply, "address", ADDR_REPR(&client->addr));
					blobmsg_add_u16(reply, "port", client->port);
					blobmsg_close_table(reply, cl);
				}
			}
			blobmsg_close_array(reply, cls);
		}

		blobmsg_close_table(reply, if_table);
	}

	blobmsg_close_array(reply, rib_arr);
	ipc_close_reply(reply, t);
	return 0;
}

int monitor_group(struct ipc_user *u, __unused char *data,
		__unused size_t len, struct blob_buf *reply)
{
	monitor m = container_of(u, monitor_s, ipc_users[MONITOR_IPC_GRP]);
	void *t = ipc_open_reply(reply);
	void *grp_arr = blobmsg_open_array(reply, "groups");
	pim_rpa rpa;

	group g;
	ifgroups_for_each_group(m->igs, g) {
		void *grp_table = blobmsg_open_table(reply, NULL);
		blobmsg_add_string(reply, "group", ADDR_REPR(&g->addr));
		blobmsg_add_string(reply, "rpa", ((rpa = pim_rpa_get(m->pim, g)))?
						ADDR_REPR(&rpa->addr):"none");
		blobmsg_add_string(reply, "pim_upstream", g->pim_upstream?"Join":"None");
		blobmsg_add_string(reply, "conf_join_desired", PIM_STATE_STR(g->conf_join_desired));
		blobmsg_add_u8(reply, "jp_joined", g->jp_joined);
		blobmsg_add_u8(reply, "ctl_joined", g->ctl_joined);
		void *src_arr = blobmsg_open_array(reply, "sources");
		gsource gs;
		ifgroups_for_each_source_in_group(g, gs) {
			void *src_table = blobmsg_open_table(reply, NULL);
			blobmsg_add_string(reply, "source", ADDR_REPR(&gs->source->addr));
			blobmsg_add_string(reply, "pim_upstream", gs->pim_upstream?"Join":"None");
			blobmsg_add_string(reply, "pim_upstream_rpt", gs->pim_upstream_rpt?"Prune":"None");
			blobmsg_add_u8(reply, "pim_join_desired", gs->pim_join_desired);
			blobmsg_add_string(reply, "conf_join_desired", PIM_STATE_STR(gs->conf_join_desired));
			blobmsg_add_u8(reply, "jp_joined", gs->jp_joined);
			blobmsg_add_u8(reply, "jp_pruned", gs->jp_pruned);
			blobmsg_add_u8(reply, "ctl_joined", gs->ctl_joined);
			blobmsg_add_u8(reply, "ctl_pruned", gs->ctl_pruned);
			blobmsg_close_table(reply, src_table);
		}
		blobmsg_close_array(reply, src_arr);
		ifgroup ig;
		void *ig_arr = blobmsg_open_array(reply, "ifgroups");
		ifgroups_for_each_in_group(g, ig) {
			void *ig_table = blobmsg_open_table(reply, NULL);
			blobmsg_add_string(reply, "ifname", ig->iface->ifname);
			blobmsg_add_string(reply, "pim_downstream", PIM_STATE_STR(ig->pim_downstream));
			blobmsg_add_string(reply, "pim_local_exclude", ig->pim_local_exclude?"Exclude":"Include");
			blobmsg_add_u32(reply, "pim_expiry_timer",
					(uint32_t) uloop_timeout_remaining(&ig->pim_expiry_timer));
			blobmsg_add_u32(reply, "pim_pp_timer",
								(uint32_t) uloop_timeout_remaining(&ig->pim_pp_timer));
			blobmsg_add_u32(reply, "listener_exclude", ig->listener_exclude);
			blobmsg_add_u32(reply, "proxy_join", ig->proxy_join);
			ifgsource ifgs;
			void *ifgs_arr = blobmsg_open_array(reply, "ifgsources");
			ifgroups_for_each_source_in_ig(ig, ifgs) {
				void *ifgs_table = blobmsg_open_table(reply, NULL);
				blobmsg_add_string(reply, "source", ADDR_REPR(&ifgs->gs->source->addr));
				//Downstream
				blobmsg_add_string(reply, "pim_dowstream", PIM_STATE_STR(ifgs->pim_downstream));
				blobmsg_add_u32(reply, "pim_expiry_timer",
						(uint32_t) uloop_timeout_remaining(&ifgs->pim_expiry_timer));
				blobmsg_add_u32(reply, "pim_pp_timer",
						(uint32_t) uloop_timeout_remaining(&ifgs->pim_pp_timer));
				//Downstream rpt
				blobmsg_add_string(reply, "pim_dowstream_rpt", PIM_STATE_STR(ifgs->pim_downstream_rpt));
				blobmsg_add_u32(reply, "pim_expiry_timer_rpt",
						(uint32_t) uloop_timeout_remaining(&ifgs->pim_rpt_expiry_timer));
				blobmsg_add_u32(reply, "pim_pp_timer_rpt",
						(uint32_t) uloop_timeout_remaining(&ifgs->pim_rpt_pp_timer));
				//Local
				blobmsg_add_string(reply, "pim_local_exclude", ifgs->pim_local_exclude?"Exclude":"None");
				blobmsg_add_string(reply, "pim_local_include", ifgs->pim_local_include?"Include":"None");
				//listener
				blobmsg_add_u32(reply, "listener_exclude", ifgs->listener_exclude);
				blobmsg_add_u32(reply, "listener_include", ifgs->listener_include);
				//proxy
				blobmsg_add_u32(reply, "proxy_join", ifgs->proxy_join);
				blobmsg_add_u32(reply, "proxy_prune", ifgs->proxy_prune);
				blobmsg_close_table(reply, ifgs_table);
			}
			blobmsg_close_array(reply, ifgs_arr);
			blobmsg_close_table(reply, ig_table);
		}
		blobmsg_close_array(reply, ig_arr);
		blobmsg_close_table(reply, grp_table);
	}

	blobmsg_close_array(reply, grp_arr);
	ipc_close_reply(reply, t);
	return 0;
}

int monitor_proxy(struct ipc_user *u, __unused char *data,
		__unused size_t len, struct blob_buf *reply) {
	monitor m = container_of(u, monitor_s, ipc_users[MONITOR_IPC_PROXY]);
	pim p = m->pim;
	pim_ctl ctl;
	void *t = ipc_open_reply(reply);
	void *ar = blobmsg_open_array(reply, "controllers");
	pim_for_each_ctl(p, ctl) {
		void *pr = blobmsg_open_table(reply, NULL);
		blobmsg_add_string(reply, "address", ADDR_REPR(&ctl->addr));
		blobmsg_add_u16(reply, "port", ctl->port);
		blobmsg_add_string(reply, "state", ctl->ufd.fd.fd?"Open":"Pending");
		if(!ctl->ufd.fd.fd)
			blobmsg_add_u32(reply, "next_try", uloop_timeout_remaining(&ctl->timer));
		else
			blobmsg_add_u32(reply, "next_ka", uloop_timeout_remaining(&ctl->timer));
		blobmsg_close_table(reply, pr);
	}
	blobmsg_close_array(reply, ar);
	ipc_close_reply(reply, t);
	return 0;
}

static struct ipc_user monitor_users[MONITOR_IPC_USERS_MAX] = {
		[MONITOR_IPC_RPA]  = {.command = "rpa_list",  .cb = monitor_rpa},
		[MONITOR_IPC_RIB]  = {.command = "rib_list",  .cb = monitor_rib},
		[MONITOR_IPC_IF] = {.command = "link_list",  .cb = monitor_link},
		[MONITOR_IPC_GRP] = {.command = "group_list", .cb = monitor_group},
		[MONITOR_IPC_PROXY] = {.command = "proxy_list", .cb = monitor_proxy}
};

void monitor_init(monitor monitor, ifgroups igs, pim pim, ipc ipc)
{
	monitor->igs = igs;
	monitor->pim = pim;
	monitor->ipc = ipc;
	memcpy(&monitor->ipc_users, monitor_users, MONITOR_IPC_USERS_MAX*sizeof(struct ipc_user));
	int i;
	for(i=0; i<MONITOR_IPC_USERS_MAX; i++) {
		ipc_add_user(ipc, &monitor->ipc_users[i]);
	}
}
