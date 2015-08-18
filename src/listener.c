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

#include "listener.h"

#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ifgroup_s.h"

static void list_iface_teardown(iface i)
{
	if(!i->listener.sock4)
		return;

	L_INFO("Tearing down listener on %s", i->ifname);
	close(i->listener.sock4);
	close(i->listener.sock6);
	i->listener.sock4 = 0;
	i->listener.sock6 = 0;
	i->listener.group_count = 0;
	iface_unref(i);
}

static int list_iface_setup(iface i)
{
	if(i->listener.sock4) //Already up
		return 0;

	if((i->listener.sock4 = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		goto v4;

	if((i->listener.sock6 = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
		goto v6;

	L_INFO("Setting-up listener on %s (%d, %d)", i->ifname, i->listener.sock4, i->listener.sock6);
	iface_ref(i);
	return 0;
v6:
	i->listener.sock6 = 0;
	close(i->listener.sock4);
v4:
	i->listener.sock4 = 0;
	return -1;
}


#define source_write(s, v4, src) do {\
	if(v4){\
		addr_unmap(&((struct sockaddr_in *)(s))->sin_addr, src);\
		((struct sockaddr_in *)(s))->sin_family = AF_INET;\
	}else{\
		addr_cpy(&((struct sockaddr_in6 *)(s))->sin6_addr, src);\
		((struct sockaddr_in6 *)(s))->sin6_family = AF_INET6;\
	}\
} while(0)

static void list_group_update(ifgroup ig)
{
	ifgsource ifgs;

	//Count sources
	ig->listener_excl_cnt = 0;
	ig->listener_incl_cnt = 0;
	ifgroups_for_each_source_in_ig(ig, ifgs) {
		if((ifgs->listener_include || (ifgs->ig->listener_exclude & (~ifgs->listener_exclude))))
			ig->listener_incl_cnt++;
		else
			ig->listener_excl_cnt++;
	}

	size_t src_cnt = ig->listener_exclude?ig->listener_excl_cnt:ig->listener_incl_cnt;
	size_t len = GROUP_FILTER_SIZE(src_cnt);
	struct group_req greq;
	struct group_filter *f, unsub;
	int v4 = addr_ismapped(&ig->group->addr);
	int sock;
	int sol = v4?SOL_IP:SOL_IPV6;
	char active = ig->listener_active;

	//Allocate sockopt structure
	if((!ig->listener_exclude && !src_cnt) ||
			!(f = malloc(len))) {
		f = &unsub;
		len = GROUP_FILTER_SIZE(0);
		src_cnt = 0;
	}

	//Write sockopt structures
	greq.gr_interface = ig->iface->ifindex;
	source_write((&greq.gr_group),v4,&ig->group->addr);

	f->gf_fmode = ig->listener_exclude?MCAST_EXCLUDE:MCAST_INCLUDE;
	f->gf_numsrc = src_cnt;
	f->gf_interface = ig->iface->ifindex;
	L_DEBUG("Updating listener "IFGROUP_L" mod %s", IFGROUP_LA(ig), ig->listener_exclude?"Exclude":"Include");
	source_write((&f->gf_group),v4,&ig->group->addr);
	ifgroups_for_each_source_in_ig(ig, ifgs) {
		if(!src_cnt)
			break;

		char include = !!(ifgs->listener_include || (ifgs->ig->listener_exclude & (~ifgs->listener_exclude)));
		if((ig->listener_exclude && !include) ||
				(!ig->listener_exclude && include)) {
			src_cnt--;
			L_DEBUG("%s "IFGSOURCE_L, ig->listener_exclude?"Exclude":"Include", IFGSOURCE_LA(ifgs));
			source_write(&(f->gf_slist[src_cnt]),v4,&ifgs->gs->source->addr);
		}
	}

	//Leave group
	if(ig->listener_active) {
		sock = v4?ig->iface->listener.sock4:ig->iface->listener.sock6;
		if(setsockopt(sock, sol, MCAST_LEAVE_GROUP, &greq, sizeof(greq))) {
			L_ERR("setsockopt MCAST_LEAVE_GROUP failed: %s", strerror(errno));
		} else {
			L_DEBUG("setsockopt MCAST_LEAVE_GROUP OK");
			ig->listener_active = 0;
			ig->iface->listener.group_count--;
		}
	}

	//Join group
	if(ig->listener_exclude || ig->listener_incl_cnt) {
		if(ig->listener_active) {
			L_ERR("Cannot join group because leave failed");
		} else if(list_iface_setup(ig->iface)) { //If not up, the socket will be set up
			L_WARN("Cannot setup listener on %s", ig->iface->ifname);
		}  else {
			sock = v4?ig->iface->listener.sock4:ig->iface->listener.sock6;
			if(setsockopt(sock, sol, MCAST_JOIN_GROUP, &greq, sizeof(greq))) {
				L_ERR("setsockopt MCAST_JOIN_GROUP failed: %s", strerror(errno));
				if(errno == ENOBUFS && v4)
					L_ERR("Check igmp_max_memberships ?");
			} else {
				L_DEBUG("setsockopt MCAST_JOIN_GROUP OK");
				ig->listener_active = 1;
				ig->iface->listener.group_count++;
				if(f == &unsub) {
					L_ERR("Cannot set filter because of failed memory allocation");
				} else if (setsockopt(sock, sol, MCAST_MSFILTER, f, len)) {
					L_ERR("setsockopt MCAST_MSFILTER failed: %s", strerror(errno));
				} else {
					L_DEBUG("setsockopt MCAST_MSFILTER OK");
				}
			}
		}
	}

	if(!ig->iface->listener.group_count) //Teardown iface if not used anymore
		list_iface_teardown(ig->iface);

	if(active && !ig->listener_active) {
		ifgroup_unref(ig);
	} else if(!active && ig->listener_active) {
		ifgroup_ref(ig);
	}

	if(f != &unsub) //Free allocated buffer
		free(f);
}



void listener_update_G(ifgroup ig, uint8_t user, char exclude)
{
	uint8_t excl = exclude?user:0;

	if((excl ^ ig->listener_exclude) & user) {//Something change
		if(!ig->listener_exclude)
			ifgroup_ref(ig);

		ig->listener_exclude = (ig->listener_exclude & ~user) | excl;
		list_group_update(ig);

		if(!ig->listener_exclude)
			ifgroup_unref(ig);
	}
}

void listener_update_G_S(ifgsource ifgs, uint8_t user, char include, char exclude)
{
	uint8_t inc = include?user:0;
	uint8_t excl = exclude?user:0;

	if(((inc ^ ifgs->listener_include) | (excl ^ ifgs->listener_exclude)) & user) {//Something change
		if(!ifgs->listener_include && !ifgs->listener_exclude)
			ifgsource_ref(ifgs);

		ifgs->listener_include = (ifgs->listener_include & ~user) | inc;
		ifgs->listener_exclude = (ifgs->listener_exclude & ~user) | excl;

		list_group_update(ifgs->ig); //todo: Optimize this so that it is not so often called

		if(!ifgs->listener_include && !ifgs->listener_exclude)
			ifgsource_unref(ifgs);
	}
}

