/*
 * Author: Steven Barth <steven at midlink.org>
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

#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/timerfd.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <linux/mroute6.h>

#include "mrib.h"
#include "querier.h"
#include "ifgroup_s.h"

#define MLD_SUPPRESS (1 << 3)

struct mld_query {
	struct mld_hdr mld;
	uint8_t s_qrv;
	uint8_t qqic;
	uint16_t nsrc;
	struct in6_addr addrs[0];
};

// Test whether group address is valid and interesting
static bool mld_is_valid_group(const struct in6_addr *addr)
{
	return IN6_IS_ADDR_MULTICAST(addr) &&
			!IN6_IS_ADDR_MC_LINKLOCAL(addr) && !IN6_IS_ADDR_MC_NODELOCAL(addr);
}

// Handle Multicast Address Record from MLD-Packets (called by mld_receive)
static ssize_t mld_handle_record(iface i, const uint8_t *data, size_t len)
{
	struct mld_record {
		uint8_t type;
		uint8_t aux;
		uint16_t nsrc;
		struct in6_addr addr;
		struct in6_addr sources[];
	} *r = (struct mld_record*)data;

	if (len < sizeof(*r))
		return -1;

	size_t nsrc = ntohs(r->nsrc);
	size_t read = sizeof(*r) + nsrc * sizeof(struct in6_addr) + r->aux;

	if (len < read)
		return -1;

	if (r->type >= UPDATE_IS_INCLUDE && r->type <= UPDATE_BLOCK && mld_is_valid_group(&r->addr))
		groups_update_state(i, &r->addr, r->sources, nsrc, r->type);

	return read;
}

// Receive an MLD-Packet from a node (called by uloop as callback)
void mld_handle(struct mrib_querier *mrib, const struct mld_hdr *hdr, size_t len,
		const struct sockaddr_in6 *from)
{
	iface i = container_of(mrib, iface_s, querier.mrib);
	if(!i->querier.v6up)
		return;

	pimbd_time_t now = pimbd_time();
	if (hdr->mld_icmp6_hdr.icmp6_type == ICMPV6_MGM_QUERY) {
		struct mld_query *query = (struct mld_query*)hdr;
		if (len != 24 && ((size_t)len < sizeof(*query) ||
				(size_t)len < sizeof(*query) + ntohs(query->nsrc) * sizeof(struct in6_addr)))
			return;

		if (!IN6_IS_ADDR_UNSPECIFIED(&query->mld.mld_addr) &&
				!mld_is_valid_group(&query->mld.mld_addr))
			return;

		// Detect local source address
		if(!i->lladdr) {
			L_ERR("Cannot handle MLD query without a link local address on %s", i->ifname);
			return;
		}

		int election;
		if(!(election = memcmp(&from->sin6_addr, &i->lladdr->addr, sizeof(struct in6_addr))))
			return; //Message is from us

		bool suppress = false;
		size_t nsrc = 0;
		int robustness = 2;
		pimbd_time_t mrd = 10000;
		pimbd_time_t query_interval = 125000;

		if (query->mld.mld_icmp6_hdr.icmp6_dataun.icmp6_un_data16[0])
			mrd = (len == 24) ? ntohs(query->mld.mld_icmp6_hdr.icmp6_dataun.icmp6_un_data16[0]) :
					querier_mrd(query->mld.mld_icmp6_hdr.icmp6_dataun.icmp6_un_data16[0]);

		if (len > 24) {
			if (query->s_qrv & 0x7)
				robustness = query->s_qrv & 0x7;

			if (query->qqic)
				query_interval = querier_qqi(query->qqic) * 1000;
		}

		if (!suppress && !IN6_IS_ADDR_UNSPECIFIED(&query->mld.mld_addr))
			groups_update_timers(i, &query->mld.mld_addr, query->addrs, nsrc);

		L_INFO("%s: detected other querier %s with priority %d on %s",
				__FUNCTION__, ADDR_REPR(&from->sin6_addr), election, i->ifname);
		// TODO: if other querier loses election but is MLDv1, do we want to care?

		if (election < 0 && IN6_IS_ADDR_UNSPECIFIED(&query->mld.mld_addr)) {
			groups_update_config(i, true, mrd, query_interval, robustness);

			i->querier.mld_other_querier = true;
			i->querier.mld_next_query = now + (i->querier.cfg_v6.query_response_interval / 2) +
				(i->querier.cfg_v6.robustness * i->querier.cfg_v6.query_interval);
		}
	} else if (hdr->mld_icmp6_hdr.icmp6_type == ICMPV6_MLD2_REPORT) {
		struct icmp6_hdr *mld_report = (struct icmp6_hdr *)hdr;
		if ((size_t)len <= sizeof(*mld_report))
			return;

		uint8_t *buf = (uint8_t*)hdr;
		size_t count = ntohs(mld_report->icmp6_dataun.icmp6_un_data16[1]);
		ssize_t offset = sizeof(*mld_report);

		while (count > 0 && offset < (ssize_t)len) {
			ssize_t read = mld_handle_record(i, &buf[offset], len - offset);
			if (read < 0)
				break;

			offset += read;
			--count;
		}
	} else if (hdr->mld_icmp6_hdr.icmp6_type == MLD_LISTENER_REPORT ||
			hdr->mld_icmp6_hdr.icmp6_type == MLD_LISTENER_REDUCTION) {

		if (len != 24 || !mld_is_valid_group(&hdr->mld_addr))
			return;

		groups_update_state(i, &hdr->mld_addr, NULL, 0,
				(hdr->mld_icmp6_hdr.icmp6_type == MLD_LISTENER_REPORT) ? UPDATE_REPORT : UPDATE_DONE);
	}
	uloop_timeout_set(&i->querier.timeout, 0);
}


// Send generic / group-specific / group-and-source-specific queries
ssize_t mld_send_query(iface i, ifgroup ig,
		const struct list_head *sources, bool suppress)
{
	if(ig) {
		L_DEBUG("%s: sending MLD %s-specific query for %s on %s (S: %d)", __FUNCTION__,
				(!sources) ? "group" : "source", ADDR_REPR(&ig->group->addr), i->ifname, suppress);
	} else {
		L_DEBUG("%s: sending generic MLD-query on %s (S: 0)", __FUNCTION__, i->ifname);
	}

	if(!i->lladdr) {
		L_WARN("Can't send mld query as there is no link local IPv6 address on %s", i->ifname);
		return -EADDRNOTAVAIL;
	}

	uint16_t mrc = querier_mrc((ig)?i->querier.cfg_v6.last_listener_query_interval:i->querier.cfg_v6.query_response_interval);
	struct {
		struct mld_query q;
		struct in6_addr addrs[QUERIER_MAX_SOURCE];
	} query = {.q = {
		.mld = {.mld_icmp6_hdr = {MLD_LISTENER_QUERY, 0, 0, {.icmp6_un_data16 = {mrc, 0}}}},
		.s_qrv = (i->querier.cfg_v6.robustness & 0x7) | (suppress ? MLD_SUPPRESS : 0),
		.qqic = querier_qqic(i->querier.cfg_v6.query_interval / 1000),
	}};

	ifgsource ifgs;
	size_t cnt = 0;
	if (sources) {
		groups_for_each_source(ig, ifgs) {
			if (cnt >= QUERIER_MAX_SOURCE)
				break; // TODO: log source overflow

			query.addrs[cnt++] = ifgs->gs->source->addr;
		}
	}
	query.q.nsrc = htons(cnt);

	struct in6_addr dst = IPV6_ALL_NODES_INIT;
	if (ig)
		query.q.mld.mld_addr = dst = ig->group->addr;

	return mrib_send_mld(&i->querier.mrib, &query.q.mld,
			sizeof(query.q) + cnt * sizeof(query.addrs[0]), &i->lladdr->addr, &dst);
}
