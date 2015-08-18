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
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>

#include "querier.h"
#include "ifgroup_s.h"
#include "utils.h"

// Test if multicast-group is valid and relevant
static bool igmp_is_valid_group(in_addr_t group)
{
	uint32_t addr = be32_to_cpu(group);
	return IN_MULTICAST(addr) && ((addr & 0xffffff00U) != 0xe0000000U);
}

// Handle an IGMP-record from an IGMP-packet (called by igmp_receive)
static ssize_t igmp_handle_record(iface i, const uint8_t *data, size_t len)
{
	struct igmpv3_grec *r = (struct igmpv3_grec*)data;

	if (len < sizeof(*r))
		return -1;

	size_t nsrc = ntohs(r->grec_nsrcs);
	size_t read = sizeof(*r) + nsrc * sizeof(struct in_addr) + r->grec_auxwords * 4;

	if (len < read)
		return -1;

	if (r->grec_type >= UPDATE_IS_INCLUDE && r->grec_type <= UPDATE_BLOCK &&
			igmp_is_valid_group(r->grec_mca)) {
		struct in6_addr addr, sources[nsrc];
		addr_map(&addr, (struct in_addr *)&r->grec_mca);

		for (size_t i = 0; i < nsrc; ++i)
			addr_map(&sources[i], (struct in_addr *)&r->grec_src[i]);

		groups_update_state(i, &addr, sources, nsrc, r->grec_type);
	}

	return read;
}

// Receive and parse an IGMP-packet (called by uloop as callback)
void igmp_handle(struct mrib_querier *mrib, const struct igmphdr *igmp, size_t len,
		const struct sockaddr_in *from)
{
	iface i = container_of(mrib, iface_s, querier.mrib);
	if(!i->querier.v4up)
		return;

	pimbd_time_t now = pimbd_time();
	struct in6_addr group, fromaddr;
	addr_map(&group, (struct in_addr *)&igmp->group);
	addr_map(&fromaddr, (struct in_addr *)&from->sin_addr);

	if (igmp->type == IGMP_HOST_MEMBERSHIP_QUERY) {
		struct igmpv3_query *query = (struct igmpv3_query*)igmp;

		if (len != sizeof(*igmp) && ((size_t)len < sizeof(*query) ||
				(size_t)len < sizeof(*query) + ntohs(query->nsrcs) * sizeof(struct in_addr)))
			return;

		if (query->group && !igmp_is_valid_group(query->group))
			return;

		if(!i->v4addr) {
			L_ERR("Cannot handle IGMP query without an IPv4 address on %s", i->ifname);
			return;
		}

		int election;
		if(!(election = memcmp(&fromaddr, &i->v4addr->addr, sizeof(struct in6_addr))))
			return; //Message from self

		bool suppress = false;
		size_t nsrc = 0;
		int robustness = 2;
		pimbd_time_t mrd = 10000;
		pimbd_time_t query_interval = 125000;

		if (igmp->code)
			mrd = 100 * ((len == sizeof(*igmp)) ? igmp->code : querier_qqi(igmp->code));

		if ((size_t)len > sizeof(*igmp)) {
			if (query->qrv)
				robustness = query->qrv;

			if (query->qqic)
				query_interval = querier_qqi(query->qqic) * 1000;

			suppress = query->suppress;
			nsrc = ntohs(query->nsrcs);
		}

		if (!suppress && query->group) {
			struct in6_addr sources[nsrc];
			for (size_t i = 0; i < nsrc; ++i)
				addr_map(&sources[i], (struct in_addr *)&query->srcs[i]);

			groups_update_timers(i, &group, sources, nsrc);
		}

		L_INFO("%s: detected other querier %s with priority %d on %s",
				__FUNCTION__, ADDR_REPR(&fromaddr), election, i->ifname);
		// TODO: if other querier loses election but is IGMPv1/v2, do we want to care?

		if (election < 0 && !query->group) {
			groups_update_config(i, false, mrd, query_interval, robustness);

			i->querier.igmp_other_querier = true;
			i->querier.igmp_next_query = now + (i->querier.cfg_v4.query_response_interval / 2) +
				(i->querier.cfg_v4.robustness * i->querier.cfg_v4.query_interval);
		}
	} else if (igmp->type == IGMPV3_HOST_MEMBERSHIP_REPORT) {
		struct igmpv3_report *report = (struct igmpv3_report*)igmp;

		if ((size_t)len <= sizeof(*report))
			return;

		uint8_t *ibuf = (uint8_t*)igmp;
		size_t count = ntohs(report->ngrec);
		size_t offset = sizeof(*report);

		while (count > 0 && offset < len) {
			ssize_t read = igmp_handle_record(i, &ibuf[offset], len - offset);
			if (read < 0)
				break;

			offset += read;
			--count;
		}
	} else if (igmp->type == IGMPV2_HOST_MEMBERSHIP_REPORT ||
			igmp->type == IGMP_HOST_LEAVE_MESSAGE ||
			igmp->type == IGMP_HOST_MEMBERSHIP_REPORT) {

		if (len != sizeof(*igmp) || !igmp_is_valid_group(igmp->group))
			return;

		groups_update_state(i, &group, NULL, 0,
				(igmp->type == IGMPV2_HOST_MEMBERSHIP_REPORT) ? UPDATE_REPORT :
				(igmp->type == IGMP_HOST_MEMBERSHIP_REPORT) ? UPDATE_REPORT_V1 : UPDATE_DONE);
	}

	uloop_timeout_set(&i->querier.timeout, 0);
}

// Send generic / group-specific / group-and-source specific IGMP-query
int igmp_send_query(iface i, ifgroup ig,
		const struct list_head *sources,
		bool suppress)
{
	if(ig) {
		L_DEBUG("%s: sending IGMP %s-specific query for %s on %s (S: %d)", __FUNCTION__,
				(!sources) ? "group" : "source", ADDR_REPR(&ig->group->addr), i->ifname, suppress);
	} else {
		L_DEBUG("%s: sending generic IGMP-query on %s (S: 0)", __FUNCTION__, i->ifname);
	}

	if(!i->v4addr) {
		L_WARN("Can't send igmp query as there is no IPv4 address on %s", i->ifname);
		return -EADDRNOTAVAIL;
	}
	uint8_t qqic = querier_qqic(((ig) ? i->querier.cfg_v4.last_listener_query_interval:i->querier.cfg_v4.query_response_interval) / 100);
	struct {
		struct igmpv3_query q;
		struct in_addr srcs[QUERIER_MAX_SOURCE];
	} query = {.q = {
		.type = IGMP_HOST_MEMBERSHIP_QUERY,
		.code = qqic,
		.qrv = i->querier.cfg_v4.robustness,
		.suppress = suppress,
		.qqic = querier_qqic(i->querier.cfg_v4.query_interval / 1000),
	}};

	ifgsource ifgs;
	size_t cnt = 0;
	if (sources) {
		groups_for_each_source(ig, ifgs) {
			if (cnt >= QUERIER_MAX_SOURCE) {
				L_WARN("%s: maximum source count (%d) exceeded",
						__FUNCTION__, QUERIER_MAX_SOURCE);
				break;
			}
			addr_unmap((struct in_addr *)&query.q.srcs[cnt], &ifgs->gs->source->addr);
		}
	}
	query.q.nsrcs = htons(cnt);

	struct in_addr dst = {htonl(0xe0000001U)};
	if (ig) {
		addr_unmap((struct in_addr *)&query.q.group, &ig->group->addr);
		dst.s_addr = query.q.group;
	}
	struct in_addr src;
	addr_unmap(&src, &i->v4addr->addr);

	return mrib_send_igmp(&i->querier.mrib, &query.q,
			sizeof(query.q) + cnt * sizeof(query.srcs[0]), &src, &dst);
}

