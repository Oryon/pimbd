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

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "groups.h"
#include "ifgroup_s.h"

bool group_is_included(ifgroup ig, pimbd_time_t time)
{
	return ig && ig->querier_set && ig->querier.exclude_until <= time;
}

bool source_is_included(ifgsource ifgs, pimbd_time_t time)
{
	return ifgs && ifgs->querier_set && ifgs->querier.include_until > time;
}

// Expire a group and / or its associated sources depending on the current time
static pimbd_time_t expire_group(ifgroup ig,
		pimbd_time_t now, pimbd_time_t next_event)
{
	if(!ig->querier_set) //todo: Maybe this can be removed, depending on whether it is checked before calling.
		return next_event;

	struct querier_config *cfg = IN6_IS_ADDR_V4MAPPED(&ig->group->addr) ? &ig->iface->querier.cfg_v4 : &ig->iface->querier.cfg_v6;
	pimbd_time_t llqi = now + cfg->last_listener_query_interval;
	pimbd_time_t llqt = now + (cfg->last_listener_query_interval * cfg->last_listener_query_count);

	// Handle group and source-specific query retransmission
	struct list_head suppressed = LIST_HEAD_INIT(suppressed);
	struct list_head unsuppressed = LIST_HEAD_INIT(unsuppressed);
	ifgsource ifgs, ifgs2;

	if (ig->querier.next_source_transmit > 0 && ig->querier.next_source_transmit <= now) {
		ig->querier.next_source_transmit = 0;

		groups_for_each_source_safe(ig, ifgs, ifgs2) {
			if (ifgs->querier.retransmit > 0) {
				list_move_tail(&ifgs->querier.head, (ifgs->querier.include_until > llqt) ? &suppressed : &unsuppressed);
				--ifgs->querier.retransmit;
			}

			if (ifgs->querier.retransmit > 0)
				ig->querier.next_source_transmit = llqi;
		}
	}

	if (ig->querier.next_source_transmit > 0 && ig->querier.next_source_transmit < next_event)
		next_event = ig->querier.next_source_transmit;

	// Handle group-specific query retransmission
	if (ig->querier.retransmit > 0 && ig->querier.next_generic_transmit <= now) {
		ig->querier.next_generic_transmit = 0;

		querier_send_query(ig, NULL, ig->querier.exclude_until > llqt);

		--ig->querier.retransmit;

		if (ig->querier.retransmit > 0)
			ig->querier.next_generic_transmit = llqi;

		// Skip suppresed source-specific query (RFC 3810 7.6.3.2)
		list_splice_init(&suppressed, &ig->querier.sources);
	}

	if (ig->querier.next_generic_transmit > 0 && ig->querier.next_generic_transmit < next_event)
		next_event = ig->querier.next_generic_transmit;

	if (!list_empty(&suppressed)) {
		querier_send_query(ig, &suppressed, true);

		list_splice(&suppressed, &ig->querier.sources);
	}

	if (!list_empty(&unsuppressed)) {
		querier_send_query(ig, &unsuppressed, false);

		list_splice(&unsuppressed, &ig->querier.sources);
	}

	// Handle source and group expiry
	bool changed = false;
	if (ig->querier.exclude_until > 0) {
		if (group_is_included(ig, now)) {
			// Leaving exclude mode
			ig->querier.exclude_until = 0;
			changed = true;
		} else if (ig->querier.exclude_until < next_event) {
			next_event = ig->querier.exclude_until;
		}
	}

	groups_for_each_source_safe(ig, ifgs, ifgs2) {
		if (ifgs->querier.include_until > 0) {
			if (!source_is_included(ifgs, now)) {
				ifgs->querier.include_until = 0;
				changed = true;
			} else if (ifgs->querier.include_until < next_event) {
				next_event = ifgs->querier.include_until;
			}
		}

		if (ig->querier.exclude_until == 0 && ifgs->querier.include_until == 0)
			querier_remove_source(ifgs);
	}

	if (ig->querier.exclude_until == 0 && ig->querier.source_count == 0)
		querier_remove_group(ig, now);
	else if (changed)
		querier_announce_change(ig, now);

	return next_event;
}

// Rearm the global groups-timer if the next event is before timer expiration
static void rearm_timer(iface i, int msecs)
{
	int remain = uloop_timeout_remaining(&i->querier.groups_timer);
	if (remain < 0 || remain >= msecs)
		uloop_timeout_set(&i->querier.groups_timer, msecs);
}

// Expire all groups of a group-state (called by timer as callback)
static void expire_groups(struct uloop_timeout *t)
{
	iface i = container_of(t, iface_s, querier.groups_timer);
	pimbd_time_t now = pimbd_time();
	pimbd_time_t next_event = now + 3600 * PIMBD_TIME_PER_SECOND;

	ifgroup ig, ig2;
	ifgroups_for_each_in_iface_safe(i, ig, ig2) {
		if(ig->querier_set)
			next_event = expire_group(ig, now, next_event);
	}
	rearm_timer(i, (next_event > now) ? next_event - now : 0);
}

// Initialize a group-state
void groups_init(iface i)
{
	i->querier.groups_timer.pending = false;
	i->querier.groups_timer.cb = expire_groups;
	querier_iface_conf_update(i);
	i->querier.cfg_v4 = i->querier.conf;
	i->querier.cfg_v6 = i->querier.conf;
}

// Cleanup a group-state
void groups_deinit(iface i)
{
	//Group cleaning is done by querier, we just need to cancel the timer here
	uloop_timeout_cancel(&i->querier.groups_timer);
}

// Get group-object for a given group, create if requested
static ifgroup groups_get_group(iface i,
		const struct in6_addr *addr, bool *created)
{
	ifgroup ig = ifgroup_get(i, group_get(i->ifgroups, addr, !!created), !!created);
	if(ig && !ig->querier_set && created) {
		memset(&ig->querier, 0, sizeof(ig->querier));
		ig->querier_set = 1;
		ifgroup_ref(ig);
		INIT_LIST_HEAD(&ig->querier.sources);
		*created = true;
	} else if(created) {
		*created = false;
	}
	return ig;
}

// Get source-object for a given source, create if requested
static ifgsource groups_get_source(ifgroup ig,
		const struct in6_addr *addr, bool *created)
{
	gsource gs = gsource_get(ig->group, source_get(ig->iface->ifgroups, addr, !!created), !!created);
	ifgsource ifgs = ifgsource_get(ig, gs, !!created);
	if(ifgs && !ifgs->querier_set && created) {
		if(ig->querier.source_count == ig->iface->querier.source_limit) {
			ifgsource_clean_maybe(ifgs);
			*created = false;
			return NULL;
		}
		memset(&ifgs->querier, 0, sizeof(ifgs->querier));
		++ig->querier.source_count;
		ifgs->querier_set = 1;
		list_add_tail(&ifgs->querier.head, &ig->querier.sources);
		ifgsource_ref(ifgs);
		*created = true;
	} else if(created) {
		*created = false;
	}
	return ifgs;
}

// Update the IGMP/MLD timers of a group-state
void groups_update_config(iface i, bool v6,
		pimbd_time_t query_response_interval, pimbd_time_t query_interval, int robustness)
{
	struct querier_config *cfg = v6 ? &i->querier.cfg_v6 : &i->querier.cfg_v4;
	cfg->query_response_interval = query_response_interval;
	cfg->query_interval = query_interval;
	cfg->robustness = robustness;
	cfg->last_listener_query_count = cfg->robustness;
	cfg->last_listener_query_interval = 1 * PIMBD_TIME_PER_SECOND;
}

// Update timers for a given group (called when receiving queries from other queriers)
void groups_update_timers(iface i,
		const struct in6_addr *groupaddr,
		const struct in6_addr *addrs, size_t len)
{
	char addrbuf[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, groupaddr, addrbuf, sizeof(addrbuf));
	ifgroup ig = groups_get_group(i, groupaddr, NULL);
	if (!ig) {
		L_WARN("%s: failed to update timer: no such group %s", __FUNCTION__, addrbuf);
		return;
	}

	struct querier_config *cfg = IN6_IS_ADDR_V4MAPPED(&ig->group->addr) ? &i->querier.cfg_v4 : &i->querier.cfg_v6;
	pimbd_time_t now = pimbd_time();
	pimbd_time_t llqt = now + (cfg->last_listener_query_count * cfg->last_listener_query_interval);

	if (len == 0) {
		if (ig->querier.exclude_until > llqt)
			ig->querier.exclude_until = llqt;
	} else {
		for (size_t i = 0; i < len; ++i) {
			ifgsource ifgs = groups_get_source(ig, &addrs[i], NULL);
			if (!ifgs) {
				L_WARN("%s: failed to update timer: unknown sources for group %s", __FUNCTION__, addrbuf);
				continue;
			}

			if (ifgs->querier.include_until > llqt)
				ifgs->querier.include_until = llqt;
		}
	}

	rearm_timer(i, llqt - now);
}

// Update state of a given group (on reception of node's IGMP/MLD packets)
void groups_update_state(iface i,
		const struct in6_addr *groupaddr,
		const struct in6_addr *addrs, size_t len,
		enum groups_update update)
{
	bool created = false, changed = false;
	char addrbuf[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, groupaddr, addrbuf, sizeof(addrbuf));
	L_DEBUG("%s: %s (+%d sources) => %d", __FUNCTION__, addrbuf, (int)len, update);

	ifgroup ig = groups_get_group(i, groupaddr, &created);
	if (!ig) {
		L_ERR("querier_state: failed to allocate group for %s", addrbuf);
		return;
	}

	if (created)
		changed = true;

	pimbd_time_t now = pimbd_time();
	pimbd_time_t next_event = PIMBD_TIME_MAX;
	struct querier_config *cfg = IN6_IS_ADDR_V4MAPPED(&ig->group->addr) ? &i->querier.cfg_v4 : &i->querier.cfg_v6;

	// Backwards compatibility modes
	if (ig->querier.compat_v2_until > now || ig->querier.compat_v1_until > now) {
		if (update == UPDATE_BLOCK)
			return;

		if (ig->querier.compat_v1_until > now && (update == UPDATE_DONE || update == UPDATE_TO_IN))
			return;

		if (update == UPDATE_TO_EX)
			len = 0;
	}

	if (update == UPDATE_REPORT || update == UPDATE_REPORT_V1 || update == UPDATE_DONE) {
		pimbd_time_t compat_until = now + cfg->query_response_interval +
				(cfg->robustness * cfg->query_interval);

		if (update == UPDATE_REPORT_V1)
			ig->querier.compat_v1_until = compat_until;
		else if (update == UPDATE_REPORT)
			ig->querier.compat_v2_until = compat_until;

		update = (update == UPDATE_DONE) ? UPDATE_TO_IN : UPDATE_IS_EXCLUDE;
		len = 0;
	}

	bool include = ig->querier.exclude_until <= now;
	bool is_include = update == UPDATE_IS_INCLUDE || update == UPDATE_TO_IN || update == UPDATE_ALLOW;

	int llqc = cfg->last_listener_query_count;
	pimbd_time_t mali = now + (cfg->robustness * cfg->query_interval) + cfg->query_response_interval;
	pimbd_time_t llqt = now + (cfg->last_listener_query_interval * cfg->last_listener_query_count);

	// RFC 3810 7.4
	struct list_head saved = LIST_HEAD_INIT(saved);
	struct list_head queried = LIST_HEAD_INIT(queried);
	for (size_t i = 0; i < len; ++i) {
		bool *create = (include && update == UPDATE_BLOCK) ? NULL : &created;
		ifgsource ifgs = groups_get_source(ig, &addrs[i], create);

		if (include && update == UPDATE_BLOCK) {
			if (ifgs)
				list_move_tail(&ifgs->querier.head, &queried);
		} else {
			bool query = false;
			if (!ifgs) {
				groups_update_state(ig->iface, groupaddr, NULL, 0, false);
				L_WARN("querier: failed to allocate source for %s, fallback to ASM", addrbuf);
				return;
			}

			if (created)
				changed = true;
			else if (include && update == UPDATE_TO_EX)
				query = true;

			if (ifgs->querier.include_until <= now && update == UPDATE_SET_IN) {
				ifgs->querier.include_until = mali;
				changed = true;
			} else if (ifgs->querier.include_until > now && update == UPDATE_SET_EX) {
				ifgs->querier.include_until = now;
				changed = true;
			}

			if (!include && (update == UPDATE_BLOCK || update == UPDATE_TO_EX) &&
					(created || ifgs->querier.include_until > now))
				query = true;

			if ((is_include || (!include && created))) {
				if (ifgs->querier.include_until <= now)
					changed = true;

				ifgs->querier.include_until = (is_include || update == UPDATE_IS_EXCLUDE)
						? mali : ig->querier.exclude_until;

				if (next_event > mali)
					next_event = mali;
			}

			if (query)
				list_move_tail(&ifgs->querier.head, &queried);
			else if (update == UPDATE_IS_EXCLUDE || update == UPDATE_TO_EX ||
					update == UPDATE_SET_EX || update == UPDATE_SET_IN)
				list_move_tail(&ifgs->querier.head, &saved);
		}
	}

	if (update == UPDATE_IS_EXCLUDE || update == UPDATE_TO_EX || update == UPDATE_SET_EX) {
		if (include || !list_empty(&ig->querier.sources))
			changed = true;

		querier_clear_sources(ig);
		list_splice(&saved, &ig->querier.sources);
		ig->querier.exclude_until = mali;

		if (next_event > mali)
			next_event = mali;
	}

	if (update == UPDATE_SET_IN) {
		if (!include || !list_empty(&ig->querier.sources)) {
			changed = true;
			next_event = now;
		}

		querier_clear_sources(ig);
		list_splice(&saved, &ig->querier.sources);
		ig->querier.exclude_until = now;
	}

	// Prepare queries
	if (update == UPDATE_TO_IN) {
		ifgsource ifgs, ifgs2;
		groups_for_each_source_safe(ig, ifgs, ifgs2) {
			if (ifgs->querier.include_until <= now)
				continue;

			size_t i;
			for (i = 0; i < len && !IN6_ARE_ADDR_EQUAL(&ifgs->gs->source->addr, &addrs[i]); ++i);
			if (i == len)
				list_move_tail(&ifgs->querier.head, &queried);
		}
	}

	if (!list_empty(&queried)) {
		ifgsource ifgs;
		list_for_each_entry(ifgs, &queried, querier.head) {
			if (ifgs->querier.include_until > llqt)
				ifgs->querier.include_until = llqt;

			ig->querier.next_source_transmit = now;
			ifgs->querier.retransmit = llqc;
		}

		next_event = now;
		list_splice(&queried, &ig->querier.sources);
	}

	if (!include && update == UPDATE_TO_IN) {
		if (ig->querier.exclude_until > llqt)
			ig->querier.exclude_until = llqt;

		ig->querier.next_generic_transmit = now;
		ig->querier.retransmit = llqc;
		next_event = now;
	}

	querier_announce_change(ig, now);

	if (group_is_included(ig, now) && ig->querier.source_count == 0)
		next_event = now;

	if (next_event < PIMBD_TIME_MAX)
		rearm_timer(ig->iface, next_event - now);

	if (changed)
		L_DEBUG("%s: %s => %s (+%d sources)", __FUNCTION__, addrbuf,
				(group_is_included(ig, now)) ? "included" : "excluded",
				(int)ig->querier.source_count);

}

// Get group object of a given group
ifgroup groups_get(iface i, const struct in6_addr *addr)
{
	return groups_get_group(i, addr, NULL);
}

// Test if a group (and source) is requested in the current group state
// (i.e. for deciding if it should be routed / forwarded)
bool groups_includes_group_source(ifgroup ig,
		ifgsource ifgs, pimbd_time_t time)
{
	if(!ig || !ig->querier_set)
		return false;

	if (!ifgs && (!group_is_included(ig, time) || ig->querier.source_count > 0))
		return true;

	if ((!group_is_included(ig, time) && (!ifgs || !ifgs->querier_set || source_is_included(ifgs, time))) ||
			(group_is_included(ig, time) && (ifgs && ifgs->querier_set) && source_is_included(ifgs, time)))
		return true;

	return false;
}

// Synthesize all group events again to resynchronize a querier user
void groups_synthesize_events(iface i)
{
	if(i->querier.state != QUERIER_IF_UP)
		return;

	pimbd_time_t now = pimbd_time();

	ifgroup ig;
	ifgroups_for_each_in_iface(i, ig) {
		if(i->querier.state == QUERIER_IF_UP)
			querier_announce_change(ig, now);
	}
}
