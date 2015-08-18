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

#pragma once

#include <libubox/list.h>
#include <libubox/avl.h>
#include <libubox/uloop.h>
#include <arpa/inet.h>
#include "pimbd.h"
#include "ifgroup.h"

void groups_init(iface i);
void groups_deinit(iface i);


enum groups_update {
	UPDATE_UNSPEC,
	UPDATE_IS_INCLUDE	= 1,
	UPDATE_IS_EXCLUDE	= 2,
	UPDATE_TO_IN		= 3,
	UPDATE_TO_EX		= 4,
	UPDATE_ALLOW		= 5,
	UPDATE_BLOCK		= 6,
	UPDATE_REPORT		= 7,
	UPDATE_REPORT_V1	= 8,
	UPDATE_DONE			= 9,
	UPDATE_SET_IN		= 0x11,
	UPDATE_SET_EX		= 0x12,
};

void groups_update_config(iface i, bool v6,
		pimbd_time_t query_response_interval, pimbd_time_t query_interval, int robustness);

void groups_update_timers(iface i,
		const struct in6_addr *groupaddr,
		const struct in6_addr *addrs, size_t len);

void groups_update_state(iface i,
		const struct in6_addr *groupaddr,
		const struct in6_addr *addrs, size_t len,
		enum groups_update update);

void groups_synthesize_events(iface i);

// Groups user query API

bool group_is_included(ifgroup ig, pimbd_time_t time);
bool source_is_included(ifgsource ifgs, pimbd_time_t time);

/* API with PIM */

/* G is in exclude mode */
#define groups_receiver_exclude_G(ig, now) ((ig)->querier_set && ((ig)->querier.exclude_until > now))

/* The source S is in the exclude list (G must be in exclude mode) */
#define groups_receiver_exclude_G_S(ifgs, now) ((ifgs)->querier_set && (ifgs)->querier.include_until <= now)

/* G has at list one included source (G must be in include mode) */
#define groups_receiver_include_G_anysource(ig, now) ((ig)->querier_set && (ig)->querier.source_count)

/* (S,G) is included (G must be in include mode) */
#define groups_receiver_include_G_S(ifgs, now) ((ifgs)->querier_set && ((ifgs)->querier.include_until > now ))


#define groups_for_each_source(ig, ifgs) list_for_each_entry(ifgs, &(ig)->querier.sources, querier.head)
#define groups_for_each_source_safe(ig, ifgs, ifgs2) list_for_each_entry_safe(ifgs, ifgs2, &(ig)->querier.sources, querier.head)

#define group_for_each_active_source(ig, ifgs, time) \
		groups_for_each_source(ig, ifgs) \
			if (source_is_included(ifgs, time) == group_is_included(ig, time))

ifgroup groups_get(iface i, const struct in6_addr *addr);
