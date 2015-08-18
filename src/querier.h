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
#include <libubox/uloop.h>
#include <libubox/avl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <string.h>
#include <stdbool.h>

#include "mrib.h"
#include "groups.h"
#include "ifgroup.h"

struct querier_group {
	struct list_head sources;
	size_t source_count;
	pimbd_time_t exclude_until;
	pimbd_time_t compat_v2_until;
	pimbd_time_t compat_v1_until;
	pimbd_time_t next_generic_transmit;
	pimbd_time_t next_source_transmit;
	int retransmit;
};

struct querier_source {
	struct list_head head;
	pimbd_time_t include_until;
	int retransmit;
};

struct querier_config {
	enum {
		QCONF_NONE = 0, QCONF_DEFAULT, QCONF_CUSTOM,
	} state;
	pimbd_time_t query_response_interval;
	pimbd_time_t query_interval;
	pimbd_time_t last_listener_query_interval;
	int robustness;
	int last_listener_query_count;
};

struct querier_iface {
	enum {
		QUERIER_IF_NONE,
		QUERIER_IF_INIT,
		QUERIER_IF_TRYING,
		QUERIER_IF_UP,
	} state;

	bool v4up;
	bool v6up;

	struct list_head head;
	struct list_head users;
	struct uloop_timeout timeout;
	struct querier_config conf;

	struct uloop_fd igmp_fd;
	pimbd_time_t igmp_next_query;
	bool igmp_other_querier;
	int igmp_startup_tries;

	struct uloop_fd mld_fd;
	pimbd_time_t mld_next_query;
	bool mld_other_querier;
	int mld_startup_tries;

	struct mrib_querier mrib;

	//Taken from groups.h
	struct querier_config cfg_v4;
	struct querier_config cfg_v6;
	struct uloop_timeout groups_timer;
	size_t source_limit;
	size_t group_limit;
};

struct querier;
struct querier_user_iface;
typedef void (querier_iface_cb)(struct querier_user_iface *user, ifgroup ig, pimbd_time_t now);

struct querier_user_iface {
	struct list_head head;
	iface iface;
	querier_iface_cb *iface_cb;
};


/* External API */
void querier_init(struct querier *querier, ifgroups igs);
void querier_deinit(struct querier *querier);

void querier_attach(struct querier_user_iface *user,
		iface i, querier_iface_cb *cb);
void querier_detach(struct querier_user_iface *user);

/* Must be called after modifying the configuration structure,
 * and once before starting to using it */
void querier_iface_conf_update(iface i);

/* Internal API */

struct querier {
	ifgroups igs;
	ifgroups_user_s igs_user;
};

#define QUERIER_IF_CAN_SETUP_MLD(i) (!((~(i)->flags) & (IFACE_FLAG_MLD_QUERIER | IFACE_FLAG_EXISTS | IFACE_FLAG_UP | IFACE_FLAG_LLADDR)))
#define QUERIER_IF_CAN_SETUP_IGMP(i) (!((~(i)->flags) & (IFACE_FLAG_IGMP_QUERIER | IFACE_FLAG_EXISTS | IFACE_FLAG_UP | IFACE_FLAG_V4ADDR)))

#define QUERIER_MAX_SOURCE 75
#define QUERIER_MAX_GROUPS 256

void querier_synthesize_events(struct querier *querier);

int querier_qqi(uint8_t qqic);
int querier_mrd(uint16_t mrc);
uint8_t querier_qqic(int qi);
uint16_t querier_mrc(int mrd);

// Used by group.c
void querier_announce_change(ifgroup ig, pimbd_time_t now);
void querier_send_query(ifgroup ig,
		const struct list_head *sources, bool suppress);

void querier_remove_source(ifgsource ifgs);
void querier_clear_sources(ifgroup ig);
void querier_remove_group(ifgroup ig, pimbd_time_t now);
