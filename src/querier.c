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
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <libubox/ustream.h>
#include <libubox/usock.h>
#include <libubox/list.h>

#include "querier.h"
#include "ifgroup_s.h"

#define QUERIER_IFUP_RETRY_INTERVAL 5000

#define querier_for_each_iface_user(i, user) \
	list_for_each_entry(user, &(i)->querier.users, head)

void igmp_handle(struct mrib_querier *mrib, const struct igmphdr *igmp, size_t len,
		const struct sockaddr_in *from);
int igmp_send_query(iface i, ifgroup ig,
		const struct list_head *sources,
		bool suppress);

void mld_handle(struct mrib_querier *mrib, const struct mld_hdr *hdr, size_t len,
		const struct sockaddr_in6 *from);
ssize_t mld_send_query(iface i, ifgroup ig,
		const struct list_head *sources,
		bool suppress);

// Resynthesize all group-events for a given querier
void querier_synthesize_events(struct querier *querier)
{
	iface i;
	ifgroups_for_each_iface(querier->igs, i) {
		if(i->querier.state == QUERIER_IF_UP)
			groups_synthesize_events(i);
	}
}

// Handle changes from a querier for a given group (called by a group-state as callback)
void querier_announce_change(ifgroup ig, pimbd_time_t now)
{
	// Only recognize changes to non-link-local groups
	struct querier_user_iface *user;
	querier_for_each_iface_user(ig->iface, user)
		if(user->iface_cb)
			user->iface_cb(user, ig, now);
}

// Remove a source-definition for a group
void querier_remove_source(ifgsource ifgs)
{
	--ifgs->ig->querier.source_count;
	ifgs->querier_set = 0;
	list_del(&ifgs->querier.head);
	ifgsource_unref(ifgs);
}

// Clear all sources of a certain group
void querier_clear_sources(ifgroup ig)
{
	ifgsource ifgs, ifgs2;
	groups_for_each_source_safe(ig, ifgs, ifgs2)
		querier_remove_source(ifgs);
}

// Remove a group and all associated sources from the group state
void querier_remove_group(ifgroup ig, pimbd_time_t now)
{
	querier_clear_sources(ig);
	ig->querier.exclude_until = 0;
	querier_announce_change(ig, now);
	ig->querier_set = 0; //Delete reference
	ifgroup_unref(ig);
}

// Send query for a group + sources (called by a group-state as callback)
void querier_send_query(ifgroup ig,
		const struct list_head *sources, bool suppress)
{
	bool v4 = IN6_IS_ADDR_V4MAPPED(&ig->group->addr);
	if (v4 && !ig->iface->querier.igmp_other_querier)
		igmp_send_query(ig->iface, ig, sources, suppress);
	else if (!v4 && !ig->iface->querier.mld_other_querier)
		mld_send_query(ig->iface, ig, sources, suppress);
}

static void querier_iface_setup(iface i);

// Expire interface timers and send queries (called by timer as callback)
static void querier_iface_timer(struct uloop_timeout *timeout)
{
	iface i = container_of(timeout, iface_s, querier.timeout);

	// The timer is used for retrying setup as well
	if(i->querier.state == QUERIER_IF_TRYING) {
		querier_iface_setup(i);
		return;
	}

	pimbd_time_t now = pimbd_time();
	pimbd_time_t next_event = now + 3600 * PIMBD_TIME_PER_SECOND;

	if (i->querier.v4up && i->querier.igmp_next_query <= now) {
		// If the other querier is gone, reset interface config
		if (i->querier.igmp_other_querier) {
			i->querier.cfg_v4 = i->querier.conf;
			i->querier.igmp_other_querier = false;
		}

		igmp_send_query(i, NULL, NULL, false);

		if (i->querier.igmp_startup_tries > 0)
			--i->querier.igmp_startup_tries;

		i->querier.igmp_next_query = now + ((i->querier.igmp_startup_tries > 0) ?
						(i->querier.cfg_v4.query_interval / 4) :
						i->querier.cfg_v4.query_interval);
	}

	if (i->querier.v4up && i->querier.igmp_next_query < next_event)
		next_event = i->querier.igmp_next_query;

	if (i->querier.v6up && i->querier.mld_next_query <= now) {
		// If the other querier is gone, reset interface config
		if (i->querier.mld_other_querier) {
			i->querier.cfg_v6 = i->querier.conf;
			i->querier.mld_other_querier = false;
		}

		mld_send_query(i, NULL, NULL, false);

		if (i->querier.mld_startup_tries > 0)
			--i->querier.mld_startup_tries;

		i->querier.mld_next_query = now + ((i->querier.mld_startup_tries > 0) ?
						(i->querier.cfg_v6.query_interval / 4) :
						i->querier.cfg_v6.query_interval);
	}

	if (i->querier.v6up && i->querier.mld_next_query < next_event)
		next_event = i->querier.mld_next_query;

	uloop_timeout_set(&i->querier.timeout, (next_event > now) ? next_event - now : 0);
}

// Calculate QQI from QQIC
int querier_qqi(uint8_t qqic)
{
	return (qqic & 0x80) ? (((qqic & 0xf) | 0x10) << (((qqic >> 4) & 0x7) + 3)) : qqic;
}

// Calculate MRD from MRC
int querier_mrd(uint16_t mrc)
{
	mrc = ntohs(mrc);
	return (mrc & 0x8000) ? (((mrc & 0xfff) | 0x1000) << (((mrc >> 12) & 0x7) + 3)) : mrc;
}

// Calculate QQIC from QQI
uint8_t querier_qqic(int qqi)
{
	if (qqi >= 128) {
		int exp = 3;

		while ((qqi >> exp) > 0x1f && exp <= 10)
			++exp;

		if (exp > 10)
			qqi = 0xff;
		else
			qqi = 0x80 | ((exp - 3) << 4) | ((qqi >> exp) & 0xf);
	}
	return qqi;
}

// Calculate MRC from MRD
uint16_t querier_mrc(int mrd)
{
	if (mrd >= 32768) {
		int exp = 3;

		while ((mrd >> exp) > 0x1fff && exp <= 10)
			++exp;

		if (exp > 10)
			mrd = 0xffff;
		else
			mrd = 0x8000 | ((exp - 3) << 12) | ((mrd >> exp) & 0xfff);
	}
	return htons(mrd);
}

static void querier_v4_set(iface i, bool up)
{
	if(up == i->querier.v4up)
		return;

	i->querier.v4up = up;
	if(up) {
		L_NOTICE("Setting up IGMP querier on %s", i->ifname);
		i->querier.igmp_next_query = 0;
		i->querier.igmp_other_querier = 0;
		uloop_timeout_set(&i->querier.timeout, 0);
	} else {
		L_NOTICE("Tearing down IGMP querier on %s", i->ifname);
		pimbd_time_t now = pimbd_time();
		ifgroup ig, ig2;
		ifgroups_for_each_in_iface_safe(i, ig, ig2) {
			if(ig->querier_set && IN6_IS_ADDR_V4MAPPED(&ig->group->addr))
				querier_remove_group(ig, now);
		}
	}
}

static void querier_v6_set(iface i, bool up)
{
	if(up == i->querier.v6up)
		return;

	i->querier.v6up = up;
	if(up) {
		L_NOTICE("Setting up MLD querier on %s", i->ifname);
		i->querier.mld_next_query = 0;
		i->querier.mld_other_querier = 0;
		uloop_timeout_set(&i->querier.timeout, 0);
	} else {
		L_NOTICE("Tearing down MLD querier on %s", i->ifname);
		pimbd_time_t now = pimbd_time();
		ifgroup ig, ig2;
		ifgroups_for_each_in_iface_safe(i, ig, ig2) {
			if(ig->querier_set && !IN6_IS_ADDR_V4MAPPED(&ig->group->addr))
				querier_remove_group(ig, now);
		}
	}
}

static void querier_iface_init(iface i)
{
	if(i->querier.state != QUERIER_IF_NONE)
		return;

	INIT_LIST_HEAD(&i->querier.users);
	i->querier.timeout.pending = 0;
	i->querier.timeout.cb = querier_iface_timer;

	i->querier.state = QUERIER_IF_INIT;
	iface_ref(i);
}

static void querier_iface_setup(iface i)
{
	switch (i->querier.state) {
	case QUERIER_IF_NONE:
		querier_iface_init(i);
		//no break;
	case QUERIER_IF_INIT:
	case QUERIER_IF_TRYING:
		uloop_timeout_cancel(&i->querier.timeout);
		if(mrib_attach_querier(&i->querier.mrib, i->ifindex, igmp_handle, mld_handle)) {
			L_ERR("Could not setup querier on %s. Will retry in %d ms.", i->ifname, QUERIER_IFUP_RETRY_INTERVAL);
			if(uloop_timeout_set(&i->querier.timeout, QUERIER_IFUP_RETRY_INTERVAL)) {
				L_ERR("Critical error: Could not set timer for trying later.");
				i->querier.state = QUERIER_IF_INIT;
			} else {
				i->querier.state = QUERIER_IF_TRYING;
			}
		} else {
			L_INFO("Setting up querier on iface %s", i->ifname);
			i->querier.source_limit = QUERIER_MAX_SOURCE;
			i->querier.group_limit = QUERIER_MAX_GROUPS;
			groups_init(i);
			i->querier.igmp_startup_tries = i->querier.cfg_v4.robustness;
			i->querier.mld_startup_tries = i->querier.cfg_v6.robustness;
			uloop_timeout_set(&i->querier.timeout, 0);
			i->querier.state = QUERIER_IF_UP;
		}
		break;
	case QUERIER_IF_UP:
		break;
	}

	if(i->querier.state == QUERIER_IF_UP) {
		if(QUERIER_IF_CAN_SETUP_IGMP(i))
			querier_v4_set(i, 1);
		if(QUERIER_IF_CAN_SETUP_MLD(i))
			querier_v6_set(i, 1);
	}
}

static void querier_iface_teardown(iface i)
{
	switch (i->querier.state) {
		case QUERIER_IF_NONE:
		case QUERIER_IF_INIT:
			break;
		case QUERIER_IF_UP:
			groups_deinit(i);
			mrib_detach_querier(&i->querier.mrib);
			//no break;
		case QUERIER_IF_TRYING:
			L_INFO("Tearing down querier on %s", i->ifname);
			uloop_timeout_cancel(&i->querier.timeout);
			i->querier.state = QUERIER_IF_INIT;
			break;
	}
}

// Attach an interface to a querier-instance
void querier_attach(struct querier_user_iface *user,
		iface i, querier_iface_cb *cb)
{
	querier_iface_init(i);

	list_add(&user->head, &i->querier.users);
	user->iface = i;
	user->iface_cb = cb;
	iface_ref(i);
}

// Detach an interface from a querier-instance
void querier_detach(struct querier_user_iface *user)
{
	list_del(&user->head);
	iface_unref(user->iface);
}

static void querier_iface_callback(__unused ifgroups_user user, iface i, __unused iface_flags changed_flags)
{
	//iface_setup checks for MLD and IGMP too.
	QUERIER_IF_CAN_SETUP_MLD(i)?querier_iface_setup(i):querier_v6_set(i, 0);
	QUERIER_IF_CAN_SETUP_IGMP(i)?querier_iface_setup(i):querier_v4_set(i, 0);

	if(!i->querier.v4up && !i->querier.v6up)
		querier_iface_teardown(i);
}

void querier_iface_conf_update(iface i)
{
	if(i->querier.conf.state == QCONF_NONE) {
		i->querier.conf.query_response_interval = 10 * PIMBD_TIME_PER_SECOND;
		i->querier.conf.query_interval = 125 * PIMBD_TIME_PER_SECOND;
		i->querier.conf.robustness = 2;
		i->querier.conf.last_listener_query_count = 2;
		i->querier.conf.last_listener_query_interval = 1 * PIMBD_TIME_PER_SECOND;
		i->querier.conf.state = QCONF_DEFAULT;
		return;
	}

	int dflt = (i->querier.conf.query_response_interval == 10 * PIMBD_TIME_PER_SECOND &&
			i->querier.conf.query_interval == 125 * PIMBD_TIME_PER_SECOND &&
			i->querier.conf.robustness == 2 &&
			i->querier.conf.last_listener_query_interval == 1 * PIMBD_TIME_PER_SECOND &&
			i->querier.conf.last_listener_query_count == 2);

	//This is to not forget custom configuration
	if(dflt) {
		if(i->querier.conf.state == QCONF_CUSTOM) {
			i->querier.conf.state = QCONF_DEFAULT;
			iface_unref(i);
		}
	} else {
		if(i->querier.conf.state == QCONF_DEFAULT) {
			i->querier.conf.state = QCONF_CUSTOM;
			iface_ref(i);
		}
	}
}

// Initialize querier-instance
void querier_init(struct querier *querier, ifgroups igs)
{
	memset(querier, 0, sizeof(*querier));
	querier->igs = igs;
	querier->igs_user.if_cb = querier_iface_callback;
	ifgroups_subscribe(igs, &querier->igs_user);
}

// Cleanup querier-instance
void querier_deinit(struct querier *querier)
{
	ifgroups_unsubscribe(&querier->igs_user);
	iface i, i2;
	ifgroups_for_each_iface_safe(querier->igs, i, i2) {
		if(i->querier.state) {
			querier_iface_teardown(i);
			struct querier_user_iface *user, *n;
			list_for_each_entry_safe(user, n, &i->querier.users, head)
				querier_detach(user);
		}
	}
}
