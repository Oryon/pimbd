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

/*
 * Generic storage dealing with ifaces and groups.
 * Users can store data for each iface, group or iface/group pairs.
 * The iface object also provides callbacks for configuration events.
 *
 */

#ifndef IFGROUP_H_
#define IFGROUP_H_

#include <net/if.h> //IFNAMSIZ
#include <netinet/in.h> //struct in6_addr

#include <libubox/list.h>
#include <libubox/avl.h>

#include "pimbd.h"
#include "rib.h"

/* Defined in ifgroup_s.h */
typedef struct iface_struct *iface, iface_s;
typedef struct group_struct *group, group_s;
typedef struct source_struct *source, source_s;
typedef struct ifgroup_struct *ifgroup, ifgroup_s;
typedef struct gsource_struct *gsource, gsource_s;
typedef struct ifgsource_struct *ifgsource, ifgsource_s;

typedef uint16_t iface_flags;

typedef struct ifgroups_struct *ifgroups, ifgroups_s;
typedef struct ifgroups_user_struct ifgroups_user_s, *ifgroups_user;

/**
 * The callback type for iface events subscribers.
 */
typedef void (*iface_callback)(ifgroups_user user, iface i, iface_flags changed_flags);

/**
 * Used by a module in order to specify the callback
 * function to use when an interface is modified.
 */
struct ifgroups_user_struct {

	struct list_head le;

	/* Called when some interface's flags are modified. */
	iface_callback if_cb;

};

/**
 * Root structure for ifgroups storage system.
 */
struct ifgroups_struct {

	/* List containing iface users */
	struct list_head users;

	/* List containing all ifaces */
	struct list_head ifaces;

	/* Tree containing all the groups. */
	struct avl_tree groups;

	/* Tree containing all the sources. */
	struct avl_tree sources;

	/* Rib user that receives addresses */
	rib rib;
	rib_user_s rib_user;
};

/**
 * Other generic values
 */

//Generic enum used everywhere where a PIM state is used
enum pim_state {
	PIM_NONE = 0,
	PIM_JOIN,
	PIM_PRUNE,
	PIM_PRUNEPENDING,
};

extern const char *pim_state_str[];
#define PIM_STATE_STR(s) pim_state_str[s]

/**
 * Initializes ifgroups structure.
 */
void ifgroups_init(ifgroups igs, rib rib);

#define ifgroups_subscribe(igs, user) list_add(&(user)->le, &(igs)->users)

#define ifgroups_unsubscribe(user) list_del(&(user)->le)

#endif /* IFGROUP_H_ */
