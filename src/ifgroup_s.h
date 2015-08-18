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
 * Secondary header file for ifgroup.h.
 * Defined for simplicity given dependency maze between users and
 * ifgroups objects.
 */

#ifndef IFGROUP_I_H_
#define IFGROUP_I_H_

#include "ifgroup.h"
#include "pim.h"
#include "pim_proxy.h"
#include "conf.h"
#include "querier.h"
#include "groups.h"
#include "listener.h"

#define object_ref(o) (++(o)->refcnt)
#define object_unref(type, o) do {if((!(o)->refcnt) || !(--(o)->refcnt)) type##_clean_maybe(o);}while(0)

/********************** Per iface structure **************************/

/**
 * Structure representing one interface.
 */
struct iface_struct {

    /* Linked in ifaces. */
	struct list_head le;

	/* BackPointer to ifgroups */
	ifgroups ifgroups;

	/* Interface name. */
	char ifname[IFNAMSIZ];

	/* Interface related information */
	iface_flags flags;
#define IFACE_FLAG_EXISTS       0x01  /* Iface exists on the system */
#define IFACE_FLAG_UP           0x02  /* Iface is up */
#define IFACE_FLAG_PIM          0x04  /* PIM should be enabled on this iface */
#define IFACE_FLAG_PROXY        0x08  /* The proxy should be enabled on this iface */
#define IFACE_FLAG_MLD_QUERIER  0x10  /* The MLD querier should be enabled on this iface */
#define IFACE_FLAG_IGMP_QUERIER 0x20  /* The IGMP querier should be enabled on this iface */
#define IFACE_FLAG_LLADDR       0x40  /* The link-local address is set */
#define IFACE_FLAG_V4ADDR       0x80  /* The IPv4 address is set */
#define IFACE_FLAG_SSBIDIR      0x100 /* Enable SSBIDIR support on that interface */


	/* Tree containing ifgroups associated with that iface. */
	struct avl_tree igs;

	/* Number of users. The iface may be destroyed when it comes to zero. */
	int refcnt;

	/* System ifindex. Must be correct whenever IFACE_FLAG_EXISTS is set. */
	int ifindex;

	/* An available link-local IPv6 address (or NULL) */
	rib_addr lladdr;

	/* An available IPv4 address (or NULL) */
	rib_addr v4addr;

	/* The port and address the proxy should listen on */
	in_port_t proxy_port;
	struct in6_addr proxy_addr;

	/* User structures */
	pim_iface_s pim;

	conf_iface_s conf;

	pim_proxy_iface_s proxy;

	struct querier_iface querier;

	struct listener_iface listener;
};

/**
 * Sets the iface flags and calls the user callbacks from all iface
 * users except the one of the provided user. If flags aren't changed,
 * users are not notified.
 */
void iface_set_flags(ifgroups_user user, iface iface, iface_flags new_flags);

/**
 * Get or create an interface with the given name.
 */
iface iface_get_byname(ifgroups igs, const char *ifname, bool create);

/**
 * Fetch an existing iface with the corresponding ifindex.
 * If it doesn't exist, good old if_indextoname is used to get the name.
 * When created this way, user's iface callbacks are called with flag IFACE_FLAG_EXISTS.
 */
iface iface_get_byindex(ifgroups igs, int ifindex, bool create);

#define iface_ref(i) object_ref(i)

#define iface_unref(i) object_unref(iface, i)

void iface_clean_maybe(iface);




/********************** Per Group structure **************************/

/**
 * Group structure.
 * The address doesn't need to be a multicast one.
 */
struct group_struct {

	/* Inserted in groups */
	struct avl_node te;

	/* Address of that group */
	struct in6_addr addr;

	/* Backpointer to ifgroups */
	ifgroups ifgroups;

	/* List containing associated ifgroups */
	struct list_head igs;

	/* Tree containing associated gsources */
	struct avl_tree gss;

	unsigned int refcnt            : 4; //Number of users (max 15)
	unsigned int pim_upstream      : 1; //PIM Upstream state
	unsigned int conf_join_desired : 2; //Configuration Join Desired Override
	unsigned int pim_rpa_set       : 1; //Whether pim_rpa is valid
	unsigned int jp_to_send        : 1; //Whether a jp should be sent
	unsigned int jp_joined         : 1; //Whether a join was sent
	unsigned int ctl_updated       : 1; //Whether the group should be checked for ctl update
	unsigned int ctl_joined        : 1; //Whether the controller joined the group

	pim_rpa pim_rpa;              //The associated rpa (use getter pim_rpa_get)
	uint16_t pim_jd_source_count; //Number of sources with join_desired set
	pim_neigh jp_prev_df;        //The current upstream forwarder
	struct in6_addr jp_prev_rpa; //RP address used for last Join
	pimbd_time_t jp_next;        //When next update should be sent
	uint32_t jp_tolerance;       //JP can be sent that long before actual next
};

/**
 * Gets or create the group associated with this address.
 */
group group_get(ifgroups igs, const struct in6_addr *addr, bool create);

#define group_ref(g) object_ref(g)

#define group_unref(g) object_unref(group, g)

void group_clean_maybe(group);

#define GROUP_L "(*,%s)"
#define GROUP_LA(g) ADDR_REPR(&(g)->addr)

/******************* Per Source structure *******************/

/*
 * A source stores state related to a given multicast traffic source
 */
struct source_struct {

	/* Inserted in groups */
	struct avl_node te;

	/* Address of that group */
	struct in6_addr addr;

	/* Backpointer to ifgroups */
	ifgroups ifgroups;

	/* Tree containing gsources associated with that source. */
	struct list_head gss;

	unsigned int refcnt             : 4; //Number of users (max 15)
};

source source_get(ifgroups igs, const struct in6_addr *source, bool create);

#define source_ref(s) object_ref(s)
#define source_unref(s) object_unref(source, s)

void source_clean_maybe(source s);

#define SOURCE_L "%s"
#define SOURCE_LA(s) ADDR_REPR(&(s)->addr)


/******************* Per Iface And Group structure *******************/

/**
 * An ifgroup stores state related to iface/group pairs.
 */
struct ifgroup_struct {

	/* Backpointer to the associated iface */
	iface iface;

	/* Backpointer to the associated group */
	group group;

	/* Linked in group object. */
	struct list_head in_group;

	/* Linked in iface object. */
	struct avl_node in_iface;

	/* Tree containing all associated ifgsources */
	struct avl_tree ifgss;

	unsigned int refcnt             : 4; //Number of users (max 15)
	unsigned int pim_local_exclude  : 1; //Local subscribers in exclude mode
	unsigned int pim_downstream     : 2; //PIM Downstream state
	unsigned int conf_local_exclude : 1; //Configured local exclude
	unsigned int querier_set        : 1; //Whether the querier uses that structure
	unsigned int listener_exclude   : 2; //Listener exclude bitfield
	unsigned int listener_active    : 1; //Whether the listener is active

	struct uloop_timeout pim_expiry_timer; //PIM Downstream Expiry timeout
	struct uloop_timeout pim_pp_timer;     //PIM Prune Pending timeout

	uint32_t proxy_join;

	uint16_t listener_incl_cnt;
	uint16_t listener_excl_cnt;

	/* querier group state */
	struct querier_group querier;
};

/**
 * Gets or creates an ifgroup.
 * iface or group can be NULL (In which case NULL is returned.).
 */
ifgroup ifgroup_get(iface iface, group group, bool create);

#define ifgroup_ref(ig) object_ref(ig)

#define ifgroup_unref(ig) object_unref(ifgroup, ig)

void ifgroup_clean_maybe(ifgroup ifgroup);

#define IFGROUP_L "(*,%s,%s)"
#define IFGROUP_LA(ig) ADDR_REPR(&(ig)->group->addr), (ig)->iface->ifname

/******************* Per Source And Group structure *******************/

/**
 * A gsource stores state related to a group and source pair.
 */
struct gsource_struct {

	/* Backpointer to the associated group */
	group group;

	/* Backpointer to the associated source */
	source source;

	/* Linked in group object. */
	struct avl_node in_group;

	/* Linked in source object. */
	struct list_head in_source;

	/* List containing all associated ifgsources */
	struct list_head ifgss;

	unsigned int refcnt            : 4; //Number of users (max 15 users)
	unsigned int pim_upstream      : 1; //PIM Upstream state
	unsigned int pim_upstream_rpt  : 1; //PIM Upstream rpt state
	unsigned int pim_join_desired  : 1; //PIM Downstream (G,S) aggregate
	unsigned int conf_join_desired : 2; //Configuration Join Desired Override
	unsigned int jp_to_send        : 1; //Whether a jp should be sent
	unsigned int jp_joined         : 1; //Whether a join was sent
	unsigned int jp_rpt_to_send    : 1; //Whether a (S,G,rpt) should be sent
	unsigned int jp_pruned         : 1; //Whether a (S,G,rpt) was sent already
	unsigned int ctl_joined        : 1; //Whether the controller sent joined
	unsigned int ctl_pruned        : 1; //Whether the controller sent pruned

	pimbd_time_t jp_next;        //When next update should be sent
	uint32_t jp_tolerance;       //JP can be sent that long before actual next

	pimbd_time_t jp_rpt_next;    //Triggered send or override
	uint32_t jp_rpt_tolerance;   //JP can be sent that long before actual next
};

/**
 * Gets or creates an ifgroup.
 * iface or group can be NULL (In which case NULL is returned.).
 */
gsource gsource_get(group group, source source, bool create);

#define gsource_ref(gs) object_ref(gs)

#define gsource_unref(gs) object_unref(gsource, gs)

void gsource_clean_maybe(gsource gsource);

#define GSOURCE_L "(%s,%s)"
#define GSOURCE_LA(gs) ADDR_REPR(&(gs)->source->addr), ADDR_REPR(&(gs)->group->addr)


/**
 * Represents a source for a given group and iface
 */
struct ifgsource_struct {

	/* Associated ifgroup */
	ifgroup ig;

	/* Associated gsource */
	gsource gs;

	/* Linked in the ifgroup */
	struct avl_node in_ifgroup;

	/* Linked in the gsource */
	struct list_head in_gsource;

	/* querier per-source state */
	struct querier_source querier;

	unsigned int refcnt             : 4; //Number of users
	unsigned int pim_downstream     : 2; //PIM (S,G) downstream state
	unsigned int pim_downstream_rpt : 2; //PIM (S,G,rpt) downstream state
	unsigned int pim_saw_rpt_prune  : 1; //While parsing, we saw this prune (temporary state)
	unsigned int pim_local_exclude  : 1; //Local subscribers in exclude mode
	unsigned int pim_local_include  : 1; //Local subscribers in include mode
	//todo: conf_local_exclude
	unsigned int querier_set        : 1; //Whether the querier uses that structure
	unsigned int listener_include   : 2; //Listener include bitfield
	unsigned int listener_exclude   : 2; //Listener exclude bitfield

	struct uloop_timeout pim_expiry_timer; //PIM expiry timer
	struct uloop_timeout pim_pp_timer;     //PIM Prune Pending timer

	struct uloop_timeout pim_rpt_expiry_timer; //PIM expiry timer
	struct uloop_timeout pim_rpt_pp_timer;     //PIM Prune Pending timer

	uint32_t proxy_join;
	uint32_t proxy_prune;
};

/* Get or create an ifgsource. Returns NULL if ig is NULL. */
ifgsource ifgsource_get(ifgroup ig, gsource gs, bool create);
ifgsource ifgsource_get2(iface i, group g, source s, bool create);
ifgsource ifgsource_get3(ifgroup ig, const struct in6_addr *source);

#define ifgsource_ref(ifgs) object_ref(ifgs)

#define ifgsource_unref(ifgs) object_unref(ifgsource, ifgs)

void ifgsource_clean_maybe(ifgsource ifgs);

#define IFGSOURCE_L "(%s,%s,%s)"
#define IFGSOURCE_LA(ifgs) ADDR_REPR(&(ifgs)->gs->source->addr), ADDR_REPR(&(ifgs)->gs->group->addr), (ifgs)->ig->iface->ifname



/**
 * Iterates over all groups.
 */
#define ifgroups_for_each_group(grs, g) avl_for_each_element(&(grs)->groups, g, te)
#define ifgroups_for_each_group_safe(grs, g, g2) avl_for_each_element_safe(&(grs)->groups, g, te, g2)

/**
 * Iterates over all ifaces.
 */
#define ifgroups_for_each_iface(grs, i) list_for_each_entry(i, &(grs)->ifaces, le)
#define ifgroups_for_each_iface_safe(grs, i, i2) list_for_each_entry_safe(i, i2, &(grs)->ifaces, le)

/**
 * Iterates over all ifgroups in a group.
 */
#define ifgroups_for_each_in_group(g, ig) list_for_each_entry(ig, &(g)->igs, in_group)
#define ifgroups_for_each_in_group_safe(g, ig, ig2) list_for_each_entry_safe(ig, ig2, &(g)->igs, in_group)

/**
 * Iterates over all ifgroups in an iface.
 */
#define ifgroups_for_each_in_iface(i, ig) avl_for_each_element(&(i)->igs, ig, in_iface)
#define ifgroups_for_each_in_iface_safe(i, ig, ig2) avl_for_each_element_safe(&(i)->igs, ig, in_iface, ig2)

/**
 * Iterates over all ifgsources in an ifgroup
 */
#define ifgroups_for_each_source_in_ig(ig, ifgs) avl_for_each_element(&(ig)->ifgss, ifgs, in_ifgroup)
#define ifgroups_for_each_source_in_ig_safe(ig, ifgs, ifgs2) avl_for_each_element_safe(&(ig)->ifgss, ifgs, in_ifgroup, ifgs2)

/**
 * Iterates over all gsources in an group
 */
#define ifgroups_for_each_source_in_group(g, gs) avl_for_each_element(&(g)->gss, gs, in_group)
#define ifgroups_for_each_source_in_group_safe(g, gs, gs2) avl_for_each_element_safe(&(g)->gss, gs, in_group, gs2)


/**
 * Iterates over all ifgsources in an gsource
 */
#define ifgroups_for_each_iface_in_gsource(gs, ifgs) list_for_each_entry(ifgs, &(gs)->ifgss, in_gsource)
#define ifgroups_for_each_iface_in_gsource_safe(gs, ifgs, ifgs2) list_for_each_entry(ifgs, ifgs2, &(gs)->ifgss, in_gsource)


#endif /* IFGROUP_I_H_ */
