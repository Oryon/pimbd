/*
 * Author: Pierre Pfister <pierre pfister at darou.fr>
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

#ifndef RIB_H_
#define RIB_H_

#include <arpa/inet.h>
#include <libubox/avl.h>

#include "utils.h"

struct rib_struct {
	struct avl_tree entries;   //Contains all entries
	struct avl_tree addresses; //Contains all addresses
	struct list_head users;
};
typedef struct rib_struct *rib, rib_s;

typedef struct rib_entry_struct {
	//linked in rib
	struct avl_node in_rib;

	struct in6_addr src;
	uint8_t src_plen;
	struct in6_addr dst;
	uint8_t dst_plen;
	int metric;
	bool onlink;
	struct in6_addr nexthop;
	int oif;
} *rib_entry, rib_entry_s;

typedef struct rib_addr_struct {
	//linked in rib
	struct avl_node in_rib;

	struct in6_addr addr;
	uint8_t plen;
	int ifindex;
} *rib_addr, rib_addr_s;

typedef struct rib_user_struct *rib_user, rib_user_s;
struct rib_user_struct {
	struct list_head le;
	void (*route_cb)(rib_user, rib_entry, int to_delete);
	void (*addr_cb)(rib_user, rib_addr, int to_delete);
};

#define RIB_ENTRY_L "route from %s to %s via %s dev %d metric %d"
#define RIB_ENTRY_LA(e) PREFIX_REPR(&(e)->src, (e)->src_plen), PREFIX_REPR(&(e)->dst, (e)->dst_plen), ADDR_REPR(&(e)->nexthop), (e)->oif, (e)->metric

#define RIB_ADDR_L "address %s on iface #%d"
#define RIB_ADDR_LA(a) PREFIX_REPR(&(a)->addr, (a)->plen), (a)->ifindex

#define RIB_ROUTE_PREFERENCE(r) 1000

/* Initializes the rib structure. */
int rib_init(rib rib);

/* Modifies a route.
 * Returns -1 in case of error. */
int rib_routemod(rib rib, const struct in6_addr *src, uint8_t src_plen,
		const struct in6_addr *dst, uint8_t dst_plen, int oif,
		const struct in6_addr *nexthop, int metric, int delete);

/* Returns the best route to some destination, given the source address (or NULL). */
rib_entry rib_lookup(rib rib, const struct in6_addr *src, const struct in6_addr *dst);

/* Called by rtnl to modify an address */
int rib_addrmod(rib rib, const struct in6_addr *addr, uint8_t plen,
		int ifindex, int delete);

/* Look for a local assignment for an address (optionally on some interface) */
rib_addr rib_addr_find(rib rib, const struct in6_addr *addr, int ifindex);

#define RIB_ADDR_LOCAL(rib, addr, index) (rib_addr_find(rib, addr, IN6_IS_ADDR_LINKLOCAL(addr)?index:-1))

/* Look for a link local address associated with the given interface. */
rib_addr rib_addr_find_ll(rib rib, int ifindex);
rib_addr rib_addr_find_v4(rib rib, int ifindex);

/* A rib user will get routes add and removal notification.
 * There is no route "modification". */
void rib_register(rib rib, rib_user user);
void rib_unregister(rib_user user);

#endif /* RIB_H_ */
