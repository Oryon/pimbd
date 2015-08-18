/*
 * Authors: Pierre Pfister <pierre pfister at darou.fr>
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


#include "rib.h"

#include <stdlib.h>

#include "pimbd.h"
#include "utils.h"

/* Order is used to optimize the lookup.
 * Once a matching route is found, it is the best.*/
int rib_entry_cmp(const void *k1, const void *k2, __unused void *ptr)
{
	const struct rib_entry_struct *e1 = k1;
	const struct rib_entry_struct *e2 = k2;
	int i;
	if((i = (e1->dst_plen - e2->dst_plen)) ||
			(i = (e1->src_plen - e2->src_plen)) ||
			(i = (e2->metric - e1->metric)) ||
			(i = ((!!e1->onlink) - (!!e2->onlink))) ||
			(i = (e1->oif - e2->oif)) ||
			(i = addr_cmp(&e1->src, &e2->src)) ||
			(i = addr_cmp(&e1->dst, &e2->dst)) ||
			(i = e1->onlink?0:addr_cmp(&e1->nexthop, &e2->nexthop)))
		return (i>0)?1:(i<0)?-1:0;

	return 0;
}

int rib_addr_cmp(const void *k1, const void *k2, __unused void *ptr)
{
	return addr_cmp(k1, k2);
}

int rib_init(rib rib)
{
	avl_init(&rib->entries, rib_entry_cmp, false, NULL);
	INIT_LIST_HEAD(&rib->users);
	avl_init(&rib->addresses, rib_addr_cmp, true, NULL);
	return 0;
}

static void rib_route_notify_users(rib rib, rib_entry entry, int del)
{
	rib_user u;
	list_for_each_entry(u, &rib->users, le) {
		if(u->route_cb)
			u->route_cb(u, entry, del);
	}
}

static void rib_addr_notify_users(rib rib, rib_addr a, int del)
{
	rib_user u;
	list_for_each_entry(u, &rib->users, le) {
		if(u->addr_cb)
			u->addr_cb(u, a, del);
	}
}

static void rib_entry_destroy(rib rib, rib_entry entry)
{
	L_INFO("Del "RIB_ENTRY_L, RIB_ENTRY_LA(entry));
	avl_delete(&rib->entries, &entry->in_rib);
	rib_route_notify_users(rib, entry, 1);
	free(entry);
}

static rib_entry rib_entry_goc(rib rib,
		const struct in6_addr *src, uint8_t src_plen,
		const struct in6_addr *dst, uint8_t dst_plen,
		int oif, const struct in6_addr *nexthop,
		int metric, int create)
{
	struct in6_addr nil = { .s6_addr = {0}};
	rib_entry_s e = {
			.src = (src && src_plen)?*src:nil,
			.dst = (dst && dst_plen)?*dst:nil,
			.src_plen = src_plen,
			.dst_plen = dst_plen,
			.metric = metric,
			.oif = oif,
			.onlink = !nexthop,
			.nexthop = nexthop?*nexthop:nil,
	};
	struct avl_node *node;
	if((node = avl_find(&rib->entries, &e)))
		return container_of(node, rib_entry_s, in_rib);

	if(create) {
		rib_entry p;
		if(!(p = malloc(sizeof(*p)))) {
			L_ERR("malloc error");
			return NULL;
		}
		memcpy(p, &e, sizeof(*p));
		p->in_rib.key = p;
		if(avl_insert(&rib->entries, &p->in_rib)) {
			L_ERR("Insert in tree error (rib.c)");
			free(p);
			return NULL;
		}
		L_INFO("Add "RIB_ENTRY_L, RIB_ENTRY_LA(p));
		rib_route_notify_users(rib, p, 0);
		return p;
	}

	return NULL;
}

int rib_routemod(rib rib,
		const struct in6_addr *src, uint8_t src_plen,
		const struct in6_addr *dst, uint8_t dst_plen,
		int oif, const struct in6_addr *nexthop,
		int metric, int delete)
{
	rib_entry e = rib_entry_goc(rib, src, src_plen, dst, dst_plen, oif, nexthop, metric, !delete);
	if(!delete)
		return e?0:1;
	if(e)
		rib_entry_destroy(rib, e);
	return 0;
}

rib_entry rib_lookup(rib rib, const struct in6_addr *src, const struct in6_addr *dst)
{
	rib_entry e;
	//L_DEBUG("rib lookup to %s from %s", ADDR_REPR(dst), src?ADDR_REPR(src):"any");
	avl_for_each_element_reverse(&rib->entries, e, in_rib) {
		if(prefix_contains(&e->dst, e->dst_plen, dst) &&
				((!src) || (src && prefix_contains(&e->src, e->src_plen, src)))) {
			//L_DEBUG("  -- Best route is "RIB_ENTRY_L, RIB_ENTRY_LA(e));
			return e;
		}
	}
	//L_DEBUG("  -- No best route");
	return NULL;
}

static void rib_addr_destroy(rib rib, rib_addr addr)
{
	avl_delete(&rib->addresses, &addr->in_rib);
	L_NOTICE("Delete "RIB_ADDR_L, RIB_ADDR_LA(addr));
	rib_addr_notify_users(rib, addr, 1);
	free(addr);
}

rib_addr rib_addr_find(rib rib, const struct in6_addr *addr, int ifindex)
{
	rib_addr a = avl_find_element(&rib->addresses, addr, a, in_rib);
	rib_addr i;
	if(ifindex <= 0 || !a)
		return a;

	avl_for_element_to_last(&rib->addresses, a, i, in_rib) {
		if(addr_cmp(addr, &i->addr))
			return NULL;
		if(ifindex == i->ifindex) {
			return i;
		}
	}
	return NULL;
}

rib_addr rib_addr_find_v4(rib rib, int ifindex)
{
	rib_addr a;
	avl_for_each_element(&rib->addresses, a, in_rib) {
		if(a->ifindex == ifindex && IN6_IS_ADDR_V4MAPPED(&a->addr))
			return a;
	}
	return NULL;
}

rib_addr rib_addr_find_ll(rib rib, int ifindex)
{
	rib_addr a;
	avl_for_each_element(&rib->addresses, a, in_rib) {
		if(a->ifindex == ifindex && IN6_IS_ADDR_LINKLOCAL(&a->addr))
			return a;
	}
	return NULL;
}

static rib_addr rib_addr_goc(rib rib, const struct in6_addr *addr, uint8_t plen,
		int ifindex, int create)
{
	rib_addr a = rib_addr_find(rib, addr, ifindex);
	if(!create || a)
		return a;

	if(!(a = malloc(sizeof(*a))))
		return NULL;

	a->ifindex = ifindex;
	a->plen = plen;
	addr_cpy(&a->addr, addr);
	a->in_rib.key = &a->addr;
	avl_insert(&rib->addresses, &a->in_rib);
	L_NOTICE("Add "RIB_ADDR_L, RIB_ADDR_LA(a));

	rib_addr_notify_users(rib, a, 0);
	return a;
}

int rib_addrmod(rib rib, const struct in6_addr *addr, uint8_t plen,
		int ifindex, int delete)
{
	rib_addr e = rib_addr_goc(rib, addr, plen, ifindex, !delete);
	if(!delete)
		return e?0:1;
	if(e)
		rib_addr_destroy(rib, e);
	return 0;
}

void rib_register(rib rib, rib_user user)
{
	list_add(&user->le, &rib->users);
}

void rib_unregister(rib_user user)
{
	list_del(&user->le);
}
