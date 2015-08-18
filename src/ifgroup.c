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

#include "ifgroup_s.h"

#include <string.h>
#include <stdlib.h>
#include <net/if.h>

const char *pim_state_str[4] = {
		[PIM_NONE] = "None",
		[PIM_JOIN] = "Join",
		[PIM_PRUNE] = "Prune",
		[PIM_PRUNEPENDING] = "None",
};

static int ifgroup_avl_cmp(const void *k1, const void *k2, __unused void *ptr)
{
	return memcmp(k1, k2, sizeof(struct in6_addr));
}

static void ifgroups_addr_cb(rib_user u, rib_addr a, int del)
{
	ifgroups igs = container_of(u, ifgroups_s, rib_user);
	iface i = iface_get_byindex(igs, a->ifindex, !del);
	if(!i) {
		if(!del) {
			L_ERR("Uncaught error: Unknown iface #%d - Address %s can't be used", a->ifindex, ADDR_REPR(&a->addr));
		}
		return;
	}

	iface_flags f = 0;
	rib_addr *container;
	rib_addr (*finder)(rib, int);

	if(IN6_IS_ADDR_V4MAPPED(&a->addr)) {
		f = IFACE_FLAG_V4ADDR;
		container = &i->v4addr;
		finder = rib_addr_find_v4;
	} else if(IN6_IS_ADDR_LINKLOCAL(&a->addr)) {
		f = IFACE_FLAG_LLADDR;
		container = &i->lladdr;
		finder = rib_addr_find_ll;
	} else {
		return;
	}

	if(del) {
		if(*container == a) {
			*container = finder(igs->rib, i->ifindex);
		} else {
			f = 0;
		}
	} else {
		if(!*container) {
			*container = a;
		} else {
			f = 0;
		}
	}

	if(f) {
		i->flags = (*container)?(i->flags | f):(i->flags & ~f);
		L_DEBUG("Changed interface %s flags to 0x%x", i->ifname, i->flags);
		ifgroups_user u;
		list_for_each_entry(u, &igs->users, le) {
			if(u->if_cb)
				u->if_cb(u, i, f);
		}
	}
}

/********************** General structure **************************/

void ifgroups_init(ifgroups igs, rib rib)
{
	INIT_LIST_HEAD(&igs->users);
	INIT_LIST_HEAD(&igs->ifaces);
	avl_init(&igs->groups, ifgroup_avl_cmp, false, NULL);
	avl_init(&igs->sources, ifgroup_avl_cmp, false, NULL);
	igs->rib_user.addr_cb = ifgroups_addr_cb;
	igs->rib_user.route_cb = NULL;
	igs->rib = rib;
	rib_register(rib, &igs->rib_user);
}


/********************** Per iface structure **************************/

static iface iface_find(ifgroups igs, const char *ifname) {
	iface i;
	ifgroups_for_each_iface(igs, i) {
		if(!strcmp(ifname, i->ifname))
			return i;
	}
	return NULL;
}

static iface iface_create(ifgroups igs, const char *ifname) {
	iface i;
	if(!(i = calloc(1, sizeof(*i))))
		return NULL;

	strcpy(i->ifname, ifname);
	i->ifgroups = igs;
	avl_init(&i->igs, ifgroup_avl_cmp, false, NULL);
	list_add_tail(&i->le, &igs->ifaces);
	return i;
}

static void iface_destroy(iface i) {
	L_DEBUG("Destroying structure iface %s", i->ifname);
	list_del(&i->le);
	free(i);
}

iface iface_get_byindex(ifgroups igs, int ifindex, bool create)
{
	iface i;
	ifgroups_for_each_iface(igs, i) {
		if((i->flags & IFACE_FLAG_EXISTS) && (ifindex == i->ifindex))
			return i;
	}
	if(!create)
		return NULL;

	char ifname[IFNAMSIZ+1];
	if((!if_indextoname(ifindex, ifname)) || !(i = iface_get_byname(igs, ifname, true))) {
		L_ERR("Could not create interface #%d by index", ifindex);
		return NULL;
	}

	L_INFO("Creating interface %s (%d) by index (Did not receive rtnetlink first ?)", ifname, ifindex);
	i->ifindex = ifindex;
	iface_set_flags(NULL, i, IFACE_FLAG_EXISTS);
	return i;
}

iface iface_get_byname(ifgroups igs, const char *ifname, bool create)
{
	iface i;
	return ((i = iface_find(igs, ifname)))?i:(create?iface_create(igs, ifname):NULL);
}

void iface_set_flags(ifgroups_user user, iface iface, iface_flags new_flags)
{
	ifgroups igs = iface->ifgroups;
	iface_flags changed_flags = new_flags ^ iface->flags;
	if(changed_flags) {
		L_DEBUG("Change interface %s flags to 0x%x", iface->ifname, new_flags);
		iface->flags = new_flags;
		ifgroups_user u;
		list_for_each_entry(u, &igs->users, le) {
			if(u->if_cb && u != user)
				u->if_cb(u, iface, changed_flags);
		}
	}
	iface_clean_maybe(iface);
}

void iface_clean_maybe(iface iface)
{
	if(avl_is_empty(&iface->igs) && !iface->refcnt && !iface->flags)
		iface_destroy(iface);
}



/********************** Per Group structure **************************/


static void group_destroy(group group)
{
	L_DEBUG("Destroying structure group "GROUP_L, GROUP_LA(group));
	avl_delete(&group->ifgroups->groups, &group->te);
	free(group);
}

static group group_create(ifgroups igs, const struct in6_addr *addr)
{
	group g;
	if(!(g = calloc(1, sizeof(*g))))
		return NULL;

	memcpy(&g->addr, addr, sizeof(*addr));
	g->ifgroups = igs;
	g->te.key = &g->addr;
	INIT_LIST_HEAD(&g->igs);
	avl_init(&g->gss, ifgroup_avl_cmp, false, NULL);
	if(!avl_insert(&igs->groups, &g->te))
		return g;

	free(g);
	return NULL;
}

group group_get(ifgroups igs, const struct in6_addr *addr, bool create)
{
	struct avl_node *n;
	return ((n = avl_find(&igs->groups, addr)))?container_of(n, group_s, te):(create?group_create(igs, addr):NULL);
}

void group_clean_maybe(group group)
{
	if(!group->refcnt &&
			list_empty(&group->igs) && avl_is_empty(&group->gss))
		group_destroy(group);
}

/********************** Per Source structure **************************/

static void source_destroy(source s)
{
	L_DEBUG("Destroying structure source "SOURCE_L, SOURCE_LA(s));
	avl_delete(&s->ifgroups->sources, &s->te);
	free(s);
}

static source source_create(ifgroups igs, const struct in6_addr *addr)
{
	source s;
	if(!(s = calloc(1, sizeof(*s))))
		return NULL;

	memcpy(&s->addr, addr, sizeof(*addr));
	s->ifgroups = igs;
	s->te.key = &s->addr;
	INIT_LIST_HEAD(&s->gss);
	if(!avl_insert(&igs->sources, &s->te))
		return s;

	free(s);
	return NULL;
}

source source_get(ifgroups igs, const struct in6_addr *addr, bool create)
{
	struct avl_node *n;
	return ((n = avl_find(&igs->sources, addr)))?container_of(n, source_s, te):(create?source_create(igs, addr):NULL);
}

void source_clean_maybe(source s)
{
	if(!s->refcnt && list_empty(&s->gss))
		source_destroy(s);
}


/******************* Per Iface And Group structure *******************/

ifgroup ifgroup_create(iface iface, group group) {
	ifgroup ig;
	if(!(ig = calloc(1, sizeof(*ig))))
		return NULL;

	ig->group = group;
	ig->iface = iface;
	ig->in_iface.key = &group->addr;
	if(avl_insert(&iface->igs, &ig->in_iface)) {
		free(ig);
		return NULL;
	}
	list_add_tail(&ig->in_group, &group->igs);
	avl_init(&ig->ifgss, ifgroup_avl_cmp, false, NULL);

	return ig;
}

void ifgroup_destroy(ifgroup ig)
{
	L_DEBUG("Destroying structure ifgroup "IFGROUP_L, IFGROUP_LA(ig));
	list_del(&ig->in_group);
	avl_delete(&ig->iface->igs, &ig->in_iface);
	iface_clean_maybe(ig->iface);
	group_clean_maybe(ig->group);
	free(ig);
}

ifgroup ifgroup_get(iface iface, group group, bool create)
{
	if(!iface || !group)
		return NULL;

	struct avl_node *n;
	return ((n = avl_find(&iface->igs, &group->addr)))?container_of(n, ifgroup_s, in_iface):create?ifgroup_create(iface, group):NULL;
}

void ifgroup_clean_maybe(ifgroup ifgroup)
{
	if(!ifgroup->refcnt && avl_is_empty(&ifgroup->ifgss))
		ifgroup_destroy(ifgroup);
}

/******************* Per Source And Group structure *******************/

gsource gsource_create(group group, source source)
{
	gsource gs;
	if(!(gs = calloc(1, sizeof(*gs))))
		return NULL;
	gs->group = group;
	gs->source = source;
	gs->in_group.key = &source->addr;
	INIT_LIST_HEAD(&gs->ifgss);
	if(avl_insert(&group->gss, &gs->in_group)) {
		free(gs);
		return NULL;
	}
	list_add(&gs->in_source, &source->gss);
	return gs;
}

void gsource_destroy(gsource gs)
{
	L_DEBUG("Destroying structure gsource "GSOURCE_L, GSOURCE_LA(gs));
	avl_delete(&gs->group->gss, &gs->in_group);
	list_del(&gs->in_source);
	group_clean_maybe(gs->group);
	source_clean_maybe(gs->source);
	free(gs);
}

gsource gsource_get(group group, source source, bool create)
{
	if(!group || !source)
		return NULL;

	struct avl_node *n;
	return ((n = avl_find(&group->gss, &source->addr)))?container_of(n, gsource_s, in_group):(create?gsource_create(group, source):NULL);
}

void gsource_clean_maybe(gsource gs)
{
	if(!gs->refcnt && list_empty(&gs->ifgss))
		gsource_destroy(gs);
}

/******************* Per Iface, Group and Source structure *******************/

static ifgsource ifgsource_create(ifgroup ig, gsource gs)
{
	ifgsource ifgs;
	if(!(ifgs = calloc(1, sizeof(*ifgs))))
		return NULL;
	ifgs->gs = gs;
	ifgs->ig = ig;
	ifgs->in_ifgroup.key = &gs->source->addr;
	if(avl_insert(&ig->ifgss, &ifgs->in_ifgroup)) {
		free(ifgs);
		return NULL;
	}
	list_add(&ifgs->in_gsource, &gs->ifgss);
	return ifgs;
}

static void ifgsource_destroy(ifgsource ifgs)
{
	avl_delete(&ifgs->ig->ifgss, &ifgs->in_ifgroup);
	list_del(&ifgs->in_gsource);
	ifgroup_clean_maybe(ifgs->ig);
	gsource_clean_maybe(ifgs->gs);
	free(ifgs);
}

ifgsource ifgsource_get(ifgroup ig, gsource gs, bool create)
{
	if(!ig || !gs)
		return NULL;
	struct avl_node *n;
	return ((n = avl_find(&ig->ifgss, &gs->source->addr)))?container_of(n, ifgsource_s, in_ifgroup):(create?ifgsource_create(ig, gs):NULL);
}

ifgsource ifgsource_get2(iface i, group g, source s, bool create)
{
	ifgroup ig = ifgroup_get(i, g, create);
	gsource gs = gsource_get(g, s, create);
	return (ig && gs)?ifgsource_get(ig, gs, create):NULL;
}

ifgsource ifgsource_get3(ifgroup ig, const struct in6_addr *source)
{
	struct avl_node *n;
	return ((n = avl_find(&ig->ifgss, source)))?container_of(n, ifgsource_s, in_ifgroup):NULL;
}

void ifgsource_clean_maybe(ifgsource ifgs)
{
	if(!ifgs->refcnt)
		ifgsource_destroy(ifgs);
}
