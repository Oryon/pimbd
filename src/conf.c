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

#include "conf.h"

#include <limits.h>

#include "ifgroup.h"
#include "pim_proto.h"
#include "pim_group.h"
#include "pim_ctl.h"

int cifv_defaults[] = {
		[CIFV_PIM_HELLO_PERIOD_MS] = PP_HELLO_PERIOD_MS,
		[CIFV_PIM_US_T_PERIODIC_MS] = PP_T_PERIODIC_MS,
		[CIFV_CONF_MAX] = INT_MIN,

		[CIFV_PIM_DR_PRIORITY] = PP_DR_PRIORITY,
		[CIFV_PIM_DFE_OFFER_PERIOD_MS] = PP_DFE_OFFER_PERIOD_MS,
		[CIFV_PIM_DFE_BACKOFF_PERIOD_MS] = PP_DFE_BACKOFF_PERIOD_MS,
		[CIFV_PIM_DFE_ROBUSTNESS] = PP_DFE_ROBUSTNESS,
		[CIFV_PIM_JP_OVERRIDE_INTERVAL_MS] = PP_OVERRIDE_INTERVAL_MS,
};

int conf_get_ifvalue(conf conf, iface i, enum conf_iface_value v)
{
	if(v < CIFV_CONF_MAX && i->conf.state && i->conf.values[v] != INT_MIN) {
		return i->conf.values[v];
	}

	if(v < CIFV_CONF_ARRAY_MAX) {
		return cifv_defaults[v];
	}

	// The following values depend on other configuration values
	int res;
	switch (v) {
	case CIFV_PIM_TRIGGERED_HELLO_DELAY_MS:
		return conf_get_ifvalue(conf, i, CIFV_PIM_HELLO_PERIOD_MS) / 6;
	case CIFV_PIM_HOLDTIME_S:
		return ((res = ((3.5 * conf_get_ifvalue(conf, i, CIFV_PIM_HELLO_PERIOD_MS))/1000)))?res:1;
	case CIFV_PIM_US_JP_HOLDTIME_S:
		return ((res = ((3.5 * conf_get_ifvalue(conf, i, CIFV_PIM_US_T_PERIODIC_MS))/1000)))?res:1;
	default:
		L_ERR("Invalid configuration ifvalue was requested !! (%u)", (unsigned int)v);
		return INT_MIN;
	}
	return 0;
}


#define CONF_IFACE_ALL (IFACE_FLAG_PIM | IFACE_FLAG_PROXY | \
			IFACE_FLAG_MLD_QUERIER | IFACE_FLAG_IGMP_QUERIER | IFACE_FLAG_SSBIDIR)

int conf_set_ifvalue(iface i, enum conf_iface_value v, int value)
{
	if(!i->conf.state) {
		i->conf.state = 1;
		i->conf.values[0] = INT_MIN;
		i->conf.values[1] = INT_MIN;
		iface_ref(i);
	}

	if(v >= CIFV_CONF_MAX) {
		L_ERR("Can't configure ifvalue %u", v);
		return -1;
	}

	i->conf.values[v] = value;

	if(i->conf.values[0] == INT_MIN &&
			i->conf.values[1] == INT_MIN) {
		i->conf.state = 0;
		iface_unref(i);
	}
	return 0;
}

int conf_set_iface_flags(iface i, iface_flags flags, iface_flags flagsmask)
{
	flagsmask &= CONF_IFACE_ALL;
	flags &= flagsmask;
	iface_set_flags(NULL, i, (i->flags & (~flagsmask)) | flags);
	return 0;
}

/* Disables the interface. */
#define conf_set_iface_disabled(conf, ifname) conf_set_iface_flags(conf, ifname, \
							0, CONF_IFACE_ALL)

/* Sets the interface as internal (runs PIM and the querier). */
#define conf_set_iface_internal(conf, ifname) conf_set_iface_flags(conf, ifname, \
							IFACE_FLAG_PIM | IFACE_FLAG_QUERIER, CONF_IFACE_ALL)

/* Sets the interface as external (runs the proxy).  */
#define conf_set_iface_external(conf, ifname) conf_set_iface_flags(conf, ifname, \
							IFACE_FLAG_PROXY, CONF_IFACE_ALL)


enum {
	CONF_LINK_DEV,
	CONF_LINK_PIM,
	CONF_LINK_SSBIDIR,
	CONF_LINK_MLD,
	CONF_LINK_IGMP,
	CONF_LINK_PROXY,
	CONF_LINK_HELLO,
	CONF_LINK_JOIN,
	CONF_LINK_LLQC,
	CONF_LINK_ROBUSTNESS,
	CONF_LINK_MAX
};
const struct blobmsg_policy conf_link_attrs[CONF_LINK_MAX] = {
	[CONF_LINK_DEV] = { .name = "dev", .type = BLOBMSG_TYPE_STRING },
	[CONF_LINK_PIM] = { .name = "pim", .type = BLOBMSG_TYPE_BOOL },
	[CONF_LINK_SSBIDIR] = { .name = "ssbidir", .type = BLOBMSG_TYPE_BOOL },
	[CONF_LINK_MLD] = { .name = "mld", .type = BLOBMSG_TYPE_BOOL },
	[CONF_LINK_IGMP] = { .name = "igmp", .type = BLOBMSG_TYPE_BOOL },
	[CONF_LINK_PROXY] = { .name = "proxy", .type = BLOBMSG_TYPE_STRING },
	[CONF_LINK_HELLO] = { .name = "hello", .type = BLOBMSG_TYPE_INT32 },
	[CONF_LINK_JOIN] = { .name = "join", .type = BLOBMSG_TYPE_INT32 },
	[CONF_LINK_LLQC] = { .name = "llqc", .type = BLOBMSG_TYPE_INT32 },
	[CONF_LINK_ROBUSTNESS] = { .name = "robustness", .type = BLOBMSG_TYPE_INT32 },
};

static int conf_link_set(struct ipc_user *u, char *data, size_t len, __unused struct blob_buf *reply)
{
	conf conf = container_of(u, conf_s, ipc_users[CONF_IPC_LINK_SET]);
	struct blob_attr *tb[CONF_LINK_MAX];
	iface_flags flags = 0, flags_mod = 0;
	iface i;
	int ret = 0;

	if(blobmsg_parse(conf_link_attrs, CONF_LINK_MAX, tb, data, len) ||
			!tb[CONF_LINK_DEV])
		return -EINVAL;

	if(tb[CONF_LINK_LLQC] || tb[CONF_LINK_ROBUSTNESS]) {
		return -EOPNOTSUPP;
	}

	if(!(i = iface_get_byname(conf->igs, blobmsg_get_string(tb[CONF_LINK_DEV]), 1)))
		return -ENOMEM;

	iface_ref(i);

#define _(attr, flag) \
		if(attr) { \
			flags_mod |= flag; \
			if(blobmsg_get_bool(attr)) { \
				flags |= flag; \
			} else { \
				flags &= ~(flag); \
			} \
		}\

	_(tb[CONF_LINK_PIM], IFACE_FLAG_PIM);
	_(tb[CONF_LINK_SSBIDIR], IFACE_FLAG_SSBIDIR);
	_(tb[CONF_LINK_MLD], IFACE_FLAG_MLD_QUERIER);
	_(tb[CONF_LINK_IGMP], IFACE_FLAG_IGMP_QUERIER);

#undef _

	if(tb[CONF_LINK_PROXY]) {
		char *s = NULL;
		char *port = NULL;
		struct in6_addr addr;
		if(!(s = blobmsg_get_string(tb[CONF_LINK_PROXY])))
			return -EINVAL;

		if(!strcmp(s, "off")) {
			flags_mod |= IFACE_FLAG_PROXY;
			flags &= ~(IFACE_FLAG_PROXY);
		} else if(!(port = strchr(s, ' ')) || strchr(port + 1, ' ')) {
			return -EINVAL;
		} else {
			*port = '\0';
			port++;
			int p;
			if((sscanf(port, "%d", &p) != 1) || p >= 65536 || p<=0 || !addr_pton(&addr, s))
				return -EINVAL;

			if(i->proxy_port != p || addr_cmp(&i->proxy_addr, &addr)) {
				addr_cpy(&i->proxy_addr, &addr);
				i->proxy_port = (in_port_t) p;
				flags_mod |= IFACE_FLAG_PROXY;
				flags |= IFACE_FLAG_PROXY;
			}
		}
	}

	conf_set_iface_flags(i, flags, flags_mod);

	if(tb[CONF_LINK_HELLO]) {
		int hello = blobmsg_get_u32(tb[CONF_LINK_HELLO]);
		conf_set_ifvalue(i, CIFV_PIM_HELLO_PERIOD_MS, (hello>0)?hello:INT_MIN);
	}

	if(tb[CONF_LINK_JOIN]) {
		int join = blobmsg_get_u32(tb[CONF_LINK_JOIN]);
		conf_set_ifvalue(i, CIFV_PIM_US_T_PERIODIC_MS, (join>0)?join:INT_MIN);
	}

	iface_unref(i);
	return ret;
}

enum {
	CONF_RPA_RPA,
	CONF_RPA_GROUPS,
	CONF_RPA_RPL_JP,
	CONF_RPA_MAX,
};
const struct blobmsg_policy conf_rpa_attrs[CONF_RPA_MAX] = {
	[CONF_RPA_RPA] = { .name = "rpa", .type = BLOBMSG_TYPE_STRING },
	[CONF_RPA_GROUPS] = { .name = "groups", .type = BLOBMSG_TYPE_STRING },
	[CONF_RPA_RPL_JP] = { .name = "rpl_jp", .type = BLOBMSG_TYPE_BOOL },
};

static int conf_rpa_set(struct ipc_user *u, char *data, size_t len, __unused struct blob_buf *reply)
{
	conf conf = container_of(u, conf_s, ipc_users[CONF_IPC_RPA_SET]);
	struct blob_attr *tb[CONF_RPA_MAX];
	struct in6_addr rpa;

	if(blobmsg_parse(conf_rpa_attrs, CONF_RPA_MAX, tb, data, len) ||
			!tb[CONF_RPA_RPA] || !addr_pton(&rpa, blobmsg_get_string(tb[CONF_RPA_RPA])) ||
			tb[CONF_RPA_GROUPS])
		return -1;

	if(tb[CONF_RPA_RPL_JP])
		pim_rpa_set_rpl_jp(conf->pim, &rpa, blobmsg_get_u8(tb[CONF_RPA_RPL_JP]));

	return 0;
}

static int conf_rpa_flush(struct ipc_user *u, char *data, size_t len, __unused struct blob_buf *reply)
{
	conf conf = container_of(u, conf_s, ipc_users[CONF_IPC_RPA_FLUSH]);
	struct blob_attr *tb[CONF_RPA_MAX];
	struct in6_addr rpa;

	if(blobmsg_parse(conf_rpa_attrs, CONF_RPA_MAX, tb, data, len) ||
			!tb[CONF_RPA_RPA] || !addr_pton(&rpa, blobmsg_get_string(tb[CONF_RPA_RPA])) ||
			tb[CONF_RPA_GROUPS] || tb[CONF_RPA_RPL_JP])
		return -EINVAL;

	pim_rpa_update(conf->pim, &rpa);
	pim_rpa_flush(conf->pim, &rpa);
	return 0;
}

static int conf_rpa_mod(conf conf, char *data, size_t len, __unused struct blob_buf *reply, bool del)
{
	struct blob_attr *tb[CONF_RPA_MAX];
	struct in6_addr rpa;
	struct in6_addr gr;
	uint8_t plen;

	if(blobmsg_parse(conf_rpa_attrs, CONF_RPA_MAX, tb, data, len) ||
			!tb[CONF_RPA_RPA] || !addr_pton(&rpa, blobmsg_get_string(tb[CONF_RPA_RPA])) ||
			!tb[CONF_RPA_GROUPS] || !prefix_pton(&gr, &plen, blobmsg_get_string(tb[CONF_RPA_GROUPS])) ||
			!addr_is_multicast(&gr) || tb[CONF_RPA_RPL_JP])
		return -EINVAL;

	if(del)
		pim_rpa_del(conf->pim, &rpa, &gr, plen);
	else
		pim_rpa_add(conf->pim, &rpa, &gr, plen);
	return 0;
}

static int conf_rpa_add(struct ipc_user *u, char *data, size_t len, __unused struct blob_buf *reply)
{
	return conf_rpa_mod(container_of(u, conf_s, ipc_users[CONF_IPC_RPA_ADD]), data, len, reply, false);
}

static int conf_rpa_del(struct ipc_user *u, char *data, size_t len, __unused struct blob_buf *reply)
{
	return conf_rpa_mod(container_of(u, conf_s, ipc_users[CONF_IPC_RPA_DEL]), data, len, reply, true);
}


enum {
	CONF_G_GROUP,
	CONF_G_SRC,
	CONF_G_DEV,
	CONF_G_LISTENER,
	CONF_G_LOCAL,
	CONF_G_PIM,
	CONF_G_MAX
};
const struct blobmsg_policy conf_g_attrs[CONF_G_MAX] = {
	[CONF_G_GROUP] = { .name = "group", .type = BLOBMSG_TYPE_STRING },
	[CONF_G_SRC] = { .name = "src", .type = BLOBMSG_TYPE_STRING },
	[CONF_G_DEV] = { .name = "dev", .type = BLOBMSG_TYPE_STRING },
	[CONF_G_LISTENER] = { .name = "listener", .type = BLOBMSG_TYPE_STRING },
	[CONF_G_LOCAL] = { .name = "local", .type = BLOBMSG_TYPE_STRING },
	[CONF_G_PIM] = { .name = "pim", .type = BLOBMSG_TYPE_STRING },
};

int conf_group_set(struct ipc_user *u, char *data, size_t len, __unused struct blob_buf *reply)
{
	conf conf = container_of(u, conf_s, ipc_users[CONF_IPC_GROUP_SET]);
	ifgroups igs = conf->igs;
	pim pim = conf->pim;
	struct blob_attr *tb[CONF_G_MAX];
	struct in6_addr grp, src;
	group g = NULL;
	source s = NULL;
	gsource gs = NULL;
	iface i = NULL;
	ifgroup ig = NULL;
	ifgsource ifgs = NULL;
	int join = 0, listen = 0, local = 0;
	char *str;
	int ret = 0;

	if(blobmsg_parse(conf_g_attrs, CONF_G_MAX, tb, data, len) ||
			!tb[CONF_G_GROUP] || !addr_pton(&grp, blobmsg_get_string(tb[CONF_G_GROUP])) ||
			!addr_is_multicast(&grp) ||
			(tb[CONF_G_SRC] && !addr_pton(&src, blobmsg_get_string(tb[CONF_G_SRC]))) ||
			(tb[CONF_G_LISTENER] && !tb[CONF_G_DEV]))
		return -EINVAL;

	if(tb[CONF_G_PIM]) {
		if(!(str = blobmsg_get_string(tb[CONF_G_PIM])))
			return -EINVAL;
		else if (!strcmp(str, "join"))
			join = PIM_JOIN;
		else if(!strcmp(str, "prune"))
			join = PIM_PRUNE;
		else if(!strcmp(str, "none"))
			join = PIM_NONE;
		else
			return -EINVAL;
	}

	if(tb[CONF_G_LISTENER]) {
		if(!(str = blobmsg_get_string(tb[CONF_G_LISTENER])))
			return -EINVAL;
		else if (!strcmp(str, "include"))
			listen = PIM_JOIN;
		else if(!strcmp(str, "exclude"))
			listen = PIM_PRUNE;
		else if(!strcmp(str, "none"))
			listen = PIM_NONE;
		else
			return -EINVAL;
	}

	if(tb[CONF_G_LOCAL]) {
		if(!(str = blobmsg_get_string(tb[CONF_G_LOCAL])))
			return -EINVAL;
		else if (!strcmp(str, "include"))
			local = PIM_JOIN;
		else if(!strcmp(str, "exclude"))
			local = PIM_PRUNE;
		else if(!strcmp(str, "none"))
			local = PIM_NONE;
		else
			return -EINVAL;
	}

	if((tb[CONF_G_LOCAL] && !tb[CONF_G_DEV]) ||
			(tb[CONF_G_LISTENER] && !tb[CONF_G_DEV]))
		return -EINVAL;

	if((tb[CONF_G_GROUP] && (!(g = group_get(igs, &grp, 1)) || !group_ref(g))) ||
			(tb[CONF_G_SRC] && ((!(s = source_get(igs, &src, 1)) || !group_ref(s)) ||
					(!(gs = gsource_get(g, s, 1)) || !gsource_ref(gs)))) ||
			(tb[CONF_G_DEV] && ((!(i = iface_get_byname(igs, blobmsg_get_string(tb[CONF_G_DEV]), 1)) || !iface_ref(i)) ||
							(!(ig = ifgroup_get(i, g, 1)) || !ifgroup_ref(ig)))) ||
							(ig && gs && (!(ifgs = ifgsource_get(ig, gs, 1)) || !ifgsource_ref(ifgs)))) {
		ret = -ENOMEM;
		goto out;
	}

	if(tb[CONF_G_PIM]) {
		if(gs) {
			L_INFO("Set configuration of gsource "GSOURCE_L" - pim_join_desired : %s", GSOURCE_LA(gs), PIM_STATE_STR(join));
			if(!gs->conf_join_desired)
				gsource_ref(gs);
			gs->conf_join_desired = join;
			pim_gsource_conf_changed(pim, gs);
			if(!gs->conf_join_desired)
				gsource_unref(gs);
		} else {
			L_INFO("Set configuration of group "GROUP_L" - pim_join_desired : %s", GROUP_LA(g), PIM_STATE_STR(join));
			if(!g->conf_join_desired)
				group_ref(g);
			g->conf_join_desired = join;
			pim_group_conf_changed(pim, g);
			if(!g->conf_join_desired)
				group_unref(g);
		}
	}

	if(tb[CONF_G_LOCAL]) {
		L_INFO("Set configuration of ifgroup "IFGROUP_L" - local_exclude : %d", IFGROUP_LA(ig), (local == PIM_PRUNE));
		if(!ig->conf_local_exclude)
			ifgroup_ref(ig);
		ig->conf_local_exclude = !!(local == PIM_PRUNE);
		pim_ifgroup_conf_changed(pim, ig);
		if(!ig->conf_local_exclude)
			ifgroup_unref(ig);
	}

	if (tb[CONF_G_LISTENER]) {
		if(ifgs) {
			listener_update_G_S(ifgs, LISTENER_CONF, listen == PIM_JOIN, listen == PIM_PRUNE);
		} else {
			listener_update_G(ig, LISTENER_CONF, listen == PIM_PRUNE);
		}
	}

out:
	if(ifgs)
		ifgsource_unref(ifgs);
	if(gs)
		gsource_unref(gs);
	if(ig)
		ifgroup_unref(ig);
	if(g)
		group_unref(g);
	if(s)
		source_unref(s);
	if(i)
		iface_unref(i);
	return ret;
}

enum{
	CONF_PROXY_ADDR,
	CONF_PROXY_PORT,
	CONF_PROXY_MAX
};
const struct blobmsg_policy conf_proxy_attrs[CONF_PROXY_MAX]={
		[CONF_PROXY_ADDR]={.name="addr",.type=BLOBMSG_TYPE_STRING},
		[CONF_PROXY_PORT]={.name="port",.type=BLOBMSG_TYPE_INT32},
};

static int conf_proxy_mod(conf conf, char *data, size_t len, __unused struct blob_buf *reply, bool del)
{
	struct blob_attr* tb[CONF_PROXY_MAX];
	int iport;
	const char* saddr;
	struct in6_addr addr;

	if (blobmsg_parse(conf_proxy_attrs, CONF_PROXY_MAX, tb, data, len))
		return -1;

	if(!tb[CONF_PROXY_ADDR] || !tb[CONF_PROXY_PORT] ||
			!(saddr = blobmsg_get_string(tb[CONF_PROXY_ADDR])) ||
			!(iport = blobmsg_get_u32(tb[CONF_PROXY_PORT])))
		return -EINVAL;
	if(!(addr_pton(&addr, saddr)) || iport >= 65535 || iport <= 0)
		return -EINVAL;

	if(del) {
		pim_ctl_del_proxy(conf->pim, &addr, (in_port_t) iport);
	} else {
		pim_ctl_add_proxy(conf->pim, &addr, (in_port_t) iport);
	}
	return 0;
}

static int conf_proxy_add(struct ipc_user *u, char *data, size_t len, __unused struct blob_buf *reply)
{
	return conf_proxy_mod(container_of(u, conf_s, ipc_users[CONF_IPC_PROXY_ADD]), data, len, reply, false);
}

static int conf_proxy_del(struct ipc_user *u, char *data, size_t len, __unused struct blob_buf *reply)
{
	return conf_proxy_mod(container_of(u, conf_s, ipc_users[CONF_IPC_PROXY_DEL]), data, len, reply, true);
}

static struct ipc_user users[CONF_IPC_USERS_MAX] = {
		[CONF_IPC_LINK_SET] =   {.command = "link_set", .cb = conf_link_set},
		[CONF_IPC_RPA_ADD] =    {.command = "rpa_add", .cb = conf_rpa_add},
		[CONF_IPC_RPA_DEL] =    {.command = "rpa_del", .cb = conf_rpa_del},
		[CONF_IPC_RPA_FLUSH] =  {.command = "rpa_flush", .cb = conf_rpa_flush},
		[CONF_IPC_RPA_SET] =    {.command = "rpa_set", .cb = conf_rpa_set},
		[CONF_IPC_PROXY_ADD] =  {.command = "proxy_add", .cb = conf_proxy_add},
		[CONF_IPC_PROXY_DEL] =  {.command = "proxy_del", .cb = conf_proxy_del},
		[CONF_IPC_GROUP_SET] =  {.command = "group_set", .cb = conf_group_set},
};

void conf_init(conf conf, ifgroups igs, pim pim, ipc ipc)
{
	conf->igs = igs;
	conf->pim = pim;
	conf->ipc = ipc;
	memcpy(&conf->ipc_users, users, CONF_IPC_USERS_MAX*sizeof(struct ipc_user));
	int i;
	for(i=0; i<CONF_IPC_USERS_MAX; i++) {
		ipc_add_user(ipc, &conf->ipc_users[i]);
	}
}
