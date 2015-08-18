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

#include "pim_proto.h"

#include "utils.h"
#include "pimbd.h"

struct in6_addr pp_all_routers = {.s6_addr = {0xff,0x02, 0x00,0x00, 0x00,0x00, 0x00,0x00,
												0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x0d}};

void pp_addr_set(struct pp_addr *a, const struct in6_addr *addr)
{
	if(addr_ismapped(addr)) {
		a->family = PP_FAMILY_IP;
		a->encoding = PP_ENCODING_NATIVE;
		addr_unmap((struct in_addr *)a->addr, addr);
	} else {
		a->family = PP_FAMILY_IP6;
		a->encoding = PP_ENCODING_NATIVE;
		addr_cpy(a->addr, addr);
	}
}

int pp_addr_get(struct in6_addr *addr, const struct pp_addr *a)
{
	if(a->encoding != PP_ENCODING_NATIVE)
				return -1;

	switch (a->family) {
		case PP_FAMILY_IP:
			addr_map(addr, (struct in_addr *)a->addr);
			return 0;
		case PP_FAMILY_IP6:
			addr_cpy(addr, a->addr);
			return 0;
		default:
			break;
	}

	return -1;
}

int pp_group_get(struct in6_addr *addr, uint8_t *plen, const struct pp_group *g)
{
	if(g->encoding != PP_ENCODING_NATIVE)
		return -1;

	switch (g->family) {
	case PP_FAMILY_IP:
		prefix_map(addr, plen, (struct in_addr *)&g->addr, g->masklen);
		return 0;
	case PP_FAMILY_IP6:
		prefix_can(addr, plen, (struct in6_addr *)&g->addr, g->masklen);
		return 0;
	default:
		break;
	}

	return -1;
}

void pp_group_set(struct pp_group *g, const struct in6_addr *addr, uint8_t plen, uint8_t flags)
{
	g->encoding = PP_ENCODING_NATIVE;
	if(prefix_ismapped(addr, plen)) {
		g->family = PP_FAMILY_IP;
		prefix_unmap((struct in_addr *)&g->addr, &g->masklen, addr, plen);
	} else {
		g->family = PP_FAMILY_IP6;
		prefix_cpy((struct in6_addr *)&g->addr, g->masklen, addr, plen);
	}
	g->flags = flags;
}

int pp_df_metric_cmp(struct pp_df_metric *m1, struct in6_addr *s1,
		struct pp_df_metric *m2, struct in6_addr *s2)
{
	if(PP_DF_METRIC_IS_INFINITE(m1) &&
			PP_DF_METRIC_IS_INFINITE(m2))
		return 0;

	if(ntohl(m1->preference) < ntohl(m2->preference))
		return 1;
	if(ntohl(m2->preference) < ntohl(m1->preference))
		return -1;
	if(ntohl(m1->metric) < ntohl(m2->metric))
		return 1;
	if(ntohl(m2->metric) < ntohl(m1->metric))
		return -1;

	return s1?memcmp(s1, s2, sizeof(*s1)):0;
}

void pp_jp_set(struct pp_jp *jp, uint8_t num_groups, uint16_t hold_time)
{
	jp->rsv = 0;
	jp->num_groups = num_groups;
	jp->hold_time = htons(hold_time);
}

