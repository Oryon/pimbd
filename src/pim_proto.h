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
 * Network specific PIM elements.
 */

#ifndef PIM_PROTO_H_
#define PIM_PROTO_H_

#include <netinet/in.h> //struct in6_addr
#include <stdbool.h> //bool

extern struct in6_addr pp_all_routers;

#define PP_VERSION 2

#define PP_HELLO_PERIOD_MS (30 * PIMBD_TIME_PER_SECOND)
//#define PP_TRIGGERED_HELLO_DELAY_MS (PP_HELLO_PERIOD_MS / 6)
#define PP_DR_PRIORITY 1
#define PP_HOLDTIME_DEFAULT_S ((uint16_t) 105)
#define PP_HOLDTIME_MAX_S 0xffff
#define PP_DFE_OFFER_PERIOD_MS 100
#define PP_DFE_BACKOFF_PERIOD_MS 1000
#define PP_DFE_ROBUSTNESS 3
#define PP_OVERRIDE_INTERVAL_MS 3000
#define PP_T_PERIODIC_MS 60000
//#define PP_JP_HOLDTIME_S (uint32_t) (PP_T_PERIODIC_S * (3.5))
#define PP_JP_HOLDTIME_MAX 0xffff
#define PP_JP_HOLDTIME_FOREVER_MS (PIMBD_TIME_PER_SECOND * 60 * 60 * 24)

/* This shifter also tests if there is enough space. If not, NULL is returned. */
#define PP_SHIFT(buff, len, shift_len) ((len >= shift_len)?(len -= shift_len, ((void *) (((char *)buff) + shift_len))):(NULL))

enum pp_type {
	PPT_HELLO = 0,
	PPT_REGISTER,
	PPT_REGISTER_STOP,
	PPT_JOIN_PRUNE,
	PPT_BOOTSTRAP,
	PPT_ASSERT,
	PPT_GRAFT,
	PPT_GRAFT_ACK,
	PPT_CANDIDATE_RP,
	PPT_DF_ELECTION = 10
};

struct pp_header {
	uint8_t type;
	uint8_t rsv;
	uint16_t checksum;
} __attribute__((packed));

#define PP_HEADER_TYPE(hdr) ((hdr)->type & 0x0f)
#define PP_HEADER_VERSION(hdr) (((hdr)->type & 0xf0) >> 4)
#define PP_HEADER_SET(hdr, version, t) do {(hdr)->type = (t | ((version)<<4)); (hdr)->rsv = 0;} while(0)
#define PP_HEADER_DATA(hdr, avail) PP_SHIFT(hdr, avail, sizeof(struct pp_header))

enum pp_addr_family {
	PP_FAMILY_IP = 1,
	PP_FAMILY_IP6 = 2,
};

enum pp_encoding {
	PP_ENCODING_NATIVE = 0
};

struct pp_addr {
	uint8_t family;
	uint8_t encoding;
	uint8_t addr[];
} __attribute__((packed));

void pp_addr_set(struct pp_addr *a, const struct in6_addr *addr);
int pp_addr_get(struct in6_addr *addr, const struct pp_addr *a);
#define PP_ADDR_LEN(a) (((a)->family == PP_FAMILY_IP)?(6):(((a)->family == PP_FAMILY_IP6)?18:INT32_MAX))
#define PP_ADDR_SHIFT(a, len) ((len < sizeof(struct pp_addr))?NULL:PP_SHIFT(a, len, PP_ADDR_LEN(a)))

struct pp_group {
	uint8_t family;
	uint8_t encoding;
	uint8_t flags;
	uint8_t masklen;
	uint8_t addr[];
} __attribute__((packed));

int pp_group_get(struct in6_addr *addr, uint8_t *plen, const struct pp_group *g);
void pp_group_set(struct pp_group *g, const struct in6_addr *addr, uint8_t plen, uint8_t flags);

#define PP_GROUP_FLAG_BIDIR 0x80
#define PP_GROUP_FLAG_ADMIN 0x01
#define PP_GROUP_BIDIR(group) ((group)->flags & PP_GROUP_FLAG_BIDIR)
#define PP_GROUP_ADMIN(group) ((group)->flags & PP_GROUP_FLAG_ADMIN)
#define PP_GROUP_LEN(g) (((g)->family == PP_FAMILY_IP)?(8):(((g)->family == PP_FAMILY_IP6)?20:INT32_MAX))
#define PP_GROUP_SHIFT(g, len) ((len < sizeof(struct pp_group))?NULL:PP_SHIFT(g, len, PP_GROUP_LEN(g)))

struct pp_source {
	uint8_t family;
	uint8_t encoding;
	uint8_t flags;
	uint8_t masklen;
	uint8_t addr[];
} __attribute__((packed));

#define PP_SOURCE_FLAG_SPARSE 0x04
#define PP_SOURCE_FLAG_WILDCARD 0X02
#define PP_SOURCE_FLAG_RPT 0x01
#define PP_SOURCE_SPARSE(source) ((source)->flags & PP_SOURCE_FLAG_SPARSE)
#define PP_SOURCE_WILDCARD(source) ((source)->flags & PP_SOURCE_FLAG_WILDCARD)
#define PP_SOURCE_RPT(source) ((source)->flags & PP_SOURCE_FLAG_RPT)

#define pp_source_get(addr, plen, source) pp_group_get(addr, plen, (struct pp_group *)source)
#define pp_source_set(source, addr, plen, flags) pp_group_set((struct pp_group *)source, addr, plen, flags)
#define PP_SOURCE_LEN(s) PP_GROUP_LEN(s)
#define PP_SOURCE_SHIFT(s, len) PP_GROUP_SHIFT(s, len)

/* Hello message */
struct pp_hello_opt {
	uint16_t type;
	uint16_t length;
	uint8_t value[];
} __attribute__((packed));

#define PPH_OPT_SET(opt, t, opt_len) \
	do { (opt)->type = htons(t); (opt)->length = htons(opt_len); } while(0)
#define PPH_OPT_LENGTH(opt) ntohs((opt)->length)
#define PPH_OPT_TYPE(opt) ntohs((opt)->type)
#define PPH_OPT_TOT_LENGTH(opt) (sizeof(struct pp_hello_opt) + PPH_OPT_LENGTH(opt))
#define PPH_OPT_DATA(opt) (void *) (opt)->value
#define PPH_OPT_OK(opt, avail) ((avail >= sizeof(struct pp_hello_opt)) && (avail >= PPH_OPT_TOT_LENGTH(opt)))
#define PPH_OPT_NEXT(opt, avail) PP_SHIFT(opt, avail, PPH_OPT_TOT_LENGTH(opt))


enum pp_hello_type {
	PPHT_HOLDTIME = 1,
	PPHT_LAN_PRUNE_DELAY,
	PPHT_DR_PRIORITY = 19,
	PPHT_GENERATION_ID,
	PPHT_BIDIR_CAP = 22,
	PPHT_ADDRESS_LIST = 24,
	PPHT_SSBIDIR_CAP = 62372 //Chosen randomly
} __attribute__((packed));

struct pp_hello_holdtime {
	uint16_t holdtime;
} __attribute__((packed));

#define PPH_HT_SET(ht, val) ((ht)->holdtime = htons(val))
#define PPH_HT_GET(ht) ntohs((ht)->holdtime)

struct pp_hello_lpd {
	uint16_t __f;
	uint16_t override_interval;
} __attribute__((packed));

#define PPH_LPD_T(hello_lpd) (ntohs((hello_lpd)->__f) & 0x8000)
#define PPH_LPD_PROPAGINT(hello_lpd) (ntohs((hello_lpd)->__f) & (~0x8000))
#define PPH_LPD_SET(hello_lpd, t, propagint) ((hello_lpd)->__f = htons(((t)?0x8000:0) | (propagint & (~0x8000))))

struct pp_hello_drp {
	uint32_t priority;
} __attribute__((packed));

#define PPH_DRP_SET(drp, prio) (drp)->priority = htonl(prio)
#define PPH_DRP_GET(drp) ntohl((drp)->priority)

struct pp_hello_genid {
	uint32_t genid;
} __attribute__((packed));

#define PPH_GENID_SET(g, id) (g)->genid = htonl(id)
#define PPH_GENID_GET(g) ntohl((g)->genid)

struct pp_hello_addrlist {
	struct pp_addr addresses[1];
} __attribute__((packed));


/* join/prune */
struct pp_jp_group {
	uint16_t n_joined;
	uint16_t n_pruned;
} __attribute__((packed));

#define PP_JP_GROUP_JOINED(g) (ntohs(g->n_joined))
#define PP_JP_GROUP_PRUNED(g) (ntohs(g->n_pruned))
#define PP_JP_GROUP_SET(g, joined, pruned) do {(g)->n_joined = htons(joined);(g)->n_pruned = htons(pruned); } while(0)

struct pp_jp {
	uint8_t rsv;
	uint8_t num_groups;
	uint16_t hold_time;
} __attribute__((packed));

#define PP_JP_HOLDTIME_GET(jp) (htons((jp)->hold_time))
void pp_jp_set(struct pp_jp *jp, uint8_t num_groups, uint16_t hold_time);

/* assert */
struct pp_assert {
	struct pp_source source;
	uint32_t __f;
	uint32_t metric;
} __attribute__((packed));

#define PP_ASSERT_RPT(assert) (ntohl((assert)->__f) & 0x80000000)
#define PP_ASSERT_METRIC_PREF(assert) (ntohl((assert)->__f) & (~0x80000000))
#define PP_ASSERT_SET(assert, rpt, metric_pref) \
		((assert)->__f = ntohl((((assert)->__f)?0x80000000:0) | (metric_pref & (~0x80000000))))


/* DF Election */
#define PP_DF_SUBTYPE(hdr) (hdr->rsv >> 4)
#define PP_DF_HEADER_SET(hdr, subtype) do {PP_HEADER_SET(hdr, PP_VERSION, PPT_DF_ELECTION); hdr->rsv = subtype << 4;} while(0)

/* DF Election header */
enum pp_df_type {
	PP_DFT_OFFER = 1,
	PP_DFT_WINNER,
	PP_DFT_BACKOFF,
	PP_DFT_PASS
};

struct pp_df_metric {
	uint32_t preference;
	uint32_t metric;
} __attribute__((packed));

#define PP_DF_METRIC_L "%"PRIx32":%"PRIx32
#define PP_DF_METRIC_LA(m) (m)->preference, (m)->metric
#define PP_DF_METRIC_SET(s, pref, met) do {(s)->preference = htonl(pref); (s)->metric = htonl(met);} while(0)
#define PP_DF_METRIC_IS_INFINITE(m) ((m)->preference == UINT32_MAX && (m)->metric == UINT32_MAX)
int pp_df_metric_cmp(struct pp_df_metric *m1, struct in6_addr *s1,
		struct pp_df_metric *m2, struct in6_addr *s2);

struct pp_df_hdr {
	struct pp_df_metric sender_metric;
} __attribute__((packed));

struct pp_df_backoff {
	struct pp_df_metric offer_metric;
	uint16_t interval;
} __attribute__((packed));

#define PP_DF_BACKOFF_INTERVAL(b) ntohs((b)->interval)
#define PP_DF_BACKOFF_INTERVAL_SET(b, i) (b)->interval = htons(i)

struct pp_df_pass {
	struct pp_df_metric new_metric;
} __attribute__((packed));

#endif /* PIM_PROTO_H_ */
