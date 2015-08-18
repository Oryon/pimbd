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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <linux/mroute.h>
#include <linux/mroute6.h>

#include <libubox/uloop.h>

#include "pimbd.h"
#include "mrib.h"

#define MRIB_DEBUG(...) L_DEBUG(__VA_ARGS__)

struct mrib_route {
	struct list_head head;
	struct in6_addr group;
	struct in6_addr source;
	pimbd_time_t valid_until;
};

struct mrib_iface {
	int ifindex;
	struct list_head users;
	struct list_head routes;
	struct list_head queriers;
	struct uloop_timeout timer;
};

static uint32_t ipv4_rtr_alert = cpu_to_be32(0x94040000);
static struct {
	struct ip6_hbh hdr;
	struct ip6_opt_router rt;
	uint8_t pad[2];
} ipv6_rtr_alert = {
	.hdr = {0, 0},
	.rt = {IP6OPT_ROUTER_ALERT, 2, {0, IP6_ALERT_MLD}},
	.pad = {0, 0}
};


#define DISABLE_ASSERT_EXTENSION
static struct mrib_iface mifs[MAXMIFS] = {};
static struct uloop_fd mrt_fd = { .fd = -1 };
static struct uloop_fd mrt6_fd = { .fd = -1 };
static bool mrib_assert_extension = 0;

#define MRIB_LIFETIME_WITH_EXT (30 * PIMBD_TIME_PER_SECOND)
#define MRIB_LIFETIME_WITHOUT_EXT (5 * PIMBD_TIME_PER_SECOND)

// Unmap IPv4 address from IPv6
static inline void mrib_unmap(struct in_addr *addr4, const struct in6_addr *addr6)
{
	addr4->s_addr = addr6->s6_addr32[3];
}

// Add / delete multicast route
static int mrib_set(const struct in6_addr *group, const struct in6_addr *source,
		struct mrib_iface *iface, mrib_filter dest, bool del)
{
	int status = 0;
	size_t mifid = iface - mifs;
	if (IN6_IS_ADDR_V4MAPPED(group)) {
		struct mfcctl ctl = { .mfcc_parent = mifid };
		mrib_unmap(&ctl.mfcc_origin, source);
		mrib_unmap(&ctl.mfcc_mcastgrp, group);

		if(!del)
			for (size_t i = 0; i < MAXMIFS; ++i)
				if (dest & (1 << i))
					ctl.mfcc_ttls[i] = 1;

		if (setsockopt(mrt_fd.fd, IPPROTO_IP,
				(del) ? MRT_DEL_MFC : MRT_ADD_MFC,
				&ctl, sizeof(ctl)))
			status = -errno;
	} else {
		struct mf6cctl ctl = {
			.mf6cc_origin = {AF_INET6, 0, 0, *source, 0},
			.mf6cc_mcastgrp = {AF_INET6, 0, 0, *group, 0},
			.mf6cc_parent = mifid,
		};

		if(!del)
			for (size_t i = 0; i < MAXMIFS; ++i)
				if (dest & (1 << i))
					IF_SET(i, &ctl.mf6cc_ifset);

		if (setsockopt(mrt6_fd.fd, IPPROTO_IPV6,
				(del) ? MRT6_DEL_MFC : MRT6_ADD_MFC,
				&ctl, sizeof(ctl)))
			status = -errno;
	}

	char groupbuf[INET6_ADDRSTRLEN], sourcebuf[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, group, groupbuf, sizeof(groupbuf));
	inet_ntop(AF_INET6, source, sourcebuf, sizeof(sourcebuf));
	if(del) {
		L_DEBUG("%s: deleting MFC-entry for %s from %s%%%d: %s",
				__FUNCTION__, groupbuf, sourcebuf, iface->ifindex, strerror(-status));
	} else {
		int ifbuf_len = 0;
		char ifbuf[256] = {0};
		for (size_t i = 0; i < MAXMIFS; ++i)
			if (dest & (1 << i))
				ifbuf_len += snprintf(&ifbuf[ifbuf_len], sizeof(ifbuf) - ifbuf_len, " %d", mifs[i].ifindex);


		L_DEBUG("%s: setting MFC-entry for %s from %s%%%d to %s: %s",
				__FUNCTION__, groupbuf, sourcebuf, iface->ifindex, ifbuf, strerror(-status));
	}

	return status;
}


// We have no way of knowing when a source disappears, so we delete multicast routes from time to time
static void mrib_clean(struct uloop_timeout *t)
{
	struct mrib_iface *iface = container_of(t, struct mrib_iface, timer);
	pimbd_time_t now = pimbd_time();
	uloop_timeout_cancel(t);

	struct mrib_route *c, *n;
	list_for_each_entry_safe(c, n, &iface->routes, head) {
		if (c->valid_until <= now || (list_empty(&iface->users) && list_empty(&iface->queriers))) {
			mrib_set(&c->group, &c->source, iface, 0, 1);
			list_del(&c->head);
			free(c);
		} else {
			uloop_timeout_set(t, c->valid_until - now);
			break;
		}
	}
}


// Find MIFID by ifindex
static size_t mrib_find(int ifindex)
{
	size_t i = 0;
	while (i < MAXMIFS && mifs[i].ifindex != ifindex)
		++i;
	return i;
}

static void mrib_notify(struct mrib_iface *iface,
		const struct in6_addr *group, const struct in6_addr *source)
{
	mrib_filter filter = 0;
	struct mrib_user *user;
	char ifname[IFNAMSIZ];
	size_t i;
	struct mrib_route *route, *other;
	struct mrib_iface *found_iface;
	pimbd_time_t lifetime;

	list_for_each_entry(user, &iface->users, head)
		if (user->cb_newsource)
			user->cb_newsource(user, group, source, &filter);

	L_DEBUG("iface->timer.pending: %d", iface->timer.pending);

	found_iface = NULL;
	for(i=0; i<MAXMIFS; i++) {
		if(!mifs[i].ifindex)
			continue;
		list_for_each_entry(route, &mifs[i].routes, head) {
			if (!memcmp(group, &route->group, sizeof(*group)) &&
					!memcmp(source, &route->source, sizeof(*group))) {
				found_iface = &mifs[i];
				goto found;
			}
		}
	}
found:
	L_DEBUG("iface->timer.pending: %d", iface->timer.pending);

	char groupbuf[INET6_ADDRSTRLEN], sourcebuf[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, group, groupbuf, sizeof(groupbuf));
	inet_ntop(AF_INET6, source, sourcebuf, sizeof(sourcebuf));
	L_DEBUG("%s: detected %s multicast source %s for %s on %s(%d)",
			__FUNCTION__, found_iface?(found_iface == iface)?"existing":"unexpected":"new",
					sourcebuf, groupbuf,
					if_indextoname(iface->ifindex, ifname), iface->ifindex);

	lifetime = mrib_assert_extension?MRIB_LIFETIME_WITH_EXT:MRIB_LIFETIME_WITHOUT_EXT;
	if(filter)
		goto set;

	if(!mrib_assert_extension) {
		//We won't receive all wrong-iface notifications.
		//So let's do our best to find one positive answer.
		//That answer is set with short lifetime in case it is wrong.
		for(i=0; i<MAXMIFS; i++) {
			if(!mifs[i].ifindex || &mifs[i] == iface)
				continue;
			list_for_each_entry(user, &mifs[i].users, head)
				if (user->cb_newsource)
					user->cb_newsource(user, group, source, &filter);

			if(filter) {
				iface = &mifs[i];
				goto set;
			}
		}
	}

set:
	if(!found_iface) {
		if(!(route = malloc(sizeof(*route)))) {
			L_ERR("mrib_notify: Memory error !");
			return;
		}
		route->group = *group;
		route->source = *source;
		list_add_tail(&route->head, &iface->routes);
	} else {
		list_move_tail(&route->head, &iface->routes);
	}

	route->valid_until = pimbd_time() + lifetime;
	list_for_each_entry_reverse(other, &iface->routes, head) {
		if(other != route && other->valid_until <= route->valid_until) {
			list_move(&route->head, &other->head);
			break;
		}
	}

	if(route == list_first_entry(&iface->routes, struct mrib_route, head))
		uloop_timeout_set(&iface->timer, lifetime);

	mrib_set(group, source, iface, filter, 0);
}

// Calculate IGMP-checksum
static uint16_t igmp_checksum(const uint16_t *buf, size_t len)
{
	int32_t sum = 0;

	while (len > 1) {
		sum += *buf++;
		sum = (sum + (sum >> 16)) & 0xffff;
		len -= 2;
	}

	if (len == 1) {
		sum += *((uint8_t*)buf);
		sum += (sum + (sum >> 16)) & 0xffff;
	}

	return ~sum;
}

// Receive and handle MRT event
static void mrib_receive_mrt(struct uloop_fd *fd, __unused unsigned flags)
{
	uint8_t buf[9216], cbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];
	char addrbuf[INET_ADDRSTRLEN];
	struct sockaddr_in from;

	while (true) {
		struct iovec iov = {buf, sizeof(buf)};
		struct msghdr hdr = {&from, sizeof(from), &iov, 1, cbuf, sizeof(cbuf), 0};

		ssize_t len = recvmsg(fd->fd, &hdr, MSG_DONTWAIT);
		MRIB_DEBUG("mrib_receive_mrt %d (%d:%s)", (int) len, errno, strerror(errno));
		if (len < 0)
			break;

		struct iphdr *iph = iov.iov_base;
		if (len < (ssize_t)sizeof(*iph))
			continue;

		if (iph->protocol == 0) {
			MRIB_DEBUG("Receiving IPv4 MC packet from kernel");
			// Pseudo IP/IGMP-packet from kernel MC-API
			struct igmpmsg *msg = iov.iov_base;
			struct mrib_iface *iface = NULL;
			if (msg->im_vif < MAXMIFS)
				iface = &mifs[msg->im_vif];

			if (!iface || !iface->ifindex) {
				L_WARN("MRT kernel-message for unknown MIF %i", msg->im_vif);
				continue;
			}

			switch (msg->im_msgtype) {
				case IGMPMSG_WRONGVIF:
				case IGMPMSG_NOCACHE:
				{
					struct in6_addr dst = IN6ADDR_ANY_INIT;
					struct in6_addr src = IN6ADDR_ANY_INIT;
					dst.s6_addr32[2] = cpu_to_be32(0xffff);
					dst.s6_addr32[3] = msg->im_dst.s_addr;
					src.s6_addr32[2] = cpu_to_be32(0xffff);
					src.s6_addr32[3] = msg->im_src.s_addr;
					mrib_notify(iface, &dst, &src);
				}
					break;
				default:
					L_WARN("Unknown MRT kernel-message %i on interface %d",
											msg->im_msgtype, iface->ifindex);
					break;
			}
		} else {
			MRIB_DEBUG("Receiving IGMP packet from kernel");
			// IGMP packet
			if ((len -= iph->ihl * 4) < 0)
				continue;

			int ifindex = 0;
			for (struct cmsghdr *ch = CMSG_FIRSTHDR(&hdr); ch != NULL; ch = CMSG_NXTHDR(&hdr, ch)) {
				if (ch->cmsg_level == IPPROTO_IP && ch->cmsg_type == IP_PKTINFO) {
					struct in_pktinfo *info = (struct in_pktinfo*)CMSG_DATA(ch);
					ifindex = info->ipi_ifindex;
				}
			}

			if (ifindex == 0)
				continue;

			inet_ntop(AF_INET, &from.sin_addr, addrbuf, sizeof(addrbuf));
			struct igmphdr *igmp = (struct igmphdr*)&buf[iph->ihl * 4];

			uint16_t checksum = igmp->csum;
			igmp->csum = 0;

			if (iph->ttl != 1 || len < (ssize_t)sizeof(*igmp) ||
					checksum != igmp_checksum((uint16_t*)igmp, len)) {
				L_WARN("%s: ignoring invalid IGMP-message of type %x from %s on %d",
						__FUNCTION__, igmp->type, addrbuf, ifindex);
				continue;
			}

			uint32_t *opts = (uint32_t*)&iph[1];
			bool alert = (void*)&opts[1] <= (void*)igmp && *opts == ipv4_rtr_alert;
			if (!alert && (igmp->type != IGMP_HOST_MEMBERSHIP_QUERY ||
							(size_t)len > sizeof(*igmp) || igmp->code > 0)) {
				L_WARN("%s: ignoring invalid IGMP-message of type %x from %s on %d",
						__FUNCTION__, igmp->type, addrbuf, ifindex);
				continue;
			}

			ssize_t mifid = mrib_find(ifindex);
			if (mifid < MAXMIFS) {
				struct mrib_querier *q;
				list_for_each_entry(q, &mifs[mifid].queriers, head) {
					if (q->cb_igmp)
						q->cb_igmp(q, igmp, len, &from);
				}
			}
		}
	}
}

// Receive and handle MRT6 event
static void mrib_receive_mrt6(struct uloop_fd *fd, __unused unsigned flags)
{
	uint8_t buf[9216], cbuf[128];
	char addrbuf[INET6_ADDRSTRLEN];
	struct sockaddr_in6 from;

	while (true) {
		struct iovec iov = {buf, sizeof(buf)};
		struct msghdr hdr = {&from, sizeof(from), &iov, 1, cbuf, sizeof(cbuf), 0};

		ssize_t len = recvmsg(fd->fd, &hdr, MSG_DONTWAIT);
		MRIB_DEBUG("mrib_receive_mrt6 %d (%d:%s)", (int) len, errno, strerror(errno));
		if (len < 0)
			break;

		struct mld_hdr *mld = iov.iov_base;
		if (len < (ssize_t)sizeof(*mld))
			continue;

		if (mld->mld_icmp6_hdr.icmp6_type == 0) {
			// Pseudo ICMPv6/MLD-packet from kernel MC-API
			MRIB_DEBUG("Receiving IPv6 MC packet from kernel");
			struct mrt6msg *msg = iov.iov_base;
			struct mrib_iface *iface = NULL;
			if (msg->im6_mif < MAXMIFS)
				iface = &mifs[msg->im6_mif];

			if (!iface || !iface->ifindex) {
				L_WARN("MRT6 kernel-message for unknown MIF %i", msg->im6_mif);
				continue;
			}

			switch (msg->im6_msgtype) {
				case MRT6MSG_WRONGMIF:
				case MRT6MSG_NOCACHE:
					mrib_notify(iface, &msg->im6_dst, &msg->im6_src);
					break;
				default:
					L_WARN("Unknown MRT6 kernel-message %i on interface %d",
											msg->im6_msgtype, iface->ifindex);
					break;
			}
		} else {
			MRIB_DEBUG("Receiving MLD packet from kernel");
			int hlim = 0, ifindex = from.sin6_scope_id;
			bool alert = false;
			for (struct cmsghdr *ch = CMSG_FIRSTHDR(&hdr); ch != NULL; ch = CMSG_NXTHDR(&hdr, ch)) {
				if (ch->cmsg_level == IPPROTO_IPV6 && ch->cmsg_type == IPV6_HOPLIMIT) {
					memcpy(&hlim, CMSG_DATA(ch), sizeof(hlim));
				} else if (ch->cmsg_level == IPPROTO_IPV6 && ch->cmsg_type == IPV6_HOPOPTS &&
						ch->cmsg_len >= CMSG_LEN(sizeof(ipv6_rtr_alert))) {
					uint8_t *option = CMSG_DATA(ch) + sizeof(struct ip6_hbh);
					ssize_t len = (((uint8_t *) ch) + ch->cmsg_len) - option;
					while(len > 0) {
						if(*option != IP6OPT_PAD1 && (len < *(option + 1) + 2)) {
							MRIB_DEBUG("Invalid header option of type %d (optlen=%d, len=%d)",
									(int) *option, (int) *(option + 1), (int)len);
							break;
						}

						if (*option == IP6OPT_ROUTER_ALERT) {
							if(*(option + 1) != 2) {
								MRIB_DEBUG("Malformed Router Alert Option (bad length)");
							} else if (*(option + 2) == 0 && *(option + 3) == IP6_ALERT_MLD) {
								alert = true;
								break;
							} else {
								MRIB_DEBUG("Received Unknown Router Alert %d:%d",
										*(option + 2), *(option + 3));
							}
						}

						if(*option == IP6OPT_PAD1) {
							len--;
							option++;
						} else {
							len -= *(option + 1) + 2;
							option += *(option + 1) + 2;
						}
					}
				}
			}
			inet_ntop(AF_INET6, &from.sin6_addr, addrbuf, sizeof(addrbuf));

			if (!IN6_IS_ADDR_LINKLOCAL(&from.sin6_addr) || hlim != 1 || len < 24 || !alert) {
				L_WARN("mld: ignoring invalid MLD-message of type %d from %s on %d",
						mld->mld_icmp6_hdr.icmp6_type, addrbuf, ifindex);
				continue;
			}

			ssize_t mifid = mrib_find(from.sin6_scope_id);
			if (mifid < MAXMIFS) {
				struct mrib_querier *q;
				list_for_each_entry(q, &mifs[mifid].queriers, head) {
					if (q->cb_mld)
						q->cb_mld(q, mld, len, &from);
				}
			}
		}
	}
}

// Send an IGMP-packet
int mrib_send_igmp(struct mrib_querier *q, struct igmpv3_query *igmp, size_t len,
		const struct in_addr *src, const struct in_addr *dst)
{
	igmp->csum = 0;
	igmp->csum = igmp_checksum((uint16_t*)igmp, len);

	struct sockaddr_in in = {
			.sin_addr = *dst,
			.sin_family = AF_INET
	};

	struct iovec iov[1] = {
			{.iov_base = igmp, .iov_len = len}
	};

	struct in_pktinfo *pkt;
	char buf[CMSG_SPACE(sizeof(*pkt))] = {}; //Init for valgrind
	struct msghdr msg = {
			.msg_iov = iov,
			.msg_iovlen = 1,
			.msg_name = &in,
			.msg_namelen = sizeof(in),
			.msg_control = buf,
			.msg_controllen = sizeof(buf),
	};

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(*pkt));
	cmsg->cmsg_level = IPPROTO_IP;
	cmsg->cmsg_type = IP_PKTINFO;
	pkt = (struct in_pktinfo *)CMSG_DATA(cmsg);
	pkt->ipi_addr = *src;
	pkt->ipi_ifindex = q->iface->ifindex;

	ssize_t s = sendmsg(mrt_fd.fd, &msg, MSG_DONTWAIT);
	return (s < 0) ? -errno : (s < (ssize_t)len) ? -EMSGSIZE : 0;
}

// Send an IGMP-packet
int mrib_send_mld(struct mrib_querier *q, struct mld_hdr *mld, size_t len,
		const struct in6_addr *src, const struct in6_addr *dst)
{
	struct sockaddr_in6 in = {
			.sin6_addr = *dst,
			.sin6_family = AF_INET6,
			.sin6_scope_id = q->iface->ifindex
	};

	struct iovec iov[1] = {
			{.iov_base = mld, .iov_len = len}
	};

	struct in6_pktinfo *pkt;
	char buf[CMSG_SPACE(sizeof(*pkt))] = {}; //Init for valgrind
	struct msghdr msg = {
			.msg_iov = iov,
			.msg_iovlen = 1,
			.msg_name = &in,
			.msg_namelen = sizeof(in),
			.msg_control = buf,
			.msg_controllen = sizeof(buf),
	};

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(*pkt));
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_PKTINFO;
	pkt = (struct in6_pktinfo *)CMSG_DATA(cmsg);
	pkt->ipi6_addr = *src;
	pkt->ipi6_ifindex = q->iface->ifindex;

	ssize_t s = sendmsg(mrt6_fd.fd, &msg, MSG_DONTWAIT);
	return (s < 0) ? -errno : (s < (ssize_t)len) ? -EMSGSIZE : 0;
}

// Initialize MRIB
static int mrib_init(void)
{
	int fd;
	int val;

	if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP)) < 0)
		goto err;

	val = 1;
	if (setsockopt(fd, IPPROTO_IP, MRT_INIT, &val, sizeof(val)))
		goto err;

#ifndef DISABLE_ASSERT_EXTENSION
	val = 2;
	socklen_t len = sizeof(val);
	if (setsockopt(fd, IPPROTO_IP, MRT_ASSERT, &val, sizeof(val)))
		goto err;

	if(getsockopt(fd, IPPROTO_IP, MRT_ASSERT, &val, &len))
		goto err;

	if(val == 2) {//If set to 2, the extension is supported
		L_INFO("mrib_init: Kernel assert extension is supported.");
		mrib_assert_extension = 1;
	} else {
		L_INFO("mrib_init: Kernel assert extension is not supported.");
		mrib_assert_extension = 0;
	}
#endif

	val = 1;
	if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &val, sizeof(val)))
		goto err;

	// Configure IP header fields
	if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &val, sizeof(val)))
		goto err;

	val = 0xc0;
	if (setsockopt(fd, IPPROTO_IP, IP_TOS, &val, sizeof(val)))
		goto err;

	/*val = 0;
	if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &val, sizeof(val)))
		goto err;*/

	// Set router-alert option
	if (setsockopt(fd, IPPROTO_IP, IP_OPTIONS, &ipv4_rtr_alert, sizeof(ipv4_rtr_alert)))
		goto err;

	mrt_fd.fd = fd;


	if ((fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0)
		goto err;

	// We need to know the source interface and hop-opts
	val = 1;
	if (setsockopt(fd, IPPROTO_IPV6, MRT6_INIT, &val, sizeof(val)))
		goto err;

#ifndef DISABLE_ASSERT_EXTENSION
	val = 2;
	if (setsockopt(fd, IPPROTO_IPV6, MRT6_ASSERT, &val, sizeof(val)))
		goto err;

	if(getsockopt(fd, IPPROTO_IPV6, MRT6_ASSERT, &val, &len))
		goto err;

	if((val == 1 && mrib_assert_extension) ||
			(val == 2 && !mrib_assert_extension)) {
		L_ERR("mrib_init: Kernel assert extension is incoherent !");
		goto err;
	}
#endif

	val = 1;
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPOPTS, &val, sizeof(val)))
		goto err;

	if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &val, sizeof(val)))
		goto err;

	// MLD has hoplimit 1
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &val, sizeof(val)))
		goto err;

	//We detect self address now
	/*val = 0;
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &val, sizeof(val)))
		goto err;*/

	// Let the kernel compute our checksums
	val = 2;
	if (setsockopt(fd, IPPROTO_RAW, IPV6_CHECKSUM, &val, sizeof(val)))
		goto err;

	// Set hop-by-hop router alert on outgoing
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_HOPOPTS, &ipv6_rtr_alert, sizeof(ipv6_rtr_alert)))
		goto err;

	// Set ICMP6 filter
	struct icmp6_filter flt;
	ICMP6_FILTER_SETBLOCKALL(&flt);
	ICMP6_FILTER_SETPASS(ICMPV6_MGM_QUERY, &flt);
	ICMP6_FILTER_SETPASS(ICMPV6_MGM_REPORT, &flt);
	ICMP6_FILTER_SETPASS(ICMPV6_MGM_REDUCTION, &flt);
	ICMP6_FILTER_SETPASS(ICMPV6_MLD2_REPORT, &flt);
	if (setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &flt, sizeof(flt)))
		goto err;

	mrt6_fd.fd = fd;

	mrt_fd.cb = mrib_receive_mrt;
	mrt6_fd.cb = mrib_receive_mrt6;

	uloop_fd_add(&mrt_fd, ULOOP_READ | ULOOP_EDGE_TRIGGER);
	uloop_fd_add(&mrt6_fd, ULOOP_READ | ULOOP_EDGE_TRIGGER);

	fd = -1;
	errno = 0;

err:
	if (fd >= 0)
		close(fd);
	return -errno;
}

// Create new interface entry
static struct mrib_iface* mrib_get_iface(int ifindex)
{
	if (mrt_fd.fd < 0 && mrib_init() < 0)
		return NULL;

	size_t mifid = mrib_find(ifindex);
	if (mifid < MAXMIFS)
		return &mifs[mifid];

	errno = EBUSY;
	if ((mifid = mrib_find(0)) >= MAXMIFS)
		return NULL;

	struct mrib_iface *iface = &mifs[mifid];

	struct vifctl ctl = {mifid, VIFF_USE_IFINDEX, 1, 0, { .vifc_lcl_ifindex = ifindex }, {INADDR_ANY}};
	if (setsockopt(mrt_fd.fd, IPPROTO_IP, MRT_ADD_VIF, &ctl, sizeof(ctl)))
		return NULL;

	struct mif6ctl ctl6 = {mifid, 0, 1, ifindex, 0};
	if (setsockopt(mrt6_fd.fd, IPPROTO_IPV6, MRT6_ADD_MIF, &ctl6, sizeof(ctl6)))
		return NULL;

	struct ip_mreqn mreq = {{INADDR_ALLIGMPV3RTRS_GROUP}, {INADDR_ANY}, ifindex};
	setsockopt(mrt_fd.fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

	mreq.imr_multiaddr.s_addr = cpu_to_be32(INADDR_ALLRTRS_GROUP);
	setsockopt(mrt_fd.fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

	struct ipv6_mreq mreq6 = {MLD2_ALL_MCR_INIT, ifindex};
	setsockopt(mrt6_fd.fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq6, sizeof(mreq6));

	mreq6.ipv6mr_multiaddr.s6_addr[15] = 0x02;
	setsockopt(mrt6_fd.fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq6, sizeof(mreq6));

	iface->timer.cb = mrib_clean;
	iface->ifindex = ifindex;
	INIT_LIST_HEAD(&iface->routes);
	INIT_LIST_HEAD(&iface->users);
	INIT_LIST_HEAD(&iface->queriers);
	return iface;
}

// Remove interfaces if it has no more users
static void mrib_clean_iface(struct mrib_iface *iface)
{
	if (list_empty(&iface->users) && list_empty(&iface->queriers)) {
		iface->ifindex = 0;
		mrib_clean(&iface->timer);

		size_t mifid = iface - mifs;
		struct vifctl ctl = {mifid, VIFF_USE_IFINDEX, 1, 0,
				{ .vifc_lcl_ifindex = iface->ifindex }, {INADDR_ANY}};
		setsockopt(mrt_fd.fd, IPPROTO_IP, MRT_DEL_VIF, &ctl, sizeof(ctl));

		struct mif6ctl ctl6 = {mifid, 0, 1, iface->ifindex, 0};
		setsockopt(mrt6_fd.fd, IPPROTO_IPV6, MRT6_DEL_MIF, &ctl6, sizeof(ctl6));

		struct ip_mreqn mreq = {{INADDR_ALLIGMPV3RTRS_GROUP}, {INADDR_ANY}, iface->ifindex};
		setsockopt(mrt_fd.fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));

		mreq.imr_multiaddr.s_addr = cpu_to_be32(INADDR_ALLRTRS_GROUP);
		setsockopt(mrt_fd.fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));

		struct ipv6_mreq mreq6 = {MLD2_ALL_MCR_INIT, iface->ifindex};
		setsockopt(mrt6_fd.fd, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, &mreq6, sizeof(mreq6));

		mreq6.ipv6mr_multiaddr.s6_addr[15] = 0x02;
		setsockopt(mrt6_fd.fd, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, &mreq6, sizeof(mreq6));
	}
}

// Register a new interface to mrib
int mrib_attach_user(struct mrib_user *user, int ifindex, mrib_cb *cb_newsource)
{
	struct mrib_iface *iface = mrib_get_iface(ifindex);
	if (!iface)
		return -errno;

	if (user->iface == iface)
		return -EALREADY;

	list_add(&user->head, &iface->users);
	user->iface = iface;
	user->cb_newsource = cb_newsource;
	return 0;
}

// Deregister an interface from mrib
void mrib_detach_user(struct mrib_user *user)
{
	struct mrib_iface *iface = user->iface;
	if (!iface)
		return;

	user->iface = NULL;
	list_del(&user->head);
	mrib_clean_iface(iface);
}

// Register a querier to mrib
int mrib_attach_querier(struct mrib_querier *querier, int ifindex, mrib_igmp_cb *cb_igmp, mrib_mld_cb *cb_mld)
{
	struct mrib_iface *iface = mrib_get_iface(ifindex);
	if (!iface)
		return -errno;
	list_add(&querier->head, &iface->queriers);
	querier->iface = iface;
	querier->cb_igmp = cb_igmp;
	querier->cb_mld = cb_mld;
	return 0;
}

// Deregister a querier from mrib
void mrib_detach_querier(struct mrib_querier *querier)
{
	struct mrib_iface *iface = querier->iface;
	if (!iface)
		return;

	querier->iface = NULL;
	list_del(&querier->head);
	mrib_clean_iface(iface);
}

static uint8_t prefix_contains(const struct in6_addr *p, uint8_t plen, const struct in6_addr *addr)
{
	int blen = plen >> 3;
	if(blen && memcmp(p, addr, blen))
		return 0;

	int rem = plen & 0x07;
	if(rem && ((p->s6_addr[blen] ^ addr->s6_addr[blen]) >> (8 - rem)))
		return 0;

	return 1;
}

// Flush state for a multicast route
int mrib_flush(struct mrib_user *user, const struct in6_addr *group, uint8_t group_plen, const struct in6_addr *source)
{
	struct mrib_iface *iface = user->iface;
	if (!iface)
		return -ENOENT;

	bool found = false;
	struct mrib_route *route, *n;
	list_for_each_entry_safe(route, n, &iface->routes, head) {
		if (prefix_contains(group, group_plen, &route->group) &&
				(!source || IN6_ARE_ADDR_EQUAL(&route->source, source))) {
			route->valid_until = 0;
			list_del(&route->head);
			list_add(&route->head, &iface->routes);
			found = true;
		}
	}

	if (found)
		mrib_clean(&iface->timer);

	return (found) ? 0 : -ENOENT;
}

// Add an interface to the filter
int mrib_filter_add(mrib_filter *filter, struct mrib_user *user)
{
	struct mrib_iface *iface = user->iface;
	if (!iface)
		return -ENOENT;

	*filter |= 1 << (iface - mifs);
	return 0;
}
