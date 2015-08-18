/*
 * Author: Pierre Pfister <pierre pfister@darou.fr>
 *
 * Copyright (c) 2015 Pierre Pfister
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:

 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef UTILS_H_
#define UTILS_H_

#include <string.h>
#include <netinet/in.h>
#include <alloca.h>
#include <stdlib.h>

/* Maps a v4 address into a v6 address.
 * Returns dst. */
struct in6_addr *addr_map(struct in6_addr *dst, const struct in_addr *v4addr);

/* Unmaps a v4mapped address into a v4 address.
 * Doesn't check if the address actually is a mapped address.
 * Returns dst. */
struct in_addr *addr_unmap(struct in_addr *dst, const struct in6_addr *v4mapped);

struct in_addr *prefix_unmap(struct in_addr *dst, uint8_t *dst_plen, const struct in6_addr *v4mapped, uint8_t plen);

#define addr_ismapped(addr) (((uint64_t *)addr)[0] == 0 && ((uint32_t *)addr)[2] == htonl(0x0000ffff))

#define prefix_ismapped(addr, plen) (plen >= 96 && addr_ismapped(addr))

#define addr_cpy(dst, src) memcpy(dst, src, sizeof(struct in6_addr))

#define addr_get(family, dst, src) ((family == AF_INET)?addr_map(dst, src):addr_cpy(dst, src))

int addr_cmp(const struct in6_addr *a1, const struct in6_addr *a2);

/* Parses a string representing an address into an address structure.
 * Returns 1 on success, 0 on error (Just like inet_pton...).*/
int addr_pton(struct in6_addr *addr, const char *src);

/* Writes address representation into a string.
 * dst should be at least of size INET6_ADDRSTRLEN to be safe.
 * Returns dst. */
const char *addr_ntop(char *dst, size_t bufflen, const struct in6_addr *addr);

#define addr_is_multicast(addr) (IN6_IS_ADDR_V4MAPPED(addr)?IN_MULTICAST(ntohl((addr)->s6_addr32[3])):IN6_IS_ADDR_MULTICAST(addr))

/* Writes prefix representation into a string. */
const char *prefix_ntop(char *dst, size_t bufflen, const struct in6_addr *addr, uint8_t plen);

/* Parses a string in order to obtain a prefix. If not prefix length is specified, 128 is used. */
struct in6_addr *prefix_pton(struct in6_addr *addr, uint8_t *plen, const char *str);

struct in6_addr *prefix_map(struct in6_addr *dst, uint8_t *dst_plen, const struct in_addr *p, uint8_t plen);

struct in6_addr *prefix_can(struct in6_addr *dst, uint8_t *dst_plen, const struct in6_addr *p, uint8_t plen);

int prefix_cmp(const struct in6_addr *p1, uint8_t plen1, const struct in6_addr *p2, uint8_t plen2);

#define prefix_cpy(dst, dst_len, src, src_len) do {dst_len = src_len; memcpy(dst, src, ((src_len - 1) >> 3) + 1);} while(0)

uint8_t prefix_match(const struct in6_addr *p, uint8_t plen, const struct in6_addr *addr);

uint8_t prefix_contains(const struct in6_addr *p, uint8_t plen, const struct in6_addr *addr);

#define prefix_contains_p(p1, plen1, p2, plen2) (plen1 <= plen2 && prefix_contains(p1, plen1, p2))

#define prefix_get(family, dst, dst_plen, src, plen) (((family) == AF_INET)?prefix_map(dst, dst_plen, src, plen):prefix_can(dst, dst_plen, src, plen))

/* Helper for printing addresses. */
#define ADDR_REPR(addr) addr_ntop(alloca(INET6_ADDRSTRLEN), INET6_ADDRSTRLEN, addr)

#define PREFIX_REPR(p, plen) (plen?prefix_ntop(alloca(INET6_ADDRSTRLEN + 4), INET6_ADDRSTRLEN + 4,  p, plen):"::/0")


int bool_pton(const char *str);

#define rand_i(min, max) (min + (((double) rand())/RAND_MAX)*(max - min))

#endif /* UTILS_H_ */
