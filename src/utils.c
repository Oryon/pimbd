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

#include "utils.h"
#include "pimbd.h"

#include <arpa/inet.h>
#include <stdio.h>

int addr_cmp(const struct in6_addr *a1, const struct in6_addr *a2)
{
	return memcmp(a1, a2, sizeof(struct in6_addr));
}

struct in6_addr *addr_map(struct in6_addr *dst, const struct in_addr *v4addr)
{
	dst->s6_addr32[0] = 0;
	dst->s6_addr32[1] = 0;
	dst->s6_addr32[2] = htonl(0x0000ffff);
	dst->s6_addr32[3] = v4addr->s_addr;
	return dst;
}

struct in_addr *addr_unmap(struct in_addr *dst, const struct in6_addr *v4mapped)
{
	dst->s_addr = v4mapped->s6_addr32[3];
	return dst;
}

struct in_addr *prefix_unmap(struct in_addr *dst, uint8_t *dst_plen, const struct in6_addr *v4mapped, uint8_t plen)
{
	*dst_plen = plen - 96;
	if(plen != 96){
		memcpy(dst, &((uint32_t *)v4mapped)[3], ((plen - 97) >> 3) + 1);
	}
	return dst;
}

int addr_pton(struct in6_addr *addr, const char *src)
{
	struct in_addr v4;
	const char *c = src;
	while(1) {
		switch(*c) {
		case ':':
			goto v6;
		case '.':
			goto v4;
		case '\0':
			return 0;
		}
		c++;
	}

v6:
	return inet_pton(AF_INET6, src, addr);
v4:
	if(inet_pton(AF_INET, src, &v4)) {
		addr_map(addr, &v4);
		return 1;
	}
	return 0;
}

const char *addr_ntop(char *dst, size_t bufflen, const struct in6_addr *addr)
{
	int i = IN6_IS_ADDR_V4MAPPED(addr);
	if(i) {
		return inet_ntop(AF_INET, &addr->s6_addr32[3], dst, bufflen);
	} else {
		return inet_ntop(AF_INET6, addr, dst, bufflen);
	}
}

const char *prefix_ntop(char *dst, size_t bufflen, const struct in6_addr *addr, uint8_t plen)
{
	if(bufflen < 4 || !addr_ntop(dst, bufflen - 4, addr))
		return NULL;

	char *str = dst + strlen(dst);
	if(plen >= 96 && IN6_IS_ADDR_V4MAPPED(addr)) {
		sprintf(str, "/%d", plen - 96);
	} else {
		sprintf(str, "/%d", plen);
	}
	return dst;
}

struct in6_addr *prefix_pton(struct in6_addr *addr, uint8_t *plen, const char *str)
{
	char *slash;
	int i;
	if(!(slash = strchr(str, '/'))) {
		if(!addr_pton(addr, str))
			return NULL;
		*plen = 128;
		return addr;
	} else if(strchr(slash + 1, '/')) {
		return NULL;
	} else {
		char tmp[INET6_ADDRSTRLEN+1];
		if((sscanf(str, "%46[0123456789abcdef:.]/%d", tmp, &i) != 2) ||
				(strlen(tmp) != (size_t)(slash - str)) ||
				!addr_pton(addr, tmp) ||
				i > 128 || i < 0) {
			printf("Parse error %s %d\n", tmp, i);
			return NULL;
		}
		*plen = i;
		if(!strchr(tmp, ':')) { //IPv4
			if(*plen > 32)
				return NULL;
			*plen += 96;
		}
	}
	return addr;
}

struct in6_addr *prefix_map(struct in6_addr *dst, uint8_t *dst_plen, const struct in_addr *p, uint8_t plen)
{
	struct in6_addr v6;
	v6.s6_addr32[0] = 0;
	v6.s6_addr32[1] = 0;
	v6.s6_addr32[2] = htonl(0x0000ffff);
	if(plen)
		v6.s6_addr32[3] = p->s_addr;
	else
		v6.s6_addr32[3] = 0;

	return prefix_can(dst, dst_plen, &v6, plen + 96);
}

struct in6_addr *prefix_can(struct in6_addr *dst, uint8_t *dst_plen, const struct in6_addr *p, uint8_t plen)
{
	uint8_t bytes = plen?(((plen - 1) >> 3) + 1):0;
	*dst_plen = plen;
	plen &= 0x7;
	if(bytes)
		memcpy(dst, p, bytes);
	if(bytes != 16)
		memset(&dst->s6_addr[bytes], 0, 16 - bytes);
	if(plen)
		dst->s6_addr[bytes] = p->s6_addr[bytes] & (0xff << (8 - plen));
	return dst;
}

uint8_t prefix_match(const struct in6_addr *p, uint8_t plen, const struct in6_addr *addr)
{
	int match = 0;
	int i = 0;
	int blen = (plen + 7)>>3;
	for(i = 0; i < blen; i++) {
		if(p->s6_addr[i] != addr->s6_addr[i])
			break;
	}

	match = i<<3;
	if(match >= plen)
		return plen;

	uint8_t xor = p->s6_addr[i] != addr->s6_addr[i];
	i = 0x80;
	while(match < plen) {
		if(xor & i)
			return match;
		match++;
		i>>=1;
	}
	return plen;
}

uint8_t prefix_contains(const struct in6_addr *p, uint8_t plen, const struct in6_addr *addr)
{
	int blen = plen >> 3;
	if(blen && memcmp(p, addr, blen))
		return 0;

	int rem = plen & 0x07;
	if(rem && ((p->s6_addr[blen] ^ addr->s6_addr[blen]) >> (8 - rem)))
		return 0;

	return 1;
}

int bool_pton(const char *str)
{
	if(!strcmp(str, "1") ||
			!strcmp(str, "true") ||
			!strcmp(str, "enabled") ||
			!strcmp(str, "up") ||
			!strcmp(str, "yes"))
		return 1;

	return 0;
}
