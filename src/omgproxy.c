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

#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <net/if.h>
#include <unistd.h>

#include <libubox/uloop.h>
#include <libubox/blobmsg.h>

#include "pimbd.h"
#include "proxy.h"

int log_level = 7;


enum {
	PROXY_ATTR_NAME,
	PROXY_ATTR_SOURCE,
	PROXY_ATTR_SCOPE,
	PROXY_ATTR_BIND,
	PROXY_ATTR_DEST,
	PROXY_ATTR_CONNECT,
	PROXY_ATTR_MAX,
};

static struct blobmsg_policy proxy_policy[PROXY_ATTR_MAX] = {
	[PROXY_ATTR_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
	[PROXY_ATTR_SOURCE] = { .name = "source", .type = BLOBMSG_TYPE_STRING },
	[PROXY_ATTR_SCOPE] = { .name = "scope", .type = BLOBMSG_TYPE_STRING },
	[PROXY_ATTR_BIND] = { .name = "bind", .type = BLOBMSG_TYPE_INT32 },
	[PROXY_ATTR_DEST] = { .name = "dest", .type = BLOBMSG_TYPE_ARRAY },
	[PROXY_ATTR_CONNECT] = { .name = "connect", .type = BLOBMSG_TYPE_ARRAY },
};

static __unused int handle_proxy_unset(void *data, size_t len)
{
	struct blob_attr *tb[PROXY_ATTR_MAX];
	blobmsg_parse(proxy_policy, PROXY_ATTR_MAX, tb, data, len);

	if (!tb[PROXY_ATTR_NAME])
		return -EINVAL;

	return proxy_unset(blobmsg_get_string(tb[PROXY_ATTR_NAME]));
}

static int handle_proxy_set(void *data, size_t len)
{
	struct blob_attr *tb[PROXY_ATTR_MAX], *c;
	blobmsg_parse(proxy_policy, PROXY_ATTR_MAX, tb, data, len);

	if (!(c = tb[PROXY_ATTR_NAME]))
		return -EINVAL;

	const char *name = blobmsg_get_string(c);
	int uplink = 0;
	int port = 0;
	int downlinks[32] = {0};
	size_t downlinks_cnt = 0;
	struct sockaddr_in6 connects[32] = {};
	size_t connects_cnt = 0;
	enum proxy_flags flags = 0;

	if ((c = tb[PROXY_ATTR_SOURCE]) && !(uplink = if_nametoindex(blobmsg_get_string(c)))) {
		L_WARN("proxy_set(%s): %s (%s)", name, strerror(errno), blobmsg_get_string(c));
		return -errno;
	}

	if ((c = tb[PROXY_ATTR_SCOPE])) {
		const char *scope = blobmsg_get_string(c);
		if (!strcmp(scope, "global"))
			flags = PROXY_GLOBAL;
		else if (!strcmp(scope, "organization"))
			flags = PROXY_ORGLOCAL;
		else if (!strcmp(scope, "site"))
			flags = PROXY_SITELOCAL;
		else if (!strcmp(scope, "admin"))
			flags = PROXY_ADMINLOCAL;
		else if (!strcmp(scope, "realm"))
			flags = PROXY_REALMLOCAL;

		if (!flags) {
			L_WARN("proxy_set(%s): invalid scope (%s)", name, scope);
			return -EINVAL;
		}
	}

	if ((c = tb[PROXY_ATTR_BIND])) {
		port = blobmsg_get_u32(c);
		if (port < 1 || port > 65535) {
			L_WARN("proxy_set(%s): invalid port (%d)", name, port);
			return -EINVAL;
		}
	}

	if ((c = tb[PROXY_ATTR_DEST])) {
		struct blob_attr *d;
		unsigned rem;
		blobmsg_for_each_attr(d, c, rem) {
			if (downlinks_cnt >= 32) {
				L_WARN("proxy_set(%s): maximum number of destinations exceeded", name);
				return -EINVAL;
			}

			const char *n = blobmsg_type(d) == BLOBMSG_TYPE_STRING ? blobmsg_get_string(d) : "";
			if (!(downlinks[downlinks_cnt++] = if_nametoindex(n))) {
				L_WARN("proxy_set(%s): %s (%s)", name, strerror(errno), blobmsg_get_string(c));
				return -errno;
			}
		}
	}

	if ((c = tb[PROXY_ATTR_CONNECT])) {
		struct addrinfo *res, hints = {
			.ai_flags = AI_NUMERICHOST | AI_V4MAPPED,
			.ai_family = AF_INET6,
			.ai_socktype = SOCK_STREAM,
			.ai_protocol = IPPROTO_TCP
		};

		struct blob_attr *d;
		unsigned rem;
		blobmsg_for_each_attr(d, c, rem) {
			if (connects_cnt >= 32) {
				L_WARN("proxy_set(%s): maximum number of connections exceeded", name);
				return -EINVAL;
			}

			char *sep, *value = blobmsg_get_string(d);
			if (value[0] != '[' || !(sep = strstr(value, "]:")) || (*sep = 0) ||
					getaddrinfo(&value[1], &sep[2], &hints, &res) || !res) {
				L_WARN("proxy_set(%s): invalid target address: %s", name, value);
				break;
			}

			memcpy(&connects[connects_cnt++], res->ai_addr, sizeof(struct sockaddr_in6));
			freeaddrinfo(res);
		}
	}

	return proxy_set(name, flags, uplink, downlinks, downlinks_cnt, port, connects, connects_cnt);
}

#ifdef WITH_UBUS
#include <libubus.h>

static int handle_ubus(__unused struct ubus_context *ctx, __unused struct ubus_object *obj,
		__unused struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	int status = 0;
	if (!strcmp(method, "set"))
		status = handle_proxy_set(blob_data(msg), blob_len(msg));
	else if (!strcmp(method, "unset"))
		status = handle_proxy_unset(blob_data(msg), blob_len(msg));
	else if (!strcmp(method, "update"))
		proxy_update(false);
	else if (!strcmp(method, "flush"))
		proxy_flush();
	else
		status = UBUS_STATUS_METHOD_NOT_FOUND;

	if (status == -EINVAL)
		status = UBUS_STATUS_INVALID_ARGUMENT;
	else if (status == -ENOENT)
		status = UBUS_STATUS_NOT_FOUND;
	else if (status < 0)
		status = UBUS_STATUS_UNKNOWN_ERROR;

	return status;
}

static struct ubus_method main_object_methods[] = {
	{.name = "set", .handler = handle_ubus},
	{.name = "unset", .handler = handle_ubus},
	{.name = "update", .handler = handle_ubus},
	{.name = "flush", .handler = handle_ubus},
};

static struct ubus_object_type main_object_type =
		UBUS_OBJECT_TYPE("omgproxy", main_object_methods);

static struct ubus_object main_object = {
        .name = "omgproxy",
        .type = &main_object_type,
        .methods = main_object_methods,
        .n_methods = ARRAY_SIZE(main_object_methods),
};

static void setup_ubus()
{
	struct ubus_context *ubus;
	while (!(ubus = ubus_connect(NULL)))
		usleep(100000);
	ubus_add_uloop(ubus);
	ubus_add_object(ubus, &main_object);
}
#endif

static void handle_signal(__unused int signal)
{
	uloop_end();
}

static void usage(const char *arg) {
	fprintf(stderr, "Usage: %s <proxy1> [<proxy2>] [...]\n"
			"\nProxy examples:\n"
			"source=eth1,dest=eth2\n"
			"source=eth1,dest=eth2/eth3,scope=organization\n"
			"source=eth1,dest=eth2,scope=global,bind=1234,connect=[2001:db8::1]:1234\n"
			"\nProxy options (each option may only occur once):\n"
			"	source=<interface>		source interface\n"
			"	dest=<iface1>[/<iface2>][...]	destination interface\n"
			"	scope=<scope>			minimum multicast scope to proxy\n"
			"		[global,organization,site,admin,realm] (default: global)\n"
			"	bind=<port>			create remote server on port\n"
			"	connect=<addr1>[/<addr2>][...]	connect to remote server\n"
			"		IPv6 URL-format e.g. [2001:db80::1]:1234\n\n",
	arg);
}

int main(int argc, char **argv) {
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
	signal(SIGHUP, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	openlog("omgproxy", LOG_PERROR, LOG_DAEMON);

	if (getuid()) {
		L_ERR("must be run as root!");
		return 2;
	}

	uloop_init();
	bool start = true;

	for (ssize_t i = 1; i < argc; ++i) {
		enum {
			OPT_SOURCE,
			OPT_DEST,
			OPT_SCOPE,
			OPT_BIND,
			OPT_CONNECT
		};
		char *const token[] = {
			[OPT_SOURCE] = "source",
			[OPT_DEST] = "dest",
			[OPT_SCOPE] = "scope",
			[OPT_BIND] = "bind",
			[OPT_CONNECT] = "connect",
			NULL
		};

		char *subopts = argv[i], *value;
		struct blob_buf b = {NULL, NULL, 0, NULL};
		blob_buf_init(&b, 0);

		while (*subopts) {
			int opt = getsubopt(&subopts, token, &value);
			if (!value)
				value = "";
			if (opt == OPT_SOURCE) {
				blobmsg_add_string(&b, "source", value);
			} else if (opt == OPT_DEST) {
				void *k = blobmsg_open_array(&b, "dest");
				char *s;
				for (char *c = strtok_r(value, "/", &s); c; c = strtok_r(NULL, "/", &s))
					blobmsg_add_string(&b, NULL, c);
				blobmsg_close_array(&b, k);
			} else if (opt == OPT_SCOPE) {
				blobmsg_add_string(&b, "scope", value);
			} else if (opt == OPT_BIND) {
				blobmsg_add_u32(&b, "bind", atoi(value));
			} else if (opt == OPT_CONNECT) {
				void *k = blobmsg_open_array(&b, "connect");
				char *s;
				for (char *c = strtok_r(value, "/", &s); c; c = strtok_r(NULL, "/", &s))
					blobmsg_add_string(&b, NULL, c);
				blobmsg_close_array(&b, k);
			} else {
				break;
			}
		}

		if (*subopts) {
			fprintf(stderr, "invalid configuration: %s\n\n", argv[i]);
			usage(argv[0]);
			start = false;
		}

		char *buf = blobmsg_alloc_string_buffer(&b, "name", 8);
		snprintf(buf, 8, "proxy%u", (unsigned)i);
		blobmsg_add_string_buffer(&b);

		if (handle_proxy_set(blob_data(b.head), blob_len(b.head))) {
			fprintf(stderr, "failed to setup proxy: %s\n", argv[i]);
			start = false;
		}

		blob_buf_free(&b);
	}

#ifdef WITH_UBUS
	setup_ubus();
#else
	if (argc < 2) {
		usage(argv[0]);
		start = false;
	}
#endif

	if (start)
		uloop_run();

	proxy_update(true);
	proxy_flush();

	uloop_done();
	return 0;
}
