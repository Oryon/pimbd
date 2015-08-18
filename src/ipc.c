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

#include "ipc.h"

#include <errno.h>
#include <getopt.h>
#include <libubox/blobmsg_json.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "pimbd.h"
#include "utils.h"

#define IPC_RETRY 10000
#define IPC_CLIENTSOCK "/tmp/pimbd-ifconf-%d.sock"

#define IPC_CLIENT_SLEEP_S 1

static int client_tentatives = 4;

enum {
	IPC_COMMAND,
	IPC_ARGS,
	IPC_MAX,
};
const struct blobmsg_policy ipc_attrs[IPC_MAX] = {
	[IPC_COMMAND] = { .name = "command", .type = BLOBMSG_TYPE_STRING },
	[IPC_ARGS] = { .name = "args", .type = BLOBMSG_TYPE_TABLE },
};

enum {
	IPC_REPLY_STATUS,
	IPC_REPLY_INFO,
	IPC_REPLY_DATA,
	IPC_REPLY_MAX,
};
const struct blobmsg_policy ipc_reply_attrs[IPC_REPLY_MAX] = {
	[IPC_REPLY_STATUS] = { .name = "status", .type = BLOBMSG_TYPE_INT32 },
	[IPC_REPLY_INFO] = { .name = "info", .type = BLOBMSG_TYPE_STRING },
	[IPC_REPLY_DATA] = { .name = "data", .type = BLOBMSG_TYPE_TABLE }
};

void *ipc_open_reply(struct blob_buf *res)
{
	return blobmsg_open_table(res, ipc_reply_attrs[IPC_REPLY_DATA].name);
}

static void ipc_handle(ipc ipc, char *data, size_t len,
		struct blob_buf *res)
{
	struct blob_attr *tb[IPC_MAX];
	int status = 0;
	if(blobmsg_parse(ipc_attrs, IPC_MAX, tb, data, len)) {
		status = EILSEQ;
	} else if(!tb[IPC_COMMAND] || !tb[IPC_ARGS]) {
		status = EINVAL;
	} else {
		char found = 0;
		struct ipc_user *u;
		list_for_each_entry(u, &ipc->users, le) {
			if(!strcmp(blobmsg_get_string(tb[IPC_COMMAND]), u->command)) {
				status = -u->cb(u, blobmsg_data(tb[IPC_ARGS]), blobmsg_len(tb[IPC_ARGS]), res);
				found = 1;
				break;
			}
		}
		if(!found)
			status = ENOENT;
	}

	blobmsg_add_u32(res, ipc_reply_attrs[IPC_REPLY_STATUS].name, status);
	blobmsg_add_string(res, ipc_reply_attrs[IPC_REPLY_INFO].name, strerror(status));
	if(status)
		L_WARN("Hanlde IPC request: %d %s", status, strerror(status));
	else
		L_DEBUG("Hanlde IPC request: %d %s", status, strerror(status));
}

static void ipc_rcv(ipc ipc)
{
	char *buff;
	struct sockaddr_un addr;
	int avail;
	socklen_t size = sizeof(addr);

	if(ioctl(ipc->fd.fd, FIONREAD, &avail)) {
		L_WARN("Cannot get receive length");
	} else if (!(buff = malloc(avail))) {
		L_WARN("malloc error");
	} else if((avail = recvfrom(ipc->fd.fd, buff, avail, MSG_DONTWAIT, (struct sockaddr *)&addr, &size)) < 0) {
		L_WARN("recvfrom error %s", strerror(errno));
	} else {
		struct blob_buf res = {NULL, NULL, 0, NULL};
		blobmsg_buf_init(&res);
		ipc_handle(ipc, buff, avail, &res);
		sendto(ipc->fd.fd, blobmsg_data(res.head), blobmsg_len(res.head), 0, (struct sockaddr *)&addr, size);
		blob_buf_free(&res);
	}
}

static void ipc_setup_schedule(ipc ipc)
{
	if(uloop_timeout_set(&ipc->to, IPC_RETRY)) {
		L_ERR("Ouch ! Cannot schedule ipc retry.");
	}
}

static int ipc_setup(ipc ipc)
{
	L_INFO("Setting up ipc");

	struct sockaddr_un addr;
	if((ipc->fd.fd = socket(AF_UNIX, SOCK_DGRAM, 0))<0) {
		L_WARN("Could not open IPC socket: %s", strerror(errno));
		return -1;
	}

	if(strlen(ipc->sockpath) >= sizeof(addr.sun_path)) {
		close(ipc->fd.fd);
		ipc->fd.fd = -1;
		return -1;
	}
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, ipc->sockpath);
	unlink(ipc->sockpath);
	if(bind(ipc->fd.fd, (struct sockaddr *)&addr, sizeof(addr)) ||
			uloop_fd_add(&ipc->fd, ULOOP_READ | ULOOP_EDGE_TRIGGER)) {
		L_WARN("Could not open %s: %s", ipc->sockpath, strerror(errno));
		close(ipc->fd.fd);
		ipc->fd.fd = -1;
		return -1;
	}
	L_INFO("IPC opened at %s", ipc->sockpath);
	return 0;
}

static int ipc_restart(ipc ipc)
{
	if(ipc->fd.fd >= 0) {
		close(ipc->fd.fd);
		ipc->fd.fd = -1;
	}

	if(ipc_setup(ipc)) {
		ipc_setup_schedule(ipc);
		return -1;
	}
	return 0;
}

static void ipc_to_cb(struct uloop_timeout *to)
{
	ipc ipc = container_of(to, ipc_s, to);
	ipc_restart(ipc);
}

static void ipc_fd_cb(struct uloop_fd *fd, unsigned int events)
{
	ipc ipc = container_of(fd, ipc_s, fd);
	if(events & (EPOLLERR | EPOLLHUP)) {
		L_ERR("ipc unix socket error (%u).", events);
		ipc_restart(ipc);
	} else if (events & EPOLLIN) {
		ipc_rcv(ipc);
	} else if(events) {
		L_WARN("Unexpected ipc socket event (%u)", events);
	}
}


int ipc_init(ipc ipc, const char *sockpath)
{
	ipc->sockpath = sockpath;
	ipc->fd.cb = ipc_fd_cb;
	ipc->fd.registered = 0;
	ipc->fd.fd = -1;
	ipc->to.cb = ipc_to_cb;
	ipc->to.pending = 0;
	INIT_LIST_HEAD(&ipc->users);
	return ipc_restart(ipc);
}

void ipc_add_user(ipc ipc, struct ipc_user *user)
{
	L_INFO("Adding ipc command '%s'", user->command);
	list_add(&user->le, &ipc->users);
}

int ipc_client_raw(const struct blob_buf *req,
		const char *serverpath, void **data, size_t *len)
{
	int sock, avail;
	struct sockaddr_un serveraddr = { .sun_family = AF_UNIX };
	struct sockaddr_un clientaddr = { .sun_family = AF_UNIX };
	struct timeval tv = {.tv_sec = 2, .tv_usec = 0};

	if(snprintf(clientaddr.sun_path, sizeof(clientaddr.sun_path), IPC_CLIENTSOCK, getpid())
					> (int) sizeof(serveraddr.sun_path) ||
			snprintf(serveraddr.sun_path, sizeof(serveraddr.sun_path), "%s", serverpath)
					> (int) sizeof(serveraddr.sun_path))
		return -ENAMETOOLONG;

	unlink(clientaddr.sun_path);

	if((sock = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0)
		return -errno;

	if(bind(sock, (struct sockaddr *)&clientaddr, sizeof(clientaddr)) ||
			setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval)) ||
			setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(struct timeval))) {
		close(sock);
		return -errno;
	}

	int tentatives;
	for(tentatives = 0; tentatives < client_tentatives; tentatives++) {
		if(((sendto(sock, blobmsg_data(req->head), blobmsg_len(req->head), MSG_DONTWAIT,
				(struct sockaddr *)&serveraddr, sizeof(serveraddr))) < 0) ||
						(recv(sock, NULL, 0, MSG_PEEK) < 0)  || //Wait for data
						ioctl(sock, FIONREAD, &avail)) {
			if((errno != ECONNREFUSED && errno != EAGAIN) || tentatives == (client_tentatives - 1)) {
				close(sock);
				return -errno;
			}
			L_INFO("%s - Retry in %d seconds", strerror(errno), IPC_CLIENT_SLEEP_S);
			sleep(IPC_CLIENT_SLEEP_S);
		} else {
			break;
		}
	}

	if(!avail) {
		close(sock);
		return -ECONNABORTED;
	}

	if(!(*data = malloc(avail))) {
		close(sock);
		return -ENOMEM;
	}

	if((avail = recv(sock, *data, avail, 0)) < 0) {
		free(*data);
		close(sock);
		return -errno;
	}

	*len = avail;
	return 0;
}

enum {
	IPC_IFCONF_IFNAME,
	IPC_IFCONF_MOD,
	IPC_IFCONF_PIM,
	IPC_IFCONF_QUERIER,
	IPC_IFCONF_PROXY,
	IPC_IFCONF_MAX
};

int ipc_raw(int argc, char *const *argv)
{
	const char *serverpath = IPC_SOCKSERVER;
	log_level = 3;

	int opt;
	while ((opt = getopt(argc, argv, "s:vt:")) != -1) {
		switch (opt) {
		case 's':
			serverpath = optarg;
			break;
		case 'v':
			log_level = 7;
			break;
		case 't':
			client_tentatives = atoi(optarg);
			if(client_tentatives <= 0) {
				L_ERR("Invalid timeout '%s'", optarg);
				return -1;
			}
			break;
		default: /* '?' */
			L_ERR("Unknown option '%c'", opt);
			return -1;
		}
	}
	argc -= optind;
	argv += optind;

	if(argc != 1) {
		L_ERR("You must provide a JSON argument");
		return EINVAL;
	}

	int ret;
	struct blob_buf b = {NULL, NULL, 0, NULL};
	if((ret = -blobmsg_buf_init(&b))) {
		L_ERR("blobmsg_buf_init: %s", strerror(ret));
		return ret;
	}

	if(!blobmsg_add_json_from_string(&b, argv[0])) {
		L_ERR("Can't parse JSON argument '%s'", argv[0]);
		return EINVAL;
	}

	void *res = NULL;
	size_t reslen;
	if((ret = -ipc_client_raw(&b, serverpath, &res, &reslen))) {
		L_ERR("ipc client error: %s", strerror(ret));
		goto blob;
	}

	struct blob_attr *tb[IPC_REPLY_MAX];
	if(blobmsg_parse(ipc_reply_attrs, IPC_REPLY_MAX, tb, res, reslen) ||
			!tb[IPC_REPLY_STATUS]) {
		L_ERR("Invalid reply from ipc_client_raw");
		ret = EBADE;
		goto res;
	}

	uint32_t status = blobmsg_get_u32(tb[IPC_REPLY_STATUS]);
	if(status) {
		const char *msg;
		if(tb[IPC_REPLY_INFO] && (msg = blobmsg_get_string(tb[IPC_REPLY_INFO]))) {
			L_ERR("pimbd returned error %d: %s", status, msg);
		} else {
			L_ERR("pimbd returned error %d", status);
		}
	}
	if(tb[IPC_REPLY_DATA]) {
		char *buf = blobmsg_format_json_indent(tb[IPC_REPLY_DATA], true, true);
		puts(buf);
		free(buf);
	}
	ret = status;

res:
	free(res);
blob:
	blob_buf_free(&b);
	return ret;
}

