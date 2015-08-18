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
 * IPC allows controlling configuration at runtime using a unix socket.
 */


#ifndef IPC_H_
#define IPC_H_

#include <libubox/list.h>
#include <libubox/uloop.h>
#include <libubox/blobmsg.h>

#define IPC_SOCKSERVER "/tmp/pimbd_ipc_server.sock"

struct ipc_struct {
	const char *sockpath;
	struct uloop_fd fd;
	struct uloop_timeout to;
	struct list_head users;
};
typedef struct ipc_struct ipc_s, *ipc;

struct ipc_user {
	struct list_head le;
	const char *command;
	int (*cb)(struct ipc_user *, char *data, size_t len, struct blob_buf *reply);
};

int ipc_init(ipc ipc, const char *sockpath);

void ipc_add_user(ipc ipc, struct ipc_user *);

/* Open and close the data reply array. */
void *ipc_open_reply(struct blob_buf *);
#define ipc_close_reply(buf, cookie) blobmsg_close_table(buf, cookie)

int ipc_raw(int argc, char *const *argv);

#endif /* IPC_H_ */
