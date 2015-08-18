/*
 * Authors: Mohammed Hawari <mohammed at hawari.fr>
 *          Pierre Pfister <pierre pfister at darou.fr>
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
 * Proxy receiver. Receives subscription from controllers
 * and apply the state on proxy interfaces (by mld).
 */

#ifndef PIM_PROXY_H_
#define PIM_PROXY_H_

#include <libubox/ustream.h>

#define PIM_PROXYMSG_KA     1
#define PIM_PROXYMSG_UPDATE 2

#define PIM_PROXY_NOINFO 0
#define PIM_PROXY_JOIN   1
#define PIM_PROXY_PRUNE  2

struct pim_proxy_msg {
	uint16_t type;
	uint16_t length;
	char value[];
} __attribute__((packed));

#include "ifgroup.h"
#include "mrib.h"

typedef struct pim_proxy_struct pim_proxy_s, *pim_proxy;
typedef struct pim_proxy_iface_struct  pim_proxy_iface_s, *pim_proxy_iface;

typedef struct pim_proxy_client_struct {
	uint8_t id; //Place in clients array
	struct in6_addr addr;
	in_port_t port;
	struct ustream_fd ufd; //ustream
	bool hdr_set;
	struct pim_proxy_msg hdr;
} pim_proxy_client_s, *pim_proxy_client;

#define PIM_PROXY_CLIENTS 32
struct pim_proxy_iface_struct {
	pim_proxy p;
	pim_proxy_client_s clients[PIM_PROXY_CLIENTS];
	struct uloop_timeout timer; //Open retry timeout
	struct uloop_fd server_fd; //Socket server TCP
	struct mrib_user mrib_user; //For packet forwarding
};

#include "pim.h"

struct pim_proxy_struct {
	ifgroups igs; //Ifgroups pointer
	pim pim;
	ifgroups_user_s ifgroup_user; //ifgroups user (To get iface callbacks)
};

#define PIM_PROXY_ENABLED(i) ((i)->proxy.server_fd.fd)

void pim_proxy_init(pim_proxy p, ifgroups igs, pim pim);
void pim_proxy_teardown(pim_proxy p);

#define pim_proxy_for_each_client(i, p, client) for(i = 0; i<PIM_PROXY_CLIENTS; i++) if((client = &(p)->clients[i]) && (client)->ufd.fd.fd)

#endif /* PIM_PROXY_H_ */
