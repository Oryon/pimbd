/*
 * Author: Mohammed Hawari <mohammed at hawari.fr >
 *         Pierre Pfister <pierre.pfister at darou.fr>
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
 * Proxy controller allows the daemon to send subscription
 * state to another router (see pim_proxy.h).
 */


#ifndef PIM_CTL_H_
#define PIM_CTL_H_

#include "pim.h"

#include <libubox/ustream.h>

typedef struct pim_ctl_struct {
	struct list_head le;
	pim pim;
	struct ustream_fd ufd;
	struct in6_addr addr;
	in_port_t port;
	struct uloop_timeout timer;
} pim_ctl_s, *pim_ctl;

/* Add or remove a distant proxy given an address and a port. */
int pim_ctl_add_proxy(pim p, struct in6_addr *a,in_port_t port);
void pim_ctl_del_proxy(pim p, struct in6_addr *a,in_port_t port);

/* Schedule an update for a given group */
void pim_ctl_update(pim p, group g);
void pim_ctl_update_maybe_G(pim p, group g);
void pim_ctl_update_maybe_G_S(pim p, gsource gs);

#define PIM_CTL_L "[%s]:%u"
#define PIM_CTL_LA(ctl) ADDR_REPR(&(ctl)->addr), (ctl)->port

#endif /* PIM_CTL_H_ */
