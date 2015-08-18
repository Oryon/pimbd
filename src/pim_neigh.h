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
 * PIM neighboring subsystem.
 * Takes care of keeping info about neighbors, send Hellos, etc...
 */

#ifndef PIM_NEIGH_H_
#define PIM_NEIGH_H_

typedef struct pim_neigh_struct *pim_neigh, pim_neigh_s;
#include <libubox/uloop.h>

#include "utils.h"
#include "ifgroup.h"

/* Represents a neighbor */
struct pim_neigh_struct {
	struct list_head le; //Linked in iface
	struct in6_addr addr;
	iface i;
	uint32_t genid;
	uint32_t drp;
	struct uloop_timeout holdto;
	char ssbidir_cap; //ssbidir capable
	char sent_hello; //If a hello was sent when this neighbor existed
	char send_jp; //Used by pim_jp to send updates
};

#include "pim.h"

#define PIM_NEIGH_P "%s%%%s"
#define PIM_NEIGH_PA(neigh) (neigh)?ADDR_REPR(&(neigh)->addr):"NULL", (neigh)?(neigh)->i->ifname:"NULL"

/* Neighboring subsystem is setup when an interface becomes ready. */
int pimn_iface_setup(iface i);

/* Neighboring subsystem is torn down when an interface is not ready
 * anymore. */
void pimn_iface_teardown(iface i);

/* Receive a hello message. */
void pimn_rcv_hello(iface i, uint8_t *data, size_t len, struct in6_addr *src);

/* Returns whether there is more than 1 neighbor */
#define pimn_has2neigh(i) (PIM_IF_RUNNING((i)) && ((i)->pim.neigh.neighs.next->next != &(i)->pim.neigh.neighs))

pim_neigh pimn_neighbor_get(iface i, struct in6_addr *addr);

#define pim_for_each_neigh_in_iface(i, n) list_for_each_entry(n, &(i)->pim.neigh.neighs, le)

/* Send a hello now !*/
int pimn_iface_send_hello(iface i);
/* When we need to send a message to someone, we want to be sure he may have received
 * at least one hello. */
int pimn_send_hello_maybe(pim_neigh n);

#endif /* PIM_NEIGH_H_ */
