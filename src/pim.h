/*
 * Authors: Pierre Pfister <pierre pfister at darou.fr>
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
 * PIM specific sub-processes are started and managed by this.
 */

#ifndef PIM_H_
#define PIM_H_

#include <libubox/uloop.h>
#include <libubox/avl.h>

#include "rib.h"
#include "mrib.h"
#include "querier.h"

typedef uint8_t pim_if_t;
#define PIM_N_IFACES 10 //Maximum number of running PIM interfaces

typedef struct pim_neigh_struct *pim_neigh;
typedef struct pim_struct *pim, pim_s;

/* PIM state for each iface. */
typedef struct pim_iface_struct {
	pim p;
	enum {
		PIM_IF_NONE = 0,
		PIM_IF_TRYING,
		PIM_IF_READY,
	} state;

	/* When state is READY, pim_index is a unique interface index between 1 and PIM_N_IFACES.
	 * Tt is 0 otherwise. */
	pim_if_t pim_index;

	struct uloop_timeout timer;
	struct uloop_fd socket;
	bool ssbidir_neighs; //all neighbors are ssbidir capable

	struct {
		struct list_head neighs;  //List containing neighbors
		struct uloop_timeout hto; //Hello sending timer
		struct uloop_timeout thto;//Triggered hello timer
		uint32_t genid;           //Random generation id
		int hello_counter;        //Number of sent hellos since pim enabled on the interface
	} neigh;

	struct list_head rpa_vneighs; //Virtual neighbors (One per rpa and iface)

	struct mrib_user mrib_user; //Iface's mrib interface
	struct querier_user_iface querier_user; //For receiving callbacks about groups

} *pim_iface, pim_iface_s;

#define PIM_IF_CAN_SETUP(i) (!((~(i)->flags) & (IFACE_FLAG_PIM | IFACE_FLAG_EXISTS | IFACE_FLAG_UP | IFACE_FLAG_LLADDR)))
#define PIM_IF_SSBIDIR(i) ((i)->flags & IFACE_FLAG_SSBIDIR)
#define PIM_IF_RUNNING(i) ((i)->pim.state == PIM_IF_READY)

typedef struct pim_rpa_struct *pim_rpa;

typedef struct pim_dfe_struct *pim_dfe;

#include "ifgroup.h"
#include "conf.h"
#include "rib.h"
#include "pim_rpa.h"

/* Main PIM structure. */
struct pim_struct {
	ifgroups ifgroups;
	conf conf;
	rib rib;
	ifgroups_user_s ifgroups_user;
	rib_user_s rib_user;
	struct avl_tree rpas;
	struct uloop_timeout jp_timer;
	iface ifaces[PIM_N_IFACES + 1];

	//pim_ctl
	struct list_head controllers;
	struct uloop_timeout ctl_timer;
};

#define pim_for_each_ctl(p, ctl) list_for_each_entry(ctl, &(p)->controllers, le)

int pim_init(pim pim, ifgroups ifgroups, conf conf, rib rib);

/* Private to PIM subsystems */

//Press the red button in case of emergency
void pim_iface_reset(pim p, iface i);

int pim_iface_sendto(iface i, void *data, size_t len, struct in6_addr *dst);

#include "ifgroup_s.h"

#endif /* PIM_H_ */
