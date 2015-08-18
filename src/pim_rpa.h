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
 * RPA management and DFE elections.
 */

#ifndef PIM_RPA_H_
#define PIM_RPA_H_

#include <netinet/in.h>
#include <libubox/vlist.h>

#include "pim.h"
#include "pim_neigh.h"
#include "ifgroup.h"
#include "pim_proto.h"
#include "rib.h"

typedef struct pim_dfe_struct  *pim_dfe, pim_dfe_s;

/* Represents a rendez-vous point address entry.
 * An RPA is associated with one or multiple groups. */
typedef struct pim_rpa_struct {
	struct avl_node ne;      //Linked in pim structure
	struct in6_addr addr;    //The RP address
	struct list_head groups; //List of associated group ranges
	pim_dfe dfes[PIM_N_IFACES + 1]; //Associated dfes (for running ifaces, NULL otherwise)
	rib_entry path;          //Used rib entry toward rpa
	pim_dfe dfe;             //Upstream election
	bool running;            //Whether this rpa is active (dfe created for each interface)

	//Configuration
	bool rpl_jp;             //Whether we should send PIM J/P on the rpl

} *pim_rpa, pim_rpa_s;

/* Represents a group range as multicast address
 * prefix. */
typedef struct group_range_struct {
	struct list_head le;   //Linked in the pim_rpa
	struct in6_addr group; //Group range address
	uint8_t len;           //Group range length
	bool to_delete;        //Used in update process
	pim_rpa rpa;           //The linked rpa
} *group_range, group_range_s;

/* Each RPA requires an election state for each interface. */
struct pim_dfe_struct {
	pim_rpa rpa;               //The associated rpa
	iface iface;               //The associated iface
	enum pim_dfe_mod {
		PIM_DFEM_NONE = 0,      //Disabled
		PIM_DFEM_ELECTION,      //BIDIR Election mod
		PIM_DFEM_RPL_PASSIVE,   //Iface is RPL, send nothing
		PIM_DFEM_RPL_ACTIVE,    //Iface is RPL, send JP to RPA
	} mod;
	enum pim_dfe_state {       //The election state
		PIM_DFE_OFFER,         //Offering a route
		PIM_DFE_LOSE,          //Lost, not DF
		PIM_DFE_WIN,           //Winner, is the DF
		PIM_DFE_BACKOFF,       //Waiting before passing, is the DF
	} state;
	struct uloop_timeout timer;//The election timer
	int message_counter;       //Counts messages

	int is_df;                 //Whether we are df
	pim_neigh best;            //Best offer neighbor (backoff)
	struct pp_df_metric best_metric; //Best offer metric (backoff)
	pim_neigh df;              //The elected neighbor
	struct pp_df_metric df_metric; //The chosen metric

	pim_neigh_s vneigh;    //RPL virtual neighbor, used when mod is RPL_ACTIVE
};

extern const char *pim_dfe_state_str[PIM_DFE_BACKOFF + 1];
extern const char *pim_dfe_mod_str[PIM_DFEM_RPL_ACTIVE + 1];

/* Initializes the rpa subsystem. */
int pim_rpa_init(pim p);

/* Called when pim_rpa must start and stop using an iface */
int pim_rpa_iface_setup(iface i);
void pim_rpa_iface_teardown(iface i);

/* Called whenever a rib entry is added or deleted */
void pim_rpa_rib_update(pim p, rib_entry e, int del);

/* Called when a DF election message is received on an active interface */
void pim_dfe_rcv(iface i, uint8_t *buff, size_t len, struct in6_addr *from);

/* Called whenever a neighbor fails */
void pim_rpa_dead_neighbor(pim p, pim_neigh neigh);

/* Called whenever a new neighbor is heard */
void pim_rpa_new_neighbor(pim_neigh neigh);

/* Called when the first hello was sent.
 * RFC states election starts immediately (move to offer and start sending).
 * Sending interval is Offer_Period = 100ms, whereas the first hello is sent
 * after a randomized time up to Triggered_Hello_Delay = 5s (default).
 * We improve that by blocking election until a first hello is sent. */
void pim_rpa_sent_first_hello(iface i);

/* Returns the group range (linked to rpa) associated with the given group */
pim_rpa pim_rpa_find(pim p, const struct in6_addr *group, uint8_t masklen);

#define pim_dfe_find(i, rpa) ((rpa)->dfes[(i)->pim.pim_index])

/* API for getting groups rpa and ifgroups dfes */
pim_rpa pim_rpa_get_update(pim p, group g);
#define pim_rpa_get(pi, g) (((g)->pim_rpa_set)?(g)->pim_rpa:pim_rpa_get_update(pi, g))

//pim_rpa_get() must have been called before
#define pim_dfe_get(ifg) (((ifg)->group->pim_rpa)?pim_dfe_find((ifg)->iface, (ifg)->group->pim_rpa):NULL)

/* RPA configuration can be incremental or complete.
 * After update is called, flush will remove all mappings
 * that haven't been added. */
void pim_rpa_update(pim p, struct in6_addr *rpa);
int pim_rpa_add(pim p, struct in6_addr *rpa, const struct in6_addr *group, uint8_t len);
void pim_rpa_del(pim p, struct in6_addr *rpa, const struct in6_addr *group, uint8_t len);
void pim_rpa_flush(pim p, struct in6_addr *rpa);

/* Sets whether we should send J/P messages on the rplink. */
int pim_rpa_set_rpl_jp(pim p, struct in6_addr *rpa, bool rpl_jp);

#define pim_for_each_rpa(p, rpa) avl_for_each_element(&(p)->rpas, rpa, ne)

#define pim_for_each_group_range(rpa, g) list_for_each_entry(g, &(rpa)->groups, le)

extern pim_if_t __pim_rpa_index;
extern pim_dfe __pim_rpa_dfe;
extern pim_rpa __pim_rpa_rpa;

#define pim_for_each_dfe_in_rpa(rpa, dfe) \
		for(__pim_rpa_index = 1; __pim_rpa_index <= PIM_N_IFACES; __pim_rpa_index++) \
			if((dfe = (rpa)->dfes[__pim_rpa_index])) //This iterator is safe

#define PIM_RPA_OIFINDEX(rpa) ((int) ((rpa && rpa->path)?rpa->path->oif:-1))

#define RPA_L "rpa %s"
#define RPA_LA(rpa) ADDR_REPR(&(rpa)->addr)

#define DFE_L "dfe %s%%%s"
#define DFE_LA(dfe) ADDR_REPR(&((dfe)->rpa)->addr), (dfe)->iface->ifname

#endif /* PIM_RPA_H_ */
