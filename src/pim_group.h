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
 * Group specific state machines.
 * Keeps upstream and link join/prune states
 */

#include "pim.h"

#ifndef PIM_GROUP_H_
#define PIM_GROUP_H_

/*
 * Called by pim.c
 */

/* We received a Join/Prune message */
void pim_group_rcv_joinprune(iface i, const uint8_t *buff, size_t len, struct in6_addr *from);

/* The SSBIDIR flag conf changes for some interface */
void pim_group_ssbidir_changed(iface i);

/* Interface control */
int pim_group_iface_setup(iface i);
void pim_group_iface_start(pim p, iface i);
void pim_group_iface_teardown(iface i);

/* Configures a rib entry based on PIM rules */
void pim_mrib_forward_upstream(pim p, iface inc,
		gsource gs, mrib_filter *filter);
void pim_mrib_forward_downstream(iface inc,
		gsource gs, mrib_filter *filter);

/*
 * Functions called by pim_rpa.c
 */

/* Some group will be associated with another RPA. */
void pim_group_rpa_update(pim p, group g, pim_rpa old);

/* We become or are not DF anymore for a given election. */
void pim_group_is_df_change(pim_dfe dfe);

/* The upstream DF for a given rpa is changed. */
void pim_group_upstream_df_update(pim p, pim_rpa rpa, pim_neigh old);

/*
 * Functions called by pim_neigh.c
 */

/* Called when the ssbidir status of a neighbor changes (including when it is created).
 * If a neighbor is deleted, the function is called with n == NULL. */
void pim_group_neigh_ssbidir_changed(iface i, pim_neigh n);

/*
 * Functions called by conf.c
 */

void pim_group_conf_changed(pim p, group g);
void pim_ifgroup_conf_changed(pim p, ifgroup ig);
void pim_gsource_conf_changed(pim p, gsource gs);

/*
 * API provided by pim_group.h
 */
pim_neigh pim_group_upstream_df(pim p, group g);


#endif /* PIM_GROUP_H_ */
