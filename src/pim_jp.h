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
 * Used by the group state machine, this program takes care of sending
 * Join and Prunes messages.
 * Updates are sent asynchronously. And a small delay is introduced to
 * try to make Join Prunes messages to be joint.
 */

#ifndef PIM_JP_H_
#define PIM_JP_H_

#include "pim_rpa.h"

enum pim_jp_mod{
	PIM_JP_UPDATE_JD,//Desired state was changed
	PIM_JP_UPDATE_DF,//DF was changed
	PIM_JP_OVERRIDE, //Send an update earlier than the delay.
	PIM_JP_SUPPRESS, //Send an update after the delay.
	PIM_JP_CANCEL_OT, //Cancel override timer
};


void pim_jp_init(pim p);

/* Removes remembered jp */
void pim_jp_dead_neighbor(pim p, pim_neigh n);

/* Tells when to send the next jp */
void pim_jp_update_G(pim p, group g, enum pim_jp_mod mod, pimbd_time_t now, uint32_t delay);
void pim_jp_update_G_S(pim p, gsource gs, enum pim_jp_mod mod, pimbd_time_t now, uint32_t delay);
void pim_jp_update_G_S_rpt(pim p, gsource gs, enum pim_jp_mod mod, pimbd_time_t now, uint32_t delay);

#endif /* PIM_JP_H_ */
