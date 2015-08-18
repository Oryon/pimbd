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
 * The listener handles multicast subscriptions on given interfaces.
 * The proxy will provide subscription for all requested (*,G) and (S,G) groups.
 *
 */

#ifndef LISTENER_H_
#define LISTENER_H_

#include "ifgroup.h"

#define LISTENER_CONF      0x1
#define LISTENER_PIM_PROXY 0x2

struct listener_iface {
	int sock6;          //Socket used for MLD joins
	int sock4;          //Socket used for IGMP joins
	size_t group_count; //Number of active groups
};

/* Updates requested subscription state on an interface, for a given group.
 * The state can only be LISTENER_NONE or LISTENER_EXCLUDE */
void listener_update_G(ifgroup ig, uint8_t user, char exclude);

/* Updates requested subscription state on an interface, for a given group and source. */
void listener_update_G_S(ifgsource igs, uint8_t user, char include, char exclude);

#endif /* LISTENER_H_ */
