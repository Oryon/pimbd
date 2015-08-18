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
 * Configuration layer to be used by other elements (like ipc)
 * to setup configuration.
 */

#ifndef CONF_H_
#define CONF_H_

#include <libubox/blobmsg.h>

#include "ifgroup.h"

typedef struct conf_struct *conf, conf_s;

enum conf_iface_value {
	/* Configurable values */
	CIFV_PIM_HELLO_PERIOD_MS = 0, //interval between hellos in ms
	CIFV_PIM_US_T_PERIODIC_MS,    //interval between join refresh
	CIFV_CONF_MAX,

	/* Non-configurable with default values in array */
	CIFV_PIM_DR_PRIORITY,            //DR priority
	CIFV_PIM_DFE_OFFER_PERIOD_MS,    //DFE Offer period
	CIFV_PIM_DFE_BACKOFF_PERIOD_MS,  //DFE Backoff period
	CIFV_PIM_DFE_ROBUSTNESS,         //Election packet loss robustness
	CIFV_PIM_JP_OVERRIDE_INTERVAL_MS,//PRUNE_PENDING timer
	CIFV_CONF_ARRAY_MAX,

	/* Non-configurable with special values */
	CIFV_PIM_TRIGGERED_HELLO_DELAY_MS, //Some hellos may be triggered
	CIFV_PIM_HOLDTIME_S,               //Neighbor holdtime
	CIFV_PIM_US_JP_HOLDTIME_S,         //JP holdtime
	CIFV_CONF_ALL_MAX
};

/* iface specific configuration */
typedef struct conf_iface_struct {
	char state; //Set to true if some of the values are != INT_MIN
	int values[CIFV_CONF_MAX];
} *conf_iface, conf_iface_s;

#include "pim_rpa.h"
#include "ipc.h"

enum {
	CONF_IPC_LINK_SET,
	CONF_IPC_RPA_ADD,
	CONF_IPC_RPA_DEL,
	CONF_IPC_RPA_FLUSH,
	CONF_IPC_RPA_SET,
	CONF_IPC_PROXY_ADD,
	CONF_IPC_PROXY_DEL,
	CONF_IPC_GROUP_SET,
	CONF_IPC_USERS_MAX
};
struct conf_struct {
	ifgroups igs;
	pim pim;
	ipc ipc;
	struct ipc_user ipc_users[CONF_IPC_USERS_MAX];
};

void conf_init(conf conf, ifgroups igs, pim pim, ipc ipc);

/* Gets per-interface configuration values.
 * Returns -1 if no value was found. */
int conf_get_ifvalue(conf conf, iface i, enum conf_iface_value v);

#endif /* CONF_H_ */
