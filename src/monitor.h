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
 * monitor.c gathers functions used to access internal state
 * of pimbd by the mean of the ipc.
 */

#ifndef MONITOR_H_
#define MONITOR_H_

#include "ipc.h"
#include "pim.h"
#include "ifgroup.h"

enum {
	MONITOR_IPC_RPA,
	MONITOR_IPC_RIB,
	MONITOR_IPC_IF,
	MONITOR_IPC_GRP,
	MONITOR_IPC_PROXY,
	MONITOR_IPC_USERS_MAX
};
typedef struct monitor_struct {
	ifgroups igs;
	pim pim;
	ipc ipc;
	struct ipc_user ipc_users[MONITOR_IPC_USERS_MAX];
} monitor_s, *monitor;

void monitor_init(monitor, ifgroups, pim, ipc);

#endif /* MONITOR_H_ */
