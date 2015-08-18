/*
 * Author: Pierre Pfister <pierre pfister at darou.fr>
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
 * rtnetlink is used to monitor system's interfaces and routes.
 */

#ifndef RTNL_H_
#define RTNL_H_

#include "ifgroup_s.h"
#include "rib.h"

/**
 * Structure containing rtnetlink state.
 */
struct rtnl_struct {
	ifgroups igs;
	rib rib;
	enum {
		RTNL_S_DOWN = 0,
		RTNL_S_WAITING_LINKS,
		RTNL_S_WAITING_ADDR,
		RTNL_S_WAITING_RT4,
		RTNL_S_WAITING_RT6,
		RTNL_S_UP,
	} state;
	struct uloop_fd fd;
	uint32_t nlmsg_seq;
	struct uloop_timeout to;
	uint32_t tentatives;
};
typedef struct rtnl_struct rtnl_s, *rtnl;

int rtnl_init(rtnl rt, ifgroups igs, rib rib);

#endif
