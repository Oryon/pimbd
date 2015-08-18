/*
 * Authors: Pierre Pfister <pierre pfister at darou.fr>
 *          Steven Barth <steven at midlink.org>
 *          Mohammed Hawari <mohammed at hawari.fr>
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

#include <fcntl.h> //Some version of this have a __unused defined...

#include "pimbd.h"

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "ifgroup.h"
#include "conf.h"
#include "rib.h"
#include "rtnl.h"
#include "pim.h"
#include "ipc.h"
#include "monitor.h"
#include "pim_proxy.h"

#define IPC_NAME "pimb-ipc"
#define IPC_UTILITY "pimbc"

int log_level = 7;
char use_syslog = 0;
char show_date = 0;
const char *log_prefix = " pimbd: ";

char time_buffer[40];
const char *formatted_time() {
	time_t timer;
	struct tm* tm_info;
	time(&timer);
	tm_info = localtime(&timer);
	return strftime(time_buffer, 40, "%Y:%m:%d %H:%M:%S", tm_info) == 0 ? NULL : time_buffer;
}

int pimbd_config_file(char *const file)
{
	int pid;
	L_WARN("Loading configuration file %s", file);
	if((pid = fork()) < 0)
		return -1;

	if(pid)
		return 0;

	sleep(1);
	char *const argv[] = {IPC_UTILITY, "file", file, NULL};
	if(execvp(IPC_UTILITY, argv)) {
		L_ERR("execv error: %s",strerror(errno));
		return -1;
	}
	return 0;
}

void usage() {
	printf("pimbd\n"
		   " -h Displays help\n"
		   " -c <config-file> Use the provided file for conf.\n"
		   " -s <sock-path> Specify the IPC unix socket path to use.\n"
           " -S Use syslog for logs.\n"
           " -l <log-file> Specify a log file (incompatible with syslog enabled).\n"
           " -p <pid-file> The process pid is written to that file if initialization succeeds.\n");
}

int check_sysproc(const char *file, int value) {
	int v, ret = -1;
	FILE *f = NULL;
	if(!(f = fopen(file, "r"))) {
		L_ERR("Could not open %s: %s", file, strerror(errno));
	} else if (!fscanf(f, "%d", &v)) {
		L_ERR("Could not read integer");
	} else if (v != value) {
		L_ERR("Unexpected sysctl value: %s = %d", file, v);
	} else {
		L_DEBUG("Correct sysctl value: %s = %d", file, v);
		ret = 0;
	}
	if(f)
		fclose(f);
	return ret;
}

int pimbd(int argc, char *const *argv) {
	L_INFO("PIM BIDIR daemon starting\n");

		ifgroups_s igs;
		conf_s conf;
		rib_s rib;
		rtnl_s rt;
		pim_s pim;
		struct querier querier;
		ipc_s ipc;
		monitor_s m;
		pim_proxy_s proxy;

		int opt;
		char *conffile = NULL;
		char *logfile = NULL;
		char *pidfile = NULL;
		char *sockpath = IPC_SOCKSERVER;
		char usyslog = 0;
		while ((opt = getopt(argc, argv, "hc:s:l:Sp:")) != -1) {
			switch (opt) {
			case 'c':
				conffile = optarg;
				break;
			case 's':
				sockpath = optarg;
				break;
			case 'S':
				usyslog = 1;
				break;
			case 'h':
				usage();
				return 0;
			case 'l':
				logfile = optarg;
				break;
			case 'p':
				pidfile = optarg;
				break;
			default: /* '?' */
				L_ERR("Unknown option '%c'", opt);
				usage();
				return -1;
			}
		}

		if(uloop_init()) {
			L_ERR("Cannot initialize uloop.");
			return -1;
		}

		/* init random */
		int urandom_fd;
		if(((urandom_fd = open("/dev/urandom", O_CLOEXEC | O_RDONLY))) < 0) {
			L_ERR("Could not init random %s", strerror(errno));
			return -1;
		}
		unsigned int seed;
		read(urandom_fd, &seed, sizeof(seed));
		close(urandom_fd);
		srandom(seed);

		check_sysproc("/proc/sys/net/ipv6/conf/all/forwarding", 1);
		check_sysproc("/proc/sys/net/ipv6/conf/all/mc_forwarding", 1);
		check_sysproc("/proc/sys/net/ipv4/conf/all/forwarding", 1);
		check_sysproc("/proc/sys/net/ipv4/conf/all/mc_forwarding", 1);
		check_sysproc("/proc/sys/net/ipv4/ip_forward", 1);
		check_sysproc("/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts", 0);

		if(ipc_init(&ipc, sockpath))
			L_ERR("Cannot initialize ipc");

		if(rib_init(&rib)) {
			L_ERR("Cannot initialize rib.");
			return -1;
		}

		ifgroups_init(&igs, &rib);

		if(rtnl_init(&rt, &igs, &rib)) {
			L_ERR("Cannot initialize rtnetlink.");
			return -2;
		}

		if(pim_init(&pim, &igs, &conf, &rib)) {
			L_ERR("Cannot initialize PIM structure");
			return -3;
		}

		pim_proxy_init(&proxy, &igs, &pim);
		querier_init(&querier, &igs);

		conf_init(&conf, &igs, &pim, &ipc);
		monitor_init(&m, &igs, &pim, &ipc);

		if(conffile) {
			if(pimbd_config_file(conffile)) {
				L_ERR("Can't load configuration file %s", conffile);
				return -1;
			}
		}

		FILE *f;
		if(pidfile) {
			if(!(f = fopen(pidfile, "w"))) {
				L_ERR("Can't open pid file %s: %s", pidfile, strerror(errno));
				return -1;
			}
			fprintf(f, "%d", getpid());
			fclose(f);
		}

		if(usyslog) {
			if(logfile) {
				L_ERR("Cannot specify a log file while using sysctl");
				return -1;
			}
			use_syslog = 1;
			openlog(log_prefix, LOG_CONS /*| LOG_PERROR*/, LOG_DAEMON);
		}

		if(logfile && !freopen(logfile, "a", stderr)) {
			L_ERR("Could not open log file %s", logfile);
			return -1;
		}
		if(logfile)
			show_date = 1;

		uloop_run();

		return 0;
}

int main(int argc, char *const *argv) {
	if(!argc)
		return -10;

	if(strlen(argv[0]) >= strlen(IPC_NAME) &&
			!strcmp(argv[0] + strlen(argv[0]) - strlen(IPC_NAME), IPC_NAME)) {
		return ipc_raw(argc, argv);
	}
	return pimbd(argc, argv);
}


