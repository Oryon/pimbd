#!/bin/sh

#
# Author: Pierre Pfister <pierre pfister at darou.fr>
#
# Copyright 2015 Deutsche Telekom AG
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#

#
# pimb-ipc translator, from fancy syntax to JSON
#

if [ "$(id -u)" -ne "0"  ]; then
	echo "You must be root !"
	exit 1
fi

COMMAND=""
ARGS=""
COMMA=""
EXEC="$0"
DRY_RUN=""
OPTIONS=""
VERBOSE=""

usage () {
	cat 1>&2 << EOF
Usage: pimbc [ OPTIONS ] { help | link | rpa | proxy | group | raw | file }
OPTIONS := [ -s |         pimbd UNIX socket path.
             -d |         dryrun. Do not send anything to pimbd.
             -t |         Timeout in seconds.
             -v ]         Prints debug information.

pimbc help

pimbc link {  | list }
pimbc link set DEVICE
           [ pim { on | off } ]
           [ ssbidir { on | off } ]
           [ mld { on | off } ]
           [ igmp { on | off } ]
           [ proxy { ADDRESS PORT | off } ]
           [ hello TIME ]
           [ join TIME ]
           [ llqc N ]
           [ robustness NUMBER ]

pimbc rpa {  | list }
pimbc rpa { add | del } ADDRESS GROUP_PREFIX
pimbc rpa flush ADDRESS
pimbc rpa set ADDRESS [ rpl_jp { on | off } ]

pimbc proxy {  | list }
pimbc proxy { add | del } ADDRESS PORT

pimbc group {  | list }
pimbc group set GROUP [ src ADDRESS ] [ dev DEVICE ]
		[ listener { include | exclude | none } ]
		[ local { include | exclude | none } ]
		[ pim { join | prune | none } ]

pimbc raw JSON

pimbc file FILE_PATH
EOF
}

echoerr() { echo "$@" 1>&2; }

error () {
	[ "$1" != "" ] && echoerr "Error: $1"
	exit 1
}

while [ "$1" != "" -a "${1:0:1}" = "-" ]; do
	case "$1" in
		"-s") OPTIONS="$OPTIONS -s $2"; shift 2;;
		"-d") OPTIONS="$OPTIONS -d"; DRY_RUN="1"; shift 1;;
		"-v") OPTIONS="$OPTIONS -v"; VERBOSE="1"; shift 1;;
		"-t") OPTIONS="$OPTIONS -t $2"; shift 2;;
		*) error "Unknown option '$1'.";;
	esac
done

args_add_element () {
	[ "$#" != "2" ] && { error "Oops ! args_add_element"; }
	[ -n "$COMMA" ] && ARGS=$ARGS", "
	[ -n "$1" ] && ARGS="$ARGS\"$1\":"
	ARGS="${ARGS}${2}"
	COMMA="1"
	return 0
}

args_add_string () {
	[ -z "$2" ] && { error "Oops ! args_add_string"; }
	args_add_element "$1" "\"$2\""
}

args_add_int () {
	[ -z "$2" ] && error "Missing integer value."
	[ "$2" -eq "$2" ] 2>/dev/null || error "Invalid integer '$2'."
	args_add_element "$1" "$2"
}

args_add_time () {
	[ -z "$2" ] && error "Missing time value."
	T=${2%s}
	[ "$T" -eq "$T" ] 2>/dev/null && args_add_int "$1" `expr $T \* 1000` && return
	T=${2%ms}
	[ "$T" -eq "$T" ] 2>/dev/null  && args_add_int "$1" $T && return
	error "Incorrect time format '$2'. Expecting NUMBER{  | s | ms }"
}

args_open_array () {
	[ -n "$COMMA" ] && ARGS=$ARGS", "
	[ -n "$1" ] && ARGS="$ARGS\"$1\":"
	ARGS="$ARGS["
	COMMA=""
}

args_close_array () {
	ARGS="${ARGS}]"
	COMMA="1"
}

args_open_table () {
	[ -n "$COMMA" ] && ARGS=$ARGS", "
	[ -n "$1" ] && ARGS="$ARGS\"$1\":"
	ARGS="$ARGS{"
	COMMA=""
}

args_close_table () {
	ARGS="${ARGS}}"
	COMMA="1"
}

args_add_bool () {
	[ "$2" = "true" -o "$2" = "1" -o "$2" = "on" -o "$2" = "enabled" ] && args_add_element "$1" true && return
	[ "$2" = "false" -o "$2" = "0" -o "$2" = "off" -o "$2" = "disabled" ] && args_add_element "$1" false && return
	error "Incorrect of missing boolean expression '$2'"
}

args_add_onoff () {
	[ -z "$2" ] && error "Expecting 'on' or 'off' argument rather than '$2'"
	case "$2" in
		"on") args_add_element "$1" true;;
		"off") args_add_element "$1" false;;
		*) error "Expecting 'on' or 'off' argument rather than '$2'"
	esac
}

link_conf () {
	case "$1" in
		"" | "list" | "show" )
			COMMAND="link_list"
			;;
		"set")
			COMMAND="link_set"
			[ -z "$2" ] && error "Expecting device name: pimbc link set DEVICE ..."
			args_add_string "dev" "$2"
			shift 2
			while [ -n "$1" ]; do case "$1" in
				pim) args_add_onoff "pim" "$2"; shift 2;;
				ssbidir) args_add_onoff "ssbidir" "$2"; shift 2;;
				mld) args_add_onoff "mld" "$2"; shift 2;;
				igmp) args_add_onoff "igmp" "$2"; shift 2;;
				proxy)
					shift 1;
					[ -z "$1" ] && error "Expecting 'off' or 'ADDRESS PORT'."
					[ "$1" = "off" ] && args_add_string "proxy" "off" && shift 1 && break				
					[ -z "$2" ] && error "Expecting PORT instead of '$2'"
					args_add_string "proxy" "$1 $2" && shift 2
					;;
				hello) args_add_time "hello" $2; shift 2;;
				join) args_add_time "join" $2; shift 2;;
				llqc) args_add_int "llqc" $2; shift 2;;
				robustness) args_add_int "robustness" $2; shift 2;;
				*) error "Unknown argument '$1'";;
			esac done;;
			
		*)
			error "Unknown command '$1'.";;
	esac
}

rpa_conf () {
	case "$1" in
		"" | "list" | "show" )
			COMMAND="rpa_list";;
		"add" | "del" )
			COMMAND="rpa_$1"
			[ -z "$2" -o -z "$3" ] && error "Expecting rpa address and group (pimbc rpa $1 ADDRESS GROUP_PREFIX)."
			args_add_string "rpa" "$2"
			args_add_string "groups" "$3"
			;;
		"set")
			COMMAND="rpa_set"
			[ -z "$2" ] && error "Expecting rpa address: pimbc rpa set ADDRESS ..."
			args_add_string "rpa" "$2"
			[ "$3" != "" ] && case "$3" in
				"rpl_jp") args_add_onoff "rpl_jp" "$4";;
				*) error "Unknown argument '$3'.";;
			esac;;
		"flush")
			COMMAND="rpa_flush"
			[ -z "$2" ] && error "Expecting { ADDRESS | all }"
			args_add_string "rpa" "$2"
			;;
		*)
			error "Unknown command '$1'.";;
	esac
}

group_conf () {
	case "$1" in
		"" | "list")
			COMMAND="group_list";;
		"set")
			COMMAND="group_set"
			[ -z "$2" ] && error "Expecting group address after 'set' token."
			args_add_string "group" "$2"
			shift 2
			while [ -n "$1" ]; do case $1 in
				"src")
					[ -z "$2" ] && error "Expecting a source address after 'src' token."
					args_add_string "src" "$2"
					shift 2
					;;
				"dev")
					[ -z "$2" ] && error "Expecting a device name after 'dev' token."
					args_add_string "dev" "$2"
					shift 2
					;;
				"listener" | "local")
					[ "$2" != "include" -a "$2" !=  "exclude" -a "$2" != "none" ] &&
						error "Expecting { include | exclude | none}' after '$1' token."
					args_add_string "$1" "$2"
					shift 2
					;;
				"pim")
					[ "$2" != "join" -a "$2" != "prune" -a "$2" != "none" ] && error "Expecting '{ join | prune | none }' after 'pim' token."
					args_add_string "pim" "$2"
					shift 2
					;;
				*)
					error "Unknown argument '$1'";;
			esac done;;
		*)
			error "Unknown command '$1'.";;
	esac
}

proxy_conf () {
	case "$1" in
		"" | "list")
			COMMAND="proxy_list";;
		"add" | "del")
			COMMAND="proxy_$1"
			[ -z "$2" -o -z "$3" ] && error "Expecting ADDRESS PORT"
			args_add_string "addr" "$2"
			args_add_int "port" "$3"
			;;
		*)
			error "Expecting {  | list | add | del }.";;
	esac
}

raw_conf () {
	pimb-ipc "$1"
	exit $?
}

file_conf () {
	[ -z "$1" ] && error "Expecting file path."
	[ ! -f "$1" ] && error "File $1 does not exists."
	ctr=0
	awk 'NF && $1!~/^#/' $1 | while read LINE
	do
		ctr=`expr $ctr + 1`
		echo "$EXEC $LINE"
		$EXEC $OPTIONS $LINE
		[ "$?" != "0" ] && error "Error at $1:$ctr : $LINE"
	done
	exit 0;
}

case "$1" in
	help) usage; exit 0;;
	link) shift 1; link_conf $@;;
	rpa) shift 1; rpa_conf $@;;
	group) shift 1; group_conf $@;;
	proxy) shift 1; proxy_conf $@;;
	rib) COMMAND="rib_list";;
	raw) shift 1; raw_conf $@;;
	file) shift 1; file_conf $@;;
	*) error "No such command '$1'";;
esac

ARG="{\"command\":\"$COMMAND\", \"args\":{$ARGS}}"
[ -n "$VERBOSE" ] && echo "JSON Argument: $ARG" >&2
[ -n "$DRY_RUN" ] && exit 0
pimb-ipc $OPTIONS "$ARG"
exit $?

