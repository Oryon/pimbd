# pimbd - A PIM BIDIR dual-stack implementation.

Pimb is a PIM BIDIR implementation enabling IPv4 and IPv6 multicast traffic forwarding. It supports dynamic configuration via IPC and is integrated into hnetd (An HNCP implementation: github.com/sbyx/hnetd/) for zeroconf operations.

The project is licensed under the terms of the Apache 2.0 License (See LICENSE file).


## Specifications and Features

### Specifications

Pimb implements the following specifications:
- PIM Basics: RFC 4601
- PIM BIDIR: RFC 5015
- MLDv2 querier: RFC 3810
- IGMPv3 querier: RFC 3376
- PIM SSBIDIR: draft-pfister-pim-ssbidir-00
- PIM Border Proxy: draft-pfister-pim-border-proxy-00
- PIM Homenet: draft-pfister-homenet-multicast-00

Pimb provides IPv4 and IPv6 multicast forwarding while exclusivly sending control PIM packets on top of IPv6. This approach takes advantage of link-local auto-configured addresses and therefore enables IPv4 multicast forwarding on unumbered networks. This approach is not in conformance with RFC 5015 and is, for now, not specified in any document. It simply consists in sending IPv4 Join/Prune messages in IPv6 packets, which is forbidden by RFC5015 but which, in practice, greatly simplifies implementation and operation of this protocol.

### Features

#### Those features you probably care

The following is a non-exhaustive list of the additional fancy features of Pimb.

- Multiple RP Addresses, mapped with group ranges
- Dual-stack (IPv4 and IPv6)
- Dynamically configured using the IPC (pimbc)
- Plenty of configuration option (manual PIM state, MLD/IGMP membership, etc... )
- json based monitoring (using pimbc)


#### Those features you probably don't care

The following is a non-exhaustive list of those things that were done because we can.

Kernel patch for crappy linux multicast support:
    Linux multicast forwarding was primarly targeting PIM SM. Extensions were later created for SSM and multicast proxy, none of which are generic enough (e.g., no support for source mobility). Pimb provides a simple kernel patch which enables some more generic behavior. The patch allows MRT_ASSERT socket option to be set to 2. When set to 2, multicast traffic received on any interface other than the input interface of an existing routing entry will trigger a MRT6MSG_WRONGMIF mld notification. The presence of this patch is automatically detected and acted upon by pimbd, unless macro DISABLE_ASSERT_EXTENSION is set. When DISABLE_ASSERT_EXTENSION is set, or when the kernel is not patched, short-lived multicast routes are used.

Joining the Joins just like traveling waves.
    PIM Join/Prunes are sent at regular intervals. Pimbd introduces a small random shift and allows for slightly premature Join/Prune emission such that all Joins and Prunes are eventually syncrhonized. You can see this as small waves that travel at different speeds and, by catching each other, eventually form one big wave.

Works with linux network namespaces.
    For testing reasons, I made sure that multiple instances of pimbd and pimbc can be run in different namespaces. Some care needs to be taken with Unix-Socket paths (for IPC), wich are not part of Linux network namespaces.

## Requirements

#### Platform
linux platform
- Tested on 3.10 and later
- Maybe works on older platforms

Built with Multicast Forwarding support
- CONFIG_IP_MROUTE
- CONFIG_IPV6_MROUTE

#### Building requirements
cmake

#### Linked libraries

pimbd makes use of libubox, which is included as a git submodule.
By default, you don't need to install libubox, but make sure you enabled git submodules in the source directory:
$  git submodule init
$  git submodule update

And also make sure you have libjson-c installed:
$  apt-get install libjson-c-dev

If you want to install libubox, try this:
$  apt-get install liblua5.1-0-dev
$  git clone http://git.openwrt.org/project/libubox.git
$  (cd libubox && cmake . && make && sudo make install)

If you have libubox installed on your system, use the WITH_LIBUBOX cmake option.
$  cmake . -DWITH_LIBUBOX=1

## How-To

#### Build & Install
cmake . -DL_LEVEL=9
make
sudo make install

#### Running the daemon: pimbd
There is no init.d script for now.
To start pimbd, use the commandline.

sudo pimbd <options>

pimbd commandline options are:
 -h Displays options
 -c <config-file> Use the provided file for conf (Similar to later call to pimbc file <config-file>).
 -s <sock-path> Specify the IPC unix socket path to use.
 -S Use syslog for logs.
 -l <log-file> Specify a log file (incompatible with syslog enabled).
 -p <pid-file> The process pid is written to that file if initialization succeeds.


#### Configuration using pimbc
pimbd boots with almost no configuration and initially does almost nothing. It is therefore harmless to start a pimbd instance with not configuration. The only thing it will do is try to initialize multicast routing and listen to netlink.

Configuration happens after boot and is done dynamically using pimbc. pimbc is a simple script which translates human friendly commands into a json formatted string that is then provided to pimb-ipc. pimb-ipc sends the json string through a Unix socket to pimbd and prints the json object that is returned by pimbd.

pimbc options can be found in the man page.


## On-going work

This work is still in progress


## Known Bugs and Problems

This section keeps track of known bugs and problems.

#### (S,G) mrib entries in the kernel

Linux assumes there may be just one input interface per (S,G). In some cases this is wrong (transitory routing state/load balancing). The problem is that when a packet comes from an iif, if an (S,G) mrib entry exists for a different iif, the routing daemon does not get notified and the packet is dropped.

This means that such a packet will only be considered when an entry timeouts.

Also, it means that we cannot add a negative entry (entry with no oif) in order to stop receiving kernel's notifications.

Pimb implements a workaround to this problem, and additionaly provides a simple kernel patch which enables a more sane and CPU efficient behavior.

#### IPv6 MLD loopback subscription

Linux does not feedback local subscriptions to the MLD querier. Which means pimbd
will not be able to consider self multicast subscriptions. To make them work,
the subscription must be made on the right upstream interface.

This works fine with IPv4.


## Authors and Acknowledgments

The authors of this project are:
- Pierre Pfister <pierre at darou.fr>
- Steven Barth   <steven at midlink.org>
- Mohammed Hawari <mohammed at hawari.fr>

Participating organizations:
- Cisco Systems
- Deutsche Telekom
- OpenWrt
- Ecole Polytechnique (Paris)
