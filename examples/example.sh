#!/bin/sh

# This is a small net-ns based example.
# A small network is created with static routes.
# pimbd is started on top of that.

DIR=`dirname $0`
NS="pimbdns"
VETH="pimbdveth"

function stop() {
	echo "$2"
	echo "Killing pimbd processes"
	for i in `seq 0 4`; do
		sudo kill -9 `cat $DIR/pimbd${i}.pid`
	done
	echo "Deleting namespaces"
	for i in `seq 0 4`; do
        	sudo ip netns del "${NS}${i}"
	done
	for i in `seq 0 4`; do
		sudo rm "$DIR/pimbd${i}.pid" "$DIR/pimbd${i}.sock"
		
	done
	([ -n "$1" ] && exit "$1") || exit 0
}

trap stop INT

echo "This script uses sudo."
(sudo echo -n "") || (echo "sudo failed" && exit 1)

for i in `seq 0 4`; do
	sudo ip netns add "${NS}${i}" || stop 2 "Could not create namespace $NS$i"
	(
	sudo ip netns exec $NS$i sysctl -w net.ipv6.conf.all.forwarding=1 && 
	sudo ip netns exec $NS$i sysctl -w net.ipv4.conf.all.forwarding=1 && 
	sudo ip netns exec $NS$i sysctl -w net.ipv4.ip_forward=1 && 
	sudo ip netns exec $NS$i sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=0
	) > /dev/null 2>&1 || stop 2 "Could not configure namespace $NS$i"
	echo "Created namespace $NS$i"
done

function connect() {
	sudo ip netns exec $NS$1 ip link add $VETH$1$2 type veth peer name $VETH$2$1 || stop 4 "Could not create veth interfaces"
	sudo ip netns exec $NS$1 ip link set $VETH$2$1 netns $NS$2 || stop 5 "Could not move veth to other namespace"
	sudo ip netns exec $NS$1 ip link set $VETH$1$2 up || stop 6 "Could not set veth up"
	sudo ip netns exec $NS$2 ip link set $VETH$2$1 up || stop 7 "Could not set veth down"
}

#
# Network topology and route setup
#

connect 0 1
connect 1 2
connect 2 3
connect 2 4

sudo ip netns exec ${NS}0 ip -6 addr add "2001:db8:01::01/64" dev ${VETH}01
sudo ip netns exec ${NS}0 ip -4 addr add "10.0.01.01/24" dev ${VETH}01
sudo ip netns exec ${NS}0 ip -6 route add "2001::/16" dev ${VETH}01 via "2001:db8:01::10"
sudo ip netns exec ${NS}0 ip -4 route add "10.0.0.0/8" dev ${VETH}01 via "10.0.01.10"

sudo ip netns exec ${NS}1 ip -6 addr add "2001:db8:01::10/64" dev ${VETH}10
sudo ip netns exec ${NS}1 ip -4 addr add "10.0.01.10/24" dev ${VETH}10

sudo ip netns exec ${NS}1 ip -6 addr add "2001:db8:12::12/64" dev ${VETH}12
sudo ip netns exec ${NS}1 ip -4 addr add "10.0.12.12/24" dev ${VETH}12
sudo ip netns exec ${NS}1 ip -6 route add "2001::/16" dev ${VETH}12 via "2001:db8:12::21"
sudo ip netns exec ${NS}1 ip -4 route add "10.0.0.0/8" dev ${VETH}12 via "10.0.12.21"

sudo ip netns exec ${NS}2 ip -6 addr add "2001:db8:12::21/64" dev ${VETH}21
sudo ip netns exec ${NS}2 ip -4 addr add "10.0.12.21/24" dev ${VETH}21
sudo ip netns exec ${NS}2 ip -6 route add "2001:db8:01::/64" dev ${VETH}21 via "2001:db8:12::12"
sudo ip netns exec ${NS}2 ip -4 route add "10.0.01.0/24" dev ${VETH}21 via "10.0.12.12"

sudo ip netns exec ${NS}2 ip -6 addr add "2001:db8:24::24/64" dev ${VETH}24
sudo ip netns exec ${NS}2 ip -4 addr add "10.0.24.24/24" dev ${VETH}24

sudo ip netns exec ${NS}2 ip -6 addr add "2001:db8:23::23/64" dev ${VETH}23
sudo ip netns exec ${NS}2 ip -4 addr add "10.0.23.23/24" dev ${VETH}23

sudo ip netns exec ${NS}3 ip -6 addr add "2001:db8:23::32/64" dev ${VETH}32
sudo ip netns exec ${NS}3 ip -4 addr add "10.0.23.32/24" dev ${VETH}32
sudo ip netns exec ${NS}3 ip -6 route add "2001::/16" dev ${VETH}32 via "2001:db8:23::23"
sudo ip netns exec ${NS}3 ip -4 route add "10.0.0.0/8" dev ${VETH}32 via "10.0.23.23"

sudo ip netns exec ${NS}4 ip -6 addr add "2001:db8:24::42/64" dev ${VETH}42
sudo ip netns exec ${NS}4 ip -4 addr add "10.0.24.42/24" dev ${VETH}42
sudo ip netns exec ${NS}4 ip -6 route add "2001::/16" dev ${VETH}42 via "2001:db8:24::24"
sudo ip netns exec ${NS}4 ip -4 route add "10.0.0.0/8" dev ${VETH}42 via "10.0.24.24"

#
# Start pimbd
#

for i in `seq 0 4`; do
	sudo ip netns exec ${NS}$i pimbd -s $DIR/pimbd$i.sock -l $DIR/pimbd$i.log -L 9 -p $DIR/pimbd$i.pid &
done

sleep 2

#
# Setup PIM
#
sudo pimbc -s $DIR/pimbd0.sock link set ${VETH}01 pim on ssbidir on mld on igmp on hello 1000
sudo pimbc -s $DIR/pimbd1.sock link set ${VETH}10 pim on ssbidir on mld on igmp on hello 1000
sudo pimbc -s $DIR/pimbd1.sock link set ${VETH}12 pim on ssbidir on mld on igmp on hello 1000
sudo pimbc -s $DIR/pimbd2.sock link set ${VETH}21 pim on ssbidir on mld on igmp on hello 1000
sudo pimbc -s $DIR/pimbd2.sock link set ${VETH}23 pim on ssbidir on mld on igmp on hello 1000
sudo pimbc -s $DIR/pimbd2.sock link set ${VETH}24 pim on ssbidir on mld on igmp on hello 1000
sudo pimbc -s $DIR/pimbd3.sock link set ${VETH}32 pim on ssbidir on mld on igmp on hello 1000
sudo pimbc -s $DIR/pimbd4.sock link set ${VETH}42 pim on ssbidir on mld on igmp on hello 1000

sudo pimbc -s $DIR/pimbd0.sock group set "ff05::1111" dev "${VETH}01" listener exclude
sudo pimbc -s $DIR/pimbd0.sock group set "224.1.1.11" dev "${VETH}01" listener exclude

sudo pimbc -s $DIR/pimbd3.sock group set "ff05::1111" dev "${VETH}32" listener exclude
sudo pimbc -s $DIR/pimbd3.sock group set "224.1.1.11" dev "${VETH}32" listener exclude

sudo pimbc -s $DIR/pimbd4.sock group set "ff05::1111" dev "${VETH}42" listener exclude
sudo pimbc -s $DIR/pimbd4.sock group set "224.1.1.11" dev "${VETH}42" listener exclude

for i in `seq 0 4`; do
	sudo pimbc -s "$DIR/pimbd${i}.sock" rpa add "2001:db8:24::42" "ff05::1111/16"
	sudo pimbc -s "$DIR/pimbd${i}.sock" rpa add "2001:db8:24::42" "224.0.0.0/8"
done

echo "Now running. Lets do some pings."
while [ -n "1" ]; do
	sudo ip netns exec ${NS}0 ping6 -c 1 -W 1 -t 20 -I ${VETH}01 "ff05::1111"
	sudo ip netns exec ${NS}0 ping -c 1 -W 1 -t 20 -I ${VETH}01 "224.1.1.11"
	sudo ip netns exec ${NS}3 ping6 -c 1 -W 1 -t 20 -I ${VETH}32 "ff05::1111"
	sudo ip netns exec ${NS}3 ping -c 1 -W 1 -t 20 -I ${VETH}32 "224.1.1.11"
	sudo ip netns exec ${NS}4 ping6 -c 1 -W 1 -t 20 -I ${VETH}42 "ff05::1111"
	sudo ip netns exec ${NS}4 ping -c 1 -W 1 -t 20 -I ${VETH}42 "224.1.1.11"
	sleep 1
done

#sleep 100000
stop
