#!/usr/bin/bash

set -o xtrace

ip link del name cilium_vxlan

ip link add name cilium_vxlan address 6e:a5:69:d1:ca:48 type vxlan id 42 local 192.168.1.50 remote 192.168.56.12 dstport 4789
#ip a add 192.168.1.50/32 dev cilium_vxlan
ip link set cilium_vxlan up
arp -s 192.168.1.200 6e:a5:69:d1:ca:49 dev cilium_vxlan
ip r add 192.168.1.200/32 dev cilium_vxlan
