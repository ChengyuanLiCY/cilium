#!/usr/bin/bash

set -o xtrace

ip link del name cilium_vxlan

ip link add name cilium_vxlan address 6e:a5:69:d1:ca:48 type vxlan id 42 local fd01::50 remote fd04::12 dstport 4789
#ip a add fd01::50/32 dev cilium_vxlan
ip link set cilium_vxlan up
ip -6 neigh add fd01::200 lladdr 6e:a5:69:d1:ca:49 dev cilium_vxlan
ip r add fd01::200/32 dev cilium_vxlan
