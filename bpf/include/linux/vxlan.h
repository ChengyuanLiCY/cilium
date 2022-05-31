/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright Authors of the Linux kernel */
#ifndef _LINUX_VXLAN_H
#define _LINUX_VXLAN_H

/* VXLAN protocol (RFC 7348) header:
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |R|R|R|R|I|R|R|R|               Reserved                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                VXLAN Network Identifier (VNI) |   Reserved    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * I = VXLAN Network Identifier (VNI) present.
 */
struct vxlanhdr {
	__be32 vx_flags;
	__be32 vx_vni;
};

#endif /* _LINUX_VXLAN_H */
