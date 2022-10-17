/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright Authors of the Linux kernel */
#ifndef _LINUX_GENEVE_H
#define _LINUX_GENEVE_H

/* Geneve Header:
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Virtual Network Identifier (VNI)       |    Reserved   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Variable Length Options                    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Option Header:
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          Option Class         |      Type     |R|R|R| Length  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                      Variable Option Data                     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct geneve_opt {
	__be16	opt_class;
	__u8	type;
#ifdef __LITTLE_ENDIAN_BITFIELD
	__u8	length:5;
	__u8	r3:1;
	__u8	r2:1;
	__u8	r1:1;
#else
	__u8	r1:1;
	__u8	r2:1;
	__u8	r3:1;
	__u8	length:5;
#endif
	__u8	opt_data[];
};

struct genevehdr {
#ifdef __LITTLE_ENDIAN_BITFIELD
	__u8 opt_len:6;
	__u8 ver:2;
	__u8 rsvd1:6;
	__u8 critical:1;
	__u8 oam:1;
#else
	__u8 ver:2;
	__u8 opt_len:6;
	__u8 oam:1;
	__u8 critical:1;
	__u8 rsvd1:6;
#endif
	__be16 proto_type;
	__u8 vni[3];
	__u8 rsvd2;
	struct geneve_opt options[];
};

#endif /* _LINUX_GENEVE_H */
