/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_HIGH_SCALE_IPCACHE_H_
#define __LIB_HIGH_SCALE_IPCACHE_H_

#include "maps.h"

#ifdef ENABLE_HIGH_SCALE_IPCACHE
/* WORLD_CIDR_STATIC_PREFIX4 gets sizeof non-IP, non-prefix part of
 * world_cidrs_key4.
 */
# define WORLD_CIDR_STATIC_PREFIX4						\
	(8 * (sizeof(struct world_cidrs_key4) - sizeof(struct bpf_lpm_trie_key)	\
	      - sizeof(__u32)))
#define WORLD_CIDR_PREFIX_LEN4(PREFIX) (WORLD_CIDR_STATIC_PREFIX4 + (PREFIX))

static __always_inline __maybe_unused bool
world_cidrs_lookup4(__u32 addr)
{
	__u8 *matches;
	struct world_cidrs_key4 key = {
		.lpm_key = { WORLD_CIDR_PREFIX_LEN4(V4_CACHE_KEY_LEN), {} },
		.ip = addr,
	};

	key.ip &= GET_PREFIX(V4_CACHE_KEY_LEN);
	matches = map_lookup_elem(&WORLD_CIDRS4_MAP, &key);
	return matches != NULL;
}

static __always_inline bool
needs_encapsulation(__u32 addr)
{
# ifdef ENABLE_NO_ENCAPSULATION
	/*
	 * Return false always for the transparent mode,
	 * i.e. no packets encapsulation for any egress packets.
	 */
	return false;
# endif

# ifndef ENABLE_ROUTING
	/* If endpoint routes are enabled, we need to check if the destination
	 * is a local endpoint, in which case we don't want to encapsulate. If
	 * endpoint routes are disabled, we don't need to check this because we
	 * will never reach this point and the packet will be redirected to the
	 * destination endpoint directly.
	 */
	if (__lookup_ip4_endpoint(addr))
		return false;
# endif /* ENABLE_ROUTING */
	/* If the destination doesn't match one of the world CIDRs, we assume
	 * it's destined to a remote pod. In that case, since the high-scale
	 * ipcache is enabled, we want to encapsulate with the remote pod's IP
	 * itself.
	 */
	return !world_cidrs_lookup4(addr);
}
#endif /* ENABLE_HIGH_SCALE_IPCACHE */
#endif /* __LIB_HIGH_SCALE_IPCACHE_H_ */
