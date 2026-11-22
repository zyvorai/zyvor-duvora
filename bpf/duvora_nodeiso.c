// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
//
// Node isolation: an allow-only egress filter at the head of the TCX egress
// chain of the node's uplinks.
//
//   off      everything passes
//   shadow   count what the allow-list would block, never drop
//   enforce  drop new outbound flows the allow-list does not cover
//
// Judged: TCP SYN without ACK (new outbound connections) and every UDP or
// other-protocol packet. Always passes: established TCP (so an SSH session
// survives enforce), ICMP/ICMPv6, DHCP/DHCPv6, non-first fragments, packets
// whose local source port is exempt, and anything that fails to parse.
//
// Rules live under a generation key; the agent writes a whole new generation
// and publishes it in iso_cfg last, so a packet sees one complete rule set.
#include "duvora_bpf.h"

#define ISO_MAX_RULES 80
#define ISO_MODE_OFF 0u
#define ISO_MODE_SHADOW 1u
#define ISO_MODE_ENFORCE 2u

#define ISO_ALLOWED 0u
#define ISO_WOULD_BLOCK 1u
#define ISO_BLOCKED 2u
#define ISO_EXEMPT 3u
#define ISO_WOULD_BLOCK_BYTES 4u
#define ISO_BLOCKED_BYTES 5u
#define ISO_SLOTS 6u

struct iso_config {
    __u32 generation; // 0 = no policy
    __u32 mode;
    __u32 rule_count;
    __u32 reserved;
};

struct iso_rule_key {
    __u32 generation;
    __u32 index;
};

// A packet matches when (daddr & mask) == addr, the protocol matches
// (0 = any) and, if port_hi != 0, its TCP/UDP destination port is in range.
struct iso_rule {
    __u8 family;
    __u8 protocol;
    __u16 port_lo;
    __u16 port_hi;
    __u16 reserved;
    __u64 addr[2];
    __u64 mask[2];
};

struct iso_exempt_key {
    __u32 generation;
    __u8 protocol;
    __u8 reserved;
    __u16 port; // local source port
};

struct iso_dest_key {
    __u8 family;
    __u8 protocol;
    __u16 port;
    __u8 address[16];
};

struct iso_dest_value {
    __u64 packets;
    __u64 bytes;
};

_Static_assert(sizeof(struct iso_config) == 16, "iso config ABI");
_Static_assert(sizeof(struct iso_rule_key) == 8, "iso rule key ABI");
_Static_assert(sizeof(struct iso_rule) == 40, "iso rule ABI");
_Static_assert(sizeof(struct iso_exempt_key) == 8, "iso exempt key ABI");
_Static_assert(sizeof(struct iso_dest_key) == 20, "iso dest key ABI");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct iso_config);
} iso_cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 3 * ISO_MAX_RULES);
    __type(key, struct iso_rule_key);
    __type(value, struct iso_rule);
} iso_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, struct iso_exempt_key);
    __type(value, __u8);
} iso_exempt SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, ISO_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
} iso_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct iso_dest_key);
    __type(value, struct iso_dest_value);
} iso_dests SEC(".maps");

struct iso_peer {
    __u64 w[2];
};

static __always_inline void iso_count(__u32 slot, __u64 n)
{
    __u64 *v = bpf_map_lookup_elem(&iso_stats, &slot);
    if (v)
        *v += n;
}

// Global and noinline: the verifier checks it once rather than once per
// iteration of the rule scan. Five arguments at most, so family, protocol
// and has_ports travel packed in `meta`.
__attribute__((noinline)) int duvora_iso_match(__u32 generation, __u32 index, __u32 meta, __u32 dport,
                                               const struct iso_peer *peer)
{
    if (!peer)
        return 0;
    struct iso_rule_key key = {.generation = generation, .index = index};
    struct iso_rule *r = bpf_map_lookup_elem(&iso_rules, &key);
    if (!r)
        return 0;
    if (r->family != (__u8)meta)
        return 0;
    if (((peer->w[0] & r->mask[0]) != r->addr[0]) || ((peer->w[1] & r->mask[1]) != r->addr[1]))
        return 0;
    if (r->protocol && r->protocol != (__u8)(meta >> 8))
        return 0;
    if (r->port_hi == 0)
        return 1;
    return ((meta >> 16) & 1) && dport >= r->port_lo && dport <= r->port_hi;
}

static __always_inline int iso_allowed(const struct iso_config *c, const struct dv_packet *p)
{
    __u32 count = c->rule_count;
    if (count > ISO_MAX_RULES)
        count = ISO_MAX_RULES;
    struct iso_peer peer;
    __builtin_memcpy(&peer, p->daddr, 16);
    __u32 meta = (__u32)p->family | ((__u32)p->protocol << 8) | ((__u32)p->has_ports << 16);
#pragma clang loop unroll(disable)
    for (__u32 i = 0; i < ISO_MAX_RULES; i++) {
        if (i >= count)
            break;
        if (duvora_iso_match(c->generation, i, meta, p->dport, &peer))
            return 1;
    }
    return 0;
}

static __always_inline int iso_always_passes(const struct dv_packet *p)
{
    if (!p->first_frag)
        return 1;
    if (p->protocol == IPPROTO_ICMP || p->protocol == IPPROTO_ICMPV6)
        return 1;
    if (p->protocol == IPPROTO_TCP)
        return !p->has_ports || p->tcp_flags != DV_TCP_SYN;
    if (p->protocol == IPPROTO_UDP && p->has_ports)
        return (p->sport == 68 && p->dport == 67) || (p->sport == 546 && p->dport == 547);
    return 0;
}

SEC("tcx/egress")
int duvora_nodeiso_egress(struct __sk_buff *skb)
{
    __u32 zero = 0;
    struct iso_config *cfg = bpf_map_lookup_elem(&iso_cfg, &zero);
    if (!cfg || cfg->generation == 0 || cfg->mode == ISO_MODE_OFF)
        return TC_ACT_UNSPEC;
    struct iso_config c = *cfg;

    struct dv_packet p = {};
    if (!dv_parse(skb, &p) || iso_always_passes(&p))
        return TC_ACT_UNSPEC;
    if (p.has_ports) {
        struct iso_exempt_key ek = {.generation = c.generation, .protocol = p.protocol, .port = p.sport};
        if (bpf_map_lookup_elem(&iso_exempt, &ek)) {
            iso_count(ISO_EXEMPT, 1);
            return TC_ACT_UNSPEC;
        }
    }
    if (iso_allowed(&c, &p)) {
        iso_count(ISO_ALLOWED, 1);
        return TC_ACT_UNSPEC;
    }
    struct iso_dest_key dk = {.family = p.family, .protocol = p.protocol, .port = p.dport};
    __builtin_memcpy(dk.address, p.daddr, 16);
    struct iso_dest_value *dv = bpf_map_lookup_elem(&iso_dests, &dk);
    if (dv) {
        __sync_fetch_and_add(&dv->packets, 1);
        __sync_fetch_and_add(&dv->bytes, skb->len);
    } else {
        struct iso_dest_value init = {.packets = 1, .bytes = skb->len};
        bpf_map_update_elem(&iso_dests, &dk, &init, BPF_NOEXIST);
    }
    if (c.mode == ISO_MODE_ENFORCE) {
        iso_count(ISO_BLOCKED, 1);
        iso_count(ISO_BLOCKED_BYTES, skb->len);
        return TC_ACT_SHOT;
    }
    iso_count(ISO_WOULD_BLOCK, 1);
    iso_count(ISO_WOULD_BLOCK_BYTES, skb->len);
    return TC_ACT_UNSPEC;
}

char LICENSE[] SEC("license") = "GPL";
