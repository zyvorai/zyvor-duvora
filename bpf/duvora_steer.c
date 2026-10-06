// SPDX-License-Identifier: Apache-2.0
//
// Traffic steering: ordered 5-tuple rules on the host's uplinks, at the head
// of both TCX chains. Each packet takes the action of the first matching rule
// (or the rule set's default):
//
//   bypass   pass without accounting beyond the counters
//   allow    pass
//   inspect  pass, and copy the start of the flow's payload for the agent's
//            analyzer (one capture per flow until the agent drains it)
//   drop     shadow: count as would-drop; enforce: drop
//
// The bypass flag passes everything (upgrade, fail-safe, operator bypass).
// Always passes: SSH (port 22 either side), traffic to or from the control
// plane (steer_exempt), and anything that fails to parse.
//
// This runs in the host kernel. It is not DPU offload.
//
// Rules live in two halves of one array; the agent writes the half for the
// next generation, zeroes its counters, then publishes steer_cfg.
#include "duvora_bpf.h"

#define ST_MAX_RULES 1000
#define ST_SLOTS (ST_MAX_RULES + 1) // rules plus the default
#define ST_MODE_OFF 0u
#define ST_MODE_SHADOW 1u
#define ST_MODE_ENFORCE 2u
#define ST_FLAG_BYPASS 1u
#define ST_FLAG_DEFAULT_DROP 2u

#define ST_BYPASS 0u
#define ST_ALLOW 1u
#define ST_INSPECT 2u
#define ST_DROP 3u

#define ST_DIR_INGRESS 1u
#define ST_DIR_EGRESS 2u

#define ST_MATCHED 0u
#define ST_ALLOWED 1u
#define ST_DROPPED 2u
#define ST_WOULD_DROP 3u
#define ST_INSPECTED 4u
#define ST_BYPASSED 5u
#define ST_EXEMPT 6u
#define ST_DROPPED_BYTES 7u
#define ST_WOULD_DROP_BYTES 8u
#define ST_STAT_SLOTS 9u

#define ST_CAPTURE 256u

struct st_config {
    __u32 generation; // 0 = no rule set
    __u32 mode;
    __u32 rule_count;
    __u32 flags;
};

// A rule matches when the direction bit is set, (addr & mask) == net for
// source and destination, the protocol matches (0 = any) and, for ranges
// with hi != 0, the TCP/UDP port is within [lo, hi].
struct st_rule {
    __u8 directions;
    __u8 family; // 0 = any
    __u8 protocol;
    __u8 action;
    __u16 sport_lo;
    __u16 sport_hi;
    __u16 dport_lo;
    __u16 dport_hi;
    __u32 reserved;
    __u64 src[2];
    __u64 src_mask[2];
    __u64 dst[2];
    __u64 dst_mask[2];
};

struct st_counter {
    __u64 packets;
    __u64 bytes;
};

// Control-plane endpoints, matched as (address, port) on either side so a
// controller that shares the node's address does not exempt all its traffic.
struct st_exempt_key {
    __u32 generation;
    __u8 family;
    __u8 reserved;
    __u16 port;
    __u8 address[16];
};

struct st_flow_key {
    __u8 direction;
    __u8 family;
    __u8 protocol;
    __u8 action;
    __u16 sport;
    __u16 dport;
    __u8 saddr[16];
    __u8 daddr[16];
};

struct st_flow_value {
    __u32 rule; // index; rule_count = default
    __u32 reserved;
    __u64 packets;
    __u64 bytes;
    __u64 last_ns;
};

struct st_payload {
    __u32 len;
    __u32 rule;
    __u8 data[ST_CAPTURE];
};

_Static_assert(sizeof(struct st_config) == 16, "steer config ABI");
_Static_assert(sizeof(struct st_rule) == 80, "steer rule ABI");
_Static_assert(sizeof(struct st_exempt_key) == 24, "steer exempt key ABI");
_Static_assert(sizeof(struct st_flow_key) == 40, "steer flow key ABI");
_Static_assert(sizeof(struct st_flow_value) == 32, "steer flow value ABI");
_Static_assert(sizeof(struct st_payload) == 264, "steer payload ABI");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct st_config);
} steer_cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2 * ST_MAX_RULES);
    __type(key, __u32);
    __type(value, struct st_rule);
} steer_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2 * ST_SLOTS);
    __type(key, __u32);
    __type(value, struct st_counter);
} steer_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, ST_STAT_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
} steer_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct st_exempt_key);
    __type(value, __u8);
} steer_exempt SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct st_flow_key);
    __type(value, struct st_flow_value);
} steer_flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 512);
    __type(key, struct st_flow_key);
    __type(value, struct st_payload);
} steer_payloads SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct st_payload);
} steer_scratch SEC(".maps");

struct st_addrs {
    __u64 s[2];
    __u64 d[2];
};

static __always_inline void st_count(__u32 slot, __u64 n)
{
    __u64 *v = bpf_map_lookup_elem(&steer_stats, &slot);
    if (v)
        *v += n;
}

// Global and noinline so the verifier checks it once, not once per rule.
// Direction, family, protocol and has_ports travel in `meta`, both ports in
// `ports`; every argument must be used or clang leaves its register unset.
__attribute__((noinline)) int duvora_steer_match(__u32 slot, __u32 meta, __u32 ports, const struct st_addrs *a)
{
    if (!a)
        return -1;
    struct st_rule *r = bpf_map_lookup_elem(&steer_rules, &slot);
    if (!r)
        return -1;
    if (!(r->directions & (__u8)meta))
        return -1;
    if (r->family && r->family != (__u8)(meta >> 8))
        return -1;
    if (r->protocol && r->protocol != (__u8)(meta >> 16))
        return -1;
    if (((a->s[0] & r->src_mask[0]) != r->src[0]) || ((a->s[1] & r->src_mask[1]) != r->src[1]))
        return -1;
    if (((a->d[0] & r->dst_mask[0]) != r->dst[0]) || ((a->d[1] & r->dst_mask[1]) != r->dst[1]))
        return -1;
    __u32 has_ports = (meta >> 24) & 1;
    __u32 sport = ports >> 16, dport = ports & 0xffff;
    if (r->sport_hi && (!has_ports || sport < r->sport_lo || sport > r->sport_hi))
        return -1;
    if (r->dport_hi && (!has_ports || dport < r->dport_lo || dport > r->dport_hi))
        return -1;
    return r->action;
}

static __always_inline void st_flow(const struct st_flow_key *k, __u32 rule, __u64 len)
{
    struct st_flow_value *v = bpf_map_lookup_elem(&steer_flows, k);
    if (v) {
        __sync_fetch_and_add(&v->packets, 1);
        __sync_fetch_and_add(&v->bytes, len);
        v->last_ns = bpf_ktime_get_ns();
        v->rule = rule;
    } else {
        struct st_flow_value init = {.rule = rule, .packets = 1, .bytes = len, .last_ns = bpf_ktime_get_ns()};
        bpf_map_update_elem(&steer_flows, k, &init, BPF_NOEXIST);
    }
}

static __always_inline void st_capture(struct __sk_buff *skb, const struct dv_packet *p, const struct st_flow_key *k, __u32 rule)
{
    if (!p->payload_off || p->payload_off >= skb->len || bpf_map_lookup_elem(&steer_payloads, k))
        return;
    __u32 zero = 0;
    struct st_payload *buf = bpf_map_lookup_elem(&steer_scratch, &zero);
    if (!buf)
        return;
    __u32 n = skb->len - p->payload_off;
    if (n > ST_CAPTURE)
        n = ST_CAPTURE;
    // n >= 1 here; the mask form lets the verifier see the length as 1..256.
    n = ((n - 1) & (ST_CAPTURE - 1)) + 1;
    if (bpf_skb_load_bytes(skb, p->payload_off, buf->data, n) < 0)
        return;
    buf->len = n;
    buf->rule = rule;
    bpf_map_update_elem(&steer_payloads, k, buf, BPF_NOEXIST);
    st_count(ST_INSPECTED, 1);
}

static __always_inline int st_exempt(__u32 generation, const struct dv_packet *p)
{
    if (!p->has_ports)
        return 0;
    if (p->sport == 22 || p->dport == 22)
        return 1;
    struct st_exempt_key k = {.generation = generation, .family = p->family, .port = p->sport};
    __builtin_memcpy(k.address, p->saddr, 16);
    if (bpf_map_lookup_elem(&steer_exempt, &k))
        return 1;
    k.port = p->dport;
    __builtin_memcpy(k.address, p->daddr, 16);
    return bpf_map_lookup_elem(&steer_exempt, &k) != 0;
}

static __always_inline int st_steer(struct __sk_buff *skb, __u32 direction)
{
    __u32 zero = 0;
    struct st_config *cfg = bpf_map_lookup_elem(&steer_cfg, &zero);
    if (!cfg || cfg->generation == 0 || cfg->mode == ST_MODE_OFF)
        return TC_ACT_UNSPEC;
    struct st_config c = *cfg;
    if (c.flags & ST_FLAG_BYPASS) {
        st_count(ST_BYPASSED, 1);
        return TC_ACT_UNSPEC;
    }
    struct dv_packet p = {};
    if (!dv_parse(skb, &p))
        return TC_ACT_UNSPEC;
    if (st_exempt(c.generation, &p)) {
        st_count(ST_EXEMPT, 1);
        return TC_ACT_UNSPEC;
    }
    __u32 count = c.rule_count;
    if (count > ST_MAX_RULES)
        count = ST_MAX_RULES;
    __u32 base = (c.generation & 1) * ST_MAX_RULES;
    struct st_addrs a;
    __builtin_memcpy(a.s, p.saddr, 16);
    __builtin_memcpy(a.d, p.daddr, 16);
    __u32 meta = direction | ((__u32)p.family << 8) | ((__u32)p.protocol << 16) | ((__u32)p.has_ports << 24);
    __u32 ports = ((__u32)p.sport << 16) | p.dport;
    __u32 rule = count;
    int action = (c.flags & ST_FLAG_DEFAULT_DROP) ? ST_DROP : ST_BYPASS;
#pragma clang loop unroll(disable)
    for (__u32 i = 0; i < ST_MAX_RULES; i++) {
        if (i >= count)
            break;
        int hit = duvora_steer_match(base + i, meta, ports, &a);
        if (hit >= 0) {
            rule = i;
            action = hit;
            break;
        }
    }
    st_count(ST_MATCHED, rule < count);
    __u32 slot = (c.generation & 1) * ST_SLOTS + (rule <= ST_MAX_RULES ? rule : ST_MAX_RULES);
    struct st_counter *ctr = bpf_map_lookup_elem(&steer_counters, &slot);
    if (ctr) {
        ctr->packets += 1;
        ctr->bytes += skb->len;
    }
    if (action == ST_BYPASS) {
        st_count(ST_BYPASSED, 1);
        return TC_ACT_UNSPEC;
    }
    struct st_flow_key k = {.direction = direction, .family = p.family, .protocol = p.protocol, .action = action,
                            .sport = p.sport, .dport = p.dport};
    __builtin_memcpy(k.saddr, p.saddr, 16);
    __builtin_memcpy(k.daddr, p.daddr, 16);
    st_flow(&k, rule, skb->len);
    if (action == ST_DROP) {
        if (c.mode == ST_MODE_ENFORCE) {
            st_count(ST_DROPPED, 1);
            st_count(ST_DROPPED_BYTES, skb->len);
            return TC_ACT_SHOT;
        }
        st_count(ST_WOULD_DROP, 1);
        st_count(ST_WOULD_DROP_BYTES, skb->len);
        return TC_ACT_UNSPEC;
    }
    if (action == ST_INSPECT)
        st_capture(skb, &p, &k, rule);
    st_count(ST_ALLOWED, 1);
    return TC_ACT_UNSPEC;
}

SEC("tcx/ingress")
int duvora_steer_ingress(struct __sk_buff *skb)
{
    return st_steer(skb, ST_DIR_INGRESS);
}

SEC("tcx/egress")
int duvora_steer_egress(struct __sk_buff *skb)
{
    return st_steer(skb, ST_DIR_EGRESS);
}

char LICENSE[] SEC("license") = "GPL";
