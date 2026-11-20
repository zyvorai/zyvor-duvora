// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
//
// Interface counters and egress destinations, attached at TCX ingress and
// egress of the agent's uplinks. Observe only: always TC_ACT_UNSPEC (next).
#include "duvora_bpf.h"

struct iface_key {
    __u32 ifindex;
    __u32 direction; // 0 ingress, 1 egress
};

struct iface_value {
    __u64 packets;
    __u64 bytes;
};

// Egress destination aggregate, the source of "top talkers".
struct flow_key {
    __u8 family;
    __u8 protocol;
    __u16 port;
    __u8 address[16];
};

struct flow_value {
    __u64 packets;
    __u64 bytes;
    __u64 last_ns;
};

_Static_assert(sizeof(struct iface_key) == 8, "iface key ABI");
_Static_assert(sizeof(struct iface_value) == 16, "iface value ABI");
_Static_assert(sizeof(struct flow_key) == 20, "flow key ABI");
_Static_assert(sizeof(struct flow_value) == 24, "flow value ABI");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 256);
    __type(key, struct iface_key);
    __type(value, struct iface_value);
} iface_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct flow_key);
    __type(value, struct flow_value);
} iface_flows SEC(".maps");

static __always_inline void count_iface(struct __sk_buff *skb, __u32 direction)
{
    struct iface_key k = {.ifindex = skb->ifindex, .direction = direction};
    struct iface_value *v = bpf_map_lookup_elem(&iface_stats, &k);
    if (v) {
        v->packets += 1;
        v->bytes += skb->len;
        return;
    }
    struct iface_value init = {.packets = 1, .bytes = skb->len};
    bpf_map_update_elem(&iface_stats, &k, &init, BPF_NOEXIST);
}

SEC("tcx/ingress")
int duvora_iface_ingress(struct __sk_buff *skb)
{
    count_iface(skb, 0);
    return TC_ACT_UNSPEC;
}

SEC("tcx/egress")
int duvora_iface_egress(struct __sk_buff *skb)
{
    count_iface(skb, 1);
    struct dv_packet p = {};
    if (!dv_parse(skb, &p))
        return TC_ACT_UNSPEC;
    struct flow_key k = {.family = p.family, .protocol = p.protocol, .port = p.dport};
    __builtin_memcpy(k.address, p.daddr, 16);
    __u64 now = bpf_ktime_get_ns();
    struct flow_value *v = bpf_map_lookup_elem(&iface_flows, &k);
    if (v) {
        __sync_fetch_and_add(&v->packets, 1);
        __sync_fetch_and_add(&v->bytes, skb->len);
        v->last_ns = now;
        return TC_ACT_UNSPEC;
    }
    struct flow_value init = {.packets = 1, .bytes = skb->len, .last_ns = now};
    bpf_map_update_elem(&iface_flows, &k, &init, BPF_NOEXIST);
    return TC_ACT_UNSPEC;
}

char LICENSE[] SEC("license") = "GPL";
