// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
//
// TCP health: retransmits, resets sent and resets received, node-wide.
#include "duvora_bpf.h"

#define TCP_RETRANSMIT 0u
#define TCP_RST_SENT 1u
#define TCP_RST_RECEIVED 2u

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} tcp_counts SEC(".maps");

static __always_inline void bump(__u32 slot)
{
    __u64 *v = bpf_map_lookup_elem(&tcp_counts, &slot);
    if (v)
        *v += 1;
}

SEC("tp_btf/tcp_retransmit_skb")
int duvora_tcp_retransmit(unsigned long long *ctx)
{
    bump(TCP_RETRANSMIT);
    return 0;
}

SEC("tp_btf/tcp_send_reset")
int duvora_tcp_send_reset(unsigned long long *ctx)
{
    bump(TCP_RST_SENT);
    return 0;
}

SEC("tp_btf/tcp_receive_reset")
int duvora_tcp_receive_reset(unsigned long long *ctx)
{
    bump(TCP_RST_RECEIVED);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
