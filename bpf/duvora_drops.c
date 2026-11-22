// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
//
// Kernel drop reasons: counts kfree_skb by its `reason` argument. The agent
// names the reasons from the tracepoint's format (enum skb_drop_reason).
#include "duvora_bpf.h"

// enum skb_drop_reason: 0 = not dropped yet, 1 = consumed (not a drop).
#define DV_FIRST_DROP_REASON 2u

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 512);
    __type(key, __u32);
    __type(value, __u64);
} drop_reasons SEC(".maps");

// kfree_skb(skb, location, reason[, rx_sk]): the reason is argument 2.
SEC("tp_btf/kfree_skb")
int duvora_kfree_skb(unsigned long long *ctx)
{
    __u32 reason = (__u32)ctx[2];
    if (reason < DV_FIRST_DROP_REASON)
        return 0;
    __u64 *v = bpf_map_lookup_elem(&drop_reasons, &reason);
    if (v) {
        *v += 1;
        return 0;
    }
    __u64 one = 1;
    bpf_map_update_elem(&drop_reasons, &reason, &one, BPF_NOEXIST);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
