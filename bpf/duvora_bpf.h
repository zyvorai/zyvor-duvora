// SPDX-License-Identifier: Apache-2.0
// Shared prelude for Duvora's eBPF objects: no libbpf headers, no vmlinux.h.
#ifndef DUVORA_BPF_H
#define DUVORA_BPF_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)BPF_FUNC_map_update_elem;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static long (*bpf_skb_load_bytes)(const void *skb, __u32 offset, void *to, __u32 len) = (void *)BPF_FUNC_skb_load_bytes;

#define DV_AF_INET 4u
#define DV_AF_INET6 6u

struct dv_vlan_hdr {
    __be16 tci;
    __be16 encap_proto;
};

// One parsed IP packet. `first_frag` is 0 for non-first fragments (no L4 header).
struct dv_packet {
    __u8 family;
    __u8 protocol;
    __u8 has_ports;
    __u8 first_frag;
    __u8 tcp_flags; // bit0 SYN, bit1 ACK
    __u8 pad;
    __u16 payload_off; // L4 payload offset from the frame start; 0 when unknown
    __u16 sport;
    __u16 dport;
    __u8 saddr[16];
    __u8 daddr[16];
};

#define DV_TCP_SYN 1u
#define DV_TCP_ACK 2u

static __always_inline void dv_ports(void *data, void *l4, void *end, struct dv_packet *p)
{
    if (p->protocol == IPPROTO_TCP) {
        struct tcphdr *t = l4;
        if ((void *)(t + 1) > end)
            return;
        p->sport = __builtin_bswap16(t->source);
        p->dport = __builtin_bswap16(t->dest);
        p->tcp_flags = (t->syn ? DV_TCP_SYN : 0) | (t->ack ? DV_TCP_ACK : 0);
        p->has_ports = 1;
        p->payload_off = (__u16)((l4 - data) + (__u32)t->doff * 4);
    } else if (p->protocol == IPPROTO_UDP) {
        struct udphdr *u = l4;
        if ((void *)(u + 1) > end)
            return;
        p->sport = __builtin_bswap16(u->source);
        p->dport = __builtin_bswap16(u->dest);
        p->has_ports = 1;
        p->payload_off = (__u16)((void *)(u + 1) - data);
    }
}

// Ethernet (up to two VLAN tags), IPv4 or IPv6. Returns 0 for anything else.
static __always_inline int dv_parse(struct __sk_buff *skb, struct dv_packet *p)
{
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end)
        return 0;
    void *cur = eth + 1;
    __u16 proto = __builtin_bswap16(eth->h_proto);
#pragma unroll
    for (int i = 0; i < 2; i++) {
        if (proto != 0x8100 && proto != 0x88a8)
            break;
        struct dv_vlan_hdr *v = cur;
        if ((void *)(v + 1) > end)
            return 0;
        proto = __builtin_bswap16(v->encap_proto);
        cur = v + 1;
    }
    p->first_frag = 1;
    if (proto == ETH_P_IP) {
        struct iphdr *ip = cur;
        if ((void *)(ip + 1) > end || ip->ihl < 5)
            return 0;
        p->family = DV_AF_INET;
        p->protocol = ip->protocol;
        __builtin_memcpy(p->saddr, &ip->saddr, 4);
        __builtin_memcpy(p->daddr, &ip->daddr, 4);
        if (__builtin_bswap16(ip->frag_off) & 0x1fff) {
            p->first_frag = 0;
            return 1;
        }
        dv_ports(data, (void *)ip + (__u32)ip->ihl * 4, end, p);
        return 1;
    }
    if (proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = cur;
        if ((void *)(ip6 + 1) > end)
            return 0;
        p->family = DV_AF_INET6;
        p->protocol = ip6->nexthdr;
        __builtin_memcpy(p->saddr, ip6->saddr.in6_u.u6_addr8, 16);
        __builtin_memcpy(p->daddr, ip6->daddr.in6_u.u6_addr8, 16);
        dv_ports(data, ip6 + 1, end, p);
        return 1;
    }
    return 0;
}

#endif
