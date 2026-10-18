// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "knet_tracer.h"

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Map for tracking packet bandwidth and latency per flow at TC egress/ingress
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_id);
    __type(value, __u64); // cumulative byte count
} tc_flow_bytes SEC(".maps");

// TC Ingress Classifier
SEC("classifier/ingress")
int tc_ingress(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    __u32 saddr = ip->saddr;
    __u32 daddr = ip->daddr;
    __u8 proto = ip->protocol;
    __u16 sport = 0;
    __u16 dport = 0;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)((void *)ip + (ip->ihl * 4));
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        sport = bpf_ntohs(tcp->source);
        dport = bpf_ntohs(tcp->dest);
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = (void *)((void *)ip + (ip->ihl * 4));
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        sport = bpf_ntohs(udp->source);
        dport = bpf_ntohs(udp->dest);
    } else {
        return TC_ACT_OK;
    }

    struct flow_id key = {
        .saddr = saddr,
        .daddr = daddr,
        .sport = sport,
        .dport = dport,
        .proto = proto,
    };

    __u64 pkt_len = (__u64)skb->len;
    __u64 *bytes = bpf_map_lookup_elem(&tc_flow_bytes, &key);
    if (bytes) {
        __sync_fetch_and_add(bytes, pkt_len);
    } else {
        bpf_map_update_elem(&tc_flow_bytes, &key, &pkt_len, BPF_ANY);
    }

    return TC_ACT_OK;
}

// TC Egress Classifier
SEC("classifier/egress")
int tc_egress(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    __u32 saddr = ip->saddr;
    __u32 daddr = ip->daddr;
    __u8 proto = ip->protocol;
    __u16 sport = 0;
    __u16 dport = 0;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)((void *)ip + (ip->ihl * 4));
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        sport = bpf_ntohs(tcp->source);
        dport = bpf_ntohs(tcp->dest);
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = (void *)((void *)ip + (ip->ihl * 4));
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        sport = bpf_ntohs(udp->source);
        dport = bpf_ntohs(udp->dest);
    } else {
        return TC_ACT_OK;
    }

    struct flow_id key = {
        .saddr = saddr,
        .daddr = daddr,
        .sport = sport,
        .dport = dport,
        .proto = proto,
    };

    __u64 pkt_len = (__u64)skb->len;
    __u64 *bytes = bpf_map_lookup_elem(&tc_flow_bytes, &key);
    if (bytes) {
        __sync_fetch_and_add(bytes, pkt_len);
    } else {
        bpf_map_update_elem(&tc_flow_bytes, &key, &pkt_len, BPF_ANY);
    }

    return TC_ACT_OK;
}
