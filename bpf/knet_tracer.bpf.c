// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "knet_tracer.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Ring buffer for pushing high-velocity telemetry events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024); // 16MB ring buffer
} events SEC(".maps");

// Per-CPU Hash map for tracking active TCP socket statistics
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_id);
    __type(value, struct socket_stats_event);
} active_flows SEC(".maps");

// Rate limit map to avoid event floods on packet drops
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32); // drop reason
    __type(value, __u64); // last dropped timestamp_ns
} drop_ratelimit SEC(".maps");

// Probe 1: tcp_rcv_established - Called when incoming packet is processed on an established connection
SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(trace_tcp_rcv_established, struct sock *sk)
{
    if (!sk)
        return 0;

    struct inet_sock *inet = (struct inet_sock *)sk;
    struct tcp_sock *tp = (struct tcp_sock *)sk;

    // Check IPv4 AF_INET
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != 2) // AF_INET
        return 0;

    __u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __u16 sport = bpf_ntohs(BPF_CORE_READ(inet, inet_sport));
    __u16 dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    // srtt_us is stored scaled by 8 in kernel: tp->srtt_us >> 3
    __u32 srtt = BPF_CORE_READ(tp, srtt_us) >> 3;
    __u32 rttvar = BPF_CORE_READ(tp, mdev_us) >> 2;
    __u32 min_rtt = BPF_CORE_READ(tp, rtt_min.s[0].v);
    if (min_rtt == ~0U) {
        min_rtt = srtt;
    }

    struct tcp_rtt_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->saddr = saddr;
    evt->daddr = daddr;
    evt->sport = sport;
    evt->dport = dport;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid = (__u32)(pid_tgid >> 32);
    evt->tgid = (__u32)pid_tgid;

    evt->srtt_us = srtt;
    evt->rttvar_us = rttvar;
    evt->min_rtt_us = min_rtt;
    evt->total_retrans = BPF_CORE_READ(tp, total_retrans);
    evt->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    bpf_ringbuf_submit(evt, 0);

    // Update active socket stats map
    struct flow_id key = {
        .saddr = saddr,
        .daddr = daddr,
        .sport = sport,
        .dport = dport,
        .proto = IPPROTO_TCP,
    };

    struct socket_stats_event stats = {
        .saddr = saddr,
        .daddr = daddr,
        .sport = sport,
        .dport = dport,
        .bytes_acked = BPF_CORE_READ(tp, bytes_acked),
        .bytes_rcvd = BPF_CORE_READ(tp, bytes_received),
        .snd_cwnd = BPF_CORE_READ(tp, snd_cwnd),
        .snd_ssthresh = BPF_CORE_READ(tp, snd_ssthresh),
        .total_retrans = evt->total_retrans,
        .rcv_buf_bytes = BPF_CORE_READ(sk, sk_rcvbuf),
        .snd_buf_bytes = BPF_CORE_READ(sk, sk_sndbuf),
        .tcp_state = BPF_CORE_READ(sk, __sk_common.skc_state),
        .timestamp_ns = evt->timestamp_ns,
    };
    bpf_map_update_elem(&active_flows, &key, &stats, BPF_ANY);

    return 0;
}

// Probe 2: tracepoint/skb/kfree_skb - Captures kernel packet drops with drop reason
SEC("tracepoint/skb/kfree_skb")
int trace_kfree_skb(struct trace_event_raw_kfree_skb *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    if (!skb)
        return 0;

    void *head = BPF_CORE_READ(skb, head);
    __u16 network_header = BPF_CORE_READ(skb, network_header);
    struct iphdr ip;

    // Read IPv4 Header
    if (bpf_core_read(&ip, sizeof(ip), head + network_header) < 0)
        return 0;

    if (ip.version != 4)
        return 0;

    __u32 saddr = ip.saddr;
    __u32 daddr = ip.daddr;
    __u16 sport = 0;
    __u16 dport = 0;

    if (ip.protocol == IPPROTO_TCP) {
        struct tcphdr tcp;
        __u16 transport_header = BPF_CORE_READ(skb, transport_header);
        if (bpf_core_read(&tcp, sizeof(tcp), head + transport_header) == 0) {
            sport = bpf_ntohs(tcp.source);
            dport = bpf_ntohs(tcp.dest);
        }
    } else if (ip.protocol == IPPROTO_UDP) {
        struct udphdr udp;
        __u16 transport_header = BPF_CORE_READ(skb, transport_header);
        if (bpf_core_read(&udp, sizeof(udp), head + transport_header) == 0) {
            sport = bpf_ntohs(udp.source);
            dport = bpf_ntohs(udp.dest);
        }
    }

    __u32 reason = ctx->reason;
    __u64 now = bpf_ktime_get_ns();

    // Rate limiting: skip if dropped within 50 microseconds for same reason
    __u64 *last_drop = bpf_map_lookup_elem(&drop_ratelimit, &reason);
    if (last_drop && (now - *last_drop < 50000)) {
        return 0;
    }
    bpf_map_update_elem(&drop_ratelimit, &reason, &now, BPF_ANY);

    struct packet_drop_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->saddr = saddr;
    evt->daddr = daddr;
    evt->sport = sport;
    evt->dport = dport;
    evt->proto = ip.protocol;
    evt->reason = reason;
    evt->location = (unsigned long)ctx->location;
    evt->timestamp_ns = now;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// Probe 3: tcp_set_state - Tracks TCP state machine transitions (SYN_SENT, ESTABLISHED, CLOSE_WAIT, etc.)
SEC("kprobe/tcp_set_state")
int BPF_KPROBE(trace_tcp_set_state, struct sock *sk, int state)
{
    if (!sk)
        return 0;

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != 2) // AF_INET
        return 0;

    struct inet_sock *inet = (struct inet_sock *)sk;
    __u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __u16 sport = bpf_ntohs(BPF_CORE_READ(inet, inet_sport));
    __u16 dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    struct flow_id key = {
        .saddr = saddr,
        .daddr = daddr,
        .sport = sport,
        .dport = dport,
        .proto = IPPROTO_TCP,
    };

    if (state == 7 /* TCP_CLOSE */) {
        bpf_map_delete_elem(&active_flows, &key);
    }

    return 0;
}
