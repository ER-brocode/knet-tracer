// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#pragma once

#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

typedef unsigned char  __u8;
typedef unsigned short __u16;
typedef unsigned int   __u32;
typedef unsigned long long __u64;

enum event_type {
    EVENT_TCP_RTT      = 1,
    EVENT_PACKET_DROP  = 2,
    EVENT_SOCKET_STATS = 3,
    EVENT_TCP_STATE    = 4,
};

enum drop_reason {
    DROP_NOT_SPECIFIED = 0,
    DROP_NO_SOCKET     = 1,
    DROP_PKT_TOO_BIG   = 2,
    DROP_TCP_CSUM      = 3,
    DROP_TCP_FILTER    = 4,
    DROP_TCP_ZEROWIN   = 5,
    DROP_TCP_RESET     = 6,
    DROP_QUEUE_PURGE   = 7,
    DROP_NETFILTER     = 8,
};

struct flow_id {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  pad[3];
};

struct tcp_rtt_event {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 pid;
    __u32 tgid;
    __u32 srtt_us;
    __u32 rttvar_us;
    __u32 min_rtt_us;
    __u32 total_retrans;
    char  comm[16];
    __u64 timestamp_ns;
};

struct packet_drop_event {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  pad[3];
    __u32 reason;
    __u64 location;
    char  comm[16];
    __u64 timestamp_ns;
};

struct socket_stats_event {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u64 bytes_acked;
    __u64 bytes_rcvd;
    __u32 snd_cwnd;
    __u32 snd_ssthresh;
    __u32 total_retrans;
    __u32 rcv_buf_bytes;
    __u32 snd_buf_bytes;
    __u8  tcp_state;
    __u8  pad[3];
    __u64 timestamp_ns;
};
