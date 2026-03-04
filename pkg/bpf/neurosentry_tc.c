// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0
//
// neurosentry_tc.c - TC (Traffic Control) eBPF program for Network Monitoring
//
// This program uses TC (Traffic Control) instead of XDP for better compatibility
// with cloud environments like AWS EC2. TC works at a higher level in the
// network stack and has broader driver support.
//
// MONITOR-ONLY MODE: This program never drops packets, only monitors them.

//go:build ignore
// +build ignore

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -Wno-visibility" NeuroSentryTC ./neurosentry_tc.c -- -I./headers

#include "vmlinux.h"

// ============================================================================
// Type Definitions
// ============================================================================

#ifndef __u8
typedef unsigned char __u8;
#endif
#ifndef __u16
typedef unsigned short __u16;
#endif
#ifndef __u32
typedef unsigned int __u32;
#endif
#ifndef __u64
typedef unsigned long long __u64;
#endif

// ============================================================================
// BPF Helper Definitions
// ============================================================================

#define SEC(NAME) __attribute__((section(NAME), used))
#define __always_inline inline __attribute__((always_inline))

// TC return codes
#define TC_ACT_OK       0
#define TC_ACT_SHOT     2
#define TC_ACT_UNSPEC   -1

// Map types
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_ANY 0

// Protocol constants
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// Map helper macros
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

// Endian conversion
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_ntohl(x) __builtin_bswap32(x)

// BPF helpers
static void *(*bpf_map_lookup_elem)(void *map, void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, void *key, void *value, __u64 flags) = (void *)2;
static void *(*bpf_ringbuf_reserve)(void *map, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_skb_load_bytes)(const void *skb, __u32 offset, void *to, __u32 len) = (void *)26;

// ============================================================================
// License and Maps
// ============================================================================

char LICENSE[] SEC("license") = "GPL";

#define MAX_ALLOWED_IPS 256

// Network event for userspace
struct network_event {
    __u64 timestamp;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u8 direction;  // 0 = ingress, 1 = egress
    __u8 suspicious;
    __u8 pad;
    char reason[32];
};

// TC statistics
struct ns_tc_stats {
    __u64 total_packets;
    __u64 ingress_packets;
    __u64 egress_packets;
    __u64 suspicious_packets;
    __u64 bytes_in;
    __u64 bytes_out;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ns_tc_stats);
} ns_tc_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ALLOWED_IPS);
    __type(key, __u32);
    __type(value, __u8);
} blocked_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024);
} tc_events SEC(".maps");

// ============================================================================
// Helper Functions
// ============================================================================

static __always_inline void update_stats(__u8 direction, __u32 len, __u8 suspicious)
{
    __u32 key = 0;
    struct ns_tc_stats *stats = bpf_map_lookup_elem(&ns_tc_stats_map, &key);
    if (!stats) return;

    __sync_fetch_and_add(&stats->total_packets, 1);

    if (direction == 0) {
        __sync_fetch_and_add(&stats->ingress_packets, 1);
        __sync_fetch_and_add(&stats->bytes_in, len);
    } else {
        __sync_fetch_and_add(&stats->egress_packets, 1);
        __sync_fetch_and_add(&stats->bytes_out, len);
    }

    if (suspicious) {
        __sync_fetch_and_add(&stats->suspicious_packets, 1);
    }
}

static __always_inline void send_event(__u32 saddr, __u32 daddr,
                                        __u16 sport, __u16 dport,
                                        __u8 protocol, __u8 direction,
                                        __u8 suspicious)
{
    struct network_event *e = bpf_ringbuf_reserve(&tc_events, sizeof(*e), 0);
    if (!e) return;

    e->timestamp = bpf_ktime_get_ns();
    e->saddr = saddr;
    e->daddr = daddr;
    e->sport = sport;
    e->dport = dport;
    e->protocol = protocol;
    e->direction = direction;
    e->suspicious = suspicious;
    e->pad = 0;
    __builtin_memset(e->reason, 0, sizeof(e->reason));

    bpf_ringbuf_submit(e, 0);
}

// ============================================================================
// TC Ingress Program - Monitor incoming traffic
// ============================================================================

SEC("tc")
int neurosentry_tc_ingress(struct __sk_buff *skb)
{
    void *data_end = (void *)(__u64)skb->data_end;
    void *data = (void *)(__u64)skb->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        update_stats(0, skb->len, 0);
        return TC_ACT_OK;
    }

    // Only process IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        update_stats(0, skb->len, 0);
        return TC_ACT_OK;
    }

    // Parse IP header
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) {
        update_stats(0, skb->len, 0);
        return TC_ACT_OK;
    }

    __u32 saddr = ip->saddr;
    __u32 daddr = ip->daddr;
    __u8 protocol = ip->protocol;

    // Only monitor TCP/UDP
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
        update_stats(0, skb->len, 0);
        return TC_ACT_OK;
    }

    // Parse L4 header
    __u16 sport = 0, dport = 0;
    void *l4 = data + sizeof(struct ethhdr) + (ip->ihl * 4);

    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end) {
            update_stats(0, skb->len, 0);
            return TC_ACT_OK;
        }
        sport = bpf_ntohs(tcp->source);
        dport = bpf_ntohs(tcp->dest);
    } else {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end) {
            update_stats(0, skb->len, 0);
            return TC_ACT_OK;
        }
        sport = bpf_ntohs(udp->source);
        dport = bpf_ntohs(udp->dest);
    }

    // Check if source is in blocked list (monitor only)
    __u8 suspicious = 0;
    __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &saddr);
    if (blocked && *blocked) {
        suspicious = 1;
        send_event(saddr, daddr, sport, dport, protocol, 0, 1);
    }

    update_stats(0, skb->len, suspicious);

    // ALWAYS pass traffic - monitor only
    return TC_ACT_OK;
}

// ============================================================================
// TC Egress Program - Monitor outgoing traffic
// ============================================================================

SEC("tc")
int neurosentry_tc_egress(struct __sk_buff *skb)
{
    void *data_end = (void *)(__u64)skb->data_end;
    void *data = (void *)(__u64)skb->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        update_stats(1, skb->len, 0);
        return TC_ACT_OK;
    }

    // Only process IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        update_stats(1, skb->len, 0);
        return TC_ACT_OK;
    }

    // Parse IP header
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) {
        update_stats(1, skb->len, 0);
        return TC_ACT_OK;
    }

    __u32 saddr = ip->saddr;
    __u32 daddr = ip->daddr;
    __u8 protocol = ip->protocol;

    // Only monitor TCP/UDP
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
        update_stats(1, skb->len, 0);
        return TC_ACT_OK;
    }

    // Parse L4 header
    __u16 sport = 0, dport = 0;
    void *l4 = data + sizeof(struct ethhdr) + (ip->ihl * 4);

    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end) {
            update_stats(1, skb->len, 0);
            return TC_ACT_OK;
        }
        sport = bpf_ntohs(tcp->source);
        dport = bpf_ntohs(tcp->dest);
    } else {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end) {
            update_stats(1, skb->len, 0);
            return TC_ACT_OK;
        }
        sport = bpf_ntohs(udp->source);
        dport = bpf_ntohs(udp->dest);
    }

    // Check if destination is in blocked list (monitor only)
    __u8 suspicious = 0;
    __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &daddr);
    if (blocked && *blocked) {
        suspicious = 1;
        send_event(saddr, daddr, sport, dport, protocol, 1, 1);
    }

    update_stats(1, skb->len, suspicious);

    // ALWAYS pass traffic - monitor only
    return TC_ACT_OK;
}
