// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0
//
// neurosentry_xdp.c - XDP programs for Network Monitoring (MONITOR-ONLY MODE)
//
// This eBPF program attaches to XDP (eXpress Data Path) to MONITOR network
// packets at the driver level. This is a SAFE, monitor-only implementation
// that NEVER blocks traffic - all packets are passed through.
//
// IMPORTANT: This program does NOT filter/block any traffic. It only:
// - Collects packet statistics
// - Monitors for suspicious patterns
// - Reports potential exfiltration attempts
// All traffic is passed through (XDP_PASS) regardless of analysis results.
//
// COMPILATION INSTRUCTIONS:
// 1. Generate vmlinux.h from BTF: bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
// 2. Compile: clang -target bpf -g -O2 -I. -c neurosentry_xdp.c -o neurosentry_xdp.o
// 3. Load: sudo bpftool prog load neurosentry_xdp.o /sys/fs/bpf/neurosentry_xdp

//go:build ignore
// +build ignore

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -Wno-visibility" NeuroSentryXDP ./neurosentry_xdp.c -- -I./headers

#include "vmlinux.h"

// ============================================================================
// Type Definitions for BPF (ensure availability before helper declarations)
// ============================================================================

// Standard fixed-width types if not defined in vmlinux.h
#ifndef __u32
typedef unsigned int __u32;
#endif
#ifndef __u64
typedef unsigned long long __u64;
#endif

// ============================================================================
// BPF Helper Definitions (self-contained, no system headers needed)
// ============================================================================

// Map types
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_RINGBUF 27

// XDP actions - MONITOR MODE ONLY: We only use XDP_PASS
#define XDP_PASS 1
// XDP_DROP removed - this program is monitor-only and never blocks traffic

#define MAX_ALLOWED_IPS 256
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define BPF_ANY 0
#define BPF_NOEXIST 1
#define BPF_EXIST 2

// Protocol constants
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// Section attribute and BPF_PROG macro
#define SEC(NAME) __attribute__((section(NAME), used))

// Endian conversion helpers
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#define bpf_ntohl(x) __builtin_bswap32(x)

// BPF helper function declarations
static void *(*bpf_map_lookup_elem)(void *map, void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, void *key, void *value, unsigned long long flags) = (void *)2;
static void *(*bpf_ringbuf_reserve)(void *map, unsigned long long size, unsigned long long flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, unsigned long long flags) = (void *)132;
static long (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long long (*bpf_ktime_get_ns)(void) = (void *)5;

// Map definition helper macros for BTF-style maps
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

// Inline attributes for BPF functions
#define __always_inline inline __attribute__((always_inline))

// ============================================================================
// Program Sections and Maps
// ============================================================================

char LICENSE[] SEC("license") = "GPL";

// Network event for user space (monitor-only - all traffic passes)
struct network_event {
    unsigned int pid;
    unsigned long long timestamp;
    unsigned int action;         // Always XDP_PASS (monitor mode)
    unsigned int saddr;
    unsigned int daddr;
    unsigned short sport;
    unsigned short dport;
    unsigned char protocol;
    char reason[32];            // Classification reason for monitoring
};

// Allowed IP CIDR ranges (simplified as single IPs for now)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ALLOWED_IPS);
    __type(key, unsigned int);
    __type(value, unsigned char);
} allowed_egress_ips SEC(".maps");

// Blocked IPs (known bad destinations)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ALLOWED_IPS);
    __type(key, unsigned int);
    __type(value, unsigned char);
} blocked_ips SEC(".maps");

// Trusted PIDs that can make any network connection
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, unsigned int);
    __type(value, unsigned char);
} trusted_pids SEC(".maps");

// Configuration
struct xdp_config {
    unsigned char block_exfil;     // Block large outbound transfers
    unsigned int threshold_bytes;  // Threshold for exfil detection
    unsigned char enforce_mode;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, struct xdp_config);
} xdp_config_map SEC(".maps");

// Per-PID connection tracking for exfiltration detection
struct conn_stats {
    unsigned long long egress_bytes;
    unsigned long long ingress_bytes;
    unsigned long long last_update;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, unsigned int);
    __type(value, struct conn_stats);
} conn_stats_map SEC(".maps");

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024);
} network_events SEC(".maps");

// Statistics (monitor-only - no drops)
struct xdp_stats {
    unsigned long long total_packets;
    unsigned long long passed_packets;
    unsigned long long suspicious_packets;  // Renamed: packets that WOULD have been blocked
    unsigned long long exfil_attempts;      // Detected but not blocked (monitor only)
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, struct xdp_stats);
} xdp_stats_map SEC(".maps");

// ============================================================================
// XDP Program Implementation
// ============================================================================

// Helper function to send network event
static __always_inline void send_network_event(struct xdp_md *ctx,
                                                unsigned int action,
                                                unsigned int saddr,
                                                unsigned int daddr,
                                                unsigned short sport,
                                                unsigned short dport,
                                                unsigned char protocol,
                                                const char *reason)
{
    struct network_event *e;
    e = bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
    if (!e) return;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->timestamp = bpf_ktime_get_ns();
    e->action = action;
    e->saddr = saddr;
    e->daddr = daddr;
    e->sport = sport;
    e->dport = dport;
    e->protocol = protocol;

    if (reason) {
        __builtin_memset(e->reason, 0, sizeof(e->reason));
        // Note: bpf_probe_read_kernel_str not available in self-contained mode
        // We'll use a fixed reason string for now
        e->reason[0] = 'X';
    }

    bpf_ringbuf_submit(e, 0);
}

// Helper function to update statistics (monitor-only mode)
static __always_inline void update_xdp_stats(unsigned char suspicious)
{
    unsigned int key = 0;
    struct xdp_stats *stats = bpf_map_lookup_elem(&xdp_stats_map, &key);
    if (!stats) return;

    // Use __sync builtins (now safe since struct is not packed)
    __sync_fetch_and_add(&stats->total_packets, 1);
    __sync_fetch_and_add(&stats->passed_packets, 1);  // Always pass in monitor mode
    if (suspicious) {
        __sync_fetch_and_add(&stats->suspicious_packets, 1);
    }
}

// ============================================================================
// Main XDP Program - MONITOR ONLY MODE
// ============================================================================
// This program NEVER blocks traffic. It only collects statistics and
// monitors for suspicious patterns. All traffic is passed through.
// ============================================================================

SEC("xdp")
int neurosentry_xdp_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        update_xdp_stats(0);
        return XDP_PASS;  // Always pass - even malformed packets
    }

    // Only collect stats for IPv4 TCP/UDP - pass everything else immediately
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        update_xdp_stats(0);
        return XDP_PASS;
    }

    // Parse IP header
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) {
        update_xdp_stats(0);
        return XDP_PASS;
    }

    unsigned int saddr = ip->saddr;
    unsigned int daddr = ip->daddr;
    unsigned char protocol = ip->protocol;

    // Only monitor TCP/UDP - pass all other protocols immediately
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
        update_xdp_stats(0);
        return XDP_PASS;
    }

    // Parse L4 header to get ports for monitoring
    unsigned short sport = 0, dport = 0;
    void *l4_hdr = data + sizeof(struct ethhdr) + (ip->ihl * 4);

    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4_hdr;
        if ((void *)(tcp + 1) > data_end) {
            update_xdp_stats(0);
            return XDP_PASS;
        }
        sport = bpf_ntohs(tcp->source);
        dport = bpf_ntohs(tcp->dest);
    } else {
        struct udphdr *udp = l4_hdr;
        if ((void *)(udp + 1) > data_end) {
            update_xdp_stats(0);
            return XDP_PASS;
        }
        sport = bpf_ntohs(udp->source);
        dport = bpf_ntohs(udp->dest);
    }

    // =========================================================================
    // MONITOR ONLY: Check if this would have been suspicious traffic
    // We track but NEVER block - all paths lead to XDP_PASS
    // =========================================================================

    unsigned char suspicious = 0;

    // Check if destination is in blocked_ips list (for monitoring only)
    unsigned char *blocked = bpf_map_lookup_elem(&blocked_ips, &daddr);
    if (blocked && *blocked) {
        suspicious = 1;
        // Send event for monitoring but DO NOT block
        send_network_event(ctx, XDP_PASS, saddr, daddr, sport, dport,
                          protocol, "blocked_ip_monitor");
    }

    // Check for potential exfiltration patterns (monitor only)
    unsigned int cfg_key = 0;
    struct xdp_config *cfg = bpf_map_lookup_elem(&xdp_config_map, &cfg_key);
    if (cfg && cfg->block_exfil) {
        // Track egress bytes for monitoring
        unsigned int pid = bpf_get_current_pid_tgid() >> 32;
        if (pid != 0) {
            struct conn_stats *stats = bpf_map_lookup_elem(&conn_stats_map, &pid);
            if (!stats) {
                struct conn_stats new_stats = {};
                bpf_map_update_elem(&conn_stats_map, &pid, &new_stats, BPF_ANY);
                stats = bpf_map_lookup_elem(&conn_stats_map, &pid);
            }
            if (stats) {
                unsigned long long packet_size = data_end - data;
                __sync_fetch_and_add(&stats->egress_bytes, packet_size);
                stats->last_update = bpf_ktime_get_ns();

                // Check threshold but only mark as suspicious, don't block
                if (stats->egress_bytes > cfg->threshold_bytes) {
                    suspicious = 1;
                    unsigned int stats_key = 0;
                    struct xdp_stats *xdp_stats = bpf_map_lookup_elem(&xdp_stats_map, &stats_key);
                    if (xdp_stats) {
                        __sync_fetch_and_add(&xdp_stats->exfil_attempts, 1);
                    }
                    send_network_event(ctx, XDP_PASS, saddr, daddr, sport, dport,
                                      protocol, "exfil_monitor");
                }
            }
        }
    }

    // Update statistics
    update_xdp_stats(suspicious);

    // ALWAYS PASS - this is monitor-only mode
    return XDP_PASS;
}
