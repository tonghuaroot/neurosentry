// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0
//
// neurosentry_lsm_simple.c - Simplified LSM BPF hooks for testing
//
// This is a simplified version for testing eBPF compilation and loading
//
// COMPILATION INSTRUCTIONS:
// 1. Generate vmlinux.h from BTF: bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
// 2. Compile: clang -target bpf -g -O2 -I. -c neurosentry_lsm_simple.c -o neurosentry_lsm_simple.o
// 3. Load: sudo bpftool prog load neurosentry_lsm_simple.o /sys/fs/bpf/neurosentry_lsm

//go:build ignore
// +build ignore

#include "vmlinux.h"

// ============================================================================
// BPF Helper Definitions (self-contained, no system headers needed)
// ============================================================================

// Map types
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_RINGBUF 27

// Section attribute and BPF_PROG macro
#define SEC(NAME) __attribute__((section(NAME), used))
#define BPF_PROG(name, args...) name(args)

// BPF helper function declarations
// Correct function IDs from /usr/include/bpf/bpf_helper_defs.h
static void *(*bpf_map_lookup_elem)(void *map, void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, void *key, void *value, unsigned long long flags) = (void *)2;
static void *(*bpf_ringbuf_reserve)(void *map, unsigned long long size, unsigned long long flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, unsigned long long flags) = (void *)132;
static void (*bpf_ringbuf_discard)(void *data, unsigned long long flags) = (void *)133;
static long (*bpf_get_current_comm)(void *buf, unsigned long long size) = (void *)16;
static long (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*bpf_printk)(const char *fmt, ...) = (void *)6;

// ============================================================================
// Program Sections and Maps
// ============================================================================

char LICENSE[] SEC("license") = "GPL";

// Simple event structure
struct event {
    unsigned int pid;
    char comm[16];
};

// Map definition helper macros for BTF-style maps
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

// Ring buffer map - BTF-style definition
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

// Trusted PID map - BTF-style definition
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, unsigned int);
    __type(value, unsigned char);
} trusted_pids SEC(".maps");

// ============================================================================
// LSM Hook Implementation
// ============================================================================

// LSM hook for file_open - monitors and controls file access
// The LSM hooks use BPF_PROG macro which generates proper function signatures
SEC("lsm/file_open")
int BPF_PROG(restrict_model_file_access, struct file *file)
{
    unsigned int pid = bpf_get_current_pid_tgid() >> 32;
    char comm[16] = {};

    // Read process name
    bpf_get_current_comm(&comm, sizeof(comm));

    // Check if PID is trusted
    unsigned char *trusted = bpf_map_lookup_elem(&trusted_pids, &pid);
    if (trusted && *trusted) {
        return 0;  // Allow
    }

    // Log the access attempt
    struct event *e = bpf_ringbuf_reserve(&ringbuf, sizeof(struct event), 0);
    if (e) {
        e->pid = pid;
        __builtin_memcpy(e->comm, comm, 16);
        bpf_ringbuf_submit(e, 0);
    }

    // For testing, allow everything
    return 0;
}

// EOF
