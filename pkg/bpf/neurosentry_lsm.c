// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0
//
// neurosentry_lsm.c - LSM BPF hooks for Model File Integrity Monitoring
//
// This eBPF program attaches to LSM (Linux Security Module) hooks to monitor
// and control access to AI model weight files at the kernel level.
//
// COMPILATION INSTRUCTIONS:
// 1. Generate vmlinux.h from BTF: bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
// 2. Compile: clang -target bpf -g -O2 -I. -c neurosentry_lsm.c -o neurosentry_lsm.o
// 3. Load: sudo bpftool prog load neurosentry_lsm.o /sys/fs/bpf/neurosentry_lsm

//go:build ignore
// +build ignore

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -Wno-visibility" NeuroSentryLSM ./neurosentry_lsm.c -- -I./headers

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

// Linux constants
#define EPERM 1
#define MAY_READ 4
#define MAY_WRITE 2
#define MAY_EXEC 1
#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4

#define MAX_PATH_LEN 256
#define TASK_COMM_LEN 16

// Event types for ring buffer
#define EVENT_FILE_ACCESS 1
#define EVENT_FILE_BLOCKED 2

// Section attribute and BPF_PROG macro
#define SEC(NAME) __attribute__((section(NAME), used))
#define BPF_PROG(name, args...) name(args)

// BPF helper function declarations
// Correct function IDs from /usr/include/bpf/bpf_helper_defs.h
static void *(*bpf_map_lookup_elem)(void *map, void *key) = (void *)1;
static void *(*bpf_ringbuf_reserve)(void *map, unsigned long long size, unsigned long long flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, unsigned long long flags) = (void *)132;
static long (*bpf_get_current_comm)(void *buf, unsigned long long size) = (void *)16;
static long (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*bpf_get_current_uid_gid)(void) = (void *)15;
static long long (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_probe_read_kernel_str)(void *dst, unsigned int size, const void *unsafe_ptr) = (void *)115;
static long (*bpf_probe_read_kernel)(void *dst, unsigned int size, const void *unsafe_ptr) = (void *)113;

// Map definition helper macros for BTF-style maps
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

// Inline attributes for BPF functions
#define __always_inline inline __attribute__((always_inline))

// NULL definition for BPF programs
#ifndef NULL
#define NULL ((void *)0)
#endif

// ============================================================================
// Program Sections and Maps
// ============================================================================

char LICENSE[] SEC("license") = "GPL";

// Model file access event
struct model_access_event {
    unsigned int pid;
    unsigned int uid;
    unsigned long long timestamp;
    unsigned int event_type;  // EVENT_FILE_ACCESS or EVENT_FILE_BLOCKED
    char comm[TASK_COMM_LEN];
    char filename[MAX_PATH_LEN];
};

// Trusted PID map - populated by user space
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, unsigned int);
    __type(value, unsigned char);
} trusted_pids SEC(".maps");

// Protected extensions map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, unsigned int);
    __type(value, unsigned char);
} protected_extensions SEC(".maps");

// Configuration map
struct config {
    unsigned char enforce_mode;     // 1 = block, 0 = audit only
    unsigned char log_all_access;   // 1 = log all, 0 = log only protected
    unsigned char padding[2];
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, struct config);
} config_map SEC(".maps");

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Statistics map
struct stats {
    unsigned long long total_access_attempts;
    unsigned long long blocked_access;
    unsigned long long allowed_access;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, struct stats);
} stats_map SEC(".maps");

// ============================================================================
// LSM Hook Implementation
// ============================================================================

// Helper function to check if filename ends with a protected extension
// Returns 1 if protected, 0 if not
static __always_inline int is_protected_file(const char *filename, int len)
{
    // Check minimum length for extension matching
    if (len < 4) return 0;

    // Check for .safetensors (12 chars)
    if (len >= 12) {
        int offset = len - 12;
        if (filename[offset] == '.' &&
            filename[offset+1] == 's' &&
            filename[offset+2] == 'a' &&
            filename[offset+3] == 'f' &&
            filename[offset+4] == 'e' &&
            filename[offset+5] == 't' &&
            filename[offset+6] == 'e' &&
            filename[offset+7] == 'n' &&
            filename[offset+8] == 's' &&
            filename[offset+9] == 'o' &&
            filename[offset+10] == 'r' &&
            filename[offset+11] == 's')
            return 1;
    }

    // Check for .gguf (5 chars)
    if (len >= 5) {
        int offset = len - 5;
        if (filename[offset] == '.' &&
            filename[offset+1] == 'g' &&
            filename[offset+2] == 'g' &&
            filename[offset+3] == 'u' &&
            filename[offset+4] == 'f')
            return 1;
    }

    // Check for .pth (4 chars)
    if (len >= 4) {
        int offset = len - 4;
        if (filename[offset] == '.' &&
            filename[offset+1] == 'p' &&
            filename[offset+2] == 't' &&
            filename[offset+3] == 'h')
            return 1;
    }

    // Check for .onnx (5 chars)
    if (len >= 5) {
        int offset = len - 5;
        if (filename[offset] == '.' &&
            filename[offset+1] == 'o' &&
            filename[offset+2] == 'n' &&
            filename[offset+3] == 'n' &&
            filename[offset+4] == 'x')
            return 1;
    }

    // Check for .pt (3 chars)
    if (len >= 3) {
        int offset = len - 3;
        if (filename[offset] == '.' &&
            filename[offset+1] == 'p' &&
            filename[offset+2] == 't')
            return 1;
    }

    // Check for .h5 (3 chars) - Keras models
    if (len >= 3) {
        int offset = len - 3;
        if (filename[offset] == '.' &&
            filename[offset+1] == 'h' &&
            filename[offset+2] == '5')
            return 1;
    }

    return 0;
}

// Helper function to get string length (bounded)
static __always_inline int bounded_strlen(const char *s, int max)
{
    int len = 0;
    #pragma unroll
    for (int i = 0; i < 64; i++) {  // Max 64 chars for extension checking
        if (i >= max) break;
        if (s[i] == '\0') break;
        len++;
    }
    return len;
}

// Helper function to send event to ring buffer
static __always_inline void send_event_with_filename(unsigned int event_type, const char *filename, int fname_len)
{
    unsigned int pid = bpf_get_current_pid_tgid() >> 32;
    unsigned int uid = bpf_get_current_uid_gid();

    struct model_access_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;

    e->pid = pid;
    e->uid = uid;
    e->timestamp = bpf_ktime_get_ns();
    e->event_type = event_type;

    // Get process name
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Copy filename if provided
    __builtin_memset(e->filename, 0, sizeof(e->filename));
    if (filename && fname_len > 0) {
        // Bound the copy length
        int copy_len = fname_len;
        if (copy_len > MAX_PATH_LEN - 1)
            copy_len = MAX_PATH_LEN - 1;
        #pragma unroll
        for (int i = 0; i < 64; i++) {  // Unroll limit for verifier
            if (i >= copy_len) break;
            e->filename[i] = filename[i];
        }
    }

    bpf_ringbuf_submit(e, 0);
}

// Legacy helper for compatibility
static __always_inline void send_event(unsigned int event_type)
{
    send_event_with_filename(event_type, NULL, 0);
}

// Helper function to update statistics
static __always_inline void update_stats(unsigned char blocked)
{
    unsigned int key = 0;
    struct stats *stats = bpf_map_lookup_elem(&stats_map, &key);
    if (!stats) return;

    // Use __sync builtins (now safe since struct is not packed)
    __sync_fetch_and_add(&stats->total_access_attempts, 1);
    if (blocked) {
        __sync_fetch_and_add(&stats->blocked_access, 1);
    } else {
        __sync_fetch_and_add(&stats->allowed_access, 1);
    }
}

// LSM hook for file_open - Intercepts file open operations
SEC("lsm/file_open")
int BPF_PROG(restrict_model_file_access, struct file *file)
{
    unsigned int pid = bpf_get_current_pid_tgid() >> 32;

    // Check if PID is trusted - trusted processes always allowed
    unsigned char *trusted = bpf_map_lookup_elem(&trusted_pids, &pid);
    if (trusted && *trusted) {
        return 0;  // Allow trusted processes
    }

    // Extract filename from file->f_path.dentry->d_name.name
    // Using CO-RE style access
    char filename[64];
    __builtin_memset(filename, 0, sizeof(filename));

    // Access the dentry from file path
    struct dentry *dentry = NULL;
    struct qstr d_name;
    const unsigned char *name_ptr = NULL;

    // Read dentry pointer from file->f_path.dentry
    bpf_probe_read_kernel(&dentry, sizeof(dentry), &file->f_path.dentry);
    if (!dentry) {
        // Can't read dentry, allow access
        return 0;
    }

    // Read d_name from dentry
    bpf_probe_read_kernel(&d_name, sizeof(d_name), &dentry->d_name);

    // Read the name pointer
    bpf_probe_read_kernel(&name_ptr, sizeof(name_ptr), &d_name.name);

    // Read the actual filename string
    if (name_ptr) {
        bpf_probe_read_kernel_str(filename, sizeof(filename), name_ptr);
    }

    // Check if this is a protected file type
    int fname_len = bounded_strlen(filename, sizeof(filename));
    if (fname_len == 0 || !is_protected_file(filename, fname_len)) {
        // Not a protected file type, allow access
        return 0;
    }

    // This is a protected model file being accessed by untrusted process
    // Check config for enforce mode
    unsigned int cfg_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);

    // Send event for blocked access with filename
    send_event_with_filename(EVENT_FILE_BLOCKED, filename, fname_len);
    update_stats(1);

    // If enforce mode is enabled, block the access
    if (cfg && cfg->enforce_mode) {
        return -EPERM;  // Permission denied
    }

    // Audit mode - log but allow
    return 0;
}

// LSM hook for file_permission - Monitors read operations on open files
// Note: DISABLED due to verifier issues on kernel 6.14
// The file_open hook provides sufficient coverage for file access monitoring
// SEC("lsm/file_permission")
int BPF_PROG(monitor_model_file_read, struct file *file, int mask)
{
    // Use local variable to avoid verifier issues
    int local_mask = mask;
    unsigned int read_check = MAY_READ;

    // Only care about read operations
    if (!(local_mask & read_check)) return 0;

    unsigned int pid = bpf_get_current_pid_tgid() >> 32;

    // Check if PID is trusted
    unsigned char *trusted = bpf_map_lookup_elem(&trusted_pids, &pid);
    if (trusted && *trusted) {
        return 0;  // Allow trusted processes
    }

    // Log the access attempt
    send_event(EVENT_FILE_ACCESS);

    return 0;
}

// LSM hook for mmap - Catches memory-mapped file access (common for large models)
// Note: DISABLED due to verifier issues on kernel 6.14
// The file_open hook provides sufficient coverage for file access monitoring
// SEC("lsm/mmap_file")
int BPF_PROG(monitor_model_mmap, struct file *file,
             unsigned long prot, unsigned long flags)
{
    // Use local variables to avoid verifier issues
    unsigned long local_prot = prot;
    unsigned long read_check = PROT_READ;

    // Only care about read/exec mappings
    if (!(local_prot & read_check)) return 0;

    unsigned int pid = bpf_get_current_pid_tgid() >> 32;

    // Check if PID is trusted
    unsigned char *trusted = bpf_map_lookup_elem(&trusted_pids, &pid);
    if (trusted && *trusted) {
        return 0;  // Allow trusted processes
    }

    // Log the access attempt
    send_event(EVENT_FILE_ACCESS);

    return 0;
}
