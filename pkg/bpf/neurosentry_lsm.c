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

// Section attribute
#define SEC(NAME) __attribute__((section(NAME), used))

// Correct BPF_PROG variants: BPF programs receive their arguments in a ctx[]
// array (passed as r1), not as direct C arguments. The previous one-line
// `name(args)` macro silently passed the ctx pointer itself as the first arg,
// which made every &file->... probe_read read from random kernel memory and
// fail with EFAULT. These variants pull each declared arg out of ctx[i] and
// forward to the inline implementation. _NARGS dispatches to the right
// arity macro so 1-, 2-, and 3-arg LSM hooks all work.
#define BPF_PROG_PICK(_1, _2, _3, NAME, ...) NAME
#define BPF_PROG(name, ...) BPF_PROG_PICK(__VA_ARGS__, BPF_PROG3, BPF_PROG2, BPF_PROG1)(name, __VA_ARGS__)

#define BPF_PROG1(name, a1)                                               \
    name(unsigned long long *ctx);                                        \
    static __always_inline int ____##name(a1);                            \
    int name(unsigned long long *ctx) {                                   \
        return ____##name((void *)(unsigned long)ctx[0]);                 \
    }                                                                     \
    static __always_inline int ____##name(a1)

#define BPF_PROG2(name, a1, a2)                                           \
    name(unsigned long long *ctx);                                        \
    static __always_inline int ____##name(a1, a2);                        \
    int name(unsigned long long *ctx) {                                   \
        return ____##name((void *)(unsigned long)ctx[0],                  \
                          (unsigned long)ctx[1]);                         \
    }                                                                     \
    static __always_inline int ____##name(a1, a2)

#define BPF_PROG3(name, a1, a2, a3)                                       \
    name(unsigned long long *ctx);                                        \
    static __always_inline int ____##name(a1, a2, a3);                    \
    int name(unsigned long long *ctx) {                                   \
        return ____##name((void *)(unsigned long)ctx[0],                  \
                          (unsigned long)ctx[1],                          \
                          (unsigned long)ctx[2]);                         \
    }                                                                     \
    static __always_inline int ____##name(a1, a2, a3)

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

// Protected extensions map. Key: 16-byte zero-padded extension string,
// always starting with `.` (e.g. ".safetensors\0\0\0\0"). Value: unused
// (presence = protected). The hook looks up the file's actual extension
// against this map, so adding/removing extensions in YAML now actually
// changes what the kernel blocks.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, char[16]);
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

// Helper function to check if filename ends with a protected extension.
// Returns 1 if the file's extension is in the protected_extensions BPF map,
// 0 otherwise. The map is populated by the user-space agent from YAML,
// so the set of blocked extensions is data-driven and editable at runtime
// (via SIGHUP) without rebuilding the BPF object.
static __always_inline int is_protected_file(const char *filename, int len)
{
    // Need at least ".X" (2 chars) for any extension to make sense
    if (len < 2) return 0;

    // Find the LAST '.' in the bounded filename window (bounded forward scan
    // — the verifier requires a constant upper bound, can't loop backward
    // from a variable index).
    int last_dot = -1;
    // Bounded loop, no #pragma unroll — verifier handles it natively
    // since kernel 5.3+ and unrolling 256 iterations explodes the program
    // size past the 1M-insn verifier limit.
    for (int i = 0; i < 256; i++) {
        if (i >= len) break;
        if (filename[i] == '.') last_dot = i;
    }
    if (last_dot < 0) return 0;  // no '.' anywhere => no extension

    // Length of the extension (including the dot itself)
    int ext_len = len - last_dot;
    if (ext_len > 15) return 0;  // 15-char extension cap (16-byte key incl. NUL)

    // Copy the extension into a 16-byte zero-padded fixed buffer for the
    // hash map lookup. Keys in protected_extensions are exactly 16 bytes.
    char ext_key[16];
    __builtin_memset(ext_key, 0, sizeof(ext_key));
    #pragma unroll
    for (int i = 0; i < 15; i++) {
        if (i >= ext_len) break;
        ext_key[i] = filename[last_dot + i];
    }

    unsigned char *hit = bpf_map_lookup_elem(&protected_extensions, ext_key);
    return (hit && *hit) ? 1 : 0;
}

// Legacy hard-coded matcher kept for reference / fallback. Not called.
static __always_inline int is_protected_file_legacy(const char *filename, int len)
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

// Helper function to get string length (bounded).
// Bumped from 64 to 256 in v1.1: a 64-byte cap meant any leaf filename
// longer than 63 bytes had its extension truncated off the buffer, so the
// extension matcher silently missed and the hook returned 0 (allow). 256
// covers ~all real model filenames; truly long names beyond 256 chars
// remain a documented limit and require the d_name.len-based scheme on
// the v1.2 punch list.
static __always_inline int bounded_strlen(const char *s, int max)
{
    int len = 0;
    // Bounded loop, no #pragma unroll — verifier handles it natively
    // since kernel 5.3+ and unrolling 256 iterations explodes the program
    // size past the 1M-insn verifier limit.
    for (int i = 0; i < 256; i++) {
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
        for (int i = 0; i < 256; i++) {  // matches MAX_PATH_LEN
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

// LSM hook for file_open — intercepts file open operations.
//
// Design notes (rev 2):
//   * Use the kernel-provided d_name.len rather than scanning for NUL,
//     so the matcher works on filenames of arbitrary length.
//   * Match the file's extension against the data-driven
//     protected_extensions BPF map (16-byte zero-padded keys, populated
//     by the user-space agent from YAML).
//   * Read only the LAST 16 bytes of the filename for matching — that's
//     where the extension lives, and limiting the match window to 16
//     bytes keeps the verifier's program-instruction count well under
//     the 1M cap. Earlier rev tried 256-byte loops and the verifier
//     rejected with "BPF program is too large".
//   * Read up to 64 bytes of the filename for the audit event payload
//     (truncated for forensics; full path reconstruction is the agent's
//     job via PID + comm + cwd).
SEC("lsm/file_open")
int BPF_PROG(restrict_model_file_access, struct file *file)
{
    unsigned int pid = bpf_get_current_pid_tgid() >> 32;

    // Trusted PID? Allow.
    unsigned char *trusted = bpf_map_lookup_elem(&trusted_pids, &pid);
    if (trusted && *trusted) {
        return 0;
    }

    // Walk file -> f_path.dentry -> d_name to get the filename pointer + length.
    struct dentry *dentry = NULL;
    bpf_probe_read_kernel(&dentry, sizeof(dentry), &file->f_path.dentry);
    if (!dentry) return 0;

    struct qstr d_name;
    bpf_probe_read_kernel(&d_name, sizeof(d_name), &dentry->d_name);
    if (!d_name.name || d_name.len < 2) return 0;

    // Cap real_len so the verifier can reason about derived offsets.
    unsigned int real_len = d_name.len;
    if (real_len > 4096) real_len = 4096;

    // ----- Tail read for extension matching: always read exactly 16 bytes -----
    // For names shorter than 16, this reads a few bytes of adjacent kernel
    // memory (still mapped — qstr->name points into a kmalloc'd buffer with
    // the ext4/tmpfs/etc dentry name; even if we read past the trailing NUL
    // we stay on the same page). For names >= 16 we read the LAST 16 bytes.
    // Constant-size reads keep the verifier happy.
    char tail[16];
    __builtin_memset(tail, 0, sizeof(tail));
    unsigned int tail_off = (real_len >= 16) ? (real_len - 16) : 0;
    bpf_probe_read_kernel(tail, 16, (const char *)d_name.name + tail_off);

    // For very short names, only the leading `real_len` bytes of `tail` are
    // actually filename data — the rest is undefined. Compute the boundary.
    unsigned int valid_in_tail = (real_len >= 16) ? 16 : real_len;

    // Find last '.' inside the valid portion of tail.
    int last_dot = -1;
    for (int i = 0; i < 16; i++) {
        if ((unsigned int)i >= valid_in_tail) break;
        if (tail[i] == '.') last_dot = i;
    }
    if (last_dot < 0) return 0;  // no extension in the last 16 bytes

    // Build the 16-byte zero-padded extension key. last_dot in [0,15];
    // src_idx capped at <16 so tail[src_idx] is in-bounds.
    char ext_key[16];
    __builtin_memset(ext_key, 0, sizeof(ext_key));
    for (int i = 0; i < 16; i++) {
        unsigned int src_idx = (unsigned int)(last_dot + i);
        if (src_idx >= 16) break;
        if (src_idx >= valid_in_tail) break;
        ext_key[i] = tail[src_idx];
    }

    unsigned char *hit = bpf_map_lookup_elem(&protected_extensions, ext_key);
    if (!hit || !*hit) return 0;  // extension not in protected map => allow

    // ----- Match. Read a small filename buffer for the event payload. -----
    char filename[64];
    __builtin_memset(filename, 0, sizeof(filename));
    bpf_probe_read_kernel(filename, 64, d_name.name);

    // Enforce or audit?
    unsigned int cfg_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);

    send_event_with_filename(EVENT_FILE_BLOCKED, filename, 64);
    update_stats(1);

    if (cfg && cfg->enforce_mode) {
        return -EPERM;
    }
    return 0;  // audit-only mode
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
