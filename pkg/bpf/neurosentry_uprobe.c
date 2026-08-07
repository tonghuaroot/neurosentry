// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0
//
// neurosentry_uprobe.c - Uprobe programs for AI Framework Monitoring
//
// This eBPF program uses user-space probes (uprobes) to monitor AI framework
// internals, such as PyTorch model loading and pickle deserialization.
//
// COMPILATION INSTRUCTIONS:
// 1. Generate vmlinux.h from BTF: bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
// 2. Compile: clang -target bpf -g -O2 -I. -c neurosentry_uprobe.c -o neurosentry_uprobe.o
// 3. Load: sudo bpftool prog load neurosentry_uprobe.o /sys/fs/bpf/neurosentry_uprobe

//go:build ignore
// +build ignore

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -Wno-visibility" NeuroSentryUprobe ./neurosentry_uprobe.c -- -I./headers

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

#define MAX_FUNC_NAME_LEN 128
#define MAX_PATH_LEN 256
#define MAX_STACK_DEPTH 16
#define TASK_COMM_LEN 16
#define BPF_F_USER_STACK (1ULL << 1)

// Event types
#define EVENT_MODEL_LOAD 1
#define EVENT_PICKLE_LOAD 2
#define EVENT_DANGEROUS_PICKLE 3

// Section attribute
#define SEC(NAME) __attribute__((section(NAME), used))

// Architecture-aware first-argument accessor for uprobe context.
//
// Uprobes receive `struct pt_regs *`, whose layout differs per arch (x86_64:
// `di`; arm64: `regs[0]`). We must NOT read that field through vmlinux.h:
// vmlinux.h pushes `preserve_access_index` over every record, so `ctx->di` /
// `ctx->regs[0]` each emit a CO-RE relocation against `struct pt_regs` — the
// one kernel struct whose layout genuinely differs per architecture. When the
// vmlinux.h the object was built against (here: arm64, `regs[]`) doesn't match
// the running kernel (x86_64, `di`), that relocation cannot resolve and the
// program fails to load ("bad CO-RE relocation: invalid func unknown#NNN",
// libbpf poison 0x0BAD2310), silently disabling pickle/PyTorch protection.
//
// Instead we index the context as a raw register array at the architecture's
// fixed offset. This reads a constant offset with NO relocation, so the object
// loads on the target kernel no matter which arch's vmlinux.h built it. Direct
// context reads at a fixed offset are permitted for pt_regs uprobe programs.
// x86_64 pt_regs: `di` is the 15th long (index 14); arm64: `regs[0]` is index 0.
#if defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
  #define PT_REGS_PARM1(ctx) (((const unsigned long *)(ctx))[0])
#else
  #define PT_REGS_PARM1(ctx) (((const unsigned long *)(ctx))[14])
#endif

// BPF helper function declarations.
// NOTE: helper IDs are stable kernel ABI (enum bpf_func_id in include/uapi/linux/bpf.h).
//   112 bpf_probe_read_user      113 bpf_probe_read_kernel
//   114 bpf_probe_read_user_str  115 bpf_probe_read_kernel_str
// The previous 113 here was wrong: it called probe_read_kernel on a user-space
// pointer, which silently fails with -EFAULT on every uprobe invocation.
static void *(*bpf_map_lookup_elem)(void *map, void *key) = (void *)1;
static void *(*bpf_ringbuf_reserve)(void *map, unsigned long long size, unsigned long long flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, unsigned long long flags) = (void *)132;
static long (*bpf_get_current_comm)(void *buf, unsigned long long size) = (void *)16;
static long (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long long (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_get_stack)(void *ctx, void *buf, unsigned long long size, unsigned long long flags) = (void *)67;
static long (*bpf_probe_read_user_str)(void *dst, unsigned long long size, const void *unsafe_ptr) = (void *)114;

// Map definition helper macros for BTF-style maps
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

// Inline attributes for BPF functions
#define __always_inline inline __attribute__((always_inline))

// ============================================================================
// Program Sections and Maps
// ============================================================================

char LICENSE[] SEC("license") = "GPL";

// Model load event
struct model_load_event {
    unsigned int pid;
    unsigned long long timestamp;
    unsigned long long model_size;
    char model_path[MAX_PATH_LEN];
    char comm[TASK_COMM_LEN];
    unsigned char framework;  // 1=PyTorch, 2=TensorFlow, 3=ONNX
    unsigned char model_hash[32];
};

// Pickle load event
struct pickle_event {
    unsigned int pid;
    unsigned long long timestamp;
    char pickle_path[MAX_PATH_LEN];
    char comm[TASK_COMM_LEN];
    unsigned char dangerous;  // 1 if dangerous symbols found
    char stack_trace[MAX_STACK_DEPTH * 8];
};

// Dangerous symbol patterns for pickle bombs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, char[32]);
    __type(value, unsigned char);
} dangerous_symbols SEC(".maps");

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} uprobe_events SEC(".maps");

// Statistics
struct uprobe_stats {
    unsigned long long model_loads_total;
    unsigned long long pickle_loads_total;
    unsigned long long dangerous_pickles;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, struct uprobe_stats);
} uprobe_stats_map SEC(".maps");

// ============================================================================
// Uprobe Program Implementation
// ============================================================================

// Helper function to check for dangerous symbols in stack trace
static __always_inline int check_dangerous_stack(void *ctx)
{
    // Stack trace capture
    unsigned long long ip[MAX_STACK_DEPTH];
    __builtin_memset(ip, 0, sizeof(ip));

    unsigned int nr_stack = bpf_get_stack(ctx, ip,
                                    sizeof(unsigned long long) * MAX_STACK_DEPTH,
                                    BPF_F_USER_STACK);

    if (nr_stack < 1) return 0;

    // Simplified check - in production would do symbolization in user space
    // For now, just check if we have a deep stack (potential indication of complex call chain)
    if (nr_stack > 8) {
        return 1;  // Potentially suspicious
    }

    return 0;
}

// PyTorch torch::load() hook
SEC("uprobe")
int uprobe_torch_load(struct pt_regs *ctx)
{
    unsigned int pid = bpf_get_current_pid_tgid() >> 32;
    unsigned long long timestamp = bpf_ktime_get_ns();

    // Allocate event
    struct model_load_event *e;
    e = bpf_ringbuf_reserve(&uprobe_events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->timestamp = timestamp;
    e->framework = 1;  // PyTorch

    // Get process name
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Read filename argument (first argument: rdi on x86_64, x0 on arm64)
    void *filename_ptr = (void *)PT_REGS_PARM1(ctx);
    if (filename_ptr) {
        bpf_probe_read_user_str(e->model_path, sizeof(e->model_path), filename_ptr);
    }

    e->model_size = 0;
    __builtin_memset(e->model_hash, 0, sizeof(e->model_hash));

    bpf_ringbuf_submit(e, 0);

    // Update stats
    unsigned int key = 0;
    struct uprobe_stats *stats = bpf_map_lookup_elem(&uprobe_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->model_loads_total, 1);
    }

    return 0;
}

// Python pickle.load() hook
SEC("uprobe")
int uprobe_pickle_load(struct pt_regs *ctx)
{
    unsigned int pid = bpf_get_current_pid_tgid() >> 32;
    unsigned long long timestamp = bpf_ktime_get_ns();

    // Allocate event
    struct pickle_event *e;
    e = bpf_ringbuf_reserve(&uprobe_events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->timestamp = timestamp;
    e->dangerous = 0;

    // Get process name
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Clear stack trace buffer
    __builtin_memset(e->stack_trace, 0, sizeof(e->stack_trace));

    // Capture stack trace for analysis
    unsigned long long ip[MAX_STACK_DEPTH];
    unsigned int nr_stack = bpf_get_stack(ctx, ip, sizeof(ip), BPF_F_USER_STACK);

    // Store raw IPs for user-space symbolization
    if (nr_stack > 0) {
        for (unsigned int i = 0; i < nr_stack && i < MAX_STACK_DEPTH; i++) {
            unsigned long long addr = ip[i];
            // Store address in stack trace buffer
            if (i * sizeof(unsigned long long) < sizeof(e->stack_trace)) {
                __builtin_memcpy(e->stack_trace + i * sizeof(unsigned long long), &addr, sizeof(unsigned long long));
            }
        }
    }

    // Check for dangerous patterns
    e->dangerous = check_dangerous_stack(ctx);

    // Update path placeholder
    __builtin_memset(e->pickle_path, 0, sizeof(e->pickle_path));

    // Save dangerous flag before submitting (e becomes invalid after submit)
    unsigned char dangerous = e->dangerous;

    bpf_ringbuf_submit(e, 0);

    // Update stats
    unsigned int key = 0;
    struct uprobe_stats *stats = bpf_map_lookup_elem(&uprobe_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->pickle_loads_total, 1);
        if (dangerous) {
            __sync_fetch_and_add(&stats->dangerous_pickles, 1);
        }
    }

    return 0;
}

// Python __reduce__ hook (often used in pickle exploits)
SEC("uprobe")
int uprobe_pickle_reduce(struct pt_regs *ctx)
{
    // Just log the event - serialization is less suspicious than deserialization
    // but can still be useful to track

    return 0;
}

// TensorFlow SavedModel load hook
SEC("uprobe")
int uprobe_tf_load(struct pt_regs *ctx)
{
    unsigned int pid = bpf_get_current_pid_tgid() >> 32;
    unsigned long long timestamp = bpf_ktime_get_ns();

    struct model_load_event *e;
    e = bpf_ringbuf_reserve(&uprobe_events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->timestamp = timestamp;
    e->framework = 2;  // TensorFlow

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memset(e->model_path, 0, sizeof(e->model_path));
    e->model_size = 0;
    __builtin_memset(e->model_hash, 0, sizeof(e->model_hash));

    bpf_ringbuf_submit(e, 0);

    unsigned int key = 0;
    struct uprobe_stats *stats = bpf_map_lookup_elem(&uprobe_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->model_loads_total, 1);
    }

    return 0;
}

// ONNX Runtime load model hook
SEC("uprobe")
int uprobe_onnx_load(struct pt_regs *ctx)
{
    unsigned int pid = bpf_get_current_pid_tgid() >> 32;
    unsigned long long timestamp = bpf_ktime_get_ns();

    struct model_load_event *e;
    e = bpf_ringbuf_reserve(&uprobe_events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->timestamp = timestamp;
    e->framework = 3;  // ONNX

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memset(e->model_path, 0, sizeof(e->model_path));
    e->model_size = 0;
    __builtin_memset(e->model_hash, 0, sizeof(e->model_hash));

    bpf_ringbuf_submit(e, 0);

    unsigned int key = 0;
    struct uprobe_stats *stats = bpf_map_lookup_elem(&uprobe_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->model_loads_total, 1);
    }

    return 0;
}

// Return probe for torch::load - captures successful load
SEC("uretprobe")
int uretprobe_torch_load(struct pt_regs *ctx)
{
    // The return value would contain the loaded model object
    // We can capture additional information here if needed

    return 0;
}
