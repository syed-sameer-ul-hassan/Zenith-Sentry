#ifdef __BCC__
#include <uapi/linux/ptrace.h>
#include <linux/types.h>
#include <linux/ktime.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/sched.h>
#else
#define __common_types_only
#endif
#ifndef u32
typedef unsigned int u32;
#endif
#ifndef u64
typedef unsigned long long u64;
#endif
#ifndef u16
typedef unsigned short u16;
#endif
#ifndef u8
typedef unsigned char u8;
#endif
#ifndef TRACEPOINT_PROBE
#define TRACEPOINT_PROBE(category, event) int tp_##category##_##event(struct category##_##event##_args *args)
#endif
#ifndef BPF_PERF_OUTPUT
#define BPF_PERF_OUTPUT(name) struct { int (*perf_submit)(void *, void *, int); } name
#endif
#ifndef BPF_RINGBUF_OUTPUT
#define BPF_RINGBUF_OUTPUT(name, pages) struct { void* (*ringbuf_reserve)(int); void (*ringbuf_submit)(void*, int); void (*ringbuf_discard)(void*, int); int (*ringbuf_output)(void*, int, int); } name
#endif
#ifndef bpf_get_current_pid_tgid
static inline u64 bpf_get_current_pid_tgid(void) { return 0; }
#endif
#ifndef bpf_get_current_uid_gid
static inline u64 bpf_get_current_uid_gid(void) { return 0; }
#endif
#ifndef bpf_ktime_get_ns
static inline u64 bpf_ktime_get_ns(void) { return 0; }
#endif
#ifndef bpf_get_current_task
static inline u64 bpf_get_current_task(void) { return 0; }
#endif
#ifndef bpf_probe_read_kernel_str
static inline int bpf_probe_read_kernel_str(void *dst, int size, const void *unsafe_ptr) { return 0; }
#endif
#ifndef bpf_probe_read_user_str
static inline int bpf_probe_read_user_str(void *dst, int size, const void *unsafe_ptr) { return 0; }
#endif
#ifndef bpf_probe_read_kernel
static inline int bpf_probe_read_kernel(void *dst, int size, const void *unsafe_ptr) { return 0; }
#endif
#ifndef ntohs
static inline u16 ntohs(u16 netshort) { return 0; }
#endif
#ifndef struct_task_struct
struct task_struct {
    char comm[16];
};
#endif
#ifndef struct_sock
struct sock {
    struct {
        u32 skc_daddr;
        u16 skc_dport;
    } __sk_common;
};
#endif
#ifndef struct_syscalls_sys_enter_execve_args
struct syscalls_sys_enter_execve_args {
    unsigned long unused;
    const char *filename;
};
#endif
#ifndef struct_syscalls_sys_exit_execve_args
struct syscalls_sys_exit_execve_args {
    unsigned long unused;
    long ret;
};
#endif
#ifndef struct_pt_regs
struct pt_regs {
    unsigned long unused;
};
#endif
BPF_PERF_OUTPUT(event_table);
BPF_PERF_OUTPUT(connect_events);
struct execve_event {
    u32 pid;
    u32 tgid;
    u32 ppid;
    u32 uid;
    u32 gid;
    char comm[16];
    char filename[256];
    u64 timestamp_ns;
    u8  event_type;   
};
struct connect_event {
    u32 pid;
    u32 tgid;
    u32 uid;
    u32 daddr;        
    u16 dport;        
    u8  event_type;   
};
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct execve_event event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid  = bpf_get_current_uid_gid();
    event.pid          = pid_tgid >> 32;
    event.tgid         = pid_tgid & 0xFFFFFFFF;
    event.ppid         = 0;          
    event.uid          = uid_gid & 0xFFFFFFFF;
    event.gid          = (uid_gid >> 32) & 0xFFFFFFFF;
    event.timestamp_ns = bpf_ktime_get_ns();
    event.event_type   = 1;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel_str(&event.comm,     sizeof(event.comm),     &task->comm);
    bpf_probe_read_user_str  (&event.filename, sizeof(event.filename), args->filename);
    event_table.perf_submit(args, &event, sizeof(event));
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_execve) {
    if (args->ret != 0) {
        struct execve_event event = {};
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u64 uid_gid  = bpf_get_current_uid_gid();
        event.pid          = pid_tgid >> 32;
        event.tgid         = pid_tgid & 0xFFFFFFFF;
        event.uid          = uid_gid & 0xFFFFFFFF;
        event.timestamp_ns = bpf_ktime_get_ns();
        event.event_type   = 2;
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        bpf_probe_read_kernel_str(&event.comm, sizeof(event.comm), &task->comm);
        event_table.perf_submit(args, &event, sizeof(event));
    }
    return 0;
}
int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    struct connect_event event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid  = bpf_get_current_uid_gid();
    event.pid        = pid_tgid >> 32;
    event.tgid       = pid_tgid & 0xFFFFFFFF;
    event.uid        = uid_gid & 0xFFFFFFFF;
    event.event_type = 3;
    u32 daddr = 0;
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    event.daddr = daddr;
    u16 dport_be = 0;
    bpf_probe_read_kernel(&dport_be, sizeof(dport_be), &sk->__sk_common.skc_dport);
    event.dport = ntohs(dport_be);
    connect_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
