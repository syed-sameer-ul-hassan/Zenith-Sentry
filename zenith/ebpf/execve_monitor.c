#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

BPF_RINGBUF_OUTPUT(events, 256);

BPF_PERF_OUTPUT(event_table);

struct execve_event {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    char comm[16];
    char filename[256];
    u64 timestamp_ns;
    u8 event_type;
};

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct execve_event event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    event.pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event.ppid = 0;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.gid = (bpf_get_current_uid_gid() >> 32) & 0xFFFFFFFF;
    event.timestamp_ns = bpf_ktime_get_ns();
    event.event_type = 1;
    
    bpf_probe_read_kernel_str(&event.comm, sizeof(event.comm), 
                              &task->comm);
    
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename),
                            args->filename);
    
    bpf_ringbuf_output(&events, &event, sizeof(event), 0);
    
    event_table.perf_submit(args, &event, sizeof(event));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_execve) {
    if (args->ret != 0) {
        struct execve_event event = {};
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        
        event.pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
        event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        event.timestamp_ns = bpf_ktime_get_ns();
        event.event_type = 2;
        
        bpf_probe_read_kernel_str(&event.comm, sizeof(event.comm),
                                  &task->comm);
        
        bpf_ringbuf_output(&events, &event, sizeof(event), 0);
    }
    
    return 0;
}
