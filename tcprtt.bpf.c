#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// for the definition of the type shared between user and kernel
#include "tcprtt.h"

#include "bpf_tracing_net.h"

// Define the ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);  // Adjust buffer size as needed
} rb SEC(".maps");

// Define the eBPF program to monitor TCP RTT
SEC("fentry/tcp_rcv_established")
int BPF_PROG(tcp_rcv, struct sock *sk) {
    // Only handle IPv4 packets
    if (sk->__sk_common.skc_family != AF_INET)
        return 0;

    // Reserve space in the ring buffer for a new event
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;  // Allocation failed

    // Fill in the event structure
    e->pid = bpf_get_current_pid_tgid() >> 32;  // Get process ID
    bpf_get_current_comm(&e->comm, sizeof(e->comm));  // Get process command

    // Read source and destination IP addresses and ports
    e->saddr = sk->__sk_common.skc_rcv_saddr;
    e->daddr = sk->__sk_common.skc_daddr;
    e->sport = bpf_ntohs(sk->__sk_common.skc_num);
    e->dport = bpf_ntohs(sk->__sk_common.skc_dport);

    // Get RTT from the TCP socket structure
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    e->rtt = BPF_CORE_READ(tp, srtt_us) >> 3;  // Convert to milliseconds

    // Submit the event to the ring buffer
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
