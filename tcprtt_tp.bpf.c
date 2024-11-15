#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h> // Include this for bpf_ntohs and bpf_htons

#include "tcprtt.h"

#include "bpf_tracing_net.h"

// Define the ring buffer for sending data to user-space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096); // Size of the ring buffer
} rb SEC(".maps");

// Define a hash map to store socket state and timestamps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024); // Maximum number of entries in the hash map
    __type(key, void *);       // Key is the socket address
    __type(value, u64);        // Value is the timestamp (in nanoseconds)
} timestamp_map SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    // Handle IPv4 connections only
    if (ctx->family != AF_INET)
        return 0;

    // Extract the old and new states
    int old_state = ctx->oldstate;
    int new_state = ctx->newstate;

    // Only handle transitions to ESTABLISHED (TCP_ESTABLISHED == 1)
    if (new_state != TCP_ESTABLISHED)
        return 0;

    // Get the current timestamp in nanoseconds
    u64 ts = bpf_ktime_get_ns();

    // Use the socket address as the key
    const void *skaddr = ctx->skaddr;

    bpf_printk("Start") ; 

    if (old_state == TCP_SYN_SENT || old_state == TCP_SYN_RECV) {
        bpf_printk("In") ; 

        // SYN_SENT -> ESTABLISHED or SYN_RECV -> ESTABLISHED transition: calculate RTT

        // Lookup the timestamp for the socket in the hash map
        u64 *start_ts = bpf_map_lookup_elem(&timestamp_map, &skaddr);
        if (start_ts) {
            // Calculate RTT
            u64 rtt_ns = ts - *start_ts;

            // Prepare event for user-space
            struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
            if (!e) {
                return 0; // Allocation failed
            }

            // Populate event structure
            e->pid = bpf_get_current_pid_tgid() >> 32;  // Process ID
            bpf_get_current_comm(&e->comm, sizeof(e->comm)); // Command name
            e->saddr = *((__u32 *)ctx->saddr); // Source IP
            e->daddr = *((__u32 *)ctx->daddr); // Destination IP
            e->sport = bpf_ntohs(ctx->sport); // Source port
            e->dport = bpf_ntohs(ctx->dport); // Destination port
            e->rtt = rtt_ns / 1000000; // Convert RTT to milliseconds

            // Submit the event to the ring buffer
            bpf_ringbuf_submit(e, 0);

            // Remove the entry from the hash map
            bpf_map_delete_elem(&timestamp_map, &skaddr);
        }
    } else if (new_state == TCP_SYN_SENT || new_state == TCP_SYN_RECV) {
        bpf_printk("Updsate") ; 
        // SYN_SENT or SYN_RECV state: store the timestamp in the hash map
        bpf_map_update_elem(&timestamp_map, &skaddr, &ts, BPF_ANY);
    } else if (new_state == TCP_CLOSE) {
        bpf_printk("Close") ; 
        // TCP_CLOSE state: remove any existing entry for the socket
        bpf_map_delete_elem(&timestamp_map, &skaddr);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
