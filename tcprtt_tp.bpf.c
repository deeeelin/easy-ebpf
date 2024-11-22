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

// Main eBPF program attached to the tracepoint
SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
    // Handle IPv4 connections only
    if (ctx->family != AF_INET)
        return 0;

    // Extract the old and new states
    int old_state = ctx->oldstate;
    int new_state = ctx->newstate;
    struct sock *sk = (struct sock*) ctx->skaddr;

    // Get the current timestamp in nanoseconds
    u64 ts = bpf_ktime_get_ns();

    

    // Handle specific state transitions
    if (new_state == TCP_ESTABLISHED) {
        bpf_printk("TTCP Established : old_state = %d, new_state = %d", old_state, new_state);

        if (old_state == TCP_SYN_SENT || old_state == TCP_SYN_RECV) {
            bpf_printk("TTCP Sent , RECV: old_state = %d, new_state = %d", old_state, new_state);
            // Lookup the timestamp for the socket in the hash map
            u64 *start_ts = bpf_map_lookup_elem(&timestamp_map, &sk);
            if (start_ts) {
                bpf_printk("SStart ts RECV: old_state = %d, new_state = %d", old_state, new_state);
                // Calculate RTT
                u64 rtt_ns = ts - *start_ts;

                // Prepare event for user-space
                struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
                if (e) {
                    // Populate event structure
                    e->pid = bpf_get_current_pid_tgid() >> 32;  // Process ID
                    bpf_get_current_comm(&e->comm, sizeof(e->comm)); // Command name
                    e->saddr = *((__u32 *)ctx->saddr); // Source IP
                    e->daddr = *((__u32 *)ctx->daddr); // Destination IP
                    e->sport = ctx->sport; // Source port
                    e->dport = ctx->dport; // Destination port
                    e->rtt = rtt_ns / 1000000; // Convert RTT to milliseconds

                    // Submit the event to the ring buffer
                     // Debug log for all state transitions
                     // Debug log for all state transitions
                    bpf_printk("Transition observed: old_state = %d, new_state = %d", old_state, new_state);
                   
                    bpf_printk("Event Details: PID=%d, COMM=%s, SADDR=%d, DADDR=%d, SPORT=%d, DPORT=%d, RTT=%llu ms",
                        e->pid,
                        e->comm,
                        e->saddr,
                        e->daddr,
                        e->sport,
                        e->dport,
                        e->rtt
                        );


                    bpf_ringbuf_submit(e, 0);
                }
                bpf_printk("Delete element : old_state = %d, new_state = %d", old_state, new_state);

                // Remove the entry from the hash map
                //bpf_map_delete_elem(&timestamp_map, &sk);
            }
        }
       
        
    }
    
    if (new_state == TCP_CLOSE) {
        // TCP_CLOSE state: remove any existing entry for the socket
        bpf_map_delete_elem(&timestamp_map, &sk);
        bpf_printk("Connection closed, timestamp entry removed.");
    } else {
        // Store the timestamp for new ESTABLISHED state
        bpf_map_update_elem(&timestamp_map, &sk, &ts, BPF_ANY);
        bpf_printk("Connection established, timestamp stored.");
        bpf_printk("ERROR : Transition observed: old_state = %d, new_state = %d", old_state, new_state);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
