/*
 * Author: Ugo Varetto - ugo.varetto@csiro.au
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * traffic_meter.bpf.c - eBPF program to meter network traffic per UID.
 *
 * This program attaches to cgroup_skb hooks to capture all IPv4 and IPv6
 * network traffic. It uses cgroup hooks (rather than XDP) because they
 * provide access to socket information, including the UID of the process
 * that owns the socket.
 *
 * For each packet, we extract:
 *   - UID of the socket owner
 *   - Packet size in bytes
 *   - Source and destination IP addresses (IPv4 or IPv6)
 *   - Direction (ingress or egress)
 *
 * Events are sent to user space via ring buffers (separate for IPv4/IPv6)
 * for real-time processing.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * Static list of IPv4 networks to ignore. Each entry contains a network address
 * and a netmask in network byte order. Packets whose source OR destination IP
 * matches any of these networks will be skipped.
 */
struct ipv4_mask {
    __u32 net;   /* network address */
    __u32 mask;  /* netmask */
};


/* IPv6 untracked network definition */
struct ipv6_mask {
    __u8 net[16];
    __u8 prefix_len; // number of leading bits in mask
};

/* IP masks listing the ip addresses not to be tracked */

/* Example entries (network byte order):
 *   10.0.0.0/8   -> net = 0x0a000000, mask = 0xff000000
 *   192.168.1.0/24 -> net = 0xc0a80100, mask = 0xffffff00
 *
 * static const struct ipv4_mask untracked_ipv4[] = {
 *   { __builtin_bswap32(0x0a000000), __builtin_bswap32(0xff000000) }, // 10.0.0.0/8
 *   { __builtin_bswap32(0xc0a80100), __builtin_bswap32(0xffffff00) }, // 192.168.1.0/24
 * };
 * static const int untracked_ipv4_cnt = sizeof(untracked_ipv4) / sizeof(untracked_ipv4[0]);
*/

/*
 * Example entries (network byte order):
 *   2001:db8::/32 -> net = {0x20,0x01,0x0d,0xb8,0x00...}, prefix_len = 32
 *
 static const struct ipv6_mask untracked_ipv6[] = {
     // add entries as needed
 };
 static const int untracked_ipv6_cnt = sizeof(untracked_ipv6) / sizeof(untracked_ipv6[0]);
*/

/*
 * Use the ipmask_tool utility to generate the ip_masks.h file from ip addresses like 192.168.*.*
 */

#include "untracked_masks.h"


/* Helper to check if an IPv4 address (network byte order) is in the untracked list */
/*
 * Check if an IPv4 address (network byte order) matches any entry in
 * the untracked_ipv4 list. Returns 1 if the address should be ignored.
 */
static __always_inline int ipv4_is_untracked(__u32 ip) {
    #pragma unroll /* no loops allowed */
    for (int i = 0; i != untracked_ipv4_cnt; i++) {
        //if (i >= untracked_ipv4_cnt) break;
        if ((ip & untracked_ipv4[i].mask) == untracked_ipv4[i].net)
            return 1;
    }
    return 0;
}

/*
 * Check if an IPv6 address matches any entry in the untracked_ipv6 list.
 * Returns 1 if the address should be ignored.
 */
static __always_inline int ipv6_is_untracked(const __u8 ip[16]) {
    #pragma unroll
    for (int i = 0; i != untracked_ipv6_cnt; i++) {
        //if (i >= untracked_ipv6_cnt) break;
        const struct ipv6_mask *m = &untracked_ipv6[i];
        int full_bytes = m->prefix_len / 8;
        int remaining_bits = m->prefix_len % 8;
        int match = 1;
        for (int b = 0; b < full_bytes; b++) {
            if (ip[b] != m->net[b]) { match = 0; break; }
        }
        if (match && remaining_bits) {
            __u8 mask = (__u8)(0xFF << (8 - remaining_bits));
            if ((ip[full_bytes] & mask) != (m->net[full_bytes] & mask))
                match = 0;
        }
        if (match) return 1;
    }
    return 0;
}

#include <bpf/bpf_endian.h>

/*
 * eBPF traffic meter program.
 * Captures per‑process network traffic (both IPv4 and IPv6) via cgroup_skb
 * ingress/egress hooks, emitting events to user space through ring buffers.
 * The code also supports static untracked IP/netmask lists to filter out traffic
 * from or to specific networks.
 */

/*
 * IPv4 event structure sent to user space via ring buffer.
 * This is a per-packet event containing all relevant traffic metadata.
 */
struct traffic_event {
    __u32 uid;       /* UID of the process owning the socket */
    __u32 bytes;     /* Packet size in bytes */
    __u32 src_ip;    /* Source IPv4 address (network byte order) */
    __u32 dst_ip;    /* Destination IPv4 address (network byte order) */
    __u8 direction;  /* Traffic direction: 0 = ingress (in), 1 = egress (out) */
};

/*
 * IPv6 event structure sent to user space via ring buffer.
 * Uses 16-byte arrays for 128-bit IPv6 addresses.
 */
struct traffic_event_v6 {
    __u32 uid;        /* UID of the process owning the socket */
    __u32 bytes;      /* Packet size in bytes */
    __u8 src_ip[16];  /* Source IPv6 address (network byte order) */
    __u8 dst_ip[16];  /* Destination IPv6 address (network byte order) */
    __u8 direction;   /* Traffic direction: 0 = ingress (in), 1 = egress (out) */
};

/*
 * Ring buffer map for IPv4 events.
 * Size is 256KB which can hold thousands of events before overflow.
 * User space must poll frequently enough to prevent event loss.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  /* 256 KB ring buffer */
} events SEC(".maps");

/*
 * Ring buffer map for IPv6 events.
 * Separate from IPv4 to allow different event structures and
 * independent consumption rates.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  /* 256 KB ring buffer */
} events_v6 SEC(".maps");

/*
 * traffic_meter_egress - Capture outgoing (egress) IPv4 packets.
 *
 * @skb: Socket buffer containing the packet data
 *
 * This function is called for every outgoing packet in the attached cgroup.
 * It filters for IPv4 packets, extracts metadata, and sends an event to
 * user space via the ring buffer.
 *
 * Returns: 1 to allow the packet (we never drop packets, just observe)
 */
SEC("cgroup_skb/egress")
int traffic_meter_egress(struct __sk_buff *skb)
{
    __u8 ip_ver = 0;

    /* Read first byte of IP header to get version (upper 4 bits) */
    bpf_skb_load_bytes(skb, 0, &ip_ver, 1);

    /* Only process IPv4 packets (version == 4) */
    if ((ip_ver >> 4) != 4)
        return 1;

    /* Reserve space in ring buffer for our event */
    struct traffic_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 1;  /* Ring buffer full, drop event but allow packet */

    /* Get UID of the socket owner (requires CAP_NET_ADMIN) */
    e->uid = bpf_get_socket_uid(skb);

    /* Record packet size */
    e->bytes = skb->len;

    /* Mark as egress (outgoing) traffic */
    e->direction = 1;

    /*
     * Extract source and destination IPs from IPv4 header.
     * IPv4 header layout:
     *   Offset 12: Source IP (4 bytes)
     *   Offset 16: Destination IP (4 bytes)
     */
    bpf_skb_load_bytes(skb, 12, &e->src_ip, 4);
    bpf_skb_load_bytes(skb, 16, &e->dst_ip, 4);

    /* Apply untracked IP filter – drop event if src and dst matches */
    /* Skip untracked IPs */
    if (ipv4_is_untracked(e->src_ip) && ipv4_is_untracked(e->dst_ip)) {
        bpf_ringbuf_discard(e, 0);
        return 1;
    }

    /* Submit event to ring buffer for user space to consume */
    bpf_ringbuf_submit(e, 0);

    return 1;  /* Allow packet to continue */
}

/*
 * traffic_meter_ingress - Capture incoming (ingress) IPv4 packets.
 *
 * @skb: Socket buffer containing the packet data
 *
 * This function is called for every incoming packet in the attached cgroup.
 * It filters for IPv4 packets, extracts metadata, and sends an event to
 * user space via the ring buffer.
 *
 * Returns: 1 to allow the packet (we never drop packets, just observe)
 */
SEC("cgroup_skb/ingress")
int traffic_meter_ingress(struct __sk_buff *skb)
{
    __u8 ip_ver = 0;

    /* Read first byte of IP header to get version (upper 4 bits) */
    bpf_skb_load_bytes(skb, 0, &ip_ver, 1);

    /* Only process IPv4 packets (version == 4) */
    if ((ip_ver >> 4) != 4)
        return 1;

    /* Reserve space in ring buffer for our event */
    struct traffic_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 1;  /* Ring buffer full, drop event but allow packet */

    /* Get UID of the socket owner (requires CAP_NET_ADMIN) */
    e->uid = bpf_get_socket_uid(skb);

    /* Record packet size */
    e->bytes = skb->len;

    /* Mark as ingress (incoming) traffic */
    e->direction = 0;

    /*
     * Extract source and destination IPs from IPv4 header.
     * IPv4 header layout:
     *   Offset 12: Source IP (4 bytes)
     *   Offset 16: Destination IP (4 bytes)
     */
    bpf_skb_load_bytes(skb, 12, &e->src_ip, 4);
    bpf_skb_load_bytes(skb, 16, &e->dst_ip, 4);

    /* Apply untracked IP filter – drop event if src and dst matches */
    /* Skip untracked IPs */
    if (ipv4_is_untracked(e->src_ip) && ipv4_is_untracked(e->dst_ip)) {
        bpf_ringbuf_discard(e, 0);
        return 1;
    }

    /* Submit event to ring buffer for user space to consume */
    bpf_ringbuf_submit(e, 0);

    return 1;  /* Allow packet to continue */
}

/*
 * traffic_meter_egress_v6 - Capture outgoing (egress) IPv6 packets.
 *
 * @skb: Socket buffer containing the packet data
 *
 * This function is called for every outgoing packet in the attached cgroup.
 * It filters for IPv6 packets, extracts metadata, and sends an event to
 * user space via the IPv6 ring buffer.
 *
 * Returns: 1 to allow the packet (we never drop packets, just observe)
 */
SEC("cgroup_skb/egress")
int traffic_meter_egress_v6(struct __sk_buff *skb)
{
    __u8 ip_ver = 0;

    /* Read first byte of IP header to get version (upper 4 bits) */
    bpf_skb_load_bytes(skb, 0, &ip_ver, 1);

    /* Only process IPv6 packets (version == 6) */
    if ((ip_ver >> 4) != 6)
        return 1;

    /* Reserve space in IPv6 ring buffer for our event */
    struct traffic_event_v6 *e = bpf_ringbuf_reserve(&events_v6, sizeof(*e), 0);
    if (!e)
        return 1;  /* Ring buffer full, drop event but allow packet */

    /* Get UID of the socket owner (requires CAP_NET_ADMIN) */
    e->uid = bpf_get_socket_uid(skb);

    /* Record packet size */
    e->bytes = skb->len;

    /* Mark as egress (outgoing) traffic */
    e->direction = 1;

    /*
     * Extract source and destination IPs from IPv6 header.
     * IPv6 header layout:
     *   Offset 8: Source IP (16 bytes)
     *   Offset 24: Destination IP (16 bytes)
     */
    bpf_skb_load_bytes(skb, 8, &e->src_ip, 16);
    bpf_skb_load_bytes(skb, 24, &e->dst_ip, 16);

    /* Apply untracked IPv6 filter – drop event if src and dst matches */
    /* Skip untracked IPv6 IPs */
    if (ipv6_is_untracked(e->src_ip) && ipv6_is_untracked(e->dst_ip)) {
        bpf_ringbuf_discard(e, 0);
        return 1;
    }

    /* Submit event to ring buffer for user space to consume */
    bpf_ringbuf_submit(e, 0);

    return 1;  /* Allow packet to continue */
}

/*
 * traffic_meter_ingress_v6 - Capture incoming (ingress) IPv6 packets.
 *
 * @skb: Socket buffer containing the packet data
 *
 * This function is called for every incoming packet in the attached cgroup.
 * It filters for IPv6 packets, extracts metadata, and sends an event to
 * user space via the IPv6 ring buffer.
 *
 * Returns: 1 to allow the packet (we never drop packets, just observe)
 */
SEC("cgroup_skb/ingress")
int traffic_meter_ingress_v6(struct __sk_buff *skb)
{
    __u8 ip_ver = 0;

    /* Read first byte of IP header to get version (upper 4 bits) */
    bpf_skb_load_bytes(skb, 0, &ip_ver, 1);

    /* Only process IPv6 packets (version == 6) */
    if ((ip_ver >> 4) != 6)
        return 1;

    /* Reserve space in IPv6 ring buffer for our event */
    struct traffic_event_v6 *e = bpf_ringbuf_reserve(&events_v6, sizeof(*e), 0);
    if (!e)
        return 1;  /* Ring buffer full, drop event but allow packet */

    /* Get UID of the socket owner (requires CAP_NET_ADMIN) */
    e->uid = bpf_get_socket_uid(skb);

    /* Record packet size */
    e->bytes = skb->len;

    /* Mark as ingress (incoming) traffic */
    e->direction = 0;

    /*
     * Extract source and destination IPs from IPv6 header.
     * IPv6 header layout:
     *   Offset 8: Source IP (16 bytes)
     *   Offset 24: Destination IP (16 bytes)
     */
    bpf_skb_load_bytes(skb, 8, &e->src_ip, 16);
    bpf_skb_load_bytes(skb, 24, &e->dst_ip, 16);

    /* Apply untracked IPv6 filter – drop event if src and dst matches */
    /* Skip untracked IPv6 IPs */
    if (ipv6_is_untracked(e->src_ip) && ipv6_is_untracked(e->dst_ip)) {
        bpf_ringbuf_discard(e, 0);
        return 1;
    }

    /* Submit event to ring buffer for user space to consume */
    bpf_ringbuf_submit(e, 0);

    return 1;  /* Allow packet to continue */
}

/* GPL license required for using bpf_get_socket_uid and other GPL-only helpers */
char _license[] SEC("license") = "GPL";
