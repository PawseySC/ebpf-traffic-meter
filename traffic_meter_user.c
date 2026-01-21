/*
 * Author: Ugo Varetto - ugo.varetto@csiro.au
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * traffic_meter_user.c - User-space loader for traffic_meter eBPF program.
 *
 * This program:
 *   1. Loads the compiled eBPF object file (traffic_meter.bpf.o)
 *   2. Attaches the eBPF programs to a cgroup for traffic monitoring
 *   3. Polls ring buffers for traffic events from the kernel (IPv4 and IPv6)
 *   4. Writes per-packet logs via pluggable output backend
 *
 * Usage: sudo ./traffic_meter_user [cgroup_path] [nic_id]
 *
 * Output files: /tmp/traffic_user_<nic_id>_<uid>.log
 * CSV format: direction,bytes,src_ip,dst_ip,timestamp,total_in,total_out
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/*
 * IPv4 traffic event structure - must match the kernel-side definition exactly.
 * Received from the eBPF ring buffer for each captured IPv4 packet.
 */
struct traffic_event {
    __u32 uid;       /* UID of the process owning the socket */
    __u32 bytes;     /* Packet size in bytes */
    __u32 src_ip;    /* Source IPv4 address (network byte order) */
    __u32 dst_ip;    /* Destination IPv4 address (network byte order) */
    __u8 direction;  /* 0 = ingress (in), 1 = egress (out) */
};

/*
 * IPv6 traffic event structure - must match the kernel-side definition exactly.
 * Received from the eBPF ring buffer for each captured IPv6 packet.
 */
struct traffic_event_v6 {
    __u32 uid;        /* UID of the process owning the socket */
    __u32 bytes;      /* Packet size in bytes */
    __u8 src_ip[16];  /* Source IPv6 address (network byte order) */
    __u8 dst_ip[16];  /* Destination IPv6 address (network byte order) */
    __u8 direction;   /* 0 = ingress (in), 1 = egress (out) */
};

/*
 * Unified traffic record structure for output backends.
 * Contains all data needed to log a traffic event, independent of IP version.
 */
struct traffic_record {
    __u32 uid;                       /* UID of the process owning the socket */
    __u32 bytes;                     /* Packet size in bytes */
    char src_ip[INET6_ADDRSTRLEN];   /* Source IP as string (IPv4 or IPv6) */
    char dst_ip[INET6_ADDRSTRLEN];   /* Destination IP as string (IPv4 or IPv6) */
    __u8 direction;                  /* 0 = ingress (in), 1 = egress (out) */
    struct timespec timestamp;       /* Event timestamp with nanosecond precision */
    __u64 total_in;                  /* Cumulative bytes received for this UID */
    __u64 total_out;                 /* Cumulative bytes sent for this UID */
};

/*
 * Output backend interface.
 * Implement this interface to add new output targets (syslog, socket, database, etc.)
 */
struct output_backend {
    int (*init)(void *config);                        /* Initialize backend */
    int (*write)(const struct traffic_record *rec);   /* Write a traffic record */
    void (*close)(void);                              /* Cleanup and close backend */
};

/*
 * Per-UID statistics structure for tracking cumulative byte counts.
 * Stored in a hash table keyed by UID for O(1) lookup.
 * Note: IPv4 and IPv6 traffic is combined into the same per-UID totals.
 */
struct uid_stats {
    __u32 uid;              /* User ID */
    __u64 total_in;         /* Cumulative bytes received (IPv4 + IPv6) */
    __u64 total_out;        /* Cumulative bytes sent (IPv4 + IPv6) */
    struct uid_stats *next; /* Next entry in hash bucket (chaining) */
};

/* Hash table size for UID stats - should be power of 2 for efficient modulo */
#define HASH_SIZE 1024

/* Global hash table for per-UID cumulative statistics */
static struct uid_stats *uid_hash[HASH_SIZE];

/* Flag set by signal handler to trigger graceful shutdown */
static volatile int exiting = 0;

/* NIC identifier for log filenames (from command line) */
static const char *g_nic_id = "unknown";

/* ============================================================================
 * File Output Backend Implementation
 * ============================================================================ */

/*
 * file_init - Initialize file output backend.
 *
 * @config: Configuration (unused for file backend)
 *
 * Returns: 0 on success
 */
static int file_init(void *config)
{
    (void)config;
    return 0;
}

/*
 * file_write - Write a traffic record to per-UID CSV file.
 *
 * @rec: Traffic record to write
 *
 * Opens/appends to /tmp/traffic_user_<nic_id>_<uid>.log
 * CSV format: direction,bytes,src_ip,dst_ip,timestamp,total_in,total_out
 *
 * Returns: 0 on success, -1 on failure
 */
static int file_write(const struct traffic_record *rec)
{
    char filename[256];
    snprintf(filename, sizeof(filename), "/tmp/traffic_user_%s_%u.log",
             g_nic_id, rec->uid);

    FILE *f = fopen(filename, "a");
    if (!f)
        return -1;

    fprintf(f, "%s,%u,%s,%s,%ld.%09ld,%llu,%llu\n",
            rec->direction ? "out" : "in",
            rec->bytes,
            rec->src_ip, rec->dst_ip,
            rec->timestamp.tv_sec, rec->timestamp.tv_nsec,
            (unsigned long long)rec->total_in,
            (unsigned long long)rec->total_out);

    fclose(f);
    return 0;
}

/*
 * file_close - Close file output backend.
 *
 * No-op for file backend since we open/close per write.
 */
static void file_close(void)
{
    /* Nothing to do - files are closed after each write */
}

/* File backend instance */
static struct output_backend file_backend = {
    .init = file_init,
    .write = file_write,
    .close = file_close,
};

/* Active output backend (can be changed to use different backends) */
static struct output_backend *g_backend = &file_backend;

/* ============================================================================
 * UID Statistics Management
 * ============================================================================ */

/*
 * find_or_create_stats - Get or create stats entry for a UID.
 *
 * @uid: User ID to look up
 *
 * Uses a simple hash table with chaining for collision resolution.
 * Creates a new entry if the UID is not found.
 *
 * Returns: Pointer to uid_stats structure, or NULL on allocation failure
 */
static struct uid_stats *find_or_create_stats(__u32 uid)
{
    /* Hash UID to get bucket index */
    unsigned int idx = uid % HASH_SIZE;

    /* Search the chain for existing entry */
    struct uid_stats *s = uid_hash[idx];
    while (s) {
        if (s->uid == uid)
            return s;
        s = s->next;
    }

    /* Not found - create new entry */
    s = calloc(1, sizeof(*s));
    if (!s)
        return NULL;

    /* Initialize and insert at head of chain */
    s->uid = uid;
    s->next = uid_hash[idx];
    uid_hash[idx] = s;

    return s;
}

/* ============================================================================
 * Signal Handling and Utilities
 * ============================================================================ */

/*
 * sig_handler - Signal handler for graceful shutdown.
 *
 * @sig: Signal number (unused)
 *
 * Sets the exiting flag to break the main polling loop.
 */
static void sig_handler(int sig)
{
    (void)sig;  /* Suppress unused parameter warning */
    exiting = 1;
}

/*
 * ip_to_str - Convert IPv4 address to string representation.
 *
 * @ip: IPv4 address in network byte order
 * @buf: Output buffer for the string
 * @buflen: Size of output buffer (should be >= INET_ADDRSTRLEN)
 */
static void ip_to_str(__u32 ip, char *buf, size_t buflen)
{
    struct in_addr a = { .s_addr = ip };
    inet_ntop(AF_INET, &a, buf, buflen);
}

/* ============================================================================
 * Event Handling
 * ============================================================================ */

/*
 * handle_event - Ring buffer callback for processing IPv4 traffic events.
 *
 * @ctx: User context (unused)
 * @data: Pointer to traffic_event structure from kernel
 * @data_sz: Size of data (unused, we know the structure size)
 *
 * This function is called by ring_buffer__poll() for each IPv4 event.
 * It updates cumulative statistics and passes the record to the output backend.
 *
 * Returns: 0 to continue processing events
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;      /* Suppress unused parameter warning */
    (void)data_sz;  /* Suppress unused parameter warning */

    struct traffic_event *e = data;

    /* Get or create cumulative stats for this UID */
    struct uid_stats *stats = find_or_create_stats(e->uid);
    if (!stats)
        return 0;  /* Allocation failed, skip this event */

    /* Update cumulative byte counters based on direction */
    if (e->direction)
        stats->total_out += e->bytes;
    else
        stats->total_in += e->bytes;

    /* Build traffic record for output backend */
    struct traffic_record rec;
    rec.uid = e->uid;
    rec.bytes = e->bytes;
    rec.direction = e->direction;
    rec.total_in = stats->total_in;
    rec.total_out = stats->total_out;

    /* Convert IPv4 addresses to strings */
    ip_to_str(e->src_ip, rec.src_ip, sizeof(rec.src_ip));
    ip_to_str(e->dst_ip, rec.dst_ip, sizeof(rec.dst_ip));

    /* Get current timestamp with nanosecond precision */
    clock_gettime(CLOCK_REALTIME, &rec.timestamp);

    /* Write record via output backend */
    g_backend->write(&rec);

    return 0;
}

/*
 * handle_event_v6 - Ring buffer callback for processing IPv6 traffic events.
 *
 * @ctx: User context (unused)
 * @data: Pointer to traffic_event_v6 structure from kernel
 * @data_sz: Size of data (unused, we know the structure size)
 *
 * This function is called by ring_buffer__poll() for each IPv6 event.
 * It updates cumulative statistics (shared with IPv4) and passes the
 * record to the output backend.
 *
 * Returns: 0 to continue processing events
 */
static int handle_event_v6(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;      /* Suppress unused parameter warning */
    (void)data_sz;  /* Suppress unused parameter warning */

    struct traffic_event_v6 *e = data;

    /* Get or create cumulative stats for this UID (shared with IPv4) */
    struct uid_stats *stats = find_or_create_stats(e->uid);
    if (!stats)
        return 0;  /* Allocation failed, skip this event */

    /* Update cumulative byte counters based on direction */
    if (e->direction)
        stats->total_out += e->bytes;
    else
        stats->total_in += e->bytes;

    /* Build traffic record for output backend */
    struct traffic_record rec;
    rec.uid = e->uid;
    rec.bytes = e->bytes;
    rec.direction = e->direction;
    rec.total_in = stats->total_in;
    rec.total_out = stats->total_out;

    /* Convert IPv6 addresses to strings */
    inet_ntop(AF_INET6, e->src_ip, rec.src_ip, sizeof(rec.src_ip));
    inet_ntop(AF_INET6, e->dst_ip, rec.dst_ip, sizeof(rec.dst_ip));

    /* Get current timestamp with nanosecond precision */
    clock_gettime(CLOCK_REALTIME, &rec.timestamp);

    /* Write record via output backend */
    g_backend->write(&rec);

    return 0;
}

/* ============================================================================
 * Main Program
 * ============================================================================ */

/*
 * main - Program entry point.
 *
 * @argc: Argument count
 * @argv: Argument vector
 *        argv[1] = cgroup path (optional, defaults to /sys/fs/cgroup/user.slice)
 *        argv[2] = NIC identifier for log filenames (optional, defaults to "unknown")
 *
 * Returns: 0 on success, 1 on error
 */
int main(int argc, char **argv)
{
    /* Parse optional NIC identifier from command line */
    g_nic_id = (argc > 2) ? argv[2] : "unknown";

    /*
     * Increase RLIMIT_MEMLOCK to allow BPF maps to be locked in memory.
     * Required for ring buffers and other BPF map types.
     */
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return 1;
    }

    /* Initialize output backend */
    if (g_backend->init(NULL) < 0) {
        fprintf(stderr, "Failed to initialize output backend\n");
        return 1;
    }

    /* Set up signal handlers for graceful shutdown */
    signal(SIGINT, sig_handler);   /* Ctrl+C */
    signal(SIGTERM, sig_handler);  /* kill command */

    /*
     * Open the cgroup v2 directory.
     * We attach BPF programs to this cgroup to monitor its network traffic.
     * Default to user.slice which contains user processes.
     */
    const char *cgroup_path = (argc > 1 && argv[1][0] != '\0')
                              ? argv[1]
                              : "/sys/fs/cgroup/user.slice";
    int cgroup_fd = open(cgroup_path, O_RDONLY);
    if (cgroup_fd < 0) {
        /* Fall back to root cgroup if user.slice doesn't exist */
        cgroup_path = "/sys/fs/cgroup";
        cgroup_fd = open(cgroup_path, O_RDONLY);
        if (cgroup_fd < 0) {
            perror("open cgroup");
            g_backend->close();
            return 1;
        }
    }
    printf("Using cgroup: %s\n", cgroup_path);

    /*
     * Load the compiled BPF object file.
     * This contains the BPF programs and maps defined in traffic_meter.bpf.c
     */
    struct bpf_object *obj = bpf_object__open_file("traffic_meter.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object file\n");
        close(cgroup_fd);
        g_backend->close();
        return 1;
    }

    /* Load BPF programs and maps into the kernel */
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object into kernel\n");
        bpf_object__close(obj);
        close(cgroup_fd);
        g_backend->close();
        return 1;
    }

    /*
     * Find and attach the IPv4 egress (outgoing traffic) BPF program.
     * BPF_CGROUP_INET_EGRESS hook is called for all outgoing packets.
     * BPF_F_ALLOW_MULTI allows multiple programs on the same hook (needed for IPv6).
     */
    struct bpf_program *prog_egress = bpf_object__find_program_by_name(
        obj, "traffic_meter_egress");
    if (!prog_egress) {
        fprintf(stderr, "Failed to find IPv4 egress program in BPF object\n");
        bpf_object__close(obj);
        close(cgroup_fd);
        g_backend->close();
        return 1;
    }
    int prog_egress_fd = bpf_program__fd(prog_egress);
    if (bpf_prog_attach(prog_egress_fd, cgroup_fd,
                        BPF_CGROUP_INET_EGRESS, BPF_F_ALLOW_MULTI) < 0) {
        perror("bpf_prog_attach(IPv4 egress)");
        bpf_object__close(obj);
        close(cgroup_fd);
        g_backend->close();
        return 1;
    }

    /*
     * Find and attach the IPv4 ingress (incoming traffic) BPF program.
     * BPF_CGROUP_INET_INGRESS hook is called for all incoming packets.
     */
    struct bpf_program *prog_ingress = bpf_object__find_program_by_name(
        obj, "traffic_meter_ingress");
    if (!prog_ingress) {
        fprintf(stderr, "Failed to find IPv4 ingress program in BPF object\n");
        bpf_prog_detach2(prog_egress_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_object__close(obj);
        close(cgroup_fd);
        g_backend->close();
        return 1;
    }
    int prog_ingress_fd = bpf_program__fd(prog_ingress);
    if (bpf_prog_attach(prog_ingress_fd, cgroup_fd,
                        BPF_CGROUP_INET_INGRESS, BPF_F_ALLOW_MULTI) < 0) {
        perror("bpf_prog_attach(IPv4 ingress)");
        bpf_prog_detach2(prog_egress_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_object__close(obj);
        close(cgroup_fd);
        g_backend->close();
        return 1;
    }

    /*
     * Find and attach the IPv6 egress (outgoing traffic) BPF program.
     * This runs alongside the IPv4 egress program on the same hook.
     */
    struct bpf_program *prog_egress_v6 = bpf_object__find_program_by_name(
        obj, "traffic_meter_egress_v6");
    if (!prog_egress_v6) {
        fprintf(stderr, "Failed to find IPv6 egress program in BPF object\n");
        bpf_prog_detach2(prog_egress_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_prog_detach2(prog_ingress_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS);
        bpf_object__close(obj);
        close(cgroup_fd);
        g_backend->close();
        return 1;
    }
    int prog_egress_v6_fd = bpf_program__fd(prog_egress_v6);
    if (bpf_prog_attach(prog_egress_v6_fd, cgroup_fd,
                        BPF_CGROUP_INET_EGRESS, BPF_F_ALLOW_MULTI) < 0) {
        perror("bpf_prog_attach(IPv6 egress)");
        bpf_prog_detach2(prog_egress_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_prog_detach2(prog_ingress_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS);
        bpf_object__close(obj);
        close(cgroup_fd);
        g_backend->close();
        return 1;
    }

    /*
     * Find and attach the IPv6 ingress (incoming traffic) BPF program.
     * This runs alongside the IPv4 ingress program on the same hook.
     */
    struct bpf_program *prog_ingress_v6 = bpf_object__find_program_by_name(
        obj, "traffic_meter_ingress_v6");
    if (!prog_ingress_v6) {
        fprintf(stderr, "Failed to find IPv6 ingress program in BPF object\n");
        bpf_prog_detach2(prog_egress_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_prog_detach2(prog_ingress_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS);
        bpf_prog_detach2(prog_egress_v6_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_object__close(obj);
        close(cgroup_fd);
        g_backend->close();
        return 1;
    }
    int prog_ingress_v6_fd = bpf_program__fd(prog_ingress_v6);
    if (bpf_prog_attach(prog_ingress_v6_fd, cgroup_fd,
                        BPF_CGROUP_INET_INGRESS, BPF_F_ALLOW_MULTI) < 0) {
        perror("bpf_prog_attach(IPv6 ingress)");
        bpf_prog_detach2(prog_egress_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_prog_detach2(prog_ingress_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS);
        bpf_prog_detach2(prog_egress_v6_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_object__close(obj);
        close(cgroup_fd);
        g_backend->close();
        return 1;
    }

    /*
     * Create ring buffer manager to receive IPv4 events from the kernel.
     * The callback handle_event() is called for each IPv4 event.
     */
    struct ring_buffer *rb = ring_buffer__new(
        bpf_object__find_map_fd_by_name(obj, "events"),
        handle_event,  /* Callback function for IPv4 events */
        NULL,          /* User context (unused) */
        NULL);         /* Options (use defaults) */
    if (!rb) {
        fprintf(stderr, "Failed to create IPv4 ring buffer\n");
        bpf_prog_detach2(prog_egress_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_prog_detach2(prog_ingress_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS);
        bpf_prog_detach2(prog_egress_v6_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_prog_detach2(prog_ingress_v6_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS);
        bpf_object__close(obj);
        close(cgroup_fd);
        g_backend->close();
        return 1;
    }

    /*
     * Add IPv6 ring buffer to the same ring buffer manager.
     * This allows polling both buffers with a single ring_buffer__poll() call.
     * The callback handle_event_v6() is called for each IPv6 event.
     */
    if (ring_buffer__add(rb,
                         bpf_object__find_map_fd_by_name(obj, "events_v6"),
                         handle_event_v6,  /* Callback function for IPv6 events */
                         NULL) < 0) {      /* User context (unused) */
        fprintf(stderr, "Failed to add IPv6 ring buffer\n");
        ring_buffer__free(rb);
        bpf_prog_detach2(prog_egress_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_prog_detach2(prog_ingress_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS);
        bpf_prog_detach2(prog_egress_v6_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
        bpf_prog_detach2(prog_ingress_v6_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS);
        bpf_object__close(obj);
        close(cgroup_fd);
        g_backend->close();
        return 1;
    }

    printf("eBPF traffic meter loaded (cgroup mode, IPv4+IPv6). Press Ctrl+C to exit.\n");
    fflush(stdout);

    /*
     * Main event loop - poll ring buffers for events.
     * Timeout of 100ms allows periodic checking of the exiting flag.
     * Both IPv4 and IPv6 buffers are polled in the same call.
     */
    while (!exiting) {
        ring_buffer__poll(rb, 100);  /* 100ms timeout */
    }

    /*
     * Cleanup: detach all BPF programs and free resources.
     * Programs are automatically unloaded when we close the object.
     * Use bpf_prog_detach2() which takes the program fd for precise detachment
     * (needed when using BPF_F_ALLOW_MULTI).
     */
    ring_buffer__free(rb);
    bpf_prog_detach2(prog_egress_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
    bpf_prog_detach2(prog_ingress_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS);
    bpf_prog_detach2(prog_egress_v6_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS);
    bpf_prog_detach2(prog_ingress_v6_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS);
    bpf_object__close(obj);
    close(cgroup_fd);

    /* Close output backend */
    g_backend->close();

    printf("Detached and exiting.\n");
    return 0;
}
