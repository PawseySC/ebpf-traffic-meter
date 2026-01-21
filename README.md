# eBPF Traffic Meter

- [eBPF Traffic Meter](#ebpf-traffic-meter)
  - [eBPF](#ebpf)
  - [Requirements](#requirements)
    - [Fedora/RHEL](#fedorarhel)
    - [Ubuntu/Debian](#ubuntudebian)
    - [SLES](#sles)
  - [Building](#building)
  - [Usage](#usage)
    - [Arguments](#arguments)
    - [Examples](#examples)
  - [Output](#output)
    - [Fields](#fields)
    - [Example Output](#example-output)
  - [Untracked IP Filtering](#untracked-ip-filtering)
  - [Architecture](#architecture)
  - [License](#license)
  - [References](#references)

A per-user network traffic monitoring tool using eBPF. Captures all IPv4 and IPv6 network traffic and logs it to per-user files with direction, byte count, and IP addresses.
It is possible to specify network addressess to ignore to e.g. only capture external network traffic.

## eBPF

eBPF is a technology with origins in the Linux kernel that can run sandboxed programs in a privileged context such as the operating system kernel.
It is used to safely and efficiently extend the capabilities of the kernel without requiring to change kernel source code or load kernel modules.

It can track events and interact with the OS at any level including filesystem, GPU, network and any system call, see [references](#references).

## Requirements

- Linux kernel 5.8+ (for ring buffer support)
- clang (for BPF compilation)
- libbpf, libelf, libz development headers
- **Root privileges** (for loading eBPF programs)

### Fedora/RHEL

```bash
sudo dnf install clang libbpf-devel elfutils-libelf-devel zlib-devel
```

### Ubuntu/Debian

```bash
sudo apt install clang libbpf-dev libelf-dev zlib1g-dev
```

### SLES

**warning**: to be confirmed

```bash
sudo zypper install clang libbpf-devel libelf-devel zlib-devel
```

## Building

```bash
make clean && make
```

This produces:
- `traffic_meter.bpf.o` - eBPF program object
- `traffic_meter_user` - User-space loader
- `ipmask_tool` - generates bitmasks of untracked networks in network byte order, see [below](#untracked-ip-filtering)

## Usage

```bash
sudo ./traffic_meter_user [cgroup_path] [nic_id]
```

### Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `cgroup_path` | `/sys/fs/cgroup/user.slice` | Cgroup to attach to (falls back to `/sys/fs/cgroup`) |
| `nic_id` | `unknown` | Identifier for log filenames |

### Examples

```bash
# Default cgroup, specify NIC for filename
sudo ./traffic_meter_user "" eno1

# Specific cgroup path
sudo ./traffic_meter_user /sys/fs/cgroup/user.slice/user-1000.slice eth0

# Monitor all traffic (root cgroup)
sudo ./traffic_meter_user /sys/fs/cgroup wlan0
```

Press `Ctrl+C` to stop.

## Output

Log files are written to `/tmp/traffic_user_<nic_id>_<uid>.log` in CSV format:

```
direction,bytes,src_ip,dst_ip,timestamp,total_in,total_out
```

### Fields

| Field | Description |
|-------|-------------|
| `direction` | `in` (received) or `out` (sent) |
| `bytes` | Packet size in bytes |
| `src_ip` | Source IP address (IPv4 or IPv6) |
| `dst_ip` | Destination IP address (IPv4 or IPv6) |
| `timestamp` | Unix timestamp with nanosecond precision (seconds.nanoseconds) |
| `total_in` | Cumulative bytes received so far for this UID |
| `total_out` | Cumulative bytes sent so far for this UID |

### Example Output

```csv
out,52,192.168.1.100,8.8.8.8,1732985432.123456789,0,52
in,84,8.8.8.8,192.168.1.100,1732985432.234567890,84,52
out,1500,192.168.1.100,142.250.185.78,1732985433.345678901,84,1552
in,1500,142.250.185.78,192.168.1.100,1732985433.456789012,1584,1552
out,80,2001:db8::1,2607:f8b0:4004:800::200e,1732985434.567890123,1584,1632
in,1280,2607:f8b0:4004:800::200e,2001:db8::1,1732985434.678901234,2864,1632
```

## Untracked IP Filtering 

The eBPF program includes a static list of IPv4 and IPv6 network masks that are **ignored** during monitoring. 

These masks are defined in the file `untracked_masks.h` included by`traffic_meter.bpf.c` as `untracked_ipv4` and `untracked_ipv6` arrays. 

For each packet the program checks whether the source **and** destination address matches any of the configured networks.
If a match is found, the event is discarded with `bpf_ringbuf_discard()` and the packet is allowed to continue without being logged.

* **IPv4** – Each entry stores a network address and a netmask in network byte order. Example entries include `10.0.0.0/8` and `192.168.1.0/24`.
* **IPv6** – Each entry stores a 16‑byte network prefix and a prefix length. The helper function `ipv6_is_untracked()` performs a byte‑wise comparison respecting the prefix length.

To modify the ignored networks, edit the static arrays in `untracked_masks.h` and rebuild the project (`make clean && make`). 
This allows you to tailor the monitoring to exclude internal or otherwise irrelevant traffic.

Content of file `untracked_masks.h`

```c
static const struct ipv4_mask untracked_ipv4[] = {
  { __builtin_bswap32(0x0a000000), __builtin_bswap32(0xff000000) }, // 10.0.0.0/8
  { __builtin_bswap32(0xc0a80100), __builtin_bswap32(0xffffff00) }, // 192.168.1.0/24
};

static const struct ipv6_mask untracked_ipv6[] = {
    { { 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 32 },
    { { 0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x00, 0x00 }, 112 },
};
```

Use the included `ipmask_tool` to generate the the `untracked_masks.h` file from a list of IP
addresses stored in a file using `*` as the wildcard; e.g.:

`ip_list.txt`:
```
10.0.*.*
192.168.1.*
2001:db8::*
2001:db8:abcd:1234:5678:9abc:def0:*
```

**Usage**

```sh
./ipmask_tool ip_list.txt > untracked_masks.h
```

The tool is useful for maintaining the untracked networks without manually calculating bitmasks.

Note that, because loops are forbidden in eBPF kernels, a `#pragma unroll` directive is used to unroll the loop
and the array length is a static constant. The maximum number of iterations to be considered for
a full unrolling varies with the compiler and the compiler version and in some cases can be dynamic
based on the analysis the compiler does of the code.


## Architecture

1. **eBPF Program** (`traffic_meter.bpf.c`):
   - Attaches to `cgroup_skb/egress` and `cgroup_skb/ingress` hooks for both IPv4 and IPv6
   - Uses `bpf_get_socket_uid()` to identify the socket owner (UID)
   - Extracts source/destination IPs from IP headers
   - Sends events to user space via separate ring buffers for IPv4 and IPv6

2. **User-Space Loader** (`traffic_meter_user.c`):
   - Loads and attaches the eBPF programs (4 total: ingress/egress for IPv4 and IPv6)
   - Polls both ring buffers for events
   - Tracks cumulative bytes per UID for in/out directions
   - Passes events to pluggable output backend
   - Default backend writes CSV to per-user log files


The output system uses a pluggable backend interface:

```c
struct output_backend {
    int (*init)(void *config);
    int (*write)(const struct traffic_record *rec);
    void (*close)(void);
};
```

To add new output targets (syslog, network socket, database, etc.), implement this interface and set `g_backend` to your implementation.


## License

GPL (required for eBPF programs using GPL-only helpers)

## References

- [Official site](https://ebpf.io/)
- [eBPF docs](https://docs.ebpf.io/)
- [Tutorial](https://eunomia.dev/tutorials/)
