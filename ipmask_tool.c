/*
 * Author: Ugo Varetto - ugo.varetto@csiro.au
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * ipmask_tool.c - Helper utility to convert wildcard IP lists to C bitmask arrays.
 *
 * Usage: ipmask_tool <input_file>
 * The input file should contain one IP address per line. Wildcards are represented
 * by '*'. For IPv4, each octet may be a number (0-255) or '*'. Example lines:
 *   10.0.*.*
 *   192.168.1.*
 *   2001:db8::*
 *   2001:db8:abcd:1234:5678:9abc:def0:*
 *
 * The program prints to stdout C code defining static const arrays suitable for
 * inclusion in traffic_meter.bpf.c:
 *
 *   static const struct ipv4_mask untracked_ipv4[] = {
 *       { __builtin_bswap32(0x0a000000), __builtin_bswap32(0xff000000) },
 *       ...
 *   };
 *   static const struct ipv6_mask untracked_ipv6[] = {
 *       { {0x20,0x01,0x0d,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, 48 },
 *       ...
 *   };
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Helper structures matching those in traffic_meter.bpf.c */
struct ipv4_mask {
    uint32_t net;   /* network address in host byte order */
    uint32_t mask;  /* netmask in host byte order */
};

struct ipv6_mask {
    uint8_t net[16];
    uint8_t prefix_len; /* number of leading bits in the mask */
};

/* Parse a single IPv4 wildcard line into net/mask.
 * Returns 0 on success, non‑zero on failure.
 */
static int parse_ipv4(const char *line, struct ipv4_mask *out) {
    unsigned int octets[4];
    int is_wild[4] = {0,0,0,0};
    char buf[64];
    strncpy(buf, line, sizeof(buf)-1);
    buf[sizeof(buf)-1] = '\0';
    char *token = strtok(buf, ".");
    int idx = 0;
    while (token && idx < 4) {
        if (strcmp(token, "*") == 0) {
            is_wild[idx] = 1;
            octets[idx] = 0; // placeholder
        } else {
            int val = atoi(token);
            if (val < 0 || val > 255) return 1;
            octets[idx] = (unsigned int)val;
        }
        token = strtok(NULL, ".");
        idx++;
    }
    if (idx != 4) return 1; // malformed

    uint32_t net = 0, mask = 0;
    for (int i = 0; i < 4; i++) {
        net <<= 8;
        mask <<= 8;
        if (is_wild[i]) {
            mask |= 0x00;
        } else {
            net |= octets[i];
            mask |= 0xFF;
        }
    }
    out->net = net;
    out->mask = mask;
    return 0;
}

/* Parse IPv6 wildcard line. Supports '*' in place of a 16‑bit group.
 * Example: "2001:db8::*" or "2001:db8:abcd:1234:5678:9abc:def0:*"
 */
static int parse_ipv6(const char *line, struct ipv6_mask *out) {
    // Initialize net to zeros.
    memset(out->net, 0, 16);
    out->prefix_len = 0;
    char buf[128];
    strncpy(buf, line, sizeof(buf)-1);
    buf[sizeof(buf)-1] = '\0';
    char *token = strtok(buf, ":");
    int group = 0;
    while (token && group < 8) {
        if (strcmp(token, "*") == 0) {
            // Wildcard for remaining bits: stop processing further groups.
            break;
        }
        // Convert hex group to integer.
        unsigned int val = 0;
        if (sscanf(token, "%x", &val) != 1) return 1;
        // Store big‑endian bytes.
        out->net[group*2] = (val >> 8) & 0xFF;
        out->net[group*2 + 1] = val & 0xFF;
        out->prefix_len += 16;
        token = strtok(NULL, ":");
        group++;
    }
    // Any remaining groups are wild (bits zero, mask not set).
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    FILE *fp = fopen(argv[1], "r");
    if (!fp) {
        perror("fopen");
        return 1;
    }
    struct ipv4_mask v4_list[256];
    struct ipv6_mask v6_list[256];
    int v4_cnt = 0, v6_cnt = 0;
    char line[128];
    while (fgets(line, sizeof(line), fp)) {
        // Trim whitespace and newline.
        char *p = line;
        while (*p && (*p == ' ' || *p == '\t')) p++;
        char *end = p + strlen(p) - 1;
        while (end > p && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t')) *end-- = '\0';
        if (*p == '\0' || *p == '#') continue; // skip empty/comment lines
        // Determine if IPv4 (contains '.') or IPv6 (contains ':').
        if (strchr(p, '.')) {
            if (v4_cnt >= 256) { fprintf(stderr, "Too many IPv4 entries\n"); break; }
            if (parse_ipv4(p, &v4_list[v4_cnt]) == 0) v4_cnt++;
        } else if (strchr(p, ':')) {
            if (v6_cnt >= 256) { fprintf(stderr, "Too many IPv6 entries\n"); break; }
            if (parse_ipv6(p, &v6_list[v6_cnt]) == 0) v6_cnt++;
        } else {
            fprintf(stderr, "Unrecognized line: %s\n", p);
        }
    }
    fclose(fp);

    // Output C code.
    printf("static const struct ipv4_mask untracked_ipv4[] = {\n");
    for (int i = 0; i < v4_cnt; i++) {
        printf("    { __builtin_bswap32(0x%08x), __builtin_bswap32(0x%08x) }, // %u.%u.%u.%u\n",
               v4_list[i].net, v4_list[i].mask,
               (v4_list[i].net >> 24) & 0xFF,
               (v4_list[i].net >> 16) & 0xFF,
               (v4_list[i].net >> 8) & 0xFF,
               v4_list[i].net & 0xFF);
    }
    printf("};\n\n");
    // size
    printf("static const int untracked_ipv4_cnt = %d;\n\n", v4_cnt);

    printf("static const struct ipv6_mask untracked_ipv6[] = {\n");
    for (int i = 0; i < v6_cnt; i++) {
        printf("    { { ");
        for (int b = 0; b < 16; b++) {
            printf("0x%02x", v6_list[i].net[b]);
            if (b < 15) printf(", ");
        }
        printf(" }, %u },\n", v6_list[i].prefix_len);
    }
    printf("};\n\n");
    printf("static const int untracked_ipv6_cnt = %d;\n\n", v6_cnt);

    return 0;
}
