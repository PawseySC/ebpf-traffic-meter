# Author: Ugo Varetto - ugo.varetto@csiro.au
# SPDX-License-Identifier: GPL-2.0-or-later

# Makefile for eBPF traffic meter

# Added ipmask_tool compilation
IPMASK_SRC = ipmask_tool.c
IPMASK_BIN = ipmask_tool

BPF_SRC = traffic_meter.bpf.c untracked_masks.h
BPF_OBJ = traffic_meter.bpf.o
USER_SRC = traffic_meter_user.c
USER_BIN = traffic_meter_user
SKEL_HDR = traffic_meter.skel.h

CLANG ?= clang
CPPFLAGS ?= -I/usr/include -I.
CFLAGS ?= -O2 -g -Wall
LIBS ?= -lbpf -lelf -lz

all: $(BPF_OBJ) $(USER_BIN) $(IPMASK_BIN)

# Build BPF object file
$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_X86 -c $< -o $@

# Build user‑space loader (no skeleton needed)
$(USER_BIN): $(USER_SRC)
	$(CC) $(CFLAGS) $(CPPFLAGS) $< -o $@ $(LIBS)

# Build ipmask_tool utility
$(IPMASK_BIN): $(IPMASK_SRC)
	$(CC) $(CFLAGS) $(CPPFLAGS) $< -o $@

clean:
	rm -f $(BPF_OBJ) $(USER_BIN) $(IPMASK_BIN)

.PHONY: all clean
