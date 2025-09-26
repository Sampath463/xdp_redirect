# ---- Makefile for xdp_redirect ----

BPF_CLANG ?= clang
BPF_CFLAGS ?= -O2 -g -Wall -target bpf \
  -I/usr/include -I/usr/include/aarch64-linux-gnu

# Interface where XDP will attach
IFACE ?= wlan0
SEC ?= xdp
OBJ := xdp_redirect.o
SRC := xdp_redirect.c

all: $(OBJ)

$(OBJ): $(SRC)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

load: $(OBJ)
	@echo "Attaching $(OBJ) (section $(SEC)) to $(IFACE)..."
	- sudo ip link set dev $(IFACE) xdp obj $(OBJ) sec $(SEC) || \
	  sudo ip link set dev $(IFACE) xdpgeneric obj $(OBJ) sec $(SEC)

unload:
	@echo "Detaching XDP from $(IFACE)..."
	- sudo ip link set dev $(IFACE) xdp off
	- sudo ip link set dev $(IFACE) xdpgeneric off

show:
	@ip -details -stat link show dev $(IFACE) | sed -n '/prog.xdp/,+10p' || true
	@which bpftool >/dev/null 2>&1 && bpftool net || true

trace:
	@echo "Reading trace_pipe logs... (Ctrl+C to stop)"
	sudo cat /sys/kernel/debug/tracing/trace_pipe

clean:
	rm -f $(OBJ)
