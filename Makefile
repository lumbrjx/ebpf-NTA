# Variables
TARGET = tc.o
INTERFACE = enp1s0

# Dependencies installation
.PHONY: install-deps
install-deps:
	sudo apt update
	sudo apt install -y clang llvm libelf-dev linux-headers-$$(uname -r) build-essential

# Compile the eBPF program
$(TARGET): tc.c
	clang -O2 -target bpf -c tc.c -o $(TARGET)

# Load the eBPF program
.PHONY: load
load: $(TARGET)
	sudo tc qdisc add dev $(INTERFACE) clsact
	sudo tc filter add dev $(INTERFACE) ingress bpf da obj $(TARGET) sec tc
	sudo tc filter add dev $(INTERFACE) egress bpf da obj $(TARGET) sec tc

# View bpf_printk output
.PHONY: view
view:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

# Remove the filters and qdisc when done
.PHONY: clean
clean:
	sudo tc filter del dev $(INTERFACE) ingress
	sudo tc filter del dev $(INTERFACE) egress
	sudo tc qdisc del dev $(INTERFACE) clsact
	rm -f $(TARGET)

# All
.PHONY: all
all: install-deps $(TARGET) load
