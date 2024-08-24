# eBPF Network Traffic Analyzer

### This repository contains an eBPF program designed to analyze network traffic on a Linux system. The program is compiled with Clang and loaded into the Linux kernel using the tc (Traffic Control) command. It attaches to both the ingress and egress paths of a specified network interface, allowing real-time inspection and filtering of packets.

## Features

- Packet Inspection: Analyze incoming and outgoing packets on a specific network interface.
- Real-Time Logging: Use bpf_printk to log packet details directly from the kernel.
- User-Space Control with Go: A Go program is provided for interacting with the eBPF program in user space, offering an easy and flexible way to control and retrieve data from the eBPF program.
- Easy Setup: Automated setup and cleanup using a Makefile.

## Getting Started

Clone the repository and run make all to compile and load the eBPF program.

```bash

git clone https://github.com/lumbrjx/ebpf-NTA.git
cd ebpf-NTA
make all
```
# Requirements

- Linux with eBPF support
- Clang/LLVM
- Kernel headers
- Go (for user-space control)

# License

This project is licensed under the MIT License.
