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
### Requirements

Before using the Makefile, ensure you have the following installed on your system:

- Linux with eBPF support
- Clang/LLVM
- Kernel headers
- Go (for user-space control)
- libelf-dev: A library to handle ELF files (used by the eBPF program).

### Targets:

The Makefile contains the following targets:
1. install-deps

Description: Installs the necessary dependencies for building and running the eBPF and user-space programs.

Usage:

```bash

make install-deps
```
2. $(TARGET)

Description: Compiles the eBPF program (tc.c) into a binary object file (tc.o).

Usage:

```bash

make tc.o
```
3. load

Description: Loads the compiled eBPF program into the kernel using the tc command. This sets up a classifier-action (clsact) qdisc and attaches the eBPF program to the ingress and egress filters on the specified network interface.

Usage:

```bash

make load
```
4. view

Description: Views the output of bpf_printk in the kernel trace pipe.

Usage:

```bash

make view
```
5. view-tcp

Description: Filters the trace_pipe output to show only TCP-related logs.

Usage:

```bash

make view-tcp
```
6. view-udp

Description: Filters the trace_pipe output to show only UDP-related logs.

Usage:

```bash

make view-udp
```
7. build-US

Description: Compiles the Go user-space program (tc.go) located in the user_space directory.

Usage:

```bash

make build-US
```
8. start-US

Description: Starts the compiled user-space program (tc_US).

Usage:

```bash

make start-US
```
9. clean

Description: Cleans up the environment by removing the compiled eBPF object file, the user-space binary, and detaching the eBPF program from the network interface.

Usage:

```bash

make clean
```
10. all

Description: Executes all the steps in sequence: installs dependencies, compiles the eBPF program, builds the user-space program, and starts the user-space program.

Usage:

```bash

make all
```
### Notes

The default network interface used in this Makefile is enp1s0. If your network interface is different, modify the INTERFACE variable in the Makefile.
Ensure you have root privileges to execute some of these commands as they interact with the network interface and kernel tracing features.

# License

This project is licensed under the MIT License.
