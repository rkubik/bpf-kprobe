# BPF Kprobe

Loads BPF instructions into the kernel to count the number of times a
syscall has been made.

## Build

Ensure you have the bcc library installed[1].

    mkdir build
    cd build
    cmake ..
    make

1. https://github.com/iovisor/bcc

## Usage

    ./bin/bpf-kprobe <symbol name>

    ./bin/bpf-kprobe sys_rename
    count: 1
