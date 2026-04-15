# zig-nacap (npcap-zig)

**zig-nacap** is an idiomatic, high-performance Zig 0.16.0 wrapper for **Npcap** on Windows. It enables developers to build powerful network monitoring tools, packet sniffers, and protocol analyzers with ease.

Built for the modern Zig ecosystem, it prioritizes **zero-allocation** and **zero-copy** parsing, ensuring your applications remain lean and fast.

---

## 🚀 Key Features

- **Idiomatic Zig API**: No leaky C abstractions. Work with native Zig structs and errors.
- **Zero-Allocation Decoding**: Protocol parsers use no memory allocator.
- **Zero-Copy Performance**: All data slices point directly into the original packet buffer.
- **Comprehensive Protocol Support**:
    - **L2**: Ethernet, ARP
    - **L3**: IPv4, IPv6, ICMPv4
    - **L4**: TCP, UDP
    - **L7**: DNS, HTTP/1.x (Hint Detection)
- **Native Windows Backend**: Integrates directly with Npcap `wpcap.dll` and `Packet.dll`.
- **BPF Filtering**: Full support for Berkeley Packet Filter strings.

---

## 📚 Table of Contents

1. [**Introduction**](./index.md) (You are here)
2. [**Installation & Setup**](./installation.md)
   - Windows environment, Npcap SDK, and project integration.
3. [**Getting Started**](./getting-started.md)
   - A simple guide to listing devices and capturing your first packet.
4. [**API Reference**]()
   - [Capture API](./api/capture.md) — Opening devices, loops, and filters.
   - [Parser API](./api/parser.md) — Core L2, L3, and L4 protocol decoding.
   - [Protocol Modules](./api/proto.md) — DNS and HTTP specialist parsers.
   - [Types & Headers](./api/types.md) — Struct definitions and constants.
5. [**Examples**](./examples.md)
   - Walkthrough of the included sniffer and monitor tools.
6. [**Roadmap**](./roadmap.md)
   - Current status and future goals.

---

## ⚡ Quick Start

```zig
const std = @import("std");
const npcap = @import("npcap_zig");

pub fn main() !void {
    // List available network interfaces
    const devices = try npcap.capture.listDevices(std.heap.c_allocator);
    defer npcap.capture.freeDevices(std.heap.c_allocator, devices);

    for (devices) |dev| {
        std.debug.print("Found: {s} ({s})\n", .{ dev.name, dev.description });
    }
}
```

---

> **Note:** Capture operations require **Administrator** privileges on Windows.
