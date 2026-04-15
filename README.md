# npcap\_zig

Idiomatic Zig 0.16 wrapper for [Npcap](https://npcap.com/) on Windows.

Zero-allocation packet capture with pure-Zig protocol decoders.
No libc, no C++ headers, no global state leaking into userspace.

---

## Requirements

| Requirement | Details |
|---|---|
| **OS** | Windows 10 / 11 (64-bit) |
| **Npcap** | [npcap.com](https://npcap.com/#download) — must be installed before running |
| **Npcap SDK** | [npcap-sdk-1.13.zip](https://npcap.com/dist/npcap-sdk-1.13.zip) extracted to `C:\npcap-sdk` |
| **Zig** | 0.16.0 or newer |
| **Privileges** | Run executables **as Administrator** |

---

## Adding as a Dependency

1. In your project's `build.zig.zon`, add:

```zig
.dependencies = .{
    .npcap_zig = .{
        .url  = "https://github.com/youruser/npcap_zig/archive/refs/tags/v0.1.0.tar.gz",
        .hash = "<zig fetch output here>",
    },
},
```

2. In your `build.zig`, fetch and import the module:

```zig
const npcap_dep = b.dependency("npcap_zig", .{
    .target   = target,
    .optimize = optimize,
});
exe.root_module.addImport("npcap_zig", npcap_dep.module("npcap_zig"));
```

---

## Quick-Start Usage

```zig
const std       = @import("std");
const npcap_zig = @import("npcap_zig");
const capture   = npcap_zig.capture;
const types     = npcap_zig.proto.types;
const parser    = npcap_zig.proto.parser;

pub fn main() !void {
    const allocator = std.heap.c_allocator;

    // 1. List network interfaces
    const devices = try capture.listDevices(allocator);
    defer capture.freeDevices(allocator, devices);

    // 2. Open the first non-loopback interface
    var chosen: ?capture.Device = null;
    for (devices) |dev| {
        if (!dev.is_loopback) { chosen = dev; break; }
    }
    const dev = chosen orelse return;

    const name_z = try allocator.dupeZ(u8, dev.name);
    defer allocator.free(name_z);

    var cap = try capture.openDevice(name_z, 65535, true, 1000);
    defer cap.close();

    // 3. Optional BPF filter
    try cap.setFilter("tcp port 80");

    // 4. Capture loop
    while (true) {
        const pkt = cap.nextPacket() orelse continue;

        // 5. Decode ETH → IPv4 → TCP
        const eth = parser.parseEthernet(pkt.data) catch continue;
        if (eth.ether_type != .ipv4) continue;
        const ip = parser.parseIpv4(eth.payload) catch continue;
        if (ip.proto != .tcp) continue;
        const tcp = parser.parseTcp(ip.payload) catch continue;

        var ib1: [15]u8 = undefined;
        var ib2: [15]u8 = undefined;
        std.debug.print("TCP  {s}:{d}  →  {s}:{d}  ({d}b)\n", .{
            types.formatIp(ip.src, &ib1),  tcp.src_port,
            types.formatIp(ip.dst, &ib2),  tcp.dst_port,
            tcp.payload.len,
        });
    }
}
```

---

## Protocol Support

| Layer | Protocol | Function | Return type |
|---|---|---|---|
| L2 | Ethernet | `parser.parseEthernet` | `ParseError!EthernetFrame` |
| L2 | ARP | `parser.parseArp` | `ParseError!ArpPacket` |
| L3 | IPv4 | `parser.parseIpv4` | `ParseError!Ipv4Header` |
| L3 | IPv6 | `parser.parseIpv6` | `ParseError!Ipv6Header` |
| L3 | ICMPv4 | `parser.parseIcmp` | `ParseError!IcmpMessage` |
| L4 | TCP | `parser.parseTcp` | `ParseError!TcpSegment` |
| L4 | UDP | `parser.parseUdp` | `ParseError!UdpDatagram` |
| L7 | DNS | `dns.parseDns` | `ParseError!DnsMessage` |
| L7 | HTTP/1.x | `http.parseHttp` | `ParseError!HttpMessage` |
| L7 | HTTP hint | `http.detect` | `?HttpHint` |

All parsers are **pure functions**: no allocator, no I/O, no side effects.
All string/slice results point into the **original packet buffer** — zero-copy.

---

## Examples

| File | Build step | Description |
|---|---|---|
| [`examples/basic_capture.zig`](examples/basic_capture.zig) | `zig build run` | Full multi-protocol sniffer |
| [`examples/dns_monitor.zig`](examples/dns_monitor.zig) | `zig build dns_monitor` | BPF-filtered DNS query logger |

### Building

```powershell
# Build + run the full sniffer (20 packets)
zig build run

# Build + run the DNS logger (runs until Ctrl+C)
zig build dns_monitor

# Build everything without running
zig build

# Run tests
zig build test
```

---

## Module Layout

```
src/
  root.zig            ← only file downstream users import
  capture.zig         ← CaptureHandle, listDevices, openDevice, …
  backend/
    npcap_raw.zig     ← thin @cImport wrapper for wpcap.dll / Packet.dll
  proto/
    types.zig         ← all shared types (EthernetFrame, Ipv4Header, …)
    parser.zig        ← ETH, IPv4, IPv6, TCP, UDP, ARP, ICMP parsers
    dns.zig           ← DNS message parser (RFC 1035)
    http.zig          ← HTTP/1.x first-line + Host: header detector
    ipv6.zig          ← IPv6 fixed-header convenience wrapper
examples/
  basic_capture.zig
  dns_monitor.zig
```

---

## License

MIT — see LICENSE file.
