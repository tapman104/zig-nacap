# npcap_zig

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
| **Zig** | 0.16.0 |
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
const proto     = npcap_zig.proto;

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
        const eth = try proto.eth.parseEthernet(pkt.data);
        if (eth.ether_type != .ipv4) continue;
        
        const ip = try proto.ipv4.parseIpv4(eth.payload);
        if (ip.proto != .tcp) continue;
        
        const tcp = try proto.tcp.parseTcp(ip.payload);

        var ib1: [15]u8 = undefined;
        var ib2: [15]u8 = undefined;
        std.debug.print("TCP  {s}:{d}  →  {s}:{d}  payload={d}b\n", .{
            proto.ipv4.formatIp(ip.src, &ib1), tcp.src_port,
            proto.ipv4.formatIp(ip.dst, &ib2), tcp.dst_port,
            tcp.payload.len,
        });
    }
}
```

---

## Protocol Support

| Layer | Protocol | Function | Return type |
|---|---|---|---|
| L2 | Ethernet | `proto.eth.parseEthernet` | `ParseError!EthernetFrame` |
| L2 | ARP | `proto.arp.parseArp` | `ParseError!ArpPacket` |
| L3 | IPv4 | `proto.ipv4.parseIpv4` | `ParseError!Ipv4Header` |
| L3 | IPv6 | `proto.ipv6.parseIpv6` | `ParseError!Ipv6Header` |
| L4 | ICMPv4 | `proto.icmpv4.parseIcmp` | `ParseError!IcmpMessage` |
| L4 | ICMPv6 | `proto.icmpv6.parseIcmpv6` | `ParseError!Icmpv6Message` |
| L4 | TCP | `proto.tcp.parseTcp` | `ParseError!TcpSegment` |
| L4 | UDP | `proto.udp.parseUdp` | `ParseError!UdpDatagram` |
| L7 | DNS | `proto.dns.parseDns` | `ParseError!DnsMessage` |
| L7 | HTTP/1.x | `proto.http.detect` | `?HttpHint` |

All parsers are **pure functions**: no allocator, no I/O, no side effects.
All string/slice results point into the **original packet buffer** — zero-copy.

---

## TCP Flow Tracking

The library includes a stateful TCP flow tracker that handles normalization (client/server detection) and connection state transitions.

```zig
const flow = npcap_zig.flow;
// ... inside capture loop ...
const status = flow.processTcp(&flow_table, pkt, ip.src, ip.dst, tcp, ip.payload.len);
// status: "flow=NEW", "flow=ESTABLISHED", "flow=FIN_WAIT", etc.
```

---

## Examples

| File | Build step | Description |
|---|---|---|
| [`examples/basic_capture.zig`](examples/basic_capture.zig) | `zig build run` | Full multi-protocol sniffer with flow tracking |
| [`examples/dns_monitor.zig`](examples/dns_monitor.zig) | `zig build dns_monitor` | BPF-filtered DNS query logger |

### Building

```powershell
# Build + run the full sniffer (20 packets)
zig build run

# Build + run the DNS logger (runs until Ctrl+C)
zig build dns_monitor

# Build everything without running
zig build
```

---

## Module Layout

```
src/
  root.zig            ← Public API re-exports
  capture.zig         ← Npcap live/file capture engine
  packet.zig          ← ParsedPacket and Layer3/4 unions
  flow/
    tracker.zig       ← TCP flow tracking state machine
  proto/
    errors.zig        ← Shared parsing error set
    eth.zig           ← Ethernet II frame parser
    ipv4.zig          ← IPv4 header parser
    ipv6.zig          ← IPv6 header + extension headers
    arp.zig           ← Address Resolution Protocol (ARP)
    tcp.zig           ← TCP segment parser
    udp.zig           ← UDP datagram parser
    icmpv4.zig        ← ICMPv4 message parser
    icmpv6.zig        ← ICMPv6 / NDP parser
    dns.zig           ← DNS (RFC 1035) Question/Answer parser
    http.zig          ← HTTP/1.1 method/host detector
  backend/
    npcap_raw.zig     ← Low-level pcap DLL wrapper
```

---

## License

[MIT](LICENSE)
