# Core Types & Headers

The `types` module (accessible via `npcap_zig.proto.types`) defines all the native Zig structures used to represent network headers.

---

## Packet Structure

Every capture returns a `Packet` struct.

```zig
pub const Packet = struct {
    timestamp_us: u64,  // Microseconds since Unix epoch
    data: []const u8,   // Raw slice into the capture buffer
    original_len: u32,  // Wire length (may be larger than data.len if truncated)
    datalink: i32,      // The DLT type (e.g., DLT_EN10MB for Ethernet)
};
```

---

## Protocol Headers

These structs are returned by the [Parser API](./parser.md). All payload fields are `[]const u8` slices that point directly into the captured packet's data.

### Layer 2

| Struct | Fields |
| :--- | :--- |
| `EthernetFrame` | `dst: MacAddr`, `src: MacAddr`, `ether_type: EtherType`, `payload: []const u8` |
| `ArpPacket` | `operation: ArpOp`, `sender_mac: MacAddr`, `sender_ip: [4]u8`, `target_mac: MacAddr`, `target_ip: [4]u8` |

### Layer 3

| Struct | Fields |
| :--- | :--- |
| `Ipv4Header` | `src: [4]u8`, `dst: [4]u8`, `proto: IpProto`, `ttl: u8`, `payload: []const u8` |
| `Ipv6Header` | `src: [16]u8`, `dst: [16]u8`, `proto: IpProto`, `hop_limit: u8`, `payload: []const u8` |
| `IcmpMessage` | `type_: u8`, `code: u8`, `payload: []const u8` |

### Layer 4

| Struct | Fields |
| :--- | :--- |
| `TcpSegment` | `src_port: u16`, `dst_port: u16`, `seq: u32`, `ack: u32`, `flags: TcpFlags`, `payload: []const u8` |
| `UdpDatagram` | `src_port: u16`, `dst_port: u16`, `payload: []const u8` |

---

## Enums & Bitfields

### `EtherType` (u16)
- `.ipv4` = `0x0800`
- `.arp` = `0x0806`
- `.ipv6` = `0x86DD`

### `IpProto` (u8)
- `.icmp` = `1`
- `.tcp` = `6`
- `.udp` = `17`

### `TcpFlags` (u8 Packed)
A 1-byte bitfield representing the TCP control flags:
`fin`, `syn`, `rst`, `psh`, `ack`, `urg`.

---

## Helper Functions

These functions are useful for turning raw byte arrays into human-readable strings.

| Function | Output Format |
| :--- | :--- |
| `formatMac(mac, buf)` | `aa:bb:cc:dd:ee:ff` |
| `formatIp(ip4, buf)` | `192.168.1.1` |
| `formatIpv6(ip6, buf)` | `2001:0db8:0000:0000:0000:8a2e:0370:7334` |

> **Note:** These functions require a `[]u8` buffer to write into. The return value is a slice into that buffer.

```zig
var buf: [39]u8 = undefined;
const s = types.formatIpv6(ipv6_header.src, &buf);
std.debug.print("Source: {s}\n", .{s});
```
