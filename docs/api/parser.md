# Parser API Reference

The `parser` module contains pure-Zig functions to decode raw packet bytes into human-readable headers.

| Feature | Details |
| :--- | :--- |
| **Import Path** | `@import("npcap_zig").proto.parser` |
| **Memory** | **Zero-allocation**. No allocator required. |
| **Logic** | **Zero-copy**. Strings and payloads point directly into the input buffer. |
| **Dependencies**| **None**. Pure Zig code with no C headers or libc. |

---

## Error Handling

All parser functions use the `ParseError` error set:

- `TooShort`: The data buffer was smaller than the minimum header size for that protocol.
- `InvalidHeader`: The data did not conform to the protocol (e.g., incorrect version number).
- `UnsupportedProtocol`: The packet contains a protocol variation not yet handled by this parser.

---

## Layer 2: Data Link

### `parseEthernet`
Decodes an Ethernet II frame.

```zig
pub fn parseEthernet(data: []const u8) ParseError!EthernetFrame
```
- **Returns**: `EthernetFrame` struct with MAC addresses and the inner `EtherType`.

### `parseArp`
Decodes an ARP (Address Resolution Protocol) packet.

```zig
pub fn parseArp(data: []const u8) ParseError!ArpPacket
```

---

## Layer 3: Network

### `parseIpv4`
Decodes an IPv4 header. Automatically handles IHL (Header Length) to find the payload.

```zig
pub fn parseIpv4(data: []const u8) ParseError!Ipv4Header
```

### `parseIpv6`
Decodes an IPv6 header. 

```zig
pub fn parseIpv6(data: []const u8) ParseError!Ipv6Header
```
- **Note**: This parser automatically traverses and skips common extension headers (Hop-by-Hop, Routing, Fragment, etc.) to reach the actual upper-layer protocol (TCP/UDP).

### `parseIcmp`
Decodes an ICMPv4 message.

```zig
pub fn parseIcmp(data: []const u8) ParseError!IcmpMessage
```

---

## Layer 4: Transport

### `parseTcp`
Decodes a TCP segment. Handles the data offset to find the payload.

```zig
pub fn parseTcp(data: []const u8) ParseError!TcpSegment
```
- **Returns**: `TcpSegment` containing ports, sequence numbers, and a bitfield of flags (SYN, ACK, etc.).

### `parseUdp`
Decodes a UDP datagram.

```zig
pub fn parseUdp(data: []const u8) ParseError!UdpDatagram
```

---

## Usage Pattern

Parsers are designed to be chained in a `switch` or `if` sequence based on the `ether_type` or `proto` field.

```zig
const eth = try parser.parseEthernet(pkt.data);

switch (eth.ether_type) {
    .ipv4 => {
        const ip = try parser.parseIpv4(eth.payload);
        // ... process IP ...
    },
    .ipv6 => {
        const ip = try parser.parseIpv6(eth.payload);
        // ... process IPv6 ...
    },
    else => {},
}
```
