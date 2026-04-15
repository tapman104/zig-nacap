# Protocol Specialist API

For complex Application Layer (L7) protocols, `zig-nacap` provides specialized modules that handle detailed field extraction.

| Module | Purpose | Memory |
| :--- | :--- | :--- |
| `dns` | Full RFC 1035 message parsing | **Zero-allocation** (stack buffers) |
| `http` | HTTP/1.x line & header detection | **Zero-allocation** (slices) |

---

## DNS (`proto.dns`)

The DNS module provides a robust parser for UDP-based DNS messages. It automatically handles **name compression** (pointer-following) without requiring a heap allocator.

### `parseDns`
Parses a DNS message from a raw UDP payload.

```zig
pub fn parseDns(data: []const u8) ParseError!DnsMessage
```

### `DnsMessage` (Struct)
- `id`: Transaction ID.
- `questions`: An array of up to 8 `DnsQuestion`.
- `answers`: An array of up to 16 `DnsRecord`.
- Flags: `is_response`, `rcode`, `opcode`, etc.

### `DnsQuestion` & `DnsRecord`
Both include a `.name()` method to retrieve the decoded domain name (e.g., `"google.com"`).

```zig
if (msg.questions[0].name() == "example.org") { ... }
```

> **Note:** Decoded names are stored in a small inline buffer within the struct. This allows the parser to work without an allocator, but limits the name length to 253 characters (RFC standard).

---

## HTTP (`proto.http`)

The HTTP module is a high-speed detector designed for passive traffic inspection. It is **not** a full streaming HTTP state machine; it is optimized for classifying the start of a connection.

### `detect`
Quickly classifies a TCP payload as an HTTP request or response. Perfect for "first look" sniffers.

```zig
pub fn detect(data: []const u8) ?HttpHint 
```
- **Returns**: `?HttpHint` containing the first line, the `Host:` header value, and a request/response boolean.

### `parseHttp`
A more detailed parser for the HTTP start line.

```zig
pub fn parseHttp(data: []const u8) ParseError!HttpMessage
```

### `HttpMessage` (Union)
- `request`: Contains `.method` (enum), `.path`, and `.version`.
- `response`: Contains `.version`, `.status_code` (u16), and `.reason`.

---

## Usage Example

```zig
const dns = @import("npcap_zig").proto.dns;

// Inside a UDP capture loop...
if (udp.dst_port == 53 or udp.src_port == 53) {
    if (dns.parseDns(udp.payload)) |msg| {
        for (msg.questions[0..msg.question_count]) |q| {
            std.debug.print("Query for: {s}\n", .{ q.name() });
        }
    } else |_| {}
}
```
