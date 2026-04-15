# Capture API Reference

The `capture` module provides the primary interface for interacting with Npcap. It handles device enumeration, session management, and packet reception.

| Import Path |
| :--- |
| `@import("npcap_zig").capture` |

---

## Functions

### `listDevices`
Scans the system for available network interfaces.

```zig
pub fn listDevices(allocator: std.mem.Allocator) CaptureError![]Device
```
- **Returns**: A slice of `Device` structs.
- **Note**: This allocates memory for the strings and the slice. You must call `freeDevices` to prevent leaks.

### `freeDevices`
Cleans up the memory allocated by `listDevices`.

```zig
pub fn freeDevices(allocator: std.mem.Allocator, devices: []Device) void
```

### `openDevice`
Opens a live capture session on a network adapter.

```zig
pub fn openDevice(
    device_name: [:0]const u8,
    snaplen: i32,
    promisc: bool,
    timeout_ms: i32
) CaptureError!CaptureHandle
```
- **`device_name`**: The `\0` terminated name from `Device.name`.
- **`snaplen`**: Maximum size of bytes to capture per packet (e.g., 65535).
- **`promisc`**: Whether to put the interface in promiscuous mode.
- **`timeout_ms`**: Read timeout in milliseconds.

### `openFile`
Opens a saved `.pcap` or `.pcapng` file for offline analysis.

```zig
pub fn openFile(path: [:0]const u8) CaptureError!CaptureHandle
```

### `lastError`
Returns the descriptive error message from the Npcap backend if a function fails.

```zig
pub fn lastError() ?[]const u8
```

---

## `CaptureHandle` (Struct)

Represent an active capture session.

### `close()`
Closes the session and releases the Npcap handle. Always `defer` this.

```zig
pub fn close(self: *CaptureHandle) void
```

### `setFilter()`
Applies a BPF (Berkeley Packet Filter) string.

```zig
pub fn setFilter(self: *CaptureHandle, filter: [:0]const u8) CaptureError!void
```
- **Example**: `try handle.setFilter("tcp and port 443")`
- **Throws**: `error.FilterCompileFailed` if the syntax is incorrect.

### `nextPacket()`
Polls for a single packet. Returns `null` if no packet reached the buffer during the timeout.

```zig
pub fn nextPacket(self: *CaptureHandle) ?types.Packet
```
- **Returns**: A `types.Packet` containing the timestamp and a slice to the raw data.
- **Note**: The returned data slice points to an internal Npcap buffer. It is only valid until the next call to `nextPacket` or `loop`.

### `loop()`
High-performance capture loop that calls a callback function.

```zig
pub fn loop(
    self: *CaptureHandle,
    count: i32,
    comptime callback: fn (pkt: types.Packet) void
) CaptureError!void
```
- **`count`**: Number of packets to capture. Pass `-1` to loop indefinitely.
- **`callback`**: A function taking a single `types.Packet`.

### `stop()`
Safely breaks out of a running `loop()`. Call this from another thread or from the callback to stop capturing.

```zig
pub fn stop(self: *CaptureHandle) void
```

---

## Errors

The API uses the `CaptureError` error set:

- `DeviceEnumFailed`: Could not query system interfaces.
- `NoDevicesFound`: Npcap returned an empty list.
- `OpenFailed`: Invalid device name or insufficient permissions.
- `FilterCompileFailed`: BPF string syntax error.
- `FilterSetFailed`: Could not apply the filter to the driver.
- `CaptureFailed`: Unexpected error during the capture loop.
