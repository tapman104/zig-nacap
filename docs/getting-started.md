# Getting Started

This guide walks you through a basic "Hello World" of packet capture: finding your network device and listening for any incoming data.

---

## 1. List Network Devices

Before you can capture packets, you need to identify which network adapter to use. `zig-nacap` provides a simple way to iterate through interfaces.

```zig
const std = @import("std");
const npcap = @import("npcap_zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Retrieve a list of all devices
    const devices = try npcap.capture.listDevices(allocator);
    defer npcap.capture.freeDevices(allocator, devices);

    for (devices, 0..) |dev, i| {
        std.debug.print("[{d}] {s}\n    Description: {s}\n    Wireless? {any}\n", .{
            i, dev.name, dev.description, dev.is_wireless
        });
    }
}
```

---

## 2. Open a Capture Session

Once you have a device name, you can open a `CaptureHandle`.

```zig
// Assuming 'chosen_device' is a name from the list above
var cap = try npcap.capture.openDevice(
    chosen_device, // Device name string
    65535,         // Snapshot length (max bytes per packet)
    true,          // Promiscuous mode
    1000           // Read timeout in milliseconds
);
defer cap.close();
```

---

## 3. The Capture Loop

There are two main ways to receive packets: `loop()` (callback-based) and `nextPacket()` (polling-based).

### Using `nextPacket` (Simple Polling)
This is usually easier for simple CLI tools.

```zig
while (true) {
    // nextPacket() returns ?Packet
    if (cap.nextPacket()) |pkt| {
        std.debug.print("Captured packet! Size: {d} bytes\n", .{pkt.data.len});
    }
}
```

### Using `loop` (High Performance)
This calls a callback function for every packet, which is more efficient for high-volume traffic.

```zig
fn handlePacket(pkt: npcap.types.Packet) void {
    std.debug.print("Time: {d} | Bytes: {d}\n", .{pkt.timestamp_us, pkt.data.len});
}

// ... inside main ...
try cap.loop(-1, handlePacket); // -1 means loop forever
```

---

## 4. Full Basic Example

Combine everything into a small sniffer that counts packets:

```zig
const std = @import("std");
const npcap = @import("npcap_zig");

pub fn main() !void {
    const allocator = std.heap.c_allocator;

    const devices = try npcap.capture.listDevices(allocator);
    defer npcap.capture.freeDevices(allocator, devices);

    if (devices.len == 0) return error.NoDevices;
    
    // Just pick the first device for this example
    const dev = devices[0];
    const name_z = try allocator.dupeZ(u8, dev.name);
    defer allocator.free(name_z);

    std.debug.print("Opening {s}...\n", .{dev.description});

    var cap = try npcap.capture.openDevice(name_z, 65535, true, 1000);
    defer cap.close();

    var count: usize = 0;
    while (count < 10) {
        if (cap.nextPacket()) |_| {
            count += 1;
            std.debug.print("Received packet {d}/10\r", .{count});
        }
    }
    std.debug.print("\nDone!\n", .{});
}
```

---

> **Tip:** Visit the [API Reference](./api/capture.md) to learn about BPF filters and offline file reading (.pcap).
