// ─────────────────────────────────────────────────────────────────────────────
// main.zig
// CLI sniffer demo — shows how to use capture.zig
// Run: zig build run
// ─────────────────────────────────────────────────────────────────────────────

const std = @import("std");
const capture = @import("capture.zig");
const parser  = @import("packet/parser.zig");
const types   = @import("packet/types.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout = std.io.getStdOut().writer();

    // ── Print Npcap version ───────────────────────────────────────────────────
    try stdout.print("Npcap: {s}\n\n", .{capture.version()});

    // ── List devices ──────────────────────────────────────────────────────────
    const devices = capture.listDevices(allocator) catch |err| {
        try stdout.print("Failed to list devices: {}\n", .{err});
        try stdout.print("Make sure Npcap is installed and you're running as Admin.\n", .{});
        return;
    };
    defer capture.freeDevices(allocator, devices);

    try stdout.print("Available interfaces:\n", .{});
    for (devices, 0..) |dev, i| {
        const kind = if (dev.is_wireless) "WiFi"
                     else if (dev.is_loopback) "Loop"
                     else "Eth ";
        try stdout.print("  [{d}] [{s}] {s}\n       {s}\n",
            .{ i, kind, dev.name, dev.description });
    }

    // ── Pick first non-loopback device ───────────────────────────────────────
    var chosen: ?capture.Device = null;
    for (devices) |dev| {
        if (!dev.is_loopback) {
            chosen = dev;
            break;
        }
    }

    const dev = chosen orelse {
        try stdout.print("\nNo usable interface found.\n", .{});
        return;
    };

    try stdout.print("\nOpening: {s}\n", .{dev.name});

    // Need a null-terminated version of the device name
    const name_z = try allocator.dupeZ(u8, dev.name);
    defer allocator.free(name_z);

    var cap = capture.openDevice(name_z, 65535, true, 1000) catch |err| {
        try stdout.print("Failed to open device: {}\n", .{err});
        return;
    };
    defer cap.close();

    // ── Optional: set BPF filter ──────────────────────────────────────────────
    // Uncomment to filter:
    // try cap.setFilter("tcp");
    // try cap.setFilter("port 80");
    // try cap.setFilter("udp");

    try stdout.print("Capturing 20 packets (Ctrl+C to stop early)...\n\n", .{});

    // ── Capture loop ──────────────────────────────────────────────────────────
    var count: u32 = 0;
    while (count < 20) {
        const pkt = cap.nextPacket() orelse continue;
        count += 1;

        try printPacket(stdout, pkt, count);
    }
}

// ── Packet printer ────────────────────────────────────────────────────────────

fn printPacket(
    writer: anytype,
    pkt: types.Packet,
    n: u32,
) !void {
    try writer.print("── Packet #{d} ─── {d} bytes (wire: {d}) ──\n",
        .{ n, pkt.data.len, pkt.original_len });

    // Try Ethernet
    const eth = parser.parseEthernet(pkt.data) catch {
        try writer.print("  [raw, datalink={d}]\n\n", .{pkt.datalink});
        return;
    };

    var mac_buf: [17]u8 = undefined;
    var mac_buf2: [17]u8 = undefined;
    try writer.print("  ETH  {s} → {s}  type=0x{x:0>4}\n", .{
        types.formatMac(eth.src, &mac_buf),
        types.formatMac(eth.dst, &mac_buf2),
        @intFromEnum(eth.ether_type),
    });

    // Try IPv4
    if (eth.ether_type == .ipv4) {
        const ip = parser.parseIpv4(eth.payload) catch {
            try writer.print("  [IPv4 parse error]\n\n", .{});
            return;
        };

        var ip_buf: [15]u8 = undefined;
        var ip_buf2: [15]u8 = undefined;
        try writer.print("  IPv4 {s} → {s}  proto={s}  ttl={d}\n", .{
            types.formatIp(ip.src, &ip_buf),
            types.formatIp(ip.dst, &ip_buf2),
            @tagName(ip.proto),
            ip.ttl,
        });

        switch (ip.proto) {
            .tcp => {
                const tcp = parser.parseTcp(ip.payload) catch return;
                try writer.print("  TCP  :{d} → :{d}  seq={d}  flags=[{s}{s}{s}{s}{s}]\n", .{
                    tcp.src_port,
                    tcp.dst_port,
                    tcp.seq,
                    if (tcp.flags.syn) "S" else "",
                    if (tcp.flags.ack) "A" else "",
                    if (tcp.flags.fin) "F" else "",
                    if (tcp.flags.rst) "R" else "",
                    if (tcp.flags.psh) "P" else "",
                });
            },
            .udp => {
                const udp = parser.parseUdp(ip.payload) catch return;
                try writer.print("  UDP  :{d} → :{d}  payload={d}b\n", .{
                    udp.src_port,
                    udp.dst_port,
                    udp.payload.len,
                });
            },
            else => {},
        }
    }

    try writer.print("\n", .{});
}
