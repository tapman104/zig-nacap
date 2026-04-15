// ─────────────────────────────────────────────────────────────────────────────
// examples/dns_monitor.zig
// Captures only UDP port 53 traffic and prints DNS query names.
// Usage: zig build dns_monitor
// Requires Npcap installed and running as Administrator.
// ─────────────────────────────────────────────────────────────────────────────

const std       = @import("std");
const npcap_zig = @import("npcap_zig");
const capture   = npcap_zig.capture;
const types     = npcap_zig.proto.types;
const parser    = npcap_zig.proto.parser;
const dns       = npcap_zig.proto.dns;

pub fn main() !void {
    const allocator = std.heap.c_allocator;
    std.debug.print("[dns_monitor] DNS query logger\n", .{});
    std.debug.print("Npcap: {s}\n\n", .{capture.version()});

    // ── List and pick non-loopback device ─────────────────────────────────────
    const devices = capture.listDevices(allocator) catch |err| {
        std.debug.print("Failed to list devices: {}\n", .{err});
        std.debug.print("Make sure Npcap is installed and run as Admin.\n", .{});
        return;
    };
    defer capture.freeDevices(allocator, devices);

    var chosen: ?capture.Device = null;
    for (devices) |dev| {
        if (!dev.is_loopback) { chosen = dev; break; }
    }
    const dev = chosen orelse {
        std.debug.print("No usable interface found.\n", .{});
        return;
    };

    std.debug.print("Interface: {s}\n", .{dev.name});

    const name_z = try allocator.dupeZ(u8, dev.name);
    defer allocator.free(name_z);

    // ── Open device ───────────────────────────────────────────────────────────
    var cap = capture.openDevice(name_z, 65535, true, 1000) catch |err| {
        std.debug.print("Failed to open device: {}\n", .{err});
        if (capture.lastError()) |msg| std.debug.print("Detail: {s}\n", .{msg});
        return;
    };
    defer cap.close();

    // ── Apply BPF filter ──────────────────────────────────────────────────────
    cap.setFilter("udp port 53") catch |err| {
        std.debug.print("Filter error: {}\n", .{err});
        if (capture.lastError()) |msg| std.debug.print("Detail: {s}\n", .{msg});
        return;
    };
    std.debug.print("Filter : udp port 53\n", .{});
    std.debug.print("Listening for DNS queries (Ctrl+C to stop)...\n\n", .{});

    // ── Capture loop ──────────────────────────────────────────────────────────
    while (true) {
        const pkt = cap.nextPacket() orelse {
            if (capture.lastError()) |msg| {
                std.debug.print("Capture error: {s}\n", .{msg});
                break;
            }
            continue;
        };
        processDnsPacket(pkt);
    }
}

// ── Internal: ETH → IP → UDP → DNS ───────────────────────────────────────────
// No I/O inside decoders; all printing happens here.

fn processDnsPacket(pkt: types.Packet) void {
    const eth = parser.parseEthernet(pkt.data) catch return;

    const udp_payload: []const u8 = switch (eth.ether_type) {
        .ipv4 => blk: {
            const ip = parser.parseIpv4(eth.payload) catch return;
            if (ip.proto != .udp) return;
            const udp = parser.parseUdp(ip.payload) catch return;
            break :blk udp.payload;
        },
        .ipv6 => blk: {
            const ip6 = parser.parseIpv6(eth.payload) catch return;
            if (ip6.proto != .udp) return;
            const udp = parser.parseUdp(ip6.payload) catch return;
            break :blk udp.payload;
        },
        else => return,
    };

    const msg = dns.parseDns(udp_payload) catch return;
    const kind = if (msg.is_response) "reply " else "query ";

    var qi: u8 = 0;
    while (qi < msg.question_count) : (qi += 1) {
        const q = &msg.questions[qi];
        std.debug.print("DNS  {s}  {s}  type={s}\n", .{
            kind, q.name(), @tagName(q.qtype),
        });
    }
}
