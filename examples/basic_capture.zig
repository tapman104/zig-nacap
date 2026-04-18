// ─────────────────────────────────────────────────────────────────────────────
// examples/basic_capture.zig
// Full-featured sniffer demo — shows the complete npcap_zig public API.
// Run:  zig build run
// Requires Npcap installed and Administrator privileges.
// ─────────────────────────────────────────────────────────────────────────────

const std       = @import("std");
const npcap_zig = @import("npcap_zig");
const capture   = npcap_zig.capture;
const types     = npcap_zig.proto.types;
const parser    = npcap_zig.proto.parser;
const dns       = npcap_zig.proto.dns;
const http      = npcap_zig.proto.http;

// ── Windows DLL reachability probe ──────────────────────────────────────────
// LoadLibraryA mirrors the OS loader search order — the only reliable check.
extern "kernel32" fn LoadLibraryA(
    lpLibFileName: [*:0]const u8,
) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn FreeLibrary(
    hLibModule: *anyopaque,
) callconv(.winapi) i32;

fn dllLoadable(name: [*:0]const u8) bool {
    const h = LoadLibraryA(name) orelse return false;
    _ = FreeLibrary(h);
    return true;
}

fn printNpcapDiagnostics(io: std.Io, allocator: std.mem.Allocator) void {
    std.debug.print("Startup diagnostics:\n", .{});
    const cwd = std.process.currentPathAlloc(io, allocator) catch |err| {
        std.debug.print("  cwd: <unavailable> ({})\n", .{err});
        return;
    };
    defer allocator.free(cwd);
    std.debug.print("  cwd: {s}\n", .{cwd});

    const dlls = [_][*:0]const u8{ "wpcap.dll", "Packet.dll" };
    std.debug.print("  DLL probes (via LoadLibraryA):\n", .{});
    for (dlls) |dll| {
        std.debug.print("    {s} -> {s}\n", .{
            dll,
            if (dllLoadable(dll)) "loadable" else "NOT loadable",
        });
    }
    std.debug.print("\n", .{});
}

fn printBackendErr() void {
    if (capture.lastError()) |msg|
        std.debug.print("Npcap detail: {s}\n", .{msg})
    else
        std.debug.print("Npcap detail: (none)\n", .{});
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn main() !void {
    const allocator = std.heap.c_allocator;
    std.debug.print("[basic_capture] start\n", .{});

    const io = std.Io.Threaded.global_single_threaded.io();
    printNpcapDiagnostics(io, allocator);

    std.debug.print("Npcap: {s}\n\n", .{capture.version()});

    // ── List devices ──────────────────────────────────────────────────────────
    const devices = capture.listDevices(allocator) catch |err| {
        std.debug.print("Failed to list devices: {}\n", .{err});
        printBackendErr();
        std.debug.print("Make sure Npcap is installed and run as Admin.\n", .{});
        return;
    };
    defer capture.freeDevices(allocator, devices);

    std.debug.print("Available interfaces:\n", .{});
    for (devices, 0..) |dev, i| {
        const kind = if (dev.is_wireless) "WiFi"
                     else if (dev.is_loopback) "Loop"
                     else "Eth ";
        std.debug.print("  [{d}] [{s}] {s}\n       {s}\n",
            .{ i, kind, dev.name, dev.description });
    }

    // ── Pick first non-loopback device ───────────────────────────────────────
    var chosen: ?capture.Device = null;
    for (devices) |dev| {
        if (!dev.is_loopback) { chosen = dev; break; }
    }
    const dev = chosen orelse {
        std.debug.print("\nNo usable interface found.\n", .{});
        return;
    };

    std.debug.print("\nOpening: {s}\n", .{dev.name});
    const name_z = try allocator.dupeZ(u8, dev.name);
    defer allocator.free(name_z);

    var cap = capture.openDevice(name_z, 65535, true, 1000) catch |err| {
        std.debug.print("Failed to open device: {}\n", .{err});
        printBackendErr();
        return;
    };
    defer cap.close();

    std.debug.print("Capturing 20 packets (Ctrl+C to stop early)...\n\n", .{});

    var count: u32 = 0;
    while (count < 20) {
        const pkt = cap.nextPacket() orelse {
            if (capture.lastError()) |_| {
                std.debug.print("Capture stopped due to backend error.\n", .{});
                printBackendErr();
                break;
            }
            continue;
        };
        count += 1;
        printPacket(pkt, count);
    }
}

// ── Packet printer ────────────────────────────────────────────────────────────

fn printPacket(pkt: types.Packet, n: u32) void {
    std.debug.print("--- Packet #{d} --- {d} bytes (wire: {d}) ---\n",
        .{ n, pkt.data.len, pkt.original_len });

    const eth = parser.parseEthernet(pkt.data) catch {
        std.debug.print("  [raw, datalink={d}]\n\n", .{pkt.datalink});
        return;
    };

    var m1: [17]u8 = undefined;
    var m2: [17]u8 = undefined;
    std.debug.print("  ETH  {s} -> {s}  type=0x{x:0>4}\n", .{
        types.formatMac(eth.src, &m1),
        types.formatMac(eth.dst, &m2),
        @intFromEnum(eth.ether_type),
    });

    switch (eth.ether_type) {
        .arp  => printArp(eth.payload),
        .ipv4 => printIpv4(eth.payload),
        .ipv6 => printIpv6(eth.payload),
        else  => {},
    }

    std.debug.print("\n", .{});
}

// ── Protocol printers — all output goes through std.debug.print ──────────────

fn printArp(payload: []const u8) void {
    const arp = parser.parseArp(payload) catch {
        std.debug.print("  [ARP parse error]\n", .{});
        return;
    };
    var ib1: [15]u8 = undefined;
    var ib2: [15]u8 = undefined;
    var mb:  [17]u8 = undefined;
    switch (arp.operation) {
        .request => std.debug.print("  ARP  request  {s} -> {s}\n", .{
            types.formatIp(arp.sender_ip, &ib1),
            types.formatIp(arp.target_ip, &ib2),
        }),
        .reply => std.debug.print("  ARP  reply    {s} is at {s}\n", .{
            types.formatMac(arp.sender_mac, &mb),
            types.formatIp(arp.sender_ip,  &ib1),
        }),
        _ => std.debug.print("  ARP  op={d}\n", .{@intFromEnum(arp.operation)}),
    }
}

fn printIcmp(payload: []const u8) void {
    const icmp = parser.parseIcmp(payload) catch {
        std.debug.print("  [ICMP parse error]\n", .{});
        return;
    };
    std.debug.print("  ICMP type={d} code={d}\n", .{ icmp.type_, icmp.code });
}

fn printIcmpv6(payload: []const u8) void {
    const icmp = parser.parseIcmpv6(payload) catch {
        std.debug.print("  [ICMPv6 parse error]\n", .{});
        return;
    };
    
    const type_num = @intFromEnum(icmp.type_);
    const type_str = switch (icmp.type_) {
        .destination_unreachable => "Destination Unreachable",
        .packet_too_big => "Packet Too Big",
        .time_exceeded => "Time Exceeded",
        .parameter_problem => "Parameter Problem",
        .echo_request => "Echo Request",
        .echo_reply => "Echo Reply",
        .mld_query => "MLD Query",
        .mld_report => "MLD Report",
        .mld_done => "MLD Done",
        .router_solicitation => "RS",
        .router_advertisement => "RA",
        .neighbor_solicitation => "NS",
        .neighbor_advertisement => "NA",
        .redirect => "Redirect",
        .mldv2_report => "MLDv2 Report",
        _ => "unknown",
    };
    
    const is_ndp = switch (icmp.type_) {
        .router_solicitation, .router_advertisement, .neighbor_solicitation, .neighbor_advertisement, .redirect => true,
        else => false,
    };
    
    std.debug.print("  ICMPv6 type={d} ({s})", .{ type_num, type_str });
    
    if (!is_ndp or icmp.code != 0) {
        std.debug.print(" code={d}", .{icmp.code});
    }

    if (icmp.type_ == .neighbor_solicitation or icmp.type_ == .neighbor_advertisement) {
        if (icmp.payload.len >= 20) {
            var tb: [39]u8 = undefined;
            const target_ip = icmp.payload[4..20].*;
            std.debug.print(" target={s}", .{types.formatIpv6(target_ip, &tb)});
        }
    }
    
    std.debug.print("\n", .{});
}

fn printTcp(payload: []const u8) void {
    const tcp = parser.parseTcp(payload) catch {
        std.debug.print("  [TCP parse error]\n", .{});
        return;
    };
    std.debug.print("  TCP  :{d} -> :{d}  seq={d}  flags=[{s}{s}{s}{s}{s}]\n", .{
        tcp.src_port, tcp.dst_port, tcp.seq,
        if (tcp.flags.syn) "S" else "",
        if (tcp.flags.ack) "A" else "",
        if (tcp.flags.fin) "F" else "",
        if (tcp.flags.rst) "R" else "",
        if (tcp.flags.psh) "P" else "",
    });

    // HTTP hint on port 80 / 8080
    const is_http_port =
        tcp.src_port == 80 or tcp.dst_port == 80 or
        tcp.src_port == 8080 or tcp.dst_port == 8080;
    if (is_http_port) {
        if (http.detect(tcp.payload)) |hint| {
            if (hint.host) |host| {
                std.debug.print("  HTTP {s}  host={s}\n", .{ hint.method, host });
            } else {
                std.debug.print("  HTTP {s}\n", .{hint.method});
            }
        }
    }
}

fn printUdp(payload: []const u8) void {
    const udp = parser.parseUdp(payload) catch {
        std.debug.print("  [UDP parse error]\n", .{});
        return;
    };
    std.debug.print("  UDP  :{d} -> :{d}  payload={d}b\n", .{
        udp.src_port, udp.dst_port, udp.payload.len,
    });

    // DNS on port 53
    if (udp.src_port == 53 or udp.dst_port == 53) {
        const msg = dns.parseDns(udp.payload) catch return;
        const kind = if (msg.is_response) "reply" else "query";
        var qi: u8 = 0;
        while (qi < msg.question_count) : (qi += 1) {
            const q = &msg.questions[qi];
            std.debug.print("  DNS  {s}  {s}  type={s}\n", .{
                kind, q.name(), @tagName(q.qtype),
            });
        }
    }
}

fn printIpv4(payload: []const u8) void {
    const ip = parser.parseIpv4(payload) catch {
        std.debug.print("  [IPv4 parse error]\n", .{});
        return;
    };
    var ib1: [15]u8 = undefined;
    var ib2: [15]u8 = undefined;
    std.debug.print("  IPv4 {s} -> {s}  proto={s}  ttl={d}\n", .{
        types.formatIp(ip.src, &ib1),
        types.formatIp(ip.dst, &ib2),
        @tagName(ip.proto),
        ip.ttl,
    });
    switch (ip.proto) {
        .icmp => printIcmp(ip.payload),
        .tcp  => printTcp(ip.payload),
        .udp  => printUdp(ip.payload),
        else  => {},
    }
}

fn printIpv6(payload: []const u8) void {
    const ip6 = parser.parseIpv6(payload) catch {
        std.debug.print("  [IPv6 parse error]\n", .{});
        return;
    };
    var b1: [39]u8 = undefined;
    var b2: [39]u8 = undefined;
    std.debug.print("  IPv6 {s} -> {s}  proto={s}  hop={d}\n", .{
        types.formatIpv6(ip6.src, &b1),
        types.formatIpv6(ip6.dst, &b2),
        @tagName(ip6.proto),
        ip6.hop_limit,
    });
    switch (ip6.proto) {
        .icmpv6 => printIcmpv6(ip6.payload),
        .tcp  => printTcp(ip6.payload),
        .udp  => printUdp(ip6.payload),
        else  => {},
    }
}
