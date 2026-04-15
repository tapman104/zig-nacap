// ─────────────────────────────────────────────────────────────────────────────
// main.zig
// CLI sniffer demo — shows how to use capture.zig
// Run: zig build run
// ─────────────────────────────────────────────────────────────────────────────

const std = @import("std");
const capture = @import("capture.zig");
const parser  = @import("packet/parser.zig");
const types   = @import("packet/types.zig");

// ── Windows DLL probe ────────────────────────────────────────────────────────
// We use LoadLibraryA/FreeLibrary instead of a filesystem access() check.
// LoadLibraryA replicates the Windows DLL search order (application dir,
// System32, System32\Npcap shim layer, PATH, etc.), which is the only reliable
// way to know whether the runtime linker can actually find a DLL.
extern "kernel32" fn LoadLibraryA(lpLibFileName: [*:0]const u8) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn FreeLibrary(hLibModule: *anyopaque) callconv(.winapi) i32;

fn dllLoadable(name: [*:0]const u8) bool {
    const handle = LoadLibraryA(name) orelse return false;
    _ = FreeLibrary(handle);
    return true;
}

fn printNpcapDiagnostics(io: std.Io, allocator: std.mem.Allocator) void {
    std.debug.print("Startup diagnostics:\n", .{});
    std.debug.print("  exe: <unknown>\n", .{});

    const cwd_path = std.process.currentPathAlloc(io, allocator) catch |err| {
        std.debug.print("  cwd: <unavailable> ({})\n", .{err});
        return;
    };
    defer allocator.free(cwd_path);
    std.debug.print("  cwd: {s}\n", .{cwd_path});

    // Probe via LoadLibraryA so results reflect the actual Windows loader
    // search order, not just whether a file exists at a literal path.
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

fn printBackendErrorDetail() void {
    if (capture.lastError()) |msg| {
        std.debug.print("Npcap detail: {s}\n", .{msg});
    } else {
        std.debug.print("Npcap detail: (none provided)\n", .{});
    }
}

pub fn main() !void {
    const allocator = std.heap.c_allocator;
    std.debug.print("[sniffer] start\n", .{});

    // Obtain a blocking Io handle using the pre-built single-threaded global.
    // This instance requires no allocator and supports no cancellation/concurrency,
    // which is exactly what we need for simple synchronous diagnostics.
    const io = std.Io.Threaded.global_single_threaded.io();

    printNpcapDiagnostics(io, allocator);

    // ── Print Npcap version ───────────────────────────────────────────────────
    std.debug.print("Npcap: {s}\n\n", .{capture.version()});

    // ── List devices ──────────────────────────────────────────────────────────
    const devices = capture.listDevices(allocator) catch |err| {
        std.debug.print("Failed to list devices: {}\n", .{err});
        printBackendErrorDetail();
        std.debug.print("Make sure Npcap is installed and you're running as Admin.\n", .{});
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
        if (!dev.is_loopback) {
            chosen = dev;
            break;
        }
    }

    const dev = chosen orelse {
        std.debug.print("\nNo usable interface found.\n", .{});
        return;
    };

    std.debug.print("\nOpening: {s}\n", .{dev.name});

    // Need a null-terminated version of the device name
    const name_z = try allocator.dupeZ(u8, dev.name);
    defer allocator.free(name_z);

    var cap = capture.openDevice(name_z, 65535, true, 1000) catch |err| {
        std.debug.print("Failed to open device: {}\n", .{err});
        printBackendErrorDetail();
        return;
    };
    defer cap.close();

    // ── Optional: set BPF filter ──────────────────────────────────────────────
    // Uncomment to filter:
    // try cap.setFilter("tcp");
    // try cap.setFilter("port 80");
    // try cap.setFilter("udp");

    std.debug.print("Capturing 20 packets (Ctrl+C to stop early)...\n\n", .{});

    // ── Capture loop ──────────────────────────────────────────────────────────
    var count: u32 = 0;
    while (count < 20) {
        const pkt = cap.nextPacket() orelse {
            if (capture.lastError()) |_| {
                std.debug.print("Capture stopped due to backend error.\n", .{});
                printBackendErrorDetail();
                break;
            }
            continue;
        };
        count += 1;

        try printPacket(pkt, count);
    }
}

// ---------- Packet printer --------------------------------------------------

fn printPacket(
    pkt: types.Packet,
    n: u32,
) !void {
    std.debug.print("--- Packet #{d} --- {d} bytes (wire: {d}) ---\n",
        .{ n, pkt.data.len, pkt.original_len });

    // Try Ethernet
    const eth = parser.parseEthernet(pkt.data) catch {
        std.debug.print("  [raw, datalink={d}]\n\n", .{pkt.datalink});
        return;
    };

    var mac_buf: [17]u8 = undefined;
    var mac_buf2: [17]u8 = undefined;
    std.debug.print("  ETH  {s} → {s}  type=0x{x:0>4}\n", .{
        types.formatMac(eth.src, &mac_buf),
        types.formatMac(eth.dst, &mac_buf2),
        @intFromEnum(eth.ether_type),
    });

    // Try IPv4
    if (eth.ether_type == .ipv4) {
        const ip = parser.parseIpv4(eth.payload) catch {
            std.debug.print("  [IPv4 parse error]\n\n", .{});
            return;
        };

        var ip_buf: [15]u8 = undefined;
        var ip_buf2: [15]u8 = undefined;
        std.debug.print("  IPv4 {s} → {s}  proto={s}  ttl={d}\n", .{
            types.formatIp(ip.src, &ip_buf),
            types.formatIp(ip.dst, &ip_buf2),
            @tagName(ip.proto),
            ip.ttl,
        });

        switch (ip.proto) {
            .tcp => {
                const tcp = parser.parseTcp(ip.payload) catch return;
                std.debug.print("  TCP  :{d} → :{d}  seq={d}  flags=[{s}{s}{s}{s}{s}]\n", .{
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
                std.debug.print("  UDP  :{d} → :{d}  payload={d}b\n", .{
                    udp.src_port,
                    udp.dst_port,
                    udp.payload.len,
                });
            },
            else => {},
        }
    }

    std.debug.print("\n", .{});
}
