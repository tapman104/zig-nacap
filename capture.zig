// ─────────────────────────────────────────────────────────────────────────────
// capture.zig
// YOUR clean Zig capture API.
// Apps use this. No C types leak out.
// Backend: Npcap (Windows) via npcap_raw.zig
// ─────────────────────────────────────────────────────────────────────────────

const std = @import("std");
const raw = @import("backend/npcap_raw.zig");
pub const types = @import("packet/types.zig");
pub const parser = @import("packet/parser.zig");

const last_error_capacity = 512;
var last_error_storage: [last_error_capacity]u8 = [_]u8{0} ** last_error_capacity;
var last_error_len: usize = 0;

fn clearLastError() void {
    last_error_len = 0;
}

fn setLastError(message: []const u8) void {
    const trimmed = std.mem.trim(u8, message, " \t\r\n");
    if (trimmed.len == 0) {
        clearLastError();
        return;
    }

    const len = @min(trimmed.len, last_error_storage.len);
    std.mem.copyForwards(u8, last_error_storage[0..len], trimmed[0..len]);
    last_error_len = len;
}

fn cStringFromErrbuf(errbuf: []const u8) []const u8 {
    const end = std.mem.indexOfScalar(u8, errbuf, 0) orelse errbuf.len;
    return errbuf[0..end];
}

fn setLastErrorFromErrbuf(errbuf: []const u8) void {
    setLastError(cStringFromErrbuf(errbuf));
}

fn setLastErrorFromHandle(handle: *raw.pcap_t) void {
    setLastError(std.mem.span(raw.pcap_geterr(handle)));
}

// ── Error set ─────────────────────────────────────────────────────────────────

pub const CaptureError = error{
    DeviceEnumFailed,
    NoDevicesFound,
    OpenFailed,
    FilterCompileFailed,
    FilterSetFailed,
    CaptureFailed,
};

// ── Device info ───────────────────────────────────────────────────────────────

pub const Device = struct {
    name: []const u8,
    description: []const u8,
    is_wireless: bool,
    is_loopback: bool,
};

// ── Capture handle ────────────────────────────────────────────────────────────

pub const CaptureHandle = struct {
    handle: *raw.pcap_t,
    datalink: i32,

    /// Close the capture session
    pub fn close(self: *CaptureHandle) void {
        raw.pcap_close(self.handle);
    }

    /// Set a BPF filter string e.g. "tcp", "port 80", "udp and port 53"
    pub fn setFilter(self: *CaptureHandle, filter: [:0]const u8) CaptureError!void {
        clearLastError();
        var prog: raw.bpf_program = undefined;

        const rc = raw.pcap_compile(
            self.handle,
            &prog,
            filter.ptr,
            1,
            raw.PCAP_NETMASK_UNKNOWN,
        );
        if (rc != 0) {
            setLastErrorFromHandle(self.handle);
            return error.FilterCompileFailed;
        }
        defer raw.pcap_freecode(&prog);

        if (raw.pcap_setfilter(self.handle, &prog) != 0) {
            setLastErrorFromHandle(self.handle);
            return error.FilterSetFailed;
        }
    }

    /// Capture packets in a loop. Calls `callback` for each packet.
    /// Pass count = -1 to loop forever.
    /// Pass count = N to capture N packets then return.
    pub fn loop(
        self: *CaptureHandle,
        count: i32,
        comptime callback: fn (pkt: types.Packet) void,
    ) CaptureError!void {
        clearLastError();
        const Context = struct {
            fn handler(
                _: ?*u8,
                header: *const raw.pcap_pkthdr,
                data: [*]const u8,
            ) callconv(.C) void {
                const pkt = types.Packet{
                    .timestamp_us  = @as(u64, @intCast(header.ts.tv_sec)) * 1_000_000 +
                                     @as(u64, @intCast(header.ts.tv_usec)),
                    .data          = data[0..header.caplen],
                    .original_len  = header.len,
                    .datalink      = 0, // set below via closure workaround
                };
                callback(pkt);
            }
        };

        const rc = raw.pcap_loop(self.handle, count, Context.handler, null);
        if (rc == -1) {
            setLastErrorFromHandle(self.handle);
            return error.CaptureFailed;
        }
    }

    /// Single non-blocking poll. Returns null if no packet available yet.
    pub fn nextPacket(self: *CaptureHandle) ?types.Packet {
        var header: *raw.pcap_pkthdr = undefined;
        var data: ?[*]const u8 = null;

        const rc = raw.pcap_next_ex(self.handle, &header, &data);
        if (rc == -1) {
            setLastErrorFromHandle(self.handle);
            return null;
        }
        if (rc != 1 or data == null) return null;

        return types.Packet{
            .timestamp_us = @as(u64, @intCast(header.ts.tv_sec)) * 1_000_000 +
                            @as(u64, @intCast(header.ts.tv_usec)),
            .data         = data.?[0..header.caplen],
            .original_len = header.len,
            .datalink     = self.datalink,
        };
    }

    /// Stop a running pcap_loop
    pub fn stop(self: *CaptureHandle) void {
        raw.pcap_breakloop(self.handle);
    }
};

// ── Public API ────────────────────────────────────────────────────────────────

/// List all available network interfaces.
/// Caller must call freeDevices() when done.
pub fn listDevices(allocator: std.mem.Allocator) CaptureError![]Device {
    clearLastError();
    var errbuf: [raw.PCAP_ERRBUF_SIZE]u8 = [_]u8{0} ** raw.PCAP_ERRBUF_SIZE;
    var alldevs: *raw.pcap_if_t = undefined;

    if (raw.pcap_findalldevs(&alldevs, &errbuf) == -1) {
        setLastErrorFromErrbuf(errbuf[0..]);
        return error.DeviceEnumFailed;
    }
    defer raw.pcap_freealldevs(alldevs);

    // Two-pass: count devices, allocate slice, then fill it.
    var count: usize = 0;
    var dv: ?*raw.pcap_if_t = alldevs;
    while (dv) |d| : (dv = d.next) {
        count += 1;
    }

    if (count == 0) {
        setLastError("Npcap returned zero capture devices.");
        return error.NoDevicesFound;
    }

    var devices = allocator.alloc(Device, count) catch {
        setLastError("Allocation failed while preparing device list.");
        return error.DeviceEnumFailed;
    };
    errdefer allocator.free(devices);

    var i: usize = 0;
    errdefer {
        for (devices[0..i]) |d| {
            allocator.free(d.name);
            allocator.free(d.description);
        }
    }

    dv = alldevs;
    while (dv) |d| : (dv = d.next) {
        const name = allocator.dupe(u8, std.mem.span(d.name)) catch {
            setLastError("Allocation failed while copying device name.");
            return error.DeviceEnumFailed;
        };
        const desc = if (d.description) |desc_ptr|
            allocator.dupe(u8, std.mem.span(desc_ptr)) catch {
                allocator.free(name);
                setLastError("Allocation failed while copying device description.");
                return error.DeviceEnumFailed;
            }
        else
            allocator.dupe(u8, "(no description)") catch {
                allocator.free(name);
                setLastError("Allocation failed while copying device description.");
                return error.DeviceEnumFailed;
            };

        devices[i] = Device{
            .name = name,
            .description = desc,
            .is_wireless = (d.flags & raw.PCAP_IF_WIRELESS) != 0,
            .is_loopback = (d.flags & raw.PCAP_IF_LOOPBACK) != 0,
        };
        i += 1;
    }

    return devices[0..count];
}

pub fn freeDevices(allocator: std.mem.Allocator, devices: []Device) void {
    for (devices) |d| {
        allocator.free(d.name);
        allocator.free(d.description);
    }
    allocator.free(devices);
}

/// Open a device for live capture.
/// snaplen: max bytes per packet (65535 = full)
/// promisc: true = promiscuous mode (capture all frames)
/// timeout_ms: read timeout
pub fn openDevice(
    device_name: [:0]const u8,
    snaplen: i32,
    promisc: bool,
    timeout_ms: i32,
) CaptureError!CaptureHandle {
    clearLastError();
    var errbuf: [raw.PCAP_ERRBUF_SIZE]u8 = [_]u8{0} ** raw.PCAP_ERRBUF_SIZE;

    const handle = raw.pcap_open_live(
        device_name.ptr,
        snaplen,
        if (promisc) 1 else 0,
        timeout_ms,
        &errbuf,
    ) orelse {
        setLastErrorFromErrbuf(errbuf[0..]);
        return error.OpenFailed;
    };

    return CaptureHandle{
        .handle   = handle,
        .datalink = raw.pcap_datalink(handle),
    };
}

/// Open a saved .pcap file for reading
pub fn openFile(path: [:0]const u8) CaptureError!CaptureHandle {
    clearLastError();
    var errbuf: [raw.PCAP_ERRBUF_SIZE]u8 = [_]u8{0} ** raw.PCAP_ERRBUF_SIZE;

    const handle = raw.pcap_open_offline(path.ptr, &errbuf)
        orelse {
            setLastErrorFromErrbuf(errbuf[0..]);
            return error.OpenFailed;
        };

    return CaptureHandle{
        .handle   = handle,
        .datalink = raw.pcap_datalink(handle),
    };
}

/// Print Npcap version string
pub fn version() []const u8 {
    return std.mem.span(raw.pcap_lib_version());
}

/// Last backend error text captured from Npcap/libpcap.
pub fn lastError() ?[]const u8 {
    if (last_error_len == 0) return null;
    return last_error_storage[0..last_error_len];
}
