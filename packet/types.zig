// ─────────────────────────────────────────────────────────────────────────────
// packet/types.zig
// Clean Zig-native packet types used throughout the platform.
// No C types leak above this layer.
// ─────────────────────────────────────────────────────────────────────────────

const std = @import("std");

// ── Raw captured packet ───────────────────────────────────────────────────────

pub const Packet = struct {
    /// Microseconds since Unix epoch
    timestamp_us: u64,
    /// Actual captured bytes (slice into internal buffer)
    data: []const u8,
    /// Original wire length (may be > data.len if truncated)
    original_len: u32,
    /// Data link type (DLT_EN10MB, DLT_IEEE802_11, etc.)
    datalink: i32,
};

// ── Parsed Ethernet frame ─────────────────────────────────────────────────────

pub const MacAddr = [6]u8;

pub const EtherType = enum(u16) {
    ipv4 = 0x0800,
    arp  = 0x0806,
    ipv6 = 0x86DD,
    vlan = 0x8100,
    _,   // unknown
};

pub const EthernetFrame = struct {
    dst: MacAddr,
    src: MacAddr,
    ether_type: EtherType,
    payload: []const u8,
};

// ── Parsed IPv4 header ────────────────────────────────────────────────────────

pub const IpProto = enum(u8) {
    icmp = 1,
    tcp  = 6,
    udp  = 17,
    _,
};

pub const Ipv4Header = struct {
    src: [4]u8,
    dst: [4]u8,
    proto: IpProto,
    ttl: u8,
    payload: []const u8,
};

// ── Parsed TCP segment ────────────────────────────────────────────────────────

pub const TcpSegment = struct {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: TcpFlags,
    payload: []const u8,
};

pub const TcpFlags = packed struct(u8) {
    fin: bool,
    syn: bool,
    rst: bool,
    psh: bool,
    ack: bool,
    urg: bool,
    _pad: u2 = 0,
};

// ── Parsed UDP datagram ───────────────────────────────────────────────────────

pub const UdpDatagram = struct {
    src_port: u16,
    dst_port: u16,
    payload: []const u8,
};

// ── Helper: format MAC address ───────────────────────────────────────────────

pub fn formatMac(mac: MacAddr, buf: []u8) []u8 {
    const s = std.fmt.bufPrint(
        buf,
        "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}",
        .{ mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] },
    ) catch buf[0..0];
    return s;
}

// ── Helper: format IPv4 address ───────────────────────────────────────────────

pub fn formatIp(ip: [4]u8, buf: []u8) []u8 {
    const s = std.fmt.bufPrint(
        buf,
        "{}.{}.{}.{}",
        .{ ip[0], ip[1], ip[2], ip[3] },
    ) catch buf[0..0];
    return s;
}
