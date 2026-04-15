// -----------------------------------------------------------------------------
// src/proto/types.zig
// Clean Zig-native packet types used throughout the platform.
// No C types leak above this layer.
// -----------------------------------------------------------------------------

const std = @import("std");

// -- Raw captured packet ------------------------------------------------------

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

// -- Parsed Ethernet frame ----------------------------------------------------

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

// -- Parsed IPv4 header -------------------------------------------------------

pub const IpProto = enum(u8) {
    icmp   = 1,
    tcp    = 6,
    udp    = 17,
    icmpv6 = 58,
    _,
};

pub const Ipv4Header = struct {
    src: [4]u8,
    dst: [4]u8,
    proto: IpProto,
    ttl: u8,
    payload: []const u8,
};

// -- Parsed IPv6 header -------------------------------------------------------

pub const Ipv6Header = struct {
    src: [16]u8,
    dst: [16]u8,
    /// Upper-layer protocol after skipping extension headers
    proto: IpProto,
    hop_limit: u8,
    payload: []const u8,
};

// -- Parsed TCP segment -------------------------------------------------------

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

// -- Parsed UDP datagram ------------------------------------------------------

pub const UdpDatagram = struct {
    src_port: u16,
    dst_port: u16,
    payload: []const u8,
};

// -- Helper: format MAC address -----------------------------------------------

pub fn formatMac(mac: MacAddr, buf: []u8) []u8 {
    const s = std.fmt.bufPrint(
        buf,
        "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}",
        .{ mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] },
    ) catch buf[0..0];
    return s;
}

// -- Helper: format IPv4 address ----------------------------------------------

pub fn formatIp(ip: [4]u8, buf: []u8) []u8 {
    const s = std.fmt.bufPrint(
        buf,
        "{}.{}.{}.{}",
        .{ ip[0], ip[1], ip[2], ip[3] },
    ) catch buf[0..0];
    return s;
}

// -- Helper: format IPv6 address (compact groups) -----------------------------

pub fn formatIp6(ip: [16]u8, buf: []u8) []u8 {
    const s = std.fmt.bufPrint(buf,
        "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:" ++
        "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}",
        .{
            ip[0],  ip[1],  ip[2],  ip[3],
            ip[4],  ip[5],  ip[6],  ip[7],
            ip[8],  ip[9],  ip[10], ip[11],
            ip[12], ip[13], ip[14], ip[15],
        },
    ) catch buf[0..0];
    return s;
}

// -- ARP ----------------------------------------------------------------------

pub const ArpOp = enum(u16) {
    request = 1,
    reply   = 2,
    _,
};

pub const ArpPacket = struct {
    operation:  ArpOp,
    sender_mac: MacAddr,
    sender_ip:  [4]u8,
    target_mac: MacAddr,
    target_ip:  [4]u8,
};

// -- ICMPv4 -------------------------------------------------------------------

pub const IcmpMessage = struct {
    type_:   u8,
    code:    u8,
    payload: []const u8,
};

// -- DNS (lightweight hint types — zero-copy slices into packet data) ----------
// Full parsed types with name buffers live in proto/dns.zig.

pub const DnsQType = enum(u16) {
    a     = 1,
    ns    = 2,
    cname = 5,
    mx    = 15,
    aaaa  = 28,
    _,
};

pub const DnsQuestion = struct {
    /// Decoded domain name e.g. "example.com" — slice into caller-provided buffer.
    name:  []const u8,
    type_: DnsQType,
};

pub const DnsMessage = struct {
    id:        u16,
    is_reply:  bool,
    /// Slice into a caller-provided DnsQuestion buffer.
    questions: []DnsQuestion,
};

// -- HTTP (lightweight hint — zero-copy slices into TCP payload) ---------------

pub const HttpHint = struct {
    /// "GET", "POST", "HTTP/1.1 200" etc. — slice into original packet data.
    method:      []const u8,
    /// Value of Host: header if present — slice into original packet data.
    host:        ?[]const u8,
    /// true if this looks like a response (starts with "HTTP/").
    is_response: bool,
};

// -- Helper: format IPv6 address (word-grouped, uses fixedBufferStream) -------
// Alias for formatIp6 using the canonical name expected by external callers.
// buf must be at least 39 bytes.

pub fn formatIpv6(ip: [16]u8, buf: []u8) []u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();
    var i: usize = 0;
    while (i < 16) : (i += 2) {
        if (i > 0) w.writeByte(':') catch {};
        const word = std.mem.readInt(u16, ip[i..][0..2], .big);
        std.fmt.format(w, "{x:0>4}", .{word}) catch {};
    }
    return buf[0..fbs.pos];
}

