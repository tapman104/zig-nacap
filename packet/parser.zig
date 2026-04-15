// ─────────────────────────────────────────────────────────────────────────────
// packet/parser.zig
// Pure Zig protocol parsers. No C, no dependencies.
// Ethernet → IPv4 → TCP/UDP
// ─────────────────────────────────────────────────────────────────────────────

const std = @import("std");
const t = @import("types.zig");

pub const ParseError = error{
    TooShort,
    InvalidHeader,
    UnsupportedProtocol,
};

// ── Ethernet ──────────────────────────────────────────────────────────────────

pub fn parseEthernet(data: []const u8) ParseError!t.EthernetFrame {
    if (data.len < 14) return error.TooShort;

    const ether_type_raw = std.mem.readInt(u16, data[12..14], .big);

    return .{
        .dst        = data[0..6].*,
        .src        = data[6..12].*,
        .ether_type = @enumFromInt(ether_type_raw),
        .payload    = data[14..],
    };
}

// ── IPv4 ──────────────────────────────────────────────────────────────────────

pub fn parseIpv4(data: []const u8) ParseError!t.Ipv4Header {
    if (data.len < 20) return error.TooShort;

    const version_ihl = data[0];
    const version = version_ihl >> 4;
    if (version != 4) return error.InvalidHeader;

    const ihl = (version_ihl & 0x0F) * 4;
    if (data.len < ihl) return error.TooShort;

    const total_len = std.mem.readInt(u16, data[2..4], .big);
    const payload_end = @min(total_len, data.len);

    return .{
        .src     = data[12..16].*,
        .dst     = data[16..20].*,
        .proto   = @enumFromInt(data[9]),
        .ttl     = data[8],
        .payload = data[ihl..payload_end],
    };
}

// ── TCP ───────────────────────────────────────────────────────────────────────

pub fn parseTcp(data: []const u8) ParseError!t.TcpSegment {
    if (data.len < 20) return error.TooShort;

    const data_offset = (data[12] >> 4) * 4;
    if (data.len < data_offset) return error.TooShort;

    return .{
        .src_port = std.mem.readInt(u16, data[0..2], .big),
        .dst_port = std.mem.readInt(u16, data[2..4], .big),
        .seq      = std.mem.readInt(u32, data[4..8], .big),
        .ack      = std.mem.readInt(u32, data[8..12], .big),
        .flags    = @bitCast(data[13]),
        .payload  = data[data_offset..],
    };
}

// ── UDP ───────────────────────────────────────────────────────────────────────

pub fn parseUdp(data: []const u8) ParseError!t.UdpDatagram {
    if (data.len < 8) return error.TooShort;

    return .{
        .src_port = std.mem.readInt(u16, data[0..2], .big),
        .dst_port = std.mem.readInt(u16, data[2..4], .big),
        .payload  = data[8..],
    };
}
