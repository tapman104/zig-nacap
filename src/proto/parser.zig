// -----------------------------------------------------------------------------
// src/proto/parser.zig
// Pure Zig protocol parsers. No C, no dependencies.
// Ethernet -> IPv4/IPv6 -> TCP/UDP
// -----------------------------------------------------------------------------

const std = @import("std");
const t = @import("types.zig");

pub const ParseError = error{
    TooShort,
    InvalidHeader,
    UnsupportedProtocol,
};

// -- Ethernet -----------------------------------------------------------------

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

// -- IPv4 ---------------------------------------------------------------------

pub fn parseIpv4(data: []const u8) ParseError!t.Ipv4Header {
    if (data.len < 20) return error.TooShort;

    const version_ihl = data[0];
    const version = version_ihl >> 4;
    if (version != 4) return error.InvalidHeader;

    const ihl: usize = (version_ihl & 0x0F) * 4;
    if (ihl < 20 or data.len < ihl) return error.TooShort;

    const total_len = std.mem.readInt(u16, data[2..4], .big);
    // total_len includes the header itself — payload starts after ihl
    // guard against malformed packets where total_len < ihl
    const payload_end = if (@as(usize, total_len) > ihl)
        @min(@as(usize, total_len), data.len)
    else
        data.len;

    return .{
        .src     = data[12..16].*,
        .dst     = data[16..20].*,
        .proto   = @enumFromInt(data[9]),
        .ttl     = data[8],
        .payload = data[ihl..payload_end],
    };
}

// -- IPv6 ---------------------------------------------------------------------

pub fn parseIpv6(data: []const u8) ParseError!t.Ipv6Header {
    if (data.len < 40) return error.TooShort;

    const version = data[0] >> 4;
    if (version != 6) return error.InvalidHeader;

    const payload_len = std.mem.readInt(u16, data[4..6], .big);

    // Walk extension headers until we reach an upper-layer protocol.
    // Extension header next-header values: 0, 43, 44, 51, 60
    var next_hdr: u8 = data[6];
    var offset: usize = 40;

    while (true) {
        switch (next_hdr) {
            0, 43, 60 => { // hop-by-hop, routing, destination options
                if (data.len < offset + 2) return error.TooShort;
                next_hdr = data[offset];
                offset += ((@as(usize, data[offset + 1]) + 1) * 8);
            },
            44 => { // fragment
                if (data.len < offset + 8) return error.TooShort;
                next_hdr = data[offset];
                offset += 8;
            },
            else => break, // upper-layer protocol
        }
    }

    const raw_payload_end = 40 + @as(usize, payload_len);
    const payload_end = @min(raw_payload_end, data.len);
    if (offset > payload_end) return error.TooShort;

    return .{
        .src       = data[8..24].*,
        .dst       = data[24..40].*,
        .proto     = @enumFromInt(next_hdr),
        .hop_limit = data[7],
        .payload   = data[offset..payload_end],
    };
}

// -- TCP ----------------------------------------------------------------------

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

// -- UDP ----------------------------------------------------------------------

pub fn parseUdp(data: []const u8) ParseError!t.UdpDatagram {
    if (data.len < 8) return error.TooShort;

    return .{
        .src_port = std.mem.readInt(u16, data[0..2], .big),
        .dst_port = std.mem.readInt(u16, data[2..4], .big),
        .payload  = data[8..],
    };
}

// -- ARP ----------------------------------------------------------------------

pub fn parseArp(data: []const u8) ParseError!t.ArpPacket {
    if (data.len < 28) return error.TooShort;
    return .{
        .operation  = @enumFromInt(std.mem.readInt(u16, data[6..8], .big)),
        .sender_mac = data[8..14].*,
        .sender_ip  = data[14..18].*,
        .target_mac = data[18..24].*,
        .target_ip  = data[24..28].*,
    };
}

// -- ICMPv4 -------------------------------------------------------------------

pub fn parseIcmp(data: []const u8) ParseError!t.IcmpMessage {
    if (data.len < 4) return error.TooShort;
    return .{
        .type_   = data[0],
        .code    = data[1],
        .payload = data[4..],
    };
}

// -- ICMPv6 -------------------------------------------------------------------

pub fn parseIcmpv6(data: []const u8) ParseError!t.Icmpv6Message {
    if (data.len < 4) return error.TooShort;
    return .{
        .type_    = @enumFromInt(data[0]),
        .code     = data[1],
        .checksum = std.mem.readInt(u16, data[2..4], .big),
        .payload  = data[4..],
    };
}

// -- Unknown Ethernet Handler -------------------------------------------------

pub fn parseUnknownEth(eth: t.EthernetFrame) t.UnknownEth {
    var raw: [16]u8 = undefined;
    @memset(&raw, 0);
    const raw_len = @min(eth.payload.len, 16);
    @memcpy(raw[0..raw_len], eth.payload[0..raw_len]);
    
    return .{
        .ethertype = @intFromEnum(eth.ether_type),
        .src = eth.src,
        .dst = eth.dst,
        .raw = raw,
        .raw_len = @as(u8, @intCast(raw_len)),
    };
}
