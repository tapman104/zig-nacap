const std = @import("std");
const errors = @import("errors.zig");

pub const MacAddr = [6]u8;

pub const UnknownEth = struct {
    ethertype: u16,
    src: [6]u8,
    dst: [6]u8,
    raw: [16]u8,   // first 16 bytes of payload (zero-padded if shorter)
    raw_len: u8,   // actual bytes available (may be < 16)
};

pub const EtherType = enum(u16) {
    ipv4 = 0x0800,
    arp  = 0x0806,
    ipv6 = 0x86DD,
    vlan = 0x8100,
    lldp = 0x88cc,
    mpls = 0x8847,
    qinq = 0x88a8,
    eth_loop = 0x9000,
    _,   // unknown
};

pub const EthernetFrame = struct {
    dst: MacAddr,
    src: MacAddr,
    ether_type: EtherType,
    payload: []const u8,
};

pub fn formatMac(mac: MacAddr, buf: []u8) []u8 {
    const s = std.fmt.bufPrint(
        buf,
        "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}",
        .{ mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] },
    ) catch buf[0..0];
    return s;
}

pub fn parseEthernet(data: []const u8) errors.ParseError!EthernetFrame {
    if (data.len < 14) return error.TooShort;

    const ether_type_raw = std.mem.readInt(u16, data[12..14], .big);

    return .{
        .dst        = data[0..6].*,
        .src        = data[6..12].*,
        .ether_type = @enumFromInt(ether_type_raw),
        .payload    = data[14..],
    };
}

pub fn parseUnknownEth(eth: EthernetFrame) UnknownEth {
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
