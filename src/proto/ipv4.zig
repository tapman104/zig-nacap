const std = @import("std");
const errors = @import("errors.zig");

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

pub fn formatIp(ip: [4]u8, buf: []u8) []u8 {
    const s = std.fmt.bufPrint(
        buf,
        "{}.{}.{}.{}",
        .{ ip[0], ip[1], ip[2], ip[3] },
    ) catch buf[0..0];
    return s;
}

pub fn parseIpv4(data: []const u8) errors.ParseError!Ipv4Header {
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
