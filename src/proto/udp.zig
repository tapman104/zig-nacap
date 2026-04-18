const std = @import("std");
const errors = @import("errors.zig");

pub const UdpDatagram = struct {
    src_port: u16,
    dst_port: u16,
    payload: []const u8,
};

pub fn parseUdp(data: []const u8) errors.ParseError!UdpDatagram {
    if (data.len < 8) return error.TooShort;

    return .{
        .src_port = std.mem.readInt(u16, data[0..2], .big),
        .dst_port = std.mem.readInt(u16, data[2..4], .big),
        .payload  = data[8..],
    };
}
