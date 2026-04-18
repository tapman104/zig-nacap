const std = @import("std");
const errors = @import("errors.zig");

pub const TcpFlags = packed struct(u8) {
    fin: bool,
    syn: bool,
    rst: bool,
    psh: bool,
    ack: bool,
    urg: bool,
    _pad: u2 = 0,
};

pub const TcpSegment = struct {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: TcpFlags,
    payload: []const u8,
};

pub fn parseTcp(data: []const u8) errors.ParseError!TcpSegment {
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
