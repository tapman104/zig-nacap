const std = @import("std");
const errors = @import("errors.zig");
const eth = @import("eth.zig");

pub const ArpOp = enum(u16) {
    request = 1,
    reply   = 2,
    _,
};

pub const ArpPacket = struct {
    operation:  ArpOp,
    sender_mac: eth.MacAddr,
    sender_ip:  [4]u8,
    target_mac: eth.MacAddr,
    target_ip:  [4]u8,
};

pub fn parseArp(data: []const u8) errors.ParseError!ArpPacket {
    if (data.len < 28) return error.TooShort;
    return .{
        .operation  = @enumFromInt(std.mem.readInt(u16, data[6..8], .big)),
        .sender_mac = data[8..14].*,
        .sender_ip  = data[14..18].*,
        .target_mac = data[18..24].*,
        .target_ip  = data[24..28].*,
    };
}
