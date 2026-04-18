const std = @import("std");
const errors = @import("errors.zig");

pub const IcmpMessage = struct {
    type_:   u8,
    code:    u8,
    payload: []const u8,
};

pub fn parseIcmp(data: []const u8) errors.ParseError!IcmpMessage {
    if (data.len < 4) return error.TooShort;
    return .{
        .type_   = data[0],
        .code    = data[1],
        .payload = data[4..],
    };
}
