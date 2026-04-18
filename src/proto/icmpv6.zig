const std = @import("std");
const errors = @import("errors.zig");

pub const Icmpv6Type = enum(u8) {
    destination_unreachable = 1,
    packet_too_big = 2,
    time_exceeded = 3,
    parameter_problem = 4,
    echo_request = 128,
    echo_reply = 129,
    mld_query = 130,
    mld_report = 131,
    mld_done = 132,
    router_solicitation = 133,
    router_advertisement = 134,
    neighbor_solicitation = 135,
    neighbor_advertisement = 136,
    redirect = 137,
    mldv2_report = 143,
    _,
};

pub const Icmpv6Message = struct {
    type_: Icmpv6Type,
    code: u8,
    checksum: u16,
    payload: []const u8,
};

pub fn parseIcmpv6(data: []const u8) errors.ParseError!Icmpv6Message {
    if (data.len < 4) return error.TooShort;
    return .{
        .type_    = @enumFromInt(data[0]),
        .code     = data[1],
        .checksum = std.mem.readInt(u16, data[2..4], .big),
        .payload  = data[4..],
    };
}
