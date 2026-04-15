// -----------------------------------------------------------------------------
// src/proto/ipv6.zig
// IPv6 fixed header parser (RFC 8200).
// Does not follow extension headers — payload points past the fixed header.
// -----------------------------------------------------------------------------

const std    = @import("std");
const t      = @import("types.zig");
const parser = @import("parser.zig");

pub const ParseError = parser.ParseError;

/// Parse the 40-byte IPv6 fixed header.
/// payload points past the fixed header (extension headers not stripped).
pub fn parse(data: []const u8) ParseError!t.Ipv6Header {
    if (data.len < 40) return error.TooShort;

    const version = data[0] >> 4;
    if (version != 6) return error.InvalidHeader;

    const payload_len = std.mem.readInt(u16, data[4..6], .big);
    const end = @min(@as(usize, 40) + payload_len, data.len);

    return .{
        .src       = data[8..24].*,
        .dst       = data[24..40].*,
        .proto     = @enumFromInt(data[6]),
        .hop_limit = data[7],
        .payload   = data[40..end],
    };
}
