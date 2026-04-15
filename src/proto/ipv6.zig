// -----------------------------------------------------------------------------
// src/proto/ipv6.zig
// IPv6 header parser (RFC 8200).
// Thin wrapper around parser.parseIpv6 — re-exports types and adds helpers.
// -----------------------------------------------------------------------------

const std   = @import("std");
const t      = @import("types.zig");
const parser = @import("parser.zig");

pub const ParseError  = parser.ParseError;
pub const Ipv6Header  = t.Ipv6Header;

/// Parse an IPv6 header from a raw Ethernet payload (or any buffer starting
/// at the IPv6 header).
pub const parse = parser.parseIpv6;

/// Format an IPv6 address as a full (non-compressed) colon-hex string.
/// `buf` must be at least 39 bytes.
pub fn formatAddr(addr: [16]u8, buf: []u8) []u8 {
    return t.formatIp6(addr, buf);
}
