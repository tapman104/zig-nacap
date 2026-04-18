const std = @import("std");
const errors = @import("errors.zig");
const ipv4 = @import("ipv4.zig"); // to get IpProto

pub const Ipv6Header = struct {
    src: [16]u8,
    dst: [16]u8,
    /// Upper-layer protocol after skipping extension headers
    proto: ipv4.IpProto,
    hop_limit: u8,
    payload: []const u8,
};

pub fn formatIp6(ip: [16]u8, buf: []u8) []u8 {
    const s = std.fmt.bufPrint(buf,
        "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:" ++
        "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}",
        .{
            ip[0],  ip[1],  ip[2],  ip[3],
            ip[4],  ip[5],  ip[6],  ip[7],
            ip[8],  ip[9],  ip[10], ip[11],
            ip[12], ip[13], ip[14], ip[15],
        },
    ) catch buf[0..0];
    return s;
}

pub fn formatIpv6(ip: [16]u8, buf: []u8) []u8 {
    var pos: usize = 0;
    var i: usize = 0;
    while (i < 16) : (i += 2) {
        if (i > 0 and pos < buf.len) {
            buf[pos] = ':';
            pos += 1;
        }
        const word = std.mem.readInt(u16, ip[i..][0..2], .big);
        const s = std.fmt.bufPrint(buf[pos..], "{x:0>4}", .{word}) catch break;
        pos += s.len;
    }
    return buf[0..pos];
}

pub fn parseIpv6(data: []const u8) errors.ParseError!Ipv6Header {
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
