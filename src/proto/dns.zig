// -----------------------------------------------------------------------------
// src/proto/dns.zig
// DNS message parser — zero allocation, operates on a raw UDP payload slice.
// Decodes the question section fully and answer A/AAAA records.
// Reference: RFC 1035
// -----------------------------------------------------------------------------

const std = @import("std");

pub const ParseError = error{
    TooShort,
    InvalidLabel,
    TruncatedName,
    TooManyPointers, // pointer loop guard
};

// -- Types --------------------------------------------------------------------

pub const DnsType = enum(u16) {
    a     = 1,
    ns    = 2,
    cname = 5,
    soa   = 6,
    ptr   = 12,
    mx    = 15,
    txt   = 16,
    aaaa  = 28,
    srv   = 33,
    _,
};

pub const DnsClass = enum(u16) {
    in = 1,  // Internet
    _,
};

/// A decoded DNS question entry.
pub const DnsQuestion = struct {
    /// Points into the original `data` slice — zero-copy.
    /// Name labels are dot-separated, stored in `name_buf`.
    name_buf: [253]u8,
    name_len: u9,
    qtype:  DnsType,
    qclass: DnsClass,

    pub fn name(self: *const DnsQuestion) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

/// A decoded DNS resource record (answer/authority/additional).
pub const DnsRecord = struct {
    name_buf: [253]u8,
    name_len: u9,
    rtype:  DnsType,
    rclass: DnsClass,
    ttl:    u32,
    
    // Decoded fields
    a: ?[4]u8 = null,
    aaaa: ?[16]u8 = null,
    cname: ?[253]u8 = null,
    cname_len: u8 = 0,

    pub fn name(self: *const DnsRecord) []const u8 {
        return self.name_buf[0..self.name_len];
    }

    pub fn cnameStr(self: *const DnsRecord) []const u8 {
        if (self.cname) |buf| {
            return buf[0..self.cname_len];
        }
        return "";
    }
};

pub const MAX_QUESTIONS = 8;
pub const MAX_RECORDS   = 16;

/// Parsed DNS message. Questions and records are stored inline — no heap.
pub const DnsMessage = struct {
    id:      u16,
    is_response: bool,
    opcode:  u4,
    is_authoritative: bool,
    is_truncated: bool,
    recursion_desired:   bool,
    recursion_available: bool,
    rcode:   u4,

    question_count: u8,
    answer_count:   u8,
    questions: [MAX_QUESTIONS]DnsQuestion,
    answers:   [MAX_RECORDS]DnsRecord,
};

// -- Parser -------------------------------------------------------------------

/// Parse a DNS message from a raw UDP payload.
pub fn parseDns(data: []const u8) ParseError!DnsMessage {
    if (data.len < 12) return error.TooShort;

    const flags = std.mem.readInt(u16, data[2..4], .big);

    var msg = DnsMessage{
        .id      = std.mem.readInt(u16, data[0..2], .big),
        .is_response         = (flags >> 15) != 0,
        .opcode              = @truncate((flags >> 11) & 0xF),
        .is_authoritative    = (flags & 0x0400) != 0,
        .is_truncated        = (flags & 0x0200) != 0,
        .recursion_desired   = (flags & 0x0100) != 0,
        .recursion_available = (flags & 0x0080) != 0,
        .rcode               = @truncate(flags & 0xF),
        .question_count = 0,
        .answer_count   = 0,
        .questions = undefined,
        .answers   = undefined,
    };

    const qdcount = std.mem.readInt(u16, data[4..6], .big);
    const ancount = std.mem.readInt(u16, data[6..8], .big);

    var offset: usize = 12;

    // Decode questions
    const q_limit = @min(qdcount, MAX_QUESTIONS);
    var qi: usize = 0;
    while (qi < q_limit) : (qi += 1) {
        var q: DnsQuestion = undefined;
        offset = try readName(data, offset, &q.name_buf, &q.name_len);
        if (offset + 4 > data.len) return error.TooShort;
        q.qtype  = @enumFromInt(std.mem.readInt(u16, data[offset..][0..2], .big));
        q.qclass = @enumFromInt(std.mem.readInt(u16, data[offset + 2 ..][0..2], .big));
        offset += 4;
        msg.questions[qi] = q;
        msg.question_count += 1;
    }

    // Decode answer records
    const a_limit = @min(ancount, MAX_RECORDS);
    var ai: usize = 0;
    while (ai < a_limit) : (ai += 1) {
        var rec = DnsRecord{
            .name_buf = undefined,
            .name_len = 0,
            .rtype = undefined,
            .rclass = undefined,
            .ttl = 0,
            .a = null,
            .aaaa = null,
            .cname = null,
            .cname_len = 0,
        };
        offset = try readName(data, offset, &rec.name_buf, &rec.name_len);
        if (offset + 10 > data.len) return error.TooShort;
        rec.rtype  = @enumFromInt(std.mem.readInt(u16, data[offset..][0..2], .big));
        rec.rclass = @enumFromInt(std.mem.readInt(u16, data[offset + 2 ..][0..2], .big));
        rec.ttl    = std.mem.readInt(u32, data[offset + 4 ..][0..4], .big);
        const rdlen = std.mem.readInt(u16, data[offset + 8 ..][0..2], .big);
        offset += 10;
        if (offset + rdlen > data.len) return error.TooShort;
        
        switch (rec.rtype) {
            .a => {
                if (rdlen == 4) rec.a = data[offset..][0..4].*;
            },
            .aaaa => {
                if (rdlen == 16) rec.aaaa = data[offset..][0..16].*;
            },
            .cname => {
                var cname_buf: [253]u8 = undefined;
                var cname_len: u9 = 0;
                _ = readName(data, offset, &cname_buf, &cname_len) catch |err| {
                    if (err != error.TruncatedName and err != error.InvalidLabel and err != error.TooManyPointers) return err;
                    // For anything else, ignore or maybe just don't set cname.
                };
                if (cname_len > 0) {
                    rec.cname = cname_buf;
                    rec.cname_len = @intCast(cname_len);
                }
            },
            else => {},
        }
        
        offset += rdlen;
        msg.answers[ai] = rec;
        msg.answer_count += 1;
    }

    return msg;
}

// -- Internal: DNS name decoder (pointer-following) ---------------------------

fn readName(
    data: []const u8,
    start: usize,
    out: *[253]u8,
    out_len: *u9,
) ParseError!usize {
    var pos: usize = start;
    var write: usize = 0;
    var jumped = false;
    var jump_return: usize = 0;
    var pointer_hops: u8 = 0;

    while (true) {
        if (pos >= data.len) return error.TruncatedName;
        const byte = data[pos];

        if (byte == 0) { // end of name
            if (!jumped) pos += 1;
            break;
        }

        if ((byte & 0xC0) == 0xC0) { // pointer
            if (pos + 1 >= data.len) return error.TruncatedName;
            const ptr_offset: usize = (@as(usize, byte & 0x3F) << 8) | data[pos + 1];
            if (!jumped) jump_return = pos + 2;
            jumped = true;
            pos = ptr_offset;
            pointer_hops += 1;
            if (pointer_hops > 16) return error.TooManyPointers;
            continue;
        }

        // Normal label
        const label_len: usize = byte & 0x3F;
        pos += 1;
        if (pos + label_len > data.len) return error.TruncatedName;

        if (write > 0) {
            if (write >= 253) return error.InvalidLabel;
            out[write] = '.';
            write += 1;
        }
        if (write + label_len > 253) return error.InvalidLabel;
        @memcpy(out[write..][0..label_len], data[pos..][0..label_len]);
        write += label_len;
        pos += label_len;
    }

    out_len.* = @intCast(write);
    return if (jumped) jump_return else pos;
}
