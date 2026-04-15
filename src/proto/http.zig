// -----------------------------------------------------------------------------
// src/proto/http.zig
// Lightweight HTTP/1.x sniffer — no allocation, no full parser.
// Inspects the first line of a TCP payload to classify request vs response.
// Does not handle chunked encoding, compression, or multi-packet streams.
// -----------------------------------------------------------------------------

const std = @import("std");
const t   = @import("types.zig");

pub const ParseError = error{
    TooShort,
    NotHttp,
};

// -- Types --------------------------------------------------------------------

pub const HttpMethod = enum {
    GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH,

    pub fn fromSlice(s: []const u8) ?HttpMethod {
        const map = .{
            .{ "GET",     .GET     },
            .{ "HEAD",    .HEAD    },
            .{ "POST",    .POST    },
            .{ "PUT",     .PUT     },
            .{ "DELETE",  .DELETE  },
            .{ "CONNECT", .CONNECT },
            .{ "OPTIONS", .OPTIONS },
            .{ "TRACE",   .TRACE   },
            .{ "PATCH",   .PATCH   },
        };
        inline for (map) |entry| {
            if (std.mem.eql(u8, s, entry[0])) return entry[1];
        }
        return null;
    }
};

pub const HttpRequest = struct {
    method:  HttpMethod,
    /// Slice into the original payload — zero-copy.
    path:    []const u8,
    /// "HTTP/1.0" or "HTTP/1.1"
    version: []const u8,
};

pub const HttpResponse = struct {
    version:     []const u8,
    status_code: u16,
    /// Slice into the original payload — zero-copy.
    reason:      []const u8,
};

pub const HttpMessage = union(enum) {
    request:  HttpRequest,
    response: HttpResponse,
};

// -- Parser -------------------------------------------------------------------

/// Inspect the first line of `data` and return a parsed HttpMessage.
/// All string slices point into `data` — no allocation.
pub fn parseHttp(data: []const u8) ParseError!HttpMessage {
    if (data.len < 7) return error.TooShort;

    // Find end of first line (CRLF or LF)
    const eol = std.mem.indexOfScalar(u8, data, '\n') orelse return error.NotHttp;
    const line = std.mem.trimEnd(u8, data[0..eol], "\r");

    // Split into at most 3 whitespace-separated tokens
    var it = std.mem.splitScalar(u8, line, ' ');
    const tok0 = it.next() orelse return error.NotHttp;
    const tok1 = it.next() orelse return error.NotHttp;
    const tok2 = it.rest(); // everything after second space (may be empty)

    if (std.mem.startsWith(u8, tok0, "HTTP/")) {
        // Response: "HTTP/1.1 200 OK"
        const code = std.fmt.parseInt(u16, tok1, 10) catch return error.NotHttp;
        return .{ .response = .{
            .version     = tok0,
            .status_code = code,
            .reason      = tok2,
        }};
    }

    if (HttpMethod.fromSlice(tok0)) |method| {
        // Request: "GET /path HTTP/1.1"
        if (!std.mem.startsWith(u8, tok2, "HTTP/")) return error.NotHttp;
        return .{ .request = .{
            .method  = method,
            .path    = tok1,
            .version = tok2,
        }};
    }

    return error.NotHttp;
}

// -- Convenience hint detector (used by examples) ----------------------------

/// Quick passive hint for traffic inspection on port 80/8080.
/// Returns null if `data` does not begin with a recognised HTTP/1.x line.
/// The `method` field holds the entire first request/status line
/// (e.g. "GET /index.html HTTP/1.1" or "HTTP/1.1 200 OK").
/// All slices point into the original `data` — zero-copy.
pub fn detect(data: []const u8) ?t.HttpHint {
    const msg = parseHttp(data) catch return null;
    const eol = std.mem.indexOfScalar(u8, data, '\n') orelse data.len;
    const first_line = std.mem.trimEnd(u8, data[0..eol], "\r");
    const host = findHeader(data, "Host:");
    return switch (msg) {
        .request  => .{ .method = first_line, .host = host, .is_response = false },
        .response => .{ .method = first_line, .host = host, .is_response = true  },
    };
}

/// Case-insensitive header value scanner.
/// Scans past the blank-line separator — searches only in headers.
fn findHeader(data: []const u8, name: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < data.len) {
        const line_end = std.mem.indexOf(u8, data[i..], "\r\n") orelse break;
        const line = data[i .. i + line_end];
        // End of headers
        if (line.len == 0) break;
        if (line.len >= name.len and
            std.ascii.eqlIgnoreCase(line[0..name.len], name))
        {
            return std.mem.trimStart(u8, line[name.len..], " \t");
        }
        i += line_end + 2;
    }
    return null;
}
