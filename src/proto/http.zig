// -----------------------------------------------------------------------------
// src/proto/http.zig
// Lightweight HTTP/1.x sniffer — no allocation, no full parser.
// Inspects the first line of a TCP payload to classify request vs response.
// Does not handle chunked encoding, compression, or multi-packet streams.
// -----------------------------------------------------------------------------

const std = @import("std");

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
    const line = std.mem.trimRight(u8, data[0..eol], "\r");

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
