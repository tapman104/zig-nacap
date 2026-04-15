// -----------------------------------------------------------------------------
// src/root.zig
// Library entry point — re-exports the full public API.
// Users add the package via build.zig.zon and then:
//
//   const npcap = @import("npcap_zig");
//   const cap   = npcap.capture;
//   const types = npcap.proto.types;
//   const dns   = npcap.proto.dns;
// -----------------------------------------------------------------------------

pub const capture = @import("capture.zig");

pub const proto = struct {
    pub const types  = @import("proto/types.zig");
    pub const parser = @import("proto/parser.zig");
    pub const dns    = @import("proto/dns.zig");
    pub const ipv6   = @import("proto/ipv6.zig");
    pub const http   = @import("proto/http.zig");
};
