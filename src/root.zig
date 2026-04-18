// -----------------------------------------------------------------------------
// src/root.zig
// Library entry point — re-exports the full public API.
// -----------------------------------------------------------------------------

pub const capture = @import("capture.zig");
pub const packet = @import("packet.zig");
pub const flow = @import("flow/tracker.zig");

pub const proto = struct {
    pub const errors = @import("proto/errors.zig");
    pub const eth = @import("proto/eth.zig");
    pub const ipv4 = @import("proto/ipv4.zig");
    pub const ipv6 = @import("proto/ipv6.zig");
    pub const arp = @import("proto/arp.zig");
    pub const tcp = @import("proto/tcp.zig");
    pub const udp = @import("proto/udp.zig");
    pub const icmpv4 = @import("proto/icmpv4.zig");
    pub const icmpv6 = @import("proto/icmpv6.zig");
    pub const dns = @import("proto/dns.zig");
    pub const http = @import("proto/http.zig");
};
