const std = @import("std");
const eth = @import("proto/eth.zig");
const ipv4 = @import("proto/ipv4.zig");
const ipv6 = @import("proto/ipv6.zig");
const arp = @import("proto/arp.zig");
const tcp = @import("proto/tcp.zig");
const udp = @import("proto/udp.zig");
const icmpv4 = @import("proto/icmpv4.zig");
const icmpv6 = @import("proto/icmpv6.zig");

pub const Packet = struct {
    /// Microseconds since Unix epoch
    timestamp_us: u64,
    /// Actual captured bytes (slice into internal buffer)
    data: []const u8,
    /// Original wire length (may be > data.len if truncated)
    original_len: u32,
    /// Data link type (DLT_EN10MB, DLT_IEEE802_11, etc.)
    datalink: i32,
};

pub const Layer3 = union(enum) {
    ipv4: ipv4.Ipv4Header,
    ipv6: ipv6.Ipv6Header,
    arp: arp.ArpPacket,
    unknown,
};

pub const Layer4 = union(enum) {
    tcp: tcp.TcpSegment,
    udp: udp.UdpDatagram,
    icmpv4: icmpv4.IcmpMessage,
    icmpv6: icmpv6.Icmpv6Message,
    none,
};

pub const ParsedPacket = struct {
    eth: eth.EthernetFrame,
    l3: Layer3,
    l4: Layer4,
};
