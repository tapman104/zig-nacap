const std = @import("std");
const packet = @import("../packet.zig");
const tcp = @import("../proto/tcp.zig");

pub const FlowState = enum {
    MID_STREAM,
    SYN_SENT,
    SYN_RCVD,
    ESTABLISHED,
    FIN_WAIT,
    CLOSED,
};

pub const FlowKey = struct {
    client_ip: [4]u8,
    server_ip: [4]u8,
    client_port: u16,
    server_port: u16,
};

pub const Flow = struct {
    state: FlowState,
    client_seq: u32,
    server_seq: u32,
    seen_client: bool,
    seen_server: bool,
    packet_count: u32,
    byte_count: u64,
    first_seen: u64,
    last_seen: u64,
};

pub const FlowTable = std.AutoHashMap(FlowKey, Flow);

pub fn processTcp(
    flow_table: *FlowTable,
    pkt: packet.Packet,
    ip_src: [4]u8,
    ip_dst: [4]u8,
    tcp_seg: tcp.TcpSegment,
    /// IP payload length = TCP header + TCP data (not the Ethernet/IP overhead)
    ip_payload_len: usize,
) []const u8 {
    var flow_status: []const u8 = "";

    var key = FlowKey{
        .client_ip = ip_src,
        .server_ip = ip_dst,
        .client_port = tcp_seg.src_port,
        .server_port = tcp_seg.dst_port,
    };

    // Normalize so the lower-port side is client
    if (tcp_seg.src_port > tcp_seg.dst_port) {
        key.client_ip = ip_dst;
        key.server_ip = ip_src;
        key.client_port = tcp_seg.dst_port;
        key.server_port = tcp_seg.src_port;
    }

    const gop = flow_table.getOrPut(key) catch unreachable;
    var is_new = false;
    if (!gop.found_existing) {
        is_new = true;
        gop.value_ptr.* = Flow{
            .state = .MID_STREAM,
            .client_seq = 0,
            .server_seq = 0,
            .seen_client = false,
            .seen_server = false,
            .packet_count = 0,
            .byte_count = 0,
            .first_seen = pkt.timestamp_us,
            .last_seen = pkt.timestamp_us,
        };
    }

    var flow = gop.value_ptr;
    flow.packet_count += 1;
    flow.byte_count += ip_payload_len;
    flow.last_seen = pkt.timestamp_us;

    // Track per-flow metadata
    if (tcp_seg.src_port == key.client_port) {
        flow.client_seq = tcp_seg.seq;
        flow.seen_client = true;
    } else {
        flow.server_seq = tcp_seg.seq;
        flow.seen_server = true;
    }

    if (flow.state == .MID_STREAM and flow.packet_count >= 2 and flow.seen_client and flow.seen_server) {
        flow.state = .ESTABLISHED;
    }

    // Simplistic flow state machine
    if (tcp_seg.flags.syn and !tcp_seg.flags.ack) {
        flow.state = .SYN_SENT;
        flow_status = "flow=NEW";
    } else if (tcp_seg.flags.syn and tcp_seg.flags.ack) {
        flow.state = .SYN_RCVD;
        flow_status = "flow=SYN_RCVD";
    } else if (tcp_seg.flags.fin) {
        if (flow.state == .FIN_WAIT) {
            flow.state = .CLOSED;
        } else {
            flow.state = .FIN_WAIT;
        }
        flow_status = if (flow.state == .CLOSED) "flow=CLOSED" else "flow=FIN_WAIT";
    } else if (tcp_seg.flags.rst) {
        flow.state = .CLOSED;
        flow_status = "flow=CLOSED";
    } else if (tcp_seg.flags.ack) {
        if (flow.state == .SYN_RCVD) {
            flow.state = .ESTABLISHED;
            flow_status = "flow=ESTABLISHED";
        } else if (flow.state == .FIN_WAIT) {
            flow.state = .CLOSED;
            flow_status = "flow=CLOSED";
        } else if (flow.state == .ESTABLISHED) {
            flow_status = "flow=ESTABLISHED";
        }
    }

    if (flow_status.len == 0) {
        flow_status = if (is_new) "flow=MID_STREAM" else "flow=UPDATE";
    }

    return flow_status;
}
