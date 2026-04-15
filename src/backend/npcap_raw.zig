// -----------------------------------------------------------------------------
// src/backend/npcap_raw.zig
// Raw C bindings to wpcap.dll / Npcap SDK
// These mirror the libpcap C API exactly.
// Don't use this file directly — use capture.zig instead.
// -----------------------------------------------------------------------------

const std = @import("std");

// -- Constants ----------------------------------------------------------------

pub const PCAP_ERRBUF_SIZE: usize = 256;
pub const PCAP_IF_LOOPBACK: u32 = 0x00000001;
pub const PCAP_IF_UP: u32 = 0x00000002;
pub const PCAP_IF_RUNNING: u32 = 0x00000004;
pub const PCAP_IF_WIRELESS: u32 = 0x00000008;

pub const DLT_NULL: c_int = 0;
pub const DLT_EN10MB: c_int = 1; // Ethernet
pub const DLT_IEEE802_11: c_int = 105; // Raw 802.11 wireless

pub const PCAP_NETMASK_UNKNOWN: u32 = 0xFFFFFFFF;

// -- Opaque handle types ------------------------------------------------------

pub const pcap_t = opaque {};
pub const pcap_dumper_t = opaque {};

// -- Structs ------------------------------------------------------------------

pub const timeval = extern struct {
    tv_sec: c_long,
    tv_usec: c_long,
};

pub const pcap_pkthdr = extern struct {
    ts: timeval,
    caplen: u32, // bytes actually captured
    len: u32, // original packet length
};

pub const pcap_if_t = extern struct {
    next: ?*pcap_if_t,
    name: [*:0]u8,
    description: ?[*:0]u8,
    addresses: ?*pcap_addr_t,
    flags: u32,
};

pub const sockaddr = extern struct {
    sa_family: u16,
    sa_data: [14]u8,
};

pub const pcap_addr_t = extern struct {
    next: ?*pcap_addr_t,
    addr: ?*sockaddr,
    netmask: ?*sockaddr,
    broadaddr: ?*sockaddr,
    dstaddr: ?*sockaddr,
};

pub const bpf_insn = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
};

pub const bpf_program = extern struct {
    bf_len: u32,
    bf_insns: ?*bpf_insn,
};

// -- Callback type ------------------------------------------------------------

pub const pcap_handler = *const fn (
    user: ?*u8,
    header: *const pcap_pkthdr,
    data: [*]const u8,
) callconv(.C) void;

// -- Extern function declarations ---------------------------------------------

pub extern fn pcap_findalldevs(
    alldevsp: **pcap_if_t,
    errbuf: [*]u8,
) c_int;

pub extern fn pcap_freealldevs(alldevs: *pcap_if_t) void;

pub extern fn pcap_open_live(
    device: [*:0]const u8,
    snaplen: c_int,
    promisc: c_int,
    to_ms: c_int,
    errbuf: [*]u8,
) ?*pcap_t;

pub extern fn pcap_open_offline(
    fname: [*:0]const u8,
    errbuf: [*]u8,
) ?*pcap_t;

pub extern fn pcap_close(p: *pcap_t) void;

pub extern fn pcap_loop(
    p: *pcap_t,
    cnt: c_int,
    callback: pcap_handler,
    user: ?*u8,
) c_int;

pub extern fn pcap_dispatch(
    p: *pcap_t,
    cnt: c_int,
    callback: pcap_handler,
    user: ?*u8,
) c_int;

pub extern fn pcap_next(
    p: *pcap_t,
    h: *pcap_pkthdr,
) ?[*]const u8;

pub extern fn pcap_next_ex(
    p: *pcap_t,
    pkt_header: **pcap_pkthdr,
    pkt_data: *?[*]const u8,
) c_int;

pub extern fn pcap_breakloop(p: *pcap_t) void;

pub extern fn pcap_compile(
    p: *pcap_t,
    fp: *bpf_program,
    str: [*:0]const u8,
    optimize: c_int,
    netmask: u32,
) c_int;

pub extern fn pcap_setfilter(
    p: *pcap_t,
    fp: *bpf_program,
) c_int;

pub extern fn pcap_freecode(fp: *bpf_program) void;

pub extern fn pcap_datalink(p: *pcap_t) c_int;

pub extern fn pcap_geterr(p: *pcap_t) [*:0]const u8;

pub extern fn pcap_lib_version() [*:0]const u8;

pub extern fn pcap_dump_open(
    p: *pcap_t,
    fname: [*:0]const u8,
) ?*pcap_dumper_t;

pub extern fn pcap_dump(
    dumper: *pcap_dumper_t,
    header: *const pcap_pkthdr,
    data: [*]const u8,
) void;

pub extern fn pcap_dump_close(dumper: *pcap_dumper_t) void;
