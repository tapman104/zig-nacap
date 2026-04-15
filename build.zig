const std = @import("std");

// Npcap SDK paths — install SDK from https://npcap.com/dist/npcap-sdk-1.13.zip
// and extract to C:\npcap-sdk (the default search position).
const npcap_include: std.Build.LazyPath = .{ .cwd_relative = "C:/npcap-sdk/Include" };
const npcap_lib_dir: std.Build.LazyPath = .{ .cwd_relative = "C:/npcap-sdk/Lib/x64" };

pub fn build(b: *std.Build) void {
    const target   = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ── Shared library module (also the public module for downstream consumers) ─
    const lib_mod = b.addModule("npcap_zig", .{
        .root_source_file = b.path("src/root.zig"),
        .target           = target,
        .optimize         = optimize,
    });
    lib_mod.addIncludePath(npcap_include);
    lib_mod.addLibraryPath(npcap_lib_dir);
    lib_mod.linkSystemLibrary("wpcap",  .{});
    lib_mod.linkSystemLibrary("Packet", .{});
    lib_mod.link_libc = true;

    // ── Static library artifact ───────────────────────────────────────────────
    const lib = b.addLibrary(.{
        .name        = "npcap_zig",
        .linkage     = .static,
        .root_module = lib_mod,
    });
    b.installArtifact(lib);

    // ── Example: basic_capture ────────────────────────────────────────────────
    const basic_mod = b.createModule(.{
        .root_source_file = b.path("examples/basic_capture.zig"),
        .target           = target,
        .optimize         = optimize,
    });
    basic_mod.addImport("npcap_zig", lib_mod);
    basic_mod.link_libc = true;

    const basic = b.addExecutable(.{
        .name        = "basic_capture",
        .root_module = basic_mod,
    });
    b.installArtifact(basic);

    const run_basic = b.addRunArtifact(basic);
    const run_step  = b.step("run", "Run basic_capture example");
    run_step.dependOn(&run_basic.step);

    // ── Example: dns_monitor ──────────────────────────────────────────────────
    const dns_mod = b.createModule(.{
        .root_source_file = b.path("examples/dns_monitor.zig"),
        .target           = target,
        .optimize         = optimize,
    });
    dns_mod.addImport("npcap_zig", lib_mod);
    dns_mod.link_libc = true;

    const dns_mon = b.addExecutable(.{
        .name        = "dns_monitor",
        .root_module = dns_mod,
    });
    b.installArtifact(dns_mon);

    const run_dns  = b.addRunArtifact(dns_mon);
    const dns_step = b.step("dns_monitor", "Run dns_monitor example");
    dns_step.dependOn(&run_dns.step);

    // ── Tests ─────────────────────────────────────────────────────────────────
    // Tests reuse lib_mod so they inherit the Npcap SDK paths and libc.
    const tests = b.addTest(.{
        .root_module = lib_mod,
    });

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);
}
