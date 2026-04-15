const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ── Library ────────────────────────────────────────────────────────────
    const lib = b.addStaticLibrary(.{
        .name = "npcap-zig",
        .root_source_file = b.path("src/capture.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Npcap SDK paths (default install location)
    // Install Npcap SDK from https://npcap.com/dist/npcap-sdk-1.13.zip
    // and extract to C:/npcap-sdk
    lib.addIncludePath(.{ .cwd_relative = "C:/npcap-sdk/Include" });
    lib.addLibraryPath(.{ .cwd_relative = "C:/npcap-sdk/Lib/x64" });
    lib.linkSystemLibrary("wpcap");
    lib.linkSystemLibrary("Packet");
    lib.linkLibC();

    b.installArtifact(lib);

    // ── CLI demo executable ────────────────────────────────────────────────
    const exe = b.addExecutable(.{
        .name = "sniffer",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.addIncludePath(.{ .cwd_relative = "C:/npcap-sdk/Include" });
    exe.addLibraryPath(.{ .cwd_relative = "C:/npcap-sdk/Lib/x64" });
    exe.linkSystemLibrary("wpcap");
    exe.linkSystemLibrary("Packet");
    exe.linkLibC();

    b.installArtifact(exe);

    // ── Run step ──────────────────────────────────────────────────────────
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    const run_step = b.step("run", "Run the sniffer demo");
    run_step.dependOn(&run_cmd.step);
}
