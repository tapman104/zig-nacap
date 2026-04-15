const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = std.Build.standardTargetOptions(b, .{});
    const optimize = std.Build.standardOptimizeOption(b, .{});

    const include_path = std.Build.LazyPath{ .cwd_relative = "C:/npcap-sdk/Include" };
    const lib_path = std.Build.LazyPath{ .cwd_relative = "C:/npcap-sdk/Lib/x64" };

    // ── Library ────────────────────────────────────────────────────────────
    // Create a Module for the Zig wrapper and register it as a library.
    const lib_module = std.Build.addModule(b, "npcap-zig", .{
        .root_source_file = std.Build.path(b, "capture.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Npcap SDK paths (default install location)
    // Install Npcap SDK from https://npcap.com/dist/npcap-sdk-1.13.zip
    // and extract to C:/npcap-sdk
    // Keep the module as a pure Zig wrapper: only add include path here.
    std.Build.Module.addIncludePath(lib_module, include_path);

    const lib = std.Build.addLibrary(b, .{
        .name = "npcap-zig",
        .root_module = lib_module,
    });

    std.Build.installArtifact(b, lib);

    // ── CLI demo executable ────────────────────────────────────────────────
    const exe_module = std.Build.addModule(b, "sniffer-main", .{
        .root_source_file = std.Build.path(b, "main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = std.Build.addExecutable(b, .{
        .name = "sniffer",
        .root_module = exe_module,
    });

    std.Build.Module.addIncludePath(exe_module, include_path);
    std.Build.Module.addLibraryPath(exe_module, lib_path);
    std.Build.Module.linkSystemLibrary(exe_module, "wpcap", .{});
    std.Build.Module.linkSystemLibrary(exe_module, "Packet", .{});
    // Request linking libc for the executable when appropriate
    exe_module.link_libc = true;

    std.Build.installArtifact(b, exe);

    // ── Run step ──────────────────────────────────────────────────────────
    const run_cmd = std.Build.addRunArtifact(b, exe);
    run_cmd.step.dependOn(std.Build.getInstallStep(b));
    const run_step = std.Build.step(b, "run", "Run the sniffer demo");
    run_step.dependOn(&run_cmd.step);
}
