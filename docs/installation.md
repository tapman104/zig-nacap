# Installation & Setup

This guide covers setting up your Windows environment to use **zig-nacap** and integrating it into your Zig project.

---

## 🛠 System Requirements

| Requirement | Details |
| :--- | :--- |
| **OS** | Windows 10 or 11 (64-bit) |
| **Zig Compiler** | 0.16.0-dev or newer |
| **Npcap Driver** | [npcap.com](https://npcap.com/#download) — Must be installed on the machine |
| **Npcap SDK** | [npcap-sdk-1.13.zip](https://npcap.com/dist/npcap-sdk-1.13.zip) — Required for compilation |

---

## 1. Environment Setup

### Install Npcap
1. Download the Npcap installer from [npcap.com](https://npcap.com/).
2. Run the installer.
3. **Important:** Ensure you check the box for **"Install Npcap in WinPcap API-compatible Mode"** if you want maximum compatibility with other tools, although `zig-nacap` works directly with the Npcap DLLs.

### Setup Npcap SDK
The SDK is required only for the developer machine to compile projects.
1. Download the [Npcap SDK](https://npcap.com/dist/npcap-sdk-1.13.zip).
2. Extract the contents to `C:\npcap-sdk`.
3. Your folder structure should look like this:
   - `C:\npcap-sdk\Lib\x64\wpcap.lib`
   - `C:\npcap-sdk\Include\pcap.h`

> **Tip:** If you prefer a different location, you will need to update the `pcap_sdk_path` constant in your `build.zig`.

---

## 2. Integration with your Zig Project

### Step A: Add Dependency
Add `zig-nacap` to your `build.zig.zon` file:

```zig
.{
    .name = "my-awesome-sniffer",
    .version = "0.1.0",
    .dependencies = .{
        .npcap_zig = .{
            .url = "https://github.com/your-username/npcap-zig/archive/<commit-hash>.tar.gz",
            .hash = "<fetch-hash>",
        },
    },
    .paths = .{ "" },
}
```

### Step B: Configure Build
Update your `build.zig` to include the library and link the Npcap SDK:

```zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // 1. Fetch the dependency
    const npcap_dep = b.dependency("npcap_zig", .{
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "my-app",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // 2. Import the module
    exe.root_module.addImport("npcap_zig", npcap_dep.module("npcap_zig"));

    // 3. Link Npcap SDK
    // Note: The npcap_zig package provides a helper to handle linking properly
    // if you use its build system, otherwise ensure C libraries are linked:
    exe.linkSystemLibrary("wpcap");
    exe.linkSystemLibrary("Packet");
    exe.addLibraryPath(b.path("C:/npcap-sdk/Lib/x64"));
    exe.addIncludePath(b.path("C:/npcap-sdk/Include"));

    b.installArtifact(exe);
}
```

---

## 3. Running Applications

Because `zig-nacap` interacts with low-level network drivers, any executable using it **must be run as Administrator**.

> **Warning:** Without Administrator privileges, `listDevices` may return an empty list or `CaptureError.OpenFailed` will be triggered when trying to open an interface.
