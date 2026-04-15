# Examples Walkthrough

This project includes two functional examples that demonstrate how to use the `zig-nacap` API for real-world tasks.

---

## 1. Basic Capture (`examples/basic_capture.zig`)

This is a comprehensive multi-protocol sniffer. It demonstrates:
- Npcap DLL diagnostic checks.
- Device enumeration and selection.
- Opening a live capture session.
- Implementing a nested protocol decoder (Ethernet → IP → TCP/UDP).
- Using specialist parsers for DNS and HTTP.

### How to Run
```powershell
zig build run
```

### What to Expect
1. It will print diagnostic information about the available Npcap DLLs.
2. It will list all network interfaces detected on your machine.
3. It will automatically pick the first physical (non-loopback) adapter.
4. It will capture exactly **20 packets** and print a detailed breakdown of each:
   - MAC addresses.
   - IP addresses (v4 and v6).
   - TCP flags and segments.
   - DNS query names.
   - HTTP method and status lines.

---

## 2. DNS Monitor (`examples/dns_monitor.zig`)

This is a focused tool that demonstrates the power of **BPF Filters**. Instead of capturing everything and filtering in code, it tells the Npcap driver to only send UDP traffic on port 53.

### Key Logic
- Uses `cap.setFilter("udp port 53")` to reduce CPU overhead.
- Leverages the zero-allocation `proto.dns` module to decode domain names.
- Operates until manually stopped (Ctrl+C).

### How to Run
```powershell
zig build dns_monitor
```

### What to Expect
The monitor will sit quietly until you (or an application on your machine) performs a DNS lookup. You will then see output like:
```text
DNS  query   google.com  type=a
DNS  reply   google.com  type=a
DNS  query   github.com  type=aaaa
```

---

## 💡 Pro Tips for Examples

### Administrator Privileges
Both examples require access to the network driver. If you see a `CaptureError.OpenFailed` or an empty list of devices, ensure your terminal is running as **Administrator**.

### Building for Production
If you want to create a standalone `.exe` of these examples:
```powershell
zig build -Doptimize=ReleaseSafe
```
The output will be located in `zig-out/bin/`.

### Custom Filters
You can modify `dns_monitor.zig` to listen for other traffic by changing the BPF string:
- `tcp port 443` (HTTPS)
- `icmp` (Ping)
- `not port 22` (Ignore SSH traffic)
