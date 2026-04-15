# npcap-zig

Npcap wrapper in Zig — Windows network packet capture.

Clean Zig API over `wpcap.dll`. No C leaks into your app code.

## Architecture

```
your app
   │
capture.zig          ← clean Zig API (use this)
   │
backend/npcap_raw.zig  ← raw C bindings to wpcap.dll
   │
wpcap.dll / Npcap    ← kernel driver + userland
```

## Requirements

- Zig 0.13+
- [Npcap](https://npcap.com/) installed (run as Administrator)
- [Npcap SDK](https://npcap.com/dist/npcap-sdk-1.13.zip) extracted to `C:/npcap-sdk`

## Build

```sh
zig build        # builds library + sniffer.exe
zig build run    # runs sniffer demo (needs Admin)
```

## Usage

```zig
const capture = @import("capture.zig");

// List interfaces
const devices = try capture.listDevices(allocator);
defer capture.freeDevices(allocator, devices);

// Open device
var cap = try capture.openDevice("\\Device\\NPF_{...}", 65535, true, 1000);
defer cap.close();

// Optional BPF filter
try cap.setFilter("tcp");

// Capture packets
while (true) {
    const pkt = cap.nextPacket() orelse continue;
    // pkt.data, pkt.timestamp_us, pkt.original_len
}
```

## Packet Parsing (pure Zig, no C)

```zig
const parser = @import("packet/parser.zig");

const eth = try parser.parseEthernet(pkt.data);
const ip  = try parser.parseIpv4(eth.payload);
const tcp = try parser.parseTcp(ip.payload);
```

## Next: USBPcap

USBPcap backend will be added in `backend/usbpcap.zig`
with same API surface — `capture.openDevice()` works for both.
