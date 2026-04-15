# Roadmap & Limitations

**zig-nacap** is currently in an early but stable state, providing a robust foundation for Windows-based packet capture.

---

## 🚧 Current Limitations

While the library is highly efficient, users should be aware of the following:

- **Platform**: Currently **Windows-only** (via Npcap). Linux (libpcap) and macOS support are not yet implemented.
- **Protocol Depth**: Parsers exist for the most common protocols, but complex L7 structures (like TLS handshakes or SMB) are not yet fully decoded.
- **Packet Injection**: The current API focuses on **Capture**. Packet injection (sending raw bytes back onto the wire) is implemented in the raw backend but not yet exposed in the high-level `CaptureHandle` API.
- **Datalink Types**: The parser assumes Ethernet II (`DLT_EN10MB`). Support for Raw IP or 8080.11 radiotap headers is not yet standard.

---

## 🗺 Future Goals

### Phase 1: Core API Expansion
- [ ] Add `cap.sendPacket()` to enable packet injection.
- [ ] Implement `pcap_stats` to track dropped packets.
- [ ] Add support for reading multi-packet TCP streams (reassembly).

### Phase 2: Protocol Support
- [ ] **TLS**: Handshaking inspection (extracting SNI).
- [ ] **QUIC**: Initial parsing.
- [ ] **ICMPv6**: Full decoding (NDP, etc.).
- [ ] **VLAN**: Support for 802.1Q tags in `parseEthernet`.

### Phase 3: Cross-Platform
- [ ] Implement a Linux backend using `libpcap` (linking `libpcap.so`).
- [ ] Abstract the backend to allow the same `CaptureHandle` code to work on both Windows and Linux.

---

## 🤝 Contributing

We welcome contributions! If you would like to help:
1. **Add a Parser**: Feel free to submit a PR for a new protocol in `src/proto/`. Ensure it remains zero-allocation and zero-copy.
2. **Improve Examples**: Create more utility-style examples (e.g., a simple ping-checker).
3. **Bug Reports**: If you find an edge-case in a packet that causes a parser to crash or return `error.InvalidHeader`, please open an issue with the hex dump of the packet.

---

> **Note:** This project prioritizes performance and memory safety. All additions to the `proto` module must follow the **pure function** design pattern.
