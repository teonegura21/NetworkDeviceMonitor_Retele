# Network Flow Analysis - Learning Guide

## Part 1: Understanding /proc/net/tcp

This is the **kernel's view** of all TCP connections on your system.

### Real Data from Your System

```
  sl  local_address rem_address   st tx_queue rx_queue ...
   0: 00000000:1F41 00000000:0000 0A 00000000:00000000 ...
   8: 017AA8C0:0035 00000000:0000 0A 00000000:00000000 ...
  11: 1101A8C0:8366 AEB9FA8E:01BB 01 00000000:00000000 ...
```

Let's decode each field!

---

### Field 1: `sl` (Slot Number)

Just a sequential ID - not important for our purposes.

---

### Field 2: `local_address` - YOUR Machine

Format: `XXXXXXXX:PPPP` where X=IP in hex, P=port in hex

**Example 1:** `00000000:1F41`
- IP: `00000000` = 0.0.0.0 (listening on ALL interfaces)
- Port: `1F41` hex = **8001** decimal

**Example 2:** `1101A8C0:8366`
- IP: `1101A8C0` → Let's convert!
  - Linux stores in **little-endian**: bytes are reversed
  - `11` `01` `A8` `C0` → read backwards: `C0.A8.01.11`
  - `C0` = 192, `A8` = 168, `01` = 1, `11` = 17
  - **Result: 192.168.1.17** (Your local IP!)
- Port: `8366` hex = **33638** decimal

**Conversion Formula (C++):**
```cpp
std::string hexToIP(const std::string& hex) {
    uint32_t ip = std::stoul(hex, nullptr, 16);
    // Little-endian: least significant byte first
    return std::to_string(ip & 0xFF) + "." +           // 1st byte
           std::to_string((ip >> 8) & 0xFF) + "." +    // 2nd byte
           std::to_string((ip >> 16) & 0xFF) + "." +   // 3rd byte
           std::to_string((ip >> 24) & 0xFF);          // 4th byte
}

uint16_t hexToPort(const std::string& hex) {
    return std::stoul(hex, nullptr, 16);  // Ports are NOT reversed
}
```

---

### Field 3: `rem_address` - REMOTE Machine

Same format as local_address.

**Example:** `AEB9FA8E:01BB`
- IP: `AEB9FA8E` → backwards: `8E.FA.B9.AE`
  - `8E` = 142, `FA` = 250, `B9` = 185, `AE` = 174
  - **Result: 142.250.185.174** (This is Google!)
- Port: `01BB` hex = **443** (HTTPS!)

So this line shows: **Your machine (192.168.1.17:33638) → Google (142.250.185.174:443)**

---

### Field 4: `st` - Connection State

| Hex | Decimal | State Name | Meaning |
|-----|---------|------------|---------|
| 01 | 1 | ESTABLISHED | Active connection, data flowing |
| 02 | 2 | SYN_SENT | You sent SYN, waiting for response |
| 03 | 3 | SYN_RECV | Received SYN, sent SYN-ACK, waiting |
| 04 | 4 | FIN_WAIT1 | You sent FIN, waiting for ACK |
| 05 | 5 | FIN_WAIT2 | Got ACK for FIN, waiting for their FIN |
| 06 | 6 | TIME_WAIT | Waiting to ensure remote got final ACK |
| 07 | 7 | CLOSE | Socket is closed |
| 08 | 8 | CLOSE_WAIT | Remote closed, you haven't yet |
| 09 | 9 | LAST_ACK | Waiting for final ACK |
| 0A | 10 | LISTEN | Server socket waiting for connections |
| 0B | 11 | CLOSING | Both sides sent FIN simultaneously |

**From your data:**
- `0A` = **LISTEN** (servers waiting for connections)
- `01` = **ESTABLISHED** (active connections like your Chrome → Google)

---

### Real Connections Decoded

| Line | Local | Remote | State | Meaning |
|------|-------|--------|-------|---------|
| 0 | 0.0.0.0:8001 | - | LISTEN | Some service on port 8001 |
| 8 | 192.168.122.1:53 | - | LISTEN | DNS server (libvirt?) |
| 11 | 192.168.1.17:33638 | 142.250.185.174:443 | ESTABLISHED | Chrome → Google HTTPS |
| 12 | 192.168.1.17:39810 | 142.251.140.170:443 | ESTABLISHED | Chrome → Google HTTPS |

---

## Part 2: Understanding /proc/net/udp

Similar format but UDP has no "connection state" (it's connectionless!).

```
   sl  local_address rem_address   st ...
  285: 00000000:81FE 00000000:0000 07 ...
 1675: 00000000:076C 00000000:0000 07 ...
```

**State 07** = UDP socket (doesn't really mean "closed" - UDP has no connection concept)

**Example:** `00000000:076C`
- Port `076C` = **1900** decimal
- This is **SSDP** (Simple Service Discovery Protocol - used by Spotify for device discovery!)

---

## Part 3: Why `ss` is Easier

The `ss` command parses this for you:

```
Netid State   Local Address:Port              Peer Address:Port  Process
udp   ESTAB   192.168.1.17:40173              142.250.185.174:443 chrome
```

But for our C++ agent, we'll read `/proc/net/*` directly - it's faster and has no external dependency!

---

## Part 4: What We'll Collect

For each connection, we want:

```cpp
struct NetworkFlow {
    string protocol;      // "TCP" or "UDP"
    string local_ip;      // e.g., "192.168.1.17"
    uint16_t local_port;  // e.g., 33638
    string remote_ip;     // e.g., "142.250.185.174"
    uint16_t remote_port; // e.g., 443
    string state;         // e.g., "ESTABLISHED"
    time_t timestamp;     // When we captured this
};
```

---

## Next Steps

See NetworkMonitor.h and NetworkMonitor.cpp for implementation!
