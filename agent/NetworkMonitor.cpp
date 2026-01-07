#include "NetworkMonitor.h"
#include <cstdint>
#include <iostream>

namespace NMS {

// ============================================================================
// PUBLIC METHODS
// ============================================================================

std::vector<NetworkFlow> NetworkMonitor::CollectFlows() {
  std::vector<NetworkFlow> all_flows;

  // Collect TCP connections
  auto tcp = CollectTCP();
  all_flows.insert(all_flows.end(), tcp.begin(), tcp.end());

  // Collect UDP sockets
  auto udp = CollectUDP();
  all_flows.insert(all_flows.end(), udp.begin(), udp.end());

  return all_flows;
}

std::vector<NetworkFlow> NetworkMonitor::CollectTCP() {
  return ParseProcNetFile("/proc/net/tcp", "TCP");
}

std::vector<NetworkFlow> NetworkMonitor::CollectUDP() {
  return ParseProcNetFile("/proc/net/udp", "UDP");
}

std::vector<NetworkFlow> NetworkMonitor::GetActiveConnections() {
  std::vector<NetworkFlow> active;
  auto all = CollectFlows();

  for (const auto &flow : all) {
    if (flow.IsActive()) {
      active.push_back(flow);
    }
  }

  return active;
}

std::vector<NetworkFlow> NetworkMonitor::GetListeningSockets() {
  std::vector<NetworkFlow> listening;
  auto tcp = CollectTCP(); // Only TCP can "listen"

  for (const auto &flow : tcp) {
    if (flow.IsListening()) {
      listening.push_back(flow);
    }
  }

  return listening;
}

// ============================================================================
// PRIVATE METHODS
// ============================================================================

std::vector<NetworkFlow>
NetworkMonitor::ParseProcNetFile(const std::string &path,
                                 const std::string &protocol) {
  std::vector<NetworkFlow> flows;
  std::ifstream file(path);

  if (!file.is_open()) {
    std::cerr << "[NetworkMonitor] Failed to open " << path << std::endl;
    return flows;
  }

  std::string line;

  // Skip the header line
  // Format: "  sl  local_address rem_address   st tx_queue rx_queue ..."
  std::getline(file, line);

  while (std::getline(file, line)) {
    // Parse line
    // Example: "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 ..."

    std::istringstream iss(line);
    std::string slot, local_addr, remote_addr, state_hex;

    // Read: slot_number, local_address, remote_address, state
    iss >> slot >> local_addr >> remote_addr >> state_hex;

    if (local_addr.empty() || remote_addr.empty()) {
      continue; // Skip malformed lines
    }

    // Parse local address (format: XXXXXXXX:PPPP)
    size_t colon_pos = local_addr.find(':');
    if (colon_pos == std::string::npos)
      continue;

    std::string local_ip_hex = local_addr.substr(0, colon_pos);
    std::string local_port_hex = local_addr.substr(colon_pos + 1);

    // Parse remote address
    colon_pos = remote_addr.find(':');
    if (colon_pos == std::string::npos)
      continue;

    std::string remote_ip_hex = remote_addr.substr(0, colon_pos);
    std::string remote_port_hex = remote_addr.substr(colon_pos + 1);

    // Create NetworkFlow
    NetworkFlow flow;
    flow.protocol = protocol;
    flow.local_ip = HexToIP(local_ip_hex);
    flow.local_port = HexToPort(local_port_hex);
    flow.remote_ip = HexToIP(remote_ip_hex);
    flow.remote_port = HexToPort(remote_port_hex);

    // Parse state (convert hex string to int, then to state name)
    int state_code = 0;
    try {
      state_code = std::stoi(state_hex, nullptr, 16);
    } catch (...) {
      state_code = 0;
    }

    if (protocol == "TCP") {
      flow.state = StateCodeToString(state_code);
    } else {
      // UDP doesn't have connection states
      flow.state = "UNCONN";
    }

    flow.timestamp = time(nullptr);

    flows.push_back(flow);
  }

  return flows;
}

std::string NetworkMonitor::HexToIP(const std::string &hex) {
  /*
   * Convert hex IP to dotted decimal.
   *
   * Linux stores IP addresses in /proc/net/* in little-endian hex format.
   * Example: "1101A8C0" represents 192.168.1.17
   *
   * Breaking it down:
   *   Hex: 11 01 A8 C0
   *   As 32-bit value: 0x1101A8C0 = 285,313,216 decimal
   *
   *   Extracting bytes (little-endian read):
   *     Byte 0 (bits 0-7):   0xC0 & 0xFF = 192
   *     Byte 1 (bits 8-15):  (0xC0 >> 8) & 0xFF = 168
   *     Byte 2 (bits 16-23): (0xC0 >> 16) & 0xFF = 1
   *     Byte 3 (bits 24-31): (0xC0 >> 24) & 0xFF = 17
   *
   *   Wait, that's backwards! Let me recalculate...
   *
   *   Actually: 0x1101A8C0
   *     Byte 0: 0x1101A8C0 & 0xFF = 0xC0 = 192  ← Network order: first byte
   *     Byte 1: (0x1101A8C0 >> 8) & 0xFF = 0xA8 = 168
   *     Byte 2: (0x1101A8C0 >> 16) & 0xFF = 0x01 = 1
   *     Byte 3: (0x1101A8C0 >> 24) & 0xFF = 0x11 = 17
   *
   *   Result: 192.168.1.17 ✓
   */

  if (hex.empty()) {
    return "0.0.0.0";
  }

  try {
    uint32_t ip = std::stoul(hex, nullptr, 16);

    // Extract each byte (little-endian storage in /proc/net)
    uint8_t b0 = ip & 0xFF;
    uint8_t b1 = (ip >> 8) & 0xFF;
    uint8_t b2 = (ip >> 16) & 0xFF;
    uint8_t b3 = (ip >> 24) & 0xFF;

    return std::to_string(b0) + "." + std::to_string(b1) + "." +
           std::to_string(b2) + "." + std::to_string(b3);
  } catch (...) {
    return "0.0.0.0";
  }
}

uint16_t NetworkMonitor::HexToPort(const std::string &hex) {
  /*
   * Convert hex port number to integer.
   *
   * Unlike IP addresses, ports are stored in a straightforward way.
   * Example: "01BB" = 443 (HTTPS)
   *          "0050" = 80 (HTTP)
   *          "0016" = 22 (SSH)
   */

  if (hex.empty()) {
    return 0;
  }

  try {
    return static_cast<uint16_t>(std::stoul(hex, nullptr, 16));
  } catch (...) {
    return 0;
  }
}

std::string NetworkMonitor::StateCodeToString(int state) {
  /*
   * TCP state codes from Linux kernel.
   *
   * These correspond to the TCP state machine:
   *
   *    CLOSED ─────▶ LISTEN (server waiting)
   *                      │
   *             SYN_RECV ◀┘
   *                 │
   *                 ▼
   *    ESTABLISHED ◀───── (three-way handshake complete)
   *         │
   *    FIN_WAIT1 ────▶ FIN_WAIT2 ────▶ TIME_WAIT ────▶ CLOSED
   *         │              │
   *    CLOSING ◀───────────┘
   *         │
   *    LAST_ACK ────▶ CLOSED
   */

  switch (state) {
  case 1:
    return "ESTABLISHED"; // Connection active
  case 2:
    return "SYN_SENT"; // Outgoing SYN sent
  case 3:
    return "SYN_RECV"; // SYN received, waiting for ACK
  case 4:
    return "FIN_WAIT1"; // FIN sent, waiting for response
  case 5:
    return "FIN_WAIT2"; // FIN acknowledged, waiting for FIN
  case 6:
    return "TIME_WAIT"; // Waiting before final close
  case 7:
    return "CLOSE"; // Connection closed
  case 8:
    return "CLOSE_WAIT"; // Remote closed, local hasn't yet
  case 9:
    return "LAST_ACK"; // Waiting for final ACK
  case 10:
    return "LISTEN"; // Server socket listening
  case 11:
    return "CLOSING"; // Both ends sent FIN simultaneously
  default:
    return "UNKNOWN";
  }
}

} // namespace NMS
