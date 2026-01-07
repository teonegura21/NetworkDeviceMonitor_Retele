#pragma once

#include <cstdint>
#include <ctime>
#include <string>

namespace NMS {

/**
 * Represents a single network connection or socket.
 *
 * This structure captures the essential information about a network flow:
 * - Protocol (TCP/UDP)
 * - Local and remote endpoints (IP:Port)
 * - Connection state (for TCP)
 * - Timestamp of capture
 */
struct NetworkFlow {
  std::string protocol;  // "TCP" or "UDP"
  std::string local_ip;  // e.g., "192.168.1.17"
  uint16_t local_port;   // e.g., 33638
  std::string remote_ip; // e.g., "142.250.185.174"
  uint16_t remote_port;  // e.g., 443
  std::string state;     // e.g., "ESTABLISHED", "LISTEN", "UNCONN"
  time_t timestamp;      // Unix timestamp of capture

  /**
   * Format the flow as a syslog message for transmission to SIEM.
   *
   * Output format:
   * NETWORK_FLOW: TCP 192.168.1.17:33638 -> 142.250.185.174:443
   * state=ESTABLISHED
   */
  std::string ToSyslog() const {
    return "NETWORK_FLOW: " + protocol + " " + local_ip + ":" +
           std::to_string(local_port) + " -> " + remote_ip + ":" +
           std::to_string(remote_port) + " state=" + state;
  }

  /**
   * Check if this is an active (non-listening) connection.
   */
  bool IsActive() const {
    return state == "ESTABLISHED" || state == "SYN_SENT" ||
           state == "SYN_RECV" || state == "ESTAB";
  }

  /**
   * Check if this is a server socket (listening).
   */
  bool IsListening() const { return state == "LISTEN"; }

  /**
   * Get a human-readable description of the connection.
   */
  std::string Describe() const {
    if (IsListening()) {
      return protocol + " listening on port " + std::to_string(local_port);
    } else if (IsActive()) {
      return protocol + " " + local_ip + " → " + remote_ip + ":" +
             std::to_string(remote_port);
    } else {
      return protocol + " " + state + " " + local_ip + ":" +
             std::to_string(local_port);
    }
  }
};

} // namespace NMS
