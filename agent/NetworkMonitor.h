#pragma once

#include "NetworkFlow.h"
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace NMS {

/**
 * NetworkMonitor - Collects network connection information from /proc
 * filesystem.
 *
 * This class reads TCP and UDP socket information directly from the Linux
 * kernel via the /proc/net/tcp and /proc/net/udp pseudo-files. This approach:
 * - Has no external dependencies (doesn't shell out to 'ss' or 'netstat')
 * - Is very fast (direct kernel interface)
 * - Works without elevated privileges (basic socket info is readable by any
 * user)
 *
 * The /proc/net/tcp format:
 *   sl  local_address rem_address   st tx_queue rx_queue ...
 *   0:  0100007F:1F90 00000000:0000 0A 00000000:00000000 ...
 *
 * Where:
 * - local_address/rem_address = IP:PORT in hex (IP is little-endian!)
 * - st = TCP state (0A=LISTEN, 01=ESTABLISHED, etc.)
 */
class NetworkMonitor {
public:
  NetworkMonitor() = default;
  ~NetworkMonitor() = default;

  /**
   * Collect all current network connections (TCP + UDP).
   *
   * @return Vector of NetworkFlow objects representing all connections.
   */
  std::vector<NetworkFlow> CollectFlows();

  /**
   * Collect only TCP connections.
   */
  std::vector<NetworkFlow> CollectTCP();

  /**
   * Collect only UDP sockets.
   */
  std::vector<NetworkFlow> CollectUDP();

  /**
   * Get only active (ESTABLISHED) connections - useful for monitoring traffic.
   */
  std::vector<NetworkFlow> GetActiveConnections();

  /**
   * Get only listening sockets - useful for security auditing.
   */
  std::vector<NetworkFlow> GetListeningSockets();

private:
  /**
   * Parse /proc/net/tcp file.
   */
  std::vector<NetworkFlow> ParseProcNetFile(const std::string &path,
                                            const std::string &protocol);

  /**
   * Convert hex IP address to dotted decimal string.
   *
   * Linux stores IPs in little-endian hex format:
   *   "1101A8C0" → parse as 0xC0A80111 → "192.168.1.17"
   *
   * The bytes are stored in reverse order because x86 is little-endian.
   */
  std::string HexToIP(const std::string &hex);

  /**
   * Convert hex port to integer.
   * Ports are stored in network byte order (big-endian), which is the same
   * as how we normally read them, so no reversal needed.
   */
  uint16_t HexToPort(const std::string &hex);

  /**
   * Convert TCP state code to human-readable string.
   *
   * State codes (from Linux kernel include/net/tcp_states.h):
   *   01 = ESTABLISHED  06 = TIME_WAIT
   *   02 = SYN_SENT     07 = CLOSE
   *   03 = SYN_RECV     08 = CLOSE_WAIT
   *   04 = FIN_WAIT1    09 = LAST_ACK
   *   05 = FIN_WAIT2    0A = LISTEN
   *                     0B = CLOSING
   */
  std::string StateCodeToString(int state);
};

} // namespace NMS
