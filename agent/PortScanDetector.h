#pragma once

#include "NetworkFlow.h"
#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace NMS {

/**
 * Represents a detected port scan alert.
 */
struct ScanAlert {
  std::string source_ip;    // IP performing the scan
  std::string scan_type;    // "TCP_CONNECT", "TCP_SYN", "UDP"
  std::set<uint16_t> ports; // Ports that were scanned
  int total_attempts;       // Total connection attempts
  int failed_attempts;      // Failed/refused connections
  int duration_seconds;     // How long the scan took
  std::string severity;     // "HIGH", "MEDIUM", "LOW"
  time_t detected_at;       // When we detected the scan
  std::string description;  // Human-readable description

  /**
   * Format as syslog message for transmission to SIEM.
   */
  std::string ToSyslog() const;
};

/**
 * PortScanDetector - Detects TCP and UDP port scanning attacks.
 *
 * This class implements the following detection rules:
 *
 * TCP RULES:
 * -----------------------------------------------------------------
 * Rule TCP_1: Short-lived connections
 *   - Connection established then closed in <1 second
 *   - Less than 100 bytes transferred
 *   - Indicates port probing, not legitimate traffic
 *
 * Rule TCP_2: Many ports from single source
 *   - Same source IP connects to 5+ different ports
 *   - Within 60 second time window
 *   - Classic port scan pattern
 *
 * Rule TCP_3: High failure rate
 *   - >70% of connection attempts are refused/reset
 *   - Scanners hit many closed ports
 *
 * Rule TCP_4: Sequential port access
 *   - Ports accessed in order (21, 22, 23, 24...)
 *   - nmap default scan behavior
 *
 * UDP RULES:
 * -----------------------------------------------------------------
 * Rule UDP_1: Closed port responses (via iptables logging)
 *   - Parse /var/log/kern.log for UDP_IN entries
 *   - Multiple UDP packets to closed ports from same IP
 *
 * Rule UDP_2: ICMP unreachable burst (via /proc/net/snmp)
 *   - Spike in OutDestUnreachs counter
 *   - Indicates someone hitting closed UDP ports
 */
class PortScanDetector {
public:
  PortScanDetector();
  ~PortScanDetector() = default;

  // =========================================================
  // CONFIGURATION
  // =========================================================

  /**
   * Set minimum ports to trigger scan detection.
   * Default: 5 ports
   */
  void SetPortThreshold(int threshold);

  /**
   * Set time window for tracking.
   * Default: 60 seconds
   */
  void SetTimeWindow(int seconds);

  /**
   * Set failure rate threshold.
   * Default: 0.70 (70%)
   */
  void SetFailureRateThreshold(float rate);

  // =========================================================
  // TCP DETECTION
  // =========================================================

  /**
   * Record a TCP connection observation.
   * Call this for each flow observed in /proc/net/tcp
   *
   * @param flow The network flow observation
   */
  void RecordTCPFlow(const NetworkFlow &flow);

  /**
   * Record a connection attempt (more detailed tracking).
   *
   * @param source_ip       Remote IP that connected
   * @param dest_port       Port they connected to
   * @param state           Connection state (ESTABLISHED, SYN_RECV, etc)
   * @param duration_ms     How long connection lasted (if known)
   * @param bytes_sent      Bytes transferred (if known)
   */
  void RecordTCPConnection(const std::string &source_ip, uint16_t dest_port,
                           const std::string &state, int duration_ms = -1,
                           int bytes_sent = -1);

  // =========================================================
  // UDP DETECTION
  // =========================================================

  /**
   * Record a UDP packet observation (from iptables log).
   *
   * @param source_ip  Source IP of UDP packet
   * @param dest_port  Destination port probed
   */
  void RecordUDPPacket(const std::string &source_ip, uint16_t dest_port);

  /**
   * Parse kernel log for UDP packets (requires iptables logging).
   * Looks for lines matching: "UDP_IN: ... SRC=x.x.x.x ... DPT=yyy"
   *
   * @param log_path Path to kernel log (default: /var/log/kern.log)
   * @return Number of UDP probes found
   */
  int ParseKernelLogForUDP(const std::string &log_path = "/var/log/kern.log");

  /**
   * Check ICMP "port unreachable" counter from /proc/net/snmp.
   * A sudden spike indicates UDP scan in progress.
   *
   * @return Delta in unreachable count since last check
   */
  uint64_t CheckICMPUnreachable();

  // =========================================================
  // DETECTION & ALERTS
  // =========================================================

  /**
   * Run all detection rules and return any new alerts.
   * Should be called periodically (e.g., every 5 seconds).
   *
   * @return Vector of new scan alerts detected
   */
  std::vector<ScanAlert> DetectScans();

  /**
   * Get all alerts generated since startup.
   *
   * @param max_count Maximum alerts to return (0 = all)
   * @return Vector of scan alerts
   */
  std::vector<ScanAlert> GetAlerts(int max_count = 0);

  /**
   * Clear old tracking data (older than time window).
   */
  void Cleanup();

  // =========================================================
  // STATISTICS
  // =========================================================

  /**
   * Get current statistics.
   */
  struct Stats {
    int tracked_ips;
    int total_tcp_observations;
    int total_udp_observations;
    int alerts_generated;
  };
  Stats GetStats() const;

private:
  /**
   * Tracking structure for each source IP.
   */
  struct IPTracker {
    std::set<uint16_t> ports_accessed;
    std::vector<std::chrono::steady_clock::time_point> access_times;
    int connection_count = 0;
    int failed_count = 0;
    int short_lived_count = 0; // Connections < 1 second
    int low_data_count = 0;    // Connections < 100 bytes
    bool alerted = false;      // Already generated alert for this IP
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
  };

  // Detection rule implementations
  bool CheckTCPRule_ManyPorts(const std::string &ip, const IPTracker &tracker);
  bool CheckTCPRule_HighFailure(const std::string &ip,
                                const IPTracker &tracker);
  bool CheckTCPRule_ShortLived(const std::string &ip, const IPTracker &tracker);
  bool CheckTCPRule_Sequential(const std::string &ip, const IPTracker &tracker);

  bool CheckUDPRule_ManyPorts(const std::string &ip, const IPTracker &tracker);
  bool CheckUDPRule_ICMPBurst();

  // Calculate alert severity
  std::string CalculateSeverity(const IPTracker &tracker);

  // Build alert description
  std::string BuildDescription(const std::string &ip, const IPTracker &tracker);

  // Parse ICMP stats from /proc/net/snmp
  uint64_t ReadICMPUnreachableCount();

  // Configuration
  int port_threshold_ = 5;
  int time_window_seconds_ = 60;
  float failure_rate_threshold_ = 0.70f;

  // Tracking data
  std::map<std::string, IPTracker> tcp_trackers_;
  std::map<std::string, IPTracker> udp_trackers_;
  std::vector<ScanAlert> alerts_;

  // ICMP tracking
  uint64_t last_icmp_unreachable_ = 0;
  std::chrono::steady_clock::time_point last_icmp_check_;

  // Thread safety
  mutable std::mutex mutex_;
};

} // namespace NMS
