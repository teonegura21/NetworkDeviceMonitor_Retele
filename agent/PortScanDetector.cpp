#include "PortScanDetector.h"
#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>

namespace NMS {

// ============================================================================
// ScanAlert methods
// ============================================================================

std::string ScanAlert::ToSyslog() const {
  std::ostringstream ss;
  ss << "PORT_SCAN_DETECTED: type=" << scan_type << " src=" << source_ip
     << " ports=" << ports.size() << " attempts=" << total_attempts
     << " failed=" << failed_attempts << " severity=" << severity;
  return ss.str();
}

// ============================================================================
// Constructor
// ============================================================================

PortScanDetector::PortScanDetector() {
  last_icmp_check_ = std::chrono::steady_clock::now();
  last_icmp_unreachable_ = ReadICMPUnreachableCount();
}

// ============================================================================
// Configuration
// ============================================================================

void PortScanDetector::SetPortThreshold(int threshold) {
  std::lock_guard<std::mutex> lock(mutex_);
  port_threshold_ = threshold;
}

void PortScanDetector::SetTimeWindow(int seconds) {
  std::lock_guard<std::mutex> lock(mutex_);
  time_window_seconds_ = seconds;
}

void PortScanDetector::SetFailureRateThreshold(float rate) {
  std::lock_guard<std::mutex> lock(mutex_);
  failure_rate_threshold_ = rate;
}

// ============================================================================
// TCP Detection
// ============================================================================

void PortScanDetector::RecordTCPFlow(const NetworkFlow &flow) {
  // Only track incoming connections (remote connecting to us)
  // Skip if remote is 0.0.0.0 (listening sockets)
  if (flow.remote_ip == "0.0.0.0")
    return;

  RecordTCPConnection(flow.remote_ip, flow.local_port, flow.state,
                      -1, // duration unknown
                      -1  // bytes unknown
  );
}

void PortScanDetector::RecordTCPConnection(const std::string &source_ip,
                                           uint16_t dest_port,
                                           const std::string &state,
                                           int duration_ms, int bytes_sent) {
  std::lock_guard<std::mutex> lock(mutex_);

  auto now = std::chrono::steady_clock::now();
  auto &tracker = tcp_trackers_[source_ip];

  // Initialize first_seen if new tracker
  if (tracker.connection_count == 0) {
    tracker.first_seen = now;
  }
  tracker.last_seen = now;

  // Record the port access
  tracker.ports_accessed.insert(dest_port);
  tracker.access_times.push_back(now);
  tracker.connection_count++;

  // Track connection characteristics
  // Failed states: SYN_RECV (never established), RST
  if (state == "SYN_RECV" || state == "CLOSE" || state == "TIME_WAIT") {
    tracker.failed_count++;
  }

  // Short-lived detection (if duration known)
  if (duration_ms >= 0 && duration_ms < 1000) {
    tracker.short_lived_count++;
  }

  // Low data detection (if bytes known)
  if (bytes_sent >= 0 && bytes_sent < 100) {
    tracker.low_data_count++;
  }
}

// ============================================================================
// UDP Detection
// ============================================================================

void PortScanDetector::RecordUDPPacket(const std::string &source_ip,
                                       uint16_t dest_port) {
  std::lock_guard<std::mutex> lock(mutex_);

  auto now = std::chrono::steady_clock::now();
  auto &tracker = udp_trackers_[source_ip];

  if (tracker.connection_count == 0) {
    tracker.first_seen = now;
  }
  tracker.last_seen = now;

  tracker.ports_accessed.insert(dest_port);
  tracker.access_times.push_back(now);
  tracker.connection_count++;
}

int PortScanDetector::ParseKernelLogForUDP(const std::string &log_path) {
  /*
   * Parse iptables LOG entries from kernel log.
   *
   * Expected format (from iptables -j LOG --log-prefix "UDP_IN: "):
   * Jan  7 20:00:00 host kernel: UDP_IN: IN=eth0 ... SRC=1.2.3.4 ... DPT=161
   * ...
   *
   * We extract SRC (source IP) and DPT (destination port).
   */

  std::ifstream file(log_path);
  if (!file.is_open()) {
    return 0;
  }

  // Regex to match: SRC=x.x.x.x and DPT=yyy
  std::regex src_regex("SRC=([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)");
  std::regex dpt_regex("DPT=([0-9]+)");

  int count = 0;
  std::string line;

  // Read last 1000 lines to avoid processing entire log
  std::vector<std::string> recent_lines;
  while (std::getline(file, line)) {
    if (line.find("UDP_IN:") != std::string::npos) {
      recent_lines.push_back(line);
      if (recent_lines.size() > 1000) {
        recent_lines.erase(recent_lines.begin());
      }
    }
  }

  for (const auto &log_line : recent_lines) {
    std::smatch src_match, dpt_match;

    if (std::regex_search(log_line, src_match, src_regex) &&
        std::regex_search(log_line, dpt_match, dpt_regex)) {

      std::string src_ip = src_match[1].str();
      uint16_t dest_port = static_cast<uint16_t>(std::stoi(dpt_match[1].str()));

      RecordUDPPacket(src_ip, dest_port);
      count++;
    }
  }

  return count;
}

uint64_t PortScanDetector::CheckICMPUnreachable() {
  std::lock_guard<std::mutex> lock(mutex_);

  uint64_t current = ReadICMPUnreachableCount();
  uint64_t delta = current - last_icmp_unreachable_;

  last_icmp_unreachable_ = current;
  last_icmp_check_ = std::chrono::steady_clock::now();

  return delta;
}

uint64_t PortScanDetector::ReadICMPUnreachableCount() {
  /*
   * Read ICMP statistics from /proc/net/snmp
   *
   * Format:
   * Icmp: InMsgs InErrors ... OutDestUnreachs ...
   * Icmp: 123    0        ... 456            ...
   *
   * We want OutDestUnreachs (destination unreachable sent)
   */

  std::ifstream file("/proc/net/snmp");
  if (!file.is_open()) {
    return 0;
  }

  std::string line;
  std::string header_line, values_line;

  while (std::getline(file, line)) {
    if (line.substr(0, 5) == "Icmp:") {
      if (header_line.empty()) {
        header_line = line;
      } else {
        values_line = line;
        break;
      }
    }
  }

  if (header_line.empty() || values_line.empty()) {
    return 0;
  }

  // Find OutDestUnreachs column
  std::istringstream header_ss(header_line);
  std::istringstream values_ss(values_line);

  std::string col_name;
  std::string col_value;

  while (header_ss >> col_name && values_ss >> col_value) {
    if (col_name == "OutDestUnreachs") {
      try {
        return std::stoull(col_value);
      } catch (...) {
        return 0;
      }
    }
  }

  return 0;
}

// ============================================================================
// Detection Rules
// ============================================================================

std::vector<ScanAlert> PortScanDetector::DetectScans() {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<ScanAlert> new_alerts;

  auto now = std::chrono::steady_clock::now();

  // Check TCP trackers
  for (auto &[ip, tracker] : tcp_trackers_) {
    if (tracker.alerted)
      continue;

    bool is_scan = false;
    std::string scan_type = "TCP_CONNECT";

    // Apply detection rules
    if (CheckTCPRule_ManyPorts(ip, tracker)) {
      is_scan = true;
    }
    if (CheckTCPRule_HighFailure(ip, tracker)) {
      is_scan = true;
      scan_type = "TCP_SYN"; // High failure suggests SYN scan
    }
    if (CheckTCPRule_Sequential(ip, tracker)) {
      is_scan = true;
      scan_type = "TCP_SEQUENTIAL";
    }
    if (CheckTCPRule_ShortLived(ip, tracker)) {
      is_scan = true;
    }

    if (is_scan) {
      ScanAlert alert;
      alert.source_ip = ip;
      alert.scan_type = scan_type;
      alert.ports = tracker.ports_accessed;
      alert.total_attempts = tracker.connection_count;
      alert.failed_attempts = tracker.failed_count;

      auto duration = std::chrono::duration_cast<std::chrono::seconds>(
          tracker.last_seen - tracker.first_seen);
      alert.duration_seconds = static_cast<int>(duration.count());

      alert.severity = CalculateSeverity(tracker);
      alert.detected_at = time(nullptr);
      alert.description = BuildDescription(ip, tracker);

      new_alerts.push_back(alert);
      alerts_.push_back(alert);
      tracker.alerted = true;

      std::cout << "🚨 " << alert.ToSyslog() << std::endl;
    }
  }

  // Check UDP trackers
  for (auto &[ip, tracker] : udp_trackers_) {
    if (tracker.alerted)
      continue;

    if (CheckUDPRule_ManyPorts(ip, tracker)) {
      ScanAlert alert;
      alert.source_ip = ip;
      alert.scan_type = "UDP";
      alert.ports = tracker.ports_accessed;
      alert.total_attempts = tracker.connection_count;
      alert.failed_attempts =
          tracker.connection_count; // All UDP to closed ports

      auto duration = std::chrono::duration_cast<std::chrono::seconds>(
          tracker.last_seen - tracker.first_seen);
      alert.duration_seconds = static_cast<int>(duration.count());

      alert.severity = CalculateSeverity(tracker);
      alert.detected_at = time(nullptr);
      alert.description = "UDP port scan detected from " + ip;

      new_alerts.push_back(alert);
      alerts_.push_back(alert);
      tracker.alerted = true;

      std::cout << "🚨 " << alert.ToSyslog() << std::endl;
    }
  }

  return new_alerts;
}

// ============================================================================
// TCP Detection Rules Implementation
// ============================================================================

bool PortScanDetector::CheckTCPRule_ManyPorts(const std::string &ip,
                                              const IPTracker &tracker) {
  /*
   * Rule TCP_2: Many ports from single source
   *
   * If same IP connects to 5+ different ports within time window,
   * it's likely a port scan.
   */

  if (tracker.ports_accessed.size() < static_cast<size_t>(port_threshold_)) {
    return false;
  }

  // Check time window
  auto now = std::chrono::steady_clock::now();
  auto window_start = now - std::chrono::seconds(time_window_seconds_);

  // Count recent accesses
  int recent_count = 0;
  for (const auto &access_time : tracker.access_times) {
    if (access_time >= window_start) {
      recent_count++;
    }
  }

  // At least port_threshold_ different ports in time window
  return recent_count >= port_threshold_;
}

bool PortScanDetector::CheckTCPRule_HighFailure(const std::string &ip,
                                                const IPTracker &tracker) {
  /*
   * Rule TCP_3: High failure rate
   *
   * If >70% of connection attempts fail (RST, refused, never established),
   * it indicates scanning behavior.
   */

  if (tracker.connection_count < 5) {
    return false; // Need enough samples
  }

  float failure_rate =
      static_cast<float>(tracker.failed_count) / tracker.connection_count;
  return failure_rate >= failure_rate_threshold_;
}

bool PortScanDetector::CheckTCPRule_ShortLived(const std::string &ip,
                                               const IPTracker &tracker) {
  /*
   * Rule TCP_1: Short-lived connections
   *
   * Many connections that last < 1 second with < 100 bytes transferred
   * indicate probing rather than legitimate traffic.
   */

  if (tracker.connection_count < 5) {
    return false;
  }

  // If >50% of connections are short-lived AND low-data
  float short_rate =
      static_cast<float>(tracker.short_lived_count) / tracker.connection_count;
  float low_data_rate =
      static_cast<float>(tracker.low_data_count) / tracker.connection_count;

  return (short_rate > 0.5) || (low_data_rate > 0.5);
}

bool PortScanDetector::CheckTCPRule_Sequential(const std::string &ip,
                                               const IPTracker &tracker) {
  /*
   * Rule TCP_4: Sequential port access
   *
   * Ports accessed in order (21, 22, 23, 24...) indicate
   * automated scanning (nmap default behavior).
   */

  if (tracker.ports_accessed.size() < 5) {
    return false;
  }

  // Convert set to sorted vector
  std::vector<uint16_t> ports(tracker.ports_accessed.begin(),
                              tracker.ports_accessed.end());
  std::sort(ports.begin(), ports.end());

  // Count sequential pairs (port[i+1] - port[i] <= 2)
  int sequential_count = 0;
  for (size_t i = 1; i < ports.size(); i++) {
    if (ports[i] - ports[i - 1] <= 2) {
      sequential_count++;
    }
  }

  // If >60% of port pairs are sequential
  float sequential_rate =
      static_cast<float>(sequential_count) / (ports.size() - 1);
  return sequential_rate > 0.6;
}

// ============================================================================
// UDP Detection Rules Implementation
// ============================================================================

bool PortScanDetector::CheckUDPRule_ManyPorts(const std::string &ip,
                                              const IPTracker &tracker) {
  /*
   * Rule UDP_1: Many UDP packets to different closed ports
   *
   * Similar to TCP rule - if we see UDP packets to 5+ different
   * closed ports from same IP, it's a UDP scan.
   */

  return tracker.ports_accessed.size() >= static_cast<size_t>(port_threshold_);
}

bool PortScanDetector::CheckUDPRule_ICMPBurst() {
  /*
   * Rule UDP_2: ICMP unreachable burst
   *
   * If we see >20 ICMP port unreachable messages in 5 seconds,
   * someone is hitting closed UDP ports.
   */

  // This is checked globally, not per-IP
  // The delta from CheckICMPUnreachable() should be >20

  return false; // Checked separately via CheckICMPUnreachable()
}

// ============================================================================
// Helper Methods
// ============================================================================

std::string PortScanDetector::CalculateSeverity(const IPTracker &tracker) {
  int ports = static_cast<int>(tracker.ports_accessed.size());

  if (ports >= 50)
    return "HIGH";
  if (ports >= 20)
    return "MEDIUM";
  return "LOW";
}

std::string PortScanDetector::BuildDescription(const std::string &ip,
                                               const IPTracker &tracker) {
  std::ostringstream ss;
  ss << "Port scan from " << ip << ": " << tracker.ports_accessed.size()
     << " ports scanned, " << tracker.failed_count << "/"
     << tracker.connection_count << " failed";

  if (tracker.ports_accessed.size() <= 20) {
    ss << " [ports: ";
    bool first = true;
    for (auto port : tracker.ports_accessed) {
      if (!first)
        ss << ",";
      ss << port;
      first = false;
    }
    ss << "]";
  }

  return ss.str();
}

std::vector<ScanAlert> PortScanDetector::GetAlerts(int max_count) {
  std::lock_guard<std::mutex> lock(mutex_);

  if (max_count <= 0 || static_cast<size_t>(max_count) >= alerts_.size()) {
    return alerts_;
  }

  return std::vector<ScanAlert>(alerts_.end() - max_count, alerts_.end());
}

void PortScanDetector::Cleanup() {
  std::lock_guard<std::mutex> lock(mutex_);

  auto now = std::chrono::steady_clock::now();
  auto cutoff = now - std::chrono::seconds(time_window_seconds_ * 2);

  // Remove old TCP trackers
  for (auto it = tcp_trackers_.begin(); it != tcp_trackers_.end();) {
    if (it->second.last_seen < cutoff) {
      it = tcp_trackers_.erase(it);
    } else {
      ++it;
    }
  }

  // Remove old UDP trackers
  for (auto it = udp_trackers_.begin(); it != udp_trackers_.end();) {
    if (it->second.last_seen < cutoff) {
      it = udp_trackers_.erase(it);
    } else {
      ++it;
    }
  }
}

PortScanDetector::Stats PortScanDetector::GetStats() const {
  std::lock_guard<std::mutex> lock(mutex_);

  Stats stats;
  stats.tracked_ips =
      static_cast<int>(tcp_trackers_.size() + udp_trackers_.size());
  stats.total_tcp_observations = 0;
  stats.total_udp_observations = 0;

  for (const auto &[ip, tracker] : tcp_trackers_) {
    stats.total_tcp_observations += tracker.connection_count;
  }
  for (const auto &[ip, tracker] : udp_trackers_) {
    stats.total_udp_observations += tracker.connection_count;
  }

  stats.alerts_generated = static_cast<int>(alerts_.size());

  return stats;
}

} // namespace NMS
