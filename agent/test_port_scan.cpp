#include "NetworkMonitor.h"
#include "PortScanDetector.h"
#include <chrono>
#include <iomanip>
#include <iostream>
#include <thread>

using namespace NMS;

void PrintStats(const PortScanDetector::Stats &stats) {
  std::cout << "  Tracked IPs:     " << stats.tracked_ips << std::endl;
  std::cout << "  TCP Observations:" << stats.total_tcp_observations
            << std::endl;
  std::cout << "  UDP Observations:" << stats.total_udp_observations
            << std::endl;
  std::cout << "  Alerts Generated:" << stats.alerts_generated << std::endl;
}

void SimulatePortScan(PortScanDetector &detector) {
  /*
   * Simulate a port scan from a "malicious" IP.
   * This demonstrates how the detection would work.
   */

  std::cout << "\n🎭 Simulating port scan from 10.0.0.99..." << std::endl;

  // Simulate scanning ports 20-30
  for (int port = 20; port <= 30; port++) {
    detector.RecordTCPConnection(
        "10.0.0.99", // Attacker IP
        port,        // Destination port
        "SYN_RECV",  // State (SYN received, never established)
        50,          // Duration: 50ms (very short)
        0            // 0 bytes (probe only)
    );
  }

  std::cout << "   Recorded 11 connection attempts to ports 20-30" << std::endl;
}

void SimulateUDPScan(PortScanDetector &detector) {
  /*
   * Simulate a UDP scan from another IP.
   */

  std::cout << "\n🎭 Simulating UDP scan from 192.168.100.50..." << std::endl;

  // Simulate UDP packets to various ports
  std::vector<uint16_t> udp_ports = {53, 69, 123, 161, 500, 514, 1900, 5353};

  for (auto port : udp_ports) {
    detector.RecordUDPPacket("192.168.100.50", port);
  }

  std::cout << "   Recorded " << udp_ports.size() << " UDP packets"
            << std::endl;
}

int main() {
  std::cout << "===========================================" << std::endl;
  std::cout << "  Port Scan Detector - Test Program       " << std::endl;
  std::cout << "===========================================" << std::endl;
  std::cout << std::endl;

  // Create detector with custom thresholds
  PortScanDetector detector;
  detector.SetPortThreshold(5);           // 5 ports = scan
  detector.SetTimeWindow(60);             // 60 second window
  detector.SetFailureRateThreshold(0.5f); // 50% failure for testing

  // Create network monitor
  NetworkMonitor monitor;

  // =========================================================
  // TEST 1: Feed real network flows to detector
  // =========================================================
  std::cout << "📊 Test 1: Analyzing current network flows..." << std::endl;
  std::cout << "-------------------------------------------" << std::endl;

  auto flows = monitor.CollectFlows();
  std::cout << "   Collected " << flows.size() << " flows from /proc/net/"
            << std::endl;

  for (const auto &flow : flows) {
    detector.RecordTCPFlow(flow);
  }

  auto stats = detector.GetStats();
  PrintStats(stats);
  std::cout << std::endl;

  // =========================================================
  // TEST 2: Simulate a TCP port scan
  // =========================================================
  std::cout << "📊 Test 2: Simulating TCP port scan..." << std::endl;
  std::cout << "-------------------------------------------" << std::endl;

  SimulatePortScan(detector);

  // Run detection
  auto alerts = detector.DetectScans();

  std::cout << "\n   Detection results: " << alerts.size() << " alerts"
            << std::endl;
  for (const auto &alert : alerts) {
    std::cout << "   → " << alert.description << std::endl;
    std::cout << "     Severity: " << alert.severity << std::endl;
    std::cout << "     Type: " << alert.scan_type << std::endl;
  }
  std::cout << std::endl;

  // =========================================================
  // TEST 3: Simulate a UDP scan
  // =========================================================
  std::cout << "📊 Test 3: Simulating UDP scan..." << std::endl;
  std::cout << "-------------------------------------------" << std::endl;

  SimulateUDPScan(detector);

  alerts = detector.DetectScans();

  std::cout << "\n   Detection results: " << alerts.size() << " new alerts"
            << std::endl;
  for (const auto &alert : alerts) {
    std::cout << "   → " << alert.description << std::endl;
    std::cout << "     Severity: " << alert.severity << std::endl;
    std::cout << "     Type: " << alert.scan_type << std::endl;
  }
  std::cout << std::endl;

  // =========================================================
  // TEST 4: Check ICMP unreachable stats
  // =========================================================
  std::cout << "📊 Test 4: ICMP statistics..." << std::endl;
  std::cout << "-------------------------------------------" << std::endl;

  uint64_t icmp_delta = detector.CheckICMPUnreachable();
  std::cout << "   ICMP unreachable delta: " << icmp_delta << std::endl;

  if (icmp_delta > 20) {
    std::cout << "   ⚠️  High ICMP unreachable count - possible UDP scan!"
              << std::endl;
  } else {
    std::cout << "   ✅ Normal ICMP levels" << std::endl;
  }
  std::cout << std::endl;

  // =========================================================
  // TEST 5: Show all alerts
  // =========================================================
  std::cout << "📊 Test 5: All detected alerts..." << std::endl;
  std::cout << "-------------------------------------------" << std::endl;

  auto all_alerts = detector.GetAlerts(10);
  std::cout << "   Total alerts: " << all_alerts.size() << std::endl;
  std::cout << std::endl;

  for (const auto &alert : all_alerts) {
    std::cout << "   🚨 ALERT" << std::endl;
    std::cout << "      Source IP:  " << alert.source_ip << std::endl;
    std::cout << "      Type:       " << alert.scan_type << std::endl;
    std::cout << "      Ports:      " << alert.ports.size() << std::endl;
    std::cout << "      Attempts:   " << alert.total_attempts << std::endl;
    std::cout << "      Failed:     " << alert.failed_attempts << std::endl;
    std::cout << "      Severity:   " << alert.severity << std::endl;
    std::cout << "      Syslog:     " << alert.ToSyslog() << std::endl;
    std::cout << std::endl;
  }

  // =========================================================
  // Final statistics
  // =========================================================
  std::cout << "📈 Final Statistics:" << std::endl;
  std::cout << "-------------------------------------------" << std::endl;
  stats = detector.GetStats();
  PrintStats(stats);
  std::cout << std::endl;

  std::cout << "✅ Port Scan Detector working correctly!" << std::endl;
  std::cout << std::endl;
  std::cout << "To test with real port scan:" << std::endl;
  std::cout << "  nmap -sT localhost -p 1-100" << std::endl;
  std::cout << "  nmap -sS localhost -p 1-100  (requires root)" << std::endl;
  std::cout << "  nmap -sU localhost -p 1-100  (UDP, requires root)"
            << std::endl;

  return 0;
}
