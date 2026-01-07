#include "FileSource.h"
#include "NetworkMonitor.h"
#include "NetworkSender.h"
#include "PortScanDetector.h"
#include "SyslogFormatter.h"
#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

using namespace std;
using namespace NMS;

// ============================================================================
// CONFIGURATION
// ============================================================================

const string SERVER_IP = "127.0.0.1";
const int SERVER_PORT = 514; // Syslog port
const TransportProtocol PROTOCOL = TCP;

// Monitoring intervals (milliseconds)
const int LOG_CHECK_INTERVAL = 1000;       // Check log files every 1 second
const int NETWORK_FLOW_INTERVAL = 10000;   // Collect flows every 10 seconds
const int PORT_SCAN_CHECK_INTERVAL = 5000; // Check for scans every 5 seconds

// ============================================================================
// HELPER: Send network flows to SIEM
// ============================================================================

void SendNetworkFlows(NetworkSender &sender, NetworkMonitor &monitor) {
  /*
   * Collect current network flows and send to SIEM server.
   *
   * Data Flow:
   *   Agent reads /proc/net/tcp, /proc/net/udp
   *   → Formats as syslog: "NETWORK_FLOW: TCP 192.168.1.17:443 -> ..."
   *   → Sends to server port 514
   *   → Server parses and stores in NetworkFlows table
   *   → Client displays in Dashboard
   */

  // Only send active (non-listening) connections
  auto flows = monitor.GetActiveConnections();

  for (const auto &flow : flows) {
    // Format as syslog message
    string msg = flow.ToSyslog();
    string syslog_msg = SyslogFormatter::Format(msg, "network-flow");

    if (sender.Send(syslog_msg)) {
      // Sent successfully (don't spam console for every flow)
    }
  }

  if (!flows.empty()) {
    cout << "📊 Sent " << flows.size() << " network flows" << endl;
  }
}

// ============================================================================
// HELPER: Check for port scans and send alerts
// ============================================================================

void CheckPortScans(NetworkSender &sender, PortScanDetector &detector,
                    NetworkMonitor &monitor) {
  /*
   * Feed network flows to detector and check for scans.
   *
   * Data Flow:
   *   Agent detects scan pattern
   *   → Formats as syslog: "PORT_SCAN_DETECTED: type=TCP_SYN src=..."
   *   → Sends to server port 514 (HIGH PRIORITY)
   *   → Server creates alert in Alerts table
   *   → Client displays in Alerts tab with severity colors
   */

  // Feed current flows to detector
  auto flows = monitor.CollectFlows();
  for (const auto &flow : flows) {
    detector.RecordTCPFlow(flow);
  }

  // Run detection rules
  auto alerts = detector.DetectScans();

  // Send any new alerts to SIEM
  for (const auto &alert : alerts) {
    string msg = alert.ToSyslog();
    // Use high priority (severity 1) for security alerts
    string syslog_msg = SyslogFormatter::Format(msg, "security-alert");

    if (sender.Send(syslog_msg)) {
      cout << "🚨 ALERT: " << alert.description << endl;
    } else {
      cerr << "❌ Failed to send alert!" << endl;
    }
  }

  // Cleanup old tracking data
  detector.Cleanup();
}

// ============================================================================
// MAIN
// ============================================================================

int main() {
  cout << "==========================================" << endl;
  cout << "  NMS Agent v2.0 - Network Monitor       " << endl;
  cout << "==========================================" << endl;
  cout << endl;
  cout << "🔵 Starting NMS Agent..." << endl;
  cout << "   Target: " << SERVER_IP << ":" << SERVER_PORT
       << (PROTOCOL == TCP ? " (TCP)" : " (UDP)") << endl;
  cout << endl;

  // ========================================
  // 1. Initialize Network Sender
  // ========================================
  NetworkSender sender(SERVER_IP, SERVER_PORT, PROTOCOL);

  // ========================================
  // 2. Initialize Log File Sources
  // ========================================
  vector<InputSource *> log_sources;

  log_sources.push_back(new FileSource("/var/log/syslog", "syslog"));
  log_sources.push_back(new FileSource("/var/log/auth.log", "auth"));
  log_sources.push_back(new FileSource("./agent_test.log", "test-agent"));

  cout << "📁 Log sources: " << log_sources.size() << " files" << endl;

  // ========================================
  // 3. Initialize Network Monitors (NEW!)
  // ========================================
  NetworkMonitor network_monitor;
  PortScanDetector scan_detector;

  // Configure port scan detector
  scan_detector.SetPortThreshold(5);           // 5 ports = scan
  scan_detector.SetTimeWindow(60);             // 60 second window
  scan_detector.SetFailureRateThreshold(0.7f); // 70% failure

  cout << "🌐 Network flow monitor: enabled" << endl;
  cout << "🔍 Port scan detector: enabled" << endl;
  cout << "   Threshold: 5 ports in 60 seconds" << endl;
  cout << endl;

  // ========================================
  // 4. Timing variables
  // ========================================
  auto last_flow_check = chrono::steady_clock::now();
  auto last_scan_check = chrono::steady_clock::now();

  cout << "✅ Agent started. Monitoring..." << endl;
  cout << "   Press Ctrl+C to stop." << endl;
  cout << endl;

  // ========================================
  // 5. Main Loop
  // ========================================
  while (true) {
    auto now = chrono::steady_clock::now();

    // -------------------------------------
    // Check log files (every 1 second)
    // -------------------------------------
    for (auto source : log_sources) {
      vector<string> new_lines = source->ReadNewLines();

      if (!new_lines.empty()) {
        string tag = "app";
        FileSource *fs = dynamic_cast<FileSource *>(source);
        if (fs)
          tag = fs->GetTag();

        for (const auto &line : new_lines) {
          string rfc5424_msg = SyslogFormatter::Format(line, tag);

          if (sender.Send(rfc5424_msg)) {
            cout << "✓ Log: " << line.substr(0, 50) << "..." << endl;
          }
        }
      }
    }

    // -------------------------------------
    // Collect network flows (every 10 seconds)
    // -------------------------------------
    auto flow_elapsed =
        chrono::duration_cast<chrono::milliseconds>(now - last_flow_check)
            .count();

    if (flow_elapsed >= NETWORK_FLOW_INTERVAL) {
      SendNetworkFlows(sender, network_monitor);
      last_flow_check = now;
    }

    // -------------------------------------
    // Check for port scans (every 5 seconds)
    // -------------------------------------
    auto scan_elapsed =
        chrono::duration_cast<chrono::milliseconds>(now - last_scan_check)
            .count();

    if (scan_elapsed >= PORT_SCAN_CHECK_INTERVAL) {
      CheckPortScans(sender, scan_detector, network_monitor);
      last_scan_check = now;
    }

    // Sleep to avoid high CPU usage
    this_thread::sleep_for(chrono::milliseconds(LOG_CHECK_INTERVAL));
  }

  // Cleanup
  for (auto s : log_sources)
    delete s;
  return 0;
}
