#include "FileSource.h"
#include "NetworkMonitor.h"
#include "NetworkSender.h"
#include "PortScanDetector.h"
#include "SyslogFormatter.h"
#include <chrono>
#include <cstdio>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

using namespace std;
using namespace NMS;

// ============================================================================
// CONFIGURATION GLOBALS
// ============================================================================
string SERVER_IP = "192.168.122.1"; // HARDCODED FOR VM
int SERVER_PORT = 514;
const TransportProtocol PROTOCOL = TCP;

// Monitoring intervals (milliseconds)
const int LOG_CHECK_INTERVAL = 1000;       // Check log files every 1 second
const int NETWORK_FLOW_INTERVAL = 10000;   // Collect flows every 10 seconds
const int PORT_SCAN_CHECK_INTERVAL = 5000; // Check for scans every 5 seconds

// ============================================================================
// CONFIG LOADER (DISABLED TO FORCE IP)
// ============================================================================
void LoadConfig() {
  // Disabled to guarantee connection to 192.168.122.1
  /*
  FILE* f = fopen("nms_agent.conf", "r");
  if (!f) f = fopen("/etc/nms-agent/nms_agent.conf", "r");

  if (f) {
      char line[256];
      while (fgets(line, sizeof(line), f)) {
          string s(line);
          if (s.find("server_ip=") == 0) {
              size_t end = s.find_first_of("\r\n");
              SERVER_IP = s.substr(10, end - 10);
          }
          if (s.find("server_port=") == 0) {
              try {
                  SERVER_PORT = stoi(s.substr(12));
              } catch(...) {}
          }
      }
      fclose(f);
      cout << "📄 Loaded config: Server=" << SERVER_IP << ":" << SERVER_PORT <<
  endl; } else { cout << "⚠️ No config file found. Using default: " << SERVER_IP
  << ":" << SERVER_PORT << endl;
  }
  */
  cout << "🔒 Config locked to: " << SERVER_IP << ":" << SERVER_PORT << endl;
}

// ============================================================================
// HELPER: Send network flows to SIEM
// ============================================================================

void SendNetworkFlows(NetworkSender &sender, NetworkMonitor &monitor) {
  // Only send active (non-listening) connections
  auto flows = monitor.GetActiveConnections();

  for (const auto &flow : flows) {
    // Format as syslog message
    string msg = flow.ToSyslog();
    string syslog_msg = SyslogFormatter::Format(msg, "network-flow");

    if (sender.Send(syslog_msg)) {
      // Sent successfully
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
  LoadConfig();

  cout << "==========================================" << endl;
  cout << "  NMS Agent v2.1 - Network Monitor       " << endl;
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
  // log_sources.push_back(new FileSource("./agent_test.log", "test-agent"));

  cout << "📁 Log sources: " << log_sources.size() << " files" << endl;

  // ========================================
  // 3. Initialize Network Monitors
  // ========================================
  NetworkMonitor network_monitor;
  PortScanDetector scan_detector;

  // Configure port scan detector
  scan_detector.SetPortThreshold(5);
  scan_detector.SetTimeWindow(60);
  scan_detector.SetFailureRateThreshold(0.7f);

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
    // Collect network flows
    // -------------------------------------
    auto flow_elapsed =
        chrono::duration_cast<chrono::milliseconds>(now - last_flow_check)
            .count();

    if (flow_elapsed >= NETWORK_FLOW_INTERVAL) {
      SendNetworkFlows(sender, network_monitor);
      last_flow_check = now;
    }

    // -------------------------------------
    // Check for port scans
    // -------------------------------------
    auto scan_elapsed =
        chrono::duration_cast<chrono::milliseconds>(now - last_scan_check)
            .count();

    if (scan_elapsed >= PORT_SCAN_CHECK_INTERVAL) {
      CheckPortScans(sender, scan_detector, network_monitor);
      last_scan_check = now;
    }

    // Sleep
    this_thread::sleep_for(chrono::milliseconds(LOG_CHECK_INTERVAL));
  }

  // Cleanup
  for (auto s : log_sources)
    delete s;
  return 0;
}
