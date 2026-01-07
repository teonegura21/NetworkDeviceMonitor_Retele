#include "NetworkMonitor.h"
#include <iomanip>
#include <iostream>

using namespace NMS;

int main() {
  std::cout << "==========================================" << std::endl;
  std::cout << "  Network Flow Monitor - Test Program    " << std::endl;
  std::cout << "==========================================" << std::endl;
  std::cout << std::endl;

  NetworkMonitor monitor;

  // =====================================================
  // TEST 1: Get all connections
  // =====================================================
  std::cout << "📊 All Network Connections:" << std::endl;
  std::cout << "-------------------------------------------" << std::endl;

  auto all_flows = monitor.CollectFlows();
  std::cout << "Total connections: " << all_flows.size() << std::endl;
  std::cout << std::endl;

  // =====================================================
  // TEST 2: Show listening sockets (servers)
  // =====================================================
  std::cout << "🎧 Listening Sockets (Server Ports):" << std::endl;
  std::cout << "-------------------------------------------" << std::endl;

  auto listening = monitor.GetListeningSockets();
  std::cout << std::left << std::setw(20) << "Local Address" << std::setw(10)
            << "Port" << std::endl;
  std::cout << "-------------------------------------------" << std::endl;

  for (const auto &flow : listening) {
    std::cout << std::left << std::setw(20) << flow.local_ip << std::setw(10)
              << flow.local_port << std::endl;
  }
  std::cout << std::endl;

  // =====================================================
  // TEST 3: Show active connections
  // =====================================================
  std::cout << "🔗 Active Connections (ESTABLISHED):" << std::endl;
  std::cout << "-------------------------------------------" << std::endl;

  auto active = monitor.GetActiveConnections();
  std::cout << std::left << std::setw(8) << "Proto" << std::setw(22) << "Local"
            << std::setw(25) << "Remote" << std::setw(12) << "State"
            << std::endl;
  std::cout << "-------------------------------------------" << std::endl;

  for (const auto &flow : active) {
    std::string local = flow.local_ip + ":" + std::to_string(flow.local_port);
    std::string remote =
        flow.remote_ip + ":" + std::to_string(flow.remote_port);

    std::cout << std::left << std::setw(8) << flow.protocol << std::setw(22)
              << local << std::setw(25) << remote << std::setw(12) << flow.state
              << std::endl;
  }
  std::cout << std::endl;

  // =====================================================
  // TEST 4: Show syslog format (what we send to SIEM)
  // =====================================================
  std::cout << "📤 Sample Syslog Messages (first 5):" << std::endl;
  std::cout << "-------------------------------------------" << std::endl;

  int count = 0;
  for (const auto &flow : active) {
    if (count++ >= 5)
      break;
    std::cout << flow.ToSyslog() << std::endl;
  }
  std::cout << std::endl;

  // =====================================================
  // TEST 5: Statistics
  // =====================================================
  int tcp_count = 0, udp_count = 0;
  int established = 0, listen_count = 0;

  for (const auto &flow : all_flows) {
    if (flow.protocol == "TCP")
      tcp_count++;
    else
      udp_count++;

    if (flow.state == "ESTABLISHED")
      established++;
    else if (flow.state == "LISTEN")
      listen_count++;
  }

  std::cout << "📈 Statistics:" << std::endl;
  std::cout << "-------------------------------------------" << std::endl;
  std::cout << "  Total flows:    " << all_flows.size() << std::endl;
  std::cout << "  TCP:            " << tcp_count << std::endl;
  std::cout << "  UDP:            " << udp_count << std::endl;
  std::cout << "  ESTABLISHED:    " << established << std::endl;
  std::cout << "  LISTEN:         " << listen_count << std::endl;
  std::cout << std::endl;

  std::cout << "✅ Network Monitor working correctly!" << std::endl;

  return 0;
}
