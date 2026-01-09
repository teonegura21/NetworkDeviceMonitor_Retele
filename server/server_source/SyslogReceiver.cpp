#include "SyslogReceiver.h"
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <sstream>
#include <sys/socket.h>
#include <unistd.h>

#define BUFFER_SIZE 4096

SyslogReceiver::SyslogReceiver(int port, ManagerBazaDate *db) {
  this->port = port;
  this->db = db;
  this->running = false;
  this->udp_socket = -1;
  this->tcp_socket = -1;
}

SyslogReceiver::~SyslogReceiver() { Stop(); }

void SyslogReceiver::Start() {
  if (running)
    return;
  running = true;

  // --- UDP Setup ---
  udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
  if (udp_socket >= 0) {
    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(udp_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
      cerr << "❌ Syslog UDP Bind Failed on port " << port << endl;
      close(udp_socket);
      udp_socket = -1;
    } else {
      cout << "✓ Syslog UDP listening on port " << port << endl;
      udp_thread = thread(&SyslogReceiver::UdpLoop, this);
    }
  }

  // --- TCP Setup ---
  tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
  if (tcp_socket >= 0) {
    int opt = 1;
    setsockopt(tcp_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(tcp_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
      cerr << "❌ Syslog TCP Bind Failed on port " << port << endl;
      close(tcp_socket);
      tcp_socket = -1;
    } else {
      listen(tcp_socket, 5);
      cout << "✓ Syslog TCP listening on port " << port << endl;
      tcp_thread = thread(&SyslogReceiver::TcpLoop, this);
    }
  }
}

void SyslogReceiver::Stop() {
  running = false;

  if (udp_socket >= 0) {
    close(udp_socket);
    udp_socket = -1;
  }
  if (tcp_socket >= 0) {
    close(tcp_socket);
    tcp_socket = -1;
  }

  if (udp_thread.joinable())
    udp_thread.join();
  if (tcp_thread.joinable())
    tcp_thread.join();
}

void SyslogReceiver::UdpLoop() {
  char buffer[BUFFER_SIZE];
  sockaddr_in client_addr;
  socklen_t addr_len = sizeof(client_addr);

  while (running && udp_socket >= 0) {
    memset(buffer, 0, BUFFER_SIZE);
    int received = recvfrom(udp_socket, buffer, BUFFER_SIZE - 1, 0,
                            (struct sockaddr *)&client_addr, &addr_len);

    if (received > 0) {
      string src_ip = inet_ntoa(client_addr.sin_addr);
      string raw_msg(buffer);
      ProcessMessage(raw_msg, src_ip);
    }
  }
}

void SyslogReceiver::TcpLoop() {
  while (running && tcp_socket >= 0) {
    sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    int client_sock =
        accept(tcp_socket, (struct sockaddr *)&client_addr, &addr_len);
    if (client_sock >= 0) {
      // Detach a thread for each TCP connection (simple approach) or handle in
      // a loop
      thread client_handler(&SyslogReceiver::HandleTcpConnection, this,
                            client_sock, client_addr);
      client_handler.detach();
    }
  }
}

void SyslogReceiver::HandleTcpConnection(int client_sock,
                                         sockaddr_in client_addr) {
  char buffer[BUFFER_SIZE];
  string src_ip = inet_ntoa(client_addr.sin_addr);

  // Simple TCP syslog: usually one message per packet, or \n delimited
  // For simplicity here, we assume one packet = one or more messages
  while (running) {
    memset(buffer, 0, BUFFER_SIZE);
    int received = recv(client_sock, buffer, BUFFER_SIZE - 1, 0);

    if (received <= 0)
      break; // Disconnect

    string raw_msg(buffer);
    // Split by newline if multiple messages came in one packet
    stringstream ss(raw_msg);
    string segment;
    while (getline(ss, segment)) {
      if (!segment.empty()) {
        ProcessMessage(segment, src_ip);
      }
    }
  }
  close(client_sock);
}

void SyslogReceiver::ProcessMessage(const string &raw_msg,
                                    const string &src_ip) {
  // 1. Parse using RFC5424Parser
  SyslogMessage msg = RFC5424Parser::Parse(raw_msg);

  // 2. Determine admin_id based on source IP or hostname?
  // For now, default to admin (1) or lookup agent in DB?
  // Let's lookup agent by src_ip/hostname to find the owner admin
  int admin_id = 1; // Default
  auto agent = db->GetAgentByHost(msg.hostname, src_ip);
  if (agent.has_value()) {
    admin_id = agent->admin_id;
    db->UpdateAgentHeartbeat(agent->id);
  } else {
    // Agent not found - Auto-Register it!
    cout << "🆕 Auto-registering new agent: " << msg.hostname << " (" << src_ip
         << ")" << endl;
    // Default to admin_id=1, name=hostname, os=Unknown, version=1.0
    db->RegisterAgent(1, msg.hostname, msg.hostname, "Unknown", "1.0", src_ip);

    // Refresh to get the new ID
    agent = db->GetAgentByHost(msg.hostname, src_ip);
    if (agent.has_value()) {
      admin_id = agent->admin_id;
    }
  }

  // 3. Check for specialized message types (NETWORK_FLOW, PORT_SCAN)
  if (msg.message.find("NETWORK_FLOW:") != string::npos) {
    // Parse: "NETWORK_FLOW: TCP 192.168.1.17:443 -> 8.8.8.8:443
    // state=ESTABLISHED"
    string protocol = "TCP";
    string local_addr = "0.0.0.0";
    int local_port = 0;
    string remote_addr = "0.0.0.0";
    int remote_port = 0;
    string state = "UNKNOWN";

    size_t pos = msg.message.find("NETWORK_FLOW: ");
    if (pos != string::npos) {
      string data = msg.message.substr(pos + 14);
      stringstream ss(data);
      string local_full, arrow, remote_full;

      ss >> protocol >> local_full >> arrow >> remote_full;

      // Parse local addr:port
      size_t colon = local_full.rfind(':');
      if (colon != string::npos) {
        local_addr = local_full.substr(0, colon);
        try {
          local_port = stoi(local_full.substr(colon + 1));
        } catch (...) {
        }
      }

      // Parse remote addr:port
      colon = remote_full.rfind(':');
      if (colon != string::npos) {
        remote_addr = remote_full.substr(0, colon);
        try {
          remote_port = stoi(remote_full.substr(colon + 1));
        } catch (...) {
        }
      }

      // Parse state=XXX
      size_t state_pos = msg.message.find("state=");
      if (state_pos != string::npos) {
        state = msg.message.substr(state_pos + 6);
        size_t end = state.find_first_of(" \n\r");
        if (end != string::npos)
          state = state.substr(0, end);
      }
    }

    // Store in NetworkFlows table
    db->StoreNetworkFlow(admin_id, msg.hostname, protocol, local_addr,
                         local_port, remote_addr, remote_port, state, "");
    return; // Don't also store in Loguri
  }

  if (msg.message.find("PORT_SCAN_DETECTED:") != string::npos) {
    // Parse port scan alert and create alert
    // Format: "PORT_SCAN_DETECTED: type=TCP_SYN src=10.0.0.99 ports=11
    // severity=HIGH"
    string scan_type = "TCP_CONNECT";
    string source_ip = "unknown";
    int ports = 0;
    int severity = 3; // Default medium

    // Simple parsing - find key=value pairs
    size_t pos;
    if ((pos = msg.message.find("type=")) != string::npos) {
      size_t end = msg.message.find(' ', pos);
      scan_type = msg.message.substr(pos + 5, end - pos - 5);
    }
    if ((pos = msg.message.find("src=")) != string::npos) {
      size_t end = msg.message.find(' ', pos);
      source_ip = msg.message.substr(pos + 4, end - pos - 4);
    }
    if ((pos = msg.message.find("ports=")) != string::npos) {
      size_t end = msg.message.find(' ', pos);
      string ports_str = msg.message.substr(pos + 6, end - pos - 6);
      try {
        ports = stoi(ports_str);
      } catch (...) {
      }
    }
    if (msg.message.find("severity=HIGH") != string::npos)
      severity = 1;
    else if (msg.message.find("severity=MEDIUM") != string::npos)
      severity = 3;
    else if (msg.message.find("severity=LOW") != string::npos)
      severity = 5;

    // Create port scan alert
    db->CreatePortScanAlert(admin_id, source_ip, scan_type, "", ports, 0,
                            severity);

    cout << "🚨 PORT SCAN ALERT: " << source_ip << " (" << scan_type << ", "
         << ports << " ports)" << endl;
    return;
  }

  // 4. Store regular messages in Loguri (generic event)
  int event_id = db->SalveazaLogExtins(admin_id, msg.app_name, msg.message,
                                       src_ip, "syslog");

  // 5. Store extra details in syslog_rfc5424
  RFC5424Data data;
  data.facility = msg.facility;
  data.severity = msg.severity;
  data.hostname = msg.hostname;
  data.app_name = msg.app_name;
  data.proc_id = msg.proc_id;
  data.msg_id = msg.msg_id;
  data.structured_data = msg.structured_data;
  data.parsed_ok = msg.parsed_ok;

  db->SalveazaRFC5424(event_id, data);

  cout << "📨 Syslog parsed (Fac:" << msg.facility << " Sev:" << msg.severity
       << ") from " << src_ip << " [" << msg.app_name << "]" << endl;
}
