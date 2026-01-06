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
    // Auto-register unknown agents to admin 1? Or just log to admin 1?
    // Let's just log to admin 1 for now.
  }

  // 3. Store in Loguri (generic event)
  int event_id = db->SalveazaLogExtins(admin_id, msg.app_name, msg.message,
                                       src_ip, "syslog");

  // 4. Store extra details in syslog_rfc5424
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
