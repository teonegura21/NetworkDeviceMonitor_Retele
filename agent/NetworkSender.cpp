#include "NetworkSender.h"
#include <cstring>
#include <iostream>

NetworkSender::NetworkSender(const string &server_ip, int port,
                             TransportProtocol proto) {
  this->server_ip = server_ip;
  this->port = port;
  this->protocol = proto;
  this->sock = -1;
  this->connected = false;

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr);
}

NetworkSender::~NetworkSender() { Close(); }

void NetworkSender::Close() {
  if (sock >= 0) {
    close(sock);
    sock = -1;
  }
  connected = false;
}

bool NetworkSender::Connect() {
  if (connected)
    return true;

  if (protocol == UDP) {
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock >= 0)
      connected = true; // UDP is connectionless
  } else {
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
      if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) ==
          0) {
        connected = true;
      } else {
        Close();
      }
    }
  }

  return connected;
}

bool NetworkSender::Send(const string &message) {
  if (!Connect())
    return false;

  if (protocol == UDP) {
    int sent = sendto(sock, message.c_str(), message.length(), 0,
                      (struct sockaddr *)&server_addr, sizeof(server_addr));
    return sent == (int)message.length();
  } else {
    // TCP need to handle disconnection
    string packet = message + "\n"; // Framed with newline
    int sent = send(sock, packet.c_str(), packet.length(), 0);

    if (sent < 0) {
      // Error, try to reconnect once
      Close();
      if (Connect()) {
        sent = send(sock, packet.c_str(), packet.length(), 0);
      }
    }

    return sent == (int)packet.length();
  }
}
