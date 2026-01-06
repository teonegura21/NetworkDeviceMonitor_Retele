#pragma once
#include <arpa/inet.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

using namespace std;

enum TransportProtocol { UDP, TCP };

class NetworkSender {
public:
  NetworkSender(const string &server_ip, int port, TransportProtocol proto);
  ~NetworkSender();

  bool Send(const string &message);

private:
  string server_ip;
  int port;
  TransportProtocol protocol;
  int sock;
  struct sockaddr_in server_addr;
  bool connected;

  bool Connect();
  void Close();
};
