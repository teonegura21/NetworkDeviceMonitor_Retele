#include "Interfaces.h"
// RFC5424Parser no longer strictly needed here if we decouple via Manager,
// but currently SyslogReceiver uses it directly or via db?
// Actually SyslogReceiver puts data into DB.
// Ideally SyslogReceiver should emit Events to a Pipeline.
// For Phase 5 step 1 (Refactor only), we keep logic but add Interface.
#include "RFC5424Parser.h"
#include <atomic>
#include <netinet/in.h>
#include <thread>
#include <vector>

using namespace std;

class SyslogReceiver : public IInputSource {
public:
  SyslogReceiver(int port, ManagerBazaDate *db);
  ~SyslogReceiver();

  // IInputSource implementation
  void Start() override;
  void Stop() override;
  string GetName() const override { return "SyslogReceiver TCP/UDP"; }

private:
  int port;
  ManagerBazaDate *db;
  atomic<bool> running;

  int udp_socket;
  int tcp_socket;

  thread udp_thread;
  thread tcp_thread;

  void UdpLoop();
  void TcpLoop();
  void HandleTcpConnection(int client_sock, sockaddr_in client_addr);

  void ProcessMessage(const string &raw_msg, const string &src_ip);
};
