#include "Client.h"
#include <arpa/inet.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

using namespace std;

int main(int argc, char *argv[]) {
  string adresa = "127.0.0.1";
  int port = 8080;

  if (argc >= 2) {
    adresa = argv[1];
  }
  if (argc >= 3) {
    port = stoi(argv[2]);
  }

  Client client(adresa, port);

  if (!client.Conecteaza()) {
    return 1;
  }

  client.Ruleaza();

  return 0;
}
