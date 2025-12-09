#include "Logic_Server.h"
#include <iostream>

using namespace std;

int main() {
  try {
    // Creeaza server: port 8080, minim 8 threaduri, maxim 128 threaduri
    Server server(8080, 8, 128);

    // Porneste serverul (blocheaza si ruleaza la infinit)
    server.Ruleaza();

  } catch (const exception &e) {
    cerr << "Eroare server: " << e.what() << endl;
    return 1;
  }

  return 0;
}