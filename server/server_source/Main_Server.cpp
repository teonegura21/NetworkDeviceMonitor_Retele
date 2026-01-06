#include "Logic_Server.h"
#include "SyslogReceiver.h"
#include <iostream>

#include "ModuleManager.h"
#include "RFC5424Parser.h"

using namespace std;

int main() {
  try {

    // Initializeaza baza de date partajata
    ManagerBazaDate *db = new ManagerBazaDate("../SQL.lite_db/nms_romania.db");

    // Phase 5: Modularity - Register Components
    auto syslog_server = make_shared<SyslogReceiver>(514, db);
    ModuleManager::Instance().RegisterInput(syslog_server);

    auto rfc_parser = make_shared<RFC5424Parser>();
    ModuleManager::Instance().RegisterDecoder(rfc_parser);

    // VERIFICATION: Dummy Input Source to prove extensibility
    class TestInputSource : public IInputSource {
    public:
      void Start() override {
        cout << "[TestInputSource] ✅ STARTED (Managed by ModuleManager)"
             << endl;
      }
      void Stop() override { cout << "[TestInputSource] 🛑 STOPPED" << endl; }
      string GetName() const override { return "TestInputSource"; }
    };
    auto test_input = make_shared<TestInputSource>();
    ModuleManager::Instance().RegisterInput(test_input);

    // Start All Inputs
    ModuleManager::Instance().StartAll();

    // Note: SyslogReceiver uses RFC5424Parser internally logic still (Hybrid
    // approach for transition) Eventually SyslogReceiver should emit raw data
    // to ModuleManager::ProcessRaw

    // Creeaza server comenzi: port 8080, minim 8 threaduri, maxim 128 threaduri
    Server server(8080, 8, 128, db);

    // Porneste serverul (blocheaza si ruleaza la infinit)
    server.Ruleaza();

  } catch (const exception &e) {
    cerr << "Eroare server: " << e.what() << endl;
    return 1;
  }

  return 0;
}