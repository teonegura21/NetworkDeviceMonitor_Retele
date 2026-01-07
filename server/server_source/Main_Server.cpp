#include "Logic_Server.h"
#include "SyslogReceiver.h"
#include <iostream>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ModuleManager.h"
#include "RFC5424Parser.h"

using namespace std;

// Global PID for ML service child process
static pid_t ml_service_pid = 0;

// Signal handler for cleanup
void cleanup_handler(int signum) {
  if (ml_service_pid > 0) {
    cout << "\n🛑 Stopping ML service (PID: " << ml_service_pid << ")..."
         << endl;
    kill(ml_service_pid, SIGTERM);
    waitpid(ml_service_pid, nullptr, 0);
  }
  exit(0);
}

// Start ML service as background process
pid_t start_ml_service() {
  pid_t pid = fork();

  if (pid == 0) {
    // Child process - execute ML service via bash script
    chdir("../ml");

    // Use the run_service.sh script which activates venv properly
    if (access("run_service.sh", X_OK) == 0) {
      execl("/bin/bash", "bash", "run_service.sh", nullptr);
    } else if (access("ml_venv/bin/python3", X_OK) == 0) {
      // Direct venv python with PYTHONPATH
      setenv("PYTHONHOME", "", 1); // Clear any inherited PYTHONHOME
      execl("ml_venv/bin/python3", "ml_venv/bin/python3", "ml_service.py",
            nullptr);
    } else {
      // Fallback to system Python
      execlp("python3", "python3", "ml_service.py", nullptr);
    }

    // If exec fails
    cerr << "❌ Failed to start ML service" << endl;
    exit(1);
  } else if (pid > 0) {
    // Parent process
    cout << "🤖 ML Anomaly Detection service started (PID: " << pid << ")"
         << endl;
    return pid;
  } else {
    cerr << "❌ Failed to fork ML service process" << endl;
    return 0;
  }
}

int main() {
  try {
    // Setup signal handlers for cleanup
    signal(SIGINT, cleanup_handler);
    signal(SIGTERM, cleanup_handler);

    // Initializeaza baza de date partajata
    ManagerBazaDate *db = new ManagerBazaDate("../SQL.lite_db/nms_romania.db");

    // Start ML Anomaly Detection Service
    ml_service_pid = start_ml_service();

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
    if (ml_service_pid > 0) {
      kill(ml_service_pid, SIGTERM);
    }
    return 1;
  }

  return 0;
}