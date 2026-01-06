#include "FileSource.h"
#include "NetworkSender.h"
#include "SyslogFormatter.h"
#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

using namespace std;

// Configuration (could be loaded from file)
const string SERVER_IP = "127.0.0.1";
const int SERVER_PORT = 514;
const TransportProtocol PROTOCOL = TCP; // Use TCP for reliability

int main() {
  cout << "🔵 Starting NMS Agent..." << endl;
  cout << "   Target: " << SERVER_IP << ":" << SERVER_PORT
       << (PROTOCOL == TCP ? " (TCP)" : " (UDP)") << endl;

  // 1. Initialize Network Sender
  NetworkSender sender(SERVER_IP, SERVER_PORT, PROTOCOL);

  // 2. Initialize Inputs
  vector<InputSource *> sources;

  // Add common log files (adjust for specific system)
  // For demo purposes, we can monitor /var/log/syslog or creating a dummy file
  // Check if /var/log/syslog exists, otherwise use a local test file
  sources.push_back(new FileSource("/var/log/syslog", "syslog"));
  sources.push_back(new FileSource("/var/log/auth.log", "auth"));

  // Also monitor a test file for easy verification
  sources.push_back(new FileSource("./agent_test.log", "test-agent"));

  cout << "   Monitoring " << sources.size() << " sources." << endl;

  // 3. Main Loop
  while (true) {
    bool activity = false;

    for (auto source : sources) {
      vector<string> new_lines = source->ReadNewLines();

      if (!new_lines.empty()) {
        activity = true;
        // Get tag from source if it's a FileSource
        string tag = "app";
        FileSource *fs = dynamic_cast<FileSource *>(source);
        if (fs)
          tag = fs->GetTag();

        for (const auto &line : new_lines) {
          // Format and Send
          string rfc5424_msg = SyslogFormatter::Format(line, tag);

          if (sender.Send(rfc5424_msg)) {
            cout << "✓ Sent: " << line.substr(0, 50) << "..." << endl;
          } else {
            cerr << "❌ Send failed!" << endl;
          }
        }
      }
    }

    // Sleep to avoid high CPU usage
    this_thread::sleep_for(chrono::milliseconds(1000));
  }

  // Cleanup
  for (auto s : sources)
    delete s;
  return 0;
}
