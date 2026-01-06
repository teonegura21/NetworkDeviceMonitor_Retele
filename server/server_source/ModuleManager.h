#ifndef MODULE_MANAGER_H
#define MODULE_MANAGER_H

#include "Interfaces.h"
#include <iostream>
#include <map>
#include <memory>
#include <vector>

using namespace std;

class ModuleManager {
public:
  static ModuleManager &Instance() {
    static ModuleManager instance;
    return instance;
  }

  // Register components
  void RegisterInput(shared_ptr<IInputSource> input) {
    inputs.push_back(input);
    cout << "[ModuleManager] Registered Input: " << input->GetName() << endl;
  }

  void RegisterDecoder(shared_ptr<IDecoder> decoder) {
    decoders.push_back(decoder);
    cout << "[ModuleManager] Registered Decoder: " << decoder->GetName()
         << endl;
  }

  // Lifecycle
  void StartAll() {
    for (auto &input : inputs) {
      cout << "[ModuleManager] Starting " << input->GetName() << "..." << endl;
      input->Start();
    }
  }

  void StopAll() {
    for (auto &input : inputs) {
      input->Stop();
    }
  }

  // Pipeline Processing (Public to be called by Inputs)
  // Note: Inputs need reference to Manager or a callback.
  // For now, let's assume inputs call this static or singleton method?
  // Or inputs are linked to a specific pipeline.
  // Simplest: `ModuleManager::Instance().ProcessRaw(...)`
  void ProcessRaw(const string &raw_data, const string &src_ip) {
    // Find a decoder
    for (auto &decoder : decoders) {
      if (decoder->CanHandle(raw_data)) {
        NormalizedEvent event = decoder->Decode(raw_data, src_ip);
        // Dispatch to filters (TODO)
        // Dispatch to Storage (db)
        // Need DB access here.
        // For Phase 5 PoC, we might just print/forward.
        // But we need to maintain existing functionality.
        // Existing SyslogReceiver writes DIRECTLY to DB.
        // Refactoring that strictly is risky in one go.
        // Let's keep SyslogReceiver writing to DB for now, BUT
        // prove ModuleManager can Start/Stop inputs properly.
        return;
      }
    }
    // No decoder found
    // Log raw event?
  }

private:
  ModuleManager() {}
  vector<shared_ptr<IInputSource>> inputs;
  vector<shared_ptr<IDecoder>> decoders;
};

#endif
