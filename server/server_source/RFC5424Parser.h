#pragma once
#include "../SQL.lite_db/db.h"
#include <ctime>
#include <string>

using namespace std;

/**
 * Structura pentru datele extrase din mesajul RFC5424
 */
struct SyslogMessage {
  int facility;         // 0-23
  int severity;         // 0-7
  int version;          // ar trebui sa fie 1
  string timestamp_str; // String timestamp original
  string hostname;
  string app_name;
  string proc_id;
  string msg_id;
  string structured_data; // JSON raw string sau "-"
  string message;         // Mesajul propriu-zis
  bool parsed_ok;         // True daca parsing-ul partial a reusit
};

#include "Interfaces.h"

// ... (SyslogMessage struct remains) ...

class RFC5424Parser : public IDecoder {
public:
  // IDecoder implementation
  bool CanHandle(const string &raw_data) override;
  NormalizedEvent Decode(const string &raw_data, const string &src_ip) override;
  string GetName() const override { return "RFC5424Parser"; }

  // Static helper remains for manual usage
  static SyslogMessage Parse(const string &raw_message);

private:
  // Helpers
  static int ParsePRI(const string &pri_str);
  static void ExtractPRI(const string &raw, int &facility, int &severity,
                         size_t &cursor);
};
