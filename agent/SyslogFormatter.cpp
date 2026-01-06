#include "SyslogFormatter.h"
#include <ctime>
#include <iomanip>
#include <sstream>
#include <unistd.h>

// Helper for caching hostname
static string cached_hostname = "";

string SyslogFormatter::Format(const string &raw_message, const string &tag,
                               int severity) {
  // 1. Calculate PRI
  // Facility: 16 (local0), Severity: variable
  int facility = 16;
  int pri = (facility * 8) + severity;

  // 2. Timestamp (ISO 8601)
  string timestamp = GetISOTimestamp();

  // 3. Hostname
  if (cached_hostname.empty()) {
    cached_hostname = GetHostname();
  }

  // 4. App Name = tag

  // 5. ProcID
  int pid = GetPID();

  // 6. MsgID = -

  // 7. Structured Data = -

  // Format: <PRI>VER TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
  stringstream ss;
  ss << "<" << pri << ">1 " << timestamp << " " << cached_hostname << " " << tag
     << " " << pid << " "
     << "- "
     << "- " << raw_message;

  return ss.str();
}

string SyslogFormatter::GetISOTimestamp() {
  time_t now = time(nullptr);
  struct tm *t = localtime(&now);

  char buf[64];
  strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", t);

  // Add timezone offset manually or use simple format
  // For simplicity, we just use local time without offset info or assume +00:00
  // Z if needed But RFC5424 prefers full offset. Let's keep it simple:
  // YYYY-MM-DDTHH:MM:SS
  return string(buf);
}

string SyslogFormatter::GetHostname() {
  char hostname[1024];
  if (gethostname(hostname, sizeof(hostname)) == 0) {
    return string(hostname);
  }
  return "unknown-host";
}

int SyslogFormatter::GetPID() { return getpid(); }
