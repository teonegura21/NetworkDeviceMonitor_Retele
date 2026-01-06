#pragma once
#include <string>

using namespace std;

class SyslogFormatter {
public:
  /**
   * Formats a raw log line into RFC5424 compliant string
   * @param raw_message The content of the log
   * @param tag The tag/app_name (e.g. "nginx", "system")
   * @param severity Syslog severity (default 6=info)
   * @return Formatted RFC5424 string (framed with \n for TCP streaming
   * compatibility)
   */
  static string Format(const string &raw_message, const string &tag,
                       int severity = 6);

private:
  static string GetISOTimestamp();
  static string GetHostname();
  static int GetPID();
};
