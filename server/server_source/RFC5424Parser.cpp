#include "RFC5424Parser.h"
#include <iostream>
#include <sstream>
#include <vector>

using namespace std;

// Helper: extrage token delimitat de spatiu
string ExtractToken(const string &raw, size_t &cursor) {
  if (cursor >= raw.length())
    return "";

  size_t next_space = raw.find(' ', cursor);
  if (next_space == string::npos) {
    string token = raw.substr(cursor);
    cursor = raw.length();
    return token;
  }

  string token = raw.substr(cursor, next_space - cursor);
  cursor = next_space + 1;
  return token;
}

SyslogMessage RFC5424Parser::Parse(const string &raw_message) {
  SyslogMessage msg;
  msg.parsed_ok = false;
  msg.facility = 1; // user-level default
  msg.severity = 5; // notice default
  msg.version = 1;

  if (raw_message.empty())
    return msg;

  size_t cursor = 0;

  // 1. PRI Part: <123>
  if (raw_message[0] == '<') {
    size_t end_pri = raw_message.find('>');
    if (end_pri != string::npos && end_pri < 6) { // PRI max 3-5 chars
      string pri_str = raw_message.substr(1, end_pri - 1);
      int pri = stoi(pri_str);
      msg.facility = pri / 8;
      msg.severity = pri % 8;
      cursor = end_pri + 1;
    }
  }

  // 2. Version (RFC 5424 expects a version number immediately after PRI)
  // E.g. <134>1 2023...
  if (cursor < raw_message.length() && isdigit(raw_message[cursor])) {
    // Find next space
    string ver_token = ExtractToken(raw_message, cursor);
    try {
      msg.version = stoi(ver_token);
    } catch (...) {
      msg.version = 0;
    }
  }

  // 3. Timestamp
  msg.timestamp_str = ExtractToken(raw_message, cursor);

  // 4. Hostname
  msg.hostname = ExtractToken(raw_message, cursor);

  // 5. App-Name
  msg.app_name = ExtractToken(raw_message, cursor);

  // 6. ProcID
  msg.proc_id = ExtractToken(raw_message, cursor);

  // 7. MsgID
  msg.msg_id = ExtractToken(raw_message, cursor);

  // 8. Structured Data [id k="v"]... or -
  // This is complex because it can contain spaces inside quotes
  if (cursor < raw_message.length()) {
    if (raw_message[cursor] == '-') {
      msg.structured_data = "-";
      cursor += 2; // skip "- "
    } else if (raw_message[cursor] == '[') {
      // Read until we stop seeing [...] blocks
      size_t start_sd = cursor;
      bool inside_sd = true;
      while (inside_sd && cursor < raw_message.length()) {
        size_t end_bracket = raw_message.find(']', cursor);
        if (end_bracket == string::npos)
          break; // Invalid

        cursor = end_bracket + 1;
        if (cursor < raw_message.length() && raw_message[cursor] != '[') {
          inside_sd = false;
        }
      }
      msg.structured_data = raw_message.substr(start_sd, cursor - start_sd);
      if (cursor < raw_message.length() && raw_message[cursor] == ' ')
        cursor++;
    } else {
      // No SD match, unlikely if standard compliant but possible
      msg.structured_data = "-";
    }
  }

  // 9. Message (rest of the string)
  if (cursor < raw_message.length()) {
    msg.message = raw_message.substr(cursor);

    // Remove BOM if present (EF BB BF)
    if (msg.message.length() >= 3 && (unsigned char)msg.message[0] == 0xEF &&
        (unsigned char)msg.message[1] == 0xBB &&
        (unsigned char)msg.message[2] == 0xBF) {
      msg.message = msg.message.substr(3);
    }
  }

  msg.parsed_ok = true;
  return msg;
}

// IDecoder implementation
bool RFC5424Parser::CanHandle(const string &raw_data) {
  if (raw_data.empty())
    return false;
  // RFC5424 usually starts with <PRI>VER
  // Minimal check: starts with <
  return raw_data[0] == '<';
}

NormalizedEvent RFC5424Parser::Decode(const string &raw_data,
                                      const string &src_ip) {
  SyslogMessage msg = RFC5424Parser::Parse(raw_data);

  NormalizedEvent norm;
  norm.raw_data = raw_data;
  norm.source_ip = src_ip;
  norm.message = msg.message;
  norm.timestamp =
      time(nullptr); // Use current time if parsing fails or as default

  // Map RFC5424 fields to normalized struct
  RFC5424Data data;
  data.facility = msg.facility;
  data.severity = msg.severity;
  data.hostname = msg.hostname;
  data.app_name = msg.app_name;
  data.proc_id = msg.proc_id;
  data.msg_id = msg.msg_id;
  data.structured_data = msg.structured_data;
  data.parsed_ok = msg.parsed_ok;

  norm.syslog_data = data;
  norm.tenant_id = 0; // To be filled by filters/tenant mapper

  return norm;
}
