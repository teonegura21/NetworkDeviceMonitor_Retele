#ifndef INTERFACES_H
#define INTERFACES_H

#include "../SQL.lite_db/db.h" // For Event/RFC5424Data structs
#include <optional>
#include <string>
#include <vector>

using namespace std;

// ============================================================================
// IInputSource: Interface for data input sources (e.g., Syslog UDP, TCP, File)
// ============================================================================
class IInputSource {
public:
  virtual ~IInputSource() = default;

  // Start listening/polling
  virtual void Start() = 0;

  // Stop listening
  virtual void Stop() = 0;

  // Name of the source (for identification)
  virtual string GetName() const = 0;
};

// ============================================================================
// NormalizedEvent: Unified event structure passed inside the pipeline
// ============================================================================
struct NormalizedEvent {
  string raw_data;
  string source_ip;

  // Parsed fields
  optional<RFC5424Data> syslog_data;
  string message; // The main text content

  // Metadata
  long timestamp;
  int tenant_id; // Determined by Source Mapping
};

// ============================================================================
// IDecoder: Interface for parsing raw data into structured events
// ============================================================================
class IDecoder {
public:
  virtual ~IDecoder() = default;

  // Check if this decoder can handle the raw message
  virtual bool CanHandle(const string &raw_data) = 0;

  // Decode the data
  virtual NormalizedEvent Decode(const string &raw_data,
                                 const string &src_ip) = 0;

  // Decoder name
  virtual string GetName() const = 0;
};

// ============================================================================
// IFilter: Interface for filtering/enriching events
// ============================================================================
class IFilter {
public:
  virtual ~IFilter() = default;

  // Apply filter. Returns true to KEEP, false to DROP.
  virtual bool Apply(NormalizedEvent &event) = 0;

  virtual string GetName() const = 0;
};

#endif // INTERFACES_H
