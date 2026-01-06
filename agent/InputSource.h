#pragma once
#include <string>
#include <vector>

using namespace std;

/**
 * Interface for any log input source (File, EventLog, Journald, etc.)
 */
class InputSource {
public:
  virtual ~InputSource() = default;

  /**
   * Reads new lines available from this source since last read.
   * Should be non-blocking or return immediately if no data.
   */
  virtual vector<string> ReadNewLines() = 0;

  /**
   * Helper to get a descriptive name of the source (e.g. filename)
   */
  virtual string GetName() const = 0;
};
