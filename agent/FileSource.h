#pragma once
#include "InputSource.h"
#include <fstream>
#include <string>

class FileSource : public InputSource {
public:
  FileSource(const string &filepath, const string &tag);
  ~FileSource();

  vector<string> ReadNewLines() override;
  string GetName() const override;
  string GetTag() const; // e.g. "nginx", "system", "auth"

private:
  string filepath;
  string tag;
  ifstream file;
  streampos last_pos;

  void ReopenFile();
};
