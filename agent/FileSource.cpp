#include "FileSource.h"
#include <filesystem>
#include <iostream>

using namespace std;

FileSource::FileSource(const string &filepath, const string &tag) {
  this->filepath = filepath;
  this->tag = tag;
  this->last_pos = 0;

  // Open initially and seek to end to only read NEW logs
  ReopenFile();
  if (file.is_open()) {
    file.seekg(0, ios::end);
    last_pos = file.tellg();
  }
}

FileSource::~FileSource() {
  if (file.is_open()) {
    file.close();
  }
}

string FileSource::GetName() const { return filepath; }

string FileSource::GetTag() const { return tag; }

void FileSource::ReopenFile() {
  if (file.is_open()) {
    file.close();
  }

  file.open(filepath, ios::in);
  if (!file.is_open()) {
    // File might not exist yet or permission denied
    return;
  }

  // Check if file was rotated (size became smaller than last_pos)
  file.seekg(0, ios::end);
  streampos current_size = file.tellg();

  if (current_size < last_pos) {
    last_pos = 0; // Reset for rotated file
  }

  file.seekg(last_pos);
}

vector<string> FileSource::ReadNewLines() {
  vector<string> lines;

  // Check if file exists, if not try to open
  if (!file.is_open()) {
    ReopenFile();
    if (!file.is_open())
      return lines;
  }

  // Refresh file state
  file.clear(); // Clear EOF flags

  // Check for rotation (inode check is better but size check is
  // simpler/portable) Here we just try to read

  string line;
  while (getline(file, line)) {
    if (!line.empty()) {
      lines.push_back(line);
    }
  }

  // Save position
  if (file.eof()) {
    file.clear();
    last_pos = file.tellg();
  } else if (file.good()) {
    last_pos = file.tellg();
  }

  return lines;
}
