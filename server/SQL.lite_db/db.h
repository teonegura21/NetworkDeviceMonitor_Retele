#pragma once
#include <sqlite3.h>
#include <string>

class ManagerBazaDate {
private:
  sqlite3 *bd;
  void CreazaTabele();

public:
  ManagerBazaDate(const char *cale_bd);
  ~ManagerBazaDate();

  bool Autentificare(const std::string &utilizator, const std::string &parola);
  void SalveazaLog(const std::string &utilizator, const std::string &mesaj);
};
