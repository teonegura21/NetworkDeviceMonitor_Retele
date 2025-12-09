#include "db.h"
#include <iostream>
#include <string>

using namespace std;

ManagerBazaDate::ManagerBazaDate(const char *cale_bd) {
  if (sqlite3_open(cale_bd, &bd) != SQLITE_OK) {
    cerr << "Eroare la deschiderea Bazei de Date: " << sqlite3_errmsg(bd)
         << endl;
    bd = nullptr;
  } else {
    cout << "✓ Baza de date conectata: " << cale_bd << endl;
    CreazaTabele();
  }
}

ManagerBazaDate::~ManagerBazaDate() {
  if (bd) {
    sqlite3_close(bd);
    cout << "Baza de date inchisa." << endl;
  }
}

void ManagerBazaDate::CreazaTabele() {
  const char *interogare_sql = R"(
        CREATE TABLE IF NOT EXISTS Utilizatori (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nume_utilizator TEXT UNIQUE NOT NULL,
            parola TEXT NOT NULL
        );
        
        CREATE TABLE IF NOT EXISTS Loguri (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nume_utilizator TEXT,
            mesaj TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        -- Inseram un user default 'admin' / 'admin' daca nu exista
        INSERT OR IGNORE INTO Utilizatori (nume_utilizator, parola) VALUES ('admin', 'admin');
    )";

  char *mesaj_eroare;
  if (sqlite3_exec(bd, interogare_sql, nullptr, nullptr, &mesaj_eroare) !=
      SQLITE_OK) {
    cerr << "Eroare creare tabele: " << mesaj_eroare << endl;
    sqlite3_free(mesaj_eroare);
  } else {
    cout << "✓ Tabele verificate/create cu succes." << endl;
  }
}

bool ManagerBazaDate::Autentificare(const string &utilizator,
                                    const string &parola) {
  sqlite3_stmt *declaratie;
  const char *interogare_sql =
      "SELECT id FROM Utilizatori WHERE nume_utilizator = ? AND parola = ?";

  if (sqlite3_prepare_v2(bd, interogare_sql, -1, &declaratie, nullptr) !=
      SQLITE_OK) {
    return false;
  }

  sqlite3_bind_text(declaratie, 1, utilizator.c_str(), -1, SQLITE_STATIC);
  sqlite3_bind_text(declaratie, 2, parola.c_str(), -1, SQLITE_STATIC);

  bool succes = false;
  if (sqlite3_step(declaratie) == SQLITE_ROW) {
    succes = true; // Utilizator gasit
    cout << "Utilizator '" << utilizator << "' autentificat." << endl;
  }

  sqlite3_finalize(declaratie);
  return succes;
}

void ManagerBazaDate::SalveazaLog(const string &utilizator,
                                  const string &mesaj) {
  sqlite3_stmt *declaratie;
  const char *interogare_sql =
      "INSERT INTO Loguri (nume_utilizator, mesaj) VALUES (?, ?)";

  if (sqlite3_prepare_v2(bd, interogare_sql, -1, &declaratie, nullptr) ==
      SQLITE_OK) {
    sqlite3_bind_text(declaratie, 1, utilizator.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(declaratie, 2, mesaj.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(declaratie) != SQLITE_DONE) {
      cerr << "Eroare la salvare log: " << sqlite3_errmsg(bd) << endl;
    }
    sqlite3_finalize(declaratie);
  }
}