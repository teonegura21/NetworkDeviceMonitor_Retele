#pragma once
#include "../SQL.lite_db/db.h"
#include <string>

using namespace std;

// Tipuri de comenzi posibile
enum TipComanda {
  REGISTER,
  HEARTBEAT,
  BATCH_EVENT,
  RESULTS,
  COMMAND,
  ACK,
  NECUNOSCUT
};

class ProcesorComenzi {
public:
  // Recunoaste tipul de comanda din mesajul text (primul cuvant)
  static TipComanda RecunoasteTipComanda(const string &mesaj_text);

  // Proceseaza fiecare tip de comanda (input string -> output string)
  // Acum primesc si pointer la Baza de Date pentru a face verificari/salvari
  static string ProceseazaREGISTER(const string &argumente, int socket_client,
                                   ManagerBazaDate *bd);
  static string ProceseazaHEARTBEAT(const string &argumente, int socket_client,
                                    ManagerBazaDate *bd);
  static string ProceseazaBATCH_EVENT(const string &argumente,
                                      int socket_client, ManagerBazaDate *bd);

  // Genereaza raspunsuri text
  static string GenereazaACK(const string &stare, const string &mesaj);
  static string GenereazaRESULTS(const string &date);
};
