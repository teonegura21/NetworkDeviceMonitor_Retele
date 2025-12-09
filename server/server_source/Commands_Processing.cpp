#include "Commands_Processing.h"
#include <iostream>
#include <sstream>

using namespace std;

// Recunoaste tipul comenzii din mesajul text (primul cuvant)
TipComanda ProcesorComenzi::RecunoasteTipComanda(const string &mesaj_text) {
  stringstream ss(mesaj_text);
  string tip;
  ss >> tip;

  if (tip == "REGISTER")
    return REGISTER;
  if (tip == "HEARTBEAT")
    return HEARTBEAT;
  if (tip == "BATCH_EVENT")
    return BATCH_EVENT;
  if (tip == "RESULTS")
    return RESULTS;
  if (tip == "COMMAND")
    return COMMAND;
  if (tip == "ACK")
    return ACK;

  return NECUNOSCUT;
}

// Proceseaza comanda REGISTER
// Format: REGISTER <versiune> <hostname> <os>
string ProcesorComenzi::ProceseazaREGISTER(const string &argumente,
                                           int socket_client,
                                           ManagerBazaDate *bd) {
  stringstream ss(argumente);
  string comanda, versiune, hostname, os;

  ss >> comanda >> versiune >> hostname >> os;

  cout << "📝 REGISTER primit de la socket " << socket_client << endl;
  cout << "   Versiune: " << versiune << endl;
  cout << "   Hostname: " << hostname << endl;
  cout << "   OS: " << os << endl;

  // Inregistram/Autentificam (Momentan doar verificam conexiunea cu DB)
  // Pentru simplitate, consideram ca 'hostname' este username-ul
  // Intr-o versiune viitoare, vom separa auth de register
  if (bd->Autentificare("admin", "admin")) {
    cout << "   [DB] Conexiune DB OK." << endl;
  }

  return GenereazaACK("OK", "Registration successful");
}

// Proceseaza comanda HEARTBEAT
// Format: HEARTBEAT <uptime_seconds>
string ProcesorComenzi::ProceseazaHEARTBEAT(const string &argumente,
                                            int socket_client,
                                            ManagerBazaDate *bd) {
  stringstream ss(argumente);
  string comanda;
  long uptime;

  ss >> comanda >> uptime;

  cout << "💓 HEARTBEAT primit de la socket " << socket_client << endl;
  cout << "   Uptime: " << uptime << "s" << endl;

  return GenereazaACK("OK", "Heartbeat received");
}

// Proceseaza comanda BATCH_EVENT
// Format: BATCH_EVENT <numar_evenimente> (restul sunt loguri, ignoram momentan)
string ProcesorComenzi::ProceseazaBATCH_EVENT(const string &argumente,
                                              int socket_client,
                                              ManagerBazaDate *bd) {
  cout << "📦 BATCH_EVENT primit de la socket " << socket_client << endl;

  // Salvam un log generic in baza de date
  bd->SalveazaLog("admin", "Batch event received from socket " +
                               to_string(socket_client));

  return GenereazaRESULTS("Processed events");
}

// Genereaza mesaj ACK
// Format: ACK <stare> <mesaj>
string ProcesorComenzi::GenereazaACK(const string &stare, const string &mesaj) {
  return "ACK " + stare + " " + mesaj;
}

// Genereaza mesaj RESULTS
string ProcesorComenzi::GenereazaRESULTS(const string &date) {
  return "RESULTS " + date;
}
