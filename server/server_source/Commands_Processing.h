#pragma once
#include "../SQL.lite_db/db.h"
#include <string>

using namespace std;

// Tipuri de comenzi posibile
enum TipComanda {
  LOGIN,
  REGISTER,
  HEARTBEAT,
  BATCH_EVENT,
  QUERY_EVENTS,        // NEW: Query last N events
  CREATE_USER,         // NEW: Create a new user (admin only)
  PROMOTE_USER,        // NEW: Promote user to admin (admin only)
  QUERY_METRICS,       // NEW: Query metrics for dashbaord
  QUERY_ALERTS,        // NEW: Query ML alerts
  QUERY_NETWORK_FLOWS, // NEW: Query network flow data
  LIST_USERS,          // NEW: List users under admin
  DELETE_USER,         // NEW: Delete a user
  LIST_AGENTS,         // NEW: List registered agents
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
  static string ProceseazaLOGIN(const string &argumente, int socket_client,
                                ManagerBazaDate *bd);
  static string ProceseazaREGISTER(const string &argumente, int socket_client,
                                   ManagerBazaDate *bd);
  static string ProceseazaHEARTBEAT(const string &argumente, int socket_client,
                                    ManagerBazaDate *bd);
  static string ProceseazaBATCH_EVENT(const string &argumente,
                                      int socket_client, ManagerBazaDate *bd);

  // NEW: Query events with modular parameters
  // Format: QUERY_EVENTS <username> <limit> [event_type=X] [since=timestamp]
  static string ProceseazaQUERY_EVENTS(const string &argumente,
                                       int socket_client, ManagerBazaDate *bd);

  // NEW: Create a new user (admin only)
  // Format: CREATE_USER <admin_username> <new_username> <new_password> [role]
  static string ProceseazaCREATE_USER(const string &argumente,
                                      int socket_client, ManagerBazaDate *bd);

  // NEW: Promote a user to admin (admin only)
  // Format: PROMOTE_USER <admin_username> <target_username>
  static string ProceseazaPROMOTE_USER(const string &argumente,
                                       int socket_client, ManagerBazaDate *bd);

  // NEW: Query metrics
  // Format: QUERY_METRICS <username> <metric_type>
  static string ProceseazaQUERY_METRICS(const string &argumente,
                                        int socket_client, ManagerBazaDate *bd);

  // NEW: Query alerts
  // Format: QUERY_ALERTS <username> <limit> [state]
  static string ProceseazaQUERY_ALERTS(const string &argumente,
                                       int socket_client, ManagerBazaDate *bd);

  // NEW: Query network flows
  // Format: QUERY_NETWORK_FLOWS <username> <limit> [protocol]
  static string ProceseazaQUERY_NETWORK_FLOWS(const string &argumente,
                                              int socket_client,
                                              ManagerBazaDate *bd);

  // NEW: List users under admin
  // Format: LIST_USERS <admin_username>
  static string ProceseazaLIST_USERS(const string &argumente, int socket_client,
                                     ManagerBazaDate *bd);

  // NEW: Delete a user
  // Format: DELETE_USER <admin_username> <target_username>
  static string ProceseazaDELETE_USER(const string &argumente,
                                      int socket_client, ManagerBazaDate *bd);

  // NEW: List registered agents
  // Format: LIST_AGENTS <admin_username>
  static string ProceseazaLIST_AGENTS(const string &argumente,
                                      int socket_client, ManagerBazaDate *bd);

  // Genereaza raspunsuri text
  static string GenereazaACK(const string &stare, const string &mesaj);
  static string GenereazaRESULTS(const string &date);
};
