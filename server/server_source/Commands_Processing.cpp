#include "Commands_Processing.h"
#include <iostream>
#include <sstream>
#include <vector>

using namespace std;

// ============================================================================
// Recunoaste tipul comenzii din mesajul text (primul cuvant)
// ============================================================================
TipComanda ProcesorComenzi::RecunoasteTipComanda(const string &mesaj_text) {
  stringstream ss(mesaj_text);
  string tip;
  ss >> tip;

  if (tip == "LOGIN")
    return LOGIN;
  if (tip == "REGISTER")
    return REGISTER;
  if (tip == "HEARTBEAT")
    return HEARTBEAT;
  if (tip == "BATCH_EVENT")
    return BATCH_EVENT;
  if (tip == "QUERY_EVENTS")
    return QUERY_EVENTS;
  if (tip == "CREATE_USER")
    return CREATE_USER;
  if (tip == "PROMOTE_USER")
    return PROMOTE_USER;
  if (tip == "QUERY_METRICS")
    return QUERY_METRICS;
  if (tip == "QUERY_ALERTS")
    return QUERY_ALERTS;
  if (tip == "QUERY_NETWORK_FLOWS")
    return QUERY_NETWORK_FLOWS;
  if (tip == "LIST_USERS")
    return LIST_USERS;
  if (tip == "DELETE_USER")
    return DELETE_USER;
  if (tip == "LIST_AGENTS")
    return LIST_AGENTS;
  if (tip == "RESULTS")
    return RESULTS;
  if (tip == "COMMAND")
    return COMMAND;
  if (tip == "ACK")
    return ACK;

  return NECUNOSCUT;
}

// ============================================================================
// LOGIN - Authenticate user
// Format: LOGIN <username> <password>
// ============================================================================
string ProcesorComenzi::ProceseazaLOGIN(const string &argumente,
                                        int socket_client,
                                        ManagerBazaDate *bd) {
  stringstream ss(argumente);
  string comanda, username, password;

  ss >> comanda >> username >> password;

  cout << "🔐 LOGIN incercare de la socket " << socket_client << endl;
  cout << "   Username: " << username << endl;

  // Verificam credentialele in baza de date
  if (bd->Autentificare(username, password)) {
    string role = bd->GetUserRole(username);
    cout << "   ✅ Autentificare REUSITA pentru " << username
         << " (role: " << role << ")" << endl;
    return GenereazaACK("OK", "Login successful role=" + role);
  } else {
    cout << "   ❌ Autentificare ESUATA pentru " << username << endl;
    return GenereazaACK("FAIL", "Invalid credentials");
  }
}

// ============================================================================
// REGISTER - Register an agent for an admin
// Format: REGISTER <username> <version> <hostname> <os>
// ============================================================================
string ProcesorComenzi::ProceseazaREGISTER(const string &argumente,
                                           int socket_client,
                                           ManagerBazaDate *bd) {
  stringstream ss(argumente);
  string comanda, username, versiune, hostname, os;

  ss >> comanda >> username >> versiune >> hostname >> os;

  cout << "📝 REGISTER primit de la socket " << socket_client << endl;
  cout << "   Username: " << username << endl;
  cout << "   Versiune: " << versiune << endl;
  cout << "   Hostname: " << hostname << endl;
  cout << "   OS: " << os << endl;

  // Get admin_id for this user
  int admin_id = bd->GetAdminIdForUser(username);
  if (admin_id < 0) {
    // User doesn't exist, default to admin 1
    admin_id = 1;
  }

  // Register agent in database
  int agent_id =
      bd->RegisterAgent(admin_id, hostname, hostname, os, versiune, "");

  if (agent_id > 0) {
    cout << "   ✅ Agent inregistrat cu ID: " << agent_id << endl;
    return GenereazaACK("OK", "Registration successful agent_id=" +
                                  to_string(agent_id));
  } else {
    return GenereazaACK("FAIL", "Registration failed");
  }
}

// ============================================================================
// HEARTBEAT - Update agent last_seen
// Format: HEARTBEAT <hostname> <uptime_seconds>
// ============================================================================
string ProcesorComenzi::ProceseazaHEARTBEAT(const string &argumente,
                                            int socket_client,
                                            ManagerBazaDate *bd) {
  stringstream ss(argumente);
  string comanda, hostname;
  long uptime;

  ss >> comanda >> hostname >> uptime;

  cout << "💓 HEARTBEAT primit de la socket " << socket_client << endl;
  cout << "   Hostname: " << hostname << endl;
  cout << "   Uptime: " << uptime << "s" << endl;

  // Update agent heartbeat
  bd->UpdateAgentHeartbeatByHost(hostname, "");

  return GenereazaACK("OK", "Heartbeat received");
}

// ============================================================================
// BATCH_EVENT - Store a log event
// Format: BATCH_EVENT <username> <log_message>
// ============================================================================
string ProcesorComenzi::ProceseazaBATCH_EVENT(const string &argumente,
                                              int socket_client,
                                              ManagerBazaDate *bd) {
  // Extragem mesajul de log din argumente
  stringstream ss(argumente);
  string comanda, username, log_mesaj;
  ss >> comanda >> username;
  getline(ss, log_mesaj); // Restul liniei este mesajul de log

  // Curatam spatiul de la inceput
  if (!log_mesaj.empty() && log_mesaj[0] == ' ') {
    log_mesaj = log_mesaj.substr(1);
  }

  // If no username provided, default to "admin"
  if (username.empty()) {
    username = "admin";
  }

  cout << "📦 BATCH_EVENT primit de la socket " << socket_client << endl;

  // Get admin_id for this user
  int admin_id = bd->GetAdminIdForUser(username);
  if (admin_id < 0)
    admin_id = 1; // Default to admin 1

  // Salvam log-ul extins in baza de date
  int event_id =
      bd->SalveazaLogExtins(admin_id, username, log_mesaj, "", "batch_event");

  if (event_id > 0) {
    return GenereazaACK("OK", "Event received id=" + to_string(event_id));
  } else {
    return GenereazaACK("FAIL", "Event save failed");
  }
}

// ============================================================================
// QUERY_EVENTS - Get last N events (modular query)
// Format: QUERY_EVENTS <username> <limit> [event_type=X] [since=timestamp]
// ============================================================================
string ProcesorComenzi::ProceseazaQUERY_EVENTS(const string &argumente,
                                               int socket_client,
                                               ManagerBazaDate *bd) {
  stringstream ss(argumente);
  string comanda, username;
  int limit = 25; // Default limit

  ss >> comanda >> username >> limit;

  // Parse optional filters (event_type=X, since=timestamp)
  optional<EventFilter> filter = nullopt;
  string token;
  while (ss >> token) {
    if (token.find("event_type=") == 0) {
      EventFilter f;
      f.event_type = token.substr(11);
      filter = f;
    } else if (token.find("since=") == 0) {
      EventFilter f = filter.value_or(EventFilter{});
      f.since_timestamp = stol(token.substr(6));
      filter = f;
    }
  }

  // Get admin_id for user
  int admin_id = bd->GetAdminIdForUser(username);
  if (admin_id < 0) {
    return GenereazaACK("FAIL", "User not found");
  }

  // Query events
  vector<Event> events = bd->GetLastNEvents(admin_id, limit, filter);

  // Format results as simple text (one event per line)
  stringstream result;
  result << "count=" << events.size() << ";";

  for (const auto &e : events) {
    // Format: id|timestamp|type|message (escape pipes in message)
    string msg = e.message;
    // Truncate message if too long
    if (msg.length() > 100) {
      msg = msg.substr(0, 100) + "...";
    }
    // Replace newlines and pipes
    for (char &c : msg) {
      if (c == '|' || c == '\n' || c == '\r')
        c = ' ';
    }
    // Format: id|timestamp|src_ip|event_type|message
    string src = e.src_ip.empty() ? "unknown" : e.src_ip;
    result << e.id << "|" << e.timestamp << "|" << src << "|" << e.event_type
           << "|" << msg << ";";
  }

  // Single concise log line
  cout << "📋 QUERY_EVENTS: " << username << " -> " << events.size()
       << " events" << endl;
  return GenereazaRESULTS(result.str());
}

// ============================================================================
// CREATE_USER - Create a new user (admin only)
// Format: CREATE_USER <admin_username> <new_username> <new_password> [role]
// ============================================================================
string ProcesorComenzi::ProceseazaCREATE_USER(const string &argumente,
                                              int socket_client,
                                              ManagerBazaDate *bd) {
  stringstream ss(argumente);
  string comanda, admin_username, new_username, new_password, role;

  ss >> comanda >> admin_username >> new_username >> new_password >> role;

  if (role.empty()) {
    role = "user"; // Default role
  }

  cout << "👤 CREATE_USER primit de la socket " << socket_client << endl;
  cout << "   Admin: " << admin_username << endl;
  cout << "   New User: " << new_username << endl;
  cout << "   Role: " << role << endl;

  // 1. Verify admin has admin role
  string admin_role = bd->GetUserRole(admin_username);
  if (admin_role != "admin") {
    cout << "   ❌ Acces refuzat - nu esti admin! (" << admin_username << ")"
         << endl;
    return GenereazaACK("FAIL", "Access denied - admin role required");
  }

  // 2. Get admin's id (owner of the new user)
  // If admin is "super-admin" (admin_id=NULL or 1), they own the user.
  int admin_id = bd->GetAdminIdForUser(admin_username);
  // Correction: If admin_username is an admin, they might map to themselves or
  // NULL? Our DB logic: 'admin' has id=1, role='admin', admin_id=NULL.
  // bd->GetAdminIdForUser returns the parent.
  // If I am admin, I should be the parent. But GetAdminIdForUser returns MY
  // parent (NULL). So we need to resolve MY id to assign to child.

  // Let's resolve the ID of the `admin_username` directly
  // We don't have GetUserIdByName exposed, but GetUser returns User struct
  // object Let's assume we can fetch user details. Actually `GetAdminIdForUser`
  // returns who manages me. If I am main admin, NULL manages me. But I want MY
  // ID to be the parent. We need `bd->GetUser(admin_username).id`.

  optional<User> admin_obj = bd->GetUser(admin_username);
  if (!admin_obj) {
    return GenereazaACK("FAIL", "Admin user not found");
  }

  // Check if trying to create another admin?
  if (role == "admin" && admin_obj->admin_id != 0 && admin_obj->admin_id != 1) {
    // Maybe restricting sub-admins from creating admins?
    // For now, allow it.
  }

  // Create the new user assigned to THIS admin (admin_obj->id)
  int new_user_id =
      bd->CreateUser(new_username, new_password, role, admin_obj->id);

  if (new_user_id > 0) {
    cout << "   ✅ Utilizator creat cu ID: " << new_user_id << endl;
    return GenereazaACK("OK", "User created id=" + to_string(new_user_id));
  } else {
    cout << "   ❌ Eroare la crearea utilizatorului" << endl;
    return GenereazaACK("FAIL", "User creation failed");
  }
}

// ============================================================================
// PROMOTE_USER - Promote user to admin
// Format: PROMOTE_USER <admin_username> <target_username>
// ============================================================================
string ProcesorComenzi::ProceseazaPROMOTE_USER(const string &argumente,
                                               int socket_client,
                                               ManagerBazaDate *bd) {
  stringstream ss(argumente);
  string comanda, admin_username, target_username;

  ss >> comanda >> admin_username >> target_username;

  cout << "👑 PROMOTE_USER primit de la socket " << socket_client << endl;
  cout << "   Admin: " << admin_username << endl;
  cout << "   Target: " << target_username << endl;

  // 1. Verify requester is admin
  string admin_role = bd->GetUserRole(admin_username);
  if (admin_role != "admin") {
    return GenereazaACK("FAIL", "Access denied - you are not admin");
  }

  // 2. Verify target exists and is assigned to this admin (Isolation Check)
  // Get admin object to check ID
  optional<User> admin_obj = bd->GetUser(admin_username);
  if (!admin_obj)
    return GenereazaACK("FAIL", "Admin not found");

  // Allow promotion ONLY if target is managed by this admin
  // Exception: 'admin' (id 1) can promote anyone?
  // Let's enforce strict ownership:
  if (!bd->IsUserAssignedToAdmin(target_username, admin_obj->id) &&
      admin_obj->id != 1) {
    return GenereazaACK("FAIL", "Target user not assigned to you");
  }

  // 3. Promote
  if (bd->PromoteUserToAdmin(target_username)) {
    cout << "   ✅ User " << target_username << " promovat la ADMIN" << endl;
    return GenereazaACK("OK", "User promoted to admin");
  } else {
    return GenereazaACK("FAIL", "Promotion failed");
  }
}

// ============================================================================
// QUERY_METRICS - Get metrics for dashboard
// Format: QUERY_METRICS <username> <metric_type>
// Types: events_over_time, severity_dist, top_sources
// ============================================================================
string ProcesorComenzi::ProceseazaQUERY_METRICS(const string &argumente,
                                                int socket_client,
                                                ManagerBazaDate *bd) {
  stringstream ss(argumente);
  string comanda, username, metric_type;

  ss >> comanda >> username >> metric_type;

  // Single concise log (only on first call or errors)

  // Authorization Logic
  // 1. Resolve to admin_id (for Isolation)
  int admin_id = bd->GetAdminIdForUser(username);
  if (admin_id < 0)
    return GenereazaACK("FAIL", "User not found");

  string role = bd->GetUserRole(username);
  if (role == "admin") {
    // If I am admin, I need my OWN id.
    auto user_obj = bd->GetUser(username);
    if (user_obj)
      admin_id = user_obj->id;
  }

  vector<string> data;

  if (metric_type == "events_over_time") {
    data = bd->GetEventsOverTime(admin_id);
  } else if (metric_type == "severity_dist") {
    data = bd->GetSeverityDistribution(admin_id);
  } else if (metric_type == "top_sources") {
    data = bd->GetTopSources(admin_id);
  } else {
    return GenereazaACK("FAIL", "Unknown metric type");
  }

  // Format results: RESULTS count=N;val1;val2...
  stringstream result;
  result << "count=" << data.size() << ";";
  for (const auto &item : data) {
    result << item << ";";
  }

  return GenereazaRESULTS(result.str());
}

// ============================================================================
// Response Generators
// ============================================================================

// Genereaza mesaj ACK
// Format: ACK <stare> <mesaj>
string ProcesorComenzi::GenereazaACK(const string &stare, const string &mesaj) {
  return "ACK " + stare + " " + mesaj;
}

// Genereaza mesaj RESULTS
string ProcesorComenzi::GenereazaRESULTS(const string &date) {
  return "RESULTS " + date;
}
// QUERY_ALERTS handler - add this to Commands_Processing.cpp

/**
 * QUERY_ALERTS command
 * Format: QUERY_ALERTS <username> <limit> [state]
 * Returns alerts for the user's admin
 */
string ProcesorComenzi::ProceseazaQUERY_ALERTS(const string &argumente,
                                               int socket_client,
                                               ManagerBazaDate *bd) {
  stringstream ss(argumente);
  string comanda, username, state_filter;
  int limit = 50;

  ss >> comanda >> username >> limit;

  // Optional state filter
  if (ss >> state_filter) {
    // state_filter has value
  } else {
    state_filter = ""; // All states
  }

  // Get admin_id for this user
  int admin_id = bd->GetAdminIdForUser(username);
  if (admin_id == -1) {
    return GenereazaACK("EROARE", "User not found");
  }

  // Query alerts
  vector<Alert> alerts = bd->GetRecentAlerts(admin_id, limit, state_filter);

  // Format:
  // count=N;id|created_at|rule_id|severity|state|ml_score|src_ip|message;...
  stringstream result;
  result << "count=" << alerts.size() << ";";

  for (const auto &alert : alerts) {
    result << alert.id << "|" << alert.created_at << "|" << alert.rule_id << "|"
           << alert.severity << "|" << alert.state << "|" << alert.ml_score
           << "|" << alert.src_ip << "|" << alert.message << ";";
  }

  return GenereazaACK("RESULTS", result.str());
}

// ============================================================================
// QUERY_NETWORK_FLOWS - Query network flow data
// Format: QUERY_NETWORK_FLOWS <username> <limit> [protocol]
// Returns:
// timestamp|source_host|protocol|local_addr|local_port|remote_addr|remote_port|state
// ============================================================================
string ProcesorComenzi::ProceseazaQUERY_NETWORK_FLOWS(const string &argumente,
                                                      int socket_client,
                                                      ManagerBazaDate *bd) {
  stringstream ss(argumente);
  string cmd, username, limit_str, protocol_filter;

  ss >> cmd >> username >> limit_str;

  // Optional protocol filter
  if (ss >> protocol_filter) {
    // Got protocol filter
  }

  if (username.empty() || limit_str.empty()) {
    return GenereazaACK(
        "ERR", "Format: QUERY_NETWORK_FLOWS <username> <limit> [protocol]");
  }

  int limit = 100;
  try {
    limit = stoi(limit_str);
  } catch (...) {
    limit = 100;
  }

  // Get admin_id for user
  int admin_id = bd->GetAdminIdForUser(username);
  if (admin_id <= 0) {
    return GenereazaACK("ERR", "User not found or not authorized");
  }

  // Query network flows
  vector<NetworkFlow> flows =
      bd->GetRecentFlows(admin_id, limit, protocol_filter);

  // Format response:
  // timestamp|source_host|protocol|local_addr|local_port|remote_addr|remote_port|state
  stringstream result;

  for (const auto &flow : flows) {
    result << flow.timestamp << "|" << flow.source_host << "|" << flow.protocol
           << "|" << flow.local_addr << "|" << flow.local_port << "|"
           << flow.remote_addr << "|" << flow.remote_port << "|" << flow.state
           << "\n";
  }

  if (flows.empty()) {
    return GenereazaACK("OK", "No network flows found");
  }

  return result.str();
}

// ============================================================================
// LIST_USERS - List all users under this admin
// Format: LIST_USERS <admin_username>
// Returns: username|role|admin_id for each user
// ============================================================================
string ProcesorComenzi::ProceseazaLIST_USERS(const string &argumente,
                                             int socket_client,
                                             ManagerBazaDate *bd) {
  stringstream ss(argumente);
  string cmd, admin_username;
  ss >> cmd >> admin_username;

  if (admin_username.empty()) {
    return GenereazaACK("ERR", "Format: LIST_USERS <admin_username>");
  }

  // Verify admin is actually an admin
  string role = bd->GetUserRole(admin_username);
  if (role != "admin") {
    return GenereazaACK("ERR", "Not authorized");
  }

  // Get admin's user ID
  auto admin_user = bd->GetUser(admin_username);
  if (!admin_user) {
    return GenereazaACK("ERR", "User not found");
  }
  int admin_id = admin_user->id;

  // Query users - get all users with this admin_id or the admin themselves
  vector<tuple<string, string, int>> users = bd->GetUsersForAdmin(admin_id);

  stringstream result;
  result << "count=" << users.size() << ";";
  for (const auto &user : users) {
    result << get<0>(user) << "|" << get<1>(user) << "|" << get<2>(user) << ";";
  }

  return GenereazaACK("RESULTS", result.str());
}

// ============================================================================
// DELETE_USER - Delete a user (admin only)
// Format: DELETE_USER <admin_username> <target_username>
// ============================================================================
string ProcesorComenzi::ProceseazaDELETE_USER(const string &argumente,
                                              int socket_client,
                                              ManagerBazaDate *bd) {
  stringstream ss(argumente);
  string cmd, admin_username, target_username;
  ss >> cmd >> admin_username >> target_username;

  if (admin_username.empty() || target_username.empty()) {
    return GenereazaACK("ERR", "Format: DELETE_USER <admin> <target>");
  }

  // Verify admin
  string role = bd->GetUserRole(admin_username);
  if (role != "admin") {
    return GenereazaACK("ERR", "Not authorized");
  }

  // Cannot delete yourself
  if (admin_username == target_username) {
    return GenereazaACK("ERR", "Cannot delete yourself");
  }

  // Delete user
  bool success = bd->DeleteUser(target_username);
  if (success) {
    return GenereazaACK("OK", "User deleted: " + target_username);
  } else {
    return GenereazaACK("ERR", "Failed to delete user");
  }
}

// ============================================================================
// LIST_AGENTS - List registered agents for this admin
// Format: LIST_AGENTS <admin_username>
// Returns: hostname|ip|last_heartbeat|status for each agent
// ============================================================================
string ProcesorComenzi::ProceseazaLIST_AGENTS(const string &argumente,
                                              int socket_client,
                                              ManagerBazaDate *bd) {
  stringstream ss(argumente);
  string cmd, admin_username;
  ss >> cmd >> admin_username;

  if (admin_username.empty()) {
    return GenereazaACK("ERR", "Format: LIST_AGENTS <admin_username>");
  }

  // Verify admin
  string role = bd->GetUserRole(admin_username);
  if (role != "admin") {
    return GenereazaACK("ERR", "Not authorized");
  }

  // Get admin ID
  int admin_id = bd->GetAdminIdForUser(admin_username);
  if (admin_id < 0) {
    return GenereazaACK("ERR", "User not found");
  }

  // Get agents for this admin
  vector<Agent> agents = bd->GetAgentsForAdmin(admin_id);

  stringstream result;
  result << "count=" << agents.size() << ";";
  for (const auto &agent : agents) {
    // Agent struct has: hostname, src_ip, last_seen
    result << agent.hostname << "|" << agent.src_ip << "|" << agent.last_seen
           << "|online;";
  }

  return GenereazaACK("RESULTS", result.str());
}
