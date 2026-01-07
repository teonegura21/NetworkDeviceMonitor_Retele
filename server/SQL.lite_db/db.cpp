#include "db.h"
#include <iostream>
#include <sstream>

using namespace std;

// ============================================================================
// Constructor / Destructor
// ============================================================================

ManagerBazaDate::ManagerBazaDate(const string &cale_fisier) {
  this->db_path = cale_fisier;

  int rc = sqlite3_open(cale_fisier.c_str(), &this->db);
  if (rc != SQLITE_OK) {
    cerr << "❌ Eroare la deschiderea bazei de date: "
         << sqlite3_errmsg(this->db) << endl;
    this->db = nullptr;
    return;
  }

  cout << "✓ Baza de date conectata: " << cale_fisier << endl;

  // Ensure tables exist (CREATE IF NOT EXISTS)
  // This is safe to run on every startup
  const char *create_tables = R"(
        CREATE TABLE IF NOT EXISTS Utilizatori (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nume_utilizator TEXT UNIQUE NOT NULL,
            parola TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            admin_id INTEGER REFERENCES Utilizatori(id)
        );
        
        CREATE TABLE IF NOT EXISTS Loguri (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nume_utilizator TEXT,
            mesaj TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            admin_id INTEGER REFERENCES Utilizatori(id),
            src_ip TEXT,
            event_type TEXT DEFAULT 'batch_event'
        );
        
        CREATE TABLE IF NOT EXISTS syslog_rfc5424 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL REFERENCES Loguri(id),
            facility INTEGER,
            severity INTEGER,
            hostname TEXT,
            app_name TEXT,
            proc_id TEXT,
            msg_id TEXT,
            structured_data TEXT,
            parsed_ok INTEGER DEFAULT 1
        );
        
        CREATE TABLE IF NOT EXISTS agents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER NOT NULL REFERENCES Utilizatori(id),
            name TEXT,
            hostname TEXT,
            os TEXT,
            version TEXT,
            src_ip TEXT,
            last_seen DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    )";

  ExecuteSQL(create_tables);
}

ManagerBazaDate::~ManagerBazaDate() {
  if (this->db) {
    sqlite3_close(this->db);
    cout << "✓ Baza de date inchisa" << endl;
  }
}

// ============================================================================
// Private Helper Methods
// ============================================================================

bool ManagerBazaDate::ExecuteSQL(const string &sql) {
  char *err_msg = nullptr;
  int rc = sqlite3_exec(this->db, sql.c_str(), nullptr, nullptr, &err_msg);

  if (rc != SQLITE_OK) {
    cerr << "❌ SQL Error: " << err_msg << endl;
    sqlite3_free(err_msg);
    return false;
  }
  return true;
}

// ============================================================================
// User Management
// ============================================================================

bool ManagerBazaDate::Autentificare(const string &username,
                                    const string &password) {
  if (!this->db)
    return false;

  string sql =
      "SELECT id FROM Utilizatori WHERE nume_utilizator = ? AND parola = ?;";
  sqlite3_stmt *stmt;

  int rc = sqlite3_prepare_v2(this->db, sql.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK) {
    cerr << "❌ Prepare error: " << sqlite3_errmsg(this->db) << endl;
    return false;
  }

  sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 2, password.c_str(), -1, SQLITE_STATIC);

  bool found = (sqlite3_step(stmt) == SQLITE_ROW);
  sqlite3_finalize(stmt);

  return found;
}

string ManagerBazaDate::GetUserRole(const string &username) {
  if (!this->db)
    return "";

  string sql = "SELECT role FROM Utilizatori WHERE nume_utilizator = ?;";
  sqlite3_stmt *stmt;

  int rc = sqlite3_prepare_v2(this->db, sql.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK)
    return "";

  sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

  string role = "";
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    const char *r = (const char *)sqlite3_column_text(stmt, 0);
    if (r)
      role = r;
  }
  sqlite3_finalize(stmt);

  return role;
}

int ManagerBazaDate::GetAdminIdForUser(const string &username) {
  if (!this->db)
    return -1;

  // First get the user's info
  string sql =
      "SELECT id, role, admin_id FROM Utilizatori WHERE nume_utilizator = ?;";
  sqlite3_stmt *stmt;

  int rc = sqlite3_prepare_v2(this->db, sql.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK)
    return -1;

  sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

  int result = -1;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    int id = sqlite3_column_int(stmt, 0);
    const char *role = (const char *)sqlite3_column_text(stmt, 1);

    if (role && string(role) == "admin") {
      // Admin's events are owned by themselves
      result = id;
    } else {
      // User's admin_id
      if (sqlite3_column_type(stmt, 2) != SQLITE_NULL) {
        result = sqlite3_column_int(stmt, 2);
      }
    }
  }
  sqlite3_finalize(stmt);

  return result;
}

optional<User> ManagerBazaDate::GetUser(const string &username) {
  if (!this->db)
    return nullopt;

  string sql = "SELECT id, nume_utilizator, role, admin_id FROM Utilizatori "
               "WHERE nume_utilizator = ?;";
  sqlite3_stmt *stmt;

  int rc = sqlite3_prepare_v2(this->db, sql.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK)
    return nullopt;

  sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

  optional<User> result = nullopt;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    User user;
    user.id = sqlite3_column_int(stmt, 0);
    user.username = (const char *)sqlite3_column_text(stmt, 1);
    const char *r = (const char *)sqlite3_column_text(stmt, 2);
    user.role = r ? r : "user";
    user.admin_id = sqlite3_column_type(stmt, 3) == SQLITE_NULL
                        ? 0
                        : sqlite3_column_int(stmt, 3);
    result = user;
  }
  sqlite3_finalize(stmt);

  return result;
}

int ManagerBazaDate::CreateUser(const string &username, const string &password,
                                const string &role, int admin_id) {
  if (!this->db)
    return -1;

  string sql = "INSERT INTO Utilizatori (nume_utilizator, parola, role, "
               "admin_id) VALUES (?, ?, ?, ?);";
  sqlite3_stmt *stmt;

  int rc = sqlite3_prepare_v2(this->db, sql.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK)
    return -1;

  sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 2, password.c_str(), -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 3, role.c_str(), -1, SQLITE_STATIC);

  if (admin_id > 0) {
    sqlite3_bind_int(stmt, 4, admin_id);
  } else {
    sqlite3_bind_null(stmt, 4);
  }

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);

  if (rc != SQLITE_DONE) {
    cerr << "❌ Error creating user: " << sqlite3_errmsg(this->db) << endl;
    return -1;
  }

  return (int)sqlite3_last_insert_rowid(this->db);
}

// ============================================================================
// Event/Log Management
// ============================================================================

void ManagerBazaDate::SalveazaLog(const string &username, const string &mesaj) {
  // Legacy method - get admin_id for user and call extended version
  int admin_id = GetAdminIdForUser(username);
  if (admin_id < 0)
    admin_id = 1; // Default to admin id 1

  SalveazaLogExtins(admin_id, username, mesaj, "", "batch_event");
}

int ManagerBazaDate::SalveazaLogExtins(int admin_id, const string &username,
                                       const string &mesaj,
                                       const string &src_ip,
                                       const string &event_type) {
  if (!this->db)
    return -1;

  string sql = "INSERT INTO Loguri (admin_id, nume_utilizator, mesaj, src_ip, "
               "event_type) VALUES (?, ?, ?, ?, ?);";
  sqlite3_stmt *stmt;

  int rc = sqlite3_prepare_v2(this->db, sql.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK) {
    cerr << "❌ Prepare error: " << sqlite3_errmsg(this->db) << endl;
    return -1;
  }

  sqlite3_bind_int(stmt, 1, admin_id);
  sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 3, mesaj.c_str(), -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 4, src_ip.c_str(), -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 5, event_type.c_str(), -1, SQLITE_STATIC);

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);

  if (rc != SQLITE_DONE) {
    cerr << "❌ Error saving log: " << sqlite3_errmsg(this->db) << endl;
    return -1;
  }

  return (int)sqlite3_last_insert_rowid(this->db);
}

bool ManagerBazaDate::SalveazaRFC5424(int event_id, const RFC5424Data &data) {
  if (!this->db)
    return false;

  string sql = R"(
        INSERT INTO syslog_rfc5424 
        (event_id, facility, severity, hostname, app_name, proc_id, msg_id, structured_data, parsed_ok)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
    )";
  sqlite3_stmt *stmt;

  int rc = sqlite3_prepare_v2(this->db, sql.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK)
    return false;

  sqlite3_bind_int(stmt, 1, event_id);
  sqlite3_bind_int(stmt, 2, data.facility);
  sqlite3_bind_int(stmt, 3, data.severity);
  sqlite3_bind_text(stmt, 4, data.hostname.c_str(), -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 5, data.app_name.c_str(), -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 6, data.proc_id.c_str(), -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 7, data.msg_id.c_str(), -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 8, data.structured_data.c_str(), -1, SQLITE_STATIC);
  sqlite3_bind_int(stmt, 9, data.parsed_ok ? 1 : 0);

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);

  return rc == SQLITE_DONE;
}

vector<Event>
ManagerBazaDate::GetLastNEvents(int admin_id, int limit,
                                const optional<EventFilter> &filter) {
  vector<Event> events;
  if (!this->db)
    return events;

  // Build query with optional filters
  stringstream sql;
  sql << "SELECT id, nume_utilizator, mesaj, timestamp, admin_id, src_ip, "
         "event_type "
      << "FROM Loguri WHERE admin_id = ?";

  if (filter.has_value()) {
    if (filter->event_type.has_value()) {
      sql << " AND event_type = '" << filter->event_type.value() << "'";
    }
    if (filter->src_ip.has_value()) {
      sql << " AND src_ip = '" << filter->src_ip.value() << "'";
    }
    if (filter->since_timestamp.has_value()) {
      sql << " AND timestamp >= datetime(" << filter->since_timestamp.value()
          << ", 'unixepoch')";
    }
  }

  sql << " ORDER BY timestamp DESC LIMIT ?;";

  sqlite3_stmt *stmt;
  int rc = sqlite3_prepare_v2(this->db, sql.str().c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK) {
    cerr << "❌ Query error: " << sqlite3_errmsg(this->db) << endl;
    return events;
  }

  sqlite3_bind_int(stmt, 1, admin_id);
  sqlite3_bind_int(stmt, 2, limit);

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    Event e;
    e.id = sqlite3_column_int(stmt, 0);

    const char *user = (const char *)sqlite3_column_text(stmt, 1);
    e.username = user ? user : "";

    const char *msg = (const char *)sqlite3_column_text(stmt, 2);
    e.message = msg ? msg : "";

    const char *ts = (const char *)sqlite3_column_text(stmt, 3);
    e.timestamp = ts ? ts : "";

    e.admin_id = sqlite3_column_int(stmt, 4);

    const char *ip = (const char *)sqlite3_column_text(stmt, 5);
    e.src_ip = ip ? ip : "";

    const char *type = (const char *)sqlite3_column_text(stmt, 6);
    e.event_type = type ? type : "batch_event";

    events.push_back(e);
  }

  sqlite3_finalize(stmt);
  return events;
}

optional<RFC5424Data> ManagerBazaDate::GetRFC5424ForEvent(int event_id) {
  if (!this->db)
    return nullopt;

  string sql = "SELECT facility, severity, hostname, app_name, proc_id, "
               "msg_id, structured_data, parsed_ok "
               "FROM syslog_rfc5424 WHERE event_id = ?;";
  sqlite3_stmt *stmt;

  int rc = sqlite3_prepare_v2(this->db, sql.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK)
    return nullopt;

  sqlite3_bind_int(stmt, 1, event_id);

  optional<RFC5424Data> result = nullopt;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    RFC5424Data data;
    data.facility = sqlite3_column_int(stmt, 0);
    data.severity = sqlite3_column_int(stmt, 1);

    const char *h = (const char *)sqlite3_column_text(stmt, 2);
    data.hostname = h ? h : "";

    const char *a = (const char *)sqlite3_column_text(stmt, 3);
    data.app_name = a ? a : "";

    const char *p = (const char *)sqlite3_column_text(stmt, 4);
    data.proc_id = p ? p : "";

    const char *m = (const char *)sqlite3_column_text(stmt, 5);
    data.msg_id = m ? m : "";

    const char *s = (const char *)sqlite3_column_text(stmt, 6);
    data.structured_data = s ? s : "";

    data.parsed_ok = sqlite3_column_int(stmt, 7) == 1;

    result = data;
  }

  sqlite3_finalize(stmt);
  return result;
}

// ============================================================================
// Agent Management
// ============================================================================

int ManagerBazaDate::RegisterAgent(int admin_id, const string &name,
                                   const string &hostname, const string &os,
                                   const string &version,
                                   const string &src_ip) {
  if (!this->db)
    return -1;

  // Check if agent already exists
  auto existing = GetAgentByHost(hostname, src_ip);
  if (existing.has_value()) {
    UpdateAgentHeartbeat(existing->id);
    return existing->id;
  }

  string sql = "INSERT INTO agents (admin_id, name, hostname, os, version, "
               "src_ip, last_seen) "
               "VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP);";
  sqlite3_stmt *stmt;

  int rc = sqlite3_prepare_v2(this->db, sql.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK)
    return -1;

  sqlite3_bind_int(stmt, 1, admin_id);
  sqlite3_bind_text(stmt, 2, name.c_str(), -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 3, hostname.c_str(), -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 4, os.c_str(), -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 5, version.c_str(), -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 6, src_ip.c_str(), -1, SQLITE_STATIC);

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);

  if (rc != SQLITE_DONE)
    return -1;

  cout << "✓ Agent inregistrat: " << hostname << " (" << src_ip << ")" << endl;
  return (int)sqlite3_last_insert_rowid(this->db);
}

void ManagerBazaDate::UpdateAgentHeartbeat(int agent_id) {
  if (!this->db)
    return;

  string sql = "UPDATE agents SET last_seen = CURRENT_TIMESTAMP WHERE id = ?;";
  sqlite3_stmt *stmt;

  int rc = sqlite3_prepare_v2(this->db, sql.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK)
    return;

  sqlite3_bind_int(stmt, 1, agent_id);
  sqlite3_step(stmt);
  sqlite3_finalize(stmt);
}

void ManagerBazaDate::UpdateAgentHeartbeatByHost(const string &hostname,
                                                 const string &src_ip) {
  if (!this->db)
    return;

  string sql = "UPDATE agents SET last_seen = CURRENT_TIMESTAMP WHERE hostname "
               "= ? AND src_ip = ?;";
  sqlite3_stmt *stmt;

  int rc = sqlite3_prepare_v2(this->db, sql.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK)
    return;

  sqlite3_bind_text(stmt, 1, hostname.c_str(), -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 2, src_ip.c_str(), -1, SQLITE_STATIC);
  sqlite3_step(stmt);
  sqlite3_finalize(stmt);
}

vector<Agent> ManagerBazaDate::GetAgentsForAdmin(int admin_id) {
  vector<Agent> agents;
  if (!this->db)
    return agents;

  string sql = "SELECT id, admin_id, name, hostname, os, version, src_ip, "
               "last_seen, created_at "
               "FROM agents WHERE admin_id = ? ORDER BY last_seen DESC;";
  sqlite3_stmt *stmt;

  int rc = sqlite3_prepare_v2(this->db, sql.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK)
    return agents;

  sqlite3_bind_int(stmt, 1, admin_id);

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    Agent a;
    a.id = sqlite3_column_int(stmt, 0);
    a.admin_id = sqlite3_column_int(stmt, 1);

    const char *n = (const char *)sqlite3_column_text(stmt, 2);
    a.name = n ? n : "";

    const char *h = (const char *)sqlite3_column_text(stmt, 3);
    a.hostname = h ? h : "";

    const char *o = (const char *)sqlite3_column_text(stmt, 4);
    a.os = o ? o : "";

    const char *v = (const char *)sqlite3_column_text(stmt, 5);
    a.version = v ? v : "";

    const char *ip = (const char *)sqlite3_column_text(stmt, 6);
    a.src_ip = ip ? ip : "";

    const char *ls = (const char *)sqlite3_column_text(stmt, 7);
    a.last_seen = ls ? ls : "";

    const char *ca = (const char *)sqlite3_column_text(stmt, 8);
    a.created_at = ca ? ca : "";

    agents.push_back(a);
  }

  sqlite3_finalize(stmt);
  return agents;
}

optional<Agent> ManagerBazaDate::GetAgentByHost(const string &hostname,
                                                const string &src_ip) {
  if (!this->db)
    return nullopt;

  string sql = "SELECT id, admin_id, name, hostname, os, version, src_ip, "
               "last_seen, created_at "
               "FROM agents WHERE hostname = ? AND src_ip = ?;";
  sqlite3_stmt *stmt;

  int rc = sqlite3_prepare_v2(this->db, sql.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK)
    return nullopt;

  sqlite3_bind_text(stmt, 1, hostname.c_str(), -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 2, src_ip.c_str(), -1, SQLITE_STATIC);

  optional<Agent> result = nullopt;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    Agent a;
    a.id = sqlite3_column_int(stmt, 0);
    a.admin_id = sqlite3_column_int(stmt, 1);

    const char *n = (const char *)sqlite3_column_text(stmt, 2);
    a.name = n ? n : "";

    const char *h = (const char *)sqlite3_column_text(stmt, 3);
    a.hostname = h ? h : "";

    const char *o = (const char *)sqlite3_column_text(stmt, 4);
    a.os = o ? o : "";

    const char *v = (const char *)sqlite3_column_text(stmt, 5);
    a.version = v ? v : "";

    const char *ip = (const char *)sqlite3_column_text(stmt, 6);
    a.src_ip = ip ? ip : "";

    const char *ls = (const char *)sqlite3_column_text(stmt, 7);
    a.last_seen = ls ? ls : "";

    const char *ca = (const char *)sqlite3_column_text(stmt, 8);
    a.created_at = ca ? ca : "";

    result = a;
  }

  sqlite3_finalize(stmt);
  return result;
}

bool ManagerBazaDate::PromoteUserToAdmin(const string &username) {
  if (!this->db)
    return false;

  // Promote: role='admin', admin_id=NULL
  string sql = "UPDATE Utilizatori SET role='admin', admin_id=NULL WHERE "
               "nume_utilizator=?;";
  sqlite3_stmt *stmt;

  int rc = sqlite3_prepare_v2(this->db, sql.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK)
    return false;

  sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);

  return rc == SQLITE_DONE;
}

bool ManagerBazaDate::IsUserAssignedToAdmin(const string &username,
                                            int admin_id) {
  if (!this->db)
    return false;

  string sql = "SELECT admin_id FROM Utilizatori WHERE nume_utilizator = ?;";
  sqlite3_stmt *stmt;

  int rc = sqlite3_prepare_v2(this->db, sql.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK)
    return false;

  sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

  bool match = false;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    if (sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
      int user_admin_id = sqlite3_column_int(stmt, 0);
      if (user_admin_id == admin_id)
        match = true;
    }
  }
  sqlite3_finalize(stmt);
  return match;
}

// ============================================================================
// Metrics & Aggregation
// ============================================================================

vector<string> ManagerBazaDate::GetEventsOverTime(int admin_id) {
  vector<string> results;
  if (!this->db)
    return results;

  // Last 24 hours grouped by hour
  // SQLite strftime: %Y-%m-%d %H:00:00
  string sql =
      "SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as hour, COUNT(*) "
      "FROM Loguri "
      "WHERE admin_id = ? OR admin_id IN (SELECT id FROM Utilizatori WHERE "
      "admin_id=?) "
      "GROUP BY hour "
      "ORDER BY hour DESC LIMIT 24;";

  // Note: The OR condition allows Admin to see their logs AND their users' logs
  // Simplified: Just match admin_id (assuming all events are owned by admin or
  // stamped with admin_id) Our design says: events from agent have admin_id of
  // the agent's owner. If Admin1 owns Agent1, events get admin_id=Admin1. If
  // User1 is sub-user of Admin1, User1 sees events where admin_id=Admin1. This
  // method takes 'admin_id' which is determining the data scope. If caller is
  // User1, we should pass Admin1's ID. If caller is Admin1, we pass Admin1's
  // ID. So the query is simple: WHERE admin_id = ?

  // Let's refine SQL for simplicity and correctness with our model:
  sql = "SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as hour, COUNT(*) "
        "FROM Loguri "
        "WHERE admin_id = ? "
        "GROUP BY hour "
        "ORDER BY hour DESC LIMIT 24;";

  sqlite3_stmt *stmt;
  int rc = sqlite3_prepare_v2(this->db, sql.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK)
    return results;

  sqlite3_bind_int(stmt, 1, admin_id);

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    const char *h = (const char *)sqlite3_column_text(stmt, 0);
    int count = sqlite3_column_int(stmt, 1);

    string hour = h ? h : "unknown";
    results.push_back(hour + "|" + to_string(count));
  }
  sqlite3_finalize(stmt);
  return results;
}

vector<string> ManagerBazaDate::GetSeverityDistribution(int admin_id) {
  vector<string> results;
  if (!this->db)
    return results;

  // Join with Loguri to filter by admin_id
  string sql = "SELECT s.severity, COUNT(*) "
               "FROM syslog_rfc5424 s "
               "JOIN Loguri l ON s.event_id = l.id "
               "WHERE l.admin_id = ? "
               "GROUP BY s.severity;";

  sqlite3_stmt *stmt;
  int rc = sqlite3_prepare_v2(this->db, sql.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK)
    return results;

  sqlite3_bind_int(stmt, 1, admin_id);

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    int severity = sqlite3_column_int(stmt, 0);
    int count = sqlite3_column_int(stmt, 1);
    results.push_back(to_string(severity) + "|" + to_string(count));
  }
  sqlite3_finalize(stmt);
  return results;
}

vector<string> ManagerBazaDate::GetTopSources(int admin_id) {
  vector<string> results;
  if (!this->db)
    return results;

  string sql = "SELECT src_ip, COUNT(*) "
               "FROM Loguri "
               "WHERE admin_id = ? "
               "GROUP BY src_ip "
               "ORDER BY COUNT(*) DESC LIMIT 10;";

  sqlite3_stmt *stmt;
  int rc = sqlite3_prepare_v2(this->db, sql.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK)
    return results;

  sqlite3_bind_int(stmt, 1, admin_id);

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    const char *ip = (const char *)sqlite3_column_text(stmt, 0);
    int count = sqlite3_column_int(stmt, 1);

    string src = ip ? ip : "unknown";
    results.push_back(src + "|" + to_string(count));
  }
  sqlite3_finalize(stmt);
  return results;
}
// Add this to db.cpp after UpdateAgentHeartbeat implementation

/**
 * Get recent alerts for an admin
 */
vector<Alert> ManagerBazaDate::GetRecentAlerts(int admin_id, int limit,
                                               const string &state_filter) {
  vector<Alert> results;

  string sql = "SELECT a.id, a.event_id, a.rule_id, a.ml_score, a.severity, "
               "a.state, a.created_at, l.mesaj, l.src_ip "
               "FROM Alerts a "
               "JOIN Loguri l ON a.event_id = l.id "
               "WHERE l.admin_id = ?";

  // Add state filter if provided
  if (!state_filter.empty()) {
    sql += " AND a.state = ?";
  }

  sql += " ORDER BY a.created_at DESC LIMIT ?";

  sqlite3_stmt *stmt;
  if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
    cerr << "[DB] GetRecentAlerts prepare error: " << sqlite3_errmsg(db)
         << endl;
    return results;
  }

  int param_idx = 1;
  sqlite3_bind_int(stmt, param_idx++, admin_id);

  if (!state_filter.empty()) {
    sqlite3_bind_text(stmt, param_idx++, state_filter.c_str(), -1,
                      SQLITE_TRANSIENT);
  }

  sqlite3_bind_int(stmt, param_idx, limit);

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    Alert alert;
    alert.id = sqlite3_column_int(stmt, 0);
    alert.event_id = sqlite3_column_int(stmt, 1);

    const char *rule_id =
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));
    alert.rule_id = rule_id ? rule_id : "";

    alert.ml_score = static_cast<float>(sqlite3_column_double(stmt, 3));
    alert.severity = sqlite3_column_int(stmt, 4);

    const char *state =
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 5));
    alert.state = state ? state : "";

    const char *created =
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 6));
    alert.created_at = created ? created : "";

    const char *msg =
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 7));
    alert.message = msg ? msg : "";

    const char *src =
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 8));
    alert.src_ip = src ? src : "unknown";

    results.push_back(alert);
  }

  sqlite3_finalize(stmt);
  return results;
}

// ============================================================================
// Network Flow Monitoring (NEW!)
// ============================================================================

int ManagerBazaDate::StoreNetworkFlow(int admin_id, const string &source_host,
                                      const string &protocol,
                                      const string &local_addr, int local_port,
                                      const string &remote_addr,
                                      int remote_port, const string &state,
                                      const string &process_name) {
  if (!db)
    return -1;

  const char *sql = "INSERT INTO NetworkFlows "
                    "(admin_id, source_host, protocol, local_addr, local_port, "
                    "remote_addr, remote_port, state, process_name) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

  sqlite3_stmt *stmt;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    cerr << "❌ StoreNetworkFlow prepare error: " << sqlite3_errmsg(db) << endl;
    return -1;
  }

  sqlite3_bind_int(stmt, 1, admin_id);
  sqlite3_bind_text(stmt, 2, source_host.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, protocol.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 4, local_addr.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 5, local_port);
  sqlite3_bind_text(stmt, 6, remote_addr.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 7, remote_port);
  sqlite3_bind_text(stmt, 8, state.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 9, process_name.c_str(), -1, SQLITE_TRANSIENT);

  int result = -1;
  if (sqlite3_step(stmt) == SQLITE_DONE) {
    result = static_cast<int>(sqlite3_last_insert_rowid(db));
  } else {
    cerr << "❌ StoreNetworkFlow execute error: " << sqlite3_errmsg(db) << endl;
  }

  sqlite3_finalize(stmt);
  return result;
}

int ManagerBazaDate::CreatePortScanAlert(int admin_id, const string &source_ip,
                                         const string &scan_type,
                                         const string &ports_scanned,
                                         int port_count, int duration_seconds,
                                         int severity) {
  if (!db)
    return -1;

  // First create generic log entry
  string message = "PORT_SCAN_DETECTED: type=" + scan_type +
                   " src=" + source_ip + " ports=" + to_string(port_count);

  const char *insert_log =
      "INSERT INTO Loguri (mesaj, src_ip, admin_id, event_type) "
      "VALUES (?, ?, ?, 'port_scan')";

  sqlite3_stmt *stmt;
  if (sqlite3_prepare_v2(db, insert_log, -1, &stmt, nullptr) != SQLITE_OK) {
    return -1;
  }

  sqlite3_bind_text(stmt, 1, message.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, source_ip.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 3, admin_id);

  if (sqlite3_step(stmt) != SQLITE_DONE) {
    sqlite3_finalize(stmt);
    return -1;
  }

  int event_id = static_cast<int>(sqlite3_last_insert_rowid(db));
  sqlite3_finalize(stmt);

  // Now create alert
  const char *insert_alert =
      "INSERT INTO Alerts (event_id, rule_id, severity, state, ml_score) "
      "VALUES (?, 'port_scan', ?, 'open', 0.95)";

  if (sqlite3_prepare_v2(db, insert_alert, -1, &stmt, nullptr) != SQLITE_OK) {
    return -1;
  }

  sqlite3_bind_int(stmt, 1, event_id);
  sqlite3_bind_int(stmt, 2, severity);

  if (sqlite3_step(stmt) != SQLITE_DONE) {
    sqlite3_finalize(stmt);
    return -1;
  }

  int alert_id = static_cast<int>(sqlite3_last_insert_rowid(db));
  sqlite3_finalize(stmt);

  // Finally add port scan details
  const char *insert_details =
      "INSERT INTO PortScanDetails "
      "(alert_id, source_ip, scan_type, ports_scanned, port_count, "
      "duration_seconds) "
      "VALUES (?, ?, ?, ?, ?, ?)";

  if (sqlite3_prepare_v2(db, insert_details, -1, &stmt, nullptr) != SQLITE_OK) {
    return alert_id; // At least we created the alert
  }

  sqlite3_bind_int(stmt, 1, alert_id);
  sqlite3_bind_text(stmt, 2, source_ip.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, scan_type.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 4, ports_scanned.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 5, port_count);
  sqlite3_bind_int(stmt, 6, duration_seconds);

  sqlite3_step(stmt);
  sqlite3_finalize(stmt);

  cout << "🚨 Port scan alert created: " << source_ip << " scanned "
       << port_count << " ports" << endl;

  return alert_id;
}

vector<NetworkFlow>
ManagerBazaDate::GetRecentFlows(int admin_id, int limit,
                                const string &protocol_filter) {
  vector<NetworkFlow> results;
  if (!db)
    return results;

  string sql =
      "SELECT id, timestamp, admin_id, source_host, protocol, "
      "local_addr, local_port, remote_addr, remote_port, state, process_name "
      "FROM NetworkFlows WHERE admin_id = ?";

  if (!protocol_filter.empty()) {
    sql += " AND protocol = ?";
  }
  sql += " ORDER BY timestamp DESC LIMIT ?";

  sqlite3_stmt *stmt;
  if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
    return results;
  }

  int param_idx = 1;
  sqlite3_bind_int(stmt, param_idx++, admin_id);

  if (!protocol_filter.empty()) {
    sqlite3_bind_text(stmt, param_idx++, protocol_filter.c_str(), -1,
                      SQLITE_TRANSIENT);
  }

  sqlite3_bind_int(stmt, param_idx, limit);

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    NetworkFlow flow;
    flow.id = sqlite3_column_int(stmt, 0);

    const char *ts =
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
    flow.timestamp = ts ? ts : "";

    flow.admin_id = sqlite3_column_int(stmt, 2);

    const char *host =
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
    flow.source_host = host ? host : "";

    const char *proto =
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 4));
    flow.protocol = proto ? proto : "";

    const char *laddr =
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 5));
    flow.local_addr = laddr ? laddr : "";

    flow.local_port = sqlite3_column_int(stmt, 6);

    const char *raddr =
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 7));
    flow.remote_addr = raddr ? raddr : "";

    flow.remote_port = sqlite3_column_int(stmt, 8);

    const char *state =
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 9));
    flow.state = state ? state : "";

    const char *proc =
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 10));
    flow.process_name = proc ? proc : "";

    results.push_back(flow);
  }

  sqlite3_finalize(stmt);
  return results;
}

ManagerBazaDate::FlowStats ManagerBazaDate::GetFlowStatistics(int admin_id,
                                                              int minutes) {
  FlowStats stats = {0, 0, 0, 0, {}};
  if (!db)
    return stats;

  // Get protocol counts
  string sql =
      "SELECT protocol, state, COUNT(*) as cnt FROM NetworkFlows "
      "WHERE admin_id = ? AND timestamp > datetime('now', '-' || ? || ' "
      "minutes') "
      "GROUP BY protocol, state";

  sqlite3_stmt *stmt;
  if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
    sqlite3_bind_int(stmt, 1, admin_id);
    sqlite3_bind_int(stmt, 2, minutes);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
      const char *proto =
          reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
      const char *state =
          reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
      int count = sqlite3_column_int(stmt, 2);

      string protocol = proto ? proto : "";
      string st = state ? state : "";

      if (protocol == "TCP")
        stats.tcp_count += count;
      if (protocol == "UDP")
        stats.udp_count += count;
      if (st == "ESTABLISHED")
        stats.established_count += count;
      if (st == "LISTEN")
        stats.listen_count += count;
    }
    sqlite3_finalize(stmt);
  }

  // Get top remotes
  sql = "SELECT remote_addr, COUNT(*) as cnt FROM NetworkFlows "
        "WHERE admin_id = ? AND timestamp > datetime('now', '-' || ? || ' "
        "minutes') "
        "AND remote_addr != '0.0.0.0' "
        "GROUP BY remote_addr ORDER BY cnt DESC LIMIT 10";

  if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
    sqlite3_bind_int(stmt, 1, admin_id);
    sqlite3_bind_int(stmt, 2, minutes);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
      const char *addr =
          reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
      int count = sqlite3_column_int(stmt, 1);

      if (addr) {
        stats.top_remotes.push_back({addr, count});
      }
    }
    sqlite3_finalize(stmt);
  }

  return stats;
}
