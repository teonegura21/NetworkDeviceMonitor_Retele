#pragma once
#include <ctime>
#include <optional>
#include <sqlite3.h>
#include <string>
#include <vector>

using namespace std;

/**
 * Represents a user in the system (admin or regular user)
 */
struct User {
  int id;
  string username;
  string role;  // 'admin' or 'user'
  int admin_id; // NULL (0) for admins, points to admin's id for users
};

/**
 * Represents an event/log entry
 */
struct Event {
  int id;
  string username;
  string message;
  string timestamp;
  int admin_id;
  string src_ip;
  string event_type; // 'batch_event', 'syslog', 'agent', etc.
};

/**
 * Represents RFC5424 syslog parsed fields
 */
struct RFC5424Data {
  int facility; // 0-23
  int severity; // 0-7
  string hostname;
  string app_name;
  string proc_id;
  string msg_id;
  string structured_data; // JSON string
  bool parsed_ok;
};

/**
 * Represents an agent registered to an admin
 */
struct Agent {
  int id;
  int admin_id;
  string name;
  string hostname;
  string os;
  string version;
  string src_ip;
  string last_seen;
  string created_at;
};

/**
 * Represents an alert from ML anomaly detection
 */
struct Alert {
  int id;
  int event_id;
  string rule_id;
  float ml_score;
  int severity;
  string state; // 'open', 'acknowledged', 'closed'
  string created_at;
  string message; // Cached from event for convenience
  string src_ip;  // Cached from event
};

/**
 * Represents a network flow (TCP/UDP connection) from agent
 */
struct NetworkFlow {
  int id;
  string timestamp;
  int admin_id;
  string source_host; // Agent hostname
  string protocol;    // "TCP" or "UDP"
  string local_addr;
  int local_port;
  string remote_addr;
  int remote_port;
  string state; // "ESTABLISHED", "LISTEN", etc.
  string process_name;
};

/**
 * Represents port scan detection details
 */
struct PortScanDetail {
  int id;
  int alert_id;
  string source_ip;
  string scan_type;     // "TCP_CONNECT", "TCP_SYN", "UDP"
  string ports_scanned; // Comma-separated ports
  int port_count;
  int duration_seconds;
};

/**
 * Optional filter for querying events
 */
struct EventFilter {
  optional<int> severity;
  optional<string> event_type;
  optional<time_t> since_timestamp;
  optional<string> src_ip;
};

// ============================================================================
// Database Manager Class (OOP Interface)
// ============================================================================

class ManagerBazaDate {
private:
  sqlite3 *db;
  string db_path;

  // Private helper methods
  bool ExecuteSQL(const string &sql);

public:
  /**
   * Constructor - opens database and ensures tables exist
   * @param cale_fisier Path to SQLite database file
   */
  ManagerBazaDate(const string &cale_fisier);

  /**
   * Destructor - closes database connection
   */
  ~ManagerBazaDate();

  // ========================================================================
  // User Management
  // ========================================================================

  /**
   * Authenticate user with username and password
   * @return true if credentials are valid
   */
  bool Autentificare(const string &username, const string &password);

  /**
   * Get user's role ('admin' or 'user')
   * @return role string or empty if user not found
   */
  string GetUserRole(const string &username);

  /**
   * Get the admin_id for a user
   * For admins, returns their own id
   * For users, returns their assigned admin's id
   * @return admin_id or -1 if not found
   */
  int GetAdminIdForUser(const string &username);

  /**
   * Get user info by username
   * @return User struct or nullopt if not found
   */
  optional<User> GetUser(const string &username);

  /**
   * Create a new user assigned to an admin
   * @return new user id or -1 on failure
   */
  int CreateUser(const string &username, const string &password,
                 const string &role, int admin_id);

  /**
   * Promote a user to admin role (and clear their admin_id)
   * @return true on success
   */
  bool PromoteUserToAdmin(const string &username);

  /**
   * Check if a user is assigned to a specific admin
   */
  bool IsUserAssignedToAdmin(const string &username, int admin_id);

  // ========================================================================
  // Metrics & Aggregation
  // ========================================================================
  /**
   * Get event counts per hour for the last 24h
   * Returns: "YYYY-MM-DD HH:00:00|count"
   */
  vector<string> GetEventsOverTime(int admin_id);

  /**
   * Get distribution of events by severity
   * Returns: "severity_level|count"
   */
  vector<string> GetSeverityDistribution(int admin_id);

  /**
   * Get top log sources by volume
   * Returns: "src_ip|count"
   */
  vector<string> GetTopSources(int admin_id);

  // ========================================================================
  // ========================================================================

  /**
   * Save a simple log (legacy method for backward compatibility)
   */
  void SalveazaLog(const string &username, const string &mesaj);

  /**
   * Save an extended log with full metadata
   * @return new event id or -1 on failure
   */
  int SalveazaLogExtins(int admin_id, const string &username,
                        const string &mesaj, const string &src_ip,
                        const string &event_type);

  /**
   * Save RFC5424 syslog parsed data linked to an event
   * @param event_id The event id from Loguri table
   * @param data The parsed RFC5424 fields
   * @return true on success
   */
  bool SalveazaRFC5424(int event_id, const RFC5424Data &data);

  /**
   * Get the last N events for an admin (including events visible to their
   * users)
   * @param admin_id The admin's user id
   * @param limit Number of events to return
   * @param filter Optional filters
   * @return Vector of Event structs
   */
  vector<Event> GetLastNEvents(int admin_id, int limit,
                               const optional<EventFilter> &filter = nullopt);

  /**
   * Get RFC5424 data for a specific event
   * @return RFC5424Data or nullopt if not found
   */
  optional<RFC5424Data> GetRFC5424ForEvent(int event_id);

  // ========================================================================
  // Agent Management
  // ========================================================================

  /**
   * Register a new agent for an admin
   * @return new agent id or existing agent id if already exists
   */
  int RegisterAgent(int admin_id, const string &name, const string &hostname,
                    const string &os, const string &version,
                    const string &src_ip);

  /**
   * Update agent's last_seen timestamp
   */
  void UpdateAgentHeartbeat(int agent_id);

  // ========================================================================
  // Alert Management
  // ========================================================================

  /**
   * Get recent alerts for an admin
   * @param admin_id  Admin whose alerts to retrieve
   * @param limit     Maximum number of alerts to return
   * @param state_filter Optional state filter ('open', 'acknowledged',
   * 'closed')
   * @return Vector of Alert structs
   */
  vector<Alert> GetRecentAlerts(int admin_id, int limit,
                                const string &state_filter = "");

  /**
   * Update agent heartbeat by hostname/src_ip
   */
  void UpdateAgentHeartbeatByHost(const string &hostname, const string &src_ip);

  /**
   * Get all agents for an admin
   */
  vector<Agent> GetAgentsForAdmin(int admin_id);

  /**
   * Get agent by hostname and src_ip
   */
  optional<Agent> GetAgentByHost(const string &hostname, const string &src_ip);

  // ========================================================================
  // Network Flow Monitoring (NEW!)
  // ========================================================================

  /**
   * Store a network flow (TCP/UDP connection) reported by agent
   * @param admin_id The admin who owns this agent
   * @param source_host Hostname of the reporting agent
   * @param protocol "TCP" or "UDP"
   * @param local_addr Local IP address
   * @param local_port Local port number
   * @param remote_addr Remote IP address
   * @param remote_port Remote port number
   * @param state Connection state (ESTABLISHED, LISTEN, etc.)
   * @param process_name Process name if known
   * @return Inserted row ID or -1 on failure
   */
  int StoreNetworkFlow(int admin_id, const string &source_host,
                       const string &protocol, const string &local_addr,
                       int local_port, const string &remote_addr,
                       int remote_port, const string &state,
                       const string &process_name = "");

  /**
   * Create a port scan alert with details
   * @param admin_id Admin ID
   * @param source_ip IP that performed the scan
   * @param scan_type Type of scan (TCP_CONNECT, TCP_SYN, UDP)
   * @param ports_scanned Comma-separated list of scanned ports
   * @param port_count Number of ports scanned
   * @param duration_seconds Duration of the scan
   * @param severity Alert severity (1=high, 5=low)
   * @return Alert ID or -1 on failure
   */
  int CreatePortScanAlert(int admin_id, const string &source_ip,
                          const string &scan_type, const string &ports_scanned,
                          int port_count, int duration_seconds, int severity);

  /**
   * Get recent network flows for dashboard
   * @param admin_id Admin whose flows to retrieve
   * @param limit Maximum flows to return
   * @param protocol_filter Optional: filter by protocol ("TCP" or "UDP")
   * @return Vector of NetworkFlow structs
   */
  vector<NetworkFlow> GetRecentFlows(int admin_id, int limit,
                                     const string &protocol_filter = "");

  /**
   * Get network flow statistics (protocol distribution, top remotes)
   * @param admin_id Admin ID
   * @param minutes Time window in minutes
   */
  struct FlowStats {
    int tcp_count;
    int udp_count;
    int established_count;
    int listen_count;
    vector<pair<string, int>> top_remotes; // IP -> count
  };
  FlowStats GetFlowStatistics(int admin_id, int minutes = 5);

private:
};
