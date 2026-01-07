# Network Data Flow - Agent to Database

## Overview

This document explains how network data flows from the agent to the database.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              DATA FLOW DIAGRAM                                   │
└─────────────────────────────────────────────────────────────────────────────────┘

  ┌──────────────┐              ┌──────────────┐              ┌──────────────┐
  │   Agent      │  syslog UDP  │   Server     │   SQLite     │   Database   │
  │   (C++)      │─────────────▶│   (C++)      │─────────────▶│   (.db)      │
  └──────────────┘   port 514   └──────────────┘              └──────────────┘
         │                             │                             │
         │                             │                             │
  ┌──────┴──────┐              ┌───────┴───────┐             ┌───────┴───────┐
  │ Collects:   │              │ Parses:       │             │ Stores:       │
  │ -Log files  │              │ -RFC5424      │             │ -Loguri table │
  │ -Net flows  │              │ -NETWORK_FLOW │             │ -NetworkFlows │
  │ -Port scans │              │ -PORT_SCAN    │             │ -Alerts table │
  └─────────────┘              └───────────────┘             └───────────────┘
```

---

## Step 1: Agent Collects Data

The agent (NMS_Agent) runs on each monitored system and collects:

### Log Files
```cpp
FileSource("/var/log/syslog", "syslog")
FileSource("/var/log/auth.log", "auth")
```

### Network Flows (every 10 seconds)
```cpp
NetworkMonitor monitor;
auto flows = monitor.GetActiveConnections();
// Produces: "NETWORK_FLOW: TCP 192.168.1.17:443 -> 8.8.8.8:443 state=ESTABLISHED"
```

### Port Scan Alerts (every 5 seconds)
```cpp
PortScanDetector detector;
auto alerts = detector.DetectScans();
// Produces: "PORT_SCAN_DETECTED: type=TCP_SYN src=10.0.0.99 ports=11 severity=HIGH"
```

---

## Step 2: Agent Sends via Syslog

All data is formatted as RFC5424 syslog and sent to server:

```
<14>1 2026-01-07T20:15:00.000Z hostname NMS network-flow - - 
NETWORK_FLOW: TCP 192.168.1.17:443 -> 8.8.8.8:443 state=ESTABLISHED

<9>1 2026-01-07T20:15:05.000Z hostname NMS security-alert - - 
PORT_SCAN_DETECTED: type=TCP_SYN src=10.0.0.99 ports=11 severity=HIGH
```

---

## Step 3: Server Parses and Stores

### RFC5424 Parser (server/server_source/RFC5424Parser.cpp)
```cpp
// Parses syslog message and extracts:
// - Timestamp
// - Hostname  
// - App name
// - Message content
```

### Database Handler (server/SQL.lite_db/db.cpp)
```cpp
// INSERT INTO Loguri (mesaj, src_ip, timestamp, ...)
// INSERT INTO Alerts (event_id, rule_id, severity, ...)
```

---

## Step 4: Database Tables

### Existing Tables:
```sql
-- General logs
CREATE TABLE Loguri (
    id INTEGER PRIMARY KEY,
    admin_id INTEGER,
    mesaj TEXT,
    src_ip TEXT,
    timestamp DATETIME,
    prioritate INTEGER,
    ml_analyzed INTEGER DEFAULT 0,
    ml_score REAL DEFAULT 0
);

-- ML-generated alerts
CREATE TABLE Alerts (
    id INTEGER PRIMARY KEY,
    event_id INTEGER,
    rule_id TEXT,
    severity INTEGER,
    state TEXT DEFAULT 'open',
    ml_score REAL,
    created_at DATETIME
);
```

### NEW Tables for Network Monitoring:
```sql
-- Network flow data
CREATE TABLE IF NOT EXISTS NetworkFlows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    admin_id INTEGER,
    source_host TEXT,           -- Which agent reported this
    protocol TEXT,              -- TCP or UDP
    local_addr TEXT,
    local_port INTEGER,
    remote_addr TEXT,
    remote_port INTEGER,
    state TEXT,                 -- ESTABLISHED, LISTEN, etc.
    process TEXT                -- Process name if known
);

CREATE INDEX idx_flows_time ON NetworkFlows(timestamp);
CREATE INDEX idx_flows_remote ON NetworkFlows(remote_addr);

-- Bandwidth statistics
CREATE TABLE IF NOT EXISTS BandwidthStats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    admin_id INTEGER,
    host TEXT,
    interface TEXT,
    rx_bytes_per_sec INTEGER,
    tx_bytes_per_sec INTEGER
);
```

---

## Step 5: Server-Side Handler Updates Needed

To fully store network data, add these to the server:

### In RFC5424Parser.cpp:
```cpp
// Detect network flow messages
if (message.find("NETWORK_FLOW:") != std::string::npos) {
    // Parse and store in NetworkFlows table
    ParseAndStoreNetworkFlow(message, admin_id);
}

// Detect port scan alerts  
if (message.find("PORT_SCAN_DETECTED:") != std::string::npos) {
    // Create high-priority alert
    CreateSecurityAlert(message, admin_id);
}
```

### In db.cpp:
```cpp
void ManagerBazaDate::StoreNetworkFlow(
    int admin_id,
    const std::string& source_host,
    const std::string& protocol,
    const std::string& local_addr,
    int local_port,
    const std::string& remote_addr,
    int remote_port,
    const std::string& state
) {
    const char* sql = 
        "INSERT INTO NetworkFlows "
        "(admin_id, source_host, protocol, local_addr, local_port, "
        "remote_addr, remote_port, state) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    
    // Execute prepared statement...
}
```

---

## Summary

| Component | What it does | Where it stores |
|-----------|-------------|-----------------|
| Agent monitors logs | Reads /var/log/* | → Loguri table |
| Agent monitors network | Reads /proc/net/* | → NetworkFlows table |
| Agent detects scans | Analyzes patterns | → Alerts table |
| Client displays | Reads from server | ← All tables |

The agent is now ready. Server needs handlers for NETWORK_FLOW and PORT_SCAN_DETECTED messages.
