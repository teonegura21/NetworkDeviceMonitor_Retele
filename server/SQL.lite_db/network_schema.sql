-- ============================================================================
-- Network Data Tables Schema
-- ============================================================================
-- This file creates tables for storing network flow and port scan data
-- Run this SQL to add network monitoring support to nms_romania.db

-- Network Flow Table
-- Stores TCP/UDP connection information collected by agents
CREATE TABLE IF NOT EXISTS NetworkFlows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    admin_id INTEGER NOT NULL,
    source_host TEXT NOT NULL,      -- Hostname of the agent that reported
    protocol TEXT NOT NULL,          -- 'TCP' or 'UDP'
    local_addr TEXT,
    local_port INTEGER,
    remote_addr TEXT,
    remote_port INTEGER,
    state TEXT,                      -- 'ESTABLISHED', 'LISTEN', etc.
    process_name TEXT,               -- Process that owns the connection (if known)
    
    FOREIGN KEY (admin_id) REFERENCES Utilizatori(id)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON NetworkFlows(timestamp);
CREATE INDEX IF NOT EXISTS idx_flows_admin ON NetworkFlows(admin_id);
CREATE INDEX IF NOT EXISTS idx_flows_remote ON NetworkFlows(remote_addr);
CREATE INDEX IF NOT EXISTS idx_flows_protocol ON NetworkFlows(protocol);

-- Port Scan Alerts Table (extends Alerts)
-- Note: PORT_SCAN alerts are stored in the existing Alerts table with rule_id='port_scan'
-- This table stores additional detail about scanned ports

CREATE TABLE IF NOT EXISTS PortScanDetails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL,       -- Links to Alerts table
    source_ip TEXT NOT NULL,
    scan_type TEXT,                  -- 'TCP_CONNECT', 'TCP_SYN', 'UDP'
    ports_scanned TEXT,              -- Comma-separated list of ports
    port_count INTEGER,
    duration_seconds INTEGER,
    
    FOREIGN KEY (alert_id) REFERENCES Alerts(id)
);

CREATE INDEX IF NOT EXISTS idx_scan_alert ON PortScanDetails(alert_id);
CREATE INDEX IF NOT EXISTS idx_scan_source ON PortScanDetails(source_ip);

-- Bandwidth Statistics Table
CREATE TABLE IF NOT EXISTS BandwidthStats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    admin_id INTEGER NOT NULL,
    host TEXT NOT NULL,
    interface TEXT,                 -- 'eth0', 'wlan0', etc.
    rx_bytes_per_sec INTEGER,       -- Receive rate
    tx_bytes_per_sec INTEGER,       -- Transmit rate
    
    FOREIGN KEY (admin_id) REFERENCES Utilizatori(id)
);

CREATE INDEX IF NOT EXISTS idx_bw_timestamp ON BandwidthStats(timestamp);
CREATE INDEX IF NOT EXISTS idx_bw_host ON BandwidthStats(host);

-- ============================================================================
-- Example queries for network monitoring dashboard
-- ============================================================================

-- Get protocol distribution (last 5 minutes)
-- SELECT protocol, COUNT(*) as count 
-- FROM NetworkFlows 
-- WHERE admin_id = ? AND timestamp > datetime('now', '-5 minutes')
-- GROUP BY protocol;

-- Get top remote connections
-- SELECT remote_addr, remote_port, COUNT(*) as connection_count
-- FROM NetworkFlows
-- WHERE admin_id = ? AND timestamp > datetime('now', '-1 hour')
-- GROUP BY remote_addr, remote_port
-- ORDER BY connection_count DESC
-- LIMIT 10;

-- Get port scan alerts with details
-- SELECT a.*, p.ports_scanned, p.scan_type
-- FROM Alerts a
-- JOIN PortScanDetails p ON a.id = p.alert_id
-- WHERE a.rule_id = 'port_scan' AND a.state = 'open';
