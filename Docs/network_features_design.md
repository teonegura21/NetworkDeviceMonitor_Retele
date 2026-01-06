# Network Monitoring Features - Technical Design

## Feature 1: Network Flow Analysis 🌐

### Overview
Real-time monitoring of network connections on each monitored system, tracking bandwidth usage, protocol distribution, and connection states.

---

### Technical Architecture

#### Data Flow
```
Linux System → ss/netstat → Parser → Network Event → SIEM Server → Dashboard
                                          ↓
                                    Flow Database
```

#### Components

**1. Flow Collector (Python - runs on each agent)**
```python
# agent/network_monitor.py

import subprocess
import time
import socket
from collections import defaultdict

class NetworkFlowMonitor:
    def __init__(self):
        self.flows = {}
        self.bandwidth_tracker = defaultdict(lambda: {"rx": 0, "tx": 0})
    
    def collect_flows(self):
        """Collect active network connections using ss command"""
        # ss -tunap gives: Protocol, Local IP:Port, Remote IP:Port, State, Process
        cmd = "ss -tunap -o"
        output = subprocess.check_output(cmd, shell=True).decode()
        
        flows = []
        for line in output.split('\n')[1:]:  # Skip header
            if not line.strip():
                continue
            
            flow = self.parse_ss_line(line)
            if flow:
                flows.append(flow)
        
        return flows
    
    def parse_ss_line(self, line):
        """Parse ss output line into structured data"""
        # Example line: tcp ESTAB 0 0 192.168.1.10:50123 8.8.8.8:443 users:(("chrome",pid=1234))
        parts = line.split()
        
        if len(parts) < 5:
            return None
        
        protocol = parts[0]  # tcp/udp
        state = parts[1]     # ESTAB, TIME-WAIT, etc.
        local = parts[4]     # local_ip:port
        remote = parts[5]    # remote_ip:port
        
        # Extract process info if available
        process = None
        if 'users:' in line:
            # Parse: users:(("firefox",pid=5678))
            start = line.find('users:((') + 8
            end = line.find(',pid=')
            if start > 7 and end > start:
                process = line[start:end].strip('"')
        
        return {
            "protocol": protocol.upper(),
            "state": state,
            "local_addr": local.split(':')[0] if ':' in local else local,
            "local_port": int(local.split(':')[1]) if ':' in local else 0,
            "remote_addr": remote.split(':')[0] if ':' in remote else remote,
            "remote_port": int(remote.split(':')[1]) if ':' in remote else 0,
            "process": process,
            "timestamp": time.time()
        }
    
    def get_bandwidth_stats(self):
        """Get current bandwidth using /proc/net/dev"""
        with open('/proc/net/dev', 'r') as f:
            lines = f.readlines()[2:]  # Skip headers
        
        stats = {}
        for line in lines:
            parts = line.split()
            iface = parts[0].rstrip(':')
            rx_bytes = int(parts[1])
            tx_bytes = int(parts[9])
            
            stats[iface] = {
                "rx_bytes": rx_bytes,
                "tx_bytes": tx_bytes
            }
        
        return stats
    
    def send_flow_update(self, flows, bandwidth):
        """Send flow data to SIEM as syslog RFC5424"""
        for flow in flows:
            message = (
                f"NETWORK_FLOW: {flow['protocol']} "
                f"{flow['local_addr']}:{flow['local_port']} -> "
                f"{flow['remote_addr']}:{flow['remote_port']} "
                f"state={flow['state']} process={flow['process']}"
            )
            
            # Send via syslog
            self.send_syslog(message, severity=6)  # Informational
    
    def run(self, interval=10):
        """Main monitoring loop"""
        while True:
            flows = self.collect_flows()
            bandwidth = self.get_bandwidth_stats()
            
            self.send_flow_update(flows, bandwidth)
            time.sleep(interval)
```

**2. Server-Side Flow Processor**
```python
# server/ml/network_flow_processor.py

class NetworkFlowProcessor:
    def __init__(self, db_path):
        self.db = sqlite3.connect(db_path)
        self.create_tables()
    
    def create_tables(self):
        """Create network flow tables"""
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS NetworkFlows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                admin_id INTEGER,
                source_host TEXT,
                protocol TEXT,
                local_addr TEXT,
                local_port INTEGER,
                remote_addr TEXT,
                remote_port INTEGER,
                state TEXT,
                process TEXT,
                bytes_sent INTEGER DEFAULT 0,
                bytes_received INTEGER DEFAULT 0
            )
        """)
        
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS BandwidthStats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                admin_id INTEGER,
                host TEXT,
                interface TEXT,
                rx_bytes_per_sec INTEGER,
                tx_bytes_per_sec INTEGER
            )
        """)
        
        # Indexes for performance
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_flows_time ON NetworkFlows(timestamp)")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_flows_remote ON NetworkFlows(remote_addr)")
        self.db.commit()
    
    def process_flow_log(self, log_message, admin_id, source_ip):
        """Parse NETWORK_FLOW log and store"""
        # Parse: "NETWORK_FLOW: TCP 192.168.1.10:50123 -> 8.8.8.8:443 state=ESTAB process=chrome"
        
        import re
        pattern = r'NETWORK_FLOW: (\w+) ([\d.]+):(\d+) -> ([\d.]+):(\d+) state=(\w+) process=(\w+)'
        match = re.search(pattern, log_message)
        
        if match:
            protocol, local_addr, local_port, remote_addr, remote_port, state, process = match.groups()
            
            self.db.execute("""
                INSERT INTO NetworkFlows 
                (admin_id, source_host, protocol, local_addr, local_port, 
                 remote_addr, remote_port, state, process)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (admin_id, source_ip, protocol, local_addr, int(local_port),
                  remote_addr, int(remote_port), state, process))
            
            self.db.commit()
    
    def get_active_flows_summary(self, admin_id, last_minutes=5):
        """Get summary of recent flows"""
        cursor = self.db.execute("""
            SELECT 
                protocol,
                COUNT(*) as count,
                COUNT(DISTINCT remote_addr) as unique_remotes
            FROM NetworkFlows
            WHERE admin_id = ?
              AND timestamp > datetime('now', '-' || ? || ' minutes')
            GROUP BY protocol
        """, (admin_id, last_minutes))
        
        return cursor.fetchall()
    
    def get_top_connections(self, admin_id, limit=10):
        """Get most frequent remote destinations"""
        cursor = self.db.execute("""
            SELECT 
                remote_addr,
                remote_port,
                COUNT(*) as connection_count,
                MAX(timestamp) as last_seen
            FROM NetworkFlows
            WHERE admin_id = ?
              AND timestamp > datetime('now', '-1 hour')
            GROUP BY remote_addr, remote_port
            ORDER BY connection_count DESC
            LIMIT ?
        """, (admin_id, limit))
        
        return cursor.fetchall()
```

**3. Dashboard Integration**
```python
# client/client_gui_v2.py - Add to Dashboard tab

def _create_network_flows_widget(self):
    """Network flows visualization"""
    widget = QGroupBox("🌐 Network Activity (Live)")
    layout = QVBoxLayout()
    
    # Protocol distribution chart
    self.protocol_chart = QChartView()
    layout.addWidget(self.protocol_chart)
    
    # Top connections table
    self.connections_table = QTableWidget()
    self.connections_table.setColumnCount(4)
    self.connections_table.setHorizontalHeaderLabels([
        "Remote IP", "Port", "Connections", "Protocol"
    ])
    layout.addWidget(self.connections_table)
    
    widget.setLayout(layout)
    return widget

def _update_network_flows(self):
    """Fetch and display network flow data"""
    if not self.client or not self.current_user:
        return
    
    # Query server for flow stats
    cmd = f"QUERY_NETWORK_FLOWS {self.current_user} 300"  # Last 5 min
    if self.client.send(cmd):
        response = self.client.receive()
        if response and "ACK RESULTS" in response:
            self._populate_network_flows(response)
```

---

## Feature 2: Port Scanner Detection 🔍

### Overview
Detect port scanning activities by analyzing connection patterns - multiple connection attempts to different ports from a single source in a short time window.

---

### Port Scan Detection Algorithm

#### Pattern Recognition
```
Port Scan Indicators:
1. Many connections to DIFFERENT ports
2. From SINGLE source IP
3. In SHORT time window (<60 seconds)
4. Many connections FAILED or SYN-only

Example:
Source: 185.142.x.x
Time: 14:30:00-14:30:45
Attempts:
  → port 22 (SSH)    - REFUSED
  → port 23 (Telnet) - REFUSED
  → port 80 (HTTP)   - REFUSED
  → port 443 (HTTPS) - ESTAB
  → port 3306 (MySQL)- REFUSED
  → port 8080        - REFUSED
  
→ ALERT: Port scan detected!
```

#### Detection Logic
```python
# server/ml/port_scan_detector.py

from collections import defaultdict
from datetime import datetime, timedelta

class PortScanDetector:
    def __init__(self, db_path):
        self.db = sqlite3.connect(db_path)
        self.scan_cache = defaultdict(list)  # IP → [(port, timestamp)]
        
        # Thresholds
        self.PORT_THRESHOLD = 5      # Min ports to trigger alert
        self.TIME_WINDOW = 60        # Seconds
        self.DIFFERENT_PORTS = True  # Must be different ports
    
    def analyze_connection_attempt(self, source_ip, dest_port, state, timestamp):
        """Check if this connection is part of a scan"""
        
        # Add to cache
        self.scan_cache[source_ip].append({
            "port": dest_port,
            "state": state,
            "timestamp": timestamp
        })
        
        # Clean old entries (older than time window)
        cutoff_time = datetime.now() - timedelta(seconds=self.TIME_WINDOW)
        self.scan_cache[source_ip] = [
            entry for entry in self.scan_cache[source_ip]
            if entry["timestamp"] > cutoff_time
        ]
        
        # Check if scan pattern detected
        if self.is_port_scan(source_ip):
            self.create_scan_alert(source_ip)
    
    def is_port_scan(self, source_ip):
        """Determine if IP is performing a port scan"""
        attempts = self.scan_cache[source_ip]
        
        if len(attempts) < self.PORT_THRESHOLD:
            return False
        
        # Count unique ports attempted
        unique_ports = len(set(a["port"] for a in attempts))
        
        if unique_ports < self.PORT_THRESHOLD:
            return False  # Same port repeated, not a scan
        
        # Check for many failed connections (typical of scans)
        failed_states = ["SYN-SENT", "REFUSED", "CLOSED"]
        failed_count = sum(1 for a in attempts if a["state"] in failed_states)
        
        # If >70% failed, likely a scan
        if failed_count / len(attempts) > 0.7:
            return True
        
        # Or if accessing many sequential ports
        ports = sorted([a["port"] for a in attempts])
        sequential_count = 0
        for i in range(len(ports) - 1):
            if ports[i+1] - ports[i] <= 2:  # Sequential or close together
                sequential_count += 1
        
        if sequential_count > unique_ports * 0.6:
            return True  # Likely sequential scan
        
        return False
    
    def create_scan_alert(self, source_ip):
        """Create high-priority alert for port scan"""
        attempts = self.scan_cache[source_ip]
        ports_scanned = set(a["port"] for a in attempts)
        
        alert_message = (
            f"PORT SCAN DETECTED from {source_ip}! "
            f"Scanned {len(ports_scanned)} ports in {self.TIME_WINDOW}s: "
            f"{', '.join(str(p) for p in sorted(ports_scanned)[:10])}"
        )
        
        # Store in Alerts table
        self.db.execute("""
            INSERT INTO Alerts (event_id, rule_id, severity, state, notes)
            VALUES (
                (SELECT id FROM Loguri WHERE src_ip = ? ORDER BY timestamp DESC LIMIT 1),
                'port_scan_detected',
                1,  -- Severity 1 = Critical (Alert)
                'open',
                ?
            )
        """, (source_ip, alert_message))
        
        self.db.commit()
        
        # Clear cache for this IP
        self.scan_cache[source_ip] = []
        
        print(f"🚨 {alert_message}")
    
    def get_scan_statistics(self, admin_id, last_hours=24):
        """Get port scan statistics"""
        cursor = self.db.execute("""
            SELECT COUNT(*) as scan_count,
                   COUNT(DISTINCT src_ip) as unique_scanners
            FROM Alerts a
            JOIN Loguri l ON a.event_id = l.id
            WHERE a.rule_id = 'port_scan_detected'
              AND l.admin_id = ?
              AND a.created_at > datetime('now', '-' || ? || ' hours')
        """, (admin_id, last_hours))
        
        return cursor.fetchone()
```

#### Integration with Flow Monitor
```python
# Combine port scan detection with flow monitoring

class NetworkSecurityMonitor:
    def __init__(self, db_path):
        self.flow_processor = NetworkFlowProcessor(db_path)
        self.scan_detector = PortScanDetector(db_path)
    
    def process_network_event(self, log_message, admin_id, source_ip):
        """Process network event - check for both flows and scans"""
        
        # Store flow data
        self.flow_processor.process_flow_log(log_message, admin_id, source_ip)
        
        # Extract connection details
        import re
        pattern = r'(\d+\.\d+\.\d+\.\d+):(\d+) -> (\d+\.\d+\.\d+\.\d+):(\d+) state=(\w+)'
        match = re.search(pattern, log_message)
        
        if match:
            local_ip, local_port, remote_ip, remote_port, state = match.groups()
            
            # Check if remote IP is scanning local system
            self.scan_detector.analyze_connection_attempt(
                source_ip=remote_ip,
                dest_port=int(local_port),
                state=state,
                timestamp=datetime.now()
            )
```

---

## Implementation Plan

### Phase 1: Network Flow Monitoring (4-6 hours)

**Step 1:** Create flow collection agent (2h)
- Implement `NetworkFlowMonitor` class
- Test `ss` command parsing
- Add syslog sending

**Step 2:** Server-side storage (1h)
- Create database tables
- Implement `NetworkFlowProcessor`
- Test flow ingestion

**Step 3:** Dashboard widgets (2h)
- Add protocol distribution chart
- Add top connections table
- Implement auto-refresh

**Step 4:** Testing (1h)
- Generate test traffic
- Verify flow tracking
- Check dashboard updates

### Phase 2: Port Scan Detection (3-4 hours)

**Step 1:** Detection algorithm (2h)
- Implement `PortScanDetector`
- Create pattern matching logic
- Test with simulated scans

**Step 2:** Alert integration (1h)
- Connect to Alerts table
- Create high-priority alerts
- Display in Alerts tab

**Step 3:** Testing (1h)
- Run `nmap` port scan against system
- Verify detection triggers
- Check alert appears in UI

---

## Testing Strategy

### Test 1: Normal Traffic
```bash
# Generate normal connections
curl https://google.com
ping 8.8.8.8
ssh user@server

# Expected: Flows shown in dashboard, NO scan alert
```

### Test 2: Port Scan
```bash
# Run nmap to simulate port scan
nmap -p 1-100 localhost

# Expected: 
# - Flows recorded
# - Port scan alert triggered
# - Alert appears in UI with list of scanned ports
```

### Test 3: High Traffic
```bash
# Generate many legitimate connections
for i in {1..50}; do curl https://example.com & done

# Expected:
# - All flows tracked
# - NO scan alert (same dest port 443)
# - Bandwidth stats updated
```

---

## UI Mockup

### Dashboard - Network Tab
```
┌────────────────────────────────────────────────────┐
│ 📊 Network Activity Dashboard                      │
├────────────────────────────────────────────────────┤
│                                                     │
│ Protocol Distribution (Last 5 min)                 │
│ ┌─────────────────────────────┐                   │
│ │ TCP: 78% ████████████░░░░░  │                   │
│ │ UDP: 22% █████░░░░░░░░░░░░  │                   │
│ └─────────────────────────────┘                   │
│                                                     │
│ Top Connections                                    │
│ ┌─────────────────────────────────────────────┐  │
│ │ Remote IP    │ Port │ Count │ Protocol      │  │
│ ├─────────────────────────────────────────────┤  │
│ │ 8.8.8.8      │ 53   │ 342   │ UDP (DNS)    │  │
│ │ 151.101.x.x  │ 443  │ 28    │ TCP (HTTPS)  │  │
│ │ 192.168.1.1  │ 53   │ 15    │ UDP (DNS)    │  │
│ └─────────────────────────────────────────────┘  │
│                                                     │
│ 🚨 Security Alerts                                 │
│ • Port scan detected from 185.142.x.x (87 ports)  │
│ • Unusual connection to TOR exit node             │
└────────────────────────────────────────────────────┘
```

---

## Expected Outcomes

**Network Flow Analysis:**
- ✅ Real-time connection monitoring
- ✅ Protocol statistics (TCP/UDP distribution)
- ✅ Bandwidth tracking per interface
- ✅ Top talkers identification

**Port Scanner Detection:**
- ✅ Automatic detection of nmap, masscan, etc.
- ✅ Pattern recognition (many ports, short time)
- ✅ High-priority security alerts
- ✅ Detailed scan information (ports list)

**Demonstrates for Networks Course:**
- TCP/UDP protocols
- Socket states (ESTAB, TIME_WAIT, etc.)
- Port numbers and services
- Network security concepts
- Traffic analysis
- Attack detection

---

## Time Estimate
- Network Flow: 4-6 hours
- Port Scanner Detection: 3-4 hours
- **Total: 7-10 hours**

Ready to start implementation?
