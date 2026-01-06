#!/usr/bin/env bash
set -euo pipefail

: <<'ROADMAP'
NetworkDeviceMonitor_Retele — SIEM Completion Roadmap (Wazuh-inspired)
Date: 2026-01-05

This file is a roadmap document stored as a runnable shell script.
Everything below is documentation (a heredoc block).

======================================================================
0) Goal (what “done” means)
======================================================================
Primary requirement (Docs/cerinta.txt):
Implement a platform for network operations monitoring and security incident monitoring.
Must provide a centralized dashboard with metrics/statistics generated from logs collected from:
- network equipment (routers/switches/firewalls)
- endpoints (workstations)
- servers
Must be:
- multiuser
- multithreaded
- configurable dashboard
- capable of collecting native syslog
- modular (add data sources, agents, filters)
Must be demonstrated on physical/virtual infrastructure, allowing third‑party agents.

Definition of DONE (minimum acceptable SIEM MVP):
A. Ingestion
  A1. Native Syslog receiver works (UDP 514 and/or TCP syslog) and stores parsed events.
  A2. Agent/endpoint forwarder works (custom TCP protocol or agent) and stores events.
  A3. At least 3 distinct sources demonstrated:
      - one “network device” syslog sender (can be router emulator / Linux rsyslog acting as a device)
      - one endpoint source (Windows or Linux endpoint)
      - one server source (Linux server logs)
B. Normalization/Storage
  B1. Raw + structured fields stored, queryable, and retained by policy.
C. Multiuser
  C1. Real users with authentication; per-user/tenant isolation enforced.
D. Dashboard
  D1. Central dashboard shows metrics/statistics (not only live text).
  D2. Dashboard is configurable per user.
E. Modularity
  E1. Clear plugin-like interfaces for sources/filters/decoders.
F. Demonstration
  F1. Repeatable demo infrastructure (VMs/containers) and a written demo checklist.

======================================================================
1) Current State Snapshot (what exists today)
======================================================================
Server (C++):
- TCP server on 8080, newline-delimited commands.
- Thread pool auto-scales (min 8 -> max 128).
- Recognizes REGISTER, HEARTBEAT, BATCH_EVENT; replies ACK/RESULTS.
- SQLite storage exists, but saves only a generic log message for BATCH_EVENT.

Client:
- PyQt6 GUI connects/sends REGISTER/HEARTBEAT and tails /var/log/syslog into BATCH_EVENT.
- C++ CLI client also tails /var/log/syslog.

Gaps vs SIEM MVP:
- No native syslog receiver.
- No true multiuser/tenant isolation.
- No metrics/statistics dashboard.
- No modular pipeline interfaces.
- DB schema too small (events not stored properly).

======================================================================
2) Architecture Target (Wazuh-inspired, simplified)
======================================================================
Components:
1) Ingestion inputs
   - SyslogReceiver(UDP/TCP)
   - AgentReceiver(CustomTCP EVENT)
   - Optional: Importer endpoint for 3rd-party tools

2) Pipeline (modular stages)
   - Decode/Parse
   - Normalize
   - Enrich
   - Filter
   - Store
   - Correlate/Alert

3) Storage
   - SQLite for prototype, structured schema.
   - Retention job.

4) Query API
   - A small query protocol over TCP (or add HTTP later).

5) Dashboard
   - Keep PyQt dashboard, add panels and historical queries.
   - (Creative option) add a lightweight web dashboard.

Design rule:
- Every input produces a RawEvent.
- Pipeline converts RawEvent -> NormalizedEvent.
- Only NormalizedEvent is stored and used for metrics/alerts.

======================================================================
3) Roadmap Overview (phases)
======================================================================
Phase 1 — Foundation: store real events + query
Phase 2 — Native syslog ingestion (mandatory)
Phase 3 — Multiuser + tenant isolation (mandatory)
Phase 4 — Dashboard metrics + configurable layout (mandatory)
Phase 5 — Modularity: sources/agents/filters/decoders (mandatory)
Phase 6 — Correlation/alerts (SIEM core)
Phase 7 — Infrastructure demo + third-party integration (mandatory)
Phase 8 — Security hardening + creative extensions (bonus)

Each phase below includes:
- Tasks
- Deliverables
- Acceptance tests (how you prove it works)

======================================================================
PHASE 1 — Foundation: store REAL events + historical queries
======================================================================
Objective:
Turn the project from a “networking prototype” into a “log platform core” by storing real
incoming events and enabling historical queries.

1.1 Database schema upgrade (SQLite)
Tasks:
- Replace the current Loguri table usage with a real Events table.
- Keep Loguri only for internal server logs if you want.

Proposed tables (minimal SIEM MVP):
- tenants(id, name, created_at)
- users(id, tenant_id, username UNIQUE within tenant, password_hash, role, created_at)
- sources(id, tenant_id, type, name, config_json, last_seen)
- events(id, tenant_id, source_id, ingest_time, event_time, src_ip, host, app, severity,
         facility, category, event_type, message, raw, parsed_ok)
- dashboards(id, user_id, name, layout_json, created_at, updated_at)
- rules(id, tenant_id, name, enabled, severity, rule_json, created_at)
- alerts(id, tenant_id, rule_id, event_id, created_at, state, score, summary)

Deliverables:
- Migration logic in server startup: create missing tables.
- Update BATCH_EVENT handler to store actual message content.

Acceptance tests:
- Send BATCH_EVENT with a real log line; confirm it appears in DB as raw/message.
- Query last 100 events and display them in UI.

1.2 Protocol additions for querying
Tasks:
- Add commands for query:
  - QUERY_EVENTS <since_epoch> <limit>
  - QUERY_EVENTS_FILTER <since_epoch> <limit> <key=value;key=value>
  - QUERY_METRICS <since_epoch> <bucket_seconds>

Deliverables:
- Server recognizes query commands and returns RESULTS JSON (or a safe text format).
- Client can request recent events and show them.

Acceptance tests:
- Query returns consistent results across reconnects.
- Basic filters work (severity, host, src_ip).

======================================================================
PHASE 2 — Native Syslog ingestion (MANDATORY)
======================================================================
Objective:
Satisfy “capable to collect native syslog” from cerinta.txt.

2.1 Syslog UDP receiver on port 514
Tasks:
- Add a dedicated receiver thread that binds UDP 514.
- For each packet:
  - capture src_ip, recv_time, payload
  - pass into pipeline/DB

Deliverables:
- SyslogUdpReceiver module.

Acceptance tests:
- From a Linux VM: `logger --server <server_ip> --udp --port 514 "test"`
  and the event is stored + visible.

2.2 RFC5424 parser/decoder (minimum viable)
Tasks:
- Parse PRI to facility/severity.
- Parse header fields if present (timestamp/hostname/app/procid/msgid).
- If parse fails: store raw and mark parsed_ok=false.

Deliverables:
- SyslogParser.

Acceptance tests:
- Send a valid RFC5424 message and confirm structured fields are populated.
- Send a malformed syslog string; confirm it still stores raw safely.

2.3 Optional: Syslog TCP receiver
Tasks:
- Accept TCP connections on 514 and parse newline-delimited frames (start simple).

Acceptance tests:
- `logger --server <ip> --tcp --port 514` works.

======================================================================
PHASE 3 — Multiuser + tenant isolation (MANDATORY)
======================================================================
Objective:
Satisfy “Platforma va fi multiuser” and avoid cross-user data exposure.

3.1 Authentication
Tasks:
- Replace placeholder DB check with real auth.
- Add commands:
  - AUTH_REGISTER <tenant> <username> <password>
  - AUTH_LOGIN <tenant> <username> <password>
  - AUTH_LOGOUT
- Implement password hashing (Argon2/bcrypt preferred; PBKDF2 acceptable).

Deliverables:
- User creation/login.
- Session token per connection.

Acceptance tests:
- Two users can login.
- Invalid password is rejected.

3.2 Authorization
Tasks:
- Add roles: admin / analyst / viewer.
- Enforce: queries return only tenant’s events.

Acceptance tests:
- User in tenant A cannot query tenant B events.

3.3 Tenant mapping for syslog senders
Tasks:
- Add configuration mapping: src_ip ranges -> tenant_id.
- Store source_id per sender.

Acceptance tests:
- Two syslog senders mapped to different tenants; queries are isolated.

======================================================================
PHASE 4 — Dashboard Metrics + Configurable Dashboard (MANDATORY)
======================================================================
Objective:
Satisfy “afiseaza centralizat, intr-un dashboard, metrici si statistici” and “dashboard configurabil”.

4.1 Define the required dashboard metrics (minimum)
Panels (must be real metrics, not just text):
- Events over time (bucketed counts)
- Severity distribution
- Top sources (by src_ip / host)
- Recent alerts (when Phase 6 is done)
- Ingestion health (connected agents, syslog messages per minute)

4.2 Implement server-side metrics queries
Tasks:
- Implement QUERY_METRICS for:
  - count per time bucket
  - severity histogram
  - top hosts/src_ips

Acceptance tests:
- Metrics change when you generate events.

4.3 Implement configurable dashboards
Minimum viable interpretation:
- Each user can save:
  - which widgets are visible
  - time range default
  - refresh interval
- Store as JSON in dashboards table.

Acceptance tests:
- Two users have different saved dashboards.

4.4 Update PyQt UI
Tasks:
- Add a “Metrics” area (tabs or panels) and a “Dashboard Settings” section.
- Keep it simple but functional.

Acceptance tests:
- Demo shows metrics updating live and historical views.

======================================================================
PHASE 5 — Modularity: sources, agents, filters (MANDATORY)
======================================================================
Objective:
Satisfy “modulara – cu posibilitatea de a adauga surse de date, agenti si filtre”.

5.1 Define extension interfaces
Server-side interfaces (C++):
- IInputSource: start/stop, emits RawEvent
- IDecoder: can_handle(raw) -> bool, decode(raw) -> NormalizedEvent
- IFilter: apply(event) -> decision (drop/keep/transform)

5.2 Implement a registry
Tasks:
- On startup, register built-in modules:
  - SyslogUdpReceiver
  - TcpAgentReceiver
  - Decoders: RFC5424, simple auth decoder
  - Filters: rate limit filter, tenant mapping filter

Acceptance tests:
- Adding a new decoder requires only adding a new file and registering it.

5.3 Agent model
Tasks:
- Standardize agent messages as EVENT JSON.
- Add agent metadata message: AGENT_HELLO with host/os/version.

Acceptance tests:
- Server tracks last_seen per agent.

======================================================================
PHASE 6 — Correlation and Alerts (SIEM core)
======================================================================
Objective:
Move from “log collection” to “incident/security monitoring”.

6.1 Rule engine (Wazuh-inspired)
Rule types (implement in this order):
- Match rule: if decoder == X and field == Y -> alert
- Threshold rule: N events with same key within T -> alert
- Sequence rule (optional): pattern A then B within T -> alert

Rule storage:
- rules.rule_json stores conditions.

Acceptance tests:
- Generate repeated failed logins -> alert triggers.

6.2 Alert lifecycle
Tasks:
- Alert states: open / acknowledged / closed.
- Store alerts table and link to events.

Acceptance tests:
- Alerts can be listed and changed state.

6.3 Dashboard integration
Tasks:
- Alerts panel
- Severity score

Acceptance tests:
- Alert appears immediately after trigger.

======================================================================
PHASE 7 — Real Infrastructure + Third-party agents (MANDATORY)
======================================================================
Objective:
Satisfy “Implementarea presupune configurarea unei infrastructuri fizice sau virtuale …
se va putea instala software third party (agenti)”.

7.1 Minimal virtual lab (recommended)
Suggested setup (works even on Windows host):
- Server: run in a Linux VM or WSL2 (because server uses POSIX sockets includes).
- VM1 (ServerLogs): Ubuntu VM sending syslog to server (rsyslog/logger).
- VM2 (Endpoint): another VM/WSL agent sending events via custom TCP.
- Optional: router emulator or a “network device simulator” via rsyslog.

Deliverables:
- A one-page setup checklist and IP/port map.

7.2 Third-party integration (choose one)
Options:
A) Wazuh agent installed on a VM, configure it to forward alerts via syslog to your server.
B) Suricata installed on a VM, forward EVE JSON or syslog alerts.
C) Sysmon on Windows endpoint, forward events through your Windows agent.

Acceptance tests:
- Show at least one third-party generated event flowing into your DB and dashboard.

======================================================================
PHASE 8 — Security + Advanced creativity (BONUS)
======================================================================
Objective:
Make it “better than required” and justify SIEM claim.

8.1 Transport security
Tasks:
- Add TLS for custom TCP channel.
- Optionally add mTLS for agent authentication.

Acceptance tests:
- Wireshark shows encrypted payload.

8.2 On-device privacy boundaries
Tasks:
- Ensure agents send only necessary fields; keep raw logs, but consider redaction filters.

8.3 ML/anomaly detection (optional bonus)
If you want to use ONNX Runtime reference:
- Baseline event rate per host and detect spikes.
- Output alerts with “why” (rate deviation).

8.4 Web dashboard (optional bonus)
- Add a lightweight web UI for read-only views.

======================================================================
PHASE 9 — Agents & Endpoint Telemetry (MANDATORY for endpoints/servers)
======================================================================
Objective:
Satisfy “log-uri colectate din … endpoints si servere” with a real agent story
that works on your Windows development machine.

9.1 Linux agent (quick win, reliable)
Tasks:
- Expand the current client tailer into an “agent mode” that can:
  - tail /var/log/syslog and /var/log/auth.log (or journald if available)
  - attach host metadata (host.name, host.ip, os.name, agent.version)
  - send structured EVENT JSON (preferred) rather than plain BATCH_EVENT
- Add heartbeat/health:
  - AGENT_HEARTBEAT <uptime> <events_sent> <queue_depth>

Acceptance tests:
- You can show endpoint + server logs from two Linux VMs (or VM + WSL2).

9.2 Windows endpoint support (choose one)
Option A (fast demo):
- Run the server in WSL2/Linux VM; keep the PyQt dashboard on Windows.
- Use WSL2 as an “endpoint agent” to generate and forward logs.

Option B (real endpoint agent):
- Implement a Windows service/agent that reads Windows Event Log:
  - channels: Security, System, Application
  - forward as EVENT JSON
- Add a minimal event mapping (e.g., login failure, service install, firewall change).

Acceptance tests:
- At least one real Windows Security log type is forwarded and visible.

9.3 Third-party agents (explicitly supported)
Goal: satisfy the “third party agents” clause via documented integrations.
Choose at least one and make it part of the final demo:
- Wazuh agent installed on a VM and configured to forward alerts/events via syslog to your server.
- Suricata installed on a VM; forward alerts via syslog or EVE JSON; decode + alert.
- Sysmon on Windows; forward via your Windows agent.

Acceptance tests:
- At least one third-party generated event appears in your DB and dashboard.

======================================================================
PHASE 10 — Security Hardening (recommended to credibly claim SIEM)
======================================================================
Objective:
Reduce the most obvious security/robustness risks while keeping scope realistic.

10.1 Input hardening
Tasks:
- Message size limits (per packet/per line/per JSON)
- Strict JSON validation for EVENT
- Rate limiting per session/source_ip
- Audit log table for admin actions:
  - user created/deleted
  - rules changed
  - dashboard changes

Acceptance tests:
- Oversized input is rejected safely.
- Flood traffic triggers rate limiting without server crash.

10.2 Transport security (bonus but strongly recommended)
Tasks:
- TLS for the custom TCP protocol (optionally mTLS for agents)

Acceptance tests:
- Wireshark shows encrypted payload.

======================================================================
PHASE 11 — Deployment & Infrastructure (MANDATORY)
======================================================================
Objective:
Provide a reproducible physical/virtual infrastructure and show collection
from multiple source types.

11.1 Reproducible lab environment
Option 1 (recommended): Docker Compose
- server container (manager)
- optional dashboard container
- syslog-generator container
- optional suricata container

Option 2: VirtualBox/VMware
- Ubuntu VM as syslog sender
- router/firewall emulator OR another Linux VM simulating a “network device”
- Windows endpoint OR WSL2-based endpoint agent

Deliverables:
- A simple topology diagram (IPs, ports, roles)
- A step-by-step “Demo Setup” checklist

Acceptance tests:
- End-to-end ingestion from:
  - at least one native syslog sender
  - at least one endpoint agent
  - both visible centrally in the dashboard

======================================================================
PHASE 12 — Testing, Wireshark, and Performance Proof
======================================================================
Objective:
Make the project presentation-grade: repeatable demos, measurable behavior.

12.1 Wireshark demonstration script
Show:
- TCP handshake + AUTH_LOGIN
- EVENT ingestion
- Syslog UDP packet capture on port 514
- Invalid command -> error response

12.2 Load test
Tasks:
- Simulate N syslog messages/sec (simple generator)
- Simulate multiple agents
- Track and display:
  - ingest rate
  - queue depth
  - DB write latency (approx)
  - thread pool scaling events

Acceptance tests:
- Under load, server remains responsive and continues storing events.

======================================================================
PHASE 13 — Documentation (final deliverables)
======================================================================
Objective:
Produce documentation that makes your project understandable and “complete”.

13.1 Protocol specification
Tasks:
- Document all supported commands (AUTH, EVENT, QUERY_*, etc)
- Define error codes and expected responses
- Include syslog ingestion behavior (RFC5424 fields stored)

13.2 User/admin docs
Tasks:
- How to add a syslog source
- How to add an agent
- How to add a decoder/filter
- How to create users/tenants
- How to build the lab environment

13.3 (Optional) Technical report update
If you maintain a LNCS report, ensure it matches the implemented protocol and architecture.

======================================================================
14) Milestones (keep execution focused)
======================================================================
Milestone A — Requirements-complete SIEM MVP
- Native syslog ingestion + parsing
- Normalized event storage (events table)
- Multiuser auth + tenant isolation
- Metrics/statistics dashboard + configurable widgets
- Modular pipeline interfaces (inputs/filters/decoders)
- Demo infra + a repeatable demo checklist

Milestone B — SIEM+ (creativity)
- Rule engine + alerts UI
- One integration: Suricata OR Wazuh-forwarded alerts OR ML anomaly detection
- Performance/load section with real numbers

Milestone C — Polish
- Hardening: TLS, rate limits, retention
- Clean build/run instructions

======================================================================
4) Recommended Build Order (fastest path to full requirements)
======================================================================
Order is chosen to unlock requirements early:
1) Store real events + query (Phase 1)
2) Native syslog receiver (Phase 2)  <-- mandatory, high impact
3) Multiuser isolation (Phase 3)     <-- mandatory
4) Metrics dashboard + configurable (Phase 4) <-- mandatory
5) Modularity interfaces (Phase 5)   <-- mandatory
6) Alerts rules (Phase 6)            <-- SIEM core
7) Infrastructure + 3rd party agent (Phase 7) <-- mandatory
8) Security + bonus (Phase 8)

======================================================================
5) Demo Checklist (what you show in final presentation)
======================================================================
- Show dashboard metrics: events/min, severity histogram, top sources.
- Show syslog native ingestion from a VM/device.
- Show endpoint agent ingestion.
- Show 2 users and isolation.
- Trigger a correlation rule -> alert.
- Show modularity by enabling/disabling a filter or decoder.
- Show infrastructure topology (VM diagram).

======================================================================
6) Concrete Acceptance Matrix (map each cerinta.txt clause)
======================================================================
Clause: “platforma de monitorizare a operatiunilor de retea si a incidentelor de securitate”
- Evidence: alerts + correlation rules + network syslog sources.

Clause: “dashboard metrici si statistici generate din log-uri”
- Evidence: metrics queries + charts/panels.

Clause: “log-uri colectate din echipamente de retea, endpoints si servere”
- Evidence: demo sources: syslog sender (network), endpoint agent, server syslog.

Clause: “multiuser”
- Evidence: auth + tenants + isolation.

Clause: “multithreaded”
- Evidence: thread pool + separate pipelines.

Clause: “dashboard configurabl”
- Evidence: saved widget config per user.

Clause: “colecteze nativ syslog”
- Evidence: UDP/TCP 514 capture + parsed RFC5424.

Clause: “modulara – surse, agenti, filtre”
- Evidence: source/decoder/filter registry + easy add.

Clause: “infrastructura fizica/virtuala + third party agents”
- Evidence: VM lab + one third-party tool integration.

======================================================================
7) Notes for Windows Development
======================================================================
- Current server/client C++ use POSIX headers (netinet/in.h, sys/socket.h, unistd.h).
  On Windows, easiest is WSL2 or a Linux VM for the server build/run.
- PyQt dashboard runs on Windows fine and can connect to server in WSL2/VM.

ROADMAP

# If you want, add utility commands here later (build/run scripts).
# For now this file is purely the roadmap text.

