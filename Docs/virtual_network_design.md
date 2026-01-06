# Virtual Network Test Infrastructure

## Requirement
From `cerinta.txt`: "configurarea unei infrastructuri fizice sau virtuale cu echipamente active și/sau endpoints"

You need to demonstrate the SIEM working across multiple networked devices.

---

## Proposed Architecture

### Network Topology
```
                    Virtual Network: 172.20.0.0/24
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        │                     │                     │
   ┌────┴────┐          ┌────┴────┐          ┌────┴────┐
   │ SIEM    │          │ Agent1  │          │ Agent2  │
   │ Server  │          │ (Web)   │          │ (DB)    │
   │         │          │         │          │         │
   │ Port:   │          │ Logs:   │          │ Logs:   │
   │ 8080    │←─────────│ Apache  │          │ MySQL   │
   │ 514     │          │ Auth    │          │ Syslog  │
   └────┬────┘          └─────────┘          └─────────┘
        │                                          
        │                     │                     
   ┌────┴────┐          ┌────┴────┐          ┌─────────┐
   │ Client  │          │ Agent3  │          │ Attacker│
   │ PyQt6   │          │ (SSH)   │          │ (nmap)  │
   │ GUI     │          │         │          │         │
   └─────────┘          └─────────┘          └─────────┘
  172.20.0.10          172.20.0.13          172.20.0.100
```

### Components (6 nodes total)

1. **SIEM Server** (172.20.0.2)
   - C++ server (ports 8080, 514)
   - ML service (Python)
   - SQLite database

2. **Agent1 - Web Server** (172.20.0.11)
   - Ubuntu/Debian
   - Apache web server
   - NMS_Agent monitoring apache logs

3. **Agent2 - Database Server** (172.20.0.12)
   - Ubuntu/Debian  
   - MySQL database
   - NMS_Agent monitoring mysql logs

4. **Agent3 - SSH Server** (172.20.0.13)
   - Ubuntu/Debian
   - SSH server (openssh)
   - NMS_Agent monitoring auth.log

5. **Client Workstation** (172.20.0.10)
   - GUI client (PyQt6)
   - Connects to SIEM server

6. **Attacker Node** (172.20.0.100)
   - Kali Linux / Ubuntu with nmap
   - For testing port scan detection

---

## Implementation Option 1: Docker (Recommended) 🐳

**Advantages:**
- ✅ Fast setup (5-10 minutes)
- ✅ Lightweight (no full VMs)
- ✅ Easy to distribute (Docker Compose file)
- ✅ Reproducible environment

### Docker Compose Configuration

```yaml
# docker-compose.yml

version: '3.8'

networks:
  siem_network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24

services:
  # SIEM Server
  siem-server:
    build:
      context: ./server
      dockerfile: Dockerfile
    container_name: siem-server
    hostname: siem-server
    networks:
      siem_network:
        ipv4_address: 172.20.0.2
    ports:
      - "8080:8080"   # Client API
      - "514:514/tcp" # Syslog TCP
      - "514:514/udp" # Syslog UDP
    volumes:
      - ./server/SQL.lite_db:/app/database
      - ./server/ml:/app/ml
    command: /app/Main_Server

  # ML Service (runs alongside server)
  ml-service:
    build:
      context: ./server/ml
      dockerfile: Dockerfile.ml
    container_name: ml-service
    hostname: ml-service
    networks:
      - siem_network
    volumes:
      - ./server/SQL.lite_db:/app/database
      - ./server/ml:/app/ml
    depends_on:
      - siem-server
    command: python3 ml_service.py

  # Agent 1: Web Server
  agent-web:
    image: ubuntu:22.04
    container_name: agent-web
    hostname: web-server
    networks:
      siem_network:
        ipv4_address: 172.20.0.11
    volumes:
      - ./agent/NMS_Agent:/usr/local/bin/nms-agent
    command: |
      bash -c "
        apt-get update && apt-get install -y apache2 &&
        service apache2 start &&
        /usr/local/bin/nms-agent
      "

  # Agent 2: Database Server
  agent-db:
    image: ubuntu:22.04
    container_name: agent-db
    hostname: db-server
    networks:
      siem_network:
        ipv4_address: 172.20.0.12
    volumes:
      - ./agent/NMS_Agent:/usr/local/bin/nms-agent
    command: |
      bash -c "
        apt-get update && apt-get install -y mysql-server &&
        service mysql start &&
        /usr/local/bin/nms-agent
      "

  # Agent 3: SSH Server
  agent-ssh:
    image: ubuntu:22.04
    container_name: agent-ssh
    hostname: ssh-server
    networks:
      siem_network:
        ipv4_address: 172.20.0.13
    volumes:
      - ./agent/NMS_Agent:/usr/local/bin/nms-agent
    command: |
      bash -c "
        apt-get update && apt-get install -y openssh-server &&
        service ssh start &&
        /usr/local/bin/nms-agent
      "

  # Client Workstation
  client:
    image: python:3.11
    container_name: siem-client
    hostname: client-ws
    networks:
      siem_network:
        ipv4_address: 172.20.0.10
    volumes:
      - ./client:/app
    environment:
      - DISPLAY=:0
    command: python3 /app/client_gui_v2.py

  # Attacker (for testing)
  attacker:
    image: kalilinux/kali-rolling
    container_name: attacker
    hostname: attacker
    networks:
      siem_network:
        ipv4_address: 172.20.0.100
    command: tail -f /dev/null  # Keep running
```

### Dockerfiles

**Server Dockerfile:**
```dockerfile
# server/Dockerfile
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    g++ \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY server_source/ /app/
COPY SQL.lite_db/ /app/database/

RUN g++ -o Main_Server Main_Server.cpp Logic_Server.cpp \
    Commands_Processing.cpp RFC5424Parser.cpp SyslogReceiver.cpp \
    ../database/db.cpp -lsqlite3 -pthread -std=c++17

EXPOSE 8080 514/tcp 514/udp

CMD ["/app/Main_Server"]
```

**ML Service Dockerfile:**
```dockerfile
# server/ml/Dockerfile.ml
FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/ml

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ml_service.py .
COPY *.pkl *.onnx *.json ./

CMD ["python3", "ml_service.py"]
```

### Setup & Run

```bash
# 1. Start all containers
docker-compose up -d

# 2. Check status
docker-compose ps

# 3. View logs
docker-compose logs -f siem-server

# 4. Access client container
docker exec -it siem-client bash

# 5. Test port scan
docker exec -it attacker nmap -p 1-100 172.20.0.11

# 6. Stop all
docker-compose down
```

---

## Implementation Option 2: VirtualBox VMs (More Realistic)

**Advantages:**
- ✅ Full OS simulation
- ✅ More realistic network behavior
- ✅ Can test actual network tools

### VM Configuration

**VM 1: SIEM Server**
- OS: Ubuntu Server 22.04
- RAM: 2 GB
- Network: Bridged Adapter
- IP: 192.168.1.100 (or static in your network)
- Install: Server + ML service

**VM 2-4: Agent Nodes**
- OS: Ubuntu Server 22.04 (minimal)
- RAM: 512 MB each
- Network: Bridged Adapter
- IPs: 192.168.1.101-103
- Install: NMS_Agent + service (apache/mysql/ssh)

**VM 5: Client**
- OS: Ubuntu Desktop 22.04
- RAM: 2 GB
- Network: Bridged Adapter
- Install: Python + PyQt6 + client

**VM 6: Attacker**
- OS: Kali Linux
- RAM: 2 GB
- Network: Bridged Adapter
- Tools: nmap, masscan

### Vagrant Configuration (Automated VM Setup)

```ruby
# Vagrantfile
Vagrant.configure("2") do |config|
  # SIEM Server
  config.vm.define "siem" do |siem|
    siem.vm.box = "ubuntu/jammy64"
    siem.vm.hostname = "siem-server"
    siem.vm.network "private_network", ip: "192.168.56.10"
    siem.vm.provider "virtualbox" do |vb|
      vb.memory = "2048"
    end
    siem.vm.provision "shell", path: "scripts/setup_server.sh"
  end

  # Agent 1: Web Server
  config.vm.define "agent1" do |agent|
    agent.vm.box = "ubuntu/jammy64"
    agent.vm.hostname = "web-server"
    agent.vm.network "private_network", ip: "192.168.56.11"
    agent.vm.provider "virtualbox" do |vb|
      vb.memory = "512"
    end
    agent.vm.provision "shell", inline: <<-SHELL
      apt-get update
      apt-get install -y apache2
      # Copy and run NMS_Agent
    SHELL
  end

  # Agent 2: Database Server
  config.vm.define "agent2" do |agent|
    agent.vm.box = "ubuntu/jammy64"
    agent.vm.hostname = "db-server"
    agent.vm.network "private_network", ip: "192.168.56.12"
    agent.vm.provider "virtualbox" do |vb|
      vb.memory = "512"
    end
    agent.vm.provision "shell", inline: <<-SHELL
      apt-get update
      apt-get install -y mysql-server
    SHELL
  end

  # ... more agents ...
end
```

```bash
# Start all VMs
vagrant up

# SSH into any VM
vagrant ssh siem

# Stop all
vagrant halt
```

---

## Implementation Option 3: Linux Network Namespaces (Lightweight)

**Advantages:**
- ✅ Extremely lightweight
- ✅ Native Linux feature
- ✅ No Docker/VM overhead

**Disadvantages:**
- ⚠️ Only works on Linux
- ⚠️ More manual setup

```bash
#!/bin/bash
# create_test_network.sh

# Create network namespaces
ip netns add siem-server
ip netns add agent1
ip netns add agent2
ip netns add client

# Create virtual ethernet pairs
ip link add veth-siem type veth peer name veth-br-siem
ip link add veth-a1 type veth peer name veth-br-a1
ip link add veth-a2 type veth peer name veth-br-a2
ip link add veth-client type veth peer name veth-br-client

# Create bridge
brctl addbr siem-br

# Attach to bridge
brctl addif siem-br veth-br-siem
brctl addif siem-br veth-br-a1
brctl addif siem-br veth-br-a2
brctl addif siem-br veth-br-client

# Move interfaces to namespaces
ip link set veth-siem netns siem-server
ip link set veth-a1 netns agent1
ip link set veth-a2 netns agent2
ip link set veth-client netns client

# Assign IPs
ip netns exec siem-server ip addr add 172.20.0.2/24 dev veth-siem
ip netns exec agent1 ip addr add 172.20.0.11/24 dev veth-a1
ip netns exec agent2 ip addr add 172.20.0.12/24 dev veth-a2
ip netns exec client ip addr add 172.20.0.10/24 dev veth-client

# Bring up interfaces
ip netns exec siem-server ip link set veth-siem up
ip netns exec agent1 ip link set veth-a1 up
# ... etc

# Run server in namespace
ip netns exec siem-server /path/to/Main_Server
```

---

## Recommended Approach: Docker 🚀

**Why Docker is best for demonstration:**
1. **Easy setup** - Single `docker-compose up` command
2. **Portable** - Share with professor via docker-compose.yml
3. **Fast** - Containers start in seconds
4. **Reproducible** - Works on any Linux/Mac/Windows with Docker
5. **Resource efficient** - Can run all 6 nodes on one laptop

**Setup time:** 10-15 minutes  
**Hardware needed:** 4 GB RAM minimum

---

## Testing Scenarios

### Scenario 1: Normal Operation
```bash
# Generate web traffic on agent1
docker exec agent-web bash -c "for i in {1..100}; do curl localhost; done"

# Expected: Logs appear in SIEM client Events tab
```

### Scenario 2: Port Scan Detection
```bash
# Run nmap from attacker
docker exec attacker nmap -p 1-100 172.20.0.11

# Expected: Port scan alert in SIEM Alerts tab
```

### Scenario 3: Failed Login Attempts
```bash
# Try SSH with wrong passwords
docker exec attacker bash -c "
  for i in {1..10}; do 
    sshpass -p wrong ssh user@172.20.0.13
  done
"

# Expected: Failed login alerts, ML detects anomaly
```

### Scenario 4: Network Flow Analysis
```bash
# Monitor active connections across all agents
# Expected: Dashboard shows TCP/UDP distribution, top connections
```

---

## Quick Start Guide

### Option 1: Docker (15 minutes)
```bash
# 1. Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# 2. Create docker-compose.yml (see above)
cd NetworkDeviceMonitor_Retele
nano docker-compose.yml

# 3. Build and start
docker-compose up -d

# 4. Verify
docker-compose ps
docker-compose logs -f

# 5. Test
docker exec attacker nmap -p 1-100 172.20.0.11
```

### Option 2: Vagrant + VirtualBox (30 minutes)
```bash
# 1. Install Vagrant & VirtualBox
sudo apt install vagrant virtualbox

# 2. Create Vagrantfile (see above)
nano Vagrantfile

# 3. Start VMs
vagrant up

# 4. Access any VM
vagrant ssh siem
```

---

## Deliverable for Demonstration

**What to show professor:**

1. **Network topology diagram** (from this document)
2. **Docker Compose file** or Vagrantfile
3. **Running demonstration:**
   - Show `docker ps` or `vagrant status` (6 nodes running)
   - Show client GUI connected to server
   - Generate events from agents
   - Demonstrate port scan detection
   - Show network flow analysis

**Documentation to include:**
- Setup instructions (this document)
- Network diagram
- Screenshots of all 6 nodes running
- Wireshark capture showing syslog traffic between nodes

---

## Time Estimate

| Approach | Setup Time | Demo Prep | Total |
|----------|-----------|-----------|-------|
| Docker | 15 min | 30 min | 45 min |
| Vagrant | 30 min | 30 min | 1 hour |
| Manual VMs | 2 hours | 30 min | 2.5 hours |

**Recommendation:** Docker for fastest deployment!

---

## Next Steps

1. Choose deployment method (Docker recommended)
2. Create configuration files
3. Test setup locally
4. Prepare demonstration script
5. Document virtual infrastructure

Ready to create the Docker Compose setup?
