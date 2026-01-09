#!/bin/bash
# Script to setup ONLY the Agent on Ubuntu VM
# Usage: ./setup_vm_agent_only.sh
# REQUIREMENT: Place the 'NMS_Agent' binary in the same folder as this script before running!

# 192.168.122.1 is the default gateway for KVM/Libvirt NAT networks (connects to Host)
SIEM_SERVER="192.168.122.1"
SIEM_PORT=514

echo "🚀 Setting up NMS Agent on VM..."

# 0. Check for binary
if [ ! -f "NMS_Agent" ]; then
    echo "❌ Error: 'NMS_Agent' binary not found!"
    echo "   Please copy it to this folder: scp agent/NMS_Agent user@vm_ip:~/"
    exit 1
fi

# 1. Install runtime dependencies
echo "📦 Installing runtime dependencies..."
sudo apt-get update
sudo apt-get install -y libpcap0.8

# 2. Install Binary
echo "💿 Installing Binary..."
sudo cp NMS_Agent /usr/local/bin/nms-agent
sudo chmod +x /usr/local/bin/nms-agent

# 3. Create Config
echo "📝 Creating Configuration..."
# We write to the current directory where the binary expects it, or /etc?
# The agent likely looks for nms_agent.conf in current dir or specific path.
# Let's assume /usr/local/bin or put it in /etc and symlink if needed.
# For now, placing it where the service runs (WorkingDirectory).

sudo mkdir -p /etc/nms-agent
cat > nms_agent.conf <<EOL
server_ip=$SIEM_SERVER
server_port=$SIEM_PORT
hostname=$(hostname)
check_interval=5
interfaces=eth0
EOL
sudo mv nms_agent.conf /etc/nms-agent/

# 4. Create Systemd Service
echo "⚙️ Creating Systemd Service..."
sudo bash -c 'cat > /etc/systemd/system/nms-agent.service <<EOL
[Unit]
Description=NMS Monitoring Agent
After=network.target

[Service]
ExecStart=/usr/local/bin/nms-agent
WorkingDirectory=/etc/nms-agent
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOL'

# 5. Start Service
echo "🚀 Starting Service..."
sudo systemctl daemon-reload
sudo systemctl enable nms-agent
sudo systemctl start nms-agent

echo ""
echo "✅ Agent Installed and Running!"
echo "   Server: $SIEM_SERVER:$SIEM_PORT"
echo "   Status: sudo systemctl status nms-agent"
