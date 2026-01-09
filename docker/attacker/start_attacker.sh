#!/bin/bash

# Configuration
SIEM_SERVER=${SIEM_SERVER:-192.168.122.100}
SIEM_PORT=${SIEM_PORT:-514}
TARGET_IP=${TARGET_IP:-$SIEM_SERVER}

echo "🔴 Starting Attacker Agent..."
echo "Target SIEM: $SIEM_SERVER:$SIEM_PORT"
echo "Attack Target: $TARGET_IP"

# Create agent config file (monitoring itself)
cat > nms_agent.conf <<EOL
server_ip=$SIEM_SERVER
server_port=$SIEM_PORT
hostname=$(hostname)
check_interval=5
interfaces=eth0
EOL

# Start the agent in background
echo "🚀 Starting NMS Agent..."
/usr/local/bin/nms-agent &

# Wait for network stabilization
sleep 10

# Run attacks in a loop
while true; do
    echo "⚔️ Running attack scenarios..."
    /app/attack_scenarios.sh
    
    echo "💤 Sleeping 5 minutes before next wave..."
    sleep 300
done
