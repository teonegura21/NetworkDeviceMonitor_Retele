#!/bin/bash

# Configuration
SIEM_SERVER=${SIEM_SERVER:-192.168.122.100}
SIEM_PORT=${SIEM_PORT:-514}

echo "🖥️ Starting Normal Workstation Agent..."
echo "Target SIEM: $SIEM_SERVER:$SIEM_PORT"

# Create agent config file
cat > nms_agent.conf <<EOL
server_ip=$SIEM_SERVER
server_port=$SIEM_PORT
hostname=$(hostname)
check_interval=5
interfaces=eth0
EOL

echo "📄 Config created:"
cat nms_agent.conf

# Start the agent in background
echo "🚀 Starting NMS Agent..."
/usr/local/bin/nms-agent &

# Simulate normal user behavior
echo "🌐 Simulating web browsing..."

while true; do
    # 1. Web browsing (HTTP/HTTPS)
    TARGETS=("www.google.com" "www.youtube.com" "www.github.com" "www.wikipedia.org" "www.reddit.com" "stackoverflow.com")
    RANDOM_SITE=${TARGETS[$RANDOM % ${#TARGETS[@]}]}
    
    echo "   Browsing: $RANDOM_SITE"
    curl -L -s -o /dev/null "https://$RANDOM_SITE"
    
    # 2. DNS Lookups
    nslookup $RANDOM_SITE > /dev/null 2>&1
    
    # 3. Random sleep (trapezoidal distribution-ish, mostly 5-30s)
    SLEEP_TIME=$((5 + RANDOM % 25))
    sleep $SLEEP_TIME
done
