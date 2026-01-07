#!/bin/bash
# setup_udp_logging.sh
# Configure iptables to log all incoming UDP packets for port scan detection.
# Requires root privileges!

set -e

echo "==========================================="
echo "  UDP Logging Setup for Port Scan Detection"
echo "==========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Error: This script requires root privileges."
    echo "   Please run with: sudo ./setup_udp_logging.sh"
    exit 1
fi

# Define the log prefix we'll search for
LOG_PREFIX="UDP_IN: "

echo "📋 Current iptables INPUT rules:"
iptables -L INPUT -n --line-numbers | head -10
echo ""

# Check if rule already exists
if iptables -L INPUT -n | grep -q "UDP_IN:"; then
    echo "✅ UDP logging rule already exists!"
else
    echo "➕ Adding UDP logging rule..."
    
    # Log all incoming UDP packets
    # -p udp: Match UDP protocol
    # -j LOG: Jump to LOG target
    # --log-prefix: Adds prefix for easy parsing
    # --log-level 4: Warning level (appears in kern.log)
    iptables -A INPUT -p udp -j LOG --log-prefix "$LOG_PREFIX" --log-level 4
    
    echo "✅ Rule added!"
fi

echo ""
echo "📋 Updated iptables INPUT rules:"
iptables -L INPUT -n --line-numbers | head -15
echo ""

# Configure rsyslog to ensure kern.log exists
if [ -f /etc/rsyslog.conf ]; then
    echo "📝 Checking rsyslog configuration..."
    if grep -q "kern\..*\/var\/log\/kern\.log" /etc/rsyslog.conf; then
        echo "✅ kern.log logging already configured"
    else
        echo "⚠️  Note: Make sure kernel messages go to /var/log/kern.log"
        echo "   You may need to check /var/log/syslog or dmesg instead."
    fi
fi

echo ""
echo "==========================================="
echo "  Setup Complete!"
echo "==========================================="
echo ""
echo "UDP packets will now be logged with prefix: $LOG_PREFIX"
echo ""
echo "To view logged UDP packets:"
echo "  tail -f /var/log/kern.log | grep 'UDP_IN'"
echo "  or"  
echo "  dmesg -w | grep 'UDP_IN'"
echo ""
echo "To test, send a UDP packet to a closed port:"
echo "  echo 'test' | nc -u localhost 54321"
echo ""
echo "To remove the logging rule later:"
echo "  sudo iptables -D INPUT -p udp -j LOG --log-prefix \"$LOG_PREFIX\" --log-level 4"
echo ""
