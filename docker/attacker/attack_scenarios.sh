#!/bin/bash

# Target configuration
TARGET=${TARGET_IP:-192.168.122.100}

echo "🎯 Starting Attack Wave against $TARGET"

# 1. TCP SYN Scan (Stealthy)
echo "   [1/5] Running TCP SYN scan..."
nmap -sS -p 1-1000 $TARGET --min-rate 100 > /dev/null 2>&1
sleep 5

# 2. UDP Scan (Selected ports)
echo "   [2/5] Running UDP scan..."
# Scan common ports: DNS(53), DHCP(67/68), TFTP(69), NTP(123), SNMP(161/162), Syslog(514)
nmap -sU -p 53,67,68,69,123,161,162,514 $TARGET --min-rate 50 > /dev/null 2>&1
sleep 5

# 3. Version Detection (Noisier)
echo "   [3/5] Running Service Version Detection..."
nmap -sV -p 8080,514,22 $TARGET > /dev/null 2>&1
sleep 5

# 4. Aggressive Scan
echo "   [4/5] Running Aggressive Scan..."
nmap -A -T4 -p 8080 $TARGET > /dev/null 2>&1
sleep 5

# 5. SYN Flood Simulation (hping3)
if command -v hping3 &> /dev/null; then
    echo "   [5/5] Simulating SYN Flood (10 packets)..."
    hping3 -S -p 8080 -c 10 --fast $TARGET > /dev/null 2>&1
else
    echo "   [5/5] hping3 not installed, skipping flood."
fi

echo "✅ Attack Wave Complete."
