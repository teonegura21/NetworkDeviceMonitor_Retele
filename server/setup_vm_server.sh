#!/bin/bash
# Script to setup SIEM Server on Ubuntu VM
# Run this INSIDE the VM!

set -e

echo "🚀 Setting up SIEM Server..."

# 1. Install dependencies
echo "📦 Installing dependencies..."
sudo apt-get update
sudo apt-get install -y build-essential g++ libsqlite3-dev python3.11-venv python3-pip

# 2. Compile Server
echo "🔨 Compiling Server..."
cd server_source
g++ -std=c++17 -pthread -o Main_Server \
    Main_Server.cpp Logic_Server.cpp Commands_Processing.cpp \
    RFC5424Parser.cpp SyslogReceiver.cpp ../SQL.lite_db/db.cpp \
    -lsqlite3

if [ $? -eq 0 ]; then
    echo "✅ Compilation successful!"
else
    echo "❌ Compilation failed!"
    exit 1
fi

# 3. Setup ML Environment
echo "🤖 Setting up ML Environment..."
cd ../ml
if [ ! -d "ml_venv" ]; then
    python3 -m venv ml_venv
fi

source ml_venv/bin/activate
pip install onnxruntime numpy scikit-learn

echo ""
echo "✅ Setup Complete!"
echo ""
echo "Find your IP address with: ip a"
echo "Then update docker-compose.yml on your host machine."
echo ""
echo "To run the server:"
echo "cd ~/path/to/server/server_source"
echo "sudo ./Main_Server"
