#!/bin/bash
# Start ML Anomaly Detection Service
cd "$(dirname "$0")"

echo "🤖 Starting ML Anomaly Detection Service..."
echo "   Database: ../SQL.lite_db/nms_romania.db"
echo "   Model: log_anomaly_detector.onnx"
echo ""

# Check if model exists
if [ ! -f "log_anomaly_detector.onnx" ]; then
    echo "❌ Model not found! Run ./train.sh first"
    exit 1
fi

# Run service
ml_venv/bin/python3 ml_service.py
