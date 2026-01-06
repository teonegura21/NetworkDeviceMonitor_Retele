#!/bin/bash
# Train and export Isolation Forest model
cd "$(dirname "$0")"

echo "🤖 Training Isolation Forest anomaly detector..."
ml_venv/bin/python3 train_isolation_forest.py

echo ""
echo "✅ Training complete! Model files in server/ml/"
echo ""
echo "Next steps:"
echo "1. Check model files: ls -lh *.pkl *.onnx"
echo "2. Implement C++ ONNX inference"
echo "3. Integrate into SyslogReceiver"
