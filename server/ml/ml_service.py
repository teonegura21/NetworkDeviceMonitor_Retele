#!/usr/bin/env python3
"""
ML Anomaly Detection Service
Continuous background service that analyzes logs and creates alerts
"""

import time
import sqlite3
import pickle
import onnxruntime as rt
from datetime import datetime
import numpy as np
import sys
import os

class MLService:
    def __init__(self, db_path, model_path, vectorizer_path):
        """Initialize ML service with model and database"""
        self.db_path = db_path
        
        # Load ONNX model
        print(f"📦 Loading ONNX model: {model_path}")
        self.session = rt.InferenceSession(model_path)
        self.input_name = self.session.get_inputs()[0].name
        print(f"✅ Model loaded (input: {self.input_name})")
        
        # Load TF-IDF vectorizer
        print(f"📊 Loading vectorizer: {vectorizer_path}")
        with open(vectorizer_path, 'rb') as f:
            self.vectorizer = pickle.load(f)
        print(f"✅ Vectorizer loaded (vocab size: {len(self.vectorizer.vocabulary_)})")
        
        # Database connection
        self.db = None
        self._connect_db()
        
        # Statistics
        self.total_analyzed = 0
        self.total_anomalies = 0
    
    def _connect_db(self):
        """Connect to database"""
        try:
            self.db = sqlite3.connect(self.db_path, check_same_thread=False)
            self.db.row_factory = sqlite3.Row
            print(f"✅ Connected to database: {self.db_path}")
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
            sys.exit(1)
    
    def fetch_unanalyzed_logs(self, limit=100):
        """Fetch logs that haven't been analyzed by ML yet"""
        cursor = self.db.cursor()
        cursor.execute("""
            SELECT id, mesaj, src_ip, timestamp 
            FROM Loguri 
            WHERE ml_analyzed = 0 
            ORDER BY timestamp DESC 
            LIMIT ?
        """, (limit,))
        return cursor.fetchall()
    
    def analyze_logs(self, logs):
        """Run ML inference on batch of logs"""
        if not logs:
            return
        
        # Extract data
        log_ids = [log['id'] for log in logs]
        messages = [log['mesaj'] for log in logs]
        sources = [log['src_ip'] or 'unknown' for log in logs]
        timestamps = [log['timestamp'] for log in logs]
        
        # TF-IDF feature extraction
        try:
            features = self.vectorizer.transform(messages).toarray().astype(np.float32)
        except Exception as e:
            print(f"❌ Feature extraction failed: {e}")
            return
        
        # ML inference
        try:
            predictions = self.session.run(None, {self.input_name: features})[0]
        except Exception as e:
            print(f"❌ ML inference failed: {e}")
            return
        
        # Process results
        anomaly_count = 0
        for log_id, message, source, timestamp, pred in zip(log_ids, messages, sources, timestamps, predictions):
            # Isolation Forest returns 1 for inliers, -1 for outliers
            # pred might be array or scalar, extract value safely
            if isinstance(pred, np.ndarray):
                prediction_value = int(pred.item()) if pred.size == 1 else int(pred[0])
            else:
                prediction_value = int(pred)
            
            is_anomaly = (prediction_value == -1)
            
            # For Isolation Forest, we don't have a continuous score in predictions
            # Use -1 for anomaly, 1 for normal
            score = float(prediction_value)
            
            # Update log with ML analysis
            self.db.execute("""
                UPDATE Loguri 
                SET ml_analyzed = 1, ml_score = ? 
                WHERE id = ?
            """, (score, log_id))
            
            # Create alert if anomaly detected
            if is_anomaly:
                self.create_alert(log_id, message, source, score)
                anomaly_count += 1
        
        self.db.commit()
        
        # Update statistics
        self.total_analyzed += len(logs)
        self.total_anomalies += anomaly_count
        
        print(f"✅ Analyzed {len(logs)} logs → {anomaly_count} anomalies detected "
              f"(total: {self.total_anomalies}/{self.total_analyzed})")
    
    def create_alert(self, event_id, message, source, score):
        """Create alert for detected anomaly"""
        # Determine severity based on score
        # More negative = more anomalous
        if score < -0.7:
            severity = 2  # Critical
        elif score < -0.5:
            severity = 3  # Error
        else:
            severity = 4  # Warning
        
        try:
            self.db.execute("""
                INSERT INTO Alerts (event_id, rule_id, ml_score, severity, state)
                VALUES (?, 'ml_anomaly', ?, ?, 'open')
            """, (event_id, score, severity))
            
            # Truncate message for logging
            msg_preview = message[:80] + "..." if len(message) > 80 else message
            print(f"  🚨 ALERT #{event_id}: {msg_preview} (score={score:.3f}, sev={severity})")
        
        except Exception as e:
            print(f"  ❌ Failed to create alert: {e}")
    
    def get_stats(self):
        """Get service statistics"""
        cursor = self.db.cursor()
        
        # Count unanalyzed logs
        cursor.execute("SELECT COUNT(*) FROM Loguri WHERE ml_analyzed = 0")
        unanalyzed = cursor.fetchone()[0]
        
        # Count open alerts
        cursor.execute("SELECT COUNT(*) FROM Alerts WHERE state = 'open'")
        open_alerts = cursor.fetchone()[0]
        
        return {
            'unanalyzed_logs': unanalyzed,
            'open_alerts': open_alerts,
            'total_analyzed': self.total_analyzed,
            'total_anomalies': self.total_anomalies,
            'detection_rate': f"{(self.total_anomalies/self.total_analyzed*100):.1f}%" if self.total_analyzed > 0 else "N/A"
        }
    
    def run(self, poll_interval=5, batch_size=100):
        """Main service loop"""
        print("=" * 60)
        print("🤖 ML Anomaly Detection Service Started")
        print("=" * 60)
        print(f"Poll interval: {poll_interval}s")
        print(f"Batch size: {batch_size}")
        print("Press Ctrl+C to stop")
        print("=" * 60)
        
        iteration = 0
        try:
            while True:
                iteration += 1
                
                # Fetch and analyze logs
                logs = self.fetch_unanalyzed_logs(batch_size)
                if logs:
                    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Iteration #{iteration}")
                    self.analyze_logs(logs)
                else:
                    # No new logs
                    if iteration % 12 == 0:  # Every minute if 5s interval
                        stats = self.get_stats()
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                              f"Idle - {stats['open_alerts']} open alerts, "
                              f"{stats['unanalyzed_logs']} logs pending")
                
                time.sleep(poll_interval)
        
        except KeyboardInterrupt:
            print("\n\n⏹ Service stopped by user")
            stats = self.get_stats()
            print(f"\nFinal Statistics:")
            print(f"  - Logs analyzed: {stats['total_analyzed']}")
            print(f"  - Anomalies found: {stats['total_anomalies']} ({stats['detection_rate']})")
            print(f"  - Open alerts: {stats['open_alerts']}")
            print(f"  - Unanalyzed logs: {stats['unanalyzed_logs']}")
        
        except Exception as e:
            print(f"\n❌ Service error: {e}")
            import traceback
            traceback.print_exc()
        
        finally:
            if self.db:
                self.db.close()
                print("✅ Database connection closed")

def main():
    # Configuration
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DB_PATH = os.path.join(BASE_DIR, "../SQL.lite_db/nms_romania.db")
    MODEL_PATH = os.path.join(BASE_DIR, "log_anomaly_detector.onnx")
    VECTORIZER_PATH = os.path.join(BASE_DIR, "vectorizer.pkl")
    
    # Validate files exist
    for path, name in [(DB_PATH, "Database"), (MODEL_PATH, "Model"), (VECTORIZER_PATH, "Vectorizer")]:
        if not os.path.exists(path):
            print(f"❌ {name} not found: {path}")
            sys.exit(1)
    
    # Create service
    service = MLService(
        db_path=DB_PATH,
        model_path=MODEL_PATH,
        vectorizer_path=VECTORIZER_PATH
    )
    
    # Run
    service.run(poll_interval=5, batch_size=100)

if __name__ == "__main__":
    main()
