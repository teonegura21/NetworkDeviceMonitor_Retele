#!/usr/bin/env python3
"""
Isolation Forest Log Anomaly Detection - Training Script
Trains on normal log samples and exports to ONNX format
"""

import sys
import sqlite3
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
import pickle
import json

def load_logs_from_db(db_path, limit=10000):
    """Load recent normal logs from database"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get recent logs (assuming most are normal)
    cursor.execute("""
        SELECT mesaj FROM Loguri 
        ORDER BY timestamp DESC 
        LIMIT ?
    """, (limit,))
    
    logs = [row[0] for row in cursor.fetchall() if row[0]]
    conn.close()
    
    print(f"✅ Loaded {len(logs)} log samples from database")
    return logs

def extract_features(logs, max_features=100):
    """Extract TF-IDF features from log messages"""
    print(f"📊 Extracting features (max_features={max_features})...")
    
    vectorizer = TfidfVectorizer(
        max_features=max_features,
        ngram_range=(1, 2),  # Unigrams and bigrams
        min_df=2,  # Ignore very rare terms
        max_df=0.95,  # Ignore very common terms
        strip_accents='unicode',
        lowercase=True
    )
    
    features = vectorizer.fit_transform(logs).toarray()
    
    print(f"✅ Feature matrix shape: {features.shape}")
    return features, vectorizer

def train_isolation_forest(features, contamination=0.05):
    """Train Isolation Forest model"""
    print(f"🤖 Training Isolation Forest (contamination={contamination})...")
    
    model = IsolationForest(
        contamination=contamination,  # Expected % of anomalies
        n_estimators=100,
        max_samples='auto',
        n_jobs=-1,  # Use all CPU cores
        random_state=42,
        verbose=1
    )
    
    model.fit(features)
    
    # Test predictions
    predictions = model.predict(features)
    n_anomalies = np.sum(predictions == -1)
    
    print(f"✅ Training complete!")
    print(f"   - Normal logs: {np.sum(predictions == 1)}")
    print(f"   - Anomalies detected: {n_anomalies} ({n_anomalies/len(predictions)*100:.1f}%)")
    
    return model

def save_model(model, vectorizer, output_dir=None):
    """Save model and vectorizer"""
    if output_dir is None:
        output_dir = os.path.dirname(os.path.abspath(__file__))
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Save scikit-learn model
    model_path = f"{output_dir}/isolation_forest.pkl"
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    print(f"✅ Model saved: {model_path}")
    
    # Save vectorizer
    vectorizer_path = f"{output_dir}/vectorizer.pkl"
    with open(vectorizer_path, 'wb') as f:
        pickle.dump(vectorizer, f)
    print(f"✅ Vectorizer saved: {vectorizer_path}")
    
    # Save metadata
    metadata = {
        'n_features': vectorizer.max_features,
        'contamination': model.contamination,
        'n_estimators': model.n_estimators,
        'vocabulary_size': len(vectorizer.vocabulary_)
    }
    
    metadata_path = f"{output_dir}/model_metadata.json"
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"✅ Metadata saved: {metadata_path}")
    
    return model_path, vectorizer_path

def export_to_onnx(model_path, vectorizer_path, output_dir=None):
    """Export to ONNX format using skl2onnx"""
    if output_dir is None:
        output_dir = os.path.dirname(os.path.abspath(__file__))
    try:
        from skl2onnx import to_onnx
        from skl2onnx.common.data_types import FloatTensorType
        import pickle
        
        print("📦 Converting to ONNX format...")
        
        # Load model
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        
        # Define input type (adjust feature count as needed)
        with open(f"{output_dir}/model_metadata.json", 'r') as f:
            import json
            metadata = json.load(f)
            n_features = metadata['n_features']
        
        initial_type = [('float_input', FloatTensorType([None, n_features]))]
        
        # Convert with target opset for compatibility
        onnx_model = to_onnx(
            model, 
            initial_types=initial_type,
            target_opset={'': 15, 'ai.onnx.ml': 3}  # Compatible versions
        )
        
        # Save
        onnx_path = f"{output_dir}/log_anomaly_detector.onnx"
        with open(onnx_path, 'wb') as f:
            f.write(onnx_model.SerializeToString())
        
        print(f"✅ ONNX model exported: {onnx_path}")
        
        # Get file size
        import os
        size_mb = os.path.getsize(onnx_path) / (1024 * 1024)
        print(f"   Model size: {size_mb:.2f} MB")
        
        return onnx_path
        
    except ImportError as e:
        print(f"⚠️  skl2onnx not installed: {e}")
        print("   Install with: pip install skl2onnx")
        print("   Skipping ONNX export for now")
        return None

def test_inference(model, vectorizer, test_logs):
    """Test inference on sample logs"""
    print("\n🧪 Testing inference on sample logs...")
    
    for log in test_logs:
        features = vectorizer.transform([log]).toarray()
        prediction = model.predict(features)[0]
        score = model.score_samples(features)[0]
        
        status = "✅ NORMAL" if prediction == 1 else "🚨 ANOMALY"
        print(f"{status} (score={score:.3f}): {log[:80]}...")

def main():
    print("=" * 60)
    print("Isolation Forest Log Anomaly Detection - Training")
    print("=" * 60)
    
    # Configuration
    import os
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DB_PATH = os.path.join(BASE_DIR, "../SQL.lite_db/nms_romania.db")
    SAMPLE_SIZE = 10000
    MAX_FEATURES = 200  # Increased from 100 for better coverage
    CONTAMINATION = 0.05
    
    # Step 1: Load logs
    logs = load_logs_from_db(DB_PATH, SAMPLE_SIZE)
    
    if len(logs) < 100:
        print("❌ Not enough log samples (need at least 100)")
        sys.exit(1)
    
    # Step 2: Extract features
    features, vectorizer = extract_features(logs, MAX_FEATURES)
    
    # Step 3: Train model
    model = train_isolation_forest(features, CONTAMINATION)
    
    # Step 4: Save model
    model_path, vectorizer_path = save_model(model, vectorizer)
    
    # Step 5: Export to ONNX
    onnx_path = export_to_onnx(model_path, vectorizer_path)
    
    # Step 6: Test on sample logs
    test_samples = [
        "User login successful from 192.168.1.100",
        "CRITICAL ERROR: Database connection failed",
        "System startup complete",
        "FATAL PANIC: Out of memory kernel crash"
    ]
    test_inference(model, vectorizer, test_samples)
    
    print("\n" + "=" * 60)
    print("✅ Training complete!")
    print("=" * 60)
    print(f"Model: {model_path}")
    print(f"Vectorizer: {vectorizer_path}")
    if onnx_path:
        print(f"ONNX: {onnx_path}")
    print("\nNext steps:")
    print("1. pip install isolation-forest-onnx (if not done)")
    print("2. Implement C++ ONNX inference")
    print("3. Integrate into SyslogReceiver")

if __name__ == "__main__":
    main()
