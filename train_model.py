"""
Deep Learning Model Training Pipeline
Trains production-ready threat detection model on CICIDS2017 dataset
"""

import os
import sys
import logging
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split

# Add project root to path
sys.path.append(str(Path(__file__).parent))

from data_preprocessing import DataPreprocessor
from model import ThreatDetectionModel

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    print("🔥 Training Proactive Threat Detection Model")
    print("=" * 60)
    
    # Step 1: Data Preprocessing
    logger.info("📊 Loading and preprocessing CICIDS2017 datasets...")
    preprocessor = DataPreprocessor()
    X, y_labels, feature_names = preprocessor.load_and_preprocess_all()
    
    # Step 2: Prepare training data
    label_encoder = preprocessor.label_encoder
    y_numeric = label_encoder.transform(y_labels)
    
    logger.info(f"✅ Dataset ready: {X.shape[0]:,} samples, {X.shape[1]} features")
    logger.info(f"Threat distribution: {pd.Series(y_labels).value_counts().to_dict()}")
    
    # Step 3: Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_numeric, test_size=0.2, random_state=42, stratify=y_numeric
    )
    
    # Step 4: Create and train model
    logger.info("🧠 Creating Deep Learning model...")
    model = ThreatDetectionModel()
    model.create_model(X.shape[1])
    
    logger.info("🎯 Training model...")
    history = model.train(X_train, y_train, X_test, y_test, epochs=50)
    
    # Step 5: Final evaluation
    test_loss, test_accuracy = model.model.evaluate(X_test, y_test, verbose=0)
    predictions = model.predict(X_test)
    
    logger.info(f"🎉 FINAL RESULTS:")
    logger.info(f"   Test Accuracy: {test_accuracy:.4f} ({test_accuracy*100:.2f}%)")
    logger.info(f"   Test Samples: {len(X_test):,}")
    
    # Step 6: Save everything
    os.makedirs('models', exist_ok=True)
    model.save('models/threat_detection_model.h5')
    preprocessor.save_preprocessors()
    
    logger.info("💾 SAVED FILES:")
    logger.info("   models/threat_detection_model.h5")
    logger.info("   models/scaler.pkl") 
    logger.info("   models/label_encoder.pkl")
    
    print("\n✅ PRODUCTION MODEL READY!")
    print("Run: python app.py")
    print("Test: python simulate_threats.py")

if __name__ == "__main__":
    main()
