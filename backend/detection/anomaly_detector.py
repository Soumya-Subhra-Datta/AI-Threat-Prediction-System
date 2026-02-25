"""
Network Anomaly Detection Module
Uses trained autoencoder to detect anomalies in network traffic
"""

import os
import sys
import numpy as np
import pandas as pd
import joblib
import tensorflow as tf
from tensorflow import keras

def get_project_root():
    """Get the project root directory"""
    possible_roots = [
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),  # backend/detection/
        os.path.dirname(os.getcwd()),  # One level up from cwd
        os.getcwd(),  # Current working directory
        os.path.join(os.path.expanduser('~'), 'OneDrive', 'Desktop', 'ai-threat-detection-system'),
    ]
    
    if sys.platform == 'win32':
        possible_roots.append('C:/Users/soumy/OneDrive/Desktop/ai-threat-detection-system')
    
    for root in possible_roots:
        model_path = os.path.join(root, 'backend', 'model')
        if os.path.exists(model_path):
            return root
    
    return os.getcwd()

PROJECT_ROOT = get_project_root()
MODEL_DIR = os.path.join(PROJECT_ROOT, 'backend', 'model')

class AnomalyDetector:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.config = None
        self.threshold = None
        self.feature_columns = None
        self.is_loaded = False
        
    def load_model(self):
        """Load the trained model and scaler"""
        if self.is_loaded:
            return True
            
        model_path = os.path.join(MODEL_DIR, 'autoencoder_model.keras')
        scaler_path = os.path.join(MODEL_DIR, 'scaler.pkl')
        config_path = os.path.join(MODEL_DIR, 'model_config.pkl')
        
        if not os.path.exists(model_path):
            print(f"Model not found at {model_path}")
            print("Please run train_autoencoder.py first.")
            return False
            
        try:
            self.model = keras.models.load_model(model_path)
            self.scaler = joblib.load(scaler_path)
            self.config = joblib.load(config_path)
            self.threshold = self.config['threshold']
            self.feature_columns = self.config['feature_columns']
            self.is_loaded = True
            print(f"Model loaded successfully. Threshold: {self.threshold:.6f}")
            return True
        except Exception as e:
            print(f"Error loading model: {str(e)}")
            return False
    
    def detect_anomaly(self, data):
        """Detect anomaly in network traffic data"""
        if not self.is_loaded:
            if not self.load_model():
                return None
                
        try:
            # Prepare data
            if isinstance(data, pd.DataFrame):
                X = data.copy()
            else:
                X = pd.DataFrame([data])
            
            # Use only the feature columns the model was trained on
            available_cols = [col for col in self.feature_columns if col in X.columns]
            X = X[available_cols]
            
            # Handle missing values
            X = X.replace([np.inf, -np.inf], np.nan)
            X = X.fillna(0)
            
            # Ensure we have all required columns
            for col in self.feature_columns:
                if col not in X.columns:
                    X[col] = 0
            
            X = X[self.feature_columns]
            
            # Scale the data
            X_scaled = self.scaler.transform(X)
            
            # Get reconstruction
            X_pred = self.model.predict(X_scaled, verbose=0)
            
            # Calculate reconstruction error (MSE)
            mse = np.mean(np.power(X_scaled - X_pred, 2), axis=1)
            
            # Determine if anomalous
            is_anomaly = mse > self.threshold
            
            # Classify severity based on how far above threshold
            severity = []
            for error in mse:
                if error > self.threshold * 10:
                    severity.append('Critical')
                elif error > self.threshold * 5:
                    severity.append('High')
                elif error > self.threshold * 2:
                    severity.append('Medium')
                else:
                    severity.append('Low')
            
            results = []
            for i in range(len(mse)):
                results.append({
                    'anomaly': bool(is_anomaly[i]),
                    'anomaly_score': float(mse[i]),
                    'threshold': float(self.threshold),
                    'severity': severity[i]
                })
            
            return results[0] if len(results) == 1 else results
            
        except Exception as e:
            print(f"Error in anomaly detection: {str(e)}")
            return None
    
    def get_model_info(self):
        """Get information about the loaded model"""
        if not self.is_loaded:
            if not self.load_model():
                return {
                    'loaded': False,
                    'message': 'Model not loaded'
                }
        return {
            'loaded': True,
            'threshold': float(self.threshold),
            'num_features': len(self.feature_columns),
            'features': self.feature_columns[:10]  # First 10 features
        }

# Singleton instance
_detector = None

def get_detector():
    global _detector
    if _detector is None:
        _detector = AnomalyDetector()
    return _detector
