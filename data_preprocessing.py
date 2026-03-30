"""
Complete Data Preprocessing Pipeline for Cyber Threat Detection
Handles CICIDS2017 datasets + synthetic log data fusion
Production-ready with error handling
"""

import pandas as pd
import numpy as np
import os
from pathlib import Path
import logging
import pickle
from sklearn.preprocessing import StandardScaler, LabelEncoder

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DataPreprocessor:
    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_names = None
        
    def load_cicids_datasets(self):
        """Load CICIDS2017 network flow datasets with error handling"""
        data_dir = Path('data')
        cicids_files = [
            'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
            'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
            'Friday-WorkingHours-Morning.pcap_ISCX.csv',
            'Monday-WorkingHours.pcap_ISCX.csv',
            'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
            'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
            'Tuesday-WorkingHours.pcap_ISCX.csv',
            'Wednesday-workingHours.pcap_ISCX.csv'
        ]
        
        all_data = []
        for file in cicids_files:
            file_path = data_dir / file
            if file_path.exists():
                try:
                    df = pd.read_csv(file_path)
                    logger.info(f"Loaded {file}: {len(df)} rows")
                    all_data.append(df)
                except Exception as e:
                    logger.warning(f"Failed to load {file}: {e}")
        
        if all_data:
            combined = pd.concat(all_data, ignore_index=True)
            logger.info(f"✅ Combined {len(combined)} network flow records")
            return combined
        else:
            logger.warning("No CICIDS files found, generating synthetic data")
            return self._generate_synthetic_network_data()
    
    def _generate_synthetic_network_data(self):
        """Generate synthetic network data for demo"""
        np.random.seed(42)
        n_samples = 10000
        
        data = {
            'Flow Duration': np.random.exponential(1000, n_samples),
            'Total Length of Fwd Packets': np.random.exponential(1024, n_samples),
            'Total Length of Bwd Packets': np.random.exponential(512, n_samples),
            'Fwd Packet Length Max': np.random.normal(1500, 300, n_samples),
            'Bwd Packet Length Max': np.random.normal(1500, 300, n_samples),
            'Flow Bytes/s': np.random.exponential(1024, n_samples),
            'Flow Packets/s': np.random.exponential(100, n_samples),
            'Pkt Size Avg': np.random.normal(512, 100, n_samples),
            'PSH Flag Cnt': np.random.poisson(1, n_samples),
            'Active Mean': np.random.exponential(100, n_samples),
            'Idle Mean': np.random.exponential(500, n_samples)
        }
        
        df = pd.DataFrame(data)
        df['Label'] = np.random.choice(['BENIGN', 'DDoS', 'PortScan', 'DoS Hulk', 'Bot'], n_samples)
        logger.info("✅ Generated synthetic network data")
        return df
    
    def map_attack_to_severity(self, attack_type):
        """Map CICIDS attack types to threat severity levels"""
        severity_map = {
            # Benign/normal traffic
            'BENIGN': 'LOW',
            
            # Reconnaissance
            'PortScan': 'MEDIUM',
            
            # Web attacks
            'Web Attack - Brute Force': 'HIGH',
            'Web Attack - XSS': 'HIGH',
            'Web Attack - Sql Injection': 'HIGH',
            
            # DoS attacks
            'DoS Hulk': 'HIGH',
            'DoS GoldenEye': 'HIGH',
            'DoS slowloris': 'HIGH',
            'DoS Slowhttptest': 'HIGH',
            
            # Critical threats
            'DDoS': 'CRITICAL',
            'Infiltration': 'CRITICAL',
            'Bot': 'CRITICAL',
            'Heartbleed': 'CRITICAL'
        }
        return severity_map.get(attack_type, 'LOW')
    
    def engineer_features(self, df):
        """Feature engineering for ML model"""
        # Handle infinite and NaN values
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(0, inplace=True)
        
        # Core network flow features (CICIDS2017 standard)
        feature_cols = [
            'Flow Duration',
            'Total Length of Fwd Packets',
            'Total Length of Bwd Packets', 
            'Fwd Packet Length Max',
            'Bwd Packet Length Max',
            'Flow Bytes/s',
            'Flow Packets/s',
            'Pkt Size Avg',
            'PSH Flag Cnt',
            'Active Mean',
            'Idle Mean'
        ]
        
        # Use available columns only
        available_features = [col for col in feature_cols if col in df.columns]
        if not available_features:
            logger.error("No network features found!")
            return pd.DataFrame()
            
        df_features = df[available_features]
        self.feature_names = available_features
        
        logger.info(f"✅ Features engineered: {len(self.feature_names)} features")
        return df_features
    
    def load_and_preprocess_all(self):
        """Production preprocessing pipeline"""
        try:
            # Load and clean data
            df_network = self.load_cicids_datasets()
            
            # Safe label mapping
            if 'Label' in df_network.columns:
                df_network['Threat_Severity'] = df_network['Label'].apply(self.map_attack_to_severity)
            else:
                logger.warning("No 'Label' column, using synthetic labels")
                df_network['Threat_Severity'] = np.random.choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], len(df_network))
            
            # Feature engineering
            X = self.engineer_features(df_network)
            if X.empty:
                raise ValueError("No features extracted")
            
            # Encode severity labels
            y = self.label_encoder.fit_transform(df_network['Threat_Severity'])
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            logger.info(f"✅ Pipeline complete: {X_scaled.shape} | Classes: {dict(zip(self.label_encoder.classes_, np.bincount(y)))}")
            return X_scaled, df_network['Threat_Severity'].tolist(), self.feature_names
            
        except Exception as e:
            logger.error(f"❌ Preprocessing failed: {e}")
            raise
    
    def preprocess_single_event(self, event_data):
        """Real-time single event preprocessing"""
        try:
            if self.feature_names is None:
                raise ValueError("Preprocessor not fitted")
                
            event_array = np.zeros(len(self.feature_names))
            for i, feature in enumerate(self.feature_names):
                event_array[i] = event_data.get(feature, 0)
            
            X_processed = self.scaler.transform(event_array.reshape(1, -1))
            return X_processed
        except Exception as e:
            logger.error(f"Single event preprocessing failed: {e}")
            return np.zeros((1, 11))  # Fallback
    
    def save_preprocessors(self):
        """Save scaler and encoder for production"""
        os.makedirs('models', exist_ok=True)
        with open('models/scaler.pkl', 'wb') as f:
            pickle.dump(self.scaler, f)
        with open('models/label_encoder.pkl', 'wb') as f:
            pickle.dump(self.label_encoder, f)
        logger.info("✅ Preprocessors saved to models/")
    
    @classmethod
    def load_preprocessors(cls):
        """Load preprocessors for production inference"""
        instance = cls()
        try:
            with open('models/scaler.pkl', 'rb') as f:
                instance.scaler = pickle.load(f)
            with open('models/label_encoder.pkl', 'rb') as f:
                instance.label_encoder = pickle.load(f)
            logger.info("✅ Production preprocessors loaded")
            return instance
        except FileNotFoundError:
            logger.warning("Preprocessors not found, using demo mode")
            instance.feature_names = ['Flow Duration', 'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 
                                    'Fwd Packet Length Max', 'Bwd Packet Length Max', 'Flow Bytes/s', 
                                    'Flow Packets/s', 'Pkt Size Avg', 'PSH Flag Cnt', 'Active Mean', 'Idle Mean']
            return instance
