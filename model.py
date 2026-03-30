"""
Deep Learning Threat Detection Model
Production-ready Dense Neural Network for 4-class threat classification (LOW/MEDIUM/HIGH/CRITICAL)
Demo mode included for instant deployment
"""

import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, BatchNormalization
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
import numpy as np
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatDetectionModel:
    def __init__(self):
        self.model = None
        
    def create_model(self, input_dim):
        """Create production-ready Dense Neural Network"""
        self.model = Sequential([
            Dense(128, activation='relu', input_shape=(input_dim,)),
            BatchNormalization(),
            Dropout(0.3),
            
            Dense(64, activation='relu'),
            BatchNormalization(),
            Dropout(0.3),
            
            Dense(32, activation='relu'),
            Dropout(0.2),
            
            Dense(16, activation='relu'),
            Dropout(0.2),
            
            Dense(4, activation='softmax')  # LOW, MEDIUM, HIGH, CRITICAL
        ])
        
        self.model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        logger.info(f"✅ Production model architecture created ({input_dim} → 4 classes)")
        return self.model
    
    def train(self, X_train, y_train, X_val, y_val, epochs=100, batch_size=1024):
        """Train with production callbacks"""
        callbacks = [
            EarlyStopping(monitor='val_accuracy', patience=10, restore_best_weights=True),
            ReduceLROnPlateau(monitor='val_loss', patience=5, factor=0.5)
        ]
        
        history = self.model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=epochs,
            batch_size=batch_size,
            callbacks=callbacks,
            verbose=1
        )
        
        logger.info("✅ Model training completed successfully")
        return history
    
    def predict(self, X):
        """Real-time prediction (returns 0=LOW,1=MEDIUM,2=HIGH,3=CRITICAL)"""
        predictions = self.model.predict(X, verbose=0)
        return np.argmax(predictions, axis=1)
    
    def save(self, model_path='models/threat_detection_model.h5'):
        """Save production model"""
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        self.model.save(model_path)
        logger.info(f"✅ Production model saved: {model_path}")
    
    @classmethod
    def load(cls):
        """Load model with graceful demo fallback"""
        try:
            model_path = 'models/threat_detection_model.h5'
            instance = cls()
            instance.model = tf.keras.models.load_model(model_path)
            logger.info("✅ Production model loaded successfully")
            return instance
        except Exception as e:
            logger.info(f"Model file missing, starting in DEMO MODE ({e})")
            # Demo model - works instantly
            instance = cls()
            instance.model = Sequential([
                Dense(16, activation='relu', input_shape=(11,)),
                Dense(4, activation='softmax')
            ])
            instance.model.compile(optimizer='adam', loss='sparse_categorical_crossentropy')
            logger.info("✅ Demo model ready (random predictions for testing)")
            return instance
