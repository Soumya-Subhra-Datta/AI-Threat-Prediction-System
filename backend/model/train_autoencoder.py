"""
Autoencoder Model Training Script for Network Anomaly Detection
Uses TensorFlow/Keras to train an autoencoder on normal network traffic
"""

import os
import sys
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
import warnings
warnings.filterwarnings('ignore')

# Set random seeds for reproducibility
np.random.seed(42)
tf.random.set_seed(42)

# Get project root directory - handle different execution contexts
def get_project_root():
    """Get the project root directory"""
    # Check common possible locations
    possible_roots = [
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),  # backend/model/
        os.path.dirname(os.getcwd()),  # One level up from cwd
        os.getcwd(),  # Current working directory
        os.path.join(os.path.expanduser('~'), 'OneDrive', 'Desktop', 'ai-threat-detection-system'),
    ]
    
    # Add Windows-specific path
    if sys.platform == 'win32':
        possible_roots.append('C:/Users/soumy/OneDrive/Desktop/ai-threat-detection-system')
    
    for root in possible_roots:
        datasets_path = os.path.join(root, 'datasets')
        if os.path.exists(datasets_path):
            return root
    
    # Default to current directory
    return os.getcwd()

PROJECT_ROOT = get_project_root()
MODEL_DIR = os.path.join(PROJECT_ROOT, 'backend', 'model')
DATASETS_DIR = os.path.join(PROJECT_ROOT, 'datasets')

def find_dataset_file():
    """Find available dataset file in datasets directory"""
    import glob
    
    # Look for Monday file (normal traffic)
    monday_patterns = [
        os.path.join(DATASETS_DIR, 'Monday-WorkingHours.pcap_ISCX.csv'),
        os.path.join(DATASETS_DIR, '*Monday*.csv'),
        os.path.join(DATASETS_DIR, '*.csv'),
    ]
    
    for pattern in monday_patterns:
        matches = glob.glob(pattern)
        if matches:
            # Filter for files that exist and contain Monday
            for match in matches:
                if os.path.exists(match) and 'Monday' in os.path.basename(match):
                    return match
    
    # Fallback: find any CSV file
    all_csv = glob.glob(os.path.join(DATASETS_DIR, '*.csv'))
    if all_csv:
        # Prefer Monday file if exists
        for f in all_csv:
            if 'Monday' in os.path.basename(f):
                return f
        return all_csv[0]
    
    raise FileNotFoundError(f"No dataset found in {DATASETS_DIR}")

# Find the training file
TRAINING_FILE = find_dataset_file()
print(f"Using dataset: {TRAINING_FILE}")

def load_and_preprocess_data():
    """Load and preprocess network traffic data"""
    print("Loading network traffic data...")
    
    # Load the dataset
    df = pd.read_csv(TRAINING_FILE)
    print(f"Total samples in dataset: {len(df)}")
    
    # Filter only BENIGN (normal) traffic for training
    if 'Label' in df.columns:
        normal_data = df[df['Label'] == 'BENIGN'].copy()
        print(f"Normal (BENIGN) traffic samples: {len(normal_data)}")
        
        if len(normal_data) == 0:
            print("Warning: No BENIGN traffic found. Using all data.")
            normal_data = df.copy()
    else:
        print("Warning: No 'Label' column found. Using all data.")
        normal_data = df.copy()
    
    # Select numerical features for the model
    feature_columns = [
        'Destination Port', 'Flow Duration', 'Total Fwd Packets',
        'Total Backward Packets', 'Total Length of Fwd Packets',
        'Total Length of Bwd Packets', 'Fwd Packet Length Max',
        'Fwd Packet Length Min', 'Fwd Packet Length Mean',
        'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
        'Flow IAT Std', 'Fwd IAT Total', 'Bwd IAT Total',
        'Fwd Header Length', 'Bwd Header Length',
        'Fwd Packets/s', 'Bwd Packets/s',
        'Min Packet Length', 'Max Packet Length',
        'Packet Length Mean', 'Average Packet Size',
        'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
        'Subflow Fwd Packets', 'Subflow Fwd Bytes',
        'Subflow Bwd Packets', 'Subflow Bwd Bytes'
    ]
    
    # Keep only available columns
    available_columns = [col for col in feature_columns if col in normal_data.columns]
    print(f"Using {len(available_columns)} features")
    
    # Extract features and handle infinities
    X = normal_data[available_columns].copy()
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)
    
    return X, available_columns

def build_autoencoder(input_dim):
    """Build the autoencoder model"""
    # Encoder
    encoder_input = keras.Input(shape=(input_dim,))
    x = layers.Dense(64, activation='relu')(encoder_input)
    x = layers.Dense(32, activation='relu')(x)
    x = layers.Dense(16, activation='relu')(x)
    encoder_output = layers.Dense(8, activation='relu')(x)
    
    # Decoder
    x = layers.Dense(16, activation='relu')(encoder_output)
    x = layers.Dense(32, activation='relu')(x)
    x = layers.Dense(64, activation='relu')(x)
    decoder_output = layers.Dense(input_dim, activation='linear')(x)
    
    # Autoencoder
    autoencoder = keras.Model(encoder_input, decoder_output, name='autoencoder')
    autoencoder.compile(
        optimizer=keras.optimizers.Adam(learning_rate=0.001),
        loss='mse'
    )
    
    return autoencoder

def train_model(epochs=50):
    """Main training function"""
    print("=" * 60)
    print("Autoencoder Training for Network Anomaly Detection")
    print("=" * 60)
    print(f"Project root: {PROJECT_ROOT}")
    print(f"Model directory: {MODEL_DIR}")
    print(f"Dataset: {TRAINING_FILE}")
    
    # Load and preprocess data
    X, feature_columns = load_and_preprocess_data()
    
    # Limit training samples for faster training
    max_samples = 50000
    if len(X) > max_samples:
        X = X.sample(n=max_samples, random_state=42)
        print(f"Using {max_samples} samples for training")
    
    # Scale the data
    print("Scaling data...")
    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Split data
    X_train, X_val = train_test_split(X_scaled, test_size=0.2, random_state=42)
    
    print(f"Training samples: {len(X_train)}")
    print(f"Validation samples: {len(X_val)}")
    
    # Build the model
    print("\nBuilding autoencoder model...")
    input_dim = X_train.shape[1]
    model = build_autoencoder(input_dim)
    model.summary()
    
    # Train the model
    print(f"\nTraining autoencoder for {epochs} epochs...")
    early_stop = keras.callbacks.EarlyStopping(
        monitor='val_loss',
        patience=5,
        restore_best_weights=True,
        verbose=1
    )
    
    history = model.fit(
        X_train, X_train,
        epochs=epochs,
        batch_size=256,
        validation_data=(X_val, X_val),
        callbacks=[early_stop],
        verbose=1
    )
    
    # Calculate reconstruction error threshold on validation set
    print("\nCalculating anomaly threshold...")
    X_val_pred = model.predict(X_val, verbose=0)
    mse = np.mean(np.power(X_val - X_val_pred, 2), axis=1)
    
    # Use 95th percentile as threshold
    threshold = np.percentile(mse, 95)
    print(f"Anomaly threshold (95th percentile): {threshold:.6f}")
    
    # Save the model
    os.makedirs(MODEL_DIR, exist_ok=True)
    model_path = os.path.join(MODEL_DIR, 'autoencoder_model.keras')
    model.save(model_path)
    print(f"\nModel saved to: {model_path}")
    
    # Save the scaler
    scaler_path = os.path.join(MODEL_DIR, 'scaler.pkl')
    joblib.dump(scaler, scaler_path)
    print(f"Scaler saved to: {scaler_path}")
    
    # Save feature columns and threshold
    config = {
        'feature_columns': feature_columns,
        'threshold': threshold,
        'input_dim': input_dim
    }
    config_path = os.path.join(MODEL_DIR, 'model_config.pkl')
    joblib.dump(config, config_path)
    print(f"Model config saved to: {config_path}")
    
    print("\n" + "=" * 60)
    print("Training complete!")
    print("=" * 60)
    
    return model, scaler, threshold

if __name__ == '__main__':
    train_model()
