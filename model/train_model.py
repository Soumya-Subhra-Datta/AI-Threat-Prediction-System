import os
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from keras.models import Sequential
from keras.layers import Dense, LSTM, Dropout
from keras.utils import to_categorical
import joblib

# Create model directory if not exists
os.makedirs('model', exist_ok=True)

print("1. Generating Synthetic Network Traffic Data...")
# Generate dummy data for 4 threat levels
# Features: [packet_size, request_rate, failed_logins, payload_size]

np.random.seed(42)
num_samples = 5000

# Level 0: Low (Normal-ish traffic)
low = np.random.normal(loc=[500, 10, 0, 200], scale=[50, 5, 0.1, 50], size=(num_samples, 4))
y_low = np.zeros(num_samples)

# Level 1: Medium (Slight anomalies)
medium = np.random.normal(loc=[1500, 50, 2, 800], scale=[100, 10, 1, 100], size=(num_samples, 4))
y_medium = np.ones(num_samples)

# Level 2: High (Suspicious spikes)
high = np.random.normal(loc=[5000, 150, 5, 2500], scale=[500, 20, 2, 500], size=(num_samples, 4))
y_high = np.full(num_samples, 2)

# Level 3: Critical (DDoS/Brute Force patterns)
critical = np.random.normal(loc=[10000, 500, 20, 8000], scale=[1000, 50, 5, 1000], size=(num_samples, 4))
y_critical = np.full(num_samples, 3)

# Combine datasets
X = np.vstack((low, medium, high, critical))
X = np.clip(X, 0, None) # No negative values
y = np.concatenate((y_low, y_medium, y_high, y_critical))

print("2. Preprocessing Data...")
# Standardize features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Save the scaler for future predictions
joblib.dump(scaler, 'model/scaler.pkl')

# Convert labels to categorical
y_categorical = to_categorical(y, num_classes=4)

# Reshape input for LSTM (samples, timesteps, features)
# We treat each network event as 1 timestep with 4 features
X_lstm = X_scaled.reshape((X_scaled.shape[0], 1, X_scaled.shape[1]))

X_train, X_test, y_train, y_test = train_test_split(X_lstm, y_categorical, test_size=0.2, random_state=42)

print("3. Building Deep Learning LSTM Model...")
model = Sequential()
model.add(LSTM(64, input_shape=(X_lstm.shape[1], X_lstm.shape[2]), activation='relu', return_sequences=True))
model.add(Dropout(0.2))
model.add(LSTM(32, activation='relu'))
model.add(Dropout(0.2))
model.add(Dense(16, activation='relu'))
model.add(Dense(4, activation='softmax')) # 4 output classes

model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])

print("4. Training Model (This might take a moment)...")
model.fit(X_train, y_train, epochs=10, batch_size=32, validation_data=(X_test, y_test), verbose=1)

print("5. Evaluating Model...")
loss, accuracy = model.evaluate(X_test, y_test, verbose=0)
print(f"Model Accuracy: {accuracy*100:.2f}%")

print("6. Saving Model...")
model.save('model/model.h5')
joblib.dump(['packet_size', 'request_rate', 'failed_logins', 'payload_size'], 'model/features.pkl')

print("SUCCESS: Model training complete. Assets saved to /model directory.")