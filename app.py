import os
import json
import requests
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify, render_template, Response
import mysql.connector
from mysql.connector import Error
from keras.models import load_model
import joblib
from datetime import datetime

# Import the new configuration
from config import Config

app = Flask(__name__)

# Database configuration using environment variables
DB_PARAMS = {
    'host': Config.DB_HOST,
    'user': Config.DB_USER,
    'password': Config.DB_PASSWORD,
    'database': Config.DB_NAME
}

# ML Model Loading
MODEL_PATH = 'model/model.h5'
SCALER_PATH = 'model/scaler.pkl'
try:
    model = load_model(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    print("[SYSTEM] ML Model and Scaler loaded successfully.")
except Exception as e:
    print(f"[WARNING] ML Model not found. Error: {e}")
    model, scaler = None, None

THREAT_LEVELS = {0: 'Low', 1: 'Medium', 2: 'High', 3: 'Critical'}

# ==========================================
# DATABASE INITIALIZATION
# ==========================================
def get_db_connection():
    try:
        conn = mysql.connector.connect(**DB_PARAMS)
        return conn
    except Error as e:
        print(f"[DB ERROR] {e}")
        return None

def init_db():
    try:
        # Connect to MySQL server to refresh the DB
        conn = mysql.connector.connect(
            host=Config.DB_HOST, 
            user=Config.DB_USER, 
            password=Config.DB_PASSWORD
        )
        conn.autocommit = True
        cursor = conn.cursor()
        
        print(f"[DB] Refreshing database '{Config.DB_NAME}'...")
        cursor.execute(f"DROP DATABASE IF EXISTS {Config.DB_NAME}")
        cursor.execute(f"CREATE DATABASE {Config.DB_NAME}")
        
        cursor.close()
        conn.close()

        # Create Tables
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                ip_address VARCHAR(45),
                traffic_data TEXT,
                threat_level VARCHAR(20),
                action_taken VARCHAR(100)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip_address VARCHAR(45) UNIQUE,
                blocked_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR(20) DEFAULT 'Blocked'
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS redeemed_threats (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip_address VARCHAR(45),
                redeemed_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                threat_level VARCHAR(20)
            )
        ''')
        
        conn.commit()
        cursor.close()
        conn.close()
        print("[DB] Database initialized successfully.")
    except Exception as e:
        print(f"[DB SETUP ERROR] {e}")

# ==========================================
# THREAT LOGIC & API
# ==========================================
def query_cerberus_api(ip_address, threat_level):
    headers = {"Authorization": f"Bearer {Config.CERBERUS_API_KEY}"}
    payload = {"ip": ip_address, "detected_level": threat_level}
    # Mock call
    return {"status": "Success"}

def log_to_db(ip, data, level, action):
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO traffic_logs (ip_address, traffic_data, threat_level, action_taken) VALUES (%s, %s, %s, %s)",
            (ip, json.dumps(data), level, action)
        )
        if "Block" in action:
            try:
                cursor.execute("INSERT INTO blocked_ips (ip_address) VALUES (%s) ON DUPLICATE KEY UPDATE blocked_time=CURRENT_TIMESTAMP", (ip,))
            except: pass 
        if "Redeem" in action:
            cursor.execute("INSERT INTO redeemed_threats (ip_address, threat_level) VALUES (%s, %s)", (ip, level))
        conn.commit()
        cursor.close()
        conn.close()
        print("[DB] Log Stored Successfully\n")

# ==========================================
# ROUTES
# ==========================================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/threat_data', methods=['POST'])
def handle_traffic():
    data = request.json
    ip = data.get('ip', '0.0.0.0')
    
    features = np.array([[data.get('packet_size', 0), data.get('request_rate', 0), data.get('failed_logins', 0), data.get('payload_size', 0)]])
    
    if model and scaler:
        scaled = scaler.transform(features).reshape((1, 1, 4))
        threat_idx = np.argmax(model.predict(scaled, verbose=0))
        threat_level = THREAT_LEVELS.get(threat_idx, 'Low')
    else:
        threat_level = 'Low'

    print(f"[INFO] Incoming Traffic from IP: {ip}")
    print(f"[INFO] Threat Level: {threat_level}")
    
    action = "Redeemed"
    if threat_level in ['Medium', 'High']:
        action = "Redeemed & Blocked"
        print(f"Threat Redeemed – {threat_level} Risk | IP Blocked")
    elif threat_level == 'Critical':
        action = "Redeemed & Blocked Immediately"
        print("CRITICAL Threat – IP Blocked Immediately")
    else:
        print("Threat Redeemed – Low Risk")

    query_cerberus_api(ip, threat_level)
    log_to_db(ip, data, threat_level, action)
    
    return jsonify({"status": "success", "action": action, "level": threat_level})

@app.route('/api/dashboard_data')
def dashboard_data():
    conn = get_db_connection()
    if not conn: return jsonify({"error": "DB Fail"}), 500
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM traffic_logs ORDER BY id DESC LIMIT 20")
    logs = cursor.fetchall()
    cursor.execute("SELECT * FROM blocked_ips")
    blocked = cursor.fetchall()
    cursor.execute("SELECT * FROM redeemed_threats")
    redeemed = cursor.fetchall()
    cursor.execute("SELECT threat_level, COUNT(*) as count FROM traffic_logs GROUP BY threat_level")
    dist = cursor.fetchall()
    cursor.close()
    conn.close()

    # Date formatting
    for r in logs + blocked + redeemed:
        for k in r:
            if isinstance(r[k], datetime): r[k] = r[k].strftime('%Y-%m-%d %H:%M:%S')

    return jsonify({"live_traffic": logs, "blocked_ips": blocked, "redeemed": redeemed, 
                    "stats": {"total_threats": len(logs), "total_blocked": len(blocked), "total_redeemed": len(redeemed), "threat_distribution": dist}})

@app.route('/download/<type>')
def download(type):
    conn = get_db_connection()
    table = {'logs': 'traffic_logs', 'blocked': 'blocked_ips', 'redeemed': 'redeemed_threats'}.get(type)
    df = pd.read_sql(f"SELECT * FROM {table}", conn)
    conn.close()
    return Response(df.to_csv(index=False), mimetype="text/csv", headers={"Content-disposition": f"attachment; filename={type}.csv"})

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=Config.PORT, debug=Config.DEBUG)