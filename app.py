import os
import json
from flask import Flask, request, jsonify, render_template, Response
import mysql.connector
from mysql.connector import Error
import numpy as np
import pandas as pd
from keras.models import load_model
import joblib
from datetime import datetime
from config import Config

app = Flask(__name__)

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
except Exception:
    model, scaler = None, None

THREAT_LEVELS = {0: 'Low', 1: 'Medium', 2: 'High', 3: 'Critical'}

def get_db_connection():
    try: return mysql.connector.connect(**DB_PARAMS)
    except Error: return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/threat_data', methods=['POST'])
def handle_traffic():
    data = request.json
    ip = data.get('ip', '0.0.0.0')
    
    if model and scaler:
        features = np.array([[data.get('packet_size', 0), data.get('request_rate', 0), data.get('failed_logins', 0), data.get('payload_size', 0)]])
        scaled = scaler.transform(features).reshape((1, 1, 4))
        threat_idx = np.argmax(model.predict(scaled, verbose=0))
        threat_level = THREAT_LEVELS.get(threat_idx, 'Low')
    else:
        threat_level = 'Low'

    action = "Redeemed"
    if threat_level in ['Medium', 'High', 'Critical']:
        action = "Redeemed & Blocked"
    
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO traffic_logs (ip_address, traffic_data, threat_level, action_taken) VALUES (%s, %s, %s, %s)", (ip, json.dumps(data), threat_level, action))
        if "Blocked" in action:
            cursor.execute("INSERT IGNORE INTO blocked_ips (ip_address) VALUES (%s)", (ip,))
        cursor.execute("INSERT INTO redeemed_threats (ip_address, threat_level) VALUES (%s, %s)", (ip, threat_level))
        conn.commit()
        cursor.close()
        conn.close()
    
    # Updated to include 'action' key to fix KeyError in attack_simulator.py
    return jsonify({
        "status": "success", 
        "level": threat_level,
        "action": action
    })

@app.route('/api/dashboard_data')
def dashboard_data():
    conn = get_db_connection()
    if not conn: return jsonify({"error": "DB Fail"}), 500
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT * FROM traffic_logs ORDER BY id DESC LIMIT 50")
    logs = cursor.fetchall()
    cursor.execute("SELECT * FROM blocked_ips")
    blocked = cursor.fetchall()
    cursor.execute("SELECT * FROM redeemed_threats")
    redeemed = cursor.fetchall()
    cursor.execute("SELECT threat_level, COUNT(*) as count FROM traffic_logs GROUP BY threat_level")
    dist = cursor.fetchall()
    
    cursor.close()
    conn.close()

    for r in logs + blocked + redeemed:
        for k in r:
            if isinstance(r[k], datetime): r[k] = r[k].strftime('%Y-%m-%d %H:%M:%S')

    return jsonify({
        "live_traffic": logs, 
        "blocked_ips": blocked, 
        "redeemed": redeemed, 
        "stats": {
            "total_threats": len(logs), 
            "total_blocked": len(blocked), 
            "total_redeemed": len(redeemed), 
            "threat_distribution": dist
        }
    })

@app.route('/api/clear_history', methods=['POST'])
def clear_history():
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("TRUNCATE TABLE traffic_logs")
        cursor.execute("TRUNCATE TABLE blocked_ips")
        cursor.execute("TRUNCATE TABLE redeemed_threats")
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"status": "cleared"})
    return jsonify({"status": "error"}), 500

@app.route('/download/<type>')
def download(type):
    conn = get_db_connection()
    table = {'logs': 'traffic_logs', 'blocked': 'blocked_ips', 'redeemed': 'redeemed_threats'}.get(type)
    df = pd.read_sql(f"SELECT * FROM {table}", conn)
    conn.close()
    return Response(df.to_csv(index=False), mimetype="text/csv", headers={"Content-disposition": f"attachment; filename={type}.csv"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
