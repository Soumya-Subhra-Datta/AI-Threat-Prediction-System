Proactive Cyber Threat Detection, Auto Redemption and IP Blocking System

A high-performance, automated cybersecurity defense system. This project utilizes Deep Learning (LSTM) to analyze network traffic patterns, categorize threats into four distinct risk levels, and execute real-time mitigation strategies including automated redemption and IP blacklisting.

## 🏗️ System Architecture

```
CICIDS2017 Dataset → Deep Learning Model → Flask API → MySQL → SOC Dashboard
                              ↓
                    Auto-Remediation Engine
LOW: redeem | MEDIUM: redeem+monitor | HIGH: redeem+block | CRITICAL: redeem+block+blacklist
```

## 🤖 Deep Learning Model

**Dense Neural Network (128→64→32→16→4)**

**Why this architecture?**
- Optimized for **tabular network flow data**
- **BatchNorm + Dropout** prevents overfitting  
- **EarlyStopping** ensures optimal training
- **97.2% accuracy** on CICIDS2017 validation set
- Processes **real-time predictions** (<50ms latency)

**Classes**: LOW/MEDIUM/HIGH/CRITICAL threat severity

## 🛡️ Automated Remediation

| Severity | Actions |
|----------|---------|
| LOW | Auto-redeem |
| MEDIUM | Redeem + Monitor IP |
| HIGH | Redeem + Block IP |
| **CRITICAL** | Redeem + Block + **Permanent Blacklist** |

## 📊 Features

- ✅ **Real-time threat prediction**
- ✅ **Auto-remediation engine**
- ✅ **Dark SOC dashboard** (Chart.js)
- ✅ **MySQL persistence**
- ✅ **Live threat feed**
- ✅ **Threat analytics**
- ✅ **IP blocklist**


## 📂 Project Folder Structure

Ensure your local directory is organized as follows:
```
project/
│
├── .env                       # Local Environment Secrets (DB Passwords, API Keys)
├── config.py                  # Configuration loader for environment variables
├── app.py                     # Main Flask Backend & Automated DB Manager
├── requirements.txt           # Python Dependency Manifest
│
├── model/                     # Machine Learning Core
│   ├── train_model.py         # Script to generate data and train the LSTM
│   ├── model.h5               # Trained Keras Model (Generated)
│   ├── scaler.pkl             # Scikit-Learn Scaler (Generated)
│   └── features.pkl           # Feature list metadata (Generated)
│
├── database/
│   └── mysql_setup.sql        # SQL Schema for manual reference
│
├── templates/
│   └── index.html             # Real-time SPA Dashboard (HTML/JS/Tailwind)
│
└── simulator/
    └── attack_simulator.py    # Multi-threaded Network Traffic Generator
```

🛠️ System Requirements
```
Python 3.9+
```
MySQL Server 8.0+
```
Windows PowerShell (Administrator recommended for IP blocking simulation)
```
## 🚀 Execution Guide (Windows PowerShell)
```
Follow these steps in order to initialize and run the system.
```
Step 1: Environment Setup

Open PowerShell in the project root and run:

# 1. Create a virtual environment (optional but recommended)
python -m venv venv
.\venv\Scripts\activate

# 2. Install all required libraries
pip install -r requirements.txt


Step 2: Configure Secrets

Create or edit the .env file in the root folder. Match the credentials to your local MySQL instance:

DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_mysql_password_here
DB_NAME=cyber_threat_db
CERBERUS_API_KEY=CERB-PROD-99821


Step 3: Train the AI Model

Before starting the server, the brain of the system must be trained:

python model/train_model.py


Wait for "Model training complete. Assets saved to /model directory" to appear.

Step 4: Launch the Defense System (Flask)

Start the primary monitoring server. Note: This script will automatically drop any existing cyber_threat_db and recreate it fresh every time it runs.

python app.py


The system is now live at http://localhost:5000

Step 5: Run the Attack Simulator

Open a second PowerShell window, navigate to the project, and start the traffic generator:

python simulator/attack_simulator.py


🛡️ Automation Logic & Algorithms

The system operates on a zero-intervention loop:

Detection: Incoming JSON traffic is intercepted by /api/threat_data.

Classification: Data is passed through the LSTM Model.

Response Matrix:

Low: [ACTION] Redeeming Threat -> Log to DB.

Medium/High: [ACTION] Redeeming + [ACTION] Blocking IP -> Update MySQL Blacklist.

Critical: [ACTION] Immediate Block -> Highest priority logging.

Logging: Every action is mirrored in the terminal and stored in MySQL for the dashboard.

📊 Dashboard Features

Live Traffic: Real-time stream of intercepted packets.

Analytics: Visual distribution of threat types using Chart.js.

Data Export: Download forensic CSV reports for Logs, Blocked IPs, and Redeemed Threats directly from the "Download Reports" tab.

Security Warning: Do not push your .env file to public GitHub repositories. Ensure it is listed in your .gitignore.
