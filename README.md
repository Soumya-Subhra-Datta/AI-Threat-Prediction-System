AI-Powered Proactive Threat Detection System

A real-time cybersecurity web-application utilizing Deep Learning (LSTM) to monitor, classify, and mitigate network threats automatically.

🧠 Why LSTM (Long Short-Term Memory)?

In this project, we utilize an LSTM Recurrent Neural Network instead of a standard Artificial Neural Network (ANN) for several critical reasons:

Temporal Awareness: Network attacks (like DDoS or Brute Force) are not single events; they are sequences of events over time. LSTMs are designed to remember patterns in sequences, making them superior at identifying shifting traffic behaviors.

Feature Correlation: The model analyzes the relationship between packet_size, request_rate, failed_logins, and payload_size. An LSTM can identify if a high request rate combined with specific packet sizes over a window of time constitutes a "High" vs "Critical" threat.

Accuracy in Volatility: Cyber traffic is "noisy." LSTMs use "gates" to forget irrelevant data and focus on high-impact threat signals, leading to fewer false positives.

🛡️ The "Identify-Grade-Mitigate" Workflow

The system follows a 4-step automated logic once a packet hits the api/threat_data endpoint:

## 1. Identification (Data Ingestion)

The backend captures four key telemetry points from every incoming request:

Packet Size: The weight of individual data units.

Request Rate: The frequency of hits from a specific IP.

Failed Logins: Tracking unauthorized access attempts.

Payload Size: Detecting potential buffer overflows or data exfiltration attempts.

## 2. Grading (AI Classification)

The data is normalized via a scaler and passed into the model.h5. The model outputs a probability across four categories:

Low (0): Normal user behavior.

Medium (1): Suspicious activity (e.g., unusual scanning).

High (2): Likely attack (e.g., repeated login failures).

Critical (3): Immediate threat (e.g., high-volume DDoS signature).

## 3. Redeeming (Processing)

"Redeeming" is our term for the successful interception and logging of a threat.

Every hit is cross-referenced against the AI's grade.

The system "redeems" the threat by converting raw packet data into a structured security log, ensuring the security team has an audit trail of exactly why a specific IP was flagged.

## 4. Blocking (Active Defense)

If the AI grades a threat as Medium, High, or Critical, the system triggers an automated "Block":

The IP is immediately added to the blocked_ips database table.

In a production environment, this table feeds directly into a Firewall (WAF) or Nginx configuration to drop all future packets from that source.

🚀 Running the System

Prerequisites

Python 3.8+

MySQL Server

TensorFlow/Keras & Flask

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

Data Export: Download forensic CSV reports for Logs, Blocked IPs, and Remediated Threats directly from the "Download Reports" tab.

Security Warning: Do not push your .env file to public GitHub repositories. Ensure it is listed in your .gitignore.
