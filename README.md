# AI-Driven Threat Detection and Automated Remediation System

A production-ready threat detection system using Deep Learning (Autoencoder) for network anomaly detection, with real-time monitoring, automated remediation, and a comprehensive dashboard.

## Features

- **Deep Learning Anomaly Detection**: TensorFlow/Keras autoencoder trained on normal network traffic
- **Network Monitoring**: Real-time detection of network anomalies and port scans
- **Log Analysis**: Brute force and suspicious login detection
- **Automated Remediation**: Simulated IP blocking, account lock, and process termination
- **Secure Authentication**: JWT-based auth with bcrypt password hashing
- **Data Encryption**: Fernet encryption for sensitive data
- **Interactive Dashboard**: Real-time threat visualization and management

## System Requirements

- Python 3.11+
- Windows, Linux, or macOS
- 4GB+ RAM recommended
- No admin privileges required

## Installation

### 1. Create Virtual Environment (Optional but Recommended)

```
bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

### 2. Install Dependencies

```
bash
cd backend
pip install -r requirements.txt
```

### 3. Dataset Setup

The system expects datasets in the `datasets/` folder. The following CSV files are supported:

- `network_data.csv` - Network traffic data
- `logs_data.csv` - System logs

If you don't have these files, generate them:

```
bash
cd scripts
python generate_data.py
```

This will create synthetic network and log data for testing.

### 4. Database Setup

#### Option A: MySQL (Recommended for Production)

1. Create a MySQL database using one of these methods:

**Method 1 - MySQL Command Line:**
```
sql
CREATE DATABASE threat_detection;
```

**Method 2 - MySQL Workbench:**
- Open MySQL Workbench
- Connect to your MySQL server
- Click "Create New Schema"
- Name it `threat_detection`
- Click "Apply"

**Method 3 - Using Python:**
```
python
import pymysql
conn = pymysql.connect(host='localhost', user='root', password='your_password')
cursor = conn.cursor()
cursor.execute("CREATE DATABASE threat_detection")
conn.commit()
conn.close()
```

**Method 4 - Using mysql CLI:**
```
bash
mysql -u root -p -e "CREATE DATABASE threat_detection;"
```

2. Configure in `backend/.env`:
```
DB_TYPE=mysql
DB_HOST=localhost
DB_PORT=3306
DB_NAME=threat_detection
DB_USER=root
DB_PASSWORD=your_password
```

#### Option B: SQLite (For Development/Testing)

The system defaults to SQLite. To explicitly use SQLite:
```
DB_TYPE=sqlite
DATABASE_URL=sqlite:///threat_detection.db
```

### 5. Generate Secure Keys

For security, generate SECRET_KEY and JWT_SECRET_KEY values. Run:

```
bash
cd backend
python generate_keys.py
```

This will generate secure random keys. Add them to your `.env` file.

### 6. Initialize Database

The database will be created automatically on first run. Default users:
- **Admin**: username: `admin`, password: `admin123`
- **Demo**: username: `demo`, password: `demo123`

## Training the Model

### Option 1: Quick Train (Recommended for Testing)

Train a lightweight model:

```
bash
cd backend
python -c "from model.train_autoencoder import train_model; train_model(epochs=10)"
```

### Option 2: Full Training

For better accuracy, train with more epochs:

```
bash
cd backend
python -c "from model.train_autoencoder import train_model; train_model(epochs=50)"
```

Training will:
1. Load network traffic data from `datasets/`
2. Filter for normal (BENIGN) traffic
3. Train an autoencoder to reconstruct normal patterns
4. Save the model as `model/autoencoder_model.keras`
5. Save the scaler as `model/scaler.pkl`
6. Calculate and save the anomaly threshold

## Running the Application

### Start the Server

```
bash
cd backend
python app.py
```

The server will start at `http://localhost:5000`

### Access the Dashboard

Open your browser and navigate to:
- **Dashboard**: http://localhost:5000/dashboard
- **Login**: http://localhost:5000/login

## Default Credentials

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Admin |
| demo | demo123 | User |

## API Endpoints

### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/register` - Register new user

### Threat Detection
- `POST /api/detection/analyze` - Analyze network data
- `GET /api/threats` - Get all threats
- `GET /api/threats/stats` - Get threat statistics

### Remediation
- `POST /api/remediation/block-ip` - Block an IP
- `POST /api/remediation/unblock-ip` - Unblock an IP
- `POST /api/remediation/lock-account` - Lock an account
- `GET /api/remediation/history` - Get remediation history

### System
- `GET /api/system/health` - System health status
- `GET /api/blocked-ips` - Get blocked IPs

## Attack Simulation

Test the system with simulated attacks:

```
bash
cd scripts
python simulate_attack.py
```

Select from:
1. Network Anomaly Detection
2. Brute Force Attack
3. Port Scan Attack
4. All Scenarios

## Project Structure

```
.
├── backend/
│   ├── app.py                 # Main Flask application
│   ├── config.py              # Configuration settings
│   ├── requirements.txt       # Python dependencies
│   ├── .env                   # Environment variables
│   ├── model/
│   │   ├── train_autoencoder.py   # Model training script
│   │   ├── autoencoder_model.keras # Trained model
│   │   └── scaler.pkl             # Data scaler
│   ├── detection/
│   │   ├── anomaly_detector.py    # Network anomaly detection
│   │   ├── log_monitor.py         # Log analysis
│   │   └── network_monitor.py     # Network monitoring
│   ├── remediation/
│   │   └── auto_response.py      # Automated responses
│   ├── security/
│   │   ├── crypto_utils.py        # Encryption utilities
│   │   └── auth.py                # Authentication
│   ├── database/
│   │   ├── db.py                  # Database initialization
│   │   └── models.py              # SQLAlchemy models
│   └── utils/
│       └── logger.py              # Logging utilities
├── frontend/
│   ├── templates/
│   │   ├── index.html             # Home page
│   │   ├── login.html            # Login page
│   │   └── dashboard.html        # Dashboard
│   └── static/
│       ├── css/style.css         # Styles
│       └── js/app.js             # JavaScript
├── datasets/
│   ├── network_data.csv          # Network traffic
│   └── logs_data.csv             # System logs
├── scripts/
│   ├── generate_data.py          # Generate sample data
│   └── simulate_attack.py        # Attack simulation
└── README.md
```

## Technology Stack

- **Backend**: Flask, Python 3.11+
- **Database**: SQLite with SQLAlchemy
- **Deep Learning**: TensorFlow/Keras
- **Authentication**: JWT, bcrypt
- **Encryption**: Fernet (cryptography)
- **Frontend**: HTML, CSS, JavaScript

## Security Notes

- Change default passwords in production
- Use strong SECRET_KEY values
- Enable SSL/TLS for production
- Keep dependencies updated
- Review and audit logs regularly

## Troubleshooting

### Model not found
Train the model first:
```
bash
cd backend
python -c "from model.train_autoencoder import train_model; train_model()"
```

### Database errors
Delete the existing database and restart:
```
bash
rm backend/threat_detection.db
python app.py
```

### Port already in use
Change the port in `backend/app.py`:
```
python
app.run(debug=True, port=5001)
```

## License

MIT License - Use at your own risk for educational and testing purposes.
