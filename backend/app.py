"""
AI-Driven Threat Detection and Automated Remediation System
Main Flask Application
"""

import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, jsonify, request, render_template
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from functools import wraps

from config import Config
from database.db import init_db, db
from database.models import User, ThreatEvent, BlockedIP, RemediationAction, SystemLog
from security.auth import admin_required
from utils.logger import log_to_database

# Initialize Flask app with proper template and static paths
# Get the project root directory
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_DIR = os.path.join(PROJECT_ROOT, 'frontend', 'templates')
STATIC_DIR = os.path.join(PROJECT_ROOT, 'frontend', 'static')

app = Flask(__name__, 
            template_folder=TEMPLATE_DIR,
            static_folder=STATIC_DIR,
            static_url_path='/static')
app.config.from_object(Config)

# Initialize extensions
jwt = JWTManager(app)
db.init_app(app)

# Initialize database
init_db(app)

# Import detection modules (after app is created)
from detection.anomaly_detector import get_detector
from detection.log_monitor import get_log_monitor
from detection.network_monitor import get_network_monitor
from remediation.auto_response import get_remediation

# ==================== ROUTES ====================

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    """Dashboard page"""
    return render_template('dashboard.html')

@app.route('/login')
def login_page():
    """Login page"""
    return render_template('login.html')

# ==================== API ROUTES ====================

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Authenticate user and return JWT token"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    print(f"Login attempt: username={username}, password={password}")
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    user = User.query.filter_by(username=username).first()
    
    print(f"User found in DB: {user}")
    if user:
        print(f"User password_hash: {user.password_hash[:30]}...")
    
    # Create user if doesn't exist (for demo purposes)
    if not user:
        # Only allow demo/admin for demo - BUT only with correct default passwords
        if username == 'admin' and password == 'admin123':
            user = User(username=username, email=f'{username}@demo.local')
            user.set_password(password)
            user.is_admin = True
            db.session.add(user)
            db.session.commit()
            print(f"Created new user: {username} with password {password}")
        elif username == 'demo' and password == 'demo123':
            user = User(username=username, email=f'{username}@demo.local')
            user.set_password(password)
            user.is_admin = False
            db.session.add(user)
            db.session.commit()
            print(f"Created new user: {username} with password {password}")
        else:
            print(f"User not found - invalid username or password")
            return jsonify({'error': 'User not found'}), 401
    
    password_valid = user.check_password(password)
    print(f"Password validation result: {password_valid}")
    
    if not password_valid:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Create JWT token
    access_token = create_access_token(identity=username)
    
    return jsonify({
        'access_token': access_token,
        'username': username,
        'is_admin': user.is_admin
    })

# ==================== THREAT DETECTION ROUTES ====================

@app.route('/api/detection/analyze', methods=['POST'])
@jwt_required()
def analyze_traffic():
    """Analyze network traffic for anomalies"""
    data = request.get_json()
    
    # Get detector
    detector = get_detector()
    
    # Load model if not loaded
    if not detector.is_loaded:
        detector.load_model()
    
    # Analyze the data
    result = detector.detect_anomaly(data)
    
    if result:
        # Create threat event if anomaly detected
        if result.get('anomaly'):
            threat = ThreatEvent(
                threat_type='network_anomaly',
                severity=result.get('severity', 'Low'),
                description=f"Anomaly detected with score: {result.get('anomaly_score')}",
                anomaly_score=result.get('anomaly_score'),
                remediation_action='detected'
            )
            db.session.add(threat)
            db.session.commit()
            
            log_to_database('WARNING', 'Detection', 
                          f"Network anomaly detected: {result.get('severity')}")
        
        return jsonify(result)
    
    return jsonify({'error': 'Analysis failed'}), 500

@app.route('/api/detection/network/status', methods=['GET'])
@jwt_required()
def get_detection_status():
    """Get detection system status"""
    detector = get_detector()
    model_info = detector.get_model_info()
    
    return jsonify({
        'model_loaded': model_info.get('loaded', False),
        'model_info': model_info,
        'simulation_mode': Config.SIMULATION_MODE
    })

# ==================== THREAT EVENTS ROUTES ====================

@app.route('/api/threats', methods=['GET'])
@jwt_required()
def get_threats():
    """Get all threat events"""
    limit = request.args.get('limit', 100, type=int)
    severity = request.args.get('severity')
    
    query = ThreatEvent.query.order_by(ThreatEvent.timestamp.desc())
    
    if severity:
        query = query.filter_by(severity=severity)
    
    threats = query.limit(limit).all()
    
    return jsonify([{
        'id': t.id,
        'timestamp': t.timestamp.isoformat(),
        'threat_type': t.threat_type,
        'severity': t.severity,
        'source_ip': t.source_ip,
        'description': t.description,
        'anomaly_score': t.anomaly_score,
        'status': t.status
    } for t in threats])

@app.route('/api/threats/stats', methods=['GET'])
@jwt_required()
def get_threat_stats():
    """Get threat statistics"""
    total = ThreatEvent.query.count()
    active = ThreatEvent.query.filter_by(status='active').count()
    
    # Severity distribution
    severity_dist = {}
    for severity in ['Low', 'Medium', 'High', 'Critical']:
        count = ThreatEvent.query.filter_by(severity=severity).count()
        severity_dist[severity] = count
    
    # Threat type distribution
    threat_types = db.session.query(
        ThreatEvent.threat_type, 
        db.func.count(ThreatEvent.id)
    ).group_by(ThreatEvent.threat_type).all()
    
    threat_type_dist = {t[0]: t[1] for t in threat_types}
    
    return jsonify({
        'total': total,
        'active': active,
        'severity_distribution': severity_dist,
        'threat_type_distribution': threat_type_dist
    })

# ==================== BLOCKED IPs ROUTES ====================

@app.route('/api/blocked-ips', methods=['GET'])
@jwt_required()
def get_blocked_ips():
    """Get list of blocked IPs"""
    blocked = BlockedIP.query.filter_by(is_active=True).all()
    
    return jsonify([{
        'id': b.id,
        'ip_address': b.ip_address,
        'timestamp': b.timestamp.isoformat(),
        'reason': b.reason,
        'blocked_until': b.blocked_until.isoformat() if b.blocked_until else None
    } for b in blocked])

@app.route('/api/blocked-ips', methods=['POST'])
@jwt_required()
@admin_required
def block_ip():
    """Block an IP address"""
    data = request.get_json()
    ip_address = data.get('ip_address')
    reason = data.get('reason', 'Manual block')
    duration = data.get('duration', 60)
    
    if not ip_address:
        return jsonify({'error': 'IP address required'}), 400
    
    remediation = get_remediation()
    result = remediation.block_ip(ip_address, reason, duration)
    
    return jsonify(result)

@app.route('/api/blocked-ips/<ip_address>', methods=['DELETE'])
@jwt_required()
@admin_required
def unblock_ip(ip_address):
    """Unblock an IP address"""
    remediation = get_remediation()
    result = remediation.unblock_ip(ip_address)
    
    return jsonify(result)

# ==================== REMEDIATION ROUTES ====================

@app.route('/api/remediation/history', methods=['GET'])
@jwt_required()
def get_remediation_history():
    """Get remediation action history"""
    limit = request.args.get('limit', 50, type=int)
    
    remediation = get_remediation()
    history = remediation.get_remediation_history(limit)
    
    return jsonify(history)

@app.route('/api/remediation/apply', methods=['POST'])
@jwt_required()
@admin_required
def apply_remediation():
    """Manually apply remediation to a threat"""
    data = request.get_json()
    threat_id = data.get('threat_id')
    
    if not threat_id:
        return jsonify({'error': 'Threat ID required'}), 400
    
    threat = ThreatEvent.query.get(threat_id)
    if not threat:
        return jsonify({'error': 'Threat not found'}), 404
    
    remediation = get_remediation()
    
    # Apply remediation based on threat type
    threat_data = {
        'type': threat.threat_type,
        'severity': threat.severity,
        'source_ip': threat.source_ip
    }
    
    actions = remediation.apply_remediation(threat_data)
    
    # Update threat status
    threat.status = 'remediated'
    threat.remediation_action = 'auto_remediation'
    db.session.commit()
    
    return jsonify({
        'success': True,
        'actions': actions
    })

@app.route('/api/remediation/simulation-mode', methods=['GET'])
@jwt_required()
def get_simulation_mode():
    """Get current simulation mode"""
    remediation = get_remediation()
    return jsonify({
        'simulation_mode': remediation.simulation_mode
    })

@app.route('/api/remediation/simulation-mode', methods=['POST'])
@jwt_required()
@admin_required
def set_simulation_mode():
    """Set simulation mode"""
    data = request.get_json()
    mode = data.get('mode', True)
    
    remediation = get_remediation()
    remediation.set_simulation_mode(mode)
    
    return jsonify({
        'success': True,
        'simulation_mode': mode
    })

# ==================== SYSTEM ROUTES ====================

@app.route('/api/system/health', methods=['GET'])
@jwt_required()
def system_health():
    """Get system health status"""
    # Check database
    try:
        db.session.execute(db.text('SELECT 1'))
        db_status = 'healthy'
    except:
        db_status = 'error'
    
    # Check model
    detector = get_detector()
    model_status = 'loaded' if detector.is_loaded else 'not_loaded'
    
    return jsonify({
        'database': db_status,
        'model': model_status,
        'simulation_mode': Config.SIMULATION_MODE,
        'debug': Config.DEBUG
    })

@app.route('/api/system/logs', methods=['GET'])
@jwt_required()
def get_system_logs():
    """Get system logs"""
    limit = request.args.get('limit', 100, type=int)
    level = request.args.get('level')
    
    query = SystemLog.query.order_by(SystemLog.timestamp.desc())
    
    if level:
        query = query.filter_by(level=level)
    
    logs = query.limit(limit).all()
    
    return jsonify([{
        'id': l.id,
        'timestamp': l.timestamp.isoformat(),
        'level': l.level,
        'source': l.source,
        'message': l.message,
        'details': l.details
    } for l in logs])

# ==================== TRAINING ROUTES ====================

@app.route('/api/model/train', methods=['POST'])
@jwt_required()
@admin_required
def train_model():
    """Train the anomaly detection model"""
    from model.train_autoencoder import train_model as train
    
    try:
        model, scaler, threshold = train()
        
        # Reload detector with new model
        detector = get_detector()
        detector.load_model()
        
        log_to_database('INFO', 'Model', 'Anomaly detection model trained successfully')
        
        return jsonify({
            'success': True,
            'threshold': float(threshold),
            'message': 'Model trained successfully'
        })
    except Exception as e:
        log_to_database('ERROR', 'Model', f'Training failed: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ==================== DATA SIMULATION ROUTES ====================

@app.route('/api/simulate/threat', methods=['POST'])
@jwt_required()
@admin_required
def simulate_threat():
    """Simulate a threat for testing"""
    data = request.get_json()
    threat_type = data.get('type', 'network_anomaly')
    
    threat = ThreatEvent(
        threat_type=threat_type,
        severity=data.get('severity', 'Medium'),
        source_ip=data.get('source_ip', '10.0.0.100'),
        description=data.get('description', 'Simulated threat'),
        status='active'
    )
    
    db.session.add(threat)
    db.session.commit()
    
    log_to_database('WARNING', 'Simulation', 
                   f"Simulated {threat_type} threat from {data.get('source_ip')}")
    
    return jsonify({
        'success': True,
        'threat_id': threat.id
    })

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def server_error(e):
    log_to_database('ERROR', 'App', str(e))
    return jsonify({'error': 'Internal server error'}), 500

# ==================== CLI COMMANDS ====================

@app.cli.command('init-db')
def init_db_command():
    """Initialize the database"""
    init_db(app)
    print('Database initialized')

if __name__ == '__main__':
    # Create logs directory
    os.makedirs('logs', exist_ok=True)
    
    # Run the app
    app.run(host='0.0.0.0', port=5000, debug=True)
