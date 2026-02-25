"""
Suspicious Login Detection Module
Detects brute-force patterns and suspicious login attempts from log data
"""

import os
import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict
import re

DATASET_PATH = os.path.join('..', 'datasets')

class LogMonitor:
    def __init__(self):
        self.failed_logins = defaultdict(list)
        self.successful_logins = defaultdict(list)
        self.suspicious_patterns = []
        self.brute_force_threshold = 5  # Failed attempts threshold
        self.time_window_minutes = 10  # Time window for detection
        
    def load_logs(self, log_file=None):
        """Load system logs for analysis"""
        if log_file is None:
            # Check if logs_data.csv exists, otherwise create sample data
            log_file = os.path.join(DATASET_PATH, 'logs_data.csv')
        
        if not os.path.exists(log_file):
            # Create sample log data for demonstration
            return self._create_sample_logs()
        
        try:
            df = pd.read_csv(log_file)
            return df
        except Exception as e:
            print(f"Error loading logs: {str(e)}")
            return self._create_sample_logs()
    
    def _create_sample_logs(self):
        """Create sample log data for demonstration"""
        # Sample SSH-like log entries
        sample_logs = []
        base_time = datetime.now()
        
        # Normal logins
        for i in range(50):
            sample_logs.append({
                'timestamp': base_time - timedelta(minutes=i*5),
                'source_ip': f'192.168.1.{10+i%10}',
                'username': 'admin',
                'status': 'success',
                'service': 'ssh'
            })
        
        # Failed login attempts (simulated brute force)
        attacker_ips = ['10.0.0.50', '10.0.0.51', '10.0.0.52']
        for ip in attacker_ips:
            for attempt in range(15):
                sample_logs.append({
                    'timestamp': base_time - timedelta(minutes=attempt*2),
                    'source_ip': ip,
                    'username': 'root',
                    'status': 'failed',
                    'service': 'ssh'
                })
        
        return pd.DataFrame(sample_logs)
    
    def analyze_logs(self, logs_df):
        """Analyze logs for suspicious patterns"""
        threats = []
        
        for _, row in logs_df.iterrows():
            timestamp = row.get('timestamp', datetime.now())
            source_ip = row.get('source_ip', 'unknown')
            username = row.get('username', 'unknown')
            status = row.get('status', 'unknown')
            
            # Track failed attempts
            if status == 'failed':
                self.failed_logins[source_ip].append({
                    'timestamp': timestamp,
                    'username': username
                })
            else:
                self.successful_logins[source_ip].append({
                    'timestamp': timestamp,
                    'username': username
                })
        
        # Detect brute force patterns
        for ip, attempts in self.failed_logins.items():
            if len(attempts) >= self.brute_force_threshold:
                # Check if within time window
                recent_attempts = [
                    a for a in attempts 
                    if (datetime.now() - a['timestamp']).total_seconds() < 
                       self.time_window_minutes * 60
                ]
                
                if len(recent_attempts) >= self.brute_force_threshold:
                    threat = {
                        'type': 'brute_force',
                        'source_ip': ip,
                        'severity': 'High' if len(recent_attempts) >= 10 else 'Medium',
                        'description': f"Brute force attack detected from {ip} with {len(recent_attempts)} failed attempts",
                        'attempts': len(recent_attempts),
                        'target_users': list(set([a['username'] for a in recent_attempts]))
                    }
                    threats.append(threat)
        
        # Detect account lockouts (multiple failures followed by success from different IP)
        for ip, successes in self.successful_logins.items():
            if ip in self.failed_logins:
                fail_count = len(self.failed_logins[ip])
                if fail_count >= 3:
                    threat = {
                        'type': 'account_compromise',
                        'source_ip': ip,
                        'severity': 'Critical',
                        'description': f"Possible account compromise: {fail_count} failed attempts before successful login",
                        'attempts': fail_count
                    }
                    threats.append(threat)
        
        # Detect unusual login times
        for ip, successes in self.successful_logins.items():
            for success in successes:
                hour = success['timestamp'].hour
                if hour < 6 or hour > 22:  # Outside normal hours
                    threat = {
                        'type': 'unusual_login_time',
                        'source_ip': ip,
                        'severity': 'Low',
                        'description': f"Unusual login time from {ip} at {success['timestamp']}",
                        'timestamp': success['timestamp']
                    }
                    threats.append(threat)
        
        return threats
    
    def detect_suspicious_login(self, source_ip, username, status):
        """Real-time detection of suspicious login"""
        timestamp = datetime.now()
        
        if status == 'failed':
            self.failed_logins[source_ip].append({
                'timestamp': timestamp,
                'username': username
            })
            
            # Check for brute force
            recent_attempts = [
                a for a in self.failed_logins[source_ip]
                if (timestamp - a['username']).total_seconds() < 300  # Last 5 minutes
            ]
            
            if len(recent_attempts) >= self.brute_force_threshold:
                return {
                    'suspicious': True,
                    'type': 'brute_force',
                    'severity': 'High',
                    'message': f'Brute force detected: {len(recent_attempts)} failed attempts from {source_ip}'
                }
        
        return {
            'suspicious': False,
            'type': 'normal',
            'severity': 'None'
        }
    
    def get_failed_login_count(self, source_ip):
        """Get count of failed logins from an IP"""
        return len(self.failed_logins.get(source_ip, []))
    
    def clear_old_records(self, hours=24):
        """Clear records older than specified hours"""
        cutoff = datetime.now() - timedelta(hours=hours)
        
        for ip in list(self.failed_logins.keys()):
            self.failed_logins[ip] = [
                a for a in self.failed_logins[ip]
                if a['timestamp'] > cutoff
            ]
            if not self.failed_logins[ip]:
                del self.failed_logins[ip]
        
        for ip in list(self.successful_logins.keys()):
            self.successful_logins[ip] = [
                a for a in self.successful_logins[ip]
                if a['timestamp'] > cutoff
            ]
            if not self.successful_logins[ip]:
                del self.successful_logins[ip]

# Singleton instance
_monitor = None

def get_log_monitor():
    global _monitor
    if _monitor is None:
        _monitor = LogMonitor()
    return _monitor
