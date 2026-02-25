"""
Port Scan Detection Module
Detects port scanning activities from network traffic data
"""

import os
import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict
import numpy as np

DATASET_PATH = os.path.join('..', 'datasets')

class NetworkMonitor:
    def __init__(self):
        self.connection_attempts = defaultdict(list)
        self.port_scan_threshold = 10  # Number of different ports to trigger alert
        self.time_window_seconds = 60  # Time window for detection
        self.detected_scans = []
        
    def analyze_port_scan(self, data):
        """Analyze network data for port scan patterns"""
        threats = []
        
        # Convert data to DataFrame if needed
        if not isinstance(data, pd.DataFrame):
            data = pd.DataFrame(data)
        
        # Group by source IP
        if 'Source IP' in data.columns:
            source_col = 'Source IP'
        elif 'source_ip' in data.columns:
            source_col = 'source_ip'
        else:
            return threats
            
        if 'Destination Port' in data.columns:
            dest_port_col = 'Destination Port'
        elif 'dest_port' in data.columns:
            dest_port_col = 'dest_port'
        else:
            return threats
        
        # Group connections by source IP
        ip_connections = defaultdict(set)
        
        for _, row in data.iterrows():
            ip = row.get(source_col)
            port = row.get(dest_port_col)
            if ip and port:
                try:
                    ip_connections[str(ip)].add(int(port))
                except:
                    pass
        
        # Detect port scans
        for ip, ports in ip_connections.items():
            if len(ports) >= self.port_scan_threshold:
                # Check if rapid connection (simulate time-based detection)
                threat = {
                    'type': 'port_scan',
                    'source_ip': ip,
                    'severity': 'High' if len(ports) > 20 else 'Medium',
                    'description': f"Port scan detected from {ip}: {len(ports)} different ports accessed",
                    'ports_scanned': list(ports)[:20],  # First 20 ports
                    'total_ports': len(ports)
                }
                threats.append(threat)
                self.detected_scans.append(threat)
        
        return threats
    
    def check_connection(self, source_ip, dest_port):
        """Check a single connection for port scan pattern"""
        timestamp = datetime.now()
        
        self.connection_attempts[source_ip].append({
            'port': dest_port,
            'timestamp': timestamp
        })
        
        # Get recent attempts
        recent_attempts = [
            a for a in self.connection_attempts[source_ip]
            if (timestamp - a['timestamp']).total_seconds() < self.time_window_seconds
        ]
        
        # Get unique ports
        unique_ports = set(a['port'] for a in recent_attempts)
        
        if len(unique_ports) >= self.port_scan_threshold:
            return {
                'port_scan_detected': True,
                'severity': 'High',
                'source_ip': source_ip,
                'unique_ports': len(unique_ports),
                'message': f'Port scan detected from {source_ip}: {len(unique_ports)} ports in {self.time_window_seconds}s'
            }
        
        return {
            'port_scan_detected': False,
            'severity': 'None',
            'unique_ports': len(unique_ports)
        }
    
    def get_connection_count(self, source_ip):
        """Get number of connections from an IP"""
        return len(self.connection_attempts.get(source_ip, []))
    
    def get_scanned_ports(self, source_ip):
        """Get list of ports scanned by an IP"""
        ports = set()
        for attempt in self.connection_attempts.get(source_ip, []):
            ports.add(attempt['port'])
        return list(ports)
    
    def clear_old_records(self, hours=1):
        """Clear connection records older than specified hours"""
        cutoff = datetime.now() - timedelta(hours=hours)
        
        for ip in list(self.connection_attempts.keys()):
            self.connection_attempts[ip] = [
                a for a in self.connection_attempts[ip]
                if a['timestamp'] > cutoff
            ]
            if not self.connection_attempts[ip]:
                del self.connection_attempts[ip]
    
    def get_detected_scans(self):
        """Get all detected port scans"""
        return self.detected_scans
    
    def load_network_data(self, file_path=None):
        """Load network data from CSV file"""
        if file_path is None:
            # Use the PortScan dataset
            file_path = os.path.join(DATASET_PATH, 'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv')
        
        if not os.path.exists(file_path):
            # Return sample data
            return self._create_sample_data()
        
        try:
            df = pd.read_csv(file_path, nrows=10000)  # Limit rows for performance
            return df
        except Exception as e:
            print(f"Error loading network data: {str(e)}")
            return self._create_sample_data()
    
    def _create_sample_data(self):
        """Create sample network data for demonstration"""
        sample_data = []
        
        # Normal traffic
        for i in range(100):
            sample_data.append({
                'source_ip': f'192.168.1.{10+i%10}',
                'dest_port': np.random.choice([80, 443, 22, 3306, 8080]),
                'bytes': np.random.randint(100, 10000),
                'packets': np.random.randint(1, 100)
            })
        
        # Port scan traffic (single IP scanning many ports)
        for port in range(1, 100):  # Scan ports 1-100
            sample_data.append({
                'source_ip': '10.0.0.100',
                'dest_port': port,
                'bytes': np.random.randint(50, 200),
                'packets': 1
            })
        
        return pd.DataFrame(sample_data)

# Singleton instance
_monitor = None

def get_network_monitor():
    global _monitor
    if _monitor is None:
        _monitor = NetworkMonitor()
    return _monitor
