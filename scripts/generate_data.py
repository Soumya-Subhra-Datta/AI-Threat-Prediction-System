"""
Generate Sample Network Data
Creates network_data.csv and logs_data.csv for the threat detection system
"""

import os
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

# Output directory
OUTPUT_DIR = os.path.join('..', 'datasets')

def generate_network_data():
    """Generate synthetic network traffic data"""
    print("Generating network traffic data...")
    
    # Network features similar to the UNSW-NB15 dataset
    data = []
    
    # Normal traffic patterns
    normal_ports = [80, 443, 22, 3306, 8080, 53, 21, 25, 110, 143]
    
    # Generate normal traffic
    for i in range(5000):
        row = {
            'Destination Port': np.random.choice(normal_ports),
            'Flow Duration': np.random.randint(100, 100000),
            'Total Fwd Packets': np.random.randint(1, 50),
            'Total Backward Packets': np.random.randint(0, 30),
            'Total Length of Fwd Packets': np.random.randint(50, 5000),
            'Total Length of Bwd Packets': np.random.randint(0, 3000),
            'Fwd Packet Length Max': np.random.randint(50, 1500),
            'Fwd Packet Length Min': np.random.randint(40, 100),
            'Fwd Packet Length Mean': np.random.randint(45, 500),
            'Flow Bytes/s': np.random.randint(1000, 1000000),
            'Flow Packets/s': np.random.randint(10, 5000),
            'Flow IAT Mean': np.random.randint(10, 1000),
            'Flow IAT Std': np.random.randint(0, 500),
            'Fwd IAT Total': np.random.randint(100, 10000),
            'Bwd IAT Total': np.random.randint(0, 5000),
            'Fwd Header Length': np.random.randint(20, 100),
            'Bwd Header Length': np.random.randint(0, 80),
            'Fwd Packets/s': np.random.randint(5, 2000),
            'Bwd Packets/s': np.random.randint(0, 1000),
            'Min Packet Length': np.random.randint(40, 60),
            'Max Packet Length': np.random.randint(500, 1500),
            'Packet Length Mean': np.random.randint(100, 600),
            'Average Packet Size': np.random.randint(100, 600),
            'Avg Fwd Segment Size': np.random.randint(50, 500),
            'Avg Bwd Segment Size': np.random.randint(0, 300),
            'Subflow Fwd Packets': np.random.randint(1, 30),
            'Subflow Fwd Bytes': np.random.randint(50, 3000),
            'Subflow Bwd Packets': np.random.randint(0, 20),
            'Subflow Bwd Bytes': np.random.randint(0, 2000),
            'Label': 'BENIGN'
        }
        data.append(row)
    
    # Generate anomalous traffic (simulated attacks)
    # DDoS-like patterns
    for i in range(500):
        row = {
            'Destination Port': np.random.choice([80, 443, 8080]),
            'Flow Duration': np.random.randint(10, 1000),
            'Total Fwd Packets': np.random.randint(100, 1000),
            'Total Backward Packets': np.random.randint(0, 10),
            'Total Length of Fwd Packets': np.random.randint(1000, 10000),
            'Total Length of Bwd Packets': np.random.randint(0, 100),
            'Fwd Packet Length Max': np.random.randint(60, 100),
            'Fwd Packet Length Min': np.random.randint(40, 60),
            'Fwd Packet Length Mean': np.random.randint(45, 65),
            'Flow Bytes/s': np.random.randint(5000000, 50000000),
            'Flow Packets/s': np.random.randint(10000, 100000),
            'Flow IAT Mean': np.random.randint(1, 10),
            'Flow IAT Std': np.random.randint(0, 5),
            'Fwd IAT Total': np.random.randint(10, 100),
            'Bwd IAT Total': 0,
            'Fwd Header Length': np.random.randint(20, 40),
            'Bwd Header Length': 0,
            'Fwd Packets/s': np.random.randint(5000, 50000),
            'Bwd Packets/s': 0,
            'Min Packet Length': np.random.randint(40, 60),
            'Max Packet Length': np.random.randint(60, 100),
            'Packet Length Mean': np.random.randint(45, 65),
            'Average Packet Size': np.random.randint(45, 65),
            'Avg Fwd Segment Size': np.random.randint(45, 65),
            'Avg Bwd Segment Size': 0,
            'Subflow Fwd Packets': np.random.randint(100, 500),
            'Subflow Fwd Bytes': np.random.randint(5000, 30000),
            'Subflow Bwd Packets': 0,
            'Subflow Bwd Bytes': 0,
            'Label': 'DDoS'
        }
        data.append(row)
    
    # Port scan patterns
    for i in range(300):
        row = {
            'Destination Port': np.random.randint(1, 1000),
            'Flow Duration': np.random.randint(1, 100),
            'Total Fwd Packets': np.random.randint(1, 3),
            'Total Backward Packets': 0,
            'Total Length of Fwd Packets': np.random.randint(40, 100),
            'Total Length of Bwd Packets': 0,
            'Fwd Packet Length Max': np.random.randint(40, 60),
            'Fwd Packet Length Min': np.random.randint(40, 50),
            'Fwd Packet Length Mean': np.random.randint(40, 50),
            'Flow Bytes/s': np.random.randint(100000, 1000000),
            'Flow Packets/s': np.random.randint(10000, 50000),
            'Flow IAT Mean': np.random.randint(1, 5),
            'Flow IAT Std': np.random.randint(0, 2),
            'Fwd IAT Total': np.random.randint(1, 10),
            'Bwd IAT Total': 0,
            'Fwd Header Length': np.random.randint(20, 30),
            'Bwd Header Length': 0,
            'Fwd Packets/s': np.random.randint(10000, 50000),
            'Bwd Packets/s': 0,
            'Min Packet Length': np.random.randint(40, 50),
            'Max Packet Length': np.random.randint(40, 60),
            'Packet Length Mean': np.random.randint(40, 50),
            'Average Packet Size': np.random.randint(40, 50),
            'Avg Fwd Segment Size': np.random.randint(40, 50),
            'Avg Bwd Segment Size': 0,
            'Subflow Fwd Packets': np.random.randint(1, 3),
            'Subflow Fwd Bytes': np.random.randint(40, 100),
            'Subflow Bwd Packets': 0,
            'Subflow Bwd Bytes': 0,
            'Label': 'PortScan'
        }
        data.append(row)
    
    df = pd.DataFrame(data)
    
    # Save to CSV
    output_path = os.path.join(OUTPUT_DIR, 'network_data.csv')
    df.to_csv(output_path, index=False)
    print(f"Network data saved to: {output_path}")
    print(f"Total records: {len(df)}")
    print(f"Label distribution:\n{df['Label'].value_counts()}")
    
    return df

def generate_logs_data():
    """Generate synthetic system logs"""
    print("\nGenerating system logs data...")
    
    data = []
    base_time = datetime.now() - timedelta(days=7)
    
    # Normal login events
    users = ['admin', 'root', 'user1', 'user2', 'demo']
    normal_ips = [f'192.168.1.{i}' for i in range(10, 30)]
    services = ['ssh', 'ftp', 'http', 'https', 'mysql']
    
    for i in range(1000):
        timestamp = base_time + timedelta(minutes=i*10)
        user = np.random.choice(users)
        ip = np.random.choice(normal_ips)
        service = np.random.choice(services)
        
        # Mostly successful logins
        status = 'success' if random.random() > 0.1 else 'failed'
        
        data.append({
            'timestamp': timestamp.isoformat(),
            'source_ip': ip,
            'username': user,
            'status': status,
            'service': service,
            'message': f'{service} login {"successful" if status == "success" else "failed"} for user {user}'
        })
    
    # Brute force attempts
    attacker_ips = ['10.0.0.50', '10.0.0.51', '10.0.0.52', '192.168.100.10']
    for ip in attacker_ips:
        for attempt in range(20):
            timestamp = base_time + timedelta(hours=attempt*2)
            data.append({
                'timestamp': timestamp.isoformat(),
                'source_ip': ip,
                'username': np.random.choice(['root', 'admin', 'oracle']),
                'status': 'failed',
                'service': 'ssh',
                'message': f'Failed SSH login attempt for user root from {ip}'
            })
    
    # Successful login after brute force (account compromise)
    for ip in attacker_ips[:2]:
        timestamp = base_time + timedelta(hours=40)
        data.append({
            'timestamp': timestamp.isoformat(),
            'source_ip': ip,
            'username': 'root',
            'status': 'success',
            'service': 'ssh',
            'message': f'Successful SSH login for user root from {ip} (possible compromise)'
        })
    
    df = pd.DataFrame(data)
    
    # Save to CSV
    output_path = os.path.join(OUTPUT_DIR, 'logs_data.csv')
    df.to_csv(output_path, index=False)
    print(f"Logs data saved to: {output_path}")
    print(f"Total records: {len(df)}")
    print(f"Status distribution:\n{df['status'].value_counts()}")
    
    return df

if __name__ == '__main__':
    # Generate both datasets
    generate_network_data()
    generate_logs_data()
    print("\nData generation complete!")
