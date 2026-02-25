"""
Simulate Attack Scenarios
Script to simulate various attack scenarios for testing the threat detection system
"""

import os
import sys
import time
import random
import requests
from datetime import datetime

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

# API base URL
BASE_URL = 'http://localhost:5000'

class AttackSimulator:
    def __init__(self, token=None):
        self.token = token or self.get_token()
        
    def get_token(self):
        """Get authentication token"""
        response = requests.post(f'{BASE_URL}/api/auth/login', json={
            'username': 'admin',
            'password': 'admin123'
        })
        if response.ok:
            return response.json().get('access_token')
        return None
    
    def simulate_network_anomaly(self):
        """Simulate network anomaly detection"""
        print("\n[+] Simulating network anomaly...")
        
        # Generate random network traffic data
        data = {
            'Destination Port': random.choice([80, 443, 22, 8080]),
            'Flow Duration': random.randint(10, 1000),
            'Total Fwd Packets': random.randint(100, 1000),
            'Total Backward Packets': random.randint(0, 10),
            'Total Length of Fwd Packets': random.randint(1000, 10000),
            'Total Length of Bwd Packets': random.randint(0, 100),
            'Fwd Packet Length Max': random.randint(60, 100),
            'Fwd Packet Length Min': random.randint(40, 60),
            'Fwd Packet Length Mean': random.randint(45, 65),
            'Flow Bytes/s': random.randint(5000000, 50000000),
            'Flow Packets/s': random.randint(10000, 100000),
            'Flow IAT Mean': random.randint(1, 10),
            'Flow IAT Std': random.randint(0, 5),
            'Fwd IAT Total': random.randint(10, 100),
            'Bwd IAT Total': 0,
            'Fwd Header Length': random.randint(20, 40),
            'Bwd Header Length': 0,
            'Fwd Packets/s': random.randint(5000, 50000),
            'Bwd Packets/s': 0,
            'Min Packet Length': random.randint(40, 60),
            'Max Packet Length': random.randint(60, 100),
            'Packet Length Mean': random.randint(45, 65),
            'Average Packet Size': random.randint(45, 65),
            'Avg Fwd Segment Size': random.randint(45, 65),
            'Avg Bwd Segment Size': 0,
            'Subflow Fwd Packets': random.randint(100, 500),
            'Subflow Fwd Bytes': random.randint(5000, 30000),
            'Subflow Bwd Packets': 0,
            'Subflow Bwd Bytes': 0
        }
        
        headers = {'Authorization': f'Bearer {self.token}'}
        response = requests.post(
            f'{BASE_URL}/api/detection/analyze',
            json=data,
            headers=headers
        )
        
        if response.ok:
            result = response.json()
            print(f"    Result: Anomaly={result.get('anomaly')}, Score={result.get('anomaly_score', 0):.4f}")
            return result
        print(f"    Error: {response.text}")
        return None
    
    def simulate_brute_force(self):
        """Simulate brute force attack"""
        print("\n[+] Simulating brute force attack...")
        
        source_ips = ['10.0.0.100', '10.0.0.101', '192.168.100.50']
        
        for i in range(10):
            ip = random.choice(source_ips)
            headers = {'Authorization': f'Bearer {self.token}'}
            
            # Simulate failed login attempts
            threat_data = {
                'type': 'brute_force',
                'severity': 'High' if i >= 5 else 'Medium',
                'source_ip': ip,
                'description': f'Brute force attempt from {ip} - attempt {i+1}/10'
            }
            
            response = requests.post(
                f'{BASE_URL}/api/simulate/threat',
                json=threat_data,
                headers=headers
            )
            
            if response.ok:
                print(f"    Attempt {i+1}/10: Threat logged")
            time.sleep(0.5)
        
        return True
    
    def simulate_port_scan(self):
        """Simulate port scan attack"""
        print("\n[+] Simulating port scan attack...")
        
        attacker_ip = '10.0.0.200'
        headers = {'Authorization': f'Bearer {self.token}'}
        
        # Simulate scanning multiple ports
        for i in range(15):
            threat_data = {
                'type': 'port_scan',
                'severity': 'High' if i >= 10 else 'Medium',
                'source_ip': attacker_ip,
                'description': f'Port scan detected: {i+1} ports scanned'
            }
            
            response = requests.post(
                f'{BASE_URL}/api/simulate/threat',
                json=threat_data,
                headers=headers
            )
            
            if response.ok:
                print(f"    Scan progress: {i+1}/15 ports")
            time.sleep(0.3)
        
        return True
    
    def view_results(self):
        """View current threats and stats"""
        print("\n" + "="*50)
        print("CURRENT THREAT STATUS")
        print("="*50)
        
        headers = {'Authorization': f'Bearer {self.token}'}
        
        # Get stats
        response = requests.get(f'{BASE_URL}/api/threats/stats', headers=headers)
        if response.ok:
            stats = response.json()
            print(f"\nTotal Threats: {stats['total']}")
            print(f"Active Threats: {stats['active']}")
            print(f"\nSeverity Distribution:")
            for sev, count in stats['severity_distribution'].items():
                print(f"  {sev}: {count}")
        
        # Get recent threats
        response = requests.get(f'{BASE_URL}/api/threats?limit=5', headers=headers)
        if response.ok:
            threats = response.json()
            print(f"\nRecent Threats:")
            for t in threats:
                print(f"  - [{t['severity']}] {t['threat_type']}: {t['description'][:50]}...")
        
        # Get blocked IPs
        response = requests.get(f'{BASE_URL}/api/blocked-ips', headers=headers)
        if response.ok:
            blocked = response.json()
            print(f"\nBlocked IPs: {len(blocked)}")
            for ip in blocked[:3]:
                print(f"  - {ip['ip_address']}: {ip['reason']}")
        
        print()
    
    def run_scenario(self, scenario='all'):
        """Run attack simulation scenarios"""
        scenarios = {
            '1': ('Network Anomaly', self.simulate_network_anomaly),
            '2': ('Brute Force', self.simulate_brute_force),
            '3': ('Port Scan', self.simulate_port_scan),
            '4': ('All', lambda: [self.simulate_network_anomaly(), 
                                 self.simulate_brute_force(), 
                                 self.simulate_port_scan()])
        }
        
        if scenario == 'all':
            # Run all scenarios
            print("\n" + "="*50)
            print("ATTACK SIMULATION - ALL SCENARIOS")
            print("="*50)
            self.simulate_network_anomaly()
            self.simulate_brute_force()
            self.simulate_port_scan()
        elif scenario in scenarios:
            name, func = scenarios[scenario]
            print(f"\nRunning {name} simulation...")
            func()
        
        # Show results
        time.sleep(1)
        self.view_results()

def main():
    """Main entry point"""
    print("="*50)
    print("THREAT DETECTION ATTACK SIMULATOR")
    print("="*50)
    
    # Check if server is running
    try:
        response = requests.get(BASE_URL)
        print(f"\n[✓] Server is running at {BASE_URL}")
    except requests.exceptions.ConnectionError:
        print(f"\n[!] Error: Server not running at {BASE_URL}")
        print("    Please start the server with: python app.py")
        return
    
    # Get token
    simulator = AttackSimulator()
    if not simulator.token:
        print("\n[!] Error: Could not authenticate")
        return
    
    print("[✓] Authenticated successfully")
    
    # Show menu
    print("\nSelect attack scenario:")
    print("  1. Network Anomaly Detection")
    print("  2. Brute Force Attack")
    print("  3. Port Scan Attack")
    print("  4. All Scenarios")
    
    choice = input("\nEnter choice (1-4): ").strip()
    
    simulator.run_scenario(choice)
    
    print("\n[✓] Attack simulation complete!")

if __name__ == '__main__':
    main()
