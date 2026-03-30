"""
Threat Simulation Engine
Generates realistic cyber threats across all 4 severity levels
Triggers automated remediation system
"""

import requests
import time
import random
import json
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatSimulator:
    def __init__(self):
        self.api_url = "http://localhost:5000/api/detect"
        self.ip_pool = [
            "192.168.1.{}".format(i) for i in range(1, 255)
        ] + [
            "10.0.0.{}".format(i) for i in range(1, 255)
        ] + [
            "172.16.{}.{}".format(i//256, i%256) for i in range(1, 65535)
        ]
    
    def generate_threat_event(self, severity):
        """Generate realistic network event for given severity"""
        base_events = {
            'LOW': {
                'duration': random.randint(100, 1000),
                'fwd_bytes': random.randint(100, 2000),
                'bwd_bytes': random.randint(100, 2000),
                'packet_rate': random.randint(10, 50),
                'psh_flags': 1
            },
            'MEDIUM': {
                'duration': random.randint(500, 2000),
                'fwd_bytes': random.randint(500, 5000),
                'bwd_bytes': random.randint(100, 1000),
                'packet_rate': random.randint(20, 100),
                'psh_flags': random.randint(0, 3)
            },
            'HIGH': {
                'duration': random.randint(1000, 5000),
                'fwd_bytes': random.randint(10000, 50000),
                'bwd_bytes': random.randint(1000, 5000),
                'packet_rate': random.randint(100, 500),
                'psh_flags': random.randint(2, 10)
            },
            'CRITICAL': {
                'duration': random.randint(5000, 30000),
                'fwd_bytes': random.randint(100000, 1000000),
                'bwd_bytes': random.randint(10000, 100000),
                'packet_rate': random.randint(500, 5000),
                'psh_flags': random.randint(5, 50)
            }
        }
        
        event = base_events[severity]
        event.update({
            'ip': random.choice(self.ip_pool),
            'port': random.randint(20, 65535),
            'protocol': random.choice(['TCP', 'UDP', 'ICMP']),
            'severity': severity
        })
        
        return event
    
    def simulate_attack_sequence(self, attack_type, count=5):
        """Simulate specific attack pattern"""
        severities = {
            'port_scan': 'MEDIUM',
            'brute_force': 'HIGH', 
            'ddos': 'CRITICAL',
            'recon': 'LOW'
        }
        
        logger.info(f"🚨 Simulating {attack_type} attack ({count}x)")
        
        for i in range(count):
            event = self.generate_threat_event(severities[attack_type])
            response = self.send_to_detection(event)
            
            if response:
                logger.info(f"   {i+1}/{count} - {event['ip']}:{event['port']} -> {response.get('severity')} ({response.get('confidence'):.2f})")
            
            # Attack timing
            time.sleep(random.uniform(0.5, 3.0))
    
    def send_to_detection(self, event):
        """Send threat event to detection system"""
        try:
            response = requests.post(self.api_url, json=event, timeout=5)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.error(f"Failed to send event: {e}")
        return None
    
    def run_continuous_simulation(self, duration_minutes=10):
        """Run continuous threat simulation"""
        logger.info(f"🎯 Starting {duration_minutes}min continuous simulation...")
        start_time = time.time()
        
        attack_patterns = [
            ('recon', 3),
            ('port_scan', 8),
            ('brute_force', 5),
            ('ddos', 2)
        ]
        
        while time.time() - start_time < duration_minutes * 60:
            pattern, count = random.choice(attack_patterns)
            self.simulate_attack_sequence(pattern, count)
            time.sleep(random.uniform(5, 15))
        
        logger.info("✅ Simulation complete")

def main():
    simulator = ThreatSimulator()
    
    print("🎮 Threat Simulator Menu:")
    print("1. Quick test (all severity levels)")
    print("2. Continuous simulation (10min)")
    print("3. Custom attack sequence")
    
    choice = input("Select (1-3): ").strip()
    
    if choice == '1':
        for severity in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
            event = simulator.generate_threat_event(severity)
            print(f"\n🧪 Testing {severity}: {event['ip']}:{event['port']}")
            response = simulator.send_to_detection(event)
            time.sleep(2)
    
    elif choice == '2':
        simulator.run_continuous_simulation()
    
    elif choice == '3':
        attack = input("Attack type (port_scan/brute_force/ddos/recon): ")
        count = int(input("Count: "))
        simulator.simulate_attack_sequence(attack, count)
    
    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()
