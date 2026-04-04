import requests
import time
import random
import json

# API Endpoint of the Flask application
FLASK_URL = "http://localhost:5000/api/threat_data"

def generate_random_ip():
    return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

def simulate_traffic():
    print("--- Starting Attack Simulator ---")
    print("Sending traffic data to Flask backend...\n")
    
    threat_types = ['Low', 'Medium', 'High', 'Critical']
    
    while True:
        target_threat = random.choice(threat_types)
        
        # Generate features based on targeted threat level (matches training distribution)
        if target_threat == 'Low':
            data = {
                "ip": generate_random_ip(),
                "packet_size": random.uniform(400, 600),
                "request_rate": random.uniform(5, 15),
                "failed_logins": random.randint(0, 1),
                "payload_size": random.uniform(100, 300)
            }
        elif target_threat == 'Medium':
            data = {
                "ip": generate_random_ip(),
                "packet_size": random.uniform(1000, 2000),
                "request_rate": random.uniform(40, 60),
                "failed_logins": random.randint(1, 3),
                "payload_size": random.uniform(500, 1000)
            }
        elif target_threat == 'High':
            data = {
                "ip": generate_random_ip(),
                "packet_size": random.uniform(4000, 6000),
                "request_rate": random.uniform(100, 200),
                "failed_logins": random.randint(3, 8),
                "payload_size": random.uniform(2000, 3000)
            }
        else: # Critical
            data = {
                "ip": generate_random_ip(),
                "packet_size": random.uniform(8000, 12000),
                "request_rate": random.uniform(400, 600),
                "failed_logins": random.randint(10, 30),
                "payload_size": random.uniform(7000, 9000)
            }

        print(f"--> Sending Sim Traffic: Intended {target_threat} from {data['ip']}")
        
        try:
            response = requests.post(FLASK_URL, json=data)
            if response.status_code == 200:
                result = response.json()
                print(f"<-- System Response: Level {result['level']} | Action: {result['action']}\n")
            else:
                print(f"Error: {response.status_code}")
        except requests.exceptions.ConnectionError:
            print("Connection Error: Is the Flask server running on http://localhost:5000?")
            break
            
        # Wait before sending next packet
        time.sleep(random.uniform(1.5, 3.5))

if __name__ == "__main__":
    try:
        simulate_traffic()
    except KeyboardInterrupt:
        print("\nSimulator stopped by user.")