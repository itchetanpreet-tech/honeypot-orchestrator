#!/usr/bin/env python3
import json
import random
import time
import urllib.request
import urllib.error

# Render URL (apna Render URL daalo)
RENDER_URL = "https://honeypot-orchestrator.onrender.com/api/events"

# Fake attacker IPs
FAKE_IPS = [
    "192.168.1.100", "10.0.0.50", "172.16.0.10", 
    "203.0.113.50", "185.220.101.44", "45.155.205.12",
    "194.61.24.9", "103.85.24.7", "91.240.118.33"
]

# Attack types ke liye payloads
PAYLOADS = [
    "", 
    "' OR '1'='1", 
    "<script>alert(1)</script>", 
    "; cat /etc/passwd",
    "1; DROP TABLE users;--",
    "<img src=x onerror=alert(1)>",
    "| whoami"
]

def send_event():
    """Ek random event generate karke Render pe bhejo"""
    
    # Random event generate karo
    event = {
        "source_ip": random.choice(FAKE_IPS),
        "target": random.choice(["SSH-01", "HTTP-01", "DB-01"]),
        "protocol": random.choice(["SSH", "HTTP", "DB"]),
        "event_type": random.choice(["LOGIN_ATTEMPT", "HTTP_REQUEST", "QUERY", "PORT_SCAN"]),
        "username": random.choice(["admin", "root", "test", "ubuntu", "oracle", "postgres"]),
        "password": random.choice(["password", "123456", "admin", "root", "P@ssw0rd", "qwerty", "toor"]),
        "status": "failed",
        "payload": random.choice(PAYLOADS)
    }
    
    # JSON data prepare karo
    data = json.dumps(event).encode('utf-8')
    
    # Request bhejo
    req = urllib.request.Request(
        RENDER_URL, 
        data=data, 
        headers={"Content-Type": "application/json"}, 
        method="POST"
    )
    
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            print(f"✅ {event['source_ip']} → {event['event_type']} → {event['target']}")
            return True
    except urllib.error.URLError as e:
        print(f"❌ Connection error: {e}")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def main():
    print("=" * 50)
    print("🔄 Sending events to Render...")
    print(f"📍 Target: {RENDER_URL}")
    print("⏹️  Press Ctrl+C to stop")
    print("=" * 50)
    
    count = 0
    success = 0
    
    try:
        while True:
            count += 1
            if send_event():
                success += 1
            
            # Har 10 events ke baad status dikhao
            if count % 10 == 0:
                print(f"📊 Sent: {count} | Success: {success} | Failed: {count - success}")
            
            # 2-5 seconds ka random gap
            time.sleep(random.uniform(2, 5))
            
    except KeyboardInterrupt:
        print("\n" + "=" * 50)
        print(f"✅ Stopped! Total: {count} | Success: {success} | Failed: {count - success}")
        print("=" * 50)

if __name__ == "__main__":
    main()