#!/usr/bin/env python3
import argparse
import json
import random
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

FAKE_ATTACKER_IPS = [
    "185.220.101.44", "45.155.205.12", "194.61.24.9", "103.85.24.7",
    "91.240.118.33", "5.188.62.19", "198.51.100.23", "203.0.113.77",
]

SSH_USERNAMES = ["root", "admin", "ubuntu", "test", "administrator", "oracle", "postgres"]
SSH_PASSWORDS = ["123456", "password", "admin", "root", "toor", "P@ssw0rd", "qwerty"]

HTTP_TARGETS_RECON = ["/admin", "/.env", "/.git/config", "/config", "/api/keys", "/wp-login.php"]
SQLI_PAYLOADS = ["' OR '1'='1", "1; DROP TABLE users;--", "' UNION SELECT username,password FROM users--"]
XSS_PAYLOADS = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
CMD_PAYLOADS = ["; cat /etc/passwd", "| whoami", "`id`"]

def post_event(base_url, event):
    data = json.dumps(event).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url}/api/events", data=data,
        headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.URLError as e:
        print(f"[!] Failed to reach backend at {base_url}: {e}")
        return None

def now():
    return datetime.now(timezone.utc).isoformat()

def scenario_port_scan(base_url, ip):
    print(f"[SCAN] Port discovery from {ip}")
    for target in ["SSH-01", "HTTP-01", "DB-01"]:
        post_event(base_url, {
            "timestamp": now(), "source_ip": ip, "target": target,
            "protocol": "TCP", "event_type": "PORT_SCAN", "status": "detected",
        })
        time.sleep(0.05)

def scenario_ssh_brute_force(base_url, ip, attempts=8):
    print(f"[BRUTE] SSH authentication attempts from {ip}")
    for _ in range(attempts):
        post_event(base_url, {
            "timestamp": now(), "source_ip": ip, "target": "SSH-01",
            "protocol": "SSH", "event_type": "LOGIN_ATTEMPT",
            "username": random.choice(SSH_USERNAMES),
            "password": random.choice(SSH_PASSWORDS),
            "status": "failed",
        })
        time.sleep(0.05)

def scenario_http_recon(base_url, ip):
    print(f"[RECON] HTTP endpoint discovery from {ip}")
    for target in HTTP_TARGETS_RECON:
        post_event(base_url, {
            "timestamp": now(), "source_ip": ip, "target": target,
            "protocol": "HTTP", "event_type": "HTTP_REQUEST", "status": "detected",
        })
        time.sleep(0.05)

def scenario_sqli(base_url, ip):
    print(f"[SQLi] Malicious HTTP request from {ip}")
    post_event(base_url, {
        "timestamp": now(), "source_ip": ip, "target": "/api/login",
        "protocol": "HTTP", "event_type": "HTTP_REQUEST",
        "payload": random.choice(SQLI_PAYLOADS), "status": "detected",
    })

def scenario_xss(base_url, ip):
    print(f"[XSS] Suspicious payload from {ip}")
    post_event(base_url, {
        "timestamp": now(), "source_ip": ip, "target": "/comments",
        "protocol": "HTTP", "event_type": "HTTP_REQUEST",
        "payload": random.choice(XSS_PAYLOADS), "status": "detected",
    })

def scenario_cmd_injection(base_url, ip):
    print(f"[CMD] Command injection attempt from {ip}")
    post_event(base_url, {
        "timestamp": now(), "source_ip": ip, "target": "/api/ping",
        "protocol": "HTTP", "event_type": "HTTP_REQUEST",
        "payload": random.choice(CMD_PAYLOADS), "status": "detected",
    })

def scenario_db_probe(base_url, ip):
    print(f"[DB] Database probe from {ip}")
    post_event(base_url, {
        "timestamp": now(), "source_ip": ip, "target": "DB-01",
        "protocol": "DB", "event_type": "QUERY",
        "payload": random.choice(SQLI_PAYLOADS), "status": "detected",
    })

def run_full_kill_chain(base_url, ip):
    scenario_port_scan(base_url, ip)
    scenario_http_recon(base_url, ip)
    scenario_ssh_brute_force(base_url, ip, attempts=random.randint(4, 10))
    random.choice([scenario_sqli, scenario_xss, scenario_cmd_injection, scenario_db_probe])(base_url, ip)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:4000")
    parser.add_argument("--attackers", type=int, default=6)
    parser.add_argument("--continuous", action="store_true")
    args = parser.parse_args()

    print("[+] Starting simulation")
    print(f"[+] Target backend: {args.url}\n")

    ips = random.sample(FAKE_ATTACKER_IPS, min(args.attackers, len(FAKE_ATTACKER_IPS)))
    total = 0

    def one_round():
        nonlocal total
        for ip in ips:
            run_full_kill_chain(args.url, ip)
            total += 1

    one_round()
    if args.continuous:
        print("\n[+] Continuous mode — press Ctrl+C to stop")
        try:
            while True:
                time.sleep(random.uniform(3, 8))
                one_round()
        except KeyboardInterrupt:
            pass

    print(f"\n[+] Simulation complete — {total} attacker kill-chains generated")
    print(f"[+] Open the dashboard at {args.url}/ to see the results")

if __name__ == "__main__":
    main()
