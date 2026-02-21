#!/usr/bin/env python3
import json
import random
from datetime import datetime, timedelta
import os

def generate_network_data(num_flows=500):
    random.seed(42)

    suspicious_ips = ["203.0.113.10", "198.51.100.77", "192.0.2.55", "45.33.32.156"]
    suspicious_domains = ["c2.bad-domain.example", "exfil.bad-domain.example", "dropper.bad-domain.example"]

    countries = ["US", "CN", "RU", "IN", "DE", "FR", "BR"]
    protocols = ["TCP", "UDP", "HTTP", "HTTPS", "DNS"]
    indicators = ["C2", "EXFIL", "PORT_SCAN", "NONE"]

    start_time = datetime.now() - timedelta(days=2)
    end_time = datetime.now()

    flows = []

    for _ in range(num_flows):
        ts = start_time + timedelta(seconds=random.randint(0, int((end_time - start_time).total_seconds())))
        src_ip = f"10.1.{random.randint(0,9)}.{random.randint(1,254)}"

        if random.random() < 0.2:
            dst_ip = random.choice(suspicious_ips)
            dst_domain = random.choice(suspicious_domains)
            threat_indicator = random.choice(["C2", "EXFIL"])
            country = random.choice(["CN", "RU"])
        else:
            dst_ip = f"172.20.{random.randint(0,9)}.{random.randint(1,254)}"
            dst_domain = random.choice(["cdn.example.com", "api.example.com", "updates.example.com", "mail.example.com"])
            threat_indicator = random.choice(indicators)
            country = random.choice(countries)

        proto = random.choice(protocols)
        dst_port = random.choice([53, 80, 443, 22, 8080, 445, 3389])
        bytes_sent = random.randint(500, 200000)
        bytes_received = random.randint(500, 300000)

        if threat_indicator == "EXFIL":
            bytes_sent = random.randint(200000, 2000000)
            bytes_received = random.randint(1000, 50000)

        flow = {
            "timestamp": ts.isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_domain": dst_domain,
            "dst_port": dst_port,
            "protocol": proto,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "geo": {"country": country},
            "threat_indicator": threat_indicator
        }

        flows.append(flow)

    flows.sort(key=lambda x: x["timestamp"])
    return flows

def save_network_data(flows, filepath):
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(flows, f, indent=2)
        print(f"Saved network data to {filepath} ({len(flows)} flows)")
        return True
    except Exception as e:
        print("Error saving network data:", str(e))
        return False

if __name__ == "__main__":
    flows = generate_network_data(num_flows=500)
    save_network_data(flows, "../data/network/network_analysis.json")
