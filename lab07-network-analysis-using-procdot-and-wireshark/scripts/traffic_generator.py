#!/usr/bin/env python3
# File: traffic_generator.py

import socket
import time
import threading
import requests
from datetime import datetime

class TrafficGenerator:
    def __init__(self):
        self.running = False
        self.urls = [
            "http://httpbin.org/get",
            "http://httpbin.org/post",
            "http://httpbin.org/headers"
        ]

    def generate_http_traffic(self):
        """Generate HTTP traffic simulating product API calls"""
        session = requests.Session()

        headers = {
            "User-Agent": "ProductSecurityLab/1.0",
            "X-Product-ID": "LAB-PRODUCT-001"
        }

        idx = 0
        while self.running:
            try:
                url = self.urls[idx % len(self.urls)]
                idx += 1

                # Alternate GET and POST
                if url.endswith("/post"):
                    payload = {
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "event": "heartbeat",
                        "component": "product_agent"
                    }
                    r = session.post(url, headers=headers, json=payload, timeout=10)
                    print(f"[HTTP] POST {url} -> {r.status_code} ({len(r.content)} bytes)")
                else:
                    r = session.get(url, headers=headers, timeout=10)
                    print(f"[HTTP] GET  {url} -> {r.status_code} ({len(r.content)} bytes)")

                time.sleep(2)

            except Exception as e:
                print(f"HTTP error: {e}")
                time.sleep(5)

    def generate_dns_traffic(self):
        """Generate DNS queries for product domains"""
        domains = [
            "product-security.example.com",
            "api.security-scanner.com"
        ]

        idx = 0
        while self.running:
            domain = domains[idx % len(domains)]
            idx += 1
            try:
                ip = socket.gethostbyname(domain)
                print(f"[DNS] {domain} -> {ip}")
            except Exception as e:
                print(f"[DNS] lookup failed for {domain}: {e}")

            time.sleep(3)

    def start(self):
        """Start traffic generation in separate threads"""
        self.running = True

        http_thread = threading.Thread(target=self.generate_http_traffic, daemon=True)
        dns_thread = threading.Thread(target=self.generate_dns_traffic, daemon=True)

        http_thread.start()
        dns_thread.start()

        print("[+] Traffic generator running. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[!] Stopping traffic generator...")
            self.running = False
            time.sleep(2)
            print("[+] Traffic generator stopped.")

if __name__ == "__main__":
    generator = TrafficGenerator()
    generator.start()
