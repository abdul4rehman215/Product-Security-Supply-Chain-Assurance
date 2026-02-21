#!/bin/bash
# Lab 15: Detect Protocol Weaknesses with Crafted Packet Tests
# Commands Executed During Lab (sequential)

# -------------------------------
# Task 1: Verify Environment Setup
# -------------------------------
python3 --version
python3 -c "from scapy.all import *; print('Scapy ready')"

sudo apt update
sudo apt install -y python3-pip
pip3 install --break-system-packages colorama tabulate scapy

# -----------------------------------------------
# Task 1: Create Working Directory + Target Server
# -----------------------------------------------
mkdir -p ~/lab15_protocol_testing
cd ~/lab15_protocol_testing

nano protocol_server.py
python3 -m py_compile protocol_server.py

# Start server (Terminal 1)
python3 protocol_server.py

# --------------------------------------
# Task 2: Create Basic Packet Crafter
# --------------------------------------
# (Terminal 2)
cd ~/lab15_protocol_testing
nano packet_crafter.py
python3 packet_crafter.py

# -------------------------------
# Task 3: Automated Scanner Setup
# -------------------------------
nano automated_scanner.py
nano test_config.json

# --------------------------
# Task 3: Traffic Analyzer
# --------------------------
nano traffic_analyzer.py

# Terminal 2: start traffic capture first (sniff 30s)
sudo python3 traffic_analyzer.py

# Terminal 1/another terminal: run scanner while analyzer is sniffing
python3 automated_scanner.py

# ---------------------------
# Verify Files + View Report
# ---------------------------
ls
cat scan_report.json

# -------------------------------
# Troubleshooting / Verification
# -------------------------------
ss -tlnp | grep 8888
nc -zv 127.0.0.1 8888
