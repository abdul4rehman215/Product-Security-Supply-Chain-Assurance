#!/usr/bin/env bash
# Lab 12: Analyze Update Mechanisms for Supply Chain Risks
# Environment: Ubuntu 24.04 LTS (Cloud Lab)
# User: toor

set -e

# ----------------------------
# Task 1: Working Directory
# ----------------------------
mkdir -p ~/supply-chain-lab
cd ~/supply-chain-lab
pwd

# ----------------------------
# Task 1: Audit Package Manager Security
# ----------------------------

# View APT sources
cat /etc/apt/sources.list

# List additional repo source files
ls -la /etc/apt/sources.list.d/

# Audit keys (apt-key deprecated but used for audit)
sudo apt-key list

# Create package analyzer script
nano package_analyzer.py

# Run analyzer
chmod +x package_analyzer.py
python3 package_analyzer.py

# View generated report
cat package_security_report.json

# ----------------------------
# Task 2: Monitor Update Network Traffic
# ----------------------------

# Ubuntu 24.04 note: netstat may not be installed by default
sudo apt update
sudo apt install -y net-tools

# Create update monitor script
nano update_monitor.py

# Run traffic monitor
python3 update_monitor.py

# View generated traffic report
cat update_traffic_report.json

# ----------------------------
# Task 3: Evaluate TLS Security of Update Servers
# ----------------------------

# Create TLS analyzer script
nano tls_analyzer.py

# Run TLS analysis
python3 tls_analyzer.py

# View generated TLS report
cat tls_security_report.json

# ----------------------------
# Task 4: Integrated Supply Chain Auditor
# ----------------------------

# Create integrated auditor script
nano supply_chain_auditor.py

# Run integrated audit
python3 supply_chain_auditor.py

# Verify generated deliverables
ls -la

# View integrated audit summary
cat supply_chain_audit_report.txt
