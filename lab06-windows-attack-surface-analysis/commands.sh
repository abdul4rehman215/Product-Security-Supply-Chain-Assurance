#!/usr/bin/env bash
# Lab 06: Windows Attack Surface Analysis with OpenSource Tools
# Environment: Ubuntu 24.04.1 LTS (Cloud Lab)
# User: toor

# -----------------------------
# Task 1: Install Required Tools
# -----------------------------
sudo apt update
sudo apt install -y python3 python3-pip htop net-tools lsof

# Install Python libraries (user install due to permissions)
pip3 install --upgrade psutil tabulate colorama

# --------------------------------------------
# Task 1: Create Working Directory + Scripts
# --------------------------------------------
mkdir -p ~/attack_surface_lab
cd ~/attack_surface_lab
ls -la

# Create scripts (edited in nano)
nano process_enum.py
chmod +x process_enum.py
ls -la process_enum.py

nano service_enum.py
chmod +x service_enum.py
ls -la service_enum.py

# --------------------------------------------
# Task 1: Run Enumeration Scripts + Save Output
# --------------------------------------------
python3 process_enum.py
python3 service_enum.py

# Save results to file
python3 process_enum.py > enumeration_results.txt
python3 service_enum.py >> enumeration_results.txt
ls -la enumeration_results.txt

# --------------------------------------------
# Task 2: Attack Surface Analyzer
# --------------------------------------------
nano attack_surface_analyzer.py
chmod +x attack_surface_analyzer.py
ls -la attack_surface_analyzer.py

# --------------------------------------------
# Task 2: Vulnerability Scanner
# --------------------------------------------
cd ~/attack_surface_lab
nano vulnerability_scanner.py
chmod +x vulnerability_scanner.py
ls -la vulnerability_scanner.py

# --------------------------------------------
# Task 3: Run Complete Analysis
# --------------------------------------------
python3 attack_surface_analyzer.py
python3 vulnerability_scanner.py

# Validate JSON formatting
cat attack_surface_report.json | python3 -m json.tool

# --------------------------------------------
# Task 3: Generate Consolidated HTML Report
# --------------------------------------------
cd ~/attack_surface_lab
nano generate_report.py
python3 generate_report.py

# Verify files created
ls -la

# --------------------------------------------
# Manual Verification (Cross-check automation)
# --------------------------------------------
sudo netstat -tlnp
ps aux | grep -E 'root|www-data'
find /usr/bin -perm -4000 -type f 2>/dev/null
sudo cat /etc/ssh/sshd_config | grep -E 'PermitRoot|PasswordAuth'

# --------------------------------------------
# Analyst Notes / Findings Documentation
# --------------------------------------------
nano findings.md
cat findings.md
