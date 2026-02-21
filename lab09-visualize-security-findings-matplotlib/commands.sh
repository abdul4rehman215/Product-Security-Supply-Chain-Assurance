#!/usr/bin/env bash
# Lab 09: Visualize Security Findings with Matplotlib
# Environment: Ubuntu 24.04.x (Cloud VM)
# User: toor
# Working Dir: ~/security_viz_lab

set -e

# -----------------------------
# Task 1: Environment Setup
# -----------------------------
mkdir -p ~/security_viz_lab/{data,scripts,outputs}
cd ~/security_viz_lab
ls -la

python3 --version

# Install dependencies (already present in the lab image)
pip3 install matplotlib pandas numpy seaborn

# -----------------------------
# Task 1: Data Preparation
# -----------------------------
# Create security events dataset
nano data/security_events.csv

# Create vulnerability dataset
nano data/vulnerabilities.csv

# Verify data files
ls -lh data/
head -5 data/security_events.csv

# -----------------------------
# Task 2: Basic Visualizations
# -----------------------------
nano scripts/basic_viz.py

cd ~/security_viz_lab/scripts
chmod +x basic_viz.py
python3 basic_viz.py
ls -lh ../outputs/

# -----------------------------
# Task 3: Timeline + Geo Analysis
# -----------------------------
nano timeline_viz.py
nano geo_viz.py

chmod +x timeline_viz.py geo_viz.py
python3 timeline_viz.py
python3 geo_viz.py
ls -lh ../outputs/

# -----------------------------
# Task 4: Vulnerability Dashboard
# -----------------------------
nano vuln_dashboard.py

chmod +x vuln_dashboard.py
python3 vuln_dashboard.py
ls -lh ../outputs/vuln_dashboard.png

# -----------------------------
# Task 5: Automated Security Report
# -----------------------------
nano report_generator.py

chmod +x report_generator.py
python3 report_generator.py
ls -lh ../outputs/security_report.pdf

# -----------------------------
# Task 5: Summary Stats Script
# -----------------------------
nano stats_summary.py

chmod +x stats_summary.py
python3 stats_summary.py
ls -lh ../outputs/security_summary.txt

# -----------------------------
# Final Verification
# -----------------------------
ls -lh ../outputs/
