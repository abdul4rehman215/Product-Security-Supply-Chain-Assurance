#!/bin/bash
# ============================================================
# Lab 17: Fuzz Network Protocols with Boofuzz
# Complete Command Execution Log
# Environment: Ubuntu 24.04 (Cloud Lab)
# ============================================================


# ------------------------------------------------------------
# Task 1: Install and Configure Boofuzz
# ------------------------------------------------------------

# Create lab directory
mkdir -p ~/boofuzz-lab
cd ~/boofuzz-lab

# Create virtual environment
python3 -m venv boofuzz-env

# Activate virtual environment
source boofuzz-env/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install Boofuzz
pip install boofuzz


# ------------------------------------------------------------
# Step 1.2: Verify Installation
# ------------------------------------------------------------

# Create verification script
nano verify_boofuzz.py

# Make executable
chmod +x verify_boofuzz.py

# Run verification script
python3 verify_boofuzz.py


# ------------------------------------------------------------
# Step 1.3: Create Configuration Module
# ------------------------------------------------------------

nano boofuzz_config.py


# ------------------------------------------------------------
# Task 2: Build Test Server and Protocol Definitions
# ------------------------------------------------------------

# Create test server
nano test_server.py

# Create protocol fuzzer definition
nano protocol_fuzzer.py

# Verify files created
ls -la


# ------------------------------------------------------------
# Task 2.3: Execute Manual Fuzzing Campaign
# ------------------------------------------------------------

cd ~/boofuzz-lab
source boofuzz-env/bin/activate

# Start test server in background
python3 test_server.py &
SERVER_PID=$!

# Display server PID
echo "Server PID: $SERVER_PID"

# Wait for server to initialize
sleep 2

# Run protocol fuzzer
python3 protocol_fuzzer.py

# Stop test server
kill $SERVER_PID

# Verify generated files
ls -1

# View fuzzing summary
cat fuzzing_summary_*.txt


# ------------------------------------------------------------
# Task 3: Implement Automated Fuzzing Framework
# ------------------------------------------------------------

# Create automated fuzzing framework
nano automated_fuzzer.py

# Create JSON configuration
nano fuzzing_config.json


# ------------------------------------------------------------
# Step 3.3: Run Automated Campaign
# ------------------------------------------------------------

cd ~/boofuzz-lab
source boofuzz-env/bin/activate

# Execute automated fuzzing framework
python3 automated_fuzzer.py

# List generated vulnerability reports
ls -1 vulnerability_report_*

# View text report
cat vulnerability_report_*.txt

# View JSON report
cat vulnerability_report_*.json


# ------------------------------------------------------------
# Step 3.4: Create Results Analysis Script
# ------------------------------------------------------------

nano analyze_results.py

# Run analysis script
python3 analyze_results.py


# ------------------------------------------------------------
# Optional Diagnostic Commands
# ------------------------------------------------------------

# Verify Python version
python3 --version

# Verify Boofuzz installed
pip show boofuzz

# Check port usage
ss -tlnp | grep 8080

# Deactivate virtual environment (if needed)
deactivate
