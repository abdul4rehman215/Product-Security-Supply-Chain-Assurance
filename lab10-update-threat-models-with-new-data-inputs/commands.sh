#!/usr/bin/env bash
# Lab 10: Update Threat Models with New Data Inputs
# Environment: Ubuntu 24.04.x
# User: toor
# Working Dir: ~/threat-model-lab

# -------------------------------
# Task 1: Setup Lab Environment
# -------------------------------

mkdir -p ~/threat-model-lab/{data/{telemetry,network,threat-models},scripts,output,logs}
cd ~/threat-model-lab
ls -R

# -------------------------------
# Task 1: Create venv + install deps
# -------------------------------

python3 -m venv threat-env
source threat-env/bin/activate
which python

pip install pandas numpy matplotlib requests pyyaml

# -------------------------------
# Task 1: Run data generators
# (Fix applied: run from correct scripts directory)
# -------------------------------

cd ~/threat-model-lab/scripts
python3 telemetry_generator.py
python3 network_data_generator.py
cd ..

ls -lh data/telemetry/
ls -lh data/network/

# -------------------------------
# Task 2: Run threat model manager
# -------------------------------

cd ~/threat-model-lab/scripts
python3 threat_model_manager.py
cd ..

ls -lh data/threat-models/
ls -lh output/

# View threat model metadata summary
cat data/threat-models/updated_threat_model.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
print('Threat Model Summary:')
print(f\" Version: {data['metadata']['version']}\")
print(f\" Attack Patterns: {len(data['attack_patterns'])}\")
print(f\" Last Updated: {data['metadata']['last_updated']}\")"

# View threat report summary
cat output/threat_report.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
print('Threat Report Summary:')
print(f\" Total Patterns: {data['summary']['total_attack_patterns']}\")
print(f\" High Severity: {data['summary']['high_severity_techniques']}\")
print(f\" Recommendations: {len(data['recommendations'])}\")"

# -------------------------------
# Task 3: Run automated updater + logs
# -------------------------------

cd ~/threat-model-lab/scripts
python3 automated_threat_updater.py
cd ..

tail -20 logs/threat_updater.log
ls -lh data/threat-models/backups/

# -------------------------------
# Task 3: Generate visualizations
# -------------------------------

cd ~/threat-model-lab/scripts
python3 visualize_threats.py
cd ..

ls -lh output/*.png

# -------------------------------
# Task 4: Run workflow again + verify outputs
# -------------------------------

cd ~/threat-model-lab/scripts
python3 automated_threat_updater.py

echo "=== Threat Model ==="
ls -lh ../data/threat-models/

echo "=== Reports ==="
ls -lh ../output/

echo "=== Logs ==="
ls -lh ../logs/

echo "=== Backups ==="
ls -lh ../data/threat-models/backups/

# Optional: test config loader
python3 config_loader.py
