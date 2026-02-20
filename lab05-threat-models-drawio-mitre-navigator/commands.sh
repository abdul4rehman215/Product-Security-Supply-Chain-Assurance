#!/bin/bash
# Lab 05 - Create Threat Models in Draw.io + MITRE ATT&CK Navigator
# Commands Executed During Lab (sequential, no explanations)

# ----------------------------------------
# Task 1: Draw.io Access + Verification
# ----------------------------------------

firefox &

ls -lh ~/Downloads | grep -i ecommerce || true

# ----------------------------------------
# Task 2: MITRE ATT&CK Navigator Export Verification
# ----------------------------------------

ls -lh ~/Downloads | grep -i ecommerce_attack_layer || true

# ----------------------------------------
# Task 3: Python Environment Setup
# ----------------------------------------

cd ~/Desktop
mkdir -p threat_modeling_lab
cd threat_modeling_lab
pwd

nano requirements.txt

pip3 install --upgrade pip
pip3 install -r requirements.txt

# ----------------------------------------
# Task 4: Create + Syntax Check Scripts
# ----------------------------------------

nano mitre_fetcher.py
python3 -m py_compile mitre_fetcher.py

nano threat_model_generator.py
python3 -m py_compile threat_model_generator.py

nano drawio_exporter.py
python3 -m py_compile drawio_exporter.py

# ----------------------------------------
# Task 5: Run Automation Pipeline
# ----------------------------------------

chmod +x mitre_fetcher.py threat_model_generator.py drawio_exporter.py

python3 mitre_fetcher.py
python3 threat_model_generator.py
python3 drawio_exporter.py

ls -lh *.csv *.json *.png *.drawio *.txt
