#!/bin/bash
# Lab 18: Develop Attack Trees for Identified Vulnerabilities
# Environment: Ubuntu 24.04 LTS

# -----------------------------
# Task 1: Environment Setup
# -----------------------------

# Create project structure
mkdir -p ~/attack-trees-lab/{data,scripts,output}
cd ~/attack-trees-lab

# Update system and install dependencies
sudo apt update
sudo apt install -y python3-pip python3-venv graphviz

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install required Python libraries
pip install networkx matplotlib anytree

# -----------------------------
# Task 1.2: Create dataset
# -----------------------------

# Create vulnerability dataset
nano data/vulnerabilities.json

# Validate JSON structure
python3 -m json.tool data/vulnerabilities.json

# -----------------------------
# Task 2: Attack Tree Framework
# -----------------------------

# Create attack tree framework script
nano scripts/attack_tree.py

# Test attack tree framework
cd ~/attack-trees-lab/scripts
python3 attack_tree.py

# Create vulnerability-specific attack trees script
cd ~/attack-trees-lab
nano scripts/vuln_attack_trees.py

# Run vulnerability attack tree generator
cd ~/attack-trees-lab/scripts
python3 vuln_attack_trees.py

# -----------------------------
# Task 3: Attack Path Mapping
# -----------------------------

# Create attack path mapper script
cd ~/attack-trees-lab
nano scripts/attack_path_mapper.py

# Run attack path analysis
cd ~/attack-trees-lab/scripts
python3 attack_path_mapper.py

# -----------------------------
# Task 4: Risk Analysis
# -----------------------------

# Create risk analyzer script
cd ~/attack-trees-lab
nano scripts/risk_analyzer.py

# Run risk analyzer and generate remediation report
cd ~/attack-trees-lab/scripts
python3 risk_analyzer.py

# View generated remediation report
cat ../output/remediation_report.json
