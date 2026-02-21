#!/bin/bash
# Lab 08: Process Product Telemetry Data in Jupyter + Pandas
# Commands Executed During Lab

# ------------------------------
# Environment verification
# ------------------------------
python3 --version
jupyter --version
python3 -c "import pandas, numpy, matplotlib, seaborn; print('pandas', pandas.__version__); print('numpy', numpy.__version__); print('matplotlib', matplotlib.__version__); print('seaborn', seaborn.__version__)"

# ------------------------------
# Task 1: Create project structure
# ------------------------------
mkdir -p ~/telemetry_lab/{data,notebooks,scripts,output}
cd ~/telemetry_lab
ls -la

# ------------------------------
# Task 1: Create and run telemetry generator script
# ------------------------------
nano scripts/generate_telemetry.py
python3 scripts/generate_telemetry.py

ls -lh data/
head -5 data/product_telemetry.csv

# ------------------------------
# Task 2: Launch Jupyter Notebook
# ------------------------------
cd ~/telemetry_lab
jupyter notebook --ip=0.0.0.0 --port=8888 --no-browser

# (Notebook created in browser)
# notebooks/Telemetry_Analysis.ipynb

# Confirm notebook file exists (from a new terminal)
ls -lh notebooks/

# ------------------------------
# Task 3: Confirm plots saved from notebook
# ------------------------------
ls -lh output/

# ------------------------------
# Task 4: Create and run automation script
# ------------------------------
nano scripts/automate_analysis.py
python3 scripts/automate_analysis.py

# Review generated outputs
ls -lh output/
cat output/analysis_report.json
