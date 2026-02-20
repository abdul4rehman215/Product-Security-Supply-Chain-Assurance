#!/bin/bash
# Lab 01: OSINT-Based Product Reconnaissance with SpiderFoot & recon-ng
# Commands Executed During Lab

# -----------------------------
# Task 1: Install & Configure OSINT Tools
# -----------------------------

sudo apt update && sudo apt upgrade -y

sudo apt install -y python3 python3-pip python3-venv git curl wget build-essential \
python3-dev libxml2-dev libxslt1-dev zlib1g-dev libffi-dev libssl-dev \
dnsutils net-tools

python3 --version
pip3 --version

mkdir ~/osint-lab
cd ~/osint-lab

# ---- SpiderFoot install ----
git clone https://github.com/smicallef/spiderfoot.git
cd spiderfoot
pip3 install -r requirements.txt
python3 sf.py --help

# ---- recon-ng install ----
cd ~/osint-lab
git clone https://github.com/lanmaster53/recon-ng.git
cd recon-ng
pip3 install -r REQUIREMENTS
python3 recon-ng --help

# ---- Start SpiderFoot service ----
cd ~/osint-lab/spiderfoot
python3 sf.py -l 127.0.0.1:5001 &
sleep 5
curl -s http://127.0.0.1:5001 > /dev/null && echo "SpiderFoot running" || echo "Failed to start"


# -----------------------------
# Task 2: Create OSINT Automation Scripts
# -----------------------------

nano ~/osint-lab/spiderfoot_scanner.py
chmod +x ~/osint-lab/spiderfoot_scanner.py

nano ~/osint-lab/reconng_scanner.py
chmod +x ~/osint-lab/reconng_scanner.py

nano ~/osint-lab/osint_master.py
chmod +x ~/osint-lab/osint_master.py


# -----------------------------
# Task 3: Execute OSINT Reconnaissance
# -----------------------------

cd ~/osint-lab/spiderfoot

dig example.com A +short
dig example.com MX +short
dig example.com NS +short
dig -x 93.184.216.34 +short

for sub in www mail ftp api admin; do
  echo -n "Testing $sub.example.com: "
  dig +short $sub.example.com
done

cd ~/osint-lab

python3 spiderfoot_scanner.py example.com
python3 reconng_scanner.py example.com
python3 osint_master.py example.com

cat results/osint_report_*.json | python3 -m json.tool
cat results/osint_report_*.txt

grep -r "subdomain" results/


# -----------------------------
# Task 4: Analysis & Reporting Tools
# -----------------------------

nano ~/osint-lab/analyze_results.py
chmod +x ~/osint-lab/analyze_results.py

python3 analyze_results.py results/osint_report_*.json
