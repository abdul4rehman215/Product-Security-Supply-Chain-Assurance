# ============================================================
# Lab 19: Apply CVSS Scoring to Discovered Threats
# Commands Only (no scripts)
# ============================================================

# ---------- Task 1: Setup + Data ----------
mkdir -p ~/cvss-lab/{vulnerabilities,scripts,reports}
cd ~/cvss-lab

# Create sample vulnerability data
nano vulnerabilities/sample_vulnerabilities.json

# Validate JSON
python3 -m json.tool vulnerabilities/sample_vulnerabilities.json

# Create manual calculation notes
nano vulnerabilities/manual_calculation.txt

# ---------- Task 2: CVSS Calculator Script ----------
nano scripts/cvss_calculator.py
chmod +x scripts/cvss_calculator.py

cd scripts
python3 cvss_calculator.py

# ---------- Task 3: Report Generator ----------
nano cvss_reporter.py

# Return to project root
cd ..

# Create additional test data
nano vulnerabilities/web_vulnerabilities.json

# Validate JSON
python3 -m json.tool vulnerabilities/web_vulnerabilities.json

# Generate reports (JSON / HTML / CSV)
cd scripts

python3 cvss_reporter.py ../vulnerabilities/sample_vulnerabilities.json -o ../reports/report.json
python3 cvss_reporter.py ../vulnerabilities/sample_vulnerabilities.json -o ../reports/report.html -f html
python3 cvss_reporter.py ../vulnerabilities/sample_vulnerabilities.json -o ../reports/report.csv -f csv

# Verify report files
ls ../reports

# ---------- Task 3: Prioritization Script ----------
nano prioritize_vulns.py

# Run prioritization on generated JSON report
python3 prioritize_vulns.py ../reports/report.json

# ---------- Task 4: Executive Summary ----------
nano ../reports/executive_summary.txt

# Optional quick check
ls -la ../reports
cat ../reports/executive_summary.txt
