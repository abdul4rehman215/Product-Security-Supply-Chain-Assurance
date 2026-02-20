# ==========================================================
# Lab 4: Linux Service Enumeration with nmap & netstat
# ALL commands executed during this lab
# ==========================================================

# -----------------------------
# Task 1: nmap Enumeration
# -----------------------------

# Verify nmap installation
which nmap

# Update system (if needed)
sudo apt update

# Install nmap (if not installed)
sudo apt install nmap -y

# Check nmap version
nmap --version

# Basic scan
nmap localhost

# Scan specific port range
nmap -p 1-1000 localhost

# Scan all ports
nmap -p- localhost

# Service version detection
nmap -sV localhost

# Aggressive scan (OS detection + scripts)
nmap -A localhost

# Default script scan + version detection
nmap -sC -sV localhost

# Create comprehensive scanning script
nano nmap_scan.sh

# Make script executable
chmod +x nmap_scan.sh

# Run scanning script
./nmap_scan.sh

# Verify scan results directory
ls -la scan_results


# -----------------------------
# Task 2: netstat Enumeration
# -----------------------------

# Verify netstat installation
which netstat

# Install net-tools (if required)
sudo apt install net-tools -y

# Check netstat version
netstat --version

# Show listening ports
netstat -l

# Show listening ports with process info
netstat -lp

# Show TCP listening ports
netstat -lt

# Show UDP listening ports
netstat -lu

# Show numeric listening ports
netstat -ln

# Show all active connections
netstat -a

# Show active TCP connections
netstat -at

# Show all connections with process info
netstat -ap

# Show network statistics
netstat -s

# Show routing table
netstat -r

# Create netstat monitoring script
nano netstat_monitor.sh

# Make script executable
chmod +x netstat_monitor.sh

# Run monitoring script
./netstat_monitor.sh

# Verify output files
ls -la netstat_results | head


# -----------------------------
# Task 3: Python Automation
# -----------------------------

# Install pip (if required)
sudo apt install python3-pip -y

# Install python-nmap module
pip3 install python-nmap

# Verify python-nmap installation
python3 -c "import nmap; print('python-nmap installed successfully')"

# Create automation scripts
nano service_enumeration.py
nano advanced_nmap_scripts.py

# Make Python scripts executable
chmod +x service_enumeration.py
chmod +x advanced_nmap_scripts.py

# Run main enumeration script
python3 service_enumeration.py

# Run advanced scanning script
python3 advanced_nmap_scripts.py

# Verify advanced scan JSON file
ls -la advanced_scan_*.json | tail -1


# -----------------------------
# Task 3.5: Master Automation
# -----------------------------

# Create master enumeration script
nano master_enumeration.sh

# Make executable
chmod +x master_enumeration.sh

# Run master script
./master_enumeration.sh

# View master summary
cat master_enumeration_*/master_summary.txt

# View JSON reports
ls -la */enumeration_report_*.json

# Compare nmap vs netstat results
diff <(grep "open" */nmap_basic.txt | awk '{print $1}') \
     <(grep "LISTEN" */netstat_listening.txt | awk '{print $4}' | cut -d: -f2 | sort -u)

# -----------------------------
# Service Analysis
# -----------------------------

# Create service analysis script
nano analyze_services.py

# Run service analysis
python3 analyze_services.py
