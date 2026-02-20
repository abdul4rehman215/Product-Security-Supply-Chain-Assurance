#!/usr/bin/env bash
# Lab 7: Trace Product Network Activity Using ProcDOT & Wireshark
# Environment: Ubuntu 24.04.1 LTS
# User: toor

# --------------------------------------------------
# Task 1: Verify Installation
# --------------------------------------------------

wireshark --version
tshark --version
python3 --version

# --------------------------------------------------
# Add user to wireshark group for capture permissions
# --------------------------------------------------

sudo usermod -a -G wireshark $USER
newgrp wireshark

# --------------------------------------------------
# Create Working Directory
# --------------------------------------------------

mkdir -p ~/lab7_network_analysis
cd ~/lab7_network_analysis
pwd

# --------------------------------------------------
# Install Required Python Libraries
# --------------------------------------------------

pip3 install --upgrade requests pyshark pandas matplotlib networkx

# --------------------------------------------------
# Identify Network Interfaces
# --------------------------------------------------

ip link show
tshark -D

# --------------------------------------------------
# Create Traffic Generator Script
# --------------------------------------------------

nano traffic_generator.py
chmod +x traffic_generator.py

# --------------------------------------------------
# Start Packet Capture (Background)
# --------------------------------------------------

tshark -i any -w product_traffic.pcap -f "not port 22" &
CAPTURE_PID=$!
echo "Capture PID: $CAPTURE_PID"

# --------------------------------------------------
# Start Traffic Generation (Foreground)
# --------------------------------------------------

python3 traffic_generator.py

# --------------------------------------------------
# Stop Packet Capture
# --------------------------------------------------

kill $CAPTURE_PID

# --------------------------------------------------
# Confirm PCAP File
# --------------------------------------------------

ls -lh product_traffic.pcap

# --------------------------------------------------
# Analyze Basic Statistics
# --------------------------------------------------

tshark -r product_traffic.pcap -q -z conv,ip
tshark -r product_traffic.pcap -q -z endpoints,ip

# --------------------------------------------------
# Task 2: Convert PCAP to CSV
# --------------------------------------------------

nano pcap_converter.py
chmod +x pcap_converter.py

python3 pcap_converter.py product_traffic.pcap network_data.csv
ls -lh network_data.csv

# --------------------------------------------------
# Create Process Monitor Log Simulator
# --------------------------------------------------

nano create_procmon_log.py
chmod +x create_procmon_log.py

python3 create_procmon_log.py
ls -lh procmon_log.csv

# --------------------------------------------------
# Task 3: Network Visualization
# --------------------------------------------------

nano network_visualizer.py
chmod +x network_visualizer.py

python3 network_visualizer.py
ls -lh network_flows.png

xdg-open network_flows.png

# --------------------------------------------------
# Task 4: Automated Analysis Pipeline
# --------------------------------------------------

nano automated_analysis.py
chmod +x automated_analysis.py

nano config.py

mkdir -p analysis_output

python3 automated_analysis.py

ls -lh analysis_output/

# --------------------------------------------------
# Final Verification
# --------------------------------------------------

ls -lh
