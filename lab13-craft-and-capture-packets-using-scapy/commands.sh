#!/usr/bin/env bash
set -e

echo "==============================================="
echo "Lab 13: Craft and Capture Packets Using Scapy"
echo "==============================================="

# --------------------------------------------
# Task 1: Install & Verify Scapy
# --------------------------------------------
echo "[+] Updating system and installing dependencies..."
sudo apt update
sudo apt install -y python3-pip python3-dev libpcap-dev tcpdump curl dnsutils python3-scapy

echo "[+] Verifying Scapy installation..."
sudo python3 -c "import scapy; print('Scapy version:', scapy.__version__)"

echo "[+] Checking network interfaces..."
ip addr show

# --------------------------------------------
# Task 2: Packet Crafting
# --------------------------------------------
echo "[+] Running packet crafting scripts..."
cd scripts

chmod +x packet_crafter.py
sudo python3 packet_crafter.py

chmod +x advanced_crafter.py
sudo python3 advanced_crafter.py

mkdir -p ../pcaps
mv -f crafted_packets.pcap ../pcaps/ 2>/dev/null || true
mv -f advanced_packets.pcap ../pcaps/ 2>/dev/null || true

# --------------------------------------------
# Task 3: Generate Traffic for Capture
# --------------------------------------------
echo "[+] Generating test traffic..."
ping -c 5 127.0.0.1 >/dev/null 2>&1 &
curl -s http://example.com >/dev/null 2>&1 &
nslookup google.com >/dev/null 2>&1 &

sleep 2

echo "[+] Running packet capture scripts..."

chmod +x packet_capture.py
sudo python3 packet_capture.py
mv -f captured.pcap ../pcaps/ 2>/dev/null || true

chmod +x filtered_capture.py
sudo python3 filtered_capture.py

mv -f tcp_only.pcap ../pcaps/ 2>/dev/null || true
mv -f http_traffic.pcap ../pcaps/ 2>/dev/null || true
mv -f dns_traffic.pcap ../pcaps/ 2>/dev/null || true

# --------------------------------------------
# Task 4: Automation & Send/Receive
# --------------------------------------------
echo "[+] Running automation framework..."

chmod +x packet_automation.py
sudo python3 packet_automation.py

mkdir -p ../reports
mv -f automation_sent_*.pcap ../pcaps/ 2>/dev/null || true
mv -f automation_captured_*.pcap ../pcaps/ 2>/dev/null || true
mv -f automation_report_*.json ../reports/ 2>/dev/null || true

echo "[+] Running send/receive tests..."
chmod +x send_receive.py
sudo python3 send_receive.py

echo "==============================================="
echo "Lab 13 execution completed."
echo "Check pcaps/ and reports/ directories."
echo "==============================================="
