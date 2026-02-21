#!/bin/bash
# Lab 16: Build Custom Scapy Layers for Proprietary Protocols
# All commands executed during this lab (in chronological order)

# ------------------------------------------------------------
# Task 1: Explore Existing Scapy Layers
# ------------------------------------------------------------

cd ~

nano explore_layers.py

sudo python3 explore_layers.py


# ------------------------------------------------------------
# Task 2: Create SecureComm Custom Protocol
# ------------------------------------------------------------

nano secure_comm_protocol.py

sudo python3 secure_comm_protocol.py


# ------------------------------------------------------------
# Task 3: Create Advanced AuthProtocol
# ------------------------------------------------------------

cd ~

nano auth_protocol.py

sudo python3 auth_protocol.py


# ------------------------------------------------------------
# Task 4: Create SecureComm UDP Test Server
# ------------------------------------------------------------

cd ~

nano protocol_server.py

sudo python3 protocol_server.py &


# ------------------------------------------------------------
# Create Protocol Tester
# ------------------------------------------------------------

cd ~

nano protocol_tester.py

sudo python3 protocol_tester.py


# ------------------------------------------------------------
# Capture Traffic (Terminal 1)
# ------------------------------------------------------------

sudo tcpdump -i lo -w custom_protocols.pcap port 9999 &


# ------------------------------------------------------------
# Run Tests While Capture Is Active (Terminal 2)
# ------------------------------------------------------------

sudo python3 protocol_tester.py


# ------------------------------------------------------------
# Stop Capture
# ------------------------------------------------------------

sudo pkill tcpdump


# ------------------------------------------------------------
# Verify Capture File
# ------------------------------------------------------------

ls -lh custom_protocols.pcap


# ------------------------------------------------------------
# Task 5: Create Packet Analyzer
# ------------------------------------------------------------

cd ~

nano packet_analyzer.py

sudo python3 packet_analyzer.py


# ------------------------------------------------------------
# Attempt Wireshark GUI (CLI Environment Warning)
# ------------------------------------------------------------

wireshark custom_protocols.pcap &


# ------------------------------------------------------------
# Verification & Diagnostic Commands
# ------------------------------------------------------------

ip addr show

ps aux | grep python

sudo iptables -L
