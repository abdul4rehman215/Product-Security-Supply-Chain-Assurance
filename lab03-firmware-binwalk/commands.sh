#!/bin/bash
# Lab 3: Extract Firmware Using binwalk and Analyze Filesystem
# commands.sh — Commands executed in the lab

# -----------------------------
# Task 1: Install and Configure binwalk
# -----------------------------

# Update package repositories
sudo apt update

# Install binwalk and essential dependencies
sudo apt install -y binwalk python3-pip git

# Install additional extraction tools (split across multiple apt runs for clean parsing on Ubuntu 24.04)
sudo apt install -y mtd-utils gzip bzip2 tar arj lhasa p7zip p7zip-full cabextract cramfsprogs cramfsswap
sudo apt install -y squashfs-tools sleuthkit default-jdk lzop srecord

# Install Python dependencies for advanced features
pip3 install python-magic pycrypto

# Verify installation
binwalk --help
binwalk --list-plugins

# -----------------------------
# Task 1: Download Sample Firmware
# -----------------------------

# Create working directory
mkdir ~/firmware_lab
cd ~/firmware_lab

# Download sample firmware (OpenWrt)
wget https://downloads.openwrt.org/releases/22.03.0/targets/ath79/generic/openwrt-22.03.0-ath79-generictplink_archer-c7-v2-squashfs-sysupgrade.bin

# Create a sample firmware for demonstration (dummy firmware)
dd if=/dev/zero of=sample_firmware.bin bs=1024 count=1024

# -----------------------------
# Task 2: Extract and Analyze Firmware Components
# -----------------------------

# Analyze firmware structure
binwalk sample_firmware.bin

# Entropy analysis
binwalk -E sample_firmware.bin

# Save entropy plot data
binwalk -E --save sample_firmware.bin

# Extract firmware automatically
binwalk -e sample_firmware.bin

# Extract with verbose output
binwalk -e -v sample_firmware.bin

# List extracted contents
ls -la _sample_firmware.bin.extracted/

# Manual extraction attempts
binwalk --dd=".*" sample_firmware.bin
binwalk --dd="filesystem" sample_firmware.bin

# -----------------------------
# Task 3: Analyze Extracted Filesystem for Vulnerabilities
# -----------------------------

# Navigate to extracted directory
cd _sample_firmware.bin.extracted/

# List extracted components (first 20)
find . -type f -name "*" | head -20

# Look for common filesystem images
find . -name "*.squashfs" -o -name "*.jffs2" -o -name "*.cramfs"

# Create mount point
sudo mkdir -p /mnt/firmware

# If squashfs-root exists, explore it
if [ -f squashfs-root ]; then
  echo "SquashFS root directory found"
  cd squashfs-root
  ls -la
fi

# Directory tree view (fallback to find if tree not installed)
tree -L 3 . 2>/dev/null || find . -type d | head -20

# Security analysis - config files
find . -name "*.conf" -o -name "*.cfg" -o -name "*.ini" 2>/dev/null

# Password files
find . -name "*passwd*" -o -name "*shadow*" 2>/dev/null

# Hardcoded credentials search (first 10 lines)
grep -r -i "password\|passwd\|pwd" . 2>/dev/null | head -10

# Private keys
find . -name "*.key" -o -name "*.pem" -o -name "*_rsa" 2>/dev/null

# Databases
find . -name "*.db" -o -name "*.sqlite*" 2>/dev/null

# Executables
find . -type f -executable 2>/dev/null | head -10

# Shell scripts
find . -name "*.sh" 2>/dev/null

# Potential command injection keywords (first 5)
grep -r "system\|exec\|eval" . 2>/dev/null | head -5

# Web artifacts (first 10)
find . -name "*.php" -o -name "*.cgi" -o -name "*.html" 2>/dev/null | head -10

# -----------------------------
# Task 4: Automate Extraction and Analysis with Python
# -----------------------------

# Go back to lab dir
cd ~/firmware_lab

# Create scripts
nano firmware_analyzer.py
chmod +x firmware_analyzer.py

nano vulnerability_scanner.py
chmod +x vulnerability_scanner.py

# Run automated analysis
python3 firmware_analyzer.py sample_firmware.bin
ls -la analysis_sample_firmware

# Run vulnerability scanner on extracted directory
python3 vulnerability_scanner.py analysis_sample_firmware/_sample_firmware.bin.extracted/

# Create comprehensive analysis script
nano comprehensive_analysis.sh
chmod +x comprehensive_analysis.sh

# Run comprehensive analysis script
./comprehensive_analysis.sh sample_firmware.bin

# Quick peek at the summary report
sed -n '1,80p' comprehensive_analysis_sample_firmware/analysis_summary.txt
