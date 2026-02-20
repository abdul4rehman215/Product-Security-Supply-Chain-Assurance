#!/bin/bash

# ==========================================================
# Lab 4 - Comprehensive Nmap Scanning Script
# ==========================================================
# This script performs multiple types of scans on a target
# and stores results in a structured output directory.
# ==========================================================

TARGET="localhost"
OUTPUT_DIR="scan_results"

# Create output directory if it doesn't exist
mkdir -p $OUTPUT_DIR

echo "=================================================="
echo "Starting comprehensive nmap scan of $TARGET"
echo "Results will be saved in $OUTPUT_DIR directory"
echo "=================================================="

# ----------------------------------------------------------
# Basic Port Scan
# ----------------------------------------------------------
echo "[+] Performing basic port scan..."
nmap $TARGET > $OUTPUT_DIR/basic_scan.txt

# ----------------------------------------------------------
# Service Version Detection
# ----------------------------------------------------------
echo "[+] Performing service version detection..."
nmap -sV $TARGET > $OUTPUT_DIR/service_scan.txt

# ----------------------------------------------------------
# Aggressive Scan (OS detection + scripts)
# ----------------------------------------------------------
echo "[+] Performing aggressive scan..."
nmap -A $TARGET > $OUTPUT_DIR/aggressive_scan.txt

# ----------------------------------------------------------
# UDP Scan (Top 100 Ports)
# Requires sudo privileges
# ----------------------------------------------------------
echo "[+] Performing UDP scan..."
sudo nmap -sU --top-ports 100 $TARGET > $OUTPUT_DIR/udp_scan.txt

# ----------------------------------------------------------
# Default Script Scan
# ----------------------------------------------------------
echo "[+] Performing default script scan..."
nmap -sC $TARGET > $OUTPUT_DIR/script_scan.txt

echo "=================================================="
echo "Scan completed successfully."
echo "Check $OUTPUT_DIR directory for detailed results."
echo "=================================================="
