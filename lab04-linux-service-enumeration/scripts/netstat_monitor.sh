#!/bin/bash

# ==========================================================
# Lab 4 - Netstat Monitoring Script
# ==========================================================
# This script analyzes:
#  - Listening ports
#  - Active connections
#  - Process-port mapping
#  - Network statistics
# It stores timestamped results in a structured directory.
# ==========================================================

OUTPUT_DIR="netstat_results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Create output directory
mkdir -p $OUTPUT_DIR

echo "=================================================="
echo "Starting network connection analysis..."
echo "Timestamp: $(date)"
echo "=================================================="

# ----------------------------------------------------------
# Listening Ports (numeric)
# ----------------------------------------------------------
echo "[+] Analyzing listening ports..."
netstat -ln > $OUTPUT_DIR/listening_ports_$TIMESTAMP.txt

# ----------------------------------------------------------
# Active Connections
# ----------------------------------------------------------
echo "[+] Analyzing active connections..."
netstat -an > $OUTPUT_DIR/active_connections_$TIMESTAMP.txt

# ----------------------------------------------------------
# Process and Port Mapping
# ----------------------------------------------------------
echo "[+] Analyzing processes and ports..."
netstat -lnp > $OUTPUT_DIR/process_ports_$TIMESTAMP.txt

# ----------------------------------------------------------
# Network Statistics
# ----------------------------------------------------------
echo "[+] Gathering network statistics..."
netstat -s > $OUTPUT_DIR/network_stats_$TIMESTAMP.txt

# ----------------------------------------------------------
# Generate Summary Report
# ----------------------------------------------------------
echo "[+] Creating summary report..."

{
    echo "Network Analysis Summary"
    echo "========================================"
    echo "Timestamp: $(date)"
    echo ""

    echo "Listening TCP Ports:"
    netstat -lnt | grep LISTEN | awk '{print $4}' | sort -u
    echo ""

    echo "Listening UDP Ports:"
    netstat -lnu | awk 'NR>2 {print $4}' | sort -u
    echo ""

    echo "Active Connection Count:"
    netstat -an | grep ESTABLISHED | wc -l
    echo ""

    echo "Top 10 Most Active Ports:"
    netstat -an | grep ESTABLISHED | awk '{print $4}' | cut -d: -f2 | sort | uniq -c | sort -nr | head -10
    echo ""
} > $OUTPUT_DIR/summary_$TIMESTAMP.txt

echo "=================================================="
echo "Analysis completed successfully."
echo "Results saved in: $OUTPUT_DIR/"
echo "=================================================="
