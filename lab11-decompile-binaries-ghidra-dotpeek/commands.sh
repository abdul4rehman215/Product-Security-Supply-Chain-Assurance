#!/bin/bash
# ============================================================
# Lab 11: Decompile Binaries Using Ghidra & dotPeek
# Environment: Ubuntu 24.04.1 LTS (Cloud Lab Environment)
# User: toor
# ============================================================

# -----------------------------
# Step 1.1: Install Java (Ghidra requirement)
# -----------------------------
sudo apt update && sudo apt install openjdk-17-jdk -y

# -----------------------------
# Create working directory
# -----------------------------
mkdir -p ~/lab11-binary-analysis
cd ~/lab11-binary-analysis
pwd

# -----------------------------
# Download and extract Ghidra
# -----------------------------
wget -O ghidra_10.4_PUBLIC_20230928.zip "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.4_build/ghidra_10.4_PUBLIC_20230928.zip"
unzip ghidra_10.4_PUBLIC_20230928.zip

# Rename extracted folder to 'ghidra'
mv ghidra_10.4_PUBLIC ghidra

# Make launcher executable
chmod +x ghidra/ghidraRun

# Verify installation (help output confirms launcher works)
./ghidra/ghidraRun -h | head -20

# -----------------------------
# Step 1.2: Create vulnerable C binary
# -----------------------------
cd ~/lab11-binary-analysis
nano vulnerable_app.c

# Compile with security features disabled (for analysis)
gcc -o vulnerable_app vulnerable_app.c -fno-stack-protector -z execstack -no-pie

# Verify binary type
file vulnerable_app

# -----------------------------
# Step 1.3: Install Wine + dotPeek
# -----------------------------
sudo dpkg --add-architecture i386
sudo apt update
sudo apt install -y wine64 wine32

# Configure Wine (GUI)
winecfg

# Download dotPeek installer into Wine C: drive
mkdir -p ~/.wine/drive_c/dotpeek
cd ~/.wine/drive_c/dotpeek
wget -O JetBrains.dotPeek.2023.2.3.exe "https://download.jetbrains.com/resharper/dotUltimate.2023.2.3/JetBrains.dotPeek.2023.2.3.exe"

# Run dotPeek installer (GUI wizard)
wine JetBrains.dotPeek.2023.2.3.exe

# -----------------------------
# Step 1.4: Create vulnerable .NET assembly (C#)
# -----------------------------
cd ~/lab11-binary-analysis
nano VulnerableApp.cs

# Install Mono and compile
sudo apt update
sudo apt install -y mono-devel

mcs VulnerableApp.cs -out:VulnerableApp.exe

# Verify produced file
file VulnerableApp.exe

# -----------------------------
# Task 2: Ghidra GUI analysis launch
# -----------------------------
cd ~/lab11-binary-analysis
./ghidra/ghidraRun &

# (GUI steps performed inside Ghidra)

# -----------------------------
# Create native binary analysis report
# -----------------------------
cd ~/lab11-binary-analysis
nano analysis_report.md

# -----------------------------
# Task 3: Launch dotPeek (Wine)
# -----------------------------
cd ~/.wine/drive_c/Program\ Files/JetBrains
ls -la

cd ~/.wine/drive_c/Program\ Files/JetBrains/JetBrains\ dotPeek\ 2023.2.3/bin
wine dotPeek64.exe &

# (GUI steps performed inside dotPeek, including export to dotpeek_output)

# -----------------------------
# Create .NET analysis report
# -----------------------------
cd ~/lab11-binary-analysis
nano dotnet_analysis.md

# -----------------------------
# Task 4: Automation with Python + Ghidra headless
# -----------------------------
cd ~/lab11-binary-analysis
mkdir -p scripts automated_analysis

nano scripts/automated_analysis.py
nano scripts/FindVulnerabilities.java

chmod +x scripts/automated_analysis.py
python3 scripts/automated_analysis.py

cat ~/lab11-binary-analysis/automated_analysis/analysis_report.json
