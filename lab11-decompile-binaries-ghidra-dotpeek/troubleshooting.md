# 🛠 Troubleshooting Guide - Lab 11: Decompile Binaries Using Ghidra & dotPeek

---

# 1️⃣ Ghidra Won't Start

### 🔍 Symptoms
- `ghidraRun` fails to execute
- GUI does not launch
- Java-related errors

### 🎯 Possible Causes
- Java not installed
- Wrong Java version
- Permission issues

### 🧪 Diagnosis
```

java -version
ls -lh ghidra/ghidraRun

```

### ✅ Resolution
```

sudo apt install openjdk-17-jdk -y
chmod +x ghidra/ghidraRun

```

### 🔐 Prevention
Always verify Java version compatibility before installing Ghidra.

---

# 2️⃣ dotPeek Fails to Install in Wine

### 🔍 Symptoms
- Installer crashes
- Missing DLL errors

### 🎯 Possible Causes
- Wine not configured
- Missing 32-bit support

### 🧪 Diagnosis
```

winecfg

```

### ✅ Resolution
```

sudo dpkg --add-architecture i386
sudo apt update
sudo apt install wine32 wine64
winecfg

```

### 🔐 Prevention
Configure Wine environment before installing Windows-based tools.

---

# 3️⃣ Headless Analysis Fails

### 🔍 Symptoms
- Timeout errors
- "Binary does not exist"
- Permission denied

### 🎯 Possible Causes
- Incorrect path
- Non-executable binary
- Timeout too low

### 🧪 Diagnosis
```

file vulnerable_app
ls -lh vulnerable_app
ls -ld automated_analysis

```

### ✅ Resolution
- Ensure binary exists
- Increase timeout in Python script
- Verify permissions

---

# 4️⃣ Mono Compilation Errors

### 🔍 Symptoms
- `mcs` command not found
- Missing assembly references

### 🎯 Possible Causes
- Mono not installed

### 🧪 Diagnosis
```

which mcs

```

### ✅ Resolution
```

sudo apt install mono-devel -y

```

---

# 5️⃣ Ghidra Analysis Not Showing Functions

### 🔍 Symptoms
- Empty decompiler window

### 🎯 Possible Causes
- Auto-analysis not run
- Wrong architecture selected

### ✅ Resolution
- Re-import binary
- Enable full analysis options
- Check architecture settings

---

# 🔐 Security Note

Always perform reverse engineering in a controlled lab environment.  
Never analyze unknown binaries on production systems.

---

# ✅ End of Troubleshooting Guide
