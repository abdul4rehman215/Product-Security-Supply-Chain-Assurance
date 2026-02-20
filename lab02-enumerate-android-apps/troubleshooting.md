# 🛠️ Troubleshooting Guide - Lab 2: Android APK Static Analysis (apktool + JADX + apkleaks)

---

# 🔍 1️⃣ apktool Issues

---

## ❌ Problem: `apktool` fails to decompile APK

### Error Example:
`
Exception in thread "main" brut.androlib.AndrolibException
`

### ✅ Possible Causes
- Corrupted APK file
- Unsupported APK version
- Missing framework files
- Java not properly installed

### 🔧 Solutions

#### 1. Verify Java Installation
```bash
java -version
````

If not installed:

```bash
sudo apt install openjdk-11-jdk
```

---

#### 2. Force Decompilation

```bash
apktool d -f sample_app.apk
```

---

#### 3. Verify APK Integrity

```bash
file sample_app.apk
```

Should return:

```
Zip archive data
```

---

#### 4. Clear Framework Cache

```bash
rm -rf ~/.local/share/apktool/framework/*
```

---

# 🔍 2️⃣ JADX Issues

---

## ❌ Problem: JADX produces empty output directory

### Possible Causes

* Low disk space
* Permission issues
* Corrupted DEX file

### 🔧 Solutions

#### 1. Check Disk Space

```bash
df -h
```

#### 2. Run with Verbose Mode

```bash
jadx -v -d output sample_app.apk
```

#### 3. Check Permissions

```bash
chmod -R 755 jadx_output/
```

---

## ❌ Problem: Decompiled code looks incomplete

### Explanation

* Some apps use obfuscation (ProGuard / R8)
* Class names may appear like `a.a.a`

### Recommendation

* Focus on logic rather than class names
* Use string search (`grep`) for secrets
* Combine with dynamic analysis

---

# 🔍 3️⃣ apkleaks Issues

---

## ❌ Problem: `apkleaks` command not found

### Solution:

```bash
pip3 install --upgrade apkleaks
```

Verify:

```bash
apkleaks --version
```

---

## ❌ Problem: No secrets detected

### Possible Reasons

* App genuinely secure
* Patterns not matching
* Obfuscation applied

### 🔧 Solutions

#### 1. Use Custom Pattern File

```bash
apkleaks -f sample_app.apk -p custom_patterns.json
```

#### 2. Inspect Java Source Manually

```bash
grep -r "key\|token\|password" jadx_output/
```

---

## ❌ Problem: JSON parsing error in automation script

### Cause

apkleaks JSON structure may vary.

### Fix

Validate JSON:

```bash
jq . apkleaks_output/secrets_report.json
```

---

# 🔍 4️⃣ Python Script Issues

---

## ❌ Problem: Permission denied

### Fix:

```bash
chmod +x scripts/*.py
```

---

## ❌ Problem: Module not found

### Fix:

```bash
pip3 install --upgrade apkleaks
```

---

## ❌ Problem: Script exits unexpectedly

### Debug Method:

Add print debugging or run manually:

```bash
python3 scripts/comprehensive_analyzer.py sample_app.apk -o test_output
```

---

# 🔍 5️⃣ aapt Issues

---

## ❌ Problem: `aapt dump badging` fails

### Cause:

`aapt` not installed or wrong version.

### Fix:

```bash
sudo apt install aapt
```

If still failing:

* Install Android SDK build tools
* Add build-tools to PATH

---

# 🔍 6️⃣ HTML Report Not Generating

---

## ❌ Problem: HTML file empty

### Causes

* JSON file not found
* JSON malformed

### Fix:

```bash
ls final_analysis/
jq . final_analysis/comprehensive_analysis.json
```

Re-run:

```bash
python3 scripts/generate_report.py final_analysis/comprehensive_analysis.json final_analysis/report.html
```

---

# 🔍 7️⃣ Performance Issues

---

## ❌ Problem: Analysis takes too long

### Causes

* Large APK
* Limited CPU resources

### Recommendations

* Increase timeout values in script
* Allocate more RAM
* Run tools individually to isolate bottleneck

---

# 🔍 8️⃣ Security Tool Best Practices

---

### ⚠️ Avoid Running as Root

If possible:

```bash
sudo -u username command
```

---

### ⚠️ Use Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install apkleaks
```

---

# 📌 Real-World Troubleshooting Strategy

When tools fail in enterprise environments:

1. Verify environment configuration
2. Validate input file integrity
3. Run tool independently
4. Increase verbosity
5. Check logs
6. Compare with known working APK
7. Review tool documentation

---

# 🎯 Key Lessons

* Static analysis tools can fail due to environment misconfiguration.
* Always validate prerequisites first.
* Combine multiple tools for reliable results.
* Automation requires defensive error handling.
* Logging and verbose mode are critical for debugging.

---

# ✅ Final Note

Most Android analysis failures are caused by:

* Missing dependencies
* Incorrect tool versions
* Corrupted APKs
* Permission issues

Systematic troubleshooting ensures reliable and repeatable security assessments.
