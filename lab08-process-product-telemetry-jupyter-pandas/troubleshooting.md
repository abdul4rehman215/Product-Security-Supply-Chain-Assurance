# 🛠️ Troubleshooting Guide Lab 08 — Jupyter + Pandas Telemetry Analysis

> This document covers common issues that may occur while performing **Lab 08: Process Product Telemetry Data in Jupyter + Pandas**, along with practical fixes and verification commands.

---

## 1) Issue: Jupyter Notebook won’t start (port already in use)

### ✅ Symptoms
- Jupyter prints an error like:
  - `Address already in use`
  - or notebook fails to bind to port `8888`

### 🔍 Likely Cause
- Another process is already using port `8888`
- A previously launched Jupyter instance is still running

### ✅ Fix Option A — Check port usage
```bash
netstat -tuln | grep 8888
````

If you want process details:

```bash
sudo lsof -i :8888
```

### ✅ Fix Option B — Start Jupyter on a different port

```bash
jupyter notebook --ip=0.0.0.0 --port=8889 --no-browser
```

### ✅ Fix Option C — Stop existing Jupyter session

If Jupyter is running in the terminal, stop it with:

* `CTRL + C` (twice if required)

---

## 2) Issue: Cannot access notebook URL in browser

### ✅ Symptoms

* Browser shows:

  * “This site can’t be reached”
  * connection timed out
  * or `172.x.x.x` IP not accessible

### 🔍 Likely Causes

* The cloud environment blocks inbound ports
* You are using the wrong IP
* You launched Jupyter without binding to `0.0.0.0`

### ✅ Fix Steps

1. Ensure Jupyter is started correctly:

```bash
jupyter notebook --ip=0.0.0.0 --port=8888 --no-browser
```

2. Confirm it is listening:

```bash
netstat -tuln | grep 8888
```

3. If you must access from local machine, use SSH port forward (if allowed):

```bash
ssh -L 8888:127.0.0.1:8888 toor@<server-ip>
```

---

## 3) Issue: Pandas cannot find CSV file (FileNotFoundError)

### ✅ Symptoms

* `FileNotFoundError: [Errno 2] No such file or directory: '../data/product_telemetry.csv'`

### 🔍 Likely Causes

* Notebook working directory is not what you expected
* Relative path is incorrect from inside `notebooks/`
* CSV was not generated or placed in `data/`

### ✅ Fix Steps

1. Confirm your current working directory inside notebook:

```python
import os
os.getcwd()
```

2. Confirm CSV exists from terminal:

```bash
ls -lh ~/telemetry_lab/data/
```

3. Use absolute path in notebook (safe option):

```python
telemetry_df = pd.read_csv('/home/toor/telemetry_lab/data/product_telemetry.csv')
```

---

## 4) Issue: Plots are not displaying in Jupyter

### ✅ Symptoms

* Code runs but no plots appear

### 🔍 Likely Causes

* Missing matplotlib inline magic
* Missing `plt.show()`
* Kernel display issues

### ✅ Fix Steps

At the top of the notebook:

```python
%matplotlib inline
```

Ensure plot cells end with:

```python
plt.show()
```

Restart kernel if required:

* Jupyter menu → **Kernel → Restart Kernel and Clear Output**

---

## 5) Issue: `seaborn` style errors or seaborn not found

### ✅ Symptoms

* `ModuleNotFoundError: No module named 'seaborn'`
* or style warnings/errors

### ✅ Fix Steps

Install seaborn (if not already present):

```bash
pip3 install seaborn
```

Verify:

```bash
python3 -c "import seaborn; print(seaborn.__version__)"
```

---

## 6) Issue: Automation script fails due to relative paths (`../data/`)

### ✅ Symptoms

* Running `python3 scripts/automate_analysis.py` fails to locate `../data/product_telemetry.csv`

### 🔍 Likely Cause

* The script uses paths relative to **where the script is executed**
* If you run it from an unexpected directory, relative paths break

### ✅ Fix Option A — Always run from lab root (recommended)

```bash
cd ~/telemetry_lab
python3 scripts/automate_analysis.py
```

### ✅ Fix Option B — Modify script to compute absolute paths dynamically

Example improvement:

```python
base_dir = os.path.dirname(os.path.abspath(__file__))
data_path = os.path.join(base_dir, "..", "data")
output_path = os.path.join(base_dir, "..", "output")
```

---

## 7) Issue: Memory errors with large datasets

### ✅ Symptoms

* Kernel restarts
* Memory allocation errors when reading CSV

### 🔍 Likely Causes

* Dataset too large for available memory
* Non-optimized dtypes

### ✅ Fix Option A — Load CSV in chunks

```python
chunks = pd.read_csv('../data/product_telemetry.csv', chunksize=1000)
telemetry_df = pd.concat(chunks)
```

### ✅ Fix Option B — Reduce memory usage via dtype

```python
telemetry_df = pd.read_csv(
    '../data/product_telemetry.csv',
    dtype={
        "device_id": "category",
        "product_type": "category",
        "location": "category"
    }
)
```

---

## 8) Issue: Output files not appearing in `output/`

### ✅ Symptoms

* `ls output/` shows empty or missing PNG files
* JSON report missing after automation run

### 🔍 Likely Causes

* Wrong path used in `plt.savefig`
* Running notebook from a different directory
* Script didn’t execute fully due to an error

### ✅ Fix Steps

1. Confirm output directory exists:

```bash
ls -la ~/telemetry_lab/output/
```

2. Confirm notebook saving uses correct relative path:

* From `notebooks/`, saving to `../output/` is correct.

3. Re-run automation:

```bash
cd ~/telemetry_lab
python3 scripts/automate_analysis.py
```

---

## ✅ Quick Health Checklist (Final Verification)

Run these after completion:

```bash
cd ~/telemetry_lab
```

# Dataset exists
```ls -lh data/product_telemetry.csv```

# Notebook exists
```ls -lh notebooks/Telemetry_Analysis.ipynb```

# Output artifacts exist
```ls -lh output/```

# Report is readable JSON
```cat output/analysis_report.json```

---
