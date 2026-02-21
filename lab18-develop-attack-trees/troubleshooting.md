# 🛠 Troubleshooting Guide - Lab 18 – Develop Attack Trees for Identified Vulnerabilities  

---

## 🔎 Overview

During the development and execution of this lab, multiple components were involved:

- Python virtual environment setup  
- JSON parsing and validation  
- Custom module imports  
- Graph-based analysis using NetworkX  
- Risk calculation logic  
- File path management  

Below are common issues encountered during execution and their detailed resolutions.

---

# 🧩 1️⃣ Issue: Import Errors for Custom Modules

### ❌ Error Example
```

ModuleNotFoundError: No module named 'attack_tree'

````

### 🎯 Cause

Python cannot locate custom scripts (`attack_tree.py`, `vuln_attack_trees.py`) because:

- The scripts directory is not in `PYTHONPATH`
- Script executed from wrong working directory

### ✅ Solution

Run script from inside the `scripts/` directory:

```bash
cd ~/attack-trees-lab/scripts
python3 vuln_attack_trees.py
````

OR export Python path:

```bash
export PYTHONPATH="${PYTHONPATH}:~/attack-trees-lab/scripts"
```

### 🔐 Security Note

Improper module imports may cause execution failures in automation pipelines. Always structure projects correctly.

---

# 🧩 2️⃣ Issue: JSON Parsing Errors

### ❌ Error Example

```
json.decoder.JSONDecodeError: Expecting ',' delimiter
```

### 🎯 Cause

* Syntax error in `vulnerabilities.json`
* Missing comma
* Incorrect quotes
* Invalid JSON structure

### ✅ Solution

Validate JSON format:

```bash
python3 -m json.tool data/vulnerabilities.json
```

If valid, it prints formatted JSON.
If invalid, it shows exact error location.

### 🔐 Security Relevance

Improperly formatted configuration files can break automation pipelines and risk assessment systems.

---

# 🧩 3️⃣ Issue: NetworkX Not Installed

### ❌ Error Example

```
ModuleNotFoundError: No module named 'networkx'
```

### 🎯 Cause

Required Python libraries not installed in virtual environment.

### ✅ Solution

Activate virtual environment:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install networkx matplotlib anytree
```

Verify installation:

```bash
pip list
```

---

# 🧩 4️⃣ Issue: Graph Visualization Not Working

### ❌ Problem

Graph or visualization functionality fails.

### 🎯 Cause

* Graphviz not installed
* Missing system dependencies

### ✅ Solution

Install Graphviz:

```bash
sudo apt install graphviz
```

Verify installation:

```bash
dot -V
```

Expected output:

```
dot - graphviz version 2.x
```

---

# 🧩 5️⃣ Issue: Risk Calculations Returning Zero

### ❌ Symptom

All nodes show:

```
risk=0.00
```

### 🎯 Cause

* Probability not set (default = 0.0)
* Impact not set
* Node incorrectly classified

### ✅ Solution

Ensure:

* Probability between `0.0 – 1.0`
* Impact between `0.0 – 10.0`
* LEAF nodes have defined values

Example:

```python
tree.add_node("Goal", "SQL Injection", "LEAF", 0.8, 9.0, 50)
```

---

# 🧩 6️⃣ Issue: Attack Paths Not Generated

### ❌ Symptom

```
No scenarios found.
```

### 🎯 Cause

* Graph edges not defined
* Vulnerability IDs mismatch
* Relationships incorrectly configured

### ✅ Solution

Verify relationships in:

```python
define_attack_relationships()
```

Check vulnerability IDs:

```
VULN-001
VULN-002
VULN-003
VULN-004
```

IDs must match exactly.

---

# 🧩 7️⃣ Issue: File Not Found Errors

### ❌ Error Example

```
FileNotFoundError: Vulnerability file not found
```

### 🎯 Cause

Wrong relative path.

### ✅ Solution

From scripts directory:

```bash
python3 vuln_attack_trees.py
```

Ensure JSON path:

```python
"../data/vulnerabilities.json"
```

Check directory structure:

```
attack-trees-lab/
 ├── data/
 ├── scripts/
 └── output/
```

---

# 🧩 8️⃣ Issue: Virtual Environment Not Activated

### ❌ Symptom

System Python used instead of lab environment.

### 🎯 Cause

Virtual environment not activated.

### ✅ Solution

Activate before running scripts:

```bash
source .venv/bin/activate
```

Prompt should change to:

```
(.venv) toor@...
```

---

# 🧩 9️⃣ Issue: Remediation Report Not Generated

### ❌ Symptom

No file in `output/` directory.

### 🎯 Cause

* Output path incorrect
* Directory not created

### ✅ Solution

Ensure directory exists:

```bash
mkdir -p output
```

Script auto-creates directory using:

```python
out_path.parent.mkdir(parents=True, exist_ok=True)
```

Verify:

```bash
cat output/remediation_report.json
```

---

# 🧩 🔟 Performance Issue with Large Datasets

### ❌ Symptom

Attack path computation slow.

### 🎯 Cause

`nx.all_simple_paths()` can be computationally expensive for large graphs.

### ✅ Solution

For production:

* Limit path depth
* Use optimized search
* Pre-filter vulnerability categories

---

# 🧠 General Debugging Strategy Used in This Lab

1. Validate JSON
2. Check module imports
3. Verify directory structure
4. Confirm Python environment
5. Print intermediate values
6. Validate graph nodes and edges
7. Inspect generated attack paths

---

# 🔐 Security-Oriented Lessons from Troubleshooting

* Configuration errors can break security automation
* Dependency management is critical in DevSecOps
* Proper path handling prevents execution failures
* Risk calculations must validate input bounds
* Structured debugging is essential in secure development

---

# ✅ Final Stability Check

Before final submission, verify:

```bash
python3 attack_tree.py
python3 vuln_attack_trees.py
python3 attack_path_mapper.py
python3 risk_analyzer.py
```

Confirm:

* No import errors
* Attack trees generated
* Attack scenarios categorized
* Remediation report created successfully

---

# 🎯 Final Outcome

All components successfully executed:

* Attack Tree Framework operational
* Vulnerability chaining identified
* Risk scores calculated
* Remediation prioritized
* Report generated

Lab execution completed successfully without runtime errors.

---
