# 🧪 Lab 08: Process Product Telemetry Data in Jupyter + Pandas

This lab demonstrates how to generate, process, analyze, and visualize **product telemetry data** using **Python, Pandas, and Jupyter Notebook**. The workflow simulates an IoT / product analytics pipeline where telemetry is continuously collected and analyzed for **performance trends** and **anomalous behavior**.

---

## 📌 Lab Summary

In this lab, I:

- Generated a **synthetic telemetry dataset** (5000 records) simulating device metrics across multiple product types and locations
- Loaded and cleaned telemetry data using **Pandas**
- Performed statistical analysis and correlations across device performance metrics
- Detected anomalies using **standard deviation thresholds** and **resource-usage rules**
- Built a repeatable automation pipeline that:
  - Produces visualizations
  - Generates a structured **JSON report**
  - Summarizes key metrics and anomaly counts

---

## 🎯 Objectives

By the end of this lab, I was able to:

- Set up a Jupyter Notebook environment for telemetry analysis
- Load, clean, and preprocess telemetry data using Pandas
- Run statistical analysis and anomaly detection
- Create meaningful visualizations to interpret patterns
- Automate analysis workflows with reusable scripts

---

## ✅ Prerequisites

- Basic Python (variables, functions, loops)
- Familiarity with CSV
- Basic statistics (mean, standard deviation)

---

## 🧰 Lab Environment

| Component | Details |
|---|---|
| OS | Ubuntu 24.04.1 LTS (Cloud Lab Environment) |
| User | toor |
| Python | 3.12.3 |
| Jupyter Notebook | notebook 7.1.2 |
| Libraries | pandas 2.2.2, numpy 2.0.1, matplotlib 3.8.2, seaborn 0.13.2 |

✅ Verified in terminal:
- `python3 --version`
- `jupyter --version`
- `python3 -c "import pandas, numpy, matplotlib, seaborn; ..."`

---

## 🗂️ Repository Structure

```text
lab08-process-product-telemetry-jupyter-pandas/
├── README.md
├── commands.sh
├── output.txt
├── interview_qna.md
├── troubleshooting.md
├── data/
│   └── product_telemetry.csv
├── notebooks/
│   └── Telemetry_Analysis.ipynb
├── output/
│   ├── distribution_analysis.png
│   ├── time_series_analysis.png
│   ├── anomaly_detection.png
│   └── correlation_heatmap.png
├── reports/
│   └── analysis_report.json
└── scripts/
    ├── generate_telemetry.py
    └── automate_analysis.py
````

---

## 🧩 Tasks Performed (Overview)

### ✅ Task 1 — Generate Sample Telemetry Data

* Created lab folder structure:

  * `data/`, `notebooks/`, `scripts/`, `output/`
* Built `scripts/generate_telemetry.py` to generate:

  * 5000 telemetry records
  * 4 product types, 5 locations
  * multiple metrics (temperature, CPU, memory, power, latency, error counts)
  * injected ~5% anomalies to simulate abnormal device behavior
* Output dataset saved as:

  * `data/product_telemetry.csv`

---

### ✅ Task 2 — Analyze Telemetry Data with Pandas (Notebook)

Inside `notebooks/Telemetry_Analysis.ipynb`:

* Loaded CSV + converted timestamps
* Explored schema, types, summary statistics, missing values
* Cleaned data (duplicates/NA, numeric coercion, filtering invalid metrics)
* Statistical analysis:

  * Average metrics by product type
  * Highest-error devices
  * Correlation matrix
  * Highest average power devices
* Anomaly detection:

  * Temperature anomalies using `mean ± (2 * std)`
  * Performance anomalies using CPU > 80% or Memory > 90%
* Time-series analysis:

  * hourly resampling (`H`)
  * daily aggregations (`D`)
  * hourly pattern extraction
  * rolling temperature mean (24h)

---

### ✅ Task 3 — Visualize Telemetry Data

Generated and saved plots into `output/`:

1. `distribution_analysis.png`

   * product distribution pie chart
   * temperature histogram
   * CPU vs memory scatter
   * power consumption boxplot by product
2. `time_series_analysis.png`

   * daily temperature trend
   * daily CPU trend
   * hourly power pattern
3. `anomaly_detection.png`

   * temperature anomalies over time
4. `correlation_heatmap.png`

   * correlation matrix visualization

---

### ✅ Task 4 — Automate Data Processing Pipeline

Created `scripts/automate_analysis.py`:

* Loads CSV and cleans dataset safely
* Computes:

  * total records, device count, product/location lists
  * metrics by product type
  * top error devices
  * top power devices
* Detects anomalies:

  * temperature (std method)
  * performance (threshold method)
  * power anomalies (std method)
* Generates plots (matplotlib-based in automation)
* Writes report:

  * `output/analysis_report.json`
* Prints summary to terminal

---

## 📊 Results

* Dataset generated: **5000 records**
* Unique devices: **1655**
* Detected anomalies (automation results):

  * Temperature anomalies: **247**
  * Performance anomalies: **229**
  * Power anomalies: **250**
* Outputs generated:

  * **4 PNG charts**
  * **1 JSON report**
  * **CSV dataset**
  * **Jupyter notebook**

---

## 📌 Key Learnings

* Pandas enables fast preprocessing and analysis of telemetry at scale
* Simple statistical thresholds can detect abnormal device patterns quickly
* Time-series resampling is effective for identifying trends
* Automated pipelines ensure repeatable, consistent monitoring outputs

---

## 🌍 Why This Matters

Telemetry analysis is a core capability in product engineering and product security monitoring:

* abnormal resource usage can signal device malfunction or compromised behavior
* anomaly detection helps prioritize investigation and response
* automation pipelines are essential for continuous monitoring and reporting

---

## ✅ Conclusion

This lab implemented a complete telemetry analysis workflow:

* data generation → cleaning → statistical analysis → anomaly detection → visualization → automation/reporting

It provides a reusable foundation for real-world telemetry monitoring and continuous analytics using Python.
