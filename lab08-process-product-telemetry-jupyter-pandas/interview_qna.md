# 🎤 Interview Q&A _ Lab 08: Telemetry Data Processing with Jupyter + Pandas

> This Q&A set is based on the work completed in **Lab 08: Process Product Telemetry Data in Jupyter + Pandas**, including dataset generation, Pandas analysis, anomaly detection, visualizations, and automation.

---

## 1) What is telemetry data, and why is it important for product security?

**Answer:**  
Telemetry data is continuous runtime data collected from devices/applications (e.g., temperature, CPU usage, memory usage, latency, error counts). From a product security perspective, telemetry helps detect abnormal behavior (spikes, unusual error patterns, suspicious resource use) that may indicate device faults, misconfiguration, or compromise.

---

## 2) Why did you generate synthetic telemetry instead of using real device data?

**Answer:**  
Synthetic telemetry allows safe experimentation without exposing sensitive customer/device data. It also makes it easy to inject known anomaly patterns (~5% in this lab) to validate detection logic and automate repeatable analysis workflows.

---

## 3) What cleaning steps did you apply before analysis?

**Answer:**  
The cleaning pipeline included:
- Dropping duplicates
- Removing null values
- Converting numeric fields safely using `pd.to_numeric(errors="coerce")`
- Filtering invalid ranges (e.g., CPU and memory outside 0–100, temperature below a reasonable bound)

This ensures analysis and anomaly detection are not skewed by malformed records.

---

## 4) How did you perform anomaly detection for temperature?

**Answer:**  
I used a statistical method based on standard deviation:
- Compute mean and standard deviation for temperature
- Define bounds: `mean ± (std_threshold * std)`
- Flag records above or below those thresholds as anomalies  
In the lab run, temperature anomalies were ~247 records.

---

## 5) How did you detect performance anomalies?

**Answer:**  
Using threshold-based rules:
- CPU usage > 80%
- Memory usage > 90%  
Any record meeting those conditions was flagged as a performance anomaly. The lab run detected ~229 such records.

---

## 6) Why do you combine statistical detection with threshold-based detection?

**Answer:**  
Because not all telemetry anomalies are best captured statistically:
- Temperature deviations work well with z-score/std methods
- CPU/memory often have known operational boundaries where “high usage” itself is meaningful  
Combining methods reduces false negatives and provides better operational coverage.

---

## 7) What metrics did you aggregate by product type, and why?

**Answer:**  
I computed mean values for:
- temperature
- CPU usage
- memory usage
- power consumption  
This helps compare baseline behavior across product families (e.g., EdgeGateway naturally has higher temperature and power usage than Thermostat).

---

## 8) What did the correlation matrix tell you?

**Answer:**  
The correlation matrix shows relationships between numeric metrics. In this lab:
- Temperature had higher correlation with power consumption (~0.73)
- CPU and memory showed moderate correlation (~0.62)
This suggests resource usage trends can move together and some metrics can be predictors for others.

---

## 9) Why do time-series resampling (`H` and `D`) in telemetry analysis?

**Answer:**  
Telemetry is time-based; resampling helps:
- reduce noise by aggregating raw datapoints
- identify daily/hourly patterns
- detect trend drift over time  
In the lab, hourly and daily aggregates supported trend visualization.

---

## 10) What is the purpose of generating visualizations in telemetry workflows?

**Answer:**  
Visuals reveal patterns that raw tables can hide:
- distributions highlight expected ranges
- boxplots show spread by product type
- anomaly plots show temporal clusters
- heatmaps show metric relationships  
This is essential for quick investigation and reporting.

---

## 11) What did your automation script produce?

**Answer:**  
`scripts/automate_analysis.py` produced:
- PNG visualizations (distribution, time-series, anomalies, correlation heatmap)
- `analysis_report.json` containing:
  - counts of records/devices
  - date range
  - metrics by product type
  - top error devices
  - anomaly counts and sample entries
- A printed summary in terminal

---

## 12) How would you scale this pipeline for production telemetry?

**Answer:**  
Key improvements:
- Use scheduled execution (cron/systemd timers)
- Store telemetry in a time-series DB or log platform (e.g., Elasticsearch, InfluxDB)
- Use streaming ingestion (Kafka, MQTT brokers)
- Add alerting thresholds and notifications
- Track baseline per product type/location/device model (reduce false positives)

---

## 13) What security use-case can “top devices by error count” support?

**Answer:**  
High error count devices can indicate:
- failing firmware/software components
- unstable deployments or misconfiguration
- attack attempts causing repeated failures
- denial-of-service style stress  
These devices should be prioritized for investigation.

---

## 14) Why is keeping automation “matplotlib-only” useful?

**Answer:**  
Using matplotlib-only reduces dependencies and makes the script easier to run in minimal environments. Seaborn is great interactively in notebooks, but automation pipelines benefit from fewer external requirements.

---

## 15) If anomalies increase suddenly, what would you investigate first?

**Answer:**  
I would check:
- if telemetry ingestion changed (format/schema drift)
- deployments/firmware updates in the time window
- whether anomalies cluster to a specific product type/location
- error_count spikes with CPU/memory spikes
- whether timestamps/timezones are correct

Then I would validate with raw logs and correlate with any operational events.

---
