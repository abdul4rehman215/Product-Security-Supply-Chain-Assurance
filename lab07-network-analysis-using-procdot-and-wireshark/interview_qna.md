# 🎤 Interview Q&A - Lab 7: Trace Product Network Activity Using ProcDOT & Wireshark

---

## 1️⃣ What is the difference between Wireshark and tshark?

**Answer:**  
Wireshark is a GUI-based packet analyzer used for interactive traffic inspection, while tshark is its command-line equivalent. Tshark is preferred for automation, scripting, and headless environments such as servers and cloud labs.

---

## 2️⃣ Why was the `any` interface used for packet capture?

**Answer:**  
The `any` interface captures packets from all available interfaces. In cloud environments, this ensures no traffic is missed if traffic flows across multiple virtual interfaces.

---

## 3️⃣ What does the capture filter `"not port 22"` accomplish?

**Answer:**  
It excludes SSH traffic from being captured. This prevents the analyst’s own remote session traffic from polluting the dataset and focuses analysis on product-related communications.

---

## 4️⃣ What is a PCAP file?

**Answer:**  
A PCAP (Packet Capture) file stores raw packet-level network traffic. It preserves timestamps, headers, payload data, and protocol information, making it essential for forensic and traffic analysis.

---

## 5️⃣ Why was PyShark used in this lab?

**Answer:**  
PyShark is a Python wrapper for tshark. It allows programmatic parsing of PCAP files, enabling automation of packet extraction and conversion to structured formats like CSV.

---

## 6️⃣ How was anomaly detection implemented?

**Answer:**  
An anomaly threshold was calculated as three times the mean packet count per source IP. IPs exceeding this threshold were flagged as potentially suspicious high-volume communicators.

---

## 7️⃣ Why is converting PCAP to CSV useful?

**Answer:**  
CSV format enables:
- Data processing with pandas
- Statistical analysis
- Visualization
- Easier integration into SIEM or reporting systems

---

## 8️⃣ What role does NetworkX play in the lab?

**Answer:**  
NetworkX builds and visualizes a directed graph of network flows, representing:
- Nodes → IP addresses  
- Edges → Communication relationships  
- Edge weight → Packet volume  

This helps visualize communication patterns.

---

## 9️⃣ How can DNS traffic be security-relevant?

**Answer:**  
DNS traffic can indicate:
- Command-and-Control communication  
- Data exfiltration via DNS tunneling  
- Malware beaconing  
- Suspicious domain lookups  

Monitoring DNS is critical for threat detection.

---

## 🔟 What is the purpose of simulating a process monitor log?

**Answer:**  
The simulated ProcMon log allows correlation between:
- Process activity (PID, operation)
- Network communication (PCAP data)

This mimics real-world forensic investigations where analysts correlate host activity with network events.

---

## 1️⃣1️⃣ Why automate the entire pipeline?

**Answer:**  
Automation ensures:
- Consistent forensic methodology  
- Faster incident response  
- Reduced human error  
- Scalable monitoring  

It is essential in enterprise SOC environments.

---

## 1️⃣2️⃣ What is the importance of correlating processes with network flows?

**Answer:**  
It helps identify:
- Which process initiated a suspicious connection  
- Whether malware initiated outbound traffic  
- Whether legitimate applications are behaving abnormally  

This strengthens root-cause analysis.

---

## 1️⃣3️⃣ What indicators could suggest malicious behavior in this dataset?

**Answer:**  
- High packet volume from a single IP  
- Unexpected outbound DNS queries  
- Connections to uncommon ports  
- Repeated failed TCP connections  

---

## 1️⃣4️⃣ What improvements could enhance this solution?

**Answer:**  
- Real-time anomaly detection  
- Machine learning-based traffic profiling  
- Integration with SIEM systems  
- Threat intelligence feed correlation  
- Deep packet inspection of payload data  

---

## 1️⃣5️⃣ How is this lab relevant to Product Security?

**Answer:**  
Product security teams must:
- Monitor application communication patterns  
- Detect data exfiltration risks  
- Identify abnormal API behavior  
- Validate that products communicate only with approved endpoints  

This lab demonstrates exactly those capabilities.

---

# ✅ End of Interview Q&A
