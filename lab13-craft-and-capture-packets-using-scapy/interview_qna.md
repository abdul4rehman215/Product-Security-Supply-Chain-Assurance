# 🎤 Interview Q&A - Lab 13: Craft and Capture Packets Using Scapy

---

## 1️⃣ What is Scapy and why is it used?

Scapy is a Python-based packet manipulation tool that allows users to:
- craft custom packets,
- send packets,
- sniff live traffic,
- analyze network behavior.

It is widely used in:
- network testing,
- penetration testing,
- protocol analysis,
- security research.

---

## 2️⃣ Why do Scapy scripts require sudo/root privileges?

Scapy uses raw sockets for:
- packet crafting
- packet sniffing

Raw socket operations require elevated privileges on Linux systems.  
Without sudo, packet sending or capture may fail.

---

## 3️⃣ What is the difference between `send()` and `sr1()`?

- `send()` → Sends packets but does NOT wait for a reply.
- `sr1()` → Sends a packet and waits for exactly ONE response.
- `sr()` → Sends multiple packets and collects answered/unanswered responses.

---

## 4️⃣ What does a TCP SYN packet represent?

A TCP SYN packet is:
- The first step in the TCP 3-way handshake.
- Used to initiate a connection.
- Commonly used in SYN scanning during reconnaissance.

---

## 5️⃣ Why did we receive TCP RST responses in this lab?

Because:
- No service was listening on localhost ports (22, 80, 443).
- The OS responded with RST (connection refused).
- This indicates the port is closed.

---

## 6️⃣ What is a PCAP file and why is it important?

PCAP (Packet Capture) files:
- Store raw packet data.
- Can be analyzed later using tools like tcpdump or Wireshark.
- Are essential for forensic analysis and traffic investigation.

---

## 7️⃣ What is BPF filtering?

BPF (Berkeley Packet Filter) allows filtering captured traffic using expressions like:
- `tcp`
- `tcp port 80`
- `udp port 53`

Benefits:
- Reduces noise
- Improves performance
- Focuses on relevant traffic

---

## 8️⃣ Why did the script fall back from eth0 to lo?

Because:
- The cloud environment used `ens5`, not `eth0`.
- The script auto-selected the first available interface (`lo`).
- Capturing on loopback is valid for localhost traffic testing.

---

## 9️⃣ What are fragmented packets and why do they matter?

Fragmented packets occur when:
- Packet size exceeds MTU.
- IP splits the packet into smaller fragments.

Security relevance:
- Attackers may use fragmentation to bypass firewalls or IDS systems.

---

## 🔟 What is the benefit of automation in packet testing?

Automation allows:
- Repeatable testing
- Response correlation
- Logging and reporting
- Faster reconnaissance
- Scalable network validation

---

## 1️⃣1️⃣ How can packet crafting be used in real-world security?

Examples:
- Testing firewall rules
- Validating IDS signatures
- Simulating malicious traffic patterns
- Protocol fuzzing
- Incident response investigations

---

## 1️⃣2️⃣ What is the difference between ICMP echo-request and echo-reply?

- Echo-request → Sent to test reachability (ping).
- Echo-reply → Response indicating host is reachable.

---

## 1️⃣3️⃣ Why is interface selection important in packet capture?

If the wrong interface is selected:
- No packets will be captured.
- Results will be misleading.

Correct interface ensures:
- Accurate traffic visibility.
- Real-time packet monitoring.

---

## 1️⃣4️⃣ What did the JSON automation report contain?

The report included:
- Timestamp
- Sent packet count
- Captured packet count
- Protocol distribution (ICMP/TCP/UDP)
- Top source IP addresses

---

## 1️⃣5️⃣ How would you extend this lab further?

Possible improvements:
- Add SYN-ACK detection for open port identification.
- Add anomaly detection logic.
- Implement packet rate monitoring.
- Integrate with Wireshark for visualization.
- Add logging framework.

---

# ✅ End of Interview Q&A
