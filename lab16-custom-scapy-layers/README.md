# 🧪 Lab 16: Build Custom Scapy Layers for Proprietary Protocols
 
> **Focus:** Creating custom Scapy layers, testing proprietary packet formats, capturing traffic, and analyzing PCAPs

---

## 🎯 Objectives

By the end of this lab, I was able to:

- Design and implement **custom Scapy protocol layers** using `fields_desc`
- Create packet structures for **proprietary protocols**
- Build and test **SecureComm** and **AuthProtocol** packet formats
- Validate protocol behavior using:
  - `show()`, `bytes(pkt)`
  - traffic capture (`tcpdump`)
  - offline analysis (`rdpcap`)
- Detect anomalies in captured traffic (invalid version, unknown message types)
- Apply custom layers in realistic security testing scenarios

---

## 🧩 Prerequisites

- Basic Python programming (functions, classes, imports)
- Understanding of TCP/IP and UDP
- Familiarity with packet structure concepts
- Linux CLI basics

---

## 🧰 Lab Environment

This lab was performed in a cloud lab environment:

- Ubuntu 24.04 LTS
- Python 3.x
- Scapy
- tcpdump
- Wireshark 

<!--
(GUI not available in this cloud environment)
> 📌 Note: Wireshark GUI could not launch due to missing display, but PCAP analysis was still performed via scripts.
-->

---

## 🗂 Repo Structure

```text
lab-16-custom-scapy-layers/
├── README.md
├── commands.sh
├── output.txt
├── interview_qna.md
├── troubleshooting.md
├── scripts/
│   ├── explore_layers.py
│   ├── secure_comm_protocol.py
│   ├── auth_protocol.py
│   ├── protocol_server.py
│   ├── protocol_tester.py
│   └── packet_analyzer.py
└── artifacts/
    └── custom_protocols.pcap
````

✅ **Why this structure?**

* `scripts/` keeps all Python files clean and reusable
* `commands.sh` contains only the commands executed
* `output.txt` keeps raw outputs separate for authenticity
* `artifacts/` stores generated files like `.pcap`

---

## 🧪 What I Built in This Lab (High-Level)

### ✅ Task 1: Understand Scapy Layer Architecture

* Explored how Scapy defines layers (`fields_desc`)
* Printed TCP structure and field types
* Practiced working with:

  * `ByteField`, `ShortField`, `IntField`
  * `StrField`, `StrFixedLenField`
  * `ByteEnumField`
* Verified raw bytes output with `bytes(pkt)`

---

### ✅ Task 2: Create a Custom Protocol Layer (SecureComm)

Designed and implemented a protocol called **SecureComm**, structure:

* Magic (4 bytes): `0x53434D4D` (`"SCMM"`)
* Version (1 byte)
* Message type (1 byte enum): HELLO/DATA/ACK/CLOSE
* Sequence (4 bytes)
* Payload length (2 bytes)
* Checksum (2 bytes)

Implemented:

* `SecureCommHeader(Packet)`
* `post_build()` to auto-calculate:

  * payload length
  * checksum
* bound layer to UDP port `9999` using `bind_layers()`
* sent test packets to localhost

---

### ✅ Task 3: Build Advanced Authentication Protocol (AuthProtocol)

Designed and implemented a richer protocol with:

* Magic: `0x41555448` (`"AUTH"`)
* Version
* Command enum:

  * AUTH_REQUEST
  * AUTH_RESPONSE
  * SESSION_DATA
  * LOGOUT
* Flags
* Session ID
* Timestamp (auto-filled)
* Token (16 bytes)
* Data length (auto-filled)
* CRC (auto-calculated using `zlib.crc32`)

Also implemented:

* `AuthData(Packet)` as a structured payload:

  * username length + username
  * password length + password
  * client_id

Binding behavior:

* `AuthProtocolHeader` bound to TCP port `8888`
* `AuthData` bound when `cmd=1 (AUTH_REQUEST)`

---

### ✅ Task 4: Test Custom Protocols Against Target Systems

To test SecureComm realistically:

* Built a UDP test server (`protocol_server.py`)
* Implemented a client tester (`protocol_tester.py`) that:

  * sends HELLO/DATA/ACK/CLOSE
  * runs fuzz tests:

    * invalid magic
    * invalid version
    * unknown msg_type
    * large payload boundary test
  * generates a simple PASS/FAIL report

---

### ✅ Task 5: Capture and Analyze Traffic

Captured packets using:

* `tcpdump` on loopback interface (`lo`)
* saved capture to: `custom_protocols.pcap`

Then analyzed the PCAP using a custom script:

* Loaded capture with `rdpcap()`
* Validated SecureComm header fields
* Detected anomalies such as:

  * invalid version `99`
  * invalid message type `99`
* Computed anomaly rate

---

## ✅ Verification Checklist

- ✔ Custom layers bind correctly to UDP/TCP
- ✔ `show()` displays readable protocol fields
- ✔ `post_build()` auto-calculates lengths/checksums
- ✔ UDP server receives and responds
- ✔ PCAP capture contains expected SecureComm packets
- ✔ Packet analyzer identifies protocol + flags anomalies

---

## 🧠 What I Learned

* How Scapy builds protocols using `Packet` + `fields_desc`
* How to implement protocol logic safely using `post_build()`
* How to bind custom layers into Scapy’s parsing system (`bind_layers`)
* How to create realistic testing pipelines:

  * server + client
  * fuzzing + boundary testing
  * capture + offline analysis
* How PCAP validation helps detect malformed packets and unexpected protocol behavior

---

## 🌍 Why This Matters (Real-World Relevance)

Custom protocols are common in:

* IoT devices
* industrial systems (ICS/SCADA)
* embedded controllers
* proprietary vendor tooling

Being able to:

* model protocols,
* craft packets,
* fuzz edge cases,
* capture traffic,
* detect anomalies,

…is a core skill for **protocol reverse engineering**, **product security**, and **network security testing**.

---

## ✅ Conclusion

This lab strengthened my ability to create and validate proprietary protocol layers using Scapy.

I successfully built:

* SecureComm custom layer + UDP test infrastructure
* AuthProtocol custom layer with session/token fields
* fuzz testing workflows
* capture + PCAP analysis pipeline to detect anomalies

> ⚠ Ethical Note: Only test systems/protocols you own or have explicit permission to assess.

```
