
---

## ✅ **TASK 5: Network Packet Analyzer – README.md (DETAILED)**

```markdown
# 📡 Task 5: Network Packet Analyzer

This project is a simple yet powerful **packet sniffer** built using Python and Scapy. The tool captures live network traffic and extracts useful information from the packets such as IP addresses, protocols, ports, and payload content.

---

## 📌 Features

- Captures live packets in real time
- Extracts and logs:
  - Timestamp of packet
  - Source and destination IP addresses
  - Protocol used (TCP, UDP)
  - Source and destination ports
  - First 20 bytes of payload (if available)
- Logs all information to `packet_log.txt`
- Outputs log to console as well

---

## 🛠️ Requirements

- Python 3.x
- `scapy` library
- Administrator privileges

### 📦 Install Scapy

```bash
pip install scapy
