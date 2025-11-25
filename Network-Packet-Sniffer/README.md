![Python](https://img.shields.io/badge/Python-3.9%2B-blue) ![License](https://img.shields.io/badge/License-Apache%202.0-green)

# Network-Packet-Sniffer

A Python-based cybersecurity tool that captures and analyzes live network traffic, detects anomalies like port scans or flooding, and logs data into SQLite. Built with Scapy for packet sniffing and Matplotlib for visualizing protocol usage and top IPs, enabling real-time network threat monitoring and analysis.

## Features
- Real-time packet capture using Scapy
- Logs packet metadata to SQLite
- Detects anomalies:
  - Port Scanning
  - High-rate traffic bursts
- Generates analytics:
  - Protocol distribution graph
  - Top source IPs chart
- Optional: Email alert integration

## Tools & Technologies
- Python 3.9+
- Scapy
- SQLite3
- Matplotlib, Pandas
- Npcap (for Windows)
- Virtual Environment (venv)

## ⚙️ Installation & Setup

1. Clone the repository
   `git clone https://github.com/rajveemore112/Network-Packet-Sniffer.git
   cd Network-Packet-Sniffer`

2. Create & activate a virtual environment
   `python -m venv venv
    venv\Scripts\activate`

3. Install dependencies
   `pip install -r requirements.txt`

4. Ensure Npcap is installed
 -Download from https://nmap.org/npcap/
 -Run Command Prompt as Administrator before sniffing.

## How To Run

1. Start the Sniffer
   `python sniffer.py`
   Generated files:
   - packets.db [auto-created database of packets]
   - alerts.log [log file for anomalies]
3. Run the Port Scan Simulator
   Run this in a second admin CMD window to simulate a scan:
   `python simulate_scan.py`
  
4. Generate Visual Reports
   `python visualize.py`
   Generated files:
   - protocol_dist.png [Protocol distribution graph]
   - top_src.png [Top source IPs chart]

## Repository Structure
Network-Packet-Sniffer/
│
├── sniffer.py          # main sniffer with anomaly detection
├── simulate_scan.py    # safe port-scan simulator
├── visualize.py        # generates graphs from SQLite data
├── requirements.txt
├── LICENSE
└── README.md
