# 🛡️ CyberShield

## Network Intrusion Detection & Threat Intelligence Platform

### 1. Project Overview

CyberShield is a Python-based Network Intrusion Detection and Threat Intelligence Platform developed to monitor and analyze network traffic and identify 
suspicious activities. The system analyzes PCAP files using Scapy and extracts important network information such as source IP, destination IP, protocol, 
ports, and packet length. It detects activities such as port scanning, excessive network connections, and connections to potentially sensitive ports. 
The project also includes an IOC-based threat intelligence component that checks source IP addresses against a configured list of suspicious indicators 
and assigns appropriate risk levels to detected security events.

### 2. Technologies & Features

The project is developed using **Python, Scapy, Flask, SQLite, HTML, CSS, and JavaScript**. CyberShield includes network packet parsing, intrusion detection, 
threat intelligence, IOC matching, risk classification, SQLite-based alert storage, duplicate alert prevention, and a Flask-based SOC dashboard. 
The dashboard displays total alerts and risk distribution and provides security alert details including attack type, source IP, destination IP, count, 
risk level, and description. It also provides search and risk-based filtering capabilities. A synthetic PCAP generator is included to safely demonstrate 
and test the detection mechanisms.

### 3. Results & Learning Outcomes

CyberShield successfully analyzes synthetic network traffic and identifies multiple types of suspicious activity. In the demonstrated test, the system 
analyzed **18 network packets and generated 8 security alerts**, including **1 Critical, 2 High, and 5 Medium alerts**. The project provides practical 
experience in network traffic analysis, intrusion detection, threat intelligence, IOC analysis, risk assessment, security alert management, database integration, 
Python automation, and SOC dashboard development. It is designed for educational purposes, cybersecurity portfolio development, and authorized security testing.
