# 🛡️ Suraksha — OT Network Intrusion Detection System

> Suraksha means Protection in Sanskrit.  
A lightweight passive IDS for OT/ICS networks monitoring Modbus TCP, OPC-UA, and DNP3 using behavioral ML — without sending a single packet to the OT network.

![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-Python-009688?logo=fastapi&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-TimescaleDB-FDB515?logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-Streams-DC382D?logo=redis&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 📌 The Problem

OT networks still use legacy protocols with:

- No authentication  
- No encryption  
- Minimal logging  

| Issue | Existing Tools | Suraksha |
|---|---|---|
| Protocol awareness | Generic TCP only | FC-level decode |
| Detection | Static signatures | Behavioral ML |
| Scanning risk | Active probing | Passive SPAN |
| Alerts | Generic | Plain-English + fix |

---

## 🧠 System Architecture

### Full Stack Flowchart

```mermaid
flowchart TD
PLC[PLC / RTU] --> SPAN[SPAN Mirror Port]
SCADA[SCADA] --> SPAN
HMI[HMI] --> SPAN
SENSOR[Sensors] --> SPAN

SPAN --> SCAPY[Scapy Sniffer]

SCAPY --> MODBUS[Modbus Decoder]
SCAPY --> OPCUA[OPC-UA Parser]
SCAPY --> DNP3[DNP3 Decoder]

MODBUS --> REDIS
OPCUA --> REDIS
DNP3 --> REDIS

REDIS --> ML[ML Engine]

ML --> API[FastAPI Backend]
API --> DB[(TimescaleDB)]
API --> UI[React Dashboard]
sequenceDiagram
participant OT as OT Network
participant CAP as Capture Engine
participant ML as ML Engine
participant API as FastAPI
participant UI as Dashboard

OT->>CAP: SPAN mirrored packets
CAP->>CAP: Decode Modbus/OPC-UA/DNP3
CAP->>ML: Send structured events
ML->>API: Send anomalies
API->>UI: WebSocket alerts
UI->>UI: Visualize
