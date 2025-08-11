## 🛡 Home SOC Lab — Build, Simulate, and Detect
A hands-on SOC (Security Operations Center) lab project designed to simulate attacks, collect telemetry, and detect malicious activity using LimaCharlie (EDR), Sysmon, and Sliver C2.

This project is great for:

 - SOC Analyst training
 - Incident detection & response practice
 - Building a personal cybersecurity portfolio

 ---
 
## 📚 Table of Contents
1. Overview
2. Architecture
3. Tools Used
4. Setup Steps
5. Attack Simulation
6. EDR Detection
7. Demo Video
8. Disclaimer

---

## 📌 Overview
This lab sets up:

 - Windows VM (victim machine with Sysmon & LimaCharlie Agent)
 - Ubuntu VM (attack server running Sliver C2)
 - EDR telemetry collection & detection rules in LimaCharlie
 - Simulated credential dumping attack on lsass.exe

The goal: See the full attack lifecycle from execution to detection in a SIEM/EDR environment.

---

## 🖼 Architecture

     [ Windows VM ]  <--->  [ Ubuntu VM with Sliver C2 ]
           |                        |
        Sysmon                Payload hosting
      LimaCharlie EDR         Command & Control
           |
       LimaCharlie Cloud  -->  Detection Rules

---

## 🛠 Tools Used
 - Windows 10 VM — victim endpoint
 - Ubuntu VM — attack host
 - Sysmon — endpoint event logging
 - LimaCharlie.io — EDR platform
 - Sliver C2 — red team command & control framework
 - Python HTTP Server — payload delivery

---

## ⚙ Setup Steps
The detailed step-by-step guide is in SETUP.md, covering:
1. Disable Windows Defender (for lab only)
2. Install Sysmon with SwiftOnSecurity config
3. Install & configure LimaCharlie Agent
4. Set up Ubuntu with static IP & Sliver C2
5. Generate & transfer payload to Windows VM
6. Launch C2 session

---

## 🎯 Attack Simulation
 - Generate Sliver payload targeting the Windows VM
 - Deliver payload via HTTP server
 - Execute payload to establish C2 session
 - Simulate credential dumping using:
  `procdump -n lsass.exe -s lsass.dmp`

---

## 🔍 EDR Detection
- Use LimaCharlie Processes & Network views to identify malicious activity
- Search for SENSITIVE_PROCESS_ACCESS events targeting lsass.exe
- Create Detection & Response (D&R) rule:
  `event: SENSITIVE_PROCESS_ACCESS
op: ends with
path: event/*/TARGET/FILE_PATH
value: lsass.exe`
 - Set response:
   `- action: report
  name: LSASS access
`
- Trigger attack again and confirm detection alert in LimaCharlie

---

🎥 Demo Video

---

## ⚠ Disclaimer
This lab is for educational purposes only.
Do NOT run these tools or commands on production systems or networks you do not own or have explicit permission to test.
