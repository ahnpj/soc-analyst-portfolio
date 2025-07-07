# 🛡️ Playbook: Suspicious Network Traffic Analysis

## Overview  
Detect and investigate anomalies in network traffic such as unexpected outbound connections.

## Detection  
- Alerts from IDS/IPS, firewall logs  
- Unusual port usage or data volumes  
- Traffic to known malicious IPs or countries  

## Response Steps  
1. **Validate alert**  
   - Confirm traffic isn’t legitimate (scheduled tasks, updates)  
2. **Capture network data**  
   - Use packet capture tools for detailed analysis  
3. **Identify source and destination**  
   - Trace endpoints and user accounts involved  
4. **Contain threat**  
   - Block malicious IPs or isolate affected devices  
5. **Investigate scope and intent**  
   - Look for lateral movement or data exfiltration  
6. **Remediate and recover**  
   - Patch vulnerabilities and update rules

## Tools & References  
- IDS/IPS (Snort, Suricata)  
- Firewall logs  
- Packet capture (tcpdump, Wireshark)  
