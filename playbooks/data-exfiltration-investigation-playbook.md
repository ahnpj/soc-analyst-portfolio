# 🛡️ Playbook: Data Exfiltration Investigation

## Overview  
Identify and respond to suspicious data transfers or large unauthorized uploads.

## Detection  
- Unusual outbound traffic spikes  
- Alerts from DLP or UEBA systems  
- Abnormal use of cloud storage or removable media  

## Response Steps  
1. **Confirm suspicious activity**  
   - Analyze logs and network captures  
2. **Identify affected data and systems**  
   - Determine type and sensitivity of data involved  
3. **Contain exfiltration path**  
   - Block offending IPs, user accounts, or protocols  
4. **Investigate user activity**  
   - Review access logs and endpoint data  
5. **Eradicate threat**  
   - Remove malware or revoke credentials if compromised  
6. **Report & Remediate**  
   - Notify stakeholders and initiate remediation plan

## Tools & References  
- DLP solutions  
- Network monitoring tools (Wireshark, NetFlow)  
- UEBA platforms  
