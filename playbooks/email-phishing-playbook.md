# 🛡️ Playbook: Email Phishing Attempt

## 📘 Overview
This playbook outlines a structured approach to identify, contain, and remediate phishing email incidents, leveraging email gateway tools, endpoint detection, and user awareness to minimize risk and prevent credential compromise. Respond to a suspected phishing email reported by an end-user or detected by an email security gateway.
## 📍 Detection

#### ✅ Common Indicators & Triggers
* User-reported suspicious email (via phishing button or ticket)
* Alert from secure email gateway (e.g., Proofpoint, Microsoft Defender)
* Suspicious email detected in SIEM (e.g., keyword or IOC match)

## 🚨 Response Procedure
🧭 **Step-by-Step Response** 
1. _Initial Triage_
* Task 1: Confirm email source	
  * Tool/Platform: Email headers analysis
  * Notes: Use tools like mxtoolbox or header analyzer
* Task 2: Check for attachments/URLs
  * Tool/Platform: Sandbox or URL scanner	
  * Notes: Use tools like Joe Sandbox, VirusTotal, AnyRun
* Task 3: Identify recipients
  * Tool/Platform: Email gateway logs, O365	
  * Notes: Determine blast radius

2. _Containment_
* Task 1: Quarantine email
  * Tool/Platform: Email security platform
  * Notes: Search and remove using message trace
* Task 2: Block malicious IOCs
  * Tool/Platform: Firewall/Proxy/SIEM
  * Notes: Add to blocklists in EDR or FW rules
* Task 3: Alert affected users
  * Tool/Platform: Internal comms, IT Helpdesk
  * Notes: Share educational awareness if needed

3. _Investigation_
* Task 1: Search for lateral movement
  * Tool/Platform: SIEM (Splunk/QRadar)
  * Notes: Correlate user login attempts post-click
* Task 2: Scan endpoints
  * Tool/Platform: EDR (CrowdStrike, etc)
  * Notes: Check for malware persistence
* Task 3: Extract IOCs
  * Tool/Platform: Email + sandbox reports
  * Notes: Store in case notes and update detection

4. _Eradication & Recovery_
* Remove any malicious files found
* Ensure no persistence mechanisms (scheduled tasks, registry keys, etc.)
* Reset credentials if account compromise is suspected

5. _Post-Incident_
* Task 1: Report to threat intel team	
  * Description: Share new IOCs, sender domains, etc.
* Task 2: Update detection rules
  * Description: Add SIEM or email detection logic
* Task 3: Document in IR tracker
  * Description: Include timeline, findings, remediation
* Task 4: Conduct user awareness
  * Description: Targeted training for affected users

📊 **Metrics & KPIs**
* Time to detect (TTD)
* Time to contain (TTC)
* Number of affected users
* Recurrence of similar phishing types

📚 **References**
* MITRE ATT&CK T1566.001 (Phishing via Email)
* NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide)

🧰 **Incident Checklist Template**

- [ ] Validate alert source and category
- [ ] Review related logs in SIEM
- [ ] Identify affected host/user/account
- [ ] Contain and mitigate threat
- [ ] Document findings
- [ ] Notify stakeholders
- [ ] Close ticket with lessons learned
