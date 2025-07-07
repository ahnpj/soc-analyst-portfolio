# 🛡️ Playbook: Suspicious Login or Access Attempt

## 📘 Overview

This playbook outlines the steps to identify, respond to, and mitigate **unauthorized or suspicious login attempts** on production systems or cloud platforms. It aims to contain potential breaches quickly while minimizing false positives.

## 📍 Detection

#### ✅ Common Indicators
- Login from an unusual geographic location
- Multiple failed login attempts (brute-force behavior)
- Login at unusual times (e.g., 2 a.m. local time)
- Use of anonymizing services (e.g., VPNs, Tor)
- Access from known malicious IPs
- MFA (Multi-Factor Authentication) bypass attempt

#### 🔍 Sources to Monitor
- System logs (e.g., `/var/log/auth.log`, `/var/log/secure`)
- Cloud provider IAM login events (e.g., AWS CloudTrail, Azure AD logs)
- Web application login logs
- SIEM alerts (e.g., Splunk, Elastic, Datadog)


## 🚨 Response Procedure

#### 1. **Confirm the Suspicion**
- Cross-check login metadata:
  - IP address geolocation
  - Device / browser fingerprint
  - Timestamps vs. user activity patterns
- Look for known false positives (e.g., traveling employees, VPN usage)

#### 2. **Isolate the User Account**
- Immediately disable or lock the account
- Invalidate all active sessions/tokens
- Notify affected user (secure channel only)

#### 3. **Block Malicious Source**
- Block suspicious IP at the firewall or WAF
- Add the IP to threat feeds if internal system supports it

#### 4. **Collect and Preserve Evidence**
- Save relevant log entries
- Take a snapshot of affected systems (if intrusion is suspected)
- Document timestamps, user IDs, IPs, and observed actions

#### 5. **Perform Impact Assessment**
- Was sensitive data accessed or modified?
- Any privilege escalation attempts?
- Any lateral movement?

#### 6. **Report and Escalate**
- Notify your security team or SOC
- File an internal incident report
- Escalate to legal or compliance if regulated data may be involved


## 🔁 Recovery and Follow-up

#### ✅ Restore Access
- Reset passwords and enforce MFA for affected accounts
- Enable login anomaly detection (e.g., user risk scoring)

#### 🧠 Lessons Learned
- Conduct a post-incident review
- Update detection rules based on new indicators
- Improve onboarding training about phishing or password hygiene


## 🛠 Tools & Commands

### Linux (SSH brute-force example):
```bash
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr
