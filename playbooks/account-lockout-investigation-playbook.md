# 🛡️ Playbook: Account Lockout Investigation

## Overview  
Troubleshoot repeated account lockouts and investigate potential account compromise.

## Detection  
- Alerts from authentication systems or SIEM  
- User reports of inability to log in  
- High volume of failed login attempts

## Response Steps  
1. **Identify affected accounts**  
   - Check lockout logs and audit trails  
2. **Determine cause**  
   - Brute force attacks, password spraying, or user error  
3. **Check source IPs**  
   - Look for suspicious IP addresses or geolocations  
4. **Contain and remediate**  
   - Reset passwords, enable MFA, block offending IPs  
5. **Notify user and security team**  
   - Inform affected users and escalate if needed  
6. **Document incident**  
   - Record findings and preventive actions

## Tools & References  
- Authentication logs (Windows Event ID 4740)  
- SIEM tools  
- IAM policies and MFA enforcement  
