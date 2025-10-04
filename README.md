# 🛡️ SOC Analyst Portfolio

Welcome to my SOC Analyst Portfolio!  
This repo is where I collect the hands-on work I’ve been doing to build practical blue team skills. My focus is on learning how to think and work like a Security Operations Center (SOC) analyst — investigating alerts, analyzing logs, and documenting clear playbooks.

This is a **work in progress** — I’m continuing to add more labs and examples as I go. What you see here will grow over time, with each lab building in complexity and depth (Lab01 = fundamentals, Lab02+ = more advanced scenarios).

---

## What’s Inside

<h3>Labs → (labs/)</h3> Hands-on labs where I dig into SIEM data, practice log analysis, and build investigation workflows. 
Currently includes:
<br/><br/>

<details>
<summary><b>SIEM</b></summary>

> <details>
> <summary>SIEM Basics</summary>
>
> - <a href="labs/siem/siem-basics/Lab01-intro-to-siem/Lab01-suspicious-process-investigation.md">Lab01 – Suspicious Process Investigation</a><br/>
>   <em>Level: Beginner</em> → Investigating abnormal process activity in logs, understanding correlation rules.
>
> </details>

> <details>
> <summary>Splunk</summary>
>
> - <a href="labs/siem/splunk/Lab01-splunk-vpn-log-analysis/Lab01-splunk-vpn-log-analysis-basics.md">Lab01 – Splunk VPN Log Analysis</a><br/>
>   <em>Level: Beginner</em> → Detecting unusual VPN login activity, analyzing login patterns by user and source country, and identifying suspicious travel or account compromise.
> - <a href="labs/siem/splunk/Lab02-splunk-data-manipulation/Lab02-splunk-data-manipulation-basics.md">Lab02 – Splunk Data Manipulation</a><br/>
>   <em>Level: Beginner</em> → Understanding how Splunk processes, parses, and manipulates machine-generated data using configuration files (inputs.conf, props.conf, transforms.conf) to ensure accurate field extraction and reliable analysis for security investigations.
>
> </details>

</details>


<details>
<summary><b>Endpoint Analysis & Investigation</b></summary>

> <details>
> <summary>Windows CMD/CLI</summary>
>
> - <a href="labs/endpoint-triage/windows-cli/Lab01-windows-cli-endpoint-triage-basics/Lab01-windows-cli-endpoint-triage-basics.md">Lab01 – Windows CMD/CLI Basics</a><br/>
>   <em>Level: Beginner</em> → Using Windows command-line tools to investigate processes, review system information, and identify suspicious activity.
>
> </details>

> <details>
> <summary>PowerShell</summary>
>
> - <a href="labs/endpoint-triage/powershell/Lab01-powershell-endpoint-triage-basics/Lab01-powershell-endpoint-triage-basics.md">Lab01 – PowerShell Basics</a><br/>
>   <em>Level: Beginner</em> → Leveraging PowerShell commands to collect endpoint data, filter logs, and detect potential anomalies in process execution.
>
> </details>

</details>

<h3>Playbooks → (playbooks/)</h3> Step-by-step response guides I’ve written for common security events. These are structured like SOC playbooks to help with incident triage, investigation, and response.
Currently includes:
<br/><br/>
<details>
<summary><b>Account Lockouts</b></summary>

> - <a href="playbooks/account-lockout-investigation-playbook.md">Account lockouts</a><br/>
>Troubleshoot repeated account lockouts and investigate potential account compromise.
</details>

<details>
  
<summary><b>Alert Triage Escalation</b></summary>

> - <a href="playbooks/alert-triage-escalation-playbook.md">Alert Escalation</a><br/>
>Process for analyzing security alerts, prioritizing incidents, and escalating appropriately.

</details>

<details>
  
<summary><b>Data Exfiltration Investigation</b></summary>

> - <a href="playbooks/data-exfiltration-investigation-playbook.md">Data Exfiltration Investigation</a><br/>
>Identify and respond to suspicious data transfers or large unauthorized uploads.

</details>

<details>
  
<summary><b>Email Phishing Attempt</b></summary>

> - <a href="playbooks/email-phishing-playbook.md">Email Phishing Attempt</a><br/>
>Identify, contain, and remediate phishing email incidents.

</details>

<details>
  
<summary><b>Malware Detection and Response</b></summary>

> - <a href="playbooks/malware-detection-response-playbook.md">Malware Detection and Response</a><br/>
>Steps to identify, isolate, and remediate malware infections on endpoints to minimize impact.

</details>

<details>
  
<summary><b>Suspicious Network Traffic Analysis</b></summary>

> - <a href="playbooks//suspicious-network-traffic-analysis-playbook.md">Suspicious Network Traffic Analysis</a><br/>
>Detect and investigate anomalies in network traffic such as unexpected outbound connections.

</details>

<details>
  
<summary><b>Suspicious Login or Access Attempt</b></summary>

> - <a href="playbooks/unauthorized-access-detection-playbook.md">Suspicious Login or Access Attempt</a><br/>
>Identify, respond to, and mitigate unauthorized or suspicious login attempts on production systems or cloud platforms.

</details>

<details>
  
<summary><b>Unauthorized USB Device Detection</b></summary>

> - <a href="playbooks/unauthorized-usb-detection-playbook.md">Unauthorized USB Device Detection</a><br/>
>Investigate alerts triggered by unknown USB devices connecting to endpoints.

</details>

---

## Skills Demonstrated

- Reading and analyzing SIEM logs (Splunk, general SIEM concepts)  
- Identifying suspicious or abnormal activity  
- Writing structured investigation notes and playbooks  
- Documenting technical work clearly for others to follow  
- Building up complexity across labs (introductory → intermediate → advanced)  

---

## Roadmap / Coming Soon

This repo will continue to grow as I add more content, including:  
- Additional SIEM labs (ELK stack, more Splunk scenarios)  
- Network analysis labs (Wireshark, packet capture)  
- Scanning/recon labs (Nmap, basic vulnerability discovery)  
- Expanded incident response playbooks  

---

## 💡 Note

All work here is practice and simulation — no real company data is included.  
I’m using this repo to document my learning journey and showcase how I approach **SOC analyst tasks step by step**. Feedback and suggestions are always welcome!
