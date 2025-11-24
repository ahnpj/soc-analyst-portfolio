# 🛡️ SOC Analyst Portfolio

Welcome to my SOC Analyst Portfolio!
<br></br>
This repo is where I collect the hands-on work I’ve been doing to build practical blue team skills. My focus is on learning how to think and work like a Security Operations Center (SOC) analyst — investigating alerts, analyzing logs, and documenting clear playbooks.

This is a **work in progress** — I’m continuing to add more labs and examples as I go. 

<blockquote>
What you see here will grow over time, with each lab building in complexity and depth (Lab01 = fundamentals, Lab02+ = more advanced scenarios).
</blockquote>

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
>- <a href="labs/siem/splunk/Lab03-splunk-cyber-kill-chain-investigation/Lab03-splunk-cyber-kill-chain-investigation.md">Lab03 – Splunk Cyber Kill Chain Investigation</a><br/>
>   <em>Level: Intermediate</em> → Performing a complete investigation of a simulated web server defacement incident by tracing attacker activity through each phase of the Cyber Kill Chain. This includes identifying reconnaissance behavior, analyzing exploit attempts, verifying malware installation, and uncovering command-and-control (C2) communication using Splunk queries and network log data. The lab emphasizes the analytical workflow of a SOC analyst — from detecting the initial compromise to mapping adversary TTPs against frameworks like MITRE ATT&CK and NIST SP 800-61. Learners will gain hands-on experience correlating IDS alerts, HTTP traffic, and DNS records to produce actionable intelligence and document incident findings in a professional, report-ready format.
>- <a href="labs/siem/splunk/Lab04-splunk-backdoor-and-registry-hunt/Lab04-splunk-backdoor-and-registry-hunt.md">Lab04 – Splunk Backdoor and Registry Hunt</a><br/>
>   <em>Level: Advanced</em> → This lab walks through a full investigation of malicious activity using Splunk, including identifying backdoor account creation, registry modifications, remote WMIC abuse, and encoded PowerShell payloads. I traced attacker actions across multiple event sources (Security, Sysmon, and PowerShell logs), used host-based filtering to pinpoint suspicious activity, and decoded multi-layer Base64 payloads to uncover the final callback URL. The lab demonstrates how to think like an analyst: pivoting between events, validating assumptions, decoding obfuscated commands, and connecting evidence across hosts to reconstruct the adversary’s behavior.
> </details>

</details>



<details>
<summary><b>Network Analysis</b></summary>

> <details>
> <summary>Tcpdump</summary>
>
> - <a href="labs/network-analysis/tcpdump/Lab01-tcpdump-packet-capture-and-filtering/Lab01-tcpdump-packet-capture-and-filtering.md">Lab01 – Tcpdump Packet Capture and Filtering</a><br/>
>   <em>Level: Beginner</em> → Capturing and analyzing network traffic using tcpdump to understand packet structures, apply filters, and identify key fields for basic network troubleshooting and security monitoring.
>
> </details>

> <details>
> <summary>Wireshark</summary>
>
> - <a href="labs/network-analysis/wireshark/Lab01-wireshark-packet-analysis-and-filtering/Lab01-wireshark-packet-analysis-and-filtering.md">Lab01 – Wireshark Packet Analysis and Filtering</a><br/>
>   <em>Level: Beginner</em> → Captured and analyzed network traffic using Wireshark to examine packet structures, apply filters, and identify key fields useful for basic network troubleshooting and security monitoring.
>
> </details>

</details>

<details>
<summary><b>Shell Scripting</b></summary>

> <details>
> <summary>Linux and Scripting</summary>
>
> - <a href="labs/shell-and-scripting/linux-shell-and-scripting/Lab01-linux-bash-usage-and-scripting/Lab01-linux-bash-usage-and-scripting.md">Lab01 – Linux Shells and Scripting</a><br/>
>   <em>Level: Beginner</em> → Building Bash scripts that apply variables, user input, conditional logic, and iterative loops to automate decision-making and repetitive tasks in a Linux environment.
>
> </details>

</details>


<details>
<summary><b>Log Analysis & Scripting</b></summary>

> <details>
> <summary>Python Log Parsing & Security Analysis</summary>
>
> - <a href="labs/log-analysis-and-scripting/Lab01-python-log-parsing-and-security-analysis/Lab01-python-log-parsing-and-security-analysis.md">Lab01 – Python Log Parsing & Security Analysis</a><br/>
>   <em>Level: Beginner</em> → This lab demonstrates how to use Python to parse and analyze Apache, SSH, Windows, and CloudTrail logs, extracting meaningful security insights from raw event data. It highlights how scripting can automate detection of suspicious behavior, failed logins, scanning activity, and risky cloud actions.
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


<details>
<summary><b>Active Directory</b></summary>

> <details>
> <summary>Active Directory Labs</summary>
>
> - <a href="labs/active-directory/Lab01-active-directory-domain-structure/Lab01-active-directory-domain-structure.md">Lab01 – Active Directory Domain Structure and Administration</a><br/>
>   <em>Level: Beginner</em> → Practicing managing users, computers, and permissions through OUs and Group Policy, and I got hands-on experience with how Kerberos and NTLM authentication actually work behind the scenes. I also learned how larger networks use trees, forests, and trust relationships to stay organized and secure. Overall, it helped connect what I studied for Security+ to real Active Directory implementation.
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

## Note

All work here is practice and simulation — no real company data is included.
<br></br>
I’m using this repo to document my learning journey and showcase how I approach **SOC analyst tasks step by step**. Feedback and suggestions are always welcome!
