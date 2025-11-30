# Cybersecurity & IT Operations Portfolio

Welcome to the part of my GitHub where I’m teaching myself how to work across cybersecurity and IT operations. Nothing here is meant to look perfect. It’s basically where I learn by doing — breaking things, fixing them, chasing weird logs, and slowly figuring out how real investigations and day-to-day IT work actually feel.

This repo is my running record of that process. I’m practicing everything from SIEM searches and log analysis to scripting, network traffic reviews, and basic system administration tasks. Some labs go smoothly, some definitely don’t, but that’s the whole point — I want to understand how things really behave, not just how they’re “supposed” to work.

You’ll notice the labs are numbered. That’s intentional.
They follow the order I wanted to learn things:

Early labs = fundamentals

Later labs = more noise, more steps, more pivot points, more places to get things wrong

As the numbers go up, the investigations start to feel more real: multi-stage activity, correlating different log sources, piecing timelines together, tuning searches, checking assumptions, and actually explaining what happened instead of just guessing.

---

## What’s Inside

<h3>Labs → (labs/)</h3> Hands-on labs covering cybersecurity, IT ops, scripting, and investigation-style problem solving. Each one walks through what I saw, what I thought it meant, what actually happened, and how I figured it out. Some are quick. Some took forever. All of them taught me something.
<br/><br/>

Currently includes:

<details>
<summary><b>Systems & Endpoints</b></summary>

> <details>
> <summary>Linux</summary>
>
> - <a href="labs/systems-and-endpoints/Lab01-linux-shell-and-scripting-basics/Lab01-linux-shell-and-scripting-basics.md">Lab01 – Linux Shell and Scripting</a><br/>
>   A hands-on introduction to core Linux commands, navigation, and automation. I wrote small Bash scripts using variables, loops, and conditionals to automate repetitive tasks. This lab strengthened my command-line comfort and problem-solving mindset. Building Bash scripts that apply variables, user input, conditional logic, and iterative loops to automate decision-making and repetitive tasks in a Linux environment.
>
> </details>

> <details>
> <summary>Windows CMD/CLI</summary>
>
> - <a href="labs/systems-and-endpoints/Lab02-windows-cli-endpoint-triage-basics/Lab02-windows-cli-endpoint-triage-basics.md">Lab02 – Windows CMD - File Discovery, Network & Process Investigation</a><br/>
>   Used Windows command-line tools to investigate system behavior, look up running processes, review basic host information, and spot suspicious activity. This lab helped me understand what normal endpoint behavior looks like and how to manually triage a Windows machine.
> </details>

> <details>
> <summary>PowerShell</summary>
>
> - <a href="labs/systems-and-endpoints/Lab03-powershell-endpoint-triage-basics/Lab03-powershell-endpoint-triage-basics.md">Lab03 – PowerShell Endpoint Triage</a><br/>
>   Collected and filtered system data using PowerShell, focusing on processes, services, and event logs. I practiced identifying patterns that could indicate malicious activity. This lab sharpened my ability to use PowerShell for real investigation workflows.
> </details>


</details>



<details>
<summary><b>Identity and Access Management</b></summary>

> <details>
> <summary>Active Directory</summary>
>
> - <a href="labs/identity-and-access-management/Lab04-active-directory-identity-and-access-management/Lab04-active-directory-identity-and-access-management.md">Lab04 – Active Directory Domain Structure and Administration</a><br/>
>   Explored how real enterprise AD environments are structured, including users, OUs, groups, and authentication flows. I created accounts, adjusted permissions, and experimented with Group Policy. This lab helped connect theoretical AD concepts to real hands-on configuration.
>
> </details>


</details>

<details>
<summary><b>Networking and Traffic Analysis</b></summary>

> <details>
> <summary>tcpdump</summary>
>
> - <a href="labs/networking-and-traffic-analysis/Lab05-tcpdump-packet-capture-and-filtering/Lab05-tcpdump-packet-capture-and-filtering.md">Lab05 – Tcpdump Packet Capture and Filtering</a><br/>
>   Captured live network traffic using tcpdump and analyzed packet details through filters. I learned how to isolate meaningful traffic from noise and understand key packet fields. This lab built a foundation for packet-level monitoring and troubleshooting.
>
> </details>

> <details>
> <summary>WireShark</summary>
>
> - <a href="labs/networking-and-traffic-analysis/Lab06-wireshark-packet-analysis-and-filtering/Lab06-wireshark-packet-analysis-and-filtering.md">Lab06 – Wireshark Packet Analysis and Filtering</a><br/>
>   Used Wireshark to inspect packets visually, apply powerful filters, and interpret network behavior. I practiced recognizing normal patterns vs. anomalies. This lab improved my ability to analyze network data beyond the command line.
>
> </details>

</details>


<details>
<summary><b>Log Analysis & Automation</b></summary>

> <details>
> <summary>Python Log Parsing & Security Analysis</summary>
>
> - <a href="labs/log-analysis-and-automation/Lab07-python-log-parsing-and-security-analysis/Lab07-python-log-parsing-and-security-analysis.md">Lab07 – Python Log Parsing & Security Analysis</a><br/>
>   Wrote Python scripts to parse and analyze logs from Apache, SSH, Windows, and AWS CloudTrail. Automated detection of failed logins, scanning activity, and other suspicious patterns. This lab showed how scripting can speed up investigations and reduce human error.
>
> </details>

</details>


<details>
<summary><b>Monitoring and SIEM</b></summary>

> <details>
> <summary>Investigations</summary>
>
> - <a href="labs/monitoring-and-siem/investigations/Lab08-siem-suspicious-process-investigation/Lab08-suspicious-process-investigation.md">Lab08 – Suspicious Process Investigation</a><br/>
>   Performed a basic SIEM investigation into unusual process activity. Followed breadcrumbs across event logs to identify what happened and why it looked suspicious. This lab established my workflow for triage and hypothesis-driven analysis.
>
> </details>

> <details>
> <summary>Splunk</summary>
>
> - <a href="labs/monitoring-and-siem/splunk/Lab09-splunk-vpn-log-analysis-basics/Lab09-splunk-vpn-log-analysis-basics.md">Lab09 – Splunk VPN Log Analysis Basics</a><br/>
>   Used Splunk to analyze VPN authentication logs and identify risky login patterns. Looked at user behavior, location anomalies, and signs of potential account compromise. A solid introduction to real-world access monitoring in Splunk.
>
> - <a href="labs/monitoring-and-siem/splunk/Lab10-splunk-data-processing-and-parsing-basics/Lab10-splunk-data-processing-and-parsing-basics.md">Lab10 – Splunk Data Processing & Parsing Basics</a><br/>
>   Learned how Splunk ingests and transforms data using inputs.conf, props.conf, and transforms.conf. Worked with field extractions and parsing rules to improve log quality. This lab made Splunk feel less like a “black box” and more like a system I can configure intelligently.
>
> - <a href="labs/monitoring-and-siem/splunk/Lab11-splunk-cyber-kill-chain-investigation/Lab11-splunk-cyber-kill-chain-investigation.md">Lab11 – Splunk Cyber Kill Chain Investigation</a><br/>
>   Conducted a full investigation of a simulated web-server compromise by mapping activity across every phase of the Cyber Kill Chain. Correlated IDS alerts, web logs, and DNS data to reconstruct attacker behavior. This lab built my ability to handle multi-stage intrusions using Splunk.
>
> - <a href="labs/monitoring-and-siem/splunk/Lab12-splunk-backdoor-and-registry-investigation/Lab12-splunk-backdoor-and-registry-investigation.md">Lab12 – Splunk Backdoor and Registry Investigation</a><br/>
>   Investigated a complex intrusion involving backdoor account creation, suspicious registry modifications, WMIC abuse, and encoded PowerShell payloads. Decoded and traced attacker actions across multiple log sources. This was one of my most advanced labs and reflects real SOC-level investigation depth.
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

## Skills I'm Practicing

- Reading and analyzing SIEM logs (Splunk, general SIEM concepts)  
- Identifying suspicious or abnormal activity  
- Writing structured investigation notes and playbooks  
- Documenting technical work clearly for others to follow  
- Building up complexity across labs (introductory → intermediate → advanced)
- Documenting investigations like an analyst
- Basic Bash & PowerShell scripting
- Running packet captures and reading network traffic
- Windows & Linux triage
- Building playbooks and repeatable processes
- Steadily increasing complexity across labs

---

## Roadmap / Coming Soon

This repo will continue to grow as I add more content, including:  
- Additional SIEM labs (ELK stack, more Splunk scenarios)  
- Network analysis labs (Wireshark, packet capture)  
- Scanning/recon labs (Nmap, basic vulnerability discovery)  
- Expanded incident response playbooks  

---

## Note

This repo exists so I can learn, stay consistent, and get better at security and IT operational work over time.
<br></br>
Feedback is always welcome.
