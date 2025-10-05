
# Lab03 – Splunk Cyber Kill Chain Investigation (Tasks 1-7)

---

## Introduction to Incident Handling

### Overview / Objective
The objective was to understand how an incident impacts confidentiality, integrity, or availability (CIA) and how **Splunk**, functioning as a Security Information and Event Management (SIEM) system, supports the incident‑handling process.

In this lab, I conducted a full end-to-end investigation of a simulated cyber incident using Splunk as my primary analysis tool. The scenario involved a web server defacement attack against `imreallynotbatman.com`, hosted by the fictional company Wayne Enterprises. My objectives were to trace the adversary’s actions through each stage of the **Lockheed Martin Cyber Kill Chain**, identify the attacker’s tactics, techniques, and procedures (TTPs), and correlate activity across multiple data sources such as HTTP logs, IDS alerts, and Sysmon telemetry. 

Throughout the lab, I performed detailed Splunk queries to uncover reconnaissance behavior, brute-force authentication attempts, malware installation, command and control (C2) communication, and the final defacement of the target system. Each query was analyzed line-by-line to understand what it revealed about the attacker’s behavior and how it maps to MITRE ATT&CK techniques. The overall objective was to strengthen my ability to think like a SOC analyst — connecting raw log data to broader threat frameworks, applying NIST SP 800-61 principles, and producing an actionable, evidence-based incident report. This lab emphasized not only technical proficiency with Splunk but also structured analytical thinking, documentation, and professional reporting skills critical to cybersecurity operations.

### Environment & Prerequisites
- Splunk Enterprise environment pre‑configured with the `botsv1` dataset.  
- Access to simulated log sources: Suricata IDS, IIS web server, Sysmon, and Fortigate firewall.  
- Familiarity with basic Splunk navigation and search syntax.

### Step‑by‑Step Walkthrough
The lab described incident handling as a structured response to any event that could jeopardize CIA. I reviewed Splunk’s role in aggregating and correlating logs from multiple systems to detect these events. No commands were executed yet, but I examined indexed data to confirm ingestion from multiple sources and verified connectivity to Splunk Search Head and Indexer components.

📸 **Screenshot Placeholder:** Splunk Search Head interface showing available indexes and data sources.

### Findings / Analysis
Understanding incident handling early clarified how every detection and response task later in the lab aligns with the **NIST SP 800‑61 r2** lifecycle and **CompTIA Security+ Domain 2 (Incident Response)**. The introduction underscored the need for predefined processes and emphasized that SIEM tools automate detection and correlation across multiple log types.

### What I Learned
This task reinforced the foundational concepts of incident response. I learned that Splunk enables centralized visibility, correlation, and alerting—critical capabilities during incident triage. It highlighted that preparation and documentation are essential for containment and recovery phases. The key takeaway is that strong monitoring and data normalization pipelines form the backbone of any modern SOC.

---

## Incident Handling Lifecycle

### Overview / Objective
The goal was to review the **Incident Handling Lifecycle** and understand each of its stages: Preparation, Detection & Analysis, Containment & Eradication, and Post‑Incident Activity.

### Step‑by‑Step Walkthrough
I studied the lifecycle diagram provided and matched each phase to Splunk functionality:
- **Preparation** → Configuring data inputs and alert rules.  
- **Detection & Analysis** → Using correlation searches to detect anomalies.  
- **Containment & Eradication** → Blocking IPs, disabling accounts, or isolating assets.  
- **Post‑Incident Activity** → Reporting and continuous improvement.

### Findings / Analysis
Each phase is cyclical and dependent on accurate log collection. I learned how Splunk supports these by offering correlation searches, risk‑based alerting, and notable events within Enterprise Security.

### What I Learned
The task strengthened my understanding that incident handling is continuous. Every incident fuels process improvement. This maps directly to **Security+ Domain 2.5 (Apply incident response procedures)** and NIST’s emphasis on lessons learned to enhance defensive posture.

---

## Scenario Setup and Cyber Kill Chain Overview

### Overview / Objective
This task introduced the simulated incident at **Wayne Enterprises**, where the domain `imreallynotbatman.com` was defaced. My objective was to understand the environment, available data, and how attacker behavior maps to the **Lockheed Martin Cyber Kill Chain**.

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-01.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="500"><br>
  <em>Figure 1</em>
</p>

This part of the lab established the context of the lab and defined what constitutes a **security incident**. 

### Data Sources Review
- `stream:http` – Network flows.  
- `iis` – Web server access logs.  
- `suricata` – Intrusion Detection System alerts.  
- `XmlWinEventLog:Microsoft‑Windows‑Sysmon` – Endpoint process creation and network events.

### Lab Environment Setup
For this lab, I was provided with a virtual machine (VM) that served as the investigation environment. Once deployed, the machine was automatically assigned an IP address labeled as `MACHINE_IP`, which took approximately 3–5 minutes to initialize and become available. The VM contained all the event logs required for the investigation, specifically stored in the `index=botsv1` dataset. This dataset, released by Splunk, is designed to simulate a realistic environment for security analysis and may include real-world language or expressions. The lab’s purpose was to connect to this environment, explore the data sources and source types, and begin performing investigations based on the provided event data.

I accessed Splunk Enterprise on the target VM at `http://10.201.33.31` using the AttackBox browser (AttackBox IP `10.201.122.5`). From the provided AttackBox (on the lab network) I verified reachability with ping, enumerated services with nmap, and inspected any web interfaces by opening `http://10.201.33.31` in the AttackBox browser.

In Splunk’s Search & Reporting app I confirmed the index=botsv1 dataset with `index=botsv1 | stats count by sourcetype` to understand what types of data were available

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="700"><br>
</p>

- **Event Logs Source**: I was provided [`index=botsv1`](https://github.com/splunk/botsv1), which contained all event data necessary for the analysis. The results showed different sourcetypes, which represent various log formats such as network, web, or host data. This helped me confirm that the dataset was properly loaded and gave me a clear view of the log sources I would be analyzing throughout the lab.

#### Independent Checks
I performed some independent, explaratory checks outside the lab instructions to validate connectivity and practice recon techniques.
- **Target:**  `10.201.17.82` (deployed via TryHackMe lab UI)  
- **Context:**  I deployed the target machine using the TryHackMe interface and used the provided AttackBox (attacker VM) to perform reconnaissance and basic connection tests.

#### Practical Checklist I Used
- Deploy the target VM via TryHackMe and copy the Target IP.  
- Open the AttackBox and ensure I am on the lab network.  
- Run `ping` to confirm host is up.  
- Run `nmap` (full or targeted) to discover open ports and services.  
- Use `curl` or the AttackBox browser to fetch web pages if HTTP(S) is available.  
- Use `nc` to quickly test specific ports.  
- If SSH is exposed and credentials are provided by the lab, use `ssh` for interactive access.  
- Terminate or extend the VM when finished using the TryHackMe controls.

**(1) Checking Basic Connectivity (AttackBox Linux Bash terminal)** </br>

My goal here is to quickly confirm  whether the target is reachable from the AttackBox (verifies network connectivity and that the VM is up).

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-02.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="500"><br>
  <em>Figure 2</em>
</p>

```bash
ping -c 3 10.201.17.82
```
- `ping` — Sends ICMP Echo Request packets to the target to check if the host responds. Useful for basic reachability checks.
- `-c 3` — Limits the ping to 3 ICMP packets so the test is quick and concise.
- `10.201.17.82` — The target IP returned by the TryHackMe lab UI.

**(2) Discovering Open Ports via Nmap (Attackbox Linux Bash terminal)** </br>

I also wanted to  enumerate which ports are open and which services are listening so I know where to focus further testing (web, SSH, custom services, etc.).

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-03.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="500"><br>
  <em>Figure 3</em>
</p>

Welp, that didn't work, so I just moved on for now. This is all my own confirmation check, and not necessary for this lab.

```bash
nmap -sS -sV -p- 10.201.17.82
```
- `nmap` — Network scanner used to discover hosts and services on a network.
- `-sS` — TCP SYN scan (also called "half-open" scan). It sends a SYN and analyzes the response without completing the TCP handshake; it's fast and stealthier than a full connect scan.
- `-sV` — Service/version detection. Nmap attempts to identify the service running on each open port and the software version (e.g., Apache 2.4.41).
- `-p-` — Scan every TCP port (1–65535). Useful if you want a full port sweep rather than just common ports.
- `10.201.17.82` — The target IP.

**(3) Checking Basic Connectivity (AttackBox Linux Bash terminal)** </br>

My goal here is to try verifying that the web server is present, inspect response headers (server, cookies, redirects, status codes), and quickly retrieve pages for manual review or to inform later automated testing.

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-04.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="500"><br>
  <em>Figure 4</em>
</p>

```bash
curl -I http://10.201.17.82
curl http://10.201.17.82/index.php
```
- `curl` — Command-line tool to transfer data from or to a server using various protocols (HTTP, HTTPS, FTP, etc.).
- `-I` — Requests only the HTTP headers (HEAD request), useful for quickly seeing server type, status code, and response headers without downloading the full page.
- `http://10.201.17.82` — The target’s web root. If a web service listens on a nonstandard port, include `:port` (for example `http://10.201.17.82:8000`).
- `http://10.201.17.82/index.php` — Example path to fetch a specific page or endpoint to see content or responses.

**(4) Testing Specific TCP Ports via netcat (AttackBox Linux Bash terminal)** </br>

I wanted quick verification of whether a specific port is accepting TCP connections (faster than a full nmap when you want to check individual services).

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-05.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="500"><br>
  <em>Figure 5</em>
</p>

```bash
nc -vz 10.201.17.82 80
nc -vz 10.201.17.82 22
```
- `nc` (netcat) — Lightweight utility for reading/writing raw TCP/UDP connections. Great for quick port checks and banner grabbing.
- `-v` — Verbose output to show connection attempts and results.
- `-z` — Zero-I/O mode: used for scanning/listening without sending data (useful for quick port checks).
- `10.201.17.82 80` — Target IP and port to test (80 = HTTP).

### Findings / Analysis
All expected sourcetypes were present. Understanding these sources early streamlined later correlation searches across network and host data. This setup phase emphasized the importance of situational awareness before analysis. Knowing data sources and their fields prevents misinterpretation of logs—a skill fundamental to blue‑team operations. This relates to **MITRE ATT&CK TA0001 (Initial Access)** and Security+ objectives covering data collection and correlation.

---

## Task 1 – Reconnaissance Phase

### Overview / Objective
The objective was to detect early reconnaissance activity targeting `imreallynotbatman.com`. Reconnaissance is the first phase of the Cyber Kill Chain, where adversaries gather intelligence about targets.

### Step‑by‑Step Walkthrough
<h4>(1) I began by searching the dataset for any logs referencing the domain.</h4>

```spl
index=botsv1 imreallynotbatman.com
```
- **index=botsv1** – Restricts scope to the lab dataset. *Why:* Prevents irrelevant results.  
- **imreallynotbatman.com** – Keyword search for the targeted domain. *Why:* Captures any events involving the compromised web server.

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-06.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="500"><br>
  <em>Figure 6</em>
</p>

This returned several sourcetypes, including `suricata`, `stream:http`, `fortigate_utm`, and `iis`. 

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-07.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="500"><br>
  <em>Figure 7</em>
</p>

<h4>(2)</h4> I refined the query to focus on HTTP traffic because the domain represents a web address. 

I first limited my query to `HTTP` traffic using `sourcetype=stream:http` to focus only on web communication logs and reduce unrelated results. This made the search faster and more precise, allowing me to see which source IPs had connected to that domain. The results showed two main IPs — `40.80.148.42` and `23.22.63.114`, with the first generating the majority of HTTP requests, suggesting it was the primary host involved in the connection.

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-08.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 8</em>
</p>

```spl
index=botsv1 imreallynotbatman.com sourcetype=stream:http
```
- **sourcetype=stream:http** – Selects HTTP network flows. *Why:* Web traffic best illustrates enumeration behavior.  

From this search, I identified two IPs (`40.80.148.42` and `23.22.63.114`) repeatedly connecting to the server (identified via "src_ip" field in Splunk). `40.80.148.42` was by far generating the majority of the HTTP requests. So I investigated `40.80.148.42` first.

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-09.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 9</em>
</p>

<h4>(3) I needed to validate that this was indeed a scanning attempt by `40.80.148.42`.</h4>

I started by narrowing my search query to Suricata logs using the query:

```spl
index=botsv1
imreallynotbatman.com
sourcetype:suricata
```

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-10.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 10: This query will show the logs from the suricata log source that are from the source IP 40.80.248.42</em>
</p>

After using the Suricata IDS logs, and then filtering events generated by the source IP `40.80.148.42`, I found 46 distinct alert signatures under the `alert.signature` field. These included exploit attempts (active recon) such as Cross-Site Scripting, SQL Injection, XXE, and Shellshock (CVE-2014-6271). Most likely to test or exploit vulnerabilities. The large number of repeated detections and variety of triggered signatures confirm that this IP was performing reconnaissance and vulnerability scanning against the target host 192.168.250.70.

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-11.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 11</em>
</p>

While reviewing Suricata events for source IP `40.80.148.42`, one of the first alerts observed was “SURICATA HTTP Host header invalid.” This alert typically appears when an HTTP request contains a malformed or empty Host header, which is something normal browsers rarely do. HTTP requests with empty headers are common with automated vulnerability scanners or reconnaissance tools, which sends deliberately malformed requests to see how a web server responds. The goal of this attacker was most likely to fingerprint the web application, determine how it handles unexpected inputs, and identify potential misconfigurations.

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-12.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 12</em>
</p>

Because this activity doesn’t exploit a specific vulnerability but instead maps and tests the server’s behavior, it’s a strong indicator of active reconnaissance.


### Findings / Analysis
`40.80.148.42` accounted for over 90 % of the requests, and was consistent with automated vulnerability scanning. Active recon evidence included frequent GET requests.

### What I Learned
This task demonstrated how correlated IDS and network logs can expose early attacker behavior. Recognizing reconnaissance helps defenders act during the earliest possible stage of an attack, aligning with **Security+ Domain 3 (Threat Detection)** and **NIST IR Phase – Identification** (Woohoo! Earning my CompTIA Sec+ cert was worth it).

---

## Task 2 – Exploitation Phase

### Overview / Objective
The objective was to confirm whether the attacker attempted or succeeded in exploiting vulnerabilities discovered during reconnaissance—specifically targeting the Joomla CMS running on the web server.

### Step‑by‑Step Walkthrough
I began by counting the number of requests from each source IP to the target domain:

```spl
index=botsv1 imreallynotbatman.com sourcetype=stream:* 
| stats count(src_ip) as Requests by src_ip 
| sort -Requests
```
**Breakdown**
- **sourcetype=stream*** – Includes all protocol types captured by Splunk Stream. *Why:* Provides a full view of potential attack vectors.  
- **stats count(src_ip) as Requests by src_ip** – Counts events per source IP. *Why:* Identifies hosts generating abnormal traffic.  
- **sort -Requests** – Orders results descending. *Why:* Highlights the most active attackers first.

Next, I filtered for HTTP POST methods to identify credential submissions:

```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST
```
**Breakdown**
- **dest_ip="192.168.250.70"** – Specifies the web server. *Why:*  Focuses on attacker traffic targeting the victim.  
- **http_method=POST** – Selects requests containing form data. *Why:*  POST requests typically carry credentials during authentication.

Inspecting the `form_data` field revealed multiple login attempts to `/joomla/administrator/index.php`. I used regex to extract submitted passwords:

```spl
rex field=form_data "passwd=(?<password>\w+)"
```
The successful credentials were `admin : batman`, originating from `40.80.148.42`.

📸 **Screenshot Placeholder:** Table of POST requests showing multiple login attempts and the successful one.

### Findings / Analysis
Evidence confirmed a brute‑force attack followed by successful authentication. `23.22.63.114` performed failed attempts while `40.80.148.42` achieved login success.

### What I Learned
This task taught me how to use Splunk to detect web‑based brute‑force and credential attacks through HTTP method filtering and field extraction. It emphasized the value of regex for pulling key data points from raw logs and how statistics commands summarize large volumes efficiently. From a SOC perspective, this correlates to **MITRE ATT&CK T1110 (Brute Force)** and **Security+ Domain 3.2 (Analyze Indicators of Compromise)**.

---

## Task 3 – Installation Phase

### Overview / Objective
The objective of this task was to verify whether the attacker successfully installed or executed any malicious payloads following exploitation. In the Cyber Kill Chain, **Installation** represents the stage where adversaries establish persistence within a target environment, typically by deploying malware or backdoors.

### Step‑by‑Step Walkthrough
After confirming successful authentication from the prior phase, I searched for evidence of file uploads to the compromised host:

```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" *.exe
```
**Breakdown**
- **index=botsv1** – Targets the dataset containing simulated incident logs. *Why:* Ensures only relevant Splunk BOTSv1 data is queried.  
- **sourcetype=stream:http** – Filters events to HTTP network traffic. *Why:* Malware is often delivered via HTTP uploads.  
- **dest_ip="192.168.250.70"** – Specifies the compromised web server. *Why:* Focuses on inbound traffic directed at the victim.  
- **.exe** – Keyword search for executable files. *Why:* Detects potential binary uploads used to install persistence agents.

The results displayed two filenames—`3791.exe` and `agent.php`. Both were uploaded by the attacker IP `40.80.148.42`. To confirm execution, I queried Windows Sysmon process creation logs:

```spl
index=botsv1 "3791.exe" sourcetype=XmlWinEventLog EventCode=1
```
**Breakdown**
- **sourcetype=XmlWinEventLog** – Targets Windows event logs forwarded to Splunk. *Why:* Sysmon records detailed process events.  
- **EventCode=1** – Filters for process creation events. *Why:* Event ID 1 confirms the execution of a binary.  
- **"3791.exe"** – Search term for the suspected malware. *Why:* Validates that the payload was run after upload.

📸 **Screenshot Placeholder:** Sysmon EventCode 1 log entry showing process creation for `3791.exe`.

### Findings / Analysis
Results confirmed that `3791.exe` executed shortly after upload. This demonstrated the attacker successfully transitioned from exploitation to persistence. The malicious binary likely established communication with external infrastructure for command and control.

### What I Learned
I learned how to validate malware execution through cross‑referencing network and endpoint data sources in Splunk. Sysmon EventCode 1 is a reliable indicator for process creation and should be monitored in production environments using detection rules aligned with **MITRE ATT&CK T1059 (Command and Scripting Interpreter)**. This phase also illustrates **Security+ Domain 2.2 (Analyze Indicators of Malware)** and connects to the **Eradication** phase of the NIST Incident Response Lifecycle.

---

## Task 4 – Action on Objectives Phase

### Overview / Objective
The goal of this phase was to determine the attacker’s ultimate objective after establishing persistence. In this scenario, the malicious actor defaced the company’s public website—a clear indicator of the **Actions on Objectives** stage of the Cyber Kill Chain.

### Step‑by‑Step Walkthrough
I examined outbound traffic from the compromised host to identify files or domains related to the defacement activity.

```spl
index=botsv1 src=192.168.250.70 sourcetype=suricata
```
**Breakdown**
- **src=192.168.250.70** – Specifies the infected host as the source. *Why:* Identifies outgoing traffic from the compromised system.  
- **sourcetype=suricata** – Filters for network IDS alerts. *Why:* Detects anomalous connections or file transfers to external domains.

This query revealed outbound requests to `prankglassinebracket.jumpingcrab.com` transferring a file named `poisonivy-is-coming-for-you-batman.jpeg`. This image replaced the homepage of the target server, confirming defacement.

📸 **Screenshot Placeholder:** Suricata alert showing outbound connection to `jumpingcrab.com`.

### Findings / Analysis
The attacker’s intent was to publicly deface the website to demonstrate control. Outbound IDS alerts and web traffic correlation validated data exfiltration and modification activities. This phase provided a clear end goal of the intrusion campaign.

### What I Learned
This task taught me how to trace adversary objectives using Splunk by following the attack from reconnaissance to impact. Understanding “Actions on Objectives” is vital for incident classification and damage assessment within a SOC. The technique relates to **MITRE ATT&CK T1491 (Defacement)** and NIST’s **Recovery Phase** of incident handling. Documenting such activity supports executive reporting and post‑incident remediation plans.

---

## Task 5 – Command and Control (C2) Phase

### Overview / Objective
This task focused on identifying if the attacker established a **Command and Control (C2)** channel with external infrastructure. C2 allows threat actors to remotely control infected hosts and execute further commands.

### Step‑by‑Step Walkthrough
I searched firewall and network logs for evidence of communication with the domain `prankglassinebracket.jumpingcrab.com`.

```spl
index=botsv1 sourcetype=fortigate_utm "poisonivy-is-coming-for-you-batman.jpeg"
```
**Breakdown**
- **sourcetype=fortigate_utm** – Specifies Fortigate Unified Threat Management logs. *Why:* Captures firewall and web‑filter activity.  
- **Search term for JPEG file** – Links the known defacement artifact to potential C2 communication. *Why:* The same infrastructure may host C2 services.

The results showed repeated connections from `192.168.250.70` to `23.22.63.114` over port 1337, correlating with the dynamic DNS domain `jumpingcrab.com`.

📸 **Screenshot Placeholder:** Firewall logs displaying C2 communication over port 1337.

### Findings / Analysis
The attacker used a Dynamic DNS service to obfuscate their C2 server IP. Port 1337 indicated custom malware communication, matching signatures of the Poison Ivy remote access tool. This showed a successful persistence channel was active.

### What I Learned
I learned to detect C2 communications by correlating IDS, firewall, and endpoint data. Dynamic DNS is a common tactic for maintaining C2 reachability, and Splunk queries can identify these patterns through consistent destination hostnames and ports. This aligns with **MITRE ATT&CK T1071 (Application Layer Protocol)** and **Security+ Domain 3.3 (Analyze threat data to support an incident response)**.

---

## Task 6 – Weaponization Phase

### Overview / Objective
The objective was to analyze how the attacker prepared and delivered their payloads by pivoting on known indicators through OSINT tools. In the Cyber Kill Chain, Weaponization covers the creation of malware and exploitation packages used later in Delivery.

### Step‑by‑Step Walkthrough
I conducted open‑source lookups on the malicious domain and associated infrastructure using external intelligence sources (VirusTotal, Robtex, and Whois). These lookups linked `jumpingcrab.com` to an email address `lillian.rose@po1son1vy.com`, indicating possible threat‑actor attribution.

📸 **Screenshot Placeholder:** VirusTotal graph view showing domain relationships.

### Findings / Analysis
The domain was associated with multiple subdomains and related IP addresses used in previous campaigns. This confirmed the attacker leveraged pre‑existing malware infrastructure to deliver payloads, a common APT pattern.

### What I Learned
Weaponization is rarely observable in internal logs, but threat intelligence correlation can expose it indirectly. I learned how OSINT enriches SIEM data and helps analysts build context beyond raw events. This relates to **MITRE ATT&CK T1587 (Develop Capabilities)** and **Security+ Domain 1.4 (Explain threat actors and attributes)**.

---

## Task 7 – Delivery Phase

### Overview / Objective
The purpose of this phase was to examine malware delivery artifacts identified during the Weaponization stage and determine how the malicious payload reached the target.

### Step‑by‑Step Walkthrough
I queried threat intelligence sources for the hashes of the malware identified in the Fortigate and Sysmon logs:

```spl
index=botsv1 hash=* OR file_name="MirandaTateScreensaver.scr.exe"
```
**Breakdown**
- **hash=*** – Searches for hash values in indexed logs. *Why:* Allows pivoting on known file identifiers.  
- **file_name="MirandaTateScreensaver.scr.exe"** – Targets the malware sample. *Why:* Validates if the payload appears within local telemetry.

Cross‑referencing with VirusTotal and Hybrid Analysis showed the file was a Poison Ivy variant with MD5 `c99131e0169171935c5ac32615ed6261`. It was delivered via HTTP download and executed through a user interaction.

📸 **Screenshot Placeholder:** Hybrid‑Analysis summary of malware behavior.

### Findings / Analysis
Analysis confirmed that the malware was delivered through social engineering and web downloads, not email. This represents the **Delivery** phase of the Cyber Kill Chain, bridging reconnaissance and exploitation.

### What I Learned
I learned how threat intelligence enrichment enhances forensic findings within Splunk. Malware delivery mechanisms must be monitored for early warning signs, particularly HTTP downloads of executables. This maps to **Security+ Domain 1.2 (Compare and contrast attack types)** and **MITRE ATT&CK T1566 (Phishing)** for social delivery vectors.

---

## Conclusion and Lessons Learned

### Overview / Objective
The final task consolidated the findings from the entire investigation and reviewed each phase of the Cyber Kill Chain to produce a comprehensive summary for executive reporting and process improvement.

### Findings / Analysis
| Phase | Evidence | Indicators |
|:------|:----------|:-----------|
| Reconnaissance | Scanning of imreallynotbatman.com | IP 40.80.148.42 |
| Exploitation | Brute‑force on Joomla CMS | IP 23.22.63.114, Creds admin/batman |
| Installation | Upload and execution of 3791.exe | Process Creation Event Code 1 |
| Action on Objectives | Website defacement | poisonivy‑is‑coming‑for‑you‑batman.jpeg |
| Command & Control | C2 communication over port 1337 | jumpingcrab.com |
| Weaponization | Malware infrastructure setup | Email lillian.rose@po1son1vy.com |
| Delivery | Poison Ivy variant delivery | MirandaTateScreensaver.scr.exe |

### What I Learned
This final phase reinforced how SIEM platforms like Splunk enable end‑to‑end attack mapping and incident documentation. I learned to connect each stage of the Cyber Kill Chain to real telemetry sources and apply Security+ and NIST principles to practical incident response. The key takeaway is that consistent data enrichment, timeline reconstruction, and cross‑source correlation are essential for proactive threat hunting and strategic defense operations.

📸 **Screenshot Placeholder:** Summary dashboard displaying timeline of attack phases and associated indicators.

---


