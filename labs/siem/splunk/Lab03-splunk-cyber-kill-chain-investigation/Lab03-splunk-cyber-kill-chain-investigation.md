
# Lab03 – Splunk Cyber Kill Chain Investigation (Objectives 1-7)

<details>
  <summary><b>📘 Table of Contents</b></summary>

  - [Overview / Objective](#overviewobjective-)
    - [Objective](#Objective)
    - [Environment & Prerequisites](#environmentprerequisites)
    - [Step-by-Step Walkthrough](#stepbystepwalkthrough)
    - [Findings / Analysis](#findingsanalysis)
  - [Scenario Overview & Environment Setup](#scenariooverview--environment-setup-)
    - [Scenario](#scenario)
    - [Data Sources](#datasources)
    - [Environment Setup](#environmentsetup)
    - [Independent Checks](#independentchecks)
    - [Findings / Analysis](#findingsanalysis1)
    - [What I Learned](#whatilearned)
  - [Objective 1 – Reconnaissance Phase](#objective1reconnaissancephase-)
    - [Overview](#overview)
    - [Step‑by‑Step Walkthrough](#stepbystepwalkthrough-1)
    - [Findings / Analysis](#findingsanalysis-2)
    - [What I Learned](#whatilearned1-)
  - [Objective 2 – Exploitation Phase](#objective2exploitationphase)
  - [Objective 3 – Installation Phase](#objective3installation-phase)
  - [Objective 4 – Action on Objectives Phase](#objective4actiononobjectives-phase)
  - [Objective 5 – Command and Control (C2) Phase](#objective5commandandcontrolc2phase)
  - [Objective 6 – Weaponization Phase](#objective6weaponizationphase)
  - [Objective 7 – Delivery Phase](#objective7deliveryphase)
  - [Conclusion and Lessons Learned](#conclusionandlessonslearned)
</details>

---

## Overview / Objective </br>

<details>

<summary><b>(Click to expand)</b></summary>

### Objective

The objective was to understand how an incident impacts confidentiality, integrity, or availability (CIA) and how **Splunk**, functioning as a Security Information and Event Management (SIEM) system, supports the incident‑handling process.

In this lab, I conducted a full end-to-end investigation of a simulated cyber incident using Splunk as my primary analysis tool. The scenario involved a web server defacement attack against `imreallynotbatman.com`, hosted by the fictional company Wayne Enterprises. My objectives were to trace the adversary’s actions through each stage of the **Lockheed Martin Cyber Kill Chain**, identify the attacker’s tactics, techniques, and procedures (TTPs), and correlate activity across multiple data sources such as HTTP logs, IDS alerts, and Sysmon telemetry. 

Throughout the lab, I performed detailed Splunk queries to uncover reconnaissance behavior, brute-force authentication attempts, malware installation, command and control (C2) communication, and the final defacement of the target system. Each query was analyzed line-by-line to understand what it revealed about the attacker’s behavior and how it maps to MITRE ATT&CK techniques. The overall objective was to strengthen my ability to think like a SOC analyst — connecting raw log data to broader threat frameworks, applying NIST SP 800-61 principles, and producing an actionable, evidence-based incident report. This lab emphasized not only technical proficiency with Splunk but also structured analytical thinking, documentation, and professional reporting skills critical to cybersecurity operations.


### Environment & Prerequisites

- Splunk Enterprise environment pre‑configured with the `botsv1` dataset.  
- Access to simulated log sources: Suricata IDS, IIS web server, Sysmon, and Fortigate firewall.  
- Familiarity with basic Splunk navigation and search syntax.

### Step‑by‑Step Walkthrough

The lab described incident handling as a structured response to any event that could jeopardize CIA. I reviewed Splunk’s role in aggregating and correlating logs from multiple systems to detect these events. No commands were executed yet, but I examined indexed data to confirm ingestion from multiple sources and verified connectivity to Splunk Search Head and Indexer components.

### Findings / Analysis

Understanding incident handling early clarified how every detection and response task later in the lab aligns with the **NIST SP 800‑61 r2** lifecycle and **CompTIA Security+ Domain 2 (Incident Response)**. The introduction underscored the need for predefined processes and emphasized that SIEM tools automate detection and correlation across multiple log types.

</details>

<!--
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
-->

---

## Scenario Overview & Environment Setup </br>

<details>

<summary><b>(Click to expand)</b></summary>

### Scenario

The domain `imreallynotbatman.com` was defaced in a simulated breach of Wayne Enterprises. I examined the environment and collected relevant logs to track attacker actions across the Lockheed Martin Cyber Kill Chain.

<p align="center">
  <img src="images/splunk-cyber-kill-chain-investigation-01.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="300"><br>
  <em>Figure 1</em>
</p>

This part of the lab established the context of the lab and defined what constitutes a **security incident**. 

### Data Sources

- `stream:http` – Network flows.  
- `iis` – Web server access logs.  
- `suricata` – Intrusion Detection System alerts.  
- `XmlWinEventLog:Microsoft‑Windows‑Sysmon` – Endpoint process creation and network events.

### Environment Setup 

The investigation was performed in a virtual machine (VM) environment preconfigured for Splunk analysis. Once deployed, the VM was automatically assigned an internal IP address (`MACHINE_IP`) and initialized within a few minutes. The Splunk instance hosted the `botsv1` dataset — a realistic collection of simulated security event logs designed for enterprise-scale analysis. This dataset included various sourcetypes representing web, network, and host activity, allowing for comprehensive event correlation and threat investigation throughout the lab.

<blockquote>
<strong>Important Note:</strong> IP addresses in this lab are ephemeral and were recorded at the time of each step (placeholders such as `MACHINE_IP` are used in this write-up when the IP changed between sessions).
</blockquote>

I accessed Splunk Enterprise on the target VM (`10.201.17.82`, `http://10.201.33.31`, `10.201.117.123`, `10.201.119.166`, `10.201.5.103`, or `10.201.35.24`) using the AttackBox browser (AttackBox IP `10.201.122.5`,  `10.201.117-139`, or `10.201.81.194`). From the provided AttackBox (on the lab network) I verified reachability with ping, enumerated services with nmap, and inspected any web interfaces by opening `10.201.17.82` or `http://10.201.33.31` in the AttackBox browser.

- **Target:**  `10.201.17.82` and `10.201.33.31` (deployed in an isolated virtual lab environment)  
- **Context:**  I deployed the target machine and used the attacker VM to perform reconnaissance and basic connection tests.
- **Event Logs Source**: The dataset for this lab was indexed under [`index=botsv1`](https://github.com/splunk/botsv1), which contained all event data necessary for the analysis. The results showed multiple sourcetypes representing various log formats (network, web, and host data). This confirmed that the dataset was properly loaded and gave me a clear view of the log sources I would be analyzing throughout the lab.

In Splunk’s Search & Reporting app I confirmed the index=botsv1 dataset with `index=botsv1 | stats count by sourcetype` to understand what types of data were available

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="700"><br>
</p>

### Independent Checks 

I performed some independent, exploratory checks outside the provided lab instructions to validate connectivity and practice reconnaissance techniques.

<h4>(1) Checking Basic Connectivity (AttackBox Linux Bash terminal)</h4>

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
- `10.201.17.82` — Target IP assigned to the analysis VM.

<h4>(2) Discovering Open Ports via Nmap (Attackbox Linux Bash terminal)</h4>

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

<h4>(3) Checking Basic Connectivity (AttackBox Linux Bash terminal)</h4>

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

<h4>(4) Testing Specific TCP Ports via netcat (AttackBox Linux Bash terminal)</h4>

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

#### Practical Checklist I Used
- Deploy the target VM and copy the target IP. 
- Open the AttackBox and ensure I am on the lab network.  
- Run `ping` to confirm host is up.  
- Run `nmap` (full or targeted) to discover open ports and services.  
- Use `curl` or the AttackBox browser to fetch web pages if HTTP(S) is available.  
- Use `nc` to quickly test specific ports.  
- If SSH is exposed and credentials are provided by the lab, use `ssh` for interactive access.  
- Terminate or extend the VM when finished with the investigation.

### Findings / Analysis

All expected sourcetypes were present. Understanding these sources early streamlined later correlation searches across network and host data. This setup phase emphasized the importance of situational awareness before analysis. Knowing data sources and their fields prevents misinterpretation of logs—a skill fundamental to blue‑team operations. This relates to **MITRE ATT&CK TA0001 (Initial Access)** and Security+ objectives covering data collection and correlation.


</details>

---

## Objective 1 – Reconnaissance Phase </br>
<details>

<summary><b>(Click to expand)</b></summary>

### Overview

The objective was to detect early reconnaissance activity targeting `imreallynotbatman.com`. Reconnaissance is the first phase of the Cyber Kill Chain, where adversaries gather intelligence about targets.


### Step‑by‑Step Walkthrough

<h4>(Step 1) I began by searching the dataset for any logs referencing the domain.</h4>

```spl
index=botsv1
imreallynotbatman.com
```
- **index=botsv1**  –  Specifies the data source or repository (database of logs).
- **imreallynotbatman.com**  –  Specifies the specific domain I'm investigating, like a keyword search for the targeted domain to capture any events involving the compromised (defaced) web server.

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-06.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 6</em>
</p>

This returned several sourcetypes, including `suricata`, `stream:http`, `fortigate_utm`, and `iis`. 

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-07.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 7</em>
</p>

<h4>(Step 2) I refined the query to focus on HTTP traffic because the domain represents a web address.</h4>

I first limited my query to `HTTP` traffic using `sourcetype=stream:http` to focus only on web communication logs and reduce unrelated results. This made the search faster and more precise, allowing me to see which source IPs had connected to that domain. The results showed two main IPs — `40.80.148.42` and `23.22.63.114`, with the first generating the majority of HTTP requests, suggesting it was the primary host involved in the connection.

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-08.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 8</em>
</p>

```spl
index=botsv1
imreallynotbatman.com
sourcetype=stream:http
```
- **sourcetype=stream:http** – Selects HTTP network flows to focus on web communication logs and investigate potential enumeration behavior.  

From this search, I identified two IPs (`40.80.148.42` and `23.22.63.114`) repeatedly connecting to the server (identified via `src_ip` field in Splunk). `40.80.148.42` was by far generating the majority of the HTTP requests. So I investigated `40.80.148.42` first.

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-09.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 9</em>
</p>

<h4>(Step 3) I needed to validate that this was indeed a scanning attempt by `40.80.148.42`.</h4>

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
       width="1000"><br>
  <em>Figure 10: This query will show the logs from the suricata log source that are from the source IP 40.80.248.42</em>
</p>

After using the Suricata IDS logs, and then filtering events generated by the source IP `40.80.148.42`, I found 46 distinct alert signatures under the `alert.signature` field. These included exploit attempts (active recon) such as Cross-Site Scripting, SQL Injection, XXE, and Shellshock (CVE-2014-6271). Most likely to test or exploit vulnerabilities. 

The large number of repeated detections and variety of triggered signatures confirm that this IP was performing reconnaissance and vulnerability scanning against the target host 192.168.250.70.

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-11.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 11</em>
</p>

While reviewing Suricata events for source IP `40.80.148.42`, one of the first alerts observed was “SURICATA HTTP Host header invalid.” This alert typically appears when an HTTP request contains a malformed or empty Host header, which is something normal browsers rarely do. 

HTTP requests with empty headers are common with automated vulnerability scanners or reconnaissance tools, which sends deliberately malformed requests to see how a web server responds. The goal of this attacker was most likely to fingerprint the web application, determine how it handles unexpected inputs, and identify potential misconfigurations.

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-12.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 12</em>
</p>

Because this activity doesn’t exploit a specific vulnerability but instead maps and tests the server’s behavior, it’s a strong indicator of active reconnaissance.

### Findings / Analysis

- `40.80.148.42` accounted for over  90 % of the requests, and was consistent with automated vulnerability scanning. Active recon evidence included frequent GET requests.
- I filtered the Suricata logs for traffic from the attacker IP `40.80.148.42` to the web server `192.168.250.70`. In the `http_referrer` field, I found multiple entries pointing to paths such as `/joomla/index.php` and `/joomla/administrator/`. These are specific to the Joomla content management system, confirming the web server was running Joomla. This field typically shows the URL of the webpage that directed the client to the current resource, so basically where each request originated from.
- To further investigate the nature of the attack, I examined the `http_user_agent` field in the same logs. This field identifies the software or tool that generated each `HTTP` request, which helps determine whether the traffic originated from a legitimate browser or an automated scanner. Within this field, I found entries containing the string `acunetix_wvs_security_test`, a known signature used by the Acunetix web vulnerability scanner. Combined with the presence of the Shellshock (CVE-2014-6271) exploit pattern, this confirms that the attacker was using Acunetix to perform automated reconnaissance and vulnerability testing against the Joomla server.
- Summary:
  - CMS of web server: Joomla
  - Scanner attacker likely used: Acunetix
  - CVE: 2014-6271 (Shellshock)

### What I Learned

This task demonstrated how correlated IDS and network logs can expose early attacker behavior. Recognizing reconnaissance helps defenders act during the earliest possible stage of an attack, aligning with **Security+ Domain 3 (Threat Detection)** and **NIST IR Phase – Identification** (Woohoo! Earning my CompTIA Sec+ cert was worth it).

</details>

---

## Objective 2 – Exploitation Phase</br>

<details>

<summary><b>(Click to expand)</b></summary>

### Overview
The objective was to confirm whether the attacker attempted or succeeded in exploiting vulnerabilities discovered during reconnaissance—specifically targeting the Joomla CMS running on the web server.

**The information we have so far:**
- I found two IP addresses from the reconnaissance phase that were sending requests to the web server:
    - `40.80.148.42`
    - `23.22.63.114`
 - One of the IPs `40.80.148.42` was seen attempting to scan the web server with IP `192.168.250.70`.
 - The attacker was using the web scanner Acunetix for the scanning attempt.
 - The webserver is using the Joomla CMS.

### Step‑by‑Step Walkthrough

<h4>(Step 1) I began by running three Splunk searches to analyze web activity targeting the imreallynotbatman.com web server</h4>

  - <b>First query:</b> I immediately noticed `40.80.148.42` has made the majority of requests with 17483 requests and `23.22.63.114` made 1235 requests against web server (Figure 13).
  - <b>Second query:</b> Saw that `40.80.148.42`, `23.22.63.114`, and `192.168.2.50` have all made HTTP requests to the web server by looking into the `src_ip` field (Figure 14). Looking into the `http_method` field, I saw that most of the HTTP traffic observed consisted of POST requests directed at the web server (see Figure 15).
  - <b>Third query:</b> Confirmed that both `40.80.148.42` and `23.22.63.114` sent POST requests to the web server, with the majority originating from `40.80.148.42` (see Figure 16).

<blockquote>
Below are more details about each query and the corresponding findings.
</blockquote>

_<b>First query (Step 1)</b>_

This query was used to identify which client IPs accessed the domain name, and the count events per source IP, regardless of how it resolved (`sourcetype=stream:*`). This search focused on hostname-based activity across multiple Stream sourcetypes (`sourcetype=stream:*`), capturing a broad view of traffic involving the domain (including DNS and HTTP Host header references).

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-13.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 13</em>
</p>

```spl
index=botsv1 imreallynotbatman.com sourcetype=stream:* 
| stats count(src_ip) as Requests by src_ip 
| sort -Requests
```

- **sourcetype=stream*** – Includes all protocol types captured by Splunk Stream. This provides a full view of potential attack vectors.  
- **stats count(src_ip) as Requests by src_ip** – Counts events per source IP. Doing so identifies hosts generating abnormal traffic.  
- **sort -Requests** – Orders results descending. This is to highlight the most active attackers first.

_<b>Second query (Step 1)</b>_

This query was used to narrow the scope to HTTP requests directed specifically to the web server’s IP address to identify all inbound HTTP traffic. This provided a more focused look at network-level interactions and potential data submissions to the site. As part of the second query, I looked into the `http_method` field and saw that most of the HTTP traffic observed consisted of POST requests directed at the web server (see Figure 15). POST requests typically carry credentials during authentication.

```spl
index=botsv1
sourcetype=stream:http
dest_ip="192.168.250.70"
```

- **dest_ip="192.168.250.70"** – Specifies the web server. Helps focus on attacker traffic targeting the web server.  
- **sourcetype=stream:http** - Specifically records HTTP protocol events, including details like source/destination IPs, methods (GET/POST), URLs, headers, and response codes.

<p align="center">
  <img src="images/splunk-cyber-kill-chain-investigation-14.png?raw=true&v=2" width="45%">
  <img src="images/splunk-cyber-kill-chain-investigation-15.png?raw=true&v=2" width="45%">
  <br>
  <sub>Figure 14 (left) & Figure 15 (right)</sub>
</p>

_<b>Third query (Step 1)</b>_ 

Was used to identify which IP addresses sent POST requests to the web server and counted how many requests each one made.

```spl
index=botsv1
sourcetype=stream:http
dest_ip="192.168.250.70"
http_method=POST
```

- **dest_ip="192.168.250.70"** – Specifies the web server. Helps focus on attacker traffic targeting the web server.  
- **sourcetype=stream:http** - Specifically records HTTP protocol events, including details like source/destination IPs, methods (GET/POST), URLs, headers, and response codes.
- **http_method=POST** - Narrowed the scope to HTTP POST requests directed specifically to the web server’s IP address.

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-16.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 16</em>
</p>

<h4>(Step 2) After identifying that the target web server uses the Joomla CMS, I wanted to check if anyone tried accessing the admin login page. Admin pages are important to monitor because attackers often try to reach them first when attempting to log in or exploit a site. I began by running two Splunk queries</h4>

<blockquote>
Through a quick online search, I learned that Joomla’s admin login page is usually found at: `/joomla/administrator/index.php`. 
</blockquote>

- <b>First query:</b> Immediately noticed after inspecting the `form_data` field that there were multiple login attempts to `/joomla/administrator/index.php`. The field `form_data` contained the requests sent through the form on the admin panel page, which has a login page.
- <b>Second query:</b> Used to create a table containing important fields such as destination ip (`dest_ip`), HTTP method (`http_method`), URI (`uri`), and form data (`form_data`), and eventually IP `23.22.63.114` was trying to guess the password by brute-forcing and attempting numerous passwords.

<blockquote>
Below are more details about each query and the corresponding findings.
</blockquote>

_<b>First query (Step 2)</b>_ 

Used to identify traffic coming into this URI (`/joomla/administrator/index.php`). 

```spl
index=botsv1
imreallynotbatman.com
sourcetype=stream:http
dest_ip="192.168.250.70"
uri="/joomla/administrator/index.php"
```

- **imreallynotbatman** - Matches the domain name in the event data (like in the HTTP host header). This ensured I was only pulling events related to that specific website, especially if the same web server hosts multiple domains.
- **dest_ip="192.168.250.70"** – Specifies the web server. Helps focus on attacker traffic targeting the web server's IP address at the network level. Ensured I was only capturing traffic sent to the actual web server, regardless of what hostname or alias was used in the request.
- **sourcetype=stream:http** - Specifically records HTTP protocol events, including details like source/destination IPs, methods (GET/POST), URLs, headers, and response codes.
- **uri="/joomla/administrator/index.php"** - Specifies the URI path being requested. In this case, it filters for requests targeting Joomla’s admin login page, which is a common location attackers probe when trying to gain access.

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-17.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 17</em>
</p>

_<b>Second query (Step 2)</b>_

Was used to create a table containing important fields such as destination ip (`dest_ip`), HTTP method (`http_method`), URI (`uri`), and form data (`form_data`), and eventually extract the username and password credentials attempted using `form_data`. 

```spl
index=botsv1
imreallynotbatman.com
sourcetype=stream:http
dest_ip="192.168.250.70"
uri="/joomla/administrator/index.php"
| table _time uri src_ip dest_ip form_data
```

- **imreallynotbatman** - Matches the domain name in the event data (like in the HTTP host header). This ensured I was only pulling events related to that specific website, especially if the same web server hosts multiple domains.
- **sourcetype=stream:http** - Specifically records HTTP protocol events, including details like source/destination IPs, methods (GET/POST), URLs, headers, and response codes.
- **dest_ip="192.168.250.70"** – Specifies the web server. Helps focus on attacker traffic targeting the web server's IP address at the network level. Ensured I was only capturing traffic sent to the actual web server, regardless of what hostname or alias was used in the request.
- **uri="/joomla/administrator/index.php" - Specifies the URI path being requested. In this case, it filters for requests targeting Joomla’s admin login page, which is a common location attackers probe when trying to gain access.
- **table _time uri src_ip dest_ip form_data** - Took all results from my search and displayed only the specific fields I cared about in a easy-to-read table.

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-18.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 18</em>
</p>

<blockquote>
Inspecting the `form_data` field revealed multiple login attempts to `/joomla/administrator/index.php` from IP `23.22.63.114`.
</blockquote>

<blockquote>
<strong>Note:</strong> To further narrow down my results, I could add a specific source IP to the query, such as src_ip="40.80.148.42". This would limit the search to only show HTTP requests sent from that particular client. Filtering by source IP helps identify which system initiated the traffic, making it easier to trace suspicious behavior or confirm repeated login attempts from the same host. This kind of filter is especially useful when analyzing targeted activity against the Joomla admin login page.
</blockquote>

<h4>(Step 3) After confirming that most traffic to "/joomla/administrator/index.php" (Joomla's admin login page) were POST requests (mostly from `40.80.148.42`, with some from `23.22.63.114`), I wanted to extract the submitted form fields to see the username and password values those POST attempts used.</h4>

Previously, after inspecting the `form_data` field and confirmed multiple login attempts to `/joomla/administrator/index.php`, I used regex to extract only the username (`username`) and password (`passwd`) fields:

```spl
index=botsv1
sourcetype=stream:http
dest_ip="192.168.250.70"
http_method=POST
uri="/joomla/administrator/index.php"
form_data=*username*passwd*
| table _time uri src_ip dest_ip form_data
```

- **sourcetype=stream:http** - Filters to HTTP events captured by Splunk Stream (application-layer HTTP requests and related fields).
- **dest_ip="192.168.250.70"** – Specifies destination IP which only returns events whose destination IP is the web server.
- **http_method=POST** - Keeps only HTTP POST requests (commonly used for form submissions, like login attempts).
- **uri="/joomla/administrator/index.php"** - Specifies the URI path being requested. In this case, it filters for requests targeting Joomla’s admin login page, which is a common location attackers probe when trying to gain access.
- **form_data=*username*passwd*** - Wildcard match intended to find events where the `form_data` field contains the fields `username` and `passwd`.
- **table _time uri src_ip dest_ip form_data** - Took all results from my search and displayed only the specific fields I cared about in a easy-to-read table.

<blockquote>
<strong>Note:</strong> I filtered HTTP POST traffic to `dest_ip=192.168.250.70` and the Joomla admin URI `/joomla/administrator/index.php` to find login attempts. I used the server IP rather than the domain because the IP reliably captures all traffic to that machine in this lab environment; adding the domain would only be necessary if the server hosted multiple sites and I needed to confirm the virtual host. I then displayed "form_data" to inspect submitted "username" and "passwd" values.
</blockquote>

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-19.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 19</em>
</p>

<h4>(Step 4) After extracting the submitted form fields to see the username and password values those POST attempts used, I ran two Splunk queries utilizing regular expressions.</h4>
  
- **The first query** was to extract all password found in the `passwd` field.
- **The second query** was used identify whether credential submissions came from normal browsers or from automated tools/scripts; patterns in user-agents help distinguish human traffic from likely scanning or brute-force activity.

<blockquote>
Below are more details about each query and the corresponding findings.
</blockquote>

_<b>First query (Step 4)</b>_

Used to extract all password found in the `passwd` field.

```spl
index=botsv1
sourcetype=stream:http
dest_ip="192.168.250.70"
http_method=POST
form_data=*username*passwd*
| rex field=form_data "passwd=(?<creds>\w+)"
| table src_ip creds
```

- **sourcetype=stream:http** - Filters to HTTP events captured by Splunk Stream (application-layer HTTP requests and related fields).
- **dest_ip="192.168.250.70"** – Specifies destination IP which only returns events whose destination IP is the web server.
- **http_method=POST** - Keeps only HTTP POST requests (commonly used for form submissions, like login attempts).
- **form_data=*username*passwd*** - Wildcard match intended to find events where the `form_data` field contains the fields `username` and `passwd`.
- **| rex field=form_data "passwd=(?<creds>\w+)"** — extract the password value into a new field called `creds`.
    - **?<creds>** — name for the capture. In Splunk rex, that becomes the field name `creds`
    - **\w** — a character class that matches any “word” character: letters (A–Z, a–z), digits (0–9), and underscore (_)
    - **+** — a quantifier meaning “one or more” of the previous token
    - Together: **(?<creds>\w+)** captures one or more word characters and stores them in the field `creds`
- **| table src_ip creds** - Show a simple table with the client IP and the extracted password.

<blockquote>
<strong>Note:</strong>I removed the uri filter (uri="/joomla/administrator/index.php") filter to capture any HTTP POSTs to `192.168.250.70` that included login fields, since credential submissions can occur at multiple or inconsistent paths and the uri field is not always present in every event. The query then uses a rex to extract the "passwd" value into "creds" and shows the source IP and password attempts.
</blockquote>

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-20.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 20</em>
</p>

_<b>Second query (Step 4)</b>_ 

I ran this query to identify whether credential submissions came from normal browsers or from automated tools/scripts. Patterns in "user-agents" helped distinguish human traffic from likely scanning or brute-force activity.

This query finds POSTs to the server that look like login attempts, pulls out the password token into `creds`, and shows when they happened (`_time`), who sent them (`src_ip`), what `URI` was requested, and which client/tool (`user_agent`) made the request.

```spl
index=botsv1
sourcetype=stream:http
dest_ip="192.168.250.70"
http_method=POST
form_data=*username*passwd*
| rex field=form_data "passwd=(?<creds>\w+)"
| table _time src_ip uri http_user_agent creds
```

- **sourcetype=stream:http** - Filters to HTTP events captured by Splunk Stream (application-layer HTTP requests and related fields).
- **dest_ip="192.168.250.70"** – Specifies destination IP which only returns events whose destination IP is the web server.
- **http_method=POST** - Keeps only HTTP POST requests (commonly used for form submissions, like login attempts).
- **form_data=*username*passwd*** - Wildcard match intended to find events where the `form_data` field contains the fields `username` and `passwd`.
- **| rex field=form_data "passwd=(?<creds>\w+)"** — extract the password value into a new field called `creds`.
    - **?<creds>** — name for the capture. In Splunk rex, that becomes the field name `creds`
    - **\w** — a character class that matches any “word” character: letters (A–Z, a–z), digits (0–9), and underscore (_)
    - **+** — a quantifier meaning “one or more” of the previous token
    - Together: **(?<creds>\w+)** captures one or more word characters and stores them in the field `creds`
- **| table _time src_ip uri http_user_agent creds** - Shows a table that outputs as a table showing:
    - **_time** = when the request happened
    - **src_ip** = client IP that made the request
    - **uri** = requested path (even though you didn’t filter on it here)
    - **http_user_agent** = the browser or tool used
    - **creds** = the extracted password value

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-21.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 21</em>
</p>

This result clearly shows a continuous brute-force attack attempt from an IP `23.22.63.114` using what appears to be a python script. 1 login attempt from IP `40.80.148.42` using the Mozilla browser. The successful credentials were `admin : batman`, originating from `40.80.148.42`.

<blockquote>
<strong>Note:</strong> I updated the extraction to create separate fields (`username` and `passwd`) using rex, [^&\s]+ and urldecode(), so both submitted credentials appear in the table (preventing one extraction from overwriting the other).
</blockquote>

```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST form_data=*username*passwd*
| rex field=form_data "passwd=(?<password>[^&\s]+)"
| rex field=form_data "username=(?<username>[^&\s]+)"
| eval username = urldecode(username), password = urldecode(password)
| table _time src_ip uri http_user_agent username password
```

- **password** and **username** are separate fields - Gives each reg a different name so one doesn’t overwrite the other; I end up with two columns (username, password) instead of one mixed-up creds.
- **[^&\s]+** - Basically means “grab everything until the next & or space,” so it captures special characters and the full value (e.g., passwd=p@ss! → p@ss!) instead of stopping at non-word chars.
- **urldecode()** converts URL-encoded characters to normal text (e.g., %40 → @, + → space), so I could read the actual username/password instead of gibberish.

### Findings / Analysis

- Evidence confirmed a brute‑force attack followed by successful authentication. `23.22.63.114` performed failed attempts while `40.80.148.42` achieved login success.
- Analysis of the `botsv1` logs shows a coordinated scanning and credential-attack against the Joomla admin endpoint (`/joomla/administrator/index.php`) on `192.168.250.70`.
- Two hostile IPs were prominent: `40.80.148.42` (the source of the majority of requests and broader Acunetix-style scanning) and `23.22.63.114` (which generated numerous repeated POSTs consistent with brute-force attempts).
- By extracting `form_data` with rex I recovered submitted credentials and found that most attempts from `23.22.63.114` failed, while `40.80.148.42` achieved a successful login using `admin:batman`.
- `User-agent`  further differentiated the traffic which was automated/scripted agents for the brute-force activity versus a browser-like agent for the successful login—so the activity aligns with scanning followed by credential compromise (ATT&CK T1110).

### What I Learned
This task taught me how to use Splunk dto detect web-based brute-force and credential attacks through HTTP method filtering and field extraction. It emphasized the value of regex for pulling data points from raw logs and how statistics commands summarize large volumes eddiciently. From a SOC perspective, this correlated to MITRO ATT&CK T1110 (Brute Force) and Security Domain 3.2 (Analyze Indicators of Compromise).

</details>

---

## Objective 3 – Installation Phase</br>

<details>

<summary><b>(Click to expand)</b></summary>

### Overview
The objective of this task was to now verify whether the attacker successfully installed or executed any malicious payloads following exploitation. In the Cyber Kill Chain, **Installation** represents the stage where adversaries establish persistence within a target environment, typically by deploying malware or backdoors. 

I ran 3 Splunk queries to achieve this:

  - <b>First query:</b> I ran this query to search for evidence of file uploads to the compromised host (web server) with the IP `192.168.250.70`.
  - <b>Second query:</b> Saw that `40.80.148.42`, `23.22.63.114`, and `192.168.2.50` have all made HTTP requests to the web server by looking into the `src_ip` field (Figure 14). Looking into the `http_method` field, I saw that most of the HTTP traffic observed consisted of POST requests directed at the web server (see Figure 15).
  - <b>Third query:</b> Confirmed that both `40.80.148.42` and `23.22.63.114` sent POST requests to the web server, with the majority originating from `40.80.148.42` (see Figure 16).

<blockquote>
Below are more details about each query and the corresponding findings.
</blockquote>

### Step‑by‑Step Walkthrough

<h4>(Step 1) After confirming successful authentication from the prior phase (`40.80.148.42` achieved a successful login using `admin:batman`), I searched for evidence of file uploads to the compromised host using the first query</h4>

```spl
index=botsv1
sourcetype=stream:http
dest_ip="192.168.250.70" *.exe
```
- **index=botsv1** – Targets the dataset containing simulated incident logs. Ensured only relevant Splunk BOTSv1 data is queried.  
- **sourcetype=stream:http** – Filters events to HTTP network traffic. Malware is often delivered via HTTP uploads.  
- **dest_ip="192.168.250.70"** – Specifies the compromised web server. Focuses on inbound traffic directed at the victim.  
- **.exe** – Keyword search for executable files. This detects potential binary uploads used to install persistence agents.

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-22.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 22</em>
</p>

I examined the `part_filename{}` field in Splunk to identify any files transferred over the network during the activity. The results displayed two filenames: `3791.exe` and `agent.php`, which appear to be executable files in HTTP traffic that were either downloaded or executed on the web server.

<h4>(Step 2) I had to confirm if any of these files came from the IP addresses that were found to be associated in objective 2</h4>

- `40.80.148.42`,
- `23.22.63.114`, or
- `192.168.2.50`

I ran the following search query to find out if `3791.exe` came from any of the the IP addresses in question:

```spl
index=botsv1
sourcetype=stream:http
dest_ip="192.168.250.70"
"part_filename{}"="3791.exe"
```
- **index=botsv1** - Searches within the `botsv1` dataset (the index containing all related logs).
- **sourcetype=stream:http** - Filters results to only include HTTP traffic logs captured by the Stream app.
- **dest_ip="192.168.250.70"** - Limits results to web traffic where the destination IP is the target web server `192.168.250.70` which the compromised web server.
- **"part_filename{}"="3791.exe"** - Finds HTTP events that reference or transfer the executable named `3791.exe` found from the previous query (potentially a malicious executable).

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-23.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 23</em>
</p>

I checked the `c_ip` (client IP address) field to see which host on the network requested or downloaded `3791.exe`. This allowed me to trace the origin of the activity within the environment. They were uploaded by the attacker IP `40.80.148.42`.

<blockquote>
Both "src_ip" and "c_ip" confirms the IP that started any process, but "c_ip" is application-focused (the client in a session), while "src_ip" is network-focused (the raw source of the packet).
</blockquote>

<blockquote>
I reviewed the "c_ip" field to identify which host initiated the HTTP request for `3791.exe`. Since the data came from the `stream:http` sourcetype, it records application-level traffic using client/server roles, so the "c_ip" field shows the requesting client, while "src_ip" isn’t present in this type of log.
</blockquote>

<h4>(Step 3) Now, I needed to confirm whether the file, `3791.exe`, was executed</h4>

I ran the query `index=botsv1 "3791.exe"`, which returned 76 events distributed across multiple sourcetypes, with the majority (about 91%) coming from `XmlWinEventLog`, followed by a few from `WinEventLog`, `stream:http`, `fortigate_utm`, and `suricata`. 

This distribution shows that most of the activity involving `3791.exe` was captured through host-based Windows event logging, specifically Sysmon. While a small number of the remaining events originated from network and security monitoring sources. 

- The `XmlWinEventLog` entries indicates that the file was executed or interacted with at the endpoint level
- And its presence in `stream:http` suggests it may have been downloaded or transferred via HTTP traffic.

Overall, this correlation between host and network data points to a potential infection vector where `3791.exe` was delivered over the network and then executed on the host system.

<blockquote>
I ran this specific query to trace the presence and activity of a suspicious file (`3791.exe`) across multiple log sources.
</blockquote>

<blockquote>
It’s called out as Sysmon because the `XmlWinEventLog` entries come from the Sysmon Operational log, which records detailed host-based activity. It's basically showing that `3791.exe` wasn’t just downloaded, but also ran on the endpoint.
</blockquote>

```spl
index=botsv1
"3791.exe"
```
- **"3791.exe"** – Search term for the suspected malware. This validates that the payload was run after upload.

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-24.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 24</em>
</p>

<h4>(Step 4) After confirming traces of the executable `3791.exe` were identified in multiple sources including `Sysmon`, `WinEventLog`, and `Fortigate_UTM`, I needed to determine whether the file was executed on the host. Sysmon data was examined because the majority (about 91%) of the executable's presence was coming from `XmlWinEventLog`</h4>

<blockquote>
Sysmon provides detailed system-level monitoring of process activity. In particular, **Event ID 1 (Process Creation)** logs evidence of newly started processes and includes valuable fields like ProcessGUID, command line arguments, and file hashes. Leveraging this event type allows me to confirm and gather evidence of if `3791.exe` was executed on the system and when it was executed.
<strong>Reference:</strong> https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
</blockquote>

```spl
index=botsv1
"3791.exe"
sourcetype="XmlWinEventLog"
EventCode=1
```
- **sourcetype=XmlWinEventLog** – Targets Windows event logs forwarded to Splunk. Sysmon records detailed process events.  
- **"3791.exe"** – Search term for the suspected malware. Validates that the payload was run after upload.
- **EventCode=1** – Filters for process creation events. Event ID 1 confirms the execution of a binary.

<blockquote>
This query will look for the process creation logs containing the term `3791.exe` in the logs.
</blockquote>

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-25.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 25</em>
</p>

I examined the `CommandLine` field to verify how `3791.exe` was executed on the host system. This field shows the exact command used to launch a process. Checking it provided clear evidence that the executable was actually run, which is crucial for understanding attacker behavior and intent.

When examining the `CommandLine` field for `3791.exe`, I clicked the entry itself, which automatically updated my query to `index=botsv1 "3791.exe" sourcetype="XmlWinEventLog" EventCode=1 CommandLine="3791.exe"`. I then focused on this specific process within the `Hashes` field to isolate its hash details and successfully retrieved the MD5 hash of the executable, confirming its integrity and providing evidence of its execution on the host.

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-26.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 26</em>
</p>


### Findings / Analysis
Results confirmed that `3791.exe` executed shortly after upload. This demonstrated the attacker successfully transitioned from exploitation to persistence. The malicious file likely connected to an external server to receive commands or send data.

I also examined the `user` and `user_id` fields within the event to identify which account executed the `3791.exe` process, allowing me to tie the activity to a specific user on the system. These fields are valuable for determining who initiated the execution and whether it was done under an administrative or standard user context. 

To gather additional intelligence, I submitted the retrieved hash value of the executable to VirusTotal, a malware analysis platform that aggregates results from multiple antivirus engines. This provided further details on the file’s reputation, detection rate, and potential malicious behavior across other security databases.

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-27.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 27</em>
</p>

### What I Learned
I learned how to validate malware execution through cross‑referencing network and endpoint data sources in Splunk. Sysmon Event ID 1 is a reliable indicator for process creation and should almost always be monitored in production environments using detection rules aligned with **MITRE ATT&CK T1059 (Command and Scripting Interpreter)**. This phase also illustrates **Security+ Domain 2.2 (Analyze Indicators of Malware)** and connected to the *Eradication** phase of the NIST Incident Response Lifecycle.

</details>

---

## Objective 4 – Action on Objectives Phase</br>

<details>

<summary><b>(Click to expand)</b></summary>

### Overview
The goal of this phase was to determine how the malicious actor defaced the company’s public website, which is a clear indicator of the **Actions on Objectives** stage of the Cyber Kill Chain.

### Step‑by‑Step Walkthrough

<h4>(Step 1): I first examined inbound traffic to the defaced website at IP `192.168.250.70`.</h4>

To do so, I ran the following query to analyze inbound network traffic targeting the web server at IP `192.168.250.70` and looked at the `src_ip` field:

```spl
index=botsv1
dest=192.168.250.70
sourcetype=suricata
```
- **dest=192.168.250.70** – Specifies the infected host as the source. Identifies outgoing traffic from the compromised system.  
- **sourcetype=suricata** – Filters for network IDS alerts. Detects anomalous connections or file transfers to external domains.

<blockquote>
This query looks at inbound network traffic going to the web server 192.168.250.70 using Suricata IDS logs from the botsv1 dataset. Unlike http logs that show normal web requests, Suricata captures all network activity, including scans or attack attempts. This helps spot suspicious or malicious traffic before it reaches the server. It gives a clear picture of what kind of threats were targeting the Joomla web server.
</blockquote>

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-28.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 28</em>
</p>

This was unusual as the logs did not show any external IP communicating with the server.

<h4>(Step 2) Because there were no external IP communicating with the server, I reversed the flow so that 192.168.250.70 was the source. I wanted to see if any outbound traffic originated from the server instead.</h4>

To do so, I ran the following query to analyze outbound network traffic from the web server at IP `192.168.250.70`, then looked at the `dest_ip` field:

```spl
index=botsv1
dest=192.168.250.70
sourcetype=suricata
```
- **src=192.168.250.70** – Specifies the infected host as the source. Identifies outgoing traffic from the compromised system.  
- **sourcetype=suricata** – Filters for network IDS alerts. *Why:* Detects anomalous connections or file transfers to external domains.

<blockquote></blockquote>
This query revealed outbound requests to `prankglassinebracket.jumpingcrab.com` transferring a file named `poisonivy-is-coming-for-you-batman.jpeg`. This image replaced the homepage, which confirmed defacement.
</blockquote>

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-29.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 29</em>
</p>

What was interesting about this output is that web servers don't usually originate traffic. The browser or client would originate the traffic as the source and the server would be the destination. I noticed immediately that the web server initiated large traffic to `40.80.148.42`, `22.23.63.114`, and `192.168.250.40`. 

<h4>(Step 3) I checked Suricata logs for the top three destination IPs and found evidence of defacement from `192.168.250.40`</h4>

I found evidence from `192.168.250.70` by running the following query, then looking into the `url` field:

```spl
index=botsv1
src=192.168.250.70
sourcetype=suricata
dest_ip=23.22.63.114
```

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-30.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 30</em>
</p>

<blockquote>
That query filters Suricata logs to show outbound network traffic from the web server (192.168.250.70) to the external IP (23.22.63.114). Checking the url field let me see what specific web resource or endpoint the server tried to access.
</blockquote>

The `url` field showed 2 PHP files and a JPEG file. The JPEG file looked interesting, so I investigated more into it.

<h4>(Step 4) I wanted to investigate the JPEG file and created a table to get a hollistic view</h4>

To do so, I ran the following query:

```spl
index=botsv1
url="/poisonivy-is-coming-for-you-batman.jpeg"
dest_ip="192.168.250.70"
| table _time src dest_ip http.hostname url
```

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-31.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 31</em>
</p>

<blockquote>
The investigation revealed that the file `poisonivy-is-coming-for-you-batman.jpeg` was fetched by the compromised web server from the external host `prankglassinebracket.jumpingcrab.com`. No inbound traffic from an attacker IP was observed because the web server itself (or visitors’ browsers) initiated the outbound connection after its content had already been modified. 
</blockquote>

<h4>(Step 5) To deepen my investigaton, I used a query to review firewall logs for traffic sent from the web server to 23.22.63.114</h4>

To do so, I checked Fortigate UTM data to help determine whether this outbound connection was permitted, blocked, or flagged as suspicious, which gave more insight into the server’s network behavior and possible compromise indicators. I searched for the top three external IPs that showed when I searched outbound traffic from the webserver: `40.80.148.42`, `22.23.63.114`, and `192.168.250.40`. I found an SQL injection attempt  from `40.80.148.42` by looking at the `signature` field.

```spl
index=botsv1
src=192.168.250.70
sourcetype=fortigate_utm
```

<p align="left">
  <img src="images/splunk-cyber-kill-chain-investigation-32.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 32</em>
</p>

### Findings / Analysis
The attacker’s intent was to publicly deface the website to demonstrate control. Outbound IDS alerts and web traffic correlation validated data exfiltration and modification activities. This phase provided a clear end goal of the instrusion.

The investigation revealed that the file `poisonivy-is-coming-for-you-batman.jpeg` was fetched by the compromised web server from the external host `prankglassinebracket.jumpingcrab.com`. No inbound traffic from an attacker IP was observed because the web server itself (or visitors’ browsers) initiated the outbound connection after its content had already been modified. 

This suggests the attacker had previously injected malicious code or edited a template so the page automatically requested the external image, essentially causing the victim server to pull the defacement file rather than the attacker pushing it. The absence of any new inbound IP suggests that the initial compromise occurred earlier through another vector such as CMS credential abuse, a vulnerable plugin, or a prior file upload.

To understand how that could happen, I looked at how different log sources work together. Each type of log provides a different view of what happened:

| Log Layer | Description | Purpose |
|------------|--------------|----------|
| **Application-level** | Logs from the website or CMS, such as Apache access logs or web app errors. | Show requests made by the web server, changes to web pages, or injected content. |
| **System / OS-level** | Logs from the operating system like `/var/log/auth.log` or command history. | Reveal who logged in, what commands were run, or when files were changed. |
| **Network-level** | Logs from firewalls, proxies, or DNS resolvers. | Show outbound connections or lookups to suspicious domains. |
| **Host / Endpoint** | Logs from security tools or local monitoring (e.g., Sysmon, EDR). | Show which process downloaded or executed a file. |

Looking at logs from multiple layers helps connect the dots. Web logs show the symptom (the server fetched the image), while system and network logs could show how that happened or when the compromise began. This demonstrates why analysts use data from many sources — each layer reveals part of the full story.

Recommended next steps:
1. Review outbound firewall, proxy, or VPC flow logs for connections to `prankglassinebracket.jumpingcrab.com` or its resolved IPs to confirm the egress source and timing.
2. Inspect webroot and CMS directories for recently modified files referencing that domain or image name, and compare inode timestamps to identify when the injection occurred.
3. Examine web application and admin audit logs for suspicious POSTs, file uploads, or unauthorized logins around the same period.
4. Search system and process telemetry (bash history, scheduled tasks, PHP error logs) for any curl, wget, or remote-file-inclusion activity.
5. Capture or review DNS resolver logs to validate that the server resolved the attacker’s domain.
6. Correlate findings to determine whether the defacement was client-side (browser image include) or server-side (server-executed fetch), then document remediation steps such as file restoration, credential rotation, and patching the exploited entry point.

### What I Learned
This task taught me how to trace adversary objectives using Splunk by following the attack from reconnaissance to impact. Understanding “Actions on Objectives” is vital for incident classification and damage assessment within a SOC. The technique relates to **MITRE ATT&CK T1491 (Defacement)** and NIST’s **Recovery Phase** of incident handling. Documenting such activity supports executive reporting and post‑incident remediation plans.

</details>

---

## Objective 5 – Command and Control (C2) Phase</br>

<details>

<summary><b>(Click to expand)</b></summary>

### Overview
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

</details>

---

## Objective 6 – Weaponization Phase</br>

<details>

<summary><b>(Click to expand)</b></summary>

### Overview
The objective was to analyze how the attacker prepared and delivered their payloads by pivoting on known indicators through OSINT tools. In the Cyber Kill Chain, Weaponization covers the creation of malware and exploitation packages used later in Delivery.

### Step‑by‑Step Walkthrough
I conducted open‑source lookups on the malicious domain and associated infrastructure using external intelligence sources (VirusTotal, Robtex, and Whois). These lookups linked `jumpingcrab.com` to an email address `lillian.rose@po1son1vy.com`, indicating possible threat‑actor attribution.

📸 **Screenshot Placeholder:** VirusTotal graph view showing domain relationships.

### Findings / Analysis
The domain was associated with multiple subdomains and related IP addresses used in previous campaigns. This confirmed the attacker leveraged pre‑existing malware infrastructure to deliver payloads, a common APT pattern.

### What I Learned
Weaponization is rarely observable in internal logs, but threat intelligence correlation can expose it indirectly. I learned how OSINT enriches SIEM data and helps analysts build context beyond raw events. This relates to **MITRE ATT&CK T1587 (Develop Capabilities)** and **Security+ Domain 1.4 (Explain threat actors and attributes)**.

</details>

---

## Objective 7 – Delivery Phase</br>

<details>

<summary><b>(Click to expand)</b></summary>

### Overview
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

</details>

---

## Conclusion and Lessons Learned</br>

<details>

<summary><b>(Click to expand)</b></summary>

### Overview
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

</details>

---


