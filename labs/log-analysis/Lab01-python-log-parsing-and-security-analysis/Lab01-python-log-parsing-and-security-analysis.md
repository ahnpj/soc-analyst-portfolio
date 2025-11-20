# Python Log Parsing Mini-Lab Report
Author: Peter Ahn  
Environment: Google Cloud Shell (Browser-Based Linux VM)

## Overview
I wanted to run hands-on log parsing labs in a live Linux environment without installing anything locally. Using Google Cloud Shell’s built‑in Linux VM, I created several logs (Apache, SSH auth logs, Windows EventLog CSV, and AWS CloudTrail JSON) and wrote Python scripts to parse each one.

My goals:
- Understand different log formats  
- Practice regex, CSV, and JSON parsing  
- Identify anomalies like web scanning, SSH brute force, failed Windows logons, and risky IAM actions  
- Build clear, screenshot-friendly labs for my GitHub portfolio

This report includes code, explanations, and what I learned from each lab.

---

# Lab 1 — Apache Logs: Detecting Web Scanning Activity </br>

<details>

<summary><b>(Click to expand)</b></summary>

## Objective
Simulate web attack enumeration (404 spikes, admin path scans) and write a Python parser to detect suspicious IPs.

## Creating the Apache Log
```bash
cat << 'EOF' > apache_access.log
127.0.0.1 - - [20/Nov/2025:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"
203.0.113.10 - - [20/Nov/2025:10:01:10 +0000] "GET /wp-login.php HTTP/1.1" 404 256 "-" "Mozilla/5.0"
203.0.113.10 - - [20/Nov/2025:10:01:12 +0000] "GET /admin HTTP/1.1" 404 256 "-" "Mozilla/5.0"
203.0.113.10 - - [20/Nov/2025:10:01:14 +0000] "GET /phpmyadmin HTTP/1.1" 404 256 "-" "Mozilla/5.0"
198.51.100.5 - - [20/Nov/2025:10:02:00 +0000] "GET /login HTTP/1.1" 200 512 "-" "Mozilla/5.0"
EOF
```

## Python Parser (parser_apache.py)
```python
import re
from collections import Counter

log_file = "apache_access.log"
ip_pattern = re.compile(r"(\d{1,3}\.){3}\d{1,3}")

ips = []
errors_404 = {}

with open(log_file) as f:
    for line in f:
        m = ip_pattern.search(line)
        if not m:
            continue

        ip = m.group()
        ips.append(ip)

        if " 404 " in line:
            errors_404[ip] = errors_404.get(ip, 0) + 1

print("Top IPs by request count:")
for ip, count in Counter(ips).most_common():
    print(f"{ip}: {count} requests")

print("\nIPs with 404s (possible scanning):")
for ip, count in errors_404.items():
    print(f"{ip}: {count} x 404")
```

## Findings
- IP **203.0.113.10** repeatedly attempted invalid admin paths.
- Multiple 404 errors indicate enumeration/scanning behavior.
- Regex-based extraction made parsing extremely simple.

## What I Learned
Apache logs follow predictable patterns. Even small logs reveal attacker behavior clearly when analyzed with basic Python tools.

</details>

---

# Lab 2 — SSH Auth Logs: Identifying Brute-Force Attempts </br>

<details>

<summary><b>(Click to expand)</b></summary>

## Objective
Detect repeated failed SSH login attempts, which mimic brute-force attacks.

## Creating the Auth Log
```bash
cat << 'EOF' > auth.log
Nov 20 10:10:01 server sshd[1001]: Failed password for invalid user admin from 203.0.113.50 port 54321 ssh2
Nov 20 10:10:03 server sshd[1001]: Failed password for invalid user admin from 203.0.113.50 port 54322 ssh2
Nov 20 10:10:05 server sshd[1001]: Failed password for invalid user root from 203.0.113.50 port 54323 ssh2
Nov 20 10:11:00 server sshd[1002]: Accepted password for peter from 198.51.100.77 port 50000 ssh2
EOF
```

## Python Parser (parser_auth.py)
```python
import re
from collections import Counter

log_file = "auth.log"
fail_pattern = re.compile(r"Failed password .* from (\d{1,3}(?:\.\d{1,3}){3})")

fail_ips = []

with open(log_file) as f:
    for line in f:
        m = fail_pattern.search(line)
        if m:
            fail_ips.append(m.group(1))

print("Failed SSH logins by IP:")
for ip, count in Counter(fail_ips).most_common():
    print(f"{ip}: {count} failed attempts")
```

## Findings
- The attacker IP **203.0.113.50** attempted 3 logins across 2 fake users (admin & root).
- Perfect small-scale example of SSH brute force.

## What I Learned
Auth logs are verbose but uniform. Regex makes parsing attacker IPs straightforward.

</details>

---

# Lab 3 — Windows Event Logs (CSV): Tracking Failed Logons </br>

<details>

<summary><b>(Click to expand)</b></summary>

## Objective
Identify repeated Event ID **4625** (Failed Logon) across users and IPs.

## Creating the Windows Event CSV
```bash
cat << 'EOF' > windows_events.csv
EventID,AccountName,IpAddress,Status
4625,admin,203.0.113.80,FAILURE
4625,admin,203.0.113.80,FAILURE
4625,testuser,198.51.100.10,FAILURE
4624,peter,10.0.0.5,SUCCESS
EOF
```

## Python Parser (parser_windows.py)
```python
import csv
from collections import Counter

fail_counts = Counter()

with open("windows_events.csv") as f:
    reader = csv.DictReader(f)
    for row in reader:
        if row["EventID"] == "4625":
            key = (row["AccountName"], row["IpAddress"])
            fail_counts[key] += 1

print("Windows 4625 failed logons:")
for (user, ip), count in fail_counts.most_common():
    print(f"{user} from {ip}: {count} failures")
```

## Findings
- admin from **203.0.113.80** had multiple failures.
- CSV-based logs are extremely easy to parse compared to raw EVTX.

## What I Learned
Windows logs become manageable when exported to CSV and filtered by Event ID.

</details>

---

# Lab 4 — CloudTrail Logs (JSON): Detecting IAM Abuse </br>

<details>

<summary><b>(Click to expand)</b></summary>



## Objective
Parse AWS CloudTrail logs for suspicious IAM actions like policy changes or trail deletion.

## Creating the CloudTrail JSON
```bash
cat << 'EOF' > cloudtrail.json
[
  {
    "eventName": "AttachUserPolicy",
    "userIdentity": { "userName": "alice" },
    "sourceIPAddress": "203.0.113.90"
  },
  {
    "eventName": "ListBuckets",
    "userIdentity": { "userName": "alice" },
    "sourceIPAddress": "203.0.113.90"
  },
  {
    "eventName": "DeleteTrail",
    "userIdentity": { "userName": "bob" },
    "sourceIPAddress": "198.51.100.200"
  }
]
EOF
```

## Python Parser (parser_cloudtrail.py)
```python
import json
from collections import defaultdict

with open("cloudtrail.json") as f:
    events = json.load(f)

actions_by_user = defaultdict(list)
risky = {"AttachUserPolicy", "DeleteTrail", "PutUserPolicy"}

for e in events:
    user = e.get("userIdentity", {}).get("userName", "UNKNOWN")
    actions_by_user[user].append(e["eventName"])

print("CloudTrail actions by user:")
for user, actions in actions_by_user.items():
    print(f"{user}: {', '.join(actions)}")

print("\nPotentially risky actions:")
for e in events:
    if e["eventName"] in risky:
        user = e.get("userIdentity", {}).get("userName", "UNKNOWN")
        print(f"{user} did {e['eventName']} from {e['sourceIPAddress']}")
```

## Findings
- alice performed a privileged action: **AttachUserPolicy**
- bob executed **DeleteTrail**, which is highly suspicious.

## What I Learned
CloudTrail JSON parsing is simple in Python and quickly reveals dangerous IAM behavior.

</details>

---


# Final Takeaways </br>

<details>

<summary><b>(Click to expand)</b></summary>

Across all four labs, I practiced:
- Parsing log formats (text, CSV, JSON)
- Using regex for pattern matching
- Identifying anomalies (404 spikes, SSH brute force, Windows failed logons, IAM risky actions)
- Running everything inside a clean browser-based Linux VM

These labs replicate real SOC analyst workflows and give me strong beginner-friendly material for my GitHub portfolio.

</details>
