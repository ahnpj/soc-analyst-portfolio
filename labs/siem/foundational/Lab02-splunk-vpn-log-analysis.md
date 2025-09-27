# Lab 02 – Splunk VPN Log Analysis

## Overview
This lab analyzes VPN logs in Splunk to surface behaviors a SOC analyst cares about: remote access volume, who is most active, where connections originate, and whether there are stability or misuse indicators.  
Events live in **`index="main"`** and are **JSON-formatted**, so I use **`spath`** to extract fields (like `UserName`, `Source_ip`, `Source_Country`, `source_state`, `protocol`, `port`, `action`) before aggregating with `stats`.

---

## Goals
- Build baselines: activity by **action**, **user**, **country**, and **state**.  
- Narrow to distinct slices (e.g., **tcp/443 teardowns**) to drive different event counts and investigative pivots.  
- Produce results that are immediately useful for triage and reporting.

---

## Dataset & Commands (what they are and why I use them)
- **Index**: `index="main"` → The logical bucket that stores these VPN events. If you search the wrong index, you’ll return 0 results.  
- **`spath`** → Parses JSON so nested fields (e.g., `Source_Country`, `UserName`) become searchable/reportable.  
- **`stats`** → Aggregates records (e.g., `count by UserName`) to summarize and rank activity.  
- **`search`** → Filters results with conditions (e.g., `action=teardown`).  
- **`sort`** → Orders output for readability (`sort - count` = highest first).  
- **`table`** → Shows selected columns for quick sanity checks.

---
## Query 1 — Events by User and Country

**What I’m searching for**  
Events grouped by `UserName` and `Source_Country`, showing the number of times a user generated traffic from different countries.  

**SPL**
```spl
index="main" 
| spath 
| search Source_Country!="France" 
| stats count by UserName, Source_Country 
| sort - count
```
<p align="left">
  <img src="" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 1: Suspicious process in SIEM dashboard</em>
</p>
**Good for**  

- Detecting unusual geolocation behavior (e.g., a user logging in from multiple foreign countries).  
- Identifying potential account compromise or travel-related anomalies.  

**Field breakdown**  

- `index="main"` → Points Splunk to the correct dataset.  
- `spath` → Ensures JSON fields are parsed for querying.  
- `UserName` → Identifies the account.  
- `Source_Country` → Captures geolocation metadata.  
- `stats count` → Aggregates how many events match.  
- `sort - count` → Displays most frequent results at the top.  

---
## Query 2 — Failed Login Attempts by User

**What I’m searching for**  
Events where `action=failed`, aggregated by user and IP.

**SPL**
```spl
index="main" action=failed
| spath
| stats count by UserName, Source_ip
| sort - count
```
**Good for**  

- Investigating brute force attempts or repeated login failures. 
- Correlating failed attempts with possible attacker IP addresses.  

**Field breakdown**  

- `index="main"` → Points Splunk to the correct dataset.  
- `spath` → Ensures JSON fields are parsed for querying.  
- `UserName` → Identifies the account.  
- `action=failed` → Filters only failed authentication attempts. 
- `UserName` → Reveals which account is being targeted.  
- `Source_ip` → Identifies the attacker or misconfigured client.

---
## Query 3 — Event Count by State (USA only)

**What I’m searching for**  
Events originating only from the `United States`, grouped by `source_state`.

**SPL**
```spl
index="main" Source_Country="United States"
| spath
| stats count by source_state
| sort - count
```
**Good for**  

- Spotting regional anomalies within the same country.
- Useful for organizations that expect traffic only from certain states.  

**Field breakdown**  

- `index="main"` → Points Splunk to the correct dataset.  
- `spath` → Ensures JSON fields are parsed for querying.  
- `Source_Country="United States"` → Filters for U.S. traffic only.  
- `source_state` → Provides geographic detail within the country. 
- `stats count` → Counts activity per state.

---
## Query 4 — TCP Teardown Traffic on Port 443

**What I’m searching for**  
Events where action is `teardown`, using `protocol=tcp`, focusing on `port=443` or any destination port equal to 443.

**SPL**
```spl
index="main" action=teardown protocol=tcp (port=443 OR dest_port=443)
| spath
| stats count by Source_ip
| sort - count
```
**Good for**  

- Identifying terminated HTTPS sessions (potential exfiltration or scanning).
- Correlating which IPs are repeatedly generating teardown events.

**Field breakdown**  

- `index="main"` → Points Splunk to the correct dataset.  
- `spath` → Ensures JSON fields are parsed for querying.  
- `action=teardown` → Sessions that were closed.
- `protocol=443 OR dest_port=443` → Narrows down to HTTPS traffic. 
- `Source_ip` → The origin of the session.

---
## Query 5 — Event Volume by Outcome (Action)

**What I’m searching for**  
The distribution of session outcomes (e.g., `teardown`, `accept).

**SPL**
```spl
index="main"
| spath
| stats count by action
| sort - count
```
**Good for**  

- Establishing a baseline of normal network activity.
- Identifying spikes in unusual outcomes (e.g., too many `failed` events).

**Field breakdown**  

- `index="main"` → Points Splunk to the correct dataset.  
- `spath` → Ensures JSON fields are parsed for querying.   
- `action` → The outcome of a session (accepted, failed, teardown, etc.).
- `stats count by action` → Quickly counts how many of each outcome exist.

---
## Summary

- `index` ensures Splunk queries the correct dataset.
- `spath` parses JSON data into searchable fields.
- `stats` performs aggregations to summarize raw data.
- **Filtering fields** like `UserName`, `Source_ip`, `Source_Country`, and `action` allow analysts to pinpoint anomalies.

These foundational queries are starting points for SOC investigations and can be adapted to different detection use cases, such as brute force detection, suspicious geolocation, HTTPS traffic analysis, and baseline outcome tracking.
