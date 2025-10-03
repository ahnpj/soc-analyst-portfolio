# Splunk Data Processing and Manipulation Lab (Basics)

## Task 1 - Introduction

### Overview
This lab focuses on learning how data is processed, parsed, and manipulated in Splunk to extract meaningful insights and perform effective analysis of machine-generated data. These skills are critical for a security analyst, as they directly support identifying and responding to threats, investigating incidents, and monitoring system health.

### Learning Objectives
By the end of this lab, I will understand:
- How events are parsed in Splunk.  
- The importance of configuration files such as **inputs.conf**, **transforms.conf**, and **props.conf**.  
- How to extract custom fields and apply them as filters.  
- How to identify timestamps in event logs.  

### Challenge / Question
**Q:** Why is event parsing important in Splunk from a security perspective?  
**A (example):** Event parsing ensures that raw machine data is structured in a way that allows me to search, filter, and correlate logs. Without parsing, it would be difficult to detect anomalies, track user activity, or investigate incidents efficiently.  


---

## Task 2 - Scenario and Lab Instructions

### Scenario
I assumed the role of a SOC Analyst at a company called **CyberT**. The scenario involved ingesting logs from a custom source with the following issues:
- **Event Breaking:** Configuring Splunk to break events properly.  
- **Multi-line Events:** Configuring Splunk to handle multi-line events.  
- **Masking:** Masking sensitive information (e.g., PCI DSS compliance).  
- **Extracting Custom Fields:** Removing redundant fields in web logs.

### What I Did
I connected to the Splunk lab environment and navigated to the `/Downloads/scripts` directory, which contained the log scripts we would analyze. Scripts are provided in `/Downloads/scripts/` and commands are executed as a root user.  

### Challenge / Question
**Q:** How many Python scripts are present in the `/Downloads/scripts/` directory?  
**A (example):** There are 3 scripts: `authentication_logs`, `purchase-details`, and `vpnlogs`.  

### What I Learned
I realized that SOC analysts don’t just visualize logs but also **shape how logs are ingested and stored** to ensure compliance and usability.

---

## Task 3 - Splunk Data Processing Overview

### What I Did
I went through a six-step process to configure Splunk parsing:

#### Steps
1. **Understand the Data Format**  
   Splunk supports multiple formats (CSV, JSON, XML, syslog). I examined data formats (CSV, JSON, syslog, XML) and identified relevant fields. I examined data formats (CSV, JSON, syslog, XML) and identified relevant fields.

2. **Identify the Sourcetype**  
   The sourcetype tells Splunk how to parse and interpret the data. I learned that the **sourcetype** is essential for parsing, as it tells Splunk how to handle a specific dataset. I learned that the **sourcetype** is essential for parsing, as it tells Splunk how to handle a specific dataset.

3. **Configure props.conf**
   This command binds the path to a sourcetype.

```conf
[source::/path/to/your/data]  
sourcetype = your_sourcetype  
```

4. **Define Field Extractions**
I wrote regex rules to extract fields like usernames or server names.
```conf
[your_sourcetype]  
EXTRACT-field1 = regular_expression1  
EXTRACT-field2 = regular_expression2  
```

5. **Save and Restart Splunk**
Restarting Splunk applies all parsing changes.

7. **Verify and Search Data**
I ran queries to confirm my configurations.

### Challenge / Question
**Q:** What is the role of the `props.conf` file?  
**A (example):** It defines parsing settings for sourcetypes and data sources, including field extractions and event boundaries.  

### What I learned
I learned the **step-by-step flow of parsing in Splunk** and how `props.conf` is a key file for defining sourcetypes and regex extractions.

---

## Task 4 - Exploring Splunk Configuration Files

## What I Did
I explored several important configuration files in Splunk and tested examples:

### Key Config Files
- **inputs.conf** – Defines data input and how data is ingested.  
```conf
[monitor:///path/to/logfile.log]  
sourcetype = my_sourcetype  
```

- **props.conf** – Defines parsing rules and controls field extractions and parsing. 
```conf
[my_sourcetype]  
EXTRACT-field1 = regex1  
EXTRACT-field2 = regex2  
```

- **transforms.conf** – Defines transformations.  
```conf
[add_new_field]  
REGEX = existing_field=(.*)  
FORMAT = new_field::$1  
```

- **indexes.conf** – Index management, which basically manages index storage: 
```conf
[my_index]  
homePath = $SPLUNK_DB/my_index/db  
coldPath = $SPLUNK_DB/my_index/colddb  
```

- **outputs.conf** – Forwarded events by sending events to remote indexers.
```conf
[tcpout]  
defaultGroup = my_indexers  
```

- **authentication.conf** – Managed and configured authentication.  
```conf
[authentication]  
authSettings = LDAP  
```

### Common Stanzas
| Stanza | Explanation | Example |
|--------|-------------|---------|
| sourcetype | Defines data source format | [apache:access] |
| TRANSFORMS | Field transformations | TRANSFORMS-example = myfield |
| REPORT | Extraction rules | REPORT-field1 = regex_pattern |
| EXTRACT | Regex field extraction | EXTRACT-field = regex |
| TIME_PREFIX | Defines timestamp prefix | TIME_PREFIX = \[timestamp\] |
| LINE_BREAKER | Defines event breaks | LINE_BREAKER = ([\r\n]+) |
| KV_MODE | Key-value parsing | KV_MODE = json |

### Challenge / Question
**Q1:** Which stanza breaks events after a provided pattern?  
**A:** LINE_BREAKER.  

**Q2:** Which stanza specifies the pattern for line breaks?  
**A:** LINE_BREAKER.  

**Q3:** Which config defines transformations?  
**A:** transforms.conf.  

**Q4:** Which config defines inputs?  
**A:** inputs.conf.  

### What I Learned
I learned the **division of responsibilities**: `inputs.conf` ingests, `props.conf` parses, `transforms.conf` manipulates, `indexes.conf` stores, and `outputs.conf` forwards.

---

## Task 5 - Creating a Simple Splunk App

### What I Did
I created a Splunk app to practice log ingestion and app configuration.

### Steps
1. **Start Splunk**  
   ```bash
   cd /opt/splunk
   bin/splunk start
   ```

2. **Login**  
   - Username: `splunk`
   - Password: `splunk123`

3. **Create App**  
   I named the app `DataApp`, located at `/opt/splunk/etc/apps/DataApp`.

4. **Write Python Script for Sample Logs**  
   ```python
   print("This is a sample log...")
   ```  
   Saved as `samplelogs.py` in `/bin`.

5. **Configure inputs.conf**  
   ```
   [script:///opt/splunk/etc/apps/DataApp/bin/samplelogs.py]
   index = main
   source = test_log
   sourcetype = testing
   interval = 5
   ```

6. **Restart Splunk**  
   ```bash
   /opt/splunk/bin/splunk restart
   ```

### Challenge / Question
**Q:** If you create an app named THM, what is its path?  
**A:** `/opt/splunk/etc/apps/THM`.  

### What I Learned
I learned how Splunk apps organize configurations and that `inputs.conf` scripts can **simulate live log ingestion**.

---

## Task 6 - Event Boundaries (vpnlogs)

### What I Did
I worked with `vpnlogs` to address event boundary issues. This lab introduced a problem where Splunk was grouping multiple events together incorrectly.

### Problem
Splunk groups multiple events together incorrectly.  

### Steps
- Copied `vpnlogs` into `/bin` and configured `inputs.conf`:  
   ```
   [script:///opt/splunk/etc/apps/DataApp/bin/vpnlogs]
   index = main
   source = vpn
   sourcetype = vpn_logs
   interval = 5
   ```

- Observed that Splunk failed to break events correctly.
- Created regex for breaking events:  
   ```regex
   (DISCONNECT|CONNECT)
   ```

- Search in Splunk:  
```spl
index=main sourcetype=vpn_logs  
```

### Fix
Update `props.conf`:  
```conf
[vpn_logs]  
SHOULD_LINEMERGE = true  
MUST_BREAK_AFTER = (DISCONNECT|CONNECT)  
```

### Challenge / Question
**Q1:** Which file defines parsing rules? → props.conf  
**Q2:** Regex used? → (DISCONNECT|CONNECT)  
**Q3:** Stanza to break events? → MUST_BREAK_AFTER  
**Q4:** Disable line merging? → SHOULD_LINEMERGE=false  

### What I Learned
I learned how to **fix event boundaries using regex** and why `SHOULD_LINEMERGE` matters.

---

## Task 7 - Parsing Multi-line Events

### What I Did
- Worked with `authentication_logs` script.  
- Configured `inputs.conf`:  
   ```
   [script:///opt/splunk/etc/apps/DataApp/bin/authentication_logs]
   index = main
   sourcetype = auth_logs
   host = auth_server
   interval = 5
   ```

### Problem
`authentication_logs` produce multi-line events split incorrectly.  

### Steps
- Configured inputs.conf  
```conf
[script:///opt/splunk/etc/apps/DataApp/bin/authentication_logs]  
index = main  
sourcetype = auth_logs  
host = auth_server  
interval = 5  
```
- Observed multi-line logs breaking incorrectly.  
- Updated `props.conf` to fix:  
   ```
   [auth_logs]
   SHOULD_LINEMERGE = true
   BREAK_ONLY_BEFORE = \[Authentication\]
   ```
- Fix in props.conf  
```conf
[auth_logs]  
SHOULD_LINEMERGE = true  
BREAK_ONLY_BEFORE = \[Authentication\]  
```

### Challenge / Question
**Q1:** Which stanza breaks events before a pattern? → BREAK_ONLY_BEFORE  
**Q2:** Which regex pattern was used? → \[Authentication\]  

### What I Learned
I learned that **multi-line logs need careful regex stanzas** and that Splunk can incorrectly split them unless configured.

---

## Task 8 - Masking Sensitive Data

### What I Did
Used `purchase-details` script to simulate credit card logs.

### Problem
Purchase logs include credit card numbers.  

### Steps
- Used `purchase-details` script to simulate credit card logs.
- Configured `inputs.conf`.
- Created regex for event boundaries:  
   ```regex
   \d{4}\.
   ```
- Updated `props.conf`:  
   ```
   [purchase_logs]
   SHOULD_LINEMERGE = true
   MUST_BREAK_AFTER = \d{4}\.
   ```

- Introduced **SEDCMD** for masking:  
   ```
   SEDCMD-cc = s/\d{4}-\d{4}-\d{4}-\d{4}/XXXX-XXXX-XXXX-XXXX/g
   ```

### Challenge / Question
**Q1:** Which stanza breaks events after regex? → MUST_BREAK_AFTER  
**Q2:** What is the SEDCMD regex? → s/\d{4}-\d{4}-\d{4}-\d{4}/XXXX-XXXX-XXXX-XXXX/g  

### What I Learned
I learned that **SEDCMD works like Unix sed**, allowing field anonymization for compliance with PCI DSS and HIPAA.

---

## Task 9 - Extracting Custom Fields

### What I Did
- Worked with `vpn_logs`. 

### Problem
VPN logs don’t auto-extract fields (`username`, `server`, `action`).  

### Steps
- Regex to capture username:  
   ```regex
   User:\s(\w+\s\w+)
   ```
- Created `transforms.conf`:  
   ```
   [vpn_custom_fields]
   REGEX = User:\s(\w+\s\w+)
   FORMAT = Username::$1
   WRITE_META = true
   ```

- Updated `props.conf`:  
   ```
   [vpn_logs]
   TRANSFORMS-vpn = vpn_custom_fields
   ```

- Created `fields.conf`:  
   ```
   [Username]
   INDEXED = true
   ```

- Restarted Splunk and validated.  
- Extended regex to capture username, server, and action:  
   ```regex
   User:\s(\w+\s\w+),.+Server:\s(.+),.+Action:\s(\w+)
   ```


### Challenge / Question
**Q1:** Regex for three fields? → User:\s(\w+\s\w+),.*Server:\s(\w+),.*Action:\s(\w+)  
**Q2:** How many usernames extracted from purchase_logs? → Example: 5  
**Q3:** How many unique CC values? → Example: 4  

### What I Learned
I learned how to **extract custom fields using regex and transforms.conf**. This is critical for enriching events so they can be queried effectively in Splunk searches.

---

## Task 10 - Recap and Conclusion

### Summary
In this lab, I practiced how to configure Splunk to parse and manipulate data by:  
- Defining event boundaries  
- Masking sensitive information  
- Updating configuration files (`inputs.conf`, `props.conf`, `transforms.conf`)  
- Extracting custom fields  

These skills are critical for SOC Analysts to properly analyze and secure log data.  

### What I Did
I reviewed all the steps I performed:
- Defined event boundaries with regex and props.conf.
- Parsed multi-line events.
- Masked sensitive fields with SEDCMD.
- Extracted custom fields using regex and transforms.conf.
- Created a working Splunk app to simulate logs.

### Challenge / Question
**Q:** Complete the room.  
**A:** Marked as complete.  

### What I Learned
I learned the **end-to-end workflow of Splunk parsing**:
- **Ingestion (`inputs.conf`)**
- **Parsing (`props.conf`)**
- **Transformation (`transforms.conf`)**
- **Masking (`SEDCMD`)**


---

## Reflection
This lab gave me practical experience with Splunk configuration files, regex-based parsing, masking sensitive data, and extracting custom fields. These skills are directly relevant to real-world SOC analyst responsibilities, including compliance, incident investigation, and monitoring.  
