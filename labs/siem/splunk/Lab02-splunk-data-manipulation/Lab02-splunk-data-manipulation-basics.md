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
I am working as a SOC Analyst at CyberT. A client needs help ingesting logs from a custom source into Splunk. The issues include:  
- **Event Breaking:** Configuring Splunk to break events properly.  
- **Multi-line Events:** Configuring Splunk to handle multi-line events.  
- **Masking:** Masking sensitive information (e.g., PCI DSS compliance).  
- **Extracting Custom Fields:** Removing redundant fields in web logs.  

Scripts are provided in `/Downloads/scripts/`. Commands are executed as a root user.  

### Challenge / Question
**Q:** How many Python scripts are present in the `/Downloads/scripts/` directory?  
**A (example):** There are 3 scripts: `authentication_logs`, `purchase-details`, and `vpnlogs`.  


---

## Task 3 - Splunk Data Processing Overview

### Steps
1. **Understand the Data Format**  
   Splunk supports multiple formats (CSV, JSON, XML, syslog).  

2. **Identify the Sourcetype**  
   The sourcetype tells Splunk how to parse and interpret the data.  

3. **Configure props.conf**  
```conf
[source::/path/to/your/data]  
sourcetype = your_sourcetype  
```

4. **Define Field Extractions**  
```conf
[your_sourcetype]  
EXTRACT-field1 = regular_expression1  
EXTRACT-field2 = regular_expression2  
```

5. **Save and Restart Splunk**  

6. **Verify and Search Data**  

### Challenge / Question
**Q:** What is the role of the `props.conf` file?  
**A (example):** It defines parsing settings for sourcetypes and data sources, including field extractions and event boundaries.  


---

## Task 4 - Exploring Splunk Configuration Files

### Key Config Files
- **inputs.conf** – Defines data inputs.  
```conf
[monitor:///path/to/logfile.log]  
sourcetype = my_sourcetype  
```

- **props.conf** – Defines parsing rules.  
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

- **indexes.conf** – Index management.  
```conf
[my_index]  
homePath = $SPLUNK_DB/my_index/db  
coldPath = $SPLUNK_DB/my_index/colddb  
```

- **outputs.conf** – Forwarding events.  
```conf
[tcpout]  
defaultGroup = my_indexers  
```

- **authentication.conf** – Manages authentication.  
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


---

## Task 5 - Creating a Simple Splunk App

### Steps
1. **Start Splunk**  
```bash
cd /opt/splunk/bin  
./splunk start  
```

2. **Create a New App (DataApp)**  
Stored under `/opt/splunk/etc/apps/`.  

3. **Explore App Directory**  
- `app.conf` → Metadata  
- `bin/` → Custom scripts  
- `default/` → XML dashboards  
- `local/` → Overrides  

4. **Generate Logs**  
```python
print("This is a sample log...")  
```

5. **Configure inputs.conf**  
```conf
[script:///opt/splunk/etc/apps/DataApp/bin/samplelogs.py]  
index = main  
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


---

## Task 6 - Event Boundaries (vpnlogs)

### Problem
Splunk groups multiple events together incorrectly.  

### Steps
- Place `vpnlogs` in `bin/`.  
- Configure `inputs.conf`.  
```conf
[script:///opt/splunk/etc/apps/DataApp/bin/vpnlogs]  
index = main  
sourcetype = vpn_logs  
interval = 5  
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


---

## Task 7 - Parsing Multi-line Events

### Problem
`authentication_logs` produce multi-line events split incorrectly.  

### Steps
- Configure inputs.conf  
```conf
[script:///opt/splunk/etc/apps/DataApp/bin/authentication_logs]  
index = main  
sourcetype = auth_logs  
host = auth_server  
interval = 5  
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


---

## Task 8 - Masking Sensitive Data

### Problem
Purchase logs include credit card numbers.  

### Steps
- Configure inputs.conf for `purchase-details`.  
- Fix event boundaries:  
```conf
[purchase_logs]  
SHOULD_LINEMERGE = true  
MUST_BREAK_AFTER = \d{4}\.  
```

- Apply SEDCMD to mask CC numbers:  
```conf
[purchase_logs]  
SEDCMD-cc = s/\d{4}-\d{4}-\d{4}-\d{4}/XXXX-XXXX-XXXX-XXXX/g  
```

### Challenge / Question
**Q1:** Which stanza breaks events after regex? → MUST_BREAK_AFTER  
**Q2:** What is the SEDCMD regex? → s/\d{4}-\d{4}-\d{4}-\d{4}/XXXX-XXXX-XXXX-XXXX/g  


---

## Task 9 - Extracting Custom Fields

### Problem
VPN logs don’t auto-extract fields (`username`, `server`, `action`).  

### Steps
1. **Regex pattern**  
```regex
User:\s(\w+\s\w+)  
```

2. **transforms.conf**  
```conf
[vpn_custom_fields]  
REGEX = User:\s(\w+\s\w+)  
FORMAT = Username::$1  
WRITE_META = true  
```

3. **props.conf**  
```conf
[vpn_logs]  
SHOULD_LINEMERGE = true  
MUST_BREAK_AFTER = (DISCONNECT|CONNECT)  
TRANSFORMS-vpn = vpn_custom_fields  
```

4. **fields.conf**  
```conf
[Username]  
INDEXED = true  
```

5. **Extended Extraction**  
```regex
User:\s(\w+\s\w+),.*Server:\s(\w+),.*Action:\s(\w+)  
```

### Challenge / Question
**Q1:** Regex for three fields? → User:\s(\w+\s\w+),.*Server:\s(\w+),.*Action:\s(\w+)  
**Q2:** How many usernames extracted from purchase_logs? → Example: 5  
**Q3:** How many unique CC values? → Example: 4  


---

## Task 10 - Recap and Conclusion

### Summary
In this lab, I practiced how to configure Splunk to parse and manipulate data by:  
- Defining event boundaries  
- Masking sensitive information  
- Updating configuration files (`inputs.conf`, `props.conf`, `transforms.conf`)  
- Extracting custom fields  

These skills are critical for SOC Analysts to properly analyze and secure log data.  

### Challenge / Question
**Q:** Complete the room.  
**A:** Marked as complete.  


---

## Reflection
This lab gave me practical experience with Splunk configuration files, regex-based parsing, masking sensitive data, and extracting custom fields. These skills are directly relevant to real-world SOC analyst responsibilities, including compliance, incident investigation, and monitoring.  
