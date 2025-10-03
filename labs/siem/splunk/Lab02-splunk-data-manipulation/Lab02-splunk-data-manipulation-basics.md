# Splunk Data Processing and Manipulation Lab (Basics)

## Task 1 - Introduction

### Overview
This lab focuses on learning how data is processed, parsed, and manipulated in Splunk to extract meaningful insights and perform effective analysis of machine-generated data. These skills are critical for a security analyst, as they directly support identifying and responding to threats, investigating incidents, and monitoring system health.

I started by reviewing the lab’s introduction, which outlined the learning objectives for the exercises ahead. The lab emphasized how Splunk handles event parsing, the role of configuration files such as `inputs.conf`, `props.conf`, and `transforms.conf`, and how to use these files to extract and filter fields. I paid attention to the context of why parsing is so critical for a SOC analyst: poorly parsed logs can lead to incomplete data, false negatives, or gaps in investigations. This task didn’t involve hands-on commands yet, but it set the stage by showing me what I would be practicing.  

### Learning Objectives
By the end of this lab, I will understand:
- How events are parsed in Splunk.  
- The importance of configuration files such as **inputs.conf**, **transforms.conf**, and **props.conf**.  
- How to extract custom fields and apply them as filters.  
- How to identify timestamps in event logs. 
---

## Task 2 - Scenario and Lab Instructions

### Scenario
I assumed the role of a SOC Analyst at a company called **CyberT**. The scenario involved ingesting logs from a custom source with the following issues:
- **Event Breaking:** Configuring Splunk to break events properly.  
- **Multi-line Events:** Configuring Splunk to handle multi-line events.  
- **Masking:** Masking sensitive information (e.g., PCI DSS compliance).  
- **Extracting Custom Fields:** Removing redundant fields in web logs.

### What I Did
I assumed the role of a SOC analyst working at a fictional company, where my task was to process and transform logs coming from a custom source. The lab simulated realistic issues I would encounter, such as events not breaking correctly, multi-line logs being treated as separate events instead of one, and sensitive information like credit card numbers appearing in raw logs. I connected to the lab machine, navigated to the `/Downloads/scripts` directory, and noted that all the scripts I’d be working with were stored there for me to analyze. Scripts are provided in `/Downloads/scripts/` and commands are executed as a root user. I worked within a Linux environment (confirmed by the ubuntu@tryhackme prompt, which indicates an Ubuntu-based Linux system).  

### Challenge / Question
At the end of this portion of the lab, a question asked me to determine how many Python scripts were present in the ~/Downloads/scripts directory. Since I already knew the target location, I navigated directly to it by running: `cd Downloads/scripts`.

<p align="left">
  <img src="images/lab02-splunk-data-manipulation-figure01.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 1</em>
</p>

After entering the directory, I used the `ls` command to list its contents. The output showed three items: `authentication_logs`, `purchase-details`, and `vpnlogs`. None of these files had the typical `.py` extension, which is what I usually expect Python scripts to have. But the question asked how many scripts there were at this directory path, so I concluded that there were three Python scripts in this directory.

<p align="left">
  <img src="images/lab02-splunk-data-manipulation-figure02.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 2</em>
</p>

**Q:** How many Python scripts are present in the `/Downloads/scripts/` directory?  
**A (example):** There are 3 scripts: `authentication_logs`, `purchase-details`, and `vpnlogs`.  

### What I Learned
This exercise reinforced how to quickly navigate through the Linux file system and inspect directories using commands like `cd` and `ls`. It also reminded me that while most Python scripts are saved with a `.py` extension, technically any file could contain Python code if it starts with a proper line (e.g., #!/usr/bin/python3). However, in practical scenarios and exams, the `.py` extension is the standard indicator.

---

## Task 3 - Splunk Data Processing Overview

### What I Did
I walked through the high-level process Splunk uses to parse data. First, I studied how Splunk needs to understand the format of incoming data, whether it’s JSON, XML, syslog, or CSV. Next, I saw how every dataset is assigned a sourcetype, which tells Splunk what parsing rules to apply. I then worked with examples of how to configure the `props.conf` file to bind a sourcetype to a source path, and how to define regular expressions for extracting fields. The provided configuration snippets showed me how to write stanzas in `props.conf` and attach field extractions using `EXTRACT-field = regex`. Finally, I looked at the importance of saving the file, restarting Splunk, and validating by running searches to confirm whether the extracted fields were working as intended.

#### Steps
I went through a six-step process to configure Splunk parsing:

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
I learned that parsing in Splunk is a structured pipeline that begins with ingestion and continues through sourcetype assignment, regex extraction, and validation. The `props.conf` file is central to this process, acting as the instruction manual for Splunk on how to handle each dataset. I also learned that without proper configuration, Splunk would ingest data as raw text, making searches much less useful.

---

## Task 4 - Exploring Splunk Configuration Files

## What I Did
I explored multiple configuration files to understand their roles. I practiced writing examples for `inputs.conf` to ingest log files, `props.conf` to define field extractions, and `transforms.conf` to enrich data by creating new fields. I also looked at `indexes.conf`, which determines where the data is stored, and `outputs.conf`, which controls how data is sent to other Splunk instances. Finally, I learned about `authentication.conf`, which enables features like LDAP authentication. I also examined the different stanza types in Splunk, such as `[sourcetype]`, `REPORT`, `EXTRACT`, and `TIME_PREFIX`, which define how events are processed and indexed. 

### Key Config Files
I explored several important configuration files in Splunk and tested examples:

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
I learned that each configuration file has a unique responsibility, and together they create the entire ingestion and parsing pipeline. Knowing which file to modify is critical to solving problems quickly. I also learned that stanza-based configuration is extremely powerful, allowing very granular control over parsing behavior with just a few lines of configuration. I learned the **division of responsibilities**: `inputs.conf` ingests, `props.conf` parses, `transforms.conf` manipulates, `indexes.conf` stores, and `outputs.conf` forwards.

---

## Task 5 - Creating a Simple Splunk App

### What I Did
I created my own Splunk app called `DataApp`. First, I started the Splunk service from `/opt/splunk` using the `bin/splunk start` command and logged in with the provided credentials. Once inside the Splunk web interface, I navigated to the Apps section and created a new app with fields like name, folder path, author, and description. To simulate log ingestion, I created a simple Python script called `samplelogs.py` that printed a single log line. I placed this script in the `bin` directory of the app. Next, I created an `inputs.conf` file that told Splunk to execute the script every five seconds, sending its output to the `main` index with a sourcetype of `testing`. Finally, I restarted Splunk to apply the changes.  

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
I learned how Splunk apps provide a modular way to manage configuration and how they can be used to simulate log ingestion for testing. Writing even a simple script and configuring `inputs.conf` gave me a clear picture of how Splunk consumes and indexes events in real time. I also learned the importance of restarting Splunk to make new configurations effective. It was cool to see how Splunk apps organize configurations and that `inputs.conf` scripts can **simulate live log ingestion**.

---

## Task 6 - Event Boundaries (vpnlogs)

### What I Did
I worked with the `vpnlogs` script, which generated VPN connection and disconnection events. After placing the script into the app’s `bin` directory, I configured an `inputs.conf` entry to ingest it into Splunk. When I searched the ingested data, I noticed that Splunk did not break the events correctly, treating multiple log lines as one. To fix this, I created a regular expression that matched the words `DISCONNECT` or `CONNECT` at the end of each line. I updated `props.conf` to include `MUST_BREAK_AFTER = (DISCONNECT|CONNECT)` and enabled line merging with `SHOULD_LINEMERGE = true`. After restarting Splunk, I confirmed that each event was being properly broken at the correct boundary. 

### Problem
This lab introduced a problem where Splunk was grouping multiple events together incorrectly.

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
I learned how important it is to configure event boundaries so Splunk can distinguish between separate events. Regex-based rules in `props.conf` give me precise control over where events start and end. This is essential because improper event breaking can cause searches and dashboards to misinterpret the data. 

---

## Task 7 - Parsing Multi-line Events

### What I Did
Next, I worked with the `authentication_logs` script, which generated multi-line log entries. After ingesting the logs using `inputs.conf`, I noticed that Splunk incorrectly treated the logs as multiple events. To fix this, I configured `props.conf` to merge lines and only break events when a line started with `[Authentication]`. This was done using `BREAK_ONLY_BEFORE = \[Authentication\]` along with `SHOULD_LINEMERGE = true`. Restarting Splunk and re-running the search showed me that the multi-line logs were now captured correctly as single events.  

### Problem
`authentication_logs` produce multi-line events split incorrectly. Worked with `authentication_logs` script.  


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
I learned that multi-line events are a common challenge in Splunk, especially for logs like authentication or application errors that span several lines. Using the right regex and stanza settings in `props.conf` ensures these logs remain intact, preventing data fragmentation.  

---

## Task 8 - Masking Sensitive Data

### What I Did
I worked with the `purchase-details` script, which generated logs containing credit card numbers. These logs were ingested into Splunk using an `inputs.conf` configuration. To fix event boundaries, I wrote a regex that broke events after a 4-digit sequence. After confirming the events were structured properly, I used the `SEDCMD` setting in `props.conf` to mask the credit card numbers. My regex replaced the full numbers with `XXXX-XXXX-XXXX-XXXX`. Restarting Splunk showed that the sensitive information was masked in the search results.

### Problem
Purchase logs include credit card numbers. Used `purchase-details` script to simulate credit card logs.

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
I learned that Splunk provides built-in mechanisms to anonymize sensitive data at ingestion time. The `SEDCMD` setting works like the Unix `sed` command, applying regex replacements before indexing the data. This ensures compliance with standards like PCI DSS and HIPAA while still preserving logs for analysis.

---

## Task 9 - Extracting Custom Fields

### What I Did
I returned to the `vpnlogs` dataset to practice extracting custom fields. Using regex, I captured the username with `User:\s(\w+\s\w+)` and created a stanza in `transforms.conf` that formatted the result into a `Username` field. I then updated `props.conf` to apply this transform and created a `fields.conf` entry to mark the new field as indexed. After restarting Splunk, I validated that usernames were extracted. I then extended the regex to capture not only the username but also the server and action fields, using `User:\s(\w+\s\w+),.+Server:\s(.+),.+Action:\s(\w+)`. I updated the transform and fields configuration to include these fields and confirmed that Splunk extracted them successfully. 

### Problem
VPN logs don’t auto-extract fields (`username`, `server`, `action`). Worked with `vpn_logs`. 

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
I learned that custom field extraction is one of the most powerful aspects of Splunk. Using regex in `transforms.conf` and `props.conf` allows me to create new, meaningful fields from raw log text. This makes searches much more efficient, since I can query structured fields rather than relying on free-text search.

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
I reviewed all the work I had completed in the lab. I practiced defining event boundaries, parsing multi-line logs, masking sensitive information, and extracting custom fields. I also built a simple Splunk app to simulate log ingestion, which tied together all the configurations I had practiced. Each task built upon the last, giving me a realistic view of the types of parsing and ingestion issues a SOC analyst faces.  

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
