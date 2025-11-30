# Lab 10 - Splunk Data Processing and Parsing (Basics)

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
  <img src="images/lab10-splunk-data-manipulation-figure01.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="500"><br>
  <em>Figure 1</em>
</p>

After entering the directory, I used the `ls` command to list its contents. The output showed three items: `authentication_logs`, `purchase-details`, and `vpnlogs`. None of these files had the typical `.py` extension, which is what I usually expect Python scripts to have. But the question asked how many scripts there were at this directory path, so I concluded that there were three Python scripts in this directory.

<p align="left">
  <img src="images/lab10-splunk-data-manipulation-figure02.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="500"><br>
  <em>Figure 2</em>
</p>

**Q:** How many Python scripts are present in the `/Downloads/scripts/` directory?  
**A** There are 3 scripts: `authentication_logs`, `purchase-details`, and `vpnlogs`.  

### What I Learned
This exercise reinforced how to quickly navigate through the Linux file system and inspect directories using commands like `cd` and `ls`. It also reminded me that while most Python scripts are saved with a `.py` extension, technically any file could contain Python code if it starts with a proper line (e.g., #!/usr/bin/python3). However, in practical scenarios and exams, the `.py` extension is the standard indicator.

---

## Task 3 - Splunk Data Processing Overview

### What I Did
I walked through the high-level process Splunk uses to parse data. First, I studied how Splunk needs to understand the format of incoming data, whether it’s JSON, XML, syslog, or CSV. Next, I saw how every dataset is assigned a sourcetype, which tells Splunk what parsing rules to apply. I then worked with examples of how to configure the `props.conf` file to bind a sourcetype to a source path, and how to define regular expressions for extracting fields. The provided configuration snippets showed me how to write to specific sections (or stanzas) in `props.conf` and attach field extractions using `EXTRACT-field = regex`. Finally, I looked at the importance of saving the file, restarting Splunk, and validating by running searches to confirm whether the extracted fields were working as intended.

#### Steps
I went through a six-step process to configure Splunk parsing:

1. **Understand the Data Format**  
   Splunk supports multiple formats (CSV, JSON, XML, syslog). I examined data formats (CSV, JSON, syslog, XML) and identified relevant fields. I examined data formats (CSV, JSON, syslog, XML) and identified relevant fields.

2. **Identify the Sourcetype**  
   The sourcetype tells Splunk how to parse and interpret the data. It essentially represents the format of the data being indexed. I learned that the **sourcetype** is essential for parsing, as it tells Splunk how to handle a specific dataset.

3. **Configure props.conf**  
   In this step of the task, I learned that you can use the configuration file (example in lab: `props.conf`) to define data parsing settings for specific sourcetypes and data sources. I also learned how to assign a sourcetype to a data source by first defining the path of the data source, and then defining its sourcetype.
   
   This command template binds the path to a sourcetype.

```conf
[source::/path/to/your/data]  
sourcetype = your_sourcetype  
```
- `/path/to/your/data` is basically telling Splunk where the data source lives.
- `sourcetype` tells Splunk the format of the data being indexed and subsequently how to parse and interpret the data.

4. **Define Field Extractions**
Here, I learned that you can define regular expressions (regex) to parse (or "filter") to extract specific fields from the data, like usernames or server names.
This command template defines the fields you want to extract from your data source:
```conf
[your_sourcetype]  
EXTRACT-field1 = regular_expression1  
EXTRACT-field2 = regular_expression2  
```
- `your_sourcetype` is the sourcetype (as described earlier)
- `EXTRACT-field1 = regular_expression1` and `EXTRACT-field2 = regular_expression2` is basically how you would extract a single field from your data source.
  - `field1` and `field2` are the names of a fields you want to extract, and `regular_expression1` and `regular_expression2` are the regex used to match, filter, and extract the values.

### (WAIT): Quick Personal Side Experiment For Step 4

I wanted to try out my own simple example to check my understanding of how field extractions work in Splunk. I made up a small log line (from an imaginary data source) with two users and their actions:  
```
user=john action=login
user=alice action=logout
```
To extract these values, I would write the following in `props.conf` file:  

```
[mysourcetype]
EXTRACT-user = user=(\w+)
EXTRACT-action = action=(\w+)
```
The regex `user=(\w+)` will match both `john` and `alice`, and the regex `action=(\w+)` will match both `login` and `logout`.

- `user=(\w+)`
  - `user=` literally matches the users in the log.
  - `(\w+)` is a capturing group.
      - `\w matches` any word character (letters a-z, A-Z, digits 0-9, and underscore _).
      - `+` means basically means "one or more."
      - Together, `\w+` captures names like `john` or `alice`.
- `action=(\w+)`
  - `action=` literally matches the text action=.
  - `(\w+)` works the same as above, capturing words like `login` and `logout`.

I wanted to try out another example, but slightly more complex, so I imagined (lol, yes just imagining) the data source contained many different users and I wanted to capture everyone whose name starts with “j”, but only when their action was specifically `login`, I could adjust the regex like this:
```
[mysourcetype]
EXTRACT-j_users_login = user=(j\w+)\s+action=login
```
- `user=(j\w+)` captures any username starting with the letter “j” (e.g., john, james, jill, jacob).
- `s+` would match the space or spaces after the username, so like any whitespace. The `+` is one or more of however many whitespace there is.
- `action=login` would only match entries where the action is exactly `login`.

The result would create a field listing all users whose names start with a "j" and who performed a `login` action.


5. **Save and Restart Splunk**
I learned after editing the configuration file, I would restart Splunk which applies all parsing changes.

7. **Verify and Search Data**
I also learned that once Splunk restarts, I can search the data and verify it parsed correctly to confirm my configurations.

### What I learned
I learned that parsing in Splunk is a structured pipeline that begins with ingestion and continues through sourcetype assignment, regex extraction, and validation. The `props.conf` file (example configuration file) in this task  is central to this process, acting as the instruction manual for Splunk on how to handle each dataset. I also learned that without proper configuration, Splunk would ingest data as raw text, making searches much less useful.

---

## Task 4 - Exploring Splunk Configuration Files

## What I Did
In this task of the lab, I explored multiple configuration files to understand their roles. I practiced writing examples for `inputs.conf` to ingest log files, `props.conf` to define field extractions, and `transforms.conf` to enrich data by creating new fields. I also looked at `indexes.conf`, which determines where the data is stored, and `outputs.conf`, which controls how data is sent to other Splunk instances. Finally, I learned about `authentication.conf`, which enables features like LDAP authentication. I also examined the different stanza types in Splunk, such as `[sourcetype]`, `REPORT`, `EXTRACT`, and `TIME_PREFIX`, which define how events are processed and indexed. 

### Key Config Files
I learned about several important configuration files in Splunk and tested examples:

<b>(1) inputs.conf</b> - Defines data input, where that data lives, and how data is ingested. Below is an example `inputs.conf` file.

```conf
[monitor:///path/to/logfile.log]  
sourcetype = my_sourcetype  
```

<b>(2) props.conf</b>– Defines parsing rules and controls field extractions and parsing. This is the configuration file I worked with in task 3. 

```conf
[my_sourcetype]  
EXTRACT-field1 = regex1  
EXTRACT-field2 = regex2  
```

<b>(3) transforms.conf</b> -  Defines transformations. I was confused what "transformation" actually meant, but learned that it's simply a rule that tells Splunk how to change or process data. It is similar to `props.conf` except `transforms.conf` is the actual rule for transformations, whereas `props.conf` defines when and where to apply a transformation. The following is an example block of a `transform.conf` file. As a simple example comparison, `transforms.conf` says "here's the rule on how to extract users" and `props.conf` says "now apply those rules to these logs".

```conf
[add_new_field]  
REGEX = existing_field=(.*)  
FORMAT = new_field::$1  
```

  - **(3-A)** I thought about this configuration file a little more and imagined a data source that contains a log entry:
`user=john action=login`, which in practice, could look a little more like this: `192.168.1.45 - - [04/Oct/2025:09:34:56 -0400] "GET /index.html HTTP/1.1" 200 1024 user=john`
    - `192.168.1.45` is the client IP address
    - `-` is a placeholder that shows the "name" of the remote user, which I learned is called "identd". I also learned that in practice, almost nobody uses this, so it's just a single `-`. The second instance of `-` would show the username if the web server `john` is connected to required login or authentication.
    - `[04/Oct/2025:09:34:56 -0400` is the timestamp. The `-0400` represents time zone, which is the offset from UTC.
    - `GET /index.html HTTP/1.1" is using the `GET` HTTP method for data retrieval from the web server. It's also requesting resources from `/index.html`. `HTTP/1.1` is the web protocol and version number.
    - `200` is a HTTP status code returned by the web server and means success. Other commonly known HTTP status codes are `404` (Not Found) and `500` (Server Error)
    - `1024` is the response size in bytes, but only for the body and doesn't include headers. This just means 1024 bytes were retrieved and sent back to the client, `john`.
    - `user=john` is a custom field and provides a value. In this case, it would be the client's name making the request.

- **(3-B)** If I wanted to pull the username as a searchable field, I'd modify the `transforms.conf` file by defining an `extract_user` rule:

  ```conf
  [extract_user]
  REGEX = user=(\w+)
  FORMAT = user::$1
  ```

  - `[extract_user]` represents the name of the rule/transformation.
  - `REGEX = user=(\w+)` is the regular expression Splunk will look for inside the log.
    - `user=` is the literal text in the log.
    - `(\w+)` matches the word that comes after `user=`.
  - `FORMAT = user::$1` tells Splunk how to store the captured value as a field.
    - `user::` means the field name will be `user`.
    - `$1` means “take the first capture group from the regex” (e.g., `john`).


- **(3-C)** Now if I wanted to apply these rules to a log file:

  ```conf
  [source_type]
  REPORT-extract_user = extract_user
  ```

  - `[source_type]` is what I discussed in task 3, which is basically the format of the data being indexed, which also tells Splunk how to parse and interpret the data.
  - `REPORT-extract_user = extract_user` pulls and runs the `extract_user` transform rule from the `transforms.conf` file.


<b>(4) indexes.conf</b> – Index management, which basically manages index storage. I learned that Splunk stores data in indexes, which are like separate folders of events from a data source. It basically tells Splunk where to store the data and how to do it. Below is an example `indexes.conf` file:

```conf
[my_index]  
homePath = $SPLUNK_DB/my_index/db  
coldPath = $SPLUNK_DB/my_index/colddb
```

- `homePath` is telling Splunk where recent data should be stored.
- `coldPath` is telling Splunk where to move aged data (past certain thresholds).

<b>(5) outputs.conf</b> – Forwarded events by sending events to remote indexers. It basically tells Splunk where to sent/forward data in instances where Splunk is not the final destination. It controls things like which indexers to send events to (good for load balancing, sending events to multiple targets) and which protocol to use (TCP, SSL). Example `outputs.conf` file below:

```conf
[tcpout]
defaultGroup = my_indexers
[tcpout: myindexers]
server = remote_indexer:9997
```

- `[tcpout]` tells Splunk I'm setting up a TCP output (forwarding events via TCP]
- `defaultGroup = my_indexers` tells Splunk that I'm sending my data to the `my_indexers` group. Side note, I learned that a group is just a nickname for a group of Splunk indexers.
- `[tcpout: myindexers]` defines the group name. In this case, it's `myindexers`.
- `server = remote_indexer:9997` is telling Splunk which specific index servers within the group to send the data.


<b>(6) authentication.conf</b> – Manages and configures authentication settings. Below is an example `authentication.conf` file:

```conf
[authentication]  
authSettings = LDAP
[authenticationLDAP]
SSLEnabled = true 
```

- The `[authentication]` section is telling Splunk which authentication method to use. In this example, it's `LDAP`.
- The `[authenticationLDAP]` section defines how LDAP is configured. So `SSLEnabled` says to use SSL/TLS encryption when connecting to an LDAP server. This is crucial because without SSL, login credentials would be sent in cleartext.

Although these are not all of the configuration files Splunk provides, these are the ones I focused on in this lab. In particular, I got to learn about `inputs.conf`, `props.conf`, `transforms.conf`, `indexes.conf`, `outputs.conf`, and a small piece of `authentication.conf` to understand how parsing, routing, storage, forwarding, and authentication work together. Splunk also has many other configuration files that handle tasks such as server settings (`server.conf`), limits (`limits.conf`), deployment (`deploymentclient.conf`), and more. For the scope of this lab, however, I concentrated on the files most relevant to the data pipeline and authentication basics.

I learned that each configuration file has a specific purpose and all of them work together.

### Stanzas
In this lab, I also learned about stanzas in Splunk configuration files. A stanza is essentially a section within a `.conf` file that defines specific behavior or rules. Each stanza has a name (like `[sourcetype]`, `[REPORT]`, or `[TRANSFORMS]`) and contains settings that control how Splunk processes data. For example, I saw how stanzas such as `TIME_PREFIX` and `TIME_FORMAT` help Splunk correctly identify timestamps, while `LINE_BREAKER` and `SHOULD_LINEMERGE` determine how raw events are split into individual lines. Other stanzas like `REPORT` and `EXTRACT` use regular expressions to pull out fields, and `KV_MODE` can automatically extract key/value pairs. Understanding these gave me a clearer picture of how Splunk’s parsing pipeline works and how flexible it is when dealing with different log formats.

Here is a quick table I created to loosely defines some common stanzas and provides an example of how it might appear in configuration files:

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
At the end of this task (task 4) of the lab, I was presented with a few questions that quizzed me on stanzas and configuration files.

<p align="left">
  <img src="images/lab10-splunk-data-manipulation-figure03.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="900"><br>
  <em>Figure 3</em>
</p>

**Q1:** Which stanza breaks events after a provided pattern?  
**A:** `BREAK_ONLY_AFTER` 

**Q2:** Which stanza specifies the pattern for line breaks?  
**A:** `LINE_BREAKER` 

**Q3:** Which config defines transformations?  
**A:** `transforms.conf`  

**Q4:** Which config defines inputs?  
**A:** `inputs.conf`  

### What I Learned
I learned that each configuration file has a unique responsibility, and together they create the entire ingestion and parsing pipeline. Knowing which file to modify is critical to solving problems quickly. I also learned that stanza-based configuration is extremely powerful, allowing very granular control over parsing behavior with just a few lines of configuration. I learned the **"division of responsibilities"**: `inputs.conf` ingests, `props.conf` parses, `transforms.conf` manipulates, `indexes.conf` stores, and `outputs.conf` forwards. I also learned about how "stanzas" in Splunk configuration files is essentially a section within a `.conf` file that defines specific behavior or rules.

---

## Task 5 - Creating a Simple Splunk App

### What I Did
For this task of the lab, I created my own Splunk app called `DataApp`. I created a simple Splunk app to better understand how Splunk organizes and extends functionality through apps. An app in Splunk is essentially a container that holds configurations, inputs, and supporting files such as scripts or dashboards. By building a very simple sample app that outputs a test log, I was able to see how Splunk apps are structured and where they are stored in the file system. The purpose of this lab is not to build a production-ready application, but to practice the process of creating, saving, and placing files into Splunk’s app framework. This helps demonstrate how custom data sources or logic can be added into Splunk through apps, making it easier to manage specific use cases in an organized way.

First, I started the Splunk service from `/opt/splunk` using the `bin/splunk start` command and logged in with the provided credentials. Once inside the Splunk web interface, I navigated to the Apps section and created a new app with fields like name, folder path, author, and description. To simulate log ingestion, I created a simple Python script called `samplelogs.py` that printed a single log line. I placed this script in the `bin` directory of the app. Next, I created an `inputs.conf` file that told Splunk to execute the script every five seconds, sending its output to the `main` index with a sourcetype of `testing`. Finally, I restarted Splunk to apply the changes.  

### Steps
1. **Start Splunk**  
   ```bash
   cd /opt/splunk
   bin/splunk start
   ```
I changed into the Splunk installation directory with `cd /opt/splunk` (this is where third-party apps are commonly placed on Linux). From there I started Splunk by running sudo bin/splunk start. The bin folder contains the Splunk executable, so running Splunk start launches the Splunk server processes (the splunkd web server). I hit permission errors when trying to start it without elevated rights, so I prefixed the command with `sudo` to run it as superuser. The console showed the web server coming up and printed the access URL — “The Splunk web interface is at http://tryhackme:8000”, which is the address to open in a browser to reach the running Splunk instance.

2. **Login**
   - Username: `splunk`
   - Password: `splunk123`

3. **Create App**
  - **(3a)** After reaching the Splunk instance via FireFox, I clicked the gear icon next to **Apps** which landed me to a page where there was a table of applications where I could manage them.

<p align="center">
  <img src="images/lab10-splunk-data-manipulation-figure04.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="600"><br>
  <em>Figure 4</em>
</p>

<br></br>
  - **(3b)** Then, I clicked the **[Create app]** button on the top right.

<p align="center">
  <img src="images/lab10-splunk-data-manipulation-figure05.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="600"><br>
  <em>Figure 5</em>
</p>

<br></br>
  - **(3c)** I was redirected to a page where I can add details for my Splunk app. I named the app and folder name **DataApp**, located at `$SPLUNK_HOME/etc/apps/`. I gave it version **1.0.0** as is the first version of this sample app. Lastly, I filled in the remaining details like my name for the **Author**, and a quick **Description**.

<p align="center">
  <img src="images/lab10-splunk-data-manipulation-figure06.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="600"><br>
  <em>Figure 6</em>
</p>

<br></br>
  - **(3d)** I was brought back to the Apps page where you manage all Splunk apps, and saw the app that I've just created: **DataApp**.

<p align="center">
  <img src="images/lab10-splunk-data-manipulation-figure07.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="600"><br>
  <em>Figure 7</em>
</p>

<br></br>
  - **(3e)** I clicked **[Launch App]** under the **Actions** column, which evidently showed that no activity has been logged. **I went ahead and wrote a Python Script for sample logs in step 4.**
    
<p align="center">
  <img src="images/lab10-splunk-data-manipulation-figure08.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="600"><br>
  <em>Figure 8</em>
</p>

<br></br>
  - **(3f)** Before moving to the next step, I stepped back into the Linux terminal (bash shell) and entered the following commands to locate the newly created sample app **from step 3(e)**:

<p align="center">
  <img src="images/lab10-splunk-data-manipulation-figure09.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="600"><br>
  <em>Figure 9</em>
</p>

4. **Write Python Script for Sample Logs**

  - **(4a)** As I learned earlier in this task, the `bin` directory contains the scripts required by the app I have just created. I switched directories to the `/bin` folder and entered `ls` to see a list of available scripts. I withheld the screenshots because it required multiple screenshots to capture the entire list of scripts. There was a sample script file that the lab left us to use. The sample script was named `samplelogs.py`. I entered the command: `nano samplelogs.py` to open the script file, then entered the following:

   ```python
   print("This is a sample log...")
   ```
<p align="center">
  <img src="images/lab10-splunk-data-manipulation-figure10.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="600"><br>
  <em>Figure 10</em>
</p>

<br></br>
   - **(4b)** Saved as `samplelogs.py` in `/bin`. Then ran the script to test.

<p align="center">
  <img src="images/lab10-splunk-data-manipulation-figure11.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="600"><br>
  <em>Figure 11</em>
</p>

5. **Configure inputs.conf**
In this part of the lab, I created an `inputs.conf` file. The reason for doing this is because in Splunk, `inputs.conf` is the configuration file that tells Splunk what data to collect and how to collect it. By defining settings inside `inputs.conf`, I can specify details such as file paths, scripts, or network ports that Splunk should monitor for incoming events. For this part of the lab specifically, the goal was to simulate a real-world scenario where Splunk needs to ingest data from a custom source — in this case, the sample Python script I created earlier that generates simple log messages. By setting up `inputs.conf`, I'm telling Splunk to treat the output of that script as input data and begin indexing it. The purpose of this step is not just to collect fake data, but to understand how Splunk apps bundle configurations that control data ingestion. In production, different apps use their own `inputs.conf` files to define how logs from servers, applications, or security tools are pulled into Splunk. This exercise helps reinforce that idea by walking through the process in a simplified example.

  - **(5a)** At this stage of the lab, I needed to make changes to the sample `inputs.conf` file located in Splunk’s default directory. To get there, I first navigated back to the main Splunk directory so I had a clean starting point. From there, I ran `cd /opt/splunk/etc/system/default` to move into the `default` configuration folder and used `ls` to confirm that the inputs.conf file was there. Once I saw it, I opened it with `nano inputs.conf` to begin editing.

<p align="center">
  <img src="images/lab10-splunk-data-manipulation-figure12.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="600"><br>
  <em>Figure 12</em>
</p>

  - **(5b)** At this stage of the lab, I needed to make changes to the sample `inputs.conf` file located in Splunk’s default directory. To get there, I first navigated back to the main Splunk directory so I had a clean starting point. From there, I ran `cd /opt/splunk/etc/system/default` to move into the `default` configuration folder and used `ls` to confirm that the inputs.conf file was there. Once I saw it, I opened it with `nano inputs.conf` to begin editing.

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


