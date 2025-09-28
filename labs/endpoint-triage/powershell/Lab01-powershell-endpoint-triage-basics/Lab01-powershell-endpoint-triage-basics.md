# PowerShell Lab Report (Tasks 3–8)

This lab report documents my hands-on work with PowerShell. Each section demonstrates not only the commands I used but also why I used them, how they can be applied in real-world security or administrative contexts, and what insights they provided. The goal is to showcase practical skills and understanding of how PowerShell can be leveraged effectively.

---

## Task 3: PowerShell Basics

### What I Did
I started by connecting to the target lab machine via SSH and launching PowerShell. Once inside, I explored how PowerShell structures its commands with the `Verb-Noun` format. I then practiced discovering available commands and getting help on their usage.

### Commands I Used
- `powershell`
- `Get-Command`
- `Get-Command -CommandType Function`
- `Get-Help Get-Date`
- `Get-Alias`
- `Find-Module -Name "PowerShell*"`
- `Install-Module -Name PowerShellGet`

### Why This Matters
This exercise helped me build the foundation for all future tasks. For example:  
- `Get-Command` and `Get-Help` are my go-to references when I don’t remember exact syntax.  
- Aliases like `dir` → `Get-ChildItem` show how PowerShell bridges the gap with older shells.  
- Installing modules (`Install-Module`) demonstrates how PowerShell can be extended for tasks such as Active Directory management or forensic analysis.

### Real-World Value
Recruiters should note: I can confidently navigate PowerShell, discover the tools available, and extend its capabilities with modules. This is exactly what’s needed when moving between different environments and tools on the job.

---

## Task 4: Navigating the File System and Working with Files

### What I Did
Here I explored the file system — listing directories, moving around, creating new files/folders, copying them, and even reading content. Instead of memorizing different commands like in CMD (`dir`, `cd`, `mkdir`), I worked with consistent PowerShell cmdlets.

### Commands I Used
- `Get-ChildItem`
- `Set-Location -Path`
- `New-Item -ItemType Directory`
- `New-Item -ItemType File`
- `Remove-Item`
- `Copy-Item`
- `Move-Item`
- `Get-Content`

### Why This Matters
I got practice in performing file operations in a structured way:  
- `New-Item` handles both files and folders, simplifying automation.  
- `Remove-Item`, `Copy-Item`, and `Move-Item` replace multiple traditional commands.  
- `Get-Content` is especially useful for reading text and log files — key in incident response and troubleshooting.

### Real-World Value
This skill translates to **log analysis, evidence collection, and forensic tasks**, where I need to quickly move through a file system, copy artifacts, and view contents without opening external editors.

---

## Task 5: Piping, Filtering, and Sorting Data

### What I Did
I practiced chaining commands together with pipes, sorting files by size, filtering by extension, and even searching text within files. This is where PowerShell’s object-oriented design really showed its strength.

### Commands I Used
- `Get-ChildItem | Sort-Object Length`
- `Get-ChildItem | Where-Object -Property Extension -eq ".txt"`
- `Get-ChildItem | Where-Object -Property Name -like "ship*"`
- `Get-ChildItem | Select-Object Name, Length`
- `Select-String -Path .\captain-hat.txt -Pattern "hat"`

### Why This Matters
Instead of manually checking each file, I automated the process:  
- Sorting by size lets me quickly identify unusually large or suspicious files.  
- Filtering by extension helps when hunting for specific file types (like `.log` or `.exe`).  
- `Select-String` gave me the equivalent of `grep` — powerful for scanning logs for IOCs.

### Real-World Value
In a SOC environment, I could use this same method to **parse event logs, filter by criteria, and search for suspicious strings** without needing third-party tools.

---

## Task 6: System and Network Information

### What I Did
I retrieved system information, checked for local users, and pulled detailed network configuration and IP assignments.

### Commands I Used
- `Get-ComputerInfo`
- `Get-LocalUser`
- `Get-NetIPConfiguration`
- `Get-NetIPAddress`

### Why This Matters
These commands provided me with:  
- A complete system snapshot (`Get-ComputerInfo`).  
- A list of all local accounts, which is critical for detecting hidden or unauthorized users.  
- Networking details including DNS and gateway configuration — the same data often checked during incident response.  

### Real-World Value
This aligns with **host auditing and reconnaissance**. For example, if I suspect persistence mechanisms or hidden accounts, I can use these commands to validate the system baseline.

---

## Task 7: Real-Time System Analysis

### What I Did
I moved into monitoring mode — checking processes, services, open connections, and verifying file integrity with hashes.

### Commands I Used
- `Get-Process`
- `Get-Service`
- `Get-NetTCPConnection`
- `Get-FileHash`

### Why This Matters
- `Get-Process` shows CPU/memory usage — key for spotting rogue processes.  
- `Get-Service` reveals which services are running or disabled. Attackers often tamper with these.  
- `Get-NetTCPConnection` gives visibility into open network connections — crucial for uncovering backdoors or suspicious outbound traffic.  
- `Get-FileHash` verifies if a file has been altered (tampered with malware, for example).

### Real-World Value
This mirrors what I’d do as an analyst during **threat hunting or incident response**, where checking processes, services, and connections is often step one.

---

## Task 8: Scripting

### What I Did
I wrapped up by practicing PowerShell scripting, focusing on how to automate repetitive tasks and even execute commands remotely with `Invoke-Command`.

### Commands I Used
- `Get-Help Invoke-Command -examples`
- `Invoke-Command -FilePath script.ps1 -ComputerName Server01`
- `Invoke-Command -ComputerName Server01 -ScriptBlock { Get-Culture }`

### Why This Matters
- I learned how scripts can save time and reduce human error by automating repetitive tasks.  
- Remote execution is especially important: with `Invoke-Command`, I could push commands to multiple systems at once.  
- This is applicable in both defensive tasks (running IOC scans across a network) and offensive testing (enumerating systems).

### Real-World Value
This demonstrates I can **scale operations across environments**. Recruiters should see this as a practical skill: I’m not only comfortable with individual commands, but also capable of designing and running scripts to automate security workflows.

---

# Closing Notes
Across Tasks 3–8, I moved from learning the basics of PowerShell to applying it for **file management, data filtering, system analysis, and scripting automation**. These exercises show that I can use PowerShell not just as a command-line tool, but as a versatile platform for **system administration, security monitoring, and incident response**.

