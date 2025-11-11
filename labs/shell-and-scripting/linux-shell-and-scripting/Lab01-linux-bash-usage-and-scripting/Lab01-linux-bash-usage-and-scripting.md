
# Lab01 – Linux Shells and Scripting

## Section 1: Introduction to Linux Shells

<details>

<summary><b>(Click to expand)</b></summary>

### Objective

The objective of this section was to understand what a Linux shell is and why interacting with a system through the command line can be more efficient than relying solely on a graphical interface. I wanted to build a foundational understanding of how the shell acts as the intermediary between the user and the operating system.

I revisited the relationship between the shell and the kernel, reinforcing that the kernel performs core system and hardware management, while the shell acts as the interactive layer that interprets user commands and relays them to the kernel.

<blockquote>
The environment used a Linux terminal running the Bash shell, where I entered and executed commands directly through the command-line interface.
</blockquote>

### Step-by-Step Walkthrough

I reviewed the difference between the Graphical User Interface (GUI) and the Command Line Interface (CLI). While the GUI is visually intuitive and easier for everyday use, it hides internal system operations. The shell, by comparison, provides direct control. When I type a command, the shell interprets the instruction and communicates with the system to execute it.

This connected well with what I learned while studying for the CompTIA Security+ exam, where system administration and command-line usage are heavily emphasized in security tasks.

**Steps I followed:**
- Observed how the GUI and CLI offer different levels of control.
- Learned that the shell interprets user commands and relays them to the OS.
- Understood how CLI access is foundational in system administration and automation.

### Environment Setup

**Lab environment — quick summary**

- Environment: Ubuntu 20.04.6 LTS (x86_64), Linux kernel 5.15.0-1068-aws on a remote virtual machine.
- User: user (shell prompt shown).
- Network: VM had a private IPv4 address on ens5 (10.201.72.1).

<blockquote>
This VM was ephemeral / non-persistent. Each time the session was closed and relaunched, the environment reset and a new instance of the machine was provisioned. As a result, the internal/private IP address changed between sessions (e.g., addresses in the 10.x.x.x range), any files or configurations created during previous sessions were not retained unless manually exported or saved externally, and the system state (updates, installed packages, running processes, logs) returned to its baseline default image on every new launch.
</blockquote>

**System Concepts Review**

I took time to review and reinforce the relationship between the operating system, the kernel, and the shell. I confirmed that the operating system provides the full environment the machine runs on, while the kernel is the core component that directly manages hardware resources such as memory, CPU, storage, and devices. The shell serves as the user-facing interface that accepts commands and passes them to the kernel for execution.

I also refreshed the differences between common shells. In this environment, I used Bash, which is the default shell on most Linux systems and supports both interactive commands and shell scripting. I compared this to PowerShell on Windows, which serves a similar purpose as a command interface but also functions as a scripting language and works with objects rather than plain text. I also noted the distinction from the older Windows Command Prompt (cmd.exe), which is more limited in functionality compared to PowerShell.

This review helped clarify how the pieces fit together:

- OS = full system environment
- Kernel = low-level manager that talks to hardware
- Shell = interface that interprets and runs user commands
- Bash = common Linux shell and scripting environment
- PowerShell = Windows shell and scripting language with object-based processing

**What I did (initial steps)**

1. Connected to the remote VM (SSH) and observed the MOTD/welcome banner giving immediate system info.
2. Ran basic reconnaissance commands to confirm the banner values and gather more detail:
    - `uname -a` — confirmed kernel and architecture.
    - `lsb_release -a` — confirmed Ubuntu 20.04.6 LTS.
    - `ip -4 addr show ens5` — verified the VM’s private IPv4 on ens5.
    - `free -h` — checked memory usage and swap status.
    - `df -h /` — checked root filesystem size and usage.
    - `whoami` — confirmed current user and groups.
    - `last -a | head` — reviewed last logins (banner also showed last login).
    - `sudo apt update && apt list --upgradable` — checked package update status (banner indicated many updates).

<p align="left">
  <img src="images/linux-bash-usage-and-scripting-01.png?raw=true&v=2" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
</p>

### Findings / Analysis
The shell provides precision, speed, and flexibility. Many tasks that would require multiple actions in a GUI can be done in one or two commands in the CLI. This reduces time, improves control, and allows customization through scripting.

### What I Learned
I learned that the shell is essential for interacting with Linux on a deeper level. This set the stage for the scripting and automation tasks later in the lab.

</details>

---

## Section 2: Interacting With the Shell

<details>

<summary><b>(Click to expand)</b></summary>

### Objective
To learn how to perform basic navigation, view files, and execute commands within the Linux terminal.

### Step-by-Step Walkthrough

I opened the terminal and began by identifying my location in the system with `pwd` (print working directory). I used `cd` to move into different folders and used `ls` to view the contents of directories. When I encountered files, I used `cat` to display their contents. I also used `grep` to search for specific terms inside files.

This approach reminded me how analysts rely heavily on log searching and file parsing when investigating incidents.

**Commands I practiced:**
- `pwd` — showed my current directory.
- `ls` — listed files and directories.
- `cd <directory>` — moved into another directory.
- `cat <file>` — displayed file contents.
- `grep <pattern> <file>` — searched for specific text.

---

<h4>(Step 1)</h4>

### Findings / Analysis
Navigating Linux via the CLI provides fast access to system information. The ability to search text efficiently with commands like `grep` is particularly useful for log and forensic work.

### What I Learned
I reinforced core navigation and file interaction commands in Linux. These are essential commands that I will use frequently as I continue building administrative and security skills.

</details>

---

## Section 3: Types of Linux Shells

<details>

<summary><b>(Click to expand)</b></summary>

### Objective
To learn about different shell types and how they influence command behavior and scripting style.

### Step-by-Step Walkthrough

I checked my current shell using `echo $SHELL`. Then, I viewed all installed shells using `cat /etc/shells`. I temporarily switched to Zsh to see how it behaves differently from Bash.

**Commands I used:**
- `echo $SHELL` — identified the active shell.
- `cat /etc/shells` — listed available shells.
- Launched alternate shell using `zsh`.

### Findings / Analysis
Bash is widely used and is a stable, script-friendly option. Shells like Zsh and Fish offer more interactive features such as improved tab completion and syntax highlighting.

### What I Learned
I learned that different shells can improve workflow depending on preference and environment. This helped me understand why administrators may choose one shell over another.

</details>

---

## Section 4: Shell Scripting and Components

<details>

<summary><b>(Click to expand)</b></summary>

### Objective
To begin writing shell scripts and understand how variables, loops, and conditional statements support automation.

### Step-by-Step Walkthrough

I created my first shell script and included a shebang (`#!/bin/bash`) to define the interpreter. I practiced using variables, loops, and conditional logic. Before running the script, I applied execution permissions with `chmod +x`.

**Commands and structure I practiced:**
- Creating a script: `nano script.sh`
- Declaring variables and referencing them with `$var`
- Writing loops like `for i in {1..10}; do ...; done`
- Using conditionals:
```
if [ condition ]; then
   ...
fi
```
- Making the script executable: `chmod +x script.sh`

### Findings / Analysis
Scripting allows repetitive tasks to be automated reliably. Conditional logic allows scripts to adapt based on input or system state.

### What I Learned
Understanding how to write scripts opens the door to automation. This is essential in system administration and incident response.

</details>

---

## Section 5: The Locker Script

<details>

<summary><b>(Click to expand)</b></summary>

### Objective
To build a script that validates user input using conditionals.

### Step-by-Step Walkthrough

I wrote a script that requested a username, company name, and PIN. The script compared input against required values. If all three matched, access was granted; otherwise, access was denied.

### Findings / Analysis
This script simulated simple authentication logic. It highlighted the importance of correct condition syntax and secure handling of input.

### What I Learned
This exercise strengthened my understanding of how simple security checks can be automated.

</details>

---

## Section 6: Practical Exercise

<details>

<summary><b>(Click to expand)</b></summary>

### Objective
To use scripting to search system logs for specific keywords.

### Step-by-Step Walkthrough

I switched to root using `sudo su` and examined a script that parsed `.log` files under `/var/log`. I filled in missing values and ran the script to extract a hidden answer.

### Findings / Analysis
This exercise reinforced how scripts can automate system monitoring tasks.

### What I Learned
I learned how shell scripts apply directly to real-world administration and security workflows.

<details>

<summary><b>(Click to expand)</b></summary>

---

## Section 7: Conclusion

<details>

<summary><b>(Click to expand)</b></summary>

I built confidence navigating the Linux shell and writing scripts to automate system tasks. These skills align directly with system administration and security operations tasks, especially those covered in Security+.

</details>
