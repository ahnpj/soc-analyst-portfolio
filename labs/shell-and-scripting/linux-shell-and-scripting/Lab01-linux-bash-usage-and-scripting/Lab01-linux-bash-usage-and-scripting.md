
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
- Network: VM had a private IPv4 address on ens5 (10.201.72.1, 10.201.6.0, 10.201.19.118, 10.11.90.211).

<p align="left">
  <img src="images/linux-bash-usage-and-scripting-01.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 1</em>
</p>

<blockquote>
This VM was ephemeral / non-persistent. Each time the session was closed and relaunched, the environment reset and a new instance of the machine was provisioned. As a result, the internal/private IP address changed between sessions (addresses in the 10.201.x.x range), any files or configurations created during previous sessions were not retained unless manually exported or saved externally, and the system state (updates, installed packages, running processes, logs) returned to its baseline default image on every new launch.
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
  <img src="images/linux-bash-usage-and-scripting-02.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 2</em>
</p>

> **📌 Personal Learning Note:**  
> I took time to independently review and refresh several Linux command-line fundamentals, including which commands to use for system enumeration, how to interpret their output, and the correct syntax for writing them. This helped reinforce consistent command usage, improved clarity in my workflow, and ensured that I fully understood what each command was doing rather than running them by memory alone.

### Findings / Analysis
The shell provides precision, speed, and flexibility. Many tasks that would require multiple actions in a GUI can be done in one or two commands in the CLI. This reduces time, improves control, and allows customization through scripting.

### What I Learned
I learned that the shell is essential for interacting with Linux on a deeper level. This set the stage for the scripting and automation tasks later in the lab.

</details>

---

## Section 2: Interacting With the Shell

<details>

<summary><b>(Click to expand)</b></summary>
<br>

> **📌 Personal Learning Note:**  
> I took time to independently review and refresh several Linux command-line fundamentals, including which commands to use for system enumeration, how to interpret their output, and the correct syntax for writing them. This helped reinforce consistent command usage, improved clarity in my workflow, and ensured that I fully understood what each command was doing rather than running them by memory alone.

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

<h4>(Step 1) SSH into the Virtual Machine</h4> 

I first connected to the remote machine via SSH using the IP address assigned to the lab instance. After successfully authenticating, I was placed into the terminal session where I could begin interacting with the system. I ran the following command to do so:

`ssh 10.201.19.118`

---

<h4>(Step 2) I began by identifying my location in the system</h4>

I began by running `pwd` (print working directory) to verify my location within the filesystem and confirmed that I was currently in the `/home/user` directory.

---

<h4>(Step 3) Reviewed directory context and refreshed directory traversal concepts</h4>

I revisited directory navigation to refresh my memory on the filesystem context. I used `cd` to move between folders and `cd ..` to step one directory up. The `..` operator reminded me of directory traversal concepts attackers abuse when manipulating relative paths. While performing these checks I captured the outputs and noted the paths I visited for evidence.

---

<h4>(Step 3) Reviewed the grep command</h4>

I revisited the `grep` command, which allows searching for specific keywords or patterns within files. This is especially helpful when dealing with large files, such as logs, where I only need lines that match a certain term. Running `grep` with the desired pattern returned only the lines in the file that contained that keyword.

For example, I could run: `grep "hello" examplefile.txt`, which would return only the lines in `examplefile.txt` that contain the word `"hello"`. This allowed me to quickly locate relevant data.

---

<h4>(Step 4) Reviewed the ls command </h4>

I reviewed the `ls` command to refresh how to list the contents of a directory. This included recalling how ls displays files, subdirectories, and sometimes hidden items depending on the options used. I also revisited several common flags that provide additional detail or change the output format (such as showing file permissions, sizes, and timestamps).

- For example, I could run `ls -la`, which would list all files (including hidden ones) in long format, which displays file permissions, owner, group, size, and modification dates in a structured way. This is especially helpful when determining file visibility and understanding permission settings within a directory.

I also reviewed how to use `ls -l` to display file and directory permissions in long format. The output includes several fields, such as the file type, permission bits, owner, group, file size, and the last modification date. This helped reinforce how Linux controls access to files and directories through permission settings.

- For example, running `ls -l` returned entries such as `drwxr-xr-x` for directories or `-rw-r--r--` for files.

I took time to refamiliarize myself with how to interpret these permission strings, noting that the first character indicates the file type (for example, `d` for directory), followed by three sets of read (`r`), write (`w`), and execute (`e`) permissions for the owner, group, and others. Reviewing this helped reinforce how Linux controls access to files and directories and reminded me that understanding permissions is useful both for routine system interaction and when identifying misconfigurations that could be leveraged in an attack or privilege escalation scenario.

---

<h4> (Step 5) Reviewed other basic commands</h4>

During this session, I also revisited several additional Linux commands that I commonly use for basic enumeration and situational awareness. These included commands such as `whoami` to confirm my current user context, uname `-a` to review kernel and system information, hostname to identify the system name, and `ip a` to inspect network interfaces and assigned IP addresses. I also used `df -h` and `free -h` to check disk and memory usage respectively, along with `ps aux` to view active running processes. 

I additionally tested directory navigation and file interaction commands such as `touch`, `cat`, `less`, `head`, and `tail` to ensure I remained familiar with reading, creating, and examining files directly from the command line. Since these were primarily refreshers and foundational operations that I am already familiar with, I did not document each command output in detail here. The purpose of this review was to re-establish confidence in these core commands so that my focus can remain on analysis and interpretation rather than recalling syntax.

---

### Findings / Analysis
Navigating Linux via the CLI provides fast access to system information. The ability to search text efficiently with commands like `grep` is particularly useful for log and forensic work.

### What I Learned
I reinforced core navigation and file interaction commands in Linux. These are essential commands that I will use frequently as I continue building administrative and security skills.

</details>

---

## Section 3: Types of Linux Shells

<details>

<summary><b>(Click to expand)</b></summary>
<br>

> **📌 Personal Learning Note:**  
> I took time to independently review and refresh several Linux command-line fundamentals, including which commands to use for system enumeration, how to interpret their output, and the correct syntax for writing them. This helped reinforce consistent command usage, improved clarity in my workflow, and ensured that I fully understood what each command was doing rather than running them by memory alone.

### Objective
To learn about different shell types and how they influence command behavior and scripting style. In this part of the lab I stepped back from hands-on exploitation and did more of a structured review.  
The goal was to look at the different Linux shells available on the system, see which one I was actually using, and compare a few popular shells (Bash, Fish, and Zsh) in terms of features and usability.

<blockquote>
This part of the lab was mostly review, but it helped me organize what I already knew about Linux shells into something more systematic
</blockquote>

Even though this section was mostly “review,” I treated it like a small reconnaissance exercise on my own environment.

By the end of this section I had:

- Verified which shell my user account was currently using.
- Enumerated all login shells available on the system.
- Reviewed how to switch between shells temporarily and permanently.
- Compared Bash, Fish, and Zsh from a day-to-day usability perspective:
  - scripting support  
  - tab completion  
  - customization  
  - user friendliness  
  - syntax highlighting

### Step-by-Step Walkthrough

---

**(Step 1)** Checking my current shell

I checked my current shell using `echo $SHELL`. To do so, I started by confirming which shell my session was actually running. In the terminal, I echoed the `$SHELL` environment variable. To do so, I ran the following command: `echo $SHELL`, which identified the active shell I was using.

<p align="left">
  <img src="images/linux-bash-usage-and-scripting-03.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 3</em>
</p>

The output showed: `/bin/bash`. So, as expected, my user was currently using Bash as the default login shell.

---

**(Step 2)** Listing all available shells

I viewed all installed shells using `cat /etc/shells`. I temporarily switched to `Zsh` to see how it behaves differently from `Bash`. 

To achieve this, I first needed to see what other shells were installed and allowed for login on this system. Linux stores this information in `/etc/shells`, so I ran the following command to display the available shells: `cat /etc/shells`.

<p align="left">
  <img src="images/linux-bash-usage-and-scripting-04.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 4</em>
</p>

---

**(Step 3)** Switching shells in the current session

<blockquote>
For this review portion I did not actually change my default shell; instead I focused on understanding the mechanism and when it would be appropriate to use it (for example, if I decided to fully migrate from Bash to Zsh).
</blockquote>

Instead of immediately changing my default shell, I first tested them interactively. For example, to start a `zsh` session from within Bash, I could run `zsh`.

<p align="left">
  <img src="images/linux-bash-usage-and-scripting-05.gif?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 5</em>
</p>

After exiting the Z shell (zsh) setup menu, I manually switched my shell back. To do this, I simply typed `bash` and pressed [Enter]. This immediately returned me to the standard Bash prompt, confirming that I was now back in the Bash environment.

<p align="left">
  <img src="images/linux-bash-usage-and-scripting-06.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 6</em>
</p>

---

**(Step 4)** Reviewing how to change the default shell

I also reviewed how to permanently change the default shell for a user. The command pattern looks like this: `chsh -s /usr/bin/zsh`. 

For this review portion I did not actually change my default shell; instead I focused on understanding the mechanism and when it would be appropriate to use it (for example, if I decided to fully migrate from Bash to Zsh).

---

**(Step 5)** Reviewing Bash (Bourne Again Shell)

I shifted into a more conceptual comparison of shells, starting with Bash.

Key points I reviewed about Bash:
- It is the default shell on many Linux distributions.
- It supports scripting, and most basic shell scripts in the wild are written for Bash or compatible shells.
- Bash has history and tab completion, which make it easier to recall and complete commands.
- It provides decent flexibility but not as much “out-of-the-box” user friendliness or visual niceties as newer shells.

From a security and operations perspective, Bash is still important because a lot of automation, tooling, and older documentation assume Bash or sh compatibility.

---

**(Step 6)** Reviewing Fish (Friendly Interactive Shell)

Next, I went over Fish (Friendly Interactive Shell). This was also a more conceptual comparison of shells, but now with Fish. 

Highlights I noted:
- Fish focuses heavily on user friendliness:
  - Very clean, beginner-friendly prompt.
  - Auto-suggestions based on history and completions.
- It supports scripting, but its scripting syntax differs from POSIX/Bash, which can be a drawback for portability.
- It offers:
  - powerful tab completion,
  - built-in syntax highlighting,
  - and helpful prompts that flag errors as you type.

The main trade-off I took away: Fish is great for interactive use, but not ideal for writing scripts that need to run everywhere.

---

**(Step 7)** Reviewing Zsh (Z Shell)

Finally, I reviewed Zsh, which is kind of a hybrid between a traditional Unix shell and a more modern, highly customizable environment.

Key points I reviewed:
- Zsh is often described as a “modern shell” that blends features from other shells.
- It supports advanced tab completion and powerful customization through frameworks and plugins (e.g., oh-my-zsh).
- Like Fish, it offers:
  - syntax highlighting,
  - better auto-completion,
  - and a lot of room for theming and prompt customization.
- It remains quite compatible with Bash-style scripting, which makes it more attractive than Fish for people who want both scripting and a nice interactive experience.

I came away with the impression that Zsh is a strong “daily-driver” candidate for power users, especially when combined with plugins.

---

**(Step 7)** Comparing Bash, Fish, and Zsh

I did personal research and reviewed a comparison table for Bash, Fish, and Zsh across several categories. I summarized it for myself like this:

**Scripting**
- Bash: Widely used and highly compatible. Most scripts target Bash or POSIX sh.
- Fish: Supports scripting but uses its own syntax; less portable.
- Zsh: Very capable scripting support and largely compatible with existing shell scripts.

**Tab Completion**
- Bash: Basic completion; can be extended with extra configuration.
- Fish: Very advanced completion with intelligent suggestions.
- Zsh: Extremely powerful completion, especially with plugin frameworks.

**Customization**
- Bash: Customizable via .bashrc and other config files, but mostly manual.
- Fish: Interactive tools make customization easier, especially for prompts.
- Zsh: Extremely customizable; plugin managers and frameworks make it easy to build a very tailored shell.

**User Friendliness**
- Bash: Familiar and traditional; many users are comfortable with it.
- Fish: Probably the most user-friendly out of the box.
- Zsh: Can be very friendly, especially after some initial setup.

**Syntax Highlighting**
- Bash: Not built in; requires third-party tools or custom configuration.
- Fish: Built-in syntax highlighting by default.
- Zsh: Syntax highlighting is typically enabled via plugins, but works very well.

This reinforced the idea that there’s no “one best shell”; it really depends on whether I care more about compatibility, interactivity, or customization.

---

### Findings / Analysis
Bash is widely used and is a stable, script-friendly option. Shells like Zsh and Fish offer more interactive features such as improved tab completion and syntax highlighting.

### What I Learned
I learned that different shells can improve workflow depending on preference and environment. This helped me understand why administrators may choose one shell over another.

Even though this part of the lab was mostly review, it helped me organize what I already knew about Linux shells into something more systematic:

- I confirmed how to identify and enumerate shells on a Linux system using $SHELL and /etc/shells.
- I saw how easy it is to test different shells interactively without changing system defaults.
- I revisited the strengths and weaknesses of Bash, Fish, and Zsh, especially in terms of scripting vs. interactive use.
- From a security/ops perspective, I’m reminded that:
  - Bash remains a baseline skill because of its ubiquity in scripts and tooling.
  - Fish and Zsh can dramatically improve productivity and reduce typing mistakes in day-to-day terminal work.

If I were to change my default shell in the future, I’d likely experiment with Zsh plus a plugin framework, while still keeping Bash skills sharp for scripts and servers that only offer the standard tools.

</details>

---

## Section 4: Shell Scripting and Components

<details>

<summary><b>(Click to expand)</b></summary>
<br>

> **📌 Personal Learning Note:**  
> I took time to independently review and refresh several Linux command-line fundamentals, including which commands to use for system enumeration, how to interpret their output, and the correct syntax for writing them. This helped reinforce consistent command usage, improved clarity in my workflow, and ensured that I fully understood what each command was doing rather than running them by memory alone.

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
<br>

> **📌 Personal Learning Note:**  
> I took time to independently review and refresh several Linux command-line fundamentals, including which commands to use for system enumeration, how to interpret their output, and the correct syntax for writing them. This helped reinforce consistent command usage, improved clarity in my workflow, and ensured that I fully understood what each command was doing rather than running them by memory alone.

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
<br>

> **📌 Personal Learning Note:**  
> I took time to independently review and refresh several Linux command-line fundamentals, including which commands to use for system enumeration, how to interpret their output, and the correct syntax for writing them. This helped reinforce consistent command usage, improved clarity in my workflow, and ensured that I fully understood what each command was doing rather than running them by memory alone.

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
