# Tcpdump Packet Capture and Filtering

---

## Introduction / Overview / Objective

<details>

<summary><b>(Click to expand)</b></summary>

### Objective
The purpose of this lab was to explore the Tcpdump command-line tool for packet capture and filtering. I wanted to learn how to collect, view, and analyze network packets using real commands instead of relying on graphical tools like Wireshark. Tcpdump gives analysts the ability to see network traffic at a very granular level, making it a valuable skill for network troubleshooting and cybersecurity analysis. 

### Overview
Tcpdump is built on the **libpcap** library, which is responsible for capturing packets from network interfaces. On Windows systems, the equivalent library is **WinPcap**. Both provide low-level access to network data, allowing analysts to observe traffic in real time. In this lab, I performed multiple exercises that involved capturing live traffic, saving packet data to `.pcap` files, filtering specific protocols, and learning advanced filtering expressions.

I began by reviewing basic network concepts such as IP addressing, protocols, and the TCP/IP model. Then, I started a virtual lab machine, which allowed me to run Tcpdump commands in a controlled environment. The following sections document the commands I ran, what they accomplished, and what I learned from each step.

### Environment
I accessed a remote Ubuntu 20.04 LTS Linux environment via SSH to perform command-line and system analysis tasks. I entered commands in the Linux terminal (bash shell) of an Ubuntu virtual machine.

- **OS:** Ubuntu 20.04.6 LTS
- **Kernel:** 5.15.0-1066-aws → indicates it’s hosted on AWS
- **Access Type:** SSH (remote login)
- **Environment Type:** Virtual Machine (VM)
- **IP Address: 10.201.121.21** (private network, internal lab subnet)

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_01.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="500"><br>
  <em>Figure 1</em>
</p>

</details>

---

## Task 1 – Basic Packet Capture

<details>

<summary><b>(Click to expand)</b></summary>

### Objective
The goal of this section was to understand how to perform basic packet captures using Tcpdump, specify which network interface to listen on, and save the captured data for later review.

### Step-by-Step Walkthrough

<h4>(Step 1) I first checked which network interfaces were available</h4> 

I checked which network interfaces were available to decide which one to listen to by using the command `ip a s` (which is short for `ip address show`). This showed interfaces like `lo` for loopback and `ens5` for Ethernet.

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_02.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="500"><br>
  <em>Figure 2</em>
</p>

<h4>(Step 2) I started a capture session by specifying the interface</h4>

I started a capture session by specifying the interface with the command `sudo tcpdump -i ens5 -c 5 -n`. This began printing live traffic directly to the terminal.

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_03.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="500"><br>
  <em>Figure 3</em>
</p>

The command `sudo tcpdump -i ens5 -c 5 -n` told the system to listen on the `ens5` network interface, capture five packets, and display them without converting IPs to hostnames. Running it with sudo gave the necessary root permissions to access the network interface.

After execution, the output showed five TCP packets exchanged between local IPs. This confirmed that the `ens5` interface was active and that I successfully captured real network traffic in real time using tcpdump.

<!--
- To save packets to a file for later analysis, I used the `-w` flag, such as `sudo tcpdump -i ens5 -w data.pcap`. The file extension `.pcap` allows compatibility with other tools like Wireshark.
- I learned how to read previously captured packets using `tcpdump -r data.pcap`, which replays packets in readable form.
- I limited the capture size using the `-c` flag, for example `-c 10`, which stops the capture after a specific number of packets.
- To avoid unnecessary DNS lookups and make the output faster and cleaner, I used `-n` or `-nn` to prevent IP and port name resolution.
- I increased verbosity with `-v`, `-vv`, and `-vvv` to see more details about each packet, such as TTL, window size, and protocol flags.
-->

### Findings / Analysis
I found that Tcpdump provides full control over how much data I capture and display. It can quickly become overwhelming if I do not use filters or limit the capture. Saving captures to files is helpful for detailed analysis later, especially if I need to share results or correlate with intrusion detection tools.
- Using `-n` and `-c` made the capture process much more efficient, and verbosity levels provided flexibility depending on how deep I wanted to go into packet details.

I learned how to use tcpdump more effectively to capture and analyze network packets. 
- I discovered that I could save captured packets to a file by using the `-w` flag, for example `sudo tcpdump -i ens5 -w data.pcap`. The `.pcap` file format can be opened later in tools like Wireshark for deeper inspection.
- I also learned that I can replay previously captured packets using the `-r` flag, which makes it easier to review network activity without running a live capture again.

I practiced limiting captures.
- I used the `-c` option, which stopped recording after a specific number of packets, and
- I used `-n` (tells tcpdump not to resolve DNS) or `-nn` (tells tcpdump not to resolve port names) to prevent hostname and port name lookups, showing only the numeric value.
- Using `-v`, `-vv`, or `-vvv` helped display extra details such as TTL values, window sizes, and protocol flags. For the purposes of this lab, I used a capture file named `data.pcap` to test these features and better understand how tcpdump works for basic packet analysis.

### What I Learned
I learned how to start and stop packet captures, choose interfaces, and save or replay packet data. These basic Tcpdump skills are the foundation for more advanced filtering and analysis techniques that I used later in the lab.

</details>

---

## Task 2 – Filtering Expressions

<details>

<summary><b>(Click to expand)</b></summary>

### Objective
This section was about learning how to focus my captures on specific hosts, ports, or protocols using Tcpdump filtering expressions. Without filters, packet captures can be massive and difficult to analyze.

### Step-by-Step Walkthrough
- I started by filtering packets from a specific host using `sudo tcpdump host example.com -w http.pcap`. This allowed me to capture only traffic to and from that domain.
- I practiced filtering by direction using `src host` and `dst host` to focus on source or destination traffic only.
- To capture traffic from specific ports, I used `sudo tcpdump -i ens5 port 53 -n`, which captured DNS requests and responses (since DNS uses port 53).
- I used `src port` and `dst port` to filter traffic going to or coming from a particular service.
- I filtered by protocol using commands like `sudo tcpdump -i ens5 icmp -n` to capture only ICMP traffic, which showed ping requests and replies.
- Finally, I combined multiple filters with logical operators like `and`, `or`, and `not` to refine the output. For example, `tcpdump tcp and port 80` captured only HTTP packets, while `not port 22` excluded SSH traffic.

### Findings / Analysis
Filtering made a huge difference in how readable and manageable the packet data was. Instead of seeing thousands of lines of unrelated traffic, I could focus on the specific interactions I cared about. For example, filtering ICMP packets showed how ping operates at the network layer, while filtering port 53 helped me visualize DNS resolution. Logical operators allowed me to build complex yet very precise queries.

### What I Learned
I learned how to construct efficient filters to capture only what I needed. In real-world network investigations, this ability to narrow down traffic is crucial. It saves time and focuses analysis on relevant packets, whether for troubleshooting, intrusion detection, or malware analysis.

</details>

---

## Task 3 – Advanced Filtering

<details>

<summary><b>(Click to expand)</b></summary>

### Objective
In this task, I experimented with more advanced Tcpdump filters, including binary operations, packet length comparisons, and TCP flag analysis.

### Step-by-Step Walkthrough
- I used filters like `greater LENGTH` and `less LENGTH` to display packets based on their size. For instance, `tcpdump greater 1000` captured packets larger than 1000 bytes.
- I reviewed binary operations (`&`, `|`, and `!`) to understand how Tcpdump processes bits. These operations are often used in protocol-level filtering.
- I explored the concept of header bytes and learned that I could filter based on specific byte positions using the syntax `proto[expr:size]`. This allowed for very detailed inspection, such as targeting parts of the Ethernet or IP header.
- I then focused on TCP flags. Using expressions like `tcp[tcpflags] == tcp-syn`, I was able to isolate SYN packets, which represent connection initiation.
- I also captured ACK and FIN packets using variations such as:
  - `tcp[tcpflags] & tcp-ack != 0`
  - `tcp[tcpflags] & (tcp-syn|tcp-ack) != 0`

### Findings / Analysis
This section revealed how powerful Tcpdump can be when analyzing lower-level protocol behavior. By filtering specific TCP flags, I could observe the TCP handshake (SYN, SYN-ACK, ACK) in action. This understanding is essential for identifying abnormal connection behavior or incomplete handshakes that may indicate scanning or denial-of-service attempts.

### What I Learned
I learned how to perform deep-level packet analysis using binary logic and TCP flag filtering. These skills are particularly valuable for cybersecurity investigations where recognizing network patterns—such as repeated SYN packets without ACKs—can reveal potential attacks.

</details>

---

## Task 4 – Displaying Packets

<details>

<summary><b>(Click to expand)</b></summary>

### Objective
This section focused on customizing Tcpdump’s output to better interpret packet data. I learned how to display packet headers and payloads in multiple formats, including ASCII and hexadecimal.

### Step-by-Step Walkthrough
- I displayed basic packet information with `tcpdump -r TwoPackets.pcap` to review captured data.
- To simplify the output, I used `-q` for “quick” mode, which only showed source/destination IPs and ports.
- To include MAC addresses and Ethernet headers, I added the `-e` flag.
- To view packet data in readable text, I used `-A`, which printed the ASCII representation of the packet contents.
- For a raw hexadecimal view, I added `-xx`, which printed the bytes of each packet.
- Finally, I combined both hex and ASCII output using `-X`, which showed packets in both formats simultaneously.

### Findings / Analysis
Each display mode serves a different purpose. ASCII mode (`-A`) was useful when inspecting plaintext protocols like HTTP, while hexadecimal mode (`-xx`) provided insight into binary structures and headers. The combined `-X` mode made it easy to correlate header data with payload information. These display options help analysts interpret packets quickly, especially when verifying encoded data or identifying suspicious payloads.

### What I Learned
I learned how to present captured packets in various output styles depending on the analysis goal. This flexibility is important when switching between examining human-readable text and low-level network structures.

</details>

---

## Conclusions

<details>

<summary><b>(Click to expand)</b></summary>

### Summary
Throughout this lab, I practiced using Tcpdump to capture, filter, and interpret network traffic from a command-line interface. I moved from basic captures to advanced filtering techniques that allowed me to identify very specific types of network activity. The experience reinforced how important it is to filter data effectively, since raw packet captures can be overwhelming without structure.

### Reflection
Tcpdump is lightweight but incredibly powerful. Unlike graphical tools, it provides immediate insight without requiring a large amount of system resources. By learning its syntax and options, I can now use it to diagnose connectivity issues, observe protocol behavior, and even detect potential malicious traffic. Combining Tcpdump with tools like Wireshark or Splunk could create a strong foundation for deeper network investigations.

### What I Learned
I learned how to:
- Identify and capture traffic from specific interfaces.
- Save and replay captured packets.
- Apply filters for hosts, ports, and protocols.
- Use binary and TCP flag operations for deeper inspection.
- Display packet data in both human-readable and hexadecimal formats.

Overall, this lab strengthened my ability to use Tcpdump as a practical analysis tool for both troubleshooting and security purposes.

</details>
