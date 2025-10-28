# Wireshark: Packet Analysis and Filtering

---

## Introduction / Overview / Objective

<details>

<summary><b>(Click to expand)</b></summary>

### Objective
The purpose of this lab was to explore Wireshark, one of the most widely used network protocol analyzers. My goal was to understand how to navigate its interface, capture and inspect network packets, and analyze data across different layers of the TCP/IP model. Wireshark provides a graphical approach to packet analysis that complements command-line tools like Tcpdump which makes it easier to visualize network activity.

### Overview
Wireshark is an open-source, cross-platform network analyzer capable of sniffing and investigating live network traffic or analyzing stored packet captures (PCAP files). It’s widely used by network engineers, system administrators, and security analysts for troubleshooting and incident response.  
In this lab, I used pre-captured files such as **http1.pcapng** and **Exercise.pcapng** to simulate and analyze network behavior. These files provided realistic packet data to inspect different network layers, display filters, and analyze conversations between hosts.

Before beginning, I reviewed the learning objectives:
- Navigate and configure Wireshark’s user interface.
- Inspect packets and extract information from various layers of TCP/IP.
- Apply and manage display filters for efficient packet analysis.

</details>

---

## Task 1 – Tool Overview

<details>

<summary><b>(Click to expand)</b></summary>

### Objective
This section focused on familiarizing myself with Wireshark’s graphical interface, core features, and basic functionalities. I learned how to load PCAP files, interpret different panes, and understand what each visual section of the interface represents.

### Step-by-Step Walkthrough

I explored Wireshark’s layout, which is divided into sections such as the **Toolbar**, **Display Filter Bar**, **Recent Files**, **Capture Interfaces**, and **Status Bar**.

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-01.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 1</em>
</p>

<h4>(Step 1) Loading and opening PCAP files</h4>
I practiced opening existing capture files like **http1.pcapng** to see packet details displayed in real time.

You can load the PCAP file by either opening it from the "File" menu, dragging and dropping the file directly, or simply double-clicking the file itself. I personally did the drag and drop.



- The packet details were displayed in three key panes:
  - **Packet List Pane** – shows a summary of each captured packet, including protocol, source, destination, and length.
  - **Packet Details Pane** – displays protocol details in a hierarchical structure, such as Ethernet, IP, TCP, and application layer data.
  - **Packet Bytes Pane** – presents hexadecimal and ASCII representations of the selected packet.


- I experimented with **coloring rules**, which visually separate packets by protocol type or condition (e.g., TCP, ARP, ICMP). This made it easier to recognize anomalies or traffic types at a glance.
- I also tested **traffic sniffing**, which captures live packets, and learned how to start and stop captures using the blue “shark fin” icon.
- Finally, I explored Wireshark’s ability to **merge PCAP files**, combine multiple captures, and view detailed file statistics such as total packets, file hash, and SHA256 checksum.

### Findings / Analysis
This task helped me become comfortable with the Wireshark environment. I realized that while it can look overwhelming at first, its layout is designed for efficiency. The ability to colorize, filter, and merge captures helps tremendously when analyzing complex datasets. Packet details across the three panes allowed me to trace communication flow between hosts from the link layer up to the application layer.

### What I Learned
I learned how to load packet captures, interpret Wireshark’s GUI components, and apply default coloring rules. I also understood how Wireshark structures packet data and how to access detailed information efficiently.

</details>

---

## Task 2 – Packet Dissection

<details>

<summary><b>(Click to expand)</b></summary>

### Objective
The objective of this section was to dissect packets at multiple OSI layers and examine detailed protocol information. I wanted to understand how Wireshark decodes network packets and organizes them into structured fields for analysis.

### Step-by-Step Walkthrough
- I examined captured HTTP traffic and learned to break packets down by OSI layers, starting from the physical layer up to the application layer.
- By clicking on a specific packet, Wireshark expanded its contents to reveal information such as Ethernet source/destination MAC addresses, IP headers, TCP flags, and payloads.
- The **Frame layer** showed metadata like arrival time, encapsulation type, and frame length.
- The **Network layer** revealed IP header information, including source and destination IP addresses, protocol version, and time-to-live (TTL) value.
- The **Transport layer** displayed TCP details, including sequence and acknowledgment numbers, flags (SYN, ACK, FIN), and window size.
- The **Application layer** decoded protocols like HTTP, showing request methods, user agents, and URLs accessed.
- I explored **protocol reassembly**, where Wireshark automatically combined fragmented TCP streams to show complete data transfers.

### Findings / Analysis
Packet dissection allowed me to see how data travels through network layers. By analyzing headers, I could identify the path, type, and purpose of packets. I also learned how Wireshark automatically interprets complex fields like checksums and TCP segments, saving time compared to manual decoding. Seeing the full HTTP request headers (like “GET /index.html”) helped connect the transport and application layers.

### What I Learned
I learned to correlate protocol layers to understand end-to-end communication. This exercise gave me hands-on experience tracing traffic from Ethernet frames to TCP streams and application data.

</details>

---

## Task 3 – Packet Navigation

<details>

<summary><b>(Click to expand)</b></summary>

### Objective
This section focused on learning how to efficiently navigate within Wireshark captures, locate specific packets, and manage annotations for deeper analysis.

### Step-by-Step Walkthrough
- I observed that every packet is assigned a **packet number**, which helps in referencing specific entries within a large capture.
- I used the **“Go To Packet”** feature to quickly jump to specific packets by number or relative position.
- I practiced using **Find Packet** to search based on criteria like IP address, protocol, or specific text patterns.
- I learned how to **mark packets** for later reference, which was especially useful when analyzing lengthy captures.
- I explored how to **add comments** to packets for documentation purposes, then viewed and edited them through the Packet Comments panel.
- I tested the **Export Packets** feature, which allowed saving filtered or selected packets into a new capture file.
- I also explored **Export Objects**, a feature that extracts downloadable content (e.g., HTTP files) embedded within packets.
- Lastly, I experimented with adjusting the **Time Display Format**, switching between default and UTC timestamps for better temporal analysis.

### Findings / Analysis
Wireshark’s navigation tools make packet inspection much more manageable. Being able to jump directly to relevant packets or mark them for comparison is extremely useful for forensic analysis. Exporting objects or filtered data creates a more efficient workflow for isolating specific traffic without cluttering the main capture file.

### What I Learned
I learned how to move through large captures effectively, mark and comment on key packets, and export relevant data. These functions are essential for documenting and sharing findings in professional investigations.

</details>

---

## Task 4 – Packet Filtering

<details>

<summary><b>(Click to expand)</b></summary>

### Objective
This section was about understanding and applying packet filtering within Wireshark to isolate traffic of interest. I wanted to practice using display filters to view only relevant protocols or hosts.

### Step-by-Step Walkthrough
- I applied filters using **Apply as Filter**, which allowed me to right-click a field and instantly generate a filter expression.
- I learned how to create **Conversation Filters** to follow specific TCP or UDP streams, showing all packets related to one session.
- I experimented with **Colorise Conversation**, which highlights related packets visually for easier tracking.
- I used **Prepare as Filter** to build a filter expression before activating it, giving me more flexibility.
- I practiced **Follow TCP Stream**, which reconstructs an entire conversation (e.g., HTTP request/response). This view displayed both client and server data in plain text, color-coded by direction.
- I also learned to **Apply as Column**, which adds custom fields (like IP address or protocol) directly into the packet list for easier comparison.

### Findings / Analysis
Filtering drastically improves visibility in large datasets. The ability to highlight or isolate specific streams helped me identify communication patterns, such as repeated requests between hosts. The Follow Stream feature was especially powerful because it reassembled conversations at the application level, allowing me to read HTTP requests and responses like chat logs.

### What I Learned
I learned how to construct and apply Wireshark filters efficiently. Understanding display filters and stream following is essential for analyzing targeted communications and identifying potential issues or malicious behaviors in network traffic.

</details>

---

## Conclusions

<details>

<summary><b>(Click to expand)</b></summary>

### Summary
This lab demonstrated the core capabilities of Wireshark and how it simplifies packet analysis through its graphical interface. I learned to capture, dissect, and filter network traffic while becoming familiar with the structure of PCAP files. Each exercise provided deeper insight into how different layers of network communication interact.

### Reflection
Wireshark is an indispensable tool for both network troubleshooting and cybersecurity investigations. It allowed me to visualize how data moves through various layers, identify anomalies, and reconstruct conversations in real time. Compared to command-line tools, Wireshark offers an intuitive way to interpret complex network behavior.

### What I Learned
Through this lab, I learned how to:
- Navigate Wireshark’s GUI and analyze captured packets.
- Dissect protocols across all OSI layers.
- Apply and customize display filters to isolate traffic of interest.
- Follow conversations and export relevant data for documentation.

Overall, this lab strengthened my foundational understanding of network analysis and gave me the confidence to use Wireshark for real-world packet investigation scenarios.

</details>

---
