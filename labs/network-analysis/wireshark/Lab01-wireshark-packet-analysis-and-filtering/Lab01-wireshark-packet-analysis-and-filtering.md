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

---

<h4>(Step 1) Loading and opening PCAP files</h4>
I practiced opening existing capture files like **http1.pcapng** to see packet details displayed in real time.

<blockquote>
You can load the PCAP file by either opening it from the "File" menu, dragging and dropping the file directly, or simply double-clicking the file itself. I personally did the drag and drop.
</blockquote>

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-02.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 2</em>
</p>

The packet details were displayed in three key panes:
  - **Packet List Pane** – shows a summary of each captured packet, including protocol, source, destination, and length. (top pane)
  - **Packet Details Pane** – displays protocol details in a hierarchical structure, such as Ethernet, IP, TCP, and application layer data. (bottom-left pane)
  - **Packet Bytes Pane** – presents hexadecimal and ASCII representations of the selected packet. (bottom-right pane)

---

<h4>(Step 2) Exploring Packet Coloring</h4>

I explored Wireshark’s default packet colouring system and learned how it helps quickly identify different protocols and spot anomalies at a glance. I did so by working with both **temporary** and **permanent** coloring rules going to **View → Coloring Rules** and using the options in the **Wireshark - Coloring Rules Default** modal that appeared, to create or manage them. 

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-03.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 3</em>
</p>

At first, I was confused about why most of the TCP packets in my Wireshark capture were showing up green instead of purple, even though the default TCP colouring rule was clearly set to purple. 

After checking the **Coloring Rules** window, I realized that Wireshark applies colours based on the first matching rule from top to bottom. That means if a packet matches a rule higher in the list (like “Bad TCP” or another green rule), Wireshark uses that colour and doesn’t continue checking further rules. 

Once I understood this priority system, it made sense why most of my TCP packets appeared green. They were simply being matched by an earlier rule in the list before the default purple TCP rule.

<blockquote>
I later experimented with toggling the “Colorize Packet List” feature and using conversation filters for temporary highlighting. Overall, I now understand how packet colours can make analysis more efficient and how to customize these rules for specific events of interest.
</blockquote>

---

<h4>(Step 3) Traffic Sniffing</h4>

I also tested **traffic sniffing**, which captures live packets, and learned how to start and stop captures using the blue “shark fin” icon.

I wanted to try capturing live network traffic in Wireshark, so I went to **Capture → Options** and looked through the available interfaces. I selected “Cisco remote capture: ciscodump,” thinking it was my network interface, but I later learned it’s actually used for remote captures from Cisco devices, not local network traffic. The other interfaces listed were also virtual or system-based, not real network adapters. Because there were no active local interfaces, the **[Start Capture]** button stayed greyed out.

---

<h4>(Step 4) Merging PCAP Files and Viewing File Details</h4>

I explored Wireshark’s ability to **merge PCAP files** (**File > Merge**), combine multiple captures, and view detailed file statistics such as total packets, file hash, and SHA256 checksum.

I decided to try merging another .pcap file with my current capture to see how Wireshark handles multiple data sources in one timeline. Merging pcap files is useful when you want to analyze traffic captured from different interfaces or at different times together. For example, combining client and server captures to see the full conversation, or merging sequential captures to create one continuous session. It helps provide a more complete picture of network activity without having to switch between separate files.

---

<h4>(Step 4-a) I merged a separate PCAP file to the one that was already uploaded</h4>

First, I went to **File > Merge**, then merged **Exercise.pcapng** to **http1.pcapng**.

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-04.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 4</em>
</p>

---

<h4>(Step 4-b) Viewed File Details</h4>

I went to **Statistics → Capture File Properties** because I wanted to see more information about the capture file itself, such as when it was created, what interface it came from, the SHA256 hash value, and what format or capture options were used. Viewing file details is important because it helps verify the context of the capture. For example, confirming the capture duration, packet count, and source interface can all be crucial for accurate analysis. It ensures you understand where the data originated and whether anything might affect how you interpret the packets.

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-05.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 5</em>
</p>

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

I examined captured HTTP traffic and learned to break packets down by OSI layers, starting from the physical layer up to the application layer. By clicking on a specific packet, Wireshark expanded its contents to reveal information such as Ethernet source/destination MAC addresses, IP headers, TCP flags, and payloads.

For this task, I focused in on a specific packet, which was packet #27 which was using the HTTP protocol. 

The **Packet Details Pane** pane at the bottom-left lists each decoded protocol layer, while the **Packet Bytes Pane** pane at the bottom-right displays the raw hexadecimal data that was actually captured on the wire.

When I click any field in the **Packet Details Pane** pane at the bottom-left, Wireshark automatically highlights the exact bytes in the **Packet Bytes Pane** pane at the bottom-right hex view that correspond to that field.

This color-linking helped me visualize how the human-readable protocol information is stored as raw binary data:
- Each row in the hex view shows 16 bytes (the actual bits sent over the network).
- Wireshark maps those bytes to their decoded meaning, so when you select, say, the “Source IP” line, the four bytes representing that IP address turn blue in the hex pane.
- This makes it easy to trace any part of a packet back to its raw data representation and see how the packet is built layer-by-layer.

### Step-by-Step Walkthrough

---

<h4>(Step 1): The Frame Layer (Layer 1 - Physical) </h4>

The **Frame layer** (Layer 1 - Physical) showed metadata like arrival time, encapsulation type, and frame length. 

In this Wireshark capture, the **Frame** section represents information captured at Layer 1 (Physical layer) of the OSI model, which is the point where raw bits are transmitted across the physical medium (like an Ethernet cable or Wi-Fi).

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-06.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 6</em>
</p>

The details in the red box show what Wireshark records about that physical transmission rather than the data itself.

Specifically:
- Frame 27 identifies the specific packet captured out of all the traffic on the wire.
- 214 bytes on wire, 214 bytes captured means the full frame was successfully captured from the physical medium.
- Encapsulation type: Ethernet (1) tells us this capture was taken on an Ethernet network which is the physical and data-link technology used.
- Arrival Time / Epoch Time / Time delta fields show when the signal reached the network interface and how much time elapsed between packets. This relates to the timing of bit transmission on the medium.
- Protocols in frame: lists the protocol stack Wireshark detected inside the captured bits (Ethernet → IP → TCP → HTTP).

In other words, this layer shows metadata about how the packet physically appeared on the wire — its total size in bits, when it was received, and how it was encapsulated.

It corresponds to the Physical Layer (Layer 1) of the OSI model, where data exists only as electrical, optical, or radio signals being transmitted or received before higher-level headers (like MAC or IP) are interpreted.

The highlighted blue section corresponds to the bytes that belong to the Ethernet, IP, and TCP headers (and possibly part of the HTTP payload). It visually connects the physical transmission (hexadecimal data) to the structured OSI layers shown in the details pane.

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-07.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 7</em>
</p>

---

<h4>(Step 2): The Source [MAC] (Layer 2 - Data Link)</h4>

The **Source [MAC] Layer** (Layer 2 - Data Link) revealed IP header information, including source and destination IPv4 addresses, protocol version, and time-to-live (TTL) value.

In this capture, Wireshark displayed the Ethernet II header, which represents Layer 2 (the Data Link layer) of the OSI model.

This layer is responsible for framing, MAC addressing, and delivering packets between devices on the same local network. It doesn’t deal with IPs or ports yet, only the physical device identifiers (MAC addresses).

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-08.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 8</em>
</p>

Inside the red box, we can see:
- Destination: Xerox_00:00:00 → The hardware address of the receiving device.
- Source: fe:ff:20:00:01:00 → The MAC address of the sending device.
- Type: IPv4 (0x0800) → Indicates that the payload inside this Ethernet frame is an IP packet (Layer 3).

These details show how the **Data Link layer** wraps the network-layer data in an Ethernet frame to move it across a physical medium (like a switch or LAN). When this frame reaches the destination, the MAC address helps ensure it’s delivered to the correct network interface before being passed up to Layer 3 (IP).

---

<h4>(Step 3): Source [IP] (Layer 3 - Network)</h4>

The **Source [IP] Layer** (Layer 3 - Network) revealed IP header information, including source and destination IP addresses, protocol version, and time-to-live (TTL) value.

In this capture, Wireshark is displaying details from the Internet Protocol (IP) header, which represents the Network layer (Layer 3) of the OSI model. This layer is responsible for logical addressing and routing as it determines how packets travel from one device to another across different networks.

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-09.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 9</em>
</p>

Inside the red box, you can see several key Layer 3 fields:
- Version 4: Indicates this packet uses IPv4.
- Header Length (20 bytes): Shows how large the IP header is before the next layer (TCP).
- Source IP: 216.239.59.99 — the sender’s logical network address.
- Destination IP: 145.254.160.237 — the receiver’s logical address.
- Protocol: TCP (6) — tells Layer 4 what transport protocol to use.
- TTL (Time to Live): 55 — the number of network hops allowed before the packet is discarded.
- Total Length: 200 bytes — the full size of this IP datagram.

All of these values are used by routers and network devices to route the packet from its source to its final destination across networks, regardless of physical medium or local addressing (like MACs).

When you click any of these IP fields in Wireshark, the corresponding bytes in the **Packet Bytes Pane** (bottom-right) are highlighted which showed the exact binary data representing these Layer 3 details.

---

<h4>(Step 4): Protocol (Layer 4 - Transport)</h4>

The **Protocol Layer** (Layer 4 - Transport) revealed details of the protocol used (UDP/TCP), including sequence and acknowledgment numbers, flags (SYN, ACK, FIN), and window size and source/destination ports.

In this capture, Wireshark is displaying details from the Transmission Control Protocol (TCP) header, which represents the Transport layer (Layer 4) of the OSI model.

This layer is responsible for end-to-end communication, ensuring data is reliably delivered between the source and destination applications. It uses port numbers to identify which process or service is sending and receiving the data.

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-10.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 10</em>
</p>

Inside the red box, we can see key fields that define this TCP segment:
- Source Port: 80 – the sending application’s port (HTTP server).
- Destination Port: 3371 – the receiving application’s port on the client.
- Sequence Number: 1431 – tracks the order of bytes sent so they can be reassembled correctly.
- Acknowledgment Number: 722 – confirms receipt of previous data from the other side.
- Header Length: 20 bytes – the size of the TCP header.

These details show how TCP provides reliability by numbering segments, confirming receipt, and keeping track of timing. In the **Packet Bytes Pane** on the bottom-right, the blue-highlighted bytes correspond to the exact section of the packet where the TCP header data resides. This visually connects the decoded TCP information to its raw binary form.

Below this, the dropdown arrows expand into additional subsections that give deeper insights into TCP behavior:
- Flags – shows control bits like PSH (push data to the app immediately) and ACK (acknowledges received data).
    - Flags are critical for managing TCP’s connection-oriented behavior (SYN, ACK, FIN, etc.).
- SEQ/ACK Analysis – Wireshark calculates and shows relative sequence/acknowledgment numbers to make it easier to follow streams of packets in order.
- Timestamps – records the timing information used to measure round-trip delay and help with congestion control and retransmission.

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-11.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 11</em>
</p>

Within the TCP header, I observed important fields such as **Sequence and Acknowledgment** numbers, which track data flow between the sender and receiver. The **Flags field (0x018 – PSH, ACK)** showed that the packet was actively acknowledging received data and instructing the receiver to push it immediately to the application.

Additional dropdowns like **SEQ/ACK analysis** and **Timestamps** revealed how Wireshark tracks packet timing, delays, and flow control. These values help verify that TCP communication is synchronized and reliable. Overall, this section demonstrated how Layer 4 manages data delivery, acknowledgment, and timing—bridging the IP-based routing (Layer 3) below and application data (Layer 7) above.

---

<h4>(Step 5): Protocol Errors (Layer 4 Details - Still Transport)</h4>

The **Protocol Errors Layer** (Layer 4 - Transport) is a continuation of the 4th layer and showed specfic details about any TCP errors. I explored **protocol reassembly**, where Wireshark automatically combined fragmented TCP streams to show complete data transfers.

In this capture, Wireshark is displaying reassembled TCP Segments, which is part of the **Transport layer (Layer 4)** in the OSI model. TCP often splits large pieces of data into multiple smaller segments, and Wireshark automatically reassembles them to show the full data stream.

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-12.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 12</em>
</p>

Inside the red box, Wireshark shows:
- Frame 26 (payload 0–1429 bytes) and Frame 27 (payload 1430–1589 bytes) — two TCP segments that make up one complete message.
- Segment count: 2 — confirms that the full data was divided between two packets.
- Reassembled TCP length: 1590 bytes — total combined payload size after reassembly.
- Reassembled TCP Data: shows the merged binary data stream before it’s handed off to the Application layer (in this case, HTTP).

This step demonstrates how TCP ensures reliable, ordered data delivery. Even though packets may arrive separately, TCP reassembles them in the correct order before passing them upward to the application.

---

<h4>(Step 6): Application Protocol and Application Data (Layer 5,6,7 - Session, Presentation, Application)</h4>

The **Application layer** (Layer 5,6,7 - Sessions, Presentation, Application) decoded protocols like HTTP, showing request methods, user agents, and URLs accessed. The **Application Data Layer** showed the actual content or payload (HTML, JSON, etc.)

In this capture, Wireshark displays the Hypertext Transfer Protocol (HTTP) section, which represents the top layers of the OSI model (5–7) — the Session, Presentation, and Application layers.

This part of the packet shows the actual application data being exchanged between the client and server after all lower-layer transmissions (Ethernet, IP, TCP) have been completed.

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-13.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 13</em>
</p>

Inside the red box, we can see:
- HTTP/1.1 200 OK → the server’s response indicating the client’s request was successful.
- Status Code 200 and Response Phrase “OK” → confirm proper communication and content delivery.
- Content-Type: text/html → tells the client the data being sent is an HTML web page.
- Content-Length: 1272 bytes → specifies the size of the response body.
- Date and Server fields → show when and by what system the response was generated.
- The HTML text in the “Line-based text data” section shows part of the actual web content.

This layer corresponds to the Application level of the OSI model, where user-facing protocols (like HTTP, FTP, SMTP, or DNS) operate.

Here’s how the OSI model maps to what we see here:
- Layer 5 (Session): manages and maintains the communication session between client and server.
- Layer 6 (Presentation): translates and formats data for readability (e.g., text/html, encoding type).
- Layer 7 (Application): handles the actual application protocol — in this case, HTTP for web communication.

---

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

--- 

<h4>(Step 1) Learning about Packet Numbers</h4>

While exploring Wireshark, I learned that each packet is assigned a unique number in the **Packet List Pane**, which helps identify and analyze individual transmissions. When I click on a specific packet number, Wireshark displays its detailed breakdown in the **Packet Details Pane** at the bottom-left, showing protocol layers and fields. At the same time, the **Packet Bytes Pane** at the bottom-right reveals the raw hexadecimal and ASCII data, allowing me to see exactly what the packet looks like at the byte level.

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-14.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 14</em>
</p>

---

<h4>(Step 2) Going to specific packets</h4>

In this step, I explored how packet numbering works in Wireshark and how it helps with both navigation and analysis. I learned that each packet has a unique number in the **Packet List Pane**, and then clicking one opens its protocol details in the **Packet Details Pane** and its raw data in the **Packet Bytes Pane**. 

I also practiced using the **[Go]** menu and toolbar options, including **[Go to Packet]** to jump to a specific number by number or relative position, **[Next/Previous Packet]** to move up or down, **[Next/Previous Packet in Conversation]** to follow related packets within the same stream, and **[First/Last Packet]** to reach the start or end of the capture. 

These tools made it easier to track communication between hosts and understand how packets relate to each other. Overall, this part helped me see how packet numbering and navigation features improve the efficiency of analyzing network traffic in Wireshark.

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-15.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 15</em>
</p>

---

<h4>(Step 3) Finding packets</h4>

In this step, I learned how to find packets in Wireshark using the **[Edit → Find Packet]** feature. Unlike packet numbers, this tool allows searching by packet content, which is useful for locating specific events such as intrusion patterns or network errors.

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-16.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 16</em>
</p>

I explored the four input types
- Display filter
- Hex
- String
- Regex

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-17.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 17</em>
</p>

<blockquote>
I learned that **String** and **Regex** are the most commonly used, with an option to enable/disable case sensitivity. 
</blockquote>

I also practiced selecting the correct search field across depending on where the data appears:
- Packet List pane (top half)
- Packet Details pane (bottom-left) 
- Packet Bytes pane (bottom-right)

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-18.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 18</em>
</p>

<blockquote>
This showed me how important it is to choose the right input type and pane when performing searches to efficiently pinpoint the packets of interest.
</blockquote>

---

<h4>(Step 4) Marking packets</h4>

I learned how to mark one or more packets in Wireshark to highlight specific event(s) or packet(s) for further analysis. By using the **[Edit] → Mark/UnMark Packet(s)]** or right-clicking a packet or group of packets, I could easily mark or unmark one or more packets of interest. This makes them stand out for later review or export. 

<blockquote>
"Ctrl + M" is the hotkey shortcut.
</blockquote>

I noticed that once marked, packets appear in black, regardless of their original color, which helps quickly identify them during analysis. For practice, I marked packets 20 - 26. 

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-19.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 19</em>
</p>

<blockquote>
I also learned that marking is temporary. Marked packets are cleared once the capture file is closed. This feature is especially useful for keeping track of important findings during live or large-scale packet investigations.
</blockquote>

---

<h4>(Step 5) Commenting on packets</h4>

I explored how to **add comments** to packets for documentation purposes, then viewed and edited them through the **Packet Comments** panel.

I learned how to add comments to packets in Wireshark to document important findings or suspicious activity during analysis. Similar to marking, commenting helps highlight specific packets for further investigation or for other analysts reviewing the same capture.

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-20.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 20</em>
</p>

However, unlike marking, comments are saved within the capture file and remain there until manually removed. This makes it a valuable feature for collaboration and long-term investigations, as analysts can leave detailed notes directly tied to specific packets.

<blockquote>
I used the [right-click → Packet Comment] option (as shown in my screenshot), but I also learned that you can comment on packets through the [Edit → Packet Comment] menu or by using the [Ctrl + Alt + C] shortcut
</blockquote>

I then viewed and edited a test comment through the **Packet Comments** panel for packet number 23.

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-21.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 21</em>
</p>

---

<h4>(Step 6) Exporting objects</h4>

I tested the **Export Objects** feature (**[File > Export Objects]**), a feature that extracts downloadable content (e.g., HTTP files) embedded within packets.

I learned how Wireshark can extract and export files that were transferred over the network. This feature is especially valuable for security analysts, as it allows them to recover and examine shared or potentially malicious files for further investigation. 

I discovered that exporting objects is only available for certain protocol streams, including DICOM, HTTP, IMF, SMB, and TFTP. By accessing these streams, analysts can save transferred files locally to analyze their contents, verify suspicious activity, or gather evidence of data exfiltration. This capability makes Wireshark a powerful tool for both troubleshooting and digital forensics.

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-22.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 22</em>
</p>

---

<h4>(Step 7) Exporting packets</h4>

I also explored **Export Packets**, which allowed saving filtered or selected packets into a new capture file.

I learned how to export specific packets from a capture file in Wireshark for focused analysis. Since capture files can contain thousands of packets, it’s often necessary to isolate only the suspicious or relevant packets to investigate an incident more efficiently. 

I used the **[File → Export Specified Packets]** option to save a smaller, filtered capture that contained just the packets within my chosen scope. This process helps analysts share only the essential data while excluding redundant information. It’s especially useful when collaborating with others or conducting deeper analysis on targeted network activity.

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-23.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 23</em>
</p>

The export window allows choosing between **Captured** and **Displayed** packets. 
- **Captured** includes all packets in the file
- **Displayed** only includes those visible after applying filters

This makes it easier to save and share only the relevant data needed for investigation while excluding unnecessary traffic. I also learned that Wireshark provides additional options to export:
- **Selected packets only** - Exports only the packets I’ve manually selected in the **Packet List Pane** (highlighted in blue - packets 3 - 13). This is useful when you want to save just a few specific packets for closer analysis.
- **Marked packets only** - Exports only the packets I’ve previously marked using the **[Edit]** menu or right-click option. This helps isolate packets I flagged as important or suspicious during the investigation.
- **Range** - Lets me manually define a range of packet numbers (for example, 50–150) to export only those packets within that sequence. This is helpful when you want to capture a continuous portion of traffic without exporting the entire file.

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-24.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 24</em>
</p>

This gives analysts flexibility when isolating specific parts of network activity. Overall, this feature helps streamline the analysis process and focus on packets tied directly to an incident or event of interest.

---

<h4>(Step 8) Changing Time Display Format</h4>

Lastly, I experimented with adjusting the **Time Display Format**, switching between default and UTC timestamps for better temporal analysis.

I learned how to change the time display format in Wireshark to make packet analysis easier and more accurate. By default, Wireshark shows time as **Seconds Since Beginning of Capture**, which reflects when each packet was captured relative to the start of the recording. 

However, this isn’t always ideal for investigations that require exact timestamps or time correlation with other systems. Using the **[View → Time Display Format]** menu, I switched to the **UTC Date and Time of Day**, which provided clearer, standardized timestamps. This feature helps analysts better align packet activity with external logs or events during incident analysis.

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-25.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 25</em>
</p>

<h4>(Step 9) Expert Information feature</h4>

Lastly, I learned about Wireshark’s **[Analyze → Expert Information]** feature, which automatically detects potential issues or anomalies in captured network traffic. This tool categorizes findings into different severity levels, indicates the protocols, and displays the number of occurrences:
- Chat (Blue) for normal information
- Note (Cyan) for notable events
- Warn (Yellow) for warnings
- Error (Red) for serious problems like malformed packets.

I also learned that Wireshark groups these detections under categories such as **Checksum**, **Comment**, **Deprecated**, **Malformed**, **Protocol**, and **Sequence**. This helps analysts quickly identify specific types of issues. 

The expert info can be viewed through the **[Analyze → Expert Information]** menu or in the lower-left status bar, where a summary window lists the packet number, protocol group, and total occurrences. This feature is especially helpful for spotting irregular behavior and prioritizing which packets need deeper investigation.

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-26.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 26</em>
</p>

<blockquote>
There are around 8 – 10 major groups, but Wireshark dynamically shows only the ones relevant to the traffic you’re analyzing. In the screenshot above, for example, I was only seeing Malformed, Protocol, Sequence, and Comment, which are the most common ones in typical TCP/HTTP captures.
</blockquote>

---

<h4>(Step 10) Self Test 1: Finding the MD5 Hash of an Image</h4>

In this self test, I observed packet number 39765, and saw an `HTTP 200 OK` response from a remote server returning a `JPEG` image to my host. The image was split across multiple TCP segments, so Wireshark reassembled those segments and decoded the file structure (you can see the Start of Image (0xFFD8), quantization tables, Start of Scan, etc.) in the **Packet Details** pane. In short: the client sent an `HTTP GET`, the server replied with the `JPEG` payload, Wireshark reassembled the TCP stream, and the packet (and reassembled bytes) show the full `JPEG` content ready for export.

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-27.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 27</em>
</p>

---

(Step 10-a) To extract the image from the capture, I right-clicked on **[JPEG File Interchange Format]** under the **Packet Details Pane** and selected **[Export Packet Bytes]**.

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-28.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 28</em>
</p>

---

(Step 10-b) I then saved the raw image data as `peter_test.jpg` to my desktop. 

<blockquote>
This method exports only the bytes from that specific protocol layer, effectively reconstructing the image as it was transmitted over the network. Once saved, I could open the image locally to verify that it was successfully captured and properly reconstructed.
</blockquote>

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-29.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 29</em>
</p>

---

(Step 10-c) After saving the file I opened a bash terminal in the folder containing the saved image and ran the following command to retrieve the MD5 hash of the image:

`md5sum peter_test`

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-30.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 30</em>
</p>

<blockquote>
You can also run "sha256sum peter_test" for alternate hashes). I recorded the resulting hash in my lab notes and used it to verify the integrity of the saved file by re-running the same command later which produced the same hash to verify the file was unchanged.
</blockquote>

<blockquote>
MD5 and SHA-256 are different hashing algorithms with key differences in their security and hash output size. SHA-256 is a more secure algorithm that produces a 256-bit hash, while MD5 is older, faster, and produces a 128-bit hash
</blockquote>

---

<h4>(Step 11) Self Test 2: Finding TXT File and Reading it</h4>

---

(Step 11-a) I knew there was a txt file in the capture file, so I navigated to **[File > Export Objects > HTTP]** which allowed me to export all HTTP objects found in this file.

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-31.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 31</em>
</p>

---

(Step 11-b) In the "Text Filter" field, I entered `.txt` to filter the list of HTTP objects for just `.txt` files.

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-32.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 32</em>
</p>

---

(Step 11-c) I saved the `.txt` as `peter_note.txt`

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-33.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 33</em>
</p>

---

(Step 11-d) Instead of simply previewing the `.txt` file directly in Wireshark or jumping to the packet number from **Step 11-b** to view it in the **Packet Details Pane**, I opened a Bash terminal in the folder containing the saved `.txt` file and ran the following command to read its contents:

`cat peter_note.txt`

<p align="left">
  <img src="images/wireshark-packet-analysis-and-filtering-34.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 34</em>
</p>

---

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
