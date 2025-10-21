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
- **IP Address: 10.201.121.21, 10.11.81.126, 10-201.28-187, 10-201-55-119** (ephemeral/dynamic)

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_01.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
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

---

<h4>(Step 1) I first checked which network interfaces were available</h4> 

I checked which network interfaces were available to decide which one to listen to by using the command `ip a s` (which is short for `ip address show`). This showed interfaces like `lo` for loopback and `ens5` for Ethernet.

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_02.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 2</em>
</p>

---

<h4>(Step 2) I started a capture session by specifying the interface</h4>

I started a capture session by specifying the interface with the command `sudo tcpdump -i ens5 -c 5 -n`. This began printing live traffic directly to the terminal.

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_03.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 3</em>
</p>

The command `sudo tcpdump -i ens5 -c 5 -n` told the system to listen on the `ens5` network interface, capture five packets, and display them without converting IPs to hostnames. Running it with sudo gave the necessary root permissions to access the network interface.

---

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

- (Step 1) Filtering by Host
- (Step 2) Filtering by Port
- (Step 3) Filtering by Protocol
- (Step 4) Filtering Packets from a PCAP file
- (Step 5) More Packet Analysis Practice with tcpdump

---

<h4>(Step 1) Filtering by Host: I started by filtering packets from a specific host</h4> 

I captured filtering packets from a specific host using `sudo tcpdump host example.com -w http.pcap`. This allowed me to capture only traffic to and from that domain and capture traffic that passes through and writes it to a file named `http.pcap` file on my computer. 

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_04.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 4</em>
</p>

- `tcpdump` is the command that starts the packet capture session
- `host example.com` specifies the capture to traffic going to and coming from `example.com`
- `-w http.pcap` saves all captured packets into a file named `http.pcap`

<blockquote>
In this case, `tcpdump` is listening on the network interface `ens5`, but since there was no actual traffic to or from `example.com`, no packets were recorded. `example.com` is just a placeholder domain used for demonstration.
</blockquote>

If this has been a live, active domain that my computer was communicating with, `tcpdump` would have displayed real-time capture activity. 

I used `Ctrl + C` which stopped the capture and provided a short summary of all packets that were captured. The short summary includes the number of packets captured, number of packets received by the filter, and the number of packets dropped be the kernel. The file `http.pcap` would contain those captured packets, which could later be opened in Wireshark for further inspection such as IP addresses, ports, HTTP requests, etc.

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_05.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 5</em>
</p>

I could also filter by direction including `src host` and `dst host` in my filter to focus on specific source or destination traffic only.

---

<h4>(Step 2) Filtering by Port: I moved to capturing traffic from specific ports</h4> 

I went on and started capturing traffic from specific ports. I used `sudo tcpdump -i ens5 port 53 -n`, which captured all DNS requests and responses (since DNS uses port 53).

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_06.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 6</em>
</p>

- `tcpdump` is the command that starts the packet capture session
- `-i ens5` specifies the network interface to listen on
- `port 53` specifies the port number
- `-n` basically stops `tcpdump` from resolving IP addresses or port numbers into names, so I see numberic IPs instead

Again, I used `Ctrl + C` which stopped the capture and provided a short summary of all packets that were captured.

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_07.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 7</em>
</p>

I could also use `src port` or `dst port` to filter traffic going to or coming from a particular port.

---

<h4>(Step 3) Filtering by Protocol: I captured traffic by specific protocols</h4>

Finally, I started filtering by protocol using commands like `sudo tcpdump -i ens5 icmp -n` to capture only ICMP traffic, which showed ping requests and replies.

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_08.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 8</em>
</p>

- `tcpdump` is the command that starts the packet capture session
- `-i ens5` specifies the network interface to listen on
- `icmp` specifies the protocol so that the capture only shows ICMP packets
- `-n` basically stops `tcpdump` from resolving IP addresses or hostnames into names, so I see numberic versions instead

Again, I used `Ctrl + C` which stopped the capture and provided a short summary of all packets that were captured.

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_09.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 9</em>
</p>

If this has been a live network interface that my computer was communicating with, `tcpdump` would have displayed real-time capture activity. For this exercise, it captured 0 packets.

I could also combine multiple filters with logical operators like `and`, `or`, and `not` to be more specific. For example, `tcpdump tcp and port 80` captures only HTTP packets, `tcpdump udp or icmp` captured UDP or ICMP traffic if at least one of the conditions is true, and adding other conditions like `not port 22` excludes SSH traffic.

I could also create a longer filter with multiple conditions such as `tcpdump -i ens5 host example.com and tcp port 443 -w https.pcap`. This will capture and filter traffic going to and coming from `example.com` that uses `tcp` and `port 443`, which is for filtering HTTPS traffic.

- `tcpdump` will start the capture session
- `-i ens5` will specify the network interface to listen on
- `host example.com` captures traffic going to and coming from `example.com` since the `src port` or `dst port` wasn't defined
- `and` is the logical operator meaning both conditions must be true to capture the packet
- `tcp` specifies the protocol so that the capture only shows TCP packets
- `port 443` specifies the port number, which would be HTTPS

---

<h4>(Step 4) Filtering Packets from a PCAP file</h4>

To analyze a previously captured packet file and filter network traffic originating from a specific IP address, I ran the command `tcpdump -r traffic.pcap src 192.168.124.1 -n | wc -l`. 

I used the `tcpdump` command with the `-r` flag to read packets from an existing capture file (`traffic.pcap`) instead of capturing live traffic. The filter src `192.168.124.1` limited the output to only packets sent from the source IP address `192.168.124.1`. The `-n` option prevented hostname resolution which kept the IPs in numeric form. By piping the output into `wc -l`, I counted how many packets in the file matched this filter, giving me a quick summary of how many transmissions came from that source host.

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_10.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 10</em>
</p>

- `tcpdump -r traffic.pcap` read packets from a saved capture file named `traffic.pcap` instead of live traffic
- `src 192.168.124.1` filtered the output to show only packets originating from the IP address `192.168.124.1`
- `-n` disabled hostname lookups so IPs stay numeric.
- `| wc` piped the output into the word count (`wc`) command, which counts the number of lines, words, and characters in the output.

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_11.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 11</em>
</p>

The results showed that there were `910` number of lines, which roughly estimates to about 910 packets displayed by `tcpdump`, `17415` total number of words printed in the `traffic.pcap` file, and `140616` total number of individual characters printed in that same file.

The most useful number for packet analysis here is the first one (`910`), which is showing the number of packets from `192.168.124.1` in the `traffic.pcap` file.

---

<h4>(Step 5) More Packet Analysis Practice with tcpdump</h4>

I wnated to practice analyzing captured network traffic using `tcpdump` by filtering specific protocols and identifying key network details such as packet counts, IP addresses, and DNS queries.

---

**(Step 5-a)** I analyzed packets in `traffic.pcap` that were using the `ICMP` protocol. To do so, I ran the following command:

`sudo tcpdump -r traffic.pcap icmp -n | wc`

I used the `-r` flag to read packets from a saved capture file (`traffic.pcap`) and filtered for the `ICMP` protocol, which includes ping requests and replies. The `-n` flag disabled hostname lookups to display numeric IPs. Piping the output into `wc` allowed me to count the results. 

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_12.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 12</em>
</p>

The results showed that there were `26` number of lines, which  estimates to about 26 packets displayed by `tcpdump`, `358` total number of words printed in the `traffic.pcap` file, and `2722` total number of individual characters printed in that same file.

---

**(Step 5-b)** I analyzed packets in `traffic.pcap` to look for the IP address of the host that asked for the MAC address of `92.168.124.137`. To do so, I ran the following command:

`sudo tcpdump -r traffic.pcap arp and host 192.168.124.137`

I filtered the capture file to display ARP (Address Resolution Protocol) traffic related to the host `192.168.124.137`. ARP is used to map IP addresses to physical MAC addresses on the local network.

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_13.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 13</em>
</p>

From the ARP request, I could see that the host `192.168.124.148` was asking for the MAC address of `192.168.124.137`.

---

**(Step 5-c)** I identified the hostname (not IP) that appeared in the first DNS query in the `traffic.pcap` file. To do so, I ran the following command:

`sudo tcpdump -r traffic.pcap port 53 -A`

This command filtered the capture to show `DNS` traffic (which uses `port 53`) and prints the data in ASCII (`-A`) for readability. This allows viewing the actual domain names being queried.

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_14.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 14</em>
</p>

`07:18:24.058626 IP ip-192-168-124-137.eu-west-1.compute.internal.33672 > ip-192-168-124-1.eu-west-1.compute.internal.domain: 39913+ A? mirrors.rockylinux.org. (40)`

This packet capture entry showed that the `mirrors.rockylinux.org` was the hostname that appeared in the first DNS query in the `traffic.pcap` file.

---

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

---

<h4>(Step 1) I used filters like `greater [LENGTH]` and `less [LENGTH]` to display packets based on their size.</h4>

---

<h4>(Step 1-a) I practiced using length-based filters in tcpdump to capture packets according to their size. </h4>

I learned that the keywords `greater` and `less` allow filtering packets based on their byte length, regardless of source, destination, or protocol. For example, the command `tcpdump greater 1000` captures all packets larger than `1000` bytes on the default interface. 

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_15.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 15</em>
</p>

At any point, I can use `Ctrl + C` to stop the live capture and see a short summary of all packets captured on the default interface. That's exactly what I did:

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_16.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 16</em>
</p>

---

<h4>(Step 1-b) I specified an interface</h4>

For example, the command `tcpdump -i ens5 greater 1000` captured all packets on the `ens5` interface that are larger than 1000 bytes.

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_17.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 17</em>
</p>

I pressed `Ctrl + C` to stop the live capture to see a short summary of all packets captured on the `ens5` interface:

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_18.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 18</em>
</p>

---

<h4>(Step 1-c) I specified an interface and a host</h4>
  
I also modified the filter command by only capturing packets that are larger than 1000 bytes involving the host `example.com` on the `ens5` interface by using: `tcpdump -i ens5 host example.com and greater 1000`

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_19.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 19</em>
</p>

I pressed `Ctrl + C` to stop the live capture to see a short summary of all packets captured involving the host `example.com` on the `ens5` interface that are larger than 1000 bytes:

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_20.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 20</em>
</p>

---

<h4>(Step 1-d) I specified an interface, host, and protocol using the and operator</h4>

I also discovered that I can capture only TCP packets larger than 1000 bytes on a specific network involving a specific domain. So I modified my command filter as such: `tcpdump -i ens5 tcp and host example.com and greater 1000`, which captured all TCP packets that are greater than 1000 bytes on the `ens5` network involved the host `example.com`

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_21.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 21</em>
</p>

I pressed `Ctrl + C` to stop the live capture to see a short summary of all `TCP` packets captured involving the host `example.com` on the `ens5` interface that are larger than 1000 bytes:

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_22.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 22</em>
</p>

---

<h4>(Step 2) I reviewed binary operations</h4> 

I reviewed three binary operations (`&`, `|`, and `!`) to understand how tcpdump processes bits. These operations are often used in protocol-level filtering. I learned:

- The `&` operation takes two bits and returns 0 unless both inputs are 1.
- The `|` operation takes two bits and returns 1 unless both inpurts are 0.
- The `!` operation takes only one bit and inverts it. So an input of 1 returns 0, and an input of 0 gives 1.

---

<h4>(Step 3) I explored the concept of header bytes and learned that I could filter based on specific byte positions</h4> 

I explored the concept of header bytes and learned that I could filter based on specific byte positions using the syntax `proto[expr:size]`. This allowed for very detailed inspection, such as targeting parts of the Ethernet or IP header.

- `proto` refers to the protocol I want to specify
- `expr` is the byte offset, where `0` refers to the first byte
- `size` indicates the number of bytes, which can be either `1`, `2`, or `4` and is `1` by default. This field is optional.

---

<h4>(Step 3-a) Combining Header Byte Filters (Bitwise) and Host Filters</h4>

I incportated `ether[0] & 1 != 0` to display packets sent to multicast addresses. This filter checks the first byte (`[0]`) in the Ethernet header (`ether`) and uses a binary AND operation (`&`) with `1` to see if the result is not (`!=`) `0`. This is to see if the packet was sent to a multicast group instead of a single device.

I experimented with combining bitwise filters and host filters in tcpdump to capture more specific packet types. I learned that filters like `ether[0] & 1 != 0` can be used alongside host filters to refine captures. For example, the command: `sudo tcpdump -i ens5 'host example.com and ether[0] & 1 != 0'` captured packets sent to and from `example.com` whose Ethernet destination address is a multicast address.

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_23.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 23</em>
</p>

I pressed `Ctrl + C` to stop the capture and get a short summary of all packets captured:

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_24.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 24</em>
</p>

---

<h4>(Step 4) I then focused on TCP flags.</h4> 

I then explored TCP flags to understand how they indicate the state and behavior of a TCP connection, such as connection setup (SYN), acknowledgment (ACK), termination (FIN), and resets (RST). By analyzing these flags in captured packets, I could identify different stages of TCP communication and detect unusual patterns like retransmissions or abrupt connection resets. 

<blockquote>TCP flags are 1-bit in size and exist in TCP headers. These flags describe the state or purpose of a TCP packet during communication.</blockquote>

---

<h4>(Step 4-a) I captured TCP packets with only the SYN (Synchronization) flag in their headers with all other flags unset</h4>
  
To achieve this, I used the expression: `tcpdump -i ens5 'tcp[tcpflags] == tcp-syn'`. I was able to isolate SYN packets, which represent the initial connection attempt, on the `ens5` network. This also filters for packets where only the SYN flag is present, as indicated by the `==` operator. 

<blockquote>
When I ran this tcpdump command to capture SYN packets, no packets appeared. This occurred because the test environment wasn’t generating any active TCP traffic at that moment. The filter specifically looks for TCP packets initiating new connections (SYN flags). Because there were no real network activity, no matches were found. In a live environment or during active network use, this command would display packets involved in TCP connection setup.
</blockquote>

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_25.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 25</em>
</p>

I pressed `Ctrl + C` to stop the capture and get a short summary of all packets captured:

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_26.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 26</em>
</p>

---

<h4>(Step 4-b) I captured TCP packets with at least the SYN (Synchronization) flag in their headers regardless of the presence of other flags</h4>

To achieve this, I used the expression: `tcpdump -i ens5 'tcp[tcpflags] & tcp-syn != 0'`. I was able to isolate TCP packets with at least the SYN flag present, regardless if other flags were present, as indicated by the `!=` operator, and were making the initial connection attempt on the `ens5` network.

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_27.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 27</em>
</p>

I pressed `Ctrl + C` to stop the live capture and get a short summary of all packets captured:

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_28.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 28</em>
</p>

---

<h4>(Step 4-c) I captured TCP packets with at least the SYN (Synchronization) or ACK (Acknowledge) flag in their headers regardless of the presence of other flags</h4>

To achieve this, I used the expression: `tcpdump -i ens5 'tcp[tcpflags] & (tcp-syn|tcp-ack) != 0'`. I was able to isolate TCP packets with at least the SYN or ACK flags present, regardless if other flags were present, as indicated by the `!=` operator, and were making the initial connection attempt on the `ens5` network. This filter identifies traffic involved in establishing (SYN) or acknowledging (ACK) TCP connections. This includes the handshake process between two hosts. It helped me observe the flow of connection initiation and acknowledgment packets on the network interface `ens5`.

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_29.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 29</em>
</p>

<blockquote>
I took this screenshot before running the command because once I executed it, the terminal (Linux Bash) displayed a continuous stream of live packet captures. To avoid flooding the screen, I pressed Ctrl +C shortly after starting the capture to stop the output.
</blockquote>

I pressed `Ctrl + C` to stop the live capture and get a short summary of all packets captured:

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_30.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 30</em>
</p>

---

<h4>(Step 5) Retrieving TCP Flag Information from a PCAP file</h4>

I practiced analyzing an existing capture file instead of live network traffic. I used the command: `sudo tcpdump -r traffic.pcap 'tcp[tcpflags] == tcp-rst' | wc -l` to count how many packets had only the TCP Reset (RST) flag set. 
- The `-r traffic.pcap` option tells tcpdump to read packets from the saved file rather than capturing live traffic
- The `'tcp[tcpflags] == tcp-rst'` isolates packets with the `RST` flag.
- The `| wc -l` part pipes the output through the word count command, returning the number of lines, which equals the total number of matching packets.

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_31.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 31</em>
</p>

Next, I ran: `sudo tcpdump -r traffic.pcap 'greater 15000' -n` to find the IP address of the host that sent packets larger than 15,000 bytes.

- The `traffic.pcap` file is the existing file that contains packet captures from a previous exercise
- The `'greater 15000'` filter displays only packets exceeding that size, and
- The `-n` option disables DNS resolution, ensuring that IP addresses are shown directly instead of hostnames

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_32.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 32</em>
</p>

---

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

<blockquote>
For this part of the lab, I used the "traffic.pcap" file. This file was used to practice analyzing small packet captures and verifying capture integrity and content in a controlled, minimal dataset.
</blockquote>

### Step-by-Step Walkthrough

---

<h4>(Step 1) I displayed basic packet information without any arguments or specifications</h4>

I displayed basic packet information without any arguments or specifications using `tcpdump -r traffic.pcap -c 2` to review captured data. This command reads and displays the first two packets from a previously captured packet file (`traffic.pcap`). It shows the following information:

- **Timestamp** - when the packet was captured
- **Source and destination IP addresses** - who sent and who received the packet
- **Protocol type** - TCP, UDP, ICMP, ARP, etc
- **Ports** - Source and destination ports for TCP traffic
- **Flags** - TCP flags like SYN, ACK, FIN
- **Packet Length** - Total number of bytes in the frame
- **Additional Information** - Sometimes includes checksums or ICMP message types

<blockquote>
I added the `-c 2` option to limit the output to just two packets. This was because capture file (traffic.pcap) contained a large number of packets and I only needed to display a small sample for analysis.
</blockquote>

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_33.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 33</em>
</p>

---

<h4>(Step 2) I used "-q" to get brief packet information</h4>

To simplify the output of the two packets I've captured and displayed in **Step 1** above, I used `-q` for “quick” mode, which only showed source/destination IPs and ports. To do so, I used: `tcpdump -r traffic.pcap -q -c 2`. `-q`, as it might suggest, stands for "quick". So "quick view".

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_34.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 34</em>
</p>

---

<h4>(Step 3) I included MAC addresses and Ethernet headers to display link-level headers</h4>

To include MAC addresses and Ethernet headers, I added the `-e` flag to the command from **step 1**: `tcpdump -r traffic.pcap -e -c 2`.

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_35.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 35</em>
</p>

---

<h4>(Step 4) Displayed packets as ASCII</h4>

To view packet data in readable text, I added `-A`, which printed the ASCII representation of the packet contents. The command was `tcpdump -r traffic.pcap -A -c 2`. This one was interesting because it also displayed all the bytes mapped to English letters, numbers, and symbols. The output appeared mostly unreadable, filled with random letters, numbers, and symbols. This happened because the captured packets contained encrypted SSH traffic. When `-A` is used, tcpdump tries to show the raw payload data as ASCII text, but since encrypted or binary data can’t be represented as readable characters, it appears as gibberish. The readable parts, such as IP addresses, ports, and flags, still provide useful metadata for analysis.

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_36.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 36</em>
</p>

---

<h4>(Step 5) Displayed packets in Hexadecimal Format </h4>

To view packet data in hexidecimal format, I added `-xx`, which printed the the bytes of each packet. The command was `tcpdump -r traffic.pcap -xx -c 2`. The results also show the IP and TCP headers in addition to the packet contents.

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_37.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 37</em>
</p>

---

<h4>(Step 6) Displayed packets using both ASCII and Hexadecimal Format</h4>

Finally, I combined both hex and ASCII output using `-X`, which showed packets in both formats simultaneously. I used `tcpdump -r traffic.pcap -X -c 2`.

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_38.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 38</em>
</p>

---

<h4>(Step 7) Finding the MAC address of host that sent an ARP request</h4>

As a test, I sought to find the MAC address of any hosts that sent ARP requests. To achieve this, I ran `tcpdump -r traffic.pcap arp -e`

<p align="left">
  <img src="images/tcpdump_packet_capture_and_filtering_39.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 39</em>
</p>

I identified an ARP request asking “who has `192.168.124.137`” that was broadcast to the network. The MAC address before the `>` symbol in tcpdump’s output represents the source (sender), while the one after represents the destination. Using this format, I determined that the host with MAC address `52:54:00:7c:d3:5b` sent the ARP request. The reply came from `52:54:00:23:60:2b`, confirming it as the device associated with `192.168.124.137`.

---

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

---
