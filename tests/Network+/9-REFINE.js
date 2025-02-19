db.tests.insertOne({
  "category": "nplus",
  "testId": 9,
  "testName": "Network+ Practice Test #9 (Ruthless)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A network administrator is troubleshooting a complex routing issue in a network using OSPF as the routing protocol. They observe that some, but not all, routes are being learned correctly.  They suspect a problem with OSPF area configuration.  Which of the following commands on a Cisco router would be MOST useful in verifying the OSPF area configuration for a specific interface?",
      "options": [
        "show ip route ospf",
        "show ip ospf neighbor",
        "show ip ospf interface [interface_name]",
        "show ip protocols"
      ],
      "correctAnswerIndex": 2,
      "explanation": "While `show ip route ospf` shows OSPF routes, and `show ip ospf neighbor` shows neighbor relationships, `show ip ospf interface [interface_name]` provides *detailed* information about OSPF on a *per-interface* basis, including the *area ID* to which the interface belongs, the interface type, cost, hello and dead intervals, and other OSPF parameters. This is crucial for verifying that the interface is participating in the correct OSPF area and that its settings are consistent with other routers in the area.  `show ip protocols` gives a general overview of routing protocols, but not detailed OSPF interface information.",
      "examTip": "Use `show ip ospf interface [interface_name]` to verify detailed OSPF configuration on a per-interface basis, including the area ID."
    },
    {
      "id": 2,
      "question": "A network is experiencing intermittent connectivity issues. A protocol analyzer capture shows a large number of TCP retransmissions, duplicate ACKs, and TCP ZeroWindow messages. Further analysis reveals that the TCP ZeroWindow messages are primarily originating from a specific server. What is the MOST likely cause of the problem, and what steps should be taken to investigate?",
      "options": [
        "A DNS server misconfiguration is causing name resolution failures.",
        "The network is experiencing a broadcast storm.",
        "The server is experiencing a resource bottleneck (CPU, memory, disk I/O, or network bandwidth) that is preventing it from processing incoming data quickly enough, causing its receive buffer to fill up. Investigate server resource utilization, network interface statistics, and application performance.",
        "A faulty network cable is causing packet loss."
      ],
      "correctAnswerIndex": 2,
      "explanation": "TCP retransmissions and duplicate ACKs indicate packet loss. Critically, *TCP ZeroWindow messages originating from the server* indicate that the *server's* receive buffer is full, meaning it cannot accept any more data from the clients. This points to a *server-side bottleneck*, not a general network problem. The likely causes are: 1. *CPU overload:* The server's processor is too busy to process incoming data. 2. *Memory exhaustion:* The server is running out of RAM. 3. *Disk I/O bottleneck:* The server's disk subsystem is too slow to handle the read/write requests. 4. *Network bandwidth saturation:* The server's network interface is overloaded. DNS issues wouldn't cause these specific TCP symptoms. A broadcast storm would affect the *entire* network, not just communication with one server. A faulty cable is *possible* but less likely than a server resource issue given the ZeroWindow messages *from the server*.",
      "examTip": "TCP ZeroWindow messages from a server often indicate a resource bottleneck on the server itself; monitor CPU, memory, disk I/O, and network utilization."
    },
    {
      "id": 3,
      "question": "You are designing a highly resilient network for a data center. You need to ensure that if a single switch fails, network connectivity is maintained with minimal downtime.  Which combination of technologies, properly configured, would provide the BEST solution?",
      "options": [
        "Spanning Tree Protocol (STP) on all switches.",
        "Multiple switches configured with HSRP (Hot Standby Router Protocol) or VRRP (Virtual Router Redundancy Protocol) for gateway redundancy, and redundant links between switches with either STP or a loop-free Layer 2 protocol.",
        "A single, large, modular switch with redundant power supplies.",
        "Port security on all switch ports."
      ],
      "correctAnswerIndex": 1,
      "explanation": "High resilience requires redundancy at *multiple* layers. The best approach includes: *Layer 3 Redundancy:* HSRP or VRRP provides *gateway redundancy*.  Multiple routers (or Layer 3 switches) share a virtual IP address, and if the active router fails, a standby router takes over, ensuring continuous routing. *Layer 2 Redundancy:* *Either* STP *or* a loop-free Layer 2 protocol (like a modern, rapid spanning-tree variant or a proprietary link aggregation protocol) is needed to prevent loops in the switched network when redundant links are present.  STP alone doesn't provide *gateway* redundancy. A single switch, even with redundant power, is a single point of failure. Port security enhances *security*, not *resilience*.",
      "examTip": "High resilience requires redundancy at both Layer 2 (loop prevention) and Layer 3 (gateway redundancy)."
    },
    {
      "id": 4,
      "question": "A network administrator configures a Cisco router with the following commands: `router ospf 1` `network 192.168.1.0 0.0.0.255 area 0` `network 172.16.0.0 0.0.15.255 area 1` `network 10.0.0.0 0.255.255.255 area 0` What is the effect of this configuration?",
      "options": [
        "It enables OSPF on the router but does not include any interfaces in the OSPF process.",
        "It enables OSPF on the router and includes interfaces with IP addresses in the 192.168.1.0/24, 172.16.0.0/20, and 10.0.0.0/8 networks in the OSPF process, placing the 192.168.1.0/24 and 10.0.0.0/8 networks in area 0 and the 172.16.0.0/20 network in area 1.",
        "It enables OSPF on the router and includes all interfaces in area 0.",
        "It enables RIP on the router."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`router ospf 1` enables OSPF with process ID 1. The `network` commands define which interfaces will participate in OSPF and which OSPF area they belong to. The command uses *wildcard masks*, which are the inverse of subnet masks: `network 192.168.1.0 0.0.0.255 area 0`: Includes interfaces with IPs in the 192.168.1.0/24 network in area 0. `network 172.16.0.0 0.0.15.255 area 1`: Includes interfaces with IPs in the 172.16.0.0/20 network in area 1. `network 10.0.0.0 0.255.255.255 area 0`: Includes interfaces with IPs in the 10.0.0.0/8 network in area 0. It's *not* RIP, and it doesn't place *all* interfaces in area 0.",
      "examTip": "Understand how the `network` command in OSPF configuration uses wildcard masks to define which interfaces participate in which OSPF areas."
    },
    {
      "id": 5,
      "question": "A network is experiencing intermittent connectivity issues.  A protocol analyzer capture shows a high number of ARP requests, many of which are for the *same* IP address but with *different* source MAC addresses. What type of attack is MOST likely occurring?",
      "options": [
        "Denial-of-service (DoS) attack",
        "Distributed denial-of-service (DDoS) attack",
        "ARP spoofing (ARP poisoning)",
        "MAC flooding"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The key here is *multiple ARP requests for the same IP address but with different source MAC addresses*. This strongly suggests *ARP spoofing (ARP poisoning)*. An attacker is sending forged ARP messages to associate *their* MAC address with the IP address of another device (often the default gateway). This allows them to intercept, modify, or block traffic intended for that device. A DoS/DDoS would likely involve flooding with various types of traffic, not just ARP. MAC flooding targets switch CAM tables, not ARP.",
      "examTip": "ARP spoofing is characterized by forged ARP messages associating an attacker's MAC address with a legitimate IP address."
    },
    {
      "id": 6,
      "question": "You are configuring a wireless network using WPA2 Enterprise. Which of the following components is REQUIRED for WPA2 Enterprise authentication?",
      "options": [
        "A pre-shared key (PSK).",
        "A RADIUS server and 802.1X.",
        "WEP encryption.",
        "MAC address filtering."
      ],
      "correctAnswerIndex": 1,
      "explanation": "WPA2 *Enterprise* (unlike WPA2-Personal) requires an external authentication server, typically a *RADIUS server*, and uses the *802.1X* protocol for port-based network access control. The RADIUS server handles the authentication of users or devices based on credentials (username/password, certificates) or other authentication methods. WPA2-Personal uses a pre-shared key (PSK). WEP is an outdated, insecure protocol. MAC address filtering is a separate security measure, not directly related to WPA2 authentication.",
      "examTip": "WPA2-Enterprise requires a RADIUS server and 802.1X for authentication."
    },
    {
      "id": 7,
      "question": "A network administrator wants to prevent rogue DHCP servers from operating on a network segment.  Which of the following switch security features would be MOST effective in achieving this, and how does it work?",
      "options": [
        "Port security; it limits the number of MAC addresses allowed on a port.",
        "DHCP snooping; it inspects DHCP messages and only allows DHCP traffic from trusted sources (typically, designated DHCP server ports), preventing unauthorized DHCP servers from assigning IP addresses.",
        "802.1X; it requires users and devices to authenticate before gaining network access.",
        "VLANs; they segment the network into separate broadcast domains."
      ],
      "correctAnswerIndex": 1,
      "explanation": "*DHCP snooping* is specifically designed to prevent rogue DHCP servers. It's a security feature implemented on switches that *inspects* DHCP messages. The switch learns which ports are connected to trusted DHCP servers (usually through manual configuration) and *only allows* DHCP traffic (specifically, DHCP server responses) from those trusted ports. DHCP messages from untrusted ports are dropped, preventing rogue servers from assigning IP addresses. Port security limits MAC addresses, 802.1X provides *authentication*, and VLANs segment the network *logically*; none of these *directly* prevent rogue DHCP servers.",
      "examTip": "DHCP snooping is a crucial security feature to prevent rogue DHCP servers from disrupting network operations and potentially launching attacks."
    },
    {
      "id": 8,
      "question": "What is 'split horizon' with 'poison reverse', and how does it improve upon basic split horizon in preventing routing loops in distance-vector routing protocols?",
      "options": [
        "Split horizon with poison reverse is a method for encrypting routing updates.",
        "Split horizon with poison reverse is a technique for prioritizing certain routes over others.",
        "Split horizon prevents a router from advertising a route back out the same interface it was learned on. Poison reverse does advertise the route back, but with an infinite metric, making it clear that the route is unreachable through that interface. This combination is more robust than basic split horizon in preventing loops.",
        "Split horizon with poison reverse is a technique for load balancing traffic."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Both split horizon and poison reverse are loop-prevention techniques for distance-vector protocols (like RIP). *Split horizon:* A router does not advertise a route back out the same interface it learned that route from. This prevents simple two-node loops. *Poison reverse:* The router does advertise the route back out the same interface, but with an infinite metric (making it unreachable). This is more robust because it actively informs the neighbor that the route is no longer usable through that path, rather than simply not advertising it. This helps prevent more complex loops and speeds up convergence. It's not about encryption, prioritization, or load balancing.",
      "examTip": "Split horizon with poison reverse is a more effective loop prevention technique than basic split horizon in distance-vector routing."
    },
    {
      "id": 9,
      "question": "You are configuring a Cisco router. You want to allow SSH access (TCP port 22) to the router's VTY lines *only* from hosts within the 192.168.1.0/24 network and deny all other access to the VTY lines. Which of the following command sequences is the MOST correct and secure way to accomplish this?",
      "options": [
        "line vty 0 4\ntransport input all",
        "line vty 0 4\ntransport input ssh\naccess-list 10 permit ip any any\naccess-class 10 in",
        "line vty 0 4\ntransport input ssh\naccess-list 10 permit tcp 192.168.1.0 0.0.0.255 host [Router's Management IP] eq 22\naccess-class 10 in",
        "line vty 0 4 \n transport input telnet \n access-list 10 permit 192.168.1.0 0.0.0.255 \n access-class 10 in"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Here's the breakdown and why the correct answer is best: 1. **`line vty 0 4`**: Enters configuration mode for the virtual terminal lines (VTY lines 0-4), used for remote access (SSH, Telnet). 2. **`transport input ssh`**: Crucially, this restricts remote access to only SSH, disabling the insecure Telnet protocol. This is a fundamental security best practice. 3. **`access-list 10 permit tcp 192.168.1.0 0.0.0.255 host [Router's Management IP] eq 22`**: Creates an access control list (ACL) named '10'. This line permits TCP traffic originating from the 192.168.1.0/24 network (using the wildcard mask 0.0.0.255) specifically to the router's management IP address on port 22 (SSH). Important: Replace [Router's Management IP] with the actual IP address you use to manage the router via SSH. This is more secure than permitting to any. 4. **`access-class 10 in`**: Applies the ACL named '10' to the incoming traffic on the VTY lines. This means that only traffic matching the ACL (SSH from 192.168.1.0/24) will be allowed to establish a connection. Option A allows all protocols on the VTY lines (insecure). Option B allows SSH from any IP address (insecure). Option D allows only Telnet (extremely insecure) and applies it to console, not VTY.",
      "examTip": "To securely restrict SSH access on a Cisco router, use `transport input ssh` on the VTY lines and an ACL that permits only SSH traffic from authorized sources."
    },
    {
      "id": 10,
      "question": "A network administrator is troubleshooting slow performance on a network segment.  They use a protocol analyzer and observe a very high number of TCP retransmissions and duplicate ACKs. They also notice several instances of 'TCP Window Full' and 'TCP ZeroWindow' messages.  Which of the following is the MOST accurate interpretation of these findings?",
      "options": [
        "The DNS server is not functioning correctly, causing delays in name resolution.",
        "The DHCP server has run out of available IP addresses.",
        "The network is experiencing significant packet loss, likely due to congestion, faulty hardware, or a misconfigured MTU. The 'TCP Window Full' and 'ZeroWindow' messages suggest that either the sending or receiving host (or both) is having trouble keeping up with the data flow, possibly due to resource constraints.",
        "The network is experiencing a broadcast storm."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The combination of these TCP issues points directly to problems with reliable data delivery: TCP Retransmissions occur when the sender didn't receive an acknowledgment for a transmitted packet within a timeout, indicating packet loss. Duplicate ACKs indicate that the receiver is getting packets out of order, often because some packets were dropped and later ones arrived first. TCP ZeroWindow messages indicate that the receiver's buffer is full, telling the sender to stop transmitting temporarily. This can be due to network congestion or the receiver being unable to process data fast enough. Out-of-order sequence numbers reinforce the packet loss and reordering. These symptoms strongly suggest packet loss and/or congestion on the network, or potentially a resource bottleneck on one of the hosts (CPU, memory, disk I/O, or network bandwidth). It's not primarily a DNS, DHCP, or browser issue.",
      "examTip": "TCP retransmissions, duplicate ACKs, ZeroWindow messages, and out-of-order sequence numbers are strong indicators of packet loss and potential network congestion or host resource issues."
    },
    {
      "id": 11,
      "question": "You are designing a network that must support a large number of wireless clients in a high-density environment (e.g., a conference center or stadium). Which 802.11 wireless standard is BEST suited for this scenario, and what are some key features of that standard that make it suitable?",
      "options": [
        "802.11g; it supports high data rates and operates in the 5 GHz band.",
        "802.11n; it uses MIMO technology to improve throughput.",
        "802.11ax (Wi-Fi 6/6E); it includes features like OFDMA, MU-MIMO, and Target Wake Time (TWT) that improve efficiency, capacity, and performance in dense environments.",
        "802.11ac; it offers very high speeds in the 5 GHz band."
      ],
      "correctAnswerIndex": 2,
      "explanation": "802.11ax (Wi-Fi 6/6E) is specifically designed for high-density environments. Key features that make it suitable include: OFDMA (Orthogonal Frequency-Division Multiple Access) allows multiple clients to transmit data simultaneously on different subcarriers of the same channel, improving efficiency; MU-MIMO (Multi-User Multiple-Input Multiple-Output) allows the access point to communicate with multiple clients simultaneously, increasing overall network capacity; Target Wake Time (TWT) allows devices to negotiate scheduled wake times, reducing power consumption and improving battery life for client devices; BSS Coloring helps reduce interference between overlapping wireless networks. 802.11g is very old and slow. 802.11n is an improvement, but significantly less capable than 802.11ax. 802.11ac is a good standard, but 802.11ax offers significant advantages in dense deployments.",
      "examTip": "802.11ax (Wi-Fi 6/6E) is the best choice for high-density wireless deployments due to its efficiency and capacity-enhancing features."
    },
    {
      "id": 12,
      "question": "What is 'DHCP starvation', and how does enabling 'DHCP snooping' and 'port security' on a switch help mitigate this and other DHCP-related attacks?",
      "options": [
        "DHCP starvation is a method for encrypting DHCP traffic; DHCP snooping and port security prevent the encryption key from being compromised.",
        "DHCP starvation is a technique for increasing the speed of IP address assignment; DHCP snooping and port security ensure that only authorized devices can benefit from this speed increase.",
        "DHCP starvation is a denial-of-service attack where an attacker floods the network with DHCP requests using spoofed MAC addresses, exhausting the DHCP server's pool of available IP addresses; DHCP snooping prevents rogue DHCP servers, and port security limits the number of MAC addresses allowed on a port, mitigating both starvation and rogue server attacks.",
        "DHCP starvation is a protocol for translating domain names to IP addresses; DHCP snooping and port security help to secure this translation process."
      ],
      "correctAnswerIndex": 2,
      "explanation": "DHCP starvation is a DoS attack where an attacker floods the network with DHCP requests, often using spoofed MAC addresses. This exhausts the DHCP server's pool of available IP addresses, preventing legitimate clients from obtaining IP addresses and connecting to the network. DHCP snooping prevents rogue DHCP servers by inspecting DHCP messages and only allowing those from trusted sources (usually specific switch ports connected to authorized DHCP servers). Port security limits the number of MAC addresses allowed on a switch port, which can help mitigate DHCP starvation by preventing an attacker from using a large number of spoofed MAC addresses from a single port. It's not about encryption, speeding up DHCP, or DNS.",
      "examTip": "DHCP snooping and port security are crucial security measures to prevent DHCP starvation and rogue DHCP server attacks."
    },
    {
      "id": 13,
      "question": "You are troubleshooting a network connectivity issue. A user reports they cannot access any websites, but they *can* ping external IP addresses (like 8.8.8.8) successfully.  What is the MOST likely cause, and what is the BEST command-line tool to use for further diagnosis?",
      "options": [
        "A faulty network cable; use a cable tester.",
        "A problem with the user's web browser; reinstall the browser.",
        "A DNS resolution problem; use `nslookup` (or `dig`) to query DNS servers and test name resolution.",
        "The user's default gateway is configured incorrectly."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The ability to *ping external IP addresses* rules out a basic network connectivity problem (cable) or a problem with the default gateway (which would prevent reaching *any* external IP). The inability to access websites *by name* strongly suggests a DNS resolution issue. The *best* tool for diagnosing DNS problems is `nslookup` (Windows) or `dig` (Linux/macOS). These tools allow you to directly query DNS servers and see if they can resolve domain names to IP addresses. A browser issue is possible, but less likely than a DNS problem given the symptoms.",
      "examTip": "If you can ping by IP but not by name, the problem is almost certainly with DNS resolution; use `nslookup` or `dig` to diagnose."
    },
    {
      "id": 14,
      "question": "A network is experiencing intermittent performance problems.  A protocol analyzer capture shows a large number of TCP retransmissions, but the retransmissions are *not* consistently associated with any particular source or destination IP address or port number. The issue affects multiple applications and multiple hosts. What is the MOST likely cause?",
      "options": [
        "A misconfigured DNS server.",
        "A misconfigured DHCP server.",
        "General network congestion or a faulty network device (switch, router, or cabling) causing widespread packet loss.",
        "A misconfigured firewall."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The key here is that the retransmissions are widespread and not specific to a single application, host, or port. This strongly suggests a general network problem causing packet loss, rather than an issue with a specific application, host, or service (like DNS or DHCP). The most likely causes are network congestion or faulty hardware (a failing switch, router, NIC, or cable). A misconfigured firewall would more likely block traffic consistently, not cause intermittent retransmissions across multiple applications. DNS and DHCP issues would manifest differently.",
      "examTip": "Widespread, non-specific TCP retransmissions across multiple hosts and applications usually indicate general network congestion or a faulty network device."
    },
    {
      "id": 15,
      "question": "You are configuring a Cisco router and need to control which networks are advertised by the OSPF routing protocol. Which command, and with what parameters, is used within the OSPF configuration to specify the networks that will participate in OSPF?",
      "options": [
        "router ospf 1 \n  redistribute static",
        "router ospf 1 \n  network 192.168.1.0 255.255.255.0 area 0",
        "router ospf 1 \n  network 192.168.1.0 0.0.0.255 area 0",
        "router ospf 1 \n  passive-interface GigabitEthernet0/0"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Within the OSPF configuration (`router ospf [process-id]`), the `network` command is used to define which interfaces will participate in OSPF, and in which OSPF area. Critically, the `network` command uses a *wildcard mask*, not a subnet mask. The syntax is: `network [network-address] [wildcard-mask] area [area-id]`. So, to include the 192.168.1.0/24 network in area 0, the correct command is `network 192.168.1.0 0.0.0.255 area 0`. Option B uses an incorrect subnet mask. Option A redistributes static routes, which is a different function. Option D makes an interface passive (doesn't send OSPF hellos), which is not for defining participating networks.",
      "examTip": "The `network` command in OSPF configuration uses a wildcard mask (the inverse of the subnet mask) to define participating networks and areas."
    },
    {
      "id": 16,
      "question": "A network administrator wants to implement a solution that provides centralized authentication, authorization, and accounting (AAA) for users connecting to the network via VPN. Which protocol is BEST suited for this purpose?",
      "options": [
        "SNMP (Simple Network Management Protocol)",
        "RADIUS (Remote Authentication Dial-In User Service)",
        "SMTP (Simple Mail Transfer Protocol)",
        "HTTP (Hypertext Transfer Protocol)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RADIUS (Remote Authentication Dial-In User Service) is a networking protocol specifically designed for centralized AAA. It allows a central server to authenticate users (verify their identity), authorize their access to specific network resources, and track their network usage (accounting). This is commonly used for VPN access, dial-up, and wireless authentication. SNMP is for network management, SMTP is for email, and HTTP is for web browsing.",
      "examTip": "RADIUS is the industry-standard protocol for centralized AAA in network access control, including VPNs."
    },
    {
      "id": 17,
      "question": "What is '802.1X', and how does it enhance network security?",
      "options": [
        "A wireless security protocol similar to WEP.",
        "A port-based network access control (PNAC) protocol that provides an authentication mechanism, requiring users or devices to authenticate before being granted access to the network (LAN or WLAN). It often works in conjunction with a RADIUS server.",
        "A routing protocol used for large networks.",
        "A protocol for assigning IP addresses dynamically."
      ],
      "correctAnswerIndex": 1,
      "explanation": "802.1X is a standard for port-based Network Access Control (PNAC). It provides an authentication framework that requires users or devices to prove their identity before being allowed to connect to the network. This is often used in conjunction with a RADIUS server for centralized authentication, authorization, and accounting (AAA). It significantly enhances security by preventing unauthorized devices from gaining network access. It's not just a wireless protocol (it can be used on wired networks too), a routing protocol, or DHCP.",
      "examTip": "802.1X provides authenticated network access control, verifying identity before granting access."
    },
    {
      "id": 18,
      "question": "What is 'port mirroring' (also known as 'SPAN') on a network switch, and what is a common use case?",
      "options": [
        "To encrypt network traffic for security.",
        "To restrict access to a switch port based on the connected device's MAC address.",
        "To copy network traffic from one or more source ports to a designated destination port, allowing for non-intrusive monitoring and analysis of the traffic. This is commonly used with intrusion detection systems (IDSs), intrusion prevention systems (IPSs), or protocol analyzers.",
        "To dynamically assign IP addresses to devices."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Port mirroring is a powerful diagnostic and monitoring feature on network switches. It allows you to duplicate the traffic flowing through one or more switch ports (the source ports) to another port (the destination port). You then connect a network analyzer (like Wireshark), an IDS/IPS, or another monitoring device to the destination port to capture and analyze the traffic without disrupting the normal flow of data on the source ports. It's not encryption, port security, or DHCP.",
      "examTip": "Port mirroring is essential for non-intrusive network traffic monitoring, troubleshooting, and security analysis."
    },
    {
      "id": 19,
      "question": "You are configuring a wireless network using WPA2 Enterprise. Which of the following components are REQUIRED for this configuration to function correctly?",
      "options": [
        "A pre-shared key (PSK) and MAC address filtering.",
        "A RADIUS server, 802.1X authentication, and an encryption protocol (AES/CCMP is recommended).",
        "WEP encryption and a strong password.",
        "Only a wireless access point (AP)."
      ],
      "correctAnswerIndex": 1,
      "explanation": "WPA2 Enterprise (unlike WPA2-Personal) requires several components: RADIUS server (this server handles the authentication of users or devices), 802.1X (this is the port-based network access control protocol that works with RADIUS to control network access), and an encryption protocol (while not strictly part of the authentication process, WPA2 Enterprise uses strong encryption—AES/CCMP is the standard for WPA2). A pre-shared key is used for WPA2-Personal, not Enterprise. WEP is insecure. MAC address filtering is a separate (and weak) security measure. An AP alone is insufficient.",
      "examTip": "WPA2-Enterprise requires a RADIUS server, 802.1X, and strong encryption (AES/CCMP)."
    },
    {
      "id": 20,
      "question": "A network administrator is troubleshooting a slow network connection between two devices.  They use a protocol analyzer and observe a large number of TCP retransmissions, duplicate ACKs, and TCP ZeroWindow messages.  Furthermore, they notice that the TCP sequence numbers are frequently out of order.  What is the MOST likely cause of these symptoms?",
      "options": [
        "The DNS server is not resolving domain names correctly.",
        "The DHCP server is not assigning IP addresses correctly.",
        "Packet loss and/or significant network congestion, potentially combined with a resource bottleneck on either the sending or receiving host.",
        "The web browser is misconfigured on one of the devices."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The combination of these TCP issues points directly to problems with reliable data delivery: TCP retransmissions occur when the sender doesn't receive an acknowledgment for a transmitted packet within a timeout, indicating packet loss. Duplicate ACKs indicate that the receiver is getting packets out of order, often because some packets were dropped and later ones arrived first. TCP ZeroWindow messages indicate that the receiver's buffer is full, telling the sender to stop transmitting temporarily. This can be due to network congestion or the receiver being unable to process data fast enough. Out-of-order sequence numbers reinforce the packet loss and reordering. These symptoms strongly suggest packet loss and/or congestion on the network, or potentially a resource bottleneck on one of the hosts (CPU, memory, disk I/O, or network bandwidth). It's not primarily a DNS, DHCP, or browser issue.",
      "examTip": "TCP retransmissions, duplicate ACKs, ZeroWindow messages, and out-of-order sequence numbers are strong indicators of packet loss and potential network congestion or host resource issues."
    },
    {
      "id": 21,
      "question": "A user reports being unable to access any websites, either by name (e.g., `www.example.com`) or by IP address (e.g., 8.8.8.8).  The user can, however, ping their own computer's IP address and the loopback address (127.0.0.1).  What is the MOST likely cause of the problem?",
      "options": [
        "A problem with the DNS server.",
        "A problem with the user's web browser.",
        "A problem with the physical network connection (e.g., a faulty network cable, a disabled network adapter, or a problem with the switch port), or an incorrect IP address, subnet mask, or default gateway configuration on the user's computer.",
        "The websites the user is trying to access are all down."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The ability to ping the loopback address and the computer's own IP confirms that the TCP/IP stack on the user's computer is functioning locally. The inability to access anything by IP address or name, and the inability to reach external destinations, points to a problem with the physical connection or the basic IP configuration. It's either a faulty network cable, a disabled or malfunctioning network adapter (NIC), a problem with the switch port the computer is connected to, or an incorrectly configured IP address, subnet mask, or default gateway. DNS is only for name resolution; if you can't reach anything even by IP address, DNS isn't the primary issue. A browser issue wouldn't prevent pinging. It's highly unlikely that all websites are down simultaneously.",
      "examTip": "When troubleshooting complete lack of network access, start with the physical layer (cable, NIC) and the basic IP configuration (address, mask, gateway)."
    },
    {
      "id": 22,
      "question": "You are designing a network that must support Voice over IP (VoIP) traffic.  Which of the following network performance characteristics is MOST critical for ensuring good call quality, and what QoS mechanism is commonly used to achieve it?",
      "options": [
        "High bandwidth; use traffic shaping.",
        "Low latency and low jitter; use prioritization (e.g., DSCP markings) and queuing mechanisms (e.g., priority queuing or weighted fair queuing).",
        "High throughput; use link aggregation.",
        "Low packet loss; use error correction codes."
      ],
      "correctAnswerIndex": 1,
      "explanation": "VoIP is a real-time application, meaning it's very sensitive to delay and variations in delay. The two most critical characteristics are: Low latency, which is the overall delay between when a packet is sent and when it's received (high latency causes noticeable delays in conversation), and low jitter, which is the variation in latency (high jitter causes packets to arrive at uneven intervals, leading to choppy audio and dropped syllables). While bandwidth is important, it's less critical than latency and jitter for VoIP quality (as long as there's enough bandwidth). QoS mechanisms used to achieve this include prioritization (marking VoIP packets with a high priority using DSCP values like EF - Expedited Forwarding) and queuing (using priority queuing or weighted fair queuing on routers and switches to ensure VoIP packets are sent first).",
      "examTip": "For good VoIP quality, prioritize low latency and low jitter using QoS mechanisms like prioritization and queuing."
    },
    {
      "id": 23,
      "question": "A network administrator wants to prevent unauthorized (rogue) wireless access points from being connected to the wired network. Which of the following security measures, implemented on the wired network infrastructure, would be MOST effective in achieving this?",
      "options": [
        "Implementing strong passwords on all user accounts.",
        "Enabling MAC address filtering on all wireless access points.",
        "Implementing 802.1X port-based network access control on the wired switch ports, requiring authentication before a device (including a potential rogue AP) can gain access to the network.",
        "Using WEP encryption on the wireless network."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The key here is securing the wired network against rogue wireless devices. 802.1X is a port-based Network Access Control (PNAC) standard. It requires devices connecting to a network port (wired or wireless) to authenticate before being granted access. By implementing 802.1X on the wired switch ports, you prevent a rogue AP from connecting to the wired network and bridging unauthorized wireless clients onto the corporate network. Strong passwords are important, but don't prevent a rogue AP from connecting. MAC filtering is easily bypassed. WEP is an insecure wireless protocol, and the question is about securing the wired network.",
      "examTip": "Use 802.1X on wired switch ports to prevent rogue access points from bridging unauthorized wireless clients onto the wired network."
    },
    {
      "id": 24,
      "question": "A network is experiencing intermittent performance problems.  A protocol analyzer capture shows a large number of TCP retransmissions, but the retransmissions are not consistently associated with any particular source or destination IP address or port number. The issue affects multiple applications and multiple hosts. What is the MOST likely cause?",
      "options": [
        "A misconfigured DNS server.",
        "A misconfigured DHCP server.",
        "General network congestion or a faulty network device (switch, router, or cabling) causing widespread packet loss.",
        "A misconfigured firewall."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The key here is that the retransmissions are widespread and not specific to a single application, host, or port. This strongly suggests a general network problem causing packet loss, rather than an issue with a specific application, host, or service. The most likely causes are network congestion or faulty hardware (a failing switch, router, NIC, or cable). A misconfigured firewall would more likely block traffic consistently, not cause intermittent retransmissions across multiple applications. DNS and DHCP issues would manifest differently.",
      "examTip": "Widespread, non-specific TCP retransmissions across multiple hosts and applications usually indicate general network congestion or a faulty network device."
    },
    {
      "id": 25,
      "question": "A network administrator is configuring a new VLAN on a Cisco switch.  After creating the VLAN, they assign several switch ports to it.  However, devices connected to those ports cannot communicate with each other, even though they have valid IP addresses within the same subnet. What is the MOST likely cause of this problem, and what command would you use to verify the configuration?",
      "options": [
        "The switch ports are configured as trunk ports; use the `show interfaces trunk` command.",
        "The Spanning Tree Protocol (STP) is blocking the ports; use the `show spanning-tree` command.",
        "The switch ports are not in the correct VLAN, or are not in the active state for that VLAN; use the `show vlan brief` command.",
        "The default gateway is not configured on the client devices; use the `ipconfig /all` command on each client."
      ],
      "correctAnswerIndex": 2,
      "explanation": "If devices are on the same subnet but cannot communicate, and they are connected to the same switch, the most likely issue is with the VLAN configuration on the switch. The ports might not be assigned to the correct VLAN, or the VLAN itself might not be active. The `show vlan brief` command on a Cisco switch is the best way to quickly verify this. It shows the VLAN ID and name, status (active/suspended), and the ports assigned to each VLAN. If the ports are not listed for the correct VLAN, or if the VLAN is not in the active state, that's the problem. Trunk ports are for carrying multiple VLANs (usually between switches). STP prevents loops; if it were blocking a port, you'd see that in `show spanning-tree`, but it wouldn't explain the VLAN-specific isolation. The default gateway is for communication outside the subnet, not within it.",
      "examTip": "Use `show vlan brief` on a Cisco switch to quickly verify VLAN assignments and status."
    },
    {
      "id": 26,
      "question": "You are designing a network for a company with a main office and several small branch offices. Each branch office needs secure access to resources at the main office. What is the MOST cost-effective and secure way to connect the branch offices to the main office?",
      "options": [
        "Connect each branch office directly to the main office using public Wi-Fi hotspots.",
        "Configure site-to-site VPN tunnels between each branch office's router/firewall and the main office's router/firewall.",
        "Establish a dedicated leased line between each branch office and the main office.",
        "Configure a wireless mesh network spanning all locations."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Site-to-site VPNs create secure, encrypted tunnels over the public internet, connecting the networks of the branch offices to the main office network. This is generally much more cost-effective than dedicated leased lines, and it provides strong security. Public Wi-Fi is extremely insecure and unsuitable. Leased lines are secure but very expensive. A wireless mesh is more appropriate for local wireless coverage within a site, not for connecting geographically separate sites.",
      "examTip": "Site-to-site VPNs are a cost-effective and secure way to connect geographically dispersed offices over the public internet."
    },
    {
      "id": 27,
      "question": "A network administrator configures a new switch. After connecting several devices, they notice that communication between some devices is very slow, while others seem to be working fine. The administrator suspects a duplex mismatch. Which command on a Cisco switch would allow them to verify the speed and duplex settings of a specific interface (e.g., GigabitEthernet0/1)?",
      "options": [
        "show interfaces status",
        "show interfaces description",
        "show interfaces GigabitEthernet0/1",
        "show cdp neighbors"
      ],
      "correctAnswerIndex": 2,
      "explanation": "While `show interfaces status` can provide a brief overview, the most detailed information about a specific interface, including speed and duplex settings, is obtained with `show interfaces [interface_name]`. So, `show interfaces GigabitEthernet0/1` would show the speed, duplex, and other detailed statistics for that specific port. `show interfaces description` shows only the description (if configured). `show cdp neighbors` shows directly connected Cisco devices.",
      "examTip": "Use `show interfaces [interface_name]` on a Cisco switch to view detailed information about a specific interface, including speed and duplex settings."
    },
    {
      "id": 28,
      "question": "Which of the following is the MOST accurate description of 'MAC address spoofing', and what is a potential security implication?",
      "options": [
        "Dynamically assigning IP addresses to devices on a network.",
        "Encrypting network traffic to protect data confidentiality.",
        "Changing a device's MAC address to impersonate another device, potentially bypassing MAC address filtering, gaining unauthorized network access, or launching man-in-the-middle attacks.",
        "A method for prioritizing different types of network traffic."
      ],
      "correctAnswerIndex": 2,
      "explanation": "MAC addresses are supposed to be unique, hard-coded identifiers for network interface cards. However, it's possible to change (spoof) a device's MAC address using software tools. Attackers can use this to bypass MAC address filtering if a network only allows specific MAC addresses, impersonate other devices to intercept traffic or launch attacks, or evade detection by constantly changing their MAC address. It's not about IP assignment, encryption, or QoS.",
      "examTip": "MAC address spoofing is a technique used to impersonate devices and bypass security measures that rely on MAC addresses."
    },
    {
      "id": 29,
      "question": "A network administrator is implementing 802.1X authentication on a wired network. Which of the following components are typically involved in an 802.1X setup?",
      "options": [
        "A pre-shared key (PSK) and WEP encryption.",
        "A supplicant (client device), an authenticator (switch or access point), and an authentication server (usually a RADIUS server).",
        "A DHCP server and a DNS server.",
        "A firewall and a VPN gateway."
      ],
      "correctAnswerIndex": 1,
      "explanation": "802.1X is a port-based Network Access Control (PNAC) standard. It requires three main components: Supplicant (the device, such as a laptop or phone, requesting network access), Authenticator (the network device, typically a switch or wireless access point, that controls access to the network), and Authentication Server (usually a RADIUS server, which verifies the supplicant's credentials and authorizes network access). A pre-shared key is used in WPA2-Personal, not 802.1X. WEP is insecure. DHCP and DNS are network services, but not directly part of 802.1X. A firewall and VPN are security components, but not core to 802.1X itself.",
      "examTip": "802.1X authentication typically involves a supplicant, an authenticator, and a RADIUS server."
    },
    {
      "id": 30,
      "question": "You are troubleshooting a network where some users can access a particular website, while others cannot. All users are on the same subnet and use the same DNS servers.  You suspect a problem with DNS caching. Which command on a Windows computer would you use to clear the local DNS resolver cache?",
      "options": [
        "ping [website address]",
        "tracert [website address]",
        "ipconfig /flushdns",
        "ipconfig /release"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The `ipconfig /flushdns` command on a Windows computer clears the local DNS resolver cache. This forces the computer to query the DNS server again for name resolution, which can resolve issues caused by outdated or incorrect cached DNS entries. `ping` tests basic connectivity, `tracert` shows the route, and `ipconfig /release` releases the DHCP lease (not directly related to DNS caching). Since some users can access the site, it's unlikely to be a global DNS issue; it's more likely a local caching problem.",
      "examTip": "`ipconfig /flushdns` is a useful command for troubleshooting DNS resolution problems by clearing the local DNS cache on Windows."
    },
    {
      "id": 31,
      "question": "What is 'split horizon' with 'poison reverse', and how does it compare to basic split horizon in preventing routing loops in distance-vector routing protocols?",
      "options": [
        "Split horizon with poison reverse is a method for encrypting routing updates.",
        "Split horizon with poison reverse is a way to prioritize certain routes over others.",
        "Split horizon prevents a router from advertising a route back out the same interface it was learned on. Poison reverse does advertise the route back out the same interface, but with an infinite metric, making it clearly unreachable. This combination is more robust than basic split horizon alone.",
        "Split horizon with poison reverse is a technique for load balancing traffic."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Both are loop-prevention techniques for distance-vector protocols (like RIP). Split horizon prevents a router from advertising a route back out the same interface it learned that route from, which helps prevent simple loops. Poison reverse, on the other hand, advertises the route back out the same interface but with an infinite metric, effectively indicating that the route is unreachable through that interface. This active notification helps prevent more complex loops and speeds up convergence. It's not about encryption, prioritization, or load balancing.",
      "examTip": "Split horizon with poison reverse is a more effective loop prevention technique than basic split horizon in distance-vector routing."
    },
    {
      "id": 32,
      "question": "A network uses the OSPF routing protocol. A network administrator wants to ensure that routing updates are authenticated to prevent malicious or accidental injection of false routing information. Which OSPF feature should be configured?",
      "options": [
        "OSPF route summarization",
        "OSPF split horizon",
        "OSPF MD5 authentication",
        "OSPF equal-cost multi-path (ECMP)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "OSPF supports authentication to ensure that only trusted routers participate in the routing process and that routing updates are legitimate. MD5 authentication is a commonly used method. It requires routers to share a secret key and use it to generate a cryptographic hash (digest) of each OSPF packet. This hash is included in the packet, and receiving routers can verify the hash to ensure the packet's authenticity and integrity. Route summarization reduces routing table size, split horizon prevents loops, and ECMP allows load balancing; none of these directly provide authentication.",
      "examTip": "Use OSPF authentication (e.g., MD5) to secure OSPF routing updates and prevent unauthorized routers from participating in the routing process."
    },
    {
      "id": 33,
      "question": "You are troubleshooting a slow network connection.  You suspect that packet fragmentation is occurring. Which of the following tools and techniques would be MOST effective in identifying if fragmentation is happening and where it's occurring along the path?",
      "options": [
        "A cable tester.",
        "ping with varying packet sizes and the 'Don't Fragment' (DF) bit set in the IP header, combined with a protocol analyzer (like Wireshark) to examine IP header fragmentation flags.",
        "nslookup to check DNS resolution.",
        "ipconfig /all to check local network interface configuration."
      ],
      "correctAnswerIndex": 1,
      "explanation": "To diagnose fragmentation, you need to test for MTU limitations by using ping with increasing packet sizes and the Don't Fragment (DF) bit set. If a packet is too large for a link along the path and the DF bit is set, the router will send back an ICMP \"Fragmentation Needed and DF bit set\" message indicating the MTU of that link. Additionally, a protocol analyzer like Wireshark can capture traffic and show the IP header fields that indicate fragmentation. A cable tester checks physical cables, nslookup is for DNS, and ipconfig /all shows local configuration.",
      "examTip": "Use ping with the DF bit and varying packet sizes, combined with a protocol analyzer, to diagnose packet fragmentation issues."
    },
    {
      "id": 34,
      "question": "What is a 'zero-day' vulnerability, and why is it considered a particularly serious security threat?",
      "options": [
        "A vulnerability that has been known for a long time and has many available patches.",
        "A software or hardware vulnerability that is unknown to, or unaddressed by, the vendor (or the security community in general), meaning there is no patch available, and attackers can exploit it *before* a fix is released.",
        "A vulnerability that only affects outdated operating systems.",
        "A vulnerability that is easily detected and prevented by basic firewalls."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Zero-day vulnerabilities are *extremely* dangerous because they are *unknown* to the software or hardware vendor (or there's no patch yet). This gives attackers a window of opportunity to exploit the vulnerability *before* the vendor is even aware of the problem or can develop a fix. They are *not* known and patched vulnerabilities, not limited to old OSes, and not easily detected/prevented by *basic* firewalls (advanced intrusion prevention systems *might* offer some protection based on behavioral analysis).",
      "examTip": "Zero-day vulnerabilities are highly prized by attackers and pose a significant security risk due to their unknown and unpatched nature."
    },
    {
      "id": 35,
      "question": "A network administrator is designing a network for a financial institution. Data security and confidentiality are paramount. Which of the following combinations of security measures would provide the MOST robust protection for sensitive data in transit and at rest?",
      "options": [
        "Strong passwords and a firewall.",
        "Encryption of data in transit (using protocols like TLS/SSL or IPsec), encryption of data at rest (using full-disk encryption or file-level encryption), strong authentication (multi-factor authentication), network segmentation (VLANs), intrusion prevention systems (IPS), regular security audits, and a robust security policy.",
        "WEP encryption for wireless and MAC address filtering.",
        "Hiding the SSID of the wireless network and using a DMZ."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Securing sensitive data requires a multi-layered approach (defense in depth): *Data in transit encryption:* Use protocols like TLS/SSL (for web traffic, etc.) or IPsec (for VPNs) to encrypt data as it travels across the network. *Data at rest encryption:* Use full-disk encryption (e.g., BitLocker, FileVault) or file-level encryption to protect data stored on servers and devices. *Strong authentication:* Implement multi-factor authentication (MFA) to verify user identities. *Network segmentation:* Use VLANs to isolate sensitive data and systems from less critical parts of the network. *Intrusion Prevention Systems (IPS):* To detect and block malicious traffic. *Regular security audits:* To identify vulnerabilities and ensure security controls are effective. *Robust security policy:* To define security rules and procedures. Strong passwords and a firewall are important, but insufficient on their own. WEP is insecure, and MAC filtering is easily bypassed. Hiding the SSID provides obscurity, not true security, and a DMZ is for publicly accessible servers, not for protecting internal data.",
      "examTip": "Protecting sensitive data requires a multi-layered approach, including encryption, strong authentication, network segmentation, intrusion prevention, and regular security audits."
    },
    {
      "id": 36,
      "question": "You are troubleshooting a network where a particular server is experiencing very high CPU utilization and slow response times. Network monitoring tools show a large volume of incoming TCP SYN packets to that server, but relatively few established TCP connections. What type of attack is MOST likely occurring, and what is a common mitigation technique?",
      "options": [
        "A man-in-the-middle (MitM) attack; implement stronger encryption.",
        "A phishing attack; train users to recognize phishing emails.",
        "A SYN flood attack (a type of denial-of-service attack); implement SYN cookies or other SYN flood mitigation techniques on the firewall or server.",
        "An ARP spoofing attack; implement Dynamic ARP Inspection (DAI)."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A *SYN flood attack* is a type of denial-of-service (DoS) attack that exploits the TCP three-way handshake. The attacker sends a flood of TCP SYN packets (the first step in establishing a TCP connection) to the server, often with spoofed source IP addresses. The server responds with SYN-ACK packets, but the attacker never sends the final ACK, leaving the server with many half-open connections consuming resources (CPU, memory). This prevents legitimate clients from establishing connections. A MitM attack intercepts traffic, phishing is about deception, and ARP spoofing targets MAC address resolution. *SYN cookies* are a common mitigation technique: the server doesn’t allocate resources until it receives the final ACK, preventing resource exhaustion.",
      "examTip": "A SYN flood attack is a type of DoS attack that exploits the TCP handshake to overwhelm a server with half-open connections."
    },
    {
      "id": 37,
      "question": "A network uses OSPF as its routing protocol. The network administrator wants to prevent a specific router from becoming the Designated Router (DR) or Backup Designated Router (BDR) on a particular multi-access network segment. How can the administrator achieve this?",
      "options": [
        "Configure a higher OSPF cost on the router's interface.",
        "Configure the router's OSPF priority to 0 on the relevant interface.",
        "Disable OSPF on the router.",
        "Configure the router as a stub area border router (ABR)."
      ],
      "correctAnswerIndex": 1,
      "explanation": "In OSPF, on multi-access networks (like Ethernet), a Designated Router (DR) and Backup Designated Router (BDR) are elected to minimize the number of adjacencies formed. The router with the highest OSPF priority on the segment becomes the DR, and the router with the second-highest priority becomes the BDR. To prevent a router from becoming DR or BDR, you can set its OSPF priority to 0 on the relevant interface. Changing the cost affects route selection, but not DR/BDR election. Disabling OSPF would remove the router from the OSPF process entirely. An ABR connects different OSPF areas.",
      "examTip": "Set the OSPF priority to 0 on an interface to prevent a router from becoming DR or BDR on a multi-access segment."
    },
    {
      "id": 38,
      "question": "A network administrator is configuring a Cisco router with the following commands: `router ospf 1` `network 192.168.1.0 0.0.0.255 area 0` `network 172.16.0.0 0.0.15.255 area 1` `network 10.0.0.0 0.255.255.255 area 0` What is the effect of this configuration?",
      "options": [
        "It enables OSPF on the router but does not include any interfaces in the OSPF process.",
        "It enables OSPF on the router and includes interfaces with IP addresses in the 192.168.1.0/24, 172.16.0.0/20, and 10.0.0.0/8 networks in the OSPF process, placing the 192.168.1.0/24 and 10.0.0.0/8 networks in area 0 and the 172.16.0.0/20 network in area 1.",
        "It enables OSPF on the router and includes all interfaces in area 0.",
        "It enables RIP on the router."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`router ospf 1` enables OSPF with process ID 1. The `network` commands define which interfaces will participate in OSPF and which OSPF area they belong to. The command uses wildcard masks, which are the inverse of subnet masks: `network 192.168.1.0 0.0.0.255 area 0` includes interfaces with IPs in the 192.168.1.0/24 network in area 0; `network 172.16.0.0 0.0.15.255 area 1` includes interfaces with IPs in the 172.16.0.0/20 network in area 1; `network 10.0.0.0 0.255.255.255 area 0` includes interfaces with IPs in the 10.0.0.0/8 network in area 0. It's not RIP, and it doesn't place all interfaces in area 0.",
      "examTip": "Understand how the `network` command in OSPF configuration uses wildcard masks to define which interfaces participate in which OSPF areas."
    },
    {
      "id": 39,
      "question": "Which of the following statements accurately describes the difference between 'stateful' and 'stateless' firewalls?",
      "options": [
        "Stateful firewalls are less secure than stateless firewalls.",
        "Stateful firewalls only examine individual packets in isolation, based on predefined rules (like source/destination IP address, port); stateless firewalls track the state of network connections (e.g., TCP sessions) and make filtering decisions based on both packet headers and the connection context.",
        "Stateless firewalls only examine individual packets in isolation, based on predefined rules; stateful firewalls track the state of network connections (e.g. TCP sessions) and make filtering decisions based on both packet headers and the connection context.",
        "Stateful firewalls are only used for wireless networks; stateless firewalls are only used for wired networks."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Stateless firewalls (also called packet filters) examine each packet individually, based on rules that typically consider source/destination IP address, port numbers, and protocol. They do not keep track of the state of network connections. Stateful firewalls, on the other hand, maintain a table of active connections and can distinguish between legitimate return traffic for an established connection and unsolicited incoming traffic, providing much better security. Stateful firewalls are more secure, not less, and are used in all types of networks.",
      "examTip": "Stateful firewalls provide more robust security than stateless firewalls by considering the context of network connections."
    },
    {
      "id": 40,
      "question": "What is 'MAC flooding', and how does it affect the operation of a network switch?",
      "options": [
        "A technique for encrypting network traffic to protect data confidentiality.",
        "A method for dynamically assigning IP addresses to devices on a network.",
        "An attack that overwhelms a switch's CAM table (Content Addressable Memory) with fake MAC addresses, causing the switch to exhaust its resources and start behaving like a hub, forwarding traffic to all ports. This allows an attacker to potentially eavesdrop on network traffic.",
        "A technique for prioritizing different types of network traffic to improve performance."
      ],
      "correctAnswerIndex": 2,
      "explanation": "MAC flooding is an attack that targets the MAC address learning mechanism of network switches. Switches maintain a CAM table that maps MAC addresses to switch ports. In a MAC flooding attack, the attacker sends a large number of frames with different, fake source MAC addresses. This fills up the switch's CAM table. When the CAM table is full, the switch can no longer learn new MAC addresses and, in many cases, will start flooding traffic out all ports (like a hub). This allows the attacker to potentially sniff traffic that they shouldn't be able to see. It is not encryption, DHCP, or QoS.",
      "examTip": "MAC flooding attacks can compromise network security by causing switches to flood traffic, allowing attackers to eavesdrop."
    },
    {
      "id": 41,
      "question": "What is 'DHCP snooping', and which types of attacks does it help prevent?",
      "options": [
        "A method for encrypting DHCP traffic.",
        "A switch security feature that inspects DHCP messages and only allows DHCP traffic from trusted sources (typically, designated DHCP server ports), preventing rogue DHCP servers from operating on the network and mitigating DHCP starvation attacks.",
        "A technique for speeding up the DHCP address assignment process.",
        "A protocol for monitoring user web browsing activity."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DHCP snooping is a security feature implemented on network switches to prevent rogue DHCP servers and DHCP starvation attacks. The switch learns which ports are connected to trusted DHCP servers (usually through manual configuration) and only allows DHCP server responses to come from those trusted ports. It drops DHCP messages from untrusted sources. This prevents attackers from setting up rogue DHCP servers or exhausting the DHCP server's address pool. It is not encryption, a speed-up technique, or web monitoring.",
      "examTip": "DHCP snooping is a critical security measure to prevent rogue DHCP servers and DHCP starvation attacks."
    },
    {
      "id": 42,
      "question": "A user reports that they can access some websites but not others. They can successfully ping the IP addresses of all the websites, both the working and non-working ones. `nslookup [hostname]` fails on the user's computer, but `nslookup [hostname] [different_dns_server]` (using a known, working public DNS server like 8.8.8.8) succeeds. What is the MOST likely cause, and what action should you take?",
      "options": [
        "The server is down.",
        "The user's network cable is faulty.",
        "The problem is with the internal DNS server that the user's computer is configured to use. It is either unreachable, not functioning correctly, or does not have the correct record for the server's hostname. You should investigate the internal DNS server, check its configuration, and ensure it has the correct records.",
        "The user's computer has a virus."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The ability to ping the server's IP rules out basic network connectivity issues. The fact that `nslookup` fails with the user's configured DNS server but succeeds with a different, known-good DNS server strongly indicates that the problem is with the internal DNS server the user's computer is using. The internal DNS server may be unreachable, malfunctioning, or missing the correct record. The solution is to investigate and fix the internal DNS server.",
      "examTip": "If `nslookup` fails with the default DNS server but works with a different server, the problem is likely with the default DNS server's configuration or availability."
    },
    {
      "id": 43,
      "question": "You are designing a network for a company with multiple departments (e.g., Sales, Marketing, Engineering, Finance). Each department needs to be logically isolated from the others for security reasons, but some limited communication between departments needs to be allowed (e.g., access to a shared file server). Which of the following network designs, using a combination of technologies, would be MOST appropriate?",
      "options": [
        "Connect all devices to a single, unmanaged switch.",
        "Implement VLANs to segment the network into separate broadcast domains for each department, use a Layer 3 switch or router for inter-VLAN routing, and configure access control lists (ACLs) on the router/switch to control traffic flow between VLANs.",
        "Configure all devices to use the same IP subnet.",
        "Implement MAC address filtering on all network devices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "This scenario requires logical segmentation and controlled inter-segment communication. The best approach is to use VLANs to assign each department to a separate broadcast domain, use a Layer 3 switch or router for inter-VLAN routing, and then apply ACLs to control which traffic can flow between departments. A single unmanaged switch provides no segmentation, using the same subnet defeats the purpose, and MAC filtering is easily bypassed.",
      "examTip": "Use VLANs for logical segmentation, a Layer 3 device for inter-VLAN routing, and ACLs to control traffic flow between segments."
    },
    {
      "id": 44,
      "question": "A network administrator wants to configure a Cisco router to obtain its WAN interface IP address automatically from an ISP using DHCP. Which of the following command sequences is correct?",
      "options": [
        "interface GigabitEthernet0/0 \n ip address dhcp",
        "interface GigabitEthernet0/0 \n ip address 192.168.1.1 255.255.255.0 \n ip dhcp client",
        "ip dhcp pool WAN \n network dhcp",
        "interface GigabitEthernet0/0 \n ip helper-address dhcp"
      ],
      "correctAnswerIndex": 0,
      "explanation": "To configure a Cisco router interface to obtain an IP address via DHCP, use the `ip address dhcp` command on the interface. Assuming the WAN interface is GigabitEthernet0/0, the correct sequence is to enter interface configuration mode and then use `ip address dhcp`. Option B sets a static IP and incorrectly uses `ip dhcp client`. Option C configures the router as a DHCP server, and Option D is used to relay DHCP requests on different subnets.",
      "examTip": "Use the `ip address dhcp` command on a Cisco router interface to obtain an IP address via DHCP."
    },
    {
      "id": 45,
      "question": "What is 'BGP hijacking', and what is a potential consequence?",
      "options": [
        "A type of phishing attack.",
        "An attack where a malicious actor compromises a router and falsely advertises routes to redirect network traffic, potentially leading to traffic interception, denial of service, or blackholing.",
        "A technique for encrypting network traffic.",
        "A method for dynamically assigning IP addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "BGP hijacking is an attack on Border Gateway Protocol where an attacker compromises a router or exploits a misconfiguration to falsely advertise routes for IP address prefixes that they do not control. This causes traffic intended for the legitimate owner of those IP addresses to be redirected to the attacker's network, potentially allowing for traffic interception, denial of service, or blackholing.",
      "examTip": "BGP hijacking is a serious attack that can disrupt internet routing and redirect traffic to malicious actors."
    },
    {
      "id": 46,
      "question": "Which of the following statements BEST describes the difference between 'authentication', 'authorization', and 'accounting' (AAA) in network security?",
      "options": [
        "They are all different terms for the same process.",
        "Authentication verifies a user's or device's identity. Authorization determines what resources or actions the authenticated user/device is permitted to access. Accounting tracks the user/device's activity and resource usage.",
        "Authentication assigns IP addresses, authorization encrypts data, and accounting manages user accounts.",
        "Authentication filters network traffic, authorization translates domain names, and accounting provides wireless access."
      ],
      "correctAnswerIndex": 1,
      "explanation": "AAA is a framework for controlling access to network resources and tracking their usage. Authentication verifies who or what is requesting access, authorization determines what an authenticated user or device is allowed to do, and accounting tracks the activity of authenticated users and devices. They are not synonyms, nor are they IP assignment, encryption, filtering, or DNS functions.",
      "examTip": "Remember AAA: Authentication (who are you?), Authorization (what are you allowed to do?), and Accounting (what did you do?)."
    },
    {
      "id": 47,
      "question": "A network administrator wants to implement a security mechanism that will dynamically inspect network traffic and automatically block or prevent malicious activity in real-time, based on signatures, anomalies, or behavioral analysis. Which technology is BEST suited for this purpose?",
      "options": [
        "A firewall.",
        "An intrusion detection system (IDS).",
        "An intrusion prevention system (IPS).",
        "A virtual private network (VPN)."
      ],
      "correctAnswerIndex": 2,
      "explanation": "An Intrusion Prevention System (IPS) actively monitors network traffic and takes action to block or prevent malicious activity in real-time. An IDS only detects and alerts without blocking, a firewall enforces predefined rules but may not dynamically detect threats, and a VPN provides secure remote access rather than intrusion prevention.",
      "examTip": "An IPS provides active, real-time protection against network attacks, going beyond the detection capabilities of an IDS."
    },
    {
      "id": 48,
      "question": "What is 'multicast' addressing, and how does it differ from unicast and broadcast addressing?",
      "options": [
        "Multicast sends data to all devices on a network; unicast sends data to a single device; broadcast sends data to a specific group of devices.",
        "Multicast sends data to a specific group of devices that have joined a multicast group; unicast sends data to a single, specific device; broadcast sends data to all devices on a network segment.",
        "Multicast sends data to a single device; unicast sends data to all devices; broadcast sends data to a specific group of devices.",
        "Multicast sends data to all devices on a specific VLAN; unicast sends data to all devices on the network; broadcast sends data to a single device."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Unicast sends data to a single, specific destination IP address. Broadcast sends data to all devices on a local network segment. Multicast sends data to a specific group of devices that have joined a multicast group. This method is more efficient than broadcast for applications where only certain devices need the data.",
      "examTip": "Unicast: one-to-one; Broadcast: one-to-all (local); Multicast: one-to-many (specific group)."
    },
    {
      "id": 49,
      "question": "You are troubleshooting a network connectivity issue where a user cannot access a specific website. You can ping the website's IP address successfully. `nslookup` also resolves the website's domain name correctly. However, when you try to access the website using a web browser, you get a 'connection timed out' error. What is the MOST likely cause?",
      "options": [
        "A problem with the user's network cable.",
        "A DNS resolution problem.",
        "A firewall blocking access to the website, a problem with the web server itself (e.g., it's down or overloaded), or a routing problem between your network and the web server (but after the point where the ping succeeded).",
        "The user's computer has a virus."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Since the website's IP can be pinged and DNS resolution works correctly, basic connectivity and DNS are not the issues. The 'connection timed out' error in the browser indicates that the connection to the web server is being blocked or is failing after the initial connectivity check. This suggests the presence of a firewall blocking web traffic, an issue with the web server itself, or a routing problem affecting the specific traffic.",
      "examTip": "If you can ping an IP and DNS resolves correctly but the browser times out, suspect a firewall, a web server issue, or a routing problem affecting that traffic."
    },
    {
      "id": 50,
      "question": "A network administrator wants to configure a Cisco router to act as a DHCP server. They have defined the DHCP pool, network, default gateway, and DNS servers. However, they want to ensure that the IP addresses 192.168.1.1 through 192.168.1.10 and the address 192.168.1.254 are not assigned by DHCP. Which of the following commands, entered in global configuration mode, would correctly exclude these addresses?",
      "options": [
        "ip dhcp excluded-address 192.168.1.1 192.168.1.10",
        "ip dhcp excluded-address 192.168.1.1 192.168.1.10 192.168.1.254",
        "ip dhcp excluded-address 192.168.1.1-192.168.1.10 192.168.1.254",
        "ip dhcp excluded-address 192.168.1.1 192.168.1.10 \n ip dhcp excluded-address 192.168.1.254"
      ],
      "correctAnswerIndex": 3,
      "explanation": "The `ip dhcp excluded-address` command is used to prevent the DHCP server from assigning specific IP addresses or ranges. To exclude non-contiguous addresses (a range and a single IP), you must use separate commands. Option A excludes only the range 192.168.1.1-192.168.1.10. Options B and C use incorrect syntax. Option D correctly uses two separate commands to exclude the desired addresses.",
      "examTip": "Use separate `ip dhcp excluded-address` commands to exclude non-contiguous IP addresses from DHCP assignment."
    },
    {
      "id": 51,
      "question": "A network administrator configures a Cisco switch with the following commands: \ninterface GigabitEthernet0/1\nswitchport mode trunk\nswitchport trunk encapsulation dot1q\nswitchport trunk allowed vlan 10,20,30\nWhat is the effect of this configuration?",
      "options": [
        "The interface will be an access port for VLANs 10, 20, and 30.",
        "The interface will be a trunk port, carrying traffic for VLANs 10, 20, and 30, using 802.1Q tagging.",
        "The interface will be disabled.",
        "The interface will be an access port for VLAN 10 only."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The command `switchport mode trunk` configures the interface as a trunk port, meaning it carries traffic for multiple VLANs. `switchport trunk encapsulation dot1q` specifies that 802.1Q tagging is used. `switchport trunk allowed vlan 10,20,30` limits the trunk to only VLANs 10, 20, and 30. The interface is not an access port, not disabled, and not limited to a single VLAN.",
      "examTip": "Trunk ports carry traffic for multiple VLANs using tagging (802.1Q)."
    },
    {
      "id": 52,
      "question": "You are troubleshooting a network connectivity issue. `ping` requests to a remote host are failing with the error message 'Request timed out'. However, you can successfully `traceroute` to the same host, and the traceroute output shows all hops along the path. What is a POSSIBLE explanation for this behavior?",
      "options": [
        "The remote host is down.",
        "The remote host is configured to block ICMP Echo Request packets (or a firewall along the path is blocking them), but it is still forwarding other types of traffic.",
        "The DNS server is not resolving the hostname correctly.",
        "The local computer's network cable is unplugged."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A successful traceroute indicates that packets are reaching the destination and that intermediate routers are responding. The failure of `ping` (which uses ICMP Echo Request packets) suggests that the destination host or a nearby firewall is blocking ICMP, while still allowing other types of traffic.",
      "examTip": "If traceroute succeeds but ping fails, ICMP may be blocked by the destination or a nearby firewall."
    },
    {
      "id": 53,
      "question": "A network administrator wants to configure a Cisco router to redistribute routes learned from OSPF into EIGRP. Which of the following commands, entered in router configuration mode for EIGRP, would achieve this?",
      "options": [
        "router eigrp 100 \n network 192.168.1.0",
        "router eigrp 100 \n redistribute static",
        "router eigrp 100 \n redistribute ospf 1 metric 10000 100 255 1 1500",
        "router eigrp 100 \n passive-interface GigabitEthernet0/1"
      ],
      "correctAnswerIndex": 2,
      "explanation": "To redistribute routes from OSPF into EIGRP, use the `redistribute` command within the EIGRP configuration. The syntax requires specifying the source protocol (OSPF) with its process ID and the metric values required by EIGRP. Option C correctly redistributes OSPF routes (assuming OSPF process ID 1) into EIGRP with the necessary metric.",
      "examTip": "Use the `redistribute` command with appropriate metric values in EIGRP configuration to redistribute OSPF routes."
    },
    {
      "id": 54,
      "question": "What is '802.1X', and how does it relate to RADIUS and EAP in the context of network access control?",
      "options": [
        "802.1X is a wireless security protocol, RADIUS is a routing protocol, and EAP is a type of network cable.",
        "802.1X is a port-based Network Access Control (PNAC) standard that provides an authentication framework; RADIUS is a protocol often used as the authentication server in an 802.1X setup; and EAP (Extensible Authentication Protocol) is a framework that allows for various authentication methods to be used within 802.1X.",
        "802.1X is a protocol for assigning IP addresses dynamically, RADIUS is a protocol for encrypting network traffic, and EAP is a method for filtering MAC addresses.",
        "802.1X is a type of firewall, RADIUS is a type of intrusion detection system, and EAP is a type of network monitoring tool."
      ],
      "correctAnswerIndex": 1,
      "explanation": "802.1X is a standard for port-based Network Access Control (PNAC) that defines a framework for authenticating users and devices before granting network access. RADIUS is commonly used as the authentication server in an 802.1X setup, while EAP provides a framework for various authentication methods. They work together to provide secure network access.",
      "examTip": "802.1X (PNAC) + RADIUS (AAA Server) + EAP (Authentication Methods) = Secure Network Access Control."
    },
    {
      "id": 55,
      "question": "You are troubleshooting a network connectivity issue. A user reports being unable to access a specific internal server by its hostname. You can successfully ping the server's IP address from the user's computer. `nslookup [hostname]` fails on the user's computer, but `nslookup [hostname] [different_dns_server]` (using a known, working public DNS server like 8.8.8.8) succeeds. What is the MOST likely cause, and what action should you take?",
      "options": [
        "The server is down.",
        "The user's network cable is faulty.",
        "The problem is with the internal DNS server that the user's computer is configured to use. It is either unreachable, not functioning correctly, or does not have the correct record for the server's hostname. You should investigate the internal DNS server, check its configuration, and ensure it has the correct records.",
        "The user's computer has a virus."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Since the server's IP can be pinged and `nslookup` works when using a known-good DNS server, the issue is with the internal DNS server that the user's computer is configured to use. This server may be unreachable, malfunctioning, or missing the correct record. The solution is to investigate and fix the internal DNS server.",
      "examTip": "If `nslookup` fails with the default DNS server but works with a different server, the problem is likely with the default DNS server's configuration or availability."
    },
    {
      "id": 56,
      "question": "A network administrator is configuring a new VLAN on a Cisco switch. After creating the VLAN, they assign several switch ports to it. However, devices connected to those ports cannot communicate with each other, even though they have valid IP addresses within the same subnet. What is the MOST likely cause of this problem, and what command would you use to verify the configuration?",
      "options": [
        "The switch ports are configured as trunk ports; use the `show interfaces trunk` command.",
        "The Spanning Tree Protocol (STP) is blocking the ports; use the `show spanning-tree` command.",
        "The switch ports are not in the correct VLAN, or are not in the active state for that VLAN; use the `show vlan brief` command.",
        "The default gateway is not configured on the client devices; use the `ipconfig /all` command on each client."
      ],
      "correctAnswerIndex": 2,
      "explanation": "If devices on the same subnet cannot communicate and are connected to the same switch, the most likely issue is with the VLAN configuration. The ports might not be assigned to the correct VLAN or the VLAN might not be active. The `show vlan brief` command is the best way to verify VLAN assignments and status on a Cisco switch.",
      "examTip": "Use `show vlan brief` to quickly verify VLAN assignments and status on a Cisco switch."
    },
    {
      "id": 57,
      "question": "A network administrator wants to design a network for a company with a main office and several small branch offices. Each branch office needs secure access to resources at the main office. What is the MOST cost-effective and secure way to connect the branch offices to the main office?",
      "options": [
        "Connect each branch office directly to the main office using public Wi-Fi hotspots.",
        "Configure site-to-site VPN tunnels between each branch office's router/firewall and the main office's router/firewall.",
        "Establish a dedicated leased line between each branch office and the main office.",
        "Configure a wireless mesh network spanning all locations."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Site-to-site VPNs create secure, encrypted tunnels over the public internet to connect branch office networks to the main office network. This method is both cost-effective and secure compared to dedicated leased lines, and far more secure than using public Wi-Fi. A wireless mesh network is more suited for local wireless coverage rather than connecting geographically separated sites.",
      "examTip": "Site-to-site VPNs are a cost-effective and secure way to connect geographically dispersed offices over the public internet."
    },
    {
      "id": 58,
      "question": "A network administrator configures a Cisco router with the command `ip access-group 101 in` on the GigabitEthernet0/0 interface. What is the purpose and effect of this command?",
      "options": [
        "It enables encryption on the GigabitEthernet0/0 interface.",
        "It applies access control list (ACL) 101 to outgoing traffic on the GigabitEthernet0/0 interface.",
        "It applies access control list (ACL) 101 to incoming traffic on the GigabitEthernet0/0 interface.",
        "It displays the configuration of access control list 101."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The command `ip access-group 101 in` applies ACL 101 to traffic entering the GigabitEthernet0/0 interface. This means that incoming traffic is filtered based on the rules defined in ACL 101.",
      "examTip": "Use `ip access-group [acl-number] in` to apply an ACL to incoming traffic on an interface."
    },
    {
      "id": 59,
      "question": "What is 'BGP hijacking', and why is it a significant security risk?",
      "options": [
        "A method for encrypting network traffic.",
        "A technique used to dynamically assign IP addresses.",
        "An attack where a malicious actor compromises a router (or exploits a misconfiguration) and falsely advertises routes for IP address prefixes that they do not legitimately control, redirecting traffic to their network. This can lead to traffic interception, denial of service, or blackholing.",
        "A way to prioritize certain types of network traffic."
      ],
      "correctAnswerIndex": 2,
      "explanation": "BGP hijacking is an attack on the Border Gateway Protocol where an attacker falsely advertises routes for IP prefixes they do not own, causing traffic to be misdirected to the attacker's network. This can result in traffic interception, denial of service, or blackholing of traffic.",
      "examTip": "BGP hijacking can disrupt internet routing and redirect traffic to malicious actors."
    },
    {
      "id": 60,
      "question": "A network administrator configures a Cisco switch with the following commands: \ninterface GigabitEthernet0/1\nswitchport mode trunk\nswitchport trunk encapsulation dot1q\nswitchport trunk allowed vlan 10,20,30\nswitchport trunk native vlan 99\nWhat is the purpose of the `switchport trunk native vlan 99` command in this configuration?",
      "options": [
        "It disables VLAN tagging for all traffic on the trunk.",
        "It specifies that untagged traffic received on the trunk port will be assigned to VLAN 99.",
        "It specifies that VLAN 99 is the only VLAN allowed on the trunk.",
        "It encrypts traffic on VLAN 99."
      ],
      "correctAnswerIndex": 1,
      "explanation": "On a Cisco switch trunk port using 802.1Q, the native VLAN is the VLAN for untagged traffic. The command `switchport trunk native vlan 99` changes the native VLAN from the default (usually VLAN 1) to VLAN 99. This means that any untagged traffic on that trunk will be assigned to VLAN 99.",
      "examTip": "The native VLAN on a trunk port handles untagged traffic; it is a best practice to change it from the default VLAN 1."
    },
    {
      "id": 61,
      "question": "A network is experiencing intermittent connectivity problems. A network administrator uses a protocol analyzer to capture network traffic and observes a large number of TCP RST (reset) packets. What does this typically indicate?",
      "options": [
        "The network is functioning normally.",
        "The DNS server is not resolving domain names correctly.",
        "One or both ends of a TCP connection are abruptly terminating the connection, possibly due to an application crash, a firewall rule, or a network device forcibly closing the connection.",
        "The DHCP server is not assigning IP addresses correctly."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A TCP RST packet is sent to immediately terminate a TCP connection. A large number of RST packets typically indicates that connections are being abruptly closed, which can occur if an application crashes, if a firewall is blocking traffic by sending resets, or if a network device is forcefully terminating sessions.",
      "examTip": "Frequent TCP RST packets often indicate abrupt connection terminations due to application, firewall, or network device issues."
    },
    {
      "id": 62,
      "question": "A network administrator is configuring OSPF on a Cisco router. They want to ensure that OSPF routing updates are authenticated to prevent unauthorized routers from injecting false routing information. Which of the following commands, entered in OSPF router configuration mode, would enable MD5 authentication for OSPF?",
      "options": [
        "router ospf 1 \n passive-interface GigabitEthernet0/1",
        "router ospf 1 \n area 0 authentication message-digest",
        "router ospf 1 \n network 192.168.1.0 0.0.0.255 area 0",
        "router ospf 1 \n redistribute static"
      ],
      "correctAnswerIndex": 1,
      "explanation": "To enable MD5 authentication in OSPF, you first enable authentication for the OSPF area using the command `area [area-id] authentication message-digest` within OSPF router configuration mode. Then, you configure a message-digest key on each interface using the `ip ospf message-digest-key` command in interface configuration mode. Option B is the required step to enable authentication at the area level.",
      "examTip": "OSPF MD5 authentication requires enabling message-digest authentication for the area and configuring a shared key on each interface."
    },
    {
      "id": 63,
      "question": "You are troubleshooting a slow network connection between two computers on the same subnet. You suspect a problem with the physical layer. Which of the following tools is BEST suited to test the network cable for continuity, shorts, miswires, and cable length?",
      "options": [
        "A protocol analyzer (like Wireshark)",
        "A cable tester",
        "A toner and probe",
        "A spectrum analyzer"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A cable tester is specifically designed to verify the physical integrity of network cables. It tests for continuity, shorts, miswires, and can also measure cable length. A protocol analyzer captures network traffic, a toner and probe is used to locate cables, and a spectrum analyzer is used for analyzing radio frequencies in wireless communications.",
      "examTip": "Use a cable tester to diagnose physical layer issues with network cabling."
    },
    {
      "id": 64,
      "question": "What is 'ARP spoofing' (also known as 'ARP poisoning'), and what is a specific, effective technique to mitigate this type of attack on a switched network?",
      "options": [
        "ARP spoofing is a method for dynamically assigning IP addresses; it can be mitigated by using static IP addresses.",
        "ARP spoofing is a technique for encrypting network traffic; it can be mitigated by using stronger encryption algorithms.",
        "ARP spoofing is an attack where a malicious actor sends forged ARP messages to associate their MAC address with the IP address of another device (often the default gateway), allowing them to intercept or manipulate traffic; Dynamic ARP Inspection (DAI) on switches is a specific and effective mitigation technique.",
        "ARP spoofing is a way to prioritize network traffic; it can be mitigated by disabling QoS."
      ],
      "correctAnswerIndex": 2,
      "explanation": "ARP spoofing is a man-in-the-middle attack that sends fake ARP messages to associate an attacker's MAC address with the IP address of a legitimate device, often the default gateway. This allows the attacker to intercept or manipulate traffic. Dynamic ARP Inspection (DAI) is a security feature on switches that validates ARP packets and discards those with invalid bindings, thereby mitigating ARP spoofing.",
      "examTip": "Dynamic ARP Inspection (DAI) is an effective mitigation technique against ARP spoofing attacks."
    },
    {
      "id": 65,
      "question": "A network uses multiple VLANs. Inter-VLAN routing is configured on a Layer 3 switch. A network administrator wants to control the flow of traffic between specific VLANs. Which of the following technologies, configured on the Layer 3 switch, would be MOST appropriate for this purpose?",
      "options": [
        "Spanning Tree Protocol (STP)",
        "Port security",
        "Access control lists (ACLs)",
        "DHCP snooping"
      ],
      "correctAnswerIndex": 2,
      "explanation": "While VLANs segment the network, controlling traffic between them requires the use of Access Control Lists (ACLs) applied on the Layer 3 switch or router. ACLs can filter traffic based on various criteria, thereby enforcing inter-VLAN communication policies.",
      "examTip": "Use ACLs on a Layer 3 switch to control traffic flow between VLANs."
    },
    {
      "id": 66,
      "question": "A network administrator suspects that a user's computer is infected with malware and is participating in a botnet. Which of the following network monitoring techniques would be MOST effective in detecting this type of activity?",
      "options": [
        "Monitoring DNS requests for unusual patterns, such as queries to known malicious domains or a high volume of requests to unfamiliar domains.",
        "Checking the user's web browser history.",
        "Monitoring the user's email for suspicious attachments.",
        "Scanning the user's computer for viruses."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Monitoring DNS requests is particularly effective for detecting botnet activity. Botnets often use DNS to contact command-and-control servers or resolve malicious domains. Unusual DNS query patterns—such as a high volume of queries or queries to known malicious domains—can indicate that a computer is part of a botnet.",
      "examTip": "Monitor DNS requests for unusual patterns to detect potential botnet activity and malware infections."
    },
    {
      "id": 67,
      "question": "A network administrator is troubleshooting an OSPF routing issue. They want to verify that OSPF is enabled on a specific interface, check the OSPF area the interface belongs to, and examine the OSPF hello and dead intervals. Which command on a Cisco router would provide this information?",
      "options": [
        "show ip route ospf",
        "show ip ospf neighbor",
        "show ip ospf interface [interface-name]",
        "show ip protocols"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The `show ip ospf interface [interface-name]` command provides detailed, *interface-specific* OSPF information, including: *OSPF Process ID*, *Area ID*, *Interface Type (e.g., broadcast, point-to-point)*, *Cost*, *Hello and Dead Intervals*, *Neighbor Count*, and *State (e.g., DR, BDR, DROTHER)*. This is the *most direct* way to verify OSPF configuration on a *specific* interface. `show ip route ospf` shows OSPF *routes*. `show ip ospf neighbor` shows *neighbor relationships*. `show ip protocols` gives a *general* overview of routing protocols, but not detailed OSPF interface information.",
      "examTip": "Use `show ip ospf interface [interface_name]` to verify detailed OSPF configuration on a per-interface basis."
    },
    {
      "id": 68,
      "question": "What is '802.1Q', and why is it essential for implementing VLANs in a switched network?",
      "options": [
        "A wireless security protocol used to encrypt network traffic.",
        "The IEEE standard for VLAN tagging; it adds a tag to Ethernet frames to identify the VLAN to which they belong, allowing multiple VLANs to be carried over a single physical link (a trunk).",
        "A routing protocol used to exchange routing information between networks.",
        "A protocol used for dynamically assigning IP addresses to devices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "802.1Q is the industry standard for *VLAN tagging*. VLANs logically segment a switched network into separate broadcast domains. To carry traffic for multiple VLANs across a single physical link (a *trunk link*), 802.1Q adds a *tag* to each Ethernet frame. This tag identifies the VLAN to which the frame belongs, allowing switches to forward the frame only to ports that are members of that VLAN. It's *not* a wireless security protocol, a routing protocol, or DHCP.",
      "examTip": "802.1Q is the foundation for implementing VLANs in switched networks; it enables VLAN tagging on trunk links."
    },
    {
      "id": 69,
      "question": "A network administrator wants to limit the number of MAC addresses that can be learned on a specific switch port to enhance security. They also want the switch to dynamically learn the MAC addresses of connected devices, up to the configured limit, and to *store these learned MAC addresses in the running configuration*, so they persist across reboots. Which Cisco IOS commands, and in what order, achieve this?",
      "options": [
        "interface [interface-name]\nswitchport mode access\nswitchport port-security",
        "interface [interface-name]\nswitchport mode access\nswitchport port-security\nswitchport port-security maximum [number]\nswitchport port-security mac-address sticky",
        "interface [interface-name]\nswitchport mode trunk\nswitchport port-security",
        "interface [interface-name]\nswitchport port-security maximum [number]\nswitchport port-security mac-address [mac-address]"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The correct sequence is:\n1. `interface [interface-name]` – enter interface configuration mode.\n2. `switchport mode access` – configure the port as an access port (carrying traffic for a single VLAN).\n3. `switchport port-security` – enable port security on the interface.\n4. `switchport port-security maximum [number]` – set the maximum number of allowed MAC addresses.\n5. `switchport port-security mac-address sticky` – enable sticky learning so that the switch dynamically learns the MAC addresses and adds them to the running configuration. This ensures the learned addresses persist across reboots. Option A is missing the maximum and sticky commands; Option C incorrectly sets the port as a trunk; Option D sets a static MAC address rather than dynamically learning it.",
      "examTip": "Use `switchport port-security maximum` and `switchport port-security mac-address sticky` to dynamically learn and secure a single MAC address on a switch port and shut down the port on violation if necessary."
    },
    {
      "id": 70,
      "question": "You are troubleshooting a network connectivity issue where a user cannot access a specific web server. You have verified that the user's computer has a valid IP address, subnet mask, and default gateway. You can ping the web server's IP address successfully from the user's computer. You can also successfully resolve the web server's domain name using `nslookup`. However, when you try to access the web server using a web browser, you receive a 'Connection refused' error. What is the MOST likely cause?",
      "options": [
        "A problem with the user's network cable.",
        "A problem with the DNS server.",
        "The web server is not running, the web server application (e.g., Apache, IIS) is not running or is misconfigured, or a firewall is blocking traffic to the web server's port (typically TCP port 80 for HTTP or 443 for HTTPS).",
        "The user's computer does not have a default gateway configured."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Successful ping and `nslookup` rule out basic network connectivity and DNS issues. A 'Connection refused' error means the TCP connection request was actively rejected by the server. This typically indicates that the web server or its application is not running or is misconfigured, or that a firewall is blocking access to the server's port.",
      "examTip": "A 'Connection refused' error usually indicates that the target service is not running or is rejecting connections, or that a firewall is blocking the connection."
    },
    {
      "id": 71,
      "question": "A network administrator wants to configure a Cisco router to redistribute routes learned from OSPF into EIGRP. They also want to set a specific metric for the redistributed routes. Assuming OSPF is using process ID 1 and EIGRP is using autonomous system number 100, which of the following commands, entered in router configuration mode for EIGRP, would correctly achieve this?",
      "options": [
        "router eigrp 100 \n network 192.168.1.0 0.0.0.255",
        "router eigrp 100 \n redistribute static",
        "router eigrp 100 \n redistribute ospf 1 metric 10000 100 255 1 1500",
        "router eigrp 100 \n passive-interface GigabitEthernet0/0"
      ],
      "correctAnswerIndex": 2,
      "explanation": "To redistribute routes from OSPF into EIGRP, use the `redistribute` command within the EIGRP configuration. The correct syntax is: `redistribute ospf 1 metric 10000 100 255 1 1500` which redistributes OSPF routes (assuming OSPF process ID 1) into EIGRP with the required metric values. Options A and B do not redistribute OSPF routes, and Option D only affects interface behavior.",
      "examTip": "When redistributing OSPF routes into EIGRP, use the `redistribute` command with appropriate metric values in EIGRP configuration."
    },
    {
      "id": 72,
      "question": "A network administrator is troubleshooting a slow network. Using a protocol analyzer, they capture network traffic and observe a significant number of TCP ZeroWindow messages. What does this indicate, and what is a likely cause?",
      "options": [
        "The network is experiencing a high number of collisions.",
        "The DNS server is not responding.",
        "The receiving host is unable to process incoming data fast enough (due to CPU overload, memory exhaustion, slow disk I/O, or other resource constraints), causing its receive buffer to fill up. It is advertising a zero window size to tell the sender to stop transmitting temporarily.",
        "The network is experiencing high jitter."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A TCP ZeroWindow message indicates that the receiver's buffer is full and it cannot accept more data at that moment. This typically points to a bottleneck on the receiving host, which might be due to CPU overload, memory exhaustion, slow disk I/O, or other resource constraints.",
      "examTip": "TCP ZeroWindow messages indicate that the receiver's buffer is full; investigate resource bottlenecks on the receiving host."
    },
    {
      "id": 73,
      "question": "What is 'DHCP starvation', and what are two specific security measures that can be implemented on a network switch to mitigate this type of attack?",
      "options": [
        "DHCP starvation is a method for encrypting DHCP requests and responses; it can be mitigated by using stronger encryption algorithms.",
        "DHCP starvation is a technique for speeding up the DHCP address assignment process; it can be mitigated by increasing the DHCP lease time.",
        "DHCP starvation is a denial-of-service attack where an attacker floods the network with DHCP requests using spoofed MAC addresses, attempting to exhaust the DHCP server's pool of available IP addresses; DHCP snooping and port security can mitigate this.",
        "DHCP starvation is a protocol used for translating domain names to IP addresses; it can be mitigated by using more reliable DNS servers."
      ],
      "correctAnswerIndex": 2,
      "explanation": "DHCP starvation is a type of DoS attack where an attacker floods the network with DHCP requests (often with spoofed MAC addresses) to exhaust the DHCP server's available IP addresses. Two effective mitigations are: DHCP snooping, which ensures only trusted DHCP server responses are allowed, and port security, which limits the number of MAC addresses on a port.",
      "examTip": "Mitigate DHCP starvation with DHCP snooping and port security on network switches."
    },
    {
      "id": 74,
      "question": "A network is experiencing a connectivity issue where a user cannot access a specific internal server by its hostname (e.g., `server.example.com`). The user can ping the server's IP address, but `nslookup server.example.com` fails with a 'Non-existent domain' error, even when using a public DNS server. What is the MOST likely cause of the problem?",
      "options": [
        "The user's network cable is unplugged.",
        "The internal DNS server is not configured to forward requests to external DNS servers.",
        "The authoritative DNS servers for the `example.com` domain do not have a valid A record for `server.example.com`, or there is a problem with DNS propagation.",
        "The internal server is down."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Since the user can ping the server's IP address, network connectivity is working. The failure of `nslookup` with both internal and public DNS servers indicates that the problem lies with the authoritative DNS records for the domain, such as a missing or incorrect A record for `server.example.com`.",
      "examTip": "If `nslookup` fails with both internal and external DNS servers, the issue is likely with the authoritative DNS records."
    },
    {
      "id": 75,
      "question": "A network administrator is designing a wireless network for a large office building. They need to provide both 2.4 GHz and 5 GHz coverage. To minimize interference between access points, what is the BEST practice for channel assignment in both bands?",
      "options": [
        "Use the same channel for all access points in both bands.",
        "For 2.4 GHz, use non-overlapping channels (1, 6, 11); for 5 GHz, use any available channels, as there are many more non-overlapping channels available.",
        "Use automatic channel selection on all access points.",
        "Use only the 2.4 GHz band, as it provides better coverage."
      ],
      "correctAnswerIndex": 1,
      "explanation": "To minimize interference, it is best to use non-overlapping channels. In the 2.4 GHz band, only channels 1, 6, and 11 are non-overlapping in most regions. The 5 GHz band offers many more non-overlapping channels. While automatic channel selection can be useful, a well-planned manual assignment is often more effective in dense environments.",
      "examTip": "Use non-overlapping channels: channels 1, 6, and 11 for 2.4 GHz; choose from many non-overlapping channels for 5 GHz."
    },
    {
      "id": 76,
      "question": "What is 'BGP hijacking', and what are some potential consequences?",
      "options": [
        "A method for encrypting network traffic.",
        "A technique used to dynamically assign IP addresses.",
        "An attack where a malicious actor compromises a router (or exploits a misconfiguration) and falsely advertises routes for IP address prefixes that they don't legitimately control. This can redirect traffic to the attacker's network, leading to traffic interception, denial of service, or blackholing.",
        "A way to prioritize network traffic."
      ],
      "correctAnswerIndex": 2,
      "explanation": "BGP hijacking is an attack on Border Gateway Protocol where an attacker falsely advertises routes for IP prefixes they do not own. This misdirection can cause traffic to be sent to the attacker, enabling interception, denial of service, or blackholing.",
      "examTip": "BGP hijacking can lead to traffic interception and service disruption; it is a major threat to internet routing."
    },
    {
      "id": 77,
      "question": "Which of the following is a potential security risk associated with using SNMPv1 or SNMPv2c for network device management, and what is the recommended alternative?",
      "options": [
        "They provide strong encryption; the risk is that they are too complex to configure.",
        "They use community strings for authentication, which are transmitted in plain text and are easily intercepted; SNMPv3, with its support for authentication and encryption, is the recommended alternative.",
        "They are only compatible with older network devices; the recommended alternative is to upgrade to newer devices.",
        "They cause network loops; the recommended alternative is to enable Spanning Tree Protocol."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SNMPv1 and SNMPv2c rely on community strings transmitted in plain text, making them vulnerable to interception. SNMPv3 offers authentication and encryption, significantly enhancing security.",
      "examTip": "Avoid SNMPv1 and SNMPv2c; use SNMPv3 for secure network device management."
    },
    {
      "id": 78,
      "question": "A network administrator is troubleshooting a slow file transfer between two computers on the same local network. Pings between the computers are successful with low latency. What is the next MOST logical step to investigate?",
      "options": [
        "Check the DNS server configuration.",
        "Check for a duplex mismatch between the network interface cards (NICs) of the two computers and the switch ports they are connected to. Also, inspect the interface error counters on both the NICs and the switch ports for signs of physical layer problems.",
        "Verify that Spanning Tree Protocol is enabled.",
        "Check the DHCP server's IP address lease time."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Since both computers are on the same local network and pings are successful, the issue is likely at the physical layer. A duplex mismatch between the NICs and switch ports can cause collisions and significantly reduce throughput. Checking interface error counters for CRC errors, runts, or giants can help identify physical layer issues.",
      "examTip": "For slow transfers on a local network, verify duplex settings and check for physical layer errors."
    },
    {
      "id": 79,
      "question": "A network administrator is configuring a new switch and wants to implement VLANs. Which of the following commands on a Cisco switch would display a summary of the configured VLANs, their status, and the ports assigned to each VLAN?",
      "options": [
        "show interfaces trunk",
        "show spanning-tree",
        "show vlan brief",
        "show ip interface brief"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The `show vlan brief` command displays a concise summary of VLANs, including VLAN IDs, names, statuses, and the ports assigned to each VLAN. It is the most direct command for verifying VLAN configuration.",
      "examTip": "Use `show vlan brief` to quickly view VLAN configuration and port assignments on a Cisco switch."
    },
    {
      "id": 80,
      "question": "You are designing a network that will carry both regular data traffic and Voice over IP (VoIP) traffic. What are the two MOST critical network performance characteristics that must be considered to ensure good VoIP call quality, and what QoS mechanism is typically used to address them?",
      "options": [
        "High bandwidth and low packet loss; traffic shaping is used.",
        "Low latency and low jitter; traffic classification (e.g., DSCP markings) and priority queuing are used.",
        "High throughput and low collision rate; link aggregation is used.",
        "Low error rate and high security; encryption is used."
      ],
      "correctAnswerIndex": 1,
      "explanation": "VoIP requires low latency (minimal delay) and low jitter (consistent packet arrival times) for clear, uninterrupted call quality. QoS mechanisms, such as marking VoIP traffic with DSCP and using priority queuing on network devices, help ensure these conditions are met.",
      "examTip": "For VoIP, ensure low latency and low jitter by using QoS mechanisms like DSCP marking and priority queuing."
    },
    {
      "id": 81,
      "question": "A network administrator suspects that an attacker is attempting a brute-force attack against a server's SSH service. Which of the following log entries or network monitoring data would MOST strongly support this suspicion?",
      "options": [
        "A large number of DNS requests for the server's hostname.",
        "Repeated failed SSH login attempts from multiple source IP addresses within a short period, potentially showing a pattern of username/password combinations.",
        "A high volume of ICMP Echo Request (ping) packets directed at the server.",
        "A large number of ARP requests on the local network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Repeated failed SSH login attempts, especially from multiple source IP addresses, strongly indicate a brute-force attack targeting the SSH service.",
      "examTip": "Monitor for repeated failed SSH login attempts from various sources to detect brute-force attacks."
    },
    {
      "id": 82,
      "question": "What is '802.1X', and which three main components are typically involved in an 802.1X authentication process?",
      "options": [
        "A wireless security protocol similar to WEP.",
        "A port-based network access control (PNAC) standard that requires authentication before granting network access; it typically involves a supplicant (client), an authenticator (switch or AP), and an authentication server (usually RADIUS).",
        "A routing protocol used for large networks.",
        "A protocol for dynamically assigning IP addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "802.1X is a standard for port-based Network Access Control (PNAC). It defines a framework where a supplicant (client device) requests access, an authenticator (switch or AP) controls the access, and an authentication server (typically RADIUS) validates the credentials before allowing network access.",
      "examTip": "802.1X involves a supplicant, an authenticator, and an authentication server (RADIUS) for secure network access."
    },
    {
      "id": 83,
      "question": "A network administrator is troubleshooting a slow network. They use a protocol analyzer to capture network traffic and observe a large number of TCP retransmissions, duplicate ACKs, and out-of-order packets. They also notice many TCP packets with the 'PSH' (Push) flag set. What is the MOST likely interpretation of these combined findings?",
      "options": [
        "The network is functioning normally, and the PSH flag simply indicates that data should be delivered to the application immediately.",
        "The network is experiencing significant packet loss due to congestion, faulty hardware, or MTU issues, and the frequent use of the PSH flag might be an attempt by the application to overcome the delays, potentially exacerbating the problem.",
        "The DNS server is not resolving domain names correctly.",
        "The DHCP server is not assigning IP addresses correctly."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Frequent TCP retransmissions, duplicate ACKs, and out-of-order packets indicate packet loss and network congestion. The PSH flag tells the receiver to deliver data immediately, and excessive use may reflect an application trying to overcome delays, which can worsen congestion.",
      "examTip": "High TCP retransmissions, duplicate ACKs, out-of-order packets, and excessive PSH usage typically indicate packet loss and network congestion."
    },
    {
      "id": 84,
      "question": "A network administrator is configuring a Cisco router to act as a DHCP server. They want to exclude a range of IP addresses from being assigned by DHCP. The network is 192.168.1.0/24, and the addresses to be excluded are 192.168.1.1 through 192.168.1.10, and also the single address 192.168.1.254. Which of the following command sequences, entered in global configuration mode, would correctly achieve this?",
      "options": [
        "ip dhcp excluded-address 192.168.1.1 192.168.1.10",
        "ip dhcp excluded-address 192.168.1.1 192.168.1.10 192.168.1.254",
        "ip dhcp excluded-address 192.168.1.1-192.168.1.10 192.168.1.254",
        "ip dhcp excluded-address 192.168.1.1 192.168.1.10 \n ip dhcp excluded-address 192.168.1.254"
      ],
      "correctAnswerIndex": 3,
      "explanation": "To exclude non-contiguous IP addresses from DHCP assignment, you must use separate `ip dhcp excluded-address` commands. Option D correctly excludes the range 192.168.1.1–192.168.1.10 and then excludes the single address 192.168.1.254 using a separate command.",
      "examTip": "Use separate `ip dhcp excluded-address` commands to exclude non-contiguous IP addresses from DHCP assignment."
    },
    {
      "id": 85,
      "question": "A network administrator wants to implement a security mechanism on a Cisco switch that will dynamically learn the MAC address of the first device connected to a port and then *only* allow traffic from that MAC address. If a device with a different MAC address connects, the port should be shut down. Which of the following command sequences, starting from interface configuration mode, would achieve this?",
      "options": [
        "switchport mode trunk \n switchport port-security",
        "switchport mode access \n switchport port-security \n switchport port-security maximum 1 \n switchport port-security mac-address sticky \n switchport port-security violation shutdown",
        "switchport mode access \n switchport port-security \n switchport port-security maximum 1 \n switchport port-security mac-address 00:11:22:33:44:55",
        "switchport mode access \n switchport port-security violation restrict"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The correct sequence is:\n1. `switchport mode access` – set the port as an access port.\n2. `switchport port-security` – enable port security.\n3. `switchport port-security maximum 1` – allow only one MAC address.\n4. `switchport port-security mac-address sticky` – enable dynamic (sticky) learning of the MAC address and store it in the running configuration.\n5. `switchport port-security violation shutdown` – configure the port to shut down if a violation occurs.",
      "examTip": "Use sticky port security with a maximum of 1 MAC address and set violation to shutdown to secure a switch port."
    },
    {
      "id": 86,
      "question": "A network administrator suspects that a company is experiencing intermittent network outages. The network uses multiple switches with redundant links between them. The administrator suspects a Spanning Tree Protocol (STP) issue. Which of the following findings, obtained from show commands on the switches, would STRONGLY suggest an STP problem?",
      "options": [
        "High CPU utilization on the switches.",
        "Frequent changes in the root bridge election and ports transitioning between forwarding and blocking states, especially if these changes occur without any deliberate network changes.",
        "A large number of MAC addresses learned on a single switch port.",
        "High latency when pinging devices on different VLANs."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Frequent changes in the root bridge election and ports transitioning between forwarding and blocking states without corresponding physical link changes are strong indicators of STP instability, which can cause intermittent outages.",
      "examTip": "STP instability is often evidenced by frequent root bridge changes and port state transitions."
    },
    {
      "id": 87,
      "question": "A network administrator is configuring a Cisco router in a multi-area OSPF network. They want to summarize multiple contiguous networks into a single route advertisement to reduce routing table size and simplify routing. Which command, and in what context, would you use to achieve this?",
      "options": [
        "On the Area Border Router (ABR), in router configuration mode for OSPF, use the `area [area-id] range [network-address] [subnet-mask]` command.",
        "On any router within the OSPF area, in router configuration mode for OSPF, use the `summary-address` command.",
        "On the Area Border Router (ABR), in interface configuration mode, use the `ip summary-address ospf` command.",
        "On any router within the OSPF area, in interface configuration mode, use the `ip ospf summary` command."
      ],
      "correctAnswerIndex": 0,
      "explanation": "OSPF route summarization is performed on an Area Border Router (ABR) using the command `area [area-id] range [network-address] [subnet-mask]` within OSPF router configuration mode. This aggregates multiple specific routes into one summary route for the specified area.",
      "examTip": "Use `area [area-id] range [network-address] [subnet-mask]` on an ABR to summarize routes in OSPF."
    },
    {
      "id": 88,
      "question": "A network administrator is troubleshooting a connectivity issue between two devices on different subnets. Routing is configured, and the administrator suspects a problem with an access control list (ACL). Which command on a Cisco router would allow the administrator to see which ACLs are applied to a specific interface (e.g., GigabitEthernet0/0) and in which direction (inbound or outbound)?",
      "options": [
        "show ip access-lists",
        "show ip interface GigabitEthernet0/0",
        "show running-config interface GigabitEthernet0/0",
        "show access-lists"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `show ip interface GigabitEthernet0/0` command displays detailed information about the interface, including any ACLs applied in the inbound and outbound directions. While `show running-config` would also show ACLs, `show ip interface` provides a concise summary focused on ACL application.",
      "examTip": "Use `show ip interface [interface-name]` to quickly see ACLs applied to that interface."
    },
    {
      "id": 89,
      "question": "What is '802.1X', and which three main components are involved in an 802.1X authentication process?",
      "options": [
        "A wireless security protocol similar to WEP.",
        "A port-based network access control (PNAC) standard that requires authentication before granting network access; the main components are the supplicant (client), the authenticator (switch or AP), and the authentication server (typically a RADIUS server).",
        "A routing protocol.",
        "A dynamic IP address assignment protocol."
      ],
      "correctAnswerIndex": 1,
      "explanation": "802.1X is a standard for port-based Network Access Control (PNAC) that requires devices to authenticate before being granted network access. The three components involved are the supplicant (client device), the authenticator (network device such as a switch or AP), and the authentication server (typically a RADIUS server).",
      "examTip": "802.1X involves a supplicant, an authenticator, and a RADIUS server for secure network access."
    },
    {
      "id": 90,
      "question": "What is 'DHCP snooping', and which two types of attacks does it primarily help prevent?",
      "options": [
        "A method for encrypting DHCP traffic.",
        "A security feature on switches that inspects DHCP messages and only allows DHCP traffic from trusted sources (typically, designated DHCP server ports), preventing rogue DHCP servers and DHCP starvation attacks.",
        "A technique for speeding up the DHCP address assignment process.",
        "A protocol for monitoring user web browsing activity."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DHCP snooping is a switch security feature that prevents rogue DHCP servers and DHCP starvation attacks by allowing DHCP traffic only from trusted ports and dropping DHCP server responses from untrusted ports.",
      "examTip": "DHCP snooping helps prevent rogue DHCP servers and DHCP starvation attacks."
    },
    {
      "id": 91,
      "question": "A network administrator is troubleshooting a network performance issue. Users report slow access to a web application. A protocol analyzer shows a large number of TCP retransmissions, duplicate ACKs, and out-of-order packets specifically for traffic to and from the web application's server. What is the MOST likely cause?",
      "options": [
        "A problem with the DNS server.",
        "A problem with the user's web browser.",
        "Packet loss due to network congestion, faulty hardware (NIC, cable, switch port, router interface), or an issue with the web application server itself (overloaded, misconfigured, or faulty network interface).",
        "A problem with the DHCP server."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The observed TCP issues—retransmissions, duplicate ACKs, and out-of-order packets—indicate packet loss. When these symptoms are specific to traffic involving the web application's server, it suggests that congestion, hardware issues, or server problems are likely causing the packet loss.",
      "examTip": "TCP retransmissions and duplicate ACKs are strong indicators of packet loss; investigate congestion, hardware issues, and server problems."
    },
    {
      "id": 92,
      "question": "A network administrator configures a Cisco router with the command `router ospf 1`. What is the effect of this command?",
      "options": [
        "It disables all routing protocols on the router.",
        "It enables the OSPF routing protocol with process ID 1.",
        "It configures a static route for the OSPF network.",
        "It enables RIP routing on the router."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The command `router ospf 1` enables OSPF on the router using process ID 1. It does not disable routing protocols, configure static routes, or enable RIP.",
      "examTip": "`router ospf [process-id]` starts the OSPF process on a Cisco router."
    },
    {
      "id": 93,
      "question": "What is 'split horizon', and how does it help prevent routing loops in distance-vector routing protocols?",
      "options": [
        "A method for encrypting routing updates.",
        "A technique that prevents a router from advertising a route back out the *same interface* on which it learned that route. This prevents routing information from bouncing between routers and forming loops.",
        "A way to prioritize certain routes over others.",
        "A technique for load balancing traffic across multiple links."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Split horizon is a loop-prevention mechanism used in distance-vector routing protocols. It prevents a router from advertising a route back out the same interface on which it was learned, thereby preventing routing loops.",
      "examTip": "Split horizon is fundamental for preventing routing loops in distance-vector protocols."
    },
    {
      "id": 94,
      "question": "What is a 'man-in-the-middle' (MitM) attack, and what are some effective ways to mitigate this type of attack?",
      "options": [
        "An attempt to overwhelm a network server with excessive traffic.",
        "An attempt to trick users into revealing personal information.",
        "An attack where the attacker secretly intercepts and potentially alters communication between two parties who believe they are communicating directly; using strong encryption (like HTTPS for web traffic), VPNs, and verifying digital certificates can help mitigate MitM attacks.",
        "An attempt to guess passwords by trying many different combinations."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A man-in-the-middle attack involves an attacker intercepting and possibly altering communications between two parties without their knowledge. Mitigations include using strong encryption (e.g., HTTPS), VPNs, and verifying digital certificates to ensure authenticity.",
      "examTip": "Mitigate MitM attacks by using strong encryption (HTTPS, VPNs) and verifying certificates."
    },
    {
      "id": 95,
      "question": "A network administrator wants to prevent rogue DHCP servers from operating on a network segment. They configure the relevant switch ports as 'untrusted' in the context of DHCP snooping. What is the effect of this configuration?",
      "options": [
        "The switch will allow all DHCP traffic on those ports.",
        "The switch will block all DHCP traffic on those ports.",
        "The switch will only forward DHCP client requests from those ports, and it will drop any DHCP server responses received on those ports.",
        "The switch will encrypt all DHCP traffic on those ports."
      ],
      "correctAnswerIndex": 2,
      "explanation": "With DHCP snooping enabled, untrusted ports only allow DHCP client requests and drop DHCP server responses. This prevents rogue DHCP servers from assigning IP addresses on the network.",
      "examTip": "DHCP snooping distinguishes between trusted and untrusted ports to block rogue DHCP server responses."
    },
    {
      "id": 96,
      "question": "What is the purpose of the `traceroute` (or `tracert`) command, and how does it work?",
      "options": [
        "To test the speed of a network connection.",
        "To display the IP address of a website.",
        "To trace the route that packets take to reach a destination host, showing each hop (router) along the way and the time it takes to reach each hop. It works by sending packets with increasing Time-to-Live (TTL) values.",
        "To configure a network interface."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Traceroute (or tracert) works by sending packets with incrementally increasing TTL values. Each router along the path decrements the TTL, and when it reaches zero, the router discards the packet and sends an ICMP Time Exceeded message back to the sender. This process reveals the route and round-trip time for each hop.",
      "examTip": "Traceroute uses increasing TTL values and ICMP Time Exceeded messages to map the route to a destination."
    },
    {
      "id": 97,
      "question": "A network administrator is configuring a Cisco router and wants to restrict access to the router's command-line interface (CLI) via SSH. They want to allow SSH access *only* from devices within the 192.168.1.0/24 network. Which of the following command sequences, starting from global configuration mode, is the MOST secure and correct way to achieve this?",
      "options": [
        "line vty 0 4 \n transport input all",
        "line vty 0 4 \n transport input ssh \n access-list 10 permit any \n access-class 10 in",
        "line vty 0 4 \n transport input ssh \n access-list 10 permit tcp 192.168.1.0 0.0.0.255 host [Router's Management IP] eq 22 \n access-class 10 in",
        "line con 0 \n transport input ssh \n access-list 10 permit 192.168.1.0 0.0.0.255 \n access-class 10 in"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The correct sequence is:\n1. Enter VTY configuration with `line vty 0 4`.\n2. Restrict transport to SSH using `transport input ssh`.\n3. Create an ACL (10) that permits TCP traffic from 192.168.1.0/24 to the router's management IP on port 22. (Replace [Router's Management IP] with the actual IP.)\n4. Apply the ACL with `access-class 10 in` to restrict incoming SSH connections.\nThis ensures only authorized devices can access the router via SSH.",
      "examTip": "Restrict SSH access by using `transport input ssh` and applying an ACL that permits only authorized source IPs."
    },
    {
      "id": 98,
      "question": "A network administrator is configuring a new VLAN on a Cisco switch. They create the VLAN using the `vlan [vlan-id]` command in global configuration mode. Then, they assign several switch ports to the VLAN using the `switchport access vlan [vlan-id]` command. However, devices connected to those ports still cannot communicate with each other. What additional step, specifically related to the VLAN itself, might be missing?",
      "options": [
        "Enabling Spanning Tree Protocol (STP) on the switch.",
        "Configuring a default gateway on the client devices.",
        "The VLAN might not be in the 'active' state. Use the `show vlan brief` command to check the VLAN's status, and if it's not active, there may be an issue preventing it from activating.",
        "Configuring an IP address on the switch for the VLAN."
      ],
      "correctAnswerIndex": 2,
      "explanation": "After creating a VLAN, it's important to verify that it is in the 'active' state using `show vlan brief`. If the VLAN is not active, devices assigned to it will not be able to communicate. No additional command is typically required if the VLAN is active.",
      "examTip": "Check VLAN status with `show vlan brief` to ensure the VLAN is active."
    },
    {
      "id": 99,
      "question": "A network administrator is troubleshooting a slow network. They suspect that a particular application is consuming a disproportionate amount of bandwidth. Which of the following tools or techniques would be MOST effective in identifying the specific application and quantifying its bandwidth usage?",
      "options": [
        "A cable tester.",
        "A protocol analyzer (like Wireshark) with application-layer analysis capabilities, or a network monitoring tool with NetFlow/sFlow support and application-level visibility.",
        "The `ping` command.",
        "The `traceroute` command."
      ],
      "correctAnswerIndex": 1,
      "explanation": "To identify which application is consuming excessive bandwidth, you need a tool that can analyze application-layer traffic. Protocol analyzers with application decoding or network monitoring tools that support NetFlow/sFlow are best suited for this task.",
      "examTip": "Use a protocol analyzer with application-layer analysis or NetFlow/sFlow-based tools to identify bandwidth-heavy applications."
    },
    {
      "id": 100,
      "question": "A network uses the OSPF routing protocol. The network administrator wants to prevent a specific router from being elected as the Designated Router (DR) or Backup Designated Router (BDR) on a particular multi-access network segment (e.g., an Ethernet LAN). What is the MOST direct and reliable way to achieve this on a Cisco router, and which command is used?",
      "options": [
        "Configure a higher OSPF cost on the router's interface connected to the multi-access segment.",
        "Set the OSPF priority to 0 on the interface connected to the multi-access segment using the `ip ospf priority 0` command in interface configuration mode.",
        "Disable OSPF on the router entirely.",
        "Configure the router as a stub area border router (ABR)."
      ],
      "correctAnswerIndex": 1,
      "explanation": "To prevent a router from becoming DR or BDR on a multi-access network, you set its OSPF priority to 0 on the relevant interface. This is done using the `ip ospf priority 0` command in interface configuration mode. This ensures the router will never be elected as DR or BDR, regardless of its Router ID.",
      "examTip": "Set the OSPF priority to 0 on an interface to prevent the router from being elected as DR or BDR on a multi-access segment."
    }
  ]
});
