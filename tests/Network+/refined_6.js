db.tests.insertOne({
  "category": "nplus",
  "testId": 6,
  "testName": "Network+ Practice Test #6 (Formidable) - Part 1",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A network administrator is troubleshooting intermittent connectivity issues affecting multiple users on different subnets. They observe high CPU utilization on the core router.  Packet captures show a large number of small packets with varying destination IP addresses, many of which are unknown or invalid. What is the MOST likely cause?",
      "options": [
        "A misconfigured DHCP server.",
        "A widespread DNS server outage.",
        "A distributed denial-of-service (DDoS) attack targeting the network.",
        "A faulty network cable connecting a single workstation."
      ],
      "correctAnswerIndex": 2,
      "explanation": "High CPU utilization on the *core router* combined with a flood of small packets with *varying, often invalid* destination IPs strongly suggests a DDoS attack. A DHCP issue would primarily affect IP assignment, a DNS outage would prevent name resolution (but not necessarily cause high router CPU), and a single faulty cable would affect only one device. The *widespread* nature and packet characteristics point to a DDoS.",
      "examTip": "Recognize the symptoms of a DDoS attack: high resource utilization and a flood of traffic from many sources."
    },
    {
      "id": 2,
      "question": "You are configuring a new switch in a network that uses VLANs. To allow inter-VLAN routing, you configure a Switched Virtual Interface (SVI) for each VLAN. However, devices on different VLANs still cannot communicate. What is the MOST likely reason?",
      "options": [
        "Spanning Tree Protocol (STP) is not enabled.",
        "The switch ports are not assigned to the correct VLANs.",
        "The default gateway is not configured on the client devices.",
        "IP routing is not enabled on the switch, or there is a routing configuration issue."
      ],
      "correctAnswerIndex": 3,
      "explanation": "While incorrect VLAN assignments on switch ports (*B*) would prevent communication *within* a VLAN, SVIs are used for *inter*-VLAN routing. If devices *within* a VLAN can communicate, but those on *different* VLANs cannot, the issue is likely at Layer 3.  Either IP routing isn't enabled globally on the switch (using a command like `ip routing` on a Cisco device), or there's a misconfiguration in the routing protocols or static routes.  STP (*A*) prevents loops, not routing. The default gateway (*C*) on clients is important, but if the router (SVI) isn't routing, the gateway won't help.",
      "examTip": "Remember that SVIs provide Layer 3 routing functionality for VLANs; IP routing must be explicitly enabled on the switch."
    },
    {
      "id": 3,
      "question": "A company wants to implement a wireless network that provides seamless roaming between multiple access points. They also need centralized management and control of the wireless infrastructure. Which wireless architecture BEST meets these requirements?",
      "options": [
        "An ad-hoc network.",
        "A network of independent, autonomous access points.",
        "A wireless LAN controller (WLC) with lightweight access points.",
        "A mesh network with multiple independent access points."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A Wireless LAN Controller (WLC) provides centralized management, configuration, and control of multiple lightweight access points (LAPs). This architecture simplifies deployment, enables seamless roaming (as the WLC handles client handoffs between APs), and provides advanced features like centralized security policies. Autonomous APs lack centralized management. Ad-hoc networks are peer-to-peer. Mesh networks *can* offer roaming, but WLC-based solutions are generally better for enterprise-grade deployments.",
      "examTip": "Wireless LAN Controllers are essential for managing large-scale, enterprise wireless networks."
    },
    {
      "id": 4,
      "question": "You are designing a network that requires extremely high bandwidth and low latency for data center interconnectivity.  The distance between the data centers is approximately 5 kilometers.  Which cabling solution is MOST appropriate?",
      "options": [
        "Unshielded Twisted Pair (UTP) Cat 6a",
        "Shielded Twisted Pair (STP) Cat 7",
        "Multimode Fiber Optic Cable",
        "Single-mode Fiber Optic Cable"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Single-mode fiber is the best choice for long-distance, high-bandwidth, and low-latency applications.  5 kilometers far exceeds the distance limitations of UTP and STP (which are limited to 100 meters). While multimode *can* reach several hundred meters, single-mode offers significantly better performance and is the standard for data center interconnects over these distances.",
      "examTip": "Single-mode fiber is the preferred choice for long-haul, high-bandwidth data center connections."
    },
    {
      "id": 5,
      "question": "A network administrator is troubleshooting a slow network. Using a protocol analyzer, they observe a high number of TCP window size zero messages. What does this indicate?",
      "options": [
        "The network is experiencing high levels of jitter.",
        "The receiving device is unable to process incoming data fast enough, indicating a potential bottleneck on the receiving end.",
        "The DNS server is not responding.",
        "The network is experiencing a high number of collisions."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A TCP window size of zero indicates that the receiving device's buffer is full and it cannot accept any more data. This tells the sending device to stop transmitting until the receiver can process the data it already has. This is often a sign of a bottleneck on the *receiving* end, not necessarily the network itself (though network congestion *could* contribute). It's *not* directly related to jitter, DNS, or collisions (though collisions could lead to retransmissions, *indirectly* contributing).",
      "examTip": "TCP window size zero messages indicate receiver-side buffering issues."
    },
    {
      "id": 6,
      "question": "You are configuring a router to connect your local network (192.168.1.0/24) to the internet. Your ISP has provided you with the following information: Public IP: 203.0.113.5, Subnet Mask: 255.255.255.252, Gateway: 203.0.113.6. Which of the following configurations on the router's WAN interface is CORRECT?",
      "options": [
        "IP: 192.168.1.1, Subnet Mask: 255.255.255.0, Gateway: 203.0.113.6",
        "IP: 203.0.113.5, Subnet Mask: 255.255.255.0, Gateway: 203.0.113.6",
        "IP: 203.0.113.5, Subnet Mask: 255.255.255.252, Gateway: 203.0.113.6",
        "IP: 203.0.113.6, Subnet Mask: 255.255.255.252, Gateway: 203.0.113.5"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The router's WAN interface must be configured with the *public* IP address and subnet mask provided by the ISP, and the gateway should be the ISP's gateway address. Option A uses the *private* network information. Option B has the correct IP but the wrong subnet mask. Option D has the IP and gateway reversed.",
      "examTip": "Carefully configure the router's WAN interface with the information provided by your ISP."
    },
    {
      "id": 7,
      "question": "You are troubleshooting a connectivity issue where a workstation cannot access network resources.  `ipconfig /all` shows a valid IP address, subnet mask, and default gateway.  `ping` to the default gateway is successful, but `ping` to external websites by name fails. `ping` to external websites by IP address *also* fails.  What is the MOST likely cause?",
      "options": [
        "A DNS resolution problem.",
        "A problem with the workstation's web browser.",
        "A routing problem beyond the default gateway, or a firewall blocking traffic.",
        "A faulty network cable."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Successful ping to the default gateway rules out local network issues (cable, NIC, IP configuration).  Failure to ping *external IPs* rules out DNS as the *primary* cause (DNS would only affect name resolution). This strongly suggests a problem with routing *beyond* the local network (either on the router itself or further upstream), *or* a firewall blocking outbound traffic to the internet. While a browser *could* have issues, it wouldn't affect `ping`.",
      "examTip": "Systematically eliminate possibilities when troubleshooting: local connectivity, DNS, then routing/firewall."
    },
    {
      "id": 8,
      "question": "What is the function of the 'TTL' (Time to Live) field in an IP packet header?",
      "options": [
        "To specify the encryption method used for the packet.",
        "To indicate the priority of the packet.",
        "To limit the number of hops a packet can take before being discarded, preventing routing loops.",
        "To specify the source and destination port numbers."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The TTL field is a counter that is decremented by each router that forwards the packet. When the TTL reaches zero, the packet is discarded, preventing it from circulating endlessly in a routing loop.  It's *not* about encryption, priority, or port numbers.",
      "examTip": "The TTL field prevents packets from looping indefinitely in a network."
    },
    {
      "id": 9,
      "question": "A company wants to implement a network security solution that can detect and *automatically* respond to malicious network activity, blocking attacks in real-time. Which technology BEST meets this requirement?",
      "options": [
        "An intrusion detection system (IDS).",
        "An intrusion prevention system (IPS).",
        "A firewall.",
        "A virtual private network (VPN)."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An Intrusion Prevention System (IPS) actively monitors network traffic and takes action to *block* or *prevent* malicious activity.  An IDS only *detects* and alerts. A firewall controls traffic based on rules but doesn't necessarily have the *dynamic* threat detection and response capabilities of an IPS. A VPN provides secure remote access, not intrusion prevention.",
      "examTip": "An IPS provides active, real-time threat protection, while an IDS is primarily for detection and alerting."
    },
    {
      "id": 10,
      "question": "You are configuring a wireless network and need to choose a channel for the 2.4 GHz band. To minimize interference from neighboring wireless networks, which channels are generally recommended?",
      "options": [
        "1, 6, and 11",
        "1, 2, and 3",
        "6, 7, and 8",
        "Any available channel"
      ],
      "correctAnswerIndex": 0,
      "explanation": "In the 2.4 GHz band, channels 1, 6, and 11 are the only *non-overlapping* channels. Using these channels minimizes interference between adjacent access points.  Other channel combinations will overlap, leading to reduced performance. While 'any available channel' *might* work, it's not the *best* practice for minimizing interference.",
      "examTip": "Use non-overlapping channels (1, 6, 11) in the 2.4 GHz band to minimize wireless interference."
    },
    {
      "id": 11,
      "question": "Which of the following statements BEST describes the purpose of Network Address Translation (NAT)?",
      "options": [
        "To encrypt network traffic between two points.",
        "To dynamically assign IP addresses to devices on a network.",
        "To translate private IP addresses used within a local network to one or more public IP addresses used on the internet, and vice-versa, conserving public IPv4 addresses.",
        "To prevent network loops in a switched network."
      ],
      "correctAnswerIndex": 2,
      "explanation": "NAT's primary function is to allow multiple devices on a private network (using private IP addresses like 192.168.x.x) to share a limited number of public IP addresses when communicating with the internet. This conserves the dwindling supply of IPv4 addresses. It is *not* primarily for encryption, dynamic IP assignment (DHCP), or loop prevention (STP).",
      "examTip": "NAT is essential for connecting private networks to the internet with limited public IP addresses."
    },
    {
      "id": 12,
      "question": "A user reports they cannot access a network printer. Other users on the same subnet *can* access the printer. The user can ping the printer's IP address. What is the MOST likely cause?",
      "options": [
        "The printer is powered off.",
        "The network cable is unplugged from the user's computer.",
        "A permissions issue or a local printer configuration problem on the user's computer.",
        "The printer's IP address has changed."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Since the user *can* ping the printer, and *other* users can print, the problem is most likely *local* to the user's computer and specific to the *printing* function, *not* basic network connectivity. The printer is clearly powered on and reachable. A cable unplug would prevent *pinging*. The IP *could* have changed, but the successful ping rules that out. The most likely issue is either a permissions problem (the user doesn't have rights to use that printer) or a misconfiguration of the printer *on that specific computer* (wrong driver, incorrect port settings, etc.).",
      "examTip": "When troubleshooting access to a shared resource, consider user-specific permissions and configurations after verifying basic network connectivity."
    },
    {
      "id": 13,
      "question": "What is 'split horizon' in the context of distance-vector routing protocols?",
      "options": [
        "A technique for encrypting routing updates.",
        "A method for preventing routing loops by preventing a router from advertising a route back to the neighbor from which it was learned.",
        "A way to prioritize certain routes over others.",
        "A technique for load balancing traffic across multiple links."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Split horizon is a loop prevention technique used by distance-vector routing protocols. It prevents a router from sending information about a route *back* to the neighbor from which it learned that route. This helps prevent routing loops where routing information bounces back and forth between routers. It's *not* encryption, prioritization, or load balancing.",
      "examTip": "Split horizon is a key mechanism for preventing routing loops in distance-vector protocols."
    },
    {
      "id": 14,
      "question": "You are designing a network for a company that requires high availability and fault tolerance for their critical servers. Which of the following strategies would be MOST effective?",
      "options": [
        "Using a single, powerful server with a fast processor.",
        "Implementing redundant servers with automatic failover capabilities, and using redundant network connections (e.g., multiple NICs, multiple switches).",
        "Using a strong firewall to protect the servers from external attacks.",
        "Backing up the server data to a remote location once a week."
      ],
      "correctAnswerIndex": 1,
      "explanation": "High availability requires *redundancy*.  This means having multiple servers configured so that if one fails, another automatically takes over (failover).  It also means having redundant *network* components (NICs, switches, links) to eliminate single points of failure. A single server, even a powerful one, is a single point of failure. A firewall provides *security*, not *availability*. Backups are for *recovery*, not *availability* (they don't prevent downtime, they help you recover *after* downtime).",
      "examTip": "High availability is achieved through redundancy at multiple levels (servers, network components)."
    },
    {
      "id": 15,
      "question": "What is the primary purpose of a 'wireless LAN controller' (WLC)?",
      "options": [
        "To provide wireless access to a network.",
        "To centrally manage and control multiple lightweight access points (LAPs) in a wireless network, simplifying deployment, configuration, and security.",
        "To connect a wireless network to the internet.",
        "To encrypt wireless traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A WLC is used in enterprise wireless networks to manage a large number of access points. It handles tasks like AP configuration, firmware updates, security policies, client roaming, and radio frequency (RF) management. While individual APs *provide* wireless access, the *WLC* manages them *centrally*. It doesn't *directly* connect to the internet (a router does that), and while it *manages* security (including encryption), it's not solely an encryption device.",
      "examTip": "WLCs are essential for managing large-scale wireless deployments."
    },
    {
      "id": 16,
      "question": "What is 'link aggregation' (also known as 'port channeling' or 'EtherChannel') used for?",
      "options": [
        "To encrypt network traffic.",
        "To create multiple VLANs on a single switch.",
        "To combine multiple physical network links into a single logical link, increasing bandwidth and providing redundancy.",
        "To filter network traffic based on MAC addresses."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Link aggregation allows you to bundle multiple physical Ethernet links together, treating them as a single, higher-bandwidth link. This also provides redundancy – if one physical link fails, the others continue to carry traffic. It's *not* encryption, VLAN creation, or MAC address filtering.",
      "examTip": "Link aggregation increases bandwidth and provides fault tolerance for network connections."
    },
    {
      "id": 17,
      "question": "You are troubleshooting a network connectivity problem. You suspect a faulty network cable.  Which tool would be MOST effective in testing the cable for continuity, shorts, and miswires?",
      "options": [
        "A protocol analyzer (like Wireshark).",
        "A toner and probe.",
        "A cable tester.",
        "A spectrum analyzer."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A cable tester is specifically designed to test the physical integrity of network cables. It sends signals through the cable and checks for opens (breaks), shorts (wires touching where they shouldn't), and miswires (wires connected in the wrong order). A protocol analyzer captures *traffic*, a toner and probe *locates* cables, and a spectrum analyzer analyzes *radio frequencies* (for wireless).",
      "examTip": "A cable tester is an essential tool for diagnosing physical layer network problems."
    },
    {
      "id": 18,
      "question": "What is the purpose of the Address Resolution Protocol (ARP)?",
      "options": [
        "To translate domain names (like google.com) into IP addresses.",
        "To dynamically assign IP addresses to devices on a network.",
        "To map IP addresses to MAC addresses on a local network, enabling communication at the data link layer.",
        "To encrypt network traffic."
      ],
      "correctAnswerIndex": 2,
      "explanation": "ARP is used within a local Ethernet network to find the MAC address (physical address) associated with a known IP address (logical address). This is necessary for devices to send data frames to each other at Layer 2.  It's *not* DNS, DHCP, or encryption.",
      "examTip": "ARP is fundamental for communication within a local Ethernet network."
    },
    {
      "id": 19,
      "question": "What is a 'broadcast storm' on a network, and what is a common cause?",
      "options": [
        "A period of heavy rainfall that interferes with wireless signals.",
        "Excessive broadcast traffic flooding the network, consuming bandwidth and processing resources, potentially causing a network outage; often caused by network loops.",
        "A type of computer virus.",
        "A misconfigured DHCP server."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A broadcast storm is a critical network problem where broadcast traffic (packets sent to all devices on the network) overwhelms the network, degrading performance or causing a complete outage. Network loops (where a packet can circulate endlessly between switches) are a *common* cause. Spanning Tree Protocol (STP) is designed to prevent these loops. It's *not* weather, a virus, or a DHCP server (though a *rogue* DHCP server *could* cause *other* issues).",
      "examTip": "Broadcast storms are often caused by network loops; STP is essential to prevent them."
    },
    {
      "id": 20,
      "question": "You are configuring a router to connect to the internet. Your ISP has provided you with a static IP address, subnet mask, and default gateway.  Where should you configure these settings on the router?",
      "options": [
        "On the router's LAN interface.",
        "On the router's WAN interface.",
        "On each individual computer connected to the network.",
        "On the DNS server."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The WAN (Wide Area Network) interface on a router is the connection to the *external* network (the internet).  You must configure the static IP address, subnet mask, and default gateway provided by your ISP *on the WAN interface*. The LAN interface connects to your *internal* network. Individual computers would typically get their IP settings from DHCP (or be statically assigned *private* IPs). The DNS server handles name resolution.",
      "examTip": "The WAN interface connects the router to the internet; the LAN interface connects to your local network."
    },
    {
      "id": 21,
      "question": "What is the purpose of 'port security' on a network switch?",
      "options": [
        "To encrypt network traffic.",
        "To assign IP addresses to devices.",
        "To restrict access to a switch port based on MAC address, limiting the number of MAC addresses allowed or specifying which MAC addresses are permitted.",
        "To translate domain names to IP addresses."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Port security is a Layer 2 security feature that controls which devices (identified by their MAC addresses) can connect to a specific switch port.  You can limit the *number* of MAC addresses allowed on a port or create a list of *specific* allowed MAC addresses. This helps prevent unauthorized devices from connecting to the network. It's *not* encryption, IP assignment, or DNS.",
      "examTip": "Port security enhances network security by controlling access at the switch port level."
    },
    {
      "id": 22,
      "question": "A company is experiencing frequent network outages due to broadcast storms. Which of the following actions would be MOST effective in preventing future broadcast storms?",
      "options": [
        "Implementing stronger passwords on all user accounts.",
        "Ensuring that Spanning Tree Protocol (STP) is properly configured on all switches in the network.",
        "Increasing the bandwidth of the internet connection.",
        "Replacing all network cables with fiber optic cables."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Broadcast storms are most often caused by network loops. Spanning Tree Protocol (STP) is specifically designed to detect and prevent loops in switched networks by blocking redundant paths. Stronger passwords, increased bandwidth, and fiber cables address *other* issues, but *not* the root cause of broadcast storms.",
      "examTip": "STP is essential for preventing network loops and broadcast storms in switched networks."
    },
    {
      "id": 23,
      "question": "Which of the following statements BEST describes the difference between TCP and UDP?",
      "options": [
        "TCP is faster than UDP.",
        "TCP is connectionless and unreliable; UDP is connection-oriented and reliable.",
        "TCP is connection-oriented, providing reliable, ordered delivery with error checking; UDP is connectionless and does not guarantee delivery or order, making it faster but less reliable.",
        "TCP is used only for web browsing; UDP is used only for file transfer."
      ],
      "correctAnswerIndex": 2,
      "explanation": "TCP establishes a connection between two devices, provides error checking, and ensures that data packets are delivered in the correct order. This makes it reliable but adds overhead. UDP is connectionless and doesn't guarantee delivery or order. This makes it faster but less reliable, suitable for applications where some data loss is acceptable (like streaming video).  Speed depends on various factors, not *just* the protocol. Both can be used for various applications.",
      "examTip": "Choose TCP for reliability (e.g., web browsing, email); choose UDP for speed when some data loss is tolerable (e.g., streaming, online gaming)."
    },
    {
      "id": 24,
      "question": "What is the purpose of a 'virtual private network' (VPN)?",
      "options": [
        "To increase your internet connection speed.",
        "To create a secure, encrypted tunnel over a public network (like the internet), protecting your data from eavesdropping and allowing secure remote access to private networks.",
        "To block all incoming and outgoing network traffic.",
        "To automatically assign IP addresses to devices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A VPN encrypts your internet traffic and routes it through a secure server, masking your IP address and protecting your data, especially on public Wi-Fi. It allows remote users to access private network resources as if they were directly connected.  It's *not* primarily about speeding up connections, blocking *all* traffic, or assigning IPs.",
      "examTip": "Use a VPN for secure remote access and to enhance your online privacy, especially on untrusted networks."
    },
    {
      "id": 25,
      "question": "Which of the following is a characteristic of 'infrastructure as code' (IaC)?",
      "options": [
        "It involves manually configuring network devices using a command-line interface.",
        "It treats infrastructure (networks, servers, configurations) as software, managing and provisioning it through code, enabling automation, version control, and repeatability.",
        "It is only used for small networks.",
        "It eliminates the need for network administrators."
      ],
      "correctAnswerIndex": 1,
      "explanation": "IaC allows you to define your infrastructure (networks, servers, configurations) in code (often using tools like Terraform or Ansible). This code can be version-controlled, tested, and reused, making infrastructure deployments more consistent, reliable, and automated. It's *not* manual configuration, limited to small networks, or a replacement for administrators (it *empowers* them).",
      "examTip": "IaC is a key practice for DevOps and cloud computing, enabling automation and consistency in infrastructure management."
    },
    {
      "id": 26,
      "question": "What is a 'zero-trust' security model?",
      "options": [
        "Trusting all users and devices within the network perimeter by default.",
        "Assuming that no user or device, whether inside or outside the network perimeter, should be trusted by default, and verifying every access request based on identity, context, and device posture.",
        "Relying solely on firewalls for network security.",
        "Using only strong passwords for authentication."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Zero trust is a security framework that shifts away from the traditional 'perimeter-based' security model. It assumes that *no* user or device, regardless of location (inside or outside the network), should be trusted by default. Every access request must be verified based on multiple factors, including identity, device security posture, and the context of the request.  It's *not* about trusting everything inside, relying solely on firewalls, or only using strong passwords (though those are *part* of it).",
      "examTip": "Zero trust is a modern security approach that emphasizes 'never trust, always verify'."
    },
    {
      "id": 27,
      "question": "A network administrator is troubleshooting a slow network. They use a protocol analyzer and observe a large number of TCP retransmissions and duplicate ACKs.  What is the MOST likely cause?",
      "options": [
        "The DNS server is not responding.",
        "The DHCP server is not assigning IP addresses.",
        "Packet loss due to network congestion, faulty hardware, or other network issues.",
        "The web browser is not configured correctly."
      ],
      "correctAnswerIndex": 2,
      "explanation": "TCP retransmissions and duplicate ACKs are strong indicators of packet loss. When a sender doesn't receive an acknowledgment for a transmitted packet within a certain timeout, it retransmits the packet. Duplicate ACKs indicate that the receiver is getting out-of-order packets, likely due to dropped packets. This points to network congestion, faulty hardware, or other network-level problems, *not* DNS, DHCP, or browser issues.",
      "examTip": "TCP retransmissions and duplicate ACKs are key indicators of packet loss on a network."
    },
    {
      "id": 28,
      "question": "Which of the following is a benefit of using a standardized cabling system (e.g., structured cabling) in a building or campus network?",
      "options": [
        "It makes the network cabling look more colorful.",
        "It provides a consistent, organized, and well-documented infrastructure for network connectivity, simplifying troubleshooting, maintenance, and future upgrades.",
        "It eliminates the need for network switches.",
        "It guarantees complete network security."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Structured cabling uses standardized components (cables, connectors, patch panels, racks) and a hierarchical design to create a well-organized and easy-to-manage cabling infrastructure. This simplifies troubleshooting, makes it easier to add or change connections, and supports future growth. It's *not* about aesthetics, eliminating switches, or guaranteeing *complete* security (though it *supports* good security practices).",
      "examTip": "Structured cabling is essential for large and complex networks to ensure manageability and scalability."
    },
    {
      "id": 29,
      "question": "What is the purpose of a 'load balancer' in a network?",
      "options": [
        "To encrypt network traffic.",
        "To distribute network traffic across multiple servers, improving performance, availability, and preventing any single server from becoming overloaded.",
        "To assign IP addresses to devices dynamically.",
        "To translate domain names to IP addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A load balancer sits in front of a group of servers and distributes incoming client requests across those servers. This improves application responsiveness, prevents server overload, and provides high availability (if one server fails, the load balancer can redirect traffic to other servers). It's not primarily about encryption, IP assignment, or DNS.",
      "examTip": "Load balancers are essential for high-traffic websites and applications to ensure performance and availability."
    },
    {
      "id": 30,
      "question": "You are designing a network for a company that requires extremely low latency for real-time applications like high-frequency trading. Which of the following network technologies would be MOST appropriate?",
      "options": [
        "Satellite internet",
        "DSL internet",
        "Fiber optic connections with optimized routing protocols.",
        "Cable internet"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Fiber optic connections offer the lowest latency and highest bandwidth compared to other options. Optimizing routing protocols (e.g., using protocols that prioritize low-latency paths) further minimizes delays. Satellite internet has *very high* latency due to the distance signals must travel. DSL and cable have higher latency than fiber.",
      "examTip": "For extremely low-latency applications, fiber optic connections and optimized routing are crucial."
    },
    {
      "id": 31,
      "question": "A network is experiencing intermittent connectivity issues.  You suspect a problem with the physical cabling. Which tool would you use to test for cable faults like opens, shorts, and miswires?",
      "options": [
        "Protocol analyzer (like Wireshark)",
        "Toner and probe",
        "Cable tester",
        "Spectrum analyzer"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A cable tester is specifically designed to test the physical integrity of network cables. It checks for continuity (a complete connection), shorts (wires touching where they shouldn't), and miswires (wires connected in the wrong order).  A protocol analyzer captures *traffic*, a toner and probe *locates* cables, and a spectrum analyzer analyzes *radio frequencies*.",
      "examTip": "A cable tester is an essential tool for diagnosing physical layer network problems."
    },
    {
      "id": 32,
      "question": "Which of the following BEST describes the function of an 'intrusion detection system' (IDS)?",
      "options": [
        "To automatically assign IP addresses to devices on a network.",
        "To actively block or prevent network attacks.",
        "To passively monitor network traffic and logs for suspicious activity or security policy violations, and generate alerts for security personnel.",
        "To encrypt network traffic."
      ],
      "correctAnswerIndex": 2,
      "explanation": "An IDS is a *passive* security system. It observes network traffic and system activity, looking for patterns or signatures that indicate malicious activity. It *generates alerts* to notify administrators, but it *doesn't* automatically block or prevent attacks. That's the role of an *Intrusion Prevention System* (IPS).  It's not about IP assignment or encryption.",
      "examTip": "Think of an IDS as a security alarm system that detects suspicious activity but doesn't automatically stop it."
    },
    {
      "id": 33,
      "question": "What is 'phishing'?",
      "options": [
        "A type of fishing sport.",
        "A type of network cable.",
        "A cyberattack where attackers attempt to deceive users into revealing sensitive information (like passwords or credit card numbers) or installing malware, often by impersonating a trustworthy entity.",
        "A method for organizing files on a computer."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Phishing attacks rely on social engineering – tricking users into taking actions that compromise their security. Attackers often use deceptive emails, websites, or messages that appear to be from legitimate sources. It's *not* a sport, cable type, or file organization method.",
      "examTip": "Be extremely cautious of unsolicited emails, messages, or websites asking for personal information."
    },
    {
      "id": 34,
      "question": "What is a 'man-in-the-middle' (MitM) attack?",
      "options": [
        "An attempt to overwhelm a network server with excessive traffic.",
        "An attempt to trick users into revealing personal information.",
        "An attack where the attacker secretly intercepts and potentially alters communication between two parties who believe they are communicating directly with each other.",
        "An attempt to guess passwords by systematically trying many combinations."
      ],
      "correctAnswerIndex": 2,
      "explanation": "In a MitM attack, the attacker positions themselves between two communicating parties, allowing them to eavesdrop on the conversation, steal data, or even modify the communication. This can happen on unsecured Wi-Fi networks or through other network vulnerabilities.  It's *not* overwhelming traffic (DoS), tricking users (phishing), or password guessing (brute-force).",
      "examTip": "Use HTTPS and VPNs to protect against MitM attacks, especially on public Wi-Fi."
    },
    {
      "id": 35,
      "question": "What does 'encryption' do to data?",
      "options": [
        "It makes the data larger and easier to read.",
        "It transforms data into an unreadable format (ciphertext) using an algorithm and a key, protecting it from unauthorized access. Only someone with the correct decryption key can read the data.",
        "It permanently deletes data from a storage device.",
        "It organizes files and folders on a computer."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption is a fundamental security technique that scrambles data, making it unintelligible to anyone who doesn't have the correct decryption key. This protects the confidentiality of data both in transit (over a network) and at rest (stored on a device).  It doesn't make data larger, delete it, or organize it.",
      "examTip": "Encryption is essential for protecting sensitive data, both in transit and at rest."
    },
    {
      "id": 36,
      "question": "A network administrator configures a switch port with `switchport port-security maximum 2`. What is the effect of this configuration?",
      "options": [
        "The port will be shut down if more than two devices connect simultaneously.",
        "Only two specific MAC addresses will be allowed to connect to the port.",
        "The port will allow a maximum of two MAC addresses to be learned dynamically. If a third device attempts to connect, a security violation will occur (the specific action depends on the violation mode).",
        "The port will be limited to a speed of 2 Mbps."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The `switchport port-security maximum 2` command limits the number of MAC addresses that can be *learned* dynamically on that switch port.  It doesn't automatically shut down the port (unless that's the configured *violation* mode), nor does it pre-define *specific* MAC addresses (that would be a *static* configuration). It's *not* about port speed.",
      "examTip": "Port security limits the number of MAC addresses learned on a switch port, enhancing security."
    },
    {
      "id": 37,
      "question": "What is a 'zero-day' vulnerability?",
      "options": [
        "A vulnerability that has been known for a long time.",
        "A vulnerability that is publicly known and has a patch available.",
        "A software vulnerability that is unknown to the vendor or has no patch available, making it extremely dangerous because attackers can exploit it before a fix is released.",
        "A vulnerability that only affects outdated operating systems."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A zero-day vulnerability is a security flaw that is unknown to the software vendor or for which no patch has yet been developed. This means attackers can exploit it *before* the vendor is even aware of the problem, making it a very serious threat. It's *not* known/patched, nor is it limited to old OSes.",
      "examTip": "Zero-day vulnerabilities are highly prized by attackers and pose a significant security risk."
    },
    {
      "id": 38,
      "question": "What is 'defense in depth' in the context of network security?",
      "options": [
        "Relying solely on a strong firewall for network security.",
        "Implementing multiple layers of security controls (physical, technical, administrative) so that if one layer fails, others are in place to prevent a breach.",
        "Using only strong passwords for authentication.",
        "Encrypting all network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Defense in depth is a security strategy that uses multiple, overlapping layers of security controls. This approach recognizes that no single security measure is perfect, and if one layer is bypassed, others are still in place to protect the network. It's *not* relying on just a firewall, just passwords, or just encryption – it's a *combination* of many controls.",
      "examTip": "Defense in depth is a best practice for creating a robust and resilient security posture."
    },
    {
      "id": 39,
      "question": "Which of the following is a potential disadvantage of using Network Address Translation (NAT)?",
      "options": [
        "It increases the number of available public IP addresses.",
        "It can complicate troubleshooting and application compatibility, particularly for protocols that embed IP addresses within the application data.",
        "It makes the network more vulnerable to attacks.",
        "It slows down network performance."
      ],
      "correctAnswerIndex": 1,
      "explanation": "While NAT conserves IPv4 addresses and provides a basic level of security by hiding internal network structure, it can also create challenges. Some applications that embed IP addresses within their data (e.g., some older VoIP protocols) may not function correctly through NAT without special configuration (like Application Layer Gateways or ALGs). It does *not* increase *public* IPs, it can *improve* security (by hiding internal IPs), and while it *can* add a *small* amount of overhead, the performance impact is usually negligible.",
      "examTip": "NAT can sometimes cause compatibility issues with certain applications."
    },
    {
      "id": 40,
      "question": "A network administrator configures a router with the following access control list (ACL): `access-list 101 permit tcp any host 192.168.1.100 eq 80`. What is the effect of this ACL?",
      "options": [
        "It blocks all traffic to the host 192.168.1.100.",
        "It allows all TCP traffic from any source to the host 192.168.1.100 on port 80 (HTTP).",
        "It allows all traffic from the host 192.168.1.100 to any destination.",
        "It blocks all TCP traffic to port 80 on any host."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The ACL explicitly *permits* TCP traffic from *any* source (`any`) to the specific host 192.168.1.100, *only* on port 80 (which is the standard port for HTTP).  It does *not* block all traffic to the host, allow traffic *from* the host, or block TCP to port 80 on *all* hosts.  Remember that ACLs are processed sequentially, and an implicit `deny any` exists at the end of every ACL.",
      "examTip": "Carefully analyze ACL statements to understand their precise effect on network traffic."
    },
    {
      "id": 41,
      "question": "Which type of DNS record is used to map a domain name to an IPv6 address?",
      "options": [
        "A",
        "AAAA",
        "CNAME",
        "MX"
      ],
      "correctAnswerIndex": 1,
      "explanation": "An AAAA (quad-A) record is used in DNS to map a hostname to an IPv6 address. An A record maps to an IPv4 address. CNAME records create aliases, and MX records specify mail servers.",
      "examTip": "Remember AAAA for IPv6 address records in DNS."
    },
    {
      "id": 42,
      "question": "You are troubleshooting a network connectivity problem.  You can ping the loopback address (127.0.0.1) successfully, but you cannot ping your default gateway or any other devices on the local network.  Which of the following is the LEAST likely cause?",
      "options": [
        "A faulty network cable.",
        "A misconfigured IP address or subnet mask on your computer.",
        "A problem with the network interface card (NIC) on your computer.",
        "A problem with the DNS server."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Pinging the loopback address confirms that the TCP/IP stack on your computer is working.  The inability to ping the default gateway or other *local* devices suggests a problem with the *local* network connection or configuration. A faulty cable, a bad NIC, or an incorrect IP address/subnet mask could all prevent local communication.  DNS is for *name resolution*, not basic IP connectivity; you're not even getting to the point where DNS would be involved.",
      "examTip": "Systematically eliminate possibilities: start with the physical layer (cable, NIC) and local IP configuration before considering higher-level issues like DNS."
    },
    {
      "id": 43,
      "question": "Which of the following statements BEST describes the difference between a 'vulnerability' and an 'exploit'?",
      "options": [
        "A vulnerability is a successful attack; an exploit is a potential weakness.",
        "A vulnerability is a weakness in a system or network that *could* be exploited; an exploit is a specific piece of code or technique that *takes advantage* of a vulnerability to cause harm.",
        "A vulnerability is a type of malware; an exploit is a type of firewall.",
        "Vulnerabilities and exploits are the same thing."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A *vulnerability* is a flaw or weakness in software, hardware, or configuration that *could* be used by an attacker. An *exploit* is the *actual method* used to take advantage of that vulnerability. It's the difference between a *potential* problem and the *actual* attack.",
      "examTip": "Think of a vulnerability as a hole in a fence, and an exploit as the act of climbing through that hole."
    },
    {
      "id": 44,
      "question": "What is the purpose of using 'private' IP address ranges (like 192.168.x.x, 10.x.x.x, and 172.16.x.x - 172.31.x.x) within a local network?",
      "options": [
        "To make the network more secure.",
        "To allow direct communication with devices on the public internet.",
        "To conserve public IP addresses and allow multiple devices to share a single public IP address using NAT.",
        "To increase network speed."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Private IP addresses are *not* routable on the public internet. They are used *within* private networks (homes, offices) to allow devices to communicate with each other. Network Address Translation (NAT) is then used to translate these private addresses to a public IP address when communicating with the internet. This conserves the limited number of available public IPv4 addresses. Private IPs alone do *not* make a network *more* secure (security requires firewalls, etc.), allow *direct* internet communication, or increase speed.",
      "examTip": "Private IP addresses are used within local networks and are not directly accessible from the internet."
    },
    {
      "id": 45,
      "question": "You are configuring a wireless access point.  Which of the following settings would provide the WEAKEST security for your wireless network?",
      "options": [
        "WPA2 with AES encryption",
        "WPA3 with SAE encryption",
        "WEP (Wired Equivalent Privacy)",
        "WPA with TKIP encryption"
      ],
      "correctAnswerIndex": 2,
      "explanation": "WEP (Wired Equivalent Privacy) is an outdated and extremely vulnerable wireless security protocol. It has known weaknesses and can be easily cracked using readily available tools. WPA is better than WEP, but also has vulnerabilities. WPA2 with AES is significantly stronger, and WPA3 is the most secure.",
      "examTip": "Never use WEP for wireless security; it offers virtually no protection."
    },
    {
      "id": 46,
      "question": "What is 'packet sniffing'?",
      "options": [
        "A method for organizing files on a computer.",
        "The process of capturing and analyzing network traffic, often using a tool like Wireshark, to inspect data packets and diagnose network problems or identify security threats.",
        "A type of computer virus.",
        "A technique for speeding up internet connections."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Packet sniffing (or packet analysis) involves capturing the raw data packets traveling across a network and examining their contents. This can be used legitimately for troubleshooting, network monitoring, and security analysis, or maliciously for eavesdropping and stealing data. It's not about file organization, viruses, or speeding up connections.",
      "examTip": "Packet sniffers are powerful tools that can be used for both good and bad purposes."
    },
    {
      "id": 47,
      "question": "Which of the following is a characteristic of a 'stateful firewall' compared to a stateless packet filter?",
      "options": [
        "A stateful firewall only examines individual packets in isolation.",
        "A stateful firewall tracks the state of network connections (e.g., TCP sessions) and makes filtering decisions based on both packet headers and the context of the connection, providing more robust security.",
        "A stateful firewall is less secure than a stateless packet filter.",
        "A stateful firewall is only used for wireless networks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Stateful firewalls maintain a table of active network connections and use this information to make more intelligent filtering decisions. They can distinguish between legitimate return traffic and unsolicited incoming traffic, providing better security than stateless packet filters, which only examine individual packets without considering the connection context. Stateful firewalls are *more* secure, and they are used in *all* types of networks.",
      "examTip": "Stateful firewalls are the standard for modern network security."
    },
    {
      "id": 48,
      "question": "You are configuring a new server and want to ensure it always receives the same IP address from the DHCP server.  What is the BEST way to achieve this?",
      "options": [
        "Configure a long DHCP lease time.",
        "Configure a DHCP reservation (or static mapping) that associates the server's MAC address with a specific IP address.",
        "Configure the server with a static IP address outside the DHCP scope.",
        "Configure the DHCP server to exclude the desired IP address."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DHCP reservation (or static mapping) guarantees that the DHCP server will *always* assign the *same* IP address to the server, based on its MAC address.  While a *static IP* (option C) *would* work, it's generally *better* to manage addresses centrally through DHCP when possible. A long lease time only makes it *less likely* to change, not *guaranteed*. Excluding the address would *prevent* it from being assigned.",
      "examTip": "Use DHCP reservations for devices that require consistent IP addresses, and manage them centrally through the DHCP server."
    },
    {
      "id": 49,
      "question": "What is the primary purpose of an 'intrusion prevention system' (IPS)?",
      "options": [
        "To assign IP addresses to devices on a network.",
        "To actively monitor network traffic for malicious activity and take steps to block or prevent attacks in real-time.",
        "To encrypt network traffic to protect data confidentiality.",
        "To translate domain names into IP addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An IPS goes beyond the *detection* capabilities of an IDS (Intrusion Detection System).  An IPS *actively* intervenes to stop threats, dropping malicious packets, resetting connections, blocking traffic from specific sources, or even quarantining infected systems.  It's *not* about IP assignment, encryption, or DNS.",
      "examTip": "An IPS provides proactive, real-time protection against network attacks."
    },
    {
      "id": 50,
      "question": "Which of the following is a characteristic of 'infrastructure as code' (IaC)?",
      "options": [
        "It involves manually configuring network devices using a command-line interface.",
        "It treats infrastructure (networks, servers, configurations) as software, managing and provisioning it through code, enabling automation, version control, repeatability, and faster deployments.",
        "It is only suitable for small and simple networks.",
        "It eliminates the need for skilled network engineers."
      ],
      "correctAnswerIndex": 1,
      "explanation": "IaC allows you to define and manage your infrastructure (networks, servers, virtual machines, etc.) using code (often in a declarative format). This code can be version-controlled, tested, and reused, making infrastructure deployments more consistent, reliable, and automated. It's *not* manual configuration, it's applicable to *all* sizes of networks, and it *doesn't* eliminate the need for skilled engineers (it changes their role).",
      "examTip": "IaC is a key practice for DevOps and cloud computing, enabling automation and consistency in infrastructure management."
    },
    {
      "id": 51,
      "question": "A network administrator is troubleshooting a slow website. Using `traceroute`, they observe high latency at a specific hop *before* the final destination.  What does this indicate?",
      "options": [
        "The problem is with the user's local computer.",
        "The problem is with the website's DNS server.",
        "The problem is likely with the network infrastructure at or near the hop with high latency.",
        "The problem is with the user's web browser."
      ],
      "correctAnswerIndex": 2,
      "explanation": "`traceroute` shows the path that packets take to reach a destination, including the delay at each hop (router). High latency at a *specific* hop indicates a problem *at that point* in the network, *not* the user's local computer, DNS, or web browser.  It could be congestion, a faulty router, or a misconfigured link at that hop.",
      "examTip": "Use `traceroute` to identify points of high latency along a network path."
    },
    {
      "id": 52,
      "question": "What is a 'denial-of-service' (DoS) attack?",
      "options": [
        "An attempt to steal user passwords.",
        "An attempt to overwhelm a network or server with traffic from a *single* source, making it unavailable to legitimate users.",
        "An attempt to trick users into revealing personal information.",
        "An attempt to gain unauthorized access to a system by guessing passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DoS attack aims to disrupt a service by flooding it with traffic *from a single attacking machine*, making it inaccessible to legitimate users. Password stealing is credential theft, tricking users is phishing, and password guessing is a brute-force attack. A *distributed* DoS (DDoS) uses *multiple* sources.",
      "examTip": "DoS attacks can cause significant downtime and disruption to online services."
    },
    {
      "id": 53,
      "question": "What is the function of the Address Resolution Protocol (ARP)?",
      "options": [
        "To translate domain names (like google.com) into IP addresses.",
        "To dynamically assign IP addresses to devices.",
        "To map IP addresses to MAC addresses on a local network, allowing devices to communicate at the data link layer.",
        "To encrypt network traffic."
      ],
      "correctAnswerIndex": 2,
      "explanation": "ARP is crucial for *local* network communication. Before a device can send data to another device on the *same* subnet, it needs to know the recipient's MAC address. ARP resolves the IP address to the corresponding MAC address. It's *not* DNS, DHCP, or encryption.",
      "examTip": "ARP is essential for communication within an Ethernet LAN."
    },
    {
      "id": 54,
      "question": "You are configuring a wireless network and want to use the 5 GHz band. Which of the following 802.11 standards operate in the 5 GHz band (either exclusively or optionally)?",
      "options": [
        "802.11b only",
        "802.11g only",
        "802.11a, 802.11n, 802.11ac, and 802.11ax",
        "802.11b and 802.11g"
      ],
      "correctAnswerIndex": 2,
      "explanation": "802.11a operates *exclusively* in the 5 GHz band. 802.11n, 802.11ac, and 802.11ax can operate in *both* the 2.4 GHz and 5 GHz bands. 802.11b and 802.11g operate *only* in the 2.4 GHz band.",
      "examTip": "Know the frequency bands used by different 802.11 standards."
    },
    {
      "id": 55,
      "question": "What is a 'virtual LAN' (VLAN)?",
      "options": [
        "A network that uses only virtual machines.",
        "A logical grouping of network devices that are on the same broadcast domain, regardless of their physical location within a switched network.",
        "A type of network cable.",
        "A program for creating virtual reality environments."
      ],
      "correctAnswerIndex": 1,
      "explanation": "VLANs allow you to segment a *physical* network into multiple, *logically* separate networks. This improves security, performance (by reducing broadcast traffic), and manageability. Devices on different VLANs cannot communicate directly without a router (or Layer 3 switch). They are *not* limited to virtual machines, a cable type, or VR software.",
      "examTip": "VLANs are a fundamental tool for network segmentation in switched networks."
    },
    {
      "id": 56,
      "question": "Which of the following statements BEST describes 'network segmentation'?",
      "options": [
        "Physically separating network cables.",
        "Dividing a network into smaller, isolated subnetworks (using VLANs, subnets, or other techniques) to improve security, performance, and manageability.",
        "Connecting multiple networks together using routers.",
        "Encrypting all network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Network segmentation is about creating logical boundaries within a network to isolate traffic and limit the impact of security breaches. It's *not* just about *physical* separation, connecting networks (that's routing), or encryption. Segmentation improves both security and performance by reducing broadcast domains and containing potential problems.",
      "examTip": "Segmentation is a critical security best practice for any network."
    },
    {
      "id": 57,
      "question": "What is 'social engineering' in the context of cybersecurity?",
      "options": [
        "Building and managing a social media presence.",
        "Manipulating people into divulging confidential information or performing actions that compromise security, often through deception, impersonation, or psychological tricks.",
        "Using social media for marketing.",
        "Networking with colleagues at a conference."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Social engineering attacks exploit *human* vulnerabilities, not technical ones. Attackers use various techniques to trick people into revealing sensitive information (like passwords or credit card numbers) or granting them access to systems. It's about *manipulation*, not social media platforms, marketing, or professional networking (in the traditional sense).",
      "examTip": "Be skeptical of unsolicited requests for information, and always verify the identity of anyone asking for sensitive data."
    },
    {
      "id": 58,
      "question": "A network administrator configures a router with an access control list (ACL) that includes the statement `deny ip any any`.  What is the effect of this ACL, assuming it's applied to an interface?",
      "options": [
        "It allows all IP traffic.",
        "It blocks all IP traffic.",
        "It allows only TCP traffic.",
        "It allows only UDP traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`deny ip any any` blocks *all* IP traffic.  `ip` refers to the IP protocol (covering both TCP and UDP), `any` for the source means *any* source IP address, and `any` for the destination means *any* destination IP address. ACLs are processed sequentially, and there's an implicit `deny any` at the end of every ACL, so this single statement effectively blocks everything.",
      "examTip": "Understand the structure and logic of ACL statements to determine their impact on network traffic."
    },
    {
      "id": 59,
      "question": "You are troubleshooting a network where users are experiencing intermittent connectivity and slow performance.  Using a protocol analyzer, you observe a large number of ARP requests and replies.  What does this MOST likely indicate?",
      "options": [
        "The network is functioning normally.",
        "The DNS server is not responding.",
        "There may be an ARP spoofing attack, a misconfigured device, or a large number of devices constantly joining and leaving the network, causing excessive ARP traffic.",
        "The DHCP server is not assigning IP addresses."
      ],
      "correctAnswerIndex": 2,
      "explanation": "While *some* ARP traffic is normal, an *excessive* amount suggests a problem.  Possibilities include ARP spoofing (a malicious attack), a misconfigured device (e.g., constantly requesting an IP), or a very unstable network environment. It's *not* normal operation, and it's not directly related to DNS or DHCP (though DHCP *issues* could indirectly lead to *more* ARP requests if devices are constantly trying to get an IP).",
      "examTip": "Excessive ARP traffic can indicate network problems or security threats."
    },
    {
      "id": 60,
      "question": "What is the primary purpose of using 'Quality of Service' (QoS) mechanisms in a network?",
      "options": [
        "To encrypt all network traffic.",
        "To prioritize certain types of network traffic (like voice or video) over others, ensuring that critical or time-sensitive applications receive adequate bandwidth and low latency.",
        "To automatically assign IP addresses to devices.",
        "To translate domain names into IP addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "QoS allows network administrators to manage network resources and give preferential treatment to specific types of traffic. This is crucial for real-time applications (like VoIP and video conferencing) that require low latency and consistent bandwidth. It's *not* about encryption, IP assignment (DHCP), or DNS.",
      "examTip": "QoS is essential for ensuring a good user experience for real-time applications on congested networks."
    },
    {
      "id": 61,
      "question": "Which of the following is a key characteristic of a 'zero-trust' security model?",
      "options": [
        "Trusting all users and devices inside the network perimeter by default.",
        "Assuming that no user or device, whether inside or outside the network perimeter, should be trusted by default, and verifying every access request based on multiple factors.",
        "Relying solely on firewalls for network security.",
        "Using only strong passwords for authentication."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Zero trust is a security framework that shifts away from the traditional 'perimeter-based' security model. It assumes that *no* user or device, regardless of location, should be automatically trusted.  Every access request must be verified based on identity, device security posture, context, and other factors.  It's *not* about trusting everything inside, relying solely on firewalls, or *only* using strong passwords (though those are *part* of it).",
      "examTip": "Zero trust is a modern security approach that emphasizes 'never trust, always verify'."
    },
    {
      "id": 62,
      "question": "What is 'split horizon' used for in distance-vector routing protocols?",
      "options": [
        "To encrypt routing updates.",
        "To prevent routing loops by preventing a router from advertising a route back out the same interface from which it was learned.",
        "To prioritize certain routes over others.",
        "To load balance traffic across multiple links."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Split horizon is a loop-prevention technique. A router will *not* advertise a route back to the neighbor from which it *learned* that route. This helps prevent situations where routers bounce routing information back and forth, creating a loop. It's *not* about encryption, prioritization, or load balancing.",
      "examTip": "Split horizon is a key mechanism for preventing routing loops in distance-vector routing protocols like RIP."
    },
    {
      "id": 63,
      "question": "A network administrator wants to implement a solution that provides centralized authentication, authorization, and accounting (AAA) for network access. Which protocol is MOST appropriate?",
      "options": [
        "SNMP (Simple Network Management Protocol)",
        "RADIUS (Remote Authentication Dial-In User Service)",
        "SMTP (Simple Mail Transfer Protocol)",
        "HTTP (Hypertext Transfer Protocol)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RADIUS is a networking protocol specifically designed to provide centralized AAA services. It's commonly used for network access control, including dial-up, VPN, and wireless authentication. SNMP is for network *management*, SMTP is for *email*, and HTTP is for *web browsing*.",
      "examTip": "RADIUS is the standard protocol for centralized AAA in network access control."
    },
    {
      "id": 64,
      "question": "What is 'port mirroring' (also known as 'SPAN') used for on a network switch?",
      "options": [
        "To encrypt network traffic.",
        "To restrict access to a switch port based on MAC address.",
        "To copy network traffic from one or more source ports to a destination port for monitoring and analysis, often used with intrusion detection systems or protocol analyzers.",
        "To assign IP addresses dynamically."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Port mirroring allows you to duplicate network traffic from one or more switch ports to another port. This is typically used to connect a network monitoring device (like an IDS or a protocol analyzer) to capture and analyze traffic without disrupting the normal flow of data. It's *not* encryption, port security, or IP assignment.",
      "examTip": "Port mirroring is a valuable tool for network monitoring and troubleshooting."
    },
    {
      "id": 65,
      "question": "Which of the following is a potential disadvantage of using a 'star' network topology?",
      "options": [
        "It is difficult to add or remove devices.",
        "If one cable fails, the entire network goes down.",
        "The central hub or switch represents a single point of failure; if it fails, all devices connected to it lose network access.",
        "It requires more cabling than other topologies."
      ],
      "correctAnswerIndex": 2,
      "explanation": "While the star topology is easy to manage and troubleshoot (a single cable failure only affects *one* device), the *central* device (hub or switch) is a *single point of failure*. If that central device fails, all devices connected to it lose network connectivity. It's *not* difficult to add/remove devices, and a *single* cable failure doesn't take down the *entire* network. Star does typically require more cabling than bus, but that is not an inherent disadvantage compared to the single point of failure.",
      "examTip": "The central device in a star topology is a critical point of failure; consider redundancy for high-availability networks."
    },
    {
      "id": 66,
      "question": "What is a 'distributed denial-of-service' (DDoS) attack?",
      "options": [
        "An attempt to steal user passwords.",
        "An attempt to overwhelm a network or server with traffic originating from *multiple*, compromised computers (often a botnet), making the service unavailable to legitimate users.",
        "A type of phishing attack.",
        "A type of brute-force attack."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DDoS attack is a more sophisticated and powerful form of DoS attack. Instead of originating from a single source, the attack traffic comes from many compromised computers (often part of a botnet – a network of infected machines controlled by an attacker). This makes it much harder to block or mitigate. It's *not* password stealing, phishing, or brute-force (though those might be used to build a botnet in the first place).",
      "examTip": "DDoS attacks are a major threat to online services and require specialized mitigation techniques."
    },
    {
      "id": 67,
      "question": "Which type of DNS record is used to map a domain name to an IPv4 address?",
      "options": [
        "AAAA",
        "A",
        "CNAME",
        "MX"
      ],
      "correctAnswerIndex": 1,
      "explanation": "An 'A' record in DNS maps a hostname (like www.example.com) to an IPv4 address. AAAA records map to IPv6 addresses, CNAME records create aliases, and MX records specify mail servers.",
      "examTip": "Remember 'A' records for IPv4 and 'AAAA' records for IPv6 in DNS."
    },
    {
      "id": 68,
      "question": "What does 'MTU' stand for, and why is it important in networking?",
      "options": [
        "Maximum Transfer Unit; it's the minimum packet size allowed on a network.",
        "Maximum Transmission Unit; it's the largest packet size that can be transmitted on a network link without fragmentation.",
        "Minimum Transmission Unit; it's the smallest packet size that can be transmitted on a network.",
        "Media Transfer Unit; it's the type of cable used on the network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "MTU (Maximum Transmission Unit) defines the largest data packet (in bytes) that can be transmitted over a network link *without* being fragmented. If a packet exceeds the MTU, it must be broken into smaller fragments, which can degrade performance. It's *not* about the minimum packet size or cable type.",
      "examTip": "Ensure that the MTU is set correctly across all devices on a network to avoid fragmentation and performance issues."
    },
    {
      "id": 69,
      "question": "A network administrator configures a router with the following access control list (ACL): `access-list 100 deny tcp any host 192.168.1.50 eq 22` and `access-list 100 permit ip any any`. What is the effect of this ACL, assuming it is applied to an interface in the inbound direction?",
      "options": [
        "It allows all traffic to the host 192.168.1.50.",
        "It blocks all traffic to the host 192.168.1.50.",
        "It blocks SSH (port 22) traffic from any source to the host 192.168.1.50, but allows all other IP traffic.",
        "It allows only SSH traffic to the host 192.168.1.50."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The first line explicitly denies TCP traffic from any source to host 192.168.1.50 *on port 22* (SSH). The second line permits all other IP traffic. That means SSH traffic to 192.168.1.50 is blocked, but everything else is allowed. There's an implicit `deny any` at the end of the ACL, but `permit ip any any` overrides it for all other traffic.",
      "examTip": "Read ACLs line by line and remember the implicit `deny any` at the end."
    },
    {
      "id": 70,
      "question": "You are troubleshooting a network connectivity problem.  A user can ping their own computer's IP address and the loopback address (127.0.0.1), but they cannot ping any other devices on their local subnet.  What is the LEAST likely cause?",
      "options": [
        "A faulty network cable.",
        "A misconfigured IP address or subnet mask on the user's computer.",
        "A problem with the network interface card (NIC) on the user's computer.",
        "A problem with the DNS server."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Because the user can ping their own IP and loopback, the local TCP/IP stack is fine. Not being able to ping devices on the local subnet points to either a physical issue (cable, NIC), or incorrect IP/subnet mask. DNS only comes into play when translating names to IP addresses, but here they can’t even ping by IP. Therefore, DNS is the least likely cause.",
      "examTip": "First verify physical/connectivity issues. DNS won’t matter if you can’t ping IPs on the same subnet."
    },
    {
      "id": 71,
      "question": "What is 'CSMA/CD', and in what type of network is it used?",
      "options": [
        "Carrier Sense Multiple Access with Collision Detection; it's used in modern switched Ethernet networks.",
        "Carrier Sense Multiple Access with Collision Detection; it's used in older, hub-based Ethernet networks to manage collisions.",
        "Carrier Sense Multiple Access with Collision Avoidance; it's used in wireless networks.",
        "Code Division Multiple Access; it's used in cellular networks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "CSMA/CD was the method Ethernet used to handle collisions when multiple devices shared a collision domain (as with hubs). Devices listen for network traffic (carrier sense) and, if a collision is detected, back off and retry. Modern switched Ethernet uses full-duplex on each port, eliminating collisions. Wireless uses CSMA/CA, and CDMA is for cellular networks.",
      "examTip": "CSMA/CD is legacy; full-duplex switched Ethernet no longer requires it."
    },
    {
      "id": 72,
      "question": "A company wants to implement a network security solution that provides centralized authentication, authorization, and accounting (AAA) for users accessing network resources via VPN, dial-up, and wireless connections. Which protocol is MOST appropriate?",
      "options": [
        "SNMP (Simple Network Management Protocol)",
        "RADIUS (Remote Authentication Dial-In User Service)",
        "SMTP (Simple Mail Transfer Protocol)",
        "HTTP (Hypertext Transfer Protocol)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RADIUS is specifically designed for centralized AAA. It allows a central server to authenticate users, authorize their access to specific resources, and log their sessions (accounting). SNMP is for network management, SMTP is email, HTTP is web browsing.",
      "examTip": "RADIUS is the de facto standard for AAA in many enterprise networks."
    },
    {
      "id": 73,
      "question": "What is a 'deauthentication attack' in the context of wireless networks?",
      "options": [
        "An attempt to steal wireless network passwords.",
        "A type of denial-of-service attack where the attacker sends forged deauthentication frames to disconnect legitimate users from a wireless access point.",
        "An attempt to trick users into revealing their personal information.",
        "An attempt to guess wireless network passwords using a brute-force attack."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A deauthentication attack involves sending fake deauth frames, which are part of 802.11 management traffic, to the AP or clients. This forces legitimate clients off the network. Attackers often use it as a precursor to an Evil Twin or man-in-the-middle attack. It’s not simply password theft, phishing, or brute forcing the Wi-Fi key (though that can also happen).",
      "examTip": "Deauth attacks exploit the unprotected nature of 802.11 management frames."
    },
    {
      "id": 74,
      "question": "You are designing a network with multiple VLANs. You want to ensure that traffic between VLANs is controlled and inspected by a firewall. Which design is MOST appropriate?",
      "options": [
        "Configure all VLANs on the same switch with no router or firewall in between.",
        "Configure inter-VLAN routing on a Layer 2 switch only.",
        "Use a Layer 3 device (router or L3 switch) for inter-VLAN routing, and ensure all inter-VLAN traffic passes through a firewall interface for inspection.",
        "Put all devices in a single subnet; no need for VLANs."
      ],
      "correctAnswerIndex": 2,
      "explanation": "To inspect traffic between VLANs, you must route it through a firewall. A Layer 2 switch cannot do routing. A single subnet defeats the purpose. The typical solution is: VLAN trunk into a Layer 3 device (or sub-interfaces), then pass traffic to the firewall for policy enforcement.",
      "examTip": "For VLAN-to-VLAN inspection, you need routing plus a firewall in the traffic path."
    },
    {
      "id": 75,
      "question": "Which of the following statements BEST describes 'network convergence'?",
      "options": [
        "Separate networks for voice, data, and video.",
        "Using only wireless for everything.",
        "Combining multiple services (voice, data, video, etc.) onto a single shared network infrastructure.",
        "A method for encrypting all traffic on a network."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Network convergence is the trend of putting all communications (phone calls/VoIP, data, video conferencing, etc.) on one IP-based network. It simplifies management and can reduce costs. It’s not about separating them or only wireless, nor purely encryption.",
      "examTip": "Converged networks carry voice, data, and video together."
    },
    {
      "id": 76,
      "question": "A network administrator configures a switch port with `spanning-tree portfast`. What does this do?",
      "options": [
        "Disables STP on that port entirely.",
        "Enables immediate forwarding state on that port, bypassing listening/learning, and should only be used for end-user ports (no other switches).",
        "Sets the switch as the root bridge.",
        "Enables link aggregation on that port."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`portfast` means the port transitions instantly to a forwarding state instead of going through listening and learning states. This is safe only if the port is connected to a single end device, not another switch. It doesn’t disable STP, set the root bridge, or do link aggregation.",
      "examTip": "Use `portfast` for end-user ports to speed up connectivity after link-up."
    },
    {
      "id": 77,
      "question": "What is '802.1X' in network security?",
      "options": [
        "A wireless encryption standard.",
        "A port-based network access control (PNAC) protocol requiring authentication before permitting LAN or WLAN access.",
        "A layer-3 routing protocol.",
        "A technology for link aggregation."
      ],
      "correctAnswerIndex": 1,
      "explanation": "802.1X is a standard for authenticating devices on a port (wired or wireless) before granting network access. Often used with RADIUS. Not just wireless encryption, not a routing protocol, and not link aggregation.",
      "examTip": "802.1X controls access at the port level; often used with RADIUS for AAA."
    },
    {
      "id": 78,
      "question": "You are troubleshooting a network. A user can browse some websites but not others; pings by IP to the ‘problem’ sites succeed, but pings by hostname fail. What is the MOST likely issue?",
      "options": [
        "A faulty Ethernet cable.",
        "A problem with the user’s browser configuration.",
        "An intermittent or incorrect DNS configuration or DNS server issue.",
        "A firewall blocking all traffic to those sites."
      ],
      "correctAnswerIndex": 2,
      "explanation": "If ping-by-IP works, then network connectivity is fine. If ping-by-name fails, that strongly suggests DNS resolution problems. It’s not the cable or a firewall blocking (since IP-based pings go through). A browser config might affect HTTP, but not ICMP name resolution.",
      "examTip": "Always separate DNS issues from basic IP connectivity issues in troubleshooting."
    },
    {
      "id": 79,
      "question": "What is the purpose of a subnet mask in IP networking?",
      "options": [
        "It encrypts IP packets.",
        "It identifies which portion of the IP address is the network part vs. the host part.",
        "It assigns IP addresses automatically.",
        "It filters packets based on MAC addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A subnet mask, combined with the IP address, determines which bits represent the network and which bits represent the host. It’s not encryption, DHCP, or MAC filtering.",
      "examTip": "Subnet masks are crucial for defining network boundaries."
    },
    {
      "id": 80,
      "question": "What is a potential security risk of using a public, unsecured Wi-Fi hotspot?",
      "options": [
        "Faster speeds than your home network.",
        "Better encryption than WPA2 at home.",
        "Susceptibility to man-in-the-middle attacks and eavesdropping, since traffic may be unencrypted.",
        "Guaranteed QoS for your applications."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Open hotspots often have no encryption, enabling attackers to intercept or modify traffic. They are not necessarily faster, definitely not more secure than WPA2, and there’s no guaranteed QoS.",
      "examTip": "Use a VPN on public Wi-Fi; unencrypted traffic can be snooped."
    },
    {
      "id": 81,
      "question": "What is a ‘reverse DNS lookup’?",
      "options": [
        "Converting a domain name into an IP address.",
        "Converting an IP address into a domain name.",
        "Encrypting DNS traffic.",
        "A way to block malicious domains."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Reverse DNS means you start with an IP address and look up the associated domain name (if any). The forward lookup is domain-to-IP. Reverse is IP-to-domain. It’s not encryption or blocking.",
      "examTip": "Reverse DNS can be useful for verifying mail senders, logging, etc."
    },
    {
      "id": 82,
      "question": "A network admin enters `ip route 0.0.0.0 0.0.0.0 192.168.1.1` on a router. What does this do?",
      "options": [
        "Creates a route only for the 192.168.1.0 network.",
        "Creates a default route that sends all traffic with no more specific match to 192.168.1.1.",
        "Creates a dynamic route using RIP.",
        "Blocks all traffic to 192.168.1.1."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Using `0.0.0.0 0.0.0.0` sets a default route (the ‘gateway of last resort’). Any traffic not matching a more specific route goes to 192.168.1.1. Not a dynamic route, not a block.",
      "examTip": "The ‘all-zeroes’ address with all-zeroes mask means default route."
    },
    {
      "id": 83,
      "question": "What is ‘DHCP snooping’ on a switch?",
      "options": [
        "Encrypting DHCP requests.",
        "Preventing rogue DHCP servers by allowing DHCP responses only from trusted ports.",
        "Speeding up IP lease times.",
        "Capturing user browsing data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DHCP snooping inspects DHCP traffic, ensuring only the official DHCP server (on a trusted port) can hand out addresses. It’s not encryption or data capture. It helps block rogue DHCP servers.",
      "examTip": "DHCP snooping is an important layer-2 security feature to prevent unauthorized IP assignments."
    },
    {
      "id": 84,
      "question": "Which is a drawback of using a hub (instead of a switch) in a modern network?",
      "options": [
        "They are very expensive.",
        "They create a single collision domain, reducing performance as collisions increase with more devices.",
        "They require special cables.",
        "They can’t connect to the internet."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hubs simply replicate signals on all ports, causing a single collision domain. Switches intelligently forward traffic and separate collision domains. Hubs are actually cheaper, can use standard cables, and can connect to the internet (if attached to a router) — but they’re inefficient.",
      "examTip": "Hubs are legacy devices. Switches replaced them for better performance."
    },
    {
      "id": 85,
      "question": "A company wants a single security appliance that acts as a firewall, IPS, antivirus scanner, web filter, and VPN gateway. Which solution fits?",
      "options": [
        "A domain controller",
        "A network-attached storage (NAS) server",
        "A wireless controller",
        "A unified threat management (UTM) device"
      ],
      "correctAnswerIndex": 3,
      "explanation": "UTM devices consolidate multiple security features (firewall, IPS, antivirus, web filtering, VPN, etc.) into one box. Domain controllers are for user authentication in Windows. NAS is for storage. WLC is for managing Wi-Fi APs.",
      "examTip": "UTM = all-in-one security solution."
    },
    {
      "id": 86,
      "question": "What does ‘BGP’ stand for, and what does it do?",
      "options": [
        "Basic Gateway Protocol; it assigns private IPs to clients.",
        "Border Gateway Protocol; it’s the routing protocol that exchanges routes between autonomous systems on the internet.",
        "Broadband Gateway Protocol; it’s used for connecting DSL modems.",
        "Backup Gateway Protocol; it’s used only for secondary routers."
      ],
      "correctAnswerIndex": 1,
      "explanation": "BGP is the Border Gateway Protocol. It’s the main exterior routing protocol that allows separate autonomous systems (ISPs, large organizations) to exchange routing info on the internet. Not for assigning IPs or backups or broadband specifically.",
      "examTip": "BGP essentially makes the internet possible by interconnecting ASes."
    },
    {
      "id": 87,
      "question": "Which is a fundamental difference between symmetric and asymmetric encryption?",
      "options": [
        "Symmetric uses one shared key; asymmetric uses a public/private key pair.",
        "Asymmetric is faster than symmetric.",
        "Symmetric can only be used for data at rest; asymmetric is only for data in motion.",
        "They are the same; just different names."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Symmetric encryption uses the same key to encrypt and decrypt. Asymmetric uses a public key for encryption and a private key for decryption. Asymmetric is typically slower. They can be used for data at rest or in motion.",
      "examTip": "Symmetric is fast but needs secure key exchange. Asymmetric solves key exchange but is slower."
    },
    {
      "id": 88,
      "question": "A network administrator notices sluggish performance. They suspect a particular application is hogging bandwidth. Which tool is best to confirm and see how much traffic that app uses?",
      "options": [
        "A cable tester.",
        "A toner/probe kit.",
        "A protocol analyzer (like Wireshark) or a network monitoring solution that supports application-layer visibility.",
        "The ping command."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A protocol analyzer can capture and identify traffic flows per application/protocol. A cable tester checks wiring, toner/probe locates cables, and ping only tests basic connectivity/latency, not app bandwidth usage.",
      "examTip": "Use a packet capture or monitoring tool to see exactly what’s eating bandwidth."
    },
    {
      "id": 89,
      "question": "Which is a known security risk when enabling WPS (Wi-Fi Protected Setup)?",
      "options": [
        "It forces WPA3 encryption, which some older devices don’t support.",
        "It eliminates the need for a passphrase entirely.",
        "The PIN can be brute-forced, allowing attackers to gain network access.",
        "It disables encryption on the network."
      ],
      "correctAnswerIndex": 2,
      "explanation": "WPS PIN mode can be brute-forced easily. This is a major vulnerability. WPS doesn’t disable encryption or force WPA3. Nor does it remove the passphrase entirely in normal mode. But the brute-force vulnerability is well-known.",
      "examTip": "Disable WPS to avoid the PIN brute-force attack vector."
    },
    {
      "id": 90,
      "question": "What is ‘latency’ in network communications?",
      "options": [
        "A measure of available bandwidth.",
        "A measure of data security.",
        "The time delay for data to travel from source to destination, often measured in milliseconds.",
        "The number of connected devices on a subnet."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Latency is the delay between sending data and the receiver getting it. High latency can hurt real-time apps like voice or gaming. Bandwidth is capacity, not the same as latency.",
      "examTip": "Latency is often referred to as ‘ping time’ in casual terms."
    },
    {
      "id": 91,
      "question": "What is a virtual machine (VM)?",
      "options": [
        "A physical server with multiple CPUs.",
        "A software-based emulation of a computer system that runs on a host’s hardware, enabling multiple OSes/applications to share a single physical machine.",
        "A new type of network cable standard.",
        "An advanced firewall."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A VM is a software simulation of a computer. It runs on a hypervisor or host OS, and each VM sees a ‘virtual’ hardware environment. It’s not a cable or firewall.",
      "examTip": "Virtualization is key for efficient resource utilization and cloud deployments."
    },
    {
      "id": 92,
      "question": "Which is a major benefit of ‘infrastructure as code’ (IaC)?",
      "options": [
        "It removes the need for any human oversight or network engineers.",
        "It allows you to define servers, networks, and configurations in code, which you can version-control, test, and automate for consistency and repeatability.",
        "It’s only suitable for very small environments.",
        "It inherently encrypts all network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "IaC uses code-like definitions for infrastructure. This means you can track changes in version control, quickly deploy or roll back, and keep everything consistent. It doesn’t replace humans; it’s not only for small setups and doesn’t automatically encrypt traffic.",
      "examTip": "IaC is central to DevOps, enabling fully automated provisioning."
    },
    {
      "id": 93,
      "question": "What does a cable tester do?",
      "options": [
        "Measures bandwidth usage.",
        "Identifies the physical path of a cable through walls (toning).",
        "Tests the continuity, pin-out, and general integrity of a cable, detecting opens, shorts, or miswires.",
        "Captures and analyzes traffic at the packet level."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Cable testers send signals along each wire in the cable, checking for correct wiring (pin-out), breaks, or shorts. They don’t measure bandwidth or capture traffic, and a toner/probe is for tracing cables in walls.",
      "examTip": "Use a cable tester to confirm physical-layer health of network cabling."
    },
    {
      "id": 94,
      "question": "Why is using outdated or unpatched operating systems a security risk?",
      "options": [
        "They run faster and thus attract hackers.",
        "They are more stable.",
        "They contain known vulnerabilities that attackers can exploit, since no patches are applied.",
        "They automatically backup data to the cloud, bypassing encryption."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Outdated OSes have unpatched security holes. Attackers know about these vulnerabilities. They are not necessarily faster or more stable and do not automatically do cloud backups.",
      "examTip": "Always patch and update to protect against known exploits."
    },
    {
      "id": 95,
      "question": "Which best describes two-factor authentication (2FA)?",
      "options": [
        "Using two passwords on the same account.",
        "Reusing the same password for multiple accounts.",
        "Requiring two distinct forms of identification (like something you know + something you have) to log in.",
        "Encryption of passwords in transit."
      ],
      "correctAnswerIndex": 2,
      "explanation": "2FA means a user must supply two different factors, e.g. password + phone token, password + biometric, etc. Not just two passwords or reusing the same password. Encryption is separate.",
      "examTip": "2FA significantly increases account security."
    },
    {
      "id": 96,
      "question": "Which of the following describes the Domain Name System (DNS)?",
      "options": [
        "It dynamically assigns IP addresses to devices (DHCP).",
        "It maps user-friendly domain names (e.g., example.com) to IP addresses, and can also perform reverse lookups.",
        "It encrypts all network traffic end-to-end.",
        "It manages bridging loops on switches (STP)."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DNS resolves domain names into IPs and vice versa (reverse DNS). DHCP assigns IPs, encryption is done by protocols like TLS, and STP prevents loops. DNS is basically the ‘internet phone book.’",
      "examTip": "DNS is critical for easy navigation of the internet by hostnames."
    },
    {
      "id": 97,
      "question": "What is the primary function of a firewall?",
      "options": [
        "To assign IP addresses to devices.",
        "To store user credentials and manage authentication (like an LDAP server).",
        "To monitor and control inbound/outbound traffic based on security rules, acting as a barrier between trusted and untrusted networks.",
        "To physically secure a data center."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Firewalls examine network traffic and apply rules to permit or deny traffic. They don’t assign IPs (DHCP does), store user credentials (directory servers do), or handle physical security.",
      "examTip": "Firewalls enforce the security policy on network traffic flows."
    },
    {
      "id": 98,
      "question": "What can happen during a broadcast storm on a network?",
      "options": [
        "Network performance degrades severely or the entire network can crash due to excessive broadcast traffic.",
        "All traffic is encrypted automatically.",
        "It speeds up certain data transfers.",
        "Nothing; broadcast storms are harmless."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Broadcast storms overwhelm the network, consuming bandwidth and device resources, sometimes causing total failure. They definitely do not encrypt traffic or improve speed, and they’re far from harmless.",
      "examTip": "Prevent broadcast storms with proper switch configuration and STP."
    },
    {
      "id": 99,
      "question": "What is the purpose of ‘port forwarding’ on a router?",
      "options": [
        "To hide all internal devices from the internet.",
        "To allow devices on the LAN to connect to external websites via a proxy.",
        "To map an external port to an internal host and port, so services on the LAN can be accessed from the internet.",
        "To dynamically assign IP addresses to internal hosts."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Port forwarding (a.k.a. NAT port mapping) allows external requests on a specific port to reach an internal server on that port (or a different one). It doesn’t hide everything or assign IPs. It’s not a simple proxy either.",
      "examTip": "Use port forwarding to host internal services on the public internet."
    },
    {
      "id": 100,
      "question": "Given an ACL with `access-list 105 permit tcp any any eq 22` and `access-list 105 deny ip any any`, applied inbound on a router interface, which traffic is permitted?",
      "options": [
        "All IP traffic is allowed.",
        "Only TCP traffic on port 22 (SSH) from any source to any destination.",
        "No traffic is allowed at all.",
        "All traffic except SSH."
      ],
      "correctAnswerIndex": 1,
      "explanation": "This ACL explicitly permits TCP traffic on port 22 (SSH). All other IP traffic is denied by the second statement. Hence, only SSH is allowed.",
      "examTip": "Always consider the implicit or explicit denies at the end of an ACL."
    }
  ]
});
