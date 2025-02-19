db.tests.insertOne({
  "category": "nplus",
  "testId": 5,
  "testName": "Network+ Practice Test #5 (Intermediate)", 
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A user reports intermittent connectivity to a specific website. You can ping the website's IP address consistently, but `tracert` shows varying paths and occasional packet loss. What is the MOST likely cause?",
      "options": [
        "A software or configuration issue with the user's local network adapter causing it to not function consistently and reliably.",
        "A problem with the DNS resolution process for the website's domain name on the authoritative DNS server.",
        "Network congestion or instability along the path to the website's server.",
        "A misconfiguration in the firewall rules on the user's computer affecting outbound network traffic."  
      ],
      "correctAnswerIndex": 2,
      "explanation": "Consistent pings to the IP address rule out a *local* adapter or firewall issue, and successful pings also rule out a *complete* DNS failure.  Varying `tracert` paths and packet loss indicate a problem *between* the user and the website's server, most likely network congestion or an unstable route.",
      "examTip": "Use `tracert` to diagnose path-related network issues, not just complete failures."
    },
    {
      "id": 2,
      "question": "You are configuring a new switch and need to implement VLANs.  Which protocol is used to tag Ethernet frames with VLAN membership information?",
      "options": [
        "The Spanning Tree Protocol (STP) which is used to create a logical topology and prevent network loops in switched Ethernet networks.",
        "The VLAN Trunking Protocol (VTP) which is used to manage and propagate VLAN configuration information across multiple switches.",
        "802.1Q",
        "The Link Aggregation Control Protocol (LACP) which is used to bundle multiple physical ports together to create a single logical channel."
      ],
      "correctAnswerIndex": 2,
      "explanation": "802.1Q is the IEEE standard for VLAN tagging. It adds a tag to the Ethernet frame header that identifies the VLAN to which the frame belongs. STP prevents loops, VTP manages VLAN *databases* (not the tagging itself), and LACP is for link aggregation.",
      "examTip": "Remember 802.1Q as the standard for VLAN tagging."
    },
    {
      "id": 3, 
      "question": "You need to connect two buildings located 800 meters apart.  Performance is critical, and the environment has high levels of electromagnetic interference (EMI). Which cabling type is the BEST choice?",
      "options": [
        "Unshielded Twisted Pair (UTP) Category 6 cable which is commonly used for high-speed data networks and can support speeds up to 10 Gbps.",
        "Shielded Twisted Pair (STP) Category 6a cable which includes additional shielding to protect against electromagnetic interference (EMI).",
        "Multimode optical fiber cable which uses multiple light paths and is suitable for shorter distance applications up to a few hundred meters.", 
        "Single-mode Fiber"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Single-mode fiber is the best choice for long distances (800 meters exceeds multimode's typical range) and offers the highest bandwidth and complete immunity to EMI. UTP/STP are limited to 100 meters and susceptible to EMI. While multimode *could* reach, single-mode provides better performance and future-proofing.",
      "examTip": "Fiber optic cable is the best option for long distances and high-EMI environments."
    },
    {
      "id": 4,
      "question": "You are designing a network with multiple switches.  To prevent broadcast storms and ensure network stability, which protocol MUST be implemented?",
      "options": [
        "The Dynamic Host Configuration Protocol (DHCP) which is used to automatically assign IP addresses to devices on a network.",
        "The Domain Name System (DNS) protocol which is used to translate human-readable domain names into IP addresses.",
        "STP (Spanning Tree Protocol)",
        "The Address Resolution Protocol (ARP) which is used to map IP addresses to MAC addresses on a local network."
      ], 
      "correctAnswerIndex": 2,
      "explanation": "Spanning Tree Protocol (STP) is essential for preventing network loops in switched networks with redundant links. Loops can cause broadcast storms, which can cripple a network. DHCP assigns IP addresses, DNS resolves domain names, and ARP maps IPs to MAC addresses; none of these prevent loops.",
      "examTip": "STP is crucial for maintaining a stable switched network."
    },
    {
      "id": 5,
      "question": "A user complains that their VoIP calls are experiencing choppy audio and frequent drops.  Which network performance metric is MOST likely the cause?",
      "options": [
        "Insufficient network bandwidth capacity causing congestion and impacting the real-time transmission of VoIP data packets.",
        "High network latency or delay in the transmission of data packets between the source and destination.",
        "Jitter", 
        "Reduced data throughput rates on the network connection limiting the amount of VoIP data that can be transmitted per unit time."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Jitter is the variation in latency (delay) over time.  High jitter disrupts the consistent flow of data packets required for real-time applications like VoIP, causing choppy audio and dropped calls. Bandwidth is capacity, latency is overall delay, and throughput is the actual data transfer rate.",
      "examTip": "Monitor jitter when troubleshooting real-time application performance issues."
    },
    {
      "id": 6,
      "question": "You are configuring a router to connect your local network (192.168.1.0/24) to the internet. Your ISP has provided you with a single public IP address. Which technology MUST you use to allow multiple internal devices to share this public IP address?",
      "options": [
        "Implementing Virtual Local Area Networks (VLANs) to logically segment your network while using a single public IP address.",
        "Configuring the Dynamic Host Configuration Protocol (DHCP) server to assign private IP addresses to internal devices.",
        "NAT (Network Address Translation)",
        "Configuring the Domain Name System (DNS) server to translate internal hostnames to the public IP address."
      ],
      "correctAnswerIndex": 2,
      "explanation": "NAT translates private IP addresses (like 192.168.1.x) used within your local network to your single public IP address when communicating with the internet (and vice versa).  This conserves public IP addresses and provides a layer of security. VLANs segment networks, DHCP assigns IPs *locally*, and DNS resolves domain names.",
      "examTip": "NAT is essential for connecting private networks to the internet using a limited number of public IP addresses."  
    },
    {
      "id": 7,
      "question": "What is a characteristic of an 'ad hoc' wireless network?",
      "options": [
        "It requires the use of a central wireless access point (AP) to coordinate communication between wireless devices.",
        "It is a temporary, peer-to-peer connection between wireless devices, without a central access point.",
        "It provides robust security features by default, such as strong encryption and user authentication.",
        "It is commonly used for large-scale, enterprise-level wireless network deployments with many access points."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An ad hoc network is a decentralized wireless network where devices connect directly to each other without an access point. This is typically used for temporary connections, such as sharing files between two laptops. Ad hoc networks generally lack the security and management features of infrastructure-mode networks (which *do* use an AP).",
      "examTip": "Ad hoc networks are for temporary, peer-to-peer wireless connections."
    },
    {
      "id": 8,
      "question": "You are troubleshooting a network connectivity issue. You suspect a problem with the DNS server. Which command would you use on a Windows computer to clear the DNS resolver cache?",
      "options": [
        "The `ipconfig /release` command which is used to release the current IP address lease obtained from a DHCP server.",
        "The `ipconfig /renew` command which is used to request a new IP address lease from a DHCP server.",
        "ipconfig /flushdns",
        "The `ipconfig /all` command which is used to display detailed configuration information for all network adapters."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The `ipconfig /flushdns` command clears the local DNS resolver cache on a Windows computer. This forces the computer to query the DNS server again for name resolution, which can resolve issues caused by outdated or incorrect cached DNS entries. `/release` and `/renew` are for DHCP, and `/all` displays configuration.",
      "examTip": "Use `ipconfig /flushdns` to troubleshoot DNS resolution problems."
    },
    {
      "id": 9,
      "question": "Which of the following correctly describes the relationship between IP addresses and MAC addresses?",
      "options": [
        "IP addresses are hardware-assigned physical addresses used for communication within a local network segment, while MAC addresses are software-assigned logical addresses used for communication between different networks.",
        "IP addresses are used for communication within a local network segment at the data link layer (Layer 2), while MAC addresses are used for communication across different networks at the network layer (Layer 3).",
        "IP addresses are assigned dynamically by a DHCP server, while MAC addresses are statically assigned by a network administrator and cannot be changed.",
        "IP addresses are used for routing between networks (Layer 3); MAC addresses are used for communication within a local network segment (Layer 2)."  
      ],
      "correctAnswerIndex": 3,
      "explanation": "IP addresses are *logical* addresses used for routing data *between* networks (at the Network layer, Layer 3).  MAC addresses are *physical* addresses assigned to network interface cards and used for communication *within* a single network segment (at the Data Link layer, Layer 2).  While IP addresses *can* be static, they are often dynamic (DHCP). MAC addresses are *generally* static (though spoofing is possible).",
      "examTip": "IP addresses are for global routing; MAC addresses are for local delivery." 
    },
    {
      "id": 10,
      "question": "You are configuring a firewall.  Which type of firewall inspects the state of network connections (e.g., TCP sessions) and makes filtering decisions based on both packet headers and connection context?",
      "options": [
        "A packet filtering firewall which analyzes individual packets in isolation based on predefined rules, without considering the state of connections.",
        "Stateful inspection firewall",
        "A proxy firewall which acts as an intermediary between clients and servers, performing deep packet inspection and content filtering.",
        "An application-layer firewall which operates at Layer 7 of the OSI model and can understand application-specific protocols and data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Stateful inspection firewalls maintain a table of active connections and use this information to make more intelligent filtering decisions.  They can allow return traffic for established connections, providing better security than simple packet filters (which examine each packet in isolation). Proxy firewalls act as intermediaries, and application-layer firewalls inspect traffic at a higher level.",
      "examTip": "Stateful inspection provides more robust security than simple packet filtering."
    },
    {
      "id": 11,
      "question": "What is the purpose of using a 'subnet mask' in IP addressing?",
      "options": [
        "To encrypt network traffic between devices on different subnets to ensure data confidentiality and integrity.", 
        "To identify the network portion and the host portion of an IP address, enabling routing and subnetting.",
        "To automatically assign IP addresses to devices on a network without the need for manual configuration.",
        "To filter network traffic based on specific content or application types using deep packet inspection."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The subnet mask, used in conjunction with an IP address, defines which bits of the address represent the network and which bits represent the host. This is essential for determining whether two devices are on the same subnet and for routing traffic between networks.  It's *not* encryption, dynamic IP assignment (DHCP), or content filtering.",
      "examTip": "Subnet masks are fundamental to IP addressing and network segmentation."
    },
    {
      "id": 12,
      "question": "A small office network is experiencing slow performance.  The network uses a single, unmanaged hub to connect all devices.  What is the MOST likely cause of the slow performance, and what is the BEST solution?",
      "options": [
        "The internet connection bandwidth from the ISP is insufficient for the needs of the office and should be upgraded to a higher speed tier.",
        "The hub creates a single collision domain, causing frequent collisions and reducing efficiency; replace the hub with a switch.",
        "The network interface drivers on the connected computers are outdated and should be updated to the latest versions from the manufacturers.",
        "The total length of network cabling exceeds the maximum distance supported by Ethernet standards and should be shortened."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hubs operate at Layer 1 and broadcast all traffic to every connected device, creating a single collision domain. This leads to frequent collisions, especially as the number of devices increases, significantly degrading performance. Replacing the hub with a *switch* (which operates at Layer 2 and forwards traffic only to the intended recipient) is the best solution. While internet speed, drivers, or cable length *could* be issues, the hub is the *most likely* bottleneck in this scenario.",
      "examTip": "Replace hubs with switches for improved network performance and efficiency."
    },
    {
      "id": 13,
      "question": "What is the primary use of Quality of Service (QoS) in a network?",
      "options": [
        "To encrypt sensitive network traffic to ensure data confidentiality and integrity between communicating parties.",
        "To prioritize certain types of network traffic (e.g., voice, video) over others, ensuring critical applications receive adequate bandwidth and low latency.",
        "To automatically assign IP addresses to network devices using a centralized server to simplify address management.",
        "To translate human-readable domain names into IP addresses, allowing devices to locate and communicate with each other."
      ],
      "correctAnswerIndex": 1,
      "explanation": "QoS allows network administrators to manage network resources and ensure that time-sensitive or high-priority applications receive the necessary performance, even during periods of network congestion. It's *not* encryption, IP assignment (DHCP), or DNS.",
      "examTip": "QoS is crucial for delivering a good user experience for real-time applications like VoIP and video conferencing."
    },
    {
      "id": 14,
      "question": "Which of the following is a characteristic of a 'mesh' network topology?",
      "options": [
        "All devices in the network are connected to a central hub or switch, which acts as a single point of failure.",
        "Devices are connected in a circular loop, with data traveling in a single direction around the ring.",
        "Each device has multiple paths to other devices, providing high redundancy and fault tolerance.",
        "All devices are connected to a single, shared cable, which acts as a common communication medium."
      ], 
      "correctAnswerIndex": 2,
      "explanation": "Mesh networks offer excellent redundancy because each node is connected to multiple other nodes. If one link fails, traffic can be rerouted through alternative paths. This makes them highly resilient but also more complex to implement and manage.  Star uses a central device, ring uses a loop, and bus uses a single cable.",
      "examTip": "Mesh networks are often used in critical infrastructure where high availability is essential."
    },
    {
      "id": 15,
      "question": "What is the primary function of an 'intrusion prevention system' (IPS)?",
      "options": [
       "To automatically manage and distribute IP addresses across the network through a centralized DHCP service, ensuring efficient address allocation and preventing conflicts",
       "To actively monitor network traffic for malicious activity and take steps to block or prevent it.",
       "To implement advanced encryption protocols that secure all network traffic using industry-standard algorithms and certificate-based authentication",
       "To maintain a hierarchical database system that translates human-readable domain names into machine-readable IP addresses for network routing"
    ],
    "correctAnswerIndex": 1,
    "explanation": "An IPS goes beyond the *detection* capabilities of an IDS (Intrusion Detection System) by *actively* intervening to stop threats. It can drop malicious packets, reset connections, block traffic from specific sources, or even quarantine infected systems.  It's *not* about IP assignment, encryption, or DNS.",
    "examTip": "An IPS is a proactive security measure that can prevent attacks from succeeding."
},
{
  "id": 16,
  "question": "You are configuring a wireless network.  Which of the following provides the STRONGEST security?",
  "options": [
    "WEP (Wired Equivalent Privacy) with 128-bit encryption and dynamic key rotation implemented through enterprise authentication",
    "WPA (Wi-Fi Protected Access) with TKIP encryption and robust pre-shared key management with regular updates",
    "WPA2 (Wi-Fi Protected Access 2) with AES encryption",
    "WPA3 (Wi-Fi Protected Access 3)"
  ],
  "correctAnswerIndex": 3,
  "explanation": "WPA3 is the latest and most secure wireless security protocol, offering improved encryption and protection against attacks. WEP is extremely outdated and easily cracked. WPA is also vulnerable. WPA2 with AES is *better* than WPA and WEP, but WPA3 is *superior*.",
  "examTip": "Always use WPA3 if your devices and access point support it; otherwise, use WPA2 with AES."
},
{
  "id": 17,
  "question": "What is the purpose of a 'virtual private network' (VPN)?",
  "options": [
    "To optimize network performance through advanced traffic shaping algorithms and quality of service (QoS) implementations",
    "To create a secure, encrypted tunnel over a public network (like the internet), allowing remote users to access private network resources and protecting data from eavesdropping.",
    "To implement comprehensive firewall policies that control and filter all incoming and outgoing network traffic based on security rules",
    "To provide automated network configuration through dynamic host configuration protocols and centralized management systems"
  ],
  "correctAnswerIndex": 1,
  "explanation": "A VPN encrypts your internet traffic and routes it through a secure server, masking your IP address and protecting your data, especially on public Wi-Fi. It allows remote access to private networks as if you were directly connected. It doesn't primarily speed up connections, block all traffic, or assign IPs.",
  "examTip": "Use a VPN for secure remote access and to enhance your online privacy."
},
{
  "id": 18,
  "question": "What does 'MTU' stand for, and what does it define?",
  "options": [
    "Maximum Transfer Unit; the comprehensive routing protocol that determines optimal network paths based on dynamic bandwidth measurements",
    "Maximum Transmission Unit; the largest packet size that can be transmitted on a network without fragmentation.",
    "Minimum Transmission Unit; the threshold value that determines the smallest allowable data packet size for guaranteed network delivery",
    "Media Transfer Unit; the specialized hardware component responsible for converting between different network media types and protocols"
  ],
  "correctAnswerIndex": 1,
  "explanation": "MTU stands for Maximum Transmission Unit. It defines the largest data packet (in bytes) that can be transmitted over a network link without being fragmented. If a packet exceeds the MTU, it must be broken down into smaller fragments, which can impact performance.",
  "examTip": "An incorrect MTU setting can cause network performance problems."
},
{
  "id": 19,
  "question": "Which of the following is a potential consequence of having duplicate IP addresses on a network?",
  "options": [
    "Enhanced network security through redundant address verification and authentication protocols",
    "Optimized network performance through load balancing and automatic failover capabilities",
    "Network connectivity problems for the devices with the duplicate addresses, including intermittent connectivity or complete loss of communication.",
    "Improved bandwidth utilization through dynamic address sharing and resource allocation"
  ],
  "correctAnswerIndex": 2,
  "explanation": "Each device on a TCP/IP network must have a unique IP address. If two devices have the same IP address, it creates a conflict, and neither device may be able to communicate reliably on the network. This does *not* improve security or bandwidth or increase internet speeds.",
  "examTip": "Use DHCP to avoid duplicate IP address conflicts, or carefully manage static IP assignments."
},
{
  "id": 20,
  "question": "You are troubleshooting a computer that cannot connect to the network. The `ipconfig` command shows an IP address of 0.0.0.0. What does this indicate?",
  "options": [
    "The computer has been manually configured with a permanent static IP address for enhanced security",
    "The computer has successfully established a connection with the DHCP server and received proper network configuration",
    "The computer has failed to obtain an IP address and has no valid network configuration.",
    "The computer has established a direct connection to the internet through an automatic configuration protocol"
  ],
  "correctAnswerIndex": 2,
  "explanation": "An IP address of 0.0.0.0 indicates that the network interface has no valid IP address assigned. This usually means the computer failed to obtain an address from a DHCP server or has a problem with its network adapter configuration. It is *not* a static IP and doesn't indicate internet connectivity.",
  "examTip": "An IP address of 0.0.0.0 indicates a serious network configuration problem."
},
{
  "id": 21,
  "question": "Which of the following is a benefit of using fiber optic cable instead of copper cable?",
  "options": [
    "Fiber optic cable provides a more cost-effective solution with reduced installation and maintenance expenses over traditional cabling methods",
    "Fiber optic cable installation requires minimal technical expertise and can be completed with standard networking tools and basic training",
    "Fiber optic cable can transmit data over longer distances with less signal loss and is immune to electromagnetic interference (EMI).",
    "Fiber optic cable offers superior durability and resistance to physical damage, eliminating the need for protective conduits or special handling"
  ],
  "correctAnswerIndex": 2,
  "explanation": "Fiber optic cable uses light signals instead of electrical signals, providing significant advantages: much higher bandwidth, longer transmission distances, and immunity to EMI. However, it's generally *more* expensive and can be *more* complex to install and terminate than copper. While *some* types are rugged, fiber can be *more* susceptible to damage from bending/breaking than *some* copper types.",
  "examTip": "Fiber is the preferred choice for high-speed, long-distance, and EMI-prone environments."
},
{
  "id": 22,
  "question": "What is the purpose of using a DMZ in a network?",
  "options": [
    "To create a highly secure environment for storing sensitive internal data and critical business applications with multiple layers of encryption",
    "To establish a dedicated network segment for wireless devices with enhanced security protocols and access controls",
    "To host publicly accessible servers (like web servers or email servers) while providing a buffer zone between the internet and the internal network, improving security.",
    "To implement a redundant power distribution system that ensures continuous operation of critical network infrastructure during power failures"
  ],
  "correctAnswerIndex": 2,
  "explanation": "A DMZ is a network segment that sits between the trusted internal network and the untrusted external network (internet). It allows external users to access specific services (like web servers) without having direct access to the internal network, minimizing the risk of a successful attack compromising the entire internal network.",
  "examTip": "A DMZ is used to isolate publicly accessible servers from the internal network, enhancing security."
},
{
  "id": 23,
  "question": "What is a man-in-the-middle (MitM) attack?",
  "options": [
    "A sophisticated denial-of-service technique that floods network resources with specially crafted packets to disrupt service availability",
    "A social engineering method that uses psychological manipulation to extract sensitive information through elaborate deception schemes",
    "An attack where the attacker secretly intercepts and potentially alters communication between two parties who believe they are directly communicating with each other.",
    "A systematic approach to compromising network security through automated password generation and testing against authentication systems"
  ],
  "correctAnswerIndex": 2,
  "explanation": "In a MitM attack, the attacker positions themselves between two communicating parties, allowing them to eavesdrop on the conversation, steal data, or even modify the communication. It's *not* overwhelming traffic (DoS), tricking users (phishing), or password guessing (brute-force).",
  "examTip": "MitM attacks can be mitigated with strong encryption and secure protocols (like HTTPS)."
},
{
  "id": 24,
  "question": "What is the primary purpose of network address translation (NAT)?",
  "options": [
    "To implement end-to-end encryption protocols that secure all data transmissions across public and private networks",
    "To allow multiple devices on a private network to share a single public IP address when communicating with the internet, conserving IPv4 addresses.",
    "To provide automated IP address management through dynamic allocation and lease timing mechanisms",
    "To analyze and filter network traffic based on content patterns and security policies defined by administrators"
  ],
  "correctAnswerIndex": 1,
  "explanation": "NAT translates private IP addresses (used within a local network) to a public IP address (used on the internet), and vice versa. This allows many devices to share a single public IP, which is crucial given the limited number of available IPv4 addresses. It's not primarily for encryption, dynamic IP assignment (DHCP), or content filtering.",
  "examTip": "NAT is a fundamental technology for connecting private networks to the internet."
},
{
  "id": 25,
  "question": "Which of the following is a characteristic of a stateful firewall compared to a stateless packet filter?",
  "options": [
    "A stateful firewall processes individual packets in isolation without maintaining any connection history or context information",
    "A stateful firewall tracks the state of network connections and makes filtering decisions based on both packet headers and connection context; a stateless packet filter examines each packet in isolation.",
    "A stateful firewall provides basic security features with minimal resource requirements compared to more sophisticated stateless filters",
    "A stateful firewall specializes in securing wireless network communications through dedicated radio frequency monitoring"
  ],
  "correctAnswerIndex": 1,
  "explanation": "Stateful firewalls maintain a table of active connections and use this information to make more intelligent filtering decisions. They can distinguish between legitimate return traffic for an established connection and unsolicited incoming traffic, providing better security than stateless packet filters, which examine each packet independently without considering the connection context. Stateful firewalls are more secure and used in all types of networks.",
  "examTip": "Stateful firewalls offer more robust security by considering the context of network connections."
},
{
  "id": 26,
  "question": "What is the purpose of a proxy server?",
  "options": [
    "To automatically configure and manage IP address assignments for all network devices through centralized administration",
    "To act as an intermediary between clients and other servers, providing services like caching, filtering, and security, often improving performance and controlling access.",
    "To maintain a comprehensive database of domain names and their corresponding IP addresses for network routing",
    "To implement strong encryption protocols that protect all data transmissions between network endpoints"
  ],
  "correctAnswerIndex": 1,
  "explanation": "A proxy server sits between clients and other servers (often the internet). It can cache frequently accessed content (improving performance), filter web traffic (controlling access and enhancing security), and mask the client's IP address. It's not about IP assignment (DHCP), DNS, or general encryption (though proxies can be involved in SSL/TLS).",
  "examTip": "Proxy servers provide an additional layer of control, security, and performance optimization for network traffic."
},
{
  "id": 27,
  "question": "Which type of network device is used to create a wireless local area network (WLAN)?",
  "options": [
    "A high-performance network switch with dedicated virtual LAN capabilities and advanced traffic management",
    "A sophisticated routing device that manages traffic between different network segments with quality of service controls",
    "Access Point (AP)",
    "A specialized network interface that converts digital signals for transmission over telephone lines"
  ],
  "correctAnswerIndex": 2,
  "explanation": "An access point (AP) provides wireless connectivity to devices, allowing them to join a network (typically a wired network connected to the AP). Switches connect wired devices, routers connect networks, and modems connect to an ISP.",
  "examTip": "Access points are the foundation of Wi-Fi networks."
},
{
  "id": 28,
  "question": "You are configuring a new network interface card (NIC) on a server. You need to ensure it operates at the fastest possible speed and allows simultaneous sending and receiving of data. What settings should you configure?",
  "options": [
    "Configure the interface for 10 Mbps operation with half-duplex mode to ensure stable and reliable network communications",
    "Set the interface to operate at 100 Mbps with half-duplex transmission for optimal data handling",
    "1000 Mbps (Gigabit), Full-duplex",
    "Enable auto-negotiation with half-duplex mode to automatically determine the best connection parameters"
  ],
  "correctAnswerIndex": 2,
  "explanation": "For the fastest speed and simultaneous send/receive, you should choose 1000 Mbps (Gigabit Ethernet) and Full-duplex. Auto-negotiate is generally recommended, but only if you're certain the connected device also supports and is configured for auto-negotiation. For a server NIC, explicitly setting it is often preferred for reliability.",
  "examTip": "For optimal performance, use Gigabit Ethernet and Full-duplex whenever possible."
},
{
  "id": 29,
  "question": "What is the purpose of the `ping` command?",
  "options": [
    "To display and manage detailed routing table entries for optimal network path selection",
    "To test network connectivity to a remote host and measure round-trip time.",
    "To provide comprehensive information about network interface configurations and status",
    "To perform advanced DNS lookups and verify proper name resolution across the network"
  ],
  "correctAnswerIndex": 1,
  "explanation": "`ping` sends ICMP Echo Request packets to a target host and listens for Echo Reply packets. This tests basic connectivity and measures the time it takes for packets to travel to the host and back. It's not for displaying routing tables, interface configurations, or querying DNS.",
  "examTip": "`ping` is a fundamental tool for network troubleshooting."
},
{
  "id": 30,
  "question": "What does DNS stand for, and what is its primary function?",
  "options": [
    "Dynamic Network System; to automatically configure and optimize network settings for improved performance",
    "Domain Name System; to translate human-readable domain names (like google.com) into numerical IP addresses.",
    "Data Network Security; to implement comprehensive security protocols protecting network communications",
    "Digital Network Service; to manage and control access to various internet services and resources"
  ],
  "correctAnswerIndex": 1,
  "explanation": "DNS (Domain Name System) is like the internet's phone book. It translates the website names we use (e.g., google.com) into the IP addresses that computers use to communicate. It's not about dynamic IP assignment (DHCP), security, or providing internet access.",
  "examTip": "Without DNS, we'd have to remember IP addresses instead of website names."
},
    {
      "id": 31,
      "question": "A user reports they cannot access any websites. You check their computer and find they have a valid IP address, subnet mask, and default gateway. What is the NEXT troubleshooting step you should take?",
      "options": [
        "Reinstall the user’s web browser to rule out application errors.",
        "Verify the DNS settings and test resolution using tools such as nslookup or ping.",
        "Replace the Ethernet cable to rule out any physical connectivity fault.",
        "Reboot the computer to refresh the system and clear temporary issues."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Since the user’s IP configuration is valid, the issue is likely with name resolution. Checking the DNS settings is the next logical step.",
      "examTip": "After confirming IP connectivity, test DNS resolution when websites aren’t reachable by name."
    },
    {
      "id": 32,
      "question": "Which of the following is a characteristic of a virtual LAN (VLAN)?",
      "options": [
        "It mandates the use of separate physical switches for each VLAN.",
        "It logically divides a single physical network into isolated broadcast domains even on the same switch.",
        "It enlarges the broadcast domain, contrary to its actual purpose.",
        "It is designed primarily to manage wireless network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "VLANs logically segment a physical network into separate broadcast domains, even if devices share the same hardware.",
      "examTip": "VLANs are key for network segmentation, reducing broadcast domains and enhancing security."
    },
    {
      "id": 33,
      "question": "What is jitter in network performance?",
      "options": [
        "It signifies the total data capacity available on a network link.",
        "It indicates the fixed time delay that every packet experiences during transmission.",
        "It reflects the variation in delay between packets, which can disrupt real-time applications like VoIP.",
        "It counts the number of devices connected to the network at any moment."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Jitter is the inconsistency in latency from packet to packet, which can affect applications sensitive to timing.",
      "examTip": "Monitor jitter to troubleshoot issues in real-time applications such as voice and video calls."
    },
    {
      "id": 34,
      "question": "What is latency in network performance?",
      "options": [
        "It refers to the maximum data throughput achievable over the connection.",
        "It is the time delay in data transmission from source to destination.",
        "It represents the number of devices concurrently using the network.",
        "It describes the physical distance between two network devices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Latency is the time a packet takes to travel from its source to its destination. High latency results in noticeable delays.",
      "examTip": "Low latency is essential for applications that require real-time interaction."
    },
    {
      "id": 35,
      "question": "Which of the following is a security best practice for managing network devices?",
      "options": [
        "Retaining default usernames and passwords as supplied by the manufacturer.",
        "Keeping firewall ports open to allow unrestricted traffic.",
        "Regularly updating firmware and disabling nonessential services to reduce vulnerabilities.",
        "Sharing administrative passwords among all staff to ease management."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Updating firmware and disabling unnecessary services reduces vulnerabilities and minimizes the attack surface.",
      "examTip": "Regular firmware updates and service minimization are critical for network device security."
    },
    {
      "id": 36,
      "question": "What is the purpose of network documentation?",
      "options": [
        "To boost network performance by optimizing data paths.",
        "To serve as a detailed record of network design, configuration, and operations for troubleshooting and planning.",
        "To replace technical security measures by providing an overall system overview.",
        "To block user access to external websites solely by policy."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Proper documentation of the network’s design, configurations, and procedures is essential for troubleshooting and future planning.",
      "examTip": "Keep thorough, up-to-date documentation to simplify maintenance and troubleshooting."
    },
    {
      "id": 37,
      "question": "What is a default gateway in a TCP/IP network configuration?",
      "options": [
        "It denotes the IP address of the DNS server used for name resolution.",
        "It represents the IP address of the router that sends traffic outside the local subnet.",
        "It shows the MAC address of the computer's network interface.",
        "It defines the subnet mask for the local network segment."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The default gateway is the router that forwards traffic from the local network to destinations beyond it.",
      "examTip": "Ensure each device has the correct default gateway to enable communication outside its local network."
    },
    {
      "id": 38,
      "question": "Which of the following is a common use for a virtual private network (VPN)?",
      "options": [
        "To improve your internet connection speed by optimizing routing paths.",
        "To securely connect to a private network over a public network, encrypting data in transit.",
        "To completely block both incoming and outgoing traffic.",
        "To automatically assign IP addresses to all devices on a network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A VPN creates an encrypted tunnel to securely connect remote users to a private network over the internet.",
      "examTip": "Use a VPN to safeguard sensitive data when accessing corporate resources remotely."
    },
    {
      "id": 39,
      "question": "What is a denial-of-service (DoS) attack?",
      "options": [
        "It involves stealing user passwords through repeated guessing.",
        "It floods a network or server with traffic from a single source, making it unavailable.",
        "It deceives users into disclosing personal information via social tactics.",
        "It gains unauthorized access by systematically guessing account credentials."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DoS attack overwhelms a target with traffic from one source, causing service disruption.",
      "examTip": "DoS attacks typically originate from one location, unlike DDoS attacks which are distributed."
    },
    {
      "id": 40,
      "question": "Which of the following is a potential security risk associated with using default usernames and passwords on network devices (routers, switches, access points)?",
      "options": [
        "They inherently enhance network security.",
        "They simplify administration without drawbacks.",
        "They allow attackers to gain easy unauthorized access using publicly known credentials.",
        "They improve the overall performance of the device."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Default credentials are well-known and can be exploited by attackers, making them a significant security risk.",
      "examTip": "Change default usernames and passwords immediately after device installation."
    },
    {
      "id": 41,
      "question": "Which command-line tool is used to display the ARP cache on a Windows system?",
      "options": [
        "ipconfig /all displays overall network settings.",
        "arp -a shows the ARP cache with IP-to-MAC mappings.",
        "netstat -r lists routing information but not ARP data.",
        "route print outputs the routing table only."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The command 'arp -a' lists the ARP cache, which contains the mappings between IP addresses and MAC addresses learned by the computer.",
      "examTip": "Viewing the ARP cache can help diagnose local network communication issues."
    },
    {
      "id": 42,
      "question": "Which of the following best describes a honeypot in the context of cybersecurity?",
      "options": [
        "A secure server designed solely to store critical data.",
        "A decoy system intended to attract and trap attackers for analysis.",
        "A specialized firewall that blocks all incoming traffic.",
        "A tool that encrypts network traffic for confidentiality."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A honeypot is set up as a decoy to lure attackers, allowing security teams to observe attack methods.",
      "examTip": "Honeypots help organizations learn how attackers operate and improve security defenses."
    },
    {
      "id": 43,
      "question": "Which of the following best describes social engineering in cybersecurity?",
      "options": [
        "It involves developing and managing a social media network.",
        "It refers to manipulating individuals to divulge sensitive information through deceptive tactics.",
        "It is the use of social media platforms for marketing purposes.",
        "It describes professional networking at industry events."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Social engineering uses deception to trick people into revealing confidential information or compromising security.",
      "examTip": "Always be cautious of unsolicited requests for sensitive information."
    },
    {
      "id": 44,
      "question": "What does encryption do to data?",
      "options": [
        "It enlarges data and makes it easier to read, which is false.",
        "It converts data into an unreadable format (ciphertext) that requires a decryption key to revert.",
        "It permanently deletes data from a device.",
        "It organizes data into structured folders and files."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption scrambles data into a ciphertext that is unintelligible without the correct decryption key.",
      "examTip": "Encryption is vital for keeping sensitive data confidential during storage and transmission."
    },
    {
      "id": 45,
      "question": "Which of the following is a key characteristic of cloud computing?",
      "options": [
        "All computing resources are maintained on-premises within the organization.",
        "It provides on-demand access to shared computing resources over the internet with scalability and cost benefits.",
        "It requires a substantial initial investment in physical hardware.",
        "It offers limited scalability and flexibility compared to traditional systems."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Cloud computing allows on-demand, scalable, and flexible access to computing resources over the internet with a pay-as-you-go model.",
      "examTip": "Cloud computing is popular for its scalability and cost efficiency."
    },
    {
      "id": 46,
      "question": "You are setting up a network and need to ensure that a specific server always receives the same IP address from the DHCP server. What DHCP feature should you use?",
      "options": [
        "DHCP scope, which defines the pool of available addresses.",
        "DHCP reservation (or static mapping), which binds a specific MAC address to a fixed IP address.",
        "DHCP exclusion, which prevents certain addresses from being assigned.",
        "DHCP lease time, which controls how long an address is valid."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DHCP reservation ensures that a device always gets the same IP address by binding its MAC address to a specific IP.",
      "examTip": "Use DHCP reservations for devices that require a fixed IP address."
    },
    {
      "id": 47,
      "question": "Which command-line tool is commonly used to test network connectivity to a remote host and measure round-trip time?",
      "options": [
        "tracert (or traceroute) shows the network path taken.",
        "ping sends ICMP echo requests and measures round-trip time.",
        "ipconfig displays local IP configuration.",
        "nslookup resolves domain names to IP addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The ping command tests connectivity by sending ICMP echo requests and timing the replies, indicating latency.",
      "examTip": "Ping is a fundamental tool for checking connectivity and measuring response times."
    },
    {
      "id": 48,
      "question": "What is a honeypot in the context of cybersecurity?",
      "options": [
        "A secure server used for storing confidential information.",
        "A decoy system designed to attract attackers so their methods can be analyzed.",
        "A type of firewall that blocks malicious traffic.",
        "A tool that encrypts data before transmission."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A honeypot is a purposely vulnerable system that serves as a trap to lure attackers and study their behavior.",
      "examTip": "Honeypots can provide valuable insights into attacker techniques."
    },
    {
      "id": 49,
      "question": "Which of the following best describes social engineering in cybersecurity?",
      "options": [
        "It involves creating and managing a social media platform.",
        "It refers to manipulating individuals into revealing confidential information through deception.",
        "It is the process of using social media for corporate marketing.",
        "It means meeting professionals at industry conferences."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Social engineering exploits human psychology to trick people into divulging sensitive information.",
      "examTip": "Always scrutinize requests for sensitive information, especially if they seem unusual."
    },
    {
      "id": 50,
      "question": "What does encryption do to data?",
      "options": [
        "It increases the size of data and makes it easier to interpret, which is incorrect.",
        "It converts data into an unreadable format (ciphertext) that can only be deciphered with the correct key.",
        "It permanently erases data from storage.",
        "It sorts data into organized directories for ease of use."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption scrambles data into a secure format that is indecipherable without the appropriate decryption key.",
      "examTip": "Encryption is essential for ensuring that sensitive data remains confidential."
    },
    {
      "id": 51,
      "question": "Which of the following is a key characteristic of cloud computing?",
      "options": [
        "All resources are kept in on-premises data centers.",
        "It offers on-demand, scalable access to shared computing resources over the internet.",
        "It requires large, upfront capital expenditures for hardware.",
        "It provides limited flexibility and scalability."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Cloud computing provides on-demand access to computing resources with scalability and flexibility via an internet connection.",
      "examTip": "Cloud computing is known for its agility and cost-effective scalability."
    },
    {
      "id": 52,
      "question": "You are setting up a network and need to ensure that a specific server always receives the same IP address from the DHCP server. What DHCP feature should you use?",
      "options": [
        "DHCP scope, which defines the range of assignable IP addresses.",
        "DHCP reservation (or static mapping), which binds a device's MAC address to a specific IP.",
        "DHCP exclusion, which removes certain addresses from the pool.",
        "DHCP lease time, which controls how long an address is assigned."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DHCP reservation guarantees that a device always gets the same IP address by linking its MAC address with a fixed IP.",
      "examTip": "Use DHCP reservations for devices that require a consistent IP configuration."
    },
    {
      "id": 53,
      "question": "Which command-line tool is used to display the current routing table on a Windows computer?",
      "options": [
        "ipconfig /all displays full interface details.",
        "arp -a shows the ARP cache mappings.",
        "netstat -r provides routing information in a brief format.",
        "route print displays the complete routing table."
      ],
      "correctAnswerIndex": 3,
      "explanation": "The command 'route print' displays the entire routing table, indicating how packets are forwarded to various networks.",
      "examTip": "Use 'route print' to review the routing table when troubleshooting connectivity issues."
    },
    {
      "id": 54,
      "question": "What is a potential consequence of a broadcast storm on a network?",
      "options": [
        "Enhanced network security, which is not the case.",
        "An increase in available bandwidth, which does not occur.",
        "Severe performance degradation or network outage due to excessive broadcast traffic.",
        "Faster data transfer speeds, which is not true."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A broadcast storm can overwhelm network devices with excessive traffic, leading to significant performance issues or even complete network failure.",
      "examTip": "Design networks with proper segmentation and protocols like STP to prevent broadcast storms."
    },
    {
      "id": 55,
      "question": "What is the primary purpose of using a virtual LAN (VLAN) in a switched network?",
      "options": [
        "To increase the overall network bandwidth by aggregating links.",
        "To logically segment a physical network into separate broadcast domains for improved security and performance.",
        "To provide wireless access to users without cables.",
        "To encrypt traffic between devices on the same network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "VLANs logically divide a single physical network into multiple isolated segments, reducing broadcast domains and enhancing security and performance.",
      "examTip": "VLANs are a key method for segmenting and securing network traffic in switched environments."
    },
    {
      "id": 56,
      "question": "What is the purpose of a default gateway in a TCP/IP network configuration?",
      "options": [
        "It provides wireless connectivity to the network.",
        "It translates domain names into IP addresses.",
        "It serves as the route for traffic leaving the local subnet, typically the IP address of a router.",
        "It encrypts data before it leaves the network."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The default gateway is the router that a device uses to send traffic to destinations outside its local subnet.",
      "examTip": "Make sure every device has the correct default gateway configured to enable external communications."
    },
    {
      "id": 57,
      "question": "Which type of network device operates at Layer 2 (the Data Link layer) of the OSI model and makes forwarding decisions based on MAC addresses?",
      "options": [
        "Hub, which simply repeats signals without filtering.",
        "Switch, which learns MAC addresses and forwards frames accordingly.",
        "Router, which operates at Layer 3 to route packets between networks.",
        "Repeater, which only amplifies signals."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Switches operate at Layer 2 by learning MAC addresses and using them to forward traffic only to the intended destination.",
      "examTip": "Switches are essential for efficient LAN operation by reducing unnecessary traffic."
    },
    {
      "id": 58,
      "question": "What is Power over Ethernet (PoE)?",
      "options": [
        "A specific type of network cable designed only for power transmission.",
        "A technology that allows network cables to carry both data and electrical power simultaneously.",
        "A protocol that encrypts all data transmitted over Ethernet cables.",
        "A system for dynamically assigning IP addresses to PoE-enabled devices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "PoE enables both data and electrical power to be carried over standard Ethernet cables, simplifying device installation.",
      "examTip": "PoE is commonly used to power devices such as IP cameras and wireless access points without separate power supplies."
    },
    {
      "id": 59,
      "question": "What is the purpose of the traceroute (or tracert) command?",
      "options": [
        "To test the overall speed of a network connection.",
        "To display the IP address of a website.",
        "To trace the path that packets take to reach a destination, showing each hop and its response time.",
        "To configure a network interface automatically."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Traceroute (or tracert) displays the path packets take through the network and shows the time taken for each hop, helping diagnose routing issues.",
      "examTip": "Use traceroute to identify where delays or losses occur in the network path."
    },
    {
      "id": 60,
      "question": "Which command is used on a Windows computer to release and renew a DHCP-assigned IP address?",
      "options": [
        "ipconfig /all, which displays full interface details.",
        "ipconfig /release followed by ipconfig /renew to reset the DHCP lease.",
        "ipconfig /flushdns, which clears the DNS cache.",
        "netstat -r, which shows routing information."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Using 'ipconfig /release' followed by 'ipconfig /renew' will release the current DHCP lease and request a new IP address from the DHCP server.",
      "examTip": "These commands are useful for resolving DHCP-related connectivity issues."
    },
    {
      "id": 61,
      "question": "A user reports being unable to access a specific network share. You can ping the file server by IP address, and other users can access the share. What is the MOST likely cause?",
      "options": [
        "The file server is completely down.",
        "The network cable is unplugged from the user’s computer.",
        "A permissions issue on the share preventing the user’s access.",
        "A problem with the DNS server, affecting name resolution."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Since the server is reachable and others can access the share, the issue is most likely related to user-specific permissions.",
      "examTip": "After confirming connectivity, check user permissions when access to a resource is denied."
    },
    {
      "id": 62,
      "question": "What is the primary purpose of a firewall in network security?",
      "options": [
        "To increase the speed of your internet connection.",
        "To control traffic by allowing or blocking data based on security rules between trusted and untrusted networks.",
        "To assign IP addresses dynamically using DHCP.",
        "To translate domain names into IP addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A firewall enforces security policies by filtering traffic between networks, thereby preventing unauthorized access.",
      "examTip": "Firewalls are a critical first line of defense in network security."
    },
    {
      "id": 63,
      "question": "Which of the following best describes SSID in wireless networking?",
      "options": [
        "Secure System Identifier.",
        "Service Set Identifier.",
        "System Security ID.",
        "Simple Service ID."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SSID stands for Service Set Identifier and is the name broadcast by a wireless network.",
      "examTip": "The SSID is the public name used to identify a Wi-Fi network."
    },
    {
      "id": 64,
      "question": "Which of the following is a characteristic of a mesh network topology?",
      "options": [
        "All devices connect to a central hub.",
        "Devices are arranged in a simple loop.",
        "Each device has multiple paths to others, providing high redundancy.",
        "All devices share a single common cable."
      ],
      "correctAnswerIndex": 2,
      "explanation": "In a mesh network, each node connects to several others, creating multiple redundant paths and enhancing fault tolerance.",
      "examTip": "Mesh topologies offer robust redundancy but can be complex to manage."
    },
    {
      "id": 65,
      "question": "You are troubleshooting a slow network. You use a protocol analyzer and notice a large number of TCP retransmissions. What does this MOST likely indicate?",
      "options": [
        "The network is secure and encryption is working properly.",
        "Packet loss or network congestion causing repeated data resends.",
        "The DNS server is not responding, delaying name resolution.",
        "The DHCP server is failing to assign IP addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "TCP retransmissions are usually a sign of packet loss or congestion, requiring data to be resent.",
      "examTip": "A high volume of TCP retransmissions typically signals underlying network performance issues."
    },
    {
      "id": 66,
      "question": "What is the purpose of subnetting an IP network?",
      "options": [
        "To increase the overall number of IP addresses available.",
        "To divide a network into smaller subnetworks, improving security, performance, and management.",
        "To encrypt network traffic between subnets.",
        "To intentionally expose the network to more risk."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Subnetting breaks a larger network into smaller segments, which can reduce broadcast traffic and enhance security and manageability.",
      "examTip": "Subnetting is a key method for organizing and securing IP networks."
    },
    {
      "id": 67,
      "question": "What is the primary purpose of network address translation (NAT)?",
      "options": [
        "To encrypt network traffic between devices.",
        "To conserve public IPv4 addresses by allowing multiple private addresses to share a public IP.",
        "To dynamically assign IP addresses using DHCP.",
        "To prevent network loops by modifying routing paths."
      ],
      "correctAnswerIndex": 1,
      "explanation": "NAT translates private IP addresses to a public IP address (and vice versa) so that many devices can share one public IP, conserving IPv4 space.",
      "examTip": "NAT is essential for connecting a private network to the internet while conserving IP addresses."
    },
    {
      "id": 68,
      "question": "Which of the following is a security best practice for managing network devices?",
      "options": [
        "Using default usernames and passwords, which is insecure.",
        "Leaving all firewall ports open for maximum connectivity.",
        "Regularly updating firmware and disabling unnecessary services to limit vulnerabilities.",
        "Sharing administrative credentials among all users for convenience."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Updating firmware and disabling unnecessary services reduces the risk of security vulnerabilities on network devices.",
      "examTip": "Always secure network devices by keeping them updated and minimizing their attack surface."
    },
    {
      "id": 69,
      "question": "What is the purpose of network documentation?",
      "options": [
        "To improve network speed by optimizing traffic flow.",
        "To maintain a detailed record of the network’s design, configuration, and operations for troubleshooting and planning.",
        "To replace all network security measures with administrative records.",
        "To block users from accessing the internet through strict guidelines."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Network documentation provides critical details that help in troubleshooting, planning, and maintaining a network.",
      "examTip": "Keep thorough and current documentation to aid in network management."
    },
    {
      "id": 70,
      "question": "What is a default gateway in a TCP/IP network configuration?",
      "options": [
        "The IP address assigned to the DNS server.",
        "The IP address of the router used to send traffic to destinations beyond the local network.",
        "The physical MAC address of the computer’s network interface.",
        "The subnet mask defining the local network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The default gateway is the router that a device uses to send data to destinations outside its local subnet.",
      "examTip": "A properly configured default gateway is essential for external network communication."
    },
    {
      "id": 71,
      "question": "Which of the following is a common use for a virtual private network (VPN)?",
      "options": [
        "To boost your internet connection speed by optimizing routing.",
        "To securely connect to a private network over a public network, protecting data with encryption.",
        "To block both inbound and outbound traffic completely.",
        "To automatically assign IP addresses to client devices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A VPN creates an encrypted tunnel for secure remote access to a private network over the internet.",
      "examTip": "Use VPNs to protect sensitive data when accessing corporate networks from remote locations."
    },
    {
      "id": 72,
      "question": "Which type of network attack involves an attacker overwhelming a network or server with traffic from a single source?",
      "options": [
        "An attack aimed at stealing user passwords.",
        "An attack that floods a target with traffic from one source, causing service unavailability.",
        "An attack that deceives users into revealing confidential information.",
        "An attack that systematically guesses account credentials."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DoS attack floods a network or server with traffic from a single source, leading to denial of service for legitimate users.",
      "examTip": "DoS attacks are generally launched from a single location, unlike DDoS attacks which use multiple sources."
    },
    {
      "id": 73,
      "question": "Which of the following best describes the relationship between IP addresses and MAC addresses?",
      "options": [
        "IP addresses are physical identifiers; MAC addresses are logical.",
        "IP addresses are used within local networks; MAC addresses are used for routing across networks.",
        "IP addresses are typically dynamic while MAC addresses are manually assigned.",
        "IP addresses facilitate inter-network routing (Layer 3) while MAC addresses handle local delivery (Layer 2)."
      ],
      "correctAnswerIndex": 3,
      "explanation": "IP addresses are used for routing between networks (Layer 3) while MAC addresses operate at the data link layer (Layer 2) for local communications.",
      "examTip": "Remember that IP addresses are logical and used for routing, while MAC addresses are physical and used within the LAN."
    },
    {
      "id": 74,
      "question": "Which of the following is a potential security risk associated with using default usernames and passwords on network devices?",
      "options": [
        "They enhance network security by standardizing access.",
        "They simplify management but at the cost of potential exposure.",
        "They enable attackers to gain easy unauthorized access using well-known credentials.",
        "They improve performance by streamlining logins."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Default usernames and passwords are widely published and easily exploited by attackers, making them a serious security risk.",
      "examTip": "Always change default credentials immediately after installing network devices."
    },
    {
      "id": 75,
      "question": "Which command-line tool is used to display the ARP cache on a Windows system?",
      "options": [
        "ipconfig /all, which shows comprehensive interface details.",
        "arp -a, which lists the ARP cache with IP-to-MAC mappings.",
        "netstat -r, which displays routing information.",
        "route print, which outputs the routing table."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The 'arp -a' command displays the ARP cache containing the IP and MAC address mappings the system has learned.",
      "examTip": "Viewing the ARP cache helps diagnose local network communication issues."
    },
    {
      "id": 76,
      "question": "Which of the following best describes a honeypot in cybersecurity?",
      "options": [
        "A secure server dedicated to protecting sensitive data.",
        "A decoy system designed to lure attackers so that their methods can be analyzed.",
        "A firewall configured to block all unauthorized traffic.",
        "A tool that encrypts data before transmission to ensure confidentiality."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A honeypot is an intentionally vulnerable system used as a decoy to attract attackers for research purposes.",
      "examTip": "Honeypots provide valuable insights into attacker behavior and tactics."
    },
    {
      "id": 77,
      "question": "Which of the following best describes social engineering in cybersecurity?",
      "options": [
        "It involves designing and managing social media platforms for business.",
        "It entails deceiving individuals into divulging confidential information through manipulation or impersonation.",
        "It refers to using social networks for marketing and public relations.",
        "It means meeting with colleagues in professional gatherings."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Social engineering uses deception to trick individuals into giving up sensitive information or access credentials.",
      "examTip": "Always be cautious of unexpected requests for personal or confidential data."
    },
    {
      "id": 78,
      "question": "What does encryption do to data?",
      "options": [
        "It increases data size and improves readability, which is false.",
        "It transforms data into an unreadable format (ciphertext) that requires a key for decryption.",
        "It permanently deletes data from a storage device.",
        "It organizes data into a structured file system."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption converts data into ciphertext so that it remains secure and unreadable without the proper decryption key.",
      "examTip": "Encryption is critical for ensuring data confidentiality both in transit and at rest."
    },
    {
      "id": 79,
      "question": "Which of the following is a key characteristic of cloud computing?",
      "options": [
        "All computing resources are maintained on-premises.",
        "It offers on-demand access to shared resources over the internet with high scalability and flexibility.",
        "It requires a significant upfront investment in physical infrastructure.",
        "It provides limited scalability compared to traditional systems."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Cloud computing provides scalable, on-demand access to computing resources over the internet using a pay-as-you-go model.",
      "examTip": "Cloud computing is popular for its flexibility, scalability, and potential cost savings."
    },
    {
      "id": 80,
      "question": "What is the purpose of using DHCP reservation?",
      "options": [
        "A DHCP scope defines the range of addresses available for assignment.",
        "DHCP reservation (or static mapping) binds a device’s MAC address to a specific IP address permanently.",
        "DHCP exclusion removes certain addresses from the pool.",
        "DHCP lease time sets the duration an address is valid before renewal."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DHCP reservation ensures that a device always receives the same IP address by associating its MAC address with a fixed IP.",
      "examTip": "Use DHCP reservations for devices that require a consistent IP address."
    },
    {
      "id": 81,
      "question": "Which command-line tool is used to display the current routing table on a Windows computer?",
      "options": [
        "ipconfig /all displays comprehensive interface details.",
        "arp -a shows the ARP cache mappings.",
        "netstat -r gives brief routing information.",
        "route print displays the full routing table clearly."
      ],
      "correctAnswerIndex": 3,
      "explanation": "The 'route print' command displays the complete routing table, showing how traffic is routed to various networks.",
      "examTip": "Use route print to diagnose routing issues on your computer."
    },
    {
      "id": 82,
      "question": "What is a broadcast storm and what can it cause?",
      "options": [
        "It improves network security by isolating traffic, which is incorrect.",
        "It increases available bandwidth, which it does not.",
        "It results in severe performance degradation or network outages due to overwhelming broadcast traffic.",
        "It leads to faster data transfer speeds, which is not true."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A broadcast storm floods the network with excessive broadcast traffic, overwhelming network devices and leading to performance issues or outages.",
      "examTip": "Implement proper segmentation and use protocols like STP to prevent broadcast storms."
    },
    {
      "id": 83,
      "question": "What is the primary purpose of using VLANs in a switched network?",
      "options": [
        "To increase overall network bandwidth by aggregating connections.",
        "To logically segment a physical network into isolated broadcast domains for improved security and performance.",
        "To provide wireless connectivity without cables.",
        "To encrypt data traffic between devices on the same network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "VLANs divide a single physical network into multiple isolated segments, thereby reducing broadcast traffic and enhancing security.",
      "examTip": "VLANs are a fundamental tool for organizing and securing a network."
    },
    {
      "id": 84,
      "question": "Which command is used to test network connectivity to a remote host and measure round-trip time?",
      "options": [
        "tracert (or traceroute) reveals the network path but not primarily latency.",
        "ping sends echo requests and measures the time for replies.",
        "ipconfig displays local configuration details.",
        "nslookup resolves hostnames to IP addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The ping command sends ICMP echo requests to a remote host and measures round-trip time, providing basic connectivity and latency information.",
      "examTip": "Ping is a core troubleshooting tool for testing network connectivity."
    },
    {
      "id": 85,
      "question": "What is a honeypot in network security?",
      "options": [
        "A secure server dedicated to storing sensitive information.",
        "A decoy system designed to attract attackers for the purpose of study and analysis.",
        "A specialized firewall used to filter out malicious traffic.",
        "A tool used to encrypt data transmitted over the network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A honeypot is an intentionally vulnerable system set up as a decoy to lure attackers and gather information on their tactics.",
      "examTip": "Honeypots are useful for understanding attacker behavior and improving defenses."
    },
    {
      "id": 86,
      "question": "Which of the following best describes social engineering in cybersecurity?",
      "options": [
        "It involves developing and managing social media platforms for communication.",
        "It refers to manipulating individuals into revealing confidential information through deceptive practices.",
        "It is the use of social networks for promotional marketing purposes.",
        "It means networking with peers at professional events for business development."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Social engineering uses deception to trick people into divulging sensitive information or performing actions that compromise security.",
      "examTip": "Always be cautious of unexpected requests for personal or confidential data."
    },
    {
      "id": 87,
      "question": "What does encryption do to data?",
      "options": [
        "It enlarges data and simplifies reading, which is false.",
        "It converts data into an unreadable format (ciphertext) that can only be decoded with the correct key.",
        "It permanently erases data from a storage medium.",
        "It organizes data into a structured format for easy retrieval."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption transforms data into a ciphertext that protects it from unauthorized access, requiring the correct key for decryption.",
      "examTip": "Encryption is fundamental for protecting sensitive information during transmission and storage."
    },
    {
      "id": 88,
      "question": "Which of the following is a key characteristic of cloud computing?",
      "options": [
        "All resources are kept strictly on-premises.",
        "It provides on-demand access to shared computing resources over the internet with scalability and flexibility.",
        "It requires a large, initial hardware investment.",
        "It offers limited scalability compared to traditional setups."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Cloud computing offers scalable, on-demand resources accessed over the internet, often reducing upfront costs and providing flexibility.",
      "examTip": "Cloud computing is popular for its ability to scale resources as needed and its cost efficiency."
    },
    {
      "id": 89,
      "question": "Which command-line tool is used to display the ARP cache on a Windows system?",
      "options": [
        "ipconfig /all displays comprehensive interface details.",
        "arp -a shows the current ARP cache entries.",
        "netstat -r shows routing information but not ARP mappings.",
        "route print outputs the routing table."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The command 'arp -a' lists the ARP cache, which shows the mappings between IP addresses and MAC addresses on the local network.",
      "examTip": "Use arp -a to quickly check local IP-to-MAC mappings."
    },
    {
      "id": 90,
      "question": "What is a potential consequence of a broadcast storm on a network?",
      "options": [
        "It results in improved network security measures.",
        "It leads to an increase in available network bandwidth.",
        "It causes severe performance degradation or a network outage due to excessive broadcast traffic.",
        "It enhances internet speeds significantly."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A broadcast storm floods the network with broadcast traffic, consuming bandwidth and processing power, which can lead to network outages.",
      "examTip": "Prevent broadcast storms by designing networks with proper segmentation and loop prevention."
    },
    {
      "id": 91,
      "question": "Which of the following best describes the purpose of port forwarding on a router?",
      "options": [
        "To block all incoming traffic on a specified port.",
        "To allow external access to a specific internal service by mapping an external port to an internal IP address and port.",
        "To encrypt data transmitted on a specific port.",
        "To increase the speed of your internet connection by prioritizing certain ports."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Port forwarding directs traffic from an external port on the router to a specific internal address and port, enabling remote access to internal services.",
      "examTip": "Port forwarding is useful for hosting services (such as web or game servers) behind a NAT device."
    },
    {
      "id": 92,
      "question": "What is the primary purpose of the Address Resolution Protocol (ARP)?",
      "options": [
        "To translate domain names into IP addresses as DNS does.",
        "To dynamically assign IP addresses to devices via DHCP.",
        "To map IP addresses to MAC addresses on a local network so devices can communicate at Layer 2.",
        "To encrypt data before transmission on the network."
      ],
      "correctAnswerIndex": 2,
      "explanation": "ARP maps IP addresses to the corresponding MAC addresses on a local network, which is essential for data link layer communication.",
      "examTip": "Without ARP, devices would not know where to send frames on a local network."
    },
    {
      "id": 93,
      "question": "What does WPA3 stand for, and why is it important for wireless network security?",
      "options": [
        "Wired Protocol Access 3, which is outdated and insecure.",
        "Wi-Fi Protected Access 3, the latest wireless security standard with enhanced encryption and protection.",
        "Wireless Protected Area 3, a term referring to a secure wireless zone.",
        "Web Page Access 3, which is unrelated to security."
      ],
      "correctAnswerIndex": 1,
      "explanation": "WPA3 is the current standard for wireless security, offering stronger encryption and improved protection compared to earlier protocols.",
      "examTip": "Use WPA3 where possible for the best wireless security; otherwise, use WPA2 with AES."
    },
    {
      "id": 94,
      "question": "Which command-line tool is commonly used to test network connectivity to a remote host and measure round-trip time?",
      "options": [
        "tracert (or traceroute) shows the path taken by packets.",
        "ping sends ICMP echo requests and measures the round-trip time.",
        "ipconfig displays local configuration details.",
        "nslookup resolves domain names to IP addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Ping sends ICMP echo requests to a remote host and measures the response time, making it ideal for testing connectivity and latency.",
      "examTip": "Ping is the go-to tool for verifying connectivity and measuring network delay."
    },
    {
      "id": 95,
      "question": "What is a honeypot in cybersecurity?",
      "options": [
        "A secure server used to store highly sensitive data.",
        "A decoy system set up to lure attackers for analysis of their techniques.",
        "A dedicated firewall that blocks unauthorized access.",
        "A tool that encrypts traffic to keep data confidential."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A honeypot is intentionally left vulnerable to attract attackers so that their methods can be studied for security improvements.",
      "examTip": "Honeypots are useful for understanding attacker behavior and enhancing network defense strategies."
    },
    {
      "id": 96,
      "question": "What is the purpose of an intrusion detection system (IDS)?",
      "options": [
        "To assign IP addresses to devices on a network.",
        "To actively block attacks in real-time, which is the role of an IPS.",
        "To monitor network traffic for suspicious activity and alert administrators without automatically blocking traffic.",
        "To encrypt all network traffic for security."
      ],
      "correctAnswerIndex": 2,
      "explanation": "An IDS monitors network traffic for signs of malicious activity and alerts security personnel but does not take automated blocking actions.",
      "examTip": "An IDS functions like a security camera that alerts you to potential threats."
    },
    {
      "id": 97,
      "question": "What is a distributed denial-of-service (DDoS) attack?",
      "options": [
        "An attack aimed at stealing user passwords through repeated attempts.",
        "An attack that uses multiple compromised systems to flood a target with traffic, making it unavailable.",
        "A phishing campaign designed to trick users into revealing confidential data.",
        "A brute-force attack that systematically guesses passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DDoS attack uses traffic from many sources (often a botnet) to overwhelm a target, making it very difficult to mitigate by blocking a single IP.",
      "examTip": "DDoS attacks require comprehensive mitigation techniques due to their distributed nature."
    },
    {
      "id": 98,
      "question": "What is the primary purpose of using multi-factor authentication (MFA)?",
      "options": [
        "Relying solely on a complex password for security.",
        "Requiring two or more independent forms of identification to verify a user’s identity.",
        "Using the same password for multiple accounts for convenience.",
        "None of the above."
      ],
      "correctAnswerIndex": 1,
      "explanation": "MFA adds additional security by combining two or more verification methods, making unauthorized access much more difficult.",
      "examTip": "Implement MFA to significantly strengthen account security."
    },
    {
      "id": 99,
      "question": "Which of the following is a potential security risk associated with using default usernames and passwords on network devices?",
      "options": [
        "They inherently enhance network security.",
        "They simplify network administration with no drawbacks.",
        "They allow attackers to gain unauthorized access using well-known default credentials.",
        "They boost overall device performance."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Default credentials are widely published and easily exploited, making them a serious vulnerability.",
      "examTip": "Always change default usernames and passwords immediately after deployment."
    },
    {
      "id": 100,
      "question": "You are setting up a network and need to ensure that a specific server always receives the same IP address from the DHCP server. What DHCP feature should you use?",
      "options": [
        "DHCP scope, which defines the available address range.",
        "DHCP reservation (or static mapping), which binds a device’s MAC address to a specific IP.",
        "DHCP exclusion, which prevents certain addresses from being issued.",
        "DHCP lease time, which sets the duration for an IP assignment."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DHCP reservation ensures that a device always receives the same IP address by linking its MAC address to a fixed IP in the DHCP server.",
      "examTip": "Use DHCP reservations for critical devices that require a consistent IP address."
    }
  ]
});
