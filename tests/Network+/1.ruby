db.tests.insertOne({
  "category": "nplus",
  "testId": 1,
  "testName": "CompTIA Network+ (N10-009) Practice Test #1 (Normal)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "Which protocol should be used when securely transferring files over a network while also providing encryption for the session?",
      "options": [
        "SFTP",
        "FTP",
        "TFTP",
        "HTTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SFTP (Secure File Transfer Protocol) uses SSH to provide encrypted file transfer sessions, ensuring both data and session confidentiality. FTP (File Transfer Protocol) lacks encryption, making it insecure for sensitive data. TFTP (Trivial File Transfer Protocol) is faster but offers no encryption or authentication. HTTP (Hypertext Transfer Protocol) is used for web traffic and does not secure file transfers.",
      "examTip": "For secure file transfers, prefer SFTP over FTP to ensure encryption and authentication."
    },
    {
      "id": 2,
      "question": "What is the FIRST step in troubleshooting a network issue where users report intermittent connectivity loss?",
      "options": [
        "Identify and gather information about the problem",
        "Replace the suspected faulty network switch",
        "Restart the affected network services",
        "Escalate the issue to a senior network engineer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The first step in troubleshooting is always to gather information about the problem to understand its scope and possible causes. Replacing hardware or restarting services without proper diagnosis can be costly and may not address the root cause. Escalation should occur only if the issue cannot be resolved after initial troubleshooting steps.",
      "examTip": "Always gather relevant information before taking corrective actions. This helps avoid unnecessary changes and pinpoint the root cause faster."
    },
    {
      "id": 3,
      "question": "Which of the following BEST describes a scenario where APIPA is assigned to a host device?",
      "options": [
        "The DHCP server is unreachable, and the host assigns itself an address in the 169.254.x.x range.",
        "The host is configured for a static IP in the 192.168.x.x range.",
        "The host uses NAT to communicate with external networks.",
        "The DHCP server assigns a dynamic IP from the available scope."
      ],
      "correctAnswerIndex": 0,
      "explanation": "APIPA (Automatic Private IP Addressing) assigns an IP address from the 169.254.x.x range when a host cannot reach a DHCP server. Static IPs in the 192.168.x.x range are manually configured. NAT allows private networks to communicate externally, unrelated to APIPA. DHCP dynamically assigns addresses from a scope when available, which APIPA only substitutes if DHCP fails.",
      "examTip": "APIPA addresses (169.254.x.x) indicate DHCP issues—check connectivity to the DHCP server when you see them."
    },
    {
      "id": 4,
      "question": "Which wireless encryption protocol provides the MOST secure connection for a modern enterprise Wi-Fi network?",
      "options": [
        "WPA3",
        "WEP",
        "WPA",
        "WPA2"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3 provides the most secure wireless encryption currently available, offering stronger protections against brute-force attacks and better encryption methods. WEP is outdated and easily compromised. WPA improves on WEP but is still less secure than WPA2. WPA2 was long the standard but has vulnerabilities that WPA3 addresses.",
      "examTip": "Always choose WPA3 when available for the strongest wireless encryption and security."
    },
    {
      "id": 5,
      "question": "A network engineer needs to ensure high availability between two routers at the edge of the network. Which protocol would BEST achieve this goal?",
      "options": [
        "VRRP",
        "BGP",
        "OSPF",
        "RIP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "VRRP (Virtual Router Redundancy Protocol) provides high availability by allowing a backup router to take over automatically if the primary router fails. BGP is used for routing between autonomous systems, not for redundancy. OSPF dynamically selects the best path but doesn't handle router failover. RIP is an outdated dynamic routing protocol unsuitable for high availability needs.",
      "examTip": "For router redundancy and high availability, use VRRP or HSRP protocols instead of traditional routing protocols."
    },
    {
      "id": 6,
      "question": "Which OSI layer is responsible for reliable data transfer, including error correction and flow control?",
      "options": [
        "Transport",
        "Network",
        "Session",
        "Data Link"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The Transport layer (Layer 4) ensures reliable data transfer through error correction and flow control (e.g., using TCP). The Network layer (Layer 3) handles routing and addressing. The Session layer (Layer 5) manages sessions between applications but not data reliability. The Data Link layer (Layer 2) ensures data transfer across the physical link but without end-to-end reliability.",
      "examTip": "Remember TCP operates at the Transport layer for reliable delivery, while UDP also works at this layer without guaranteed delivery."
    },
    {
      "id": 7,
      "question": "A company needs to connect two data centers over the internet securely. Which solution provides an encrypted connection while maintaining existing IP schemes on both sides?",
      "options": [
        "Site-to-site VPN",
        "NAT gateway",
        "Direct Connect",
        "GRE tunnel"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A site-to-site VPN establishes a secure, encrypted connection between two networks over the internet, preserving internal IP schemes. A NAT gateway translates IP addresses but doesn’t provide encryption. Direct Connect is a dedicated private connection without encryption. A GRE tunnel encapsulates packets but lacks encryption unless paired with IPsec.",
      "examTip": "Use site-to-site VPN for secure, encrypted communication between entire networks."
    },
    {
      "id": 8,
      "question": "Which wireless standard operates in the 5GHz frequency and supports data rates up to 1.3 Gbps?",
      "options": [
        "802.11ac",
        "802.11n",
        "802.11g",
        "802.11a"
      ],
      "correctAnswerIndex": 0,
      "explanation": "802.11ac operates in the 5GHz band and supports speeds up to 1.3 Gbps. 802.11n can operate in 2.4GHz and 5GHz bands but maxes out at 600 Mbps. 802.11g is limited to 2.4GHz with 54 Mbps. 802.11a also uses 5GHz but supports only 54 Mbps.",
      "examTip": "802.11ac is ideal for high-speed Wi-Fi in modern networks due to its higher throughput and reduced interference at 5GHz."
    },
    {
      "id": 9,
      "question": "What type of attack involves intercepting and potentially altering communications between two parties without their knowledge?",
      "options": [
        "On-path attack",
        "DNS poisoning",
        "ARP spoofing",
        "Phishing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An on-path attack (formerly 'man-in-the-middle') occurs when an attacker intercepts communication between two entities, potentially altering or stealing data. DNS poisoning corrupts DNS records to redirect traffic. ARP spoofing tricks devices into sending traffic to the attacker’s MAC address but focuses on LAN-level interception. Phishing targets users through deceptive communication, not network interception.",
      "examTip": "Enable encryption protocols like TLS and use VPNs to mitigate on-path attacks."
    },
    {
      "id": 10,
      "question": "Which addressing method allows a device to communicate with the nearest member of a group of hosts?",
      "options": [
        "Anycast",
        "Broadcast",
        "Multicast",
        "Unicast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Anycast sends traffic to the nearest host in a group based on routing metrics, commonly used in global DNS servers. Broadcast sends data to all devices in a network segment. Multicast sends traffic to multiple specified recipients but not necessarily the closest. Unicast targets a single specific host.",
      "examTip": "Anycast is often used in load balancing and CDN environments for efficient routing."
    },
    {
      "id": 11,
      "question": "Which topology provides the MOST redundancy and fault tolerance but is the most expensive to implement?",
      "options": [
        "Mesh",
        "Star",
        "Bus",
        "Ring"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A mesh topology connects every device to every other device, offering the highest redundancy and fault tolerance. Star topology relies on a central hub, making it less redundant. Bus topology uses a single backbone, which can be a point of failure. Ring topology offers some redundancy but is prone to disruption if a single node fails without additional protection mechanisms like dual rings.",
      "examTip": "Mesh topologies are ideal for critical networks where uptime is essential, despite higher costs."
    },
    {
      "id": 12,
      "question": "Which protocol uses port 3389 and allows remote access to graphical desktops on Windows systems?",
      "options": [
        "RDP",
        "SSH",
        "Telnet",
        "VNC"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RDP (Remote Desktop Protocol) uses port 3389 to provide remote graphical access to Windows desktops. SSH provides secure command-line access. Telnet also offers command-line access but lacks encryption. VNC (Virtual Network Computing) offers cross-platform graphical access but uses different ports (usually 5900).",
      "examTip": "For secure remote desktop access in Windows environments, RDP is the standard choice."
    },
    {
      "id": 13,
      "question": "Which of the following is a **private** IPv4 address range according to RFC1918?",
      "options": [
        "10.0.0.0/8",
        "8.8.8.8/32",
        "172.33.0.0/16",
        "192.0.2.0/24"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 10.0.0.0/8 range is designated for private use. 8.8.8.8 is a public IP (Google DNS). 172.33.0.0/16 falls outside the private 172.16.0.0–172.31.255.255 range. 192.0.2.0/24 is reserved for documentation and not private use.",
      "examTip": "Private IP ranges per RFC1918: 10.0.0.0/8, 172.16.0.0–172.31.255.255, and 192.168.0.0/16."
    },
    {
      "id": 14,
      "question": "Which cloud deployment model provides exclusive use of cloud resources by a single organization?",
      "options": [
        "Private",
        "Public",
        "Hybrid",
        "Community"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Private cloud environments are dedicated to a single organization, offering enhanced control and security. Public clouds share resources among multiple customers. Hybrid clouds combine private and public elements. Community clouds are shared among organizations with common interests.",
      "examTip": "Private clouds are ideal for organizations with strict regulatory or security requirements."
    },
    {
      "id": 15,
      "question": "A network engineer wants to ensure that certain applications receive higher priority over others. Which feature should be configured?",
      "options": [
        "Quality of Service",
        "VLAN",
        "NAT",
        "Port mirroring"
      ],
      "correctAnswerIndex": 0,
      "explanation": "QoS (Quality of Service) prioritizes certain types of traffic (like VoIP) to ensure performance. VLANs segment networks logically but do not prioritize traffic. NAT translates private to public IPs. Port mirroring duplicates traffic for monitoring purposes, not prioritization.",
      "examTip": "Configure QoS to reduce latency and jitter for critical applications such as VoIP and video conferencing."
    },
    {
      "id": 16,
      "question": "Which protocol uses port 53 and is responsible for resolving domain names to IP addresses?",
      "options": [
        "DNS",
        "DHCP",
        "HTTP",
        "LDAP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DNS (Domain Name System) uses port 53 to resolve domain names into IP addresses. DHCP assigns IP configurations dynamically. HTTP handles web traffic on port 80. LDAP manages directory services over port 389.",
      "examTip": "If users report issues accessing websites by name, check DNS server settings first."
    },
    {
      "id": 17,
      "question": "Which dynamic routing protocol uses link-state information to build a map of the network and selects the shortest path first?",
      "options": [
        "OSPF",
        "RIP",
        "BGP",
        "EIGRP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "OSPF (Open Shortest Path First) uses a link-state algorithm and prioritizes the shortest path. RIP uses hop count but is less efficient. BGP is used for interdomain routing. EIGRP combines distance-vector and link-state characteristics but is proprietary to Cisco.",
      "examTip": "OSPF is ideal for large enterprise networks due to its fast convergence and scalability."
    },
    {
      "id": 18,
      "question": "Which tool would a network administrator use to trace the path packets take from one network host to another?",
      "options": [
        "traceroute",
        "ping",
        "netstat",
        "arp"
      ],
      "correctAnswerIndex": 0,
      "explanation": "traceroute tracks the path packets take, displaying each hop along the way. ping tests connectivity but doesn’t show the path. netstat displays network connections and routing tables. arp shows IP-to-MAC address mappings on a network segment.",
      "examTip": "Use traceroute for diagnosing routing issues and identifying where traffic is being dropped."
    },
    {
      "id": 19,
      "question": "What technology allows multiple virtual networks to run on top of a single physical network infrastructure?",
      "options": [
        "VXLAN",
        "VLAN",
        "VPN",
        "NAT"
      ],
      "correctAnswerIndex": 0,
      "explanation": "VXLAN (Virtual Extensible LAN) allows Layer 2 networks to be extended over Layer 3 infrastructure, supporting multiple virtual networks. VLANs separate traffic at Layer 2 but don’t extend across WANs by default. VPNs provide secure connections over public networks but don’t virtualize networks internally. NAT translates IP addresses between networks.",
      "examTip": "VXLAN is essential in large-scale data centers needing multi-tenant network segmentation."
    },
    {
      "id": 20,
      "question": "A technician observes repeated CRC errors on a switch port. What is the MOST likely cause?",
      "options": [
        "Faulty cable or connector",
        "Incorrect VLAN assignment",
        "Port speed mismatch",
        "Duplicate IP address"
      ],
      "correctAnswerIndex": 0,
      "explanation": "CRC (Cyclic Redundancy Check) errors indicate corrupted frames, typically caused by faulty cables or connectors. Incorrect VLAN assignments don’t cause CRC errors. Port speed mismatches may cause link failures but not CRC errors. Duplicate IP addresses result in network communication issues, not physical layer errors.",
      "examTip": "CRC errors often point to physical issues—replace cables or check connectors first."
    },
    {
      "id": 21,
      "question": "Which protocol is used for secure remote command-line access and file transfers, operating over port 22?",
      "options": [
        "SSH",
        "Telnet",
        "FTP",
        "RDP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH (Secure Shell) provides encrypted remote command-line access and can securely transfer files using SCP or SFTP, all over port 22. Telnet is insecure as it lacks encryption. FTP uses ports 20/21 and isn’t secure by default. RDP offers graphical remote access over port 3389.",
      "examTip": "Always use SSH instead of Telnet for secure remote access."
    },
    {
      "id": 22,
      "question": "Which technology allows a single physical server to host multiple independent virtual machines (VMs)?",
      "options": [
        "Hypervisor",
        "Container",
        "Load balancer",
        "Switch"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A hypervisor manages and runs multiple virtual machines on a single physical host. Containers provide isolated environments for applications but share the OS kernel. Load balancers distribute network traffic across multiple servers. Switches forward traffic between devices on a network.",
      "examTip": "Hypervisors are fundamental for server virtualization and resource optimization in data centers."
    },
    {
      "id": 23,
      "question": "What is the primary benefit of using link aggregation between two switches?",
      "options": [
        "Increased bandwidth and redundancy",
        "Simplified IP addressing",
        "Enhanced encryption between switches",
        "Improved wireless connectivity"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Link aggregation combines multiple physical links into a single logical link, increasing bandwidth and providing redundancy. It doesn’t simplify IP addressing or provide encryption. Wireless connectivity is unrelated to link aggregation between switches.",
      "examTip": "Use LACP (Link Aggregation Control Protocol) for dynamic link aggregation between compatible devices."
    },
    {
      "id": 24,
      "question": "Which protocol uses port 123 to synchronize time across network devices?",
      "options": [
        "NTP",
        "SNMP",
        "LDAP",
        "TFTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NTP (Network Time Protocol) synchronizes clocks across network devices on port 123. SNMP manages network devices. LDAP handles directory services. TFTP transfers files without authentication or encryption.",
      "examTip": "Accurate time synchronization using NTP is essential for proper logging, authentication, and network operations."
    },
    {
      "id": 25,
      "question": "Which addressing mechanism automatically assigns an IPv6 address to a device without a DHCP server?",
      "options": [
        "SLAAC",
        "DHCPv6",
        "APIPA",
        "NAT64"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SLAAC (Stateless Address Autoconfiguration) allows IPv6 hosts to configure their addresses automatically using router advertisements. DHCPv6 assigns IPv6 addresses but requires a DHCP server. APIPA is only relevant for IPv4 addressing. NAT64 translates IPv6 addresses to IPv4, not for self-assignment.",
      "examTip": "For automatic IPv6 addressing without DHCP, SLAAC is the default choice."
    },
    {
      "id": 26,
      "question": "Which device is responsible for filtering network traffic based on predefined security rules and can block unauthorized access while allowing legitimate communication?",
      "options": [
        "Firewall",
        "Router",
        "Switch",
        "Load balancer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A firewall filters traffic based on security rules, preventing unauthorized access. Routers direct traffic between networks but do not inherently filter traffic for security purposes. Switches forward frames within a LAN but don’t provide traffic filtering based on rules. Load balancers distribute network traffic across multiple servers for efficiency but don’t filter traffic for security.",
      "examTip": "Firewalls are the first line of defense—always ensure rules are updated to reflect current security policies."
    },
    {
      "id": 27,
      "question": "Which wireless frequency band provides the longest range but is more prone to interference from common household devices?",
      "options": [
        "2.4GHz",
        "5GHz",
        "6GHz",
        "60GHz"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 2.4GHz band provides longer range and better wall penetration but is more susceptible to interference from devices like microwaves and cordless phones. The 5GHz and 6GHz bands offer higher speeds with less interference but shorter ranges. 60GHz is typically used for high-speed, short-range applications like WiGig.",
      "examTip": "Choose 2.4GHz for coverage, but switch to 5GHz or 6GHz for higher speeds and less interference."
    },
    {
      "id": 28,
      "question": "Which protocol facilitates secure web communication by encrypting traffic using port 443?",
      "options": [
        "HTTPS",
        "HTTP",
        "FTP",
        "SMTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "HTTPS (Hypertext Transfer Protocol Secure) encrypts web traffic using port 443. HTTP (port 80) does not provide encryption. FTP (port 20/21) transfers files but lacks encryption unless paired with secure variants. SMTP (port 25) is used for email transmission, not web traffic.",
      "examTip": "Always ensure web applications use HTTPS, especially when transmitting sensitive information."
    },
    {
      "id": 29,
      "question": "Which dynamic routing protocol is most commonly used for routing between autonomous systems on the Internet?",
      "options": [
        "BGP",
        "OSPF",
        "RIP",
        "EIGRP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BGP (Border Gateway Protocol) is the standard for routing between autonomous systems (AS) on the Internet. OSPF and EIGRP are primarily used within organizations (intra-domain). RIP is outdated and lacks the scalability required for modern networks.",
      "examTip": "BGP is known as the 'protocol of the Internet'—essential for ISPs and large-scale networks."
    },
    {
      "id": 30,
      "question": "Which protocol is used for network device management, providing capabilities such as monitoring performance and sending alerts?",
      "options": [
        "SNMP",
        "NTP",
        "DNS",
        "TFTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SNMP (Simple Network Management Protocol) is used for managing and monitoring network devices, sending alerts (traps) when issues arise. NTP synchronizes time across network devices. DNS resolves hostnames to IP addresses. TFTP transfers files without encryption or authentication.",
      "examTip": "Use SNMPv3 for secure device management, as it supports encryption and authentication."
    },
    {
      "id": 31,
      "question": "Which type of wireless antenna is MOST suitable for providing 360-degree coverage in an open office environment?",
      "options": [
        "Omnidirectional",
        "Directional",
        "Yagi",
        "Parabolic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Omnidirectional antennas provide 360-degree coverage, making them ideal for open office spaces. Directional, Yagi, and Parabolic antennas focus signals in specific directions, which are better suited for point-to-point links or long-distance communication.",
      "examTip": "For indoor, multi-user environments like offices, omnidirectional antennas provide the best all-around coverage."
    },
    {
      "id": 32,
      "question": "Which cabling type provides the HIGHEST resistance to electromagnetic interference (EMI)?",
      "options": [
        "Single-mode fiber",
        "Coaxial cable",
        "Shielded twisted pair (STP)",
        "Unshielded twisted pair (UTP)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Single-mode fiber uses light for transmission, making it immune to EMI. Coaxial cables offer some EMI resistance but not as much as fiber. STP reduces EMI better than UTP but still uses electrical signals susceptible to interference compared to fiber.",
      "examTip": "Fiber optic cables are best in environments with high EMI, such as industrial settings."
    },
    {
      "id": 33,
      "question": "Which network device connects different networks together and directs data based on IP addresses?",
      "options": [
        "Router",
        "Switch",
        "Firewall",
        "Hub"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Routers connect multiple networks and direct traffic based on IP addresses. Switches operate at Layer 2 (MAC addresses). Firewalls provide security through traffic filtering. Hubs broadcast data to all ports without any traffic management.",
      "examTip": "Routers operate at Layer 3 of the OSI model, making routing decisions based on IP addresses."
    },
    {
      "id": 34,
      "question": "Which IPv6 feature allows simultaneous use of both IPv4 and IPv6 addresses on the same network device?",
      "options": [
        "Dual stack",
        "Tunneling",
        "NAT64",
        "SLAAC"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Dual stack allows devices to run both IPv4 and IPv6 simultaneously. Tunneling encapsulates IPv6 packets within IPv4. NAT64 translates IPv6 traffic to IPv4 networks. SLAAC allows automatic IPv6 address configuration without DHCPv6.",
      "examTip": "Dual stack ensures backward compatibility during IPv6 adoption, reducing migration risks."
    },
    {
      "id": 35,
      "question": "A company requires real-time video conferencing with minimal delay. Which network performance metric is MOST critical to monitor?",
      "options": [
        "Latency",
        "Throughput",
        "Bandwidth",
        "Jitter"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Latency measures the delay in data transmission and is critical for real-time applications like video conferencing. Throughput measures actual data transfer rates. Bandwidth is the maximum capacity, not actual performance. Jitter refers to variations in latency but isn’t as critical as overall latency for real-time communication.",
      "examTip": "Low latency is key for VoIP, video conferencing, and online gaming for seamless performance."
    },
    {
      "id": 36,
      "question": "Which encryption protocol is MOST commonly used to secure data transmitted over VPNs?",
      "options": [
        "IPSec",
        "SSL",
        "TLS",
        "GRE"
      ],
      "correctAnswerIndex": 0,
      "explanation": "IPSec (Internet Protocol Security) encrypts IP packets for secure VPN communication. SSL and TLS are more common for web applications. GRE provides tunneling but without encryption unless paired with IPSec.",
      "examTip": "For secure VPN implementations, IPSec is the industry standard, especially for site-to-site configurations."
    },
    {
      "id": 37,
      "question": "Which protocol allows secure, encrypted communication for file transfers and also operates over port 22?",
      "options": [
        "SFTP",
        "FTP",
        "TFTP",
        "SCP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SFTP (Secure File Transfer Protocol) uses SSH over port 22 for secure file transfers. FTP lacks encryption. TFTP is lightweight but insecure. SCP also uses SSH and port 22 but is typically used for direct file transfers rather than managing files on the server like SFTP.",
      "examTip": "For secure file transfers requiring full management capabilities, SFTP is preferred over SCP."
    },
    {
      "id": 38,
      "question": "Which technology allows for automatic rerouting of traffic in case of link failure between routers, ensuring continuous availability?",
      "options": [
        "FHRP",
        "NAT",
        "QoS",
        "VLAN"
      ],
      "correctAnswerIndex": 0,
      "explanation": "First Hop Redundancy Protocols (FHRP), such as HSRP and VRRP, provide automatic failover in case a router fails. NAT translates IP addresses between networks. QoS prioritizes traffic but doesn’t ensure redundancy. VLANs segment network traffic but don’t provide failover capabilities.",
      "examTip": "FHRP is crucial for maintaining network uptime by providing router redundancy at the first hop."
    },
    {
      "id": 39,
      "question": "Which connector type is commonly used with fiber optic cables and features a push-pull locking mechanism?",
      "options": [
        "LC",
        "ST",
        "SC",
        "BNC"
      ],
      "correctAnswerIndex": 0,
      "explanation": "LC (Local Connector) is a fiber optic connector with a push-pull mechanism for secure connections. ST connectors use a bayonet-style twist lock. SC connectors use a push-pull mechanism but are larger than LC. BNC connectors are used for coaxial cables, not fiber.",
      "examTip": "LC connectors are preferred in modern fiber installations due to their compact size and secure connection."
    },
    {
      "id": 40,
      "question": "A network administrator is troubleshooting a slow wireless connection. Which factor would MOST likely cause signal degradation in a 5GHz network?",
      "options": [
        "Physical obstructions like walls",
        "Interference from microwaves",
        "Overlapping channels",
        "High device density"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 5GHz band has shorter wavelengths, making it more susceptible to physical obstructions like walls. Microwaves typically interfere with the 2.4GHz band. Overlapping channels are a bigger concern in 2.4GHz. High device density affects capacity, not signal strength.",
      "examTip": "5GHz offers higher speeds but requires careful placement of access points due to reduced range and penetration."
    },
    {
      "id": 41,
      "question": "Which protocol is used to securely authenticate users to network services, often in enterprise environments?",
      "options": [
        "RADIUS",
        "SNMP",
        "NTP",
        "TACACS+"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RADIUS (Remote Authentication Dial-in User Service) provides centralized authentication, authorization, and accounting (AAA) for users accessing network services. SNMP monitors devices. NTP synchronizes time. TACACS+ also provides AAA but is typically preferred for device administration rather than user authentication.",
      "examTip": "Use RADIUS for user authentication and TACACS+ for network device administration in enterprise settings."
    },
    {
      "id": 42,
      "question": "Which network architecture uses a centralized controller to manage forwarding devices through open protocols like OpenFlow?",
      "options": [
        "Software-defined networking",
        "Spine and leaf architecture",
        "Collapsed core architecture",
        "Three-tier architecture"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Software-defined networking (SDN) separates the control plane from the data plane, allowing centralized control through protocols like OpenFlow. Spine and leaf is a physical topology. Collapsed core and three-tier architectures define traditional hierarchical network designs without centralized control.",
      "examTip": "SDN enhances network agility by providing centralized control, ideal for dynamic cloud environments."
    },
    {
      "id": 43,
      "question": "Which port is used by Secure Shell (SSH) for encrypted remote management?",
      "options": [
        "22",
        "23",
        "443",
        "3389"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH uses port 22 for secure remote command-line access. Port 23 is used by Telnet (insecure). Port 443 is for HTTPS, and 3389 is used by RDP for remote desktop access.",
      "examTip": "Memorize well-known ports like 22 for SSH, 80 for HTTP, and 443 for HTTPS for quick recall during exams."
    },
    {
      "id": 44,
      "question": "Which service ensures that all logs from various network devices are collected and stored in a central location for easier management?",
      "options": [
        "Syslog",
        "SIEM",
        "SNMP",
        "TFTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Syslog collects and stores logs from network devices in a central repository. SIEM systems analyze these logs for security insights but rely on syslog for collection. SNMP monitors device performance. TFTP transfers files without authentication.",
      "examTip": "Implement centralized syslog servers to simplify network monitoring and incident response."
    },
    {
      "id": 45,
      "question": "Which type of IP address allows a single device to send traffic to multiple recipients simultaneously without broadcasting to the entire network?",
      "options": [
        "Multicast",
        "Unicast",
        "Anycast",
        "Broadcast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Multicast sends data to multiple specified recipients without sending it to all devices on the network. Unicast targets a single recipient. Anycast sends data to the nearest recipient in a group. Broadcast sends data to all devices in a network segment.",
      "examTip": "Multicast is commonly used for streaming media and group communication services to optimize bandwidth usage."
    },
    {
      "id": 46,
      "question": "A network technician needs to connect a router to an ISP’s network for WAN connectivity. Which interface type would MOST likely be used?",
      "options": [
        "Serial",
        "Ethernet",
        "Fiber Channel",
        "USB"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Serial interfaces are commonly used for WAN connections, especially with legacy systems and certain ISP links. Ethernet is typically used for LAN connections. Fiber Channel is used for high-speed data storage networks, not WAN connectivity. USB is rarely used for WAN connections in enterprise environments.",
      "examTip": "For traditional WAN connections, serial interfaces remain a standard choice, especially in older setups."
    },
    {
      "id": 47,
      "question": "Which routing protocol uses hop count as its primary metric and has a maximum hop limit of 15?",
      "options": [
        "RIP",
        "OSPF",
        "BGP",
        "EIGRP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RIP (Routing Information Protocol) uses hop count as its metric, with a maximum of 15 hops, making it unsuitable for large networks. OSPF uses link-state metrics, BGP uses path vector metrics for interdomain routing, and EIGRP uses a combination of metrics but is more advanced than RIP.",
      "examTip": "RIP is simple but outdated; remember the 15-hop limit for quick identification in exams."
    },
    {
      "id": 48,
      "question": "Which standard defines port-based Network Access Control (NAC), ensuring that devices meet security policies before network access?",
      "options": [
        "802.1X",
        "802.11ac",
        "802.3af",
        "802.1Q"
      ],
      "correctAnswerIndex": 0,
      "explanation": "802.1X provides port-based NAC, ensuring devices are authenticated before gaining network access. 802.11ac defines wireless networking standards. 802.3af relates to Power over Ethernet (PoE). 802.1Q specifies VLAN tagging on Ethernet frames.",
      "examTip": "802.1X is key for securing wired and wireless networks by enforcing authentication at the port level."
    },
    {
      "id": 49,
      "question": "Which device combines multiple physical network links into a single logical link to provide redundancy and increased bandwidth?",
      "options": [
        "Switch using link aggregation",
        "Router using NAT",
        "Firewall with ACLs",
        "Load balancer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Link aggregation on switches combines multiple physical links for redundancy and higher bandwidth. Routers using NAT translate IP addresses but do not combine links. Firewalls with ACLs control access but don’t aggregate links. Load balancers distribute traffic across servers, not links.",
      "examTip": "Link aggregation (often using LACP) is essential for preventing single points of failure between network devices."
    },
    {
      "id": 50,
      "question": "Which network service automatically assigns IP addresses and provides options such as default gateway and DNS servers to clients?",
      "options": [
        "DHCP",
        "DNS",
        "NAT",
        "TFTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DHCP (Dynamic Host Configuration Protocol) dynamically assigns IP addresses and additional options like default gateways and DNS servers. DNS resolves domain names to IP addresses. NAT translates IP addresses for network communication. TFTP provides simple file transfers without authentication.",
      "examTip": "Check DHCP configurations first when multiple devices experience IP-related connectivity issues."
    },
    {
      "id": 51,
      "question": "Which cloud service model provides the most control over the underlying hardware and software configurations?",
      "options": [
        "IaaS",
        "SaaS",
        "PaaS",
        "FaaS"
      ],
      "correctAnswerIndex": 0,
      "explanation": "IaaS (Infrastructure as a Service) gives users control over operating systems, storage, and applications, with the provider managing the infrastructure. SaaS (Software as a Service) provides fully managed software. PaaS (Platform as a Service) offers a platform for developers but with limited control over infrastructure. FaaS (Function as a Service) runs code in response to events without server management.",
      "examTip": "Choose IaaS when you need to configure and control the virtual environment without owning physical hardware."
    },
    {
      "id": 52,
      "question": "Which type of network cable uses light pulses for data transmission, providing immunity to electromagnetic interference (EMI)?",
      "options": [
        "Fiber optic",
        "Coaxial",
        "Shielded twisted pair (STP)",
        "Unshielded twisted pair (UTP)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Fiber optic cables transmit data using light, making them immune to EMI and suitable for long-distance, high-speed communications. Coaxial, STP, and UTP cables use electrical signals and are more susceptible to EMI, with STP offering better protection than UTP.",
      "examTip": "Fiber optics are the go-to solution for environments with high EMI or where long-distance transmission is required."
    },
    {
      "id": 53,
      "question": "Which term describes the process of combining multiple network connections to increase throughput and provide redundancy?",
      "options": [
        "Link aggregation",
        "Load balancing",
        "Failover clustering",
        "Spanning Tree Protocol"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Link aggregation combines multiple connections for increased throughput and redundancy. Load balancing distributes traffic among multiple servers. Failover clustering provides redundancy for applications. Spanning Tree Protocol prevents network loops but does not aggregate links.",
      "examTip": "LACP is a common protocol for dynamic link aggregation—key for high-availability designs."
    },
    {
      "id": 54,
      "question": "Which network device dynamically learns MAC addresses and forwards traffic only to the appropriate port, reducing unnecessary traffic?",
      "options": [
        "Switch",
        "Hub",
        "Router",
        "Firewall"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Switches dynamically learn MAC addresses and forward traffic only to the intended recipient’s port, improving network efficiency. Hubs broadcast traffic to all ports. Routers forward traffic based on IP addresses. Firewalls filter traffic based on security rules, not MAC addresses.",
      "examTip": "Switches operate at Layer 2 of the OSI model, optimizing traffic flow and improving network performance."
    },
    {
      "id": 55,
      "question": "Which protocol uses port 161 for device monitoring and management in network environments?",
      "options": [
        "SNMP",
        "DNS",
        "NTP",
        "TFTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SNMP (Simple Network Management Protocol) uses port 161 for monitoring and managing network devices. DNS (port 53) resolves domain names. NTP (port 123) synchronizes time. TFTP (port 69) transfers files without authentication.",
      "examTip": "Always use SNMPv3 for secure network management due to its support for encryption and authentication."
    },
    {
      "id": 56,
      "question": "Which protocol resolves IP addresses to MAC addresses within a local subnet?",
      "options": [
        "ARP",
        "DNS",
        "DHCP",
        "ICMP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "ARP (Address Resolution Protocol) resolves IP addresses to MAC addresses within a local subnet. DNS resolves domain names to IP addresses. DHCP assigns IP addresses dynamically. ICMP is used for diagnostic purposes like ping and traceroute.",
      "examTip": "ARP issues can lead to connectivity problems within local networks; clear ARP caches when troubleshooting."
    },
    {
      "id": 57,
      "question": "Which topology is MOST fault-tolerant due to each device being connected to every other device in the network?",
      "options": [
        "Mesh",
        "Star",
        "Bus",
        "Ring"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Mesh topology provides the highest fault tolerance, with each device connected to every other device, eliminating single points of failure. Star topology relies on a central hub. Bus topology uses a single backbone cable, while ring topology connects devices in a closed loop, both less fault-tolerant.",
      "examTip": "Full mesh topologies are expensive but ideal for critical networks where uptime is essential."
    },
    {
      "id": 58,
      "question": "Which IP address type is used by routers to determine the default path for traffic when a more specific route is not available?",
      "options": [
        "Default gateway",
        "Loopback address",
        "Broadcast address",
        "Multicast address"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The default gateway directs traffic to external networks when a more specific route is unavailable. Loopback addresses (127.0.0.1 for IPv4) are used for testing local systems. Broadcast addresses send data to all devices in a subnet. Multicast addresses send traffic to multiple recipients.",
      "examTip": "Always verify default gateway settings during network troubleshooting, especially for external connectivity issues."
    },
    {
      "id": 59,
      "question": "Which wireless standard supports data rates up to 54 Mbps and operates exclusively in the 5GHz frequency band?",
      "options": [
        "802.11a",
        "802.11b",
        "802.11g",
        "802.11n"
      ],
      "correctAnswerIndex": 0,
      "explanation": "802.11a supports speeds up to 54 Mbps in the 5GHz band. 802.11b (11 Mbps) and 802.11g (54 Mbps) operate in the 2.4GHz band. 802.11n operates in both 2.4GHz and 5GHz bands, offering speeds up to 600 Mbps.",
      "examTip": "5GHz bands reduce interference but have shorter ranges; 802.11a was an early standard for higher-speed Wi-Fi."
    },
    {
      "id": 60,
      "question": "Which dynamic routing protocol uses autonomous system path information for making routing decisions on the Internet?",
      "options": [
        "BGP",
        "RIP",
        "OSPF",
        "EIGRP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BGP (Border Gateway Protocol) uses AS-path information to route traffic between autonomous systems on the Internet. RIP uses hop count. OSPF uses link-state algorithms for internal networks. EIGRP is a Cisco-proprietary hybrid routing protocol.",
      "examTip": "BGP is essential for ISPs and organizations that connect directly to the Internet—known as the 'glue' of the Internet."
    },
    {
      "id": 61,
      "question": "Which protocol is used to provide secure, encrypted access to network devices for configuration and management?",
      "options": [
        "SSH",
        "Telnet",
        "SNMP",
        "RDP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH (Secure Shell) provides secure, encrypted access to network devices for management. Telnet provides similar access but is unencrypted. SNMP monitors devices, and RDP offers graphical remote access to Windows systems.",
      "examTip": "SSH over port 22 is the standard for secure CLI access; always disable Telnet to prevent security risks."
    },
    {
      "id": 62,
      "question": "Which type of firewall inspects the entire connection state and ensures packets belong to a valid session?",
      "options": [
        "Stateful firewall",
        "Stateless firewall",
        "Next-generation firewall",
        "Packet-filtering firewall"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Stateful firewalls track the state of active connections, ensuring that only packets matching a valid session are allowed. Stateless firewalls inspect packets independently. Next-generation firewalls include stateful inspection plus advanced features like deep packet inspection. Packet-filtering firewalls operate at a basic level without session tracking.",
      "examTip": "Stateful firewalls provide better security than stateless ones by tracking active sessions and connection states."
    },
    {
      "id": 63,
      "question": "Which technology extends Layer 2 networks over a Layer 3 infrastructure, commonly used in large-scale data centers?",
      "options": [
        "VXLAN",
        "VPN",
        "VLAN",
        "NAT"
      ],
      "correctAnswerIndex": 0,
      "explanation": "VXLAN (Virtual Extensible LAN) encapsulates Layer 2 traffic over a Layer 3 network, enabling large-scale multi-tenant environments. VPNs provide secure network connections but don’t extend Layer 2 networks. VLANs segment networks at Layer 2. NAT translates IP addresses between networks.",
      "examTip": "VXLAN is essential for data center network scalability, enabling efficient cloud architectures."
    },
    {
      "id": 64,
      "question": "Which technology allows devices to use both IPv4 and IPv6 addresses simultaneously on the same network?",
      "options": [
        "Dual stack",
        "NAT64",
        "6to4 tunneling",
        "SLAAC"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Dual stack allows devices to run both IPv4 and IPv6 protocols simultaneously. NAT64 translates IPv6 to IPv4. 6to4 tunneling encapsulates IPv6 in IPv4 packets. SLAAC automatically configures IPv6 addresses without DHCPv6.",
      "examTip": "Dual stack ensures seamless IPv6 adoption by maintaining compatibility with existing IPv4 infrastructure."
    },
    {
      "id": 65,
      "question": "Which DNS record type maps a hostname to an IPv6 address?",
      "options": [
        "AAAA",
        "A",
        "CNAME",
        "MX"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The AAAA record maps a hostname to an IPv6 address. A records map hostnames to IPv4 addresses. CNAME records provide aliases for hostnames. MX records specify mail servers for a domain.",
      "examTip": "Remember: 'A' for IPv4 and 'AAAA' for IPv6—easy to recall for DNS configurations."
    },
    {
      "id": 66,
      "question": "Which service allows a host to automatically configure its own IPv6 address without the use of a DHCP server?",
      "options": [
        "SLAAC",
        "DHCPv6",
        "NAT64",
        "Dual stack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SLAAC (Stateless Address Autoconfiguration) enables a device to generate its own IPv6 address using router advertisements without DHCPv6. DHCPv6 requires a server for address allocation. NAT64 translates IPv6 traffic to IPv4. Dual stack allows IPv4 and IPv6 coexistence but doesn't handle address configuration independently.",
      "examTip": "SLAAC is often the default method for IPv6 addressing when minimal configuration is desired."
    },
    {
      "id": 67,
      "question": "Which network device operates at the OSI model’s Layer 2 and forwards data based on MAC addresses?",
      "options": [
        "Switch",
        "Router",
        "Hub",
        "Firewall"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A switch operates at Layer 2, forwarding frames based on MAC addresses. Routers work at Layer 3, forwarding packets based on IP addresses. Hubs broadcast all data to every port, operating at Layer 1. Firewalls filter traffic based on security rules and typically operate at Layers 3 and 4.",
      "examTip": "Remember: Switch = Layer 2 = MAC addresses; Router = Layer 3 = IP addresses."
    },
    {
      "id": 68,
      "question": "Which wireless security protocol offers the STRONGEST protection for modern Wi-Fi networks?",
      "options": [
        "WPA3",
        "WPA2",
        "WPA",
        "WEP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3 offers the most robust wireless encryption, improving security against brute-force attacks. WPA2 remains widely used but has known vulnerabilities. WPA is outdated and less secure. WEP is easily compromised and no longer considered secure.",
      "examTip": "Always select WPA3 for the highest wireless security when supported by devices."
    },
    {
      "id": 69,
      "question": "A network engineer needs to prevent network loops in a switched network. Which protocol should be implemented?",
      "options": [
        "STP",
        "OSPF",
        "RIP",
        "BGP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "STP (Spanning Tree Protocol) prevents loops in Layer 2 networks by blocking redundant paths. OSPF, RIP, and BGP are routing protocols that operate at Layer 3 and do not prevent Layer 2 switching loops.",
      "examTip": "Use STP to ensure loop-free topology in Ethernet networks, especially in redundant link scenarios."
    },
    {
      "id": 70,
      "question": "Which port is used by HTTPS for secure web communication?",
      "options": [
        "443",
        "80",
        "22",
        "25"
      ],
      "correctAnswerIndex": 0,
      "explanation": "HTTPS uses port 443 to secure web traffic using encryption. Port 80 is for HTTP (unencrypted web traffic). Port 22 is used by SSH. Port 25 is associated with SMTP for email transmission.",
      "examTip": "Quick port recall: 80 (HTTP), 443 (HTTPS), 22 (SSH), 25 (SMTP)."
    },
    {
      "id": 71,
      "question": "Which protocol is responsible for synchronizing clocks on network devices?",
      "options": [
        "NTP",
        "SNMP",
        "LDAP",
        "TFTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NTP (Network Time Protocol) synchronizes time across network devices. SNMP manages and monitors network devices. LDAP provides directory services. TFTP transfers files without encryption.",
      "examTip": "Accurate time synchronization via NTP is crucial for log analysis, security events, and authentication protocols."
    },
    {
      "id": 72,
      "question": "Which cloud deployment model combines public and private clouds, allowing data and applications to be shared between them?",
      "options": [
        "Hybrid cloud",
        "Public cloud",
        "Private cloud",
        "Community cloud"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Hybrid cloud combines public and private cloud environments, offering flexibility and scalability. Public clouds are shared among multiple organizations. Private clouds are exclusive to one organization. Community clouds are shared by organizations with similar interests.",
      "examTip": "Hybrid cloud is ideal for businesses needing the flexibility of public clouds with the control of private clouds."
    },
    {
      "id": 73,
      "question": "Which service model in cloud computing provides users with applications over the internet without managing underlying infrastructure?",
      "options": [
        "SaaS",
        "IaaS",
        "PaaS",
        "FaaS"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SaaS (Software as a Service) delivers software applications over the internet without user management of infrastructure. IaaS provides infrastructure resources. PaaS offers a platform for application development. FaaS (Function as a Service) provides event-driven execution environments.",
      "examTip": "SaaS = End-user applications (e.g., Gmail, Salesforce); minimal management responsibility for users."
    },
    {
      "id": 74,
      "question": "Which addressing method is used when a device sends traffic to the nearest node in a group of potential receivers?",
      "options": [
        "Anycast",
        "Unicast",
        "Multicast",
        "Broadcast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Anycast delivers traffic to the nearest node in a group based on routing metrics, often used for load balancing. Unicast sends traffic to a single device. Multicast sends to multiple specified recipients. Broadcast sends to all devices in a network segment.",
      "examTip": "Anycast improves response times in global services like DNS by routing traffic to the closest server."
    },
    {
      "id": 75,
      "question": "Which tool can be used to determine the route taken by packets across an IP network?",
      "options": [
        "traceroute",
        "ping",
        "netstat",
        "arp"
      ],
      "correctAnswerIndex": 0,
      "explanation": "traceroute identifies each hop along the path between two devices. ping checks basic connectivity. netstat shows active connections and routing tables. arp displays IP-to-MAC address mappings.",
      "examTip": "Use traceroute for diagnosing where traffic is being delayed or dropped in a network path."
    },
    {
      "id": 76,
      "question": "Which topology connects all devices to a central device, such as a switch, where the failure of the central device brings down the entire network?",
      "options": [
        "Star",
        "Bus",
        "Ring",
        "Mesh"
      ],
      "correctAnswerIndex": 0,
      "explanation": "In a star topology, all devices connect to a central device; if the central device fails, the entire network is affected. Bus topology uses a single backbone cable. Ring topology connects devices in a loop. Mesh topology provides multiple redundant connections between devices.",
      "examTip": "Star topology is popular due to easy management and scalability, but the central device is a single point of failure."
    },
    {
      "id": 77,
      "question": "Which protocol uses port 3389 and provides remote graphical access to Windows systems?",
      "options": [
        "RDP",
        "SSH",
        "VNC",
        "Telnet"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RDP (Remote Desktop Protocol) operates on port 3389, allowing remote graphical access to Windows systems. SSH provides secure command-line access over port 22. VNC provides graphical remote access but uses different ports (typically 5900). Telnet provides unencrypted command-line access over port 23.",
      "examTip": "RDP is the standard for remote Windows desktop access—ensure port 3389 is properly secured in firewalls."
    },
    {
      "id": 78,
      "question": "Which type of network traffic is sent from one sender to all devices in the network segment?",
      "options": [
        "Broadcast",
        "Unicast",
        "Multicast",
        "Anycast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Broadcast traffic is sent to all devices within a network segment. Unicast is sent to a single recipient. Multicast targets a specific group. Anycast sends data to the nearest node in a group.",
      "examTip": "Excessive broadcasts can cause performance issues—VLAN segmentation helps reduce unnecessary broadcast traffic."
    },
    {
      "id": 79,
      "question": "Which cable type is MOST suitable for 10Gbps speeds over short distances, such as connections between network devices in the same rack?",
      "options": [
        "Direct attach copper",
        "Single-mode fiber",
        "Multimode fiber",
        "Coaxial cable"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DAC (Direct attach copper) cables provide high-speed (up to 10Gbps) connectivity over short distances (typically within racks). Single-mode fiber supports longer distances but at higher cost. Multimode fiber supports high speeds but over moderate distances. Coaxial cables are not used for high-speed, short-distance networking between devices.",
      "examTip": "DAC cables are cost-effective for short, high-speed connections within data centers."
    },
    {
      "id": 80,
      "question": "Which protocol uses port 389 and provides access to directory services for authentication and authorization purposes?",
      "options": [
        "LDAP",
        "RADIUS",
        "TACACS+",
        "SNMP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "LDAP (Lightweight Directory Access Protocol) uses port 389 for accessing directory services. RADIUS provides user authentication but uses ports 1812/1813. TACACS+ provides device administration access. SNMP monitors network devices.",
      "examTip": "LDAP is widely used for centralized authentication (e.g., Microsoft Active Directory)."
    },
    {
      "id": 81,
      "question": "Which technology uses port security by limiting access to a switch port based on MAC address?",
      "options": [
        "Network Access Control",
        "802.1X",
        "Port mirroring",
        "Spanning Tree Protocol"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NAC (Network Access Control) enforces security policies by restricting access based on device properties like MAC addresses. 802.1X provides port-based authentication. Port mirroring duplicates traffic for monitoring. STP prevents Layer 2 loops but does not handle port security.",
      "examTip": "Use NAC for endpoint compliance, ensuring only authorized devices access network resources."
    },
    {
      "id": 82,
      "question": "Which attack involves sending fraudulent ARP messages to associate the attacker’s MAC address with the IP address of a legitimate device?",
      "options": [
        "ARP poisoning",
        "DNS spoofing",
        "Phishing",
        "MAC flooding"
      ],
      "correctAnswerIndex": 0,
      "explanation": "ARP poisoning tricks devices into associating the attacker’s MAC address with a legitimate IP address, allowing data interception. DNS spoofing manipulates DNS data. Phishing deceives users into revealing sensitive information. MAC flooding overwhelms switches with MAC addresses, forcing them to broadcast traffic.",
      "examTip": "Dynamic ARP inspection and static ARP entries help mitigate ARP poisoning attacks."
    },
    {
      "id": 83,
      "question": "Which device is designed to detect and alert administrators to potential security threats but does NOT block malicious traffic?",
      "options": [
        "IDS",
        "IPS",
        "Firewall",
        "Proxy server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An IDS (Intrusion Detection System) monitors network traffic for suspicious activity and alerts administrators. IPS (Intrusion Prevention System) detects and blocks malicious traffic. Firewalls block unauthorized access based on rules. Proxy servers act as intermediaries but do not detect intrusions.",
      "examTip": "Use IDS for monitoring and IPS for both detection and active prevention of threats."
    },
    {
      "id": 84,
      "question": "Which protocol provides secure remote access to network devices by encrypting traffic and operates over port 22?",
      "options": [
        "SSH",
        "Telnet",
        "FTP",
        "RDP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH (Secure Shell) encrypts traffic for secure remote access over port 22. Telnet operates over port 23 but lacks encryption. FTP transfers files over ports 20/21 without encryption. RDP provides graphical remote access over port 3389.",
      "examTip": "Always use SSH instead of Telnet to prevent credential interception during remote sessions."
    },
    {
      "id": 85,
      "question": "Which wireless standard introduced MU-MIMO (Multi-User Multiple Input Multiple Output) technology for better performance in multi-user environments?",
      "options": [
        "802.11ac",
        "802.11n",
        "802.11g",
        "802.11a"
      ],
      "correctAnswerIndex": 0,
      "explanation": "802.11ac introduced MU-MIMO, allowing multiple devices to communicate simultaneously, improving throughput. 802.11n supports MIMO but not MU-MIMO. 802.11g and 802.11a do not support MIMO technologies.",
      "examTip": "MU-MIMO in 802.11ac significantly boosts performance in environments with multiple active users."
    },
    {
      "id": 86,
      "question": "Which type of IPv6 address is used to communicate with all devices on a local network segment?",
      "options": [
        "Multicast",
        "Anycast",
        "Unicast",
        "Global unicast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Multicast addresses in IPv6 are used to communicate with multiple devices on a local network segment simultaneously. Anycast delivers data to the nearest node in a group. Unicast addresses are used for one-to-one communication. Global unicast addresses are similar to IPv4 public addresses and are used for internet routing.",
      "examTip": "IPv6 multicast addresses begin with FF00::/8—commonly used for services like DHCPv6 and routing protocols."
    },
    {
      "id": 87,
      "question": "A technician is troubleshooting network connectivity issues. Which command would BEST help verify the current IP configuration on a Windows host?",
      "options": [
        "ipconfig",
        "ping",
        "tracert",
        "netstat"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 'ipconfig' command displays the current IP configuration on a Windows host, including IP address, subnet mask, and default gateway. 'ping' tests connectivity to another host. 'tracert' shows the path taken by packets to reach a destination. 'netstat' displays active network connections and listening ports.",
      "examTip": "For quick verification of IP settings on Windows, 'ipconfig' is the go-to command."
    },
    {
      "id": 88,
      "question": "Which type of fiber optic cable is BEST suited for long-distance transmissions of 10km or more?",
      "options": [
        "Single-mode fiber",
        "Multimode fiber",
        "Direct attach copper",
        "Coaxial cable"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Single-mode fiber uses a narrow core and laser light source, allowing data transmission over long distances (tens of kilometers) with minimal signal loss. Multimode fiber supports shorter distances due to modal dispersion. Direct attach copper is used for short distances within racks. Coaxial cables are not suitable for long-distance high-speed data transmission.",
      "examTip": "Single-mode fiber = Long-distance + High speed; Multimode fiber = Short to medium distances."
    },
    {
      "id": 89,
      "question": "Which layer of the OSI model is responsible for establishing, maintaining, and terminating communication sessions between applications?",
      "options": [
        "Session layer",
        "Presentation layer",
        "Transport layer",
        "Application layer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The Session layer (Layer 5) manages sessions between applications, including establishing, maintaining, and terminating connections. The Presentation layer (Layer 6) handles data formatting and encryption. The Transport layer (Layer 4) ensures reliable data transmission. The Application layer (Layer 7) provides services directly to user applications.",
      "examTip": "Session = Connection management; Presentation = Data translation; Transport = Reliable delivery."
    },
    {
      "id": 90,
      "question": "A user reports that their device cannot obtain an IP address and shows an address in the 169.254.x.x range. Which service is MOST likely unavailable?",
      "options": [
        "DHCP",
        "DNS",
        "NAT",
        "SNMP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An address in the 169.254.x.x range indicates APIPA is being used because the device cannot contact a DHCP server. DNS issues would result in problems resolving hostnames but would not affect IP assignment. NAT translates private addresses but is unrelated to local IP allocation. SNMP manages and monitors network devices but doesn’t assign IP addresses.",
      "examTip": "169.254.x.x = DHCP server unreachable; check DHCP services and connectivity."
    },
    {
      "id": 91,
      "question": "Which command is used on Linux systems to display or configure network interfaces?",
      "options": [
        "ifconfig",
        "ping",
        "traceroute",
        "netstat"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'ifconfig' displays or configures network interfaces on Linux systems. 'ping' checks connectivity. 'traceroute' shows the path packets take to a destination. 'netstat' displays network connections and routing tables.",
      "examTip": "'ifconfig' is being replaced by 'ip addr' on modern Linux systems but remains widely used in troubleshooting."
    },
    {
      "id": 92,
      "question": "Which device provides redundancy by allowing multiple network connections to appear as a single logical connection, enhancing both bandwidth and fault tolerance?",
      "options": [
        "Switch with LACP",
        "Router using NAT",
        "Firewall with ACLs",
        "Access point with band steering"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A switch using LACP (Link Aggregation Control Protocol) combines multiple physical links into a single logical link for redundancy and increased bandwidth. Routers using NAT manage IP address translation. Firewalls with ACLs filter traffic but do not aggregate links. Access points with band steering direct clients to optimal frequencies but do not enhance bandwidth via link aggregation.",
      "examTip": "LACP (802.3ad) is commonly used for dynamic link aggregation, especially in data center environments."
    },
    {
      "id": 93,
      "question": "Which protocol encrypts network traffic at the IP layer and is commonly used in VPNs for secure communication?",
      "options": [
        "IPSec",
        "TLS",
        "SSH",
        "GRE"
      ],
      "correctAnswerIndex": 0,
      "explanation": "IPSec (Internet Protocol Security) encrypts data at the IP layer, making it ideal for VPNs. TLS secures application-layer communications like HTTPS. SSH provides secure remote access and file transfers. GRE provides tunneling without encryption unless paired with IPSec.",
      "examTip": "For VPNs, IPSec ensures secure tunneling and encryption at the network layer."
    },
    {
      "id": 94,
      "question": "Which type of attack involves overwhelming a network device or service with excessive traffic, rendering it unavailable to users?",
      "options": [
        "DDoS attack",
        "Phishing attack",
        "Man-in-the-middle attack",
        "ARP spoofing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A DDoS (Distributed Denial of Service) attack floods a target with excessive traffic from multiple sources, disrupting service availability. Phishing attacks trick users into providing sensitive information. Man-in-the-middle attacks intercept communications. ARP spoofing redirects traffic by manipulating ARP tables.",
      "examTip": "Implement rate limiting and robust firewalls to mitigate DDoS attacks."
    },
    {
      "id": 95,
      "question": "Which type of connector is commonly used with coaxial cables in networking environments, providing a secure locking mechanism?",
      "options": [
        "BNC",
        "RJ45",
        "LC",
        "SC"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BNC connectors are used with coaxial cables and provide a secure bayonet-style locking mechanism. RJ45 connectors are used with twisted-pair Ethernet cables. LC and SC connectors are used with fiber optic cables.",
      "examTip": "BNC connectors are typical in legacy networks and specialized applications like CCTV systems."
    },
    {
      "id": 96,
      "question": "Which service is responsible for translating domain names into corresponding IP addresses?",
      "options": [
        "DNS",
        "DHCP",
        "NAT",
        "SNMP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DNS (Domain Name System) translates domain names into IP addresses, enabling users to access resources using easy-to-remember names. DHCP assigns IP addresses to hosts. NAT translates private IP addresses to public ones. SNMP is used for network device management.",
      "examTip": "If web addresses aren't resolving, start troubleshooting with DNS settings and server availability."
    },
    {
      "id": 97,
      "question": "Which Wi-Fi frequency band offers faster speeds with less interference but shorter range?",
      "options": [
        "5GHz",
        "2.4GHz",
        "900MHz",
        "60GHz"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 5GHz band provides faster speeds and less interference but has a shorter range compared to 2.4GHz. The 2.4GHz band offers broader coverage but is more prone to interference. 900MHz is used for longer-range, lower-speed applications. 60GHz is used for ultra-high-speed, short-range wireless connections like WiGig.",
      "examTip": "Use 5GHz for performance-focused environments and 2.4GHz where range is a priority."
    },
    {
      "id": 98,
      "question": "Which routing protocol uses cost as its metric and builds a complete map of the network using the Dijkstra algorithm?",
      "options": [
        "OSPF",
        "RIP",
        "BGP",
        "EIGRP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "OSPF (Open Shortest Path First) uses cost (based on link speed) as its metric and builds a network map using the Dijkstra algorithm. RIP uses hop count as its metric. BGP uses path attributes for routing between autonomous systems. EIGRP uses a composite metric including bandwidth and delay.",
      "examTip": "OSPF is a preferred IGP for large enterprise networks due to its efficient convergence and scalability."
    },
    {
      "id": 99,
      "question": "Which type of IPv6 address is used for communication between devices on the same link and begins with FE80::/10?",
      "options": [
        "Link-local address",
        "Global unicast address",
        "Multicast address",
        "Anycast address"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Link-local addresses in IPv6 begin with FE80::/10 and are used for communication within the same link or subnet. Global unicast addresses are globally routable. Multicast addresses are used for group communication. Anycast addresses route traffic to the nearest node in a group.",
      "examTip": "Link-local addresses are automatically assigned and required for IPv6-enabled interfaces for local network communication."
    },
    {
      "id": 100,
      "question": "Which protocol provides secure, encrypted file transfers and uses port 22 by leveraging SSH?",
      "options": [
        "SFTP",
        "FTP",
        "TFTP",
        "SCP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SFTP (SSH File Transfer Protocol) operates over port 22, providing secure file transfer by leveraging SSH. FTP (ports 20/21) is unencrypted. TFTP (port 69) provides simple, unencrypted file transfers. SCP also uses SSH and port 22 but is typically used for direct file copying, lacking full file management capabilities that SFTP offers.",
      "examTip": "For secure file transfers with robust management features, SFTP is preferred over SCP or FTP."
    }
  ]
});
