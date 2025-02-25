db.tests.insertOne({
  "category": "nplus",
  "testId": 3,
  "testName": "Network+ Practice Test #3 (Easy)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A user cannot access a website by its domain name but can access it using the IP address. Which service is MOST likely causing the issue?",
      "options": [
        "DNS",
        "DHCP",
        "NAT",
        "SNMP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DNS resolves domain names to IP addresses. If the website works with an IP address but not with its domain name, it's likely a DNS issue. DHCP assigns IP configurations. NAT handles address translation, and SNMP monitors network devices.",
      "examTip": "Domain not resolving? Always check DNS settings or server reachability first."
    },
    {
      "id": 2,
      "question": "Which of the following would BEST prevent unauthorized devices from connecting to a corporate wireless network?",
      "options": [
        "Implement WPA3 encryption",
        "Enable MAC filtering",
        "Disable SSID broadcast",
        "Use a guest Wi-Fi network"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3 encryption provides the strongest security, preventing unauthorized access even if SSID is known. MAC filtering can be bypassed. Disabling SSID broadcast offers only minimal security through obscurity. Guest Wi-Fi networks are for visitor access, not prevention of unauthorized connections.",
      "examTip": "Always prioritize strong encryption like WPA3 over methods like MAC filtering or SSID hiding."
    },
    {
      "id": 3,
      "question": "A network administrator needs to reduce broadcast traffic on a LAN. Which solution is MOST appropriate?",
      "options": [
        "Create VLANs",
        "Add more hubs",
        "Use a repeater",
        "Deploy additional switches"
      ],
      "correctAnswerIndex": 0,
      "explanation": "VLANs (Virtual Local Area Networks) segment a LAN, reducing broadcast domains. Hubs increase unnecessary traffic. Repeaters extend signals but don’t control broadcasts. Additional switches without VLAN configuration won’t limit broadcast traffic.",
      "examTip": "VLANs = Virtual segmentation; the best way to reduce broadcast storms."
    },
    {
      "id": 4,
      "question": "Which protocol should be used to securely manage and monitor network devices?",
      "options": [
        "SNMPv3",
        "FTP",
        "Telnet",
        "SNMPv2c"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SNMPv3 adds encryption and authentication for secure management of network devices. SNMPv2c lacks encryption. FTP is for file transfers and is unencrypted. Telnet provides unencrypted remote access.",
      "examTip": "SNMPv3 = Security first. Always choose v3 for encrypted device monitoring."
    },
    {
      "id": 5,
      "question": "A server requires both high-speed performance and low latency storage access. Which solution BEST meets this need?",
      "options": [
        "Storage Area Network (SAN)",
        "Network Attached Storage (NAS)",
        "External USB drive",
        "Cloud storage"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A SAN offers high-speed, low-latency storage access, ideal for performance-critical applications. NAS is file-level storage and slower. External drives and cloud storage don’t meet the performance needs for enterprise-level applications.",
      "examTip": "SAN = Fast + Flexible + Scalable storage for critical enterprise systems."
    },
    {
      "id": 6,
      "question": "Which wireless network configuration ensures data confidentiality even if someone intercepts the traffic?",
      "options": [
        "WPA3 encryption",
        "SSID broadcast disabled",
        "MAC address filtering",
        "Open network with captive portal"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3 encryption secures data in transit. Disabling SSID broadcast or using MAC filtering only adds superficial protection. Open networks with captive portals do not encrypt traffic.",
      "examTip": "Encryption like WPA3 is always the best defense against eavesdropping."
    },
    {
      "id": 7,
      "question": "Which type of IP address allows multiple users in a private network to access the internet using a single public IP?",
      "options": [
        "NAT",
        "APIPA",
        "Loopback",
        "Multicast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NAT (Network Address Translation) allows multiple private IP addresses to share a single public IP for internet access. APIPA is for local addressing when DHCP fails. Loopback is for internal host testing. Multicast is for group communications.",
      "examTip": "NAT = One public IP for many private users — key for IPv4 efficiency."
    },
    {
      "id": 8,
      "question": "A technician needs to connect two buildings 500 meters apart with minimal interference. Which cable type is BEST?",
      "options": [
        "Single-mode fiber",
        "Cat 6 Ethernet cable",
        "Coaxial cable",
        "Multimode fiber"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Single-mode fiber supports long-distance, high-speed connections with minimal interference. Cat 6 Ethernet cables are limited to shorter distances. Coaxial is not suitable for long-distance data transmission. Multimode fiber supports moderate distances but less than single-mode.",
      "examTip": "Single-mode = Long distance + High speed + Minimal interference."
    },
    {
      "id": 9,
      "question": "Which network service automatically assigns IP addresses to devices on a network?",
      "options": [
        "DHCP",
        "DNS",
        "NAT",
        "SNMP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DHCP (Dynamic Host Configuration Protocol) assigns IP addresses dynamically. DNS resolves domain names. NAT translates private to public IPs. SNMP monitors network devices.",
      "examTip": "DHCP = Plug and play IP addressing; reduces manual configuration errors."
    },
    {
      "id": 10,
      "question": "Which wireless frequency band provides better range but is more prone to interference?",
      "options": [
        "2.4GHz",
        "5GHz",
        "6GHz",
        "60GHz"
      ],
      "correctAnswerIndex": 0,
      "explanation": "2.4GHz offers better range but is more susceptible to interference from common devices. 5GHz and 6GHz offer faster speeds with less interference but shorter ranges. 60GHz is ultra-fast but for very short ranges.",
      "examTip": "2.4GHz = Range; 5GHz = Speed. Choose based on user and environment needs."
    },
    {
      "id": 11,
      "question": "Which OSI model layer is responsible for end-to-end communication, reliability, and flow control?",
      "options": [
        "Transport layer",
        "Network layer",
        "Presentation layer",
        "Data link layer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The Transport layer (Layer 4) manages end-to-end communication, ensuring data reliability using TCP. The Network layer handles routing. The Presentation layer formats and encrypts data. The Data link layer handles physical addressing.",
      "examTip": "Transport = Trustworthy delivery; TCP ensures reliability at this layer."
    },
    {
      "id": 12,
      "question": "A user reports slow network performance. Which tool would BEST help analyze packet flow and detect bottlenecks?",
      "options": [
        "Protocol analyzer",
        "Ping",
        "Traceroute",
        "Cable tester"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A protocol analyzer (packet sniffer) examines network traffic at a granular level, helping detect bottlenecks. Ping checks basic connectivity. Traceroute identifies routing paths. Cable testers verify cable integrity but don’t analyze traffic flow.",
      "examTip": "Protocol analyzer = Deep network insight; essential for diagnosing performance issues."
    },
    {
      "id": 13,
      "question": "Which wireless standard introduced MU-MIMO technology, enhancing performance in multi-user environments?",
      "options": [
        "802.11ac",
        "802.11n",
        "802.11g",
        "802.11a"
      ],
      "correctAnswerIndex": 0,
      "explanation": "802.11ac introduced MU-MIMO, enabling simultaneous data streams to multiple devices. 802.11n supports MIMO but not MU-MIMO. 802.11g and 802.11a don’t support MIMO technologies.",
      "examTip": "802.11ac = Advanced performance with MU-MIMO; ideal for busy wireless networks."
    },
    {
      "id": 14,
      "question": "Which port is used by Secure Shell (SSH) for encrypted remote access?",
      "options": [
        "22",
        "23",
        "443",
        "80"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH uses port 22 for secure remote access. Telnet uses port 23 but is insecure. Port 443 is for HTTPS, and port 80 is for HTTP.",
      "examTip": "SSH = Secure remote shell = Port 22; always preferred over Telnet for security."
    },
    {
      "id": 15,
      "question": "Which addressing type allows one sender to communicate with multiple recipients without sending to all devices?",
      "options": [
        "Multicast",
        "Broadcast",
        "Unicast",
        "Anycast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Multicast sends data to multiple specified recipients. Broadcast sends data to all devices in a network. Unicast is one-to-one. Anycast sends data to the nearest node in a group.",
      "examTip": "Multicast = Targeted group communication; efficient for streaming and conferencing."
    },
    {
      "id": 16,
      "question": "Which routing protocol uses hop count as its primary metric and has a maximum limit of 15 hops?",
      "options": [
        "RIP",
        "OSPF",
        "BGP",
        "EIGRP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RIP (Routing Information Protocol) uses hop count with a 15-hop limit. OSPF uses cost based on bandwidth. BGP uses path attributes. EIGRP uses a composite metric including bandwidth and delay.",
      "examTip": "RIP = Simple but limited; hop count ≤ 15 means limited scalability."
    },
    {
      "id": 17,
      "question": "Which protocol ensures time synchronization across network devices?",
      "options": [
        "NTP",
        "SNMP",
        "DNS",
        "TFTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NTP (Network Time Protocol) synchronizes time across network devices. SNMP monitors devices. DNS resolves hostnames. TFTP transfers files without authentication.",
      "examTip": "NTP = Accurate time, accurate logs; critical for security and troubleshooting."
    },
    {
      "id": 18,
      "question": "Which IPv6 address type is automatically assigned for communication between devices on the same link and starts with FE80::?",
      "options": [
        "Link-local address",
        "Global unicast address",
        "Multicast address",
        "Anycast address"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Link-local addresses (starting with FE80::) are automatically assigned for communication on the same link. Global unicast addresses are globally routable. Multicast addresses target multiple recipients. Anycast sends to the nearest node.",
      "examTip": "Link-local = Local link only; always starts with FE80:: in IPv6."
    },
    {
      "id": 19,
      "question": "Which network tool would help identify duplicate IP addresses on a network?",
      "options": [
        "arp",
        "ping",
        "traceroute",
        "ipconfig"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 'arp' command displays IP-to-MAC address mappings, helping detect duplicate IP issues. 'ping' checks connectivity. 'traceroute' tracks packet paths. 'ipconfig' shows IP configurations but doesn't reveal duplicates.",
      "examTip": "arp = Address Resolution Protocol; use to uncover IP/MAC conflicts."
    },
    {
      "id": 20,
      "question": "Which wireless security standard uses AES encryption and is currently considered the MOST secure?",
      "options": [
        "WPA3",
        "WPA2",
        "WPA",
        "WEP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3 provides the strongest wireless encryption using AES, improving protection against brute-force attacks. WPA2 uses AES but lacks WPA3’s enhancements. WPA is outdated, and WEP is insecure and obsolete.",
      "examTip": "WPA3 = Latest and strongest Wi-Fi encryption; always use when available."
    },
    {
      "id": 21,
      "question": "A network administrator wants to ensure that only authorized users can access a secure server by verifying both a password and a code sent to their mobile device. Which security method is being used?",
      "options": [
        "Multifactor authentication (MFA)",
        "Single sign-on (SSO)",
        "Role-based access control (RBAC)",
        "Least privilege access"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Multifactor authentication (MFA) requires two or more verification methods, such as a password and a code sent to a mobile device. SSO allows users to access multiple systems with one set of credentials. RBAC assigns permissions based on user roles. Least privilege access limits users to only the permissions they need.",
      "examTip": "MFA = Multiple forms of proof; something you know + something you have + something you are."
    },
    {
      "id": 22,
      "question": "Which type of network device allows for traffic filtering based on source and destination IP addresses, ports, and protocols?",
      "options": [
        "Firewall",
        "Router",
        "Switch",
        "Repeater"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Firewalls filter network traffic based on rules related to IP addresses, ports, and protocols. Routers forward packets between networks. Switches connect devices within a LAN based on MAC addresses. Repeaters regenerate signals but do not filter traffic.",
      "examTip": "Firewall = Network bouncer; filters traffic at the perimeter based on defined rules."
    },
    {
      "id": 23,
      "question": "Which device would MOST likely be used to prioritize voice traffic over data traffic to prevent latency issues?",
      "options": [
        "Switch with QoS enabled",
        "Load balancer",
        "Repeater",
        "Firewall"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A switch with Quality of Service (QoS) enabled can prioritize voice traffic (VoIP) over data traffic, reducing latency. Load balancers distribute traffic among servers. Repeaters extend signal range. Firewalls provide security but do not prioritize traffic.",
      "examTip": "QoS = Quality of Service = Prioritize critical traffic like voice and video for smooth communication."
    },
    {
      "id": 24,
      "question": "Which of the following BEST describes a hybrid cloud deployment?",
      "options": [
        "Combines public and private cloud resources",
        "A cloud deployment managed entirely by a third party",
        "A private cloud hosted in an on-premises data center",
        "A cloud service offering on-demand software applications"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A hybrid cloud combines public and private cloud resources for flexibility and scalability. Public clouds are managed by third parties. Private clouds are on-premises or dedicated to one organization. On-demand software applications are part of the SaaS model.",
      "examTip": "Hybrid cloud = Flexibility; best of both worlds combining public and private clouds."
    },
    {
      "id": 25,
      "question": "Which of the following wireless standards provides the HIGHEST throughput and operates exclusively in the 5GHz band?",
      "options": [
        "802.11ac",
        "802.11n",
        "802.11g",
        "802.11a"
      ],
      "correctAnswerIndex": 0,
      "explanation": "802.11ac offers the highest throughput among the listed options and operates exclusively in the 5GHz band. 802.11n supports both 2.4GHz and 5GHz but with lower speeds. 802.11g and 802.11a support lower speeds (54 Mbps).",
      "examTip": "802.11ac = 'ac'celerated speeds in 5GHz; best for modern, high-speed Wi-Fi networks."
    },
    {
      "id": 26,
      "question": "Which routing protocol is designed for large enterprise networks and uses link-state information to determine the best path?",
      "options": [
        "OSPF",
        "RIP",
        "BGP",
        "EIGRP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "OSPF (Open Shortest Path First) uses link-state information and the Dijkstra algorithm for path determination. RIP uses hop count. BGP is used for routing between autonomous systems on the internet. EIGRP uses a hybrid approach (Cisco proprietary).",
      "examTip": "OSPF = Optimal for large networks with fast convergence and scalable architecture."
    },
    {
      "id": 27,
      "question": "Which cable type is MOST appropriate for high-speed, short-distance connections between servers in a data center?",
      "options": [
        "Direct Attach Copper (DAC)",
        "Single-mode fiber",
        "Coaxial cable",
        "Category 5e Ethernet"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Direct Attach Copper (DAC) cables are designed for high-speed, short-distance server connections in data centers. Single-mode fiber is for long distances. Coaxial cables are outdated for data centers. Cat 5e supports gigabit speeds but is less optimal than DAC for such applications.",
      "examTip": "DAC = Data center direct connect — short distance, high speed, low cost."
    },
    {
      "id": 28,
      "question": "Which addressing scheme allows multiple networks to share the same IP range without conflict by using different subnet masks?",
      "options": [
        "VLSM",
        "APIPA",
        "NAT",
        "IPv6"
      ],
      "correctAnswerIndex": 0,
      "explanation": "VLSM (Variable Length Subnet Mask) allows different subnet masks in the same network, supporting efficient IP address allocation. APIPA assigns local IPs when DHCP fails. NAT translates private to public IPs. IPv6 provides a larger address space.",
      "examTip": "VLSM = Efficient subnetting; customize subnet sizes to fit network needs."
    },
    {
      "id": 29,
      "question": "Which IPv6 feature allows both IPv4 and IPv6 to operate on the same network until full IPv6 adoption?",
      "options": [
        "Dual stack",
        "Tunneling",
        "NAT64",
        "Anycast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Dual stack allows both IPv4 and IPv6 to operate simultaneously. Tunneling encapsulates IPv6 traffic in IPv4 packets. NAT64 translates IPv6 to IPv4. Anycast routes to the nearest node in a group.",
      "examTip": "Dual stack = Dual compatibility; smooth IPv6 transition while maintaining IPv4."
    },
    {
      "id": 30,
      "question": "A network technician is asked to configure a switch port for voice traffic. Which configuration is MOST appropriate?",
      "options": [
        "Assign a voice VLAN to the port",
        "Enable port mirroring",
        "Disable PoE on the port",
        "Configure link aggregation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Assigning a voice VLAN ensures proper QoS and traffic segmentation for voice communications. Port mirroring copies traffic for analysis. Disabling PoE may affect IP phones. Link aggregation combines multiple ports for redundancy and bandwidth, not voice optimization.",
      "examTip": "Voice VLAN = Clear voice traffic paths + QoS prioritization."
    },
    {
      "id": 31,
      "question": "Which type of fiber optic cable is typically used for high-bandwidth applications over long distances, such as WAN connections?",
      "options": [
        "Single-mode fiber",
        "Multimode fiber",
        "Coaxial cable",
        "Twisted-pair cable"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Single-mode fiber supports long-distance, high-bandwidth transmissions, ideal for WAN links. Multimode fiber supports shorter distances. Coaxial and twisted-pair cables are not suitable for high-bandwidth, long-distance connections.",
      "examTip": "Single-mode = Single, straight path for light; best for long-haul, high-speed links."
    },
    {
      "id": 32,
      "question": "Which tool is MOST appropriate for capturing and analyzing network traffic for security and performance troubleshooting?",
      "options": [
        "Protocol analyzer",
        "Cable tester",
        "Toner probe",
        "Wi-Fi analyzer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A protocol analyzer captures and analyzes network traffic for performance and security troubleshooting. Cable testers check cable integrity. Toner probes locate cables. Wi-Fi analyzers assess wireless signal strength and coverage.",
      "examTip": "Protocol analyzer = Deep packet inspection for advanced troubleshooting."
    },
    {
      "id": 33,
      "question": "Which network topology provides the highest fault tolerance but at the cost of increased complexity and expense?",
      "options": [
        "Mesh",
        "Star",
        "Bus",
        "Ring"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A mesh topology provides the highest fault tolerance by connecting every node to every other node, but it’s expensive and complex. Star topologies are simpler but depend on a central hub. Bus and ring topologies offer lower fault tolerance.",
      "examTip": "Mesh = Maximum redundancy; critical networks demand it despite higher costs."
    },
    {
      "id": 34,
      "question": "Which port is commonly used by Remote Desktop Protocol (RDP)?",
      "options": [
        "3389",
        "443",
        "22",
        "80"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RDP uses port 3389 for remote desktop access. Port 443 is for HTTPS, port 22 is for SSH, and port 80 is for HTTP.",
      "examTip": "RDP = Remote Desktop = Port 3389 — ensure it’s secured when exposed externally."
    },
    {
      "id": 35,
      "question": "Which type of network device manages distribution of network traffic across multiple servers to optimize performance?",
      "options": [
        "Load balancer",
        "Firewall",
        "Switch",
        "Router"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A load balancer distributes incoming traffic across multiple servers, optimizing performance and preventing overload. Firewalls secure networks. Switches forward traffic in a LAN. Routers direct traffic between networks.",
      "examTip": "Load balancer = Even workload distribution = High availability + Scalability."
    },
    {
      "id": 36,
      "question": "Which port is used by the Lightweight Directory Access Protocol (LDAP)?",
      "options": [
        "389",
        "443",
        "3389",
        "21"
      ],
      "correctAnswerIndex": 0,
      "explanation": "LDAP uses port 389 for directory services. Port 443 is for HTTPS, port 3389 for RDP, and port 21 for FTP.",
      "examTip": "LDAP = Directory services = Port 389 (unencrypted) or 636 (secure)."
    },
    {
      "id": 37,
      "question": "Which type of cloud service provides a platform allowing customers to develop, run, and manage applications without infrastructure management?",
      "options": [
        "PaaS",
        "IaaS",
        "SaaS",
        "DaaS"
      ],
      "correctAnswerIndex": 0,
      "explanation": "PaaS (Platform as a Service) provides platforms for application development without infrastructure management. IaaS offers infrastructure components. SaaS delivers ready-to-use applications. DaaS (Desktop as a Service) provides virtual desktops.",
      "examTip": "PaaS = Developer-friendly; code without worrying about infrastructure."
    },
    {
      "id": 38,
      "question": "Which wireless security method provides enterprise-level authentication using RADIUS servers?",
      "options": [
        "WPA2-Enterprise",
        "WPA3-Personal",
        "WPA2-Personal",
        "WEP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA2-Enterprise uses RADIUS servers for enterprise-level authentication. WPA3-Personal and WPA2-Personal use pre-shared keys (PSK). WEP is outdated and insecure.",
      "examTip": "WPA2-Enterprise = Secure + Scalable authentication for organizations."
    },
    {
      "id": 39,
      "question": "Which protocol allows secure, remote access to a network using encryption at the application layer?",
      "options": [
        "SSH",
        "Telnet",
        "HTTP",
        "TFTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH (Secure Shell) provides encrypted remote access at the application layer. Telnet offers unencrypted remote access. HTTP is unencrypted web traffic. TFTP provides basic, unsecured file transfers.",
      "examTip": "SSH = Secure CLI access; always preferred over Telnet for encrypted sessions."
    },
    {
      "id": 40,
      "question": "Which addressing type allows a host to send a packet to all devices in a network segment?",
      "options": [
        "Broadcast",
        "Unicast",
        "Multicast",
        "Anycast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Broadcast addressing sends packets to all devices on a network segment. Unicast is one-to-one. Multicast targets a group of specific devices. Anycast routes to the nearest node in a group.",
      "examTip": "Broadcast = One-to-all communication; can cause congestion if unmanaged."
    },
    {
      "id": 41,
      "question": "Which tool would a network technician MOST likely use to identify incorrect cabling or poor terminations in a network installation?",
      "options": [
        "Cable tester",
        "Toner probe",
        "Wi-Fi analyzer",
        "Loopback plug"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A cable tester checks for wiring continuity, shorts, or incorrect terminations. Toner probes trace cables but do not verify correct wiring. Wi-Fi analyzers evaluate wireless networks, and loopback plugs test port functionality, not cabling.",
      "examTip": "Cable tester = First step in diagnosing physical cable issues."
    },
    {
      "id": 42,
      "question": "Which port does Secure File Transfer Protocol (SFTP) use for secure file transfers?",
      "options": [
        "22",
        "21",
        "20",
        "443"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SFTP uses port 22 as it runs over SSH for secure file transfers. FTP uses ports 20/21 but is unencrypted. Port 443 is used by HTTPS for secure web traffic.",
      "examTip": "SFTP = Secure FTP over SSH (Port 22); think secure shell for file transfers."
    },
    {
      "id": 43,
      "question": "A technician notices that a network switch port shows 'administratively down.' What is the MOST likely cause?",
      "options": [
        "The port has been disabled manually.",
        "A bad Ethernet cable is connected.",
        "The connected device is powered off.",
        "The port is negotiating at the wrong speed."
      ],
      "correctAnswerIndex": 0,
      "explanation": "'Administratively down' indicates the port was disabled via configuration. A bad cable or powered-off device would show different statuses. Speed mismatches typically result in 'err-disabled' or connection errors, not 'administratively down.'",
      "examTip": "Check switch configs for 'shutdown' commands if 'administratively down' is displayed."
    },
    {
      "id": 44,
      "question": "Which of the following would provide redundancy for both power and network connections in a data center?",
      "options": [
        "Dual power supplies and dual network interfaces",
        "Uninterruptible power supply (UPS) only",
        "Single power supply with link aggregation",
        "PoE-enabled switches"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Dual power supplies and network interfaces ensure continuous power and network connectivity. UPS provides power backup but no network redundancy. Link aggregation provides network redundancy but not power. PoE-enabled switches provide power over Ethernet, not redundancy.",
      "examTip": "Redundancy = Duplicate everything critical (power + network paths)."
    },
    {
      "id": 45,
      "question": "Which protocol is used for sending email securely using encryption over port 587?",
      "options": [
        "SMTPS",
        "SMTP",
        "IMAP",
        "POP3"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SMTPS uses port 587 for sending emails securely with encryption. SMTP (port 25) sends emails without encryption. IMAP (port 143) and POP3 (port 110) are for receiving emails, not sending them.",
      "examTip": "SMTPS = Secure email sending (port 587) — 'S' for secure!"
    },
    {
      "id": 46,
      "question": "Which IPv6 feature reduces the size of routing tables by summarizing multiple network routes?",
      "options": [
        "Route aggregation",
        "Dual stack",
        "Anycast addressing",
        "Tunneling"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Route aggregation in IPv6 summarizes routes, optimizing routing tables. Dual stack allows IPv4 and IPv6 coexistence. Anycast directs traffic to the nearest node. Tunneling encapsulates IPv6 packets in IPv4 but doesn’t reduce routing table size.",
      "examTip": "Route aggregation = Efficient routing; fewer entries, faster lookups."
    },
    {
      "id": 47,
      "question": "Which layer of the OSI model is responsible for establishing, managing, and terminating communication sessions between applications?",
      "options": [
        "Session layer",
        "Presentation layer",
        "Transport layer",
        "Network layer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The Session layer (Layer 5) manages sessions between applications. The Presentation layer (Layer 6) handles data translation and encryption. The Transport layer ensures reliable transmission, while the Network layer handles routing.",
      "examTip": "Session layer = 'Session management' — think start, maintain, end communication sessions."
    },
    {
      "id": 48,
      "question": "Which wireless frequency band provides the greatest coverage area but at lower data rates?",
      "options": [
        "2.4GHz",
        "5GHz",
        "6GHz",
        "60GHz"
      ],
      "correctAnswerIndex": 0,
      "explanation": "2.4GHz provides broader coverage but at lower data rates due to higher interference. 5GHz and 6GHz offer faster speeds but shorter ranges. 60GHz is ultra-fast but extremely short-range.",
      "examTip": "2.4GHz = Range over speed; ideal for larger coverage areas with fewer obstructions."
    },
    {
      "id": 49,
      "question": "Which of the following would MOST likely indicate a duplex mismatch between two connected devices?",
      "options": [
        "High number of late collisions",
        "Low signal-to-noise ratio",
        "High bandwidth utilization",
        "Increased interface resets"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Late collisions typically occur when one device runs full-duplex while the other runs half-duplex. Low signal-to-noise ratio indicates interference. High bandwidth usage and interface resets could suggest other issues like congestion or hardware faults.",
      "examTip": "Duplex mismatch = Late collisions. Always verify speed/duplex settings."
    },
    {
      "id": 50,
      "question": "Which network device can dynamically learn MAC addresses and forward traffic based on them?",
      "options": [
        "Switch",
        "Router",
        "Hub",
        "Bridge"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Switches operate at Layer 2 and dynamically learn MAC addresses for efficient data forwarding. Routers work at Layer 3 using IP addresses. Hubs broadcast all traffic. Bridges segment networks but lack advanced switching functions.",
      "examTip": "Switch = Smart traffic forwarding; knows who’s connected to each port."
    },
    {
      "id": 51,
      "question": "Which cloud model provides hardware resources over the internet where customers manage the operating system and applications?",
      "options": [
        "Infrastructure as a Service (IaaS)",
        "Platform as a Service (PaaS)",
        "Software as a Service (SaaS)",
        "Function as a Service (FaaS)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "IaaS offers virtualized computing resources, where users manage the OS and applications. PaaS provides a platform for development without OS management. SaaS offers complete applications. FaaS runs functions without server management.",
      "examTip": "IaaS = Infrastructure provided; you manage OS, apps, and middleware."
    },
    {
      "id": 52,
      "question": "Which command would BEST verify if a DNS server is resolving hostnames correctly?",
      "options": [
        "nslookup",
        "ping",
        "traceroute",
        "ipconfig"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'nslookup' queries DNS servers to resolve hostnames. 'ping' tests connectivity. 'traceroute' shows the packet path. 'ipconfig' displays IP configurations but doesn’t test DNS resolution.",
      "examTip": "nslookup = DNS detective; your go-to tool when name resolution fails."
    },
    {
      "id": 53,
      "question": "A technician needs to allow traffic from the internet to an internal web server. Which firewall rule would BEST accomplish this?",
      "options": [
        "Allow inbound traffic on TCP port 80",
        "Allow outbound traffic on TCP port 443",
        "Allow inbound traffic on UDP port 53",
        "Allow outbound traffic on TCP port 22"
      ],
      "correctAnswerIndex": 0,
      "explanation": "TCP port 80 allows HTTP web traffic. Port 443 is for HTTPS but typically outbound. UDP port 53 is for DNS queries. TCP port 22 is for SSH access, not web server access.",
      "examTip": "Web traffic = Port 80 (HTTP) or 443 (HTTPS); configure inbound rules for external access."
    },
    {
      "id": 54,
      "question": "Which protocol uses port 3389 for remote graphical access to Windows systems?",
      "options": [
        "RDP",
        "SSH",
        "Telnet",
        "VNC"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RDP (Remote Desktop Protocol) uses port 3389 for remote graphical sessions on Windows. SSH (port 22) provides CLI access. Telnet is unencrypted remote CLI. VNC uses port 5900 for cross-platform graphical access.",
      "examTip": "RDP = Remote Desktop = Port 3389; secure this port for remote admin access."
    },
    {
      "id": 55,
      "question": "Which subnet mask would provide the MOST host addresses for a single Class C network?",
      "options": [
        "255.255.255.0",
        "255.255.255.128",
        "255.255.255.192",
        "255.255.255.224"
      ],
      "correctAnswerIndex": 0,
      "explanation": "255.255.255.0 provides 254 usable host addresses. The other masks further divide the network, reducing available host addresses to 126, 62, and 30 respectively.",
      "examTip": "More zeroes in the subnet mask = More hosts per network."
    },
    {
      "id": 56,
      "question": "Which network device would MOST likely be used to perform deep packet inspection for identifying malicious traffic patterns?",
      "options": [
        "Next-Generation Firewall (NGFW)",
        "Router",
        "Switch",
        "Hub"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Next-Generation Firewalls (NGFW) perform deep packet inspection, detecting malicious patterns. Routers direct traffic between networks. Switches connect devices in a LAN. Hubs broadcast traffic to all ports without analysis.",
      "examTip": "NGFW = Beyond traditional firewalls; smarter protection with application awareness."
    },
    {
      "id": 57,
      "question": "Which wireless encryption protocol is the LEAST secure and should be avoided in modern networks?",
      "options": [
        "WEP",
        "WPA2",
        "WPA3",
        "WPA"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WEP (Wired Equivalent Privacy) is outdated and vulnerable. WPA2 and WPA3 provide stronger encryption. WPA is more secure than WEP but less than WPA2/WPA3.",
      "examTip": "NEVER use WEP; opt for WPA3 where possible for optimal wireless security."
    },
    {
      "id": 58,
      "question": "Which protocol securely synchronizes time between network devices?",
      "options": [
        "NTP with NTS",
        "SNMP",
        "DHCP",
        "TFTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NTP with Network Time Security (NTS) provides secure time synchronization. SNMP monitors devices. DHCP assigns IP addresses. TFTP transfers files but is insecure.",
      "examTip": "NTP + NTS = Secure time = Reliable logs and synchronization for security audits."
    },
    {
      "id": 59,
      "question": "Which addressing type in IPv6 allows communication to multiple devices that have joined a specific group?",
      "options": [
        "Multicast",
        "Unicast",
        "Anycast",
        "Broadcast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Multicast sends data to multiple devices in a specific group. Unicast is one-to-one. Anycast delivers data to the nearest node. IPv6 does not use broadcast addressing like IPv4.",
      "examTip": "IPv6 = Efficient multicast usage; no broadcast overhead like IPv4."
    },
    {
      "id": 60,
      "question": "Which device would BEST segment a network into multiple broadcast domains?",
      "options": [
        "Router",
        "Switch",
        "Hub",
        "Repeater"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Routers segment networks into multiple broadcast domains by routing traffic between them. Switches create collision domains but not separate broadcast domains. Hubs and repeaters extend networks but do not segment them.",
      "examTip": "Router = Broadcast domain breaker; each interface = new broadcast domain."
    },
    {
      "id": 61,
      "question": "Which type of DNS record is used to map a domain name to an IPv6 address?",
      "options": [
        "AAAA",
        "A",
        "CNAME",
        "MX"
      ],
      "correctAnswerIndex": 0,
      "explanation": "AAAA records map a domain name to an IPv6 address. 'A' records map domain names to IPv4 addresses. 'CNAME' provides aliases for domains, and 'MX' records define mail exchange servers.",
      "examTip": "Think 'AAAA' = IPv6 (because IPv6 addresses are longer than IPv4)."
    },
    {
      "id": 62,
      "question": "Which protocol uses port 5060 for unencrypted signaling in voice over IP (VoIP) communications?",
      "options": [
        "SIP",
        "RTP",
        "H.323",
        "MGCP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SIP (Session Initiation Protocol) uses port 5060 for unencrypted signaling. RTP handles media streaming. H.323 is another VoIP protocol but uses different ports. MGCP manages VoIP gateways.",
      "examTip": "SIP = Starts the call (signaling) — Port 5060 unencrypted, 5061 encrypted."
    },
    {
      "id": 63,
      "question": "Which of the following wireless security standards is the MOST secure for modern networks?",
      "options": [
        "WPA3",
        "WPA2",
        "WPA",
        "WEP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3 is the most secure, offering enhanced protection against brute-force attacks and better encryption. WPA2 is secure but lacks WPA3's improvements. WPA and WEP are outdated and vulnerable.",
      "examTip": "Always choose WPA3 if available; it's the gold standard in wireless security today."
    },
    {
      "id": 64,
      "question": "Which type of fiber optic connector uses a push-pull mechanism and is commonly used due to its small form factor?",
      "options": [
        "LC",
        "SC",
        "ST",
        "BNC"
      ],
      "correctAnswerIndex": 0,
      "explanation": "LC (Lucent Connector) uses a push-pull mechanism and has a compact form factor. SC is larger but also uses push-pull. ST uses a twist-lock mechanism. BNC is for coaxial cables, not fiber optic.",
      "examTip": "LC = Little Connector; small size, easy to handle in dense fiber environments."
    },
    {
      "id": 65,
      "question": "Which addressing type allows multiple recipients to receive the same packet without sending it to all devices on the network?",
      "options": [
        "Multicast",
        "Broadcast",
        "Unicast",
        "Anycast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Multicast sends data to multiple recipients who have joined a specific group. Broadcast sends data to all devices. Unicast is one-to-one. Anycast sends data to the nearest node among multiple recipients.",
      "examTip": "Multicast = Many-but-not-all — efficient for streaming and conferencing."
    },
    {
      "id": 66,
      "question": "Which protocol uses port 445 for file sharing and printer services on Windows networks?",
      "options": [
        "SMB",
        "FTP",
        "NFS",
        "TFTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SMB (Server Message Block) uses port 445 for file and printer sharing in Windows environments. FTP transfers files over ports 20/21. NFS is used for file sharing on UNIX/Linux systems. TFTP provides basic, unsecured file transfers on port 69.",
      "examTip": "SMB = Sharing Made Basic (Windows sharing) — Port 445 is the key."
    },
    {
      "id": 67,
      "question": "Which command would BEST help a technician determine if a device can reach a remote host across the network?",
      "options": [
        "ping",
        "ipconfig",
        "nslookup",
        "netstat"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'ping' tests network connectivity by sending ICMP echo requests. 'ipconfig' displays IP configurations. 'nslookup' checks DNS resolution. 'netstat' shows network connections and port usage.",
      "examTip": "ping = First test in troubleshooting connectivity; quick and effective."
    },
    {
      "id": 68,
      "question": "A network administrator needs to allow secure remote access to a server's command line. Which protocol should be used?",
      "options": [
        "SSH",
        "Telnet",
        "FTP",
        "RDP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH (Secure Shell) provides encrypted remote command-line access over port 22. Telnet provides unencrypted access. FTP transfers files, and RDP offers graphical remote access but not CLI-focused.",
      "examTip": "SSH = Secure remote CLI access; always preferred over Telnet."
    },
    {
      "id": 69,
      "question": "Which protocol provides dynamic address assignment and configuration to network hosts?",
      "options": [
        "DHCP",
        "DNS",
        "NAT",
        "SNMP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DHCP (Dynamic Host Configuration Protocol) dynamically assigns IP addresses. DNS resolves hostnames. NAT translates private to public IP addresses. SNMP monitors and manages network devices.",
      "examTip": "DHCP = Plug-and-play IP assignment; no manual configuration needed."
    },
    {
      "id": 70,
      "question": "Which tool would BEST help identify channel overlap and signal strength issues in a wireless network?",
      "options": [
        "Wi-Fi analyzer",
        "Toner probe",
        "Cable tester",
        "Loopback plug"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A Wi-Fi analyzer identifies signal strength, interference, and channel overlap issues. Toner probes trace wired cables. Cable testers check wiring continuity. Loopback plugs test port functionality.",
      "examTip": "Wi-Fi analyzer = Wireless health check; find interference and optimize coverage."
    },
    {
      "id": 71,
      "question": "Which cloud service model provides fully functional applications accessed over the internet without local installation?",
      "options": [
        "SaaS",
        "PaaS",
        "IaaS",
        "FaaS"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SaaS (Software as a Service) provides fully functional applications like Google Workspace or Microsoft 365. PaaS offers platforms for app development. IaaS offers infrastructure, and FaaS offers serverless function execution.",
      "examTip": "SaaS = Ready-to-use apps in the cloud; no installation, just access."
    },
    {
      "id": 72,
      "question": "Which type of network topology connects all devices to a central device, providing easy isolation of failures?",
      "options": [
        "Star",
        "Mesh",
        "Bus",
        "Ring"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Star topology connects all devices to a central hub or switch, making it easy to isolate issues. Mesh provides redundancy but is complex. Bus uses a single cable, and Ring connects devices in a loop.",
      "examTip": "Star topology = Central point simplicity; popular for ease of troubleshooting."
    },
    {
      "id": 73,
      "question": "A network administrator needs to configure inter-VLAN routing on a new switch that will handle VLANs 10, 20, and 30. The switch is connected to a router using a single physical link. Which of the following configurations should be used to allow devices in each VLAN to communicate with each other, while also conserving port usage on the router?",
      "options": [
        "Enable 802.1Q trunking on the switch port and configure subinterfaces for each VLAN on the router interface",
        "Use separate physical interfaces on the router, each connected to an access port in the corresponding VLAN on the switch",
        "Assign a separate IP address to each switch port in the VLANs and configure the router with a single default gateway",
        "Configure VLAN trunking protocol (VTP) in transparent mode across all network devices"
      ],
      "answerIndex": 0,
      "explanation": "By enabling 802.1Q trunking on one interface and configuring subinterfaces (one for each VLAN) on the router, you can handle routing for multiple VLANs using a single physical link. This approach is commonly referred to as 'Router-on-a-Stick'.",
      "examTip": "Know how to configure 802.1Q trunking and subinterfaces for inter-VLAN routing. It’s a fundamental skill for managing multiple VLANs efficiently in modern networks."
    },
    {
      "id": 74,
      "question": "Which command-line tool shows the path packets take from a source to a destination, identifying each hop?",
      "options": [
        "traceroute",
        "ping",
        "ipconfig",
        "nslookup"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'traceroute' (or 'tracert' in Windows) shows the path and each hop along the way. 'ping' checks connectivity. 'ipconfig' displays IP settings. 'nslookup' tests DNS resolution.",
      "examTip": "traceroute = Path inspector; great for identifying where traffic slows or fails."
    },
    {
      "id": 75,
      "question": "Which port does HTTPS use for secure web traffic?",
      "options": [
        "443",
        "80",
        "22",
        "21"
      ],
      "correctAnswerIndex": 0,
      "explanation": "HTTPS uses port 443 for secure web communication. HTTP uses port 80, SSH uses port 22, and FTP uses port 21.",
      "examTip": "HTTPS = Secure web = Port 443; encrypts traffic via SSL/TLS."
    },
    {
      "id": 76,
      "question": "Which type of IPv6 address is equivalent to the IPv4 private address range?",
      "options": [
        "Unique local address",
        "Link-local address",
        "Global unicast address",
        "Anycast address"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Unique local addresses (fc00::/7) in IPv6 are equivalent to IPv4 private addresses. Link-local addresses (fe80::/10) are for local communication. Global unicast addresses are publicly routable. Anycast addresses deliver data to the nearest node.",
      "examTip": "Unique local = IPv6’s version of private addresses (like 192.168.x.x in IPv4)."
    },
    {
      "id": 77,
      "question": "Which technology allows multiple virtual networks to operate on the same physical infrastructure in a cloud environment?",
      "options": [
        "NFV",
        "SDN",
        "VLAN",
        "VPN"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NFV (Network Functions Virtualization) enables multiple virtual networks on shared infrastructure. SDN (Software-Defined Networking) separates control and data planes. VLANs segment LANs. VPNs provide secure remote access.",
      "examTip": "NFV = Virtual network functions running without dedicated hardware."
    },
    {
      "id": 78,
      "question": "Which addressing type in IPv6 allows communication to the nearest node in a group of potential receivers?",
      "options": [
        "Anycast",
        "Unicast",
        "Multicast",
        "Broadcast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Anycast sends data to the nearest recipient in a group. Unicast targets a single recipient. Multicast targets multiple recipients. IPv6 does not use broadcast addressing.",
      "examTip": "Anycast = Fastest responder wins; great for load balancing and redundancy."
    },
    {
      "id": 79,
      "question": "Which protocol ensures time synchronization between network devices?",
      "options": [
        "NTP",
        "SNMP",
        "DNS",
        "TFTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NTP (Network Time Protocol) synchronizes time across devices. SNMP monitors network devices. DNS resolves hostnames. TFTP transfers files without authentication.",
      "examTip": "NTP = Correct time, correct logs; crucial for troubleshooting and security."
    },
    {
      "id": 80,
      "question": "Which type of cable provides the HIGHEST immunity to electromagnetic interference (EMI)?",
      "options": [
        "Fiber optic cable",
        "Coaxial cable",
        "Shielded twisted-pair cable",
        "Unshielded twisted-pair cable"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Fiber optic cables are immune to EMI as they use light for data transmission. Coaxial and shielded twisted-pair cables offer some EMI resistance but not to the same level. Unshielded twisted-pair cables provide the least EMI protection.",
      "examTip": "Fiber optic = No EMI issues; ideal for environments with high electrical interference."
    },
    {
      "id": 81,
      "question": "Which protocol uses port 123 to synchronize the clocks of computer systems over packet-switched networks?",
      "options": [
        "NTP",
        "SNMP",
        "FTP",
        "DNS"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NTP (Network Time Protocol) uses port 123 to synchronize time across network devices. SNMP monitors network devices. FTP handles file transfers. DNS resolves domain names.",
      "examTip": "NTP = Accurate time for logs and security; remember port 123 (easy as 1-2-3)."
    },
    {
      "id": 82,
      "question": "Which protocol would a technician MOST likely use to transfer a file securely using encryption over port 22?",
      "options": [
        "SFTP",
        "FTP",
        "TFTP",
        "SCP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SFTP (SSH File Transfer Protocol) uses port 22 and provides encrypted file transfers. FTP is unencrypted. TFTP provides unsecured file transfers. SCP also uses SSH but is more suitable for single file transfers without advanced management features.",
      "examTip": "SFTP = Secure file transfer over SSH (Port 22) — secure and reliable."
    },
    {
      "id": 83,
      "question": "A network administrator needs to secure web traffic between users and a company website. Which port should they ensure is open?",
      "options": [
        "443",
        "80",
        "21",
        "3389"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Port 443 is used for HTTPS traffic, ensuring secure web communication. Port 80 is used for HTTP (unencrypted). Port 21 is for FTP, and port 3389 is for RDP.",
      "examTip": "HTTPS = Secure web = Port 443; always prefer HTTPS for secure web transactions."
    },
    {
      "id": 84,
      "question": "Which DNS record type is used to define the authoritative name server for a domain?",
      "options": [
        "NS",
        "A",
        "MX",
        "CNAME"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The NS (Name Server) record specifies the authoritative name server for a domain. A records map hostnames to IPv4 addresses. MX records define mail servers. CNAME records create domain aliases.",
      "examTip": "NS = Name Server authority — critical for proper DNS zone management."
    },
    {
      "id": 85,
      "question": "Which technology would a network engineer use to logically separate traffic on the same physical switch?",
      "options": [
        "VLAN",
        "VPN",
        "NAT",
        "STP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "VLANs (Virtual Local Area Networks) logically segment networks on the same physical switch. VPNs secure communications over public networks. NAT translates IP addresses. STP prevents network loops.",
      "examTip": "VLAN = Logical segmentation; improves security and reduces broadcast domains."
    },
    {
      "id": 86,
      "question": "Which addressing scheme allows automatic assignment of IP addresses in the 169.254.x.x range when a DHCP server is unavailable?",
      "options": [
        "APIPA",
        "Static",
        "Loopback",
        "Private"
      ],
      "correctAnswerIndex": 0,
      "explanation": "APIPA (Automatic Private IP Addressing) assigns 169.254.x.x addresses when DHCP fails. Static addresses are manually configured. Loopback (127.0.0.1) is for local host testing. Private addresses (e.g., 192.168.x.x) are manually or dynamically assigned for internal networks.",
      "examTip": "169.254.x.x = APIPA; indicates DHCP issues when devices self-assign."
    },
    {
      "id": 87,
      "question": "Which wireless standard operates in both 2.4GHz and 5GHz frequencies and supports speeds up to 600 Mbps?",
      "options": [
        "802.11n",
        "802.11a",
        "802.11b",
        "802.11g"
      ],
      "correctAnswerIndex": 0,
      "explanation": "802.11n supports dual-band operation (2.4GHz and 5GHz) and speeds up to 600 Mbps. 802.11a uses 5GHz at 54 Mbps. 802.11b (2.4GHz) and 802.11g (2.4GHz) support lower speeds.",
      "examTip": "802.11n = 'n' for 'next-gen' at the time — dual-band support and better speeds."
    },
    {
      "id": 88,
      "question": "Which network device can forward packets based on IP addresses and also provide NAT functionality?",
      "options": [
        "Router",
        "Switch",
        "Firewall",
        "Hub"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Routers forward packets based on IP addresses and often provide NAT to connect private networks to the internet. Switches forward traffic based on MAC addresses. Firewalls filter traffic. Hubs broadcast all traffic to connected devices.",
      "examTip": "Router = IP traffic director + NAT translator for internet access."
    },
    {
      "id": 89,
      "question": "Which cable type supports the highest data transmission rates over the longest distances without signal degradation?",
      "options": [
        "Single-mode fiber",
        "Multimode fiber",
        "Cat 6 Ethernet",
        "Coaxial cable"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Single-mode fiber supports long-distance, high-speed transmissions with minimal signal loss. Multimode fiber is better for shorter distances. Cat 6 Ethernet is suitable for shorter copper runs. Coaxial cables provide moderate performance for specific applications.",
      "examTip": "Single-mode fiber = Long haul + High speed — ideal for backbone and WAN connections."
    },
    {
      "id": 90,
      "question": "Which OSI layer is responsible for logical addressing and path determination?",
      "options": [
        "Network layer",
        "Data Link layer",
        "Transport layer",
        "Application layer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The Network layer (Layer 3) manages logical addressing (IP) and routing. The Data Link layer handles MAC addresses and frame delivery. The Transport layer ensures reliable transmission. The Application layer interfaces with user software.",
      "examTip": "Network layer = IP addressing and routing — where routers operate."
    },
    {
      "id": 91,
      "question": "Which tool would BEST help determine if a network path is experiencing latency issues at a particular hop?",
      "options": [
        "traceroute",
        "ping",
        "netstat",
        "ipconfig"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'traceroute' shows each hop on a network path, helping identify where delays occur. 'ping' tests connectivity but not hop latency. 'netstat' displays active connections. 'ipconfig' shows IP configuration details.",
      "examTip": "traceroute = Path tester — use it to find latency or routing issues along the way."
    },
    {
      "id": 92,
      "question": "Which protocol provides secure remote login capabilities and file transfers using encryption on port 22?",
      "options": [
        "SSH",
        "Telnet",
        "FTP",
        "HTTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH (Secure Shell) provides encrypted remote access and file transfers over port 22. Telnet is unencrypted. FTP transfers files without encryption. HTTP is unencrypted web traffic.",
      "examTip": "SSH = Secure access via port 22; always choose SSH over Telnet for secure sessions."
    },
    {
      "id": 93,
      "question": "Which addressing method delivers data to all hosts within a broadcast domain in IPv4 networks?",
      "options": [
        "Broadcast",
        "Unicast",
        "Multicast",
        "Anycast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Broadcast delivers data to all hosts in a subnet. Unicast targets a single recipient. Multicast delivers to selected recipients. Anycast delivers to the nearest node in a group.",
      "examTip": "Broadcast = One-to-all communication — limited to local networks in IPv4."
    },
    {
      "id": 94,
      "question": "Which type of IPv6 address is automatically assigned and used for communication between nodes on the same link?",
      "options": [
        "Link-local",
        "Global unicast",
        "Unique local",
        "Anycast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Link-local addresses (starting with FE80::) are auto-assigned for communication on the same link. Global unicast addresses are routable on the internet. Unique local addresses are for internal networks. Anycast addresses route to the nearest node in a group.",
      "examTip": "FE80:: = Link-local; local network-only communication in IPv6."
    },
    {
      "id": 95,
      "question": "Which command would BEST help identify active network connections and listening ports on a local machine?",
      "options": [
        "netstat",
        "ping",
        "traceroute",
        "arp"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'netstat' shows active connections, routing tables, and listening ports. 'ping' tests basic connectivity. 'traceroute' shows routing paths. 'arp' shows IP-to-MAC mappings.",
      "examTip": "netstat = Network status at a glance — essential for troubleshooting connections."
    },
    {
      "id": 96,
      "question": "Which protocol ensures secure authentication and encryption when accessing web applications?",
      "options": [
        "HTTPS",
        "HTTP",
        "FTP",
        "Telnet"
      ],
      "correctAnswerIndex": 0,
      "explanation": "HTTPS (Hypertext Transfer Protocol Secure) encrypts web traffic using SSL/TLS. HTTP transmits data unencrypted. FTP handles file transfers. Telnet provides unsecured remote access.",
      "examTip": "HTTPS = Secure web browsing — always use port 443 for encrypted sessions."
    },
    {
      "id": 97,
      "question": "Which device connects multiple network segments and uses MAC addresses to forward traffic efficiently?",
      "options": [
        "Switch",
        "Router",
        "Hub",
        "Repeater"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Switches forward frames based on MAC addresses, reducing unnecessary traffic. Routers use IP addresses for routing. Hubs broadcast traffic to all ports. Repeaters regenerate signals but don’t direct traffic.",
      "examTip": "Switch = MAC manager — smarter, faster forwarding within LANs."
    },
    {
      "id": 98,
      "question": "Which protocol is used for secure remote desktop access to Windows systems?",
      "options": [
        "RDP",
        "SSH",
        "VNC",
        "Telnet"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RDP (Remote Desktop Protocol) uses port 3389 for secure graphical access to Windows systems. SSH provides secure CLI access. VNC provides graphical access but typically without built-in encryption. Telnet is insecure.",
      "examTip": "RDP = Remote Desktop for Windows — secure graphical remote management."
    },
    {
      "id": 99,
      "question": "Which wireless frequency band provides the fastest speeds but has the shortest effective range?",
      "options": [
        "5GHz",
        "2.4GHz",
        "900MHz",
        "60GHz"
      ],
      "correctAnswerIndex": 0,
      "explanation": "5GHz provides faster speeds with less interference but has a shorter range than 2.4GHz. 900MHz is typically used for longer-range IoT applications. 60GHz supports ultra-fast but extremely short-range communication.",
      "examTip": "5GHz = Speed-focused; best for dense, high-performance environments."
    },
    {
      "id": 100,
      "question": "Which feature of a network switch allows multiple physical ports to be combined into a single logical port for redundancy and increased throughput?",
      "options": [
        "Link aggregation",
        "Spanning Tree Protocol (STP)",
        "Port mirroring",
        "VLAN tagging"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Link aggregation combines multiple physical ports into one logical link, increasing bandwidth and providing redundancy. STP prevents network loops. Port mirroring copies traffic for analysis. VLAN tagging segments networks logically.",
      "examTip": "Link aggregation = More bandwidth + Failover protection — critical for high-availability networks."
    }
  ]
});      
