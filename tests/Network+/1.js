db.tests.insertOne({
  "category": "nplus",
  "testId": 1,
  "testName": "Network+ Practice Test #1 (Normal)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "Which layer of the OSI model is responsible for logical addressing and routing?",
      "options": [
        "Layer 2 (Data Link): Handles frame transmission and MAC addressing.",
        "Layer 3 (Network): Handles IP-based addressing and routing decisions.",
        "Layer 4 (Transport): Manages end-to-end data delivery and flow control.",
        "Layer 7 (Application): Manages high-level protocols for user applications."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The Network layer (Layer 3) handles logical addressing (like IP addresses) and determines the best path for data to travel (routing). Layer 2 uses physical addresses (MAC addresses). Layer 4 manages reliable data transfer. Layer 7 provides network services to applications.",
      "examTip": "Remember the OSI model layers in order (Please Do Not Throw Sausage Pizza Away).  Focus on the key function of each layer."
    },
    {
      "id": 2,
      "question": "What is the purpose of a firewall in a network?",
      "options": [
        "Offers Wi-Fi access for client devices on the network.",
        "Oversees dynamic or static IP address assignments to hosts.",
        "Monitors and blocks data flows using specific security criteria.",
        "Accelerates data transfer rates for all connected systems."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Firewalls act as security barriers, controlling network traffic by allowing or blocking it based on configured rules.  They don't provide wireless access, manage IPs (that's DHCP), or directly boost speed.",
      "examTip": "Think of a firewall as a gatekeeper for network traffic, focusing on security."
    },
    {
      "id": 3,
      "question": "Which of the following is a characteristic of a Storage Area Network (SAN)?",
      "options": [
        "Presents storage at the block level as though locally attached.",
        "Utilizes the same cabling as standard LAN connections.",
        "Serves small office file sharing without special hardware.",
        "Delivers lower performance than typical NAS solutions."
      ],
      "correctAnswerIndex": 0,
      "explanation": "SANs offer block-level access, making them appear as locally attached drives to servers. They typically use dedicated, high-speed connections (like Fibre Channel), not the main network cabling.  They are designed for high performance, unlike NAS, which is file-level.",
      "examTip": "Distinguish between SAN (block-level, high-performance) and NAS (file-level, easier to manage)."
    },
    {
      "id": 4,
      "question": "You are setting up a new wireless network.  Which standard provides the BEST combination of speed and security for most modern devices?",
      "options": [
        "802.11b: Offers slower speeds in the 2.4 GHz band only.",
        "802.11g: Provides moderate speeds at 2.4 GHz frequency.",
        "802.11ac: Delivers high throughput but is older than Wi-Fi 6.",
        "802.11ax (Wi-Fi 6/6E): Delivers top speeds and improved security."
      ],
      "correctAnswerIndex": 3,
      "explanation": "802.11ax (Wi-Fi 6/6E) is the most current standard, offering the best speed, efficiency, and security features. The others are older and less performant/secure.",
      "examTip": "Keep up-to-date with the latest wireless standards.  Remember that newer standards generally offer significant improvements."
    },
    {
      "id": 5,
      "question": "What is the FIRST step you should take when troubleshooting a network connectivity issue?",
      "options": [
        "Swap the Ethernet cable to rule out physical damage.",
        "Restart the router to clear out possible conflicts.",
        "Collect details about the symptoms and environment.",
        "Call your ISP to confirm any service interruptions."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The first step in troubleshooting is always to gather information: identify symptoms, talk to users, and determine what, if anything, has changed.  Jumping to solutions without understanding the problem is inefficient.",
      "examTip": "Always follow the troubleshooting methodology:  Gather information *before* taking action."
    },
    {
      "id": 6,
      "question": "Which port is commonly used for unencrypted web traffic?",
      "options": [
        "Port 21, primarily used for FTP file transfers.",
        "Port 22, used for secure remote logins via SSH.",
        "Port 80, the default for HTTP connections.",
        "Port 443, reserved for HTTPS sessions."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Port 80 is the standard port for HTTP (Hypertext Transfer Protocol), which is unencrypted web traffic. Port 443 is for HTTPS (secure). 21 is FTP, and 22 is SSH.",
      "examTip": "Memorize the common port numbers for key services like HTTP, HTTPS, FTP, SSH, and DNS."
    },
    {
      "id": 7,
      "question": "A user reports they cannot access a specific website.  You can ping the website's IP address successfully.  What is the MOST likely cause?",
      "options": [
        "Damaged Ethernet cable preventing full network access.",
        "DNS lookup failure preventing domain name resolution.",
        "Server outage making the site fully inaccessible.",
        "User's IP address is blacklisted by the site."
      ],
      "correctAnswerIndex": 1,
      "explanation": "If you can ping the IP address but not access the website by name, the issue is likely with DNS resolution (translating the website name to an IP address). A faulty cable would prevent pinging.  If the server was down, you likely couldn't ping it.",
      "examTip": "Distinguish between IP connectivity (ping) and name resolution (DNS) when troubleshooting access problems."
    },
    {
      "id": 8,
      "question": "What type of cable is MOST resistant to electromagnetic interference (EMI)?",
      "options": [
        "UTP cable with no additional shielding.",
        "STP cable providing some protective foil.",
        "Coaxial cable using a single copper conductor.",
        "Fiber optic cable immune to electrical noise."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Fiber optic cable uses light instead of electricity, making it immune to EMI. STP offers more protection than UTP, and coaxial cable has some shielding but is less resistant than fiber.",
      "examTip": "Remember that fiber optic cable is the best choice for environments with high EMI."
    },
    {
      "id": 9,
      "question": "Which command is used to display the routing table on a Windows computer?",
      "options": [
        "ipconfig /all: Shows interface configurations.",
        "route print: Lists all current routing entries.",
        "netstat -r: Displays routes in a less direct format.",
        "tracert: Traces the path to a remote host."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`route print` displays the routing table. `ipconfig /all` shows network interface configuration, `netstat -r` shows routing information (but not as clearly), and `tracert` traces the route to a destination.",
      "examTip": "Learn the specific commands for viewing routing tables on both Windows and Linux systems."
    },
    {
      "id": 10,
      "question": "What is a subnet mask used for?",
      "options": [
        "Protecting data through encryption algorithms.",
        "Defining which part of an IP address is network vs. host.",
        "Assigning IP addresses automatically to devices.",
        "Filtering packets based on hardware (MAC) addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The subnet mask defines which bits of an IP address represent the network and which represent the host.  This is crucial for routing and network segmentation.  It doesn't encrypt, assign addresses (DHCP does that), or filter by MAC address (switches do that).",
      "examTip": "Understand how subnet masks work to divide an IP address into network and host identifiers."
    },
    {
      "id": 11,
      "question": "Which of the following is an example of a Class C IP address?",
      "options": [
        "10.0.0.5, belonging to the Class A range.",
        "172.16.1.10, which falls under Class B.",
        "192.168.1.100, typical of Class C space.",
        "224.0.0.1, used for multicast (Class D)."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Class C IP addresses range from 192.0.0.0 to 223.255.255.255.  10.x.x.x is Class A, 172.16.x.x - 172.31.x.x is Class B, and 224.x.x.x is Class D (multicast).",
      "examTip": "Memorize the IP address class ranges, even though classful addressing is largely obsolete."
    },
    {
      "id": 12,
      "question": "What is the purpose of the `traceroute` (or `tracert`) command?",
      "options": [
        "Gauges a link’s upload and download throughput.",
        "Retrieves the numerical IP address for a given domain.",
        "Shows each hop a packet takes to reach a destination.",
        "Adjusts a NIC’s configuration to match the network."
      ],
      "correctAnswerIndex": 2,
      "explanation": "`traceroute` shows the hops (routers) that packets traverse to reach a target host, helping diagnose routing problems. It doesn't directly measure speed, display IP addresses (that's `nslookup` or `dig`), or configure interfaces.",
      "examTip": "Use `traceroute` to identify points of failure or latency along a network path."
    },
    {
      "id": 13,
      "question": "Which wireless security protocol is considered the MOST secure?",
      "options": [
        "WEP: Obsolete and easily cracked.",
        "WPA: Better than WEP but still vulnerable.",
        "WPA2: Very common, though older than WPA3.",
        "WPA3: Latest standard with stronger protections."
      ],
      "correctAnswerIndex": 3,
      "explanation": "WPA3 is the latest and most secure wireless security protocol, offering stronger encryption and protection against attacks. WEP is extremely vulnerable, and WPA and WPA2 have known weaknesses.",
      "examTip": "Always use WPA3 if your devices support it.  Avoid WEP entirely."
    },
    {
      "id": 14,
      "question": "You are configuring a DHCP server.  What is the purpose of a DHCP reservation?",
      "options": [
        "Carving out IP ranges that will never be assigned.",
        "Forcing a specific MAC to always receive the same IP.",
        "Shortening the time that clients hold an address.",
        "Maintaining a backup of the DHCP configurations."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DHCP reservation ensures that a specific device (identified by its MAC address) always receives the same IP address from the DHCP server.  Exclusions prevent addresses from being assigned, lease time controls how long an address is valid, and backups are separate configurations.",
      "examTip": "Use DHCP reservations for devices that need consistent IP addresses, like servers or printers."
    },
    {
      "id": 15,
      "question": "What is the default subnet mask for a Class B network?",
      "options": [
        "255.0.0.0 for Class A subnets.",
        "255.255.0.0 for Class B addresses.",
        "255.255.255.0 for Class C ranges.",
        "255.255.255.255 for single-host coverage."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The default subnet mask for a Class B network is 255.255.0.0. Class A is 255.0.0.0, Class C is 255.255.255.0, and 255.255.255.255 is typically used for a single host or a broadcast address.",
      "examTip": "Understand the relationship between IP address classes and their default subnet masks."
    },
    {
      "id": 16,
      "question": "Which technology allows multiple VLANs to be transmitted over a single physical link?",
      "options": [
        "STP: Manages loop prevention in Layer 2 networks.",
        "VTP: Helps synchronize VLAN databases across switches.",
        "802.1Q trunking: Tags traffic to identify VLAN membership.",
        "Link Aggregation: Combines multiple physical ports into one."
      ],
      "correctAnswerIndex": 2,
      "explanation": "802.1Q trunking (also just called trunking) adds tags to Ethernet frames to identify the VLAN they belong to, allowing multiple VLANs to share a single link. STP prevents loops, VTP manages VLAN databases, and link aggregation combines multiple links into one logical link.",
      "examTip": "Remember that 802.1Q is the standard for VLAN tagging on trunk links."
    },
    {
      "id": 17,
      "question": "A network administrator needs to connect two buildings that are 500 meters apart. Which cabling type is MOST appropriate?",
      "options": [
        "UTP Cat 6: Limited to around 100 meters for Ethernet.",
        "STP Cat 6a: Also best under 100 meters for stable throughput.",
        "Multimode Fiber: Good for a few hundred meters at lower cost.",
        "Single-mode Fiber: Typically used for much greater distances."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Multimode fiber is suitable for distances up to a few hundred meters and is generally less expensive than single-mode fiber. UTP and STP Cat 6/6a are limited to 100 meters. Single-mode fiber is for much longer distances (kilometers).",
      "examTip": "Consider distance limitations when choosing cable types.  Multimode fiber is often used for shorter distances within a building or campus."
    },
    {
      "id": 18,
      "question": "What is the function of a DNS server?",
      "options": [
        "Assigns IP configurations like addresses or gateways.",
        "Transforms domain names into their numeric IP addresses.",
        "Directs traffic between different subnets or networks.",
        "Grants encrypted VPN access for remote connections."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DNS servers translate human-readable domain names (like google.com) into IP addresses that computers use to communicate. DHCP assigns IP addresses, routers route traffic, and VPNs provide secure remote access.",
      "examTip": "Think of DNS as the 'phone book' of the internet, converting names to numbers."
    },
    {
      "id": 19,
      "question": "Which protocol operates at the Transport layer of the OSI model and provides reliable, connection-oriented communication?",
      "options": [
        "UDP: A connectionless, best-effort protocol.",
        "TCP: Connection-oriented with reliable delivery.",
        "IP: Works at Layer 3 handling logical addresses.",
        "ICMP: Used for error messages and diagnostics."
      ],
      "correctAnswerIndex": 1,
      "explanation": "TCP (Transmission Control Protocol) is a connection-oriented protocol that provides reliable data delivery with error checking and retransmission. UDP is connectionless and unreliable. IP is at the Network layer, and ICMP is used for diagnostics (like ping).",
      "examTip": "Differentiate between TCP (reliable) and UDP (unreliable) at the Transport layer."
    },
    {
      "id": 20,
      "question": "You need to configure a network device to allow SSH access only from a specific management workstation. What is the BEST way to achieve this?",
      "options": [
        "Set up an ACL to permit SSH for certain IP addresses.",
        "Use MAC filtering to block all unknown MACs.",
        "Change the default port number for SSH sessions.",
        "Disable every other service running on the device."
      ],
      "correctAnswerIndex": 0,
      "explanation": "An ACL allows you to specify which IP addresses or networks are permitted to access specific services (like SSH). MAC filtering is less secure (easily spoofed). Changing the SSH port provides obscurity, not strong security. Disabling other services is unnecessary and might impact functionality.",
      "examTip": "Use ACLs to control access to network devices and services based on IP addresses."
    },
    {
      "id": 21,
      "question": "What does 'PoE' stand for in networking?",
      "options": [
        "Power over Ethernet for carrying electricity on data lines.",
        "Point of Entry for inbound traffic filtering.",
        "Packet over Ethernet for WAN data encapsulation.",
        "Port over Ethernet for extended switch port capacity."
      ],
      "correctAnswerIndex": 0,
      "explanation": "PoE stands for Power over Ethernet, a technology that allows network cables to carry electrical power.",
      "examTip": "PoE simplifies deployments by providing power and data over a single cable."
    },
    {
      "id": 22,
      "question": "Which of the following is a valid IPv6 address?",
      "options": [
        "192.168.1.1, which is an IPv4 address format.",
        "2001:db8::1, a proper compressed IPv6 notation.",
        "172.32.1.256, an invalid IPv4 with out-of-range octet.",
        "255.255.255.0, a typical IPv4 subnet mask."
      ],
      "correctAnswerIndex": 1,
      "explanation": "2001:db8::1 is a valid IPv6 address. IPv6 addresses are 128 bits long and written in hexadecimal. The other options are IPv4 addresses or a subnet mask.",
      "examTip": "Recognize the format of IPv6 addresses (hexadecimal, colons, and double colons for consecutive zero groups)."
    },
    {
      "id": 23,
      "question": "What is the main purpose of an Intrusion Detection System (IDS)?",
      "options": [
        "Blocks any unauthorized attempt to join the network.",
        "Scans and records suspicious traffic patterns, generating alerts.",
        "Encrypts data packets passing through the network perimeter.",
        "Assigns IP configurations to clients on secure segments."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An IDS passively monitors network traffic and alerts administrators to potential security breaches. Firewalls prevent access, encryption protects data, and DHCP assigns IPs.",
      "examTip": "Differentiate between IDS (detects) and IPS (prevents) intrusions."
    },
    {
      "id": 24,
      "question": "Which type of network topology connects all devices to a central hub or switch?",
      "options": [
        "Bus: Single backbone cable shared by multiple nodes.",
        "Ring: Each node forms a closed loop connection.",
        "Star: All nodes link to a central point.",
        "Mesh: Nodes interconnect with multiple redundant paths."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A star topology uses a central device (hub or switch) to connect all other nodes. Bus uses a single cable, ring connects devices in a loop, and mesh has multiple connections between devices.",
      "examTip": "Star topology is the most common in modern Ethernet networks due to its ease of management and fault tolerance."
    },
    {
      "id": 25,
      "question": "You observe high latency when accessing a cloud-based application. Which tool would be MOST helpful in identifying the source of the delay?",
      "options": [
        "ping: Checks basic connectivity and round-trip time.",
        "tracert/traceroute: Reveals each hop and associated latency.",
        "ipconfig: Shows local IP settings but not path latency.",
        "nslookup: Tests DNS resolution but not hop-by-hop delays."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Tracert/traceroute shows the path and delay at each hop, helping pinpoint where latency is occurring. Ping only tests basic connectivity, ipconfig shows local interface configuration, and nslookup resolves domain names.",
      "examTip": "Use tracert/traceroute for diagnosing latency issues across multiple network segments."
    },
    {
      "id": 26,
      "question": "What is the primary advantage of using fiber optic cable over copper cable?",
      "options": [
        "Costs less than standard twisted-pair cabling.",
        "Easier to install and terminate than copper.",
        "Supports higher bandwidth and longer distances.",
        "Resists physical damage better than copper wires."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Fiber optic cables offer significantly higher bandwidth and can transmit data over much longer distances than copper cables. They are generally more expensive and can be more complex to install.",
      "examTip": "Fiber is the preferred choice for high-speed, long-distance network connections."
    },
    {
      "id": 27,
      "question": "Which command is used to release and renew a DHCP lease on a Windows computer?",
      "options": [
        "ipconfig /release and ipconfig /renew",
        "ipconfig /flushdns for clearing DNS caches",
        "netsh winsock reset for fixing socket issues",
        "route add for configuring static routes"
      ],
      "correctAnswerIndex": 0,
      "explanation": "ipconfig /release releases the current DHCP lease, and ipconfig /renew requests a new one. ipconfig /flushdns clears the DNS resolver cache, netsh winsock reset resets the Winsock catalog, and route add adds a static route.",
      "examTip": "Use ipconfig /release and ipconfig /renew to troubleshoot DHCP-related connectivity issues."
    },
    {
      "id": 28,
      "question": "What is a MAC address?",
      "options": [
        "A unique hardware identifier on a network interface.",
        "A dynamic logical address for routing traffic.",
        "An IP automatically handed out via DHCP.",
        "A reference to specialized network cabling."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A MAC address is a unique hardware address burned into a network interface card (NIC). IP addresses are logical and assigned by DHCP or static configuration.",
      "examTip": "MAC addresses are used for communication within a local network segment (Layer 2)."
    },
    {
      "id": 29,
      "question": "You are setting up a small office network.  Which device is MOST likely to provide both routing and switching functionality?",
      "options": [
        "Dedicated router with only routing features",
        "Standalone switch for local device connections",
        "Modem converting signals from ISP to digital",
        "SOHO router combining multiple network services"
      ],
      "correctAnswerIndex": 3,
      "explanation": "SOHO routers typically combine routing, switching, and often wireless access point functionality into a single device.  Dedicated routers and switches perform only their specific function, and a modem connects to the internet but doesn't route or switch.",
      "examTip": "SOHO routers are common in small networks for their all-in-one convenience."
    },
    {
      "id": 30,
      "question": "What is the purpose of a default gateway?",
      "options": [
        "Serves as the DNS resolver for the network.",
        "Provides internal IP addresses via DHCP service.",
        "Acts as the router IP for traffic leaving the local subnet.",
        "Filters broadcast traffic within the local segment."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The default gateway is the IP address of the router that a device uses to send traffic to destinations outside the local network.  DHCP assigns IP addresses, switches filter by MAC address, and DNS servers translate domain names.",
      "examTip": "Without a default gateway, devices can only communicate within their local subnet."
    },
    {
      "id": 31,
      "question": "Which of the following network services uses UDP port 53?",
      "options": [
        "SMTP sending mail on TCP port 25",
        "DNS resolving queries over UDP 53",
        "DHCP operating on UDP ports 67/68",
        "HTTP running on TCP port 80"
      ],
      "correctAnswerIndex": 1,
      "explanation": "DNS primarily uses UDP port 53 for name resolution queries.  SMTP uses TCP port 25, DHCP uses UDP ports 67 and 68, and HTTP uses TCP port 80.",
      "examTip": "Remember that DNS uses UDP for speed, although it can also use TCP for larger responses or zone transfers."
    },
    {
      "id": 32,
      "question": "What is the maximum data transfer rate of standard 802.11g wireless networks?",
      "options": [
        "11 Mbps at the 2.4 GHz frequency band",
        "54 Mbps over 2.4 GHz channels",
        "150 Mbps using multiple data streams",
        "300 Mbps using an 802.11n setup"
      ],
      "correctAnswerIndex": 1,
      "explanation": "802.11g has a maximum data rate of 54 Mbps. 802.11b is 11 Mbps, and 802.11n can reach higher speeds.",
      "examTip": "Know the approximate speeds of the common 802.11 standards (b, g, n, ac, ax)."
    },
    {
      "id": 33,
      "question": "What command would you use to view the Address Resolution Protocol (ARP) cache on a Windows machine?",
      "options": [
        "arp -a: Lists current IP-to-MAC mappings",
        "ipconfig /displaydns: Shows DNS cache entries",
        "netstat -an: Displays active connections",
        "show arp: A common command on Cisco devices"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `arp -a` command displays the ARP cache, which maps IP addresses to MAC addresses. ipconfig /displaydns shows DNS cache, netstat -an shows network connections, and show arp is a common Cisco command.",
      "examTip": "The ARP cache is crucial for local network communication, allowing devices to find each other's MAC addresses."
    },
    {
      "id": 34,
      "question": "A network is experiencing intermittent connectivity issues.  You suspect a faulty patch cable. Which tool would be MOST useful for testing the cable?",
      "options": [
        "Protocol analyzer to capture packet details",
        "Cable tester to check continuity and pinouts",
        "Toner probe to locate a specific cable end",
        "Wi-Fi analyzer to scan wireless interference"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A cable tester checks for continuity, shorts, and other physical cable problems. A protocol analyzer captures network traffic, a toner probe helps locate cables, and a Wi-Fi analyzer is for wireless networks.",
      "examTip": "Use a cable tester as a first step when troubleshooting physical layer connectivity problems."
    },
    {
      "id": 35,
      "question": "What is the purpose of Network Address Translation (NAT)?",
      "options": [
        "Encrypts transmitted data for secure communications",
        "Maps private IPs to a public IP for external access",
        "Dynamically provides IP addresses to clients",
        "Filters traffic based on predefined URL rules"
      ],
      "correctAnswerIndex": 1,
      "explanation": "NAT allows multiple devices on a private network to share a single public IP address, conserving public IP addresses and providing a layer of security. Encryption protects data, DHCP assigns IPs, and content filters control access to specific websites or content.",
      "examTip": "NAT is essential for connecting private networks to the internet using a limited number of public IP addresses."
    },
    {
      "id": 36,
      "question": "Which type of VPN creates a secure, encrypted tunnel between two networks over the internet?",
      "options": [
        "Client-to-site VPN for individual user connections",
        "Site-to-site VPN for linking entire local networks",
        "Remote access VPN for single-device connectivity",
        "Clientless VPN requiring only a web browser"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A site-to-site VPN connects two entire networks (e.g., two branch offices). Client-to-site (or remote access) connects a single device to a network. Clientless VPNs provide access to specific applications without a full network tunnel.",
      "examTip": "Distinguish between site-to-site (network-to-network) and client-to-site (device-to-network) VPNs."
    },
    {
      "id": 37,
      "question": "What is the function of a router in a network?",
      "options": [
        "Joins devices in the same LAN using MAC addresses",
        "Examines IP-based traffic to forward data between networks",
        "Modulates and demodulates signals for ISP connections",
        "Filters or blocks packets based on security rules"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Routers operate at Layer 3 (Network) and forward packets based on IP addresses, connecting different networks. Switches connect devices within the same LAN, modems convert signals, and switches (not routers) can filter based on MAC addresses.",
      "examTip": "Routers are the 'traffic cops' of the internet, directing data between networks."
    },
    {
      "id": 38,
      "question": "Which of the following is an advantage of using a cloud-based service model like IaaS?",
      "options": [
        "Complete protection against cyber threats",
        "Lower overhead by renting virtualized hardware",
        "Turnkey software maintenance and patching",
        "Easier code development with built-in libraries"
      ],
      "correctAnswerIndex": 1,
      "explanation": "IaaS (Infrastructure as a Service) allows you to rent virtualized computing resources, reducing the need to purchase and maintain physical hardware. SaaS provides automatic updates, PaaS simplifies development, and security is a shared responsibility in the cloud, not a guarantee.",
      "examTip": "Understand the different cloud service models (IaaS, PaaS, SaaS) and their respective benefits."
    },
    {
      "id": 39,
      "question": "What is the purpose of a 'DMZ' in a network?",
      "options": [
        "Separates critical internal servers behind multiple routers",
        "Enables a private Wi-Fi network for local office users",
        "Houses publicly accessible servers safely outside the main LAN",
        "Offers an emergency power backup zone for network hardware"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A DMZ (Demilitarized Zone) is a network segment that sits between the internal network and the internet, providing a buffer zone for servers that need to be accessible from the outside (like web servers). It doesn't secure internal servers directly, separate wireless devices, or provide backup power.",
      "examTip": "Think of a DMZ as a 'semi-trusted' zone for publicly accessible resources."
    },
    {
      "id": 40,
      "question": "Which protocol is used to securely manage and monitor network devices?",
      "options": [
        "SNMP: Collects information, with v3 offering security",
        "Telnet: Sends commands in plain text across networks",
        "FTP: Transfers files unencrypted between hosts",
        "HTTP: Unsecured protocol for web-based interactions"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SNMP is used to monitor and manage network devices. While SNMPv3 offers security features, the earlier versions (v1 and v2c) are not secure. Telnet, FTP, and HTTP are not designed for secure device management.",
      "examTip": "Use SNMPv3 for secure device management, and avoid using earlier, insecure versions."
    },
    {
      "id": 41,
      "question": "What is the purpose of using VLANs?",
      "options": [
        "Boosting bandwidth beyond physical switch limits",
        "Separating one physical network into logical segments",
        "Encrypting data flowing within the local subnet",
        "Handing out IP addresses to host devices"
      ],
      "correctAnswerIndex": 1,
      "explanation": "VLANs logically separate a physical network into multiple broadcast domains, improving security and manageability. They don't directly increase bandwidth, encrypt traffic, or assign IPs (DHCP does that).",
      "examTip": "VLANs are a fundamental tool for network segmentation and security."
    },
    {
      "id": 42,
      "question": "When configuring a wireless access point, what does the SSID represent?",
      "options": [
        "A shared encryption key for wireless security",
        "The broadcast name of the Wi-Fi network",
        "The unique MAC hardware address of the AP",
        "The IP address used to manage the AP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The SSID (Service Set Identifier) is the name that identifies a wireless network to users. The encryption key secures the network, the MAC address is the physical address of the AP, and the IP address is its logical address.",
      "examTip": "The SSID is what users see when they search for available Wi-Fi networks."
    },
    {
      "id": 43,
      "question": "What is the role of an authoritative DNS server?",
      "options": [
        "Caches DNS records for faster lookups",
        "Holds the official records for a given domain",
        "Relays requests to other DNS servers",
        "Offers internet DNS to home routers"
      ],
      "correctAnswerIndex": 1,
      "explanation": "An authoritative DNS server holds the original, master records for a domain. Caching servers store copies of records, forwarding servers relay requests, and home users typically use recursive DNS servers provided by their ISP.",
      "examTip": "Authoritative servers are the ultimate source of truth for DNS information about a domain."
    },
    {
      "id": 44,
      "question": "You are troubleshooting a network where users are experiencing slow file transfers. You suspect a duplex mismatch. What does this mean?",
      "options": [
        "Both devices set to half-duplex, causing collisions",
        "One device at half-duplex, the other at full-duplex",
        "Devices with mismatched IPs, blocking all traffic",
        "Switch port overload from too many connections"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A duplex mismatch occurs when two connected devices are configured for different duplex settings (half-duplex allows communication in only one direction at a time, full-duplex allows simultaneous bidirectional communication). This causes collisions and performance issues.",
      "examTip": "Ensure that both ends of a network connection have matching speed and duplex settings."
    },
    {
      "id": 45,
      "question": "Which of the following is a characteristic of a mesh network topology?",
      "options": [
        "Connects every node to a central bridging device",
        "Chains each device in a single loop arrangement",
        "Offers multiple paths between any two nodes",
        "Relies on a shared backbone bus for all traffic"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Mesh networks provide high redundancy because each node has multiple connections to other nodes. Star uses a central hub, ring uses a loop, and bus uses a single cable.",
      "examTip": "Mesh networks are highly resilient but can be more complex to manage."
    },
    {
      "id": 46,
      "question": "What information can be found on the Main Distribution Frame (MDF) of a network?",
      "options": [
        "All internal endpoints and workstations",
        "Core switch ports connected to wireless APs",
        "Terminations for IDFs and external provider links",
        "Individual user devices and patch cables"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The MDF is the central point where connections from IDFs (Intermediate Distribution Frames) and incoming lines from service providers terminate.  Workstations and access points are connected at IDFs, not the MDF.  Patch cables connect within a rack, but the overall termination is at the MDF or IDF.",
      "examTip": "Think of the MDF as the 'core' of the structured cabling system, connecting to the outside world and the IDFs."
    },
    {
      "id": 47,
      "question": "What is the function of a hypervisor in virtualization?",
      "options": [
        "Abstracts hardware to let multiple virtual machines run",
        "Acts as a dedicated switch for virtual networks",
        "Stores and organizes virtual disk images",
        "Handles daily data backups for all virtual machines"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A hypervisor (or Virtual Machine Monitor - VMM) is software that creates and runs virtual machines, abstracting the underlying hardware. It doesn't directly provide network connectivity (that's handled by virtual switches), store files (that's the storage system), or perform backups (although it can facilitate them).",
      "examTip": "The hypervisor is the foundation of virtualization, allowing multiple operating systems to run on a single physical host."
    },
    {
      "id": 48,
      "question": "What does 'MTU' stand for in networking?",
      "options": [
        "Maximum Transmission Unit, a packet size limit",
        "Media Transfer Unit, for converting analog signals",
        "Minimum Transmission Unit, the smallest allowed frame",
        "Main Transfer Utility, a file-sync protocol"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MTU stands for Maximum Transmission Unit, which defines the largest packet size that can be transmitted over a network without fragmentation.",
      "examTip": "An incorrect MTU setting can lead to performance problems and fragmentation."
    },
    {
      "id": 49,
      "question": "What is the primary difference between a Layer 2 switch and a Layer 3 switch?",
      "options": [
        "Layer 2 uses MAC addressing, Layer 3 routes by IP",
        "Layer 2 switches always faster than Layer 3 devices",
        "Layer 2 switches allow VLANs, Layer 3 do not",
        "Layer 2 for small networks, Layer 3 for large ones"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Layer 2 switches operate at the data link layer and make forwarding decisions based on MAC addresses (within a single network). Layer 3 switches operate at the network layer and can route traffic between different networks based on IP addresses. Both can support VLANs; speed depends on the specific model; and both can be used in various network sizes.",
      "examTip": "Layer 3 switches combine switching and routing functionality."
    },
    {
      "id": 50,
      "question": "Which security protocol is used to authenticate users and devices on a network using a centralized database, often used with 802.1X?",
      "options": [
        "RADIUS for centralized authentication and accounting",
        "SSH for secure command-line connections",
        "SSL/TLS for encrypted web sessions",
        "IPsec for VPN-based data security"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RADIUS (Remote Authentication Dial-In User Service) is a networking protocol that provides centralized authentication, authorization, and accounting (AAA) management. SSH is for secure remote access, SSL/TLS encrypts web traffic, and IPsec is used for VPNs.",
      "examTip": "RADIUS is commonly used for network access control, especially with 802.1X port-based authentication."
    }
    {
      "id": 51,
      "question": "What is the purpose of Spanning Tree Protocol (STP)?",
      "options": [
        "Expands link capacity to reduce congestion.",
        "Prevents bridging loops by managing redundant paths.",
        "Applies secure encryption to all LAN traffic.",
        "Dispenses IP configurations to connected nodes."
      ],
      "correctAnswerIndex": 1,
      "explanation": "STP prevents broadcast storms and network outages caused by loops in a switched network by blocking redundant paths. It doesn't increase bandwidth, encrypt traffic, or assign IPs.",
      "examTip": "STP is essential for maintaining a stable switched network with redundant links."
    },
    {
      "id": 52,
      "question": "What is a 'broadcast domain'?",
      "options": [
        "Coverage zone for a single wireless AP.",
        "All hosts that see each other's broadcast traffic.",
        "An IP range managed by DHCP scope settings.",
        "The complete wiring system of a location."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A broadcast domain is a logical division of a network where all nodes can reach each other by broadcast at the data link layer. VLANs are used to segment broadcast domains.",
      "examTip": "Switches forward broadcasts within a broadcast domain; routers separate broadcast domains."
    },
    {
      "id": 53,
      "question": "Which command would you use to test basic network connectivity to a remote host, measuring round-trip time?",
      "options": [
        "tracert: Traces the path through multiple hops.",
        "ping: Sends ICMP echoes to measure reachability.",
        "nslookup: Queries DNS for hostname records.",
        "ipconfig: Reviews local IP configuration details."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `ping` command sends ICMP echo requests to a host and measures the time it takes to receive a reply. `tracert` shows the route, `nslookup` resolves domain names, and `ipconfig` displays local network configuration.",
      "examTip": "`ping` is a fundamental tool for troubleshooting network connectivity."
    },
    {
      "id": 54,
      "question": "A network administrator wants to ensure that only authorized devices can connect to specific switch ports. Which technology BEST achieves this?",
      "options": [
        "VLANs: Segment the network logically by grouping ports.",
        "Port Security: Restricts switch port access by MAC address.",
        "DHCP Snooping: Validates DHCP offers and requests.",
        "STP: Eliminates loops in a switched environment."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Port security allows you to restrict access to a switch port based on MAC address, limiting which devices can connect. VLANs segment networks logically, DHCP snooping prevents rogue DHCP servers, and STP prevents loops.",
      "examTip": "Port security is a key component of network access control at the switch level."
    },
    {
      "id": 55,
      "question": "What is 'jitter' in the context of network performance?",
      "options": [
        "Fluctuations in the delay of transmitted data packets.",
        "The total one-way latency from sender to receiver.",
        "The number of packets dropped during transit.",
        "The top throughput a link can handle consistently."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Jitter is the variability in latency (delay) over time. It's particularly important for real-time applications like VoIP and video conferencing. Latency is the overall delay, packet loss is data loss, and bandwidth is capacity.",
      "examTip": "High jitter can cause choppy audio and video in real-time communications."
    },
    {
      "id": 56,
      "question": "Which of the following is a benefit of network segmentation?",
      "options": [
        "Generates more frequent broadcast communication overall.",
        "Enhances security boundaries and cuts down on broadcast storms.",
        "Makes all administrative tasks straightforward by default.",
        "Reduces expenses by eliminating additional hardware."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Network segmentation, often achieved with VLANs, isolates network traffic, improving security by limiting the impact of breaches and reducing congestion by limiting broadcast domains. It can increase management complexity initially, and costs depend on implementation.",
      "examTip": "Segmentation is a crucial security best practice, especially for isolating sensitive systems."
    },
    {
      "id": 57,
      "question": "What is the purpose of the `nslookup` command?",
      "options": [
        "Displays the system’s active routing entries.",
        "Queries DNS records for IP or domain info.",
        "Checks connectivity with remote hosts via ICMP.",
        "Modifies a host’s NIC parameters."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`nslookup` is used to troubleshoot DNS resolution issues by querying DNS servers. `route print` displays routing tables, `ping` tests connectivity, and `ipconfig` configures interfaces.",
      "examTip": "Use `nslookup` to verify that domain names are resolving correctly to IP addresses."
    },
    {
      "id": 58,
      "question": "Which of the following is the MOST secure method for remote access to a network device's command-line interface?",
      "options": [
        "Telnet: Sends all data unencrypted across the network.",
        "SSH: Establishes an encrypted command-line session.",
        "HTTP: Unsecured protocol for exchanging web data.",
        "FTP: Transfers files without secure encryption."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SSH (Secure Shell) encrypts the communication session, protecting usernames, passwords, and commands. Telnet, HTTP, and FTP transmit data in plain text, making them vulnerable to eavesdropping.",
      "examTip": "Always use SSH for remote command-line access; never use Telnet."
    },
    {
      "id": 59,
      "question": "What is a 'collision domain'?",
      "options": [
        "The wireless zone covered by a single access point.",
        "All devices sharing the same medium where collisions can occur.",
        "All assigned addresses in a DHCP scope.",
        "All structured cabling for a particular building."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A collision domain is a network segment where devices share the same bandwidth and their transmissions can interfere with each other. Hubs create large collision domains; switches segment collision domains (each port is its own collision domain).",
      "examTip": "Switches eliminate collisions in modern Ethernet networks, unlike hubs."
    },
    {
      "id": 60,
      "question": "Which of the following is an example of a network monitoring tool?",
      "options": [
        "Wireshark: Captures and analyzes packet traffic.",
        "Microsoft Word: Creates text documents.",
        "Adobe Photoshop: Edits and manipulates images.",
        "AutoCAD: Designs 2D/3D engineering drafts."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Wireshark is a popular protocol analyzer used for network monitoring and troubleshooting. The other options are applications for different purposes.",
      "examTip": "Protocol analyzers like Wireshark capture and analyze network traffic, providing valuable insights."
    },
    {
      "id": 61,
      "question": "You need to implement Quality of Service (QoS) on your network.  What is the PRIMARY purpose of QoS?",
      "options": [
        "Scrambles data with strong encryption methods.",
        "Ranks and manages traffic flows to ensure critical data runs smoothly.",
        "Assigns IP addresses dynamically to various hosts.",
        "Filters packets based on their destination MAC addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "QoS allows you to give preferential treatment to specific applications or types of traffic (like voice or video) to ensure their performance.  It doesn't encrypt, assign IPs, or filter by MAC address.",
      "examTip": "QoS is essential for ensuring the performance of real-time applications on congested networks."
    },
    {
      "id": 62,
      "question": "Which type of IP address is automatically assigned to a device when it fails to obtain an address from a DHCP server?",
      "options": [
        "A manually entered static IP address for local use.",
        "A standard dynamic IP lease from the DHCP pool.",
        "A self-configured link-local address (169.254.x.x).",
        "An externally routable public IP address from the ISP."
      ],
      "correctAnswerIndex": 2,
      "explanation": "APIPA addresses (in the range 169.254.x.x) are self-assigned by devices when a DHCP server is unavailable. Static IPs are manually configured, dynamic IPs are assigned by DHCP, and public IPs are used on the internet.",
      "examTip": "APIPA allows limited local communication when DHCP fails, but it doesn't provide internet access."
    },
    {
      "id": 63,
      "question": "What is the purpose of the `ipconfig /all` command on a Windows system?",
      "options": [
        "Shows only default gateway details for each interface.",
        "Releases and renews the system’s DHCP lease settings.",
        "Presents complete adapter data, including DNS and MAC addresses.",
        "Checks reachability to a remote endpoint."
      ],
      "correctAnswerIndex": 2,
      "explanation": "`ipconfig /all` shows comprehensive information about network adapters, including IP address, subnet mask, default gateway, DNS servers, MAC address, and DHCP status. `route print` shows the routing table, `ipconfig /release` and `/renew` manage DHCP leases, and `ping` tests connectivity.",
      "examTip": "`ipconfig /all` is a valuable tool for gathering network configuration details on Windows."
    },
    {
      "id": 64,
      "question": "Which of the following best describes a 'virtual private network' (VPN)?",
      "options": [
        "A fully wired LAN that uses physical cabling for all nodes.",
        "A local network only available in a specific region.",
        "An encrypted tunnel over the internet for private access.",
        "A specialized link solely dedicated to live video feeds."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A VPN creates a secure tunnel over a public network, allowing users to access private resources remotely as if they were directly connected. It's not limited to a specific location or purpose.",
      "examTip": "VPNs are essential for secure remote access and protecting data privacy over untrusted networks."
    },
    {
      "id": 65,
      "question": "What is the function of an access point (AP) in a wireless network?",
      "options": [
        "Bridges wireless clients to the wired infrastructure.",
        "Allocates IP addresses for all LAN devices automatically.",
        "Screens and discards wireless packets by MAC address.",
        "Implements end-to-end encryption for all traffic flows."
      ],
      "correctAnswerIndex": 0,
      "explanation": "An AP acts as a bridge between wireless devices and a wired network. While an AP can be part of a router or system that assigns IP addresses or encrypts data, its primary role is to connect wireless and wired segments.",
      "examTip": "Think of an AP as a 'wireless switch' that connects Wi-Fi devices to the wired network."
    },
    {
      "id": 66,
      "question": "Which network device operates primarily at Layer 1 (Physical) of the OSI model?",
      "options": [
        "Router: Analyzes Layer 3 IP addresses for packet forwarding.",
        "Switch: Relies on MAC addresses at Layer 2 to switch frames.",
        "Hub: Repeats signals at the Physical layer without filtering.",
        "Firewall: Inspects traffic across multiple OSI layers."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A hub is a simple device that repeats signals received on one port to all other ports. It operates at the physical layer and doesn't examine MAC addresses or IP addresses. Routers are Layer 3, switches are primarily Layer 2 (though some are Layer 3), and firewalls can operate at multiple layers.",
      "examTip": "Hubs are largely obsolete due to their inefficiency and security issues; switches are preferred."
    },
    {
      "id": 67,
      "question": "What is a common symptom of a network loop caused by a Spanning Tree Protocol (STP) failure?",
      "options": [
        "Slight drop in overall internet speed for some users.",
        "Intense broadcast storms overwhelming the LAN.",
        "Client devices failing to obtain IP addresses entirely.",
        "Repeated wireless deauthentications for mobile clients."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Network loops can cause broadcast storms, where broadcast frames are endlessly circulated, consuming bandwidth and potentially crashing the network.  Slow speeds, IP address issues, and wireless disconnections are usually caused by other problems.",
      "examTip": "STP is crucial for preventing loops in networks with redundant links; a failure can be catastrophic."
    },
    {
      "id": 68,
      "question": "What is the purpose of a subnet?",
      "options": [
        "Expanding the available IP address pool beyond its limit.",
        "Carving out smaller logical networks for manageability.",
        "Encrypting all traffic crossing network boundaries.",
        "Filtering packet content based on application data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Subnetting divides a larger network into smaller logical networks, improving security, performance, and manageability. It doesn't increase the total number of addresses, encrypt traffic, or filter content (firewalls do that).",
      "examTip": "Subnetting is fundamental to IP addressing and network design."
    },
    {
      "id": 69,
      "question": "Which of the following is an example of a network documentation best practice?",
      "options": [
        "Keep diagrams stored only on a single administrator’s machine.",
        "Update documentation promptly whenever network changes occur.",
        "Rely exclusively on physical diagrams without logical topologies.",
        "Share master passwords with the entire technical department."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Network documentation should be kept up-to-date to accurately reflect the current state of the network.  It should be centrally stored and accessible (with appropriate security), include both physical and logical diagrams, and passwords should be managed securely, not widely shared.",
      "examTip": "Good network documentation is essential for troubleshooting, planning, and security."
    },
    {
      "id": 70,
      "question": "What is 'latency' in a network context?",
      "options": [
        "The capacity limit for data throughput on a link.",
        "The round-trip or one-way delay experienced by traffic.",
        "The total number of user devices on the same subnet.",
        "The direct physical distance separating network endpoints."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Latency is the delay experienced by data as it travels across a network. Bandwidth is the amount of data, the number of devices is network size, and distance is just physical separation.",
      "examTip": "Low latency is crucial for real-time applications like online gaming and video conferencing."
    },
    {
      "id": 71,
      "question": "Which type of network attack involves flooding a target with excessive traffic, overwhelming its resources?",
      "options": [
        "Man-in-the-middle: Eavesdrops and alters traffic flows.",
        "DoS: Sends excessive traffic to knock a service offline.",
        "Phishing: Tricks users into revealing sensitive data.",
        "SQL injection: Manipulates databases via crafted queries."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DoS attack aims to make a network or service unavailable by overwhelming it with traffic. Man-in-the-middle intercepts communication, phishing uses deceptive emails, and SQL injection targets databases.",
      "examTip": "DoS attacks can disrupt network services and cause significant downtime."
    },
    {
      "id": 72,
      "question": "Which technology is used to create a logical grouping of devices on a network, regardless of their physical location?",
      "options": [
        "Subnetting: Separates networks by IP addressing boundaries.",
        "VLANs: Form logical segments across a physical LAN layout.",
        "NAT: Translates private addresses to public addresses.",
        "DHCP: Dynamically allocates IP configuration to clients."
      ],
      "correctAnswerIndex": 1,
      "explanation": "VLANs group devices logically, even if they are connected to different physical switches. Subnetting divides networks based on IP address ranges, NAT translates addresses, and DHCP assigns them.",
      "examTip": "VLANs are essential for network segmentation and security, allowing you to group users and devices based on function, not just physical location."
    },
    {
      "id": 73,
      "question": "What is the purpose of a firewall's 'stateful inspection' feature?",
      "options": [
        "Blocks all inbound packets by default, ignoring session state.",
        "Keeps track of active sessions to permit valid returning traffic.",
        "Encrypts every packet that passes through the firewall.",
        "Assigns IP addresses to new hosts automatically."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Stateful inspection monitors the state of active connections and uses this information to make filtering decisions, allowing return traffic for established sessions. Blocking all incoming traffic is a default deny approach, encryption protects data, and DHCP assigns IPs.",
      "examTip": "Stateful inspection enhances firewall security by considering the context of network connections."
    },
    {
      "id": 74,
      "question": "Which of the following is a benefit of using cloud-based services?",
      "options": [
        "Complete immunity to security breaches of any kind.",
        "Easy expansion of resources on demand to meet needs.",
        "Direct physical access to servers and networking gear.",
        "An absolute guarantee of no service outages."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Cloud services offer scalability (easily adjust resources) and flexibility (choose different services as needed). Security is a shared responsibility, you don't control the physical infrastructure, and 100% uptime is rarely guaranteed (though SLAs provide high availability).",
      "examTip": "Cloud computing offers various advantages, including cost savings, scalability, and agility."
    },
    {
      "id": 75,
      "question": "What is the function of a DHCP server?",
      "options": [
        "Resolves domain names into IP addresses for hosts.",
        "Dynamically distributes addresses and network settings.",
        "Routes incoming data to separate subnets or VLANs.",
        "Filters requests based on specific keyword content."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DHCP server automates the process of IP address assignment, making network management easier. DNS translates domain names, routers route traffic, and content filters control website access.",
      "examTip": "DHCP simplifies network configuration and avoids IP address conflicts."
    },
    {
      "id": 76,
      "question": "What does the acronym 'UTP' stand for in the context of network cabling?",
      "options": [
        "Universal Twisted Pair for universal cabling standards.",
        "Unshielded Twisted Pair commonly used in Ethernet.",
        "Underground Twisted Pair for long-distance outdoor runs.",
        "Unified Threat Protection for layered security solutions."
      ],
      "correctAnswerIndex": 1,
      "explanation": "UTP stands for Unshielded Twisted Pair, a common type of copper cabling used in Ethernet networks. It lacks the shielding found in STP (Shielded Twisted Pair) cable.",
      "examTip": "UTP is cost-effective and widely used, but it's more susceptible to interference than STP."
    },
    {
      "id": 77,
      "question": "Which of the following is a characteristic of single-mode fiber optic cable?",
      "options": [
        "Ideal only for short runs like in-building cabling.",
        "Features a larger core diameter than multimode fiber.",
        "Relies on LEDs as light sources for transmission.",
        "Transmits a single light wave, supporting very long links."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Single-mode fiber has a very small core that allows only one light path (mode), minimizing signal loss and enabling very long transmission distances (often using lasers). Multimode fiber has a larger core, uses LEDs, and is for shorter distances.",
      "examTip": "Single-mode fiber is used for long-haul, high-bandwidth applications."
    },
    {
      "id": 78,
      "question": "Which of the following is an advantage of using a star topology in a wired network?",
      "options": [
        "Requires the least cabling among typical topologies.",
        "A single cable fault takes the entire network down.",
        "Simplifies troubleshooting because each node is connected centrally.",
        "Offers the highest redundancy via multiple direct links."
      ],
      "correctAnswerIndex": 2,
      "explanation": "In a star topology, each device connects to a central hub or switch. This makes it easy to identify and fix cable issues affecting only one device. It uses more cabling than a bus, a single cable failure only affects one device, and mesh topology provides higher redundancy.",
      "examTip": "Star topology's centralized design simplifies management and troubleshooting."
    },
    {
      "id": 79,
      "question": "What is the purpose of the Address Resolution Protocol (ARP)?",
      "options": [
        "Look up domain names to locate IP addresses.",
        "Hand out network configurations to DHCP clients.",
        "Translate IP addresses into corresponding physical addresses.",
        "Encrypt packets for secure end-to-end transmission."
      ],
      "correctAnswerIndex": 2,
      "explanation": "ARP is used on local networks to find the MAC address associated with a known IP address, enabling devices to communicate at the data link layer. DNS resolves domain names, DHCP assigns IPs, and encryption is handled by other protocols.",
      "examTip": "ARP is essential for communication within a local Ethernet network."
    },
    {
      "id": 80,
      "question": "What is a 'full-duplex' network connection?",
      "options": [
        "Allows data flow strictly in one direction at a time.",
        "Permits both sending and receiving at once without collisions.",
        "Uses two separate cables for inbound and outbound data.",
        "Restricts throughput to a maximum of 10 Mbps."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Full-duplex allows simultaneous bidirectional communication, increasing efficiency. Half-duplex allows communication in only one direction at a time. The number of cables and speed are separate characteristics.",
      "examTip": "Modern switched networks almost always use full-duplex connections."
    },
    {
      "id": 81,
      "question": "Which tool is MOST useful for identifying the location of a specific cable within a bundle of cables?",
      "options": [
        "Cable tester: Checks pinouts and continuity issues.",
        "Toner probe: Emits a tone so you can trace cable ends.",
        "Protocol analyzer: Captures and inspects network packets.",
        "Crimping tool: Attaches RJ-45 connectors to cable ends."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A toner probe (also called a tone generator and probe) generates a tone on one end of a cable, and the probe is used to detect that tone at the other end, even within a bundle. A cable tester checks for continuity, a protocol analyzer captures traffic, and a crimping tool attaches connectors.",
      "examTip": "Toner probes are invaluable for tracing cables in complex wiring environments."
    },
    {
      "id": 82,
      "question": "What is the purpose of the 'show ip interface brief' command on a Cisco router or switch?",
      "options": [
        "Displays the complete IP routing table for the device.",
        "Lists each interface along with its IP and up/down status.",
        "Initiates a configuration mode for editing interface settings.",
        "Reveals cached mappings of IP addresses to MAC addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `show ip interface brief` command provides a concise overview of interface status (up/down), IP addresses, and other basic information. It's a quick way to check interface configurations. `show ip route` displays the routing table, specific `interface` commands are used for configuration, and `show arp` shows the ARP cache.",
      "examTip": "`show ip interface brief` is one of the most frequently used Cisco commands for troubleshooting."
    },
    {
      "id": 83,
      "question": "What is the function of a network interface card (NIC)?",
      "options": [
        "Enables Wi-Fi access point capabilities for a LAN.",
        "Provides the hardware interface to join a network.",
        "Routes traffic between different subnets or VLANs.",
        "Supplies IP addresses automatically to client devices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A NIC provides the physical interface for a device to connect to a network, either wired or wireless (if it's a wireless NIC). It doesn't route traffic (routers do that) or assign IP addresses (DHCP servers do that).",
      "examTip": "Every device connected to a network needs a NIC."
    },
    {
      "id": 84,
      "question": "Which type of network documentation shows the physical connections between devices, including cable types and port numbers?",
      "options": [
        "Logical diagram: Shows VLANs and IP addressing schemes.",
        "Physical diagram: Depicts actual cables and interface details.",
        "IP address schema: Lists IP assignments for each device.",
        "Security policy: Describes rules for user access controls."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A physical diagram depicts the actual cabling and connections between devices. A logical diagram shows the network topology and IP addressing, an IP address schema documents IP address assignments, and a security policy outlines security rules.",
      "examTip": "Physical diagrams are essential for troubleshooting cabling problems."
    },
    {
      "id": 85,
      "question": "Which wireless standard operates in the 5 GHz frequency band *exclusively*?",
      "options": [
        "802.11g: Functions on 2.4 GHz only for moderate speeds.",
        "802.11b: Uses 2.4 GHz with up to 11 Mbps rate.",
        "802.11a: Transmits solely in the 5 GHz frequency range.",
        "802.11n: Can use both 2.4 GHz and 5 GHz bands."
      ],
      "correctAnswerIndex": 2,
      "explanation": "802.11a operates *only* in the 5 GHz band. 802.11g and 802.11b operate in the 2.4 GHz band. 802.11n can operate in both 2.4 GHz and 5 GHz.",
      "examTip": "Knowing the frequency bands of different wireless standards helps in troubleshooting interference and choosing the right standard."
    },
    {
      "id": 86,
      "question": "What is the purpose of a 'loopback address'?",
      "options": [
        "Allows external hosts to remotely access the device.",
        "Redirects data to the internet through a separate gateway.",
        "Tests local TCP/IP functionality without leaving the host.",
        "Forces a static IP configuration on a network interface."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The loopback address (127.0.0.1 in IPv4, ::1 in IPv6) is used to test network software on a device without sending traffic over the network. It's a self-referential address.",
      "examTip": "Pinging the loopback address is a quick way to verify that the TCP/IP stack is functioning correctly on a device."
    },
    {
      "id": 87,
      "question": "Which of the following is MOST likely to cause signal degradation in a UTP cable?",
      "options": [
        "Poor termination or incorrect RJ-45 connector use.",
        "Extending the cable beyond the recommended 100-meter limit.",
        "Prolonged cable storage in low-humidity environments.",
        "Ensuring good grounding and shielded jacketing."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Exceeding the maximum length of a UTP cable (typically 100 meters) causes signal attenuation and degradation. Proper grounding and correct connectors are good practices. Humidity has minimal impact on UTP.",
      "examTip": "Adhere to cable length limitations to avoid signal degradation."
    },
    {
      "id": 88,
      "question": "Which command is used to display the DNS server settings on a Windows computer?",
      "options": [
        "ipconfig /renew: Requests a new IP from the DHCP server.",
        "ipconfig /all: Shows full adapter details including DNS info.",
        "ipconfig /release: Drops the current DHCP lease.",
        "ipconfig /flushdns: Clears the DNS resolver cache."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`ipconfig /all` displays detailed network configuration, including the DNS servers being used. `/renew` requests a new DHCP lease, `/release` releases the current lease, and `/flushdns` clears the DNS cache.",
      "examTip": "`ipconfig /all` is your go-to command for checking DNS server settings on Windows."
    },
    {
      "id": 89,
      "question": "You are troubleshooting a computer that cannot connect to the network. You discover that it has an IP address of 169.254.10.5. What does this indicate?",
      "options": [
        "User manually configured a private static address.",
        "A valid address was successfully assigned via DHCP.",
        "The device assigned itself a link-local IP (APIPA).",
        "Indicates a direct connection to the public internet."
      ],
      "correctAnswerIndex": 2,
      "explanation": "An IP address in the 169.254.x.x range indicates an APIPA address, meaning the computer couldn't get an address from a DHCP server. It's not a static address, and it doesn't guarantee internet connectivity.",
      "examTip": "An APIPA address is a sign of DHCP failure."
    },
    {
      "id": 90,
      "question": "What is a common security best practice for configuring a wireless access point?",
      "options": [
        "Keep factory SSID and default login credentials as is.",
        "Disable all wireless encryption for ease of access.",
        "Use custom SSID/password and enable WPA2/WPA3 encryption.",
        "Make the SSID hidden so no device can detect it."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Always change default credentials and use the strongest available encryption (WPA3 if supported, otherwise WPA2).  Default settings are easily exploited, disabling encryption leaves the network open, and hiding the SSID is only a mild deterrent.",
      "examTip": "Securing a wireless network starts with changing defaults and enabling strong encryption."
    },
    {
      "id": 91,
      "question": "What is the role of a gateway in a TCP/IP network?",
      "options": [
        "Translates data between unrelated network protocols.",
        "Bridges networks using distinct IP addressing schemes.",
        "Controls firewall rules for inbound and outbound traffic.",
        "Serves as the router interface for external communications."
      ],
      "correctAnswerIndex": 3,
      "explanation": "The gateway, usually a router, acts as the point where traffic enters and exits your local network to reach external networks, including the internet.",
      "examTip": "The gateway address on a host is usually the IP address of the router's interface connected to the local network."
    },
    {
      "id": 92,
      "question": "Which layer of the OSI model handles reliable data transmission and flow control?",
      "options": [
        "Layer 2 (Data Link): Deals with MAC-based frames.",
        "Layer 3 (Network): Manages IP addresses and routing.",
        "Layer 4 (Transport): Ensures reliable delivery and flow control.",
        "Layer 7 (Application): Interfaces with software applications."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The Transport layer (Layer 4) provides reliable data delivery using protocols like TCP, including mechanisms for flow control, error checking, and retransmission. Layer 2 deals with physical addressing, Layer 3 with logical addressing, and Layer 7 provides application services.",
      "examTip": "Remember that TCP (connection-oriented) and UDP (connectionless) operate at the Transport layer."
    },
    {
      "id": 93,
      "question": "Which type of network device is designed to prevent unauthorized access to or from a private network?",
      "options": [
        "Switch: Directs traffic using MAC addresses on a LAN.",
        "Router: Forwards packets at Layer 3 between networks.",
        "Firewall: Blocks or allows traffic based on security policies.",
        "Hub: Broadcasts incoming signals to every connected port."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A firewall's primary purpose is to control network traffic based on security rules, blocking unauthorized access attempts. Switches connect devices within a network, routers forward traffic between networks, and hubs are simple repeaters.",
      "examTip": "Firewalls are a fundamental component of network security."
    },
    {
      "id": 94,
      "question": "What is the maximum cable length for 1000BASE-T (Gigabit Ethernet) over UTP cable?",
      "options": [
        "50 meters is recommended for all Gigabit Ethernet links.",
        "100 meters is the typical maximum for Cat5e or Cat6.",
        "150 meters, supported when STP cables are used.",
        "200 meters, assuming high-grade cable and connectors."
      ],
      "correctAnswerIndex": 1,
      "explanation": "1000BASE-T, like other common Ethernet standards over UTP, has a maximum length of 100 meters (328 feet).",
      "examTip": "Exceeding cable length limits leads to signal degradation and connectivity problems."
    },
    {
      "id": 95,
      "question": "What is a common cause of crosstalk in network cabling?",
      "options": [
        "Using improper connector terminations, which can disrupt twisting.",
        "Excessive cable bending that physically damages the conductors.",
        "Long cable runs causing attenuation and signal weakening.",
        "Poor or absent cable shielding that amplifies interference."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Crosstalk is the unwanted transfer of signals between adjacent wires within a cable, causing interference and data corruption. Bending is physical damage, signal loss is attenuation, and incorrect connectors are termination issues.",
      "examTip": "Using twisted-pair cabling and proper termination techniques helps minimize crosstalk."
    },
    {
      "id": 96,
      "question": "Which of the following is a characteristic of a virtual LAN (VLAN)?",
      "options": [
        "Demands a separate switch for each VLAN deployment.",
        "Lets you split a single switch into multiple logical networks.",
        "Expands the broadcast domain beyond standard size.",
        "Operates solely in wireless environments."
      ],
      "correctAnswerIndex": 1,
      "explanation": "VLANs create logical groupings of devices regardless of their physical location, allowing for better network segmentation and security. They reduce broadcast domain size, can be on the same physical switch, and are used primarily in wired networks.",
      "examTip": "VLANs are a crucial tool for network segmentation and security, allowing administrators to group devices based on function or security needs."
    },
    {
      "id": 97,
      "question": "You are setting up a network and need to ensure that a specific server always receives the same IP address. What DHCP feature should you use?",
      "options": [
        "DHCP scope: Defines the general IP address range.",
        "DHCP reservation: Associates a specific IP with a device’s MAC.",
        "DHCP exclusion: Keeps certain IPs out of the dynamic pool.",
        "DHCP lease time: Sets how long an address is valid."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DHCP reservation maps a specific MAC address to a specific IP address, ensuring the device always gets the same IP.  A scope defines the range of addresses, an exclusion prevents certain addresses from being assigned, and lease time controls how long an address is valid.",
      "examTip": "Use DHCP reservations for servers, printers, and other devices that require consistent IP addresses."
    },
    {
      "id": 98,
      "question": "What is the purpose of the Domain Name System (DNS)?",
      "options": [
        "Automatically assigns IP addresses to network clients.",
        "Maps human-friendly names to IP addresses for connectivity.",
        "Implements encryption for data in transit across WAN links.",
        "Blocks web traffic based on keywords or URL patterns."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DNS acts like the internet's phone book, converting domain names into the IP addresses that computers use to communicate. DHCP assigns IPs, encryption is handled by other protocols, and content filtering is done by firewalls or specialized software.",
      "examTip": "Without DNS, we'd have to remember IP addresses instead of website names."
    },
    {
      "id": 99,
      "question": "Which of the following is a security risk associated with using a public Wi-Fi network?",
      "options": [
        "Achieving faster upload and download speeds automatically.",
        "Utilizing stronger encryption methods than private networks.",
        "Allowing attackers to intercept or snoop on user traffic.",
        "Gaining unrestricted entry to all corporate resources."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Public Wi-Fi networks often lack strong security, making it easier for attackers to intercept data transmitted over the network. They don't inherently offer faster speeds or stronger encryption, and access to resources is usually restricted.",
      "examTip": "Use a VPN when connecting to public Wi-Fi to protect your data."
    },
    {
      "id": 100,
      "question": "What is a 'default route' in a routing table?",
      "options": [
        "Used only for traffic remaining on the local subnet.",
        "A fallback path if the destination is not in any other routes.",
        "Applies exclusively to internal network communications.",
        "The route selected based on the highest priority metric."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The default route is the 'route of last resort'. If a router doesn't have a more specific route in its table for a destination IP address, it sends the packet to the default gateway specified by the default route. It's not for local or internal traffic specifically, and administrative distance determines route preference, not what a default route is.",
      "examTip": "The default route is essential for connecting to networks outside the locally configured ones (like the internet)."
    }
  ]
});



