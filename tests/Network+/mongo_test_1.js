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
        "Layer 2 - Data Link",
        "Layer 3 - Network",
        "Layer 4 - Transport",
        "Layer 7 - Application"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The Network layer (Layer 3) handles logical addressing (like IP addresses) and determines the best path for data to travel (routing). Layer 2 uses physical addresses (MAC addresses). Layer 4 manages reliable data transfer. Layer 7 provides network services to applications.",
      "examTip": "Remember the OSI model layers in order (Please Do Not Throw Sausage Pizza Away).  Focus on the key function of each layer."
    },
    {
      "id": 2,
      "question": "What is the purpose of a firewall in a network?",
      "options": [
        "To provide wireless connectivity to devices.",
        "To manage IP address allocation.",
        "To filter network traffic based on predefined rules.",
        "To boost the speed of network connections."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Firewalls act as security barriers, controlling network traffic by allowing or blocking it based on configured rules.  They don't provide wireless access, manage IPs (that's DHCP), or directly boost speed.",
      "examTip": "Think of a firewall as a gatekeeper for network traffic, focusing on security."
    },
    {
      "id": 3,
      "question": "Which of the following is a characteristic of a Storage Area Network (SAN)?",
      "options": [
        "Provides block-level access to storage devices.",
        "Uses the same cabling as the main network.",
        "Is primarily used for file sharing within a small office.",
        "Offers lower performance compared to NAS."
      ],
      "correctAnswerIndex": 0,
      "explanation": "SANs offer block-level access, making them appear as locally attached drives to servers. They typically use dedicated, high-speed connections (like Fibre Channel), not the main network cabling.  They are designed for high performance, unlike NAS, which is file-level.",
      "examTip": "Distinguish between SAN (block-level, high-performance) and NAS (file-level, easier to manage)."
    },
    {
      "id": 4,
      "question": "You are setting up a new wireless network.  Which standard provides the BEST combination of speed and security for most modern devices?",
      "options": [
        "802.11b",
        "802.11g",
        "802.11ac",
        "802.11ax (Wi-Fi 6/6E)"
      ],
      "correctAnswerIndex": 3,
      "explanation": "802.11ax (Wi-Fi 6/6E) is the most current standard, offering the best speed, efficiency, and security features. The others are older and less performant/secure.",
      "examTip": "Keep up-to-date with the latest wireless standards.  Remember that newer standards generally offer significant improvements."
    },
    {
      "id": 5,
      "question": "What is the FIRST step you should take when troubleshooting a network connectivity issue?",
      "options": [
        "Replace the network cable.",
        "Reboot the router.",
        "Gather information about the problem.",
        "Contact your internet service provider (ISP)."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The first step in troubleshooting is always to gather information: identify symptoms, talk to users, and determine what, if anything, has changed.  Jumping to solutions without understanding the problem is inefficient.",
      "examTip": "Always follow the troubleshooting methodology:  Gather information *before* taking action."
    },
    {
      "id": 6,
      "question": "Which port is commonly used for unencrypted web traffic?",
      "options": [
        "21",
        "22",
        "80",
        "443"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Port 80 is the standard port for HTTP (Hypertext Transfer Protocol), which is unencrypted web traffic. Port 443 is for HTTPS (secure). 21 is FTP, and 22 is SSH.",
      "examTip": "Memorize the common port numbers for key services like HTTP, HTTPS, FTP, SSH, and DNS."
    },
    {
      "id": 7,
      "question": "A user reports they cannot access a specific website.  You can ping the website's IP address successfully.  What is the MOST likely cause?",
      "options": [
        "A faulty network cable on the user's computer.",
        "A DNS resolution problem.",
        "The website's server is down.",
        "The user's IP address is blocked."
      ],
      "correctAnswerIndex": 1,
      "explanation": "If you can ping the IP address but not access the website by name, the issue is likely with DNS resolution (translating the website name to an IP address). A faulty cable would prevent pinging.  If the server was down, you likely couldn't ping it.",
      "examTip": "Distinguish between IP connectivity (ping) and name resolution (DNS) when troubleshooting access problems."
    },
    {
      "id": 8,
      "question": "What type of cable is MOST resistant to electromagnetic interference (EMI)?",
      "options": [
        "UTP (Unshielded Twisted Pair)",
        "STP (Shielded Twisted Pair)",
        "Coaxial Cable",
        "Fiber Optic Cable"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Fiber optic cable uses light instead of electricity, making it immune to EMI. STP offers more protection than UTP, and coaxial cable has some shielding but is less resistant than fiber.",
      "examTip": "Remember that fiber optic cable is the best choice for environments with high EMI."
    },
    {
      "id": 9,
      "question": "Which command is used to display the routing table on a Windows computer?",
      "options": [
        "ipconfig /all",
        "route print",
        "netstat -r",
        "tracert"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`route print` displays the routing table. `ipconfig /all` shows network interface configuration, `netstat -r` shows routing information (but not as clearly), and `tracert` traces the route to a destination.",
      "examTip": "Learn the specific commands for viewing routing tables on both Windows and Linux systems."
    },
    {
      "id": 10,
      "question": "What is a subnet mask used for?",
      "options": [
        "To encrypt network traffic.",
        "To identify the network and host portions of an IP address.",
        "To assign IP addresses dynamically.",
        "To filter network traffic based on MAC addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The subnet mask defines which bits of an IP address represent the network and which represent the host.  This is crucial for routing and network segmentation.  It doesn't encrypt, assign addresses (DHCP does that), or filter by MAC address (switches do that).",
      "examTip": "Understand how subnet masks work to divide an IP address into network and host identifiers."
    },
    {
      "id": 11,
      "question": "Which of the following is an example of a Class C IP address?",
      "options": [
        "10.0.0.5",
        "172.16.1.10",
        "192.168.1.100",
        "224.0.0.1"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Class C IP addresses range from 192.0.0.0 to 223.255.255.255.  10.x.x.x is Class A, 172.16.x.x - 172.31.x.x is Class B, and 224.x.x.x is Class D (multicast).",
      "examTip": "Memorize the IP address class ranges, even though classful addressing is largely obsolete."
    },
    {
      "id": 12,
      "question": "What is the purpose of the `traceroute` (or `tracert`) command?",
      "options": [
        "To test the speed of a network connection.",
        "To display the IP address of a website.",
        "To show the path that packets take to reach a destination.",
        "To configure a network interface."
      ],
      "correctAnswerIndex": 2,
      "explanation": "`traceroute` shows the hops (routers) that packets traverse to reach a target host, helping diagnose routing problems. It doesn't directly measure speed, display IP addresses (that's `nslookup` or `dig`), or configure interfaces.",
      "examTip": "Use `traceroute` to identify points of failure or latency along a network path."
    },
    {
      "id": 13,
      "question": "Which wireless security protocol is considered the MOST secure?",
      "options": [
        "WEP",
        "WPA",
        "WPA2",
        "WPA3"
      ],
      "correctAnswerIndex": 3,
      "explanation": "WPA3 is the latest and most secure wireless security protocol, offering stronger encryption and protection against attacks. WEP is extremely vulnerable, and WPA and WPA2 have known weaknesses.",
      "examTip": "Always use WPA3 if your devices support it.  Avoid WEP entirely."
    },
    {
      "id": 14,
      "question": "You are configuring a DHCP server.  What is the purpose of a DHCP reservation?",
      "options": [
        "To exclude a range of IP addresses from being assigned.",
        "To assign a specific IP address to a particular MAC address.",
        "To limit the lease time for IP addresses.",
        "To create a backup of the DHCP server configuration."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DHCP reservation ensures that a specific device (identified by its MAC address) always receives the same IP address from the DHCP server.  Exclusions prevent addresses from being assigned, lease time controls how long an address is valid, and backups are separate configurations.",
      "examTip": "Use DHCP reservations for devices that need consistent IP addresses, like servers or printers."
    },
    {
      "id": 15,
      "question": "What is the default subnet mask for a Class B network?",
      "options": [
        "255.0.0.0",
        "255.255.0.0",
        "255.255.255.0",
        "255.255.255.255"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The default subnet mask for a Class B network is 255.255.0.0. Class A is 255.0.0.0, Class C is 255.255.255.0, and 255.255.255.255 is typically used for a single host or a broadcast address.",
      "examTip": "Understand the relationship between IP address classes and their default subnet masks."
    },
    {
      "id": 16,
      "question": "Which technology allows multiple VLANs to be transmitted over a single physical link?",
      "options": [
        "STP (Spanning Tree Protocol)",
        "VTP (VLAN Trunking Protocol)",
        "802.1Q Trunking",
        "Link Aggregation"
      ],
      "correctAnswerIndex": 2,
      "explanation": "802.1Q trunking (also just called trunking) adds tags to Ethernet frames to identify the VLAN they belong to, allowing multiple VLANs to share a single link. STP prevents loops, VTP manages VLAN databases, and link aggregation combines multiple links into one logical link.",
      "examTip": "Remember that 802.1Q is the standard for VLAN tagging on trunk links."
    },
    {
      "id": 17,
      "question": "A network administrator needs to connect two buildings that are 500 meters apart. Which cabling type is MOST appropriate?",
      "options": [
        "UTP Cat 6",
        "STP Cat 6a",
        "Multimode Fiber",
        "Single-mode Fiber"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Multimode fiber is suitable for distances up to a few hundred meters and is generally less expensive than single-mode fiber. UTP and STP Cat 6/6a are limited to 100 meters. Single-mode fiber is for much longer distances (kilometers).",
      "examTip": "Consider distance limitations when choosing cable types.  Multimode fiber is often used for shorter distances within a building or campus."
    },
    {
      "id": 18,
      "question": "What is the function of a DNS server?",
      "options": [
        "To assign IP addresses to devices.",
        "To translate domain names to IP addresses.",
        "To route traffic between networks.",
        "To provide secure remote access to a network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DNS servers translate human-readable domain names (like google.com) into IP addresses that computers use to communicate. DHCP assigns IP addresses, routers route traffic, and VPNs provide secure remote access.",
      "examTip": "Think of DNS as the 'phone book' of the internet, converting names to numbers."
    },
    {
      "id": 19,
      "question": "Which protocol operates at the Transport layer of the OSI model and provides reliable, connection-oriented communication?",
      "options": [
        "UDP",
        "TCP",
        "IP",
        "ICMP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "TCP (Transmission Control Protocol) is a connection-oriented protocol that provides reliable data delivery with error checking and retransmission. UDP is connectionless and unreliable. IP is at the Network layer, and ICMP is used for diagnostics (like ping).",
      "examTip": "Differentiate between TCP (reliable) and UDP (unreliable) at the Transport layer."
    },
    {
      "id": 20,
      "question": "You need to configure a network device to allow SSH access only from a specific management workstation. What is the BEST way to achieve this?",
      "options": [
        "Configure an access control list (ACL).",
        "Enable MAC filtering.",
        "Change the default SSH port.",
        "Disable all other services on the device."
      ],
      "correctAnswerIndex": 0,
      "explanation": "An ACL allows you to specify which IP addresses or networks are permitted to access specific services (like SSH). MAC filtering is less secure (easily spoofed). Changing the SSH port provides obscurity, not strong security. Disabling other services is unnecessary and might impact functionality.",
      "examTip": "Use ACLs to control access to network devices and services based on IP addresses."
    },
    {
      "id": 21,
      "question": "What does 'PoE' stand for in networking?",
      "options": [
        "Power over Ethernet",
        "Point of Entry",
        "Packet over Ethernet",
        "Port over Ethernet"
      ],
      "correctAnswerIndex": 0,
      "explanation": "PoE stands for Power over Ethernet, a technology that allows network cables to carry electrical power.",
      "examTip": "PoE simplifies deployments by providing power and data over a single cable."
    },
    {
      "id": 22,
      "question": "Which of the following is a valid IPv6 address?",
      "options": [
        "192.168.1.1",
        "2001:db8::1",
        "172.32.1.256",
        "255.255.255.0"
      ],
      "correctAnswerIndex": 1,
      "explanation": "2001:db8::1 is a valid IPv6 address. IPv6 addresses are 128 bits long and written in hexadecimal. The other options are IPv4 addresses or a subnet mask.",
      "examTip": "Recognize the format of IPv6 addresses (hexadecimal, colons, and double colons for consecutive zero groups)."
    },
    {
      "id": 23,
      "question": "What is the main purpose of an Intrusion Detection System (IDS)?",
      "options": [
        "To prevent unauthorized access to a network.",
        "To monitor network traffic for malicious activity and generate alerts.",
        "To encrypt network traffic.",
        "To assign IP addresses dynamically."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An IDS passively monitors network traffic and alerts administrators to potential security breaches. Firewalls prevent access, encryption protects data, and DHCP assigns IPs.",
      "examTip": "Differentiate between IDS (detects) and IPS (prevents) intrusions."
    },
    {
      "id": 24,
      "question": "Which type of network topology connects all devices to a central hub or switch?",
      "options": [
        "Bus",
        "Ring",
        "Star",
        "Mesh"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A star topology uses a central device (hub or switch) to connect all other nodes. Bus uses a single cable, ring connects devices in a loop, and mesh has multiple connections between devices.",
      "examTip": "Star topology is the most common in modern Ethernet networks due to its ease of management and fault tolerance."
    },
    {
      "id": 25,
      "question": "You observe high latency when accessing a cloud-based application. Which tool would be MOST helpful in identifying the source of the delay?",
      "options": [
        "ping",
        "tracert/traceroute",
        "ipconfig",
        "nslookup"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Tracert/traceroute shows the path and delay at each hop, helping pinpoint where latency is occurring. Ping only tests basic connectivity, ipconfig shows local interface configuration, and nslookup resolves domain names.",
      "examTip": "Use tracert/traceroute for diagnosing latency issues across multiple network segments."
    },
    {
      "id": 26,
      "question": "What is the primary advantage of using fiber optic cable over copper cable?",
      "options": [
        "Lower cost",
        "Easier installation",
        "Greater bandwidth and longer distances",
        "Better resistance to physical damage"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Fiber optic cables offer significantly higher bandwidth and can transmit data over much longer distances than copper cables. They are generally more expensive and can be more complex to install.",
      "examTip": "Fiber is the preferred choice for high-speed, long-distance network connections."
    },
    {
      "id": 27,
      "question": "Which command is used to release and renew a DHCP lease on a Windows computer?",
      "options": [
        "ipconfig /release then ipconfig /renew",
        "ipconfig /flushdns",
        "netsh winsock reset",
        "route add"
      ],
      "correctAnswerIndex": 0,
      "explanation": "ipconfig /release releases the current DHCP lease, and ipconfig /renew requests a new one. ipconfig /flushdns clears the DNS resolver cache, netsh winsock reset resets the Winsock catalog, and route add adds a static route.",
      "examTip": "Use ipconfig /release and ipconfig /renew to troubleshoot DHCP-related connectivity issues."
    },
    {
      "id": 28,
      "question": "What is a MAC address?",
      "options": [
        "A unique physical address assigned to a network interface.",
        "A logical address used for routing.",
        "An address assigned by a DHCP server.",
        "A type of network cable."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A MAC address is a unique hardware address burned into a network interface card (NIC). IP addresses are logical and assigned by DHCP or static configuration.",
      "examTip": "MAC addresses are used for communication within a local network segment (Layer 2)."
    },
    {
      "id": 29,
      "question": "You are setting up a small office network.  Which device is MOST likely to provide both routing and switching functionality?",
      "options": [
        "A dedicated router",
        "A dedicated switch",
        "A modem",
        "A SOHO (Small Office/Home Office) router"
      ],
      "correctAnswerIndex": 3,
      "explanation": "SOHO routers typically combine routing, switching, and often wireless access point functionality into a single device.  Dedicated routers and switches perform only their specific function, and a modem connects to the internet but doesn't route or switch.",
      "examTip": "SOHO routers are common in small networks for their all-in-one convenience."
    },
    {
      "id": 30,
      "question": "What is the purpose of a default gateway?",
      "options": [
        "To provide a path for traffic to leave the local network.",
        "To assign IP addresses to devices on the network.",
        "To filter network traffic based on MAC addresses.",
        "To translate domain names to IP addresses."
      ],
      "correctAnswerIndex": 0,
      "explanation": "The default gateway is the IP address of the router that a device uses to send traffic to destinations outside the local network.  DHCP assigns IP addresses, switches filter by MAC address, and DNS servers translate domain names.",
      "examTip": "Without a default gateway, devices can only communicate within their local subnet."
    },
    {
      "id": 31,
      "question": "Which of the following network services uses UDP port 53?",
      "options": [
        "SMTP",
        "DNS",
        "DHCP",
        "HTTP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "DNS primarily uses UDP port 53 for name resolution queries.  SMTP uses TCP port 25, DHCP uses UDP ports 67 and 68, and HTTP uses TCP port 80.",
      "examTip": "Remember that DNS uses UDP for speed, although it can also use TCP for larger responses or zone transfers."
    },
    {
      "id": 32,
      "question": "What is the maximum data transfer rate of standard 802.11g wireless networks?",
      "options": [
        "11 Mbps",
        "54 Mbps",
        "150 Mbps",
        "300 Mbps"
      ],
      "correctAnswerIndex": 1,
      "explanation": "802.11g has a maximum data rate of 54 Mbps. 802.11b is 11 Mbps, and 802.11n can reach higher speeds.",
      "examTip": "Know the approximate speeds of the common 802.11 standards (b, g, n, ac, ax)."
    },
    {
      "id": 33,
      "question": "What command would you use to view the Address Resolution Protocol (ARP) cache on a Windows machine?",
      "options": [
        "arp -a",
        "ipconfig /displaydns",
        "netstat -an",
        "show arp"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `arp -a` command displays the ARP cache, which maps IP addresses to MAC addresses. ipconfig /displaydns shows DNS cache, netstat -an shows network connections, and show arp is a common Cisco command.",
      "examTip": "The ARP cache is crucial for local network communication, allowing devices to find each other's MAC addresses."
    },
    {
      "id": 34,
      "question": "A network is experiencing intermittent connectivity issues.  You suspect a faulty patch cable. Which tool would be MOST useful for testing the cable?",
      "options": [
        "Protocol analyzer",
        "Cable tester",
        "Toner probe",
        "Wi-Fi analyzer"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A cable tester checks for continuity, shorts, and other physical cable problems. A protocol analyzer captures network traffic, a toner probe helps locate cables, and a Wi-Fi analyzer is for wireless networks.",
      "examTip": "Use a cable tester as a first step when troubleshooting physical layer connectivity problems."
    },
    {
      "id": 35,
      "question": "What is the purpose of Network Address Translation (NAT)?",
      "options": [
        "To encrypt network traffic.",
        "To translate public IP addresses to private IP addresses, and vice versa.",
        "To assign IP addresses dynamically.",
        "To filter network traffic based on content."
      ],
      "correctAnswerIndex": 1,
      "explanation": "NAT allows multiple devices on a private network to share a single public IP address, conserving public IP addresses and providing a layer of security. Encryption protects data, DHCP assigns IPs, and content filters control access to specific websites or content.",
      "examTip": "NAT is essential for connecting private networks to the internet using a limited number of public IP addresses."
    },
    {
      "id": 36,
      "question": "Which type of VPN creates a secure, encrypted tunnel between two networks over the internet?",
      "options": [
        "Client-to-site VPN",
        "Site-to-site VPN",
        "Remote access VPN",
        "Clientless VPN"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A site-to-site VPN connects two entire networks (e.g., two branch offices). Client-to-site (or remote access) connects a single device to a network. Clientless VPNs provide access to specific applications without a full network tunnel.",
      "examTip": "Distinguish between site-to-site (network-to-network) and client-to-site (device-to-network) VPNs."
    },
    {
      "id": 37,
      "question": "What is the function of a router in a network?",
      "options": [
        "To connect devices within the same local area network (LAN).",
        "To forward data packets between different networks.",
        "To convert digital signals to analog signals.",
        "To filter network traffic based on MAC addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Routers operate at Layer 3 (Network) and forward packets based on IP addresses, connecting different networks. Switches connect devices within the same LAN, modems convert signals, and switches(not routers) can filter based on mac addreses.",
      "examTip": "Routers are the 'traffic cops' of the internet, directing data between networks."
    },
    {
      "id": 38,
      "question": "Which of the following is an advantage of using a cloud-based service model like IaaS?",
      "options": [
        "Reduced capital expenditure on hardware.",
        "Automatic software updates and patching.",
        "Simplified application development.",
        "Guaranteed data security."
      ],
      "correctAnswerIndex": 0,
      "explanation": "IaaS (Infrastructure as a Service) allows you to rent virtualized computing resources, reducing the need to purchase and maintain physical hardware. SaaS provides automatic updates, PaaS simplifies development, and security is a shared responsibility in the cloud, not a guarantee.",
      "examTip": "Understand the different cloud service models (IaaS, PaaS, SaaS) and their respective benefits."
    },
    {
      "id": 39,
      "question": "What is the purpose of a 'DMZ' in a network?",
      "options": [
        "To provide a secure zone for internal servers.",
        "To create a separate network for wireless devices.",
        "To host publicly accessible servers while protecting the internal network.",
        "To act as a backup power source for network devices."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A DMZ (Demilitarized Zone) is a network segment that sits between the internal network and the internet, providing a buffer zone for servers that need to be accessible from the outside (like web servers). It doesn't secure internal servers directly, separate wireless devices, or provide backup power.",
      "examTip": "Think of a DMZ as a 'semi-trusted' zone for publicly accessible resources."
    },
    {
      "id": 40,
      "question": "Which protocol is used to securely manage and monitor network devices?",
      "options": [
        "SNMP (Simple Network Management Protocol)",
        "Telnet",
        "FTP (File Transfer Protocol)",
        "HTTP (Hypertext Transfer Protocol)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SNMP is used to monitor and manage network devices. While SNMPv3 offers security features, the earlier versions (v1 and v2c) are not secure. Telnet, FTP, and HTTP are not designed for secure device management.",
      "examTip": "Use SNMPv3 for secure device management, and avoid using earlier, insecure versions."
    },
    {
      "id": 41,
      "question": "What is the purpose of using VLANs?",
      "options": [
        "To increase network bandwidth.",
        "To segment a physical network into multiple logical networks.",
        "To encrypt network traffic.",
        "To assign IP addresses to devices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "VLANs logically separate a physical network into multiple broadcast domains, improving security and manageability. They don't directly increase bandwidth, encrypt traffic, or assign IPs (DHCP does that).",
      "examTip": "VLANs are a fundamental tool for network segmentation and security."
    },
    {
      "id": 42,
      "question": "When configuring a wireless access point, what does the SSID represent?",
      "options": [
        "The encryption key for the network.",
        "The name of the wireless network.",
        "The MAC address of the access point.",
        "The IP address of the access point."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The SSID (Service Set Identifier) is the name that identifies a wireless network to users. The encryption key secures the network, the MAC address is the physical address of the AP, and the IP address is its logical address.",
      "examTip": "The SSID is what users see when they search for available Wi-Fi networks."
    },
    {
      "id": 43,
      "question": "What is the role of an authoritative DNS server?",
      "options": [
        "To cache DNS records from other servers.",
        "To hold the master copy of DNS records for a specific domain.",
        "To forward DNS requests to other servers.",
        "To provide DNS services to home users."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An authoritative DNS server holds the original, master records for a domain. Caching servers store copies of records, forwarding servers relay requests, and home users typically use recursive DNS servers provided by their ISP.",
      "examTip": "Authoritative servers are the ultimate source of truth for DNS information about a domain."
    },
    {
      "id": 44,
      "question": "You are troubleshooting a network where users are experiencing slow file transfers. You suspect a duplex mismatch. What does this mean?",
      "options": [
        "One device is operating in half-duplex mode, and the other is in full-duplex mode.",
        "The network cable is too long.",
        "The devices are using different IP addresses.",
        "The network switch is overloaded."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A duplex mismatch occurs when two connected devices are configured for different duplex settings (half-duplex allows communication in only one direction at a time, full-duplex allows simultaneous bidirectional communication). This causes collisions and performance issues.",
      "examTip": "Ensure that both ends of a network connection have matching speed and duplex settings."
    },
    {
      "id": 45,
      "question": "Which of the following is a characteristic of a mesh network topology?",
      "options": [
        "All devices are connected to a central hub.",
        "Devices are connected in a circular loop.",
        "Each device has multiple paths to other devices.",
        "Devices are connected along a single cable."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Mesh networks provide high redundancy because each node has multiple connections to other nodes. Star uses a central hub, ring uses a loop, and bus uses a single cable.",
      "examTip": "Mesh networks are highly resilient but can be more complex to manage."
    },
    {
      "id": 46,
      "question": "What information can be found on the Main Distribution Frame (MDF) of a network?",
      "options": [
        "Connections from IDFs and external lines",
        "End-user workstations",
        "Wireless access points",
        "Individual patch cables"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The MDF is the central point where connections from IDFs (Intermediate Distribution Frames) and incoming lines from service providers terminate.  Workstations and access points are connected at IDFs, not the MDF.  Patch cables connect within a rack, but the overall termination is at the MDF or IDF.",
      "examTip": "Think of the MDF as the 'core' of the structured cabling system, connecting to the outside world and the IDFs."
    },
    {
      "id": 47,
      "question": "What is the function of a hypervisor in virtualization?",
      "options": [
        "It creates and runs virtual machines by abstracting the underlying hardware.",
        "It provides network connectivity for virtual machines.",
        "It manages storage for virtual machines.",
        "It handles backup and recovery for virtual machines."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A hypervisor (or Virtual Machine Monitor - VMM) is software that creates and runs virtual machines, abstracting the underlying hardware. It doesn't directly provide network connectivity (that's handled by virtual switches), store files (that's the storage system), or perform backups (although it can facilitate them).",
      "examTip": "The hypervisor is the foundation of virtualization, allowing multiple operating systems to run on a single physical host."
    },
    {
      "id": 48,
      "question": "What does 'MTU' stand for in networking?",
      "options": [
        "Maximum Transmission Unit",
        "Media Transfer Unit",
        "Minimum Transmission Unit",
        "Main Transfer Utility"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MTU stands for Maximum Transmission Unit, which defines the largest packet size that can be transmitted over a network without fragmentation.",
      "examTip": "An incorrect MTU setting can lead to performance problems and fragmentation."
    },
    {
      "id": 49,
      "question": "What is the primary difference between a Layer 2 switch and a Layer 3 switch?",
      "options": [
        "Layer 2 switches forward traffic based on MAC addresses; Layer 3 switches forward traffic based on IP addresses.",
        "Layer 2 switches are faster than Layer 3 switches.",
        "Layer 2 switches support VLANs; Layer 3 switches do not.",
        "Layer 2 switches are used in small networks; Layer 3 switches are used in large networks."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Layer 2 switches operate at the data link layer and make forwarding decisions based on MAC addresses (within a single network). Layer 3 switches operate at the network layer and can route traffic between different networks based on IP addresses. Both can support VLANs; speed depends on the specific model; and both can be used in various network sizes.",
      "examTip": "Layer 3 switches combine switching and routing functionality."
    },
    {
      "id": 50,
      "question": "Which security protocol is used to authenticate users and devices on a network using a centralized database, often used with 802.1X?",
      "options": [
        "RADIUS",
        "SSH",
        "SSL/TLS",
        "IPsec"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RADIUS (Remote Authentication Dial-In User Service) is a networking protocol that provides centralized authentication, authorization, and accounting (AAA) management. SSH is for secure remote access, SSL/TLS encrypts web traffic, and IPsec is used for VPNs.",
      "examTip": "RADIUS is commonly used for network access control, especially with 802.1X port-based authentication."
    },
    {
      "id": 51,
      "question": "What is the purpose of Spanning Tree Protocol (STP)?",
      "options": [
        "To increase network bandwidth.",
        "To prevent loops in switched networks.",
        "To encrypt network traffic.",
        "To assign IP addresses to devices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "STP prevents broadcast storms and network outages caused by loops in a switched network by blocking redundant paths. It doesn't increase bandwidth, encrypt traffic, or assign IPs.",
      "examTip": "STP is essential for maintaining a stable switched network with redundant links."
    },
    {
      "id": 52,
      "question": "What is a 'broadcast domain'?",
      "options": [
        "The area covered by a wireless access point.",
        "The set of all devices that receive broadcast frames originating from any device within the set.",
        "The range of IP addresses assigned by a DHCP server.",
        "The physical cabling infrastructure of a network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A broadcast domain is a logical division of a network where all nodes can reach each other by broadcast at the data link layer. VLANs are used to segment broadcast domains.",
      "examTip": "Switches forward broadcasts within a broadcast domain; routers separate broadcast domains."
    },
    {
      "id": 53,
      "question": "Which command would you use to test basic network connectivity to a remote host, measuring round-trip time?",
      "options": [
        "tracert",
        "ping",
        "nslookup",
        "ipconfig"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `ping` command sends ICMP echo requests to a host and measures the time it takes to receive a reply. `tracert` shows the route, `nslookup` resolves domain names, and `ipconfig` displays local network configuration.",
      "examTip": "`ping` is a fundamental tool for troubleshooting network connectivity."
    },
    {
      "id": 54,
      "question": "A network administrator wants to ensure that only authorized devices can connect to specific switch ports. Which technology BEST achieves this?",
      "options": [
        "VLANs",
        "Port Security",
        "DHCP Snooping",
        "STP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Port security allows you to restrict access to a switch port based on MAC address, limiting which devices can connect. VLANs segment networks logically, DHCP snooping prevents rogue DHCP servers, and STP prevents loops.",
      "examTip": "Port security is a key component of network access control at the switch level."
    },
    {
      "id": 55,
      "question": "What is 'jitter' in the context of network performance?",
      "options": [
        "The variation in delay between packets.",
        "The total time it takes for a packet to travel from source to destination.",
        "The amount of data lost during transmission.",
        "The maximum bandwidth of a network connection."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Jitter is the variability in latency (delay) over time.  It's particularly important for real-time applications like VoIP and video conferencing. Latency is the overall delay, packet loss is data loss, and bandwidth is capacity.",
      "examTip": "High jitter can cause choppy audio and video in real-time communications."
    },
    {
      "id": 56,
      "question": "Which of the following is a benefit of network segmentation?",
      "options": [
        "Increased broadcast traffic.",
        "Improved security and reduced congestion.",
        "Simplified network management.",
        "Lower network costs."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Network segmentation, often achieved with VLANs, isolates network traffic, improving security by limiting the impact of breaches and reducing congestion by limiting broadcast domains. It can *increase* management complexity initially, and costs depend on implementation.",
      "examTip": "Segmentation is a crucial security best practice, especially for isolating sensitive systems."
    },
    {
      "id": 57,
      "question": "What is the purpose of the `nslookup` command?",
      "options": [
        "To display the routing table.",
        "To query DNS servers for information about domain names and IP addresses.",
        "To test network connectivity to a remote host.",
        "To configure a network interface."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`nslookup` is used to troubleshoot DNS resolution issues by querying DNS servers. `route print` displays routing tables, `ping` tests connectivity, and `ipconfig` configures interfaces.",
      "examTip": "Use `nslookup` to verify that domain names are resolving correctly to IP addresses."
    },
    {
      "id": 58,
      "question": "Which of the following is the MOST secure method for remote access to a network device's command-line interface?",
      "options": [
        "Telnet",
        "SSH",
        "HTTP",
        "FTP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SSH (Secure Shell) encrypts the communication session, protecting usernames, passwords, and commands. Telnet, HTTP, and FTP transmit data in plain text, making them vulnerable to eavesdropping.",
      "examTip": "Always use SSH for remote command-line access; never use Telnet."
    },
    {
      "id": 59,
      "question": "What is a 'collision domain'?",
      "options": [
        "The area covered by a wireless access point.",
        "The set of devices on a network where their transmissions can collide with each other.",
        "The range of IP addresses assigned by a DHCP server.",
        "The physical cabling infrastructure of a network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A collision domain is a network segment where devices share the same bandwidth and their transmissions can interfere with each other.  Hubs create large collision domains; switches segment collision domains (each port is its own collision domain).",
      "examTip": "Switches eliminate collisions in modern Ethernet networks, unlike hubs."
    },
    {
      "id": 60,
      "question": "Which of the following is an example of a network monitoring tool?",
      "options": [
        "Wireshark",
        "Microsoft Word",
        "Adobe Photoshop",
        "AutoCAD"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Wireshark is a popular protocol analyzer used for network monitoring and troubleshooting. The other options are applications for different purposes.",
      "examTip": "Protocol analyzers like Wireshark capture and analyze network traffic, providing valuable insights."
    },
    {
      "id": 61,
      "question": "You need to implement Quality of Service (QoS) on your network.  What is the PRIMARY purpose of QoS?",
      "options": [
        "To encrypt network traffic.",
        "To prioritize certain types of network traffic over others.",
        "To assign IP addresses to devices.",
        "To filter network traffic based on MAC addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "QoS allows you to give preferential treatment to specific applications or types of traffic (like voice or video) to ensure their performance.  It doesn't encrypt, assign IPs, or filter by MAC address.",
      "examTip": "QoS is essential for ensuring the performance of real-time applications on congested networks."
    },
    {
      "id": 62,
      "question": "Which type of IP address is automatically assigned to a device when it fails to obtain an address from a DHCP server?",
      "options": [
        "Static IP address",
        "Dynamic IP address",
        "APIPA (Automatic Private IP Addressing) address",
        "Public IP address"
      ],
      "correctAnswerIndex": 2,
      "explanation": "APIPA addresses (in the range 169.254.x.x) are self-assigned by devices when a DHCP server is unavailable. Static IPs are manually configured, dynamic IPs are assigned by DHCP, and public IPs are used on the internet.",
      "examTip": "APIPA allows limited local communication when DHCP fails, but it doesn't provide internet access."
    },
    {
      "id": 63,
      "question": "What is the purpose of the `ipconfig /all` command on a Windows system?",
      "options": [
        "To display the routing table.",
        "To release and renew a DHCP lease.",
        "To display detailed network interface configuration information.",
        "To test network connectivity to a remote host."
      ],
      "correctAnswerIndex": 2,
      "explanation": "`ipconfig /all` shows comprehensive information about network adapters, including IP address, subnet mask, default gateway, DNS servers, MAC address, and DHCP status. `route print` shows the routing table, `ipconfig /release` and `/renew` manage DHCP leases, and `ping` tests connectivity.",
      "examTip": "`ipconfig /all` is a valuable tool for gathering network configuration details on Windows."
    },
    {
      "id": 64,
      "question": "Which of the following best describes a 'virtual private network' (VPN)?",
      "options": [
        "A network that uses physical cables to connect devices.",
        "A network that is only accessible within a specific geographic location.",
        "A secure, encrypted connection over a public network, such as the internet.",
        "A network that is used exclusively for video conferencing."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A VPN creates a secure tunnel over a public network, allowing users to access private resources remotely as if they were directly connected. It's not limited to a specific location or purpose.",
      "examTip": "VPNs are essential for secure remote access and protecting data privacy over untrusted networks."
    },
    {
      "id": 65,
      "question": "What is the function of an access point (AP) in a wireless network?",
      "options": [
        "To connect wireless devices to a wired network.",
        "To assign IP addresses to wireless devices.",
        "To filter wireless traffic based on MAC addresses.",
        "To encrypt wireless traffic."
      ],
      "correctAnswerIndex": 0,
      "explanation": "An AP acts as a bridge between wireless devices and a wired network. While an AP *can* be part of a system that assigns IP addresses (like a router with a built in AP), assigns IP addresses through DHCP, and encrypts traffic (using protocols like WPA2/WPA3), its *primary* function is bridging the wireless and wired networks.",
      "examTip": "Think of an AP as a 'wireless switch' that connects Wi-Fi devices to the wired network."
    },
    {
      "id": 66,
      "question": "Which network device operates primarily at Layer 1 (Physical) of the OSI model?",
      "options": [
        "Router",
        "Switch",
        "Hub",
        "Firewall"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A hub is a simple device that repeats signals received on one port to all other ports. It operates at the physical layer and doesn't examine MAC addresses or IP addresses. Routers are Layer 3, switches are primarily Layer 2 (though some are Layer 3), and firewalls can operate at multiple layers.",
      "examTip": "Hubs are largely obsolete due to their inefficiency and security issues; switches are preferred."
    },
    {
      "id": 67,
      "question": "What is a common symptom of a network loop caused by a Spanning Tree Protocol (STP) failure?",
      "options": [
        "Slow internet speeds",
        "Broadcast storms",
        "Inability to obtain an IP address",
        "Frequent disconnections from wireless networks"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Network loops can cause broadcast storms, where broadcast frames are endlessly circulated, consuming bandwidth and potentially crashing the network.  Slow speeds, IP address issues, and wireless disconnections are usually caused by other problems.",
      "examTip": "STP is crucial for preventing loops in networks with redundant links; a failure can be catastrophic."
    },
    {
      "id": 68,
      "question": "What is the purpose of a subnet?",
      "options": [
        "To increase the number of available IP addresses.",
        "To divide a network into smaller, more manageable segments.",
        "To encrypt network traffic.",
        "To filter network traffic based on content."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Subnetting divides a larger network into smaller logical networks, improving security, performance, and manageability.  It doesn't increase the *total* number of addresses, encrypt traffic, or filter content (firewalls do that).",
      "examTip": "Subnetting is fundamental to IP addressing and network design."
    },
    {
      "id": 69,
      "question": "Which of the following is an example of a network documentation best practice?",
      "options": [
        "Keeping all network diagrams on a single administrator's computer.",
        "Regularly updating network diagrams and documentation to reflect changes.",
        "Using only physical network diagrams, not logical diagrams.",
        "Sharing network passwords with all IT staff."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Network documentation should be kept up-to-date to accurately reflect the current state of the network.  It should be centrally stored and accessible (with appropriate security), include both physical and logical diagrams, and passwords should be managed securely, not widely shared.",
      "examTip": "Good network documentation is essential for troubleshooting, planning, and security."
    },
    {
      "id": 70,
      "question": "What is 'latency' in a network context?",
      "options": [
        "The amount of data that can be transmitted over a network connection.",
        "The time it takes for data to travel from the source to the destination.",
        "The number of devices connected to a network.",
        "The physical distance between two network devices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Latency is the delay experienced by data as it travels across a network. Bandwidth is the amount of data, the number of devices is network size, and distance is just physical separation.",
      "examTip": "Low latency is crucial for real-time applications like online gaming and video conferencing."
    },
    {
      "id": 71,
      "question": "Which type of network attack involves flooding a target with excessive traffic, overwhelming its resources?",
      "options": [
        "Man-in-the-middle attack",
        "Denial-of-service (DoS) attack",
        "Phishing attack",
        "SQL injection attack"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DoS attack aims to make a network or service unavailable by overwhelming it with traffic. Man-in-the-middle intercepts communication, phishing uses deceptive emails, and SQL injection targets databases.",
      "examTip": "DoS attacks can disrupt network services and cause significant downtime."
    },
    {
      "id": 72,
      "question": "Which technology is used to create a logical grouping of devices on a network, regardless of their physical location?",
      "options": [
        "Subnetting",
        "VLANs (Virtual LANs)",
        "NAT (Network Address Translation)",
        "DHCP (Dynamic Host Configuration Protocol)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "VLANs group devices logically, even if they are connected to different physical switches. Subnetting divides networks based on IP address ranges, NAT translates addresses, and DHCP assigns them.",
      "examTip": "VLANs are essential for network segmentation and security, allowing you to group users and devices based on function, not just physical location."
    },
    {
      "id": 73,
      "question": "What is the purpose of a firewall's 'stateful inspection' feature?",
      "options": [
        "To track the state of network connections and allow only legitimate traffic.",
        "To block all incoming traffic by default.",
        "To encrypt network traffic.",
        "To assign IP addresses to devices."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Stateful inspection monitors the state of active connections and uses this information to make filtering decisions, allowing return traffic for established sessions. Blocking all incoming traffic is a default deny approach, encryption protects data, and DHCP assigns IPs.",
      "examTip": "Stateful inspection enhances firewall security by considering the context of network connections."
    },
    {
      "id": 74,
      "question": "Which of the following is a benefit of using cloud-based services?",
      "options": [
        "Elimination of all security risks.",
        "Scalability and flexibility.",
        "Complete control over the physical infrastructure.",
        "Guaranteed 100% uptime."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Cloud services offer scalability (easily adjust resources) and flexibility (choose different services as needed). Security is a shared responsibility, you don't control the physical infrastructure, and 100% uptime is rarely guaranteed (though SLAs provide high availability).",
      "examTip": "Cloud computing offers various advantages, including cost savings, scalability, and agility."
    },
    {
      "id": 75,
      "question": "What is the function of a DHCP server?",
      "options": [
        "Translates domain names to IP addresses.",
        "Automatically assigns IP addresses and other network configuration parameters to devices.",
        "Routes traffic between different networks.",
        "Filters network traffic based on content."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DHCP server automates the process of IP address assignment, making network management easier. DNS translates domain names, routers route traffic, and content filters control website access.",
      "examTip": "DHCP simplifies network configuration and avoids IP address conflicts."
    },
    {
      "id": 76,
      "question": "What does the acronym 'UTP' stand for in the context of network cabling?",
      "options": [
        "Universal Twisted Pair",
        "Unshielded Twisted Pair",
        "Underground Twisted Pair",
        "Unified Threat Protection"
      ],
      "correctAnswerIndex": 1,
      "explanation": "UTP stands for Unshielded Twisted Pair, a common type of copper cabling used in Ethernet networks. It lacks the shielding found in STP (Shielded Twisted Pair) cable.",
      "examTip": "UTP is cost-effective and widely used, but it's more susceptible to interference than STP."
    },
    {
      "id": 77,
      "question": "Which of the following is a characteristic of single-mode fiber optic cable?",
      "options": [
        "Used for short distances.",
        "Larger core size than multimode fiber.",
        "Uses LEDs as the light source.",
        "Allows only one mode of light to propagate, enabling long distances."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Single-mode fiber has a very small core that allows only one light path (mode), minimizing signal loss and enabling very long transmission distances (often using lasers). Multimode fiber has a larger core, uses LEDs, and is for shorter distances.",
      "examTip": "Single-mode fiber is used for long-haul, high-bandwidth applications."
    },
    {
      "id": 78,
      "question": "Which of the following is an advantage of using a star topology in a wired network?",
      "options": [
        "Requires less cabling than other topologies.",
        "If one cable fails, the entire network goes down.",
        "Easy to troubleshoot and isolate cable problems.",
        "Provides the highest level of redundancy."
      ],
      "correctAnswerIndex": 2,
      "explanation": "In a star topology, each device connects to a central hub or switch. This makes it easy to identify and fix cable issues affecting only one device. It uses *more* cabling than a bus, a single cable failure only affects *one* device, and mesh topology provides higher redundancy.",
      "examTip": "Star topology's centralized design simplifies management and troubleshooting."
    },
    {
      "id": 79,
      "question": "What is the purpose of the Address Resolution Protocol (ARP)?",
      "options": [
        "To resolve domain names to IP addresses.",
        "To dynamically assign IP addresses.",
        "To map IP addresses to MAC addresses.",
        "To encrypt network communication."
      ],
      "correctAnswerIndex": 2,
      "explanation": "ARP is used on local networks to find the MAC address associated with a known IP address, enabling devices to communicate at the data link layer. DNS resolves domain names, DHCP assigns IPs, and encryption is handled by other protocols.",
      "examTip": "ARP is essential for communication within a local Ethernet network."
    },
    {
      "id": 80,
      "question": "What is a 'full-duplex' network connection?",
      "options": [
        "A connection that can only transmit data in one direction at a time.",
        "A connection that can transmit and receive data simultaneously.",
        "A connection that uses two separate cables for transmission and reception.",
        "A connection that is limited to 10 Mbps speed."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Full-duplex allows simultaneous bidirectional communication, increasing efficiency. Half-duplex allows communication in only one direction at a time. The number of cables and speed are separate characteristics.",
      "examTip": "Modern switched networks almost always use full-duplex connections."
    },
    {
      "id": 81,
      "question": "Which tool is MOST useful for identifying the location of a specific cable within a bundle of cables?",
      "options": [
        "Cable tester",
        "Toner probe",
        "Protocol analyzer",
        "Crimping tool"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A toner probe (also called a tone generator and probe) generates a tone on one end of a cable, and the probe is used to detect that tone at the other end, even within a bundle. A cable tester checks for continuity, a protocol analyzer captures traffic, and a crimping tool attaches connectors.",
      "examTip": "Toner probes are invaluable for tracing cables in complex wiring environments."
    },
    {
      "id": 82,
      "question": "What is the purpose of the 'show ip interface brief' command on a Cisco router or switch?",
      "options": [
        "To display detailed routing table information.",
        "To show a summary of interface status and IP addresses.",
        "To configure interface settings.",
        "To display the ARP cache."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `show ip interface brief` command provides a concise overview of interface status (up/down), IP addresses, and other basic information. It's a quick way to check interface configurations.  `show ip route` displays the routing table, specific `interface` commands are used for configuration, and `show arp` shows the ARP cache.",
      "examTip": "`show ip interface brief` is one of the most frequently used Cisco commands for troubleshooting."
    },
    {
      "id": 83,
      "question": "What is the function of a network interface card (NIC)?",
      "options": [
        "To provide wireless connectivity.",
        "To connect a computer or device to a network.",
        "To route traffic between networks.",
        "To assign IP addresses dynamically."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A NIC provides the physical interface for a device to connect to a network, either wired or wireless (if it's a wireless NIC).  It doesn't route traffic (routers do that) or assign IP addresses (DHCP servers do that).",
      "examTip": "Every device connected to a network needs a NIC."
    },
    {
      "id": 84,
      "question": "Which type of network documentation shows the physical connections between devices, including cable types and port numbers?",
      "options": [
        "Logical diagram",
        "Physical diagram",
        "IP address schema",
        "Security policy"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A physical diagram depicts the actual cabling and connections between devices. A logical diagram shows the network topology and IP addressing, an IP address schema documents IP address assignments, and a security policy outlines security rules.",
      "examTip": "Physical diagrams are essential for troubleshooting cabling problems."
    },
    {
      "id": 85,
      "question": "Which wireless standard operates in the 5 GHz frequency band *exclusively*?",
      "options": [
        "802.11g",
        "802.11b",
        "802.11a",
        "802.11n"
      ],
      "correctAnswerIndex": 2,
      "explanation": "802.11a operates *only* in the 5 GHz band. 802.11g and 802.11b operate in the 2.4 GHz band. 802.11n can operate in both 2.4 GHz and 5 GHz.",
      "examTip": "Knowing the frequency bands of different wireless standards helps in troubleshooting interference and choosing the right standard."
    },
    {
      "id": 86,
      "question": "What is the purpose of a 'loopback address'?",
      "options": [
        "To test the network stack on a local machine.",
        "To access a remote server.",
        "To connect to the internet.",
        "To assign a static IP address."
      ],
      "correctAnswerIndex": 0,
      "explanation": "The loopback address (127.0.0.1 in IPv4, ::1 in IPv6) is used to test network software on a device without sending traffic over the network. It's a self-referential address.",
      "examTip": "Pinging the loopback address is a quick way to verify that the TCP/IP stack is functioning correctly on a device."
    },
    {
      "id": 87,
      "question": "Which of the following is MOST likely to cause signal degradation in a UTP cable?",
      "options": [
        "Excessive length",
        "Proper grounding",
        "Using the correct connectors",
        "Low humidity"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Exceeding the maximum length of a UTP cable (typically 100 meters) causes signal attenuation and degradation. Proper grounding and correct connectors are *good* practices. Humidity has minimal impact on UTP.",
      "examTip": "Adhere to cable length limitations to avoid signal degradation."
    },
    {
      "id": 88,
      "question": "Which command is used to display the DNS server settings on a Windows computer?",
      "options": [
        "ipconfig /renew",
        "ipconfig /all",
        "ipconfig /release",
        "ipconfig /flushdns"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`ipconfig /all` displays detailed network configuration, including the DNS servers being used. `/renew` requests a new DHCP lease, `/release` releases the current lease, and `/flushdns` clears the DNS cache.",
      "examTip": "`ipconfig /all` is your go-to command for checking DNS server settings on Windows."
    },
    {
      "id": 89,
      "question": "You are troubleshooting a computer that cannot connect to the network. You discover that it has an IP address of 169.254.10.5. What does this indicate?",
      "options": [
        "The computer has a static IP address.",
        "The computer has successfully obtained an IP address from a DHCP server.",
        "The computer failed to obtain an IP address from a DHCP server and has self-assigned an APIPA address.",
        "The computer is connected to the internet."
      ],
      "correctAnswerIndex": 2,
      "explanation": "An IP address in the 169.254.x.x range indicates an APIPA address, meaning the computer couldn't get an address from a DHCP server. It's not a static address, and it doesn't guarantee internet connectivity.",
      "examTip": "An APIPA address is a sign of DHCP failure."
    },
    {
      "id": 90,
      "question": "What is a common security best practice for configuring a wireless access point?",
      "options": [
        "Using the default SSID and password.",
        "Disabling encryption.",
        "Changing the default SSID and password, and enabling strong encryption (WPA3).",
        "Broadcasting the SSID publicly."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Always change default credentials and use the strongest available encryption (WPA3 if supported, otherwise WPA2).  Default settings are easily exploited, disabling encryption leaves the network open, and broadcasting the SSID is a minor security concern but less critical than the others.",
      "examTip": "Securing a wireless network starts with changing defaults and enabling strong encryption."
    },
    {
      "id": 91,
      "question": "What is the role of a gateway in a TCP/IP network?",
      "options": [
        "To translate data between different network protocols.",
        "To connect networks with different IP addressing schemes.",
        "To manage network security.",
        "To act as the entry point for all external traffic, typically provided by a router."
      ],
      "correctAnswerIndex": 3,
      "explanation": "The gateway, usually a router, acts as the point where traffic enters and exits your local network to reach external networks, including the internet.",
      "examTip": "The gateway address on a host is usually the IP address of the router's interface connected to the local network."
    },
    {
      "id": 92,
      "question": "Which layer of the OSI model handles reliable data transmission and flow control?",
      "options": [
        "Layer 2 - Data Link",
        "Layer 3 - Network",
        "Layer 4 - Transport",
        "Layer 7 - Application"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The Transport layer (Layer 4) provides reliable data delivery using protocols like TCP, including mechanisms for flow control, error checking, and retransmission. Layer 2 deals with physical addressing, Layer 3 with logical addressing, and Layer 7 provides application services.",
      "examTip": "Remember that TCP (connection-oriented) and UDP (connectionless) operate at the Transport layer."
    },
    {
      "id": 93,
      "question": "Which type of network device is designed to prevent unauthorized access to or from a private network?",
      "options": [
        "Switch",
        "Router",
        "Firewall",
        "Hub"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A firewall's primary purpose is to control network traffic based on security rules, blocking unauthorized access attempts. Switches connect devices within a network, routers forward traffic between networks, and hubs are simple repeaters.",
      "examTip": "Firewalls are a fundamental component of network security."
    },
    {
      "id": 94,
      "question": "What is the maximum cable length for 1000BASE-T (Gigabit Ethernet) over UTP cable?",
      "options": [
        "50 meters",
        "100 meters",
        "150 meters",
        "200 meters"
      ],
      "correctAnswerIndex": 1,
      "explanation": "1000BASE-T, like other common Ethernet standards over UTP, has a maximum length of 100 meters (328 feet).",
      "examTip": "Exceeding cable length limits leads to signal degradation and connectivity problems."
    },
    {
      "id": 95,
      "question": "What is a common cause of crosstalk in network cabling?",
      "options": [
        "The use of incorrect connectors.",
        "Excessive bending of the cable.",
        "Signal loss due to long cable length.",
        "Poor shielding of the cable."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Crosstalk is the unwanted transfer of signals between adjacent wires within a cable, causing interference and data corruption. Bending is physical damage, signal loss is attenuation, and incorrect connectors are termination issues.",
      "examTip": "Using twisted-pair cabling and proper termination techniques helps minimize crosstalk."
    },
    {
      "id": 96,
      "question": "Which of the following is a characteristic of a virtual LAN (VLAN)?",
      "options": [
        "It requires separate physical switches for each VLAN.",
        "It logically segments a network, even if devices are on the same physical switch.",
        "It increases the size of the broadcast domain.",
        "It is only used in wireless networks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "VLANs create logical groupings of devices regardless of their physical location, allowing for better network segmentation and security.  They *reduce* broadcast domain size, can be used on the *same* physical switch, and are used in *wired* networks (primarily).",
      "examTip": "VLANs are a crucial tool for network segmentation and security, allowing administrators to group devices based on function or security needs."
    },
    {
      "id": 97,
      "question": "You are setting up a network and need to ensure that a specific server always receives the same IP address. What DHCP feature should you use?",
      "options": [
        "DHCP scope",
        "DHCP reservation",
        "DHCP exclusion",
        "DHCP lease time"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DHCP reservation maps a specific MAC address to a specific IP address, ensuring the device always gets the same IP.  A scope defines the *range* of addresses, an exclusion prevents certain addresses from being assigned, and lease time controls how long an address is valid.",
      "examTip": "Use DHCP reservations for servers, printers, and other devices that require consistent IP addresses."
    },
    {
      "id": 98,
      "question": "What is the purpose of the Domain Name System (DNS)?",
      "options": [
        "To assign IP addresses to devices dynamically.",
        "To translate human-readable domain names (like example.com) into IP addresses.",
        "To encrypt network traffic.",
        "To filter network traffic based on content."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DNS acts like the internet's phone book, converting domain names into the IP addresses that computers use to communicate. DHCP assigns IPs, encryption is handled by other protocols, and content filtering is done by firewalls or specialized software.",
      "examTip": "Without DNS, we'd have to remember IP addresses instead of website names."
    },
    {
      "id": 99,
      "question": "Which of the following is a security risk associated with using a public Wi-Fi network?",
      "options": [
        "Increased network speed.",
        "Stronger encryption.",
        "Potential for eavesdropping and data interception.",
        "Automatic access to all network resources."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Public Wi-Fi networks often lack strong security, making it easier for attackers to intercept data transmitted over the network.  They don't inherently offer faster speeds or stronger encryption, and access to resources is usually restricted.",
      "examTip": "Use a VPN when connecting to public Wi-Fi to protect your data."
    },
    {
      "id": 100,
      "question": "What is a 'default route' in a routing table?",
      "options": [
        "The route used to reach the local network.",
        "The route used when no other specific route matches the destination IP address.",
        "The route used for all internal traffic.",
        "The route with the highest administrative distance."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The default route is the 'route of last resort'.  If a router doesn't have a more specific route in its table for a destination IP address, it sends the packet to the default gateway specified by the default route. It's not for local or internal traffic specifically, and administrative distance determines route preference, not what a default route *is*.",
      "examTip": "The default route is essential for connecting to networks outside the locally configured ones (like the internet)."
    }
  ]
});
