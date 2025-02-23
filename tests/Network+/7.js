db.tests.insertOne({
  "category": "nplus",
  "testId": 7,
  "testName": "Network+ Practice Test #9 (Challenging)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A network engineer observes intermittent connectivity issues between two sites connected via a BGP session. The BGP session resets periodically. Which is the MOST likely cause of this behavior?",
      "options": [
        "MTU mismatch on WAN interfaces.",
        "Incorrect BGP neighbor authentication.",
        "Flapping WAN link causing session resets.",
        "Route reflector misconfiguration."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A flapping WAN link causes the BGP session to reset when the physical connection drops intermittently. MTU mismatches typically cause performance issues, not session resets. Incorrect neighbor authentication would prevent the session from establishing altogether. Route reflector misconfiguration affects route advertisement, not session stability.",
      "examTip": "**Flapping WAN link = BGP resets.** Check link stability when troubleshooting BGP session drops."
    },
    {
      "id": 2,
      "question": "Which configuration allows dynamic load balancing between multiple default routes in an enterprise network using OSPF?",
      "options": [
        "Equal-cost multi-path (ECMP) routing.",
        "Redistribution of static default routes.",
        "Increasing OSPF cost on backup links.",
        "Using BGP to manage external routes."
      ],
      "correctAnswerIndex": 0,
      "explanation": "ECMP (Equal-Cost Multi-Path) allows OSPF to balance traffic dynamically across multiple default routes with equal cost. Redistributing static routes doesn’t enable dynamic balancing. Increasing cost on backup links prevents load balancing. BGP is used for external routing, not internal OSPF load balancing.",
      "examTip": "**ECMP = OSPF load balancing.** Ensure multiple equal-cost routes are available for dynamic distribution."
    },
    {
      "id": 3,
      "question": "A cloud provider needs to ensure each customer's virtual network remains isolated while sharing the same physical infrastructure. Which technology BEST achieves this goal?",
      "options": [
        "VXLAN (Virtual Extensible LAN).",
        "VPN (Virtual Private Network).",
        "GRE (Generic Routing Encapsulation).",
        "VLAN (Virtual LAN)."
      ],
      "correctAnswerIndex": 0,
      "explanation": "VXLAN provides Layer 2 isolation across Layer 3 boundaries, allowing multiple tenants to share physical infrastructure securely. VPNs secure traffic but don’t provide Layer 2 isolation. GRE tunnels traffic without providing tenant isolation. VLANs provide segmentation but are limited in scalability compared to VXLAN.",
      "examTip": "**VXLAN = Multi-tenant isolation at scale.** Ideal for large cloud environments with overlapping networks."
    },
    {
      "id": 4,
      "question": "A network administrator configures SNMPv3 for secure device monitoring. Which three security features does SNMPv3 provide?",
      "options": [
        "Authentication, encryption, and message integrity.",
        "Community string encryption, user authentication, and ACLs.",
        "Unencrypted traps, hashed passwords, and session persistence.",
        "Plain-text authentication, secure data transport, and network isolation."
      ],
      "correctAnswerIndex": 0,
      "explanation": "SNMPv3 supports authentication (user-based), encryption (to protect data in transit), and message integrity (to detect data tampering). SNMPv3 does not rely on community strings, unencrypted traps, or plain-text authentication like earlier versions.",
      "examTip": "**SNMPv3 = Secure network monitoring.** Always prefer SNMPv3 for robust, secure network management."
    },
    {
      "id": 5,
      "question": "Which routing protocol would BEST support a multi-vendor enterprise environment requiring fast convergence, scalability, and open-standard compliance?",
      "options": [
        "OSPF",
        "EIGRP",
        "BGP",
        "RIP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "OSPF is an open-standard, link-state protocol supporting fast convergence and scalability. EIGRP is Cisco-proprietary. BGP handles inter-domain routing, not optimal for internal enterprise environments. RIP is outdated with slow convergence.",
      "examTip": "**OSPF = Enterprise-grade, open-standard routing.** The default choice for scalable, multi-vendor networks."
    },
    {
      "id": 6,
      "question": "Which IPv6 addressing method allows multiple devices to share the same address, with data routed to the nearest device in the group?",
      "options": [
        "Anycast",
        "Multicast",
        "Unicast",
        "Global unicast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Anycast routes traffic to the nearest node in a group sharing the same address, optimizing latency. Multicast sends data to multiple recipients. Unicast addresses a single device. Global unicast addresses are publicly routable but don’t provide proximity-based routing.",
      "examTip": "**Anycast = Nearest-node efficiency.** Essential for DNS servers and distributed services requiring low latency."
    },
    {
      "id": 7,
      "question": "Which solution provides end-to-end encryption for data in transit between two sites while ensuring that IP addresses are not visible to intermediate devices?",
      "options": [
        "IPSec in tunnel mode.",
        "GRE tunneling.",
        "SSL/TLS encryption.",
        "L2TP without IPSec."
      ],
      "correctAnswerIndex": 0,
      "explanation": "IPSec in tunnel mode encrypts both the payload and the original IP headers, ensuring full data and identity protection. GRE provides tunneling without encryption. SSL/TLS secures web traffic, not IP headers. L2TP alone doesn’t provide encryption.",
      "examTip": "**IPSec tunnel mode = Full packet protection.** Ideal for secure site-to-site VPN implementations."
    },
    {
      "id": 8,
      "question": "Which cloud model provides access to virtualized computing resources such as servers and storage while allowing customers full control over the operating systems and applications?",
      "options": [
        "IaaS (Infrastructure as a Service).",
        "SaaS (Software as a Service).",
        "PaaS (Platform as a Service).",
        "FaaS (Function as a Service)."
      ],
      "correctAnswerIndex": 0,
      "explanation": "IaaS provides virtualized infrastructure, giving customers control over OS and applications. SaaS provides fully managed applications. PaaS offers a platform for development without OS control. FaaS allows code execution without server management.",
      "examTip": "**IaaS = Full infrastructure control.** Best for organizations needing granular management of systems."
    },
    {
      "id": 9,
      "question": "Which port is commonly used by RDP (Remote Desktop Protocol) for secure remote desktop access?",
      "options": [
        "3389",
        "22",
        "443",
        "80"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RDP uses TCP port 3389 for secure remote desktop access. Port 22 is for SSH. Port 443 is used by HTTPS. Port 80 serves HTTP traffic.",
      "examTip": "**Port 3389 = Secure remote desktop.** Always secure RDP endpoints with strong credentials and VPN access."
    },
    {
      "id": 10,
      "question": "A company plans to deploy a high-performance wireless network in a dense office environment. Which wireless standard provides the BEST performance with support for the 6GHz band?",
      "options": [
        "802.11ax (Wi-Fi 6E).",
        "802.11ac (Wi-Fi 5).",
        "802.11n (Wi-Fi 4).",
        "802.11g (Wi-Fi 3)."
      ],
      "correctAnswerIndex": 0,
      "explanation": "802.11ax (Wi-Fi 6E) extends Wi-Fi 6 capabilities into the 6GHz band, offering less interference, higher throughput, and lower latency. 802.11ac uses 5GHz only. 802.11n and 802.11g are older and offer lower throughput.",
      "examTip": "**Wi-Fi 6E = Future-proof performance.** Best for high-density environments requiring minimal interference."
    },
    {
      "id": 11,
      "question": "Which DNS record type allows a domain to be an alias for another canonical domain name?",
      "options": [
        "CNAME",
        "A",
        "MX",
        "PTR"
      ],
      "correctAnswerIndex": 0,
      "explanation": "CNAME (Canonical Name) records map an alias to a canonical domain. A records map to IPv4 addresses. MX records define mail servers. PTR records map IP addresses to hostnames (reverse DNS).",
      "examTip": "**CNAME = Domain aliasing.** Useful for pointing multiple services to a single domain endpoint."
    },
    {
      "id": 12,
      "question": "Which WAN technology offers high-speed, low-latency, and private connectivity to cloud providers, bypassing the public internet?",
      "options": [
        "Direct Connect.",
        "IPSec VPN.",
        "SD-WAN.",
        "MPLS."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Direct Connect provides private, high-speed cloud connections, bypassing public internet. IPSec VPNs traverse the internet. SD-WAN optimizes multiple WAN links but typically over the internet. MPLS offers private WAN services but isn’t cloud-specific.",
      "examTip": "**Direct Connect = Reliable cloud access.** Ideal for latency-sensitive cloud workloads."
    },
    {
      "id": 13,
      "question": "Which IPv6 transition mechanism allows devices to run both IPv4 and IPv6 simultaneously, simplifying migration by ensuring compatibility?",
      "options": [
        "Dual stack.",
        "NAT64.",
        "6to4 tunneling.",
        "ISATAP."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Dual stack allows devices to run both IPv4 and IPv6 simultaneously, ensuring compatibility without translation. NAT64 translates between IPv6 and IPv4. 6to4 tunneling encapsulates IPv6 in IPv4 packets. ISATAP enables IPv6 communication over IPv4 networks within an organization.",
      "examTip": "**Dual stack = Smooth IPv6 adoption.** Provides compatibility while transitioning networks."
    },
    {
      "id": 14,
      "question": "Which tool would BEST help a network administrator determine the source of increased network latency and packet drops between two endpoints?",
      "options": [
        "traceroute",
        "ping",
        "netstat",
        "ipconfig"
      ],
      "correctAnswerIndex": 0,
      "explanation": "traceroute provides a hop-by-hop view of the network path, helping identify where latency or packet loss occurs. ping tests basic connectivity. netstat shows active connections. ipconfig displays local interface information.",
      "examTip": "**traceroute = Path performance insight.** Essential for diagnosing latency and loss along network routes."
    },
    {
      "id": 15,
      "question": "Which protocol enables secure device management over a network by encrypting the entire session, including authentication information?",
      "options": [
        "SSH",
        "Telnet",
        "SNMPv2",
        "HTTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH (Secure Shell) encrypts the entire session, including credentials. Telnet sends data in plaintext. SNMPv2 lacks encryption by default. HTTP transmits data unencrypted.",
      "examTip": "**SSH = Secure CLI management.** Always use SSH for secure remote access."
    },
    {
      "id": 16,
      "question": "Which addressing scheme is used by IPv6 to send a packet to all nodes on a local network segment?",
      "options": [
        "Multicast (FF02::1).",
        "Unicast.",
        "Anycast.",
        "Global unicast."
      ],
      "correctAnswerIndex": 0,
      "explanation": "The FF02::1 multicast address delivers packets to all nodes on a local link. Unicast addresses a single device. Anycast sends traffic to the nearest node in a group. Global unicast addresses are routable on the public internet.",
      "examTip": "**FF02::1 = IPv6 all-nodes multicast.** Commonly used for essential local network communications."
    },
    {
      "id": 17,
      "question": "Which BGP attribute can be manipulated to influence how external ASes prefer one path over another when routing traffic into your network?",
      "options": [
        "AS path prepending.",
        "Local preference.",
        "MED (Multi-Exit Discriminator).",
        "Next-hop."
      ],
      "correctAnswerIndex": 0,
      "explanation": "AS path prepending adds additional AS entries to make a path appear longer, discouraging external ASes from selecting it. Local preference affects outbound routing. MED influences inbound routing only among directly connected peers. Next-hop indicates the next routing hop.",
      "examTip": "**AS path prepending = Inbound path influence.** Useful for inbound traffic engineering."
    },
    {
      "id": 18,
      "question": "Which cloud deployment model provides the highest level of security and control by dedicating cloud infrastructure to a single organization?",
      "options": [
        "Private cloud.",
        "Public cloud.",
        "Hybrid cloud.",
        "Community cloud."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Private clouds are dedicated to a single organization, offering maximum control and security. Public clouds share infrastructure. Hybrid clouds combine public and private resources. Community clouds are shared among organizations with similar requirements.",
      "examTip": "**Private cloud = Maximum control.** Best for organizations with strict compliance needs."
    },
    {
      "id": 19,
      "question": "Which protocol uses port 443 and provides encrypted communications for secure web browsing?",
      "options": [
        "HTTPS",
        "HTTP",
        "SSH",
        "FTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "HTTPS uses port 443 to provide secure, encrypted web communications. HTTP uses port 80 without encryption. SSH secures command-line access over port 22. FTP transfers files without encryption over port 21.",
      "examTip": "**Port 443 = Secure web traffic.** Always use HTTPS to protect web sessions from interception."
    },
    {
      "id": 20,
      "question": "Which type of DNS record is used to map an IPv4 address to a domain name in reverse DNS lookups?",
      "options": [
        "PTR",
        "A",
        "CNAME",
        "MX"
      ],
      "correctAnswerIndex": 0,
      "explanation": "PTR (Pointer) records map IPv4 addresses to domain names for reverse DNS lookups. A records map domain names to IPv4 addresses. CNAME records provide domain aliases. MX records specify mail servers for a domain.",
      "examTip": "**PTR = Reverse DNS lookups.** Essential for verifying that IPs resolve correctly back to domain names."
    },
    {
      "id": 21,
      "question": "A network engineer needs to reduce the propagation of unnecessary broadcast traffic while maintaining network segmentation at Layer 2. Which solution BEST achieves this?",
      "options": [
        "Implement VLANs with appropriate trunking.",
        "Deploy routers between each network segment.",
        "Configure access control lists (ACLs) on core switches.",
        "Use port mirroring for traffic monitoring."
      ],
      "correctAnswerIndex": 0,
      "explanation": "VLANs limit broadcast domains at Layer 2, reducing unnecessary traffic. Routers would segment at Layer 3 but may introduce latency. ACLs control traffic flow but don’t reduce broadcasts. Port mirroring copies traffic for analysis, not segmentation.",
      "examTip": "**VLANs = Broadcast containment at Layer 2.** Use VLANs to reduce broadcast storms and isolate traffic efficiently."
    },
    {
      "id": 22,
      "question": "Which wireless technology improves throughput by allowing simultaneous data transmission to multiple devices over the same channel?",
      "options": [
        "MU-MIMO",
        "Beamforming",
        "Band steering",
        "Roaming"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MU-MIMO (Multi-User Multiple Input Multiple Output) allows multiple devices to receive data simultaneously, increasing throughput. Beamforming improves signal strength in specific directions. Band steering moves devices between frequency bands. Roaming ensures seamless transitions between access points.",
      "examTip": "**MU-MIMO = Multi-device efficiency.** Ideal for environments with multiple high-bandwidth users."
    },
    {
      "id": 23,
      "question": "Which protocol provides automated network topology discovery by exchanging information between directly connected Layer 2 devices?",
      "options": [
        "LLDP (Link Layer Discovery Protocol)",
        "CDP (Cisco Discovery Protocol)",
        "SNMPv3",
        "OSPF"
      ],
      "correctAnswerIndex": 0,
      "explanation": "LLDP is an open-standard protocol that discovers network topology by sharing information between connected Layer 2 devices. CDP is similar but Cisco-proprietary. SNMPv3 is for network management. OSPF is a Layer 3 routing protocol.",
      "examTip": "**LLDP = Vendor-neutral network discovery.** Useful for mapping and managing multi-vendor environments."
    },
    {
      "id": 24,
      "question": "A company needs to implement a wireless solution that supports real-time applications with minimal latency. Which frequency and channel width configuration is MOST appropriate?",
      "options": [
        "5GHz band with 80MHz channels.",
        "2.4GHz band with 20MHz channels.",
        "5GHz band with 20MHz channels.",
        "2.4GHz band with 40MHz channels."
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 5GHz band offers higher throughput with less interference than 2.4GHz, and 80MHz channels provide wider bandwidth for real-time applications. 2.4GHz bands are more prone to interference. Narrower channels (20MHz) provide less throughput.",
      "examTip": "**5GHz + 80MHz = Low-latency wireless.** Best for VoIP, video conferencing, and high-bandwidth tasks."
    },
    {
      "id": 25,
      "question": "Which BGP attribute is considered when an ISP wants to influence the route their customers take to reach a particular destination network?",
      "options": [
        "MED (Multi-Exit Discriminator)",
        "Local preference",
        "AS path",
        "Weight"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MED influences how external autonomous systems select entry points into an AS. Local preference affects outbound traffic decisions. AS path influences inbound traffic by showing path length. Weight is Cisco-specific and affects route selection locally, not globally.",
      "examTip": "**MED = Inbound traffic influencer.** Adjust MED values to guide external peers’ routing preferences."
    },
    {
      "id": 26,
      "question": "Which IPv6 address type is designed for private communication within a site and is not routable on the global internet?",
      "options": [
        "Unique Local Address (ULA)",
        "Global Unicast Address",
        "Link-Local Address",
        "Multicast Address"
      ],
      "correctAnswerIndex": 0,
      "explanation": "ULA addresses (fc00::/7) are private and not globally routable, similar to IPv4 private addresses. Global unicast addresses are routable on the internet. Link-local addresses are for communication within the same link. Multicast addresses send data to multiple recipients.",
      "examTip": "**ULA = IPv6 private addressing.** Use ULA for internal communications without internet exposure."
    },
    {
      "id": 27,
      "question": "A technician needs to secure router configurations by encrypting all management sessions. Which protocol should be implemented?",
      "options": [
        "SSH",
        "Telnet",
        "HTTP",
        "SNMPv2"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH encrypts all session data, including authentication credentials. Telnet transmits data in plaintext. HTTP lacks encryption, while SNMPv2 doesn’t encrypt management traffic unless upgraded to SNMPv3.",
      "examTip": "**SSH = Secure management access.** Always use SSH over Telnet for encrypted device administration."
    },
    {
      "id": 28,
      "question": "Which cloud service model provides developers with a platform including operating systems, development tools, and database management without managing the underlying infrastructure?",
      "options": [
        "PaaS (Platform as a Service)",
        "IaaS (Infrastructure as a Service)",
        "SaaS (Software as a Service)",
        "FaaS (Function as a Service)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "PaaS provides a complete development platform without infrastructure management. IaaS offers infrastructure control. SaaS delivers software applications. FaaS enables execution of code functions without managing servers.",
      "examTip": "**PaaS = Developer’s playground.** Best for rapid app development without infrastructure overhead."
    },
    {
      "id": 29,
      "question": "Which tool allows a network administrator to capture and analyze packets in real-time to troubleshoot application latency issues?",
      "options": [
        "Wireshark",
        "NetFlow analyzer",
        "Nmap",
        "Syslog server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Wireshark captures and analyzes network packets in real-time, essential for diagnosing latency and protocol issues. NetFlow analyzes traffic flows but not individual packets. Nmap scans networks for open ports. Syslog servers aggregate logs, not real-time traffic data.",
      "examTip": "**Wireshark = Deep packet analysis.** Go-to tool for resolving application-level network issues."
    },
    {
      "id": 30,
      "question": "Which protocol enables secure file transfers over a network by leveraging SSH for encryption?",
      "options": [
        "SFTP",
        "TFTP",
        "FTP",
        "HTTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SFTP (SSH File Transfer Protocol) uses SSH (port 22) for secure file transfers. TFTP is unencrypted and uses port 69. FTP uses ports 20/21 without encryption. HTTP is for web traffic, not file transfers.",
      "examTip": "**SFTP = Secure file transfer.** Always prefer SFTP for transferring sensitive data securely."
    },
    {
      "id": 31,
      "question": "Which addressing method allows IPv6 devices to generate a unique host identifier using the device’s MAC address?",
      "options": [
        "EUI-64",
        "SLAAC",
        "NAT64",
        "DHCPv6"
      ],
      "correctAnswerIndex": 0,
      "explanation": "EUI-64 generates a unique interface ID by combining the device’s MAC address with additional bits. SLAAC auto-configures addresses but may use EUI-64. NAT64 enables IPv6-to-IPv4 communication. DHCPv6 provides centralized address assignment.",
      "examTip": "**EUI-64 = MAC-derived IPv6 addressing.** Guarantees unique interface identifiers in IPv6 networks."
    },
    {
      "id": 32,
      "question": "Which redundancy protocol allows multiple routers to share a virtual IP address and provides automatic failover if the active router fails?",
      "options": [
        "VRRP",
        "HSRP",
        "GLBP",
        "CARP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "VRRP (Virtual Router Redundancy Protocol) is a vendor-neutral standard that enables router failover by sharing a virtual IP. HSRP is Cisco-specific. GLBP offers load balancing and redundancy. CARP is an open-source alternative to VRRP and HSRP.",
      "examTip": "**VRRP = Cross-vendor redundancy.** Ensures high availability for default gateways in enterprise networks."
    },
    {
      "id": 33,
      "question": "Which protocol provides end-to-end secure communications for web applications using encryption, digital certificates, and secure handshakes?",
      "options": [
        "TLS (Transport Layer Security)",
        "SSL",
        "IPSec",
        "SSH"
      ],
      "correctAnswerIndex": 0,
      "explanation": "TLS is the modern, secure standard for web encryption, replacing SSL. IPSec secures IP packets, and SSH secures remote management sessions. SSL is outdated and less secure than TLS.",
      "examTip": "**TLS = Web encryption gold standard.** Always ensure TLS for secure web applications and APIs."
    },
    {
      "id": 34,
      "question": "Which high-availability feature in cloud environments allows traffic to be distributed across multiple servers, improving application scalability and fault tolerance?",
      "options": [
        "Load balancing",
        "Auto-scaling",
        "Geo-redundancy",
        "Failover clustering"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Load balancing distributes traffic across multiple servers, enhancing scalability and resilience. Auto-scaling adjusts resources based on demand. Geo-redundancy spreads data across multiple locations. Failover clustering ensures service continuity if a server fails.",
      "examTip": "**Load balancing = Scalability + Availability.** Essential for handling large volumes of web traffic efficiently."
    },
    {
      "id": 35,
      "question": "Which WAN technology provides predictable, private, and high-performance connectivity for enterprise applications without using the public internet?",
      "options": [
        "MPLS (Multiprotocol Label Switching)",
        "IPSec VPN",
        "Direct Internet Access",
        "SD-WAN"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MPLS offers private, predictable performance suitable for critical applications. IPSec VPNs operate over the public internet. Direct Internet Access lacks private routing. SD-WAN optimizes WAN usage but typically includes internet-based links.",
      "examTip": "**MPLS = Consistent private WAN performance.** Ideal for latency-sensitive enterprise applications."
    },
    {
      "id": 36,
      "question": "Which layer of the OSI model is responsible for establishing, maintaining, and terminating communication sessions between applications?",
      "options": [
        "Session layer (Layer 5)",
        "Presentation layer (Layer 6)",
        "Transport layer (Layer 4)",
        "Application layer (Layer 7)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The session layer manages communication sessions between applications. The presentation layer formats and encrypts data. The transport layer ensures reliable data delivery. The application layer interfaces with user applications.",
      "examTip": "**Layer 5 = Session management.** Key for protocols like NetBIOS and RPC."
    },
    {
      "id": 37,
      "question": "Which protocol allows secure, encrypted remote graphical access to desktop environments over a network?",
      "options": [
        "RDP (Remote Desktop Protocol)",
        "VNC",
        "SSH",
        "Telnet"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RDP provides secure, encrypted graphical access, commonly used in Windows environments. VNC offers similar functionality but may lack encryption. SSH secures command-line access. Telnet is insecure and transmits data in plaintext.",
      "examTip": "**RDP = Secure remote GUI access.** Always secure RDP connections with strong credentials and network controls."
    },
    {
      "id": 38,
      "question": "Which security solution combines multiple functions such as firewall, antivirus, and content filtering into a single integrated platform?",
      "options": [
        "UTM (Unified Threat Management)",
        "IDS (Intrusion Detection System)",
        "IPS (Intrusion Prevention System)",
        "SIEM (Security Information and Event Management)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "UTM devices integrate multiple security functions into a single appliance. IDS detects threats but doesn’t prevent them. IPS prevents threats but doesn’t handle antivirus or content filtering. SIEM focuses on event correlation and logging.",
      "examTip": "**UTM = All-in-one security solution.** Ideal for simplifying security management in small to mid-sized networks."
    },
    {
      "id": 39,
      "question": "Which routing protocol uses a hierarchical network design with areas to optimize routing efficiency and convergence?",
      "options": [
        "OSPF",
        "BGP",
        "RIP",
        "EIGRP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "OSPF uses a hierarchical design with multiple areas, improving routing efficiency and reducing overhead. BGP handles inter-domain routing. RIP is less efficient and outdated. EIGRP is Cisco-proprietary and doesn’t require hierarchical design.",
      "examTip": "**OSPF = Hierarchical routing efficiency.** Ideal for large enterprise networks requiring fast convergence."
    },
    {
      "id": 40,
      "question": "Which IPv6 feature allows a single device to have multiple addresses for different purposes, such as link-local and global communication?",
      "options": [
        "Multiple address assignment",
        "Anycast addressing",
        "Multicast addressing",
        "Tunneling"
      ],
      "correctAnswerIndex": 0,
      "explanation": "IPv6 supports multiple address assignments on a single interface, including link-local, global unicast, and multicast addresses. Anycast delivers traffic to the nearest node. Multicast sends traffic to multiple recipients. Tunneling encapsulates IPv6 within IPv4 but isn’t related to multiple addressing.",
      "examTip": "**Multiple addressing = Flexible IPv6 communications.** Supports diverse network roles on a single interface."
    },
    {
      "id": 41,
      "question": "A network engineer notices that BGP routes from an external peer are being preferred incorrectly. Which BGP attribute should be adjusted to influence the outbound routing decision within the local autonomous system?",
      "options": [
        "Local preference",
        "AS path",
        "MED (Multi-Exit Discriminator)",
        "Next-hop"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Local preference is the BGP attribute that influences outbound routing decisions within an autonomous system; higher values are preferred. AS path affects inbound traffic. MED influences inbound traffic but only among directly connected peers. Next-hop specifies the next hop but doesn’t influence preference.",
      "examTip": "**Local preference = Outbound path control.** Adjust local preference for optimal outbound routing within your AS."
    },
    {
      "id": 42,
      "question": "Which protocol enables dynamic distribution of VLAN information to switches in a Cisco environment, simplifying VLAN configuration?",
      "options": [
        "VTP (VLAN Trunking Protocol)",
        "STP (Spanning Tree Protocol)",
        "LACP (Link Aggregation Control Protocol)",
        "RSTP (Rapid Spanning Tree Protocol)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "VTP distributes VLAN information to switches automatically in Cisco networks. STP and RSTP prevent switching loops but don’t distribute VLAN configurations. LACP aggregates multiple links but doesn’t handle VLANs.",
      "examTip": "**VTP = Simplified VLAN management.** Ensure proper VTP configuration to avoid unintended VLAN changes."
    },
    {
      "id": 43,
      "question": "Which tool allows network administrators to identify which devices are connected to which switch ports by querying network devices?",
      "options": [
        "LLDP (Link Layer Discovery Protocol)",
        "Nmap",
        "NetFlow analyzer",
        "Wireshark"
      ],
      "correctAnswerIndex": 0,
      "explanation": "LLDP provides device discovery by sharing information between connected Layer 2 devices. Nmap scans for open ports. NetFlow analyzes traffic patterns. Wireshark captures and analyzes packet data but doesn’t map switch port connections.",
      "examTip": "**LLDP = Network topology mapping.** Use LLDP for multi-vendor environments to visualize Layer 2 connections."
    },
    {
      "id": 44,
      "question": "Which cloud model provides dedicated resources hosted off-premises and offers complete control and customization similar to an on-premises environment?",
      "options": [
        "Private cloud",
        "Public cloud",
        "Hybrid cloud",
        "Community cloud"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Private clouds offer dedicated resources with complete control, ideal for organizations with strict security requirements. Public clouds share resources among multiple tenants. Hybrid clouds combine public and private cloud resources. Community clouds serve organizations with shared goals or compliance requirements.",
      "examTip": "**Private cloud = Full control off-premises.** Best for sensitive workloads requiring customization and isolation."
    },
    {
      "id": 45,
      "question": "Which IPv6 transition mechanism encapsulates IPv6 packets within IPv4 for transmission over IPv4 networks without modifying applications?",
      "options": [
        "6to4 tunneling",
        "NAT64",
        "Dual stack",
        "ISATAP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "6to4 tunneling allows IPv6 packets to be encapsulated within IPv4 for transmission across IPv4 networks. NAT64 translates IPv6 addresses to IPv4, dual stack runs both protocols simultaneously, and ISATAP is used for intra-site communication within IPv4 networks.",
      "examTip": "**6to4 = Quick IPv6 over IPv4 solution.** Suitable when applications don’t support IPv6 natively."
    },
    {
      "id": 46,
      "question": "A wireless network administrator needs to prevent clients from connecting to rogue access points impersonating legitimate ones. Which security method provides the BEST protection?",
      "options": [
        "WPA3-Enterprise with 802.1X authentication",
        "MAC filtering",
        "SSID hiding",
        "WEP encryption"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3-Enterprise with 802.1X provides strong encryption and user authentication, mitigating rogue AP threats. MAC filtering and SSID hiding are easily bypassed. WEP is outdated and insecure.",
      "examTip": "**WPA3-Enterprise + 802.1X = Secure wireless access.** Essential for mitigating rogue AP risks in enterprise networks."
    },
    {
      "id": 47,
      "question": "Which routing protocol uses hop count as its primary metric and is considered outdated due to slow convergence and lack of scalability?",
      "options": [
        "RIP (Routing Information Protocol)",
        "OSPF",
        "EIGRP",
        "BGP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RIP uses hop count as its primary metric, but it is limited to 15 hops and converges slowly. OSPF uses cost based on bandwidth. EIGRP uses multiple metrics like bandwidth and delay. BGP handles routing between autonomous systems and uses path vector metrics.",
      "examTip": "**RIP = Legacy routing protocol.** Avoid using RIP for modern, large-scale networks due to performance limitations."
    },
    {
      "id": 48,
      "question": "Which tool helps detect physical cable faults, such as breaks or significant signal attenuation, by measuring the time for a signal reflection?",
      "options": [
        "OTDR (Optical Time Domain Reflectometer)",
        "Cable tester",
        "Toner probe",
        "Multimeter"
      ],
      "correctAnswerIndex": 0,
      "explanation": "OTDR tests fiber optic cables by sending pulses and measuring reflected signals to detect faults. Cable testers verify wiring correctness. Toner probes trace cables. Multimeters measure electrical properties but don’t detect signal attenuation in fiber.",
      "examTip": "**OTDR = Fiber optic diagnostics.** Essential for pinpointing cable faults and performance issues in optical networks."
    },
    {
      "id": 49,
      "question": "A network administrator needs to prevent loops in a Layer 2 network with redundant links. Which protocol should be configured for faster convergence?",
      "options": [
        "RSTP (Rapid Spanning Tree Protocol)",
        "STP (Spanning Tree Protocol)",
        "LACP",
        "VTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RSTP (802.1w) provides faster convergence compared to STP, reducing downtime during topology changes. LACP aggregates links but doesn’t prevent loops. VTP distributes VLAN configurations but isn’t related to loop prevention.",
      "examTip": "**RSTP = Quick loop prevention.** Use RSTP over STP for reduced convergence times in modern networks."
    },
    {
      "id": 50,
      "question": "Which port does Secure LDAP (LDAPS) use by default to ensure encrypted directory service communications?",
      "options": [
        "636",
        "389",
        "443",
        "22"
      ],
      "correctAnswerIndex": 0,
      "explanation": "LDAPS (LDAP over SSL) uses port 636 for secure directory services. Port 389 is used for standard LDAP. Port 443 is for HTTPS. Port 22 is used for SSH connections.",
      "examTip": "**Port 636 = Secure LDAP (LDAPS).** Always prefer LDAPS over LDAP for secure directory communications."
    },
    {
      "id": 51,
      "question": "Which network protocol operates at the transport layer and provides connection-oriented services ensuring reliable data delivery?",
      "options": [
        "TCP (Transmission Control Protocol)",
        "UDP (User Datagram Protocol)",
        "ICMP",
        "GRE"
      ],
      "correctAnswerIndex": 0,
      "explanation": "TCP provides reliable, connection-oriented data transmission. UDP is connectionless and doesn’t guarantee delivery. ICMP is used for error reporting and diagnostics. GRE provides tunneling without transport layer reliability.",
      "examTip": "**TCP = Reliable delivery.** Choose TCP when guaranteed data integrity and order are critical."
    },
    {
      "id": 52,
      "question": "Which wireless technology provides simultaneous communication with multiple clients using spatial streams, improving throughput in dense environments?",
      "options": [
        "MU-MIMO (Multi-User MIMO)",
        "Beamforming",
        "Band steering",
        "Roaming"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MU-MIMO allows multiple devices to receive data simultaneously, increasing network efficiency in dense environments. Beamforming focuses signals toward devices. Band steering directs clients to optimal frequencies. Roaming enables seamless transitions between access points.",
      "examTip": "**MU-MIMO = Efficient multi-user Wi-Fi.** Key for high-density networks with multiple concurrent users."
    },
    {
      "id": 53,
      "question": "Which protocol uses port 123 and synchronizes time across network devices, critical for log consistency and network security?",
      "options": [
        "NTP (Network Time Protocol)",
        "SNMP",
        "SSH",
        "Telnet"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NTP uses port 123 to synchronize time across devices, ensuring accurate log timestamps and time-sensitive operations. SNMP manages network devices. SSH secures command-line sessions. Telnet is insecure and transmits data in plaintext.",
      "examTip": "**Port 123 = NTP time sync.** Always configure NTP for consistent logs and accurate time across network systems."
    },
    {
      "id": 54,
      "question": "Which routing protocol is open-standard, uses a link-state algorithm, and supports large enterprise networks with fast convergence times?",
      "options": [
        "OSPF",
        "BGP",
        "EIGRP",
        "RIP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "OSPF is an open-standard, link-state protocol providing fast convergence and scalability. BGP is used for inter-domain routing. EIGRP is Cisco-proprietary. RIP is outdated and offers slow convergence.",
      "examTip": "**OSPF = Enterprise-grade routing.** Best choice for scalable, multi-vendor networks needing fast convergence."
    },
    {
      "id": 55,
      "question": "Which cloud deployment model combines on-premises infrastructure with cloud resources, offering flexibility and cost optimization?",
      "options": [
        "Hybrid cloud",
        "Private cloud",
        "Public cloud",
        "Community cloud"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Hybrid cloud integrates on-premises resources with public cloud services, providing flexibility and optimizing costs. Private clouds offer full control but at higher costs. Public clouds provide shared resources. Community clouds are tailored for organizations with shared compliance needs.",
      "examTip": "**Hybrid cloud = Flexibility + Optimization.** Ideal for workloads needing both local control and cloud scalability."
    },
    {
      "id": 56,
      "question": "Which IPv6 address type is automatically assigned and used for communication between nodes on the same link without requiring manual configuration?",
      "options": [
        "Link-local address (FE80::/10)",
        "Global unicast address",
        "Unique local address",
        "Anycast address"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Link-local addresses (starting with FE80::) are automatically assigned for communication within the same link. Global unicast addresses are publicly routable. Unique local addresses are for internal communication. Anycast routes traffic to the nearest device in a group.",
      "examTip": "**FE80:: = Link-local IPv6.** Crucial for neighbor discovery and local communications without configuration."
    },
    {
      "id": 57,
      "question": "Which port is used by the Secure Shell (SSH) protocol to provide encrypted command-line access to network devices?",
      "options": [
        "22",
        "443",
        "3389",
        "80"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH uses port 22 for secure remote access. Port 443 is for HTTPS. Port 3389 is for RDP. Port 80 serves HTTP traffic.",
      "examTip": "**Port 22 = SSH secure access.** Always use SSH instead of Telnet for encrypted device management."
    },
    {
      "id": 58,
      "question": "Which wireless standard, operating exclusively in the 5GHz band, supports high throughput and multi-user communication for modern enterprise networks?",
      "options": [
        "802.11ac (Wi-Fi 5)",
        "802.11n (Wi-Fi 4)",
        "802.11g",
        "802.11b"
      ],
      "correctAnswerIndex": 0,
      "explanation": "802.11ac (Wi-Fi 5) operates in the 5GHz band, supporting high throughput and MU-MIMO. 802.11n supports both 2.4GHz and 5GHz with lower speeds. 802.11g and 802.11b are older standards with lower performance.",
      "examTip": "**802.11ac = 5GHz high-speed Wi-Fi.** Ideal for high-performance wireless deployments in enterprise environments."
    },
    {
      "id": 59,
      "question": "Which network monitoring tool provides real-time traffic analysis, allowing administrators to understand bandwidth usage patterns?",
      "options": [
        "NetFlow analyzer",
        "Wireshark",
        "SIEM system",
        "Toner probe"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NetFlow analyzers provide traffic flow analysis, offering insights into bandwidth usage and traffic patterns. Wireshark captures packet data for in-depth analysis. SIEM systems correlate security events. Toner probes trace physical cables, not traffic patterns.",
      "examTip": "**NetFlow = Bandwidth and traffic visibility.** Key for proactive capacity planning and performance optimization."
    },
    {
      "id": 60,
      "question": "Which protocol enables secure management of network devices by encrypting authentication credentials and supporting granular access control?",
      "options": [
        "SNMPv3",
        "Telnet",
        "FTP",
        "LDAP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SNMPv3 provides secure network management with encryption, authentication, and granular access control. Telnet transmits data in plaintext. FTP is used for file transfers without encryption. LDAP manages directory services but isn’t designed for device management.",
      "examTip": "**SNMPv3 = Secure device management.** Always prefer SNMPv3 over SNMPv1/v2 for encrypted, authenticated management."
    },
    {
      "id": 61,
      "question": "A network engineer needs to ensure that latency-sensitive applications like VoIP have guaranteed bandwidth during peak hours. Which solution BEST addresses this requirement?",
      "options": [
        "Configure Quality of Service (QoS) with traffic prioritization.",
        "Increase the available WAN bandwidth.",
        "Implement VLAN segmentation for VoIP traffic.",
        "Deploy additional switches to reduce congestion."
      ],
      "correctAnswerIndex": 0,
      "explanation": "QoS policies prioritize latency-sensitive traffic such as VoIP, ensuring bandwidth during peak usage. Increasing WAN bandwidth may not be cost-effective. VLANs provide segmentation but not prioritization. Adding switches does not guarantee traffic prioritization.",
      "examTip": "**QoS = Priority for critical traffic.** Essential for VoIP and real-time applications."
    },
    {
      "id": 62,
      "question": "Which WAN technology allows organizations to dynamically choose the best path for traffic based on real-time performance metrics across multiple link types?",
      "options": [
        "SD-WAN",
        "MPLS",
        "IPSec VPN",
        "Leased line"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SD-WAN dynamically routes traffic based on performance metrics, optimizing WAN utilization. MPLS provides predictable performance but lacks dynamic path selection. IPSec VPN secures traffic but doesn’t optimize performance. Leased lines are static and expensive.",
      "examTip": "**SD-WAN = Intelligent WAN optimization.** Best for balancing performance and cost."
    },
    {
      "id": 63,
      "question": "Which protocol provides secure, encrypted access to web applications using a standard web browser without installing client software?",
      "options": [
        "Clientless SSL VPN",
        "IPSec VPN",
        "SSH",
        "L2TP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Clientless SSL VPN offers secure access via browsers without client installation. IPSec VPN requires a client. SSH secures remote CLI access, not web apps. L2TP is a tunneling protocol without encryption unless paired with IPSec.",
      "examTip": "**Clientless SSL VPN = Browser-based secure access.** Ideal for remote access to web applications."
    },
    {
      "id": 64,
      "question": "Which type of IPv6 address allows devices to communicate globally and is equivalent to a public IPv4 address?",
      "options": [
        "Global unicast address",
        "Link-local address",
        "Unique local address",
        "Anycast address"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Global unicast addresses are globally routable, similar to public IPv4 addresses. Link-local addresses are only for local link communication. Unique local addresses are private. Anycast delivers data to the nearest node in a group.",
      "examTip": "**Global unicast = Public IPv6 addressing.** Used for devices requiring internet access."
    },
    {
      "id": 65,
      "question": "Which protocol dynamically resolves IP addresses to MAC addresses on a local network?",
      "options": [
        "ARP (Address Resolution Protocol)",
        "DNS",
        "DHCP",
        "NTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "ARP resolves IP addresses to MAC addresses within a local network. DNS resolves domain names to IP addresses. DHCP assigns IP configurations. NTP synchronizes time across network devices.",
      "examTip": "**ARP = IP-to-MAC resolution.** Vital for proper network communication on local segments."
    },
    {
      "id": 66,
      "question": "A network technician observes frequent changes in routing paths, leading to packet loss. What is the MOST likely cause?",
      "options": [
        "Routing loop caused by incorrect route advertisement.",
        "Port security misconfiguration.",
        "Firewall rules blocking ICMP traffic.",
        "VLAN misassignment."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Routing loops occur when incorrect routing advertisements create continuous path cycles, causing packet loss. Port security issues restrict access but don’t affect routing. Blocking ICMP affects diagnostics, not routing. VLAN misassignments impact Layer 2 segmentation, not routing loops.",
      "examTip": "**Routing loop = Unstable path selection.** Use TTL analysis and correct route advertisements to resolve."
    },
    {
      "id": 67,
      "question": "Which IPv6 mechanism allows devices to automatically configure their own addresses using router advertisements without manual intervention?",
      "options": [
        "SLAAC (Stateless Address Autoconfiguration)",
        "EUI-64",
        "DHCPv6",
        "NAT64"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SLAAC allows devices to auto-configure IPv6 addresses based on router advertisements. EUI-64 generates unique host identifiers. DHCPv6 provides centralized address management. NAT64 translates IPv6 to IPv4 addresses.",
      "examTip": "**SLAAC = Plug-and-play IPv6.** Simplifies IPv6 deployments with minimal configuration."
    },
    {
      "id": 68,
      "question": "Which protocol is used by email clients to retrieve messages from a mail server while leaving the original message on the server?",
      "options": [
        "IMAP (Internet Message Access Protocol)",
        "POP3",
        "SMTP",
        "FTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "IMAP retrieves emails while leaving them on the server for multi-device access. POP3 downloads and deletes emails by default. SMTP sends emails. FTP transfers files, unrelated to email retrieval.",
      "examTip": "**IMAP = Email sync across devices.** Best for multi-device email access needs."
    },
    {
      "id": 69,
      "question": "Which network topology offers the highest fault tolerance, ensuring that all devices remain connected even if multiple links fail?",
      "options": [
        "Full mesh topology",
        "Star topology",
        "Ring topology",
        "Bus topology"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Full mesh topology provides maximum redundancy; each device connects directly to every other device. Star topology depends on a central node. Ring topology is vulnerable to breaks unless dual-ring is used. Bus topology has a single point of failure.",
      "examTip": "**Full mesh = Maximum redundancy.** Ideal for critical networks where uptime is paramount."
    },
    {
      "id": 70,
      "question": "Which protocol uses port 443 and ensures encrypted data transmission for secure web browsing?",
      "options": [
        "HTTPS",
        "HTTP",
        "SSH",
        "SFTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "HTTPS uses port 443 for secure web communications via TLS encryption. HTTP uses port 80 without encryption. SSH (port 22) secures CLI access. SFTP (port 22) provides secure file transfers.",
      "examTip": "**Port 443 = Secure web access.** Always enforce HTTPS for secure online interactions."
    },
    {
      "id": 71,
      "question": "Which high-availability solution provides both redundancy and load balancing among multiple routers, ensuring efficient resource usage and failover?",
      "options": [
        "GLBP (Gateway Load Balancing Protocol)",
        "HSRP",
        "VRRP",
        "CARP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "GLBP provides load balancing and redundancy among multiple routers. HSRP and VRRP provide redundancy but not load balancing. CARP is an open-source alternative similar to VRRP.",
      "examTip": "**GLBP = Load balancing + Redundancy.** Ideal for multi-router environments needing efficient traffic distribution."
    },
    {
      "id": 72,
      "question": "Which wireless technology enhances performance by intelligently directing Wi-Fi signals toward client devices rather than broadcasting equally in all directions?",
      "options": [
        "Beamforming",
        "MU-MIMO",
        "Band steering",
        "Roaming"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Beamforming focuses wireless signals toward connected devices, improving performance and reducing interference. MU-MIMO supports simultaneous multi-user transmission. Band steering shifts devices between frequency bands. Roaming provides seamless AP transitions.",
      "examTip": "**Beamforming = Targeted wireless performance.** Boosts signal strength and reduces wasted bandwidth."
    },
    {
      "id": 73,
      "question": "Which authentication protocol supports single sign-on (SSO) by exchanging authentication and authorization data securely between parties using XML?",
      "options": [
        "SAML (Security Assertion Markup Language)",
        "RADIUS",
        "TACACS+",
        "LDAP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SAML enables SSO by securely exchanging authentication data using XML. RADIUS and TACACS+ provide centralized authentication but aren’t primarily used for SSO. LDAP manages directory services but doesn’t handle SSO across different systems.",
      "examTip": "**SAML = Web-based SSO.** Best for federated authentication across cloud services and web applications."
    },
    {
      "id": 74,
      "question": "Which protocol uses port 67 and port 68 to provide dynamic IP address configuration to devices in a network?",
      "options": [
        "DHCP (Dynamic Host Configuration Protocol)",
        "DNS",
        "TFTP",
        "NTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DHCP uses ports 67 (server) and 68 (client) to dynamically assign IP configurations. DNS resolves domain names to IP addresses. TFTP handles basic file transfers. NTP synchronizes time across network devices.",
      "examTip": "**Ports 67/68 = DHCP dynamic IP assignment.** Critical for automating IP distribution in large networks."
    },
    {
      "id": 75,
      "question": "Which routing protocol uses TCP port 179 and is essential for inter-domain routing decisions across the internet?",
      "options": [
        "BGP (Border Gateway Protocol)",
        "OSPF",
        "EIGRP",
        "RIP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BGP uses TCP port 179 for reliable inter-domain routing, forming the backbone of internet routing. OSPF handles internal routing using a link-state algorithm. EIGRP is Cisco-proprietary. RIP uses hop count but is outdated.",
      "examTip": "**BGP = Internet’s routing backbone.** Always associated with port 179 and policy-based routing."
    },
    {
      "id": 76,
      "question": "Which type of DNS record maps a domain name to an IPv6 address?",
      "options": [
        "AAAA record",
        "A record",
        "CNAME record",
        "MX record"
      ],
      "correctAnswerIndex": 0,
      "explanation": "AAAA records map domain names to IPv6 addresses. A records map to IPv4 addresses. CNAME provides domain aliases. MX specifies mail servers for the domain.",
      "examTip": "**AAAA = IPv6 DNS mapping.** Remember: A for IPv4, AAAA for IPv6."
    },
    {
      "id": 77,
      "question": "Which IPv6 address type is automatically assigned for communication on a local network segment and is required for neighbor discovery protocols?",
      "options": [
        "Link-local (FE80::/10)",
        "Global unicast",
        "Anycast",
        "Unique local"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Link-local addresses (FE80::/10) are automatically assigned for local communication and neighbor discovery. Global unicast addresses are publicly routable. Anycast sends data to the nearest node. Unique local addresses are private and not globally routable.",
      "examTip": "**FE80:: = Essential for local IPv6 operations.** Crucial for neighbor discovery and auto-configuration."
    },
    {
      "id": 78,
      "question": "Which network component is typically placed in a Demilitarized Zone (DMZ) to provide external users with secure access to internal applications without exposing internal networks?",
      "options": [
        "Reverse proxy server",
        "Firewall",
        "Load balancer",
        "Access point"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A reverse proxy server provides secure access to internal applications by handling external requests in the DMZ. Firewalls enforce security policies. Load balancers distribute traffic internally. Access points provide wireless connectivity, not DMZ functionality.",
      "examTip": "**Reverse proxy = Secure external access.** Essential for protecting internal applications while serving external clients."
    },
    {
      "id": 79,
      "question": "Which type of attack intercepts communication between two parties, allowing the attacker to modify or capture transmitted data without detection?",
      "options": [
        "On-path attack (Man-in-the-Middle)",
        "Denial-of-Service (DoS)",
        "ARP poisoning",
        "DNS spoofing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "On-path attacks (Man-in-the-Middle) intercept and potentially alter communication between two parties. DoS overwhelms resources to disrupt services. ARP poisoning redirects traffic via malicious ARP messages. DNS spoofing misdirects users to fraudulent sites.",
      "examTip": "**On-path attack = Silent interception.** Mitigate with encryption (TLS) and strong authentication measures."
    },
    {
      "id": 80,
      "question": "Which wireless security mechanism provides the highest level of protection by using SAE (Simultaneous Authentication of Equals) to resist dictionary attacks?",
      "options": [
        "WPA3",
        "WPA2",
        "WEP",
        "TKIP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3 uses SAE for robust encryption, resisting offline dictionary attacks. WPA2 is secure but less resistant to such attacks. WEP and TKIP are outdated and vulnerable.",
      "examTip": "**WPA3 = Top-tier Wi-Fi security.** Always implement WPA3 for new wireless deployments."
    },
    {
      "id": 81,
      "question": "A network administrator needs to ensure that only authorized devices connect to the network. Which technology uses certificates to validate devices before granting access?",
      "options": [
        "802.1X with EAP-TLS",
        "MAC address filtering",
        "WPA2-Personal",
        "Captive portal authentication"
      ],
      "correctAnswerIndex": 0,
      "explanation": "802.1X with EAP-TLS uses certificates for strong authentication, ensuring only authorized devices gain network access. MAC filtering is easily spoofed. WPA2-Personal uses shared passwords without device validation. Captive portals authenticate users, not devices.",
      "examTip": "**802.1X + EAP-TLS = Certificate-based network access.** Critical for securing enterprise environments against rogue devices."
    },
    {
      "id": 82,
      "question": "Which routing protocol supports both IPv4 and IPv6, is open-standard, and uses a hierarchical area-based design for scalability and fast convergence?",
      "options": [
        "OSPFv3",
        "BGP",
        "RIPng",
        "EIGRP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "OSPFv3 supports IPv6 (and IPv4), uses a hierarchical design, and converges quickly. BGP is used for external routing. RIPng is simple but lacks scalability. EIGRP is Cisco-proprietary.",
      "examTip": "**OSPFv3 = Scalable dual-stack routing.** Ideal for large enterprise networks transitioning to IPv6."
    },
    {
      "id": 83,
      "question": "Which WAN technology offers private, high-performance cloud connectivity by bypassing the public internet, ensuring consistent latency and throughput?",
      "options": [
        "Direct Connect",
        "IPSec VPN",
        "SD-WAN",
        "Leased line"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Direct Connect provides dedicated cloud connectivity, bypassing the public internet for stable performance. IPSec VPN secures data but traverses the internet. SD-WAN optimizes multiple WAN links. Leased lines provide point-to-point connectivity but aren’t cloud-specific.",
      "examTip": "**Direct Connect = Reliable cloud access.** Best for latency-sensitive cloud applications."
    },
    {
      "id": 84,
      "question": "A technician needs to verify that a router has learned the correct next-hop addresses for remote networks. Which command is MOST appropriate?",
      "options": [
        "show ip route",
        "show running-config",
        "ping",
        "traceroute"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`show ip route` displays the routing table, including next-hop information. `show running-config` shows current configurations. `ping` tests connectivity. `traceroute` reveals path information but not routing table details.",
      "examTip": "**show ip route = Routing verification.** Always check the routing table when diagnosing path issues."
    },
    {
      "id": 85,
      "question": "Which IPv6 transition technology allows IPv6-only devices to communicate with IPv4-only services by translating protocols and addresses?",
      "options": [
        "NAT64",
        "6to4 tunneling",
        "ISATAP",
        "Dual stack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NAT64 translates IPv6 packets into IPv4, enabling interoperability. 6to4 tunneling encapsulates IPv6 over IPv4 but doesn’t translate protocols. ISATAP facilitates intra-site IPv6 communications. Dual stack runs both protocols without translation.",
      "examTip": "**NAT64 = IPv6-to-IPv4 translator.** Essential during IPv6 adoption when IPv4 services must remain accessible."
    },
    {
      "id": 86,
      "question": "Which tool would BEST help a network engineer identify the source of excessive bandwidth usage in real-time?",
      "options": [
        "NetFlow analyzer",
        "Wireshark",
        "SNMP",
        "Toner probe"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NetFlow analyzers provide real-time traffic flow insights, showing bandwidth usage patterns. Wireshark captures packet-level details but lacks high-level traffic overviews. SNMP monitors device health but doesn’t provide traffic analysis. Toner probes trace cables physically.",
      "examTip": "**NetFlow = Bandwidth usage insight.** Critical for proactive capacity management."
    },
    {
      "id": 87,
      "question": "Which cloud service model allows developers to deploy applications without managing underlying infrastructure, focusing solely on the application logic?",
      "options": [
        "PaaS (Platform as a Service)",
        "IaaS (Infrastructure as a Service)",
        "SaaS (Software as a Service)",
        "FaaS (Function as a Service)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "PaaS provides developers with an environment to develop and deploy applications without managing infrastructure. IaaS requires infrastructure management. SaaS delivers complete applications. FaaS executes code without persistent application management.",
      "examTip": "**PaaS = Development without infrastructure headaches.** Perfect for rapid deployment and scaling of applications."
    },
    {
      "id": 88,
      "question": "Which wireless technology directs the signal toward specific devices, improving performance and reducing interference?",
      "options": [
        "Beamforming",
        "MU-MIMO",
        "Band steering",
        "Roaming"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Beamforming focuses the wireless signal toward client devices, enhancing speed and reliability. MU-MIMO supports simultaneous client transmissions. Band steering balances devices across frequency bands. Roaming ensures uninterrupted access point transitions.",
      "examTip": "**Beamforming = Directed Wi-Fi strength.** Key for enhancing wireless performance in dense environments."
    },
    {
      "id": 89,
      "question": "Which protocol uses port 5060 for unencrypted communication and port 5061 for encrypted communication in VoIP networks?",
      "options": [
        "SIP (Session Initiation Protocol)",
        "RTP",
        "MGCP",
        "H.323"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SIP uses port 5060 for unencrypted and port 5061 for encrypted (TLS) VoIP signaling. RTP handles media streams, not signaling. MGCP and H.323 are older VoIP protocols with different port assignments.",
      "examTip": "**SIP = VoIP signaling.** Remember: 5060 (unencrypted), 5061 (encrypted with TLS)."
    },
    {
      "id": 90,
      "question": "Which layer of the OSI model is responsible for translating data formats, such as encryption and compression?",
      "options": [
        "Presentation layer (Layer 6)",
        "Session layer (Layer 5)",
        "Application layer (Layer 7)",
        "Transport layer (Layer 4)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The presentation layer formats data for the application layer, handling encryption, compression, and translation. The session layer manages sessions. The application layer provides user services. The transport layer manages end-to-end communication.",
      "examTip": "**Layer 6 = Data formatting & encryption.** Critical for secure and compatible data exchange."
    },
    {
      "id": 91,
      "question": "Which BGP attribute can be manipulated to control inbound routing decisions from external autonomous systems by altering perceived path length?",
      "options": [
        "AS path prepending",
        "Local preference",
        "MED (Multi-Exit Discriminator)",
        "Next-hop"
      ],
      "correctAnswerIndex": 0,
      "explanation": "AS path prepending lengthens the AS path, making a route less attractive for inbound traffic. Local preference affects outbound routing. MED influences preferred entry points. Next-hop indicates the next routing hop but doesn’t influence path selection directly.",
      "examTip": "**AS path prepending = Inbound traffic control.** Adjust AS path to influence external peers’ routing decisions."
    },
    {
      "id": 92,
      "question": "Which IPv6 address type is designed to provide communication between nodes in the same organization but not routable on the public internet?",
      "options": [
        "Unique local address (ULA)",
        "Global unicast address",
        "Link-local address",
        "Anycast address"
      ],
      "correctAnswerIndex": 0,
      "explanation": "ULAs (fc00::/7) provide internal communication within an organization but are not globally routable. Global unicast addresses are public. Link-local addresses communicate within a link. Anycast delivers packets to the nearest node.",
      "examTip": "**ULA = Private IPv6 addressing.** Best for internal networks without global exposure."
    },
    {
      "id": 93,
      "question": "Which high-availability technique ensures minimal downtime by running two systems in parallel, providing immediate failover without performance impact?",
      "options": [
        "Active-active clustering",
        "Active-passive clustering",
        "Cold site deployment",
        "Warm site deployment"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Active-active clustering runs systems in parallel, offering load balancing and seamless failover. Active-passive keeps one node idle until failover. Cold sites require full system setup during recovery. Warm sites have partial resources pre-configured.",
      "examTip": "**Active-active = High performance + Redundancy.** Ideal for mission-critical applications needing continuous availability."
    },
    {
      "id": 94,
      "question": "Which protocol uses port 1433 by default and enables database connectivity for SQL servers?",
      "options": [
        "TDS (Tabular Data Stream) for SQL Server",
        "LDAP",
        "RDP",
        "SMTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "TDS (used by Microsoft SQL Server) operates on port 1433 by default for database connectivity. LDAP uses port 389. RDP uses port 3389. SMTP uses port 25 for email transmission.",
      "examTip": "**Port 1433 = SQL Server communication.** Always secure database ports to prevent unauthorized access."
    },
    {
      "id": 95,
      "question": "Which cloud deployment model allows a single organization exclusive access to cloud infrastructure hosted off-site, ensuring maximum control and security?",
      "options": [
        "Private cloud",
        "Hybrid cloud",
        "Public cloud",
        "Community cloud"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Private clouds provide dedicated resources for one organization, offering full control and security. Hybrid clouds combine public and private elements. Public clouds share resources among users. Community clouds serve organizations with common concerns.",
      "examTip": "**Private cloud = Dedicated security.** Best for compliance-driven industries requiring isolated environments."
    },
    {
      "id": 96,
      "question": "Which protocol ensures precise time synchronization across devices with microsecond-level accuracy, often used in financial and telecommunications systems?",
      "options": [
        "PTP (Precision Time Protocol)",
        "NTP",
        "SNMP",
        "Syslog"
      ],
      "correctAnswerIndex": 0,
      "explanation": "PTP offers sub-microsecond synchronization, essential for time-sensitive operations. NTP provides millisecond-level accuracy. SNMP manages network devices. Syslog collects event logs but doesn’t synchronize time.",
      "examTip": "**PTP = Precision timing.** Critical for high-frequency trading and telecom networks."
    },
    {
      "id": 97,
      "question": "Which protocol enables secure email transmission by encrypting SMTP connections on port 587?",
      "options": [
        "SMTPS (SMTP Secure)",
        "POP3S",
        "IMAPS",
        "SFTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SMTPS encrypts email transmissions via SMTP on port 587. POP3S and IMAPS secure email retrieval. SFTP secures file transfers, unrelated to email.",
      "examTip": "**Port 587 + SMTPS = Secure email sending.** Always use SMTPS to protect outbound email communications."
    },
    {
      "id": 98,
      "question": "Which BGP attribute influences outbound routing decisions within an autonomous system by assigning a preference value to specific routes?",
      "options": [
        "Local preference",
        "AS path",
        "MED",
        "Weight"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Local preference controls outbound traffic within an AS; higher values are preferred. AS path affects inbound traffic. MED influences how external peers select entry points. Weight is Cisco-specific and affects only the local router.",
      "examTip": "**Local preference = Outbound path control.** Adjust this attribute to prefer specific external links."
    },
    {
      "id": 99,
      "question": "Which DNS record type maps a hostname to an IPv4 address for forward lookups?",
      "options": [
        "A record",
        "PTR record",
        "CNAME record",
        "AAAA record"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A records map hostnames to IPv4 addresses. PTR records provide reverse DNS mapping. CNAME records create domain aliases. AAAA records map hostnames to IPv6 addresses.",
      "examTip": "**A record = IPv4 DNS mapping.** Essential for standard web service configurations."
    },
    {
      "id": 100,
      "question": "Which wireless standard, operating in the 6GHz band, offers reduced latency and higher throughput for dense environments with minimal interference?",
      "options": [
        "802.11ax (Wi-Fi 6E)",
        "802.11ac",
        "802.11n",
        "802.11g"
      ],
      "correctAnswerIndex": 0,
      "explanation": "802.11ax (Wi-Fi 6E) operates in the 6GHz band, providing higher speeds, reduced latency, and minimal interference. 802.11ac uses 5GHz. 802.11n supports both 2.4GHz and 5GHz. 802.11g uses 2.4GHz with lower speeds.",
      "examTip": "**Wi-Fi 6E = 6GHz high-performance wireless.** Ideal for modern enterprise deployments requiring maximum throughput."
    }
  ]
});      
