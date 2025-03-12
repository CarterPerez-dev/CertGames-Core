db.tests.insertOne({
  "category": "nplus",
  "testId": 6,
  "testName": "CompTIA Network+ (N10-009) Practice Test #6 (Formidable)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A network engineer needs to configure inter-VLAN routing on a multi-layer switch. The VLANs have been created, and ports have been assigned. What is the FIRST configuration step to enable communication between the VLANs?",
      "options": [
        "Create Switch Virtual Interfaces for each VLAN.",
        "Enable trunking on the uplink ports.",
        "Configure a static route between VLANs.",
        "Assign IP addresses to access ports."
      ],
      "correctAnswerIndex": 0,
      "explanation": "SVIs provide Layer 3 interfaces for VLANs, enabling inter-VLAN routing. Trunking is necessary between switches but not for routing on the same switch. Static routes aren’t required if SVIs are configured. Access ports do not require IP addresses.",
      "examTip": "**SVI = VLAN routing.** Always configure SVIs first for inter-VLAN communication."
    },
    {
      "id": 2,
      "question": "Which protocol enhances routing efficiency between autonomous systems by preventing routing loops and supporting policy-based routing decisions?",
      "options": [
        "BGP",
        "OSPF",
        "EIGRP",
        "RIP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BGP (Border Gateway Protocol) uses path-vector logic to avoid routing loops and supports policy-based routing between autonomous systems. OSPF and EIGRP are used internally, and RIP is outdated and less efficient.",
      "examTip": "**BGP = Internet’s routing backbone.** Handles large-scale, inter-AS routing decisions."
    },
    {
      "id": 3,
      "question": "An organization needs to ensure rapid failover for critical WAN links without manual intervention. Which technology provides this capability by dynamically rerouting traffic?",
      "options": [
        "SD-WAN",
        "HSRP",
        "VRRP",
        "OSPF"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SD-WAN dynamically reroutes traffic based on link conditions, ensuring rapid failover. HSRP and VRRP provide gateway redundancy but do not manage WAN links. OSPF supports internal routing but not WAN link failover directly.",
      "examTip": "**SD-WAN = Smart WAN failover.** Ideal for maintaining uptime across multiple WAN links."
    },
    {
      "id": 4,
      "question": "Which IPv6 transition technology allows IPv6-enabled devices to communicate over an IPv4-only network without modifying the existing IPv4 infrastructure?",
      "options": [
        "6to4 tunneling",
        "NAT64",
        "Dual stack",
        "ISATAP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "6to4 tunneling encapsulates IPv6 packets within IPv4 packets, enabling communication without infrastructure changes. NAT64 translates between IPv6 and IPv4. Dual stack requires running both protocols, and ISATAP is limited to intra-site communication.",
      "examTip": "**6to4 = IPv6 over IPv4 tunnel.** Useful during gradual IPv6 adoption phases."
    },
    {
      "id": 5,
      "question": "A technician notices that a trunk link between two switches is carrying fewer VLANs than expected. Which misconfiguration is MOST likely the cause?",
      "options": [
        "VLANs not allowed on the trunk link.",
        "Native VLAN mismatch on the trunk ports.",
        "Incorrect duplex settings on the trunk interface.",
        "Spanning Tree Protocol (STP) blocking the trunk port."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If VLANs are not explicitly allowed on the trunk, they won’t be carried across. A native VLAN mismatch triggers security warnings but doesn't block VLANs. Duplex mismatches affect speed, not VLAN carriage. STP would block entire ports, not specific VLANs.",
      "examTip": "**Check trunk allowed VLANs.** Always verify the allowed VLAN list during trunk troubleshooting."
    },
    {
      "id": 6,
      "question": "Which routing metric does OSPF use to determine the shortest path to a destination network?",
      "options": [
        "Cost based on bandwidth",
        "Hop count",
        "Delay and reliability",
        "Administrative distance"
      ],
      "correctAnswerIndex": 0,
      "explanation": "OSPF uses cost derived from bandwidth to calculate the shortest path. RIP uses hop count. EIGRP uses delay and reliability. Administrative distance is used to select routing protocols, not paths within OSPF.",
      "examTip": "**OSPF = Bandwidth-based routing.** Higher bandwidth = lower cost in OSPF calculations."
    },
    {
      "id": 7,
      "question": "Which technology ensures that only authorized devices gain access to network resources by enforcing port-based authentication?",
      "options": [
        "802.1X",
        "Port security",
        "MAC filtering",
        "Access Control List (ACL)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "802.1X provides robust port-based authentication using RADIUS servers. Port security limits MAC addresses but is susceptible to spoofing. MAC filtering is weaker and easier to bypass. ACLs control traffic flow but don’t handle authentication.",
      "examTip": "**802.1X = Strong port-based access control.** Ideal for enterprise-grade network security."
    },
    {
      "id": 8,
      "question": "A network administrator is configuring a VPN solution that allows clients to access internal resources securely without client software. Which VPN type should be implemented?",
      "options": [
        "Clientless SSL VPN",
        "IPSec site-to-site VPN",
        "Full-tunnel VPN with client software",
        "Split-tunnel VPN"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Clientless SSL VPN allows secure access via a web browser without installing client software. IPSec site-to-site VPN connects entire networks. Full-tunnel VPN requires client software, and split-tunnel VPN directs only some traffic through the VPN.",
      "examTip": "**Clientless SSL VPN = Browser-based secure access.** Perfect for remote users without client installations."
    },
    {
      "id": 9,
      "question": "Which protocol supports fast convergence, hierarchical network design, and uses areas to optimize routing?",
      "options": [
        "OSPF",
        "BGP",
        "RIP",
        "IS-IS"
      ],
      "correctAnswerIndex": 0,
      "explanation": "OSPF supports fast convergence and hierarchical design with areas. BGP is for inter-AS routing. RIP is outdated with slow convergence. IS-IS is similar to OSPF but less commonly used in enterprise networks.",
      "examTip": "**OSPF = Area-based efficiency.** Ideal for scalable, hierarchical network designs."
    },
    {
      "id": 10,
      "question": "Which tool provides deep inspection of network traffic and can be used to analyze protocols, detect anomalies, and troubleshoot latency issues?",
      "options": [
        "Wireshark",
        "NetFlow analyzer",
        "Nmap",
        "Syslog server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Wireshark captures and analyzes packet-level traffic for in-depth troubleshooting. NetFlow provides flow statistics but not detailed packet analysis. Nmap scans for open ports and services. Syslog servers collect and store event logs.",
      "examTip": "**Wireshark = Deep-dive packet analysis.** Essential for protocol troubleshooting and latency investigations."
    },
    {
      "id": 11,
      "question": "A company needs to ensure that sensitive network segments are isolated but can still communicate securely when necessary. Which approach BEST achieves this?",
      "options": [
        "Implementing VLANs with inter-VLAN routing and ACLs.",
        "Placing all devices on a single VLAN with strict firewall rules.",
        "Using port mirroring for traffic segmentation.",
        "Deploying a flat network with network segmentation at the core switch."
      ],
      "correctAnswerIndex": 0,
      "explanation": "VLANs provide logical segmentation, while ACLs control inter-VLAN traffic securely. Single VLAN configurations don’t provide proper segmentation. Port mirroring is for monitoring, not segmentation. Flat networks lack effective isolation.",
      "examTip": "**VLAN + ACL = Secure segmentation.** Combines isolation with controlled communication."
    },
    {
      "id": 12,
      "question": "Which IPv6 transition mechanism translates IPv6 addresses to IPv4, allowing communication between IPv6-only and IPv4-only hosts?",
      "options": [
        "NAT64",
        "6to4 tunneling",
        "Dual stack",
        "ISATAP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NAT64 translates IPv6 addresses into IPv4, facilitating cross-protocol communication. 6to4 tunneling encapsulates IPv6 in IPv4. Dual stack runs both stacks independently. ISATAP provides IPv6 connectivity within IPv4 networks.",
      "examTip": "**NAT64 = IPv6-IPv4 translator.** Enables interoperability without dual-stacking."
    },
    {
      "id": 13,
      "question": "Which routing protocol uses hop count as its only metric and has a maximum hop count limit, making it less suitable for large networks?",
      "options": [
        "RIP",
        "OSPF",
        "EIGRP",
        "BGP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RIP (Routing Information Protocol) uses hop count with a maximum of 15 hops, limiting scalability. OSPF uses bandwidth-based cost. EIGRP uses a composite metric. BGP is policy-based for inter-AS routing.",
      "examTip": "**RIP = Hop count simplicity.** Avoid in large networks due to scalability constraints."
    },
    {
      "id": 14,
      "question": "Which device provides intelligent traffic management, balances load among multiple servers, and improves application availability?",
      "options": [
        "Load balancer",
        "Firewall",
        "Router",
        "Proxy server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Load balancers distribute client traffic across multiple servers, enhancing availability and performance. Firewalls secure networks. Routers forward packets between networks. Proxy servers mediate client requests but don’t balance server loads.",
      "examTip": "**Load balancer = High availability & scalability.** Key for resilient web and application services."
    },
    {
      "id": 15,
      "question": "A network engineer must implement a solution that continuously verifies system health and redirects traffic away from failed nodes in real-time. Which solution should be deployed?",
      "options": [
        "High-availability load balancer with health checks",
        "Redundant firewalls in active-passive mode",
        "Dynamic DNS failover",
        "Spanning Tree Protocol (STP)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Load balancers with health checks detect failures and reroute traffic instantly. Redundant firewalls provide perimeter security redundancy but not traffic balancing. Dynamic DNS helps with external failover. STP prevents Layer 2 loops, not traffic rerouting.",
      "examTip": "**Health-checked load balancing = Real-time failover.** Ensures seamless user experience during outages."
    },
    {
      "id": 16,
      "question": "Which type of wireless antenna provides the widest coverage area but typically at lower signal strength?",
      "options": [
        "Omnidirectional",
        "Directional",
        "Yagi",
        "Parabolic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Omnidirectional antennas radiate signal equally in all directions, providing broad coverage. Directional, Yagi, and parabolic antennas focus the signal for longer-distance communication but with narrower coverage areas.",
      "examTip": "**Omnidirectional = Wide-area coverage.** Best for general indoor wireless deployments."
    },
    {
      "id": 17,
      "question": "Which protocol encrypts authentication information and supports multifactor authentication, making it suitable for enterprise wireless networks?",
      "options": [
        "RADIUS",
        "LDAP",
        "TACACS+",
        "Kerberos"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RADIUS encrypts authentication data and supports multifactor authentication. LDAP lacks encryption by default. TACACS+ encrypts the entire payload but is more common in device management. Kerberos is used for secure ticket-based authentication.",
      "examTip": "**RADIUS = Secure wireless authentication.** Often paired with 802.1X for enterprise networks."
    },
    {
      "id": 18,
      "question": "Which cloud service model provides developers with a framework and tools to build applications without managing the underlying infrastructure?",
      "options": [
        "PaaS",
        "SaaS",
        "IaaS",
        "FaaS"
      ],
      "correctAnswerIndex": 0,
      "explanation": "PaaS (Platform as a Service) offers environments for application development without managing infrastructure. SaaS provides complete applications. IaaS offers raw infrastructure. FaaS provides serverless architecture for running code functions.",
      "examTip": "**PaaS = Developer’s playground.** Focus on coding, not managing servers."
    },
    {
      "id": 19,
      "question": "Which port number is used by SNMP traps for sending alert notifications from managed devices to monitoring systems?",
      "options": [
        "162",
        "161",
        "514",
        "69"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SNMP traps use UDP port 162 for sending alerts. Port 161 is used for SNMP polling. Port 514 is for Syslog, and port 69 is for TFTP.",
      "examTip": "**SNMP traps = Port 162.** For proactive alerts from network devices to management systems."
    },
    {
      "id": 20,
      "question": "Which IPv6 address type allows communication with all nodes on a link and is typically used for neighbor discovery?",
      "options": [
        "Multicast (FF02::1)",
        "Anycast",
        "Global unicast",
        "Unique local"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The multicast address FF02::1 targets all nodes on a local link, commonly used for neighbor discovery. Anycast sends data to the nearest node. Global unicast addresses are publicly routable. Unique local addresses are private equivalents in IPv6.",
      "examTip": "**FF02::1 = All nodes multicast.** Key for local IPv6 operations like neighbor discovery."
    },
    {
      "id": 21,
      "question": "A network administrator is implementing OSPF across multiple areas to optimize routing. Which statement BEST describes how OSPF handles area configuration?",
      "options": [
        "Area 0 must be present and act as the backbone area connecting all other areas.",
        "All areas must be directly connected to each other without a backbone.",
        "Areas can be created arbitrarily without hierarchical design for simplicity.",
        "External routes are redistributed automatically without user configuration."
      ],
      "correctAnswerIndex": 0,
      "explanation": "In OSPF, Area 0 (the backbone) is essential for connecting all other areas and maintaining routing efficiency. Non-backbone areas must connect to Area 0. Arbitrary designs without hierarchy lead to inefficiency. External route redistribution requires configuration.",
      "examTip": "**OSPF Area 0 = Backbone.** Always connect non-backbone areas to Area 0 for optimal OSPF operations."
    },
    {
      "id": 22,
      "question": "An engineer needs to implement a solution that allows multiple physical links to be combined into one logical link for redundancy and increased throughput. Which technology should be used?",
      "options": [
        "Link Aggregation Control Protocol (LACP)",
        "Spanning Tree Protocol (STP)",
        "EtherChannel",
        "Port mirroring"
      ],
      "correctAnswerIndex": 0,
      "explanation": "LACP (part of IEEE 802.3ad) enables multiple links to function as a single logical link, offering redundancy and higher throughput. EtherChannel also achieves this but is vendor-specific. STP prevents loops but doesn’t aggregate links. Port mirroring is for monitoring purposes.",
      "examTip": "**LACP = Redundancy + Bandwidth.** Use LACP for vendor-agnostic link aggregation."
    },
    {
      "id": 23,
      "question": "A user reports that their VPN connection works but cannot access internal resources by hostname. Which is the MOST likely cause?",
      "options": [
        "DNS misconfiguration in the VPN settings.",
        "Split tunneling is disabled.",
        "The VPN uses an incorrect encryption protocol.",
        "Firewall rules are blocking VPN traffic."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If internal resources are accessible by IP but not hostname, DNS misconfiguration is likely. Split tunneling affects routing, not name resolution. Encryption protocol issues would block the VPN entirely. Firewall rules typically block all access, not just DNS resolution.",
      "examTip": "**VPN DNS issues? Check DNS settings first.** Hostname resolution failures usually trace back to DNS."
    },
    {
      "id": 24,
      "question": "Which technology allows the encapsulation of Layer 2 traffic over a Layer 3 network, often used for data center interconnects?",
      "options": [
        "VXLAN",
        "GRE",
        "IPSec",
        "MPLS"
      ],
      "correctAnswerIndex": 0,
      "explanation": "VXLAN (Virtual Extensible LAN) encapsulates Layer 2 frames within Layer 3 packets, enabling Layer 2 connectivity over long distances. GRE provides generic tunneling but lacks Layer 2 awareness. IPSec secures data but doesn’t handle Layer 2 encapsulation. MPLS directs packets at Layer 3 based on labels.",
      "examTip": "**VXLAN = Layer 2 over Layer 3.** Ideal for scalable multi-data center architectures."
    },
    {
      "id": 25,
      "question": "A network team is implementing dual-stack IPv6. What is a key advantage of this approach?",
      "options": [
        "It allows simultaneous support for IPv4 and IPv6 without translation.",
        "It eliminates the need for IPv4 immediately.",
        "It reduces the complexity of network configurations.",
        "It allows IPv6-only devices to communicate with IPv4-only devices without extra mechanisms."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Dual-stack runs both IPv4 and IPv6 on the same devices, enabling native support for both protocols without translation. However, it doesn’t eliminate IPv4 immediately or simplify configurations. Inter-protocol communication still requires NAT64 or similar mechanisms.",
      "examTip": "**Dual-stack = Native dual-protocol support.** Smooth transition strategy for IPv6 adoption."
    },
    {
      "id": 26,
      "question": "Which protocol would be BEST for securely synchronizing time across devices in a highly secure enterprise environment?",
      "options": [
        "NTP with NTS (Network Time Security)",
        "SNMPv3",
        "RADIUS",
        "PTP (Precision Time Protocol)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NTP with NTS ensures secure time synchronization by protecting against time-based attacks. SNMPv3 secures device management. RADIUS handles authentication. PTP is highly precise but typically used in specialized environments like financial trading, not general enterprise synchronization.",
      "examTip": "**NTP + NTS = Secure time sync.** Crucial for accurate logging and security across distributed systems."
    },
    {
      "id": 27,
      "question": "A network engineer needs to prevent broadcast storms in a Layer 2 network with redundant links. Which protocol should be implemented?",
      "options": [
        "Rapid Spanning Tree Protocol (RSTP)",
        "LACP",
        "OSPF",
        "VTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RSTP (802.1w) quickly resolves topology changes and prevents broadcast storms caused by Layer 2 loops. LACP aggregates links. OSPF operates at Layer 3. VTP manages VLAN configurations but doesn’t prevent loops.",
      "examTip": "**RSTP = Fast loop prevention.** Reduces downtime during topology changes compared to standard STP."
    },
    {
      "id": 28,
      "question": "Which protocol uses port 636 and provides secure access to directory services?",
      "options": [
        "LDAPS",
        "LDAP",
        "HTTPS",
        "RADIUS"
      ],
      "correctAnswerIndex": 0,
      "explanation": "LDAPS (LDAP over SSL) uses port 636 to secure directory service communications. LDAP on port 389 is unencrypted. HTTPS secures web traffic on port 443. RADIUS handles authentication, typically on ports 1812 and 1813.",
      "examTip": "**LDAPS = Secure directory access.** Always prefer LDAPS over LDAP for secure identity management."
    },
    {
      "id": 29,
      "question": "A company uses BGP for internet connectivity. What is the MOST likely reason for configuring BGP attributes such as AS path and local preference?",
      "options": [
        "To influence routing decisions and path selection.",
        "To encrypt data during transmission across ISPs.",
        "To prevent DDoS attacks on the network.",
        "To provide redundancy within an OSPF area."
      ],
      "correctAnswerIndex": 0,
      "explanation": "BGP attributes like AS path and local preference influence routing decisions by determining the preferred path. BGP doesn’t handle encryption or DDoS mitigation directly. OSPF operates independently of BGP attributes.",
      "examTip": "**BGP attributes = Path control.** Use AS path and local preference for intelligent route optimization."
    },
    {
      "id": 30,
      "question": "Which protocol supports tunneling of private network traffic over public networks by encrypting the entire IP packet, ensuring confidentiality and integrity?",
      "options": [
        "IPSec in tunnel mode",
        "GRE",
        "L2TP",
        "SSL"
      ],
      "correctAnswerIndex": 0,
      "explanation": "IPSec in tunnel mode encrypts the entire original IP packet, providing secure site-to-site VPN connectivity. GRE provides tunneling but no encryption. L2TP lacks encryption unless paired with IPSec. SSL secures web traffic but isn’t designed for IP-level tunneling.",
      "examTip": "**IPSec tunnel mode = Full packet protection.** Use for secure site-to-site VPNs."
    },
    {
      "id": 31,
      "question": "A network administrator needs to configure a VLAN that prioritizes VoIP traffic. Which configuration BEST achieves this?",
      "options": [
        "Voice VLAN with QoS settings applied.",
        "Default VLAN with increased bandwidth allocation.",
        "Trunk port carrying voice and data traffic without QoS.",
        "Separate physical network for voice traffic."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A dedicated voice VLAN with QoS ensures proper prioritization and minimal latency for VoIP. Using the default VLAN or trunking without QoS risks congestion. Separate physical networks are expensive and unnecessary with VLANs.",
      "examTip": "**Voice VLAN + QoS = Clear calls.** Always configure QoS for latency-sensitive applications like VoIP."
    },
    {
      "id": 32,
      "question": "Which device is responsible for converting digital signals into modulated signals for transmission over analog media such as DSL lines?",
      "options": [
        "Modem",
        "Router",
        "Switch",
        "Access Point"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A modem modulates and demodulates signals for transmission over analog mediums like DSL. Routers direct traffic between networks. Switches forward traffic within networks. Access points connect wireless devices to a wired network.",
      "examTip": "**Modem = Digital-analog converter.** Critical for broadband technologies like DSL."
    },
    {
      "id": 33,
      "question": "Which IPv6 mechanism allows automatic generation of an interface identifier using the device’s MAC address?",
      "options": [
        "EUI-64",
        "SLAAC",
        "NAT64",
        "DHCPv6"
      ],
      "correctAnswerIndex": 0,
      "explanation": "EUI-64 generates a 64-bit interface identifier from a MAC address, ensuring unique addresses. SLAAC allows self-configuration but may use EUI-64 for the interface ID. NAT64 translates IPv6 to IPv4. DHCPv6 assigns addresses but doesn’t derive them from MAC addresses.",
      "examTip": "**EUI-64 = MAC-based IPv6 address.** Guarantees globally unique IPv6 addresses."
    },
    {
      "id": 34,
      "question": "Which topology provides full redundancy by directly connecting every node to every other node, though at higher cost and complexity?",
      "options": [
        "Full mesh",
        "Star",
        "Bus",
        "Ring"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Full mesh topologies offer maximum redundancy and fault tolerance as every node connects directly to all others. Star topologies rely on a central device. Bus topologies share a single medium. Ring topologies have limited redundancy and can suffer from single points of failure.",
      "examTip": "**Full mesh = Redundancy maximized.** Best for critical network segments needing high availability."
    },
    {
      "id": 35,
      "question": "Which protocol allows secure, remote access to a graphical desktop over the internet, commonly used in Windows environments?",
      "options": [
        "RDP",
        "VNC",
        "SSH",
        "Telnet"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RDP (Remote Desktop Protocol) allows secure access to graphical desktops, especially in Windows environments, using port 3389. VNC offers graphical access but typically lacks built-in encryption. SSH provides secure command-line access. Telnet is insecure and deprecated.",
      "examTip": "**RDP = Secure Windows GUI access.** Always secure RDP traffic with encryption or VPN tunneling."
    },
    {
      "id": 36,
      "question": "Which routing protocol uses TCP for reliability and is essential for routing decisions across the internet?",
      "options": [
        "BGP",
        "OSPF",
        "EIGRP",
        "RIP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BGP (Border Gateway Protocol) uses TCP port 179, ensuring reliable delivery of routing information across the internet. OSPF uses IP directly (protocol 89). EIGRP uses reliable transport but not TCP. RIP uses UDP port 520 and is less scalable.",
      "examTip": "**BGP = TCP-based internet routing.** Guarantees reliability in inter-domain route exchanges."
    },
    {
      "id": 37,
      "question": "Which component of a network management system collects and stores logs from various devices for centralized analysis?",
      "options": [
        "Syslog server",
        "SNMP manager",
        "TFTP server",
        "NetFlow collector"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A Syslog server centralizes log collection, simplifying monitoring and troubleshooting. SNMP managers collect device metrics but not logs. TFTP servers handle file transfers. NetFlow collectors analyze traffic flows, not logs.",
      "examTip": "**Syslog server = Central log hub.** Essential for tracking events across distributed systems."
    },
    {
      "id": 38,
      "question": "A technician is configuring a router for dynamic NAT. What is the PRIMARY requirement for this configuration to function correctly?",
      "options": [
        "A defined pool of public IP addresses.",
        "A one-to-one mapping of private to public IPs.",
        "A static route to the destination network.",
        "A VPN tunnel for secure translations."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Dynamic NAT requires a pool of public IP addresses for mapping private addresses as they access external networks. Static NAT provides one-to-one mappings. Static routes direct traffic but aren’t required for NAT. VPN tunnels encrypt traffic but don’t affect NAT configuration.",
      "examTip": "**Dynamic NAT = IP pool required.** Maps multiple private IPs to available public addresses."
    },
    {
      "id": 39,
      "question": "Which encryption protocol secures wireless networks by providing robust authentication and encrypting both control and management frames?",
      "options": [
        "WPA3",
        "WPA2",
        "WEP",
        "TKIP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3 offers stronger encryption (SAE) and protects management frames. WPA2 is secure but lacks WPA3’s enhancements. WEP is outdated and insecure. TKIP was designed for WEP upgrades but is now obsolete.",
      "examTip": "**WPA3 = Modern Wi-Fi security.** Always implement WPA3 when available for maximum wireless protection."
    },
    {
      "id": 40,
      "question": "Which wireless technology dynamically selects the best available frequency band for a client device to optimize performance?",
      "options": [
        "Band steering",
        "MU-MIMO",
        "Beamforming",
        "Roaming"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Band steering automatically shifts clients to the best frequency (2.4GHz or 5GHz) for optimal performance. MU-MIMO allows simultaneous multi-device communication. Beamforming directs signal strength toward specific devices. Roaming enables seamless AP switching without manual intervention.",
      "examTip": "**Band steering = Optimal frequency allocation.** Balances client loads for efficient wireless performance."
    },
    {
      "id": 41,
      "question": "A network engineer needs to reduce routing table size and improve convergence speed in a large OSPF deployment. Which technique should be used?",
      "options": [
        "Route summarization",
        "Redistribution between routing protocols",
        "Static routing",
        "Default routing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Route summarization reduces the number of entries in routing tables, improving convergence times in large OSPF environments. Redistribution is used between different protocols but increases complexity. Static routing reduces flexibility. Default routing is efficient but not suitable for all destinations in large networks.",
      "examTip": "**Summarization = Simpler routing tables.** Speeds up convergence and reduces resource use in OSPF."
    },
    {
      "id": 42,
      "question": "Which technology allows dynamic distribution of network policies and configurations across multiple WAN connections, optimizing application performance?",
      "options": [
        "SD-WAN",
        "MPLS",
        "VPN",
        "BGP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SD-WAN dynamically applies policies and routes traffic across WAN links based on performance metrics. MPLS provides reliable transport but lacks dynamic optimization. VPNs secure traffic but don’t optimize it. BGP influences routing decisions but doesn’t apply application-specific policies.",
      "examTip": "**SD-WAN = Intelligent WAN optimization.** Adjusts paths dynamically for better app performance."
    },
    {
      "id": 43,
      "question": "Which IPv6 address type is used for one-to-many communication within a network segment, such as sending routing updates to multiple devices?",
      "options": [
        "Multicast",
        "Unicast",
        "Anycast",
        "Link-local"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Multicast addresses deliver data to multiple recipients, such as routing updates. Unicast addresses a single device. Anycast delivers data to the nearest node in a group. Link-local addresses are limited to the local network segment.",
      "examTip": "**Multicast = Efficient group communication.** Reduces unnecessary traffic when broadcasting to multiple devices."
    },
    {
      "id": 44,
      "question": "Which network security technique provides segmentation by isolating groups of devices at Layer 2 without using separate physical hardware?",
      "options": [
        "VLANs",
        "ACLs",
        "Port mirroring",
        "Trunking"
      ],
      "correctAnswerIndex": 0,
      "explanation": "VLANs logically segment devices at Layer 2, providing isolation without extra hardware. ACLs control traffic flow but don’t segment networks. Port mirroring copies traffic for analysis. Trunking carries multiple VLANs across a single link but doesn’t provide segmentation itself.",
      "examTip": "**VLANs = Logical segmentation.** Improve security and efficiency without extra physical equipment."
    },
    {
      "id": 45,
      "question": "Which protocol dynamically assigns IP addresses and provides options such as default gateway and DNS server information?",
      "options": [
        "DHCP",
        "DNS",
        "NTP",
        "SNMP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DHCP (Dynamic Host Configuration Protocol) automatically assigns IP addresses and configuration parameters. DNS resolves domain names. NTP synchronizes time. SNMP manages network devices but doesn’t handle IP assignments.",
      "examTip": "**DHCP = Plug-and-play networking.** Essential for efficient IP management in dynamic environments."
    },
    {
      "id": 46,
      "question": "A network administrator wants to ensure that only authorized devices can connect to network switches. Which technology provides authentication at the port level using credentials?",
      "options": [
        "802.1X",
        "MAC filtering",
        "Port security",
        "ACLs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "802.1X offers port-based authentication using RADIUS servers, ensuring only authorized devices access the network. MAC filtering and port security are less secure and easier to bypass. ACLs manage traffic but don’t authenticate devices.",
      "examTip": "**802.1X = Port-level authentication.** Combine with RADIUS for robust access control."
    },
    {
      "id": 47,
      "question": "Which type of DNS record is responsible for mapping domain names to IPv6 addresses?",
      "options": [
        "AAAA",
        "A",
        "CNAME",
        "MX"
      ],
      "correctAnswerIndex": 0,
      "explanation": "AAAA records map domain names to IPv6 addresses. A records map to IPv4 addresses. CNAME provides alias names. MX specifies mail servers for the domain.",
      "examTip": "**AAAA = IPv6 DNS mapping.** Remember: A for IPv4, AAAA for IPv6."
    },
    {
      "id": 48,
      "question": "Which cloud deployment model allows organizations to share resources while addressing specific community concerns, such as compliance and security?",
      "options": [
        "Community cloud",
        "Public cloud",
        "Private cloud",
        "Hybrid cloud"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Community clouds are shared among organizations with similar requirements, balancing cost and compliance. Public clouds serve multiple unrelated users. Private clouds offer dedicated resources. Hybrid clouds combine public and private elements.",
      "examTip": "**Community cloud = Shared compliance focus.** Ideal for sectors like healthcare or finance."
    },
    {
      "id": 49,
      "question": "Which wireless standard operates exclusively in the 5GHz band and supports MU-MIMO for multiple simultaneous data streams?",
      "options": [
        "802.11ac",
        "802.11n",
        "802.11g",
        "802.11b"
      ],
      "correctAnswerIndex": 0,
      "explanation": "802.11ac operates in the 5GHz band and supports MU-MIMO for improved performance. 802.11n supports 2.4GHz and 5GHz but with lower throughput. 802.11g and 802.11b are older, slower standards using 2.4GHz.",
      "examTip": "**802.11ac = 5GHz + MU-MIMO.** Best for high-performance wireless networks."
    },
    {
      "id": 50,
      "question": "Which protocol uses port 53 and is essential for resolving hostnames to IP addresses on a network?",
      "options": [
        "DNS",
        "DHCP",
        "NTP",
        "SSH"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DNS (Domain Name System) uses port 53 for both TCP and UDP to resolve hostnames. DHCP assigns IP configurations. NTP synchronizes clocks. SSH secures remote connections.",
      "examTip": "**DNS = Internet’s phonebook.** Always check DNS first when experiencing name resolution issues."
    },
    {
      "id": 51,
      "question": "Which security concept ensures that users can only access the minimum resources necessary to perform their job functions?",
      "options": [
        "Principle of least privilege",
        "Role-based access control (RBAC)",
        "Separation of duties",
        "Single sign-on (SSO)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The principle of least privilege restricts users to only necessary resources. RBAC assigns permissions based on roles. Separation of duties prevents fraud by dividing responsibilities. SSO allows access to multiple systems with one login but doesn’t limit permissions.",
      "examTip": "**Least privilege = Minimize access, minimize risk.** Key for reducing attack surfaces."
    },
    {
      "id": 52,
      "question": "Which protocol is used for secure file transfers and runs over SSH to encrypt data during transmission?",
      "options": [
        "SFTP",
        "FTP",
        "TFTP",
        "HTTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SFTP (SSH File Transfer Protocol) uses SSH (port 22) for secure file transfers. FTP is unencrypted. TFTP is a simple, unsecured protocol. HTTP serves web pages but doesn’t handle file transfers securely.",
      "examTip": "**SFTP = Secure file transfers.** Always prefer SFTP for sensitive data exchanges."
    },
    {
      "id": 53,
      "question": "Which BGP attribute is MOST effective for influencing outbound traffic in an enterprise network with multiple ISPs?",
      "options": [
        "Local preference",
        "AS path",
        "MED",
        "Next-hop"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Local preference influences outbound routing decisions in BGP, with higher values being preferred. AS path influences inbound routing. MED (Multi-Exit Discriminator) affects how external peers select paths into an AS. Next-hop specifies the next router but doesn’t influence outbound decisions.",
      "examTip": "**Local preference = Outbound traffic control.** Use for efficient multi-ISP traffic management."
    },
    {
      "id": 54,
      "question": "Which technology allows wireless clients to roam seamlessly between access points without losing connection?",
      "options": [
        "Fast BSS Transition (802.11r)",
        "Band steering",
        "MU-MIMO",
        "Beamforming"
      ],
      "correctAnswerIndex": 0,
      "explanation": "802.11r (Fast BSS Transition) enables rapid handoffs between access points without dropping connections. Band steering optimizes frequency selection. MU-MIMO allows multi-client communication. Beamforming directs wireless signals for better performance.",
      "examTip": "**802.11r = Seamless roaming.** Essential for VoIP and real-time applications on Wi-Fi networks."
    },
    {
      "id": 55,
      "question": "Which network tool helps detect physical layer issues such as cable breaks and attenuation in fiber optic cables?",
      "options": [
        "OTDR (Optical Time Domain Reflectometer)",
        "Toner probe",
        "Cable certifier",
        "Light meter"
      ],
      "correctAnswerIndex": 0,
      "explanation": "OTDR tests fiber optic cables for breaks and signal loss by measuring reflections. Toner probes locate copper cables. Cable certifiers ensure cables meet standards. Light meters measure optical power but don’t detect breaks.",
      "examTip": "**OTDR = Fiber troubleshooting hero.** Essential for pinpointing faults in optical networks."
    },
    {
      "id": 56,
      "question": "Which protocol allows dynamic routing updates to be securely transmitted between routers within an autonomous system?",
      "options": [
        "OSPF",
        "BGP",
        "RIP",
        "EIGRP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "OSPF (Open Shortest Path First) provides secure, efficient dynamic routing within an autonomous system. BGP handles inter-AS routing. RIP is less secure and slower. EIGRP is Cisco-proprietary.",
      "examTip": "**OSPF = Secure internal routing.** The enterprise standard for fast-converging, link-state routing."
    },
    {
      "id": 57,
      "question": "Which security method is MOST effective in preventing unauthorized devices from connecting to a corporate wireless network?",
      "options": [
        "WPA3-Enterprise with 802.1X authentication",
        "WPA2-Personal with PSK",
        "MAC address filtering",
        "SSID hiding"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3-Enterprise with 802.1X provides strong authentication via RADIUS, preventing unauthorized access. WPA2-Personal uses a shared key, which can be compromised. MAC filtering and SSID hiding are easily bypassed by attackers.",
      "examTip": "**WPA3-Enterprise + 802.1X = Gold standard Wi-Fi security.** Always implement for enterprise environments."
    },
    {
      "id": 58,
      "question": "Which dynamic routing protocol is commonly used by ISPs for exchanging routing information between autonomous systems on the internet?",
      "options": [
        "BGP",
        "EIGRP",
        "OSPF",
        "RIP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BGP (Border Gateway Protocol) is the standard for routing between autonomous systems on the internet. EIGRP is Cisco-proprietary. OSPF is for internal routing. RIP is outdated for internet-scale routing.",
      "examTip": "**BGP = Internet’s routing backbone.** Handles large-scale routing between ISPs and enterprises."
    },
    {
      "id": 59,
      "question": "Which component of a secure network architecture ensures that sensitive devices are separated from other parts of the network, typically using firewall rules?",
      "options": [
        "DMZ (Demilitarized Zone)",
        "VLAN",
        "Subinterface",
        "Proxy server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A DMZ places public-facing services in a segregated zone, limiting access to internal networks. VLANs segment at Layer 2. Subinterfaces logically divide interfaces. Proxy servers manage client requests but don’t isolate network segments.",
      "examTip": "**DMZ = Buffer zone.** Place public services here to protect internal networks from external threats."
    },
    {
      "id": 60,
      "question": "Which protocol ensures secure access to remote network devices via an encrypted command-line interface over port 22?",
      "options": [
        "SSH",
        "Telnet",
        "RDP",
        "SNMPv3"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH (Secure Shell) uses port 22 for encrypted command-line access. Telnet is unencrypted. RDP provides remote desktop access. SNMPv3 manages devices but isn’t used for direct device access.",
      "examTip": "**SSH = Secure CLI access.** Always prefer SSH over Telnet for secure remote management."
    },
    {
      "id": 61,
      "question": "A network engineer needs to prevent ARP spoofing attacks on a Layer 2 network. Which solution BEST mitigates this risk?",
      "options": [
        "Dynamic ARP inspection (DAI)",
        "Port security with MAC filtering",
        "Spanning Tree Protocol (STP)",
        "VLAN segmentation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Dynamic ARP Inspection (DAI) validates ARP packets against trusted sources, preventing ARP spoofing attacks. Port security and MAC filtering prevent unauthorized device connections but don’t validate ARP traffic. STP prevents loops, and VLANs provide segmentation but don’t secure ARP processes.",
      "examTip": "**DAI = ARP spoofing defense.** Always enable DAI on switches to secure Layer 2 ARP traffic."
    },
    {
      "id": 62,
      "question": "Which WAN technology offers connectionless packet-switched transport with variable packet delivery times, suitable for bursty data traffic?",
      "options": [
        "Frame Relay",
        "ISDN",
        "T1 line",
        "Leased line"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Frame Relay is a connectionless WAN technology suitable for bursty data with variable delivery times. ISDN provides circuit-switched services. T1 and leased lines offer dedicated, consistent bandwidth but lack the flexibility of Frame Relay.",
      "examTip": "**Frame Relay = Bursty traffic solution.** Best for cost-effective, scalable WAN needs."
    },
    {
      "id": 63,
      "question": "An organization requires that all remote users access internal applications securely using their web browsers without installing VPN clients. Which solution BEST meets this requirement?",
      "options": [
        "Clientless SSL VPN",
        "IPSec VPN with client software",
        "L2TP VPN",
        "GRE tunneling"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A clientless SSL VPN allows secure web-based access without additional client software. IPSec and L2TP VPNs typically require client installations. GRE provides tunneling but without encryption.",
      "examTip": "**Clientless SSL VPN = Browser-based secure access.** Ideal for remote users without client installations."
    },
    {
      "id": 64,
      "question": "Which IPv6 transition technology enables IPv6 packets to be transmitted over an IPv4 network by encapsulating them within IPv4 headers, without requiring dual-stack configuration?",
      "options": [
        "6to4 tunneling",
        "NAT64",
        "ISATAP",
        "Dual stack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "6to4 tunneling encapsulates IPv6 traffic in IPv4 headers for cross-protocol transmission without dual-stack requirements. NAT64 translates between IPv6 and IPv4. ISATAP is used for intra-site communication. Dual stack runs both protocols simultaneously.",
      "examTip": "**6to4 = IPv6 over IPv4 bridge.** Perfect for incremental IPv6 adoption strategies."
    },
    {
      "id": 65,
      "question": "Which BGP attribute allows ISPs to influence inbound traffic from other autonomous systems by making one path appear shorter than others?",
      "options": [
        "AS path prepending",
        "Local preference",
        "MED (Multi-Exit Discriminator)",
        "Next-hop"
      ],
      "correctAnswerIndex": 0,
      "explanation": "AS path prepending artificially increases the AS path length to make a path less attractive, influencing inbound traffic. Local preference affects outbound path selection. MED influences the preferred entry point from neighboring ASes. Next-hop specifies the next router but doesn’t control path attractiveness.",
      "examTip": "**AS path prepending = Inbound traffic shaping.** Adjust the AS path to influence traffic flow from peers."
    },
    {
      "id": 66,
      "question": "A network administrator suspects a routing loop in the network. Which command-line tool would BEST help diagnose this issue by showing each hop along the path?",
      "options": [
        "traceroute",
        "ping",
        "netstat",
        "arp"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'traceroute' displays each hop along the packet's path, helping to identify routing loops. 'ping' checks basic connectivity. 'netstat' shows network connections, and 'arp' displays address resolution tables.",
      "examTip": "**traceroute = Routing loop detector.** Always use when traffic is stuck in cyclical paths."
    },
    {
      "id": 67,
      "question": "Which IPv6 address type is automatically assigned to an interface and used for communication between nodes on the same link, starting with FE80::?",
      "options": [
        "Link-local",
        "Global unicast",
        "Multicast",
        "Anycast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Link-local addresses (FE80::/10) are automatically assigned for communication within the same link. Global unicast addresses are publicly routable. Multicast addresses target groups of devices. Anycast delivers traffic to the nearest node in a group.",
      "examTip": "**FE80:: = Link-local.** Essential for neighbor discovery and local device communication."
    },
    {
      "id": 68,
      "question": "Which type of firewall inspects traffic at multiple layers of the OSI model and can detect application-specific threats?",
      "options": [
        "Next-generation firewall (NGFW)",
        "Packet-filtering firewall",
        "Stateful inspection firewall",
        "Proxy firewall"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Next-generation firewalls (NGFWs) inspect traffic at multiple OSI layers and detect application-level threats. Packet-filtering firewalls operate at lower layers without deep inspection. Stateful firewalls track connections but lack deep application analysis. Proxy firewalls focus on application-level traffic but may not cover lower-layer threats.",
      "examTip": "**NGFW = Multi-layer threat protection.** The modern standard for comprehensive network security."
    },
    {
      "id": 69,
      "question": "Which protocol uses UDP ports 161 and 162 and is commonly employed for network device monitoring and alerting?",
      "options": [
        "SNMP",
        "NTP",
        "LDAP",
        "TFTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SNMP (Simple Network Management Protocol) uses UDP port 161 for polling and port 162 for traps (alerts). NTP synchronizes time. LDAP manages directory services. TFTP provides basic file transfers.",
      "examTip": "**SNMP = Network monitoring essential.** Port 161 = Queries, Port 162 = Alerts."
    },
    {
      "id": 70,
      "question": "Which wireless feature allows a device to switch seamlessly between access points without interrupting connectivity, especially important for VoIP applications?",
      "options": [
        "802.11r (Fast BSS Transition)",
        "Band steering",
        "Beamforming",
        "MU-MIMO"
      ],
      "correctAnswerIndex": 0,
      "explanation": "802.11r enables fast roaming between access points without connection loss, crucial for real-time applications like VoIP. Band steering optimizes frequency allocation. Beamforming enhances signal strength toward specific devices. MU-MIMO supports simultaneous multi-client communication.",
      "examTip": "**802.11r = Seamless Wi-Fi roaming.** Essential for mobile users needing uninterrupted connections."
    },
    {
      "id": 71,
      "question": "Which DNS record type specifies the authoritative name server for a domain?",
      "options": [
        "NS",
        "A",
        "MX",
        "CNAME"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NS (Name Server) records indicate the authoritative servers for a domain. A records map domains to IPv4 addresses. MX records define mail servers. CNAME records provide aliasing for domain names.",
      "examTip": "**NS record = Domain authority pointer.** Essential for proper DNS delegation."
    },
    {
      "id": 72,
      "question": "Which routing protocol is known for rapid convergence, uses a composite metric including bandwidth and delay, and is proprietary to Cisco?",
      "options": [
        "EIGRP",
        "OSPF",
        "BGP",
        "RIP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "EIGRP (Enhanced Interior Gateway Routing Protocol) is Cisco-proprietary, offering rapid convergence with metrics based on bandwidth, delay, and reliability. OSPF uses bandwidth-based cost. BGP manages inter-AS routing. RIP uses hop count and is slower.",
      "examTip": "**EIGRP = Cisco's rapid convergence protocol.** Ideal for Cisco-dominant networks needing fast adaptability."
    },
    {
      "id": 73,
      "question": "Which port is used by HTTPS for secure web traffic encryption?",
      "options": [
        "443",
        "80",
        "22",
        "25"
      ],
      "correctAnswerIndex": 0,
      "explanation": "HTTPS uses port 443 for secure web communications. Port 80 is for HTTP. Port 22 is for SSH. Port 25 is for SMTP email transmission.",
      "examTip": "**Port 443 = Secure web access.** Always ensure HTTPS for encrypted web transactions."
    },
    {
      "id": 74,
      "question": "Which cloud service model provides virtualized computing resources over the internet, allowing customers to run their own operating systems and applications?",
      "options": [
        "IaaS",
        "PaaS",
        "SaaS",
        "FaaS"
      ],
      "correctAnswerIndex": 0,
      "explanation": "IaaS (Infrastructure as a Service) offers virtualized resources like servers and storage. PaaS provides platforms for app development. SaaS delivers fully managed applications. FaaS provides serverless computing for executing functions.",
      "examTip": "**IaaS = Cloud infrastructure at your command.** Offers maximum flexibility for system architecture."
    },
    {
      "id": 75,
      "question": "A network engineer needs to ensure real-time network monitoring and alerting based on defined thresholds. Which solution would BEST fulfill this requirement?",
      "options": [
        "SIEM (Security Information and Event Management)",
        "Syslog server",
        "NetFlow analyzer",
        "Packet sniffer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SIEM solutions provide real-time monitoring, correlation, and alerting based on security and performance events. Syslog servers collect logs without advanced analysis. NetFlow analyzers focus on traffic patterns. Packet sniffers analyze traffic details but lack real-time alerting.",
      "examTip": "**SIEM = Proactive monitoring and alerts.** Essential for security and compliance-focused environments."
    },
    {
      "id": 76,
      "question": "Which wireless standard operates in the 6GHz frequency band and supports high throughput with low latency, enhancing dense network environments?",
      "options": [
        "802.11ax (Wi-Fi 6E)",
        "802.11ac",
        "802.11n",
        "802.11g"
      ],
      "correctAnswerIndex": 0,
      "explanation": "802.11ax (Wi-Fi 6E) extends Wi-Fi 6 capabilities into the 6GHz band, offering more bandwidth and less interference. 802.11ac operates in 5GHz. 802.11n supports 2.4GHz and 5GHz. 802.11g uses 2.4GHz with lower speeds.",
      "examTip": "**Wi-Fi 6E = 6GHz performance boost.** Ideal for modern, high-density wireless deployments."
    },
    {
      "id": 77,
      "question": "Which high-availability solution allows two routers to share a virtual IP address, providing failover capabilities if one router fails?",
      "options": [
        "VRRP",
        "HSRP",
        "GLBP",
        "CARP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "VRRP (Virtual Router Redundancy Protocol) provides failover by sharing a virtual IP. HSRP is Cisco-proprietary. GLBP offers load balancing with redundancy. CARP is an open-source alternative to VRRP and HSRP.",
      "examTip": "**VRRP = Vendor-neutral router redundancy.** Ensures gateway availability without proprietary limitations."
    },
    {
      "id": 78,
      "question": "Which technique improves wireless performance by steering capable devices to the 5GHz band, reducing congestion on the 2.4GHz band?",
      "options": [
        "Band steering",
        "Beamforming",
        "MU-MIMO",
        "Roaming"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Band steering shifts devices to less congested 5GHz channels, improving performance. Beamforming directs signals toward devices. MU-MIMO allows simultaneous data streams. Roaming ensures seamless AP switching but doesn’t optimize frequency usage.",
      "examTip": "**Band steering = Load balancing for Wi-Fi.** Enhances performance by leveraging higher-frequency bands."
    },
    {
      "id": 79,
      "question": "Which routing protocol supports both IPv4 and IPv6, is open-standard, and uses a hierarchical design with areas to optimize routing?",
      "options": [
        "OSPFv3",
        "EIGRP",
        "BGP",
        "RIPng"
      ],
      "correctAnswerIndex": 0,
      "explanation": "OSPFv3 is the IPv6-capable version of OSPF, supporting hierarchical area-based routing. EIGRP is Cisco-proprietary. BGP manages inter-AS routing. RIPng is for IPv6 but lacks advanced hierarchical design.",
      "examTip": "**OSPFv3 = Scalable IPv6 routing.** The preferred open-standard protocol for large IPv6 networks."
    },
    {
      "id": 80,
      "question": "Which type of IPv6 address is similar to IPv4 private addresses and is used for internal communication within an organization?",
      "options": [
        "Unique local address (ULA)",
        "Global unicast address",
        "Link-local address",
        "Multicast address"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Unique local addresses (ULA) in IPv6 are equivalent to IPv4 private addresses, intended for internal use. Global unicast addresses are publicly routable. Link-local addresses are for local link communications. Multicast addresses send data to multiple recipients.",
      "examTip": "**ULA = IPv6 private addressing.** Ideal for internal communications without internet routing."
    },
    {
      "id": 81,
      "question": "A network administrator needs to ensure that critical VoIP traffic receives higher priority across the network to prevent latency and jitter. Which configuration BEST achieves this goal?",
      "options": [
        "Apply QoS policies with traffic classification and prioritization.",
        "Increase overall bandwidth for all network segments.",
        "Deploy separate physical networks for VoIP and data traffic.",
        "Implement VLANs without QoS configuration."
      ],
      "correctAnswerIndex": 0,
      "explanation": "QoS (Quality of Service) policies ensure that latency-sensitive traffic like VoIP receives priority, minimizing jitter and delays. Increasing bandwidth may not address prioritization. Separate physical networks are costly and unnecessary. VLANs alone segment traffic but do not prioritize it.",
      "examTip": "**QoS = Priority for real-time traffic.** Always implement QoS for applications like VoIP and video conferencing."
    },
    {
      "id": 82,
      "question": "Which IPv6 transition technology allows IPv6 hosts to communicate with IPv4 hosts by translating IPv6 packets into IPv4 packets?",
      "options": [
        "NAT64",
        "6to4 tunneling",
        "Dual stack",
        "ISATAP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NAT64 translates IPv6 packets into IPv4, enabling communication between IPv6-only and IPv4-only hosts. 6to4 tunneling encapsulates IPv6 over IPv4 networks but doesn’t translate. Dual stack runs both protocols side by side. ISATAP provides IPv6 connectivity within an IPv4 network but without translation.",
      "examTip": "**NAT64 = IPv6-IPv4 translator.** Essential for cross-protocol communication during transition phases."
    },
    {
      "id": 83,
      "question": "Which protocol provides dynamic failover for routers by electing an active and standby router, ensuring minimal downtime if the active router fails?",
      "options": [
        "HSRP",
        "VRRP",
        "GLBP",
        "BGP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "HSRP (Hot Standby Router Protocol) provides dynamic failover by electing active and standby routers. VRRP is a similar, open-standard alternative. GLBP offers both load balancing and redundancy. BGP is a routing protocol for inter-domain path selection, not failover at the local gateway level.",
      "examTip": "**HSRP = Gateway redundancy with minimal downtime.** Prefer in Cisco environments requiring high availability."
    },
    {
      "id": 84,
      "question": "Which security solution detects unauthorized attempts to access network resources by analyzing traffic patterns and signatures but does NOT actively block the traffic?",
      "options": [
        "IDS (Intrusion Detection System)",
        "IPS (Intrusion Prevention System)",
        "Firewall",
        "UTM (Unified Threat Management)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An IDS monitors and alerts on malicious traffic but does not block it. IPS can detect and block malicious traffic. Firewalls control traffic based on defined rules. UTM appliances combine multiple security functions, including firewall, IPS, and antivirus.",
      "examTip": "**IDS = Detect, not block.** Use alongside active defenses like IPS for comprehensive protection."
    },
    {
      "id": 85,
      "question": "Which routing protocol supports policy-based routing, uses TCP for reliable delivery, and is commonly used by ISPs for inter-domain routing?",
      "options": [
        "BGP",
        "OSPF",
        "EIGRP",
        "RIP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BGP (Border Gateway Protocol) uses TCP port 179, enabling policy-based routing and is essential for inter-domain routing across the internet. OSPF and EIGRP are internal routing protocols. RIP uses hop count and lacks the scalability required for internet routing.",
      "examTip": "**BGP = Policy-based global routing.** The backbone protocol for internet routing decisions."
    },
    {
      "id": 86,
      "question": "A technician needs to troubleshoot intermittent packet loss between two network nodes. Which tool provides hop-by-hop latency and packet loss information along the network path?",
      "options": [
        "traceroute",
        "ping",
        "tcpdump",
        "ipconfig"
      ],
      "correctAnswerIndex": 0,
      "explanation": "traceroute shows each hop along the network path, including latency information, which helps pinpoint where packet loss occurs. ping checks connectivity but not intermediate hops. tcpdump captures packet data for deeper analysis. ipconfig shows local interface configurations.",
      "examTip": "**traceroute = End-to-end path visibility.** Best for identifying latency and loss across network segments."
    },
    {
      "id": 87,
      "question": "Which wireless security protocol provides the most robust encryption and protects against dictionary attacks, making it the BEST choice for modern enterprise networks?",
      "options": [
        "WPA3",
        "WPA2",
        "WEP",
        "TKIP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3 uses Simultaneous Authentication of Equals (SAE) for robust encryption and improved protection against dictionary attacks. WPA2 is secure but lacks WPA3’s enhancements. WEP and TKIP are outdated and vulnerable to attacks.",
      "examTip": "**WPA3 = Modern Wi-Fi security standard.** Always choose WPA3 for new enterprise deployments."
    },
    {
      "id": 88,
      "question": "Which component of a data center network topology connects each leaf switch to every spine switch, ensuring predictable latency and high bandwidth?",
      "options": [
        "Spine-and-leaf architecture",
        "Star topology",
        "Full mesh topology",
        "Ring topology"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The spine-and-leaf architecture provides predictable latency and high bandwidth by connecting each leaf switch to every spine switch. Star topologies rely on a central switch. Full mesh provides maximum redundancy but at higher cost. Ring topologies can suffer from single points of failure.",
      "examTip": "**Spine-and-leaf = Scalable DC performance.** Ideal for data centers needing predictable latency and throughput."
    },
    {
      "id": 89,
      "question": "Which type of address is assigned automatically in IPv6 for communication on a single link and is used for operations such as neighbor discovery?",
      "options": [
        "Link-local",
        "Global unicast",
        "Unique local",
        "Anycast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Link-local addresses (starting with FE80::) are automatically assigned for communication within a local link, essential for functions like neighbor discovery. Global unicast addresses are publicly routable. Unique local addresses are private, internal-use equivalents. Anycast addresses route to the nearest node in a group.",
      "examTip": "**FE80:: = Link-local.** Essential for local IPv6 functions and neighbor discovery."
    },
    {
      "id": 90,
      "question": "A network engineer is designing a redundant network topology with minimal cabling. Which topology should be implemented to ensure redundancy while keeping cabling costs low?",
      "options": [
        "Ring topology",
        "Full mesh topology",
        "Star topology",
        "Bus topology"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A ring topology provides redundancy with fewer cables than a full mesh. A full mesh offers complete redundancy but is costly. Star topologies depend on a central node, creating a single point of failure. Bus topologies lack redundancy entirely.",
      "examTip": "**Ring = Balanced redundancy and cost.** Suitable when limited cabling is a priority."
    },
    {
      "id": 91,
      "question": "Which protocol uses port 5060 for unencrypted signaling and is essential for establishing and managing VoIP calls?",
      "options": [
        "SIP",
        "RTP",
        "H.323",
        "MGCP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SIP (Session Initiation Protocol) uses port 5060 for unencrypted signaling and port 5061 for encrypted signaling. RTP handles real-time media streams. H.323 is an older VoIP protocol. MGCP manages media gateways but doesn’t handle call initiation directly.",
      "examTip": "**SIP = VoIP call signaling.** Always pair with TLS (port 5061) for secure communications."
    },
    {
      "id": 92,
      "question": "Which IPv6 address type provides one-to-nearest routing among a group of potential receivers, enhancing performance for services like DNS and CDN?",
      "options": [
        "Anycast",
        "Multicast",
        "Global unicast",
        "Link-local"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Anycast addresses route traffic to the nearest node in a group, improving performance for services like DNS and CDNs. Multicast addresses deliver to multiple recipients. Global unicast is similar to IPv4 public addressing. Link-local addresses serve local communications.",
      "examTip": "**Anycast = Nearest-node delivery.** Essential for load balancing and high-availability services."
    },
    {
      "id": 93,
      "question": "A company needs to ensure that its website can handle large surges in traffic without impacting performance. Which solution should be implemented?",
      "options": [
        "Load balancer",
        "Proxy server",
        "Firewall",
        "Router with QoS"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Load balancers distribute incoming traffic across multiple servers, ensuring scalability and high availability. Proxy servers manage client requests but don’t distribute load. Firewalls secure networks but don’t balance traffic. Routers with QoS prioritize traffic but don’t provide load distribution.",
      "examTip": "**Load balancer = Scalable web performance.** Critical for maintaining availability during traffic surges."
    },
    {
      "id": 94,
      "question": "Which tool provides visibility into traffic patterns by collecting and analyzing flow data from network devices, helping with capacity planning and troubleshooting?",
      "options": [
        "NetFlow analyzer",
        "SIEM system",
        "Packet sniffer",
        "Syslog server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NetFlow analyzers collect flow data, providing insights into traffic patterns and aiding in capacity planning. SIEM systems correlate security events. Packet sniffers capture detailed traffic but aren’t optimized for high-level traffic analysis. Syslog servers collect logs without traffic pattern analysis.",
      "examTip": "**NetFlow = Traffic pattern insight.** Essential for proactive network management and capacity planning."
    },
    {
      "id": 95,
      "question": "Which BGP attribute can be adjusted to influence outbound routing decisions by specifying preferred exit points from an autonomous system?",
      "options": [
        "Local preference",
        "AS path",
        "MED",
        "Weight"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Local preference influences outbound routing within an AS, with higher values being preferred. AS path affects inbound traffic decisions. MED influences how external peers select entry points. Weight is Cisco-specific and affects route selection locally, not globally.",
      "examTip": "**Local preference = Outbound path control.** Adjust for optimal exit path selection in multi-homed environments."
    },
    {
      "id": 96,
      "question": "Which protocol ensures time synchronization across network devices with high accuracy, often used in financial trading systems and telecommunications?",
      "options": [
        "PTP (Precision Time Protocol)",
        "NTP",
        "SNMP",
        "Syslog"
      ],
      "correctAnswerIndex": 0,
      "explanation": "PTP (IEEE 1588) provides sub-microsecond accuracy, ideal for time-sensitive applications. NTP offers millisecond-level synchronization suitable for general purposes. SNMP manages network devices but doesn’t synchronize time. Syslog logs events but isn’t a timing protocol.",
      "examTip": "**PTP = Precision timing.** Critical for environments where timing accuracy is essential, like trading systems."
    },
    {
      "id": 97,
      "question": "Which technique improves wireless network performance by directing the signal specifically toward a client device rather than broadcasting it equally in all directions?",
      "options": [
        "Beamforming",
        "MU-MIMO",
        "Band steering",
        "Roaming"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Beamforming focuses the wireless signal toward a client device, enhancing speed and reliability. MU-MIMO enables simultaneous transmissions to multiple clients. Band steering directs clients to optimal frequency bands. Roaming allows seamless handoffs between access points.",
      "examTip": "**Beamforming = Focused wireless performance.** Boosts signal strength and reduces interference."
    },
    {
      "id": 98,
      "question": "Which component is typically located at the network edge, providing routing, NAT, and firewall services for an enterprise network?",
      "options": [
        "Unified Threat Management (UTM) appliance",
        "Core switch",
        "Access point",
        "Repeater"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A UTM appliance combines routing, NAT, firewall, and other security services at the network edge. Core switches handle high-speed data switching in the core network. Access points provide wireless connectivity. Repeaters extend network signals without security functions.",
      "examTip": "**UTM = All-in-one edge protection.** Ideal for simplifying network edge management while enhancing security."
    },
    {
      "id": 99,
      "question": "Which protocol allows secure command-line access to network devices by encrypting both authentication credentials and session data?",
      "options": [
        "SSH",
        "Telnet",
        "SNMPv2",
        "HTTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH (Secure Shell) encrypts both authentication credentials and session data, providing secure command-line access. Telnet transmits data in plaintext. SNMPv2 lacks encryption unless upgraded to SNMPv3. HTTP is unencrypted and unsuitable for secure device access.",
      "examTip": "**SSH = Secure CLI management.** Always use SSH instead of Telnet for secure remote administration."
    },
    {
      "id": 100,
      "question": "Which cloud deployment model allows businesses to use a combination of public and private clouds, offering flexibility in distributing workloads based on security and performance requirements?",
      "options": [
        "Hybrid cloud",
        "Private cloud",
        "Public cloud",
        "Community cloud"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Hybrid clouds combine public and private cloud elements, offering flexibility for workload distribution. Private clouds are dedicated to a single organization. Public clouds serve multiple users without dedicated resources. Community clouds cater to organizations with shared concerns.",
      "examTip": "**Hybrid cloud = Flexible cloud strategy.** Balances cost, performance, and security needs."
    }
  ]
});   
