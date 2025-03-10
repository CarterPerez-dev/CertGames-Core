db.tests.insertOne({
  "category": "nplus",
  "testId": 5,
  "testName": "CompTIA Network+ (N10-009) Practice Test #5 (Intermediate)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A network engineer is troubleshooting why two VLANs on the same switch cannot communicate. The VLANs are configured correctly, and the devices have appropriate IP addresses. Which of the following is the MOST likely cause?",
      "options": [
        "Missing Layer 3 interface for inter-VLAN routing",
        "Trunk port misconfiguration on the switch",
        "Incorrect subnet mask on one of the VLANs",
        "Disabled Spanning Tree Protocol (STP)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Inter-VLAN communication requires a Layer 3 device, such as a router or a Layer 3 switch with an SVI (Switch Virtual Interface). Without it, devices in separate VLANs cannot communicate. Trunk ports are needed between switches, not for communication on the same switch. Incorrect subnet masks would prevent communication within the same subnet but would not block VLAN-to-VLAN traffic if routing existed. STP prevents loops but does not affect inter-VLAN routing.",
      "examTip": "**Inter-VLAN = Layer 3 routing required.** Ensure SVIs or router-on-a-stick are configured."
    },
    {
      "id": 2,
      "question": "An organization wants to ensure its cloud deployment allows for rapid scaling during peak usage while maintaining control over internal processes. Which cloud model BEST meets these requirements?",
      "options": [
        "Hybrid cloud",
        "Private cloud",
        "Public cloud",
        "Community cloud"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A hybrid cloud combines private infrastructure control with the scalability of public cloud services during peak demands. Private clouds lack the rapid scalability of public cloud resources. Public clouds provide scalability but less control. Community clouds cater to multiple organizations with shared interests but not necessarily rapid scalability.",
      "examTip": "**Hybrid cloud = Control + Scalability.** Ideal for fluctuating workloads needing flexibility."
    },
    {
      "id": 3,
      "question": "Which protocol should be implemented to ensure encrypted authentication and secure access when remotely managing network devices via command line?",
      "options": [
        "SSH",
        "Telnet",
        "SNMPv2",
        "HTTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH (Secure Shell) provides encrypted remote access over port 22, securing authentication and session data. Telnet transmits data in plaintext, making it insecure. SNMPv2 is used for device management but lacks encryption. HTTP provides unencrypted web access.",
      "examTip": "**SSH = Secure CLI access.** Always use SSH over Telnet for security."
    },
    {
      "id": 4,
      "question": "Which network topology offers the BEST redundancy and fault tolerance but is expensive to implement due to cabling costs?",
      "options": [
        "Full mesh",
        "Star",
        "Ring",
        "Bus"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A full mesh topology connects every node to every other node, providing the highest redundancy and fault tolerance. However, it’s costly due to the number of links required. Star topologies depend on a central device, ring topologies have limited redundancy, and bus topologies have a single point of failure.",
      "examTip": "**Full mesh = Max redundancy, max cost.** Reserved for critical, high-availability environments."
    },
    {
      "id": 5,
      "question": "Which IPv6 mechanism allows IPv6 traffic to be encapsulated within IPv4 packets for transmission across an IPv4 network?",
      "options": [
        "Tunneling",
        "NAT64",
        "Dual stack",
        "Anycast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Tunneling encapsulates IPv6 packets in IPv4 headers, enabling communication across IPv4 networks. NAT64 translates IPv6 addresses to IPv4. Dual stack runs both IPv4 and IPv6 simultaneously. Anycast delivers traffic to the nearest node.",
      "examTip": "**Tunneling = IPv6-over-IPv4 bridge.** Useful during phased IPv6 adoption."
    },
    {
      "id": 6,
      "question": "A user reports intermittent connectivity issues. The technician notices CRC errors on the interface. What is the FIRST action the technician should take?",
      "options": [
        "Replace the network cable.",
        "Check for duplex mismatches.",
        "Restart the network switch.",
        "Update the NIC driver."
      ],
      "correctAnswerIndex": 0,
      "explanation": "CRC errors typically indicate faulty cabling or interference. Replacing the cable is the simplest and fastest first step. Duplex mismatches cause late collisions, not CRC errors. Restarting the switch affects multiple users unnecessarily. NIC driver issues rarely cause CRC errors.",
      "examTip": "**CRC errors? Check the cable first.** Physical layer issues are the most common culprit."
    },
    {
      "id": 7,
      "question": "A network administrator is implementing QoS to prioritize VoIP traffic. Which technique would BEST ensure low latency for voice traffic?",
      "options": [
        "Traffic shaping",
        "Weighted Fair Queuing (WFQ)",
        "Link aggregation",
        "Port mirroring"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Traffic shaping manages bandwidth and ensures priority traffic, like VoIP, experiences minimal latency. WFQ distributes bandwidth fairly but may not prioritize VoIP sufficiently. Link aggregation increases total bandwidth but doesn’t guarantee traffic prioritization. Port mirroring duplicates traffic for monitoring purposes, not prioritization.",
      "examTip": "**QoS for VoIP = Traffic shaping.** Prioritize voice traffic for clear, delay-free calls."
    },
    {
      "id": 8,
      "question": "Which of the following technologies allows dynamic discovery of nearby devices on the same network and provides information about them?",
      "options": [
        "LLDP",
        "OSPF",
        "NTP",
        "BGP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "LLDP (Link Layer Discovery Protocol) allows network devices to discover each other and share information like identity and capabilities. OSPF is a routing protocol. NTP synchronizes time across devices. BGP handles routing between autonomous systems on the internet.",
      "examTip": "**LLDP = Network self-awareness.** Essential for mapping and managing large networks."
    },
    {
      "id": 9,
      "question": "A technician is setting up an IPsec VPN. Which protocol is used to establish a secure channel for key exchange?",
      "options": [
        "IKE",
        "ESP",
        "AH",
        "GRE"
      ],
      "correctAnswerIndex": 0,
      "explanation": "IKE (Internet Key Exchange) establishes a secure channel for key exchange in an IPsec VPN. ESP (Encapsulating Security Payload) provides encryption. AH (Authentication Header) ensures data integrity. GRE provides tunneling but lacks encryption.",
      "examTip": "**IKE = Key exchange king.** Essential for secure VPN handshakes."
    },
    {
      "id": 10,
      "question": "Which method would BEST prevent VLAN hopping attacks on a switch?",
      "options": [
        "Disabling unused ports and setting them to an unused VLAN",
        "Enabling port mirroring on all switch ports",
        "Using default VLANs for all access ports",
        "Enabling auto-negotiation on trunk ports"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Disabling unused ports and placing them in an unused VLAN prevents VLAN hopping by ensuring attackers cannot exploit inactive ports. Port mirroring is for traffic monitoring, not security. Using default VLANs can expose vulnerabilities. Auto-negotiation does not mitigate VLAN hopping risks.",
      "examTip": "**Prevent VLAN hopping = Disable unused ports + unused VLANs.** Security through proper segmentation."
    },
    {
      "id": 11,
      "question": "A network administrator is reviewing logs and notices a device attempting to access multiple internal resources it should not have access to. Which security mechanism would BEST prevent such activity?",
      "options": [
        "Access Control Lists (ACLs)",
        "Spanning Tree Protocol (STP)",
        "Port mirroring",
        "Load balancing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "ACLs enforce traffic control policies by permitting or denying traffic based on IP, port, or protocol, effectively preventing unauthorized access. STP prevents network loops. Port mirroring is for monitoring. Load balancing distributes traffic but does not provide access control.",
      "examTip": "**ACLs = Network traffic bouncer.** Only approved traffic gains access."
    },
    {
      "id": 12,
      "question": "Which IPv6 address type is assigned automatically to each interface for local communication and always begins with FE80::?",
      "options": [
        "Link-local",
        "Global unicast",
        "Anycast",
        "Unique local"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Link-local addresses (starting with FE80::) are used for communication on the local segment and are automatically assigned. Global unicast addresses are routable on the internet. Anycast addresses route to the nearest node. Unique local addresses are similar to private IPv4 addresses.",
      "examTip": "**FE80:: = Link-local IPv6.** Local-only communication; no routing beyond the link."
    },
    {
      "id": 13,
      "question": "Which wireless technology enables multiple clients to transmit data simultaneously, enhancing network performance in high-density environments?",
      "options": [
        "MU-MIMO",
        "Beamforming",
        "Band steering",
        "Roaming"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MU-MIMO (Multi-User, Multiple Input, Multiple Output) allows multiple devices to receive and transmit data at once, increasing efficiency. Beamforming directs signals toward specific devices. Band steering pushes devices to the optimal frequency. Roaming allows seamless AP switching.",
      "examTip": "**MU-MIMO = More users, more throughput.** Critical for high-density Wi-Fi networks."
    },
    {
      "id": 14,
      "question": "Which security concept ensures that sensitive data remains unaltered during transmission?",
      "options": [
        "Integrity",
        "Confidentiality",
        "Availability",
        "Authentication"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Integrity ensures that data is not tampered with during transmission. Confidentiality protects data from unauthorized access. Availability ensures data is accessible when needed. Authentication verifies the identity of users or devices.",
      "examTip": "**Integrity = Untouched data.** Think of it as tamper-proofing your data."
    },
    {
      "id": 15,
      "question": "Which protocol uses port 3389 to provide secure remote desktop access to Windows systems?",
      "options": [
        "RDP",
        "SSH",
        "Telnet",
        "VNC"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RDP (Remote Desktop Protocol) uses port 3389 for secure graphical access to Windows systems. SSH (port 22) provides secure CLI access. Telnet is insecure. VNC offers graphical access but typically lacks encryption by default.",
      "examTip": "**RDP = Remote Desktop for Windows.** Port 3389 for graphical remote management."
    },
    {
      "id": 16,
      "question": "Which tool would BEST help a network technician identify bandwidth usage and traffic patterns in real time?",
      "options": [
        "NetFlow analyzer",
        "Packet sniffer",
        "Cable tester",
        "Loopback plug"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NetFlow analyzers provide real-time insights into bandwidth usage and traffic flows. Packet sniffers capture individual packets for deeper analysis. Cable testers verify physical cabling. Loopback plugs test port functionality.",
      "examTip": "**NetFlow = Traffic insights.** Essential for bandwidth optimization and anomaly detection."
    },
    {
      "id": 17,
      "question": "Which technology allows multiple physical Ethernet ports to be combined into one logical connection for redundancy and increased throughput?",
      "options": [
        "Link aggregation",
        "Port mirroring",
        "Trunking",
        "Spanning Tree Protocol (STP)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Link aggregation combines multiple physical connections into a single logical one for higher throughput and redundancy. Port mirroring duplicates traffic for monitoring. Trunking carries multiple VLANs. STP prevents loops in redundant topologies.",
      "examTip": "**Link aggregation = Bandwidth + Redundancy.** Boost performance with failover protection."
    },
    {
      "id": 18,
      "question": "Which wireless encryption standard is currently the MOST secure for enterprise Wi-Fi networks?",
      "options": [
        "WPA3-Enterprise",
        "WPA2-Personal",
        "WPA-Personal",
        "WEP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3-Enterprise provides the strongest encryption and robust authentication for enterprise environments. WPA2-Personal is secure but lacks WPA3’s enhancements. WPA-Personal and WEP are outdated and vulnerable.",
      "examTip": "**WPA3-Enterprise = Top-tier Wi-Fi security.** Always choose for business-critical environments."
    },
    {
      "id": 19,
      "question": "Which tool would a technician use to determine the distance to a break in a fiber optic cable?",
      "options": [
        "OTDR (Optical Time Domain Reflectometer)",
        "TDR (Time Domain Reflectometer)",
        "Cable certifier",
        "Light meter"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An OTDR measures signal reflections in fiber optic cables, helping locate breaks. TDRs perform a similar function for copper cables. Cable certifiers validate wiring standards. Light meters measure signal strength but don’t locate breaks.",
      "examTip": "**OTDR = Fiber fault finder.** Pinpoint fiber breaks with precise distance measurements."
    },
    {
      "id": 20,
      "question": "Which protocol would a network engineer MOST likely use to securely synchronize time across all network devices?",
      "options": [
        "NTP with NTS",
        "SNMP",
        "RADIUS",
        "Syslog"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NTP with NTS (Network Time Security) ensures secure time synchronization. SNMP manages network devices. RADIUS handles authentication. Syslog collects event logs but doesn’t handle time sync.",
      "examTip": "**NTP + NTS = Secure time sync.** Accurate timestamps are critical for troubleshooting and security."
    },
    {
      "id": 21,
      "question": "A network administrator needs to ensure minimal downtime and maximum redundancy for critical WAN links. Which technology BEST achieves this objective?",
      "options": [
        "SD-WAN",
        "VRRP",
        "HSRP",
        "OSPF"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SD-WAN (Software-Defined WAN) provides intelligent path control, redundancy, and automatic failover across multiple WAN links, ensuring minimal downtime. VRRP and HSRP provide router redundancy but are limited to LAN-level failover. OSPF is a dynamic routing protocol but does not manage WAN redundancy directly.",
      "examTip": "**SD-WAN = Intelligent WAN resilience.** Ensures high availability with dynamic path optimization."
    },
    {
      "id": 22,
      "question": "A user reports slow access to cloud applications during peak hours. Network analysis shows high bandwidth utilization on the internet link. Which solution would BEST alleviate this problem?",
      "options": [
        "Implement QoS policies prioritizing cloud traffic.",
        "Upgrade the user's network interface card (NIC).",
        "Change the DNS server configuration.",
        "Replace the access switch with a Layer 3 switch."
      ],
      "correctAnswerIndex": 0,
      "explanation": "QoS (Quality of Service) prioritizes critical cloud application traffic, ensuring performance even during congestion. Upgrading the NIC affects only local performance. DNS changes resolve name resolution issues, not bandwidth contention. A Layer 3 switch helps with routing but not with internet bandwidth prioritization.",
      "examTip": "**QoS = Prioritize critical traffic.** Essential for ensuring cloud app performance during peak hours."
    },
    {
      "id": 23,
      "question": "Which IPv6 transition mechanism allows both IPv4 and IPv6 to operate simultaneously on the same network interface?",
      "options": [
        "Dual stack",
        "Tunneling",
        "NAT64",
        "6to4"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Dual stack enables both IPv4 and IPv6 to run concurrently, ensuring compatibility during the transition period. Tunneling encapsulates IPv6 in IPv4 packets. NAT64 translates IPv6 to IPv4. 6to4 provides automatic tunneling but requires IPv4 addresses.",
      "examTip": "**Dual stack = Seamless IPv6 migration.** Run both protocols without performance loss."
    },
    {
      "id": 24,
      "question": "Which security technique ensures that only devices with specific MAC addresses can connect to a wireless network?",
      "options": [
        "MAC filtering",
        "WPA3-Personal encryption",
        "SSID hiding",
        "Captive portal"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MAC filtering restricts network access to devices with specified MAC addresses. WPA3-Personal encrypts data but doesn't filter devices. SSID hiding only obscures the network name. Captive portals require user authentication but do not inherently filter by MAC.",
      "examTip": "**MAC filtering = Basic device access control.** Best combined with stronger encryption for security."
    },
    {
      "id": 25,
      "question": "A technician needs to determine which physical switch port is connected to a specific server. Which command would MOST likely provide this information?",
      "options": [
        "show mac-address-table",
        "show interface status",
        "show running-config",
        "show ip route"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'show mac-address-table' displays the MAC addresses learned on each switch port, helping trace which port a device connects to. 'show interface status' gives port statuses but not MAC information. 'show running-config' shows current configurations. 'show ip route' displays routing tables, not Layer 2 connections.",
      "examTip": "**show mac-address-table = Find device location.** Essential for port mapping and troubleshooting."
    },
    {
      "id": 26,
      "question": "A company needs to prevent unauthorized DHCP servers from assigning IP addresses. Which security feature on a switch can BEST achieve this?",
      "options": [
        "DHCP snooping",
        "Port security",
        "Access control lists (ACLs)",
        "Dynamic ARP inspection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DHCP snooping filters unauthorized DHCP traffic by allowing only trusted ports to serve DHCP requests. Port security limits MAC addresses per port. ACLs filter traffic based on IP and port but not specifically DHCP. Dynamic ARP inspection prevents ARP spoofing, not unauthorized DHCP responses.",
      "examTip": "**DHCP snooping = Authorized IP assignments only.** Prevent rogue DHCP servers from causing disruptions."
    },
    {
      "id": 27,
      "question": "Which routing protocol uses a cost metric based on bandwidth to determine the shortest path and supports fast convergence?",
      "options": [
        "OSPF",
        "RIP",
        "EIGRP",
        "BGP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "OSPF (Open Shortest Path First) uses bandwidth as its cost metric, converges quickly, and scales well for large networks. RIP uses hop count, which is less efficient. EIGRP (Cisco proprietary) uses bandwidth and delay. BGP is used for internet routing, not internal path optimization.",
      "examTip": "**OSPF = Fast convergence + bandwidth-aware.** Ideal for large enterprise networks."
    },
    {
      "id": 28,
      "question": "Which tool would a technician use to analyze packet-level data to diagnose network latency and application performance issues?",
      "options": [
        "Wireshark",
        "Nmap",
        "Toner probe",
        "Cable tester"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Wireshark captures and analyzes packet-level data, helping diagnose latency and performance issues. Nmap scans for open ports. Toner probes trace cables. Cable testers check physical wiring integrity.",
      "examTip": "**Wireshark = Deep packet inspection.** Critical for advanced network troubleshooting."
    },
    {
      "id": 29,
      "question": "A network engineer is setting up redundancy for two core routers. Which protocol would allow them to share a virtual IP address for high availability?",
      "options": [
        "VRRP",
        "OSPF",
        "BGP",
        "HSRP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "VRRP (Virtual Router Redundancy Protocol) allows multiple routers to share a virtual IP, ensuring high availability. OSPF is a routing protocol but doesn't provide redundancy at the gateway level. BGP routes between autonomous systems. HSRP is similar but Cisco proprietary.",
      "examTip": "**VRRP = Gateway redundancy.** Ensures continuous network availability in case of router failure."
    },
    {
      "id": 30,
      "question": "Which protocol would be BEST to secure voice and video traffic transmitted over an IP network?",
      "options": [
        "SRTP",
        "SIP",
        "RTP",
        "H.323"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SRTP (Secure Real-time Transport Protocol) encrypts voice and video traffic, providing confidentiality and integrity. SIP initiates communication sessions but doesn't secure media. RTP carries media streams without encryption. H.323 is an older VoIP protocol without inherent encryption.",
      "examTip": "**SRTP = Secure media streams.** Encrypts VoIP and video traffic for privacy."
    },
    {
      "id": 31,
      "question": "Which wireless standard introduced the 6GHz frequency band, improving capacity and reducing congestion in high-density environments?",
      "options": [
        "802.11ax (Wi-Fi 6E)",
        "802.11ac",
        "802.11n",
        "802.11g"
      ],
      "correctAnswerIndex": 0,
      "explanation": "802.11ax (Wi-Fi 6E) supports the 6GHz band, providing additional capacity and reduced congestion. 802.11ac supports 5GHz. 802.11n supports 2.4GHz and 5GHz. 802.11g supports only 2.4GHz.",
      "examTip": "**Wi-Fi 6E = 6GHz for high-density areas.** Future-proof your wireless infrastructure."
    },
    {
      "id": 32,
      "question": "A user reports that they cannot access an external website by name, but they can access it by IP address. Which service is MOST likely misconfigured?",
      "options": [
        "DNS",
        "DHCP",
        "NAT",
        "SNMP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DNS (Domain Name System) resolves hostnames to IP addresses. If the user can access the site by IP but not by name, DNS issues are likely. DHCP assigns IP configurations. NAT translates IP addresses for external access. SNMP manages network devices.",
      "examTip": "**Hostname issues? Check DNS first.** Domain resolution problems are the usual suspects."
    },
    {
      "id": 33,
      "question": "Which topology provides the BEST balance of fault tolerance, scalability, and cost in a large data center network?",
      "options": [
        "Spine-and-leaf",
        "Full mesh",
        "Star",
        "Bus"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Spine-and-leaf topology provides predictable latency, redundancy, and scalability for modern data centers. Full mesh offers maximum redundancy but at a high cost. Star topologies have a single point of failure. Bus topologies lack redundancy and scalability.",
      "examTip": "**Spine-and-leaf = Modern data center gold standard.** Balances performance with scalability."
    },
    {
      "id": 34,
      "question": "Which type of firewall inspects traffic at all seven OSI layers and can make filtering decisions based on application context?",
      "options": [
        "Next-generation firewall (NGFW)",
        "Stateful firewall",
        "Packet-filtering firewall",
        "Proxy firewall"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NGFWs provide deep packet inspection, considering application context, user identity, and threat intelligence. Stateful firewalls track connections but lack deep application awareness. Packet-filtering firewalls only inspect headers. Proxy firewalls mediate requests but lack full OSI inspection.",
      "examTip": "**NGFW = Deep inspection, smarter protection.** Essential for modern threat prevention."
    },
    {
      "id": 35,
      "question": "A company is deploying a critical web application that requires both high availability and scalability. Which solution BEST meets these requirements?",
      "options": [
        "Load balancer with multiple web servers",
        "Single high-performance server with RAID 10",
        "Clustered firewall configuration",
        "Spine-and-leaf network architecture"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Load balancers distribute traffic across multiple web servers, ensuring high availability and scalability. A single high-performance server is a single point of failure. Clustered firewalls enhance security but don’t provide application scalability. Spine-and-leaf architecture supports network scalability but not web application load distribution.",
      "examTip": "**Load balancer = High availability + scalability.** Essential for mission-critical applications."
    },
    {
      "id": 36,
      "question": "Which IPv6 address type is used to communicate with all nodes on a local network segment and starts with FF02::1?",
      "options": [
        "Multicast",
        "Anycast",
        "Global unicast",
        "Link-local"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The FF02::1 multicast address reaches all nodes on the local link. Anycast delivers to the nearest node. Global unicast addresses are publicly routable. Link-local addresses (FE80::) are used for local communication but not for group messaging.",
      "examTip": "**FF02::1 = All nodes multicast.** Useful for service announcements on local links."
    },
    {
      "id": 37,
      "question": "Which technology ensures that network configuration changes are automatically deployed and consistent across multiple devices?",
      "options": [
        "Infrastructure as Code (IaC)",
        "Zero-touch provisioning (ZTP)",
        "Network Access Control (NAC)",
        "Dynamic Host Configuration Protocol (DHCP)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "IaC treats network configurations as code, ensuring consistency and repeatability. ZTP automates initial device provisioning. NAC manages device access based on policy. DHCP dynamically assigns IP configurations but doesn’t manage device configurations.",
      "examTip": "**IaC = Code your infrastructure.** Ensures rapid, consistent network deployment."
    },
    {
      "id": 38,
      "question": "Which protocol allows a user to securely access a remote network as if directly connected, encrypting all transmitted data?",
      "options": [
        "IPSec VPN",
        "SSH",
        "SSL",
        "SFTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "IPSec VPN creates secure tunnels for remote network access, encrypting all transmitted data. SSH provides secure remote shell access. SSL secures web traffic. SFTP secures file transfers.",
      "examTip": "**IPSec VPN = Remote access, secure tunnel.** The gold standard for encrypted remote connectivity."
    },
    {
      "id": 39,
      "question": "A network engineer needs to ensure that DNS traffic is encrypted and protected from eavesdropping. Which protocol BEST achieves this goal?",
      "options": [
        "DoH (DNS over HTTPS)",
        "DNSSEC",
        "TLS",
        "NTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DoH encrypts DNS queries using HTTPS, preventing eavesdropping. DNSSEC ensures DNS integrity but not encryption. TLS provides encryption for various protocols but not DNS specifically. NTP synchronizes time across devices.",
      "examTip": "**DoH = Private DNS lookups.** Encrypt DNS queries to prevent spying."
    },
    {
      "id": 40,
      "question": "Which tool would BEST help a network technician identify physical layer issues, such as cable breaks or excessive attenuation in fiber optic cables?",
      "options": [
        "OTDR (Optical Time Domain Reflectometer)",
        "Cable certifier",
        "Toner probe",
        "Light meter"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An OTDR detects breaks and attenuation in fiber optic cables by analyzing signal reflections. Cable certifiers ensure cabling meets standards. Toner probes trace cables. Light meters measure signal strength but don’t locate breaks.",
      "examTip": "**OTDR = Fiber optic troubleshooting hero.** Pinpoint cable issues with precise measurements."
    },
    {
      "id": 41,
      "question": "A network administrator needs to prevent a Layer 2 switch from being overwhelmed by broadcast traffic. Which technology should be implemented?",
      "options": [
        "VLAN segmentation",
        "Spanning Tree Protocol (STP)",
        "Access Control Lists (ACLs)",
        "Link aggregation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "STP (Spanning Tree Protocol) prevents broadcast storms by blocking redundant paths that could cause loops. VLAN segmentation isolates broadcast domains but doesn't prevent loops. ACLs control traffic but do not address Layer 2 broadcast issues. Link aggregation combines ports for bandwidth but doesn't prevent loops.",
      "examTip": "**STP = Loop prevention + broadcast control.** Always enable STP in redundant switch topologies."
    },
    {
      "id": 42,
      "question": "Which protocol is responsible for translating private IP addresses to public IP addresses for internet access?",
      "options": [
        "NAT",
        "DNS",
        "DHCP",
        "SNMP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NAT (Network Address Translation) translates private IP addresses to public ones, enabling internet access. DNS resolves domain names to IP addresses. DHCP assigns IP configurations. SNMP manages and monitors network devices but doesn’t handle address translation.",
      "examTip": "**NAT = Private-to-public translator.** Essential for private networks accessing the internet."
    },
    {
      "id": 43,
      "question": "Which cloud deployment model combines on-premises infrastructure with public cloud services, allowing data and applications to be shared between them?",
      "options": [
        "Hybrid cloud",
        "Public cloud",
        "Private cloud",
        "Community cloud"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A hybrid cloud combines private (on-premises) and public cloud resources, offering flexibility and scalability. Public clouds are shared and fully managed externally. Private clouds are solely for one organization. Community clouds are shared by organizations with similar goals.",
      "examTip": "**Hybrid cloud = Flexibility + control.** Ideal for balancing sensitive data control with public cloud scalability."
    },
    {
      "id": 44,
      "question": "A network engineer wants to securely transmit login credentials over an unsecured network. Which protocol should be used?",
      "options": [
        "SSH",
        "Telnet",
        "HTTP",
        "FTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH (Secure Shell) provides encrypted communication, making it ideal for secure remote logins. Telnet, HTTP, and FTP transmit data in plaintext, making them insecure for credential transmission.",
      "examTip": "**SSH = Secure command-line access.** Always replace Telnet with SSH for secure authentication."
    },
    {
      "id": 45,
      "question": "Which type of IPv6 address is equivalent to a private IPv4 address and is used for local communications within an organization?",
      "options": [
        "Unique local",
        "Global unicast",
        "Link-local",
        "Anycast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Unique local addresses (ULA) are used for private, internal IPv6 networks, similar to private IPv4 addresses. Global unicast addresses are publicly routable. Link-local addresses are only valid within a single link. Anycast delivers data to the nearest node in a group.",
      "examTip": "**Unique local = Private IPv6.** Think of it as IPv6's version of RFC1918 addresses."
    },
    {
      "id": 46,
      "question": "Which wireless feature allows clients to automatically connect to the strongest available access point as they move between coverage areas?",
      "options": [
        "Roaming",
        "Band steering",
        "MU-MIMO",
        "Beamforming"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Roaming enables seamless connectivity by allowing clients to switch between access points without manual intervention. Band steering pushes devices to optimal frequency bands. MU-MIMO allows simultaneous multi-client communication. Beamforming focuses signals towards specific devices.",
      "examTip": "**Roaming = Seamless connectivity.** Critical for mobile users moving between access points."
    },
    {
      "id": 47,
      "question": "Which protocol allows secure access to web applications over the internet by encrypting HTTP traffic?",
      "options": [
        "HTTPS",
        "HTTP",
        "SSH",
        "SFTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "HTTPS encrypts web traffic using TLS over port 443, securing data between clients and servers. HTTP transmits data in plaintext. SSH provides secure command-line access, and SFTP securely transfers files over SSH but doesn't handle web traffic.",
      "examTip": "**HTTPS = Secure web browsing.** Always use HTTPS to protect web communications."
    },
    {
      "id": 48,
      "question": "A company requires high availability for its web services. Which solution would BEST distribute client requests among multiple servers to achieve this?",
      "options": [
        "Load balancer",
        "Proxy server",
        "Firewall cluster",
        "VRRP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Load balancers distribute client requests across multiple servers, ensuring high availability and fault tolerance. Proxy servers manage client requests but don't balance loads. Firewall clusters provide security redundancy. VRRP provides gateway redundancy, not load distribution.",
      "examTip": "**Load balancer = Distribute traffic, avoid overload.** Essential for scalable web applications."
    },
    {
      "id": 49,
      "question": "Which port is used by the Lightweight Directory Access Protocol (LDAP) for unencrypted communication?",
      "options": [
        "389",
        "636",
        "443",
        "22"
      ],
      "correctAnswerIndex": 0,
      "explanation": "LDAP uses port 389 for unencrypted communication. Port 636 is for LDAPS (secure LDAP). Port 443 is for HTTPS, and port 22 is for SSH.",
      "examTip": "**LDAP = Port 389 (unencrypted), LDAPS = Port 636 (encrypted).** Always prefer LDAPS for secure directory access."
    },
    {
      "id": 50,
      "question": "Which IPv6 feature allows a device to generate its own address without using a DHCP server, based on its MAC address?",
      "options": [
        "SLAAC",
        "NAT64",
        "Dual stack",
        "Tunneling"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SLAAC (Stateless Address Autoconfiguration) enables IPv6 devices to configure their own addresses using the network prefix and MAC address. NAT64 translates IPv6 to IPv4. Dual stack runs both protocols concurrently. Tunneling encapsulates IPv6 within IPv4 packets.",
      "examTip": "**SLAAC = Plug-and-play IPv6.** DHCP-free autoconfiguration for IPv6 networks."
    },
    {
      "id": 51,
      "question": "Which device would MOST likely be used to connect different network architectures, such as Ethernet and Fiber Channel?",
      "options": [
        "Gateway",
        "Router",
        "Switch",
        "Firewall"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Gateways connect networks using different protocols and architectures, performing protocol conversions if necessary. Routers connect networks but don’t typically perform protocol conversions. Switches operate at Layer 2 for traffic forwarding. Firewalls control network security but don’t bridge architectures.",
      "examTip": "**Gateway = Protocol translator.** Critical for heterogeneous network integration."
    },
    {
      "id": 52,
      "question": "A technician needs to test for end-to-end connectivity and measure response time between two network devices. Which command would BEST accomplish this?",
      "options": [
        "ping",
        "traceroute",
        "netstat",
        "nslookup"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'ping' tests connectivity and measures response time between two devices. 'traceroute' identifies the path taken but focuses on hop details. 'netstat' shows network connections and ports. 'nslookup' resolves DNS names to IP addresses.",
      "examTip": "**ping = Quick connectivity check.** First step in any network troubleshooting process."
    },
    {
      "id": 53,
      "question": "Which network protocol uses port 53 and is responsible for resolving hostnames to IP addresses?",
      "options": [
        "DNS",
        "DHCP",
        "NTP",
        "SNMP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DNS (Domain Name System) uses port 53 for both UDP and TCP traffic, translating hostnames to IP addresses. DHCP assigns IP configurations. NTP synchronizes network device time. SNMP manages and monitors network devices.",
      "examTip": "**DNS = Name to number resolver.** Always check DNS when facing hostname resolution issues."
    },
    {
      "id": 54,
      "question": "Which type of attack involves intercepting and potentially altering communication between two parties without their knowledge?",
      "options": [
        "Man-in-the-middle (MITM)",
        "Denial-of-service (DoS)",
        "Phishing",
        "Spoofing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MITM attacks intercept communication between two parties, potentially altering or stealing data. DoS attacks disrupt service availability. Phishing tricks users into revealing information. Spoofing involves impersonation but doesn’t necessarily intercept ongoing communication.",
      "examTip": "**MITM = Silent interception.** Use encryption (SSL/TLS) to prevent such attacks."
    },
    {
      "id": 55,
      "question": "Which type of cable should be used to directly connect two similar devices, such as switch-to-switch, without an intermediate device?",
      "options": [
        "Crossover cable",
        "Straight-through cable",
        "Fiber optic cable",
        "Coaxial cable"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Crossover cables connect similar devices by crossing the transmit and receive pairs. Straight-through cables connect different device types. Fiber optic cables are for high-speed data transfer over longer distances. Coaxial cables are typically used for broadband or older Ethernet implementations.",
      "examTip": "**Crossover cable = Like-to-like connection.** Many modern devices support auto-MDIX, eliminating the need for crossover cables."
    },
    {
      "id": 56,
      "question": "Which wireless encryption standard is currently considered the MOST secure for home networks?",
      "options": [
        "WPA3-Personal",
        "WPA2-Personal",
        "WPA-Personal",
        "WEP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3-Personal offers enhanced encryption and protection against brute-force attacks, making it the most secure option for home networks. WPA2-Personal is still secure but lacks WPA3’s enhancements. WPA-Personal and WEP are outdated and vulnerable.",
      "examTip": "**WPA3-Personal = Home Wi-Fi security leader.** Always use WPA3 when supported for optimal protection."
    },
    {
      "id": 57,
      "question": "Which type of address is assigned dynamically and may change over time on a network?",
      "options": [
        "Dynamic IP address",
        "Static IP address",
        "Loopback address",
        "Multicast address"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Dynamic IP addresses are assigned by DHCP and can change when the lease expires. Static IP addresses are manually assigned and remain constant. Loopback addresses (127.0.0.1) are for local testing. Multicast addresses send data to multiple recipients simultaneously.",
      "examTip": "**Dynamic IP = DHCP-assigned, flexible addressing.** Ideal for non-critical devices in dynamic networks."
    },
    {
      "id": 58,
      "question": "Which protocol is used to transfer files securely between two networked hosts over an encrypted connection?",
      "options": [
        "SFTP",
        "FTP",
        "TFTP",
        "HTTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SFTP (Secure File Transfer Protocol) uses SSH for encrypted file transfers. FTP transfers files but is unencrypted. TFTP offers simple, unsecured file transfers. HTTP transfers web content, not files between hosts.",
      "examTip": "**SFTP = Secure file transfers.** Always prefer SFTP over FTP for sensitive data movement."
    },
    {
      "id": 59,
      "question": "A technician needs to identify network devices and their interconnections within a large enterprise. Which protocol would BEST assist with this task?",
      "options": [
        "LLDP",
        "BGP",
        "NTP",
        "OSPF"
      ],
      "correctAnswerIndex": 0,
      "explanation": "LLDP (Link Layer Discovery Protocol) allows network devices to share information about themselves and discover neighboring devices. BGP handles inter-autonomous system routing. NTP synchronizes device clocks. OSPF is used for routing within an organization but doesn’t provide device discovery information.",
      "examTip": "**LLDP = Network mapping made easy.** Crucial for visualizing large network topologies."
    },
    {
      "id": 60,
      "question": "Which routing protocol is commonly used by ISPs to exchange routing information across the internet?",
      "options": [
        "BGP",
        "EIGRP",
        "OSPF",
        "RIP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BGP (Border Gateway Protocol) is the de facto standard for routing between ISPs and large organizations on the internet. EIGRP is proprietary to Cisco. OSPF is typically used for internal routing within organizations. RIP uses hop count and is less suitable for large networks like the internet.",
      "examTip": "**BGP = The internet’s routing backbone.** Handles routing between autonomous systems globally."
    },
    {
      "id": 61,
      "question": "A technician needs to ensure that internal devices can initiate outbound internet connections, but external hosts cannot initiate inbound sessions. Which technology provides this functionality?",
      "options": [
        "Port Address Translation (PAT)",
        "Access Control List (ACL)",
        "Stateful firewall",
        "Static NAT"
      ],
      "correctAnswerIndex": 0,
      "explanation": "PAT allows multiple internal devices to share a single public IP for outbound connections while preventing inbound connections from being initiated externally. ACLs can control traffic but are less dynamic. Stateful firewalls track connections but may not perform address translation. Static NAT maps one-to-one IPs, allowing potential inbound access.",
      "examTip": "**PAT = Many-to-one outbound translation.** Prevents unsolicited inbound traffic while allowing internet access."
    },
    {
      "id": 62,
      "question": "Which WAN technology uses packet-switching and can dynamically route traffic based on current network conditions?",
      "options": [
        "MPLS",
        "Frame Relay",
        "ISDN",
        "T1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MPLS (Multiprotocol Label Switching) uses labels to route packets dynamically based on real-time conditions. Frame Relay is older and less dynamic. ISDN is a circuit-switched technology, and T1 provides a fixed, point-to-point connection.",
      "examTip": "**MPLS = Flexible, dynamic WAN routing.** Ideal for modern enterprise WAN connectivity."
    },
    {
      "id": 63,
      "question": "A network engineer suspects a routing loop in the network. Which tool would BEST help diagnose this issue?",
      "options": [
        "traceroute",
        "ping",
        "netstat",
        "ipconfig"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'traceroute' reveals each hop along a packet’s path, making it useful for identifying routing loops. 'ping' checks connectivity but doesn’t reveal routing details. 'netstat' displays active connections, and 'ipconfig' shows local IP settings.",
      "examTip": "**traceroute = Path visibility.** Essential for detecting routing loops and misconfigurations."
    },
    {
      "id": 64,
      "question": "Which network service ensures time synchronization across network devices to support accurate event logging and scheduling?",
      "options": [
        "NTP",
        "DNS",
        "DHCP",
        "SNMP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NTP (Network Time Protocol) synchronizes time across devices. DNS resolves hostnames to IPs. DHCP assigns IP addresses. SNMP monitors and manages network devices but doesn’t handle time synchronization.",
      "examTip": "**NTP = Accurate timestamps.** Crucial for troubleshooting, security, and performance logging."
    },
    {
      "id": 65,
      "question": "Which port should be opened on a firewall to allow secure web traffic from external clients?",
      "options": [
        "443",
        "80",
        "22",
        "25"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Port 443 is used for HTTPS, enabling secure web communication. Port 80 is for unencrypted HTTP. Port 22 is for SSH, and port 25 is for SMTP email transmission.",
      "examTip": "**HTTPS = Port 443.** Always secure web traffic using TLS over this port."
    },
    {
      "id": 66,
      "question": "A network administrator needs to ensure that network devices can automatically learn MAC addresses and populate forwarding tables. Which device performs this function?",
      "options": [
        "Switch",
        "Hub",
        "Router",
        "Firewall"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Switches operate at Layer 2, learning MAC addresses to forward traffic efficiently. Hubs broadcast traffic to all ports. Routers operate at Layer 3, forwarding packets based on IP addresses. Firewalls enforce security policies.",
      "examTip": "**Switch = MAC-aware traffic forwarder.** Reduces unnecessary network traffic through intelligent forwarding."
    },
    {
      "id": 67,
      "question": "Which IPv6 feature allows traffic to be sent to the nearest node within a group of potential recipients, improving response time?",
      "options": [
        "Anycast",
        "Unicast",
        "Multicast",
        "Link-local"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Anycast addresses route traffic to the nearest device in a group, reducing latency. Unicast addresses a single recipient. Multicast delivers to multiple recipients. Link-local addresses are restricted to the local network segment.",
      "examTip": "**Anycast = Nearest node routing.** Ideal for load balancing and high-availability services."
    },
    {
      "id": 68,
      "question": "Which network architecture component provides centralized authentication for network access using RADIUS or TACACS+?",
      "options": [
        "AAA server",
        "Proxy server",
        "Load balancer",
        "DNS server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An AAA (Authentication, Authorization, and Accounting) server uses protocols like RADIUS or TACACS+ to manage access. Proxy servers manage traffic flow. Load balancers distribute traffic among servers. DNS servers resolve hostnames.",
      "examTip": "**AAA = Centralized access control.** Securely authenticate users across network services."
    },
    {
      "id": 69,
      "question": "Which technology allows secure remote access to a corporate network by encrypting all transmitted data?",
      "options": [
        "IPSec VPN",
        "SSH",
        "SSL",
        "RDP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "IPSec VPN encrypts all data transmitted over the tunnel, providing secure remote access. SSH secures remote command-line sessions. SSL encrypts web traffic. RDP provides remote desktop access but doesn’t inherently secure network traffic.",
      "examTip": "**IPSec VPN = End-to-end encrypted access.** Securely extend the corporate network to remote users."
    },
    {
      "id": 70,
      "question": "A user reports that a web application is slow to load, but other applications are unaffected. Network monitoring shows high latency for that specific traffic. What is the BEST immediate action?",
      "options": [
        "Implement QoS policies prioritizing web traffic.",
        "Reboot the web server hosting the application.",
        "Upgrade the user’s network interface card (NIC).",
        "Replace the access switch with a higher-capacity model."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Implementing QoS prioritizes web traffic, ensuring the application receives necessary bandwidth. Rebooting the server may not address the network issue. Upgrading the NIC or switch affects hardware but may not resolve traffic prioritization issues.",
      "examTip": "**QoS = Prioritize critical applications.** Optimize bandwidth allocation for business-critical traffic."
    },
    {
      "id": 71,
      "question": "Which wireless frequency band provides the widest coverage but typically at lower data rates?",
      "options": [
        "2.4GHz",
        "5GHz",
        "6GHz",
        "60GHz"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 2.4GHz band offers greater coverage and wall penetration but lower speeds. The 5GHz and 6GHz bands provide higher speeds but shorter ranges. The 60GHz band provides ultra-high speeds over very short distances.",
      "examTip": "**2.4GHz = Range > Speed.** Suitable for larger coverage areas with fewer performance demands."
    },
    {
      "id": 72,
      "question": "Which OSI layer is responsible for establishing, maintaining, and terminating sessions between applications?",
      "options": [
        "Session layer",
        "Presentation layer",
        "Transport layer",
        "Network layer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The Session layer (Layer 5) manages sessions between applications. The Presentation layer (Layer 6) handles data formatting and encryption. The Transport layer (Layer 4) ensures reliable data transfer. The Network layer (Layer 3) handles routing and addressing.",
      "examTip": "**Session layer = Conversations manager.** Think of it as the coordinator for communication sessions."
    },
    {
      "id": 73,
      "question": "Which routing protocol supports classless routing, offers fast convergence, and is based on link-state technology?",
      "options": [
        "OSPF",
        "RIP",
        "BGP",
        "EIGRP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "OSPF (Open Shortest Path First) is a classless, link-state protocol that converges quickly. RIP uses hop counts and is slower. BGP is a path-vector protocol used for internet routing. EIGRP is Cisco proprietary and uses a hybrid approach.",
      "examTip": "**OSPF = Link-state + fast convergence.** Ideal for large, complex enterprise networks."
    },
    {
      "id": 74,
      "question": "Which component of a data center network topology provides direct connectivity between spine switches and leaf switches without intermediate devices?",
      "options": [
        "Spine-and-leaf architecture",
        "Star topology",
        "Full mesh topology",
        "Bus topology"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Spine-and-leaf architectures connect each leaf switch to every spine switch directly, ensuring low latency and predictable performance. Star topologies rely on a central device. Full mesh topologies connect every node to every other node but are costlier. Bus topologies use a single backbone with limited scalability.",
      "examTip": "**Spine-and-leaf = Scalable data center design.** Guarantees predictable performance under heavy loads."
    },
    {
      "id": 75,
      "question": "Which protocol uses port 161 and is commonly used for monitoring and managing network devices?",
      "options": [
        "SNMP",
        "NTP",
        "DNS",
        "SSH"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SNMP (Simple Network Management Protocol) uses port 161 for polling and port 162 for traps. NTP synchronizes time. DNS resolves domain names. SSH provides secure remote access but doesn’t handle network management.",
      "examTip": "**SNMP = Network management made simple.** Port 161 = management queries, port 162 = alerts."
    },
    {
      "id": 76,
      "question": "Which IPv6 address type allows communication within the same link or network segment and starts with FE80::?",
      "options": [
        "Link-local",
        "Global unicast",
        "Anycast",
        "Multicast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Link-local addresses (FE80::/10) are automatically assigned for communication within a local link. Global unicast addresses are publicly routable. Anycast addresses reach the nearest node. Multicast addresses send data to multiple recipients.",
      "examTip": "**FE80:: = Link-local only.** Used for neighbor discovery and local communication without routing."
    },
    {
      "id": 77,
      "question": "Which technology provides security by allowing only specified MAC addresses to access a specific switch port?",
      "options": [
        "Port security",
        "802.1X",
        "VLAN tagging",
        "ACLs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Port security limits access to a switch port based on MAC addresses. 802.1X provides port-based authentication. VLAN tagging segregates network traffic. ACLs control traffic flow based on IP and protocol rules.",
      "examTip": "**Port security = Device-level access control.** Prevent unauthorized devices from accessing the network."
    },
    {
      "id": 78,
      "question": "Which wireless standard provides the fastest data rates and supports MU-MIMO technology for multiple simultaneous data streams?",
      "options": [
        "802.11ax (Wi-Fi 6)",
        "802.11ac",
        "802.11n",
        "802.11g"
      ],
      "correctAnswerIndex": 0,
      "explanation": "802.11ax (Wi-Fi 6) supports MU-MIMO in both uplink and downlink, providing higher data rates and improved efficiency in dense environments. 802.11ac supports MU-MIMO only in downlink. 802.11n and 802.11g offer lower speeds and lack advanced MU-MIMO support.",
      "examTip": "**Wi-Fi 6 = High-speed, high-density hero.** Choose 802.11ax for future-proof wireless performance."
    },
    {
      "id": 79,
      "question": "Which network security concept ensures that sensitive information remains accessible only to authorized users?",
      "options": [
        "Confidentiality",
        "Integrity",
        "Availability",
        "Non-repudiation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Confidentiality ensures data access is restricted to authorized users. Integrity ensures data remains unaltered. Availability guarantees data is accessible when needed. Non-repudiation ensures users cannot deny actions they performed.",
      "examTip": "**Confidentiality = Keep it secret, keep it safe.** Encryption and access controls are key components."
    },
    {
      "id": 80,
      "question": "Which device would MOST likely be configured as a demarcation point between an organization’s internal network and an external network?",
      "options": [
        "Firewall",
        "Switch",
        "Router",
        "Repeater"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Firewalls act as demarcation points, controlling traffic between internal and external networks based on security rules. Switches forward traffic within networks. Routers direct traffic between networks but aren’t always security-focused. Repeaters regenerate signals but don’t provide segmentation or protection.",
      "examTip": "**Firewall = Network boundary guardian.** First line of defense at the network edge."
    },
    {
      "id": 81,
      "question": "A network administrator notices high CPU utilization on a firewall due to excessive traffic. After analysis, the traffic is identified as legitimate but non-critical. What is the BEST course of action?",
      "options": [
        "Implement Quality of Service (QoS) policies.",
        "Upgrade the firewall hardware.",
        "Deploy an additional firewall in parallel.",
        "Increase the bandwidth of the internet link."
      ],
      "correctAnswerIndex": 0,
      "explanation": "QoS policies can prioritize critical traffic and limit resource use by non-critical traffic, effectively reducing CPU load. Upgrading hardware or adding firewalls may be costlier and unnecessary. Increasing internet bandwidth won’t reduce CPU utilization on the firewall.",
      "examTip": "**QoS = Prioritize and optimize.** Always tune existing resources before adding hardware."
    },
    {
      "id": 82,
      "question": "Which protocol is used for secure device management and supports authentication, encryption, and integrity protection over port 22?",
      "options": [
        "SSH",
        "Telnet",
        "SNMPv2",
        "HTTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH (Secure Shell) provides secure remote device management over port 22. Telnet lacks encryption. SNMPv2 is used for management but without strong security. HTTP is unencrypted and unsuitable for device management.",
      "examTip": "**SSH = Secure remote management.** Always use SSH instead of Telnet for administrative access."
    },
    {
      "id": 83,
      "question": "Which cloud service model provides customers with access to application software hosted by the provider without managing the underlying infrastructure?",
      "options": [
        "SaaS",
        "PaaS",
        "IaaS",
        "FaaS"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SaaS (Software as a Service) delivers fully functional applications over the internet. PaaS provides a development platform. IaaS provides infrastructure components. FaaS offers serverless computing for running functions without managing infrastructure.",
      "examTip": "**SaaS = Ready-to-use apps.** No infrastructure management required for end users."
    },
    {
      "id": 84,
      "question": "A network technician suspects a duplex mismatch between two connected devices. Which symptom is MOST indicative of this issue?",
      "options": [
        "Late collisions on the interface.",
        "High CRC error rates.",
        "Interface flapping.",
        "Excessive ARP requests."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Late collisions occur when duplex settings are mismatched (one full-duplex, one half-duplex). CRC errors often indicate cabling issues. Interface flapping suggests physical connection instability. Excessive ARP requests typically point to IP or ARP-related issues.",
      "examTip": "**Duplex mismatch = Late collisions.** Always check duplex settings during link performance issues."
    },
    {
      "id": 85,
      "question": "Which addressing method sends data to all devices within a specific broadcast domain?",
      "options": [
        "Broadcast",
        "Unicast",
        "Multicast",
        "Anycast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Broadcast addresses send data to all devices in the broadcast domain. Unicast targets a single device. Multicast delivers to multiple selected recipients. Anycast routes to the nearest recipient among a group.",
      "examTip": "**Broadcast = All devices in the domain.** Limited to local networks; routers typically block broadcasts."
    },
    {
      "id": 86,
      "question": "Which tool would BEST identify intermittent wireless signal interference in a corporate environment?",
      "options": [
        "Spectrum analyzer",
        "Wi-Fi analyzer",
        "Packet sniffer",
        "Toner probe"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A spectrum analyzer detects interference from both Wi-Fi and non-Wi-Fi sources. A Wi-Fi analyzer checks Wi-Fi-specific issues like channel overlap. Packet sniffers analyze data packets, not interference. Toner probes trace cables, not wireless signals.",
      "examTip": "**Spectrum analyzer = Interference hunter.** Essential for identifying rogue devices and signal disruptors."
    },
    {
      "id": 87,
      "question": "Which protocol allows for secure web-based management of network devices, ensuring both authentication and encryption?",
      "options": [
        "HTTPS",
        "HTTP",
        "SSH",
        "SNMPv2"
      ],
      "correctAnswerIndex": 0,
      "explanation": "HTTPS provides encrypted web access over port 443, suitable for secure device management. HTTP is unencrypted. SSH secures command-line access but not web interfaces. SNMPv2 lacks encryption by default.",
      "examTip": "**HTTPS = Secure GUI management.** Always choose HTTPS over HTTP for web-based interfaces."
    },
    {
      "id": 88,
      "question": "Which wireless authentication method provides the highest level of security for enterprise networks, using individual user credentials and a RADIUS server?",
      "options": [
        "WPA3-Enterprise",
        "WPA3-Personal",
        "WPA2-Personal",
        "WEP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3-Enterprise uses a RADIUS server for user authentication, offering the highest security level. WPA3-Personal uses a shared passphrase. WPA2-Personal and WEP are less secure, with WEP being obsolete.",
      "examTip": "**WPA3-Enterprise = Enterprise-grade security.** Always deploy for business-critical wireless networks."
    },
    {
      "id": 89,
      "question": "Which IPv6 address type is designed to be unique across the entire internet and begins with 2000::/3?",
      "options": [
        "Global unicast",
        "Link-local",
        "Unique local",
        "Multicast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Global unicast addresses (2000::/3) are publicly routable on the internet. Link-local (FE80::) is for local network segments. Unique local addresses are private equivalents. Multicast addresses target multiple recipients simultaneously.",
      "examTip": "**2000::/3 = Global unicast.** Equivalent to IPv4 public addressing for internet communication."
    },
    {
      "id": 90,
      "question": "A technician is troubleshooting connectivity issues on a switch port. The port is showing 'administratively down.' What is the FIRST step to resolve the issue?",
      "options": [
        "Enable the port using the appropriate CLI command.",
        "Replace the Ethernet cable connected to the port.",
        "Restart the connected end device.",
        "Reboot the switch."
      ],
      "correctAnswerIndex": 0,
      "explanation": "'Administratively down' indicates the port is manually disabled. Enabling the port using a CLI command like `no shutdown` restores functionality. Replacing cables or restarting devices is unnecessary if the port is administratively disabled. Rebooting the switch is excessive.",
      "examTip": "**'Admin down' = Run 'no shutdown'.** Always check configuration before physical troubleshooting."
    },
    {
      "id": 91,
      "question": "Which protocol allows users to access a secure virtual desktop environment remotely over the internet?",
      "options": [
        "RDP",
        "SSH",
        "VNC",
        "Telnet"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RDP (Remote Desktop Protocol) provides secure graphical desktop access over port 3389. SSH provides secure shell access, VNC allows graphical access but with less inherent security, and Telnet is unencrypted.",
      "examTip": "**RDP = Remote desktop access.** Always use strong authentication and encryption when exposing RDP externally."
    },
    {
      "id": 92,
      "question": "Which method would BEST prevent rogue DHCP servers from assigning IP addresses on the network?",
      "options": [
        "DHCP snooping",
        "Port security",
        "802.1X authentication",
        "ACLs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DHCP snooping allows only trusted ports to provide DHCP services, preventing rogue servers. Port security controls MAC addresses per port. 802.1X authenticates devices before network access. ACLs filter traffic but don’t specifically prevent rogue DHCP activity.",
      "examTip": "**DHCP snooping = Prevent rogue IP assignments.** Ensure only authorized servers provide DHCP leases."
    },
    {
      "id": 93,
      "question": "Which IPv6 transition mechanism allows IPv6 packets to be transmitted over an IPv4 network by encapsulating them inside IPv4 packets?",
      "options": [
        "Tunneling",
        "NAT64",
        "Dual stack",
        "Anycast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Tunneling encapsulates IPv6 packets within IPv4 packets, enabling communication across IPv4 infrastructure. NAT64 translates between IPv6 and IPv4. Dual stack runs both protocols concurrently. Anycast optimizes traffic delivery but isn’t a transition mechanism.",
      "examTip": "**Tunneling = IPv6 over IPv4 bridge.** Useful during phased IPv6 adoption strategies."
    },
    {
      "id": 94,
      "question": "A network administrator needs to monitor real-time bandwidth usage on multiple WAN links. Which solution provides this functionality?",
      "options": [
        "NetFlow analyzer",
        "Packet sniffer",
        "Syslog server",
        "TDR (Time Domain Reflectometer)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NetFlow analyzers track and report on network traffic patterns, including real-time bandwidth usage. Packet sniffers capture detailed traffic data but aren’t optimized for high-level monitoring. Syslog servers aggregate logs. TDRs test copper cables for faults.",
      "examTip": "**NetFlow = Real-time traffic insight.** Perfect for WAN optimization and capacity planning."
    },
    {
      "id": 95,
      "question": "Which cloud deployment model is dedicated to a single organization and offers the highest level of security and control?",
      "options": [
        "Private cloud",
        "Public cloud",
        "Hybrid cloud",
        "Community cloud"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Private clouds are dedicated environments, providing maximum control and security. Public clouds share infrastructure among multiple users. Hybrid clouds combine public and private elements. Community clouds are shared among organizations with common interests.",
      "examTip": "**Private cloud = Full control, full responsibility.** Ideal for highly sensitive workloads."
    },
    {
      "id": 96,
      "question": "Which tool would MOST effectively detect unauthorized wireless access points within a corporate network?",
      "options": [
        "Wi-Fi analyzer",
        "Spectrum analyzer",
        "Packet sniffer",
        "OTDR"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Wi-Fi analyzers detect unauthorized access points and rogue devices by scanning wireless networks. Spectrum analyzers detect general RF interference. Packet sniffers analyze data but don’t specifically detect rogue APs. OTDRs test fiber optic cables.",
      "examTip": "**Wi-Fi analyzer = Rogue AP detector.** Essential for securing wireless environments."
    },
    {
      "id": 97,
      "question": "Which networking device forwards traffic based on IP addresses and typically forms the backbone of WAN connectivity?",
      "options": [
        "Router",
        "Switch",
        "Hub",
        "Repeater"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Routers operate at Layer 3, directing traffic between networks using IP addresses, making them essential for WAN connectivity. Switches operate at Layer 2, forwarding traffic within LANs. Hubs broadcast traffic to all ports. Repeaters extend signal range but don’t route traffic.",
      "examTip": "**Router = Network traffic director.** Critical for inter-network and WAN communication."
    },
    {
      "id": 98,
      "question": "Which protocol uses port 3389 and provides encrypted remote desktop access to Windows systems?",
      "options": [
        "RDP",
        "SSH",
        "VNC",
        "Telnet"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RDP (Remote Desktop Protocol) uses port 3389 for secure remote graphical access to Windows systems. SSH (port 22) secures command-line sessions. VNC provides graphical access but may lack encryption. Telnet is insecure and transmits data in plaintext.",
      "examTip": "**RDP = Secure Windows remote access.** Always secure RDP sessions with VPN or strong authentication."
    },
    {
      "id": 99,
      "question": "Which technique improves wireless network performance by directing signals toward specific devices rather than broadcasting them in all directions?",
      "options": [
        "Beamforming",
        "MU-MIMO",
        "Roaming",
        "Band steering"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Beamforming focuses wireless signals directly toward connected devices, improving speed and reliability. MU-MIMO allows multiple devices to transmit simultaneously. Roaming ensures seamless handoffs between access points. Band steering shifts devices to optimal frequency bands.",
      "examTip": "**Beamforming = Targeted Wi-Fi performance.** Reduces interference and boosts signal strength for connected clients."
    },
    {
      "id": 100,
      "question": "Which port should be opened on a firewall to allow Secure File Transfer Protocol (SFTP) traffic?",
      "options": [
        "22",
        "21",
        "443",
        "80"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SFTP uses port 22 as it runs over SSH, providing encrypted file transfers. FTP uses port 21 but is unencrypted. Port 443 is for HTTPS. Port 80 is for HTTP.",
      "examTip": "**SFTP = Secure FTP via SSH.** Always choose SFTP over FTP for secure file transfers."
    }
  ]
});
