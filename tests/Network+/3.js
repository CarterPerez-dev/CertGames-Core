db.tests.insertOne({
  "category": "nplus",
  "testId": 3,                 
  "testName": "Practice Test #3 (Easy)",
  "xpPerCorrect": 10,                     
  "questions": [
    {
      "id": 1,
      "question": "A network administrator must secure all traffic between a remote branch and headquarters. Which solution is the MOST effective way to protect data in transit?",
      "options": [
        "Utilize GRE tunnels without any encryption",
        "Configure a site-to-site VPN with IPSec",
        "Enable Telnet for remote device management",
        "Implement unencrypted HTTP sessions only"
      ],
      "correctAnswerIndex": 1, 
      "explanation": "Option A lacks native encryption, leaving data exposed. Option B (correct) creates an encrypted IPSec tunnel, ensuring confidentiality and integrity. Option C uses a plaintext protocol, unsafe for sensitive traffic. Option D fails to secure any data with encryption.",
      "examTip": "Always prioritize encrypted VPN tunneling for secure site-to-site connections."
    },
    {
      "id": 2,
      "question": "You notice repeated TCP retransmissions between two routers. What is the FIRST action you should take to identify the problem?",
      "options": [
        "Replace all network cables immediately",
        "Check interface statistics and error counters",
        "Restart both routers to clear sessions",
        "Reduce the MTU size on both ends"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is premature without confirming physical issues. Option B (correct) helps pinpoint issues like CRC errors or drops. Option C can resolve some issues temporarily but doesn't diagnose root causes. Option D is only relevant if MTU mismatch is proven.",
      "examTip": "Always gather interface statistics first to narrow down possible physical or configuration errors."
    },
    {
      "id": 3,
      "question": "Which of the following BEST ensures an organization’s wireless network requires unique credentials for each user?",
      "options": [
        "Enable WPA3-Personal with a shared passphrase",
        "Implement MAC filtering on all access points",
        "Use WPA2-Enterprise with 802.1X authentication",
        "Disable SSID broadcast to conceal the network"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A uses a single shared password, not unique per user. Option B is weak because MAC addresses can be spoofed. Option C (correct) forces individual user authentication via RADIUS/802.1X. Option D only obscures the SSID but doesn't strengthen credentials.",
      "examTip": "When securing WLANs in a corporate environment, 802.1X-based authentication is preferred for user-level accountability."
    },
    {
      "id": 4,
      "question": "A user reports being unable to reach the internet after a network change. Which is the FIRST step to troubleshoot this problem?",
      "options": [
        "Review the default gateway settings",
        "Assign a static IP address to the user",
        "Disable all firewall rules",
        "Change the DNS server to 8.8.8.8"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) quickly verifies if traffic is properly routed out of the local subnet. Option B is arbitrary and ignores underlying routing or DHCP issues. Option C could expose the network to threats and isn’t a diagnostic approach. Option D might solve DNS issues but not general connectivity if gateway is wrong.",
      "examTip": "Always confirm IP configuration details (IP, subnet, gateway) before making broader changes."
    },
    {
      "id": 5,
      "question": "A technician must create a network design for multiple VLANs. Which device is BEST suited to route between VLANs for optimal performance?",
      "options": [
        "A layer 2 switch with trunk ports",
        "A layer 3 switch with SVIs",
        "A basic consumer-grade router",
        "A wireless access point using WPA2"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A only switches traffic at layer 2; it can’t route VLANs without external routing. Option B (correct) provides inter-VLAN routing via Switch Virtual Interfaces efficiently. Option C can route, but typically less performant for large VLAN deployments. Option D is unrelated to VLAN routing needs.",
      "examTip": "Use layer 3 switches for high-speed, inter-VLAN routing in enterprise environments."
    },
    {
      "id": 6,
      "question": "Your organization wants to separate guest traffic from internal traffic. Which approach is the BEST to achieve this using a single managed switch?",
      "options": [
        "Implement VLANs on the switch ports",
        "Use static IP addresses on guest devices",
        "Disable DHCP on all internal VLANs",
        "Set MAC filtering on each internal port"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) logically segments traffic with VLANs, a standard method for separation. Option B alone won’t separate traffic at layer 2 or layer 3. Option C is not directly related to segmentation and complicates network management. Option D does not truly segregate guest from internal traffic, only restricts devices by MAC.",
      "examTip": "VLANs are the primary method to segment traffic and enhance security within a single switch infrastructure."
    },
    {
      "id": 7,
      "question": "Which of the following MOST helps to mitigate broadcast storms in a large switched network?",
      "options": [
        "Configure DNS with multiple record types",
        "Enable spanning tree protocol",
        "Increase router NAT table size",
        "Disable syslog on all devices"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is unrelated to broadcast domains. Option B (correct) uses STP to block redundant paths and prevent loops. Option C has no effect on layer 2 broadcast storms. Option D does not influence broadcast traffic control.",
      "examTip": "Redundant links can cause loops; STP blocks loops, preventing broadcast storms."
    },
    {
      "id": 8,
      "question": "A router is discarding packets due to TTL expiration. Which layer of the OSI model is primarily involved in this process?",
      "options": [
        "Session layer (Layer 5)",
        "Network layer (Layer 3)",
        "Transport layer (Layer 4)",
        "Data link layer (Layer 2)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A deals with interhost communication sessions. Option B (correct) is where IP addresses and TTL fields exist, so TTL expiration is handled there. Option C involves ports and reliable data transport, not IP TTL. Option D handles physical addressing, not TTL.",
      "examTip": "Time to Live (TTL) is an IP-level mechanism, which is Layer 3 of the OSI model."
    },
    {
      "id": 9,
      "question": "Which port is typically used by LDAP over SSL (LDAPS) for secure directory queries?",
      "options": [
        "Port 389",
        "Port 636",
        "Port 443",
        "Port 161"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is LDAP (plain text). Option B (correct) is the standard LDAPS port. Option C is HTTPS, unrelated to LDAP. Option D is SNMP, not LDAP.",
      "examTip": "LDAPS commonly runs on TCP port 636 to provide encryption for directory services."
    },
    {
      "id": 10,
      "question": "During a wireless site survey, you discover overlapping channels on the 2.4 GHz band. What is the FIRST measure you should take to minimize interference?",
      "options": [
        "Switch to 802.11a-only for all clients",
        "Use channels 1, 6, and 11 for APs",
        "Increase transmit power to overpower interference",
        "Enable MAC filtering on the AP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A forces older standard usage and won’t fix channel overlap. Option B (correct) uses non-overlapping channels in 2.4 GHz. Option C typically worsens adjacent channel interference. Option D doesn’t affect channel overlap.",
      "examTip": "In 2.4 GHz networks, stick to non-overlapping channels (1, 6, 11) to reduce co-channel interference."
    },
    {
      "id": 11,
      "question": "You suspect a bad patch cable is causing intermittent connectivity. Which tool is MOST appropriate to confirm cable integrity?",
      "options": [
        "Wireless analyzer",
        "Protocol analyzer",
        "Cable tester",
        "Port mirroring session"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is for Wi-Fi signals, not copper cable integrity. Option B captures traffic, not physical cable faults. Option C (correct) verifies continuity and wire mapping. Option D only duplicates traffic to another port for analysis, not confirming cable status.",
      "examTip": "A basic cable tester is key to diagnosing physical-layer issues before investigating higher layers."
    },
    {
      "id": 12,
      "question": "A technician needs to encrypt in-flight traffic while tunneling through an untrusted network. Which technology is BEST for ensuring confidentiality and integrity?",
      "options": [
        "GRE encapsulation alone",
        "IPSec VPN using ESP",
        "Clear-text HTTP sessions",
        "SNMPv1 traps"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A lacks encryption by default. Option B (correct) uses Encapsulating Security Payload (ESP) for both encryption and integrity. Option C is not encrypted. Option D is outdated and does not protect data in transit.",
      "examTip": "ESP within IPSec encrypts and authenticates IP packets, ensuring secure tunnels over untrusted links."
    },
    {
      "id": 13,
      "question": "Users are unable to connect to a new VLAN. You discover their ports are set to VLAN 10 but the switch trunk port for the uplink is missing VLAN 10. What is the BEST fix?",
      "options": [
        "Change native VLAN to 10 on the trunk",
        "Add VLAN 10 to the trunk allowed list",
        "Reboot the users’ PCs to renew leases",
        "Disable STP on the trunk interface"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A only sets VLAN 10 as native, which may not help if VLAN 10 isn’t allowed on the trunk. Option B (correct) ensures the trunk passes VLAN 10 traffic. Option C won’t resolve a trunk misconfiguration. Option D is dangerous and unrelated.",
      "examTip": "Verify that your trunk ports allow all the required VLANs in their allowed VLAN list."
    },
    {
      "id": 14,
      "question": "A server repeatedly fails to obtain an IP address. After confirming the DHCP server is online, which is the FIRST step to isolate the issue?",
      "options": [
        "Assign a static IP and hope it resolves",
        "Check DHCP scope options and available leases",
        "Manually flush DNS cache on the server",
        "Disable RSTP on the switches"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is a workaround, not a diagnosis. Option B (correct) checks if the scope is exhausted or misconfigured. Option C deals with name resolution, not address leasing. Option D is unrelated to DHCP address allocation.",
      "examTip": "Always verify the DHCP scope settings (range, reservations, and remaining addresses) to pinpoint allocation issues."
    },
    {
      "id": 15,
      "question": "Which of the following IPv6 transition methods allows an IPv6 packet to be encapsulated inside IPv4 traffic?",
      "options": [
        "Dual stack",
        "Tunneling",
        "NAT64",
        "APIPA"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A uses both IPv4 and IPv6 stacks simultaneously but does not encapsulate traffic. Option B (correct) encapsulates IPv6 in IPv4 for transition. Option C translates IPv6 addresses to IPv4 addresses, not strictly encapsulation. Option D is a fallback for IPv4 addresses, not an IPv6 transition mechanism.",
      "examTip": "Tunneling is a common method for integrating IPv6 traffic into existing IPv4 networks without direct translation."
    },
    {
      "id": 16,
      "question": "You need to ensure high availability for your default gateway in a subnet. Which protocol BEST provides an automatic failover if the primary gateway goes down?",
      "options": [
        "ARP",
        "DNSSEC",
        "HTTP",
        "VRRP"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Option A resolves MAC addresses, not gateway redundancy. Option B secures DNS records, not gateways. Option C is a web protocol, irrelevant to default gateway HA. Option D (correct) is a First Hop Redundancy Protocol ensuring an alternate default gateway.",
      "examTip": "VRRP (or HSRP/GLBP) is used to provide gateway redundancy in enterprise networks."
    },
    {
      "id": 17,
      "question": "A router chooses a path with the shortest metric even though a different path has fewer hops. Which routing protocol characteristic explains this?",
      "options": [
        "Administrative distance",
        "Horizontal scaling",
        "Cost-based selection",
        "Prefix length priority"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A determines trust in a route source, not how the metric is calculated. Option B is not a routing metric concept. Option C (correct) indicates the protocol uses metrics beyond hop count (e.g., OSPF uses cost). Option D is about route specificity, not cost calculations.",
      "examTip": "Some routing protocols consider bandwidth or delay over hop count, leading to a cost-based selection."
    },
    {
      "id": 18,
      "question": "Which type of DNS record is used to identify the mail server responsible for accepting email on behalf of a domain?",
      "options": [
        "A record",
        "CNAME record",
        "MX record",
        "TXT record"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A maps a hostname to an IPv4 address. Option B is an alias for another domain name. Option C (correct) designates mail server responsibility. Option D often holds verification or arbitrary text data.",
      "examTip": "Always verify MX records for proper email routing to your domain’s mail server."
    },
    {
      "id": 19,
      "question": "You are tasked with capturing traffic to troubleshoot random disconnections. Which tool is MOST appropriate for deep packet inspection on a wired Ethernet segment?",
      "options": [
        "Wi-Fi analyzer",
        "Protocol analyzer",
        "Cable toner probe",
        "SNMP polling utility"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A only inspects wireless signals. Option B (correct) can capture packets for detailed analysis. Option C traces cable paths, not packet-level analysis. Option D queries devices for performance data but doesn’t do packet inspection.",
      "examTip": "Use a protocol analyzer (like Wireshark) when you need to see exact packet contents and conversation flows."
    },
    {
      "id": 20,
      "question": "A consultant is designing a WAN solution that automatically selects the best path based on latency and cost across multiple transport links. Which emerging technology is BEST suited?",
      "options": [
        "SD-WAN",
        "NAT64",
        "Static routing",
        "Simple QoS tagging"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) dynamically balances multiple WAN links for performance and cost. Option B translates IPv6 addresses to IPv4, unrelated to WAN path optimization. Option C requires manual configuration and no automatic path selection. Option D just marks traffic but doesn’t pick paths automatically.",
      "examTip": "SD-WAN solutions are transport-agnostic and use policies to choose the optimal path in real time."
    },
    {
      "id": 21,
      "question": "A network engineer notices that traffic within the same data center is routing out to the internet gateway first. Which topology or design approach can help keep east-west traffic local?",
      "options": [
        "Collapsed core",
        "Three-tier model with core routing",
        "North-south approach only",
        "Hub-and-spoke architecture"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) aggregates distribution and core layers, often keeping local traffic inside the data center. Option B might route traffic to a separate core. Option C describes external traffic flows, not local data center paths. Option D is more typical in WAN designs than local data center traffic.",
      "examTip": "A collapsed core can minimize unnecessary routing hops for east-west (intra-data-center) traffic."
    },
    {
      "id": 22,
      "question": "Which of the following is the MOST effective strategy to prevent switch port flooding attacks (MAC flooding)?",
      "options": [
        "Disable CDP globally",
        "Set port security limits on MAC addresses",
        "Use an unmanaged switch without STP",
        "Enable DNSSEC to secure name resolution"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A prevents device discovery but doesn’t prevent MAC floods. Option B (correct) restricts the number of MACs per port, mitigating floods. Option C offers no security or loop protection. Option D only secures DNS queries, not MAC learning behavior.",
      "examTip": "Port security can limit MAC addresses learned per interface and shut down ports exceeding that limit."
    },
    {
      "id": 23,
      "question": "When configuring an IPv4 address of 10.10.5.10/29, what is the maximum number of usable host addresses in this subnet?",
      "options": [
        "2",
        "6",
        "14",
        "30"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is /30. Option B (correct) a /29 has 8 total IPs, 1 network address, 1 broadcast, leaving 6 usable. Options C and D correspond to masks /28 or /27, providing more hosts.",
      "examTip": "Remember that a /29 gives you 8 total IPs, 6 of which can be assigned to devices."
    },
    {
      "id": 24,
      "question": "You need to identify the root cause of intermittent network outages by correlating logs from multiple devices in real time. Which solution is BEST?",
      "options": [
        "Manually reviewing each device’s local log",
        "Setting up a syslog collector and SIEM",
        "Using Wi-Fi analyzer on all network segments",
        "Enabling DHCP snooping on edge switches"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is time-consuming and prone to missing cross-device patterns. Option B (correct) centralizes logs for correlation and real-time alerts. Option C is for wireless analysis only, ignoring other logs. Option D helps track DHCP traffic but not a complete log correlation approach.",
      "examTip": "A SIEM aggregates logs and provides automated analysis, crucial for detecting multi-device anomalies."
    },
    {
      "id": 25,
      "question": "Your router references a route from an internal protocol and a route from an external protocol for the same subnet. Which concept determines which route is installed in the routing table?",
      "options": [
        "Hop count mismatch",
        "Administrative distance",
        "CIDR block usage",
        "Default gateway priority"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is a metric detail, but different protocols might not use the same metric. Option B (correct) decides which source of routing information is preferred. Option C is about subnetting, not preference. Option D is a local IP setting, not route selection logic.",
      "examTip": "When multiple protocols offer a route, the one with the lowest administrative distance is chosen."
    },
    {
      "id": 26,
      "question": "In a virtualized data center, which technology encapsulates Layer 2 frames within UDP for easier network extension across Layer 3 boundaries?",
      "options": [
        "VXLAN",
        "PPP",
        "802.1Q trunking",
        "Syslog"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) encapsulates Ethernet frames in UDP for large-scale virtualization. Option B is a WAN protocol for serial links. Option C is VLAN tagging, not an encapsulation across L3. Option D is a logging protocol, unrelated to virtualization tunnels.",
      "examTip": "VXLAN is commonly used in modern data centers to extend VLANs at scale."
    },
    {
      "id": 27,
      "question": "You need to ensure each port on a switch only allows one device at a time. What is the FIRST feature to consider enabling?",
      "options": [
        "Port mirroring",
        "MAC address sticky port security",
        "SNMP polling",
        "Trunking"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A replicates traffic for analysis, not controlling device count. Option B (correct) lets the switch learn one MAC and disable the port if additional MACs appear. Option C only monitors device data, not limiting devices. Option D aggregates multiple VLANs but doesn’t restrict device count.",
      "examTip": "Port security with sticky MAC helps ensure only one legitimate host can connect on a given interface."
    },
    {
      "id": 28,
      "question": "Which command is used on Linux to display network interface configuration details, such as IP and MAC addresses?",
      "options": [
        "dig",
        "ipconfig",
        "tcpdump",
        "ip addr show"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Option A queries DNS name servers. Option B is a Windows command, not Linux. Option C captures packets but doesn’t show interface config. Option D (correct) displays IP/MAC addresses on Linux.",
      "examTip": "On modern Linux systems, 'ip addr show' or 'ip link show' replaces older ifconfig usage."
    },
    {
      "id": 29,
      "question": "Which protocol is a distance-vector routing protocol used primarily in smaller networks and uses hop count as its metric?",
      "options": [
        "OSPF",
        "BGP",
        "RIP",
        "EIGRP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is link-state. Option B is path-vector used for internet routing. Option C (correct) is distance-vector using hop count. Option D is an advanced distance-vector but uses a composite metric, not just hop count.",
      "examTip": "RIP is a classic distance-vector protocol limited by a max hop count of 15."
    },
    {
      "id": 30,
      "question": "You are setting up a mesh wireless network. Which statement BEST describes a characteristic of a mesh topology?",
      "options": [
        "Each AP must be directly wired to the core",
        "All traffic relies on a single root bridge",
        "APs dynamically route traffic through neighboring APs",
        "SSID broadcast must be disabled for bridging"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is typical for standard infrastructure but not mesh. Option B references spanning tree for switches, not mesh Wi-Fi. Option C (correct) is the core advantage of mesh, distributing load among nodes. Option D doesn’t reflect mesh operation.",
      "examTip": "In a wireless mesh, each node can forward traffic to others, expanding coverage organically."
    },
    {
      "id": 31,
      "question": "Which record type ensures that a certain domain name points to another canonical (true) domain name, effectively creating an alias?",
      "options": [
        "MX",
        "A",
        "CNAME",
        "TXT"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A directs mail exchange. Option B provides an IPv4 address. Option C (correct) defines a canonical name alias. Option D is free-form text data.",
      "examTip": "CNAME records allow one domain to act as an alias, avoiding multiple A records for the same resource."
    },
    {
      "id": 32,
      "question": "A network engineer wants to ensure devices from two different subnets in the same VLAN can be quickly discovered and enumerated. Which protocol can help identify attached devices via Layer 2 frames?",
      "options": [
        "DNS",
        "LLDP",
        "NTP",
        "FTP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A resolves domain names, not device discovery on the link layer. Option B (correct) helps discover neighbors over Layer 2. Option C synchronizes clocks, unrelated to device discovery. Option D is file transfer protocol.",
      "examTip": "LLDP (or CDP on Cisco devices) is commonly used to discover directly connected network devices."
    },
    {
      "id": 33,
      "question": "Which of the following is the FIRST step to mitigate a suspected VLAN hopping attack?",
      "options": [
        "Delete all VLANs except the native VLAN",
        "Use SSH instead of Telnet on the switch",
        "Manually specify the trunk native VLAN and disallow auto trunking",
        "Enable jumbo frames to reduce overhead"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is drastic and disrupts normal VLAN segmentation. Option B secures management but not VLAN hopping. Option C (correct) sets a static native VLAN and disables DTP auto trunking, preventing double tagging. Option D does nothing to mitigate VLAN hopping.",
      "examTip": "To prevent VLAN hopping, disable DTP and assign a specific native VLAN on trunk ports."
    },
    {
      "id": 34,
      "question": "A user complains they can’t connect to the network. You notice the switch port is in an “err-disabled” state. What is the MOST likely cause?",
      "options": [
        "Excessive PoE draw from the device",
        "DNS server misconfiguration",
        "Incorrect subnet mask on user PC",
        "DHCP address pool exhaustion"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) can trigger err-disabled if the port detects an over-limit PoE usage or a fault. Option B wouldn’t disable the port at layer 2. Option C wouldn’t typically cause the port to go err-disable. Option D also wouldn’t force the port into err-disable.",
      "examTip": "When a port goes err-disabled, investigate port security, PoE load, or other physical triggers that cause the switch to shut it down."
    },
    {
      "id": 35,
      "question": "You want to capture all traffic passing through a specific port on a switch to analyze it. Which configuration is BEST for this task?",
      "options": [
        "Enable port mirroring (SPAN) to a monitor port",
        "Assign a dynamic IP address to the port",
        "Disable CDP on the interface",
        "Implement ACLs to block inbound traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) copies traffic to a monitoring port for analysis. Option B is for IP configuration, irrelevant to packet capturing. Option C hides device info but doesn’t mirror traffic. Option D blocks traffic instead of capturing it.",
      "examTip": "Use port mirroring (a SPAN session) when you need to send copies of traffic to a packet analyzer."
    },
    {
      "id": 36,
      "question": "A network administrator sees that an interface has incrementing CRC errors. Which layer of the OSI model is MOST likely affected?",
      "options": [
        "Presentation layer",
        "Network layer",
        "Physical layer",
        "Application layer"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A relates to data formatting, not bit-level errors. Option B deals with IP addressing. Option C (correct) indicates physical or data link hardware issues. Option D is user-facing data exchange, not frames or bits.",
      "examTip": "CRC errors typically point to cabling, connectors, or physical interface issues at Layer 1."
    },
    {
      "id": 37,
      "question": "Which of the following is the MOST secure method for a remote user to access internal network resources without installing a local VPN client?",
      "options": [
        "Client-based IPSec tunnel",
        "Clientless SSL VPN via web portal",
        "Telnet session over WAN",
        "FTP file transfers to DMZ"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A requires a local client installed. Option B (correct) uses a browser-based portal for secure remote access. Option C is unencrypted. Option D only handles file transfers and is usually not secure by default.",
      "examTip": "A clientless SSL VPN allows users to securely connect from a web browser without specialized client software."
    },
    {
      "id": 38,
      "question": "Which layer of the OSI model is responsible for maintaining sessions between hosts, such as establishing, controlling, and ending the sessions?",
      "options": [
        "Layer 5",
        "Layer 2",
        "Layer 4",
        "Layer 7"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) is the Session layer that manages interhost communication sessions. Option B is Data Link, Option C is Transport, and Option D is Application. None of those specifically focus on session management.",
      "examTip": "Layer 5 is often overlooked but it’s crucial for starting and ending persistent communication sessions."
    },
    {
      "id": 39,
      "question": "Which would be the FIRST step in investigating a suspected on-path attack (previously known as man-in-the-middle)?",
      "options": [
        "Check for an invalid default gateway MAC",
        "Format the hard drive of the affected workstation",
        "Disable SNMP on all network devices",
        "Delete old VLAN configurations on the switches"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) helps detect ARP poisoning or spoofing that can indicate an on-path scenario. Option B is extreme and unrelated. Option C is about management protocol, not ARP-based attacks. Option D is not specifically relevant to a man-in-the-middle.",
      "examTip": "Check the ARP table and gateway MAC to spot suspicious mappings that might indicate ARP spoofing."
    },
    {
      "id": 40,
      "question": "A user complains about slow network speeds. You confirm no general WAN issues exist. Which parameter is MOST likely to cause local performance bottlenecks?",
      "options": [
        "Mismatched duplex on the switch port",
        "Improper DNS record delegation",
        "High CPU usage on the domain controller",
        "Overlapping channels in the 5GHz band only"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) can drastically reduce speeds if half-duplex conflicts with full-duplex. Option B would cause name resolution issues, not raw speed drops. Option C might affect authentication but not typically cause slow throughput on a single link. Option D is less common for 5GHz, which has more channels.",
      "examTip": "Always verify speed/duplex settings when troubleshooting localized throughput problems."
    },
    {
      "id": 41,
      "question": "Which of the following protocols uses a three-way handshake to establish a reliable connection between hosts?",
      "options": [
        "UDP",
        "TCP",
        "ICMP",
        "GRE"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is connectionless. Option B (correct) initiates connections with SYN, SYN-ACK, and ACK. Option C is used for diagnostics and control messages, not reliable sessions. Option D is a tunneling protocol without built-in reliability.",
      "examTip": "TCP uses a handshake to ensure reliable, ordered data delivery."
    },
    {
      "id": 42,
      "question": "Which scenario-based approach is MOST appropriate for verifying whether an unauthorized DHCP server is active on the network?",
      "options": [
        "Analyze ARP tables to see unexpected MACs",
        "Use a packet sniffer to filter DHCP offer messages",
        "Disable spanning tree on the core switch",
        "Implement DNSSEC to validate DNS requests"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A might find suspicious devices but is less direct. Option B (correct) directly catches rogue DHCP offers. Option C is risky and unrelated to DHCP. Option D is about DNS record security, not DHCP servers.",
      "examTip": "Capturing DHCP traffic is the surest way to spot rogue servers responding to client broadcasts."
    },
    {
      "id": 43,
      "question": "Which command can be used on a Windows machine to view the current IP configuration, including subnet mask and default gateway?",
      "options": [
        "ip addr show",
        "netstat -an",
        "ipconfig",
        "arp -a"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is for Linux systems. Option B displays active connections/ports. Option C (correct) shows IP configuration details on Windows. Option D only shows MAC-to-IP mappings in the ARP cache.",
      "examTip": "Use 'ipconfig' (Windows) or 'ifconfig'/'ip' (Linux) to check IP address, gateway, and DNS settings quickly."
    },
    {
      "id": 44,
      "question": "Which protocol is commonly used for time synchronization across network devices?",
      "options": [
        "SNMP",
        "NTP",
        "HTTP",
        "FTP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A collects management information, not time sync. Option B (correct) synchronizes clocks. Option C is web traffic, and Option D is file transfers.",
      "examTip": "Accurate time is vital for logs and authentication; NTP is the standard for synchronization."
    },
    {
      "id": 45,
      "question": "A wired link between two switches sometimes goes down. The cable length is near maximum for Cat5e. Which approach is BEST to maintain a stable connection?",
      "options": [
        "Disable 802.1Q trunking",
        "Use a single-mode fiber cable instead",
        "Change the IP addressing scheme",
        "Upgrade to Cat3 cables"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A trunking removal doesn't fix signal integrity. Option B (correct) ensures better distance support and fewer interference issues. Option C won't affect physical layer reliability. Option D is a downgrade from Cat5e.",
      "examTip": "For long distances or questionable copper runs, fiber often provides a more reliable physical medium."
    },
    {
      "id": 46,
      "question": "Which AAA protocol uses TCP and encrypts the entire authentication payload, making it more secure for device administration access?",
      "options": [
        "RADIUS",
        "TACACS+",
        "LDAP",
        "LDAPS"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A uses UDP and only partially encrypts packets. Option B (correct) uses TCP and fully encrypts. Option C is a directory service protocol, not specifically AAA. Option D is LDAP over SSL but still not the typical AAA method for network devices.",
      "examTip": "TACACS+ is often preferred for device administration because it encrypts the entire session."
    },
    {
      "id": 47,
      "question": "A technician wants to confirm whether a specific IP is reachable and measure the path to that destination. Which command is MOST useful?",
      "options": [
        "ping",
        "traceroute/tracert",
        "arp -a",
        "nslookup"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A checks reachability but not each hop. Option B (correct) identifies the path hop-by-hop. Option C shows ARP cache, not path. Option D resolves DNS queries, unrelated to path determination.",
      "examTip": "Use traceroute (Linux) or tracert (Windows) to map the route packets take to a destination."
    },
    {
      "id": 48,
      "question": "A company's public web server must handle heavy traffic loads. Which device is BEST suited for distributing incoming requests across multiple back-end servers?",
      "options": [
        "Layer 2 switch",
        "Load balancer",
        "Content filter",
        "Proxy server"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A simply switches packets at layer 2. Option B (correct) distributes requests to multiple servers, ensuring better performance. Option C typically inspects or restricts content. Option D caches or modifies requests, not necessarily balancing load among servers.",
      "examTip": "Load balancers help optimize traffic distribution, crucial for large-scale web services."
    },
    {
      "id": 49,
      "question": "Which of the following is a benefit of VLAN trunking using 802.1Q?",
      "options": [
        "Eliminates broadcast traffic on the network",
        "Carries multiple VLAN traffic over a single link",
        "Merges DHCP and DNS services into one VLAN",
        "Enables encryption of all VLAN data in transit"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A can’t fully eliminate broadcasts. Option B (correct) encapsulates VLAN tags so multiple VLANs can share one physical link. Option C is unrelated to trunking. Option D standard 802.1Q does not encrypt traffic.",
      "examTip": "802.1Q tagging is the standard for carrying multiple VLANs across a single trunk link."
    },
    {
      "id": 50,
      "question": "Which layer of the OSI model handles data encryption and decryption, as well as format changes (like compression) before passing data to the application?",
      "options": [
        "Layer 6",
        "Layer 2",
        "Layer 4",
        "Layer 7"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) is the Presentation layer, which deals with data formatting, encryption, and compression. Option B is Data Link. Option C is Transport. Option D is Application, which interacts with end-user software.",
      "examTip": "Layer 6 is often overlooked but crucial for encryption and data format transformations."
    },
    {
      "id": 51,
      "question": "In a high-availability design, which approach uses active-active node pairs, ensuring both nodes are processing traffic simultaneously?",
      "options": [
        "VRRP with a single master",
        "Hot standby with a passive secondary",
        "Active-active clustering",
        "Backup tapes stored offsite"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A typically has one active node. Option B describes active-passive, not active-active. Option C (correct) both devices share load. Option D is offline backups, unrelated to real-time traffic sharing.",
      "examTip": "Active-active configurations maximize resource usage, but require careful synchronization between nodes."
    },
    {
      "id": 52,
      "question": "Which scenario-based question is BEST for mitigating a DNS poisoning attack on your network?",
      "options": [
        "Implement DNSSEC to validate DNS responses",
        "Use Telnet for internal DNS queries",
        "Configure jumbo frames on all DNS servers",
        "Force an SSL VPN for all DNS traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) ensures DNS data authenticity via signatures. Option B is insecure for DNS server management. Option C doesn’t protect DNS query integrity. Option D is not standard for DNS queries and doesn’t specifically mitigate poisoning.",
      "examTip": "DNSSEC helps prevent spoofed DNS responses by verifying cryptographic signatures."
    },
    {
      "id": 53,
      "question": "Which of these is the FIRST thing to verify when your device fails to obtain an IPv4 address via DHCP?",
      "options": [
        "Check if STP is configured in Rapid mode",
        "Confirm the DHCP server scope and lease availability",
        "Enable domain controller role on the server",
        "Use NAT on the client interface"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A covers loop protection, not IP address assignment. Option B (correct) ensures the server can still hand out addresses. Option C is unrelated to DHCP. Option D is for translating private IPs to public, not address assignment.",
      "examTip": "Always verify the DHCP scope has addresses left and is properly configured before checking more complex issues."
    },
    {
      "id": 54,
      "question": "Which of the following methods is BEST for preventing unauthorized users from simply plugging into an open office Ethernet jack and accessing your internal LAN?",
      "options": [
        "Disable SSL on the local router",
        "Implement NAC with 802.1X authentication",
        "Enable DNS caching on every switch port",
        "Adopt a static routing protocol"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is irrelevant to LAN port security. Option B (correct) requires users to authenticate before gaining network access. Option C doesn’t control access. Option D is about routing, not controlling port access.",
      "examTip": "NAC (with 802.1X) ensures only authenticated, compliant endpoints can communicate on your network."
    },
    {
      "id": 55,
      "question": "A user calls in complaining that while on Wi-Fi, they randomly lose connectivity but can reconnect after moving. Which factor is MOST likely the cause?",
      "options": [
        "802.1Q trunk error",
        "Mismatched VLAN ID on trunk port",
        "Co-channel or adjacent channel interference",
        "DHCP lease is too long"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is a wired trunking issue. Option B also pertains to a wired VLAN misconfiguration. Option C (correct) describes a common Wi-Fi coverage or channel overlap problem. Option D does not usually cause random disconnects.",
      "examTip": "Wireless interference from overlapping channels often causes dropped connections, especially if AP coverage is not well planned."
    },
    {
      "id": 56,
      "question": "A user cannot browse internal resources, but can ping IP addresses internally. Which is the FIRST item to check?",
      "options": [
        "DNS server configuration on the user’s device",
        "Spanning tree root bridge ID",
        "Subnet mask on the DHCP pool",
        "Switch’s VLAN trunking protocol"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) is critical if name resolution fails while IP connectivity works. Option B deals with loop prevention, less likely the cause. Option C can cause broader connectivity issues, but user pings are successful so it’s not the mask. Option D is unrelated if pings already succeed across subnets.",
      "examTip": "When IP pings succeed but domain-based browsing fails, DNS is the prime suspect."
    },
    {
      "id": 57,
      "question": "During a DoS attack, you see excessive half-open TCP connections. Which concept does this specifically reference?",
      "options": [
        "SYN flood",
        "ARP spoofing",
        "Fraggle attack",
        "Ping of death"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) is a classic half-open connection flood. Option B modifies ARP caches. Option C uses UDP echo traffic. Option D involves oversized ICMP packets, not half-open states.",
      "examTip": "A SYN flood sends repeated SYNs without completing the handshake, overwhelming a server’s half-open connections."
    },
    {
      "id": 58,
      "question": "Which of these is a direct benefit of using SNMPv3 over SNMPv1?",
      "options": [
        "Simplified community strings",
        "Shorter MIB definitions",
        "Encrypted authentication and data",
        "Real-time packet capturing"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is a legacy concept for SNMPv1/v2c. Option B is not a version difference. Option C (correct) is a key enhancement: authentication and encryption. Option D is a separate function not provided by SNMP.",
      "examTip": "SNMPv3 adds security by encrypting data and requiring authentication, unlike v1/v2c’s clear-text approach."
    },
    {
      "id": 59,
      "question": "You’re troubleshooting a slow file transfer across the WAN. A packet capture shows significant TCP retransmissions. Which is the MOST likely cause?",
      "options": [
        "Link is set to half-duplex at both ends",
        "Network cable is physically broken",
        "Excessive packet loss on the WAN link",
        "DNS is misconfigured"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A might cause collisions but typically you’d see runts/errors. Option B is total link failure. Option C (correct) triggers frequent retransmits due to lost segments. Option D would not cause retransmissions, just name resolution issues.",
      "examTip": "High retransmissions usually indicate packet loss or congestion on the link."
    },
    {
      "id": 60,
      "question": "Which device aggregates LAN traffic and operates primarily at Layer 2, forwarding frames based on MAC addresses?",
      "options": [
        "Router",
        "Hub",
        "Switch",
        "Firewall"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A operates at Layer 3. Option B is a basic repeater with no MAC table. Option C (correct) is a typical Layer 2 forwarding device. Option D typically inspects or filters traffic at various layers, not strictly based on MAC addresses.",
      "examTip": "Switches learn MACs to forward traffic at Layer 2, improving efficiency over hubs."
    },
    {
      "id": 61,
      "question": "A company wants to hide internal addressing and allow multiple clients to share a single public IP for outbound internet traffic. Which technology BEST meets this goal?",
      "options": [
        "DHCP reservations",
        "Port address translation (PAT)",
        "Spanning tree protocol",
        "IPSec encryption"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A ensures static IP mapping from DHCP, not address sharing. Option B (correct) translates many private IPs to one public IP using different ports. Option C is a loop-prevention protocol. Option D encrypts data but doesn't handle address sharing.",
      "examTip": "PAT is a common variant of NAT that allows multiple internal devices to share a single external IP."
    },
    {
      "id": 62,
      "question": "Which immediate action is the BEST FIRST step to secure a newly purchased switch before deployment?",
      "options": [
        "Enable port mirroring",
        "Update firmware to the latest supported version",
        "Activate jumbo frames for all ports",
        "Configure jumbo VLANs"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A only provides monitoring. Option B (correct) addresses known vulnerabilities and ensures current security patches. Option C is not primarily a security measure. Option D is not a standard term or security approach.",
      "examTip": "Always patch and update network equipment firmware before production deployment to address security fixes."
    },
    {
      "id": 63,
      "question": "A user receives an IP in the 169.254.x.x range. Which conclusion is MOST accurate?",
      "options": [
        "DHCP provided an extended lease",
        "APIPA assigned an address due to DHCP failure",
        "DNS is incorrectly set to a public server",
        "The interface is operating in promiscuous mode"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is incorrect; 169.254.x.x is not a typical DHCP range. Option B (correct) indicates Automatic Private IP Addressing. Option C is about domain name resolution, not address assignment. Option D is about capturing traffic, not IP assignment.",
      "examTip": "169.254.x.x addresses typically mean a device couldn’t contact the DHCP server and self-assigned an APIPA address."
    },
    {
      "id": 64,
      "question": "Which type of record in DNS allows reverse lookup from an IP address to a domain name?",
      "options": [
        "NS record",
        "PTR record",
        "A record",
        "CNAME record"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A identifies a DNS nameserver. Option B (correct) is used for reverse DNS lookups. Option C is forward lookup from domain to IP. Option D is an alias record, not reverse lookup.",
      "examTip": "PTR records link IP addresses back to hostnames, enabling reverse DNS queries."
    },
    {
      "id": 65,
      "question": "While reviewing switch logs, you find a port that repeatedly transitions from up to down. Which is the FIRST step to isolate the cause?",
      "options": [
        "Assign a static IP to the interface",
        "Move the cable to a different port and retest",
        "Disable the native VLAN on the trunk",
        "Reboot the entire switch"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A addresses IP but not physical flapping. Option B (correct) tests if the port or cable is faulty. Option C is unrelated to link status flaps. Option D is too disruptive for a first step.",
      "examTip": "Always try swapping cables or ports to determine if the issue follows the cable/device or remains on the port."
    },
    {
      "id": 66,
      "question": "Which protocol uses port 23 and is considered insecure for remote management tasks?",
      "options": [
        "SSH",
        "Telnet",
        "HTTP",
        "RDP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A (port 22) is secure shell, not port 23. Option B (correct) uses port 23 and is unencrypted. Option C is port 80 for web traffic. Option D is port 3389 for remote desktop.",
      "examTip": "Telnet sends data in clear text; modern networks typically use SSH instead."
    },
    {
      "id": 67,
      "question": "After running a network cable near heavy machinery, you see constant CRC errors. Which cable type would MOST likely mitigate this issue?",
      "options": [
        "UTP Cat5e",
        "STP Cat6 or better",
        "Thin coaxial cable",
        "Plenum-rated Cat5"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A offers no shielding. Option B (correct) has shielding to reduce EMI. Option C is rarely used in modern LANs. Option D is for fire code compliance, not necessarily EMI reduction.",
      "examTip": "Shielded twisted pair helps protect signals from external electromagnetic interference, especially around industrial equipment."
    },
    {
      "id": 68,
      "question": "Which scenario-based question is BEST addressed by implementing Quality of Service (QoS)?",
      "options": [
        "How to restrict employees from visiting social media sites",
        "How to ensure voice traffic has priority over regular data",
        "How to physically secure the IDF racks from theft",
        "How to encrypt all web-based application sessions"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is a content filtering issue. Option B (correct) is a classic use case for QoS. Option C is a physical security matter. Option D is encryption, not traffic prioritization.",
      "examTip": "QoS ensures mission-critical or latency-sensitive traffic (e.g., VoIP) receives higher priority on the network."
    },
    {
      "id": 69,
      "question": "Which of the following is the FIRST step in the standard troubleshooting methodology?",
      "options": [
        "Establish a plan of action",
        "Test the theory to determine cause",
        "Identify the problem",
        "Establish a theory of probable cause"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A occurs after determining the cause. Option B happens after forming a theory. Option C (correct) is the initial step in any troubleshooting process. Option D is the next step after identifying the problem.",
      "examTip": "Always start by clearly identifying or defining the issue: gather symptoms, question users, replicate if possible."
    },
    {
      "id": 70,
      "question": "A newly installed switch needs to connect to a router for inter-VLAN routing. Which interface configuration on the router is commonly used for multiple VLANs over a single link?",
      "options": [
        "Subinterfaces on a router-on-a-stick",
        "Separate physical interfaces for each VLAN",
        "A trunk port on the router in half-duplex",
        "Assign NAT to each VLAN interface"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) is the classic router-on-a-stick approach for inter-VLAN routing. Option B is feasible but not common if physical interfaces are limited. Option C is typically full-duplex trunking, but routers seldom do trunking the same way as switches. Option D is for address translation, not VLAN routing.",
      "examTip": "Router-on-a-stick uses subinterfaces with 802.1Q tagging to route multiple VLANs over one physical interface."
    },
    {
      "id": 71,
      "question": "A device must always receive the same IP from DHCP. Which approach is BEST?",
      "options": [
        "Configure a DHCP reservation for its MAC address",
        "Use APIPA for guaranteed consistent addressing",
        "Flush the DNS records daily",
        "Force DHCP relay from a different subnet"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) associates a device’s MAC with a specific IP in DHCP. Option B only occurs when DHCP fails. Option C is about name resolution, not IP assignment. Option D simply forwards DHCP, not guaranteeing a specific IP.",
      "examTip": "DHCP reservations tie a MAC address to a specific IP, ensuring consistent address assignment."
    },
    {
      "id": 72,
      "question": "Which statement is TRUE about an evil twin attack in a Wi-Fi environment?",
      "options": [
        "It floods the switch port with bogus MAC addresses",
        "It uses ARP poisoning to intercept packets on the LAN",
        "It sets up a rogue AP mimicking a legitimate SSID",
        "It physically disables the real AP’s antennas"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is a switch-based MAC flooding. Option B is ARP spoofing. Option C (correct) duplicates a legitimate SSID to trick users. Option D is unlikely and not typical of an evil twin approach.",
      "examTip": "Evil twin attacks create a malicious AP with the same SSID so users mistakenly connect and divulge data."
    },
    {
      "id": 73,
      "question": "Which command-line tool would you use on a Linux system to capture and analyze traffic in real time for troubleshooting?",
      "options": [
        "tcpdump",
        "ipconfig",
        "dig",
        "ifconfig"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) captures live network traffic at the command line. Option B is a Windows utility. Option C queries DNS. Option D shows interface settings but doesn’t capture traffic.",
      "examTip": "tcpdump is a powerful CLI packet capture tool for Linux/Unix systems."
    },
    {
      "id": 74,
      "question": "Management wants to ensure all new devices connecting to the network meet certain security criteria before accessing resources. Which technology is BEST suited?",
      "options": [
        "Network Access Control (NAC)",
        "Trivial File Transfer Protocol (TFTP)",
        "IPSec site-to-site tunnel",
        "802.3af PoE injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) enforces posture checks and authentication before granting full access. Option B is a basic file transfer protocol, not security posture. Option C secures traffic between sites, not local endpoints. Option D is power over Ethernet, unrelated to security checks.",
      "examTip": "NAC solutions often use 802.1X or agent-based posture checks to ensure compliance before allowing network access."
    },
    {
      "id": 75,
      "question": "A user is downloading large files from the internal file server, causing network congestion. Which technique can you implement to ensure critical VoIP traffic is not disrupted?",
      "options": [
        "Configure port mirroring",
        "Apply QoS prioritization for voice packets",
        "Split tunnel the VPN",
        "Assign a static IP to the file server"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A only monitors traffic. Option B (correct) ensures voice is prioritized over bulk data. Option C is a VPN design choice, not local traffic prioritization. Option D does not address congestion management.",
      "examTip": "Quality of Service helps preserve real-time application performance when network resources are constrained."
    },
    {
      "id": 76,
      "question": "Which of these is a security advantage of using a proxy server for outbound web traffic?",
      "options": [
        "Redirects DNS queries to local servers",
        "Masks internal client IP addresses from external hosts",
        "Provides layer 2 loop prevention features",
        "Enforces jumbo frames for all traffic"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is more about DNS settings. Option B (correct) proxies requests so external servers see the proxy IP, not the actual client. Option C is done by spanning tree, not a proxy. Option D is a performance setting, not a security benefit.",
      "examTip": "A proxy can hide internal host identities and enforce content filtering or logging for security purposes."
    },
    {
      "id": 77,
      "question": "A router is configured for PAT. Which statement BEST describes how outbound connections from multiple internal hosts share a single public IP?",
      "options": [
        "Each host uses the same public IP but different external ports",
        "Hosts share the same port number but different NAT pools",
        "A default route is not needed in this scenario",
        "All traffic is broadcast to the external interface"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) is exactly how PAT works: unique source port assignments for each internal host. Option B is reversed. Option C is false; a default route is typically still required. Option D is incorrect, as NAT does not broadcast traffic.",
      "examTip": "Port Address Translation modifies the source port for each internal host to uniquely map to one public IP."
    },
    {
      "id": 78,
      "question": "You’re setting up an IPSec VPN tunnel. Which component of IPSec provides both authentication and encryption for the data payload?",
      "options": [
        "AH (Authentication Header)",
        "ESP (Encapsulating Security Payload)",
        "GRE (Generic Routing Encapsulation)",
        "IKE (Internet Key Exchange)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A only authenticates headers, not encrypting data. Option B (correct) encrypts and authenticates data. Option C is a tunneling protocol without native security. Option D negotiates keys, but does not carry the data encryption itself.",
      "examTip": "ESP is crucial for confidentiality and integrity in IPSec VPN tunnels."
    },
    {
      "id": 79,
      "question": "Which command shows the MAC address table on a Cisco switch for verifying learned addresses?",
      "options": [
        "show mac-address-table",
        "show arp",
        "show interface trunk",
        "show spanning-tree"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) displays the table mapping MACs to ports. Option B shows IP-to-MAC mappings, typically from an ARP cache. Option C shows trunking info. Option D shows STP status and port roles.",
      "examTip": "Use 'show mac-address-table' to confirm which MACs are learned on which switch ports."
    },
    {
      "id": 80,
      "question": "Which action is MOST appropriate FIRST when noticing a series of MAC addresses flooding a switch port, potentially indicating an attack?",
      "options": [
        "Shut down the port and investigate",
        "Reload the switch’s configuration file",
        "Reboot all connected endpoints",
        "Increase the VLAN pool to accommodate more MACs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) immediately isolates the threat and prevents further flooding. Option B may reapply config but doesn’t stop the live attack. Option C disrupts legitimate endpoints unnecessarily. Option D is the opposite of security best practice, allowing more addresses.",
      "examTip": "When detecting a malicious flood, isolating the affected port is crucial to prevent further impact."
    },
    {
      "id": 81,
      "question": "A company's regulations demand that all data center switch configurations be archived daily for quick recovery. Which practice BEST accomplishes this?",
      "options": [
        "Periodic port mirroring sessions",
        "Automated configuration backups to a central repository",
        "Implement DHCP for all switch IP addressing",
        "Enable IPv6 dual-stack on each switch"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A captures traffic, not switch config. Option B (correct) ensures config files are saved and recoverable. Option C is an IP assignment practice, not config backup. Option D is a protocol approach, not a backup strategy.",
      "examTip": "Regular automatic backups of device configs are a key part of robust change management processes."
    },
    {
      "id": 82,
      "question": "Which of the following best describes a rogue DHCP server?",
      "options": [
        "A DHCP server that uses DNSSEC for secure updates",
        "A malicious or unauthorized server handing out IP addresses",
        "A server that runs out of IP addresses for clients",
        "A DHCP server only accessible via IPv6"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is legitimate secure DNS updates. Option B (correct) is an unauthorized device providing incorrect IP settings. Option C is a capacity issue, not necessarily rogue. Option D doesn’t define rogue behavior, just IPv6 usage.",
      "examTip": "A rogue DHCP server can disrupt the network by assigning invalid or malicious configurations to clients."
    },
    {
      "id": 83,
      "question": "A technician investigating a connectivity issue sees the gateway has an IP of 192.168.0.1/24 while the user's PC is configured as 192.168.1.10/24. What is the problem?",
      "options": [
        "Duplicate IP addresses detected",
        "Incorrect subnet assignment blocks local gateway reachability",
        "Gateway IP is in the broadcast domain",
        "DHCP scope mismatch on the router"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is not indicated. Option B (correct) the user is on 192.168.1.x/24 and gateway is on 192.168.0.x/24, so no local route. Option C is not specifically an error. Option D might be possible but the direct issue is the mismatch between subnets.",
      "examTip": "For a /24 mask, the network portion must match for the PC to see its default gateway."
    },
    {
      "id": 84,
      "question": "Which approach ensures that a newly deployed AP is broadcasting at appropriate power levels and channels?",
      "options": [
        "Using a Wi-Fi analyzer to perform a site survey",
        "Enabling RSTP on the AP",
        "Forcing 802.11b compatibility mode",
        "Ignoring local regulations and using maximum power"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) identifies coverage and interference. Option B is a spanning tree protocol for switches. Option C reverts to an older standard, potentially reducing speed. Option D risks regulatory noncompliance and interference.",
      "examTip": "Site surveys help optimize channel selection and power settings for new wireless deployments."
    },
    {
      "id": 85,
      "question": "Which scenario-based question is BEST resolved by implementing a captive portal?",
      "options": [
        "How to provide guests with temporary Wi-Fi access without giving them domain credentials",
        "How to route traffic between VLANs more efficiently",
        "How to diagnose cable continuity issues",
        "How to encrypt back-end server traffic using SSL"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) captive portals allow guests to authenticate on a splash page. Option B involves routing or switching, not a captive portal. Option C is a physical-layer test. Option D is encryption best practices, not a portal solution.",
      "examTip": "Captive portals are common for guest Wi-Fi access, requiring acceptance of terms or credentials via a web page."
    },
    {
      "id": 86,
      "question": "A technician is setting a static route on a router. Which parameter must be specified along with the destination network and subnet mask?",
      "options": [
        "Administrative distance",
        "Next-hop IP address or exit interface",
        "Local VLAN ID",
        "Default DNS server"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is optional and can be assumed. Option B (correct) is needed so the router knows where to send traffic. Option C is a switching concept, not relevant to routing. Option D is for name resolution, not routing.",
      "examTip": "A static route requires the destination network, subnet mask, and the next hop (or outgoing interface)."
    },
    {
      "id": 87,
      "question": "Which of the following is TRUE regarding DNS over HTTPS (DoH)?",
      "options": [
        "It resolves addresses using MAC-based filtering",
        "It encrypts DNS queries within HTTPS, enhancing privacy",
        "It only applies to IPv6 networks",
        "It automatically sets up a VPN tunnel for DNS"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is unrelated. Option B (correct) DoH secures DNS queries through HTTPS. Option C works with both IPv4 and IPv6. Option D is not how DoH operates; it doesn’t create a VPN.",
      "examTip": "DNS over HTTPS helps prevent eavesdropping or manipulation of DNS traffic by encrypting it."
    },
    {
      "id": 88,
      "question": "Which feature can dynamically combine multiple physical switch ports into a single logical channel for increased throughput and redundancy?",
      "options": [
        "Port mirroring",
        "Link aggregation (LACP)",
        "SNMPv3 traps",
        "DHCP scope options"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A copies traffic, not bandwidth. Option B (correct) bundles links for higher aggregate bandwidth. Option C is for management notifications. Option D sets IP parameters for clients, not channel bonding.",
      "examTip": "Link aggregation groups multiple ports to act as one, boosting bandwidth and fault tolerance."
    },
    {
      "id": 89,
      "question": "A user with a mission-critical role must have priority traffic for IP telephony. Which is the MOST direct method to ensure their VoIP packets are prioritized?",
      "options": [
        "Implement port security on their switch port",
        "Configure DSCP markings and apply QoS",
        "Use a separate unmanaged switch",
        "Block all non-VoIP traffic at the firewall"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A controls device MAC addresses, not QoS. Option B (correct) sets QoS policies using DSCP to prioritize voice. Option C removes management, not helpful. Option D is too restrictive and can break other needed services.",
      "examTip": "Differentiated Services Code Point (DSCP) is widely used to classify and prioritize traffic for QoS policies."
    },
    {
      "id": 90,
      "question": "Which direct question addresses implementing IPv6 to reduce address exhaustion while allowing some IPv4 to remain active?",
      "options": [
        "Can we run dual stack on devices supporting both IPv4 and IPv6?",
        "Should we remove all NAT configuration from the router?",
        "Will 802.1Q trunking reduce IPv4 usage?",
        "Should we disable TCP in favor of UDP for all traffic?"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) is the essence of dual stack. Option B can still be needed for internet access. Option C only relates to VLAN tagging. Option D does not solve IP addressing constraints.",
      "examTip": "Dual stack is often the easiest transition method, letting IPv4 and IPv6 coexist on the same devices."
    },
    {
      "id": 91,
      "question": "Which type of firewall is placed between the internal network and a DMZ, forwarding traffic to the public-facing servers while monitoring for threats?",
      "options": [
        "Next-generation firewall",
        "Stateful packet filter on the core switch",
        "Transparent bridging device",
        "Content filter proxy"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) typically has advanced inspection (Layer 7, IPS, etc.) for DMZ traffic. Option B is a simpler solution, might not provide full NGFW features. Option C is a bridging approach, not a typical DMZ firewall. Option D focuses on web content, not the entire DMZ security.",
      "examTip": "A next-generation firewall often sits at the network edge/DMZ to inspect traffic deeply and provide advanced threat protection."
    },
    {
      "id": 92,
      "question": "Which tool can confirm the presence of a continuous cable path and pinpoint breaks by sending a tone down the cable and tracing it?",
      "options": [
        "Protocol analyzer",
        "Toner probe",
        "Wi-Fi analyzer",
        "Nmap"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A inspects packet data, not physical cable runs. Option B (correct) helps locate cables and breaks with audible tone. Option C checks wireless signals. Option D scans network hosts and ports.",
      "examTip": "A toner probe kit is essential for tracing cables hidden in walls or cable bundles."
    },
    {
      "id": 93,
      "question": "A network administrator needs to create an IPsec tunnel. Which phase establishes the secure channel for key exchange and negotiation before data encryption begins?",
      "options": [
        "IKE Phase 1",
        "DNS resolution",
        "ESP key distribution phase",
        "DHCP lease acquisition"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) is the phase where secure negotiation is set (ISAKMP/IKE). Option B is name resolution, unrelated. Option C is part of IPsec data encryption but not the negotiation handshake. Option D is for IP address assignment, not IPsec negotiation.",
      "examTip": "IKE Phase 1 sets up a secure channel (ISAKMP SA); then Phase 2 negotiates actual IPsec SAs for data traffic."
    },
    {
      "id": 94,
      "question": "Which of the following is the BEST approach to handle a router interface that frequently crashes due to unknown software bugs?",
      "options": [
        "Swap the Ethernet cable",
        "Disable port security on that interface",
        "Update the router’s firmware to the latest version",
        "Increase the DHCP lease time"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A might fix physical issues but not software bugs. Option B is security, not a bug fix. Option C (correct) addresses known software or firmware issues. Option D affects IP address renewal intervals, not router crashes.",
      "examTip": "Keeping firmware up to date often resolves stability issues and security vulnerabilities."
    },
    {
      "id": 95,
      "question": "A data center migration requires that in case of failure, services can spin up quickly at a second site. Which concept ensures the secondary site is up but only partially configured, requiring some final steps?",
      "options": [
        "Active-active high availability",
        "Warm site",
        "Hot site",
        "Cold site"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is fully operational at both locations. Option B (correct) is partially ready, requiring moderate setup. Option C is fully ready to go. Option D has minimal resources and requires the most setup.",
      "examTip": "A warm site has hardware and some data, but requires additional steps to become fully operational after a disaster."
    },
    {
      "id": 96,
      "question": "Which is the FIRST step to take when a user's interface counters show a high number of runts and giants?",
      "options": [
        "Implement a full network redesign",
        "Check for speed/duplex mismatch",
        "Change DNS servers",
        "Re-enable spanning tree on core switches"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is extreme. Option B (correct) often causes frame size mismatches. Option C is unrelated to frame errors. Option D is for loop prevention, not frame anomalies.",
      "examTip": "Runts and giants often point to layer 1 or 2 configuration mismatches, like incorrect speed/duplex or MTU settings."
    },
    {
      "id": 97,
      "question": "A core router’s routing table shows two entries for 192.168.10.0/24: one via OSPF (AD 110) and one via RIP (AD 120). Which route will the router prefer and why?",
      "options": [
        "RIP, because it is simpler to configure",
        "OSPF, because it has a lower administrative distance",
        "RIP, because it has a lower hop count metric",
        "OSPF, because it uses a link-state database"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is irrelevant to route choice. Option B (correct) OSPF’s AD of 110 is preferred over RIP’s 120. Option C doesn’t matter if the route from RIP has a lower hop count, AD still decides. Option D is partial reasoning but the key is administrative distance priority.",
      "examTip": "When multiple routing protocols advertise the same network, the router installs the route with the lowest AD."
    },
    {
      "id": 98,
      "question": "Which scenario-based question is BEST solved by implementing HIDS/HIPS on critical servers?",
      "options": [
        "How to route VLAN traffic faster in the core",
        "How to detect malicious activities directly on a host in real time",
        "How to ensure DNS queries are resolved quickly",
        "How to reduce cable clutter in the server rack"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is a switching or routing design. Option B (correct) host intrusion detection/prevention detects system-level threats. Option C is performance or DNS caching. Option D is a physical organization issue, not security.",
      "examTip": "HIDS/HIPS solutions inspect host-level activity and can block or alert on abnormal behavior in real time."
    },
    {
      "id": 99,
      "question": "You discover that a broadcast storm is affecting the network. Which feature is designed to block redundant links and prevent loops at Layer 2?",
      "options": [
        "STP (Spanning Tree Protocol)",
        "ICMP redirect",
        "DHCP snooping",
        "Reverse Proxy"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) blocks loops by electing a root bridge and disabling certain ports. Option B is used by routers to direct traffic. Option C monitors DHCP traffic for rogue servers, not loops. Option D is an application-layer service, not for loop prevention.",
      "examTip": "STP is essential in switched networks to avoid bridging loops that can cause broadcast storms."
    },
    {
      "id": 100,
      "question": "Which single action can MOST reduce the blast radius of an internal network breach?",
      "options": [
        "Use VLANs to segment critical systems from other hosts",
        "Disable QoS to reduce overhead",
        "Configure jumbo frames for all traffic",
        "Reserve an IP for each device using DHCP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) network segmentation limits movement within the environment if a breach occurs. Option B is about traffic prioritization, not security segmentation. Option C is for performance, not security. Option D ensures consistent IP assignment but doesn’t prevent lateral movement.",
      "examTip": "Segmentation—via VLANs or subnets—helps contain a compromised device to a smaller portion of the network."
    }
  ]
});
