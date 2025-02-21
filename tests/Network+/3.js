db.tests.insertOne({
  "category": "nplus",
  "testId": 3,
  "testName": "Network Practice Test #3 (Easy)",
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
      "explanation": "Utilize GRE tunnels without any encryption lacks native encryption, leaving data exposed. Configure a site-to-site VPN with IPSec (correct) creates an encrypted IPSec tunnel, ensuring confidentiality and integrity. Enable Telnet for remote device management uses a plaintext protocol, unsafe for sensitive traffic. Implement unencrypted HTTP sessions only fails to secure any data with encryption.",
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
      "explanation": "Replace all network cables immediately is premature without confirming physical issues. Check interface statistics and error counters (correct) helps pinpoint issues like CRC errors or drops. Restart both routers to clear sessions can resolve some issues temporarily but doesn't diagnose root causes. Reduce the MTU size on both ends is only relevant if MTU mismatch is proven.",
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
      "explanation": "Enable WPA3-Personal with a shared passphrase uses a single shared password, not unique per user. Implement MAC filtering on all access points is weak because MAC addresses can be spoofed. Use WPA2-Enterprise with 802.1X authentication (correct) forces individual user authentication via RADIUS/802.1X. Disable SSID broadcast to conceal the network only obscures the SSID but doesn't strengthen credentials.",
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
      "explanation": "Review the default gateway settings (correct) quickly verifies if traffic is properly routed out of the local subnet. Assign a static IP address to the user is arbitrary and ignores underlying routing or DHCP issues. Disable all firewall rules could expose the network to threats and isn’t a diagnostic approach. Change the DNS server to 8.8.8.8 might solve DNS issues but not general connectivity if gateway is wrong.",
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
      "explanation": "A layer 2 switch with trunk ports only switches traffic at layer 2; it can’t route VLANs without external routing. A layer 3 switch with SVIs (correct) provides inter-VLAN routing via Switch Virtual Interfaces efficiently. A basic consumer-grade router can route, but typically less performant for large VLAN deployments. A wireless access point using WPA2 is unrelated to VLAN routing needs.",
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
      "explanation": "Implement VLANs on the switch ports (correct) logically segments traffic with VLANs, a standard method for separation. Use static IP addresses on guest devices alone won’t separate traffic at layer 2 or layer 3. Disable DHCP on all internal VLANs is not directly related to segmentation and complicates network management. Set MAC filtering on each internal port does not truly segregate guest from internal traffic, only restricts devices by MAC.",
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
      "explanation": "Configure DNS with multiple record types is unrelated to broadcast domains. Enable spanning tree protocol (correct) uses STP to block redundant paths and prevent loops. Increase router NAT table size has no effect on layer 2 broadcast storms. Disable syslog on all devices does not influence broadcast traffic control.",
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
      "explanation": "Session layer (Layer 5) deals with interhost communication sessions. Network layer (Layer 3) (correct) is where IP addresses and TTL fields exist, so TTL expiration is handled there. Transport layer (Layer 4) involves ports and reliable data transport, not IP TTL. Data link layer (Layer 2) handles physical addressing, not TTL.",
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
      "explanation": "Port 389 is LDAP (plain text). Port 636 (correct) is the standard LDAPS port. Port 443 is HTTPS, unrelated to LDAP. Port 161 is SNMP, not LDAP.",
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
      "explanation": "Switch to 802.11a-only for all clients forces older standard usage and won’t fix channel overlap. Use channels 1, 6, and 11 for APs (correct) uses non-overlapping channels in 2.4 GHz. Increase transmit power to overpower interference typically worsens adjacent channel interference. Enable MAC filtering on the AP doesn’t affect channel overlap.",
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
      "explanation": "Wireless analyzer is for Wi-Fi signals, not copper cable integrity. Protocol analyzer captures traffic, not physical cable faults. Cable tester (correct) verifies continuity and wire mapping. Port mirroring session only duplicates traffic to another port for analysis, not confirming cable status.",
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
      "explanation": "GRE encapsulation alone lacks encryption by default. IPSec VPN using ESP (correct) uses Encapsulating Security Payload (ESP) for both encryption and integrity. Clear-text HTTP sessions is not encrypted. SNMPv1 traps is outdated and does not protect data in transit.",
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
      "explanation": "Change native VLAN to 10 on the trunk only sets VLAN 10 as native, which may not help if VLAN 10 isn’t allowed on the trunk. Add VLAN 10 to the trunk allowed list (correct) ensures the trunk passes VLAN 10 traffic. Reboot the users’ PCs to renew leases won’t resolve a trunk misconfiguration. Disable STP on the trunk interface is dangerous and unrelated.",
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
      "explanation": "Assign a static IP and hope it resolves is a workaround, not a diagnosis. Check DHCP scope options and available leases (correct) checks if the scope is exhausted or misconfigured. Manually flush DNS cache on the server deals with name resolution, not address leasing. Disable RSTP on the switches is unrelated to DHCP address allocation.",
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
      "explanation": "Dual stack uses both IPv4 and IPv6 stacks simultaneously but does not encapsulate traffic. Tunneling (correct) encapsulates IPv6 in IPv4 for transition. NAT64 translates IPv6 addresses to IPv4 addresses, not strictly encapsulation. APIPA is a fallback for IPv4 addresses, not an IPv6 transition mechanism.",
      "examTip": "Tunneling is a common method for integrating IPv6 traffic into existing IPv4 networks without translation."
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
      "explanation": "ARP resolves MAC addresses, not gateway redundancy. DNSSEC secures DNS records, not gateways. HTTP is a web protocol, irrelevant to default gateway HA. VRRP (correct) is a First Hop Redundancy Protocol ensuring an alternate default gateway.",
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
      "explanation": "Administrative distance determines trust in a route source, not how the metric is calculated. Horizontal scaling is not a routing metric concept. Cost-based selection (correct) indicates the protocol uses metrics beyond hop count (e.g., OSPF uses cost). Prefix length priority is about route specificity, not cost calculations.",
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
      "explanation": "A record maps a hostname to an IPv4 address. CNAME record is an alias for another domain name. MX record (correct) designates mail server responsibility. TXT record often holds verification or arbitrary text data.",
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
      "explanation": "Wi-Fi analyzer only inspects wireless signals. Protocol analyzer (correct) can capture packets for detailed analysis. Cable toner probe traces cable paths, not packet-level analysis. SNMP polling utility queries devices for performance data but doesn’t do packet inspection.",
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
      "explanation": "SD-WAN (correct) dynamically balances multiple WAN links for performance and cost. NAT64 translates IPv6 addresses to IPv4, unrelated to WAN path optimization. Static routing requires manual configuration and no automatic path selection. Simple QoS tagging just marks traffic but doesn’t pick paths automatically.",
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
      "explanation": "Collapsed core (correct) aggregates distribution and core layers, often keeping local traffic inside the data center. Three-tier model with core routing might route traffic to a separate core. North-south approach only describes external traffic flows, not local data center paths. Hub-and-spoke architecture is more typical in WAN designs than local data center traffic.",
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
      "explanation": "Disable CDP globally prevents device discovery but doesn’t prevent MAC floods. Set port security limits on MAC addresses (correct) restricts the number of MACs per port, mitigating floods. Use an unmanaged switch without STP offers no security or loop protection. Enable DNSSEC to secure name resolution only secures DNS queries, not MAC learning behavior.",
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
      "explanation": "2 is /30. 6 (correct) a /29 has 8 total IPs, 1 network address, 1 broadcast, leaving 6 usable. 14 and 30 correspond to masks /28 or /27, providing more hosts.",
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
      "explanation": "Manually reviewing each device’s local log is time-consuming and prone to missing cross-device patterns. Setting up a syslog collector and SIEM (correct) centralizes logs for correlation and real-time alerts. Using Wi-Fi analyzer on all network segments is for wireless analysis only, ignoring other logs. Enabling DHCP snooping on edge switches helps track DHCP traffic but not a complete log correlation approach.",
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
      "explanation": "Hop count mismatch is a metric detail, but different protocols might not use the same metric. Administrative distance (correct) decides which source of routing information is preferred. CIDR block usage is about subnetting, not preference. Default gateway priority is a local IP setting, not route selection logic.",
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
      "explanation": "VXLAN (correct) encapsulates Ethernet frames in UDP for large-scale virtualization. PPP is a WAN protocol for serial links. 802.1Q trunking is VLAN tagging, not an encapsulation across L3. Syslog is a logging protocol, unrelated to virtualization tunnels.",
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
      "explanation": "Port mirroring replicates traffic for analysis, not controlling device count. MAC address sticky port security (correct) lets the switch learn one MAC and disable the port if additional MACs appear. SNMP polling only monitors device data, not limiting devices. Trunking aggregates multiple VLANs but doesn’t restrict device count.",
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
      "explanation": "dig queries DNS name servers. ipconfig is a Windows command, not Linux. tcpdump captures packets but doesn’t show interface config. ip addr show (correct) displays IP/MAC addresses on Linux.",
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
      "explanation": "OSPF is link-state. BGP is path-vector used for internet routing. RIP (correct) is distance-vector using hop count. EIGRP is an advanced distance-vector but uses a composite metric, not just hop count.",
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
      "explanation": "Each AP must be directly wired to the core is typical for standard infrastructure but not mesh. All traffic relies on a single root bridge references spanning tree for switches, not mesh Wi-Fi. APs dynamically route traffic through neighboring APs (correct) is the core advantage of mesh, distributing load among nodes. SSID broadcast must be disabled for bridging doesn’t reflect mesh operation.",
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
      "explanation": "MX directs mail exchange. A provides an IPv4 address. CNAME (correct) defines a canonical name alias. TXT is free-form text data.",
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
      "explanation": "DNS resolves domain names, not device discovery on the link layer. LLDP (correct) helps discover neighbors over Layer 2. NTP synchronizes clocks, unrelated to device discovery. FTP is file transfer protocol.",
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
      "explanation": "Delete all VLANs except the native VLAN is drastic and disrupts normal VLAN segmentation. Use SSH instead of Telnet on the switch secures management but not VLAN hopping. Manually specify the trunk native VLAN and disallow auto trunking (correct) sets a static native VLAN and disables DTP auto trunking, preventing double tagging. Enable jumbo frames to reduce overhead does nothing to mitigate VLAN hopping.",
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
      "explanation": "Excessive PoE draw from the device (correct) can trigger err-disabled if the port detects an over-limit PoE usage or a fault. DNS server misconfiguration wouldn’t disable the port at layer 2. Incorrect subnet mask on user PC wouldn’t typically cause the port to go err-disable. DHCP address pool exhaustion also wouldn’t force the port into err-disable.",
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
      "explanation": "Enable port mirroring (SPAN) to a monitor port (correct) copies traffic to a monitoring port for analysis. Assign a dynamic IP address to the port is for IP configuration, irrelevant to packet capturing. Disable CDP on the interface hides device info but doesn’t mirror traffic. Implement ACLs to block inbound traffic blocks traffic instead of capturing it.",
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
      "explanation": "Presentation layer relates to data formatting, not bit-level errors. Network layer deals with IP addressing. Physical layer (correct) indicates physical or data link hardware issues. Application layer is user-facing data exchange, not frames or bits.",
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
      "explanation": "Client-based IPSec tunnel requires a local client installed. Clientless SSL VPN via web portal (correct) uses a browser-based portal for secure remote access. Telnet session over WAN is unencrypted. FTP file transfers to DMZ only handles file transfers and is usually not secure by default.",
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
      "explanation": "Layer 5 (correct) is the Session layer that manages interhost communication sessions. Layer 2 is Data Link, Layer 4 is Transport, and Layer 7 is Application. None of those specifically focus on session management.",
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
      "explanation": "Check for an invalid default gateway MAC (correct) helps detect ARP poisoning or spoofing that can indicate an on-path scenario. Format the hard drive of the affected workstation is extreme and unrelated. Disable SNMP on all network devices is about management protocol, not ARP-based attacks. Delete old VLAN configurations on the switches is not specifically relevant to a man-in-the-middle.",
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
      "explanation": "Mismatched duplex on the switch port (correct) can drastically reduce speeds if half-duplex conflicts with full-duplex. Improper DNS record delegation would cause name resolution issues, not raw speed drops. High CPU usage on the domain controller might affect authentication but not typically cause slow throughput on a single link. Overlapping channels in the 5GHz band only is less common for 5GHz, which has more channels.",
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
      "explanation": "UDP is connectionless. TCP (correct) initiates connections with SYN, SYN-ACK, and ACK. ICMP is used for diagnostics and control messages, not reliable sessions. GRE is a tunneling protocol without built-in reliability.",
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
      "explanation": "Analyze ARP tables to see unexpected MACs might find suspicious devices but is less direct. Use a packet sniffer to filter DHCP offer messages (correct) directly catches rogue DHCP offers. Disable spanning tree on the core switch is risky and unrelated to DHCP. Implement DNSSEC to validate DNS requests is about DNS record security, not DHCP servers.",
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
      "explanation": "ip addr show is for Linux systems. netstat -an displays active connections/ports. ipconfig (correct) shows IP configuration details on Windows. arp -a only shows MAC-to-IP mappings in the ARP cache.",
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
      "explanation": "SNMP collects management information, not time sync. NTP (correct) synchronizes clocks. HTTP is web traffic, and FTP is file transfers.",
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
      "explanation": "Disable 802.1Q trunking trunking removal doesn't fix signal integrity. Use a single-mode fiber cable instead (correct) ensures better distance support and fewer interference issues. Change the IP addressing scheme won't affect physical layer reliability. Upgrade to Cat3 cables is a downgrade from Cat5e.",
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
      "explanation": "RADIUS uses UDP and only partially encrypts packets. TACACS+ (correct) uses TCP and fully encrypts. LDAP is a directory service protocol, not specifically AAA. LDAPS is LDAP over SSL but still not the typical AAA method for network devices.",
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
      "explanation": "ping checks reachability but not each hop. traceroute/tracert (correct) identifies the path hop-by-hop. arp -a shows ARP cache, not path. nslookup resolves DNS queries, unrelated to path determination.",
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
      "explanation": "Layer 2 switch simply switches packets at layer 2. Load balancer (correct) distributes requests to multiple servers, ensuring better performance. Content filter typically inspects or restricts content. Proxy server caches or modifies requests, not necessarily balancing load among servers.",
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
      "explanation": "Eliminates broadcast traffic on the network can’t fully eliminate broadcasts. Carries multiple VLAN traffic over a single link (correct) encapsulates VLAN tags so multiple VLANs can share one physical link. Merges DHCP and DNS services into one VLAN is unrelated to trunking. Enables encryption of all VLAN data in transit standard 802.1Q does not encrypt traffic.",
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
      "explanation": "Layer 6 (correct) is the Presentation layer, which deals with data formatting, encryption, and compression. Layer 2 is Data Link. Layer 4 is Transport. Layer 7 is Application, which interacts with end-user software.",
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
      "explanation": "VRRP with a single master typically has one active node. Hot standby with a passive secondary describes active-passive, not active-active. Active-active clustering (correct) both devices share load. Backup tapes stored offsite is offline backups, unrelated to real-time traffic sharing.",
      "examTip": "Active-active configurations maximize resource usage, but require careful synchronization between nodes."
    },
    {
      "id": 52,
      "question": "Which  is BEST for mitigating a DNS poisoning attack on your network?",
      "options": [
        "Implement DNSSEC to validate DNS responses",
        "Use Telnet for internal DNS queries",
        "Configure jumbo frames on all DNS servers",
        "Force an SSL VPN for all DNS traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Implement DNSSEC to validate DNS responses (correct) ensures DNS data authenticity via signatures. Use Telnet for internal DNS queries is insecure for DNS server management. Configure jumbo frames on all DNS servers doesn’t protect DNS query integrity. Force an SSL VPN for all DNS traffic is not standard for DNS queries and doesn’t specifically mitigate poisoning.",
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
      "explanation": "Check if STP is configured in Rapid mode covers loop protection, not IP address assignment. Confirm the DHCP server scope and lease availability (correct) ensures the server can still hand out addresses. Enable domain controller role on the server is unrelated to DHCP. Use NAT on the client interface is for translating private IPs to public, not address assignment.",
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
      "explanation": "Disable SSL on the local router is irrelevant to LAN port security. Implement NAC with 802.1X authentication (correct) requires users to authenticate before gaining network access. Enable DNS caching on every switch port doesn’t control access. Adopt a static routing protocol is about routing, not controlling port access.",
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
      "explanation": "802.1Q trunk error is a wired trunking issue. Mismatched VLAN ID on trunk port also pertains to a wired VLAN misconfiguration. Co-channel or adjacent channel interference (correct) describes a common Wi-Fi coverage or channel overlap problem. DHCP lease is too long does not usually cause random disconnects.",
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
      "explanation": "DNS server configuration on the user’s device (correct) is critical if name resolution fails while IP connectivity works. Spanning tree root bridge ID deals with loop prevention, less likely the cause. Subnet mask on the DHCP pool can cause broader connectivity issues, but user pings are successful so it’s not the mask. Switch’s VLAN trunking protocol is unrelated if pings already succeed across subnets.",
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
      "explanation": "SYN flood (correct) is a classic half-open connection flood. ARP spoofing modifies ARP caches. Fraggle attack uses UDP echo traffic. Ping of death involves oversized ICMP packets, not half-open states.",
      "examTip": "A SYN flood sends repeated SYNs without completing the handshake, overwhelming a server’s half-open connections."
    },
    {
      "id": 58,
      "question": "Which of these is a benefit of using SNMPv3 over SNMPv1?",
      "options": [
        "Simplified community strings",
        "Shorter MIB definitions",
        "Encrypted authentication and data",
        "Real-time packet capturing"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Simplified community strings is a legacy concept for SNMPv1/v2c. Shorter MIB definitions is not a version difference. Encrypted authentication and data (correct) is a key enhancement: authentication and encryption. Real-time packet capturing is a separate function not provided by SNMP.",
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
      "explanation": "Link is set to half-duplex at both ends might cause collisions but typically you’d see runts/errors. Network cable is physically broken is total link failure. Excessive packet loss on the WAN link (correct) triggers frequent retransmits due to lost segments. DNS is misconfigured would not cause retransmissions, just name resolution issues.",
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
      "explanation": "Router operates at Layer 3. Hub is a basic repeater with no MAC table. Switch (correct) is a typical Layer 2 forwarding device. Firewall typically inspects or filters traffic at various layers, not strictly based on MAC addresses.",
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
      "explanation": "DHCP reservations ensures static IP mapping from DHCP, not address sharing. Port address translation (PAT) (correct) translates many private IPs to one public IP using different ports. Spanning tree protocol is a loop-prevention protocol. IPSec encryption encrypts data but doesn't handle address sharing.",
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
      "explanation": "Enable port mirroring only provides monitoring. Update firmware to the latest supported version (correct) addresses known vulnerabilities and ensures current security patches. Activate jumbo frames for all ports is not primarily a security measure. Configure jumbo VLANs is not a standard term or security approach.",
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
      "explanation": "DHCP provided an extended lease is incorrect; 169.254.x.x is not a typical DHCP range. APIPA assigned an address due to DHCP failure (correct) indicates Automatic Private IP Addressing. DNS is incorrectly set to a public server is about domain name resolution, not address assignment. The interface is operating in promiscuous mode is about capturing traffic, not IP assignment.",
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
      "explanation": "NS record identifies a DNS nameserver. PTR record (correct) is used for reverse DNS lookups. A record is forward lookup from domain to IP. CNAME record is an alias record, not reverse lookup.",
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
      "explanation": "Assign a static IP to the interface addresses IP but not physical flapping. Move the cable to a different port and retest (correct) tests if the port or cable is faulty. Disable the native VLAN on the trunk is unrelated to link status flaps. Reboot the entire switch is too disruptive for a first step.",
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
      "explanation": "SSH (port 22) is secure shell, not port 23. Telnet (correct) uses port 23 and is unencrypted. HTTP is port 80 for web traffic. RDP is port 3389 for remote desktop.",
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
      "explanation": "UTP Cat5e offers no shielding. STP Cat6 or better (correct) has shielding to reduce EMI. Thin coaxial cable is rarely used in modern LANs. Plenum-rated Cat5 is for fire code compliance, not necessarily EMI reduction.",
      "examTip": "Shielded twisted pair helps protect signals from external electromagnetic interference, especially around industrial equipment."
    },
    {
      "id": 68,
      "question": "Which  is BEST addressed by implementing Quality of Service (QoS)?",
      "options": [
        "restrict employees from visiting social media sites",
        "ensure voice traffic has priority over regular data",
        "physically secure the IDF racks from theft",
        "encrypt all web-based application sessions"
      ],
      "correctAnswerIndex": 1,
      "explanation": "restrict employees from visiting social media sites is a content filtering issue. ensure voice traffic has priority over regular data (correct) is a classic use case for QoS. physically secure the IDF racks from theft is a physical security matter. encrypt all web-based application sessions is encryption, not traffic prioritization.",
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
      "explanation": "Establish a plan of action occurs after determining the cause. Test the theory to determine cause happens after forming a theory. Identify the problem (correct) is the initial step in any troubleshooting process. Establish a theory of probable cause is the next step after identifying the problem.",
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
      "explanation": "Subinterfaces on a router-on-a-stick (correct) is the classic router-on-a-stick approach for inter-VLAN routing. Separate physical interfaces for each VLAN is feasible but not common if physical interfaces are limited. A trunk port on the router in half-duplex is typically full-duplex trunking, but routers seldom do trunking the same way as switches. Assign NAT to each VLAN interface is for address translation, not VLAN routing.",
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
      "explanation": "Configure a DHCP reservation for its MAC address (correct) associates a device’s MAC with a specific IP in DHCP. Use APIPA for guaranteed consistent addressing only occurs when DHCP fails. Flush the DNS records daily is about name resolution, not IP assignment. Force DHCP relay from a different subnet simply forwards DHCP, not guaranteeing a specific IP.",
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
      "explanation": "It floods the switch port with bogus MAC addresses is a switch-based MAC flooding. It uses ARP poisoning to intercept packets on the LAN is ARP spoofing. It sets up a rogue AP mimicking a legitimate SSID (correct) duplicates a legitimate SSID to trick users. It physically disables the real AP’s antennas is unlikely and not typical of an evil twin approach.",
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
      "explanation": "tcpdump (correct) captures live network traffic at the command line. ipconfig is a Windows utility. dig queries DNS. ifconfig shows interface settings but doesn’t capture traffic.",
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
      "explanation": "Network Access Control (NAC) (correct) enforces posture checks and authentication before granting full access. Trivial File Transfer Protocol (TFTP) is a basic file transfer protocol, not security posture. IPSec site-to-site tunnel secures traffic between sites, not local endpoints. 802.3af PoE injection is power over Ethernet, unrelated to security checks.",
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
      "explanation": "Configure port mirroring only monitors traffic. Apply QoS prioritization for voice packets (correct) ensures voice is prioritized over bulk data. Split tunnel the VPN is a VPN design choice, not local traffic prioritization. Assign a static IP to the file server does not address congestion management.",
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
      "explanation": "Redirects DNS queries to local servers is more about DNS settings. Masks internal client IP addresses from external hosts (correct) proxies requests so external servers see the proxy IP, not the actual client. Provides layer 2 loop prevention features is done by spanning tree, not a proxy. Enforces jumbo frames for all traffic is a performance setting, not a security benefit.",
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
      "explanation": "Each host uses the same public IP but different external ports (correct) is exactly how PAT works: unique source port assignments for each internal host. Hosts share the same port number but different NAT pools is reversed. A default route is not needed in this scenario is false; a default route is typically still required. All traffic is broadcast to the external interface is incorrect, as NAT does not broadcast traffic.",
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
      "explanation": "AH (Authentication Header) only authenticates headers, not encrypting data. ESP (Encapsulating Security Payload) (correct) encrypts and authenticates data. GRE (Generic Routing Encapsulation) is a tunneling protocol without native security. IKE (Internet Key Exchange) negotiates keys, but does not carry the data encryption itself.",
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
      "explanation": "show mac-address-table (correct) displays the table mapping MACs to ports. show arp shows IP-to-MAC mappings, typically from an ARP cache. show interface trunk shows trunking info. show spanning-tree shows STP status and port roles.",
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
      "explanation": "Shut down the port and investigate (correct) immediately isolates the threat and prevents further flooding. Reload the switch’s configuration file may reapply config but doesn’t stop the live attack. Reboot all connected endpoints disrupts legitimate endpoints unnecessarily. Increase the VLAN pool to accommodate more MACs is the opposite of security best practice, allowing more addresses.",
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
      "explanation": "Periodic port mirroring sessions captures traffic, not switch config. Automated configuration backups to a central repository (correct) ensures config files are saved and recoverable. Implement DHCP for all switch IP addressing is an IP assignment practice, not config backup. Enable IPv6 dual-stack on each switch is a protocol approach, not a backup strategy.",
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
      "explanation": "A DHCP server that uses DNSSEC for secure updates is legitimate secure DNS updates. A malicious or unauthorized server handing out IP addresses (correct) is an unauthorized device providing incorrect IP settings. A server that runs out of IP addresses for clients is a capacity issue, not necessarily rogue. A DHCP server only accessible via IPv6 doesn’t define rogue behavior, just IPv6 usage.",
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
      "explanation": "Duplicate IP addresses detected is not indicated. Incorrect subnet assignment blocks local gateway reachability (correct) the user is on 192.168.1.x/24 and gateway is on 192.168.0.x/24, so no local route. Gateway IP is in the broadcast domain is not specifically an error. DHCP scope mismatch on the router might be possible but the issue is the mismatch between subnets.",
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
      "explanation": "Using a Wi-Fi analyzer to perform a site survey (correct) identifies coverage and interference. Enabling RSTP on the AP is a spanning tree protocol for switches. Forcing 802.11b compatibility mode reverts to an older standard, potentially reducing speed. Ignoring local regulations and using maximum power risks regulatory noncompliance and interference.",
      "examTip": "Site surveys help optimize channel selection and power settings for new wireless deployments."
    },
    {
      "id": 85,
      "question": "Which  is BEST resolved by implementing a captive portal?",
      "options": [
        "provide guests with temporary Wi-Fi access without giving them domain credentials",
        "route traffic between VLANs more efficiently",
        "diagnose cable continuity issues",
        "encrypt back-end server traffic using SSL"
      ],
      "correctAnswerIndex": 0,
      "explanation": "provide guests with temporary Wi-Fi access without giving them domain credentials (correct) captive portals allow guests to authenticate on a splash page. route traffic between VLANs more efficiently involves routing or switching, not a captive portal. diagnose cable continuity issues is a physical-layer test. encrypt back-end server traffic using SSL is encryption best practices, not a portal solution.",
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
      "explanation": "Administrative distance is optional and can be assumed. Next-hop IP address or exit interface (correct) is needed so the router knows where to send traffic. Local VLAN ID is a switching concept, not relevant to routing. Default DNS server is for name resolution, not routing.",
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
      "explanation": "It resolves addresses using MAC-based filtering is unrelated. It encrypts DNS queries within HTTPS, enhancing privacy (correct) DoH secures DNS queries through HTTPS. It only applies to IPv6 networks works with both IPv4 and IPv6. It automatically sets up a VPN tunnel for DNS is not how DoH operates; it doesn’t create a VPN.",
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
      "explanation": "Port mirroring copies traffic, not bandwidth. Link aggregation (LACP) (correct) bundles links for higher aggregate bandwidth. SNMPv3 traps is for management notifications. DHCP scope options sets IP parameters for clients, not channel bonding.",
      "examTip": "Link aggregation groups multiple ports to act as one, boosting bandwidth and fault tolerance."
    },
    {
      "id": 89,
      "question": "A user with a mission-critical role must have priority traffic for IP telephony. Which is the MOST method to ensure their VoIP packets are prioritized?",
      "options": [
        "Implement port security on their switch port",
        "Configure DSCP markings and apply QoS",
        "Use a separate unmanaged switch",
        "Block all non-VoIP traffic at the firewall"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Implement port security on their switch port controls device MAC addresses, not QoS. Configure DSCP markings and apply QoS (correct) sets QoS policies using DSCP to prioritize voice. Use a separate unmanaged switch removes management, not helpful. Block all non-VoIP traffic at the firewall is too restrictive and can break other needed services.",
      "examTip": "Differentiated Services Code Point (DSCP) is widely used to classify and prioritize traffic for QoS policies."
    },
    {
      "id": 90,
      "question": "Which question addresses implementing IPv6 to reduce address exhaustion while allowing some IPv4 to remain active?",
      "options": [
        "Can we run dual stack on devices supporting both IPv4 and IPv6?",
        "Should we remove all NAT configuration from the router?",
        "Will 802.1Q trunking reduce IPv4 usage?",
        "Should we disable TCP in favor of UDP for all traffic?"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Can we run dual stack on devices supporting both IPv4 and IPv6? (correct) is the essence of dual stack. Should we remove all NAT configuration from the router? can still be needed for internet access. Will 802.1Q trunking reduce IPv4 usage? only relates to VLAN tagging. Should we disable TCP in favor of UDP for all traffic? does not solve IP addressing constraints.",
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
      "explanation": "Next-generation firewall (correct) typically has advanced inspection (Layer 7, IPS, etc.) for DMZ traffic. Stateful packet filter on the core switch is a simpler solution, might not provide full NGFW features. Transparent bridging device is a bridging approach, not a typical DMZ firewall. Content filter proxy focuses on web content, not the entire DMZ security.",
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
      "explanation": "Protocol analyzer inspects packet data, not physical cable runs. Toner probe (correct) helps locate cables and breaks with audible tone. Wi-Fi analyzer checks wireless signals. Nmap scans network hosts and ports.",
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
      "explanation": "IKE Phase 1 (correct) is the phase where secure negotiation is set (ISAKMP/IKE). DNS resolution is name resolution, unrelated. ESP key distribution phase is part of IPsec data encryption but not the negotiation handshake. DHCP lease acquisition is for IP address assignment, not IPsec negotiation.",
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
      "explanation": "Swap the Ethernet cable might fix physical issues but not software bugs. Disable port security on that interface is security, not a bug fix. Update the router’s firmware to the latest version (correct) addresses known software or firmware issues. Increase the DHCP lease time affects IP address renewal intervals, not router crashes.",
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
      "explanation": "Active-active high availability is fully operational at both locations. Warm site (correct) is partially ready, requiring moderate setup. Hot site is fully ready to go. Cold site has minimal resources and requires the most setup.",
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
      "explanation": "Implement a full network redesign is extreme. Check for speed/duplex mismatch (correct) often causes frame size mismatches. Change DNS servers is unrelated to frame errors. Re-enable spanning tree on core switches is for loop prevention, not frame anomalies.",
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
      "explanation": "RIP, because it is simpler to configure is irrelevant to route choice. OSPF, because it has a lower administrative distance (correct) OSPF’s AD of 110 is preferred over RIP’s 120. RIP, because it has a lower hop count metric doesn’t matter if the route from RIP has a lower hop count, AD still decides. OSPF, because it uses a link-state database is partial reasoning but the key is administrative distance priority.",
      "examTip": "When multiple routing protocols advertise the same network, the router installs the route with the lowest AD."
    },
    {
      "id": 98,
      "question": "Which  is BEST solved by implementing HIDS/HIPS on critical servers?",
      "options": [
        "route VLAN traffic faster in the core",
        "detect malicious activities directly on a host in real time",
        "ensure DNS queries are resolved quickly",
        "reduce cable clutter in the server rack"
      ],
      "correctAnswerIndex": 1,
      "explanation": "route VLAN traffic faster in the core is a switching or routing design. detect malicious activities directly on a host in real time (correct) host intrusion detection/prevention detects system-level threats. ensure DNS queries are resolved quickly is performance or DNS caching. reduce cable clutter in the server rack is a physical organization issue, not security.",
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
      "explanation": "STP (Spanning Tree Protocol) (correct) blocks loops by electing a root bridge and disabling certain ports. ICMP redirect is used by routers to traffic. DHCP snooping monitors DHCP traffic for rogue servers, not loops. Reverse Proxy is an application-layer service, not for loop prevention.",
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
      "explanation": "Use VLANs to segment critical systems from other hosts (correct) network segmentation limits movement within the environment if a breach occurs. Disable QoS to reduce overhead is about traffic prioritization, not security segmentation. Configure jumbo frames for all traffic is for performance, not security. Reserve an IP for each device using DHCP ensures consistent IP assignment but doesn’t prevent lateral movement.",
      "examTip": "Segmentation—via VLANs or subnets—helps contain a compromised device to a smaller portion of the network."
    }
  ]
});
