db.tests.insertOne({
  "category": "netplus",
  "testId": 5,
  "testName": "Practice Test #5 (Intermediate)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "Which component is MOST crucial for translating a private IPv4 address into a public address in many-to-one scenarios?",
      "options": [
        "Spanning Tree Protocol on a core switch",
        "DNS zone transfers for local domains",
        "PAT on a NAT-enabled router",
        "802.1X port-based authentication"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A addresses loop prevention, not address translation. Option B replicates DNS data between servers, unrelated to NAT. Option C (correct) enables many internal clients to share one public IP by mapping source ports. Option D controls network port authentication, not IP address translation.",
      "examTip": "Port Address Translation (PAT) is the typical solution for letting multiple private IPs share a single public IP."
    },
    {
      "id": 2,
      "question": "A network engineer must confirm whether an attacker is ARP poisoning a segment. Which tool or process is the FIRST step to detect abnormal ARP activity?",
      "options": [
        "Check the DHCP server logs for scope exhaustion",
        "Use a protocol analyzer to inspect ARP replies",
        "Deploy an SIEM to correlate multiple log sources",
        "Run traceroute on the local subnet"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A can reveal rogue DHCP but not ARP issues. Option B (correct) captures packets to see repeated unsolicited ARP replies. Option C is beneficial but not the quickest first step. Option D shows route paths, not local ARP manipulations.",
      "examTip": "Perform a packet capture on your local segment to spot suspicious ARP announcements or duplications."
    },
    {
      "id": 3,
      "question": "Which statement accurately describes the role of the ‘distribution’ layer in a three-tier network design?",
      "options": [
        "It physically hosts all devices, serving as the wiring closet layer",
        "It provides fault isolation and aggregates access layer connections",
        "It interconnects multiple data centers through WAN links",
        "It offers direct VLAN tagging for end-user devices"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is the access layer function, hosting end-user connections. Option B (correct) aggregates access layer switches and often applies routing policies. Option C relates more to core routing or WAN edge. Option D references trunking to end devices, typically an access-layer function.",
      "examTip": "In the three-tier model, the distribution layer sits between core and access, handling routing and policy enforcement."
    },
    {
      "id": 4,
      "question": "A newly deployed switch uses a default native VLAN 1 on every port. Why is it generally RECOMMENDED to assign a different VLAN as the native VLAN?",
      "options": [
        "To block broadcast traffic entirely on VLAN 1",
        "To minimize potential VLAN-hopping attacks exploiting VLAN 1",
        "To enable half-duplex operation on VLAN 1 only",
        "To force STP root election on VLAN 1"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is impossible; VLAN 1 by default can carry management traffic. Option B (correct) reassigning native VLAN to a non-1 ID helps prevent certain double-tag attacks. Option C is a link-layer setting, not a VLAN assignment. Option D focuses on STP, not the native VLAN risk.",
      "examTip": "Best practice is to avoid using VLAN 1 for native VLAN to reduce vulnerability to VLAN hopping."
    },
    {
      "id": 5,
      "question": "Which approach is the MOST effective in preventing unauthorized wireless devices from connecting to a corporate SSID?",
      "options": [
        "Implement a captive portal without requiring passwords",
        "Use WPA2-PSK with a shared passphrase for all users",
        "Use WPA3-Enterprise with 802.1X authentication",
        "Hide the SSID broadcast on all corporate APs"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A only presents a splash page but doesn’t strongly authenticate. Option B uses a common passphrase, easy to share or leak. Option C (correct) provides individual credentials via RADIUS. Option D only obscures the network, not securing it.",
      "examTip": "Enterprise-level Wi-Fi typically uses 802.1X with unique credentials to ensure strong authentication and traceability."
    },
    {
      "id": 6,
      "question": "A network administrator notices that multiple devices in one VLAN are receiving IP addresses from a DHCP server in a different VLAN. What is the MOST likely cause?",
      "options": [
        "Excessive broadcast domain collisions",
        "Improper trunk configuration allowing DHCP offers to traverse VLANs",
        "Expired ARP entries causing IP conflicts",
        "A missing DNS entry for the default gateway"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A references collisions but doesn't explain cross-VLAN DHCP. Option B (correct) likely means the trunk is passing VLANs it shouldn't, enabling DHCP leakage. Option C is an unrelated ARP issue. Option D is about DNS, not DHCP scope crossing.",
      "examTip": "Carefully define trunked VLANs on switch ports so DHCP offers remain confined to their intended VLAN."
    },
    {
      "id": 7,
      "question": "Which of the following is the MOST direct advantage of PoE+ (802.3at) over standard PoE (802.3af)?",
      "options": [
        "PoE+ encrypts data packets at layer 2",
        "PoE+ delivers up to about 30W of power, supporting higher-demand devices",
        "PoE+ allows VLAN trunking across all powered devices",
        "PoE+ requires half-duplex to supply stable current"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is incorrect because PoE does not handle encryption. Option B (correct) is the key improvement, doubling the available power for devices like PTZ cameras. Option C is unrelated to PoE, that’s a switching feature. Option D is false; PoE does not mandate half-duplex.",
      "examTip": "802.3at (PoE+) can provide roughly 30W per port, powering devices that require more than the ~15W of 802.3af."
    },
    {
      "id": 8,
      "question": "A user reports losing network connectivity whenever large data transfers occur. The switchport error counters show a growing number of late collisions. Which mismatch is MOST likely at fault?",
      "options": [
        "Port speed mismatch (10 vs. 100 vs. 1000)",
        "Incorrect VLAN ID on the trunk interface",
        "Mismatched MTU between endpoints",
        "Half-duplex vs. full-duplex setting"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Option A can cause other errors, but late collisions typically point to half vs. full duplex conflicts. Option B is more of a VLAN trunk issue. Option C can cause fragmentation, not collisions. Option D (correct) is a classic source of collisions on switched networks.",
      "examTip": "Late collisions often arise when one side is full-duplex and the other is half-duplex."
    },
    {
      "id": 9,
      "question": "Which direct factor distinguishes an SFTP connection from FTP?",
      "options": [
        "SFTP uses TCP port 21 by default",
        "SFTP includes encryption over SSH on port 22",
        "SFTP does not allow file uploads, only downloads",
        "SFTP is limited to local subnet transfers only"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is FTP’s control channel. Option B (correct) SFTP is essentially FTP over SSH, typically on port 22. Option C is false; SFTP supports two-way file operations. Option D is false, you can connect globally if allowed by firewall rules.",
      "examTip": "SFTP is an encrypted file transfer protocol layered over SSH, usually using TCP 22."
    },
    {
      "id": 10,
      "question": "A team wants to streamline server provisioning in a large virtual data center. Which solution allows for using templates and version control for repeatable deployments?",
      "options": [
        "802.1X NAC on each vSwitch",
        "Infrastructure as Code (IaC) with playbooks",
        "DHCP snooping for all server ports",
        "Manual configuration of each VM via SSH"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is about network access control. Option B (correct) uses scripts or playbooks to automate server builds. Option C is about DHCP security. Option D is time-consuming and prone to human error.",
      "examTip": "IaC with tools like Ansible, Chef, or Puppet helps create consistent, versioned server and network configurations."
    },
    {
      "id": 11,
      "question": "Which portion of an IPv6 address identifies the network portion by default in a global unicast address?",
      "options": [
        "The last 64 bits",
        "The first 48 bits",
        "The first 64 bits",
        "The entire 128 bits"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A typically refers to the interface identifier. Option B might refer to a site prefix but is not standard default. Option C (correct) is the standard IPv6 subnet boundary for global unicast addresses (64/64). Option D is not correct, as part is host ID.",
      "examTip": "In IPv6, the common practice is a /64 prefix for the network portion, leaving the remaining 64 bits for host IDs."
    },
    {
      "id": 12,
      "question": "A network security engineer sees an unusual spike in inbound UDP traffic on port 161 from unknown external IPs. Which type of malicious activity is MOST likely occurring?",
      "options": [
        "A brute-force SSH attack",
        "DNS amplification reflecting on port 53",
        "SNMP probing or attack attempts",
        "SMTP open relay scanning"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is TCP 22, unrelated. Option B is DNS, which is port 53. Option C (correct) SNMP uses UDP 161, so external sources may be probing or attacking. Option D is mail relay scanning on port 25 or 587, not 161.",
      "examTip": "SNMP runs by default on UDP 161, so suspicious inbound queries could indicate a malicious scan or reflection attempt."
    },
    {
      "id": 13,
      "question": "During an internal security audit, it is discovered that many switches still use default credentials. Which action should the administrator take FIRST to remediate this?",
      "options": [
        "Implement 802.1Q trunking on all distribution switches",
        "Change switch passwords to unique, strong credentials",
        "Enable Telnet on each switch for remote admin",
        "Disable PoE across all unused ports"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is VLAN tagging, not credential security. Option B (correct) is the immediate step to eliminate easy unauthorized access. Option C uses an unsecure protocol. Option D is unrelated to login credentials.",
      "examTip": "Default logins on network devices are a major vulnerability; secure them with unique, complex credentials immediately."
    },
    {
      "id": 14,
      "question": "Which of the following BEST describes an MSA (multi-source agreement) transceiver type commonly used in 10 Gbps fiber links?",
      "options": [
        "SFP+",
        "RJ45",
        "SC",
        "LC"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) SFP+ is a standard for 10 Gigabit optical or copper modules. Option B is a twisted-pair connector. Option C and D are connector types, not transceiver form factors themselves.",
      "examTip": "SFP+ is a popular hot-swappable form factor for 10 Gbps transceivers, building on the older SFP standard."
    },
    {
      "id": 15,
      "question": "A user complains they cannot reach the internet, but the IP configuration and DNS settings are correct. Which next diagnostic step is MOST appropriate?",
      "options": [
        "Tracert to a well-known external IP to see where traffic stops",
        "Set a static ARP entry on the user’s machine",
        "Disable DHCP across the core switch",
        "Reboot the DNS server to clear cached records"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) helps identify at which hop the packet is dropped. Option B is rarely needed and not typically recommended. Option C is drastic and disrupts many users. Option D is extreme if DNS is proven correct.",
      "examTip": "Use traceroute (tracert) to check each hop’s responsiveness, quickly isolating a network path failure."
    },
    {
      "id": 16,
      "question": "You notice a pair of redundant switches in the core. Both become active simultaneously, creating bridging loops. Which protocol or feature is PRIMARILY designed to prevent this?",
      "options": [
        "VTP pruning",
        "Port security sticky MAC",
        "Spanning Tree Protocol",
        "802.1X authentication"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A only prunes VLANs, not loops. Option B restricts MAC addresses, not loops. Option C (correct) ensures only one active path in redundancy. Option D is for endpoint authentication. STP is standard for loop prevention.",
      "examTip": "STP or RSTP ensures a loop-free topology in networks with redundant switch interconnections."
    },
    {
      "id": 17,
      "question": "Which direct approach helps detect an intruder capturing network packets on a compromised switch port?",
      "options": [
        "Configure SNMP traps for high CPU usage",
        "Implement 802.1x EAP-TLS for the switch port",
        "Enable port mirroring on all access ports by default",
        "Check for a port set to monitor mode or unusual MAC addresses learned"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Option A is not necessarily triggered by packet sniffing. Option B is about authentication, not continuous monitoring. Option C duplicates traffic and is typically a tool for legitimate analysis. Option D (correct) an intruder might have changed the port to SPAN or introduced odd MAC addresses for sniffing.",
      "examTip": "Regularly verify switch port configurations to spot any suspicious ports in monitor/SPAN mode or unexpected MAC activity."
    },
    {
      "id": 18,
      "question": "A newly installed router incorrectly flags a legitimate domain’s traffic as malicious. Which technology is MOST likely misconfigured to cause this false positive?",
      "options": [
        "DHCP relay with IP helper addresses",
        "Content filtering or reputation-based firewall rules",
        "LACP trunk with multiple VLANs",
        "Port security limiting MAC addresses"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A forwards DHCP requests, not domain-based filtering. Option B (correct) reputation or content filtering might block certain domains. Option C aggregates links, irrelevant to domain blocking. Option D restricts MAC addresses, not URLs or domains.",
      "examTip": "Web filtering or reputation services can mistakenly block legitimate sites if misconfigured or outdated."
    },
    {
      "id": 19,
      "question": "Which wireless technology uses a 5 GHz band but does NOT allow older 802.11b/g devices to connect?",
      "options": [
        "802.11n",
        "802.11ac",
        "802.11g",
        "802.11b"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A can operate on 2.4 or 5 GHz and can be backward compatible. Option B (correct) is 5 GHz only, no b/g fallback. Option C is 2.4 GHz only. Option D is also 2.4 GHz only. 802.11ac solely uses 5 GHz.",
      "examTip": "802.11ac (and 802.11ax for 5 GHz) do not support older b/g devices which operate in 2.4 GHz."
    },
    {
      "id": 20,
      "question": "Which technology encapsulates IPv6 traffic inside IPv4 packets to traverse an IPv4-only network?",
      "options": [
        "QoS marking",
        "Tunneling (e.g., 6to4)",
        "SNMP community strings",
        "DHCP option 43"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is traffic prioritization. Option B (correct) is IPv6 tunneling. Option C is for management access. Option D is a DHCP vendor extension. Tunneling solutions like 6to4 or ISATAP wrap IPv6 in IPv4.",
      "examTip": "When migrating to IPv6 over an IPv4 network, tunnels can carry v6 traffic if direct support is absent."
    },
    {
      "id": 21,
      "question": "A core switch experiences repeated CPU spikes during ARP table updates. Which measure can help reduce ARP broadcast traffic in a large flat layer 2 environment?",
      "options": [
        "Implement smaller VLANs with router gateways for each segment",
        "Use jumbo frames to carry more data per packet",
        "Allow trunk ports to dynamically negotiate using DTP",
        "Enable half-duplex on each port to slow traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) segments broadcast domains, reducing ARP overhead. Option B is a performance tweak, not broadcast management. Option C can create trunks automatically, not reduce ARP. Option D is detrimental to performance and doesn't specifically reduce ARP.",
      "examTip": "Reducing broadcast domain size (via VLANs and routing) often lowers ARP storms in large flat networks."
    },
    {
      "id": 22,
      "question": "Which scenario-based question is BEST addressed by implementing a warm site for disaster recovery?",
      "options": [
        "How to ensure zero downtime with fully active systems in multiple data centers",
        "How to bring systems online within hours if the primary site fails",
        "How to store daily tape backups in a secure offsite locker",
        "How to keep routers updated with the latest firmware automatically"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is an active-active or hot site. Option B (correct) describes a warm site with partial readiness. Option C is more like cold site or standard backup practice. Option D is routine maintenance, not DR site strategy.",
      "examTip": "A warm site has pre-installed hardware and some data; it can be made operational more quickly than a cold site."
    },
    {
      "id": 23,
      "question": "You suspect a WAN link is severely congested. Which tool or command is BEST to measure real-time network performance from end to end?",
      "options": [
        "nslookup",
        "nmap",
        "iperf",
        "arp -a"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A queries DNS. Option B scans hosts and ports. Option C (correct) tests bandwidth and throughput between two endpoints. Option D shows ARP cache, not performance.",
      "examTip": "iperf can generate traffic and measure network throughput, identifying bottlenecks on a link."
    },
    {
      "id": 24,
      "question": "A network admin needs to secure SNMP communications between devices. Which protocol version should be selected to ensure encrypted authentication and data?",
      "options": [
        "SNMPv1",
        "SNMPv2c",
        "SNMPv3",
        "SNMP over SSL v1"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A and B do not support encryption. Option C (correct) introduces encryption and user-based security model. Option D is not a standard designation. SNMPv3 is recommended for secure management.",
      "examTip": "Use SNMPv3 to avoid sending community strings and data in clear text over the network."
    },
    {
      "id": 25,
      "question": "Which WAN topology uses a single central router or hub with multiple branch routers as spokes, minimizing direct site-to-site links?",
      "options": [
        "Full mesh",
        "Point-to-point dedicated lines",
        "Hub-and-spoke",
        "Spine-leaf"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is every site connected to every other site, more expensive. Option B is one dedicated line per pair. Option C (correct) features a central hub with spokes. Option D is typical in data center switching, not WAN.",
      "examTip": "A hub-and-spoke design uses a central location for routing all site connections, simpler but can create bottlenecks."
    },
    {
      "id": 26,
      "question": "Which primary security benefit does a NAT firewall provide to internal hosts accessing the internet?",
      "options": [
        "It encrypts all data in transit using IPSec",
        "It hides internal IP addresses from external networks",
        "It compresses data packets for faster routing",
        "It automatically blocks inbound TCP port 80"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is separate from NAT. Option B (correct) ensures external hosts only see the NAT IP, not private IPs. Option C is performance, not typical NAT function. Option D is a policy choice, not inherent to NAT.",
      "examTip": "NAT effectively masks internal IPs, raising the difficulty for unsolicited inbound connections."
    },
    {
      "id": 27,
      "question": "A network engineer wants to distribute traffic across multiple servers offering the same application. Which device or feature BEST balances workload among these servers?",
      "options": [
        "A next-generation firewall",
        "A load balancer",
        "A transparent switch in Layer 2 mode",
        "A PoE injector"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A inspects traffic, not balancing loads. Option B (correct) distributes requests among multiple servers. Option C is bridging only. Option D delivers power to devices, not load distribution.",
      "examTip": "Load balancers optimize performance and redundancy by routing requests among multiple backend servers."
    },
    {
      "id": 28,
      "question": "Which FIRST step is advised when diagnosing repeated 'IP conflict' notifications on a subnet?",
      "options": [
        "Enable jumbo frames on all devices",
        "Check the DHCP server’s scope and reservations",
        "Disable STP on the core switch",
        "Change the default gateway address"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is a frame-size tweak, unrelated. Option B (correct) ensures no overlapping static assignment or exhausted range. Option C invites loops. Option D breaks the router setup. DHCP misconfiguration is a common source of conflicts.",
      "examTip": "Examine DHCP scopes, reservations, and any static IP overlaps when conflicts appear."
    },
    {
      "id": 29,
      "question": "Which advantage does a 2.4 GHz wireless band typically offer over the 5 GHz band?",
      "options": [
        "Higher maximum throughput for each channel",
        "Less interference from microwave ovens and phones",
        "Greater range and wall penetration due to lower frequency",
        "No legacy device restrictions"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is incorrect; 5 GHz generally yields higher data rates. Option B is false; 2.4 GHz often faces more interference. Option C (correct) 2.4 GHz signals travel farther and better penetrate walls. Option D is incorrect; older 802.11b/g are 2.4 GHz, not 5 GHz.",
      "examTip": "2.4 GHz typically covers more distance, though it has fewer non-overlapping channels and can have more interference."
    },
    {
      "id": 30,
      "question": "In an SDN environment, which plane is responsible for making forwarding decisions based on the network-wide view?",
      "options": [
        "The control plane in a centralized SDN controller",
        "The data plane on each router interface",
        "The management plane on every end-user device",
        "The virtualization plane in the hypervisor"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) in SDN, the controller handles routing logic. Option B is the local forwarding engine. Option C is device administration. Option D is server virtualization, not network control.",
      "examTip": "In SDN, the control plane is centralized. Devices simply forward packets under the controller’s instructions."
    },
    {
      "id": 31,
      "question": "Which is the PRIMARY advantage of using OSPF in a larger corporate network instead of RIPv2?",
      "options": [
        "OSPF uses a hop count limit of 15",
        "OSPF operates over UDP instead of TCP",
        "OSPF converges faster and handles bigger networks efficiently",
        "OSPF is proprietary while RIP is open standard"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is a RIP characteristic. Option B is inaccurate; OSPF is IP protocol 89, not standard TCP/UDP. Option C (correct) is the fundamental advantage. Option D is reversed: OSPF is open standard, EIGRP is proprietary (historically).",
      "examTip": "OSPF is a link-state protocol designed for larger, more complex topologies, converging faster than RIP’s distance-vector approach."
    },
    {
      "id": 32,
      "question": "Which command in Windows displays TCP connections, listening ports, and the associated process identifiers?",
      "options": [
        "tracert",
        "netstat -ano",
        "arp -s",
        "ipconfig /renew"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A traces route hops. Option B (correct) shows ports, addresses, state, and process IDs. Option C manually sets ARP entries. Option D renews DHCP lease, not listing connections.",
      "examTip": "Use 'netstat -ano' on Windows to check active TCP endpoints, states, and matching PID for processes."
    },
    {
      "id": 33,
      "question": "Which of these is the FIRST measure when a newly installed switch port rapidly transitions between up and down states?",
      "options": [
        "Shut down the port and swap the cable or device",
        "Increase the QoS priority for that port",
        "Move the port to VLAN 1 to stabilize traffic",
        "Configure a static MAC address on the port"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) quickly isolates if the cable or connected device is the problem. Option B addresses traffic prioritization, not physical flapping. Option C is security risk and not relevant. Option D is port security but not the best immediate diagnostic.",
      "examTip": "Disable the problematic port, test with a different cable or device to rule out hardware issues causing link flaps."
    },
    {
      "id": 34,
      "question": "Which step is PRIMARILY taken to verify that your new DHCP scope has enough addresses for all clients, especially in a rapidly growing subnet?",
      "options": [
        "Shorten the DHCP lease time to free addresses sooner",
        "Implement port mirroring to watch DHCP traffic",
        "Use APIPA addresses for devices without leases",
        "Enable trunking on all uplink interfaces"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) ensures addresses recycle faster, preventing exhaustion. Option B is only traffic monitoring. Option C is an automatic fallback, not a real solution. Option D is about VLAN trunking, not addressing capacity.",
      "examTip": "Leases that are too long can exhaust scope addresses in dynamic environments. Adjust lease time or expand the scope."
    },
    {
      "id": 35,
      "question": "An ISP router is announcing a more specific /28 route, overriding your static /24 route. Which concept explains why the router chooses that /28 route?",
      "options": [
        "Fewer administrative hops",
        "Longest prefix match",
        "Lower administrative distance",
        "Route injection via DHCP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is irrelevant. Option B (correct) the router picks the route with the most specific (longest) prefix. Option C is typically used when comparing different protocols, but a more specific route beats a broader route if both come from the same protocol. Option D is not how routes are chosen.",
      "examTip": "Routers prefer the route with the longest prefix match (highest subnet mask) when multiple routes exist."
    },
    {
      "id": 36,
      "question": "Which is the MOST likely reason an 802.11ax (Wi-Fi 6) network might not achieve its full speed potential?",
      "options": [
        "Access point is in 2.4 GHz mode only",
        "Using WPA3 encryption lowers data rates dramatically",
        "Switch trunk ports do not allow VLAN 1",
        "Client devices are set to half-duplex"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) 2.4 GHz significantly limits Wi-Fi 6 performance. Option B WPA3 overhead is negligible compared to overall speed. Option C VLAN 1 is a separate matter. Option D half-duplex is not typical for Wi-Fi clients. Running Wi-Fi 6 in 5 GHz or 6 GHz is essential for high speeds.",
      "examTip": "Wi-Fi 6 can operate in 2.4 GHz but top speeds are typically realized in 5 or 6 GHz bands."
    },
    {
      "id": 37,
      "question": "In a corporate wireless deployment, why might one enable band steering on dual-band access points?",
      "options": [
        "To push capable clients onto the 5 GHz band for better throughput",
        "To prevent users from roaming between APs",
        "To force older devices to upgrade firmware",
        "To disable WPA3 encryption on 2.4 GHz"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) band steering tries to move clients to 5 GHz. Option B is the opposite of normal. Option C is not feasible. Option D is a separate security choice, not related to band steering.",
      "examTip": "Band steering encourages dual-band clients to use the higher-performance 5 GHz spectrum, leaving 2.4 GHz for legacy devices."
    },
    {
      "id": 38,
      "question": "Which condition can cause a DHCP server to reject a client’s request if MAC filtering is in place?",
      "options": [
        "The client’s hostname is already taken by another device",
        "The client’s MAC address is not in the allowed list",
        "The client’s default gateway is misconfigured",
        "The server’s NAT table is full"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is a name conflict, not a typical DHCP reject scenario. Option B (correct) if the MAC is not allowed, the server will refuse. Option C is a local setting, not a DHCP server filter. Option D is about IP translation, unrelated to DHCP filtering.",
      "examTip": "If DHCP is configured with MAC-based allowlists or blocklists, a mismatch blocks the client from receiving a lease."
    },
    {
      "id": 39,
      "question": "A network admin wants to ensure secure remote CLI management. Which protocol is BEST for encrypted command-line access to network devices?",
      "options": [
        "SSH",
        "Telnet",
        "SNMPv1",
        "TFTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) uses port 22 for secure, encrypted sessions. Option B sends data in plain text. Option C is unencrypted for v1. Option D is a trivial file transfer, no interactive shell.",
      "examTip": "SSH is the standard for secure remote management, replacing Telnet’s clear-text approach."
    },
    {
      "id": 40,
      "question": "Which device feature can automatically shut down a switch interface when it detects too many MAC addresses learned on that port?",
      "options": [
        "NAC posture check",
        "BPDU Guard",
        "SNMP traps",
        "Port security"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Option A enforces endpoint compliance, not MAC limitations. Option B protects STP from rogue devices. Option C sends notifications, not enforce. Option D (correct) can lock or disable a port that sees excessive MAC addresses (e.g., MAC flooding).",
      "examTip": "Port security can set a max MAC count, placing the port in error if exceeded, thwarting flooding attacks."
    },
    {
      "id": 41,
      "question": "What is the MAIN advantage of implementing a captive portal for guest wireless access?",
      "options": [
        "It encrypts all traffic using IPSec tunnels",
        "It restricts user speed by applying rate limits at layer 2",
        "It provides a branded login page to authenticate or accept usage terms",
        "It forces users to set static IP addresses"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is not typical of captive portals. Option B is a QoS setting. Option C (correct) is the core purpose of captive portals. Option D is not a standard requirement for captive portals.",
      "examTip": "Captive portals greet guest users with disclaimers or authentication steps before granting network access."
    },
    {
      "id": 42,
      "question": "An admin wants to detect whether a suspicious host is communicating with unexpected external servers. Which tool or technique is the FIRST step?",
      "options": [
        "arp -a",
        "Configure netflow or sflow on the gateway",
        "Enable DNSSEC for name resolution",
        "Disable SNMP on the host"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is ARP cache listing. Option B (correct) NetFlow or sFlow helps track traffic flows for analysis. Option C ensures DNS record integrity but not traffic analysis. Option D turns off monitoring, not detection.",
      "examTip": "Flow technologies (NetFlow, sFlow) record metadata about who is talking to whom, revealing suspicious outbound connections."
    },
    {
      "id": 43,
      "question": "Which statement BEST defines a rogue access point in a corporate network?",
      "options": [
        "A legitimate AP that has outdated firmware",
        "An unauthorized AP connected to the wired network, potentially bypassing security",
        "A backup AP used for load balancing in the DMZ",
        "An AP that does not broadcast its SSID"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is just outdated software, not necessarily rogue. Option B (correct) is an unauthorized device, a security concern. Option C might be part of a high-availability design, not rogue. Option D is hiding SSID, not necessarily unauthorized.",
      "examTip": "A rogue AP is typically installed without permission, exposing the network to attackers if unsecured."
    },
    {
      "id": 44,
      "question": "Which of the following is PRIMARILY responsible for preventing buffer overflows and malware from executing in protected areas of system memory on a modern CPU?",
      "options": [
        "Stateful firewall rules",
        "802.1X NAC protocols",
        "Port Address Translation",
        "NX bit / Data Execution Prevention"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Option A inspects network traffic, not CPU memory. Option B authenticates devices, not memory protection. Option C is NAT-based. Option D (correct) prevents certain memory sections from being executed, reducing exploits.",
      "examTip": "Data Execution Prevention (DEP) or NX bit is an OS/CPU feature that blocks code execution in non-executable memory regions."
    },
    {
      "id": 45,
      "question": "A user is experiencing very slow responses when accessing internal file shares. Other users on the same subnet have no issues. Which FIRST step is recommended to isolate the problem on the user's machine?",
      "options": [
        "Flush the DNS cache and retry",
        "Replace the Ethernet cable immediately",
        "Run a continuous ping (ping -t) to the file server and observe latency",
        "Reduce the DHCP lease to 30 minutes"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A might help if name resolution is suspect, but not a direct measure of latency. Option B is possible, but you should confirm connectivity first. Option C (correct) quickly gauges if there’s packet loss or delay. Option D is IP address management, not performance debugging.",
      "examTip": "A sustained ping test can reveal patterns of packet drops or spikes in response time."
    },
    {
      "id": 46,
      "question": "Which technique is MOST effective for segmenting IoT devices like sensors and cameras, reducing the risk if they’re compromised?",
      "options": [
        "Place them all on a flat layer 2 subnet",
        "Assign them to an isolated VLAN with restrictive ACLs",
        "Provide static IP addresses from the core router",
        "Use half-duplex connections to limit throughput"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A lumps devices with others, risking lateral movement. Option B (correct) isolates these devices from critical network resources. Option C only ensures consistent addresses, not security. Option D does not address security segmentation.",
      "examTip": "Creating dedicated VLANs with ACLs or firewall rules for IoT devices can drastically reduce the blast radius if they’re compromised."
    },
    {
      "id": 47,
      "question": "In a zero trust architecture (ZTA), which principle is emphasized for every resource request, even for internal users?",
      "options": [
        "Automatic acceptance if source IP is on the corporate LAN",
        "Repeatable, context-based verification of identity and posture before granting access",
        "Full mesh physical connections to all servers",
        "Use of static routing for internal traffic"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is the opposite of zero trust. Option B (correct) reauthenticates and checks device posture each time. Option C is physical topology, not ZTA. Option D is a routing choice, not a security principle.",
      "examTip": "Zero trust means ‘never trust, always verify,’ requiring continuous authentication and authorization checks."
    },
    {
      "id": 48,
      "question": "Which scenario BEST calls for a 1000BASE-LX SFP module instead of a 1000BASE-T module?",
      "options": [
        "Connecting a user’s PC that is 90 meters away",
        "A short 10-meter run to a server rack",
        "A 5 km fiber run between buildings",
        "A 1 Gbps link over standard Cat5e"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is within copper limits. Option B can use shorter copper or fiber. Option C (correct) is where single-mode fiber is needed for extended range. Option D is standard copper use. LX is typically for longer fiber runs.",
      "examTip": "1000BASE-LX supports longer single-mode fiber distances, often up to 5 km or more."
    },
    {
      "id": 49,
      "question": "A user is working on a laptop and notices the signal strength drops drastically when they move to another conference room. What is the FIRST step to confirm if channel overlap or interference is causing the issue?",
      "options": [
        "Enable static IP addressing",
        "Use a Wi-Fi analyzer to check channel utilization and signal levels",
        "Lower the MTU setting on the wireless adapter",
        "Change the DHCP scope to a larger range"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is about address assignment, not signal issues. Option B (correct) helps visualize channel usage and identify interference. Option C addresses packet size, not signal. Option D addresses IP availability, unrelated to signal drop.",
      "examTip": "A Wi-Fi analyzer is the primary tool for diagnosing RF coverage gaps, overlapping channels, or interference."
    },
    {
      "id": 50,
      "question": "Which characteristic distinguishes TCP from UDP when discussing data transmission?",
      "options": [
        "TCP uses a three-way handshake for reliable delivery",
        "UDP encrypts data by default",
        "TCP always uses port 69",
        "UDP is only used for DNS requests"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) is the fundamental difference for reliability. Option B is false; encryption is not default in UDP. Option C is TFTP’s port, not TCP. Option D is incorrect; UDP is also used for other protocols.",
      "examTip": "TCP is connection-oriented with reliable delivery, while UDP is connectionless without guaranteed reliability."
    },
    {
      "id": 51,
      "question": "During a network upgrade, the new firewall must NAT inbound HTTPS connections to an internal web server. Which port must be allowed externally to reach that server over HTTPS?",
      "options": [
        "TCP 21",
        "TCP 443",
        "UDP 69",
        "TCP 3389"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is FTP. Option B (correct) is HTTPS. Option C is TFTP, Option D is RDP. Port 443 is standard for encrypted web traffic.",
      "examTip": "HTTPS typically runs on TCP 443 for secure connections."
    },
    {
      "id": 52,
      "question": "Which FIRST-step approach is recommended when a routing loop is suspected between two OSPF routers?",
      "options": [
        "Disable OSPF entirely and rely on static routes",
        "Verify both routers have a matching area ID and hello/dead timers",
        "Enable Telnet on each router interface",
        "Switch to RIPv2 for simpler metric calculations"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is drastic. Option B (correct) ensures OSPF adjacency is correct. Mismatch in area or timers can cause loops or neighbor issues. Option C is insecure remote admin, not a fix. Option D is a different protocol with limitations.",
      "examTip": "When OSPF adjacency is off, routing issues or loops can occur. Confirm matching parameters first."
    },
    {
      "id": 53,
      "question": "A malicious user connected a portable router to an office port. Which switch configuration is MOST likely to detect and shut down the port automatically?",
      "options": [
        "BPDU filter disabled on trunk ports",
        "Port security with limited MAC count",
        "DHCP snooping disabled on that VLAN",
        "LACP negotiations for all access ports"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A can ignore BPDUs but doesn't shut the port. Option B (correct) port security sees a second device's MAC and can disable. Option C is for preventing rogue DHCP, not devices. Option D is for link aggregation, not unauthorized devices.",
      "examTip": "Port security can restrict the number of MACs learned, disabling the port if a rogue router is connected."
    },
    {
      "id": 54,
      "question": "Which device aggregates logs, correlates security events, and provides real-time analysis from multiple network sources?",
      "options": [
        "SPAM filter",
        "Syslog server with no analytics",
        "SIEM",
        "Protocol analyzer"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is for email spam. Option B is basic log collection without advanced correlation. Option C (correct) centralizes, correlates, and alerts on data from multiple devices. Option D captures packets but doesn’t unify logs from different sources.",
      "examTip": "A SIEM aggregates logs and applies real-time correlation to detect patterns indicating threats."
    },
    {
      "id": 55,
      "question": "A broadcast storm occurred after the primary root bridge in STP failed. Which single configuration helps ensure a predictable failover root?",
      "options": [
        "Set the same priority on all switches",
        "Manually adjust STP priority values to designate a backup root",
        "Enable DHCP snooping on the root switch",
        "Disable all trunk ports except on the root bridge"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A yields no definite backup root. Option B (correct) ensures a second switch has a lower priority than all others, becoming the next root. Option C is for DHCP security, not STP. Option D is not practical and restricts redundancy.",
      "examTip": "Explicitly setting STP priority for a designated backup root switch ensures an orderly failover if the primary goes down."
    },
    {
      "id": 56,
      "question": "Which condition would MOST likely trigger DHCP IP address exhaustion in a subnet of 200 addresses?",
      "options": [
        "Incorrect DNS server IP in DHCP options",
        "Lease time set to 9999 days with no reclamation",
        "Rogue WAP using the same SSID",
        "A default gateway mismatch on the router"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is incorrect server info, not using up addresses. Option B (correct) might never reuse addresses, depleting the pool. Option C is a wireless security risk but not necessarily address exhaustion. Option D is a routing issue, not scope usage.",
      "examTip": "Excessively long leases cause addresses to remain assigned even if devices leave the network."
    },
    {
      "id": 57,
      "question": "Which type of DNS record is used to identify the canonical name for an alias domain?",
      "options": [
        "MX",
        "A",
        "PTR",
        "CNAME"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Option A is mail exchange, Option B is IPv4, Option C is reverse lookup, Option D (correct) is the alias to a canonical name.",
      "examTip": "CNAME records allow multiple domain aliases to resolve to the same actual (canonical) domain."
    },
    {
      "id": 58,
      "question": "A technician suspects one cable run is exceeding distance limits, causing intermittent connectivity. Which tool is BEST for accurately measuring cable length and identifying breaks?",
      "options": [
        "Toner probe kit",
        "Loopback plug",
        "Time domain reflectometer (TDR)",
        "Protocol analyzer"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A locates cables, not measuring exact length. Option B confirms port connectivity but not length. Option C (correct) TDR pinpoints distance to a cable fault. Option D examines packet data, not physical cable faults.",
      "examTip": "A TDR sends signals and measures reflections to gauge cable length and find breaks or crimps."
    },
    {
      "id": 59,
      "question": "Which is the PRIMARY purpose of a NAC solution utilizing posture assessment?",
      "options": [
        "Verifying a router has the latest firmware",
        "Checking endpoints meet security requirements before granting network access",
        "Managing RADIUS server certificates",
        "Encoding all VLAN data in an encrypted tunnel"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is a single device approach, not NAC posture checks across endpoints. Option B (correct) is the essence of NAC posture. Option C is a separate AAA configuration. Option D is encryption, not NAC posture.",
      "examTip": "NAC posture ensures endpoints have required patches, AV, etc., before allowing them on the network."
    },
    {
      "id": 60,
      "question": "A user cannot connect to the corporate SSID. Other users are fine. The logs show 'invalid credentials' repeatedly. Which FIRST action is most logical?",
      "options": [
        "Re-image the entire operating system",
        "Change the user’s VLAN to the native VLAN",
        "Verify the user’s password or re-enter their credentials",
        "Swap out the AP for a new one"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is extreme. Option B is about VLAN assignment, not credentials. Option C (correct) is the minimal step: confirm correct username/password. Option D is drastic hardware replacement. Typically incorrect or expired passwords cause this error.",
      "examTip": "Check the simplest explanation first, especially for 'invalid credentials'—the user may be typing the wrong password."
    },
    {
      "id": 61,
      "question": "A network admin sees frequent MAC address changes on a single port, suggesting a possible hub or rogue device connected. Which configuration will BEST mitigate this?",
      "options": [
        "Enable MAC address sticky with a limited MAC count",
        "Increase the DHCP lease time",
        "Disable spanning tree on that port",
        "Force the port speed to 10 Mbps"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) locks learned MAC addresses. Option B is unrelated to MAC changes. Option C could cause loops. Option D is a performance setting. Sticky MAC with a limit prevents multi-device usage on one port.",
      "examTip": "Port security sticky MAC can detect unauthorized devices behind a hub or rogue switch, shutting the port if multiple MACs appear."
    },
    {
      "id": 62,
      "question": "While troubleshooting a WAN link, you see repeated TTL-expired messages. At which OSI layer does TTL primarily operate?",
      "options": [
        "Layer 2",
        "Layer 3",
        "Layer 4",
        "Layer 5"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is MAC addresses. Option B (correct) IP header includes TTL. Option C is TCP/UDP. Option D is session management.",
      "examTip": "TTL is an IP-level field, so it belongs to Layer 3 of the OSI model."
    },
    {
      "id": 63,
      "question": "Which scenario-based question is BEST resolved by deploying an IPS instead of an IDS?",
      "options": [
        "How to passively monitor traffic without disruptions",
        "How to disable encryption on all inbound connections",
        "How to immediately block detected malicious traffic in real time",
        "How to gather flow data for capacity planning"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is an IDS scenario. Option B is unrelated to intrusion detection. Option C (correct) is the advantage of inline IPS. Option D is flow analysis, not intrusion detection. IPS blocks suspicious traffic inline.",
      "examTip": "IDS detects, IPS detects and actively prevents malicious activity."
    },
    {
      "id": 64,
      "question": "A router cannot ping outside its local subnet. Which setting is the FIRST to confirm?",
      "options": [
        "Default gateway on the router interface",
        "DNS server IP address",
        "802.1Q trunk native VLAN assignment",
        "SNMP community string"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) if the router has no correct gateway, it cannot route beyond its subnet. Option B resolves names, but ping by IP should still work. Option C is a VLAN trunk setting, less relevant. Option D is for monitoring, not routing.",
      "examTip": "Always ensure the router’s default route or gateway is valid for outbound traffic to remote networks."
    },
    {
      "id": 65,
      "question": "Which form of cloud service model delivers a development platform where customers can build and run their own applications without managing underlying servers?",
      "options": [
        "IaaS",
        "PaaS",
        "SaaS",
        "DRaaS"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is raw infrastructure. Option B (correct) is a platform environment for custom apps. Option C is fully hosted software. Option D is disaster recovery. PaaS abstracts the OS and hardware layers.",
      "examTip": "Platform as a Service provides an environment to develop, run, and manage applications without dealing with infrastructure details."
    },
    {
      "id": 66,
      "question": "Which direct factor can cause WPA2 Enterprise authentication to fail if a RADIUS server certificate has expired?",
      "options": [
        "Clients cannot validate the server’s identity and drop the connection",
        "The switch will block all VLAN tagging",
        "802.1D spanning tree protocol is disabled globally",
        "DHCP requests will not reach the server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) a valid certificate is needed for EAP-based authentication. Option B is unrelated. Option C is loop prevention, not Wi-Fi auth. Option D is about address assignment. Expired certificates break client trust.",
      "examTip": "802.1X or WPA2-Enterprise relies on valid RADIUS/EAP certificates for mutual authentication."
    },
    {
      "id": 67,
      "question": "A company is upgrading from 1 Gbps to 10 Gbps links between racks. The existing multimode fiber is 62.5 micron (OM1). Which outcome is MOST likely?",
      "options": [
        "It supports 10 Gbps up to 5 km without issues",
        "It will not reliably achieve 10 Gbps unless replaced with higher-grade fiber",
        "It can only run 10 Gbps if half-duplex is used",
        "It requires ST connectors to reach 10 Gbps speed"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is single-mode distances, not 62.5 micron. Option B (correct) older OM1 fiber is not recommended for stable 10 Gbps beyond very short distances. Option C half-duplex is irrelevant in fiber context. Option D is a connector form factor, not the limiting factor. OM1 is generally insufficient for 10 Gbps over typical data center distances.",
      "examTip": "OM1 fiber is often too limited for 10 Gbps beyond short runs; consider OM3/OM4 (50 micron) or single-mode for stable 10 Gbps links."
    },
    {
      "id": 68,
      "question": "Which action is BEST suited to prevent someone with physical access from intercepting unencrypted console management traffic?",
      "options": [
        "Relocate the main distribution frame to an open area",
        "Use a locked rack or cabinet for the core switch",
        "Enable half-duplex on the console port",
        "Shorten DHCP lease times in the server"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A does the opposite. Option B (correct) physically restricts console access. Option C is a duplex setting, not security. Option D addresses IP addresses, not console security.",
      "examTip": "Physical security (locked cabinets) is essential to protect console ports from unauthorized local access."
    },
    {
      "id": 69,
      "question": "Which behavior is characteristic of an IP on-path (man-in-the-middle) attack?",
      "options": [
        "Broadcasting DHCP offers to multiple VLANs",
        "Decrypting SSL traffic without the client’s knowledge by spoofing certificates",
        "Disabling spanning tree to cause a loop",
        "Randomly flooding the ARP table with unrelated MACs"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A might be a rogue DHCP, not necessarily MITM. Option B (correct) an on-path attacker can present fake certs to intercept encrypted traffic. Option C is loop creation. Option D is MAC flooding, a different type of attack. True MITM can intercept and decrypt traffic (if certificate forging is possible).",
      "examTip": "An on-path attacker intercepts traffic stealthily, often using spoofed certs to decrypt TLS sessions."
    },
    {
      "id": 70,
      "question": "A user can browse the intranet but not external sites. They can ping external IPs, but HTTP requests fail. Which setting is likely misconfigured?",
      "options": [
        "Default gateway IP is missing",
        "DNS server address is invalid",
        "MAC address on the NIC is corrupted",
        "The switchport is in half-duplex mode"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is correct for no off-subnet access, but the user can ping external IP addresses, so gateway works. Option B (correct) explains why domain names fail while IP pings succeed. Option C is improbable if IP-level traffic works. Option D might cause collisions but not name resolution failures specifically.",
      "examTip": "If external IP pings work but website names do not, check DNS settings on the client."
    },
    {
      "id": 71,
      "question": "Which OSPF state implies that two routers have formed adjacency and are exchanging full routing information?",
      "options": [
        "2-Way",
        "ExStart",
        "Full",
        "Init"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is partial adjacency. Option B is negotiation of master/slave roles. Option C (correct) is the final adjacency state with full LSDB exchange. Option D is the initial contact. 'Full' indicates fully synchronized LSDBs.",
      "examTip": "OSPF adjacency goes through states: Down, Init, 2-Way, ExStart, Exchange, Loading, Full. 'Full' is complete adjacency."
    },
    {
      "id": 72,
      "question": "A manager wants a single device at remote offices to handle firewall, VPN, content filtering, and intrusion detection. Which solution meets this requirement?",
      "options": [
        "802.1X switch with trunking",
        "UTM (Unified Threat Management) appliance",
        "DHCP server with IP reservations",
        "Spanning Tree-enabled layer 2 switch"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A handles NAC, not all security roles. Option B (correct) merges multiple security features. Option C is address assignment only. Option D is loop prevention, not comprehensive security. UTMs combine firewall, IDS/IPS, AV filtering, etc.",
      "examTip": "A UTM device consolidates various security services into one box, handy for remote or small offices."
    },
    {
      "id": 73,
      "question": "Which situation BEST illustrates why an organization might use a DMZ?",
      "options": [
        "They need to host a publicly accessible web server without exposing internal LAN",
        "They want to tunnel all traffic via SSH to the main site",
        "They intend to store all user home directories behind the firewall",
        "They require secure VLAN trunking between core switches"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) is the classic reason for a DMZ: exposing services externally while protecting the internal network. Option B is a separate remote access method. Option C is internal storage, typically behind the internal firewall. Option D is VLAN architecture, not a DMZ scenario.",
      "examTip": "DMZ is a perimeter network segment for external-facing servers, isolating them from the internal LAN."
    },
    {
      "id": 74,
      "question": "A router must connect multiple subnets but only has one physical interface. Which method is MOST likely used for inter-VLAN routing in this setup?",
      "options": [
        "Enable 802.1X on the router interface",
        "Assign a subinterface for each VLAN with 802.1Q encapsulation (router-on-a-stick)",
        "Use static IP addresses on all VLAN members",
        "Implement NAT on each VLAN"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is port authentication. Option B (correct) a subinterface per VLAN is the classic single-interface routing. Option C is an addressing method, not a routing solution. Option D is address translation, not layer 3 routing for VLANs.",
      "examTip": "Router-on-a-stick uses subinterfaces with VLAN tagging over a single trunk link for multiple VLANs."
    },
    {
      "id": 75,
      "question": "A remote technician must manage a switch that is offline from the primary network. Which solution offers out-of-band management capability?",
      "options": [
        "Use Telnet through the default gateway",
        "Access via a separate dial-up modem or console server link",
        "Configure DHCP relay on the core router",
        "Enable jumbo frames on the switch VLAN"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is in-band and requires a working network. Option B (correct) a dial-up or console server is typical OOB. Option C is a DHCP function, not OOB. Option D is performance, not OOB management.",
      "examTip": "Out-of-band methods like a console server or modem line let you manage devices even if the primary network is down."
    },
    {
      "id": 76,
      "question": "Which tool quickly identifies which switch port a particular cable is connected to by sending an audible tone down the line?",
      "options": [
        "Wi-Fi analyzer",
        "TDR",
        "Toner probe",
        "Cable crimper"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is for wireless. Option B measures length and faults. Option C (correct) locates cables with a tone generator and probe. Option D physically terminates cable ends.",
      "examTip": "A toner probe kit helps trace cables behind walls or in patch panels to find the exact port termination."
    },
    {
      "id": 77,
      "question": "Which is the PRIMARY rationale for network segmentation, such as placing HR systems separate from the corporate LAN?",
      "options": [
        "Achieving higher throughput for VLAN trunking",
        "Preventing broad host scanning across sensitive subnets",
        "Enforcing half-duplex on mission-critical ports",
        "Reducing the scope of spanning tree domains"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is not specifically security-oriented. Option B (correct) segmentation restricts unauthorized scanning or lateral movement. Option C is a performance detriment. Option D is a side effect but not the main driver. Security is key.",
      "examTip": "Segmenting sensitive departments (e.g., HR) helps ensure only authorized traffic can reach those systems."
    },
    {
      "id": 78,
      "question": "A new WAP is deployed to handle 802.11ac clients. Users on the 2.4 GHz band complain about poor speeds. Which factor is MOST relevant?",
      "options": [
        "802.11ac only operates on 5 GHz",
        "802.11ac forces channel bonding at 2.4 GHz",
        "802.11ac does not support WPA2 encryption",
        "802.11ac restricts legacy 802.11b devices from connecting"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) 802.11ac is a 5 GHz-only standard. 2.4 GHz users only get fallback speeds from older protocols (like 802.11n or g). Option B is incorrect. Option C is false; it supports WPA2. Option D is partially true but not the main factor in poor speeds.",
      "examTip": "If 2.4 GHz devices connect to an 802.11ac AP, they use older standards with slower throughput."
    },
    {
      "id": 79,
      "question": "Which statement BEST describes a site-to-site VPN?",
      "options": [
        "An always-on encrypted tunnel between two network gateways",
        "A browser-based SSL portal for teleworkers",
        "A wireless bridge connecting two laptops directly",
        "A dial-up PPP link requiring local client software"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) site-to-site VPNs connect entire networks. Option B is clientless SSL VPN. Option C is a Wi-Fi ad hoc link. Option D is legacy dial-up, not a permanent site tunnel.",
      "examTip": "Site-to-site VPN typically connects two LANs through their gateways, providing persistent secure communication."
    },
    {
      "id": 80,
      "question": "A technician needs to check if a newly added static route is being used. Which Cisco command displays the routing table to confirm the route is present?",
      "options": [
        "show running-config interface",
        "show mac-address-table",
        "show ip route",
        "show ip nat translations"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A shows interface config. Option B is a layer 2 MAC table. Option C (correct) lists IP routing table entries. Option D is NAT mappings. 'show ip route' confirms if the route is installed.",
      "examTip": "On Cisco devices, 'show ip route' is the go-to command for verifying routing table entries."
    },
    {
      "id": 81,
      "question": "Which is the OPTIMAL reason to implement EtherChannel (link aggregation) between two switches?",
      "options": [
        "Provide redundant management IP addresses",
        "Increase port security features for VLAN trunking",
        "Combine multiple physical links into one logical channel for bandwidth and redundancy",
        "Eliminate the need for STP across the aggregated interfaces"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is gateway redundancy, not EtherChannel. Option B is a security approach, not link bundling. Option C (correct) is the main function of EtherChannel. Option D is false; STP still runs but sees the bundle as one interface.",
      "examTip": "EtherChannel (LACP or PAgP) merges multiple Ethernet links for higher throughput and failover."
    },
    {
      "id": 82,
      "question": "A user’s device is assigned a 169.254.x.x address. What does this signify?",
      "options": [
        "APIPA due to no DHCP response",
        "NAT overload IP for internet access",
        "IPv6 address for local link usage",
        "DNS record for an A type host"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) is the Windows auto-configuration address range. Option B is private to public address translation. Option C is a different standard for IPv6 link-local. Option D is an IPv4 forward record, not an APIPA assignment.",
      "examTip": "169.254.x.x indicates the host didn’t receive a DHCP lease and self-assigned an APIPA address for local segment only."
    },
    {
      "id": 83,
      "question": "Which situation calls for changing the OSPF hello and dead timers from their defaults?",
      "options": [
        "When you need to reduce CPU usage on the router",
        "When you want faster convergence or have unreliable links and must adjust keepalive intervals",
        "When you must disable NAT for all subnets",
        "When you want to create a hub-and-spoke VLAN design"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is not typically relevant to adjusting timers. Option B (correct) modifies how quickly routers detect neighbor down events. Option C is unrelated to dynamic routing. Option D is a WAN topology, not about OSPF timers.",
      "examTip": "Changing OSPF hello/dead timers can speed up or slow down adjacency checks, impacting convergence times."
    },
    {
      "id": 84,
      "question": "Which command on a Windows PC renews the DHCP lease if an IP address is currently assigned?",
      "options": [
        "ipconfig /release",
        "arp -d",
        "ipconfig /renew",
        "netstat -r"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A releases the IP but doesn’t reacquire. Option B clears ARP cache, not renewing DHCP. Option C (correct) requests a fresh lease. Option D shows routing table, no lease action.",
      "examTip": "Use 'ipconfig /renew' to request a new DHCP lease after releasing or to force DHCP negotiation."
    },
    {
      "id": 85,
      "question": "A critical server must have exactly the same IP address. Which DHCP feature ensures the server always receives the same IP via DHCP?",
      "options": [
        "DHCP relay agent",
        "PXE boot",
        "Reservations based on MAC address",
        "Multiple DHCP scopes"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A forwards requests across subnets. Option B network boots a machine. Option C (correct) ties a MAC to a specific IP. Option D defines multiple ranges, not static assignment. Reservation is the DHCP method for permanent IP assignment.",
      "examTip": "DHCP reservations link a device’s MAC to a consistent IP without requiring static configuration on the host."
    },
    {
      "id": 86,
      "question": "Which approach do zero-day vulnerabilities exploit?",
      "options": [
        "Unpatched software flaws unknown to the vendor or public",
        "Weak SSID passwords on public hotspots",
        "Configuration drift caused by missing NAT rules",
        "DNSSEC validation on record queries"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) is the definition of zero-day. Option B is a Wi-Fi weakness, not necessarily zero-day. Option C is a config management issue. Option D is a DNS security measure. Zero-days exploit undisclosed or unpatched flaws.",
      "examTip": "Zero-day vulnerabilities are unknown or newly discovered without a vendor patch available, making them particularly dangerous."
    },
    {
      "id": 87,
      "question": "Which term describes ensuring that sensitive financial systems can only be accessed by authorized finance staff and not by other employees?",
      "options": [
        "Least privilege",
        "Evil twin filtering",
        "Port mirroring",
        "VLAN hopping"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) is restricting each user’s access rights. Option B is a rogue AP scenario. Option C duplicates traffic. Option D is an attack vector. Principle of least privilege means finance staff only gets finance resources.",
      "examTip": "Least privilege is fundamental to restricting access—only the minimum necessary permissions for a user’s role."
    },
    {
      "id": 88,
      "question": "A technician wants to test connectivity specifically at layer 3. Which command is primarily used for sending ICMP echo requests to verify reachability?",
      "options": [
        "ping",
        "ftp",
        "ssh",
        "nmap"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) sends ICMP ECHO requests. Option B is file transfer. Option C is secure shell. Option D scans hosts/ports but not a simple echo request. Ping checks basic IP-level connectivity.",
      "examTip": "ping is the go-to tool for verifying layer 3 connectivity with ICMP echo requests."
    },
    {
      "id": 89,
      "question": "Which type of firewall can inspect traffic at layers 5–7 and apply application-specific rules?",
      "options": [
        "Packet filter firewall",
        "Stateful firewall with access lists only",
        "Next-generation firewall",
        "Port-based firewall"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A only checks IP headers. Option B tracks state but not deep application inspection. Option C (correct) performs deep packet inspection at higher layers. Option D is a basic approach focusing on ports. NGFW covers application-level intelligence.",
      "examTip": "Next-generation firewalls provide content inspection and application-level controls beyond simple port filtering."
    },
    {
      "id": 90,
      "question": "A network admin wants to accelerate user authentication by allowing a single set of credentials across multiple internal applications. Which solution is MOST relevant?",
      "options": [
        "Radius with single SSID for all",
        "Single sign-on (SSO) system",
        "Disabling Captive Portal to reduce overhead",
        "Switchport NAC with 802.1X only"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is for network access, not app-level SSO. Option B (correct) unifies authentication tokens across multiple services. Option C is for guest Wi-Fi, not centralized auth. Option D secures port access, not multiple application logins. SSO addresses multiple internal apps under one login.",
      "examTip": "Single sign-on streamlines user credentials across multiple apps to improve convenience and reduce repeated logins."
    },
    {
      "id": 91,
      "question": "Which scenario-based question is MOST directly addressed by implementing a honeypot in the DMZ?",
      "options": [
        "How to safely observe attacker behavior without compromising production systems",
        "How to ensure VLAN trunking for guest traffic",
        "How to block all inbound ICMP requests",
        "How to store backups in an offsite location"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) is the hallmark advantage of honeypots. Option B is about VLAN design. Option C is a firewall rule. Option D is backup policy. Honeypots decoy attackers, letting admins observe threats safely.",
      "examTip": "Honeypots intentionally attract malicious activity to study attackers and keep them away from real systems."
    },
    {
      "id": 92,
      "question": "Which tool is designed to display real-time packets, commonly used in Linux for on-the-fly network traffic capture?",
      "options": [
        "tcpdump",
        "Wi-Fi analyzer",
        "ipconfig",
        "netstat -rn"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) is a CLI packet capture. Option B is for wireless signal analysis. Option C is Windows IP config. Option D shows kernel routing table, not packet details. tcpdump is standard for capturing in Linux.",
      "examTip": "tcpdump is a powerful CLI utility for capturing and analyzing packets on Unix/Linux systems."
    },
    {
      "id": 93,
      "question": "Which direct measure could stop devices from receiving IP addresses from an unauthorized DHCP server on the LAN?",
      "options": [
        "Configure VRRP on the core router",
        "Use DHCP snooping to filter DHCP offers from untrusted ports",
        "Set the switch port to half-duplex",
        "Enable jumbo frame support"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is a gateway redundancy protocol, not DHCP security. Option B (correct) blocks DHCP offers from unknown devices. Option C is a link-level setting. Option D is for frame size, not DHCP control.",
      "examTip": "DHCP snooping is the recommended approach to prevent rogue DHCP servers on your network."
    },
    {
      "id": 94,
      "question": "Which SNMP concept holds device information like interface statistics and can be polled by a network management system?",
      "options": [
        "OID aggregator",
        "Syslog messages",
        "MIB (Management Information Base)",
        "Community strings"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A references SNMP object identifiers but not the data structure. Option B is for log data. Option C (correct) is the database of managed objects. Option D is a shared password approach, not the data itself.",
      "examTip": "The MIB organizes variables managed via SNMP, each identified by an OID, storing device-specific stats."
    },
    {
      "id": 95,
      "question": "A technician is told to verify the security posture of an older layer 2 switch that lacks modern firmware updates. Which measure is the MOST critical to implement immediately?",
      "options": [
        "Enable Telnet on all VLAN interfaces",
        "Disable unused ports or place them in an isolated VLAN",
        "Assign a public IP to the management interface for easy remote access",
        "Set every port to half-duplex for collision avoidance"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is insecure. Option B (correct) prevents unauthorized access via idle ports. Option C exposes management to the internet. Option D is suboptimal performance, not security. Disabling or isolating unused ports is crucial on older gear.",
      "examTip": "Shutting down or isolating unused switch ports helps reduce the attack surface, especially on older hardware."
    },
    {
      "id": 96,
      "question": "A building’s elevator system intermittently jams 2.4 GHz signals. Which immediate workaround can BEST maintain wireless performance?",
      "options": [
        "Stop the elevator's operation during business hours",
        "Switch affected APs to 5 GHz channels where possible",
        "Enable half-duplex mode on APs",
        "Use MAC filtering on elevator control circuits"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is not realistic. Option B (correct) 5 GHz is less prone to interference from such systems. Option C is detrimental to throughput. Option D is unrelated. Elevators or motors can cause 2.4 GHz interference; 5 GHz typically avoids it.",
      "examTip": "If 2.4 GHz is noisy, shift dual-band clients to 5 GHz for better performance and less interference."
    },
    {
      "id": 97,
      "question": "A technician must ensure critical servers have priority over non-essential traffic. Which network mechanism is MOST appropriate?",
      "options": [
        "Captive portal for critical users",
        "SNMPv1 to monitor usage",
        "Quality of Service (QoS) with DSCP marking",
        "Wi-Fi band steering"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is for guest onboarding. Option B is basic monitoring, not prioritization. Option C (correct) classifies and prioritizes important traffic. Option D influences Wi-Fi band usage, not traffic priority. QoS with DSCP ensures mission-critical traffic gets preferential handling.",
      "examTip": "QoS prioritizes time-sensitive or vital data, usually configured using DSCP or similar markings."
    },
    {
      "id": 98,
      "question": "Which type of BGP is typically run between an organization’s edge router and its ISP, exchanging routes between different autonomous systems?",
      "options": [
        "iBGP (internal BGP)",
        "eBGP (external BGP)",
        "OSPF area border",
        "IS-IS multi-level"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is used within the same AS. Option B (correct) is between different AS. Option C references OSPF boundaries, not BGP. Option D is a separate link-state protocol. eBGP is used for internet routing with your provider.",
      "examTip": "External BGP peers with a different autonomous system, commonly used for internet connectivity to an ISP."
    },
    {
      "id": 99,
      "question": "A user cannot access a secure website internally, though others can. The user pings the server successfully. Which FIRST step can clarify the issue?",
      "options": [
        "Check the user’s browser or SSL certificate trust settings",
        "Disable STP on the user’s switch port",
        "Increase DHCP scope for the VLAN",
        "Assign a static route to the server’s IP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) if SSL fails but ping works, it could be a certificate or browser issue. Option B is loop prevention, unrelated. Option C addresses IP capacity, not SSL. Option D is routing, but ping is successful, so routing is fine. TLS/SSL errors often involve certificate or browser misconfigurations.",
      "examTip": "SSL-specific issues typically require verifying browser or certificate trust settings if basic IP connectivity is confirmed."
    },
    {
      "id": 100,
      "question": "Which single configuration change can MOST help contain a malware outbreak if a workstation is compromised, minimizing lateral movement?",
      "options": [
        "Implement host-based firewalls on all endpoints",
        "Combine all VLANs into one large subnet",
        "Disable DHCP on core routers",
        "Assign static DNS server addresses on each user’s PC"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) blocks unauthorized inbound connections at the host, limiting spread. Option B broadens the broadcast domain, making it easier for malware to spread. Option C breaks address allocation. Option D is name resolution config, not an infection containment strategy.",
      "examTip": "Host-based firewalls can isolate an infected machine from scanning or infecting peers, adding another security layer."
    }
  ]
});
