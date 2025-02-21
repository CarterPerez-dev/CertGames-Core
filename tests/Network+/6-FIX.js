db.tests.insertOne({
  "category": "netplus",
  "testId": 6,
  "testName": "Practice Test #6 (Formidable)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A network engineer notices repeated neighbor resets on an eBGP session. Logs show 'Hold Timer Expired.' Which factor is MOST likely causing the flaps?",
      "options": [
        "No default gateway configured on the router",
        "Mismatched BGP hold timers on each side",
        "DHCP scope exhaustion on the LAN",
        "Port security shutting down the interface"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is irrelevant for BGP adjacency if the neighbor addresses are reachable. Option B (correct) is a classic cause: if hold timers differ or keepalives fail, sessions reset. Option C is unrelated to BGP. Option D would produce different logs. Ensuring both ends have consistent timers prevents frequent resets.",
      "examTip": "Always confirm BGP keepalive and hold timers match. Mismatches often trigger hold-time expiry and session flaps."
    },
    {
      "id": 2,
      "question": "A company is deploying a private cloud. Which advantage does IaaS provide compared to physical on-prem servers?",
      "options": [
        "Physical hardware is typically cheaper than virtual resources",
        "Instant elasticity to provision and deprovision compute resources",
        "No requirement for hypervisors or virtualization layers",
        "Fewer security controls are necessary"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is often the opposite; virtualization can be more cost-effective. Option B (correct) is the main benefit of IaaS, offering dynamic scalability. Option C is false because virtualization underlies IaaS. Option D is incorrect; cloud environments often require robust security. IaaS simplifies infrastructure provisioning through automation.",
      "examTip": "IaaS allows you to spin up and tear down VMs quickly, matching resource demands without buying new hardware."
    },
    {
      "id": 3,
      "question": "Which is the PRIMARY reason to configure STP portfast on an access port connecting to a single workstation?",
      "options": [
        "To drop any DHCP traffic on that port",
        "To allow immediate transition to forwarding state with no delay",
        "To force trunk negotiations automatically",
        "To encrypt user data at layer 2"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is unrelated to STP. Option B (correct) speeds up port convergence for end-host ports. Option C references DTP trunking, not portfast. Option D is outside STP's scope. Portfast bypasses listening/learning states, enabling quick connectivity for end devices.",
      "examTip": "Use portfast on access ports to reduce STP convergence delays when end devices connect."
    },
    {
      "id": 4,
      "question": "An IDS passively observes suspicious traffic but cannot drop packets. Which deployment mode allows an IPS to actually block malicious flows?",
      "options": [
        "Out-of-band sensor on a SPAN port",
        "Inline placement between the switch and the internal network",
        "Tap-based capture with no physical blocking",
        "Port mirroring session in the DMZ"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A, C, and D are passive approaches. Option B (correct) an inline IPS can intercept and reject harmful traffic. Passive sensors only alert, while inline IPS devices can actively mitigate threats.",
      "examTip": "For real-time blocking, place the IPS inline so it can inspect and drop malicious packets on the fly."
    },
    {
      "id": 5,
      "question": "Which direct feature can isolate a compromised device by automatically placing its switch port into a quarantine VLAN upon a failed NAC posture check?",
      "options": [
        "BPDU filter",
        "DHCP relay agent",
        "802.1X with dynamic VLAN assignment",
        "VTP pruning"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A handles spanning tree frames, Option B is for forwarding DHCP broadcasts, Option C (correct) NAC solutions can reassign non-compliant endpoints to a restricted VLAN. Option D prunes VLANs but doesn’t isolate compromised hosts. Dynamic VLAN assignment is common in NAC implementations.",
      "examTip": "802.1X NAC can dynamically move endpoints into a 'quarantine' VLAN if they fail security posture checks."
    },
    {
      "id": 6,
      "question": "An organization wants to prevent route updates from being maliciously injected. Which method is BEST to authenticate OSPF routes?",
      "options": [
        "Enable port security on all router interfaces",
        "Configure OSPF MD5 or key chain authentication",
        "Use half-duplex across OSPF neighbors",
        "Block HTTP traffic on TCP port 80"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is a layer 2 measure. Option B (correct) uses cryptographic checks to validate legitimate OSPF peers. Option C is a link setting, not route security. Option D is a firewall rule, unrelated to OSPF updates.",
      "examTip": "OSPF can support plain-text or MD5 authentication. MD5 is strongly recommended to avoid rogue route injection."
    },
    {
      "id": 7,
      "question": "Which DNS record type is used for reverse lookups, mapping an IP address back to a hostname?",
      "options": [
        "AAAA",
        "PTR",
        "NS",
        "TXT"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is IPv6, Option B (correct) is pointer for reverse DNS, Option C indicates a DNS nameserver, Option D is free-form text. PTR records link IPs to hostnames in reverse zones.",
      "examTip": "PTR records live in reverse DNS zones: IP -> name."
    },
    {
      "id": 8,
      "question": "On a multi-layer switch, several VLANs no longer route after a config rollback. Which FIRST step should you check?",
      "options": [
        "Verify each Switch Virtual Interface (SVI) is in an 'up/up' state with correct IPs",
        "Set the default gateway on every client to 0.0.0.0",
        "Enable jumbo frames for all VLANs",
        "Reduce DHCP lease times on each scope"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) is crucial for inter-VLAN routing. Option B breaks routing, Option C is performance, not routing, Option D is address management. If SVIs are down or missing IPs, routing fails.",
      "examTip": "Always confirm that each SVI is up and has a proper IP for inter-VLAN routing to function."
    },
    {
      "id": 9,
      "question": "Which scenario BEST justifies implementing a warm site for disaster recovery?",
      "options": [
        "Needing sub-second failover with zero downtime",
        "Recovering within hours with partially staged systems",
        "Storing only tape backups offsite",
        "Performing monthly vulnerability scans"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is a hot site scenario, Option B (correct) matches warm site with moderate readiness, Option C is a cold site approach, Option D is standard security practice. A warm site is partially equipped and can be activated faster than a cold site.",
      "examTip": "Warm sites balance cost and recovery time, typically able to come online in hours if hardware is pre-installed."
    },
    {
      "id": 10,
      "question": "A new firewall is dropping inbound HTTPS to a public web server. Which is the FIRST item to verify for proper NAT?",
      "options": [
        "Confirm the correct public IP and TCP 443 are forwarded to the server's private IP",
        "Enable jumbo frames for faster forwarding",
        "Install a load balancer in the DMZ",
        "Set half-duplex on the DMZ interface"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) if NAT is misconfigured, external users cannot reach the server on port 443. Option B is a frame-size tweak, not NAT. Option C might help scaling, not NAT basics. Option D is a link-layer setting that rarely solves NAT issues.",
      "examTip": "Check port-forward rules or NAT translation carefully to ensure inbound traffic on port 443 routes to the correct host."
    },
    {
      "id": 11,
      "question": "Which protocol is used for time synchronization in enterprise networks, ensuring consistent clocks across devices?",
      "options": [
        "SNMP",
        "RDP",
        "NTP",
        "Telnet"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is for network management, Option B is remote desktop, Option C (correct) Network Time Protocol, Option D is unencrypted CLI. NTP coordinates clock synchronization across hosts.",
      "examTip": "Consistent time is critical for logs, authentication, and security. NTP typically runs over UDP 123."
    },
    {
      "id": 12,
      "question": "A switch's MAC table is suddenly flooded with bogus entries, causing frames to be broadcast. Which security feature prevents this?",
      "options": [
        "Storm control to limit broadcast rate",
        "Spanning Tree Protocol root guard",
        "Port security restricting learned MAC addresses",
        "DHCP snooping on untrusted ports"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A mitigates broadcast storms but not specifically MAC flooding. Option B ensures STP root stability. Option C (correct) can shut down a port if too many MACs appear. Option D is for DHCP offers, not MAC table attacks.",
      "examTip": "MAC flooding tries to overflow the CAM table, turning the switch into a hub. Port security can limit MAC count on a port."
    },
    {
      "id": 13,
      "question": "A network sees multiple VLANs inadvertently trunked to an unauthorized device. Which direct setting is MOST effective at preventing this scenario?",
      "options": [
        "Set trunk ports to dynamic desirable",
        "Disable DTP and configure trunk/access mode statically",
        "Enforce native VLAN 1 across all ports",
        "Use DHCP reservations for device IPs"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A still negotiates trunking automatically. Option B (correct) ensures no auto trunk formation. Option C is default but not necessarily secure. Option D is IP-level, not trunk config. Hard-coding trunk or access prevents unexpected VLAN trunking.",
      "examTip": "Always disable dynamic trunk negotiation on ports that don’t need it, specifying trunk or access explicitly."
    },
    {
      "id": 14,
      "question": "Which improvement does Wi-Fi 6 (802.11ax) bring over previous standards?",
      "options": [
        "Dependence on WEP encryption for speed",
        "Support only for 2.4 GHz channels",
        "OFDMA and improved multi-user efficiency",
        "Mandatory half-duplex across all devices"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is insecure, Option B is false (it supports 2.4 and 5/6 GHz), Option C (correct) is the hallmark of 11ax. Option D is normal for wireless at layer 2, but not the key new feature. OFDMA significantly improves performance for many clients simultaneously.",
      "examTip": "802.11ax (Wi-Fi 6) uses OFDMA to subdivide channels, boosting efficiency in high-density environments."
    },
    {
      "id": 15,
      "question": "Which question does SD-WAN primarily solve for distributed branch offices?",
      "options": [
        "How to unify cable labeling across racks",
        "How to transport traffic over multiple links with centralized policy control",
        "How to block Layer 2 loops on core switches",
        "How to share SNMP community strings securely"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is a physical org question, Option B (correct) is precisely SD-WAN’s function. Option C references spanning tree, Option D is management config. SD-WAN orchestrates traffic across various WAN connections, applying central policies.",
      "examTip": "SD-WAN provides intelligent path selection and orchestration for remote branches, often mixing MPLS, broadband, LTE, etc."
    },
    {
      "id": 16,
      "question": "A router defaults to a route learned from EIGRP over one learned from OSPF for the same prefix. Which factor decides this behavior?",
      "options": [
        "Hop count mismatch",
        "Administrative distance",
        "Link-state vs distance-vector preference",
        "Prefix length"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is an internal metric. Option B (correct) EIGRP has a lower AD (90) than OSPF (110). Option C is conceptual but not how the router chooses. Option D is relevant only if mask differs. Lower AD is the deciding factor.",
      "examTip": "Routers prefer routes from the protocol with the lowest administrative distance if the prefix is identical."
    },
    {
      "id": 17,
      "question": "Why might one configure a router to advertise 'default-information originate' in OSPF?",
      "options": [
        "To ensure NAT is disabled on that interface",
        "To inject a default route so downstream routers know where to send internet-bound traffic",
        "To block all inbound connections on port 443",
        "To reduce ARP broadcast domains"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is not related, Option B (correct) shares the 0.0.0.0/0 route with OSPF neighbors. Option C is a firewall rule, Option D is a VLAN or subnet design matter. 'default-information originate' helps OSPF devices learn a default route.",
      "examTip": "OSPF does not automatically forward a default route unless you configure 'default-information originate' (and have a valid default route)."
    },
    {
      "id": 18,
      "question": "A wireless survey suggests high co-channel interference on 5 GHz channels. Which FIRST measure addresses this directly?",
      "options": [
        "Enable 40–80 MHz channel bonding on all APs",
        "Increase transmit power to overpower adjacent APs",
        "Reduce channel width to 20 MHz on congested APs",
        "Disable WPA3 to reduce encryption overhead"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A can worsen overlap, Option B can lead to more interference, Option C (correct) less channel bonding means more distinct channels, Option D reduces security with no direct effect on interference. Narrower channels help avoid co-channel overlap in dense deployments.",
      "examTip": "In crowded 5 GHz spaces, smaller channel widths can alleviate co-channel interference by maximizing non-overlapping channels."
    },
    {
      "id": 19,
      "question": "A host's IP is 10.0.5.9/29. What is the broadcast address for its subnet?",
      "options": [
        "10.0.5.7",
        "10.0.5.14",
        "10.0.5.8",
        "10.0.5.15"
      ],
      "correctAnswerIndex": 3,
      "explanation": "For 10.0.5.8/29, the network is 10.0.5.8, usable range .9–.14, and broadcast .15 (correct). Option A .7 would be for the 10.0.5.0/29 block. Option B .14 is a usable IP, Option C .8 is the network address. Therefore, .15 is the broadcast.",
      "examTip": "A /29 yields 8 total IP addresses: network, 6 host IPs, and one broadcast. In the 10.0.5.8–15 block, .15 is broadcast."
    },
    {
      "id": 20,
      "question": "Which firewall approach inspects application-layer data (layer 7) to decide if traffic should be allowed?",
      "options": [
        "Stateless packet filter",
        "Next-generation firewall",
        "Stateful ACL-based firewall only",
        "DHCP relay firewall"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A only checks headers at layers 3–4. Option B (correct) NGFWs include deep packet inspection at layer 7. Option C is stateful but not necessarily layer 7. Option D is not a typical firewall type. NGFW can identify apps and enforce advanced policies.",
      "examTip": "Next-generation firewalls analyze traffic at higher layers, including content inspection, user identification, and more."
    },
    {
      "id": 21,
      "question": "A network admin sees frequent interface errors labeled as runts and giants. Which mismatch is MOST likely to cause these frame size discrepancies?",
      "options": [
        "Native VLAN mismatch on trunk",
        "802.1X misconfiguration",
        "MTU or speed/duplex mismatch",
        "Incorrect DHCP server options"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is trunk VLAN mismatch but typically shows VLAN issues, Option B is authentication, Option C (correct) can produce frames too large or too small, causing runts/giants. Option D is IP config, not layer 2 frame errors.",
      "examTip": "Frame size errors often trace back to mismatched MTU or duplex configurations at physical interfaces."
    },
    {
      "id": 22,
      "question": "Which scenario-based question is BEST addressed by using a VLAN ACL to block production traffic from a lab VLAN?",
      "options": [
        "How to reduce IP addresses used in DHCP",
        "How to restrict lab users from accessing sensitive production servers",
        "How to enforce jumbo frames on trunk links",
        "How to configure spanning tree root guard"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is IP management, not ACL security. Option B (correct) is a typical reason for a VLAN access control list. Option C is performance, Option D is loop prevention. VLAN ACLs can isolate or restrict traffic between subnets or VLANs.",
      "examTip": "ACLs at the VLAN or interface level can block specific traffic flows, preventing unauthorized cross-VLAN access."
    },
    {
      "id": 23,
      "question": "A company’s public DNS server must be reachable from the internet. Which firewall rule is MOST appropriate?",
      "options": [
        "Block all inbound requests to port 53",
        "Allow inbound UDP and TCP port 53 to the DNS server IP",
        "Enable DHCP snooping on the DNS VLAN",
        "Allow only HTTPS inbound on port 443"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A denies DNS queries entirely, Option B (correct) open port 53 for DNS queries, Option C is unrelated, Option D is for web traffic. DNS commonly uses UDP 53 for queries, but TCP 53 for large zone transfers or DNSSEC.",
      "examTip": "For DNS, allow both UDP and TCP 53 inbound if hosting authoritative services. UDP is typical, but large transfers may need TCP."
    },
    {
      "id": 24,
      "question": "Which is the MAIN characteristic of a zero trust architecture in enterprise networks?",
      "options": [
        "All internal traffic is automatically trusted",
        "Extensive VLAN trunking for every edge port",
        "Frequent user/device authentication for each resource request",
        "No external traffic is ever allowed"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is the opposite of zero trust, Option B is about VLAN design, Option C (correct) is the crux of zero trust. Option D is extreme and not typical. Zero trust requires continuous verification of identity and posture.",
      "examTip": "Zero trust means 'never trust, always verify,' applying checks even inside the LAN."
    },
    {
      "id": 25,
      "question": "An engineer needs to gather traffic from multiple VLANs to a single analysis device. Which switch feature accomplishes this?",
      "options": [
        "NAC posture checks on each port",
        "Port mirroring (SPAN) session filtering by VLAN",
        "IGMP snooping for multicast",
        "EtherChannel bundling"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is authentication compliance, Option B (correct) can replicate traffic from VLANs or ports to a monitor port, Option C handles multicast membership, Option D is link aggregation. SPAN or RSPAN can capture VLAN traffic to one port.",
      "examTip": "Port mirroring/monitoring (SPAN) duplicates traffic so you can analyze or capture it on a single interface."
    },
    {
      "id": 26,
      "question": "Which approach ensures that a wireless AP automatically adjusts its channel or power based on detected RF interference?",
      "options": [
        "MAC filtering for rogue SSIDs",
        "Rogue detection on the controller",
        "Dynamic radio resource management by the WLC",
        "Captive portal enforcement"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is basic authentication measure, Option B is scanning for unauthorized APs, Option C (correct) many enterprise controllers dynamically tune channels/power, Option D is user login. RRM automatically adjusts AP settings for optimal coverage.",
      "examTip": "Controller-based WLANs often have auto-RF or RRM features that adapt channel and power to reduce interference."
    },
    {
      "id": 27,
      "question": "Which FIRST action is most logical if a switch logs show repeated TCN (Topology Change Notification) events in spanning tree?",
      "options": [
        "Disable STP on all ports to avoid recalculations",
        "Locate flapping interfaces or ports toggling up/down",
        "Enable jumbo frames to reduce overhead",
        "Reboot all distribution switches"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is dangerous, leading to loops, Option B (correct) is the standard method to find the cause. Option C is performance, not topology changes. Option D is disruptive. Frequent TCNs typically stem from a port going up/down repeatedly.",
      "examTip": "When STP keeps recalculating, check for a port or device flapping. Fix that instability to reduce TCN floods."
    },
    {
      "id": 28,
      "question": "A high-security site wants to protect switch configurations from unauthorized alterations. Which method ensures a device logs every change and ties it to a specific admin?",
      "options": [
        "Enable local user admin with shared credentials",
        "Use TACACS+ for per-command authentication and accounting",
        "Disable SNMP on the switch",
        "Deploy a DHCP reservation for the switch IP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A cannot track individual changes if credentials are shared. Option B (correct) TACACS+ logs each command and which admin executed it. Option C is good for security but not command tracking. Option D ensures consistent IP but not auditing. TACACS+ provides command-level accounting.",
      "examTip": "AAA with TACACS+ or RADIUS can record who made each configuration change, essential for compliance and auditing."
    },
    {
      "id": 29,
      "question": "Which phenomenon describes unused open ports left unprotected, creating potential security vulnerabilities?",
      "options": [
        "Server sprawl",
        "Application whitelisting",
        "Open port exposure or 'listening port creep'",
        "Full mesh network design"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is about unmanaged servers, Option B is security strategy for apps, Option C (correct) open listening ports that are not needed can be exploited, Option D is a topology. Minimizing open ports reduces attack surfaces.",
      "examTip": "Periodically audit listening services. Close or firewall unused ports to reduce vulnerabilities."
    },
    {
      "id": 30,
      "question": "Which step is MOST relevant for verifying that OSPF neighbors have fully exchanged link-state databases after adjacency is formed?",
      "options": [
        "Confirm the final OSPF state is 'Full'",
        "Check if the trunk ports are half-duplex",
        "Lower the DHCP lease time across the OSPF routers",
        "Enable port mirroring to capture OSPF packets"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) indicates complete adjacency. Option B is a link setting, not adjacency verification. Option C is about IP leasing, not routing. Option D is a passive capture method. 'Full' state means OSPF neighbors have synchronized LSDBs.",
      "examTip": "OSPF transitions through states (Down, Init, 2-Way, ExStart, Exchange, Loading, Full). 'Full' means full adjacency."
    },
    {
      "id": 31,
      "question": "A user complains of abnormally high latency when accessing a remote data center. Which command helps identify if a particular hop is introducing delays?",
      "options": [
        "ping -t",
        "traceroute/tracert",
        "ipconfig /renew",
        "arp -a"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A checks continuous connectivity but not each hop. Option B (correct) shows per-hop latency. Option C renews DHCP, Option D shows ARP cache. Traceroute identifies which router hop may be slowing traffic.",
      "examTip": "Use traceroute/tracert to discover path hops and pinpoint excessive response times or unreachable nodes."
    },
    {
      "id": 32,
      "question": "Which scenario would benefit MOST from implementing VRRP or HSRP on the default gateway?",
      "options": [
        "Needing a single private IP for NAT with multiple public IPs",
        "Ensuring a backup gateway if the primary router fails",
        "Enforcing WPA2 Enterprise on the Wi-Fi network",
        "Collecting NetFlow data on the LAN interfaces"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is about NAT. Option B (correct) VRRP/HSRP provide a virtual IP with redundancy. Option C is wireless security, Option D is traffic analysis. First-hop redundancy ensures continuous gateway availability.",
      "examTip": "First Hop Redundancy Protocols (VRRP, HSRP, GLBP) let multiple routers present one virtual gateway IP, preventing downtime if one router fails."
    },
    {
      "id": 33,
      "question": "A distribution switch CPU is maxed out due to broadcast traffic in a single flat network. Which direct remedy can reduce this broadcast domain?",
      "options": [
        "Implement multiple VLANs and inter-VLAN routing",
        "Enable jumbo frames for layer 2 traffic",
        "Use NAT on each switch interface",
        "Deploy a honeypot in the DMZ"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) smaller VLANs reduce broadcast storms. Option B is a frame-size tweak, not a domain fix. Option C is typically a layer 3 function on routers, not for broadcast reduction. Option D is unrelated to broadcast containment.",
      "examTip": "Splitting large layer 2 segments into multiple VLANs drastically cuts broadcast traffic overhead."
    },
    {
      "id": 34,
      "question": "Which of the following specifically helps mitigate VLAN hopping attacks?",
      "options": [
        "Use static trunk assignments and disable DTP",
        "Enable half-duplex on the trunk ports",
        "Use a single /8 subnet across all VLANs",
        "Increase DHCP scope size"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) stops double-tagging or auto-trunking exploits. Option B is link performance, not security. Option C merges all hosts into one big subnet, risky. Option D is an IP address measure, not relevant. VLAN hopping is prevented by disabling DTP and strictly defining trunk/access modes.",
      "examTip": "To avoid VLAN hopping, disable trunk auto-negotiation and assign a distinct native VLAN (never VLAN 1) on trunk ports."
    },
    {
      "id": 35,
      "question": "Which condition is MOST indicative of a SYN flood attack on a server?",
      "options": [
        "High volume of half-open TCP connections",
        "Repeated DNS requests for an invalid domain",
        "Mass ARP broadcast from the same MAC",
        "Excessive 802.1Q trunk negotiation logs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) is the hallmark of SYN floods. Option B suggests DNS spam, Option C is ARP-related, Option D is trunk config. SYN floods exploit partial TCP handshakes, filling the server’s backlog queue.",
      "examTip": "A SYN flood attempts to exhaust a server’s half-open connection table by sending many SYNs without completing the handshake."
    },
    {
      "id": 36,
      "question": "Which technology allows an IPv6 host to access IPv4-only websites by translating IPv6 requests into IPv4 packets?",
      "options": [
        "Dual stack",
        "NAT64",
        "6to4 tunnel",
        "ISATAP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A uses both stacks simultaneously, no translation. Option B (correct) converts IPv6 traffic to IPv4. Option C encapsulates IPv6 in IPv4. Option D is a tunneling mechanism inside IPv4. NAT64 specifically translates protocols, letting IPv6-only clients reach IPv4 services.",
      "examTip": "NAT64 is used when you have IPv6-only hosts needing to talk to IPv4 servers. The translator sits at the network boundary."
    },
    {
      "id": 37,
      "question": "Which approach is BEST for collecting netflow data on a router to analyze traffic patterns?",
      "options": [
        "Enable port mirroring on every interface to a single monitor port",
        "Configure the router to export flow statistics to a collector IP",
        "Use DHCP snooping on untrusted interfaces",
        "Set VLAN 1 as native on all trunk ports"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is a hardware port approach, not netflow. Option B (correct) netflow typically exports flow records to a collector. Option C is DHCP security, Option D is VLAN trunk detail. Flow analysis is done by enabling netflow on the router and sending data to a flow collector.",
      "examTip": "Netflow or sFlow is configured on the device, which sends summarized flow data to a central collector for analysis."
    },
    {
      "id": 38,
      "question": "A new RADIUS server certificate was not renewed, causing wireless clients to fail 802.1X authentication. Which direct symptom indicates this problem?",
      "options": [
        "WPA2-PSK passphrase mismatch message",
        "Clients see a warning about the server certificate or cannot connect at all",
        "DHCP server logs show scope exhaustion",
        "Switch port negotiation is stuck in half-duplex"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is for pre-shared keys, Option B (correct) a failing or untrusted RADIUS certificate breaks EAP. Option C is address pool usage, Option D is a link-layer mismatch. Expired RADIUS cert leads to EAP failure or certificate prompts.",
      "examTip": "802.1X with EAP requires a valid server certificate. If it’s expired, clients can’t complete the authentication handshake."
    },
    {
      "id": 39,
      "question": "Which statement describes the difference between iBGP and eBGP sessions?",
      "options": [
        "iBGP is used to route within the same AS; eBGP is for routing between different AS domains",
        "iBGP uses TCP port 23, eBGP uses port 25",
        "iBGP is always preferred over OSPF, eBGP is never used in large ISPs",
        "iBGP requires all routers to be connected in a full mesh physically"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) is the fundamental difference. Option B uses incorrect ports (BGP is port 179). Option C is false, eBGP is used widely by ISPs. Option D is logical mesh or route reflectors, not necessarily physical. iBGP is internal, eBGP external to the AS.",
      "examTip": "iBGP is within the same AS, eBGP is between different AS domains, but both use TCP port 179."
    },
    {
      "id": 40,
      "question": "A switch keeps shutting down a port after detecting multiple MAC addresses. Which is the MOST likely feature causing this?",
      "options": [
        "Root guard for spanning tree",
        "BPDU filter blocking BPDUs",
        "Port security with a MAC address limit",
        "DHCP snooping for rogue servers"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A ensures STP root stability, Option B discards BPDUs, Option C (correct) triggers an err-disable if too many MACs appear. Option D is DHCP-based. Port security can limit MAC addresses and shut the port if exceeded.",
      "examTip": "Port security often places a port in error-disabled state upon detecting multiple unauthorized MACs."
    },
    {
      "id": 41,
      "question": "Which scenario-based question is BEST resolved by implementing a honeynet in the DMZ?",
      "options": [
        "How to centralize logs from multiple syslog sources",
        "How to collect threat intelligence by luring attackers to fake hosts",
        "How to reduce broadcast traffic in a large subnet",
        "How to block all inbound telnet attempts"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is log aggregation, Option B (correct) describes a honeynet’s purpose, Option C is broadcast domain design, Option D is a firewall ACL. A honeynet or honeypot is a decoy environment for studying attacker methods.",
      "examTip": "Honeynets attract malicious activity, letting defenders observe or capture attackers’ techniques safely."
    },
    {
      "id": 42,
      "question": "A router is discarding packets with a 'time-to-live exceeded' error. At which OSI layer is TTL processed?",
      "options": [
        "Layer 2",
        "Layer 3",
        "Layer 5",
        "Layer 7"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is MAC addressing, Option B (correct) IP header includes TTL, Option C is session, Option D is application. Routers decrement TTL at layer 3 and discard if it hits zero.",
      "examTip": "TTL (time to live) is an IP-layer field used to prevent routing loops."
    },
    {
      "id": 43,
      "question": "Which direct measure stops devices from getting IP addresses from an unauthorized DHCP server on the LAN?",
      "options": [
        "Enable DHCP snooping on relevant VLANs",
        "Use default gateway 0.0.0.0 for all clients",
        "Disable STP root guard on trunk links",
        "Block port 443 inbound on the router"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) drops DHCP offers from untrusted ports, Option B is not valid, Option C is about STP stability, Option D is HTTPS blocking. DHCP snooping ensures only trusted interfaces can respond to DHCP requests.",
      "examTip": "DHCP snooping is crucial for preventing rogue DHCP servers from handing out bad IP configs."
    },
    {
      "id": 44,
      "question": "Which action helps mitigate an on-path (man-in-the-middle) attack attempting to spoof the default gateway MAC?",
      "options": [
        "Implement dynamic ARP inspection to validate ARP replies",
        "Disable DNSSEC on the local DNS server",
        "Set all switchports to half-duplex",
        "Enable jumbo frames for fewer packets"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) DAI checks ARP messages against known IP-to-MAC bindings. Option B removing DNSSEC doesn't help. Option C is a link setting, Option D is a performance tweak. DAI prevents ARP spoofing by verifying ARP data with DHCP snooping or static entries.",
      "examTip": "Dynamic ARP Inspection (DAI) blocks ARP spoofing, a common MITM technique, by verifying ARP packets."
    },
    {
      "id": 45,
      "question": "A router references a default route in its routing table for all unknown networks. Which prefix commonly represents this default route?",
      "options": [
        "255.255.255.255/32",
        "10.0.0.0/8",
        "0.0.0.0/0",
        "192.168.0.0/16"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is a single host route, Option B is private class A, Option C (correct) is the default route, Option D is a private class B. 0.0.0.0/0 indicates all IP addresses not in a more specific route.",
      "examTip": "A default route is typically shown as 0.0.0.0/0 in IPv4 routing tables."
    },
    {
      "id": 46,
      "question": "Which would be the FIRST step to investigate if a BGP peer remains stuck in 'Idle' state?",
      "options": [
        "Check if an access list blocks TCP port 179",
        "Disable STP on the WAN switch",
        "Enable half-duplex on the interface",
        "Lower the DHCP lease time"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) BGP relies on TCP port 179. A blocked port can keep it in Idle. Option B is irrelevant to BGP, Option C is a link setting, Option D is IP lease management. Confirm connectivity on port 179 for BGP adjacency.",
      "examTip": "BGP neighbors form a TCP session on port 179. Firewalls or ACLs blocking that port prevent adjacency."
    },
    {
      "id": 47,
      "question": "A user claims they can ping an internal server but cannot access it via HTTPS. Others have no issue. Which FIRST check helps isolate the cause?",
      "options": [
        "Ensure the user's browser or TLS settings are correct",
        "Disable STP root guard on the user’s port",
        "Move the user to the native VLAN",
        "Reboot the entire distribution switch"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) if ping works, IP connectivity is fine. SSL or browser settings might be blocking HTTPS. Option B is loop prevention, not SSL. Option C is VLAN config, not necessarily relevant. Option D is too disruptive. Likely the user’s HTTPS or certificate setting is misconfigured.",
      "examTip": "If an IP-level ping works but HTTPS fails, suspect browser configuration, SSL certificates, or firewall restrictions."
    },
    {
      "id": 48,
      "question": "Which wireless feature introduces multi-user MIMO and OFDMA to handle numerous clients simultaneously on 2.4 and 5 GHz bands?",
      "options": [
        "802.11g",
        "802.11n",
        "802.11ac",
        "802.11ax (Wi-Fi 6)"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Option A is older 2.4 GHz standard, Option B 2.4/5 GHz but older, Option C is 5 GHz, Option D (correct) is Wi-Fi 6 with OFDMA and MU-MIMO. 802.11ax significantly improves multi-user efficiency.",
      "examTip": "Wi-Fi 6 (802.11ax) uses OFDMA and MU-MIMO to handle high-density deployments more efficiently."
    },
    {
      "id": 49,
      "question": "Which is the PRIMARY benefit of enabling root guard on access switch ports that should never become root?",
      "options": [
        "It enforces half-duplex operation on untrusted ports",
        "It prevents a potential rogue switch from taking over as STP root bridge",
        "It allows VLAN trunk negotiation automatically",
        "It assigns a static default gateway for all end users"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is not relevant, Option B (correct) ensures no device on that port can claim root. Option C is about trunk negotiation, Option D is IP-based. Root guard protects STP from an unauthorized switch becoming root by sending superior BPDUs.",
      "examTip": "Root guard enforces the designated root; if a port receives better BPDUs, that port is put in root-inconsistent state."
    },
    {
      "id": 50,
      "question": "Which question is BEST addressed by implementing SASE (Secure Access Service Edge)?",
      "options": [
        "How to unify WAN optimization, security, and cloud-based access for remote users",
        "How to reduce the cost of on-prem layer 2 switches",
        "How to store only static ARP tables on the router",
        "How to physically protect the MDF in a campus building"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) SASE merges SD-WAN and security into a cloud-based service for distributed workforces. Option B references hardware cost, Option C is an ARP approach, Option D is physical security. SASE addresses secure, scalable edge services for remote and branch users.",
      "examTip": "SASE converges network and security functions at the cloud edge for consistent, secure access from anywhere."
    },
    {
      "id": 51,
      "question": "Which is the PRIMARY driver behind using MPLS in enterprise WANs?",
      "options": [
        "Packet-level encryption for all data in transit",
        "Label-switched paths for predictable performance and QoS",
        "Automatic spanning tree root election across the WAN",
        "Complete elimination of IP addresses on the WAN"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is false; MPLS does not inherently encrypt. Option B (correct) MPLS uses labels for efficient routing and QoS. Option C is a LAN concept, Option D is also untrue. MPLS provides traffic engineering, not default encryption.",
      "examTip": "MPLS uses labels to forward traffic along predetermined paths, supporting QoS and traffic engineering."
    },
    {
      "id": 52,
      "question": "A remote user repeatedly connects to the SSL VPN but cannot reach internal hosts afterward. Others have no issue. Which FIRST troubleshooting step is logical?",
      "options": [
        "Disable the user’s Active Directory account",
        "Have the user verify IP configuration assigned by the VPN, including default gateway",
        "Assign the user to VLAN 1 at all times",
        "Enable SNMP traps on the user’s PC"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is punitive without diagnosis, Option B (correct) ensures the user’s VPN tunnel interface has correct IP, netmask, gateway, Option C is insecure best practice, Option D is monitoring. Possibly a local route or default gateway is missing if they can’t reach internal hosts.",
      "examTip": "Always confirm the client’s VPN-assigned IP details. If the default route or netmask is incorrect, internal access fails."
    },
    {
      "id": 53,
      "question": "Which statement is TRUE regarding channel overlap in the 2.4 GHz band?",
      "options": [
        "Channels 1, 6, and 11 are typically used to avoid overlap",
        "Any channel combination can co-exist without interference",
        "2.4 GHz has infinite non-overlapping channels",
        "Only channel 5 has no overlap"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) they’re the standard non-overlapping channels in many regions. Option B is untrue, channel overlap is common. Option C is false; 2.4 GHz only has 3–4 non-overlapping channels depending on country. Option D is incorrect. Using 1, 6, 11 helps minimize interference.",
      "examTip": "2.4 GHz is limited. Channels 1, 6, 11 are recommended to avoid overlap in the majority of regulatory domains."
    },
    {
      "id": 54,
      "question": "Which scenario is BEST resolved by using a clientless SSL VPN?",
      "options": [
        "A site-to-site VPN between headquarters and a branch router",
        "Employees needing secure remote access without installing a dedicated VPN client",
        "Encrypting broadcast traffic in a local VLAN",
        "Requiring PPP dial-up connections for traveling staff"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is site-to-site, typically IPSec. Option B (correct) a user can connect from a browser-based SSL portal. Option C is a local network measure. Option D is a legacy dial-up method. Clientless VPNs simplify remote user access with just a browser.",
      "examTip": "Clientless SSL VPN solutions allow remote users to securely access internal resources via HTTPS without specialized client software."
    },
    {
      "id": 55,
      "question": "A router needs to hand out IP addresses to local clients. Which protocol or service accomplishes this automatically?",
      "options": [
        "DNSSEC",
        "ARP",
        "DHCP",
        "SSH"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A secures DNS records, Option B resolves MAC addresses, Option C (correct) auto-assigns IP addresses, Option D is remote admin. DHCP is for dynamic address allocation.",
      "examTip": "Dynamic Host Configuration Protocol is standard for assigning IP addresses, subnet masks, gateways, DNS, etc."
    },
    {
      "id": 56,
      "question": "A help desk technician sees ping succeed but traceroute fails beyond the first hop. Which protocol is likely being blocked, causing traceroute to fail?",
      "options": [
        "TCP port 21",
        "UDP or ICMP replies used by traceroute",
        "SNMPv3 authentication packets",
        "SYSLOG messages on port 514"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is FTP, Option B (correct) traceroute commonly uses UDP or ICMP echo for hop discovery, Option C is for management queries, Option D is logging. Many firewalls block traceroute’s higher ports or ICMP TTL exceeded messages.",
      "examTip": "Traceroute typically uses UDP with incrementing ports (or ICMP on Windows). If these are blocked, traceroute fails beyond the first hop."
    },
    {
      "id": 57,
      "question": "A technician must verify whether malicious DNS responses are being injected on the wire. Which solution is BEST for authenticating DNS records?",
      "options": [
        "DNSSEC",
        "DHCP snooping",
        "802.1D RSTP",
        "LLDP-MED"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) cryptographically signs DNS data, preventing spoofing. Option B ensures valid DHCP servers. Option C is loop prevention, Option D is link layer discovery for VoIP. DNSSEC ensures DNS responses are authentic and untampered.",
      "examTip": "DNSSEC adds digital signatures, letting resolvers verify the source and integrity of DNS records."
    },
    {
      "id": 58,
      "question": "Which approach is essential for preventing direct bridging loops introduced by user-connected hubs or switches on access ports?",
      "options": [
        "Enable spanning tree portfast and BPDU guard on edge ports",
        "Configure a separate VLAN for each user device",
        "Lower the ARP cache timer globally",
        "Use SNMPv3 for better encryption"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) portfast speeds up access ports, BPDU guard prevents unauthorized bridging. Option B is segmentation, not loop prevention. Option C is ARP lifetime, Option D is management security. BPDU guard disables a port if it sees BPDUs from user side.",
      "examTip": "BPDU guard on end-user ports ensures no external switch can inject bridging loops by sending spanning tree BPDUs."
    },
    {
      "id": 59,
      "question": "A switch interface counters show CRC errors increasing. Which is the FIRST step in diagnosing this physical-layer issue?",
      "options": [
        "Reduce DHCP lease times in that subnet",
        "Try a known-good cable or transceiver",
        "Increase link speed from 1 Gbps to 10 Gbps",
        "Configure half-duplex on both ends"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is about IP addresses, Option B (correct) addresses possible cable/transceiver faults, Option C might exacerbate errors if hardware is subpar, Option D can degrade throughput. Checking physical components is the best first step for CRC errors.",
      "examTip": "CRC errors usually indicate cable, connector, or port hardware issues. Swap cables/transceivers to isolate the cause."
    },
    {
      "id": 60,
      "question": "Which statement is TRUE about NAT overload (PAT) on a router?",
      "options": [
        "It assigns each internal host a dedicated public IP",
        "It translates multiple private IPs to a single public IP using different source ports",
        "It blocks all inbound traffic unless a static route is set",
        "It only supports TCP traffic, not UDP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is one-to-one NAT, Option B (correct) describes PAT, Option C is more firewall logic, Option D is incorrect. PAT modifies source ports to differentiate multiple internal hosts behind one public IP.",
      "examTip": "Port Address Translation is a many-to-one NAT solution, rewriting source ports to track each internal client."
    },
    {
      "id": 61,
      "question": "Which scenario-based question is BEST addressed by deploying HIDS/HIPS on critical servers?",
      "options": [
        "How to physically secure the MDF",
        "How to detect suspicious activity directly on a host and possibly block it",
        "How to route VLAN 10 and VLAN 20",
        "How to reduce broadcast storms at layer 2"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is physical security, Option B (correct) host-based IDS/IPS checks local processes, Option C is layer 3 routing, Option D is STP or VLAN design. HIDS/HIPS provide real-time monitoring and potential blocking of malicious actions on the host itself.",
      "examTip": "HIDS/HIPS inspects system-level activity, offering immediate response if it detects malicious behavior."
    },
    {
      "id": 62,
      "question": "A large enterprise must ensure routers do not accept route updates from unknown devices. Which BGP mechanism can validate the origin of IP prefixes?",
      "options": [
        "RIP max hop count",
        "Prefix lists and route filters (ROAs) with RPKI",
        "Static NAT for inbound traffic",
        "STP root guard"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is for RIP, Option B (correct) RPKI (Resource Public Key Infrastructure) checks route origin authenticity. Option C is address translation, Option D is layer 2 loop prevention. BGP can use RPKI to confirm IP prefix ownership and block invalid routes.",
      "examTip": "RPKI with prefix origin validation helps mitigate BGP hijacking by verifying that an AS is authorized to announce specific prefixes."
    },
    {
      "id": 63,
      "question": "Which is the MAIN function of an L2TP/IPSec VPN vs. PPTP?",
      "options": [
        "To provide an unencrypted tunnel for legacy devices",
        "To ensure stronger encryption and encapsulation with double encryption",
        "To allow dial-up connections only",
        "To block NAT for any remote users"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is PPTP’s weaker approach, Option B (correct) L2TP/IPSec offers robust encryption. Option C is outdated dial-up, Option D is not correct. L2TP alone is not encrypted, but combined with IPSec provides secure tunneling that PPTP lacks.",
      "examTip": "L2TP/IPSec is generally more secure than PPTP, employing stronger encryption and integrity checks."
    },
    {
      "id": 64,
      "question": "Which condition triggers an STP topology change notification (TCN)?",
      "options": [
        "DHCP scope is near exhaustion",
        "A port moves from blocking to forwarding or vice versa",
        "SNMP community string mismatch",
        "A user enters the wrong WPA2 passphrase"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is IP addressing, Option B (correct) changes in port states cause STP TCN. Option C is device management, Option D is Wi-Fi security. Ports transitioning states can produce TCNs that ripple through the STP domain.",
      "examTip": "Any port going up/down or changing STP state can trigger a TCN, causing partial re-convergence in the spanning tree."
    },
    {
      "id": 65,
      "question": "Which is the BEST reason to enable WPA2-Enterprise (802.1X) rather than WPA2-Personal in a corporate WLAN?",
      "options": [
        "To share a single passphrase across all users",
        "To require individual credentials with RADIUS authentication",
        "To ensure maximum backward compatibility with WEP clients",
        "To allow unlimited broadcast SSIDs"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is a PSK approach, Option B (correct) is enterprise authentication, Option C references WEP which is insecure, Option D is not relevant. WPA2-Enterprise enforces unique logins via 802.1X/RADIUS.",
      "examTip": "Enterprise mode offers per-user authentication for better security and auditing, unlike a shared PSK."
    },
    {
      "id": 66,
      "question": "Which factor is MOST critical when configuring site-to-site VPN tunnels for different branches using IPSec?",
      "options": [
        "Matching tunnel names on each router",
        "Consistent encryption, hashing, and Phase 1/Phase 2 parameters",
        "Sharing the same NAT pool across all sites",
        "Half-duplex operation to reduce collisions"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is a cosmetic detail, Option B (correct) parameters must match (encryption, hash, lifetime, etc.). Option C might not matter if each site has unique public IPs. Option D is not required for VPN. IPSec requires matching policies on both ends for the tunnel to form.",
      "examTip": "Both ends of an IPSec tunnel must agree on Phase 1 (IKE) and Phase 2 (IPSec) settings—encryption, authentication, lifetime, etc."
    },
    {
      "id": 67,
      "question": "When troubleshooting a reported VLAN mismatch, which command on a Cisco switch can show the VLAN assignment of each interface?",
      "options": [
        "show mac-address-table",
        "show vlan brief",
        "show ip interface brief",
        "show running-config trunk"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A shows MAC-to-port mappings, Option B (correct) displays VLANs and their assigned ports, Option C shows IP details but not VLAN membership, Option D shows trunk settings. 'show vlan brief' lists ports and VLAN membership.",
      "examTip": "Use 'show vlan brief' to see which ports belong to each VLAN and confirm correct assignments."
    },
    {
      "id": 68,
      "question": "Which advantage does WPA3 have over WPA2 specifically?",
      "options": [
        "It allows only 802.11b data rates",
        "It requires open authentication for all clients",
        "It uses SAE (Simultaneous Authentication of Equals), mitigating offline dictionary attacks",
        "It eliminates the need for encryption by default"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is older standard, Option B is for open networks, Option C (correct) SAE provides forward secrecy and stronger handshake, Option D is false; WPA3 enforces encryption. WPA3 addresses WPA2’s vulnerabilities by using SAE in personal mode.",
      "examTip": "WPA3-Personal replaces PSK with SAE, providing better protection against brute-force attacks on passphrases."
    },
    {
      "id": 69,
      "question": "A technician sees a router repeatedly drop large packets. Which FIRST action should be considered?",
      "options": [
        "Adjust the router’s MTU or enable path MTU discovery",
        "Disable IPSec on the router",
        "Enable half-duplex to reduce packet size",
        "Enable VLAN 1 as native"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) large packets might exceed current MTU, Option B is a security measure, not relevant, Option C is a link mismatch, Option D is trunking detail. Checking MTU settings or enabling PMTUD helps large packets pass without fragmentation issues.",
      "examTip": "If large packets are dropped or need fragmentation, ensure consistent MTU or allow path MTU discovery to avoid blackhole routes."
    },
    {
      "id": 70,
      "question": "A broadcast storm crippled a network. Investigation shows a loop formed when a user connected a home switch to two wall jacks. Which measure stops such accidental bridging loops?",
      "options": [
        "Configure user ports as trunk dynamic desirable",
        "Enable BPDU guard on access ports",
        "Allow all VLANs on every trunk",
        "Increase DHCP lease time"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A fosters trunk negotiation, Option B (correct) disables a port receiving BPDUs from unauthorized devices, Option C can worsen bridging loops, Option D addresses IP lease times. BPDU guard is crucial for preventing loops from end-user connections.",
      "examTip": "BPDU guard on end-user ports helps stop unauthorized bridging devices from causing spanning tree loops."
    },
    {
      "id": 71,
      "question": "Which is TRUE about IPv6 global unicast addresses?",
      "options": [
        "They start with FE80:: and cannot route externally",
        "They always require NAT to reach the internet",
        "They often use a /64 network prefix, with a 64-bit interface identifier",
        "They use broadcast addresses to reach all nodes"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is link-local, Option B NAT is generally unnecessary in IPv6, Option C (correct) is standard practice, Option D IPv6 uses multicast, not broadcast. Most IPv6 subnets are /64, with EUI-64 or random interface IDs.",
      "examTip": "Global unicast IPv6 addresses are publicly routable, typically assigned with /64 networks for each subnet."
    },
    {
      "id": 72,
      "question": "A security team mandates that all SNMP communications must be encrypted. Which version complies with this requirement?",
      "options": [
        "SNMPv1 community strings",
        "SNMPv2c community strings",
        "SNMPv3 with authPriv",
        "SNMPv2 over FTP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A and B are unencrypted. Option C (correct) can use authentication and privacy (encryption). Option D is nonsensical. SNMPv3 with authPriv provides both authentication and encryption of the data.",
      "examTip": "SNMPv3 in authPriv mode ensures credentials and data are encrypted in transit."
    },
    {
      "id": 73,
      "question": "Which scenario-based question is BEST addressed by implementing dual-stack IPv4/IPv6 on endpoints?",
      "options": [
        "How to create a NAT64 translation for legacy devices",
        "How to support both IPv4 and IPv6 services without fully migrating at once",
        "How to unify DHCP and DNS servers across subnets",
        "How to encrypt all traffic at layer 2"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is NAT64 approach, Option B (correct) dual-stack transitions smoothly, Option C addresses IP management, Option D is layer 2 encryption. Dual-stack devices can run both IPv4 and IPv6 until the network is fully IPv6 capable.",
      "examTip": "Running dual-stack is a common method to introduce IPv6 gradually while keeping IPv4 intact for compatibility."
    },
    {
      "id": 74,
      "question": "A newly installed PoE+ (802.3at) switch keeps rebooting under heavy load. What is the FIRST area to check?",
      "options": [
        "SFP modules for fiber mismatch",
        "Power budget capacity and cooling in the switch closet",
        "DHCP scope size for IP addresses",
        "Trunk VLANs allowed on each port"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is fiber transceiver mismatch, Option B (correct) PoE+ can draw more power, possibly overloading or causing heat issues, Option C is IP management, Option D is VLAN trunk config. PoE devices can exceed the switch’s power capacity, causing restarts.",
      "examTip": "PoE+ draws up to 30W per port. Ensure the switch’s total power budget and cooling can handle the load."
    },
    {
      "id": 75,
      "question": "Which protocol supports site-to-site VPNs by transporting entire IP packets securely, often in tunnel mode?",
      "options": [
        "FTP with TLS",
        "IPSec",
        "TFTP",
        "DNSSEC"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is file transfer, Option B (correct) a common standard for secure IP tunneling, Option C is trivial file transfer, Option D is DNS record authentication. IPSec can encrypt entire IP packets (tunnel mode) for site-to-site VPNs.",
      "examTip": "IPSec in tunnel mode wraps the entire IP packet with a new header, enabling secure site-to-site connections."
    },
    {
      "id": 76,
      "question": "Which step is MOST relevant for preventing eavesdropping on remote switch configuration sessions?",
      "options": [
        "Use SSH instead of Telnet for CLI access",
        "Enable portfast on trunk ports",
        "Assign the switch a public IP for management",
        "Lower the DHCP lease time to 15 minutes"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) encrypts management traffic, Option B is for STP on access ports, Option C is not recommended, Option D is IP management. SSH ensures CLI sessions are encrypted, protecting credentials and commands from snooping.",
      "examTip": "Telnet sends commands in clear text. Always use SSH for secure device management."
    },
    {
      "id": 77,
      "question": "A network admin sees thousands of 'ICMP echo requests' from a single source saturating the WAN link. Which direct measure can mitigate this DoS?",
      "options": [
        "Shut down STP root ports",
        "Enforce jumbo frames across the WAN",
        "Rate-limit or block excessive ICMP from that source at the edge",
        "Use DHCP reservations for all devices"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is for bridging loops, Option B is a performance tweak, Option C (correct) dropping or limiting malicious ICMP traffic stops the DoS, Option D is IP management. Rate-limiting or filtering ICMP from the offending IP is the typical approach.",
      "examTip": "Filtering or throttling high-volume ICMP requests at your perimeter is a common defense against ICMP flood attacks."
    },
    {
      "id": 78,
      "question": "Which scenario-based question is BEST solved by deploying IPSec in transport mode rather than tunnel mode?",
      "options": [
        "Encrypting site-to-site communications between different networks",
        "Protecting end-to-end communications between two hosts on the same LAN",
        "Enforcing NAT for multiple LAN clients behind one IP",
        "Allowing a router to share DHCP requests across subnets"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is typically tunnel mode for site-to-site, Option B (correct) transport mode secures traffic from host to host. Option C is NAT, Option D is DHCP relay. Transport mode only encrypts payload, commonly used for host-level encryption within the same network.",
      "examTip": "IPSec transport mode is often used for host-to-host encryption with minimal overhead. Tunnel mode encapsulates the entire IP packet."
    },
    {
      "id": 79,
      "question": "In OSPF, which area type does not allow external routes (E2) while still allowing inter-area routes from the backbone?",
      "options": [
        "Backbone area (Area 0)",
        "NSSA (Not-So-Stubby Area)",
        "Stub or Totally Stubby area",
        "OSPF doesn’t support different area types"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is the main area, Option B allows limited external routes, Option C (correct) stub or totally stubby areas block external routes, Option D is incorrect. Stub areas restrict external LSAs, but can accept inter-area routes from Area 0.",
      "examTip": "Stub areas discard Type-5 external LSAs. Totally stubby areas also discard inter-area routes except a default route."
    },
    {
      "id": 80,
      "question": "Which approach is MOST suitable if you need to replicate layer 2 domains across multiple data center pods using IP-based transport?",
      "options": [
        "VXLAN encapsulation",
        "802.3ad link aggregation",
        "Telnet-based VLAN trunking",
        "ARP flooding across subnets"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) VXLAN encapsulates Ethernet frames in UDP for bridging over layer 3. Option B is link bundling. Option C is unsecure CLI. Option D is undesired. VXLAN is widely used for multi-DC L2 extension.",
      "examTip": "VXLAN tunnels layer 2 traffic over an IP-based fabric, often used in modern data center designs for scalable virtualization."
    },
    {
      "id": 81,
      "question": "A user can only connect to the local network but not the internet after reconfiguring IP settings manually. Which is the FIRST check?",
      "options": [
        "Confirm the default gateway is set to the correct router IP",
        "Disable bridging loops on the switch",
        "Force trunk mode on the user port",
        "Increase the user’s DHCP lease time"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) if the gateway is missing or wrong, external traffic fails. Option B is a layer 2 measure, Option C is for VLAN trunking, Option D is about IP addresses. Internet connectivity requires a valid default gateway for off-subnet routing.",
      "examTip": "Manual IP configs often fail externally if the default gateway is incorrect or omitted."
    },
    {
      "id": 82,
      "question": "Which direct measure addresses VLAN double-tagging attacks?",
      "options": [
        "Use DHCP Option 82 on the server",
        "Prohibit VLAN 1 from being the native VLAN on trunks",
        "Implement half-duplex on trunk ports",
        "Enable jumbo frames for each VLAN"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is a relay info field, Option B (correct) separate the native VLAN from VLAN 1 to mitigate double-tagging. Option C is not relevant, Option D is a performance tweak. Double-tagging relies on default VLAN 1 as native.",
      "examTip": "Changing the native VLAN to something other than 1 and disallowing trunk auto-negotiation helps prevent double-tagging attacks."
    },
    {
      "id": 83,
      "question": "A user complains their VoIP calls break up whenever large file transfers occur. Which solution is the MOST direct fix?",
      "options": [
        "Configure QoS prioritization for voice traffic on the network",
        "Implement half-duplex on the user NIC",
        "Change all default gateways to 0.0.0.0",
        "Extend the DHCP lease to a week"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) ensures voice is prioritized over bulk data. Option B cripples throughput. Option C invalidates routing. Option D addresses IP assignment, not performance. QoS classification for VoIP prevents packet drops under heavy load.",
      "examTip": "Voice is sensitive to latency and jitter. Apply QoS marking (DSCP EF) or priority queues so large data transfers don’t starve calls."
    },
    {
      "id": 84,
      "question": "Which factor is CRITICAL for enabling link aggregation (LACP) between two switches?",
      "options": [
        "Matching port speeds and duplex settings on both ends",
        "Switches running different STP protocols",
        "DHCP snooping must be disabled",
        "IPv6 addresses assigned to each port"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) LACP requires consistent speed, duplex, and VLAN configuration. Option B can co-exist with LACP. Option C is unrelated, Option D is not required. If ports differ in speed/duplex, aggregation fails.",
      "examTip": "For EtherChannel/LACP, all member ports must match speed, duplex, and trunk settings for a stable bundle."
    },
    {
      "id": 85,
      "question": "Which term describes a rogue wireless AP that replicates the SSID of a legitimate network to lure users into connecting?",
      "options": [
        "Evil twin",
        "War driving",
        "WIPS sensor",
        "MAC flooding"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) is a malicious AP posing as a trusted SSID. Option B is scanning for Wi-Fi networks, Option C is intrusion prevention sensor, Option D is a wired attack. An evil twin AP tricks users into joining an attacker-controlled hotspot.",
      "examTip": "Evil twin attacks create a fake AP with the same SSID, intercepting user data if they connect."
    },
    {
      "id": 86,
      "question": "A router shows a route learned via OSPF with cost 10 and a route via RIP with hop count 3 for the same subnet. Which route is installed if both have AD 120?",
      "options": [
        "The RIP route with fewer hops is always chosen",
        "The OSPF route with the lower cost is always chosen",
        "Neither route is used; the router discards traffic",
        "The route with the lowest AD or same-protocol metric is chosen, but here AD is the same. So it compares metric within the same protocol. This scenario is contradictory in real networks."
      ],
      "correctAnswerIndex": 3,
      "explanation": "In real Cisco gear, OSPF has AD 110, RIP 120. But if both had AD 120, they'd be equally trusted. Typically you wouldn't set them the same. If they truly match, tie-breaking might be vendor-specific or load balanced. This scenario is tricky: it’s not standard. The question highlights AD is the next deciding factor after the prefix length. If they have the same AD and prefix length, the router might not prefer either route or could do equal-cost load balancing if the protocols allow. So the best answer is that this scenario is contradictory or depends on vendor tie-break rules.",
      "examTip": "By default, OSPF AD is 110, RIP is 120. If forced to the same AD, route selection can be ambiguous or vendor-dependent."
    },
    {
      "id": 87,
      "question": "Which design concept references placing applications or services in close proximity to the end user to reduce latency, often in distributed mini data centers?",
      "options": [
        "Cloud bursting",
        "Edge computing",
        "Three-tier core/distribution/access",
        "VPN split tunneling"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A extends workloads to a public cloud, Option B (correct) processes data near users or devices, Option C is a LAN design, Option D is a remote user VPN approach. Edge computing aims to minimize latency by bringing compute resources geographically closer to endpoints.",
      "examTip": "Edge computing locates compute/storage at the network edge, reducing round-trip times for data processing."
    },
    {
      "id": 88,
      "question": "A new LAN switch must integrate with existing RADIUS for per-user authentication. Which standard is used for port-based network access control?",
      "options": [
        "802.1Q",
        "802.3af",
        "802.1D",
        "802.1X"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Option A is VLAN trunking, Option B is PoE, Option C is spanning tree, Option D (correct) is port-based NAC. 802.1X requires devices to authenticate via RADIUS before granting LAN access.",
      "examTip": "802.1X enforces a user/device authentication process on each port, often integrated with RADIUS servers."
    },
    {
      "id": 89,
      "question": "Which factor is the MAIN reason to implement STP Root Guard on a distribution switch?",
      "options": [
        "To block untrusted DHCP offers",
        "To ensure it remains the designated STP root, preventing rogue devices from taking over",
        "To disable port security automatically",
        "To force VLAN trunking on all user ports"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is DHCP snooping, Option B (correct) ensures the current root remains root. Option C is not relevant, Option D is trunk negotiation. Root guard sets certain ports to ignore superior BPDUs.",
      "examTip": "Root guard keeps the designated root from changing if a lower bridge ID tries to claim root from an unexpected port."
    },
    {
      "id": 90,
      "question": "A load balancer must distribute HTTPS traffic across multiple backend servers. Which port must be open to receive HTTPS requests from clients?",
      "options": [
        "TCP 80",
        "TCP 443",
        "UDP 69",
        "TCP 445"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is HTTP, Option B (correct) is HTTPS, Option C is TFTP, Option D is SMB. 443 is standard for encrypted web traffic.",
      "examTip": "HTTPS typically listens on port 443. The load balancer also needs to talk to the servers on appropriate ports."
    },
    {
      "id": 91,
      "question": "Which best practice helps ensure logs from multiple network devices are correlated in real time for threat detection?",
      "options": [
        "Use a SIEM platform that collects and analyzes logs centrally",
        "Mirror all ports to a single analysis machine",
        "Shorten DHCP lease times so IPs are recycled quickly",
        "Disable all syslog forwarding to reduce overhead"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) SIEM aggregates and correlates logs from numerous sources. Option B only sees raw traffic, not log correlation. Option C is IP management, not log analysis. Option D removes logging entirely. SIEM is the standard for real-time log correlation and alerting.",
      "examTip": "A SIEM solution unifies logs from firewalls, switches, servers, etc., applying analytics and alerting on suspicious patterns."
    },
    {
      "id": 92,
      "question": "Which direct approach can help contain damage if an attacker compromises a host in one department's subnet?",
      "options": [
        "Use a single VLAN for all departments",
        "Implement NAC posture checks only on wireless users",
        "Apply micro-segmentation and ACLs to restrict lateral movement",
        "Adopt half-duplex on all switches"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A lumps all devices together, Option B is limited to Wi-Fi, Option C (correct) secures each segment so an attacker can’t pivot freely, Option D is about link mode. Micro-segmentation isolates smaller groups or even individual hosts, limiting breaches.",
      "examTip": "Segmenting the network with ACLs or micro-segmentation reduces the ‘blast radius’ if a single host is compromised."
    },
    {
      "id": 93,
      "question": "Which 802.11 standard introduced speeds up to 54 Mbps but only in 5 GHz, preceding 802.11n?",
      "options": [
        "802.11a",
        "802.11b",
        "802.11g",
        "802.11ac"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) 802.11a operates at 5 GHz with up to 54 Mbps. Option B is 2.4 GHz 11 Mbps, Option C is 2.4 GHz 54 Mbps, Option D is a newer 5 GHz standard with higher throughput. 11a was overshadowed by 11g in 2.4 GHz but is still significant historically.",
      "examTip": "802.11a was 5 GHz at 54 Mbps, concurrent with 11b/g which used 2.4 GHz."
    },
    {
      "id": 94,
      "question": "A company needs to separate guest wireless traffic from internal systems. Which design is MOST typical?",
      "options": [
        "Use a hub for guest traffic to limit collisions",
        "Place guests on the same VLAN as servers to reduce overhead",
        "Configure a separate SSID mapped to a dedicated VLAN and apply firewall rules",
        "Enforce half-duplex for guest WLAN"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is outdated, Option B merges guests with critical systems (insecure), Option C (correct) is standard practice, Option D is performance-limiting. A separate guest SSID and VLAN with ACLs or firewall ensures isolation from internal resources.",
      "examTip": "Always segregate guest traffic in its own VLAN/subnet, restricting it from internal corporate LAN resources."
    },
    {
      "id": 95,
      "question": "Which command on a Cisco router shows all IP NAT translations currently in use?",
      "options": [
        "show ip route",
        "show ip interface brief",
        "show ip nat translations",
        "show arp"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is routing table, Option B is interface statuses, Option C (correct) NAT table, Option D is IP-to-MAC. 'show ip nat translations' displays active NAT sessions.",
      "examTip": "Use 'show ip nat translations' to verify NAT/pool usage on Cisco devices."
    },
    {
      "id": 96,
      "question": "When deploying a next-generation firewall, which advantage does application awareness at layer 7 offer over a traditional stateful firewall?",
      "options": [
        "Simplified LACP negotiation for link aggregation",
        "Greater QoS classification by port number only",
        "Ability to identify and filter traffic by application signatures",
        "Automatic bridging loops detection"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is link aggregation, Option B is basic port-based, Option C (correct) is layer 7 inspection, Option D is STP. NGFW can detect apps (e.g., Skype, Dropbox) beyond standard port usage, allowing granular policy enforcement.",
      "examTip": "Next-generation firewalls do deep packet inspection, controlling traffic by actual application rather than just port or IP."
    },
    {
      "id": 97,
      "question": "Which direct measure can protect the control plane on Cisco devices by splitting route processing from data forwarding via software abstractions?",
      "options": [
        "Activate SDN-based control plane separation like OpenFlow",
        "Enable jumbo frames globally",
        "Use EIGRP instead of RIP",
        "Enforce 802.1X NAC on trunk interfaces"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) software-defined networking separates the control plane (central controller) from data plane. Option B is a performance tweak, Option C is a better routing protocol but doesn't separate planes, Option D is port-based auth. SDN centralizes route logic away from hardware forwarding.",
      "examTip": "SDN decouples the control plane from the data plane, letting a controller define network behavior programmatically."
    },
    {
      "id": 98,
      "question": "Which is the FIRST step if a user's switch port is err-disabled due to a security violation?",
      "options": [
        "Re-enable the port after investigating if multiple MACs or other triggers caused it",
        "Lower the DHCP lease time to free addresses",
        "Disable port mirroring on that interface",
        "Convert the port to a trunk"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) you must investigate why it triggered, fix the cause, and then re-enable. Option B is about IP addresses, Option C is a monitoring approach, Option D is for VLAN trunking. Typically, you'll check port security or other conditions, then reset the port.",
      "examTip": "In err-disabled state, identify the reason (port security, link fault) and correct it, then administratively bring the port back online."
    },
    {
      "id": 99,
      "question": "Which scenario-based question is BEST addressed by implementing a captive portal on a guest Wi-Fi network?",
      "options": [
        "How to provide an open SSID with no disclaimers",
        "How to ensure LAN printers are accessible by guests",
        "How to force guests to accept terms or authenticate before granting internet access",
        "How to reduce DHCP usage on the main VLAN"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is entirely open, Option B is typically restricted, Option C (correct) is the main captive portal function, Option D is IP management. Captive portals intercept traffic, presenting a login or terms page to guests.",
      "examTip": "Captive portals display usage terms or require credentials from guest users before allowing broader network access."
    },
    {
      "id": 100,
      "question": "Which single step can MOST reduce the blast radius if one subnet is compromised by a malware outbreak?",
      "options": [
        "Implement tighter segmentation and ACLs between subnets",
        "Use a single VLAN for the entire enterprise",
        "Reserve IP addresses in DHCP for each device",
        "Increase channel bonding on the Wi-Fi"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) ensures compromised hosts cannot easily move laterally, Option B lumps everything, Option C is consistent IP assignment but no security, Option D is purely Wi-Fi performance. Segmentation restricts attacker movement if one subnet is breached.",
      "examTip": "Network segmentation (via VLANs, subnets, ACLs) is key to containing threats and preventing lateral spread."
    }
  ]
});
