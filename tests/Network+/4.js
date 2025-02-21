db.tests.insertOne({
  "category": "netplus",
  "testId": 4,
  "testName": "Network+ Practice Test #4 (Moderate)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A systems administrator suspects a broadcast loop in the distribution switches is overwhelming the network. Which INITIAL step is the MOST effective to isolate this issue?",
      "options": [
        "Disable all trunk ports and re-enable them one at a time",
        "Set every port on all switches to half-duplex",
        "Replace every patch cable across the distribution layer",
        "Enable DHCP snooping on core switches"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Disable all trunk ports and re-enable them one at a time (correct) systematically tests each trunk connection to find the loop source. Set every port on all switches to half-duplex can degrade performance without addressing loops. Replace every patch cable across the distribution layer is too broad and does not target the root cause. Enable DHCP snooping on core switches protects DHCP but not broadcast storms from spanning loops.",
      "examTip": "When facing a suspected loop, narrow it down by isolating trunk links and verifying STP configurations."
    },
    {
      "id": 2,
      "question": "A network technician is configuring inter-VLAN routing on a new Layer 3 switch. Which factor is CRITICAL to ensure traffic can pass between VLANs?",
      "options": [
        "Each VLAN must have a different MAC address on its interface",
        "The switch must have a DHCP reservation for each VLAN",
        "SVIs must be assigned unique IP addresses per VLAN",
        "All VLANs must share the same subnet to communicate"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Each VLAN must have a different MAC address on its interface is irrelevant because MAC addresses are typically unique anyway. The switch must have a DHCP reservation for each VLAN only addresses IP assignment, not routing. SVIs must be assigned unique IP addresses per VLAN (correct) is required so each VLAN interface can route traffic. All VLANs must share the same subnet to communicate prevents inter-VLAN routing; separate subnets are necessary.",
      "examTip": "Assign each VLAN interface (SVI) a distinct IP in its subnet to enable Layer 3 routing between VLANs."
    },
    {
      "id": 3,
      "question": "A router receives two routes for the same network: one from OSPF and one from BGP. Which parameter determines which route ends up in the routing table?",
      "options": [
        "The route with the fewest next hops is preferred",
        "The route using the largest prefix length is preferred",
        "The route with the lowest administrative distance is selected",
        "The route that was learned most recently takes priority"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The route with the fewest next hops is preferred references hop count but not relevant to protocol preference. The route using the largest prefix length is preferred covers route specificity but is secondary to AD. The route with the lowest administrative distance is selected (correct) is the standard selection rule when protocols compete. The route that was learned most recently takes priority is not how route selection works.",
      "examTip": "When multiple dynamic routing protocols present the same route, the router chooses the one with the lowest administrative distance."
    },
    {
      "id": 4,
      "question": "A client complains of frequent disconnections on their 2.4 GHz Wi-Fi. Upon inspection, the access point’s channel width is set to 40 MHz. What is the PRIMARY adjustment to reduce interference?",
      "options": [
        "Switch to a 20 MHz channel on 2.4 GHz",
        "Increase the transmit power to maximum",
        "Enable MAC filtering on the SSID",
        "Use a 160 MHz channel to reduce overhead"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Switch to a 20 MHz channel on 2.4 GHz (correct) narrows the channel, reducing overlap and interference in 2.4 GHz. Increase the transmit power to maximum can worsen interference by overpowering. Enable MAC filtering on the SSID is an access control measure, not interference mitigation. Use a 160 MHz channel to reduce overhead is not feasible in 2.4 GHz and would create more overlap if it were.",
      "examTip": "In 2.4 GHz environments, 20 MHz channels often minimize co-channel and adjacent-channel interference."
    },
    {
      "id": 5,
      "question": "You are tasked with implementing a new firewall between the LAN and DMZ. Which action BEST ensures only approved inbound connections reach DMZ servers?",
      "options": [
        "Enabling port mirroring on the DMZ switch",
        "Blocking all outbound traffic from the DMZ",
        "Using an explicit allow list for inbound service ports",
        "Setting every DMZ interface to half-duplex"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Enabling port mirroring on the DMZ switch captures traffic but does not filter it. Blocking all outbound traffic from the DMZ addresses outbound, not inbound. Using an explicit allow list for inbound service ports (correct) admits only known and necessary ports to DMZ hosts. Setting every DMZ interface to half-duplex can degrade performance but does not secure inbound traffic.",
      "examTip": "Default deny with explicit allows is the foundation of firewall policy to minimize attack surfaces."
    },
    {
      "id": 6,
      "question": "A technician must deploy an IDS solution that can also stop malicious traffic in real time. Which solution is MOST appropriate?",
      "options": [
        "A passive network tap capturing all traffic",
        "A network-based IPS configured inline",
        "A SIEM collecting logs from multiple devices",
        "A honeynet placed in the internal LAN"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A passive network tap capturing all traffic only observes. A network-based IPS configured inline (correct) can detect and actively block. A SIEM collecting logs from multiple devices correlates events but does not block. A honeynet placed in the internal LAN is for attacker research, not proactive blocking.",
      "examTip": "Use an inline IPS for real-time traffic inspection and active threat mitigation."
    },
    {
      "id": 7,
      "question": "Which factor is MOST important to verify if remote sites using SD-WAN frequently lose connection over a multi-link environment?",
      "options": [
        "If each link has a unique default gateway address",
        "Whether DNS cache is cleared at each site",
        "If zero-touch provisioning is properly configured",
        "Whether user devices are using static IPs"
      ],
      "correctAnswerIndex": 2,
      "explanation": "If each link has a unique default gateway address does not address SD-WAN orchestration. Whether DNS cache is cleared at each site only affects name resolution. If zero-touch provisioning is properly configured (correct) ensures remote endpoints can re-provision links automatically. Whether user devices are using static IPs is an IP addressing detail, not typically the cause of multi-link SD-WAN drops.",
      "examTip": "For SD-WAN, confirm the zero-touch provisioning steps and controllers are reachable for stable multi-link operation."
    },
    {
      "id": 8,
      "question": "A branch office router is repeatedly crashing after large file transfers. The logs suggest memory overflow. Which FIRST step should a technician take to remedy this?",
      "options": [
        "Perform a firmware upgrade or patch",
        "Replace the router with an unmanaged switch",
        "Limit the DHCP scope to fewer addresses",
        "Enable port security on every interface"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Perform a firmware upgrade or patch (correct) can fix known bugs causing memory leaks. Replace the router with an unmanaged switch does not provide routing capabilities. Limit the DHCP scope to fewer addresses is unrelated. Enable port security on every interface addresses MAC addresses, not memory usage.",
      "examTip": "Always patch device firmware when faced with recurring stability issues before considering hardware replacement."
    },
    {
      "id": 9,
      "question": "A user’s laptop fails to get an IP from DHCP unless the port is manually configured at 10 Mbps half-duplex. Which problem is MOST likely present?",
      "options": [
        "Excessive VLAN trunking on that interface",
        "Massive broadcast storms in the subnet",
        "A speed/duplex mismatch with the switch",
        "DNS server misconfiguration on that VLAN"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Excessive VLAN trunking on that interface is unrelated to forced half-duplex. Massive broadcast storms in the subnet can slow performance but not cause partial link negotiation. A speed/duplex mismatch with the switch (correct) indicates the switch autonegotiation is failing. DNS server misconfiguration on that VLAN is about name resolution, not link speed.",
      "examTip": "When a NIC only works at a reduced speed/duplex, suspect a mismatch or failed negotiation on the switch port."
    },
    {
      "id": 10,
      "question": "A network engineer must configure a VPN for traveling employees without installing additional VPN software on their laptops. Which method is PRIMARY for easy remote access?",
      "options": [
        "Site-to-site IPSec tunnel between user router and HQ",
        "Clientless SSL VPN using a web portal",
        "Evil twin hotspot setup at each hotel",
        "Dial-up PPP connections with RADIUS"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Site-to-site IPSec tunnel between user router and HQ is for a fixed site, not personal user devices. Clientless SSL VPN using a web portal (correct) needs only a web browser. Evil twin hotspot setup at each hotel is malicious. Dial-up PPP connections with RADIUS is outdated and rarely used now.",
      "examTip": "Clientless VPN portals allow remote connectivity without installing specialized VPN clients."
    },
    {
      "id": 11,
      "question": "Which tactic helps reduce collisions and broadcast storms when multiple devices connect in a star topology?",
      "options": [
        "Use a standard Ethernet hub",
        "Enable half-duplex on all nodes",
        "Deploy a managed switch at the center",
        "Assign a single IP across all devices"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Use a standard Ethernet hub repeats signals to all ports, inviting collisions. Enable half-duplex on all nodes fosters collision domains. Deploy a managed switch at the center (correct) segments traffic with MAC-based forwarding. Assign a single IP across all devices is invalid IP usage.",
      "examTip": "Switches intelligently forward unicast frames only to the destination port, reducing collisions compared to hubs."
    },
    {
      "id": 12,
      "question": "An administrator notices an unknown device handing out IP addresses on the corporate network. Which direct action is BEST to stop this rogue DHCP server?",
      "options": [
        "Enable DHCP snooping on all VLANs",
        "Switch to static IP configuration across the network",
        "Use jumbo frames to reduce broadcast traffic",
        "Assign a DNS suffix to every client"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Enable DHCP snooping on all VLANs (correct) blocks DHCP offers from untrusted ports. Switch to static IP configuration across the network is labor-intensive. Use jumbo frames to reduce broadcast traffic is performance-related, not security. Assign a DNS suffix to every client is a naming convention, not relevant.",
      "examTip": "DHCP snooping filters unauthorized DHCP servers by limiting where valid offers can originate."
    },
    {
      "id": 13,
      "question": "Which approach is the PRIMARY reason to implement port security with a limited MAC address count on an access port?",
      "options": [
        "To allow trunking over multiple VLANs",
        "To prevent VLAN trunk negotiation with other switches",
        "To reduce the chance of MAC flooding attacks",
        "To activate Layer 3 routing on that switchport"
      ],
      "correctAnswerIndex": 2,
      "explanation": "To allow trunking over multiple VLANs is trunking, not relevant. To prevent VLAN trunk negotiation with other switches is DTP-based. To reduce the chance of MAC flooding attacks (correct) is the main driver: preventing malicious MAC floods. To activate Layer 3 routing on that switchport is beyond the scope of typical port security.",
      "examTip": "Port security with a MAC limit helps mitigate MAC table overflow attacks that can force a switch to behave like a hub."
    },
    {
      "id": 14,
      "question": "A remote user complains that their VPN keeps disconnecting whenever large file transfers are initiated. Which setting is the INITIAL priority to check on the firewall or VPN device?",
      "options": [
        "SNMP community string",
        "Maximum transmission unit (MTU)",
        "DNS forwarders configured",
        "DHCP scope capacity"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SNMP community string is for monitoring, not throughput. Maximum transmission unit (MTU) (correct) can cause fragmentation or dropped packets if set improperly. DNS forwarders configured is about name resolution. DHCP scope capacity is address allocation, not data size.",
      "examTip": "VPN disconnections during large transfers often point to an MTU or fragmentation issue."
    },
    {
      "id": 15,
      "question": "A company uses a single public IP for internet access across dozens of internal clients. Which technology BEST describes this configuration?",
      "options": [
        "DNS round robin",
        "PAT (NAT overload)",
        "Link aggregation",
        "Spanning tree protocol"
      ],
      "correctAnswerIndex": 1,
      "explanation": "DNS round robin balances DNS queries among multiple servers. PAT (NAT overload) (correct) translates many private addresses to one public address with different source ports. Link aggregation aggregates multiple links for bandwidth. Spanning tree protocol prevents loops in switched networks.",
      "examTip": "Port Address Translation (PAT) is the usual solution to let multiple LAN clients share a single public IP."
    },
    {
      "id": 16,
      "question": "A user’s computer keeps getting a 169.254.x.x address. Which step is MOST appropriate for initial troubleshooting?",
      "options": [
        "Check if the DHCP server is reachable on the network",
        "Enable jumbo frames on the user's adapter",
        "Change the user’s IP from DHCP to static",
        "Disable QoS tagging for the user VLAN"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Check if the DHCP server is reachable on the network (correct) addresses the inability to obtain a DHCP lease, causing APIPA assignment. Enable jumbo frames on the user's adapter is performance-related. Change the user’s IP from DHCP to static bypasses the real issue. Disable QoS tagging for the user VLAN does not affect IP addressing directly.",
      "examTip": "169.254.x.x indicates APIPA, which appears when a DHCP client cannot reach the DHCP server."
    },
    {
      "id": 17,
      "question": "You need to gather in-depth traffic details on a switch to diagnose random packet loss. Which tool or method is BEST for capturing packets for analysis?",
      "options": [
        "TDR tester on each port",
        "Port mirroring (SPAN) to a protocol analyzer",
        "SNMP polling using community strings",
        "Syslog server collecting error logs"
      ],
      "correctAnswerIndex": 1,
      "explanation": "TDR tester on each port tests cable length and continuity, not real traffic. Port mirroring (SPAN) to a protocol analyzer (correct) sends all port traffic to a monitor port for analysis. SNMP polling using community strings collects performance data, not full packets. Syslog server collecting error logs aggregates logs, not packet capture.",
      "examTip": "Use port mirroring (SPAN) when you need actual traffic data for deeper analysis with a protocol analyzer."
    },
    {
      "id": 18,
      "question": "A newly installed firewall shows many incoming SSH attempts from unknown IPs. Which IMMEDIATE measure can help reduce such unauthorized connections?",
      "options": [
        "Implement 802.1X on all interfaces",
        "Disable Telnet across the firewall",
        "Block inbound SSH at the firewall unless specifically allowed",
        "Use DNSSEC to secure SSH credentials"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Implement 802.1X on all interfaces is for switch port authentication. Disable Telnet across the firewall is irrelevant to SSH. Block inbound SSH at the firewall unless specifically allowed (correct) explicitly denies inbound SSH except from authorized IPs. Use DNSSEC to secure SSH credentials is about DNS security, not SSH access control.",
      "examTip": "Firewalls should limit inbound management protocols to trusted sources only."
    },
    {
      "id": 19,
      "question": "A network engineer is planning to deploy multiple APs in a large open office. Which factor is MOST critical to avoid overlapping and co-channel interference in 2.4 GHz?",
      "options": [
        "Use channels 1, 5, 9, and 13 for maximum coverage",
        "Implement port security on the switch supporting the APs",
        "Configure AP transmit power to the absolute highest setting",
        "Space APs on non-overlapping channels (e.g., 1, 6, 11)"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Use channels 1, 5, 9, and 13 for maximum coverage channels often overlap in many regulatory domains. Implement port security on the switch supporting the APs secures wired ports, not RF interference. Configure AP transmit power to the absolute highest setting can worsen overlap. Space APs on non-overlapping channels (e.g., 1, 6, 11) (correct) ensures minimal channel interference in 2.4 GHz.",
      "examTip": "Standard practice in 2.4 GHz: use channels 1, 6, and 11 to minimize co-channel interference."
    },
    {
      "id": 20,
      "question": "Which concept differentiates a trunk port from an access port in a switching environment?",
      "options": [
        "A trunk port carries multiple VLAN tags, while an access port is for one VLAN only",
        "A trunk port blocks STP, while an access port allows STP",
        "A trunk port is half-duplex, while an access port is full-duplex",
        "A trunk port always uses PoE, while an access port does not"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A trunk port carries multiple VLAN tags, while an access port is for one VLAN only (correct) is the defining difference. A trunk port blocks STP, while an access port allows STP is incorrect; both can run STP. A trunk port is half-duplex, while an access port is full-duplex is not true. A trunk port always uses PoE, while an access port does not is unrelated to VLAN tagging.",
      "examTip": "Trunk ports carry tagged VLAN traffic, while access ports connect an end device to a single VLAN."
    },
    {
      "id": 21,
      "question": "A Layer 3 switch stops routing between VLANs after a firmware update. Which FIRST action should be taken?",
      "options": [
        "Revert to the previous firmware backup",
        "Replace the switch with a spare",
        "Attempt a factory reset on the device",
        "Run a cable test on all connected trunks"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Revert to the previous firmware backup (correct) quickly restores known working firmware. Replace the switch with a spare is more drastic. Attempt a factory reset on the device loses all settings. Run a cable test on all connected trunks checks physical links but not firmware issues.",
      "examTip": "If a firmware update breaks critical features, rolling back is often the fastest path to restoration."
    },
    {
      "id": 22,
      "question": "Which of the following protocols encapsulates LAN frames into IP for easy extension of layer 2 networks across layer 3 boundaries?",
      "options": [
        "VXLAN",
        "MPLS",
        "RSTP",
        "LDAP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "VXLAN (correct) encapsulates Ethernet frames in UDP for large-scale bridging. MPLS is label switching for WAN. RSTP prevents loops at layer 2. LDAP is a directory service protocol.",
      "examTip": "VXLAN is widely used to stretch VLANs over layer 3 in modern data centers."
    },
    {
      "id": 23,
      "question": "A network segment experiences high latency with no obvious cause. Which command helps identify each hop's response time to a destination?",
      "options": [
        "dig",
        "ipconfig",
        "traceroute/tracert",
        "show mac-address-table"
      ],
      "correctAnswerIndex": 2,
      "explanation": "dig checks DNS. ipconfig is Windows IP info. traceroute/tracert (correct) reveals hop-by-hop delays. show mac-address-table shows MACs learned by a switch.",
      "examTip": "Use traceroute (Linux) or tracert (Windows) to diagnose path latency and pinpoint slow hops."
    },
    {
      "id": 24,
      "question": "Which solution is BEST suited to centrally aggregate logs for correlation and alerting across multiple network devices?",
      "options": [
        "Port mirroring on a core switch",
        "A SIEM platform",
        "A passive IDS sensor on each subnet",
        "DHCP snooping"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Port mirroring on a core switch sends copies of traffic, not correlated logs. A SIEM platform (correct) collects logs from many devices, providing analytics. A passive IDS sensor on each subnet detects intrusions but doesn’t unify logs. DHCP snooping filters DHCP but is not a log correlation tool.",
      "examTip": "A SIEM aggregates, analyzes, and correlates logs from diverse network components for faster threat detection."
    },
    {
      "id": 25,
      "question": "A user cannot reach internal file servers by hostname, but pinging the IP works. What is the MOST likely cause?",
      "options": [
        "Speed/duplex mismatch on the NIC",
        "Incorrect DNS server settings",
        "Bad default gateway configuration",
        "Low PoE budget on the switch"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Speed/duplex mismatch on the NIC may affect performance, not name resolution. Incorrect DNS server settings (correct) typically breaks hostname-based connectivity. Bad default gateway configuration would block off-subnet traffic, but IP pings are successful. Low PoE budget on the switch concerns power to devices.",
      "examTip": "When IP-based pings work but hostnames fail, DNS settings are the prime suspect."
    },
    {
      "id": 26,
      "question": "Which factor is CRITICAL when planning a wireless deployment for maximum capacity and minimal interference?",
      "options": [
        "Full channel bonding across all APs on 2.4 GHz",
        "Exact matching of all SSIDs on every AP",
        "Sufficient channel separation and coverage overlap",
        "Reducing power to the absolute lowest on all APs"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Full channel bonding across all APs on 2.4 GHz may cause overlap. Exact matching of all SSIDs on every AP handles roaming but not capacity. Sufficient channel separation and coverage overlap (correct) ensures coverage while preventing interference. Reducing power to the absolute lowest on all APs can introduce coverage gaps.",
      "examTip": "Proper channel planning and AP spacing are key to high-capacity Wi-Fi deployments."
    },
    {
      "id": 27,
      "question": "You must configure a router interface for a single physical port to handle multiple VLANs. Which method is typically used?",
      "options": [
        "PPPoE tunneling on each VLAN interface",
        "Subinterfaces with 802.1Q tagging (router-on-a-stick)",
        "Trunk each VLAN on a half-duplex link",
        "Use a separate IP address for every switch port"
      ],
      "correctAnswerIndex": 1,
      "explanation": "PPPoE tunneling on each VLAN interface is PPP over Ethernet, not VLAN trunking. Subinterfaces with 802.1Q tagging (router-on-a-stick) (correct) is the classic router-on-a-stick approach. Trunk each VLAN on a half-duplex link is typically avoided. Use a separate IP address for every switch port is not needed if using subinterfaces.",
      "examTip": "Router-on-a-stick uses subinterfaces on a single physical link to route between multiple VLANs."
    },
    {
      "id": 28,
      "question": "Which of these is a legitimate reason to use NAT64 in a mixed IPv4 and IPv6 environment?",
      "options": [
        "To tunnel IPv6 packets inside IPv4 without translation",
        "To provide encryption between IPv4 and IPv6 clients",
        "To translate IPv6 requests to IPv4-only resources",
        "To remove the need for routing protocols entirely"
      ],
      "correctAnswerIndex": 2,
      "explanation": "To tunnel IPv6 packets inside IPv4 without translation describes a 6to4 tunnel, not NAT64. To provide encryption between IPv4 and IPv6 clients is not NAT’s function. To translate IPv6 requests to IPv4-only resources (correct) NAT64 converts IPv6 traffic to IPv4 for legacy servers. To remove the need for routing protocols entirely is inaccurate; routing protocols may still be needed.",
      "examTip": "NAT64 is used to allow IPv6 clients to reach IPv4-only resources by translating addresses."
    },
    {
      "id": 29,
      "question": "Which direct measure can help mitigate ARP spoofing in a switched network?",
      "options": [
        "Use proxy servers for web traffic",
        "Implement port security with sticky MAC addresses",
        "Set up spanning tree in rapid mode",
        "Enable SSH for switch management"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Use proxy servers for web traffic addresses HTTP caching, not ARP spoofing. Implement port security with sticky MAC addresses (correct) restricts unknown MAC addresses. Set up spanning tree in rapid mode prevents loops. Enable SSH for switch management secures management but doesn’t affect ARP at layer 2.",
      "examTip": "Sticky MAC on access ports can hinder ARP spoofing by limiting MAC addresses to trusted endpoints."
    },
    {
      "id": 30,
      "question": "Which statement BEST describes why an organization would choose an L2TP/IPSec VPN over PPTP?",
      "options": [
        "PPTP provides stronger encryption keys",
        "L2TP/IPSec offers better security through double encapsulation",
        "PPTP is the only option that uses port 443",
        "L2TP/IPSec cannot support mobile clients"
      ],
      "correctAnswerIndex": 1,
      "explanation": "PPTP provides stronger encryption keys is incorrect; PPTP is weaker. L2TP/IPSec offers better security through double encapsulation (correct) L2TP combined with IPSec is more secure. PPTP is the only option that uses port 443 is false; PPTP uses TCP 1723. L2TP/IPSec cannot support mobile clients is also false; L2TP/IPSec supports many clients.",
      "examTip": "L2TP/IPSec is generally considered more secure than PPTP, offering stronger encryption and integrity checks."
    },
    {
      "id": 31,
      "question": "A network admin wants to restrict telnet access to core switches. Which BEST practice should they implement?",
      "options": [
        "Block TCP port 23 inbound on the switch ACL",
        "Require jumbo frames for Telnet sessions",
        "Use a coaxial connection for console management",
        "Set the switch to half-duplex on the management VLAN"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Block TCP port 23 inbound on the switch ACL (correct) denies Telnet at port 23. Require jumbo frames for Telnet sessions is irrelevant to security. Use a coaxial connection for console management is obsolete. Set the switch to half-duplex on the management VLAN is a link setting, not an ACL approach.",
      "examTip": "Disabling Telnet (port 23) or restricting it is critical; SSH is recommended for secure remote management."
    },
    {
      "id": 32,
      "question": "An administrator suspects a faulty fiber patch cable. Which specialized tool is MOST useful to check for continuity and attenuation in that cable?",
      "options": [
        "Toner probe kit",
        "Optical power meter",
        "RJ45 loopback plug",
        "Wi-Fi analyzer"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Toner probe kit is for copper cables. Optical power meter (correct) measures light power. RJ45 loopback plug is for Ethernet loopback. Wi-Fi analyzer is for wireless signals.",
      "examTip": "Optical power meters or OTDRs help diagnose fiber integrity issues effectively."
    },
    {
      "id": 33,
      "question": "You are asked to separate guest Wi-Fi traffic so it cannot access internal LAN resources. Which approach is the MOST efficient?",
      "options": [
        "Use MAC filtering on the guest VLAN",
        "Create a separate SSID bound to a dedicated VLAN",
        "Increase the DHCP lease time for the guest subnet",
        "Configure spanning tree exclusively for guest devices"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Use MAC filtering on the guest VLAN is easily bypassed. Create a separate SSID bound to a dedicated VLAN (correct) isolates guests with dedicated VLAN and can be ACL-limited. Increase the DHCP lease time for the guest subnet is about IP lease, not security. Configure spanning tree exclusively for guest devices is loop prevention, not segmentation.",
      "examTip": "Guest SSIDs typically map to a separate VLAN with firewall rules restricting internal network access."
    },
    {
      "id": 34,
      "question": "A user in VLAN 20 repeatedly obtains an IP from VLAN 30’s DHCP scope. Which is the MOST likely cause?",
      "options": [
        "Incorrect trunk allowed VLAN list on the switch",
        "Expired DNS record for VLAN 30",
        "STP root bridge mismatch in VLAN 20",
        "Wireless interference crossing VLAN boundaries"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Incorrect trunk allowed VLAN list on the switch (correct) indicates VLAN 20 is not properly included or excluded, so VLAN 30 DHCP leaks. Expired DNS record for VLAN 30 is name resolution, not DHCP assignment. STP root bridge mismatch in VLAN 20 is loop prevention, not DHCP. Wireless interference crossing VLAN boundaries is not how VLANs function.",
      "examTip": "Check your trunk configuration to ensure each VLAN is carried correctly without bleeding into another VLAN."
    },
    {
      "id": 35,
      "question": "A server in a DMZ must accept HTTPS from the internet. Which inbound port must be permitted through the firewall?",
      "options": [
        "22",
        "53",
        "443",
        "3389"
      ],
      "correctAnswerIndex": 2,
      "explanation": "22 is SSH, 53 is DNS, 443 (correct) is HTTPS, 3389 is RDP. 443 is the standard HTTPS port.",
      "examTip": "HTTPS typically listens on TCP port 443 for secure web access."
    },
    {
      "id": 36,
      "question": "A switch interface repeatedly shows ‘err-disabled’ status after a new phone is plugged in. Which condition is MOST likely causing this?",
      "options": [
        "The phone’s MAC address is blacklisted in the ACL",
        "Port security is shutting the port due to multiple MAC addresses",
        "802.1Q trunking is incorrectly enabled on the phone interface",
        "Auto-MDIX is disabled on the switch"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The phone’s MAC address is blacklisted in the ACL is possible but typically flagged differently. Port security is shutting the port due to multiple MAC addresses (correct) is common if the phone plus attached PC present multiple MACs. 802.1Q trunking is incorrectly enabled on the phone interface is a trunk config issue, not usually err-disable. Auto-MDIX is disabled on the switch is for cable orientation, not security.",
      "examTip": "When more MACs than allowed appear, port security often places the port in err-disabled state."
    },
    {
      "id": 37,
      "question": "Which method is BEST for ensuring a single link failure does not disrupt the active path in a core distribution design?",
      "options": [
        "Use DHCP reservations for core switch IP addresses",
        "Implement a hub-and-spoke approach on layer 2",
        "Configure link aggregation (LACP) on critical interfaces",
        "Disable spanning tree on trunk ports"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Use DHCP reservations for core switch IP addresses is about IP addresses, not redundancy. Implement a hub-and-spoke approach on layer 2 is more relevant to WAN topologies. Configure link aggregation (LACP) on critical interfaces (correct) bundles links for redundancy. Disable spanning tree on trunk ports can create loops.",
      "examTip": "Link aggregation offers both increased bandwidth and failover if one cable breaks."
    },
    {
      "id": 38,
      "question": "Which statement BEST reflects the principle of least privilege in network security?",
      "options": [
        "Granting users local admin rights for convenience",
        "Allowing all protocols through the firewall by default",
        "Providing only the minimum access rights required for a user’s role",
        "Running all devices in promiscuous mode to monitor traffic"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Granting users local admin rights for convenience contradicts the principle. Allowing all protocols through the firewall by default is also contrary. Providing only the minimum access rights required for a user’s role (correct) states the principle. Running all devices in promiscuous mode to monitor traffic is a monitoring approach, not restricting privileges.",
      "examTip": "Least privilege ensures each user or service has only the minimal permissions needed to fulfill their tasks."
    },
    {
      "id": 39,
      "question": "You notice multiple trunk ports flapping after enabling dynamic trunking protocol (DTP). Which INITIAL measure can prevent unintentional trunk formation?",
      "options": [
        "Disable DTP and set trunk ports to static on or off",
        "Reset STP on all core switches",
        "Lower the DHCP lease time across all VLANs",
        "Enable jumbo frames on trunk links"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Disable DTP and set trunk ports to static on or off (correct) avoids unpredictable trunk negotiations. Reset STP on all core switches addresses loop prevention but not trunk negotiation. Lower the DHCP lease time across all VLANs affects IP lease distribution, not trunk formation. Enable jumbo frames on trunk links is unrelated to trunk stability.",
      "examTip": "Hard-code ports as trunk or access to avoid DTP misconfigurations causing port flaps."
    },
    {
      "id": 40,
      "question": "A manager requests the capability to restore the network infrastructure quickly if the core switch fails catastrophically. Which is the PRIMARY measure to implement?",
      "options": [
        "Weekly vulnerability scanning",
        "Regular configuration backups stored offsite",
        "802.1X authentication on all access ports",
        "Static NAT for each core VLAN"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Weekly vulnerability scanning is best practice but not for immediate restoration. Regular configuration backups stored offsite (correct) ensures fast recovery by reapplying configs to new hardware. 802.1X authentication on all access ports is access control, not config backup. Static NAT for each core VLAN is address translation, not hardware recovery.",
      "examTip": "Frequent backups of critical device configs enable quick restoration if a device fails."
    },
    {
      "id": 41,
      "question": "A server blade's NIC shows many CRC errors when connecting at 10 Gbps. Which direct step is BEST to isolate the cause?",
      "options": [
        "Reduce link speed to 1 Gbps on the server side",
        "Replace or reseat the fiber module if applicable",
        "Change the DNS suffix on the server",
        "Disable SNMP traps on the server NIC"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Reduce link speed to 1 Gbps on the server side is a workaround, not a real fix. Replace or reseat the fiber module if applicable (correct) addresses potential hardware issues. Change the DNS suffix on the server is name resolution, not physical errors. Disable SNMP traps on the server NIC is about monitoring, not link integrity.",
      "examTip": "CRC errors often indicate a physical-layer issue. Check transceivers, cable, or port hardware first."
    },
    {
      "id": 42,
      "question": "A newly configured router is not sending logs to the SIEM. Which is the MOST likely requirement to enable log forwarding?",
      "options": [
        "Configure Syslog server IP and severity level on the router",
        "Deploy an IDS sensor inline on the router’s WAN port",
        "Enable auto-MDIX on the router console port",
        "Set the router to half-duplex on the LAN interface"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Configure Syslog server IP and severity level on the router (correct) is needed for remote logging. Deploy an IDS sensor inline on the router’s WAN port inspects traffic but doesn’t handle log forwarding. Enable auto-MDIX on the router console port is for cable orientation. Set the router to half-duplex on the LAN interface is a link setting, not relevant to logs.",
      "examTip": "To send logs, specify the syslog destination IP and define the severity or facility on the router."
    },
    {
      "id": 43,
      "question": "Which scenario BEST illustrates a reason to deploy a honeypot or honeynet in a corporate environment?",
      "options": [
        "To scan every subnet for open ports and services",
        "To trap malicious actors and study their tactics in an isolated environment",
        "To provide additional DHCP leases in a busy segment",
        "To store production data in a safer zone"
      ],
      "correctAnswerIndex": 1,
      "explanation": "To scan every subnet for open ports and services is vulnerability scanning. To trap malicious actors and study their tactics in an isolated environment (correct) is the definition of a honeypot. To provide additional DHCP leases in a busy segment is about address allocation. To store production data in a safer zone is risky—honeypots are not for actual production data.",
      "examTip": "Honeypots lure attackers away from real assets, letting defenders observe intrusion methods safely."
    },
    {
      "id": 44,
      "question": "A technician wants to measure which sites employees visit and block certain categories. Which solution provides the MOST direct approach?",
      "options": [
        "SNMPv3 counters on switch interfaces",
        "A web content filtering proxy",
        "A toner probe on all user connections",
        "DHCP snooping with limited IP addresses"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SNMPv3 counters on switch interfaces shows bandwidth usage, not specific URLs. A web content filtering proxy (correct) can log and block websites. A toner probe on all user connections is for tracing cables. DHCP snooping with limited IP addresses only prevents rogue DHCP, not filtering sites.",
      "examTip": "A content filtering proxy inspects outbound web requests to log or block user access based on policies."
    },
    {
      "id": 45,
      "question": "A network admin sees random MAC addresses flooding the CAM table. Which FIRST action reduces the immediate risk of a successful MAC flooding attack?",
      "options": [
        "Disable spanning tree on access ports",
        "Implement port security limiting MACs per port",
        "Enable jumbo frames to minimize overhead",
        "Set the trunk to dynamic desirable mode"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Disable spanning tree on access ports can create loops. Implement port security limiting MACs per port (correct) stops excessive MAC learn. Enable jumbo frames to minimize overhead is irrelevant to security. Set the trunk to dynamic desirable mode fosters trunk negotiation, not controlling MAC flooding.",
      "examTip": "Port security with a set MAC limit prevents the CAM table from being overwhelmed."
    },
    {
      "id": 46,
      "question": "A contractor requires temporary Wi-Fi access but must not see internal VLAN traffic. Which setting is BEST suited?",
      "options": [
        "A separate SSID mapped to a guest VLAN with ACL restrictions",
        "A single SSID bridging traffic to the internal VLAN",
        "LACP trunk port for the contractor AP",
        "DHCP reservations for the contractor's device"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A separate SSID mapped to a guest VLAN with ACL restrictions (correct) keeps contractors isolated in a dedicated VLAN. A single SSID bridging traffic to the internal VLAN merges them with internal traffic. LACP trunk port for the contractor AP is link aggregation, not isolation. DHCP reservations for the contractor's device only ensures consistent IP, not isolation.",
      "examTip": "Guest or contractor SSIDs typically map to dedicated VLANs restricted from internal networks."
    },
    {
      "id": 47,
      "question": "Which phenomenon is characterized by multiple paths forming between switches, generating endless broadcast loops?",
      "options": [
        "DHCP exhaustion",
        "ARP poisoning",
        "Switch bridging loops",
        "DNS spoofing"
      ],
      "correctAnswerIndex": 2,
      "explanation": "DHCP exhaustion is a DHCP scope issue. ARP poisoning is forging ARP entries. Switch bridging loops (correct) is bridging loops. DNS spoofing modifies DNS, not bridging loops.",
      "examTip": "Bridging loops can flood a network. STP or RSTP is essential to prevent them."
    },
    {
      "id": 48,
      "question": "A small office seeks to unify security controls like firewall, antivirus, and VPN under one device. Which solution is BEST for this requirement?",
      "options": [
        "Transparent switch operating at layer 2",
        "Load balancer with content distribution",
        "UTM (Unified Threat Management) appliance",
        "Layer 3 switch with VLAN routing"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Transparent switch operating at layer 2 is only bridging. Load balancer with content distribution distributes traffic but lacks integrated security. UTM (Unified Threat Management) appliance (correct) merges firewall, AV, content filtering, and VPN. Layer 3 switch with VLAN routing routes VLANs, not a full security suite.",
      "examTip": "A UTM appliance combines various security features, suitable for smaller deployments needing multi-layer protection."
    },
    {
      "id": 49,
      "question": "A network loop was triggered by a user connecting a small home switch with STP disabled. Which control is MOST likely to prevent this scenario?",
      "options": [
        "802.1X authentication on all access ports",
        "Enabling root guard or BPDU guard on access ports",
        "Configuring jumbo frames to reduce loop overhead",
        "Setting the trunk ports to VLAN 1 only"
      ],
      "correctAnswerIndex": 1,
      "explanation": "802.1X authentication on all access ports authenticates endpoints but doesn’t block bridging loops. Enabling root guard or BPDU guard on access ports (correct) disables ports receiving unauthorized BPDUs. Configuring jumbo frames to reduce loop overhead is a performance tweak, not loop prevention. Setting the trunk ports to VLAN 1 only is not relevant to loops.",
      "examTip": "BPDU guard can shut an access port if it detects BPDUs, preventing accidental or rogue bridging devices."
    },
    {
      "id": 50,
      "question": "A help desk ticket states that a remote user cannot access internal servers over the SSL VPN. Logs show repeated failed authentication attempts. What is the FIRST action?",
      "options": [
        "Disable the user’s network account",
        "Verify the user’s credentials and ensure correct MFA usage",
        "Rebuild the entire SSL VPN portal configuration",
        "Upgrade the firewall firmware to the latest version"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Disable the user’s network account is punitive without verification. Verify the user’s credentials and ensure correct MFA usage (correct) standard procedure to confirm user credentials. Rebuild the entire SSL VPN portal configuration is drastic. Upgrade the firewall firmware to the latest version is general maintenance, not immediate user-level fix.",
      "examTip": "Before major changes, verify the user is entering the correct username, password, and MFA token."
    },
    {
      "id": 51,
      "question": "A new data center design requires traffic isolation between servers and storage, though they share the same physical infrastructure. Which solution is BEST?",
      "options": [
        "Multiple APIPA ranges assigned to each device group",
        "VLAN segmentation with ACLs restricting cross-traffic",
        "DNS load balancing to direct servers to the correct storage IP",
        "DHCP reservations based on device MAC addresses"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Multiple APIPA ranges assigned to each device group is a fallback IP assignment, not segmentation. VLAN segmentation with ACLs restricting cross-traffic (correct) logically isolates traffic. DNS load balancing to direct servers to the correct storage IP is for load distribution, not security. DHCP reservations based on device MAC addresses ensures consistent IP but doesn’t segment traffic.",
      "examTip": "VLAN segmentation plus ACLs or firewalls can isolate sensitive traffic on shared hardware."
    },
    {
      "id": 52,
      "question": "An ISP’s BGP router has multiple routes to the same subnet. Which statement is TRUE about how BGP selects the optimal route?",
      "options": [
        "It uses the fewest hops as the deciding factor",
        "It chooses the route advertised most recently",
        "It follows a complex selection process including attributes like AS-Path",
        "It simply picks the route with the lowest administrative distance"
      ],
      "correctAnswerIndex": 2,
      "explanation": "It uses the fewest hops as the deciding factor is RIP’s metric. It chooses the route advertised most recently is not how BGP logic works. It follows a complex selection process including attributes like AS-Path (correct) BGP uses Weight, Local Pref, AS-Path, MED, etc. It simply picks the route with the lowest administrative distance is more about comparing different protocols, not within BGP.",
      "examTip": "BGP path selection is influenced by multiple attributes in a strict sequence, including local preference and AS-Path."
    },
    {
      "id": 53,
      "question": "A layer 2 switch is dropping frames from an IP phone and a connected PC on the same port. Both MAC addresses appear on that port. Which switch feature can solve this while allowing phone and PC to coexist?",
      "options": [
        "Configure voice VLAN with tagged frames",
        "Enable port mirroring for traffic capture",
        "Lower the MTU on the port to handle double tagging",
        "Disable PoE on the switchport"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Configure voice VLAN with tagged frames (correct) dedicates a separate VLAN tag for voice. Enable port mirroring for traffic capture is for packet analysis. Lower the MTU on the port to handle double tagging is a mismatch fix, not typical. Disable PoE on the switchport kills power to the phone, not a solution.",
      "examTip": "Many IP phones pass voice traffic tagged (voice VLAN) and data traffic untagged, requiring a voice VLAN configuration."
    },
    {
      "id": 54,
      "question": "Which direct approach helps reduce the overhead of frequently generating new ephemeral keys in IPSec?",
      "options": [
        "Using a longer IKE Phase 1 lifetime",
        "Disabling encryption entirely",
        "Switching from ESP to AH mode only",
        "Blocking ICMP packets at the gateway"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Using a longer IKE Phase 1 lifetime (correct) extends how long the secured channel is valid. Disabling encryption entirely removes security. Switching from ESP to AH mode only eliminates payload encryption. Blocking ICMP packets at the gateway is unrelated to rekeys.",
      "examTip": "IKE Phase 1 sets up the secure SA for key exchange. A longer lifetime means fewer rekey events."
    },
    {
      "id": 55,
      "question": "A floor switch that provides PoE to multiple phones abruptly shuts down. Which environmental factor is MOST likely if the switch’s fan was running at full speed?",
      "options": [
        "Excessive heat in the telecom closet",
        "Too many VLANs assigned to the switch",
        "STP misconfiguration creating loops",
        "Cable runs exceeding 100 meters"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Excessive heat in the telecom closet (correct) can cause thermal shutdown. Too many VLANs assigned to the switch is a logical limit, not physical meltdown. STP misconfiguration creating loops causes a broadcast storm, not direct overheating. Cable runs exceeding 100 meters is cable standard violation, not necessarily thermal.",
      "examTip": "Proper ventilation or cooling is vital in closets handling high PoE loads to prevent overheating."
    },
    {
      "id": 56,
      "question": "Which step do you take FIRST if your switch logs show frequent TCN (Topology Change Notification) events in spanning tree?",
      "options": [
        "Disable spanning tree on all ports",
        "Identify flapping interfaces or ports going up/down",
        "Reboot the entire network core to reset STP",
        "Change the BPDU timers to maximum values"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Disable spanning tree on all ports invites loops. Identify flapping interfaces or ports going up/down (correct) finds the root cause for repeated STP recalculations. Reboot the entire network core to reset STP is disruptive. Change the BPDU timers to maximum values delays convergence, not solving frequent changes.",
      "examTip": "Locate unstable links or ports causing STP recalculations by frequently changing states."
    },
    {
      "id": 57,
      "question": "A server with a static IP cannot access the internet, but can reach internal hosts. Which is the MOST likely missing piece in its configuration?",
      "options": [
        "Default gateway address",
        "DNS domain suffix",
        "SNMP community string",
        "IPv6 link-local address"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Default gateway address (correct) is necessary for off-subnet traffic. DNS domain suffix affects name resolution but not raw routing. SNMP community string is for monitoring. IPv6 link-local address is IPv6 local assignment, not relevant for IPv4 internet access.",
      "examTip": "If local communication works but not external, check the default gateway for the correct IP address."
    },
    {
      "id": 58,
      "question": "A user’s PC randomly disassociates from the Wi-Fi as they move around the building. Which setting is MOST relevant for ensuring a seamless handoff?",
      "options": [
        "802.1X on the switch uplinks",
        "Wireless controller's roaming thresholds",
        "Captive portal re-authentication intervals",
        "DHCP server lease time"
      ],
      "correctAnswerIndex": 1,
      "explanation": "802.1X on the switch uplinks is wired auth, not Wi-Fi roaming. Wireless controller's roaming thresholds (correct) ensures smooth AP-to-AP handover. Captive portal re-authentication intervals is for guest logins. DHCP server lease time is about IP leases, not roam disconnections.",
      "examTip": "Optimizing roam thresholds on the wireless controller helps devices switch APs without losing connectivity."
    },
    {
      "id": 59,
      "question": "Which scenario MOST justifies using DHCP relay (IP helper) on a subnet?",
      "options": [
        "All devices on that subnet have static IPs",
        "The DHCP server resides on a different network segment",
        "DNS resolution must be handled by a local DNS server",
        "The subnet does not support IPv4"
      ],
      "correctAnswerIndex": 1,
      "explanation": "All devices on that subnet have static IPs makes DHCP unnecessary. The DHCP server resides on a different network segment (correct) is the main reason for a relay. DNS resolution must be handled by a local DNS server is name resolution, not address assignment. The subnet does not support IPv4 is contradictory to DHCP for IPv4.",
      "examTip": "DHCP relay (IP helper) is used so DHCP broadcasts can reach a server on another subnet."
    },
    {
      "id": 60,
      "question": "Which standard allows for multiple devices to share a single authenticated 802.1X port, such as a VoIP phone and a PC daisy-chained together?",
      "options": [
        "LLDP-MED",
        "MAB (MAC Authentication Bypass)",
        "EAP-TLS bridging",
        "802.1X multiple domain authentication"
      ],
      "correctAnswerIndex": 3,
      "explanation": "LLDP-MED is about enhanced discovery for VoIP. MAB (MAC Authentication Bypass) is a fallback method. EAP-TLS bridging is certificate-based but not multi-device. 802.1X multiple domain authentication (correct) is designed for phone + PC on one port with separate authentication domains.",
      "examTip": "802.1X multi-domain or multi-auth mode permits a phone and a PC to authenticate on a single switch port."
    },
    {
      "id": 61,
      "question": "A technician is analyzing suspicious ARP traffic on the LAN. Which command on a Windows PC can reveal current ARP mappings?",
      "options": [
        "netstat -an",
        "arp -a",
        "ip addr show",
        "nslookup"
      ],
      "correctAnswerIndex": 1,
      "explanation": "netstat -an shows connections and listening ports. arp -a (correct) displays ARP cache. ip addr show is typically Linux-based. nslookup is DNS queries.",
      "examTip": "arp -a lists your local ARP cache, letting you check for suspicious MAC-IP entries."
    },
    {
      "id": 62,
      "question": "Which scenario exemplifies the need for a captive portal?",
      "options": [
        "You want guests to accept usage terms before accessing Wi-Fi",
        "You require QoS for voice calls on the LAN",
        "You need to enforce out-of-band management on a router",
        "You plan to connect multiple VLANs via one trunk interface"
      ],
      "correctAnswerIndex": 0,
      "explanation": "You want guests to accept usage terms before accessing Wi-Fi (correct) is typical for guest onboarding. You require QoS for voice calls on the LAN is traffic priority. You need to enforce out-of-band management on a router is a separate management plane. You plan to connect multiple VLANs via one trunk interface is VLAN trunking, not a user login scenario.",
      "examTip": "Captive portals commonly present a terms or login page, especially for guest Wi-Fi access."
    },
    {
      "id": 63,
      "question": "Which factor is the MOST significant advantage of a stateful firewall over a stateless one?",
      "options": [
        "It can store and examine the entire data payload for viruses",
        "It tracks session information, allowing dynamic rules for return traffic",
        "It reduces the overhead of NAT by caching port assignments",
        "It can physically bond multiple interfaces for redundancy"
      ],
      "correctAnswerIndex": 1,
      "explanation": "It can store and examine the entire data payload for viruses describes deeper inspection (UTM). It tracks session information, allowing dynamic rules for return traffic (correct) is the essence of stateful: tracking connections. It reduces the overhead of NAT by caching port assignments is NAT behavior but not the main difference. It can physically bond multiple interfaces for redundancy is link aggregation, not a firewall feature.",
      "examTip": "A stateful firewall automatically allows return traffic for established connections, simplifying rule sets."
    },
    {
      "id": 64,
      "question": "A distribution switch reboots nightly at the same time. Logs show power spikes in the rack. What is the OPTIMAL solution?",
      "options": [
        "Configure jumbo frames to handle power fluctuations",
        "Add an uninterruptible power supply (UPS)",
        "Disable half-duplex on all ports",
        "Shorten the DHCP lease times"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Configure jumbo frames to handle power fluctuations is unrelated. Add an uninterruptible power supply (UPS) (correct) stabilizes power. Disable half-duplex on all ports is a link setting. Shorten the DHCP lease times is about IP leases, not power. A UPS helps handle power spikes or brownouts.",
      "examTip": "UPS devices smooth out voltage fluctuations and provide battery backup, preventing random reboots."
    },
    {
      "id": 65,
      "question": "Which priority is MOST appropriate when diagnosing why an access point repeatedly fails to hand out DHCP addresses to new Wi-Fi clients?",
      "options": [
        "Perform a speed test against the AP’s WAN link",
        "Check if the AP is configured as a DHCP server or relay",
        "Enable 802.1Q trunking on the AP",
        "Change all client SSIDs to the same channel"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Perform a speed test against the AP’s WAN link tests WAN performance, not local DHCP. Check if the AP is configured as a DHCP server or relay (correct) clarifies DHCP responsibility on the AP. Enable 802.1Q trunking on the AP might matter if VLANs are used, but only after confirming DHCP is set. Change all client SSIDs to the same channel intensifies interference.",
      "examTip": "First determine if the AP itself is running DHCP or must relay to a central server, as misconfiguration there is common."
    },
    {
      "id": 66,
      "question": "A new VLAN was created, but hosts in that VLAN cannot communicate with other subnets. Which direct setting on the router is often the culprit?",
      "options": [
        "No default route on the core router",
        "The subinterface for that VLAN is administratively down",
        "Spanning tree is blocking the trunk link to the router",
        "Incorrect DNS records for the VLAN’s hosts"
      ],
      "correctAnswerIndex": 1,
      "explanation": "No default route on the core router might affect external traffic, but not necessarily local subnets. The subinterface for that VLAN is administratively down (correct) indicates the router interface is not active. Spanning tree is blocking the trunk link to the router might happen, but typically you'd see different errors. Incorrect DNS records for the VLAN’s hosts affects name resolution, not raw routing.",
      "examTip": "Ensure the new VLAN’s interface or subinterface is up/up with a valid IP for inter-VLAN routing."
    },
    {
      "id": 67,
      "question": "A user complains that large emails fail to send through the corporate firewall. Which firewall attribute is MOST likely causing the blockage?",
      "options": [
        "URL filtering mismatch for email domains",
        "Excessive broadcasting from the WAN interface",
        "Maximum allowed packet (or message) size setting",
        "Port security limit on MAC addresses"
      ],
      "correctAnswerIndex": 2,
      "explanation": "URL filtering mismatch for email domains is web content filtering. Excessive broadcasting from the WAN interface is a routing or loop issue. Maximum allowed packet (or message) size setting (correct) can drop oversized messages. Port security limit on MAC addresses is a layer 2 security measure, not email size.",
      "examTip": "Firewalls or mail gateways often have a max message size setting. Check if large attachments exceed that limit."
    },
    {
      "id": 68,
      "question": "Which statement BEST explains why you would use OSPF instead of RIP in a corporate environment?",
      "options": [
        "RIP converges faster on large, complex networks",
        "OSPF supports the broadcast of user credentials for authentication",
        "OSPF scales better and uses cost metrics rather than hop count",
        "RIP allows dynamic VLAN creation while OSPF does not"
      ],
      "correctAnswerIndex": 2,
      "explanation": "RIP converges faster on large, complex networks is false; RIP is slower in large networks. OSPF supports the broadcast of user credentials for authentication is incorrect regarding user credentials. OSPF scales better and uses cost metrics rather than hop count (correct) OSPF uses cost and is more scalable. RIP allows dynamic VLAN creation while OSPF does not references VLAN creation, not typical for routing protocols.",
      "examTip": "OSPF is a link-state protocol that converges quickly and suits larger, more complex networks than RIP."
    },
    {
      "id": 69,
      "question": "A broadcast storm temporarily took down a network. Which log entry is MOST likely associated with spanning tree preventing a loop?",
      "options": [
        "BPDU guard putting an interface in err-disabled state",
        "DHCP failover triggered on a secondary server",
        "ARP table entry for default gateway changed",
        "DNSSEC key roll invalidating a zone"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BPDU guard putting an interface in err-disabled state (correct) is typical when STP or BPDU guard detects a potential loop. DHCP failover triggered on a secondary server is DHCP redundancy. ARP table entry for default gateway changed is normal ARP usage. DNSSEC key roll invalidating a zone is about DNS security. Only BPDU guard references bridging loop prevention.",
      "examTip": "BPDU guard or root guard can disable ports if they threaten STP stability."
    },
    {
      "id": 70,
      "question": "A remote site with limited bandwidth experiences high latency for business-critical applications. Which approach is PRIMARY to ensure these apps perform well?",
      "options": [
        "Spanning tree in fast forward mode",
        "QoS traffic shaping and prioritization",
        "Changing STP cost on all trunk ports",
        "DHCP reservations for critical devices"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Spanning tree in fast forward mode is a bridging improvement. QoS traffic shaping and prioritization (correct) ensures important traffic is prioritized. Changing STP cost on all trunk ports modifies path cost, not traffic priority. DHCP reservations for critical devices reserves IP addresses but doesn’t shape bandwidth usage.",
      "examTip": "When bandwidth is constrained, QoS ensures mission-critical traffic has priority and lower latency."
    },
    {
      "id": 71,
      "question": "Which statement is TRUE about SSL and TLS in securing network communications?",
      "options": [
        "They only encrypt data at rest, not in transit",
        "TLS is considered a more secure, updated version of SSL",
        "SSL ensures WEP encryption for wireless networks",
        "They require plain text authentication for key exchange"
      ],
      "correctAnswerIndex": 1,
      "explanation": "They only encrypt data at rest, not in transit is incorrect; they encrypt data in transit. TLS is considered a more secure, updated version of SSL (correct) TLS supersedes SSL. SSL ensures WEP encryption for wireless networks is a Wi-Fi standard, not SSL/TLS. They require plain text authentication for key exchange is false; the handshake is encrypted.",
      "examTip": "TLS replaced SSL for improved cryptographic strength and security fixes."
    },
    {
      "id": 72,
      "question": "Which direct action helps mitigate VLAN hopping attacks?",
      "options": [
        "Configuring trunk ports to negotiate dynamically on every port",
        "Disabling DTP and explicitly specifying access or trunk mode",
        "Allowing VLAN 1 as the native VLAN across all switches",
        "Blocking DNS requests on untrusted ports"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Configuring trunk ports to negotiate dynamically on every port fosters dynamic trunking, which is risky. Disabling DTP and explicitly specifying access or trunk mode (correct) avoids unintended trunk formation or double-tagging. Allowing VLAN 1 as the native VLAN across all switches can be vulnerable. Blocking DNS requests on untrusted ports is not relevant to VLAN tagging attacks.",
      "examTip": "Prevent VLAN hopping by disabling auto trunk negotiation and setting a dedicated native VLAN."
    },
    {
      "id": 73,
      "question": "Which scenario BEST fits the use of EIGRP as a routing protocol?",
      "options": [
        "A multi-vendor environment needing open standard link-state routing",
        "A Cisco-only network requiring a hybrid distance-vector protocol",
        "Internet-level routing between multiple autonomous systems",
        "Small home network with only static routes"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A multi-vendor environment needing open standard link-state routing suits OSPF or IS-IS. A Cisco-only network requiring a hybrid distance-vector protocol (correct) EIGRP is proprietary to Cisco. Internet-level routing between multiple autonomous systems is BGP. Small home network with only static routes is overly simplistic for EIGRP.",
      "examTip": "EIGRP is often chosen for Cisco environments, offering fast convergence and advanced distance-vector features."
    },
    {
      "id": 74,
      "question": "A technician must frequently review changes on a switch. Which practice is MOST effective to track who made which configuration edits?",
      "options": [
        "Enable 802.1Q trunking logs",
        "Use a local user account for everyone",
        "Integrate the switch with a TACACS+ server for authentication",
        "Disable logging to reduce overhead"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Enable 802.1Q trunking logs logs VLAN events, not user edits. Use a local user account for everyone cannot differentiate individuals. Integrate the switch with a TACACS+ server for authentication (correct) ensures per-user authentication and command logging. Disable logging to reduce overhead removes any audit trail.",
      "examTip": "TACACS+ or RADIUS can track individual administrator actions for accountability."
    },
    {
      "id": 75,
      "question": "Which method is OPTIMAL to ensure every VLAN can utilize a single trunk link to a router for inter-VLAN routing?",
      "options": [
        "Assign each VLAN to a separate physical interface",
        "Configure subinterfaces with 802.1Q on the router",
        "Use DHCP option 82 for VLAN assignment",
        "Enable multiple native VLANs on the trunk port"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Assign each VLAN to a separate physical interface is hardware-intensive. Configure subinterfaces with 802.1Q on the router (correct) is router-on-a-stick. Use DHCP option 82 for VLAN assignment is for DHCP relay info. Enable multiple native VLANs on the trunk port can be confusing and is generally not recommended.",
      "examTip": "Subinterfaces on a single trunk port is the standard practice for inter-VLAN routing on a router."
    },
    {
      "id": 76,
      "question": "A manager wants to ensure that if a core switch fails, another device can immediately serve as the default gateway. Which protocol accomplishes this?",
      "options": [
        "VRRP",
        "OSPF",
        "SMTP",
        "CDP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "VRRP (correct) VRRP is a virtual router redundancy protocol. OSPF is a routing protocol, not specifically gateway redundancy. SMTP is email. CDP is discovery.",
      "examTip": "VRRP, HSRP, and GLBP provide gateway redundancy, ensuring immediate failover."
    },
    {
      "id": 77,
      "question": "Which is the PRIMARY reason to implement WPA3-Enterprise over WPA2-Personal in a corporate WLAN?",
      "options": [
        "To share a single passphrase among all employees",
        "To enforce individual user authentication with 802.1X",
        "To allow open guest access without a password",
        "To permit only WEP-level encryption"
      ],
      "correctAnswerIndex": 1,
      "explanation": "To share a single passphrase among all employees is typical of personal mode, not secure for enterprise. To enforce individual user authentication with 802.1X (correct) ensures unique credentials via 802.1X. To allow open guest access without a password is an open network. To permit only WEP-level encryption is outdated and insecure.",
      "examTip": "Enterprise mode uses 802.1X for user-level authentication, providing stronger security and accountability."
    },
    {
      "id": 78,
      "question": "A network engineer sees consistent ICMP echo requests from a single IP, saturating the WAN link. Which is the MOST direct measure to mitigate this DoS?",
      "options": [
        "Block inbound ICMP from that IP at the edge",
        "Replace the router with a higher throughput model",
        "Disable NAT for internal subnets",
        "Remove DNS entries for that IP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Block inbound ICMP from that IP at the edge (correct) specifically blocks the source. Replace the router with a higher throughput model is a hardware upgrade that does not stop the attack. Disable NAT for internal subnets breaks normal outbound traffic. Remove DNS entries for that IP only helps if the attacker used domain names, which is not guaranteed.",
      "examTip": "Filtering or rate-limiting malicious traffic is often the first line of defense during a DoS attack."
    },
    {
      "id": 79,
      "question": "Which command on a Cisco device displays active NAT translations, such as local to global mappings?",
      "options": [
        "show ip nat translations",
        "show running-config interface NAT",
        "show port-security address",
        "debug ip packet detail"
      ],
      "correctAnswerIndex": 0,
      "explanation": "show ip nat translations (correct) specifically shows NAT table entries. show running-config interface NAT is not a recognized command for NAT stats. show port-security address is a MAC security table. debug ip packet detail is a real-time debug, not a static table view.",
      "examTip": "'show ip nat translations' is standard on Cisco devices to see NAT mapping states."
    },
    {
      "id": 80,
      "question": "A new junior admin accidentally loops a switch port back into the same switch with a patch cable. Which FIRST safety net prevents a massive broadcast storm?",
      "options": [
        "BPDU guard or root guard on access ports",
        "DHCP relay on that port",
        "Switchport port security with sticky MAC",
        "802.1X authentication for the patch cable"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BPDU guard or root guard on access ports (correct) will disable the port if it sees BPDUs from itself. DHCP relay on that port is for DHCP traffic forwarding. Switchport port security with sticky MAC is about MAC addresses, not bridging loops. 802.1X authentication for the patch cable is device-level authentication, not loop prevention.",
      "examTip": "BPDU guard or root guard can disable a port that forms a loop, preventing broadcast storms."
    },
    {
      "id": 81,
      "question": "A developer wants to automate network device configurations. Which concept is MOST relevant for consistent, repeatable deployments?",
      "options": [
        "Rapid Spanning Tree Protocol",
        "Infrastructure as Code using scripts or templates",
        "WPS push-button setup on all switches",
        "Load balancing across multiple network interfaces"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Rapid Spanning Tree Protocol is a loop prevention protocol. Infrastructure as Code using scripts or templates (correct) uses code-driven configuration. WPS push-button setup on all switches is a consumer Wi-Fi feature. Load balancing across multiple network interfaces is a performance or redundancy approach, not config automation.",
      "examTip": "Infrastructure as Code (IaC) fosters version-controlled, scripted approaches to provisioning network hardware."
    },
    {
      "id": 82,
      "question": "A new building has a main distribution frame (MDF) on the first floor. Additional IDFs must connect to it. Which cable type is MOST appropriate for runs exceeding 90 meters between floors?",
      "options": [
        "STP Cat6 copper cables",
        "Single-mode fiber cables",
        "Coaxial RG-59 cables",
        "UTP Cat5e cables"
      ],
      "correctAnswerIndex": 1,
      "explanation": "STP Cat6 copper cables and UTP Cat5e cables are both limited to ~100m. Single-mode fiber cables (correct) supports much longer runs. Coaxial RG-59 cables is older coax, rarely used for modern IDFs.",
      "examTip": "Fiber is best for backbone links that exceed copper’s typical distance limits."
    },
    {
      "id": 83,
      "question": "A user complains that after an IP scope change, they can’t map to a server using its hostname. They can still ping its IP. Which setting is MOST likely the problem?",
      "options": [
        "NetBIOS name resolution not updated",
        "DHCP server scope extended beyond the original subnet",
        "The DNS A record is outdated or missing the new IP",
        "The router’s default route points to the wrong interface"
      ],
      "correctAnswerIndex": 2,
      "explanation": "NetBIOS name resolution not updated is older Windows name resolution method. DHCP server scope extended beyond the original subnet expands addresses but not name resolution. The DNS A record is outdated or missing the new IP (correct) suggests DNS references an old IP. The router’s default route points to the wrong interface is routing, but pinging the IP still works so it's not a gateway issue.",
      "examTip": "When IPs change, ensure DNS records reflect the correct new addresses."
    },
    {
      "id": 84,
      "question": "Which scenario BEST describes using 802.3ad (LACP) in a network design?",
      "options": [
        "Bundling multiple links between switches for higher throughput and redundancy",
        "Automatically encrypting all VLAN traffic on trunk links",
        "Dynamically allocating IP addresses across multiple subnets",
        "Sending VLAN 1 traffic exclusively over a single trunk"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Bundling multiple links between switches for higher throughput and redundancy (correct) is link aggregation. Automatically encrypting all VLAN traffic on trunk links is encryption, not LACP. Dynamically allocating IP addresses across multiple subnets is DHCP. Sending VLAN 1 traffic exclusively over a single trunk is not relevant to link aggregation.",
      "examTip": "LACP combines multiple Ethernet links into one logical channel for redundancy and more bandwidth."
    },
    {
      "id": 85,
      "question": "Which question is BEST addressed by implementing 802.1X authentication on access switches?",
      "options": [
        "How to provide separate SSIDs for guests",
        "How to ensure only authorized devices gain network access at the switch port",
        "How to lower the cost of broadcast traffic in a subnet",
        "How to reduce the network’s default gateway utilization"
      ],
      "correctAnswerIndex": 1,
      "explanation": "How to provide separate SSIDs for guests is a wireless segmentation question. How to ensure only authorized devices gain network access at the switch port (correct) is the primary purpose of port-based authentication. How to lower the cost of broadcast traffic in a subnet is a broadcast domain topic, not 802.1X. How to reduce the network’s default gateway utilization is about routing, not NAC.",
      "examTip": "802.1X ensures endpoints authenticate before being granted LAN access, enhancing security."
    },
    {
      "id": 86,
      "question": "A DHCP server is configured with an IP pool of 200 addresses, but after several days, new clients fail to get addresses. Which direct factor is MOST likely?",
      "options": [
        "Wrong VLAN assigned to the server interface",
        "Lease time is too long, causing IP exhaustion",
        "APIPA addresses conflicting with the DHCP scope",
        "The router has insufficient NAT sessions"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Wrong VLAN assigned to the server interface would prevent any leases from the start. Lease time is too long, causing IP exhaustion (correct) can fill the pool if addresses aren’t released quickly. APIPA addresses conflicting with the DHCP scope is not typical. The router has insufficient NAT sessions is NAT, not internal address assignment.",
      "examTip": "If the DHCP pool is used up, shorten lease time or expand the scope so addresses can recycle."
    },
    {
      "id": 87,
      "question": "Which direct action can a security engineer take to protect routers from on-path (man-in-the-middle) attacks targeting routing updates?",
      "options": [
        "Configure STP with root guard",
        "Implement encryption or authentication on routing protocols",
        "Use half-duplex operation on router interfaces",
        "Disable DHCP on the router"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Configure STP with root guard is a switch-based measure. Implement encryption or authentication on routing protocols (correct) secures OSPF, EIGRP, or BGP. Use half-duplex operation on router interfaces is a physical setting. Disable DHCP on the router is address assignment, not route authentication.",
      "examTip": "Routing protocol authentication (e.g., OSPF MD5) prevents attackers from injecting fake routes."
    },
    {
      "id": 88,
      "question": "A recent firewall policy change blocks TFTP traffic. Which port is MOST likely closed, breaking TFTP functionality?",
      "options": [
        "21",
        "23",
        "69",
        "445"
      ],
      "correctAnswerIndex": 2,
      "explanation": "21 is FTP control, 23 is Telnet, 69 (correct) TFTP uses UDP port 69, 445 is SMB.",
      "examTip": "TFTP uses UDP port 69 for transferring files without authentication."
    },
    {
      "id": 89,
      "question": "A consultant recommends LACP for trunk links between core switches. What is the MOST direct benefit of implementing this?",
      "options": [
        "Encryption of data between core devices",
        "Combining multiple ports into a single logical interface for higher throughput",
        "Automatic IP addressing for all core switch interfaces",
        "Securing the console port with strong passwords"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption of data between core devices is not an LACP function. Combining multiple ports into a single logical interface for higher throughput (correct) is link aggregation. Automatic IP addressing for all core switch interfaces references DHCP, not LACP. Securing the console port with strong passwords is management access, unrelated to trunk throughput.",
      "examTip": "LACP aggregates multiple physical links to increase bandwidth and provide redundancy."
    },
    {
      "id": 90,
      "question": "A computer obtains a DHCP address correctly, but cannot resolve hostnames. Pinging external IPs works fine. Which is the FIRST check to perform?",
      "options": [
        "Verify the DNS servers assigned by DHCP",
        "Disable the 802.1X agent on the user’s PC",
        "Reinstall the NIC drivers",
        "Change the user’s gateway to 0.0.0.0"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Verify the DNS servers assigned by DHCP (correct) ensures the correct DNS is provided. Disable the 802.1X agent on the user’s PC is about authentication. Reinstall the NIC drivers is more drastic. Change the user’s gateway to 0.0.0.0 invalidates routing entirely.",
      "examTip": "Always confirm clients receive valid DNS server IPs when DHCP is functioning but name resolution fails."
    },
    {
      "id": 91,
      "question": "Which step is MOST suitable for tracking long-term bandwidth trends and capacity planning on core routers?",
      "options": [
        "Use port mirroring to capture all traffic",
        "Configure SNMP monitoring with historical graphing",
        "Enable WEP encryption on all WAN interfaces",
        "Shorten the DHCP lease time to gather IP data"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Use port mirroring to capture all traffic is packet capture, not trending. Configure SNMP monitoring with historical graphing (correct) collects usage counters for capacity analysis. Enable WEP encryption on all WAN interfaces is an outdated Wi-Fi security standard. Shorten the DHCP lease time to gather IP data addresses IP assignment, not usage metrics.",
      "examTip": "SNMP-based monitoring tools with graphing are critical for observing traffic trends over time."
    },
    {
      "id": 92,
      "question": "Which scenario BEST highlights the use of NAC (Network Access Control) to enforce posture checks?",
      "options": [
        "Verifying a device is patched and running antivirus before granting network access",
        "Routing VLAN 10 traffic to the internet",
        "Blocking large file transfers by default",
        "Assigning a static IP for each device"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Verifying a device is patched and running antivirus before granting network access (correct) is NAC’s prime function. Routing VLAN 10 traffic to the internet is standard routing. Blocking large file transfers by default is a policy, not posture-based. Assigning a static IP for each device is manual IP assignment, not NAC.",
      "examTip": "NAC can check if devices meet security standards (e.g., AV up to date) prior to network admission."
    },
    {
      "id": 93,
      "question": "A layer 2 loop occurs in the network. Which protocol is designed to detect and eliminate bridging loops automatically?",
      "options": [
        "RSTP",
        "VTP",
        "CDP",
        "LLDP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RSTP (correct) is Rapid Spanning Tree. VTP manages VLANs. CDP is Cisco Discovery Protocol, LLDP is Link Layer Discovery Protocol. Neither handle loops directly.",
      "examTip": "Spanning Tree Protocol (STP/RSTP) is essential for preventing bridging loops in switched networks."
    },
    {
      "id": 94,
      "question": "A help desk technician sees that a user’s IP is 192.168.100.27/28. How many usable host IP addresses are available in this subnet?",
      "options": [
        "6",
        "14",
        "30",
        "62"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A /28 has 16 total addresses (2 reserved for network and broadcast), leaving 14 usable. 6 is a /29. 14 (correct) is /28. 30 is for a /27, 62 for a /26.",
      "examTip": "Each subnet with a /28 has 16 total IPs, of which 14 are usable for hosts."
    },
    {
      "id": 95,
      "question": "Your company needs a secure remote access solution for teleworkers, but wants minimal overhead on client devices. Which technology is MOST aligned with this goal?",
      "options": [
        "Client-based L2TP/IPSec requiring pre-installed software",
        "Clientless SSL VPN accessible via a standard browser",
        "PPTP using MS-CHAP for encryption",
        "RDP sessions directly exposed to the internet"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Client-based L2TP/IPSec requiring pre-installed software requires a VPN client. Clientless SSL VPN accessible via a standard browser (correct) only needs a browser for web-based access. PPTP using MS-CHAP for encryption is outdated with weaker security. RDP sessions directly exposed to the internet is risky, exposing RDP externally.",
      "examTip": "Clientless SSL VPNs let remote users connect securely via web portals without specialized software."
    },
    {
      "id": 96,
      "question": "A core router frequently runs out of memory when handling large routing tables. Which direct action is MOST appropriate FIRST?",
      "options": [
        "Replace static routing with dynamic routing protocols",
        "Implement route summarization or aggregation where possible",
        "Increase the DHCP lease times to reduce overhead",
        "Block all inbound ICMP to reduce routing overhead"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Replace static routing with dynamic routing protocols might expand the table further if dynamic routes are large. Implement route summarization or aggregation where possible (correct) reduces the number of routes stored. Increase the DHCP lease times to reduce overhead is not relevant to routing table size. Block all inbound ICMP to reduce routing overhead dropping ICMP doesn’t reduce routing table entries.",
      "examTip": "Summarizing or aggregating routes can drastically shrink the routing table, alleviating memory pressure."
    },
    {
      "id": 97,
      "question": "A network admin suspects an unauthorized access point is operating nearby, using the same SSID as the corporate network. Which term BEST describes this threat?",
      "options": [
        "Evil twin",
        "Bluesnarfing",
        "MAC spoofing",
        "DNS injection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Evil twin (correct) sets up a rogue AP mimicking a legitimate SSID. Bluesnarfing is Bluetooth data theft, MAC spoofing manipulates MAC addresses, DNS injection alters DNS responses.",
      "examTip": "An evil twin AP copies the SSID to trick users into connecting to a malicious hotspot."
    },
    {
      "id": 98,
      "question": "Which scenario is BEST resolved by implementing out-of-band (OOB) management on critical network devices?",
      "options": [
        "Upgrading all PoE firmware without user downtime",
        "Providing remote access to devices when the primary network is unreachable",
        "Segmenting guest Wi-Fi from corporate Wi-Fi",
        "Applying content filters to block streaming media"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Upgrading all PoE firmware without user downtime is a typical process but not specifically OOB. Providing remote access to devices when the primary network is unreachable (correct) is the reason for OOB: manage devices even if the LAN is down. Segmenting guest Wi-Fi from corporate Wi-Fi is Wi-Fi segmentation. Applying content filters to block streaming media is web filtering, not OOB management.",
      "examTip": "OOB management uses a separate link or console server so you can still reach devices if the production network fails."
    },
    {
      "id": 99,
      "question": "A third-party vendor needs partial access to your LAN to monitor networked equipment. Which strategy is PRIMARY for granting restricted access?",
      "options": [
        "Give them the core router’s admin credentials",
        "Create a dedicated VLAN with ACLs limiting what they can reach",
        "Point them to a default gateway of 0.0.0.0",
        "Grant them telnet access to all devices"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Give them the core router’s admin credentials is a security risk. Create a dedicated VLAN with ACLs limiting what they can reach (correct) isolates them while controlling permitted access. Point them to a default gateway of 0.0.0.0 breaks normal routing. Grant them telnet access to all devices is insecure remote management. VLAN + ACL is a safe, restricted approach.",
      "examTip": "Limiting vendor access to a quarantined VLAN with specific ACLs prevents unauthorized exploration of your LAN."
    },
    {
      "id": 100,
      "question": "A breach in one departmental VLAN led to quick lateral movement across the entire network. Which single action can MOST reduce this risk in the future?",
      "options": [
        "Implement tighter VLAN segmentation and ACLs between departments",
        "Configure a single, larger subnet for all departments",
        "Set DHCP to a minimum one-hour lease time",
        "Enable Telnet across all routers for faster login"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Implement tighter VLAN segmentation and ACLs between departments (correct) stops attackers from moving freely across VLANs. Configure a single, larger subnet for all departments lumps everyone in the same subnet, worsening lateral spread. Set DHCP to a minimum one-hour lease time is about IP address leases, not security. Enable Telnet across all routers for faster login is an insecure protocol. VLAN segmentation plus ACLs is crucial for lateral movement prevention.",
      "examTip": "Micro-segmentation helps contain breaches; attackers cannot easily pivot if VLANs and ACLs are well enforced."
    }
  ]
});
