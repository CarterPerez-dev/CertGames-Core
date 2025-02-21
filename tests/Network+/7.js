db.tests.insertOne({
  "category": "netplus",
  "testId": 7,
  "testName": "Practice Test #7 (Challenging)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "In an OSPF multi-area deployment, which router type contains a full LSDB for the backbone area plus one or more non-backbone areas?",
      "options": [
        "Autonomous System Boundary Router (ASBR)",
        "Area Border Router (ABR)",
        "Internal Router",
        "NSSA Router"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A redistributes external routes into OSPF. Option B (correct) sits between multiple areas, holding LSDBs for each. Option C is entirely within one area. Option D is an area variant but not necessarily bridging multiple areas.",
      "examTip": "ABRs connect the backbone (Area 0) to other OSPF areas, maintaining separate LSDBs for each."
    },
    {
      "id": 2,
      "question": "A firewall logs show a burst of TCP SYN packets to port 3389 from random IPs. Which service is being probed for possible exploitation?",
      "options": [
        "Telnet",
        "RDP",
        "FTP",
        "SNMP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is port 23, Option B (correct) is Remote Desktop Protocol, Option C is 21 (control) or 20 (data), Option D is 161/162. Port 3389 scanning suggests RDP brute force attempts.",
      "examTip": "RDP commonly listens on TCP 3389, so unexpected inbound scans may indicate malicious probing."
    },
    {
      "id": 3,
      "question": "Which IPv6 address type is valid for one subnet but not routable externally, starting with ‘FD’ or ‘FC’ hex prefix?",
      "options": [
        "Global unicast",
        "Unique local",
        "Link-local",
        "Anycast"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is publicly routable (2xxx, 3xxx). Option B (correct) uses FC00::/7 or FD00::/8 ranges. Option C is FE80:: used on a single link. Option D is a routing method but not an address scope by itself.",
      "examTip": "Unique local IPv6 addresses (fc00::/7) are for internal use, not globally routed."
    },
    {
      "id": 4,
      "question": "Which advanced QoS approach allows strict priority queuing for voice but also supports weighted fair scheduling among other traffic classes?",
      "options": [
        "Policing with single-rate three-color marker",
        "Strict round-robin queueing",
        "LLQ (Low Latency Queueing)",
        "SPAN session"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is a policing concept, not scheduling. Option B is basic round-robin. Option C (correct) gives priority to voice but also ensures fair sharing for other classes. Option D is a mirroring setup. LLQ is commonly used in WAN QoS designs.",
      "examTip": "LLQ offers a strict priority queue for voice and real-time traffic plus weighted scheduling for other classes."
    },
    {
      "id": 5,
      "question": "In a dual-homed BGP design to two ISPs, which attribute is commonly used to influence inbound traffic from the internet?",
      "options": [
        "Weight",
        "Local Preference",
        "MED (Multi-Exit Discriminator)",
        "AS-Path Prepending"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Option A is local to one router, Option B is for outbound traffic, Option C influences inbound but only if the neighboring AS honors MED. Option D (correct) extends the AS path artificially, making one path less preferred to inbound traffic. AS-Path Prepending is widely used for inbound route manipulation.",
      "examTip": "To manipulate inbound traffic, you often adjust how your routes appear externally, e.g., by AS-path prepending."
    },
    {
      "id": 6,
      "question": "Which IPv6 migration strategy encapsulates IPv6 inside IPv4 packets, enabling transit over an IPv4-only core?",
      "options": [
        "Dual stack",
        "NAT64",
        "Tunneling (6to4, ISATAP, etc.)",
        "SLAAC"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A runs v4 and v6 simultaneously, Option B translates v6 to v4, Option C (correct) encapsulates v6 traffic, Option D is auto-config but does not solve IPv4 core limitations. Tunnels allow IPv6 to traverse IPv4 networks without  translation.",
      "examTip": "When an IPv4 backbone can’t be upgraded, tunneling solutions (6to4, ISATAP, GRE, etc.) carry IPv6 over IPv4."
    },
    {
      "id": 7,
      "question": "A router discards packets to an outside network due to ‘overlapping subnets’ error. Which FIRST step do you take?",
      "options": [
        "Disable spanning tree on the LAN interface",
        "Check the local route table for duplicate network statements",
        "Reboot the router to clear ARP cache",
        "Enable jumbo frames"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is unrelated, Option B (correct) typically indicates conflicting or overlapping prefixes in the router config. Option C is a short-term fix but not guaranteed. Option D is a frame-size tweak, irrelevant. Removing overlapping subnets or adjusting mask resolves the error.",
      "examTip": "Overlapping subnets in routing cause confusion about which interface handles certain IP ranges, leading to dropped packets."
    },
    {
      "id": 8,
      "question": "Which  measure prevents ARP poisoning by verifying each ARP request/reply against known IP-MAC pairs gleaned from DHCP snooping?",
      "options": [
        "DTP guard",
        "ARP flood control",
        "Dynamic ARP Inspection",
        "BPDU guard"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is about trunking, Option B is a general broadcast mitigation, Option C (correct) checks ARP traffic for integrity, Option D is STP. DAI intercepts ARP packets and validates them with DHCP snooping or static bindings.",
      "examTip": "Dynamic ARP Inspection uses DHCP snooping or static ARP tables to verify IP-to-MAC mappings, blocking spoofs."
    },
    {
      "id": 9,
      "question": "In an 802.11ac Wave 2 deployment, which technology allows multiple downstream transmissions to distinct clients simultaneously using different spatial streams?",
      "options": [
        "OFDMA random access",
        "MU-MIMO",
        "CSMA/CA",
        "FHSS hopping"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is more 802.11ax (OFDMA). Option B (correct) MU-MIMO introduced in 11ac Wave 2 for multiple simultaneous transmissions. Option C is a collision avoidance method, Option D is old frequency-hopping. MU-MIMO boosts overall throughput in multi-user scenarios.",
      "examTip": "MU-MIMO in 802.11ac Wave 2 allows an AP to send data to multiple clients at once, rather than sequentially."
    },
    {
      "id": 10,
      "question": "Which BGP attribute is considered first in route selection (on Cisco devices), but only relevant to iBGP and not carried across eBGP?",
      "options": [
        "Weight",
        "Local Preference",
        "AS Path length",
        "Origin type"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) is Cisco-proprietary and local to the router. Option B is second used throughout the AS, Option C is for external route selection. Option D is a lesser priority attribute. Weight is the top priority in Cisco’s BGP selection, but not propagated outside.",
      "examTip": "BGP decision process on Cisco: Weight > Local Preference > Origination (local) > AS-Path length > etc."
    },
    {
      "id": 11,
      "question": "Which  is BEST solved by implementing an out-of-band management (OOB) network with a console server?",
      "options": [
        " reduce broadcast storms on the core LAN",
        " manage switches if the production network is down",
        " load balance inbound HTTP requests to multiple servers",
        " secure RDP sessions with IPsec"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is an STP or VLAN design, Option B (correct) OOB is crucial for device access if main connections fail. Option C is load balancing, Option D is encryption for remote desktop. OOB ensures a separate path for management outside production traffic.",
      "examTip": "An OOB network or console server helps maintain device access during outages or main network issues."
    },
    {
      "id": 12,
      "question": "A NAT device must handle thousands of concurrent connections from inside clients. Which NAT variant uses different source port mappings to differentiate many private IP flows behind one public IP?",
      "options": [
        "Static one-to-one NAT",
        "Port Address Translation (PAT)",
        "Transparent proxy",
        "Dynamic NAT with limited pool"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is for a single mapping, Option B (correct) uses unique source port combos, Option C is an application-layer solution, Option D could run out of addresses. PAT is the standard for large outbound concurrency.",
      "examTip": "PAT translates multiple private IPs to one public IP by altering source ports to keep connections distinct."
    },
    {
      "id": 13,
      "question": "Which Cisco command reveals a switch's dynamic ARP Inspection configuration and statistics to confirm if ARP traffic is being dropped?",
      "options": [
        "show ip arp inspection",
        "show dhcp snooping binding",
        "show mac address-table",
        "show interface trunk"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) focuses on DAI status. Option B is DHCP snooping but not ARP inspection details, Option C is MAC layer, Option D is trunk status. 'show ip arp inspection' displays DAI config and drop counters.",
      "examTip": "Dynamic ARP Inspection has its own show commands to check ACL matches, drop counts, and trust settings."
    },
    {
      "id": 14,
      "question": "Which event triggers a VTP (VLAN Trunking Protocol) revision number to increment in server mode?",
      "options": [
        "A switch receiving a CDP packet from a new neighbor",
        "Any change to the VLAN database (add, delete, modify)",
        "A user logging in via SSH",
        "Configuring half-duplex on a trunk interface"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is Cisco Discovery Protocol, not VTP. Option B (correct) VLAN changes increment the revision. Option C is user login, not VLAN change. Option D is a link-layer setting. VTP revision increments whenever the VLAN database is altered on a VTP server.",
      "examTip": "Be cautious with VTP revision numbers; a higher revision can overwrite the VLAN config across the domain."
    },
    {
      "id": 15,
      "question": "Which layer of the OSI model is responsible for data translation and encryption, ensuring that the application receives data in a usable format?",
      "options": [
        "Session layer (Layer 5)",
        "Presentation layer (Layer 6)",
        "Transport layer (Layer 4)",
        "Network layer (Layer 3)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A manages sessions, Option B (correct) handles data representation, compression, encryption, Option C deals with end-to-end transport, Option D routes packets. The Presentation layer ensures data is syntactically correct for the application layer.",
      "examTip": "Layer 6 is often overlooked, but it’s key for data formatting, encryption, and compression."
    },
    {
      "id": 16,
      "question": "A router redistributes routes from EIGRP into OSPF. Which router type is it considered within OSPF domain?",
      "options": [
        "ABR (Area Border Router)",
        "IR (Internal Router)",
        "ASBR (Autonomous System Boundary Router)",
        "DR (Designated Router)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A connects OSPF areas, Option B is inside one area, Option C (correct) injects external routes from another protocol, Option D is an elected role on multi-access networks, not protocol redistribution. ASBR is any OSPF router performing route injection from outside sources.",
      "examTip": "When an OSPF router imports routes from a non-OSPF domain, it’s an ASBR."
    },
    {
      "id": 17,
      "question": "Which statement accurately describes Quality of Service marking at layer 3?",
      "options": [
        "DSCP bits in the IP header to classify traffic",
        "802.1Q VLAN tags for trunking",
        "MAC addresses set to high priority",
        "DHCP Option 43 for device identification"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) DSCP uses 6 bits in the IPv4/IPv6 header for QoS. Option B is VLAN trunk tagging, Option C is a layer 2 address, Option D is DHCP vendor info. DSCP is the standard for layer 3 QoS marking.",
      "examTip": "DiffServ uses the DS field in the IP header to classify and prioritize packets."
    },
    {
      "id": 18,
      "question": "A sysadmin sees logs of a switch port repeatedly transitioning from 'blocking' to 'forwarding' in STP. Which is the MOST probable cause?",
      "options": [
        "BPDU guard is disabled",
        "A flapping link or physical instability on that port",
        "DHCP scope depletion",
        "Insufficient VLAN trunk allowed list"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A might disable the port if BPDUs are received. Option B (correct) a link going up/down triggers STP recalculation. Option C is IP addressing, Option D is VLAN trunk config. Physical flapping or connection issues cause STP to re-converge repeatedly.",
      "examTip": "Unstable physical connections can cause STP state changes, generating TCNs and re-convergence events."
    },
    {
      "id": 19,
      "question": "A switch’s CPU is high due to excessive broadcasts. The network is flat with ~200 hosts in one VLAN. Which FIRST step reduces broadcast storms?",
      "options": [
        "Split the VLAN into smaller subnets, using a layer 3 interface between them",
        "Set all ports to half-duplex",
        "Enable jumbo frames on trunk ports",
        "Use a default gateway of 0.0.0.0 for all hosts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) smaller broadcast domains drastically reduce overhead. Option B degrades performance, Option C is a frame-size tweak, Option D breaks routing. Subdividing large L2 segments is standard for mitigating broadcast storms.",
      "examTip": "VLAN and subnet segmentation is key to controlling broadcast traffic in large networks."
    },
    {
      "id": 20,
      "question": "A distribution switch shows a large number of runts. Which mismatch is MOST likely responsible?",
      "options": [
        "Auto-MDIX mismatch",
        "Access vs trunk confusion",
        "Speed/duplex mismatch causing collisions",
        "Incorrect DNS server IP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is auto-cable detection, Option B is VLAN config, Option C (correct) collisions due to half/full duplex can lead to runts, Option D is name resolution. Runt frames often point to physical-layer issues including speed/duplex mismatch.",
      "examTip": "Runts or collisions frequently result from one side half-duplex, the other full-duplex or speed mismatch."
    },
    {
      "id": 21,
      "question": "Which  measure helps prevent evil twin attacks in a corporate WLAN environment?",
      "options": [
        "Configure each client with static IP",
        "Enable 802.1w RSTP on the core switches",
        "Use EAP-TLS with certificate-based authentication to verify the AP’s identity",
        "Assign half-duplex on all APs"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A only sets IP addresses, Option B is spanning tree, Option C (correct) ensures mutual authentication, so clients trust the legitimate AP certificate, Option D is performance-limiting. Evil twins mimic SSIDs; certificate-based EAP helps clients verify the real AP.",
      "examTip": "WPA2/WPA3-Enterprise with certificate-based EAP can prevent clients from connecting to rogue APs that lack valid certs."
    },
    {
      "id": 22,
      "question": "Which advanced concept is used in data centers to stretch Layer 2 networks across Layer 3 boundaries using MAC-in-UDP encapsulation?",
      "options": [
        "MPLS TE",
        "PPTP tunneling",
        "VXLAN",
        "ISDN PRI"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is label-based traffic engineering, Option B is a legacy VPN method, Option C (correct) encapsulates Ethernet frames in UDP, Option D is older telephony. VXLAN is commonly used for large-scale virtualized data centers, enabling extended Layer 2 domains.",
      "examTip": "VXLAN is a popular overlay protocol that encapsulates L2 frames in UDP, scalable in cloud/DC environments."
    },
    {
      "id": 23,
      "question": "A BGP router sees multiple routes for the same subnet from different neighbors. After Weight and Local Pref, which attribute is next for route selection?",
      "options": [
        "AS-Path length",
        "MED",
        "Community string",
        "Hop count"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Typical Cisco BGP selection is Weight > Local Pref > Origination (Network or Aggregate) > AS-Path length > MED, etc. Option A (correct) is next. Option B is considered after path length. Option C is a tagging mechanism. Option D is RIP's metric, not BGP’s.",
      "examTip": "If Weight and Local Preference are tied, BGP chooses the shorter AS-Path next in the decision process."
    },
    {
      "id": 24,
      "question": "Which statement is TRUE about a 'collapsed core' network design?",
      "options": [
        "Layer 2 loops are impossible",
        "Core and distribution layers are combined into a single layer for smaller networks",
        "Each access switch must be fully meshed with every other access switch",
        "It mandates half-duplex to reduce complexity"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is not guaranteed, Option B (correct) merges two tiers in smaller networks, Option C is a full mesh approach but not typical collapsed design, Option D is incorrect. Collapsing the core means distribution and core functions run on the same hardware.",
      "examTip": "A collapsed core merges the core and distribution layers, often suitable for medium or smaller campuses to simplify topology."
    },
    {
      "id": 25,
      "question": "A switch repeatedly places a port in err-disabled mode whenever a second MAC is detected. Which feature triggers this?",
      "options": [
        "DHCP snooping",
        "Port security MAC limit",
        "RSTP edge port",
        "Storm control"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is DHCP server validation, Option B (correct) locks a port if multiple MACs appear, Option C is STP config, Option D limits broadcast storms. Port security can shut down a port upon exceeding MAC constraints.",
      "examTip": "Port security with a low MAC limit is useful for preventing hubs or unauthorized devices on an access port."
    },
    {
      "id": 26,
      "question": "A user complains their IPv6-only device cannot reach an IPv4-only website. Which method is BEST to solve this without changing the user’s IPv6 stack?",
      "options": [
        "Migrate the website to IPv6",
        "Implement NAT64 at the network edge",
        "Change the user’s device to dual stack",
        "Use static IPv4 addresses on the device"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A requires website changes. Option B (correct) translates IPv6 to IPv4. Option C is feasible but modifies the user device. Option D eliminates IPv6. NAT64 is a common approach for IPv6-only clients to access IPv4 services.",
      "examTip": "NAT64 is specifically designed to connect IPv6-only clients to IPv4 resources by translating traffic at the border."
    },
    {
      "id": 27,
      "question": "Which aspect of a next-generation firewall inspects layer 7 to identify the actual application behind a flow, even if it uses a common port like 80?",
      "options": [
        "Port-based ACL",
        "Application awareness (DPI)",
        "DHCP relay service",
        "LLDP neighbor detection"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is standard. Option B (correct) deep packet inspection at layer 7 reveals the true application. Option C is IP-forwarding for DHCP, Option D is device discovery. NGFW with DPI can see beyond port usage to identify apps like Skype or BitTorrent on port 80.",
      "examTip": "Application-aware firewalls can examine payloads and signatures, detecting apps that may circumvent basic port-based filtering."
    },
    {
      "id": 28,
      "question": "A spanning tree domain has many TCN (Topology Change Notification) events. Which root guard feature helps ensure an unauthorized switch cannot dethrone the chosen root?",
      "options": [
        "DHCP snooping on root ports",
        "BPDU guard on trunk links",
        "Setting a low priority value on the designated root and root guard on other core ports",
        "Configuring half-duplex for all VLANs"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is for DHCP. Option B is for access ports receiving BPDUs. Option C (correct) ensures a designated root with the lowest priority, while root guard on other ports stops superior BPDUs. Option D is irrelevant. Setting root priority plus root guard cements the chosen root.",
      "examTip": "Root guard is typically enabled on ports facing other potential STP switches, preventing them from sending superior BPDUs."
    },
    {
      "id": 29,
      "question": "Which solution is BEST to ensure a remote site’s VPN traffic always takes the route with the least latency among multiple available WAN links?",
      "options": [
        "Static default route to one link",
        "SD-WAN with dynamic path selection",
        "802.1X NAC on the WAN edge",
        "Half-duplex on all remote routers"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is static, ignoring real-time conditions. Option B (correct) monitors link performance, automatically steering traffic. Option C is for device auth, Option D is a link mismatch. SD-WAN dynamically chooses the best path based on policy metrics like latency or loss.",
      "examTip": "SD-WAN provides real-time link monitoring and policy-based path selection, optimizing performance over multiple transports."
    },
    {
      "id": 30,
      "question": "On a Cisco switch, which command can show the trunking encapsulation (ISL or 802.1Q) and allowed VLANs on each trunk port?",
      "options": [
        "show mac address-table",
        "show trunk encapsulation",
        "show interface trunk",
        "show vlan brief"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is MAC table, Option B is not a standard command, Option C (correct) reveals trunking details including encapsulation and VLANs, Option D is VLAN membership summary. 'show interface trunk' is typical for verifying trunk mode/config.",
      "examTip": "Use 'show interface trunk' to confirm trunk status, encapsulation, native VLAN, and allowed VLAN range."
    },
    {
      "id": 31,
      "question": "A user’s machine obtains an APIPA address (169.254.x.x). Which  conclusion can be drawn?",
      "options": [
        "The DNS server is set to 8.8.8.8",
        "DHCP server was not reachable or no lease was offered",
        "Port security shut down the interface",
        "The user must set a static IP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is a public DNS, not a  cause. Option B (correct) APIPA is a fallback for no DHCP. Option C is a different scenario, Option D is a workaround but not the  conclusion. If DHCP fails, Windows auto-assigns 169.254.x.x.",
      "examTip": "An APIPA address indicates the client tried DHCP but got no valid response."
    },
    {
      "id": 32,
      "question": "Which  is BEST addressed by implementing VRRP on the default gateway for VLAN subnets?",
      "options": [
        " reduce DHCP lease conflicts",
        " ensure a backup virtual router IP if the primary gateway fails",
        " share a single VLAN across multiple buildings",
        " encrypt DNS queries end-to-end"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is DHCP scope management, Option B (correct) VRRP provides a virtual IP shared by multiple routers, Option C is trunk design, Option D is DNS security. VRRP ensures gateway redundancy for subnets.",
      "examTip": "VRRP (or HSRP, GLBP) is used for first-hop redundancy, providing an always-available default gateway IP."
    },
    {
      "id": 33,
      "question": "Which method is used to verify that a public key truly belongs to a domain owner, preventing forged certificates?",
      "options": [
        "802.1X EAP",
        "Public Key Infrastructure with certificates signed by a trusted CA",
        "WPA2 Enterprise passphrase",
        "SNMPv2c community string"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is port-based NAC, Option B (correct) PKI uses CA-signed certificates, Option C is a wireless passphrase, Option D is old SNMP auth. Trusted CAs sign domain certificates to prove authenticity.",
      "examTip": "A PKI with recognized CAs ensures a domain’s public key is validated, preventing impersonation or man-in-the-middle."
    },
    {
      "id": 34,
      "question": "Which VLAN assignment approach automatically places a VoIP phone’s traffic on a tagged VLAN, while untagged traffic from the phone’s PC port is on a different VLAN?",
      "options": [
        "ARP inspection",
        "Voice VLAN (auxiliary VLAN) configuration",
        "Trunk negotiation with dynamic auto",
        "DHCP snooping on the voice interface"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is layer 2 security, Option B (correct) sets a special voice VLAN for IP phone traffic, Option C is trunk negotiation, Option D is DHCP security. The voice VLAN feature ensures phone traffic is tagged while the PC’s traffic remains untagged on the data VLAN.",
      "examTip": "Many switches support a dedicated 'voice VLAN' to separate phone traffic from data, simplifying QoS and security."
    },
    {
      "id": 35,
      "question": "A company wants a secure alternative to Telnet for router management. Which protocol is BEST suited?",
      "options": [
        "RDP",
        "SSH",
        "FTP",
        "SNMPv1"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is a graphical remote desktop, Option B (correct) is an encrypted CLI method, Option C is file transfer, Option D is unencrypted management. SSH is the secure replacement for Telnet.",
      "examTip": "Always use SSH for secure device management at layer 7, rather than Telnet’s plaintext transmissions."
    },
    {
      "id": 36,
      "question": "Which  step is recommended if a trunk port is inadvertently formed with a user device that supports DTP?",
      "options": [
        "Use EtherChannel on that port",
        "Assign a static IP to the end device",
        "Disable DTP by setting the port mode to access or trunk non-negotiable",
        "Implement half-duplex to block trunk formation"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A aggregates multiple physical links, not relevant. Option B is addressing, Option C (correct) prevents automatic trunking, Option D is a link mismatch, not stopping trunk formation. Hard-coding trunk or access mode and disabling DTP stops unintended trunk negotiation.",
      "examTip": "Disable or limit DTP to avoid unauthorized trunk formation, which can lead to VLAN hopping or other security issues."
    },
    {
      "id": 37,
      "question": "Which EAP method requires both server and client certificates for mutual authentication in a wireless 802.1X environment?",
      "options": [
        "PEAP",
        "EAP-TTLS",
        "EAP-TLS",
        "LEAP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A uses a server cert but not necessarily client cert, Option B also typically only needs server cert, Option C (correct) requires certificates on both ends, Option D is old Cisco approach with known weaknesses. EAP-TLS is mutual certificate-based authentication.",
      "examTip": "EAP-TLS is robust but requires a PKI for both server and client certificates, ensuring highest security."
    },
    {
      "id": 38,
      "question": "A router sees large packets being dropped unless fragmentation is allowed. Which concept ensures the source adjusts packet size upon receiving ICMP ‘Fragmentation Needed’ messages?",
      "options": [
        "Inverse ARP",
        "Session Initiation Protocol",
        "Path MTU Discovery",
        "802.1w Rapid STP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is a Frame Relay technique, Option B is for VoIP session control, Option C (correct) dynamically detects the smallest MTU along a path, Option D is STP variant. PMTUD avoids fragmentation by discovering the bottleneck MTU and adjusting packet sizes.",
      "examTip": "Path MTU Discovery attempts to send large packets and reacts to 'Frag Needed' ICMP messages, preventing fragmentation."
    },
    {
      "id": 39,
      "question": "Which design principle is used in a spine-leaf data center topology?",
      "options": [
        "All leaf switches connect to every spine switch for consistent east-west performance",
        "Half-duplex is enforced on spine links",
        "A single switch acts as root for all VLANs",
        "Spines handle only layer 2 bridging"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) is the hallmark of spine-leaf. Option B is a performance degrade, Option C is STP root concept, Option D spines often do layer 3 or bridging but the key is full connectivity. Spine-leaf ensures minimal hop east-west traffic in large data centers.",
      "examTip": "Spine-leaf topologies reduce latency by having each leaf connect to all spines, ensuring uniform path lengths."
    },
    {
      "id": 40,
      "question": "Which  is BEST resolved by configuring LACP EtherChannel on adjacent switches?",
      "options": [
        " block a rogue AP from associating to the LAN",
        " provide greater bandwidth and redundancy across multiple physical links",
        " reduce multicast traffic in a VLAN",
        " authenticate user devices at the switch port"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A references wireless security, Option B (correct) link aggregation bundles parallel cables into one logical interface, Option C is IGMP snooping, Option D is NAC. LACP merges links for higher throughput and failover.",
      "examTip": "EtherChannel (LACP) is typically used to combine multiple Ethernet links between switches or switch-server for speed and redundancy."
    },
    {
      "id": 41,
      "question": "A high-availability design uses HSRP. Which statement about the virtual IP is correct?",
      "options": [
        "It must be assigned to the active router’s interface as a secondary IP",
        "It is negotiated dynamically via DHCP",
        "It is shared by all HSRP routers, providing a default gateway address",
        "It changes MAC addresses randomly"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is not how HSRP handles IP assignment, Option B is manual config, Option C (correct) multiple routers present the same virtual IP. Option D is not typical. HSRP ensures hosts keep the same gateway IP even if the active router changes.",
      "examTip": "HSRP/VRRP present a single virtual IP, letting LAN devices use one gateway IP while multiple routers back each other up."
    },
    {
      "id": 42,
      "question": "Which phenomenon describes forging or overriding entries in a switch’s CAM table by sending many bogus MAC addresses until legitimate entries are lost?",
      "options": [
        "ARP poisoning",
        "MAC flooding",
        "Double-tagging VLAN hopping",
        "Spanning tree root bridging"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A manipulates IP-to-MAC mapping at hosts, Option B (correct) overloads the switch’s MAC table, Option C is a VLAN hopping trick, Option D references STP. MAC flooding can degrade a switch into hub-like behavior.",
      "examTip": "MAC flooding is mitigated by port security, limiting the number of MAC addresses learned on a port."
    },
    {
      "id": 43,
      "question": "A user behind an enterprise firewall attempts to host a game server on port 50000. Which inbound firewall setting is typically needed for external clients to reach it?",
      "options": [
        "NAT port forwarding to that user’s private IP and port",
        "802.1X EAP bridging on the user’s VLAN",
        "Spanning tree root guard on user ports",
        "DHCP reservation for the user’s MAC"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) external requests must be forwarded to the internal host, Option B is NAC, Option C is STP security, Option D ensures consistent IP but doesn’t open inbound traffic. Port forwarding (NAT) is needed for inbound connections to a private host.",
      "examTip": "When hosting internal servers accessible externally, configure NAT or port mapping so requests on a public port map to the private IP."
    },
    {
      "id": 44,
      "question": "Which solution can provide real-time analytics and anomaly detection by gathering logs from multiple firewalls and servers in one place?",
      "options": [
        "TDR (Time Domain Reflectometer)",
        "SIEM platform",
        "Speed test server",
        "ARP inspection table"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is a cable testing tool, Option B (correct) collects/correlates logs, Option C measures throughput, Option D is a security measure for ARP. A SIEM aggregates logs from various devices to detect suspicious patterns in real time.",
      "examTip": "Security Information and Event Management (SIEM) unifies logs and uses correlation engines to spot threats quickly."
    },
    {
      "id": 45,
      "question": "Which  measure can isolate IoT devices in a dedicated network, preventing lateral movement to corporate PCs?",
      "options": [
        "Use port mirroring for all IoT switch ports",
        "Assign IoT devices to a separate VLAN and apply ACL restrictions",
        "Reduce the DHCP lease time to 2 hours",
        "Disable spanning tree on IoT ports"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is monitoring, Option B (correct) is typical segmentation. Option C is IP lease management, Option D is loop prevention. Placing IoT devices on an isolated VLAN plus ACLs ensures minimal lateral movement if compromised.",
      "examTip": "Segment IoT or untrusted devices away from sensitive networks. VLAN separation + ACLs is a standard approach."
    },
    {
      "id": 46,
      "question": "A site complains about frequent reconvergence in EIGRP. Logs show repeated SIA (Stuck in Active) queries. What is the FIRST step to investigate?",
      "options": [
        "Ensure all routes have a default gateway of 0.0.0.0",
        "Check for high latency or broken neighbor adjacencies preventing query replies",
        "Turn off RSTP across the core switches",
        "Change the DHCP server to a different subnet"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is a default route approach, Option B (correct) SIA often indicates neighbor timeouts or slow links, Option C is loop prevention, Option D is IP management. EIGRP SIA queries happen when queries aren’t answered in time, often due to a neighbor or path issue.",
      "examTip": "When EIGRP routers get stuck in active, it’s often a neighbor that fails to reply, possibly due to a link or CPU resource problem."
    },
    {
      "id": 47,
      "question": "Which  measure mitigates VLAN hopping by manipulating the native VLAN to insert double tags?",
      "options": [
        "Use ACLs to filter IP addresses",
        "Forbid VLAN 1 as native on trunk ports and disable auto-trunk negotiation",
        "Change the DHCP scope to /25",
        "Assign public IP addresses to all trunk links"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is higher-layer filtering, Option B (correct) setting a distinct native VLAN and static trunk mode blocks double-tag exploit, Option C is subnet size, Option D is addressing, not relevant. Using a non-default native VLAN is a best practice to hinder double-tagging attacks.",
      "examTip": "Double-tag VLAN hopping relies on VLAN 1 as native. Always define a separate native VLAN and disable DTP."
    },
    {
      "id": 48,
      "question": "A large enterprise wants to implement zero trust. Which principle is core to that architecture?",
      "options": [
        "Automatic trust for internal IP addresses",
        "Segment everything and require continuous verification of user and device identity",
        "Simplify NAC by disabling posture checks",
        "Use broadcast-based authentication for faster logins"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is the opposite, Option B (correct) zero trust micro-segmentation, continuous re-auth, Option C is reducing security, Option D is not a standard. Zero trust demands minimal inherent trust, verifying each access attempt with strong controls.",
      "examTip": "'Never trust, always verify'—zero trust emphasizes segmentation, strong identity, and real-time posture checks."
    },
    {
      "id": 49,
      "question": "Which solution is MOST appropriate for ephemeral data transport if you need to measure actual available throughput end to end?",
      "options": [
        "Nmap scanning for open ports",
        "iperf throughput testing",
        "Syslog server correlation",
        "DHCP snooping counters"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is a port scanner, Option B (correct) actively tests network bandwidth, Option C aggregates logs, Option D is DHCP security. iperf or similar tools generate and measure traffic to gauge throughput between endpoints.",
      "examTip": "iperf creates test streams to measure bandwidth, latency, and jitter between two endpoints."
    },
    {
      "id": 50,
      "question": "A user sees slow response from an internal web app. Pinging by IP works fine, but HTTP requests stall. Which FIRST step is logical?",
      "options": [
        "Disable Telnet on the core router",
        "Capture packets (port mirroring) to see the HTTP handshake",
        "Convert the user VLAN to half-duplex",
        "Set static DNS servers on the user machine"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is a management security step, not a  fix. Option B (correct) analyzing the handshake clarifies if the server is responding or if requests fail. Option C cripples performance, Option D is a guess. Packet capture quickly shows if SYNs get replies or if DNS is failing, etc.",
      "examTip": "When IP pings are okay but an app fails, a packet capture can reveal handshake or layer 7 issues (reset, timeouts)."
    },
    {
      "id": 51,
      "question": "A router is set to redistribute EIGRP routes into OSPF with a specific metric. Which OSPF LSA type typically represents these external networks in the OSPF domain?",
      "options": [
        "Type 1 LSA",
        "Type 2 LSA",
        "Type 5 LSA",
        "Type 7 LSA"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A describes router LSAs, Option B describes network LSAs for multi-access, Option C (correct) external LSAs, Option D is for NSSA external routes. Normal areas use Type 5 LSAs for external routes from an ASBR.",
      "examTip": "External routes in standard OSPF areas are advertised as Type 5 LSAs from the ASBR."
    },
    {
      "id": 52,
      "question": "During a trunk configuration, an engineer sees 'Native VLAN mismatch' warnings. Which  step resolves this?",
      "options": [
        "Ensure both sides of the trunk use the same native VLAN ID",
        "Disable CDP globally",
        "Enable half-duplex on both ends",
        "Assign all traffic to VLAN 1 exclusively"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) matching native VLAN across both trunk sides avoids mismatch errors, Option B is discovery protocol, not trunk config, Option C is a link setting, Option D lumps all traffic into VLAN 1, not recommended. The native VLAN must match or traffic can be mis-tagged.",
      "examTip": "To avoid trunk mismatch errors, set the same native VLAN ID on each end or use a dedicated VLAN other than 1."
    },
    {
      "id": 53,
      "question": "A site uses an MPLS WAN for voice and data. How does MPLS help QoS for voice calls?",
      "options": [
        "By encrypting voice traffic at layer 2",
        "By establishing label-switched paths with priority handling",
        "By forcing half-duplex on the phone ports",
        "By performing DNS resolution for each call"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is not inherent in MPLS, Option B (correct) labels can tag traffic for expedited forwarding, Option C is link setting, Option D is name resolution. MPLS can implement traffic engineering for guaranteed voice QoS.",
      "examTip": "MPLS TE can honor QoS policies, ensuring voice gets priority along a label-switched path with guaranteed bandwidth."
    },
    {
      "id": 54,
      "question": "Which  measure can block unknown devices on the wired LAN by requiring 802.1X authentication at each port?",
      "options": [
        "Configure a single SSID for guests",
        "Implement NAC with EAP on all access switches",
        "Use half-duplex on user ports",
        "Map each device MAC in DNS"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A references wireless guest, Option B (correct) 802.1X NAC ensures only authenticated devices pass traffic, Option C is a layer mismatch, Option D is name resolution. NAC with 802.1X is the standard for port-based access control.",
      "examTip": "802.1X forces each endpoint to authenticate (often via RADIUS) before granting network access."
    },
    {
      "id": 55,
      "question": "A trunk link is dropping some VLAN traffic. Which FIRST command is recommended on Cisco to confirm which VLANs are allowed on that trunk?",
      "options": [
        "show vlan brief",
        "show mac address-table",
        "show interface trunk",
        "show running-config trunk"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A shows VLAN membership but not trunk allow-lists, Option B is MAC table, Option C (correct) displays trunk details including allowed VLANs, Option D might vary. 'show interface trunk' is the canonical command to see trunk configuration on each interface.",
      "examTip": "If VLAN traffic is missing across a trunk, verify if the VLAN is included in the trunk’s allowed VLAN list."
    },
    {
      "id": 56,
      "question": "Which DNS record type is used to identify an email server for a given domain?",
      "options": [
        "TXT",
        "MX",
        "CNAME",
        "NS"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is free-form text, Option B (correct) mail exchange record, Option C is an alias, Option D indicates a nameserver. MX records designate mail servers responsible for a domain.",
      "examTip": "Mail Exchange (MX) records route email to the correct server. Ensure priority values are correct if multiple MXs exist."
    },
    {
      "id": 57,
      "question": "A network admin must regularly track changes in router configuration for auditing. Which method ensures every config edit is tied to a specific user?",
      "options": [
        "Use local user 'admin' with the same password for all staff",
        "Enable RADIUS or TACACS+ AAA command accounting",
        "Disable logging to reduce overhead",
        "Assign a static IP to each router interface"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A cannot differentiate individuals, Option B (correct) logs each command with the authenticated username, Option C removes auditing, Option D addresses IP but not user accountability. AAA command accounting is the standard for tracking changes.",
      "examTip": "Centralized AAA solutions like TACACS+ can record each CLI command with the executing user, crucial for audits."
    },
    {
      "id": 58,
      "question": "Which advanced feature is commonly used in BGP to attach metadata (like route origin or traffic policies) that can be matched or filtered downstream?",
      "options": [
        "EIGRP K-values",
        "RIP route tags",
        "BGP communities",
        "NAT overload"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is EIGRP metric components, Option B is a different protocol approach, Option C (correct) BGP communities let operators group routes for policy. Option D is NAT. BGP communities are labels appended to routes for flexible policy application.",
      "examTip": "BGP communities let you apply attributes or filtering rules to grouped routes, e.g., 'no-export', 'local-AS', etc."
    },
    {
      "id": 59,
      "question": "Which approach drastically limits the spread of a virus from one user subnet to another if the perimeter firewall is not aware of internal subnets?",
      "options": [
        "Implement NAC posture checks on the internet router",
        "Use 802.1Q trunking for all PCs",
        "Enforce VLAN-based segmentation with inter-VLAN ACL rules",
        "Configure half-duplex on each user port"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is external NAC, not inside. Option B lumps them on a single broadcast domain if no ACL. Option C (correct) blocks cross-subnet traffic at layer 3. Option D is performance degrade. Internal segmentation is crucial so a virus in one subnet cannot easily jump to others.",
      "examTip": "Use internal firewalls or ACLs on layer 3 boundaries to limit lateral threat movement among subnets."
    },
    {
      "id": 60,
      "question": "Which configuration ensures a router uses OSPF to share route info with neighbors, but does not forward OSPF updates out to the internet interface?",
      "options": [
        "Set OSPF network type to 'passive' on the internet-facing interface",
        "Disable NAT on the internet interface",
        "Set half-duplex on the WAN link",
        "Configure RSTP on the router"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) OSPF passive interfaces do not send hello packets, Option B is unrelated to OSPF adjacency, Option C is a link mismatch, Option D is loop prevention. Passive interface stops advertisement on that interface while still advertising subnets into OSPF.",
      "examTip": "In OSPF, 'passive-interface' prevents sending updates on an interface but still includes its network in the routing domain."
    },
    {
      "id": 61,
      "question": "A user is assigned an IP in 169.254.x.x range. Which statement is TRUE?",
      "options": [
        "They have a valid DHCP lease from the server",
        "APIPA address is used when DHCP fails to provide a lease",
        "This indicates the user VLAN is trunked incorrectly",
        "The router is performing NAT overload"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is false, Option B (correct) 169.254.x.x is Automatic Private IP Addressing fallback, Option C is trunk config, Option D is NAT. APIPA means the device’s DHCP requests went unanswered.",
      "examTip": "Windows automatically assigns 169.254.x.x if it cannot contact a DHCP server, offering link-local connectivity only."
    },
    {
      "id": 62,
      "question": "Which statement is MOST accurate about SIP (Session Initiation Protocol) in VoIP?",
      "options": [
        "It handles real-time transport of voice data",
        "It sets up, modifies, and tears down VoIP calls but uses RTP for actual audio",
        "It encrypts all voice packets by default",
        "It only runs over TCP port 23"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is more about RTP, Option B (correct) SIP is call control, RTP is media transport, Option C requires TLS or SRTP, not by default, Option D is Telnet port. SIP commonly uses TCP/UDP 5060 or TLS 5061 and relies on RTP for audio streams.",
      "examTip": "SIP is a signaling protocol for VoIP; actual voice data flows via RTP or SRTP after call setup."
    },
    {
      "id": 63,
      "question": "Which best practice helps prevent brute-forcing of WPA2-PSK networks from captured 4-way handshakes?",
      "options": [
        "Use a very long, random passphrase",
        "Disable STP on APs",
        "Set half-duplex mode for wireless interfaces",
        "Assign a static IP to each wireless client"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) a strong passphrase is the only real defense. Option B is loop prevention, Option C is a link setting, Option D is IP config. WPA2-PSK relies on passphrase complexity to thwart offline dictionary attacks.",
      "examTip": "A robust passphrase (long, random) significantly reduces the risk of offline WPA2 cracking from captured handshakes."
    },
    {
      "id": 64,
      "question": "Which next-generation firewall feature identifies a flow as 'Dropbox' or 'Skype' even if it uses TCP port 443?",
      "options": [
        "DNS proxy caching",
        "Application-layer signature inspection (DPI)",
        "PoE injection",
        "MAC flooding detection"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is domain caching, Option B (correct) deep packet inspection at layer 7, Option C is power over Ethernet, Option D is L2 security. DPI can see beyond common ports to recognize specific applications or protocols.",
      "examTip": "App-aware firewalls examine payload signatures to identify the true application, circumventing simple port-based classification."
    },
    {
      "id": 65,
      "question": "A trunk link is failing to pass VLAN 99. Which is the FIRST command to see if VLAN 99 is active and assigned on the switch?",
      "options": [
        "show ip interface brief",
        "show vlan brief",
        "show interface trunk detail",
        "show mac address-table vlan 99"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A shows IP states, Option B (correct) displays VLAN existence and port membership, Option C is trunk-level info, Option D is MAC layer for that VLAN. Checking 'show vlan brief' ensures VLAN 99 is created and not pruned.",
      "examTip": "Before checking trunk settings, confirm the VLAN actually exists and is active in the VLAN database."
    },
    {
      "id": 66,
      "question": "Which approach can unify network functions like firewall, IPS, and VPN into a single on-premises appliance for a smaller branch?",
      "options": [
        "STP in root guard mode",
        "UTM (Unified Threat Management) device",
        "EtherChannel trunking",
        "Split tunneling"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is loop prevention, Option B (correct) merges multiple security features, Option C is link aggregation, Option D is VPN design. UTM boxes commonly bundle firewall, AV, IDS/IPS, VPN, etc., for SMB or branch deployments.",
      "examTip": "Unified Threat Management devices offer an all-in-one security solution, convenient for smaller sites."
    },
    {
      "id": 67,
      "question": "Which concept indicates storing partial data replicas at the network edge to reduce latency for frequently accessed content?",
      "options": [
        "STP extended system ID",
        "CDN caching",
        "802.1X EAP chaining",
        "OSPF stub area"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is a bridging detail, Option B (correct) content delivery networks push static data closer to end users, Option C is advanced NAC, Option D is an OSPF design. CDNs reduce round-trip times by caching content in edge servers.",
      "examTip": "CDNs replicate content in geographically distributed nodes, improving performance for users accessing the same data."
    },
    {
      "id": 68,
      "question": "Which factor is MOST critical in planning a large Wi-Fi 6/6E deployment for a stadium environment?",
      "options": [
        "Ensuring each AP uses the same channel for mesh",
        "Implementing band steering to push capable devices to 5/6 GHz",
        "Using WEP encryption to maximize speed",
        "Assigning static IPs to all devices"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A leads to co-channel interference, Option B (correct) channel capacity is better in 5/6 GHz, Option C is insecure, Option D is burdensome. In high-density scenarios, band steering to 5/6 GHz is critical for throughput and reduced interference.",
      "examTip": "High-density venues often steer clients to higher-frequency bands with more bandwidth and less congestion."
    },
    {
      "id": 69,
      "question": "Which  measure stops a newly connected switch from claiming STP root on an edge port?",
      "options": [
        "Enable IP helper address on that port",
        "Configure root guard so superior BPDUs put the port in root-inconsistent state",
        "Set auto-MDIX to off",
        "Use half-duplex for trunk ports"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is for DHCP relay, Option B (correct) root guard blocks unexpected root role attempts, Option C is cable detection, Option D is a link mismatch. Root guard ensures the existing root remains authoritative.",
      "examTip": "Root guard on edge or distribution-facing ports ensures no device can send superior BPDUs to become root."
    },
    {
      "id": 70,
      "question": "A site expects sub-second failover if the primary router fails. Which high availability solution meets this goal by enabling both routers to handle traffic simultaneously?",
      "options": [
        "VRRP in active-passive mode",
        "HSRP with one active gateway",
        "Active-active clustering or GLBP",
        "STP enabling half-duplex"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A uses one master router, Option B is also an active-standby. Option C (correct) GLBP or active-active clustering can load-balance. Option D is loop prevention, not relevant. GLBP can share the virtual gateway load among multiple routers simultaneously.",
      "examTip": "GLBP allows multiple routers to actively serve as default gateways, providing redundancy and load-balancing."
    },
    {
      "id": 71,
      "question": "Which factor can cause a router to ignore an advertised default route in OSPF, preferring a static default route instead?",
      "options": [
        "OSPF's default-information originate set to passive",
        "Administrative distance of the static route being lower than OSPF",
        "Mismatched BGP local preference",
        "Using 802.1w for STP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is not standard, Option B (correct) static route typically has AD=1, OSPF=110. Option C is BGP attribute, not OSPF. Option D is bridging, not routing. A lower AD route overrides a learned OSPF default route.",
      "examTip": "If you have a static default route (AD=1) and OSPF (AD=110), the router picks the static route first."
    },
    {
      "id": 72,
      "question": "A remote user must connect to internal resources without installing extra client software. Which approach addresses this scenario?",
      "options": [
        "Client-based IPSec with preshared key",
        "Clientless SSL VPN via a web portal",
        "L2TP over GRE tunnel",
        "RDP bridging on port 389"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A requires an IPSec client, Option B (correct) only needs a browser and credentials, Option C still typically requires a VPN client, Option D is a separate remote desktop approach. Clientless SSL VPN provides a web-based solution.",
      "examTip": "Clientless VPN solutions let users securely connect from a browser without specialized software installed."
    },
    {
      "id": 73,
      "question": "Which advanced firewall feature can terminate TLS tunnels, inspect the decrypted data, and then re-encrypt traffic outbound?",
      "options": [
        "Port address translation",
        "Transparent bridging mode",
        "SSL/TLS interception or proxy",
        "DHCP snooping"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is NAT, Option B is L2 bridging, Option C (correct) inspects encrypted flows, Option D is DHCP security. SSL interception proxies can decrypt, scan data, and then re-encrypt to the server, ensuring deep inspection of HTTPS traffic.",
      "examTip": "SSL interception or 'man-in-the-middle' proxy is controversial but allows a firewall to scan encrypted traffic for threats."
    },
    {
      "id": 74,
      "question": "Which VLAN tagging method is the IEEE standard widely used on Ethernet trunks?",
      "options": [
        "ISL (Inter-Switch Link)",
        "802.1Q",
        "802.1D",
        "VTP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is Cisco proprietary, Option B (correct) is the open standard, Option C is spanning tree, Option D is VLAN trunking protocol for VLAN distribution. 802.1Q is the standard trunking mechanism on modern switches.",
      "examTip": "Most devices use IEEE 802.1Q trunking, encapsulating frames with a 4-byte VLAN tag."
    },
    {
      "id": 75,
      "question": "Which  measure ensures all connected endpoints have mandatory software patches before gaining network access on a wired 802.1X deployment?",
      "options": [
        "Captive portal on the LAN",
        "Spanning tree in root guard mode",
        "NAC posture assessment integrated with 802.1X",
        "MAC filtering for every device"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is typically for guest Wi-Fi, Option B is STP security, Option C (correct) posture checks ensure compliance, Option D is easily bypassed. NAC posture integrated with 802.1X checks endpoint patch level, AV, etc., before allowing full access.",
      "examTip": "NAC posture checks can quarantine or deny devices that fail security criteria, ensuring compliance before production access."
    },
    {
      "id": 76,
      "question": "An admin suspects QoS misconfiguration on a WAN router. Which command on Cisco typically shows if DSCP values or queue stats match traffic flows?",
      "options": [
        "show queueing interface",
        "show policy-map interface",
        "show mac address-table interface",
        "show vlan interface"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is non-standard, Option B (correct) displays policy-map stats, queue counters, DSCP matches, Option C is L2 table, Option D is VLAN membership. 'show policy-map interface' reveals if QoS classification is correct and how many packets match each class.",
      "examTip": "For Cisco QoS (MQC), 'show policy-map interface <if>' displays real-time stats and classification hits."
    },
    {
      "id": 77,
      "question": "Which  is BEST solved by using an IDS in tap mode rather than inline IPS?",
      "options": [
        " block malicious traffic in real time",
        " passively monitor traffic without risking network downtime if the sensor fails",
        " apply NAC posture checks at layer 2",
        " unify logs for a SIEM correlation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is inline IPS. Option B (correct) a tap-based IDS passively observes, no single point of failure. Option C is port-based auth. Option D is log correlation. IDS in tap mode sees all traffic but can’t drop malicious packets actively.",
      "examTip": "Tap-based or SPAN-based IDS is passive. IPS is inline, able to block or modify traffic but can introduce a single failure point."
    },
    {
      "id": 78,
      "question": "A new code release is staged on a router. Which practice ensures you can revert quickly if the new firmware introduces critical bugs?",
      "options": [
        "Test the theory by disabling DHCP",
        "Save the old firmware image and config in backup, ready to reflash",
        "Use a single switch for the entire LAN",
        "Configure half-duplex to reduce overhead"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is not relevant, Option B (correct) keep a backup image to restore quickly, Option C is a design risk, Option D is performance degrade. Retaining old images and config backups is standard for quick rollback if an upgrade fails.",
      "examTip": "Always keep a known-good firmware image and config to roll back swiftly if new code is unstable."
    },
    {
      "id": 79,
      "question": "Which statement accurately describes LACP in an EtherChannel context?",
      "options": [
        "A Cisco-proprietary protocol requiring same vendor on both sides",
        "Combines multiple links into one logical interface for bandwidth and redundancy using industry standard",
        "Requires half-duplex to avoid collisions",
        "Only supports trunk ports, not access ports"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is PAgP. Option B (correct) LACP is IEEE 802.3ad standard for link aggregation, Option C is untrue, Option D is not strictly correct; EtherChannel can be used with access ports in some scenarios. LACP bundles multiple Ethernet links.",
      "examTip": "LACP (802.3ad) is an open standard link aggregation method, enabling multi-vendor compatibility for port channeling."
    },
    {
      "id": 80,
      "question": "Which protocol is widely used for streaming voice packets once a SIP call is established?",
      "options": [
        "RTP",
        "SSH",
        "LLDP",
        "SMTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) Real-time Transport Protocol, Option B is secure shell, Option C is device discovery, Option D is email. SIP or H.323 sets up calls, while RTP carries the actual voice or video stream.",
      "examTip": "VoIP typically uses RTP for media after a signaling protocol (SIP, H.323) negotiates session parameters."
    },
    {
      "id": 81,
      "question": "Which solution is used to minimize broadcast domains in large LANs while still allowing flexible IP addressing within each domain, effectively segmenting at layer 3?",
      "options": [
        "802.1Q trunking with DTP dynamic mode",
        "EIGRP stub areas",
        "Routed VLAN interfaces (SVIs) on a Layer 3 switch",
        "ARP poisoning detection"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is trunking, Option B is an EIGRP concept but not about LAN segmentation, Option C (correct) each VLAN has a routed SVI, controlling broadcasts. Option D is a security measure. L3 SVIs break up broadcast domains while preserving logical VLAN structure.",
      "examTip": "A layer 3 switch with SVIs routes between VLANs, limiting broadcast domains for better performance and security."
    },
    {
      "id": 82,
      "question": "An engineer wants to ensure any unauthorized DHCP server on an access port is blocked. Which feature is PRIMARILY designed for this purpose?",
      "options": [
        "Port security sticky MAC",
        "DHCP snooping",
        "BPDU guard",
        "QoS shaping"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is MAC address limiting, Option B (correct) filters DHCP offers from untrusted ports, Option C is spanning tree protection, Option D is traffic priority. DHCP snooping is the standard tool to block rogue DHCP servers.",
      "examTip": "DHCP snooping designates ports as trusted or untrusted for DHCP responses, preventing malicious address assignments."
    },
    {
      "id": 83,
      "question": "Which statement BEST describes the function of a NAC solution integrated with 802.1X?",
      "options": [
        "Devices must physically connect at half-duplex",
        "Switch ports are disabled if STP sees a bridging loop",
        "Endpoints must authenticate and meet security posture before network access",
        "RIP routes are filtered from the WAN edge"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is irrelevant, Option B is spanning tree security, Option C (correct) NAC ensures posture compliance and identity. Option D is a routing scenario. NAC with 802.1X controls access at the port level, verifying user credentials and posture.",
      "examTip": "NAC posture checks combined with 802.1X can ensure endpoints meet security standards before granting LAN access."
    },
    {
      "id": 84,
      "question": "A new trunk interface is not passing traffic for VLAN 50. 'show interface trunk' indicates VLAN 50 is missing from the allowed list. Which command typically fixes this on Cisco IOS?",
      "options": [
        "switchport trunk native vlan 50",
        "switchport trunk allowed vlan add 50",
        "vlan database 50",
        "no switchport mode trunk"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A changes native VLAN, Option B (correct) appends VLAN 50 to the trunk’s allowed VLAN list, Option C references legacy CLI for creating VLAN, Option D removes trunk mode. The 'switchport trunk allowed vlan add 50' command includes VLAN 50 on that trunk.",
      "examTip": "If a VLAN is missing across a trunk, add it explicitly with 'switchport trunk allowed vlan add <vlan>' on both ends."
    },
    {
      "id": 85,
      "question": "A router in EIGRP holds an entry in the active state for a route and never gets a reply from neighbors. Which condition is likely occurring?",
      "options": [
        "A route filter in OSPF is blocking EIGRP updates",
        "A neighbor fails to respond to query, causing stuck in active (SIA)",
        "Auto summary is disabled globally",
        "DHCP snooping prevents ARP replies"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A mixes protocols, Option B (correct) SIA indicates queries are unanswered, Option C is an EIGRP config but not directly SIA cause, Option D is layer 2 security for DHCP. SIA arises when queries go unanswered, possibly due to a neighbor resource or link failure.",
      "examTip": "If EIGRP route goes active, it queries neighbors. If none respond, it’s stuck in active (SIA). Investigate neighbor adjacency or link issues."
    },
    {
      "id": 86,
      "question": "A firewall must allow TFTP inbound from the DMZ to a server. Which port is necessary?",
      "options": [
        "20",
        "21",
        "69",
        "443"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is FTP data, Option B is FTP control, Option C (correct) TFTP default UDP port, Option D is HTTPS. TFTP uses UDP port 69 for file transfers.",
      "examTip": "Trivial File Transfer Protocol is lightweight, using UDP/69, with no authentication by default."
    },
    {
      "id": 87,
      "question": "Which advanced BGP feature can apply route policies to prefixes based on matching community values, letting an ISP or enterprise shape traffic or filter routes?",
      "options": [
        "Proxy ARP",
        "Community-based route maps",
        "EIGRP stubs",
        "DHCP Relay"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is layer 2 bridging technique, Option B (correct) BGP communities allow route maps to match or set community tags, Option C is EIGRP design, Option D is forwarding DHCP. BGP route-maps referencing communities shape inbound/outbound routing policies.",
      "examTip": "BGP communities are labels on routes that can be matched by route maps to apply policies—like local-preference or acceptance."
    },
    {
      "id": 88,
      "question": "Which AAA protocol is used over TCP and encrypts the entire packet, commonly preferred for network device administration command logging?",
      "options": [
        "RADIUS",
        "TACACS+",
        "SSH",
        "SNMPv3"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A uses UDP, partial encryption, Option B (correct) uses TCP and encrypts the entire payload, Option C is remote CLI, not AAA, Option D is encrypted management but not for AAA command logs. TACACS+ is favored for device admin logging and full-packet encryption.",
      "examTip": "RADIUS focuses on user authentication (UDP), TACACS+ (TCP) encrypts entire session, ideal for device command authorization."
    },
    {
      "id": 89,
      "question": "Which statement accurately describes DHCP Option 82 in large switched environments?",
      "options": [
        "It encrypts DHCP traffic end-to-end",
        "It appends circuit ID and remote ID info to DHCP requests, aiding IP address assignment based on port location",
        "It ensures half-duplex for all DHCP client ports",
        "It prevents static addressing on user PCs"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is not standard, Option B (correct) helps track or route DHCP requests from specific switch ports, Option C is unrelated, Option D is not how DHCP works. Option 82 can insert location data so the DHCP server can assign addresses or track endpoints.",
      "examTip": "DHCP Option 82 (relay info) tags requests with switch/port details, enabling advanced address policies and logging."
    },
    {
      "id": 90,
      "question": "Which  measure can hamper VLAN trunk negotiation attacks by turning off automatic trunk formation on user-facing switch ports?",
      "options": [
        "Disable DTP (dynamic trunking protocol) and set mode access",
        "Use half-duplex for all access ports",
        "Assign a static ARP entry for each port",
        "Enable DHCP snooping on trunk interfaces"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) stops undesired trunk creation, Option B is link mismatch, Option C addresses MAC/IP, Option D is DHCP security, not trunk negotiation. Disabling DTP ensures user ports remain in access mode, preventing VLAN trunk attacks.",
      "examTip": "Best practice: turn off DTP on ports connected to end devices, forcing them as access mode to avoid trunk exploits."
    },
    {
      "id": 91,
      "question": "Which  is BEST solved by using SDN with a central controller managing multiple switches via an API like OpenFlow?",
      "options": [
        " manually assign IP addresses to each endpoint",
        " automatically apply consistent ACL changes across many switches from one interface",
        " apply half-duplex on trunk ports for error reduction",
        " block DHCP offers from rogue servers"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is a static IP approach, Option B (correct) central orchestration is a prime SDN use case, Option C is a link mismatch, Option D is DHCP snooping. SDN centralizes configuration, letting an admin push ACL or policy changes to all devices simultaneously.",
      "examTip": "SDN separates the control plane, letting a controller program network devices via standardized APIs, ideal for large-scale, consistent deployments."
    },
    {
      "id": 92,
      "question": "Which factor is CRITICAL for spanning multiple data centers with layer 2 adjacency, often used for VM mobility?",
      "options": [
        "Syslog server that aggregates logs",
        "VXLAN or similar overlay to encapsulate layer 2 over layer 3",
        "DHCP reservations for each VM",
        "Setting half-duplex on DCI links"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is logging, Option B (correct) overlay solutions (e.g., VXLAN) extend L2 across IP fabrics, Option C is IP assignment, Option D is link mismatch. VXLAN or L2-over-L3 tunnels are standard for cross-site VM mobility or L2 adjacency.",
      "examTip": "DCI (Data Center Interconnect) often uses VXLAN or other encapsulations to preserve VLAN segments across physically separate DCs."
    },
    {
      "id": 93,
      "question": "A next-generation firewall can identify suspicious inbound SSL traffic. To deeply inspect it, which feature is often used?",
      "options": [
        "SSL decryption (man-in-the-middle)",
        "Port security limit of 1 MAC",
        "Half-duplex VLAN trunking",
        "DNSSEC record verification"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) the firewall intercepts SSL, decrypts, inspects, re-encrypts. Option B is layer 2 security, Option C is link mismatch, Option D is domain name security. SSL decryption is sometimes called SSL interception or TLS proxy.",
      "examTip": "To inspect encrypted flows, a firewall must temporarily terminate and re-encrypt SSL traffic, known as a TLS/SSL proxy or interception."
    },
    {
      "id": 94,
      "question": "Which  is BEST solved by implementing IPsec in tunnel mode between two branch routers?",
      "options": [
        " passively monitor traffic for analysis",
        " ensure site-to-site encrypted communication over an untrusted WAN",
        " detect rogue DHCP servers on each LAN",
        " unify VLAN trunking across multiple ISPs"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is a passive sniff, Option B (correct) site-to-site IPsec tunnel secures traffic, Option C is DHCP security, Option D is VLAN extension. IPsec tunnel mode is standard for site-to-site encryption over public networks.",
      "examTip": "IPsec tunnel mode encapsulates entire IP packets, typically used for secure site-to-site VPNs between branch routers."
    },
    {
      "id": 95,
      "question": "Which  advantage does 802.1X multi-domain authentication offer for an IP phone with an attached PC?",
      "options": [
        "It encrypts voice packets at the application layer",
        "It allows the phone and PC to authenticate separately on the same switch port",
        "It sets trunk mode to dynamic auto",
        "It forces half-duplex for voice data"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is not accurate, Option B (correct) phone uses one domain, PC another, Option C is trunk negotiation, Option D is not required. Multi-domain authentication ensures both phone and PC are validated, each in distinct VLAN or policy scope.",
      "examTip": "Multi-domain 802.1X can handle a phone (voice VLAN) and PC (data VLAN) on one port, each with separate credentials."
    },
    {
      "id": 96,
      "question": "A user device is failing 802.1X posture checks. Which typical NAC action occurs if posture is not met?",
      "options": [
        "The device is physically disconnected from power",
        "A triple-tag VLAN hopping occurs",
        "Traffic from that device is placed in a quarantine VLAN or blocked",
        "The device obtains a 169.254.x.x APIPA address automatically"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is not typical NAC behavior, Option B is a VLAN exploit, Option C (correct) NAC typically quarantines or denies, Option D is a fallback when DHCP fails. NAC solutions often isolate non-compliant devices in a restricted VLAN until remediated.",
      "examTip": "NAC posture checks can move failing endpoints to a quarantine VLAN with minimal network access."
    },
    {
      "id": 97,
      "question": "Which  measure can help mitigate ARP spoofing attempts on a switch port?",
      "options": [
        "Enable DTP negotiation",
        "Disable half-duplex mode",
        "Use static IP addresses for all devices",
        "Configure Dynamic ARP Inspection on that VLAN"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Option A fosters trunk formation, Option B is link setting, Option C is a partial approach but not practical, Option D (correct) DAI checks ARP messages against known IP-MAC pairs. This prevents ARP spoofing on the LAN.",
      "examTip": "Dynamic ARP Inspection relies on DHCP snooping or static mappings to confirm authenticity of ARP traffic."
    },
    {
      "id": 98,
      "question": "Which method ensures that OSPF routers in an area only learn a default route for external networks, instead of individual external LSAs?",
      "options": [
        "Area 0 backbone configuration",
        "Stub or totally stubby area design",
        "LSA type 1 advertisement",
        "EIGRP summarization"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is mandatory backbone, Option B (correct) stubs block Type 5 external LSAs, injecting a default route, Option C is router LSA, Option D is an EIGRP concept. Stub or totally stubby areas significantly reduce external route flooding within that area.",
      "examTip": "OSPF stubby areas contain fewer LSAs, often only a default route to external networks, lowering resource usage."
    },
    {
      "id": 99,
      "question": "Which  approach can reduce the effect of half-open TCP connections from a SYN flood?",
      "options": [
        "ARP spoofing detection",
        "DHCP Option 82 insertion",
        "Enabling SYN cookies on the server or firewall",
        "Setting half-duplex on the server NIC"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is ARP-level, Option B is DHCP relay info, Option C (correct) SYN cookies help drop incomplete sessions under load, Option D is a link setting. SYN cookies are a TCP stack feature that mitigate floods by not storing state until the final ACK arrives.",
      "examTip": "SYN cookies allow a server to handle large numbers of SYN requests without storing session states, preventing backlog exhaustion."
    },
    {
      "id": 100,
      "question": "A router connected to a WAN occasionally sees partial adjacency issues with OSPF neighbors when CPU spikes. Which  measure might fix this?",
      "options": [
        "Increasing the OSPF hello/dead timers so the router has more time to respond",
        "Using half-duplex on the WAN link to reduce collisions",
        "Disabling DHCP snooping globally",
        "Setting a default gateway of 0.0.0.0"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) relaxing timers can prevent adjacency drops if the router is momentarily busy, Option B might degrade performance, Option C is for DHCP security, Option D is unrelated. Adjusting OSPF timers sometimes helps routers with high CPU remain stable with neighbors.",
      "examTip": "If a router is intermittently dropping OSPF neighbors under load, increasing hello/dead timers can reduce false adjacency resets."
    }
  ]
});
