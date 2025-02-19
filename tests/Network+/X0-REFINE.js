db.tests.insertOne({
  "category": "nplus",
  "testId": 10,
  "testName": "Network+ Practice Test #10 (Ultra Level)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A network administrator is troubleshooting a complex BGP routing issue between two autonomous systems (AS). They suspect a problem with BGP route propagation. Which of the following BGP path attributes, if misconfigured or manipulated, could cause routes to be improperly filtered or preferred, leading to routing anomalies, and how would you inspect this attribute on a Cisco router?",
      "options": [
        "The NEXT_HOP attribute; you can examine it with show ip bgp, checking how the next-hop addresses are advertised and whether they point to a valid router.",
        "The AS_PATH attribute; inspect it using the show ip bgp command, focusing on unexpected or manipulated AS numbers in the path.",
        "The ORIGIN attribute; verify it with show ip route to see if the route is listed as IGP, EGP, or incomplete, though misconfigurations here usually have a smaller impact.",
        "The LOCAL_PREF attribute; confirm it with show ip protocols or show ip bgp, as it sets internal route preference for routes within the same AS."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The AS_PATH attribute is a fundamental part of BGP. It lists the sequence of autonomous systems (ASes) that a route has traversed.  It's used for loop prevention (a router won't accept a route that already includes its own AS number) and can also be used for routing policy (preferring routes with shorter AS paths).  If the AS_PATH is *manipulated* (e.g., through a BGP hijacking attack or a misconfiguration), it can cause: *Route filtering:*  If a router is configured to filter routes based on the AS_PATH (e.g., rejecting routes that have traversed a specific AS), a manipulated AS_PATH could cause legitimate routes to be rejected. *Incorrect route preference:*  If a router prefers routes with shorter AS paths, a manipulated AS_PATH could cause it to prefer a suboptimal or malicious route. To inspect the AS_PATH on a Cisco router, you use the show ip bgp command. This command displays the BGP routing table, including the AS_PATH for each route. Look for: *Unexpected AS numbers*; *Manipulated AS paths*; *Missing AS numbers*. The NEXT_HOP attribute indicates the next hop IP address, but it's the AS_PATH that's directly related to inter-AS routing anomalies. ORIGIN indicates how the route was learned, and LOCAL_PREF is used for internal BGP (iBGP) preference, not primarily for inter-AS routing.",
      "examTip": "The BGP AS_PATH attribute is crucial for inter-AS routing and loop prevention; inspect it carefully using show ip bgp to detect anomalies."
    },
    {
      "id": 2,
      "question": "You are troubleshooting a complex network issue where some TCP connections are failing intermittently, while others are working fine. Using a protocol analyzer, you observe frequent TCP retransmissions and out-of-order packets for the failing connections. You also notice that the TCP window size advertised by the receiving host is fluctuating dramatically, sometimes dropping to very small values, even zero.  What is the MOST precise term for this condition, what are the potential underlying causes, and how does it impact TCP performance?",
      "options": [
        "Network congestion; caused by too much traffic on the network, affecting performance by increasing latency and packet drops.",
        "Receive window scaling problem; caused by incompatible TCP implementations, limiting throughput in high-bandwidth scenarios.",
        "TCP receive window exhaustion; caused by the receiving host's inability to process incoming data quickly enough (due to CPU overload, memory exhaustion, slow disk I/O, or network interface buffer limitations), leading to buffer filling and advertised window size reduction/zeroing; it severely impacts performance by causing the sender to slow down or stop transmitting.",
        "DNS resolution failure; caused by a misconfigured DNS server, preventing name resolution."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The most precise term is TCP receive window exhaustion.  Here's why: *TCP Retransmissions & Out-of-Order Packets* indicate packet loss or delays. *Extremely small or zero window size advertised by the receiver* is key: it shows the receiver's buffer is full and cannot process data quickly enough. Common causes include CPU overload, memory exhaustion, slow disk I/O, or NIC limitations on the receiving side. This forces the sender to stop or drastically reduce sending, harming throughput and causing intermittent stalls or timeouts.",
      "examTip": "TCP receive window exhaustion is indicated by persistently small or zero advertised windows, reflecting a bottleneck in the receiving host's ability to handle data."
    },
    {
      "id": 3,
      "question": "A network uses the OSPF routing protocol.  A network administrator notices that a particular router is not forming OSPF neighbor adjacencies with any of its directly connected neighbors on a specific multi-access network segment (Ethernet).  The administrator has verified that: IP connectivity between the routers is working (they can ping each other). OSPF is enabled on the interfaces. The interfaces are in the same OSPF area. The OSPF network type is correctly configured as 'broadcast' on all interfaces. Which of the following is the MOST likely cause of the problem, and which command on a Cisco router would help verify this?",
      "options": [
        "The OSPF hello and dead intervals are mismatched; use the show ip ospf interface [interface_name] command to confirm timer settings on each router.",
        "The OSPF router IDs are conflicting; use the show ip ospf command to see if multiple routers share the same ID.",
        "Spanning Tree Protocol (STP) is blocking the ports; use the show spanning-tree command to see port states.",
        "An ACL is blocking OSPF traffic on TCP port 179; use show ip access-lists to verify."
      ],
      "correctAnswerIndex": 0,
      "explanation": "OSPF routers on the same network segment must have matching hello and dead intervals to form neighbor adjacencies. If these intervals are mismatched, no adjacency will form. The show ip ospf interface [interface_name] command displays per-interface OSPF details, including these intervals. While conflicting Router IDs can also cause issues, they typically affect adjacency states in a different way. STP at Layer 2 or an ACL blocking TCP port 179 (used by BGP, not OSPF) are less likely the root cause here.",
      "examTip": "OSPF hello and dead intervals must match on all routers within a broadcast domain for adjacencies to form; show ip ospf interface is key to verifying."
    },
    {
      "id": 4,
      "question": "You are designing a network for a financial institution that requires extremely high availability and fault tolerance.  No single point of failure can be tolerated.  Which of the following design considerations, implemented in combination, would provide the MOST robust solution?",
      "options": [
        "Use a single, powerful router and switch chassis equipped with redundant power supplies to avoid hardware failure.",
        "Implement redundant network devices (routers, switches, firewalls) with automatic failover (HSRP/VRRP, STP/RSTP, etc.), redundant links for diverse paths, replicate data centers in different locations for site resilience, and maintain a comprehensive disaster recovery plan.",
        "Establish only strong passwords and encryption for all network devices, ignoring physical redundancy.",
        "Create dedicated VLANs for each department."
      ],
      "correctAnswerIndex": 1,
      "explanation": "High availability requires redundancy at multiple levels: *Redundant devices* (routers, switches, and firewalls), *redundant links* between them, diverse paths for critical traffic, geographically distributed data centers with real-time replication to protect against site failures, and a well-developed disaster recovery plan. A single device with redundant power is still a single point of failure. Strong passwords or VLAN segmentation are important but do not guarantee full fault tolerance by themselves.",
      "examTip": "High availability must incorporate multilayer redundancy: devices, links, paths, and sites, plus a solid disaster recovery plan."
    },
    {
      "id": 5,
      "question": "A network uses EIGRP as its routing protocol. The network administrator wants to summarize routes advertised to a neighboring router to reduce the size of the routing table on that neighbor. Which command, and in which configuration context, is used to configure route summarization on a Cisco router running EIGRP?",
      "options": [
        "Under router eigrp [as-number], use the summary-address command directly.",
        "On the interface that will send out the summary, use ip summary-address eigrp [as-number] [summary] [mask].",
        "Under router eigrp [as-number], use the auto-summary command for all networks.",
        "On the interface receiving the updates, use ip summary-address eigrp [as-number] 0.0.0.0 0.0.0.0."
      ],
      "correctAnswerIndex": 1,
      "explanation": "EIGRP route summarization is performed on the *interface* that advertises the summarized route. The correct syntax is ip summary-address eigrp [as-number] [summary-address] [subnet-mask], configured under interface configuration mode. The auto-summary command is a legacy feature for classful summarization, generally not recommended now. Summaries must be done on the sending interface, not the receiving one.",
      "examTip": "EIGRP summarization is set under interface config with ip summary-address eigrp [as-number] [summary-address] [mask]."
    },
    {
      "id": 6,
      "question": "A network administrator is troubleshooting a wireless network. Users report intermittent connectivity and slow performance. The administrator suspects interference from other devices operating in the 2.4 GHz band. Which tool would be MOST effective in identifying sources of RF interference in the 2.4 GHz band?",
      "options": [
        "A network protocol analyzer (like Wireshark) that inspects upper-layer traffic.",
        "A toner and probe kit designed to locate copper cable ends.",
        "A spectrum analyzer that displays signal activity across radio frequencies, exposing interference sources like microwaves or cordless phones.",
        "A cable tester that verifies continuity on Ethernet cables."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A spectrum analyzer is specifically designed to measure and display the radio frequency (RF) spectrum, making it ideal for finding interference from non-Wi-Fi sources such as microwave ovens, Bluetooth devices, or other 2.4 GHz emitters. Protocol analyzers, toner/probe kits, and cable testers focus on different layers or physical media.",
      "examTip": "Use a spectrum analyzer to detect RF interference in wireless networks."
    },
    {
      "id": 7,
      "question": "What is 'MAC address flooding', and what is the primary security risk it poses?",
      "options": [
        "A legitimate technique for link aggregation to combine multiple MACs into one trunk for higher bandwidth.",
        "A DoS attack that sends numerous bogus source MAC addresses to a switch, filling its CAM table and forcing it to broadcast traffic on all ports, allowing an attacker to sniff packets not intended for them.",
        "A method for dynamically assigning IP addresses to devices via DHCP.",
        "A process used to prune VLANs from trunk links."
      ],
      "correctAnswerIndex": 1,
      "explanation": "MAC address flooding overwhelms a switch's CAM table with fake MAC addresses. Once the CAM table is full, the switch behaves like a hub, broadcasting frames on all ports. This lets attackers capture traffic they shouldn't see, compromising confidentiality. It's not a legitimate trunking or IP assignment technique.",
      "examTip": "MAC flooding causes a switch to flood traffic, enabling eavesdropping. It's a serious security risk in switched networks."
    },
    {
      "id": 8,
      "question": "A user reports being unable to access a specific internal web server by its hostname (e.g., intranet.example.com). The user *can* ping the server's IP address successfully. Other users *can* access the server by its hostname. What is the MOST likely cause, and what is a specific command-line tool you could use on the affected user's *Windows* machine to investigate *further*?",
      "options": [
        "Physical cabling is faulty; use a cable tester to diagnose.",
        "The default gateway is incorrect; use ipconfig /all to check.",
        "A local DNS cache or hosts file issue on the user's machine; use ipconfig /flushdns to clear the DNS cache and also inspect the hosts file for any incorrect entries.",
        "A server outage; the server itself is powered off and unreachable."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Because the user can ping by IP address, basic network connectivity works, and other users can reach the server by hostname, the likely culprit is local DNS resolution. On Windows, ipconfig /flushdns clears the DNS resolver cache, removing any corrupted or stale entries. You can also check the hosts file for static overrides of the hostname. None of the other issues match the symptom that pings by IP succeed while hostname resolution fails for only one user.",
      "examTip": "When only one user can't resolve a hostname but can ping by IP, suspect local DNS cache or hosts file issues; ipconfig /flushdns is often the first step."
    },
    {
      "id": 9,
      "question": "Which of the following statements BEST describes 'defense in depth' as a network security strategy?",
      "options": [
        "Placing a single, high-capacity firewall at the network perimeter and trusting all traffic inside.",
        "Using a single layer of security based on physical locks on equipment racks.",
        "Implementing multiple, layered security measures (e.g., firewalls, IDS, authentication, encryption, policies, and physical controls) so that if one layer fails, others can still provide protection.",
        "Relying solely on encrypted VPN tunnels for remote access without segmenting the internal network."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Defense in depth is the concept of multiple, overlapping layers of security controls. This approach reduces the probability that the failure or bypass of any single security measure will compromise the entire system. Physical security, perimeter defenses, internal segmentation, strong authentication, regular audits, and security policies all combine to form multiple lines of defense.",
      "examTip": "Defense in depth uses several layers of security so that the failure of any single control doesn't compromise the entire system."
    },
    {
      "id": 10,
      "question": "You are configuring OSPF on a Cisco router that connects to multiple areas. You want to prevent detailed routing information from one area from being advertised into another area, reducing the size of the routing tables and improving routing efficiency. Which type of OSPF area would you configure to achieve this, and what is the key characteristic of that area type?",
      "options": [
        "A standard area; it allows all OSPF LSAs to pass freely.",
        "A stub area; it prohibits external routes (Type 5 LSAs) from entering the area and uses a default route for external destinations.",
        "A totally stubby area; it just blocks LSA flooding overall.",
        "A not-so-stubby area (NSSA); it cannot import external routes at all."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Stub areas do not allow external LSAs (Type 5) from outside the OSPF domain, relying on a default route injected by the ABR. This reduces the routing information within the area. In a totally stubby area, both external and summary LSAs are blocked, while an NSSA allows certain external routes via Type 7 LSAs. Standard areas allow all LSAs.",
      "examTip": "A stub area blocks external LSAs (Type 5) and uses a default route to reduce routing overhead."
    },
    {
      "id": 11,
      "question": "A network is experiencing intermittent connectivity issues.  Packet captures reveal a high number of TCP retransmissions, duplicate ACKs, and out-of-order packets.  Additionally, you observe that the TCP window size advertised by the receiving host is frequently very small, and you see occasional 'TCP ZeroWindow' messages. What is the MOST precise technical term for the condition affecting the receiving host, and what are the likely underlying causes?",
      "options": [
        "TCP receive window exhaustion; the receiver is unable to keep up with incoming data due to CPU, memory, or disk I/O bottlenecks, causing buffer fill and forcing the advertised window to shrink or hit zero.",
        "Network congestion; excessive traffic on the network is causing drops and out-of-order packets.",
        "DNS lookup failure; the receiving host cannot resolve sender domain names.",
        "Link layer collisions on a half-duplex segment, saturating the medium."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A persistently small or zero advertised TCP window indicates that the receiver cannot process data quickly enough. This phenomenon—TCP receive window exhaustion—arises when the host's buffers fill due to resource constraints (CPU, RAM, disk throughput). While congestion can cause out-of-order arrivals, the explicit ZeroWindow condition specifically shows a receiver-side bottleneck.",
      "examTip": "A shrunken or zero TCP window advertisement points to a receiver's inability to process data, known as TCP receive window exhaustion."
    },
    {
      "id": 12,
      "question": "A network administrator is configuring a Cisco router to redistribute routes learned from EIGRP into OSPF. EIGRP is running with autonomous system number 100, and OSPF is running with process ID 1. Which of the following commands, entered in router configuration mode for OSPF, would correctly redistribute EIGRP routes into OSPF, and what is a crucial consideration for EIGRP redistribution?",
      "options": [
        "router ospf 1 \n redistribute eigrp 100",
        "router ospf 1 \n redistribute eigrp 100 subnets metric-type 1",
        "router ospf 1 \n redistribute eigrp 100 metric-type 1",
        "router ospf 1 \n redistribute eigrp 100 subnets"
      ],
      "correctAnswerIndex": 1,
      "explanation": "When redistributing EIGRP routes into OSPF, the subnets keyword is necessary to include subnetted networks. Without subnets, OSPF only redistributes classful networks. The metric-type 1 sets the routes as OSPF type E1, meaning internal cost is added to the external metric. If you omit subnets, some routes might not appear in OSPF. If you omit metric-type 1 or 2, it defaults to E2, which can also be acceptable, but specifying it explicitly is common in certain designs.",
      "examTip": "Use redistribute eigrp [as] subnets in OSPF config to include all EIGRP routes (including subnets), and consider metric-type to control how OSPF treats external routes."
    },
    {
      "id": 13,
      "question": "A network administrator is troubleshooting a wireless network. Users report intermittent connectivity and slow speeds. The administrator suspects interference from other devices operating in the same frequency band.  Which tool is specifically designed to identify and analyze sources of radio frequency (RF) interference?",
      "options": [
        "A cable tester for verifying twisted-pair continuity.",
        "A Wireshark capture for examining TCP headers.",
        "A spectrum analyzer that can visually display the signal activity across a wide range of frequencies.",
        "A toner/probe kit for locating specific cables."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Spectrum analyzers reveal the presence of non-802.11 sources such as microwave ovens, cordless phones, or other wireless devices in the same band. Cable testers, protocol analyzers, and toner probes address physical or data-link issues differently, not RF interference identification.",
      "examTip": "Use a spectrum analyzer to detect and diagnose RF interference on wireless networks."
    },
    {
      "id": 14,
      "question": "A network administrator is configuring a Cisco switch port to prevent a rogue DHCP server from operating. They designate the port as 'untrusted' within DHCP snooping. Which traffic is blocked on that port under this configuration?",
      "options": [
        "All DHCP client and server traffic from that port is blocked entirely.",
        "Only DHCP requests (DISCOVER) are blocked, allowing server responses.",
        "DHCP server responses (OFFER, ACK, NAK) are blocked, while client messages can still pass. This prevents a rogue server from assigning addresses to clients.",
        "All traffic, including non-DHCP packets, is dropped."
      ],
      "correctAnswerIndex": 2,
      "explanation": "DHCP snooping designates ports as either trusted or untrusted. Untrusted ports can forward client requests but not server responses. This stops any DHCP server (legitimate or rogue) on an untrusted port from handing out IP addresses, thus preventing rogue server attacks.",
      "examTip": "In DHCP snooping, untrusted ports drop DHCP server responses but allow client requests, thereby blocking rogue servers."
    },
    {
      "id": 15,
      "question": "You are configuring a Cisco router to act as a DHCP server for the 192.168.1.0/24 network.  You want to ensure that the router itself (192.168.1.1) and addresses 192.168.1.2 through 192.168.1.10 are reserved for static assignments.  Additionally, a specific device with MAC address 00:11:22:33:44:55 should always receive 192.168.1.50.  Which set of commands, entered in global config mode, best accomplishes this?",
      "options": [
        "ip dhcp pool MYPOOL \n network 192.168.1.0 255.255.255.0 \n default-router 192.168.1.1 \n ip dhcp excluded-address 192.168.1.1 192.168.1.10 \n host 192.168.1.50 255.255.255.0 \n client-identifier 0100.1122.3344.55",
        "ip dhcp excluded-address 192.168.1.1 192.168.1.10 \n ip dhcp pool MYPOOL \n network 192.168.1.0 255.255.255.0 \n default-router 192.168.1.1 \n dns-server 8.8.8.8 \n host 192.168.1.50 255.255.255.0 \n client-identifier 0100.1122.3344.55",
        "ip dhcp pool MYPOOL \n network 192.168.1.0 255.255.255.0 \n default-router 192.168.1.1 \n dns-server 8.8.8.8 \n ip dhcp excluded-address 192.168.1.2 192.168.1.10 \n ip dhcp excluded-address 192.168.1.1\n host 192.168.1.50 255.255.255.0 \n client-identifier 0100.1122.3344.55",
        "ip dhcp excluded-address 192.168.1.1 192.168.1.10 \n ip dhcp pool MYPOOL \n network 192.168.1.0 255.255.255.0 \n default-router 192.168.1.1 \n dns-server 8.8.8.8 \n host 192.168.1.50 255.255.255.0 \n client-identifier 0100.1122.3344.55 \n ip dhcp excluded-address 192.168.1.254"
      ],
      "correctAnswerIndex": 2,
      "explanation": "You need to exclude 192.168.1.1 and 192.168.1.2 through 192.168.1.10. You also want a static reservation for MAC 00:11:22:33:44:55 to get 192.168.1.50. The best approach is: 1) ip dhcp excluded-address 192.168.1.1 and 192.168.1.2-192.168.1.10 2) Define the pool with the network, default-router, etc. 3) Use host 192.168.1.50 plus client-identifier for the reserved device. The other options either omit some exclusions or don't specify them correctly.",
      "examTip": "Remember to exclude the router's own IP and any static range before defining the DHCP pool, and use client-identifier for static reservations."
    },
    {
      "id": 16,
      "question": "A network administrator observes that a router running OSPF is not forming an adjacency with a neighboring router. Both routers are directly connected, and IP connectivity between them is confirmed. The administrator suspects a configuration issue. Which of the following commands, executed on the router, would provide the MOST comprehensive information to diagnose the problem, including OSPF interface settings, area membership, neighbor status, and potential misconfigurations?",
      "options": [
        "show ip route ospf",
        "show ip ospf neighbor",
        "show ip ospf interface brief",
        "show ip ospf database",
        "show ip ospf"
      ],
      "correctAnswerIndex": 4,
      "explanation": "While show ip ospf neighbor, show ip ospf interface, or show ip route ospf provide partial insights, show ip ospf is the most comprehensive single command. It summarizes OSPF process settings, including area config, interface details, router IDs, authentication, and neighbor relationships. If there's a mismatch or adjacency problem, it's likely visible here.",
      "examTip": "show ip ospf gives a wide view of the OSPF process configuration, interface states, and neighbor details in one place."
    },
    {
      "id": 17,
      "question": "A network is experiencing intermittent connectivity issues.  A network administrator captures network traffic using a protocol analyzer and observes a large number of TCP retransmissions and out-of-order packets.  Additionally, you see occasional ICMP messages indicating 'Fragmentation Needed and DF set'. What is the MOST likely underlying cause of these symptoms, and what is the BEST solution?",
      "options": [
        "DNS server misconfiguration; correct DNS entries and flush caches.",
        "DHCP scope exhaustion; expand the DHCP scope to support more IP addresses.",
        "An MTU mismatch along the path. The solution is to ensure Path MTU Discovery (PMTUD) is working correctly (allow ICMP 'Fragmentation Needed' messages) or to manually configure a consistent MTU on all relevant interfaces.",
        "A faulty cable; replace the cable and test again."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The ICMP error 'Fragmentation Needed and DF set' typically arises when a router must fragment a packet due to a smaller MTU on the outbound interface, but the packet has its DF bit set, preventing fragmentation. If PMTUD is blocked by firewalls dropping ICMP, senders won't lower their packet size. This leads to retransmissions and out-of-order issues. Ensuring PMTUD is functional or configuring a uniform MTU resolves the mismatch. DNS, DHCP, or a cable wouldn't specifically trigger this ICMP error.",
      "examTip": "ICMP 'Fragmentation Needed and DF set' signals an MTU mismatch; fix it via PMTUD or manual MTU adjustments."
    },
    {
      "id": 18,
      "question": "You are configuring a Cisco router to participate in OSPF routing. You want the router to be part of OSPF area 0. The router has three interfaces: GigabitEthernet0/0 (192.168.1.1/24), GigabitEthernet0/1 (10.0.0.1/24), and Serial0/0/0 (172.16.1.1/30).  Which of the following sets of commands, entered in global configuration mode, will correctly configure OSPF and include *all* of these interfaces in area 0?",
      "options": [
        "router ospf 1\n network 192.168.1.0 255.255.255.0 area 0\n network 10.0.0.0 255.255.255.0 area 0\n network 172.16.1.0 255.255.255.252 area 0",
        "router ospf 1\n network 192.168.1.0 0.0.0.255 area 0\n network 10.0.0.0 0.0.0.255 area 0\n network 172.16.1.0 0.0.0.3 area 0",
        "router ospf 1\n network 0.0.0.0 255.255.255.255 area 0",
        "router ospf 1\n area 0 range 192.168.1.0 255.255.255.0"
      ],
      "correctAnswerIndex": 1,
      "explanation": "OSPF network statements use wildcard masks, not traditional subnet masks. For example, 192.168.1.0/24 is represented as 192.168.1.0 0.0.0.255. The second option precisely covers 192.168.1.0/24, 10.0.0.0/24, and 172.16.1.0/30 with the correct wildcard masks. The other commands either use normal masks (option A), a universal match (option C), or area range (option D), which is for route summarization, not interface inclusion.",
      "examTip": "Use wildcard masks (the inverse of a subnet mask) in OSPF's network statements to include interfaces in a given area."
    },
    {
      "id": 19,
      "question": "A network is experiencing intermittent connectivity issues.  A network administrator captures network traffic with a protocol analyzer and observes a large number of TCP RST packets. What does the presence of numerous TCP RST packets typically indicate, and what are some potential underlying causes?",
      "options": [
        "It signifies normal TCP operation in which connections gracefully close.",
        "It indicates that a DNS server is failing to resolve queries promptly.",
        "It shows that TCP connections are being abruptly terminated. Potential causes include application crashes, firewall or intrusion prevention systems sending resets, network device misconfigurations forcibly closing sessions, or overzealous TCP keepalive settings.",
        "It demonstrates that DHCP is assigning duplicated IP addresses."
      ],
      "correctAnswerIndex": 2,
      "explanation": "TCP RST packets are used to immediately terminate a connection rather than perform a normal FIN-based teardown. Large numbers of resets often result from security appliances blocking traffic, application errors, or misconfigurations. It's not normal graceful closing, not indicative of DNS or DHCP issues specifically, and does not reflect normal operation.",
      "examTip": "A surge of TCP RST packets suggests abrupt session termination, often by firewalls, security devices, or application crashes."
    },
    {
      "id": 20,
      "question": "You are configuring a site-to-site IPsec VPN between two Cisco routers. You have configured the ISAKMP policy (Phase 1) and the IPsec transform set (Phase 2).  However, the VPN tunnel is not establishing. Which of the following commands on the Cisco router would be MOST helpful in troubleshooting the ISAKMP (Phase 1) negotiation process?",
      "options": [
        "show ip route",
        "show crypto isakmp sa",
        "show crypto ipsec sa",
        "debug ip dhcp snooping"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The show crypto isakmp sa command displays the status of IKE (ISAKMP) Phase 1 security associations. If Phase 1 has not completed successfully, Phase 2 (IPsec SAs) won't form. show crypto ipsec sa focuses on Phase 2, and show ip route does not provide VPN negotiation details. DHCP snooping debug is unrelated to IPsec establishment.",
      "examTip": "Use show crypto isakmp sa to verify IKE Phase 1 negotiation status; if Phase 1 fails, Phase 2 cannot succeed."
    },
    {
      "id": 21,
      "question": "A network administrator is designing a wireless network for a large, open office space with many users. They want to maximize throughput and minimize interference. They are using the 5 GHz band. Approximately how many non-overlapping channels are available in the 5 GHz band for use in the United States, and why is using non-overlapping channels important?",
      "options": [
        "There are only 3 non-overlapping channels in 5 GHz; using them ensures minimal co-channel contention.",
        "There are around 25 non-overlapping channels (assuming 20 MHz width and regulatory domain allowances); using non-overlapping channels prevents adjacent access points from interfering with each other, improving overall performance.",
        "There are 11 non-overlapping channels, the same as in 2.4 GHz; using them eliminates broadcast storms.",
        "5 GHz provides an unlimited number of channels, so non-overlapping doesn't matter."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The 5 GHz band in the United States provides more non-overlapping channels than 2.4 GHz. Exact numbers vary based on channel widths (20/40/80/160 MHz) and regulatory constraints, but about 25 separate 20 MHz channels are typically usable. Non-overlapping channels significantly reduce co-channel interference among adjacent APs, boosting throughput and reliability.",
      "examTip": "5 GHz has more non-overlapping channels than 2.4 GHz, critical for high-density deployments to reduce interference."
    },
    {
      "id": 22,
      "question": "What is 'DHCP starvation', and what combination of switch security features can be used to mitigate this type of attack?",
      "options": [
        "A special QoS classification for DHCP traffic; mitigated by rate-limiting DHCP packets.",
        "A tactic that modifies NAT configurations to hog public IP addresses; mitigated by static NAT rules only.",
        "A DoS attack where an attacker floods DHCP requests with spoofed MAC addresses, attempting to exhaust the DHCP server's IP pool; DHCP snooping plus port security can mitigate by limiting bogus server offers and MAC addresses.",
        "A method for encrypting DHCP packets; mitigated by WPA3-Enterprise encryption."
      ],
      "correctAnswerIndex": 2,
      "explanation": "DHCP starvation tries to exhaust the server's address pool by sending repeated DHCPDISCOVER or REQUEST messages using random (spoofed) MAC addresses. This prevents legitimate clients from obtaining leases. Combining DHCP snooping (distinguishing trusted/untrusted ports for DHCP) with port security (limiting the number of MAC addresses on a port) helps block such attacks.",
      "examTip": "DHCP snooping and port security together help prevent attackers from exhausting DHCP scopes with spoofed MACs."
    },
    {
      "id": 23,
      "question": "A network administrator configures a Cisco switch port with the following commands: switchport mode access, switchport port-security, switchport port-security maximum 1, switchport port-security mac-address sticky, switchport port-security violation protect. What is the effect of the violation protect mode in this port security configuration?",
      "options": [
        "Traffic from unknown MAC addresses is silently dropped, without incrementing any violation counters or generating syslog/SNMP traps. The port remains up.",
        "The port is shut down if an unknown MAC address is detected.",
        "The port restricts traffic from unknown MAC addresses and logs the violation count, generating syslog traps.",
        "The port allows any MAC address but logs them for monitoring."
      ],
      "correctAnswerIndex": 0,
      "explanation": "In violation protect mode, a switch quietly discards traffic from unauthorized MAC addresses but does not increment counters or generate notifications. Restrict mode logs and increments counters, while shutdown mode places the port in err-disabled upon a violation.",
      "examTip": "Port security violation protect mode drops unauthorized traffic silently, no logging or counters. Restrict mode adds logging/counters, shutdown mode disables the port."
    },
    {
      "id": 24,
      "question": "You are designing a high-availability network. You have configured HSRP (Hot Standby Router Protocol) on two routers to provide a virtual gateway for the local network.  What is the purpose of the HSRP priority, and how does it affect the election of the active router?",
      "options": [
        "HSRP priority influences load balancing by splitting traffic equally between routers.",
        "HSRP priority determines which router will become the active gateway; the router with the higher priority is active, and if priorities are equal, the router with the higher IP wins.",
        "HSRP priority designates the router ID in OSPF routing tables.",
        "HSRP priority sets the encryption level used for gateway communication."
      ],
      "correctAnswerIndex": 1,
      "explanation": "HSRP provides gateway redundancy by allowing multiple routers to share a virtual IP address. Only one is active at a time. The router with the higher priority becomes active. If priorities tie, the router with the higher interface IP is selected. It's unrelated to load balancing or OSPF IDs or encryption levels.",
      "examTip": "HSRP priority determines which router is the active gateway; higher priority wins."
    },
    {
      "id": 25,
      "question": "A network administrator suspects a problem with OSPF hello packets. Which of the following statements about OSPF hello packets is FALSE?",
      "options": [
        "OSPF hello packets are used for neighbor discovery and adjacency formation on a link.",
        "OSPF hello packets include the router ID, hello/dead intervals, and area ID, among other parameters.",
        "OSPF hello packets must match certain parameters (e.g., area ID, subnet, timers) on both routers for adjacency.",
        "OSPF hello packets are encrypted by default, ensuring confidentiality of routing data."
      ],
      "correctAnswerIndex": 3,
      "explanation": "OSPF hello packets are not encrypted by default. While they may include authentication fields if configured, that typically provides integrity rather than encryption of the entire packet. They do indeed contain parameters like router ID, timers, and so on, used for adjacency negotiations.",
      "examTip": "OSPF hello packets are not encrypted by default; they handle neighbor discovery and must match critical parameters on each router."
    },
    {
      "id": 26,
      "question": "What is 'BGP route reflection', and in what type of BGP deployment is it typically used to simplify configuration and reduce the number of iBGP sessions?",
      "options": [
        "BGP route reflection is a method for summarizing routes at the AS boundary.",
        "BGP route reflection is used in external BGP scenarios to prioritize certain AS paths.",
        "BGP route reflection is used in large internal BGP (iBGP) setups to avoid a full mesh. A route reflector can re-advertise (reflect) routes between iBGP peers, simplifying configuration.",
        "BGP route reflection is a trick for rewriting next-hop attributes on inbound routes."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Without route reflection, iBGP requires every router to peer with every other iBGP router (a full mesh). Route reflection designates a route reflector (RR) that re-advertises routes learned from one iBGP peer to other iBGP peers, eliminating the need for a full mesh. Summaries or external prioritization are separate features.",
      "examTip": "BGP route reflection eases the iBGP full-mesh requirement by letting a route reflector handle route advertisements between peers."
    },
    {
      "id": 27,
      "question": "You are configuring a site-to-site IPsec VPN between two Cisco routers. You have configured the ISAKMP policy (Phase 1) and are now configuring the IPsec transform set (Phase 2). Which of the following statements about the IPsec transform set is TRUE?",
      "options": [
        "It defines the encryption/hashing algorithms for ISAKMP Phase 1 negotiation exclusively.",
        "It specifies the security protocols (AH or ESP) plus chosen encryption (AES, 3DES) and hashing (SHA, MD5) for the actual data traffic in Phase 2.",
        "It configures the IP addresses of the remote VPN gateways.",
        "It sets up routing protocols to use inside the VPN."
      ],
      "correctAnswerIndex": 1,
      "explanation": "IPsec Phase 2 involves creating the data security association (SA) used to protect traffic across the tunnel. The IPsec transform set specifies whether you use AH or ESP, and the algorithms for encryption and integrity. ISAKMP Phase 1 is separate, dealing with key exchange and authentication. IP addresses or routing are configured elsewhere.",
      "examTip": "The transform set configures ESP or AH, plus the encryption and hashing used to protect traffic in IPsec Phase 2."
    },
    {
      "id": 28,
      "question": "A network administrator is troubleshooting an issue where a client device is unable to obtain an IP address from a DHCP server. The client is connected to a Cisco switch.  Which of the following commands on the switch would be MOST helpful in determining if the switch is receiving DHCP requests from the client and forwarding them to the DHCP server (assuming the server is on a different subnet and an IP helper address is configured)?",
      "options": [
        "show ip interface brief – checks interface statuses but not DHCP transactions.",
        "show ip dhcp snooping binding – if DHCP snooping is enabled, this displays the current MAC-to-IP bindings the switch has recorded.",
        "show running-config – displays the overall config but not real-time DHCP forwarding details.",
        "show crypto isakmp sa – used for IPsec tunnels, not DHCP."
      ],
      "correctAnswerIndex": 1,
      "explanation": "With DHCP snooping enabled, show ip dhcp snooping binding reveals how the switch records DHCP clients and their IP assignments. If the client's MAC/IP is missing, the switch may not be forwarding or receiving the client's DHCP requests properly. show ip interface brief, show running-config, or show crypto isakmp sa don't directly address DHCP transactions.",
      "examTip": "If DHCP snooping is turned on, show ip dhcp snooping binding is a prime diagnostic command to confirm DHCP allocations seen by the switch."
    },
    {
      "id": 29,
      "question": "A network administrator wants to implement QoS to prioritize voice traffic over data traffic using DSCP markings. Which DSCP value is commonly recommended for Expedited Forwarding (EF) of voice traffic, and what is the characteristic of the EF per-hop behavior (PHB)?",
      "options": [
        "DSCP 0 (Best Effort); offering no special priority for latency-sensitive traffic.",
        "DSCP 46 (EF); providing a low-loss, low-latency, and low-jitter service level that is ideal for voice.",
        "DSCP 10 (AF11); giving assured forwarding with moderate drop preference.",
        "DSCP 26 (AF31); offering partial reliability but not guaranteed minimal latency."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DSCP 46 is typically assigned to voice traffic (Expedited Forwarding), ensuring minimal latency and jitter. It is recognized network-wide to place voice packets in a high-priority queue. AF classes (like AF11, AF31) have different drop preferences but are less strict than EF.",
      "examTip": "Use DSCP EF (value 46) to mark voice traffic, securing top priority and minimal delay in DSCP-aware networks."
    },
    {
      "id": 30,
      "question": "A network uses EIGRP as its routing protocol. The network administrator wants to prevent certain EIGRP routing updates from being sent out a specific interface on a router. They do *not* want to completely disable EIGRP on the interface.  Which of the following commands, and in which configuration context, would achieve this?",
      "options": [
        "Under router eigrp [as-number], use passive-interface [interface-name], preventing outbound updates but allowing inbound learning.",
        "In global config, use no eigrp updates on [interface-name].",
        "In interface config mode, use eigrp stop updates for the specified interface.",
        "Under router eigrp [as-number], use distance eigrp 255 255."
      ],
      "correctAnswerIndex": 0,
      "explanation": "The passive-interface [interface-name] command within the EIGRP configuration (router eigrp [as]) stops EIGRP from sending hello and update packets out that interface while still receiving them if they're forwarded in. This keeps the interface's network in EIGRP but prevents outgoing updates there. The other commands are invalid or unrelated to the desired behavior.",
      "examTip": "Use passive-interface under router eigrp to suppress EIGRP updates on a specific interface without removing its network from EIGRP."
    },
    {
      "id": 31,
      "question": "What is 'route poisoning', and how is it used in conjunction with split horizon to prevent routing loops in distance-vector routing protocols?",
      "options": [
        "Route poisoning is a method for encrypting routing updates.",
        "Route poisoning is a technique where a failed route is advertised with an infinite metric (poison) so that neighbors remove it from their tables. Along with split horizon (not advertising routes back out the same interface they were learned on), it speeds up convergence and avoids loops.",
        "Route poisoning is a method for merging VLAN trunks across routers.",
        "Route poisoning is an alternate name for route summarization in EIGRP."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Distance-vector protocols use route poisoning to set the metric of a lost route to infinity (making it unreachable), then advertise that route to neighbors to purge it from the network quickly. This, paired with split horizon (no re-advertising learned routes on the same interface), helps avoid routing loops. It's not encryption, VLAN trunk merging, or summarization.",
      "examTip": "Route poisoning + split horizon accelerate loop detection in distance-vector protocols by marking bad routes as unreachable and blocking re-advertisements."
    },
    {
      "id": 32,
      "question": "A network administrator suspects that an attacker is attempting a brute-force attack against a server's SSH service. Which of the following log entries, taken from the server's system logs, would provide the STRONGEST evidence of a brute-force attack?",
      "options": [
        "A single SSH login failure followed by an immediate successful login from the same IP.",
        "Numerous DNS lookups for the server's hostname from various IPs.",
        "Repeated failed SSH login attempts in rapid succession, often from multiple source IP addresses, showing an attempt of many username/password combinations.",
        "An ARP table overflow on the local switch."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A brute-force attack typically involves a high volume of failed login attempts in a short time, potentially from multiple IPs. Seeing repeated failed SSH logins with varied credentials strongly indicates a brute-force tool. A single failure or normal DNS lookups or an ARP issue do not necessarily mean brute force.",
      "examTip": "Brute-force attempts manifest as frequent, sequential login failures. Look for unusual volumes of SSH login errors in logs."
    },
    {
      "id": 33,
      "question": "You are designing a network that requires high availability and redundancy for critical servers.  Which of the following technologies, and how they are used together, would provide the MOST robust solution?",
      "options": [
        "A single high-end server with dual power supplies, ignoring network redundancy.",
        "Multiple clustered servers with NIC teaming to multiple switches, those switches in loop-free configurations (RSTP or link aggregation) plus gateway redundancy like HSRP or VRRP, ensuring no single point of failure in servers or network paths.",
        "One strong firewall with advanced intrusion prevention, ignoring internal switch redundancy.",
        "Weekly backups to an external drive connected to the server."
      ],
      "correctAnswerIndex": 1,
      "explanation": "High availability demands redundancy at the server (clustering), network interface (NIC teaming), switch (multiple switches or stacked switches), and gateway levels (HSRP/VRRP). A single device with multiple power supplies or periodic backups doesn't assure continuous uptime if a networking component fails.",
      "examTip": "Redundant servers, NIC teaming, multiple switches, and gateway redundancy provide comprehensive fault tolerance."
    },
    {
      "id": 34,
      "question": "A network administrator is troubleshooting a slow network connection between two computers.  They suspect that packet fragmentation is contributing to the problem. Which command-line tool, and with what specific options, would allow them to test for MTU issues along the path between the two computers?",
      "options": [
        "ping with the -l (size) and -f (Don't Fragment) options on Windows to find the largest MTU-supported packet size without fragmentation.",
        "nslookup to verify domain name resolution accuracy along the path.",
        "tracert with the -pathmtu option to measure the exact path MTU automatically.",
        "ipconfig /all to see the local interface MTU setting only."
      ],
      "correctAnswerIndex": 0,
      "explanation": "On Windows, you use ping [destination] -l [size] -f, where -l specifies packet size and -f sets the DF bit. If a router can’t forward the packet without fragmenting, it returns ICMP 'Fragmentation needed and DF set,' indicating the path MTU limit. nslookup, tracert, and ipconfig don’t provide direct path MTU testing in the same manner.",
      "examTip": "Use ping with DF set and varying sizes to diagnose path MTU issues; observe if you get fragmentation needed errors."
    },
    {
      "id": 35,
      "question": "A network is experiencing intermittent connectivity problems.  A network administrator captures network traffic with a protocol analyzer and observes a large number of TCP RST packets. What does the presence of numerous TCP RST packets typically indicate, and what are some potential underlying causes?",
      "options": [
        "It indicates normal FIN-based TCP teardown between hosts.",
        "It shows multiple DNS timeouts preventing name lookups.",
        "It signifies abrupt TCP connection terminations. Potential reasons include application-layer crashes, firewall/security devices sending resets, or misconfigurations that forcibly close sessions.",
        "It reveals that DHCP requests are exhausting the address pool."
      ],
      "correctAnswerIndex": 2,
      "explanation": "TCP resets differ from normal FIN-based shutdown; they're used to abruptly end connections. Firewalls or IPS devices often send RST to block certain traffic, or application issues can trigger resets if they crash. DNS or DHCP issues do not directly cause RST storms.",
      "examTip": "Repeated TCP RST packets reflect forced connection closures, often from security tools or application failures."
    },
    {
      "id": 36,
      "question": "A network administrator wants to prevent rogue DHCP servers from operating on a network. They are configuring DHCP snooping on a Cisco switch. They have already enabled DHCP snooping globally. What is the NEXT step they must take to make DHCP snooping effective?",
      "options": [
        "Designate certain switch ports as trusted (connected to legitimate DHCP servers), leaving the rest as untrusted by default.",
        "Enable STP on all ports to block DHCP frames from unauthorized hosts.",
        "Disable DHCP on all user-facing ports so that no device can become a DHCP server.",
        "Configure dynamic ARP inspection globally to block ARP packets from unknown addresses."
      ],
      "correctAnswerIndex": 0,
      "explanation": "After enabling DHCP snooping globally, you must set the legitimate DHCP server ports as 'trusted.' Untrusted ports drop server responses, preventing rogue DHCP servers from handing out IP addresses. The other options (STP, disabling DHCP on ports, or enabling ARP inspection) address different threats or features.",
      "examTip": "DHCP snooping requires configuring trusted ports for real DHCP servers and leaving all other (user) ports untrusted."
    },
    {
      "id": 37,
      "question": "A company has implemented 802.1X authentication on its wired network. A user connects their laptop to a switch port, but they are not prompted for authentication and are not granted network access. The switch port is configured correctly for 802.1X. What is the MOST likely cause of the problem?",
      "options": [
        "There is no RADIUS server defined on the switch.",
        "The user’s laptop lacks or has a disabled 802.1X supplicant, so it never attempts EAP-based authentication.",
        "The switch port is in the wrong VLAN.",
        "Spanning Tree Protocol is blocking the port."
      ],
      "correctAnswerIndex": 1,
      "explanation": "802.1X requires a client supplicant, a network authenticator (the switch), and an authentication server (RADIUS). If the user’s device lacks a supplicant or it’s disabled, no 802.1X handshake occurs. Even if a RADIUS server is defined, the client must initiate EAP. Incorrect VLAN or STP typically won’t prevent a prompt for 802.1X credentials altogether.",
      "examTip": "802.1X authentication on a wired port hinges on having a functioning supplicant on the client. Without it, no authentication occurs."
    },
    {
      "id": 38,
      "question": "What is 'route poisoning', and how does it work in conjunction with 'split horizon' to prevent routing loops in distance-vector routing protocols?",
      "options": [
        "It is a method of encrypting RIP updates to ensure privacy.",
        "It is a dynamic NAT feature used for edge routers.",
        "When a route fails, a router advertises that route with an infinite metric (poison) to neighbors, signaling it’s unusable. Coupled with split horizon (not advertising routes back out the interface they arrived on), it prevents loops and speeds convergence.",
        "It is a high-priority QoS marking that reduces network loops."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Route poisoning sets the metric for a failed route to a maximum (indicating unreachability), then advertises it to neighbors, ensuring they do not continue using it. Split horizon prevents re-advertising routes on the interface they arrived. Together, they reduce the chance of routing loops in distance-vector protocols.",
      "examTip": "Route poisoning plus split horizon is a classic distance-vector mechanism to handle failed routes quickly and prevent loops."
    },
    {
      "id": 39,
      "question": "You are troubleshooting a network where users report intermittent connectivity to a specific server. You suspect an ARP spoofing attack. Which of the following findings, obtained from a protocol analyzer capturing traffic on the affected network segment, would provide the STRONGEST evidence of ARP spoofing?",
      "options": [
        "Multiple DHCPREQUEST messages from the same MAC address in a short period.",
        "Repetitive DNS queries for the same domain name from multiple hosts.",
        "Multiple ARP replies claiming the same IP (e.g., the server's or default gateway's IP) with different source MAC addresses, indicating conflicting ARP mappings.",
        "Frequent TCP RST packets from unknown sources."
      ],
      "correctAnswerIndex": 2,
      "explanation": "ARP spoofing occurs when an attacker forges ARP replies to map a victim’s IP address to the attacker's MAC. Seeing multiple ARP replies for the same IP but from different MACs strongly indicates an ARP poisoning attempt. DHCPREQUEST or DNS queries don’t imply that. Frequent TCP resets do not necessarily tie to ARP spoofing.",
      "examTip": "Conflicting ARP replies for one IP with multiple MAC addresses is a hallmark of ARP spoofing."
    },
    {
      "id": 40,
      "question": "A network administrator is configuring OSPF on a Cisco router. They want to prevent the router from becoming the Designated Router (DR) or Backup Designated Router (BDR) on a specific multi-access network segment (e.g., an Ethernet LAN).  Which command, and in which configuration context, would achieve this?",
      "options": [
        "Under router ospf [process-id]: passive-interface [interface].",
        "Under interface configuration: ip ospf priority 0.",
        "Under router ospf [process-id]: auto-cost reference-bandwidth 100.",
        "Under interface configuration: no ip ospf network broadcast."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Setting ip ospf priority 0 under the interface configuration ensures the router never becomes DR or BDR, regardless of its Router ID or other attributes. passive-interface stops sending hellos entirely, removing adjacency formation. auto-cost reference-bandwidth is about adjusting interface cost, and no ip ospf network broadcast changes the network type, not the DR election priority directly.",
      "examTip": "Use ip ospf priority 0 on a multi-access interface to ensure a router never becomes DR or BDR."
    },
    {
      "id": 41,
      "question": "What is 'BGP hijacking', and what are some of its potential consequences?",
      "options": [
        "A security patch that forcibly updates BGP software to the latest version.",
        "An attacker or misconfiguration that causes a router to advertise BGP routes for IP prefixes it does not own, redirecting traffic to the attacker's network. This can lead to eavesdropping or denial of service on affected ranges.",
        "A method for encrypting all BGP messages with IPsec.",
        "A specialized DHCP technique for distributing default gateways to BGP routers."
      ],
      "correctAnswerIndex": 1,
      "explanation": "BGP hijacking arises when a router improperly advertises routes to prefixes, effectively \"stealing\" them. This can intercept or null-route traffic, causing service disruption, espionage, or malicious rerouting. It's not a patch, IPsec encryption, or DHCP method. BGP relies on trust unless protected by RPKI or other route validation.",
      "examTip": "BGP hijacking disrupts or diverts internet traffic by falsely advertising IP prefixes not legitimately owned."
    },
    {
      "id": 42,
      "question": "A network administrator configures a Cisco router with the following command: ip route 192.168.10.0 255.255.255.0 10.0.0.1 200. What does the value '200' represent in this command, and what is its significance?",
      "options": [
        "It is the OSPF cost assigned to that route, influencing path selection in OSPF.",
        "It is the administrative distance of the static route, making it less preferred if another routing source offers the same network with a lower AD.",
        "It is the TTL to be used on all packets matching 192.168.10.0/24.",
        "It is the EIGRP variance for load balancing."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The last parameter in ip route for Cisco routers is the administrative distance of that static route. By default, static routes have AD=1, so specifying 200 makes it less preferred than typical dynamic protocols like OSPF (AD=110) or EIGRP (AD=90), unless those are absent for that network. TTL, variance, or OSPF cost are unrelated here.",
      "examTip": "The optional final argument in ip route is the route's administrative distance—higher AD means lower preference."
    },
    {
      "id": 43,
      "question": "A network uses OSPF as its routing protocol. The network includes both standard areas and a stub area. What type of OSPF LSAs (Link State Advertisements) are NOT allowed into a stub area by default, and why?",
      "options": [
        "Type 3 (Summary LSAs); to limit all inter-area routes.",
        "Type 5 (External LSAs); blocking external routes from entering the stub area and relying on a default route for those destinations.",
        "Type 1 (Router LSAs); preventing internal router information from flooding the area.",
        "Type 2 (Network LSAs); removing all broadcast network details."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Stub areas prohibit external LSAs (Type 5), which carry routes learned from outside OSPF. Instead, an ABR provides a default route for external destinations. Type 1 and 2 LSAs remain within the area to describe routers and networks. Type 3 summary LSAs from other areas are still allowed unless it’s a totally stubby or NSSA configuration.",
      "examTip": "Stub areas block external LSAs (Type 5) and rely on a default route to reach external networks."
    },
    {
      "id": 44,
      "question": "You are troubleshooting a network connectivity issue where a user is unable to access a web server. You have verified the following: The user's computer has a valid IP address, subnet mask, and default gateway. The user can ping the web server's IP address successfully. `nslookup` resolves the web server's domain name correctly. However, when the user tries to access the web server in a web browser, they receive a 'Connection refused' error. What is the MOST likely cause of this problem?",
      "options": [
        "The web server is not listening on the expected port or is misconfigured, or a firewall is blocking traffic to that port, causing an active refusal of the TCP connection.",
        "The DNS server is failing to resolve the domain name properly.",
        "The user’s cable is physically disconnected, preventing any actual data transmission.",
        "The user’s default gateway is not responding to ICMP pings."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A 'Connection refused' error typically indicates that the server or a firewall actively denies the TCP connection (e.g., no service listening on that port or an ACL blocking it). Because ping and DNS succeed, basic connectivity and name resolution work. The server’s application or a firewall is likely at fault, not the cable or gateway.",
      "examTip": "Connection refused means the remote end or an intermediate firewall is actively rejecting the TCP SYN; the service may be down, misconfigured, or blocked."
    },
    {
      "id": 45,
      "question": "A network administrator wants to configure a Cisco switch to automatically learn the MAC address of the first device connected to a port and add that MAC address to the running configuration as a secure MAC address.  Furthermore, if a device with a different MAC address subsequently connects to that port, the administrator wants the port to be shut down (placed in the error-disabled state). Which of the following sets of commands, starting from interface configuration mode, would achieve this?",
      "options": [
        "switchport mode trunk\nswitchport port-security\nswitchport port-security maximum 2",
        "switchport mode access\nswitchport port-security\nswitchport port-security maximum 1\nswitchport port-security mac-address sticky\nswitchport port-security violation shutdown",
        "switchport mode access\nswitchport port-security violation restrict\nswitchport port-security mac-address sticky",
        "switchport mode trunk\nswitchport port-security mac-address sticky\nswitchport port-security violation protect"
      ],
      "correctAnswerIndex": 1,
      "explanation": "To dynamically lock the port to the first MAC address seen and shut down upon violation: 1) Access port. 2) port-security enabled. 3) maximum 1. 4) mac-address sticky. 5) violation shutdown. This places the port into err-disabled if a new MAC is detected. Restrict or protect modes do not shut the port down.",
      "examTip": "Use sticky MAC with maximum 1 and violation shutdown to enforce a single learned MAC, shutting the port if a mismatch occurs."
    },
    {
      "id": 46,
      "question": "You are configuring a site-to-site IPsec VPN between two Cisco routers. You have already configured the ISAKMP policy (Phase 1).  You are now configuring the IPsec transform set (Phase 2).  You want to use ESP for encryption and authentication, AES-256 for encryption, and SHA-256 for hashing. Which of the following commands, entered in global configuration mode, would correctly create an IPsec transform set named 'TS' with these parameters?",
      "options": [
        "crypto ipsec transform-set TS esp-aes 256 esp-sha-hmac",
        "crypto isakmp policy 10\nencryption aes 256\nhash sha256",
        "crypto ipsec transform-set TS esp-aes 256 esp-sha256-hmac",
        "crypto ipsec transform-set TS ah-sha-hmac"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The command crypto ipsec transform-set TS esp-aes 256 esp-sha256-hmac defines a transform set named TS that uses ESP with AES-256 encryption and SHA-256 hashing. ESP also includes optional authentication. ISAKMP policy config is Phase 1, while AH offers integrity but no encryption. The 'esp-sha-hmac' short name usually refers to SHA-1, not SHA-256.",
      "examTip": "Use esp-aes 256 with esp-sha256-hmac for AES-256 encryption and SHA-256 integrity in the IPsec transform set."
    },
    {
      "id": 47,
      "question": "What is 'BGP hijacking', and what makes it a particularly difficult attack to detect and prevent?",
      "options": [
        "BGP hijacking is when DNS servers are compromised to redirect queries; it’s difficult to detect because DNSSEC is not fully adopted.",
        "BGP hijacking is a method to forcibly reassign IP addresses within a single AS; it’s difficult because NAT configurations are unregulated.",
        "BGP hijacking occurs when a router is compromised or misconfigured to advertise IP prefixes it doesn’t own, redirecting traffic. It’s hard to stop because BGP typically trusts announcements unless RPKI or strict filtering is used, which are not universally deployed.",
        "BGP hijacking is an encryption scheme that modifies BGP paths on the fly; it’s hard to detect due to hidden key exchanges."
      ],
      "correctAnswerIndex": 2,
      "explanation": "BGP has historically relied on trust: routers assume their neighbors advertise correct prefixes. If a malicious or incorrectly configured router announces routes for IPs it doesn’t own, traffic can be diverted. Mechanisms like RPKI exist but are not universal, making hijacking tough to fully prevent or detect globally.",
      "examTip": "BGP hijacking exploits the trust-based nature of BGP, diverting traffic by advertising unauthorized prefixes; widespread route-validation adoption is limited."
    },
    {
      "id": 48,
      "question": "A network administrator configures a Cisco switch port with the following commands: switchport mode access, switchport port-security, switchport port-security maximum 1, switchport port-security mac-address sticky, switchport port-security violation restrict. What is the *specific* effect of the violation restrict mode in this port security configuration?",
      "options": [
        "Traffic from unknown MAC addresses is immediately dropped, no logging occurs, and the port remains operational without incrementing violation counters.",
        "Traffic from unknown MAC addresses is dropped, the violation counter increments, and the switch can send alerts such as SNMP traps or syslog messages, but the port stays up.",
        "The port is shut down and placed in err-disabled upon a violation.",
        "The port allows any MAC address and no security is enforced."
      ],
      "correctAnswerIndex": 1,
      "explanation": "violation restrict means that if a new, unauthorized MAC address appears, traffic from that MAC is dropped and the violation counter increments. The switch can also log or send an SNMP trap. The port does not shut down entirely (that would be shutdown mode), nor does it remain silent about violations (protect mode).",
      "examTip": "Restrict mode logs drops and increments counters; protect mode silently drops; shutdown mode disables the port."
    },
    {
      "id": 49,
      "question": "A network is experiencing intermittent connectivity issues.  A network administrator captures network traffic with a protocol analyzer and observes a large number of TCP retransmissions.  Further analysis reveals that many of the retransmitted packets have the same sequence numbers as previously seen packets, but different payloads (data). What is the MOST likely cause of this behavior?",
      "options": [
        "A typical TCP retransmission scenario with identical data repeated, indicating normal packet loss recovery.",
        "An ARP poisoning attack leading to IP collisions on the local segment.",
        "A man-in-the-middle (MitM) attack actively modifying TCP packet contents, causing mismatched data for the same sequence numbers.",
        "A misconfigured VLAN trunk blocking certain tagged frames."
      ],
      "correctAnswerIndex": 2,
      "explanation": "When a TCP packet is retransmitted, normally the payload remains identical. If the sequence number is the same but the payload differs, it suggests that an attacker or device is intercepting and altering data in transit. This is a strong indication of a MitM attack. ARP poisoning might facilitate MitM, but the direct sign is the changed data for the same sequence.",
      "examTip": "TCP payload changes on the same sequence number strongly imply active data manipulation, a hallmark of MitM attacks."
    },
    {
      "id": 50,
      "question": "A network administrator wants to configure a Cisco router to use NTP (Network Time Protocol) to synchronize its clock with an external time server.  The NTP server's IP address is 192.0.2.1.  Which of the following commands, entered in global configuration mode, would correctly configure the router to use this NTP server?",
      "options": [
        "ntp master 1",
        "ntp server 192.0.2.1",
        "clock set 12:00:00 july 1 2025",
        "clock timezone PST -8"
      ],
      "correctAnswerIndex": 1,
      "explanation": "To have a Cisco router synchronize time with an external NTP server, use ntp server [ip-address]. The ntp master command makes the router act as an NTP source for other devices. The clock set and clock timezone commands only affect local clock display, not NTP synchronization.",
      "examTip": "ntp server [address] configures a Cisco device to use that NTP server for clock synchronization."
    },
    {
      "id": 51,
      "question": "You are troubleshooting a network where some computers can access the internet, while others on the same VLAN and subnet cannot. All computers are configured to obtain IP addresses via DHCP.  You suspect a problem with the default gateway configuration. What is the BEST way to quickly confirm the default gateway IP address being used by a *working* computer and a *non-working* computer on a Windows system, and compare them?",
      "options": [
        "Use the `ping` command on both computers.",
        "Use the `tracert` command on both computers.",
        "Use the `ipconfig /all` command on both computers and compare the 'Default Gateway' entry.",
        "Use the `nslookup` command on both computers."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The `ipconfig /all` command on a Windows computer displays detailed network configuration information, *including the default gateway*. This is the *most direct* and efficient way to check the default gateway setting. By running `ipconfig /all` on *both* a working and a non-working computer, you can quickly compare their default gateway settings and see if there's a discrepancy. `ping` only tests basic connectivity, not configuration. `tracert` shows the route, but it doesn't directly display the *configured* default gateway. `nslookup` is for DNS resolution.",
      "examTip": "Use `ipconfig /all` on Windows to quickly check the default gateway configuration (and other network settings) on a computer."
    },
    {
      "id": 52,
      "question": "A network administrator wants to prevent rogue DHCP servers from operating on a network segment. They are configuring DHCP snooping on a Cisco switch. They have already enabled DHCP snooping globally with the `ip dhcp snooping` command. What is the NEXT ESSENTIAL step they MUST take to make DHCP snooping effective?",
      "options": [
        "Configure all switch ports as access ports.",
        "Configure the switch ports connected to legitimate DHCP servers as *trusted* ports using the `ip dhcp snooping trust` interface command. Leave all other ports as *untrusted* (the default).",
        "Configure all switch ports as trunk ports.",
        "Configure a DHCP relay agent on the switch."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DHCP snooping works by classifying switch ports as *trusted* or *untrusted*: *Trusted ports:*  Ports connected to *legitimate* DHCP servers. The switch allows *all* DHCP traffic (both client requests and server responses) on these ports. *Untrusted ports:* Ports connected to client devices (or potentially to rogue servers). The switch *only* allows DHCP *client* requests (like DHCPDISCOVER, DHCPREQUEST) to be forwarded from these ports. It *drops* any DHCP *server* responses (like DHCPOFFER, DHCPACK, DHCPNAK) received on untrusted ports. After enabling DHCP snooping globally, the administrator *must* explicitly configure the ports connected to legitimate DHCP servers as *trusted* using the `ip dhcp snooping trust` command in *interface configuration mode*. All ports are *untrusted* by default when DHCP snooping is enabled. Configuring all ports as access or trunk ports doesn't directly address rogue DHCP servers. A DHCP relay agent is for forwarding DHCP requests *between subnets*, not for snooping.",
      "examTip": "After enabling DHCP snooping globally, explicitly configure trusted ports (connected to legitimate DHCP servers) using `ip dhcp snooping trust`."
    },
    {
      "id": 53,
      "question": "You are troubleshooting a slow file transfer between two computers on the same local network (same subnet and VLAN).  Pings between the computers show low latency and no packet loss.  Which of the following is the LEAST likely cause of the slow transfer speed?",
      "options": [
        "A duplex mismatch between the network interface cards (NICs) of the two computers or between a computer and the switch.",
        "A faulty network cable connecting one of the computers to the switch.",
        "Resource constraints (CPU, memory, or disk I/O) on either the sending or receiving computer.",
        "A misconfigured DNS server."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Since the computers are on the *same subnet*, routing is *not* involved.  Low latency and no packet loss with `ping` indicate that basic network connectivity is good. This eliminates DNS as a primary cause since DNS is for name resolution and the computers are on the same subnet and thus do not require routing. This makes the other options more likely: *Duplex Mismatch:*  If one device is set to full-duplex and the other to half-duplex (or if auto-negotiation fails), this will cause collisions and drastically reduce performance. *Faulty Cable:* A bad cable can cause packet loss and retransmissions, even if basic connectivity seems to work. *Resource Constraints:*  If either the sending or receiving computer is experiencing high CPU utilization, running out of memory, or has slow disk I/O, this can significantly limit the file transfer speed. The *least likely* is the DNS server, as DNS is for name resolution *before* a connection is established, and wouldn't affect the *speed* of an ongoing file transfer once the connection is made, *especially* within the *same subnet*.",
      "examTip": "For slow file transfers within the same subnet, focus on physical layer issues (cabling, NICs), duplex settings, and resource constraints on the sending/receiving computers."
    },
    {
      "id": 54,
      "question": "A network administrator wants to configure a Cisco router to redistribute routes learned from OSPF into EIGRP.  OSPF is running with process ID 1, and EIGRP is running with autonomous system number 100. Furthermore, they want to ensure that only routes with a specific OSPF tag of 777 are redistributed. Which of the following commands, entered in router configuration mode for EIGRP, would achieve this, and what additional configuration might be necessary?",
      "options": [
        "router eigrp 100 \n redistribute ospf 1",
        "router eigrp 100 \n redistribute ospf 1 match internal",
        "router eigrp 100 \n redistribute ospf 1 route-map OSPF-TO-EIGRP \n ! \n route-map OSPF-TO-EIGRP permit 10 \n match tag 777",
        "router eigrp 100 \n redistribute ospf 1 metric 10000 100 255 1 1500"
      ],
      "correctAnswerIndex": 2,
      "explanation": "To redistribute routes from one protocol to another *and* filter based on a tag, you need a *route map*.  The steps are: 1. **Define a route map.** 2. **Match on the desired tag (777).** 3. **Apply the route map in the `redistribute` command.** For example: \n``` \nrouter eigrp 100 \n  redistribute ospf 1 route-map OSPF-TO-EIGRP \n! \nroute-map OSPF-TO-EIGRP permit 10 \n  match tag 777 \n``` \nYou would also need to have configured the OSPF process to *tag* the desired routes with the value 777. Option A redistributes *all* OSPF routes. Option B matches based on OSPF route type (internal, external), not tag. Option D redistributes all OSPF routes, *without filtering by tag*, and also doesn't address route-map usage.",
      "examTip": "Use a route map to filter routes during redistribution, matching on criteria like tags. EIGRP may require a manual metric when redistributing."
    },
    {
      "id": 55,
      "question": "A network is experiencing intermittent connectivity issues. A packet capture reveals a large number of TCP RST packets.  What does a TCP RST packet indicate, and what are some potential causes of a high volume of RST packets?",
      "options": [
        "Successful TCP connection establishment.",
        "Normal TCP connection termination.",
        "Abrupt termination of a TCP connection. Potential causes include application crashes, firewall rules blocking or resetting connections, network device intervention, misconfigured TCP keepalive settings, or network instability.",
        "Successful DNS resolution."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A TCP RST (reset) packet signifies an *abrupt termination* of a TCP connection. It's *not* part of the normal connection establishment (SYN, SYN-ACK, ACK) or graceful teardown (FIN, FIN-ACK, ACK) process.  A large number of RST packets means connections are being *forcibly closed*. Potential causes include: *Application crashes:* If an application crashes, the operating system may send RST packets. *Firewall rules:* A firewall might be configured to block or reset certain traffic. *Network devices:* Routers or other network devices might forcibly close connections for security or resource reasons. *Misconfigured TCP keepalives:* If keepalives are too aggressive, connections can be dropped early. *Network instability:* Severe congestion or device issues could trigger resets. It's *not* normal for graceful termination, nor is it directly related to DNS.",
      "examTip": "A high volume of TCP RST packets indicates abrupt termination of TCP connections, often due to application, firewall, or network device issues."
    },
    {
      "id": 56,
      "question": "A network administrator is configuring OSPF on a Cisco router. They want to prevent the router from forming OSPF neighbor adjacencies on a specific interface, but they still want the network connected to that interface to be advertised into OSPF. Which command, and in which configuration context, would achieve this?",
      "options": [
        "In global configuration mode: `passive-interface [interface-name]`",
        "Under the `router ospf [process-id]` configuration: `passive-interface [interface-name]`",
        "In interface configuration mode for the specific interface: `no ip ospf network broadcast`",
        "In interface configuration mode for the specific interface: `no ip ospf enable`"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `passive-interface` command, when used *within the OSPF process configuration* (`router ospf [process-id]`), stops sending OSPF hello packets on that interface, preventing neighbor formation, while still advertising the connected network if it matches a network statement. It does not disable OSPF entirely on that interface.",
      "examTip": "Use `passive-interface` under OSPF router configuration to advertise the network without forming adjacencies on that interface."
    },
    {
      "id": 57,
      "question": "A network administrator is troubleshooting a wireless network. Users report intermittent connectivity and slow performance. The administrator suspects interference. Besides other Wi-Fi networks, what are some common *non-Wi-Fi* sources of interference that can affect wireless networks operating in the 2.4 GHz band?",
      "options": [
        "FM radio broadcasts.",
        "Microwave ovens, Bluetooth devices, cordless phones (older models), wireless video cameras, poorly shielded electrical equipment, and some industrial equipment.",
        "Satellite communications.",
        "Cellular phone networks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The 2.4 GHz band is used by many non-Wi-Fi devices, including microwave ovens, Bluetooth devices, older cordless phones, and wireless video cameras. These can cause interference that degrades Wi-Fi performance. FM radio, satellite, and cellular operate in different frequency ranges.",
      "examTip": "Non-Wi-Fi interference in the 2.4 GHz band often comes from devices like microwaves, Bluetooth, and older cordless phones."
    },
    {
      "id": 58,
      "question": "You are configuring a Cisco switch and want to ensure that only a specific, known MAC address is allowed to connect to port GigabitEthernet0/1. If any other device connects, you want the port to be shut down immediately. Which of the following command sequences, starting from global configuration mode, would achieve this?",
      "options": [
        "interface GigabitEthernet0/1 \n switchport mode trunk \n switchport port-security",
        "interface GigabitEthernet0/1 \n switchport mode access \n switchport port-security \n switchport port-security maximum 1 \n switchport port-security mac-address sticky \n switchport port-security violation shutdown",
        "interface GigabitEthernet0/1 \n switchport mode access \n switchport port-security \n switchport port-security maximum 1 \n switchport port-security mac-address [allowed_mac_address] \n switchport port-security violation shutdown",
        "interface GigabitEthernet0/1 \n switchport mode access \n switchport port-security violation protect"
      ],
      "correctAnswerIndex": 2,
      "explanation": "To strictly allow a specific MAC address, you should statically configure that MAC address on the port using the `switchport port-security mac-address [allowed_mac_address]` command, after setting the port to access mode, enabling port security, and limiting it to 1 MAC address. Then, configure `violation shutdown` so that if any other MAC is detected, the port is disabled. Option B uses sticky learning (dynamic) which is not as strict as a pre-configured MAC address.",
      "examTip": "For absolute control, statically configure the allowed MAC and use `violation shutdown` to disable the port if a different MAC appears."
    },
    {
      "id": 59,
      "question": "A network administrator configures a Cisco router with the command `ip route 192.168.10.0 255.255.255.0 10.0.0.1 200`.  What is the purpose and effect of this command, and what is a potential risk if this is the *only* static route configured?",
      "options": [
        "It configures a static route for the 192.168.1.0 network.",
        "It configures a default route, sending all traffic that doesn't match a more specific route to the gateway at 10.0.0.1. The administrative distance of 200 makes this route less preferred than most dynamic routes. If 10.0.0.1 does not correctly forward traffic for all destinations, traffic will be dropped.",
        "It configures a dynamic route using a routing protocol.",
        "It blocks all traffic to the 10.0.0.1 address."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The command sets a static default route with an administrative distance of 200, meaning it will be less preferred than routes from dynamic protocols (which typically have lower AD values). If this default route is the only path and 10.0.0.1 isn’t capable of routing to all external networks, traffic destined for unknown routes may be dropped.",
      "examTip": "A default route (0.0.0.0/0) with an AD of 200 is less preferred than dynamic routes. Ensure the next-hop is valid for all destinations."
    },
    {
      "id": 60,
      "question": "A network administrator is troubleshooting an OSPF routing problem between two directly connected routers. OSPF is enabled on both routers, and the interfaces connecting them are in the same OSPF area. However, the routers are not forming an OSPF adjacency.  `show ip ospf neighbor` on both routers shows no neighbors.  Basic IP connectivity between the interfaces is confirmed with `ping`. Which of the following is the LEAST likely cause of this problem?",
      "options": [
        "Mismatched OSPF hello or dead intervals between the routers.",
        "Mismatched OSPF network types (e.g., one router set to broadcast and the other to point-to-point).",
        "An access control list (ACL) blocking OSPF multicast traffic.",
        "Mismatched MTU settings on the interfaces."
      ],
      "correctAnswerIndex": 3,
      "explanation": "OSPF neighbor adjacencies are highly sensitive to matching hello/dead intervals, network type, and unblocked multicast traffic (224.0.0.5/6). While MTU mismatches can cause problems during database exchange, they are less likely to prevent the initial formation of an adjacency compared to the other factors.",
      "examTip": "Focus on hello/dead timers, network type, and ACLs first; MTU mismatches tend to affect later phases of adjacency formation."
    },
    {
      "id": 61,
      "question": "Which of the following statements about IPv6 addresses is FALSE?",
      "options": [
        "IPv6 addresses are 128 bits long, represented as eight groups of four hexadecimal digits separated by colons.",
        "IPv6 uses the concept of 'scope' to define the reachability of an address (e.g., link-local, site-local, global).",
        "IPv6 addresses can be automatically configured using SLAAC (Stateless Address Autoconfiguration).",
        "IPv6 completely eliminates the need for NAT (Network Address Translation)."
      ],
      "correctAnswerIndex": 3,
      "explanation": "IPv6 provides a vast address space that significantly reduces the need for NAT; however, NAT is not completely eliminated. There are scenarios, such as multi-homing or specific security policies, where NAT (NAT66) may still be used. The other statements are accurate descriptions of IPv6.",
      "examTip": "While IPv6 reduces the necessity for NAT, it does not completely eliminate its use in all cases."
    },
    {
      "id": 62,
      "question": "A network administrator is troubleshooting a connectivity issue where users on a specific VLAN are unable to reach the internet. They can ping other devices within the VLAN and can ping the SVI (Switched Virtual Interface) IP address of their VLAN on the Layer 3 switch. However, they cannot ping the IP address of the next-hop router (the default gateway for the Layer 3 switch). What is the MOST likely cause of the problem?",
      "options": [
        "A problem with the user's computers' network cables.",
        "A routing problem between the Layer 3 switch and the next-hop router, or an issue with the next-hop router itself.",
        "A DNS server misconfiguration.",
        "A DHCP server failure."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Since users can ping the SVI on the Layer 3 switch but cannot reach the next-hop router, the issue is likely with the connection between the switch and the router, or with the router itself. DNS or DHCP issues would not prevent pings to a known IP address if the local configuration is correct.",
      "examTip": "If local VLAN connectivity is good but the next-hop router is unreachable, investigate the inter-device routing or connectivity."
    },
    {
      "id": 63,
      "question": "A network administrator is troubleshooting a slow file transfer between two computers on the same subnet. Pings between the computers show low latency and no packet loss.  Which of the following is the NEXT most likely area to investigate?",
      "options": [
        "The DNS server configuration.",
        "The DHCP server configuration.",
        "Resource utilization (CPU, memory, disk I/O) on both the sending and receiving computers, and the application-level protocols being used for the file transfer.",
        "The Spanning Tree Protocol configuration."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Since the physical and basic network connectivity is confirmed with low latency and no packet loss, the issue is more likely due to the performance of the end devices or application inefficiencies rather than DNS, DHCP, or Layer 2 protocols like STP.",
      "examTip": "After ruling out physical and network issues, check the performance and resource usage on the end devices for slow file transfers."
    },
    {
      "id": 64,
      "question": "A network administrator wants to configure a Cisco router to redistribute routes learned from OSPF into EIGRP.  OSPF is running with process ID 1, and EIGRP is running with autonomous system number 100. Furthermore, they want to ensure that only routes with a specific OSPF tag of 777 are redistributed. Which of the following commands, entered in router configuration mode for EIGRP, would achieve this, and what additional configuration might be necessary?",
      "options": [
        "router eigrp 100 \n redistribute ospf 1",
        "router eigrp 100 \n redistribute ospf 1 match internal",
        "router eigrp 100 \n redistribute ospf 1 route-map OSPF-TO-EIGRP \n ! \n route-map OSPF-TO-EIGRP permit 10 \n match tag 777",
        "router eigrp 100 \n redistribute ospf 1 metric 10000 100 255 1 1500"
      ],
      "correctAnswerIndex": 2,
      "explanation": "To redistribute routes from OSPF into EIGRP with filtering based on a tag, you must use a route map that matches the desired tag (777). In this case, you create a route map (e.g., OSPF-TO-EIGRP) that permits routes with tag 777 and apply it in the redistribution command under EIGRP configuration. Option C is the correct approach. Also, ensure that OSPF is configured to tag the appropriate routes.",
      "examTip": "Use a route map in the EIGRP redistribution command to filter OSPF routes based on a tag."
    },
    {
      "id": 65,
      "question": "A network administrator is troubleshooting a network where users experience intermittent connectivity issues. A packet capture reveals a large number of TCP RST packets.  What does a TCP RST packet indicate, and what are some potential causes of a high volume of RST packets?",
      "options": [
        "It indicates normal TCP connection establishment.",
        "It indicates normal, graceful TCP connection termination.",
        "It signifies an abrupt termination of a TCP connection. Potential causes include application crashes, firewall rules blocking or resetting connections, network devices forcibly closing connections, misconfigured TCP keepalive settings, or network instability.",
        "It signifies successful DNS resolution."
      ],
      "correctAnswerIndex": 2,
      "explanation": "TCP RST packets are used to abruptly terminate TCP connections, bypassing the standard FIN handshake. A surge in RST packets suggests that connections are being forcefully closed, often due to firewalls, application issues, or misconfigurations. It does not indicate normal termination or DNS resolution.",
      "examTip": "A high volume of TCP RST packets suggests abrupt connection termination; investigate potential application crashes, firewall resets, or device misconfigurations."
    },
    {
      "id": 66,
      "question": "A network administrator is configuring OSPF on a Cisco router. They want to prevent the router from forming OSPF neighbor adjacencies on a specific interface, but they still want the network connected to that interface to be advertised into OSPF. Which command, and in which configuration context, would achieve this?",
      "options": [
        "In global configuration mode: `passive-interface [interface-name]`",
        "Under the `router ospf [process-id]` configuration: `passive-interface [interface-name]`",
        "In interface configuration mode for the specific interface: `no ip ospf network broadcast`",
        "In interface configuration mode for the specific interface: `no ip ospf enable`"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Using the `passive-interface` command under the OSPF process configuration prevents the router from sending OSPF hello packets on that interface (thus no neighbor adjacencies form) while still advertising the network if it matches a network statement.",
      "examTip": "Configure `passive-interface` under router OSPF to advertise the network without forming adjacencies on that interface."
    },
    {
      "id": 67,
      "question": "A network administrator is troubleshooting a wireless network. Users report intermittent connectivity and slow speeds. The administrator suspects interference from other devices operating in the same frequency band.  Which tool is specifically designed to identify and analyze sources of radio frequency (RF) interference?",
      "options": [
        "A cable tester for verifying continuity.",
        "A protocol analyzer (like Wireshark) for capturing packet data.",
        "A spectrum analyzer that visually displays the RF spectrum across frequencies.",
        "A toner and probe for locating cables."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A spectrum analyzer is specifically designed to scan and display the RF spectrum. This tool can identify sources of interference (e.g., microwave ovens, cordless phones, Bluetooth devices) that operate in the same frequency band as the wireless network, particularly 2.4 GHz.",
      "examTip": "For RF interference issues in wireless networks, a spectrum analyzer provides the most direct insight."
    },
    {
      "id": 68,
      "question": "A network administrator wants to configure a Cisco switch to prevent rogue DHCP servers from operating on the network. They have enabled DHCP snooping globally with the `ip dhcp snooping` command. They have also identified the switch port connected to the legitimate DHCP server. What command should they use, in interface configuration mode, to designate this port as a trusted port for DHCP snooping?",
      "options": [
        "switchport mode access",
        "ip dhcp relay",
        "ip dhcp snooping trust",
        "ip dhcp snooping limit rate"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The command `ip dhcp snooping trust` must be applied in interface configuration mode on ports that connect to legitimate DHCP servers. This ensures that DHCP server responses are permitted on those ports, while all others remain untrusted.",
      "examTip": "Mark ports connected to authorized DHCP servers as trusted using `ip dhcp snooping trust`."
    },
    {
      "id": 69,
      "question": "A network administrator configures a Cisco switch port with the following commands:  `switchport mode access` `switchport port-security` `switchport port-security maximum 1` `switchport port-security mac-address sticky` `switchport port-security violation restrict`  What is the *precise* effect of the `violation restrict` mode in this port security configuration?",
      "options": [
        "The port will be shut down (err-disabled) if a security violation occurs.",
        "The port will drop traffic from unknown MAC addresses and increment the violation counter, and it can also send an SNMP trap or syslog message, but the port will remain operational.",
        "The port will drop traffic from unknown MAC addresses without logging or incrementing any counters.",
        "The port will allow traffic from any MAC address."
      ],
      "correctAnswerIndex": 1,
      "explanation": "In `violation restrict` mode, when a violation occurs (i.e., a frame with a different MAC than allowed is received), the switch drops the frame, increments the violation counter, and may generate alerts via SNMP/syslog, but it does not shut the port down.",
      "examTip": "Restrict mode logs and drops unauthorized traffic while keeping the port up."
    },
    {
      "id": 70,
      "question": "You are troubleshooting a network where users report intermittent connectivity to a web server. You have verified the following: The user's computer has a valid IP address, subnet mask, and default gateway. The user *can* ping the web server's IP address successfully. `nslookup` resolves the web server's domain name correctly. However, when the user tries to access the web server in a web browser, they get a 'Connection timed out' error.  Which of the following is the LEAST likely cause of the problem?",
      "options": [
        "A firewall is blocking traffic to the web server's port (e.g., TCP port 80 or 443).",
        "The web server application (e.g., Apache, IIS) is not running or is misconfigured.",
        "The user's computer has a faulty network cable.",
        "The web server machine is powered off."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Since the user can successfully ping the web server's IP address, it is unlikely that the user's network cable is at fault. A 'Connection timed out' error is more indicative of the service on the web server (or a firewall blocking it) not responding, rather than a physical connectivity issue.",
      "examTip": "If pings succeed but HTTP/HTTPS fails, the issue is likely at the application or firewall level, not a physical cabling problem."
    },
    {
      "id": 71,
      "question": "A network administrator is configuring OSPF on a multi-access network (like Ethernet) where multiple routers are connected. They want to minimize the number of OSPF adjacencies formed and optimize the flooding of LSAs (Link State Advertisements). Which OSPF feature should be used, and how does it work?",
      "options": [
        "Configure all routers with the same OSPF priority.",
        "Enable OSPF authentication.",
        "Utilize the Designated Router (DR) and Backup Designated Router (BDR) election process. The DR acts as a central point for LSA flooding, and the BDR takes over if the DR fails.",
        "Configure the network as a point-to-point network type."
      ],
      "correctAnswerIndex": 2,
      "explanation": "On multi-access networks, OSPF elects a DR and BDR to reduce the number of adjacencies. The DR centralizes LSA distribution among routers on the segment. If the DR fails, the BDR assumes its role. This minimizes overhead compared to a full mesh. The other options do not directly reduce adjacencies.",
      "examTip": "DR/BDR election in OSPF minimizes adjacencies and streamlines LSA flooding on multi-access networks."
    },
    {
      "id": 72,
      "question": "A network administrator is troubleshooting a network where users are intermittently losing their network connections. You suspect a problem with the Spanning Tree Protocol (STP). Which of the following commands on a Cisco switch would provide the MOST comprehensive information about the current STP state, including the root bridge, port roles, port states, and any recent topology changes?",
      "options": [
        "show interfaces status",
        "show ip interface brief",
        "show spanning-tree",
        "show mac address-table"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The `show spanning-tree` command displays detailed information about STP, including the current root bridge, each port's role and state, and topology change counters. This is essential for diagnosing STP issues.",
      "examTip": "Use `show spanning-tree` to see the complete STP status on a Cisco switch."
    },
    {
      "id": 73,
      "question": "What is 'BGP route reflection', and in what type of BGP deployment is it typically used to simplify configuration and reduce the number of required BGP sessions?",
      "options": [
        "A technique used to summarize routes advertised between different autonomous systems.",
        "A mechanism used in large *internal* BGP (iBGP) deployments within an autonomous system to avoid the need for a full mesh of iBGP sessions between all iBGP speakers. A designated router (or set of routers) acts as a route reflector, reflecting routes learned from one iBGP peer to other iBGP peers.",
        "A method for encrypting BGP routing updates.",
        "A technique for load balancing traffic across multiple BGP paths."
      ],
      "correctAnswerIndex": 1,
      "explanation": "BGP route reflection is a scalability mechanism used in large iBGP deployments to avoid a full mesh configuration. The route reflector receives routes from client routers and re-advertises them to other clients, reducing the number of required iBGP sessions.",
      "examTip": "Route reflection minimizes iBGP sessions by having a designated route reflector re-advertise routes to its clients."
    },
    {
      "id": 74,
      "question": "A network administrator is configuring a Cisco router and wants to restrict access to the router's VTY lines (for remote management via SSH) to only allow connections from a specific subnet, 192.168.10.0/24.  Which of the following command sequences, starting from global configuration mode, is the MOST secure and correct way to achieve this?",
      "options": [
        "line vty 0 4 \n transport input all",
        "line vty 0 4 \n transport input ssh \n access-list 10 permit ip any any \n access-class 10 in",
        "line vty 0 4 \n transport input ssh \n access-list 10 permit tcp 192.168.10.0 0.0.0.255 host [Router's Management IP] eq 22 \n access-class 10 in",
        "line con 0 \n transport input ssh \n access-list 10 permit 192.168.10.0 0.0.0.255 \n access-class 10 in"
      ],
      "correctAnswerIndex": 2,
      "explanation": "For secure remote access via SSH, you must restrict VTY access to only the permitted subnet. The proper configuration is to enable SSH on the VTY lines (`transport input ssh`), create an ACL that permits TCP traffic from the 192.168.10.0/24 subnet to the router's management IP on port 22, and then apply this ACL inbound on the VTY lines using `access-class 10 in`. This ensures that only authorized devices can connect to the router.",
      "examTip": "On VTY lines, use SSH-only transport and an ACL that restricts access to the permitted subnet."
    },
    {
      "id": 75,
      "question": "A company is implementing a wireless network and needs to choose between WPA2-Personal, WPA2-Enterprise, and WPA3-Enterprise.  What are the KEY differences between these security modes, and which one provides the STRONGEST security?",
      "options": [
        "WPA2-Personal uses a pre-shared key (PSK) for authentication, WPA2-Enterprise uses a RADIUS server and 802.1X, and WPA3-Enterprise uses a more secure pre-shared key. WPA2-Personal is the most secure.",
        "WPA2-Personal, WPA2-Enterprise, and WPA3-Enterprise all use the same authentication method, but different encryption algorithms. WPA3-Enterprise is the most secure.",
        "WPA2-Personal uses a pre-shared key (PSK) for authentication, making it easier to configure but less secure for large networks. WPA2-Enterprise uses 802.1X with a RADIUS server for per-user authentication, providing stronger security and centralized management. WPA3-Enterprise further enhances security with improved encryption and key exchange mechanisms. WPA3-Enterprise is the most secure.",
        "WPA2-Personal and WPA2-Enterprise are the same; WPA3-Enterprise is only for very large networks."
      ],
      "correctAnswerIndex": 2,
      "explanation": "WPA2-Personal relies on a single shared key, which can be less secure in larger environments. WPA2-Enterprise leverages 802.1X authentication with a RADIUS server for per-user credentials, enhancing security. WPA3-Enterprise further improves upon WPA2-Enterprise by offering stronger encryption and more secure key exchange. Thus, WPA3-Enterprise is the strongest option.",
      "examTip": "WPA3-Enterprise provides the strongest security by combining 802.1X authentication with advanced encryption and key exchange improvements."
    },
    {
      "id": 76,
      "question": "A network administrator is troubleshooting a wireless network. Users report intermittent connectivity and slow performance. The administrator suspects interference. Besides other Wi-Fi networks, what are some common *non-Wi-Fi* sources of interference that can affect wireless networks operating in the 2.4 GHz band?",
      "options": [
        "FM radio broadcasts.",
        "Microwave ovens, Bluetooth devices, cordless phones (older models), wireless video cameras, poorly shielded electrical equipment, and some industrial equipment.",
        "Satellite communications.",
        "Cellular phone networks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The 2.4 GHz band is shared by many devices including microwaves, Bluetooth devices, and older cordless phones. These non-Wi-Fi sources can cause interference that degrades wireless performance. FM radio, satellite, and cellular typically operate in different frequency ranges.",
      "examTip": "Non-Wi-Fi devices like microwaves and older cordless phones can interfere with 2.4 GHz Wi-Fi."
    },
    {
      "id": 77,
      "question": "A network administrator is troubleshooting a network where devices are experiencing intermittent connectivity. A user reports being unable to access a specific web server. They are using a Windows computer. Which of the following commands would be MOST helpful in *quickly* determining if the user's computer has a valid IP address, subnet mask, and default gateway configured?",
      "options": [
        "ping 8.8.8.8",
        "tracert 8.8.8.8",
        "ipconfig /all",
        "nslookup www.google.com"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The `ipconfig /all` command provides detailed information about the computer's IP configuration, including the IP address, subnet mask, and default gateway. This is the quickest way to verify the network settings on a Windows system.",
      "examTip": "Use `ipconfig /all` to quickly confirm IP settings on a Windows machine."
    },
    {
      "id": 78,
      "question": "A network administrator is troubleshooting a network where users are unable to reach the internet from a specific VLAN. They can ping other devices within the VLAN and the SVI IP of the Layer 3 switch, but not the next-hop router. What is the MOST likely cause?",
      "options": [
        "A problem with the user's network cables.",
        "A routing issue between the Layer 3 switch and the next-hop router, or a problem with the next-hop router itself.",
        "A DNS server misconfiguration.",
        "A DHCP server failure."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Since devices can ping the local SVI but not the next-hop router, the problem likely lies in the routing path from the Layer 3 switch to the router, or with the router’s configuration itself. This indicates a problem beyond the local VLAN, not a cable, DNS, or DHCP issue.",
      "examTip": "If local connectivity works but the next hop is unreachable, check the routing between the switch and the router."
    },
    {
      "id": 79,
      "question": "A network administrator is troubleshooting a slow file transfer between two computers on the same subnet.  Pings between the computers show low latency and no packet loss.  Which of the following is the NEXT most likely area to investigate?",
      "options": [
        "The DNS server configuration.",
        "The DHCP server configuration.",
        "Resource utilization (CPU, memory, disk I/O) on both the sending and receiving computers, and the application-level protocols being used for the file transfer.",
        "The Spanning Tree Protocol configuration."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Since basic connectivity is verified by ping, physical network issues are unlikely. Slow file transfers can be due to resource limitations on the end devices or inefficiencies in the application layer, making resource utilization the next area to examine.",
      "examTip": "After ruling out physical issues, check the end devices for resource constraints affecting file transfer speeds."
    },
    {
      "id": 80,
      "question": "A network administrator is configuring a Cisco router to redistribute routes learned from OSPF into EIGRP.  OSPF is running with process ID 1, and EIGRP is running with autonomous system number 100. Furthermore, they want to ensure that only routes with a specific OSPF tag of 777 are redistributed. Which of the following commands, entered in router configuration mode for EIGRP, would achieve this, and what additional configuration might be necessary?",
      "options": [
        "router eigrp 100 \n redistribute ospf 1",
        "router eigrp 100 \n redistribute ospf 1 match internal",
        "router eigrp 100 \n redistribute ospf 1 route-map OSPF-TO-EIGRP \n ! \n route-map OSPF-TO-EIGRP permit 10 \n match tag 777",
        "router eigrp 100 \n redistribute ospf 1 metric 10000 100 255 1 1500"
      ],
      "correctAnswerIndex": 2,
      "explanation": "To redistribute OSPF routes into EIGRP with filtering based on a tag, you need to use a route map that matches the desired tag (777). The correct configuration involves creating a route map (e.g., OSPF-TO-EIGRP) that permits routes with tag 777 and then applying it in the redistribution command under EIGRP configuration. Additional configuration in OSPF may be needed to tag routes appropriately.",
      "examTip": "Use a route map in the EIGRP redistribution command to filter for routes with a specific OSPF tag."
    },
    {
      "id": 81,
      "question": "A network administrator is troubleshooting a network where devices experience intermittent connectivity. A packet capture shows a large number of TCP RST packets. What does the presence of numerous TCP RST packets typically indicate, and what are some potential underlying causes?",
      "options": [
        "It signifies normal and graceful TCP connection termination.",
        "It indicates successful DNS resolution.",
        "It signifies an abrupt termination of TCP connections. Potential causes include application crashes, firewall rules sending resets, network devices forcefully closing sessions, misconfigured TCP keepalives, or network instability.",
        "It signifies successful DHCP address assignment."
      ],
      "correctAnswerIndex": 2,
      "explanation": "TCP RST packets abruptly terminate a connection. A high volume indicates that connections are being forcibly closed, often due to firewalls, application errors, or network misconfigurations, rather than normal connection teardown.",
      "examTip": "Many TCP RST packets suggest forced connection closures; investigate firewalls, applications, and device configurations."
    },
    {
      "id": 82,
      "question": "A network administrator is configuring a Cisco router to act as a DHCP server for the 192.168.1.0/24 network.  They want to create a static mapping (reservation) to ensure that a specific device with MAC address 00:11:22:33:44:55 always receives the IP address 192.168.1.50. Which of the following commands, entered in global configuration mode within the DHCP pool configuration, would correctly achieve this?",
      "options": [
        "host 192.168.1.50 /24",
        "host 192.168.1.50 255.255.255.0 \n client-identifier 0100.1122.3344.55",
        "static-bind ip-address 192.168.1.50 mac-address 00:11:22:33:44:55",
        "address 192.168.1.50 client-id 001122334455"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Cisco routers require the use of the `host` command along with a `client-identifier` for DHCP reservations. The MAC address is expressed in a specific format (with a leading 01 for Ethernet). Therefore, the correct command is to reserve 192.168.1.50 with the appropriate subnet mask and client identifier.",
      "examTip": "Use the `host` command with the correct client-identifier in the DHCP pool to reserve an IP address for a specific device."
    },
    {
      "id": 83,
      "question": "A network uses OSPF as its routing protocol. The network is divided into multiple areas.  A network administrator wants to reduce the size of the routing tables on routers within a specific area by preventing external routes (routes learned from outside the OSPF domain) from being advertised into that area. Which type of OSPF area should the administrator configure, and what is the key characteristic of that area type?",
      "options": [
        "Standard area; it allows all types of OSPF LSAs.",
        "Stub area; it blocks external LSAs (Type 5) and uses a default route to reach external destinations.",
        "Totally stubby area; it blocks Type 3, Type 4, and Type 5 LSAs.",
        "Not-so-stubby area (NSSA); it allows Type 5 LSAs."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A stub area is designed to reduce routing overhead by blocking external LSAs (Type 5). Routers in a stub area receive a default route from the ABR to reach external networks. This reduces the amount of routing information that needs to be processed and stored.",
      "examTip": "Configure a stub area in OSPF to block external LSAs and reduce routing table size, relying on a default route for external connectivity."
    },
    {
      "id": 84,
      "question": "You are troubleshooting a network connectivity issue where a user is unable to access a web server. They have valid IP configurations and can ping the server's IP address successfully, and `nslookup` correctly resolves the domain name. However, when they try to access the server in a web browser, they receive a 'Connection timed out' error. What is the MOST likely cause of the problem?",
      "options": [
        "The web server is not listening on the expected port or is misconfigured, or a firewall is blocking the connection.",
        "The DNS server is misconfigured.",
        "The user's network cable is unplugged.",
        "The user's default gateway is misconfigured."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A 'Connection timed out' error typically means that the TCP connection attempt did not receive any response. Given that ping and DNS resolution work, the most likely cause is that the web server application is either down, misconfigured, or a firewall is blocking access to its port (typically TCP 80 or 443).",
      "examTip": "If connectivity tests (ping, nslookup) succeed but web access times out, suspect the web server service or an intervening firewall."
    },
    {
      "id": 85,
      "question": "A network administrator wants to configure a Cisco switch to automatically learn the MAC address of the first device connected to a port and add that MAC address to the running configuration as a secure MAC address.  Furthermore, if a device with a different MAC address subsequently connects to that port, the administrator wants the port to be shut down (placed in the error-disabled state). Which of the following sets of commands, starting from interface configuration mode, would achieve this?",
      "options": [
        "switchport mode trunk \n switchport port-security \n switchport port-security maximum 2",
        "switchport mode access \n switchport port-security \n switchport port-security maximum 1 \n switchport port-security mac-address sticky \n switchport port-security violation shutdown",
        "switchport mode access \n switchport port-security \n switchport port-security maximum 1 \n switchport port-security mac-address [allowed_mac_address] \n switchport port-security violation shutdown",
        "switchport mode access \n switchport port-security violation restrict"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The desired configuration is to dynamically learn a MAC address (using sticky learning), limit the port to one MAC address, and shut down the port if a different MAC appears. This is achieved by setting the port to access mode, enabling port-security with a maximum of 1, enabling sticky MAC address learning, and setting the violation mode to shutdown.",
      "examTip": "Use sticky learning with a maximum of 1 MAC address and violation shutdown to lock the port to the first device and disable it on violations."
    },
    {
      "id": 86,
      "question": "You are configuring a site-to-site IPsec VPN between two Cisco routers. You have already configured the ISAKMP policy (Phase 1) and the IPsec transform set (Phase 2).  However, the VPN tunnel is not establishing. Which of the following commands on the Cisco router would be MOST helpful in troubleshooting the ISAKMP (Phase 1) negotiation process?",
      "options": [
        "show ip route",
        "show crypto isakmp sa",
        "show crypto ipsec sa",
        "debug ip dhcp snooping"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The command `show crypto isakmp sa` displays the status of ISAKMP Security Associations (SAs) for Phase 1 of the IPsec VPN. If no SAs are established, it indicates a failure in the initial key exchange or authentication phase.",
      "examTip": "Use `show crypto isakmp sa` to diagnose Phase 1 issues in IPsec VPN setups."
    },
    {
      "id": 87,
      "question": "A network uses EIGRP as its routing protocol. The network administrator wants to summarize multiple contiguous networks into a single route advertisement to reduce the size of the routing tables on neighboring routers. Which command, and in which configuration context, should the administrator use to configure EIGRP route summarization on a Cisco router?",
      "options": [
        "Under the `router eigrp 100` configuration, use the `summary-address` command.",
        "Under the interface configuration mode for the interface *sending* the summarized route, use the `ip summary-address eigrp 100 [summary-address] [subnet-mask]` command.",
        "Under the `router eigrp 100` configuration, use the `auto-summary` command.",
        "Under the interface configuration mode for the interface *receiving* the summarized route, use the `ip summary-address eigrp 100 [summary-address] [subnet-mask]` command."
      ],
      "correctAnswerIndex": 1,
      "explanation": "EIGRP route summarization is performed on the outbound interface from which the summarized routes are sent. The correct command is issued in interface configuration mode using `ip summary-address eigrp 100 [summary-address] [subnet-mask]`. This tells the router to advertise a summary route to neighbors connected on that interface.",
      "examTip": "Configure route summarization on the outbound interface with `ip summary-address eigrp` in interface mode."
    },
    {
      "id": 88,
      "question": "A network administrator is troubleshooting a wireless network. Users report intermittent connectivity and slow performance. The administrator suspects RF interference. Besides other Wi-Fi networks, what are some common *non-Wi-Fi* sources of interference that can affect wireless networks operating in the 2.4 GHz band?",
      "options": [
        "FM radio broadcasts.",
        "Microwave ovens, Bluetooth devices, cordless phones (older models), wireless video cameras, poorly shielded electrical equipment, and some industrial equipment.",
        "Satellite communications.",
        "Cellular phone networks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Non-Wi-Fi sources such as microwave ovens, Bluetooth devices, and older cordless phones operate in the 2.4 GHz band and can cause interference with Wi-Fi signals, leading to degraded performance.",
      "examTip": "Identify interference from devices like microwaves and Bluetooth in the 2.4 GHz band using appropriate RF analysis tools."
    },
    {
      "id": 89,
      "question": "A network administrator configures a Cisco switch with the following command: `switchport trunk native vlan 99`. What is the purpose and effect of this command, and what is a potential security best practice related to the native VLAN?",
      "options": [
        "It disables VLAN tagging for all traffic on the trunk.",
        "It specifies that untagged frames received on the trunk port will be assigned to VLAN 99. It is a security best practice to use a native VLAN other than the default VLAN 1.",
        "It specifies that VLAN 99 is the only VLAN allowed on the trunk.",
        "It encrypts traffic on VLAN 99."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The command `switchport trunk native vlan 99` sets VLAN 99 as the native VLAN for the trunk port, meaning untagged frames will be associated with VLAN 99 instead of the default VLAN 1. This practice is often recommended for security reasons to avoid potential VLAN-hopping attacks that target the default VLAN.",
      "examTip": "Changing the native VLAN from the default (VLAN 1) to a different VLAN (like VLAN 99) is a common security practice."
    },
    {
      "id": 90,
      "question": "A network administrator configures a Cisco router with the following command sequence, in global configuration mode:\n`access-list 101 permit tcp any host 192.168.1.100 eq 22`\n`access-list 101 deny ip any any`\n`line vty 0 4`\n`transport input ssh`\n`access-class 101 in`\nWhat is the combined effect of THESE specific commands, in this order?",
      "options": [
        "All traffic is permitted to the router.",
        "All traffic is denied to the router.",
        "Only SSH traffic (TCP port 22) destined for 192.168.1.100 is permitted on the VTY lines; all other traffic to the VTY lines is blocked.",
        "Only SSH traffic from the host 192.168.1.100 is permitted to the router's VTY lines."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The ACL permits TCP traffic to 192.168.1.100 on port 22 and denies all other IP traffic. When applied inbound on the VTY lines, this configuration allows only SSH connections (to TCP port 22) destined for 192.168.1.100, while all other types of traffic are blocked. This does not affect transit traffic; it only secures the management access.",
      "examTip": "Applying an ACL with access-class on VTY lines filters incoming management traffic based on specified rules."
    },
    {
      "id": 91,
      "question": "A network administrator is troubleshooting a slow file transfer between two computers on the same subnet. Pings between the computers show low latency and no packet loss.  Which of the following is the NEXT most likely area to investigate?",
      "options": [
        "The DNS server configuration.",
        "The DHCP server configuration.",
        "Resource utilization (CPU, memory, disk I/O) on both the sending and receiving computers, and the application-level protocols being used for the file transfer.",
        "The Spanning Tree Protocol configuration."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Since basic connectivity is confirmed with low latency and no packet loss, the likely issue is on the host side or with the application itself. Investigate system resource constraints and how the file transfer protocol is performing.",
      "examTip": "When network conditions are good but transfers are slow, check the end devices and application performance."
    },
    {
      "id": 92,
      "question": "A network administrator is configuring a Cisco router to act as a DHCP server. They have defined the DHCP pool, network, default gateway, and DNS servers. They also want to create a static mapping (reservation) to ensure that a specific device with MAC address 00:11:22:33:44:55 always receives the IP address 192.168.1.50. Which of the following commands, entered in global configuration mode within the DHCP pool configuration, would correctly achieve this?",
      "options": [
        "host 192.168.1.50 /24",
        "host 192.168.1.50 255.255.255.0 \n client-identifier 0100.1122.3344.55",
        "static-bind ip-address 192.168.1.50 mac-address 00:11:22:33:44:55",
        "address 192.168.1.50 client-id 001122334455"
      ],
      "correctAnswerIndex": 1,
      "explanation": "For DHCP reservations on Cisco routers, within the DHCP pool configuration, you use the `host` command along with `client-identifier` to tie a specific MAC address (formatted with a leading 01 for Ethernet) to an IP address reservation.",
      "examTip": "Use the `host` command and correct client-identifier format to reserve an IP address for a specific device."
    },
    {
      "id": 93,
      "question": "A network uses OSPF as its routing protocol. The network is divided into multiple areas.  A network administrator wants to reduce the size of the routing tables on routers within a specific area by preventing external routes (routes learned from outside the OSPF domain) from being advertised into that area. Which type of OSPF area should the administrator configure, and what is the key characteristic of that area type?",
      "options": [
        "Standard area; it allows all types of OSPF LSAs.",
        "Stub area; it blocks external LSAs (Type 5) and uses a default route to reach external destinations.",
        "Totally stubby area; it blocks Type 3, Type 4, and Type 5 LSAs.",
        "Not-so-stubby area (NSSA); it allows Type 5 LSAs."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A stub area is designed to reduce routing overhead by blocking external LSAs (Type 5) from entering the area. Routers within the stub area then use a default route, injected by the ABR, to reach external networks.",
      "examTip": "Stub areas block external LSAs, reducing routing table size and simplifying OSPF processing."
    },
    {
      "id": 94,
      "question": "You are troubleshooting a network connectivity issue where a user is unable to access a web server. They have valid IP configurations and can ping the server's IP address, and `nslookup` resolves the domain name correctly. However, when they try to access the server in a web browser, they receive a 'Connection timed out' error. What is the MOST likely cause of the problem?",
      "options": [
        "The web server is not listening on the expected port or is misconfigured, or a firewall is blocking the connection on that port.",
        "The DNS server is misconfigured.",
        "The user's network cable is unplugged.",
        "The user's default gateway is not configured."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A 'Connection timed out' error, despite successful ping and DNS resolution, usually indicates that the web service is not responding. This may be due to the web server application not running, misconfiguration, or a firewall blocking the connection on the expected port.",
      "examTip": "When connectivity tests pass but application access times out, focus on the service and firewall configuration."
    },
    {
      "id": 95,
      "question": "A network administrator is troubleshooting a network performance issue. Users report that a specific web application is extremely slow.  You use a protocol analyzer to capture network traffic and observe the following: * A large number of TCP retransmissions. * Frequent duplicate ACKs. * Many TCP packets with the PSH flag set. * Occasional TCP ZeroWindow messages *from the web server*. * The 'Time' column in your protocol analyzer shows significant delays between the client's requests and the server's responses, even for small requests. Which of the following is the MOST accurate and complete diagnosis of the problem, based on these observations?",
      "options": [
        "The problem is likely caused by a DNS server misconfiguration.",
        "The problem is likely caused by a faulty network cable.",
        "The problem is likely caused by network congestion, packet loss, and/or a resource bottleneck on the web server (CPU, memory, disk I/O, or network interface). The frequent PSH flags might indicate the application is aggressively pushing data, possibly exacerbating congestion.",
        "The problem is likely caused by the user's web browser being misconfigured."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The combination of numerous TCP retransmissions, duplicate ACKs, and ZeroWindow messages indicates packet loss and/or resource exhaustion on the web server. The PSH flag usage suggests that the application might be pushing data immediately, potentially aggravating the issue. DNS or cable faults would not produce this specific set of symptoms.",
      "examTip": "A mix of TCP retransmissions, duplicate ACKs, and ZeroWindow messages generally points to congestion or resource bottlenecks at the server side."
    },
    {
      "id": 96,
      "question": "A network administrator is configuring a Cisco router to act as a DHCP server. They want to restrict the DHCP address assignment such that the router itself (with IP 192.168.1.1) and the addresses 192.168.1.2 through 192.168.1.10 are reserved for static assignments, and also reserve 192.168.1.50 for a device with MAC address 00:11:22:33:44:55. Which of the following command sequences, entered in global configuration mode within the DHCP pool configuration, would correctly achieve this?",
      "options": [
        "ip dhcp pool MYPOOL \n network 192.168.1.0 255.255.255.0 \n default-router 192.168.1.1 \n ip dhcp excluded-address 192.168.1.1 192.168.1.10 \n host 192.168.1.50 255.255.255.0 \n client-identifier 0100.1122.3344.55",
        "ip dhcp excluded-address 192.168.1.1 192.168.1.10 \n ip dhcp pool MYPOOL \n network 192.168.1.0 255.255.255.0 \n default-router 192.168.1.1 \n dns-server 8.8.8.8 \n host 192.168.1.50 255.255.255.0 \n client-identifier 0100.1122.3344.55",
        "ip dhcp pool MYPOOL \n network 192.168.1.0 255.255.255.0 \n default-router 192.168.1.1 \n dns-server 8.8.8.8 \n ip dhcp excluded-address 192.168.1.2 192.168.1.10 \n ip dhcp excluded-address 192.168.1.1\n host 192.168.1.50 255.255.255.0 \n client-identifier 0100.1122.3344.55",
        "ip dhcp excluded-address 192.168.1.1 192.168.1.10 \n ip dhcp pool MYPOOL \n network 192.168.1.0 255.255.255.0 \n default-router 192.168.1.1 \n dns-server 8.8.8.8 \n host 192.168.1.50 255.255.255.0 \n client-identifier 0100.1122.3344.55 \n ip dhcp excluded-address 192.168.1.254"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option 3 correctly excludes 192.168.1.1 (the router's own IP) and the range 192.168.1.2–192.168.1.10 from DHCP assignment, then sets up a host reservation for 192.168.1.50 with the proper client-identifier format for MAC address 00:11:22:33:44:55. The other options either misconfigure the exclusions or use incorrect syntax for the reservation.",
      "examTip": "Ensure you exclude the router’s IP and reserved ranges, then configure a host reservation with the correct client-identifier format."
    },
    {
      "id": 97,
      "question": "A network administrator is troubleshooting a connectivity issue between two directly connected routers running OSPF. Although basic IP connectivity is confirmed, no OSPF neighbor adjacencies are forming. Which command would provide the MOST comprehensive information to diagnose OSPF configuration and identify potential misconfigurations?",
      "options": [
        "show ip route ospf",
        "show ip ospf neighbor",
        "show ip ospf interface brief",
        "show ip ospf database",
        "show ip ospf"
      ],
      "correctAnswerIndex": 4,
      "explanation": "The command `show ip ospf` gives a comprehensive overview of the OSPF process, including interface configurations, neighbor statuses, and area information. This broad view is essential to diagnose why adjacencies are not forming, such as mismatched hello/dead intervals, area mismatches, or authentication issues.",
      "examTip": "Use `show ip ospf` to get a full picture of the OSPF configuration and status on the router."
    },
    {
      "id": 98,
      "question": "A network administrator is troubleshooting a network where users experience intermittent connectivity issues. Packet captures reveal many TCP retransmissions and out-of-order packets, along with occasional ICMP messages stating 'Fragmentation Needed and DF set'. What is the MOST likely underlying cause, and what is the BEST solution?",
      "options": [
        "DNS server misconfiguration; update DNS records and flush caches.",
        "DHCP scope exhaustion; expand the DHCP pool.",
        "An MTU mismatch along the path. Ensure that Path MTU Discovery (PMTUD) is functioning by allowing ICMP 'Fragmentation Needed' messages, or manually set a consistent MTU on all devices along the path.",
        "A faulty network cable; replace the cable."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The ICMP message 'Fragmentation Needed and DF set' indicates that a packet exceeds the MTU of a link and cannot be fragmented due to the DF bit. This is a classic symptom of an MTU mismatch. The solution is to ensure that PMTUD functions correctly (i.e., that necessary ICMP messages are not being blocked) or to manually set an appropriate MTU across all relevant devices.",
      "examTip": "ICMP 'Fragmentation Needed' errors point to MTU mismatches; ensure PMTUD is functional or manually configure the MTU."
    },
    {
      "id": 99,
      "question": "A network administrator is troubleshooting a network performance issue. Users report that a specific web application is extremely slow.  A protocol analyzer shows a large number of TCP retransmissions, frequent duplicate ACKs, many TCP packets with the PSH flag set, and occasional TCP ZeroWindow messages from the web server. Additionally, there are significant delays between client requests and server responses. What is the MOST accurate and complete diagnosis of the problem?",
      "options": [
        "The problem is likely caused by a DNS server misconfiguration.",
        "The problem is likely caused by a faulty network cable.",
        "The problem is likely caused by network congestion, packet loss, and/or a resource bottleneck on the web server (CPU, memory, disk I/O, or network interface). The frequent PSH flags suggest the application might be aggressively pushing data, which could exacerbate congestion.",
        "The problem is likely caused by the user's web browser being misconfigured."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The combination of frequent TCP retransmissions, duplicate ACKs, ZeroWindow messages, and PSH flags indicates that packets are being lost and that the web server is experiencing resource constraints. This suggests that network congestion and/or a bottleneck on the server is severely impacting performance.",
      "examTip": "Intermittent performance issues with these TCP symptoms typically point to congestion or server resource limitations."
    },
    {
      "id": 100,
      "question": "A network administrator wants to configure a Cisco router to use NTP (Network Time Protocol) to synchronize its clock with an external time server.  The NTP server's IP address is 192.0.2.1.  Which of the following commands, entered in global configuration mode, would correctly configure the router to use this NTP server?",
      "options": [
        "ntp master 1",
        "ntp server 192.0.2.1",
        "ntp update-calendar",
        "ntp master"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `ntp server 192.0.2.1` command configures the router to synchronize its clock with the specified NTP server. The `ntp master` command makes the router an NTP server, which is not desired in this scenario.",
      "examTip": "Use the `ntp server` command to configure a Cisco router to synchronize with an external NTP server."
    }
  ]
});
