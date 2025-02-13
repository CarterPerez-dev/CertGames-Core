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
        "The NEXT_HOP attribute; inspect it using the `show ip bgp` command.",
        "The AS_PATH attribute; inspect it using the `show ip bgp` command, and look for unexpected or manipulated AS numbers in the path.",
        "The ORIGIN attribute; inspect it using the `show ip route` command.",
        "The LOCAL_PREF attribute; inspect it using the `show ip protocols` command."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `AS_PATH` attribute is a fundamental part of BGP. It lists the sequence of autonomous systems (ASes) that a route has traversed.  It's used for loop prevention (a router won't accept a route that already includes its own AS number) and can also be used for routing policy (preferring routes with shorter AS paths).  If the `AS_PATH` is *manipulated* (e.g., through a BGP hijacking attack or a misconfiguration), it can cause: *Route filtering:*  If a router is configured to filter routes based on the AS_PATH (e.g., rejecting routes that have traversed a specific AS), a manipulated AS_PATH could cause legitimate routes to be rejected. *Incorrect route preference:*  If a router prefers routes with shorter AS paths, a manipulated AS_PATH could cause it to prefer a suboptimal or malicious route. To inspect the `AS_PATH` on a Cisco router, you use the `show ip bgp` command. This command displays the BGP routing table, including the `AS_PATH` for each route. Look for: *Unexpected AS numbers:*  AS numbers in the path that you don't expect to see. *Manipulated AS paths:*  AS paths that are artificially lengthened or shortened. *Missing AS numbers:* AS numbers that should be present but are not. The `NEXT_HOP` attribute indicates the next hop IP address, but it's the `AS_PATH` that's directly related to inter-AS routing anomalies. `ORIGIN` indicates how the route was learned, and `LOCAL_PREF` is used for *internal* BGP (iBGP) preference, not primarily for inter-AS routing.",
      "examTip": "The BGP AS_PATH attribute is crucial for inter-AS routing and loop prevention; inspect it carefully using `show ip bgp` to detect anomalies."
    },
    {
       "id": 2,
       "question": "You are troubleshooting a complex network issue where some TCP connections are failing intermittently, while others are working fine. Using a protocol analyzer, you observe frequent TCP retransmissions and out-of-order packets for the failing connections. You also notice that the TCP window size advertised by the receiving host is fluctuating dramatically, sometimes dropping to very small values, even zero.  What is the MOST precise term for this condition, what are the potential underlying causes, and how does it impact TCP performance?",
       "options":[
         "Network congestion; caused by too much traffic on the network; it impacts performance by increasing latency.",
         "Receive window scaling problem; caused by incompatible TCP implementations; it impacts performance by limiting throughput.",
         "TCP receive window exhaustion; caused by the receiving host's inability to process incoming data quickly enough (due to CPU overload, memory exhaustion, slow disk I/O, or network interface buffer limitations), leading to buffer filling and advertised window size reduction/zeroing; it severely impacts performance by causing the sender to slow down or stop transmitting, leading to increased latency and reduced throughput.",
         "DNS resolution failure; caused by a misconfigured DNS server; it impacts performance by preventing name resolution."
       ],
       "correctAnswerIndex": 2,
       "explanation": "The most precise term is *TCP receive window exhaustion*.  Here's why: *TCP Retransmissions & Out-of-Order Packets:* Indicate packet loss, which can be *caused by* congestion, but also by other factors. *Fluctuating/Small/Zero Window Size:* This is the key. The TCP *receive window* is the amount of data the receiver is willing to accept at any given time. It's advertised by the receiver to the sender.  If the receiver's buffer fills up (because it can't process data fast enough), it will *reduce* its advertised window size, possibly to *zero*. This tells the sender to *slow down or stop transmitting* until the receiver can catch up. *Causes:*  The underlying causes of receive window exhaustion are typically resource bottlenecks on the *receiving host*:  *CPU overload*, *Memory exhaustion*, *Slow disk I/O*, *Network interface buffer limitations*. While *network congestion* can *contribute* to the problem (by causing delays and packet loss, which can fill up buffers), the *ZeroWindow* messages specifically indicate a receiver-side bottleneck. While Option B mentions \"window scaling\", this is something else. Option A just blames all on congestion. Option D is clearly wrong",
       "examTip": "TCP receive window exhaustion, indicated by fluctuating and small/zero advertised window sizes, signifies a receiver-side bottleneck and severely impacts TCP throughput."
    },
    {
      "id": 3,
      "question": "A network uses the OSPF routing protocol.  A network administrator notices that a particular router is not forming OSPF neighbor adjacencies with any of its directly connected neighbors on a specific multi-access network segment (Ethernet).  The administrator has verified that: IP connectivity between the routers is working (they can ping each other). OSPF is enabled on the interfaces. The interfaces are in the same OSPF area. The OSPF network type is correctly configured as 'broadcast' on all interfaces. Which of the following is the MOST likely cause of the problem, and which command on a Cisco router would help verify this?",
      "options":[
         "The OSPF hello and dead intervals are mismatched; use the `show ip ospf interface [interface_name]` command.",
         "The OSPF router IDs are conflicting; use the `show ip ospf` command.",
         "Spanning Tree Protocol (STP) is blocking the ports; use the `show spanning-tree` command.",
         "An access control list (ACL) is blocking OSPF traffic; use the `show ip access-lists` command."
      ],
      "correctAnswerIndex": 0,
      "explanation": "OSPF routers on the same network segment must have *matching* hello and dead intervals to form neighbor adjacencies. If these intervals are *mismatched*, the routers will not become neighbors. The `show ip ospf interface [interface_name]` command displays detailed OSPF information for a specific interface, *including the hello and dead intervals*. Checking these intervals on all routers on the segment is crucial. While conflicting Router IDs (*B*) *can* cause issues, they usually result in *some* adjacencies forming, not a *complete* failure on a segment. STP (*C*) operates at Layer 2 and wouldn't directly prevent OSPF neighbor relationships *if* basic IP connectivity is working (as stated in the problem). ACLs (*D*) *could* block OSPF traffic, but the mismatched timers are a more *fundamental* OSPF requirement.",
      "examTip": "OSPF hello and dead intervals must match on all routers on a network segment for neighbor adjacencies to form; use `show ip ospf interface` to verify."
    },
    {
      "id": 4,
      "question": "You are designing a network for a financial institution that requires extremely high availability and fault tolerance.  No single point of failure can be tolerated.  Which of the following design considerations, implemented in combination, would provide the MOST robust solution?",
      "options":[
        "Using a single, very powerful router and switch with redundant power supplies.",
        "Implementing redundant network devices (routers, switches, firewalls) with automatic failover mechanisms (HSRP/VRRP, STP/RSTP, etc.), redundant links between devices, diverse paths for critical traffic, geographically dispersed data centers with real-time replication, and a comprehensive disaster recovery plan.",
        "Using strong passwords and encrypting all network traffic.",
        "Implementing VLANs and segmenting the network."
      ],
      "correctAnswerIndex": 1,
      "explanation":"High availability and fault tolerance require *redundancy at every level*: *Redundant Network Devices:* Multiple routers, switches, and firewalls, configured for automatic failover (e.g., HSRP/VRRP for routers, STP/RSTP or other loop-free protocols for switches). *Redundant Links:* Multiple physical connections between devices, so that if one link fails, others can take over. *Diverse Paths:* Ensure that traffic can take multiple paths through the network, avoiding single points of failure. *Geographically Dispersed Data Centers:* Replicating data and services to multiple locations to protect against site-wide failures. *Real-time Replication:*  Ensuring that data is continuously replicated between data centers to minimize data loss in case of a failure. *Comprehensive Disaster Recovery Plan:*  A well-defined plan for recovering from major failures, including data backups, restoration procedures, and communication protocols. A *single* device, even with redundant power, is still a single point of failure. Strong passwords and encryption are *security* measures, not *availability*. VLANs provide *segmentation*, not *redundancy*.",
      "examTip":"High availability and fault tolerance require a multi-layered approach with redundancy at every level of the network and server infrastructure."
    },
    {
      "id": 5,
      "question": "A network uses EIGRP as its routing protocol. The network administrator wants to summarize routes advertised to a neighboring router to reduce the size of the routing table on that neighbor. Which command, and in which configuration context, is used to configure route summarization on a Cisco router running EIGRP?",
      "options":[
        "Under the `router eigrp [autonomous-system-number]` configuration, use the `summary-address` command.",
        "Under the interface configuration for the interface *sending* the summarized route, use the `ip summary-address eigrp [as-number] [summary-address] [subnet-mask]` command.",
        "Under the `router eigrp [autonomous-system-number]` configuration, use the `auto-summary` command.",
        "Under the interface configuration for the interface *receiving* the summarized route, use the `ip summary-address eigrp [as-number] [summary-address] [subnet-mask]` command."
      ],
      "correctAnswerIndex": 1,
      "explanation": "In EIGRP, route summarization is configured on the *interface* that is *sending* the summarized route *out* to the neighbor. The command is used under *interface configuration mode*, *not* under the general `router eigrp` configuration. The correct command and context are: `interface [interface-name]` `ip summary-address eigrp [as-number] [summary-address] [subnet-mask] [administrative-distance]` *`[as-number]`:* The EIGRP autonomous system number. *`[summary-address]`*: The IP address of the summary route. *`[subnet-mask]`*: The subnet mask of the summary route. *`[administrative-distance]`*: (Optional) An administrative distance to assign to the summary route. Option A is incorrect; there's no `summary-address` command directly under `router eigrp`. Option C is also incorrect; `auto-summary` is a different feature (automatic summarization at classful network boundaries, which is generally *not* recommended). Option D is incorrect; summarization is configured on the *sending*, not *receiving*, interface.",
      "examTip": "EIGRP route summarization is configured on the *outbound* interface using the `ip summary-address eigrp` command."
    },
    {
      "id": 6,
      "question": "A network administrator is troubleshooting a wireless network. Users report intermittent connectivity and slow performance. The administrator suspects interference from other devices operating in the 2.4 GHz band. Which tool would be MOST effective in identifying sources of RF interference in the 2.4 GHz band?",
      "options":[
        "A cable tester.",
        "A protocol analyzer (like Wireshark).",
        "A spectrum analyzer.",
        "A toner and probe."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A *spectrum analyzer* is specifically designed to measure and display the radio frequency (RF) spectrum. It shows the signal strength at different frequencies, allowing you to identify sources of interference, such as: *Other Wi-Fi networks:*  Operating on overlapping channels. *Non-Wi-Fi devices:*  Microwave ovens, Bluetooth devices, cordless phones, and other devices that emit RF signals in the 2.4 GHz band. A cable tester checks *physical cables*. A protocol analyzer captures *network traffic*, but it doesn't directly show the *RF environment*. A toner and probe *locates* cables.",
      "examTip": "Use a spectrum analyzer to identify sources of RF interference in wireless networks."
    },
    {
      "id": 7,
      "question":"What is 'MAC address flooding', and what is the primary security risk it poses?",
      "options":[
        "A method for encrypting network traffic.",
        "A technique for assigning IP addresses dynamically.",
        "An attack that targets the MAC address learning mechanism of switches, overwhelming the switch's CAM table with fake MAC addresses, causing it to act like a hub and flood traffic to all ports, allowing an attacker to eavesdrop on network traffic.",
        "A way to prioritize different types of network traffic."
      ],
      "correctAnswerIndex": 2,
      "explanation":"Switches learn MAC addresses and associate them with specific ports, storing this information in a CAM (Content Addressable Memory) table. In a MAC flooding attack, the attacker sends a large number of frames with *different, fake source MAC addresses*. This fills up the switch's CAM table. When the CAM table is full, the switch can no longer learn new MAC addresses and, in many cases, will start behaving like a *hub*, *flooding* traffic out *all ports*. This allows the attacker to potentially *sniff* (eavesdrop on) traffic that they shouldn't be able to see, compromising network security. It's *not* encryption, DHCP, or QoS.",
      "examTip":"MAC flooding attacks can compromise network security by causing switches to flood traffic, allowing attackers to eavesdrop."
    },
    {
      "id": 8,
      "question": "A user reports being unable to access a specific internal web server by its hostname (e.g., `intranet.example.com`). The user *can* ping the server's IP address successfully. Other users *can* access the server by its hostname. What is the MOST likely cause, and what is a specific command-line tool you could use on the affected user's *Windows* machine to investigate *further*?",
      "options": [
        "The server is down.",
        "The user's network cable is faulty.",
        "The problem is likely with the user's *local* DNS resolver cache or hosts file. Use `ipconfig /flushdns` to clear the DNS cache, and check the hosts file for any incorrect entries.",
        "The default gateway is configured incorrectly."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Since the user *can* ping the server's IP address, basic network connectivity is working, ruling out a cable problem or a *completely* down server. Since *other* users can access the server by hostname, the problem is *local* to the affected user's computer. The most likely causes are: *Corrupted DNS Cache:* The user's computer might have an outdated or incorrect entry in its local DNS cache, mapping the hostname to the wrong IP address. *Hosts File Entry:* The user's computer might have a static entry in its `hosts` file that overrides DNS resolution and points the hostname to the wrong IP address. The *best first step* is to *clear the DNS cache* using `ipconfig /flushdns` on a Windows machine. If that doesn't work, check the `hosts` file for any incorrect entries. The default gateway is for *external* communication; this is an *internal* server.",
      "examTip": "If a user can ping a server by IP but not by name, and other users *can* access it by name, suspect a local DNS caching or hosts file issue on the user's machine."
    },
    {
      "id": 9,
      "question": "Which of the following statements BEST describes 'defense in depth' as a network security strategy?",
      "options":[
        "Relying solely on a single, powerful firewall for all network security.",
        "Implementing multiple, overlapping layers of security controls (physical, technical, administrative, and procedural) so that if one layer fails or is bypassed, others are still in place to protect the network and its assets.",
        "Using only very strong, unique passwords for all user accounts.",
        "Encrypting all network traffic, both internally and externally."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Defense in depth is a security strategy that recognizes that *no single security measure is perfect*. It involves implementing *multiple*, *overlapping* layers of security controls, such as: *Physical security:* Access controls to buildings and data centers. *Technical controls:* Firewalls, intrusion prevention systems, antivirus software, encryption, strong authentication. *Administrative controls:* Security policies, procedures, user training. *Procedural Controls:* Incident response plans, disaster recovery plans If one layer of security is compromised, other layers are still in place to prevent or mitigate the damage. It's *not* about relying on just *one* thing (firewall, passwords, encryption).",
      "examTip": "Defense in depth is a fundamental security principle: don't rely on a single security measure; use multiple, overlapping layers of protection."
    },
    {
      "id": 10,
      "question": "You are configuring OSPF on a Cisco router that connects to multiple areas. You want to prevent detailed routing information from one area from being advertised into another area, reducing the size of the routing tables and improving routing efficiency. Which type of OSPF area would you configure to achieve this, and what is the key characteristic of that area type?",
      "options":[
        "Standard area; it allows all types of OSPF LSAs.",
        "Stub area; it blocks external LSAs (Type 5) and summarizes routes from other areas.",
        "Totally stubby area; it blocks external LSAs (Type 5) and summary LSAs (Type 3 and 4) from other areas, relying on a default route for external destinations.",
        "Not-so-stubby area (NSSA); it allows a limited form of external route injection while still blocking most external routes."
      ],
      "correctAnswerIndex": 2,
      "explanation": "OSPF areas help manage routing information and reduce the size of routing tables. Different area types offer different levels of summarization and filtering: *Standard Area:* Allows all types of OSPF LSAs (Link State Advertisements). *Stub Area:* Blocks *external* LSAs (Type 5), which represent routes learned from *outside* the OSPF domain. It summarizes routes from *other areas* using a default route. *Totally Stubby Area:* Even *more* restrictive than a stub area. It blocks *both* external LSAs (Type 5) *and summary LSAs (Type 3 and 4)* from *other areas*. Routers in a totally stubby area rely on a *default route* for *all* destinations outside the area. *Not-So-Stubby Area (NSSA):* A special type of area that allows a *limited* form of external route injection (using Type 7 LSAs) while still blocking *most* external routes. Since the question asks for preventing *detailed* routing information from one area being advertised into another, the *Totally Stubby Area* is the *most restrictive* and therefore the *best* answer. It minimizes the routing information exchanged, relying on a default route for external destinations.",
      "examTip": "Use totally stubby areas in OSPF to minimize the amount of routing information exchanged between areas, relying on a default route for external destinations."
    },
    {
      "id": 11,
      "question": "A network is experiencing intermittent connectivity issues. Packet captures reveal a high number of TCP retransmissions, duplicate ACKs, and out-of-order packets.  Additionally, you observe that the TCP window size advertised by the receiving host is frequently very small, and you see occasional 'TCP ZeroWindow' messages. What is the MOST precise technical term for the condition affecting the receiving host, and what are the likely underlying causes?",
      "options": [
        "Network congestion; caused by too much traffic on the network.",
        "TCP receive window exhaustion; caused by the receiving host's inability to process incoming data quickly enough (due to CPU overload, memory exhaustion, slow disk I/O, or network interface buffer limitations), leading to buffer filling and reduced/zero advertised window sizes.",
        "DNS resolution failure; caused by a misconfigured or unavailable DNS server.",
        "A faulty network cable; caused by physical damage to the cable."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The most precise term is *TCP receive window exhaustion*. The combination of symptoms points directly to this: *TCP Retransmissions & Duplicate ACKs:* Indicate packet loss, which *can* be caused by congestion, but also by other factors. *Out-of-Order Packets:*  Further suggest packet loss and reordering. *Small/Zero TCP Window Size:* This is the key. The TCP *receive window* is the amount of data the receiver is willing to accept at any given time. If the receiver's buffer fills up (because it can't process data fast enough), it *reduces* its advertised window size, even to *zero* (ZeroWindow), telling the sender to slow down or stop. *Causes:* The underlying causes are typically resource bottlenecks on the *receiving host*:  *CPU overload*, *Memory exhaustion*, *Slow disk I/O*, *Network interface buffer limitations*. While *network congestion* can *contribute* (by causing delays and packet loss), the ZeroWindow messages specifically indicate a *receiver-side* problem. It's *not* primarily DNS, and a cable fault would likely cause *complete* loss, not these specific TCP symptoms.",
      "examTip": "TCP receive window exhaustion, indicated by small/zero advertised window sizes, signifies a receiver-side bottleneck and severely impacts TCP throughput."
    },
    {
      "id": 12,
      "question": "A network administrator is configuring a Cisco router to redistribute routes learned from EIGRP into OSPF. EIGRP is running with autonomous system number 100, and OSPF is running with process ID 1. Which of the following commands, entered in router configuration mode for OSPF, would correctly redistribute EIGRP routes into OSPF, and what is a crucial consideration for EIGRP redistribution?",
      "options": [
        "router ospf 1 \n redistribute eigrp 100",
        "router ospf 1 \n redistribute eigrp 100 subnets",
        "router ospf 1 \n redistribute eigrp 100 metric-type 1",
        "router ospf 1 \n redistribute eigrp 100 subnets metric-type 1"
      ],
      "correctAnswerIndex": 3,
      "explanation": "To redistribute routes from one routing protocol into another on a Cisco router, you use the `redistribute` command *within the configuration of the destination routing protocol*.  In this case, we're redistributing *into* OSPF, so the command goes under `router ospf 1`. The basic syntax is: `redistribute [source-protocol] [process-id/as-number] [options]` Here's what's needed and *why* the correct answer is the most complete: `redistribute eigrp 100`:  Specifies that we're redistributing routes from EIGRP autonomous system 100. `subnets`:  This keyword is *crucial* when redistributing into OSPF. By default, OSPF will *only* redistribute classful networks.  The `subnets` keyword tells OSPF to redistribute *subnetted* routes as well.  Without this, many routes might not be redistributed. `metric-type 1` or `metric-type 2`: This sets the OSPF metric type for the redistributed routes.  Type 1 (E1) adds the internal OSPF cost to the external metric. Type 2 (E2) only uses the external metric (this is the default).  Choosing the appropriate metric type is important for proper route selection within OSPF. While Option 1 will redistribute, it's not best practice. While Option B gets the subnets in, the default metric is not ideal. Option C sets a metric, but omits the subnets. So, Option D is the only that redistributes all necessary routes.",
      "examTip": "When redistributing routes into OSPF, always include the `subnets` keyword to redistribute subnetted routes, and consider using `metric-type` to control how the OSPF metric is calculated."
    },
    {
      "id": 13,
      "question": "A network administrator is troubleshooting a wireless network. Users report intermittent connectivity and slow speeds. The administrator suspects interference from other devices operating in the same frequency band.  Which tool is specifically designed to identify and analyze sources of radio frequency (RF) interference?",
      "options": [
        "A cable tester.",
        "A protocol analyzer (like Wireshark).",
        "A spectrum analyzer.",
        "A toner and probe."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A *spectrum analyzer* is a device specifically designed to measure and display the radio frequency (RF) spectrum. It shows the signal strength at different frequencies, allowing you to identify sources of interference, such as: *Other Wi-Fi networks:* Operating on the same or overlapping channels. *Non-Wi-Fi devices:* Microwave ovens, Bluetooth devices, cordless phones, and other devices that emit RF signals in the same frequency band (e.g., 2.4 GHz). A cable tester checks *physical cables*. A protocol analyzer captures and analyzes *network traffic*, but it doesn't directly show the *RF environment*. A toner and probe *locates* cables.",
      "examTip": "Use a spectrum analyzer to identify sources of RF interference affecting wireless network performance."
    },
    {
      "id": 14,
      "question": "A network administrator is configuring a Cisco switch and wants to prevent a rogue DHCP server from operating on a specific port. They configure the port as a DHCP snooping 'untrusted' port.  What is the specific effect of this configuration on DHCP traffic received on that port?",
      "options":[
        "All DHCP traffic on the port is blocked.",
        "All DHCP traffic on the port is allowed.",
        "DHCP client requests (like DHCPDISCOVER, DHCPREQUEST) are forwarded, but DHCP server responses (like DHCPOFFER, DHCPACK, DHCPNAK) are dropped.",
        "DHCP traffic is encrypted."
      ],
      "correctAnswerIndex": 2,
      "explanation": "DHCP snooping is a switch security feature that prevents rogue DHCP servers. It classifies switch ports as *trusted* or *untrusted*: *Trusted ports:*  Ports connected to legitimate DHCP servers (usually configured manually).  The switch allows *all* DHCP traffic on these ports. *Untrusted ports:* Ports connected to client devices (or potentially to rogue servers).  The switch *only* allows *DHCP client* requests (like DHCPDISCOVER, DHCPREQUEST, DHCPRELEASE) to be forwarded *from* these ports. It *drops* any *DHCP server* responses (like DHCPOFFER, DHCPACK, DHCPNAK) received on untrusted ports. This prevents a rogue server on an untrusted port from assigning IP addresses. It's *not* about blocking *all* DHCP traffic, allowing *all* traffic, or encryption.",
      "examTip": "DHCP snooping on a switch classifies ports as trusted (for DHCP servers) or untrusted (for clients) to prevent rogue DHCP servers."
    },
    {
      "id": 15,
      "question": "You are configuring a Cisco router to act as a DHCP server for the 192.168.1.0/24 network.  You want to ensure that the router itself (which has an IP address of 192.168.1.1 on its interface connected to this network) does *not* lease an address from the DHCP pool it's serving.  You also want to reserve the addresses 192.168.1.2 through 192.168.1.10 for static assignment.  Additionally, a specific device with MAC address 00:11:22:33:44:55 should *always* receive the IP address 192.168.1.50.  Which set of commands, entered in global configuration mode *and* interface configuration mode (as appropriate), would achieve all of this?",
      "options": [
        "ip dhcp pool MYPOOL \n network 192.168.1.0 255.255.255.0 \n default-router 192.168.1.1 \n dns-server 8.8.8.8",
        "ip dhcp pool MYPOOL \n network 192.168.1.0 255.255.255.0 \n default-router 192.168.1.1 \n dns-server 8.8.8.8 \n ip dhcp excluded-address 192.168.1.1 192.168.1.10 \n host 192.168.1.50 255.255.255.0 \n client-identifier 0100.1122.3344.55",
        "ip dhcp pool MYPOOL \n network 192.168.1.0 255.255.255.0 \n default-router 192.168.1.1 \n dns-server 8.8.8.8 \n ip dhcp excluded-address 192.168.1.1 192.168.1.10 \n ip dhcp excluded-address 192.168.1.254 \n host 192.168.1.50 255.255.255.0 \n  client-identifier 0100.1122.3344.55.00",
        "ip dhcp pool MYPOOL \n network 192.168.1.0 255.255.255.0 \n default-router 192.168.1.1 \n dns-server 8.8.8.8 \n ip dhcp excluded-address 192.168.1.2 192.168.1.10 \n ip dhcp excluded-address 192.168.1.1\n ip dhcp excluded-address 192.168.1.254 \n host 192.168.1.50 255.255.255.0 \n client-identifier 0100.1122.3344.55"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Several things need to be configured, all under the DHCP pool: 1. **`ip dhcp pool MYPOOL`**: Creates the DHCP pool named \"MYPOOL.\" 2. **`network 192.168.1.0 255.255.255.0`**: Defines the network and subnet mask for the pool. 3. **`default-router 192.168.1.1`**: Sets the default gateway that will be assigned to clients. 4. **`dns-server 8.8.8.8`**: Sets the DNS server(s) that will be assigned to clients. 5. **`ip dhcp excluded-address 192.168.1.2 192.168.1.10`**: *Excludes* the range of addresses 192.168.1.2-192.168.1.10 from being assigned by DHCP. 6.  **`ip dhcp excluded-address 192.168.1.1`**: *Excludes* the single address 192.168.1.1 (the router's own interface IP). This is crucial. 7. **`ip dhcp excluded-address 192.168.1.254`** Excludes the 192.168.1.254 from being assigned. 8. **`host 192.168.1.50 255.255.255.0`:** Creates a static mapping within the DHCP pool for a specific client. 9.  **`client-identifier 0100.1122.3344.55`**: This is the correct way to specify the MAC address for the static mapping, which includes the leading `01` for Ethernet. The MAC `00:11:22:33:44:55`, is represented as `0100.1122.3344.55`. Option A is incomplete (doesn't exclude addresses or create a static mapping). Option B is close but doesn't exclude all the necessary addresses, and uses an incorrect format. Option C has errors with the `client-identifier`. Option D is the most accurate. ",
      "examTip": "To create a static mapping (reservation) within a DHCP pool on a Cisco router, use the `host` command with the `client-identifier` (using the correct MAC address format). Also, *always* exclude the router's own IP address from the DHCP pool it serves."
    },
    {
      "id": 16,
      "question": "A network administrator observes that a router running OSPF is not forming an adjacency with a neighboring router. Both routers are directly connected, and IP connectivity between them is confirmed. The administrator suspects a configuration issue. Which of the following commands, executed on the router, would provide the MOST comprehensive information to diagnose the problem, including OSPF interface settings, area membership, neighbor status, and potential misconfigurations?",
      "options":[
        "show ip route ospf",
        "show ip ospf neighbor",
        "show ip ospf interface brief",
        "show ip ospf database",
        "show ip ospf"
      ],
      "correctAnswerIndex": 4,
      "explanation": "While other commands provide *pieces* of information, `show ip ospf` gives the most comprehensive overview of the OSPF configuration and status on the router, including: *Process ID* *Router ID* *Area information (including configured areas and their types)* *Interface information (including IP address, area, cost, state, hello/dead intervals, neighbors)* *Neighbors (detailed information about each neighbor, including state, adjacency status)* *Routing table information (summary of OSPF routes)* *OSPF-related counters and statistics* This single command provides a broad view that helps pinpoint various potential issues: mismatched area IDs, incorrect network types, hello/dead interval mismatches, authentication problems, interface misconfigurations, etc. `show ip route ospf` (*A*) only shows OSPF *routes*. `show ip ospf neighbor` (*B*) only shows *neighbor* information, not interface settings. `show ip ospf interface brief` (*C*) shows a *summary* of interface status, but not the detailed configuration like area membership and timers that `show ip ospf` provides. `show ip ospf database` shows the LSDB, but it doesn't give you the *running configuration* like areas. The MOST complete and comprehensive is `show ip ospf`",
      "examTip": "Use `show ip ospf` for a comprehensive overview of the OSPF configuration and status on a Cisco router, including interface details, neighbor information, and area configuration."
    },
    {
      "id": 17,
      "question": "A network is experiencing intermittent connectivity issues.  Packet captures reveal a large number of TCP retransmissions and out-of-order packets.  Additionally, you observe that the TCP window size advertised by the receiving host is frequently very small, and you see occasional 'TCP ZeroWindow' messages with the code 'Fragmentation Needed and DF set'. What is the MOST likely underlying cause of these symptoms, and what is the BEST solution?",
      "options": [
        "A DNS server misconfiguration.",
        "A DHCP server failure.",
        "An MTU mismatch along the path between the communicating devices. The solution is to ensure that Path MTU Discovery (PMTUD) is working correctly or to manually configure a consistent MTU across all devices and interfaces along the path.",
        "A faulty network cable."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The combination of symptoms points directly to an *MTU (Maximum Transmission Unit) mismatch*: *TCP Retransmissions & Out-of-Order Packets:* Indicate packet loss. *ICMP Destination Unreachable (Fragmentation Needed and DF set):* This is the key. This ICMP message means that a router along the path needed to *fragment* a packet because it was too large for the next hop's MTU, *but* the packet had the *Don't Fragment (DF)* bit set in the IP header.  When the DF bit is set, routers are *not allowed* to fragment the packet; instead, they must drop it and send this ICMP error message back to the sender. The *sender* is supposed to learn the path MTU and adjust its packet size accordingly (this is *Path MTU Discovery - PMTUD*). However, PMTUD often *fails* because firewalls frequently block ICMP messages. The *best* solution is to: 1. *Ensure PMTUD works:*  Make sure firewalls allow the necessary ICMP messages. 2. *If PMTUD can't be reliably enabled, manually configure a consistent MTU* across all devices and interfaces along the path. This prevents fragmentation in the first place. It's *not* a DNS or DHCP issue, and while a cable *could* cause packet loss, it wouldn't directly cause *these specific* ICMP messages.",
      "examTip": "ICMP 'Destination Unreachable (Fragmentation Needed and DF set)' messages, combined with TCP retransmissions, indicate an MTU mismatch; ensure PMTUD is working or manually configure a consistent MTU."
    },
    {
      "id": 18,
      "question": "You are configuring a Cisco router to participate in OSPF routing. You want the router to be part of OSPF area 0. The router has three interfaces: GigabitEthernet0/0 (192.168.1.1/24), GigabitEthernet0/1 (10.0.0.1/24), and Serial0/0/0 (172.16.1.1/30).  Which of the following sets of commands, entered in global configuration mode, will correctly configure OSPF and include *all* of these interfaces in area 0?",
      "options":[
        "router ospf 1 \n network 192.168.1.0 255.255.255.0 area 0 \n network 10.0.0.0 255.255.255.0 area 0 \n network 172.16.1.0 255.255.255.252 area 0",
        "router ospf 1 \n network 192.168.1.0 0.0.0.255 area 0 \n network 10.0.0.0 0.0.0.255 area 0 \n network 172.16.1.0 0.0.0.3 area 0",
        "router ospf 1 \n network 0.0.0.0 255.255.255.255 area 0",
        "router ospf 1 \n area 0 range 192.168.1.0 255.255.255.0"
      ],
      "correctAnswerIndex": 1,
      "explanation": "To enable OSPF and include interfaces in a specific area, you use the `network` command *within* the OSPF process configuration (`router ospf [process-id]`). Crucially, the `network` command uses *wildcard masks*, not subnet masks. The correct commands are: ``` router ospf 1 network 192.168.1.0 0.0.0.255 area 0 network 10.0.0.0 0.0.0.255 area 0 network 172.16.1.0 0.0.0.3 area 0 ``` *`router ospf 1`*: Enables OSPF with process ID 1. *`network 192.168.1.0 0.0.0.255 area 0`*: Includes the interface with an IP address in the 192.168.1.0/24 network in area 0. (Wildcard mask 0.0.0.255 is the inverse of 255.255.255.0). *`network 10.0.0.0 0.0.0.255 area 0`*: Includes the interface with an IP in the 10.0.0.0/24 network in area 0. *`network 172.16.1.0 0.0.0.3 area 0`*: Includes the interface with an IP in the 172.16.1.0/30 network in area 0. Option A uses *subnet masks* instead of wildcard masks, which is incorrect. Option C uses a single `network` command that covers all addresses, which is generally *not recommended* for OSPF. Option D is for *summarizing* routes within an area, not for defining participating networks.",
      "examTip": "The `network` command in OSPF configuration uses *wildcard masks* (the inverse of subnet masks) to define which interfaces participate in OSPF."
    },
    {
      "id": 19,
      "question": "A network is experiencing intermittent connectivity issues.  A network administrator captures network traffic using a protocol analyzer and observes a large number of TCP RST packets. What does the presence of numerous TCP RST packets typically indicate, and what are some potential underlying causes?",
      "options":[
        "Normal TCP connection establishment.",
        "Abrupt termination of TCP connections. Potential causes include: application crashes, firewall rules blocking traffic or resetting connections, network devices forcibly closing connections, or misconfigured TCP keepalive settings.",
        "Successful DNS resolution.",
        "Successful DHCP address assignment."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A TCP RST (reset) packet signifies an *abrupt termination* of a TCP connection. It's *not* part of the normal connection establishment (SYN, SYN-ACK, ACK) or graceful teardown (FIN, FIN-ACK, ACK) process.  A large number of RST packets indicates that connections are being *forcibly closed*. Potential causes include: *Application crashes:* If an application crashes, the operating system might send RST packets to close any open TCP connections. *Firewall rules:* A firewall might be configured to send RST packets to block certain types of traffic or to close connections that violate security policies. *Network devices:* Routers or other network devices might be configured to forcibly close connections (e.g., due to security policies, resource constraints, or misconfiguration). *Misconfigured TCP keepalives:* If keepalive settings are too aggressive, connections might be prematurely terminated. It's *not* normal operation, and it's *not* directly related to DNS or DHCP (though issues with those *could* cause *other* problems).",
      "examTip": "A large number of TCP RST packets indicates abrupt termination of TCP connections, often due to application issues, firewall rules, or network device intervention."
    },
    {
      "id": 20,
      "question": "You are configuring a site-to-site IPsec VPN between two Cisco routers. You have configured the ISAKMP policy (Phase 1) and the IPsec transform set (Phase 2).  However, the VPN tunnel is not establishing. Which of the following commands on the Cisco router would be MOST helpful in troubleshooting the ISAKMP (Phase 1) negotiation process?",
      "options": [
        "show ip route",
        "show crypto isakmp sa",
        "show crypto ipsec sa",
        "show interfaces"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`show crypto isakmp sa` displays the status of *Internet Security Association and Key Management Protocol (ISAKMP)* Security Associations (SAs). ISAKMP is used in *Phase 1* of IPsec to establish a secure, authenticated channel for negotiating the IPsec SAs (Phase 2). This command shows you: *Whether ISAKMP SAs are being established.* *The peer IP address.* *The IKE phase 1 policy being used.* *The state of the SA (e.g., QM_IDLE, MM_ACTIVE).* If there are problems with ISAKMP (Phase 1), you won't see any active SAs, or you might see SAs stuck in a non-active state. `show ip route` shows the routing table. `show crypto ipsec sa` shows the *IPsec SAs* (Phase 2), which won't be established if Phase 1 fails. `show interfaces` shows general interface status, but not ISAKMP-specific details.",
      "examTip": "Use `show crypto isakmp sa` to troubleshoot ISAKMP (Phase 1) issues in IPsec VPN tunnel establishment."
    },
    {
      "id": 21,
      "question": "A network administrator is designing a wireless network for a large, open office space with many users. They want to maximize throughput and minimize interference. They are using the 5 GHz band. Approximately how many *non-overlapping* channels are available in the 5 GHz band for use in the United States, and why is using non-overlapping channels important?",
      "options":[
        "3 non-overlapping channels; using non-overlapping channels prevents interference.",
        "Approximately 25 non-overlapping channels (depending on channel width and regulatory domain); using non-overlapping channels prevents co-channel interference, where access points and clients on the same or overlapping channels must contend for airtime, reducing performance.",
        "11 non-overlapping channels; using non-overlapping channels prevents loops.",
        "Unlimited non-overlapping channels; using non-overlapping channels allows for dynamic frequency selection."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The 5 GHz band offers significantly *more* non-overlapping channels than the 2.4 GHz band. The exact number depends on: *Regulatory domain:* Different countries/regions have different rules about which 5 GHz channels are allowed. *Channel width:* Wider channels (40 MHz, 80 MHz, 160 MHz) provide higher throughput but reduce the number of non-overlapping channels. In the United States, with standard 20 MHz channels, there are *approximately 25 non-overlapping channels* available in the 5 GHz band (this number can vary slightly depending on specific regulations and newer standards). Using *non-overlapping channels* is crucial to prevent *co-channel interference*. If access points (and their associated clients) operate on the *same or overlapping channels*, they must *contend* for airtime, which reduces performance and increases latency. It's *not* 3, 11, or unlimited. And it prevents interference, not loops.",
      "examTip": "The 5 GHz band offers a significantly larger number of non-overlapping channels than the 2.4 GHz band, making it better suited for high-density wireless deployments."
    },
    {
      "id": 22,
      "question": "What is 'DHCP starvation', and what combination of switch security features can be used to mitigate this type of attack?",
      "options":[
        "DHCP starvation is a method for encrypting DHCP traffic.",
        "DHCP starvation is a technique for increasing the speed of IP address assignment.",
        "DHCP starvation is a denial-of-service attack where an attacker floods the network with DHCP requests using spoofed MAC addresses, attempting to exhaust the DHCP server's pool of available IP addresses, preventing legitimate clients from obtaining IP addresses. DHCP snooping and port security can be used together to mitigate this.",
        "DHCP starvation is a protocol for translating domain names to IP addresses."
      ],
      "correctAnswerIndex": 2,
      "explanation":"DHCP starvation is a DoS attack that targets DHCP servers. The attacker sends a flood of DHCP requests, often with *spoofed* (fake) MAC addresses, trying to use up all the available IP addresses in the DHCP server's pool. This prevents legitimate clients from obtaining IP addresses and connecting to the network. *Mitigation:* *DHCP Snooping:* A switch security feature that inspects DHCP messages and only allows DHCP traffic from trusted sources (typically, designated DHCP server ports). This prevents rogue DHCP servers from operating. *Port Security:* Limits the number of MAC addresses allowed on a switch port. This can help prevent an attacker from sending a large number of DHCP requests with different spoofed MAC addresses from a single port. It's *not* encryption, a speed-up technique, or DNS.",
      "examTip":"DHCP starvation attacks exhaust the DHCP server's address pool; mitigate with DHCP snooping and port security on switches."
    },
    {
      "id": 23,
      "question": "A network administrator configures a Cisco switch port with the following commands: `switchport mode access` `switchport port-security` `switchport port-security maximum 1` `switchport port-security mac-address sticky` `switchport port-security violation protect` What is the effect of the `violation protect` mode in this port security configuration?",
      "options":[
        "The port will be shut down (err-disabled) if a security violation occurs.",
        "The port will drop traffic from unknown MAC addresses, but it will *not* increment the violation counter or send an SNMP trap/syslog message.",
        "The port will drop traffic from unknown MAC addresses and increment the violation counter, and it may send an SNMP trap or syslog message (depending on configuration).",
        "The port will allow traffic from any MAC address."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Port security on a Cisco switch has three violation modes: *`protect`*: This is the *least disruptive* mode. When a security violation occurs (e.g., a device with an unauthorized MAC address tries to connect), the port will *drop* traffic from the unknown MAC address.  *Crucially*, it will *not* increment the violation counter, and it will *not* send an SNMP trap or syslog message.  This makes it the *least noticeable* violation mode. *`restrict`*:  Similar to `protect`, the port drops traffic from unknown MAC addresses. *However*, it *does* increment the violation counter and can be configured to send an SNMP trap or syslog message. *`shutdown`*:  This is the *most disruptive* mode. The port is put into the *err-disabled* state (shut down) when a violation occurs.  It requires manual intervention (or configuration of errdisable recovery) to re-enable the port. The `sticky` option *dynamically learns and secures* the MAC. The key here is understanding what each `violation` mode does. `protect` is silent.",
      "examTip": "The `switchport port-security violation protect` mode on a Cisco switch drops traffic from unknown MAC addresses without incrementing the violation counter or generating alerts."
    },
    {
      "id": 24,
      "question": "You are designing a high-availability network. You have configured HSRP (Hot Standby Router Protocol) on two routers to provide a virtual gateway for the local network.  What is the purpose of the HSRP *priority*, and how does it affect the election of the active router?",
      "options": [
        "The HSRP priority determines the order in which routes are added to the routing table.",
        "The HSRP priority determines which router will become the *active* router. The router with the *higher* priority becomes the active router. If priorities are equal, the router with the highest IP address on the HSRP-configured interface becomes active.",
        "The HSRP priority determines the speed of the network connection.",
        "The HSRP priority determines the encryption method used for HSRP communication."
      ],
      "correctAnswerIndex": 1,
      "explanation": "HSRP (and VRRP, a similar protocol) provides *gateway redundancy*. Multiple routers share a *virtual IP address* and *virtual MAC address*, which is used as the default gateway by clients on the network. Only *one* router is *active* at a time, forwarding traffic for the virtual IP. The *HSRP priority* determines which router is initially elected as the *active* router. *Higher priority wins*. If priorities are *equal*, the router with the *highest IP address* on the interface configured for HSRP becomes active. The priority *doesn't* affect routing table order, network speed, or encryption.",
      "examTip": "The HSRP priority determines which router is active; the router with the higher priority wins the election."
    },
    {
      "id": 25,
      "question": "A network administrator is troubleshooting an OSPF routing issue. They suspect a problem with the OSPF hello packets. Which of the following statements about OSPF hello packets is FALSE?",
      "options":[
        "OSPF hello packets are used to discover OSPF neighbors and establish adjacencies.",
        "OSPF hello packets are sent periodically to maintain neighbor relationships.",
        "OSPF hello packets contain information such as the router ID, area ID, hello interval, dead interval, and a list of neighbors.",
        "OSPF hello packets are encrypted by default to ensure secure communication."
      ],
      "correctAnswerIndex": 3,
      "explanation": "OSPF hello packets are *multicast* packets used for: *Neighbor discovery:* Routers send hellos to discover other OSPF routers on the same network segment. *Adjacency establishment:*  Once neighbors are discovered, they exchange information to form adjacencies. *Maintaining neighbor relationships:*  Hellos are sent *periodically* to ensure that neighbors are still alive. Hello packets *do* contain important information like: *Router ID* *Area ID* *Hello Interval* *Dead Interval* *Network Mask* *List of Neighbors* (seen by the router) *Authentication data* (if configured) However, OSPF hello packets are *not encrypted by default*.  OSPF *can* be configured to use authentication (e.g., MD5), which provides integrity checks and prevents unauthorized routers from joining the OSPF domain, but this is *not enabled by default*.  Plaintext hellos are the norm unless authentication is explicitly configured.",
      "examTip": "OSPF hello packets are used for neighbor discovery and maintenance, but they are not encrypted by default; OSPF authentication must be explicitly configured."
    }
  ]
});









    {
  "questions": [
    {
      "id": 26,
      "question": "What is 'BGP route reflection', and in what type of BGP deployment is it typically used to simplify configuration and reduce the number of iBGP sessions?",
      "options":[
        "BGP route reflection is a technique for summarizing routes advertised between different autonomous systems.",
        "BGP route reflection is a mechanism used in large *internal* BGP (iBGP) deployments to avoid the need for a full mesh of iBGP sessions between all iBGP speakers. A route reflector reflects routes learned from one iBGP peer to other iBGP peers.",
        "BGP route reflection is a method for encrypting BGP routing updates.",
        "BGP route reflection is a technique for load balancing traffic across multiple BGP paths."
      ],
      "correctAnswerIndex": 1,
      "explanation": "BGP route reflection is a scalability mechanism used *within* an autonomous system (AS) in *internal BGP (iBGP)* deployments. Normally, iBGP requires a *full mesh* – every iBGP router must have a direct iBGP session with every other iBGP router in the AS. This can become unmanageable in large networks. *Route reflection* solves this: *Route Reflectors (RRs):* Designated routers act as route reflectors. *Clients:* Other iBGP routers are configured as clients of the route reflector. *Reflection:* The RR *reflects* (re-advertises) routes learned from one iBGP client to other iBGP clients. This eliminates the need for every iBGP router to peer directly with every other iBGP router. It's *not* about summarizing routes between *different* ASes (that's external BGP), encryption, or load balancing.",
      "examTip": "BGP route reflection simplifies iBGP configuration in large networks by avoiding the need for a full mesh of iBGP sessions."
    },
    {
      "id": 27,
      "question": "You are configuring a site-to-site IPsec VPN between two Cisco routers.  You have configured the ISAKMP policy (Phase 1) and are now configuring the IPsec transform set (Phase 2). Which of the following statements about the IPsec transform set is TRUE?",
      "options": [
        "The transform set defines the encryption and hashing algorithms used for ISAKMP (Phase 1) negotiation.",
        "The transform set defines the security protocols (AH or ESP), encryption algorithms (e.g., AES, 3DES), and hashing algorithms (e.g., SHA, MD5) used to protect the actual data traffic flowing through the IPsec tunnel (Phase 2).",
        "The transform set defines the IP addresses of the VPN peers.",
        "The transform set defines the routing protocol used within the VPN tunnel."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The IPsec VPN establishment process has two phases: *Phase 1 (ISAKMP):* Establishes a secure, authenticated channel for negotiating the IPsec SAs. The *ISAKMP policy* defines the parameters for this phase (encryption, hashing, authentication, Diffie-Hellman group, lifetime). *Phase 2 (IPsec):* Establishes the *IPsec SAs* themselves, which protect the *actual data traffic* flowing through the VPN tunnel. The *transform set* defines the parameters for Phase 2: *Security Protocol:* AH (Authentication Header) or ESP (Encapsulating Security Payload). AH provides authentication and integrity, but *not* confidentiality. ESP provides confidentiality (encryption), authentication, and integrity. *Encryption Algorithm:*  AES, 3DES, DES (for confidentiality - if using ESP). *Hashing Algorithm:* SHA-1, SHA-256, SHA-384, MD5 (for integrity). The transform set is *not* about Phase 1, peer IPs, or routing protocols *within* the tunnel.",
      "examTip": "The IPsec transform set defines the security protocols, encryption, and hashing algorithms used to protect data in Phase 2 of an IPsec VPN."
    },
    {
      "id": 28,
      "question": "A network administrator is troubleshooting an issue where a client device is unable to obtain an IP address from a DHCP server. The client is connected to a Cisco switch.  Which of the following commands on the switch would be MOST helpful in determining if the switch is receiving DHCP requests from the client and forwarding them to the DHCP server (assuming the server is on a different subnet and an IP helper address is configured)?",
      "options":[
        "show ip interface brief",
        "show ip dhcp binding",
        "show ip dhcp snooping binding",
        "debug ip dhcp server events"
      ],
      "correctAnswerIndex": 3,
      "explanation": "If the problem lies with DHCP itself, and you want to check activity *related to DHCP*, there are two key commands: *If DHCP Snooping is enabled*, `show ip dhcp snooping binding`. This is the BEST initial command because it directly shows if the *switch* sees DHCP requests and what it is doing with those requests. It's specifically designed for troubleshooting DHCP issues in a secure environment. This shows the MAC address, IP address, lease time, VLAN, and interface for clients who have *successfully* received an IP address via DHCP *through that switch*. If the client is *not* listed, it indicates a problem with the client's requests reaching the server, or with the server's responses reaching the client. *If DHCP Snooping is NOT enabled* , then a debug command will be the only way, use `debug ip packet detail` after setting an ACL to only view packets related to your client, this is the *most impactful* debug option, use with care. *However*, Option B. `show ip dhcp binding`, shows DHCP server activity *on the router itself* if it's the DHCP server, which in this case is NOT what we are looking for. Option A shows *general interface status*, but nothing specific to DHCP. The problem specifies the server is on a *different subnet*, meaning a helper is in place, making Option D unlikely to provide the *specific* information to the client.",
      "examTip": "Use `show ip dhcp snooping binding` to troubleshoot DHCP issues on a switch with DHCP snooping enabled; use focused debugging if snooping is not enabled."
    },
    {
      "id": 29,
      "question": "A network administrator is implementing Quality of Service (QoS) to prioritize voice traffic over data traffic. They are using DSCP (Differentiated Services Code Point) markings to classify traffic. Which DSCP value is commonly recommended for Expedited Forwarding (EF) of voice traffic, and what is the characteristic of the EF per-hop behavior (PHB)?",
      "options":[
        "DSCP 0 (Best Effort); best-effort delivery.",
        "DSCP 46 (EF); low-loss, low-latency, low-jitter, assured bandwidth service.",
        "DSCP 26 (AF31); assured forwarding with medium drop probability.",
        "DSCP 18 (CS2); class selector, backward compatible with IP Precedence."
      ],
      "correctAnswerIndex": 1,
      "explanation": "*DSCP 46 (EF - Expedited Forwarding)* is the *recommended* value for *voice traffic* (and other real-time, delay-sensitive applications). EF provides a *low-loss, low-latency, low-jitter, assured bandwidth* service. It's intended for applications that require the *highest priority* and the *strictest performance guarantees*. *DSCP 0 (Best Effort):* This is the *default*, and provides *no* QoS guarantees. *DSCP 26 (AF31):*  This is part of *Assured Forwarding (AF)*, which provides different levels of service assurance, but it's *not* as high a priority as EF. *DSCP 18 (CS2):* This is a *Class Selector* codepoint, backward compatible with IP Precedence 2 (which is *not* as high a priority as EF).",
      "examTip": "Use DSCP 46 (EF - Expedited Forwarding) for voice and other delay-sensitive real-time applications requiring the highest priority and lowest latency/jitter."
    },
    {
      "id": 30,
      "question": "A network uses EIGRP as its routing protocol. The network administrator wants to prevent certain EIGRP routing updates from being sent out a specific interface on a router. They do *not* want to completely disable EIGRP on the interface.  Which of the following commands, and in which configuration context, would achieve this?",
      "options": [
        "In global configuration mode: `passive-interface [interface-name]`",
        "Under the `router eigrp [autonomous-system-number]` configuration: `passive-interface [interface-name]`",
        "In interface configuration mode for the specific interface: `no ip eigrp [as-number]`",
        "In interface configuration mode for the specific interface: `ip summary-address eigrp [as-number] 0.0.0.0 0.0.0.0`"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `passive-interface` command, when used within a routing protocol configuration, prevents the router from *sending* routing updates *out* that interface. However, the router will *still receive* routing updates *on* that interface.  This is useful in situations where you want the router to *learn* routes from a neighbor on that interface but *not advertise* any routes to that neighbor. The command is entered under the `router eigrp [autonomous-system-number]` configuration, *not* in global configuration mode or interface configuration mode.  The correct sequence is: `router eigrp [as-number]` `passive-interface [interface-name]` Option A is incorrect because `passive-interface` is not a global command. Option C *disables* EIGRP on the interface entirely. Option D configures a summary route, which is a different function.",
      "examTip": "Use the `passive-interface` command within the routing protocol configuration to prevent a router from sending routing updates out a specific interface while still receiving updates on that interface."
    },
    {
      "id": 31,
      "question": "What is 'route poisoning', and how is it used in conjunction with split horizon to prevent routing loops in distance-vector routing protocols?",
      "options":[
        "Route poisoning is a method of encrypting routing updates to prevent unauthorized access.",
        "Route poisoning involves setting the metric for a failed route to infinity (making it unreachable) and advertising this poisoned route back to the neighbor from which the route was originally learned, preventing the neighbor from using the invalid route. Split horizon prevents advertising routes back on the interface they were received on.",
        "Route poisoning is a technique used to prioritize certain routes over others.",
        "Route poisoning is a method for load balancing traffic across multiple paths."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Route poisoning and split horizon are both loop-prevention techniques used in distance-vector routing protocols (like RIP). *Split horizon:* Prevents a router from advertising a route back out the *same interface* on which it *learned* that route. This helps prevent simple two-node loops. *Route poisoning:*  When a router detects that a route has failed, it sets the metric for that route to *infinity* (making it unreachable) and advertises this 'poisoned' route *back to all its neighbors*, including the neighbor from which it originally learned the route.  This is an *exception* to the split horizon rule, but it's done to *explicitly* inform the neighbor that the route is *no longer valid*. *Combined effect:* Split horizon prevents simple loops, and route poisoning helps to quickly propagate information about failed routes throughout the network, preventing more complex loops and speeding up convergence. It's *not* encryption, prioritization, or load balancing.",
      "examTip":"Route poisoning, combined with split horizon, is a key mechanism for preventing routing loops and speeding up convergence in distance-vector protocols."
    },
    {
      "id": 32,
      "question": "A network administrator suspects that an attacker is attempting a brute-force attack against a server's SSH service. Which of the following log entries, taken from the server's system logs, would provide the STRONGEST evidence of a brute-force attack?",
      "options":[
        "Multiple successful SSH login attempts from the same IP address.",
        "Repeated failed SSH login attempts, potentially from multiple source IP addresses, showing a pattern of different usernames and passwords being tried within a short time frame.",
        "A single failed SSH login attempt.",
        "Successful SSH login attempts from multiple different IP addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A brute-force attack involves systematically trying many different username/password combinations in an attempt to guess a valid credential. The *key indicators* are: *Repeated failed login attempts:*  This shows the attacker is trying many different credentials. *Short time frame:* The attempts are concentrated within a short period, indicating an automated process. *Potentially multiple source IP addresses:*  Attackers might use multiple sources to avoid IP-based blocking. *Pattern of usernames/passwords:*  The attempts might follow a pattern (e.g., trying common usernames, dictionary words). Option A shows *successful* logins, which is not a brute-force attack. Option C is a single failed attempt, not a pattern. Option D shows successful logins from *different* IPs, which could be legitimate. Only option B shows the *pattern* of repeated failures, indicating a brute-force attempt.",
      "examTip": "Look for repeated failed login attempts, potentially from multiple sources and within a short time frame, as evidence of a brute-force attack."
    },
    {
      "id": 33,
      "question": "You are designing a network that requires high availability and redundancy for critical servers.  Which of the following technologies, and how they are used together, would provide the MOST robust solution?",
      "options":[
        "A single, powerful server with redundant power supplies.",
        "Multiple servers configured in a cluster with automatic failover capabilities, redundant network interface cards (NICs) in each server with NIC teaming/bonding, connections to multiple, independent network switches, and those switches configured with a loop-free Layer 2 protocol (like RSTP or a proprietary link aggregation technology) and HSRP/VRRP for gateway redundancy.",
        "A strong firewall to protect the servers from external attacks.",
        "Regular data backups to an offsite location."
      ],
      "correctAnswerIndex": 1,
      "explanation": "High availability and fault tolerance require *redundancy* at *multiple levels*: *Server Redundancy:* Multiple servers configured in a *cluster* with *automatic failover*. If one server fails, another takes over its role seamlessly. *NIC Redundancy:* Each server should have *multiple NICs*, configured with *NIC teaming/bonding*. This provides both increased bandwidth and fault tolerance (if one NIC fails, the others continue to function). *Switch Redundancy:* The servers should be connected to *multiple, independent switches*. This prevents a single switch failure from isolating the servers. *Loop-Free Layer 2:* The switches must be configured with a loop-free Layer 2 protocol (like Rapid Spanning Tree Protocol - RSTP - or a proprietary link aggregation technology) to prevent network loops when redundant links are present. *Gateway Redundancy:* Use HSRP (Hot Standby Router Protocol) or VRRP (Virtual Router Redundancy Protocol) on the routers (or Layer 3 switches) that provide the default gateway for the servers. This ensures that if the primary gateway fails, a backup gateway takes over. A *single server* (*A*), even with redundant power, is a single point of failure. A firewall (*C*) provides *security*, not *availability*. Backups (*D*) are for *disaster recovery*, not real-time availability.",
      "examTip": "High availability requires redundancy at the server level (clustering, NIC teaming), network level (multiple switches, redundant links, loop-free protocols), and gateway level (HSRP/VRRP)."
    },
    {
      "id": 34,
      "question": "A network administrator is troubleshooting a slow network connection between two computers.  They suspect that packet fragmentation is contributing to the problem. Which command-line tool, and with what specific options, would allow them to test for MTU issues along the path between the two computers?",
      "options":[
        "nslookup, with the `-debug` option.",
        "ping, with the `-l` option to specify packet size and the `-f` option to set the Don't Fragment (DF) bit in the IP header.",
        "tracert, with the `-mtu` option.",
        "ipconfig /all"
      ],
      "correctAnswerIndex": 1,
      "explanation": "To diagnose MTU issues, you need to test how large a packet can be sent *without fragmentation*. The `ping` command, with specific options, is the best tool for this: *`ping [destination] -l [size]`*:  The `-l` option (lowercase L) in Windows `ping` (or `-s` on many Linux/macOS systems) allows you to specify the *size* of the ICMP Echo Request packet (in bytes). *`ping [destination] -f`*:  The `-f` option (Windows) sets the *Don't Fragment (DF)* bit in the IP header. This tells routers along the path *not* to fragment the packet, even if it exceeds the MTU of a link.  If a router encounters a packet that's too large and has the DF bit set, it will *drop* the packet and send back an ICMP \"Destination Unreachable - Fragmentation Needed and DF Bit Set\" message (Type 3, Code 4). This message also usually includes the *MTU of the next hop*. By *systematically increasing the packet size* with `-l` and using `-f`, you can determine the *path MTU* (the smallest MTU along the entire path). `nslookup` is for DNS. `tracert` shows the *route*, but doesn't directly test for MTU. `ipconfig /all` shows *local* interface configuration, not path MTU.",
      "examTip": "Use `ping [destination] -l [size] -f` (Windows) or `ping -s [size] -D [destination]` (Linux/macOS) to test for MTU issues along a network path."
    },
    {
      "id": 35,
      "question": "A network is experiencing intermittent connectivity problems.  A network administrator captures network traffic with a protocol analyzer and observes a large number of TCP RST packets. What does the presence of numerous TCP RST packets typically indicate, and what are some potential underlying causes?",
      "options":[
        "Normal TCP connection establishment.",
        "Successful DNS resolution.",
        "Abrupt termination of TCP connections. Potential causes include: application crashes, firewall rules blocking or resetting connections, network devices forcibly closing connections due to security policies or resource constraints, misconfigured TCP keepalive settings, or network instability.",
        "Successful DHCP address assignment."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A TCP RST (reset) packet is used to *immediately terminate* a TCP connection. It's *not* part of the normal connection establishment (SYN, SYN-ACK, ACK) or graceful teardown (FIN, FIN-ACK, ACK) process. A large number of RST packets indicates that connections are being *abruptly closed*, which is *not* normal. Potential causes include: *Application crashes:* If an application crashes, the operating system might send RST packets. *Firewall rules:* A firewall might be configured to block certain traffic or close connections that violate security policies. *Network devices:* Routers or other devices might forcibly close connections (e.g., due to security policy, resource constraints, or misconfiguration). *Misconfigured TCP keepalives:* If keepalives are too aggressive, connections might be prematurely terminated. *Network instability:*  Severe congestion or other network issues can sometimes lead to RST packets. It's *not* normal operation, successful DNS/DHCP, and while a *browser issue* could *potentially* lead to RSTs, it's less likely than the other causes listed.",
      "examTip": "A large number of TCP RST packets indicates abrupt termination of TCP connections, often due to application issues, firewall rules, or network device intervention."
    },
    {
      "id": 36,
      "question": "A network administrator wants to prevent rogue DHCP servers from operating on a network. They are configuring DHCP snooping on a Cisco switch. They have already enabled DHCP snooping globally. What is the NEXT step they must take to make DHCP snooping effective?",
      "options":[
        "Configure all switch ports as trusted ports.",
        "Configure specific switch ports as trusted (those connected to legitimate DHCP servers) and leave the rest as untrusted (the default).",
        "Configure a DHCP relay agent on the switch.",
        "Configure all switch ports as access ports."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DHCP snooping works by classifying switch ports as *trusted* or *untrusted*: *Trusted ports:* Ports that are connected to *legitimate* DHCP servers. The switch will allow *all* DHCP traffic (both client requests and server responses) on these ports. *Untrusted ports:* Ports that are connected to client devices (or potentially to rogue servers). The switch *only* allows DHCP *client* requests (like DHCPDISCOVER, DHCPREQUEST) to be forwarded from these ports. It *drops* any DHCP *server* responses (like DHCPOFFER, DHCPACK, DHCPNAK) from untrusted ports. After enabling DHCP snooping globally, the administrator *must* configure the appropriate ports as *trusted*. Typically, this is done manually, identifying the ports connected to the known, authorized DHCP servers. *All* ports are *untrusted* by default when DHCP snooping is enabled. You don't configure *all* ports as trusted (that would defeat the purpose). A DHCP relay agent is for forwarding DHCP requests *between subnets*, not for snooping itself. Access ports are for connecting *end devices*, not for defining DHCP trust.",
      "examTip": "After enabling DHCP snooping globally, configure trusted ports (connected to legitimate DHCP servers) and leave client-facing ports as untrusted (the default)."
    },
    {
      "id": 37,
      "question": "A company has implemented 802.1X authentication on its wired network. A user connects their laptop to a switch port, but they are not prompted for authentication and are not granted network access. The switch port is configured correctly for 802.1X. What is the MOST likely cause of the problem?",
      "options":[
        "The switch is not configured with a RADIUS server.",
        "The user's laptop does not have an 802.1X supplicant configured or enabled, or the supplicant is misconfigured.",
        "The switch port is configured with the wrong VLAN.",
        "Spanning Tree Protocol (STP) is blocking the port."
      ],
      "correctAnswerIndex": 1,
      "explanation": "802.1X requires three components: a *supplicant* (on the client device), an *authenticator* (the switch), and an *authentication server* (usually RADIUS). If the user is *not prompted* for authentication, the problem is most likely with the *supplicant*: *No supplicant:* The user's laptop might not have 802.1X supplicant software installed or enabled. *Misconfigured supplicant:* The supplicant might be configured with the wrong settings (e.g., incorrect EAP method, wrong credentials). While a missing/misconfigured RADIUS server (*A*) would prevent *successful* authentication, it wouldn't prevent the *initial authentication prompt* from appearing. The wrong VLAN (*C*) would affect network access *after* authentication, not prevent the authentication process itself. STP (*D*) prevents loops, not authentication.",
      "examTip": "If 802.1X authentication fails without a prompt, check the client device's supplicant configuration."
    },
    {
      "id": 38,
      "question": "What is 'route poisoning', and how does it work in conjunction with 'split horizon' to prevent routing loops in distance-vector routing protocols?",
      "options":[
        "Route poisoning is a technique for encrypting routing updates.",
        "Route poisoning is a method for prioritizing certain routes over others.",
        "Route poisoning is a technique where, when a router detects that a route has become invalid, it advertises that route with an infinite metric (making it unreachable) to all its neighbors, including the neighbor from which it originally learned the route. This, combined with split horizon (not advertising a route back out the interface it was learned on), helps prevent loops.",
        "Route poisoning is a technique for load balancing traffic across multiple paths."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Route poisoning and split horizon are both loop-prevention techniques used in distance-vector routing protocols (like RIP): *Split horizon:* A router *does not* advertise a route back out the *same interface* on which it *learned* that route. This prevents simple two-node loops. *Route poisoning:* When a router detects that a route has become *invalid* (e.g., the next hop is unreachable), it sets the metric for that route to *infinity* (making it unreachable) and advertises this 'poisoned' route to *all* its neighbors, *including* the neighbor from which it originally learned the route. This is an *exception* to the split horizon rule, but it's done to *explicitly* inform all neighbors that the route is *no longer valid*. The combination of split horizon and route poisoning is more robust than split horizon alone in preventing and quickly resolving routing loops. It's not encryption, prioritization, or load balancing.",
      "examTip": "Route poisoning, combined with split horizon, is a key mechanism for preventing routing loops in distance-vector protocols by explicitly advertising unreachable routes."
    },
    {
      "id": 39,
      "question": "You are troubleshooting a network where users report intermittent connectivity to a specific server. You suspect an ARP spoofing attack. Which of the following findings, obtained from a protocol analyzer capturing traffic on the affected network segment, would provide the STRONGEST evidence of ARP spoofing?",
      "options":[
        "A large number of TCP SYN packets directed to the server.",
        "Multiple ARP replies for the *same* IP address (the server's IP or the default gateway's IP) but with *different* source MAC addresses.",
        "A large number of DNS requests for the server's hostname.",
        "A large number of DHCP requests from different MAC addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "ARP spoofing (ARP poisoning) involves an attacker sending *forged* ARP messages. The goal is to associate the *attacker's* MAC address with the IP address of a *legitimate* device (often the default gateway, allowing the attacker to intercept all traffic leaving the local network, or a specific server). The *strongest evidence* in a packet capture is: *Multiple ARP replies* for the *same IP address* but with *different source MAC addresses*. This indicates that multiple devices (the legitimate device and the attacker's device) are claiming to have the same IP address, which is a clear sign of ARP spoofing. A large number of TCP SYN packets could indicate a SYN flood attack. DNS requests are normal, and while *excessive* DHCP requests could indicate a DHCP starvation attack, it's not directly related to ARP spoofing.",
      "examTip": "Multiple ARP replies for the same IP address, but with different source MAC addresses, is strong evidence of ARP spoofing."
    },
    {
      "id": 40,
      "question": "A network administrator is configuring OSPF on a Cisco router. They want to prevent the router from becoming the Designated Router (DR) or Backup Designated Router (BDR) on a specific multi-access network segment (e.g., an Ethernet LAN).  Which command, and in which configuration context, would achieve this?",
      "options": [
        "Under the `router ospf [process-id]` configuration, use the `auto-cost reference-bandwidth` command.",
        "On the interface connected to the multi-access segment, use the `ip ospf priority 0` command.",
        "Under the `router ospf [process-id]` configuration, use the `passive-interface` command.",
        "On the interface connected to the multi-access segment, use the `no ip ospf network broadcast` command."
      ],
      "correctAnswerIndex": 1,
      "explanation": "In OSPF, on multi-access networks (like Ethernet), a Designated Router (DR) and Backup Designated Router (BDR) are elected to minimize the number of adjacencies formed. The router with the *highest OSPF priority* becomes the DR, and the second-highest becomes the BDR. If priorities are equal, the router with the highest Router ID wins. To *prevent* a router from becoming DR or BDR, you set its OSPF *priority to 0* on the relevant interface. This is done with the `ip ospf priority 0` command in *interface configuration mode* for the interface connected to the multi-access segment. Changing the *cost* with `auto-cost reference-bandwidth` affects route *selection*, not DR/BDR election. The `passive-interface` command prevents OSPF from *sending hellos* on an interface, which would prevent *any* OSPF adjacency from forming. `no ip ospf network broadcast` changes the OSPF network type, which is not the direct way to prevent DR/BDR election.",
      "examTip": "Set the OSPF priority to 0 on an interface to prevent a router from becoming DR or BDR on a multi-access segment."
    },
    {
      "id": 41,
      "question": "What is 'BGP hijacking', and what are some of its potential consequences?",
      "options": [
        "A type of phishing attack where attackers trick users into revealing their BGP credentials.",
        "An attack where a malicious actor compromises a router (or exploits a misconfiguration) and falsely advertises BGP routes for IP address prefixes that they don't legitimately control. This can redirect traffic to the attacker's network.",
        "A technique for encrypting BGP routing updates.",
        "A method for dynamically assigning IP addresses to BGP routers."
      ],
      "correctAnswerIndex": 1,
      "explanation": "BGP (Border Gateway Protocol) is the routing protocol that connects different autonomous systems (ASes) on the internet. In a BGP hijacking attack: 1. An attacker gains control of a router (through compromise or by exploiting a misconfiguration). 2. The attacker then uses that router to *falsely advertise* BGP routes for IP address prefixes that they *do not own*. 3. This causes other routers on the internet to believe that the attacker's router is the best path to reach those IP addresses. *Consequences:* *Traffic Interception:* The attacker can eavesdrop on or modify the redirected traffic. *Denial of Service:* The attacker can drop the traffic, making the legitimate destination unreachable. *Blackholing:* Traffic is redirected to a 'sinkhole' where it disappears. *Spam/Malware Distribution:* The attacker can use the hijacked IP space to send spam or distribute malware. It is *not* phishing, encryption, or DHCP.",
      "examTip": "BGP hijacking is a serious attack that can disrupt internet routing and redirect traffic to malicious actors, leading to data breaches, service outages, and other harmful consequences."
    },
    {
      "id": 42,
      "question": "A network administrator configures a Cisco router with the following command: `ip route 192.168.10.0 255.255.255.0 10.0.0.1 200` What does the value '200' represent in this command, and what is its significance?",
      "options": [
        "The OSPF cost of the route.",
        "The administrative distance of the static route. A higher administrative distance means the route is less preferred.",
        "The TTL (Time to Live) value of the route.",
        "The EIGRP metric of the route."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The command `ip route [destination-network] [subnet-mask] [next-hop-ip] [administrative-distance]` configures a *static route*. The optional `[administrative-distance]` value (200 in this case) is the *administrative distance* of the route. *Administrative distance (AD)* is a value that routers use to *choose between different routing sources* for the *same* destination network. Lower AD values are *preferred*. For example, a directly connected route has an AD of 0, a static route has a default AD of 1, EIGRP summary routes have an AD of 5, internal EIGRP has an AD of 90, OSPF has an AD of 110, and external BGP has an AD of 20. If a router learns about the same network from multiple routing sources (e.g., a static route and an OSPF route), it will choose the route with the *lowest* AD. By specifying 200, this static route will be *less preferred* than routes learned from most other routing protocols (except external BGP). It's *not* the OSPF cost, TTL, or EIGRP metric (those are metrics used *within* a routing protocol, not for choosing *between* protocols).",
      "examTip": "Administrative distance is used to choose between routes to the same destination learned from different routing sources; lower values are preferred."
    },
    {
      "id": 43,
      "question": "A network uses OSPF as its routing protocol. The network includes both standard areas and a stub area. What type of OSPF LSAs (Link State Advertisements) are NOT allowed into a stub area by default, and why?",
      "options": [
        "Type 1 (Router LSAs) and Type 2 (Network LSAs); to reduce the size of the routing table.",
        "Type 5 (External LSAs); to prevent routes learned from outside the OSPF autonomous system from being flooded into the stub area, reducing routing table size and complexity.",
        "Type 3 (Summary LSAs); to prevent summary routes from being advertised.",
        "Type 4 (ASBR Summary LSAs); to prevent information about AS Boundary Routers from being advertised."
      ],
      "correctAnswerIndex": 1,
      "explanation": "OSPF *stub areas* are designed to reduce the size of the routing tables and the amount of routing information that needs to be exchanged within the area. They achieve this by *blocking* certain types of LSAs: *Type 5 (External LSAs):* These LSAs represent routes learned from *outside* the OSPF autonomous system (e.g., routes redistributed from another routing protocol like EIGRP or BGP). Stub areas *do not allow* Type 5 LSAs. Instead, the Area Border Router (ABR) connecting the stub area to the backbone area (area 0) injects a *default route* into the stub area. Routers within the stub area use this default route to reach external destinations. Type 1 (Router) and Type 2 (Network) LSAs are *allowed* in stub areas; they describe the internal topology of the area. Type 3 (Summary) LSAs are used to advertise routes *between* areas, and *are* allowed into a stub area from the backbone. Type 4 LSAs describe ASBR locations, used when external routes are present (which are blocked in a stub area). A *totally stubby area* blocks Types 3, 4, and 5.",
      "examTip": "Stub areas in OSPF block Type 5 (External) LSAs and rely on a default route injected by the ABR to reach external destinations."
    },
    {
      "id": 44,
      "question": "You are troubleshooting a network connectivity issue where a user is unable to access a web server. You have verified the following: The user's computer has a valid IP address, subnet mask, and default gateway. The user can ping the web server's IP address successfully. `nslookup` resolves the web server's domain name correctly. However, when the user tries to access the web server in a web browser, they receive a 'Connection refused' error. What is the MOST likely cause of this problem?",
      "options":[
        "The user's network cable is unplugged.",
        "The DNS server is misconfigured.",
        "The web server is not running, the web server application (e.g., Apache, IIS) is not running or is misconfigured, or a firewall (on the client, the server, or in between) is blocking the connection on the specific port used by the web server (usually TCP port 80 for HTTP or 443 for HTTPS).",
        "The user's computer does not have a default gateway configured."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Since the user can *ping the web server's IP address* and `nslookup` resolves the domain name correctly, basic network connectivity and DNS resolution are working. The 'Connection refused' error message specifically indicates that the client's TCP connection request (SYN packet) was *actively rejected* by the server. This typically means one of the following: 1. *The web server is not running:* The entire server machine might be down. 2.  *The web server application is not running or is misconfigured:* The web server software (e.g., Apache, IIS, Nginx) itself might not be started, or it might be listening on a different port than expected. 3. *A firewall is blocking the connection:* A firewall (either on the client's computer, on the server itself, or on a network device in between) might be configured to block traffic to the web server's port (typically TCP port 80 for HTTP or 443 for HTTPS). It is *not* a cable problem (ping works), a *general* DNS problem (`nslookup` works), or a default gateway problem (ping to an external IP works).",
      "examTip": "A 'Connection refused' error typically indicates that the target service (e.g., a web server) is not running or is actively rejecting connections, or that a firewall is blocking the connection."
    },
    {
      "id": 45,
      "question": "A network administrator wants to configure a Cisco switch to automatically learn the MAC address of the first device connected to a port and add that MAC address to the running configuration as a secure MAC address.  Furthermore, if a device with a different MAC address subsequently connects to that port, the administrator wants the port to be shut down (placed in the error-disabled state). Which of the following sets of commands, starting from interface configuration mode, would achieve this?",
      "options": [
        "switchport mode trunk \n switchport port-security",
        "switchport mode access \n switchport port-security \n switchport port-security maximum 1 \n switchport port-security mac-address sticky \n switchport port-security violation shutdown",
        "switchport mode access \n switchport port-security \n switchport port-security maximum 1 \n switchport port-security mac-address [allowed_mac_address] \n switchport port-security violation shutdown",
        "switchport mode access \n switchport port-security violation restrict"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The correct command sequence is: 1. `switchport mode access`: Configures the port as an *access port* (carrying traffic for a single VLAN). Port security is typically used on access ports. 2. `switchport port-security`: *Enables* port security on the interface. 3. `switchport port-security maximum 1`:  Limits the number of allowed MAC addresses on the port to *one*. 4. `switchport port-security mac-address sticky`: Enables *sticky learning*.  The switch dynamically learns the MAC address of the *first* device connected to the port and adds it to the *running configuration* as a secure MAC address. 5. `switchport port-security violation shutdown`:  Configures the *violation mode*. This specifies that if a device with a *different* MAC address tries to connect, the port will be *shut down* (placed in the error-disabled state). Option A configures a *trunk* port, which is incorrect. Option C *statically* configures a MAC address, which is not what the question asks for (dynamic learning). Option D enables port security but doesn't shut down the port on a violation and *doesn't learn the MAC dynamically*.",
      "examTip": "Use `switchport port-security mac-address sticky` with `maximum 1` and `violation shutdown` to dynamically learn and secure a single MAC address on a switch port and shut down the port on a violation."
    },
    {
      "id": 46,
      "question": "You are configuring a site-to-site IPsec VPN between two Cisco routers. You have already configured the ISAKMP policy (Phase 1).  You are now configuring the IPsec transform set (Phase 2).  You want to use ESP for encryption and authentication, AES-256 for encryption, and SHA-256 for hashing. Which of the following commands, entered in global configuration mode, would correctly create an IPsec transform set named 'TS' with these parameters?",
      "options":[
        "crypto ipsec transform-set TS esp-aes 256 esp-sha-hmac",
        "crypto ipsec transform-set TS esp-aes 256 esp-sha256-hmac",
        "crypto ipsec transform-set TS ah-sha-hmac esp-aes 256",
        "crypto isakmp policy 10 \n encryption aes 256 \n hash sha256"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `crypto ipsec transform-set` command defines the parameters for *Phase 2* of an IPsec VPN (the actual data encryption and authentication). The syntax is: `crypto ipsec transform-set [transform-set-name] [transform1] [transform2] ...` *`transform-set-name`*: A name you choose for the transform set (e.g., 'TS'). *`transform1`, `transform2`, ...:*  Specify the security protocols and algorithms to be used.  You need to choose: *ESP or AH:*  ESP (Encapsulating Security Payload) provides *both* confidentiality (encryption) and authentication/integrity. AH (Authentication Header) provides authentication and integrity *only* (no encryption). Since we want *both* encryption and authentication, we choose ESP transforms. *Encryption Algorithm:*  AES-256 (Advanced Encryption Standard with a 256-bit key) is a strong encryption algorithm. *Hashing Algorithm:* SHA-256 (Secure Hash Algorithm with a 256-bit digest) is a strong hashing algorithm. So the Correct answer is: `crypto ipsec transform-set TS esp-aes 256 esp-sha256-hmac` Option A does not specify that the SHA should use 256 bit, so its not the most specific. Option C uses AH *and* ESP, which is not standard practice. Option D configures the *ISAKMP policy* (Phase 1), *not* the IPsec transform set (Phase 2). ",
      "examTip": "The IPsec transform set defines the security protocols (ESP or AH), encryption algorithm, and hashing algorithm used for Phase 2 of an IPsec VPN."
    },
    {
      "id": 47,
      "question": "What is 'BGP hijacking', and what makes it a particularly difficult attack to detect and prevent?",
      "options":[
        "A method for encrypting BGP routing updates to ensure confidentiality.",
        "A type of phishing attack targeting network administrators.",
        "An attack where a malicious actor compromises a router (or exploits a misconfiguration) and falsely advertises BGP routes for IP address prefixes that they do not legitimately control, redirecting traffic to the attacker's network, potentially allowing interception, modification, or denial of service. It's difficult to detect because BGP inherently trusts announcements from peers, and validation mechanisms are not universally deployed.",
        "A technique for dynamically assigning IP addresses to BGP routers."
      ],
      "correctAnswerIndex": 2,
      "explanation":"BGP (Border Gateway Protocol) is the routing protocol that connects different autonomous systems (ASes) on the internet. BGP hijacking exploits the trust-based nature of BGP: *Compromise/Misconfiguration:* An attacker gains control of a router (through hacking or exploiting a misconfiguration) or has control over a misconfigured router within a legitimate AS. *False Route Advertisements:* The attacker uses the compromised router to advertise BGP routes for IP address prefixes that they *do not own*. *Traffic Redirection:* Other routers on the internet believe these false advertisements and start sending traffic intended for the legitimate owner of the IP addresses to the *attacker's* network. *Difficulty of Detection/Prevention:* *Inherent Trust:* BGP traditionally relies on trust between ASes. Routers generally assume that routing updates from their peers are valid. *Lack of Universal Validation:* While there are mechanisms to validate BGP announcements (like RPKI - Resource Public Key Infrastructure and IRR filtering), they are *not universally deployed or enforced*. It is *not* encryption, phishing, or DHCP.",
      "examTip": "BGP hijacking exploits the inherent trust in BGP and the lack of universal validation mechanisms, making it a difficult attack to detect and prevent."
    },
    {
      "id": 48,
      "question": "A network administrator configures a Cisco switch port with the following commands: `switchport mode access` `switchport port-security` `switchport port-security maximum 1` `switchport port-security mac-address sticky` `switchport port-security violation restrict` What is the *specific* effect of the `violation restrict` mode in this port security configuration?",
      "options":[
        "The port will be shut down (err-disabled) if a security violation occurs.",
        "The port will drop traffic from unknown MAC addresses *and* increment the violation counter, and it can be configured to send an SNMP trap or syslog message. However, the port will *not* be shut down.",
        "The port will drop traffic from unknown MAC addresses, but it will *not* increment the violation counter or send any notifications.",
        "The port will allow traffic from any MAC address."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Port security on a Cisco switch has three violation modes: *`protect`*: Drops traffic from unknown MAC addresses *silently* (no counter increment, no alerts). *`restrict`*: Drops traffic from unknown MAC addresses, *increments the violation counter*, and *can* be configured to send an SNMP trap or syslog message.  The port remains *up*. *`shutdown`*:  Drops traffic and puts the port in the *err-disabled* state (shuts it down). Requires manual intervention to re-enable. The question specifically asks about `violation restrict`.  This mode *drops* traffic from unauthorized MAC addresses, *logs* the violation, and *can* generate alerts, but it does *not* shut down the port. Option A describes `shutdown`. Option C describes `protect`. Option D is incorrect; port security is enabled.",
      "examTip": "The `switchport port-security violation restrict` mode drops traffic from unknown MAC addresses, increments the violation counter, and can generate alerts, but it does *not* shut down the port."
    },
    {
      "id": 49,
      "question": "A network is experiencing intermittent connectivity issues.  A protocol analyzer capture shows a large number of TCP retransmissions.  Further analysis reveals that many of the retransmitted packets have the same sequence numbers as previously seen packets, but different payloads (data). What is the MOST likely cause of this behavior?",
      "options": [
        "Normal TCP operation.",
        "A misconfigured DNS server.",
        "A man-in-the-middle (MitM) attack where an attacker is actively modifying the contents of TCP packets.",
        "A DHCP server assigning duplicate IP addresses."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The key here is *retransmissions with the same sequence number but different data*. This is *highly abnormal* and strongly suggests *active manipulation* of the traffic. *Retransmissions* normally happen when a packet is *lost*, not when it's *changed*. If the *data* within a packet changes, the TCP checksum would fail, and the receiver would normally discard the packet. The fact that the *same sequence number* is being reused with *different data* indicates that someone is *intercepting and modifying* the packets in transit. This is a classic sign of a *man-in-the-middle (MitM) attack*. Normal TCP operation would retransmit the *same* data. DNS and DHCP issues wouldn't cause this. While *packet loss* could cause retransmissions, it wouldn't cause the *data* to change while keeping the *sequence number* the same.",
      "examTip": "TCP retransmissions with the same sequence number but different data strongly suggest a man-in-the-middle attack where packets are being actively modified."
    },
    {
      "id": 50,
      "question": "A network administrator wants to configure a Cisco router to use NTP (Network Time Protocol) to synchronize its clock with an external time server.  The NTP server's IP address is 192.0.2.1.  Which of the following commands, entered in global configuration mode, would correctly configure the router to use this NTP server?",
      "options":[
        "clock timezone PST -8",
        "ntp server 192.0.2.1",
        "ntp update-calendar",
        "ntp master"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `ntp server [ip-address]` command on a Cisco router configures the router to synchronize its clock with the specified NTP server.  The correct command is simply `ntp server 192.0.2.1`. `clock timezone` sets the *time zone*, but not the time *source*. `ntp update-calendar` updates the router's *hardware* clock from the software clock (not relevant to synchronizing with an external server). `ntp master` configures the router to *act as* an NTP *server* for other devices, not to synchronize with an external server.",
      "examTip": "Use the `ntp server [ip-address]` command on a Cisco router to configure it to synchronize its clock with an external NTP server."
    }
  ]
}




{
  "questions": [
    {
      "id": 51,
      "question": "You are troubleshooting a network where some computers can access the internet, while others on the same VLAN and subnet cannot. All computers are configured to obtain IP addresses via DHCP.  You suspect a problem with the default gateway configuration. What is the BEST way to quickly confirm the default gateway IP address being used by a *working* computer and a *non-working* computer on a Windows system, and compare them?",
      "options":[
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
      "options":[
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
      "options":[
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
      "options":[
        "router eigrp 100 \n redistribute ospf 1",
        "router eigrp 100 \n redistribute ospf 1 match internal",
        "router eigrp 100 \n redistribute ospf 1 route-map OSPF-TO-EIGRP \n ! \n route-map OSPF-TO-EIGRP permit 10 \n match tag 777",
        "router eigrp 100 \n redistribute ospf 1 metric 10000 100 255 1 1500"
      ],
      "correctAnswerIndex": 2,
      "explanation": "To redistribute routes from one protocol to another *and* filter based on a tag, you need a *route map*.  The steps are: 1. **Define a route map.** 2. **Match on the desired tag (777).** 3. **Apply the route map in the `redistribute` command.** For example: ``` router eigrp 100 redistribute ospf 1 route-map OSPF-TO-EIGRP ! route-map OSPF-TO-EIGRP permit 10 match tag 777 ``` You would also need to have configured the OSPF process to *tag* the desired routes with the value 777. Option A redistributes *all* OSPF routes. Option B matches based on OSPF route type (internal, external), not tag. Option D redistributes all OSPF routes, *without filtering by tag*, and also doesn't address route-map usage. Also note that EIGRP *requires* a metric when redistributing routes if you aren’t specifying a default route-map metric; that may be the \"additional configuration\" needed in production.",
      "examTip": "Use a route map to filter routes during redistribution, matching on criteria like tags. EIGRP may require a manual metric when redistributing."
    },
    {
      "id": 55,
      "question": "A network is experiencing intermittent connectivity issues. A packet capture reveals a large number of TCP RST packets.  What does a TCP RST packet indicate, and what are some potential causes of a high volume of RST packets?",
      "options":[
        "Successful TCP connection establishment.",
        "Normal TCP connection termination.",
        "Abrupt termination of a TCP connection. Potential causes include application crashes, firewall rules, network device intervention, misconfigured TCP keepalive settings, or network instability.",
        "Successful DNS resolution."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A TCP RST (reset) packet signifies an *abrupt termination* of a TCP connection. It's *not* part of the normal connection establishment (SYN, SYN-ACK, ACK) or graceful teardown (FIN, FIN-ACK, ACK) process.  A large number of RST packets means connections are being *forcibly closed*. Potential causes include: *Application crashes:* If an application crashes, the operating system may send RST packets. *Firewall rules:* A firewall might block or reset certain traffic. *Network devices:* Routers or other network devices might forcibly close connections for security or resource reasons. *Misconfigured TCP keepalives:* If keepalives are too aggressive, connections can be dropped early. *Network instability:* Severe congestion or device issues could trigger resets. It's *not* normal for graceful termination, nor is it directly related to DNS.",
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
      "explanation": "The `passive-interface` command, when used *within the OSPF process configuration* (`router ospf [process-id]`), stops sending OSPF hellos on that interface, preventing adjacency formation. However, OSPF still includes the network for that interface in its advertisements if it’s covered by a matching `network` statement. This ensures the network is advertised but no neighbors are formed on that interface. `passive-interface` is *not* a global command or an interface command (outside of the OSPF context). `no ip ospf network broadcast` changes the OSPF network type, while `no ip ospf enable` would disable OSPF entirely on that interface, not just adjacency formation.",
      "examTip": "Use `passive-interface [iface-name]` under `router ospf [PID]` to advertise a network without forming adjacencies on that interface."
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
      "explanation": "The 2.4 GHz band is an *unlicensed* band, meaning it's used by many devices besides Wi-Fi. Common interference sources include microwave ovens, Bluetooth, older cordless phones, wireless video cameras, and poorly shielded equipment. FM radio and satellite operate in different frequency ranges, and cellular uses licensed bands. So these typical 2.4 GHz interferences can cause intermittent or degraded performance.",
      "examTip": "Non-Wi-Fi devices like microwaves, Bluetooth, and older 2.4 GHz cordless phones can cause interference in the 2.4 GHz Wi-Fi band."
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
      "explanation": "The question states you want *only one specific MAC address* allowed, and for any other MAC to shut the port down. The correct method is: \n1. `switchport mode access` (an access port) \n2. `switchport port-security` (enable port security) \n3. `switchport port-security maximum 1` (limit to one MAC) \n4. `switchport port-security mac-address [allowed_mac_address]` (statically set the permitted MAC) \n5. `switchport port-security violation shutdown` (err-disable if a different MAC shows up). \nOption B uses sticky, which dynamically learns the MAC; we want a specific known address. The other options do not match the requirement exactly.",
      "examTip": "To allow exactly one known MAC and shutdown on violation, statically configure the MAC and use `violation shutdown` in port security."
    },
    {
      "id": 59,
      "question": "A network administrator configures a Cisco router with the command `ip route 0.0.0.0 0.0.0.0 192.168.1.1`.  What is the purpose and effect of this command, and what is a potential risk if this is the *only* static route configured?",
      "options": [
        "It configures a static route for the 192.168.1.0 network.",
        "It configures a default route, sending all traffic that doesn't match a more specific route in the routing table to the gateway at 192.168.1.1. The risk is that if 192.168.1.1 is *not* a valid next hop to all destinations (e.g., the internet), traffic will be dropped.",
        "It configures a dynamic route using a routing protocol.",
        "It blocks all traffic to the 192.168.1.1 address."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`ip route 0.0.0.0 0.0.0.0 192.168.1.1` sets the *default route*, also called the \"route of last resort.\" Any traffic for a destination not in the routing table will be forwarded to 192.168.1.1. If 192.168.1.1 is not actually capable of routing to every possible external destination, traffic will be dropped. This can create blackhole scenarios if that address is invalid or misconfigured. It's neither a static route to 192.168.1.0 nor a dynamic route, and it doesn’t block traffic; it simply points to a default next hop.",
      "examTip": "A default route (`0.0.0.0/0`) forwards packets when no other, more specific route exists. Ensure the next hop truly leads to all external destinations."
    },
    {
      "id": 60,
      "question": "A network administrator is troubleshooting an OSPF routing problem between two directly connected routers. OSPF is enabled on both routers, and the interfaces connecting them are in the same OSPF area. However, the routers are not forming an OSPF adjacency.  `show ip ospf neighbor` on both routers shows no neighbors.  Basic IP connectivity between the interfaces is confirmed with `ping`. Which of the following is the LEAST likely cause of this problem?",
      "options":[
        "Mismatched OSPF hello or dead intervals.",
        "Mismatched OSPF network types (e.g., one configured as broadcast, the other as point-to-point).",
        "An access control list (ACL) blocking OSPF traffic.",
        "Mismatched MTU settings on the interfaces."
      ],
      "correctAnswerIndex": 3,
      "explanation": "OSPF adjacency formation depends on matching parameters: \n1. Same area ID \n2. Same subnet or OSPF network type (broadcast, non-broadcast, point-to-point, etc.) \n3. Same hello/dead intervals \n4. No ACLs blocking OSPF packets (multicast to 224.0.0.5 or 224.0.0.6) \nWhile MTU mismatches can cause adjacency problems in some cases, it usually manifests after partial adjacency is formed (DBD exchange issues). The others (hello/dead mismatch, network-type mismatch, ACL blocking) are more direct and common reasons that neighbors never show up in the `show ip ospf neighbor` output. Therefore, mismatched MTU is the *least* likely cause in this context.",
      "examTip": "Hello/dead timers, network type, and ACLs often cause adjacency failures. MTU mismatches typically cause later exchange issues, not a complete absence of neighbors."
    },
    {
      "id": 61,
      "question": "Which of the following statements about IPv6 addresses is FALSE?",
      "options":[
        "IPv6 addresses are 128 bits long, represented as eight groups of four hexadecimal digits separated by colons.",
        "IPv6 uses the concept of 'scope' to define the reachability of an address (e.g., link-local, site-local, global).",
        "IPv6 addresses can be automatically configured using SLAAC (Stateless Address Autoconfiguration).",
        "IPv6 completely eliminates the need for NAT (Network Address Translation)."
      ],
      "correctAnswerIndex": 3,
      "explanation": "IPv6 drastically reduces the need for NAT by providing a vast address space, but it does *not* eliminate NAT entirely. Some use cases (multi-homing, privacy, or specific network designs) can still involve NAT66. The other statements are true. IPv6 is indeed 128 bits, uses scope (like link-local, global unicast), and can use SLAAC to auto-configure addresses.",
      "examTip": "Despite IPv6’s large address space, NAT hasn’t been eliminated altogether; NAT66 and other use cases persist."
    },
    {
      "id": 62,
      "question": "A network administrator is troubleshooting a connectivity issue where users on a specific VLAN are unable to reach the internet. They can ping other devices within the same VLAN and can ping the SVI (Switched Virtual Interface) IP address of their VLAN on the Layer 3 switch. However, they cannot ping the IP address of the next-hop router (the default gateway for the Layer 3 switch). What is the MOST likely cause of the problem?",
      "options":[
        "A problem with the user's computers' network cables.",
        "A routing problem between the Layer 3 switch and the next-hop router, or an issue with the next-hop router itself.",
        "A DNS server misconfiguration.",
        "A DHCP server failure."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Users can reach local VLAN resources and the SVI on the Layer 3 switch, but they can’t reach the next-hop router IP. This strongly points to a routing or physical connectivity issue *beyond* the SVI. Possibly the next-hop router is down, incorrectly configured, or not connected properly. DNS or DHCP wouldn’t stop pings to the next hop if the IP is known, and the cables for the user PCs are fine since they can ping locally.",
      "examTip": "If hosts reach their local L3 interface but can’t reach the next hop, investigate routing between the L3 switch and the next router (or that router’s config)."
    },
    {
      "id": 63,
      "question": "A company wants to implement a wireless network that supports both the 2.4 GHz and 5 GHz frequency bands.  They want to maximize throughput and minimize interference. They are using 802.11ac access points and client devices.  Which of the following configurations would provide the BEST performance, and why?",
      "options":[
        "Configure all access points to use the 2.4 GHz band with channel bonding.",
        "Configure all access points to use the 5 GHz band with the widest possible channel width (e.g., 80 MHz or 160 MHz) supported by the devices, and use non-overlapping channels.",
        "Configure all access points to use the 2.4 GHz band with non-overlapping channels (1, 6, 11).",
        "Configure all access points to use the 5 GHz band with 20 MHz channel width."
      ],
      "correctAnswerIndex": 1,
      "explanation": "802.11ac supports higher throughput primarily by operating in the 5 GHz band, which has more available spectrum and less interference than 2.4 GHz.  Using wider channels (80 or 160 MHz) can further increase data rates—provided that enough non-overlapping spectrum is available and your environment/devices support it. 2.4 GHz is congested (especially in large spaces), so 5 GHz is preferred.  Non-overlapping channels are crucial to avoid co-channel interference.  20 MHz channels in 5 GHz can be reliable but won’t maximize throughput.",
      "examTip": "For 802.11ac, use 5 GHz with wide channels and ensure non-overlapping configuration for highest performance."
    },
    {
      "id": 64,
      "question": "A network administrator configures a Cisco switch port with the command `spanning-tree portfast`. On which types of switch ports should this command be used, and why is it important to avoid using it on other types of ports?",
      "options":[
        "It should be used on trunk ports to speed up VLAN convergence.",
        "It should be used on access ports connected to end devices (like workstations, servers, printers) to speed up the transition to the forwarding state. It should *never* be used on ports connected to other switches or bridges, as this can create network loops.",
        "It should be used on all switch ports to improve network performance.",
        "It should be used on ports connected to routers to improve routing convergence."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`spanning-tree portfast` tells the switch to transition the port directly to the forwarding state, bypassing the usual listening/learning states. This is safe for ports connected to single end hosts, because they won’t form bridging loops. Using it on ports that connect to other switches (or bridging devices) could cause temporary loops if the other switch has bridging issues. Therefore, it’s recommended only for access ports to end devices.",
      "examTip": "Enable PortFast on end-host access ports only, never on switch-to-switch links, to avoid potential loops."
    },
    {
      "id": 65,
      "question": "A network uses EIGRP as its routing protocol.  A network administrator wants to ensure that EIGRP routing updates are authenticated to prevent unauthorized routers from injecting false routing information.  Which of the following steps are required to configure MD5 authentication for EIGRP on a Cisco router?",
      "options":[
        "Enable EIGRP globally on the router.",
        "Configure a key chain with a key string and key ID, and then apply the key chain to the interface participating in EIGRP using the `ip authentication mode eigrp [as-number] md5` and `ip authentication key-chain eigrp [as-number] [key-chain-name]` commands.",
        "Configure a username and password on the router.",
        "Configure an access control list (ACL) to permit only EIGRP traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "EIGRP supports MD5 authentication. You must: 1) Create a key chain with a key ID and key string (password). 2) Under the interface running EIGRP, specify MD5 as the authentication mode (`ip authentication mode eigrp [AS] md5`) and associate the key chain (`ip authentication key-chain eigrp [AS] [chain_name]`). The username/password method is for VTY/console access, not routing updates. ACLs don’t provide per-packet cryptographic authentication.",
      "examTip": "Configure EIGRP MD5 auth with a key chain, then enable on the interface with `ip authentication mode eigrp` and `ip authentication key-chain eigrp` commands."
    },
    {
      "id": 66,
      "question": "You are troubleshooting a network connectivity issue. A user reports being unable to access a specific web server. You have verified the following: The user's computer has a valid IP address, subnet mask, and default gateway. The user *can* ping other devices on their local network. The user *cannot* ping `www.example.com`. The user *cannot* ping the IP address that `www.example.com` *should* resolve to (you know this IP from another working machine). What is the MOST likely cause of the problem?",
      "options":[
        "A DNS resolution problem.",
        "A problem with the user's web browser.",
        "A problem with the network connection between the user's computer and the default gateway, or a routing problem beyond the default gateway.",
        "The web server `www.example.com` is down."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The user can’t ping the web server’s domain name or its IP address, yet they can ping other local devices. This indicates it’s not strictly a DNS issue (because even direct IP pings fail) and not a browser issue (ICMP pings fail). The web server being down wouldn’t necessarily explain the inability to even see intermediate hops. The most likely root cause is a connectivity or routing problem between the user’s network and the outside. Possibly the default gateway is unreachable or misconfigured, or there is a missing route beyond the gateway.",
      "examTip": "When both name and IP fail, check your local LAN vs. external path. If local pings work but outside pings fail, suspect routing or gateway connectivity."
    },
    {
      "id": 67,
      "question": "A network administrator is configuring a Cisco router to perform Network Address Translation (NAT). They want to allow multiple internal devices with private IP addresses to share a single public IP address when accessing the internet. Which type of NAT should they configure, and what is the specific command syntax (assuming the inside interface is GigabitEthernet0/0 and the outside interface is GigabitEthernet0/1)?",
      "options":[
        "Static NAT; `ip nat inside source static [private-ip] [public-ip]`",
        "Dynamic NAT; `ip nat inside source list [access-list-number] interface [interface-name] overload`",
        "PAT (Port Address Translation) or NAT Overload; `ip nat inside source list [access-list-number] interface [interface-name] overload`",
        "Dynamic NAT; `ip nat inside source dynamic [private-ip-pool] [public-ip-pool]`"
      ],
      "correctAnswerIndex": 2,
      "explanation": "To let many inside hosts share one public IP, use *PAT (Port Address Translation)* or NAT overload. This is configured via: `ip nat inside source list [ACL#] interface [outside-interface] overload`. You also mark `GigabitEthernet0/0` as `ip nat inside` and `GigabitEthernet0/1` as `ip nat outside`. Static NAT is 1:1. Dynamic NAT uses a pool, not a single interface IP. The correct command for PAT is the one with `overload` on the interface.",
      "examTip": "For many-to-one NAT, use NAT overload (PAT) with `ip nat inside source list [ACL#] interface [outside-int] overload`."
    },
    {
      "id": 68,
      "question": "A network administrator wants to prevent rogue DHCP servers from operating on a network. They are configuring DHCP snooping on a Cisco switch. They have already enabled DHCP snooping globally with the `ip dhcp snooping` command. They have also identified the switch port connected to the legitimate DHCP server. What command should they use, in interface configuration mode, to designate this port as a trusted port for DHCP snooping?",
      "options":[
        "switchport mode access",
        "ip dhcp relay",
        "ip dhcp snooping trust",
        "ip dhcp snooping limit rate"
      ],
      "correctAnswerIndex": 2,
      "explanation": "To configure a port as *trusted* for DHCP snooping, use `ip dhcp snooping trust` in interface config mode. This allows DHCP server responses out of that port. All other ports remain untrusted by default, ensuring DHCP server traffic is dropped unless it originates on a trusted port. `switchport mode access` is for VLAN membership, `ip dhcp relay` is for IP helper, and `ip dhcp snooping limit rate` sets a rate limit for DHCP packets but does not define trust.",
      "examTip": "Designate legitimate DHCP server ports as trusted with `ip dhcp snooping trust` on the interface."
    },
    {
      "id": 69,
      "question": "A network administrator configures a Cisco switch port with the following commands:  `switchport mode access` `switchport port-security` `switchport port-security maximum 1` `switchport port-security mac-address sticky` `switchport port-security violation restrict`  What is the *precise* effect of the `violation restrict` mode in this port security configuration?",
      "options":[
        "The port will be shut down (err-disabled) if a security violation occurs.",
        "The port will drop traffic from unknown MAC addresses and increment the violation counter.  It can also be configured to send an SNMP trap or syslog message. However, the port will *not* be shut down.",
        "The port will drop traffic from unknown MAC addresses, but it will *not* increment the violation counter or send any notifications.",
        "The port will allow traffic from any MAC address."
      ],
      "correctAnswerIndex": 1,
      "explanation": "In port security, `violation restrict` will drop unauthorized traffic, increment violation counters, and optionally send alerts, but it does *not* disable the port. `protect` drops packets silently with no alerts or counter increments. `shutdown` places the port into err-disabled state. This question specifically references `violation restrict`, so that’s the correct effect.",
      "examTip": "`restrict` drops unknown MAC traffic, logs/increments counters, can generate SNMP/syslog, but does NOT shut the port."
    },
    {
      "id": 70,
      "question": "You are troubleshooting a network where users report intermittent connectivity to a web server. You have verified the following: The user's computer has a valid IP address, subnet mask, and default gateway. The user *can* ping the web server's IP address successfully. `nslookup [web server's domain name]` *resolves the domain name to the correct IP address*. However, when the user tries to access the web server in a web browser, they get a 'Connection timed out' error.  Which of the following is the LEAST likely cause of the problem?",
      "options":[
        "A firewall is blocking traffic to the web server's port (e.g., TCP port 80 or 443).",
        "The web server application (e.g., Apache, IIS) is not running or is misconfigured.",
        "The user's computer has a faulty network cable.",
        "The web server machine is powered off."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Since the user can *ping* the web server (layer 3 connectivity is ok) and DNS resolves fine, the cable must be fine enough to pass ICMP traffic. A 'Connection timed out' typically means the TCP connection attempt never got a response, which can be caused by a firewall blocking the port, the web service being down/misconfigured, or the server itself being offline. (Although if it were truly powered off, pings would fail, so that’s a nuance. But “machine is powered off” might indicate partially offline or unresponsive at application level.) Nevertheless, a physical cable issue is quite unlikely if pings succeed.",
      "examTip": "When pings and DNS work, suspect an application-level or firewall issue for timeouts, not the physical cable."
    },
    {
      "id": 71,
      "question": "A network administrator is configuring OSPF on a multi-access network (like Ethernet) where multiple routers are connected. They want to minimize the number of OSPF adjacencies formed and optimize the flooding of LSAs (Link State Advertisements). Which OSPF feature should be used, and how does it work?",
      "options":[
        "Configure all routers with the same OSPF priority.",
        "Enable OSPF authentication.",
        "Utilize the Designated Router (DR) and Backup Designated Router (BDR) election process. The DR acts as a central point for LSA flooding, and the BDR takes over if the DR fails.",
        "Configure the network as a point-to-point network type."
      ],
      "correctAnswerIndex": 2,
      "explanation": "On multi-access networks, OSPF elects a DR and a BDR to reduce the adjacency count and simplify LSA flooding. Instead of every router forming a full adjacency with every other router, they only form adjacencies with the DR and BDR. The DR is responsible for relaying LSAs to/from the rest of the routers. If the DR fails, the BDR becomes DR. Authentication is for security, not adjacency optimization. Making it point-to-point would only be correct if it was physically point-to-point, not multi-access.",
      "examTip": "On multi-access segments, DR/BDR election streamlines OSPF adjacencies and LSA flooding."
    },
    {
      "id": 72,
      "question": "You are troubleshooting a network where users are intermittently losing their network connections. You suspect a problem with the Spanning Tree Protocol (STP). Which of the following commands on a Cisco switch would provide the MOST comprehensive information about the current STP state, including the root bridge, port roles, port states, and any recent topology changes?",
      "options":[
        "show interfaces status",
        "show ip interface brief",
        "show spanning-tree",
        "show mac address-table"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`show spanning-tree` displays critical STP info: the root bridge ID, local bridge ID, port roles (root, designated, blocking), port states (forwarding, blocking, etc.), and topology change counters. This is exactly what you need to diagnose STP issues. The other commands don’t address STP details.",
      "examTip": "Use `show spanning-tree` to see STP’s root, port roles, states, and recent changes on Cisco switches."
    },
    {
      "id": 73,
      "question": "What is 'BGP route reflection', and in what type of BGP deployment is it typically used to simplify configuration and reduce the number of required BGP sessions?",
      "options":[
        "A technique used to summarize routes advertised between different autonomous systems.",
        "A mechanism used in large *internal* BGP (iBGP) deployments within an autonomous system to avoid the need for a full mesh of iBGP sessions between all iBGP speakers. A designated router (or set of routers) acts as a route reflector, reflecting routes learned from one iBGP peer to other iBGP peers.",
        "A method for encrypting BGP routing updates.",
        "A technique for load balancing traffic across multiple BGP paths."
      ],
      "correctAnswerIndex": 1,
      "explanation": "In large iBGP deployments, each router typically must peer with every other router (full mesh). Route reflection eliminates this need by designating one (or more) route reflectors, which re-advertise routes between clients. This drastically reduces the number of iBGP sessions. It’s not summarization, encryption, or load balancing.",
      "examTip": "BGP route reflection avoids a full iBGP mesh by letting route reflectors re-advertise routes to other clients in the same AS."
    },
    {
      "id": 74,
      "question": "A network administrator is configuring a Cisco router and wants to restrict access to the router's VTY lines (for remote management via SSH) to only allow connections from a specific subnet, 192.168.10.0/24.  Which of the following command sequences, starting from global configuration mode, is the MOST secure and correct way to achieve this?",
      "options":[
        "line vty 0 4 \n transport input all",
        "line vty 0 4 \n transport input ssh \n access-list 10 permit ip any any \n access-class 10 in",
        "line vty 0 4 \n transport input ssh \n access-list 10 permit tcp 192.168.10.0 0.0.0.255 host [Router's Management IP] eq 22 \n access-class 10 in",
        "line con 0 \n transport input ssh \n access-list 10 permit 192.168.10.0 0.0.0.255 \n access-class 10 in"
      ],
      "correctAnswerIndex": 2,
      "explanation": "For remote SSH management, restrict inbound VTY access to only specific sources. Use `transport input ssh` to disable Telnet, then create an ACL that permits only traffic from the 192.168.10.0/24 subnet to the router’s SSH port (22). Finally, apply that ACL with `access-class 10 in` on the VTY lines. The other options either permit all IP, apply to console lines, or do not specify the right addresses/ports for strict security.",
      "examTip": "On VTY lines, use `access-class` with a properly defined ACL that only allows SSH from authorized IP ranges."
    },
    {
      "id": 75,
      "question": "A company is implementing a wireless network and needs to choose between WPA2-Personal, WPA2-Enterprise, and WPA3-Enterprise.  What are the KEY differences between these security modes, and which one provides the STRONGEST security?",
      "options":[
        "WPA2-Personal uses a pre-shared key (PSK) for authentication, WPA2-Enterprise uses a RADIUS server and 802.1X, and WPA3-Enterprise uses a more secure pre-shared key. WPA2-Personal is the most secure.",
        "WPA2-Personal, WPA2-Enterprise, and WPA3-Enterprise all use the same authentication method, but different encryption algorithms. WPA3-Enterprise is the most secure.",
        "WPA2-Personal uses a pre-shared key (PSK) for authentication, making it easier to configure but less secure for large networks. WPA2-Enterprise uses 802.1X with a RADIUS server for authentication, providing stronger security and centralized management. WPA3-Enterprise enhances WPA2-Enterprise with even stronger encryption and improved authentication mechanisms. WPA3-Enterprise is the most secure.",
        "WPA2-Personal and WPA2-Enterprise are the same; WPA3-Enterprise is only for very large networks."
      ],
      "correctAnswerIndex": 2,
      "explanation": "WPA2-Personal relies on a single PSK, which is easier to implement but not great for large-scale. WPA2-Enterprise uses 802.1X with a RADIUS server for per-user credentials, stronger overall. WPA3-Enterprise improves upon WPA2-Enterprise with stronger encryption (e.g., 192-bit or 256-bit, GCMP) and more secure key exchange (SAE), making it the strongest option. The other statements are incorrect or incomplete.",
      "examTip": "WPA3-Enterprise, which builds on 802.1X + improved encryption and authentication, is currently the strongest wireless security mode."
    }
  ]
}





   {
  "questions": [
    {
      "id": 76,
      "question": "A network administrator is troubleshooting a slow network. Using a protocol analyzer, they see many TCP packets with the PSH flag set, even for relatively small data transfers. What does the PSH flag indicate, and is frequent use of the PSH flag generally considered normal or a potential sign of a problem?",
      "options": [
        "The PSH flag indicates that the packet should be prioritized for faster delivery; frequent use is normal.",
        "The PSH flag indicates that the data in the TCP segment should be delivered to the receiving application immediately, without waiting to buffer more data; while occasional use is normal, *frequent* use of the PSH flag, especially with small packets, can be inefficient and may indicate an application or network problem.",
        "The PSH flag indicates that the packet is part of a fragmented IP datagram.",
        "The PSH flag indicates that the packet is an acknowledgment (ACK)."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The TCP *PSH (Push)* flag is a hint to the receiving TCP stack. It tells the receiver to *immediately deliver* the data in the current segment to the *receiving application*, without waiting to buffer more data. *Occasional* use of the PSH flag is normal, especially for interactive applications. *However*, *frequent* use of the PSH flag, particularly with *small* data transfers, can be *inefficient*. It can indicate that: *Application behavior:* The application might be sending data in very small chunks and requesting immediate delivery, even when it's not strictly necessary. *Network problems:* The application might be trying to 'force' data through a congested or unreliable network by setting the PSH flag frequently. This *can actually worsen congestion*. While not *always* a problem, *excessive* PSH flags warrant investigation, especially when combined with other symptoms like slow performance or retransmissions. It's *not* about prioritization in the *network* (QoS handles that), fragmentation, or acknowledgments (ACK flag).",
      "examTip": "While the PSH flag itself isn't inherently bad, frequent use, especially with small packets, can indicate application behavior or underlying network issues and may reduce efficiency."
    },
    {
      "id": 77,
      "question": "You are configuring a Cisco router to participate in OSPF. The router has multiple interfaces, and you only want *some* of them to participate in OSPF. You also want to specify different OSPF *areas* for different interfaces. Which command, used within the OSPF process configuration (`router ospf [process-id]`), is used to define which interfaces participate in OSPF and which area they belong to, and what is the *critical* difference between how this command uses IP address information compared to commands like `ip address` on an interface?",
      "options":[
        "The `passive-interface` command; it uses IP addresses and subnet masks.",
        "The `network` command; it uses IP addresses and *wildcard masks*, not subnet masks.",
        "The `area` command; it uses IP addresses and subnet masks.",
        "The `redistribute` command; it uses IP addresses and subnet masks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `network` command, used *within* the OSPF process configuration (`router ospf [process-id]`), is how you tell OSPF which interfaces should participate in the routing protocol and which OSPF *area* those interfaces belong to. The *critical difference* is that the `network` command uses *wildcard masks*, *not* subnet masks. The syntax is: `network [network-address] [wildcard-mask] area [area-id]` *`[network-address]`*:  An IP address that falls *within* the network you want to include. *`[wildcard-mask]`*:  The *inverse* of the subnet mask.  A '0' bit in the wildcard mask means \"match this bit exactly\".  A '1' bit means \"don't care about this bit\". *`[area-id]`*: The OSPF area to which the interfaces matching this network statement will belong. For example: `network 192.168.1.0 0.0.0.255 area 0`  This includes any interface with an IP address in the 192.168.1.0/24 network in area 0. `passive-interface` prevents OSPF from *sending* hellos, but doesn't define participation. `area` defines area parameters, not participating networks. `redistribute` is for bringing routes *from other protocols* into OSPF.",
      "examTip": "The `network` command in OSPF configuration uses *wildcard masks*, not subnet masks, to specify which interfaces participate in OSPF and their area assignments."
    },
    {
      "id": 78,
      "question": "A network administrator wants to configure a Cisco switch to prevent rogue DHCP servers from operating on the network. They enable DHCP snooping globally. What additional configuration steps are required on the switch to make DHCP snooping effective, and what is the specific purpose of each step?",
      "options":[
        "No additional configuration is needed; DHCP snooping is fully automatic.",
        "Configure all switch ports as access ports. This automatically enables DHCP snooping on those ports.",
        "Configure the switch ports connected to legitimate DHCP servers as *trusted* ports using the `ip dhcp snooping trust` command in interface configuration mode. All other ports are *untrusted* by default.  Optionally, enable DHCP snooping on specific VLANs using `ip dhcp snooping vlan [vlan-list]`.",
        "Configure all switch ports as trunk ports."
      ],
      "correctAnswerIndex": 2,
      "explanation": "DHCP snooping works by classifying switch ports as *trusted* or *untrusted*: *Trusted ports:* Ports connected to *legitimate* DHCP servers. The switch allows *all* DHCP traffic (both client requests and server responses) on these ports. *Untrusted ports:* Ports connected to client devices (or potentially to rogue servers). The switch *only* allows DHCP *client* requests (like DHCPDISCOVER, DHCPREQUEST) to be forwarded from these ports. It *drops* any DHCP *server* responses (like DHCPOFFER, DHCPACK, DHCPNAK) received on untrusted ports. After enabling DHCP snooping globally (`ip dhcp snooping`), you *must* configure the ports connected to legitimate DHCP servers as *trusted* using the `ip dhcp snooping trust` command in *interface configuration mode*. By default, *all ports are untrusted* when DHCP snooping is enabled. Configuring ports as access or trunk ports is a separate VLAN configuration step, and *doesn't* directly enable or configure DHCP snooping. DHCP snooping is *not* fully automatic.",
      "examTip": "DHCP snooping requires enabling it globally, configuring trusted ports (connected to legitimate DHCP servers), and optionally enabling it per VLAN."
    },
    {
      "id": 79,
      "question": "You are troubleshooting an IPsec VPN tunnel that is not establishing. You have verified basic IP connectivity between the VPN gateways. Using the `show crypto isakmp sa` command on a Cisco router, you see *no* active ISAKMP SAs.  What does this indicate, and what are some potential causes?",
      "options":[
        "The IPsec tunnel (Phase 2) is not establishing, but ISAKMP (Phase 1) is working correctly.",
        "The ISAKMP (Phase 1) negotiation is failing, preventing the establishment of the secure channel needed for IPsec (Phase 2). Potential causes include mismatched ISAKMP policies (encryption, hashing, authentication, Diffie-Hellman group, lifetime), incorrect pre-shared keys or certificate configurations, or firewall rules blocking ISAKMP traffic (UDP port 500).",
        "The routing configuration is incorrect.",
        "The network cable is faulty."
      ],
      "correctAnswerIndex": 1,
      "explanation": "IPsec VPN establishment has two phases: *Phase 1 (ISAKMP)*: Establishes a secure channel for negotiating the IPsec SAs. If `show crypto isakmp sa` shows *no* active SAs, it means Phase 1 is failing. Mismatched ISAKMP policies, incorrect PSKs or certs, or blocked UDP 500 can cause it. A missing route might hamper communication, but the question states basic IP connectivity is verified, so the more likely cause is a Phase 1 mismatch or firewall block. A cable issue would break IP connectivity altogether, so that’s not it.",
      "examTip": "If `show crypto isakmp sa` shows no active SAs, Phase 1 is failing. Check ISAKMP policy parameters, keys, or firewall rules."
    },
    {
      "id": 80,
      "question": "A network administrator configures a Cisco router with the following commands: `router eigrp 100` `network 192.168.1.0 0.0.0.255` `passive-interface GigabitEthernet0/0` What is the effect of the `passive-interface GigabitEthernet0/0` command in this EIGRP configuration?",
      "options":[
        "It disables EIGRP routing on the GigabitEthernet0/0 interface.",
        "It prevents the router from sending EIGRP hello packets *out* the GigabitEthernet0/0 interface, thus preventing it from forming EIGRP neighbor adjacencies with any routers connected to that interface. However, the network connected to GigabitEthernet0/0 will still be advertised to other EIGRP neighbors.",
        "It prevents the router from receiving EIGRP updates on the GigabitEthernet0/0 interface.",
        "It configures the GigabitEthernet0/0 interface with a static IP address."
      ],
      "correctAnswerIndex": 1,
      "explanation": "In EIGRP, `passive-interface` stops sending hellos (and hence no adjacency forms), but the connected subnet is still advertised if it’s included under the `network` command. It doesn’t disable EIGRP entirely, just outbound updates on that interface. The router can still learn updates inbound, but effectively that interface is used only for that network’s advertisement, not neighbor relationships.",
      "examTip": "`passive-interface` in EIGRP or OSPF stops outbound hellos, preventing adjacency. The subnet is still advertised if matched in a `network` statement."
    },
    {
      "id": 81,
      "question": "You are troubleshooting a network where devices are experiencing intermittent connectivity. You suspect a problem with the load balancer that distributes traffic to multiple web server instances. Which of the following troubleshooting steps would be MOST effective in isolating the problem?",
      "options":[
        "Check the DNS server configuration.",
        "Bypass the load balancer and test connectivity to each web server instance directly by its IP address. If some servers work and others do not, focus on the non-working servers. Also check the load balancer's configuration and health checks.",
        "Check the DHCP server's lease table.",
        "Reboot the client computers."
      ],
      "correctAnswerIndex": 1,
      "explanation": "With intermittent connectivity and a load balancer in place, the best approach is to test each server behind the balancer directly. This determines if certain instances are malfunctioning or if the load balancer config is incorrect. DNS and DHCP are less likely to cause *intermittent* issues specifically with load-balanced services. Rebooting clients is a general step but doesn’t address the potential server or balancer misconfiguration.",
      "examTip": "When troubleshooting load-balanced environments, test each backend server individually and verify the load balancer’s health checks and config."
    },
    {
      "id": 82,
      "question": "A network administrator configures a Cisco router with the following access control list (ACL): ``` access-list 101 permit tcp any host 192.168.1.100 eq 80 access-list 101 permit tcp any host 192.168.1.100 eq 443 access-list 101 deny ip any any ``` The administrator then applies this ACL to the router's GigabitEthernet0/0 interface using the command `ip access-group 101 in`. What is the effect of this configuration on traffic *entering* the router through the GigabitEthernet0/0 interface?",
      "options":[
        "All traffic is permitted.",
        "All traffic is denied.",
        "Only HTTP (port 80) and HTTPS (port 443) traffic destined for the host 192.168.1.100 is permitted; all other traffic is blocked.",
        "All traffic is permitted except HTTP and HTTPS traffic destined for the host 192.168.1.100."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The ACL explicitly permits TCP traffic from any source to 192.168.1.100 on ports 80 and 443, then denies all other IP traffic. Applying it inbound on GigabitEthernet0/0 means any traffic entering that interface must match one of those permit statements or else it’s denied. So only HTTP/HTTPS to .100 is allowed; everything else is dropped.",
      "examTip": "Inbound ACLs apply to traffic as it arrives on the interface. If not explicitly permitted, it’s implicitly (or explicitly) denied."
    },
    {
      "id": 83,
      "question": "A network administrator is configuring a site-to-site IPsec VPN between two Cisco routers. They have configured the ISAKMP policy (Phase 1) and the IPsec transform set (Phase 2).  They have also configured the crypto map and applied it to the appropriate interface. However, the VPN tunnel is not establishing.  Which of the following commands would be MOST helpful in verifying that the *interesting traffic* (the traffic that should trigger the VPN tunnel) is being correctly identified and processed by the crypto map?",
      "options":[
        "show crypto isakmp sa",
        "show crypto ipsec sa",
        "show crypto map",
        "show interfaces"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`show crypto map` displays the crypto map configuration, including the ACL that defines interesting traffic. If the ACL doesn’t match the real traffic flows or is misconfigured, the tunnel won’t be triggered. `show crypto isakmp sa` and `show crypto ipsec sa` focus on established SAs or Phase 1/2 states, but if the ACL never matches, you won’t see SAs. `show interfaces` is too general.",
      "examTip": "`show crypto map` is crucial for verifying which ACLs define the interesting traffic and checking if they match your intended traffic."
    },
    {
      "id": 84,
      "question": "A network uses EIGRP as its routing protocol. The network administrator wants to summarize multiple contiguous networks into a single route advertisement to reduce the size of the routing tables on neighboring routers. Which command, and in which configuration context, should the administrator use to configure EIGRP route summarization on a Cisco router?",
      "options":[
        "Under the `router eigrp [autonomous-system-number]` configuration, use the `summary-address` command.",
        "Under the interface configuration mode for the interface *sending* the summarized route, use the `ip summary-address eigrp [as-number] [summary-address] [subnet-mask] [administrative-distance]` command.",
        "Under the `router eigrp [autonomous-system-number]` configuration, use the `auto-summary` command.",
        "Under the interface configuration mode for the interface *receiving* the summarized route, use the `ip summary-address eigrp [as-number] [summary-address] [subnet-mask]` command."
      ],
      "correctAnswerIndex": 1,
      "explanation": "EIGRP summarization is done *per interface* on the outbound side. The command is `ip summary-address eigrp [asn] [summary] [mask] [distance]` under the interface config. `auto-summary` is older style classful summarization, generally not recommended in modern networks. `summary-address` does not exist under router config in EIGRP. You do it under the interface to which you’re sending the summary.",
      "examTip": "In EIGRP, to summarize, use `ip summary-address eigrp` on the interface sending the summary route."
    },
    {
      "id": 85,
      "question": "A network administrator is troubleshooting a wireless network. Users report intermittent connectivity and slow performance. The administrator suspects RF interference. Besides other Wi-Fi networks, what are some common *non-Wi-Fi* sources of interference that can affect wireless networks operating in the 2.4 GHz band?",
      "options":[
        "FM radio broadcasts.",
        "Microwave ovens, Bluetooth devices, cordless phones (older models), wireless video cameras, poorly shielded electrical equipment, and some industrial equipment.",
        "Satellite communications.",
        "Cellular phone networks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Because 2.4 GHz is an unlicensed band, many devices, from microwaves to older cordless phones, can cause interference. FM radio is in a different range, as are satellites and cellular. Bluetooth and wireless cameras or poorly shielded motors, etc., can degrade Wi-Fi signals if they share the 2.4 GHz spectrum.",
      "examTip": "Non-802.11 devices in 2.4 GHz, like microwaves, Bluetooth, older cordless phones, can wreak havoc with Wi-Fi performance."
    },
    {
      "id": 86,
      "question": "A network is experiencing intermittent connectivity issues. A user reports being unable to access a specific web server. They are using a Windows computer. Which of the following commands would be MOST helpful in *quickly* determining if the user's computer has a valid IP address, subnet mask, and default gateway configured?",
      "options":[
        "ping 8.8.8.8",
        "tracert 8.8.8.8",
        "ipconfig /all",
        "nslookup www.google.com"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The `ipconfig /all` command on a Windows computer displays *detailed* network configuration information, *including the default gateway*. This is the *fastest* way to verify IP address, subnet mask, and default gateway settings on the user’s machine. Pinging 8.8.8.8 only tests external connectivity, `tracert` shows routes (not local config), and `nslookup` is for DNS queries.",
      "examTip": "`ipconfig /all` is a fundamental troubleshooting command on Windows for verifying network configuration settings."
    },
    {
      "id": 87,
      "question": "What is 'BGP hijacking', and what is a key characteristic of this type of attack that makes it difficult to prevent with traditional routing security measures?",
      "options": [
        "A method for encrypting BGP routing updates to ensure confidentiality.",
        "A type of phishing attack targeting network administrators.",
        "An attack where a malicious actor compromises a router (or exploits a misconfiguration) and falsely advertises BGP routes for IP address prefixes that they do not legitimately control, redirecting traffic to the attacker's network, potentially allowing interception, modification, or denial of service. It's difficult to detect because BGP inherently trusts announcements from peers, and validation mechanisms are not universally deployed.",
        "A technique for dynamically assigning IP addresses to BGP routers."
      ],
      "correctAnswerIndex": 2,
      "explanation": "BGP (Border Gateway Protocol) is the routing protocol that connects different autonomous systems (ASes). BGP hijacking occurs when an attacker or misconfiguration causes false route advertisements to spread, hijacking traffic. Traditional BGP is trust-based; it does not require cryptographic validation of route origins. While RPKI and IRR exist, they’re not yet universally enforced, making hijacking hard to detect. It’s not an encryption method, phishing, or IP assignment technique.",
      "examTip": "BGP hijacking exploits BGP’s trust model; route validation tools exist (like RPKI), but aren’t universally deployed, making prevention challenging."
    },
    {
      "id": 88,
      "question": "You are troubleshooting a network where devices are experiencing intermittent connectivity. You suspect a problem with duplicate IP addresses. Which of the following techniques would be the MOST reliable way to identify devices with duplicate IP addresses on a network segment?",
      "options": [
        "Ping each IP address on the network sequentially.",
        "Use a protocol analyzer (like Wireshark) to capture and analyze ARP traffic, looking for multiple MAC addresses responding to ARP requests for the same IP address.",
        "Check the DHCP server's lease table.",
        "Reboot all network devices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Duplicate IPs manifest as conflicting ARP replies. If two devices claim the same IP, they’ll both respond to ARP requests. A packet capture with a protocol analyzer can catch multiple replies to the same ARP request with different MAC addresses. Pinging each address might only reach one device. The DHCP table might not show static or rogue IP devices. Rebooting won’t necessarily solve or reveal duplicates.",
      "examTip": "Use a protocol analyzer to watch ARP replies for signs of multiple devices answering for the same IP."
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
      "explanation": "In 802.1Q trunking, the native VLAN is the VLAN to which untagged traffic belongs. By default, it’s VLAN 1. Changing it to VLAN 99 (for instance) helps avoid potential VLAN-hopping attacks or confusion from the default VLAN. It doesn’t disable tagging, nor does it make VLAN 99 the only one allowed. No traffic is encrypted by this command alone.",
      "examTip": "The trunk native VLAN handles untagged frames; changing it from VLAN 1 to a different VLAN is often recommended for security."
    },
    {
      "id": 90,
      "question": "A network administrator configures a Cisco router with the following command sequence, in global configuration mode: `access-list 101 permit tcp any host 192.168.1.100 eq 22` `access-list 101 deny ip any any` `line vty 0 4` `transport input ssh` `access-class 101 in` What is the combined effect of THESE specific commands, in this order?",
      "options": [
        "All traffic is permitted to the router.",
        "All traffic is denied to the router.",
        "Only SSH traffic (TCP port 22) from any source to the router's VTY lines is permitted. All other traffic to the VTY lines is blocked. The ACL does not affect traffic routed *through* the router, only traffic *to* the router's VTY lines for management.",
        "Only SSH traffic from the host 192.168.1.100 is permitted to the router's VTY lines."
      ],
      "correctAnswerIndex": 2,
      "explanation": "This ACL (101) permits tcp any -> host 192.168.1.100 eq 22, then denies all else. Applying with `access-class 101 in` on the VTY lines restricts *management* access (SSH) to the router. It doesn’t affect transit traffic. The router will accept SSH from any IP to 192.168.1.100:22, but no other protocols or ports are allowed to these VTY lines. That’s a best practice for secure remote management.",
      "examTip": "Applying `access-class` on VTY lines filters inbound management connections to the router itself, not transit traffic."
    },
    {
      "id": 91,
      "question": "A network administrator is troubleshooting a slow file transfer between two computers on the same subnet. Pings between the computers show low latency and no packet loss. The administrator has already verified that there are no duplex mismatches and that the interface error counters are not increasing.  What is the NEXT most likely area to investigate?",
      "options":[
        "The DNS server configuration.",
        "The DHCP server configuration.",
        "Resource utilization (CPU, memory, disk I/O) on both the sending and receiving computers, and the application-level protocols being used for the file transfer.",
        "The Spanning Tree Protocol configuration."
      ],
      "correctAnswerIndex": 2,
      "explanation": "With no packet loss and correct duplex settings, the physical/network layers seem fine. Slow file transfers can result from CPU, RAM, or disk I/O bottlenecks on either host, or from inefficiencies in the application protocol (e.g., SMB version issues). DNS or DHCP wouldn’t cause persistent slow throughput once the initial resolution or lease is done, and STP typically affects layer 2 path availability, not speed within a single VLAN if no loops are present.",
      "examTip": "After ruling out physical/network issues, check host resource constraints and app-layer factors for slow transfers."
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
      "explanation": "Cisco routers require the `host` command plus the `client-identifier` for DHCP reservations. The MAC 00:11:22:33:44:55 is written as 0100.1122.3344.55 in Cisco’s required format (`01` indicates an Ethernet MAC). `static-bind` is not valid syntax on Cisco IOS, nor is `address x client-id y` in that manner. The correct sequence is `host 192.168.1.50 255.255.255.0` and `client-identifier 0100.1122.3344.55` under the DHCP pool.",
      "examTip": "Cisco DHCP reservations use `host [ip] [mask]` and `client-identifier 01[mac]`, all under `ip dhcp pool`."
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
      "explanation": "Stub areas do not allow Type 5 external LSAs. Instead, a default route is injected by the ABR for external destinations. This reduces the routing table size within the stub area. Standard areas allow all LSAs, NSSA allows a limited form of external routes (Type 7 LSAs), and a totally stubby area is even more restrictive (blocking Type 3, 4, and 5).",
      "examTip": "A stub area omits external LSAs (Type 5), relying on a default route for external reachability."
    },
    {
      "id": 94,
      "question": "You are troubleshooting a network connectivity issue where users cannot access a particular website. They have valid IP configurations and can ping other external sites. You suspect a DNS problem. Which command-line tool, and with what specific syntax, would allow you to query a *specific* DNS server (e.g., 8.8.8.8) to resolve a specific domain name (e.g., www.example.com) and examine the response?",
      "options": [
        "ping www.example.com 8.8.8.8",
        "tracert www.example.com 8.8.8.8",
        "ipconfig /all",
        "nslookup www.example.com 8.8.8.8 (or dig www.example.com @8.8.8.8 on Linux/macOS)"
      ],
      "correctAnswerIndex": 3,
      "explanation": "The `nslookup` (Windows) or `dig` (Linux/macOS) utility allows querying a *specific* DNS server. For example, `nslookup www.example.com 8.8.8.8` or `dig www.example.com @8.8.8.8` queries Google’s DNS server (8.8.8.8) for the name resolution. ping/tracert do not let you specify a DNS server for resolution, and ipconfig /all just shows local config.",
      "examTip": "Use `nslookup` or `dig` with the desired DNS server to diagnose DNS issues and confirm correct resolution."
    },
    {
      "id": 95,
      "question": "A network is experiencing intermittent connectivity issues. A network administrator captures packets using a protocol analyzer. They observe a large number of TCP RST packets. What does the RST flag indicate, and what are some potential causes of a high volume of RST packets?",
      "options": [
        "Successful and graceful termination of a TCP connection.",
        "Successful DNS resolution.",
        "Abrupt termination of a TCP connection. Potential causes include application crashes, firewall rules blocking or resetting connections, network devices forcibly closing connections, misconfigured TCP keepalive settings, or network instability.",
        "Successful DHCP address assignment."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A TCP RST forcibly tears down a connection immediately, bypassing the normal FIN sequence. A high volume of RSTs suggests abrupt terminations, often from security devices, firewall policies, application crashes, or misconfigurations. DNS resolution and DHCP assignment do not generate RSTs in normal operation. A graceful close uses FIN, not RST.",
      "examTip": "RST signals abrupt termination of a TCP connection; investigate firewalls, app issues, or misconfigurations if you see many RST packets."
    },
    {
      "id": 96,
      "question": "A network administrator is configuring a wireless network and wants to implement the strongest possible security. Which wireless security protocol should they choose, and what are its key security features compared to older protocols?",
      "options":[
        "WEP (Wired Equivalent Privacy); it provides strong encryption and is easy to configure.",
        "WPA3-Enterprise; it offers stronger encryption (GCMP-256), individualized data encryption, and improved authentication mechanisms (including SAE - Simultaneous Authentication of Equals) compared to WPA2 and earlier protocols.",
        "WPA2-Personal with a strong pre-shared key (PSK); it's the most secure option.",
        "An open network with no encryption, combined with MAC address filtering."
      ],
      "correctAnswerIndex": 1,
      "explanation": "WPA3-Enterprise provides the highest level of security available for Wi-Fi, surpassing WPA2-Enterprise. It features stronger encryption ciphers (GCMP-256), improved key exchange (SAE), and better management frame protection. WEP is highly insecure, WPA2-Personal uses a shared PSK (less secure for enterprise), and open networks with MAC filtering are trivially bypassed.",
      "examTip": "For the strongest wireless security, choose WPA3-Enterprise with robust encryption and authentication enhancements over WPA2."
    },
    {
      "id": 97,
      "question": "A network administrator wants to configure a Cisco switch to prevent rogue DHCP servers from operating on the network. They enable DHCP snooping globally with the `ip dhcp snooping` command. They then configure the port connected to the legitimate DHCP server as a trusted port using the `ip dhcp snooping trust` command.  However, they forget to configure any VLANs for DHCP snooping. What will be the effect of this configuration?",
      "options":[
        "DHCP snooping will be effective on all VLANs.",
        "DHCP snooping will only be effective on VLAN 1.",
        "DHCP snooping will not be effective on any VLAN until it is explicitly enabled on specific VLANs using the `ip dhcp snooping vlan [vlan-list]` command.",
        "DHCP snooping will cause the switch to crash."
      ],
      "correctAnswerIndex": 0,
      "explanation": "By default, when you enable DHCP snooping globally (`ip dhcp snooping`), it is actually enabled for *all* VLANs unless you specify otherwise with `ip dhcp snooping vlan [vlan-list]`. So forgetting to specify VLANs typically means DHCP snooping is active on *every* VLAN. In some older IOS versions you might need to enable it explicitly per VLAN, but in most modern Cisco IOS, global enable applies to all VLANs unless restricted.",
      "examTip": "In most current Cisco switches, enabling DHCP snooping globally covers all VLANs unless you limit it with `ip dhcp snooping vlan`."
    },
    {
      "id": 98,
      "question": "A company has a network with multiple VLANs.  A Layer 3 switch is used for inter-VLAN routing.  A network administrator configures an access control list (ACL) on the Layer 3 switch to control traffic flow between the VLANs.  The ACL is as follows: ``` access-list 101 permit tcp any host 192.168.10.50 eq 80 access-list 101 permit tcp any host 192.168.10.50 eq 443 access-list 101 deny ip any any ``` The administrator then applies this ACL to the SVI (Switched Virtual Interface) for VLAN 10 using the command `ip access-group 101 in`.  Assuming VLAN 10 has the subnet 192.168.10.0/24, and the server with IP address 192.168.10.50 is on a *different* VLAN, what traffic will be allowed *from* VLAN 10 *to* the server at 192.168.10.50?",
      "options": [
        "All traffic from VLAN 10 to the server will be allowed.",
        "All traffic from VLAN 10 to the server will be denied.",
        "Only HTTP (port 80) and HTTPS (port 443) traffic from VLAN 10 to the server will be allowed; all other traffic is blocked.",
        "All traffic is permitted except HTTP and HTTPS."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Applying the ACL inbound on VLAN 10’s SVI means it filters traffic *originating* from VLAN 10. The permit statements explicitly allow TCP port 80 and 443 to 192.168.10.50. All else is denied by the final `deny ip any any`. Thus only HTTP and HTTPS traffic flows from VLAN 10 to that server, and nothing else. If the server is in a different VLAN, the traffic must traverse the L3 switch, so the ACL applies.",
      "examTip": "Inbound ACL on an SVI filters traffic from that VLAN to other networks; specify which ports/protocols are permitted."
    },
    {
      "id": 99,
      "question": "You are troubleshooting a network performance issue. Users report that a specific web application is extremely slow.  You use a protocol analyzer to capture network traffic and observe the following: *   A large number of TCP retransmissions. *   Frequent duplicate ACKs. *   Many TCP packets with the PSH flag set. *   Occasional TCP ZeroWindow messages *from the web server*. *   The 'Time' column in your protocol analyzer shows significant delays between the client's requests and the server's responses, even for small requests. Which of the following is the MOST accurate and complete diagnosis of the problem, based on these observations?",
      "options": [
        "The problem is likely caused by a DNS server misconfiguration.",
        "The problem is likely caused by a faulty network cable.",
        "The problem is likely caused by network congestion, packet loss, and/or a resource bottleneck on the web server (CPU, memory, disk I/O, or network interface). The frequent PSH flags might indicate the application is trying to force data through a congested or unreliable network, potentially exacerbating the problem.",
        "The problem is likely caused by the user's web browser being misconfigured."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Multiple signs point to significant performance issues: *Lots of retransmissions and dup ACKs* suggest packet loss or severe network problems. *TCP ZeroWindow messages from the server* indicate the server can’t process incoming data quickly enough (resource bottleneck). *Frequent PSH flags with small packets* might be an app that’s pushing data aggressively, possibly worsening congestion or revealing an underlying performance issue. It’s not purely DNS, not a simple cable fault, nor a mere browser misconfiguration.",
      "examTip": "Congestion, server resource limits, and excessive PSH usage can cause retransmissions, zero windows, and poor performance in TCP-based applications."
    },
    {
      "id": 100,
      "question": "A company's network is configured with multiple VLANs, and a Layer 3 switch is used for inter-VLAN routing. The network administrator wants to control which types of traffic are allowed to flow *between* specific VLANs. Which of the following technologies, and where should it be configured, would BEST achieve this?",
      "options":[
        "Spanning Tree Protocol (STP) on the switch ports.",
        "Port security on the switch ports.",
        "Access control lists (ACLs) applied to the Switched Virtual Interfaces (SVIs) on the Layer 3 switch, or to the physical interfaces if routing directly on those.",
        "DHCP snooping on the switch."
      ],
      "correctAnswerIndex": 2,
      "explanation": "To control traffic flowing from one VLAN to another, you need a Layer 3 solution—namely ACLs on the Layer 3 switch. By applying ACLs to the SVIs (or the router interfaces if using external routing), you can permit or deny specific traffic types. STP prevents loops, port security restricts MAC addresses, and DHCP snooping is for rogue DHCP server prevention; none address controlling inter-VLAN traffic in detail.",
      "examTip": "Apply ACLs at Layer 3 (on SVIs or router interfaces) to restrict/permit traffic between VLANs in a Layer 3-switched environment."
    }
  ]
}




          
