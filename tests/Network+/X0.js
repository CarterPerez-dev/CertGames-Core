db.tests.insertOne({
  "category": "nplus",
  "testId": 10,
  "testName": "Network+ Practice Test #10 (Ultra Level)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A large enterprise uses dual-homed BGP for high availability. They want to ensure inbound traffic from external ASes prefers ISP A over ISP B for their main subnet. Which BGP attribute is typically manipulated on the less-preferred path?",
      "options": [
        "Local Preference",
        "MED",
        "AS-Path Prepending",
        "Weight"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Local Preference and Weight affect outbound traffic from within your AS. MED is a hint for neighbors, but not always honored. AS-Path Prepending (correct) artificially lengthens the path to discourage external neighbors from routing inbound traffic through that path.",
      "examTip": "To shape inbound traffic from external ASes, extend the AS path on the route you want to de-prioritize."
    },
    {
      "id": 2,
      "question": "In an MST region, multiple VLANs are assigned to MST Instance 1. Which ADVANTAGE does this provide compared to running a separate RSTP instance per VLAN?",
      "options": [
        "Faster DHCP assignment for each VLAN",
        "Lower CPU overhead by sharing a single STP topology among grouped VLANs",
        "Automatic NAC posture checks for STP participants",
        "Half-duplex operation prevents bridging loops"
      ],
      "correctAnswerIndex": 1,
      "explanation": "MST groups VLANs under fewer STP instances, reducing overhead vs. one instance per VLAN. DHCP speed, NAC posture checks, and half-duplex are unrelated. This is MST’s core benefit.",
      "examTip": "MST significantly cuts down the CPU load that PVST+ would require for many VLANs."
    },
    {
      "id": 3,
      "question": "Which advanced QoS feature offers strict priority for real-time flows like voice, plus additional class-based queueing for other traffic?",
      "options": [
        "Weighted Fair Queueing (WFQ)",
        "WRED (Weighted Random Early Detection)",
        "LLQ (Low Latency Queueing)",
        "RED (Random Early Detection)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "WFQ or RED variants do not provide strict priority for real-time. LLQ (correct) merges strict priority with CBWFQ, ideal for voice/video. This ensures minimal jitter and delay for critical flows.",
      "examTip": "LLQ includes a priority queue for time-sensitive packets and weighted scheduling for everything else."
    },
    {
      "id": 4,
      "question": "A distribution switch sees frequent TCN (Topology Change Notification) events. Logs indicate a single access port toggles from blocking to forwarding repeatedly. Which FIRST step helps isolate the root cause?",
      "options": [
        "Disable DHCP snooping in that VLAN",
        "Manually set the port to half-duplex",
        "Shut down or investigate the flapping port/cable for physical issues",
        "Enable trunk dynamic auto mode"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Flapping ports cause STP re-convergence. Investigating or disabling the flapping port is the initial measure. DHCP snooping, half-duplex, or trunk negotiation do not directly fix port toggling.",
      "examTip": "A port flapping state triggers TCNs. Stabilize or shut the problematic interface to stop repeated STP recalculations."
    },
    {
      "id": 5,
      "question": "Which direct measure can reduce overhead on an EIGRP router that regularly sees 'Stuck in Active' queries flooding across the topology?",
      "options": [
        "Enable spanning tree root guard on distribution switches",
        "Designate remote routers as EIGRP stubs to limit query propagation",
        "Use half-duplex on all EIGRP interfaces",
        "Configure DHCP scope reservations for each subnet"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Root guard, half-duplex, or DHCP reservations are not relevant. Marking routers as EIGRP stubs (correct) bounds query range, preventing extensive SIA issues. This is a known technique for large networks.",
      "examTip": "Stub routing in EIGRP confines queries and lessens the risk of SIA storms in hub-and-spoke designs."
    },
    {
      "id": 6,
      "question": "A router redistributes RIP routes into OSPF. Within OSPF, which router type describes this scenario?",
      "options": [
        "Internal Router",
        "ABR (Area Border Router)",
        "ASBR (Autonomous System Boundary Router)",
        "DR (Designated Router)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "An ASBR redistributes external routes from another routing domain. Internal routers, ABRs, and DRs serve different roles. The scenario specifically calls for route injection from RIP into OSPF, so that’s an ASBR.",
      "examTip": "OSPF calls any router that imports non-OSPF routes an ASBR, generating external LSAs (Type 5 or Type 7)."
    },
    {
      "id": 7,
      "question": "Which statement accurately describes OSPF stub vs. NSSA areas?",
      "options": [
        "Stub areas block external Type 5 LSAs, while NSSAs allow external routes as Type 7 within that area",
        "Both stub and NSSA block all routing updates from area 0",
        "NSSA stands for 'No Summaries, Stub Area' and can never import external routes",
        "Stub areas require half-duplex to converge quickly"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Stub areas block Type 5 LSAs but can receive Type 3 summaries. NSSA allows external injection as Type 7 LSAs, which ABR translates into Type 5 externally. Summaries from area 0 still pass in a stub. Half-duplex is unrelated.",
      "examTip": "NSSAs permit external routes (Type 7) within a ‘stub-like’ area. ABR translates them to Type 5 for the rest of OSPF."
    },
    {
      "id": 8,
      "question": "Which trunking protocol is vendor-neutral, enabling VLAN tags on a link across multi-vendor switches?",
      "options": [
        "ISL",
        "CDP",
        "802.1Q",
        "DTP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "ISL is Cisco-proprietary, CDP is discovery, DTP negotiates trunking but is also Cisco-specific. 802.1Q (correct) is the open standard for VLAN tagging across heterogeneous equipment.",
      "examTip": "802.1Q trunking is near-universal. Ensure both ends match 802.1Q for cross-vendor VLAN traffic."
    },
    {
      "id": 9,
      "question": "Which NAC posture method reassigns a failing endpoint to a quarantine VLAN or dACL, letting it only access remediation servers?",
      "options": [
        "DHCP reservation",
        "802.1X RADIUS policy returning dynamic VLAN or ACL",
        "LLDP neighbor detection",
        "CDP trunk mode"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is IP assignment, Option B (correct) NAC posture plus 802.1X is the standard solution, Option C and D are discovery or trunk config. RADIUS can push a restricted VLAN or ACL for endpoints failing posture checks.",
      "examTip": "Combining NAC posture checks with 802.1X allows dynamic reconfiguration if a device is non-compliant."
    },
    {
      "id": 10,
      "question": "Which advanced firewall feature involves the device terminating TLS, inspecting decrypted payloads, and re-encrypting before forwarding to the server?",
      "options": [
        "Stateless ACL filtering",
        "SSL/TLS interception (forward proxy)",
        "DHCP Option 82 insertion",
        "EIGRP summarization"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is layer 3, Option B (correct) is a man-in-the-middle approach for HTTPS inspection, Option C is DHCP security, Option D is routing. SSL interception helps detect threats hidden in encrypted traffic.",
      "examTip": "NGFWs can do forward proxy for HTTPS, analyzing content inside encrypted sessions to thwart hidden malware."
    },
    {
      "id": 11,
      "question": "Which phenomenon describes forging ARP replies, poisoning the gateway MAC address in hosts, enabling an on-path attack?",
      "options": [
        "MAC flooding",
        "DHCP snooping",
        "ARP spoofing",
        "Double-tagging VLAN hopping"
      ],
      "correctAnswerIndex": 2,
      "explanation": "MAC flooding saturates the switch’s CAM, DHCP snooping is a security feature, double-tagging is a trunk exploit. ARP spoofing (correct) forges ARP responses. Attackers can impersonate the gateway or a target host for intercepting traffic.",
      "examTip": "Enable Dynamic ARP Inspection to block ARP spoofing. This references IP-to-MAC data from DHCP snooping or static tables."
    },
    {
      "id": 12,
      "question": "Which scenario-based question is BEST resolved by using LACP EtherChannel between two switches?",
      "options": [
        "How to unify DHCP scopes across different subnets",
        "How to combine multiple physical links for higher bandwidth and redundancy in one logical channel",
        "How to block bridging loops on access ports",
        "How to authenticate endpoints with posture checks"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is IP address management, Option B (correct) is link aggregation, Option C is STP-based security, Option D is NAC. LACP aggregates multiple Ethernet links into a single logical link for throughput and failover.",
      "examTip": "EtherChannel with LACP is a standard solution for bundling multiple parallel links between switches or to servers."
    },
    {
      "id": 13,
      "question": "A user’s port is err-disabled after connecting a small consumer switch with multiple MACs. Which feature triggered this behavior?",
      "options": [
        "LLDP mismatch detection",
        "BPDU guard for bridging loops",
        "Port security limiting MAC addresses on that port",
        "DHCP Snooping Option 82"
      ],
      "correctAnswerIndex": 2,
      "explanation": "LLDP mismatch typically warns but doesn’t err-disable, BPDU guard triggers if STP frames appear, Option 3 (correct) is classic if more MAC addresses appear than allowed, Option 4 is DHCP security. Port security with a MAC limit often sets err-disable if exceeded.",
      "examTip": "When multiple MACs appear unexpectedly on an access port, port security can shut it down to prevent unauthorized bridging."
    },
    {
      "id": 14,
      "question": "Which direct measure can block a malicious user from forming a trunk on an access port and performing VLAN hopping attacks?",
      "options": [
        "Enable trunk dynamic auto negotiation on all ports",
        "Use ‘switchport mode access’ and disable DTP on end-user ports",
        "Set VLAN 1 as the native VLAN for consistency",
        "Enable half-duplex for all user ports"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option 1 fosters trunk negotiation, Option 2 (correct) statically sets the port to access, disabling trunk formation. Option 3 is insecure (VLAN 1 is default native). Option 4 is performance degrade. Disabling DTP prevents auto trunk creation.",
      "examTip": "Always turn off DTP on user ports to thwart VLAN hopping. Hard-code them as access with no negotiation."
    },
    {
      "id": 15,
      "question": "In an OSPF multi-area network, which router type holds separate LSDBs for both the backbone (area 0) and non-backbone areas it connects?",
      "options": [
        "ASBR",
        "NSSA router",
        "ABR",
        "DR"
      ],
      "correctAnswerIndex": 2,
      "explanation": "ASBR redistributes external routes, NSSA router is a sub-type handling Type 7, and DR is a multi-access segment role. ABR (correct) interconnects area 0 with other areas, storing multiple LSDBs.",
      "examTip": "An Area Border Router is responsible for summarizing and exchanging routes between backbone and non-backbone areas."
    },
    {
      "id": 16,
      "question": "Which NAC scenario-based question is BEST addressed by implementing 802.1X with dynamic VLAN assignment from a posture-checking RADIUS server?",
      "options": [
        "How to unify all switchports into trunk mode",
        "How to ensure unpatched devices are automatically placed in a remediation VLAN",
        "How to half-duplex the WAN for less overhead",
        "How to disable DHCP across all VLANs"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Trunking, half-duplex, and disabling DHCP are irrelevant. NAC posture solutions typically push a quarantine VLAN if the endpoint fails compliance. That’s exactly what 802.1X dynamic VLAN assignment does.",
      "examTip": "NAC posture can reassign a failing device to a restricted VLAN automatically, preventing full network access."
    },
    {
      "id": 17,
      "question": "Which advanced firewall capability can identify a flow as 'BitTorrent' or 'Dropbox' even if the application hides behind port 80 or 443?",
      "options": [
        "DNS-based round-robin",
        "Stateless ACL filter",
        "Application-layer deep packet inspection in an NGFW",
        "DHCP snooping pass-through"
      ],
      "correctAnswerIndex": 2,
      "explanation": "DNS round-robin is load distribution, stateless ACLs check IP/port only, DHCP snooping is IP security. An NGFW with layer 7 inspection (correct) detects actual applications behind common ports.",
      "examTip": "Next-gen firewalls do content inspection or signature matching at layer 7, surpassing mere port-based rules."
    },
    {
      "id": 18,
      "question": "Which protocol ensures multiple routers share one virtual IP for a default gateway, with one router actively responding and the other(s) on standby?",
      "options": [
        "HSRP or VRRP",
        "DHCP failover",
        "BPDU guard",
        "BGP prefix-lists"
      ],
      "correctAnswerIndex": 0,
      "explanation": "HSRP (Cisco) or VRRP (open standard) provide gateway redundancy. DHCP failover is IP lease management, BPDU guard is STP, BGP prefix-lists filter routes. HSRP or VRRP is correct for FHRP solutions.",
      "examTip": "HSRP/VRRP let hosts use one gateway IP, while multiple routers behind it ensure redundancy if one fails."
    },
    {
      "id": 19,
      "question": "Which EIGRP concept allows near-instant failover if the successor route fails, provided another route meets the feasibility condition?",
      "options": [
        "Auto-summary at classful boundaries",
        "Feasible successor in the topology table",
        "Spanning tree root guard for EIGRP",
        "Passive-interface default"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Auto-summary is summarization, root guard is STP, passive-interface stops sending updates. The feasible successor (correct) is the backup route with a reported distance less than the successor’s feasible distance, enabling immediate switchover.",
      "examTip": "A feasible successor ensures EIGRP can skip query states upon primary route failure, enabling fast convergence."
    },
    {
      "id": 20,
      "question": "Which direct measure helps block inbound SSH attempts from arbitrary external IPs while permitting known management networks?",
      "options": [
        "Set half-duplex on the WAN interface",
        "Enable trunk auto negotiation on the firewall",
        "ACL/Firewall rule restricting TCP 22 to a known source subnet",
        "Change the DNS server to 8.8.8.8"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Half-duplex is link mismatch, trunk negotiation is for VLAN bridging, DNS server is name resolution. An ACL limiting SSH to certain IP ranges (correct) is the standard best practice for inbound management security.",
      "examTip": "Inbound management ports should only accept connections from trusted source IPs. A simple ACL or firewall policy does this."
    },
    {
      "id": 21,
      "question": "Which method is recommended for controlling egress traffic in a large iBGP deployment so the entire AS chooses the same exit path for a destination?",
      "options": [
        "MED",
        "Local Preference",
        "Weight assigned to eBGP routes",
        "AS-Path Prepending"
      ],
      "correctAnswerIndex": 1,
      "explanation": "MED is inbound. Weight is local to one router and not propagated. AS-Path Prepending influences inbound from external. Local Preference (correct) is distributed among iBGP routers, telling them which route to use for egress.",
      "examTip": "Local_Pref is an iBGP-wide attribute for which exit to use. A higher local_pref route is preferred by all iBGP routers."
    },
    {
      "id": 22,
      "question": "Which trunk detail typically causes traffic for a certain VLAN to fail across a trunk link if incorrectly configured?",
      "options": [
        "LLDP is disabled on the trunk",
        "VTP is in transparent mode",
        "The VLAN is not in the trunk’s allowed VLAN list",
        "DHCP Option 82 is not inserted"
      ],
      "correctAnswerIndex": 2,
      "explanation": "LLDP or VTP modes can be helpful but not necessarily block VLAN traffic, Option 3 (correct) is the usual culprit. DHCP Option 82 is a relay detail. If the VLAN is excluded from the trunk, its traffic won’t pass.",
      "examTip": "Always check ‘show interface trunk’ or equivalent to confirm your needed VLANs are permitted on the trunk."
    },
    {
      "id": 23,
      "question": "Which NAC approach is used to verify OS patches and AV status, restricting or denying devices that fail checks at the time of 802.1X authentication?",
      "options": [
        "ARP inspection with Option 43",
        "EAP posture check (e.g., EAP-PEAP plus NAC agent)",
        "DHCP snooping pass-through",
        "Spanning tree in RPVST+"
      ],
      "correctAnswerIndex": 1,
      "explanation": "ARP inspection and DHCP snooping are layer 2/3 security, not posture. STP is bridging loops. EAP posture checks (correct) use a NAC agent verifying compliance, then the RADIUS server instructs the switch to allow or quarantine the endpoint.",
      "examTip": "NAC posture solutions integrate with 802.1X EAP. If a device is out of compliance, it’s quarantined or blocked until resolved."
    },
    {
      "id": 24,
      "question": "A WAN router sees ephemeral packet drops for voice calls under microburst conditions. Which step addresses real-time voice reliability?",
      "options": [
        "Half-duplex negotiation to slow traffic",
        "Root guard for bridging loops",
        "Enable LLQ or priority queueing to protect voice packets from bursts",
        "Disable STP in the data center core"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Half-duplex is undesirable, bridging loops are STP issues, disabling STP is risky. Prioritizing voice traffic with LLQ or priority queueing (correct) ensures minimal latency/jitter. That’s standard for voice QoS.",
      "examTip": "To handle microbursts, put voice in a priority queue so it’s not delayed or dropped when bursts fill the queue."
    },
    {
      "id": 25,
      "question": "Which direct measure can hamper VLAN hopping by preventing dynamic trunk formation on user ports?",
      "options": [
        "Enable trunk dynamic desirable",
        "switchport mode access + switchport nonegotiate to disable DTP",
        "Use VLAN 1 as the native VLAN for consistency",
        "Apply half-duplex on the port to reduce collisions"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option 1 fosters trunk negotiation, Option 2 (correct) sets the port to static access, Option 3 is insecure, Option 4 is performance degrade. Hard-coding access mode plus disabling DTP blocks VLAN hopping attempts.",
      "examTip": "Disabling DTP on user ports is a fundamental switch security practice to avoid undesired trunk formation."
    },
    {
      "id": 26,
      "question": "Which BGP attribute is commonly used to label routes so they can be filtered or have policies applied, but does not directly affect path selection by default?",
      "options": [
        "Local Preference",
        "Community",
        "MED",
        "Origin"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Local Preference influences egress, MED shapes inbound, Origin is a tiebreaker. Communities (correct) are tags that can be matched by route-maps for custom policies, but alone they do not alter path selection. They’re used in a more flexible policy context.",
      "examTip": "BGP communities let you group routes for advanced manipulations or to signal your neighbors on how to treat them (e.g., no-export)."
    },
    {
      "id": 27,
      "question": "Which NAC scenario-based question is BEST resolved by implementing dACLs (downloadable ACLs) from the RADIUS server upon user authentication?",
      "options": [
        "How to unify STP root settings for multiple VLANs",
        "How to forcibly half-duplex all user devices",
        "How to tailor network permissions per user after 802.1X login without reconfiguring the switch ACLs manually",
        "How to distribute DHCP offers from multiple servers"
      ],
      "correctAnswerIndex": 2,
      "explanation": "STP, half-duplex, and DHCP distribution are unrelated. dACL (correct) is a NAC approach letting the RADIUS server push unique ACL rules per session. This yields dynamic, user-specific network policies.",
      "examTip": "Downloadable ACLs from RADIUS can apply session-based permissions or restrictions without static configs on each switch."
    },
    {
      "id": 28,
      "question": "A router has a static default route to the internet. To share it with OSPF neighbors, which standard approach is used?",
      "options": [
        "default-information originate [always]",
        "Auto-summary at classful boundaries",
        "Add half-duplex to the WAN link",
        "Use MST bridging"
      ],
      "correctAnswerIndex": 0,
      "explanation": "In OSPF, the standard command to advertise a default route is 'default-information originate', possibly with 'always' if no default route is present in the route table. Summarization, link mismatch, or MST bridging are not relevant. OSPF uses that command to inject 0.0.0.0/0.",
      "examTip": "OSPF doesn’t automatically forward a default route. ‘default-information originate’ instructs OSPF to flood that default route to neighbors."
    },
    {
      "id": 29,
      "question": "Which advanced firewall technique identifies the real application behind a session (e.g., Skype, BitTorrent) even if it uses port 443?",
      "options": [
        "Static NAT for inbound sessions",
        "Application-layer DPI (Layer 7 inspection)",
        "CDP neighbor authentication",
        "VTP pruning"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Static NAT is address translation. App-layer DPI (correct) inspects data at layer 7. CDP is discovery, VTP pruning is VLAN distribution. Next-generation firewalls use DPI to detect the actual application traffic signature.",
      "examTip": "App-aware inspection is the hallmark of NGFW—no reliance on just port numbers to identify traffic."
    },
    {
      "id": 30,
      "question": "Which NAC posture solution can ensure that if a device lacks required OS patches, it’s placed in a restricted VLAN upon 802.1X authentication?",
      "options": [
        "Port security limiting MAC addresses",
        "BPDU guard on user ports",
        "802.1X RADIUS server returning a quarantine VLAN if posture fails",
        "Half-duplex trunk negotiation"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Port security, BPDU guard, and half-duplex are unrelated. NAC posture plus 802.1X (correct) is the standard method for quarantining an unpatched device. The RADIUS server instructs the switch to move the endpoint to a restricted VLAN.",
      "examTip": "NAC posture enforcement typically uses 802.1X plus a policy server to push VLAN or ACL changes upon authentication."
    },
    {
      "id": 31,
      "question": "A router sees hold-time expirations in an eBGP session with a neighbor. Which single check is recommended FIRST?",
      "options": [
        "Ensure both neighbors have matching keepalive/hold timers and confirm TCP 179 reachability",
        "Enable trunk dynamic auto on the WAN link",
        "Configure half-duplex on the router interface",
        "Set a static NAT for the neighbor’s IP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option 1 is the typical cause: mismatched timers or blocked port 179 can cause frequent session resets. The other options are trunk or link mismatch or NAT. Ensuring keepalives are consistent and that firewall rules permit BGP traffic is critical.",
      "examTip": "BGP adjacency uses TCP 179. Any mismatch in hold/keepalive or blocked port 179 will cause repeated resets."
    },
    {
      "id": 32,
      "question": "Which trunking approach do Cisco and non-Cisco switches both commonly support to pass multiple VLANs?",
      "options": [
        "ISL encapsulation",
        "802.1Q standard",
        "CDP trunk bridging",
        "DTP dynamic desirable"
      ],
      "correctAnswerIndex": 1,
      "explanation": "ISL and DTP are Cisco-proprietary, CDP is discovery. 802.1Q (correct) is the IEEE standard, used multi-vendor for VLAN tagging on trunk ports.",
      "examTip": "802.1Q is the universal trunk encapsulation method recognized across different switch vendors."
    },
    {
      "id": 33,
      "question": "Which direct measure helps mitigate a rogue DHCP server on the LAN, handing out bogus IP info?",
      "options": [
        "DHCP snooping designating trusted ports for valid DHCP offers",
        "Root guard for bridging loops",
        "802.1X half-duplex posture checks",
        "ISL trunking across user ports"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option 1 is correct: DHCP snooping ensures only known server ports can send DHCP offers. Root guard is STP, posture checks or trunking do not fix rogue DHCP. DHCP snooping is standard to block unauthorized servers.",
      "examTip": "DHCP snooping designates only certain interfaces as ‘trusted’ for DHCP server messages, preventing rogue server confusion."
    },
    {
      "id": 34,
      "question": "Which concept best describes repeatedly adding the local AS number to an advertised prefix, discouraging inbound traffic via that path?",
      "options": [
        "Local Preference increase",
        "AS-Path Prepending",
        "MED setting to 0",
        "Community tagging"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Local Preference is outbound. MED also influences inbound but not by lengthening the path. Communities are tags. AS-Path Prepending (correct) is the standard trick to make a route appear longer, reducing inbound traffic from outside ASes.",
      "examTip": "When multi-homed, to shift inbound flows away from one link, prepend the path in BGP so neighbors see a larger AS-Path length."
    },
    {
      "id": 35,
      "question": "Which advanced NAC method checks an endpoint’s firewall or antivirus status, assigning a restricted VLAN if out of date?",
      "options": [
        "DHCP exhaustion",
        "BPDU guard trunking",
        "802.1X posture-based policy from a RADIUS server",
        "Spanning tree MST"
      ],
      "correctAnswerIndex": 2,
      "explanation": "DHCP exhaustion is a DoS scenario, BPDU guard is STP security, MST is for multi-VLAN STP. NAC posture (correct) with 802.1X checks security compliance, then possibly quarantines the device in a restricted VLAN.",
      "examTip": "Posture checks can include AV signatures, OS patch levels, etc. Non-compliant endpoints get a limited VLAN or denial of service."
    },
    {
      "id": 36,
      "question": "Which advanced feature in EIGRP ensures a backup route is ready if it meets the feasibility condition, minimizing downtime when the primary path fails?",
      "options": [
        "Feasible successor",
        "OSPF area type",
        "DHCP relay with IP helper",
        "Half-duplex bridging"
      ],
      "correctAnswerIndex": 0,
      "explanation": "OSPF area type is a different protocol, DHCP relay is IP broadcast forwarding, half-duplex is link mismatch. Feasible successor (correct) is a key EIGRP concept, enabling instant route failover without queries.",
      "examTip": "If a route’s feasible distance > the route’s reported distance from another neighbor, that neighbor route can be a feasible successor."
    },
    {
      "id": 37,
      "question": "Which approach in STP ensures no device plugged into an access port can override the existing root by sending superior BPDUs?",
      "options": [
        "DHCP snooping for BPDUs",
        "Root guard configured on the access port",
        "Half-duplex to block trunk formation",
        "CDP trunk bridging"
      ],
      "correctAnswerIndex": 1,
      "explanation": "DHCP snooping is IP-based, half-duplex is a mismatch, CDP is discovery. Root guard (correct) disqualifies ports from becoming root if they receive better BPDUs, preserving the designated root. This is used on ports facing potential new switches.",
      "examTip": "Root guard is typically on distribution or core ports where you don’t expect another root-capable device."
    },
    {
      "id": 38,
      "question": "A distribution switch CPU spikes from repeated route queries in EIGRP. How does marking remote routers as 'stub' help?",
      "options": [
        "Prevents them from sending or forwarding queries beyond themselves",
        "Forces half-duplex for traffic shaping",
        "Gives them a default gateway of 0.0.0.0 only",
        "Disables DHCP across the network"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) means the stub router does not propagate queries further. Option B is link mismatch, Option C is generic routing, Option D is an IP assignment measure. EIGRP stubs help contain query scope.",
      "examTip": "Stubs respond to queries but do not forward them, reducing the 'Stuck in Active' risk in large topologies."
    },
    {
      "id": 39,
      "question": "Which next-gen firewall feature can passively or inline inspect layer 7 data to identify apps like Skype or BitTorrent, even if using TLS on port 443?",
      "options": [
        "Stateful firewall rules at layer 4",
        "DPI-based application awareness",
        "DHCP snooping pass-through",
        "802.1D bridging"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Layer 4 is not enough for deep analysis. DHCP snooping is IP assignment security. 802.1D is STP. DPI-based app awareness (correct) sees the actual app signatures within the encrypted or unencrypted data flows.",
      "examTip": "NGFWs detect applications by signature, not just ports, enabling fine-grained traffic policies."
    },
    {
      "id": 40,
      "question": "Which approach is used to unify logs from firewalls, IDS, and servers into correlated, real-time analysis for advanced threat detection?",
      "options": [
        "Syslog server with no analytics",
        "SIEM platform",
        "CDP neighbor logging",
        "DHCP snooping logs"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A basic syslog server lacks correlation. CDP is device discovery, DHCP snooping is address security. A SIEM (correct) aggregates logs from multiple sources and correlates them for real-time threat detection.",
      "examTip": "SIEM solutions provide advanced log correlation and analytics, helping detect complex or distributed attacks."
    },
    {
      "id": 41,
      "question": "Which advanced measure helps a router defend against half-open TCP sessions in a SYN flood attack?",
      "options": [
        "SYN cookies, not allocating session memory until the handshake is complete",
        "Half-duplex forced on the WAN interface",
        "DHCP Option 43",
        "LLDP discovery"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Half-duplex is a mismatch, DHCP Option 43 is vendor info, LLDP is device discovery. SYN cookies (correct) drop or manage half-open connections without storing them, preventing backlog exhaustion during floods.",
      "examTip": "SYN cookies mitigate DoS by letting the server skip maintaining connection state until the final ACK arrives."
    },
    {
      "id": 42,
      "question": "A new trunk port is not passing VLAN 99. Which SINGLE command on a Cisco switch typically fixes this if VLAN 99 is missing from the trunk’s allowed list?",
      "options": [
        "switchport trunk allowed vlan add 99",
        "switchport trunk native vlan 99",
        "vlan 99 state active",
        "show interface trunk detail"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option 1 adds VLAN 99 to the trunk. Option 2 changes the native VLAN, Option 3 ensures VLAN existence but not trunk allowance, Option 4 is diagnostic. If VLAN 99 is missing, you must add it explicitly.",
      "examTip": "When trunk traffic for a VLAN is missing, confirm the trunk’s allowed VLAN list on each side."
    },
    {
      "id": 43,
      "question": "Which scenario-based question is BEST resolved by implementing MST in a multi-VLAN environment?",
      "options": [
        "How to unify IP addressing across the WAN",
        "How to run half-duplex on all VLANs",
        "How to cut down on separate STP instances by grouping VLANs into fewer MST instances",
        "How to block rogue DHCP servers"
      ],
      "correctAnswerIndex": 2,
      "explanation": "MST (correct) merges VLANs into fewer STP instances, reducing overhead. WAN IP, half-duplex, and DHCP security are separate. MST is specifically a scalable spanning tree solution for numerous VLANs.",
      "examTip": "MST can drastically lower CPU usage compared to per-VLAN STP (PVST+). Each MST instance covers multiple VLANs."
    },
    {
      "id": 44,
      "question": "Which approach in a zero trust architecture requires repeated identity verification and minimal permissions even for internal subnet access?",
      "options": [
        "Implicit trust once a device is inside the LAN",
        "Micro-segmentation plus NAC posture checks for each resource request",
        "Use half-duplex to reduce collisions",
        "Assign VLAN 1 as native for all trunks"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Zero trust denies inherent LAN trust. The hallmark is micro-segmentation and continuous authentication. Half-duplex or VLAN 1 usage are not zero trust measures. NAC posture checks ensure persistent compliance verification.",
      "examTip": "Zero trust demands granular network segmentation and repeated validation of user/device posture and privileges."
    },
    {
      "id": 45,
      "question": "Which measure can a distribution switch employ if a user on an access port is connecting an unauthorized switch that sends STP BPDUs?",
      "options": [
        "BPDU guard to err-disable the port if BPDUs are received",
        "DHCP snooping pass-through",
        "Link auto-negotiation to half-duplex",
        "NAT64 translation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DHCP snooping is address security, half-duplex is mismatch, NAT64 is IPv6 translation. BPDU guard (correct) disables the port upon seeing bridging frames from a device that shouldn’t be participating in STP.",
      "examTip": "BPDU guard on access ports quickly shuts any port that receives BPDUs, preventing bridging loops from rogue devices."
    },
    {
      "id": 46,
      "question": "Which direct measure can block inbound telnet from unknown external IPs, ensuring only a management subnet can telnet to the router?",
      "options": [
        "ACL permitting TCP 23 only from internal or management subnets",
        "Enable half-duplex on the outside interface",
        "Trunk dynamic auto negotiation",
        "Use EIGRP stub on the WAN"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option 1 is correct: an ACL restricts telnet to known subnets. Half-duplex, trunk negotiation, or EIGRP stub do not fix inbound telnet security. A simple inbound ACL is standard to block telnet from unknown sources.",
      "examTip": "Always limit inbound management protocols to specified IP ranges. Deny all else to reduce attack vectors."
    },
    {
      "id": 47,
      "question": "A distribution switch is hammered by an ARP spoofing attack forging gateway MAC addresses. Which dynamic security feature is specifically designed to prevent such layer 2 forging?",
      "options": [
        "DHCP snooping",
        "MAC flooding control",
        "Dynamic ARP Inspection (DAI)",
        "CDP neighbor guard"
      ],
      "correctAnswerIndex": 2,
      "explanation": "DHCP snooping is for IP assignment, MAC flooding is another layer 2 exploit, CDP is discovery. DAI (correct) verifies ARP packets against IP-MAC bindings, blocking ARP spoof attempts.",
      "examTip": "DAI uses DHCP snooping data or static ARP mapping to confirm the legitimacy of ARP replies."
    },
    {
      "id": 48,
      "question": "Which scenario-based question is BEST solved by IPsec tunnel mode between two branch routers?",
      "options": [
        "How to forcibly half-duplex the WAN link",
        "How to secure site-to-site traffic over an untrusted network by encrypting entire IP packets",
        "How to unify VLAN trunking across the WAN",
        "How to block inbound TCP port 23"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Tunnel mode IPsec encrypts entire IP packets between sites, providing site-to-site VPN security. The other options are unrelated or partial. IPsec tunnel mode is standard for WAN encryption over public links.",
      "examTip": "IPsec tunnel mode is common for branch-to-branch or branch-to-HQ encryption, encapsulating entire IP packets."
    },
    {
      "id": 49,
      "question": "Which trunking detail is commonly misconfigured if a VLAN is not passing across a trunk between two vendor switches?",
      "options": [
        "802.1Q encapsulation mismatch or missing VLAN in allowed list",
        "DHCP Option 82 not inserted by the switch",
        "Half-duplex is forced on one side",
        "ARP inspection is disabled"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option 1 is correct: either the trunk is not set to 802.1Q on both sides, or the VLAN is missing from ‘allowed VLANs.’ The other points are separate features. This is the typical cause of VLAN traffic failing on trunk links.",
      "examTip": "Multi-vendor trunking requires both ends use 802.1Q and properly list the VLAN. If VLAN is omitted, traffic is dropped."
    },
    {
      "id": 50,
      "question": "Which direct measure does NAC posture commonly impose for a device that fails OS patch checks, restricting it from normal LAN?",
      "options": [
        "Putting the port in half-duplex loopback",
        "Assigning it to a quarantine VLAN or applying a restricted dACL",
        "Root guard preventing bridging loops",
        "Disabling trunking on the distribution switch"
      ],
      "correctAnswerIndex": 1,
      "explanation": "NAC posture typically quarantines failing endpoints in a special VLAN or dACL. The other options are loop prevention, bridging security, or trunk config. That’s not NAC posture. Quarantine VLAN is standard for remediation.",
      "examTip": "NAC posture isolates non-compliant endpoints, forcing them to update or patch before granting full network access."
    },
    {
      "id": 51,
      "question": "Which advanced feature in BGP can group routes with special tags, e.g., ‘no-export,’ letting administrators apply consistent policies to that group?",
      "options": [
        "Local Preference",
        "MED",
        "Community",
        "Weight"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Local Pref influences egress, MED inbound, Weight is local to one router. BGP communities (correct) are route tags that can shape advertisement or policy. ‘no-export’ is one of the well-known communities.",
      "examTip": "Communities add flexible tagging. Route-maps can match them and apply custom policies. ‘no-export’ means don’t advertise beyond the local AS or confederation."
    },
    {
      "id": 52,
      "question": "Which zero trust measure ensures that each subnet or VLAN has tight ACL boundaries, forcing repeated authentication or posture checks for cross-segment traffic?",
      "options": [
        "802.1D STP loop detection",
        "Micro-segmentation with NAC enforcement at each boundary",
        "DHCP snooping with half-duplex bridging",
        "CDP-based trunk negotiation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "STP loop detection is layer 2, DHCP snooping is IP-based security, trunk negotiation is VLAN bridging. Micro-segmentation (correct) enforces minimal trust between segments, requiring continuous validation. That’s a core zero trust principle.",
      "examTip": "Zero trust breaks the flat LAN assumption, applying granular segmentation and policy enforcement to limit lateral movement."
    },
    {
      "id": 53,
      "question": "A site injects static routes into EIGRP. Which approach typically shares a 0.0.0.0/0 default route to EIGRP neighbors?",
      "options": [
        "Half-duplex fallback on the WAN",
        "Passive-interface default on all VLANs",
        "redistribute static metric <values> referencing 0.0.0.0/0",
        "DHCP Option 82 trunk"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Half-duplex is link mismatch, passive-interface stops routing updates, DHCP Option 82 is IP address info. ‘redistribute static’ referencing the default route (correct) is the standard method for injecting a default route into EIGRP. Provide a metric or route-map to define distances.",
      "examTip": "EIGRP requires setting metrics for redistributed routes, or a route-map. ‘redistribute static’ for 0.0.0.0/0 is typical to advertise a default route."
    },
    {
      "id": 54,
      "question": "Which phenomenon describes forging many source MAC addresses to exhaust a switch’s CAM table, forcing it to broadcast frames?",
      "options": [
        "ARP spoofing",
        "DHCP starvation",
        "MAC flooding",
        "VLAN hopping"
      ],
      "correctAnswerIndex": 2,
      "explanation": "ARP spoofing manipulates IP-to-MAC, DHCP starvation tries to exhaust IP addresses, VLAN hopping manipulates trunk/ tags. MAC flooding (correct) tries to overflow the CAM table so the switch reverts to hub-like behavior, letting attackers sniff traffic.",
      "examTip": "MAC flooding is mitigated by port security or NAC solutions limiting the allowed MAC count on each access port."
    },
    {
      "id": 55,
      "question": "Which BGP attribute is typically used by an AS to prefer one outbound path globally (i.e., all iBGP routers see it) if multiple eBGP routes exist?",
      "options": [
        "Weight",
        "Local Preference",
        "MED",
        "Community"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Weight is local to one router, MED is inbound preference, community is tagging. Local Preference (correct) is shared among iBGP routers, controlling egress path selection for the entire AS.",
      "examTip": "To choose an exit route for all routers in your AS, set a higher local_pref on the path you want them to prefer."
    },
    {
      "id": 56,
      "question": "A trunk link experiences double-tagging VLAN hopping attempts. Which direct measure addresses that attack vector?",
      "options": [
        "Keep VLAN 1 as native VLAN everywhere",
        "Disable trunk negotiation (DTP) and set a non-default native VLAN explicitly",
        "Enable half-duplex to slow traffic",
        "Configure DHCP snooping with ARP inspection"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Defaulting to VLAN 1 as native is exactly how attackers exploit double tags. Half-duplex is a mismatch. DHCP snooping and ARP inspection are IP security, not trunk-based. Setting a distinct native VLAN and disabling DTP (correct) is the standard fix.",
      "examTip": "Double-tagging relies on VLAN 1 as native. Assign a unique native VLAN and no auto trunking to thwart the exploit."
    },
    {
      "id": 57,
      "question": "Which NAC posture enforcement scenario places an endpoint in a restricted VLAN until it patches critical vulnerabilities?",
      "options": [
        "802.1X with RADIUS returning dynamic VLAN assignment upon posture check failure",
        "DHCP Option 82 for location-based addressing",
        "STP root guard preventing bridging loops",
        "CDP neighbor limiting"
      ],
      "correctAnswerIndex": 0,
      "explanation": "802.1X NAC solutions can dynamically assign or quarantine VLANs. Option 2 is DHCP info, 3 is bridging security, 4 is discovery. Dynamic VLAN from RADIUS based on posture (correct) is the approach.",
      "examTip": "Fail posture? NAC often moves the device to a remediation VLAN, allowing only patch servers or minimal external access."
    },
    {
      "id": 58,
      "question": "A router must handle thousands of internal hosts sharing one public IP. Which NAT solution accomplishes this many-to-one scenario using unique source ports?",
      "options": [
        "Static NAT one-to-one",
        "DNS round-robin resolution",
        "PAT (NAT overload)",
        "VIP gateway"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Static NAT is 1:1, DNS round-robin is load balancing, VIP gateway is not the typical NAT solution. PAT (correct) translates multiple private IP flows to a single public IP, differentiating them by source ports.",
      "examTip": "PAT is essential for large-scale outbound NAT, reusing one public IP by mapping different source ports for each internal host."
    },
    {
      "id": 59,
      "question": "Which advanced STP variant merges multiple VLANs into fewer spanning tree instances, each controlling a group of VLANs?",
      "options": [
        "PVST+",
        "MST",
        "Rapid PVST+",
        "Edge Port STP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "PVST+ is per-VLAN STP, Rapid PVST+ is faster per-VLAN, Edge Port STP is portfast. MST (correct) organizes VLANs into fewer STP instances, reducing overhead for large VLAN deployments.",
      "examTip": "MST is the IEEE 802.1s standard, grouping VLANs into MST instances for improved scalability."
    },
    {
      "id": 60,
      "question": "Which NAC posture check is TYPICAL to ensure endpoints have updated antivirus definitions before granting normal access?",
      "options": [
        "CDP trunk mode negotiation",
        "802.1X EAP-based posture verification (e.g., EAP-PEAP plus NAC agent)",
        "DHCP snooping pass-through",
        "DNS load balancing"
      ],
      "correctAnswerIndex": 1,
      "explanation": "CDP trunk, DHCP snooping, or DNS load balancing are not posture checks. NAC posture with 802.1X (correct) typically requires an agent verifying AV or patches, then RADIUS decides normal or restricted VLAN.",
      "examTip": "NAC posture can verify AV signature versions, OS patch levels, firewall status, etc., for secure admission."
    },
    {
      "id": 61,
      "question": "A distribution switch logs indicate ARP spoof attempts forging the gateway MAC. Which dynamic layer 2 security feature specifically addresses ARP integrity?",
      "options": [
        "BPDU guard for bridging loops",
        "DHCP snooping binding table",
        "Dynamic ARP Inspection referencing known IP-MAC pairs",
        "SNMPv3 authPriv"
      ],
      "correctAnswerIndex": 2,
      "explanation": "BPDU guard is STP, DHCP snooping helps but does not block ARP by itself, SNMPv3 secures management. DAI (correct) checks ARP messages against DHCP snooping or static bindings to block forged ARP entries.",
      "examTip": "DAI (Dynamic ARP Inspection) is a crucial feature to thwart ARP-based on-path attacks in switched networks."
    },
    {
      "id": 62,
      "question": "Which scenario-based question is BEST solved by enabling a SIEM solution that aggregates logs from multiple firewalls, servers, and IDS sensors?",
      "options": [
        "How to unify VLAN trunking across the campus",
        "How to detect subtle or distributed attacks by correlating events in real time",
        "How to enforce half-duplex on user ports",
        "How to assign a static default gateway to each host"
      ],
      "correctAnswerIndex": 1,
      "explanation": "VLAN trunking, half-duplex, and default gateway assignment are separate. SIEM (correct) is about log correlation from various sources to reveal complex threats. That’s the scenario-based question it addresses.",
      "examTip": "SIEM platforms unify logs, enabling analytics or correlation to spot distributed attacks otherwise missed if logs stayed siloed."
    },
    {
      "id": 63,
      "question": "Which NAC approach can place a device in a restricted VLAN if it fails posture checks for OS patch compliance?",
      "options": [
        "Static ARP entries",
        "802.1X dynamic VLAN assignment from RADIUS",
        "Spanning tree root guard",
        "CDP-based VLAN negotiation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option 1 is IP-binding, 3 is STP security, 4 is device discovery. NAC posture with 802.1X (correct) can push a restricted VLAN. That’s standard for non-compliant endpoints needing remediation.",
      "examTip": "RADIUS-based NAC posture solutions often supply VLAN or ACL changes for endpoints not meeting policy."
    },
    {
      "id": 64,
      "question": "Which statement accurately describes VRRP in a high-availability network design?",
      "options": [
        "It’s a Cisco-proprietary protocol for default gateway redundancy",
        "Multiple routers share a virtual IP; one acts as master responding to ARP and data traffic",
        "It’s used exclusively for OSPF stub areas",
        "VRRP always runs at half-duplex"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option 1 is HSRP for Cisco. Option 2 (correct) is how VRRP shares a virtual IP among multiple routers, with one master. Option 3 references OSPF, Option 4 is a mismatch. VRRP is an open standard FHRP protocol.",
      "examTip": "FHRPs like VRRP ensure continuous gateway presence if the primary fails. The virtual IP stays consistent for hosts."
    },
    {
      "id": 65,
      "question": "Which IPsec mode encapsulates the entire IP packet, adding a new header for secure site-to-site tunnels?",
      "options": [
        "Transport mode",
        "Tunnel mode",
        "Aggressive mode",
        "Route-based NAT"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Transport mode encrypts only the payload; tunnel mode (correct) wraps the original IP packet entirely. Aggressive mode is an IKE Phase 1 handshake variant, route-based NAT is a different concept. Tunnel mode is standard for site-to-site VPNs.",
      "examTip": "IPsec tunnel mode is typical for router-to-router encryption. The entire original IP packet is hidden inside the IPsec header."
    },
    {
      "id": 66,
      "question": "Which trunking protocol was Cisco proprietary and is mostly deprecated in favor of IEEE 802.1Q for VLAN tagging?",
      "options": [
        "ISL",
        "MST",
        "LACP",
        "CDP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "ISL (correct) is old Cisco trunking. MST is spanning tree, LACP is link aggregation, CDP is discovery. 802.1Q replaced ISL as the standard trunk encapsulation. Most modern switches only use 802.1Q.",
      "examTip": "ISL is rarely used now. 802.1Q is the universal trunk standard across vendors."
    },
    {
      "id": 67,
      "question": "Which scenario-based question is BEST solved by implementing EIGRP stub routing on branch routers?",
      "options": [
        "How to reduce EIGRP query scope in hub-and-spoke designs, avoiding SIA storms",
        "How to unify half-duplex links across the WAN",
        "How to block rogue DHCP servers",
        "How to implement 802.1X posture checks"
      ],
      "correctAnswerIndex": 0,
      "explanation": "EIGRP stubs do not help half-duplex or DHCP. NAC posture is unrelated. EIGRP stub (correct) is specifically for limiting query propagation in large or hub-and-spoke designs, preventing extensive SIA episodes.",
      "examTip": "Marking branch routers as stub prevents them from forwarding queries, streamlining EIGRP convergence."
    },
    {
      "id": 68,
      "question": "Which NAC posture approach can block an endpoint from the LAN if it fails to show updated antivirus definitions at login?",
      "options": [
        "BPDU guard on trunk ports",
        "802.1X with a RADIUS-based posture check",
        "NTP authentication",
        "DHCP Option 82 insertion"
      ],
      "correctAnswerIndex": 1,
      "explanation": "BPDU guard is for STP frames, NTP is time sync, Option 4 is DHCP security detail. NAC posture via 802.1X (correct) is the method to verify AV or patch level. If the device fails, it’s quarantined or denied.",
      "examTip": "NAC posture integrated with 802.1X ensures security checks (AV, OS patches) at the time of network authentication."
    },
    {
      "id": 69,
      "question": "Which advanced firewall feature specifically identifies traffic by analyzing packet contents at layers 5–7, ignoring the nominal port numbers?",
      "options": [
        "Port-based ACL filter",
        "Application-aware DPI",
        "DHCP snooping table",
        "CDP trunk bridging"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Port-based ACL checks layer 4 only, DHCP snooping is address security, CDP trunk bridging is discovery. Application-aware DPI (correct) is the next-gen firewall approach. This allows controlling apps like Skype or BitTorrent even if they use standard web ports.",
      "examTip": "Next-gen firewalls do deep packet inspection at higher layers, identifying actual apps or protocols."
    },
    {
      "id": 70,
      "question": "Which statement is TRUE about a Cisco router that sets a higher Local Preference for one eBGP route than another?",
      "options": [
        "It’s influencing inbound traffic from external neighbors",
        "It’s controlling the route selection for outbound traffic within the iBGP domain",
        "It’s forcibly assigning half-duplex on the interface",
        "It’s toggling the route to a static ARP binding"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Local Preference is used by iBGP to pick egress paths, not for inbound. Half-duplex or ARP are irrelevant. The entire AS sees that higher local_pref route as the best exit path, so that’s how you shape outbound traffic.",
      "examTip": "Local_Pref modifies outbound route selection for the whole AS. MED or AS-Path Prepending address inbound paths."
    },
    {
      "id": 71,
      "question": "Which measure on a switch can block any device from bridging multiple VLANs on an access port by sending STP BPDUs?",
      "options": [
        "BPDU guard puts the port in err-disable upon receiving a BPDU",
        "DHCP snooping pass-through",
        "Half-duplex to prevent trunk formation",
        "LLDP neighbor discovery"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BPDU guard (correct) is the direct measure. DHCP snooping secures IP addresses, half-duplex is link mismatch, LLDP is device info. If the switch sees STP frames from an access port, it disables that port to prevent loops.",
      "examTip": "BPDU guard is a critical security step on edge ports, quickly shutting them if bridging devices appear."
    },
    {
      "id": 72,
      "question": "Which scenario-based question is BEST solved by an IPsec tunnel mode between data center routers?",
      "options": [
        "How to unify VLAN trunking across the WAN",
        "How to encrypt entire IP packets for secure site-to-site data center replication over public networks",
        "How to forcibly half-duplex for old devices",
        "How to push a DHCP reservation to each node"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Trunking and half-duplex are unrelated, DHCP reservation is IP assignment. IPsec tunnel mode (correct) is standard for site-to-site encryption, encapsulating entire IP packets over untrusted transit links.",
      "examTip": "Data center to data center often uses IPsec tunnel mode to protect replication traffic from snooping or tampering on external networks."
    },
    {
      "id": 73,
      "question": "Which advanced firewall feature can do a man-in-the-middle on TLS connections, allowing inspection of encrypted data for malware or policy violations?",
      "options": [
        "DHCP snooping",
        "SSL/TLS forward proxy (interception)",
        "BPDU root guard",
        "CDP-based trunk negotiation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "DHCP snooping is IP security, root guard is STP, CDP is discovery. SSL/TLS forward proxy (correct) decrypts, inspects, re-encrypts. This is common in next-gen firewalls for deep content inspection in HTTPS flows.",
      "examTip": "Enabling SSL interception requires the firewall to present its own certificate to clients, effectively performing an authorized MITM."
    },
    {
      "id": 74,
      "question": "A distribution switch logs TCN events triggered by a user’s small bridging device. Which single configuration ensures the port is disabled upon seeing bridging BPDUs from that user?",
      "options": [
        "BPDU guard on that interface",
        "DHCP Option 82 insertion",
        "802.1Q trunk allowed vlan add user",
        "MAC flooding threshold"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option B is DHCP, Option C is trunk VLAN allowance, Option D is a security measure for CAM. BPDU guard (correct) quickly places the port in err-disable if it receives any STP frames from the user device.",
      "examTip": "BPDU guard is critical for access ports to prevent unauthorized bridging loops from user switches."
    },
    {
      "id": 75,
      "question": "Which advanced NAC posture method can check if an endpoint’s OS firewall is enabled and antivirus updated, then apply a dynamic ACL from RADIUS if it fails?",
      "options": [
        "802.1X with dACL assignment",
        "CDP trunk negotiation",
        "Portfast bridging on user ports",
        "DHCP exhaustion approach"
      ],
      "correctAnswerIndex": 0,
      "explanation": "CDP trunk is discovery, portfast is STP optimization, DHCP exhaustion is a DoS. NAC posture with 802.1X (correct) can push a dynamic ACL or VLAN from the RADIUS server if the device fails compliance.",
      "examTip": "NAC posture can alter the device’s network privileges in real-time, e.g., restricting or quarantining non-compliant endpoints."
    },
    {
      "id": 76,
      "question": "Which approach is used to manipulate inbound traffic from external ASes, making one path appear less attractive by artificially lengthening the route?",
      "options": [
        "AS-Path Prepending",
        "Local Preference increase",
        "Weight on the local router",
        "DHCP snooping pass-through"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Local Preference influences egress inside your AS. Weight is local to one device, DHCP snooping is address security. AS-Path Prepending (correct) modifies inbound selection by making that route look costlier externally.",
      "examTip": "AS-Path Prepending is the standard trick for inbound path control in BGP with multiple connections to the internet."
    },
    {
      "id": 77,
      "question": "A distribution switch sees bridging loops after a user daisychains a small switch. Which direct feature disables that port upon receiving STP frames from the user device?",
      "options": [
        "BPDU guard",
        "DHCP snooping binding",
        "LLDP neighbor classification",
        "Half-duplex trunk fallback"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BPDU guard (correct) is precisely for detecting unauthorized STP participants. DHCP snooping, LLDP, or half-duplex do not fix bridging loops. This scenario calls for immediate port shutdown if bridging frames are detected.",
      "examTip": "BPDU guard is mandatory on access ports to prevent loops from unauthorized bridging devices."
    },
    {
      "id": 78,
      "question": "Which NAC scenario-based question is BEST resolved by 802.1X posture checks that validate OS patches and AV, quarantining non-compliant endpoints?",
      "options": [
        "How to unify trunking across the WAN",
        "How to physically label cables in the MDF",
        "How to ensure only secure devices gain full network access while others remain restricted",
        "How to block inbound DNS requests"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Trunking, labeling, or inbound DNS blocks are separate. NAC posture with 802.1X (correct) is specifically about verifying device compliance. If it fails, the device is restricted or denied.",
      "examTip": "NAC posture control is essential to maintain an environment where only properly secured hosts can freely communicate."
    },
    {
      "id": 79,
      "question": "Which trunk detail typically results in VLAN traffic being dropped if the VLAN is not explicitly included in the trunk’s allowed list?",
      "options": [
        "802.3ad link aggregation mismatch",
        "DTP dynamic auto mode is disabled",
        "Native VLAN mismatch on both sides",
        "switchport trunk allowed vlan missing that VLAN"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Option 1 is LACP, 2 fosters trunk negotiation, 3 is a different mismatch causing other issues. Not listing the VLAN in ‘allowed vlan’ (correct) is the usual culprit. If VLAN is absent, frames are dropped.",
      "examTip": "Always confirm both trunk ends match the VLAN allow list, else frames for that VLAN are discarded."
    },
    {
      "id": 80,
      "question": "A site injects a static default route into OSPF. Which command typically accomplishes this injection, assuming the router already has a valid default route in its routing table?",
      "options": [
        "default-information originate",
        "network 0.0.0.0/0 area 0",
        "redistribute static metric 1 1 1 1 1",
        "Use half-duplex trunk negotiation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "OSPF uses ‘default-information originate’ to advertise 0.0.0.0/0 if the router has a default route. The ‘network’ statement doesn’t automatically generate a default, ‘redistribute static’ is typical for EIGRP or different scenario. Half-duplex is irrelevant.",
      "examTip": "If a valid default route is known to OSPF’s router, ‘default-information originate’ floods that route to neighbors."
    },
    {
      "id": 81,
      "question": "Which advanced QoS method ensures short bursts don’t drown real-time voice packets, giving voice a strict priority queue?",
      "options": [
        "WFQ with no priority",
        "LLQ (Low Latency Queueing)",
        "RED (Random Early Detection)",
        "CDP-based trunk classification"
      ],
      "correctAnswerIndex": 1,
      "explanation": "WFQ alone doesn’t guarantee strict priority. LLQ (correct) merges WFQ with a priority queue. RED manages congestion by dropping traffic early. CDP is discovery. LLQ keeps voice flows safe from microbursts or heavy data flows.",
      "examTip": "For real-time traffic, a strict priority queue is crucial to minimize jitter. LLQ is Cisco’s go-to solution."
    },
    {
      "id": 82,
      "question": "Which direct measure can hamper MAC flooding attempts that try to overload a switch’s CAM table?",
      "options": [
        "Port security limiting MAC addresses per interface",
        "BPDU guard blocking bridging loops",
        "DHCP snooping pass-through",
        "Half-duplex trunk fallback"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BPDU guard is STP, DHCP snooping is IP-based, half-duplex is link mismatch. Port security (correct) sets a max MAC limit, shutting or restricting the port if exceeded, thus mitigating flooding attacks.",
      "examTip": "MAC flooding attempts to fill the CAM table with bogus addresses. Port security is the usual solution for such attacks."
    },
    {
      "id": 83,
      "question": "Which NAC scenario-based question is BEST resolved by using a RADIUS-driven downloadable ACL upon 802.1X authentication?",
      "options": [
        "How to unify all VLAN trunk ports for guest traffic",
        "How to apply user-specific or dynamic ACLs for fine-grained network access without statically coding each switch",
        "How to run half-duplex on distribution links",
        "How to block bridging loops via root guard"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Trunking for guests, half-duplex, or STP root guard are separate. Downloadable ACL (correct) from RADIUS is a NAC approach for dynamic, user-specific security policies. This addresses per-user or per-session restrictions.",
      "examTip": "dACL or dynamic VLAN assignment from NAC/802.1X is ideal for large environments needing flexible user-based policy."
    },
    {
      "id": 84,
      "question": "Which concept ensures a subset of VLANs can share one MST instance, reducing the total number of STP processes needed in a large campus?",
      "options": [
        "VTP pruning",
        "PVST+ mode",
        "Multiple Spanning Tree (MST)",
        "CDP trunk bridging"
      ],
      "correctAnswerIndex": 2,
      "explanation": "VTP pruning is VLAN distribution, PVST+ is per-VLAN spanning tree, CDP is discovery. MST (correct) merges VLANs into fewer STP instances, optimizing CPU usage. That’s the standard for large VLAN deployments.",
      "examTip": "MST organizes VLAN sets, each mapped to one STP instance. This approach is an IEEE 802.1s standard."
    },
    {
      "id": 85,
      "question": "Which measure is recommended for inbound SSH security on a perimeter router, allowing only certain remote admins to connect?",
      "options": [
        "Half-duplex forced on the outside interface",
        "DHCP Option 82 on the WAN",
        "ACL permitting TCP 22 from specific IP ranges, denying others",
        "Root guard on trunk ports"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Half-duplex is link mismatch, DHCP Option 82 is a relay detail, root guard is STP. Using an ACL restricting SSH (port 22) to known IP ranges (correct) is standard. This blocks unknown external addresses from attempting SSH.",
      "examTip": "Always lock down remote management ports to authorized subnets or a VPN. A broad inbound allow is a big risk."
    },
    {
      "id": 86,
      "question": "Which phenomenon do advanced NAC posture checks address by verifying each endpoint’s security status (OS patches, AV) prior to granting normal LAN access?",
      "options": [
        "STP loop detection",
        "ARP spoofing enforcement",
        "Rogue AP infiltration",
        "Compromised endpoints connecting behind the firewall"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Posture checks can’t fix STP loops, ARP spoofing, or rogue APs. They ensure endpoints are properly secured, blocking compromised or unpatched hosts. That’s the scenario: even behind the firewall, NAC checks compliance before full access.",
      "examTip": "Zero trust or NAC posture ensures every endpoint is verified and secure, preventing internal threats from compromised or unpatched devices."
    },
    {
      "id": 87,
      "question": "Which BGP attribute is an inbound traffic influencer from external neighbors, often considered after local_pref and AS-path if neighbors honor it?",
      "options": [
        "MED",
        "Weight",
        "Community no-export",
        "Origin code"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Weight is local, community no-export is a policy tag, origin code is a tiebreaker. MED (correct) is used to suggest inbound path choice to neighbors. Some ISPs ignore MED, but that’s how BGP tries to shape inbound routes after primary attributes are checked.",
      "examTip": "MED (lowest is preferred) is an optional, less-preferred attribute for inbound route selection if the neighbor respects it."
    },
    {
      "id": 88,
      "question": "Which trunk mismatch typically results in VLAN traffic failing if the VLAN is omitted from 'switchport trunk allowed vlan' statements?",
      "options": [
        "Native VLAN mismatch",
        "VTP server mode vs. client mode",
        "Allowed VLAN list missing the VLAN",
        "DHCP snooping disabled"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Native VLAN mismatch is a different problem, VTP modes are VLAN distribution, DHCP snooping is IP security. If a VLAN isn’t listed under allowed VLANs (correct), its frames get dropped on that trunk link.",
      "examTip": "One of the most common reasons a VLAN doesn’t pass is it’s absent from the trunk’s ‘allowed’ set. Always check 'show interface trunk'."
    },
    {
      "id": 89,
      "question": "Which advanced NAC approach can forcibly apply an ACL from RADIUS to a device that fails posture checks, restricting its traffic to remediation servers?",
      "options": [
        "DHCP Option 82 insertion",
        "Spanning tree root guard",
        "Downloadable ACL (dACL) assigned during 802.1X authentication",
        "SNMPv3 traps"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option 1 is DHCP relay detail, 2 is STP security, 4 is event notifications. dACL (correct) from RADIUS can push an ACL that permits only certain IPs or subnets, quarantining the endpoint until compliance is met.",
      "examTip": "dACL or dynamic VLAN from NAC let you isolate failing endpoints automatically. This is powerful for posture-based NAC."
    },
    {
      "id": 90,
      "question": "Which measure in EIGRP speeds convergence if the primary route fails, avoiding queries if a valid backup route meets the feasibility condition?",
      "options": [
        "Route filtering at the ABR",
        "Feasible successor in the topology table",
        "Passive-interface on all LAN ports",
        "Half-duplex bridging"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Route filtering or passive-interface is separate. Half-duplex is irrelevant. Feasible successor (correct) is EIGRP’s immediate fallback route if it meets the feasibility condition. This is how EIGRP avoids going into active queries.",
      "examTip": "A feasible successor drastically reduces failover times in EIGRP by providing an already-validated backup route."
    },
    {
      "id": 91,
      "question": "Which NAC posture solution might require an endpoint agent verifying AV definitions, then instruct the switch to move the device to a normal VLAN if compliant?",
      "options": [
        "BPDU guard trunk mode",
        "802.1X with posture-based RADIUS policies",
        "DHCP relay agent IP helper",
        "LACP link aggregation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "BPDU guard is bridging security, DHCP relay is IP broadcast forwarding, LACP is link aggregation. NAC posture with 802.1X (correct) is the typical approach for dynamic VLAN assignment based on compliance checks.",
      "examTip": "NAC posture integrated with 802.1X ensures endpoints meet security standards, then grants full access or quarantines them."
    },
    {
      "id": 92,
      "question": "Which advanced firewall feature is used to intercept and inspect HTTPS traffic, re-signing it to the server so the firewall can scan for threats in the decrypted payload?",
      "options": [
        "Stateful packet filtering at layer 4",
        "SSL forward proxy or TLS interception",
        "BPDU guard bridging",
        "DNS load balancing"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Stateful L4 firewall doesn’t inspect decrypted content, BPDU guard is STP, DNS load balancing is external. SSL interception (correct) is the next-gen firewall technique. The firewall acts as a man-in-the-middle for TLS sessions to scan for malware or policy violations.",
      "examTip": "TLS interception is also called SSL forward proxy. The firewall must be trusted by client devices to avoid certificate warnings."
    },
    {
      "id": 93,
      "question": "Which concept in zero trust demands that each subnet or segment must individually authenticate and authorize all requests, preventing unchecked lateral movement?",
      "options": [
        "Full VLAN trunk for every user",
        "Micro-segmentation and continuous identity checks",
        "Auto summary for all routes",
        "Half-duplex bridging across the core"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Trunking every user or half-duplex bridging does not provide zero trust. Summaries are for routing. Micro-segmentation plus repeated checks (correct) is fundamental: no implicit trust within the LAN. Every segment is locked down with policy.",
      "examTip": "Zero trust micro-segmentation means each resource or subnet is protected by a policy boundary, requiring continuous authentication."
    },
    {
      "id": 94,
      "question": "Which NAC approach is typical to confine a user to a quarantine VLAN if they fail OS patch checks at login?",
      "options": [
        "802.1X posture check with dynamic VLAN assignment from RADIUS",
        "BPDU guard for bridging loops",
        "DHCP Option 82 insertion",
        "Half-duplex trunk negotiation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BPDU guard is STP, Option 3 is DHCP security info, Option 4 is a mismatch. NAC posture with 802.1X (correct) is how endpoints get quarantined VLAN if they fail checks for patches or AV signatures.",
      "examTip": "802.1X NAC solutions can push restricted VLANs if posture fails, ensuring non-compliant devices are isolated."
    },
    {
      "id": 95,
      "question": "Which trunk misconfiguration is a frequent culprit if VLAN 50 traffic is not passing across a trunk link?",
      "options": [
        "No default route in EIGRP",
        "MED set to zero in BGP",
        "VLAN 50 missing from 'allowed vlan' on the trunk",
        "DHCP relay agent not set"
      ],
      "correctAnswerIndex": 2,
      "explanation": "EIGRP default route, BGP MED, and DHCP relay are different functionalities. Typically, if VLAN traffic is missing, it’s not on the trunk’s allowed list (correct). That’s the standard trunk misconfiguration scenario.",
      "examTip": "Check ‘show interface trunk’ to confirm VLAN 50 is listed. If not, add it with 'switchport trunk allowed vlan add 50'."
    },
    {
      "id": 96,
      "question": "Which advanced firewall capability can detect Skype traffic hidden over port 443 by analyzing packet signatures at layer 7?",
      "options": [
        "L2 MAC address filtering",
        "App-aware DPI in an NGFW",
        "Static NAT for inbound connections",
        "DHCP server logs"
      ],
      "correctAnswerIndex": 1,
      "explanation": "MAC filtering is L2. Static NAT or DHCP logs do not decode application signatures. NGFW with app-aware DPI (correct) sees beyond ports. That’s how it identifies Skype or other apps over commonly used ports.",
      "examTip": "Layer 7 inspection can look into flows and detect app fingerprints, unstoppable by mere port changes."
    },
    {
      "id": 97,
      "question": "Which direct measure can mitigate bridging loops formed by a user plugging in a rogue switch on an access port?",
      "options": [
        "Enable DHCP snooping binding",
        "Use an ACL on the user VLAN",
        "BPDU guard to shutdown the port if it receives STP frames",
        "Half-duplex fallback on that port"
      ],
      "correctAnswerIndex": 2,
      "explanation": "DHCP snooping or ACL do not address bridging loops, half-duplex is a mismatch. BPDU guard (correct) is specifically to detect unauthorized STP frames from an access port, then err-disable it.",
      "examTip": "Edge ports with BPDU guard avoid loops from user-attached bridging devices. It's a fundamental STP security measure."
    },
    {
      "id": 98,
      "question": "A distribution switch sees a malicious user forging ARP replies for the default gateway. Which layer 2 security feature specifically checks ARP messages against a trusted table?",
      "options": [
        "Port security sticky MAC",
        "DHCP snooping pass-through",
        "Dynamic ARP Inspection (DAI)",
        "Root guard"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Sticky MAC addresses limit station count, DHCP snooping is for IP address security, root guard is STP. DAI (correct) checks ARP messages for authenticity, blocking ARP spoofing. It references DHCP snooping or static ARP data.",
      "examTip": "DAI enforces correct IP-to-MAC relationships, thwarting ARP spoof. It's crucial for stopping on-path attacks."
    },
    {
      "id": 99,
      "question": "Which trunk method ensures interoperability across Cisco and non-Cisco devices for VLAN tagging?",
      "options": [
        "ISL",
        "802.1Q",
        "CDP trunk bridging",
        "DTP dynamic auto"
      ],
      "correctAnswerIndex": 1,
      "explanation": "ISL is Cisco-proprietary, CDP is discovery, DTP is trunk negotiation also Cisco-based. 802.1Q (correct) is the IEEE standard recognized multi-vendor. This is the typical trunk encapsulation for cross-platform VLAN transport.",
      "examTip": "802.1Q is near-universal for VLAN trunking. Confirm both sides are set to 802.1Q for proper VLAN tagging."
    },
    {
      "id": 100,
      "question": "Which NAC posture scenario is BEST solved by 802.1X plus a RADIUS server checking if endpoints meet AV or OS patch policies, then quarantining them if they do not?",
      "options": [
        "How to unify half-duplex for older NICs",
        "How to ensure no unpatched or insecure devices gain full network access by automatically isolating them in a restricted VLAN",
        "How to forcibly trunk all VLANs to each user port",
        "How to set the STP root in each VLAN instance"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Half-duplex NICs, trunk ports, or STP root are separate. NAC posture with 802.1X (correct) automatically checks device security, placing non-compliant endpoints in a quarantine. That is exactly how NAC addresses compromised or unpatched devices.",
      "examTip": "NAC posture enforcement is central to zero trust. If a device fails checks, it's restricted or denied until corrected."
    }
  ]
});
