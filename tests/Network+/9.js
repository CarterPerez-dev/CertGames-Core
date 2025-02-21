db.tests.insertOne({
  "category": "nplus",
  "testId": 9,
  "testName": "Network Practice Test #9 (Ruthless)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A router redistributes routes from BGP into OSPF. Which OSPF LSA type is generated to represent these external networks in a standard area?",
      "options": [
        "Type 1 (Router LSA)",
        "Type 3 (Summary LSA)",
        "Type 5 (External LSA)",
        "Type 7 (NSSA LSA)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "External routes in a non-stub OSPF area are represented by Type 5 LSAs from the ASBR. Type 7 LSAs are used in NSSA areas, then converted to Type 5 by the ABR. Type 1 is for router links, and Type 3 is for inter-area summaries.",
      "examTip": "OSPF Type 5 LSAs advertise external networks injected by an ASBR in a standard or backbone area."
    },
    {
      "id": 2,
      "question": "In a zero-trust model, which approach ensures that even internal traffic between subnets is not inherently trusted and must be continuously verified?",
      "options": [
        "Assign the same VLAN across all devices for simplicity",
        "Use 802.1D STP to block internal paths by default",
        "Segment networks heavily and apply ongoing authentication/policy checks for each resource request",
        "Disable DHCP so IP addresses cannot be assigned automatically"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Zero trust means no traffic is implicitly trusted, requiring repeated validation at each step. Simple VLAN or STP changes do not accomplish this. Disabling DHCP is not relevant to ongoing identity checks.",
      "examTip": "Zero-trust architectures emphasize micro-segmentation plus continuous identity and posture verification, even inside the LAN."
    },
    {
      "id": 3,
      "question": "Which BGP attribute can override AS-Path length from a local router’s perspective, and is evaluated even before Local Preference in Cisco devices?",
      "options": [
        "MED",
        "Community no-export",
        "Weight",
        "Origin"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Weight (a Cisco-proprietary attribute) is the top priority in Cisco’s BGP route selection. It is not propagated to other routers. Local Preference, AS-Path length, and MED come after Weight in the decision order.",
      "examTip": "Weight is unique to Cisco, local to the router. Higher weight is preferred over routes with lower weight."
    },
    {
      "id": 4,
      "question": "A new trunk on a switch is not carrying VLAN 77 traffic. Which FIRST command on Cisco helps confirm whether VLAN 77 is allowed on that trunk?",
      "options": [
        "show vlan brief",
        "show arp vlan 77",
        "show interface trunk",
        "show mac address-table vlan 77"
      ],
      "correctAnswerIndex": 2,
      "explanation": "While 'show vlan brief' verifies VLAN existence, 'show interface trunk' directly shows the trunk’s encapsulation, native VLAN, and allowed VLAN list. That’s usually the first check if traffic for a specific VLAN is missing.",
      "examTip": "Always verify the trunk’s allowed VLAN list with 'show interface trunk' when a particular VLAN is not passing across the link."
    },
    {
      "id": 5,
      "question": "A router is injecting RIP-learned routes into EIGRP. Which router type is it considered within EIGRP’s domain?",
      "options": [
        "ASBR (Autonomous System Boundary Router)",
        "Stub router",
        "Feasible successor router",
        "ABR (Area Border Router)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "ASBR is a common term in OSPF, but generically it applies to any router redistributing external routes into a routing process, including EIGRP. Stub router is an EIGRP concept but not for external route injection. ABR is strictly OSPF terminology.",
      "examTip": "Any router that redistributes external routes into a routing domain can be called an ASBR, even though the term is famously used in OSPF."
    },
    {
      "id": 6,
      "question": "Which approach is recommended to mitigate an ARP-based on-path attack forging the default gateway’s MAC address?",
      "options": [
        "Use a single VLAN for all devices",
        "Enable half-duplex on user ports",
        "Implement Dynamic ARP Inspection with DHCP snooping data",
        "Trunk all VLANs to every user port"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Dynamic ARP Inspection (DAI) verifies ARP packets against known IP-to-MAC mappings from DHCP snooping or static bindings, preventing forged ARP. A single VLAN or trunking all VLANs does not help security. Half-duplex is a separate issue.",
      "examTip": "ARP spoofing can be thwarted by DAI, which checks if ARP replies match legitimate MAC-IP pairs."
    },
    {
      "id": 7,
      "question": "Which trunking protocol was proprietary to Cisco for VLAN tagging but has been replaced by IEEE 802.1Q in modern networks?",
      "options": [
        "ISL",
        "DTP",
        "LLDP",
        "VTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "ISL (Inter-Switch Link) was Cisco-proprietary. DTP negotiates trunk formation, LLDP is device discovery, and VTP is VLAN database distribution. Most modern switches use 802.1Q for trunk encapsulation.",
      "examTip": "ISL is essentially deprecated. 802.1Q is the open standard. Always confirm your equipment supports 802.1Q for interoperability."
    },
    {
      "id": 8,
      "question": "A user obtains an IP from a rogue DHCP server. Which direct feature can stop unauthorized servers from handing out addresses on the corporate LAN?",
      "options": [
        "DHCP snooping, designating only specific ports as trusted for DHCP offers",
        "Storm control limiting broadcast frames",
        "Setting all user ports to trunk mode",
        "Enabling half-duplex to slow DHCP traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DHCP snooping blocks DHCP replies from untrusted ports. Storm control limits overall broadcast, but not specifically DHCP offers. Trunk mode is irrelevant here, and half-duplex is a link mismatch approach. Snooping is the canonical solution.",
      "examTip": "DHCP snooping is essential to stop rogue servers. Only the legitimate server port is marked trusted."
    },
    {
      "id": 9,
      "question": "Which STP feature ensures a newly introduced switch cannot send superior BPDUs to become root on an access or distribution-facing port?",
      "options": [
        "BPDU filter",
        "Root guard",
        "Portfast",
        "UplinkFast"
      ],
      "correctAnswerIndex": 1,
      "explanation": "BPDU filter drops BPDUs entirely, which can hide loops. Root guard specifically prevents any device on that port from becoming root. Portfast is for end-host ports. UplinkFast speeds convergence on access switches. Root guard is the correct approach to protect the current root.",
      "examTip": "Root guard enforces that certain ports cannot accept superior BPDUs, preserving the chosen root bridge."
    },
    {
      "id": 10,
      "question": "Which technology encapsulates IPv6 in IPv4 packets so IPv6 clients can traverse an IPv4-only core without translation?",
      "options": [
        "NAT64",
        "Dual stack",
        "Tunneling (e.g., 6to4, ISATAP)",
        "DHCPv6"
      ],
      "correctAnswerIndex": 2,
      "explanation": "NAT64 translates IPv6 to IPv4. Dual stack runs both protocols natively. Tunneling (like 6to4, ISATAP) encapsulates v6 in v4. DHCPv6 is for address assignment, not transit. Tunnels let IPv6 traffic cross IPv4 networks without rewriting addresses.",
      "examTip": "If the core is not IPv6-ready, tunnels (6to4, ISATAP, GRE) let IPv6 traffic pass inside IPv4 packets."
    },
    {
      "id": 11,
      "question": "A distribution switch CPU spikes from frequent STP recalculations. Logs show TCN (Topology Change Notification) events triggered by one user port. Which direct action is recommended FIRST?",
      "options": [
        "Disable that port or check for a flapping link/device",
        "Enable DTP dynamic trunking on that port",
        "Configure half-duplex to reduce collisions",
        "Deploy DHCP snooping with Option 82"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Frequent TCN suggests a port is going up/down or toggling states. The immediate step is to disable or troubleshoot that flapping port. DTP is trunk negotiation, half-duplex is mismatch, and DHCP snooping is unrelated to STP TCNs.",
      "examTip": "Flapping ports cause repeated STP reconvergence. Isolate or shut the problematic interface to stabilize the topology."
    },
    {
      "id": 12,
      "question": "Which BGP concept allows routes to be tagged with special values (e.g., ‘no-export’) to control how they are advertised beyond the local boundary?",
      "options": [
        "Local preference",
        "Communities",
        "MED (multi-exit discriminator)",
        "Weight"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Local preference, MED, and Weight are selection attributes. Communities (correct) are used as additional route markings for advanced policy. They can be well-known like ‘no-export’ or custom. They do not by themselves determine path selection but do affect route propagation or filtering.",
      "examTip": "BGP communities are powerful tags. For example, 'no-export' prevents the route from being sent to external neighbors."
    },
    {
      "id": 13,
      "question": "Which direct measure helps prevent double-tagging VLAN hopping attacks on an 802.1Q trunk?",
      "options": [
        "Use VLAN 1 as the native VLAN consistently",
        "Manually set the trunk native VLAN to a non-default VLAN and disable DTP auto-negotiation",
        "Enable half-duplex on trunk ports",
        "Run STP in MST mode"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Double-tagging relies on VLAN 1 or default native VLAN. Changing it to a dedicated VLAN and disallowing dynamic trunk formation stops this. VLAN 1 as native is precisely the exploit point. Half-duplex or MST doesn't solve double-tagging.",
      "examTip": "Always avoid VLAN 1 as native and disable trunk auto-negotiation to reduce VLAN hopping risk."
    },
    {
      "id": 14,
      "question": "A zero trust approach is mandated. Which statement is MOST accurate about internal segmentation under zero trust?",
      "options": [
        "All subnets are merged into one large VLAN to simplify identity checks",
        "The entire corporate LAN is implicitly trusted once inside the perimeter",
        "User authentication is only required at initial login, never re-validated",
        "Micro-segmentation restricts lateral movement, requiring continuous verification for each resource"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Zero trust explicitly denies broad network trust. Merging subnets undermines security. Once inside doesn't imply trust. Re-validation is continuous. Micro-segmentation plus repeated authentication limit lateral spread.",
      "examTip": "Zero trust breaks the assumption of a trusted internal network, employing micro-segmentation and repeated identity checks."
    },
    {
      "id": 15,
      "question": "Which EIGRP feature addresses large network designs by limiting the scope of route queries beyond a certain router, preventing SIA storms?",
      "options": [
        "Split horizon with poison reverse",
        "Stub routing",
        "Auto-summary",
        "Route filtering with prefix lists"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Split horizon avoids re-advertising learned routes out the same interface, not limiting queries. Stub routing (correct) stops queries from propagating beyond the stub device. Auto-summary is classful summarization. Route filtering is manual but not specifically about query reduction. EIGRP stub is standard for branch routers that do not pass queries further.",
      "examTip": "Marking a router as EIGRP stub helps confine queries, reducing 'Stuck in Active' issues in large networks."
    },
    {
      "id": 16,
      "question": "A distribution switch sees unstoppable broadcasts after a user looped two access ports with a small consumer switch. Which feature is BEST to shut down the port when it sees BPDUs from an unexpected source?",
      "options": [
        "DHCP snooping",
        "BPDU guard",
        "CDP neighbor guard",
        "Port security with sticky MAC"
      ],
      "correctAnswerIndex": 1,
      "explanation": "BPDU guard is specifically for blocking bridging devices on access ports. DHCP snooping is for rogue DHCP, CDP neighbor guard is not a standard blocking mechanism, port security is MAC-based. BPDU guard disables the port upon receiving a BPDU from an end-user device.",
      "examTip": "BPDU guard immediately puts an access port into err-disable if it detects a bridging device sending STP frames."
    },
    {
      "id": 17,
      "question": "Which NAC posture check commonly enforces ensuring endpoints have updated antivirus signatures before granting normal LAN access?",
      "options": [
        "Spanning tree root guard",
        "802.3af PoE injection",
        "802.1X with a RADIUS-driven posture policy",
        "DHCP server scope extension"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is STP security, Option B is power over Ethernet, Option C (correct) NAC posture is integrated with 802.1X to check AV or OS patch status. Option D is IP address management. NAC posture plus 802.1X ensures only compliant endpoints get full access.",
      "examTip": "NAC posture checks confirm a device meets security policies (AV, patches) before granting LAN resources."
    },
    {
      "id": 18,
      "question": "Which method is used to manipulate outbound traffic path selection within an AS in a multi-homed BGP environment?",
      "options": [
        "MED",
        "Local Preference",
        "AS-Path Prepending",
        "Weight is always carried to other routers"
      ],
      "correctAnswerIndex": 1,
      "explanation": "MED typically influences inbound from neighboring AS. Local Preference (correct) is used inside the AS for outbound route selection. AS-Path Prepending is for inbound route manipulation externally. Weight is local to one router, not shared with iBGP peers. Local_Pref is the broad iBGP attribute for egress path choice.",
      "examTip": "Local Preference is the key attribute in iBGP for choosing which external path the AS uses to exit."
    },
    {
      "id": 19,
      "question": "A newly deployed trunk port is passing traffic for VLANs 10, 20, and 30 but not 50. Which single command typically fixes that on a Cisco switch?",
      "options": [
        "switchport trunk allowed vlan add 50",
        "switchport trunk native vlan 50",
        "vlan 50 name Data",
        "show interface trunk detail"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) adds VLAN 50 to the trunk allow list. Option B changes the native VLAN. Option C creates or names VLAN 50 but does not allow it on the trunk. Option D is a diagnostic command, not a fix. The “switchport trunk allowed vlan add 50” command ensures VLAN 50 is passed.",
      "examTip": "If a VLAN is missing from trunk traffic, confirm it’s in the allowed VLAN list. Use ‘add <vlan>’ syntax on both ends."
    },
    {
      "id": 20,
      "question": "Which is the PRIMARY role of an ABR (Area Border Router) in an OSPF domain?",
      "options": [
        "Redistribute external routes from another AS",
        "Connect multiple OSPF areas, holding LSDBs for each area",
        "Serve as the designated router in all VLANs",
        "Always store a full BGP table"
      ],
      "correctAnswerIndex": 1,
      "explanation": "ASBR injects external routes, not ABR. The ABR (correct) connects area 0 to non-backbone areas, having multiple LSDBs. DR is a multi-access segment concept, while BGP is separate. ABRs pass summary LSAs (Type 3) to other areas.",
      "examTip": "ABR stands between backbone area (0) and other OSPF areas, summarizing routes. ASBR deals with external route injection."
    },
    {
      "id": 21,
      "question": "Which statement accurately describes VRRP (Virtual Router Redundancy Protocol)?",
      "options": [
        "It enforces half-duplex on redundant links",
        "Multiple routers share one virtual IP, with one active as master",
        "It cannot be used for default gateway redundancy",
        "A single router is designated root for all VLANs"
      ],
      "correctAnswerIndex": 1,
      "explanation": "VRRP (correct) provides a virtual IP across multiple routers, one being master. Option A is a mismatch, Option C is incorrect, and Option D references STP. VRRP ensures hosts keep the same gateway IP with redundancy behind the scenes.",
      "examTip": "HSRP, VRRP, and GLBP each provide gateway redundancy. VRRP is an open standard where multiple routers share a virtual IP."
    },
    {
      "id": 22,
      "question": "Which measure helps block inbound SSH attempts from unknown internet sources while allowing internal admins?",
      "options": [
        "Default allow for all inbound management ports",
        "ACL or firewall rule permitting SSH only from known internal subnets",
        "Enable half-duplex on the SSH interface",
        "Extend the DHCP lease for internal hosts"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Permitting SSH from internal or known IP addresses is standard. Setting default allow is insecure, half-duplex is irrelevant, and DHCP lease time is about IP assignment. A firewall or ACL is the direct measure to restrict SSH.",
      "examTip": "Restrict management protocols to known IP ranges or a dedicated management VPN. Don’t expose SSH globally."
    },
    {
      "id": 23,
      "question": "In EIGRP, what does a 'feasible successor' represent?",
      "options": [
        "A route that meets the feasibility condition (lower reported distance than the successor’s feasible distance) and can be used immediately if the primary route fails",
        "An iBGP route that is used for inbound traffic shaping",
        "A route that is stuck in active state forever",
        "The designated router in an OSPF multi-access network"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A feasible successor is a backup route that meets the feasibility condition in EIGRP. If the successor fails, the router uses the feasible successor instantly. The other options reference different protocols or an error state. EIGRP’s feasible successor concept shortens convergence.",
      "examTip": "Feasible successors in EIGRP provide fast failover. They must have an advertised distance less than the successor’s feasible distance."
    },
    {
      "id": 24,
      "question": "Which advanced NAC capability can push a user-specific ACL from the RADIUS server, restricting traffic to certain destinations after successful 802.1X authentication?",
      "options": [
        "Downloadable ACL (dACL)",
        "DHCP Option 82 insertion",
        "BPDU filter for bridging loops",
        "Port security sticky MAC"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Downloadable ACL (correct) or dACL is a NAC feature that applies per-session rules from the RADIUS server. DHCP Option 82 tracks port info, BPDU filter is STP, port security is MAC-based. dACL enforces a dynamic layer 3 policy upon authentication.",
      "examTip": "dACL is a powerful NAC tool: after 802.1X success, the switch downloads a user-specific ACL from RADIUS, controlling traffic precisely."
    },
    {
      "id": 25,
      "question": "Which trunking detail is CRUCIAL if VLAN traffic fails to propagate between two multi-vendor switches?",
      "options": [
        "Confirm both sides use 802.1Q encapsulation",
        "Root guard is enabled on the trunk port",
        "Port security is limiting MAC addresses to one",
        "Syslog server is configured on the interface"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Multi-vendor gear typically requires 802.1Q for trunking. Root guard, port security, or syslog config do not address cross-vendor VLAN tagging. If one side attempts a proprietary method or default VLAN mismatch, it fails.",
      "examTip": "Ensure 802.1Q is set for multi-vendor trunking, plus consistent native VLAN and allowed VLAN lists."
    },
    {
      "id": 26,
      "question": "Which approach is used to give a phone and PC separate VLAN assignments on the same switch port, with phone traffic tagged and PC traffic untagged?",
      "options": [
        "802.1X EAP bridging",
        "Autonegotiation to half-duplex",
        "Voice VLAN (auxiliary VLAN) configuration",
        "DHCP snooping pass-through"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Voice VLAN (correct) is the typical approach for IP phones passing tagged traffic on a dedicated VLAN while the PC remains untagged on the data VLAN. EAP bridging, half-duplex, and snooping are not relevant to voice/data VLAN separation.",
      "examTip": "Voice VLAN is widely used to keep phone traffic separate from data, ensuring correct QoS and simpler management."
    },
    {
      "id": 27,
      "question": "Which BGP attribute is typically used to influence how external AS neighbors route traffic inbound into your AS if multiple entry points exist?",
      "options": [
        "Local Preference",
        "MED (Multi-Exit Discriminator)",
        "Weight",
        "Origin code"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Local Preference is for outbound selection inside your AS, Weight is local to one router, and Origin code indicates route source. MED (correct) is typically a hint to external neighbors on which path to choose inbound, if they respect it.",
      "examTip": "MED is a suggestion to external peers about which path is preferred for inbound traffic. Not all ISPs honor it, but it’s the official method."
    },
    {
      "id": 28,
      "question": "Which scenario-based question is BEST solved by deploying MST (Multiple Spanning Tree)?",
      "options": [
        "How to unify all VLANs into a single STP instance for security",
        "How to map sets of VLANs into fewer STP instances, reducing CPU overhead vs. per-VLAN spanning tree",
        "How to prevent trunk ports from allowing multiple VLANs",
        "How to block DHCP offers from rogue servers"
      ],
      "correctAnswerIndex": 1,
      "explanation": "MST (correct) groups VLANs into a limited number of STP instances, lowering overhead. Single STP instance for all VLANs is less flexible, trunk blocking is a separate configuration, DHCP offers are addressed by snooping, not MST.",
      "examTip": "MST is an IEEE standard bridging protocol grouping VLANs. This lightens the load compared to one STP per VLAN (PVST+)."
    },
    {
      "id": 29,
      "question": "A router shows a newly injected static default route in EIGRP. Which command or approach typically accomplishes this injection?",
      "options": [
        "network 0.0.0.0 under EIGRP",
        "redistribute static route-map DEFAULT",
        "passive-interface default on the WAN link",
        "Enable half-duplex on LAN"
      ],
      "correctAnswerIndex": 1,
      "explanation": "EIGRP doesn't support 'network 0.0.0.0' for default route injection. The typical method is 'redistribute static' referencing a 0.0.0.0/0 route. Passive-interface stops sending updates, and half-duplex is irrelevant. Redistributing the static default route with a proper metric or route-map is standard.",
      "examTip": "EIGRP default routes typically come from redistributing a static 0.0.0.0/0 route. A route-map or metric must be specified."
    },
    {
      "id": 30,
      "question": "Which condition does Rapid PVST+ improve upon compared to classic 802.1D STP?",
      "options": [
        "It runs half-duplex on root ports by default",
        "It speeds up convergence times by quickly transitioning ports without relying on lengthy listening/learning states",
        "It merges VLANs into a single instance of spanning tree",
        "It blocks all VLAN trunking negotiations"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Rapid PVST+ accelerates convergence using 802.1w for each VLAN, reducing the time needed for state transitions. It doesn’t force half-duplex, nor unify VLANs, nor block trunking. Rapidly converging STP is the main improvement.",
      "examTip": "802.1w Rapid STP transitions ports quickly to forwarding or blocking, improving recovery from link changes."
    },
    {
      "id": 31,
      "question": "Which next-gen firewall technique detects hidden malware by terminating SSL sessions, inspecting decrypted payloads, then re-encrypting traffic to the server?",
      "options": [
        "Stateless packet filter",
        "SSL/TLS interception (forward proxy)",
        "DHCP snooping for IP",
        "802.1Q trunk auto"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Stateless filtering is layer 3/4 only. SSL interception (correct) does a man-in-the-middle to check encrypted flows. DHCP snooping is separate, and 802.1Q trunk auto is about VLAN negotiation. SSL/TLS forward proxy is how NGFW sees inside HTTPS.",
      "examTip": "TLS interception is sometimes called SSL offloading or forward proxy, letting the firewall scan encrypted traffic for threats."
    },
    {
      "id": 32,
      "question": "Which direct measure can isolate IoT devices in a separate network, limiting possible lateral movement if they're compromised?",
      "options": [
        "Assign them all to VLAN 1 for better bandwidth",
        "Map each device MAC to half-duplex ports",
        "Use a dedicated VLAN or subnet with ACL rules restricting access to internal resources",
        "Enable trunking dynamic desirable"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A dedicated VLAN or subnet with ACL restrictions (correct) is a best practice. VLAN 1 for all devices is insecure, half-duplex is a link mismatch, trunking dynamic is not relevant. Segmenting IoT is crucial for reducing risk if compromised.",
      "examTip": "Segregate IoT or untrusted devices in their own VLAN, applying ACL/firewall rules to limit their reach into the main network."
    },
    {
      "id": 33,
      "question": "Which NAC posture enforcement scenario ensures an unpatched laptop is automatically placed in a quarantine VLAN for remediation updates?",
      "options": [
        "VTP pruning of the VLAN",
        "802.1X with dynamic VLAN assignment from RADIUS after posture check",
        "Half-duplex bridging to reduce collisions",
        "Enable root guard on the trunk port"
      ],
      "correctAnswerIndex": 1,
      "explanation": "VTP pruning is VLAN distribution optimization, half-duplex is link mismatch, and root guard is STP. 802.1X NAC with dynamic VLAN assignment (correct) places the device in a restricted VLAN if posture checks fail.",
      "examTip": "802.1X NAC solutions commonly push quarantine VLANs or dACLs from RADIUS for non-compliant endpoints."
    },
    {
      "id": 34,
      "question": "A user obtains 169.254.x.x. Which statement is TRUE about this address?",
      "options": [
        "It indicates a successful DHCP assignment",
        "It’s APIPA, used when the client can’t reach a DHCP server",
        "It’s a NAT address from the router",
        "It’s the result of spanning tree root guard"
      ],
      "correctAnswerIndex": 1,
      "explanation": "169.254.x.x is APIPA, assigned automatically if DHCP fails. It does not mean successful lease or NAT. Root guard or STP is unrelated. APIPA only provides link-local connectivity, no routing beyond the local subnet.",
      "examTip": "169.254.x.x means the client did not receive a DHCP lease, so Windows assigned APIPA fallback."
    },
    {
      "id": 35,
      "question": "Which approach is used to keep on-path attackers from intercepting WPA2-Enterprise authentication by posing as a fake RADIUS server?",
      "options": [
        "EAP methods using server certificate validation (e.g., PEAP/EAP-TLS)",
        "WEP encryption with open authentication",
        "802.1D loop detection",
        "DHCP Option 43 for phone config"
      ],
      "correctAnswerIndex": 0,
      "explanation": "EAP-based Wi-Fi enterprise authentication that verifies the server certificate ensures the client is connecting to a legitimate RADIUS/EAP server, preventing evil twin or MITM. WEP is insecure, STP is loop prevention, and Option 43 is vendor info for DHCP. Cert-based EAP is the standard.",
      "examTip": "PEAP or EAP-TLS typically requires verifying the server’s cert so clients don’t hand credentials to a rogue AP or server."
    },
    {
      "id": 36,
      "question": "Which direct measure stops traffic from an IP phone bridging another unauthorized device on the same switch port, beyond the legitimate phone and PC connection?",
      "options": [
        "LLDP-MED classification",
        "Wireless band steering",
        "Port security with a maximum of two MAC addresses on that port",
        "Half-duplex trunk for the phone"
      ],
      "correctAnswerIndex": 2,
      "explanation": "LLDP-MED is device discovery for VoIP, band steering is Wi-Fi, half-duplex is a mismatch. Port security with max MAC=2 (the phone and the PC) prevents additional devices. This ensures only the phone plus the PC behind it are recognized.",
      "examTip": "IP phones typically have a built-in switch for the attached PC. Port security limiting MAC addresses to 2 can block extra unknown devices."
    },
    {
      "id": 37,
      "question": "A switch is receiving numerous BPDUs on an access interface from a user’s mini-switch. Which feature ensures the port is disabled if it sees STP frames from an unauthorized bridging device?",
      "options": [
        "DHCP snooping",
        "BPDU guard",
        "Root guard",
        "CDP advertisements"
      ],
      "correctAnswerIndex": 1,
      "explanation": "DHCP snooping is IP address security, root guard ensures the local switch remains root if it sees superior BPDUs, but does not always shut the port. BPDU guard (correct) disables the port upon receiving any BPDUs. CDP is discovery only.",
      "examTip": "BPDU guard is specifically for access or edge ports to immediately shut them down if bridging frames appear."
    },
    {
      "id": 38,
      "question": "A network team needs a single IP address for internet access shared by many internal clients. Which NAT solution is used for that many-to-one scenario?",
      "options": [
        "Static NAT one-to-one",
        "DNS round robin",
        "PAT (Port Address Translation)",
        "SLAAC IPv6 addressing"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Static NAT is one-to-one. DNS round robin is for server load balancing, not NAT. PAT (correct) translates multiple private IPs to a single public IP using unique source port mapping. SLAAC is IPv6 autoconfiguration, not NAT.",
      "examTip": "PAT (overloaded NAT) is the standard technique for large-scale outbound connections using one or few public IPs."
    },
    {
      "id": 39,
      "question": "Which statement accurately describes an MST (Multiple Spanning Tree) region?",
      "options": [
        "All switches run a separate STP instance per VLAN",
        "MST merges all VLANs into one big STP instance with no grouping",
        "Each MST region can map multiple VLANs to different MST instances, reducing overhead vs. per-VLAN STP",
        "MST is only for half-duplex links"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is PVST+ approach, Option B lumps them into one STP instance with no grouping, losing flexibility. Option C (correct) is the main advantage. Option D is a mismatch. MST can define multiple instances, each instance can handle a set of VLANs.",
      "examTip": "MST groups VLANs so you can have fewer STP processes than one per VLAN while preserving distinct topologies if needed."
    },
    {
      "id": 40,
      "question": "Which approach is recommended if you suspect a rogue device bridging two VLANs together on an access port?",
      "options": [
        "Enable port mirroring for that user",
        "Use half-duplex to prevent bridging",
        "Enable BPDU guard or root guard for that access port",
        "Set the user’s NIC to trunk mode"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is monitoring, Option B is a mismatch, Option C (correct) stops bridging loops if the device tries to send STP frames, Option D is exactly what you do NOT want. BPDU guard or root guard helps isolate unauthorized bridging attempts.",
      "examTip": "If a user plugs in a personal switch bridging VLANs or sending BPDUs, BPDU guard or root guard can disable that port."
    },
    {
      "id": 41,
      "question": "Which scenario-based question is BEST resolved by implementing a clientless SSL VPN solution?",
      "options": [
        "How to passively monitor traffic with a SPAN port",
        "How to let traveling employees securely connect via a browser without installing a VPN client",
        "How to unify all VLANs under MST",
        "How to half-duplex the WAN link to reduce collisions"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is packet capture, Option B (correct) is the hallmark of clientless SSL VPN, Option C is STP design, Option D is link mismatch. A clientless SSL VPN only requires an HTTPS browser to connect securely to internal resources.",
      "examTip": "Clientless VPN (SSL portal) is perfect for users who lack admin rights or time to install a dedicated VPN client."
    },
    {
      "id": 42,
      "question": "Which direct measure can block inbound HTTPS attempts from unknown external IPs while allowing known partners?",
      "options": [
        "Use a DNS record for the known IPs",
        "Enable DHCP snooping on the DMZ",
        "ACL restricting port 443 to specific source IP ranges",
        "Set half-duplex on the DMZ interface"
      ],
      "correctAnswerIndex": 2,
      "explanation": "DNS records do not block traffic. DHCP snooping is for IP assignment security. An ACL (correct) is the typical firewall approach. Half-duplex is a mismatch. Firewalls commonly allow port 443 from certain IP ranges or require a deeper security check.",
      "examTip": "Use firewall or ACL rules to limit inbound connections on port 443 to trusted IPs, reducing attack surface."
    },
    {
      "id": 43,
      "question": "Which Cisco proprietary protocol can override AS-Path for route selection but only applies locally to that router, not shared with iBGP peers?",
      "options": [
        "Community no-export",
        "MED",
        "Local Preference",
        "Weight"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Communities can be passed to peers. MED and Local Preference are also shared within the AS. Weight (correct) is local-only on the router, top priority in Cisco BGP route selection. It doesn’t propagate to other routers.",
      "examTip": "Weight is a local setting in Cisco BGP. If you want to prefer one route on a specific router only, you can set its Weight higher."
    },
    {
      "id": 44,
      "question": "Which advanced NAC posture check is TYPICAL to ensure an endpoint’s OS is fully patched before granting normal VLAN access?",
      "options": [
        "BPDU guard for bridging loops",
        "802.1X EAP-based posture assessment integrated with RADIUS",
        "MST root instance mapping",
        "ARP inspection for IP-to-MAC"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A and C are STP. Option D is ARP security. NAC posture checks typically revolve around 802.1X with a RADIUS-based server that checks patch level, AV status, etc.",
      "examTip": "Zero trust or NAC solutions can dynamically move an endpoint failing posture to a quarantine VLAN, or deny it entirely."
    },
    {
      "id": 45,
      "question": "A distribution switch reboots after each large PoE device is added. Logs show power draw spikes. Which single measure is MOST appropriate?",
      "options": [
        "Implement half-duplex on PoE ports",
        "Add an uninterruptible power supply on each PoE port",
        "Check the switch’s PoE budget and possibly upgrade to a higher-capacity model or add another PoE switch",
        "Extend the DHCP scope for more IP addresses"
      ],
      "correctAnswerIndex": 2,
      "explanation": "PoE budget is limited. If new devices exceed it, the switch can overload and reboot. Half-duplex doesn’t fix power, a UPS on each port is nonsensical, and DHCP scope is IP management. Upgrading or distributing the PoE load is the typical fix.",
      "examTip": "Each PoE switch has a max wattage capacity. Exceeding it can cause shutdowns or power failures. Plan PoE budget carefully."
    },
    {
      "id": 46,
      "question": "Which measure is required on a trunk if you suspect double-tagging VLAN hopping attempts?",
      "options": [
        "Keep VLAN 1 as native everywhere for consistency",
        "Disable DTP and set a non-default native VLAN explicitly",
        "Enable half-duplex for trunk ports",
        "Assign an IP from the DHCP server"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is exactly what attackers exploit. Option B (correct) is the standard best practice. Option C is link mismatch, Option D is IP addressing. Using a distinct native VLAN and disallowing trunk auto-negotiation mitigate double-tagging attacks.",
      "examTip": "Attackers exploit VLAN 1 as the default native VLAN with double tags. Hard-coding a unique native VLAN plus static trunk mode is safer."
    },
    {
      "id": 47,
      "question": "Which advanced STP concept provides a single region where multiple VLANs can be assigned to a set of spanning tree instances, reducing overhead vs. one instance per VLAN?",
      "options": [
        "RSTP",
        "PVST+",
        "MST",
        "Portfast trunk"
      ],
      "correctAnswerIndex": 2,
      "explanation": "RSTP is rapid version of STP, PVST+ is per-VLAN spanning tree, MST (correct) groups VLANs into fewer instances, and “Portfast trunk” is not standard. MST is used for large VLAN deployments to reduce CPU load.",
      "examTip": "MST merges VLANs into a limited number of STP processes. RSTP is the fast convergence method, and MST extends that concept further for VLAN grouping."
    },
    {
      "id": 48,
      "question": "A network admin wants to ensure if the main switch fails, another can immediately handle the default gateway IP for end users. Which solution addresses this scenario?",
      "options": [
        "BPDU guard on all ports",
        "VRRP or HSRP gateway redundancy",
        "DHCP option 82 insertion",
        "EIGRP stub config on the core"
      ],
      "correctAnswerIndex": 1,
      "explanation": "BPDU guard is STP, DHCP Option 82 is relay info, EIGRP stub is route scope. VRRP or HSRP (correct) provides a virtual IP for the default gateway. If the primary fails, the backup takes over seamlessly.",
      "examTip": "HSRP/VRRP ensure a stable default gateway IP even if the primary router/switch goes offline."
    },
    {
      "id": 49,
      "question": "Which direct measure can hamper VLAN hopping by automatically turning user ports into access mode with no trunk negotiation?",
      "options": [
        "Disabling NAT overload on user ports",
        "Using DHCP reservations for all devices",
        "Switchport mode access + switchport nonegotiate (disabling DTP)",
        "Enabling half-duplex for VLAN security"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is NAT, Option B is IP management, Option C (correct) sets the port in static access mode and disables trunk negotiation, blocking VLAN hopping. Option D is a link mismatch. Disabling DTP prevents automatic trunk formation with rogue devices.",
      "examTip": "On user ports, always turn off trunk auto-negotiation. Hard-code them as access ports for security and stability."
    },
    {
      "id": 50,
      "question": "Which NAC posture approach helps isolate non-compliant devices by assigning them a quarantined subnet with limited remediation services?",
      "options": [
        "Default gateway of 0.0.0.0",
        "802.1X with dynamic VLAN or ACL from the RADIUS server",
        "DHCP snooping for IP lease checks",
        "Running STP in half-duplex"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is invalid, Option B (correct) NAC can move failing endpoints to a special VLAN or apply dACL, Option C is DHCP security, Option D is link mismatch. NAC posture can dynamically isolate non-compliant endpoints post-auth.",
      "examTip": "NAC posture enforcement commonly uses a restricted VLAN or dynamic ACL to confine endpoints until they meet security policies."
    },
    {
      "id": 51,
      "question": "Which BGP attribute is typically used to break ties after Weight, Local Pref, AS-Path, and MED have been considered?",
      "options": [
        "Origin (IGP/EGP/Incomplete)",
        "Community no-export",
        "Router ID",
        "MED is the last step"
      ],
      "correctAnswerIndex": 0,
      "explanation": "After the main attributes, the BGP route selection often checks Origin type (IGP < EGP < Incomplete). Then further tie-breaks can include lowest next-hop IP or router ID. MED is considered earlier than origin if local_pref and path length are equal.",
      "examTip": "Cisco’s BGP decision is roughly: Weight > Local_Pref > Origination (locally injected) > AS-Path length > MED > eBGP over iBGP > lowest IGP cost to next hop > oldest route > lowest neighbor ID > ... Origin is also in the priority list before final tie-breakers."
    },
    {
      "id": 52,
      "question": "Which feature in EIGRP ensures near-instant fallback if the primary (successor) route fails, provided a feasible successor route is available?",
      "options": [
        "Split horizon on each interface",
        "Feasible successor with a lower reported distance than the successor’s feasible distance",
        "DHCP snooping pass-through",
        "Auto-summary for classful boundaries"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Split horizon prevents route loops, DHCP snooping is IP security, auto-summary is classful. Feasible successor (correct) is the EIGRP backup route. If it meets the feasibility condition, failover is immediate without going active.",
      "examTip": "If a route has a feasible successor, EIGRP does not need to query neighbors upon failure, speeding convergence."
    },
    {
      "id": 53,
      "question": "Which statement accurately characterizes MPLS in a service provider WAN?",
      "options": [
        "MPLS can only operate over IPv6 networks",
        "It encrypts data by default from customer edge to customer edge",
        "It routes traffic by label rather than strictly IP lookups, allowing QoS and traffic engineering",
        "MPLS always requires half-duplex to avoid collisions"
      ],
      "correctAnswerIndex": 2,
      "explanation": "MPLS is IP version-agnostic, it does not inherently encrypt data, and half-duplex is not relevant. MPLS uses labels to forward packets, supporting TE, fast reroute, and QoS. It’s widely used by SPs to segment and manage traffic flows.",
      "examTip": "MPLS label-switched paths allow advanced traffic engineering, but encryption is not built in."
    },
    {
      "id": 54,
      "question": "Which synergy is typical in a NAC posture solution integrated with 802.1X?",
      "options": [
        "Port security sticky MAC addresses for each client",
        "RADIUS returning posture checks so the switch can enforce restricted or full VLAN assignment dynamically",
        "Auto duplex negotiation for posture detection",
        "DHCP snooping for trunk negotiation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Sticky MAC is separate. Option B (correct) NAC posture uses RADIUS to instruct the switch about VLAN or ACL. Option C is not relevant, Option D is a misapplication. NAC posture typically is part of 802.1X, controlling user access based on compliance status.",
      "examTip": "When a device authenticates via 802.1X, the NAC server checks posture and returns VLAN/ACL instructions to the switch."
    },
    {
      "id": 55,
      "question": "Which reason BEST explains using a 'voice VLAN' on access ports for IP phones?",
      "options": [
        "Half-duplex operation ensures no collisions for voice",
        "A separate VLAN can apply QoS and security policies specifically for voice traffic",
        "Phones rely on trunk negotiation for bridging PC traffic",
        "Voice VLAN forces static ARP entries"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is not required, Option B (correct) is standard practice: separate VLAN aids QoS and security. Option C referencing trunk negotiation is partially correct but not the main reason. Option D is not typical. Splitting voice from data ensures call prioritization and simpler management.",
      "examTip": "Voice VLAN tagging helps isolate phone traffic from user data, enabling clearer QoS prioritization."
    },
    {
      "id": 56,
      "question": "Which direct measure helps mitigate bridging loops introduced by user-connected dumb switches or accidental cable loops on access ports?",
      "options": [
        "802.1X EAP chaining",
        "BPDU guard placing the port in err-disable if a BPDU is received",
        "DHCP Option 82 tagging",
        "OSPF stub configuration"
      ],
      "correctAnswerIndex": 1,
      "explanation": "802.1X is NAC, DHCP Option 82 is for IP address info, OSPF stubs is routing. BPDU guard (correct) is the STP feature that prevents bridging loops by shutting down ports that receive BPDUs unexpectedly. This is precisely for user access ports.",
      "examTip": "BPDU guard is crucial on edge ports to instantly disable them if bridging frames arrive, preventing loops from user add-ons."
    },
    {
      "id": 57,
      "question": "A NAT device must support thousands of concurrent connections for internal clients. Which NAT type is used to map many private IPs to one public IP with unique source ports?",
      "options": [
        "Static one-to-one NAT",
        "PAT (overload)",
        "DNS-based load balancing",
        "DHCP relay"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Static NAT is single inside to single outside. DNS-based load balancing is unrelated to IP mapping. DHCP relay is broadcast forwarding. PAT (correct) uses source port translation for many internal hosts behind one public IP. This is standard for large enterprise outbound connections.",
      "examTip": "PAT is also called ‘NAT overload.’ It appends unique source port mappings to differentiate multiple internal flows."
    },
    {
      "id": 58,
      "question": "Which direct measure addresses a single user bridging two VLANs with a small switch on an access port, creating a loop?",
      "options": [
        "BPDU guard on that port to err-disable if bridging BPDUs appear",
        "DHCP snooping relay",
        "Half-duplex trunk mode to block bridging",
        "ARIN registration for the user MAC"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) stops bridging loops at user ports, Option B is for DHCP server security, Option C is link mismatch, Option D is irrelevant. BPDU guard is the recognized solution for shutting down a port receiving BPDUs from an unauthorized switch.",
      "examTip": "If a user’s device or hub sends STP frames, the port is swiftly disabled by BPDU guard, preventing bridging loops."
    },
    {
      "id": 59,
      "question": "Which approach is used to prefer one WAN link for inbound traffic from the internet, given multiple BGP-advertised paths to your AS?",
      "options": [
        "Higher Local Preference on the local router",
        "AS-Path Prepending on the undesired path",
        "Use half-duplex on the less favored link",
        "Lower administrative distance for BGP than for OSPF"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Local Preference influences outbound. Inbound traffic is shaped by making one path appear less attractive to external ASes, done via AS-Path Prepending (correct) on the path you want to de-prioritize. Half-duplex is irrelevant, AD is a local concept not shared externally.",
      "examTip": "AS-Path Prepending is the typical method to manipulate inbound traffic flows from external neighbors."
    },
    {
      "id": 60,
      "question": "Which advanced firewall feature applies deep inspection on layer 7 to identify actual applications (like Netflix or Skype) even if they use port 443?",
      "options": [
        "MAC address filter",
        "Application-layer DPI (App-aware firewall)",
        "Port address translation (PAT)",
        "802.1D loop guard"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is L2 basic security, Option B (correct) is an NGFW capability, Option C is NAT for multiple IPs, Option D is STP. Next-gen firewalls do deep packet inspection (DPI) at layer 7, identifying apps beyond port usage.",
      "examTip": "Application recognition is a hallmark of next-generation firewalls, enabling more granular traffic policies."
    },
    {
      "id": 61,
      "question": "A user fails 802.1X posture checks. Which NAC approach commonly puts the device in a restricted VLAN or dACL for remediation?",
      "options": [
        "BPDU guard with half-duplex",
        "802.1Q trunk negotiation",
        "802.1X with dynamic policy from RADIUS",
        "DHCP reservation for that user"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is STP security, Option B is VLAN trunking, Option C (correct) NAC posture can push a restricted VLAN or ACL, Option D is IP assignment. NAC solutions combine posture checks with 802.1X to enforce policy-based VLAN or ACL changes.",
      "examTip": "Failed posture typically triggers a NAC policy to isolate or quarantine the endpoint. RADIUS instructions accomplish that."
    },
    {
      "id": 62,
      "question": "Which phenomenon describes forging large volumes of MAC addresses to overflow a switch’s CAM table, causing the switch to broadcast all traffic?",
      "options": [
        "ARP spoofing",
        "Double-tagging VLAN hopping",
        "MAC flooding",
        "DHCP exhaustion"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A manipulates IP-to-MAC mappings, Option B is VLAN exploit, Option C (correct) saturates the CAM table, Option D is IP leasing. MAC flooding aims to degrade the switch to hub-like behavior so an attacker can sniff traffic.",
      "examTip": "MAC flooding is mitigated by port security or NAC solutions limiting the number of MAC addresses learned per port."
    },
    {
      "id": 63,
      "question": "Which advanced STP approach is used to run a single region with multiple VLANs mapped to fewer spanning tree instances, each controlling a set of VLANs?",
      "options": [
        "PVST+",
        "Rapid PVST+",
        "MST",
        "802.1D standard STP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "PVST+ runs one STP instance per VLAN, Rapid PVST+ is the same but faster, and 802.1D is classic STP. MST (correct) reduces overhead by grouping VLANs into multiple but fewer instances. This is especially helpful in large VLAN environments.",
      "examTip": "MST merges VLANs into a limited set of STP topologies, balancing control with resource usage."
    },
    {
      "id": 64,
      "question": "Which statement about EIGRP summarization is TRUE?",
      "options": [
        "Auto-summary forces classful boundaries, which might be undesired in discontiguous networks",
        "Manual summarization is impossible in EIGRP",
        "Stub routing automatically summarizes all networks",
        "EIGRP never supports summarization of any kind"
      ],
      "correctAnswerIndex": 0,
      "explanation": "EIGRP can do both auto-summary (which reverts to classful boundaries) and manual summarization. Stub routing does not summarize automatically. EIGRP does support summarization. The correct statement is that auto-summary reverts to classful edges, often undesired in complex networks.",
      "examTip": "Auto-summary can cause issues if subnets in a major network exist in different parts of the topology. Manual summarization is typically preferred."
    },
    {
      "id": 65,
      "question": "Which advanced feature of Cisco BGP can dynamically inject routes learned from an iBGP neighbor into OSPF with a specified metric or route-map?",
      "options": [
        "Community no-advertise",
        "Redistribute bgp <as-number> into ospf <process-id>",
        "HSRP for default gateway",
        "Root guard bridging"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Communities are route tags, HSRP is gateway redundancy, root guard is STP. BGP routes can be injected into OSPF by the 'redistribute bgp...' command, often specifying metrics or route-maps. This is how BGP-OSPF inter-protocol route exchange is done.",
      "examTip": "Redistributing BGP into OSPF requires specifying a default metric or letting route-map define metrics and possible filters."
    },
    {
      "id": 66,
      "question": "Which concept ensures that an OSPF stub area will not receive external LSAs (Type 5), but can still learn inter-area routes (Type 3)?",
      "options": [
        "Totally stubby area design",
        "NSSA area type",
        "Plain stub area design",
        "OSPF virtual link"
      ],
      "correctAnswerIndex": 2,
      "explanation": "In standard stub areas, external routes (Type 5) are blocked, but inter-area Type 3 routes are allowed. A totally stubby area also blocks inter-area routes, only providing a default route from the ABR. An NSSA allows some external routes as Type 7. Virtual link is a different concept.",
      "examTip": "Stub area: no Type 5 LSAs, but can get Type 3 summary LSAs. Totally stubby also suppresses Type 3, offering only a default route."
    },
    {
      "id": 67,
      "question": "Which direct measure stops bridging loops caused by a user connecting a personal switch that sends BPDUs on an access port?",
      "options": [
        "BPDU guard shutting down the port when it sees BPDUs",
        "DHCP snooping limiting IP addresses",
        "Half-duplex trunk negotiation",
        "Manual summarization in EIGRP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option A (correct) is the standard solution. DHCP snooping or half-duplex are irrelevant here, EIGRP summarization is a routing concept. BPDU guard is specifically used for user ports that must never see or send STP BPDUs.",
      "examTip": "BPDU guard is crucial on edge ports to immediately disable any port receiving bridging frames from unauthorized devices."
    },
    {
      "id": 68,
      "question": "Which approach is used to manipulate inbound traffic from external ASes in a dual-homed BGP scenario?",
      "options": [
        "Increase Local Preference on the primary router",
        "AS-Path Prepending on the secondary link to make it less attractive",
        "Set half-duplex on the backup router",
        "Use a static default route on the external AS"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Local Preference influences outbound from your AS. AS-Path Prepending (correct) makes a route appear longer to external neighbors, discouraging inbound traffic. Half-duplex is irrelevant, static default on external AS is out of your control typically. Prepending is the standard method for inbound manipulation.",
      "examTip": "AS-Path Prepending artificially lengthens your path so external neighbors prefer the other route for inbound traffic."
    },
    {
      "id": 69,
      "question": "Which scenario-based question is BEST addressed by configuring MST with multiple instances, each mapping a set of VLANs?",
      "options": [
        "How to unify IP addresses across all core routers",
        "How to reduce the overhead of a separate STP instance for each VLAN",
        "How to filter DHCP offers from rogue servers",
        "How to short-circuit EIGRP queries in large networks"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is routing design, Option B (correct) MST reduces multiple STP processes, Option C is DHCP snooping, Option D is EIGRP stub. MST is specifically for scaling STP in VLAN-rich networks.",
      "examTip": "Multiple Spanning Tree can run fewer STP instances, each controlling multiple VLANs, saving CPU overhead."
    },
    {
      "id": 70,
      "question": "Which direct measure can a switch use to confine unknown devices to a restricted VLAN if 802.1X posture checks fail?",
      "options": [
        "BPDU guard enabling half-duplex",
        "Dynamic VLAN assignment or dACL from the NAC server",
        "Spanning tree root guard for new VLANs",
        "DHCP Option 82 insertion"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is STP security, Option B (correct) NAC solutions can push restricted VLAN or ACL, Option C ensures STP root, Option D is for DHCP info. NAC typically uses 802.1X plus a RADIUS server to dynamically assign quarantined VLANs for non-compliant hosts.",
      "examTip": "NAC posture integrated with 802.1X can quickly reassign VLAN or apply ACL limiting the device’s access until it’s compliant."
    },
    {
      "id": 71,
      "question": "Which type of DNS record is used by domain controllers or other services to advertise host and port details, e.g., _kerberos._tcp?",
      "options": [
        "A",
        "CNAME",
        "SRV",
        "PTR"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A is IPv4 host record, CNAME is an alias, SRV (correct) indicates service location and port, PTR is reverse lookup. SRV records let clients discover services like Kerberos, SIP, etc.",
      "examTip": "SRV records define service-specific data (protocol, port, target host). Commonly used by AD, VoIP, etc."
    },
    {
      "id": 72,
      "question": "Which advanced NAC approach ensures each user port is locked unless the device passes an EAP-based posture check provided by a RADIUS server?",
      "options": [
        "802.1Q trunk negotiation",
        "802.1X with EAP methods enforcing NAC posture",
        "Spanning tree in MST mode",
        "BPDU filter on user ports"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is VLAN trunk config, Option B (correct) is typical NAC posture with 802.1X, Option C is STP design, Option D is bridging device detection. NAC posture commonly uses 802.1X EAP to authenticate and verify compliance before open network access.",
      "examTip": "802.1X NAC remains the standard for per-port authentication and posture checks in wired/wireless enterprise networks."
    },
    {
      "id": 73,
      "question": "Which direct measure ensures a trunk port cannot form automatically with a user device that might support trunk negotiation?",
      "options": [
        "Enable DTP dynamic desirable",
        "Disable DTP by forcing switchport mode access or static trunk with nonegotiate",
        "Use half-duplex to prevent trunk formation",
        "Set DHCP lease time to 1 hour"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A fosters auto trunk, Option B (correct) prevents auto trunk creation, Option C is a mismatch, Option D is IP management. Disabling DTP is key to avoid accidental trunk formation and VLAN hopping risk.",
      "examTip": "On end-user ports, set 'switchport mode access' and 'switchport nonegotiate' so DTP doesn’t inadvertently create a trunk."
    },
    {
      "id": 74,
      "question": "Which statement accurately describes an ABR in OSPF with multiple areas?",
      "options": [
        "It injects external routes from other protocols into OSPF",
        "It requires half-duplex to converge quickly",
        "It connects area 0 to one or more non-backbone areas, holding separate LSDBs for each",
        "It’s always the DR in multi-access segments"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is an ASBR, Option B is a link mismatch, Option C (correct) is the ABR role, Option D is not guaranteed. ABRs have LSDBs for each area they connect, typically bridging area 0 with other areas.",
      "examTip": "Area Border Routers summarize and exchange routes between the backbone area and other OSPF areas."
    },
    {
      "id": 75,
      "question": "Which direct measure specifically addresses large volumes of half-open TCP connections used in SYN flood attacks?",
      "options": [
        "Enabling jumbo frames on the WAN",
        "TCP SYN cookies, dropping incomplete connections from the backlog",
        "Limiting DHCP leases to half-duplex ports",
        "Root guard for bridging loops"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is a frame-size tweak, Option B (correct) is standard protection for SYN floods, Option C is IP config, Option D is STP security. SYN cookies let the server handle huge numbers of SYN requests without exhausting memory by only creating state upon the final ACK.",
      "examTip": "SYN cookies defend against floods by not storing session data until the handshake completes, preventing backlog exhaustion."
    },
    {
      "id": 76,
      "question": "Which NAC feature might place a device that lacks updated AV in a quarantine VLAN with a remediation server?",
      "options": [
        "802.1Q trunk native VLAN",
        "802.1X posture-based VLAN assignment from RADIUS",
        "DHCP relay agent IP helper",
        "CDP auto power negotiation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "802.1Q trunking is for VLAN tagging, DHCP relay is broadcast forwarding, CDP is Cisco discovery. NAC posture typically uses 802.1X plus RADIUS to push a restricted VLAN if posture checks fail. That’s the standard approach for quarantining non-compliant endpoints.",
      "examTip": "NAC with posture checks can place non-compliant endpoints in a dedicated VLAN for updates or scanning."
    },
    {
      "id": 77,
      "question": "Which phenomenon describes forging broadcast DHCP requests to fill a server’s IP pool, leaving legitimate clients without addresses?",
      "options": [
        "MAC flooding",
        "Double-tagging VLAN hopping",
        "DHCP starvation (exhaustion) attack",
        "ARP poisoning"
      ],
      "correctAnswerIndex": 2,
      "explanation": "MAC flooding is for CAM tables, VLAN hopping is for trunk exploits, ARP poisoning for IP-to-MAC forging. DHCP starvation (correct) bombards the DHCP server with fake requests, depleting its pool. Legit users cannot then get leases.",
      "examTip": "DHCP starvation can be mitigated by DHCP snooping or rate-limiting discovery messages from user ports."
    },
    {
      "id": 78,
      "question": "A network admin wants to reduce the overhead of one STP instance per VLAN. Which solution is the standard approach in large multi-VLAN environments?",
      "options": [
        "PVST+",
        "RSTP with half-duplex",
        "MST (Multiple Spanning Tree)",
        "DTP dynamic trunk negotiation"
      ],
      "correctAnswerIndex": 2,
      "explanation": "PVST+ is per VLAN, RSTP speeds convergence but can still be per VLAN, half-duplex is a mismatch, DTP is trunk negotiation. MST is the standard for grouping VLANs into fewer STP instances, lowering CPU usage while maintaining loop avoidance.",
      "examTip": "MST merges VLANs into multiple STP instances, each controlling a set of VLANs. This is more scalable than PVST+ in large VLAN deployments."
    },
    {
      "id": 79,
      "question": "Which NAC scenario-based question is BEST solved by implementing posture checks that verify OS patch levels and antivirus definitions at each new connection?",
      "options": [
        "How to unify VLAN trunking across multiple switches",
        "How to ensure only fully compliant devices get normal access, quarantining risky endpoints",
        "How to reduce the spanning tree diameter",
        "How to forcibly use half-duplex for older clients"
      ],
      "correctAnswerIndex": 1,
      "explanation": "VLAN trunk unification is a separate config, spanning tree diameter is a design, half-duplex is link mismatch. NAC posture ensures devices meet security requirements. Option B (correct) is precisely what posture checks accomplish.",
      "examTip": "NAC posture-based access sees if each endpoint’s OS and AV are up-to-date, quarantining or denying if not."
    },
    {
      "id": 80,
      "question": "Which BGP attribute influences egress path selection inside the same AS, but is propagated to all iBGP neighbors, meaning the entire AS sees the same preference?",
      "options": [
        "Weight",
        "Local Preference",
        "MED",
        "Community no-export"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Weight is local to one router, not shared. MED is typically for inbound suggestions from external neighbors. Community is a tagging mechanism, not a path selection rule. Local Preference (correct) is distributed among iBGP peers, influencing outbound path for the entire AS.",
      "examTip": "Local Preference is used iBGP-wide, so all routers in the AS prefer the path with the highest local_pref."
    },
    {
      "id": 81,
      "question": "Which scenario-based question is BEST resolved by using an SIEM platform that aggregates logs from multiple security devices, correlating them in real time?",
      "options": [
        "How to unify DHCP scopes across subnets",
        "How to physically test cable length behind walls",
        "How to detect advanced or distributed attacks that might not appear suspicious in individual device logs alone",
        "How to run half-duplex on trunk ports for better performance"
      ],
      "correctAnswerIndex": 2,
      "explanation": "SIEM is not about DHCP, cable testing, or half-duplex. A SIEM (correct) collects logs from multiple sources, analyzing them collectively to reveal potential threats that aren’t obvious from a single device’s perspective.",
      "examTip": "Security Information and Event Management solutions unify and correlate logs, providing broader insight into complex or distributed threats."
    },
    {
      "id": 82,
      "question": "A switch port is in err-disabled after detecting multiple MAC addresses. Which single feature triggered the shutdown?",
      "options": [
        "Port security with max MAC limit",
        "Root guard set to half-duplex",
        "BPDU guard on the trunk link",
        "DHCP snooping pass-through"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A large number of MAC addresses typically indicates a hub or bridging device. Port security with a MAC limit is the likely cause of err-disable. Root guard or BPDU guard is for STP frames, DHCP snooping is IP security. That leaves port security as the relevant one.",
      "examTip": "When port security sees more MACs than allowed, it can place the interface in err-disabled for security."
    },
    {
      "id": 83,
      "question": "Which approach can help mitigate microbursts on a switch interface carrying time-sensitive data like VoIP?",
      "options": [
        "Enable QoS LLQ or priority queueing to protect real-time traffic",
        "Assign VLAN 1 as native",
        "Use half-duplex on the interface",
        "Disable DHCP for all endpoints"
      ],
      "correctAnswerIndex": 0,
      "explanation": "LLQ or priority queueing (correct) ensures voice traffic is not dropped when short bursts fill the interface queue. VLAN 1 as native is a best practice issue, half-duplex is performance degrade, disabling DHCP is not relevant. QoS is the key approach for microburst protection.",
      "examTip": "Time-sensitive traffic can be shielded from bursts by giving it priority in a specialized queue."
    },
    {
      "id": 84,
      "question": "Which direct measure can block inbound telnet from the internet but allow internal telnet connections to a router?",
      "options": [
        "ACL: Deny telnet (TCP 23) on the router’s external interface, permit from internal subnets",
        "Enable half-duplex on the outside interface",
        "Assign a static NAT from outside to inside",
        "Allow all inbound management protocols by default"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Applying an ACL to deny external telnet but permit internal is standard. Half-duplex is irrelevant, static NAT is for address translation, and allowing all inbound is insecure. An ACL restricting TCP 23 from external sources but allowing internal subnets solves the scenario.",
      "examTip": "Always limit management protocols (like Telnet or SSH) to known IP ranges. A simple ACL can differentiate inside from outside."
    },
    {
      "id": 85,
      "question": "A distribution switch sees repeated TCN events. Logs reveal a port that transitions from forwarding to blocking frequently. Which FIRST step is recommended?",
      "options": [
        "Set the port to trunk mode dynamic auto",
        "Shut the flapping port and investigate the cable or device",
        "Enable DHCP snooping pass-through",
        "Assign half-duplex for that port"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Flapping ports cause TCN floods. The immediate step is to shut the port or fix the physical link. DHCP snooping and trunk config are unrelated, half-duplex might worsen collisions. Disabling the suspect port helps isolate the issue.",
      "examTip": "Locate the port that’s toggling states. You can temporarily shut it to stabilize STP while diagnosing the cause."
    },
    {
      "id": 86,
      "question": "Which NAC scenario-based question is BEST solved by deploying 802.1X with a RADIUS server that checks OS patch compliance?",
      "options": [
        "How to unify multiple VLAN trunk links",
        "How to physically label switch cables",
        "How to ensure only fully patched endpoints get normal LAN access",
        "How to half-duplex all ports"
      ],
      "correctAnswerIndex": 2,
      "explanation": "VLAN trunk links or cable labeling are separate issues. Half-duplex is irrelevant. NAC posture with 802.1X (correct) checks OS compliance and restricts unpatched devices. That’s the primary scenario NAC addresses.",
      "examTip": "NAC posture ensures each endpoint’s OS patches, AV status, etc. are validated pre-access, common in zero trust implementations."
    },
    {
      "id": 87,
      "question": "Which direct approach on a trunk helps mitigate a double-tagging VLAN hopping exploit?",
      "options": [
        "Enable half-duplex for all trunk ports",
        "Switchport trunk native vlan 1 for default consistency",
        "Set a non-default native VLAN and disable DTP",
        "Disable DHCP snooping"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Option A is a mismatch, Option B is exactly how attackers exploit the default native VLAN, Option C (correct) is the recommended best practice, Option D is IP security for DHCP. Changing the native VLAN from 1 plus disabling auto trunk negotiations stops double-tagging.",
      "examTip": "Double-tagging relies on VLAN 1 as native. Use a dedicated native VLAN and static trunk settings to avert this exploit."
    },
    {
      "id": 88,
      "question": "Which EAP method uses server-side certificates only, forming a secure TLS tunnel, then authenticating the user (e.g., with MSCHAPv2) inside that tunnel?",
      "options": [
        "EAP-TLS",
        "EAP-FAST",
        "PEAP",
        "LEAP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "EAP-TLS requires client/server certs. EAP-FAST uses a PAC. LEAP is older Cisco method. PEAP (correct) uses just a server cert to create a secure tunnel, then user credentials are checked within that encrypted session.",
      "examTip": "PEAP is simpler to deploy than EAP-TLS, as it only needs a server cert. The user credentials pass inside the protected TLS tunnel."
    },
    {
      "id": 89,
      "question": "A load balancer offloads SSL/TLS from backend servers. Which statement is TRUE about this configuration?",
      "options": [
        "It requires half-duplex on the server interfaces",
        "The load balancer terminates SSL from clients and may re-encrypt or pass plaintext to servers, reducing server CPU usage for encryption",
        "SSL offload is only possible if the servers use WEP encryption",
        "It merges multiple VLANs into MST"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Half-duplex is irrelevant. WEP is a wireless standard, not relevant. MST is STP. The LB offloads the encryption overhead (correct), optionally re-encrypting or using plain HTTP behind the scenes. This frees server resources from heavy SSL computations.",
      "examTip": "SSL offload or termination helps servers handle only unencrypted traffic or lighter re-encrypted streams, improving performance."
    },
    {
      "id": 90,
      "question": "Which advanced firewall feature is used when the firewall decrypts HTTPS traffic, inspects it, and re-encrypts it before sending to the destination?",
      "options": [
        "Stateless ACL filtering",
        "SSL/TLS interception or forward proxy",
        "DHCP snooping pass-through",
        "ARP inspection for IP-to-MAC"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is a basic L3 approach, Option B (correct) is the man-in-the-middle approach for deeper inspection, Option C or D handle IP or ARP security. SSL interception enables the firewall to see inside encrypted flows to detect malware or policy violations.",
      "examTip": "NGFWs often do TLS ‘man-in-the-middle’ to examine encrypted traffic for threats. Users must trust the firewall’s CA for no browser warnings."
    },
    {
      "id": 91,
      "question": "Which direct measure on a switch can limit the effect of microbursts for real-time voice traffic?",
      "options": [
        "BPDU guard on user ports",
        "DHCP option 82 insertion",
        "Port security MAC limit",
        "Priority queue or LLQ ensuring voice frames have minimal wait time"
      ],
      "correctAnswerIndex": 3,
      "explanation": "BPDU guard stops bridging loops, DHCP Option 82 is relay info, MAC limit is security. Priority queueing (correct) or LLQ helps voice frames bypass bursts from data traffic. This ensures minimal jitter or packet loss for voice.",
      "examTip": "QoS is crucial for real-time flows. Priority queueing or LLQ keeps time-sensitive packets from being delayed by microbursts."
    },
    {
      "id": 92,
      "question": "A router with iBGP neighbors must prefer one path to exit the AS. Which attribute is used to communicate that preference across all iBGP routers?",
      "options": [
        "Weight",
        "MED",
        "Local Preference",
        "AS-Path Prepending"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Weight is local to one router. MED influences inbound from external neighbors. Local Preference (correct) is shared among iBGP peers. AS-Path Prepending shapes inbound from external. Local_Pref is the standard outbound path selection attribute inside an AS.",
      "examTip": "Local_Pref is an iBGP-wide attribute. The higher the local_pref, the more preferred that route for egress from your AS."
    },
    {
      "id": 93,
      "question": "Which advanced NAC approach integrates 802.1X EAP authentication with posture checks, letting RADIUS dynamically assign a quarantine VLAN if the device fails?",
      "options": [
        "DHCP snooping table-based VLAN assignment",
        "SNMPv3 dynamic community strings",
        "802.1X with a NAC server returning VLAN or dACL instructions",
        "Spanning tree in PVST+ mode"
      ],
      "correctAnswerIndex": 2,
      "explanation": "DHCP snooping is IP assignment security, SNMPv3 is management, STP is loop prevention. NAC solutions typically rely on 802.1X plus a RADIUS NAC server to apply a restricted VLAN or dACL upon failed posture. That’s the standard approach to isolate non-compliant endpoints.",
      "examTip": "NAC posture checks with 802.1X often push VLAN or ACL from RADIUS, controlling access level based on compliance."
    },
    {
      "id": 94,
      "question": "Which trunk encapsulation is recommended for multi-vendor switches, allowing VLAN tags to pass between different brands of equipment?",
      "options": [
        "ISL",
        "802.1Q",
        "DTP dynamic desirable",
        "CDP trunk bridging"
      ],
      "correctAnswerIndex": 1,
      "explanation": "ISL is Cisco proprietary, DTP is trunk negotiation, CDP is discovery. 802.1Q (correct) is the IEEE standard for VLAN tagging across vendors. This ensures interoperability between different switch brands.",
      "examTip": "802.1Q is universal; ensure both ends are configured for 802.1Q trunk mode to avoid mismatches in multi-vendor environments."
    },
    {
      "id": 95,
      "question": "Which configuration helps an EIGRP router advertise a default route to neighbors if it already has a static 0.0.0.0/0 pointing to the internet?",
      "options": [
        "network 0.0.0.0 0.0.0.0 under EIGRP",
        "router eigrp 100\n default-information originate always",
        "redistribute static metric 1 1 1 1 1 or specify a route-map referencing 0.0.0.0/0",
        "Enable half-duplex on the WAN port"
      ],
      "correctAnswerIndex": 2,
      "explanation": "EIGRP doesn’t use default-information originate like OSPF. ‘network 0.0.0.0’ doesn’t automatically handle default routes. The typical solution is to redistribute the static default route with an assigned metric or route-map. That’s the correct approach. Half-duplex is irrelevant.",
      "examTip": "In EIGRP, the normal method to inject default is ‘redistribute static’ referencing the 0.0.0.0/0 route, setting an appropriate metric."
    },
    {
      "id": 96,
      "question": "Which advanced firewall feature identifies applications at layer 7 so it can enforce policies even if they run on common ports like 443 or 80?",
      "options": [
        "Stateful packet inspection only at layer 4",
        "Application-awareness with deep packet inspection (DPI)",
        "CDP discovery for neighbor devices",
        "DHCP snooping pass-through"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is standard L4-based stateful, Option B (correct) next-gen firewalls do DPI up to L7, Option C is Cisco device discovery, Option D is DHCP IP security. App-aware inspection sees beyond ports, applying content-based policies.",
      "examTip": "NGFW uses layer 7 inspection or ‘app awareness’ to differentiate streaming, file sharing, or web apps all running on common ports."
    },
    {
      "id": 97,
      "question": "Which BGP attribute is specifically used to suggest an ingress path to neighbors by letting you set a numerical value that your neighbors compare when choosing how to enter your AS?",
      "options": [
        "Community local-AS",
        "MED (Multi-Exit Discriminator)",
        "Local Preference",
        "Weight"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is a community controlling route scope, Option B (correct) is the inbound influencer, Option C is an outbound influencer inside your AS, Option D is local to one router. MED is the official attribute for inbound path preference, if neighbors honor it.",
      "examTip": "You set a lower MED to prefer a particular entry into your AS. But not all providers will accept or use your MED value."
    },
    {
      "id": 98,
      "question": "Which zero trust principle is exemplified by micro-segmentation of internal networks, requiring device posture checks and user authentication for each resource request?",
      "options": [
        "Implicit trust once behind the firewall",
        "Passive monitoring with no enforcement",
        "Continuous verification of identity and minimal lateral access",
        "Collapsing all VLANs into a single subnet"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Zero trust denies implicit trust, not passive or single-subnet. Option C (correct) is the hallmark of zero trust. Micro-segmentation plus continuous re-validation ensures minimal lateral movement for potential attackers.",
      "examTip": "Zero trust requires “never trust, always verify,” restricting each user or device to only the specific resources they need."
    },
    {
      "id": 99,
      "question": "A trunk mismatch is suspected because VLAN 40 traffic isn’t passing. Which single step is recommended FIRST?",
      "options": [
        "Check ‘show interface trunk’ to see if VLAN 40 is in the allowed list on each side",
        "Change the trunk to half-duplex",
        "Enable DHCP Option 82 insertion",
        "Disable STP for VLAN 40"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Half-duplex is a mismatch, Option C is DHCP, Option D is risky. Checking the trunk configuration with ‘show interface trunk’ (correct) reveals allowed VLANs, trunk encapsulation, and native VLAN settings. That’s the prime check for missing VLAN traffic.",
      "examTip": "Always verify trunk’s allowed VLAN list if traffic for a specific VLAN is missing across a trunk."
    },
    {
      "id": 100,
      "question": "Which method do advanced NAC solutions often use for dynamic enforcement if an endpoint fails posture checks?",
      "options": [
        "Root guard forcing the port to remain blocking",
        "802.1X-based VLAN or downloadable ACL assignment from the RADIUS server",
        "Half-duplex bridging to limit collisions",
        "Spanning tree fallback in MST mode"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Option A is STP security, Option B (correct) NAC uses 802.1X and RADIUS to place endpoints in quarantine or dACL. Option C is a mismatch, Option D is STP. NAC posture check + RADIUS instructions is standard for dynamic VLAN or ACL assignment based on compliance.",
      "examTip": "Endpoints that fail NAC posture can be assigned a restricted VLAN or ACL from the NAC server, allowing only remediation servers."
    }
  ]
});
