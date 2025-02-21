{
  "category": "nplus",
  "testId": 8,
  "testName": "Network Practice Test #8 (Very Challenging)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "In a large OSPF network with multiple areas, which LSA type is used by ABRs to advertise summary routes into other areas?",
      "options": [
        "Type 1 ",
        "Type 2 ",
        "Type 3 ",
        "Type 5 "
      ],
      "correctAnswerIndex": 2,
      "explanation": "Autonomous System Boundary Router (ASBR) represents the local router’s links. Type 2 LSA is used by DRs to describe multi-access networks. Type 3 LSA (correct) is a summary LSA used by ABRs to distribute inter-area routes. Type 5 LSA advertises external networks from the ASBR.",
      "examTip": "OSPF Type 3 LSAs come from area border routers to propagate routes between areas."
    },
    {
      "id": 2,
      "question": "Which critical step is required when configuring an 802.1X port in multi-auth mode to allow both a VoIP phone and a PC on the same switch port?",
      "options": [
        "Assign half-duplex on the port for two devices",
        "Enable voice VLAN trunking with DTP",
        "Allow separate authentication sessions for each MAC address",
        "Disable BPDU Guard globally"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Assign half-duplex on the port for two devices is a performance limitation. Enable voice VLAN trunking with DTP is trunk negotiation, not multi-auth. Allow separate authentication sessions for each MAC address (correct) multi-auth mode ensures both the phone’s MAC and the PC’s MAC can authenticate individually. Disable BPDU Guard globally is an STP security feature, irrelevant to 802.1X multi-auth.",
      "examTip": "802.1X multi-auth or multi-domain allows separate authentication for phone and PC, each receiving appropriate VLAN/policy."
    },
    {
      "id": 3,
      "question": "A newly added IPv6-only server must communicate with legacy IPv4-only systems. Which approach eliminates the need to dual-stack the server?",
      "options": [
        "DHCPv6 prefix delegation",
        "NAT64 translation at the network edge",
        "ISATAP tunneling on each IPv4 host",
        "Abandon IPv6 and use static IPv4"
      ],
      "correctAnswerIndex": 1,
      "explanation": "DHCPv6 prefix delegation is address delegation, not bridging IPv4. NAT64 translation at the network edge (correct) converts IPv6 traffic into IPv4. ISATAP tunneling on each IPv4 host places the tunnel on IPv6 hosts, but here the server is IPv6-only. Abandon IPv6 and use static IPv4 defeats IPv6 usage. NAT64 is the standard solution for IPv6-only to reach IPv4 resources.",
      "examTip": "NAT64 sits at the boundary, allowing IPv6-only hosts to interact with IPv4-only endpoints without dual-stacking."
    },
    {
      "id": 4,
      "question": "A router running BGP receives two routes for the same prefix: one with AS-Path length 3 and Local Pref 200, the other with AS-Path length 2 and Local Pref 100. Which route is preferred?",
      "options": [
        "The route with the shorter AS-Path",
        "They load balance equally since both are external routes",
        "The route with the higher Local Preference",
        "BGP always picks the one learned first"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The route with the shorter AS-Path is lower in the hierarchy. They load balance equally since both are external routes is not default. The route with the higher Local Preference (correct) with Local Pref 200 outranks 100. BGP always picks the one learned first is incorrect unless all else is tied.",
      "examTip": "BGP decision order: Weight > Local Pref > Origination > AS-Path length > MED, etc. Higher Local Pref wins if they differ."
    },
    {
      "id": 5,
      "question": "Which statement about zero trust networking is TRUE?",
      "options": [
        "It trusts any device with a corporate IP address implicitly",
        "It segments networks heavily and continuously revalidates each access request",
        "It requires a single flat VLAN for simplicity",
        "It relies on half-duplex links to prevent eavesdropping"
      ],
      "correctAnswerIndex": 1,
      "explanation": "It trusts any device with a corporate IP address implicitly is the opposite of zero trust. It segments networks heavily and continuously revalidates each access request (correct) demands tight segmentation and ongoing authentication checks. It requires a single flat VLAN for simplicity lumps devices, contrary to zero trust. It relies on half-duplex links to prevent eavesdropping is unrelated. Zero trust enforces minimal inherent trust, rechecking identity regularly.",
      "examTip": "Zero trust models assume no automatic trust, even on ‘internal’ networks, requiring repeated user/device posture validation."
    },
    {
      "id": 6,
      "question": "A user’s VLAN traffic is unable to traverse a trunk. Checking ‘show interface trunk’ reveals VLAN 30 is not in the ‘allowed VLANs’ list. Which single CLI command on Cisco typically resolves this?",
      "options": [
        "switchport trunk native vlan 30",
        "switchport trunk allowed vlan add 30",
        "show running-config trunk",
        "vlan 30 router-interface"
      ],
      "correctAnswerIndex": 1,
      "explanation": "switchport trunk native vlan 30 changes the native VLAN, not the allowed list. switchport trunk allowed vlan add 30 (correct) explicitly adds VLAN 30 to the trunk. show running-config trunk just shows the config, vlan 30 router-interface is not the correct syntax. Allowing VLAN 30 on the trunk is key.",
      "examTip": "If a VLAN is absent from the trunk, use ‘switchport trunk allowed vlan add <X>’ on both ends to restore it."
    },
    {
      "id": 7,
      "question": "Which advanced QoS approach allows strict priority queuing for voice but also supports weighted fair scheduling among other traffic classes?",
      "options": [
        "WRED ",
        "WFQ ",
        "LLQ ",
        "RED "
      ],
      "correctAnswerIndex": 2,
      "explanation": "WRED and RED are congestion avoidance strategies. WFQ is basic round-robin. LLQ (Low Latency Queueing) (correct) is WFQ plus a strict priority queue. This suits real-time traffic like VoIP.",
      "examTip": "LLQ merges a strict priority queue for voice and real-time traffic plus weighted scheduling for other classes."
    },
    {
      "id": 8,
      "question": "A network uses a dedicated VLAN for IP phones. Which reason BEST explains why voice traffic is segregated from data traffic?",
      "options": [
        "DHCP cannot hand out addresses for more than one subnet",
        "Phones require half-duplex mode",
        "It allows applying specialized QoS policies and security rules more easily",
        "Voice VLAN is mandatory for spanning tree"
      ],
      "correctAnswerIndex": 2,
      "explanation": "DHCP cannot hand out addresses for more than one subnet is untrue, DHCP can handle multiple scopes. Phones require half-duplex mode is outdated. It allows applying specialized QoS policies and security rules more easily (correct) segregating voice aids QoS and security. Voice VLAN is mandatory for spanning tree is not an STP requirement. Having a voice VLAN simplifies management and ensures priority for calls.",
      "examTip": "Separating voice on its own VLAN is a standard best practice for QoS, troubleshooting, and security."
    },
    {
      "id": 9,
      "question": "Which trunking protocol was proprietary to Cisco and has largely been superseded by IEEE 802.1Q?",
      "options": [
        "ISL ",
        "CDP ",
        "VTP ",
        "LACP "
      ],
      "correctAnswerIndex": 0,
      "explanation": "ISL (correct) is Cisco’s older VLAN encapsulation. CDP is device discovery, VTP automates VLAN info distribution, LACP aggregates ports. ISL is mostly replaced by the open standard 802.1Q.",
      "examTip": "Modern switches typically use 802.1Q; ISL is legacy and rarely found on current devices."
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
      "explanation": "Weight (correct) is Cisco-proprietary and local to the router. Local Preference is second used throughout the AS, AS Path length is for external route selection. Origin type is a lesser priority attribute. Weight is the top priority in Cisco’s BGP selection, but not propagated outside.",
      "examTip": "BGP decision process on Cisco: Weight > Local Preference > Origination (local) > AS-Path length > etc."
    },
    {
      "id": 11,
      "question": "A spanning tree domain has many TCN (Topology Change Notification) events. Which is the FIRST cause to investigate?",
      "options": [
        "DHCP scope is too small",
        "A port flapping up/down, triggering STP recalculations",
        "Collision domain mismatches on trunk ports",
        "Trunking mode is set to dynamic desirable"
      ],
      "correctAnswerIndex": 1,
      "explanation": "DHCP scope is too small is IP addressing, not related to STP. A port flapping up/down, triggering STP recalculations (correct) physical link instability often triggers TCNs. Collision domain mismatches on trunk ports is a half-duplex error possibility but not always TCN, Trunking mode is set to dynamic desirable can cause trunk mismatch but not necessarily TCN floods. Flapping ports typically cause topology changes in STP.",
      "examTip": "Frequent STP TCN usually indicates a port constantly changing state; fix the physical or link mismatch first."
    },
    {
      "id": 12,
      "question": "Which approach helps detect an intruder capturing network packets on a compromised switch port?",
      "options": [
        "BPDU filter",
        "DHCP snooping",
        "Dynamic ARP Inspection",
        "Port mirroring"
      ],
      "correctAnswerIndex": 3,
      "explanation": "BPDU filter is about spanning tree BPDUs, DHCP snooping is DHCP security, Dynamic ARP Inspection is ARP security, Port mirroring (correct) duplicates traffic from one port to another for inspection. Port mirroring, also known as SPAN, is used for network monitoring and security analysis.",
      "examTip": "Port mirroring copies traffic to a designated monitoring port, allowing tools to capture and analyze packets."
    },
    {
      "id": 13,
      "question": "A switch port is in err-disabled state after detecting multiple MAC addresses. Which single feature triggered this?",
      "options": [
        "Dynamic ARP Inspection",
        "Port security MAC limit",
        "CDP neighbor mismatch",
        "DHCP snooping conflict"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Dynamic ARP Inspection checks ARP authenticity, Port security MAC limit (correct) restricts MAC addresses, shutting the port if exceeded, CDP neighbor mismatch is device discovery, DHCP snooping conflict deals with IP assignment. Port security commonly places a port in err-disable on policy violations.",
      "examTip": "Port security with a low MAC limit is useful for preventing hubs or unauthorized devices on an access port."
    },
    {
      "id": 14,
      "question": "Which device or feature is used to unify threat prevention in a single on-prem appliance?",
      "options": [
        "CDP neighbor switch",
        "RADIUS server",
        "UTM box",
        "DHCP relay router"
      ],
      "correctAnswerIndex": 2,
      "explanation": "CDP neighbor switch is device discovery, RADIUS server is authentication, UTM box (correct) merges multiple security functions, DHCP relay router forwards DHCP requests. UTM appliances are all-in-one security solutions often deployed at the network edge in smaller environments.",
      "examTip": "UTM devices combine firewalling, IPS, URL filtering, and sometimes VPN into a single box."
    },
    {
      "id": 15,
      "question": "Which EAP type requires only a server-side certificate, creating a TLS tunnel for user authentication inside that tunnel?",
      "options": [
        "EAP-TLS",
        "EAP-FAST",
        "PEAP",
        "LEAP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "EAP-TLS requires both client/server certs. EAP-FAST is a Cisco approach with a Protected Access Credential. PEAP (correct) Protected EAP uses a server cert to create a secure tunnel, and user credentials are validated inside. LEAP is old, less secure. PEAP is widely used in enterprise Wi-Fi.",
      "examTip": "PEAP requires only a server certificate, whereas EAP-TLS requires both client and server certificates for mutual authentication."
    },
    {
      "id": 16,
      "question": "Which approach helps contain malware if an HR department subnet is compromised?",
      "options": [
        "Use a single VLAN for the entire building",
        "Implement NAC posture checks only for wireless guests",
        "Apply ACLs or a firewall between internal VLANs, limiting lateral movement",
        "Assign half-duplex to HR ports"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Use a single VLAN for the entire building lumps all devices, risking wider infection. Implement NAC posture checks only for wireless guests is partial coverage, not addressing wired LAN. Apply ACLs or a firewall between internal VLANs, limiting lateral movement (correct) secures boundaries so the infection can’t spread easily, Assign half-duplex to HR ports is a link mismatch and ineffective for security. Inter-VLAN ACL or micro-segmentation is essential to contain internal threats.",
      "examTip": "Securing internal segments with ACLs or micro-segmentation greatly reduces a breach’s impact by limiting lateral spread."
    },
    {
      "id": 17,
      "question": "A new IPv6 host attempts to auto-configure its address. Which protocol provides the default gateway address without a DHCPv6 server in SLAAC mode?",
      "options": [
        "NDP Router Advertisement",
        "ARP broadcast",
        "DHCPv6 prefix delegation",
        "IGMP membership"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NDP Router Advertisement (correct) NDP RA messages supply the router’s link-local address as a default gateway. ARP broadcast is IPv4 ARP, DHCPv6 prefix delegation is DHCP-based, IGMP membership is multicast group membership. SLAAC uses Router Advertisements for address prefix and gateway info.",
      "examTip": "IPv6 hosts can learn prefix and default router from NDP RAs, often no DHCPv6 required in SLAAC scenarios."
    },
    {
      "id": 18,
      "question": "Which event triggers an STP TCN?",
      "options": [
        "A user logs into the switch via SSH",
        "A port transitions between blocking and forwarding states",
        "DHCP lease expires for a subnet",
        "Root guard is explicitly disabled on the root bridge"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A user logs into the switch via SSH is management, not STP related. A port transitions between blocking and forwarding states (correct) port state changes prompt TCN. DHCP lease expires for a subnet is IP addressing, not related to STP. Root guard is explicitly disabled on the root bridge is a separate STP security measure. Changes in STP port states cause the switch to send TCNs up the STP tree.",
      "examTip": "Port transitions (up/down or blocking/forwarding) are typical triggers for TCN broadcasts."
    },
    {
      "id": 19,
      "question": "Which concept ensures SD-WAN can use multiple link types under a unified policy engine?",
      "options": [
        "Link aggregation via LACP",
        "Zero trust NAC posture checks",
        "Transport agnosticism with centralized orchestration",
        "802.1ad QinQ trunking"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Link aggregation via LACP is local bundling, Zero trust NAC posture checks is security posture, Transport agnosticism with centralized orchestration (correct) SD-WAN solutions treat any IP-based transport similarly, managed by a central controller. 802.1ad QinQ trunking is stacking VLAN tags. Transport-agnostic design is a key SD-WAN feature.",
      "examTip": "SD-WAN solutions orchestrate multiple WAN transports (MPLS, Internet, 4G, etc.) with centralized policy, unaffected by link type."
    },
    {
      "id": 20,
      "question": "Which advanced NAC capability allows a dynamic ACL to be downloaded from the RADIUS server, customizing access for each authenticated user or device?",
      "options": [
        "DHCP Option 82 insertion",
        "Downloadable ACL or dACL",
        "Port security sticky MAC",
        "LLDP MED classification"
      ],
      "correctAnswerIndex": 1,
      "explanation": "DHCP Option 82 insertion is DHCP info, not NAC function. Downloadable ACL or dACL (correct) NAC solutions can push a per-user ACL from RADIUS. Port security sticky MAC is MAC-limiting, LLDP MED classification is for VoIP config. Downloadable ACLs let the server specify policy at authentication time.",
      "examTip": "Some NAC solutions support dynamic, user-specific ACLs from the RADIUS server, refining per-session security."
    },
    {
      "id": 21,
      "question": "Which configuration on a Cisco router displays real-time QoS policy hits, showing if DSCP markings are matched properly?",
      "options": [
        "show policy-map control-plane",
        "show ip interface brief",
        "show policy-map interface <if>",
        "show mac address-table"
      ],
      "correctAnswerIndex": 2,
      "explanation": "show policy-map control-plane examines the control plane policy, show ip interface brief is basic IP info, show policy-map interface <if> (correct) reveals QoS statistics for that interface, show mac address-table is a layer 2 map. 'show policy-map interface' tracks class-based QoS hits, queue usage, and DSCP matches.",
      "examTip": "For Cisco QoS (MQC), 'show policy-map interface <if>' displays real-time stats and classification hits."
    },
    {
      "id": 22,
      "question": "A distribution switch receives BPDUs from a user port. Which feature is BEST to protect STP from malicious or accidental bridging devices on that port?",
      "options": [
        "IP helper address",
        "BPDU guard",
        "Dynamic trunk negotiation",
        "DHCP snooping"
      ],
      "correctAnswerIndex": 1,
      "explanation": "IP helper address is DHCP relay, not related to STP security. BPDU guard (correct) shuts the port if BPDUs are received on an edge port. Dynamic trunk negotiation can create trunks automatically, not related to STP protection on user ports. DHCP snooping is DHCP security, not STP protection. BPDU guard prevents unexpected STP participation from an end-user port.",
      "examTip": "BPDU guard disables any port receiving BPDUs that’s configured as an edge or access port, blocking loops."
    },
    {
      "id": 23,
      "question": "Which EIGRP feature helps reduce query scope by designating certain routers as stubs that do not forward queries beyond themselves?",
      "options": [
        "Stub routing",
        "Split horizon",
        "Auto-summary",
        "Manual summarization"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Stub routing (correct) EIGRP stub routers limit queries. Split horizon is a distance-vector routing concept, Auto-summary is older summarization approach, Manual summarization is configuring summary addresses on an interface for precise aggregation. EIGRP stub reduces query range in large topologies.",
      "examTip": "Marking a router as 'stub' in EIGRP prevents it from propagating queries, thus containing the query domain."
    },
    {
      "id": 24,
      "question": "Which key step is required when configuring a layer 3 EtherChannel between two switches for inter-VLAN routing?",
      "options": [
        "Set the channel-group as ‘mode dynamic auto’ on each port",
        "Assign an IP address to the port-channel interface instead of subinterfaces",
        "Use half-duplex to prevent collisions",
        "Disable VLAN trunking protocol on all ports"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Set the channel-group as ‘mode dynamic auto’ on each port is typical for L2 trunking, not L3. Assign an IP address to the port-channel interface instead of subinterfaces (correct) layer 3 channels use a single IP on the port-channel interface. Use half-duplex to prevent collisions is a mismatch. Disable VLAN trunking protocol on all ports might not be strictly needed. For L3 EtherChannel, the port-channel acts as a routed interface with an IP.",
      "examTip": "In L3 EtherChannel, no VLAN subinterfaces are used. The aggregated channel interface gets the IP address for inter-VLAN routing."
    },
    {
      "id": 25,
      "question": "A site runs BGP to two ISPs with partial routes. Which attribute is recommended for controlling outbound path selection within the local AS?",
      "options": [
        "Local Preference",
        "MED",
        "Origin code",
        "AS-Path Prepending"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MED is typically inbound influencer. Local Preference (correct) is used by iBGP routers to prefer one path over another. Weight is a Cisco-proprietary attribute, considered before local_pref but only relevant on that local router. Community is for tagging. Within the AS, local_pref is widely used to control outbound path preference.",
      "examTip": "Local Preference is the main way to influence egress route selection in your own AS, with a higher value favored."
    },
    {
      "id": 26,
      "question": "Which statement accurately describes route reflectors in iBGP deployments?",
      "options": [
        "They are required to run in an external BGP session only",
        "They reflect learned routes from one iBGP peer to another, reducing the need for a full mesh",
        "They must have half-duplex links to reduce loops",
        "They can only reflect default routes"
      ],
      "correctAnswerIndex": 1,
      "explanation": "They are required to run in an external BGP session only is eBGP, not iBGP. They reflect learned routes from one iBGP peer to another, reducing the need for a full mesh (correct) route reflectors pass iBGP routes to other iBGP peers, removing the requirement for a full mesh. They must have half-duplex links to reduce loops is a link mismatch, They can only reflect default routes is false. Route reflectors simplify iBGP scalability.",
      "examTip": "A route reflector modifies the normal iBGP rule that iBGP updates must not be forwarded to other iBGP peers, reducing mesh complexity."
    },
    {
      "id": 27,
      "question": "Which trunk attribute is MOST important to verify if VLAN traffic is not passing between two Cisco switches?",
      "options": [
        "Allowed VLAN list",
        "SNMP community string",
        "Spanning tree root ID",
        "Syslog server IP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Allowed VLAN list (correct) if the VLAN is not in the trunk’s allowed list, it’s blocked. SNMP community string is for device management, Spanning tree root ID is STP detail, Syslog server IP is logging. Ensuring each trunk includes the relevant VLANs is crucial for layer 2 connectivity.",
      "examTip": "Always check if the VLAN is explicitly allowed on the trunk. If not, you won’t see that VLAN traffic crossing the trunk."
    },
    {
      "id": 28,
      "question": "In an MPLS-based service provider network, which label distribution protocol might be used to assign and distribute labels between LSRs?",
      "options": [
        "OSPF for MPLS TE",
        "LDP ",
        "BGP communities only",
        "CDP for label negotiation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "OSPF for MPLS TE is an IGP with TE extensions, but not primarily for basic label distribution. LDP (correct) Label Distribution Protocol sets up labels. BGP communities only is BGP metadata, not label distribution. CDP for label negotiation is Cisco Discovery Protocol, not for MPLS labels. LDP is the standard protocol for exchanging MPLS labels in many deployments.",
      "examTip": "MPLS typically uses LDP or RSVP-TE to distribute labels among label switching routers in the provider core."
    },
    {
      "id": 29,
      "question": "Which is BEST addressed by implementing a captive portal on the guest wireless SSID?",
      "options": [
        "connect multiple VLANs via trunking",
        "require guests to accept terms of use before granting internet access",
        "reduce STP topology changes",
        "unify IP addresses for all subnets"
      ],
      "correctAnswerIndex": 1,
      "explanation": "connect multiple VLANs via trunking is VLAN design, not captive portal function. require guests to accept terms of use before granting internet access (correct) typical captive portal usage. reduce STP topology changes is loop prevention, unify IP addresses for all subnets is IP design. Captive portals present a splash page or login for guests before letting them access external networks.",
      "examTip": "Guest Wi-Fi often uses a captive portal to display usage policies or login screens to unsecured users."
    },
    {
      "id": 30,
      "question": "Which measure can block inbound SSH attempts from unknown external IPs on a next-generation firewall?",
      "options": [
        "Disable Telnet globally",
        "Port mirroring the SSH traffic to an analyzer",
        "Creating a policy rule allowing SSH only from known management subnets",
        "Turning off DHCP on the WAN interface"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Disable Telnet globally is a different protocol, not SSH. Port mirroring the SSH traffic to an analyzer is monitoring, not blocking. Creating a policy rule allowing SSH only from known management subnets (correct) restricts SSH to a trusted source, Turning off DHCP on the WAN interface is IP config, not firewall rules. Firewalls commonly use ACL/policy to limit management protocols from specific IP ranges.",
      "examTip": "Limit inbound SSH to designated IP ranges or a VPN. Default open SSH is a big attack vector."
    },
    {
      "id": 31,
      "question": "Which main advantage does EAP-TLS have over PEAP in a large enterprise deploying dot1x 802.1X?",
      "options": [
        "EAP-TLS requires no certificates on either side",
        "EAP-TLS offers mutual certificate-based authentication, providing strongest security",
        "PEAP only works on half-duplex ports",
        "PEAP is not supported on any Windows devices"
      ],
      "correctAnswerIndex": 1,
      "explanation": "EAP-TLS requires no certificates on either side is false, EAP-TLS needs both sides to have certs. EAP-TLS offers mutual certificate-based authentication, providing strongest security (correct) is a stronger mutual approach, PEAP only works on half-duplex ports is irrelevant, PEAP is not supported on any Windows devices is incorrect. EAP-TLS uses client/server certs, ensuring robust mutual authentication.",
      "examTip": "EAP-TLS is considered very secure but requires PKI on both client and server, while PEAP only requires a server cert."
    },
    {
      "id": 32,
      "question": "A router running OSPF must also inject RIP-learned routes into the OSPF domain. Which approach accomplishes this if the router already has a static default route?",
      "options": [
        "redistribute static metric 1 1 1 1 1",
        "network 0.0.0.0 0.0.0.0 under EIGRP",
        "Set half-duplex to propagate default",
        "Enable DHCP relay with IP helper"
      ],
      "correctAnswerIndex": 0,
      "explanation": "redistribute static metric 1 1 1 1 1 (correct) redistributes a static route into EIGRP with an assigned metric. network 0.0.0.0 0.0.0.0 under EIGRP doesn’t work in EIGRP for default route advertisement. Set half-duplex to propagate default is a link mismatch, Enable DHCP relay with IP helper is for forwarding DHCP broadcasts. In EIGRP, you typically redistribute a static 0.0.0.0/0 route.",
      "examTip": "Redistribute a static default route into EIGRP with an appropriate metric so downstream routers learn 0.0.0.0/0."
    },
    {
      "id": 33,
      "question": "An ISP uses route reflectors in iBGP. Which is the PRIMARY advantage of this design?",
      "options": [
        "Avoids the need for a full iBGP mesh among all routers",
        "Permits half-duplex links to reduce collisions",
        "Eliminates the need for any eBGP sessions",
        "Improves root guard function in spanning tree"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Avoids the need for a full iBGP mesh among all routers (correct) route reflectors forward routes to iBGP peers, removing the requirement for every router to peer with every other. Permits half-duplex links to reduce collisions is a link mismatch, Eliminates the need for any eBGP sessions is about external peering, Improves root guard function in spanning tree is STP. Route reflectors simplify iBGP scalability.",
      "examTip": "A route reflector modifies the normal iBGP rule that iBGP updates must not be forwarded to other iBGP peers, reducing mesh complexity."
    },
    {
      "id": 34,
      "question": "Which type of DNS record is used to identify an email server for a given domain?",
      "options": [
        "TXT",
        "MX",
        "CNAME",
        "NS"
      ],
      "correctAnswerIndex": 1,
      "explanation": "TXT is free-form text, MX (correct) mail exchange record, CNAME is an alias, NS indicates a nameserver. MX records designate mail servers responsible for a domain.",
      "examTip": "Mail Exchange (MX) records route email to the correct server. Ensure priority values are correct if multiple MXs exist."
    },
    {
      "id": 35,
      "question": "Which EAP variation uses a secure tunnel established via server cert, then authenticates client credentials with a Protected Access Credential (PAC)?",
      "options": [
        "EAP-FAST",
        "EAP-TLS",
        "PEAPv0/EAP-MSCHAPv2",
        "LEAP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "EAP-FAST (correct) EAP-Flexible Authentication via Secure Tunneling relies on a PAC. EAP-TLS uses mutual certs. PEAPv0/EAP-MSCHAPv2 uses a server cert only, not a PAC. LEAP is older Cisco method. EAP-FAST uses a PAC to authenticate clients securely.",
      "examTip": "EAP-FAST can provide a dynamic TLS tunnel using a PAC, a secure credential distributed beforehand or via provisioning."
    },
    {
      "id": 36,
      "question": "Which step is MOST helpful if frequent microbursts cause packet drops on a switch interface used by latency-sensitive apps?",
      "options": [
        "Deploy a Wi-Fi analyzer to check overlapping channels",
        "Enable port security with 1 MAC limit",
        "Implement QoS buffering or shaping on that interface",
        "Disable CDP globally"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Deploy a Wi-Fi analyzer to check overlapping channels is a wireless tool, not relevant to wired microbursts. Enable port security with 1 MAC limit is a security setting, not QoS. Implement QoS buffering or shaping on that interface (correct) helps handle short bursts by queueing or shaping. Disable CDP globally is device discovery protocol, not related to QoS. QoS can buffer microbursts or shape traffic to reduce instantaneous congestion.",
      "examTip": "Short traffic spikes can fill port queues quickly. QoS shaping or queue tuning can mitigate microburst drop issues."
    },
    {
      "id": 37,
      "question": "Which trunking method does Cisco recommend for multi-vendor interoperability?",
      "options": [
        "DTP dynamic auto negotiation",
        "ISL trunking",
        "802.1Q standard tagging",
        "CDP-based VLAN distribution"
      ],
      "correctAnswerIndex": 2,
      "explanation": "DTP dynamic auto negotiation is Cisco-specific dynamic trunk protocol, ISL trunking is old Cisco-proprietary, 802.1Q standard tagging (correct) is the IEEE standard, CDP-based VLAN distribution is a discovery protocol. 802.1Q is the open trunking standard used universally.",
      "examTip": "ISL was Cisco proprietary. 802.1Q is the recognized trunk standard for VLAN tagging across multi-vendor devices."
    },
    {
      "id": 38,
      "question": "In OSPF, how does a stub area differ from a totally stubby area?",
      "options": [
        "Stub areas disallow external LSAs but allow inter-area LSAs, whereas totally stubby also blocks inter-area routes, injecting only a default route",
        "Stub areas can’t contain an ABR, whereas totally stubby can",
        "They differ only in half-duplex operation",
        "Totally stubby is the same as an NSSA"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Stub areas disallow external LSAs but allow inter-area LSAs, whereas totally stubby also blocks inter-area routes, injecting only a default route (correct) stub areas block Type-5 external LSAs but permit Type-3 inter-area LSAs. Totally stubby blocks both Type-5 and Type-3, allowing only a default route. Stub areas can’t contain an ABR, whereas totally stubby can is incorrect. They differ only in half-duplex operation is irrelevant, Totally stubby is the same as an NSSA is a different area type. The difference is the handling of Type-3 LSAs.",
      "examTip": "Stub areas block external routes, while totally stubby also blocks inter-area routes, except a default route from the ABR."
    },
    {
      "id": 39,
      "question": "Which NAC posture check ensures an endpoint meets corporate policy before granting full access?",
      "options": [
        "Verifying cables are no more than 100 meters",
        "Checking if the endpoint runs updated AV and patches",
        "Applying half-duplex for all user devices",
        "Assigning a static IP on each interface"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Verifying cables are no more than 100 meters is a cabling limit, not posture. Checking if the endpoint runs updated AV and patches (correct) standard NAC posture check. Applying half-duplex for all user devices is a performance detriment, Assigning a static IP on each interface is IP config, not posture. NAC typically checks antivirus, OS patches, firewall status, etc., ensuring compliance.",
      "examTip": "NAC posture means verifying device health—OS patches, AV signatures, etc.—before allowing them on the network."
    },
    {
      "id": 40,
      "question": "Which VLAN security practice helps mitigate double-tagging attacks, where an attacker tries to insert two VLAN tags on frames?",
      "options": [
        "Use VLAN 1 as the native VLAN on all trunks",
        "Enable half-duplex for trunk ports",
        "Configure a non-default native VLAN and disable trunk negotiation",
        "Allow all VLANs on the trunk for maximum coverage"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Use VLAN 1 as the native VLAN on all trunks is risky, vulnerable to VLAN hopping. Enable half-duplex for trunk ports is a performance degrade, not security. Configure a non-default native VLAN and disable trunk negotiation (correct) blocks double-tag exploits, Allow all VLANs on the trunk for maximum coverage is broad trunk config and insecure. Setting a dedicated native VLAN and turning off DTP are standard countermeasures.",
      "examTip": "Double-tagging relies on VLAN 1. Always define a separate native VLAN and static trunk mode to thwart it."
    },
    {
      "id": 41,
      "question": "A distribution switch experiences high CPU usage from repeated route updates. OSPF logs show router ID conflicts. Which FIRST step do you take?",
      "options": [
        "Upgrade the switch to half-duplex",
        "Manually assign unique OSPF router IDs on each device",
        "Extend the DHCP lease times in each VLAN",
        "Enable IP NAT overload on that interface"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Upgrade the switch to half-duplex is not relevant to OSPF or CPU usage. Manually assign unique OSPF router IDs on each device (correct) ensures each OSPF speaker has a distinct ID. Extend the DHCP lease times in each VLAN is IP management, Enable IP NAT overload on that interface is address translation. Duplicate OSPF router IDs cause adjacency issues, so define unique IDs for stable routing.",
      "examTip": "OSPF router ID must be unique in the domain. Overlapping IDs often break adjacency or trigger constant re-elections."
    },
    {
      "id": 42,
      "question": "Which approach is MOST critical if an advanced persistent threat (APT) is suspected, and you need to see if data is exfiltrating through hidden channels?",
      "options": [
        "Disable STP across all core links",
        "Review SIEM logs for unusual traffic patterns or suspicious endpoints",
        "Enable jumbo frames for better performance",
        "Limit DHCP lease times to 30 minutes"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Disable STP across all core links is about loop prevention, not APT detection. Review SIEM logs for unusual traffic patterns or suspicious endpoints (correct) SIEM correlation detects anomalies. Enable jumbo frames for better performance is performance tweak, Limit DHCP lease times to 30 minutes is IP management. Detailed log correlation is key to identifying covert APT exfiltration attempts.",
      "examTip": "APT attacks rely on stealthy, prolonged infiltration. SIEM event correlation reveals unusual patterns or consistent data drips."
    },
    {
      "id": 43,
      "question": "Which measure can block bridging loops on an access port connected to a rogue switch that might send BPDUs?",
      "options": [
        "ARIN registration of MAC addresses",
        "BPDU guard",
        "Assign half-duplex on that port",
        "DHCP Option 82"
      ],
      "correctAnswerIndex": 1,
      "explanation": "ARIN registration of MAC addresses is IP registration, not relevant to STP. BPDU guard (correct) shuts the port if it sees BPDUs, preventing loops. Assign half-duplex on that port is a link mismatch, DHCP Option 82 is a DHCP extension. BPDU guard is the standard approach for blocking bridging loops from unauthorized switches.",
      "examTip": "BPDU guard ensures the existing STP root remains in place, disqualifying ports that receive superior BPDUs from becoming root."
    },
    {
      "id": 44,
      "question": "Which is BEST addressed by implementing MST (Multiple Spanning Tree)?",
      "options": [
        "unify IPv4 and IPv6 addresses on a single VLAN",
        "reduce the number of STP instances when multiple VLANs exist",
        "limit NAT sessions on a core router",
        "provide half-duplex to old devices"
      ],
      "correctAnswerIndex": 1,
      "explanation": "unify IPv4 and IPv6 addresses on a single VLAN is IP addressing, not STP. reduce the number of STP instances when multiple VLANs exist (correct) MST maps multiple VLANs to fewer STP instances. limit NAT sessions on a core router is NAT, provide half-duplex to old devices is a link setting. MST is an evolution of spanning tree that groups VLANs into instances, reducing overhead.",
      "examTip": "PVST+ runs separate STP per VLAN. MST can cluster VLANs into fewer STP instances, improving scalability."
    },
    {
      "id": 45,
      "question": "Which type of DNS record is used by devices to locate a service, like _ldap._tcp.domain.com, returning host/port details?",
      "options": [
        "SRV",
        "CNAME",
        "A",
        "MX"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SRV (correct) SRV records store service location info including protocol, port, and target host. CNAME is an alias, A is IPv4 mapping, MX is mail exchange. SRV is commonly used by Active Directory and other services to discover service endpoints.",
      "examTip": "SRV (Service) records help clients discover services (e.g., SIP, LDAP) dynamically with domain queries."
    },
    {
      "id": 46,
      "question": "Which BGP community attribute signals that a route should not be advertised beyond the local AS?",
      "options": [
        "no-advertise",
        "local-AS",
        "no-export",
        "internet"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Common well-known communities include: no-advertise (don’t advertise to any peer), local-AS (don’t export outside the confederation). no-export (correct) means it is not sent to eBGP peers. internet is not a standard BGP community. This is often used to confine routes.",
      "examTip": "BGP well-known communities: no-export (prevent route from leaving AS), no-advertise (no peers), local-as (within confed)."
    },
    {
      "id": 47,
      "question": "Which measure can mitigate a massive ICMP flood from saturating a WAN link?",
      "options": [
        "Rewrite DSCP markings to default",
        "Rate-limit or ACL block excessive ICMP at the perimeter",
        "Enable trunking negotiation on the WAN interface",
        "Increase the DHCP lease time"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Rewrite DSCP markings to default is QoS marking, not blocking traffic. Rate-limit or ACL block excessive ICMP at the perimeter (correct) dropping or throttling ICMP addresses the flood. Enable trunking negotiation on the WAN interface is a VLAN approach, Increase the DHCP lease time is IP management. Rate-limiting or filtering malicious ICMP is standard for DoS defense.",
      "examTip": "Implement an ACL or policy on the router/firewall to drop or rate-limit high-volume ICMP from suspicious sources."
    },
    {
      "id": 48,
      "question": "A technician wants to use IPv6 EUI-64 addressing. Which portion of the MAC address is typically inserted into the interface ID?",
      "options": [
        "The entire 48-bit MAC is used verbatim",
        "The first 24 bits only",
        "The last 24 bits repeated once",
        "The 48-bit MAC is split and injected around FFFE to form a 64-bit interface ID"
      ],
      "correctAnswerIndex": 3,
      "explanation": "The entire 48-bit MAC is used verbatim is incomplete for 64 bits, The first 48 bits only and The last 24 bits repeated once are partial. The 48-bit MAC is split and injected around FFFE to form a 64-bit interface ID (correct) the MAC is split at 24 bits, with FFFE in between, plus flipping the 7th bit. This forms a 64-bit interface ID. That’s standard EUI-64 procedure.",
      "examTip": "EUI-64 in IPv6 expands a 48-bit MAC into 64 bits by inserting FFFE in the middle, also flipping the U/L bit."
    },
    {
      "id": 49,
      "question": "Which statement BEST describes a difference between EAP-PEAP and EAP-TLS?",
      "options": [
        "PEAP uses Open System authentication at layer 2",
        "EAP-TLS only requires the server to have a certificate, not the client",
        "PEAP needs only a server certificate, while EAP-TLS requires both server and client certificates",
        "PEAP is a Cisco-proprietary method for NAC posture checks"
      ],
      "correctAnswerIndex": 2,
      "explanation": "PEAP uses Open System authentication at layer 2 is Wi-Fi detail, not EAP difference. EAP-TLS only requires the server to have a certificate, not the client is reversed. PEAP needs only a server certificate, while EAP-TLS requires both server and client certificates (correct) is the main difference. PEAP is a Cisco-proprietary method for NAC posture checks is inaccurate. EAP-TLS requires mutual certs, whereas PEAP typically only requires a server cert and uses encrypted user credentials inside the TLS tunnel.",
      "examTip": "PEAP = server cert only, EAP-TLS = both sides have certs for mutual authentication."
    },
    {
      "id": 50,
      "question": "Which advanced firewall feature allows the device to decrypt outbound TLS traffic, scan it, then re-encrypt before sending to the destination?",
      "options": [
        "Stateful packet inspection",
        "SSL/TLS forward proxy",
        "Port address translation",
        "DHCP snooping pass-through"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Stateful packet inspection is layer 4, SSL/TLS forward proxy (correct) intercepts SSL at the firewall, Port address translation is NAT, DHCP snooping pass-through is IP address security. SSL forward proxy (TLS interception) is often used in NGFWs to inspect encrypted flows.",
      "examTip": "To inspect encrypted flows, a firewall must temporarily terminate and re-encrypt SSL traffic, known as a TLS/SSL proxy or interception."
    },
    {
      "id": 51,
      "question": "A router in OSPF must also inject RIP-learned routes into the OSPF domain. Which statement is correct about this router?",
      "options": [
        "It’s an OSPF ABR",
        "It’s an OSPF virtual link node",
        "It’s an OSPF DR in area 0",
        "It’s an OSPF ASBR"
      ],
      "correctAnswerIndex": 3,
      "explanation": "ABR (Area Border Router) connects multiple OSPF areas, not external protocols. It’s an OSPF virtual link node extends area 0 over a non-backbone area. It’s an OSPF DR in area 0 is a designated router on a multi-access segment. ASBR (Autonomous System Boundary Router) (correct) injects external routes from another protocol or domain, hence an ASBR. Any external route injection designates it as an ASBR.",
      "examTip": "If a router imports non-OSPF routes (e.g., from RIP, EIGRP), it’s an ASBR in OSPF."
    },
    {
      "id": 52,
      "question": "Which BGP path attribute is used to define a route’s origin within the same AS, primarily influencing egress traffic when multiple paths exist inside the AS?",
      "options": [
        "MED",
        "Local Preference",
        "Weight",
        "Community"
      ],
      "correctAnswerIndex": 1,
      "explanation": "MED is typically inbound influencer, not outbound. Local Preference (correct) is used by iBGP routers to prefer one path over another for outbound traffic. Weight is local to the router, Community is for tagging. Within the AS, local_pref is widely used to control outbound path preference.",
      "examTip": "Local Preference is an iBGP-wide setting for how your AS exits to external destinations. Higher local_pref is preferred."
    },
    {
      "id": 53,
      "question": "Which protocol is used for discovery of directly connected Cisco devices at layer 2, providing details like device ID, port, and VLAN info?",
      "options": [
        "LLDP",
        "CDP",
        "LACP",
        "SNMPv3"
      ],
      "correctAnswerIndex": 1,
      "explanation": "LLDP is the open standard, CDP (correct) Cisco Discovery Protocol is Cisco-proprietary, LACP is link aggregation, SNMPv3 is management protocol. CDP reveals adjacent Cisco device details.",
      "examTip": "CDP is Cisco’s proprietary neighbor discovery protocol, while LLDP is vendor-agnostic. Both share device info at layer 2."
    },
    {
      "id": 54,
      "question": "Which NAC scenario-based approach is BEST solved by implementing posture checks for connected laptops, ensuring they have up-to-date antivirus?",
      "options": [
        "limit half-duplex on trunk ports",
        "unify VLAN 1 usage",
        "keep infected endpoints off the network until they meet security policies",
        "reduce broadcast storms in a /24"
      ],
      "correctAnswerIndex": 2,
      "explanation": "limit half-duplex on trunk ports is irrelevant to NAC. unify VLAN 1 usage is not related to security posture. keep infected endpoints off the network until they meet security policies (correct) NAC posture checks keep non-compliant devices quarantined. reduce broadcast storms in a /24 is broadcast domain management. NAC posture is about verifying security compliance before granting normal network access.",
      "examTip": "NAC posture ensures endpoints have required patches, AV, etc., before allowing them on the network."
    },
    {
      "id": 55,
      "question": "A security engineer suspects an on-path (man-in-the-middle) attack forging gateway ARP. Which method directly helps detect or block ARP spoofing on Cisco switches?",
      "options": [
        "Port security limiting MAC addresses",
        "Dynamic ARP Inspection with DHCP snooping data",
        "DHCP relay with IP helper",
        "Trunk port negotiation to dynamic auto"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Port security limiting MAC addresses is a MAC limit, not ARP inspection. Dynamic ARP Inspection with DHCP snooping data (correct) DAI checks ARP vs. snooping data. DHCP relay with IP helper is DHCP broadcast forwarding, Trunk port negotiation to dynamic auto is VLAN trunking. DAI is the standard method for verifying ARP messages and preventing spoofing.",
      "examTip": "DAI relies on DHCP snooping or ARP access lists to confirm the IP-MAC bind. Spoof attempts are dropped."
    },
    {
      "id": 56,
      "question": "A router in EIGRP 'active' state for a particular prefix times out. Logs say “Stuck in Active.” Which factor typically triggers this?",
      "options": [
        "OSPF mismatch on the same interface",
        "A neighbor not responding to query, possibly due to a link or CPU issue",
        "DHCP failover losing IP assignments",
        "RIP route updates overriding EIGRP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "OSPF mismatch on the same interface is separate protocol, not EIGRP cause. A neighbor not responding to query, possibly due to a link or CPU issue (correct) an EIGRP route goes active and queries neighbors. If a neighbor never replies, it’s stuck in active. DHCP failover losing IP assignments is DHCP redundancy, not routing protocol issue. RIP route updates overriding EIGRP is a protocol overshadowing, not typical SIA cause. SIA arises when queries go unanswered, possibly due to a neighbor resource or link failure.",
      "examTip": "EIGRP SIA issues often trace to neighbor or network resource problems preventing timely query replies."
    },
    {
      "id": 57,
      "question": "Which strategy keeps unauthorized DHCP servers from responding to clients in VLAN 20?",
      "options": [
        "Configure trunk dynamic auto on VLAN 20 ports",
        "Extend DHCP lease times",
        "Enable DHCP snooping for VLAN 20, designating only the legitimate server port as trusted",
        "Disable spanning tree on VLAN 20"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Configure trunk dynamic auto on VLAN 20 ports fosters trunk negotiation, not related to DHCP security. Extend DHCP lease times is IP addressing, not DHCP server control. Enable DHCP snooping for VLAN 20, designating only the legitimate server port as trusted (correct) designates trusted DHCP port, blocking rogue servers. Disable spanning tree on VLAN 20 kills loop prevention, unrelated to DHCP. DHCP snooping is the standard tool to block rogue DHCP servers.",
      "examTip": "DHCP snooping designates which switch ports can send valid DHCP offers, preventing malicious address assignments."
    },
    {
      "id": 58,
      "question": "Which statement is TRUE regarding an 802.1X configuration that uses EAP-TLS?",
      "options": [
        "Only the client needs a certificate; the server uses a password",
        "Both client and server must have certificates for mutual authentication",
        "No RADIUS server is needed, just a local switch database",
        "It only works on half-duplex ports"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Only the client needs a certificate; the server uses a password is typically PEAP, not EAP-TLS. Both client and server must have certificates for mutual authentication (correct) EAP-TLS is mutual cert-based. No RADIUS server is needed, just a local switch database is not typical for enterprise 802.1X, It only works on half-duplex ports is irrelevant. EAP-TLS requires certificate-based authentication for both sides to ensure high security.",
      "examTip": "EAP-TLS requires a PKI for each client plus the server, guaranteeing strong mutual authentication."
    },
    {
      "id": 59,
      "question": "A WAN router frequently sees eBGP session flaps with 'BGP hold timer expired.' Which FIRST check is recommended?",
      "options": [
        "Half-duplex mismatch on trunk",
        "ACL blocking TCP port 179 keepalives",
        "Matching BGP keepalive/hold timers on both peers",
        "DHCP scope exhaustion"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Half-duplex mismatch on trunk is a link mismatch but not the prime suspect for BGP flapping. ACL blocking TCP port 179 keepalives could block the session but you’d see no adjacency at all, not flapping. Matching BGP keepalive/hold timers on both peers (correct) mismatch in hold timers can cause repeated session resets. DHCP scope exhaustion is IP addresses, unrelated to BGP. BGP hold-time must match, or sessions flap.",
      "examTip": "If BGP neighbors are flapping with hold-time expiration, ensure consistent keepalive/hold timers and stable connectivity."
    },
    {
      "id": 60,
      "question": "Which measure can help a switch detect and prevent MAC flooding attacks that attempt to overflow the CAM table?",
      "options": [
        "ARP inspection",
        "Port security limit on MAC addresses",
        "DHCP option 82 insertion",
        "Half-duplex trunk negotiation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "ARP inspection is for ARP spoofing, not MAC flooding. Port security limit on MAC addresses (correct) sets a maximum MAC count, shutting or restricting the port if exceeded. DHCP option 82 insertion is DHCP relay info, Half-duplex trunk negotiation is a mismatch. Port security is standard for thwarting MAC floods.",
      "examTip": "MAC flooding attempts can degrade the switch. Port security with a MAC limit triggers shutdown or violation action if exceeded."
    },
    {
      "id": 61,
      "question": "Which tactic is used to manipulate inbound traffic to prefer one of your internet connections over another in BGP?",
      "options": [
        "Increasing the local preference",
        "Adjusting the weight attribute",
        "Extending DHCP lease times",
        "AS-Path Prepending"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Increasing the local preference influences outbound traffic, not inbound. Adjusting the weight attribute is local to the router, not for influencing inbound path. Extending DHCP lease times is IP config, AS-Path Prepending (correct) artificially lengthens the path so alternative routes appear more attractive from outside. AS-Path prepending shapes inbound flows by making routes less preferable.",
      "examTip": "AS-Path Prepending is the main method for controlling inbound BGP traffic from external ASes."
    },
    {
      "id": 62,
      "question": "Which advanced firewall feature examines encrypted HTTPS flows by terminating and re-establishing TLS with its own certificate?",
      "options": [
        "Stateful packet inspection",
        "SSL/TLS forward proxy",
        "Port address translation",
        "DHCP snooping pass-through"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Stateful packet inspection is layer 4, not deep inspection of HTTPS. SSL/TLS forward proxy (correct) decrypts inbound/outbound TLS to inspect data. Port address translation is NAT, DHCP snooping pass-through is IP address security. SSL forward proxy (TLS interception) is often used by NGFW to see inside encrypted sessions.",
      "examTip": "SSL forward proxy or TLS interception is needed for deep inspection of HTTPS. The firewall re-signs traffic with its own certificate."
    },
    {
      "id": 63,
      "question": "A distribution switch experiences repeated STP reconvergence. Which FIRST diagnostic step is best to locate the cause?",
      "options": [
        "Check for a port that is going up/down flapping",
        "Reboot the core to reset STP",
        "Disable CDP globally",
        "Shorten the DHCP lease time"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Check for a port that is going up/down flapping (correct) flapping ports usually cause TCNs. Reboot the core to reset STP is disruptive, Disable CDP globally is device discovery, Shorten the DHCP lease time is IP config. Finding the unstable port or link is crucial to resolving repeated STP changes.",
      "examTip": "STP changes often mean a port is transitioning states. Investigate logs or port counters for any up/down events."
    },
    {
      "id": 64,
      "question": "Which port-based NAC approach ensures endpoints authenticate at layer 2, often referencing a RADIUS server, before granting network access?",
      "options": [
        "802.1Q trunk tagging",
        "802.1D spanning tree",
        "802.1X EAP authentication",
        "802.3af PoE injection"
      ],
      "correctAnswerIndex": 2,
      "explanation": "802.1Q trunk tagging is VLAN trunking, not authentication. 802.1D spanning tree is loop prevention, not authentication. 802.1X EAP authentication (correct) 802.1X is port-based NAC. 802.3af PoE injection is power distribution, not authentication. 802.1X uses EAP with RADIUS to authenticate clients before they send normal data.",
      "examTip": "802.1X is the IEEE standard for port-based authentication, gating traffic until credentials are verified."
    },
    {
      "id": 65,
      "question": "Which EIGRP feature is used to reduce the overhead of route advertisements in a large network by combining multiple routes into one summary address?",
      "options": [
        "Stub routing",
        "Split horizon",
        "Auto-summary",
        "Manual summarization"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Stub routing is for limiting query scope, not route summarization. Split horizon with poison reverse is a distance-vector routing concept, Auto-summary auto-summarizes at classful boundaries, not always desired. Manual summarization (correct) is configuring summary addresses on an interface for precise aggregation. Manual summarization is widely used for advanced route aggregation.",
      "examTip": "Manual summarization in EIGRP is flexible, letting you define custom summarized prefixes. Auto-summary is limited to classful boundaries."
    },
    {
      "id": 66,
      "question": "Which advanced STP variant maps multiple VLANs into a single spanning tree instance, reducing CPU usage compared to one instance per VLAN?",
      "options": [
        "Rapid PVST+",
        "MST ",
        "RIP STP mode",
        "VTP Pruning"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Rapid PVST+ still runs one instance per VLAN, not reducing CPU usage. MST (correct) Multiple Spanning Tree groups VLANs. RIP STP mode is nonexistent, VTP Pruning is VLAN distribution optimization, not STP instance reduction. MST is an IEEE standard that organizes VLANs into fewer STP instances.",
      "examTip": "MST merges multiple VLANs into a small number of STP instances, saving resources while letting certain VLAN sets share a spanning tree."
    },
    {
      "id": 67,
      "question": "A network admin needs to unify logs from multiple firewalls and correlate them for real-time threat analysis. Which solution is typically used?",
      "options": [
        "Syslog server with no analytics",
        "SNMPv3 traps",
        "SIEM platform",
        "DHCP relay agent"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Syslog server with no analytics collects logs but lacks advanced correlation. SNMPv3 traps is event notification for device stats, not log aggregation. SIEM platform (correct) aggregates logs from multiple sources and applies correlation. DHCP relay agent forwards DHCP requests. A SIEM is standard for real-time log correlation and threat detection.",
      "examTip": "A SIEM aggregates logs and applies real-time correlation to detect patterns indicating threats."
    },
    {
      "id": 68,
      "question": "Which approach can unify security policies across multiple remote sites, dynamically selecting the best WAN path for traffic and applying centralized management?",
      "options": [
        "Standard routing with static next-hop",
        "SD-WAN solution with overlay tunnels and centralized policy engine",
        "STP root guard on the WAN link",
        "Client-based IPSec with local NAT"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Standard routing with static next-hop is manual, not dynamic or centralized. SD-WAN solution with overlay tunnels and centralized policy engine (correct) software-defined WAN orchestrates multiple links with a central controller. STP root guard on the WAN link is a bridging security feature, Client-based IPSec with local NAT is a remote user approach, not site-to-site. SD-WAN typically uses dynamic path selection and centralized policy.",
      "examTip": "SD-WAN commonly centralizes routing/policy decisions, automatically picking the best path among MPLS, broadband, LTE, etc."
    },
    {
      "id": 69,
      "question": "Which is the BEST reason to implement an evil twin detection sensor on the corporate WLAN?",
      "options": [
        "To unify VLAN trunking with a single SSID",
        "To spot rogue APs mimicking the legitimate SSID, preventing on-path attacks",
        "To enforce half-duplex for older 802.11b devices",
        "To block DHCP offers from untrusted ports"
      ],
      "correctAnswerIndex": 1,
      "explanation": "To unify VLAN trunking with a single SSID is unrelated to evil twin detection. To spot rogue APs mimicking the legitimate SSID, preventing on-path attacks (correct) evil twin APs replicate the SSID and intercept data. To enforce half-duplex for older 802.11b devices is performance detail, not security. To block DHCP offers from untrusted ports is DHCP-based security, not related to evil twins. Evil twin detection sensors can discover unauthorized APs broadcasting the same SSID.",
      "examTip": "Rogue or evil twin AP detection helps protect users from connecting to malicious impersonators, a common Wi-Fi attack."
    },
    {
      "id": 70,
      "question": "Which NAC enforcement method can place a device in a quarantine VLAN if it fails posture checks, granting minimal network access for remediation?",
      "options": [
        "Static IP with half-duplex",
        "Dynamic VLAN assignment via RADIUS (dVLAN or dACL)",
        "802.1D loop detection",
        "Syslog-based trunk negotiation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Static IP with half-duplex is irrelevant to NAC or quarantine. Dynamic VLAN assignment via RADIUS (dVLAN or dACL) (correct) NAC often uses 802.1X plus RADIUS to push VLAN changes. 802.1D loop detection is STP, Syslog-based trunk negotiation is not a standard feature. Downloadable VLAN or ACL from the RADIUS server quarantines non-compliant devices instantly.",
      "examTip": "NAC posture checks can move failing endpoints to a quarantine VLAN with minimal network access."
    },
    {
      "id": 71,
      "question": "Which measure does a firewall policy typically use to handle incoming traffic from an untrusted interface?",
      "options": [
        "Default allow rule for all inbound",
        "Default deny, with explicit allow rules for necessary ports/services",
        "Assign half-duplex to untrusted zones",
        "Change the native VLAN to 1"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Default allow rule for all inbound is insecure. Default deny, with explicit allow rules for necessary ports/services (correct) standard security posture for firewalls. Assign half-duplex to untrusted zones is a link mismatch, Change the native VLAN to 1 is trunk detail, not security policy. Firewalls typically adopt a “deny all inbound by default” approach, enabling only permitted traffic explicitly.",
      "examTip": "Best practice: deny by default, then create specific inbound allow rules for required services."
    },
    {
      "id": 72,
      "question": "Which AAA protocol uses UDP, encrypts only the password portion of the packet, and is primarily used for network access?",
      "options": [
        "TACACS+",
        "Kerberos",
        "RADIUS",
        "Diameter"
      ],
      "correctAnswerIndex": 2,
      "explanation": "TACACS+ uses TCP and encrypts the entire packet, Kerberos is for domain-based authentication, not network access AAA. RADIUS (correct) RADIUS uses UDP/1812-1813 or 1645-1646, partially encrypting passwords. Diameter is a next-gen RADIUS replacement, not widely used for basic network access. RADIUS is standard for user authentication in networks.",
      "examTip": "TACACS+ is full-packet encryption (TCP), RADIUS is partial encryption (UDP). RADIUS is commonly used for 802.1X/Wi-Fi/VPN user auth."
    },
    {
      "id": 73,
      "question": "Which measure can hamper VLAN trunk negotiation attacks by turning off automatic trunk formation on user-facing switch ports?",
      "options": [
        "Set switchport mode access and disable DTP",
        "Assign the ports to VLAN 1 as a trunk",
        "Use half-duplex to reduce collisions",
        "Deploy a DHCP reservation for each port"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Set switchport mode access and disable DTP (correct) ensures no auto trunk negotiation, preventing trunking attacks. Assign the ports to VLAN 1 as a trunk lumps everything in VLAN 1, Use half-duplex to reduce collisions is a link mismatch, Deploy a DHCP reservation for each port is IP config, not relevant to trunk security. Disabling DTP ensures user ports remain in access mode, preventing VLAN trunk attacks.",
      "examTip": "‘switchport mode access’ + ‘switchport nonegotiate’ is best practice for user ports to stop trunk auto-formation."
    },
    {
      "id": 74,
      "question": "Which is BEST addressed by leveraging SNMPv3 'authPriv' mode on network devices?",
      "options": [
        "push encrypted DHCP offers to clients",
        "prevent brute-force attacks on BGP sessions",
        "securely poll device statistics and send traps with both authentication and encryption",
        "unify VLAN and port security"
      ],
      "correctAnswerIndex": 2,
      "explanation": "push encrypted DHCP offers to clients is DHCP, not SNMP. prevent brute-force attacks on BGP sessions is BGP security, not SNMP. securely poll device statistics and send traps with both authentication and encryption (correct) SNMPv3 with authPriv ensures encrypted data plus authenticated access. unify VLAN and port security is general security, not specific to SNMP. SNMPv3 is essential for secure network management data transmissions.",
      "examTip": "Use SNMPv3 in 'authPriv' mode to protect credentials and data from eavesdropping or tampering."
    },
    {
      "id": 75,
      "question": "Which layer 3 overlay protocol is designed for large-scale data centers, encapsulating Ethernet frames in UDP for extended VLANs across IP networks?",
      "options": [
        "LACP",
        "VXLAN",
        "GRE keepalive",
        "VTP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "LACP is link aggregation, not overlay protocol. VXLAN (correct) Virtual eXtensible LAN encapsulates Ethernet frames in UDP. GRE keepalive is a basic tunnel heartbeat, VTP automates VLAN info. VXLAN is a popular overlay in modern data centers, supporting multi-tenant, large-scale layer 2 networks over layer 3.",
      "examTip": "VXLAN uses a 24-bit VNID, enabling up to 16 million segments, far more than traditional 802.1Q’s 4094 VLANs."
    },
    {
      "id": 76,
      "question": "Which switch feature is used to prevent a newly connected switch from introducing itself as root on an access port?",
      "options": [
        "DHCP snooping",
        "Port security MAC limit",
        "Root guard",
        "CDP neighbor guard"
      ],
      "correctAnswerIndex": 2,
      "explanation": "DHCP snooping is DHCP security, not STP root protection. Port security MAC limit restricts MAC addresses, not STP related. Root guard (correct) blocks ports receiving superior BPDUs from taking over root. CDP neighbor guard is device discovery. Root guard ensures the existing root remains authoritative.",
      "examTip": "Root guard ensures the existing STP root remains in place, disqualifying ports that receive superior BPDUs from becoming root."
    },
    {
      "id": 77,
      "question": "Which event triggers an ASBR to generate Type 5 LSAs in OSPF?",
      "options": [
        "A route is learned from an internal ABR in Area 0",
        "A router is redistributing external routes from another protocol or domain into OSPF",
        "The router becomes the designated router on a multi-access segment",
        "A backbone router forms a virtual link"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A route is learned from an internal ABR in Area 0 is inter-area routes, not external. A router is redistributing external routes from another protocol or domain into OSPF (correct) external routes cause Type 5 LSAs. The router becomes the designated router on a multi-access segment is a DR function, A backbone router forms a virtual link extends area 0 over a non-backbone area. ASBRs inject external routes into OSPF via Type 5 LSAs.",
      "examTip": "When OSPF imports non-OSPF routes, the router is an ASBR, generating Type 5 (External) LSAs unless in a stub area."
    },
    {
      "id": 78,
      "question": "A load balancer must handle SSL offloading for a farm of web servers. Which statement is correct?",
      "options": [
        "SSL offload means the servers never see any client traffic",
        "The load balancer terminates the client SSL session, potentially re-encrypting traffic to servers",
        "An STP TCN is always required for each new session",
        "All servers must be in half-duplex mode to accept the load balancing"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SSL offload means the servers never see any client traffic is inaccurate, backend servers still receive traffic. The load balancer terminates the client SSL session, potentially re-encrypting traffic to servers (correct) the LB can terminate client-side SSL, optionally re-encrypt or forward plaintext to servers. An STP TCN is always required for each new session is loop prevention detail, irrelevant. All servers must be in half-duplex mode to accept the load balancing is a link mismatch, not relevant to load balancing or SSL offloading. SSL offloading reduces CPU load on servers by shifting encryption tasks to the LB.",
      "examTip": "With SSL offload, the LB handles encryption/decryption, letting backend servers handle HTTP in plaintext or re-encrypted traffic."
    },
    {
      "id": 79,
      "question": "Which approach can reduce microbursts causing short-term congestion on a high-speed link for critical traffic?",
      "options": [
        "Implement a strict priority LLQ for real-time traffic",
        "Configure half-duplex to slow input rate",
        "Disable DHCP snooping on that interface",
        "Assign a /30 to limit broadcast domain"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Implement a strict priority LLQ for real-time traffic (correct) ensures critical traffic goes into a priority queue, shielding it from bursts. Configure half-duplex to slow input rate is detrimental and not effective for bursts. Disable DHCP snooping on that interface is DHCP security, not related to microbursts. Assign a /30 to limit broadcast domain is a small subnet and unrelated to QoS. LLQ can shield priority traffic (like voice) from microburst-induced delays.",
      "examTip": "Priority queueing or LLQ ensures time-sensitive flows aren’t starved when bursts fill the transmit queue."
    },
    {
      "id": 80,
      "question": "A newly configured router cannot ping beyond its LAN. Which single item is often missing?",
      "options": [
        "Default gateway on the router’s interface",
        "DNS server IP address",
        "802.1D spanning tree config",
        "DHCP snooping on trunk ports"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Default gateway on the router’s interface (correct) if no default route or gateway is set, external pings fail. DNS server IP address affects name resolution, but IP ping would still fail if no route is known. 802.1D spanning tree config is loop prevention, DHCP snooping on trunk ports is DHCP security. A router needs a default route (or a more specific route) for outbound connectivity.",
      "examTip": "Routers typically require a default or static route for traffic destined outside known subnets."
    },
    {
      "id": 81,
      "question": "Which next-generation firewall feature detects and identifies traffic at layer 7, even if it uses port 80 or 443, to enforce advanced policies?",
      "options": [
        "MAC address filtering",
        "Application-layer DPI (deep packet inspection)",
        "Static NAT for inbound sessions",
        "Telnet-based device discovery"
      ],
      "correctAnswerIndex": 1,
      "explanation": "MAC address filtering is a basic L2 approach, not application-aware. Application-layer DPI (deep packet inspection) (correct) identifies apps by payload, regardless of port. Static NAT for inbound sessions is address translation, Telnet-based device discovery is unsecure management. NGFWs rely on application-aware DPI to recognize traffic regardless of port/protocol.",
      "examTip": "App awareness goes beyond ports: DPI sees packet content to classify apps like Skype, Dropbox, or streaming services."
    },
    {
      "id": 82,
      "question": "What is the PRIMARY difference between EAP-TLS and EAP-FAST in an 802.1X environment?",
      "options": [
        "EAP-TLS requires full PKI with client and server certs, EAP-FAST can use a PAC for client authentication",
        "EAP-TLS is unencrypted, EAP-FAST is always encrypted",
        "PEAP is only for half-duplex links",
        "They are essentially the same protocol"
      ],
      "correctAnswerIndex": 0,
      "explanation": "EAP-TLS requires full PKI with client and server certs, EAP-FAST can use a PAC for client authentication (correct) EAP-TLS demands mutual certs, EAP-FAST uses a PAC-based tunnel. EAP-TLS is unencrypted, EAP-FAST is always encrypted is reversed, EAP-TLS is more secure. PEAP is only for half-duplex links is not relevant, They are essentially the same protocol is incorrect. EAP-FAST is simpler to deploy if distributing PACs is easier than managing client certs.",
      "examTip": "EAP-FAST provides a secure tunnel using a PAC, while EAP-TLS requires client and server certificates for mutual authentication."
    },
    {
      "id": 83,
      "question": "A distribution switch sees repeated MAC addresses flooding from a single port. Which FIRST measure is recommended?",
      "options": [
        "Enable port security with a max MAC limit",
        "Increase DHCP pool size",
        "Disable half-duplex for VLAN 1",
        "Use CDP to discover the remote device"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Enable port security with a max MAC limit (correct) blocks MAC floods or bridging devices by limiting MAC addresses per port. Increase DHCP pool size is IP addressing, not relevant to MAC flooding. Disable half-duplex for VLAN 1 is a link mismatch, Use CDP to discover the remote device is device discovery, not related to MAC flooding mitigation. Port security sets a limit on MAC addresses, mitigating flood attacks or rogue hubs/switches.",
      "examTip": "MAC flooding attempts can degrade the switch. Port security with a MAC limit triggers shutdown or violation action if exceeded."
    },
    {
      "id": 84,
      "question": "Which approach ensures minimal overhead for a user to get remote VPN access from any browser without installing a dedicated VPN client?",
      "options": [
        "Client-based IPSec with preshared key",
        "Clientless SSL VPN via a web portal",
        "DHCP relay across the WAN",
        "SSH port forwarding of the entire subnet"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Client-based IPSec with preshared key requires software installation. Clientless SSL VPN via a web portal (correct) is a web-based approach, requiring no client software. DHCP relay across the WAN is IP broadcast forwarding, SSH port forwarding of the entire subnet is partial and complex. Clientless SSL VPN is typical for quick, software-free access to internal resources from any browser.",
      "examTip": "Clientless SSL VPN is also called ‘portal VPN,’ letting users securely connect from standard HTTPS without extra installations."
    },
    {
      "id": 85,
      "question": "Which concept allows a single router interface to route multiple VLANs by creating subinterfaces, each tagged with a distinct VLAN ID?",
      "options": [
        "Router-on-a-stick",
        "Port security sticky MAC",
        "Half-duplex bridging",
        "CDP trunking"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Router-on-a-stick (correct) is the classic subinterface approach for inter-VLAN routing. Port security sticky MAC is an L2 security measure, Half-duplex bridging is a link mismatch, CDP trunking is device discovery protocol combined with trunking, not a routing method. Router-on-a-stick uses 802.1Q subinterfaces to route between VLANs over one physical link.",
      "examTip": "A router-on-a-stick config defines multiple subinterfaces on one physical port, each subinterface trunk-tagged with a unique VLAN."
    },
    {
      "id": 86,
      "question": "Which measure is recommended to avoid undesired trunk formation between two non-trunking devices, mitigating VLAN hopping?",
      "options": [
        "Set switchport mode access and disable DTP",
        "Assign the ports to VLAN 1 as a trunk",
        "Use half-duplex to reduce collisions",
        "Deploy a DHCP reservation for each port"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Set switchport mode access and disable DTP (correct) ensures no auto trunk negotiation, preventing trunking attacks. Assign the ports to VLAN 1 as a trunk lumps everything in VLAN 1, Use half-duplex to reduce collisions is a link mismatch, Deploy a DHCP reservation for each port is IP config, not relevant to trunk security. Disabling DTP ensures user ports remain in access mode, preventing VLAN trunk attacks.",
      "examTip": "‘switchport mode access’ + ‘switchport nonegotiate’ is best practice for user ports to stop trunk auto-formation."
    },
    {
      "id": 87,
      "question": "Which approach helps mitigate an evil twin attack luring users to a rogue AP with the same SSID?",
      "options": [
        "Captive portal disclaimers",
        "EAP-TLS for mutual certificate validation, so clients can confirm the AP is legitimate",
        "DHCP snooping on all switch ports",
        "Trunk negotiation with dynamic auto"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Captive portal disclaimers are user terms, not AP authentication. EAP-TLS for mutual certificate validation, so clients can confirm the AP is legitimate (correct) mutual cert authentication reveals rogue AP that lacks a valid cert. DHCP snooping on all switch ports is IP security, Trunk negotiation with dynamic auto is trunk config. Enterprise EAP methods using server certs help clients confirm they’re connecting to the real AP.",
      "examTip": "Evil twin attacks rely on user trust in an SSID. WPA2-Enterprise with validated server cert (EAP-TLS/PEAP) ensures the AP is genuine."
    },
    {
      "id": 88,
      "question": "A BGP router references a route with a lower MED vs. another route to the same prefix. Which statement is TRUE about MED?",
      "options": [
        "MED is a higher priority than Local Preference in route selection",
        "MED is used by neighboring AS to influence inbound traffic into that AS",
        "MED is only relevant if half-duplex is set on the interface",
        "MED never influences route selection"
      ],
      "correctAnswerIndex": 1,
      "explanation": "MED is a higher priority than Local Preference in route selection is reversed (Local Preference is higher priority). MED is used by neighboring AS to influence inbound traffic into that AS (correct) you set MED so external neighbors prefer one path inbound. MED is only relevant if half-duplex is set on the interface is a link mismatch, MED never influences route selection is false. MED is typically the last attribute considered after local_pref, AS-path, etc., but it can shape inbound traffic if the neighbor honors it.",
      "examTip": "MED (Multi-Exit Discriminator) suggests to external neighbors which entry point is preferred into your AS if multiple exist."
    },
    {
      "id": 89,
      "question": "Which DHCPv6 mode allows a client to configure its own IP via SLAAC but still receive additional info (e.g., DNS) from a DHCPv6 server?",
      "options": [
        "Stateful DHCPv6 only",
        "Stateless DHCPv6",
        "NDP router advertisement with no DHCPv6",
        "Prefix delegation for routers"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Stateful DHCPv6 only is fully stateful (server tracks addresses). Stateless DHCPv6 (correct) client auto-configures address from RA but obtains other info (DNS) from server. NDP router advertisement with no DHCPv6 is purely SLAAC, no server. Prefix delegation for routers is for delegating subnets, not client configuration. Stateless DHCPv6 offers config info while addresses come from SLAAC.",
      "examTip": "Stateless DHCPv6 doesn’t assign IP addresses; the client uses SLAAC for that. The server only provides extra parameters like DNS."
    },
    {
      "id": 90,
      "question": "Which approach blocks an ARP broadcast from forging the gateway MAC, preventing an on-path attack in the same broadcast domain?",
      "options": [
        "ARP inspection references DHCP snooping",
        "Flood guard enabling half-duplex",
        "RA guard filtering unauthorized router advertisements",
        "Spanning tree in RPVST mode"
      ],
      "correctAnswerIndex": 2,
      "explanation": "ARP inspection references DHCP snooping is IPv4-based ARP, not RA, and not effective for blocking ARP forgeries directly. Flood guard enabling half-duplex is a link mismatch, not security. RA guard filtering unauthorized router advertisements is IPv6 security, not ARP. Dynamic ARP Inspection referencing DHCP snooping (correct) DAI uses IP-to-MAC mappings to detect ARP spoofing. This prevents ARP spoofing on the LAN.",
      "examTip": "Dynamic ARP Inspection relies on DHCP snooping or ARP access lists to confirm authenticity of ARP traffic. Spoof attempts are dropped."
    },
    {
      "id": 91,
      "question": "Which is BEST answered by implementing an SIEM platform?",
      "options": [
        "build an L2 trunk for VLAN traffic",
        "correlate logs from many devices to detect advanced threats",
        "unify NAT translations on the core router",
        "deploy DHCP reservations for each user"
      ],
      "correctAnswerIndex": 1,
      "explanation": "build an L2 trunk for VLAN traffic is VLAN config, not SIEM. correlate logs from many devices to detect advanced threats (correct) SIEM is log correlation and threat detection. unify NAT translations on the core router is address translation, deploy DHCP reservations for each user is IP assignment, not SIEM use case. SIEM aggregates logs from firewalls, switches, servers, applying analytics to spot complex or distributed threats.",
      "examTip": "A SIEM solution is invaluable for centralized logging, correlation, and real-time alerting across diverse network devices."
    },
    {
      "id": 92,
      "question": "Which step is recommended to handle microbursts for real-time traffic on a switch interface?",
      "options": [
        "Half-duplex to slow input rate",
        "Enable LLQ or priority queueing to shield critical traffic from burst drops",
        "Configure DHCP relay with IP helper",
        "Disable trunking on that port"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Half-duplex to slow input rate is detrimental to performance and ineffective for microbursts. Enable LLQ or priority queueing to shield critical traffic from burst drops (correct) ensures real-time traffic is buffered or prioritized during short bursts. Configure DHCP relay with IP helper is DHCP broadcast forwarding, Disable trunking on that port is VLAN removal. Using a priority queue approach prevents voice/video packets from dropping during short bursts.",
      "examTip": "Priority queueing or LLQ ensures time-sensitive flows aren’t starved when bursts fill the transmit queue."
    },
    {
      "id": 93,
      "question": "Which statement is TRUE regarding IPsec transport vs. tunnel mode?",
      "options": [
        "Transport mode encrypts only the payload; tunnel mode wraps the entire IP packet",
        "Tunnel mode is used only for IPv6, while transport is IPv4",
        "Transport mode requires NAT, while tunnel mode does not",
        "Both modes require half-duplex to avoid collisions"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Transport mode encrypts only the payload; tunnel mode wraps the entire IP packet (correct) is the fundamental difference. Tunnel mode is used only for IPv6, while transport is IPv4 is incorrect, both can be IPv4 or IPv6. Transport mode requires NAT, while tunnel mode does not is not accurate, NAT can be used with both. Both modes require half-duplex to avoid collisions is irrelevant. Transport mode protects payload only, while tunnel mode encapsulates the entire IP packet with a new header.",
      "examTip": "Site-to-site VPNs often use tunnel mode. Host-to-host encryption might use transport mode, preserving the original IP header."
    },
    {
      "id": 94,
      "question": "Which approach mitigates EIGRP route query sprawl by preventing certain routers from forwarding queries beyond themselves?",
      "options": [
        "Auto-summary turned on",
        "Stub router configuration",
        "Split horizon with poison reverse",
        "DHCP snooping pass-through"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Auto-summary turned on is classful summarization, not query control. Stub router configuration (correct) stub routers limit query propagation. Split horizon with poison reverse is a distance-vector routing concept, DHCP snooping pass-through is unrelated to EIGRP or routing protocols. Configuring EIGRP stub on spoke routers helps contain queries, improving convergence speed.",
      "examTip": "In large EIGRP networks, stub routers reduce query scope and help avoid SIA situations."
    },
    {
      "id": 95,
      "question": "Which NAC enforcement method can place a device in a quarantine VLAN if it fails posture checks, granting minimal network access for remediation?",
      "options": [
        "Static IP with half-duplex",
        "Dynamic VLAN assignment via RADIUS (dVLAN or dACL)",
        "802.1D loop detection",
        "Syslog-based trunk negotiation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Static IP with half-duplex is irrelevant to NAC or quarantine. Dynamic VLAN assignment via RADIUS (dVLAN or dACL) (correct) NAC often uses 802.1X plus RADIUS to push VLAN changes. 802.1D loop detection is STP, Syslog-based trunk negotiation is not a standard feature. Downloadable VLAN or ACL from the RADIUS server quarantines non-compliant devices instantly.",
      "examTip": "NAC posture checks can move failing endpoints to a quarantine VLAN with minimal network access."
    },
    {
      "id": 96,
      "question": "A switch logs repeated ‘native VLAN mismatch’ with a neighboring switch. Which step typically fixes this?",
      "options": [
        "Set the same native VLAN ID on both trunk ports",
        "Use half-duplex to reduce collisions",
        "Disable 802.1D spanning tree entirely",
        "Shorten the DHCP lease time"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Set the same native VLAN ID on both trunk ports (correct) trunk ports must match native VLAN to avoid mismatch errors. Use half-duplex to reduce collisions is a link mismatch, Disable 802.1D spanning tree entirely is loop risk, Shorten the DHCP lease time is IP config. Ensuring both trunk ends share the same native VLAN eliminates mismatch errors.",
      "examTip": "Native VLAN mismatch can lead to unexpected traffic bridging. Align both sides’ native VLAN or pick a unique non-1 VLAN."
    },
    {
      "id": 97,
      "question": "Which BGP concept allows a group of routes to be tagged and manipulated as a unit for policy decisions, such as ‘no-export’ or ‘local-AS’?",
      "options": [
        "Community",
        "Weight attribute",
        "MED",
        "Origin code"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Community (correct) BGP communities are route tags for grouping and applying policies. Weight attribute is local to the router, MED influences inbound path, Origin code shows how BGP learned the route. Communities provide flexible route grouping for policy.",
      "examTip": "BGP communities let operators define or match custom tags, e.g., no-export, shaping how routes propagate."
    },
    {
      "id": 98,
      "question": "Which is BEST addressed by implementing 802.1X with EAP-PEAP on all wired access ports?",
      "options": [
        "monitor cable continuity behind walls",
        "ensure each user is individually authenticated with only a server certificate required",
        "unify DHCP scopes for multiple VLANs",
        "reduce broadcast storms in large subnets"
      ],
      "correctAnswerIndex": 1,
      "explanation": "monitor cable continuity behind walls is physical testing, not NAC. ensure each user is individually authenticated with only a server certificate required (correct) describes 802.1X + PEAP for secure user auth with simplified cert management. unify DHCP scopes for multiple VLANs is IP address management, reduce broadcast storms in large subnets is layer 2 design. PEAP is widely used for port-based NAC, requiring only a server cert plus user credentials (e.g., MSCHAPv2).",
      "examTip": "PEAP is simpler than EAP-TLS as it only needs a server cert. Clients use credentials securely within the TLS tunnel."
    },
    {
      "id": 99,
      "question": "A distribution switch repeatedly re-elects STP root after a newly introduced device floods BPDUs. Which feature on the distribution ports prevents losing root to unauthorized switches?",
      "options": [
        "Root guard",
        "DHCP snooping",
        "Syslog trap forwarder",
        "CDP neighbor details"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Root guard (correct) blocks ports receiving superior BPDUs, maintaining root stability. DHCP snooping is DHCP security, not relevant to STP root election. Syslog trap forwarder is logging, CDP neighbor details is device discovery. Root guard ensures the current root remains authoritative, ignoring any superior BPDU from that port.",
      "examTip": "On distribution or core ports that shouldn’t see a new root, root guard blocks superior BPDUs, stabilizing the STP topology."
    },
    {
      "id": 100,
      "question": "Which measure can hamper IPv6 SLAAC-based on-path attacks that spoof RA messages, tricking hosts into using a malicious default gateway?",
      "options": [
        "ARP inspection references DHCP snooping",
        "Flood guard enabling half-duplex",
        "RA guard filtering unauthorized router advertisements",
        "Spanning tree in RPVST mode"
      ],
      "correctAnswerIndex": 2,
      "explanation": "ARP inspection references DHCP snooping is IPv4-based ARP, not RA. Flood guard enabling half-duplex is a link mismatch, not security. RA guard filtering unauthorized router advertisements (correct) RA guard drops untrusted RAs from non-router ports. Spanning tree in RPVST mode is loop prevention, not relevant to IPv6 RA attacks. IPv6 RA guard stops rogue announcements that could divert traffic to an attacker’s gateway.",
      "examTip": "RA guard is an IPv6 security measure analogous to ARP inspection, controlling who can send router advertisements on a LAN."
    }
  ]
});
