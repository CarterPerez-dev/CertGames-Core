db.tests.insertOne({{
  "category": "nplus",
  "testId": 4,
  "testName": "Network+ Practice Test #3 (Moderate)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A user reports they can access internal resources but cannot access any websites. Which of the following should be the FIRST step in troubleshooting this issue?",
      "options": [
        "Verify DNS settings on the user’s device.",
        "Check the firewall for outbound web traffic rules.",
        "Test internet connectivity from the user’s device using ping.",
        "Ensure the user’s IP configuration matches network policies."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If internal resources are accessible but external websites are not, DNS resolution issues are likely. Verifying DNS settings should be the first step. Checking the firewall and testing connectivity with ping are valid, but DNS misconfigurations often cause such issues. IP configuration mismatches would affect internal connectivity too.",
      "examTip": "Website access issues + internal connectivity OK? **Check DNS first** — it's the usual suspect."
    },
    {
      "id": 2,
      "question": "A company’s web server is accessible internally but not from external networks. Which configuration should be reviewed FIRST?",
      "options": [
        "Firewall's NAT rules",
        "Web server's host file",
        "Internal DNS records",
        "Default gateway settings on the web server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "For external access, the firewall's NAT rules must forward incoming traffic to the web server. The host file and internal DNS would affect internal resolutions. The default gateway is essential but not the primary concern if internal access is already functional.",
      "examTip": "External access blocked? **Check NAT rules** — they map public requests internally."
    },
    {
      "id": 3,
      "question": "Which of the following BEST explains why a network administrator would implement 802.1X on switches?",
      "options": [
        "To enforce port-based network access control",
        "To segment network traffic using VLANs",
        "To provide encryption between switches",
        "To support link aggregation for higher throughput"
      ],
      "correctAnswerIndex": 0,
      "explanation": "802.1X provides port-based network access control, ensuring only authorized devices connect. VLANs handle traffic segmentation. Encryption between switches would require protocols like MACsec. Link aggregation is for combining bandwidth, not authentication.",
      "examTip": "802.1X = **Access control at the port** — keeps unauthorized devices off the network."
    },
    {
      "id": 4,
      "question": "A technician is configuring a site-to-site VPN. Which protocol would provide the MOST secure encryption for data in transit?",
      "options": [
        "IPSec",
        "GRE",
        "L2TP",
        "PPTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "IPSec provides strong encryption and authentication for VPN traffic. GRE offers tunneling but lacks encryption. L2TP can provide encryption when paired with IPSec. PPTP is outdated and insecure.",
      "examTip": "**IPSec = Go-to for VPN encryption** — secure tunnels, every time."
    },
    {
      "id": 5,
      "question": "Which cloud model allows an organization to retain control over its data center while leveraging public cloud resources during peak demand?",
      "options": [
        "Hybrid cloud",
        "Private cloud",
        "Public cloud",
        "Community cloud"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Hybrid cloud blends private infrastructure with public cloud resources for scalability. Private clouds are fully controlled by the organization. Public clouds are shared resources. Community clouds are shared among specific organizations.",
      "examTip": "**Hybrid cloud = Flexibility + Scalability** — best for handling variable workloads."
    },
    {
      "id": 6,
      "question": "A technician needs to ensure high availability and redundancy for critical systems in case of network failure. Which approach BEST meets this requirement?",
      "options": [
        "Configure dual routers using HSRP or VRRP.",
        "Implement link aggregation between switches.",
        "Deploy a mesh network topology.",
        "Utilize VLAN segmentation."
      ],
      "correctAnswerIndex": 0,
      "explanation": "HSRP (Cisco) and VRRP provide router redundancy, ensuring network availability. Link aggregation improves bandwidth, not redundancy at the router level. Mesh topologies are costly and complex. VLANs improve segmentation but not network redundancy.",
      "examTip": "**HSRP/VRRP = Router redundancy** — critical paths always available."
    },
    {
      "id": 7,
      "question": "A network device is designed to detect malicious activities, alert administrators, but not actively block traffic. What is this device called?",
      "options": [
        "Intrusion Detection System (IDS)",
        "Firewall",
        "Intrusion Prevention System (IPS)",
        "Proxy server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An IDS monitors network traffic and alerts administrators. An IPS actively blocks malicious traffic. Firewalls control access based on rules. Proxy servers act as intermediaries for client requests.",
      "examTip": "**IDS = Detects & Alerts** — it’s the watchdog, not the gatekeeper."
    },
    {
      "id": 8,
      "question": "Which of the following IPv6 addresses represents a loopback address?",
      "options": [
        "::1",
        "fe80::1",
        "2001::1",
        "ff02::1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "::1 is the IPv6 loopback address. fe80::1 is a link-local address. 2001::1 represents a global unicast address. ff02::1 is a multicast address.",
      "examTip": "**::1 = IPv6 loopback** — test local host just like 127.0.0.1 in IPv4."
    },
    {
      "id":  9,
      "question": "A technician suspects a routing issue in a network path. Which tool would provide information on each hop between the source and destination?",
      "options": [
        "traceroute",
        "ping",
        "nslookup",
        "netstat"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'traceroute' reveals each hop in a path and can identify where failures or delays occur. 'ping' checks basic connectivity. 'nslookup' resolves DNS issues. 'netstat' shows active connections.",
      "examTip": "**traceroute = Path inspector** — follow the route, find the block."
    },
    {
      "id": 10,
      "question": "Which protocol is used to encrypt data between web browsers and servers for secure communication over the internet?",
      "options": [
        "TLS",
        "SSH",
        "SFTP",
        "IPSec"
      ],
      "correctAnswerIndex": 0,
      "explanation": "TLS (Transport Layer Security) encrypts web traffic (e.g., HTTPS). SSH secures terminal access. SFTP uses SSH for secure file transfers. IPSec secures network-level communications.",
      "examTip": "**TLS = Web encryption standard** — secures HTTP as HTTPS."
    },
    {
      "id": 11,
      "question": "Which of the following services maps human-friendly domain names to IP addresses?",
      "options": [
        "DNS",
        "DHCP",
        "NAT",
        "SNMP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DNS translates domain names to IP addresses. DHCP dynamically assigns IPs. NAT translates internal addresses for external communication. SNMP monitors network devices.",
      "examTip": "**DNS = The internet's phonebook** — converts names to numbers."
    },
    {
      "id": 12,
      "question": "Which device connects multiple networks and makes decisions based on IP address information?",
      "options": [
        "Router",
        "Switch",
        "Hub",
        "Repeater"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Routers operate at Layer 3, using IP addresses to route traffic. Switches operate at Layer 2 (MAC addresses). Hubs broadcast data to all ports. Repeaters regenerate signals.",
      "examTip": "**Router = Network pathfinder** — directs traffic between networks."
    },
    {
      "id": 13,
      "question": "A company is implementing multifactor authentication (MFA). Which combination BEST represents MFA?",
      "options": [
        "Password and fingerprint scan",
        "Username and password",
        "Smart card and PIN",
        "Password and username"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MFA requires two or more authentication factors from different categories. A password (something you know) and fingerprint scan (something you are) fulfill this. Username/password is single-factor. Smart card/PIN is also MFA but less secure than biometrics.",
      "examTip": "**MFA = At least two factors** — something you know, have, or are."
    },
    {
      "id": 14,
      "question": "Which technology allows multiple VLANs to communicate without using a physical router?",
      "options": [
        "Router on a stick",
        "Layer 3 switch",
        "Trunk port",
        "Access port"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Layer 3 switches route traffic between VLANs without external routers. 'Router on a stick' uses a single physical router interface. Trunk ports carry multiple VLANs but don’t handle routing. Access ports belong to single VLANs.",
      "examTip": "**Layer 3 switch = Inter-VLAN routing** — routing at switch speed."
    },
    {
      "id": 15,
      "question": "Which of the following ensures that packets take the shortest path in a network using OSPF?",
      "options": [
        "Dijkstra algorithm",
        "Bellman-Ford algorithm",
        "BGP path selection",
        "Spanning Tree Protocol"
      ],
      "correctAnswerIndex": 0,
      "explanation": "OSPF uses the Dijkstra algorithm for shortest-path determination. Bellman-Ford is used by RIP. BGP uses path attributes. STP prevents Layer 2 loops, not routing decisions.",
      "examTip": "**OSPF = Dijkstra’s shortest path** — fast convergence, efficient routing."
    },
    {
      "id": 16,
      "question": "Which type of port is typically configured to carry traffic for multiple VLANs between switches?",
      "options": [
        "Trunk port",
        "Access port",
        "EtherChannel port",
        "SPAN port"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Trunk ports carry multiple VLANs across switches. Access ports handle single VLAN traffic. EtherChannel combines multiple links. SPAN ports mirror traffic for analysis.",
      "examTip": "**Trunk port = Multi-VLAN highway** — essential for VLAN communication across switches."
    },
    {
      "id": 17,
      "question": "Which addressing type delivers packets to all devices in a specific group but not to all devices on the network?",
      "options": [
        "Multicast",
        "Broadcast",
        "Unicast",
        "Anycast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Multicast delivers packets to multiple subscribed devices. Broadcast delivers to all devices in a segment. Unicast targets a single device. Anycast sends data to the nearest device in a group.",
      "examTip": "**Multicast = One-to-many** — efficient distribution to interested hosts only."
    },
    {
      "id": 18,
      "question": "Which technology is designed to prevent switching loops in a redundant Layer 2 network?",
      "options": [
        "Spanning Tree Protocol (STP)",
        "Link Aggregation Control Protocol (LACP)",
        "Virtual Router Redundancy Protocol (VRRP)",
        "Border Gateway Protocol (BGP)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "STP prevents Layer 2 loops by blocking redundant paths. LACP aggregates links. VRRP provides router redundancy. BGP routes between autonomous systems on the internet.",
      "examTip": "**STP = Loop prevention at Layer 2** — no loops, no broadcast storms."
    },
    {
      "id": 19,
      "question": "Which protocol uses port 3389 to provide remote graphical access to Windows machines?",
      "options": [
        "RDP",
        "SSH",
        "Telnet",
        "VNC"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RDP (Remote Desktop Protocol) uses port 3389 for remote graphical sessions on Windows. SSH provides secure CLI access. Telnet offers unencrypted CLI access. VNC offers graphical access but uses port 5900.",
      "examTip": "**RDP = Windows GUI remotely** — port 3389 for remote management."
    },
    {
      "id": 20,
      "question": "Which protocol provides dynamic routing between routers within an autonomous system using a hybrid approach combining distance-vector and link-state features?",
      "options": [
        "EIGRP",
        "RIP",
        "OSPF",
        "BGP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "EIGRP (Enhanced Interior Gateway Routing Protocol) is a Cisco proprietary protocol using a hybrid approach. RIP uses distance-vector. OSPF uses link-state. BGP manages routing between autonomous systems.",
      "examTip": "**EIGRP = Hybrid routing** — combines best of distance-vector and link-state."
    },
    {
      "id": 21,
      "question": "A technician needs to configure a firewall to allow secure web traffic from external users. Which port should be opened?",
      "options": [
        "443",
        "80",
        "22",
        "3389"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Port 443 is used for HTTPS, providing secure web traffic encryption. Port 80 is for HTTP (unencrypted). Port 22 is for SSH, and port 3389 is for RDP.",
      "examTip": "**Port 443 = Secure web access (HTTPS)** — always preferred over HTTP (port 80)."
    },
    {
      "id": 22,
      "question": "A network engineer is troubleshooting intermittent connectivity issues on a switch. The 'show interface' command reveals a high number of CRC errors. What is the MOST likely cause?",
      "options": [
        "Faulty cable or electromagnetic interference",
        "Duplex mismatch between switch and device",
        "Incorrect VLAN assignment",
        "Spanning Tree Protocol recalculations"
      ],
      "correctAnswerIndex": 0,
      "explanation": "CRC (Cyclic Redundancy Check) errors often indicate a faulty cable or EMI issues. Duplex mismatches cause late collisions. Incorrect VLAN assignments prevent communication but don’t cause CRC errors. STP recalculations cause temporary disruptions but not CRC errors.",
      "examTip": "**High CRC errors? Check cables first.** Replace or reroute away from EMI sources."
    },
    {
      "id": 23,
      "question": "Which routing protocol uses path vector attributes to determine the best path and is commonly used on the internet?",
      "options": [
        "BGP",
        "OSPF",
        "RIP",
        "EIGRP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BGP (Border Gateway Protocol) uses path vector attributes and is the standard for routing between autonomous systems on the internet. OSPF uses link-state algorithms. RIP uses hop count, and EIGRP is a Cisco proprietary hybrid protocol.",
      "examTip": "**BGP = The 'Postal Service' of the internet.** It routes between ISPs and large networks."
    },
    {
      "id": 24,
      "question": "A user can access internal network resources but cannot browse any external websites. The network administrator confirms that DNS servers are reachable. Which step should be performed NEXT?",
      "options": [
        "Check for proxy server configuration issues.",
        "Replace the Ethernet cable and retest.",
        "Verify local firewall settings for blocked ports.",
        "Clear the browser cache and cookies."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If DNS servers are reachable but external websites aren't loading, a misconfigured proxy server could block web traffic. Firewall issues would likely affect more than web browsing. The Ethernet cable and browser cache are less likely culprits given DNS connectivity.",
      "examTip": "**Web access issues with DNS OK? Check for proxy misconfigurations next.**"
    },
    {
      "id": 25,
      "question": "Which type of network device can act as a security measure by controlling which MAC addresses can connect to each port?",
      "options": [
        "Managed switch",
        "Router",
        "Unmanaged switch",
        "Load balancer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Managed switches can implement port security by specifying which MAC addresses are allowed per port. Routers control IP-based traffic. Unmanaged switches lack security features. Load balancers distribute traffic among servers.",
      "examTip": "**Managed switch = Control + Security.** Use MAC filtering for secure port access."
    },
    {
      "id": 26,
      "question": "Which wireless technology allows devices to seamlessly switch between access points without dropping the connection?",
      "options": [
        "Roaming",
        "Band steering",
        "Beamforming",
        "MU-MIMO"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Roaming allows wireless devices to move between access points without losing connectivity. Band steering directs clients to the optimal frequency. Beamforming focuses the Wi-Fi signal. MU-MIMO allows multiple devices to receive data simultaneously.",
      "examTip": "**Roaming = Continuous connectivity.** Essential for mobile users in large environments."
    },
    {
      "id": 27,
      "question": "A network administrator needs to ensure high availability of a critical database server by eliminating a single point of failure. Which solution would BEST achieve this?",
      "options": [
        "Configure a failover cluster.",
        "Increase server storage capacity.",
        "Implement VLAN segmentation.",
        "Enable jumbo frames for faster throughput."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Failover clusters provide redundancy by switching to a standby server if the primary fails. Increasing storage doesn’t improve availability. VLANs segment traffic but don’t provide redundancy. Jumbo frames improve throughput but not availability.",
      "examTip": "**Failover cluster = Always on.** No downtime if a server fails."
    },
    {
      "id": 28,
      "question": "Which IPv6 transition mechanism encapsulates IPv6 traffic within IPv4 packets for transmission across IPv4 networks?",
      "options": [
        "Tunneling",
        "Dual stack",
        "NAT64",
        "Anycast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Tunneling encapsulates IPv6 traffic inside IPv4 packets for compatibility. Dual stack runs IPv4 and IPv6 simultaneously. NAT64 translates IPv6 to IPv4. Anycast directs traffic to the nearest node in a group.",
      "examTip": "**Tunneling = IPv6 inside IPv4.** Great for gradual IPv6 deployment."
    },
    {
      "id": 29,
      "question": "A company’s firewall configuration allows traffic on port 80 but blocks port 443. Which service will NOT function properly?",
      "options": [
        "Secure web browsing (HTTPS)",
        "Regular web browsing (HTTP)",
        "Email access using IMAP",
        "Remote SSH access"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Port 443 is used for HTTPS (secure web browsing). HTTP uses port 80. IMAP typically uses port 143, and SSH uses port 22. Blocking port 443 prevents secure website access.",
      "examTip": "**No port 443? No HTTPS.** Always ensure 443 is open for secure web access."
    },
    {
      "id": 30,
      "question": "Which method would BEST secure data during transmission over an untrusted network such as the internet?",
      "options": [
        "Implementing IPSec VPN",
        "Using VLAN segmentation",
        "Enabling MAC filtering",
        "Applying static IP addresses"
      ],
      "correctAnswerIndex": 0,
      "explanation": "IPSec VPN encrypts data in transit, securing it over untrusted networks. VLANs segment internal traffic. MAC filtering secures wireless access locally. Static IPs don’t provide encryption or security in transit.",
      "examTip": "**IPSec VPN = Data encryption on the move.** Perfect for secure remote access."
    },
    {
      "id": 31,
      "question": "A user reports slow access to a network file share. Other users on the same network do not experience issues. Which is the MOST appropriate troubleshooting step?",
      "options": [
        "Check the user’s network cable and port connection.",
        "Restart the file server hosting the share.",
        "Reboot the network switch serving the user’s segment.",
        "Reconfigure the user’s TCP/IP settings."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Since the issue is isolated to one user, check the physical connection (cable and port). Restarting the file server or switch affects multiple users and should only be considered after verifying local issues. Reconfiguring TCP/IP settings might help but is less likely than a simple physical issue.",
      "examTip": "**Single-user network issues? Check local connections first.** Cables and ports often fail."
    },
    {
      "id": 32,
      "question": "Which of the following protocols is used to securely synchronize time across devices in a network?",
      "options": [
        "NTP with NTS",
        "SNMP",
        "FTP",
        "TFTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NTP with NTS (Network Time Security) securely synchronizes time across network devices. SNMP monitors network devices. FTP and TFTP transfer files but lack time synchronization features.",
      "examTip": "**NTP + NTS = Secure time sync.** Accurate logs and timestamps are critical for security."
    },
    {
      "id": 33,
      "question": "Which wireless standard supports the 6GHz frequency band and offers improved performance for dense environments?",
      "options": [
        "802.11ax (Wi-Fi 6E)",
        "802.11ac",
        "802.11n",
        "802.11g"
      ],
      "correctAnswerIndex": 0,
      "explanation": "802.11ax (Wi-Fi 6E) introduces support for the 6GHz band, improving performance in congested areas. 802.11ac supports 5GHz. 802.11n supports 2.4GHz and 5GHz. 802.11g operates at 2.4GHz only.",
      "examTip": "**Wi-Fi 6E = 6GHz + Efficiency.** Future-proof for high-density deployments."
    },
    {
      "id": 34,
      "question": "A network administrator needs to implement a method to prevent unauthorized devices from connecting to the corporate Wi-Fi. Which approach would be MOST effective?",
      "options": [
        "Implement WPA3-Enterprise with RADIUS authentication.",
        "Disable SSID broadcasting.",
        "Enable MAC address filtering.",
        "Configure a captive portal."
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3-Enterprise with RADIUS provides strong encryption and robust authentication, effectively preventing unauthorized access. Disabling SSID broadcast is easily bypassed. MAC filtering can be spoofed. Captive portals are suitable for guest networks but not robust for secure authentication.",
      "examTip": "**WPA3-Enterprise + RADIUS = Top-tier Wi-Fi security.** Don’t rely on obscurity (SSID hiding)."
    },
    {
      "id": 35,
      "question": "Which device aggregates multiple WAN connections and provides redundancy in case one link fails?",
      "options": [
        "Edge router with dual WAN capabilities",
        "Core switch with LACP",
        "Load balancer",
        "Firewall with NAT"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An edge router with dual WAN support aggregates multiple internet connections for redundancy. Core switches aggregate LAN connections. Load balancers distribute internal traffic among servers. Firewalls with NAT translate IP addresses but don’t aggregate WAN links.",
      "examTip": "**Edge router (dual WAN) = Internet failover protection.** Critical for business continuity."
    },
    {
      "id": 36,
      "question": "Which network topology provides the BEST fault tolerance but is the most expensive to implement?",
      "options": [
        "Mesh",
        "Star",
        "Bus",
        "Ring"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Mesh topology connects every node to every other node, offering high fault tolerance. Star topology relies on a central node. Bus topology uses a single cable, and Ring connects devices in a loop—both offering lower fault tolerance.",
      "examTip": "**Mesh = Maximum redundancy, maximum cost.** Use where downtime is unacceptable."
    },
    {
      "id": 37,
      "question": "A technician needs to trace a network cable from a user's workstation to the network switch in the server room. Which tool would BEST accomplish this?",
      "options": [
        "Toner probe",
        "Cable tester",
        "Loopback plug",
        "Optical power meter"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A toner probe sends a tone through a cable, which can be detected to trace the cable’s path. Cable testers check for continuity and wiring issues. Loopback plugs test network ports. Optical power meters measure signal strength in fiber optic cables.",
      "examTip": "**Toner probe = Cable detective.** Essential for physical layer tracing."
    },
    {
      "id": 38,
      "question": "Which service is responsible for translating private IP addresses to a public IP address for internet access?",
      "options": [
        "NAT",
        "DHCP",
        "DNS",
        "SNMP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NAT (Network Address Translation) translates private IP addresses into a public IP, allowing internet access. DHCP assigns IP addresses. DNS resolves domain names. SNMP monitors network devices.",
      "examTip": "**NAT = Private to public translator.** Enables internet access for private networks."
    },
    {
      "id": 39,
      "question": "Which wireless technology allows multiple clients to transmit simultaneously, increasing overall network efficiency?",
      "options": [
        "MU-MIMO",
        "Beamforming",
        "Roaming",
        "Band steering"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MU-MIMO (Multi-User, Multiple Input, Multiple Output) allows multiple devices to receive and transmit data simultaneously. Beamforming focuses signal strength. Roaming ensures seamless transitions between APs. Band steering optimizes frequency usage.",
      "examTip": "**MU-MIMO = More users, more throughput.** Essential for high-density networks."
    },
    {
      "id": 40,
      "question": "Which protocol would BEST be used to securely administer network devices from a remote location?",
      "options": [
        "SSH",
        "Telnet",
        "HTTP",
        "FTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH (Secure Shell) provides encrypted remote administration. Telnet is insecure. HTTP is used for web traffic without encryption. FTP transfers files but lacks secure administration features.",
      "examTip": "**SSH = Secure remote management.** Always use SSH over Telnet for admin access."
    },
    {
      "id": 41,
      "question": "A user reports that they can connect to local network resources but cannot access the internet. Which of the following is the MOST likely cause?",
      "options": [
        "Incorrect default gateway setting",
        "Duplicate IP address on the network",
        "DNS server misconfiguration",
        "Local firewall blocking outbound traffic"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The default gateway routes traffic from the local network to external networks. If it’s incorrect, internet access will fail. A duplicate IP would cause intermittent issues. DNS misconfiguration would still allow access by IP. A local firewall blocking outbound traffic would prevent all internet activity, but gateway issues are the most common cause.",
      "examTip": "**No internet, local OK? Check the default gateway.** It's the bridge to the outside world."
    },
    {
      "id": 42,
      "question": "Which protocol enables secure communication between a web browser and a web server by encrypting HTTP traffic?",
      "options": [
        "HTTPS",
        "SSH",
        "IPSec",
        "TLS"
      ],
      "correctAnswerIndex": 0,
      "explanation": "HTTPS (HTTP Secure) uses TLS/SSL to encrypt HTTP traffic, securing data between browser and server. SSH secures terminal sessions. IPSec secures network-level data. TLS provides encryption for various applications, but HTTPS specifically secures web traffic.",
      "examTip": "**HTTPS = Secure web traffic.** Always prefer HTTPS over HTTP for data protection."
    },
    {
      "id": 43,
      "question": "A technician is troubleshooting slow file transfers between two network segments. Which feature on a switch would MOST likely improve performance?",
      "options": [
        "Enabling jumbo frames",
        "Implementing port mirroring",
        "Configuring spanning tree protocol",
        "Disabling QoS settings"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Jumbo frames allow larger packets to be transmitted, reducing overhead and improving throughput for large file transfers. Port mirroring is for monitoring. STP prevents loops but doesn't enhance performance. Disabling QoS would remove traffic prioritization, potentially worsening performance.",
      "examTip": "**Large files + slow transfer? Enable jumbo frames.** Bigger packets, less overhead."
    },
    {
      "id": 44,
      "question": "Which protocol is responsible for dynamic assignment of IP addresses and related configuration to network devices?",
      "options": [
        "DHCP",
        "DNS",
        "NAT",
        "SNMP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DHCP (Dynamic Host Configuration Protocol) automatically assigns IP addresses and network configurations. DNS resolves domain names. NAT translates private IP addresses for internet access. SNMP monitors and manages network devices.",
      "examTip": "**DHCP = Plug-and-play IP.** No manual configuration needed."
    },
    {
      "id": 45,
      "question": "A network engineer needs to reduce the size of routing tables in a large IPv6 deployment. Which technique should be used?",
      "options": [
        "Route aggregation",
        "Tunneling",
        "Dual stack implementation",
        "Anycast addressing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Route aggregation combines multiple routes into a single entry, reducing routing table size. Tunneling encapsulates traffic. Dual stack runs IPv4 and IPv6 simultaneously. Anycast directs traffic to the nearest node but doesn’t reduce routing table size.",
      "examTip": "**Route aggregation = Smaller tables, faster routing.** Efficiency matters in large networks."
    },
    {
      "id": 46,
      "question": "Which wireless security protocol uses AES encryption and is considered the most secure for modern networks?",
      "options": [
        "WPA3",
        "WPA2",
        "WPA",
        "WEP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3 provides robust AES encryption and enhanced protections against brute-force attacks. WPA2 uses AES but lacks WPA3's improvements. WPA and WEP are outdated and vulnerable.",
      "examTip": "**WPA3 = Latest, greatest Wi-Fi security.** Always use when supported."
    },
    {
      "id": 47,
      "question": "Which port does Secure Shell (SSH) use for encrypted remote access?",
      "options": [
        "22",
        "23",
        "443",
        "80"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH uses port 22 for secure remote command-line access. Telnet (port 23) is unencrypted. Port 443 is for HTTPS, and port 80 is for HTTP.",
      "examTip": "**SSH = Secure CLI = Port 22.** Ditch Telnet; encrypt your sessions."
    },
    {
      "id": 48,
      "question": "A technician observes frequent network loops causing outages. Which protocol would MOST likely prevent this issue?",
      "options": [
        "Spanning Tree Protocol (STP)",
        "Dynamic Host Configuration Protocol (DHCP)",
        "Border Gateway Protocol (BGP)",
        "Routing Information Protocol (RIP)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "STP prevents Layer 2 network loops by placing redundant paths into a blocking state. DHCP assigns IPs. BGP and RIP are routing protocols and do not address Layer 2 loops.",
      "examTip": "**STP = No loops, no storms.** Crucial for redundant switch topologies."
    },
    {
      "id": 49,
      "question": "Which device forwards packets based on MAC addresses and operates primarily at the data link layer?",
      "options": [
        "Switch",
        "Router",
        "Hub",
        "Firewall"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Switches operate at Layer 2, forwarding traffic based on MAC addresses. Routers operate at Layer 3 using IP addresses. Hubs broadcast all traffic, and firewalls filter traffic based on rules.",
      "examTip": "**Switch = Smarter than a hub.** Knows where devices live via MAC addresses."
    },
    {
      "id": 50,
      "question": "Which IPv6 address type allows communication with all devices on the local network segment?",
      "options": [
        "Link-local address",
        "Global unicast address",
        "Multicast address",
        "Anycast address"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Link-local addresses (starting with FE80::) enable communication on the same link. Global unicast addresses are routable on the internet. Multicast sends to multiple recipients. Anycast routes to the nearest node.",
      "examTip": "**FE80:: = Link-local IPv6.** Local comms only, no routing needed."
    },
    {
      "id": 51,
      "question": "Which technology allows for logical network segmentation within a physical network infrastructure?",
      "options": [
        "VLAN",
        "VPN",
        "NAT",
        "QoS"
      ],
      "correctAnswerIndex": 0,
      "explanation": "VLANs segment networks logically within the same physical infrastructure. VPNs secure remote connections. NAT translates private IPs for external access. QoS prioritizes certain types of traffic.",
      "examTip": "**VLAN = Segmentation without extra hardware.** Improves security and performance."
    },
    {
      "id": 52,
      "question": "Which protocol provides secure file transfers and operates over port 22?",
      "options": [
        "SFTP",
        "FTP",
        "TFTP",
        "HTTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SFTP (SSH File Transfer Protocol) runs over SSH on port 22, providing secure file transfers. FTP (ports 20/21) and TFTP (port 69) lack encryption. HTTP (port 80) is for web traffic, not file transfers.",
      "examTip": "**SFTP = Secure FTP.** Think SSH + File Transfer (port 22)."
    },
    {
      "id": 53,
      "question": "A technician needs to check if the default gateway is reachable. Which command would BEST accomplish this?",
      "options": [
        "ping",
        "traceroute",
        "netstat",
        "nslookup"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'ping' tests network connectivity, making it ideal for checking gateway reachability. 'traceroute' shows the path packets take. 'netstat' displays network statistics. 'nslookup' resolves DNS queries.",
      "examTip": "**ping = Quick connectivity check.** Always test the gateway first in network issues."
    },
    {
      "id": 54,
      "question": "Which protocol is responsible for ensuring accurate time synchronization across network devices?",
      "options": [
        "NTP",
        "SNMP",
        "FTP",
        "DHCP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NTP (Network Time Protocol) synchronizes time across network devices. SNMP monitors network devices. FTP transfers files. DHCP assigns IP configurations.",
      "examTip": "**NTP = Accurate clocks, accurate logs.** Time sync is crucial for security and analysis."
    },
    {
      "id": 55,
      "question": "Which port is used by the Remote Desktop Protocol (RDP) for secure remote access to Windows systems?",
      "options": [
        "3389",
        "22",
        "443",
        "110"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RDP uses port 3389 for secure remote desktop access. SSH uses port 22, HTTPS uses port 443, and port 110 is for POP3 email retrieval.",
      "examTip": "**RDP = Remote Windows GUI.** Remember port 3389 for remote management."
    },
    {
      "id": 56,
      "question": "Which addressing scheme allows multiple networks to share the same IP range without conflict by using different subnet masks?",
      "options": [
        "VLSM",
        "CIDR",
        "NAT",
        "IPv6"
      ],
      "correctAnswerIndex": 0,
      "explanation": "VLSM (Variable Length Subnet Mask) allows subnet masks of varying sizes in the same network, promoting efficient IP use. CIDR aggregates IP routes. NAT translates addresses, and IPv6 provides an expanded address space but not variable subnetting.",
      "examTip": "**VLSM = Flexible subnetting.** Optimize IP usage based on network needs."
    },
    {
      "id": 57,
      "question": "Which protocol is commonly used for secure remote login and file transfers, ensuring encryption during transmission?",
      "options": [
        "SSH",
        "Telnet",
        "FTP",
        "HTTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH provides secure, encrypted access and file transfers. Telnet is unencrypted. FTP transfers files without encryption. HTTP serves unencrypted web traffic.",
      "examTip": "**SSH = Secure remote access.** Always use SSH instead of Telnet for security."
    },
    {
      "id": 58,
      "question": "Which tool would BEST help a technician capture and analyze network traffic to identify potential issues?",
      "options": [
        "Protocol analyzer",
        "Cable tester",
        "Toner probe",
        "Loopback adapter"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A protocol analyzer captures and analyzes network traffic for troubleshooting. Cable testers check cable integrity. Toner probes trace cables. Loopback adapters test port functionality.",
      "examTip": "**Protocol analyzer = Deep network insights.** Identify bottlenecks and malicious traffic."
    },
    {
      "id": 59,
      "question": "Which IPv6 feature allows both IPv4 and IPv6 to operate on the same network for compatibility during migration?",
      "options": [
        "Dual stack",
        "Tunneling",
        "NAT64",
        "Multicast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Dual stack allows IPv4 and IPv6 to coexist. Tunneling encapsulates IPv6 traffic in IPv4. NAT64 translates IPv6 to IPv4. Multicast delivers packets to multiple recipients but doesn’t address protocol compatibility.",
      "examTip": "**Dual stack = Seamless IPv6 transition.** Run both protocols simultaneously."
    },
    {
      "id": 60,
      "question": "Which wireless technology allows a client device to connect to the strongest available access point without user intervention?",
      "options": [
        "Roaming",
        "Beamforming",
        "MU-MIMO",
        "Band steering"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Roaming ensures that a device stays connected by switching to the strongest available access point automatically. Beamforming enhances signal strength in a specific direction. MU-MIMO allows multiple devices to communicate simultaneously. Band steering pushes clients to optimal frequency bands.",
      "examTip": "**Roaming = Stay connected on the move.** Crucial for seamless mobility in Wi-Fi networks."
    },
    {
      "id": 61,
      "question": "Which routing protocol uses administrative distance and metrics such as hop count to determine the best path for data?",
      "options": [
        "RIP",
        "OSPF",
        "BGP",
        "EIGRP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RIP (Routing Information Protocol) uses hop count as its metric and has a higher administrative distance, making it less efficient for large networks. OSPF uses link-state information, BGP uses path vector, and EIGRP uses a composite metric combining bandwidth and delay.",
      "examTip": "**RIP = Simple routing, hop count-based.** Good for small networks, but slow to converge."
    },
    {
      "id": 62,
      "question": "A network technician wants to verify the path packets take from a local machine to a remote server. Which command should they use?",
      "options": [
        "traceroute",
        "ping",
        "ipconfig",
        "nslookup"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'traceroute' (or 'tracert' in Windows) shows each hop along the packet’s path to the destination. 'ping' tests connectivity. 'ipconfig' displays IP settings. 'nslookup' queries DNS for name resolution.",
      "examTip": "**traceroute = Path tester.** Identify delays and failures hop by hop."
    },
    {
      "id": 63,
      "question": "Which network topology connects each device to a central hub or switch, making it easy to isolate issues?",
      "options": [
        "Star",
        "Mesh",
        "Bus",
        "Ring"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A star topology connects all devices to a central device, making troubleshooting straightforward. Mesh topologies offer redundancy but are expensive. Bus topologies share a single backbone, and Ring topologies connect devices in a closed loop.",
      "examTip": "**Star = Easy troubleshooting.** One cable or port down? Only one device affected."
    },
    {
      "id": 64,
      "question": "Which IPv6 address type is similar to IPv4 public addresses and is globally routable on the internet?",
      "options": [
        "Global unicast",
        "Link-local",
        "Unique local",
        "Multicast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Global unicast addresses in IPv6 are similar to IPv4 public addresses and are globally routable. Link-local addresses are only for local communication. Unique local addresses are similar to IPv4 private addresses. Multicast sends packets to multiple devices in a group.",
      "examTip": "**Global unicast = IPv6’s public IP.** Used for internet-accessible devices."
    },
    {
      "id": 65,
      "question": "A technician needs to identify the MAC address associated with a specific IP address on a local network. Which command should they use?",
      "options": [
        "arp -a",
        "ipconfig",
        "ping",
        "netstat"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'arp -a' displays the ARP table, showing IP-to-MAC address mappings. 'ipconfig' shows IP configurations. 'ping' checks connectivity. 'netstat' displays network connections and listening ports.",
      "examTip": "**arp -a = MAC-IP mapping.** Essential for Layer 2 troubleshooting."
    },
    {
      "id": 66,
      "question": "Which type of attack involves redirecting legitimate web traffic to malicious websites by altering DNS records?",
      "options": [
        "DNS poisoning",
        "ARP spoofing",
        "Man-in-the-middle",
        "DDoS"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DNS poisoning corrupts DNS records, redirecting traffic to malicious sites. ARP spoofing associates an attacker's MAC address with a legitimate IP. Man-in-the-middle intercepts communications. DDoS overwhelms systems with traffic.",
      "examTip": "**DNS poisoning = Misdirection attack.** Always use DNSSEC to secure DNS queries."
    },
    {
      "id": 67,
      "question": "Which port is used by Simple Network Management Protocol (SNMP) to send traps?",
      "options": [
        "162",
        "161",
        "443",
        "514"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SNMP uses port 162 for traps (notifications) and port 161 for general queries. Port 443 is for HTTPS. Port 514 is used by syslog for log management.",
      "examTip": "**SNMP traps = Port 162.** Queries on 161, traps on 162 — remember them together."
    },
    {
      "id": 68,
      "question": "Which cable type is MOST appropriate for a 10 Gbps connection over a short distance within a data center?",
      "options": [
        "Direct Attach Copper (DAC)",
        "Single-mode fiber",
        "Coaxial cable",
        "Cat 5e Ethernet"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DAC cables provide cost-effective, short-distance 10 Gbps connections in data centers. Single-mode fiber is used for long distances. Coaxial cables are outdated for high-speed data center applications. Cat 5e supports up to 1 Gbps, not 10 Gbps.",
      "examTip": "**DAC = Short-distance, high-speed.** Ideal for rack-to-rack server connectivity."
    },
    {
      "id": 69,
      "question": "Which wireless frequency band provides better penetration through walls but offers lower maximum data rates?",
      "options": [
        "2.4GHz",
        "5GHz",
        "6GHz",
        "60GHz"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 2.4GHz band provides better coverage and wall penetration but at lower speeds. 5GHz and 6GHz provide higher data rates with shorter range. 60GHz offers ultra-high speeds but with extremely limited range.",
      "examTip": "**2.4GHz = Range over speed.** Best for wider coverage, even through walls."
    },
    {
      "id": 70,
      "question": "A network administrator needs to allow external users to access a web application securely. Which port should be opened on the firewall?",
      "options": [
        "443",
        "80",
        "21",
        "3389"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Port 443 is used for HTTPS, ensuring secure web communications. Port 80 is HTTP (unencrypted). Port 21 is for FTP, and port 3389 is for RDP.",
      "examTip": "**HTTPS = Port 443.** Always enable 443 for secure web applications."
    },
    {
      "id": 71,
      "question": "Which cloud service model provides customers with the highest level of control over the operating system and deployed applications?",
      "options": [
        "IaaS",
        "PaaS",
        "SaaS",
        "FaaS"
      ],
      "correctAnswerIndex": 0,
      "explanation": "IaaS (Infrastructure as a Service) provides virtualized computing resources, allowing users to manage the OS and applications. PaaS provides a platform for development. SaaS offers ready-to-use applications. FaaS handles serverless functions.",
      "examTip": "**IaaS = Full control of infrastructure.** Manage your own OS, middleware, and apps."
    },
    {
      "id": 72,
      "question": "Which type of IPv6 address allows communication with all devices in a specific group simultaneously?",
      "options": [
        "Multicast",
        "Anycast",
        "Global unicast",
        "Link-local"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Multicast addresses allow communication with multiple devices in a specified group. Anycast sends data to the nearest device in a group. Global unicast addresses are publicly routable. Link-local addresses are limited to local network segments.",
      "examTip": "**Multicast = Efficient one-to-many communication.** Ideal for streaming and conferencing."
    },
    {
      "id": 73,
      "question": "Which protocol encrypts and secures data transmitted over a VPN connection at the network layer?",
      "options": [
        "IPSec",
        "SSL",
        "TLS",
        "GRE"
      ],
      "correctAnswerIndex": 0,
      "explanation": "IPSec secures VPN traffic at the network layer using encryption and authentication. SSL and TLS secure higher-layer communications like web traffic. GRE provides tunneling but lacks encryption.",
      "examTip": "**IPSec = Secure VPN tunnels.** Encrypts data at the network layer for strong protection."
    },
    {
      "id": 74,
      "question": "Which layer of the OSI model is responsible for reliable transmission of data segments and error correction?",
      "options": [
        "Transport layer",
        "Network layer",
        "Data link layer",
        "Application layer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The Transport layer (Layer 4) ensures reliable transmission and error correction (TCP). The Network layer handles IP addressing and routing. The Data Link layer manages MAC addressing. The Application layer provides services to end users.",
      "examTip": "**Transport layer = Reliability + error checking.** Think TCP vs. UDP at Layer 4."
    },
    {
      "id": 75,
      "question": "A technician suspects a faulty network cable. Which tool should they use to check for continuity and proper wiring?",
      "options": [
        "Cable tester",
        "Toner probe",
        "Wi-Fi analyzer",
        "Loopback plug"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A cable tester checks for continuity, shorts, and proper wiring. A toner probe traces cables. A Wi-Fi analyzer checks wireless networks. A loopback plug tests network interface ports.",
      "examTip": "**Cable tester = Physical layer troubleshooting.** First stop for connectivity issues."
    },
    {
      "id": 76,
      "question": "Which addressing type sends traffic from one host to the nearest instance of multiple possible receivers?",
      "options": [
        "Anycast",
        "Unicast",
        "Broadcast",
        "Multicast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Anycast routes data to the nearest node among multiple recipients. Unicast targets one recipient. Broadcast sends to all devices in a segment. Multicast sends to a group of interested hosts.",
      "examTip": "**Anycast = Nearest responder wins.** Ideal for load balancing and redundancy."
    },
    {
      "id": 77,
      "question": "Which protocol uses port 5060 for unencrypted signaling in VoIP communications?",
      "options": [
        "SIP",
        "RTP",
        "H.323",
        "MGCP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SIP (Session Initiation Protocol) uses port 5060 for unencrypted signaling. RTP handles media streams. H.323 is another VoIP protocol. MGCP manages VoIP gateways.",
      "examTip": "**SIP = Starts the call.** Port 5060 for unencrypted, 5061 for encrypted signaling."
    },
    {
      "id": 78,
      "question": "Which protocol securely resolves domain names to IP addresses using encryption over HTTPS?",
      "options": [
        "DoH",
        "DNSSEC",
        "NTP",
        "SNMP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DoH (DNS over HTTPS) encrypts DNS queries using HTTPS. DNSSEC ensures integrity but not encryption. NTP synchronizes time, and SNMP monitors devices.",
      "examTip": "**DoH = Private DNS lookups.** Encrypts queries to prevent eavesdropping."
    },
    {
      "id": 79,
      "question": "Which cloud model is operated solely for a single organization, either on-premises or hosted by a third party?",
      "options": [
        "Private cloud",
        "Public cloud",
        "Hybrid cloud",
        "Community cloud"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Private clouds are dedicated to one organization. Public clouds are shared services. Hybrid clouds combine private and public elements. Community clouds are shared by several organizations with common goals.",
      "examTip": "**Private cloud = Full control, full responsibility.** Best for sensitive data and compliance."
    },
    {
      "id": 80,
      "question": "Which wireless security feature forces clients to re-authenticate after a set period, enhancing overall network security?",
      "options": [
        "Session timeout",
        "MAC filtering",
        "SSID hiding",
        "WPA2-Enterprise"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Session timeout forces clients to re-authenticate after a specified period, reducing the risk of unauthorized access. MAC filtering can be spoofed. SSID hiding offers minimal security. WPA2-Enterprise provides robust authentication but does not inherently include session timeout.",
      "examTip": "**Session timeout = Periodic re-authentication.** Reduces risks from unattended sessions."
    },
    {
      "id": 81,
      "question": "Which network monitoring technology would BEST detect unauthorized changes to device configurations in real-time?",
      "options": [
        "Configuration management system",
        "Flow-based monitoring",
        "Packet capture analysis",
        "Port mirroring"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Configuration management systems track device configurations and alert administrators to unauthorized changes. Flow-based monitoring tracks traffic patterns. Packet captures analyze traffic but do not monitor configurations. Port mirroring sends copies of traffic for analysis but not for config changes.",
      "examTip": "**Configuration management = Consistency + Security.** Detect unauthorized changes instantly."
    },
    {
      "id": 82,
      "question": "Which wireless authentication method requires a username and password and typically uses RADIUS for authentication?",
      "options": [
        "WPA2-Enterprise",
        "WPA2-Personal",
        "WPA3-Personal",
        "WEP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA2-Enterprise uses RADIUS for authentication and requires credentials (username/password). WPA2-Personal and WPA3-Personal use a pre-shared key (PSK). WEP is outdated and insecure.",
      "examTip": "**WPA2-Enterprise = Enterprise-grade security.** Use RADIUS for centralized user management."
    },
    {
      "id": 83,
      "question": "Which type of DNS record is used to define an alias for an existing domain name?",
      "options": [
        "CNAME",
        "A",
        "MX",
        "PTR"
      ],
      "correctAnswerIndex": 0,
      "explanation": "CNAME records map an alias to a canonical name. 'A' records map a domain to an IPv4 address. MX records define mail servers. PTR records map an IP to a domain for reverse lookups.",
      "examTip": "**CNAME = Alias mapping.** Use for pointing multiple names to one server."
    },
    {
      "id": 84,
      "question": "Which protocol operates at the transport layer and ensures reliable data delivery using acknowledgments and retransmissions?",
      "options": [
        "TCP",
        "UDP",
        "ICMP",
        "IGMP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "TCP (Transmission Control Protocol) ensures reliable data delivery through acknowledgments and retransmissions. UDP is faster but unreliable. ICMP handles diagnostics (e.g., ping). IGMP manages multicast groups.",
      "examTip": "**TCP = Reliable but slower.** Think acknowledgments, sessions, and data integrity."
    },
    {
      "id": 85,
      "question": "A network administrator needs to ensure that specific VoIP traffic is given higher priority over other traffic. Which solution should be implemented?",
      "options": [
        "Quality of Service (QoS)",
        "Spanning Tree Protocol (STP)",
        "Virtual LANs (VLANs)",
        "Link Aggregation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "QoS prioritizes traffic based on type, ensuring VoIP packets get higher priority. STP prevents network loops. VLANs segment traffic but don’t prioritize it. Link aggregation combines ports for increased bandwidth.",
      "examTip": "**QoS = Prioritize what matters.** Essential for latency-sensitive apps like VoIP."
    },
    {
      "id": 86,
      "question": "Which IPv6 feature allows an organization to route traffic efficiently by summarizing multiple network prefixes?",
      "options": [
        "Route aggregation",
        "Dual stack",
        "Anycast addressing",
        "Tunneling"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Route aggregation summarizes multiple routes into one, reducing routing table size. Dual stack allows simultaneous IPv4/IPv6. Anycast directs traffic to the nearest recipient. Tunneling encapsulates traffic for cross-protocol transmission.",
      "examTip": "**Route aggregation = Simplified routing.** Reduce complexity, increase speed."
    },
    {
      "id": 87,
      "question": "Which security mechanism ensures that only authorized devices can access network ports by verifying user credentials before granting access?",
      "options": [
        "802.1X",
        "MAC filtering",
        "Port mirroring",
        "Network Address Translation (NAT)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "802.1X provides port-based authentication using credentials. MAC filtering can be spoofed. Port mirroring is for traffic analysis. NAT translates IP addresses but doesn’t control access.",
      "examTip": "**802.1X = Access control at the port.** Authenticate before connect."
    },
    {
      "id": 88,
      "question": "Which command would BEST help determine if a device has a valid route to a specified network?",
      "options": [
        "traceroute",
        "ping",
        "arp",
        "ipconfig"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'traceroute' shows each hop along a network path, confirming routing. 'ping' tests connectivity but not routing. 'arp' shows MAC-to-IP mappings. 'ipconfig' displays local network configuration.",
      "examTip": "**traceroute = Follow the path.** Identify where routing fails."
    },
    {
      "id": 89,
      "question": "Which routing protocol is considered the standard for routing between autonomous systems on the internet?",
      "options": [
        "BGP",
        "RIP",
        "EIGRP",
        "OSPF"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BGP (Border Gateway Protocol) is used for routing between autonomous systems. RIP uses hop counts and is limited to smaller networks. EIGRP is proprietary to Cisco. OSPF is used within large enterprises but not typically between autonomous systems.",
      "examTip": "**BGP = The Internet’s routing backbone.** Handles large-scale routing decisions."
    },
    {
      "id": 90,
      "question": "Which protocol helps prevent Layer 2 loops in Ethernet networks by dynamically disabling redundant paths?",
      "options": [
        "Spanning Tree Protocol (STP)",
        "Link Aggregation Control Protocol (LACP)",
        "Virtual Router Redundancy Protocol (VRRP)",
        "Border Gateway Protocol (BGP)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "STP prevents Layer 2 loops by blocking redundant paths. LACP bundles links for redundancy and speed but doesn't prevent loops. VRRP ensures router redundancy. BGP routes between autonomous systems.",
      "examTip": "**STP = Loop prevention at Layer 2.** Keeps Ethernet networks stable."
    },
    {
      "id": 91,
      "question": "A technician needs to analyze traffic on a specific switch port without affecting the traffic flow. Which feature would BEST achieve this?",
      "options": [
        "Port mirroring",
        "Link aggregation",
        "Trunk port configuration",
        "Spanning tree recalibration"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Port mirroring copies traffic from one port to another for monitoring without interrupting the original flow. Link aggregation combines links for performance. Trunk ports carry multiple VLANs. STP recalibration prevents loops but disrupts network temporarily.",
      "examTip": "**Port mirroring = Non-intrusive traffic analysis.** Monitor without disruption."
    },
    {
      "id": 92,
      "question": "Which protocol is used to encrypt communication between email servers?",
      "options": [
        "SMTPS",
        "IMAP",
        "POP3",
        "FTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SMTPS (Secure SMTP) uses encryption to secure email transmission between servers. IMAP and POP3 are for retrieving emails. FTP is for file transfers and not related to email transmission.",
      "examTip": "**SMTPS = Secure email sending.** Always secure email transfers with encryption."
    },
    {
      "id": 93,
      "question": "Which protocol allows devices on a network to discover each other’s presence and share information about their capabilities?",
      "options": [
        "LLDP",
        "NTP",
        "SNMP",
        "DNS"
      ],
      "correctAnswerIndex": 0,
      "explanation": "LLDP (Link Layer Discovery Protocol) enables network devices to advertise their identity and capabilities. NTP synchronizes time. SNMP monitors network devices. DNS resolves domain names to IP addresses.",
      "examTip": "**LLDP = Network self-awareness.** Essential for mapping and troubleshooting."
    },
    {
      "id": 94,
      "question": "Which addressing method allows communication with a single unique recipient in IPv6?",
      "options": [
        "Unicast",
        "Multicast",
        "Anycast",
        "Broadcast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Unicast addresses deliver packets to a single recipient. Multicast delivers to multiple recipients. Anycast delivers to the nearest recipient in a group. IPv6 does not use broadcast addressing.",
      "examTip": "**Unicast = One-to-one communication.** Direct, targeted traffic flow."
    },
    {
      "id": 95,
      "question": "Which network device would MOST likely be configured to provide DHCP services in a small office network?",
      "options": [
        "Router",
        "Switch",
        "Firewall",
        "Hub"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Routers often include built-in DHCP servers in small networks. Switches forward traffic based on MAC addresses. Firewalls provide security but typically don’t assign IPs. Hubs broadcast all traffic indiscriminately.",
      "examTip": "**Router = DHCP in small offices.** Central hub for routing and IP assignment."
    },
    {
      "id": 96,
      "question": "Which port does the Secure File Transfer Protocol (SFTP) use for secure file transfers?",
      "options": [
        "22",
        "21",
        "80",
        "443"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SFTP uses port 22 as it runs over SSH for secure file transfers. FTP uses port 21 (unencrypted). Port 80 is for HTTP, and port 443 is for HTTPS.",
      "examTip": "**SFTP = Secure FTP over SSH.** Port 22 = Security guaranteed."
    },
    {
      "id": 97,
      "question": "Which tool would BEST allow a technician to check for open ports on a remote server?",
      "options": [
        "Nmap",
        "Wireshark",
        "Ping",
        "Tracert"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Nmap scans networks for open ports and services. Wireshark captures packets. Ping checks basic connectivity. Tracert shows routing paths.",
      "examTip": "**Nmap = Port scanner.** Check what services are running and accessible."
    },
    {
      "id": 98,
      "question": "Which network device uses rules to allow or deny traffic based on source and destination IP addresses and ports?",
      "options": [
        "Firewall",
        "Switch",
        "Router",
        "Hub"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Firewalls filter traffic based on IPs, ports, and protocols. Switches operate at Layer 2. Routers direct traffic between networks but don’t enforce filtering rules by default. Hubs lack intelligence and broadcast traffic.",
      "examTip": "**Firewall = Traffic control.** Gatekeeper for your network."
    },
    {
      "id": 99,
      "question": "Which of the following ensures that only traffic from trusted devices is permitted on a wireless network by verifying the device’s MAC address?",
      "options": [
        "MAC filtering",
        "WPA3 encryption",
        "Captive portal",
        "SSID hiding"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MAC filtering restricts access based on MAC addresses. WPA3 encrypts data but doesn’t filter by MAC. Captive portals require user authentication. SSID hiding only obscures the network’s visibility but doesn’t prevent access.",
      "examTip": "**MAC filtering = Basic device-level control.** Can be bypassed, so use with stronger security."
    },
    {
      "id": 100,
      "question": "Which cloud deployment model offers services shared by multiple organizations with similar requirements?",
      "options": [
        "Community cloud",
        "Private cloud",
        "Public cloud",
        "Hybrid cloud"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Community clouds serve multiple organizations with shared concerns. Private clouds are exclusive to one organization. Public clouds are available to the general public. Hybrid clouds combine private and public elements.",
      "examTip": "**Community cloud = Shared interests, shared infrastructure.** Ideal for partnerships and collaborations."
    }
  ]
});    
