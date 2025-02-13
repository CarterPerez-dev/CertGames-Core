db.tests.insertOne({
  "category": "nplus",
  "testId": 5,
  "testName": "Network+ Practice Test #5 (Intermediate)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A user reports intermittent connectivity to a specific website. You can ping the website's IP address consistently, but `tracert` shows varying paths and occasional packet loss. What is the MOST likely cause?",
      "options": [
        "A problem with the user's local network adapter.",
        "An issue with the website's DNS server.",
        "Network congestion or instability along the path to the website's server.",
        "A misconfigured firewall on the user's computer."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Consistent pings to the IP address rule out a *local* adapter or firewall issue, and successful pings also rule out a *complete* DNS failure.  Varying `tracert` paths and packet loss indicate a problem *between* the user and the website's server, most likely network congestion or an unstable route.",
      "examTip": "Use `tracert` to diagnose path-related network issues, not just complete failures."
    },
    {
      "id": 2,
      "question": "You are configuring a new switch and need to implement VLANs.  Which protocol is used to tag Ethernet frames with VLAN membership information?",
      "options": [
        "STP (Spanning Tree Protocol)",
        "VTP (VLAN Trunking Protocol)",
        "802.1Q",
        "LACP (Link Aggregation Control Protocol)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "802.1Q is the IEEE standard for VLAN tagging. It adds a tag to the Ethernet frame header that identifies the VLAN to which the frame belongs. STP prevents loops, VTP manages VLAN *databases* (not the tagging itself), and LACP is for link aggregation.",
      "examTip": "Remember 802.1Q as the standard for VLAN tagging."
    },
    {
      "id": 3,
      "question": "You need to connect two buildings located 800 meters apart.  Performance is critical, and the environment has high levels of electromagnetic interference (EMI). Which cabling type is the BEST choice?",
      "options": [
        "UTP Cat 6",
        "STP Cat 6a",
        "Multimode Fiber",
        "Single-mode Fiber"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Single-mode fiber is the best choice for long distances (800 meters exceeds multimode's typical range) and offers the highest bandwidth and complete immunity to EMI. UTP/STP are limited to 100 meters and susceptible to EMI. While multimode *could* reach, single-mode provides better performance and future-proofing.",
      "examTip": "Fiber optic cable is the best option for long distances and high-EMI environments."
    },
    {
      "id": 4,
      "question": "You are designing a network with multiple switches.  To prevent broadcast storms and ensure network stability, which protocol MUST be implemented?",
      "options": [
        "DHCP",
        "DNS",
        "STP (Spanning Tree Protocol)",
        "ARP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Spanning Tree Protocol (STP) is essential for preventing network loops in switched networks with redundant links. Loops can cause broadcast storms, which can cripple a network. DHCP assigns IP addresses, DNS resolves domain names, and ARP maps IPs to MAC addresses; none of these prevent loops.",
      "examTip": "STP is crucial for maintaining a stable switched network."
    },
    {
      "id": 5,
      "question": "A user complains that their VoIP calls are experiencing choppy audio and frequent drops.  Which network performance metric is MOST likely the cause?",
      "options": [
        "Bandwidth",
        "Latency",
        "Jitter",
        "Throughput"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Jitter is the variation in latency (delay) over time.  High jitter disrupts the consistent flow of data packets required for real-time applications like VoIP, causing choppy audio and dropped calls. Bandwidth is capacity, latency is overall delay, and throughput is the actual data transfer rate.",
      "examTip": "Monitor jitter when troubleshooting real-time application performance issues."
    },
    {
      "id": 6,
      "question": "You are configuring a router to connect your local network (192.168.1.0/24) to the internet. Your ISP has provided you with a single public IP address. Which technology MUST you use to allow multiple internal devices to share this public IP address?",
      "options":[
        "VLANs",
        "DHCP",
        "NAT (Network Address Translation)",
        "DNS"
      ],
      "correctAnswerIndex": 2,
      "explanation": "NAT translates private IP addresses (like 192.168.1.x) used within your local network to your single public IP address when communicating with the internet (and vice versa).  This conserves public IP addresses and provides a layer of security. VLANs segment networks, DHCP assigns IPs *locally*, and DNS resolves domain names.",
      "examTip": "NAT is essential for connecting private networks to the internet using a limited number of public IP addresses."

    },
    {
        "id": 7,
        "question":"What is a characteristic of an 'ad hoc' wireless network?",
        "options":[
          "It requires a central access point.",
          "It is a temporary, peer-to-peer connection between wireless devices, without a central access point.",
          "It provides strong security by default.",
          "It is used for large-scale wireless deployments."
        ],
        "correctAnswerIndex": 1,
        "explanation": "An ad hoc network is a decentralized wireless network where devices connect directly to each other without an access point. This is typically used for temporary connections, such as sharing files between two laptops. Ad hoc networks generally lack the security and management features of infrastructure-mode networks (which *do* use an AP).",
        "examTip": "Ad hoc networks are for temporary, peer-to-peer wireless connections."
    },
     {
        "id": 8,
        "question":"You are troubleshooting a network connectivity issue. You suspect a problem with the DNS server. Which command would you use on a Windows computer to clear the DNS resolver cache?",
        "options":[
            "ipconfig /release",
            "ipconfig /renew",
            "ipconfig /flushdns",
            "ipconfig /all"
        ],
        "correctAnswerIndex": 2,
        "explanation":"The `ipconfig /flushdns` command clears the local DNS resolver cache on a Windows computer. This forces the computer to query the DNS server again for name resolution, which can resolve issues caused by outdated or incorrect cached DNS entries. `/release` and `/renew` are for DHCP, and `/all` displays configuration.",
        "examTip":"Use `ipconfig /flushdns` to troubleshoot DNS resolution problems."
    },
    {
        "id": 9,
         "question": "Which of the following correctly describes the relationship between IP addresses and MAC addresses?",
        "options":[
            "IP addresses are physical addresses; MAC addresses are logical addresses.",
            "IP addresses are used for communication within a local network; MAC addresses are used for communication across networks.",
            "IP addresses are assigned dynamically; MAC addresses are assigned statically by the network administrator.",
            "IP addresses are used for routing between networks (Layer 3); MAC addresses are used for communication within a local network segment (Layer 2)."
        ],
        "correctAnswerIndex": 3,
        "explanation": "IP addresses are *logical* addresses used for routing data *between* networks (at the Network layer, Layer 3).  MAC addresses are *physical* addresses assigned to network interface cards and used for communication *within* a single network segment (at the Data Link layer, Layer 2).  While IP addresses *can* be static, they are often dynamic (DHCP). MAC addresses are *generally* static (though spoofing is possible).",
        "examTip": "IP addresses are for global routing; MAC addresses are for local delivery."
    },
     {
        "id": 10,
        "question": "You are configuring a firewall.  Which type of firewall inspects the state of network connections (e.g., TCP sessions) and makes filtering decisions based on both packet headers and connection context?",
        "options": [
          "Packet filtering firewall",
          "Stateful inspection firewall",
          "Proxy firewall",
          "Application-layer firewall"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Stateful inspection firewalls maintain a table of active connections and use this information to make more intelligent filtering decisions.  They can allow return traffic for established connections, providing better security than simple packet filters (which examine each packet in isolation). Proxy firewalls act as intermediaries, and application-layer firewalls inspect traffic at a higher level.",
        "examTip": "Stateful inspection provides more robust security than simple packet filtering."
    },
    {
      "id": 11,
      "question":"What is the purpose of using a 'subnet mask' in IP addressing?",
      "options":[
        "To encrypt network traffic.",
        "To identify the network portion and the host portion of an IP address, enabling routing and subnetting.",
        "To dynamically assign IP addresses to devices.",
        "To filter network traffic based on content."
      ],
      "correctAnswerIndex": 1,
      "explanation":"The subnet mask, used in conjunction with an IP address, defines which bits of the address represent the network and which bits represent the host. This is essential for determining whether two devices are on the same subnet and for routing traffic between networks.  It's *not* encryption, dynamic IP assignment (DHCP), or content filtering.",
      "examTip":"Subnet masks are fundamental to IP addressing and network segmentation."
    },
    {
        "id": 12,
        "question": "A small office network is experiencing slow performance.  The network uses a single, unmanaged hub to connect all devices.  What is the MOST likely cause of the slow performance, and what is the BEST solution?",
        "options":[
            "The internet connection is too slow; upgrade the internet service.",
            "The hub creates a single collision domain, causing frequent collisions and reducing efficiency; replace the hub with a switch.",
            "The computers have outdated network drivers; update the drivers.",
            "The network cable is too long; shorten the cable."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Hubs operate at Layer 1 and broadcast all traffic to every connected device, creating a single collision domain. This leads to frequent collisions, especially as the number of devices increases, significantly degrading performance. Replacing the hub with a *switch* (which operates at Layer 2 and forwards traffic only to the intended recipient) is the best solution. While internet speed, drivers, or cable length *could* be issues, the hub is the *most likely* bottleneck in this scenario.",
        "examTip":"Replace hubs with switches for improved network performance and efficiency."
    },
    {
        "id": 13,
         "question": "What is 'Quality of Service' (QoS) primarily used for in a network?",
        "options":[
           "To encrypt network traffic.",
            "To prioritize certain types of network traffic (e.g., voice, video) over others, ensuring critical applications receive adequate bandwidth and low latency.",
            "To automatically assign IP addresses to devices.",
            "To translate domain names to IP addresses."
        ],
        "correctAnswerIndex": 1,
        "explanation": "QoS allows network administrators to manage network resources and ensure that time-sensitive or high-priority applications receive the necessary performance, even during periods of network congestion. It's *not* encryption, IP assignment (DHCP), or DNS.",
        "examTip": "QoS is crucial for ensuring a good user experience for real-time applications."
    },
     {
        "id": 14,
         "question": "Which of the following is a characteristic of a 'mesh' network topology?",
        "options":[
          "All devices are connected to a central hub or switch.",
           "Devices are connected in a circular loop.",
           "Each device has multiple paths to other devices, providing high redundancy and fault tolerance.",
           "All devices are connected to a single, shared cable."
        ],
        "correctAnswerIndex": 2,
        "explanation":"Mesh networks offer excellent redundancy because each node has multiple connections to other nodes. If one link fails, traffic can be rerouted through alternative paths. This makes them highly resilient but also more complex to implement and manage.  Star uses a central device, ring uses a loop, and bus uses a single cable.",
        "examTip":"Mesh networks are often used in critical infrastructure where high availability is essential."
    },
     {
        "id": 15,
         "question": "What is the primary function of an 'intrusion prevention system' (IPS)?",
        "options":[
          "To assign IP addresses dynamically.",
           "To actively monitor network traffic for malicious activity and take steps to block or prevent it.",
           "To encrypt all network traffic.",
           "To translate domain names to IP addresses."
        ],
        "correctAnswerIndex": 1,
        "explanation": "An IPS goes beyond the *detection* capabilities of an IDS (Intrusion Detection System) by *actively* intervening to stop threats. It can drop malicious packets, reset connections, block traffic from specific sources, or even quarantine infected systems.  It's *not* about IP assignment (DHCP), encryption, or DNS.",
        "examTip": "An IPS is a proactive security measure that can prevent attacks from succeeding."
    },
     {
      "id": 16,
       "question": "You are configuring a wireless network.  Which of the following provides the STRONGEST security?",
       "options":[
        "WEP (Wired Equivalent Privacy)",
        "WPA (Wi-Fi Protected Access)",
        "WPA2 (Wi-Fi Protected Access 2) with AES encryption",
        "WPA3 (Wi-Fi Protected Access 3)"
       ],
       "correctAnswerIndex": 3,
       "explanation": "WPA3 is the latest and most secure wireless security protocol, offering improved encryption and protection against various attacks. WEP is extremely outdated and easily cracked. WPA is also vulnerable. WPA2 with AES is *better* than WPA and WEP, but WPA3 is *superior*.",
       "examTip": "Always use WPA3 if your devices and access point support it.  If not, use WPA2 with AES."
    },
     {
        "id": 17,
        "question": "What is the purpose of a 'virtual private network' (VPN)?",
        "options":[
          "To speed up your internet connection.",
          "To create a secure, encrypted tunnel over a public network (like the internet), allowing remote users to access private network resources and protecting data from eavesdropping.",
           "To block all incoming and outgoing network traffic.",
           "To automatically assign IP addresses to devices."
        ],
        "correctAnswerIndex": 1,
        "explanation":"A VPN encrypts your internet traffic and routes it through a secure server, masking your IP address and protecting your data, especially on public Wi-Fi. It allows remote access to private networks as if you were directly connected. It doesn't primarily speed up connections, block *all* traffic, or assign IP addresses (DHCP does that).",
        "examTip":"Use a VPN for secure remote access and to enhance your online privacy."
    },
     {
        "id": 18,
        "question":"What does 'MTU' stand for, and what does it define?",
        "options":[
            "Maximum Transfer Unit; the smallest packet size that can be transmitted on a network.",
            "Maximum Transmission Unit; the largest packet size that can be transmitted on a network without fragmentation.",
            "Minimum Transmission Unit; the smallest packet size that can be transmitted on a network.",
            "Media Transfer Unit; the type of cabling used on a network."
        ],
        "correctAnswerIndex": 1,
        "explanation":"MTU stands for Maximum Transmission Unit. It defines the largest data packet (in bytes) that can be transmitted over a network link without being fragmented.  If a packet exceeds the MTU, it must be broken down into smaller fragments, which can impact performance.",
        "examTip":"An incorrect MTU setting can cause network performance problems."
    },
      {
        "id": 19,
         "question": "Which of the following is a potential consequence of having duplicate IP addresses on a network?",
        "options":[
          "Improved network security.",
          "Increased network bandwidth.",
          "Network connectivity problems for the devices with the duplicate addresses, including intermittent connectivity or complete loss of communication.",
          "Faster internet speeds."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Each device on a TCP/IP network must have a unique IP address. If two devices have the same IP address, it creates a conflict, and neither device may be able to communicate reliably on the network. This does *not* improve security or bandwidth or increase internet speeds.",
        "examTip": "Use DHCP to avoid duplicate IP address conflicts, or carefully manage static IP assignments."
    },
    {
      "id": 20,
      "question": "You are troubleshooting a computer that cannot connect to the network.  The `ipconfig` command shows an IP address of 0.0.0.0.  What does this indicate?",
      "options":[
       "The computer has a static IP address configured.",
       "The computer has successfully obtained an IP address from a DHCP server.",
        "The computer has failed to obtain an IP address and has no valid network configuration.",
        "The computer is connected to the internet."
      ],
      "correctAnswerIndex": 2,
      "explanation": "An IP address of 0.0.0.0 indicates that the network interface has no valid IP address assigned. This usually means the computer failed to obtain an address from a DHCP server or has a problem with its network adapter configuration. It is *not* a static IP and doesn't indicate internet connectivity.",
      "examTip": "An IP address of 0.0.0.0 indicates a serious network configuration problem."
    },
     {
        "id": 21,
        "question": "Which of the following is a benefit of using fiber optic cable instead of copper cable?",
        "options":[
          "Fiber optic cable is less expensive.",
          "Fiber optic cable is easier to install.",
          "Fiber optic cable can transmit data over longer distances with less signal loss and is immune to electromagnetic interference (EMI).",
          "Fiber optic cable is more resistant to physical damage."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Fiber optic cable uses light signals instead of electrical signals, providing significant advantages: much higher bandwidth, longer transmission distances, and immunity to EMI.  However, it's generally *more* expensive and can be *more* complex to install and terminate than copper.  While *some* types are rugged, fiber can be *more* susceptible to damage from bending/breaking than *some* copper types.",
        "examTip": "Fiber is the preferred choice for high-speed, long-distance, and EMI-prone environments."
    },
    {
      "id": 22,
       "question": "What is the purpose of using a 'demilitarized zone' (DMZ) in a network?",
       "options":[
         "To provide a secure zone for internal servers and workstations.",
          "To create a separate network for wireless devices.",
          "To host publicly accessible servers (like web servers or email servers) while providing a buffer zone between the internet and the internal network, improving security.",
          "To act as a backup power source for network devices."
       ],
       "correctAnswerIndex": 2,
       "explanation": "A DMZ is a network segment that sits between the trusted internal network and the untrusted external network (the internet). It allows external users to access specific services (like web servers) without having direct access to the internal network, minimizing the risk of a successful attack compromising the entire internal network.",
       "examTip": "A DMZ is used to isolate publicly accessible servers from the internal network."
    },
     {
        "id": 23,
        "question":"What is a 'man-in-the-middle' (MitM) attack?",
        "options":[
            "An attempt to overwhelm a network or server with traffic.",
            "An attempt to trick users into revealing personal information.",
            "An attack where the attacker secretly intercepts and potentially alters communication between two parties who believe they are directly communicating with each other.",
            "An attempt to guess passwords by trying many different combinations."
        ],
        "correctAnswerIndex": 2,
        "explanation":"In a MitM attack, the attacker positions themselves between two communicating parties, allowing them to eavesdrop on the conversation, steal data, or even modify the communication.  It's *not* overwhelming traffic (DoS), tricking users (phishing), or password guessing (brute-force).",
        "examTip":"MitM attacks can be mitigated with strong encryption and secure protocols (like HTTPS)."
    },
    {
     "id": 24,
     "question":"What is 'network address translation' (NAT) primarily used for?",
     "options":[
       "To encrypt network traffic.",
       "To allow multiple devices on a private network to share a single public IP address when communicating with the internet, conserving IPv4 addresses.",
        "To assign IP addresses dynamically.",
        "To filter network traffic based on content."
     ],
     "correctAnswerIndex": 1,
     "explanation": "NAT translates private IP addresses (used within a local network) to a public IP address (used on the internet), and vice versa.  This allows many devices to share a single public IP address, which is crucial given the limited number of available IPv4 addresses.  It's *not* encryption, dynamic IP assignment (DHCP), or content filtering.",
     "examTip": "NAT is essential for connecting private networks to the internet and conserving IPv4 addresses."
    },
     {
       "id": 25,
       "question":"Which of the following is a characteristic of a 'stateful firewall' compared to a stateless packet filter?",
       "options":[
        "A stateful firewall only examines individual packets; a stateless packet filter tracks connection states.",
        "A stateful firewall tracks the state of network connections and makes filtering decisions based on both packet headers and connection context; a stateless packet filter examines each packet in isolation.",
        "A stateful firewall is less secure than a stateless packet filter.",
         "A stateful firewall is only used for wireless networks."
       ],
       "correctAnswerIndex": 1,
       "explanation": "Stateful firewalls maintain a table of active connections and use this information to make more intelligent filtering decisions. They can distinguish between legitimate return traffic for an established connection and unsolicited incoming traffic, providing better security than stateless packet filters, which examine each packet independently without considering the connection context. Stateful firewalls are *more* secure and used in *all* types of networks.",
       "examTip":"Stateful firewalls offer more robust security by considering the context of network connections."
    },
     {
      "id": 26,
      "question": "What is the purpose of a 'proxy server'?",
      "options":[
        "To assign IP addresses to devices automatically.",
        "To act as an intermediary between clients and other servers, providing services like caching, filtering, and security, often improving performance and controlling access.",
        "To translate domain names into IP addresses.",
         "To encrypt network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A proxy server sits between clients and other servers (often the internet). It can cache frequently accessed content (improving performance), filter web traffic (controlling access and enhancing security), and mask the client's IP address. It's *not* about IP assignment (DHCP), DNS, or *general* encryption (though proxies *can* be involved in SSL/TLS).",
      "examTip": "Proxy servers provide an additional layer of control, security, and performance optimization for network traffic."
    },
    {
        "id": 27,
        "question": "Which type of network device is used to create a wireless local area network (WLAN)?",
        "options": [
            "Switch",
            "Router",
            "Access Point (AP)",
            "Modem"
        ],
        "correctAnswerIndex": 2,
        "explanation": "An access point (AP) provides wireless connectivity to devices, allowing them to join a network (typically a wired network connected to the AP). Switches connect *wired* devices, routers connect *networks*, and modems connect to an ISP.",
        "examTip": "Access points are the foundation of Wi-Fi networks."
    },
    {
        "id": 28,
        "question": "You are configuring a new network interface card (NIC) on a server. You need to ensure it operates at the fastest possible speed and allows simultaneous sending and receiving of data. What settings should you configure?",
        "options": [
           "10 Mbps, Half-duplex",
           "100 Mbps, Half-duplex",
           "1000 Mbps (Gigabit), Full-duplex",
           "Auto-negotiate, Half-duplex"
        ],
        "correctAnswerIndex": 2, // Fixed - 1000Mbps is faster, and full duplex is needed
        "explanation": "For the fastest speed and simultaneous send/receive, you should choose 1000 Mbps (Gigabit Ethernet) and Full-duplex.  Auto-negotiate is *generally* recommended, but *only if* you're *certain* the connected device (usually a switch) *also* supports and is configured for auto-negotiation. For a *server* NIC, explicitly setting it is often preferred for reliability.",
        "examTip": "For optimal performance, use Gigabit Ethernet and Full-duplex whenever possible."
    },
    {
        "id": 29,
         "question": "What is the purpose of the `ping` command?",
        "options":[
          "To display the routing table.",
           "To test network connectivity to a remote host and measure round-trip time.",
           "To display detailed network interface configuration.",
           "To query DNS servers for information."
        ],
        "correctAnswerIndex": 1,
        "explanation": "`ping` sends ICMP Echo Request packets to a target host and listens for Echo Reply packets. This tests basic connectivity and measures the time it takes for packets to travel to the host and back. It's *not* for displaying routing tables, interface configurations, or querying DNS.",
        "examTip": "`ping` is a fundamental tool for network troubleshooting."
    },
    {
        "id": 30,
        "question":"What does 'DNS' stand for, and what is its primary function?",
        "options":[
            "Dynamic Network System; to assign IP addresses automatically.",
            "Domain Name System; to translate human-readable domain names (like google.com) into numerical IP addresses.",
            "Data Network Security; to encrypt network traffic.",
            "Digital Network Service; to provide internet access."
        ],
        "correctAnswerIndex": 1,
        "explanation":"DNS (Domain Name System) is like the internet's phone book. It translates the website names we use (e.g., google.com) into the IP addresses that computers use to communicate.  It's *not* about dynamic IP assignment (DHCP), security, or providing internet access.",
        "examTip":"Without DNS, we'd have to remember IP addresses instead of website names."
    },
       {
      "id": 31,
      "question": "A user reports they cannot access any websites. You check their computer and find they have a valid IP address, subnet mask, and default gateway.  What is the NEXT troubleshooting step you should take?",
      "options": [
        "Reinstall the user's web browser.",
        "Check the user's DNS server settings and test DNS resolution (e.g., using `nslookup` or `ping` to a known domain name).",
        "Replace the user's network cable.",
        "Reboot the user's computer."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Since the user has a valid IP configuration, the problem is likely *not* with the physical connection or basic IP settings.  The *next* logical step is to check DNS, as the inability to access *any* website by name strongly suggests a name resolution issue. While rebooting *might* help (and is always a good general step), checking DNS is more targeted. Reinstalling the browser is premature.",
      "examTip": "When troubleshooting web access problems, consider DNS after verifying basic IP connectivity."
    },
    {
      "id": 32,
      "question": "Which of the following is a characteristic of a 'virtual LAN' (VLAN)?",
      "options":[
        "It requires separate physical switches for each VLAN.",
         "It logically segments a physical network into multiple, isolated broadcast domains, even if devices are connected to the same physical switch.",
         "It increases the overall size of the broadcast domain.",
        "It is primarily used for wireless networks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "VLANs allow you to create logically separate networks on the *same* physical switch infrastructure.  This improves security, performance (by reducing broadcast traffic), and manageability. They *reduce* broadcast domain size, and while they *can* be used with wireless, they're *primarily* a wired networking technology.",
      "examTip": "VLANs are essential for network segmentation and security in switched networks."
    },
    {
       "id": 33,
       "question":"What is 'jitter' in network performance?",
       "options":[
        "The total amount of data that can be transmitted over a network connection.",
        "The time it takes for a data packet to travel from its source to its destination.",
        "The variation in delay (latency) between data packets, which can negatively impact real-time applications like VoIP and video conferencing.",
        "The number of devices connected to a network."
       ],
       "correctAnswerIndex": 2,
       "explanation":"Jitter is the inconsistency in latency over time.  It's not the total bandwidth, the overall delay (that's latency), or the number of devices. High jitter causes problems with real-time applications because packets arrive at irregular intervals, leading to choppy audio or video.",
       "examTip":"Monitor jitter when troubleshooting the quality of real-time applications."
    },
     {
      "id": 34,
       "question":"What is 'latency' in network performance?",
       "options":[
        "The amount of data that can be transmitted over a network connection.",
        "The time delay in data transmission across a network, measured as the time it takes for a packet to travel from source to destination.",
        "The number of devices connected to a network.",
        "The physical distance between two network devices."
       ],
       "correctAnswerIndex": 1,
       "explanation":"Latency is the time it takes for data to travel from one point to another on a network. High latency can cause slow response times and negatively impact the user experience, especially for interactive applications. It's *not* bandwidth (capacity), device count, or physical distance (though distance *contributes* to latency).",
       "examTip":"Low latency is crucial for responsive network applications."
    },
      {
      "id": 35,
       "question": "Which of the following is a security best practice for managing network devices?",
       "options":[
        "Using default usernames and passwords.",
        "Leaving all ports open on firewalls.",
        "Regularly updating device firmware to patch security vulnerabilities and disabling unnecessary services.",
        "Sharing administrative passwords with all users."
       ],
       "correctAnswerIndex": 2,
       "explanation": "Keeping device firmware up-to-date is crucial for patching security vulnerabilities. Disabling unnecessary services reduces the attack surface.  Using default credentials, leaving ports open, and sharing passwords are all *major* security risks.",
       "examTip": "Regularly update firmware and disable unnecessary services on network devices."
    },
    {
      "id": 36,
      "question": "What is the purpose of 'network documentation'?",
      "options":[
        "To make the network run faster.",
        "To provide a detailed record of the network's design, configuration, and operation, aiding in troubleshooting, planning, and maintenance.",
        "To replace the need for network security.",
         "To prevent users from accessing the internet."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Network documentation (including diagrams, IP address assignments, device configurations, procedures, and contact information) is essential for understanding, managing, and troubleshooting a network. It doesn't make the network *run* faster, replace security, or prevent internet access.",
      "examTip": "Maintain accurate and up-to-date network documentation."
    },
        {
         "id": 37,
        "question": "What is a 'default gateway' in a TCP/IP network configuration?",
        "options":[
         "The IP address of the DNS server.",
         "The IP address of the router that a device uses to send traffic to destinations outside its local subnet.",
         "The MAC address of the network interface card.",
         "The subnet mask used on the network."
        ],
        "correctAnswerIndex": 1,
        "explanation": "The default gateway is the 'exit point' for a device's local network. When a device needs to communicate with a device on a *different* network (including the internet), it sends the traffic to its default gateway, which is typically the IP address of a router.  It's *not* the DNS server, MAC address, or subnet mask.",
        "examTip": "A device needs a default gateway configured to communicate outside its local subnet."
    },
     {
      "id": 38,
       "question": "Which of the following is a common use for a 'virtual private network' (VPN)?",
       "options":[
        "To speed up your internet connection.",
        "To securely connect to a private network (like your office network) over a public network (like the internet), protecting your data and privacy.",
        "To block all incoming and outgoing network traffic.",
        "To automatically assign IP addresses to devices."
       ],
       "correctAnswerIndex": 1,
       "explanation": "A VPN creates an encrypted tunnel for your internet traffic, allowing you to access private network resources remotely and securely, and protecting your data from eavesdropping, especially on untrusted networks like public Wi-Fi. It's *not* primarily for speeding up connections, blocking all traffic, or assigning IPs.",
       "examTip": "Use a VPN for secure remote access and to enhance privacy on public networks."
    },
               "A security measure that requires two distinct forms of identification to verify a user's identity (e.g., a password and a code sent to a mobile phone).",
          "Using a very long and complex password.",
          "Using the same password for two different accounts."
        ],
        "correctAnswerIndex": 1,
        "explanation": "2FA significantly enhances account security by requiring not just something you *know* (like a password) but also something you *have* (like a phone) or something you *are* (like a fingerprint).  This makes it much harder for attackers to gain unauthorized access, even if they have your password.  It's *not* just using two passwords, a long password, or reusing passwords.",
        "examTip": "Enable 2FA whenever possible, especially for important accounts."
    },
    {
        "id": 40,
        "question": "Which of the following is a potential security risk associated with using default usernames and passwords on network devices (routers, switches, access points)?",
        "options": [
           "It makes the network more secure.",
           "It simplifies network administration.",
            "Attackers can easily gain unauthorized access to the device and potentially the entire network using publicly known default credentials.",
            "It improves network performance."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Default usernames and passwords are well-known and easily found online.  Failing to change them is a major security vulnerability that allows attackers to easily compromise network devices. It *doesn't* improve security, simplify administration *long-term*, or improve performance.",
        "examTip": "Always change default usernames and passwords on *all* network devices immediately after installation."
    },
        {
       "id": 41,
        "question":"What is the purpose of 'port forwarding' on a router?",
        "options":[
            "To block all incoming traffic to a specific port.",
            "To allow external devices (on the internet) to access a specific service running on a device within your private network by mapping an external port to an internal IP address and port.",
            "To encrypt network traffic.",
            "To speed up your internet connection."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Port forwarding creates a 'hole' in your firewall, allowing specific incoming traffic from the internet to reach a designated device on your local network. This is commonly used for hosting game servers, web servers, or other services that need to be accessible from outside your network. It's *not* about blocking all traffic, encryption, or speeding up connections.",
        "examTip":"Use port forwarding to make internal services accessible from the internet."
    },
    {
      "id": 42,
      "question": "What is a 'distributed denial-of-service' (DDoS) attack?",
      "options": [
        "An attempt to steal user passwords.",
       "An attempt to overwhelm a network or server with traffic from *multiple* compromised computers (often a botnet), making it unavailable to legitimate users.",
        "A type of phishing attack.",
        "A type of brute-force attack."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DDoS attack is a more sophisticated and powerful form of DoS attack. Instead of originating from a single source, the attack traffic comes from many compromised computers (often part of a botnet), making it much harder to block or mitigate.  It's *not* password stealing, phishing, or a brute-force attack (though those *could* be used to *build* a botnet).",
      "examTip": "DDoS attacks are a significant threat to online services and require specialized mitigation techniques."
    },
    {
        "id": 43,
        "question": "Which of the following is a characteristic of a 'stateful' firewall?",
        "options": [
           "It only examines individual packets in isolation.",
           "It tracks the state of network connections (e.g., TCP sessions) and makes filtering decisions based on both packet headers and connection context, providing more robust security.",
           "It is less secure than a stateless packet filter.",
           "It is only used for wireless networks."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Stateful firewalls maintain a table of active connections and use this information to make more intelligent filtering decisions. They can differentiate between legitimate return traffic for an established connection and unsolicited incoming traffic, providing better security than stateless packet filters (which only examine individual packets). They are *more* secure and used in *all* types of networks.",
        "examTip": "Stateful firewalls are the standard for modern network security."
    },
     {
        "id": 44,
         "question":"What is the primary function of an 'intrusion prevention system' (IPS)?",
         "options":[
           "To assign IP addresses to devices automatically.",
           "To monitor network traffic for suspicious activity and take proactive steps to block or prevent malicious traffic in real-time.",
           "To encrypt network traffic.",
            "To translate domain names to IP addresses."
         ],
         "correctAnswerIndex": 1,
         "explanation":"An IPS goes beyond the *detection* capabilities of an IDS (Intrusion Detection System) by *actively* intervening to stop threats.  It can drop malicious packets, reset connections, block traffic from specific sources, or even quarantine infected systems *before* they can cause significant damage.  It's *not* about IP assignment, encryption, or DNS.",
         "examTip":"An IPS is a proactive security measure that can stop attacks in progress."
    },
    {
     "id": 45,
     "question": "What is the purpose of using 'network segmentation'?",
     "options":[
       "To increase the overall network bandwidth.",
       "To divide a network into smaller, isolated subnetworks, improving security by limiting the impact of breaches and improving performance by reducing congestion.",
        "To make the network easier to physically cable.",
        "To encrypt all network traffic."
     ],
     "correctAnswerIndex": 1,
     "explanation": "Network segmentation (often achieved using VLANs or subnets) creates logical divisions within a network, isolating traffic and containing security breaches. This improves both security and performance by reducing broadcast domains and limiting the spread of malware or other threats. It's *not* primarily about increasing bandwidth, simplifying *physical* cabling, or encryption.",
     "examTip": "Segmentation is a fundamental network security best practice."
    },
    {
        "id": 46,
        "question": "You are troubleshooting a network connectivity problem. A user can access resources on the local network but cannot access the internet.  What is the MOST likely cause?",
        "options": [
            "A faulty network cable on the user's computer.",
            "An incorrect IP address configuration on the user's computer.",
            "A problem with the default gateway configuration or the router acting as the default gateway.",
            "A problem with the user's web browser."
        ],
        "correctAnswerIndex": 2,
        "explanation": "The ability to access local resources but *not* the internet strongly suggests a problem with the default gateway. The default gateway is the router that provides access to other networks, including the internet. A faulty cable or incorrect IP would likely prevent *all* network access. A browser issue wouldn't prevent *pinging* external IPs.",
        "examTip": "Check the default gateway configuration when you can communicate locally but not with external networks."
    },
     {
        "id": 47,
        "question": "Which command-line tool is used to display the ARP cache on a Windows system?",
        "options": [
           "ipconfig /all",
            "arp -a",
            "netstat -r",
            "route print"
        ],
        "correctAnswerIndex": 1,
        "explanation": "The `arp -a` command shows the Address Resolution Protocol (ARP) cache, which contains the mappings between IP addresses and MAC addresses that the computer has recently learned. `ipconfig /all` shows interface details, `netstat -r` and `route print` show routing information.",
        "examTip": "The ARP cache is essential for local network communication; incorrect entries can cause connectivity problems."
    },
      {
       "id": 48,
       "question": "What is a 'rogue access point'?",
       "options":[
         "An access point that is properly configured and authorized.",
        "An unauthorized wireless access point installed on a network without the network administrator's knowledge, potentially creating a security vulnerability.",
        "An access point that is used for testing purposes.",
         "An access point that provides very strong encryption."
       ],
       "correctAnswerIndex": 1,
       "explanation": "A rogue access point is a wireless AP that has been installed on a secure network without explicit authorization from a network administrator. This can create a backdoor into the network, bypassing security measures like firewalls and allowing attackers to intercept traffic or gain access to network resources. It's a *security risk*, not a properly configured, test, or strong encryption AP.",
       "examTip": "Regularly scan for rogue access points to maintain wireless network security."
    },
    {
       "id": 49,
        "question": "Which of the following is a benefit of using a 'client-server' network model compared to a 'peer-to-peer' model?",
        "options":[
          "Easier to set up and manage for very small networks.",
          "Centralized management of resources, security, and user accounts, providing better control, scalability, and security for larger networks.",
           "All computers have equal roles and responsibilities.",
           "Lower initial cost."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Client-server networks offer centralized administration and better security and scalability, making them suitable for larger organizations and businesses. While peer-to-peer *can* be simpler for *very small* networks, it quickly becomes unmanageable as the network grows. The initial cost of client-server *can* be higher, but the long-term benefits often outweigh this. Client-server does *not* mean all computers have equal roles.",
        "examTip": "Client-server networks are the standard for most business environments."
    },
    {
       "id": 50,
        "question": "What is the primary purpose of 'network address translation' (NAT)?",
        "options":[
           "To encrypt network traffic.",
            "To allow multiple devices on a private network to share a single public IP address when communicating with the internet, conserving IPv4 addresses and providing a layer of security.",
            "To dynamically assign IP addresses to devices.",
            "To prevent network loops."
        ],
        "correctAnswerIndex": 1,
        "explanation": "NAT translates private IP addresses (used within a local network) to a public IP address (used on the internet). This is essential for connecting private networks to the internet and helps conserve the limited pool of available IPv4 addresses. It's *not* primarily for encryption, dynamic IP assignment (that's DHCP), or loop prevention (that's STP).",
        "examTip": "NAT is a fundamental technology for connecting private networks to the internet."
    },
    {
       "id": 51,
      "question": "Which of the following is a characteristic of a 'virtual LAN' (VLAN)?",
      "options":[
        "It requires physically separate switches for each VLAN.",
         "It logically segments a physical network into multiple, isolated broadcast domains, allowing for better security, performance, and manageability.",
         "It increases the overall size of the broadcast domain.",
         "It is only used in wireless networks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "VLANs allow you to create logically separate networks *on the same physical switch infrastructure*. This improves security by isolating traffic, reduces congestion by limiting broadcast domains, and makes network management easier. They *reduce* broadcast domain size, and while they *can* be used with wireless, they're *primarily* a wired networking technology.",
      "examTip": "VLANs are a fundamental tool for network segmentation in switched networks."
    },
    {
      "id": 52,
       "question": "What is the purpose of a 'default gateway' in a TCP/IP network configuration?",
        "options":[
          "To provide wireless access to the network.",
          "To translate domain names into IP addresses.",
           "To provide a path for traffic to leave the local network and reach destinations on other networks, including the internet.",
           "To encrypt network traffic."
        ],
        "correctAnswerIndex": 2,
        "explanation": "The default gateway is the IP address of the router that a device uses to send traffic that is *not* destined for its local subnet.  It's the 'exit point' from the local network.  It's *not* about wireless access, DNS, or encryption.",
        "examTip": "Without a default gateway configured, a device can only communicate within its local subnet."
    },
     {
       "id": 53,
        "question": "Which type of network device operates at Layer 2 (the Data Link layer) of the OSI model and makes forwarding decisions based on MAC addresses?",
        "options":[
           "Hub",
           "Switch",
           "Router",
           "Repeater"
        ],
        "correctAnswerIndex": 1,
        "explanation":"Switches learn the MAC addresses of connected devices and forward traffic only to the intended recipient, making them much more efficient than hubs (which broadcast to all ports). Routers operate at Layer 3 (Network), hubs and repeaters at Layer 1 (Physical).",
        "examTip":"Switches are the foundation of most modern local area networks (LANs)."
    },
     {
        "id": 54,
        "question": "What is 'Power over Ethernet' (PoE)?",
        "options":[
           "A type of network cable.",
           "A technology that allows network cables to carry both data and electrical power, simplifying the deployment of devices like IP phones, wireless access points, and security cameras.",
            "A protocol for encrypting network traffic.",
            "A method for assigning IP addresses dynamically."
        ],
        "correctAnswerIndex": 1,
        "explanation": "PoE eliminates the need for separate power outlets for network devices, making installation easier and more flexible. It's *not* a cable type, encryption protocol, or IP assignment method.",
        "examTip": "PoE is widely used to power network devices where running separate power cables is difficult or expensive."
    },
    {
      "id": 55,
      "question":"What is the purpose of the 'traceroute' (or 'tracert') command?",
      "options":[
        "To test the speed of a network connection.",
        "To display the IP address of a website.",
       "To trace the route that packets take to reach a destination host, showing each hop (router) along the way and the time it takes to reach each hop.",
        "To configure a network interface."
      ],
      "correctAnswerIndex": 2,
      "explanation":"`traceroute` (Linux/macOS) or `tracert` (Windows) is a diagnostic tool used to identify network routing problems and pinpoint sources of latency. It shows the path that packets take to reach a destination, including each router (hop) along the way.  It's not *primarily* a speed test, a way to get a website's IP (that's `nslookup` or `dig`), or for interface configuration.",
      "examTip":"Use `traceroute`/`tracert` to diagnose network connectivity problems and identify points of failure or high latency."
    },
    {
      "id": 56,
      "question": "Which command is used on a Windows computer to release and renew a DHCP-assigned IP address?",
      "options": [
        "ipconfig /all",
        "ipconfig /release then ipconfig /renew",
        "ipconfig /flushdns",
        "netstat -r"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`ipconfig /release` releases the current IP address lease from the DHCP server, and `ipconfig /renew` requests a new IP address lease. `ipconfig /all` displays configuration information, `ipconfig /flushdns` clears the DNS cache, and `netstat -r` shows routing information.",
      "examTip": "Use `ipconfig /release` and `ipconfig /renew` to troubleshoot DHCP-related connectivity issues."
    },
     {
      "id": 57,
      "question": "A user reports being unable to access a specific network share.  You can ping the file server by IP address, and other users can access the share.  What is the MOST likely cause?",
      "options":[
       "The file server is down.",
        "The network cable is unplugged from the user's computer.",
        "A permissions issue preventing the user from accessing the specific share.",
        "A problem with the DNS server."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Since you can *ping* the server, and *other* users can access it, the problem is likely *local* to the specific user and *not* a server-wide, network-wide, or DNS issue. The *most likely* cause is that the user lacks the necessary permissions to access that particular shared folder.  A cable unplug would prevent *all* network access.",
      "examTip": "When troubleshooting access problems, consider user permissions after verifying basic connectivity."
    },
    {
      "id": 58,
       "question": "What is the primary purpose of a 'firewall' in network security?",
        "options":[
           "To speed up your internet connection.",
            "To control network traffic by allowing or blocking connections based on predefined security rules, acting as a barrier between a trusted network and an untrusted network.",
            "To assign IP addresses dynamically.",
            "To translate domain names into IP addresses."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A firewall is a security device (hardware or software) that enforces access control policies, preventing unauthorized access to or from a private network. It examines network traffic and blocks or allows it based on configured rules. It's *not* about speeding up connections, IP assignment (DHCP), or DNS.",
        "examTip": "Firewalls are a fundamental component of network security."
    },
        {
        "id": 59,
        "question":"What does 'SSID' stand for in the context of wireless networking?",
        "options":[
           "Secure System Identifier",
           "Service Set Identifier",
           "System Security ID",
           "Simple Service ID"
        ],
        "correctAnswerIndex": 1,
        "explanation":"SSID (Service Set Identifier) is the name of a wireless network (Wi-Fi). It's the name you see when you search for available Wi-Fi networks on your device.",
        "examTip":"The SSID is the public name of your Wi-Fi network."
    },
    {
      "id": 60,
      "question": "Which of the following is a characteristic of a 'mesh' network topology?",
      "options": [
       "All devices are connected to a central hub or switch.",
        "Devices are connected in a circular loop.",
        "Each device has multiple paths to other devices, providing high redundancy and fault tolerance.",
        "All devices are connected to a single, shared cable."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Mesh networks provide excellent redundancy because each node has multiple connections to other nodes. If one link or device fails, traffic can be rerouted through alternative paths. This makes them highly resilient but also more complex to implement and manage. Star uses a central device, ring uses a loop, and bus uses a single cable.",
      "examTip": "Mesh networks are often used in critical infrastructure and wireless networks where high availability is paramount."
    },
    {
        "id": 61,
        "question": "You are troubleshooting a slow network.  You use a protocol analyzer (like Wireshark) and notice a large number of TCP retransmissions. What does this MOST likely indicate?",
        "options": [
            "The network is secure and properly encrypted.",
            "Packet loss or network congestion, causing the sender to resend data.",
            "The DNS server is not responding.",
            "The DHCP server is not assigning IP addresses."
        ],
        "correctAnswerIndex": 1,
        "explanation": "TCP retransmissions occur when the sender doesn't receive an acknowledgment for a transmitted packet within a certain time. This usually indicates packet loss due to network congestion, faulty hardware, or other network problems. It's *not* related to security/encryption, DNS, or DHCP.",
        "examTip": "A high number of TCP retransmissions is a strong indicator of network problems."
    },
    {
        "id": 62,
        "question":"What is the purpose of 'subnetting' an IP network?",
        "options":[
          "To increase the total number of available IP addresses.",
           "To divide a network into smaller, logically separate subnetworks, improving security, performance, and address management.",
          "To encrypt network traffic.",
          "To make the network more vulnerable to attacks."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Subnetting divides a larger network into smaller, isolated segments. This improves security (by limiting the scope of broadcasts and potential breaches), performance (by reducing broadcast traffic), and manageability (by organizing IP address allocation).  It doesn't increase the *total* address space or deal with encryption.",
        "examTip":"Subnetting is a core concept in IP networking and network design."
    },
        {
       "id": 63,
         "question":"What is 'network address translation' (NAT) primarily used for?",
        "options":[
           "To encrypt network traffic.",
           "To conserve public IPv4 addresses by allowing multiple devices on a private network to share a single public IP address when communicating with the internet.",
            "To dynamically assign IP addresses to devices.",
            "To prevent network loops."
        ],
        "correctAnswerIndex": 1,
        "explanation":"NAT translates private IP addresses (used within a local network) to a public IP address (used on the internet), and vice versa.  This allows many devices to share a single public IP, which is essential given the limited number of available IPv4 addresses.  It's not primarily for encryption, dynamic IP assignment (DHCP), or loop prevention (STP).",
        "examTip":"NAT is a fundamental technology for connecting private networks to the internet."
    },
     {
        "id": 64,
        "question": "Which of the following is a security best practice for wireless networks?",
        "options": [
            "Using an open network (no password).",
            "Using WEP encryption.",
            "Using WPA2 or, preferably, WPA3 encryption with a strong, unique password, and changing the default SSID.",
            "Sharing the network password with anyone who asks."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Strong encryption (WPA2 or WPA3) and a complex, unique password are crucial for securing a Wi-Fi network. Changing the default SSID adds a small layer of obscurity. Open networks, WEP encryption, and sharing passwords are all *major* security vulnerabilities.",
        "examTip": "Always use the strongest available encryption and a strong password for your Wi-Fi network."
    },
     {
       "id": 65,
        "question":"What is 'MAC address filtering' used for on a network?",
        "options":[
           "To assign IP addresses to devices automatically.",
            "To encrypt network traffic.",
            "To restrict network access based on the physical MAC addresses of devices, allowing or blocking specific devices.",
            "To translate domain names to IP addresses."
        ],
        "correctAnswerIndex": 2,
        "explanation":"MAC address filtering allows you to create a list of allowed (or blocked) MAC addresses, controlling which devices can connect to a network (typically a wireless network or a specific switch port). While it *can* enhance security, it's *not* foolproof, as MAC addresses can be spoofed. It's not about IP assignment, encryption, or DNS.",
        "examTip":"MAC address filtering can provide an additional layer of security, but it should not be the only security measure."
    },
    {
       "id": 66,
        "question": "What is the purpose of a 'default gateway' in a TCP/IP network configuration?",
        "options":[
           "To provide wireless access to the network.",
            "To translate domain names into IP addresses.",
            "To provide a path for traffic to leave the local network and reach destinations on other networks, including the internet; it's typically the IP address of a router.",
            "To encrypt network traffic."
        ],
        "correctAnswerIndex": 2,
        "explanation": "The default gateway is the 'exit point' for a device's local subnet. When a device needs to communicate with a device on a *different* network, it sends the traffic to its default gateway (usually a router). It's *not* about wireless access, DNS, or encryption.",
        "examTip": "A device needs a correctly configured default gateway to communicate outside its local subnet."
    },
     {
       "id": 67,
        "question": "Which layer of the OSI model is responsible for reliable data delivery, flow control, and error correction?",
        "options":[
          "Layer 2 - Data Link",
          "Layer 3 - Network",
          "Layer 4 - Transport",
          "Layer 7 - Application"
        ],
        "correctAnswerIndex": 2,
        "explanation": "The Transport layer (Layer 4) provides reliable data transfer services using protocols like TCP. It handles segmentation, reassembly, flow control, and error correction. Layer 2 deals with *local* delivery (MAC addresses), Layer 3 with routing between networks, and Layer 7 with application-specific protocols.",
        "examTip": "Remember TCP (connection-oriented, reliable) and UDP (connectionless, unreliable) as the key Transport layer protocols."
    },
    {
        "id": 68,
        "question": "You are troubleshooting a network where users are complaining of slow internet speeds. You suspect a problem with DNS resolution.  Which command-line tool is BEST suited to specifically query DNS servers and test name resolution?",
        "options": [
           "ping",
           "tracert",
           "nslookup (or dig)",
           "ipconfig /all"
        ],
        "correctAnswerIndex": 2,
        "explanation": "`nslookup` (or `dig` on Linux/macOS) is specifically designed to query DNS servers and resolve domain names to IP addresses (and vice versa).  `ping` tests basic connectivity, `tracert` shows the route, and `ipconfig /all` displays the *current* DNS server settings, but doesn't actively *test* resolution in the same way.",
        "examTip": "Use `nslookup` or `dig` to diagnose DNS resolution problems."
      },
      {
       "id": 69,
       "question":"What is a 'virtual private network' (VPN) primarily used for?",
       "options":[
        "To increase your internet connection speed.",
        "To create a secure, encrypted tunnel over a public network (like the internet), protecting your data and allowing secure remote access to private networks.",
        "To block all incoming and outgoing network traffic.",
        "To automatically assign IP addresses to devices on a network."
       ],
       "correctAnswerIndex": 1,
       "explanation":"A VPN encrypts your internet traffic and routes it through a secure server, masking your IP address and location. This is especially important for protecting your data on public Wi-Fi and for accessing private network resources remotely. It doesn't primarily speed up connections, block all traffic, or assign IPs.",
       "examTip":"Use a VPN for secure remote access and to enhance your online privacy."
    },
      {
        "id": 70,
        "question":"What is a 'denial-of-service' (DoS) attack?",
        "options":[
            "An attempt to steal user passwords.",
            "An attempt to overwhelm a network or server with traffic from a *single* source, making it unavailable to legitimate users.",
            "An attempt to trick users into revealing personal information.",
             "An attempt to gain unauthorized access to a computer system by guessing passwords."
        ],
        "correctAnswerIndex": 1,
        "explanation":"A DoS attack aims to disrupt a network service by flooding it with traffic *from a single attacking machine*.  This makes the service unavailable to legitimate users. Password stealing is credential theft, tricking users is phishing, and password guessing is a brute-force attack. *Distributed* DoS (DDoS) uses *multiple* sources.",
        "examTip":"DoS attacks can cause significant downtime and disruption."
    },
        {
        "id": 71,
        "question": "What is the purpose of using 'strong passwords' and practicing good password hygiene?",
        "options": [
            "To make it easier to remember your passwords.",
            "To comply with website requirements.",
            "To significantly reduce the risk of unauthorized access to your accounts and protect your personal information.",
            "To speed up your computer."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Strong passwords (long, complex, and unique) are much harder to guess or crack using automated tools. Good password hygiene (not reusing passwords, changing them regularly, and using a password manager) is crucial for protecting your online accounts. While compliance is a factor, the *primary* reason is security. It has *no* impact on computer speed.",
        "examTip": "Use a password manager to help you create and manage strong, unique passwords for all your accounts."
    },
      {
       "id": 72,
        "question": "Which of the following best describes 'multi-factor authentication' (MFA)?",
        "options":[
          "Using a very long and complex password.",
         "Using the same password for multiple accounts.",
          "A security measure that requires you to provide two or more independent credentials to verify your identity (e.g., password + code from phone).",
          "Using your fingerprint to unlock your computer."
        ],
        "correctAnswerIndex": 2,
        "explanation": "MFA adds a significant layer of security by requiring more than just a password. It typically combines something you *know* (password), something you *have* (phone, security token), and/or something you *are* (biometric). A fingerprint is *one* factor, but MFA requires *multiple* factors. Using the same password everywhere is a *major* security risk.",
        "examTip": "Enable MFA whenever possible, especially for important accounts like email, banking, and social media."
      },
     {
       "id": 73,
        "question": "What is a 'firewall' primarily used for in network security?",
        "options":[
           "To speed up your internet connection.",
           "To control network traffic by allowing or blocking connections based on predefined security rules, acting as a barrier between trusted and untrusted networks.",
            "To assign IP addresses to devices automatically.",
           "To translate domain names into IP addresses."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A firewall is a crucial security device (hardware or software) that enforces access control policies, preventing unauthorized access to or from a private network. It examines network traffic and blocks or allows it based on a configured set of rules.  It is *not* primarily for speed, IP assignment, or DNS.",
        "examTip": "Firewalls are a fundamental component of any network security strategy."
      },
        {
        "id": 74,
        "question": "What is 'social engineering' in the context of cybersecurity?",
        "options":[
           "Building and managing a social media platform.",
            "Manipulating people into divulging confidential information or performing actions that compromise security, often through deception and psychological tricks.",
            "Using social media for marketing and advertising.",
            "Networking with colleagues at industry events."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Social engineering attacks exploit human psychology, rather than technical vulnerabilities. Attackers might impersonate trusted individuals, use deceptive emails or websites, or prey on people's emotions to gain access to systems or information. It's about *manipulation*, not social media platforms, marketing, or professional networking.",
        "examTip": "Be skeptical of unsolicited requests for information, and always verify the identity of anyone asking for sensitive data."
      },
      {
        "id": 75,
         "question": "Which of the following is a key difference between a 'hub' and a 'switch' in a network?",
        "options":[
          "A hub is faster than a switch.",
           "A hub broadcasts all data to every connected device, creating a single collision domain and reducing efficiency; a switch learns MAC addresses and forwards data only to the intended recipient, reducing collisions and improving performance.",
           "A switch is used for wireless networks; a hub is used for wired networks.",
            "A hub provides better security than a switch."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Hubs are simple, Layer 1 devices that repeat all incoming signals to all ports, leading to collisions and wasted bandwidth. Switches are more intelligent, Layer 2 devices that learn which devices are connected to which ports and forward data only to the appropriate destination. This significantly improves network performance and reduces the chance of collisions. Both hubs and switches are primarily for *wired* networks, though hubs are rarely used now.",
        "examTip": "Switches have largely replaced hubs in modern networks due to their superior performance and efficiency."
    },
      {
        "id": 76,
         "question": "What is the purpose of 'network segmentation'?",
        "options":[
         "To increase the total number of available IP addresses.",
         "To divide a network into smaller, isolated subnetworks (often using VLANs or subnets), improving security by limiting the impact of breaches and improving performance by reducing congestion.",
        "To make the network physically easier to cable.",
        "To encrypt all network traffic."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Network segmentation creates logical divisions within a network, isolating traffic and containing security breaches. This reduces broadcast traffic, improves performance, and enhances security by limiting the spread of malware or other threats. It's not primarily about increasing the *total* address space, physical cabling, or encryption.",
        "examTip": "Segmentation is a critical security best practice for any network, especially those with sensitive data or critical systems."
    },
      {
        "id": 77,
         "question":"What is a 'distributed denial-of-service' (DDoS) attack?",
         "options":[
            "An attempt to steal user passwords.",
            "An attempt to overwhelm a network or server with traffic from *multiple*, compromised computers (often a botnet), making it unavailable to legitimate users.",
            "A type of phishing attack.",
            "A type of brute-force password-guessing attack."
         ],
         "correctAnswerIndex": 1,
         "explanation":"A DDoS attack is a more sophisticated form of DoS attack where the attack traffic comes from many different sources, often a botnet (a network of computers infected with malware and controlled by an attacker). This makes it much harder to block or mitigate the attack compared to a single-source DoS attack. It is *not* password stealing, phishing, or a brute-force attack (though those techniques *could* be used to *build* a botnet).",
         "examTip":"DDoS attacks are a major threat to online services and require robust mitigation strategies."
      },
               "It requires physically separate switches for each VLAN.",
          "It logically segments a physical network into multiple, isolated broadcast domains, allowing for better security, performance, and manageability, even if devices are on the same switch.",
          "It increases the overall size of the broadcast domain.",
          "It is only used in wireless networks."
        ],
        "correctAnswerIndex": 1,
        "explanation": "VLANs create logically separate networks *on the same physical switch infrastructure*. This allows you to group devices based on function, security requirements, or organizational structure, regardless of their physical location.  They *reduce* broadcast domain size (improving performance) and are *primarily* a wired networking technology (though they can be extended to wireless).",
        "examTip": "VLANs are a fundamental tool for network segmentation and security in switched networks."
      },
      {
        "id": 79,
        "question": "Which of the following best describes 'Quality of Service' (QoS) in networking?",
        "options": [
         "A measure of how quickly a network cable can be installed.",
          "The ability to prioritize certain types of network traffic (like voice or video) over others, ensuring that critical applications receive adequate bandwidth and low latency.",
          "A type of network cable.",
          "A method of encrypting network traffic."
        ],
        "correctAnswerIndex": 1,
        "explanation": "QoS allows network administrators to manage network resources and ensure that time-sensitive or high-priority applications receive the necessary performance, even during periods of network congestion. It's about prioritizing traffic, *not* cable installation, cable type, or encryption.",
        "examTip": "QoS is essential for delivering a good user experience for real-time applications like VoIP and video conferencing."
      },
      {
       "id": 80,
        "question":"What is 'MAC address filtering' primarily used for on a network?",
        "options":[
         "To assign IP addresses to devices automatically.",
          "To encrypt network traffic.",
          "To restrict network access based on the physical MAC addresses of devices, allowing or blocking specific devices from connecting.",
          "To translate domain names to IP addresses."
        ],
        "correctAnswerIndex": 2,
        "explanation":"MAC address filtering allows you to create a list of allowed (or blocked) MAC addresses, controlling which devices can connect to your network (typically a wireless network or a specific switch port).  While it *can* add a layer of security, it's *not* foolproof (MAC addresses can be spoofed) and should *not* be the *only* security measure. It's *not* about IP assignment, encryption, or DNS.",
        "examTip":"MAC address filtering can be a useful security measure, but it's not a substitute for strong encryption and other security best practices."
    },
    {
       "id": 81,
        "question": "A user reports they can access websites by IP address but not by their domain names.  What is the MOST likely cause?",
        "options":[
          "A faulty network cable on the user's computer.",
            "A problem with the user's web browser.",
            "A DNS resolution issue, meaning the computer cannot translate domain names into IP addresses.",
            "The user's IP address is blocked by a firewall."
        ],
        "correctAnswerIndex": 2,
        "explanation": "The ability to access websites by IP address but *not* by name strongly indicates a DNS resolution problem. The computer cannot translate the human-readable domain names into the numerical IP addresses needed to connect. A faulty cable would likely prevent *all* network access, a browser issue might affect *specific* websites differently, and an IP block wouldn't prevent *pinging* the IP directly.",
        "examTip": "Use tools like `nslookup` or `dig` to troubleshoot DNS resolution problems."
    },
    {
        "id": 82,
        "question": "Which command is used on a Windows computer to display the current routing table?",
        "options": [
          "ipconfig /all",
          "arp -a",
          "netstat -r",
          "route print"
        ],
        "correctAnswerIndex": 3,
        "explanation": "The `route print` command displays the routing table, which shows how the computer will forward traffic to different networks. `ipconfig /all` shows interface details, `arp -a` shows the ARP cache, and `netstat -r` shows routing *information* (but less clearly than `route print`).",
        "examTip": "Use `route print` to understand how your computer is routing network traffic."
    },
       {
        "id": 83,
        "question":"What is a 'rogue access point'?",
        "options":[
           "An access point that is properly configured and authorized by the network administrator.",
            "An unauthorized wireless access point installed on a network without the administrator's knowledge, potentially creating a security vulnerability.",
            "An access point that is used for testing purposes only.",
            "An access point with very strong encryption."
        ],
        "correctAnswerIndex": 1,
        "explanation":"A rogue access point is a security risk because it bypasses network security measures (like firewalls) and can allow attackers to intercept traffic or gain access to network resources. It's *not* authorized, used for testing (in a controlled way), or defined by strong encryption.",
        "examTip":"Regularly scan for rogue access points to maintain wireless network security."
    },
     {
        "id": 84,
         "question": "What is the purpose of 'network address translation' (NAT)?",
         "options":[
           "To encrypt network traffic.",
           "To translate private IP addresses used within a local network to a public IP address used on the internet (and vice versa), conserving public IPv4 addresses and providing a layer of security.",
           "To dynamically assign IP addresses to devices.",
           "To prevent network loops."
         ],
         "correctAnswerIndex": 1,
         "explanation": "NAT allows multiple devices on a private network to share a single public IP address, which is essential in today's internet due to the limited number of available IPv4 addresses. It also provides a basic level of security by hiding the internal network structure.  It's *not* primarily about encryption, dynamic IP assignment (DHCP), or loop prevention (STP).",
         "examTip": "NAT is a fundamental technology for connecting private networks to the internet."
    },
    {
       "id": 85,
        "question": "You are troubleshooting a network connectivity issue.  A user can ping their own computer's IP address and the loopback address (127.0.0.1), but they cannot ping any other devices on the local network or the default gateway.  What is the MOST likely cause?",
        "options":[
          "A problem with the DNS server.",
            "A problem with the user's web browser.",
            "A problem with the user's network adapter, network cable, or the switch port to which the computer is connected.",
            "A misconfigured firewall on the remote server."
        ],
        "correctAnswerIndex": 2,
        "explanation":"The ability to ping the loopback and the computer's own IP confirms that the TCP/IP stack is working *locally*. The inability to ping *anything else* on the *local* network points to a problem with the physical connection (cable, NIC) or the switch port.  DNS is for name resolution, a browser issue wouldn't prevent *pinging*, and a *remote* firewall wouldn't affect *local* pings.",
        "examTip":"When troubleshooting, isolate the problem by testing connectivity at different points in the network."
    },
    {
       "id": 86,
      "question": "What is the primary function of Spanning Tree Protocol (STP) in a switched network?",
      "options":[
        "To dynamically assign IP addresses to devices.",
        "To translate domain names into IP addresses.",
         "To prevent network loops by blocking redundant paths in a switched network, ensuring a single active path between any two devices.",
        "To encrypt network traffic."
      ],
      "correctAnswerIndex": 2,
      "explanation": "STP is essential for preventing broadcast storms caused by loops in networks with redundant links between switches. It logically blocks redundant paths, ensuring that only one active path exists between any two points on the network. It is *not* related to IP assignment, DNS, or encryption.",
      "examTip": "STP is critical for maintaining a stable and loop-free switched network."
    },
        {
        "id": 87,
        "question": "What is a 'DMZ' in network architecture?",
        "options":[
            "A zone where no computers are allowed.",
            "A separate network segment that sits between a private network and the public internet, used to host publicly accessible servers (like web servers) while providing an extra layer of security for the internal network.",
            "A type of network cable.",
            "A type of network attack."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A DMZ (demilitarized zone) acts as a buffer between the trusted internal network and the untrusted external network (the internet). It allows external users to access specific services (like web servers) without having direct access to the internal network, reducing the risk of a successful attack compromising the entire internal network.  It is *not* a no-computer zone, a cable type, or an attack type.",
        "examTip": "DMZs are used to isolate publicly accessible servers from the internal network, enhancing security."
    },
      {
       "id": 88,
        "question": "Which of the following is a potential consequence of a 'broadcast storm' on a network?",
        "options":[
          "Improved network security.",
          "Increased network bandwidth.",
          "Severe network performance degradation or complete network outage due to excessive broadcast traffic.",
          "Faster internet speeds."
        ],
        "correctAnswerIndex": 2,
        "explanation": "A broadcast storm occurs when broadcast traffic floods the network, consuming excessive bandwidth and processing resources, and potentially bringing the network to a standstill. This is often caused by network loops. It does *not* improve security or bandwidth or increase internet speeds.",
        "examTip": "Prevent broadcast storms by using Spanning Tree Protocol (STP) in switched networks and properly segmenting your network."
    },
    {
       "id": 89,
        "question": "What is the primary purpose of using VLANs in a switched network?",
        "options":[
           "To increase the overall network bandwidth.",
           "To logically segment a physical network into multiple, isolated broadcast domains, improving security, performance, and manageability.",
           "To provide wireless access to the network.",
            "To encrypt network traffic."
        ],
        "correctAnswerIndex": 1,
        "explanation": "VLANs allow you to create logically separate networks on the *same* physical switch infrastructure. This is crucial for isolating traffic, controlling broadcast domains, and improving security by limiting the scope of potential breaches. They don't directly *increase* bandwidth (though they *improve* performance), provide *wireless* access, or *encrypt* traffic.",
        "examTip": "VLANs are a fundamental tool for network segmentation and security in switched networks."
    },
    {
        "id": 90,
        "question": "Which type of network cabling is MOST susceptible to electromagnetic interference (EMI)?",
        "options": [
          "Fiber optic cable",
          "Shielded twisted pair (STP) cable",
           "Unshielded twisted pair (UTP) cable",
          "Coaxial cable"
        ],
        "correctAnswerIndex": 2,
        "explanation": "UTP (Unshielded Twisted Pair) cable offers the *least* protection against EMI. STP provides *some* shielding, coaxial provides *moderate* shielding, and fiber optic cable is completely *immune* to EMI because it uses light instead of electrical signals.",
        "examTip": "Use fiber optic cable in environments with high levels of EMI."
    },
    {
       "id": 91,
        "question":"What is the primary function of an 'intrusion detection system' (IDS)?",
        "options":[
          "To automatically assign IP addresses to devices.",
          "To actively block or prevent network attacks.",
          "To monitor network traffic for suspicious activity and generate alerts for security personnel, but not take automatic action to stop the activity.",
          "To encrypt network traffic."
        ],
        "correctAnswerIndex": 2,
        "explanation":"An IDS is a *passive* monitoring system. It detects potential security breaches or policy violations by analyzing network traffic and logs, but it *doesn't* automatically block or prevent attacks. That's the role of an *Intrusion Prevention System* (IPS). An IDS generates *alerts* so administrators can investigate and take action. It's *not* about IP assignment or encryption.",
        "examTip":"Think of an IDS as a security camera – it observes and records, but doesn't actively intervene."
    },
      {
        "id": 92,
        "question": "What is the purpose of 'port forwarding' on a router?",
        "options":[
            "To block all incoming traffic to a specific port.",
            "To allow external devices (on the internet) to access a specific service running on a device within your private network by mapping an external port on the router to an internal IP address and port.",
            "To encrypt network traffic.",
             "To speed up your internet connection."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Port forwarding creates a 'hole' in your firewall (which is usually part of your router), allowing specific incoming traffic from the internet to reach a particular device on your internal network. This is commonly used for hosting game servers, web servers, or other services that need to be accessible from outside your network. It's *not* about blocking *all* traffic, encryption, or speeding up connections.",
        "examTip": "Use port forwarding to make internal services accessible from the internet."
    },
    {
     "id": 93,
      "question":"What is the purpose of the Address Resolution Protocol (ARP)?",
      "options":[
        "To translate domain names into IP addresses.",
        "To dynamically assign IP addresses to devices.",
        "To map IP addresses to MAC addresses on a local network, allowing devices to communicate at the data link layer.",
        "To encrypt network traffic."
      ],
      "correctAnswerIndex": 2,
      "explanation":"ARP is essential for communication *within* a local network (specifically, Ethernet networks). Before a device can send data to another device on the same subnet, it needs to know the recipient's MAC address. ARP resolves the IP address to the corresponding MAC address. It's *not* about DNS, DHCP, or encryption.",
      "examTip":"ARP is crucial for local network communication at Layer 2."
    },
      {
       "id": 94,
       "question":"What does 'WPA3' stand for, and why is it important for wireless network security?",
       "options":[
         "Wired Protocol Access 3; it's an older, less secure protocol.",
         "Wi-Fi Protected Access 3; it's the latest and most secure wireless security protocol, offering improved encryption and protection against attacks.",
          "Wireless Protected Area 3; it's a type of wireless antenna.",
          "Web Page Access 3; it's a protocol for accessing websites."
       ],
       "correctAnswerIndex": 1,
       "explanation":"WPA3 (Wi-Fi Protected Access 3) is the most recent and secure wireless security protocol, providing stronger encryption and better protection against various attacks compared to older protocols like WEP, WPA, and even WPA2. It's *not* about wired protocols, antennas, or web page access.",
       "examTip":"Always use WPA3 if your devices and access point support it; otherwise, use WPA2 with AES."
    },
     {
       "id": 95,
        "question": "Which command-line tool is commonly used to test network connectivity to a remote host and measure round-trip time?",
        "options":[
         "tracert (or traceroute)",
         "ping",
          "ipconfig",
          "nslookup"
        ],
        "correctAnswerIndex": 1,
        "explanation": "The `ping` command sends ICMP Echo Request packets to a target host and listens for Echo Reply packets. This tests basic connectivity and measures the round-trip time, indicating latency. `tracert` shows the route, `ipconfig` displays *local* configuration, and `nslookup` queries DNS.",
        "examTip": "`ping` is a fundamental and widely used network troubleshooting tool."
    },
     {
        "id": 96,
        "question": "What is a 'honeypot' in the context of cybersecurity?",
        "options":[
          "A secure server that stores sensitive data.",
          "A decoy system or network designed to attract and trap attackers, allowing security professionals to study their methods and potentially divert them from real targets.",
          "A type of firewall.",
           "A tool for encrypting network traffic."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A honeypot is a *trap* for attackers. It's a deliberately vulnerable system or network resource that mimics a legitimate target, designed to lure attackers and provide insights into their techniques. It's *not* a secure server, firewall, or encryption tool.",
        "examTip": "Honeypots are used for cybersecurity research and threat intelligence."
    },
      {
         "id": 97,
        "question": "What is 'social engineering' in cybersecurity?",
        "options":[
          "Building and managing a social media platform.",
          "Manipulating people into divulging confidential information or performing actions that compromise security, often through deception, impersonation, or psychological tricks.",
          "Using social media for marketing and outreach.",
           "Networking with colleagues at professional events."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Social engineering attacks exploit *human* vulnerabilities rather than technical ones. Attackers use various techniques to trick people into revealing sensitive information (like passwords or credit card numbers) or granting them access to systems. It's *not* about building social media platforms, marketing, or professional networking.",
        "examTip": "Be wary of unsolicited requests for information and be aware of common social engineering tactics."
      },
     {
       "id": 98,
        "question":"What does 'encryption' do to data?",
        "options":[
          "It makes data larger and easier to read.",
          "It scrambles data into an unreadable format (ciphertext), protecting it from unauthorized access. Only someone with the correct decryption key can unscramble it.",
          "It deletes data permanently.",
           "It organizes data into folders and files."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Encryption transforms data into an unreadable code, making it unintelligible to anyone who doesn't have the decryption key. This protects the confidentiality of data both in transit (over a network) and at rest (stored on a device).  It *doesn't* make data larger, delete it, or organize it.",
        "examTip":"Encryption is crucial for protecting sensitive data."
    },
     {
       "id": 99,
        "question": "Which of the following is a key characteristic of cloud computing?",
        "options":[
           "All computing resources are located on-premises (within an organization's own data center).",
           "On-demand access to shared computing resources (servers, storage, applications) over the internet, offering scalability, flexibility, and often cost savings.",
           "Requires a significant upfront investment in hardware and infrastructure.",
           "Limited scalability and flexibility."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Cloud computing provides access to computing resources (like servers, storage, and applications) over the internet, often on a pay-as-you-go basis. This offers scalability (easily adjust resources), flexibility (choose different services), and often reduced costs compared to managing your own on-premises infrastructure. It's *not* about all resources being on-premises, requiring *large* upfront investments, or limited scalability.",
        "examTip": "Cloud computing offers various advantages, including agility, scalability, and cost efficiency."
      },
      {
        "id": 100,
        "question": "You are setting up a network and need to ensure that a specific server *always* receives the same IP address from the DHCP server.  What DHCP feature should you use?",
        "options":[
          "DHCP scope",
          "DHCP reservation (or static mapping)",
           "DHCP exclusion",
          "DHCP lease time"
        ],
        "correctAnswerIndex": 1,
        "explanation": "A DHCP reservation (sometimes called a static mapping) associates a specific MAC address with a specific IP address. This ensures that the designated device (like a server) always receives the same IP address from the DHCP server, which is important for consistent access.  A *scope* defines the *range* of addresses, an *exclusion* prevents certain addresses from being assigned, and *lease time* controls how long an address is valid.",
        "examTip": "Use DHCP reservations for servers, printers, and other devices that need consistent IP addresses."
      }
  ]
});
