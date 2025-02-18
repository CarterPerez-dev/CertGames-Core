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
      "options": [
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
      "question": "What is a characteristic of an 'ad hoc' wireless network?",
      "options": [
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
      "question": "You are troubleshooting a network connectivity issue. You suspect a problem with the DNS server. Which command would you use on a Windows computer to clear the DNS resolver cache?",
      "options": [
        "ipconfig /release",
        "ipconfig /renew",
        "ipconfig /flushdns",
        "ipconfig /all"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The `ipconfig /flushdns` command clears the local DNS resolver cache on a Windows computer. This forces the computer to query the DNS server again for name resolution, which can resolve issues caused by outdated or incorrect cached DNS entries. `/release` and `/renew` are for DHCP, and `/all` displays configuration.",
      "examTip": "Use `ipconfig /flushdns` to troubleshoot DNS resolution problems."
    },
    {
      "id": 9,
      "question": "Which of the following correctly describes the relationship between IP addresses and MAC addresses?",
      "options": [
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
      "question": "What is the purpose of using a 'subnet mask' in IP addressing?",
      "options": [
        "To encrypt network traffic.",
        "To identify the network portion and the host portion of an IP address, enabling routing and subnetting.",
        "To dynamically assign IP addresses to devices.",
        "To filter network traffic based on content."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The subnet mask, used in conjunction with an IP address, defines which bits of the address represent the network and which bits represent the host. This is essential for determining whether two devices are on the same subnet and for routing traffic between networks.  It's *not* encryption, dynamic IP assignment (DHCP), or content filtering.",
      "examTip": "Subnet masks are fundamental to IP addressing and network segmentation."
    },
    {
      "id": 12,
      "question": "A small office network is experiencing slow performance.  The network uses a single, unmanaged hub to connect all devices.  What is the MOST likely cause of the slow performance, and what is the BEST solution?",
      "options": [
        "The internet connection is too slow; upgrade the internet service.",
        "The hub creates a single collision domain, causing frequent collisions and reducing efficiency; replace the hub with a switch.",
        "The computers have outdated network drivers; update the drivers.",
        "The network cable is too long; shorten the cable."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hubs operate at Layer 1 and broadcast all traffic to every connected device, creating a single collision domain. This leads to frequent collisions, especially as the number of devices increases, significantly degrading performance. Replacing the hub with a *switch* (which operates at Layer 2 and forwards traffic only to the intended recipient) is the best solution. While internet speed, drivers, or cable length *could* be issues, the hub is the *most likely* bottleneck in this scenario.",
      "examTip": "Replace hubs with switches for improved network performance and efficiency."
    },
    {
      "id": 13,
      "question": "What is the primary use of Quality of Service (QoS) in a network?",
      "options": [
        "To encrypt network traffic.",
        "To prioritize certain types of network traffic (e.g., voice, video) over others, ensuring critical applications receive adequate bandwidth and low latency.",
        "To automatically assign IP addresses to devices.",
        "To translate domain names to IP addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "QoS allows network administrators to manage network resources and ensure that time-sensitive or high-priority applications receive the necessary performance, even during periods of network congestion. It's *not* encryption, IP assignment (DHCP), or DNS.",
      "examTip": "QoS is crucial for delivering a good user experience for real-time applications like VoIP and video conferencing."
    },
    {
      "id": 14,
      "question": "Which of the following is a characteristic of a 'mesh' network topology?",
      "options": [
        "All devices are connected to a central hub or switch.",
        "Devices are connected in a circular loop.",
        "Each device has multiple paths to other devices, providing high redundancy and fault tolerance.",
        "All devices are connected to a single, shared cable."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Mesh networks offer excellent redundancy because each node is connected to multiple other nodes. If one link fails, traffic can be rerouted through alternative paths. This makes them highly resilient but also more complex to implement and manage.  Star uses a central device, ring uses a loop, and bus uses a single cable.",
      "examTip": "Mesh networks are often used in critical infrastructure where high availability is essential."
    },
    {
      "id": 15,
      "question": "What is the primary function of an 'intrusion prevention system' (IPS)?",
      "options": [
        "To assign IP addresses dynamically.",
        "To actively monitor network traffic for malicious activity and take steps to block or prevent it.",
        "To encrypt all network traffic.",
        "To translate domain names to IP addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An IPS goes beyond the *detection* capabilities of an IDS (Intrusion Detection System) by *actively* intervening to stop threats. It can drop malicious packets, reset connections, block traffic from specific sources, or even quarantine infected systems.  It's *not* about IP assignment, encryption, or DNS.",
      "examTip": "An IPS is a proactive security measure that can prevent attacks from succeeding."
    },
    {
      "id": 16,
      "question": "You are configuring a wireless network.  Which of the following provides the STRONGEST security?",
      "options": [
        "WEP (Wired Equivalent Privacy)",
        "WPA (Wi-Fi Protected Access)",
        "WPA2 (Wi-Fi Protected Access 2) with AES encryption",
        "WPA3 (Wi-Fi Protected Access 3)"
      ],
      "correctAnswerIndex": 3,
      "explanation": "WPA3 is the latest and most secure wireless security protocol, offering improved encryption and protection against attacks. WEP is extremely outdated and easily cracked. WPA is also vulnerable. WPA2 with AES is *better* than WPA and WEP, but WPA3 is *superior*.",
      "examTip": "Always use WPA3 if your devices and access point support it; otherwise, use WPA2 with AES."
    },
    {
      "id": 17,
      "question": "What is the purpose of a 'virtual private network' (VPN)?",
      "options": [
        "To speed up your internet connection.",
        "To create a secure, encrypted tunnel over a public network (like the internet), allowing remote users to access private network resources and protecting data from eavesdropping.",
        "To block all incoming and outgoing network traffic.",
        "To automatically assign IP addresses to devices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A VPN encrypts your internet traffic and routes it through a secure server, masking your IP address and protecting your data, especially on public Wi-Fi. It allows remote access to private networks as if you were directly connected. It doesn't primarily speed up connections, block all traffic, or assign IPs.",
      "examTip": "Use a VPN for secure remote access and to enhance your online privacy."
    },
    {
      "id": 18,
      "question": "What does 'MTU' stand for, and what does it define?",
      "options": [
        "Maximum Transfer Unit; the smallest packet size that can be transmitted on a network.",
        "Maximum Transmission Unit; the largest packet size that can be transmitted on a network without fragmentation.",
        "Minimum Transmission Unit; the smallest packet size that can be transmitted on a network.",
        "Media Transfer Unit; the type of cabling used on a network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "MTU stands for Maximum Transmission Unit. It defines the largest data packet (in bytes) that can be transmitted over a network link without being fragmented.  If a packet exceeds the MTU, it must be broken down into smaller fragments, which can impact performance.",
      "examTip": "An incorrect MTU setting can cause network performance problems."
    },
    {
      "id": 19,
      "question": "Which of the following is a potential consequence of having duplicate IP addresses on a network?",
      "options": [
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
      "options": [
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
      "options": [
        "Fiber optic cable is less expensive.",
        "Fiber optic cable is easier to install.",
        "Fiber optic cable can transmit data over longer distances with less signal loss and is immune to electromagnetic interference (EMI).",
        "Fiber optic cable is more resistant to physical damage."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Fiber optic cable uses light signals instead of electrical signals, providing significant advantages: much higher bandwidth, longer transmission distances, and immunity to EMI. However, it's generally *more* expensive and can be *more* complex to install and terminate than copper. While *some* types are rugged, fiber can be *more* susceptible to damage from bending/breaking than *some* copper types.",
      "examTip": "Fiber is the preferred choice for high-speed, long-distance, and EMI-prone environments."
    },
    {
      "id": 22,
      "question": "What is the purpose of using a DMZ in a network?",
      "options": [
        "To provide a secure zone for internal servers and workstations.",
        "To create a separate network for wireless devices.",
        "To host publicly accessible servers (like web servers or email servers) while providing a buffer zone between the internet and the internal network, improving security.",
        "To act as a backup power source for network devices."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A DMZ is a network segment that sits between the trusted internal network and the untrusted external network (internet). It allows external users to access specific services (like web servers) without having direct access to the internal network, minimizing the risk of a successful attack compromising the entire internal network.",
      "examTip": "A DMZ is used to isolate publicly accessible servers from the internal network, enhancing security."
    },
    {
      "id": 23,
      "question": "What is a man-in-the-middle (MitM) attack?",
      "options": [
        "An attempt to overwhelm a network or server with traffic.",
        "An attempt to trick users into revealing personal information.",
        "An attack where the attacker secretly intercepts and potentially alters communication between two parties who believe they are directly communicating with each other.",
        "An attempt to guess passwords by trying many different combinations."
      ],
      "correctAnswerIndex": 2,
      "explanation": "In a MitM attack, the attacker positions themselves between two communicating parties, allowing them to eavesdrop on the conversation, steal data, or even modify the communication. It's *not* overwhelming traffic (DoS), tricking users (phishing), or password guessing (brute-force).",
      "examTip": "MitM attacks can be mitigated with strong encryption and secure protocols (like HTTPS)."
    },
    {
      "id": 24,
      "question": "What is the primary purpose of network address translation (NAT)?",
      "options": [
        "To encrypt network traffic.",
        "To allow multiple devices on a private network to share a single public IP address when communicating with the internet, conserving IPv4 addresses.",
        "To dynamically assign IP addresses to devices.",
        "To filter network traffic based on content."
      ],
      "correctAnswerIndex": 1,
      "explanation": "NAT translates private IP addresses (used within a local network) to a public IP address (used on the internet), and vice versa. This allows many devices to share a single public IP, which is crucial given the limited number of available IPv4 addresses. It's not primarily for encryption, dynamic IP assignment (DHCP), or content filtering.",
      "examTip": "NAT is a fundamental technology for connecting private networks to the internet."
    },
    {
      "id": 25,
      "question": "Which of the following is a characteristic of a stateful firewall compared to a stateless packet filter?",
      "options": [
        "A stateful firewall only examines individual packets; a stateless packet filter tracks connection states.",
        "A stateful firewall tracks the state of network connections and makes filtering decisions based on both packet headers and connection context; a stateless packet filter examines each packet in isolation.",
        "A stateful firewall is less secure than a stateless packet filter.",
        "A stateful firewall is only used for wireless networks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Stateful firewalls maintain a table of active connections and use this information to make more intelligent filtering decisions. They can distinguish between legitimate return traffic for an established connection and unsolicited incoming traffic, providing better security than stateless packet filters, which examine each packet independently without considering the connection context. Stateful firewalls are more secure and used in all types of networks.",
      "examTip": "Stateful firewalls offer more robust security by considering the context of network connections."
    },
    {
      "id": 26,
      "question": "What is the purpose of a proxy server?",
      "options": [
        "To assign IP addresses to devices automatically.",
        "To act as an intermediary between clients and other servers, providing services like caching, filtering, and security, often improving performance and controlling access.",
        "To translate domain names into IP addresses.",
        "To encrypt network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A proxy server sits between clients and other servers (often the internet). It can cache frequently accessed content (improving performance), filter web traffic (controlling access and enhancing security), and mask the client's IP address. It's not about IP assignment (DHCP), DNS, or general encryption (though proxies can be involved in SSL/TLS).",
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
      "explanation": "An access point (AP) provides wireless connectivity to devices, allowing them to join a network (typically a wired network connected to the AP). Switches connect wired devices, routers connect networks, and modems connect to an ISP.",
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
      "correctAnswerIndex": 2,
      "explanation": "For the fastest speed and simultaneous send/receive, you should choose 1000 Mbps (Gigabit Ethernet) and Full-duplex.  Auto-negotiate is generally recommended, but only if you're certain the connected device also supports and is configured for auto-negotiation. For a server NIC, explicitly setting it is often preferred for reliability.",
      "examTip": "For optimal performance, use Gigabit Ethernet and Full-duplex whenever possible."
    },
    {
      "id": 29,
      "question": "What is the purpose of the `ping` command?",
      "options": [
        "To display the routing table.",
        "To test network connectivity to a remote host and measure round-trip time.",
        "To display detailed network interface configuration.",
        "To query DNS servers for information."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`ping` sends ICMP Echo Request packets to a target host and listens for Echo Reply packets. This tests basic connectivity and measures the time it takes for packets to travel to the host and back. It's not for displaying routing tables, interface configurations, or querying DNS.",
      "examTip": "`ping` is a fundamental tool for network troubleshooting."
    },
    {
      "id": 30,
      "question": "What does DNS stand for, and what is its primary function?",
      "options": [
        "Dynamic Network System; to assign IP addresses automatically.",
        "Domain Name System; to translate human-readable domain names (like google.com) into numerical IP addresses.",
        "Data Network Security; to encrypt network traffic.",
        "Digital Network Service; to provide internet access."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DNS (Domain Name System) is like the internet's phone book. It translates the website names we use (e.g., google.com) into the IP addresses that computers use to communicate.  It's not about dynamic IP assignment (DHCP), security, or providing internet access.",
      "examTip": "Without DNS, we'd have to remember IP addresses instead of website names."
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
      "explanation": "Since the user has a valid IP configuration, the problem is likely not with the physical connection or basic IP settings. The next logical step is to check DNS, as the inability to access any website by name strongly suggests a name resolution issue. While rebooting might help, checking DNS is more targeted. Reinstalling the browser is premature.",
      "examTip": "When troubleshooting web access problems, consider DNS after verifying basic IP connectivity."
    },
    {
      "id": 32,
      "question": "Which of the following is a characteristic of a virtual LAN (VLAN)?",
      "options": [
        "It requires physically separate switches for each VLAN.",
        "It logically segments a physical network into multiple, isolated broadcast domains, even if devices are connected to the same physical switch.",
        "It increases the overall size of the broadcast domain.",
        "It is primarily used for wireless networks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "VLANs allow you to create logically separate networks on the same physical switch infrastructure. This improves security by isolating traffic, reduces congestion by limiting broadcast domains, and makes network management easier. They reduce broadcast domain size, and while they can be used with wireless, they're primarily a wired networking technology.",
      "examTip": "VLANs are essential for network segmentation and security in switched networks."
    },
    {
      "id": 33,
      "question": "What is jitter in network performance?",
      "options": [
        "The total amount of data that can be transmitted over a network connection.",
        "The time it takes for a data packet to travel from its source to its destination.",
        "The variation in delay (latency) between data packets, which can negatively impact real-time applications like VoIP and video conferencing.",
        "The number of devices connected to a network."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Jitter is the inconsistency in latency over time. It's not the total bandwidth, the overall delay (that's latency), or the number of devices. High jitter causes problems with real-time applications because packets arrive at irregular intervals, leading to choppy audio or video.",
      "examTip": "Monitor jitter when troubleshooting the quality of real-time applications."
    },
    {
      "id": 34,
      "question": "What is latency in network performance?",
      "options": [
        "The amount of data that can be transmitted over a network connection.",
        "The time delay in data transmission across a network, measured as the time it takes for a packet to travel from source to destination.",
        "The number of devices connected to a network.",
        "The physical distance between two network devices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Latency is the time it takes for data to travel from one point to another on a network. High latency can cause slow response times and negatively impact the user experience, especially for interactive applications. It's not bandwidth (capacity), device count, or physical distance (though distance contributes to latency).",
      "examTip": "Low latency is crucial for responsive network applications."
    },
    {
      "id": 35,
      "question": "Which of the following is a security best practice for managing network devices?",
      "options": [
        "Using default usernames and passwords.",
        "Leaving all ports open on firewalls.",
        "Regularly updating device firmware to patch security vulnerabilities and disabling unnecessary services.",
        "Sharing administrative passwords with all users."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Keeping device firmware up-to-date is crucial for patching security vulnerabilities. Disabling unnecessary services reduces the attack surface. Using default credentials, leaving ports open, and sharing passwords are all major security risks.",
      "examTip": "Regularly update firmware and disable unnecessary services on network devices."
    },
    {
      "id": 36,
      "question": "What is the purpose of network documentation?",
      "options": [
        "To make the network run faster.",
        "To provide a detailed record of the network's design, configuration, and operation, aiding in troubleshooting, planning, and maintenance.",
        "To replace the need for network security.",
        "To prevent users from accessing the internet."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Network documentation (including diagrams, IP address assignments, device configurations, procedures, and contact information) is essential for understanding, managing, and troubleshooting a network. It doesn't make the network run faster, replace security, or prevent internet access.",
      "examTip": "Maintain accurate and up-to-date network documentation."
    },
    {
      "id": 37,
      "question": "What is a default gateway in a TCP/IP network configuration?",
      "options": [
        "The IP address of the DNS server.",
        "The IP address of the router that a device uses to send traffic to destinations outside its local subnet.",
        "The MAC address of the network interface card.",
        "The subnet mask used on the network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The default gateway is the 'exit point' for a device's local network. When a device needs to communicate with a device on a different network (including the internet), it sends the traffic to its default gateway, which is typically the IP address of a router. It's not the DNS server, MAC address, or subnet mask.",
      "examTip": "A device needs a default gateway configured to communicate outside its local subnet."
    },
    {
      "id": 38,
      "question": "Which of the following is a common use for a virtual private network (VPN)?",
      "options": [
        "To speed up your internet connection.",
        "To securely connect to a private network (like your office network) over a public network (like the internet), protecting your data and privacy.",
        "To block all incoming and outgoing network traffic.",
        "To automatically assign IP addresses to devices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A VPN creates an encrypted tunnel for your internet traffic, allowing you to access private network resources remotely and securely, and protecting your data from eavesdropping, especially on untrusted networks like public Wi-Fi. It doesn't primarily speed up connections, block all traffic, or assign IPs.",
      "examTip": "Use a VPN for secure remote access and to enhance your online privacy."
    },
    {
      "id": 39,
      "question": "What is a denial-of-service (DoS) attack?",
      "options": [
        "An attempt to steal user passwords.",
        "An attempt to overwhelm a network or server with traffic from a single source, making it unavailable to legitimate users.",
        "An attempt to trick users into revealing personal information.",
        "An attempt to gain unauthorized access to a computer system by guessing passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DoS attack aims to disrupt a network service by flooding it with traffic from a single attacking machine. This makes the service unavailable to legitimate users. Password stealing is credential theft, tricking users is phishing, and password guessing is a brute-force attack. (Distributed DoS (DDoS) uses multiple sources.)",
      "examTip": "DoS attacks can cause significant downtime and disruption."
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
      "explanation": "Default usernames and passwords are well-known and easily found online. Failing to change them is a major security vulnerability that allows attackers to easily compromise network devices. It doesn't improve security, simplify administration long-term, or improve performance.",
      "examTip": "Always change default usernames and passwords on all network devices immediately after installation."
    },
    {
      "id": 41,
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
      "id": 42,
      "question": "Which of the following best describes a honeypot in the context of cybersecurity?",
      "options": [
        "A secure server that stores sensitive data.",
        "A decoy system or network designed to attract and trap attackers, allowing security professionals to study their methods and potentially divert them from real targets.",
        "A type of firewall.",
        "A tool for encrypting network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A honeypot is a trap for attackers. It's a deliberately vulnerable system or network resource that mimics a legitimate target, designed to lure attackers and provide insights into their techniques. It's not a secure server, firewall, or encryption tool.",
      "examTip": "Honeypots are used for cybersecurity research and threat intelligence."
    },
    {
      "id": 43,
      "question": "Which of the following best describes social engineering in cybersecurity?",
      "options": [
        "Building and managing a social media platform.",
        "Manipulating people into divulging confidential information or performing actions that compromise security, often through deception, impersonation, or psychological tricks.",
        "Using social media for marketing and outreach.",
        "Networking with colleagues at professional events."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Social engineering attacks exploit human vulnerabilities rather than technical ones. Attackers use various techniques to trick people into revealing sensitive information (like passwords or credit card numbers) or granting them access to systems. It's not about building social media platforms, marketing, or professional networking.",
      "examTip": "Be wary of unsolicited requests for information and be aware of common social engineering tactics."
    },
    {
      "id": 44,
      "question": "What does encryption do to data?",
      "options": [
        "It makes data larger and easier to read.",
        "It scrambles data into an unreadable format (ciphertext), protecting it from unauthorized access. Only someone with the correct decryption key can unscramble it.",
        "It deletes data permanently.",
        "It organizes data into folders and files."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption transforms data into an unreadable code, making it unintelligible to anyone who doesn't have the decryption key. This protects the confidentiality of data both in transit (over a network) and at rest (stored on a device). It doesn't make data larger, delete it, or organize it.",
      "examTip": "Encryption is crucial for protecting sensitive data."
    },
    {
      "id": 45,
      "question": "Which of the following is a key characteristic of cloud computing?",
      "options": [
        "All computing resources are located on-premises (within an organization's own data center).",
        "On-demand access to shared computing resources (servers, storage, applications) over the internet, offering scalability, flexibility, and often cost savings.",
        "Requires a significant upfront investment in hardware and infrastructure.",
        "Limited scalability and flexibility."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Cloud computing provides access to computing resources (like servers, storage, and applications) over the internet, often on a pay-as-you-go basis. This offers scalability (easily adjust resources), flexibility (choose different services), and often reduced costs compared to managing your own on-premises infrastructure. It's not about all resources being on-premises, requiring large upfront investments, or limited scalability.",
      "examTip": "Cloud computing offers various advantages, including agility, scalability, and cost efficiency."
    },
    {
      "id": 46,
      "question": "You are setting up a network and need to ensure that a specific server always receives the same IP address from the DHCP server. What DHCP feature should you use?",
      "options": [
        "DHCP scope",
        "DHCP reservation (or static mapping)",
        "DHCP exclusion",
        "DHCP lease time"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DHCP reservation (sometimes called a static mapping) associates a specific MAC address with a specific IP address. This ensures that the designated device (like a server) always receives the same IP address from the DHCP server, which is important for consistent access. A scope defines the range of addresses, an exclusion prevents certain addresses from being assigned, and lease time controls how long an address is valid.",
      "examTip": "Use DHCP reservations for servers, printers, and other devices that need consistent IP addresses."
    },
    {
      "id": 47,
      "question": "Which command-line tool is commonly used to test network connectivity to a remote host and measure round-trip time?",
      "options": [
        "tracert (or traceroute)",
        "ping",
        "ipconfig",
        "nslookup"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `ping` command sends ICMP Echo Request packets to a target host and listens for Echo Reply packets. This tests basic connectivity and measures the round-trip time, indicating latency. `tracert` shows the route, `ipconfig` displays local configuration, and `nslookup` queries DNS.",
      "examTip": "`ping` is a fundamental and widely used network troubleshooting tool."
    },
    {
      "id": 48,
      "question": "What is a honeypot in the context of cybersecurity?",
      "options": [
        "A secure server that stores sensitive data.",
        "A decoy system or network designed to attract and trap attackers, allowing security professionals to study their methods and potentially divert them from real targets.",
        "A type of firewall.",
        "A tool for encrypting network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A honeypot is a trap for attackers. It's a deliberately vulnerable system or network resource that mimics a legitimate target, designed to lure attackers and provide insights into their techniques. It's not a secure server, firewall, or encryption tool.",
      "examTip": "Honeypots are used for cybersecurity research and threat intelligence."
    },
    {
      "id": 49,
      "question": "Which of the following best describes social engineering in cybersecurity?",
      "options": [
        "Building and managing a social media platform.",
        "Manipulating people into divulging confidential information or performing actions that compromise security, often through deception, impersonation, or psychological tricks.",
        "Using social media for marketing and outreach.",
        "Networking with colleagues at professional events."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Social engineering attacks exploit human vulnerabilities rather than technical ones. Attackers use various techniques to trick people into revealing sensitive information or granting them access to systems. It's not about building social media platforms, marketing, or professional networking.",
      "examTip": "Be wary of unsolicited requests for information and be aware of common social engineering tactics."
    },
    {
      "id": 50,
      "question": "What does encryption do to data?",
      "options": [
        "It makes data larger and easier to read.",
        "It scrambles data into an unreadable format (ciphertext), protecting it from unauthorized access. Only someone with the correct decryption key can unscramble it.",
        "It deletes data permanently.",
        "It organizes data into folders and files."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption transforms data into an unreadable code, making it unintelligible to anyone who doesn't have the decryption key. This protects the confidentiality of data both in transit and at rest. It doesn't make data larger, delete it, or organize it.",
      "examTip": "Encryption is crucial for protecting sensitive data."
    },
    {
      "id": 51,
      "question": "Which of the following is a key characteristic of cloud computing?",
      "options": [
        "All computing resources are located on-premises (within an organization's own data center).",
        "On-demand access to shared computing resources over the internet, offering scalability, flexibility, and often cost savings.",
        "Requires a significant upfront investment in hardware and infrastructure.",
        "Limited scalability and flexibility."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Cloud computing provides access to computing resources over the internet on a pay-as-you-go basis, offering scalability and flexibility. It reduces the need for large upfront investments and typically offers high scalability.",
      "examTip": "Cloud computing offers various advantages, including agility, scalability, and cost efficiency."
    },
    {
      "id": 52,
      "question": "You are setting up a network and need to ensure that a specific server always receives the same IP address from the DHCP server. What DHCP feature should you use?",
      "options": [
        "DHCP scope",
        "DHCP reservation (or static mapping)",
        "DHCP exclusion",
        "DHCP lease time"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DHCP reservation associates a specific MAC address with a specific IP address, ensuring that the designated device always receives the same IP address from the DHCP server.",
      "examTip": "Use DHCP reservations for servers, printers, and other devices that need consistent IP addresses."
    },
    {
      "id": 53,
      "question": "Which command-line tool is used to display the current routing table on a Windows computer?",
      "options": [
        "ipconfig /all",
        "arp -a",
        "netstat -r",
        "route print"
      ],
      "correctAnswerIndex": 3,
      "explanation": "The `route print` command displays the routing table, which shows how the computer will forward traffic to different networks. `ipconfig /all` shows interface details, `arp -a` shows the ARP cache, and `netstat -r` shows routing information (but less clearly than `route print`).",
      "examTip": "Use `route print` to understand how your computer is routing network traffic."
    },
    {
      "id": 54,
      "question": "What is a potential consequence of a broadcast storm on a network?",
      "options": [
        "Improved network security.",
        "Increased network bandwidth.",
        "Severe network performance degradation or complete network outage due to excessive broadcast traffic.",
        "Faster internet speeds."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A broadcast storm occurs when broadcast traffic floods the network, consuming excessive bandwidth and processing resources, and potentially bringing the network to a standstill. It does not improve security, bandwidth, or internet speeds.",
      "examTip": "Prevent broadcast storms by using STP in switched networks and properly segmenting your network."
    },
    {
      "id": 55,
      "question": "What is the primary purpose of using a virtual LAN (VLAN) in a switched network?",
      "options": [
        "To increase the overall network bandwidth.",
        "To logically segment a physical network into multiple, isolated broadcast domains, improving security, performance, and manageability.",
        "To provide wireless access to the network.",
        "To encrypt network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "VLANs allow you to create logically separate networks on the same physical switch infrastructure. This is crucial for isolating traffic, controlling broadcast domains, and improving security. They don't directly increase bandwidth (though they can improve performance), provide wireless access, or encrypt traffic.",
      "examTip": "VLANs are a fundamental tool for network segmentation and security in switched networks."
    },
    {
      "id": 56,
      "question": "What is the purpose of a default gateway in a TCP/IP network configuration?",
      "options": [
        "To provide wireless access to the network.",
        "To translate domain names into IP addresses.",
        "To provide a path for traffic to leave the local network and reach destinations on other networks, including the internet; it's typically the IP address of a router.",
        "To encrypt network traffic."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The default gateway is the 'exit point' for a device's local subnet. When a device needs to communicate with a device on a different network, it sends the traffic to its default gateway (usually a router). It's not about wireless access, DNS, or encryption.",
      "examTip": "A device needs a correctly configured default gateway to communicate outside its local subnet."
    },
    {
      "id": 57,
      "question": "Which type of network device operates at Layer 2 (the Data Link layer) of the OSI model and makes forwarding decisions based on MAC addresses?",
      "options": [
        "Hub",
        "Switch",
        "Router",
        "Repeater"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Switches learn the MAC addresses of connected devices and forward traffic only to the intended recipient, making them much more efficient than hubs (which broadcast to all ports). Routers operate at Layer 3, and hubs/repeaters operate at Layer 1.",
      "examTip": "Switches are the foundation of most modern LANs."
    },
    {
      "id": 58,
      "question": "What is Power over Ethernet (PoE)?",
      "options": [
        "A type of network cable.",
        "A technology that allows network cables to carry both data and electrical power, simplifying the deployment of devices like IP phones, wireless access points, and security cameras.",
        "A protocol for encrypting network traffic.",
        "A method for assigning IP addresses dynamically."
      ],
      "correctAnswerIndex": 1,
      "explanation": "PoE eliminates the need for separate power outlets for network devices, making installation easier and more flexible. It's not a cable type, encryption protocol, or IP assignment method.",
      "examTip": "PoE is widely used to power network devices where running separate power cables is difficult or expensive."
    },
    {
      "id": 59,
      "question": "What is the purpose of the traceroute (or tracert) command?",
      "options": [
        "To test the speed of a network connection.",
        "To display the IP address of a website.",
        "To trace the route that packets take to reach a destination host, showing each hop (router) along the way and the time it takes to reach each hop.",
        "To configure a network interface."
      ],
      "correctAnswerIndex": 2,
      "explanation": "`traceroute` (or `tracert` on Windows) is a diagnostic tool used to identify network routing problems and pinpoint sources of latency. It shows the path that packets take to reach a destination, including each router (hop) along the way. It's not primarily a speed test, a way to get a website's IP (that's nslookup or dig), or for interface configuration.",
      "examTip": "Use traceroute/tracert to diagnose network connectivity problems and identify points of failure or high latency."
    },
    {
      "id": 60,
      "question": "Which command is used on a Windows computer to release and renew a DHCP-assigned IP address?",
      "options": [
        "ipconfig /all",
        "ipconfig /release then ipconfig /renew",
        "ipconfig /flushdns",
        "netstat -r"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`ipconfig /release` releases the current IP address lease from the DHCP server, and `ipconfig /renew` requests a new IP address lease. `ipconfig /all` displays configuration information, `ipconfig /flushdns` clears the DNS cache, and `netstat -r` shows routing information.",
      "examTip": "Use ipconfig /release and ipconfig /renew to troubleshoot DHCP-related connectivity issues."
    },
    {
      "id": 61,
      "question": "A user reports being unable to access a specific network share.  You can ping the file server by IP address, and other users can access the share.  What is the MOST likely cause?",
      "options": [
        "The file server is down.",
        "The network cable is unplugged from the user's computer.",
        "A permissions issue preventing the user from accessing the specific share.",
        "A problem with the DNS server."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Since you can ping the server and other users can access it, the problem is likely local to the specific user – most likely a permissions issue on that share. A cable issue would affect all connectivity, and DNS isn’t involved when accessing by IP.",
      "examTip": "When troubleshooting access problems, consider user permissions after verifying basic connectivity."
    },
    {
      "id": 62,
      "question": "What is the primary purpose of a firewall in network security?",
      "options": [
        "To speed up your internet connection.",
        "To control network traffic by allowing or blocking connections based on predefined security rules, acting as a barrier between a trusted network and an untrusted network.",
        "To assign IP addresses dynamically.",
        "To translate domain names into IP addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A firewall is a security device (hardware or software) that enforces access control policies, preventing unauthorized access to or from a private network. It examines network traffic and blocks or allows it based on configured rules. It's not about speeding up connections, IP assignment, or DNS.",
      "examTip": "Firewalls are a fundamental component of any network security strategy."
    },
    {
      "id": 63,
      "question": "Which of the following best describes SSID in wireless networking?",
      "options": [
        "Secure System Identifier",
        "Service Set Identifier",
        "System Security ID",
        "Simple Service ID"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SSID (Service Set Identifier) is the name of a wireless network (Wi-Fi). It's the name you see when you search for available Wi-Fi networks on your device.",
      "examTip": "The SSID is the public name of your Wi-Fi network."
    },
    {
      "id": 64,
      "question": "Which of the following is a characteristic of a mesh network topology?",
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
      "id": 65,
      "question": "You are troubleshooting a slow network.  You use a protocol analyzer (like Wireshark) and notice a large number of TCP retransmissions. What does this MOST likely indicate?",
      "options": [
        "The network is secure and properly encrypted.",
        "Packet loss or network congestion, causing the sender to resend data.",
        "The DNS server is not responding.",
        "The DHCP server is not assigning IP addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "TCP retransmissions occur when the sender doesn't receive an acknowledgment for a transmitted packet within a certain time. This usually indicates packet loss due to network congestion, faulty hardware, or other network problems. It's not related to security/encryption, DNS, or DHCP.",
      "examTip": "A high number of TCP retransmissions is a strong indicator of network problems."
    },
    {
      "id": 66,
      "question": "What is the purpose of subnetting an IP network?",
      "options": [
        "To increase the total number of available IP addresses.",
        "To divide a network into smaller, logically separate subnetworks, improving security, performance, and address management.",
        "To encrypt network traffic.",
        "To make the network more vulnerable to attacks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Subnetting divides a larger network into smaller, isolated segments. This improves security (by limiting the scope of broadcasts and potential breaches), performance (by reducing broadcast traffic), and manageability (by organizing IP address allocation). It doesn't increase the total address space or deal with encryption.",
      "examTip": "Subnetting is a core concept in IP networking and network design."
    },
    {
      "id": 67,
      "question": "What is the primary purpose of network address translation (NAT)?",
      "options": [
        "To encrypt network traffic.",
        "To conserve public IPv4 addresses by allowing multiple devices on a private network to share a single public IP address when communicating with the internet.",
        "To dynamically assign IP addresses to devices.",
        "To prevent network loops."
      ],
      "correctAnswerIndex": 1,
      "explanation": "NAT translates private IP addresses (used within a local network) to a public IP address (used on the internet), and vice versa. This allows many devices to share a single public IP, which is essential given the limited number of available IPv4 addresses. It's not primarily for encryption, dynamic IP assignment, or loop prevention.",
      "examTip": "NAT is a fundamental technology for connecting private networks to the internet."
    },
    {
      "id": 68,
      "question": "Which of the following is a security best practice for managing network devices?",
      "options": [
        "Using default usernames and passwords.",
        "Leaving all ports open on firewalls.",
        "Regularly updating device firmware to patch security vulnerabilities and disabling unnecessary services.",
        "Sharing administrative passwords with all users."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Keeping device firmware up-to-date is crucial for patching security vulnerabilities. Disabling unnecessary services reduces the attack surface. Using default credentials, leaving ports open, and sharing passwords are all major security risks.",
      "examTip": "Regularly update firmware and disable unnecessary services on network devices."
    },
    {
      "id": 69,
      "question": "What is the purpose of network documentation?",
      "options": [
        "To make the network run faster.",
        "To provide a detailed record of the network's design, configuration, and operation, aiding in troubleshooting, planning, and maintenance.",
        "To replace the need for network security.",
        "To prevent users from accessing the internet."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Network documentation (including diagrams, IP address assignments, device configurations, procedures, and contact information) is essential for understanding, managing, and troubleshooting a network. It doesn't make the network run faster, replace security, or prevent internet access.",
      "examTip": "Maintain accurate and up-to-date network documentation."
    },
    {
      "id": 70,
      "question": "What is a default gateway in a TCP/IP network configuration?",
      "options": [
        "The IP address of the DNS server.",
        "The IP address of the router that a device uses to send traffic to destinations outside its local subnet.",
        "The MAC address of the network interface card.",
        "The subnet mask used on the network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The default gateway is the 'exit point' for a device's local network. When a device needs to communicate with a device on a different network, it sends the traffic to its default gateway, which is typically the IP address of a router. It's not the DNS server, MAC address, or subnet mask.",
      "examTip": "A device needs a default gateway configured to communicate outside its local subnet."
    },
    {
      "id": 71,
      "question": "Which of the following is a common use for a virtual private network (VPN)?",
      "options": [
        "To speed up your internet connection.",
        "To securely connect to a private network over a public network, protecting your data and privacy.",
        "To block all incoming and outgoing network traffic.",
        "To automatically assign IP addresses to devices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A VPN encrypts your internet traffic and routes it through a secure server, masking your IP address and protecting your data – especially on public Wi-Fi – while allowing secure access to private network resources. It doesn't primarily speed up connections, block all traffic, or assign IPs.",
      "examTip": "Use a VPN for secure remote access and to enhance your online privacy."
    },
    {
      "id": 72,
      "question": "Which type of network attack involves an attacker overwhelming a network or server with traffic from a single source?",
      "options": [
        "An attempt to steal user passwords.",
        "An attempt to overwhelm a network or server with traffic from a single source, making it unavailable to legitimate users.",
        "An attempt to trick users into revealing personal information.",
        "An attempt to gain unauthorized access to a computer system by guessing passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DoS attack aims to disrupt a network service by flooding it with traffic from a single attacking machine, making the service unavailable to legitimate users. Password stealing is credential theft, tricking users is phishing, and guessing passwords is brute-force. (Note: A DDoS attack uses multiple sources.)",
      "examTip": "DoS attacks can cause significant downtime and disruption."
    },
    {
      "id": 73,
      "question": "Which of the following best describes the relationship between IP addresses and MAC addresses?",
      "options": [
        "IP addresses are physical addresses; MAC addresses are logical addresses.",
        "IP addresses are used for communication within a local network; MAC addresses are used for communication across networks.",
        "IP addresses are assigned dynamically; MAC addresses are assigned statically by the network administrator.",
        "IP addresses are used for routing between networks (Layer 3); MAC addresses are used for communication within a local network segment (Layer 2)."
      ],
      "correctAnswerIndex": 3,
      "explanation": "IP addresses are logical addresses used for routing data between networks (Layer 3), while MAC addresses are physical addresses used for local delivery within a network segment (Layer 2).",
      "examTip": "IP addresses are for global routing; MAC addresses are for local delivery."
    },
    {
      "id": 74,
      "question": "Which of the following is a potential security risk associated with using default usernames and passwords on network devices?",
      "options": [
        "It makes the network more secure.",
        "It simplifies network administration.",
        "Attackers can easily gain unauthorized access using publicly known default credentials.",
        "It improves network performance."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Default usernames and passwords are well-known and easily found online. Failing to change them is a major security vulnerability that allows attackers to compromise network devices.",
      "examTip": "Always change default credentials on all network devices immediately after installation."
    },
    {
      "id": 75,
      "question": "Which command-line tool is used to display the ARP cache on a Windows system?",
      "options": [
        "ipconfig /all",
        "arp -a",
        "netstat -r",
        "route print"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `arp -a` command shows the ARP cache, which contains mappings between IP addresses and MAC addresses that the computer has learned.",
      "examTip": "The ARP cache is essential for local network communication."
    },
    {
      "id": 76,
      "question": "Which of the following best describes a honeypot in cybersecurity?",
      "options": [
        "A secure server that stores sensitive data.",
        "A decoy system designed to attract and trap attackers, allowing study of their methods.",
        "A type of firewall.",
        "A tool for encrypting network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A honeypot is a trap for attackers—a deliberately vulnerable system that mimics a real target to lure attackers and study their behavior.",
      "examTip": "Honeypots are used for cybersecurity research and threat intelligence."
    },
    {
      "id": 77,
      "question": "Which of the following best describes social engineering in cybersecurity?",
      "options": [
        "Building and managing a social media platform.",
        "Manipulating people into divulging confidential information or performing actions that compromise security.",
        "Using social media for marketing and outreach.",
        "Networking with colleagues at professional events."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Social engineering exploits human vulnerabilities using deception to gain confidential information or access.",
      "examTip": "Always verify requests for sensitive information and be aware of common social engineering tactics."
    },
    {
      "id": 78,
      "question": "What does encryption do to data?",
      "options": [
        "It makes data larger and easier to read.",
        "It scrambles data into an unreadable format (ciphertext), protecting it from unauthorized access.",
        "It deletes data permanently.",
        "It organizes data into folders and files."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption transforms data into an unreadable form that can only be deciphered with the correct decryption key.",
      "examTip": "Encryption is crucial for protecting sensitive data."
    },
    {
      "id": 79,
      "question": "Which of the following is a key characteristic of cloud computing?",
      "options": [
        "All computing resources are on-premises.",
        "On-demand access to shared computing resources over the internet, offering scalability and flexibility.",
        "Requires a significant upfront investment in hardware.",
        "Limited scalability and flexibility."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Cloud computing provides scalable, on-demand access to computing resources over the internet on a pay-as-you-go basis.",
      "examTip": "Cloud computing offers agility, scalability, and cost efficiency."
    },
    {
      "id": 80,
      "question": "What is the purpose of using DHCP reservation?",
      "options": [
        "DHCP scope",
        "DHCP reservation (or static mapping)",
        "DHCP exclusion",
        "DHCP lease time"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DHCP reservation maps a specific MAC address to a specific IP address so that the device always receives the same IP address.",
      "examTip": "Use DHCP reservations for servers and devices that require consistent IP addresses."
    },
    {
      "id": 81,
      "question": "Which command-line tool is used to display the current routing table on a Windows computer?",
      "options": [
        "ipconfig /all",
        "arp -a",
        "netstat -r",
        "route print"
      ],
      "correctAnswerIndex": 3,
      "explanation": "The `route print` command displays the routing table, showing how the computer forwards traffic to different networks.",
      "examTip": "Use route print to view your computer's routing table."
    },
    {
      "id": 82,
      "question": "What is a broadcast storm and what can it cause?",
      "options": [
        "Improved network security.",
        "Increased network bandwidth.",
        "Severe performance degradation or network outage due to excessive broadcast traffic.",
        "Faster internet speeds."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A broadcast storm occurs when broadcast traffic overwhelms the network, consuming bandwidth and processing power, potentially causing outages.",
      "examTip": "Prevent broadcast storms with proper network design and STP."
    },
    {
      "id": 83,
      "question": "What is the primary purpose of using VLANs in a switched network?",
      "options": [
        "To increase overall network bandwidth.",
        "To logically segment a physical network into isolated broadcast domains for better security and performance.",
        "To provide wireless access to the network.",
        "To encrypt network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "VLANs create logical divisions within a physical network, isolating traffic to improve security and performance.",
      "examTip": "VLANs are fundamental for network segmentation and reducing broadcast domains."
    },
    {
      "id": 84,
      "question": "Which command is used to test network connectivity to a remote host and measure round-trip time?",
      "options": [
        "tracert (or traceroute)",
        "ping",
        "ipconfig",
        "nslookup"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The ping command sends ICMP Echo Request packets and measures the time until an Echo Reply is received, indicating connectivity and latency.",
      "examTip": "Ping is a basic yet essential tool for troubleshooting network connectivity."
    },
    {
      "id": 85,
      "question": "What is a honeypot in network security?",
      "options": [
        "A secure server that stores sensitive data.",
        "A decoy system designed to attract and trap attackers for study.",
        "A type of firewall.",
        "A tool for encrypting network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A honeypot is a decoy system meant to lure attackers so that their methods can be observed and studied.",
      "examTip": "Honeypots help gather threat intelligence by attracting attackers."
    },
    {
      "id": 86,
      "question": "Which of the following best describes social engineering in cybersecurity?",
      "options": [
        "Building and managing a social media platform.",
        "Manipulating people into divulging confidential information or performing actions that compromise security.",
        "Using social media for marketing.",
        "Networking with colleagues at professional events."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Social engineering exploits human behavior by tricking people into giving up sensitive information or performing unsafe actions.",
      "examTip": "Always verify requests for sensitive data and be aware of common social engineering tactics."
    },
    {
      "id": 87,
      "question": "What does encryption do to data?",
      "options": [
        "It makes data larger and easier to read.",
        "It scrambles data into an unreadable format (ciphertext), protecting it from unauthorized access.",
        "It deletes data permanently.",
        "It organizes data into folders and files."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Encryption converts data into an unreadable format (ciphertext) that can only be reversed with the correct decryption key.",
      "examTip": "Encryption is key to protecting data in transit and at rest."
    },
    {
      "id": 88,
      "question": "Which of the following is a key characteristic of cloud computing?",
      "options": [
        "All computing resources are located on-premises.",
        "On-demand access to shared computing resources over the internet, offering scalability, flexibility, and cost savings.",
        "Requires a significant upfront investment in hardware.",
        "Limited scalability and flexibility."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Cloud computing offers scalable, on-demand access to computing resources over the internet with a pay-as-you-go model.",
      "examTip": "Cloud computing provides agility and cost efficiency."
    },
    {
      "id": 89,
      "question": "Which command-line tool is used to display the ARP cache on a Windows system?",
      "options": [
        "ipconfig /all",
        "arp -a",
        "netstat -r",
        "route print"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `arp -a` command displays the ARP cache, which maps IP addresses to MAC addresses on the local network.",
      "examTip": "Knowing the ARP cache can help diagnose local connectivity issues."
    },
    {
      "id": 90,
      "question": "What is a potential consequence of a broadcast storm on a network?",
      "options": [
        "Improved network security.",
        "Increased network bandwidth.",
        "Severe network performance degradation or outage due to excessive broadcast traffic.",
        "Faster internet speeds."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A broadcast storm overwhelms a network with broadcast traffic, leading to performance degradation or even a complete network outage.",
      "examTip": "Prevent broadcast storms with proper network design and protocols like STP."
    },
    {
      "id": 91,
      "question": "Which of the following best describes the purpose of port forwarding on a router?",
      "options": [
        "To block all incoming traffic to a specific port.",
        "To allow external devices to access a specific service on an internal device by mapping an external port to an internal IP address and port.",
        "To encrypt network traffic.",
        "To speed up your internet connection."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Port forwarding creates a rule that directs incoming traffic on a particular external port to a specific internal IP address and port, making internal services accessible from outside the network.",
      "examTip": "Port forwarding is often used for hosting game or web servers from behind a router."
    },
    {
      "id": 92,
      "question": "What is the primary purpose of the Address Resolution Protocol (ARP)?",
      "options": [
        "To translate domain names into IP addresses.",
        "To dynamically assign IP addresses to devices.",
        "To map IP addresses to MAC addresses on a local network, allowing communication at the data link layer.",
        "To encrypt network traffic."
      ],
      "correctAnswerIndex": 2,
      "explanation": "ARP is used to resolve the physical (MAC) address corresponding to a given IP address on a local network, enabling proper data delivery at Layer 2.",
      "examTip": "Without ARP, devices on a local network could not properly communicate."
    },
    {
      "id": 93,
      "question": "What does WPA3 stand for, and why is it important for wireless network security?",
      "options": [
        "Wired Protocol Access 3; it's an older, less secure protocol.",
        "Wi-Fi Protected Access 3; it's the latest and most secure wireless security protocol, offering improved encryption and protection against attacks.",
        "Wireless Protected Area 3; it's a type of wireless antenna.",
        "Web Page Access 3; it's a protocol for accessing websites."
      ],
      "correctAnswerIndex": 1,
      "explanation": "WPA3 (Wi-Fi Protected Access 3) is the most recent and secure wireless protocol, providing stronger encryption and better resistance to attacks than its predecessors.",
      "examTip": "Always use WPA3 if available; if not, use WPA2 with AES."
    },
    {
      "id": 94,
      "question": "Which command-line tool is commonly used to test network connectivity to a remote host and measure round-trip time?",
      "options": [
        "tracert (or traceroute)",
        "ping",
        "ipconfig",
        "nslookup"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The ping command sends ICMP Echo Request packets and measures the time until an Echo Reply is received, indicating connectivity and latency.",
      "examTip": "Ping is a basic yet essential tool for troubleshooting network connectivity."
    },
    {
      "id": 95,
      "question": "What is a honeypot in cybersecurity?",
      "options": [
        "A secure server that stores sensitive data.",
        "A decoy system or network designed to attract and trap attackers for analysis.",
        "A type of firewall.",
        "A tool for encrypting network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A honeypot is intentionally vulnerable and is used to lure attackers so that their techniques can be studied, helping improve security measures.",
      "examTip": "Honeypots are useful for gathering threat intelligence."
    },
    {
      "id": 96,
      "question": "What is the purpose of an intrusion detection system (IDS)?",
      "options": [
        "To automatically assign IP addresses to devices.",
        "To actively block or prevent network attacks.",
        "To monitor network traffic for suspicious activity and generate alerts for security personnel, but not take automatic action.",
        "To encrypt network traffic."
      ],
      "correctAnswerIndex": 2,
      "explanation": "An IDS passively monitors network traffic to detect potential security breaches or policy violations and alerts administrators. It does not automatically block traffic; that is the role of an intrusion prevention system (IPS).",
      "examTip": "Think of an IDS as a security camera that observes and alerts, rather than intervening directly."
    },
    {
      "id": 97,
      "question": "What is a distributed denial-of-service (DDoS) attack?",
      "options": [
        "An attempt to steal user passwords.",
        "An attempt to overwhelm a network or server with traffic from multiple, compromised computers (a botnet), making it unavailable to legitimate users.",
        "A type of phishing attack.",
        "A type of brute-force password-guessing attack."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DDoS attack uses traffic from many sources (often a botnet) to overwhelm a target, making it much harder to mitigate than a DoS attack from a single source.",
      "examTip": "DDoS attacks require robust mitigation strategies due to their distributed nature."
    },
    {
      "id": 98,
      "question": "What is the primary purpose of using multi-factor authentication (MFA)?",
      "options": [
        "Using a very long and complex password.",
        "A security measure that requires two distinct forms of identification to verify a user's identity (e.g., a password and a code sent to a mobile phone).",
        "Using the same password for two different accounts.",
        "None of the above."
      ],
      "correctAnswerIndex": 1,
      "explanation": "MFA significantly enhances account security by requiring not just something you know (like a password) but also something you have (like a phone) or something you are (like a fingerprint). This makes it much harder for attackers to gain unauthorized access.",
      "examTip": "Enable MFA whenever possible, especially for important accounts."
    },
    {
      "id": 99,
      "question": "Which of the following is a potential security risk associated with using default usernames and passwords on network devices (routers, switches, access points)?",
      "options": [
        "It makes the network more secure.",
        "It simplifies network administration.",
        "Attackers can easily gain unauthorized access to the device using publicly known default credentials.",
        "It improves network performance."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Default usernames and passwords are well-known and can be easily exploited by attackers, making them a serious security risk.",
      "examTip": "Always change default credentials immediately after installation."
    },
    {
      "id": 100,
      "question": "You are setting up a network and need to ensure that a specific server always receives the same IP address from the DHCP server. What DHCP feature should you use?",
      "options": [
        "DHCP scope",
        "DHCP reservation (or static mapping)",
        "DHCP exclusion",
        "DHCP lease time"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DHCP reservation maps a specific MAC address to a specific IP address so that the designated device always receives the same IP address from the DHCP server.",
      "examTip": "Use DHCP reservations for servers and other devices that require a consistent IP address."
    }
  ]
});
