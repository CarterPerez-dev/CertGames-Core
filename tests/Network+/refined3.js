db.tests.insertOne({
  "category": "nplus",
  "testId": 2,
  "testName": "Network+ Practice Test #3 (Easy)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "Which layer of the OSI model deals with physical cabling?",
      "options": [
        "Layer 7",
        "Layer 4",
        "Layer 1",
        "Layer 3"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The Physical layer (Layer 1) defines the physical characteristics of the network, including cabling, voltage levels, and data rates.",
      "examTip": "Remember 'Physical' layer means the actual wires and signals."
    },
    {
      "id": 2,
      "question": "What is a common use for a network switch?",
      "options": [
        "To connect to a different network, like the Internet.",
        "To connect multiple devices within the same local network.",
        "To provide wireless access to the network.",
        "To translate domain names into IP addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Switches create a local network by connecting devices like computers, printers, and servers, allowing them to communicate efficiently.",
      "examTip": "Switches forward traffic based on MAC addresses within a local network."
    },
    {
      "id": 3,
      "question": "What does 'HTTP' stand for?",
      "options": [
        "Hypertext Transfer Program",
        "Hypertext Transfer Protocol",
        "High Transfer Text Protocol",
        "Home Text Transfer Protocol"
      ],
      "correctAnswerIndex": 1,
      "explanation": "HTTP stands for Hypertext Transfer Protocol, the foundation of data communication on the World Wide Web (for non-secure websites).",
      "examTip": "HTTP is used for accessing most websites (HTTPS is for secure websites)."
    },
    {
      "id": 4,
      "question": "What is an advantage of using a client-server network model?",
      "options": [
        "It's easier to set up than a peer-to-peer network.",
        "Centralized management of resources and security.",
        "All computers have equal roles and responsibilities.",
        "It's less expensive than a peer-to-peer network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Client-server networks offer centralized control over data, security, and user access, making them suitable for larger organizations.  While potentially more expensive to set up, they can offer long-term cost savings through better management.",
      "examTip": "Client-server networks provide better control and scalability than peer-to-peer."
    },
    {
      "id": 5,
      "question": "Which protocol is used to send email?",
      "options": [
        "HTTP",
        "FTP",
        "SMTP",
        "DNS"
      ],
      "correctAnswerIndex": 2,
      "explanation": "SMTP (Simple Mail Transfer Protocol) is the standard protocol for sending email across the internet. HTTP is for web browsing, FTP is for file transfer, and DNS translates domain names.",
      "examTip": "Remember SMTP for sending email."
    },
    {
      "id": 6,
      "question": "What type of address is 192.168.1.1?",
      "options": [
        "MAC address",
        "IPv4 address",
        "IPv6 address",
        "URL"
      ],
      "correctAnswerIndex": 1,
      "explanation": "192.168.1.1 is a commonly used private IPv4 address. IPv4 addresses are 32-bit numbers, often written in dotted-decimal notation. MAC addresses are hardware addresses, IPv6 addresses are 128-bit, and URLs are web addresses.",
      "examTip": "Recognize the format of IPv4 addresses (four numbers separated by dots)."
    },
    {
      "id": 7,
      "question": "What does a subnet mask do?",
      "options": [
        "Encrypts network traffic",
        "Identifies the network and host portions of an IP address.",
        "Assigns IP addresses automatically.",
        "Filters network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The subnet mask works with the IP address to determine which part of the address identifies the network and which part identifies the specific host on that network.",
      "examTip": "Subnet masks are essential for IP addressing and routing."
    },
    {
      "id": 8,
      "question": "Which command is used to test connectivity to a remote host and measure round-trip time?",
      "options": [
        "tracert",
        "ping",
        "ipconfig",
        "nslookup"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `ping` command sends ICMP Echo Request packets to a target host and listens for Echo Reply packets, measuring the time it takes for the round trip.",
      "examTip": "`ping` is a fundamental tool for network troubleshooting."
    },
    {
      "id": 9,
      "question": "What is the purpose of a default gateway?",
      "options": [
        "To block unwanted network traffic.",
        "To provide a path for traffic to leave the local network.",
        "To assign IP addresses to devices.",
        "To translate domain names to IP addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The default gateway is the IP address of the router that a device uses to send traffic destined for networks outside its own local subnet.",
      "examTip": "Without a default gateway, devices can only communicate within their local network."
    },
    {
      "id": 10,
      "question": "What is the main advantage of using fiber optic cable over copper cable?",
      "options": [
        "It's cheaper.",
        "It's easier to install.",
        "It can transmit data over longer distances with less signal loss.",
        "It's more resistant to physical damage."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Fiber optic cables use light to transmit data, allowing for much higher bandwidths and longer distances compared to copper cables, with minimal signal degradation.",
      "examTip": "Fiber is the preferred choice for high-speed, long-distance network connections."
    },
    {
      "id": 11,
      "question": "Which of the following is a security feature of a firewall?",
      "options": [
        "Assigning IP addresses to devices.",
        "Filtering network traffic based on rules.",
        "Providing wireless network access.",
        "Translating domain names to IP addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Firewalls control network access by examining incoming and outgoing traffic and blocking or allowing it based on predefined security rules.",
      "examTip": "Firewalls are essential for protecting networks from unauthorized access."
    },
    {
      "id": 12,
      "question": "What is the role of a DNS server?",
      "options": [
        "To assign IP addresses automatically.",
        "To translate domain names (like google.com) into IP addresses.",
        "To encrypt network traffic.",
        "To connect to the internet."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DNS servers act like the internet's phone book, converting human-readable domain names into the numerical IP addresses that computers use to communicate.",
      "examTip": "DNS is crucial for navigating the internet using website names."
    },
    {
      "id": 13,
      "question": "What is the purpose of a DHCP server?",
      "options": [
        "To translate domain names to IP addresses.",
        "To automatically assign IP addresses and other network configuration to devices.",
        "To route traffic between different networks.",
        "To provide secure remote access to a network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DHCP (Dynamic Host Configuration Protocol) servers automate the process of assigning IP addresses, subnet masks, default gateways, and DNS server information to devices on a network.",
      "examTip": "DHCP simplifies network administration and prevents IP address conflicts."
    },
    {
      "id": 14,
      "question": "Which type of network spans a large geographical area, often connecting multiple cities or countries?",
      "options": [
        "LAN (Local Area Network)",
        "WAN (Wide Area Network)",
        "MAN (Metropolitan Area Network)",
        "PAN (Personal Area Network)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "WANs (Wide Area Networks) cover large distances, connecting smaller networks (like LANs and MANs) together. The internet is the largest example of a WAN.",
      "examTip": "WANs connect geographically dispersed networks."
    },
    {
      "id": 15,
      "question": "What is a benefit of using a VPN?",
      "options": [
        "It makes your internet connection faster.",
        "It encrypts your internet traffic, providing security and privacy, especially on public Wi-Fi.",
        "It allows you to access blocked websites.",
        "It prevents viruses from infecting your computer."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A VPN (Virtual Private Network) creates a secure, encrypted tunnel for your internet traffic, protecting your data from eavesdropping and enhancing your privacy, especially on untrusted networks like public Wi-Fi. While it can sometimes be used to bypass geographical restrictions, that's not its core purpose. It does not guarantee virus protection.",
      "examTip": "Use a VPN to secure your connection on public Wi-Fi."
    },
    {
      "id": 16,
      "question": "Which of the following is a characteristic of a star network topology?",
      "options": [
        "All devices are connected to a single, central cable.",
        "All devices are connected to a central hub or switch.",
        "Devices are connected in a circular loop.",
        "Each device has multiple connections to other devices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "In a star topology, each network device has a dedicated connection to a central point, usually a switch or hub. This makes it easy to manage and isolate problems.",
      "examTip": "Star topology is the most common topology in modern Ethernet networks."
    },
    {
      "id": 17,
      "question": "What is 'bandwidth' in networking terms?",
      "options": [
        "The physical length of a network cable.",
        "The amount of data that can be transmitted over a network connection in a given period.",
        "The number of devices connected to a switch.",
        "The speed of a computer's processor."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Bandwidth is the capacity of a network connection to carry data, usually measured in bits per second (bps), kilobits per second (Kbps), megabits per second (Mbps), or gigabits per second (Gbps).",
      "examTip": "Higher bandwidth generally means faster data transfer rates."
    },
    {
      "id": 18,
      "question": "Which protocol is used for secure web browsing?",
      "options": [
        "HTTP",
        "HTTPS",
        "FTP",
        "SMTP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "HTTPS (Hypertext Transfer Protocol Secure) is the secure version of HTTP. It encrypts communication between your browser and the website, protecting sensitive information.",
      "examTip": "Always look for HTTPS (and the padlock icon) in your browser's address bar when entering personal information or financial details."
    },
    {
      "id": 19,
      "question": "What does 'NIC' stand for in networking?",
      "options": [
        "Network Interface Card",
        "Network Internet Connection",
        "Network Instruction Code",
        "New Internet Card"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NIC stands for Network Interface Card. It's the hardware component that allows a computer or other device to connect to a network.",
      "examTip": "Every device connected to a network needs a NIC, either wired or wireless."
    },
    {
      "id": 20,
      "question": "What is a common security practice for wireless networks?",
      "options": [
        "Using an open network with no password.",
        "Using WPA2 or WPA3 encryption with a strong password.",
        "Using the default SSID and password.",
        "Disabling the firewall."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Enabling strong encryption (WPA2 or WPA3) and using a complex, unique password protects your wireless network from unauthorized access. Changing the default SSID is also a good practice, but less critical than encryption.",
      "examTip": "Always secure your Wi-Fi network with strong encryption and a strong password."
    },
    {
      "id": 21,
      "question": "What is 'latency' in network terms?",
      "options": [
        "The amount of data that can be transmitted.",
        "The time it takes for data to travel from its source to its destination.",
        "The number of devices connected to a network.",
        "The physical distance between two network devices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Latency refers to the delay experienced by data as it travels across a network. High latency can cause slow response times, especially noticeable in real-time applications like online gaming or video conferencing.",
      "examTip": "Low latency is desirable for good network performance."
    },
    {
      "id": 22,
      "question": "What is the function of a router in a network?",
      "options": [
        "To connect multiple devices within the same local network.",
        "To forward data packets between different networks.",
        "To provide wireless access to a network.",
        "To translate domain names into IP addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Routers operate at the network layer (Layer 3) of the OSI model and are responsible for forwarding data packets between different networks based on IP addresses. Switches connect devices within the same network; access points provide wireless connectivity; and DNS servers translate domain names.",
      "examTip": "Routers connect networks together; switches connect devices within a network."
    },
    {
      "id": 23,
      "question": "What is a good first step when troubleshooting a network connectivity problem?",
      "options": [
        "Reinstall the operating system.",
        "Check physical connections (cables, power) and Wi-Fi settings.",
        "Replace the network interface card.",
        "Contact the device manufacturer."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Before taking more drastic measures, always verify the basics: ensure cables are securely connected, power is on, and Wi-Fi is enabled and connected (if applicable).",
      "examTip": "Start troubleshooting with the simplest and most common causes."
    },
    {
      "id": 24,
      "question": "What is the purpose of a subnet mask?",
      "options": [
        "To encrypt network traffic.",
        "To divide an IP address into a network portion and a host portion.",
        "To assign IP addresses dynamically.",
        "To filter network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A subnet mask is used in conjunction with an IP address to identify the network to which the device belongs and the specific host ID on that network. This is essential for routing.",
      "examTip": "Subnet masks and IP addresses work together to define network addressing."
    },
    {
      "id": 25,
      "question": "What is the purpose of the `ipconfig /all` command in Windows?",
      "options": [
        "To display the routing table.",
        "To release and renew a DHCP lease.",
        "To display detailed network configuration information for all network adapters.",
        "To test network connectivity to a remote host."
      ],
      "correctAnswerIndex": 2,
      "explanation": "`ipconfig /all` provides comprehensive information about network interfaces, including IP address, subnet mask, default gateway, DNS servers, MAC address, and DHCP status. `route print` shows the routing table, `ipconfig /release` and `/renew` manage DHCP leases, and `ping` tests connectivity.",
      "examTip": "`ipconfig /all` is a powerful command for gathering network information on Windows systems."
    },
    {
      "id": 26,
      "question": "Which of the following is a characteristic of a mesh network topology?",
      "options": [
        "All devices are connected to a central hub or switch.",
        "Devices are connected in a circular loop.",
        "Each device has multiple paths to other devices, providing redundancy.",
        "All devices are connected to a single cable."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Mesh networks offer high redundancy and fault tolerance because each node is connected to multiple other nodes. If one link fails, there are alternative paths for data to travel.",
      "examTip": "Mesh networks are highly reliable but can be more complex to manage."
    },
    {
      "id": 27,
      "question": "What does 'MAC' address stand for?",
      "options": [
        "Main Access Control",
        "Media Access Control",
        "Multiple Address Code",
        "Modem Access Code"
      ],
      "correctAnswerIndex": 1,
      "explanation": "MAC stands for Media Access Control. It is the unique physical address assigned to a network interface card (NIC).",
      "examTip": "The MAC address is like a device's hardware serial number on the network."
    },
    {
      "id": 28,
      "question": "Which of the following is a valid IPv6 address?",
      "options": [
        "192.168.1.1",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "256.1.1.1",
        "ABC.DEF.GHI.JKL"
      ],
      "correctAnswerIndex": 1,
      "explanation": "2001:0db8:85a3:0000:0000:8a2e:0370:7334 is a valid IPv6 address.  IPv6 addresses are 128-bit, written in hexadecimal, and separated by colons.  The other options are either invalid IPv4 addresses or not IP addresses at all.",
      "examTip": "Learn to recognize the format of IPv6 addresses (hexadecimal and colons)."
    },
    {
      "id": 29,
      "question": "What is the function of an access point (AP) in a wireless network?",
      "options": [
        "To connect wired devices to a network.",
        "To connect wireless devices to a wired network.",
        "To route traffic between different networks.",
        "To assign IP addresses dynamically."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An access point (AP) acts as a bridge between wireless devices (like laptops and smartphones) and a wired network (usually Ethernet).  It allows wireless devices to communicate with wired devices and access network resources.",
      "examTip": "Think of an AP as a 'wireless switch'."
    },
    {
      "id": 30,
      "question": "What is a common symptom of a network loop?",
      "options": [
        "Slow internet speeds.",
        "Broadcast storms that can significantly degrade network performance.",
        "Inability to obtain an IP address.",
        "Frequent disconnections from wireless networks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Network loops, often caused by STP (Spanning Tree Protocol) failures, create broadcast storms where broadcast traffic circulates endlessly, consuming bandwidth and potentially crashing the network.  The other options are more likely caused by other issues.",
      "examTip": "STP is crucial for preventing network loops in switched networks."
    },
    {
      "id": 31,
      "question": "What is the purpose of using VLANs?",
      "options": [
        "To increase network bandwidth.",
        "To logically segment a physical network into multiple, separate broadcast domains.",
        "To encrypt network traffic.",
        "To assign IP addresses to devices automatically."
      ],
      "correctAnswerIndex": 1,
      "explanation": "VLANs (Virtual LANs) divide a physical network into multiple logical networks, improving security, manageability, and performance by isolating traffic and reducing broadcast domains. They don't directly increase bandwidth, encrypt traffic, or assign IP addresses (DHCP does that).",
      "examTip": "VLANs are a fundamental tool for network segmentation."
    },
    {
      "id": 32,
      "question": "Which command is used to release and renew a DHCP lease on a Windows computer?",
      "options": [
        "ipconfig /all",
        "ipconfig /release then ipconfig /renew",
        "ipconfig /flushdns",
        "netstat -r"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`ipconfig /release` releases the current IP address assigned by DHCP, and `ipconfig /renew` requests a new IP address from the DHCP server.  `ipconfig /all` displays configuration, `ipconfig /flushdns` clears the DNS cache, and `netstat -r` shows routing information.",
      "examTip": "Use `ipconfig /release` and `ipconfig /renew` to troubleshoot DHCP-related connectivity issues."
    },
    {
      "id": 33,
      "question": "What does 'FTP' stand for?",
      "options": [
        "File Transfer Protocol",
        "Fast Transfer Protocol",
        "File Transmission Program",
        "Full Transfer Program"
      ],
      "correctAnswerIndex": 0,
      "explanation": "FTP stands for File Transfer Protocol, a standard network protocol used to transfer files between a client and a server on a computer network.",
      "examTip": "FTP is commonly used for uploading and downloading files to/from web servers."
    },
    {
      "id": 34,
      "question": "Which of the following is a characteristic of single-mode fiber optic cable compared to multimode?",
      "options": [
        "It's used for shorter distances.",
        "It has a larger core diameter.",
        "It supports longer distances and higher bandwidths.",
        "It uses LEDs as a light source."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Single-mode fiber has a smaller core that allows only one mode of light to propagate, reducing signal loss and enabling much longer transmission distances and higher bandwidths compared to multimode fiber. Multimode uses LEDs and is for shorter distances.",
      "examTip": "Single-mode fiber is used for long-haul, high-bandwidth applications; multimode is for shorter distances within buildings or campuses."
    },
    {
      "id": 35,
      "question": "What is the role of an authoritative DNS server?",
      "options": [
        "To cache DNS records from other servers.",
        "To hold the master copy of DNS records for a specific domain.",
        "To forward DNS requests to other servers.",
        "To provide DNS services to home users."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An authoritative DNS server holds the original, definitive records for a particular domain. It's the ultimate source of truth for that domain's DNS information. Caching servers store copies of records temporarily, and forwarding servers relay requests.",
      "examTip": "Authoritative DNS servers are the primary source of information for a domain's DNS records."
    },
    {
      "id": 36,
      "question": "Which of the following is a security risk associated with using public Wi-Fi?",
      "options": [
        "Increased network speed.",
        "Stronger encryption.",
        "Potential for eavesdropping and data interception due to lack of security.",
        "Automatic access to all network resources."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Public Wi-Fi networks often lack strong security measures, making it easier for attackers to intercept data transmitted over the network. Always be cautious when using public Wi-Fi.",
      "examTip": "Use a VPN when connecting to public Wi-Fi to encrypt your traffic and protect your data."
    },
    {
      "id": 37,
      "question": "What is a 'denial-of-service' (DoS) attack?",
      "options": [
        "An attempt to steal user passwords.",
        "An attempt to overwhelm a network or server with traffic, making it unavailable to legitimate users.",
        "An attempt to trick users into revealing personal information.",
        "An attempt to gain unauthorized access to a computer system."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DoS attack aims to disrupt a network service by flooding it with excessive traffic, preventing legitimate users from accessing it. Password stealing is credential theft, tricking users is phishing, and gaining unauthorized access is a general hacking attempt.",
      "examTip": "DoS attacks can cause significant downtime and disruption."
    },
    {
      "id": 38,
      "question": "Which technology is used to create a secure tunnel over the internet, allowing remote access to a private network?",
      "options": [
        "DNS",
        "DHCP",
        "VPN",
        "FTP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A VPN (Virtual Private Network) creates an encrypted connection over a public network (like the internet), providing secure access to a private network as if the user were directly connected.",
      "examTip": "VPNs are essential for secure remote access and protecting data privacy."
    },
    {
      "id": 39,
      "question": "Which command is used to display the routing table on a Windows computer?",
      "options": [
        "ipconfig /all",
        "route print",
        "netstat -r",
        "tracert"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `route print` command displays the current routing table, showing how the computer will forward traffic to different networks. `ipconfig /all` shows interface details, `netstat -r` shows routing information (but less clearly than `route print`), and `tracert` traces the route to a destination.",
      "examTip": "Use `route print` to see how your computer routes traffic to different networks."
    },
    {
      "id": 40,
      "question": "What is a benefit of using network address translation (NAT)?",
      "options": [
        "It encrypts network traffic.",
        "It allows multiple devices on a private network to share a single public IP address.",
        "It assigns IP addresses dynamically.",
        "It filters network traffic based on content."
      ],
      "correctAnswerIndex": 1,
      "explanation": "NAT translates private IP addresses used within a local network to a single public IP address used on the internet, conserving public IP addresses and providing a layer of security. Encryption is done by other protocols, DHCP assigns IPs, and content filtering is done by firewalls/proxies.",
      "examTip": "NAT is essential for connecting private networks to the internet using a limited number of public IP addresses."
    },
    {
      "id": 41,
      "question": "Which of the following is the MOST secure wireless encryption protocol?",
      "options": [
        "WEP",
        "WPA",
        "WPA2",
        "WPA3"
      ],
      "correctAnswerIndex": 3,
      "explanation": "WPA3 is the latest and most secure wireless security protocol, offering improved encryption and protection against attacks. WEP is extremely vulnerable, and WPA and WPA2 have known weaknesses.",
      "examTip": "Always use WPA3 if your devices and access point support it. Avoid WEP entirely."
    },
    {
      "id": 42,
      "question": "Which of the following is a function of an Intrusion Detection System (IDS)?",
      "options": [
        "To automatically assign IP addresses.",
        "To prevent all network attacks.",
        "To monitor network traffic for suspicious activity and generate alerts.",
        "To encrypt network traffic."
      ],
      "correctAnswerIndex": 2,
      "explanation": "An IDS passively monitors network traffic and alerts administrators to potential security breaches or policy violations. While some IDSes can take limited preventative action, their primary function is detection and alerting. Firewalls offer more robust prevention. DHCP assigns IPs, and encryption is a separate process.",
      "examTip": "Think of an IDS as a security alarm system for your network."
    },
    {
      "id": 43,
      "question": "What is a common use for a toner probe?",
      "options": [
        "To test the speed of a network connection.",
        "To identify and trace wires or cables within a bundle or wall.",
        "To measure the strength of a wireless signal.",
        "To crimp connectors onto network cables."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A toner probe consists of a tone generator (which sends a signal down the cable) and a probe (which detects the signal), allowing you to trace cables, even when they are hidden within walls or bundles.",
      "examTip": "Toner probes are essential tools for cable management and troubleshooting."
    },
    {
      "id": 44,
      "question": "What does 'PoE' stand for?",
      "options": [
        "Power over Ethernet",
        "Port over Ethernet",
        "Protocol over Ethernet",
        "Packet over Ethernet"
      ],
      "correctAnswerIndex": 0,
      "explanation": "PoE (Power over Ethernet) technology allows network cables to carry electrical power, simplifying the deployment of devices like IP phones, wireless access points, and security cameras.",
      "examTip": "PoE eliminates the need for separate power outlets for network devices."
    },
    {
      "id": 45,
      "question": "Which command is used to display a network interface's MAC address on a Windows system?",
      "options": [
        "ipconfig /release",
        "ipconfig /all",
        "ipconfig /renew",
        "arp -a"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`ipconfig /all` displays detailed configuration information for all network adapters, including the physical address (MAC address). `ipconfig /release` and `/renew` manage DHCP leases, and `arp -a` shows the ARP cache.",
      "examTip": "`ipconfig /all` is your go-to command for finding a device's MAC address on Windows."
    },
    {
      "id": 46,
      "question": "What is the primary difference between TCP and UDP?",
      "options": [
        "TCP is faster than UDP.",
        "TCP is connection-oriented and provides reliable data transfer, while UDP is connectionless and does not guarantee delivery.",
        "UDP is used for web browsing, while TCP is used for file transfer.",
        "TCP is used for wireless networks, while UDP is used for wired networks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "TCP (Transmission Control Protocol) establishes a connection, provides error checking, and guarantees delivery and order of data packets. UDP (User Datagram Protocol) is faster but does not guarantee delivery or order, making it suitable for applications where some data loss is acceptable (like streaming video).",
      "examTip": "TCP is reliable but has more overhead; UDP is faster but less reliable."
    },
    {
      "id": 47,
      "question": "What is a key difference between a router and a switch?",
      "options": [
        "A router connects devices within the same network; a switch connects different networks.",
        "A router connects different networks; a switch connects devices within the same network.",
        "A router is used for wireless networks; a switch is used for wired networks.",
        "A router assigns IP addresses; a switch assigns MAC addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Routers operate at Layer 3 (Network) and forward traffic between different networks based on IP addresses. Switches operate primarily at Layer 2 (Data Link) and forward traffic within the same network based on MAC addresses.",
      "examTip": "Routers connect networks; switches connect devices within a network."
    },
    {
      "id": 48,
      "question": "What is the purpose of a firewall?",
      "options": [
        "To speed up your internet connection.",
        "To control network traffic and block unauthorized access to or from a private network.",
        "To assign IP addresses to devices.",
        "To translate domain names into IP addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A firewall acts as a security guard for your network, examining incoming and outgoing traffic and blocking or allowing it based on predefined security rules. This helps prevent unauthorized access and protect against malware.",
      "examTip": "Firewalls are a fundamental component of network security."
    },
    {
      "id": 49,
      "question": "Which of the following is a benefit of using network documentation?",
      "options": [
        "Keeping all network information in your head.",
        "Regularly updating network diagrams and documentation to reflect changes.",
        "Using only physical network diagrams, not logical diagrams.",
        "Sharing network passwords with everyone."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Accurate and up-to-date network documentation (including diagrams, IP address assignments, configurations, and procedures) is crucial for troubleshooting, planning, and security. Information should be stored securely, not just memorized, and both physical and logical diagrams are important. Passwords should be strictly controlled.",
      "examTip": "Good network documentation is an investment that saves time and trouble in the long run."
    },
    {
      "id": 50,
      "question": "What type of network attack involves an attacker inserting themselves between two communicating parties to intercept or modify data?",
      "options": [
        "Denial-of-service (DoS) attack",
        "Man-in-the-middle (MitM) attack",
        "Phishing attack",
        "Brute-force attack"
      ],
      "correctAnswerIndex": 1,
      "explanation": "In a man-in-the-middle (MitM) attack, the attacker secretly intercepts and potentially alters communication between two parties who believe they are directly communicating with each other. DoS attacks flood a target, phishing uses deception, and brute-force attacks try to guess passwords.",
      "examTip": "MitM attacks can be mitigated with strong encryption and secure protocols."
    },
    {
      "id": 51,
      "question": "Which of the following is an example of a logical network diagram?",
      "options": [
        "A diagram showing the physical layout of network cables.",
        "A diagram showing IP addresses, subnets, and routing protocols.",
        "A photograph of a network rack.",
        "A list of network hardware serial numbers."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A logical network diagram shows the network's logical structure, including IP addressing, subnets, VLANs, routing protocols, and other logical elements. Physical diagrams show cabling, rack diagrams show equipment in racks, and serial numbers are part of asset inventory.",
      "examTip": "Logical diagrams help understand how data flows through the network, regardless of the physical layout."
    },
    {
      "id": 52,
      "question": "Which of the following is a benefit of using cloud computing services?",
      "options": [
        "You have complete control over the physical hardware.",
        "You can easily scale resources up or down as needed.",
        "It eliminates all security risks.",
        "It guarantees 100% uptime."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Cloud services offer scalability (easily adjust resources), flexibility, and often cost savings compared to managing your own infrastructure. You don't have control over the physical hardware, security is a shared responsibility, and 100% uptime is rarely guaranteed.",
      "examTip": "Cloud computing provides agility and scalability for businesses."
    },
    {
      "id": 53,
      "question": "What is a 'broadcast storm'?",
      "options": [
        "A period of heavy rainfall.",
        "A situation where excessive broadcast traffic floods a network, degrading performance and potentially causing a network outage.",
        "A type of network attack.",
        "A misconfigured DHCP server."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A broadcast storm occurs when a network is overwhelmed by broadcast traffic, often caused by network loops or malfunctioning devices. This can consume all available bandwidth and bring the network to a standstill. It's an effect, not a specific attack type.",
      "examTip": "Broadcast storms are often caused by network loops; Spanning Tree Protocol (STP) helps prevent them."
    },
    {
      "id": 54,
      "question": "Which technology allows multiple VLANs to be transmitted over a single physical link?",
      "options": [
        "STP (Spanning Tree Protocol)",
        "VTP (VLAN Trunking Protocol)",
        "802.1Q trunking",
        "Link Aggregation"
      ],
      "correctAnswerIndex": 2,
      "explanation": "802.1Q trunking (often just called 'trunking') adds tags to Ethernet frames to identify the VLAN they belong to, allowing multiple VLANs to share a single physical link between switches. STP prevents loops, VTP manages VLAN databases (not the transmission itself), and link aggregation combines multiple physical links into one logical link.",
      "examTip": "Remember that 802.1Q is the standard for VLAN tagging on trunk links."
    },
    {
      "id": 55,
      "question": "What is the purpose of the Address Resolution Protocol (ARP)?",
      "options": [
        "To resolve domain names to IP addresses.",
        "To dynamically assign IP addresses.",
        "To map IP addresses to MAC addresses on a local network.",
        "To encrypt network communication."
      ],
      "correctAnswerIndex": 2,
      "explanation": "ARP is used on local networks (specifically, Ethernet networks) to find the MAC address associated with a known IP address. This allows devices to communicate at the data link layer. DNS resolves domain names, DHCP assigns IPs, and various protocols handle encryption.",
      "examTip": "ARP is essential for communication within a local Ethernet network."
    },
    {
      "id": 56,
      "question": "Which of the following is a characteristic of a full-duplex Ethernet connection?",
      "options": [
        "It can only transmit data in one direction at a time.",
        "It can transmit and receive data simultaneously.",
        "It is limited to a maximum speed of 10 Mbps.",
        "It is more susceptible to collisions."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Full-duplex allows devices to send and receive data at the same time, eliminating collisions and improving network efficiency. Half-duplex allows communication in only one direction at a time.",
      "examTip": "Modern switched networks almost always use full-duplex connections."
    },
    {
      "id": 57,
      "question": "What is the purpose of the `nslookup` command?",
      "options": [
        "To display the routing table.",
        "To query DNS servers for information about domain names and IP addresses.",
        "To test network connectivity to a remote host.",
        "To configure a network interface."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`nslookup` is a command-line tool used to troubleshoot DNS resolution problems. It allows you to query DNS servers to find the IP address associated with a domain name, or vice versa. `route print` displays routing tables, `ping` tests connectivity, and `ipconfig` configures interfaces.",
      "examTip": "Use `nslookup` to verify that DNS resolution is working correctly."
    },
    {
      "id": 58,
      "question": "What does it mean if a device has an APIPA address?",
      "options": [
        "It has a static IP address.",
        "It has successfully obtained an IP address from a DHCP server.",
        "It failed to obtain an IP address from a DHCP server and has self-assigned an address in the 169.254.x.x range.",
        "It is connected to the internet."
      ],
      "correctAnswerIndex": 2,
      "explanation": "APIPA (Automatic Private IP Addressing) allows devices to self-configure an IP address in the 169.254.x.x range when a DHCP server is unavailable. This provides limited local network communication but not internet access.",
      "examTip": "An APIPA address usually indicates a DHCP problem."
    },
    {
      "id": 59,
      "question": "Which of the following is a security best practice for network devices?",
      "options": [
        "Using default usernames and passwords.",
        "Leaving all ports open.",
        "Changing default credentials and disabling unnecessary services.",
        "Sharing administrative passwords with all users."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Always change default usernames and passwords, disable unused services and ports, and restrict administrative access to authorized personnel. These are fundamental security hardening practices.",
      "examTip": "Securing network devices is crucial for protecting the entire network."
    },
    {
      "id": 60,
      "question": "What is 'Quality of Service' (QoS) used for in networking?",
      "options": [
        "To encrypt network traffic.",
        "To prioritize certain types of network traffic over others.",
        "To assign IP addresses to devices automatically.",
        "To filter network traffic based on content."
      ],
      "correctAnswerIndex": 1,
      "explanation": "QoS allows network administrators to prioritize different types of traffic (e.g., voice, video, data) to ensure that critical applications receive the necessary bandwidth and low latency, even during periods of network congestion.",
      "examTip": "QoS is important for real-time applications like VoIP and video conferencing."
    },
    {
      "id": 61,
      "question": "What is a 'virtual machine' (VM)?",
      "options": [
        "A physical computer.",
        "A software-based emulation of a computer system.",
        "A type of network cable.",
        "A program for creating documents."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A virtual machine (VM) is a software implementation of a computer that executes programs like a physical machine. It allows you to run multiple operating systems and applications on a single physical host.",
      "examTip": "Virtualization is a key technology for cloud computing and efficient resource utilization."
    },
    {
      "id": 62,
      "question": "What is the function of a hypervisor?",
      "options": [
        "To connect to the internet.",
        "To create and manage virtual machines.",
        "To encrypt network traffic.",
        "To print documents."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A hypervisor (also called a virtual machine monitor or VMM) is software that creates and runs virtual machines, providing an abstraction layer between the physical hardware and the virtualized operating systems.",
      "examTip": "The hypervisor is the foundation of virtualization."
    },
    {
      "id": 63,
      "question": "What is 'packet sniffing'?",
      "options": [
        "A way to organize files on your computer.",
        "The process of capturing and analyzing network traffic.",
        "A type of computer virus.",
        "A program for creating spreadsheets."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Packet sniffing (or packet analysis) involves capturing data packets traveling across a network and examining their contents. This can be used for troubleshooting, security analysis, or (illegally) for eavesdropping.",
      "examTip": "Packet sniffers can be powerful tools, but they can also be used for malicious purposes."
    },
    {
      "id": 64,
      "question": "Which tool is commonly used for packet sniffing?",
      "options": [
        "Microsoft Word",
        "Wireshark",
        "Adobe Photoshop",
        "AutoCAD"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Wireshark is a popular, open-source packet analyzer used for network troubleshooting, analysis, software and protocol development, and education.",
      "examTip": "Wireshark is a powerful tool for understanding network traffic."
    },
    {
      "id": 65,
      "question": "What is the purpose of network documentation?",
      "options": [
        "To make the network run faster.",
        "To provide a record of network configuration, topology, and other important information.",
        "To replace the need for network security.",
        "To prevent users from accessing the internet."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Good network documentation (including diagrams, IP address assignments, device configurations, and procedures) is essential for troubleshooting, planning, maintenance, and security. It helps network administrators understand the network's structure and how it operates.",
      "examTip": "Keep your network documentation up-to-date to reflect any changes."
    },
    {
      "id": 66,
      "question": "What is the purpose of an access control list (ACL)?",
      "options": [
        "To assign IP addresses to devices.",
        "To control access to network resources by permitting or denying traffic based on rules.",
        "To encrypt network traffic.",
        "To translate domain names to IP addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "ACLs are sets of rules that define which network traffic is allowed or blocked based on criteria like source/destination IP address, port numbers, and protocols. They are commonly used on routers and firewalls to enhance security.",
      "examTip": "ACLs are a fundamental tool for network security and access control."
    },
    {
      "id": 67,
      "question": "What is a 'demilitarized zone' (DMZ) in networking?",
      "options": [
        "A zone where no computers are allowed.",
        "A network segment that sits between a private network and the public internet, hosting publicly accessible servers (like web servers) while providing an extra layer of security for the internal network.",
        "A type of network cable.",
        "A program for creating presentations."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DMZ provides a buffer zone between the trusted internal network and the untrusted external network (internet). It allows external users to access specific services (like web servers) without having direct access to the internal network, improving security.",
      "examTip": "A DMZ is used to protect internal networks while still allowing access to public-facing servers."
    },
    {
      "id": 68,
      "question": "What is the function of Network Address Translation (NAT)?",
      "options": [
        "To encrypt network traffic.",
        "To translate private IP addresses used within a local network to a public IP address used on the internet (and vice versa).",
        "To assign IP addresses dynamically.",
        "To filter network traffic based on content."
      ],
      "correctAnswerIndex": 1,
      "explanation": "NAT allows multiple devices on a private network to share a single public IP address, conserving public IPv4 addresses and providing a layer of security by hiding the internal network structure from the outside world.",
      "examTip": "NAT is essential for connecting private networks to the internet."
    },
    {
      "id": 69,
      "question": "Which of the following is a benefit of using a star topology?",
      "options": [
        "It requires less cabling than a bus topology.",
        "If one cable fails, the entire network goes down.",
        "It's easy to troubleshoot and isolate cable problems because each device has a dedicated connection to a central point.",
        "It provides the highest level of redundancy."
      ],
      "correctAnswerIndex": 2,
      "explanation": "In a star topology, each device connects to a central hub or (more commonly) a switch. This makes it easy to add or remove devices and to isolate problems to a specific cable or device. It uses more cabling than a bus, a single cable failure only affects one device, and mesh offers higher redundancy.",
      "examTip": "The star topology's centralized design simplifies management and troubleshooting."
    },
    {
      "id": 70,
      "question": "Which layer of the OSI model is responsible for routing data packets between networks?",
      "options": [
        "Layer 1 - Physical",
        "Layer 2 - Data Link",
        "Layer 3 - Network",
        "Layer 4 - Transport"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The Network layer (Layer 3) handles logical addressing (like IP addresses) and routing, determining the best path for data to travel between different networks. Layer 1 is the physical cabling, Layer 2 handles MAC addresses within a single network, and Layer 4 manages reliable data transfer.",
      "examTip": "Remember that routers operate at Layer 3 (the Network layer)."
    },
    {
      "id": 71,
      "question": "What is 'port forwarding'?",
      "options": [
        "A way to block all incoming network traffic.",
        "A technique used to allow external devices to access services on a private network by mapping an external port to an internal IP address and port.",
        "A way to encrypt network traffic.",
        "A way to assign IP addresses dynamically."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Port forwarding allows you to make a service running on a device on your private network (like a game server or web server) accessible from the internet. It directs incoming traffic on a specific external port to the correct internal IP address and port.",
      "examTip": "Port forwarding is often used for hosting game servers or web servers from home networks."
    },
    {
      "id": 72,
      "question": "Which protocol is used for secure file transfer?",
      "options": [
        "HTTP",
        "FTP",
        "SFTP",
        "SMTP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "SFTP (Secure File Transfer Protocol) provides secure file transfer by encrypting both the commands and the data being transferred. FTP is not secure, as it transmits data in plain text. HTTP is for web browsing, and SMTP is for email.",
      "examTip": "Always use SFTP (or FTPS) for secure file transfers; avoid using plain FTP."
    },
    {
      "id": 73,
      "question": "What is 'jitter' in network performance?",
      "options": [
        "The total time it takes for a packet to travel from source to destination.",
        "The variation in delay (latency) between data packets.",
        "The amount of data lost during transmission.",
        "The maximum bandwidth of a network connection."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Jitter is the inconsistency in latency over time. It's particularly important for real-time applications like VoIP and video conferencing, where uneven delays can cause choppy audio or video.",
      "examTip": "High jitter can negatively impact the quality of real-time communication."
    },
    {
      "id": 74,
      "question": "Which of the following is a valid MAC address?",
      "options": [
        "192.168.1.1",
        "00:1A:2B:3C:4D:5E",
        "google.com",
        "256.1.1.1"
      ],
      "correctAnswerIndex": 1,
      "explanation": "00:1A:2B:3C:4D:5E is a valid MAC address format. MAC addresses are 48-bit hexadecimal numbers, typically written in six groups of two hexadecimal digits separated by colons or hyphens. 192.168.1.1 is an IPv4 address, google.com is a domain name, and 256.1.1.1 is an invalid IP address.",
      "examTip": "Learn to recognize the format of MAC addresses (hexadecimal, colons or hyphens)."
    },
    {
      "id": 75,
      "question": "What is a common use for a network-attached storage (NAS) device?",
      "options": [
        "To provide wireless internet access.",
        "To store and share files across a network.",
        "To connect to the internet directly.",
        "To print documents wirelessly."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A NAS device is a specialized file storage server that provides centralized access to files for multiple users and devices on a network. It's not a wireless access point, a modem, or a printer.",
      "examTip": "NAS devices are commonly used for home and small business file sharing."
    },
    {
      "id": 76,
      "question": "What is a 'subnet'?",
      "options": [
        "A smaller network within a larger network, created by dividing an IP address range.",
        "A type of network cable.",
        "A device that connects to the internet.",
        "A program for creating web pages."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Subnetting is the process of dividing a network into smaller, logical subnetworks. This improves network performance, security, and manageability.",
      "examTip": "Subnets help organize and manage IP addresses efficiently."
    },
    {
      "id": 77,
      "question": "Which of the following is a characteristic of a peer-to-peer network?",
      "options": [
        "A central server manages all resources.",
        "Each computer has equal responsibility and can share resources directly with others.",
        "It's more secure than a client-server network.",
        "It's better suited for large organizations."
      ],
      "correctAnswerIndex": 1,
      "explanation": "In a peer-to-peer network, there's no central server. Each computer acts as both a client (requesting resources) and a server (providing resources). This is simpler to set up but less manageable and less secure for larger networks than client-server.",
      "examTip": "Peer-to-peer networks are common in small home networks."
    },
    {
      "id": 78,
      "question": "What does it mean to 'troubleshoot' a network problem?",
      "options": [
        "To create network problems.",
        "To ignore network problems.",
        "To systematically identify the cause of a problem and find a solution.",
        "To make network problems worse."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Troubleshooting involves a logical process of gathering information, identifying symptoms, testing hypotheses, and implementing solutions to resolve network issues.",
      "examTip": "Always follow a systematic approach when troubleshooting."
    },
    {
      "id": 79,
      "question": "Which of the following is an example of network documentation?",
      "options": [
        "A list of your favorite websites.",
        "A diagram showing the network topology, IP address assignments, and device configurations.",
        "A collection of your personal photos.",
        "A list of your computer passwords (which you should never write down!)."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Network documentation provides a comprehensive record of the network's design, implementation, and configuration. This is essential for troubleshooting, planning, and maintaining the network.",
      "examTip": "Network diagrams are essential tools for network administrators."
    },
    {
      "id": 80,
      "question": "Which type of network cable is MOST resistant to electromagnetic interference (EMI)?",
      "options": [
        "UTP (Unshielded Twisted Pair)",
        "STP (Shielded Twisted Pair)",
        "Coaxial cable",
        "Fiber optic cable"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Fiber optic cable uses light signals instead of electrical signals, making it completely immune to EMI. STP offers some protection, UTP offers minimal protection, and coaxial offers moderate protection, but all are susceptible to EMI to varying degrees.",
      "examTip": "Fiber optic cable is the best choice for environments with high levels of EMI."
    },
    {
      "id": 81,
      "question": "Which layer of the OSI model handles data representation, encryption, and decryption?",
      "options": [
        "Layer 7 - Application",
        "Layer 6 - Presentation",
        "Layer 5 - Session",
        "Layer 4 - Transport"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The Presentation layer (Layer 6) is responsible for ensuring that data is presented in a format that both communicating applications can understand. This includes data conversion, encryption, and compression. Layer 7 provides application services, Layer 5 manages sessions, and Layer 4 handles reliable transport.",
      "examTip": "Remember the Presentation layer for data formatting and encryption."
    },
    {
      "id": 82,
      "question": "What is a 'private IP address'?",
      "options": [
        "An IP address that is publicly accessible on the internet.",
        "An IP address that is used within a private network and is not routable on the public internet.",
        "An IP address that is assigned dynamically by a DHCP server.",
        "An IP address that is used for secure communication."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Private IP addresses (like those in the 192.168.x.x, 10.x.x.x, and 172.16.x.x - 172.31.x.x ranges) are used within private networks (homes, offices) and are not directly accessible from the internet. NAT is used to translate these private addresses to a public IP address for internet communication.",
      "examTip": "Private IP addresses are used within local networks and are not visible on the public internet."
    },
    {
      "id": 83,
      "question": "What is the purpose of a firewall?",
      "options": [
        "To speed up your internet connection.",
        "To control network traffic and block unauthorized access to or from a private network.",
        "To assign IP addresses to devices.",
        "To translate domain names into IP addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A firewall acts as a security guard for your network, examining incoming and outgoing traffic and blocking or allowing it based on predefined security rules. This helps prevent unauthorized access and protect against malware.",
      "examTip": "Firewalls are a fundamental component of network security."
    },
    {
      "id": 84,
      "question": "Which of the following is a benefit of network segmentation?",
      "options": [
        "It simplifies network management.",
        "It improves security by isolating network traffic and limiting the impact of security breaches.",
        "It increases the size of the broadcast domain.",
        "It reduces the need for firewalls."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Network segmentation (often achieved using VLANs) divides a network into smaller, isolated segments. This improves security by containing breaches and reducing congestion by limiting broadcast traffic. While it can increase initial management complexity, it simplifies overall security management.",
      "examTip": "Segmentation is a crucial security best practice, especially for isolating sensitive systems."
    },
    {
      "id": 85,
      "question": "What is 'dynamic IP addressing'?",
      "options": [
        "Manually assigning IP addresses to each device on a network.",
        "Automatically assigning IP addresses to devices using a DHCP server.",
        "Using the same IP address for all devices on a network.",
        "Using public IP addresses on a private network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Dynamic IP addressing uses a DHCP server to automatically assign IP addresses, subnet masks, default gateways, and other network configuration parameters to devices. This simplifies network administration and prevents IP address conflicts.",
      "examTip": "DHCP is the standard way to assign IP addresses in most networks."
    },
    {
      "id": 86,
      "question": "What is a common symptom of a duplex mismatch between two network devices?",
      "options": [
        "No network connectivity at all.",
        "Slow network performance and increased collisions.",
        "Inability to obtain an IP address.",
        "Frequent disconnections from wireless networks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A duplex mismatch occurs when two connected devices are configured for different duplex settings (half-duplex or full-duplex). This causes collisions and significantly degrades network performance.",
      "examTip": "Always ensure that both ends of a network connection have matching speed and duplex settings."
    },
    {
      "id": 87,
      "question": "What is the purpose of the `arp -a` command?",
      "options": [
        "To display the routing table.",
        "To display the ARP cache, which maps IP addresses to MAC addresses.",
        "To display detailed network interface configuration.",
        "To test network connectivity."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `arp -a` command (on Windows and many other systems) shows the Address Resolution Protocol (ARP) cache. The ARP cache is a table that stores mappings between IP addresses and MAC addresses on the local network. `route print` displays routing, `ipconfig /all` shows interface configuration, and `ping` tests connectivity.",
      "examTip": "The ARP cache is essential for local network communication."
    },
    {
      "id": 88,
      "question": "What is a 'rogue DHCP server'?",
      "options": [
        "A DHCP server that is properly configured.",
        "An unauthorized DHCP server on a network that can cause IP address conflicts and network disruptions.",
        "A DHCP server that is used for testing purposes.",
        "A DHCP server that is located on a different subnet."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A rogue DHCP server is an unauthorized server that is providing incorrect or conflicting IP address information to devices on the network. This can cause network connectivity problems and security vulnerabilities.",
      "examTip": "Use DHCP snooping on switches to prevent rogue DHCP servers from operating on your network."
    },
    {
      "id": 89,
      "question": "Which of the following describes a zero-trust security model?",
      "options": [
        "Trusting all users and devices within the network perimeter.",
        "Assuming that no user or device, whether inside or outside the network, can be trusted by default, and verifying every access request.",
        "Relying solely on firewalls for network security.",
        "Using only strong passwords for authentication."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Zero trust is a security framework that assumes no implicit trust, regardless of whether a user or device is inside or outside the traditional network perimeter. Every access request must be verified based on identity, context, and device posture.",
      "examTip": "Zero trust is a modern security approach that emphasizes 'never trust, always verify'."
    },
    {
      "id": 90,
      "question": "What is 'infrastructure as code' (IaC)?",
      "options": [
        "A type of network cable.",
        "Managing and provisioning infrastructure (networks, virtual machines, etc.) through code instead of manual processes.",
        "A program for creating documents.",
        "A type of computer virus."
      ],
      "correctAnswerIndex": 1,
      "explanation": "IaC allows you to define your infrastructure (networks, servers, configurations) in code, which can be version-controlled, automated, and easily replicated. This improves consistency, reduces errors, and speeds up deployments.",
      "examTip": "IaC is a key practice for DevOps and cloud computing."
    },
    {
      "id": 91,
      "question": "What does 'SSID' stand for in wireless networking?",
      "options": [
        "Secure System Identifier",
        "Service Set Identifier",
        "System Security ID",
        "Simple Service ID"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SSID (Service Set Identifier) is the name of a wireless network (Wi-Fi). It's what you see when you search for available Wi-Fi networks.",
      "examTip": "The SSID is the name of your Wi-Fi network."
    },
    {
      "id": 92,
      "question": "Which of the following is a characteristic of a client-server network?",
      "options": [
        "All computers have equal roles and responsibilities.",
        "Resources and security are typically managed centrally by one or more servers.",
        "It is easier to set up than a peer-to-peer network.",
        "It is less expensive than a peer-to-peer network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "In a client-server network, dedicated servers provide resources (like files, printers, email) and manage security, while clients request those resources. This is more scalable and manageable than peer-to-peer, especially for larger organizations.",
      "examTip": "Client-server networks are common in business environments for their centralized control."
    },
    {
      "id": 93,
      "question": "What is a key difference between a router and a switch?",
      "options": [
        "A router connects devices within the same network; a switch connects different networks.",
        "A router connects different networks; a switch connects devices within the same network.",
        "A router is used for wireless networks; a switch is used for wired networks.",
        "A router assigns IP addresses; a switch assigns MAC addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Routers operate at Layer 3 (Network) and forward traffic between different networks based on IP addresses. Switches operate primarily at Layer 2 (Data Link) and forward traffic within the same network based on MAC addresses.",
      "examTip": "Routers connect networks; switches connect devices within a network."
    },
    {
      "id": 94,
      "question": "What is 'throughput' in networking?",
      "options": [
        "The theoretical maximum data transfer rate of a network connection.",
        "The actual amount of data successfully transmitted over a network connection in a given period.",
        "The total amount of data that can be stored on a network.",
        "The number of devices connected to a network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Throughput is the actual data transfer rate achieved in real-world conditions, considering factors like overhead, latency, and errors. Bandwidth is the theoretical maximum. Storage capacity and number of devices are different concepts.",
      "examTip": "Throughput is a measure of real-world network performance."
    },
    {
      "id": 95,
      "question": "What is a common security measure used to protect against unauthorized access to a network?",
      "options": [
        "Using a weak password.",
        "Leaving all ports open.",
        "Implementing a firewall and using strong authentication methods.",
        "Sharing your password with colleagues."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A combination of a firewall (to control network traffic) and strong authentication (like strong passwords and multi-factor authentication) is crucial for network security. Weak passwords, open ports, and sharing credentials are all security risks.",
      "examTip": "Network security requires a multi-layered approach."
    },
    {
      "id": 96,
      "question": "What is the function of the Domain Name System (DNS)?",
      "options": [
        "To assign IP addresses automatically.",
        "To translate domain names into IP addresses.",
        "To encrypt network traffic.",
        "To connect to the internet."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The Domain Name System (DNS) is like the internet's phone book, translating human-friendly domain names into the numerical IP addresses that computers use to communicate. DHCP assigns IP addresses, encryption is handled by other protocols, and modems/routers connect to the internet.",
      "examTip": "DNS makes it easier to navigate the internet by using names instead of numbers."
    },
    {
      "id": 97,
      "question": "What is a 'gateway' in networking terms?",
      "options": [
        "A device that connects to the internet.",
        "A device that acts as an entry/exit point for network traffic going to or from another network.",
        "A type of network cable.",
        "A program for creating web pages."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The gateway (usually a router) is the device that forwards traffic from your local network to other networks, including the internet. While a modem connects to the ISP, the gateway handles the routing between networks.",
      "examTip": "The default gateway is usually the IP address of your router's internal interface."
    },
    {
      "id": 98,
      "question": "What information can you typically find in a network diagram?",
      "options": [
        "A list of your favorite websites.",
        "The physical and/or logical layout of network devices, connections, and IP addressing.",
        "A collection of your personal photos.",
        "Your computer's password (which should never be written down!)."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Network diagrams provide a visual representation of the network's structure, helping with troubleshooting, planning, and understanding the network's design. They show how devices are connected, their IP addresses, and other relevant information.",
      "examTip": "Network diagrams are essential tools for network administrators."
    },
    {
      "id": 99,
      "question": "Which of the following is a good practice for securing a wireless network?",
      "options": [
        "Using an open network (no password).",
        "Using WEP encryption.",
        "Using WPA2 or WPA3 encryption with a strong, unique password.",
        "Using the default SSID and password."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Always use the strongest available encryption (WPA3 if supported, otherwise WPA2) and a complex, unique password to protect your Wi-Fi network from unauthorized access. WEP is outdated and easily cracked. Default settings are a major security risk.",
      "examTip": "Secure your Wi-Fi with strong encryption and a strong password."
    },
    {
      "id": 100,
      "question": "Which of the following is a type of network attack?",
      "options": [
        "Sending a friendly email.",
        "Phishing, where someone tries to trick you into revealing personal information.",
        "Updating your computer's software.",
        "Backing up your files."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Phishing attacks use deceptive emails, websites, or messages to trick users into giving away sensitive information (like passwords, credit card numbers, or personal details). Sending a friendly email, updating software, and backing up files are all good practices.",
      "examTip": "Be suspicious of unsolicited emails or messages asking for personal information."
    }
  ]
});
