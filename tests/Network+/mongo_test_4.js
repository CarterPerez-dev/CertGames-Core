db.tests.insertOne({
  "category": "nplus",
  "testId": 4,
  "testName": "Network+ Practice Test #4 (Moderate)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "You are troubleshooting a connectivity issue where a workstation cannot access network resources.  The workstation has an IP address of 169.254.33.12. What is the MOST likely cause?",
      "options": [
        "The workstation has a static IP address configured incorrectly.",
        "The workstation has failed to obtain an IP address from a DHCP server.",
        "The workstation's network cable is unplugged.",
        "The default gateway is configured incorrectly."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An IP address in the 169.254.x.x range indicates an APIPA (Automatic Private IP Addressing) address. This means the workstation failed to receive an IP address from a DHCP server and self-assigned an address. While a bad cable *could* cause this, the APIPA address is the *most direct* indicator of DHCP failure. A static IP would *not* be in this range, and a bad gateway would allow *local* communication but not *external*.",
      "examTip": "Recognize APIPA addresses (169.254.x.x) as a sign of DHCP failure."
    },
    {
      "id": 2,
      "question": "A user reports slow internet speeds.  You suspect a DNS issue. Which command-line tool is BEST suited to test DNS resolution?",
      "options": [
        "ping",
        "tracert",
        "nslookup",
        "ipconfig /all"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`nslookup` is specifically designed to query DNS servers and resolve domain names to IP addresses (and vice versa). `ping` tests basic connectivity, `tracert` shows the route, and `ipconfig /all` displays network configuration but doesn't directly *test* DNS resolution in the same way.",
      "examTip": "Use `nslookup` to verify that domain names are resolving correctly."
    },
    {
      "id": 3,
      "question": "You need to connect two buildings located 1 kilometer apart. Which cabling type is MOST appropriate?",
      "options": [
        "UTP Cat 6",
        "STP Cat 6a",
        "Multimode Fiber",
        "Single-mode Fiber"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Single-mode fiber is designed for long-distance, high-bandwidth communication, making it suitable for distances of 1 kilometer and beyond. UTP and STP are limited to 100 meters. Multimode fiber is typically used for shorter distances (up to a few hundred meters).",
      "examTip": "Consider distance limitations and bandwidth requirements when choosing network cabling."
    },
    {
      "id": 4,
      "question": "What is the primary purpose of implementing VLANs on a switched network?",
      "options": [
        "To increase the overall network bandwidth.",
        "To logically segment the network into separate broadcast domains, improving security and performance.",
        "To provide wireless access to network resources.",
        "To encrypt network traffic between devices."
      ],
      "correctAnswerIndex": 1,
      "explanation": "VLANs logically divide a physical network into multiple, isolated broadcast domains. This enhances security by limiting the scope of broadcast traffic and containing potential security breaches. It doesn't directly *increase* bandwidth (though it can *improve* performance by reducing congestion), provide *wireless* access, or *encrypt* traffic.",
      "examTip": "VLANs are a fundamental tool for network segmentation and security."
    },
    {
      "id": 5,
      "question": "You are configuring a new wireless network and need to choose a security protocol.  Which protocol provides the STRONGEST security?",
      "options": [
        "WEP",
        "WPA",
        "WPA2",
        "WPA3"
      ],
      "correctAnswerIndex": 3,
      "explanation": "WPA3 is the latest and most secure wireless security protocol, offering improved encryption and protection against various attacks. WEP is extremely outdated and vulnerable, WPA has known weaknesses, and WPA2 is still relatively secure but superseded by WPA3.",
      "examTip": "Always use WPA3 if your devices and access point support it."
    },
    {
      "id": 6,
      "question": "A user reports they cannot access a shared network drive. Other users on the same subnet can access the drive. What is the FIRST thing you should check?",
      "options":[
        "The network cable on the user's computer.",
        "The file server's configuration.",
        "The network switch configuration.",
        "The user's DNS settings."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Since other users on the *same* subnet can access the drive, the problem is likely *local* to the user's computer.  The *first* step is to check the physical connection (the network cable).  If that's not the issue, then you can investigate software configurations.",
      "examTip": "When troubleshooting, start with the physical layer and work your way up the OSI model."
    },
     {
      "id": 7,
       "question": "What is a potential consequence of a misconfigured subnet mask?",
        "options":[
            "Increased network bandwidth.",
            "Improved network security.",
            "Devices on the same physical network may not be able to communicate with each other.",
            "Faster internet speeds."
        ],
        "correctAnswerIndex": 2,
        "explanation":"An incorrect subnet mask can cause devices that should be on the same logical network to be treated as if they are on different networks, preventing communication. It does *not* increase bandwidth, improve security, or increase internet speeds.",
        "examTip":"Ensure that all devices on the same subnet use the same subnet mask."
    },
        {
        "id": 8,
         "question": "Which of the following is a characteristic of a full-duplex Ethernet connection compared to a half-duplex connection?",
        "options":[
            "It is more susceptible to collisions.",
            "It can only transmit data in one direction at a time.",
            "It allows simultaneous transmission and reception of data, reducing collisions and improving performance.",
            "It is limited to a maximum speed of 10 Mbps."
        ],
        "correctAnswerIndex": 2,
        "explanation":"Full-duplex allows bidirectional communication without collisions, significantly improving network efficiency compared to half-duplex, which can only transmit or receive at a time and is prone to collisions. Speed is a separate characteristic (e.g., 10/100/1000 Mbps).",
        "examTip":"Modern switched networks almost always use full-duplex connections."
    },
     {
        "id": 9,
        "question": "You are designing a network for a small office. You need to ensure high availability for critical servers.  Which technology is MOST appropriate?",
        "options": [
            "DHCP reservations",
            "A single, powerful server",
            "Redundant servers with failover capabilities",
            "A strong firewall"
        ],
        "correctAnswerIndex": 2,
        "explanation": "High availability is achieved through redundancy.  Using multiple servers configured for failover (where one server automatically takes over if another fails) ensures minimal downtime. DHCP reservations ensure consistent IP addresses, a single server is a single point of failure, and a firewall provides security, not *availability*.",
        "examTip": "Redundancy is key to achieving high availability."
    },
     {
        "id": 10,
        "question": "What is the function of the Spanning Tree Protocol (STP) on a switched network?",
        "options":[
          "To encrypt network traffic.",
          "To prevent network loops by blocking redundant paths.",
          "To assign IP addresses dynamically.",
          "To translate domain names to IP addresses."
        ],
        "correctAnswerIndex": 1,
        "explanation": "STP detects and prevents network loops in switched networks with redundant links. Loops can cause broadcast storms, which can cripple a network. STP blocks redundant paths, ensuring a single, loop-free path between any two devices. It doesn't encrypt, assign IPs, or translate domain names.",
        "examTip": "STP is crucial for maintaining a stable switched network with redundant links."
    },
    {
      "id": 11,
      "question": "You are setting up a server that needs to be accessible from the internet.  Which technology allows you to map a public IP address and port to a private IP address and port on your internal network?",
      "options": [
        "VLANs",
        "DHCP",
        "Port Forwarding",
        "DNS"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Port forwarding (often configured on a router) allows external devices to access a specific service running on a device within your private network. VLANs segment networks, DHCP assigns IP addresses, and DNS translates domain names.",
      "examTip": "Port forwarding is commonly used to make game servers, web servers, or other services accessible from the internet."
    },
    {
      "id": 12,
      "question": "Which of the following is a key difference between TCP and UDP?",
      "options":[
        "TCP is connectionless and unreliable; UDP is connection-oriented and reliable.",
        "TCP is connection-oriented and provides reliable, ordered delivery; UDP is connectionless and does not guarantee delivery or order.",
        "TCP is used only for web browsing; UDP is used only for file transfer.",
        "TCP is used only for wired networks; UDP is used only for wireless networks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "TCP establishes a connection, provides error checking, and ensures that data packets are delivered in the correct order. UDP is faster but doesn't guarantee delivery or order, making it suitable for applications where some data loss is acceptable (like streaming video or online gaming). Both can be used for various applications on both wired and wireless networks.",
      "examTip": "Choose TCP for reliability (e.g., web browsing, email); choose UDP for speed when some data loss is tolerable (e.g., streaming)."
    },
        {
       "id": 13,
        "question": "What is the primary benefit of using a standardized network protocol like TCP/IP?",
        "options":[
            "It guarantees complete network security.",
            "It allows devices from different manufacturers to communicate with each other.",
            "It makes network configuration easier.",
            "It eliminates the need for network administrators."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Standardized protocols like TCP/IP provide a common language for network devices, enabling interoperability between different vendors' equipment. They don't *guarantee* security (security requires additional measures), simplify *all* configuration, or eliminate the need for administrators.",
        "examTip":"Standardized protocols are essential for interoperability in networking."
    },
    {
      "id": 14,
      "question": "A user reports they can access websites by IP address but not by domain name. What is the MOST likely cause?",
      "options": [
        "A faulty network cable.",
        "A problem with the user's web browser.",
        "A DNS resolution issue.",
        "The user's IP address is blocked."
      ],
      "correctAnswerIndex": 2,
      "explanation": "If you can reach a website by its IP address but not its domain name, the problem is almost certainly with DNS resolution (the process of translating domain names to IP addresses). A faulty cable would prevent *all* access, a browser issue would likely affect *all* websites, and an IP block wouldn't prevent *pinging* the IP.",
      "examTip": "Troubleshoot DNS issues using tools like `nslookup` or `dig`."
    },
    {
        "id": 15,
        "question": "Which command is used to view the ARP cache on a Windows system?",
        "options":[
          "ipconfig /all",
          "arp -a",
          "netstat -r",
          "route print"
        ],
        "correctAnswerIndex": 1,
        "explanation":"The `arp -a` command displays the Address Resolution Protocol (ARP) cache, which contains mappings between IP addresses and MAC addresses on the local network.  `ipconfig /all` shows interface details, `netstat -r` and `route print` show routing information.",
        "examTip":"The ARP cache is essential for local network communication; incorrect entries can cause connectivity problems."
      },
        {
        "id": 16,
        "question":"What is the purpose of a 'DMZ' in a network?",
        "options":[
            "To provide a secure zone for internal servers.",
            "To host publicly accessible servers (like web servers) while providing a buffer zone between the internet and the internal network.",
            "To create a separate network for wireless devices.",
            "To act as a backup power source for network devices."
        ],
        "correctAnswerIndex": 1,
        "explanation":"A DMZ (demilitarized zone) is a network segment that sits between the internal network and the internet. It allows external users to access specific services (like web servers) without having direct access to the internal network, improving security.",
        "examTip":"Think of a DMZ as a 'semi-trusted' zone for publicly accessible resources."
      },
      {
       "id": 17,
        "question":"You are troubleshooting a network where users are experiencing slow file transfers.  You suspect a duplex mismatch.  How would you verify this?",
        "options":[
          "Ping the file server.",
          "Check the network cable for damage.",
          "Examine the interface configurations on the connected devices (e.g., switch and server) to ensure they are both set to the same duplex mode (either auto-negotiate or both set to full-duplex).",
           "Run a virus scan on the file server."
        ],
        "correctAnswerIndex": 2,
        "explanation":"A duplex mismatch occurs when two connected devices are configured for different duplex settings (half-duplex or full-duplex). This causes collisions and performance degradation. You need to check the *configuration* of the devices, not just ping or look at the cable (though a bad cable *could* cause negotiation issues).",
        "examTip":"Always ensure that connected network interfaces have matching speed and duplex settings."
      },
       {
        "id": 18,
        "question": "What is the purpose of using subnets?",
        "options":[
          "To increase the total number of available IP addresses.",
          "To divide a network into smaller, more manageable logical segments, improving security and performance.",
          "To encrypt network traffic.",
          "To filter network traffic based on content."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Subnetting divides a larger network into smaller logical networks. This improves security by isolating traffic, improves performance by reducing broadcast domains, and makes network management easier. It doesn't *increase* the *total* address space, encrypt traffic, or filter content (those are separate functions).",
        "examTip": "Subnetting is fundamental to IP addressing and network design."
      },
       {
        "id": 19,
         "question": "What is a potential security risk of using an outdated network protocol like WEP for wireless security?",
        "options":[
           "It provides strong encryption and is highly secure.",
           "It is vulnerable to various attacks and can be easily cracked, allowing unauthorized access to the network.",
           "It is only compatible with modern devices.",
           "It increases network speed."
        ],
        "correctAnswerIndex": 1,
        "explanation": "WEP (Wired Equivalent Privacy) is an outdated and extremely weak wireless security protocol. It has known vulnerabilities and can be easily cracked using readily available tools. WPA2 or, preferably, WPA3 should be used instead.",
        "examTip": "Never use WEP for wireless security; it offers virtually no protection."
       },
        {
         "id": 20,
         "question": "Which of the following is a characteristic of a mesh network topology?",
         "options":[
            "All devices are connected to a central hub or switch.",
           "Devices are connected in a circular loop.",
           "Each device has multiple paths to other devices, providing high redundancy and fault tolerance.",
            "All devices are connected to a single cable."
         ],
         "correctAnswerIndex": 2,
         "explanation": "Mesh networks offer excellent redundancy because each node has multiple connections to other nodes. If one link fails, there are alternative paths for data to travel.  This makes them highly resilient but also more complex to implement and manage.",
         "examTip": "Mesh networks are highly reliable but can be more complex to configure and maintain."
      },
       {
         "id": 21,
         "question": "What is 'MAC address filtering' used for on a network?",
        "options":[
           "To assign IP addresses dynamically.",
           "To encrypt network traffic.",
            "To restrict network access based on the physical MAC addresses of devices.",
            "To translate domain names to IP addresses."
        ],
        "correctAnswerIndex": 2,
        "explanation": "MAC address filtering allows you to create a list of allowed (or blocked) MAC addresses, controlling which devices can connect to a network (typically a wireless network, but also possible on some switches). While it can *enhance* security, it's not foolproof, as MAC addresses can be spoofed. It doesn't assign IPs, encrypt traffic, or translate domain names.",
        "examTip": "MAC address filtering can provide an additional layer of security, but it shouldn't be the *only* security measure."
      },
      {
         "id": 22,
          "question": "What is the function of a network interface card (NIC)?",
          "options":[
             "To provide wireless internet access (only).",
              "To connect a computer or device to a network (either wired or wireless).",
              "To route traffic between different networks.",
              "To assign IP addresses dynamically."
          ],
          "correctAnswerIndex": 1,
          "explanation": "A NIC provides the physical interface for a device to connect to a network.  It can be *either* wired (Ethernet) *or* wireless (Wi-Fi).  It doesn't *route* traffic (routers do that) or *assign* IP addresses (DHCP servers do that).",
          "examTip": "Every device connected to a network needs a NIC."
      },
      {
        "id": 23,
        "question":"You are troubleshooting a network connectivity problem.  You can ping the loopback address (127.0.0.1) successfully, but you cannot ping the default gateway.  What does this indicate?",
        "options":[
            "The problem is with the remote server.",
            "The problem is likely with the local network configuration or physical connection between the computer and the network.",
            "The problem is with the DNS server.",
            "The problem is with the computer's operating system."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Successfully pinging the loopback address (127.0.0.1) confirms that the TCP/IP stack on the *local* machine is functioning.  The inability to ping the default gateway suggests a problem with the *local* network connection (e.g., cable, NIC, switch port) or configuration (e.g., incorrect IP address, subnet mask, or default gateway).",
        "examTip":"The loopback address is a useful tool for testing the local TCP/IP stack."
      },
      {
        "id": 24,
        "question":"What is a 'broadcast domain'?",
        "options":[
          "The area covered by a wireless access point.",
          "The set of all devices that receive broadcast frames originating from any device within that set.",
          "The range of IP addresses assigned by a DHCP server.",
          "The physical cabling infrastructure of a network."
        ],
        "correctAnswerIndex": 1,
        "explanation":"A broadcast domain is a logical division of a network where all nodes can reach each other by broadcast at the data link layer (Layer 2). Switches, by default, forward broadcasts to all ports within the same VLAN. Routers separate broadcast domains.",
        "examTip":"VLANs are used to segment broadcast domains and improve network performance and security."
      },
       {
        "id": 25,
          "question": "Which of the following is a benefit of using a client-server network model over a peer-to-peer model?",
          "options":[
             "Easier to set up and manage for very small networks.",
              "Centralized management of resources, security, and user accounts.",
              "All computers have equal roles and responsibilities.",
              "Lower initial cost."
          ],
          "correctAnswerIndex": 1,
          "explanation": "Client-server networks offer centralized administration, making it easier to manage users, security policies, and resources, especially in larger organizations. While peer-to-peer might be *simpler* for *very small* networks, client-server scales better. Initial costs may be *higher*, but long-term management is often more efficient.",
          "examTip": "Client-server networks are preferred for their scalability, security, and manageability."
      },
    {
    "id":26,
    "question": "Which type of network device is primarily responsible for preventing unauthorized access to a private network from the internet?",
    "options":[
    "Switch",
    "Router",
    "Firewall",
    "Hub"
    ],
    "correctAnswerIndex": 2,
    "explanation": "A firewall's primary purpose is to act as a security barrier between a trusted network (like your home or office network) and an untrusted network (like the internet). It examines incoming and outgoing traffic and blocks or allows it based on predefined rules.",
    "examTip": "Firewalls are a crucial first line of defense for network security."

    },
    {
        "id": 27,
        "question": "What is the purpose of using a strong and unique password for each of your online accounts?",
        "options": [
           "To make it easier to remember all your passwords.",
            "To reduce the risk of a single compromised password affecting multiple accounts.",
            "To allow friends and family to access your accounts easily.",
            "To comply with website requirements."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Using unique passwords for each account prevents a 'domino effect' where a breach of one account compromises others. While compliance is a factor, the *primary* reason is security.",
        "examTip": "Use a password manager to help you create and manage strong, unique passwords."
    },
    {
      "id": 28,
      "question": "What is the purpose of a 'virtual private network' (VPN)?",
      "options": [
       "To speed up your internet connection.",
        "To create a secure, encrypted connection over a public network (like the internet), protecting your data and privacy.",
        "To block access to certain websites.",
        "To prevent viruses from infecting your computer."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A VPN encrypts your internet traffic and routes it through a secure server, masking your IP address and protecting your data from eavesdropping, especially on public Wi-Fi.  While it *can* sometimes bypass geo-restrictions, that's not its *primary* function. It doesn't *guarantee* virus protection.",
      "examTip": "Use a VPN to enhance your online privacy and security, especially on untrusted networks."
    },
    {
        "id": 29,
        "question": "Which of the following is an example of multi-factor authentication (MFA)?",
        "options": [
           "Using a very long password.",
            "Entering a password and then a code sent to your mobile phone.",
            "Using the same password for multiple accounts.",
            "Using your fingerprint to unlock your computer."
        ],
        "correctAnswerIndex": 1, //Best answer, as it describes TWO factors.
        "explanation": "MFA requires you to provide two or more *different* forms of verification to prove your identity.  This typically involves something you *know* (password), something you *have* (phone), and/or something you *are* (fingerprint). While a fingerprint *is* a factor, the question asks for an example of *multi*-factor.",
        "examTip": "Enable MFA whenever possible for enhanced security."
    },
     {
       "id": 30,
        "question": "What is the purpose of a 'cable tester'?",
        "options":[
           "To measure the speed of a network connection.",
           "To identify and trace wires or cables.",
           "To test the physical integrity of network cables, checking for continuity, shorts, and miswires.",
           "To capture and analyze network traffic."
        ],
        "correctAnswerIndex": 2,
        "explanation": "A cable tester verifies that a network cable is properly wired and functioning correctly. It checks for continuity (a complete connection), shorts (wires touching where they shouldn't), and miswires (wires connected in the wrong order). It's *not* for measuring speed (speed testers do that), tracing cables (toner probes do that), or analyzing traffic (packet sniffers do that).",
        "examTip": "A cable tester is an essential tool for troubleshooting physical layer network problems."
    },
    {
      "id": 31,
      "question": "Which of the following statements best describes 'network segmentation'?",
      "options": [
       "Physically separating network cables.",
        "Dividing a network into smaller, isolated subnetworks to improve security and performance.",
        "Connecting multiple networks together.",
        "Encrypting all network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Network segmentation involves logically dividing a network into smaller, isolated segments (often using VLANs or subnets). This limits the impact of security breaches, reduces network congestion, and improves overall performance. It's not just about *physical* separation, connecting networks (that's routing), or encryption.",
      "examTip": "Segmentation is a key security best practice."
    },
    {
     "id": 32,
     "question": "What is the primary function of a proxy server?",
     "options":[
       "To assign IP addresses to devices on a network.",
       "To act as an intermediary between clients and other servers, providing various services like caching, filtering, and security.",
       "To translate domain names into IP addresses",
       "To encrypt network traffic."
     ],
     "correctAnswerIndex": 1,
     "explanation": "A proxy server acts as a gateway between users and the internet (or other networks). It can improve performance by caching frequently accessed content, enhance security by filtering traffic and masking client IP addresses, and control access to specific websites or content.",
     "examTip": "Proxy servers provide an additional layer of security and control for network traffic."
    },
    {
      "id":33,
      "question": "What type of network attack involves an attacker attempting to guess passwords by systematically trying many different combinations?",
      "options": [
        "Man-in-the-middle (MitM) attack",
        "Denial-of-service (DoS) attack",
        "Brute-force attack",
        "Phishing attack"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A brute-force attack involves trying many possible passwords (often using automated tools) until the correct one is found. MitM intercepts communication, DoS floods a target, and phishing uses deception.",
      "examTip": "Strong, unique passwords are the best defense against brute-force attacks."
    },
     {
       "id": 34,
       "question": "What is 'social engineering' in the context of cybersecurity?",
       "options":[
          "Building a social media platform.",
          "Manipulating people into divulging confidential information or performing actions that compromise security.",
           "Using social media to promote a product.",
           "Networking with colleagues at a conference (in the traditional sense)."
       ],
       "correctAnswerIndex": 1,
       "explanation": "Social engineering attacks exploit human psychology rather than technical vulnerabilities. They often involve impersonation, deception, and persuasion to trick users into revealing sensitive information or granting access.",
       "examTip": "Be skeptical of unsolicited requests for information and be aware of common social engineering tactics."
    },
    {
        "id": 35,
        "question": "Which of the following is a benefit of using a DHCP server in a network?",
        "options": [
           "It encrypts all network traffic.",
           "It automatically assigns IP addresses and other network configuration parameters to devices, simplifying network administration and preventing IP address conflicts.",
           "It translates domain names into IP addresses.",
           "It provides secure remote access to a network."
        ],
        "correctAnswerIndex": 1,
        "explanation": "DHCP (Dynamic Host Configuration Protocol) automates the process of IP address assignment, making it much easier to manage devices on a network and preventing manual configuration errors.  It *doesn't* encrypt traffic, translate domain names (that's DNS), or provide remote access (that's VPN).",
        "examTip": "DHCP is essential for managing IP addresses in most networks."
    },
     {
      "id": 36,
      "question":"What is the purpose of the 'tracert' or 'traceroute' command?",
      "options":[
        "To test the speed of a network connection.",
        "To display the IP address of a website.",
        "To trace the route that packets take to reach a destination host, showing each hop (router) along the way.",
        "To configure a network interface."
      ],
      "correctAnswerIndex": 2,
      "explanation": "`tracert` (Windows) or `traceroute` (Linux/macOS) is a diagnostic tool that helps identify network routing problems by showing the path and delay at each hop along the way to a destination. It's *not* primarily for speed testing, displaying website IPs (that's `nslookup`), or configuring network interfaces.",
      "examTip":"Use `tracert`/`traceroute` to diagnose network latency or routing issues."
    },
     {
       "id": 37,
       "question": "What is a potential consequence of not regularly updating your computer's software and operating system?",
       "options":[
        "Increased computer speed.",
         "Improved security.",
          "Vulnerability to security exploits and malware.",
          "Automatic data backups."
       ],
       "correctAnswerIndex": 2,
       "explanation": "Software updates often include security patches that fix vulnerabilities that could be exploited by attackers.  Failing to update leaves your system exposed to known threats. It *doesn't* increase speed (though performance improvements *can* happen), improve security (if you *don't* update), or automatically back up data.",
       "examTip": "Enable automatic updates whenever possible to keep your system secure."
    },
     {
         "id": 38,
         "question":"What is a 'virtual LAN' (VLAN)?",
         "options":[
            "A network that uses only virtual machines.",
            "A logical grouping of network devices that are on the same broadcast domain, regardless of their physical location.",
            "A type of network cable.",
            "A program for creating virtual reality environments."
         ],
         "correctAnswerIndex": 1,
         "explanation":"VLANs allow you to segment a physical network into multiple, isolated logical networks. This improves security, performance, and manageability by controlling broadcast traffic and limiting the impact of security breaches. They are *not* limited to virtual machines, a type of cable, or VR software.",
         "examTip":"VLANs are a fundamental tool for network segmentation in switched networks."
    },
      {
        "id": 39,
        "question": "What is 'packet fragmentation'?",
        "options":[
          "The process of encrypting data packets.",
           "The process of dividing a data packet into smaller fragments for transmission over a network.",
           "The process of combining multiple data packets into one larger packet.",
           "The process of filtering network traffic."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Packet fragmentation occurs when a data packet is larger than the maximum transmission unit (MTU) of a network link. The packet is divided into smaller fragments that can be transmitted and then reassembled at the destination. It's *not* encryption, combining packets, or filtering.",
        "examTip": "Excessive fragmentation can negatively impact network performance."
      },
       {
        "id": 40,
        "question":"What is the role of an authoritative DNS server in the Domain Name System?",
        "options":[
          "To cache DNS records from other servers.",
          "To hold the master copy of DNS records for a specific domain and respond to queries about that domain.",
          "To forward DNS requests to other servers.",
          "To provide DNS services to home users."
        ],
        "correctAnswerIndex": 1,
        "explanation":"An authoritative DNS server is the ultimate source of information for a particular domain's DNS records. It holds the master copy of the records and responds to queries from other DNS servers (recursive resolvers) that are trying to resolve domain names for clients. Caching servers store copies temporarily, and forwarding servers relay requests.",
        "examTip":"Authoritative DNS servers are the foundation of the DNS hierarchy."
      },
      {
        "id": 41,
        "question": "Which of the following is a method for securing remote access to a network?",
        "options":[
           "Using Telnet.",
            "Using a VPN (Virtual Private Network) with strong encryption.",
            "Using FTP.",
            "Using HTTP."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A VPN creates a secure, encrypted tunnel over a public network (like the internet), allowing remote users to access private network resources as if they were directly connected. Telnet, FTP, and HTTP are *not* secure for remote access as they transmit data in plain text.",
        "examTip": "Always use a VPN for secure remote access to a private network."
      },
      {
        "id": 42,
         "question": "What is a 'honeypot' in cybersecurity?",
          "options":[
            "A secure server that stores sensitive data.",
             "A decoy system designed to attract and trap attackers, providing insights into their methods and potentially diverting them from real targets.",
             "A type of firewall.",
             "A tool for encrypting network traffic."
          ],
          "correctAnswerIndex": 1,
          "explanation": "A honeypot is a security mechanism that creates a trap for attackers. It mimics a legitimate system or network resource to lure attackers, allowing security professionals to study their techniques and gather information about threats. It's *not* a secure server, a firewall, or an encryption tool.",
          "examTip": "Honeypots are used for threat research and deception."
      },
      
