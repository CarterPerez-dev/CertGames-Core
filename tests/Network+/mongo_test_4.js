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
            {
        "id": 43,
        "question": "What is the purpose of using a standardized cabling system (e.g., structured cabling) in a building or campus network?",
        "options": [
          "To make the network look more aesthetically pleasing.",
          "To provide a consistent and organized infrastructure for network connectivity, simplifying troubleshooting, maintenance, and upgrades.",
          "To increase network speed.",
          "To eliminate the need for network documentation."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Structured cabling provides a standardized, organized approach to network cabling, making it easier to manage, troubleshoot, and expand the network. While aesthetics *can* be a byproduct, the *primary* purpose is organization and maintainability. It doesn't directly *increase* speed or *eliminate* documentation.",
        "examTip": "Structured cabling is essential for large and complex networks."
      },
      {
        "id": 44,
        "question": "Which of the following is a characteristic of cloud computing?",
        "options": [
           "All computing resources are located on-premises.",
           "On-demand access to shared computing resources (servers, storage, applications) over the internet.",
           "Requires significant upfront investment in hardware.",
           "Limited scalability."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Cloud computing provides access to computing resources over the internet, offering scalability, flexibility, and often cost savings compared to traditional on-premises infrastructure. Resources are *not* all on-premises, upfront investment is *reduced*, and scalability is a *key* benefit.",
        "examTip": "Cloud computing offers various advantages, including cost savings, scalability, and agility."
      },
      {
        "id": 45,
        "question": "What is 'two-factor authentication' (2FA)?",
        "options":[
          "Using two different passwords for the same account.",
          "An extra layer of security that requires two different methods to verify your identity (e.g., password and a code sent to your phone).",
          "Using a very long password.",
           "Using the same password for two different accounts."
        ],
        "correctAnswerIndex": 1,
        "explanation": "2FA adds an extra step to the login process, making it significantly harder for unauthorized users to access your accounts, even if they know your password. It typically involves something you *know* (password), something you *have* (phone), and/or something you *are* (biometric).",
        "examTip": "Enable 2FA whenever possible for important accounts."
      },
    {
        "id": 46,
        "question": "What is a benefit of using a dedicated file server in a network?",
        "options": [
            "All computers on the network have equal access to all files.",
            "Centralized storage and management of files, providing better security, backup, and access control.",
            "It's less expensive than using peer-to-peer file sharing.",
            "It eliminates the need for user accounts."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A dedicated file server provides a central location for storing and managing files, making it easier to control access, back up data, and ensure data consistency. While peer-to-peer *can* be cheaper for *very small* networks, a file server offers better scalability and manageability. It doesn't eliminate user accounts – it *relies* on them for access control.",
        "examTip": "File servers are essential for centralized file management in business networks."
    },
    {
      "id": 47,
       "question":"You are troubleshooting a network connectivity problem. You can ping the local loopback address (127.0.0.1) and other devices on your local subnet, but you cannot ping the default gateway or any devices outside your subnet.  What is the MOST likely cause?",
        "options":[
          "A problem with the DNS server.",
          "A problem with the DHCP server.",
          "An incorrect default gateway configuration on your computer, or a problem with the router acting as the default gateway.",
          "A virus infection on your computer."
        ],
        "correctAnswerIndex": 2,
        "explanation":"The ability to ping local devices but *not* the default gateway (or anything beyond it) strongly suggests a problem with the default gateway configuration on your computer or an issue with the router itself. DNS is for name resolution, DHCP is for IP assignment, and a virus is less likely (though possible) to cause *this specific* symptom.",
        "examTip":"Check the default gateway configuration when you can communicate locally but not with external networks."
    },
    {
      "id": 48,
      "question": "What is the purpose of a 'cable tester'?",
      "options": [
       "To measure the speed of a network connection.",
        "To identify and trace wires or cables within a bundle or wall.",
        "To test the physical integrity of network cables, checking for continuity, shorts, and miswires.",
        "To capture and analyze network traffic."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A cable tester verifies that a network cable is properly wired and functioning correctly. It detects common cabling problems like opens (breaks in the wire), shorts (wires touching where they shouldn't), and miswires (wires connected in the wrong order).  Speed testers measure speed, toner probes trace cables, and packet sniffers analyze traffic.",
      "examTip": "A cable tester is an essential tool for diagnosing physical layer network problems."
    },
    {
       "id": 49,
        "question": "Which of the following is a characteristic of a 'peer-to-peer' network?",
        "options":[
            "A central server manages all resources and security.",
            "Each computer can act as both a client (requesting resources) and a server (providing resources), sharing files and printers directly with other computers.",
            "It is more secure than a client-server network.",
            "It is better suited for large organizations with many users."
        ],
        "correctAnswerIndex": 1,
        "explanation":"In a peer-to-peer network, there is no central authority.  Each computer shares resources directly with others. This is simpler to set up but less manageable and less secure for larger networks compared to client-server.",
        "examTip":"Peer-to-peer networks are common in small home or office environments."
    },
    {
       "id": 50,
       "question":"What is the difference between 'bandwidth' and 'throughput'?",
       "options":[
        "Bandwidth is the actual data transfer rate; throughput is the theoretical maximum.",
        "Bandwidth is the theoretical maximum data transfer rate; throughput is the actual data transfer rate achieved in real-world conditions.",
        "Bandwidth is measured in bits per second; throughput is measured in bytes per second.",
        "Bandwidth is used for wired networks; throughput is used for wireless networks."
       ],
       "correctAnswerIndex": 1,
       "explanation":"Bandwidth represents the *potential* capacity of a network connection, while throughput represents the *actual* amount of data successfully transferred over a period, taking into account factors like overhead, latency, errors, and congestion.  Both are typically measured in bits per second (or multiples like Mbps, Gbps).",
       "examTip":"Think of bandwidth as the 'pipe size' and throughput as the 'water flow' through that pipe."
    },
    {
        "id": 51,
        "question":"What is the purpose of 'port scanning'?",
        "options":[
          "To test the physical integrity of network cables.",
            "To identify open ports and services running on a network host.",
            "To encrypt network traffic.",
            "To assign IP addresses dynamically."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Port scanning involves probing a network host to determine which ports are open and listening for connections. This can be used by network administrators for security auditing or by attackers to identify potential vulnerabilities. It's *not* about cable testing, encryption, or IP assignment.",
        "examTip":"Port scanning can be a legitimate security assessment tool or a precursor to an attack."
    },
    {
      "id": 52,
      "question": "Which of the following is a common use for a 'virtual private network' (VPN)?",
      "options":[
        "To speed up your internet connection.",
        "To securely connect to a private network (like your office network) over a public network (like the internet).",
        "To block all incoming network traffic.",
        "To prevent viruses from infecting your computer."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A VPN creates an encrypted tunnel for your internet traffic, protecting your data and privacy, especially when using public Wi-Fi. It allows remote users to access resources on a private network as if they were directly connected. While it *can* sometimes bypass geo-restrictions, that's not its *main* purpose. And it's *not* a firewall or antivirus.",
      "examTip": "Use a VPN for secure remote access and to protect your privacy on untrusted networks."
    },
      {
        "id": 53,
        "question": "Which type of network device operates primarily at Layer 3 (the Network layer) of the OSI model?",
        "options": [
          "Hub",
          "Switch",
          "Router",
          "Bridge"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Routers make forwarding decisions based on IP addresses (Layer 3 addresses), connecting different networks together. Hubs are Layer 1 devices, switches are *primarily* Layer 2 (though some have Layer 3 capabilities), and bridges are Layer 2.",
        "examTip": "Remember that routers are the key devices for inter-network communication."
      },
       {
        "id": 54,
         "question": "What is 'network latency'?",
        "options":[
           "The amount of data that can be transmitted over a network connection.",
            "The time delay in data transmission across a network.",
            "The number of devices connected to a network.",
            "The physical distance between two network devices."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Latency is the time it takes for a data packet to travel from its source to its destination. High latency can cause slow response times and negatively impact real-time applications. Bandwidth is capacity, device count is network size, and distance is just physical separation.",
        "examTip": "Low latency is crucial for good network performance, especially for interactive applications."
    },
    {
        "id": 55,
        "question": "Which of the following is a benefit of using a standardized network protocol like TCP/IP?",
        "options": [
          "It guarantees complete network security.",
          "It allows devices from different manufacturers to communicate with each other.",
          "It makes network configuration easier.",
          "It eliminates the need for network administrators."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Standardized protocols provide a common language for network devices, enabling interoperability between equipment from different vendors. They don't *guarantee* security (that requires additional measures), simplify *all* configuration, or eliminate administrators.",
        "examTip": "TCP/IP is the foundation of the internet and most modern networks."
      },
     {
       "id": 56,
        "question": "Which of the following is a characteristic of a 'stateful firewall'?",
        "options":[
          "It blocks all incoming traffic by default.",
          "It examines each packet individually, without considering the context of a connection.",
          "It tracks the state of network connections (e.g., TCP sessions) and makes filtering decisions based on both the packet header and the connection state.",
          "It only filters traffic based on MAC addresses."
        ],
        "correctAnswerIndex": 2,
        "explanation": "A stateful firewall keeps track of active network connections and uses this information to make more intelligent filtering decisions. It can allow return traffic for established connections, providing better security than a simple packet filter that examines each packet in isolation. Blocking all incoming traffic is a default-deny approach, and MAC address filtering is a Layer 2 function.",
        "examTip": "Stateful firewalls provide more robust security than stateless packet filters."
    },
      {
         "id": 57,
          "question": "What is the purpose of an 'intrusion prevention system' (IPS)?",
          "options":[
             "To assign IP addresses to devices dynamically.",
             "To monitor network traffic for malicious activity and take action to block or prevent it.",
             "To encrypt network traffic.",
             "To translate domain names to IP addresses."
          ],
          "correctAnswerIndex": 1,
          "explanation": "An IPS goes beyond the detection capabilities of an IDS (Intrusion Detection System) by actively blocking or preventing malicious traffic. It can drop packets, reset connections, or even quarantine infected systems.  It's *not* about IP assignment, encryption, or DNS.",
          "examTip":"Think of an IPS as a security guard that can actively stop threats, while an IDS is like a security camera that only observes and records."
      },
        {
       "id": 58,
        "question": "Which of the following is a good practice for creating strong passwords?",
        "options":[
           "Using your name or birthday.",
            "Using a short, common word.",
            "Using a mix of uppercase and lowercase letters, numbers, and symbols, and making it at least 12 characters long.",
            "Using the same password for all your accounts."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Strong passwords are long, complex, and unique, making them difficult to guess or crack using brute-force methods.  Avoid personal information, common words, and reusing passwords.",
        "examTip": "Use a password manager to help you generate and manage strong, unique passwords."
      },
      {
         "id": 59,
        "question":"What is a common use for a 'toner and probe' in network troubleshooting?",
        "options":[
           "To measure the speed of a network connection.",
            "To test the physical integrity of network cables.",
            "To identify and trace specific wires or cables within a bundle, wall, or ceiling.",
            "To capture and analyze network traffic."
        ],
        "correctAnswerIndex": 2,
        "explanation":"A toner and probe (also called a tone generator and probe) is used to locate and identify cables. The toner generates a signal on one end of the cable, and the probe detects that signal at the other end, even if the cable is hidden or part of a larger bundle. It's *not* for speed testing, cable integrity testing, or traffic analysis.",
        "examTip":"Toner probes are essential tools for cable management and tracing."
      },
      {
       "id": 60,
        "question":"What is 'Power over Ethernet' (PoE)?",
        "options":[
          "A type of network cable.",
          "A technology that allows network cables to carry electrical power along with data.",
          "A protocol for encrypting network traffic.",
          "A method for assigning IP addresses dynamically."
        ],
        "correctAnswerIndex": 1,
        "explanation":"PoE simplifies device deployment by providing both power and data over a single Ethernet cable. This is particularly useful for devices like IP phones, wireless access points, and security cameras, where running separate power cables might be difficult or expensive.",
        "examTip":"PoE eliminates the need for separate power outlets for many network devices."
      },
       {
        "id": 61,
         "question": "Which command-line tool is used to display detailed network configuration information on a Windows system, including IP address, subnet mask, default gateway, and DNS servers?",
         "options":[
           "ping",
            "tracert",
            "ipconfig /all",
            "nslookup"
         ],
         "correctAnswerIndex": 2,
         "explanation": "`ipconfig /all` provides a comprehensive overview of network adapter settings, including all the information needed to troubleshoot most connectivity issues. `ping` tests connectivity, `tracert` traces routes, and `nslookup` queries DNS.",
         "examTip": "`ipconfig /all` is a fundamental troubleshooting tool on Windows."
      },
      {
         "id": 62,
         "question":"What is 'network address translation' (NAT) primarily used for?",
          "options":[
             "To encrypt network traffic.",
             "To allow multiple devices on a private network to share a single public IP address when communicating with the internet.",
              "To assign IP addresses dynamically.",
              "To filter network traffic based on content."
          ],
          "correctAnswerIndex": 1,
          "explanation":"NAT translates private IP addresses (used within a local network) to a public IP address (used on the internet), conserving public IPv4 addresses and providing a layer of security by hiding the internal network structure. It's *not* encryption, dynamic IP assignment (DHCP), or content filtering.",
          "examTip":"NAT is essential for connecting private networks to the internet."
      },
      {
        "id": 63,
        "question": "What is the purpose of an 'access control list' (ACL) in network security?",
        "options": [
          "To assign IP addresses to devices.",
          "To encrypt network traffic.",
          "To control network access by permitting or denying traffic based on predefined rules (e.g., source/destination IP address, port number).",
          "To translate domain names to IP addresses."
        ],
        "correctAnswerIndex": 2,
        "explanation": "ACLs are sets of rules that define which network traffic is allowed or blocked, providing a fundamental mechanism for controlling access to network resources. They are commonly used on routers and firewalls. They're *not* for IP assignment, encryption, or DNS.",
        "examTip": "ACLs are a key component of network security and access control."
      },
      {
        "id": 64,
        "question": "Which of the following is a potential security risk associated with using default usernames and passwords on network devices?",
        "options": [
          "It makes the network more secure.",
          "It simplifies network administration.",
          "Attackers can easily gain unauthorized access to the device using well-known default credentials.",
          "It improves network performance."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Default usernames and passwords for network devices (routers, switches, access points) are publicly known and easily found online. Failing to change them is a major security vulnerability that allows attackers to easily gain control of the device and potentially the entire network.",
        "examTip": "Always change default usernames and passwords on all network devices."
      },
       {
        "id": 65,
        "question":"What is a 'denial-of-service' (DoS) attack?",
        "options":[
          "An attempt to steal user passwords.",
          "An attempt to overwhelm a network or server with traffic, making it unavailable to legitimate users.",
           "An attempt to trick users into revealing personal information.",
           "An attempt to gain unauthorized access to a computer by guessing passwords."
        ],
        "correctAnswerIndex": 1,
        "explanation":"A DoS attack aims to disrupt a network service by flooding it with excessive traffic, preventing legitimate users from accessing it. Password stealing is credential theft, tricking users is phishing, and password guessing is a brute-force attack.",
        "examTip":"DoS attacks can cause significant downtime and disruption."
      },
      {
        "id":66,
        "question": "What is a 'distributed denial-of-service' (DDoS) attack?",
        "options":[
            "A DoS attack that originates from a single source.",
            "A DoS attack that originates from multiple compromised computers (a botnet) simultaneously.",
            "A type of phishing attack.",
            "A type of brute-force attack."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A DDoS attack is a more powerful and sophisticated form of DoS attack where the attack traffic comes from many different sources, often a botnet (a network of compromised computers controlled by an attacker). This makes it much harder to block the attack.",
        "examTip": "DDoS attacks are a significant threat to online services."
      },
      {
        "id": 67,
         "question": "Which of the following is a characteristic of a 'virtual LAN' (VLAN)?",
         "options":[
          "It requires separate physical switches for each VLAN.",
           "It logically segments a physical network into multiple, isolated broadcast domains, even if devices are connected to the same physical switch.",
           "It increases the size of the broadcast domain.",
           "It is only used in wireless networks."
         ],
         "correctAnswerIndex": 1,
         "explanation": "VLANs allow you to create logically separate networks on the *same* physical switch infrastructure. This improves security, performance (by reducing broadcast traffic), and manageability. They *decrease* broadcast domain size and are *primarily* used in wired networks (though they can be extended to wireless).",
         "examTip": "VLANs are a crucial tool for network segmentation and security."
      },
      {
        "id": 68,
        "question": "What is the function of the Address Resolution Protocol (ARP)?",
        "options":[
           "To translate domain names to IP addresses.",
           "To dynamically assign IP addresses to devices.",
           "To map IP addresses to MAC addresses on a local network, allowing devices to communicate at Layer 2.",
           "To encrypt network traffic."
        ],
        "correctAnswerIndex": 2,
        "explanation": "ARP is used within a local network (specifically, Ethernet networks) to find the MAC address associated with a known IP address. This is essential for devices to send data frames to each other at the data link layer. DNS resolves domain names, DHCP assigns IPs, and various protocols handle encryption.",
        "examTip": "ARP is crucial for communication within a local Ethernet network."
      },
        {
         "id": 69,
          "question": "Which of the following best describes 'Quality of Service' (QoS) in networking?",
          "options":[
            "A measure of how quickly a network cable can be installed.",
            "The ability to prioritize certain types of network traffic over others, ensuring that critical applications (like voice or video) receive adequate bandwidth and low latency.",
             "A type of network cable.",
             "A method for encrypting network traffic."
          ],
          "correctAnswerIndex": 1,
          "explanation": "QoS allows network administrators to manage network resources and ensure that time-sensitive applications receive the necessary performance, even during periods of congestion.  It's *not* about cable installation, cable type, or encryption.",
          "examTip": "QoS is essential for delivering good performance for real-time applications."
      },
       {
        "id": 70,
        "question":"What is 'packet fragmentation'?",
        "options":[
         "The process of encrypting data packets.",
          "The process of dividing a data packet into smaller fragments for transmission over a network when the packet is larger than the MTU.",
          "The process of combining multiple data packets into one larger packet.",
          "The process of filtering network traffic based on content."
        ],
        "correctAnswerIndex": 1,
        "explanation":"When a data packet is too large for a particular network link (exceeds the Maximum Transmission Unit or MTU), it must be fragmented into smaller pieces, transmitted, and then reassembled at the destination.  It's *not* encryption, combining packets, or filtering.",
        "examTip":"Excessive fragmentation can decrease network performance."
      },
       {
          "id": 71,
           "question": "What is the purpose of a 'network mask' (also known as a 'subnet mask')?",
           "options":[
            "To encrypt network traffic.",
            "To identify the network portion and the host portion of an IP address.",
            "To assign IP addresses dynamically.",
            "To filter network traffic based on MAC addresses."
           ],
           "correctAnswerIndex": 1,
           "explanation": "The subnet mask works with the IP address to define which bits represent the network and which bits represent the host. This is essential for routing and determining whether two devices are on the same subnet. It's *not* encryption, dynamic IP assignment (DHCP), or MAC address filtering.",
           "examTip": "Subnet masks are crucial for understanding IP addressing and network segmentation."
      },
       {
         "id": 72,
         "question":"What is the difference between a 'public IP address' and a 'private IP address'?",
         "options":[
          "Public IP addresses are used within private networks; private IP addresses are used on the internet.",
          "Public IP addresses are globally unique and routable on the internet; private IP addresses are used within private networks and are not directly accessible from the internet.",
          "Public IP addresses are assigned dynamically; private IP addresses are assigned statically.",
          "Public IP addresses are more secure than private IP addresses."
         ],
         "correctAnswerIndex": 1,
         "explanation":"Public IP addresses are assigned to devices that connect directly to the internet and are globally unique. Private IP addresses (e.g., 192.168.x.x, 10.x.x.x, 172.16.x.x-172.31.x.x) are used within private networks (homes, offices) and are not directly routable on the internet. NAT translates between private and public addresses. Assignment method (dynamic/static) and security are separate concepts.",
         "examTip":"Private IP addresses are used within local networks and are not visible on the public internet."
      },
      {
       "id": 73,
       "question": "Which of the following is a benefit of using a 'virtual private network' (VPN)?",
       "options":[
         "It guarantees complete anonymity online.",
          "It encrypts your internet traffic and masks your IP address, enhancing your privacy and security, especially on public Wi-Fi.",
         "It speeds up your internet connection.",
         "It prevents all forms of malware."
       ],
       "correctAnswerIndex": 1,
       "explanation": "VPNs create a secure, encrypted tunnel for your internet traffic, protecting it from eavesdropping and enhancing your privacy. While they *mask* your IP address, they don't guarantee *complete* anonymity. They typically *don't* speed up connections (and can sometimes *slow* them down), and they don't offer *complete* malware protection.",
       "examTip": "Use a VPN to protect your data and privacy, especially on public Wi-Fi."
      },
      {
        "id": 74,
         "question": "What is the purpose of the Domain Name System (DNS)?",
        "options":[
          "To assign IP addresses to devices automatically.",
           "To translate human-readable domain names (like google.com) into numerical IP addresses that computers use to communicate.",
           "To encrypt network traffic.",
           "To prevent network loops."
        ],
        "correctAnswerIndex": 1,
        "explanation": "DNS acts like the internet's phone book, converting domain names into IP addresses, making it easier for users to access websites and other online resources. DHCP assigns IPs, encryption uses separate protocols, and STP prevents loops.",
        "examTip": "DNS is essential for navigating the internet using easy-to-remember names."
      },
      {
        "id": 75,
         "question": "Which of the following is a common security measure used to protect against unauthorized access to a wireless network?",
        "options":[
          "Using an open network with no password.",
            "Using WEP encryption.",
            "Using WPA2 or WPA3 encryption with a strong, unique password, and changing the default SSID.",
            "Sharing the network password with everyone."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Strong encryption (WPA2 or WPA3) and a complex, unique password are crucial for securing a Wi-Fi network.  Changing the default SSID adds a small layer of obscurity. Open networks, WEP, and sharing passwords are all *major* security risks.",
        "examTip": "Always secure your Wi-Fi network with strong encryption and a strong password."
      },
       {
      "id": 76,
      "question": "What is the purpose of a 'firewall' in network security?",
      "options":[
        "To speed up your internet connection.",
        "To control network traffic and block unauthorized access to or from a private network, based on predefined security rules.",
        "To assign IP addresses to devices.",
        "To translate domain names into IP addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A firewall acts as a gatekeeper, examining incoming and outgoing network traffic and allowing or blocking it based on configured rules. This helps prevent unauthorized access and protect against malware. It's *not* about speed, IP assignment (DHCP), or DNS.",
      "examTip": "Firewalls are a fundamental component of network security."
    },
    {
      "id": 77,
      "question": "Which command-line tool is commonly used to test network connectivity to a remote host and measure the round-trip time?",
      "options": [
       "tracert",
        "ping",
        "ipconfig",
        "nslookup"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `ping` command sends ICMP Echo Request packets to a target host and listens for Echo Reply packets.  The time it takes for the round trip is a measure of network latency. `tracert` shows the route, `ipconfig` displays local configuration, and `nslookup` queries DNS.",
      "examTip": "`ping` is a basic but essential network troubleshooting tool."
    },
     {
      "id": 78,
       "question":"What is the primary purpose of an 'intrusion detection system' (IDS)?",
       "options":[
        "To assign IP addresses to devices.",
        "To prevent all network attacks.",
        "To monitor network traffic for suspicious activity and generate alerts for security personnel.",
        "To encrypt all network traffic."
       ],
       "correctAnswerIndex": 2,
       "explanation":"An IDS passively monitors network traffic for signs of malicious activity or policy violations. It generates alerts so that security administrators can investigate and take action. While *some* IDSes can take *limited* preventative action, their *main* role is detection and alerting.  Intrusion *Prevention* Systems (IPSs) are more focused on *blocking* threats.",
       "examTip":"Think of an IDS as a security camera system for your network."
    },
    {
      "id": 79,
       "question": "What is the main difference between a 'hub' and a 'switch' in a network?",
       "options":[
        "A hub is faster than a switch.",
         "A hub broadcasts data to all connected devices, while a switch forwards data only to the intended recipient based on MAC address.",
         "A switch is used for wireless networks, while a hub is used for wired networks.",
         "A hub provides better security than a switch."
       ],
       "correctAnswerIndex": 1,
       "explanation": "Hubs are simple repeaters that operate at Layer 1 (Physical) and send all incoming data to every connected device, creating collisions and wasting bandwidth. Switches operate at Layer 2 (Data Link) and learn the MAC addresses of connected devices, forwarding traffic only to the appropriate port, which significantly improves efficiency and reduces collisions. Both are typically used in *wired* networks, though hubs are largely obsolete.",
       "examTip": "Switches are much more efficient and secure than hubs."
    },
    {
        "id": 80,
        "question": "Which of the following best describes 'network documentation'?",
        "options": [
            "A list of your favorite websites.",
            "A comprehensive record of a network's design, implementation, configuration, and operation, including diagrams, IP address assignments, device settings, and procedures.",
            "A collection of software licenses.",
            "A list of user passwords (which should never be written down!)."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Network documentation provides a detailed understanding of the network's structure, how it's configured, and how it operates. This is essential for troubleshooting, planning, maintenance, and security. It's *far* more than just software licenses or (insecurely stored) passwords.",
        "examTip": "Good network documentation is critical for effective network management."
    },
    {
       "id": 81,
       "question": "What is the purpose of 'subnetting' a network?",
       "options":[
        "To increase the total number of available IP addresses.",
        "To divide a network into smaller, more manageable logical subnetworks, improving security, performance, and address allocation efficiency.",
        "To encrypt all network traffic.",
        "To make the network more vulnerable to attacks."
       ],
       "correctAnswerIndex": 1,
       "explanation": "Subnetting divides a larger network into smaller, isolated segments. This reduces broadcast traffic, improves security by limiting the scope of potential breaches, and makes it easier to manage IP address allocation. It doesn't *increase* the *total* number of addresses and is unrelated to encryption.",
       "examTip": "Subnetting is a fundamental concept in IP networking."
    },
      {
        "id": 82,
         "question": "Which of the following is a characteristic of a 'star' network topology?",
        "options":[
           "All devices are connected to a single, central cable.",
            "All devices are connected to a central hub or switch, and if the central device fails, the entire network goes down.",
            "Devices are connected in a circular loop.",
            "Each device has multiple connections to other devices."
        ],
        "correctAnswerIndex": 1, // Clarified: Central Device Failure impact
        "explanation": "In a star topology, each device has a dedicated connection to a central hub or (more commonly) a switch.  This makes it easy to add/remove devices and troubleshoot. *However*, the central device is a *single point of failure* – if it goes down, the entire network connected to it is affected.",
        "examTip": "The star topology is widely used due to its simplicity, but the central device's reliability is crucial."
    },
    {
      "id": 83,
      "question": "What is the purpose of 'MAC address filtering' on a wireless access point?",
      "options": [
        "To assign IP addresses to devices automatically.",
        "To encrypt wireless traffic.",
        "To restrict network access based on the physical MAC addresses of devices, allowing or blocking specific devices.",
        "To translate domain names to IP addresses."
      ],
      "correctAnswerIndex": 2,
      "explanation": "MAC address filtering allows you to create a list of allowed (or blocked) MAC addresses, controlling which wireless devices can connect to your network.  While it can *enhance* security, it's not foolproof (MAC addresses can be spoofed) and is *not* a substitute for strong encryption. It's *not* about IP assignment, encryption, or DNS.",
      "examTip": "MAC address filtering provides an additional layer of security, but it shouldn't be the *only* security measure for a wireless network."
    },
             "correctAnswerIndex": 1,
        "explanation": "The default gateway is the 'exit point' for a device's local network. When a device needs to communicate with a device on a different network (including the internet), it sends the traffic to its default gateway, which is typically the IP address of a router.",
        "examTip": "Without a default gateway configured, a device can only communicate with other devices on the same local subnet."
      },
      {
        "id": 85,
        "question": "Which of the following is a security risk associated with using public Wi-Fi hotspots?",
        "options":[
          "Increased network speed compared to home networks.",
          "Stronger encryption than home networks.",
          "Potential for eavesdropping and data interception due to the often-unsecured nature of public networks.",
          "Automatic access to all network resources."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Public Wi-Fi networks often lack strong security measures (or any security at all), making it easier for attackers to intercept data transmitted over the network. It's crucial to use a VPN when connecting to public Wi-Fi.",
        "examTip": "Always use a VPN when connecting to public Wi-Fi to protect your data."
      },
    {
      "id": 86,
      "question": "What is 'social engineering' in the context of cybersecurity?",
      "options":[
        "Building a social media platform.",
         "Tricking people into revealing confidential information or performing actions that compromise security, often through manipulation and deception.",
        "Using social media for marketing purposes.",
        "Networking with colleagues at a professional conference."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Social engineering attacks exploit human psychology rather than technical vulnerabilities. Attackers may impersonate trusted individuals or organizations, use deceptive tactics, or prey on people's emotions to gain access to systems or information.",
      "examTip": "Be skeptical of unsolicited requests for information and be aware of common social engineering techniques."
    },
     {
        "id": 87,
        "question":"What is 'phishing'?",
        "options":[
            "A type of fishing sport.",
            "A method for organizing files on a computer.",
            "A type of cyberattack where attackers attempt to deceive users into revealing sensitive information (like usernames, passwords, or credit card details) by posing as a trustworthy entity.",
            "A way to speed up your internet connection."
        ],
        "correctAnswerIndex": 2,
        "explanation":"Phishing attacks often involve fraudulent emails, websites, or messages that appear to be from legitimate sources. The goal is to trick the recipient into clicking on malicious links, opening infected attachments, or providing personal information.",
        "examTip":"Be cautious of suspicious emails, websites, and messages, especially those asking for personal information or creating a sense of urgency."
     },
     {
       "id": 88,
        "question": "Which of the following is a good practice for protecting your computer from malware?",
        "options":[
          "Downloading files from untrusted websites.",
            "Installing and regularly updating antivirus and anti-malware software, and being cautious about opening email attachments or clicking on links from unknown sources.",
            "Disabling your computer's firewall.",
            "Using the same password for all your accounts."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Protecting your computer from malware requires a multi-layered approach, including using security software, practicing safe browsing habits, and keeping your software up-to-date. Downloading from untrusted sources, disabling firewalls, and reusing passwords are all *bad* practices.",
        "examTip": "Be proactive about protecting your computer from malware."
    },
    {
      "id": 89,
       "question": "What is the purpose of a 'virtual private network' (VPN)?",
        "options":[
          "To speed up your internet connection.",
           "To create a secure, encrypted connection over a public network (like the internet), allowing you to access private network resources remotely and protect your data from eavesdropping.",
           "To block all incoming network traffic.",
           "To assign IP addresses dynamically."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A VPN encrypts your internet traffic and routes it through a secure server, masking your IP address and protecting your data, especially on public Wi-Fi. It allows remote users to access private networks as if they were directly connected. It's *not* primarily for speeding up connections, blocking all traffic, or assigning IPs.",
        "examTip": "Use a VPN to enhance your online privacy and security."
    },
    {
      "id": 90,
      "question": "Which of the following is an example of 'multi-factor authentication' (MFA)?",
      "options": [
        "Using a very long and complex password.",
        "Entering a password and then entering a code sent to your mobile phone via SMS or generated by an authenticator app.",
        "Using the same password for multiple accounts.",
        "Using your fingerprint to unlock your computer."
      ],
      "correctAnswerIndex": 1, // Best answer - two DISTINCT factors
      "explanation": "MFA requires two or more *different* forms of verification: something you *know* (password), something you *have* (phone), and/or something you *are* (biometric). While a *fingerprint* is *one* factor, the question asks for *multi*-factor. Using the same password is a security *risk*. A long password is good, but not MFA.",
      "examTip": "Enable MFA whenever possible to significantly enhance account security."
    },
     {
        "id": 91,
        "question": "What is the purpose of an 'intrusion prevention system' (IPS)?",
        "options": [
          "To assign IP addresses to devices on a network.",
          "To monitor network traffic for suspicious activity and take proactive steps to block or prevent malicious traffic.",
          "To encrypt network traffic.",
          "To translate domain names to IP addresses."
        ],
        "correctAnswerIndex": 1,
        "explanation": "An IPS goes beyond the *detection* capabilities of an IDS (Intrusion Detection System) by actively *blocking* or *preventing* malicious traffic.  It can drop packets, reset connections, or quarantine infected systems. It's not for IP assignment (DHCP), encryption, or DNS.",
        "examTip": "An IPS is a proactive security measure that can stop attacks before they cause damage."
    },
    {
        "id": 92,
        "question": "What is a 'denial-of-service' (DoS) attack?",
        "options":[
         "An attempt to steal user passwords.",
          "An attempt to overwhelm a network or server with traffic from a single source, making it unavailable to legitimate users.",
          "An attempt to trick users into revealing personal information.",
          "An attempt to gain unauthorized access to a computer system by guessing passwords."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A DoS attack aims to disrupt a network service by flooding it with traffic *from a single source*, making it unavailable. Password stealing is credential theft, tricking users is phishing, and password guessing is a brute-force attack. *Distributed* DoS (DDoS) attacks use *multiple* sources.",
        "examTip": "DoS attacks can cause significant downtime and disruption."
      },
       {
        "id": 93,
        "question":"What is a 'distributed denial-of-service' (DDoS) attack?",
        "options":[
            "A DoS attack that originates from a single computer.",
            "A DoS attack that originates from multiple compromised computers (often a botnet) simultaneously, making it much harder to block.",
            "A type of phishing attack.",
            "A type of brute-force attack."
        ],
        "correctAnswerIndex": 1,
        "explanation":"A DDoS attack is a more powerful and sophisticated form of DoS attack where the attack traffic comes from many different sources, often a botnet (a network of compromised computers controlled by an attacker). This makes it difficult to mitigate the attack by simply blocking a single source IP address.",
        "examTip":"DDoS attacks are a major threat to online services and require specialized mitigation techniques."
    },
     {
       "id": 94,
       "question": "Which type of network device is responsible for forwarding data packets between different networks based on their IP addresses?",
        "options":[
          "Hub",
          "Switch",
          "Router",
          "Repeater"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Routers operate at Layer 3 (Network) of the OSI model and make forwarding decisions based on IP addresses. They connect different networks together and determine the best path for data to travel. Hubs and repeaters are Layer 1, and switches are *primarily* Layer 2.",
        "examTip": "Routers are the key devices for connecting networks and routing traffic across the internet."
     },
      {
      "id": 95,
       "question":"What is a 'MAC address'?",
       "options":[
        "A logical address assigned by a DHCP server.",
         "A unique physical address assigned to a network interface card (NIC) by the manufacturer.",
         "An address used for routing data between networks.",
         "A type of network cable."
       ],
       "correctAnswerIndex": 1,
       "explanation":"A MAC address (Media Access Control address) is a unique hardware identifier burned into a network interface card (NIC). It's used for communication within a local network segment (Layer 2). IP addresses are logical and used for routing (Layer 3).",
       "examTip":"MAC addresses are like a device's hardware fingerprint on the local network."
    },
      {
       "id": 96,
       "question": "What is 'network segmentation' primarily used for?",
       "options":[
        "To increase the overall network bandwidth.",
        "To improve network security and performance by dividing a network into smaller, isolated subnetworks.",
         "To simplify network cabling.",
         "To encrypt all network traffic."
       ],
       "correctAnswerIndex": 1,
       "explanation": "Network segmentation (often using VLANs or subnets) limits the scope of broadcast traffic, reduces congestion, and contains security breaches, improving both security and performance. It's *not* primarily about increasing bandwidth, simplifying cabling, or encrypting traffic (those are separate functions).",
       "examTip": "Segmentation is a crucial security best practice."
    },
     {
      "id": 97,
       "question": "Which of the following is a benefit of using a 'client-server' network model?",
       "options":[
         "All computers have equal roles and responsibilities.",
         "Centralized management of resources, security, and user accounts, providing better control and scalability.",
         "It is easier and less expensive to set up than a peer-to-peer network.",
        "It is less secure than a peer-to-peer network."
       ],
       "correctAnswerIndex": 1,
       "explanation": "Client-server networks offer centralized administration, making it easier to manage users, security policies, and resources, especially in larger organizations. While peer-to-peer *can* be simpler for *very small* setups, client-server scales much better. The *initial* setup *can* be more complex and expensive, but long-term management is often easier. They are generally *more* secure than peer-to-peer.",
       "examTip": "Client-server networks are preferred for their scalability, security, and manageability in business environments."
    },
    {
       "id": 98,
        "question": "Which of the following is the MOST secure method for remote access to a network device's command-line interface?",
        "options":[
           "Telnet",
           "SSH (Secure Shell)",
           "HTTP",
           "FTP"
        ],
        "correctAnswerIndex": 1,
        "explanation": "SSH (Secure Shell) encrypts the entire communication session, protecting usernames, passwords, and commands from eavesdropping. Telnet, HTTP, and FTP transmit data in plain text, making them highly vulnerable to interception.",
        "examTip": "Always use SSH for remote command-line access; never use Telnet."
    },
        {
        "id": 99,
        "question": "What is a 'firewall' used for in network security?",
        "options":[
            "To speed up your internet connection.",
            "To control network traffic by allowing or blocking connections based on predefined security rules.",
            "To assign IP addresses to devices automatically.",
            "To translate domain names into IP addresses."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A firewall acts as a security barrier between a trusted network and an untrusted network (like the internet). It examines network traffic and enforces security policies to prevent unauthorized access. It's *not* about speed, IP assignment, or DNS.",
        "examTip": "Firewalls are a fundamental component of network security."
      },
      {
        "id": 100,
        "question": "What is the function of the Address Resolution Protocol (ARP)?",
        "options":[
          "To translate domain names to IP addresses.",
          "To assign IP addresses dynamically.",
           "To map IP addresses to MAC addresses on a local network, allowing devices to communicate at the data link layer.",
          "To encrypt network traffic."
        ],
        "correctAnswerIndex": 2,
        "explanation": "ARP is used within a local network to find the MAC address associated with a known IP address.  This is necessary for devices to send data frames to each other at Layer 2 (Data Link). DNS resolves domain names, DHCP assigns IP addresses, and other protocols handle encryption.",
        "examTip": "ARP is essential for communication within a local Ethernet network."
      }

  ]
});
