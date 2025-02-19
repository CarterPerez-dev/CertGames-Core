
needs question 1-44

[
  {
    "id": 45,
    "question": "What is 'two-factor authentication' (2FA)?",
    "options": [
      "Utilizing two separate passcodes on a single user account as a method to enhance overall login security and identity validation thoroughly.",
      "An extra layer of security that requires two different methods to verify your identity (e.g., password and a code sent to your phone).",
      "Opting for one extremely lengthy passphrase to authenticate, without requiring any additional verification factors, and believing it provides enough defense alone.",
      "Relying on an identical passphrase across more than one login profile as the sole method of account protection, assuming convenience."
    ],
    "correctAnswerIndex": 1,
    "explanation": "2FA adds an extra step to the login process, making it significantly harder for unauthorized users to access your accounts, even if they know your password. It typically involves something you *know* (password), something you *have* (phone), and/or something you *are* (biometric).",
    "examTip": "Enable 2FA whenever possible for important accounts."
  },
  {
    "id": 46,
    "question": "What is a benefit of using a dedicated file server in a network?",
    "options": [
      "Permitting every device on the network to freely access and edit all files without limits.",
      "Centralized storage and management of files, providing better security, backup, and access control.",
      "Offering a reduced overall cost compared to setting up basic peer-based file sharing methods.",
      "Removing any requirement for user credentials or profiles, thus simplifying the entire authentication process."
    ],
    "correctAnswerIndex": 1,
    "explanation": "A dedicated file server provides a central location for storing and managing files, making it easier to control access, back up data, and ensure data consistency. While peer-to-peer *can* be cheaper for *very small* networks, a file server offers better scalability and manageability. It doesn't eliminate user accounts – it *relies* on them for access control.",
    "examTip": "File servers are essential for centralized file management in business networks."
  },
  {
    "id": 47,
    "question": "You are troubleshooting a network connectivity problem. You can ping the local loopback address (127.0.0.1) and other devices on your local subnet, but you cannot ping the default gateway or any devices outside your subnet.  What is the MOST likely cause?",
    "options": [
      "An issue arising within the domain name resolution service, preventing proper hostname-to-IP address lookups and thus halting outbound access.",
      "A critical failure on the dynamic address allocation service, blocking clients from receiving basic valid IP configurations for connectivity.",
      "An incorrect default gateway configuration on your computer, or a problem with the router acting as the default gateway.",
      "Malicious software residing on the local machine, disrupting normal basic network functionality and potentially severely altering outbound connection attempts."
    ],
    "correctAnswerIndex": 2,
    "explanation": "The ability to ping local devices but *not* the default gateway (or anything beyond it) strongly suggests a problem with the default gateway configuration on your computer or an issue with the router itself. DNS is for name resolution, DHCP is for IP assignment, and a virus is less likely (though possible) to cause *this specific* symptom.",
    "examTip": "Check the default gateway configuration when you can communicate locally but not with external networks."
  },
  {
    "id": 48,
    "question": "What is the purpose of a 'cable tester'?",
    "options": [
      "Measuring the overall data transfer rate across a given link to determine actual bandwidth performance metrics.",
      "Locating and following individual wire runs hidden inside conduits or grouped cable clusters for labeling purposes.",
      "To test the physical integrity of network cables, checking for continuity, shorts, and miswires.",
      "Collecting data packets traveling across the network link to examine protocols and diagnose communication issues thoroughly."
    ],
    "correctAnswerIndex": 2,
    "explanation": "A cable tester verifies that a network cable is properly wired and functioning correctly. It detects common cabling problems like opens (breaks in the wire), shorts (wires touching where they shouldn't), and miswires (wires connected in the wrong order).  Speed testers measure speed, toner probes trace cables, and packet sniffers analyze traffic.",
    "examTip": "A cable tester is an essential tool for diagnosing physical layer network problems."
  },
  {
    "id": 49,
    "question": "Which of the following is a characteristic of a 'peer-to-peer' network?",
    "options": [
      "Relying on a primary server to centrally oversee resource distribution, user privileges, and security measures for all connected devices.",
      "Each computer can act as both a client (requesting resources) and a server (providing resources), sharing files and printers directly with other computers.",
      "Claiming that a peer-based environment offers higher data protection, tighter access controls, and fewer vulnerabilities than client-server setups, despite lacking centralized oversight.",
      "Asserting that decentralized peer-sharing scales effectively for vast enterprises, accommodating numerous users without requiring dedicated central management and maintaining robust performance."
    ],
    "correctAnswerIndex": 1,
    "explanation": "In a peer-to-peer network, there is no central authority.  Each computer shares resources directly with others. This is simpler to set up but less manageable and less secure for larger networks compared to client-server.",
    "examTip": "Peer-to-peer networks are common in small home or office environments."
  },
  {
    "id": 50,
    "question": "What is the difference between 'bandwidth' and 'throughput'?",
    "options": [
      "Bandwidth is the actual data transfer rate, while throughput is the best possible theoretical capacity under ideal conditions.",
      "Bandwidth is the theoretical maximum data transfer rate; throughput is the actual data transfer rate achieved in real-world conditions.",
      "Bandwidth is measured strictly in bits per second, whereas throughput always appears in bytes per second measurements.",
      "Bandwidth applies only to wired transmissions, whereas throughput is used exclusively for wireless connections."
    ],
    "correctAnswerIndex": 1,
    "explanation": "Bandwidth represents the *potential* capacity of a network connection, while throughput represents the *actual* amount of data successfully transferred over a period, taking into account factors like overhead, latency, errors, and congestion.  Both are typically measured in bits per second (or multiples like Mbps, Gbps).",
    "examTip": "Think of bandwidth as the 'pipe size' and throughput as the 'water flow' through that pipe."
  },
  {
    "id": 51,
    "question": "What is the purpose of 'port scanning'?",
    "options": [
      "Physically inspecting cables to verify wiring and detect potential fractures or poor connections.",
      "To identify open ports and services running on a network host.",
      "Encrypting data packets before they traverse external network paths.",
      "Automatically assigning IP addresses and network settings to connected devices."
    ],
    "correctAnswerIndex": 1,
    "explanation": "Port scanning involves probing a network host to determine which ports are open and listening for connections. This can be used by network administrators for security auditing or by attackers to identify potential vulnerabilities. It's *not* about cable testing, encryption, or IP assignment.",
    "examTip": "Port scanning can be a legitimate security assessment tool or a precursor to an attack."
  },
  {
    "id": 52,
    "question": "Which of the following is a common use for a 'virtual private network' (VPN)?",
    "options": [
      "Accelerating internet connectivity speeds for high-traffic networks and heavy data transfers.",
      "To securely connect to a private network (like your office network) over a public network (like the internet).",
      "Blocking every form of inbound traffic, ensuring no connections enter the local LAN.",
      "Preventing all malicious software from infiltrating a workstation or server."
    ],
    "correctAnswerIndex": 1,
    "explanation": "A VPN creates an encrypted tunnel for your internet traffic, protecting your data and privacy, especially when using public Wi-Fi. It allows remote users to access resources on a private network as if they were directly connected. While it *can* sometimes bypass geo-restrictions, that's not its *main* purpose. And it's *not* a firewall or antivirus.",
    "examTip": "Use a VPN for secure remote access and to protect your privacy on untrusted networks."
  },
  {
    "id": 53,
    "question": "Which type of network device operates primarily at Layer 3 (the Network layer) of the OSI model?",
    "options": [
      "A simple hub that repeats signals at the Physical layer.",
      "A Layer 2 switch that forwards frames based on MAC addresses.",
      "A router that makes forwarding decisions based on IP addressing information.",
      "A bridge that filters traffic by hardware (MAC) addresses on local segments."
    ],
    "correctAnswerIndex": 2,
    "explanation": "Routers make forwarding decisions based on IP addresses (Layer 3 addresses), connecting different networks together. Hubs are Layer 1 devices, switches are *primarily* Layer 2 (though some have Layer 3 capabilities), and bridges are Layer 2.",
    "examTip": "Remember that routers are the key devices for inter-network communication."
  },
  {
    "id": 54,
    "question": "What is 'network latency'?",
    "options": [
      "A metric describing the total amount of data that can pass through a link in one second.",
      "The time delay in data transmission across a network.",
      "The count of all connected endpoints within a specific broadcast domain.",
      "The measured distance in miles or kilometers between two devices."
    ],
    "correctAnswerIndex": 1,
    "explanation": "Latency is the time it takes for a data packet to travel from its source to its destination. High latency can cause slow response times and negatively impact real-time applications. Bandwidth is capacity, device count is network size, and distance is just physical separation.",
    "examTip": "Low latency is crucial for good network performance, especially for interactive applications."
  },
  {
    "id": 55,
    "question": "Which of the following is a benefit of using a standardized network protocol like TCP/IP?",
    "options": [
      "It guarantees absolute protection from all forms of cyber threats across the internet.",
      "It allows devices from different manufacturers to communicate with each other.",
      "It automatically configures every device’s settings without user intervention.",
      "It removes the need for skilled administrators or further security measures."
    ],
    "correctAnswerIndex": 1,
    "explanation": "Standardized protocols provide a common language for network devices, enabling interoperability between equipment from different vendors. They don't *guarantee* security (that requires additional measures), simplify *all* configuration, or eliminate administrators.",
    "examTip": "TCP/IP is the foundation of the internet and most modern networks."
  },
  {
    "id": 56,
    "question": "Which of the following is a characteristic of a 'stateful firewall'?",
    "options": [
      "It immediately drops every incoming packet, preventing any external data from entering the network.",
      "It analyzes each datagram independently, ignoring any established sessions or connection contexts.",
      "It tracks the state of network connections (e.g., TCP sessions) and makes filtering decisions based on both the packet header and the connection state.",
      "It exclusively blocks or allows traffic according to hardware (MAC) addresses without higher-layer inspection."
    ],
    "correctAnswerIndex": 2,
    "explanation": "A stateful firewall keeps track of active network connections and uses this information to make more intelligent filtering decisions. It can allow return traffic for established connections, providing better security than a simple packet filter that examines each packet in isolation. Blocking all incoming traffic is a default-deny approach, and MAC address filtering is a Layer 2 function.",
    "examTip": "Stateful firewalls provide more robust security than stateless packet filters."
  },
  {
    "id": 57,
    "question": "What is the purpose of an 'intrusion prevention system' (IPS)?",
    "options": [
      "Dynamically allocating IP addresses to ensure each device has a valid network configuration.",
      "To monitor network traffic for malicious activity and take action to block or prevent it.",
      "Encrypting all transmissions between endpoints to prevent eavesdropping on sensitive data.",
      "Resolving domain names to IP addresses for consistent connectivity across distributed networks."
    ],
    "correctAnswerIndex": 1,
    "explanation": "An IPS goes beyond the detection capabilities of an IDS (Intrusion Detection System) by actively blocking or preventing malicious traffic. It can drop packets, reset connections, or even quarantine infected systems.  It's *not* about IP assignment, encryption, or DNS.",
    "examTip": "Think of an IPS as a security guard that can actively stop threats, while an IDS is like a security camera that only observes and records."
  },
  {
    "id": 58,
    "question": "Which of the following is a good practice for creating strong passwords?",
    "options": [
      "Picking a familiar word or birth date for quicker recall when logging in.",
      "Selecting a brief, commonly used term for effortless typing and simpler memory.",
      "Using a mix of uppercase and lowercase letters, numbers, and symbols, and making it at least 12 characters long.",
      "Recycling one known phrase across every account for convenient administration."
    ],
    "correctAnswerIndex": 2,
    "explanation": "Strong passwords are long, complex, and unique, making them difficult to guess or crack using brute-force methods.  Avoid personal information, common words, and reusing passwords.",
    "examTip": "Use a password manager to help you generate and manage strong, unique passwords."
  },
  {
    "id": 59,
    "question": "What is a common use for a 'toner and probe' in network troubleshooting?",
    "options": [
      "Measuring and benchmarking the current throughput of a given network link.",
      "Verifying that each twisted-pair cable is correctly wired without breaks or shorts.",
      "To identify and trace specific wires or cables within a bundle, wall, or ceiling.",
      "Capturing data packets for in-depth protocol analysis or forensic investigation."
    ],
    "correctAnswerIndex": 2,
    "explanation": "A toner and probe (also called a tone generator and probe) is used to locate and identify cables. The toner generates a signal on one end of the cable, and the probe detects that signal at the other end, even if the cable is hidden or part of a larger bundle. It's *not* for speed testing, cable integrity testing, or traffic analysis.",
    "examTip": "Toner probes are essential tools for cable management and tracing."
  },
  {
    "id": 60,
    "question": "What is 'Power over Ethernet' (PoE)?",
    "options": [
      "An exclusive type of high-speed cable used in backbone infrastructure deployments.",
      "A technology that allows network cables to carry electrical power along with data.",
      "A newly defined standard for encrypting data on Ethernet-based transmissions.",
      "A specialized mechanism that distributes IP configurations to connected devices."
    ],
    "correctAnswerIndex": 1,
    "explanation": "PoE simplifies device deployment by providing both power and data over a single Ethernet cable. This is particularly useful for devices like IP phones, wireless access points, and security cameras, where running separate power cables might be difficult or expensive.",
    "examTip": "PoE eliminates the need for separate power outlets for many network devices."
  },
  {
    "id": 61,
    "question": "Which command-line tool is used to display detailed network configuration information on a Windows system, including IP address, subnet mask, default gateway, and DNS servers?",
    "options": [
      "Issuing repeated ICMP Echo Requests to verify connectivity for remote endpoints.",
      "Tracing each hop a data packet takes on its route across multiple network segments.",
      "ipconfig /all",
      "Looking up DNS records to map domain names to IP addresses or vice versa."
    ],
    "correctAnswerIndex": 2,
    "explanation": "`ipconfig /all` provides a comprehensive overview of network adapter settings, including all the information needed to troubleshoot most connectivity issues. `ping` tests connectivity, `tracert` traces routes, and `nslookup` queries DNS.",
    "examTip": "`ipconfig /all` is a fundamental troubleshooting tool on Windows."
  },
  {
    "id": 62,
    "question": "What is 'network address translation' (NAT) primarily used for?",
    "options": [
      "Applying strong ciphers to scramble data traffic for confidentiality and privacy.",
      "To allow multiple devices on a private network to share a single public IP address when communicating with the internet.",
      "Dynamically providing IP settings, like addresses and gateways, to every host on a LAN.",
      "Filtering outbound connections based on specific URL or content categories."
    ],
    "correctAnswerIndex": 1,
    "explanation": "NAT translates private IP addresses (used within a local network) to a public IP address (used on the internet), conserving public IPv4 addresses and providing a layer of security by hiding the internal network structure. It's *not* encryption, dynamic IP assignment (DHCP), or content filtering.",
    "examTip": "NAT is essential for connecting private networks to the internet."
  },
  {
    "id": 63,
    "question": "What is the purpose of an 'access control list' (ACL) in network security?",
    "options": [
      "Providing IP addresses and DNS server information to hosts upon request.",
      "Securing data streams by applying robust encryption ciphers to every packet.",
      "To control network access by permitting or denying traffic based on predefined rules (e.g., source/destination IP address, port number).",
      "Resolving Fully Qualified Domain Names (FQDNs) to their respective IP addresses."
    ],
    "correctAnswerIndex": 2,
    "explanation": "ACLs are sets of rules that define which network traffic is allowed or blocked, providing a fundamental mechanism for controlling access to network resources. They are commonly used on routers and firewalls. They're *not* for IP assignment, encryption, or DNS.",
    "examTip": "ACLs are a key component of network security and access control."
  },
  {
    "id": 64,
    "question": "Which of the following is a potential security risk associated with using default usernames and passwords on network devices?",
    "options": [
      "Enforcing stronger protections automatically and simplifying overall administrative tasks.",
      "Minimizing time spent on initial configuration while boosting device performance levels.",
      "Attackers can easily gain unauthorized access to the device using well-known default credentials.",
      "Ensuring only privileged individuals know the standard credentials, increasing internal efficiency."
    ],
    "correctAnswerIndex": 2,
    "explanation": "Default usernames and passwords for network devices (routers, switches, access points) are publicly known and easily found online. Failing to change them is a major security vulnerability that allows attackers to easily gain control of the device and potentially the entire network.",
    "examTip": "Always change default usernames and passwords on all network devices."
  },
  {
    "id": 65,
    "question": "What is a 'denial-of-service' (DoS) attack?",
    "options": [
      "A systematic approach to capturing confidential user credentials through deception.",
      "An attempt to overwhelm a network or server with traffic, making it unavailable to legitimate users.",
      "A strategy to trick individuals into revealing sensitive data through fabricated communications.",
      "A method of repeatedly guessing passwords to gain illicit entry into protected systems."
    ],
    "correctAnswerIndex": 1,
    "explanation": "A DoS attack aims to disrupt a network service by flooding it with excessive traffic, preventing legitimate users from accessing it. Password stealing is credential theft, tricking users is phishing, and password guessing is a brute-force attack.",
    "examTip": "DoS attacks can cause significant downtime and disruption."
  },
  {
    "id": 66,
    "question": "What is a 'distributed denial-of-service' (DDoS) attack?",
    "options": [
      "A malicious disruption attempt originating from a single IP address, saturating network resources alone.",
      "A DoS attack that originates from multiple compromised computers (a botnet) simultaneously.",
      "A type of social engineering ploy used to deceive targets into divulging personal data.",
      "An automated password-cracking technique that cycles through numerous combinations."
    ],
    "correctAnswerIndex": 1,
    "explanation": "A DDoS attack is a more powerful and sophisticated form of DoS attack where the attack traffic comes from many different sources, often a botnet (a network of compromised computers controlled by an attacker). This makes it much harder to block the attack.",
    "examTip": "DDoS attacks are a significant threat to online services."
  },
  {
    "id": 67,
    "question": "Which of the following is a characteristic of a 'virtual LAN' (VLAN)?",
    "options": [
      "Requiring each isolated subnetwork to use a separate, physically distinct switch.",
      "It logically segments a physical network into multiple, isolated broadcast domains, even if devices are connected to the same physical switch.",
      "Expanding the broadcast domain for greater visibility of all connected hosts, whether wired or wireless.",
      "Operating solely in wireless environments to separate guest traffic from internal traffic."
    ],
    "correctAnswerIndex": 1,
    "explanation": "VLANs allow you to create logically separate networks on the *same* physical switch infrastructure. This improves security, performance (by reducing broadcast traffic), and manageability. They *decrease* broadcast domain size and are *primarily* used in wired networks (though they can be extended to wireless).",
    "examTip": "VLANs are a crucial tool for network segmentation and security."
  },
  {
    "id": 68,
    "question": "What is the function of the Address Resolution Protocol (ARP)?",
    "options": [
      "Resolving domain names (e.g., www.example.com) to their corresponding IP addresses.",
      "Assigning dynamic IP addresses to hosts through the DHCP leasing mechanism.",
      "To map IP addresses to MAC addresses on a local network, allowing devices to communicate at Layer 2.",
      "Applying encryption to all data packets to ensure secure transmission over untrusted links."
    ],
    "correctAnswerIndex": 2,
    "explanation": "ARP is used within a local network (specifically, Ethernet networks) to find the MAC address associated with a known IP address. This is essential for devices to send data frames to each other at the data link layer. DNS resolves domain names, DHCP assigns IPs, and various protocols handle encryption.",
    "examTip": "ARP is crucial for communication within a local Ethernet network."
  },
  {
    "id": 69,
    "question": "Which of the following best describes 'Quality of Service' (QoS) in networking?",
    "options": [
      "A measure of how quickly technicians can install new Ethernet cabling in a building.",
      "The ability to prioritize certain types of network traffic over others, ensuring that critical applications (like voice or video) receive adequate bandwidth and low latency.",
      "A special category of cables used exclusively for high-priority signals to reduce interference.",
      "A security protocol for encrypting all sensitive data that traverses a LAN or WAN link."
    ],
    "correctAnswerIndex": 1,
    "explanation": "QoS allows network administrators to manage network resources and ensure that time-sensitive applications receive the necessary performance, even during periods of congestion.  It's *not* about cable installation, cable type, or encryption.",
    "examTip": "QoS is essential for delivering good performance for real-time applications."
  },
  {
    "id": 70,
    "question": "What is 'packet fragmentation'?",
    "options": [
      "The process of applying cryptographic transformations to a data packet for confidentiality.",
      "The process of dividing a data packet into smaller fragments for transmission over a network when the packet is larger than the MTU.",
      "Merging multiple smaller packets into a single jumbo frame for optimized bandwidth usage.",
      "Filtering out or discarding packets that contain certain content deemed unauthorized."
    ],
    "correctAnswerIndex": 1,
    "explanation": "When a data packet is too large for a particular network link (exceeds the Maximum Transmission Unit or MTU), it must be fragmented into smaller pieces, transmitted, and then reassembled at the destination.  It's *not* encryption, combining packets, or filtering.",
    "examTip": "Excessive fragmentation can decrease network performance."
  },
  {
    "id": 71,
    "question": "What is the purpose of a 'network mask' (also known as a 'subnet mask')?",
    "options": [
      "Applying advanced encryption algorithms to safeguard sensitive data in transit.",
      "To identify the network portion and the host portion of an IP address.",
      "Automatically distributing IP settings to local hosts seeking dynamic assignments.",
      "Blocking or allowing traffic based on recognized device hardware addresses."
    ],
    "correctAnswerIndex": 1,
    "explanation": "The subnet mask works with the IP address to define which bits represent the network and which bits represent the host. This is essential for routing and determining whether two devices are on the same subnet. It's *not* encryption, dynamic IP assignment (DHCP), or MAC address filtering.",
    "examTip": "Subnet masks are crucial for understanding IP addressing and network segmentation."
  },
  {
    "id": 72,
    "question": "What is the difference between a 'public IP address' and a 'private IP address'?",
    "options": [
      "Public IP addresses stay confined within local networks, while private IP addresses exist across the global internet.",
      "Public IP addresses are globally unique and routable on the internet; private IP addresses are used within private networks and are not directly accessible from the internet.",
      "Public IP addresses must be assigned manually; private IP addresses always use dynamic allocation methods.",
      "Public IP addresses automatically secure communications, whereas private IP addresses offer no encryption at all."
    ],
    "correctAnswerIndex": 1,
    "explanation": "Public IP addresses are assigned to devices that connect directly to the internet and are globally unique. Private IP addresses (e.g., 192.168.x.x, 10.x.x.x, 172.16.x.x-172.31.x.x) are used within private networks (homes, offices) and are not directly routable on the internet. NAT translates between private and public addresses. Assignment method (dynamic/static) and security are separate concepts.",
    "examTip": "Private IP addresses are used within local networks and are not visible on the public internet."
  },
  {
    "id": 73,
    "question": "Which of the following is a benefit of using a 'virtual private network' (VPN)?",
    "options": [
      "Complete and guaranteed anonymity for every online activity, with zero traceability.",
      "It encrypts your internet traffic and masks your IP address, enhancing your privacy and security, especially on public Wi-Fi.",
      "Automatically increasing upload and download speeds regardless of your ISP limitations.",
      "Preventing all forms of malicious software, including viruses and spyware, from infecting devices."
    ],
    "correctAnswerIndex": 1,
    "explanation": "VPNs create a secure, encrypted tunnel for your internet traffic, protecting it from eavesdropping and enhancing your privacy. While they *mask* your IP address, they don't guarantee *complete* anonymity. They typically *don't* speed up connections (and can sometimes *slow* them down), and they don't offer *complete* malware protection.",
    "examTip": "Use a VPN to protect your data and privacy, especially on public Wi-Fi."
  },
  {
    "id": 74,
    "question": "What is the purpose of the Domain Name System (DNS)?",
    "options": [
      "Providing dynamic IP addresses to network hosts during their startup process.",
      "To translate human-readable domain names (like google.com) into numerical IP addresses that computers use to communicate.",
      "Encrypting sensitive data to protect it from interception or tampering in transit.",
      "Ensuring broadcast loops are prevented by blocking redundant switch ports."
    ],
    "correctAnswerIndex": 1,
    "explanation": "DNS acts like the internet's phone book, converting domain names into IP addresses, making it easier for users to access websites and other online resources. DHCP assigns IPs, encryption uses separate protocols, and STP prevents loops.",
    "examTip": "DNS is essential for navigating the internet using easy-to-remember names."
  },
  {
    "id": 75,
    "question": "Which of the following is a common security measure used to protect against unauthorized access to a wireless network?",
    "options": [
      "Operating an open SSID with no password for maximum convenience and coverage.",
      "Enabling Wired Equivalent Privacy (WEP) for basic data scrambing and partial network secrecy.",
      "Using WPA2 or WPA3 encryption with a strong, unique password, and changing the default SSID.",
      "Freely distributing the pre-shared key to any individual who requests it."
    ],
    "correctAnswerIndex": 2,
    "explanation": "Strong encryption (WPA2 or WPA3) and a complex, unique password are crucial for securing a Wi-Fi network.  Changing the default SSID adds a small layer of obscurity. Open networks, WEP, and sharing passwords are all *major* security risks.",
    "examTip": "Always secure your Wi-Fi network with strong encryption and a strong password."
  },
  {
    "id": 76,
    "question": "What is the purpose of a 'firewall' in network security?",
    "options": [
      "Ensuring maximum throughput by prioritizing data flows from high-bandwidth applications.",
      "To control network traffic and block unauthorized access to or from a private network, based on predefined security rules.",
      "Automatically allocating IP addresses and DNS configurations upon device requests.",
      "Resolving human-friendly URLs into IP addresses for routing purposes."
    ],
    "correctAnswerIndex": 1,
    "explanation": "A firewall acts as a gatekeeper, examining incoming and outgoing network traffic and allowing or blocking it based on configured rules. This helps prevent unauthorized access and protect against malware. It's *not* about speed, IP assignment (DHCP), or DNS.",
    "examTip": "Firewalls are a fundamental component of network security."
  },
  {
    "id": 77,
    "question": "Which command-line tool is commonly used to test network connectivity to a remote host and measure the round-trip time?",
    "options": [
      "tracert (or traceroute), which displays the intermediate hops on the route to the destination.",
      "ping",
      "ipconfig, which shows the local adapter’s IP configuration details.",
      "nslookup, used for querying DNS servers to resolve domain names."
    ],
    "correctAnswerIndex": 1,
    "explanation": "The `ping` command sends ICMP Echo Request packets to a target host and listens for Echo Reply packets.  The time it takes for the round trip is a measure of network latency. `tracert` shows the route, `ipconfig` displays local configuration, and `nslookup` queries DNS.",
    "examTip": "`ping` is a basic but essential network troubleshooting tool."
  },
  {
    "id": 78,
    "question": "What is the primary purpose of an 'intrusion detection system' (IDS)?",
    "options": [
      "Providing automatic IP address assignments to hosts on the local network segment.",
      "Completely preventing all inbound and outbound attacks by blocking suspicious traffic instantly.",
      "To monitor network traffic for suspicious activity and generate alerts for security personnel.",
      "Encrypting entire data flows so no third parties can intercept critical information."
    ],
    "correctAnswerIndex": 2,
    "explanation": "An IDS passively monitors network traffic for signs of malicious activity or policy violations. It generates alerts so that security administrators can investigate and take action. While *some* IDSes can take *limited* preventative action, their *main* role is detection and alerting.  Intrusion *Prevention* Systems (IPSs) are more focused on *blocking* threats.",
    "examTip": "Think of an IDS as a security camera system for your network."
  },
  {
    "id": 79,
    "question": "What is the main difference between a 'hub' and a 'switch' in a network?",
    "options": [
      "A hub processes and forwards frames only to their destination device, while a switch repeats every signal to all ports.",
      "A hub is faster than a switch under high load conditions due to simpler traffic handling.",
      "A hub broadcasts data to all connected devices, while a switch forwards data only to the intended recipient based on MAC address.",
      "A switch can only operate on wireless signals, whereas a hub is strictly for wired connections."
    ],
    "correctAnswerIndex": 2,
    "explanation": "Hubs are simple repeaters that operate at Layer 1 (Physical) and send all incoming data to every connected device, creating collisions and wasting bandwidth. Switches operate at Layer 2 (Data Link) and learn the MAC addresses of connected devices, forwarding traffic only to the appropriate port, which significantly improves efficiency and reduces collisions. Both are typically used in *wired* networks, though hubs are largely obsolete.",
    "examTip": "Switches are much more efficient and secure than hubs."
  },
  {
    "id": 80,
    "question": "Which of the following best describes 'network documentation'?",
    "options": [
      "A curated list of frequently accessed websites that users visit daily.",
      "A comprehensive record of a network's design, implementation, configuration, and operation, including diagrams, IP address assignments, device settings, and procedures.",
      "A repository of all software licenses used within an organization’s environment.",
      "A central reference holding personal user passwords for direct account access."
    ],
    "correctAnswerIndex": 1,
    "explanation": "Network documentation provides a detailed understanding of the network's structure, how it's configured, and how it operates. This is essential for troubleshooting, planning, maintenance, and security. It's *far* more than just software licenses or (insecurely stored) passwords.",
    "examTip": "Good network documentation is critical for effective network management."
  },
  {
    "id": 81,
    "question": "What is the purpose of 'subnetting' a network?",
    "options": [
      "Expanding the total pool of globally routable IP addresses available on the internet.",
      "To divide a network into smaller, more manageable logical subnetworks, improving security, performance, and address allocation efficiency.",
      "Implementing cryptographic methods to protect transmitted data from unauthorized viewing.",
      "Reducing overall resilience by introducing additional boundaries prone to malfunction."
    ],
    "correctAnswerIndex": 1,
    "explanation": "Subnetting divides a larger network into smaller, isolated segments. This reduces broadcast traffic, improves security by limiting the scope of potential breaches, and makes it easier to manage IP address allocation. It doesn't *increase* the *total* number of addresses and is unrelated to encryption.",
    "examTip": "Subnetting is a fundamental concept in IP networking."
  },
  {
    "id": 82,
    "question": "Which of the following is a characteristic of a 'star' network topology?",
    "options": [
      "Connecting every device through one continuous coaxial cable without any central device.",
      "All devices are connected to a central hub or switch, and if the central device fails, the entire network goes down.",
      "Arranging devices in a ring so that each node passes data to the next one in the circle.",
      "Providing each device multiple redundant links to every other device, forming a mesh."
    ],
    "correctAnswerIndex": 1,
    "explanation": "In a star topology, each device has a dedicated connection to a central hub or (more commonly) a switch.  This makes it easy to add/remove devices and troubleshoot. *However*, the central device is a *single point of failure* – if it goes down, the entire network connected to it is affected.",
    "examTip": "The star topology is widely used due to its simplicity, but the central device's reliability is crucial."
  },
  {
    "id": 83,
    "question": "What is the purpose of 'MAC address filtering' on a wireless access point?",
    "options": [
      "Automatically allocating IP addresses, subnet masks, and gateways to each new client on the network.",
      "Encrypting every packet exchanged over the wireless medium, ensuring data confidentiality.",
      "To restrict network access based on the physical MAC addresses of devices, allowing or blocking specific devices.",
      "Translating URLs or domain names to numeric IP addresses for client requests."
    ],
    "correctAnswerIndex": 2,
    "explanation": "MAC address filtering allows you to create a list of allowed (or blocked) MAC addresses, controlling which wireless devices can connect to your network.  While it can *enhance* security, it's not foolproof (MAC addresses can be spoofed) and is *not* a substitute for strong encryption. It's *not* about IP assignment, encryption, or DNS.",
    "examTip": "MAC address filtering provides an additional layer of security, but it shouldn't be the *only* security measure for a wireless network."
  },
  {
    "id": 84,
    "question": "What is the purpose of a default gateway in a network?",
    "options": [
      "Distributing IP address leases dynamically to connected endpoints on the LAN.",
      "To serve as the exit point for devices, routing traffic to other networks such as the internet.",
      "Offering wireless connectivity to nearby devices through radio signals or similar technology.",
      "Encrypting data transmissions to ensure confidentiality for all packets crossing the network."
    ],
    "correctAnswerIndex": 1,
    "explanation": "The default gateway is the 'exit point' for a device's local network. When a device needs to communicate with a device on a different network (including the internet), it sends the traffic to its default gateway, which is typically the IP address of a router.",
    "examTip": "Without a default gateway configured, a device can only communicate with other devices on the same local subnet."
  },
  {
    "id": 85,
    "question": "Which of the following is a security risk associated with using public Wi-Fi hotspots?",
    "options": [
      "Automatically boosting download speeds beyond typical home broadband limits.",
      "Providing more robust encryption than most home routers, ensuring greater safety.",
      "Potential for eavesdropping and data interception due to the often-unsecured nature of public networks.",
      "Allowing unfettered access to every internal resource without additional credentials."
    ],
    "correctAnswerIndex": 2,
    "explanation": "Public Wi-Fi networks often lack strong security measures (or any security at all), making it easier for attackers to intercept data transmitted over the network. It's crucial to use a VPN when connecting to public Wi-Fi.",
    "examTip": "Always use a VPN when connecting to public Wi-Fi to protect your data."
  },
  {
    "id": 86,
    "question": "What is 'social engineering' in the context of cybersecurity?",
    "options": [
      "Developing a new social media platform for enterprise communication needs.",
      "Tricking people into revealing confidential information or performing actions that compromise security, often through manipulation and deception.",
      "Promoting products and services through social networking channels to boost brand presence.",
      "Forming professional relationships at conferences for exchanging technical insights."
    ],
    "correctAnswerIndex": 1,
    "explanation": "Social engineering attacks exploit human psychology rather than technical vulnerabilities. Attackers may impersonate trusted individuals or organizations, use deceptive tactics, or prey on people's emotions to gain access to systems or information.",
    "examTip": "Be skeptical of unsolicited requests for information and be aware of common social engineering techniques."
  },
  {
    "id": 87,
    "question": "What is 'phishing'?",
    "options": [
      "A recreational activity involving the catching of fish in freshwater or saltwater environments.",
      "A file organization technique to optimize storage on local drives or network shares.",
      "A type of cyberattack where attackers attempt to deceive users into revealing sensitive information (like usernames, passwords, or credit card details) by posing as a trustworthy entity.",
      "An advanced method of increasing internet connection speeds by rerouting data streams."
    ],
    "correctAnswerIndex": 2,
    "explanation": "Phishing attacks often involve fraudulent emails, websites, or messages that appear to be from legitimate sources. The goal is to trick the recipient into clicking on malicious links, opening infected attachments, or providing personal information.",
    "examTip": "Be cautious of suspicious emails, websites, and messages, especially those asking for personal information or creating a sense of urgency."
  },
  {
    "id": 88,
    "question": "Which of the following is a good practice for protecting your computer from malware?",
    "options": [
      "Downloading files from any online source to increase the variety of available tools.",
      "Installing and regularly updating antivirus and anti-malware software, and being cautious about opening email attachments or clicking on links from unknown sources.",
      "Disabling firewalls to avoid potential connectivity issues across multiple applications.",
      "Reusing the same strong passphrase across all user accounts to simplify password management."
    ],
    "correctAnswerIndex": 1,
    "explanation": "Protecting your computer from malware requires a multi-layered approach, including using security software, practicing safe browsing habits, and keeping your software up-to-date. Downloading from untrusted sources, disabling firewalls, and reusing passwords are all *bad* practices.",
    "examTip": "Be proactive about protecting your computer from malware."
  },
  {
    "id": 89,
    "question": "What is the purpose of a 'virtual private network' (VPN)?",
    "options": [
      "Optimizing data speeds above your ISP’s limit and bypassing any bandwidth throttles.",
      "To create a secure, encrypted connection over a public network (like the internet), allowing you to access private network resources remotely and protect your data from eavesdropping.",
      "Blocking every inbound request to ensure your local device never appears on external scans.",
      "Assigning IP addresses dynamically to devices as they connect to the LAN or WLAN."
    ],
    "correctAnswerIndex": 1,
    "explanation": "A VPN encrypts your internet traffic and routes it through a secure server, masking your IP address and protecting your data, especially on public Wi-Fi. It allows remote users to access private networks as if they were directly connected. It's *not* primarily for speeding up connections, blocking all traffic, or assigning IPs.",
    "examTip": "Use a VPN to enhance your online privacy and security."
  },
  {
    "id": 90,
    "question": "Which of the following is an example of 'multi-factor authentication' (MFA)?",
    "options": [
      "Adopting a single but exceedingly complex password for enhanced protection.",
      "Entering a password and then entering a code sent to your mobile phone via SMS or generated by an authenticator app.",
      "Using the same passphrase across multiple accounts to reduce complexity.",
      "Employing a single biometric factor, like a fingerprint, as the sole login criterion."
    ],
    "correctAnswerIndex": 1,
    "explanation": "MFA requires two or more *different* forms of verification: something you *know* (password), something you *have* (phone), and/or something you *are* (biometric). While a *fingerprint* is *one* factor, the question asks for *multi*-factor. Using the same password is a security *risk*. A long password is good, but not MFA.",
    "examTip": "Enable MFA whenever possible to significantly enhance account security."
  },
  {
    "id": 91,
    "question": "What is the purpose of an 'intrusion prevention system' (IPS)?",
    "options": [
      "Distributing IP addresses to newly joined hosts on a subnet, ensuring each device has unique configuration details.",
      "To monitor network traffic for suspicious activity and take proactive steps to block or prevent malicious traffic.",
      "Protecting data transfers by encrypting packets sent between any pair of hosts on the internet.",
      "Mapping textual domain names to numerical addresses for consistent access to resources."
    ],
    "correctAnswerIndex": 1,
    "explanation": "An IPS goes beyond the *detection* capabilities of an IDS (Intrusion Detection System) by actively *blocking* or *preventing* malicious traffic.  It can drop packets, reset connections, or quarantine infected systems. It's not for IP assignment (DHCP), encryption, or DNS.",
    "examTip": "An IPS is a proactive security measure that can stop attacks before they cause damage."
  },
  {
    "id": 92,
    "question": "What is a 'denial-of-service' (DoS) attack?",
    "options": [
      "A targeted method for intercepting passwords by exploiting repeated user login attempts.",
      "An attempt to overwhelm a network or server with traffic from a single source, making it unavailable to legitimate users.",
      "A scheme involving fraudulent messages designed to trick users into revealing personal data.",
      "A repeated password-cracking mechanism that tries numerous combinations to gain entry."
    ],
    "correctAnswerIndex": 1,
    "explanation": "A DoS attack aims to disrupt a network service by flooding it with traffic *from a single source*, making it unavailable. Password stealing is credential theft, tricking users is phishing, and password guessing is a brute-force attack. *Distributed* DoS (DDoS) attacks use *multiple* sources.",
    "examTip": "DoS attacks can cause significant downtime and disruption."
  },
  {
    "id": 93,
    "question": "What is a 'distributed denial-of-service' (DDoS) attack?",
    "options": [
      "A single-host disruption attempt that saturates a remote service’s resources alone.",
      "A DoS attack that originates from multiple compromised computers (often a botnet) simultaneously, making it much harder to block.",
      "A phishing method that impersonates a website to steal login credentials from unwary users.",
      "A brute-force intrusion technique that increments possible passwords for illicit network entry."
    ],
    "correctAnswerIndex": 1,
    "explanation": "A DDoS attack is a more powerful and sophisticated form of DoS attack where the attack traffic comes from many different sources, often a botnet (a network of compromised computers controlled by an attacker). This makes it difficult to mitigate the attack by simply blocking a single source IP address.",
    "examTip": "DDoS attacks are a major threat to online services and require specialized mitigation techniques."
  },
  {
    "id": 94,
    "question": "Which type of network device is responsible for forwarding data packets between different networks based on their IP addresses?",
    "options": [
      "A hub, which simply repeats signals received on any port to all other ports.",
      "A switch that filters and forwards traffic based solely on MAC address information.",
      "A router that looks at Layer 3 addresses (IP) to determine the best path for the packets.",
      "A repeater that regenerates weak signals to extend the distance they can travel."
    ],
    "correctAnswerIndex": 2,
    "explanation": "Routers operate at Layer 3 (Network) of the OSI model and make forwarding decisions based on IP addresses. They connect different networks together and determine the best path for data to travel. Hubs and repeaters are Layer 1, and switches are *primarily* Layer 2.",
    "examTip": "Routers are the key devices for connecting networks and routing traffic across the internet."
  },
  {
    "id": 95,
    "question": "What is a 'MAC address'?",
    "options": [
      "A software-based logical identifier assigned dynamically by a DHCP server to a local host.",
      "A unique physical address assigned to a network interface card (NIC) by the manufacturer.",
      "An IP-based identifier used for routing information across wide area networks.",
      "A specialized cable format designed to interconnect various Ethernet segments."
    ],
    "correctAnswerIndex": 1,
    "explanation": "A MAC address (Media Access Control address) is a unique hardware identifier burned into a network interface card (NIC). It's used for communication within a local network segment (Layer 2). IP addresses are logical and used for routing (Layer 3).",
    "examTip": "MAC addresses are like a device's hardware fingerprint on the local network."
  },
  {
    "id": 96,
    "question": "What is 'network segmentation' primarily used for?",
    "options": [
      "Multiplying the total throughput to accommodate more data in the same timeframe.",
      "To improve network security and performance by dividing a network into smaller, isolated subnetworks.",
      "Eliminating physical wiring complexity by combining all subnets into one large broadcast domain.",
      "Encrypting every byte of traffic traversing each segment for maximum privacy."
    ],
    "correctAnswerIndex": 1,
    "explanation": "Network segmentation (often using VLANs or subnets) limits the scope of broadcast traffic, reduces congestion, and contains security breaches, improving both security and performance. It's *not* primarily about increasing bandwidth, simplifying cabling, or encrypting traffic (those are separate functions).",
    "examTip": "Segmentation is a crucial security best practice."
  },
  {
    "id": 97,
    "question": "Which of the following is a benefit of using a 'client-server' network model?",
    "options": [
      "Every machine on the network simultaneously shares resources and handles security equally.",
      "Centralized management of resources, security, and user accounts, providing better control and scalability.",
      "It inherently requires less expense and minimal configuration compared to a peer-to-peer approach.",
      "It offers weaker data protection than peer-to-peer because all devices rely on a single point of truth."
    ],
    "correctAnswerIndex": 1,
    "explanation": "Client-server networks offer centralized administration, making it easier to manage users, security policies, and resources, especially in larger organizations. While peer-to-peer *can* be simpler for *very small* setups, client-server scales much better. The *initial* setup *can* be more complex and expensive, but long-term management is often easier. They are generally *more* secure than peer-to-peer.",
    "examTip": "Client-server networks are preferred for their scalability, security, and manageability in business environments."
  },
  {
    "id": 98,
    "question": "Which of the following is the MOST secure method for remote access to a network device's command-line interface?",
    "options": [
      "Telnet, offering unencrypted plain-text sessions for straightforward configuration tasks.",
      "SSH (Secure Shell)",
      "HTTP, delivering standard web traffic over port 80 for remote administration.",
      "FTP, enabling file transfers and command execution without encryption."
    ],
    "correctAnswerIndex": 1,
    "explanation": "SSH (Secure Shell) encrypts the entire communication session, protecting usernames, passwords, and commands from eavesdropping. Telnet, HTTP, and FTP transmit data in plain text, making them highly vulnerable to interception.",
    "examTip": "Always use SSH for remote command-line access; never use Telnet."
  },
  {
    "id": 99,
    "question": "What is a 'firewall' used for in network security?",
    "options": [
      "Increasing overall bandwidth by accelerating data transfer rates to external sites.",
      "To control network traffic by allowing or blocking connections based on predefined security rules.",
      "Automatically distributing IP addresses and DNS information to connected devices on the subnet.",
      "Translating domain names into IP addresses to facilitate easier web browsing."
    ],
    "correctAnswerIndex": 1,
    "explanation": "A firewall acts as a security barrier between a trusted network and an untrusted network (like the internet). It examines network traffic and enforces security policies to prevent unauthorized access. It's *not* about speed, IP assignment, or DNS.",
    "examTip": "Firewalls are a fundamental component of network security."
  },
  {
    "id": 100,
    "question": "What is the function of the Address Resolution Protocol (ARP)?",
    "options": [
      "Looking up domain names in DNS to retrieve the corresponding IP addresses for a website.",
      "Dynamically assigning IP addresses to hosts through scope-based leasing intervals.",
      "To map IP addresses to MAC addresses on a local network, allowing devices to communicate at the data link layer.",
      "Encrypting packets end-to-end to secure transmissions against interception or tampering."
    ],
    "correctAnswerIndex": 2,
    "explanation": "ARP is used within a local network to find the MAC address associated with a known IP address.  This is necessary for devices to send data frames to each other at Layer 2 (Data Link). DNS resolves domain names, DHCP assigns IP addresses, and other protocols handle encryption.",
    "examTip": "ARP is essential for communication within a local Ethernet network."
  }
]
