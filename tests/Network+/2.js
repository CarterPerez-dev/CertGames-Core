db.tests.insertOne({{
  "category": "nplus",
  "testId": 2,
  "testName": "Network+ Practice Test #2 (Very Easy)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "Which device provides wireless network access to clients?",
      "options": [
        "Access point",
        "Switch",
        "Router",
        "Firewall"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An access point (AP) allows wireless devices to connect to a wired network using Wi-Fi. Switches connect wired devices within a LAN. Routers direct traffic between networks. Firewalls control and filter network traffic for security purposes.",
      "examTip": "Access points = Wi-Fi access. Think 'AP' for 'Air Points' for easy recall."
    },
    {
      "id": 2,
      "question": "Which port does HTTP use by default?",
      "options": [
        "80",
        "443",
        "22",
        "25"
      ],
      "correctAnswerIndex": 0,
      "explanation": "HTTP uses port 80 for web traffic. Port 443 is for HTTPS (secure web traffic). Port 22 is for SSH. Port 25 is for SMTP (email).",
      "examTip": "Quick recall: HTTP (80), HTTPS (443), SSH (22), SMTP (25)."
    },
    {
      "id": 3,
      "question": "Which type of cable is commonly used to connect a computer to a switch in a wired network?",
      "options": [
        "Ethernet cable (RJ45)",
        "Coaxial cable",
        "Fiber optic cable",
        "Serial cable"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Ethernet cables with RJ45 connectors are commonly used for wired network connections. Coaxial cables are used for cable TV and older networks. Fiber optic cables are used for high-speed, long-distance connections. Serial cables connect legacy equipment.",
      "examTip": "Ethernet cables with RJ45 = Most common wired LAN connection."
    },
    {
      "id": 4,
      "question": "Which IP address is a loopback address used for testing on a local machine?",
      "options": [
        "127.0.0.1",
        "192.168.1.1",
        "10.0.0.1",
        "169.254.0.1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "127.0.0.1 is the loopback address for testing local machine networking. 192.168.1.1 is commonly used for routers in private networks. 10.0.0.1 is another private network address. 169.254.0.1 is part of the APIPA range used when DHCP fails.",
      "examTip": "127.0.0.1 = Loopback = Test your own machine's networking stack."
    },
    {
      "id": 5,
      "question": "Which device routes traffic between different networks?",
      "options": [
        "Router",
        "Switch",
        "Hub",
        "Access point"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A router directs data packets between different networks based on IP addresses. Switches forward data within the same network based on MAC addresses. Hubs broadcast data to all connected devices. Access points provide wireless connectivity.",
      "examTip": "Router = Routes between networks; Switch = Switches within the same network."
    },
    {
      "id": 6,
      "question": "Which layer of the OSI model is responsible for presenting data in a readable format, including encryption and compression?",
      "options": [
        "Presentation layer",
        "Application layer",
        "Session layer",
        "Data link layer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The Presentation layer (Layer 6) formats data for the application layer, handling encryption and compression. The Application layer (Layer 7) interacts with user applications. The Session layer (Layer 5) manages communication sessions. The Data link layer (Layer 2) handles data transfer between adjacent network nodes.",
      "examTip": "Presentation = Pretty the data (encryption, formatting, compression)."
    },
    {
      "id": 7,
      "question": "Which wireless standard operates only on the 2.4GHz frequency and supports speeds up to 11 Mbps?",
      "options": [
        "802.11b",
        "802.11a",
        "802.11g",
        "802.11n"
      ],
      "correctAnswerIndex": 0,
      "explanation": "802.11b operates at 2.4GHz and supports speeds up to 11 Mbps. 802.11a operates at 5GHz with up to 54 Mbps. 802.11g operates at 2.4GHz with 54 Mbps. 802.11n supports both 2.4GHz and 5GHz with speeds up to 600 Mbps.",
      "examTip": "802.11b = Basic and slow; remember 'b' for 'basic' speed."
    },
    {
      "id": 8,
      "question": "Which protocol is used for sending email between mail servers?",
      "options": [
        "SMTP",
        "IMAP",
        "POP3",
        "HTTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SMTP (Simple Mail Transfer Protocol) sends emails between mail servers. IMAP and POP3 retrieve emails from mail servers. HTTP is used for web traffic.",
      "examTip": "SMTP = Send Mail To People; IMAP/POP3 = Retrieve emails."
    },
    {
      "id": 9,
      "question": "Which type of address is used by IPv4 for broadcasting messages to all devices in a local network?",
      "options": [
        "255.255.255.255",
        "192.168.0.1",
        "10.0.0.1",
        "127.0.0.1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "255.255.255.255 is the broadcast address for IPv4, used to send messages to all hosts on a local network. 192.168.0.1 and 10.0.0.1 are private IP addresses. 127.0.0.1 is the loopback address.",
      "examTip": "Broadcast = 255.255.255.255 (send to all on local network)."
    },
    {
      "id": 10,
      "question": "Which type of cable provides the HIGHEST data transmission speed and distance without electrical interference?",
      "options": [
        "Fiber optic cable",
        "Coaxial cable",
        "UTP cable",
        "STP cable"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Fiber optic cables use light for data transmission, offering high speeds and long distances with immunity to electromagnetic interference. Coaxial, UTP, and STP use electrical signals and are more prone to interference.",
      "examTip": "Fiber optic = Fast + Far + No EMI issues."
    },
    {
      "id": 11,
      "question": "Which port is used by SSH for secure remote access?",
      "options": [
        "22",
        "23",
        "80",
        "443"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH (Secure Shell) uses port 22 for secure remote access. Port 23 is for Telnet (unencrypted). Port 80 is for HTTP, and port 443 is for HTTPS.",
      "examTip": "SSH = Secure Shell = Port 22."
    },
    {
      "id": 12,
      "question": "Which device allows multiple users to share a single Internet connection by assigning private IP addresses internally?",
      "options": [
        "Router using NAT",
        "Switch",
        "Firewall",
        "Hub"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Routers use NAT (Network Address Translation) to allow multiple devices with private IPs to share a single public IP for internet access. Switches forward data within the LAN. Firewalls secure traffic, and hubs broadcast data to all devices.",
      "examTip": "NAT = Many private IPs → One public IP for Internet access."
    },
    {
      "id": 13,
      "question": "Which address is automatically assigned by a host when a DHCP server is unavailable?",
      "options": [
        "169.254.x.x",
        "192.168.x.x",
        "10.x.x.x",
        "172.16.x.x"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Addresses in the 169.254.x.x range are APIPA addresses, automatically assigned when DHCP fails. The other addresses are private IP ranges assigned either statically or dynamically by DHCP.",
      "examTip": "APIPA = 169.254.x.x = DHCP issue indicator."
    },
    {
      "id": 14,
      "question": "Which protocol resolves domain names to IP addresses?",
      "options": [
        "DNS",
        "DHCP",
        "NTP",
        "FTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DNS (Domain Name System) resolves domain names to IP addresses. DHCP assigns IP configurations. NTP synchronizes clocks, and FTP transfers files.",
      "examTip": "DNS = Phonebook of the Internet (names → numbers)."
    },
    {
      "id": 15,
      "question": "Which tool is used to test basic connectivity between two network devices?",
      "options": [
        "ping",
        "traceroute",
        "netstat",
        "arp"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 'ping' command tests basic connectivity between two devices using ICMP echo requests. 'traceroute' maps the path between devices. 'netstat' shows network connections. 'arp' shows IP-to-MAC address mappings.",
      "examTip": "Ping first—simple, fast, and effective for initial troubleshooting."
    },
    {
      "id": 16,
      "question": "Which private IP range is designated for Class A networks?",
      "options": [
        "10.0.0.0 – 10.255.255.255",
        "172.16.0.0 – 172.31.255.255",
        "192.168.0.0 – 192.168.255.255",
        "127.0.0.0 – 127.255.255.255"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 10.0.0.0 – 10.255.255.255 range is designated for Class A private networks. The 172.16.0.0 – 172.31.255.255 range is for Class B, and 192.168.0.0 – 192.168.255.255 is for Class C. The 127.0.0.0 range is for loopback addresses.",
      "examTip": "Private IP Ranges: Class A (10.x.x.x), Class B (172.16–31.x.x), Class C (192.168.x.x)."
    },
    {
      "id": 17,
      "question": "Which device forwards data based on IP addresses and determines the best path for data across networks?",
      "options": [
        "Router",
        "Switch",
        "Hub",
        "Access point"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Routers operate at Layer 3 of the OSI model, forwarding data based on IP addresses and determining the best path for traffic. Switches operate at Layer 2 using MAC addresses. Hubs broadcast data. Access points provide wireless connectivity.",
      "examTip": "Router = Network traffic manager between networks (Layer 3)."
    },
    {
      "id": 18,
      "question": "Which type of protocol is TCP known as due to its reliability and connection-oriented nature?",
      "options": [
        "Connection-oriented",
        "Connectionless",
        "Stateless",
        "Non-reliable"
      ],
      "correctAnswerIndex": 0,
      "explanation": "TCP (Transmission Control Protocol) is connection-oriented, providing reliable data transmission with error checking and correction. Connectionless protocols like UDP do not guarantee delivery. Stateless and non-reliable are not accurate descriptions of TCP.",
      "examTip": "TCP = Trustworthy Communication Protocol (Reliable, Ordered, and Error-checked)."
    },
    {
      "id": 19,
      "question": "Which port is used by DNS for resolving domain names?",
      "options": [
        "53",
        "25",
        "80",
        "443"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DNS uses port 53 to resolve domain names to IP addresses. Port 25 is for SMTP, port 80 is for HTTP, and port 443 is for HTTPS.",
      "examTip": "DNS = Port 53 (names to numbers)."
    },
    {
      "id": 20,
      "question": "Which addressing type allows communication between one sender and one receiver?",
      "options": [
        "Unicast",
        "Broadcast",
        "Multicast",
        "Anycast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Unicast communication is one-to-one between a sender and a receiver. Broadcast is one-to-all. Multicast is one-to-many (specific group). Anycast sends data to the nearest device in a group.",
      "examTip": "Unicast = Unique recipient (one-to-one)."
    },
    {
      "id": 21,
      "question": "Which device forwards data frames based on MAC addresses within a local network?",
      "options": [
        "Switch",
        "Router",
        "Firewall",
        "Access point"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A switch operates at Layer 2 of the OSI model, forwarding data frames based on MAC addresses. Routers forward packets based on IP addresses. Firewalls filter traffic based on security policies. Access points provide wireless connectivity but do not forward frames based on MAC addresses.",
      "examTip": "Switch = MAC address-based forwarding; think Layer 2 for LAN efficiency."
    },
    {
      "id": 22,
      "question": "Which port number is used by FTP for control commands?",
      "options": [
        "21",
        "20",
        "80",
        "443"
      ],
      "correctAnswerIndex": 0,
      "explanation": "FTP (File Transfer Protocol) uses port 21 for control commands and port 20 for data transfer. Port 80 is used by HTTP, and port 443 is used by HTTPS for secure web traffic.",
      "examTip": "FTP: Port 21 = Control, Port 20 = Data — easy two-step process."
    },
    {
      "id": 23,
      "question": "Which IP address class provides the MOST host addresses?",
      "options": [
        "Class A",
        "Class B",
        "Class C",
        "Class D"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Class A provides the largest number of host addresses with a range of 1.0.0.0 – 126.0.0.0. Class B offers fewer addresses (128.0.0.0 – 191.255.0.0), Class C even fewer (192.0.0.0 – 223.255.255.0), and Class D is used for multicast.",
      "examTip": "Class A = Abundant addresses; used for very large networks."
    },
    {
      "id": 24,
      "question": "Which wireless encryption protocol is now considered obsolete due to its vulnerabilities?",
      "options": [
        "WEP",
        "WPA2",
        "WPA3",
        "WPA"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WEP (Wired Equivalent Privacy) is obsolete due to major security vulnerabilities. WPA2 and WPA3 provide stronger encryption and improved security. WPA is more secure than WEP but less secure than WPA2 and WPA3.",
      "examTip": "Avoid WEP at all costs; always use WPA3 when available for the best security."
    },
    {
      "id": 25,
      "question": "Which networking tool is used to test and verify the integrity of network cables?",
      "options": [
        "Cable tester",
        "Toner probe",
        "Multimeter",
        "Loopback plug"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A cable tester checks the continuity and integrity of network cables. Toner probes locate cables. Multimeters measure electrical values but are not specialized for cable testing. Loopback plugs are used for testing ports, not cables.",
      "examTip": "Cable tester = Confirm cable integrity; essential for troubleshooting physical connections."
    },
    {
      "id": 26,
      "question": "Which type of address is assigned manually to a network device?",
      "options": [
        "Static IP address",
        "Dynamic IP address",
        "APIPA address",
        "Loopback address"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A static IP address is manually assigned and does not change unless modified by an administrator. Dynamic IP addresses are assigned by DHCP. APIPA addresses are self-assigned when DHCP fails. Loopback addresses (127.0.0.1) are used for internal testing.",
      "examTip": "Static = Stays the same; used for servers and network infrastructure."
    },
    {
      "id": 27,
      "question": "Which port does Telnet use by default?",
      "options": [
        "23",
        "22",
        "80",
        "3389"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Telnet uses port 23 for remote command-line access but lacks encryption. SSH uses port 22 for secure access. Port 80 is for HTTP, and port 3389 is for RDP (Remote Desktop Protocol).",
      "examTip": "Telnet = Port 23; insecure — always prefer SSH (Port 22) for secure connections."
    },
    {
      "id": 28,
      "question": "Which protocol retrieves email from a mail server while keeping the mail on the server by default?",
      "options": [
        "IMAP",
        "POP3",
        "SMTP",
        "HTTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "IMAP (Internet Message Access Protocol) allows emails to be retrieved and managed while leaving them on the server. POP3 downloads and removes emails from the server. SMTP is used for sending emails. HTTP is for web traffic.",
      "examTip": "IMAP = I Manage All Post (leaves mail on server); POP3 = downloads and deletes from server."
    },
    {
      "id": 29,
      "question": "Which type of network device broadcasts data to all connected devices regardless of destination?",
      "options": [
        "Hub",
        "Switch",
        "Router",
        "Firewall"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A hub broadcasts incoming data to all ports, creating unnecessary traffic. Switches send data only to the destination port. Routers forward data between networks, and firewalls filter traffic for security.",
      "examTip": "Hubs = Basic and inefficient; avoid in modern networks."
    },
    {
      "id": 30,
      "question": "Which wireless frequency provides better range but is more prone to interference?",
      "options": [
        "2.4GHz",
        "5GHz",
        "6GHz",
        "60GHz"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 2.4GHz frequency provides better range but is more susceptible to interference from devices like microwaves. The 5GHz and 6GHz bands offer higher speeds with shorter ranges. 60GHz is used for ultra-high-speed, short-range applications like WiGig.",
      "examTip": "2.4GHz = Greater range, more interference; 5GHz/6GHz = Faster, less range."
    },
    {
      "id": 31,
      "question": "Which command-line tool displays active network connections and listening ports on a host?",
      "options": [
        "netstat",
        "ping",
        "traceroute",
        "ifconfig"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'netstat' shows active network connections and listening ports. 'ping' checks basic connectivity. 'traceroute' maps the path packets take to reach a destination. 'ifconfig' displays network interface configurations in Linux.",
      "examTip": "netstat = Network statistics; essential for checking open connections."
    },
    {
      "id": 32,
      "question": "Which addressing method sends data to multiple recipients without broadcasting to the entire network?",
      "options": [
        "Multicast",
        "Broadcast",
        "Unicast",
        "Anycast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Multicast sends data to multiple specified recipients. Broadcast sends data to all devices in a network segment. Unicast is one-to-one communication. Anycast sends data to the nearest recipient in a group.",
      "examTip": "Multicast = Many, but not all — efficient group communication (e.g., streaming)."
    },
    {
      "id": 33,
      "question": "Which protocol uses port 443 for secure web traffic?",
      "options": [
        "HTTPS",
        "HTTP",
        "FTP",
        "SSH"
      ],
      "correctAnswerIndex": 0,
      "explanation": "HTTPS (Hypertext Transfer Protocol Secure) uses port 443 to encrypt web traffic. HTTP uses port 80 for unencrypted web traffic. FTP (port 20/21) handles file transfers. SSH (port 22) provides secure command-line access.",
      "examTip": "HTTPS = Secure web traffic = Port 443."
    },
    {
      "id": 34,
      "question": "Which device provides network segmentation by creating separate collision domains?",
      "options": [
        "Switch",
        "Hub",
        "Router",
        "Access point"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Switches create separate collision domains for each connected device, improving network efficiency. Hubs create a single collision domain, causing data collisions. Routers segment broadcast domains, and access points provide wireless connectivity.",
      "examTip": "Switches = Efficient LAN segmentation; each port = separate collision domain."
    },
    {
      "id": 35,
      "question": "Which port is used by Remote Desktop Protocol (RDP) for remote graphical access?",
      "options": [
        "3389",
        "22",
        "23",
        "443"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RDP uses port 3389 for remote graphical access to Windows systems. Port 22 is used by SSH. Port 23 is used by Telnet. Port 443 is used by HTTPS for secure web traffic.",
      "examTip": "RDP = Remote Desktop = Port 3389; ensure it's secured for remote access."
    },
    {
      "id": 36,
      "question": "Which type of network topology uses a single backbone cable, where failure of the backbone disrupts the entire network?",
      "options": [
        "Bus topology",
        "Star topology",
        "Ring topology",
        "Mesh topology"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Bus topology uses a single backbone cable to which all devices are connected. A failure in the backbone affects the entire network. Star topology uses a central device. Ring topology connects devices in a loop. Mesh topology provides full redundancy.",
      "examTip": "Bus = Backbone risk — simple but prone to single point of failure."
    },
    {
      "id": 37,
      "question": "Which IP address is commonly used as a default gateway in many home networks?",
      "options": [
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        "127.0.0.1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "192.168.1.1 is often used as the default gateway for home routers. 10.0.0.1 and 172.16.0.1 are also private IP addresses but less commonly used as default gateways in home networks. 127.0.0.1 is the loopback address for local testing.",
      "examTip": "192.168.1.1 = Default gateway in most home networking setups."
    },
    {
      "id": 38,
      "question": "Which protocol is commonly used for secure file transfers over SSH?",
      "options": [
        "SFTP",
        "FTP",
        "TFTP",
        "SCP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SFTP (SSH File Transfer Protocol) provides secure file transfers over SSH (port 22). FTP is unencrypted. TFTP is used for simple, unsecured file transfers. SCP also uses SSH but is primarily for direct file copying without full file management capabilities.",
      "examTip": "SFTP = Secure FTP via SSH; ideal for secure file transfers."
    },
    {
      "id": 39,
      "question": "Which wireless technology uses short-range radio signals to communicate between devices like smartphones and headsets?",
      "options": [
        "Bluetooth",
        "Wi-Fi",
        "NFC",
        "Zigbee"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Bluetooth uses short-range radio signals for communication between devices like smartphones and headsets. Wi-Fi provides longer-range wireless networking. NFC (Near Field Communication) works over very short distances for secure transactions. Zigbee is used for low-power, short-range communication in IoT applications.",
      "examTip": "Bluetooth = Personal device connections; short-range convenience."
    },
    {
      "id": 40,
      "question": "Which cable type is typically used for high-speed connections in data centers over short distances, such as connecting servers within the same rack?",
      "options": [
        "Direct attach copper (DAC)",
        "Single-mode fiber",
        "Multimode fiber",
        "Coaxial cable"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Direct attach copper (DAC) cables are used for high-speed connections over short distances (up to 10 meters) within data centers. Single-mode fiber supports long-distance connections. Multimode fiber supports shorter distances than single-mode but still more than DAC. Coaxial cables are not typically used for high-speed data center connections.",
      "examTip": "DAC = Short distance + High speed = Ideal for server-to-switch connections in data centers."
    },
    {
      "id": 41,
      "question": "Which type of network allows devices to communicate directly without a central access point or router?",
      "options": [
        "Ad hoc network",
        "Infrastructure network",
        "Mesh network",
        "Star network"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An ad hoc network allows devices to communicate directly with each other without a central device like a router or access point. Infrastructure networks rely on access points or routers. Mesh networks involve interconnected nodes, while star networks connect devices to a central hub.",
      "examTip": "Ad hoc = Direct device-to-device communication; no central controller required."
    },
    {
      "id": 42,
      "question": "Which connector type is commonly used with twisted-pair Ethernet cables?",
      "options": [
        "RJ45",
        "BNC",
        "LC",
        "SC"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RJ45 connectors are used with twisted-pair Ethernet cables. BNC connectors are for coaxial cables. LC and SC connectors are for fiber optic cables.",
      "examTip": "RJ45 = Standard Ethernet connector; used with CAT5e, CAT6 cables."
    },
    {
      "id": 43,
      "question": "Which IPv4 address range is reserved for private networks in Class B?",
      "options": [
        "172.16.0.0 – 172.31.255.255",
        "10.0.0.0 – 10.255.255.255",
        "192.168.0.0 – 192.168.255.255",
        "127.0.0.0 – 127.255.255.255"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 172.16.0.0 – 172.31.255.255 range is designated for Class B private networks. 10.0.0.0/8 is for Class A, 192.168.0.0/16 for Class C, and 127.0.0.0/8 is reserved for loopback addresses.",
      "examTip": "Class B private = 172.16.x.x – 172.31.x.x — ideal for medium-sized networks."
    },
    {
      "id": 44,
      "question": "Which protocol uses port 69 for simple file transfers without authentication?",
      "options": [
        "TFTP",
        "FTP",
        "SFTP",
        "HTTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "TFTP (Trivial File Transfer Protocol) uses port 69 for simple, unauthenticated file transfers. FTP uses ports 20/21 and supports authentication. SFTP provides secure file transfers over SSH. HTTP handles web traffic on port 80.",
      "examTip": "TFTP = Trivial transfers on port 69 — fast but insecure."
    },
    {
      "id": 45,
      "question": "Which device typically connects a LAN to a WAN, providing internet connectivity?",
      "options": [
        "Router",
        "Switch",
        "Firewall",
        "Hub"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Routers connect LANs to WANs, enabling internet access by forwarding packets between networks. Switches connect devices within a LAN. Firewalls provide network security, and hubs broadcast data without intelligent forwarding.",
      "examTip": "Router = Routes traffic between networks (LAN ↔ WAN)."
    },
    {
      "id": 46,
      "question": "Which tool would a technician use to identify the path taken by packets across a network?",
      "options": [
        "traceroute",
        "ping",
        "netstat",
        "ipconfig"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'traceroute' shows the path packets take to a destination, identifying each hop. 'ping' tests basic connectivity. 'netstat' displays network connections. 'ipconfig' shows IP configuration on Windows systems.",
      "examTip": "traceroute = Trace the route; useful for pinpointing routing issues."
    },
    {
      "id": 47,
      "question": "Which wireless encryption protocol is the MOST secure among the following options?",
      "options": [
        "WPA3",
        "WPA2",
        "WPA",
        "WEP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3 is the most secure, offering enhanced protection against brute-force attacks. WPA2 is still secure but lacks some of WPA3's advanced features. WPA is outdated, and WEP is insecure and obsolete.",
      "examTip": "Always choose WPA3 when available for maximum wireless security."
    },
    {
      "id": 48,
      "question": "Which port is used by SMTP for sending email?",
      "options": [
        "25",
        "110",
        "143",
        "53"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SMTP (Simple Mail Transfer Protocol) uses port 25 for sending emails. Port 110 is for POP3, port 143 for IMAP, and port 53 for DNS.",
      "examTip": "SMTP = Send Mail Through Port 25 — remember '25 to send away.'"
    },
    {
      "id": 49,
      "question": "Which layer of the OSI model provides logical addressing and path selection?",
      "options": [
        "Network layer",
        "Data link layer",
        "Transport layer",
        "Session layer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The Network layer (Layer 3) handles logical addressing (IP addresses) and routing. The Data link layer manages physical addressing (MAC addresses). The Transport layer ensures reliable data transfer. The Session layer manages communication sessions.",
      "examTip": "Network layer = IP addresses + Routing decisions."
    },
    {
      "id": 50,
      "question": "Which command is used in Windows to test if a host is reachable over the network?",
      "options": [
        "ping",
        "ipconfig",
        "netstat",
        "nslookup"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'ping' sends ICMP echo requests to check connectivity. 'ipconfig' shows IP settings. 'netstat' displays network connections. 'nslookup' checks DNS resolution.",
      "examTip": "ping = First troubleshooting step to confirm connectivity."
    },
    {
      "id": 51,
      "question": "Which type of network topology connects each device to a central hub or switch?",
      "options": [
        "Star topology",
        "Mesh topology",
        "Bus topology",
        "Ring topology"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Star topology connects each device to a central hub or switch. Mesh topology connects every device to every other device. Bus topology uses a single backbone cable. Ring topology connects devices in a loop.",
      "examTip": "Star topology = Popular due to easy troubleshooting; central point is key."
    },
    {
      "id": 52,
      "question": "Which addressing type in IPv6 allows one device to communicate with multiple devices in a group?",
      "options": [
        "Multicast",
        "Unicast",
        "Anycast",
        "Broadcast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Multicast in IPv6 sends data to multiple devices in a group. Unicast is one-to-one. Anycast sends data to the nearest node in a group. IPv6 does not use broadcast addressing like IPv4.",
      "examTip": "IPv6 = Multicast preferred; no broadcast overhead as in IPv4."
    },
    {
      "id": 53,
      "question": "Which technology is used to translate private IP addresses into a single public IP address for internet access?",
      "options": [
        "NAT",
        "DNS",
        "DHCP",
        "VPN"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NAT (Network Address Translation) translates private IPs to a public IP, enabling internet access. DNS resolves domain names. DHCP assigns IP addresses. VPN provides secure network connections over public networks.",
      "examTip": "NAT = Multiple private → Single public IP; essential for IPv4 conservation."
    },
    {
      "id": 54,
      "question": "Which wireless standard supports speeds up to 54 Mbps in the 5GHz frequency band?",
      "options": [
        "802.11a",
        "802.11b",
        "802.11g",
        "802.11n"
      ],
      "correctAnswerIndex": 0,
      "explanation": "802.11a operates at 5GHz with speeds up to 54 Mbps. 802.11b (11 Mbps) and 802.11g (54 Mbps) operate at 2.4GHz. 802.11n supports both 2.4GHz and 5GHz with higher speeds (up to 600 Mbps).",
      "examTip": "802.11a = Early 5GHz standard, reduced interference but limited range."
    },
    {
      "id": 55,
      "question": "Which device provides centralized authentication for users accessing network resources?",
      "options": [
        "RADIUS server",
        "Router",
        "Switch",
        "Hub"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RADIUS (Remote Authentication Dial-in User Service) servers provide centralized authentication. Routers direct network traffic. Switches connect devices within a LAN. Hubs broadcast data without intelligent forwarding.",
      "examTip": "RADIUS = Remote Authentication — user access control from a central point."
    },
    {
      "id": 56,
      "question": "Which protocol uses port 3389 to provide remote graphical access to Windows systems?",
      "options": [
        "RDP",
        "SSH",
        "Telnet",
        "VNC"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RDP (Remote Desktop Protocol) uses port 3389 for remote graphical access. SSH uses port 22 for secure command-line access. Telnet provides insecure CLI access. VNC provides cross-platform graphical remote access but uses port 5900.",
      "examTip": "RDP = Remote Desktop for Windows = Port 3389."
    },
    {
      "id": 57,
      "question": "Which tool would be used to detect and analyze wireless networks, including signal strength and channel usage?",
      "options": [
        "Wi-Fi analyzer",
        "Cable tester",
        "Toner probe",
        "Protocol analyzer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A Wi-Fi analyzer detects and analyzes wireless networks, checking signal strength and channel overlap. Cable testers check cable integrity. Toner probes locate cables. Protocol analyzers capture and analyze network traffic.",
      "examTip": "Wi-Fi analyzer = Optimize wireless performance by identifying interference and coverage gaps."
    },
    {
      "id": 58,
      "question": "Which protocol is responsible for securely accessing web pages over the internet?",
      "options": [
        "HTTPS",
        "HTTP",
        "FTP",
        "SMTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "HTTPS (Hypertext Transfer Protocol Secure) encrypts web traffic using SSL/TLS over port 443. HTTP is unencrypted. FTP transfers files. SMTP sends emails.",
      "examTip": "HTTPS = Secure web browsing; ensures confidentiality of transmitted data."
    },
    {
      "id": 59,
      "question": "Which addressing method allows devices to send data to a single nearest recipient from a group of receivers?",
      "options": [
        "Anycast",
        "Unicast",
        "Multicast",
        "Broadcast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Anycast sends data to the nearest device in a group based on routing metrics. Unicast sends data to one recipient. Multicast targets multiple specified recipients. Broadcast sends data to all devices in a network segment.",
      "examTip": "Anycast = Nearest responder; efficient for global services like DNS."
    },
    {
      "id": 60,
      "question": "Which protocol is used for secure, encrypted remote command-line access?",
      "options": [
        "SSH",
        "Telnet",
        "FTP",
        "RDP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH (Secure Shell) provides encrypted remote command-line access over port 22. Telnet offers similar functionality but is insecure. FTP transfers files. RDP provides graphical remote access.",
      "examTip": "SSH = Secure remote CLI access; always preferred over Telnet."
    },
    {
      "id": 61,
      "question": "Which tool is used to test the continuity of network cables by sending signals through each wire?",
      "options": [
        "Cable tester",
        "Toner probe",
        "Loopback plug",
        "Multimeter"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A cable tester checks the continuity and proper wiring of network cables. Toner probes locate cables, loopback plugs test network ports, and multimeters measure electrical properties but aren’t specific to networking cables.",
      "examTip": "Cable tester = Essential for verifying network cable integrity."
    },
    {
      "id": 62,
      "question": "Which protocol uses port 110 to retrieve emails from a mail server?",
      "options": [
        "POP3",
        "IMAP",
        "SMTP",
        "FTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "POP3 (Post Office Protocol v3) uses port 110 to retrieve emails, typically downloading them from the server. IMAP uses port 143 and keeps emails on the server. SMTP (port 25) is for sending emails, and FTP handles file transfers.",
      "examTip": "POP3 = Port 110 = Downloads emails locally by default."
    },
    {
      "id": 63,
      "question": "Which type of IP address is automatically assigned when a DHCP server is unavailable, typically in the 169.254.x.x range?",
      "options": [
        "APIPA",
        "Static",
        "Loopback",
        "Global unicast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "APIPA (Automatic Private IP Addressing) assigns 169.254.x.x addresses when DHCP is unavailable. Static addresses are manually configured. Loopback addresses (127.0.0.1) test local host communication. Global unicast addresses are routable IPv6 addresses.",
      "examTip": "169.254.x.x = APIPA = Check DHCP functionality when you see this."
    },
    {
      "id": 64,
      "question": "Which wireless frequency band generally provides faster speeds but shorter range?",
      "options": [
        "5GHz",
        "2.4GHz",
        "900MHz",
        "60GHz"
      ],
      "correctAnswerIndex": 0,
      "explanation": "5GHz provides faster speeds with less interference but has a shorter range than 2.4GHz. 2.4GHz has greater range but more interference. 900MHz is used in low-power applications, and 60GHz (WiGig) supports ultra-fast, short-range communications.",
      "examTip": "5GHz = Speed-focused, 2.4GHz = Coverage-focused."
    },
    {
      "id": 65,
      "question": "Which command displays the IP configuration of a device on a Windows operating system?",
      "options": [
        "ipconfig",
        "ping",
        "tracert",
        "nslookup"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'ipconfig' shows IP, subnet, and gateway information. 'ping' tests connectivity. 'tracert' shows packet paths. 'nslookup' checks DNS resolution.",
      "examTip": "ipconfig = Your first step for verifying IP settings on Windows."
    },
    {
      "id": 66,
      "question": "Which port is used by the Secure Shell (SSH) protocol?",
      "options": [
        "22",
        "23",
        "80",
        "443"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH uses port 22 for encrypted command-line access. Telnet (port 23) provides unencrypted access. Port 80 is for HTTP, and port 443 is for HTTPS.",
      "examTip": "SSH = Secure CLI access = Port 22; secure alternative to Telnet."
    },
    {
      "id": 67,
      "question": "Which device filters traffic based on preconfigured security rules to protect networks from unauthorized access?",
      "options": [
        "Firewall",
        "Switch",
        "Router",
        "Access point"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A firewall filters traffic using security rules to block unauthorized access. Switches forward data within a LAN. Routers connect different networks, and access points provide wireless connectivity.",
      "examTip": "Firewall = Network gatekeeper; first line of defense in securing networks."
    },
    {
      "id": 68,
      "question": "Which protocol translates human-friendly domain names into IP addresses?",
      "options": [
        "DNS",
        "DHCP",
        "NAT",
        "SNMP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DNS (Domain Name System) resolves domain names to IP addresses. DHCP assigns IP configurations. NAT translates private to public IPs. SNMP monitors network devices.",
      "examTip": "DNS = Internet's phonebook; critical for web browsing."
    },
    {
      "id": 69,
      "question": "Which network topology connects each device to every other device for maximum redundancy?",
      "options": [
        "Mesh topology",
        "Star topology",
        "Bus topology",
        "Ring topology"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Mesh topology connects each device to every other, providing high redundancy and fault tolerance. Star topology relies on a central device. Bus topology uses a single cable. Ring topology connects devices in a loop.",
      "examTip": "Mesh = Maximum fault tolerance; ideal for critical networks."
    },
    {
      "id": 70,
      "question": "Which layer of the OSI model is responsible for data encryption and translation?",
      "options": [
        "Presentation layer",
        "Session layer",
        "Network layer",
        "Application layer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The Presentation layer (Layer 6) handles data encryption, translation, and compression. The Session layer manages sessions. The Network layer handles IP addressing and routing. The Application layer provides user services.",
      "examTip": "Presentation = Prepares data for users; handles encryption and formatting."
    },
    {
      "id": 71,
      "question": "Which type of addressing in IPv6 is used to communicate with all nodes on the same network segment?",
      "options": [
        "Multicast",
        "Unicast",
        "Anycast",
        "Link-local"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Multicast allows communication with multiple nodes on the same segment. Unicast is one-to-one. Anycast sends to the nearest node. Link-local addresses are for local link communication but not necessarily to all nodes.",
      "examTip": "IPv6 = Multicast preferred over broadcast for efficient group communication."
    },
    {
      "id": 72,
      "question": "Which port does HTTPS use for secure web communication?",
      "options": [
        "443",
        "80",
        "21",
        "23"
      ],
      "correctAnswerIndex": 0,
      "explanation": "HTTPS uses port 443 for secure web traffic. HTTP uses port 80, FTP uses port 21, and Telnet uses port 23.",
      "examTip": "HTTPS = Secure web access = Port 443 (encrypts traffic via SSL/TLS)."
    },
    {
      "id": 73,
      "question": "Which protocol provides time synchronization between network devices?",
      "options": [
        "NTP",
        "SNMP",
        "DNS",
        "TFTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NTP (Network Time Protocol) synchronizes time across devices. SNMP monitors network devices. DNS resolves domain names. TFTP transfers files without authentication.",
      "examTip": "NTP = Network clock synchronization — critical for logs and security events."
    },
    {
      "id": 74,
      "question": "Which protocol is responsible for secure file transfers over SSH, using port 22?",
      "options": [
        "SFTP",
        "FTP",
        "TFTP",
        "SCP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SFTP (SSH File Transfer Protocol) uses port 22 for secure file transfers over SSH. FTP is unencrypted. TFTP provides basic, unsecured file transfers. SCP also uses SSH but lacks full file management capabilities.",
      "examTip": "SFTP = Secure FTP over SSH — preferred for secure file transfer with management features."
    },
    {
      "id": 75,
      "question": "Which protocol uses port 161 for network device management and monitoring?",
      "options": [
        "SNMP",
        "NTP",
        "DNS",
        "FTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SNMP (Simple Network Management Protocol) uses port 161 for managing and monitoring network devices. NTP synchronizes time. DNS resolves hostnames. FTP handles file transfers.",
      "examTip": "SNMP = Monitor device performance; use SNMPv3 for encryption and authentication."
    },
    {
      "id": 76,
      "question": "Which type of cable provides the highest resistance to electromagnetic interference (EMI)?",
      "options": [
        "Fiber optic cable",
        "Coaxial cable",
        "STP cable",
        "UTP cable"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Fiber optic cables are immune to EMI as they use light for data transmission. Coaxial cables provide moderate EMI resistance. STP offers more EMI protection than UTP, but both are still electrical and susceptible to interference.",
      "examTip": "Fiber optic = EMI-proof; best for environments with high electrical noise."
    },
    {
      "id": 77,
      "question": "Which connector type is commonly used for single-mode fiber optic cables and features a push-pull mechanism?",
      "options": [
        "LC",
        "ST",
        "SC",
        "BNC"
      ],
      "correctAnswerIndex": 0,
      "explanation": "LC (Local Connector) connectors are commonly used with single-mode fiber and feature a push-pull mechanism. ST uses a twist-lock, SC uses push-pull but is larger, and BNC is used for coaxial cables.",
      "examTip": "LC = Little Connector; preferred in modern fiber installations due to compact size."
    },
    {
      "id": 78,
      "question": "Which addressing method in networking sends data to all devices on a network?",
      "options": [
        "Broadcast",
        "Unicast",
        "Multicast",
        "Anycast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Broadcast sends data to all devices in a network segment. Unicast is one-to-one. Multicast is one-to-many (specific group). Anycast sends data to the nearest node in a group.",
      "examTip": "Broadcast = One-to-all; reduce with VLANs to avoid network congestion."
    },
    {
      "id": 79,
      "question": "Which network component assigns IP addresses dynamically to devices on a network?",
      "options": [
        "DHCP server",
        "DNS server",
        "Router with NAT",
        "Firewall"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A DHCP (Dynamic Host Configuration Protocol) server assigns IP addresses and network configurations dynamically. DNS servers resolve domain names. Routers with NAT provide internet access. Firewalls filter traffic for security.",
      "examTip": "DHCP = Automatic IP assignment; reduces manual configuration errors."
    },
    {
      "id": 80,
      "question": "Which wireless standard introduced MU-MIMO (Multi-User Multiple Input Multiple Output) technology for better multi-user performance?",
      "options": [
        "802.11ac",
        "802.11n",
        "802.11g",
        "802.11a"
      ],
      "correctAnswerIndex": 0,
      "explanation": "802.11ac introduced MU-MIMO, allowing simultaneous data streams to multiple devices. 802.11n supports MIMO (single-user). 802.11g and 802.11a do not support MIMO technologies.",
      "examTip": "802.11ac = Better performance in dense environments with MU-MIMO support."
    },
    {
      "id": 81,
      "question": "Which protocol uses port 53 to resolve hostnames to IP addresses?",
      "options": [
        "DNS",
        "DHCP",
        "FTP",
        "NTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DNS (Domain Name System) uses port 53 to resolve hostnames to IP addresses. DHCP assigns IP configurations. FTP (ports 20/21) handles file transfers. NTP (port 123) synchronizes network device clocks.",
      "examTip": "DNS = Port 53. Think of '5' and '3' as D and S for Domain System."
    },
    {
      "id": 82,
      "question": "Which device amplifies and regenerates network signals to extend transmission distance?",
      "options": [
        "Repeater",
        "Switch",
        "Router",
        "Hub"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A repeater regenerates and amplifies network signals to extend transmission distance. Switches direct traffic using MAC addresses. Routers forward traffic between networks. Hubs broadcast data to all ports without amplification.",
      "examTip": "Repeater = Repeat and boost signal for longer distances."
    },
    {
      "id": 83,
      "question": "Which port number is used by IMAP for retrieving emails while keeping them on the server?",
      "options": [
        "143",
        "110",
        "25",
        "443"
      ],
      "correctAnswerIndex": 0,
      "explanation": "IMAP (Internet Message Access Protocol) uses port 143 and allows email retrieval while leaving them on the server. POP3 uses port 110, SMTP uses port 25, and HTTPS uses port 443.",
      "examTip": "IMAP = Port 143 = Ideal for accessing mail from multiple devices."
    },
    {
      "id": 84,
      "question": "Which wireless technology allows short-range communication for contactless payments?",
      "options": [
        "NFC",
        "Bluetooth",
        "Zigbee",
        "Wi-Fi"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NFC (Near Field Communication) allows secure, short-range communication, commonly used for contactless payments. Bluetooth supports longer-range wireless connections. Zigbee is used in IoT devices. Wi-Fi provides longer-range internet access.",
      "examTip": "NFC = Near and Fast Communication; perfect for contactless transactions."
    },
    {
      "id": 85,
      "question": "Which address is used by IPv4 for broadcast communication within a local network?",
      "options": [
        "255.255.255.255",
        "192.168.1.1",
        "10.0.0.1",
        "127.0.0.1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The IPv4 address 255.255.255.255 is the broadcast address for communication to all hosts within a local network. 192.168.1.1 and 10.0.0.1 are private IPs. 127.0.0.1 is the loopback address for local testing.",
      "examTip": "Broadcast = 255.255.255.255. Think 'all 255s' = 'all devices.'"
    },
    {
      "id": 86,
      "question": "Which OSI layer ensures reliable data transfer using acknowledgments and flow control?",
      "options": [
        "Transport layer",
        "Network layer",
        "Data link layer",
        "Presentation layer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The Transport layer (Layer 4) ensures reliable data delivery through acknowledgments and flow control (using protocols like TCP). The Network layer handles routing. The Data link layer deals with physical addressing. The Presentation layer formats and encrypts data.",
      "examTip": "Transport = Trustworthy delivery with TCP ensuring data arrives intact."
    },
    {
      "id": 87,
      "question": "Which device connects different networks and determines the best path for data transmission?",
      "options": [
        "Router",
        "Switch",
        "Hub",
        "Repeater"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Routers connect different networks and determine the optimal path for data based on IP addresses. Switches connect devices within a LAN. Hubs broadcast to all devices. Repeaters boost signals but do not route traffic.",
      "examTip": "Router = Roadmap of the network; directs traffic where it needs to go."
    },
    {
      "id": 88,
      "question": "Which Wi-Fi standard supports both 2.4GHz and 5GHz frequencies and speeds up to 600 Mbps?",
      "options": [
        "802.11n",
        "802.11a",
        "802.11b",
        "802.11g"
      ],
      "correctAnswerIndex": 0,
      "explanation": "802.11n supports both 2.4GHz and 5GHz frequencies with speeds up to 600 Mbps. 802.11a operates at 5GHz (54 Mbps), 802.11b at 2.4GHz (11 Mbps), and 802.11g at 2.4GHz (54 Mbps).",
      "examTip": "802.11n = 'n' for 'new' standard that brought dual-band support."
    },
    {
      "id": 89,
      "question": "Which tool is used to check if a DNS server is properly resolving domain names to IP addresses?",
      "options": [
        "nslookup",
        "ping",
        "ipconfig",
        "netstat"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'nslookup' queries DNS servers to test name resolution. 'ping' checks network connectivity. 'ipconfig' shows IP configurations. 'netstat' shows network connections.",
      "examTip": "nslookup = Name System Lookup; first step when domain resolution fails."
    },
    {
      "id": 90,
      "question": "Which addressing method allows a device to send traffic to the nearest node in a group of potential receivers?",
      "options": [
        "Anycast",
        "Unicast",
        "Multicast",
        "Broadcast"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Anycast sends data to the nearest node in a group based on routing metrics. Unicast is one-to-one. Multicast targets multiple devices. Broadcast sends to all devices in a network segment.",
      "examTip": "Anycast = 'Any closest host' — efficient for global services like DNS."
    },
    {
      "id": 91,
      "question": "Which wireless technology supports device pairing for peripherals like keyboards and headsets?",
      "options": [
        "Bluetooth",
        "Wi-Fi",
        "Zigbee",
        "NFC"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Bluetooth provides short-range wireless communication for peripheral device pairing. Wi-Fi supports network connectivity. Zigbee is used in IoT for sensor communications. NFC enables very short-range contactless data exchanges.",
      "examTip": "Bluetooth = Best for personal device pairing (headphones, keyboards)."
    },
    {
      "id": 92,
      "question": "Which command on Linux systems displays or configures network interfaces?",
      "options": [
        "ifconfig",
        "ping",
        "traceroute",
        "netstat"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'ifconfig' shows and configures network interfaces. 'ping' tests connectivity. 'traceroute' tracks packet paths. 'netstat' displays network connections and ports.",
      "examTip": "ifconfig = Interface config; being replaced by 'ip addr' in modern Linux distributions."
    },
    {
      "id": 93,
      "question": "Which type of IP address is assigned permanently to a device and does not change over time?",
      "options": [
        "Static IP address",
        "Dynamic IP address",
        "APIPA address",
        "Loopback address"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A static IP address is manually configured and remains constant. Dynamic IP addresses are assigned via DHCP. APIPA addresses (169.254.x.x) are self-assigned when DHCP fails. Loopback addresses (127.0.0.1) are used for internal testing.",
      "examTip": "Static = Stays the same; used for servers and network hardware."
    },
    {
      "id": 94,
      "question": "Which device provides Wi-Fi connectivity to wireless clients within a network?",
      "options": [
        "Access point",
        "Router",
        "Switch",
        "Firewall"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An access point (AP) provides wireless network access to devices. Routers direct traffic between networks. Switches forward traffic in a wired LAN. Firewalls control traffic based on security rules.",
      "examTip": "Access point = Airwaves access; central for Wi-Fi networks."
    },
    {
      "id": 95,
      "question": "Which protocol encrypts network traffic at the IP layer, often used for VPN implementations?",
      "options": [
        "IPSec",
        "TLS",
        "SSH",
        "GRE"
      ],
      "correctAnswerIndex": 0,
      "explanation": "IPSec encrypts data at the IP layer, commonly used in VPNs. TLS secures application traffic. SSH encrypts remote access sessions. GRE provides tunneling without encryption unless paired with IPSec.",
      "examTip": "IPSec = Secure at the IP level; core for VPN security."
    },
    {
      "id": 96,
      "question": "Which type of network device uses MAC addresses to forward frames within a local network?",
      "options": [
        "Switch",
        "Router",
        "Hub",
        "Repeater"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Switches forward frames using MAC addresses, operating at Layer 2 of the OSI model. Routers use IP addresses (Layer 3). Hubs broadcast to all ports. Repeaters amplify signals but don’t direct traffic.",
      "examTip": "Switch = MAC manager; optimizes traffic flow in LANs."
    },
    {
      "id": 97,
      "question": "Which protocol is used for sending emails between mail servers?",
      "options": [
        "SMTP",
        "IMAP",
        "POP3",
        "FTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SMTP (Simple Mail Transfer Protocol) sends emails between mail servers. IMAP retrieves emails while keeping them on the server. POP3 downloads and deletes emails from the server. FTP transfers files.",
      "examTip": "SMTP = Send Mail To People; think '25' for its port number."
    },
    {
      "id": 98,
      "question": "Which wireless standard provides the fastest speeds in the 5GHz band?",
      "options": [
        "802.11ac",
        "802.11n",
        "802.11g",
        "802.11a"
      ],
      "correctAnswerIndex": 0,
      "explanation": "802.11ac supports high-speed data rates in the 5GHz band with MU-MIMO support. 802.11n supports both 2.4GHz and 5GHz but at lower speeds. 802.11g and 802.11a offer 54 Mbps.",
      "examTip": "802.11ac = 'ac'celerated speed on 5GHz; ideal for modern high-speed networks."
    },
    {
      "id": 99,
      "question": "Which type of connector is commonly used for coaxial cables in legacy Ethernet networks?",
      "options": [
        "BNC",
        "RJ45",
        "LC",
        "SC"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BNC connectors are used with coaxial cables in older Ethernet networks. RJ45 is for Ethernet over twisted-pair cables. LC and SC are for fiber optic connections.",
      "examTip": "BNC = Bayonet-style; mostly legacy but still found in specialized applications."
    },
    {
      "id": 100,
      "question": "Which command can be used to display the routing table on a Windows machine?",
      "options": [
        "route print",
        "ipconfig",
        "netstat -r",
        "tracert"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'route print' displays the routing table on Windows. 'ipconfig' shows IP configurations. 'netstat -r' also shows the routing table but is less commonly used. 'tracert' traces the path packets take to a destination.",
      "examTip": "route print = Routing path preview; essential for diagnosing routing issues."
    }
  ]
});
