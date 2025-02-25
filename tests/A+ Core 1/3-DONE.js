db.tests.insertOne({
  "category": "aplus",
  "testId": 3,
  "testName": "A+ Core 1 Practice Test #3 (Easy)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "Which TCP port is used by the File Transfer Protocol (FTP) for control connections?",
      "options": [
        "Port 20",
        "Port 21",
        "Port 22",
        "Port 23"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Port 21 is used by FTP for control signals, while port 20 is for data transfer. Port 22 is for SSH, and Port 23 is for Telnet. Exam tip: FTP uses ports 20 and 21 - control is 21.",
      "examTip": "FTP uses two ports: 21 for control and 20 for data. Remember 21 for the control channel."
    },
    {
      "id": 2,
      "question": "A user reports their laptop battery is not charging. What is the FIRST step a technician should typically take in troubleshooting?",
      "options": [
        "Replace the laptop battery immediately",
        "Check if the AC adapter is properly connected and working",
        "Reinstall the operating system",
        "Update the BIOS firmware"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The first step should be to check the most basic and common issue: ensuring the AC adapter is properly connected to both the laptop and the power outlet, and verifying it's functioning. Replacing the battery or OS are drastic steps too early in troubleshooting. BIOS updates are less likely the initial cause. Exam tip: Start with the simplest solutions first.",
      "examTip": "Always start troubleshooting with the basics: is it plugged in? Is the power source working? Check the AC adapter first for charging issues."
    },
    {
      "id": 3,
      "question": "Which wireless standard operates on both the 2.4 GHz and 5 GHz frequency bands?",
      "options": [
        "802.11b",
        "802.11g",
        "802.11n",
        "802.11a"
      ],
      "correctAnswerIndex": 2,
      "explanation": "802.11n is the wireless standard that can operate on both 2.4 GHz and 5 GHz bands, offering more flexibility. 802.11b and 802.11g operate only on 2.4 GHz, and 802.11a primarily on 5 GHz. Exam tip: 802.11n and newer can be dual-band.",
      "examTip": "802.11n was a big step because it introduced dual-band capability, using both 2.4 GHz and 5 GHz."
    },
    {
      "id": 4,
      "question": "Which type of network topology connects each network device to a central hub?",
      "options": [
        "Bus",
        "Ring",
        "Star",
        "Mesh"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Star topology connects each device to a central hub or switch. Bus topology uses a single cable, Ring connects in a circle, and Mesh connects devices directly to many others. Exam tip: Star topology = central hub.",
      "examTip": "Star topology is like spokes on a wheel – all devices connect to a central point, the hub or switch."
    },
    {
      "id": 5,
      "question": "A user is unable to access websites by name but can access them by IP address. What is the MOST likely service that is malfunctioning?",
      "options": [
        "DHCP (Dynamic Host Configuration Protocol)",
        "DNS (Domain Name System)",
        "SMTP (Simple Mail Transfer Protocol)",
        "HTTP (Hypertext Transfer Protocol)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "DNS (Domain Name System) is responsible for translating domain names (like websites names) into IP addresses. If name resolution fails but IP access works, DNS is the likely culprit. DHCP assigns IP addresses, SMTP is for email, and HTTP is for web traffic itself. Exam tip: DNS = name to IP translation.",
      "examTip": "DNS is the phonebook of the internet. If you can't reach websites by name but IPs work, DNS is the problem."
    },
    {
      "id": 6,
      "question": "Which of the following is a characteristic of User Datagram Protocol (UDP)?",
      "options": [
        "Connection-oriented",
        "Reliable data delivery",
        "Connectionless",
        "Guaranteed packet sequencing"
      ],
      "correctAnswerIndex": 2,
      "explanation": "UDP (User Datagram Protocol) is connectionless, meaning it doesn't establish a connection before sending data. TCP is connection-oriented and provides reliability and sequencing, which UDP lacks in favor of speed. Exam tip: UDP = connectionless, faster but less reliable.",
      "examTip": "UDP is fast and connectionless, like sending a postcard. TCP is more reliable, like sending a registered letter."
    },
    {
      "id": 7,
      "question": "Which type of memory module is commonly used in desktop computers?",
      "options": [
        "SODIMM",
        "DIMM",
        "SIMM",
        "Flash Memory"
      ],
      "correctAnswerIndex": 1,
      "explanation": "DIMM (Dual In-line Memory Module) is the standard memory module for desktop computers. SODIMM is for laptops, SIMM is older, and Flash Memory is a type of non-volatile storage. Exam tip: DIMM = desktop memory.",
      "examTip": "DIMMs are the standard-sized memory sticks for desktop PCs. SODIMMs are the smaller laptop version."
    },
    {
      "id": 8,
      "question": "What is the standard port number for HTTPS (Hypertext Transfer Protocol Secure)?",
      "options": [
        "Port 21",
        "Port 25",
        "Port 80",
        "Port 443"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Port 443 is the standard port for secure web traffic using HTTPS. Port 21 is for FTP, Port 25 for SMTP, and Port 80 for unencrypted HTTP. Exam tip: HTTPS uses port 443 for secure web.",
      "examTip": "HTTPS (secure HTTP) always uses port 443. It's the secure version of web traffic."
    },
    {
      "id": 9,
      "question": "Which of the following is a common type of video connector found on older monitors and computers?",
      "options": [
        "HDMI",
        "DisplayPort",
        "VGA",
        "DVI"
      ],
      "correctAnswerIndex": 2,
      "explanation": "VGA (Video Graphics Array) is a common analog video connector found on older monitors and computers. HDMI, DisplayPort, and DVI are newer, digital video connectors. Exam tip: VGA = older, analog video.",
      "examTip": "VGA is the older, trapezoid-shaped video connector. It's analog, unlike the digital HDMI, DisplayPort, and DVI."
    },
    {
      "id": 10,
      "question": "What is the primary function of a 'network switch' in a local network?",
      "options": [
        "To route traffic between different networks",
        "To provide wireless internet access",
        "To connect multiple devices within the same network",
        "To act as a firewall"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A network switch primarily connects multiple devices within the same local network, enabling communication between them. Routers connect different networks, access points provide Wi-Fi, and firewalls provide security. Exam tip: Switch = local network device connector.",
      "examTip": "Switches are for connecting devices on the same local network – like computers and printers in your office."
    },
    {
      "id": 11,
      "question": "Which tool is BEST used to test the continuity of a network cable?",
      "options": [
        "Toner probe",
        "Crimper",
        "Cable tester",
        "Punchdown tool"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A cable tester is specifically designed to test the continuity and wiring of network cables, verifying if each wire is properly connected. Toner probes trace cables, crimpers attach connectors, and punchdown tools terminate wires in panels. Exam tip: Cable tester = cable continuity check.",
      "examTip": "Use a cable tester to make sure your network cables are wired correctly and have continuity – that the signal can travel through them."
    },
    {
      "id": 12,
      "question": "What is the purpose of a 'print server'?",
      "options": [
        "To manage network cables",
        "To store print jobs and manage printer access for multiple users",
        "To convert digital documents to paper",
        "To scan documents"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A print server manages print jobs and printer access for multiple users on a network, queuing print requests and managing printer availability. It's not for cable management, document printing itself, or scanning. Exam tip: Print server = printer management for networks.",
      "examTip": "A print server is like a traffic controller for printers. It manages print jobs for multiple users on a network."
    },
    {
      "id": 13,
      "question": "Which of the following is a common characteristic of Solid State Drives (SSDs) compared to Hard Disk Drives (HDDs)?",
      "options": [
        "Lower cost per gigabyte",
        "Mechanical moving parts",
        "Faster read and write speeds",
        "Higher storage capacity for the same price"
      ],
      "correctAnswerIndex": 2,
      "explanation": "SSDs are known for faster read and write speeds compared to HDDs, due to the absence of mechanical moving parts. HDDs are typically lower cost per gigabyte and can offer higher capacity for the same price, but are slower and more prone to mechanical failure. Exam tip: SSD = faster, HDD = cheaper/larger capacity.",
      "examTip": "SSDs are faster and more durable than HDDs, but HDDs are generally cheaper for larger storage capacities."
    },
    {
      "id": 14,
      "question": "Which of these IP addresses is considered a private IP address?",
      "options": [
        "192.168.1.1",
        "172.10.0.1",
        "10.1.1.1",
        "169.254.1.1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "192.168.1.1 is a private IP address range (192.168.0.0 - 192.168.255.255). 172.10.0.1 and 10.1.1.1 could be, depending on subnetting, but are not definitively private ranges by default in the same way as 192.168.x.x. 169.254.x.x is APIPA (Automatic Private IP Addressing), also private but used differently. Exam tip: 192.168.x.x, 10.x.x.x, 172.16-31.x.x are private ranges.",
      "examTip": "Memorize the private IP address ranges: 192.168.x.x, 10.x.x.x, and 172.16.x.x to 172.31.x.x. 192.168.1.1 is a very common private IP."
    },
    {
      "id": 15,
      "question": "What is the function of a 'DHCP server' on a network?",
      "options": [
        "To translate domain names to IP addresses",
        "To assign IP addresses automatically to devices",
        "To provide secure web browsing",
        "To manage email traffic"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DHCP (Dynamic Host Configuration Protocol) server automatically assigns IP addresses and other network configuration parameters to devices on a network. DNS translates names to IPs, HTTPS is for secure web browsing, and SMTP/POP3/IMAP are for email. Exam tip: DHCP = automatic IP assignment.",
      "examTip": "DHCP is like an IP address dispenser. It automatically hands out IP addresses to devices on your network so you don't have to set them manually."
    },
    {
      "id": 16,
      "question": "Which type of cable is used for connecting a cable modem to the wall outlet?",
      "options": [
        "Ethernet cable",
        "Fiber optic cable",
        "Coaxial cable",
        "Telephone cable (RJ11)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Coaxial cable is used to connect cable modems to the cable TV wall outlet. Ethernet is for LAN connections, fiber is for high-speed, and telephone cable is for DSL or analog phone lines. Exam tip: Coaxial cable = cable TV/internet.",
      "examTip": "Coaxial cable is the thick cable with a screw-on connector used for cable TV and cable internet modems."
    },
    {
      "id": 17,
      "question": "Which of the following is a characteristic of fiber optic cables?",
      "options": [
        "Susceptible to electromagnetic interference (EMI)",
        "Lower bandwidth compared to copper cables",
        "Transmits data using light signals",
        "Limited to short distances"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Fiber optic cables transmit data using light signals, which is a defining characteristic. They are *not* susceptible to EMI, offer *higher* bandwidth than copper, and are used for *long* distances. Exam tip: Fiber optic = light, high speed, long distance.",
      "examTip": "Fiber optic cables use light, not electricity, to transmit data. This makes them incredibly fast and immune to electrical interference."
    },
    {
      "id": 18,
      "question": "Which of these is a common symptom of a failing hard drive?",
      "options": [
        "Blue screen errors",
        "Slow boot times and file access",
        "Overheating CPU",
        "No display output"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Slow boot times and file access are common symptoms of a failing hard drive, as it struggles to read data. Blue screens can be caused by many issues, CPU overheating is a separate problem, and no display output is usually GPU or monitor related. Exam tip: Slow performance, unusual noises = HDD issues.",
      "examTip": "Slow boot times, grinding or clicking noises, and frequent file access errors are red flags for a failing hard drive."
    },
    {
      "id": 19,
      "question": "What is the purpose of a 'loopback plug' in network troubleshooting?",
      "options": [
        "To trace network cables",
        "To test the functionality of a network port",
        "To crimp RJ45 connectors",
        "To punch down network cables"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A loopback plug is used to test the functionality of a network port by looping the signal back to the port, allowing diagnostic tests to be run. Toner probes trace cables, crimpers crimp connectors, and punchdown tools punch down wires. Exam tip: Loopback plug = port testing tool.",
      "examTip": "A loopback plug is a simple tool to test if a network port on your computer or switch is working correctly."
    },
    {
      "id": 20,
      "question": "Which of the following is a security protocol that provides encrypted terminal access, often used for remote server administration?",
      "options": [
        "Telnet",
        "FTP",
        "SSH",
        "HTTP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "SSH (Secure Shell) provides encrypted terminal access, making it secure for remote server administration. Telnet is unencrypted, FTP is for file transfer, and HTTP is for web traffic (unencrypted). Exam tip: SSH = secure remote terminal.",
      "examTip": "SSH (Secure Shell) is the secure way to remotely access a server's command line. It encrypts your session."
    },
    {
      "id": 21,
      "question": "Which of these RAM types is faster and more power-efficient?",
      "options": [
        "DDR3",
        "DDR4",
        "DDR2",
        "DDR"
      ],
      "correctAnswerIndex": 1,
      "explanation": "DDR4 (Double Data Rate 4) RAM is faster and more power-efficient than DDR3, DDR2, and original DDR. Each generation of DDR RAM improves on speed and efficiency. Exam tip: Higher DDR number = newer, faster, better.",
      "examTip": "DDR4 is newer and better than DDR3. The higher the DDR number, the newer and generally faster the RAM."
    },
    {
      "id": 22,
      "question": "What is the standard port number for Telnet?",
      "options": [
        "Port 21",
        "Port 22",
        "Port 23",
        "Port 25"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Port 23 is the standard port number for Telnet, an unencrypted remote terminal protocol. Port 21 is for FTP control, Port 22 for SSH, and Port 25 for SMTP. Exam tip: Telnet = port 23, unencrypted.",
      "examTip": "Telnet uses port 23. Remember it's unencrypted, so SSH is preferred for security."
    },
    {
      "id": 23,
      "question": "Which type of display technology is known for its excellent color accuracy and wide viewing angles, often used in high-quality monitors?",
      "options": [
        "TN (Twisted Nematic)",
        "VA (Vertical Alignment)",
        "OLED (Organic Light Emitting Diode)",
        "IPS (In-Plane Switching)"
      ],
      "correctAnswerIndex": 3,
      "explanation": "IPS (In-Plane Switching) display technology is known for excellent color accuracy and wide viewing angles, making it ideal for high-quality monitors and professional use. TN is faster but worse colors, VA is in-between, and OLED excels in contrast but is less common in typical monitors. Exam tip: IPS = best color, viewing angles.",
      "examTip": "IPS panels are prized for their color accuracy and wide viewing angles, making them great for graphics work and quality displays."
    },
    {
      "id": 24,
      "question": "Which of the following is a function of a 'router' in a network?",
      "options": [
        "To connect devices within a local network",
        "To amplify Wi-Fi signals",
        "To route traffic between different networks",
        "To protect against power surges"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A router's primary function is to route traffic between different networks, like your home network and the internet. Switches connect devices within a local network, access points amplify Wi-Fi, and surge protectors handle power surges. Exam tip: Router = network traffic director between networks.",
      "examTip": "Routers are the gateways between networks. They decide the best path for data to travel between networks."
    },
    {
      "id": 25,
      "question": "Which tool is used to attach RJ45 connectors to the end of Ethernet cables?",
      "options": [
        "Toner probe",
        "Cable tester",
        "Crimper",
        "Punchdown tool"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A crimper is used to attach RJ45 connectors to the end of Ethernet cables, securing the wires in place. Toner probes trace cables, cable testers test continuity, and punchdown tools punch down wires. Exam tip: Crimper = RJ45 connector attachment.",
      "examTip": "A crimper is essential for making your own Ethernet cables. It's used to attach the RJ45 connector."
    },
    {
      "id": 26,
      "question": "What is the purpose of 'Network Address Translation' (NAT)?",
      "options": [
        "To encrypt network traffic",
        "To translate domain names to IP addresses",
        "To allow multiple devices to share a single public IP address",
        "To manage network cables"
      ],
      "correctAnswerIndex": 2,
      "explanation": "NAT (Network Address Translation) allows multiple devices on a private network to share a single public IP address when accessing the internet. VPNs encrypt traffic, DNS translates names to IPs, and cable management is unrelated. Exam tip: NAT = share single public IP.",
      "examTip": "NAT is like a receptionist for your home network. It lets many devices share one public IP address to connect to the internet."
    },
    {
      "id": 27,
      "question": "Which of the following is a common characteristic of Hard Disk Drives (HDDs)?",
      "options": [
        "No moving parts",
        "Faster access times than SSDs",
        "Mechanical moving parts",
        "Lower power consumption compared to SSDs"
      ],
      "correctAnswerIndex": 2,
      "explanation": "HDDs have mechanical moving parts (platters and read/write heads), unlike SSDs. They are slower, consume more power, but are generally cheaper for capacity. Exam tip: HDD = mechanical parts, slower, cheaper.",
      "examTip": "HDDs are traditional hard drives with spinning platters and moving parts. This makes them slower but often cheaper for large storage."
    },
    {
      "id": 28,
      "question": "Which of these IP addresses is considered a loopback address, used for testing network interfaces on the local machine?",
      "options": [
        "127.0.0.1",
        "192.168.0.1",
        "10.0.0.1",
        "169.254.0.1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "127.0.0.1 is the IPv4 loopback address, used to test network interfaces on the local machine itself. The other addresses are private or APIPA ranges, not loopback. Exam tip: 127.0.0.1 = loopback, testing local network.",
      "examTip": "127.0.0.1 (or just 'localhost') is your computer's loopback address. It's used to test network services on your own machine."
    },
    {
      "id": 29,
      "question": "What is the purpose of 'Quality of Service' (QoS) in networking?",
      "options": [
        "To encrypt network traffic",
        "To prioritize certain types of network traffic",
        "To manage network cables",
        "To translate domain names to IP addresses"
      ],
      "correctAnswerIndex": 1,
      "explanation": "QoS (Quality of Service) prioritizes certain types of network traffic, like voice or video, to ensure they receive preferential treatment and better performance, especially when network bandwidth is limited. VPNs encrypt traffic, cable management is physical, and DNS translates names to IPs. Exam tip: QoS = prioritize network traffic.",
      "examTip": "Quality of Service (QoS) lets you prioritize certain types of network traffic, like video streaming or VoIP, to ensure they run smoothly."
    },
    {
      "id": 30,
      "question": "Which type of connector is commonly used for connecting internal SATA hard drives to a motherboard?",
      "options": [
        "Molex connector",
        "Berg connector",
        "SATA data connector",
        "IDE connector"
      ],
      "correctAnswerIndex": 2,
      "explanation": "SATA data connectors are used to connect internal SATA hard drives to the motherboard for data transfer. Molex and Berg are older power connectors, and IDE is an older drive interface. Exam tip: SATA data connector = SATA drive data.",
      "examTip": "SATA data connectors are thin, flat connectors used for data transfer between SATA hard drives and the motherboard."
    },
    {
      "id": 31,
      "question": "A user reports that their wireless connection is slow and intermittent. What is a common initial troubleshooting step?",
      "options": [
        "Replace the wireless router",
        "Move closer to the wireless access point",
        "Reinstall the operating system",
        "Upgrade the network card"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Moving closer to the wireless access point is a common initial troubleshooting step for slow and intermittent wireless connections, as signal strength often degrades with distance. Replacing routers or OS is premature. Exam tip: Check Wi-Fi signal strength first.",
      "examTip": "If your Wi-Fi is slow or cutting out, the first thing to try is moving closer to your router or access point to improve signal strength."
    },
    {
      "id": 32,
      "question": "What is the standard port number for SMTP (Simple Mail Transfer Protocol)?",
      "options": [
        "Port 21",
        "Port 23",
        "Port 25",
        "Port 80"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Port 25 is the standard port number for SMTP, used for sending email. Port 21 is for FTP control, Port 23 for Telnet, and Port 80 for HTTP. Exam tip: SMTP = port 25, email sending.",
      "examTip": "SMTP (Simple Mail Transfer Protocol) uses port 25 and is responsible for sending emails."
    },
    {
      "id": 33,
      "question": "Which type of display panel generally offers the fastest response times, making it popular for gaming monitors?",
      "options": [
        "IPS (In-Plane Switching)",
        "VA (Vertical Alignment)",
        "OLED (Organic Light Emitting Diode)",
        "TN (Twisted Nematic)"
      ],
      "correctAnswerIndex": 3,
      "explanation": "TN (Twisted Nematic) panels generally offer the fastest response times, making them popular for gaming monitors where fast refresh rates and low latency are crucial. IPS excels in color, VA in contrast, and OLED in blacks, but TN is fastest. Exam tip: TN = fastest response, gaming monitors.",
      "examTip": "TN panels are the fastest in terms of response time, making them a favorite for gamers who need quick refresh rates."
    },
    {
      "id": 34,
      "question": "What is the purpose of a 'firewall' in network security?",
      "options": [
        "To boost internet speed",
        "To prevent unauthorized access to a network",
        "To manage network cables",
        "To cool down computer components"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A firewall's main purpose is to prevent unauthorized access to a network by monitoring and controlling incoming and outgoing network traffic based on security rules. It doesn't boost speed, manage cables, or cool components. Exam tip: Firewall = network security guard.",
      "examTip": "Firewalls are your network's security guards. They control what traffic is allowed in and out to protect your network."
    },
    {
      "id": 35,
      "question": "Which tool is used to terminate network cables into patch panels and wall jacks?",
      "options": [
        "Crimper",
        "Cable tester",
        "Toner probe",
        "Punchdown tool"
      ],
      "correctAnswerIndex": 3,
      "explanation": "A punchdown tool is used to terminate network cables into patch panels and wall jacks, securing the wires into the IDC (Insulation Displacement Connector) terminals. Crimpers attach connectors, testers test cables, and probes trace cables. Exam tip: Punchdown tool = patch panel/wall jack termination.",
      "examTip": "A punchdown tool is specifically designed to push wires into the slots on patch panels and wall jacks to make a solid connection."
    },
    {
      "id": 36,
      "question": "What is the purpose of 'Virtual Private Network' (VPN)?",
      "options": [
        "To speed up internet browsing",
        "To create a secure, encrypted connection over a public network",
        "To manage network cables",
        "To translate domain names to IP addresses"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A VPN (Virtual Private Network) creates a secure, encrypted connection over a public network like the internet, protecting data privacy and security. It doesn't primarily speed up browsing, manage cables, or translate domain names. Exam tip: VPN = secure, private internet connection.",
      "examTip": "VPNs create a secure tunnel for your internet traffic, especially useful when using public Wi-Fi to protect your data."
    },
    {
      "id": 37,
      "question": "Which of the following is a common type of removable storage media that uses flash memory and connects via USB?",
      "options": [
        "Optical Disc (DVD)",
        "Floppy Disk",
        "USB flash drive",
        "Hard Disk Drive (HDD)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "USB flash drives are common removable storage media that use flash memory and connect via USB. DVDs are optical, floppy disks are outdated magnetic, and HDDs are typically not removable in the same way. Exam tip: USB drive = removable flash storage.",
      "examTip": "USB flash drives (thumb drives, memory sticks) are portable, removable storage that uses flash memory and connects via USB."
    },
    {
      "id": 38,
      "question": "Which of these IP addresses is considered an APIPA (Automatic Private IP Addressing) address?",
      "options": [
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        "169.254.1.1"
      ],
      "correctAnswerIndex": 3,
      "explanation": "169.254.1.1 is an APIPA address. APIPA addresses fall in the range 169.254.0.0 - 169.254.255.255 and are automatically assigned when a device fails to get a DHCP address. The others are private IP ranges, not APIPA. Exam tip: 169.254.x.x = APIPA, DHCP failure.",
      "examTip": "If you see an IP address in the 169.254.x.x range, it's an APIPA address. It means your computer couldn't get a DHCP address and assigned itself one."
    },
    {
      "id": 39,
      "question": "What is the purpose of 'Power over Ethernet' (PoE)?",
      "options": [
        "To increase network bandwidth",
        "To provide electrical power and data connection over a single Ethernet cable",
        "To protect against power surges",
        "To amplify Wi-Fi signals"
      ],
      "correctAnswerIndex": 1,
      "explanation": "PoE (Power over Ethernet) provides both electrical power and data connection over a single Ethernet cable, simplifying installation for devices like IP cameras and VoIP phones. It's not for bandwidth, surge protection, or Wi-Fi amplification. Exam tip: PoE = power + data over Ethernet.",
      "examTip": "Power over Ethernet (PoE) is super convenient. It lets you power devices like IP cameras and phones directly through the Ethernet cable – no separate power cord needed."
    },
    {
      "id": 40,
      "question": "Which type of connector is commonly used for connecting external SATA (eSATA) drives?",
      "options": [
        "USB connector",
        "HDMI connector",
        "eSATA connector",
        "RJ45 connector"
      ],
      "correctAnswerIndex": 2,
      "explanation": "eSATA connectors are specifically designed for connecting external SATA drives, providing SATA speeds for external storage. USB is versatile, HDMI is video, and RJ45 is network. Exam tip: eSATA connector = external SATA drives.",
      "examTip": "eSATA is an external version of SATA. It's designed for fast external hard drives, faster than USB in some older standards."
    },
    {
      "id": 41,
      "question": "A user reports their computer is running very slowly after installing new software. What is a common troubleshooting step to check?",
      "options": [
        "Reinstall the operating system",
        "Check system resource usage in Task Manager",
        "Replace the CPU",
        "Format the hard drive"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Checking system resource usage in Task Manager is a common troubleshooting step to see if the new software is consuming excessive CPU, RAM, or disk resources, causing slowdowns. Reinstalling OS, replacing CPU, or formatting are drastic steps too early. Exam tip: Task Manager = resource usage check.",
      "examTip": "When your computer gets slow, Task Manager is your friend. Check it to see what programs are hogging resources like CPU and memory."
    },
    {
      "id": 42,
      "question": "What is the standard port number for DNS (Domain Name System)?",
      "options": [
        "Port 25",
        "Port 53",
        "Port 80",
        "Port 443"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Port 53 is the standard port number for DNS, used for domain name resolution. Port 25 is for SMTP, Port 80 for HTTP, and Port 443 for HTTPS. Exam tip: DNS = port 53, name resolution.",
      "examTip": "DNS (Domain Name System) uses port 53. It's essential for translating website names into IP addresses."
    },
    {
      "id": 43,
      "question": "Which type of display technology is known for its deep blacks and high contrast ratio, often used in high-end TVs and smartphones?",
      "options": [
        "IPS (In-Plane Switching)",
        "VA (Vertical Alignment)",
        "TN (Twisted Nematic)",
        "OLED (Organic Light Emitting Diode)"
      ],
      "correctAnswerIndex": 3,
      "explanation": "OLED (Organic Light Emitting Diode) display technology is known for its deep blacks and high contrast ratio because each pixel can be turned off completely, achieving true black. VA panels also have good contrast, IPS better color, and TN fastest response but weaker contrast/colors. Exam tip: OLED = deep blacks, high contrast.",
      "examTip": "OLED panels are known for their superior contrast and black levels. They can achieve true black, making images pop."
    },
    {
      "id": 44,
      "question": "What is the purpose of 'Uninterruptible Power Supply' (UPS)?",
      "options": [
        "To boost internet speed",
        "To provide backup power in case of power outages",
        "To manage network cables",
        "To cool down computer components"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A UPS (Uninterruptible Power Supply) provides backup power in case of power outages, allowing systems to shut down safely or continue running for a short period. It's not for speed, cable management, or cooling. Exam tip: UPS = backup power.",
      "examTip": "UPS (Uninterruptible Power Supply) is like a battery backup for your computer. It protects against data loss during power outages."
    },
    {
      "id": 45,
      "question": "Which tool is used to organize and manage network cables in a server room or wiring closet?",
      "options": [
        "Crimper",
        "Cable tester",
        "Toner probe",
        "Patch panel"
      ],
      "correctAnswerIndex": 3,
      "explanation": "A patch panel is used to organize and manage network cables in a server room or wiring closet, providing a central point for cable terminations and easier management. Crimpers attach connectors, testers test cables, and probes trace cables. Exam tip: Patch panel = cable organization.",
      "examTip": "Patch panels are like organized phone switchboards for network cables. They make it easy to manage and reroute connections in a server room."
    },
    {
      "id": 46,
      "question": "What is the purpose of 'Virtual LAN' (VLAN)?",
      "options": [
        "To encrypt network traffic",
        "To create separate logical networks on the same physical network",
        "To manage network cables",
        "To translate domain names to IP addresses"
      ],
      "correctAnswerIndex": 1,
      "explanation": "VLANs (Virtual LANs) create separate logical networks on the same physical network infrastructure, improving security and network segmentation. VPNs encrypt traffic, cable management is physical, and DNS translates names to IPs. Exam tip: VLAN = logical network segmentation.",
      "examTip": "VLANs let you divide your physical network into multiple logical networks, even using the same switches. This improves security and organization."
    },
    {
      "id": 47,
      "question": "Which of the following is a common type of memory card used in digital cameras and mobile devices?",
      "options": [
        "DIMM",
        "SODIMM",
        "CompactFlash (CF)",
        "SD card (Secure Digital)"
      ],
      "correctAnswerIndex": 3,
      "explanation": "SD cards (Secure Digital) are a common type of memory card used in digital cameras and mobile devices for removable storage. DIMM and SODIMM are RAM modules, and CF is another type of memory card but less common than SD in modern consumer devices. Exam tip: SD card = camera/mobile memory card.",
      "examTip": "SD cards are the tiny memory cards you see in cameras and phones. They are small, portable, and widely used."
    },
    {
      "id": 48,
      "question": "Which of these IP addresses is considered a public IP address?",
      "options": [
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        "203.0.113.45"
      ],
      "correctAnswerIndex": 3,
      "explanation": "203.0.113.45 is a public IP address, routable on the internet. The others are private IP addresses, used within private networks and not directly routable on the public internet. Exam tip: Public IP = internet routable.",
      "examTip": "Public IP addresses are like your street address on the internet – they are unique and used for communication across the internet."
    },
    {
      "id": 49,
      "question": "What is the purpose of 'Load Balancing' in networking?",
      "options": [
        "To encrypt network traffic",
        "To distribute network traffic across multiple servers",
        "To manage network cables",
        "To translate domain names to IP addresses"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Load balancing distributes network traffic across multiple servers to prevent overload on a single server and improve performance and availability. VPNs encrypt, cable management is physical, and DNS translates names to IPs. Exam tip: Load balancing = traffic distribution for performance.",
      "examTip": "Load balancers are like traffic controllers for web servers. They distribute incoming requests to multiple servers to handle high traffic and prevent overload."
    },
    {
      "id": 50,
      "question": "Which type of connector is commonly used for modular power supply cables that connect to PCIe graphics cards?",
      "options": [
        "Molex connector",
        "Berg connector",
        "PCIe power connector (6-pin or 8-pin)",
        "SATA power connector"
      ],
      "correctAnswerIndex": 2,
      "explanation": "PCIe power connectors (6-pin or 8-pin) are used for modular power supply cables to connect to PCIe graphics cards, providing additional power for high-performance GPUs. Molex and Berg are older power connectors, and SATA power is for SATA drives. Exam tip: PCIe power connector = GPU power.",
      "examTip": "PCIe power connectors are specifically for powering graphics cards that need extra juice beyond what the motherboard slot provides."
    },
    {
      "id": 51,
      "question": "A user reports that their inkjet printer is printing faded pages. What is a common initial troubleshooting step?",
      "options": [
        "Replace the fuser assembly",
        "Check ink levels and replace low ink cartridges",
        "Reinstall the printer driver",
        "Clean the print head"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Checking ink levels and replacing low ink cartridges is a common initial step for faded inkjet prints. Fuser assemblies are for laser printers, driver issues usually cause garbled prints or no printing, and print head cleaning is for clogs, not primarily faded prints. Exam tip: Faded inkjet prints = check ink first.",
      "examTip": "Faded prints on an inkjet printer are often due to low ink. Check your ink levels and replace cartridges if needed."
    },
    {
      "id": 52,
      "question": "What is the standard port number for IMAP (Internet Message Access Protocol)?",
      "options": [
        "Port 110",
        "Port 143",
        "Port 25",
        "Port 80"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Port 143 is the standard port number for IMAP, used for retrieving emails from a server while leaving them on the server. Port 110 is for POP3, Port 25 for SMTP, and Port 80 for HTTP. Exam tip: IMAP = port 143, server-side email access.",
      "examTip": "IMAP (Internet Message Access Protocol) uses port 143 and is designed for accessing emails on a server, keeping them there."
    },
    {
      "id": 53,
      "question": "Which type of display panel technology generally offers the best contrast ratio and black levels?",
      "options": [
        "IPS (In-Plane Switching)",
        "TN (Twisted Nematic)",
        "VA (Vertical Alignment)",
        "OLED (Organic Light Emitting Diode)"
      ],
      "correctAnswerIndex": 3,
      "explanation": "OLED (Organic Light Emitting Diode) display technology offers the best contrast ratio and black levels, as it can achieve true black by turning off individual pixels. VA panels also have good contrast, IPS better color, and TN fastest response but weaker contrast/colors. Exam tip: OLED = best contrast, black levels.",
      "examTip": "OLED panels are known for their superior contrast and black levels. They can achieve true black, making images pop."
    },
    {
      "id": 54,
      "question": "What is the purpose of 'Power Supply Unit' (PSU) wattage rating?",
      "options": [
        "To indicate the physical size of the PSU",
        "To specify the maximum power the PSU can deliver",
        "To measure the efficiency of the PSU",
        "To determine the voltage output of the PSU"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The wattage rating of a PSU specifies the maximum power it can deliver to computer components. It's not about physical size, efficiency (though related), or just voltage output (it outputs multiple voltages). Exam tip: PSU wattage = max power capacity.",
      "examTip": "A PSU's wattage rating tells you how much power it can supply. Make sure it's enough for all your computer components, especially the graphics card."
    },
    {
      "id": 55,
      "question": "Which tool is used to trace and locate network cables, especially behind walls or in ceilings?",
      "options": [
        "Crimper",
        "Cable tester",
        "Toner probe",
        "Punchdown tool"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A toner probe (or toner and probe kit) is used to trace and locate network cables, especially when they are hidden behind walls or in ceilings. Crimpers attach connectors, testers test cables, and punchdown tools terminate wires. Exam tip: Toner probe = cable tracing.",
      "examTip": "A toner probe is like a detective for network cables. It helps you find and trace cables hidden in walls or ceilings."
    },
    {
      "id": 56,
      "question": "What is the purpose of 'Virtual Private Network' (VPN)?",
      "options": [
        "To speed up internet browsing",
        "To create a secure, encrypted connection over a public network",
        "To manage network cables",
        "To translate domain names to IP addresses"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A VPN (Virtual Private Network) creates a secure, encrypted connection over a public network like the internet, protecting data privacy and security. It doesn't primarily speed up browsing, manage cables, or translate domain names. Exam tip: VPN = secure, private internet connection.",
      "examTip": "VPNs create a secure tunnel for your internet traffic, especially useful when using public Wi-Fi to protect your data."
    },
    {
      "id": 57,
      "question": "A field technician is preparing a specialized mini-PC for deployment in a scorching, dust-heavy warehouse environment. Which measure helps ensure minimal dust intrusion and stable operation over the long term?",
      "options": [
        "Install a high-airflow fan design with large open vents",
        "Use a sealed fanless enclosure with passive heat dissipation fins",
        "Position the PC directly under a high-powered ceiling fan for airflow",
        "Schedule frequent compressed-air cleanings as the primary dust management method"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A sealed, fanless enclosure with passive cooling fins can keep dust out effectively, minimizing the need for internal fans that draw in particulate matter. While regular cleanings and high-airflow cooling are valid strategies in some contexts, they are less reliable in a continuously dust-heavy environment. Exam tip: In extreme conditions, reducing air intake paths is key to preventing hardware damage.",
      "examTip": "Sealed or fanless designs help mitigate dust infiltration in harsh environments, extending hardware longevity."
    },
    {
      "id": 58,
      "question": "Which type of system memory includes an on-module buffer to reduce electrical load on the memory controller, commonly found in high-end servers and workstations?",
      "options": [
        "Unbuffered SDRAM",
        "Registered (Buffered) RAM",
        "ECC SODIMM",
        "Non-ECC DDR4"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Registered (or Buffered) RAM has an additional register between the DRAM modules and the memory controller, reducing the electrical load on the controller and improving stability in systems with large amounts of RAM. Unbuffered memory lacks this register, ECC memory corrects data errors, and SODIMM is a form factor primarily for laptops. Exam tip: Registered memory is typically used in servers to handle higher memory densities more reliably.",
      "examTip": "Registered RAM is especially useful in server environments where multiple high-capacity DIMMs are used, ensuring stable performance."
    },
    {
      "id": 59,
      "question": "A research lab is trying to revive a legacy parallel port-based 2D plotter on a modern laptop that only has USB and USB-C ports. Which approach is most likely to enable stable functionality for the plotter?",
      "options": [
        "Use a simple USB-to-parallel passive cable without any additional drivers",
        "Install a PCIe parallel port card in the laptop's expansion slot",
        "Use an active USB-to-parallel adapter designed for legacy printer support",
        "Convert the plotter’s parallel port to an Ethernet adapter via a custom cable"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Active USB-to-parallel adapters include the necessary interface circuitry and driver support to properly emulate a parallel port for older printers or plotters. A simple passive cable usually fails because it does not provide the hardware-level translation. Laptops typically lack PCIe slots for parallel cards, and direct parallel-to-Ethernet conversion requires specialized hardware not commonly available for typical plotters. Exam tip: Legacy parallel devices need an active adapter to ensure correct signal conversion.",
      "examTip": "For older parallel port printers on modern systems, active adapters with built-in conversion logic are essential for consistent functionality."
    },
    {
      "id": 60,
      "question": "Which advanced CPU feature allows certain security policies to be enforced at the hardware level, helping to prevent malicious code from executing in protected areas of memory?",
      "options": [
        "Intel Hyper-Threading",
        "AMD CrossFire",
        "NX bit (No-eXecute bit) or XD bit",
        "Overclocking multipliers"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The NX (No-eXecute) bit, called the XD (eXecute Disable) bit in Intel terminology, is a hardware-based security feature that marks certain areas of memory as non-executable, preventing malicious code from running there. Hyper-Threading is about parallel execution, CrossFire is GPU-based, and overclocking multipliers adjust CPU frequency. Exam tip: The NX/XD bit is a crucial hardware security layer to mitigate buffer overflow attacks.",
      "examTip": "When you see NX bit or XD bit in BIOS/UEFI, it's a hardware security feature that helps the OS enforce memory protection."
    },
    {
      "id": 61,
      "question": "A small business owner notices unpredictable reboots on their brand-new workstation whenever it automatically backs up data to an external NAS at midnight. Which factor is MOST likely causing these random shutdowns?",
      "options": [
        "A failing mechanical hard drive that can’t sustain the backup speed",
        "An underpowered power supply unit (PSU) struggling under backup load",
        "A network router mismatch in Ethernet duplex settings causing system crashes",
        "A misconfigured screen saver that triggers a forced reboot"
      ],
      "correctAnswerIndex": 1,
      "explanation": "An underpowered power supply can cause system instability and random reboots when the system draws extra power, such as during backups that stress both the CPU and storage components. While mismatched duplex settings or failing drives can cause slowdowns or errors, they typically do not cause sudden complete reboots. A screen saver misconfiguration is unlikely to force restarts. Exam tip: Always ensure the PSU wattage is sufficient for all workloads.",
      "examTip": "Power supply issues often manifest during peak load events, like backups or high CPU/GPU usage. Always match PSU capacity to system demands."
    },
    {
      "id": 62,
      "question": "Which laser printing stage follows the 'developing' phase and involves transferring the toner from the imaging drum to the paper?",
      "options": [
        "Charging",
        "Fusing",
        "Transferring",
        "Cleaning"
      ],
      "correctAnswerIndex": 2,
      "explanation": "In the laser printing process, the 'transferring' stage moves the toner from the drum onto the paper via an electrostatic charge. Charging readies the drum, developing applies toner to the charged areas, fusing permanently bonds toner to the paper via heat, and cleaning removes residual toner from the drum. Exam tip: The standard laser printing stages are charging, exposing, developing, transferring, fusing, and cleaning.",
      "examTip": "Remember the six-step laser printing process in order: charging, exposing, developing, transferring, fusing, cleaning."
    },
    {
      "id": 63,
      "question": "Which compact motherboard form factor measures just 6.7 x 6.7 inches and is commonly used for small form factor PCs?",
      "options": [
        "ATX",
        "MicroATX",
        "Mini-ITX",
        "Nano-ITX"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Mini-ITX is a small form factor motherboard (6.7 x 6.7 inches) often used in HTPCs and compact desktop systems. MicroATX is larger, measuring up to 9.6 x 9.6 inches, while ATX is larger still. Nano-ITX exists but is less common than Mini-ITX in consumer PCs. Exam tip: Mini-ITX is a popular choice for small, quiet computer builds.",
      "examTip": "Motherboard form factors define size, mounting hole positions, and expansion options. Mini-ITX is a standard choice for ultra-compact systems."
    },
    {
      "id": 64,
      "question": "A city library employs self-service kiosks that randomly freeze when patrons print loan receipts. After investigating, the technician finds the thermal printers share a USB hub with multiple barcode scanners. Which solution is MOST likely to stabilize the kiosks?",
      "options": [
        "Disabling all USB power-saving features in the OS device manager",
        "Replacing the thermal printer with a slower dot matrix printer",
        "Using a powered USB hub or dedicated USB ports for the thermal printer",
        "Installing additional RAM in each kiosk for better printing performance"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A powered USB hub or dedicated USB port ensures the thermal printer receives consistent power and data throughput, preventing freeze-ups often caused by power draw fluctuations or overloaded USB connections. While disabling USB power saving can help, it may not fully address power draw issues. Printer type changes or additional RAM are less relevant. Exam tip: High-draw USB devices often require dedicated power sources for stable operation.",
      "examTip": "If multiple peripherals share a single bus-powered hub, the resulting power draw can cause system instability. Powered USB hubs or direct connections help."
    },
    {
      "id": 65,
      "question": "Which file system supports file sizes larger than 4 GB, is commonly used for modern Windows installations, and includes features like file and folder permissions and encryption?",
      "options": [
        "FAT32",
        "exFAT",
        "NTFS",
        "Ext4"
      ],
      "correctAnswerIndex": 2,
      "explanation": "NTFS (New Technology File System) supports large file sizes beyond 4 GB, includes robust security features like permissions and encryption, and is the default file system for modern Windows OS installations. FAT32 is limited to 4 GB file sizes, exFAT is primarily for removable drives, and Ext4 is a Linux file system. Exam tip: NTFS is standard for Windows internal drives due to its security and advanced features.",
      "examTip": "For Windows systems, especially internal disks, NTFS is the go-to due to its support for large files, file-level security, and journaling."
    },
    {
      "id": 66,
      "question": "Which upgrade is generally most beneficial when a system frequently uses a large amount of virtual memory and experiences slow performance due to swapping?",
      "options": [
        "Installing a higher-wattage power supply",
        "Adding more RAM modules",
        "Replacing the mechanical hard drive with a slower model",
        "Upgrading to a higher resolution monitor"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Adding more RAM reduces the system's reliance on virtual memory, decreasing the frequency of disk swapping and improving performance. A higher-wattage PSU addresses power issues, not memory bottlenecks. Replacing the drive with a slower model or upgrading the monitor resolution won't fix memory paging issues. Exam tip: If the system swaps to disk often, more RAM is the best remedy.",
      "examTip": "When tasks exceed available physical RAM, the OS starts using disk space as virtual memory, which is much slower. More RAM alleviates this bottleneck."
    },
    {
      "id": 67,
      "question": "A traveling photographer needs to print high-resolution images directly from an SD card using a mobile photo printer in remote areas with no AC power. The user complains of frequent print failures. Which factor is MOST likely contributing to these failures?",
      "options": [
        "The printer’s built-in Wi-Fi interfering with the SD card slot",
        "Inadequate battery capacity or insufficient power supply",
        "A corrupt SD card format that the printer cannot read",
        "Using glossy photo paper instead of standard printer paper"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Mobile photo printers require a stable power source, especially when generating high-resolution images. If the battery is underpowered, the printer may fail mid-print. While a corrupt SD card or paper mismatch can cause other errors, insufficient power is the most common cause of intermittent print failures in remote scenarios. Exam tip: Always check battery health or supply quality when operating printers off-grid.",
      "examTip": "For portable printing in remote areas, ensure a reliable power source with enough capacity to handle the printer’s peak usage."
    },
    {
      "id": 68,
      "question": "Which tool in Windows can be used to monitor disk health by scanning for bad sectors and file system errors, potentially repairing them if needed?",
      "options": [
        "Device Manager",
        "chkdsk",
        "msconfig",
        "dxdiag"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The chkdsk (Check Disk) utility scans a disk for file system errors and bad sectors, and can attempt repairs. Device Manager manages hardware drivers, msconfig configures startup items, and dxdiag provides DirectX diagnostics. Exam tip: chkdsk is crucial for repairing file system corruption and marking bad sectors.",
      "examTip": "Regularly running chkdsk can help detect and fix drive issues before they lead to data loss."
    },
    {
      "id": 69,
      "question": "An office manager attempts to share a USB label printer between two PCs via a USB switch box. Both PCs intermittently lose connection, causing failed label prints. Which solution is MOST likely to provide reliable shared printing for this device?",
      "options": [
        "Use a high-quality USB extension cable with gold-plated connectors",
        "Configure the label printer as a network printer via a dedicated print server",
        "Enable port forwarding in the router’s firewall settings",
        "Set each PC’s USB power management to maximum performance"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Using a dedicated print server turns the USB label printer into a network printer accessible by multiple PCs without physically switching cables, eliminating intermittent connections. Higher-quality cables, router port forwarding, or adjusting power management won’t reliably solve the shared USB device issue. Exam tip: Converting a locally attached printer into a network resource is often more stable than manual USB switching.",
      "examTip": "For multi-user access to a single USB printer, a network or print server solution avoids the pitfalls of physically switching USB connections."
    },
    {
      "id": 70,
      "question": "Which UTP (Unshielded Twisted Pair) cable category is officially rated for up to 10 Gbps Ethernet at 100 meters and is commonly used in modern network installations?",
      "options": [
        "Cat 5",
        "Cat 5e",
        "Cat 6",
        "Cat 6a"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Category 6a (Cat 6a) cable is rated for 10 Gbps transmission over a distance of up to 100 meters. Cat 5 and 5e usually support up to 1 Gbps (though 5e can sometimes handle 10 Gbps at shorter distances), while Cat 6 can handle 10 Gbps but typically up to 55 meters. Exam tip: For full 10G at 100 meters, Cat 6a is the recognized standard.",
      "examTip": "If you need guaranteed 10 Gbps over 100 meters on twisted pair, Cat 6a is your go-to cable rating."
    },
    {
      "id": 71,
      "question": "A small design studio has an inkjet printer producing inconsistent color output, especially after printing large posters. The first few prints look fine, but subsequent prints have shifted hues. Which factor is MOST likely the cause?",
      "options": [
        "Low-quality USB cable causing data corruption",
        "Air bubbles in the ink channels requiring a complete head replacement",
        "Printer’s ink supply running out mid-print for each color pass",
        "Overheating of the printhead due to high-volume printing, impacting color consistency"
      ],
      "correctAnswerIndex": 3,
      "explanation": "High-volume color inkjet printing can cause the printhead to heat up, altering how ink droplets are dispensed and leading to shifted hues after prolonged use. While ink supply issues can cause fading or gaps, sudden color shifts often point to thermal stress on the printhead. Exam tip: If color consistency drops during large print runs, overheating or inadequate cooling may be the culprit.",
      "examTip": "Monitor temperature and consider printer cool-down periods during large, continuous color printing jobs for consistent results."
    },
    {
      "id": 72,
      "question": "Which feature found in many modern SSDs and operating systems helps extend drive lifespan by ensuring writes are spread evenly across memory cells?",
      "options": [
        "Wear leveling",
        "S.M.A.R.T. monitoring",
        "High RPM spinning platters",
        "Partition alignment"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Wear leveling is a technique used by SSD controllers to distribute writes evenly across all memory cells, preventing premature wear on specific areas. S.M.A.R.T. monitoring tracks drive health, rotating platters are an HDD feature, and partition alignment affects performance but not specifically wear distribution. Exam tip: Wear leveling is critical for SSD longevity.",
      "examTip": "SSDs rely on wear leveling to avoid overusing the same flash cells, thereby extending overall drive life."
    },
    {
      "id": 73,
      "question": "A technician is configuring four VLANs on a managed switch: VLAN 10 (Management), VLAN 20 (Office), VLAN 30 (Guest), and VLAN 40 (VoIP). Drag each VLAN ID to match the correct interface assignment below (one VLAN per interface):\n\n- Interface g0/1: ____\n- Interface g0/2: ____\n- Interface g0/3: ____\n- Interface g0/4: ____\n\nWhich single CLI command most accurately reflects assigning VLAN 20 to interface g0/2?",
      "options": [
        "switchport mode trunk; switchport trunk allowed vlan 20",
        "switchport mode access; switchport access vlan 20",
        "switchport mode access; switchport voice vlan 20",
        "interface vlan 20; ip address dhcp"
      ],
      "correctAnswerIndex": 1,
      "explanation": "When assigning a VLAN to a switch port on a typical managed switch, you set the port to access mode and specify the VLAN. The command syntax is usually: 'switchport mode access' followed by 'switchport access vlan <ID>'. Trunk mode is for carrying multiple VLANs, voice VLAN is separate from the data VLAN, and configuring 'interface vlan 20' is for setting up an SVI (Switched Virtual Interface), not assigning a port. Exam tip: For end-user access ports, use 'switchport mode access' and 'switchport access vlan <ID>'.",
      "examTip": "In many CLI-based switches, each access port is assigned exactly one VLAN using 'switchport mode access' and 'switchport access vlan <ID>'."
    },
    {
      "id": 74,
      "question": "Which backup method archives all selected files since the last full backup and does not reset the archive bit, allowing multiple backups to track changes cumulatively?",
      "options": [
        "Full backup",
        "Incremental backup",
        "Differential backup",
        "Snapshot backup"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A differential backup copies all changes since the last full backup but does not reset the archive bit, leading each successive differential to grow until the next full backup. An incremental backup only copies changes since the last full or incremental backup and resets the bit, while a full backup copies everything. Snapshots are a point-in-time representation often used in virtualization or advanced file systems. Exam tip: Differential backups require only the last full backup and the last differential to restore.",
      "examTip": "Differential backups grow larger over time until another full backup occurs, while incremental backups remain smaller but require each incremental to restore fully."
    },
    {
      "id": 75,
      "question": "An artisan workshop uses a custom PC for laser engraving tasks. The device reboots whenever the engraving laser is activated at high power, causing job failures. Which cause is MOST likely?",
      "options": [
        "A faulty CPU that overheats under heavy processing loads",
        "Excess electromagnetic interference (EMI) from the laser disabling the motherboard",
        "An incorrectly installed operating system patch causing crashes during I/O",
        "A safety interlock in the laser software forcibly rebooting the PC for calibration"
      ],
      "correctAnswerIndex": 1,
      "explanation": "High-powered lasers can generate significant electromagnetic interference, causing system instability if the PC is not shielded or grounded properly. While CPU overheating can cause reboots, the direct correlation with laser activation points to EMI. OS patch issues or safety interlocks rarely force hardware-level reboots. Exam tip: In environments with strong EMI sources, additional shielding and proper grounding are critical for PC stability.",
      "examTip": "High-power industrial equipment can create intense EMI. Always verify proper grounding, shielding, and cable routing in such setups to prevent reboots or data corruption."
    },
    {
      "id": 76,
      "question": "Which type of expansion slot is typically used for high-performance graphics cards in modern desktop computers?",
      "options": [
        "PCI",
        "PCIe x1",
        "PCIe x16",
        "AGP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "PCIe x16 (PCI Express x16) slots are the standard for high-performance graphics cards in modern desktops, providing the necessary bandwidth. PCI and AGP are older, slower standards, and PCIe x1 is for smaller cards. Exam tip: PCIe x16 = graphics card slot.",
      "examTip": "PCIe x16 slots are designed for graphics cards. They are the longest PCIe slots on a motherboard."
    },
    {
      "id": 77,
      "question": "What is the purpose of 'Power-On Self-Test' (POST)?",
      "options": [
        "To install the operating system",
        "To test hardware components during system startup",
        "To manage network connections",
        "To speed up boot times"
      ],
      "correctAnswerIndex": 1,
      "explanation": "POST (Power-On Self-Test) is a series of diagnostic tests run by the BIOS/UEFI during system startup to check hardware components and ensure they are functioning correctly. It's not for OS install, network management, or speeding up boot. Exam tip: POST = hardware startup check.",
      "examTip": "POST (Power-On Self-Test) is the first thing your computer does when you turn it on. It checks all the hardware to make sure everything is working."
    },
    {
      "id": 78,
      "question": "Which type of network device operates at the Data Link layer (Layer 2) of the OSI model and uses MAC addresses to forward data?",
      "options": [
        "Router",
        "Switch",
        "Hub",
        "Modem"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Switches operate at the Data Link layer (Layer 2) and use MAC addresses to forward data frames efficiently within a local network. Routers operate at Layer 3 (Network layer) using IP addresses, hubs are Layer 1 (Physical layer) repeaters, and modems are for signal modulation/demodulation. Exam tip: Switch = Layer 2, MAC addresses.",
      "examTip": "Switches are Layer 2 devices and use MAC addresses to intelligently forward data within a local network, unlike hubs which just broadcast."
    },
    {
      "id": 79,
      "question": "Which of the following is a type of connector used for internal power connections within a computer, often for older drives and some fans?",
      "options": [
        "SATA power connector",
        "PCIe power connector",
        "Molex connector",
        "Berg connector"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Molex connectors are a type of power connector used for internal power connections in computers, often for older IDE/PATA drives and some case fans. SATA power is for SATA drives, PCIe for GPUs, and Berg is for floppy drives. Exam tip: Molex connector = older power connections.",
      "examTip": "Molex connectors are the older, rectangular 4-pin power connectors. You'll see them on older hard drives and some case fans."
    },
    {
      "id": 80,
      "question": "A user reports their laser printer is printing blank pages. What is a common initial troubleshooting step?",
      "options": [
        "Replace the fuser assembly",
        "Check toner levels and replace low toner cartridge",
        "Reinstall the printer driver",
        "Clean the print head"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Checking toner levels and replacing a low toner cartridge is a common initial step for blank laser printer pages. Fuser assemblies cause fusing issues, driver problems cause garbled prints, and print head cleaning is for inkjet printers. Exam tip: Blank laser prints = check toner first.",
      "examTip": "Blank pages from a laser printer often mean the toner cartridge is empty or low. Check and replace the toner cartridge first."
    },
    {
      "id": 81,
      "question": "What is the standard port number for POP3 (Post Office Protocol version 3)?",
      "options": [
        "Port 25",
        "Port 110",
        "Port 143",
        "Port 443"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Port 110 is the standard port number for POP3, used for retrieving emails from a server, typically downloading and removing them from the server. Port 25 is for SMTP, Port 143 for IMAP, and Port 443 for HTTPS. Exam tip: POP3 = port 110, email download.",
      "examTip": "POP3 (Post Office Protocol version 3) uses port 110 and is used to download emails from a server to your computer, usually removing them from the server."
    },
    {
      "id": 82,
      "question": "Which type of display panel technology generally offers a balance of good color reproduction and contrast, often found in mid-range monitors?",
      "options": [
        "TN (Twisted Nematic)",
        "IPS (In-Plane Switching)",
        "OLED (Organic Light Emitting Diode)",
        "VA (Vertical Alignment)"
      ],
      "correctAnswerIndex": 3,
      "explanation": "VA (Vertical Alignment) panel technology generally offers a good balance of color reproduction and contrast, making it common in mid-range monitors. IPS is better for color, TN for speed, and OLED for contrast/blacks. Exam tip: VA = balanced color, contrast.",
      "examTip": "VA panels are a good middle ground. They offer better contrast than IPS and TN, and decent color accuracy, making them good all-around monitors."
    },
    {
      "id": 83,
      "question": "What is the purpose of 'Redundant Array of Independent Disks' (RAID)?",
      "options": [
        "To increase CPU processing speed",
        "To improve data storage performance, redundancy, or both",
        "To manage network cables",
        "To translate domain names to IP addresses"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RAID (Redundant Array of Independent Disks) is used to improve data storage performance, redundancy (fault tolerance), or a combination of both, by using multiple hard drives. It's not for CPU speed, cable management, or DNS. Exam tip: RAID = storage performance/redundancy.",
      "examTip": "RAID is about using multiple hard drives together to either speed up data access or protect against data loss if a drive fails."
    },
    {
      "id": 84,
      "question": "Which tool is used to test and verify the pinout and wiring of network cables?",
      "options": [
        "Crimper",
        "Cable tester",
        "Toner probe",
        "Punchdown tool"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A cable tester is used to test and verify the pinout and wiring of network cables, ensuring the wires are in the correct order and properly connected. Crimpers attach connectors, probes trace cables, and punchdown tools terminate wires. Exam tip: Cable tester = wiring verification.",
      "examTip": "A cable tester confirms that your Ethernet cables are wired correctly according to T568A or T568B standards."
    },
    {
      "id": 85,
      "question": "What is the purpose of 'Virtual Machine' (VM)?",
      "options": [
        "To speed up internet browsing",
        "To run an operating system within another operating system",
        "To manage network cables",
        "To translate domain names to IP addresses"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A Virtual Machine (VM) allows you to run an operating system within another operating system, creating an isolated computing environment. It's not for browsing speed, cable management, or DNS. Exam tip: VM = OS inside OS.",
      "examTip": "Virtual Machines let you run a 'computer within a computer.' You can run different operating systems inside your main OS, like running Linux on Windows."
    },
    {
      "id": 86,
      "question": "Which type of expansion slot is typically used for network interface cards (NICs) in desktop computers?",
      "options": [
        "PCIe x16",
        "PCIe x1",
        "PCI",
        "AGP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "PCIe x1 (PCI Express x1) slots are commonly used for network interface cards (NICs) in desktop computers, providing sufficient bandwidth for network connectivity. PCIe x16 is for GPUs, PCI is older, and AGP is for older graphics. Exam tip: PCIe x1 = NIC slot.",
      "examTip": "PCIe x1 slots are often used for network cards, sound cards, and other expansion cards that don't need the high bandwidth of a PCIe x16 graphics card slot."
    },
    {
      "id": 87,
      "question": "What is the purpose of 'Boot Priority' in BIOS/UEFI settings?",
      "options": [
        "To set the system date and time",
        "To determine the order in which the system attempts to boot from different devices",
        "To enable virtualization support",
        "To set a BIOS password"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Boot Priority in BIOS/UEFI settings determines the order in which the system attempts to boot from different devices (like hard drives, USB drives, network). It's not for date/time, virtualization, or BIOS passwords. Exam tip: Boot Priority = boot device order.",
      "examTip": "Boot priority in BIOS/UEFI decides what device your computer tries to boot from first – like your hard drive, a USB drive, or the network."
    },
    {
      "id": 88,
      "question": "Which type of network device operates at the Network layer (Layer 3) of the OSI model and uses IP addresses to route data?",
      "options": [
        "Switch",
        "Hub",
        "Router",
        "Modem"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Routers operate at the Network layer (Layer 3) and use IP addresses to route data packets between different networks. Switches are Layer 2, hubs are Layer 1, and modems are for signal modulation/demodulation. Exam tip: Router = Layer 3, IP addresses.",
      "examTip": "Routers are Layer 3 devices and use IP addresses to route data between networks, like directing traffic between your home network and the internet."
    },
    {
      "id": 89,
      "question": "Which of the following is a type of connector used for older floppy disk drives?",
      "options": [
        "SATA power connector",
        "PCIe power connector",
        "Molex connector",
        "Berg connector"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Berg connectors are a type of power connector historically used for older floppy disk drives. Molex is for older IDE/PATA drives, SATA power for SATA drives, and PCIe for GPUs. Exam tip: Berg connector = floppy drive power.",
      "examTip": "Berg connectors are small, 4-pin power connectors. You might see them on old floppy drives, but they are less common now."
    },
    {
      "id": 90,
      "question": "A user reports their laser printer is printing garbled text. What is a common initial troubleshooting step?",
      "options": [
        "Replace the fuser assembly",
        "Check toner levels and replace low toner cartridge",
        "Reinstall the printer driver",
        "Clean the print head"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Reinstalling the printer driver is a common initial step for garbled text from a laser printer, as driver corruption or incompatibility can cause this. Fuser issues are for fusing, toner for blank pages, and print head cleaning for inkjet printers. Exam tip: Garbled laser prints = driver issue first.",
      "examTip": "Garbled text from a printer often points to a driver problem. Try reinstalling or updating the printer driver."
    },
    {
      "id": 91,
      "question": "What is the standard port number for NetBIOS Session Service?",
      "options": [
        "Port 21",
        "Port 139",
        "Port 143",
        "Port 443"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Port 139 is the standard port number for NetBIOS Session Service, used for file and printer sharing over NetBIOS over TCP/IP. Port 21 is for FTP control, Port 143 for IMAP, and Port 443 for HTTPS. Exam tip: NetBIOS Session Service = port 139, file/printer sharing.",
      "examTip": "NetBIOS Session Service uses port 139 and is related to older Windows file and printer sharing."
    },
    {
      "id": 92,
      "question": "Which type of display panel technology generally offers the widest color gamut and best color accuracy, often used in professional graphics monitors?",
      "options": [
        "TN (Twisted Nematic)",
        "VA (Vertical Alignment)",
        "OLED (Organic Light Emitting Diode)",
        "IPS (In-Plane Switching)"
      ],
      "correctAnswerIndex": 3,
      "explanation": "IPS (In-Plane Switching) display technology generally offers the widest color gamut and best color accuracy, making it preferred for professional graphics monitors where color fidelity is paramount. TN is fastest, VA balanced, and OLED for contrast/blacks. Exam tip: IPS = widest color gamut, accuracy.",
      "examTip": "IPS panels are the champions of color accuracy and wide color gamuts, making them ideal for graphic designers and photographers."
    },
    {
      "id": 93,
      "question": "What is the purpose of 'RAID 1' configuration?",
      "options": [
        "To increase read/write speed by striping data",
        "To provide data redundancy by mirroring data across two drives",
        "To provide fault tolerance with parity across multiple drives",
        "To combine multiple drives into a single large volume without redundancy"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RAID 1 (Mirroring) provides data redundancy by mirroring data across two drives, so if one drive fails, the data is still available on the other. RAID 0 is striping for speed, RAID 5 uses parity for fault tolerance, and spanning (JBOD) combines drives without redundancy. Exam tip: RAID 1 = mirroring, redundancy.",
      "examTip": "RAID 1 (mirroring) is all about data protection. It creates an exact copy of your data on two drives, so if one fails, you don't lose anything."
    },
    {
      "id": 94,
      "question": "Which tool is used to verify the physical connectivity of network cables and ports, often indicating lights or status?",
      "options": [
        "Crimper",
        "Cable tester",
        "Network Interface Card (NIC) tester/indicator",
        "Punchdown tool"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A Network Interface Card (NIC) tester or indicator lights on network ports (like switches and routers) are used to verify physical connectivity, often showing link and activity status. Crimpers attach connectors, testers test cable wiring, and punchdown tools terminate wires. Exam tip: NIC tester/indicator = physical link verification.",
      "examTip": "Look at the lights on your network card or switch port. They are often the first sign of whether you have a physical network connection."
    },
    {
      "id": 95,
      "question": "What is the purpose of 'Hypervisor' in virtualization?",
      "options": [
        "To speed up internet browsing",
        "To manage and run virtual machines",
        "To manage network cables",
        "To translate domain names to IP addresses"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A hypervisor is software that manages and runs virtual machines, creating and controlling the virtualized hardware environment for each VM. It's not for browsing speed, cable management, or DNS. Exam tip: Hypervisor = VM manager.",
      "examTip": "A hypervisor is the software that makes virtualization possible. It's like a virtual machine operating system that runs and controls virtual machines."
    },
    {
      "id": 96,
      "question": "Which type of expansion slot is typically used for sound cards and other lower-bandwidth expansion cards in desktop computers?",
      "options": [
        "PCIe x16",
        "PCIe x1",
        "PCI",
        "AGP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "PCIe x1 (PCI Express x1) slots are often used for sound cards and other lower-bandwidth expansion cards, as they provide sufficient bandwidth for these devices. PCIe x16 is for GPUs, PCI is older, and AGP is for older graphics. Exam tip: PCIe x1 = lower-bandwidth cards.",
      "examTip": "PCIe x1 slots are shorter than PCIe x16 slots and are typically used for expansion cards that don't need a lot of bandwidth, like sound cards and network cards."
    },
    {
      "id": 97,
      "question": "What is the purpose of 'UEFI Secure Boot'?",
      "options": [
        "To set a BIOS password",
        "To ensure that only trusted operating systems can boot",
        "To enable virtualization support",
        "To speed up boot times"
      ],
      "correctAnswerIndex": 1,
      "explanation": "UEFI Secure Boot is a security feature that ensures only trusted operating systems can boot by verifying the digital signatures of bootloaders and OS kernels, preventing malware from hijacking the boot process. It's not for passwords, virtualization, or speed. Exam tip: Secure Boot = OS boot security.",
      "examTip": "UEFI Secure Boot is a security feature that prevents unauthorized operating systems or malware from booting on your computer."
    },
    {
      "id": 98,
      "question": "Which type of network device operates as a repeater at the Physical layer (Layer 1) of the OSI model, simply broadcasting all received data to all ports?",
      "options": [
        "Switch",
        "Router",
        "Hub",
        "Modem"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Hubs operate at the Physical layer (Layer 1) and function as repeaters, broadcasting all received data to all ports, leading to collisions and inefficiency. Switches are Layer 2, routers Layer 3, and modems are for signal modulation/demodulation. Exam tip: Hub = Layer 1 repeater, broadcast.",
      "examTip": "Hubs are very basic network devices. They just repeat everything they receive to all connected devices, leading to network collisions and inefficiency."
    },
    {
      "id": 99,
      "question": "Which of the following is a type of connector used for older serial ports?",
      "options": [
        "SATA power connector",
        "PCIe power connector",
        "Molex connector",
        "DB9 connector"
      ],
      "correctAnswerIndex": 3,
      "explanation": "DB9 connectors are used for older serial ports, often for peripherals like modems or older mice. Molex is for older IDE/PATA drives, SATA power for SATA drives, and PCIe for GPUs. Exam tip: DB9 connector = older serial ports.",
      "examTip": "DB9 connectors are the older, D-shaped connectors with 9 pins. They were common for serial ports used for modems and older peripherals."
    },
    {
      "id": 100,
      "question": "A user reports their laser printer is printing double or echo images on the page. What is a common initial troubleshooting step?",
      "options": [
        "Replace the fuser assembly",
        "Check toner levels and replace low toner cartridge",
        "Check for a damaged or dirty drum unit",
        "Reinstall the printer driver"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Checking for a damaged or dirty drum unit is a common initial step for double or echo images on laser printer pages, as drum issues can cause image ghosting. Fuser issues are for fusing, toner for blank pages, and drivers for garbled text. Exam tip: Double/echo laser prints = check drum unit.",
      "examTip": "Double or 'ghost' images from a laser printer often point to a problem with the drum unit. Check if it's dirty or damaged."
    }
  ]
});
