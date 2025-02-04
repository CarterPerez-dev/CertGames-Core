QUESTIONS 17-100

  db.tests.insertOne({
    "category": "aplus",
    "testId": 6,
    "testName": "A+ Practice Test #6 (Formidable)",
    "xpPerCorrect": 10,
    "questions": [
      {
        "id": 17,
        "question": "A technician is analyzing network traffic and observes a high volume of UDP packets being broadcast to ports 67 and 68. Which network service is MOST likely generating this traffic?",
        "options": [
          "DNS (Domain Name System)",
          "DHCP (Dynamic Host Configuration Protocol)",
          "SNMP (Simple Network Management Protocol)",
          "TFTP (Trivial File Transfer Protocol)"
        ],
        "correctAnswerIndex": 1,
        "explanation": "DHCP (Dynamic Host Configuration Protocol) is MOST likely generating this traffic. DHCP uses UDP ports 67 (DHCP server) and 68 (DHCP client) for broadcast-based IP address assignment and configuration. DNS uses UDP port 53, SNMP uses UDP ports 161 and 162, and TFTP uses UDP port 69.",
        "examTip": "UDP ports 67 and 68 are the signature ports for DHCP traffic. High UDP broadcasts to these ports usually indicate DHCP client discovery or server responses."
      },
      {
        "id": 18,
        "question": "Which of the following BEST describes the purpose of a 'Hardware Security Module' (HSM) in a cryptographic system?",
        "options": [
          "To accelerate CPU processing speeds for encryption algorithms.",
          "To provide a secure, tamper-proof environment for cryptographic key management and operations.",
          "To manage network firewall rules and access control lists.",
          "To provide software-based encryption libraries and APIs to applications."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A Hardware Security Module (HSM) is BEST described as providing a secure, tamper-proof environment for cryptographic key management and operations. HSMs are specialized hardware designed to protect cryptographic keys and perform cryptographic processing securely. While they can accelerate encryption, their primary purpose is security, not just speed. Firewalls manage network rules, and software libraries are software-based, not hardware.",
        "examTip": "HSMs are all about hardware-based security for cryptography. They are designed to be physically and logically secure for key storage and crypto operations, often certified to meet high security standards."
      },
      {
        "id": 19,
        "question": "A technician is setting up a RAID array and needs to choose a level that provides both fault tolerance and improved read performance, while also maximizing usable storage capacity. Which RAID level is MOST suitable, assuming at least four drives are available?",
        "options": [
          "RAID 1",
          "RAID 5",
          "RAID 6",
          "RAID 10"
        ],
        "correctAnswerIndex": 1,
        "explanation": "RAID 5 is MOST suitable in this scenario. RAID 5 provides fault tolerance (single drive failure) and improved read performance through striping with parity, while also offering relatively good usable storage capacity compared to RAID 1 and RAID 10. RAID 1 is mirroring only, RAID 10 also has reduced capacity due to mirroring, and RAID 6 offers better fault tolerance (two drive failures) but can be more complex and have slightly lower write performance than RAID 5.",
        "examTip": "RAID 5 is often considered the 'sweet spot' for balancing fault tolerance, performance, and capacity in many server and workstation scenarios."
      },
      {
        "id": 20,
        "question": "Which of the following is the MOST likely cause if a laptop display shows distorted or flickering images, especially when the screen is moved or the lid is adjusted?",
        "options": [
          "Faulty RAM module.",
          "Damaged CPU.",
          "Loose or damaged display cable.",
          "Incorrect display driver."
        ],
        "correctAnswerIndex": 2,
        "explanation": "A loose or damaged display cable is the MOST likely cause of distorted or flickering images, especially if the issue changes when the screen is moved or the lid is adjusted. This physical manipulation often affects the connection of the display cable. Faulty RAM or CPU issues are less likely to directly cause display flicker related to physical movement. Incorrect drivers could cause display issues, but physical manipulation is more indicative of a cable problem.",
        "examTip": "Flickering or distorted laptop displays, especially when moving the screen, often point to a loose or damaged display cable connection. Check the cable and its connections first in such cases."
      },
      {
        "id": 21,
        "question": "In the context of network security, what is the primary purpose of implementing 'Network Segmentation' using VLANs or subnets?",
        "options": [
          "To increase internet bandwidth.",
          "To improve network performance by reducing broadcast traffic and containing security breaches.",
          "To simplify network cable management.",
          "To enable wireless network access."
        ],
        "correctAnswerIndex": 1,
        "explanation": "The primary purpose of Network Segmentation using VLANs or subnets is to improve network performance by reducing broadcast traffic and, crucially, to contain security breaches. Segmentation limits the scope of security incidents by isolating network segments, preventing threats from easily spreading across the entire network. While it can indirectly improve performance by reducing broadcast domains, security containment is the main driver. Cable management and wireless access are not primary purposes of network segmentation.",
        "examTip": "Network segmentation (VLANs, subnets) is a key security practice. It limits the 'blast radius' of security incidents and improves network organization and performance."
      },
      {
        "id": 22,
        "question": "Which memory technology is 'synchronous' and timed to the system clock, allowing for faster data transfer rates compared to asynchronous memory?",
        "options": [
          "FPM DRAM (Fast Page Mode DRAM)",
          "EDO RAM (Extended Data Out RAM)",
          "SDRAM (Synchronous DRAM)",
          "DDR SDRAM (Double Data Rate SDRAM)"
        ],
        "correctAnswerIndex": 2,
        "explanation": "SDRAM (Synchronous DRAM) is 'synchronous' memory and timed to the system clock, allowing for faster data transfer rates compared to asynchronous memory types like FPM DRAM and EDO RAM. DDR SDRAM is a further evolution of SDRAM, doubling the data transfer rate per clock cycle. FPM and EDO are older, asynchronous DRAM types.",
        "examTip": "SDRAM is 'synchronous' – it's timed to the system clock, enabling faster data transfer compared to older asynchronous DRAM types like FPM and EDO RAM."
      },
      {
        "id": 23,
        "question": "Which of the following is the MOST likely cause if a laser printer produces consistently blank pages, even after replacing the toner cartridge?",
        "options": [
          "Faulty Fuser Assembly.",
          "Damaged Imaging Drum or Laser Scanner Assembly.",
          "Incorrect Paper Type Setting.",
          "Defective High-Voltage Power Supply or Corona Wire issue."
        ],
        "correctAnswerIndex": 3,
        "explanation": "A Defective High-Voltage Power Supply or Corona Wire issue is the MOST likely cause of consistently blank pages on a laser printer, even after toner replacement. The high-voltage charge is essential for the charging and transferring steps of the laser printing process. If the high-voltage system is faulty, the drum may not be charged, or toner may not transfer to the paper, resulting in blank pages. Fuser and imaging drum issues typically cause different print defects, and paper settings rarely cause completely blank pages.",
        "examTip": "Consistently blank pages from a laser printer, even after toner replacement, strongly suggest a high-voltage power supply or corona wire problem. These are crucial for the laser printing process."
      },
      {
        "id": 24,
        "question": "What is the standard port number range for 'well-known ports', which are reserved for common network services and protocols?",
        "options": [
          "0-1023",
          "1024-49151",
          "49152-65535",
          "1024-65535"
        ],
        "correctAnswerIndex": 0,
        "explanation": "The standard port number range for 'well-known ports' is 0-1023. These ports are reserved for common network services and protocols like HTTP (port 80), FTP (port 21), and SMTP (port 25). Registered ports are 1024-49151, and dynamic/ephemeral ports are 49152-65535.",
        "examTip": "Well-known ports (0-1023) are the 'VIP ports'. They are reserved for standard, widely used network services and protocols. Memorize some key well-known ports for the exam."
      },
      {
        "id": 25,
        "question": "Which of these is a cloud storage service?",
        "options": [
          "Microsoft Word",
          "Adobe Photoshop",
          "Google Drive",
          "Mozilla Firefox"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Google Drive is a cloud storage service, allowing you to store files online and access them from anywhere. Microsoft Word and Adobe Photoshop are applications, and Mozilla Firefox is a web browser. Exam tip: Google Drive, Dropbox, OneDrive are cloud storage examples.",
        "examTip": "Cloud storage like Google Drive, Dropbox, and OneDrive lets you store files online, accessible anywhere."
      },
      {
        "id": 26,
        "question": "What is the purpose of 'passwords' in computer security?",
        "options": [
          "To speed up computer startup",
          "To protect user accounts from unauthorized access",
          "To organize files and folders",
          "To enhance internet browsing speed"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Passwords are used to protect user accounts from unauthorized access, ensuring only the account owner can log in. They don't speed up startup, organize files, or enhance browsing speed. Exam tip: Passwords = account security.",
        "examTip": "Passwords are your first line of defense for your accounts. Choose strong and unique ones."
      },
      {
        "id": 27,
        "question": "Which of the following is an output device?",
        "options": [
          "Microphone",
          "Webcam",
          "Printer",
          "Scanner"
        ],
        "correctAnswerIndex": 2,
        "explanation": "A printer is an output device, producing physical copies of digital documents. Microphones and webcams are input devices, and scanners are for digitizing input. Exam tip: Output devices show results *from* the computer.",
        "examTip": "Output devices like printers and monitors show you the computer's output – what it's 'telling' you."
      },
      {
        "id": 28,
        "question": "What does 'URL' stand for?",
        "options": [
          "Universal Resource Locator",
          "Uniform Record Locator",
          "Universal Routing Link",
          "Uniform Resource Locator"
        ],
        "correctAnswerIndex": 3,
        "explanation": "URL stands for Uniform Resource Locator. It's the address of a resource on the internet, like a website. The other options are not the correct expansion. Exam tip: URLs are website addresses.",
        "examTip": "Uniform Resource Locator (URL) is the web address. It tells your browser where to go."
      },
      {
        "id": 29,
        "question": "Which of these is a type of mobile operating system?",
        "options": [
          "Windows 10",
          "macOS",
          "Android",
          "Linux"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Android is a mobile operating system, primarily used on smartphones and tablets. Windows 10 and macOS are desktop OSes, and Linux is versatile but not primarily mobile-focused in its common distributions. Exam tip: Android and iOS are leading mobile OSes.",
        "examTip": "Android and iOS power most smartphones. They are designed for mobile devices."
      },
      {
        "id": 30,
        "question": "What is the purpose of 'software updates'?",
        "options": [
          "To delete old files",
          "To improve performance and security",
          "To change the computer's color theme",
          "To uninstall applications"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Software updates are primarily released to improve performance, fix bugs, and enhance security. They don't delete files, change themes, or uninstall apps as their main function. Exam tip: Updates = performance + security.",
        "examTip": "Software updates are essential for keeping your system secure and running smoothly. Always install them!"
      },
      {
        "id": 31,
        "question": "Which of these is a common type of computer port?",
        "options": [
          "Ethernet cable",
          "Power cord",
          "USB port",
          "Monitor screen"
        ],
        "correctAnswerIndex": 2,
        "explanation": "A USB port is a common type of computer port, used to connect peripherals. Ethernet cables are cables, power cords supply power, and monitor screens are displays. Exam tip: USB, HDMI, Ethernet are common ports.",
        "examTip": "USB ports are everywhere! They're the standard for connecting most peripherals."
      },
      {
        "id": 32,
        "question": "What does 'ISP' stand for in internet access?",
        "options": [
          "Internet Service Provider",
          "Internal System Protocol",
          "Integrated Security Program",
          "Internet Security Protocol"
        ],
        "correctAnswerIndex": 0,
        "explanation": "ISP stands for Internet Service Provider. Companies like Comcast or Verizon are ISPs, providing internet access. The other options are not the correct expansions. Exam tip: ISP = your internet access company.",
        "examTip": "Internet Service Provider (ISP) is who you pay for internet access. Think of companies like Comcast, Verizon, etc."
      },
      {
        "id": 33,
        "question": "Which of the following is a type of computer virus?",
        "options": [
          "Web browser",
          "Firewall",
          "Trojan horse",
          "Operating system"
        ],
        "correctAnswerIndex": 2,
        "explanation": "A Trojan horse is a type of computer virus, disguised as legitimate software to trick users. Web browsers and operating systems are software types, and firewalls are security systems. Exam tip: Trojan, Worm, Ransomware are malware types.",
        "examTip": "Trojan horses, worms, and ransomware are all types of malware that can harm your system."
      },
      {
        "id": 34,
        "question": "What is the purpose of a 'printer driver'?",
        "options": [
          "To physically install a printer",
          "To translate computer commands into printer language",
          "To refill printer ink cartridges",
          "To troubleshoot network connectivity"
        ],
        "correctAnswerIndex": 1,
        "explanation": "A printer driver translates computer commands into a language the printer understands, enabling communication. It's not for physical installation, ink refilling, or network troubleshooting directly. Exam tip: Drivers = hardware communication facilitators.",
        "examTip": "Printer drivers act as translators, allowing your computer to 'talk' to your printer."
      },
      {
        "id": 35,
        "question": "Which of these is a common type of internet browser?",
        "options": [
          "Microsoft Word",
          "Excel",
          "Google Chrome",
          "PowerPoint"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Google Chrome is a common internet browser, used to access websites. Microsoft Word, Excel, and PowerPoint are office applications. Exam tip: Chrome, Firefox, Safari, Edge are browsers.",
        "examTip": "Chrome, Firefox, Safari, and Edge are your main web browsers. They let you surf the internet."
      },
      {
        "id": 36,
        "question": "What is 'email' used for?",
        "options": [
          "Watching videos online",
          "Sending and receiving digital messages",
          "Playing online games",
          "Creating presentations"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Email is used for sending and receiving digital messages electronically. Video watching, gaming, and presentations are different functions. Exam tip: Email = electronic mail, for messages.",
        "examTip": "Email is electronic mail – a way to send and receive messages digitally."
      },
      {
        "id": 37,
        "question": "Which of the following is a storage medium that uses flash memory?",
        "options": [
          "Hard Disk Drive (HDD)",
          "Solid State Drive (SSD)",
          "Optical Disc (DVD)",
          "Floppy Disk"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Solid State Drives (SSDs) use flash memory for data storage, offering faster speeds and durability than HDDs. HDDs are magnetic disks, DVDs are optical, and floppy disks are outdated magnetic media. Exam tip: SSDs = flash memory storage.",
        "examTip": "Solid State Drives (SSDs) are fast and use flash memory, unlike traditional Hard Disk Drives (HDDs)."
      },
      {
        "id": 38,
        "question": "What is the function of a 'monitor'?",
        "options": [
          "To input text",
          "To display images and video",
          "To print documents",
          "To play audio"
        ],
        "correctAnswerIndex": 1,
        "explanation": "A monitor is an output device used to display images and video from a computer. Keyboards input text, printers print, and speakers play audio. Exam tip: Monitors = visual display.",
        "examTip": "Monitors are your visual output. They display what the computer is 'showing' you."
      },
      {
        "id": 39,
        "question": "Which of these is a type of network protocol?",
        "options": [
          "Keyboard",
          "Monitor",
          "TCP/IP",
          "Mouse"
        ],
        "correctAnswerIndex": 2,
        "explanation": "TCP/IP (Transmission Control Protocol/Internet Protocol) is a fundamental network protocol, the basis of internet communication. Keyboards, monitors, and mice are hardware devices. Exam tip: TCP/IP, HTTP, FTP are network protocols.",
        "examTip": "TCP/IP is the basic language of the internet. It's the foundation for network communication."
      },
      {
        "id": 40,
        "question": "What is 'data backup'?",
        "options": [
          "Deleting unnecessary files",
          "Creating copies of important data for recovery",
          "Speeding up computer performance",
          "Organizing files into folders"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Data backup involves creating copies of important data so it can be recovered in case of data loss. It's not about deleting files, speeding up performance, or just organizing files. Exam tip: Backups = data recovery.",
        "examTip": "Data backups are your safety net. They protect you from data loss due to hardware failure or accidents."
      },
      {
        "id": 41,
        "question": "Which port is commonly used for connecting a printer to a computer?",
        "options": [
          "Ethernet port (RJ45)",
          "USB port",
          "HDMI port",
          "Audio port"
        ],
        "correctAnswerIndex": 1,
        "explanation": "USB ports are commonly used for connecting printers to computers. Ethernet is for network connections, HDMI for video, and audio for sound. Exam tip: USB is versatile for peripherals, including printers.",
        "examTip": "USB is a very common port for printers. It's a standard connection method."
      },
      {
        "id": 42,
        "question": "What is 'cloud computing'?",
        "options": [
          "Using only desktop applications",
          "Storing and accessing data and programs over the internet",
          "Using only wired network connections",
          "Processing data only on local computers"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Cloud computing is about storing and accessing data and programs over the internet, rather than directly on your computer. It's not limited to desktop apps, wired networks, or local processing. Exam tip: Cloud = internet-based services.",
        "examTip": "Cloud computing means your data and applications are in the 'cloud' – on remote servers accessible via the internet."
      },
      {
        "id": 43,
        "question": "Which of these is a function of a 'web server'?",
        "options": [
          "To browse websites",
          "To host and deliver website content",
          "To send emails",
          "To manage computer hardware"
        ],
        "correctAnswerIndex": 1,
        "explanation": "A web server's function is to host and deliver website content to users who request it through web browsers. Browsing is done by clients, email by mail servers, and hardware management by operating systems. Exam tip: Web servers = website hosts.",
        "examTip": "Web servers are the 'hosts' of websites. They store and serve up web pages to users."
      },
      {
        "id": 44,
        "question": "What is 'phishing' in cybersecurity?",
        "options": [
          "Improving network speed",
          "A type of antivirus software",
          "Deceptive attempts to steal personal information",
          "Creating strong passwords"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Phishing is a deceptive attempt to steal personal information (like passwords or credit card details) by disguising as a trustworthy entity, often via email or fake websites. It's not about speed, antivirus, or password creation itself. Exam tip: Phishing = information theft scam.",
        "examTip": "Phishing is a trick to steal your info. Be wary of emails and websites asking for personal details."
      },
      {
        "id": 45,
        "question": "Which component is essential for cooling the CPU in a computer?",
        "options": [
          "Power supply unit (PSU)",
          "Heat sink",
          "RAM module",
          "Network Interface Card (NIC)"
        ],
        "correctAnswerIndex": 1,
        "explanation": "A heat sink is essential for cooling the CPU, dissipating heat generated by the processor. PSU supplies power, RAM is memory, and NIC is for networking. Exam tip: Heat sink + fan = CPU cooling.",
        "examTip": "Heat sinks and fans are crucial for keeping your CPU cool and preventing overheating."
      },
      {
        "id": 46,
        "question": "What is the purpose of 'disk defragmentation'?",
        "options": [
          "To delete files permanently",
          "To reorganize files on a hard drive for faster access",
          "To increase storage capacity",
          "To install new software"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Disk defragmentation reorganizes files on a hard drive to improve access speed by reducing fragmentation. It doesn't delete files, increase capacity, or install software. Exam tip: Defrag = faster HDD access.",
        "examTip": "Disk defragmentation is like tidying up your hard drive to make it run faster, especially for HDDs."
      },
      {
        "id": 47,
        "question": "Which of these is a common type of optical storage media?",
        "options": [
          "SSD",
          "HDD",
          "DVD",
          "USB flash drive"
        ],
        "correctAnswerIndex": 2,
        "explanation": "DVD (Digital Versatile Disc) is a common type of optical storage media, using lasers to read and write data. SSDs are flash memory, HDDs are magnetic disks, and USB drives are flash memory too. Exam tip: DVD, CD, Blu-ray are optical media.",
        "examTip": "DVDs, CDs, and Blu-ray discs are optical storage. They use lasers to read data."
      },
      {
        "id": 48,
        "question": "What is the function of a 'graphics card' or 'GPU'?",
        "options": [
          "To manage network connections",
          "To process and display images and video",
          "To store files and documents",
          "To regulate power supply"
        ],
        "correctAnswerIndex": 1,
        "explanation": "A graphics card (GPU) is responsible for processing and displaying images and video on a monitor. NICs handle networking, storage devices store files, and PSUs regulate power. Exam tip: GPU = graphics processing.",
        "examTip": "Graphics cards (GPUs) are dedicated to processing and displaying visuals. They are essential for gaming and video editing."
      },
      {
        "id": 49,
        "question": "Which of the following is a type of computer network based on geographic scale?",
        "options": [
          "USB network",
          "Bluetooth network",
          "Local Area Network (LAN)",
          "Powerline network"
        ],
        "correctAnswerIndex": 2,
        "explanation": "A Local Area Network (LAN) is defined by its geographic scale, typically covering a small area like an office or home. USB, Bluetooth, and Powerline are connection types, not geographic network scales. Exam tip: LAN, WAN, MAN are geographic network types.",
        "examTip": "LAN (Local Area Network) is your home or office network – a network in a limited area."
      },
      {
        "id": 50,
        "question": "What is the purpose of 'cookies' in web browsing?",
        "options": [
          "To block advertisements",
          "To store small pieces of data about your browsing activity",
          "To speed up website loading times",
          "To protect against viruses"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Cookies are small pieces of data websites store on your computer to remember information about your browsing activity, like preferences or login status. They are not for ad blocking, speeding up websites directly, or virus protection. Exam tip: Cookies = website memory.",
        "examTip": "Cookies are small files websites use to remember you and your preferences, enhancing your browsing experience (and sometimes tracking you)."
      },
      {
        "id": 51,
        "question": "Which of these is a common tool for diagnosing network connectivity issues?",
        "options": [
          "Microsoft Word",
          "Ping command",
          "Adobe Photoshop",
          "Excel"
        ],
        "correctAnswerIndex": 1,
        "explanation": "The 'ping' command is a common tool for diagnosing network connectivity issues by testing if a host is reachable. Word, Photoshop, and Excel are applications, not network tools. Exam tip: Ping, Tracert, Ipconfig are network diagnostic tools.",
        "examTip": "The 'ping' command is your basic network connectivity test. It checks if you can 'reach' another computer."
      },
      {
        "id": 52,
        "question": "What does 'VPN' stand for in network security?",
        "options": [
          "Virtual Private Network",
          "Very Personal Network",
          "Volume Protection Network",
          "Verified Public Node"
        ],
        "correctAnswerIndex": 0,
        "explanation": "VPN stands for Virtual Private Network. It creates a secure, encrypted connection over a less secure network like the internet. The other options are not the correct expansions. Exam tip: VPN = secure, private network connection.",
        "examTip": "Virtual Private Network (VPN) creates a secure tunnel for your internet traffic, protecting your privacy."
      },
      {
        "id": 53,
        "question": "Which of these is a type of computer case form factor, often used for smaller PCs?",
        "options": [
          "ATX",
          "Micro-ATX",
          "Full Tower",
          "Server Rack"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Micro-ATX is a type of computer case form factor, smaller than standard ATX, and often used for compact PCs. ATX and Full Tower are larger form factors, and Server Rack is for server systems. Exam tip: ATX, Micro-ATX, Mini-ITX are common form factors.",
        "examTip": "Micro-ATX is a smaller motherboard and case form factor, good for compact PCs."
      },
      {
        "id": 54,
        "question": "What is the purpose of 'system restore' in Windows?",
        "options": [
          "To delete all personal files",
          "To revert system settings and files to a previous state",
          "To speed up system performance",
          "To install new software"
        ],
        "correctAnswerIndex": 1,
        "explanation": "System Restore in Windows allows you to revert system settings and files to a previous point in time, often used to undo system changes that caused problems. It doesn't delete files, speed up performance directly, or install software. Exam tip: System Restore = undo system changes.",
        "examTip": "System Restore is like a 'time machine' for your Windows system settings. It can undo changes if something goes wrong."
      },
      {
        "id": 55,
        "question": "Which of these is a common type of connector for audio output?",
        "options": [
          "VGA",
          "HDMI",
          "3.5mm audio jack",
          "DVI"
        ],
        "correctAnswerIndex": 2,
        "explanation": "A 3.5mm audio jack is a common connector for audio output, used for headphones and speakers. VGA, HDMI, and DVI are primarily video connectors, though HDMI can carry audio as well. Exam tip: 3.5mm jack = standard audio connector.",
        "examTip": "The 3.5mm audio jack is the standard for headphones and speakers on most computers and devices."
      },
      {
        "id": 56,
        "question": "What is 'spam' email?",
        "options": [
          "Important emails from banks",
          "Unsolicited, unwanted emails, often advertisements",
          "Emails with attachments",
          "Emails from known contacts"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Spam email is unsolicited, unwanted email, often advertisements or phishing attempts, sent in bulk. It's not important, wanted, or necessarily from known contacts. Exam tip: Spam = junk email.",
        "examTip": "Spam is junk email – unwanted and often unsolicited messages, usually trying to sell you something or scam you."
      },
      {
        "id": 57,
        "question": "Which of the following is a type of mobile device?",
        "options": [
          "Desktop tower",
          "Server rack",
          "Smartphone",
          "Mainframe computer"
        ],
        "correctAnswerIndex": 2,
        "explanation": "A smartphone is a type of mobile device, designed for portability and mobile use. Desktop towers and mainframes are stationary, and server racks are for server systems. Exam tip: Smartphones, tablets, laptops = mobile devices.",
        "examTip": "Smartphones, tablets, and laptops are all mobile devices – designed to be carried around and used on the go."
      },
      {
        "id": 58,
        "question": "What is the function of a 'power supply unit' (PSU) in a computer?",
        "options": [
          "To cool down the CPU",
          "To provide power to computer components",
          "To store data",
          "To manage network connections"
        ],
        "correctAnswerIndex": 1,
        "explanation": "The Power Supply Unit (PSU) provides power to all computer components, converting AC power from the mains and outputs multiple DC voltages (3.3V, 5V, 12V). A UPS is wrong because it provides backup power but does not directly convert AC to DC for the PC. The motherboard regulator fine-tunes voltages but doesn’t create them from AC. An LCD inverter is related to laptop displays, not desktop power. Exam tip: Remember that desktop PSUs handle AC to DC conversion.'              
      },
      {
        "id": 59,
        "question": "Which of these is a type of network cable connector?",
        "options": [
          "USB connector",
          "HDMI connector",
          "RJ45 connector",
          "Audio jack"
        ],
        "correctAnswerIndex": 2,
        "explanation": "RJ45 is a type of connector used for Ethernet network cables. USB and HDMI are for peripherals and video, and audio jacks are for sound. Exam tip: RJ45 = Ethernet cable connector.",
        "examTip": "RJ45 connectors are for Ethernet cables. Recognize them as network cable ends."
      },
      {
        "id": 60,
        "question": "What is 'computer hardware'?",
        "options": [
          "The physical parts of a computer system",
          "Software programs",
          "Online services",
          "Digital documents"
        ],
        "correctAnswerIndex": 0,
        "explanation": "Computer hardware refers to the physical parts of a computer system, like the CPU, RAM, HDD, etc. Software is programs, online services are internet-based, and documents are data files. Exam tip: Hardware = physical components.",
        "examTip": "Computer hardware is the tangible, physical parts of your computer – what you can touch."
      },
      {
        "id": 61,
        "question": "Which of these is a common type of computer software?",
        "options": [
          "Keyboard",
          "Monitor",
          "Operating system",
          "CPU"
        ],
        "correctAnswerIndex": 2,
        "explanation": "An operating system is a type of computer software, managing hardware and software resources. Keyboards, monitors, and CPUs are hardware components. Exam tip: OS, Applications, Drivers are software types.",
        "examTip": "Operating Systems, applications like Word, and drivers are all types of computer software – the instructions for the hardware."
      },
      {
        "id": 62,
        "question": "Which type of memory is volatile, meaning it loses its data when power is turned off?",
        "options": [
          "ROM (Read-Only Memory)",
          "Flash Memory",
          "RAM (Random Access Memory)",
          "Hard Disk Drive (HDD)"
        ],
        "correctAnswerIndex": 2,
        "explanation": "RAM (Random Access Memory) is volatile memory; it requires power to maintain the stored information. ROM, Flash Memory, and HDDs are non-volatile, retaining data without power. Exam tip: Volatile memory loses data when power is off.",
        "examTip": "RAM is volatile memory – it's temporary and loses data when you turn off the computer. Think of it as short-term memory."
      },
      {
        "id": 63,
        "question": "Which of the following is an example of 'system software'?",
        "options": [
          "Microsoft Word",
          "Google Chrome",
          "Operating System (like Windows)",
          "Adobe Photoshop"
        ],
        "correctAnswerIndex": 2,
        "explanation": "An Operating System (like Windows) is system software, managing hardware and providing a platform for applications. Word, Chrome, and Photoshop are application software. Exam tip: System software manages the system itself.",
        "examTip": "System software like the OS is fundamental. It makes the hardware usable and runs application software."
      },
      {
        "id": 64,
        "question": "What is the function of 'Device Manager' in Windows?",
        "options": [
          "To manage files and folders",
          "To manage hardware devices and drivers",
          "To browse the internet",
          "To edit photos"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Device Manager in Windows is used to manage hardware devices and their drivers, troubleshooting hardware issues. File management is done by File Explorer, browsing by web browsers, and photo editing by image editors. Exam tip: Device Manager = hardware management.",
        "examTip": "Device Manager is your tool to see and manage all the hardware connected to your Windows computer and their drivers."
      },
      {
        "id": 65,
        "question": "Which of these is a common type of wireless security protocol?",
        "options": [
          "HTTP",
          "FTP",
          "WPA2",
          "TCP/IP"
        ],
        "correctAnswerIndex": 2,
        "explanation": "WPA2 (Wi-Fi Protected Access 2) is a common wireless security protocol, encrypting Wi-Fi connections. HTTP and FTP are web and file transfer protocols, and TCP/IP is a network protocol suite. Exam tip: WPA2, WPA3, WEP are wireless security protocols.",
        "examTip": "WPA2 and WPA3 are security protocols for Wi-Fi. They encrypt your wireless connection to keep it safe."
      },
      {
        "id": 66,
        "question": "What is 'cloud backup'?",
        "options": [
          "Backing up data to a local hard drive",
          "Backing up data to remote servers over the internet",
          "Deleting old backups",
          "Speeding up backup process"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Cloud backup involves backing up data to remote servers accessed over the internet, providing offsite data protection. Local backups are to local drives, and deleting backups or speeding up is not the definition of cloud backup itself. Exam tip: Cloud backup = offsite, internet backup.",
        "examTip": "Cloud backup means your backups are stored remotely in the cloud, protected from local disasters."
      },
      {
        "id": 67,
        "question": "Which of these is a type of connector used for video?",
        "options": [
          "RJ45",
          "USB",
          "VGA",
          "RJ11"
        ],
        "correctAnswerIndex": 2,
        "explanation": "VGA (Video Graphics Array) is a type of connector specifically used for video signals, primarily older analog displays. RJ45 is for Ethernet, USB is versatile, and RJ11 is for telephone lines. Exam tip: VGA, HDMI, DisplayPort, DVI are video connectors.",
        "examTip": "VGA, HDMI, DisplayPort, and DVI are all types of video connectors for monitors and displays."
      },
      {
        "id": 68,
        "question": "What is the purpose of 'Task Manager' in Windows?",
        "options": [
          "To manage files and folders",
          "To manage running applications and processes",
          "To browse the internet",
          "To edit system settings"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Task Manager in Windows is used to manage running applications and processes, monitor system performance, and end unresponsive tasks. File management is by File Explorer, browsing by browsers, and system settings by Control Panel/Settings. Exam tip: Task Manager = process and performance management.",
        "examTip": "Task Manager is your Windows tool to see what programs are running and to end unresponsive applications."
      },
      {
        "id": 69,
        "question": "Which of these is a type of wired internet connection?",
        "options": [
          "Wi-Fi",
          "Cellular",
          "DSL",
          "Satellite"
        ],
        "correctAnswerIndex": 2,
        "explanation": "DSL (Digital Subscriber Line) is correct because it is a wired internet connection, using telephone lines. Wi-Fi, Cellular, and Satellite are wireless internet technologies. Exam tip: DSL, Cable, Fiber are wired internet connections.",
        "examTip": "DSL, Cable, and Fiber internet are all wired connections that come into your home or office via cables."
      },
      {
        "id": 70,
        "question": "What is 'social engineering' in cybersecurity?",
        "options": [
          "Improving social media presence",
          "Manipulating people to gain confidential information",
          "Designing social networking software",
          "Creating social media accounts"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Social engineering in cybersecurity is manipulating people into divulging confidential information or performing actions. It's not about social media presence, software design, or account creation. Exam tip: Social engineering = human manipulation for info.",
        "examTip": "Social engineering attacks target humans, tricking them into giving up information or doing something they shouldn't."
      },
      {
        "id": 71,
        "question": "Which component is responsible for storing the operating system, applications, and data files long-term?",
        "options": [
          "RAM",
          "CPU",
          "Hard Disk Drive (HDD) or Solid State Drive (SSD)",
          "Motherboard"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Hard Disk Drives (HDDs) and Solid State Drives (SSDs) are responsible for long-term storage of the OS, applications, and data files. RAM is for active memory, CPU is the processor, and the motherboard is the main circuit board. Exam tip: HDD/SSD = long-term storage.",
        "examTip": "HDDs and SSDs are your computer's long-term storage. They hold everything even when powered off."
      },
      {
        "id": 72,
        "question": "What is the function of 'Control Panel' in Windows?",
        "options": [
          "To manage files and folders",
          "To configure system settings and hardware",
          "To browse the internet",
          "To run applications"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Control Panel in Windows is used to configure system settings and hardware, manage user accounts, etc. File management is by File Explorer, browsing by browsers, and running apps directly. Exam tip: Control Panel = system settings configuration.",
        "examTip": "Control Panel is the traditional Windows tool for configuring system settings and hardware. (Settings app is the modern counterpart)."
      },
      {
        "id": 73,
        "question": "Which of these is a common type of connector for connecting peripherals like keyboards and mice?",
        "options": [
          "Ethernet port",
          "HDMI port",
          "USB port",
          "VGA port"
        ],
        "correctAnswerIndex": 2,
        "explanation": "USB ports are commonly used for connecting peripherals like keyboards and mice. Ethernet is for network, HDMI for video, and VGA for older video. Exam tip: USB is versatile for peripherals.",
        "examTip": "USB ports are the most common for connecting peripherals like keyboards, mice, printers, and more."
      },
      {
        "id": 74,
        "question": "What is 'spyware'?",
        "options": [
          "Software that protects against viruses",
          "Software that secretly monitors user activity",
          "Software for creating presentations",
          "Software for managing system updates"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Spyware is software that secretly monitors user activity and collects information without consent. It's not antivirus, presentation software, or update management software. Exam tip: Spyware = secret monitoring software.",
        "examTip": "Spyware is malicious software that secretly watches what you do on your computer, often stealing personal information."
      },
      {
        "id": 75,
        "question": "Which of the following is a type of motherboard form factor, often used in laptops?",
        "options": [
          "ATX",
          "Micro-ATX",
          "Mini-ITX",
          "Proprietary Form Factors (Smaller Laptop Boards)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "While not a standard 'form factor' name, laptops often use proprietary, smaller form factor motherboards designed to fit specific laptop models, often smaller than even Mini-ITX. ATX, Micro-ATX, and Mini-ITX are desktop form factors. Exam tip: Laptops use compact, often proprietary boards.",
        "examTip": "Laptops use smaller, often custom-designed motherboards to fit their compact size."
      },
      {
        "id": 76,
        "question": "What is the purpose of 'Safe Mode' in Windows?",
        "options": [
          "To speed up system performance",
          "To start Windows with minimal drivers and services for troubleshooting",
          "To permanently delete files",
          "To install new hardware"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Safe Mode in Windows starts the OS with minimal drivers and services, primarily for troubleshooting system issues. It's not for speeding up performance, deleting files, or installing hardware directly. Exam tip: Safe Mode = troubleshooting startup mode.",
        "examTip": "Safe Mode is your troubleshooting mode in Windows. It starts with minimal drivers to help you fix problems."
      },
      {
        "id": 77,
        "question": "Which of these is a common type of connector for connecting to a network?",
        "options": [
          "Audio jack",
          "USB port",
          "Ethernet port",
          "HDMI port"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Ethernet ports are commonly used for wired network connections. Audio jacks are for sound, USB for peripherals, and HDMI for video. Exam tip: Ethernet port = network connection.",
        "examTip": "Ethernet ports are for wired network connections. They're often labeled with a network icon."
      },
      {
        "id": 78,
        "question": "What is 'ransomware'?",
        "options": [
          "Software that improves system security",
          "Malware that encrypts files and demands payment for decryption",
          "Software for creating backups",
          "Software for managing passwords"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Ransomware is malware that encrypts a victim's files and demands a ransom (payment) for the decryption key. It's not for security, backups, or password management. Exam tip: Ransomware = file encryption malware.",
        "examTip": "Ransomware is scary malware! It locks up your files and demands money to unlock them."
      },
      {
        "id": 79,
        "question": "Which type of memory is non-volatile, retaining data even when power is off?",
        "options": [
          "RAM (Random Access Memory)",
          "Cache Memory",
          "ROM (Read-Only Memory)",
          "SDRAM"
        ],
        "correctAnswerIndex": 2,
        "explanation": "ROM (Read-Only Memory) is non-volatile memory, retaining data even when power is off. RAM, Cache, and SDRAM are volatile. Exam tip: Non-volatile memory keeps data without power.",
        "examTip": "ROM (Read-Only Memory) is non-volatile – it keeps data even when the computer is turned off. Think of it as permanent memory."
      },
      {
        "id": 80,
        "question": "Which of the following is an example of 'application software'?",
        "options": [
          "Operating System (like macOS)",
          "Device Drivers",
          "Microsoft Word",
          "BIOS/UEFI"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Microsoft Word is application software, designed for specific user tasks like document creation. Operating Systems and Device Drivers are system software, and BIOS/UEFI is firmware. Exam tip: Application software for user tasks.",
        "examTip": "Application software is what you use to do tasks – like Word for writing, Chrome for browsing, etc."
      },
      {
        "id": 81,
        "question": "What is the function of 'Disk Cleanup' in Windows?",
        "options": [
          "To manage files and folders",
          "To remove temporary files and free up disk space",
          "To browse the internet",
          "To edit system settings"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Disk Cleanup in Windows is used to remove temporary files and free up disk space, improving system performance. Device Manager handles device drivers. Task Manager monitors processes and performance. Services.msc is for managing Windows services. Exam tip: Disk Management is your go-to for disk partition tasks in Windows.'                                                    
      },
      {
        "id": 82,
        "question": "Which of these is a common type of port for connecting to a display?",
        "options": [
          "Ethernet port",
          "USB port",
          "HDMI port",
          "Audio port"
        ],
        "correctAnswerIndex": 2,
        "explanation": "HDMI ports are commonly used for connecting to displays, carrying both video and audio. Ethernet is for network, USB for peripherals, and audio for sound. Exam tip: HDMI, VGA, DisplayPort, DVI for displays.",
        "examTip": "HDMI is a key video port. It's designed for high-definition displays and carries both video and audio."
      },
      {
        "id": 83,
        "question": "What is 'adware'?",
        "options": [
          "Software that blocks advertisements",
          "Software that displays advertisements, often unwanted",
          "Software for managing system updates",
          "Software for creating documents"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Adware is software that displays advertisements, often unwanted and intrusive, sometimes bundled with free software. It's not for ad blocking, updates, or document creation. Exam tip: Adware = advertisement-displaying software.",
        "examTip": "Adware is software that bombards you with ads. It's often bundled with free programs."
      },
      {
        "id": 84,
        "question": "Which component is often referred to as the 'brain' of the computer?",
        "options": [
          "RAM",
          "CPU",
          "Hard Disk Drive (HDD)",
          "Motherboard"
        ],
        "correctAnswerIndex": 1,
        "explanation": "The CPU (Central Processing Unit) is often referred to as the 'brain' of the computer, performing calculations and executing instructions. RAM is memory, HDD is storage, and the motherboard is the circuit board. Exam tip: CPU = computer 'brain'.",
        "examTip": "The CPU is the 'brain' of the computer. It does all the processing and calculations."
      },
      {
        "id": 85,
        "question": "What is the purpose of 'file compression'?",
        "options": [
          "To delete files",
          "To reduce the size of files",
          "To speed up computer performance",
          "To encrypt files for security"
        ],
        "correctAnswerIndex": 1,
        "explanation": "File compression is used to reduce the size of files, making them easier to store and transfer. It doesn't delete files, speed up performance directly, or primarily encrypt files. Exam tip: Compression = smaller file size.",
        "examTip": "File compression makes files smaller, saving space and making them faster to transfer online."
      },
      {
        "id": 86,
        "question": "Which of these is a common type of removable storage media?",
        "options": [
          "SSD",
          "HDD",
          "USB flash drive",
          "Motherboard"
        ],
        "correctAnswerIndex": 2,
        "explanation": "USB flash drives are common removable storage media, easily portable and rewritable. SSDs and HDDs are typically internal or external fixed drives, and motherboards are internal components. Exam tip: USB drives, memory cards = removable storage.",
        "examTip": "USB flash drives and memory cards are your everyday removable storage – easy to carry and transfer data."
      },
      {
        "id": 87,
        "question": "What is the function of a 'network switch'?",
        "options": [
          "To connect multiple networks together",
          "To connect devices within a local network",
          "To provide internet access",
          "To protect against viruses"
        ],
        "correctAnswerIndex": 1,
        "explanation": "A network switch connects devices within a local network, enabling communication between them. Routers connect networks, modems provide internet access, and antivirus protects against viruses. Exam tip: Switch = local network device connector.",
        "examTip": "Network switches are like traffic cops within your local network, directing data between devices connected to the same network."
      },
      {
        "id": 88,
        "question": "What is 'pharming' in cybersecurity?",
        "options": [
          "Improving farm technology",
          "Redirecting website traffic to fake sites",
          "Creating strong passwords",
          "Scanning for viruses"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Pharming in cybersecurity is redirecting website traffic to fake (often malicious) websites, often by compromising DNS servers. It's not about farm tech, passwords, or virus scanning. Exam tip: Pharming = website redirection scam.",
        "examTip": "Pharming is a sneaky attack that redirects you to fake websites, even if you type the correct address. It's like being secretly rerouted."
      },
      {
        "id": 89,
        "question": "Which of the following is a performance-based benefit of implementing RAID 0 for storage?",
        "options": [
          "Fault tolerance",
          "Parity-based redundancy",
          "Striping for increased read/write speed",
          "Mirroring for quick recovery"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Striping for increased read/write speed is correct because RAID 0 splits data across multiple disks, boosting performance. Fault tolerance is lacking in RAID 0. Parity-based redundancy is RAID 5/6, and mirroring is RAID 1/10. Exam tip: RAID 0 trades redundancy for raw speed.'                                                                          
      },
      {
        "id": 90,
        "question": "A technician wants to boot a system from a network image rather than a local drive. Which BIOS/UEFI setting must be enabled to use PXE (Preboot eXecution Environment)?",                                                                                           
        options": [
          "Integrated NIC with PXE support",
          "VT-x (Intel) or AMD-V",
          "Secure Boot",
          "Fast Boot"
        ],
        "correctAnswerIndex": 0,
        "explanation": "Integrated NIC with PXE support is correct for network boot. VT-x/AMD-V are for virtualization. Secure Boot checks digital signatures but doesn’t handle PXE specifically. Fast Boot skips some POST checks. Exam tip: PXE requires an enabled network interface with boot ROM or “Network Boot” setting.'                                                    
      },
      {
        "id": 91,
        "question": "A user’s mobile device frequently fails to charge unless the cable is held at a certain angle. Which is the MOST likely issue?",                                       
        options": [
          "Damaged battery causing slow charging",
          "Incorrect OS version installed",
          "Faulty charging port or loose connector",
          "Insufficient mobile data signal"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Faulty charging port or loose connector is correct because if the cable must be positioned precisely, the port is likely damaged. A damaged battery typically shows quick discharges, not needing cable angles. OS version doesn’t cause physical charging issues. Mobile data signal affects connectivity, not charging. Exam tip: Worn or bent charging ports are a common hardware fault on mobile devices.'                                            
      },
      {
        "id": 92,
        "question": "Which command-line tool can help verify the path data takes from a local computer to a remote host, listing each hop along the route?",                                
        options": [
          "ping",
          "ipconfig",
          "nslookup",
          "tracert (Windows)/traceroute (Linux)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "tracert (Windows) or traceroute (Linux) is correct because it shows each router hop en route to the destination. ping tests basic connectivity. ipconfig shows local IP settings. nslookup queries DNS. Exam tip: Use tracert/traceroute to diagnose where a connection fails along the path.'                                                                
      },
      {
        "id": 93,
        "question": "A technician needs to install a 2.5" HDD into a desktop. Which adapter or mounting solution is MOST commonly required?",                                               
        options": [
          "3.5" to 2.5" drive bay adapter',
          "USB to eSATA cable",
          "Server rackmount rails",
          "M.2 to PCI Express riser"
        ],
        "correctAnswerIndex": 0,
        "explanation": "A 3.5" to 2.5" drive bay adapter is correct because desktop bays are usually 3.5". A USB-to-eSATA cable is for external connectivity. Server rack rails are for rack-mounted systems. An M.2 to PCIe riser is for M.2 SSDs, not SATA 2.5" drives. Exam tip: Always match the physical form factor with an adapter or bracket if needed.'                      
      },
      {
        "id": 94,
        "question": "A technician wants to install a Linux VM on top of an existing Windows 10 operating system. Which hypervisor type is needed?",                                         
        options": [
          "Type 1 (bare-metal) hypervisor",
          "Type 2 (hosted) hypervisor",
          "Container-based virtualization",
          "Dedicated hardware emulator card"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Type 2 (hosted) hypervisor is correct because it runs on top of Windows (the host OS). Type 1 requires direct hardware access (no host OS). Containers share the host OS kernel. A hardware emulator card is not standard for VMs. Exam tip: VMware Workstation and Oracle VirtualBox are typical Type 2 hypervisors for desktop use.'                        
      },
      {
        "id": 95,
        "question": "Which of the following addresses is a valid IPv6 link-local address typically starting with FE80::?",                                                                  
        options": [
          "169.254.0.10",
          "192.168.1.10",
          "FE80::1C2B:3FFF:FE4A:1234",
          "FEC0::/10"
        ],
        "correctAnswerIndex": 2,
        "explanation": "FE80::1C2B:3FFF:FE4A:1234 is correct because APIPA automatically assigns addresses in the 169.254.x.x range. 192.168.0.100, 10.0.0.50, and 172.16.100.1 are private addresses but not APIPA. Exam tip: If you see a 169.254.x.x address, it usually indicates DHCP failure or no DHCP server.'                                                                            
      },
      {
        "id": 96,
        "question": "A user cannot access internal network resources when plugged into a specific wall jack, though the cable tests fine. Which tool helps confirm the jack’s wiring path to the switch port?",                                                                          
        options": [
          "Punchdown tool",
          "Tone generator and probe",
          "Multimeter",
          "Crimper"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Tone generator and probe is correct for tracing the cable route in walls and finding which switch port it terminates on. A punchdown tool is for physically terminating cables, a multimeter checks electrical continuity/voltage, and a crimper attaches RJ45 plugs. Exam tip: Toner/probe kits are indispensable for tracking cables in complex cabling setups.'                                                                                         
      },
      {
        "id": 97,
        "question": "A user wants to connect a smartphone to an external display wirelessly for presentations. Which technology is commonly used for screen mirroring on Android devices?", 
        options": [ 'RDP', 'Bluetooth tethering', 'Miracast', 'USB tethering' ],
        "correctAnswerIndex": 2,
        "explanation": "Miracast is correct for Android wireless display mirroring on compatible devices/TVs. RDP is remote desktop. Bluetooth tethering is for data connectivity, not screen sharing. USB tethering shares data over USB, not the display. Exam tip: For Android screen mirroring, Miracast or Chromecast are typical solutions.'                                    
      },
      {
        "id": 98,
        "question": 'Which scenario is MOST likely if a RAID 5 array loses two drives simultaneously?',                                                                                     
        options": [
          'Array continues to function normally',
          'All data is still intact due to mirroring',
          'Data is lost until at least one drive is replaced and rebuilt',
          'No impact because parity can rebuild both drives at once'
        ],
        "correctAnswerIndex": 2,
        "explanation": "Data is lost until at least one drive is replaced and rebuilt is correct because RAID 5 can only tolerate one drive failure. Losing two drives simultaneously breaks the array. It does not mirror two drives, and parity can’t rebuild if two drives are missing. Exam tip: RAID 5 requires all but one drive functional to remain online.'                  
      },
      {
        "id": 99,
        "question": 'Which cloud computing model involves hosting desktop environments in the cloud, allowing users to stream a full OS session remotely?',                                 
        options": [ 'IaaS', 'PaaS', 'DaaS', 'SaaS' ],
        "correctAnswerIndex": 2,
        "explanation": "DaaS (Desktop as a Service) is correct because it hosts entire desktop sessions in the cloud. IaaS provides raw compute infrastructure. PaaS offers a development platform. SaaS delivers software applications. Exam tip: DaaS solutions let users access a virtual desktop from anywhere, managed by a cloud provider.'                                     
      },
      {
        "id": 100,
        "question": 'A laptop displays artifacts and random color blocks during gaming. Which is the MOST likely cause?',                                                                   
        options": [
          'Display cable not seated',
          'Video driver or dedicated GPU hardware failure',
          'Low battery threshold set in BIOS',
          'WiFi antenna interference'
        ],
        "correctAnswerIndex": 1,
        "explanation": "Video driver or dedicated GPU hardware failure is correct because corrupted graphics are often linked to GPU or driver issues. A loose display cable usually causes flickering or a blank screen, not color artifacts. Battery threshold doesn’t affect rendering. WiFi interference impacts network, not GPU output. Exam tip: Artifacts often signal overheating or driver/hardware issues in the GPU.'                                                  
      }
    ]
  });
