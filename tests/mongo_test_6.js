

db.tests.insertOne({
  "category": "aplus",
  "testId": 6,
  "testName": "A+ Practice Test #6 (Formidable)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A user attempts to install an M.2 NVMe SSD in a laptop that previously had an M.2 SATA drive, but the drive is not recognized in the BIOS/UEFI. Which of the following is the MOST likely reason?",
      "options": [
        "The drive is not seated properly.",
        "NVMe drives are not compatible with SATA-only M.2 slots.",
        "The laptop battery is not providing enough power to the drive.",
        "The SATA cable is disconnected."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Some M.2 slots support only SATA-based drives, while NVMe drives require an M.2 slot with PCIe/NVMe support. If the slot is SATA-only, an NVMe drive will not be recognized by the system.",
      "examTip": "Verify whether the M.2 slot supports SATA, NVMe, or both before upgrading an SSD."
    },
    {
      "id": 2,
      "question": "A technician installs a new dedicated graphics card in a desktop PC, but upon boot, the system powers on with no video output. Which step is MOST likely to resolve the issue?",
      "options": [
        "Re-enable the integrated GPU in the BIOS.",
        "Connect the PCIe power cables from the PSU to the GPU.",
        "Move the card to a different PCIe x1 slot.",
        "Reseat the CPU in the socket."
      ],
      "correctAnswerIndex": 1,
      "explanation": "High-performance GPUs often require dedicated PCIe power connectors from the power supply. If these are not connected, the GPU may receive insufficient power and fail to output video.",
      "examTip": "Always check whether the GPU has 6-pin, 8-pin, or other PCIe power requirements. No power = no video."
    },
    {
      "id": 3,
      "question": "A user's desktop boots to a black screen with a cursor after a Windows update. The user can access Task Manager via Ctrl+Alt+Delete. Which advanced startup option is MOST likely to help revert the system to a functional state?",
      "options": [
        "Safe Mode with Networking",
        "System Restore",
        "Command Prompt",
        "Startup Repair"
      ],
      "correctAnswerIndex": 1,
      "explanation": "System Restore can revert recent OS changes that might have caused issues. This is often the fastest way to restore a functional state following a problematic update.",
      "examTip": "System Restore is a powerful rollback feature. Use it if a new update or driver installation breaks the OS."
    },
    {
      "id": 4,
      "question": "A technician is configuring a SOHO router. Which of the following changes is the BEST initial step to improve wireless security from default settings?",
      "options": [
        "Enable DHCP for all wireless clients.",
        "Change the default SSID and Wi-Fi password.",
        "Set up port forwarding for remote access.",
        "Increase the router's transmit power."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Changing the default SSID and Wi-Fi passphrase is the first step in securing a wireless network. Default credentials are widely known, making the network vulnerable if unchanged.",
      "examTip": "Always change default usernames, passwords, and SSIDs on new routers to prevent unauthorized access."
    },
    {
      "id": 5,
      "question": "After plugging in an external USB mouse, a laptop’s built-in trackpad becomes unresponsive. The mouse works, but the trackpad does not. Which is the MOST likely fix?",
      "options": [
        "Replace the laptop motherboard.",
        "Reinstall the operating system.",
        "Press the function-key combination to enable the trackpad.",
        "Physically reseat the trackpad cable inside the chassis."
      ],
      "correctAnswerIndex": 2,
      "explanation": "On many laptops, a function-key toggle (e.g., Fn + F5) enables or disables the trackpad. It's easy to accidentally disable the trackpad after using external peripherals.",
      "examTip": "Check for accidental function-key presses or settings that disable the trackpad when another pointing device is detected."
    },
    {
      "id": 6,
      "question": "Which type of printer relies on the 'charging, exposing, developing, transferring, fusing' process to produce a printed image?",
      "options": [
        "Inkjet",
        "Laser",
        "Thermal",
        "Dot matrix"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Laser printers use an electro-photographic process that includes these key steps to apply toner and fuse it to the paper.",
      "examTip": "Know the distinct print processes: laser printing has multiple steps involving static charges and toner."
    },
    {
      "id": 7,
      "question": "A user hears loud clicking noises from a desktop PC that eventually fails to load the operating system. Which hardware component is MOST likely causing this symptom?",
      "options": [
        "RAM",
        "Power Supply",
        "Hard Disk Drive (HDD)",
        "CPU fan"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A failing mechanical HDD commonly makes loud clicking sounds (the 'click of death') and can cause system boot failures or data corruption.",
      "examTip": "Always back up data immediately if an HDD starts making unusual clicking or grinding noises."
    },
    {
      "id": 8,
      "question": "A technician needs to configure an iOS device to securely retrieve corporate email. Which protocol is MOST likely used for secure email downloading?",
      "options": [
        "POP3",
        "IMAP over SSL (IMAPS)",
        "SMTP",
        "Telnet"
      ],
      "correctAnswerIndex": 1,
      "explanation": "IMAP over SSL (IMAPS) provides an encrypted channel for receiving email, ensuring data confidentiality. POP3 is less commonly used today, and SMTP is primarily for sending email.",
      "examTip": "For secure email retrieval, look for IMAP/POP with SSL/TLS (often referred to as IMAPS or POP3S)."
    },
    {
      "id": 9,
      "question": "Which CPU feature allows a single physical core to appear as two logical processors, improving multitasking performance?",
      "options": [
        "Overclocking",
        "Hyper-Threading",
        "Integrated graphics",
        "Dual-channel memory"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hyper-Threading (Intel) enables one physical CPU core to handle multiple threads simultaneously, making it appear as two logical cores to the operating system.",
      "examTip": "Hyper-Threading helps with parallel processing and is especially useful for multi-threaded applications."
    },
    {
      "id": 10,
      "question": "Which cable choice is BEST for achieving full Thunderbolt 3 or 4 speeds when connecting an external high-speed storage device to a laptop?",
      "options": [
        "Cat 6 Ethernet cable",
        "USB 2.0 Type-A cable",
        "USB 3.0 Type-A to Type-B cable",
        "USB-C Thunderbolt-certified cable"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Thunderbolt 3/4 can deliver up to 40 Gbps but requires a certified USB-C Thunderbolt cable. Other cable options won't achieve Thunderbolt’s maximum data rates.",
      "examTip": "Thunderbolt often uses the same USB-C connector form factor, but the cable and port must specifically support Thunderbolt."
    },
    {
      "id": 11,
      "question": "A user's desktop boots to a black screen with a cursor after a Windows update. The user can access Task Manager via Ctrl+Alt+Delete. Which advanced startup option is MOST likely to help revert the system to a functional state?",
      "options": [
        "Safe Mode with Networking",
        "System Restore",
        "Command Prompt",
        "Startup Repair"
      ],
      "correctAnswerIndex": 1,
      "explanation": "System Restore can revert recent OS changes that might have caused issues. This is often the fastest way to restore a functional state following a problematic update.",
      "examTip": "System Restore is a powerful rollback feature. Use it if a new update or driver installation breaks the OS."
    },
    {
      "id": 12,
      "question": "A technician is configuring a SOHO router. Which of the following changes is the BEST initial step to improve wireless security from default settings?",
      "options": [
        "Enable DHCP for all wireless clients.",
        "Change the default SSID and Wi-Fi password.",
        "Set up port forwarding for remote access.",
        "Increase the router's transmit power."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Changing the default SSID and Wi-Fi passphrase is the first step in securing a wireless network. Default credentials are widely known, making the network vulnerable if unchanged.",
      "examTip": "Always change default usernames, passwords, and SSIDs on new routers to prevent unauthorized access."
    },
    {
      "id": 13,
      "question": "A technician installs a new dedicated graphics card in a desktop PC, but upon boot, the system powers on with no video output. Which step is MOST likely to resolve the issue?",
      "options": [
        "Re-enable the integrated GPU in the BIOS.",
        "Connect the PCIe power cables from the PSU to the GPU.",
        "Move the card to a different PCIe x1 slot.",
        "Reseat the CPU in the socket."
      ],
      "correctAnswerIndex": 1,
      "explanation": "High-performance GPUs often require dedicated PCIe power connectors from the power supply. If these are not connected, the GPU may receive insufficient power and fail to output video.",
      "examTip": "Always check whether the GPU has 6-pin, 8-pin, or other PCIe power requirements. No power = no video."
    },
    {
      "id": 14,
      "question": "A user's desktop boots to a black screen with a cursor after a Windows update. The user can access Task Manager via Ctrl+Alt+Delete. Which advanced startup option is MOST likely to help revert the system to a functional state?",
      "options": [
        "Safe Mode with Networking",
        "System Restore",
        "Command Prompt",
        "Startup Repair"
      ],
      "correctAnswerIndex": 1,
      "explanation": "System Restore can revert recent OS changes that might have caused issues. This is often the fastest way to restore a functional state following a problematic update.",
      "examTip": "System Restore is a powerful rollback feature. Use it if a new update or driver installation breaks the OS."
    },
    {
      "id": 15,
      "question": "After plugging in an external USB mouse, a laptop’s built-in trackpad becomes unresponsive. The mouse works, but the trackpad does not. Which is the MOST likely fix?",
      "options": [
        "Replace the laptop motherboard.",
        "Reinstall the operating system.",
        "Press the function-key combination to enable the trackpad.",
        "Physically reseat the trackpad cable inside the chassis."
      ],
      "correctAnswerIndex": 2,
      "explanation": "On many laptops, a function-key toggle (e.g., Fn + F5) enables or disables the trackpad. It's easy to accidentally disable the trackpad after using external peripherals.",
      "examTip": "Check for accidental function-key presses or settings that disable the trackpad when another pointing device is detected."
    },
    {
      "id": 16,
      "question": "Which type of printer relies on the 'charging, exposing, developing, transferring, fusing' process to produce a printed image?",
      "options": [
        "Inkjet",
        "Laser",
        "Thermal",
        "Dot matrix"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Laser printers use an electro-photographic process that includes these key steps to apply toner and fuse it to the paper.",
      "examTip": "Know the distinct print processes: laser printing has multiple steps involving static charges and toner."
    },
    {
      "id": 17,
      "question": "A user hears loud clicking noises from a desktop PC that eventually fails to load the operating system. Which hardware component is MOST likely causing this symptom?",
      "options": [
        "RAM",
        "Power Supply",
        "Hard Disk Drive (HDD)",
        "CPU fan"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A failing mechanical HDD commonly makes loud clicking sounds (the 'click of death') and can cause system boot failures or data corruption.",
      "examTip": "Always back up data immediately if an HDD starts making unusual clicking or grinding noises."
    },
    {
      "id": 18,
      "question": "A technician needs to configure an iOS device to securely retrieve corporate email. Which protocol is MOST likely used for secure email downloading?",
      "options": [
        "POP3",
        "IMAP over SSL (IMAPS)",
        "SMTP",
        "Telnet"
      ],
      "correctAnswerIndex": 1,
      "explanation": "IMAP over SSL (IMAPS) provides an encrypted channel for receiving email, ensuring data confidentiality. POP3 is less commonly used today, and SMTP is primarily for sending email.",
      "examTip": "For secure email retrieval, look for IMAP/POP with SSL/TLS (often referred to as IMAPS or POP3S)."
    },
    {
      "id": 19,
      "question": "Which CPU feature allows a single physical core to appear as two logical processors, improving multitasking performance?",
      "options": [
        "Overclocking",
        "Hyper-Threading",
        "Integrated graphics",
        "Dual-channel memory"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hyper-Threading (Intel) enables one physical CPU core to handle multiple threads simultaneously, making it appear as two logical cores to the operating system.",
      "examTip": "Hyper-Threading helps with parallel processing and is especially useful for multi-threaded applications."
    },
    {
      "id": 20,
      "question": "Which cable choice is BEST for achieving full Thunderbolt 3 or 4 speeds when connecting an external high-speed storage device to a laptop?",
      "options": [
        "Cat 6 Ethernet cable",
        "USB 2.0 Type-A cable",
        "USB 3.0 Type-A to Type-B cable",
        "USB-C Thunderbolt-certified cable"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Thunderbolt 3/4 can deliver up to 40 Gbps but requires a certified USB-C Thunderbolt cable. Other cable options won't achieve Thunderbolt’s maximum data rates.",
      "examTip": "Thunderbolt often uses the same USB-C connector form factor, but the cable and port must specifically support Thunderbolt."
    },
    {
      "id": 21,
      "question": "Which of these is a common tool for diagnosing network connectivity issues?",
      "options": [
        "Microsoft Word",
        "Ping command",
        "Adobe Photoshop",
        "Excel"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The 'ping' command is a common tool for diagnosing network connectivity issues by testing if a host is reachable.",
      "examTip": "The 'ping' command is your basic network connectivity test. It checks if you can 'reach' another computer."
    },
    {
      "id": 22,
      "question": "What does 'VPN' stand for in network security?",
      "options": [
        "Virtual Private Network",
        "Very Personal Network",
        "Volume Protection Network",
        "Verified Public Node"
      ],
      "correctAnswerIndex": 0,
      "explanation": "VPN stands for Virtual Private Network. It creates a secure, encrypted connection over a less secure network like the internet.",
      "examTip": "Virtual Private Network (VPN) creates a secure tunnel for your internet traffic, protecting your privacy."
    },
    {
      "id": 23,
      "question": "Which of these is a type of computer network based on geographic scale?",
      "options": [
        "USB network",
        "Bluetooth network",
        "Local Area Network (LAN)",
        "Powerline network"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A Local Area Network (LAN) is defined by its geographic scale, typically covering a small area like an office or home.",
      "examTip": "LAN (Local Area Network) is your home or office network – a network in a limited area."
    },
    {
      "id": 24,
      "question": "What is the purpose of 'cookies' in web browsing?",
      "options": [
        "To block advertisements",
        "To store small pieces of data about your browsing activity",
        "To speed up website loading times",
        "To protect against viruses"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Cookies are small pieces of data websites store on your computer to remember information about your browsing activity, like preferences or login status.",
      "examTip": "Cookies are small files websites use to remember you and your preferences, enhancing your browsing experience (and sometimes tracking you)."
    },
    {
      "id": 25,
      "question": "Which of these is a common type of computer virus?",
      "options": [
        "Web browser",
        "Firewall",
        "Trojan horse",
        "Operating system"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A Trojan horse is a type of computer virus, disguised as legitimate software to trick users.",
      "examTip": "Trojan horses, worms, and ransomware are all types of malware that can harm your system."
    },
    {
      "id": 26,
      "question": "What is the purpose of a 'printer driver'?",
      "options": [
        "To physically install a printer",
        "To translate computer commands into printer language",
        "To refill printer ink cartridges",
        "To troubleshoot network connectivity"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A printer driver translates computer commands into a language the printer understands, enabling communication.",
      "examTip": "Printer drivers act as translators, allowing your computer to 'talk' to your printer."
    },
    {
      "id": 27,
      "question": "Which of these is a common type of internet browser?",
      "options": [
        "Microsoft Word",
        "Excel",
        "Google Chrome",
        "PowerPoint"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Google Chrome is a common internet browser, used to access websites.",
      "examTip": "Chrome, Firefox, Safari, and Edge are browsers that let you surf the internet."
    },
    {
      "id": 28,
      "question": "What does 'email' stand for?",
      "options": [
        "Watching videos online",
        "Sending and receiving digital messages",
        "Playing online games",
        "Creating presentations"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Email is used for sending and receiving digital messages electronically.",
      "examTip": "Email is electronic mail – a way to send and receive messages digitally."
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
      "explanation": "Android is a mobile operating system, primarily used on smartphones and tablets.",
      "examTip": "Android and iOS are the leading mobile operating systems."
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
      "explanation": "Software updates are primarily released to improve performance, fix bugs, and enhance security.",
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
      "explanation": "A USB port is a common type of computer port, used to connect peripherals.",
      "examTip": "USB, HDMI, and Ethernet are common ports found on computers."
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
      "explanation": "ISP stands for Internet Service Provider, which provides internet access.",
      "examTip": "ISP = your internet access company."
    },
    {
      "id": 33,
      "question": "Which of the following is a type of computer virus?",
      "options": [
        "Trojan horse",
        "Worm",
        "Ransomware",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Trojan horses, worms, and ransomware are all types of computer viruses/malware.",
      "examTip": "Remember, malware includes many types such as Trojan horses, worms, and ransomware."
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
      "explanation": "A printer driver translates computer commands into a language the printer understands.",
      "examTip": "Printer drivers act as translators between your computer and your printer."
    },
    {
      "id": 35,
      "question": "Which of these is a common type of internet browser?",
      "options": [
        "Google Chrome",
        "Mozilla Firefox",
        "Microsoft Edge",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Google Chrome, Mozilla Firefox, and Microsoft Edge are all common internet browsers.",
      "examTip": "Chrome, Firefox, Safari, and Edge are your main web browsers."
    },
    {
      "id": 36,
      "question": "What is 'email' used for?",
      "options": [
        "To send and receive digital messages",
        "To store files",
        "To run applications",
        "To browse the internet"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Email is used for sending and receiving digital messages electronically.",
      "examTip": "Email stands for electronic mail and is used for communication."
    },
    {
      "id": 37,
      "question": "Which of these is a storage medium that uses flash memory?",
      "options": [
        "Hard Disk Drive (HDD)",
        "Solid State Drive (SSD)",
        "Optical Disc (DVD)",
        "Floppy Disk"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Solid State Drives (SSDs) use flash memory for data storage.",
      "examTip": "SSDs use flash memory, which is faster and more durable than HDDs."
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
      "explanation": "A monitor is an output device used to display images and video from a computer.",
      "examTip": "Monitors display the computer’s output so you can see what’s happening."
    },
    {
      "id": 39,
      "question": "Which of these is a type of network protocol?",
      "options": [
        "TCP/IP",
        "HTTP",
        "FTP",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "TCP/IP, HTTP, and FTP are all network protocols used for communication over the internet.",
      "examTip": "Protocols like TCP/IP, HTTP, and FTP are essential for network communication."
    },
    {
      "id": 40,
      "question": "What is the purpose of 'data backup'?",
      "options": [
        "To delete unnecessary files",
        "To create copies of important data for recovery",
        "To speed up system performance",
        "To organize files into folders"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data backup involves creating copies of important data so it can be recovered in case of data loss.",
      "examTip": "Backups protect your data from loss due to hardware failure or other disasters."
    },
    {
      "id": 41,
      "question": "Which of these is a common type of computer port for connecting peripherals?",
      "options": [
        "USB port",
        "Ethernet port",
        "HDMI port",
        "Audio port"
      ],
      "correctAnswerIndex": 0,
      "explanation": "USB ports are commonly used to connect peripherals such as keyboards, mice, and printers.",
      "examTip": "USB ports are ubiquitous and used for many peripheral devices."
    },
    {
      "id": 42,
      "question": "What is 'cloud computing'?",
      "options": [
        "Storing and accessing data and programs over the internet",
        "Using only desktop applications",
        "Using only wired network connections",
        "Processing data only on local computers"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Cloud computing involves storing and accessing data and programs over the internet instead of on a local computer.",
      "examTip": "Cloud computing lets you access data and apps from anywhere with an internet connection."
    },
    {
      "id": 43,
      "question": "Which of these is a function of a 'web server'?",
      "options": [
        "To host and deliver website content",
        "To browse websites",
        "To send emails",
        "To manage computer hardware"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A web server hosts and delivers website content to users upon request.",
      "examTip": "Web servers are responsible for serving web pages to your browser."
    },
    {
      "id": 44,
      "question": "What is 'phishing' in cybersecurity?",
      "options": [
        "Deceptive attempts to steal personal information",
        "Improving network speed",
        "A type of antivirus software",
        "Creating strong passwords"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Phishing involves deceptive attempts to steal personal information, often via email or fake websites.",
      "examTip": "Be cautious of unsolicited emails or websites asking for personal data."
    },
    {
      "id": 45,
      "question": "Which component is essential for cooling the CPU in a computer?",
      "options": [
        "Heat sink",
        "Power supply unit (PSU)",
        "RAM module",
        "Network Interface Card (NIC)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A heat sink (often paired with a fan) is essential for cooling the CPU by dissipating heat.",
      "examTip": "Heat sinks and fans work together to keep the CPU from overheating."
    },
    {
      "id": 46,
      "question": "What is the purpose of 'disk defragmentation'?",
      "options": [
        "To reorganize files on a hard drive for faster access",
        "To delete files permanently",
        "To increase storage capacity",
        "To install new software"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Disk defragmentation reorganizes files on a hard drive to reduce fragmentation and improve access times.",
      "examTip": "Defragmentation can improve the performance of mechanical hard drives by organizing data contiguously."
    },
    {
      "id": 47,
      "question": "Which of these is a common type of optical storage media?",
      "options": [
        "DVD",
        "SSD",
        "HDD",
        "USB flash drive"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DVDs are a common type of optical storage media that use lasers to read and write data.",
      "examTip": "Optical media include CDs, DVDs, and Blu-ray discs."
    },
    {
      "id": 48,
      "question": "What is the function of a 'graphics card' or 'GPU'?",
      "options": [
        "To process and display images and video",
        "To manage network connections",
        "To store files and documents",
        "To regulate power supply"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A graphics card (GPU) processes and displays images and video on the monitor.",
      "examTip": "GPUs are essential for rendering images, videos, and games."
    },
    {
      "id": 49,
      "question": "Which of the following is a type of computer network based on geographic scale?",
      "options": [
        "Local Area Network (LAN)",
        "USB network",
        "Bluetooth network",
        "Powerline network"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A Local Area Network (LAN) is defined by its limited geographic scale, typically within a home or office.",
      "examTip": "LANs cover small areas, while WANs and MANs cover larger areas."
    },
    {
      "id": 50,
      "question": "What is the purpose of 'cookies' in web browsing?",
      "options": [
        "To store small pieces of data about your browsing activity",
        "To block advertisements",
        "To speed up website loading times",
        "To protect against viruses"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Cookies store small pieces of data about your browsing activity, such as preferences or login sessions.",
      "examTip": "Cookies help websites remember information about you."
    },
    {
      "id": 51,
      "question": "Which of these is a common type of computer virus?",
      "options": [
        "Trojan horse",
        "Worm",
        "Ransomware",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Trojan horses, worms, and ransomware are all types of computer viruses/malware.",
      "examTip": "Remember, malware comes in many forms including Trojans, worms, and ransomware."
    },
    {
      "id": 52,
      "question": "What is the purpose of a 'printer driver'?",
      "options": [
        "To translate computer commands into printer language",
        "To physically install a printer",
        "To refill printer ink cartridges",
        "To troubleshoot network connectivity"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A printer driver translates computer commands into a language that the printer can understand.",
      "examTip": "Think of a printer driver as a translator between your computer and your printer."
    },
    {
      "id": 53,
      "question": "Which of these is a common type of internet browser?",
      "options": [
        "Google Chrome",
        "Mozilla Firefox",
        "Microsoft Edge",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Google Chrome, Mozilla Firefox, and Microsoft Edge are all common internet browsers.",
      "examTip": "Popular browsers include Chrome, Firefox, Safari, and Edge."
    },
    {
      "id": 54,
      "question": "What is 'email' used for?",
      "options": [
        "Sending and receiving digital messages",
        "Storing files and documents",
        "Running applications",
        "Browsing the internet"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Email is used for sending and receiving digital messages electronically.",
      "examTip": "Email stands for electronic mail."
    },
    {
      "id": 55,
      "question": "Which of these is a storage medium that uses flash memory?",
      "options": [
        "Solid State Drive (SSD)",
        "Hard Disk Drive (HDD)",
        "Optical Disc (DVD)",
        "Floppy Disk"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Solid State Drives (SSDs) use flash memory for data storage.",
      "examTip": "SSDs are faster than HDDs because they use flash memory."
    },
    {
      "id": 56,
      "question": "What is the function of a 'monitor'?",
      "options": [
        "To display images and video",
        "To input text",
        "To print documents",
        "To play audio"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A monitor displays images and video from the computer.",
      "examTip": "Monitors are output devices that let you see what the computer is doing."
    },
    {
      "id": 57,
      "question": "Which of these is a type of network protocol?",
      "options": [
        "TCP/IP",
        "HTTP",
        "FTP",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "TCP/IP, HTTP, and FTP are all network protocols.",
      "examTip": "Network protocols are the rules that govern data communication on the internet."
    },
    {
      "id": 58,
      "question": "What is the purpose of 'data backup'?",
      "options": [
        "To create copies of important data for recovery",
        "To delete unnecessary files",
        "To speed up system performance",
        "To organize files into folders"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Data backup creates copies of important data so it can be recovered if data is lost.",
      "examTip": "Regular backups protect your data against loss."
    },
    {
      "id": 59,
      "question": "Which of these is a common type of computer port for connecting peripherals?",
      "options": [
        "USB port",
        "Ethernet port",
        "HDMI port",
        "Audio port"
      ],
      "correctAnswerIndex": 0,
      "explanation": "USB ports are commonly used to connect peripherals such as keyboards and mice.",
      "examTip": "USB ports are found on nearly every computer."
    },
    {
      "id": 60,
      "question": "What is 'cloud computing'?",
      "options": [
        "Storing and accessing data and programs over the internet",
        "Using only desktop applications",
        "Using only wired network connections",
        "Processing data only on local computers"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Cloud computing involves storing and accessing data and programs over the internet instead of locally.",
      "examTip": "Cloud computing enables access to data from anywhere with an internet connection."
    },
    {
      "id": 61,
      "question": "Which of these is a function of a 'web server'?",
      "options": [
        "To host and deliver website content",
        "To browse websites",
        "To send emails",
        "To manage computer hardware"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A web server hosts and delivers website content.",
      "examTip": "Web servers serve up websites to users."
    },
    {
      "id": 62,
      "question": "What is 'phishing' in cybersecurity?",
      "options": [
        "Deceptive attempts to steal personal information",
        "Improving network speed",
        "A type of antivirus software",
        "Creating strong passwords"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Phishing involves deceptive attempts to steal personal information, often via email or fake websites.",
      "examTip": "Be cautious of emails asking for personal details."
    },
    {
      "id": 63,
      "question": "Which component is essential for cooling the CPU in a computer?",
      "options": [
        "Heat sink",
        "Power supply unit (PSU)",
        "RAM module",
        "Network Interface Card (NIC)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A heat sink (often paired with a fan) is essential for cooling the CPU by dissipating heat.",
      "examTip": "A good heat sink keeps the CPU from overheating."
    },
    {
      "id": 64,
      "question": "What is the purpose of 'disk defragmentation'?",
      "options": [
        "To reorganize files on a hard drive for faster access",
        "To delete files permanently",
        "To increase storage capacity",
        "To install new software"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Disk defragmentation reorganizes files so that data is stored contiguously, which can speed up access times.",
      "examTip": "Defragmenting an HDD can improve its performance by reducing fragmentation."
    },
    {
      "id": 65,
      "question": "Which of these is a common type of optical storage media?",
      "options": [
        "DVD",
        "SSD",
        "HDD",
        "USB flash drive"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DVDs are a common type of optical storage media that use lasers to read and write data.",
      "examTip": "Optical storage includes CDs, DVDs, and Blu-ray discs."
    },
    {
      "id": 66,
      "question": "What is the function of a 'graphics card' or 'GPU'?",
      "options": [
        "To process and display images and video",
        "To manage network connections",
        "To store files and documents",
        "To regulate power supply"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A GPU processes and displays images and video on the monitor.",
      "examTip": "GPUs are essential for rendering images, videos, and games."
    },
    {
      "id": 67,
      "question": "Which of the following is a type of computer network based on geographic scale?",
      "options": [
        "Local Area Network (LAN)",
        "USB network",
        "Bluetooth network",
        "Powerline network"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A LAN is defined by its limited geographic area, such as an office or home.",
      "examTip": "LANs cover small areas; WANs and MANs cover larger areas."
    },
    {
      "id": 68,
      "question": "What is the purpose of 'cookies' in web browsing?",
      "options": [
        "To store small pieces of data about your browsing activity",
        "To block advertisements",
        "To speed up website loading times",
        "To protect against viruses"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Cookies store small pieces of data about your browsing activity, like preferences and session data.",
      "examTip": "Cookies help websites remember you and your settings."
    },
    {
      "id": 69,
      "question": "Which of these is a common type of computer virus?",
      "options": [
        "Trojan horse",
        "Worm",
        "Ransomware",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Trojan horses, worms, and ransomware are all types of computer viruses/malware.",
      "examTip": "Remember, malware can come as Trojans, worms, or ransomware."
    },
    {
      "id": 70,
      "question": "What is the purpose of a 'printer driver'?",
      "options": [
        "To translate computer commands into printer language",
        "To physically install a printer",
        "To refill printer ink cartridges",
        "To troubleshoot network connectivity"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A printer driver translates computer commands into a language the printer understands.",
      "examTip": "Printer drivers are essential for communication between your computer and printer."
    },
    {
      "id": 71,
      "question": "Which of these is a common type of internet browser?",
      "options": [
        "Google Chrome",
        "Mozilla Firefox",
        "Microsoft Edge",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Google Chrome, Mozilla Firefox, and Microsoft Edge are all common internet browsers.",
      "examTip": "Popular browsers include Chrome, Firefox, Safari, and Edge."
    },
    {
      "id": 72,
      "question": "What is 'email' used for?",
      "options": [
        "Sending and receiving digital messages",
        "Storing files and documents",
        "Running applications",
        "Browsing the internet"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Email is used for sending and receiving digital messages.",
      "examTip": "Email stands for electronic mail and is used for communication."
    },
    {
      "id": 73,
      "question": "Which of these is a storage medium that uses flash memory?",
      "options": [
        "Solid State Drive (SSD)",
        "Hard Disk Drive (HDD)",
        "Optical Disc (DVD)",
        "Floppy Disk"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Solid State Drives (SSDs) use flash memory, making them faster and more durable than HDDs.",
      "examTip": "SSDs use flash memory for quick data access."
    },
    {
      "id": 74,
      "question": "What is the function of a 'monitor'?",
      "options": [
        "To display images and video",
        "To input text",
        "To print documents",
        "To play audio"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A monitor displays images and video from the computer.",
      "examTip": "Monitors are output devices that show you the computer's output."
    },
    {
      "id": 75,
      "question": "Which of these is a type of network protocol?",
      "options": [
        "TCP/IP",
        "HTTP",
        "FTP",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "TCP/IP, HTTP, and FTP are all network protocols used for internet communication.",
      "examTip": "These protocols form the backbone of internet communications."
    },
    {
      "id": 76,
      "question": "What is the purpose of 'data backup'?",
      "options": [
        "To create copies of important data for recovery",
        "To delete unnecessary files",
        "To speed up system performance",
        "To organize files into folders"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Data backup involves creating copies of important data so that it can be recovered in case of loss.",
      "examTip": "Backups are crucial for data recovery in case of hardware failure or data loss."
    },
    {
      "id": 77,
      "question": "Which of these is a common type of computer port for connecting peripherals?",
      "options": [
        "USB port",
        "Ethernet port",
        "HDMI port",
        "Audio port"
      ],
      "correctAnswerIndex": 0,
      "explanation": "USB ports are commonly used to connect peripherals such as keyboards and mice.",
      "examTip": "USB ports are the standard connection for many peripheral devices."
    },
    {
      "id": 78,
      "question": "What is 'cloud computing'?",
      "options": [
        "Storing and accessing data and programs over the internet",
        "Using only desktop applications",
        "Using only wired network connections",
        "Processing data only on local computers"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Cloud computing is about storing and accessing data and programs over the internet.",
      "examTip": "Cloud computing enables access to resources from anywhere via the internet."
    },
    {
      "id": 79,
      "question": "Which of these is a function of a 'web server'?",
      "options": [
        "To host and deliver website content",
        "To browse websites",
        "To send emails",
        "To manage computer hardware"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A web server hosts and delivers website content to users.",
      "examTip": "Web servers provide the content you see when you visit a website."
    },
    {
      "id": 80,
      "question": "What is 'phishing' in cybersecurity?",
      "options": [
        "Deceptive attempts to steal personal information",
        "Improving network speed",
        "A type of antivirus software",
        "Creating strong passwords"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Phishing involves deceptive attempts to steal personal information, often via emails or fake websites.",
      "examTip": "Be cautious of unsolicited emails asking for sensitive data."
    },
    {
      "id": 81,
      "question": "Which component is essential for cooling the CPU in a computer?",
      "options": [
        "Heat sink",
        "Power supply unit (PSU)",
        "RAM module",
        "Network Interface Card (NIC)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A heat sink (usually with a fan) is essential for cooling the CPU by dissipating heat.",
      "examTip": "Effective CPU cooling typically involves a heat sink and fan."
    },
    {
      "id": 82,
      "question": "What is the purpose of 'disk defragmentation'?",
      "options": [
        "To reorganize files on a hard drive for faster access",
        "To delete files permanently",
        "To increase storage capacity",
        "To install new software"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Disk defragmentation reorganizes fragmented data on a hard drive, making file access faster.",
      "examTip": "Defragmenting helps improve the performance of mechanical hard drives."
    },
    {
      "id": 83,
      "question": "Which of these is a common type of optical storage media?",
      "options": [
        "DVD",
        "SSD",
        "HDD",
        "USB flash drive"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DVDs are a common type of optical storage media that use lasers to read and write data.",
      "examTip": "Optical storage includes CDs, DVDs, and Blu-ray discs."
    },
    {
      "id": 84,
      "question": "What is the function of a 'graphics card' or 'GPU'?",
      "options": [
        "To process and display images and video",
        "To manage network connections",
        "To store files and documents",
        "To regulate power supply"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A GPU processes and displays images and video on the monitor.",
      "examTip": "GPUs are vital for rendering graphics in games and video applications."
    },
    {
      "id": 85,
      "question": "Which of the following is a type of computer network based on geographic scale?",
      "options": [
        "Local Area Network (LAN)",
        "USB network",
        "Bluetooth network",
        "Powerline network"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A LAN covers a small geographic area such as an office or home.",
      "examTip": "LANs are limited to small areas, while WANs and MANs cover larger areas."
    },
    {
      "id": 86,
      "question": "What is the purpose of 'cookies' in web browsing?",
      "options": [
        "To store small pieces of data about your browsing activity",
        "To block advertisements",
        "To speed up website loading times",
        "To protect against viruses"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Cookies store small pieces of data about your browsing activity, such as preferences or session identifiers.",
      "examTip": "Cookies help websites remember information about you."
    },
    {
      "id": 87,
      "question": "Which of these is a common type of computer virus?",
      "options": [
        "Trojan horse",
        "Worm",
        "Ransomware",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Trojan horses, worms, and ransomware are all types of malware (often referred to as computer viruses).",
      "examTip": "Malware includes many types, such as Trojans, worms, and ransomware."
    },
    {
      "id": 88,
      "question": "What is the purpose of a 'printer driver'?",
      "options": [
        "To translate computer commands into printer language",
        "To physically install a printer",
        "To refill printer ink cartridges",
        "To troubleshoot network connectivity"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A printer driver translates commands from the computer into a language the printer can understand.",
      "examTip": "Printer drivers act as intermediaries between the computer and the printer."
    },
    {
      "id": 89,
      "question": "Which of these is a common type of internet browser?",
      "options": [
        "Google Chrome",
        "Mozilla Firefox",
        "Microsoft Edge",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Google Chrome, Mozilla Firefox, and Microsoft Edge are all common internet browsers.",
      "examTip": "Popular browsers include Chrome, Firefox, Safari, and Edge."
    },
    {
      "id": 90,
      "question": "What is the purpose of 'email'?",
      "options": [
        "Sending and receiving digital messages",
        "Storing files and documents",
        "Running applications",
        "Browsing the internet"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Email is used for sending and receiving digital messages.",
      "examTip": "Email stands for electronic mail."
    },
    {
      "id": 91,
      "question": "Which of these is a storage medium that uses flash memory?",
      "options": [
        "Solid State Drive (SSD)",
        "Hard Disk Drive (HDD)",
        "Optical Disc (DVD)",
        "Floppy Disk"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSDs use flash memory for data storage.",
      "examTip": "SSDs are faster than HDDs because they use flash memory."
    },
    {
      "id": 92,
      "question":

        "id": 93,
        "question": "A technician needs to install a 2.5in HDD into a desktop. Which adapter or mounting solution is MOST commonly required?",                                               
        options": [
          "3.5in to 2.5in drive bay adapter',
          "USB to eSATA cable",
          "Server rackmount rails",
          "M.2 to PCI Express riser"
        ],
        "correctAnswerIndex": 0,
        "explanation": "A 3.5in to 2.5in drive bay adapter is correct because desktop bays are usually 3.5in. A USB-to-eSATA cable is for external connectivity. Server rack rails are for rack-mounted systems. An M.2 to PCIe riser is for M.2 SSDs, not SATA 2.5in drives. Exam tip: Always match the physical form factor with an adapter or bracket if needed."                      
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
