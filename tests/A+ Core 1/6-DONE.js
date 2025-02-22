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
      "examTip": "Optical storage includes CDs, DVDs, and Blu-ray discs."
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
      "examTip": "Remember, malware comes in many forms including Trojans, worms, or ransomware."
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
      "explanation": "Email is used for sending and receiving digital messages.",
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
      "examTip": "Cloud computing enables access to resources from anywhere via the internet."
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
      "explanation": "Phishing involves deceptive attempts to steal personal information, often via emails or fake websites.",
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
      "explanation": "A heat sink (usually with a fan) is essential for cooling the CPU by dissipating heat.",
      "examTip": "Effective CPU cooling typically involves a heat sink and fan."
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
      "explanation": "Disk defragmentation reorganizes fragmented data on a hard drive, making file access faster.",
      "examTip": "Defragmenting helps improve the performance of mechanical hard drives."
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
      "examTip": "GPUs are vital for rendering graphics in games and video applications."
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
      "explanation": "Trojan horses, worms, and ransomware are all types of malware (often referred to as computer viruses).",
      "examTip": "Malware includes many types, such as Trojans, worms, and ransomware."
    },
    {
      "id": 70,
      "question": "A technician is diagnosing a smartphone that randomly shuts down even though the battery level is above 50%. Which combination of factors is MOST likely responsible?",
      "options": [
        "A faulty battery sensor combined with a recent firmware glitch.",
        "Excessive background app activity and a misconfigured power management setting.",
        "Physical damage to the battery contacts and a degraded battery cell.",
        "All of the above."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Random shutdowns can be caused by multiple factors: a faulty battery sensor or firmware glitch may misreport battery levels; background apps and power management issues can drain resources unexpectedly; physical damage can also lead to power delivery problems. When these issues combine, the result is unpredictable shutdowns.",
      "examTip": "Consider both hardware diagnostics and software settings when troubleshooting intermittent power issues."
    },
    {
      "id": 71,
      "question": "During the assembly of a desktop PC, a technician notices that the system intermittently fails to boot and produces POST beep codes. Which combination of factors could be causing this issue?",
      "options": [
        "Loose or improperly seated memory modules and an incompatible CPU cooler.",
        "Incorrect BIOS settings combined with insufficient PSU wattage.",
        "Poorly seated memory modules, improperly installed CPU, and outdated BIOS firmware.",
        "A defective hard drive and an improperly connected GPU."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Intermittent boot failures and POST beeps often point to hardware installation issues such as loosely seated memory or CPU, compounded by outdated BIOS firmware that cannot correctly interpret hardware changes.",
      "examTip": "Always re-seat critical components and update BIOS firmware to resolve ambiguous POST errors."
    },
    {
      "id": 72,
      "question": "A technician is troubleshooting a laptop that overheats and throttles performance during extended use. Which combination of internal factors is MOST likely contributing to the overheating?",
      "options": [
        "Dust buildup in the cooling vents, a failing fan, and dried-out thermal paste.",
        "Incompatible RAM modules and a malfunctioning SSD.",
        "An outdated graphics driver and insufficient system memory.",
        "A misconfigured power plan and background software updates."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Overheating is most commonly due to physical issues such as dust accumulation, a failing fan that does not move enough air, and degraded thermal paste that no longer transfers heat efficiently from the CPU/GPU.",
      "examTip": "Physical cleaning and reapplication of thermal paste are key steps in addressing thermal throttling."
    },
    {
      "id": 73,
      "question": "A user experiences intermittent Wi-Fi connectivity on their laptop even though other devices on the same network function normally. Which combination of hardware and software issues is MOST likely contributing to the problem?",
      "options": [
        "Outdated wireless adapter drivers, power-saving settings that disable the adapter, and interference from other wireless devices.",
        "A faulty router and an incompatible cable modem.",
        "Misconfigured VPN settings and an overactive firewall on the laptop.",
        "A defective Ethernet port and damaged Wi-Fi antenna."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Intermittent Wi-Fi on one device can be due to outdated drivers, aggressive power management settings that turn off the wireless adapter, and external interference. These combined factors can lead to unreliable connections.",
      "examTip": "Update drivers, check power management settings, and assess environmental interference when troubleshooting wireless issues."
    },
    {
      "id": 74,
      "question": "A technician is configuring a dual-boot system with Windows and Linux on a single hard drive. Which combination of steps is essential to ensure both operating systems install successfully without interfering with each other?",
      "options": [
        "Creating separate primary partitions, installing Windows first, and configuring the GRUB bootloader.",
        "Using the entire drive for Windows and installing Linux on an external drive.",
        "Installing Linux first, then Windows, and using a third-party boot manager.",
        "Creating one large partition and using virtual machines for the other OS."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A best practice for dual-boot systems is to install Windows first (which can overwrite boot settings), then install Linux and use its GRUB bootloader to manage both OS choices. Creating separate partitions ensures each OS has its own space.",
      "examTip": "Always back up data and plan partitioning carefully when setting up a dual-boot configuration."
    },
    {
      "id": 75,
      "question": "A desktop PC exhibits random shutdowns and blue screens under heavy load. Which combination of issues is MOST likely responsible?",
      "options": [
        "Overheating due to inadequate cooling, a failing power supply unit (PSU), and mismatched memory timings.",
        "A corrupt operating system installation and outdated applications.",
        "A faulty keyboard and an underperforming mouse.",
        "Defective optical drive and a misconfigured monitor."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Random shutdowns and blue screens under load are often due to hardware stress: inadequate cooling leads to overheating, a failing PSU cannot supply stable power, and mismatched or misconfigured RAM timings can cause system instability.",
      "examTip": "Monitor temperatures and check power supply ratings as part of troubleshooting high-load system failures."
    },
    {
      "id": 76,
      "question": "A technician is upgrading the RAM in a laptop but finds that the system only recognizes one of the two new memory modules. Which combination of factors should be considered?",
      "options": [
        "Incompatible memory speeds, faulty memory module, and improper seating of the module.",
        "Outdated BIOS, insufficient disk space, and driver conflicts.",
        "A misconfigured operating system and an overloaded USB bus.",
        "Interference from external devices and an outdated graphics card."
      ],
      "correctAnswerIndex": 0,
      "explanation": "When a new memory module is not recognized, the technician should check that both modules have compatible speeds, that each is properly seated, and that one of them isn’t defective.",
      "examTip": "Test each memory stick individually and check the system BIOS for memory configuration."
    },
    {
      "id": 77,
      "question": "A user reports that their monitor displays a flickering image and intermittent color distortions. Which combination of troubleshooting steps should be prioritized?",
      "options": [
        "Check the cable connections, update the graphics driver, test with an alternate monitor, and verify the refresh rate settings.",
        "Reinstall the operating system, replace the CPU, and update the motherboard BIOS.",
        "Replace the keyboard, test the power supply, and update the printer driver.",
        "Disable all background applications and change the desktop wallpaper."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A flickering monitor with color distortions may result from a loose or damaged video cable, outdated or corrupt graphics drivers, or an incorrect refresh rate. Testing with a different monitor can help isolate the issue.",
      "examTip": "Always start with the simplest fixes—cable and driver checks—before considering hardware replacement."
    },
    {
      "id": 78,
      "question": "A technician notices that a PC's USB ports are not functioning correctly. Which combination of potential causes is MOST likely?",
      "options": [
        "Outdated chipset drivers, disabled USB controller in the BIOS, and aggressive power management settings in the OS.",
        "A failing hard drive and a misconfigured printer.",
        "A virus infection and an overloaded CPU.",
        "Incorrect video settings and a defective monitor."
      ],
      "correctAnswerIndex": 0,
      "explanation": "When USB ports fail, common causes include outdated or corrupt chipset drivers, BIOS settings that disable the USB controller, and power management features that shut down the ports to save energy.",
      "examTip": "Verify BIOS settings and update drivers as first steps when USB ports malfunction."
    },
    {
      "id": 79,
      "question": "A user finds that their laptop's touchpad is unresponsive while an external mouse is connected, even though the settings appear correct. Which combination of factors could be contributing to this behavior?",
      "options": [
        "A feature that automatically disables the touchpad when an external device is detected, an outdated touchpad driver, and a BIOS setting that turns off the internal pointing device.",
        "A defective external mouse and a damaged USB port.",
        "Overheating of the CPU and low battery levels.",
        "Misconfigured audio settings and an outdated operating system."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Many laptops include a setting to disable the touchpad when an external mouse is connected. Additionally, outdated drivers or a BIOS option could be causing the issue.",
      "examTip": "Check both the OS settings and BIOS configuration when the internal touchpad stops working in the presence of an external mouse."
    },
    {
      "id": 80,
      "question": "A technician is tasked with setting up a secure wireless network for a small office. Which combination of settings is MOST essential for ensuring network security?",
      "options": [
        "Changing the default SSID, enabling WPA2 or WPA3 encryption, disabling WPS, and updating the router firmware.",
        "Enabling MAC address filtering only.",
        "Using a weak pre-shared key to ensure compatibility with all devices.",
        "Broadcasting the network name and enabling guest networking by default."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A secure wireless network relies on changing default settings, using strong encryption methods (WPA2/3), disabling potentially insecure features like WPS, and keeping firmware up to date.",
      "examTip": "Always use a strong, unique passphrase and disable unnecessary features to protect your wireless network."
    },
    {
      "id": 81,
      "question": "A technician needs to configure a network printer so that multiple users can access it. Which combination of configuration steps is MOST crucial?",
      "options": [
        "Assigning the printer a static IP address, installing the correct printer driver on each client, configuring printer sharing, and ensuring proper network firewall settings.",
        "Installing the printer on a single workstation and then sharing that computer's internet connection.",
        "Connecting the printer via USB to one client and relying on that client to print for everyone.",
        "Enabling Bluetooth printing and using a mobile app."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Network printers should have a static IP address so that clients can reliably locate them. Installing the proper driver, enabling sharing, and configuring network permissions are all critical steps.",
      "examTip": "Plan your network printer deployment by setting a static IP and ensuring all clients have the correct drivers installed."
    },
    {
      "id": 82,
      "question": "During troubleshooting, a technician suspects that a desktop's frequent freezes are due to a failing hard drive. Which combination of diagnostic tests and observations is MOST effective?",
      "options": [
        "Running SMART diagnostics, checking for bad sectors with disk scanning tools, listening for unusual noises, and monitoring system temperatures.",
        "Reinstalling the operating system and updating the graphics driver.",
        "Testing the power supply unit and checking for overheating of the CPU.",
        "Disabling unnecessary startup programs and updating the BIOS."
      ],
      "correctAnswerIndex": 0,
      "explanation": "SMART diagnostics and disk scanning tools are designed to detect failing hard drives by identifying bad sectors and other issues, while unusual noises and temperature spikes support the diagnosis.",
      "examTip": "Use multiple diagnostic tools to confirm a suspected hard drive failure before data recovery procedures."
    },
    {
      "id": 83,
      "question": "A user complains that their system has become significantly slower after installing new software. Which combination of troubleshooting steps should be performed to identify the cause?",
      "options": [
        "Checking for high CPU or memory usage in Task Manager, reviewing startup programs, scanning for malware, and examining disk fragmentation.",
        "Reinstalling the operating system immediately.",
        "Replacing the hard drive without further investigation.",
        "Disconnecting all peripherals and then reconnecting them one at a time."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Performance issues after new software installations can be due to excessive resource usage, unwanted startup programs, malware, or disk fragmentation. A systematic check using Task Manager and diagnostic tools is essential.",
      "examTip": "Begin troubleshooting by identifying processes that use excessive resources and by scanning for malware."
    },
    {
      "id": 84,
      "question": "A technician upgrades a desktop with a new high-performance CPU, but after installation the system fails to boot. Which combination of issues is MOST likely the cause?",
      "options": [
        "An incompatible motherboard BIOS, improper CPU seating, and missing thermal paste application.",
        "A defective power cable and a failed USB port.",
        "Outdated antivirus software and misconfigured network settings.",
        "An incorrectly formatted hard drive and a broken monitor cable."
      ],
      "correctAnswerIndex": 0,
      "explanation": "When a new CPU is installed, the motherboard must support it (often requiring a BIOS update), the CPU must be properly seated with correct thermal paste application, or else the system may not boot.",
      "examTip": "Always verify CPU–motherboard compatibility and ensure proper installation techniques when upgrading a CPU."
    },
    {
      "id": 85,
      "question": "A user experiences audio distortions and intermittent sound dropouts during video calls. Which combination of factors is MOST likely responsible?",
      "options": [
        "Outdated audio drivers, interference from other wireless devices, malfunctioning headset jack, and improper audio settings.",
        "A failing hard drive and outdated operating system.",
        "An incompatible keyboard and a broken mouse.",
        "A misconfigured video card and incorrect monitor settings."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Audio distortions and dropouts are commonly caused by driver issues, hardware problems with the audio port or headset, and interference from wireless devices affecting audio peripherals.",
      "examTip": "Begin by updating audio drivers and checking both hardware connections and wireless interference."
    },
    {
      "id": 86,
      "question": "A technician is tasked with securing a laptop against potential malware attacks. Which combination of best practices is MOST effective?",
      "options": [
        "Installing reputable antivirus software, keeping the operating system and drivers up to date, enabling the firewall, and practicing safe browsing habits.",
        "Disabling the firewall and relying solely on user caution.",
        "Installing multiple antivirus programs simultaneously for redundancy.",
        "Removing all network connectivity to prevent any attack."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A layered security approach—combining updated antivirus software, OS patches, firewall protection, and cautious user behavior—is the most effective way to protect against malware.",
      "examTip": "Regular updates and a multi-layered security strategy are key to defending against modern malware threats."
    },
    {
      "id": 87,
      "question": "A company plans to migrate its desktop applications to a virtual desktop infrastructure (VDI). Which combination of factors must be evaluated to ensure a successful transition?",
      "options": [
        "Network bandwidth requirements, hardware compatibility, virtualization software capabilities, and user training/support.",
        "Only the cost of new hardware.",
        "The color and design of the virtual desktops.",
        "The number of USB ports on each workstation."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A successful VDI migration requires evaluating network capacity to handle virtual traffic, ensuring existing hardware is compatible, verifying that the virtualization solution meets performance needs, and preparing end users through training and support.",
      "examTip": "A thorough assessment of infrastructure, software capabilities, and user readiness is essential when moving to VDI."
    },
    {
      "id": 88,
      "question": "After a recent Windows update, several peripheral devices are no longer recognized by a laptop. Which combination of troubleshooting steps is MOST appropriate?",
      "options": [
        "Rolling back the Windows update, updating the device drivers, checking BIOS settings, and testing the peripherals on another system.",
        "Reinstalling all applications and formatting the hard drive immediately.",
        "Replacing the laptop's battery and power adapter.",
        "Ignoring the issue since it will likely resolve itself."
      ],
      "correctAnswerIndex": 0,
      "explanation": "When peripheral devices stop working after an update, it is wise to roll back the update or update drivers, check BIOS settings (which may have been reset), and test the devices elsewhere to isolate the issue.",
      "examTip": "Always verify driver compatibility and BIOS configurations after an operating system update."
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
      "question": "A corporate network is experiencing intermittent connectivity issues, slow data transfers, and occasional packet loss. The network consists of multiple VLANs and a mix of wired and wireless access points. Which combination of issues is MOST likely contributing to these symptoms?",
      "options": [
        "A faulty switch port combined with outdated network drivers on client machines.",
        "Network congestion due to improper VLAN segmentation and a failing router interface.",
        "Interference from unauthorized wireless access points and misconfigured QoS settings on the router.",
        "Physical cable damage in the backbone combined with an overloaded firewall."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Improper VLAN segmentation can lead to broadcast storms and misrouted traffic, while a failing router interface can drop packets—together causing intermittent connectivity and slow data transfers.",
      "examTip": "Evaluate both network configuration and hardware performance when diagnosing connectivity issues."
    },
    {
      "id": 93,
      "question": "A technician needs to install a 2.5in HDD into a desktop system. Which adapter or mounting solution is MOST commonly required?",
      "options": [
        "3.5in to 2.5in drive bay adapter",
        "USB to eSATA cable",
        "Server rackmount rails",
        "M.2 to PCI Express riser"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Desktop bays are typically designed for 3.5in drives, so a 3.5in to 2.5in drive bay adapter is needed for 2.5in HDDs.",
      "examTip": "Always match the drive size to the bay or use the proper adapter to ensure a secure fit."
    },
    {
      "id": 94,
      "question": "A technician wants to install a Linux virtual machine on top of an existing Windows 10 operating system. Which hypervisor type is required?",
      "options": [
        "Type 1 (bare-metal) hypervisor",
        "Type 2 (hosted) hypervisor",
        "Container-based virtualization",
        "Dedicated hardware emulator card"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A Type 2 (hosted) hypervisor runs on top of an existing operating system, which is necessary when installing a VM on a Windows 10 desktop.",
      "examTip": "Examples include VMware Workstation and Oracle VirtualBox for desktop virtualization."
    },
    {
      "id": 95,
      "question": "Which of the following addresses is a valid IPv6 link-local address typically starting with FE80::?",
      "options": [
        "169.254.0.10",
        "192.168.1.10",
        "FE80::1C2B:3FFF:FE4A:1234",
        "FEC0::/10"
      ],
      "correctAnswerIndex": 2,
      "explanation": "FE80::1C2B:3FFF:FE4A:1234 is a properly formatted IPv6 link-local address. The others are either IPv4 or not in the correct range.",
      "examTip": "IPv6 link-local addresses always begin with FE80:: and are used for local network communications."
    },
    {
      "id": 96,
      "question": "A user cannot access internal network resources when plugged into a specific wall jack, even though the cable tests fine. Which tool helps confirm the jack’s wiring path to the switch port?",
      "options": [
        "Punchdown tool",
        "Tone generator and probe",
        "Multimeter",
        "Crimper"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A tone generator and probe is used to trace the wiring path through walls and locate the corresponding switch port.",
      "examTip": "Toner/probe kits are invaluable when mapping network cabling in large or complex installations."
    },
    {
      "id": 97,
      "question": "A user wants to connect a smartphone to an external display wirelessly for presentations. Which technology is most commonly used for screen mirroring on Android devices?",
      "options": [
        "RDP",
        "Bluetooth tethering",
        "Miracast",
        "USB tethering"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Miracast is a standard for wireless screen mirroring on Android (and other) devices, whereas the other options are used for different purposes.",
      "examTip": "For Android screen mirroring, Miracast (or Chromecast-based solutions) is typically used."
    },
    {
      "id": 98,
      "question": "Which scenario is MOST likely if a RAID 5 array loses two drives simultaneously?",
      "options": [
        "The array continues to function normally.",
        "All data remains intact due to mirroring.",
        "Data is lost until at least one drive is replaced and rebuilt.",
        "No impact because parity can rebuild both drives at once."
      ],
      "correctAnswerIndex": 2,
      "explanation": "RAID 5 is designed to tolerate a single drive failure. Losing two drives exceeds its fault tolerance, leading to array failure and potential data loss.",
      "examTip": "Understand the limitations of RAID 5 and always maintain current backups."
    },
    {
      "id": 99,
      "question": "Which cloud computing model involves hosting desktop environments in the cloud, allowing users to stream a full operating system session remotely?",
      "options": [
        "IaaS",
        "PaaS",
        "DaaS",
        "SaaS"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Desktop as a Service (DaaS) provides virtual desktops that are streamed to the end user from the cloud.",
      "examTip": "DaaS is a key option for organizations looking to provide remote desktop experiences without local hardware investments."
    },
    {
      "id": 100,
      "question": "A laptop displays artifacts and random color blocks during gaming. Which is the MOST likely cause?",
      "options": [
        "Display cable not seated",
        "Video driver or dedicated GPU hardware failure",
        "Low battery threshold set in BIOS",
        "WiFi antenna interference"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Artifacts and color blocks on the screen are typically due to issues with the video driver or a failing dedicated GPU, especially under high load conditions.",
      "examTip": "Check for overheating, update video drivers, and test with another display cable when diagnosing graphics issues."
    }
  ]
});
