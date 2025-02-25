db.tests.insertOne({
  "category": "aplus",
  "testId": 6,
  "testName": "A+ Core 1 Practice Test #6 (Formidable)",
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
      "question": "A user reports random bursts of static electricity when touching their high-end gaming desktop, which sometimes reboots the system. Which is the MOST likely underlying issue?",
      "options": [
        "Insufficient power supply wattage for the GPU",
        "Improper grounding in the PC case or power outlet",
        "Corrupted operating system files preventing normal boot",
        "A failing CPU cooler causing system overheating"
      ],
      "correctAnswerIndex": 1,
      "explanation": "If a desktop is not properly grounded—either by the case’s internal standoffs or by the building’s electrical system—electrostatic discharges can occur and cause sporadic reboots or system instability.",
      "examTip": "Always ensure the PC case, power supply, and building wiring are correctly grounded to avoid ESD-related reboots."
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
      "question": "A technician wants to test a newly installed liquid-cooling loop in a custom PC without risking immediate component damage. Which practice is MOST appropriate before powering the full system?",
      "options": [
        "Remove the RAM and power on to see if any POST codes occur.",
        "Use a dedicated PSU jumper to run the liquid-cooling pump in a ‘leak test’ for several hours.",
        "Install the graphics card and run a stress test at maximum load for 24 hours.",
        "Enable Safe Mode in BIOS to reduce voltage across the CPU."
      ],
      "correctAnswerIndex": 1,
      "explanation": "When assembling a custom liquid-cooling loop, it’s common to perform a leak test by jumping the PSU (so only the pump runs) for several hours. This ensures no coolant leaks before powering all sensitive components.",
      "examTip": "Always leak-test new liquid-cooling setups offline to avoid hardware damage from unexpected leaks."
    },
    {
      "id": 14,
      "question": "A mobile workstation includes a unique embedded micro-lidar sensor on the lid that scans short-range 3D shapes for CAD software. The sensor stops working after a BIOS update. Which step is MOST likely to fix this?",
      "options": [
        "Enable the micro-lidar device in the advanced BIOS peripherals menu.",
        "Downgrade to a 32-bit operating system for better sensor driver compatibility.",
        "Perform a full system reformat to reset hardware resources.",
        "Disable all integrated devices except the micro-lidar sensor in Device Manager."
      ],
      "correctAnswerIndex": 0,
      "explanation": "After certain firmware updates, specialized or less-common embedded peripherals can be disabled by default. Re-enabling them in advanced BIOS/UEFI settings usually restores functionality.",
      "examTip": "When new firmware resets default configurations, always re-check any custom or unusual integrated devices."
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
      "question": "A specialized color 3D printer uses advanced resin layers cured by UV lasers. Which process step is unique to this printing technology compared to traditional laser or inkjet printers?",
      "options": [
        "Charging a photoconductor drum before transferring toner",
        "Heating a thermal ribbon to imprint wax onto the paper",
        "Solidifying liquid resin by targeted ultraviolet exposure",
        "Utilizing a high-voltage corona wire for static adhesion"
      ],
      "correctAnswerIndex": 2,
      "explanation": "In resin-based 3D printing, liquid resin is cured layer-by-layer using UV light. This differs fundamentally from toner or ink processes in traditional laser or inkjet printers.",
      "examTip": "3D resin printing relies on UV curing to harden each layer—no fusing drum or thermal heads."
    },
    {
      "id": 17,
      "question": "A workshop desktop includes a rugged helium-filled HDD designed for high-capacity storage. The user reports the drive repeatedly spins down under moderate load, causing file transfers to stall. Which is the MOST likely culprit?",
      "options": [
        "Excessive VRAM usage on the dedicated GPU",
        "The drive’s helium chamber has leaked and lowered RPM speed",
        "An over-aggressive power management setting forcing spin-down",
        "A failing CPU cooler triggers system thermal throttling"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Even specialized helium HDDs can be subject to OS power-saving policies that spin down the drive too quickly. This leads to stalling or slow file transfers.",
      "examTip": "Check OS or firmware power settings that may prematurely spin down HDDs, especially in high-capacity drives."
    },
    {
      "id": 18,
      "question": "A traveling user needs secure point-of-sale transactions on a tablet with built-in NFC hardware. Which additional wireless security measure is MOST critical for safeguarding these tap-to-pay features?",
      "options": [
        "Using WPA3 encryption on the tablet’s Wi-Fi connection",
        "Enabling Bluetooth tethering to a trusted smartphone",
        "Installing a second antivirus program for redundancy",
        "Disabling all DNS over HTTPS (DoH) protocols"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Tap-to-pay (NFC) usage should be supplemented by robust Wi-Fi security (WPA3) when the device connects to networks. WPA3 significantly reduces the risk of eavesdropping or traffic hijacking that could compromise transactions.",
      "examTip": "Keep Wi-Fi encryption at the highest standard (like WPA3) to protect sensitive NFC financial transactions."
    },
    {
      "id": 19,
      "question": "A laptop’s BIOS supports a novel “Adaptive Quad-Core Heterogeneous Computing” feature, showing two performance cores and two specialized low-power cores. Which function does this design MOST closely resemble?",
      "options": [
        "It mirrors dual-boot functionality for separate OS partitions.",
        "It parallels CPU virtualization from a Type 1 hypervisor.",
        "It mimics the ‘big.LITTLE’ concept found in mobile ARM CPUs.",
        "It replicates purely symmetrical multiprocessing across all cores."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Heterogeneous CPU designs, often branded as big.LITTLE in ARM architectures, pair high-performance cores with energy-efficient ones to balance power consumption and compute needs.",
      "examTip": "Mixed-core setups handle background tasks on low-power cores while performance cores handle heavier loads."
    },
    {
      "id": 20,
      "question": "A user wants to connect an external VR headset that demands simultaneous 8K video feed and data transfer on a single cable. Which connection standard is REQUIRED for stable operation?",
      "options": [
        "HDMI 2.0 with Ethernet channel",
        "DisplayPort 1.2 without MST",
        "Thunderbolt 4 (USB-C) with full 40 Gbps bandwidth",
        "USB 3.1 Gen 1 Type-A"
      ],
      "correctAnswerIndex": 2,
      "explanation": "To support an 8K VR feed plus data on one cable, Thunderbolt 4’s 40 Gbps capacity is necessary. Other standards don’t reliably provide the combined throughput needed.",
      "examTip": "High-bandwidth VR solutions often need Thunderbolt-level speeds, far beyond typical USB or older HDMI specs."
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
      "question": "A next-generation motherboard includes a built-in quantum-safe co-processor for encryption. Which scenario BEST highlights why this co-processor could be valuable?",
      "options": [
        "Decompressing ZIP archives faster than a standard CPU",
        "Protecting data against future quantum-based cryptographic attacks",
        "Displaying multiple 8K video outputs without a GPU",
        "Reducing system temperature by offloading random number generation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Quantum-safe or post-quantum cryptography is designed to resist decryption attempts by quantum computers, ensuring long-term data confidentiality.",
      "examTip": "As quantum computing advances, specialized hardware can safeguard encryption algorithms against new attack vectors."
    },
    {
      "id": 34,
      "question": "A dual-screen laptop features an auxiliary OLED panel above the keyboard for specialized shortcuts. The panel stays blank after a Windows update. Which step is MOST likely to restore its functionality?",
      "options": [
        "Replace the main battery and perform a BIOS factory reset.",
        "Install the manufacturer-specific auxiliary panel driver or utility software.",
        "Disable integrated graphics in Device Manager to force external GPU usage.",
        "Switch the laptop to a Linux distribution that supports multiple displays."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Unique hardware like an auxiliary OLED panel often relies on specialized drivers or vendor utilities. After major OS updates, reinstallation of these custom drivers is often necessary.",
      "examTip": "Always check manufacturer support software for non-standard hardware panels or input surfaces."
    },
    {
      "id": 35,
      "question": "A newly released AR headset requires custom Windows software for spatial scanning. After installation, the system lags severely. Which factor is MOST likely responsible?",
      "options": [
        "The AR software demands real-time depth mapping that overwhelms a low-spec CPU/GPU combo.",
        "The operating system detected a virus in the scanning driver and quarantined the entire package.",
        "The user left the AR headset in direct sunlight, causing sensor calibration errors.",
        "Bluetooth was disabled, preventing the AR headset from pairing properly."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Augmented Reality scanning often involves heavy CPU/GPU usage for real-time depth mapping. Low-spec hardware or integrated graphics may struggle to handle these tasks smoothly.",
      "examTip": "Check system requirements for advanced AR or VR applications—they can be far higher than typical office apps."
    },
    {
      "id": 36,
      "question": "A touchscreen laptop includes a mini detachable e-ink display on its lid for quick notes. After an OS update, pen input on the e-ink panel fails. Which fix is MOST likely?",
      "options": [
        "Lower the display resolution to 1024x768 for e-ink compatibility.",
        "Install or update the e-ink panel’s pen digitizer driver from the manufacturer’s support site.",
        "Set the Windows power plan to High Performance mode.",
        "Disable the integrated webcam to free up I/O resources."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Detachable or secondary e-ink displays with pen input usually need a specialized driver. OS updates can disrupt these custom components, requiring a driver reinstallation or update.",
      "examTip": "When unusual hardware breaks after updates, always look for niche driver updates from the OEM."
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
      "question": "A specialized gaming cafe uses a local fiber ring to connect all PCs at 10 Gbps. Which best describes this network design’s physical or logical topology characteristic?",
      "options": [
        "It represents a simplistic bus topology with daisy-chained repeaters.",
        "It is a ring-based layout allowing symmetrical high-speed access for each node.",
        "It uses star topology with each PC connecting to a single central switch.",
        "It is a purely mesh network requiring each PC to have multiple NICs."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A ring-based fiber layout can provide uniform, high-speed connections, especially if the ring is used to guarantee symmetrical throughput among nodes. This differs from more common star-based LANs.",
      "examTip": "While star LANs are typical, ring-based topologies can appear in specialized or high-performance setups."
    },
    {
      "id": 50,
      "question": "A new browser extension logs user credentials for advanced single sign-on (SSO) across multiple apps. Which serious privacy concern could this extension introduce?",
      "options": [
        "It might reduce image rendering quality on websites.",
        "It can store plain-text passwords or transmit them insecurely, risking credential theft.",
        "It blocks automatic OS updates, causing system instability.",
        "It halts cookies from loading properly, disabling all web logins."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Password or credential-management extensions must securely handle user data; if they store or send passwords in plain text, attackers can easily intercept or steal them.",
      "examTip": "Always ensure password managers or SSO extensions encrypt credentials at rest and in transit."
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
      "examTip": "Remember, malware includes many types such as Trojan horses, worms, and ransomware."
    },
    {
      "id": 52,
      "question": "An industrial label printer uses advanced near-field drying ink to produce smudge-proof tags instantly. Which unusual driver requirement might this printer need?",
      "options": [
        "A real-time temperature control interface to manage ink drying speed",
        "2D GPU acceleration for rendering complex spreadsheets",
        "Wireless channel bonding over 802.11ac",
        "Continuous fuser calibration identical to a laser printer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Near-field drying printers often incorporate real-time temperature or UV-curing controls that are handled by specialized driver modules. Standard text drivers won’t account for these parameters.",
      "examTip": "Some industrial printers require specialized driver features to control hardware beyond simple page layout."
    },
    {
      "id": 53,
      "question": "A VR software suite includes a built-in micro-browser that scans real-world objects for augmented overlays. Which factor most differentiates it from standard desktop browsers?",
      "options": [
        "It uses real-time camera feeds for ‘browsing’ physical objects instead of web URLs.",
        "It cannot display text or images, only plain shapes.",
        "It is restricted to 2D rendering with no dynamic elements.",
        "It only runs on macOS and not on Windows or Linux."
      ],
      "correctAnswerIndex": 0,
      "explanation": "In AR/VR environments, a ‘browser’ might interpret real-world objects via camera input, rendering overlays or tooltips in place of conventional HTML/URL navigation.",
      "examTip": "Extended-reality browsers revolve around environment scanning rather than typical webpage fetching."
    },
    {
      "id": 54,
      "question": "A new collaboration device can send short secure messages via a proprietary protocol akin to email, but it uses blockchain-based validation. Which advantage does this approach MOST likely offer?",
      "options": [
        "Eliminates the need for any operating system at all",
        "Ensures each message has a tamper-evident record, preventing unauthorized modification",
        "Allows the user to revert to an older firmware for advanced features",
        "Drastically reduces the device’s power consumption to near-zero"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Blockchain-based messaging can store each message transaction in a tamper-evident ledger, making unauthorized modification or forgery far more difficult.",
      "examTip": "Blockchain’s immutability can enhance security for specialized messaging beyond standard email protocols."
    },
    {
      "id": 55,
      "question": "Which of the following is a type of computer virus?",
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
      "question": "A newly proposed enterprise standard uses a ‘stream-based handshake’ to replace TCP’s three-way SYN/ACK exchange. Which potential benefit might this approach offer?",
      "options": [
        "Faster connection setup and reduced latency for short-lived data exchanges",
        "Complete backward compatibility with all legacy TCP/IP stacks",
        "Elimination of the need for IP addressing or routing",
        "Encryption without the need for certificates or keys"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Protocols that reduce multi-step handshakes can lower latency, especially beneficial in scenarios with frequent, short connections. However, they typically require new or updated network stacks.",
      "examTip": "Cutting down handshake steps can speed up data flows, but adoption depends on system support for the new protocol."
    },
    {
      "id": 58,
      "question": "An enterprise IT team plans to replicate critical data to a floating underwater datacenter module for disaster recovery. Which major challenge must their backup solution address?",
      "options": [
        "Ensuring the modules remain within Wi-Fi range of the main office",
        "Accommodating high-latency or intermittently connected submarine fiber links",
        "Preventing sharks from damaging the standard Cat 5 cables",
        "Requiring staff to physically dive underwater to swap tapes"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Underwater or subsea datacenters might involve unique connectivity constraints, such as high-latency or less-stable fiber links. Backup solutions must handle potential link disruptions and latencies.",
      "examTip": "Unconventional data center deployments demand robust networking and resilience against unpredictable link conditions."
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
      "question": "An office receives repeated phone calls claiming to be from ‘IT Support’ demanding remote access for urgent patches. Which approach BEST describes this threat vector?",
      "options": [
        "Tailgating",
        "Shoulder surfing",
        "Physical intrusion",
        "Vishing (voice phishing)"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Vishing is a form of phishing conducted over the phone, where attackers pretend to be legitimate to trick users into revealing sensitive info or granting remote access.",
      "examTip": "Always verify callers claiming to be IT or support; legitimate IT staff rarely cold-call demanding immediate remote entry."
    },
    {
      "id": 63,
      "question": "A high-performance workstation uses a liquid metal compound instead of thermal paste for the CPU. What additional consideration is MOST crucial with this type of cooling?",
      "options": [
        "Ensuring the liquid metal never contacts aluminum surfaces to avoid corrosion",
        "Underclocking the CPU by 50% to reduce operating temperatures",
        "Using dedicated VRAM to offload CPU heat",
        "Disabling all CPU turbo modes in BIOS"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Liquid metal compounds (often gallium-based) can corrode or react with certain metals, especially aluminum. Manufacturers usually recommend copper-based heatsinks and care during application.",
      "examTip": "Liquid metal can yield excellent temps, but handle carefully to prevent damage or chemical reactions."
    },
    {
      "id": 64,
      "question": "A server uses multi-tier caching across numerous SSDs. Which new approach might render traditional disk defragmentation unnecessary or counterproductive?",
      "options": [
        "Advanced TRIM and wear-leveling algorithms that optimize SSD data placement automatically",
        "Locking the drive in read-only mode for improved performance",
        "Switching from MBR to GPT partition tables",
        "Mounting the filesystem as a read-write NFS share"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Modern SSDs rely on internal wear-leveling and TRIM commands to efficiently organize data. Manually defragging can cause unnecessary writes, reducing SSD lifespan.",
      "examTip": "SSD best practices typically advise against frequent defragmentation—it does little good and adds wear."
    },
    {
      "id": 65,
      "question": "A proprietary high-capacity disc format uses a multi-layer fluorescent substrate read by a specialized laser. Which advantage does it claim over standard DVD or Blu-ray?",
      "options": [
        "Magnetic data encoding for indefinite rewrites",
        "Less sensitivity to surface scratches due to deeper layer reading",
        "Ability to read discs using standard DVD drives without firmware updates",
        "Eliminates any need for a spinning motor, making the disc purely electronic"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Some experimental optical formats incorporate fluorescent or multi-layer technology that can read deeper data layers more reliably than standard discs, potentially resisting scratches better.",
      "examTip": "Innovative optical formats sometimes push capacity via multiple reflective or fluorescent layers."
    },
    {
      "id": 66,
      "question": "A new GPU model features a built-in neural engine for machine learning tasks. Which benefit might this provide compared to a traditional GPU pipeline?",
      "options": [
        "Reduced need for any system memory when rendering 3D scenes",
        "Faster inference for AI-driven features like real-time super-resolution or object detection",
        "Incompatibility with standard DX12 or Vulkan APIs, ensuring no backwards support",
        "Automatic CPU overclocking by offloading all arithmetic to the GPU"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Specialized ML hardware inside a GPU can accelerate AI-related workloads, such as super-resolution, upscaling, or object detection, beyond standard shader pipelines.",
      "examTip": "Modern GPUs often contain dedicated ML or tensor cores to boost AI performance in real-time applications."
    },
    {
      "id": 67,
      "question": "A microbranch office sets up a wireless bridging system covering multiple blocks. This arrangement merges each building into one logical network. Which best describes this design?",
      "options": [
        "A local star topology connecting all laptops via USB",
        "A wide-area mesh bridging scheme that emulates a larger LAN domain",
        "A ring network that tunnels data using fiber to each building",
        "Single-hop Wi-Fi direct connections with no central router"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A distributed wireless bridging solution can create a larger unified network by meshing building segments together, effectively treating them as one extended LAN domain across several blocks.",
      "examTip": "Wireless mesh or bridging extends a LAN’s coverage area across multiple physical locations."
    },
    {
      "id": 68,
      "question": "A specialized browser plugin stores user web session data in an encrypted hardware token rather than a typical cookie on disk. Which advantage does this method offer?",
      "options": [
        "Reduces network latency by half for all websites",
        "Protects session data from malware scanning local storage",
        "Forces the browser to run only in private/incognito mode",
        "Eliminates the need for two-factor authentication"
      ],
      "correctAnswerIndex": 1,
      "explanation": "By storing session info in an external hardware token (e.g., a secure dongle), attackers cannot simply read or modify cookies on the user’s drive, raising the bar for session hijacking.",
      "examTip": "Hardware-backed session storage can thwart many cookie-based attacks by isolating credentials from the filesystem."
    },
    {
      "id": 69,
      "question": "Which of the following is a type of computer virus?",
      "options": [
        "Trojan horse",
        "Worm",
        "Ransomware",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Trojan horses, worms, and ransomware are all types of computer viruses/malware.",
      "examTip": "Malware includes many types, such as Trojan horses, worms, and ransomware."
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
      "question": "A corporate kiosk uses a custom “information browser” to display dynamic campus maps. Which feature might this kiosk browser have that typical browsers lack?",
      "options": [
        "Full support for online multiplayer gaming",
        "A locked-down navigation mode that prevents users from entering arbitrary URLs",
        "Unrestricted file system access to user home directories",
        "Built-in cryptocurrency mining for background revenue"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Public-facing kiosks often restrict user navigation to a limited set of pages or features. Typical web browsers do not forcibly limit URL entry without additional policy or kiosk mode configurations.",
      "examTip": "Kiosk/browser solutions typically enforce a locked environment to prevent users from accessing unauthorized sites."
    },
    {
      "id": 90,
      "question": "A secure enterprise messaging platform is introduced as an ‘email alternative’ but includes ephemeral channels that auto-delete after reading. Which advantage does this specifically provide over standard email?",
      "options": [
        "Seamless printing for permanent archives",
        "Guaranteed offline access to all historical threads",
        "Immediate compliance with all retention regulations",
        "A reduced data footprint and minimal recoverability if messages are compromised"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Ephemeral messaging drastically cuts persistent storage of communications, minimizing the data footprint and limiting the window for forensic recovery in case of a breach.",
      "examTip": "Ephemeral or self-destructing messages can improve privacy but may conflict with certain archival requirements."
    },
    {
      "id": 91,
      "question": "A cutting-edge external drive claims to use ‘DNA-based’ data storage. Which aspect would MOST differentiate it from ordinary flash-based SSDs?",
      "options": [
        "It physically appears identical to a 3.5-inch HDD, including spinning platters",
        "Data is encoded in synthetic DNA strands and read by a specialized molecular sequencer",
        "It must be defragmented daily to maintain read speeds",
        "The device is only readable by Windows XP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "DNA data storage uses synthetic DNA sequences to store digital information at extremely high density. Reading requires specialized sequencing, unlike typical electronic flash memory.",
      "examTip": "Exotic storage technologies (like DNA-based) promise massive density but require unique read/write mechanisms."
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
