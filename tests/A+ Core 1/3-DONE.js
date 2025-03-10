db.tests.insertOne({
  "category": "aplus",
  "testId": 3,
  "testName": "CompTIA A+ Core 1 (1101) Practice Test #3 (Easy)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A technician needs to ensure that inbound web traffic can reach a company server. Which port should be enabled on the firewall for standard HTTP traffic?",
      "options": [
        "Port 8080",
        "Port 443",
        "Port 80",
        "Port 21"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Port 80 is the default port for unencrypted web traffic using HTTP. Port 8080 is an alternative HTTP port often used when port 80 is unavailable, Port 443 is for HTTPS (secure web traffic), and Port 21 is for FTP (file transfers). Network administrators must configure firewalls to allow traffic on appropriate ports for specific services.",
      "examTip": "Remember that HTTP is the foundation of the web and its default port, 80, is crucial for basic internet communication."
    },
    {
      "id": 2,
      "question": "A network administrator is installing cabling throughout an office building for a new network. Which cable type provides the best balance of cost, performance, and compatibility with existing infrastructure?",
      "options": [
        "Cat 5e Ethernet cable",
        "Fiber optic cable",
        "Cat 7 Ethernet cable",
        "Coaxial cable"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Cat 5e Ethernet cables provide the best balance of cost and performance for most office environments, supporting speeds up to 1 Gbps. Fiber optic offers higher speeds but is significantly more expensive, Cat 7 is overkill for standard office use, and coaxial is outdated for modern networks. The choice of cabling directly impacts both current network performance and future upgrade possibilities.",
      "examTip": "Ethernet cables (particularly Cat 5e and Cat 6) are workhorses for office networks. Know their characteristics, speed capabilities, and distance limitations."
    },
    {
      "id": 3,
      "question": "A user reports that their computer is running slowly when multiple applications are open but improves after a restart. Which component would you recommend upgrading first?",
      "options": [
        "CPU cache",
        "RAM",
        "Hard drive to SSD",
        "Graphics card"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RAM (Random Access Memory) is the volatile memory that holds actively running programs and data. Insufficient RAM causes system slowdowns when multiple applications are running. CPU cache affects processing speed but is not upgradeable separately, an SSD would help with load times but not necessarily with running multiple applications, and a graphics card primarily affects visual rendering. Memory constraints often manifest as gradually decreasing performance that temporarily improves after a restart.",
      "examTip": "Always remember that RAM functions as the computer's working memory. Insufficient RAM causes system slowdowns when multitasking."
    },
    {
      "id": 4,
      "question": "A customer wants to connect their laptop to a 4K conference room display for a presentation. Which connector provides high-definition video and audio in a single cable?",
      "options": [
        "DisplayPort",
        "DVI-D",
        "HDMI",
        "VGA"
      ],
      "correctAnswerIndex": 2,
      "explanation": "HDMI (High-Definition Multimedia Interface) provides both high-definition video and audio in a single cable, making it ideal for presentations. DisplayPort offers similar capabilities but is less common on consumer devices, DVI-D supports digital video but not audio, and VGA is an older analog standard with limited resolution support. Modern presentation environments frequently require both audio and video transmission through a single connection for simplicity.",
      "examTip": "HDMI is the standard for modern video connections. Recognize its port and its function of carrying both audio and video in a single cable."
    },
    {
      "id": 5,
      "question": "After installing a new application, a company workstation is repeatedly triggering network security alerts. What security component is most likely detecting and reporting this suspicious activity?",
      "options": [
        "Intrusion Detection System (IDS)",
        "Firewall",
        "Antivirus software",
        "Access Control List (ACL)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A firewall monitors and controls incoming and outgoing network traffic based on predetermined security rules, triggering alerts when applications attempt unauthorized network access. An IDS would detect network-based attacks but typically doesn't focus on application behavior, antivirus focuses on malicious code, and ACLs control resource access permissions. Firewalls serve as the primary gatekeepers that regulate which applications can communicate over the network and on which ports.",
      "examTip": "Think of a firewall as a security guard for your network, controlling which applications can communicate and on which ports."
    },
    {
      "id": 6,
      "question": "A technician needs to determine which software platform manages hardware resources, provides a user interface, and supports application software. Which of the following is being described?",
      "options": [
        "Hypervisor",
        "BIOS/UEFI",
        "Operating System",
        "Device driver"
      ],
      "correctAnswerIndex": 2,
      "explanation": "An operating system manages hardware resources, provides a user interface, and creates the environment where applications run. Hypervisors manage virtual machines, BIOS/UEFI handle system initialization, and device drivers enable communication with specific hardware components. The operating system serves as the essential intermediary layer between hardware and user applications.",
      "examTip": "Operating Systems like Windows, macOS, and Linux are the foundation. They manage hardware resources and provide the environment for applications to run."
    },
    {
      "id": 7,
      "question": "Which component interprets and executes instructions from software and is often referred to as the 'brain' of the computer?",
      "options": [
        "Central Processing Unit",
        "Graphics Processing Unit",
        "Northbridge Controller",
        "Random Access Memory"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The Central Processing Unit (CPU) interprets and executes instructions from software, functioning as the 'brain' of the computer. GPUs handle specialized graphics calculations, Northbridge controllers (now often integrated into CPUs) handle memory communications, and RAM stores active data and programs. CPU performance is measured by metrics such as clock speed, core count, and instruction set architecture.",
      "examTip": "The 'Central Processing Unit' is the heart of the computer. Understand its role in processing instructions and executing programs."
    },
    {
      "id": 8,
      "question": "An office needs to add wireless connectivity for guest users while keeping their network traffic separate from the internal network. Which wireless technology should be implemented?",
      "options": [
        "Wi-Fi 6 (802.11ax)",
        "Guest VLAN with Wi-Fi",
        "Bluetooth 5.0",
        "Li-Fi"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A guest VLAN with Wi-Fi provides wireless connectivity while keeping guest traffic separate from the internal network for security. Wi-Fi 6 is a standard that offers improved performance but doesn't inherently separate traffic, Bluetooth has limited range and bandwidth, and Li-Fi is an emerging optical wireless technology with limited practical deployment. Network segmentation through VLANs is a fundamental security practice for isolating different types of users and traffic.",
      "examTip": "Wi-Fi combined with network segmentation (like VLANs) provides both convenience and security when accommodating different user types."
    },
    {
      "id": 9,
      "question": "A user can't access a specific website, but all other websites load normally. Which troubleshooting tool would be most helpful to determine if there's a connection problem to that specific site?",
      "options": [
        "ipconfig",
        "netstat",
        "ping",
        "tracert"
      ],
      "correctAnswerIndex": 3,
      "explanation": "The tracert (traceroute) command shows the path network packets take to reach the destination, helping identify where the connection is failing. Ipconfig shows local IP configuration, netstat displays current connections and listening ports, and ping only tests basic connectivity without showing the path. Network path analysis is crucial when troubleshooting connectivity to specific destinations when other sites work correctly.",
      "examTip": "Web browsers like Chrome, Firefox, and Edge are your windows to navigate and view websites, but network troubleshooting tools help diagnose connection problems."
    },
    {
      "id": 10,
      "question": "A laptop user reports extremely slow file operations and system performance. Which storage upgrade would provide the most significant performance improvement?",
      "options": [
        "Larger capacity HDD",
        "External hard drive",
        "Solid State Drive (SSD)",
        "RAID 1 configuration"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Replacing a Hard Disk Drive (HDD) with a Solid State Drive (SSD) provides the most significant performance improvement due to SSDs' faster read/write speeds and lower latency. A larger capacity HDD wouldn't address the speed issue, an external drive adds storage but not system performance, and RAID 1 provides redundancy but not necessarily speed. SSDs can improve boot times, application launches, and file operations by a factor of 5-10x compared to traditional HDDs.",
      "examTip": "Think of Hard Disk Drives (HDDs) and Solid State Drives (SSDs) as the computer's long-term memory, with SSDs being significantly faster for all operations."
    },
    {
      "id": 11,
      "question": "A technician is connecting multiple peripherals to a modern laptop that only has USB Type-C ports. Which interface standard is being used?",
      "options": [
        "Universal Service Bus",
        "Unified System Bus",
        "Universal Serial Bus",
        "Unified Serial Bit"
      ],
      "correctAnswerIndex": 2,
      "explanation": "USB stands for Universal Serial Bus, a standard interface for connecting peripherals to computers. Type-C is the newest USB connector type. Universal Service Bus, Unified System Bus, and Unified Serial Bit are not recognized technical standards. USB standards continuously evolve, with each generation offering increased bandwidth, power delivery capabilities, and additional features.",
      "examTip": "Universal Serial Bus (USB) is designed to be universal - connecting many types of devices with standardized connectors."
    },
    {
      "id": 12,
      "question": "Which critical function does an operating system perform to ensure multiple applications can run simultaneously without conflicts?",
      "options": [
        "Application virtualization",
        "Memory management and process scheduling",
        "GUI rendering",
        "File compression"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Memory management and process scheduling are critical operating system functions that allow multiple applications to run simultaneously without conflicts. The OS allocates RAM to each process and determines when each gets CPU time. Application virtualization isolates applications but isn't required for multitasking, GUI rendering is for displaying graphics, and file compression is for storage. Effective memory management directly impacts system responsiveness and stability during multitasking.",
      "examTip": "The OS is the conductor of the computer's hardware orchestra. It manages resources like memory and CPU time to keep everything running smoothly."
    },
    {
      "id": 13,
      "question": "An e-commerce company needs to ensure customer payment information is encrypted during transmission. Which protocol should they implement on their web server?",
      "options": [
        "HTTP",
        "FTP",
        "HTTPS",
        "SMTP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "HTTPS (Hypertext Transfer Protocol Secure) encrypts data transmission between clients and servers, making it essential for protecting sensitive information like payment details. HTTP transmits data in plaintext, FTP is for file transfers (also typically unencrypted), and SMTP is for email transmission. HTTPS uses TLS (Transport Layer Security) to establish an encrypted connection and verify server identity through digital certificates.",
      "examTip": "HTTPS is HTTP with a security layer. Always prefer HTTPS for secure online transactions and browsing when sensitive data is involved."
    },
    {
      "id": 14,
      "question": "After experiencing system crashes, a technician discovers several unfamiliar processes running on a workstation. Which security software should be run first to identify and remove potentially harmful software?",
      "options": [
        "Disk Cleanup utility",
        "Antimalware software",
        "System Restore",
        "Disk Defragmenter"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Antimalware software should be run first to identify and remove potentially harmful software causing system crashes. Disk Cleanup removes temporary files but not malware, System Restore returns settings to a previous point but might not remove sophisticated malware, and Disk Defragmenter optimizes file storage. Modern antimalware solutions combine signature-based detection with heuristic and behavioral analysis to identify both known and novel threats.",
      "examTip": "Antimalware is your digital bodyguard, protecting your system from malicious software that can cause system instability."
    },
    {
      "id": 15,
      "question": "A user with mobility limitations needs to control their computer with minimal physical movement. Which input device would be most appropriate?",
      "options": [
        "Touchscreen monitor",
        "Graphics tablet",
        "Voice recognition system",
        "Mechanical keyboard"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A voice recognition system would be most appropriate for users with mobility limitations as it requires minimal physical movement. Touchscreens and graphics tablets still require arm movement, and mechanical keyboards require finger dexterity. Accessibility technologies are increasingly important in IT support to ensure computing is accessible to all users regardless of physical capabilities.",
      "examTip": "Input devices should match user needs and abilities. Consider accessibility requirements when recommending hardware solutions."
    },
    {
      "id": 16,
      "question": "A company needs to connect its branch office network to the headquarters network over the internet. Which network device should be installed at both locations?",
      "options": [
        "Layer 2 switch",
        "Network bridge",
        "Router with VPN capability",
        "Wireless access point"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A router with VPN capability should be installed at both locations to connect networks over the internet securely. Layer 2 switches connect devices within a local network but don't route between networks, network bridges connect similar network segments, and wireless access points provide Wi-Fi connectivity. VPN-capable routers create encrypted tunnels across the public internet, protecting data in transit between company locations.",
      "examTip": "Routers are the gateways between networks, like your branch office and headquarters, and can provide secure connections using VPN technology."
    },
    {
      "id": 17,
      "question": "A business professional needs a computer for travel that balances performance, battery life, and portability. Which form factor is most suitable?",
      "options": [
        "All-in-One PC",
        "Ultrabook laptop",
        "Gaming laptop",
        "Mini-ITX desktop"
      ],
      "correctAnswerIndex": 1,
      "explanation": "An ultrabook laptop provides the best balance of performance, battery life, and portability for business travelers. All-in-One PCs are not portable, gaming laptops are powerful but typically have poor battery life and are bulky, and Mini-ITX desktops require external peripherals and power sources. Ultrabooks are specifically designed to meet Intel's specifications for thin, lightweight laptops with extended battery life and sufficient business performance.",
      "examTip": "Laptops come in various specialized designs. Ultrabooks are optimized for portability and battery life while maintaining adequate performance for business tasks."
    },
    {
      "id": 18,
      "question": "After clicking a suspicious email link, a user's files have become inaccessible and display strange file extensions. What type of malware has likely infected the system?",
      "options": [
        "Rootkit",
        "Ransomware",
        "Keylogger",
        "Adware"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Ransomware has likely infected the system, encrypting files and making them inaccessible until a ransom is paid. Rootkits hide deep in the system to maintain persistent access, keyloggers record keystrokes to steal credentials, and adware displays unwanted advertisements. Ransomware typically changes file extensions after encryption and often provides instructions for payment in exchange for decryption keys.",
      "examTip": "Malware is the enemy! Ransomware specifically encrypts your files and demands payment for their release, making backups crucial."
    },
    {
      "id": 19,
      "question": "A small office needs to produce high-quality color marketing materials on a tight budget. Which printing technology offers the best balance of image quality and cost per page?",
      "options": [
        "Dot matrix printer",
        "Thermal printer",
        "Color laser printer",
        "Inkjet printer"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Inkjet printers offer the best balance of image quality and cost for small-volume, high-quality color printing like marketing materials. Dot matrix printers have poor quality, thermal printers typically only print in monochrome, and color laser printers have higher upfront costs and are more economical only for higher volumes. Modern photo-quality inkjets can produce professional-looking materials with special papers and have lower initial purchase prices than laser alternatives.",
      "examTip": "Inkjet printers excel at color images and photos, making them suitable for marketing materials when print volume is relatively low."
    },
    {
      "id": 20,
      "question": "A user needs to locate information about a specialized medical procedure across multiple websites. Which internet tool would be most effective?",
      "options": [
        "Web-based email client",
        "Search engine with advanced operators",
        "Social media platform",
        "Content management system"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A search engine with advanced operators (like Google's site:, filetype:, or Boolean operators) would be most effective for locating specific information across multiple websites. Web-based email is for communication, social media is primarily for social interaction, and content management systems organize content on specific sites. Advanced search techniques allow users to narrow results by domain, file type, exact phrases, or date ranges to find specialized information.",
      "examTip": "Search engines like Google, Bing, and DuckDuckGo are your primary tools for finding information online, especially when using advanced search techniques."
    },
    {
      "id": 21,
      "question": "A video editing workstation is experiencing slow render times. Which memory component would most likely need to be upgraded to improve performance?",
      "options": [
        "Virtual memory page file",
        "RAM",
        "L1 CPU cache",
        "CMOS memory"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RAM (Random Access Memory) would most likely need to be upgraded to improve video rendering performance, as video editing software utilizes large amounts of memory for processing frames and effects. Virtual memory is slower than physical RAM, L1 cache is built into the CPU and not user-upgradable, and CMOS memory stores BIOS settings. Professional video editing applications often recommend 16GB-64GB of RAM depending on resolution and complexity of projects.",
      "examTip": "RAM is the working memory of the computer. Video editing software requires substantial RAM to process multiple high-resolution frames simultaneously."
    },
    {
      "id": 22,
      "question": "A graphic designer reports that precise on-screen drawing has become difficult. Which input device issue is most likely causing this problem?",
      "options": [
        "Keyboard ghosting",
        "Mouse sensitivity settings",
        "Touchpad driver corruption",
        "Mouse tracking inconsistency"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Mouse tracking inconsistency is the most likely cause of difficulty with precise on-screen drawing for a graphic designer. Keyboard ghosting affects simultaneous key presses, sensitivity settings would affect speed but not precision, and touchpad issues would only matter if using a touchpad. Mouse tracking problems can result from dirty sensors, unsuitable surfaces, hardware failures, or driver issues that prevent smooth cursor movement for detailed work.",
      "examTip": "The mouse provides cursor control for precise interaction. Graphics professionals require accurate tracking for detailed work."
    },
    {
      "id": 23,
      "question": "A user needs to share a large business document with colleagues who might be using different word processing software. Which file format ensures maximum compatibility?",
      "options": [
        ".rtf",
        ".txt",
        ".docx",
        ".pdf"
      ],
      "correctAnswerIndex": 3,
      "explanation": "PDF (Portable Document Format) ensures maximum compatibility across different systems and software while preserving formatting. RTF (Rich Text Format) maintains basic formatting but not advanced layouts, TXT is plain text only with no formatting, and DOCX is Microsoft Word's format which might display differently in other word processors. PDF files preserve exact document appearance regardless of the operating system, device, or available fonts on the viewing system.",
      "examTip": "PDF is the universal document format for sharing. It preserves formatting across all platforms and doesn't require specific software to view."
    },
    {
      "id": 24,
      "question": "A coffee shop owner wants to offer internet access to customers without giving access to the shop's business network. Which network configuration would be most appropriate?",
      "options": [
        "WPA2-Personal encryption",
        "MAC address filtering",
        "Guest network with VLAN isolation",
        "Static IP addressing"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A guest network with VLAN isolation would be most appropriate for providing customer internet access while protecting the business network. WPA2-Personal only encrypts traffic but doesn't separate networks, MAC filtering restricts which devices can connect but doesn't separate traffic, and static IP addressing merely assigns fixed addresses. Guest networks combined with VLANs create logical separation between business and customer traffic for security purposes.",
      "examTip": "Wi-Fi security involves both encryption and network separation. Guest networks with VLAN isolation provide both internet access and security separation."
    },
    {
      "id": 25,
      "question": "A team needs to collaborate on documents while working remotely and automatically sync changes between them. Which service would best meet these requirements?",
      "options": [
        "FTP server",
        "Email attachments",
        "Cloud storage with real-time collaboration",
        "Network-attached storage (NAS)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Cloud storage with real-time collaboration (like Google Drive, Microsoft OneDrive, or Dropbox) would best meet the requirements for remote document collaboration and automatic synchronization. FTP servers don't offer real-time collaboration, email attachments create version control problems, and NAS typically requires VPN access for remote use. Modern cloud collaboration platforms provide simultaneous editing, version history, commenting, and automatic synchronization across all devices.",
      "examTip": "Cloud storage like Google Drive, Dropbox, and OneDrive lets you store files online with real-time collaboration features that enable multiple users to work on the same document simultaneously."
    },
    {
      "id": 26,
      "question": "An organization wants to implement multi-factor authentication for increased security. Which combination represents true multi-factor authentication?",
      "options": [
        "Password and security question",
        "PIN and password",
        "Password and fingerprint scan",
        "Security questions and PIN"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Password and fingerprint scan represent true multi-factor authentication because they combine different authentication factors (something you know and something you are). Password and security questions are both knowledge factors, PIN and password are both knowledge factors, and security questions and PIN are also both knowledge factors. True multi-factor authentication combines at least two different factor types: something you know (password), something you have (token), or something you are (biometric).",
      "examTip": "Passwords are your first line of defense for accounts. Multi-factor authentication significantly increases security by requiring multiple verification methods from different categories."
    },
    {
      "id": 27,
      "question": "A technician needs to create physical copies of digital diagrams for a meeting. Which peripheral device is needed?",
      "options": [
        "Scanner",
        "Plotter",
        "Laser printer",
        "Projector"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A laser printer is needed to create physical copies (printouts) of digital diagrams for a meeting. Scanners convert physical documents to digital, plotters are specialized for large-format drawings, and projectors display images on a screen. Laser printers offer high-quality text and graphics with faster output speeds and lower per-page costs than inkjets for standard business documents.",
      "examTip": "Output devices like printers convert digital information into physical form. Laser printers are ideal for business documents that combine text and graphics."
    },
    {
      "id": 28,
      "question": "A security analyst needs to verify the authenticity of a banking website. Which part of the web address should be checked first?",
      "options": [
        "The domain name and TLD (e.g., bankname.com)",
        "The protocol (HTTP vs HTTPS)",
        "The pathname after the domain",
        "URL parameters after the question mark"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The domain name and TLD (Top-Level Domain) should be checked first to verify the authenticity of a banking website, ensuring it's the legitimate domain and not a lookalike phishing domain. The protocol is important for security but doesn't verify site authenticity, while pathnames and parameters are controlled by the domain owner. Phishing sites often use domains that slightly misspell the legitimate site name or add words to it (e.g., bank-secure.com instead of bank.com).",
      "examTip": "Uniform Resource Locator (URL) is the web address. The domain name portion identifies the website owner and is critical for verifying authenticity."
    },
    {
      "id": 29,
      "question": "A user wants to download apps from the Google Play Store. Which mobile operating system must their device use?",
      "options": [
        "iOS",
        "iPadOS",
        "Android",
        "Chrome OS"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Android is the mobile operating system required to download apps from the Google Play Store. iOS and iPadOS use Apple's App Store, and Chrome OS uses the Chrome Web Store and Google Play Store but is primarily a desktop/laptop OS. While some Android apps can run on Chrome OS devices, Android remains the primary mobile platform for Google Play Store access with over 70% global mobile market share.",
      "examTip": "Android and iOS power most smartphones. Each has its own app store ecosystem with Android using Google Play and iOS using Apple's App Store."
    },
    {
      "id": 30,
      "question": "Critical security patches have been released for multiple systems. In what order should a technician apply these updates?",
      "options": [
        "According to system age, oldest first",
        "Based on user convenience, during off-hours only",
        "Starting with internet-facing and critical systems",
        "All at once using automated deployment"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Security patches should be applied starting with internet-facing and critical systems that present the highest risk if compromised. System age isn't a security priority factor, user convenience should not override security needs for critical patches, and deploying all updates simultaneously could cause widespread issues if problems occur. Patch management best practices include testing in a non-production environment first, then prioritizing based on vulnerability risk and system exposure.",
      "examTip": "Software updates are essential for keeping systems secure. Prioritize based on risk exposure and system criticality when planning update deployments."
    },
    {
      "id": 31,
      "question": "A technician needs to connect a legacy parallel printer to a modern laptop. Which port or adapter will be required?",
      "options": [
        "USB to DB-25 adapter",
        "HDMI to VGA adapter",
        "Ethernet to parallel port bridge",
        "DisplayPort to DVI converter"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A USB to DB-25 (parallel port) adapter will be required to connect a legacy parallel printer to a modern laptop. HDMI to VGA and DisplayPort to DVI are video adapters, while an Ethernet to parallel port bridge isn't a standard solution. Most parallel printers use IEEE 1284 compliant DB-25 connectors, and USB adapters for these create virtual parallel ports that can communicate with older printer hardware.",
      "examTip": "USB ports are extremely versatile and with appropriate adapters can connect to legacy devices like parallel printers that used DB-25 connectors."
    },
    {
      "id": 32,
      "question": "A remote user's internet connection is unusually slow. Who should they contact first to resolve this issue?",
      "options": [
        "Computer manufacturer",
        "Internet Service Provider",
        "Website administrator",
        "Operating system vendor"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The Internet Service Provider (ISP) should be contacted first for unusually slow internet connection issues. ISPs provide the internet connection and can diagnose line problems, outages, or account issues. Computer manufacturers handle hardware issues, website administrators manage specific sites, and OS vendors handle software issues. ISPs maintain the infrastructure connecting users to the internet and have diagnostic tools to test connection quality and throughput along their network.",
      "examTip": "Internet Service Provider (ISP) is who you pay for internet access. They're responsible for the connection quality between your location and the broader internet."
    },
    {
      "id": 33,
      "question": "A user downloaded a game that appeared legitimate but now their computer shows unwanted advertisements in all applications. Which malware type is most likely causing this?",
      "options": [
        "Keylogger",
        "Rootkit",
        "Adware bundled with a Trojan",
        "Worm"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Adware bundled with a Trojan is most likely causing unwanted advertisements across applications. The game appeared legitimate (the Trojan aspect) but contained hidden adware. Keyloggers capture keystrokes but don't display ads, rootkits hide deep in systems to maintain access, and worms self-replicate across networks. Malicious software often uses deceptive bundling, where desired applications install additional unwanted components that generate revenue through aggressive advertising.",
      "examTip": "Trojan horses masquerade as legitimate software while carrying malicious payloads like adware, spyware, or other types of malware."
    },
    {
      "id": 34,
      "question": "After installing a new printer, the computer recognizes the hardware but cannot print. What software component is most likely missing?",
      "options": [
        "Print spooler service",
        "Device driver",
        "Operating system update",
        "Firmware update"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A device driver is most likely missing if the computer recognizes the printer hardware but cannot print. Drivers translate operating system commands into printer-specific instructions. The print spooler service is typically included with the OS, OS updates might include drivers but aren't the primary issue, and firmware updates affect the printer's internal software. Printer drivers can be model-specific and often must be downloaded from the manufacturer's website for full functionality.",
      "examTip": "Printer drivers act as translators, allowing your computer to communicate with specific printer models and utilize all their features."
    },
    {
      "id": 35,
      "question": "A user complains about encountering paywalls on news websites. Which type of software would allow them to manage cookie settings and potentially bypass some paywalls?",
      "options": [
        "Media player",
        "Web browser with privacy controls",
        "Word processor",
        "File compression utility"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A web browser with privacy controls would allow the user to manage cookie settings that might help bypass some paywalls. Many paywalls rely on cookies to track article views. Media players handle audio/video content, word processors handle document creation, and file compression utilities manage compressed archives. Modern browsers include features to clear cookies, block trackers, and use private browsing modes that can sometimes help with restricted content.",
      "examTip": "Chrome, Firefox, Safari, and Edge are the main web browsers. Their privacy and cookie management features give users control over how websites track them."
    },
    {
      "id": 36,
      "question": "An organization needs to send sensitive documents to clients securely. Which email feature should they use?",
      "options": [
        "Carbon copy (CC)",
        "Large attachment support",
        "Auto-forwarding",
        "End-to-end encryption"
      ],
      "correctAnswerIndex": 3,
      "explanation": "End-to-end encryption should be used to send sensitive documents securely via email. This ensures only the intended recipient can decrypt and read the contents. Carbon copy simply sends copies to additional recipients, attachment support addresses file size but not security, and auto-forwarding could expose sensitive data to unintended recipients. Email encryption prevents the content from being read if intercepted during transmission and typically requires both sender and recipient to have compatible encryption capabilities.",
      "examTip": "Email security features like encryption protect sensitive messages from unauthorized access during transmission and storage."
    },
    {
      "id": 37,
      "question": "A photographer needs high-speed portable storage to transfer large image files between computers. Which storage technology offers the best combination of speed, capacity, and portability?",
      "options": [
        "External HDD",
        "External SSD",
        "SD memory card",
        "USB flash drive"
      ],
      "correctAnswerIndex": 1,
      "explanation": "An external SSD (Solid State Drive) offers the best combination of speed, capacity, and portability for transferring large image files. External HDDs have good capacity but slower speeds, SD cards have good portability but limited capacity and speed, and USB flash drives typically have lower performance than SSDs. External SSDs can provide transfer speeds 4-5 times faster than external HDDs while being equally portable and resistant to physical shock.",
      "examTip": "Solid State Drives (SSDs) use flash memory and offer superior performance over traditional storage methods with no moving parts, making them ideal for portable use."
    },
    {
      "id": 38,
      "question": "A CAD designer complains that small text on technical drawings is difficult to see. Which hardware upgrade would most directly address this issue?",
      "options": [
        "Higher resolution monitor",
        "Graphics card with more VRAM",
        "Faster CPU",
        "Additional system RAM"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A higher resolution monitor would most directly address the issue of small text being difficult to see on technical drawings. Higher resolution displays provide more detail and clarity for fine elements. Graphics cards affect rendering performance but not display clarity, while CPU and RAM upgrades might improve software performance but not visibility. For CAD work, 4K monitors (3840x2160) provide significantly better detail rendering than standard 1080p displays.",
      "examTip": "Monitors are your visual output device. Resolution (the number of pixels) directly impacts the clarity and detail of displayed content."
    },
    {
      "id": 39,
      "question": "An application cannot establish a network connection due to a blocked port. Which networking component is controlling this traffic?",
      "options": [
        "DNS server",
        "Dynamic Host Configuration Protocol",
        "TCP/IP protocol suite",
        "Firewall"
      ],
      "correctAnswerIndex": 3,
      "explanation": "A firewall is controlling and blocking the network traffic on specific ports. Firewalls filter network traffic based on predefined rules, including port restrictions. DNS servers resolve domain names to IP addresses, DHCP assigns IP addresses to network clients, and TCP/IP is the fundamental protocol suite for network communication. Network administrators configure firewalls to block specific application ports that may pose security risks or violate organization policies.",
      "examTip": "TCP/IP is the basic language of the internet, but firewalls control which ports and protocols can actually communicate through network boundaries."
    },
    {
      "id": 40,
      "question": "After a power outage, a company lost critical financial data. Which strategy would have best prevented this data loss?",
      "options": [
        "Using antivirus software",
        "Implementing a comprehensive backup solution",
        "Installing a faster internet connection",
        "Using disk encryption"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Implementing a comprehensive backup solution would have best prevented data loss from a power outage. Proper backups ensure data can be recovered regardless of the cause of loss. Antivirus software protects against malware but not power issues, faster internet doesn't protect data, and disk encryption protects confidentiality but not availability. An effective backup strategy includes the 3-2-1 approach: 3 copies of data, on 2 different media types, with 1 copy stored off-site.",
      "examTip": "Data backups are your safety net against all types of data loss, including hardware failure, power issues, ransomware, and human error."
    },
    {
      "id": 41,
      "question": "A department needs to share a heavy-duty laser printer. Which connection would provide the most reliable network printing for multiple users?",
      "options": [
        "Bluetooth connection",
        "Direct USB to a dedicated print server",
        "Wireless network connection",
        "Wired Ethernet connection"
      ],
      "correctAnswerIndex": 3,
      "explanation": "A wired Ethernet connection would provide the most reliable network printing experience for multiple users sharing a heavy-duty laser printer. Ethernet offers consistent speed and reliability without interference issues. Bluetooth has limited range and device support, USB to a print server is viable but still requires network distribution, and wireless connections can suffer from interference and bandwidth limitations. Enterprise print environments benefit from the stability and throughput of wired connections for high-volume printing tasks.",
      "examTip": "USB ports are common for directly connecting printers to individual computers, but Ethernet connections are preferred for shared departmental printers."
    },
    {
      "id": 42,
      "question": "A company wants to reduce hardware costs by having employees use their own applications through a browser. Which computing model should they implement?",
      "options": [
        "Peer-to-peer computing",
        "Distributed computing",
        "Cloud computing (SaaS model)",
        "Grid computing"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Cloud computing using the Software as a Service (SaaS) model should be implemented to allow employees to use applications through a browser while reducing hardware costs. SaaS provides browser-based access to applications hosted remotely. Peer-to-peer shares resources directly between computers, distributed computing spreads tasks across multiple systems, and grid computing links computers to solve complex problems. SaaS eliminates the need for local application installation, maintenance, and powerful client hardware.",
      "examTip": "Cloud computing means your data and applications are in the 'cloud' – on remote servers accessible via the internet, reducing local hardware requirements."
    },
    {
      "id": 43,
      "question": "A company needs to host multiple websites with different domain names on a single physical server. Which server configuration is required?",
      "options": [
        "DNS server with multiple zones",
        "Web server with virtual hosting",
        "DHCP server with multiple scopes",
        "File server with directory sharing"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A web server with virtual hosting is required to host multiple websites with different domain names on a single physical server. Virtual hosting allows one server to present different content based on the requested domain name. DNS servers resolve domain names to IP addresses but don't host websites, DHCP servers assign IP addresses, and file servers share documents. The HTTP Host header allows web servers to determine which virtual host is being requested during the connection process.",
      "examTip": "Web servers host and deliver website content. Virtual hosting allows a single server to host multiple websites with different domain names efficiently."
    },
    {
      "id": 44,
      "question": "A user received an email asking to verify their bank account details by clicking a link. Which cybersecurity threat does this most likely represent?",
      "options": [
        "Man-in-the-middle attack",
        "DDoS attack",
        "Phishing attempt",
        "SQL injection"
      ],
      "correctAnswerIndex": 2,
      "explanation": "This situation most likely represents a phishing attempt, where attackers impersonate legitimate entities to trick users into revealing sensitive information. Man-in-the-middle attacks intercept communications, DDoS attacks overwhelm services with traffic, and SQL injection targets website databases. Phishing emails often create urgency, contain generic greetings, have suspicious links, and request sensitive information that legitimate organizations typically wouldn't request via email.",
      "examTip": "Phishing is a social engineering attack that tricks users into revealing sensitive information by impersonating trusted entities or creating scenarios that provoke hasty actions."
    },
    {
      "id": 45,
      "question": "A high-performance gaming PC is shutting down during intense gaming sessions. Which component's failure is most likely causing this issue?",
      "options": [
        "Sound card",
        "CPU cooling system",
        "Optical drive",
        "Network card"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A failing CPU cooling system is most likely causing shutdowns during intense gaming sessions due to CPU overheating. Modern systems have thermal protection that shuts down the computer to prevent damage when temperature thresholds are exceeded. Sound cards, optical drives, and network cards typically don't generate enough heat to cause system shutdowns. Gaming puts heavy loads on both CPU and GPU, generating significant heat that requires adequate cooling to maintain safe operating temperatures.",
      "examTip": "Heat sinks and fans are crucial for keeping your CPU cool. Thermal protection features will shut down systems to prevent damage when temperatures reach unsafe levels."
    },
    {
      "id": 46,
      "question": "A user notices their traditional hard drive is becoming increasingly slow over time. Which maintenance task might improve performance?",
      "options": [
        "Disk defragmentation",
        "Increasing virtual memory",
        "Updating the graphics driver",
        "Clearing browser cookies"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Disk defragmentation might improve the performance of a traditional hard drive that has become slow over time. Fragmentation occurs when files are stored in non-contiguous clusters, increasing access times. Increasing virtual memory might help with RAM limitations but not disk-specific slowdowns, updating graphics drivers affects display performance, and clearing browser cookies affects web browsing but not overall disk performance. Defragmentation is not recommended for SSDs as it provides no benefit and can reduce their lifespan.",
      "examTip": "Disk defragmentation reorganizes file fragments on mechanical hard drives for faster access. This is unnecessary for SSDs, which have different performance characteristics."
    },
    {
      "id": 47,
      "question": "A user needs to archive large video files that will rarely be accessed but must be retained. Which storage media is most cost-effective for long-term archival?",
      "options": [
        "External SSD",
        "High-capacity tape drives",
        "Blu-ray optical discs",
        "NAS with RAID"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Blu-ray optical discs are the most cost-effective solution for long-term archival of large video files that will rarely be accessed. They offer good longevity, relatively low cost per GB for archival purposes, and don't require power during storage. External SSDs are expensive for pure archival, tape drives are economical but require specialized equipment, and NAS systems require power and maintenance. Archival-grade Blu-ray discs can have expected lifespans of 50+ years when properly stored, making them suitable for long-term data retention.",
      "examTip": "DVDs, CDs, and Blu-ray discs are optical storage. For archival purposes, Blu-ray offers the highest capacity and longevity among consumer optical options."
    },
    {
      "id": 48,
      "question": "A content creator is experiencing lag when editing 4K video. Which hardware component upgrade would most likely resolve this issue?",
      "options": [
        "Sound card",
        "Network interface card",
        "Graphics processing unit (GPU)",
        "Power supply unit (PSU)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Upgrading the Graphics Processing Unit (GPU) would most likely resolve lag when editing 4K video. Modern video editing software leverages GPU acceleration for rendering and effects processing. Sound cards handle audio, network cards manage internet connectivity, and PSUs provide power but don't directly affect processing performance. Video editing applications like Adobe Premiere Pro and DaVinci Resolve heavily utilize GPU computing power for real-time effects, color grading, and timeline scrubbing of high-resolution content.",
      "examTip": "Graphics cards (GPUs) handle visual processing tasks. Professional applications like video editing, 3D rendering, and CAD use GPU acceleration for improved performance."
    },
    {
      "id": 49,
      "question": "A company is setting up a network where all users in a single building need to communicate efficiently with minimal latency. Which network type is most appropriate?",
      "options": [
        "Personal Area Network (PAN)",
        "Metropolitan Area Network (MAN)",
        "Local Area Network (LAN)",
        "Wide Area Network (WAN)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A Local Area Network (LAN) is most appropriate for users in a single building who need to communicate with minimal latency. LANs are designed for relatively small geographic areas like buildings or campuses. PANs connect personal devices over very short distances, MANs cover city-sized areas, and WANs connect geographically distant networks. LANs typically offer higher bandwidth and lower latency than larger network types because of their limited physical scope and controlled infrastructure.",
      "examTip": "LAN (Local Area Network) is your home or office network – a network in a limited area that provides high-speed, low-latency connections."
    },
    {
      "id": 50,
      "question": "A website automatically signs a user in when they return after several days. Which browser feature enables this functionality?",
      "options": [
        "Browser history",
        "Cache memory",
        "Cookies",
        "Bookmarks"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Cookies enable websites to automatically sign users in when they return by storing authentication tokens that the browser sends back to the website. Browser history tracks visited sites but not login state, cache stores site resources for faster loading, and bookmarks are saved links to websites. Authentication cookies typically contain encrypted session identifiers that the server uses to retrieve user session information without requiring manual login each time.",
      "examTip": "Cookies are small files websites use to remember user information, preferences, and login states, enhancing browsing experiences but also potentially tracking activity."
    },
    {
      "id": 51,
      "question": "A user reports intermittent connection issues with a specific external website while all other websites work fine. Which command-line tool would help diagnose where the connection problem occurs?",
      "options": [
        "ipconfig",
        "nslookup",
        "tracert",
        "netstat"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The tracert (traceroute) command-line tool would help diagnose where a connection problem occurs with a specific website by showing the path network packets take and where delays or failures happen. Ipconfig shows local IP configuration but not path issues, nslookup checks DNS resolution, and netstat shows current connections but not the path. Tracert sends packets with increasing TTL (Time To Live) values to map each hop along the route to the destination, revealing where packets are being dropped or delayed.",
      "examTip": "The 'tracert' command is a valuable diagnostic tool that shows the complete path your data takes through the internet, helping identify where connection problems occur."
    },
    {
      "id": 52,
      "question": "A company employee needs to access the corporate network securely while traveling internationally. Which technology should be implemented?",
      "options": [
        "Virtual Private Network (VPN)",
        "Remote Desktop Protocol (RDP)",
        "File Transfer Protocol (FTP)",
        "Simple Mail Transfer Protocol (SMTP)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A Virtual Private Network (VPN) should be implemented to allow secure access to the corporate network while traveling internationally. VPNs create encrypted tunnels through public networks like hotel or airport Wi-Fi. RDP provides remote desktop access but doesn't secure the entire connection, FTP is for file transfers, and SMTP is for email transmission. VPNs also provide the benefit of masking the user's actual location, which can bypass geographic restrictions and provide an additional layer of privacy.",
      "examTip": "Virtual Private Network (VPN) creates a secure tunnel for your internet traffic, protecting your data when using public networks and allowing secure access to private networks."
    },
    {
      "id": 53,
      "question": "A system builder needs to create a compact desktop PC but wants standard component compatibility. Which motherboard form factor should they choose?",
      "options": [
        "Extended ATX (E-ATX)",
        "Mini-ITX",
        "Standard ATX",
        "Micro-ATX"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Micro-ATX would be the best motherboard form factor choice for a compact desktop PC that maintains standard component compatibility. Micro-ATX is smaller than standard ATX but still offers multiple expansion slots and compatibility with standard components. E-ATX is larger than standard ATX, standard ATX is full-sized, and Mini-ITX is the smallest but has limited expansion options. Micro-ATX motherboards typically measure 9.6 × 9.6 inches (244 × 244 mm) compared to full ATX at 12 × 9.6 inches (305 × 244 mm).",
      "examTip": "Micro-ATX is a compromise between size and expandability. It's smaller than standard ATX but offers more expansion options than Mini-ITX."
    },
    {
      "id": 54,
      "question": "After a failed software installation, a Windows system is experiencing performance issues. Which built-in recovery tool would allow returning system files and settings to a previous state without affecting personal files?",
      "options": [
        "Disk Cleanup",
        "System Restore",
        "Disk Defragmenter",
        "Safe Mode"
      ],
      "correctAnswerIndex": 1,
      "explanation": "System Restore would allow returning system files and settings to a previous state without affecting personal files, resolving issues caused by a failed software installation. It reverts Windows system files, installed programs, and registry settings to a previous point in time. Disk Cleanup removes temporary files, Disk Defragmenter optimizes file storage, and Safe Mode is a diagnostic startup mode. System Restore relies on restore points that are created automatically before significant system changes or can be created manually as a precaution.",
      "examTip": "System Restore is like a 'time machine' for your Windows system settings. It can undo system changes while preserving your personal documents and files."
    },
    {
      "id": 55,
      "question": "A user needs to connect headphones to a computer, but the sound quality is poor with static and cutting out. Which connector is most likely causing this issue?",
      "options": [
        "USB Type-C audio",
        "Digital optical (TOSLINK)",
        "Damaged 3.5mm audio jack",
        "HDMI audio"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A damaged 3.5mm audio jack is most likely causing poor sound quality with static and cutting out when connecting headphones to a computer. 3.5mm connections are analog and susceptible to physical damage and interference. USB Type-C audio is digital and less prone to quality issues, TOSLINK is digital optical with excellent quality, and HDMI audio is digital with good quality. Analog audio connections can develop issues from bent connectors, corrosion, or damage to the internal contacts in the jack.",
      "examTip": "The 3.5mm audio jack is the standard analog connector for headphones and speakers, but as an analog connection, it's susceptible to quality issues from physical damage."
    },
    {
      "id": 56,
      "question": "A business email account is receiving a high volume of unsolicited commercial messages. Which email security feature would best address this issue?",
      "options": [
        "Email encryption",
        "Spam filtering",
        "Email archiving",
        "Digital signatures"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Spam filtering would best address the issue of receiving a high volume of unsolicited commercial messages. Spam filters use various techniques to identify and segregate unwanted emails. Email encryption protects message content, archiving preserves emails for compliance, and digital signatures verify sender identity. Modern spam filtering solutions combine techniques like sender reputation checking, content analysis, pattern recognition, and machine learning to identify unsolicited bulk messages with high accuracy.",
      "examTip": "Spam filtering technologies help identify and quarantine unwanted messages before they reach your inbox, reducing clutter and potential security risks."
    },
    {
      "id": 57,
      "question": "A healthcare worker needs a device for accessing patient records while moving between rooms. Which mobile form factor is most suitable?",
      "options": [
        "Smartphone",
        "Tablet",
        "Smartwatch",
        "Laptop"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A tablet is the most suitable mobile device for a healthcare worker accessing patient records while moving between rooms. Tablets offer the optimal balance of screen size for viewing medical records and portability for mobility. Smartphones have screens too small for detailed records, smartwatches are too limited in functionality and screen size, and laptops are less convenient to carry and use while standing. Medical environments often use tablets with antimicrobial cases and specialized medical software designed for touch interfaces.",
      "examTip": "Tablets balance screen size and portability, making them ideal for mobile professionals who need to view detailed information while moving around."
    },
    {
      "id": 58,
      "question": "While building a computer, a technician notices that one component requires more power than the current configuration provides. Which computer component provides DC power to all other components?",
      "options": [
        "Motherboard",
        "Power Supply Unit (PSU)",
        "Voltage regulator module",
        "CMOS battery"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The Power Supply Unit (PSU) provides DC power to all other components in a computer. It converts AC power from the wall outlet to DC power at various voltages required by different components. The motherboard distributes power but doesn't generate it, voltage regulator modules are typically part of the motherboard, and CMOS batteries only power the real-time clock and BIOS settings when the system is off. PSUs are rated in watts, with higher-wattage units capable of supporting more powerful components and expanded configurations.",
      "examTip": "The Power Supply Unit (PSU) is the heart of your computer's power system. It converts AC power from the wall to various DC voltages needed by internal components."
    },
    {
      "id": 59,
      "question": "A technician needs to crimp new connectors onto network cables. Which connector type is required for standard Ethernet cables?",
      "options": [
        "DB-9",
        "F-type coaxial",
        "RJ45",
        "BNC"
      ],
      "correctAnswerIndex": 2,
      "explanation": "RJ45 connectors are required for standard Ethernet network cables. These 8-pin modular connectors are used with twisted pair cable for Ethernet networks. DB-9 connectors are used for serial connections, F-type connectors are for coaxial cable TV/internet, and BNC connectors are for older coaxial network and video applications. Proper RJ45 crimping requires maintaining the twisted pair integrity as close to the connector as possible to minimize signal interference and maintain network performance.",
      "examTip": "RJ45 connectors are the standard for Ethernet cables. Proper crimping requires specialized tools and adherence to either T568A or T568B wiring standards."
    },
    {
      "id": 60,
      "question": "During a computer repair, a technician needs to identify which components are hardware and which are software. Which of the following is a physical component?",
      "options": [
        "Device driver",
        "BIOS",
        "Expansion card",
        "Operating system"
      ],
      "correctAnswerIndex": 2,
      "explanation": "An expansion card is a physical hardware component that can be installed in a computer. Device drivers are software that enable communication with hardware, BIOS is firmware stored on a chip, and operating systems are software that manage hardware resources. Understanding the distinction between hardware, software, and firmware is essential for effective troubleshooting, as different problems require different approaches depending on whether they are physical or logical in nature.",
      "examTip": "Computer hardware refers to the tangible, physical parts of your computer that can be touched and handled, distinguishing them from software and firmware."
    },
    {
      "id": 61,
      "question": "A company's computers need protection from power surges during thunderstorms. Which device should be installed?",
      "options": [
        "Power strip",
        "Uninterruptible Power Supply (UPS)",
        "Power conditioner",
        "Voltage regulator"
      ],
      "correctAnswerIndex": 1,
      "explanation": "An Uninterruptible Power Supply (UPS) should be installed to protect computers from power surges during thunderstorms. A UPS provides both surge protection and battery backup to allow for safe shutdown during outages. Basic power strips may provide minimal surge protection but no backup, power conditioners filter electrical noise but typically don't provide backup, and voltage regulators stabilize voltage but don't offer backup. A UPS with Automatic Voltage Regulation (AVR) protects against surges, sags, and outages while providing clean power to sensitive electronics.",
      "examTip": "UPS devices protect equipment from power problems and provide battery backup during outages, allowing for safe shutdown and preventing data loss."
    },
    {
      "id": 62,
      "question": "A laptop user wants to upgrade their system memory for better performance. Which memory module type is specifically designed for laptops?",
      "options": [
        "DIMM",
        "SODIMM",
        "SIMM",
        "RIMM"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SODIMM (Small Outline Dual In-line Memory Module) is specifically designed for laptops and other space-constrained systems. SODIMMs are physically smaller than the DIMMs (Dual In-line Memory Modules) used in desktop computers. SIMMs are older single-sided modules rarely used now, and RIMMs are Rambus modules that are obsolete. When upgrading laptop memory, it's crucial to check the specific type, speed, and maximum capacity supported by the particular laptop model.",
      "examTip": "Laptop memory commonly uses SODIMM modules, which are physically smaller than desktop DIMMs to fit in the compact laptop chassis."
    },
    {
      "id": 63, 
      "question": "A user needs to connect an older VGA monitor to a newer computer that only has digital video outputs. Which adapter is needed?",
      "options": [
        "HDMI to DisplayPort",
        "HDMI to VGA or DisplayPort to VGA",
        "USB to Ethernet",
        "DVI to USB"
      ],
      "correctAnswerIndex": 1,
      "explanation": "An HDMI to VGA or DisplayPort to VGA adapter is needed to connect an older VGA monitor to a computer with only digital outputs. These adapters convert digital signals from HDMI or DisplayPort to the analog signals used by VGA. HDMI to DisplayPort would connect between digital formats, USB to Ethernet is for network connectivity, and DVI to USB is not a standard conversion. These digital-to-analog adapters require active conversion circuitry since they're translating between fundamentally different signal types.",
      "examTip": "VGA cables are analog connections with 15-pin D-Sub connectors, while modern systems use digital outputs like HDMI or DisplayPort, requiring active adapters for compatibility."
    },
    {
      "id": 64, 
      "question": "A technician needs to determine the IP address, subnet mask, and default gateway of a Windows workstation. Which command-line tool provides this information?",
      "options": [
        "ping",
        "ipconfig",
        "netstat",
        "route"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The ipconfig command-line tool provides information about a Windows workstation's IP address, subnet mask, default gateway, and other TCP/IP settings. Ping tests connectivity to another host, netstat shows current network connections and statistics, and route displays or modifies the routing table. Using 'ipconfig /all' provides even more detailed information, including DHCP lease information, DNS server addresses, and physical (MAC) addresses for all network adapters.",
      "examTip": "Use ipconfig /all for detailed adapter configurations, including DNS, DHCP, and MAC addresses when troubleshooting network connectivity issues."
    },
    {
      "id": 65, 
      "question": "When replacing a CPU, a technician needs to ensure proper heat dissipation. What material is applied between the CPU and heat sink to facilitate this?",
      "options": [
        "Electrical insulation tape",
        "Dielectric grease",
        "Thermal compound",
        "Silicone adhesive"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Thermal compound (also called thermal paste or thermal interface material) is applied between the CPU and heat sink to facilitate heat dissipation. It fills microscopic gaps between the surfaces, improving thermal conductivity. Electrical insulation tape would block heat transfer, dielectric grease is for electrical connections not thermal, and silicone adhesive would permanently bond the components. Proper application of thermal compound involves using just enough to fill imperfections without excess that could act as an insulator.",
      "examTip": "Thermal compound fills microscopic air gaps between CPU and heatsink surfaces, maximizing heat transfer efficiency and preventing CPU overheating."
    },
    {
      "id": 66, 
      "question": "A user reports disk errors and corrupted files on their Windows system. Which utility should be run to detect and repair file system issues?",
      "options": [
        "DISM",
        "SFC",
        "chkdsk",
        "defrag"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The chkdsk (Check Disk) utility should be run to detect and repair file system issues like disk errors and corrupted files. DISM (Deployment Image Servicing and Management) repairs Windows component store, SFC (System File Checker) verifies and repairs Windows system files, and defrag optimizes file placement but doesn't repair errors. Chkdsk examines disk structures, file records, and can recover readable information from bad sectors while marking unreadable sectors as bad to prevent future use.",
      "examTip": "Use chkdsk /f to fix errors and chkdsk /r to locate bad sectors and recover data from them when addressing file system corruption issues."
    },
    {
      "id": 67, 
      "question": "A user wants to transfer contact information to a new phone by touching the two devices together. Which wireless technology makes this possible?",
      "options": [
        "Bluetooth 5.0",
        "Near Field Communication (NFC)",
        "Wi-Fi Direct",
        "Infrared (IR)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Near Field Communication (NFC) makes it possible to transfer contact information by touching two devices together. NFC operates at extremely close range (typically less than 4cm) and allows for quick data exchange with minimal setup. Bluetooth requires pairing first, Wi-Fi Direct works at longer distances and requires configuration, and Infrared requires line-of-sight alignment. NFC's extremely short operating range provides an inherent security benefit as it's difficult to intercept transmissions without being noticed.",
      "examTip": "NFC enables quick data transfer with simple physical proximity between devices, commonly used for contactless payments, pairing Bluetooth devices, and sharing small pieces of information."
    },
    {
      "id": 68, 
      "question": "A retail business needs to print receipts quickly with low maintenance costs. Which printer type is best suited for point-of-sale operations?",
      "options": [
        "Inkjet printer",
        "Laser printer",
        "Thermal printer",
        "Impact printer"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Thermal printers are best suited for point-of-sale receipt printing due to their speed, low maintenance, and cost-effectiveness. They print by applying heat to special heat-sensitive paper. Inkjet printers have higher supply costs and slower speed, laser printers are overkill for simple receipts, and impact printers are noisy with mechanical wear concerns. Thermal printers have no ink, toner, or ribbons to replace, making them ideal for high-volume receipt printing with minimal maintenance requirements.",
      "examTip": "Thermal printers are common for receipts and shipping labels due to their speed, quiet operation, and minimal maintenance requirements."
    },
    {
      "id": 69, 
      "question": "A computer performs certain operations extremely quickly but others more slowly. Which CPU component improves performance by storing recently accessed data?",
      "options": [
        "Virtual memory",
        "Cache memory",
        "RAM",
        "Register"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Cache memory improves CPU performance by storing recently accessed data and instructions for quick retrieval. Modern CPUs have multiple cache levels (L1, L2, L3) with different capacities and speeds. Virtual memory uses the hard drive to extend RAM, RAM is the main system memory, and registers are tiny storage locations within the CPU itself. Cache memory significantly reduces the performance penalty of accessing main memory by keeping frequently used data closer to the processing cores.",
      "examTip": "CPU cache is a hierarchy (L1, L2, L3) of increasingly larger but slower memory levels that bridge the speed gap between ultra-fast CPU operations and relatively slower RAM access."
    },
    {
      "id": 70, 
      "question": "Two smartphones need to transfer files directly without using cellular data or Wi-Fi networks. Which wireless standard should be used?",
      "options": [
        "NFC",
        "LTE",
        "Bluetooth",
        "RFID"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Bluetooth should be used to transfer files directly between smartphones without using cellular data or Wi-Fi networks. Bluetooth is designed for device-to-device communication over short to medium distances. NFC works only at very close range with limited transfer speeds, LTE is a cellular standard requiring carrier networks, and RFID is primarily for identification/tracking, not file transfer. Modern Bluetooth versions (4.0+) offer improved data rates and energy efficiency over earlier versions.",
      "examTip": "Bluetooth is ideal for direct device-to-device file transfers at short to medium ranges without requiring cellular or Wi-Fi infrastructure."
    },
    {
      "id": 71,
      "question": "A user wants to set up a secure home Wi-Fi network. Which security feature allows easy connection of new devices without typing a long password?",
      "options": [
        "MAC address filtering",
        "WPA3-Personal",
        "Wi-Fi Protected Setup (WPS)",
        "Guest network isolation"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Wi-Fi Protected Setup (WPS) allows easy connection of new devices to a secure Wi-Fi network without typing a long password, typically using a button press, PIN, or NFC. MAC address filtering restricts access based on device hardware addresses, WPA3-Personal is an encryption standard requiring password entry, and guest network isolation separates visitor traffic. While convenient, WPS has known security vulnerabilities and is often recommended to be disabled on routers where security is a primary concern.",
      "examTip": "WPS simplifies device connection through button pushing or PIN entry, but has security vulnerabilities that make it a potential weak point in network security."
    },
    {
      "id": 72, 
      "question": "A technician needs to update a motherboard's firmware to support a newer CPU. Which update process would allow this without requiring a compatible CPU to be installed first?",
      "options": [
        "Windows Update",
        "Driver rollback",
        "BIOS Flashback or USB BIOS Flash",
        "Safe Mode update"
      ],
      "correctAnswerIndex": 2,
      "explanation": "BIOS Flashback (or USB BIOS Flash) allows updating a motherboard's firmware without requiring a compatible CPU to be installed first. This feature uses a dedicated USB port and button to flash the BIOS directly from a properly prepared USB drive while the system is in standby power state. Windows Update requires a working OS, driver rollback reverts to previous drivers, and Safe Mode requires a bootable system. This feature is particularly valuable when upgrading to a newer CPU generation that requires updated firmware to function.",
      "examTip": "BIOS Flashback allows firmware updates with just standby power, solving the chicken-and-egg problem of needing a working CPU to update BIOS for a new CPU."
    },
    {
      "id": 73,
      "question": "A user reports that 3D applications and games perform poorly on their computer. Which specialized memory type would most directly impact this performance?",
      "options": [
        "ECC RAM",
        "L2 Cache",
        "VRAM (Video RAM)",
        "ROM"
      ],
      "correctAnswerIndex": 2,
      "explanation": "VRAM (Video RAM) on the graphics card would most directly impact 3D application and gaming performance. This specialized memory holds textures, frame buffers, and other graphics data for quick access by the GPU. ECC RAM is for error correction in servers, L2 Cache improves CPU performance, and ROM stores firmware. Modern GPUs often use specialized forms of VRAM like GDDR6 or HBM2, which are optimized for the parallel processing requirements and high bandwidth needs of graphics rendering.",
      "examTip": "Graphics cards use specialized VRAM (often GDDR6 or similar) optimized for the massive parallel bandwidth requirements of real-time 3D rendering and texture processing."
    },
    {
      "id": 74,
      "question": "A user's computer loses all application data when powered off unexpectedly. Which memory characteristic explains this behavior?",
      "options": [
        "Non-volatility",
        "Volatility",
        "Persistent storage",
        "Write protection"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Volatility explains why a computer loses all application data when powered off unexpectedly. Volatile memory, like RAM, requires continuous power to maintain stored data and loses all content when power is removed. Non-volatility means memory retains data without power (like SSDs), persistent storage maintains data through power cycles, and write protection prevents data modification. RAM volatility is why applications prompt users to save work and why unexpected power loss can cause data corruption or loss.",
      "examTip": "RAM's volatility means it requires constant power to maintain data, which is why unexpected shutdowns cause unsaved work to be lost immediately."
    },
    {
      "id": 75,
      "question": "After a system update, a user's applications won't start. Which type of software manages hardware resources and provides services for applications to run?",
      "options": [
        "Utility software",
        "Operating system",
        "Application software",
        "Firmware"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The operating system manages hardware resources and provides services for applications to run. OS issues after updates can prevent applications from starting. Utility software performs specific system tasks, application software performs user tasks, and firmware provides low-level control of hardware. The operating system creates the runtime environment and API interfaces that applications depend on, so OS corruption or compatibility issues directly impact application functionality.",
      "examTip": "The operating system is the fundamental software layer that manages hardware resources and provides the environment where all other software runs."
    },
    {
      "id": 76,
      "question": "A technician notices an unknown device in Device Manager with a yellow warning icon. Which tool should be used to update or install the required software for this hardware?",
      "options": [
        "Task Manager",
        "System Configuration",
        "Device Manager",
        "Disk Management"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Device Manager should be used to update or install the required software (drivers) for hardware with warning icons. It provides tools to manage hardware devices and their drivers, including updating, rolling back, or uninstalling drivers. Task Manager shows running processes and performance, System Configuration manages startup items and boot options, and Disk Management handles storage devices and partitions. Device Manager is also useful for diagnosing device conflicts, disabling problematic hardware, and scanning for hardware changes.",
      "examTip": "Device Manager is your primary tool to manage hardware and drivers in Windows, showing device status with visual indicators like yellow warning icons for problematic devices."
    },
    {
      "id": 77,
      "question": "A business is upgrading their Wi-Fi network and needs robust security. Which wireless security protocol offers the strongest encryption and protection against attacks?",
      "options": [
        "WEP",
        "WPA",
        "WPA2",
        "WPA3"
      ],
      "correctAnswerIndex": 3,
      "explanation": "WPA3 offers the strongest encryption and protection against wireless attacks, making it the best choice for robust business Wi-Fi security. WEP is severely outdated and easily broken, WPA has been deprecated due to security weaknesses, and WPA2 is still common but has known vulnerabilities like KRACK. WPA3 improves upon WPA2 with stronger encryption (using SAE instead of PSK), individualized data encryption for each device, and better protection against brute force attacks.",
      "examTip": "WPA3 is the latest and most secure Wi-Fi security protocol. It provides significant improvements over WPA2 including stronger encryption and protection against password-guessing attacks."
    },
    {
      "id": 78,
      "question": "A company needs to protect against data loss from both hardware failure and ransomware attacks. Which backup strategy should they implement?",
      "options": [
        "Daily local backups to a connected drive",
        "Weekly full backups to removable media",
        "3-2-1 backup strategy with offline storage",
        "Real-time synchronization to a network share"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A 3-2-1 backup strategy with offline storage should be implemented to protect against both hardware failure and ransomware attacks. This approach maintains 3 copies of data on 2 different media types with 1 copy stored offsite/offline. Daily local backups are vulnerable to ransomware, weekly backups could lose up to a week of data, and real-time synchronization would propagate ransomware encryption to the backup. Offline backup copies are critical for ransomware protection as they're inaccessible to malware that might encrypt connected storage.",
      "examTip": "The 3-2-1 backup strategy (3 copies, 2 different media, 1 offsite/offline) provides comprehensive protection against multiple failure scenarios including disasters and ransomware."
    },
    {
      "id": 79,
      "question": "A designer needs to connect a high-resolution monitor that supports 10-bit color depth. Which digital video connector would provide the best color reproduction capabilities?",
      "options": [
        "VGA",
        "DVI-D Single Link",
        "DisplayPort 1.4",
        "HDMI 1.4"
      ],
      "correctAnswerIndex": 2,
      "explanation": "DisplayPort 1.4 would provide the best color reproduction capabilities for a high-resolution monitor with 10-bit color depth. It supports higher bandwidth, color depth, and resolutions than the alternatives. VGA is analog with limited quality, DVI-D Single Link has bandwidth limitations, and HDMI 1.4 supports lower resolutions at 10-bit color than DisplayPort 1.4. DisplayPort 1.4 can handle 4K resolution at 120Hz with HDR and 10-bit color, making it ideal for professional design work.",
      "examTip": "DisplayPort is often preferred for professional graphics and design work due to its superior bandwidth and support for higher color depths compared to older digital standards."
    },
    {
      "id": 80,
      "question": "A user notices that their computer has multiple unfamiliar processes running and is performing slowly. Which Windows utility would help identify and terminate these processes?",
      "options": [
        "File Explorer",
        "Task Manager",
        "Control Panel",
        "System Information"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Task Manager would help identify and terminate unfamiliar processes causing system slowdowns. It shows running applications, background processes, and resource usage metrics. File Explorer manages files and folders, Control Panel adjusts system settings, and System Information provides system specifications and configuration details. Task Manager's Details and Performance tabs provide valuable information about which processes are consuming CPU, memory, disk, and network resources, helping identify potential malware or problematic applications.",
      "examTip": "Task Manager allows you to monitor system resource usage and terminate problematic applications and processes that may be causing performance issues."
    },
    {
      "id": 81,
      "question": "A residential customer needs a high-speed internet connection where cable and fiber are unavailable. Which connection type provides the best performance alternative?",
      "options": [
        "Dial-up",
        "5G fixed wireless",
        "ISDN",
        "DSL"
      ],
      "correctAnswerIndex": 1,
      "explanation": "5G fixed wireless would provide the best performance alternative where cable and fiber are unavailable. It can deliver speeds comparable to wired broadband in many cases. Dial-up is extremely slow (56 Kbps maximum), ISDN is outdated with limited bandwidth (128 Kbps typical), and DSL is often available but performance degrades with distance from the central office. Modern 5G fixed wireless installations can achieve download speeds of 100-900 Mbps depending on signal quality and network congestion.",
      "examTip": "5G fixed wireless technology provides high-speed internet access that can rival wired connections in areas where fiber or cable infrastructure isn't available."
    },
    {
      "id": 82,
      "question": "After receiving training about password security, an employee is still using a sticky note with their password attached to their monitor. Which security threat does this behavior represent?",
      "options": [
        "Brute force attack vulnerability",
        "Social engineering vulnerability",
        "Man-in-the-middle attack vulnerability",
        "SQL injection vulnerability"
      ],
      "correctAnswerIndex": 1,
      "explanation": "This behavior represents a social engineering vulnerability, where someone could physically observe or take the password without technical hacking. Social engineering exploits human behavior and psychology rather than technical vulnerabilities. Brute force attacks involve repeatedly guessing passwords, man-in-the-middle attacks intercept communications, and SQL injection targets database vulnerabilities. Physical security is an essential component of a comprehensive security strategy, as even the strongest password provides no protection if it's visibly displayed.",
      "examTip": "Social engineering attacks target human behavior and social interactions rather than technical vulnerabilities. Physical security practices are crucial components of overall security posture."
    },
    {
      "id": 83,
      "question": "A computer fails to boot and displays a 'No bootable device' error. Which component is most likely failing?",
      "options": [
        "Graphics card",
        "Network interface card",
        "Storage drive",
        "Power supply"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The storage drive (HDD or SSD) is most likely failing if a computer displays a 'No bootable device' error, as the system cannot locate a valid operating system to boot. Graphics card issues typically cause display problems after POST, network cards aren't required for booting, and power supply failures usually prevent the system from powering on at all. This error can also occur if the boot order is incorrect in BIOS, the storage connection is loose, or the boot partition has been corrupted.",
      "examTip": "Storage drives contain the operating system and boot files. If the system can't detect a bootable drive, it may indicate storage drive failure, connection issues, or corrupted boot information."
    },
    {
      "id": 84,
      "question": "A user needs to adjust display resolution and power settings on a Windows computer. Which built-in tool provides the easiest access to these configuration options?",
      "options": [
        "File Explorer",
        "Registry Editor",
        "Settings app",
        "Command Prompt"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The Settings app provides the easiest access to display resolution and power settings on modern Windows computers through its System and Display sections. File Explorer manages files, Registry Editor modifies the system registry (requiring technical expertise), and Command Prompt requires specific commands for these changes. The Windows Settings app was introduced in Windows 8 and expanded in Windows 10 to gradually replace many Control Panel functions with a more user-friendly, touch-compatible interface.",
      "examTip": "The Settings app is the modern interface for configuring Windows system options, gradually replacing the traditional Control Panel with a more streamlined experience."
    },
    {
      "id": 85,
      "question": "A user frequently connects and disconnects multiple peripheral devices to their laptop. Which connection type offers the most universal compatibility for peripheral devices?",
      "options": [
        "PS/2",
        "Serial port",
        "USB",
        "Lightning connector"
      ],
      "correctAnswerIndex": 2,
      "explanation": "USB (Universal Serial Bus) offers the most universal compatibility for connecting peripheral devices to a laptop. It supports thousands of device types, provides power, and is hot-swappable. PS/2 is older, device-specific, and not hot-swappable; serial ports are legacy connections; and Lightning connectors are Apple-proprietary. USB has evolved through multiple versions (1.0, 2.0, 3.0/3.1/3.2) and connector types (A, B, C, micro, mini) while maintaining backward compatibility, making it the most versatile peripheral connection standard.",
      "examTip": "USB has become the dominant standard for peripherals due to its versatility, speed options, power delivery capabilities, and extensive device compatibility."
    },
    {
      "id": 86,
      "question": "After installing a free video editing tool, a user notices their web browser constantly redirects to advertising websites. Which type of malicious software is likely causing this behavior?",
      "options": [
        "Ransomware",
        "Browser hijacker",
        "Rootkit",
        "Keylogger"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A browser hijacker is likely causing the redirection to advertising websites. Browser hijackers modify browser settings to redirect traffic, display unwanted ads, and generate revenue for attackers. Ransomware encrypts files for ransom, rootkits provide stealthy system access, and keyloggers record keyboard input. Browser hijackers are commonly bundled with free software as part of the revenue model for the software developer, often hidden in custom installers or as optional components that users inadvertently accept.",
      "examTip": "Browser hijackers modify your browser settings to redirect traffic, change your homepage, or display unwanted advertisements, often installed bundled with free software."
    },
    {
      "id": 87,
      "question": "A company is purchasing laptops for field technicians who will frequently work in dusty, wet conditions. Which type of laptop design would best withstand these environmental challenges?",
      "options": [
        "Ultrabook",
        "Gaming laptop",
        "Rugged laptop",
        "2-in-1 convertible"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A rugged laptop would best withstand dusty, wet conditions for field technicians. Rugged laptops are specifically designed with sealed ports, reinforced cases, and enhanced durability for harsh environments. Ultrabooks focus on thinness and portability, gaming laptops prioritize performance, and 2-in-1 convertibles offer flexibility but not environmental protection. Truly rugged laptops often meet military standards like MIL-STD-810G for resistance to dust, moisture, vibration, and temperature extremes.",
      "examTip": "Rugged laptops are specialized designs that prioritize durability and protection from environmental hazards over performance, portability, or aesthetics."
    },
    {
      "id": 88,
      "question": "A Windows 10 computer fails to boot normally and displays error messages. Which startup option would allow diagnosing and fixing the issue with minimal services running?",
      "options": [
        "Normal Boot",
        "Safe Mode",
        "Fast Startup",
        "Last Known Good Configuration"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Safe Mode would allow diagnosing and fixing the issue with minimal services running. It starts Windows with only essential drivers and services to help isolate problems. Normal Boot loads all configured drivers and services, Fast Startup uses a hybrid shutdown/hibernate approach for quicker boots, and Last Known Good Configuration uses registry settings from the last successful login. Safe Mode is particularly useful when troubleshooting driver conflicts, malware infections, or software installations that prevent normal system operation.",
      "examTip": "Safe Mode starts Windows with minimal drivers and services, creating a controlled environment for troubleshooting issues that prevent normal operation."
    },
    {
      "id": 89,
      "question": "A large company needs to distribute network settings to hundreds of devices automatically. Which network service should be used to dynamically assign IP addresses?",
      "options": [
        "DNS",
        "NAT",
        "DHCP",
        "ARP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "DHCP (Dynamic Host Configuration Protocol) should be used to dynamically assign IP addresses and distribute network settings to devices automatically. DNS resolves domain names to IP addresses, NAT translates between private and public IP addresses, and ARP resolves IP addresses to MAC addresses. DHCP removes the administrative burden of manually configuring each device and can provide not just IP addresses but also subnet masks, default gateways, DNS servers, and other network parameters.",
      "examTip": "DHCP automates network configuration by dynamically assigning IP addresses and other network parameters, eliminating the need for manual configuration of each device."
    },
    {
      "id": 90,
      "question": "A user clicks on an email attachment and now their documents are encrypted with a message demanding payment for the decryption key. Which specialized malware type has infected their system?",
      "options": [
        "Spyware",
        "Ransomware",
        "Logic bomb",
        "Worm"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Ransomware has infected the system, encrypting files and demanding payment for the decryption key. Ransomware specifically holds data hostage for financial gain. Spyware collects information without user knowledge, logic bombs execute when specific conditions are met, and worms self-replicate across networks. Modern ransomware often uses strong encryption algorithms that make decryption without the key mathematically infeasible, leaving victims with limited options beyond restoration from backups.",
      "examTip": "Ransomware encrypts files and demands payment for the decryption key. Prevention through security awareness and recovery through proper backups are the best defenses."
    },
    {
      "id": 91,
      "question": "A computer retains its BIOS settings even when completely powered off and unplugged. Which memory type enables this persistent storage?",
      "options": [
        "DRAM",
        "L3 Cache",
        "CMOS memory with battery backup",
        "Virtual memory"
      ],
      "correctAnswerIndex": 2,
      "explanation": "CMOS memory with battery backup enables BIOS settings to be retained when the computer is powered off and unplugged. The small CMOS battery provides power to this non-volatile memory. DRAM is volatile system memory, L3 Cache is processor cache that loses data without power, and virtual memory is disk space used to extend RAM. The CMOS battery typically lasts 3-5 years before needing replacement, at which point BIOS settings may be reset to defaults if the computer remains unpowered for extended periods.",
      "examTip": "CMOS memory with battery backup stores BIOS/UEFI settings when the system is powered off, allowing the computer to retain its configuration between restarts."
    },
    {
      "id": 92,
      "question": "A marketing specialist needs to create professional brochures and edit photos for a campaign. Which software category would best meet these requirements?",
      "options": [
        "Operating system software",
        "Utility software",
        "Graphic design application software",
        "Programming language compiler"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Graphic design application software (like Adobe InDesign, Photoshop, or GIMP) would best meet the requirements for creating professional brochures and editing photos. Operating system software manages hardware resources, utility software performs system maintenance tasks, and programming compilers convert code to executable programs. Specialized application software is designed with specific features and workflows optimized for particular tasks like graphic design, photo manipulation, or page layout.",
      "examTip": "Application software is task-oriented, with specialized programs designed for specific user activities like graphic design, accounting, or word processing."
    },
    {
      "id": 93,
      "question": "A system administrator needs to free up space on several Windows servers. Which built-in utility can automatically remove temporary files, system logs, and previous Windows installations?",
      "options": [
        "Registry Cleaner",
        "Disk Cleanup",
        "Format tool",
        "System Restore"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Disk Cleanup can automatically remove temporary files, system logs, previous Windows installations, and other unnecessary files to free up disk space. Registry Cleaner is not a standard Windows utility and can be risky, Format completely erases a drive, and System Restore manages restore points but doesn't focus on space reclamation. The command-line version of Disk Cleanup (cleanmgr.exe) can be scripted with parameters for automated cleaning across multiple servers using administrative scripts.",
      "examTip": "Disk Cleanup is a safe system utility that identifies and removes unnecessary files like temporary files, cached web pages, and installers to recover disk space."
    },
    {
      "id": 94,
      "question": "A designer needs to connect a color-critical 4K monitor to a graphics workstation. Which digital video port provides the highest color depth and refresh rate?",
      "options": [
        "VGA",
        "DVI-D",
        "DisplayPort",
        "Composite video"
      ],
      "correctAnswerIndex": 2,
      "explanation": "DisplayPort provides the highest color depth and refresh rate for connecting a color-critical 4K monitor to a graphics workstation. Modern DisplayPort standards support 4K resolution at 120Hz+ with HDR and 10-bit+ color. VGA is analog with quality limitations, DVI-D has bandwidth limitations at 4K, and composite video is an older analog standard with very low quality. DisplayPort was specifically designed for digital display connections and offers features beyond HDMI in professional graphics applications.",
      "examTip": "DisplayPort offers the highest specifications for professional displays, supporting higher refresh rates, color depths, and resolutions than alternative digital connections."
    },
    {
      "id": 95,
      "question": "A free media player installs additional toolbars and changes browser settings without clear user consent. Which potentially unwanted software category best describes this behavior?",
      "options": [
        "Trojan",
        "Virus",
        "Adware/PUP (Potentially Unwanted Program)",
        "Worm"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Adware/PUP (Potentially Unwanted Program) best describes software that installs additional toolbars and changes browser settings without clear consent. While not necessarily malicious like traditional malware, it makes unwanted modifications to generate advertising revenue. Trojans appear legitimate but contain hidden malicious functions, viruses infect other files, and worms self-replicate across networks. PUPs often operate in legal gray areas, using deceptive installation practices or bundling to install software the user didn't explicitly request.",
      "examTip": "Adware and Potentially Unwanted Programs (PUPs) often use deceptive installation practices to place unwanted software on systems, generating revenue through advertisements or browser modifications."
    },
    {
      "id": 96,
      "question": "A high-end workstation has become unresponsive when running complex calculations. Which component is responsible for executing the mathematical operations of the software?",
      "options": [
        "RAM modules",
        "Central Processing Unit (CPU)",
        "Network Interface Card (NIC)",
        "Power Supply Unit (PSU)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The Central Processing Unit (CPU) is responsible for executing the mathematical operations of software, including complex calculations that could cause system unresponsiveness if they exceed the processor's capabilities. RAM stores active data but doesn't process it, NICs handle network communications, and PSUs provide power but don't perform calculations. For complex mathematical workloads, the CPU's architecture, clock speed, cache size, and number of cores/threads directly impact performance and system responsiveness.",
      "examTip": "The CPU is the 'brain' of the computer, performing calculations and executing instructions. Its clock speed, core count, and architecture determine computational capabilities."
    },
    {
      "id": 97,
      "question": "A user needs to email a large presentation but keeps receiving 'file too large' errors. Which technique should be used to reduce the file size?",
      "options": [
        "Disk defragmentation",
        "File compression (ZIP/RAR)",
        "Disk partitioning",
        "File encryption"
      ],
      "correctAnswerIndex": 1,
      "explanation": "File compression (using formats like ZIP or RAR) should be used to reduce the file size for email attachments. Compression algorithms identify redundant data patterns and encode them more efficiently. Disk defragmentation optimizes file storage but doesn't reduce file size, disk partitioning divides storage space, and encryption often increases file size slightly. Modern compression can typically reduce presentation files by 20-60% depending on the content, with images and media being less compressible than text and vector graphics.",
      "examTip": "File compression makes files smaller, saving space and making them faster to transfer via email or other online methods. ZIP is the most universally compatible compression format."
    },
    {
      "id": 98,
      "question": "An organization needs secure, portable storage for employees to transfer sensitive files between locations. Which solution provides the best security for this requirement?",
      "options": [
        "Standard USB flash drive",
        "External HDD with password protection",
        "Cloud file sharing service",
        "Encrypted USB drive with hardware-based encryption"
      ],
      "correctAnswerIndex": 3,
      "explanation": "An encrypted USB drive with hardware-based encryption provides the best security for transferring sensitive files between locations. Hardware encryption implements security at the physical device level, making it more difficult to bypass than software solutions. Standard USB drives offer no built-in security, password-protected external HDDs typically use weak software protection, and cloud services introduce network transmission risks. Hardware-encrypted drives often include features like brute-force protection, secure authentication, and FIPS certification for regulatory compliance.",
      "examTip": "Encrypted USB drives with hardware-based encryption provide security for data in transit through physical possession control combined with strong encryption that works regardless of the computer being used."
    },
    {
      "id": 99,
      "question": "A network administrator needs to connect multiple computers to share resources within a building while managing traffic efficiently. Which network device should be used?",
      "options": [
        "Hub",
        "Repeater",
        "Managed switch",
        "NIC"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A managed switch should be used to connect multiple computers and share resources efficiently within a building. Managed switches provide traffic management through features like VLANs, QoS, and port monitoring. Hubs broadcast all traffic to all ports creating inefficiency and security concerns, repeaters simply extend signals without traffic management, and NICs are network adapters in individual devices. Managed switches also provide security benefits through port security, access control lists, and the ability to monitor and control network traffic patterns.",
      "examTip": "Switches direct network traffic intelligently based on MAC addresses, sending data only to the specific ports that need it. Managed switches add configuration options for security, performance optimization, and network segmentation."
    },
    {
      "id": 100,
      "question": "After a company discovers unauthorized website access attempts, they implement a security technology that blocks IP addresses making repeated failed login attempts. What security measure has been implemented?",
      "options": [
        "Intrusion Prevention System",
        "Brute force protection",
        "Distributed Denial of Service (DDoS) protection",
        "Data Loss Prevention"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Brute force protection has been implemented to block IP addresses making repeated failed login attempts. This security measure specifically counters attackers trying to guess passwords through multiple login attempts. Intrusion Prevention Systems are broader security tools that detect and block various attacks, DDoS protection defends against traffic-based service disruption, and Data Loss Prevention controls data exfiltration. Brute force protection typically uses techniques like progressive delays, CAPTCHA challenges, and temporary IP bans to make automated password guessing attacks impractical.",
      "examTip": "Brute force protection prevents automated password guessing by detecting patterns of failed login attempts and implementing countermeasures like temporary account lockouts or IP address blocks."
    }
  ]
});
