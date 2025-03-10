db.tests.insertOne({
  "category": "serverplus",
  "testId": 3,
  "testName": "CompTIA Server+ (SK0-005) Practice Test #3 (Easy)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "What component in a server is responsible for converting AC power from the wall outlet to DC power for internal use?",
      "options": [
        "UPS",
        "PSU",
        "CPU",
        "RAID controller"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The PSU (Power Supply Unit) converts alternating current (AC) from the wall outlet to direct current (DC) needed by server components. A UPS provides backup power, the CPU processes data, and the RAID controller manages disk arrays.",
      "examTip": "The PSU is the heart of a server’s power system—know its role in power conversion."
    },
    {
      "id": 2,
      "question": "Which RAID level requires at least three drives and uses parity for fault tolerance?",
      "options": [
        "RAID 0",
        "RAID 1",
        "RAID 5",
        "RAID 10"
      ],
      "correctAnswerIndex": 2,
      "explanation": "RAID 5 requires a minimum of three drives and uses parity data distributed across all drives for fault tolerance. RAID 0 has no redundancy, RAID 1 mirrors data, and RAID 10 combines mirroring and striping.",
      "examTip": "RAID 5 is a common choice for fault tolerance with efficient storage use—memorize its minimum drive requirement."
    },
    {
      "id": 3,
      "question": "A server’s network connection drops intermittently. Which initial troubleshooting step should you take?",
      "options": [
        "Replace the server’s PSU",
        "Check the network cable and connections",
        "Update the server’s BIOS firmware",
        "Reinstall the operating system"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Checking the network cable and connections is the first step to diagnose intermittent network drops, as loose or damaged cables are common culprits. The PSU, BIOS, and OS are less likely to cause this specific issue.",
      "examTip": "Start troubleshooting network issues with the simplest physical checks, like cables."
    },
    {
      "id": 4,
      "question": "Which type of server memory improves reliability by detecting and correcting errors?",
      "options": [
        "DDR4",
        "ECC",
        "SRAM",
        "Non-ECC"
      ],
      "correctAnswerIndex": 1,
      "explanation": "ECC (Error-Correcting Code) memory detects and corrects single-bit errors, enhancing server reliability. DDR4 is a memory standard, SRAM is a type of memory, and Non-ECC lacks error correction.",
      "examTip": "ECC memory is a must-know for server reliability—focus on its error correction capability."
    },
    {
      "id": 5,
      "question": "What is the primary purpose of implementing a hot-aisle/cold-aisle configuration in a data center?",
      "options": [
        "To improve server security",
        "To optimize cooling efficiency",
        "To increase network bandwidth",
        "To reduce power consumption"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A hot-aisle/cold-aisle configuration separates cool incoming air from hot exhaust air, optimizing cooling efficiency. It doesn’t directly affect security, bandwidth, or power consumption.",
      "examTip": "Cooling efficiency is key in data centers—know how airflow layouts like hot-aisle/cold-aisle work."
    },
    {
      "id": 6,
      "question": "Which protocol is commonly used to remotely manage a server’s hardware when the operating system is unavailable?",
      "options": [
        "SSH",
        "RDP",
        "IPMI",
        "FTP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "IPMI (Intelligent Platform Management Interface) allows remote hardware management, even if the OS is down. SSH and RDP require OS functionality, and FTP is for file transfers.",
      "examTip": "IPMI is your go-to for out-of-band management—learn its role in hardware control."
    },
    {
      "id": 7,
      "question": "A server’s hard drive fails in a RAID 1 array. What is the immediate impact on data availability?",
      "options": [
        "All data is lost",
        "Data remains available",
        "The server shuts down",
        "Performance increases"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RAID 1 mirrors data across drives, so if one fails, data remains available on the other. No data is lost, the server continues running, and performance doesn’t increase.",
      "examTip": "RAID 1’s mirroring ensures data availability—key for redundancy questions."
    },
    {
      "id": 8,
      "question": "Which physical security measure best prevents unauthorized access to a server room?",
      "options": [
        "Video surveillance",
        "Biometric locks",
        "Fire alarms",
        "Motion sensors"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Biometric locks use unique identifiers (e.g., fingerprints) to prevent unauthorized entry effectively. Surveillance monitors, alarms detect fires, and sensors alert to movement, but locks stop access directly.",
      "examTip": "Physical security often hinges on access control—biometrics are a strong choice."
    },
    {
      "id": 9,
      "question": "What does the term 'NIC teaming' refer to in a server environment?",
      "options": [
        "Combining multiple CPUs for processing",
        "Grouping multiple network adapters for redundancy",
        "Pairing servers for load balancing",
        "Connecting storage devices over a network"
      ],
      "correctAnswerIndex": 1,
      "explanation": "NIC teaming combines multiple network interface cards for redundancy or increased bandwidth. It’s specific to networking, not CPUs, servers, or storage.",
      "examTip": "NIC teaming boosts network reliability—know its purpose and benefits."
    },
    {
      "id": 10,
      "question": "Which backup type requires the least storage space but increases restore time?",
      "options": [
        "Full backup",
        "Incremental backup",
        "Differential backup",
        "Synthetic backup"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Incremental backups only save changes since the last backup, minimizing storage use but requiring multiple restores, increasing time. Full and differential use more space, and synthetic combines backups differently.",
      "examTip": "Incremental backups trade storage efficiency for longer restore times—understand the tradeoff."
    },
    {
      "id": 11,
      "question": "What is the main function of a server’s BIOS during startup?",
      "options": [
        "Load the operating system",
        "Initialize hardware components",
        "Manage network connections",
        "Control cooling fans"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The BIOS (Basic Input/Output System) initializes and tests hardware during startup (POST). The OS loader takes over afterward, and it doesn’t manage networks or cooling.",
      "examTip": "BIOS kicks off the boot process—focus on its hardware initialization role."
    },
    {
      "id": 12,
      "question": "Which network device forwards data packets based on IP addresses?",
      "options": [
        "Switch",
        "Router",
        "Hub",
        "Bridge"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Routers forward packets based on IP addresses (Layer 3). Switches use MAC addresses (Layer 2), hubs broadcast to all, and bridges connect segments.",
      "examTip": "Routers work with IPs, switches with MACs—know the OSI layer difference."
    },
    {
      "id": 13,
      "question": "A server uses SSDs instead of HDDs. What is the primary benefit?",
      "options": [
        "Higher storage capacity",
        "Lower cost per gigabyte",
        "Faster data access speeds",
        "Improved fault tolerance"
      ],
      "correctAnswerIndex": 2,
      "explanation": "SSDs offer faster read/write speeds due to flash memory and no moving parts. HDDs typically have higher capacity and lower cost, while fault tolerance depends on RAID, not drive type.",
      "examTip": "SSDs shine in performance—speed is their key advantage."
    },
    {
      "id": 14,
      "question": "Which port number is typically used by HTTPS for secure web traffic?",
      "options": [
        "21",
        "80",
        "443",
        "3389"
      ],
      "correctAnswerIndex": 2,
      "explanation": "HTTPS uses port 443 for encrypted web traffic. Port 21 is FTP, 80 is HTTP, and 3389 is RDP.",
      "examTip": "Memorize common ports: 443 for HTTPS is a frequent test item."
    },
    {
      "id": 15,
      "question": "What is the purpose of a server’s redundant cooling fans?",
      "options": [
        "Increase processing speed",
        "Maintain operation if one fan fails",
        "Reduce power consumption",
        "Enhance network performance"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Redundant cooling fans ensure the server stays cool if one fails. They don’t affect speed, power, or networking directly.",
      "examTip": "Redundancy in cooling prevents overheating—key for server uptime."
    },
    {
      "id": 16,
      "question": "Which type of server is best suited for hosting a company’s internal database?",
      "options": [
        "Web server",
        "Mail server",
        "Database server",
        "File server"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Database servers are optimized for storing and managing structured data. Web servers host websites, mail servers handle email, and file servers manage files.",
      "examTip": "Match server type to workload—databases need database servers."
    },
    {
      "id": 17,
      "question": "What does a UPS do when a power outage occurs?",
      "options": [
        "Shuts down the server immediately",
        "Provides temporary battery power",
        "Switches to a backup server",
        "Increases network bandwidth"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A UPS (Uninterruptible Power Supply) provides battery power during outages to keep servers running or allow safe shutdown. It doesn’t shut down, switch servers, or affect bandwidth.",
      "examTip": "UPS bridges power gaps—vital for avoiding data loss."
    },
    {
      "id": 18,
      "question": "Which RAID level offers no fault tolerance and focuses on performance?",
      "options": [
        "RAID 0",
        "RAID 1",
        "RAID 5",
        "RAID 6"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RAID 0 uses striping for performance but offers no redundancy. RAID 1, 5, and 6 provide fault tolerance through mirroring or parity.",
      "examTip": "RAID 0 is all about speed—no safety net if a drive fails."
    },
    {
      "id": 19,
      "question": "What is the benefit of using a SAN for server storage?",
      "options": [
        "File-level access over a LAN",
        "Block-level access over a high-speed network",
        "Direct attachment to the server",
        "Lower cost than local drives"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A SAN (Storage Area Network) provides block-level access over a dedicated high-speed network, ideal for performance. NAS offers file-level access, DAS is direct-attached, and SANs are typically costlier.",
      "examTip": "SANs excel in performance with block-level access—know the difference from NAS."
    },
    {
      "id": 20,
      "question": "Which log should you check first for hardware failure events on a server?",
      "options": [
        "Application log",
        "Security log",
        "System log",
        "Access log"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The system log records hardware and OS-related events, including failures. Application logs track software, security logs track access, and access logs are network-specific.",
      "examTip": "System logs are your first stop for hardware issues."
    },
    {
      "id": 21,
      "question": "What is the primary role of a server’s GPU in a virtualization environment?",
      "options": [
        "Manage network traffic",
        "Accelerate graphical workloads",
        "Control power distribution",
        "Enhance storage performance"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A GPU (Graphics Processing Unit) accelerates graphical and parallel computing tasks, especially in virtual desktops. It doesn’t manage networks, power, or storage.",
      "examTip": "GPUs boost graphics—critical for VDI or compute-intensive VMs."
    },
    {
      "id": 22,
      "question": "Which cable type supports longer distances for high-speed networking?",
      "options": [
        "Cat6",
        "Fiber optic",
        "Coaxial",
        "Cat5e"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Fiber optic cables support high-speed data over long distances due to light-based transmission. Cat6 and Cat5e are limited to shorter runs, and coaxial is older technology.",
      "examTip": "Fiber optic is the choice for long-distance, high-speed links."
    },
    {
      "id": 23,
      "question": "What does a server’s hot-swappable power supply allow?",
      "options": [
        "Replacement without powering off",
        "Increased processing speed",
        "Higher storage capacity",
        "Better network redundancy"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Hot-swappable power supplies can be replaced while the server runs, minimizing downtime. They don’t affect speed, storage, or networking.",
      "examTip": "Hot-swap means no downtime—key for high-availability systems."
    },
    {
      "id": 24,
      "question": "Which protocol is used to send email from a server to another server?",
      "options": [
        "IMAP",
        "POP3",
        "SMTP",
        "DNS"
      ],
      "correctAnswerIndex": 2,
      "explanation": "SMTP (Simple Mail Transfer Protocol) sends emails between servers. IMAP and POP3 retrieve emails, and DNS resolves names.",
      "examTip": "SMTP is the email sender—know its role in mail servers."
    },
    {
      "id": 25,
      "question": "What is the main advantage of using virtualization on a server?",
      "options": [
        "Increases physical security",
        "Reduces hardware costs",
        "Improves individual VM performance",
        "Eliminates the need for backups"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Virtualization consolidates multiple workloads on one server, reducing hardware costs. It doesn’t directly enhance security, VM performance, or eliminate backups.",
      "examTip": "Virtualization saves money through consolidation—focus on resource efficiency."
    },
    {
      "id": 26,
      "question": "A server room’s temperature rises suddenly. What is the most likely cause?",
      "options": [
        "Failed cooling system",
        "Overloaded CPU",
        "Network congestion",
        "Power supply failure"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A failed cooling system (e.g., AC or fans) directly causes temperature spikes. CPU load, network issues, or PSU failures may generate heat but aren’t the primary room-level cause.",
      "examTip": "Temperature issues usually point to cooling—check fans or HVAC first."
    },
    {
      "id": 27,
      "question": "Which network topology uses a central device to connect all nodes?",
      "options": [
        "Bus",
        "Ring",
        "Star",
        "Mesh"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Star topology connects all devices to a central hub or switch. Bus uses a single cable, ring forms a loop, and mesh has multiple connections.",
      "examTip": "Star topology is common and reliable—know its central hub structure."
    },
    {
      "id": 28,
      "question": "What is the purpose of a server’s firmware updates?",
      "options": [
        "Increase storage capacity",
        "Fix hardware compatibility issues",
        "Enhance network speed",
        "Install new applications"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Firmware updates fix bugs, improve compatibility, and enhance hardware functionality. They don’t affect storage, network speed, or software apps.",
      "examTip": "Firmware keeps hardware running smoothly—think compatibility and stability."
    },
    {
      "id": 29,
      "question": "Which type of backup captures all changes since the last full backup?",
      "options": [
        "Full backup",
        "Incremental backup",
        "Differential backup",
        "Snapshot backup"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Differential backups capture all changes since the last full backup, growing over time. Full backups copy everything, incremental backups track recent changes, and snapshots are point-in-time copies.",
      "examTip": "Differential backups simplify restores but use more space—know the difference."
    },
    {
      "id": 30,
      "question": "What is the primary function of a server’s motherboard?",
      "options": [
        "Store permanent data",
        "Connect all hardware components",
        "Manage network traffic",
        "Supply power to peripherals"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The motherboard connects the CPU, memory, storage, and other components. Storage devices hold data, NICs manage networking, and the PSU supplies power.",
      "examTip": "The motherboard is the hardware backbone—everything plugs into it."
    },
    {
      "id": 31,
      "question": "Which device protects a server from power surges?",
      "options": [
        "UPS",
        "Surge protector",
        "Router",
        "Switch"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A surge protector absorbs excess voltage to protect equipment. A UPS provides backup power, while routers and switches handle networking.",
      "examTip": "Surge protectors shield from spikes—distinct from UPS backup power."
    },
    {
      "id": 32,
      "question": "What does RAID 6 use to protect against multiple drive failures?",
      "options": [
        "Mirroring",
        "Single parity",
        "Dual parity",
        "Striping"
      ],
      "correctAnswerIndex": 2,
      "explanation": "RAID 6 uses dual parity to protect against two simultaneous drive failures. Mirroring is RAID 1, single parity is RAID 5, and striping is RAID 0.",
      "examTip": "RAID 6’s dual parity doubles fault tolerance—know its strength."
    },
    {
      "id": 33,
      "question": "Which protocol resolves domain names to IP addresses for servers?",
      "options": [
        "DHCP",
        "DNS",
        "SNMP",
        "NTP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "DNS (Domain Name System) translates domain names to IPs. DHCP assigns IPs, SNMP manages devices, and NTP synchronizes time.",
      "examTip": "DNS is the internet’s phonebook—maps names to IPs."
    },
    {
      "id": 34,
      "question": "A server’s RAM usage is consistently high. What should you do first?",
      "options": [
        "Add more RAM",
        "Check for memory leaks",
        "Replace the CPU",
        "Update the firmware"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Checking for memory leaks identifies software issues causing high RAM use before adding hardware. Replacing the CPU or updating firmware doesn’t address RAM directly.",
      "examTip": "Diagnose high RAM usage before throwing hardware at it—look for leaks."
    },
    {
      "id": 35,
      "question": "What is the benefit of a blade server over a traditional rack server?",
      "options": [
        "Lower initial cost",
        "Higher storage capacity",
        "Increased density in less space",
        "Better individual performance"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Blade servers fit more units in less space by sharing resources like power and cooling. They’re often costlier, storage depends on config, and performance is comparable.",
      "examTip": "Blade servers pack more into less space—density is their edge."
    },
    {
      "id": 36,
      "question": "Which type of storage is most suitable for long-term data archiving?",
      "options": [
        "SSD",
        "HDD",
        "Tape",
        "NAS"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Tape is cost-effective and durable for long-term archiving. SSDs and HDDs are for active use, and NAS is network storage, not archival-specific.",
      "examTip": "Tape is the archival king—low cost and long life."
    },
    {
      "id": 37,
      "question": "What does a server’s POST process verify during boot?",
      "options": [
        "Network connectivity",
        "Hardware functionality",
        "OS integrity",
        "Storage capacity"
      ],
      "correctAnswerIndex": 1,
      "explanation": "POST (Power-On Self-Test) checks hardware functionality during boot. Network, OS, and storage checks happen later.",
      "examTip": "POST is the hardware health check at startup—know its scope."
    },
    {
      "id": 38,
      "question": "Which security practice reduces the attack surface on a server?",
      "options": [
        "Disabling unused services",
        "Installing antivirus software",
        "Performing regular backups",
        "Using strong passwords"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Disabling unused services reduces potential entry points for attacks. Antivirus, backups, and passwords enhance security but don’t directly shrink the attack surface.",
      "examTip": "Less running software means fewer vulnerabilities—disable what’s not needed."
    },
    {
      "id": 39,
      "question": "What is the primary purpose of a load balancer in a server farm?",
      "options": [
        "Increase storage capacity",
        "Distribute network traffic",
        "Provide power redundancy",
        "Enhance cooling efficiency"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A load balancer distributes incoming traffic across servers to prevent overload. It doesn’t affect storage, power, or cooling.",
      "examTip": "Load balancers keep servers from drowning in traffic—know their role."
    },
    {
      "id": 40,
      "question": "Which command displays current IP configuration on a Windows server?",
      "options": [
        "ifconfig",
        "ipconfig",
        "netstat",
        "ping"
      ],
      "correctAnswerIndex": 1,
      "explanation": "ipconfig shows IP configuration on Windows. ifconfig is for Linux, netstat shows connections, and ping tests connectivity.",
      "examTip": "ipconfig is Windows’ IP tool—memorize it for networking tasks."
    },
    {
      "id": 41,
      "question": "What does a server’s redundant NIC configuration ensure?",
      "options": [
        "Faster processing",
        "Network availability",
        "More storage space",
        "Better cooling"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Redundant NICs ensure network availability if one fails. They don’t affect processing, storage, or cooling.",
      "examTip": "Redundant NICs keep the network alive—focus on uptime."
    },
    {
      "id": 42,
      "question": "Which type of server is designed to proxy requests between clients and external servers?",
      "options": [
        "File server",
        "Proxy server",
        "Database server",
        "Web server"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A proxy server intermediates requests, often for caching or security. File servers store files, database servers manage data, and web servers host sites.",
      "examTip": "Proxy servers sit in the middle—know their mediation role."
    },
    {
      "id": 43,
      "question": "What is the main disadvantage of RAID 0?",
      "options": [
        "High storage overhead",
        "No fault tolerance",
        "Slow write speeds",
        "Complex setup"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RAID 0 lacks fault tolerance; one drive failure loses all data. It has no overhead, offers fast speeds, and is simple to set up.",
      "examTip": "RAID 0’s speed comes with risk—no redundancy means no recovery."
    },
    {
      "id": 44,
      "question": "Which environmental factor most directly affects server hardware longevity?",
      "options": [
        "Temperature",
        "Network speed",
        "Power usage",
        "Software updates"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Temperature directly impacts hardware life; excessive heat causes wear. Network speed, power, and updates don’t physically degrade components.",
      "examTip": "Heat is hardware’s enemy—control it for longevity."
    },
    {
      "id": 45,
      "question": "What is the purpose of a server’s iLO or iDRAC interface?",
      "options": [
        "Manage storage arrays",
        "Provide remote hardware management",
        "Increase CPU performance",
        "Secure network traffic"
      ],
      "correctAnswerIndex": 1,
      "explanation": "iLO (HP) and iDRAC (Dell) provide remote hardware management, like power control or monitoring, even if the OS is off. They don’t manage storage, CPUs, or traffic.",
      "examTip": "iLO/iDRAC are remote lifelines—key for out-of-band control."
    },
    {
      "id": 46,
      "question": "Which backup strategy minimizes data loss between backups?",
      "options": [
        "Daily full backups",
        "Weekly differential backups",
        "Hourly incremental backups",
        "Monthly snapshots"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Hourly incremental backups capture changes frequently, minimizing data loss. Full, differential, and snapshots have larger gaps.",
      "examTip": "Frequent incrementals cut data loss—time between backups matters."
    },
    {
      "id": 47,
      "question": "What does a server’s KVM switch enable?",
      "options": [
        "Network load balancing",
        "Control of multiple servers with one console",
        "Power redundancy",
        "Storage expansion"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A KVM (Keyboard, Video, Mouse) switch lets one console control multiple servers. It’s unrelated to networking, power, or storage.",
      "examTip": "KVM simplifies management—one set of controls for many servers."
    },
    {
      "id": 48,
      "question": "Which protocol secures file transfers between servers?",
      "options": [
        "FTP",
        "SFTP",
        "HTTP",
        "SNMP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SFTP (Secure File Transfer Protocol) encrypts file transfers. FTP is unsecured, HTTP is for web, and SNMP manages devices.",
      "examTip": "SFTP adds security to file transfers—know its encryption advantage."
    },
    {
      "id": 49,
      "question": "What is the main benefit of a hardware RAID controller over software RAID?",
      "options": [
        "Lower cost",
        "Easier setup",
        "Better performance",
        "More flexibility"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Hardware RAID controllers offload processing from the CPU, improving performance. They’re costlier, less flexible, and setup varies.",
      "examTip": "Hardware RAID boosts speed by reducing CPU load—performance is key."
    },
    {
      "id": 50,
      "question": "Which factor determines a server’s Recovery Time Objective (RTO)?",
      "options": [
        "Amount of data lost",
        "Time to restore operations",
        "Backup frequency",
        "Storage capacity"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RTO is the time needed to restore operations after a failure. Data loss is RPO, frequency affects RPO, and capacity is unrelated.",
      "examTip": "RTO measures downtime—focus on restoration speed."
    },
    {
      "id": 51,
      "question": "Which server component is responsible for managing and allocating IP addresses automatically to networked devices?",
      "options": [
        "DHCP server",
        "DNS server",
        "Web server",
        "File server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A DHCP (Dynamic Host Configuration Protocol) server automatically assigns IP addresses to devices on a network, simplifying network configuration. A DNS server resolves domain names to IP addresses, a web server hosts websites, and a file server manages file storage.",
      "examTip": "DHCP is key for automatic IP assignment—essential for network management."
    },
    {
      "id": 52,
      "question": "What is the primary purpose of a server's redundant power supply?",
      "options": [
        "Increase processing speed",
        "Provide backup power if one PSU fails",
        "Enhance cooling efficiency",
        "Expand storage capacity"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Redundant power supplies ensure continuous operation by providing backup power if one power supply unit (PSU) fails, improving server reliability. They do not affect processing speed, cooling, or storage capacity.",
      "examTip": "Focus on redundancy for uptime—critical in server environments."
    },
    {
      "id": 53,
      "question": "Which type of network cable supports speeds up to 10 Gbps over short distances?",
      "options": [
        "Cat5e",
        "Cat6",
        "Cat6a",
        "Cat7"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Cat6a cables support 10 Gbps speeds over distances up to 100 meters, making them ideal for high-speed networks. Cat5e supports up to 1 Gbps, Cat6 supports 10 Gbps over shorter distances, and Cat7 is designed for specialized high-speed applications.",
      "examTip": "Cat6a is a common choice for 10 Gbps—know its range and use."
    },
    {
      "id": 54,
      "question": "What does a server's BIOS password protect against?",
      "options": [
        "Unauthorized access to the operating system",
        "Unauthorized changes to hardware settings",
        "Data theft from storage drives",
        "Network-based attacks"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A BIOS password secures the server’s hardware settings and boot process, preventing unauthorized changes. It does not protect the operating system, storage data, or network directly.",
      "examTip": "BIOS security is pre-OS—think hardware-level protection."
    },
    {
      "id": 55,
      "question": "Which storage technology allows multiple servers to access the same storage pool over a network?",
      "options": [
        "DAS",
        "NAS",
        "SAN",
        "Local SSD"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A SAN (Storage Area Network) provides block-level storage access over a network, enabling multiple servers to share a storage pool. DAS is direct-attached, NAS offers file-level access, and local SSDs are server-specific.",
      "examTip": "SANs are enterprise-grade for shared storage—know their role."
    },
    {
      "id": 56,
      "question": "What is the main advantage of using a virtual machine snapshot?",
      "options": [
        "Permanent data backup",
        "Quick rollback to a previous state",
        "Increased VM performance",
        "Reduced storage usage"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Snapshots allow administrators to revert a virtual machine to a previous state quickly, ideal for testing or recovery. They are not permanent backups, do not boost performance, and may increase storage use.",
      "examTip": "Snapshots are for quick recovery—perfect for testing changes."
    },
    {
      "id": 57,
      "question": "Which server role is responsible for resolving domain names to IP addresses?",
      "options": [
        "DHCP server",
        "DNS server",
        "File server",
        "Print server"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DNS (Domain Name System) server translates domain names (e.g., www.example.com) into IP addresses. DHCP assigns IPs, file servers store files, and print servers manage printing.",
      "examTip": "DNS is the internet’s address book—vital for navigation."
    },
    {
      "id": 58,
      "question": "What is the primary benefit of using ECC memory in servers?",
      "options": [
        "Higher storage capacity",
        "Error detection and correction",
        "Faster data transfer speeds",
        "Lower power consumption"
      ],
      "correctAnswerIndex": 1,
      "explanation": "ECC (Error-Correcting Code) memory detects and corrects single-bit errors, improving data integrity and server reliability. It does not increase capacity, speed, or efficiency significantly.",
      "examTip": "ECC ensures stability—crucial for critical systems."
    },
    {
      "id": 59,
      "question": "Which type of backup captures only the files that have changed since the last backup?",
      "options": [
        "Full backup",
        "Incremental backup",
        "Differential backup",
        "Mirror backup"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Incremental backups save only changes since the last backup (full or incremental), reducing storage needs. Full backups copy everything, differential backups save changes since the last full, and mirror backups create identical copies.",
      "examTip": "Incremental is efficient—know its restore complexity."
    },
    {
      "id": 60,
      "question": "What does a server's RAID controller manage?",
      "options": [
        "Network traffic",
        "Disk arrays",
        "Power distribution",
        "Cooling systems"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A RAID controller manages disk arrays to provide redundancy and performance through RAID configurations. It does not handle networking, power, or cooling.",
      "examTip": "RAID controllers are storage-focused—key for data protection."
    },
    {
      "id": 61,
      "question": "Which network protocol is used to synchronize time across servers?",
      "options": [
        "NTP",
        "SNMP",
        "FTP",
        "DHCP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NTP (Network Time Protocol) ensures accurate time synchronization across devices. SNMP monitors devices, FTP transfers files, and DHCP assigns IPs.",
      "examTip": "NTP keeps time in sync—important for logs and audits."
    },
    {
      "id": 62,
      "question": "What is the main purpose of a server's out-of-band management interface?",
      "options": [
        "Increase network bandwidth",
        "Provide remote access to hardware",
        "Enhance storage performance",
        "Improve CPU efficiency"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Out-of-band management (e.g., IPMI, iLO) allows remote hardware control, even if the OS fails. It does not affect bandwidth, storage, or CPU performance.",
      "examTip": "Out-of-band is for remote fixes—think headless server management."
    },
    {
      "id": 63,
      "question": "Which type of server is optimized for delivering web content to clients?",
      "options": [
        "Database server",
        "Web server",
        "File server",
        "Application server"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Web servers deliver web pages to clients via HTTP/HTTPS. Database servers manage data, file servers store files, and application servers run business logic.",
      "examTip": "Web servers power websites—central to online presence."
    },
    {
      "id": 64,
      "question": "What does a server's TPM chip provide?",
      "options": [
        "Additional processing power",
        "Hardware-based security features",
        "Increased storage capacity",
        "Enhanced network speed"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A TPM (Trusted Platform Module) chip offers hardware-based security, such as encryption key storage and system integrity checks. It does not boost processing, storage, or networking.",
      "examTip": "TPM enhances security—think hardware-level protection."
    },
    {
      "id": 65,
      "question": "Which RAID level combines mirroring and striping for both performance and redundancy?",
      "options": [
        "RAID 0",
        "RAID 1",
        "RAID 5",
        "RAID 10"
      ],
      "correctAnswerIndex": 3,
      "explanation": "RAID 10 combines striping (RAID 0) for performance and mirroring (RAID 1) for redundancy. RAID 0 is speed-only, RAID 1 is redundancy-only, and RAID 5 uses parity.",
      "examTip": "RAID 10 offers speed and safety—ideal for critical apps."
    },
    {
      "id": 66,
      "question": "What is the primary function of a server's NIC?",
      "options": [
        "Store data",
        "Process instructions",
        "Connect to the network",
        "Manage power"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A NIC (Network Interface Card) enables network connectivity. Storage devices handle data, the CPU processes instructions, and the PSU manages power.",
      "examTip": "NICs link servers to networks—essential for communication."
    },
    {
      "id": 67,
      "question": "Which type of memory is used by the CPU for quick access to frequently used data?",
      "options": [
        "RAM",
        "ROM",
        "Cache",
        "Flash"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Cache memory provides the CPU with fast access to frequently used data. RAM is main memory, ROM is non-volatile, and flash is used in storage.",
      "examTip": "Cache speeds up the CPU—know its proximity role."
    },
    {
      "id": 68,
      "question": "What does a server's SNMP agent do?",
      "options": [
        "Manage file transfers",
        "Monitor and report system status",
        "Assign IP addresses",
        "Synchronize time"
      ],
      "correctAnswerIndex": 1,
      "explanation": "An SNMP (Simple Network Management Protocol) agent monitors system status and reports to a management console. It does not handle file transfers, IP assignment, or time sync.",
      "examTip": "SNMP tracks health—great for proactive monitoring."
    },
    {
      "id": 69,
      "question": "Which server component is most critical for preventing overheating?",
      "options": [
        "CPU",
        "Cooling fans",
        "PSU",
        "Motherboard"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Cooling fans dissipate heat to prevent overheating. The CPU generates heat, the PSU powers components, and the motherboard connects them.",
      "examTip": "Fans are heat fighters—ensure they’re working."
    },
    {
      "id": 70,
      "question": "What is the main advantage of using a UPS with a server?",
      "options": [
        "Increases processing speed",
        "Provides temporary power during outages",
        "Enhances network security",
        "Reduces storage costs"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A UPS (Uninterruptible Power Supply) provides backup power during outages, preventing data loss or downtime. It does not affect speed, security, or storage costs.",
      "examTip": "UPS buys time—protects against sudden power loss."
    },
    {
      "id": 71,
      "question": "Which type of server is designed to handle high volumes of email traffic?",
      "options": [
        "Web server",
        "Mail server",
        "Database server",
        "File server"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Mail servers manage email traffic, including sending and receiving. Web servers host websites, database servers store data, and file servers manage files.",
      "examTip": "Mail servers power email—know their specialty."
    },
    {
      "id": 72,
      "question": "What does a server's firmware control?",
      "options": [
        "Operating system functions",
        "Hardware behavior and settings",
        "Network protocols",
        "Application performance"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Firmware, like BIOS or RAID controller software, governs hardware behavior and settings. The OS handles software, protocols manage networks, and apps run separately.",
      "examTip": "Firmware bridges hardware and software—updates are key."
    },
    {
      "id": 73,
      "question": "Which network device operates at Layer 2 of the OSI model?",
      "options": [
        "Router",
        "Switch",
        "Hub",
        "Firewall"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Switches operate at Layer 2 (Data Link) using MAC addresses. Routers work at Layer 3 (Network), hubs at Layer 1 (Physical), and firewalls span multiple layers.",
      "examTip": "Switches use MACs—Layer 2 is their domain."
    },
    {
      "id": 74,
      "question": "What is the primary purpose of a server's hot-swappable drive?",
      "options": [
        "Increase storage capacity",
        "Allow replacement without downtime",
        "Improve read/write speeds",
        "Enhance data security"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hot-swappable drives can be replaced without powering down the server, reducing downtime. They do not inherently boost capacity, speed, or security.",
      "examTip": "Hot-swap minimizes disruption—great for availability."
    },
    {
      "id": 75,
      "question": "Which protocol is used for secure remote command-line access to a server?",
      "options": [
        "Telnet",
        "SSH",
        "FTP",
        "HTTP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SSH (Secure Shell) provides encrypted remote command-line access. Telnet is insecure, FTP transfers files, and HTTP serves web content.",
      "examTip": "SSH is secure remote access—always choose it over Telnet."
    },
    {
      "id": 76,
      "question": "What does a server's virtualization layer (hypervisor) manage?",
      "options": [
        "Physical hardware resources",
        "Network traffic",
        "File system permissions",
        "Application installations"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The hypervisor manages physical resources (CPU, memory, etc.) for virtual machines. It does not handle networking, file permissions, or apps directly.",
      "examTip": "Hypervisors share hardware—core to virtualization."
    },
    {
      "id": 77,
      "question": "Which type of RAID requires at least four drives and can survive two drive failures?",
      "options": [
        "RAID 0",
        "RAID 1",
        "RAID 5",
        "RAID 6"
      ],
      "correctAnswerIndex": 3,
      "explanation": "RAID 6 uses dual parity and needs at least four drives, tolerating two failures. RAID 0 has no redundancy, RAID 1 mirrors, and RAID 5 uses single parity.",
      "examTip": "RAID 6 doubles down on fault tolerance—know its requirements."
    },
    {
      "id": 78,
      "question": "What is the main benefit of using a SAN over a NAS for database storage?",
      "options": [
        "File-level access",
        "Lower cost",
        "Block-level access",
        "Easier setup"
      ],
      "correctAnswerIndex": 2,
      "explanation": "SANs offer block-level access, which is faster and better suited for databases. NAS provides file-level access, and SANs are typically more expensive and complex.",
      "examTip": "SANs excel in performance—ideal for databases."
    },
    {
      "id": 79,
      "question": "Which server component is most likely to cause a bottleneck in a virtualized environment with many VMs?",
      "options": [
        "CPU",
        "RAM",
        "Storage",
        "Network"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RAM often becomes the bottleneck in virtualization, as each VM requires its own memory allocation. CPU, storage, and network can also limit, but memory is critical.",
      "examTip": "Memory is king in virtualization—watch its usage."
    },
    {
      "id": 80,
      "question": "What does a server's BIOS update typically address?",
      "options": [
        "Operating system security",
        "Hardware compatibility and stability",
        "Network configuration",
        "Application performance"
      ],
      "correctAnswerIndex": 1,
      "explanation": "BIOS updates improve hardware compatibility and stability or add features. They do not impact OS security, networking, or applications directly.",
      "examTip": "BIOS updates fix hardware quirks—check compatibility."
    },
    {
      "id": 81,
      "question": "Which type of server is used to cache web content for faster access?",
      "options": [
        "Proxy server",
        "File server",
        "Database server",
        "Application server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Proxy servers cache web content to speed up access and reduce bandwidth usage. File servers store files, database servers manage data, and application servers run apps.",
      "examTip": "Proxies boost web speed—know their caching role."
    },
    {
      "id": 82,
      "question": "What is the primary purpose of a server's RAID 5 configuration?",
      "options": [
        "Maximum performance with no redundancy",
        "Fault tolerance with parity",
        "Mirroring for data redundancy",
        "Striping with dual parity"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RAID 5 uses parity for fault tolerance, surviving one drive failure. RAID 0 is performance-only, RAID 1 mirrors, and RAID 6 uses dual parity.",
      "examTip": "RAID 5 balances cost and redundancy—parity is its trick."
    },
    {
      "id": 83,
      "question": "Which network protocol is used to transfer files securely between servers?",
      "options": [
        "FTP",
        "SFTP",
        "HTTP",
        "SNMP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SFTP (Secure File Transfer Protocol) encrypts file transfers for security. FTP is insecure, HTTP serves web pages, and SNMP manages devices.",
      "examTip": "SFTP is secure file movement—prefer it over FTP."
    },
    {
      "id": 84,
      "question": "What does a server's hot aisle/cold aisle layout help with?",
      "options": [
        "Network security",
        "Cooling efficiency",
        "Power distribution",
        "Storage management"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hot aisle/cold aisle layouts improve cooling efficiency by separating hot and cold airflows. They do not affect security, power, or storage directly.",
      "examTip": "Aisle layouts optimize cooling—data center essentials."
    },
    {
      "id": 85,
      "question": "Which type of backup is a point-in-time copy of a virtual machine?",
      "options": [
        "Full backup",
        "Incremental backup",
        "Snapshot",
        "Differential backup"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Snapshots capture a VM’s state at a specific moment for quick restoration. Full, incremental, and differential backups are broader strategies.",
      "examTip": "Snapshots are VM checkpoints—useful for testing."
    },
    {
      "id": 86,
      "question": "What is the main advantage of using a blade server enclosure?",
      "options": [
        "Lower cost per server",
        "Higher individual server performance",
        "Increased density and shared resources",
        "Easier physical maintenance"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Blade enclosures increase server density and share resources like power and cooling. They are often costlier, have similar performance, and can be harder to maintain.",
      "examTip": "Blades save space—density is their edge."
    },
    {
      "id": 87,
      "question": "Which protocol is used for remote desktop access to a Windows server?",
      "options": [
        "SSH",
        "RDP",
        "FTP",
        "Telnet"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RDP (Remote Desktop Protocol) enables remote desktop access to Windows servers. SSH is command-line, FTP transfers files, and Telnet is insecure.",
      "examTip": "RDP is Windows’ remote tool—know its purpose."
    },
    {
      "id": 88,
      "question": "What does a server's iDRAC or iLO interface allow administrators to do?",
      "options": [
        "Manage virtual machines",
        "Control hardware remotely",
        "Optimize storage performance",
        "Configure network settings"
      ],
      "correctAnswerIndex": 1,
      "explanation": "iDRAC (Dell) and iLO (HP) provide remote hardware management, such as power control and monitoring, independent of the OS. They do not manage VMs, storage, or networking directly.",
      "examTip": "iDRAC/iLO are hardware lifelines—key for remote fixes."
    },
    {
      "id": 89,
      "question": "Which type of server memory is non-volatile and retains data when power is off?",
      "options": [
        "RAM",
        "Cache",
        "ROM",
        "DRAM"
      ],
      "correctAnswerIndex": 2,
      "explanation": "ROM (Read-Only Memory) is non-volatile, retaining data without power, often used for firmware. RAM, cache, and DRAM are volatile.",
      "examTip": "ROM holds firmware—non-volatile is the clue."
    },
    {
      "id": 90,
      "question": "What is the primary purpose of a server's firewall?",
      "options": [
        "Increase network speed",
        "Block unauthorized access",
        "Manage storage allocation",
        "Enhance CPU performance"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A firewall blocks unauthorized network access based on rules, enhancing security. It does not affect speed, storage, or CPU performance.",
      "examTip": "Firewalls guard the gates—focus on access control."
    },
    {
      "id": 91,
      "question": "Which RAID level provides the highest level of fault tolerance?",
      "options": [
        "RAID 0",
        "RAID 1",
        "RAID 5",
        "RAID 6"
      ],
      "correctAnswerIndex": 3,
      "explanation": "RAID 6 offers the highest fault tolerance, surviving two drive failures with dual parity. RAID 0 has none, RAID 1 survives one, and RAID 5 survives one.",
      "examTip": "RAID 6 is top-tier redundancy—two failures, no problem."
    },
    {
      "id": 92,
      "question": "What does a server's SNMP trap do?",
      "options": [
        "Request data from devices",
        "Send alerts to a management system",
        "Synchronize time",
        "Assign IP addresses"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SNMP traps send unsolicited alerts to a management system when issues arise. Polling requests data, NTP syncs time, and DHCP assigns IPs.",
      "examTip": "SNMP traps shout for help—alerts are their job."
    },
    {
      "id": 93,
      "question": "Which type of server is used to host and manage virtual machines?",
      "options": [
        "Web server",
        "Hypervisor server",
        "Database server",
        "File server"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A hypervisor server hosts and manages virtual machines using software like VMware or Hyper-V. Web servers host sites, database servers manage data, and file servers store files.",
      "examTip": "Hypervisors run VMs—virtualization’s core."
    },
    {
      "id": 94,
      "question": "What is the main benefit of using a UPS with automatic voltage regulation (AVR)?",
      "options": [
        "Increases server speed",
        "Stabilizes input voltage",
        "Enhances network security",
        "Reduces storage needs"
      ],
      "correctAnswerIndex": 1,
      "explanation": "AVR in a UPS stabilizes input voltage, protecting hardware from surges or drops. It does not affect speed, security, or storage.",
      "examTip": "AVR smooths power—guards against fluctuations."
    },
    {
      "id": 95,
      "question": "Which network protocol is used to manage and monitor network devices?",
      "options": [
        "FTP",
        "SNMP",
        "DHCP",
        "NTP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SNMP (Simple Network Management Protocol) monitors and manages network devices. FTP transfers files, DHCP assigns IPs, and NTP syncs time.",
      "examTip": "SNMP keeps tabs on devices—management made easy."
    },
    {
      "id": 96,
      "question": "What does a server's redundant cooling fan configuration provide?",
      "options": [
        "Increased processing power",
        "Backup cooling if one fan fails",
        "Higher storage capacity",
        "Better network performance"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Redundant cooling fans ensure cooling continues if one fails, preventing overheating. They do not affect processing, storage, or networking.",
      "examTip": "Redundant fans keep temps down—reliability is key."
    },
    {
      "id": 97,
      "question": "Which type of server is designed to handle large volumes of print jobs?",
      "options": [
        "Web server",
        "Print server",
        "Database server",
        "Application server"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Print servers manage and queue print jobs for networked printers. Web servers host sites, database servers manage data, and application servers run apps.",
      "examTip": "Print servers handle printing—specialized role."
    },
    {
      "id": 98,
      "question": "What is the primary purpose of a server's RAID 1 configuration?",
      "options": [
        "Maximum performance",
        "Data mirroring for redundancy",
        "Parity-based fault tolerance",
        "Striping with dual parity"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RAID 1 mirrors data across drives for redundancy. RAID 0 boosts performance, RAID 5 uses parity, and RAID 6 uses dual parity.",
      "examTip": "RAID 1 is simple redundancy—mirroring is its strength."
    },
    {
      "id": 99,
      "question": "Which protocol is used to securely manage network devices over SSH?",
      "options": [
        "Telnet",
        "SNMPv3",
        "FTP",
        "HTTP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SNMPv3 supports secure management over SSH with encryption. Telnet is insecure, FTP transfers files, and HTTP serves web content.",
      "examTip": "SNMPv3 secures management—SSH is its ally."
    },
    {
      "id": 100,
      "question": "What does a server's hypervisor do in a virtualized environment?",
      "options": [
        "Manage physical storage",
        "Allocate resources to virtual machines",
        "Control network traffic",
        "Enhance application performance"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The hypervisor allocates physical resources (CPU, memory, etc.) to virtual machines. It does not manage storage, networking, or apps directly.",
      "examTip": "Hypervisors divvy up resources—VMs depend on them."
    }
  ]
});
