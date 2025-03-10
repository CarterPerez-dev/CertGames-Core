few things- first fix this You jump from 20 directly to 31.
So 21–30 never appear. If you meant to have a continuous sequence, those are missing.
42 appears three times in a row.
44 appears twice in a row.
You skip 46. You jump from 45 to 47.


then make the explantions more in depth


db.tests.insertOne({
  "category": "serverplus",
  "testId": 2,
  "testName": "Server+ Practice Test #2 (Very Easy)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "Which RAID type provides mirroring but does not offer striping or parity?",
      "options": [
        "RAID 0",
        "RAID 1",
        "RAID 5",
        "RAID 10"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RAID 1 directly mirrors data between two drives without striping or parity.",
      "examTip": "Remember, RAID 1 is purely mirroring—no striping or parity."
    },
    {
      "id": 2,
      "question": "Which storage technology connects directly to a server without using network infrastructure?",
      "options": [
        "NAS",
        "SAN",
        "DAS",
        "Cloud storage"
      ],
      "correctAnswerIndex": 2,
      "explanation": "DAS (Direct Attached Storage) connects directly to the server without network involvement.",
      "examTip": "Directly attached storage connects physically and directly—no network required."
    },
    {
      "id": 3,
      "question": "Which cable type typically connects servers to switches in a standard Ethernet network?",
      "options": [
        "RJ-11 cable",
        "Twisted-pair Ethernet cable",
        "Fiber optic ST connector",
        "Serial RS-232 cable"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Twisted-pair Ethernet cables directly connect servers to switches.",
      "examTip": "Twisted-pair Ethernet cables (e.g., Cat5e or Cat6) connect servers to network switches."
    },
    {
      "id": 4,
      "question": "Which term describes temporarily shutting down a server for planned upgrades or maintenance?",
      "options": [
        "Failover",
        "Downtime",
        "Replication",
        "Provisioning"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Downtime specifically refers to planned or unplanned server unavailability.",
      "examTip": "Downtime is the straightforward term for planned server unavailability."
    },
    {
      "id": 5,
      "question": "Which backup type copies all files and resets archive bits after completion?",
      "options": [
        "Incremental backup",
        "Full backup",
        "Differential backup",
        "Snapshot backup"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A full backup copies all data and resets archive bits upon completion.",
      "examTip": "A full backup resets archive bits—essential for incremental backup strategies."
    },
    {
      "id": 6,
      "question": "Which type of server chassis is designed primarily to save physical space and improve density?",
      "options": [
        "Tower server",
        "Rack-mounted server",
        "Desktop workstation",
        "Standalone NAS"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Rack-mounted servers maximize density and conserve space in data centers.",
      "examTip": "Rack-mounted servers optimize physical space in server rooms."
    },
    {
      "id": 7,
      "question": "What is the main advantage of using an Uninterruptible Power Supply (UPS) with servers?",
      "options": [
        "Increasing server storage capacity",
        "Improving network speeds",
        "Providing temporary power during outages",
        "Enhancing physical security"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A UPS directly provides backup power during outages, preventing unexpected shutdowns.",
      "examTip": "Use a UPS to prevent data loss during power outages."
    },
    {
      "id": 8,
      "question": "Which type of connector is commonly used for fiber optic cable connections?",
      "options": [
        "RJ45",
        "BNC",
        "SC connector",
        "DB9"
      ],
      "correctAnswerIndex": 2,
      "explanation": "SC connectors are specifically used for fiber optic connections.",
      "examTip": "SC and LC connectors are common fiber optic cable connectors."
    },
    {
      "id": 9,
      "question": "Which operating system installation type involves installing directly onto physical server hardware?",
      "options": [
        "Bare-metal installation",
        "Virtualized installation",
        "Containerized installation",
        "Network-based installation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Bare-metal installation directly places an OS onto physical hardware without virtualization.",
      "examTip": "Bare-metal means direct installation on physical hardware."
    },
    {
      "id": 10,
      "question": "Which file system type is primarily associated with Windows operating systems?",
      "options": [
        "ext4",
        "NTFS",
        "ZFS",
        "VMFS"
      ],
      "correctAnswerIndex": 1,
      "explanation": "NTFS is natively used by Windows OS for file management and security.",
      "examTip": "NTFS is Windows’ default and primary file system."
    },
    {
      "id": 11,
      "question": "Which server feature specifically allows the replacement of failed drives without shutting down the server?",
      "options": [
        "Cold-swap drives",
        "Hot-swap drives",
        "RAID parity",
        "Drive mirroring"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hot-swappable drives enable replacement while the server remains powered on.",
      "examTip": "Remember, 'hot-swap' means no downtime during component replacement."
    },
    {
      "id": 12,
      "question": "Which device provides centralized management for multiple servers using a single keyboard, mouse, and monitor?",
      "options": [
        "Switch",
        "UPS",
        "KVM switch",
        "Rack enclosure"
      ],
      "correctAnswerIndex": 2,
      "explanation": "KVM switches centralize access to multiple servers with one keyboard, video, and mouse.",
      "examTip": "A KVM switch streamlines server management by reducing console clutter."
    },
    {
      "id": 13,
      "question": "Which type of memory is volatile and typically used by servers to temporarily store data being actively processed?",
      "options": [
        "RAM",
        "SSD",
        "HDD",
        "ROM"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RAM temporarily stores active data and is volatile—data is lost upon power loss.",
      "examTip": "RAM is always volatile; it loses contents when power is lost."
    },
    {
      "id": 14,
      "question": "Which connector type is standard for Gigabit Ethernet connections?",
      "options": [
        "RJ45",
        "SC",
        "LC",
        "RJ11"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RJ45 connectors are standard for Ethernet cabling, including Gigabit connections.",
      "examTip": "RJ45 connectors are synonymous with Ethernet networking."
    },
    {
      "id": 15,
      "question": "What storage technology is specifically designed for sharing files over a local network using standard file protocols?",
      "options": [
        "SAN",
        "NAS",
        "DAS",
        "RAID"
      ],
      "correctAnswerIndex": 1,
      "explanation": "NAS provides file-level storage access via common network protocols (SMB, NFS).",
      "examTip": "Use NAS when simple file-level network access is needed."
    },
    {
      "id": 16,
      "question": "Which method ensures a server continues running even if one of its two power supplies fails?",
      "options": [
        "Power redundancy",
        "RAID parity",
        "Disk mirroring",
        "NIC teaming"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Power redundancy allows continued operation despite power supply failure.",
      "examTip": "Redundant power supplies ensure uninterrupted server operation."
    },
    {
      "id": 17,
      "question": "Which type of virtualization involves running an operating system within another operating system as a guest?",
      "options": [
        "Type 1 Hypervisor",
        "Type 2 Hypervisor",
        "Bare-metal virtualization",
        "Containerization"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Type 2 hypervisors run inside a host OS, hosting virtualized guest OSes.",
      "examTip": "Type 2 hypervisors operate within a host OS, not directly on hardware."
    },
    {
      "id": 18,
      "question": "Which protocol provides automatic IP address assignment to network devices?",
      "options": [
        "DNS",
        "DHCP",
        "FTP",
        "SMTP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "DHCP automatically assigns IP addresses to networked devices.",
      "examTip": "DHCP manages automatic IP assignments within networks."
    },
    {
      "id": 19,
      "question": "Which security feature verifies user identities by requiring multiple authentication methods?",
      "options": [
        "Single Sign-On (SSO)",
        "Multifactor Authentication (MFA)",
        "Role-based access control",
        "Encryption"
      ],
      "correctAnswerIndex": 1,
      "explanation": "MFA requires multiple authentication methods to verify user identity securely.",
      "examTip": "MFA significantly strengthens user authentication."
    },
    {
      "id": 20,
      "question": "Which storage device has no moving parts and provides faster read and write speeds compared to traditional disks?",
      "options": [
        "SSD",
        "Tape drive",
        "Magnetic HDD",
        "CD-ROM"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Solid State Drives (SSD) use flash memory with no moving parts, providing high speeds.",
      "examTip": "SSDs deliver performance benefits due to the lack of moving mechanical parts."
    },
    {
      "id": 31,
      "question": "Which technology allows a physical CPU core to handle multiple threads simultaneously?",
      "options": [
        "Hyper-threading",
        "Overclocking",
        "RAID striping",
        "ECC memory"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Hyper-threading enables a CPU core to process multiple threads concurrently, improving performance.",
      "examTip": "Hyper-threading maximizes CPU efficiency by handling multiple threads per core."
    },
    {
      "id": 32,
      "question": "What type of connector is commonly used to provide external SATA connectivity?",
      "options": [
        "eSATA",
        "RJ45",
        "SC",
        "LC"
      ],
      "correctAnswerIndex": 0,
      "explanation": "eSATA connectors are specifically designed for external SATA connections.",
      "examTip": "Use eSATA connectors for external SATA storage devices."
    },
    {
      "id": 33,
      "question": "Which tool directly enables secure remote command-line management of Linux servers?",
      "options": [
        "Telnet",
        "SSH",
        "RDP",
        "FTP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SSH provides secure, encrypted remote command-line access to Linux servers.",
      "examTip": "Always choose SSH over Telnet for secure remote access."
    },
    {
      "id": 34,
      "question": "Which RAID level uses striping without redundancy or fault tolerance?",
      "options": [
        "RAID 0",
        "RAID 1",
        "RAID 5",
        "RAID 10"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RAID 0 uses striping for performance without providing redundancy or fault tolerance.",
      "examTip": "RAID 0 offers speed but provides no redundancy."
    },
    {
      "id": 35,
      "question": "Which backup method saves all selected files regardless of previous backups?",
      "options": [
        "Differential backup",
        "Full backup",
        "Incremental backup",
        "Snapshot backup"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A full backup always backs up all selected files, independent of past backups.",
      "examTip": "Full backups capture everything, ideal for periodic comprehensive backups."
    },
    {
      "id": 36,
      "question": "What is the primary advantage of fiber optic cabling compared to twisted-pair copper cabling?",
      "options": [
        "Lower cost",
        "Faster network speeds over longer distances",
        "Easier installation",
        "Higher susceptibility to interference"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Fiber optic cables offer higher speeds over longer distances compared to copper cables.",
      "examTip": "Use fiber optics for high-speed, long-distance network connections."
    },
    {
      "id": 37,
      "question": "Which type of document specifically outlines procedures for recovering systems after a major disruption?",
      "options": [
        "Business Impact Analysis (BIA)",
        "Disaster Recovery Plan (DRP)",
        "Asset inventory",
        "Infrastructure diagram"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A Disaster Recovery Plan outlines recovery procedures after a major disruption.",
      "examTip": "Always maintain a detailed Disaster Recovery Plan for system restoration."
    },
    {
      "id": 38,
      "question": "Which type of storage device traditionally uses magnetic tapes for data backup and archival?",
      "options": [
        "NAS",
        "Tape drive",
        "SSD",
        "RAID array"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Tape drives utilize magnetic tapes primarily for backup and archival purposes.",
      "examTip": "Tape drives offer reliable, cost-effective archival storage solutions."
    },
    {
      "id": 39,
      "question": "Which virtualization technology directly allocates physical resources such as CPUs and memory to virtual machines?",
      "options": [
        "Hypervisor",
        "File server",
        "RAID controller",
        "Load balancer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A hypervisor manages and directly allocates physical resources to virtual machines.",
      "examTip": "Hypervisors are central to virtualization, managing resource allocation."
    },
    {
      "id": 40,
      "question": "What type of site provides basic facilities but requires significant setup time during disaster recovery?",
      "options": [
        "Hot site",
        "Warm site",
        "Cold site",
        "Production site"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A cold site provides space and basic facilities but requires setup during recovery.",
      "examTip": "Cold sites are cost-effective but require significant setup in disaster situations."
    },
    {
      "id": 41,
      "question": "Which RAID type uses disk striping with parity to offer both performance and redundancy?",
      "options": [
        "RAID 0",
        "RAID 1",
        "RAID 5",
        "RAID 10"
      ],
      "correctAnswerIndex": 2,
      "explanation": "RAID 5 uses striping with parity, balancing redundancy and performance.",
      "examTip": "RAID 5 provides a good balance between redundancy and performance."
    },
    {
      "id": 42,
      "question": "Which network device enables multiple servers to share a single keyboard, monitor, and mouse?",
      "options": [
        "Switch",
        "Router",
        "KVM",
        "Firewall"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A KVM device allows multiple servers to be controlled using a single keyboard, video, and mouse setup.",
      "examTip": "Use a KVM to manage multiple servers from a single console efficiently."
    },
    {
      "id": 43,
      "question": "What storage device provides direct, block-level access to storage resources across a network?",
      "options": [
        "NAS",
        "SAN",
        "DAS",
        "Cloud Storage"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A SAN provides block-level access to storage over a dedicated network.",
      "examTip": "SANs provide high-performance block-level network storage access."
    },
    {
      "id": 42,
      "question": "What feature provides server redundancy by distributing network traffic across multiple servers?",
      "options": [
        "RAID",
        "Load balancing",
        "Backup",
        "Virtualization"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Load balancing distributes network traffic evenly, reducing risk and improving performance.",
      "examTip": "Use load balancing to enhance network reliability and performance."
    },
    {
      "id": 42,
      "question": "Which hardware component is directly responsible for storing BIOS settings?",
      "options": [
        "RAM module",
        "SSD drive",
        "CMOS battery",
        "NIC"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The CMOS battery maintains BIOS settings including date and configuration.",
      "examTip": "A failing CMOS battery can cause BIOS configuration loss."
    },
    {
      "id": 43,
      "question": "What file system type is most commonly used with Linux servers?",
      "options": [
        "NTFS",
        "FAT32",
        "ext4",
        "VMFS"
      ],
      "correctAnswerIndex": 2,
      "explanation": "ext4 is the standard Linux filesystem due to reliability and performance.",
      "examTip": "ext4 is the default filesystem for most Linux distributions."
    },
    {
      "id": 44,
      "question": "What does UPS stand for in server hardware terms?",
      "options": [
        "Universal Power Source",
        "Uninterruptible Power Supply",
        "Unified Power System",
        "Unit Power Standard"
      ],
      "correctAnswerIndex": 1,
      "explanation": "UPS stands for Uninterruptible Power Supply, providing backup power during outages.",
      "examTip": "A UPS prevents unexpected shutdowns during power failures."
    },
    {
      "id": 44,
      "question": "What connector type is commonly used to terminate Ethernet cables?",
      "options": [
        "RJ45",
        "RJ11",
        "DB9",
        "HDMI"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RJ45 connectors are standard for Ethernet networking cables.",
      "examTip": "Remember RJ45 connectors for Ethernet networking."
    },
    {
      "id": 45,
      "question": "Which command directly tests network connectivity between two hosts?",
      "options": [
        "ping",
        "tracert",
        "nslookup",
        "route"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The ping command directly verifies network connectivity between hosts.",
      "examTip": "Use ping first when diagnosing basic connectivity issues."
    },


      
    {
      "id": 47,
      "question": "Which type of user authentication requires more than one verification factor, enhancing account security?",
      "options": [
        "Single-factor authentication",
        "Biometric authentication",
        "Multifactor authentication (MFA)",
        "Single sign-on (SSO)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Multifactor authentication requires multiple methods, greatly enhancing security.",
      "examTip": "Implement MFA for increased security beyond simple passwords."
    },
    {
      "id": 48,
      "question": "Which physical security device is specifically designed to prevent unauthorized personnel entry?",
      "options": [
        "Firewall appliance",
        "Mantrap",
        "RAID controller",
        "Backup tapes"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A mantrap directly controls physical access by limiting entry to authorized individuals.",
      "examTip": "Use mantraps for secure access control at sensitive locations."
    },
    {
      "id": 49,
      "question": "Which tool can administrators use for remote graphical management of a Windows server?",
      "options": [
        "SSH",
        "RDP",
        "FTP",
        "SMTP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Remote Desktop Protocol (RDP) allows remote graphical management of Windows servers.",
      "examTip": "RDP enables remote graphical control of Windows servers."
    },
    {
      "id": 50,
      "question": "What type of server hardware provides compact, modular computing capabilities within a shared enclosure?",
      "options": [
        "Blade servers",
        "Tower servers",
        "Rack-mount servers",
        "Desktop servers"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Blade servers are modular units housed in a compact shared enclosure.",
      "examTip": "Blade servers maximize server density and modular design."
    },
    {
      "id": 51,
      "question": "Which RAID type provides striping without any redundancy, resulting in increased performance but higher risk?",
      "options": [
        "RAID 0",
        "RAID 1",
        "RAID 5",
        "RAID 10"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RAID 0 provides data striping but no redundancy, increasing risk.",
      "examTip": "RAID 0 is for speed, but offers no fault tolerance."
    },
    {
      "id": 52,
      "question": "Which feature helps maintain server functionality by providing backup power during short-term outages?",
      "options": [
        "PDU",
        "UPS",
        "NIC teaming",
        "Surge protector"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A UPS maintains power temporarily, preventing downtime during short outages.",
      "examTip": "Always pair critical servers with a UPS for immediate power redundancy."
    },
    {
      "id": 53,
      "question": "Which document tracks server hardware details, such as model numbers and serial numbers?",
      "options": [
        "Infrastructure diagram",
        "Asset inventory",
        "Performance logs",
        "System logs"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Asset inventory tracks detailed hardware information, such as serial numbers and models.",
      "examTip": "Maintain accurate asset inventories to simplify hardware management."
    },
    {
      "id": 54,
      "question": "Which storage method directly connects to a server, not using network-based protocols?",
      "options": [
        "DAS",
        "NAS",
        "SAN",
        "Cloud storage"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Direct Attached Storage (DAS) connects storage physically to a server without network protocols.",
      "examTip": "DAS provides straightforward, direct-attached storage solutions."
    },
    {
      "id": 55,
      "question": "Which server OS installation method is quickest when deploying identical configurations to multiple servers?",
      "options": [
        "Optical media installation",
        "Manual installation",
        "Cloning or imaging",
        "Remote desktop installation"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Cloning or imaging rapidly deploys identical OS setups across multiple servers.",
      "examTip": "Choose cloning or imaging for fast, standardized OS deployments."
    },
    {
      "id": 56,
      "question": "What device helps reduce server downtime by providing multiple network paths if one path fails?",
      "options": [
        "NIC teaming",
        "Firewall",
        "Load balancer",
        "DHCP server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NIC teaming provides redundancy and reduces downtime by managing multiple network paths.",
      "examTip": "NIC teaming provides immediate network redundancy to servers."
    },
    {
      "id": 57,
      "question": "Which file system format is standard on most Linux-based servers?",
      "options": [
        "NTFS",
        "ext4",
        "FAT32",
        "ReFS"
      ],
      "correctAnswerIndex": 1,
      "explanation": "ext4 is the default filesystem commonly used on Linux servers.",
      "examTip": "ext4 remains the most common Linux filesystem for stability and compatibility."
    },
    {
      "id": 58,
      "question": "What provides centralized storage accessible by multiple servers over a local network?",
      "options": [
        "SAN",
        "NAS",
        "DAS",
        "Local SSD"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Network Attached Storage (NAS) allows file-level access by multiple servers over a LAN.",
      "examTip": "Choose NAS for easy, centralized file-level storage across multiple servers."
    },
    {
      "id": 59,
      "question": "Which server chassis type is designed to stand upright independently on the floor?",
      "options": [
        "Blade enclosure",
        "Rack-mounted server",
        "Tower server",
        "Virtual server"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Tower servers are freestanding units designed to stand independently.",
      "examTip": "Tower servers are ideal for smaller environments without dedicated server racks."
    },
    {
      "id": 60,
      "question": "Which method ensures a server continues operating despite the failure of a single network card?",
      "options": [
        "RAID",
        "NIC teaming",
        "Firewall rules",
        "Incremental backup"
      ],
      "correctAnswerIndex": 1,
      "explanation": "NIC teaming provides redundancy, allowing network operations to continue after a NIC failure.",
      "examTip": "NIC teaming provides network redundancy to avoid downtime."
    },
    {
      "id": 61,
      "question": "Which protocol assigns domain names to IP addresses?",
      "options": [
        "DNS",
        "DHCP",
        "FTP",
        "SMTP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "DNS resolves domain names into IP addresses for network communication.",
      "examTip": "DNS translates human-readable names to IP addresses."
    },
    {
      "id": 62,
      "question": "Which file system is primarily used in VMware virtualization environments?",
      "options": [
        "NTFS",
        "ext4",
        "VMFS",
        "ZFS"
      ],
      "correctAnswerIndex": 2,
      "explanation": "VMFS is specifically designed by VMware for virtual machine storage.",
      "examTip": "VMware environments typically use VMFS as the storage filesystem."
    },
    {
      "id": 63,
      "question": "Which storage method is directly connected to a server and does not use networking?",
      "options": [
        "NAS",
        "SAN",
        "DAS",
        "Cloud storage"
      ],
      "correctAnswerIndex": 2,
      "explanation": "DAS connects directly without network-based protocols, unlike NAS and SAN.",
      "examTip": "Direct Attached Storage (DAS) connects physically and directly without network devices."
    },
    {
      "id": 64,
      "question": "Which type of RAID uses mirroring across two drives for redundancy?",
      "options": [
        "RAID 0",
        "RAID 1",
        "RAID 5",
        "RAID 6"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RAID 1 duplicates data across two disks for redundancy.",
      "examTip": "Remember RAID 1 as simple mirroring for redundancy."
    },
    {
      "id": 65,
      "question": "Which protocol allows administrators to manage servers remotely via an encrypted terminal?",
      "options": [
        "Telnet",
        "SSH",
        "FTP",
        "HTTP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SSH securely encrypts remote terminal sessions for server management.",
      "examTip": "Always use SSH instead of Telnet for secure remote access."
    },
    {
      "id": 66,
      "question": "Which type of memory retains its data only while the server is powered on?",
      "options": [
        "SSD",
        "HDD",
        "RAM",
        "ROM"
      ],
      "correctAnswerIndex": 2,
      "explanation": "RAM is volatile memory that loses its contents when powered off.",
      "examTip": "RAM only retains data while power is on."
    },
    {
      "id": 67,
      "question": "What ensures continued server operation during short power outages?",
      "options": [
        "Firewall",
        "Uninterruptible Power Supply (UPS)",
        "Load balancer",
        "Network switch"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A UPS provides backup power, preventing server downtime during outages.",
      "examTip": "Always pair critical servers with a UPS to protect against unexpected outages."
    },
    {
      "id": 68,
      "question": "Which server installation method involves installing an operating system directly onto hardware without a hypervisor?",
      "options": [
        "Virtualized installation",
        "Containerized installation",
        "Bare-metal installation",
        "Cloud-based installation"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Bare-metal installations install directly onto physical hardware, without virtualization layers.",
      "examTip": "Bare-metal installations are directly installed onto physical servers."
    },
    {
      "id": 69,
      "question": "Which component is directly responsible for cooling a server's CPU?",
      "options": [
        "RAID controller",
        "Heat sink and fan",
        "Power supply",
        "Network interface card"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A CPU cooler (heatsink and fan) directly dissipates heat from the CPU.",
      "examTip": "CPU cooling solutions directly maintain stable processor temperatures."
    },
    {
      "id": 70,
      "question": "Which backup type captures only data changed since the last backup, whether full or incremental?",
      "options": [
        "Full backup",
        "Differential backup",
        "Incremental backup",
        "Snapshot backup"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Incremental backups store only data changed since the last backup, whether it was full or incremental.",
      "examTip": "Incremental backups are smaller but require multiple sets to restore fully."
    },
    {
      "id": 71,
      "question": "Which storage protocol provides block-level access to storage over an IP network?",
      "options": [
        "FTP",
        "SMB",
        "NFS",
        "iSCSI"
      ],
      "correctAnswerIndex": 3,
      "explanation": "iSCSI delivers block-level storage access via standard IP networks.",
      "examTip": "iSCSI is used for block-level storage access over IP networks."
    },
    {
      "id": 72,
      "question": "Which power connector type is commonly used to supply power to servers in a rack?",
      "options": [
        "C13/C14",
        "RJ45",
        "ST",
        "LC"
      ],
      "correctAnswerIndex": 0,
      "explanation": "C13/C14 connectors are standard power connectors for rack-mounted servers.",
      "examTip": "Use C13/C14 connectors for reliable server power connections."
    },
    {
      "id": 73,
      "question": "Which hardware management tool provides administrators with access to servers even when the OS fails?",
      "options": [
        "SSH",
        "Remote Desktop Protocol",
        "IPMI",
        "Telnet"
      ],
      "correctAnswerIndex": 2,
      "explanation": "IPMI enables management and troubleshooting independent of the server OS.",
      "examTip": "IPMI is ideal for managing servers at the hardware level."
    },
    {
      "id": 74,
      "question": "Which of these is an advantage of solid-state drives over traditional HDDs?",
      "options": [
        "Lower cost per GB",
        "Faster access speeds",
        "Higher storage capacity",
        "Longer physical size"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SSDs offer significantly faster data access speeds compared to traditional HDDs.",
      "examTip": "SSDs offer speed advantages due to no mechanical moving parts."
    },
    {
      "id": 75,
      "question": "Which method specifically prevents unauthorized booting by securing the BIOS or UEFI interface?",
      "options": [
        "Setting BIOS passwords",
        "Installing antivirus software",
        "Running regular backups",
        "Using RAID configurations"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Setting BIOS passwords prevents unauthorized system boot attempts.",
      "examTip": "Use BIOS passwords to directly protect against unauthorized server access."
    },
    {
      "id": 76,
      "question": "Which tool allows direct secure file transfers between Linux servers?",
      "options": [
        "Telnet",
        "FTP",
        "SCP",
        "DHCP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Secure Copy Protocol (SCP) securely transfers files between servers over SSH.",
      "examTip": "Use SCP for secure, encrypted server-to-server file transfers."
    },
    {
      "id": 77,
      "question": "Which memory type can detect and correct single-bit errors automatically?",
      "options": [
        "Non-ECC RAM",
        "DDR3 RAM",
        "ECC RAM",
        "Cache memory"
      ],
      "correctAnswerIndex": 2,
      "explanation": "ECC RAM automatically detects and corrects single-bit memory errors.",
      "examTip": "ECC RAM improves reliability by correcting single-bit memory errors."
    },
    {
      "id": 78,
      "question": "Which backup strategy provides the quickest recovery of data after a major failure?",
      "options": [
        "Full backup",
        "Differential backup",
        "Incremental backup",
        "Weekly backup"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Full backups provide the quickest recovery, as they include all data required for restoration.",
      "examTip": "Full backups offer the simplest and fastest recovery."
    },
    {
      "id": 79,
      "question": "Which storage device is specifically designed to store data temporarily and is cleared upon reboot?",
      "options": [
        "SSD",
        "HDD",
        "RAM",
        "USB Flash Drive"
      ],
      "correctAnswerIndex": 2,
      "explanation": "RAM temporarily holds data while powered and clears data upon reboot or power loss.",
      "examTip": "RAM is volatile memory, meaning it loses data when powered off."
    },
    {
      "id": 80,
      "question": "Which device provides centralized distribution of electrical power to multiple servers in a rack?",
      "options": [
        "Power Distribution Unit (PDU)",
        "Uninterruptible Power Supply (UPS)",
        "Voltage regulator",
        "Surge protector"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A Power Distribution Unit (PDU) consolidates electrical power distribution, providing organized power management for multiple servers from a single source. While a UPS provides backup power, it does not centrally distribute power.",
      "examTip": "Use PDUs for centralized power management in server racks."
    },
    {
      "id": 81,
      "question": "What is the primary purpose of using VLANs in server networks?",
      "options": [
        "Increasing data storage capacity",
        "Enhancing physical security",
        "Improving network segmentation and security",
        "Increasing CPU performance"
      ],
      "correctAnswerIndex": 1,
      "explanation": "VLANs logically segment network traffic, enhancing security and reducing broadcast domains. They isolate network segments, improving security and traffic management. Other options listed do not describe VLAN functions.",
      "examTip": "VLANs enhance network security and organization by logical separation."
    },
    {
      "id": 82,
      "question": "What is the main function of a firewall in server management?",
      "options": [
        "To store backup data securely",
        "To encrypt file transfers",
        "To filter incoming and outgoing network traffic",
        "To provide power redundancy"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A firewall's main function is controlling and monitoring network traffic based on defined security rules. It prevents unauthorized access and secures communication between trusted and untrusted networks.",
      "examTip": "Always use firewalls to filter and secure network traffic effectively."
    },
    {
      "id": 83,
      "question": "Which server management method allows direct hardware-level control without relying on the operating system?",
      "options": [
        "Remote Desktop",
        "SSH",
        "IPMI",
        "FTP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Intelligent Platform Management Interface (IPMI) enables direct, out-of-band hardware management, including powering servers on and off independently of the OS status. Other methods depend on the OS being operational.",
      "examTip": "IPMI provides out-of-band management essential for server troubleshooting."
    },
    {
      "id": 84,
      "question": "What type of backup captures the state of a system at a specific point in time without affecting ongoing operations?",
      "options": [
        "Full backup",
        "Snapshot backup",
        "Incremental backup",
        "Differential backup"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Snapshot backups capture the exact state of a system at a specific moment, allowing quick restores without significantly interrupting operations. Incremental and differential backups track file changes but not system state precisely.",
      "examTip": "Use snapshot backups for fast recovery of system state."
    },
    {
      "id": 85,
      "question": "Which server room environmental control directly prevents overheating?",
      "options": [
        "Fire suppression system",
        "HVAC cooling",
        "Security cameras",
        "Mantrap"
      ],
      "correctAnswerIndex": 1,
      "explanation": "HVAC systems directly regulate server room temperatures by controlling cooling and ventilation, preventing overheating. Fire suppression and security devices do not directly regulate temperature.",
      "examTip": "Effective HVAC systems directly protect servers from overheating."
    },
    {
      "id": 86,
      "question": "Which hardware component is specifically designed to store firmware used during the initial startup of a server?",
      "options": [
        "SSD",
        "RAM",
        "BIOS/UEFI chip",
        "HDD"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The BIOS or UEFI chip stores firmware that initializes hardware during system boot-up. Unlike HDD or SSD storage, this chip directly manages initial hardware configuration and boot processes.",
      "examTip": "Firmware for system boot resides on BIOS/UEFI chips."
    },
    {
      "id": 87,
      "question": "What component ensures servers maintain correct date and time synchronization across a network?",
      "options": [
        "DNS server",
        "DHCP server",
        "NTP server",
        "FTP server"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Network Time Protocol (NTP) synchronizes server clocks, ensuring consistent and accurate timekeeping. DNS, DHCP, and FTP provide different network services unrelated to time synchronization.",
      "examTip": "Use NTP for precise, network-wide time synchronization."
    },
    {
      "id": 88,
      "question": "What type of documentation records specific hardware details such as serial numbers, make, and model?",
      "options": [
        "Network topology diagrams",
        "Asset inventory records",
        "Performance logs",
        "Security policies"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Asset inventory documentation specifically tracks hardware details, including serial numbers, make, model, and other identifying details. Other documents focus on different aspects, such as network or security.",
      "examTip": "Keep detailed asset inventories for efficient hardware management."
    },
    {
      "id": 89,
      "question": "What method allows administrators to install an operating system remotely across multiple servers simultaneously?",
      "options": [
        "Manual installation via USB",
        "Installation via optical drive",
        "Network-based installation (PXE)",
        "Virtual machine snapshot"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Network-based installation using PXE enables simultaneous remote installations across multiple servers, eliminating the need for manual or physical media installations, significantly speeding up deployment.",
      "examTip": "Use PXE boot for efficient remote OS deployments across multiple servers."
    },
    {
      "id": 90,
      "question": "Which server document provides a visual representation of hardware and networking connections?",
      "options": [
        "Asset inventory list",
        "Infrastructure diagram",
        "Security policy document",
        "Business impact analysis"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Infrastructure diagrams visually outline server hardware and network connections, allowing administrators to understand network topology and interdependencies clearly. Asset inventories list components but lack visual details.",
      "examTip": "Infrastructure diagrams visually represent server and network layouts."
    },
    {
      "id": 91,
      "question": "What physical security measure involves verifying identities based on unique biological characteristics?",
      "options": [
        "RFID badges",
        "PIN entry systems",
        "Biometric authentication",
        "Mantraps"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Biometric authentication identifies users based on unique biological traits like fingerprints or retinal scans, significantly enhancing physical security by ensuring only authorized individuals gain access.",
      "examTip": "Biometric systems provide high levels of security through unique biological identification."
    },
    {
      "id": 92,
      "question": "Which RAID configuration directly combines disk mirroring with disk striping?",
      "options": [
        "RAID 0",
        "RAID 1",
        "RAID 5",
        "RAID 10"
      ],
      "correctAnswerIndex": 3,
      "explanation": "RAID 10 combines mirroring (RAID 1) and striping (RAID 0), providing redundancy and improved performance. It requires a minimum of four drives, offering fault tolerance with high performance.",
      "examTip": "RAID 10 is ideal when both performance and redundancy are required."
    },
    {
      "id": 93,
      "question": "What network cabling standard supports speeds of 10 Gigabit Ethernet over short distances within server racks?",
      "options": [
        "Cat5",
        "Cat5e",
        "Cat6a",
        "Coaxial cable"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Cat6a cabling is specifically designed to support 10 Gigabit Ethernet speeds reliably over short distances (up to 100 meters), ideal for server racks and data centers. Cat5 and Cat5e typically support only up to 1Gbps reliably.",
      "examTip": "Choose Cat6a cables for reliable 10Gbps Ethernet connectivity."
    },
    {
      "id": 94,
      "question": "What is a primary advantage of using cloud-based backup solutions?",
      "options": [
        "Local data retrieval speed",
        "Elimination of the need for onsite storage infrastructure",
        "Physical security of server hardware",
        "Reduction in CPU load on servers"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Cloud-based backups eliminate the necessity for onsite storage hardware, reducing infrastructure costs and simplifying management. While retrieval might be slower, it enhances flexibility and scalability.",
      "examTip": "Cloud backups reduce onsite hardware needs and infrastructure complexity."
    },
    {
      "id": 95,
      "question": "What is the primary benefit of running virtual servers compared to physical servers?",
      "options": [
        "Improved physical security",
        "Reduced hardware utilization",
        "Easier and quicker scalability",
        "Increased CPU speed"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Virtual servers allow for rapid scaling without significant hardware changes, making resource allocation flexible, efficient, and cost-effective. Physical servers require additional hardware for scaling.",
      "examTip": "Virtualization provides flexibility and quick scalability without extra hardware."
    },
    {
      "id": 96,
      "question": "What technology is primarily used to balance incoming web traffic evenly across multiple web servers?",
      "options": [
        "Load balancer",
        "Firewall appliance",
        "DNS server",
        "UPS device"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A load balancer efficiently distributes incoming network traffic across multiple servers, enhancing availability and performance by evenly managing server workloads and preventing single points of failure.",
      "examTip": "Deploy load balancers to manage high volumes of web traffic effectively."
    },
    {
      "id": 97,
      "question": "Which action is the safest and most recommended when disposing of sensitive server storage media?",
      "options": [
        "Standard formatting",
        "Physical destruction or shredding",
        "Repartitioning the disk",
        "Deleting files manually"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Physically destroying or shredding storage media is the safest method to ensure data cannot be recovered. Other methods like formatting or file deletion leave the possibility of data recovery.",
      "examTip": "Always physically destroy sensitive media to securely prevent data recovery."
    },
    {
      "id": 98,
      "question": "What term refers to combining multiple physical network interfaces to act as a single logical interface?",
      "options": [
        "NIC teaming",
        "RAID striping",
        "Port forwarding",
        "Subnetting"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NIC teaming combines multiple physical network interfaces to form a single logical interface, providing redundancy and increased network throughput by aggregating bandwidth.",
      "examTip": "NIC teaming enhances both network redundancy and performance."
    },
    {
      "id": 99,
      "question": "Which device protects servers from power surges and voltage spikes?",
      "options": [
        "Firewall appliance",
        "Surge protector",
        "Switch",
        "Load balancer"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A surge protector shields servers from electrical surges and voltage spikes, preventing potential hardware damage and ensuring equipment longevity and reliability.",
      "examTip": "Always use surge protectors to safeguard servers from electrical spikes."
    },
    {
      "id": 100,
      "question": "What server maintenance practice directly helps prevent system overheating and hardware damage?",
      "options": [
        "Performing regular backups",
        "Applying OS patches promptly",
        "Regularly cleaning dust from server hardware",
        "Checking server log files"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Regularly cleaning dust buildup ensures proper airflow, reducing heat accumulation. Dust accumulation can significantly affect cooling efficiency, leading to overheating and hardware failure.",
      "examTip": "Periodic hardware cleaning prevents overheating and extends server lifespan."
    }
  ]
});
