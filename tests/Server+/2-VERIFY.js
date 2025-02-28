
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
    }


