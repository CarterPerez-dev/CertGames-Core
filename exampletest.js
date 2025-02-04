db.tests.insertOne({
  category: "aplus",
  testId: 1,
  testName: "A+ Practice Test #1",
  xpPerCorrect: 10,
  questions: [
    {
      id: 1,
      question: "Which of the following laptop components is primarily used for biometric security?",
      options: [
        "Fingerprint sensor",
        "NFC sensor",
        "Touchpad",
        "LCD inverter"
      ],
      correctAnswerIndex: 0,
      explanation: "Fingerprint sensor is correct because it authenticates users via unique prints. NFC sensor is wrong because it handles short-range data transfer, not biometric security. Touchpad is wrong because it controls the cursor, not biometrics. LCD inverter is wrong because it powers the display’s backlight. Exam tip: Know each laptop component's purpose and location."
    },
    {
      id: 2,
      question: "A user needs to replace the memory in a laptop. Which type of RAM module is most likely required?",
      options: [
        "DIMM",
        "SODIMM",
        "ROM",
        "CompactFlash"
      ],
      correctAnswerIndex: 1,
      explanation: "SODIMM is correct because laptops typically use Small Outline DIMMs for their smaller form factor. DIMM is wrong because standard desktops use full-sized DIMMs. ROM is wrong because it’s read-only memory used for firmware, not system RAM. CompactFlash is wrong because it’s a removable storage card, not system RAM. Exam tip: Be familiar with laptop-specific hardware terms like SODIMM."
    },
    {
      id: 3,
      question: "Which type of storage drive connection typically provides the highest throughput for an internal SSD?",
      options: [
        "SATA III",
        "PCIe/NVMe",
        "USB 3.1",
        "eSATA"
      ],
      correctAnswerIndex: 1,
      explanation: "PCIe/NVMe is correct because it uses a high-speed PCI Express interface for maximum SSD performance. SATA III is wrong because it's slower (up to 6 Gbps). USB 3.1 is wrong because it’s primarily external and still slower than NVMe in practical internal setups. eSATA is wrong because it's used externally and is limited by SATA speeds. Exam tip: NVMe drives far exceed traditional SATA speeds."
    },
    {
      id: 4,
      question: "A user has an older PC that displays a 3.3V power rail failure. Which component is most likely causing the problem?",
      options: [
        "Motherboard voltage regulator",
        "CPU fan",
        "RAM module",
        "Network card"
      ],
      correctAnswerIndex: 0,
      explanation: "Motherboard voltage regulator is correct because it regulates 3.3V for various motherboard components. CPU fan is wrong because a failing fan causes overheating, not a specific voltage rail issue. RAM module is wrong because bad RAM typically shows POST errors, not voltage rail failures. Network card is wrong because it usually doesn't directly cause a 3.3V rail failure. Exam tip: Power rail stability often depends on the motherboard’s voltage regulators."
    },
    {
      id: 5,
      question: "Which wireless standard operates only on the 5 GHz frequency and can provide speeds up to 1.3 Gbps (theoretical)?",
      options: [
        "802.11n",
        "802.11g",
        "802.11ac",
        "802.11b"
      ],
      correctAnswerIndex: 2,
      explanation: "802.11ac is correct because it operates primarily at 5 GHz and can achieve speeds around 1.3 Gbps or more. 802.11n is wrong because it can use 2.4 GHz or 5 GHz and typically caps lower. 802.11g and 802.11b are older and much slower. Exam tip: Pay attention to frequency bands and maximum theoretical speeds when identifying 802.11 standards."
    },
    {
      id: 6,
      question: "A technician wants to allow only secure, encrypted remote terminal access across TCP port 22. Which protocol should be allowed through the firewall?",
      options: [
        "Telnet",
        "SSH",
        "RDP",
        "SMB"
      ],
      correctAnswerIndex: 1,
      explanation: "SSH is correct because it provides encrypted terminal access over port 22. Telnet is wrong because it’s unencrypted and uses port 23. RDP is wrong because it uses port 3389 for remote desktop, not a text-based shell. SMB is wrong because it uses ports 445 (and sometimes 137-139), not 22. Exam tip: Remember key port numbers for common protocols."
    },
    {
      id: 7,
      question: "Which of the following is NOT needed for a basic virtual machine setup on a desktop PC?",
      options: [
        "Sufficient RAM",
        "Virtualization support in BIOS/UEFI",
        "GPU passthrough card",
        "Ample hard disk space"
      ],
      correctAnswerIndex: 2,
      explanation: "GPU passthrough card is correct to exclude because basic virtualization doesn’t require specialized GPU passthrough. Sufficient RAM is wrong because memory is essential for hosting virtual machines. Virtualization support in BIOS/UEFI is wrong because hardware-assisted virtualization must be enabled. Ample hard disk space is wrong because a VM requires space for virtual disks. Exam tip: Basic virtualization primarily relies on CPU virtualization extensions, enough RAM, and disk capacity."
    },
    {
      id: 8,
      question: "A user wants to install a RAID 1 array for data redundancy. Which configuration is correct?",
      options: [
        "Striping with no redundancy",
        "Mirroring across two drives",
        "Striping with parity across three drives",
        "Multiple drives in a spanning volume"
      ],
      correctAnswerIndex: 1,
      explanation: "Mirroring across two drives is correct because RAID 1 creates an exact copy on each drive. Striping with no redundancy is RAID 0, which doesn’t provide fault tolerance. Striping with parity is RAID 5 or 6, requiring at least three drives. Spanning is JBOD (Just a Bunch Of Disks), not a fault-tolerant RAID type. Exam tip: Know the fundamental RAID levels and their unique benefits/drawbacks."
    },
    {
      id: 9,
      question: "A technician is installing additional RAM in a dual-channel motherboard. Which configuration is recommended?",
      options: [
        "Populate slots in pairs of different sizes for maximum speed",
        "Install one module at a time for each channel",
        "Use matched pairs in the correct slot color coding",
        "Place all modules in adjacent slots, ignoring color"
      ],
      correctAnswerIndex: 2,
      explanation: "Use matched pairs in the correct slot color coding is correct because dual-channel boards usually require identical RAM modules in specific paired slots. Different sizes or ignoring color-coded slots can reduce performance or prevent dual-channel operation. Installing one module at a time doesn’t enable dual-channel. Exam tip: Always check the motherboard manual for RAM placement and channel configurations."
    },
    {
      id: 10,
      question: "Which network tool should a technician use to identify the exact location of a cable break inside a wall?",
      options: [
        "Loopback plug",
        "Toner probe",
        "Crimper",
        "Punchdown tool"
      ],
      correctAnswerIndex: 1,
      explanation: "Toner probe is correct because it helps trace and locate cable runs behind walls. Loopback plug is wrong because it tests ports by looping signals back. Crimper is wrong because it’s for attaching connectors. Punchdown tool is wrong because it secures wires into a patch panel or keystone jack. Exam tip: Toner probe kits are essential for tracing cable paths and identifying breaks."
    },
    {
      id: 11,
      question: "A user complains their laptop battery is draining quickly and physically bulging. Which is the BEST immediate action?",
      options: [
        "Perform a slow full discharge and recharge",
        "Keep using until battery fails completely",
        "Replace the battery and properly dispose of the old one",
        "Freeze the battery to reset its chemistry"
      ],
      correctAnswerIndex: 2,
      explanation: "Replace the battery and properly dispose of it is correct because a bulging battery can be a safety hazard. Fully discharging is wrong because it won’t fix a physically damaged or bulging battery. Continuing to use is dangerous. Freezing is wrong and can damage the battery further. Exam tip: Swollen lithium-ion batteries require immediate replacement to avoid potential fire hazards."
    },
    {
      id: 12,
      question: "Which troubleshooting step comes FIRST according to best practice methodology when a user reports a PC issue?",
      options: [
        "Test the theory to determine the cause",
        "Establish a theory of probable cause",
        "Identify the problem by gathering information",
        "Document all findings and close the ticket"
      ],
      correctAnswerIndex: 2,
      explanation: "Identify the problem by gathering information is correct because step 1 is always to collect details. Testing the theory is step 3, establishing a theory is step 2, and documentation is step 6. Exam tip: Memorize the CompTIA six-step troubleshooting methodology in the correct order."
    },
    {
      id: 13,
      question: "A technician notices the CPU is running excessively hot. Which is the MOST likely cause?",
      options: [
        "Faulty BIOS battery",
        "Insufficient thermal paste on the CPU",
        "Incorrect RAM timing",
        "Malfunctioning network adapter"
      ],
      correctAnswerIndex: 1,
      explanation: "Insufficient thermal paste is correct because poor heat conduction can cause CPU overheating. A faulty BIOS battery is wrong because it typically just loses date/time. Incorrect RAM timing is wrong because it can cause instability, not specifically high CPU temps. A malfunctioning NIC is wrong because it doesn’t directly affect CPU heat. Exam tip: Always check heatsinks and thermal compound when diagnosing heat-related CPU issues."
    },
    {
      id: 14,
      question: "A client wants to secure a new wireless network with encryption over a 5 GHz channel. Which standard is BEST to use?",
      options: [
        "WEP",
        "WPA",
        "WPA2/WPA3",
        "Open (no password)"
      ],
      correctAnswerIndex: 2,
      explanation: "WPA2/WPA3 is correct because they provide modern, robust encryption. WEP is wrong because it's obsolete and easily cracked. WPA is better than WEP but still weaker than WPA2/WPA3. An open network provides no encryption. Exam tip: Always use the strongest encryption supported by both access point and client devices."
    },
    {
      id: 15,
      question: "A user cannot access a website by its domain name, but can reach it by IP address. Which service is MOST likely malfunctioning?",
      options: [
        "DHCP",
        "LDAP",
        "DNS",
        "SMTP"
      ],
      correctAnswerIndex: 2,
      explanation: "DNS is correct because domain name resolution is failing. DHCP is wrong because it assigns IP addresses but isn’t responsible for hostname resolution once an IP is obtained. LDAP is wrong because it’s for directory services. SMTP is wrong because it’s for sending email. Exam tip: DNS issues typically manifest as domain name failures but still allow direct IP connections."
    }
  ]
});
