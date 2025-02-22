  db.tests.insertOne({
    category: 'aplus',
    testId: 1,
    testName: 'A+ Practice Test #1',
    xpPerCorrect: 10,
    questions: [
      {
        id: 1,
        question: 'Which of the following laptop components is primarily used for biometric security?',                                                                                   
        options: [
          'Fingerprint sensor',
          'NFC sensor',
          'Touchpad',
          'LCD inverter'
        ],
        correctAnswerIndex: 0,
        explanation: "Fingerprint sensor is correct because it authenticates users via unique prints. NFC sensor is wrong because it handles short-range data transfer, not biometric security. Touchpad is wrong because it controls the cursor, not biometrics. LCD inverter is wrong because it powers the display’s backlight. Exam tip: Know each laptop component's purpose and location."                                                                                 
      },
      {
        id: 2,
        question: 'A user needs to replace the memory in a laptop. Which type of RAM module is most likely required?',                                                                    
        options: [ 'DIMM', 'SODIMM', 'ROM', 'CompactFlash' ],
        correctAnswerIndex: 1,
        explanation: 'SODIMM is correct because laptops typically use Small Outline DIMMs for their smaller form factor. DIMM is wrong because standard desktops use full-sized DIMMs. ROM is wrong because it’s read-only memory used for firmware, not system RAM. CompactFlash is wrong because it’s a removable storage card, not system RAM. Exam tip: Be familiar with laptop-specific hardware terms like SODIMM.'                                                        
      },
      {
        id: 3,
        question: 'Which type of storage drive connection typically provides the highest throughput for an internal SSD?',                                                                
        options: [ 'SATA III', 'PCIe/NVMe', 'USB 3.1', 'eSATA' ],
        correctAnswerIndex: 1,
        explanation: "PCIe/NVMe is correct because it uses a high-speed PCI Express interface for maximum SSD performance. SATA III is wrong because it's slower (up to 6 Gbps). USB 3.1 is wrong because it’s primarily external and still slower than NVMe in practical internal setups. eSATA is wrong because it's used externally and is limited by SATA speeds. Exam tip: NVMe drives far exceed traditional SATA speeds."                                                 
      },
      {
        id: 4,
        question: 'A user has an older PC that displays a 3.3V power rail failure. Which component is most likely causing the problem?',                                                  
        options: [
          'Motherboard voltage regulator',
          'CPU fan',
          'RAM module',
          'Network card'
        ],
        correctAnswerIndex: 0,
        explanation: "Motherboard voltage regulator is correct because it regulates 3.3V for various motherboard components. CPU fan is wrong because a failing fan causes overheating, not a specific voltage rail issue. RAM module is wrong because bad RAM typically shows POST errors, not voltage rail failures. Network card is wrong because it usually doesn't directly cause a 3.3V rail failure. Exam tip: Power rail stability often depends on the motherboard’s voltage regulators."                                                                            
      },
      {
        id: 5,
        question: 'Which wireless standard operates only on the 5 GHz frequency and can provide speeds up to 1.3 Gbps (theoretical)?',                                                    
        options: [ '802.11n', '802.11g', '802.11ac', '802.11b' ],
        correctAnswerIndex: 2,
        explanation: '802.11ac is correct because it operates primarily at 5 GHz and can achieve speeds around 1.3 Gbps or more. 802.11n is wrong because it can use 2.4 GHz or 5 GHz and typically caps lower. 802.11g and 802.11b are older and much slower. Exam tip: Pay attention to frequency bands and maximum theoretical speeds when identifying 802.11 standards.'        
      },
      {
        id: 6,
        question: 'A technician wants to allow only secure, encrypted remote terminal access across TCP port 22. Which protocol should be allowed through the firewall?',                 
        options: [ 'Telnet', 'SSH', 'RDP', 'SMB' ],
        correctAnswerIndex: 1,
        explanation: 'SSH is correct because it provides encrypted terminal access over port 22. Telnet is wrong because it’s unencrypted and uses port 23. RDP is wrong because it uses port 3389 for remote desktop, not a text-based shell. SMB is wrong because it uses ports 445 (and sometimes 137-139), not 22. Exam tip: Remember key port numbers for common protocols.'   
      },
      {
        id: 7,
        question: 'Which of the following is NOT needed for a basic virtual machine setup on a desktop PC?',                                                                              
        options: [
          'Sufficient RAM',
          'Virtualization support in BIOS/UEFI',
          'GPU passthrough card',
          'Ample hard disk space'
        ],
        correctAnswerIndex: 2,
        explanation: 'GPU passthrough card is correct to exclude because basic virtualization doesn’t require specialized GPU passthrough. Sufficient RAM is wrong because memory is essential for hosting virtual machines. Virtualization support in BIOS/UEFI is wrong because hardware-assisted virtualization must be enabled. Ample hard disk space is wrong because a VM requires space for virtual disks. Exam tip: Basic virtualization primarily relies on CPU virtualization extensions, enough RAM, and disk capacity.'                                           
      },
      {
        id: 8,
        question: 'A user wants to install a RAID 1 array for data redundancy. Which configuration is correct?',                                                                          
        options: [
          'Striping with no redundancy',
          'Mirroring across two drives',
          'Striping with parity across three drives',
          'Multiple drives in a spanning volume'
        ],
        correctAnswerIndex: 1,
        explanation: 'Mirroring across two drives is correct because RAID 1 creates an exact copy on each drive. Striping with no redundancy is RAID 0, which doesn’t provide fault tolerance. Striping with parity is RAID 5 or 6, requiring at least three drives. Spanning is JBOD (Just a Bunch Of Disks), not a fault-tolerant RAID type. Exam tip: Know the fundamental RAID levels and their unique benefits/drawbacks.'                                                  
      },
      {
        id: 9,
        question: 'A technician is installing additional RAM in a dual-channel motherboard. Which configuration is recommended?',                                                         
        options: [
          'Populate slots in pairs of different sizes for maximum speed',
          'Install one module at a time for each channel',
          'Use matched pairs in the correct slot color coding',
          'Place all modules in adjacent slots, ignoring color'
        ],
        correctAnswerIndex: 2,
        explanation: 'Use matched pairs in the correct slot color coding is correct because dual-channel boards usually require identical RAM modules in specific paired slots. Different sizes or ignoring color-coded slots can reduce performance or prevent dual-channel operation. Installing one module at a time doesn’t enable dual-channel. Exam tip: Always check the motherboard manual for RAM placement and channel configurations.'                                
      },
      {
        id: 10,
        question: 'Which network tool should a technician use to identify the exact location of a cable break inside a wall?',                                                            
        options: [ 'Loopback plug', 'Toner probe', 'Crimper', 'Punchdown tool' ],
        correctAnswerIndex: 1,
        explanation: 'Toner probe is correct because it helps trace and locate cable runs behind walls. Loopback plug is wrong because it tests ports by looping signals back. Crimper is wrong because it’s for attaching connectors. Punchdown tool is wrong because it secures wires into a patch panel or keystone jack. Exam tip: Toner probe kits are essential for tracing cable paths and identifying breaks.'                                                           
      },
      {
        id: 11,
        question: 'A user complains their laptop battery is draining quickly and physically bulging. Which is the BEST immediate action?',                                                
        options: [
          'Perform a slow full discharge and recharge',
          'Keep using until battery fails completely',
          'Replace the battery and properly dispose of the old one',
          'Freeze the battery to reset its chemistry'
        ],
        correctAnswerIndex: 2,
        explanation: 'Replace the battery and properly dispose of it is correct because a bulging battery can be a safety hazard. Fully discharging is wrong because it won’t fix a physically damaged or bulging battery. Continuing to use is dangerous. Freezing is wrong and can damage the battery further. Exam tip: Swollen lithium-ion batteries require immediate replacement to avoid potential fire hazards.'                                                         
      },
      {
        id: 12,
        question: 'Which troubleshooting step comes FIRST according to best practice methodology when a user reports a PC issue?',                                                        
        options: [
          'Test the theory to determine the cause',
          'Establish a theory of probable cause',
          'Identify the problem by gathering information',
          'Document all findings and close the ticket'
        ],
        correctAnswerIndex: 2,
        explanation: 'Identify the problem by gathering information is correct because step 1 is always to collect details. Testing the theory is step 3, establishing a theory is step 2, and documentation is step 6. Exam tip: Memorize the CompTIA six-step troubleshooting methodology in the correct order.'                                                                  
      },
      {
        id: 13,
        question: 'A technician notices the CPU is running excessively hot. Which is the MOST likely cause?',                                                                             
        options: [
          'Faulty BIOS battery',
          'Insufficient thermal paste on the CPU',
          'Incorrect RAM timing',
          'Malfunctioning network adapter'
        ],
        correctAnswerIndex: 1,
        explanation: 'Insufficient thermal paste is correct because poor heat conduction can cause CPU overheating. A faulty BIOS battery is wrong because it typically just loses date/time. Incorrect RAM timing is wrong because it can cause instability, not specifically high CPU temps. A malfunctioning NIC is wrong because it doesn’t directly affect CPU heat. Exam tip: Always check heatsinks and thermal compound when diagnosing heat-related CPU issues.'        
      },
      {
        id: 14,
        question: 'A client wants to secure a new wireless network with encryption over a 5 GHz channel. Which standard is BEST to use?',                                                 
        options: [ 'WEP', 'WPA', 'WPA2/WPA3', 'Open (no password)' ],
        correctAnswerIndex: 2,
        explanation: "WPA2/WPA3 is correct because they provide modern, robust encryption. WEP is wrong because it's obsolete and easily cracked. WPA is better than WEP but still weaker than WPA2/WPA3. An open network provides no encryption. Exam tip: Always use the strongest encryption supported by both access point and client devices."                                 
      },
      {
        id: 15,
        question: 'A user cannot access a website by its domain name, but can reach it by IP address. Which service is MOST likely malfunctioning?',                                      
        options: [ 'DHCP', 'LDAP', 'DNS', 'SMTP' ],
        correctAnswerIndex: 2,
        explanation: 'DNS is correct because domain name resolution is failing. DHCP is wrong because it assigns IP addresses but isn’t responsible for hostname resolution once an IP is obtained. LDAP is wrong because it’s for directory services. SMTP is wrong because it’s for sending email. Exam tip: DNS issues typically manifest as domain name failures but still allow direct IP connections.'                                                                     
      },
      {
        id: 16,
        question: 'Which type of display technology in laptops is known for more accurate colors but slightly slower response times?',                                                    
        options: [
          'TN (Twisted Nematic)',
          'IPS (In-Plane Switching)',
          'VA (Vertical Alignment)',
          'OLED'
        ],
        correctAnswerIndex: 1,
        explanation: "IPS is correct because it provides better color accuracy and viewing angles despite slower response. TN is wrong because it has faster response but worse color accuracy. VA is wrong because it sits between TN and IPS in contrast and angles. OLED is wrong because it has excellent contrast but isn't as commonly used in mainstream laptops. Exam tip: Know the pros/cons of each display panel type."                                               
      },
      {
        id: 17,
        question: 'A technician wants to configure a subnet for an office with 50 devices, ensuring IP addresses are automatically assigned. Which server role is needed?',               
        options: [ 'DNS server', 'DHCP server', 'Mail server', 'Proxy server' ],
        correctAnswerIndex: 1,
        explanation: "DHCP server is correct because it automatically assigns IP addresses and related network information. DNS server is wrong because it resolves domain names to IPs, not assign addresses. Mail server is wrong because it's for email. Proxy server is wrong because it handles client requests through an intermediary, not IP assignments. Exam tip: DHCP is fundamental for dynamic IP assignment in most networks."                                     
      },
      {
        id: 18,
        question: 'Which cable type supports data transmission over the longest distances at the highest speeds?',                                                                        
        options: [ 'Cat 6 UTP', 'Fiber optic', 'Cat 6a STP', 'Coaxial RG-59' ],
        correctAnswerIndex: 1,
        explanation: 'Fiber optic is correct because it transmits data as light over very long distances with high bandwidth. Cat 6 UTP is wrong because it’s limited to about 100 meters. Cat 6a STP can reduce EMI but still is around 100 meters. Coaxial RG-59 is an older standard mainly for short-range video signals. Exam tip: Fiber optic cables excel in backbone or high-distance scenarios.'                                                                        
      },
      {
        id: 19,
        question: 'Which of the following is MOST crucial when replacing a laptop keyboard?',
        options: [
          'Ensuring the CPU architecture matches',
          'Using the correct driver for the GPU',
          'Matching the exact keyboard ribbon cable connector',
          'Formatting the hard drive for a new OS install'
        ],
        correctAnswerIndex: 2,
        explanation: 'Matching the exact keyboard ribbon cable connector is correct because you must use the correct physical and electrical interface. CPU architecture is irrelevant for a keyboard swap. GPU drivers do not affect a keyboard replacement. Formatting the hard drive is unrelated to physical keyboard changes. Exam tip: Always reference manufacturer guides for laptop-specific components.'                                                               
      },
      {
        id: 20,
        question: 'Which of these addresses is an example of an APIPA (Automatic Private IP Addressing) address?',                                                                        
        options: [
          '169.254.10.50',
          '192.168.0.100',
          '10.0.0.50',
          '172.16.100.1'
        ],
        correctAnswerIndex: 0,
        explanation: '169.254.10.50 is correct because APIPA automatically assigns addresses in the 169.254.x.x range. 192.168.0.100, 10.0.0.50, and 172.16.100.1 are private addresses but not APIPA. Exam tip: If you see a 169.254.x.x address, it usually indicates DHCP failure or no DHCP server.'                                                                            
      },
      {
        id: 21,
        question: 'Which protocol is commonly used for secure file transfers and operates over port 22?',                                                                                 
        options: [ 'FTP', 'SFTP', 'SNMP', 'Telnet' ],
        correctAnswerIndex: 1,
        explanation: 'SFTP is correct because it’s FTP over SSH, using port 22 securely. FTP (port 21) is unencrypted by default. SNMP (ports 161/162) is for network management. Telnet (port 23) is unencrypted remote terminal. Exam tip: Remember which secure protocols use SSH, such as SFTP and SCP.'                                                                        
      },
      {
        id: 22,
        question: 'A user wants to upgrade their 5400 RPM laptop HDD to improve speed without changing form factor. Which is the BEST upgrade option?',                                   
        options: [
          'Replace with a 7200 RPM HDD',
          'Replace with a 2.5" SATA SSD',
          'Switch to a desktop-size 3.5" HDD',
          'Add more RAM instead'
        ],
        correctAnswerIndex: 1,
        explanation: 'A 2.5" SATA SSD is correct because it drastically improves performance while fitting the same laptop drive bay. A 7200 RPM HDD is only a minor improvement. A 3.5" HDD won’t physically fit a laptop. Adding RAM helps multitasking but won’t speed up disk operations as much as an SSD. Exam tip: SSDs remain the top choice for significant read/write performance boosts.'                                                                             
      },
      {
        id: 23,
        question: 'Which troubleshooting step is performed AFTER establishing a theory of probable cause?',                                                                               
        options: [
          'Identify the problem',
          'Test the theory to confirm the cause',
          'Verify full system functionality',
          'Document the findings'
        ],
        correctAnswerIndex: 1,
        explanation: 'Test the theory to confirm the cause is correct because it’s step 3 in the CompTIA methodology. Identifying the problem is step 1, verifying functionality is step 5, and documentation is step 6. Exam tip: Know the 6-step approach by heart, including the exact order.'                                                                                   
      },
      {
        id: 24,
        question: 'Which setting in BIOS/UEFI must often be enabled to run virtual machines like VMware or Hyper-V effectively on modern CPUs?',                                          
        options: [
          'Secure Boot',
          'Boot from USB',
          'Virtualization support (VT-x/AMD-V)',
          'CPU fan control'
        ],
        correctAnswerIndex: 2,
        explanation: 'Virtualization support (VT-x on Intel or AMD-V on AMD) is correct because hardware virtualization extensions are required for best VM performance. Secure Boot, boot from USB, and CPU fan control do not directly affect the ability to run VMs. Exam tip: Always verify virtualization extensions are enabled when troubleshooting VM performance or installation issues.'                                                                               
      },
      {
        id: 25,
        question: 'When installing two new memory modules in a dual-channel motherboard, which practice ensures optimal performance?',                                                    
        options: [
          'Use one high-capacity module and one low-capacity module in adjacent slots',
          'Mixing different speeds of RAM in the first two slots',
          'Installing matching RAM modules into the color-matched slots',
          'Leaving one slot empty to reduce power usage'
        ],
        correctAnswerIndex: 2,
        explanation: 'Installing matching modules in color-matched slots is correct for dual-channel operation. Using mismatched modules or speeds can prevent dual-channel. Leaving a slot empty or mixing capacities is not optimal. Exam tip: Dual-channel memory architecture requires matched pairs placed as the motherboard manual indicates.'                               
      },
      {
        id: 26,
        question: 'Which cable type is required to connect a cable modem to an ISP’s cable network?',                                                                                     
        options: [
          'RG-59 or RG-6 coaxial cable',
          'Cat 6 Ethernet cable',
          'Fiber optic single-mode',
          'USB Type-C cable'
        ],
        correctAnswerIndex: 0,
        explanation: 'RG-59 or RG-6 coaxial cable is correct because cable modems use coax for the “last mile” cable network. Cat 6 is for LAN connections. Fiber single-mode is used by some ISPs but not typically for cable modems. USB-C is unrelated to coax distribution. Exam tip: Cable modems rely on coax lines carrying DOCSIS signals from the ISP.'                    
      },
      {
        id: 27,
        question: 'A user reports very slow print jobs and frequent paper jams on a laser printer. Which should the technician check FIRST?',                                             
        options: [
          'Ton of queued print jobs on the print server',
          'Firmware updates for the network interface card',
          'Incorrect paper type or worn-out pickup rollers',
          'Low system RAM on the user’s workstation'
        ],
        correctAnswerIndex: 2,
        explanation: 'Incorrect paper type or worn-out pickup rollers is correct because these directly cause jams and slow feeding. Too many queued jobs is possible but wouldn’t cause jams. Firmware issues might be relevant but less likely than physical feed problems. Low RAM on the user’s PC wouldn’t cause frequent paper jams. Exam tip: Always inspect physical components like rollers and correct paper settings first.'                                          
      },
      {
        id: 28,
        question: 'Which protocol is used to monitor and manage network devices, often sending data on ports 161/162?',                                                                   
        options: [ 'SMTP', 'SNMP', 'NTP', 'DNS' ],
        correctAnswerIndex: 1,
        explanation: 'SNMP is correct because it’s used for Simple Network Management Protocol on ports 161/162. SMTP is email sending (port 25). NTP is Network Time Protocol (port 123). DNS is domain name resolution (port 53). Exam tip: Remember key port numbers, especially for SNMP’s two ports.'                                                                          
      },
      {
        id: 29,
        question: 'A technician replacing a failing mechanical hard drive in a desktop wants the best overall read/write speed and can use a PCI Express slot. Which device is BEST?',    
        options: [
          '2.5-inch SSD with SATA interface',
          'M.2 NVMe SSD',
          '3.5-inch HDD at 7200 RPM',
          'USB 3.0 external drive'
        ],
        correctAnswerIndex: 1,
        explanation: 'M.2 NVMe SSD is correct because it uses PCIe lanes for significantly higher read/write speeds than SATA. A 2.5-inch SATA SSD is fast but still limited to ~6 Gbps. A 7200 RPM HDD is slower. A USB 3.0 external drive is not internal and slower than PCIe. Exam tip: NVMe (Non-Volatile Memory Express) often far outperforms SATA-based SSDs.'              
      },
      {
        id: 30,
        question: 'Which type of virtualization model provides a complete environment for the OS, including hardware emulation of CPU, memory, and storage?',                             
        options: [
          'Application virtualization',
          'Containerization',
          'Bare-metal hypervisor (Type 1)',
          'Hosted hypervisor (Type 2)'
        ],
        correctAnswerIndex: 3,
        explanation: 'A hosted hypervisor (Type 2) is correct because it emulates all hardware on top of an existing OS (like VirtualBox or VMware Workstation). Application virtualization is different—it only virtualizes the app. Containerization shares the host OS kernel. A bare-metal hypervisor (Type 1) doesn’t run on a full host OS; it runs directly on hardware. Exam tip: Distinguish between Type 1 (bare metal) and Type 2 (hosted) hypervisors in virtualization scenarios.'                                                                               
      },
      {
        id: 31,
        question: 'Which device converts alternating current (AC) from the wall into different DC voltages for a desktop PC?',                                                            
        options: [
          'Power supply unit (PSU)',
          'Uninterruptible power supply (UPS)',
          'Voltage regulator on the motherboard',
          'Transformer in the LCD inverter'
        ],
        correctAnswerIndex: 0,
        explanation: 'Power supply unit (PSU) is correct because it takes AC from the mains and outputs multiple DC voltages (3.3V, 5V, 12V). A UPS is wrong because it provides backup power but does not directly convert AC to DC for the PC. The motherboard regulator fine-tunes voltages but doesn’t create them from AC. An LCD inverter is related to laptop displays, not desktop power. Exam tip: Remember that desktop PSUs handle AC to DC conversion.'              
      },
      {
        id: 32,
        question: 'A user complains their newly installed printer prints garbled text. Which is the MOST likely cause?',                                                                  
        options: [
          'Incorrect or corrupted printer driver',
          'Low toner level',
          'Wrong type of paper in the tray',
          'Overheating fuser assembly'
        ],
        correctAnswerIndex: 0,
        explanation: 'Incorrect or corrupted printer driver is correct because mismatched drivers often produce nonsensical characters. Low toner might cause faint prints, not random garbled text. Using the wrong paper can cause jams, not garbled text. Overheating the fuser leads to smudged or distorted prints but not random characters. Exam tip: Always verify correct drivers for the OS and printer model.'                                                        
      },
      {
        id: 33,
        question: 'Which wireless security protocol was replaced by WPA due to its significant vulnerabilities?',                                                                         
        options: [ 'WPA2', 'WEP', 'WPA3', 'EAP' ],
        correctAnswerIndex: 1,
        explanation: 'WEP is correct because it was deprecated and replaced by WPA/WPA2 due to weak encryption. WPA2 and WPA3 are newer, more secure standards. EAP is an authentication framework, not a standalone wireless security protocol. Exam tip: WEP is obsolete and easily cracked—always use WPA2 or WPA3 if possible.'                                                 
      },
      {
        id: 34,
        question: 'Which device commonly uses a punchdown tool for cable terminations in a structured cabling environment?',                                                              
        options: [
          'Cable modem',
          'Patch panel',
          'Uninterruptible power supply',
          'Firewall'
        ],
        correctAnswerIndex: 1,
        explanation: 'Patch panel is correct because punchdown tools are used to secure twisted-pair cable into patch panels or keystones. Cable modems typically use coax or RJ45 connectors but not punchdown blocks. A UPS and a firewall don’t involve physical punchdown terminations. Exam tip: Know how punchdown tools are used to install UTP cables into patch panels or wall jacks.'                                                                                  
      },
      {
        id: 35,
        question: 'A technician wants to upgrade a system to handle virtualization better. Which hardware component is MOST critical?',                                                   
        options: [
          'A GPU with more VRAM',
          'Faster optical drive',
          'RAM capacity',
          'External USB 3.0 ports'
        ],
        correctAnswerIndex: 2,
        explanation: 'RAM capacity is correct because running multiple VMs requires ample memory. A more powerful GPU helps 3D graphics but not basic VM memory needs. An optical drive is rarely used in virtualization. External USB 3.0 ports are convenient but not essential for VM performance. Exam tip: Virtual machines share system RAM, so having plenty of memory is key.'                                                                                           
      },
      {
        id: 36,
        question: 'In a laser printing process, which step involves applying a negative charge to the drum so it can attract toner?',                                                     
        options: [ 'Exposing', 'Charging', 'Fusing', 'Transferring' ],
        correctAnswerIndex: 1,
        explanation: 'Charging is correct because it places a uniform negative charge on the drum before laser exposure. Exposing writes the image by discharging certain parts. Fusing uses heat and pressure to bond toner to paper. Transferring moves toner from drum to paper. Exam tip: Memorize the laser printing steps: processing, charging, exposing, developing, transferring, fusing, cleaning.'                                                                    
      },
      {
        id: 37,
        question: 'A technician notices a PC’s BIOS time resets to default after every power cycle. Which component is MOST likely failing?',                                             
        options: [
          'CMOS battery',
          'CPU voltage regulator',
          'Primary SSD',
          'Northbridge chipset'
        ],
        correctAnswerIndex: 0,
        explanation: 'CMOS battery is correct because it maintains the real-time clock (RTC) and BIOS settings when power is off. CPU voltage regulator issues cause instability, not time resets. A failing SSD might cause boot errors, not resetting time. Northbridge chip affects CPU to RAM communications, not clock settings. Exam tip: A dying CMOS battery typically manifests as repeated date/time resets.'                                                          
      },
      {
        id: 38,
        question: 'Which type of network typically extends a small geographic area like a home or office?',                                                                               
        options: [
          'PAN (Personal Area Network)',
          'WAN (Wide Area Network)',
          'SAN (Storage Area Network)',
          'LAN (Local Area Network)'
        ],
        correctAnswerIndex: 3,
        explanation: 'LAN (Local Area Network) is correct because it covers a limited geographic area like a building or campus. PAN is more personal devices around an individual. WAN spans large geographical distances. SAN is for block-level data storage networks. Exam tip: LANs are localized networks, while WANs are broader (like connecting distant sites).'           
      },
      {
        id: 39,
        question: 'Which BIOS/UEFI feature ensures that only trusted operating systems can boot by requiring properly signed software?',                                                  
        options: [
          'Virtualization support',
          'Secure Boot',
          'Fast Boot',
          'Boot priority'
        ],
        correctAnswerIndex: 1,
        explanation: 'Secure Boot is correct because it checks digital signatures to verify the OS bootloader’s integrity. Virtualization support is unrelated to OS signature checks. Fast Boot bypasses some POST checks, not security. Boot priority sets device order but doesn’t verify software signatures. Exam tip: Secure Boot helps prevent rootkits by validating the OS bootloader’s signature.'                                                                     
      },
      {
        id: 40,
        question: 'Which connector type is commonly used for fiber optic connections in enterprise backbones and uses a push/pull mechanism?',                                            
        options: [
          'ST (Straight Tip)',
          'LC (Lucent Connector)',
          'SC (Subscriber Connector)',
          'RJ45'
        ],
        correctAnswerIndex: 2,
        explanation: 'SC (Subscriber Connector) is correct because it employs a snap-in push/pull design for fiber. ST is bayonet-style twist. LC is smaller but also uses a latch, often called the “little connector.” RJ45 is for twisted-pair copper, not fiber. Exam tip: SC is sometimes nicknamed “square connector” or “standard connector.”'                               
      },
      {
        id: 41,
        question: 'Which of these issues is MOST likely if a CPU’s heat sink is clogged with dust?',                                                                                      
        options: [
          'Blue screen errors and random shutdowns',
          'Inability to install updated drivers',
          'Hard drive read/write errors',
          'Inverted display output'
        ],
        correctAnswerIndex: 0,
        explanation: 'Blue screen errors and random shutdowns are correct because overheating causes system instability. Failing to install drivers is unrelated to dust clogging. Hard drive errors are separate from CPU heat. Inverted display is typically a software or GPU setting, not heat-related. Exam tip: Overheating often manifests as system crashes, shutdowns, or BSOD.'                                                                                        
      },
      {
        id: 42,
        question: 'Which RAID level uses striping across at least three drives and distributes parity for fault tolerance?',                                                              
        options: [ 'RAID 0', 'RAID 1', 'RAID 5', 'RAID 10' ],
        correctAnswerIndex: 2,
        explanation: 'RAID 5 is correct because it stripes data and parity across three or more drives. RAID 0 is striping only (no parity). RAID 1 is mirroring. RAID 10 is nested mirroring and striping requiring at least four drives. Exam tip: RAID 5 is popular for balancing performance and fault tolerance with minimal overhead.'                                        
      },
      {
        id: 43,
        question: 'A user needs to configure a mail client that retrieves messages from the server while leaving them there by default. Which mail protocol should be used?',             
        options: [ 'POP3', 'IMAP', 'SMTP', 'SNMP' ],
        correctAnswerIndex: 1,
        explanation: 'IMAP is correct because it synchronizes mail on the server, typically leaving messages there. POP3 often downloads and removes messages by default. SMTP is for sending, not retrieving. SNMP is for network management. Exam tip: IMAP is best for accessing email across multiple devices while messages remain on the server.'                             
      },
      {
        id: 44,
        question: 'A newly built PC powers on but fails to detect any SATA drives. Which of the following is the MOST likely cause?',                                                     
        options: [
          'GPU driver not installed',
          'Insufficient PSU wattage',
          'Incorrect SATA port configuration in BIOS/UEFI',
          'Low disk partition size'
        ],
        correctAnswerIndex: 2,
        explanation: 'Incorrect SATA port configuration in BIOS/UEFI is correct because drives can remain undetected if ports are disabled or in a wrong mode. GPU drivers don’t affect drive detection. Insufficient PSU wattage might cause random shutdowns but not a specific drive detection failure. Low partition size is irrelevant if the drive is unseen by BIOS. Exam tip: Always check BIOS settings or SATA mode (AHCI/IDE) for newly attached drives.'             
      },
      {
        id: 45,
        question: 'Which step in a laser printer’s imaging process uses a high-voltage primary corona wire to prepare the drum surface?',                                                 
        options: [ 'Developing', 'Charging', 'Exposing', 'Transferring' ],
        correctAnswerIndex: 1,
        explanation: 'Charging is correct because it negatively charges the drum surface via the primary corona wire. Developing adds toner to those discharged areas. Exposing uses the laser to remove charge where toner will adhere. Transferring moves toner from drum to paper. Exam tip: Memorize the laser printing steps thoroughly for troubleshooting printers.'         
      },
      {
        id: 46,
        question: 'A technician needs to repair a laptop that shuts off randomly. Which component is MOST likely causing unexpected power loss due to poor battery contact?',             
        options: [
          'Damaged AC power adapter',
          'Loose battery connector or latch',
          'Failing CPU fan',
          'Incorrect display resolution'
        ],
        correctAnswerIndex: 1,
        explanation: "Loose battery connector or latch is correct because an intermittent connection can cause sudden power loss. A damaged AC adapter might fail to charge but wouldn't sporadically cut power if the battery is good. A failing CPU fan leads to overheating, not instant shutdown from lack of power. Display resolution issues affect video but not power. Exam tip: Check physical battery seating for random shutdowns in laptops."                        
      },
      {
        id: 47,
        question: 'Which TCP port is used by RDP (Remote Desktop Protocol) for remote administration of Windows systems?',                                                                
        options: [ '22', '23', '3389', '445' ],
        correctAnswerIndex: 2,
        explanation: '3389 is correct because RDP runs on TCP port 3389. Port 22 is SSH, 23 is Telnet, and 445 is SMB over TCP. Exam tip: Memorize the standard ports for common services like RDP, SSH, Telnet, and SMB.'                                                             
      },
      {
        id: 48,
        question: 'Which step should be performed FIRST when installing a multifunction printer on the network?',                                                                         
        options: [
          'Enable duplex printing',
          'Update the fuser assembly firmware',
          'Install the latest printer driver',
          'Assign an IP address or use DHCP'
        ],
        correctAnswerIndex: 3,
        explanation: 'Assign an IP address or use DHCP is correct because the device needs a valid network configuration before driver installation or using features like duplex. Installing the latest driver is done after the device is discoverable on the network. Duplex printing and fuser firmware are configuration items after basic setup. Exam tip: Always configure network settings so the printer is reachable before driver or feature setups.'                 
      },
      {
        id: 49,
        question: 'Which server role resolves hostnames to IP addresses across the network?',
        options: [ 'DHCP', 'DNS', 'AAA', 'Mail server' ],
        correctAnswerIndex: 1,
        explanation: 'DNS is correct because it performs domain name resolution. DHCP assigns IPs. AAA handles authentication, authorization, and accounting. A mail server handles email. Exam tip: Remember DNS stands for Domain Name System, crucial for translating domain names to IPs.'                                                                                      
      },
      {
        id: 50,
        question: 'A workstation randomly fails to power on. Which measurement tool is BEST for verifying stable and correct voltages from the PSU?',                                     
        options: [
          'Tone and probe kit',
          'Multimeter',
          'Loopback plug',
          'ESD wrist strap'
        ],
        correctAnswerIndex: 1,
        explanation: 'Multimeter is correct because it tests power supply outputs (e.g., 12V, 5V). A tone and probe kit is for cable tracing. A loopback plug tests network or serial ports. An ESD strap is for grounding, not voltage testing. Exam tip: Use a multimeter or dedicated PSU tester to confirm proper voltages.'                                                    
      },
      {
        id: 51,
        question: 'Which WiFi standard introduced MU-MIMO (Multi-User, Multiple Input/Multiple Output) for better performance with multiple devices?',                                    
        options: [
          '802.11n',
          '802.11ac (WiFi 5)',
          '802.11ax (WiFi 6)',
          '802.11g'
        ],
        correctAnswerIndex: 1,
        explanation: '802.11ac introduced MU-MIMO for simultaneous multi-user data streams. 802.11n had MIMO but not multi-user. 802.11ax (WiFi 6) further improves MU-MIMO but it was first standardized in 11ac. 802.11g is older and lacks MIMO entirely. Exam tip: MU-MIMO significantly improves throughput in busy wireless networks.'                                        
      },
      {
        id: 52,
        question: 'Which file system is required on Windows to enable file-level security and encryption features like EFS?',                                                             
        options: [ 'FAT32', 'exFAT', 'NTFS', 'HFS+' ],
        correctAnswerIndex: 2,
        explanation: 'NTFS is correct because it supports advanced file permissions, encryption (EFS), and large file sizes. FAT32 and exFAT do not offer EFS. HFS+ is a macOS file system. Exam tip: Windows-specific features like EFS require NTFS.'                                
      },
      {
        id: 53,
        question: 'Which cable type is MOST appropriate for a gigabit PoE-enabled switch powering multiple IP cameras over long distances up to 100 meters?',                             
        options: [
          'Cat 3 UTP',
          'Cat 5e or Cat 6 UTP',
          'Coax RG-59',
          'Fiber single-mode'
        ],
        correctAnswerIndex: 1,
        explanation: 'Cat 5e or Cat 6 UTP is correct for gigabit + PoE up to ~100 meters. Cat 3 is outdated (10 Mbps). RG-59 is coax for analog video, not standard Ethernet with PoE. Fiber single-mode is an option for much greater distances, but typical PoE setups rely on twisted-pair copper. Exam tip: Cat 5e or higher is required for reliable gigabit plus PoE.'        
      },
      {
        id: 54,
        question: 'Which Windows utility can be used to manage partitions and volumes, format drives, and assign drive letters?',                                                         
        options: [
          'Device Manager',
          'Disk Management',
          'Task Manager',
          'Services.msc'
        ],
        correctAnswerIndex: 1,
        explanation: 'Disk Management is correct because it manages drive partitions, formats, and letters. Device Manager handles device drivers. Task Manager monitors processes and performance. Services.msc is for managing Windows services. Exam tip: Disk Management is your go-to for disk partition tasks in Windows.'                                                    
      },
      {
        id: 55,
        question: 'Which of the following interfaces is known for being hot-swappable and commonly used for external storage with a maximum length of two meters?',                       
        options: [
          'eSATA',
          'Thunderbolt 3',
          'IDE ribbon cable',
          'Parallel port'
        ],
        correctAnswerIndex: 0,
        explanation: 'eSATA is correct for external Serial ATA connections that allow hot-swapping. Thunderbolt can be hot-swappable too, but not specifically known as eSATA. IDE ribbon is internal and not hot-swappable. Parallel port is old and not typical for modern external storage. Exam tip: eSATA extends SATA to external enclosures with a typical max cable length around two meters.'                                                                           
      },
      {
        id: 56,
        question: 'Which component is responsible for handling the initial system startup instructions and ensuring essential hardware is properly recognized?',                          
        options: [
          'Operating System Kernel',
          'UEFI/BIOS firmware',
          'Southbridge chipset',
          'Device Manager'
        ],
        correctAnswerIndex: 1,
        explanation: 'UEFI/BIOS firmware is correct because it performs POST, configures hardware, and hands off to the OS bootloader. OS Kernel is loaded later. The Southbridge chipset handles I/O but not the entire boot process. Device Manager is a Windows utility, not a firmware component. Exam tip: Distinguish the role of UEFI/BIOS in hardware initialization from the OS kernel’s role after boot.'                                                              
      },
      {
        id: 57,
        question: 'A user’s tablet supports only 2.4 GHz WiFi and experiences heavy interference. Which channel would BEST mitigate overlap in the U.S. market?',                         
        options: [ 'Channel 1', 'Channel 3', 'Channel 6', 'Channel 14' ],
        correctAnswerIndex: 2,
        explanation: 'Channel 6 is correct because in North America, non-overlapping 2.4 GHz channels are typically 1, 6, and 11. Channel 3 overlaps with 1 and 6. Channel 14 is not allowed in the U.S. Exam tip: Channels 1, 6, and 11 are the primary non-overlapping channels in 2.4 GHz for the U.S.'                                                                          
      },
      {
        id: 58,
        question: 'A user wants to configure a RAID setup that provides both disk mirroring and disk striping across four drives. Which RAID level is required?',                         
        options: [ 'RAID 5', 'RAID 0', 'RAID 10', 'RAID 1' ],
        correctAnswerIndex: 2,
        explanation: 'RAID 10 is correct (sometimes called RAID 1+0) because it nests mirrored pairs striped together, requiring at least four drives. RAID 5 is striping with parity, RAID 0 is striping only, and RAID 1 is mirroring only. Exam tip: RAID 10 blends performance (striping) and redundancy (mirroring) but needs at least four disks.'                            
      },
      {
        id: 59,
        question: 'Which scenario is MOST likely when a user sees an IP address of 169.254.x.x on their Windows machine?',                                                                
        options: [
          'The DNS server is offline',
          'DHCP server not reachable, APIPA assigned',
          'The workstation is using a static IP',
          'Malware has changed the IP settings'
        ],
        correctAnswerIndex: 1,
        explanation: 'DHCP server not reachable, APIPA assigned is correct because Windows uses Automatic Private IP Addressing (169.254.x.x) if DHCP fails. DNS server issues don’t cause 169.254 addresses. A static IP wouldn’t be 169.254 automatically. While malware can manipulate settings, 169.254 points more directly to missing DHCP. Exam tip: 169.254.x.x indicates APIPA mode, usually from DHCP server failures.'                                                
      },
      {
        id: 60,
        question: 'Which expansion slot is commonly used for high-performance graphics cards in modern desktops?',                                                                        
        options: [ 'PCI', 'PCIe x16', 'AGP', 'Mini PCI Express' ],
        correctAnswerIndex: 1,
        explanation: 'PCIe x16 is correct because it provides the necessary bandwidth for modern GPUs. Legacy PCI and AGP can’t handle today’s graphics demands. Mini PCI Express is mainly for laptops or small form factor devices. Exam tip: Graphics cards generally require a full-size PCIe x16 slot for best performance.'                                                   
      },
      {
        id: 61,
        question: 'A technician must configure a new DSL modem that connects via an RJ11 interface. Which connection type is MOST likely used by the ISP?',                               
        options: [
          'Satellite broadband',
          'Fiber to the premises',
          'POTS/telephone line for DSL',
          'Cable TV coax'
        ],
        correctAnswerIndex: 2,
        explanation: 'POTS/telephone line for DSL is correct because RJ11 is standard for telephone-based DSL. Satellite uses a dish and coax, fiber uses optical cables, and cable broadband uses coax (not RJ11). Exam tip: DSL typically runs over twisted-pair phone lines, connecting via RJ11.'                                                                               
      },
      {
        id: 62,
        question: 'A user notices their wireless mouse lags intermittently. Which is the MOST likely cause?',                                                                             
        options: [
          'Excessive CPU usage',
          'Insufficient GPU power',
          'Weak Bluetooth or USB receiver signal',
          'Outdated NIC firmware'
        ],
        correctAnswerIndex: 2,
        explanation: 'A weak Bluetooth or USB receiver signal is correct because a poor wireless link commonly causes input lag. High CPU usage rarely manifests as mouse lag alone. GPU power impacts graphics, not mouse input. NIC firmware is unrelated to wireless mouse connectivity. Exam tip: Keep wireless receivers clear of interference for smoother input device performance.'                                                                                      
      },
      {
        id: 63,
        question: 'Which Windows feature allows a user to roll back to a previous state without affecting personal files, typically used for quick recovery?',                            
        options: [
          'Windows Backup and Restore',
          'System Restore',
          'Safe Mode',
          'Disk Cleanup'
        ],
        correctAnswerIndex: 1,
        explanation: 'System Restore is correct because it reverts system files and registry to an earlier snapshot. Backup and Restore can restore entire partitions or personal files. Safe Mode helps troubleshooting but doesn’t revert changes. Disk Cleanup removes unnecessary files, not revert states. Exam tip: System Restore primarily addresses system-level changes and leaves user data intact.'                                                                  
      },
      {
        id: 64,
        question: 'A user’s inkjet printer is printing streaks and missing colors. Which action should be performed FIRST?',                                                              
        options: [
          'Replace the fuser assembly',
          'Run the printhead cleaning cycle',
          'Replace the entire printer',
          'Check for an incorrect paper orientation'
        ],
        correctAnswerIndex: 1,
        explanation: 'Running the printhead cleaning cycle is correct for addressing clogged nozzles and streaks. Fuser assemblies apply only to laser printers, not inkjet. Replacing the entire printer is too drastic. Paper orientation errors usually cause alignment or jam issues, not streaks. Exam tip: Use the built-in cleaning function first before replacing ink cartridges or hardware parts on an inkjet printer.'                                               
      },
      {
        id: 65,
        question: 'Which virtualization type uses a Type 1 hypervisor that runs directly on the system hardware without a host OS?',                                                      
        options: [
          'Hosted virtualization',
          'Container-based virtualization',
          'Bare-metal hypervisor',
          'Application sandboxing'
        ],
        correctAnswerIndex: 2,
        explanation: 'Bare-metal hypervisor is correct because it installs directly on hardware (e.g., VMware ESXi, Microsoft Hyper-V Server). Hosted virtualization (Type 2) requires a host OS. Containers and application sandboxing share the host OS kernel. Exam tip: Type 1 hypervisors have minimal overhead and best performance for enterprise servers.'                  
      },
      {
        id: 66,
        question: 'Which hardware device allows multiple internal or external drives to connect using a single interface card, often found in servers to manage RAID?',                   
        options: [
          'Sound card',
          'RAID controller',
          'KVM switch',
          'GPU expansion card'
        ],
        correctAnswerIndex: 1,
        explanation: 'A RAID controller is correct because it orchestrates multiple drives and handles RAID operations. A sound card manages audio input/output. A KVM switch connects multiple computers to a single keyboard, video, and mouse. A GPU expansion card handles graphics rendering. Exam tip: Hardware RAID controllers typically yield better performance and reliability than software-based RAID.'                                                             
      },
      {
        id: 67,
        question: 'Which IP addressing method involves manually entering all network details, such as IP, subnet mask, gateway, and DNS server?',                                         
        options: [
          'APIPA',
          'DHCP',
          'Static assignment',
          'IPv6 autoconfiguration'
        ],
        correctAnswerIndex: 2,
        explanation: 'Static assignment is correct because the user enters IP configuration manually. APIPA auto-assigns 169.254.x.x addresses when DHCP fails. DHCP dynamically provides address details. IPv6 autoconfiguration (SLAAC) automatically generates an address. Exam tip: Static IP configurations can reduce dependency on DHCP but require manual updates for each device.'                                                                                      
      },
      {
        id: 68,
        question: 'A user complains their cloud-hosted VM restarts randomly with resource usage spikes. Which service model likely requires them to manage the OS and application themselves?',                                                                                        
        options: [ 'SaaS', 'IaaS', 'PaaS', 'DaaS' ],
        correctAnswerIndex: 1,
        explanation: 'IaaS (Infrastructure as a Service) is correct because the tenant manages the OS, apps, and configuration on a virtual machine. SaaS (Software as a Service) is fully managed by the provider. PaaS provides a managed platform for developers. DaaS is Desktop as a Service. Exam tip: IaaS gives you the most control but also the most maintenance responsibilities.'                                                                                    
      },
      {
        id: 69,
        question: 'A user wants to implement VLANs for different departments on a managed switch. Which configuration is MOST likely needed?',                                            
        options: [
          'Enable 802.11ac on each port',
          'Use trunk ports with 802.1Q tagging',
          'Assign static IP addresses to each port',
          'Enable WPA2 encryption on the switch'
        ],
        correctAnswerIndex: 1,
        explanation: 'Use trunk ports with 802.1Q tagging is correct because VLAN trunking requires 802.1Q to differentiate traffic. 802.11ac is a wireless standard, not relevant here. Static IP assignment does not isolate VLAN traffic by itself. WPA2 is a wireless security method, not for wired VLAN config. Exam tip: VLAN trunking uses 802.1Q tags to carry multiple VLANs over one physical link.'                                                                  
      },
      {
        id: 70,
        question: 'Which motherboard form factor is commonly used in small or home theater PCs and measures 6.7 × 6.7 inches?',                                                           
        options: [ 'microATX', 'Mini-ITX', 'ATX', 'NLX' ],
        correctAnswerIndex: 1,
        explanation: 'Mini-ITX is correct because it’s a 6.7×6.7 inch board popular for small/HTPC builds. microATX is bigger (~9.6×9.6 inches). ATX is even larger. NLX is an older form factor. Exam tip: Know the approximate sizes and common use cases for each motherboard form factor.'                                                                                      
      },
      {
        id: 71,
        question: 'A technician wants to monitor traffic on a specific network segment for troubleshooting. Which device copies all traffic from a port to another port for analysis?',   
        options: [
          'IDS (Intrusion Detection System)',
          'Port mirror on a managed switch',
          'Wireless access point',
          'Router with NAT'
        ],
        correctAnswerIndex: 1,
        explanation: 'Port mirror on a managed switch is correct because it duplicates traffic for analysis (sometimes called SPAN). IDS inspects traffic but doesn’t necessarily mirror. A wireless AP or router with NAT do not replicate traffic for separate analysis. Exam tip: Use port mirroring (SPAN) to capture packets without altering production traffic.'             
      },
      {
        id: 72,
        question: 'Which of the following is the MOST likely cause if a laptop’s display is dim and flickers when on battery but is fine when plugged in?',                               
        options: [
          'Malfunctioning docking station',
          'Battery-saving settings reduce backlight brightness',
          'Inverter board is failing',
          'Screen resolution is set incorrectly'
        ],
        correctAnswerIndex: 1,
        explanation: 'Battery-saving settings reduce backlight brightness is correct because many laptops dim their displays to conserve battery. A failing inverter typically causes constant dim/flicker even on AC. Docking station issues are irrelevant if it’s not docked. Wrong screen resolution does not dim the backlight. Exam tip: Check power management settings first when display changes occur only on battery.'                                                
      },
      {
        id: 73,
        question: 'Which security feature is used on many motherboards to store encryption keys securely and support full disk encryption?',                                              
        options: [
          'TPM (Trusted Platform Module)',
          'UEFI Secure Boot',
          'HSM (Hardware Security Module)',
          'BIOS password'
        ],
        correctAnswerIndex: 0,
        explanation: 'TPM is correct because it securely stores cryptographic keys and is often used for BitLocker or full disk encryption. UEFI Secure Boot checks bootloader signatures but doesn’t store all keys. HSM is a separate device for enterprise key management. A BIOS password doesn’t store encryption keys. Exam tip: TPM is integral to hardware-based security and disk encryption solutions.'                                                                
      },
      {
        id: 74,
        question: 'Which is the MOST likely cause if an inkjet printer produces smudged or wet pages, especially near the output area?',                                                  
        options: [
          'Malfunctioning power supply',
          'Defective pick-up rollers',
          'Clogged printhead nozzles',
          'Damaged or misaligned paper feed rollers'
        ],
        correctAnswerIndex: 3,
        explanation: 'Damaged or misaligned paper feed rollers is correct because they can drag across wet ink, smearing the output. Power supply issues would cause power failures, not smudges. Clogged nozzles typically result in missing colors or streaks. Defective pickup rollers cause paper feeding errors but not specifically smudging. Exam tip: Smears near the output often indicate a paper feed problem causing contact with wet ink.'                          
      },
      {
        id: 75,
        question: 'A technician needs to perform a network tap to capture all traffic for analysis but has no spare ports on the switch. Which tool can still accomplish port-level capturing?',                                                                                       
        options: [
          'Managed switch with SNMP',
          'Port mirror (SPAN) on a managed switch',
          'Toner probe kit',
          'Loopback plug'
        ],
        correctAnswerIndex: 1,
        explanation: 'Port mirror (SPAN) on a managed switch is correct for capturing traffic on a specific port/VLAN. SNMP is for network management, not traffic capture. A toner probe kit traces cables. A loopback plug tests NICs or ports, not captures traffic. Exam tip: SPAN (port mirroring) is a standard feature on many managed switches for in-depth traffic analysis.'                                                                                           
      },
      {
        id: 76,
        question: 'A technician finds an M.2 drive that uses the NVMe protocol and requires a high-speed PCIe interface. Which slot type does this drive MOST likely use?',               
        options: [
          'M.2 SATA slot',
          'mSATA slot',
          'M.2 PCIe slot',
          'PCIe x16 expansion slot'
        ],
        correctAnswerIndex: 2,
        explanation: 'M.2 PCIe slot is correct because NVMe drives require a PCI Express-based M.2 interface. M.2 SATA uses the AHCI interface. mSATA is a different form factor. A full PCIe x16 expansion slot is typically for GPUs, not an M.2 card. Exam tip: Know the difference between M.2 SATA vs. M.2 NVMe to avoid performance bottlenecks.'                             
      },
      {
        id: 77,
        question: 'Which port does a technician typically configure on a firewall to allow secure HTTPS traffic from external clients to an internal web server?',                        
        options: [ '23', '80', '443', '3389' ],
        correctAnswerIndex: 2,
        explanation: '443 is correct for HTTPS. Port 23 is Telnet, 80 is HTTP (unsecured), and 3389 is RDP. Exam tip: HTTPS is a secure version of HTTP, operating on TCP port 443 by default.'                                                                                        
      },
      {
        id: 78,
        question: 'Which component in a laptop requires an inverter if using certain types of backlighting, such as older CCFL displays?',                                                
        options: [ 'Battery', 'Touchpad', 'LCD panel', 'WiFi antenna' ],
        correctAnswerIndex: 2,
        explanation: 'The LCD panel is correct because CCFL backlights need an inverter to convert DC to AC. A battery is DC-based. A touchpad is a pointer device, and WiFi antenna has no relation to inverters. Exam tip: Modern laptops with LED backlights often don’t need an inverter, but older CCFL panels do.'                                                            
      },
      {
        id: 79,
        question: 'A user’s desktop consistently overheats after upgrading to a new high-end GPU. Which is the MOST likely solution?',                                                    
        options: [
          'Replace the GPU with a low-profile variant',
          'Add more system RAM',
          'Install additional case fans or improve airflow',
          'Increase the CPU multiplier in BIOS'
        ],
        correctAnswerIndex: 2,
        explanation: 'Installing additional case fans or improving airflow is correct because a high-end GPU generates more heat. Replacing it with a low-profile card may negate performance benefits. More RAM won’t fix thermal issues. Overclocking the CPU further increases heat. Exam tip: Always ensure adequate cooling after hardware upgrades.'                          
      },
      {
        id: 80,
        question: 'Which networking tool can confirm the continuity of each wire in an Ethernet cable and detect wiring faults such as opens or shorts?',                                 
        options: [
          'Cable tester',
          'Toner probe',
          'Punchdown tool',
          'Loopback plug'
        ],
        correctAnswerIndex: 0,
        explanation: 'A cable tester is correct because it verifies each conductor’s continuity in an Ethernet cable. A toner probe is for tracing cables, not verifying conductor wiring. Punchdown tools terminate cables in patch panels. Loopback plugs are for testing ports, not cables end-to-end. Exam tip: Cable testers are essential for diagnosing wiring faults (opens, shorts, miswires).'                                                                         
      },
      {
        id: 81,
        question: 'Which connector type is commonly used for modular power supply cables that attach to SATA drives?',                                                                    
        options: [
          'Molex 4-pin',
          'PCIe 8-pin',
          'SATA 15-pin power',
          'EPS 12V connector'
        ],
        correctAnswerIndex: 2,
        explanation: 'SATA 15-pin power connector is correct because it provides power to SATA drives. Molex 4-pin is older for PATA or fans. PCIe 8-pin is for GPUs. EPS 12V is for high-power CPU connectors on motherboards. Exam tip: Modern HDDs/SSDs typically require SATA data and SATA power connectors.'                                                                  
      },
      {
        id: 82,
        question: 'Which of these is MOST likely the cause if a recently installed DIMM is not recognized by the system on boot?',                                                        
        options: [
          'Insufficient GPU VRAM',
          'Faulty module seating or incompatible RAM',
          'Unactivated Windows license',
          'Virus-infected boot sector'
        ],
        correctAnswerIndex: 1,
        explanation: 'Faulty seating or incompatible RAM is correct because the system won’t detect the module if physically or spec-wise it doesn’t match. GPU VRAM doesn’t affect main system RAM detection. Windows license status is irrelevant to hardware detection. A virus-infected boot sector might cause boot issues but not specifically unrecognized RAM. Exam tip: Always confirm the correct RAM type and ensure it’s firmly seated in the slot.'                 
      },
      {
        id: 83,
        question: 'A technician needs to ensure a new wireless router can handle both 2.4 GHz and 5 GHz frequencies. Which feature name indicates dual-band support?',                    
        options: [
          '802.11g only',
          '802.11ax (WiFi 6)',
          '802.11b/g/n',
          'Single-band antenna'
        ],
        correctAnswerIndex: 1,
        explanation: '802.11ax (WiFi 6) is correct in that it typically supports dual-band (2.4 and 5 GHz). 802.11g only runs on 2.4 GHz. 802.11b/g/n may support 2.4 or dual-band if indicated, but not guaranteed. A “single-band” antenna is obviously not dual-band. Exam tip: WiFi 5 (ac) and WiFi 6 (ax) commonly operate on both 2.4 and 5 GHz bands.'                       
      },
      {
        id: 84,
        question: 'Which of the following hypervisor types requires an underlying operating system to run and is often used in workstation-level virtualization?',                        
        options: [
          'Bare-metal hypervisor (Type 1)',
          'Hosted hypervisor (Type 2)',
          'Serverless computing environment',
          'Container-based virtualization'
        ],
        correctAnswerIndex: 1,
        explanation: 'Hosted hypervisor (Type 2) is correct because it installs on top of a host OS. Type 1 (bare-metal) runs directly on hardware. Serverless computing is unrelated to local virtualization. Container-based virtualization shares the OS kernel. Exam tip: Examples of Type 2 hypervisors include VMware Workstation and Oracle VirtualBox on Windows or Linux.' 
      },
      {
        id: 85,
        question: 'A technician uses a punchdown tool on a patch panel for twisted-pair cables. Which color code standard is commonly used for organization?',                            
        options: [
          'T568A/B',
          'SC/LC labeling',
          'RJ45 pinouts 1–8',
          'Molex color chart'
        ],
        correctAnswerIndex: 0,
        explanation: 'T568A/B is correct for specifying how cable pairs map to pin numbers. SC/LC labeling are fiber connector references. RJ45 pin numbers alone don’t define the specific color pairing. Molex is a power connector brand. Exam tip: Know T568A vs. T568B color coding for consistent cable terminations.'                                                        
      },
      {
        id: 86,
        question: 'Which display interface supports audio and video over a single cable, uses a 19-pin connector, and is commonly found on modern TVs and monitors?',                     
        options: [ 'DVI-D', 'VGA', 'HDMI', 'DisplayPort' ],
        correctAnswerIndex: 2,
        explanation: 'HDMI is correct because it carries both audio and video with a 19-pin connector. DVI-D and VGA do video only. DisplayPort can carry audio but uses a different connector. Exam tip: HDMI is ubiquitous in consumer electronics, carrying HD video + audio.'      
      },
      {
        id: 87,
        question: 'Which protocol is used to securely copy files between hosts and also operates on port 22, much like SSH?',                                                             
        options: [ 'TFTP', 'SCP', 'FTP', 'RDP' ],
        correctAnswerIndex: 1,
        explanation: 'SCP (Secure Copy Protocol) is correct because it runs over SSH (port 22). TFTP is unencrypted and uses UDP port 69, FTP uses ports 20/21 unencrypted, and RDP is port 3389 for remote desktop. Exam tip: SCP and SFTP both leverage SSH for secure file operations.'                                                                                          
      },
      {
        id: 88,
        question: 'After replacing a laptop LCD panel, the technician notices the microphone no longer works. Which is the MOST likely cause?',                                           
        options: [
          'CPU thermal compound applied incorrectly',
          'Loose or disconnected mic cable near the display assembly',
          'Dead pixel issues affecting microphone performance',
          'Broken antenna wire for WiFi'
        ],
        correctAnswerIndex: 1,
        explanation: 'Loose or disconnected mic cable near the display assembly is correct because many laptop microphones are integrated into the screen bezel. CPU thermal paste or dead pixels don’t affect the mic, and WiFi antenna cables are separate. Exam tip: Reassembling a laptop display often involves carefully reconnecting mic/webcam cables.'                     
      },
      {
        id: 89,
        question: 'Which of the following is a performance-based benefit of implementing RAID 0 for storage?',                                                                            
        options: [
          'Fault tolerance',
          'Parity-based redundancy',
          'Striping for increased read/write speed',
          'Mirroring for quick recovery'
        ],
        correctAnswerIndex: 2,
        explanation: 'Striping for increased read/write speed is correct because RAID 0 splits data across multiple disks, boosting performance. Fault tolerance is lacking in RAID 0. Parity-based redundancy is RAID 5/6, and mirroring is RAID 1/10. Exam tip: RAID 0 trades redundancy for raw speed.'                                                                          
      },
      {
        id: 90,
        question: 'A technician wants to boot a system from a network image rather than a local drive. Which BIOS/UEFI setting must be enabled to use PXE (Preboot eXecution Environment)?',                                                                                           
        options: [
          'Integrated NIC with PXE support',
          'VT-x (Intel) or AMD-V',
          'Secure Boot',
          'Fast Boot'
        ],
        correctAnswerIndex: 0,
        explanation: 'Integrated NIC with PXE support is correct for network boot. VT-x/AMD-V are for virtualization. Secure Boot checks digital signatures but doesn’t handle PXE specifically. Fast Boot skips some POST checks. Exam tip: PXE requires an enabled network interface with boot ROM or “Network Boot” setting.'                                                    
      },
      {
        id: 91,
        question: 'A user’s mobile device frequently fails to charge unless the cable is held at a certain angle. Which is the MOST likely issue?',                                       
        options: [
          'Damaged battery causing slow charging',
          'Incorrect OS version installed',
          'Faulty charging port or loose connector',
          'Insufficient mobile data signal'
        ],
        correctAnswerIndex: 2,
        explanation: 'Faulty charging port or loose connector is correct because if the cable must be positioned precisely, the port is likely damaged. A damaged battery typically shows quick discharges, not needing cable angles. OS version doesn’t cause physical charging issues. Mobile data signal affects connectivity, not charging. Exam tip: Worn or bent charging ports are a common hardware fault on mobile devices.'                                            
      },
      {
        id: 92,
        question: 'Which command-line tool can help verify the path data takes from a local computer to a remote host, listing each hop along the route?',                                
        options: [
          'ping',
          'ipconfig',
          'nslookup',
          'tracert (Windows)/traceroute (Linux)'
        ],
        correctAnswerIndex: 3,
        explanation: 'tracert (Windows) or traceroute (Linux) is correct because it shows each router hop en route to the destination. ping tests basic connectivity. ipconfig shows local IP settings. nslookup queries DNS. Exam tip: Use tracert/traceroute to diagnose where a connection fails along the path.'                                                                
      },
      {
        id: 93,
        question: 'A technician needs to install a 2.5" HDD into a desktop. Which adapter or mounting solution is MOST commonly required?',                                               
        options: [
          '3.5" to 2.5" drive bay adapter',
          'USB to eSATA cable',
          'Server rackmount rails',
          'M.2 to PCI Express riser'
        ],
        correctAnswerIndex: 0,
        explanation: 'A 3.5" to 2.5" drive bay adapter is correct because desktop bays are usually 3.5". A USB-to-eSATA cable is for external connectivity. Server rack rails are for rack-mounted systems. An M.2 to PCIe riser is for M.2 SSDs, not SATA 2.5" drives. Exam tip: Always match the physical form factor with an adapter or bracket if needed.'                      
      },
      {
        id: 94,
        question: 'A technician wants to install a Linux VM on top of an existing Windows 10 operating system. Which hypervisor type is needed?',                                         
        options: [
          'Type 1 (bare-metal) hypervisor',
          'Type 2 (hosted) hypervisor',
          'Container-based virtualization',
          'Dedicated hardware emulator card'
        ],
        correctAnswerIndex: 1,
        explanation: 'Type 2 (hosted) hypervisor is correct because it runs on top of Windows (the host OS). Type 1 requires direct hardware access (no host OS). Containers share the host OS kernel. A hardware emulator card is not standard for VMs. Exam tip: VMware Workstation and Oracle VirtualBox are typical Type 2 hypervisors for desktop use.'                        
      },
      {
        id: 95,
        question: 'Which of the following addresses is a valid IPv6 link-local address typically starting with FE80::?',                                                                  
        options: [
          '169.254.0.10',
          '192.168.1.10',
          'FE80::1C2B:3FFF:FE4A:1234',
          'FEC0::/10'
        ],
        correctAnswerIndex: 2,
        explanation: 'FE80::1C2B:3FFF:FE4A:1234 is correct because link-local IPv6 addresses begin with FE80::. 169.254.x.x is APIPA (IPv4). 192.168.1.10 is a private IPv4 address. FEC0::/10 was an old site-local range, not the standard link-local format. Exam tip: Link-local IPv6 always starts with FE80 and is only valid on the local subnet.'                           
      },
      {
        id: 96,
        question: 'A user cannot access internal network resources when plugged into a specific wall jack, though the cable tests fine. Which tool helps confirm the jack’s wiring path to the switch port?',                                                                          
        options: [
          'Punchdown tool',
          'Tone generator and probe',
          'Multimeter',
          'Crimper'
        ],
        correctAnswerIndex: 1,
        explanation: 'Tone generator and probe is correct for tracing the cable route in walls and finding which switch port it terminates on. A punchdown tool is for physically terminating cables, a multimeter checks electrical continuity/voltage, and a crimper attaches RJ45 plugs. Exam tip: Toner/probe kits are indispensable for tracking cables in complex cabling setups.'                                                                                         
      },
      {
        id: 97,
        question: 'A user wants to connect a smartphone to an external display wirelessly for presentations. Which technology is commonly used for screen mirroring on Android devices?', 
        options: [ 'RDP', 'Bluetooth tethering', 'Miracast', 'USB tethering' ],
        correctAnswerIndex: 2,
        explanation: 'Miracast is correct for Android wireless display mirroring on compatible devices/TVs. RDP is remote desktop. Bluetooth tethering is for data connectivity, not screen sharing. USB tethering shares data over USB, not the display. Exam tip: For Android screen mirroring, Miracast or Chromecast are typical solutions.'                                    
      },
      {
        id: 98,
        question: 'Which scenario is MOST likely if a RAID 5 array loses two drives simultaneously?',                                                                                     
        options: [
          'Array continues to function normally',
          'All data is still intact due to mirroring',
          'Data is lost until at least one drive is replaced and rebuilt',
          'No impact because parity can rebuild both drives at once'
        ],
        correctAnswerIndex: 2,
        explanation: 'Data is lost until at least one drive is replaced and rebuilt is correct because RAID 5 can only tolerate one drive failure. Losing two drives simultaneously breaks the array. It does not mirror two drives, and parity can’t rebuild if two drives are missing. Exam tip: RAID 5 requires all but one drive functional to remain online.'                  
      },
      {
        id: 99,
        question: 'Which cloud computing model involves hosting desktop environments in the cloud, allowing users to stream a full OS session remotely?',                                 
        options: [ 'IaaS', 'PaaS', 'DaaS', 'SaaS' ],
        correctAnswerIndex: 2,
        explanation: 'DaaS (Desktop as a Service) is correct because it hosts entire desktop sessions in the cloud. IaaS provides raw compute infrastructure. PaaS offers a development platform. SaaS delivers software applications. Exam tip: DaaS solutions let users access a virtual desktop from anywhere, managed by a cloud provider.'                                     
      },
      {
        id: 100,
        question: 'A laptop displays artifacts and random color blocks during gaming. Which is the MOST likely cause?',                                                                   
        options: [
          'Display cable not seated',
          'Video driver or dedicated GPU hardware failure',
          'Low battery threshold set in BIOS',
          'WiFi antenna interference'
        ],
        correctAnswerIndex: 1,
        explanation: 'Video driver or dedicated GPU hardware failure is correct because corrupted graphics are often linked to GPU or driver issues. A loose display cable usually causes flickering or a blank screen, not color artifacts. Battery threshold doesn’t affect rendering. WiFi interference impacts network, not GPU output. Exam tip: Artifacts often signal overheating or driver/hardware issues in the GPU.'                                                  
      }
    ]
