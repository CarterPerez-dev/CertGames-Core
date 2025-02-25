db.tests.insertOne({
  "category": "aplus",
  "testId": 8,
  "testName": "A+ Core 1 Practice Test #8 (Very Challenging)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A user reports that their laptop randomly shuts down without warning, but only when running graphically intensive applications. Which of the following is the MOST likely cause?",
      "options": [
        "Operating System corruption.",
        "Insufficient RAM.",
        "Overheating CPU or GPU.",
        "Failing hard drive."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Overheating CPU or GPU is the MOST likely cause. Graphically intensive applications place a high load on the GPU and CPU, increasing heat generation. If the cooling system is inadequate or failing, components can overheat and trigger thermal shutdowns to prevent damage. OS corruption or insufficient RAM usually cause sluggish performance or crashes, not specifically load-dependent shutdowns. A failing hard drive is less likely to cause shutdowns related to graphical load.",
      "examTip": "Load-dependent shutdowns, especially with graphically intensive tasks, strongly suggest overheating issues. Investigate cooling and thermal management."
    },
    {
      "id": 2,
      "question": "Which of the following network security concepts is BEST described as creating isolated network segments to limit the scope of a security breach and control lateral movement?",
      "options": [
        "Port Forwarding",
        "Network Address Translation (NAT)",
        "Network Segmentation",
        "Quality of Service (QoS)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Network Segmentation, using VLANs or subnets, is BEST described as creating isolated network segments to limit the scope of security breaches and control lateral movement. By dividing a network into segments, an attacker who breaches one segment is restricted from easily moving to others. Port forwarding is for external access, NAT for IP address conservation, and QoS for traffic prioritization.",
      "examTip": "Network segmentation is a critical security practice. It's about dividing your network into zones to contain breaches and limit attacker movement across your infrastructure."
    },
    {
      "id": 3,
      "question": "A technician is troubleshooting a laser printer that prints faded on one side of the page and darker on the other, with a distinct gradient across the page width. Which component is the MOST likely cause?",
      "options": [
        "Contaminated Laser Scanner Mirror.",
        "Unevenly Depleted Toner Cartridge.",
        "Damaged Transfer Corona Wire or Roller.",
        "Faulty Paper Feed Rollers."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An Unevenly Depleted Toner Cartridge is the MOST likely cause. If the toner is not evenly distributed within the cartridge or is depleted more on one side, it can result in a print gradient, with one side faded and the other darker. Laser scanner mirror issues might cause distortions, transfer corona issues affect toner transfer uniformity, and paper feed problems cause skewing or jams, not gradient fading.",
      "examTip": "A print gradient across the page width often points to uneven toner distribution or depletion within the toner cartridge. Try reseating or replacing the toner cartridge first."
    },
    {
      "id": 4,
      "question": "Which of the following attack types is characterized by an attacker intercepting and modifying communication between two parties without their knowledge?",
      "options": [
        "Denial of Service (DoS)",
        "Man-in-the-Middle (MITM)",
        "Phishing",
        "Ransomware"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Man-in-the-Middle (MITM) attacks are characterized by an attacker intercepting and modifying communication between two parties without their knowledge. The attacker positions themselves between the communicating parties, eavesdropping and potentially altering data in transit. DoS attacks disrupt service availability, phishing deceives users for information, and ransomware encrypts data for ransom.",
      "examTip": "Think of a MITM attack as eavesdropping and tampering in real-time. The attacker sits 'in the middle' of a communication path, unseen by the legitimate parties."
    },
    {
      "id": 5,
      "question": "A technician needs to select RAM for a high-performance gaming PC build that requires maximum memory bandwidth and low latency. Which RAM type and configuration is MOST appropriate?",
      "options": [
        "DDR4 RAM in a single-channel configuration.",
        "DDR4 RAM in a dual-channel configuration.",
        "DDR5 RAM in a dual-channel configuration with high clock speeds and low timings.",
        "DDR3 RAM in a quad-channel configuration."
      ],
      "correctAnswerIndex": 2,
      "explanation": "DDR5 RAM in a dual-channel configuration with high clock speeds and low timings is MOST appropriate. DDR5 is the latest and fastest RAM standard, offering higher bandwidth and performance than DDR4 and DDR3. Dual-channel configuration doubles the memory bandwidth compared to single-channel. High clock speeds and low timings further enhance performance, crucial for gaming. Quad-channel DDR3 is older and slower than dual-channel DDR5.",
      "examTip": "For top-tier gaming performance, always aim for the latest, fastest RAM standard (like DDR5) in a dual-channel or higher configuration, with attention to clock speeds and timings for optimal latency."
    },
    {
      "id": 6,
      "question": "Which of the following cloud service models provides the MOST comprehensive set of pre-configured infrastructure components, including virtual machines, storage, and networks, giving users maximum control over the environment?",
      "options": [
        "Software as a Service (SaaS)",
        "Platform as a Service (PaaS)",
        "Infrastructure as a Service (IaaS)",
        "Function as a Service (FaaS)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Infrastructure as a Service (IaaS) provides the MOST comprehensive set of pre-configured infrastructure components, including virtual machines, storage, and networks, giving users maximum control. IaaS offers the building blocks of cloud IT, allowing users to configure and manage their virtualized environment as they see fit. SaaS provides applications, PaaS a development platform, and FaaS serverless functions with less infrastructure control.",
      "examTip": "IaaS is about maximum infrastructure control in the cloud. It's the closest to having your own data center, but virtualized and on-demand."
    },
    {
      "id": 7,
      "question": "A laser printer is producing prints with consistently light or faded text and images across the entire page, even after replacing the toner cartridge and adjusting print density settings. Which component is the MOST likely cause of this uniformly faded output?",
      "options": [
        "Faulty Fuser Assembly.",
        "Worn-out or Contaminated Imaging Drum.",
        "Incorrect Paper Type Setting.",
        "Failing Laser Scanner Unit."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A Worn-out or Contaminated Imaging Drum is the MOST likely cause of uniformly faded print output. The imaging drum's condition directly affects its ability to attract and transfer toner effectively. If it's worn out or contaminated, it may not hold enough charge or transfer toner properly across the entire page, leading to consistently faded prints. Fuser issues cause smearing or unfused toner, and laser scanner issues cause distortions or banding, not uniform fading.",
      "examTip": "Uniformly faded prints, despite toner and density adjustments, often point to an aging or contaminated imaging drum. Drum replacement is often the solution for this type of print quality issue."
    },
    {
      "id": 8,
      "question": "Which of the following security threats is BEST mitigated by implementing strong input validation and output encoding techniques in web application development?",
      "options": [
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "Denial of Service (DoS)",
        "Brute-Force Attack"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Cross-Site Scripting (XSS) attacks are BEST mitigated by implementing strong input validation and output encoding techniques. XSS attacks exploit vulnerabilities in web applications that allow malicious scripts to be injected into web pages viewed by other users. Input validation prevents malicious scripts from being entered, and output encoding ensures that any user-provided data displayed on web pages is rendered safely, preventing script execution. SQL Injection is mitigated by parameterized queries, DoS by rate limiting, and brute-force by account lockout.",
      "examTip": "Input validation and output encoding are your primary defenses against Cross-Site Scripting (XSS) vulnerabilities. These techniques ensure that user-provided data is handled safely and doesn't become executable code in web browsers."
    },
    {
      "id": 9,
      "question": "A technician is configuring a new router and needs to set up a DMZ (Demilitarized Zone). What is the primary purpose of a DMZ in network security?",
      "options": [
        "To encrypt all internal network traffic.",
        "To isolate publicly accessible servers from the internal private network.",
        "To improve network performance by prioritizing traffic.",
        "To provide secure remote access to the internal network for administrators."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The primary purpose of a DMZ (Demilitarized Zone) is to isolate publicly accessible servers from the internal private network. The DMZ acts as a buffer zone, placing servers that need to be accessible from the internet (like web servers, mail servers) in a separate network segment. This way, if a server in the DMZ is compromised, attackers have limited direct access to the internal, more sensitive private network. VPNs provide secure remote access, QoS prioritizes traffic, and encryption is a broader security concept, not DMZ-specific.",
      "examTip": "Think of a DMZ as a 'safe exposure zone'. It's where you put your public-facing servers to protect your internal network from direct internet-borne threats."
    },
    {
      "id": 10,
      "question": "Which of the following memory technologies is Double Data Rate (DDR) and designed for high-performance graphics cards to handle large textures and frame buffers?",
      "options": [
        "DDR5 RAM",
        "DDR4 RAM",
        "GDDR6 (Graphics DDR6)",
        "SODIMM DDR5"
      ],
      "correctAnswerIndex": 2,
      "explanation": "GDDR6 (Graphics DDR6) is Double Data Rate (DDR) memory specifically designed for high-performance graphics cards. GDDR memory is optimized for the high bandwidth and low latency requirements of GPUs, enabling them to handle large textures and frame buffers for gaming and graphics-intensive applications. DDR4 and DDR5 RAM are system RAM types, and SODIMM DDR5 is a laptop form factor, not specifically graphics memory.",
      "examTip": "GDDR memory is dedicated graphics memory. It's different from system RAM (DDR4/DDR5) and is optimized for the unique demands of GPUs, especially bandwidth-intensive tasks like gaming."
    },
    {
      "id": 11,
      "question": "A user reports that their laptop screen is displaying an 'intermittent red tint' that comes and goes, sometimes with flickering. Which component is the MOST likely cause?",
      "options": [
        "Faulty Webcam Module.",
        "Loose or Damaged LCD Inverter.",
        "Failing GPU (Graphics Processing Unit).",
        "Loose or Damaged Video Cable."
      ],
      "correctAnswerIndex": 3,
      "explanation": "A Loose or Damaged Video Cable is the MOST likely cause of an intermittent red tint with flickering, especially if it comes and goes. A damaged or poorly connected video cable can cause signal issues, leading to color distortion and display instability. A failing GPU might cause more consistent artifacts or crashes, a faulty inverter affects backlight (not color tint specifically), and a webcam module is unrelated to the main display's color issues.",
      "examTip": "Intermittent color tints and flickering, especially in laptops, often point to a video cable problem. Check the cable and its connections first before suspecting more complex or expensive component failures."
    },
    {
      "id": 12,
      "question": "Which of the following network protocols operates at the Application Layer and is commonly used for managing and monitoring network devices?",
      "options": [
        "TCP (Transmission Control Protocol)",
        "UDP (User Datagram Protocol)",
        "SNMP (Simple Network Management Protocol)",
        "IP (Internet Protocol)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "SNMP (Simple Network Management Protocol) operates at the Application Layer and is commonly used for managing and monitoring network devices. SNMP allows network administrators to collect information from devices, monitor their status, and configure settings remotely. TCP and UDP are Transport Layer protocols, and IP is a Network Layer protocol.",
      "examTip": "SNMP is your 'network management language'. It's an Application Layer protocol designed specifically for monitoring and managing network devices."
    },
    {
      "id": 13,
      "question": "Which of the following RAID levels is known as 'disk striping with dual parity' and can tolerate up to two simultaneous drive failures without data loss, requiring a minimum of four drives?",
      "options": [
        "RAID 5",
        "RAID 6",
        "RAID 10",
        "RAID 50"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RAID 6 is known as 'disk striping with dual parity' and can tolerate up to two simultaneous drive failures without data loss. RAID 6 extends RAID 5 by adding a second parity block, enhancing fault tolerance. It requires at least four drives. RAID 5 uses single parity (one drive failure tolerance), RAID 10 is mirroring and striping (fault tolerance but less capacity efficient), and RAID 50 is nested RAID (combining RAID 5 and 0).",
      "examTip": "RAID 6 is the 'double fault tolerance' RAID level. It's more resilient than RAID 5, surviving up to two drive failures, but with slightly higher overhead and complexity."
    },
    {
      "id": 14,
      "question": "A technician needs to securely erase all data from an old SSD before disposal. Which method is MOST effective for ensuring data sanitization on an SSD?",
      "options": [
        "Quick Format.",
        "Standard Format.",
        "Degaussing.",
        "Secure Erase or Firmware-based Erase Utilities."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Secure Erase or Firmware-based Erase Utilities are MOST effective for data sanitization on SSDs. Unlike HDDs, SSDs are not effectively sanitized by degaussing or simple formatting due to their different data storage mechanisms (NAND flash). Secure Erase commands, often built into SSD firmware, use special commands to properly and securely wipe all data from SSDs, including over-provisioned areas. Quick and standard formats are insufficient for secure sanitization, and degaussing is ineffective on SSDs.",
      "examTip": "For SSD data sanitization, always use Secure Erase or firmware-based utilities. Standard formatting or degaussing are NOT reliable for SSDs."
    },
    {
      "id": 15,
      "question": "Which of the following cloud deployment models is characterized by being provisioned for exclusive use by a single organization, offering greater control and customization over the environment?",
      "options": [
        "Public Cloud",
        "Private Cloud",
        "Hybrid Cloud",
        "Community Cloud"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Private Cloud is characterized by being provisioned for exclusive use by a single organization. Private clouds offer enhanced control, security, and customization, as the infrastructure is dedicated to and managed by or for a single entity. Public clouds are shared, hybrid clouds combine public and private, and community clouds are shared by specific communities.",
      "examTip": "Private clouds are all about exclusivity and control. They are single-tenant environments, offering the highest degree of customization and security for a single organization."
    },
    {
      "id": 16,
      "question": "A user reports that their laptop speakers are producing distorted audio, especially at higher volumes, and sometimes with crackling sounds. Which component is MOST likely causing this audio distortion?",
      "options": [
        "Faulty Audio Driver.",
        "Damaged Audio Codec Chip on Motherboard.",
        "Overheating CPU.",
        "Damaged or Overdriven Laptop Speakers."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Damaged or Overdriven Laptop Speakers are the MOST likely cause of distorted audio, especially at higher volumes and with crackling sounds. Laptop speakers are small and can be easily damaged or overdriven, leading to distortion, particularly at louder volumes. While audio driver or codec issues can cause audio problems, distortion and crackling are more indicative of physical speaker damage. Overheating CPU and motherboard issues are less likely to directly cause speaker distortion.",
      "examTip": "Distorted or crackling audio, especially at higher volumes, often suggests physically damaged or overdriven speakers. Always check the speakers themselves when diagnosing audio distortion."
    },
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
      "examTip": "Flickering or distorted laptop displays, especially when moving the screen, often point to a loose or damaged display cable connection. Check the cable and its connections first for such issues."
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
      "examTip": "Network segmentation (VLANs, subnets) is a critical security practice. It's about dividing your network into zones to contain breaches and limit attacker movement across your infrastructure."
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
      "question": "A technician suspects a workstation is infected with ransomware. Which action should be performed FIRST according to best practice methodology?",
      "options": [
        "Pay the ransom to recover data.",
        "Disconnect the workstation from the network.",
        "Run a full system scan with antivirus software.",
        "Format the hard drive and reinstall the operating system."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Disconnect the workstation from the network should be the FIRST action. This isolates the infected machine, preventing the ransomware from spreading to other network devices or communicating with its command and control server. Paying the ransom is generally discouraged, scanning and formatting are later steps in remediation. Exam tip: Isolation is always the first step when dealing with suspected malware infections.",
      "examTip": "Isolate first! Disconnecting an infected machine from the network is crucial to contain the spread of ransomware and other malware."
    },
    {
      "id": 26,
      "question": "Which of the following CPU architectures is MOST commonly used in modern smartphones and tablets due to its power efficiency and suitability for mobile computing?",
      "options": [
        "x86",
        "x64",
        "ARM",
        "Itanium"
      ],
      "correctAnswerIndex": 2,
      "explanation": "ARM (Advanced RISC Machine) architecture is MOST commonly used in modern smartphones and tablets. ARM processors are known for their power efficiency, making them ideal for battery-powered mobile devices. x86 and x64 architectures are dominant in desktops and laptops, while Itanium is a server-class architecture.",
      "examTip": "ARM architecture is synonymous with mobile devices. Think smartphones and tablets – they almost universally use ARM-based processors for their power efficiency."
    },
    {
      "id": 27,
      "question": "A user reports slow internet browsing speeds, and after initial checks, the technician suspects a local network issue. Which of the following network devices should be investigated FIRST as a potential bottleneck?",
      "options": [
        "DNS Server.",
        "Web Server.",
        "SOHO Router.",
        "ISP's Gateway Router."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The SOHO Router (Small Office/Home Office Router) should be investigated FIRST. In a home or small office scenario, the SOHO router is the central device connecting the local network to the internet. It's often the bottleneck for internet speed issues within the local network. DNS server issues would typically cause website access failures, not just slowness. Web servers are remote, and the ISP's gateway router is outside the local network's immediate control.",
      "examTip": "For home or small office internet slowness, the SOHO router is the prime suspect. It's the gateway between your local network and the internet, and often the point of congestion."
    },
    {
      "id": 28,
      "question": "Which of the following is a characteristic of 'Hybrid Cloud' deployment model in terms of scalability and flexibility?",
      "options": [
        "Limited scalability and flexibility due to reliance on on-premises infrastructure.",
        "Offers enhanced scalability and flexibility by allowing workloads to be moved between private and public cloud environments based on demand.",
        "Provides fixed scalability and flexibility, as resources are pre-allocated and cannot be dynamically adjusted.",
        "Scalability and flexibility are solely determined by the public cloud component, with the private cloud acting as a static extension."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hybrid Cloud offers enhanced scalability and flexibility by allowing workloads to be moved between private and public cloud environments based on demand. This dynamic workload placement is a key advantage of hybrid clouds, enabling organizations to scale resources and adapt to changing needs by leveraging both private and public infrastructure.",
      "examTip": "Hybrid clouds are about 'best of both worlds' scalability. You can burst workloads to the public cloud for peak demand and keep sensitive data in your private cloud, offering great flexibility."
    },
    {
      "id": 29,
      "question": "A laser printer is producing prints with a repeating 'light streak' or 'fade' mark that extends horizontally across the page, perpendicular to the paper feed direction. Which printer component is MOST likely causing this horizontal streak defect?",
      "options": [
        "Toner Cartridge (defective metering blade causing uneven toner flow)",
        "Fuser Assembly (horizontal pressure roller damage)",
        "Imaging Drum (horizontal scratch or defect)",
        "Laser Scanner Assembly (vertical deflection mirror issue)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A Toner Cartridge with a defective metering blade causing uneven toner flow is MOST likely causing a horizontal light streak or fade. The metering blade controls the amount of toner applied to the drum. If it's defective, it can cause uneven toner distribution, leading to horizontal streaks. Fuser and imaging drum issues typically cause vertical defects, and laser scanner problems cause distortions or banding, not horizontal streaks.",
      "examTip": "Horizontal streaks or fades in laser prints often point to a toner cartridge metering blade issue. Try replacing the toner cartridge first when diagnosing this problem."
    },
    {
      "id": 30,
      "question": "Which of the following is a BEST practice for securing user accounts against brute-force attacks on SSH (Secure Shell) service?",
      "options": [
        "Using default SSH port 22.",
        "Allowing password-based authentication only for SSH.",
        "Disabling SSH logging to reduce system resource usage.",
        "Disabling password-based authentication and using SSH keys, along with rate limiting and intrusion detection systems."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Disabling password-based authentication and using SSH keys, along with rate limiting and intrusion detection systems, is a BEST practice for securing SSH against brute-force attacks. SSH keys provide much stronger authentication than passwords. Rate limiting reduces the rate of login attempts, and IDS can detect and block suspicious activity. Default ports and password-based auth are vulnerabilities, and disabling logging hinders security monitoring.",
      "examTip": "For SSH security, disable password authentication and enforce SSH key-based authentication. This is a major step in preventing brute-force attacks."
    },
    {
      "id": 31,
      "question": "Which of the following TCP ports is used by Microsoft Active Directory Lightweight Directory Access Protocol Secure (LDAPS) for secure queries to domain controllers?",
      "options": [
        "Port 389",
        "Port 636",
        "Port 3268",
        "Port 3269"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Port 636 is the standard TCP port used by Microsoft Active Directory Lightweight Directory Access Protocol Secure (LDAPS) for secure queries to domain controllers. LDAPS encrypts LDAP traffic using SSL/TLS for confidentiality and integrity. Port 389 is for unencrypted LDAP, and ports 3268/3269 are for Global Catalog.",
      "examTip": "Port 636 is the secure LDAP port (LDAPS). Always use LDAPS for secure communication with Active Directory domain controllers when querying directory services."
    },
    {
      "id": 32,
      "question": "A technician is optimizing Wi-Fi for a coffee shop environment with high user density and a mix of laptops, smartphones, and tablets. Which Wi-Fi band steering and load balancing strategies are MOST effective for improving user experience?",
      "options": [
        "Disabling band steering and load balancing to simplify configuration.",
        "Forcing all devices to connect to the 2.4 GHz band for wider coverage.",
        "Enabling band steering to direct dual-band clients to the 5 GHz band and implementing client load balancing across access points.",
        "Using only 5 GHz band access points with maximum channel width and transmit power to maximize throughput."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Enabling band steering to direct dual-band clients to 5 GHz and implementing client load balancing across access points is MOST effective. Band steering encourages capable devices to use the less congested 5 GHz band, and load balancing distributes clients across access points, preventing overload and improving overall performance in high-density environments. 2.4 GHz alone is too congested, and disabling steering/balancing negates key optimization features.",
      "examTip": "Band steering and load balancing are crucial for high-density Wi-Fi deployments like coffee shops. They distribute clients and traffic effectively, improving user experience for everyone."
    },
    {
      "id": 33,
      "question": "Which of the following is a key characteristic of 'Function as a Service' (FaaS) cloud computing model in terms of operational management and scaling?",
      "options": [
        "Users are responsible for managing the underlying servers and operating systems.",
        "Scaling is automatically handled by the cloud provider based on event triggers, and users do not manage server instances.",
        "Users must manually scale resources up or down based on application demand.",
        "FaaS offers limited scalability and is primarily designed for static, low-workload applications."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Scaling is automatically handled by the cloud provider in FaaS, triggered by events, and users do not manage server instances. This 'serverless' nature of FaaS means the cloud provider automatically scales resources up or down in response to function invocations, abstracting away server management from the user.",
      "examTip": "FaaS is 'auto-scaling on steroids'. Scaling is completely automated and event-driven, a core benefit of serverless computing. You don't manage servers, just functions."
    },
    {
      "id": 34,
      "question": "A laser printer is producing prints with a repeating 'light vertical line' defect, consistently appearing at the same position down the page. After replacing the toner cartridge and cleaning the paper path, the issue persists. Which component is MOST likely causing this consistent vertical line?",
      "options": [
        "Faulty Fuser Assembly Roller.",
        "Defective Transfer Corona Wire Assembly.",
        "Scratch or Defect on the Imaging Drum Surface.",
        "Contamination on the Laser Scanner Mirror."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A Scratch or Defect on the Imaging Drum Surface is the MOST likely cause of a consistent vertical light line. A physical defect on the drum will prevent toner from adhering properly at that location during each rotation, resulting in a repeating vertical line on every print. Fuser and corona wire issues typically cause different types of defects, and laser scanner mirror contamination would likely cause horizontal or broader image quality issues.",
      "examTip": "Consistent, repeating vertical lines in laser prints strongly suggest a physical defect on the imaging drum. Carefully inspect the drum surface for scratches or damage."
    },
    {
      "id": 35,
      "question": "Which of the following is a BEST practice for securing user accounts against session fixation attacks (where attackers try to hijack a valid user session ID)?",
      "options": [
        "Using predictable session IDs for simplicity.",
        "Disabling session timeouts to improve user experience.",
        "Regenerating session IDs after successful user authentication and using secure, random session IDs.",
        "Storing session IDs in URL parameters instead of cookies for easier management."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Regenerating session IDs after authentication and using secure, random session IDs are key best practices to prevent session fixation attacks. Regenerating IDs after login invalidates any pre-authentication IDs an attacker might have tried to fixate. Secure, random IDs make them harder to guess or predict. Predictable IDs and session storage in URLs are vulnerabilities.",
      "examTip": "Session ID regeneration after login and strong, random session IDs are crucial to prevent session fixation attacks. Always invalidate old session IDs upon successful authentication."
    },
    {
      "id": 36,
      "question": "Which of the following TCP ports is used by Microsoft Active Directory Kerberos Change Password Protocol (kpasswd) for password changes?",
      "options": [
        "Port 88 (Kerberos)",
        "Port 464 (kpasswd/changepw)",
        "Port 749 (kadmin/administration)",
        "Port 3268 (GC)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Port 464 is the standard TCP port used by Microsoft Active Directory Kerberos Change Password Protocol (kpasswd) for password changes. This port is specifically for Kerberos password change operations. Port 88 is for Kerberos authentication, Port 749 for kadmin administration, and Port 3268 for Global Catalog.",
      "examTip": "Port 464 is specifically for Kerberos password changes (kpasswd/changepw) in Active Directory environments."
    },
    {
      "id": 37,
      "question": "A technician is optimizing Wi-Fi for a large conference hall expecting very high client density and bandwidth usage, especially during peak event times. Which advanced Wi-Fi 6/6E features are MOST beneficial for maximizing capacity and minimizing congestion in this high-density scenario?",
      "options": [
        "Increased Transmit Power and High-Gain Antennas.",
        "Wider 2.4 GHz Channels using Channel Bonding.",
        "OFDMA (Orthogonal Frequency Division Multiple Access), MU-MIMO (Multi-User MIMO), and BSS Coloring in 5 GHz and 6 GHz bands.",
        "Disabling Wireless Encryption to Reduce Overhead."
      ],
      "correctAnswerIndex": 2,
      "explanation": "OFDMA, MU-MIMO, and BSS Coloring in 802.11ax (Wi-Fi 6/6E) are MOST beneficial for maximizing capacity and minimizing congestion in high-density scenarios like conference halls. These features are designed to improve efficiency in dense client environments. Increased transmit power can worsen interference, 2.4 GHz is too congested, and disabling encryption is a security risk.",
      "examTip": "For high-density Wi-Fi deployments, focus on 802.11ax features like OFDMA, MU-MIMO, and BSS Coloring. These technologies are designed to handle dense client loads efficiently."
    },
    {
      "id": 38,
      "question": "Which of the following is a key challenge associated with 'lift-and-shift' migration strategy when moving legacy applications to a public cloud environment?",
      "options": [
        "Simplified application management in the cloud.",
        "Automatic optimization of application performance and scalability in the cloud environment.",
        "Limited ability to leverage cloud-native features and potential for inefficient resource utilization and higher costs.",
        "Reduced security risks due to inherent cloud security features."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Limited ability to leverage cloud-native features and potential for inefficient resource utilization and higher costs are key challenges of lift-and-shift migration. 'Lift-and-shift' involves moving applications to the cloud without significant re-architecting. This often means legacy apps don't fully utilize cloud benefits like auto-scaling or managed services, leading to inefficiencies and potentially higher long-term costs compared to cloud-native approaches.",
      "examTip": "Lift-and-shift is often a quick migration path, but it can lead to inefficiencies and missed opportunities to fully leverage cloud benefits. It's a trade-off between speed and cloud optimization."
    },
    {
      "id": 39,
      "question": "A laser printer is producing prints with inconsistent density, alternating between light and dark areas across the page, creating a wavy or uneven appearance. Which printer component is MOST likely causing this uneven density issue?",
      "options": [
        "Toner Cartridge (inconsistent toner mixture)",
        "Fuser Assembly (uneven roller pressure or temperature)",
        "Imaging Drum (variable sensitivity or uneven coating)",
        "Laser Scanner Assembly (fluctuating laser beam intensity)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Variable sensitivity or uneven coating on the Imaging Drum is MOST likely causing inconsistent density and a wavy appearance. If the drum's surface sensitivity varies, it will attract toner unevenly, leading to alternating light and dark areas on the print. Toner, fuser, and laser scanner issues typically manifest differently (streaks, smearing, banding).",
      "examTip": "Uneven print density or wavy patterns often point to an issue with the imaging drum's surface uniformity. Consider drum replacement if you see inconsistent density across prints."
    },
    {
      "id": 40,
      "question": "Which of the following is a BEST practice for securing user accounts against account enumeration attacks (where attackers try to guess valid usernames)?",
      "options": [
        "Using easily guessable usernames (e.g., 'admin', 'user').",
        "Disclosing valid usernames in error messages or API responses.",
        "Implementing generic error messages for login failures and rate limiting login attempts.",
        "Providing detailed error messages indicating whether the username exists or not during login attempts."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Implementing generic error messages and rate limiting login attempts is a BEST practice to prevent account enumeration. Generic error messages (like 'Invalid login') don't reveal whether a username is valid, and rate limiting slows down guessing attempts. Default usernames and disclosing username validity in errors aid enumeration attacks.",
      "examTip": "Generic error messages and rate limiting are key defenses against account enumeration. Don't give attackers hints about valid usernames."
    },
    {
      "id": 41,
      "question": "Which of the following TCP ports is used by Microsoft Active Directory Kerberos authentication for ticket granting tickets (TGT) and service tickets?",
      "options": [
        "Port 88 (Kerberos)",
        "Port 464 (kpasswd/changepw)",
        "Port 749 (kadmin/administration)",
        "Port 3269 (GCoverSSL)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Port 88 is the standard TCP and UDP port used by Microsoft Active Directory Kerberos authentication for ticket granting tickets (TGT) and service tickets. This is the core port for Kerberos authentication traffic.",
      "examTip": "Port 88 (Kerberos) is the central port for Kerberos authentication, handling both initial ticket requests and subsequent service ticket exchanges."
    },
    {
      "id": 42,
      "question": "A technician is optimizing Wi-Fi for a long, narrow office space. Which Wi-Fi antenna type and placement strategy is MOST effective for directing the signal along the length of the office and minimizing spillover to adjacent areas?",
      "options": [
        "Using omnidirectional antennas placed centrally.",
        "Using high-gain omnidirectional antennas placed at each end of the office.",
        "Using directional antennas (e.g., Yagi or Panel antennas) pointed along the length of the office.",
        "Using patch antennas mounted on the ceiling facing downwards."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Directional antennas (Yagi or Panel) pointed along the office length are BEST for focused coverage and minimizing spillover.",
      "examTip": "For long, narrow spaces, directional antennas are ideal for focusing Wi-Fi signals where needed and reducing bleed-over."
    },
    {
      "id": 43,
      "question": "Which of the following is a key characteristic of 'Private Cloud' deployment model in terms of resource accessibility and control?",
      "options": [
        "Resources are accessible to the general public over the internet.",
        "Resources are shared among multiple organizations with common interests.",
        "Resources are provisioned for exclusive use by a single organization, offering greater control and customization.",
        "Resources are dynamically provisioned and de-provisioned by a third-party provider with minimal user control."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Private clouds offer exclusive use, greater control, and customization to a single organization.",
      "examTip": "Remember 'Private' = exclusive use and maximum control for a single organization."
    },
    {
      "id": 44,
      "question": "A laser printer is producing prints with a consistent 'jagged edge' or 'stair-step' appearance on diagonal lines and curves, while straight lines are generally sharp. Which printer component or setting is MOST likely causing this jagged edge defect?",
      "options": [
        "Low Print Resolution Setting.",
        "Faulty Fuser Assembly causing Toner Scatter.",
        "Damaged Imaging Drum causing Pixel Misalignment.",
        "Incorrect Paper Type causing Toner Bleeding."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Low Print Resolution Setting is MOST likely causing jagged edges or stair-stepping on curves and diagonals.",
      "examTip": "Jagged edges on curves and diagonals are classic signs of low print resolution. Increase the DPI setting for smoother edges."
    },
    {
      "id": 45,
      "question": "Which of the following is a BEST practice for securing user accounts against insider threats (threats originating from within the organization)?",
      "options": [
        "Granting all employees administrative privileges for system access.",
        "Disabling audit logging to protect user privacy.",
        "Implementing the principle of least privilege, role-based access control (RBAC), and regular security audits.",
        "Relying solely on perimeter security measures to prevent external access."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Least privilege, RBAC, and regular audits are crucial for mitigating insider threats by limiting unnecessary access and monitoring user activities.",
      "examTip": "Least privilege and RBAC are fundamental for insider threat mitigation. Limit access and monitor user actions."
    },
    {
      "id": 46,
      "question": "Which of the following TCP ports is used by Microsoft Active Directory Kerberos Key Distribution Center (KDC) for authentication requests using UDP?",
      "options": [
        "Port 88 (TCP and UDP)",
        "Port 464 (kpasswd/changepw)",
        "Port 749 (kadmin/administration)",
        "Port 3268 (GC)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Port 88 (Kerberos) uses both TCP and UDP, and UDP is often used for initial authentication requests due to its lower overhead.",
      "examTip": "Kerberos (port 88) uses both TCP and UDP, with UDP being common for initial authentication requests."
    },

    /* REPLACED with PBQ style question */
    {
      "id": 47,
      "question": "Performance-Based Question (PBQ): A user is preparing a brand-new 2 TB GPT disk in a UEFI-based system to install Windows 10 Pro. They want two partitions: one for the OS and one for data. Which of the following sequences is the CORRECT order of steps to create and format these partitions during Windows Setup?",
      "options": [
        "1) Select the disk, click Next to begin install, 2) Wait for Windows to auto-partition, 3) Format the OS partition post-install, 4) Create a second data partition in Disk Management after installation.",
        "1) Delete any existing partitions, 2) Create a new partition for the OS and format it, 3) Create a second data partition and format it, 4) Proceed with installation on the OS partition.",
        "1) Choose 'Upgrade' install so partitions are pre-preserved, 2) Format the entire disk as MBR, 3) Create one large partition, 4) Convert it to GPT after Windows is installed.",
        "1) Select 'Repair Your Computer', 2) Run diskpart to convert the drive to dynamic, 3) Create a single primary partition, 4) Cancel and re-run Setup with default partitioning."
      ],
      "correctAnswerIndex": 1,
      "explanation": "In a UEFI system using GPT, you typically delete any existing partitions on a brand-new disk (or confirm it's blank), create your OS partition, format it, then create and format the data partition. You can then install Windows onto the OS partition. The second partition is also created before installation if you want it recognized immediately. This approach ensures the Windows setup respects the GPT style and places the necessary EFI and recovery partitions automatically. Other methods are either incomplete or out of sequence.",
      "examTip": "When installing Windows under UEFI, always confirm GPT usage, delete old partitions (if any), then create and format new partitions in Setup or via diskpart—especially for multi-partition layouts."
    },

    /* REPLACED with PBQ style question */
    {
      "id": 48,
      "question": "Performance-Based Question (PBQ): A technician is troubleshooting a user’s inability to reach a specific internal website. Arrange the following diagnostic steps in the CORRECT order to isolate the root cause.",
      "options": [
        "1) Reinstall the web browser, 2) Swap in a new network interface card, 3) Check Wi-Fi driver logs, 4) Perform nslookup or ping to the site’s hostname/IP, then review DNS settings.",
        "1) Open the site on a known working PC for baseline, 2) Flush DNS cache and attempt to ping site by IP, 3) Check local hosts file entries, 4) Review DNS server settings or internal IP blocks.",
        "1) Run a full virus scan, 2) Power cycle all network hardware, 3) Revert to a previous system restore point, 4) Modify DHCP scope on the router to include the site’s IP in reservations.",
        "1) Disable the firewall entirely, 2) Replace the router, 3) Configure a static IP on the client, 4) Attempt to browse the site with new credentials."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A systematic approach is best: first confirm the site works elsewhere, then flush DNS and check connectivity by IP to see if DNS is the issue. Next, verify the hosts file and DNS server settings. Steps like reinstalling the browser or changing hardware are more drastic and typically come later. Starting with methodical network checks helps isolate DNS or routing issues first.",
      "examTip": "When diagnosing internal site issues, always compare with a working reference, then check DNS and local overrides (hosts file), before investigating deeper networking or hardware problems."
    },

    {
      "id": 49,
      "question": "A laser printer is producing prints with a repeating 'horizontal band of missing print' across the page, perpendicular to the paper feed direction. Which printer component is MOST likely causing this horizontal band defect?",
      "options": [
        "Toner Cartridge (defective metering roller)",
        "Fuser Assembly (roller surface damage causing toner repulsion)",
        "Imaging Drum (repeating defect along its circumference)",
        "Laser Scanner Assembly (polygon mirror facet obstruction or damage)"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Polygon mirror facet obstruction or damage in the Laser Scanner Assembly is MOST likely causing a horizontal band of missing print.",
      "examTip": "Horizontal banding in laser prints often points to issues with the laser scanner assembly, particularly the polygon mirror."
    },
    {
      "id": 50,
      "question": "Which of the following is a BEST practice for securing user accounts against session fixation attacks in web applications?",
      "options": [
        "Using long-lasting session timeouts to minimize user inconvenience.",
        "Disabling session encryption to improve performance.",
        "Regenerating session IDs after successful user authentication and using secure, random session IDs.",
        "Storing session IDs in URL parameters instead of cookies for easier management."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Regenerating session IDs after authentication and using secure, random session IDs are key best practices to prevent session fixation attacks. Regenerating IDs after login invalidates any pre-authentication IDs an attacker might have tried to fixate. Secure, random IDs make them harder to guess or predict. Predictable IDs and session storage in URLs are vulnerabilities.",
      "examTip": "Session ID regeneration after login and strong, random session IDs are crucial to prevent session fixation attacks. Always invalidate old session IDs upon successful authentication."
    },
    {
      "id": 51,
      "question": "A technician is asked to implement 'link aggregation control protocol' (LACP) on a managed switch. What is the primary advantage of using LACP over static link aggregation?",
      "options": [
        "LACP provides higher maximum bandwidth compared to static aggregation.",
        "LACP automatically detects and configures link aggregation, providing dynamic link management and failover.",
        "LACP simplifies network configuration by eliminating the need for manual link configuration.",
        "LACP reduces network latency by optimizing traffic distribution across aggregated links."
      ],
      "correctAnswerIndex": 1,
      "explanation": "LACP automatically detects and configures link aggregation, offering dynamic management and failover capabilities.",
      "examTip": "LACP offers dynamic, automatic link aggregation management, making it more resilient than static configurations."
    },
    {
      "id": 52,
      "question": "Which of the following is a key security challenge associated with 'serverless computing' or 'Function-as-a-Service (FaaS)' cloud models in terms of access control and permissions management?",
      "options": [
        "Simplified access control due to provider-managed security.",
        "Increased granularity and complexity in managing permissions for individual functions and event sources.",
        "Lack of access control options as serverless functions are inherently publicly accessible.",
        "Reduced complexity in auditing and monitoring access due to centralized function execution logs."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Serverless computing requires managing permissions for a large number of individual functions and event sources, increasing complexity.",
      "examTip": "Be prepared for granular and complex permission management in serverless architectures."
    },
    {
      "id": 53,
      "question": "A laser printer is producing prints with a repeating 'light and dark banding' pattern perpendicular to the paper feed direction, resembling a Venetian blind effect. Which printer component is MOST likely causing this banding pattern?",
      "options": [
        "Toner Cartridge (defective metering blade causing uneven toner flow)",
        "Fuser Assembly (roller surface irregularities causing uneven fusing)",
        "Imaging Drum (periodic sensitivity variations or defects along its circumference)",
        "Laser Scanner Assembly (polygon mirror facet irregularities or inconsistent laser modulation)"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Inconsistent laser modulation or polygon mirror irregularities in the Laser Scanner Assembly can cause a repeating Venetian blind effect.",
      "examTip": "Examine the laser scanner assembly if you observe regular light and dark banding patterns in your prints."
    },
    {
      "id": 54,
      "question": "Which of the following is a BEST practice for securing user accounts against credential theft attacks, such as phishing or malware-based credential harvesting?",
      "options": [
        "Storing passwords in plain text databases.",
        "Disabling multi-factor authentication (MFA).",
        "Implementing multi-factor authentication (MFA), anti-phishing training, and endpoint security measures.",
        "Relying solely on complex password policies without additional security layers."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Implementing MFA, along with user training and endpoint security, significantly reduces the risk of credential theft.",
      "examTip": "Layered security including MFA, user education, and endpoint protection is key to defending against credential theft."
    },
    {
      "id": 55,
      "question": "Which of the following TCP ports is used by Microsoft Active Directory Kerberos Administration protocol (kadmin) for remote administration of the Kerberos KDC (Key Distribution Center)?",
      "options": [
        "Port 88",
        "Port 464 (kpasswd/changepw)",
        "Port 749 (kadmin/administration)",
        "Port 3269 (GCoverSSL)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Port 749 is used for Kerberos administration (kadmin) for remote management of the KDC.",
      "examTip": "For remote Kerberos administration, port 749 is the designated port."
    },
    {
      "id": 56,
      "question": "A technician is asked to design a high-density Wi-Fi network for a large outdoor stadium requiring very high capacity and density to support tens of thousands of concurrent users. Which Wi-Fi technology and advanced features are MOST critical for ensuring network performance and stability under extreme load?",
      "options": [
        "802.11b access points with omnidirectional antennas.",
        "802.11g access points with channel bonding in the 2.4 GHz band.",
        "802.11ax (Wi-Fi 6 or Wi-Fi 6E) with high-density features like OFDMA, MU-MIMO, BSS Coloring, and 160 MHz channels in the 5 GHz and 6 GHz bands, combined with advanced cell planning and load balancing.",
        "Standard 802.11ac (Wi-Fi 5) access points with increased transmit power and high-gain omnidirectional antennas."
      ],
      "correctAnswerIndex": 2,
      "explanation": "802.11ax (Wi-Fi 6/6E) with advanced high-density features is specifically designed to handle extreme loads in environments like large outdoor stadiums.",
      "examTip": "For stadium-scale Wi-Fi, utilize the full suite of advanced 802.11ax features combined with expert network planning to support massive concurrent usage."
    },
    {
      "id": 57,
      "question": "Which of the following is a key consideration when designing a 'Backup and Disaster Recovery' (DR) strategy for a hybrid cloud environment?",
      "options": [
        "Assuming that public cloud components are inherently protected and do not require backup.",
        "Focusing solely on backing up on-premises private cloud components, as public cloud data is provider-managed.",
        "Developing a unified backup and DR strategy that covers both private and public cloud components, addressing data consistency and recovery across environments.",
        "Ignoring data replication between private and public clouds for simplicity and cost reduction."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Developing a unified backup and DR strategy that covers both private and public cloud components is essential in a hybrid cloud environment.",
      "examTip": "Ensure your DR plan addresses all components of your hybrid cloud for data consistency and rapid recovery."
    },
    {
      "id": 58,
      "question": "A laser printer is producing prints with a consistent 'smear' or 'blur' that is most pronounced at the bottom of the page and gradually fades towards the top. Which printer component is MOST likely causing this bottom-heavy smear defect?",
      "options": [
        "Toner Cartridge (overfilling or toner leakage)",
        "Fuser Assembly (uneven heating or pressure, worse at output end)",
        "Imaging Drum (contamination accumulating at the bottom edge)",
        "Cleaning Blade or Wiper Blade (ineffective cleaning at the bottom edge)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "An uneven fuser assembly, particularly at the output end, can result in a bottom-heavy smear as toner is not properly fused.",
      "examTip": "Inspect the fuser assembly for uneven pressure or temperature issues if smearing is more pronounced at the bottom of the page."
    },
    {
      "id": 59,
      "question": "Which of the following is a BEST practice for securing user accounts against session hijacking attacks in web applications?",
      "options": [
        "Using HTTP for all web traffic to avoid encryption overhead.",
        "Implementing HTTPS for all web traffic, using HTTP-only and Secure flags on session cookies, and regularly regenerating session IDs.",
        "Storing session IDs in URL parameters for easier access and management.",
        "Disabling session timeouts to minimize user interruptions."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Implementing HTTPS, secure cookie flags, and session ID regeneration are essential practices to prevent session hijacking in web applications.",
      "examTip": "Secure your web applications with HTTPS and proper session management to mitigate session hijacking risks."
    },
    {
      "id": 60,
      "question": "Which of the following TCP ports is used by Microsoft Active Directory Global Catalog for LDAP queries to retrieve objects from the entire forest, and is often used for initial domain searches?",
      "options": [
        "Port 389",
        "Port 636",
        "Port 3268",
        "Port 3269"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Port 3268 is used for non-secure Global Catalog LDAP queries to retrieve forest-wide objects.",
      "examTip": "Use port 3268 for Global Catalog queries when encryption is not mandated."
    },
    {
      "id": 61,
      "question": "A technician is optimizing Wi-Fi performance in a dense, multi-tenant office building with significant interference and channel contention. Which advanced Wi-Fi features and strategies are MOST crucial for maximizing performance in this environment?",
      "options": [
        "Using only 2.4 GHz band with fixed channels and disabling channel scanning.",
        "Deploying a basic Wi-Fi network with minimal access points to reduce complexity.",
        "Implementing a high-density Wi-Fi network using 802.11ax (Wi-Fi 6/6E) with OFDMA, MU-MIMO, BSS Coloring, dynamic channel selection, and load balancing.",
        "Maximizing transmit power and using high-gain omnidirectional antennas on 2.4 GHz access points."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A high-density Wi-Fi network using advanced 802.11ax features, combined with dynamic channel selection and load balancing, is most effective in dense, multi-tenant environments.",
      "examTip": "Advanced features like OFDMA and MU-MIMO in 802.11ax, along with dynamic channel management, are key to optimizing Wi-Fi in dense office settings."
    },
    {
      "id": 62,
      "question": "Which of the following is a key benefit of 'Containerization' over traditional 'Hardware Virtualization' when deploying and managing applications?",
      "options": [
        "Stronger isolation between containers due to full OS virtualization.",
        "Reduced attack surface due to smaller container images and shared OS kernel.",
        "Simplified security management through centralized VM-based security policies.",
        "Enhanced visibility and control over containerized application dependencies."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Containerization reduces the attack surface by using smaller images and a shared OS kernel, minimizing unnecessary components.",
      "examTip": "The lean nature of container images contributes to a reduced attack surface compared to full VMs."
    },
    {
      "id": 63,
      "question": "A laser printer is producing prints with repeating 'spots' or 'voids' of missing toner in a regular pattern across the page. Which printer component is MOST likely causing these missing toner spots?",
      "options": [
        "Toner Cartridge (clogged toner outlet or metering blade issue)",
        "Fuser Assembly (roller surface damage causing toner repulsion)",
        "Imaging Drum (repeating surface defect or obstruction causing toner dropout)",
        "High-Voltage Power Supply (intermittent voltage drop affecting toner transfer)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A repeating surface defect or obstruction on the imaging drum can cause consistent voids of missing toner in prints.",
      "examTip": "Inspect the imaging drum for defects if you observe a regular pattern of missing toner spots."
    },
    {
      "id": 64,
      "question": "Which of the following is a BEST practice for securing user accounts against password reuse across different online services and applications?",
      "options": [
        "Using the same password for all online accounts for easy management.",
        "Disabling password managers to encourage users to memorize passwords.",
        "Educating users about the risks of password reuse and promoting the use of password managers to generate and store unique, strong passwords for each account.",
        "Storing passwords in a simple spreadsheet for personal record-keeping."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Educating users about the risks of password reuse and using password managers to generate unique passwords is the best practice to prevent credential compromise across services.",
      "examTip": "Encourage the use of password managers and educate users on the dangers of password reuse."
    },
    {
      "id": 65,
      "question": "Which of the following TCP ports is used by Microsoft Active Directory Kerberos Key Distribution Center (KDC) for initial authentication requests, and is often targeted in Kerberos 'Golden Ticket' attacks?",
      "options": [
        "Port 88 (Kerberos)",
        "Port 464 (kpasswd/changepw)",
        "Port 749 (Kerberos v5)",
        "Port 3268 (GCoverSSL)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Port 88 is the standard port for Kerberos authentication and is a common target in Golden Ticket attacks.",
      "examTip": "Port 88 (Kerberos) is critical for authentication in Active Directory and is often targeted in advanced attacks like Golden Tickets."
    },
    {
      "id": 66,
      "question": "A technician is asked to implement 'link aggregation control protocol' (LACP) on a managed switch. What is the primary advantage of using LACP over static link aggregation?",
      "options": [
        "LACP provides higher maximum bandwidth compared to static aggregation.",
        "LACP automatically detects and configures link aggregation, providing dynamic link management and failover.",
        "LACP simplifies network configuration by eliminating the need for manual link configuration.",
        "LACP reduces network latency by optimizing traffic distribution across aggregated links."
      ],
      "correctAnswerIndex": 1,
      "explanation": "LACP automatically detects and configures link aggregation, offering dynamic management and failover capabilities.",
      "examTip": "LACP offers dynamic, automatic link aggregation management, making it more resilient than static configurations."
    },
    {
      "id": 67,
      "question": "Which of the following is a key security challenge associated with 'serverless computing' or 'Function-as-a-Service (FaaS)' cloud models in terms of access control and permissions management?",
      "options": [
        "Simplified access control due to provider-managed security.",
        "Increased granularity and complexity in managing permissions for individual functions and event sources.",
        "Lack of access control options as serverless functions are inherently publicly accessible.",
        "Reduced complexity in auditing and monitoring access due to centralized function execution logs."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Serverless computing requires managing permissions for a large number of individual functions and event sources, increasing complexity.",
      "examTip": "Be prepared for granular and complex permission management in serverless architectures."
    },

    /* REPLACED with PBQ style question */
    {
      "id": 68,
      "question": "Performance-Based Question (PBQ): A user is building a custom CAD workstation that must handle complex 3D modeling. They have four possible configurations with near-identical specs. Which configuration is BEST for this specialized workload?",
      "options": [
        "1) High-core-count CPU, entry-level GPU, 16 GB RAM, standard HDD, mid-range PSU.",
        "2) Balanced quad-core CPU, standard GPU, 8 GB RAM, high-speed SSD, low-watt PSU.",
        "3) High-frequency CPU with fewer cores, professional-grade GPU (Workstation card), 32 GB RAM, SSD storage, quality PSU.",
        "4) Mid-range CPU, integrated GPU, 64 GB RAM, SATA HDD, generic PSU."
      ],
      "correctAnswerIndex": 2,
      "explanation": "For CAD and 3D modeling, a high-frequency CPU helps with single-thread performance, but a workstation-class GPU (e.g., NVIDIA Quadro or AMD Radeon Pro) is also crucial. Large RAM (32 GB or more) and fast SSD storage significantly reduce bottlenecks. A stable, quality PSU is important for reliability. High-core-count consumer CPUs with weak GPUs won’t optimize 3D tasks, and integrated graphics would be insufficient for complex modeling.",
      "examTip": "CAD work relies on both CPU speed (often single-threaded tasks) and professional GPU capabilities for accurate rendering. Memory and fast storage also matter for large project files."
    },

    {
      "id": 69,
      "question": "Which of the following is a BEST practice for securing user accounts against credential theft attacks, such as phishing or malware-based credential harvesting?",
      "options": [
        "Storing passwords in plain text databases.",
        "Disabling multi-factor authentication (MFA).",
        "Implementing multi-factor authentication (MFA), anti-phishing training, and endpoint security measures.",
        "Relying solely on complex password policies without additional security layers."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Implementing MFA, along with user training and endpoint security, significantly reduces the risk of credential theft.",
      "examTip": "Layered security including MFA, user education, and endpoint protection is key to defending against credential theft."
    },
    {
      "id": 70,
      "question": "Which of the following TCP ports is used by Microsoft Active Directory Kerberos Administration protocol (kadmin) for remote administration of the Kerberos KDC (Key Distribution Center)?",
      "options": [
        "Port 88",
        "Port 464 (kpasswd/changepw)",
        "Port 749 (kadmin/administration)",
        "Port 3269 (GCoverSSL)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Port 749 is used for Kerberos administration (kadmin) for remote management of the KDC.",
      "examTip": "For remote Kerberos administration, port 749 is the designated port."
    },
    {
      "id": 71,
      "question": "A technician is asked to design a high-density Wi-Fi network for a large outdoor stadium requiring very high capacity and density to support tens of thousands of concurrent users. Which Wi-Fi technology and advanced features are MOST critical for ensuring network performance and stability under extreme load?",
      "options": [
        "802.11b access points with omnidirectional antennas.",
        "802.11g access points with channel bonding in the 2.4 GHz band.",
        "802.11ax (Wi-Fi 6 or Wi-Fi 6E) with high-density features like OFDMA, MU-MIMO, BSS Coloring, and 160 MHz channels in the 5 GHz and 6 GHz bands, combined with advanced cell planning and load balancing.",
        "Standard 802.11ac (Wi-Fi 5) access points with increased transmit power and high-gain omnidirectional antennas."
      ],
      "correctAnswerIndex": 2,
      "explanation": "802.11ax (Wi-Fi 6/6E) with advanced high-density features is specifically designed to handle extreme loads in environments like large outdoor stadiums.",
      "examTip": "For stadium-scale Wi-Fi, utilize the full suite of advanced 802.11ax features combined with expert network planning to support massive concurrent usage."
    },

    /* REPLACED with PBQ style question */
    {
      "id": 72,
      "question": "Performance-Based Question (PBQ): A PC is repeatedly blue-screening with minimal useful data in logs. The user also notes random file corruption. Arrange the following steps in the CORRECT order to systematically identify the failing component.",
      "options": [
        "1) Reinstall the OS immediately, 2) Swap in a different power supply, 3) Use a known-good GPU, 4) Validate RAM with a diagnostic tool.",
        "1) Disconnect all peripherals, 2) Perform a clean boot, 3) Update BIOS, 4) Run a CPU stress test, 5) Reseat all cables.",
        "1) Create a bootable diagnostic USB, 2) Run memory tests (e.g., MemTest86), 3) Check drive health via SMART or chkdsk, 4) If inconclusive, test PSU voltages or replace hardware sequentially.",
        "1) Boot into Safe Mode, 2) Disable the antivirus, 3) Update all device drivers, 4) Restore user data from backup, 5) Re-partition the drive if issues persist."
      ],
      "correctAnswerIndex": 2,
      "explanation": "When diagnosing BSODs and random file corruption, it’s best to gather hardware diagnostics first: memory tests, then disk checks, then methodical hardware elimination (PSU, etc.). Reinstalling the OS or disabling antivirus early won’t isolate hardware failures. Testing each piece systematically—especially RAM and storage—is essential before concluding it’s a software issue.",
      "examTip": "Start with structured diagnostic steps (RAM, disk, PSU) before reformatting or updating drivers. Random file corruption often points to failing hardware or unstable power."
    },

    {
      "id": 73,
      "question": "A laser printer is producing prints with a consistent 'smear' or 'blur' that is most pronounced at the bottom of the page and gradually fades towards the top. Which printer component is MOST likely causing this bottom-heavy smear defect?",
      "options": [
        "Toner Cartridge (overfilling or toner leakage)",
        "Fuser Assembly (uneven heating or pressure, worse at output end)",
        "Imaging Drum (contamination accumulating at the bottom edge)",
        "Cleaning Blade or Wiper Blade (ineffective cleaning at the bottom edge)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "An uneven fuser assembly, particularly at the output end, can result in a bottom-heavy smear as toner is not properly fused.",
      "examTip": "Inspect the fuser assembly for uneven pressure or temperature issues if smearing is more pronounced at the bottom of the page."
    },

    /* REPLACED with PBQ style question */
    {
      "id": 74,
      "question": "Performance-Based Question (PBQ): You are building a virtualization host for a small business lab. The manager wants maximum concurrent virtual machines with minimal slowdown. Which of the following configurations is MOST appropriate?",
      "options": [
        "1) Single-core CPU at high frequency, 8 GB RAM, basic RAID 1 HDD, integrated NIC.",
        "2) Multiple-core CPU with virtualization extensions, 64 GB ECC RAM, RAID 10 SSD array, dual NICs.",
        "3) Dual-core CPU, 16 GB RAM, single SSD, dedicated sound card, one NIC.",
        "4) GPU-centric build with minimal RAM and a basic HDD, focusing on high clock speed over core count."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Virtualization hosts thrive on large amounts of RAM, multiple CPU cores with hardware virtualization extensions, and fast storage (SSD-based RAID). Dual NICs help with network throughput or failover. Sound cards or single-core CPUs have little benefit for virtualization. ECC RAM adds reliability in a virtualized environment.",
      "examTip": "Prioritize CPU cores, substantial RAM, and robust storage for virtualization. Features like ECC RAM and multiple NICs further optimize stability and performance."
    },

    {
      "id": 75,
      "question": "Which of the following TCP ports is used by Microsoft Active Directory Global Catalog for LDAP queries to retrieve objects from the entire forest, and is often used for initial domain searches?",
      "options": [
        "Port 389",
        "Port 636",
        "Port 3268",
        "Port 3269"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Port 3268 is used for non-secure Global Catalog LDAP queries to retrieve forest-wide objects.",
      "examTip": "Use port 3268 for Global Catalog queries when encryption is not mandated."
    },
    {
      "id": 76,
      "question": "A technician is optimizing Wi-Fi performance in a dense, multi-tenant office building with significant interference and channel contention. Which advanced Wi-Fi features and strategies are MOST crucial for maximizing performance in this environment?",
      "options": [
        "Using only 2.4 GHz band with fixed channels and disabling channel scanning.",
        "Deploying a basic Wi-Fi network with minimal access points to reduce complexity.",
        "Implementing a high-density Wi-Fi network using 802.11ax (Wi-Fi 6/6E) with OFDMA, MU-MIMO, BSS Coloring, dynamic channel selection, and load balancing.",
        "Maximizing transmit power and using high-gain omnidirectional antennas on 2.4 GHz access points."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A high-density Wi-Fi network using advanced 802.11ax features, combined with dynamic channel selection and load balancing, is most effective in dense, multi-tenant environments.",
      "examTip": "Advanced features like OFDMA and MU-MIMO in 802.11ax, along with dynamic channel management, are key to optimizing Wi-Fi in dense office settings."
    },
    {
      "id": 77,
      "question": "Which of the following is a key benefit of 'Containerization' over traditional 'Hardware Virtualization' when deploying and managing applications?",
      "options": [
        "Stronger isolation between containers due to full OS virtualization.",
        "Reduced attack surface due to smaller container images and shared OS kernel.",
        "Simplified security management through centralized VM-based security policies.",
        "Enhanced visibility and control over containerized application dependencies."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Containerization reduces the attack surface by using smaller images and a shared OS kernel, minimizing unnecessary components.",
      "examTip": "The lean nature of container images contributes to a reduced attack surface compared to full VMs."
    },
    {
      "id": 78,
      "question": "A laser printer is producing prints with repeating 'spots' or 'voids' of missing toner in a regular pattern across the page. Which printer component is MOST likely causing these missing toner spots?",
      "options": [
        "Toner Cartridge (clogged toner outlet or metering blade issue)",
        "Fuser Assembly (roller surface damage causing toner repulsion)",
        "Imaging Drum (repeating surface defect or obstruction causing toner dropout)",
        "High-Voltage Power Supply (intermittent voltage drop affecting toner transfer)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A repeating surface defect or obstruction on the imaging drum can cause consistent voids of missing toner in prints.",
      "examTip": "Inspect the imaging drum for defects if you observe a regular pattern of missing toner spots."
    },

    /* REPLACED with PBQ style question */
    {
      "id": 79,
      "question": "Performance-Based Question (PBQ): A user cannot connect to the company Wi-Fi despite seeing the SSID. They insist the password is correct. Place the following diagnostic actions in the MOST logical order to find and resolve the issue.",
      "options": [
        "1) Forget the network and re-enter credentials, 2) Check Wi-Fi adapter driver version, 3) Temporarily disable antivirus, 4) Replace the router’s firmware, 5) Verify the correct wireless profile settings.",
        "1) Modify the AP to use WPA instead of WPA2, 2) Run Windows Update, 3) Check an alternate SSID, 4) Reboot the user's device, 5) Reset the user’s password in Active Directory.",
        "1) Check if other devices connect successfully, 2) Compare the user’s Wi-Fi security settings with the official standard, 3) Update or reinstall the Wi-Fi driver if needed, 4) Remove and re-add the SSID profile, 5) Try a different frequency band if supported.",
        "1) Immediately replace the user’s laptop, 2) Force 802.11b mode on the AP, 3) Reset the user’s domain account password, 4) Switch the user to a guest network to confirm it works, 5) Hardcode the IP address."
      ],
      "correctAnswerIndex": 2,
      "explanation": "First, verify if the issue is user-specific by checking other devices and ensuring the correct security standard (e.g., WPA2 or WPA3). If drivers are outdated, update them. Then remove/re-add the SSID profile to eliminate corrupted settings. Finally, testing a different frequency band can reveal interference or compatibility issues. Replacing hardware or changing router firmware are last-resort steps and less logical as an initial approach.",
      "examTip": "Always check if other clients can connect before suspecting the infrastructure. Then confirm your Wi-Fi settings match the network’s security requirements and that drivers are current."
    },

    {
      "id": 80,
      "question": "Which of the following TCP ports is used by Microsoft Active Directory Kerberos Key Distribution Center (KDC) for initial authentication requests, and is often targeted in Kerberos 'Golden Ticket' attacks?",
      "options": [
        "Port 88 (Kerberos)",
        "Port 464 (kpasswd/changepw)",
        "Port 749 (Kerberos v5)",
        "Port 3268 (GCoverSSL)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Port 88 is the standard port for Kerberos authentication and is a common target in Golden Ticket attacks.",
      "examTip": "Port 88 (Kerberos) is critical for authentication in Active Directory and is often targeted in advanced attacks like Golden Tickets."
    },
    {
      "id": 81,
      "question": "A traveling sales manager reports that whenever they plug their laptop into an older conference room's power outlet, performance slows dramatically. The laptop runs normally when on battery or with a modern AC adapter elsewhere. Which is the MOST likely cause?",
      "options": [
        "Damaged CPU thermal paste leading to random thermal shutdowns.",
        "Corrupted operating system halting CPU-intensive processes.",
        "An underpowered or incorrect-wattage power adapter triggering CPU throttling.",
        "A faulty memory module causing slow paging."
      ],
      "correctAnswerIndex": 2,
      "explanation": "If the laptop’s AC adapter cannot supply sufficient wattage (or is incompatible), the system firmware may throttle the CPU to prevent power draw that exceeds what the adapter can provide. This manifests as severe performance slowdowns when plugged into that specific power source, yet normal operation on battery or with a proper adapter.",
      "examTip": "Always match laptop power adapters to the required wattage/voltage. An inadequate adapter can cause CPU/GPU throttling or unexpected shutdowns."
    },
    {
      "id": 82,
      "question": "Which of the following accurately distinguishes NVMe from older AHCI-based SSD protocols?",
      "options": [
        "NVMe relies on parallel SCSI commands, whereas AHCI uses a single queue model.",
        "NVMe is designed for mechanical HDDs, while AHCI handles flash storage.",
        "NVMe supports significantly higher queue depths and lower latency, leveraging PCIe for greater performance.",
        "AHCI is only compatible with PCIe-based M.2 drives, while NVMe focuses on SATA interfaces."
      ],
      "correctAnswerIndex": 2,
      "explanation": "NVMe (Non-Volatile Memory Express) is built specifically for flash storage, leveraging PCIe’s high bandwidth and supporting deep command queues for lower latency. AHCI is an older interface originally designed for spinning drives, limiting queue depth and throughput. NVMe dramatically improves performance for modern SSDs.",
      "examTip": "If you see a PCIe-based SSD with extremely high throughput, it’s almost certainly NVMe rather than AHCI."
    },
    {
      "id": 83,
      "question": "A user just replaced their M.2 NVMe SSD but finds the drive is not detected in the UEFI BIOS or Windows Setup. The old M.2 SATA SSD in the same slot worked fine. Which issue is MOST likely?",
      "options": [
        "The M.2 slot only supports SATA-based M.2 drives and does not support NVMe protocol.",
        "The user forgot to partition the new SSD in Disk Management.",
        "The drive is physically damaged and must be RMA'd immediately.",
        "Windows Setup requires a specialized network driver before it can detect NVMe drives."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Many motherboards have M.2 slots that support SATA M.2 drives only, or require a specific slot for NVMe. If the motherboard does not support NVMe on that slot, an NVMe drive won’t be recognized. This is more likely than a hardware failure if the old SATA M.2 worked fine.",
      "examTip": "Always check motherboard compatibility: some M.2 slots are keyed for SATA only, some for NVMe, and some support both (M.2 ‘combo’ slots)."
    },
    {
      "id": 84,
      "question": "Which bus interface is MOST commonly used by modern laptop expansion cards such as Wi-Fi adapters or cellular modems, providing both PCIe and USB signals in one slot?",
      "options": [
        "PCI Express Mini Card (Mini PCIe)",
        "ExpressCard",
        "CardBus",
        "M.2 (NGFF)"
      ],
      "correctAnswerIndex": 3,
      "explanation": "M.2 (NGFF) slots are widely used in modern laptops, supporting various card types (like Wi-Fi, SSDs, cellular modems). The M.2 interface can carry PCIe and/or USB signals, enabling multiple device classes in one form factor. Mini PCIe and ExpressCard are older, and CardBus is legacy.",
      "examTip": "M.2 is the standard go-to interface in today’s ultrabooks and laptops for both storage and connectivity modules."
    },
    {
      "id": 85,
      "question": "Which of the following TCP ports is used by Microsoft Active Directory Kerberos Administration protocol (kadmin) for remote administration of the Kerberos KDC (Key Distribution Center)?",
      "options": [
        "Port 88",
        "Port 464 (kpasswd/changepw)",
        "Port 749 (kadmin/administration)",
        "Port 3269 (GCoverSSL)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Port 749 is used for Kerberos administration (kadmin) for remote management of the KDC.",
      "examTip": "For remote Kerberos administration, port 749 is the designated port."
    },
    {
      "id": 86,
      "question": "After replacing a motherboard in a custom-built PC, the user reports that the system now fails to POST. The CPU fan spins momentarily, then stops, and the system restarts in a loop. Which scenario is MOST likely to blame?",
      "options": [
        "The power supply wattage is too high and triggering protective shutdowns.",
        "An incompatible CPU microarchitecture for the replacement motherboard’s chipset.",
        "A faulty SATA cable that prevents the BIOS from detecting the boot drive.",
        "Insufficient RAM installed for the new motherboard’s requirements (minimum 32 GB)."
      ],
      "correctAnswerIndex": 1,
      "explanation": "If the new motherboard’s chipset or BIOS doesn’t support the CPU architecture, the system may power cycle without posting. This is more common than excessive PSU wattage or a single bad SATA cable causing a complete inability to POST. The notion that 32 GB is mandatory is unrealistic for typical boards; CPU incompatibility is the prime suspect.",
      "examTip": "Always verify CPU compatibility with the new motherboard’s socket and BIOS revision before finalizing a replacement."
    },

    /* REPLACED with PBQ style question */
    {
      "id": 87,
      "question": "Performance-Based Question (PBQ): A user complains that a multi-function printer (MFP) is not scanning to email, even though printing and copying work fine. Select the BEST step-by-step approach to diagnose and fix the issue.",
      "options": [
        "1) Reinstall printer drivers on all workstations, 2) Update firmware, 3) Enable spooler logging, 4) Test scanning after each step.",
        "1) Verify MFP network connectivity and DNS, 2) Check MFP’s SMTP settings (server address, authentication), 3) Validate correct email credentials or port, 4) Send a test scan to email.",
        "1) Power cycle the entire office switch, 2) Disable scan-to-folder on the MFP, 3) Install a second network card in the MFP, 4) Use static IP addressing.",
        "1) Configure the MFP for direct USB scanning, 2) Install a third-party scanning utility, 3) Force static DNS on each client, 4) Restart all user sessions."
      ],
      "correctAnswerIndex": 1,
      "explanation": "When troubleshooting scan-to-email, first confirm the MFP has proper network access and can resolve the mail server (DNS). Then verify SMTP server settings, authentication method, and correct email credentials. A test scan helps confirm functionality. Reinstalling drivers or forcibly changing network hardware is excessive if the core network and print functions already work.",
      "examTip": "Focus on the scanning feature’s specific requirements—SMTP configuration, DNS resolution, and valid credentials—before mass reinstallations or reboots."
    },

    {
      "id": 88,
      "question": "A laser printer is producing prints with a consistent 'smear' or 'blur' that is most pronounced at the bottom of the page and gradually fades towards the top. Which printer component is MOST likely causing this bottom-heavy smear defect?",
      "options": [
        "Toner Cartridge (overfilling or toner leakage)",
        "Fuser Assembly (uneven heating or pressure, worse at output end)",
        "Imaging Drum (contamination accumulating at the bottom edge)",
        "Cleaning Blade or Wiper Blade (ineffective cleaning at the bottom edge)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "An uneven fuser assembly, particularly at the output end, can result in a bottom-heavy smear as toner is not properly fused.",
      "examTip": "Inspect the fuser assembly for uneven pressure or temperature issues if smearing is more pronounced at the bottom of the page."
    },

    /* REPLACED with PBQ style question */
    {
      "id": 89,
      "question": "Performance-Based Question (PBQ): A new technician must replace a power supply in a desktop PC. Which set of ESD-prevention steps is the MOST accurate and safe sequence for performing this upgrade?",
      "options": [
        "1) Power off PC, 2) Touch a metal object, 3) Put on gloves, 4) Remove PSU, 5) Attach anti-static wrist strap after removing PSU.",
        "1) Leave the PC on for grounding, 2) Clip the anti-static strap to a painted surface, 3) Replace PSU, 4) Turn off power when finished.",
        "1) Shut down and unplug the PC, 2) Connect the anti-static wrist strap to an unpainted chassis area, 3) Discharge yourself on a metal part of the case, 4) Remove and replace PSU, 5) Reassemble carefully.",
        "1) Unplug the PC, 2) Wear rubber-soled shoes on carpet, 3) Quickly swap PSU without touching any metal parts, 4) Reboot the system to test."
      ],
      "correctAnswerIndex": 2,
      "explanation": "For proper ESD prevention: power off and unplug the system, attach the wrist strap to a bare metal part of the chassis, and periodically ground yourself. Then remove and replace the PSU. Wearing rubber-soled shoes on carpet or waiting to attach the strap until after you remove components significantly raises ESD risk.",
      "examTip": "Correct ESD protocol: remove power, ground yourself with a wrist strap to unpainted metal, handle components by edges, and recheck for static frequently."
    },

    {
      "id": 90,
      "question": "Which of the following TCP ports is used by Microsoft Active Directory Global Catalog for LDAP queries to retrieve objects from the entire forest, and is often used for initial domain searches?",
      "options": [
        "Port 389",
        "Port 636",
        "Port 3268",
        "Port 3269"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Port 3268 is used for non-secure Global Catalog LDAP queries to retrieve forest-wide objects.",
      "examTip": "Use port 3268 for Global Catalog queries when encryption is not mandated."
    },
    {
      "id": 91,
      "question": "A technician is optimizing Wi-Fi performance in a dense, multi-tenant office building with significant interference and channel contention. Which advanced Wi-Fi features and strategies are MOST crucial for maximizing performance in this environment?",
      "options": [
        "Using only 2.4 GHz band with fixed channels and disabling channel scanning.",
        "Deploying a basic Wi-Fi network with minimal access points to reduce complexity.",
        "Implementing a high-density Wi-Fi network using 802.11ax (Wi-Fi 6/6E) with OFDMA, MU-MIMO, BSS Coloring, dynamic channel selection, and load balancing.",
        "Maximizing transmit power and using high-gain omnidirectional antennas on 2.4 GHz access points."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A high-density Wi-Fi network using advanced 802.11ax features, combined with dynamic channel selection and load balancing, is most effective in dense, multi-tenant environments.",
      "examTip": "Advanced features like OFDMA and MU-MIMO in 802.11ax, along with dynamic channel management, are key to optimizing Wi-Fi in dense office settings."
    },
    {
      "id": 92,
      "question": "Which of the following is a key benefit of 'Containerization' over traditional 'Hardware Virtualization' when deploying and managing applications?",
      "options": [
        "Stronger isolation between containers due to full OS virtualization.",
        "Reduced attack surface due to smaller container images and shared OS kernel.",
        "Simplified security management through centralized VM-based security policies.",
        "Enhanced visibility and control over containerized application dependencies."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Containerization reduces the attack surface by using smaller images and a shared OS kernel, minimizing unnecessary components.",
      "examTip": "The lean nature of container images contributes to a reduced attack surface compared to full VMs."
    },
    {
      "id": 93,
      "question": "A laser printer is producing prints with repeating 'spots' or 'voids' of missing toner in a regular pattern across the page. Which printer component is MOST likely causing these missing toner spots?",
      "options": [
        "Toner Cartridge (clogged toner outlet or metering blade issue)",
        "Fuser Assembly (roller surface damage causing toner repulsion)",
        "Imaging Drum (repeating surface defect or obstruction causing toner dropout)",
        "High-Voltage Power Supply (intermittent voltage drop affecting toner transfer)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A repeating surface defect or obstruction on the imaging drum can cause consistent voids of missing toner in prints.",
      "examTip": "Inspect the imaging drum for defects if you observe a regular pattern of missing toner spots."
    },

    /* REPLACED with PBQ style question */
    {
      "id": 94,
      "question": "Performance-Based Question (PBQ): A PC emits a series of beeps at startup but never displays video. The user suspects a hardware failure. Which sequence of checks is MOST appropriate to isolate the cause?",
      "options": [
        "1) Replace the CPU with a random spare, 2) Update chipset drivers, 3) Boot into Windows Safe Mode, 4) Reseat GPU if CPU swap fails.",
        "1) Note the beep code pattern, 2) Compare it to the motherboard’s POST beep references, 3) Reseat or replace the indicated component (GPU or RAM), 4) Clear CMOS if issue persists.",
        "1) Swap out the PSU for a higher wattage model, 2) Run MemTest86, 3) Boot from a Linux live USB, 4) Update the BIOS if memory passes.",
        "1) Check if the integrated NIC is lit, 2) Replace the system’s case fan, 3) Enter BIOS and enable performance mode, 4) Move the RAM to a different channel."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Most motherboards provide unique beep codes to signal hardware issues (common codes relate to RAM or GPU). Documenting the pattern, checking the motherboard reference, and reseating or replacing the offending component is the logical path. Clearing CMOS may help if the beep code is still ambiguous. Randomly replacing CPUs or NIC-based checks do not specifically address beep codes.",
      "examTip": "Always look up the specific beep code pattern in the motherboard’s manual. It often directs you exactly which component to troubleshoot (RAM, GPU, etc.)."
    },

    {
      "id": 95,
      "question": "Which of the following TCP ports is used by Microsoft Active Directory Kerberos Key Distribution Center (KDC) for initial authentication requests, and is often targeted in Kerberos 'Golden Ticket' attacks?",
      "options": [
        "Port 88 (Kerberos)",
        "Port 464 (kpasswd/changepw)",
        "Port 749 (Kerberos v5)",
        "Port 3268 (GCoverSSL)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Port 88 is the standard port for Kerberos authentication and is a common target in Golden Ticket attacks.",
      "examTip": "Port 88 (Kerberos) is critical for authentication in Active Directory and is often targeted in advanced attacks like Golden Tickets."
    },
    {
      "id": 96,
      "question": "A user replaced their lost OEM laptop charger with a cheap third-party adapter. Now the battery status shows 'plugged in, not charging,' and the system performance is throttled. Which explanation is MOST likely?",
      "options": [
        "The new adapter’s barrel connector includes an embedded GPU driver mismatch.",
        "The laptop’s battery is damaged due to ESD from the old charger cable.",
        "Manufacturer laptops often require an adapter ID signal that cheaper clones lack, causing the laptop to reject or limit power.",
        "Windows Update installed an incorrect AC adapter driver preventing charging."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Many laptop brands check for a proprietary signal or 'adapter ID' from the power brick. If it’s missing or invalid, the laptop may refuse to charge or may run at reduced performance to protect against damage. This commonly occurs with unapproved third-party adapters.",
      "examTip": "Always match OEM specs and ID requirements when replacing laptop power adapters. Unrecognized adapters may cause throttling or non-charging conditions."
    },
    {
      "id": 97,
      "question": "Which of the following Intel CPU sockets uses an LGA1151 layout and typically supports 6th to 9th generation Core processors, but is incompatible with AMD’s AM4 CPUs?",
      "options": [
        "Socket AM4",
        "Socket TR4",
        "Socket LGA1151",
        "Socket FM2+"
      ],
      "correctAnswerIndex": 2,
      "explanation": "LGA1151 is the Intel socket that fits many 6th to 9th gen Core CPUs. AMD uses AM4 for mainstream Ryzen processors, and TR4 for Threadripper. FM2+ is an older AMD socket. LGA stands for 'Land Grid Array,' typical of Intel designs.",
      "examTip": "Intel’s LGA1151 is distinct from AMD’s AM4. Always confirm socket compatibility before installing a CPU."
    },
    {
      "id": 98,
      "question": "A user reports that after a major Windows update, their desktop no longer produces any sound—even though Device Manager shows no errors. The headphone jack works correctly when booting into a Linux live USB. Which is the MOST likely fix?",
      "options": [
        "Replacing the motherboard’s audio codec chip for hardware-level faults.",
        "Enabling the SATA AHCI driver in the BIOS so Windows can detect the sound card.",
        "Reinstalling or updating the Windows audio driver and verifying the default playback device.",
        "Reseating the system’s front panel audio connector on the motherboard."
      ],
      "correctAnswerIndex": 2,
      "explanation": "If audio hardware is fine under a different OS, then a Windows driver or default device configuration problem is likely after the major update. Reinstalling audio drivers and ensuring the correct playback device is selected typically resolves the issue.",
      "examTip": "Always check the OS driver status and default device selection if hardware works fine in another operating system."
    },
    {
      "id": 99,
      "question": "Which of the following statements correctly compares a patch panel to individual keystone jacks for network cable management?",
      "options": [
        "Patch panels primarily provide wireless connectivity, whereas keystone jacks are used for DSL connections only.",
        "Patch panels aggregate multiple cable runs into one organized panel, while keystone jacks are singular connectors typically used in wall plates or modular panels.",
        "Keystone jacks must always be unshielded, while patch panels are only sold in shielded varieties.",
        "Patch panels are mandatory for fiber optics, and keystone jacks can handle copper cables exclusively."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A patch panel is a centralized termination point for multiple cable runs, providing an organized interface for interconnecting or rearranging cables. Keystone jacks are individual connectors that snap into wall plates or modular panels. They are often used together: keystones in the patch panel or at the wall outlet, forming a flexible system.",
      "examTip": "Patch panels offer cable organization and easy re-patching, whereas individual keystone jacks are discrete connectors for each run."
    },
    {
      "id": 100,
      "question": "A user connects a new 4K monitor to their older desktop’s integrated GPU, only to find it caps at 30 Hz refresh. They want 60 Hz at full 4K resolution for smoother animation. Which upgrade is MOST likely needed?",
      "options": [
        "An updated BIOS to unlock higher integrated GPU refresh rates.",
        "Replacing the motherboard with the same chipset revision but new onboard video.",
        "A discrete graphics card supporting 4K@60 Hz over HDMI 2.0 or DisplayPort.",
        "Installing faster DDR4 RAM for the integrated GPU to boost pixel clock speed."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Older integrated GPUs often limit 4K output to 30 Hz. A discrete GPU with HDMI 2.0 or DisplayPort 1.2+ is typically required for stable 4K@60 Hz. Simply updating the BIOS or using faster RAM rarely overcomes hardware bandwidth limitations of older integrated video.",
      "examTip": "When a user demands higher refresh rates at 4K, confirm the GPU and cable standards (HDMI 2.0/2.1 or DP 1.2+) support it."
    }
  ]
});
