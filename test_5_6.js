
O THEE ARE TESTS 5 AND 6



{
    "_id": {
      "$oid": "GENERATED_OBJECT_ID_TEST5_1"
    },
    "category": "aplus",
    "testId": 5,
    "testName": "A+ Practice Test #5 (Intermediate)",
    "xpPerCorrect": 10,
    "questions": [
      {
        "id": 1,
        "question": "A technician suspects a DNS cache poisoning attack on a workstation. Which command-line tool can be used to flush the DNS cache on a Windows system?",
        "options": [
          "ipconfig /renew",
          "ping -flushdns",
          "nslookup -flushcache",
          "ipconfig /flushdns"
        ],
        "correctAnswerIndex": 3,
        "explanation": "The command `ipconfig /flushdns` is used in Windows to flush the DNS resolver cache. This command clears out cached DNS entries, which can be helpful in resolving DNS cache poisoning or other DNS-related issues. `ipconfig /renew` renews DHCP leases, `ping` tests connectivity, and `nslookup` is for DNS queries, not cache flushing.",
        "examTip": "Remember `ipconfig /flushdns` for clearing the DNS cache in Windows. It's a quick fix for many DNS resolution problems and security concerns like cache poisoning."
      },
      {
        "id": 2,
        "question": "Which of the following RAID levels provides both fault tolerance and improved read performance, but at the cost of higher implementation complexity and requiring at least four drives?",
        "options": [
          "RAID 1",
          "RAID 5",
          "RAID 6",
          "RAID 10"
        ],
        "correctAnswerIndex": 3,
        "explanation": "RAID 10 (or RAID 1+0) provides both fault tolerance and improved read performance by combining mirroring (RAID 1) and striping (RAID 0). It requires at least four drives and is more complex to implement but offers a good balance of speed and redundancy. RAID 1 is mirroring only, RAID 5 and RAID 6 use parity for fault tolerance but don't inherently improve read performance as much as striping.",
        "examTip": "RAID 10 is the 'high-performance, high-redundancy' RAID level. It's faster than RAID 5/6 and more resilient than RAID 0/1, but also more expensive due to drive count."
      },
      {
        "id": 3,
        "question": "A technician is troubleshooting slow wireless network speeds in an office. Which tool is BEST suited for identifying Wi-Fi channel congestion and overlapping networks?",
        "options": [
          "Cable tester",
          "Toner probe",
          "Wi-Fi analyzer",
          "Multimeter"
        ],
        "correctAnswerIndex": 2,
        "explanation": "A Wi-Fi analyzer is BEST suited for identifying Wi-Fi channel congestion and overlapping networks. It can scan wireless frequencies, show channel usage, signal strength of different networks, and help identify optimal channels with less interference. Cable testers are for wired cables, toner probes trace cables, and multimeters are for electrical testing.",
        "examTip": "Wi-Fi analyzers are essential for wireless troubleshooting. They help you 'see' the wireless spectrum and identify interference and congestion issues."
      },
      {
        "id": 4,
        "question": "Which of the following is a security best practice for BIOS/UEFI firmware to prevent unauthorized boot access and physical tampering?",
        "options": [
          "Enabling Fast Boot.",
          "Disabling USB ports in BIOS.",
          "Setting a BIOS/UEFI administrator password.",
          "Enabling virtualization support."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Setting a BIOS/UEFI administrator password is a security best practice to prevent unauthorized changes to BIOS/UEFI settings and to control boot access. This password is required to enter BIOS setup, preventing unauthorized users from altering boot order or disabling security features. Fast Boot speeds up booting but doesn't enhance security. Disabling USB ports might limit data exfiltration but not boot access control directly. Virtualization support is for VMs, not BIOS security.",
        "examTip": "Always set a strong BIOS/UEFI administrator password to protect your system's firmware settings from unauthorized changes and boot access."
      },
      {
        "id": 5,
        "question": "A user wants to connect a legacy VGA monitor to a modern laptop that only has HDMI and USB-C ports. Which adapter type is required?",
        "options": [
          "HDMI to VGA adapter",
          "VGA to HDMI adapter",
          "USB-C to Ethernet adapter",
          "USB to PS/2 adapter"
        ],
        "correctAnswerIndex": 0,
        "explanation": "An HDMI to VGA adapter is required to connect a VGA monitor to a laptop with an HDMI port. The adapter needs to convert the digital HDMI signal to analog VGA. A VGA to HDMI adapter would be used in the reverse scenario (VGA source to HDMI display). USB-C to Ethernet is for network connectivity, and USB to PS/2 is for older peripherals.",
        "examTip": "HDMI to VGA adapters are common for connecting older VGA monitors to newer devices with digital video outputs like HDMI or DisplayPort. Remember the signal conversion direction."
      },
      {
        "id": 6,
        "question": "In the laser printing process, which step involves using heat and pressure to permanently bond the toner to the paper?",
        "options": [
          "Charging",
          "Exposing",
          "Developing",
          "Fusing"
        ],
        "correctAnswerIndex": 3,
        "explanation": "The 'fusing' step in the laser printing process uses heat and pressure to permanently bond the toner to the paper, making the image durable and smudge-proof. 'Charging' prepares the drum, 'exposing' creates the latent image, and 'developing' applies toner.",
        "examTip": "Fusing is the final 'fixing' step in laser printing. It uses heat and pressure to melt toner onto the paper, making the print permanent."
      },
      {
        "id": 7,
        "question": "A technician is configuring a wireless router and wants to implement MAC address filtering. What is the primary purpose of MAC address filtering?",
        "options": [
          "To encrypt wireless traffic.",
          "To control which devices are allowed to connect to the wireless network.",
          "To improve wireless signal strength.",
          "To prioritize network traffic for certain devices."
        ],
        "correctAnswerIndex": 1,
        "explanation": "MAC address filtering is used to control which devices are allowed to connect to a wireless network. By creating a list of allowed MAC addresses, only devices with those MAC addresses can connect, providing a basic layer of access control. It does not encrypt traffic (WPA2/3 does that), improve signal strength, or prioritize traffic (QoS does that).",
        "examTip": "MAC address filtering is a basic access control method for Wi-Fi, allowing you to restrict network access to devices with specific MAC addresses."
      },
      {
        "id": 8,
        "question": "Which cloud computing service model is BEST suited for providing users with access to software applications over the internet, typically on a subscription basis?",
        "options": [
          "IaaS (Infrastructure as a Service)",
          "PaaS (Platform as a Service)",
          "SaaS (Software as a Service)",
          "DaaS (Desktop as a Service)"
        ],
        "correctAnswerIndex": 2,
        "explanation": "SaaS (Software as a Service) is BEST suited for providing users with access to software applications over the internet, usually on a subscription basis. Examples include Microsoft 365 or Google Workspace. IaaS is about infrastructure, PaaS for development platforms, and DaaS for virtual desktops.",
        "examTip": "SaaS is all about software applications delivered over the internet. Think of everyday cloud apps like Gmail, Salesforce, or Dropbox."
      },
      {
        "id": 9,
        "question": "A computer fails to boot and displays a 'No Bootable Device Found' error message. Which hardware component is the MOST likely to be causing this issue?",
        "options": [
          "RAM module",
          "CPU",
          "Hard Disk Drive (HDD) or Solid State Drive (SSD)",
          "Network Interface Card (NIC)"
        ],
        "correctAnswerIndex": 2,
        "explanation": "A 'No Bootable Device Found' error message MOST likely indicates an issue with the Hard Disk Drive (HDD) or Solid State Drive (SSD), as these are where the operating system and boot files are stored. If the system cannot access or find a bootable partition on these drives, it will display this error. While other components can cause boot issues, storage drives are the direct source of bootable OS.",
        "examTip": "'No Bootable Device Found' is a classic storage drive error. Check your hard drive or SSD first when troubleshooting this error message."
      },
      {
        "id": 10,
        "question": "Which of the following is a valid IPv6 link-local address?",
        "options": [
          "192.168.1.1",
          "10.0.0.1",
          "FE80::1234:5678:9ABC:DEF0",
          "2001:db8::1"
        ],
        "correctAnswerIndex": 2,
        "explanation": "FE80::1234:5678:9ABC:DEF0 is a valid IPv6 link-local address. IPv6 link-local addresses always start with 'FE80::' and are used for communication within the local network segment only. 192.168.1.1 and 10.0.0.1 are private IPv4, and 2001:db8::1 is a global unicast IPv6 address (example prefix for documentation).",
        "examTip": "IPv6 link-local addresses always start with 'FE80::'. They are for local network communication only and are not routable on the internet."
      },
      {
        "id": 11,
        "question": "When replacing a laptop screen, what is a critical step to ensure safety and prevent damage during the process?",
        "options": [
          "Disconnect the AC adapter only.",
          "Remove the CMOS battery.",
          "Disconnect the battery from the motherboard.",
          "Discharge static electricity by touching the metal case."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Disconnecting the battery from the motherboard is a critical step to ensure safety and prevent damage when replacing a laptop screen. This eliminates power flow to the laptop and reduces the risk of short circuits or electrical damage during disassembly and reconnection. Simply disconnecting the AC adapter might not fully remove power if the battery is still connected. CMOS battery removal and static discharge are good practices but less critical than disconnecting the main battery for screen replacement.",
        "examTip": "Always disconnect the laptop battery before working on internal components, especially the screen. This prevents shorts and electrical damage."
      },
      {
        "id": 12,
        "question": "Which of the following protocols is used for network time synchronization, ensuring devices on a network have accurate time settings?",
        "options": [
          "SNMP (Simple Network Management Protocol)",
          "SMTP (Simple Mail Transfer Protocol)",
          "NTP (Network Time Protocol)",
          "DNS (Domain Name System)"
        ],
        "correctAnswerIndex": 2,
        "explanation": "NTP (Network Time Protocol) is used for network time synchronization, ensuring devices on a network have accurate time settings. Accurate time is important for logging, security, and various applications. SNMP is for network management, SMTP for email sending, and DNS for name resolution.",
        "examTip": "NTP (Network Time Protocol) is essential for keeping time synchronized across a network. Accurate time is important for many network operations and security."
      },
      {
        "id": 13,
        "question": "Which type of display technology is known for its ability to produce curved screens and is commonly used in high-end curved TVs and monitors?",
        "options": [
          "TN (Twisted Nematic)",
          "IPS (In-Plane Switching)",
          "VA (Vertical Alignment)",
          "CRT (Cathode Ray Tube)"
        ],
        "correctAnswerIndex": 2,
        "explanation": "VA (Vertical Alignment) display technology is known for its ability to produce curved screens and is commonly used in curved TVs and monitors. VA panels can be manufactured in curved shapes more readily than IPS or TN panels while maintaining good contrast and viewing angles. OLEDs can also be curved, but VA is more typical for curved LCD screens. CRTs are bulky and not used for curved flat-panel displays.",
        "examTip": "VA panels are often used for curved screens in TVs and monitors due to their flexibility in manufacturing and good balance of display characteristics."
      },
      {
        "id": 14,
        "question": "What is the purpose of a 'Hardware Security Module' (HSM)?",
        "options": [
          "To manage network firewall rules.",
          "To securely store and manage cryptographic keys.",
          "To provide antivirus protection.",
          "To manage user accounts and permissions."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A Hardware Security Module (HSM) is a dedicated hardware device used to securely store and manage cryptographic keys. HSMs provide a tamper-resistant environment for sensitive cryptographic operations, enhancing security for encryption, digital signatures, and authentication. Firewalls manage network security rules, antivirus protects against malware, and user account management is handled by directory services or operating systems.",
        "examTip": "HSMs are specialized hardware for highly secure key management. They are used in scenarios requiring strong cryptographic security, like PKI and financial transactions."
      },
      {
        "id": 15,
        "question": "A technician is tasked with setting up a VLAN (Virtual LAN) on a managed switch. Which protocol is used to tag VLAN traffic on trunk ports?",
        "options": [
          "IPsec (Internet Protocol Security)",
          "802.1Q",
          "DHCP (Dynamic Host Configuration Protocol)",
          "DNS (Domain Name System)"
        ],
        "correctAnswerIndex": 1,
        "explanation": "802.1Q is the IEEE standard protocol used to tag VLAN traffic on trunk ports. 802.1Q tagging adds VLAN identifiers to Ethernet frames, allowing switches to differentiate and forward traffic belonging to different VLANs over the same physical link (trunk port). IPsec is for VPN encryption, DHCP for IP assignment, and DNS for name resolution.",
        "examTip": "802.1Q tagging is essential for VLAN trunking. It's how switches know which VLAN traffic belongs to when using trunk ports."
      },
      {
        "id": 16,
        "question": "Which of the following memory types is Error Correcting Code (ECC) RAM primarily designed to detect and correct?",
        "options": [
          "Overheating errors",
          "Power supply fluctuations",
          "Soft errors (random bit flips)",
          "Physical damage to memory modules"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Error Correcting Code (ECC) RAM is primarily designed to detect and correct 'soft errors', which are random bit flips or data corruption caused by background radiation or electrical noise. ECC RAM is highly effective at mitigating these types of errors, which are more common in server environments. It's not primarily designed for overheating, power issues, or physical damage, though it can improve system stability under various conditions.",
        "examTip": "ECC RAM is all about correcting 'soft errors' – random bit flips caused by environmental factors. It's crucial for data integrity in servers and critical systems."
      },
      {
        "id": 17,
        "question": "A user reports slow internet browsing speeds, and a technician suspects a proxy server issue. Which TCP port is typically used by proxy servers for HTTP traffic?",
        "options": [
          "Port 21",
          "Port 80",
          "Port 3128 or 8080",
          "Port 443"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Port 3128 or 8080 are commonly used TCP ports for HTTP proxy servers. While proxies can sometimes use port 80 (HTTP), ports 3128 and 8080 are more conventionally associated with proxy server configurations. Port 21 is for FTP, and Port 443 for HTTPS (though proxies can handle HTTPS as well).",
        "examTip": "Proxy servers commonly use ports 3128 and 8080 for HTTP traffic. Check these ports when troubleshooting proxy-related browsing issues."
      },
      {
        "id": 18,
        "question": "Which of the following display technologies is self-emissive, meaning it does not require a backlight to produce images?",
        "options": [
          "LCD (Liquid Crystal Display)",
          "LED-backlit LCD",
          "Plasma",
          "OLED (Organic Light Emitting Diode)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "OLED (Organic Light Emitting Diode) is self-emissive display technology. OLED pixels emit their own light, meaning they do not require a backlight to produce images, unlike LCD and LED-backlit LCDs. Plasma is also self-emissive but uses a different technology.",
        "examTip": "OLEDs are self-emissive. Each pixel produces its own light, leading to excellent black levels and contrast, and eliminating the need for a backlight."
      },
      {
        "id": 19,
        "question": "What is the purpose of a 'Hardware Security Module' (HSM)?",
        "options": [
          "To manage network firewall rules.",
          "To securely store and manage cryptographic keys.",
          "To provide antivirus protection.",
          "To manage user accounts and permissions."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A Hardware Security Module (HSM) is a dedicated hardware device used to securely store and manage cryptographic keys. HSMs provide a tamper-resistant environment for sensitive cryptographic operations, enhancing security for encryption, digital signatures, and authentication. Firewalls manage network security rules, antivirus protects against malware, and user account management is handled by directory services or operating systems.",
        "examTip": "HSMs are specialized hardware for highly secure key management. They are used in scenarios requiring strong cryptographic security, like PKI and financial transactions."
      },
      {
        "id": 20,
        "question": "A technician is asked to implement port security on a managed switch. Which of the following is a common port security feature?",
        "options": [
          "MAC address filtering.",
          "Traffic shaping.",
          "VLAN tagging.",
          "Quality of Service (QoS)."
        ],
        "correctAnswerIndex": 0,
        "explanation": "MAC address filtering is a common port security feature on managed switches. Port security often involves limiting which MAC addresses are allowed to send traffic through a specific switch port, enhancing security by preventing unauthorized devices from connecting. Traffic shaping and QoS are for bandwidth management, and VLAN tagging for network segmentation.",
        "examTip": "Port security often includes MAC address filtering. It's a way to control which devices can connect to specific switch ports based on their MAC addresses."
      },
      {
        "id": 21,
        "question": "Which of the following memory types is typically used for system BIOS or UEFI firmware storage?",
        "options": [
          "DDR4 RAM",
          "SDRAM",
          "SRAM",
          "Flash ROM (Read-Only Memory)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "Flash ROM (Read-Only Memory) is typically used for storing system BIOS or UEFI firmware. Flash ROM is non-volatile and can be electrically erased and reprogrammed, allowing for BIOS/UEFI updates. DDR4 RAM, SDRAM, and SRAM are volatile memory types used for system memory and cache, not firmware storage.",
        "examTip": "BIOS/UEFI firmware is stored in Flash ROM because it needs to be non-volatile (retain data without power) and updatable."
      },
      {
        "id": 22,
        "question": "A user reports that their internet connection is slow, and they suspect their wireless network is being used by unauthorized users. Which security measure can BEST help identify and potentially block unauthorized devices from accessing their Wi-Fi network?",
        "options": [
          "Enabling WEP encryption.",
          "Using MAC address filtering.",
          "Hiding the SSID (Service Set Identifier).",
          "Implementing port forwarding."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Using MAC address filtering can BEST help identify and potentially block unauthorized devices from accessing a Wi-Fi network. By monitoring connected MAC addresses and implementing a whitelist, unauthorized devices can be identified and blocked. WEP encryption is weak and easily cracked. Hiding the SSID provides minimal security and is easily bypassed. Port forwarding is unrelated to wireless access control.",
        "examTip": "MAC address filtering is a useful tool for access control in Wi-Fi networks. It lets you allow only specific devices to connect based on their MAC addresses."
      },
      {
        "id": 23,
        "question": "Which of the following BEST describes the 'Platform as a Service' (PaaS) cloud computing model?",
        "options": [
          "Provides users with access to software applications over the internet.",
          "Offers a complete computing infrastructure including servers and storage.",
          "Provides a platform for developers to build, deploy, and manage applications.",
          "Delivers virtualized desktop environments to end users."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Platform as a Service (PaaS) provides a platform for developers to build, deploy, and manage applications without managing the underlying infrastructure. PaaS offers tools and services needed for application development, testing, and deployment. SaaS is for software applications, IaaS for infrastructure, and DaaS for desktops.",
        "examTip": "PaaS is for developers. It provides a platform and tools for building and deploying applications in the cloud, without worrying about server management."
      },
      {
        "id": 24,
        "question": "Which of the following is a common symptom of insufficient RAM (Random Access Memory) in a computer?",
        "options": [
          "Overheating CPU.",
          "Slow performance, especially when multitasking or running memory-intensive applications.",
          "Blue Screen of Death (BSOD) errors related to video drivers.",
          "Inability to detect a hard drive during boot."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Slow performance, especially when multitasking or running memory-intensive applications, is a common symptom of insufficient RAM. When RAM is insufficient, the system starts using slower storage (like HDD/SSD) as virtual memory, leading to significant performance slowdowns. Overheating CPU, BSODs related to video drivers, and HDD detection issues are not typically directly caused by insufficient RAM.",
        "examTip": "Slow performance, especially when multitasking or running many applications, often points to insufficient RAM. Check RAM usage in Task Manager/Resource Monitor."
      },
      {
        "id": 25,
        "question": "Which connector type is commonly used for connecting high-end video cards to a power supply unit (PSU) to provide additional power?",
        "options": [
          "Molex connector",
          "SATA power connector",
          "PCIe power connector (6-pin or 8-pin)",
          "Berg connector"
        ],
        "correctAnswerIndex": 2,
        "explanation": "PCIe power connectors (6-pin or 8-pin) are commonly used to connect high-end video cards to a PSU to provide the extra power they require. Modern GPUs often need more power than the PCIe slot can provide. Molex and Berg connectors are older power types, and SATA power is for SATA drives.",
        "examTip": "PCIe power connectors (6-pin and 8-pin) are specifically for powering graphics cards. They provide extra power directly from the PSU to the GPU."
      },
      {
        "id": 26,
        "question": "A technician is asked to implement port forwarding on a SOHO router. What is the primary purpose of port forwarding?",
        "options": [
          "To encrypt all network traffic.",
          "To allow external access to services running on a private network.",
          "To block all incoming traffic from the internet.",
          "To improve the speed of internet browsing."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Port forwarding is primarily used to allow external access to services running on a private network. It redirects traffic from a specific port on the router's public IP address to a specific device and port within the private network, enabling access to internal services from the internet. VPNs encrypt traffic, firewalls block traffic, and port forwarding doesn't directly improve browsing speed.",
        "examTip": "Port forwarding lets you 'open' specific ports on your router to allow external access to services running inside your home or office network, like web servers or game servers."
      },
      {
        "id": 27,
        "question": "Which of the following is a characteristic of 'Plenum'-rated network cables?",
        "options": [
          "Plenum cables are less resistant to fire and smoke.",
          "Plenum cables are more flexible and easier to install.",
          "Plenum cables are designed to be installed in air handling spaces and produce less toxic smoke when burning.",
          "Plenum cables are cheaper than non-plenum cables."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Plenum-rated network cables are designed to be installed in air handling spaces (plenums) and are characterized by producing less toxic smoke when burning. This is a critical safety feature for installations in air ducts or above ceilings used for air circulation. Plenum cables are typically more expensive and less flexible than non-plenum cables, but safety is the priority in plenum spaces.",
        "examTip": "Plenum cables are fire-safety rated for air handling spaces. They are designed to produce less toxic smoke in case of fire, a crucial safety requirement for building codes."
      },
      {
        "id": 28,
        "question": "Which of the following command-line tools is used to display the network configuration of a Windows computer, including IP address, subnet mask, and default gateway?",
        "options": [
          "ping",
          "tracert",
          "nslookup",
          "ipconfig"
        ],
        "correctAnswerIndex": 3,
        "explanation": "`ipconfig` is the command-line tool used in Windows to display the network configuration of a computer, including IP address, subnet mask, default gateway, DNS servers, and more. Ping tests connectivity, tracert traces network paths, and nslookup queries DNS.",
        "examTip": "`ipconfig` is your go-to command in Windows for viewing and managing network configuration details. Use `ipconfig /all` for comprehensive information."
      },
      {
        "id": 29,
        "question": "Which type of cloud computing model is BEST suited for providing virtualized desktop environments to end-users, allowing them to access their desktops remotely?",
        "options": [
          "IaaS (Infrastructure as a Service)",
          "PaaS (Platform as a Service)",
          "SaaS (Software as a Service)",
          "DaaS (Desktop as a Service)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "DaaS (Desktop as a Service) is BEST suited for providing virtualized desktop environments to end-users, allowing them to access their desktops remotely. DaaS solutions host and manage virtual desktops in the cloud, which users can access from various devices. IaaS is for infrastructure, PaaS for development platforms, and SaaS for software applications.",
        "examTip": "DaaS (Desktop as a Service) is about providing virtual desktops in the cloud, accessible from anywhere. Think of Citrix or VMware Horizon Cloud."
      },
      {
        "id": 30,
        "question": "Which of the following memory module form factors is smaller and designed for use in laptops and notebooks?",
        "options": [
          "DIMM (Dual In-line Memory Module)",
          "SIMM (Single In-line Memory Module)",
          "RIMM (Rambus In-line Memory Module)",
          "SODIMM (Small Outline Dual In-line Memory Module)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "SODIMM (Small Outline Dual In-line Memory Module) is the memory module form factor that is smaller and designed for use in laptops and notebooks. SODIMMs are physically smaller than standard DIMMs used in desktops. SIMM and RIMM are older memory types, and DIMM is the standard desktop form factor.",
        "examTip": "SODIMMs are 'small outline' DIMMs, designed for the compact spaces in laptops. DIMMs are the standard size for desktop PCs."
      },
      {
        "id": 31,
        "question": "A user reports that their laser printer is producing ghosting, where faint images from previous prints are visible on subsequent pages. Which printer component is MOST likely causing this issue?",
        "options": [
          "Toner Cartridge",
          "Fuser Assembly",
          "Cleaning Blade or Wiper Blade",
          "Transfer Belt or Roller"
        ],
        "correctAnswerIndex": 2,
        "explanation": "A faulty Cleaning Blade or Wiper Blade in a laser printer is MOST likely to cause ghosting. The cleaning blade is responsible for removing residual toner from the drum after each print cycle. If it's not working properly, toner residue remains, leading to ghost images on subsequent prints. Toner cartridge, fuser assembly, and transfer belt/roller issues are less directly linked to ghosting.",
        "examTip": "Ghosting in laser prints often points to a problem with the cleaning blade or wiper blade. These components are crucial for removing residual toner from the drum."
      },
      {
        "id": 32,
        "question": "Which of the following TCP/UDP ports is used by SNMP (Simple Network Management Protocol) for sending traps and notifications?",
        "options": [
          "Port 161",
          "Port 162",
          "Port 443",
          "Port 53"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Port 162 (UDP) is used by SNMP (Simple Network Management Protocol) for receiving traps and notifications from managed devices. Port 161 (UDP) is used for SNMP management requests. Port 443 is for HTTPS and Port 53 for DNS.",
        "examTip": "SNMP uses two main ports: 161 for management requests and 162 for traps/notifications. Remember 162 for SNMP traps."
      },
      {
        "id": 33,
        "question": "Which display technology is known for its wide color gamut, high brightness, and is often used in high-end gaming monitors and HDR-capable displays?",
        "options": [
          "TN (Twisted Nematic)",
          "VA (Vertical Alignment)",
          "OLED (Organic Light Emitting Diode)",
          "Quantum Dot enhanced LCD (QLED)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "Quantum Dot enhanced LCD (QLED) technology is known for its wide color gamut, high brightness, and is often used in high-end gaming monitors and HDR (High Dynamic Range)-capable displays. Quantum dots enhance color purity and brightness in LCD panels. TN is fast but has poorer colors, IPS is good for color accuracy but may not reach the same brightness, and OLED excels in contrast but not always in peak brightness compared to QLED LCDs.",
        "examTip": "QLED (Quantum Dot LED) is a type of LCD that uses quantum dots to enhance color and brightness, making them great for HDR and gaming monitors."
      },
      {
        "id": 34,
        "question": "What is the purpose of implementing 'Multi-Factor Authentication' (MFA)?",
        "options": [
          "To speed up system boot times.",
          "To encrypt network traffic.",
          "To enhance security by requiring multiple forms of verification.",
          "To manage user passwords more effectively."
        ],
        "correctAnswerIndex": 3,
        "explanation": "Multi-Factor Authentication (MFA) is implemented to enhance security by requiring multiple forms of verification before granting access. This makes it significantly harder for unauthorized users to gain access, even if one factor (like a password) is compromised. MFA is not about boot speed, network encryption, or password management in itself, though password management can be part of a broader security strategy.",
        "examTip": "MFA is about 'layers of security'. It requires more than just a password, significantly increasing account protection against unauthorized access."
      },
      {
        "id": 35,
        "question": "Which tool is MOST appropriate for testing the output voltages of a computer power supply unit (PSU)?",
        "options": [
          "Cable tester",
          "Toner probe",
          "Multimeter",
          "Loopback plug"
        ],
        "correctAnswerIndex": 2,
        "explanation": "A Multimeter is MOST appropriate for testing the output voltages of a PSU. A multimeter can measure DC voltages (like 12V, 5V, 3.3V) output by the PSU, allowing a technician to verify if the PSU is providing the correct and stable voltages needed for computer components. Cable testers are for network cables, toner probes trace cables, and loopback plugs test ports.",
        "examTip": "A multimeter is your essential tool for electrical testing. Use it to measure PSU voltages and verify if the power supply is working correctly."
      },
      {
        "id": 36,
        "question": "Which of the following cloud computing models is MOST likely to be used by a large enterprise that wants to maintain full control over their infrastructure and data, but still leverage cloud technologies?",
        "options": [
          "Public Cloud",
          "Private Cloud",
          "Hybrid Cloud",
          "Community Cloud"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Private Cloud is MOST likely to be used by a large enterprise wanting full control over infrastructure and data while using cloud technologies. A private cloud is operated solely for a single organization, providing greater control and security compared to public clouds. Hybrid clouds combine private and public cloud elements. Community clouds are shared by several organizations. Public clouds are multi-tenant and offer less control.",
        "examTip": "Private clouds are for organizations needing maximum control and security. They build and manage their own cloud infrastructure, often within their own data centers."
      },
      {
        "id": 37,
        "question": "Which memory technology is 'static' and does not require constant refreshing, making it faster but more expensive than dynamic RAM?",
        "options": [
          "DRAM (Dynamic RAM)",
          "SDRAM",
          "Flash Memory",
          "SRAM (Static RAM)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "SRAM (Static RAM) is 'static' memory and does not require constant refreshing to retain data, making it significantly faster than DRAM. However, SRAM is also more expensive and less dense than DRAM, which is why it's used for cache memory (where speed is critical) and DRAM for system RAM (where density and cost are more important). Flash memory and ROM are non-volatile.",
        "examTip": "SRAM is 'static' and fast, used for CPU cache. DRAM is 'dynamic' and slower, used for system RAM. Think of SRAM as high-speed, small-capacity cache, and DRAM as larger, slower system memory."
      },
      {
        "id": 38,
        "question": "A user reports that their computer frequently freezes or crashes, and they suspect a RAM issue. Which Windows utility can be used to perform a comprehensive memory diagnostic test?",
        "options": [
          "Disk Cleanup",
          "System Restore",
          "Memory Diagnostics Tool (mdsched.exe)",
          "Device Manager"
        ],
        "correctAnswerIndex": 3,
        "explanation": "The Memory Diagnostics Tool (mdsched.exe) is a built-in Windows utility specifically designed to perform a comprehensive memory diagnostic test. It can detect various RAM-related errors. Disk Cleanup is for freeing disk space, System Restore for reverting system changes, and Device Manager for hardware management.",
        "examTip": "Windows Memory Diagnostic Tool (mdsched.exe) is your built-in tool for thoroughly testing RAM for errors. Use it when you suspect memory problems."
      },
      {
        "id": 39,
        "question": "Which connector type is commonly used for internal power connections to SATA hard drives and SSDs?",
        "options": [
          "Molex connector",
          "Berg connector",
          "PCIe power connector",
          "SATA power connector (15-pin)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "SATA power connectors (15-pin) are specifically designed and commonly used for internal power connections to SATA hard drives and SSDs. Molex and Berg connectors are older power types, and PCIe power is for GPUs.",
        "examTip": "SATA power connectors are the flat, 15-pin connectors used for powering SATA hard drives and SSDs. Recognize them as SATA power interfaces."
      },
      {
        "id": 40,
        "question": "A laser printer is producing prints with toner smearing or not properly fused to the paper. Which printer component is MOST likely faulty?",
        "options": [
          "Toner Cartridge",
          "Imaging Drum",
          "Transfer Belt or Roller",
          "Fuser Assembly"
        ],
        "correctAnswerIndex": 3,
        "explanation": "The Fuser Assembly is MOST likely faulty if a laser printer is producing prints with toner smearing or not properly fused to the paper. The fuser unit uses heat and pressure to melt and bond toner to the paper. If it's malfunctioning, toner may not fuse correctly, leading to smudging or weak adhesion. Toner cartridge, imaging drum, and transfer belt/roller issues typically cause different print quality problems.",
        "examTip": "Toner smearing or unfused toner on laser prints strongly suggests a problem with the fuser assembly. Fuser issues are often heat-related."
      },
      {
        "id": 41,
        "question": "What is the standard port number for NetBIOS Datagram Service?",
        "options": [
          "Port 137",
          "Port 138",
          "Port 139",
          "Port 445"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Port 138 is the standard UDP port number for NetBIOS Datagram Service, used for connectionless data transfer in NetBIOS over TCP/IP. Port 137 is for NetBIOS Name Service, Port 139 for NetBIOS Session Service, and Port 445 for SMB over TCP.",
        "examTip": "NetBIOS Datagram Service uses port 138 (UDP). Remember it's for datagram (connectionless) communication in NetBIOS."
      },
      {
        "id": 42,
        "question": "Which display technology typically offers the best black levels and contrast ratio due to its ability to completely turn off individual pixels?",
        "options": [
          "TN (Twisted Nematic)",
          "VA (Vertical Alignment)",
          "LED-backlit LCD",
          "OLED (Organic Light Emitting Diode)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "OLED (Organic Light Emitting Diode) technology typically offers the best black levels and contrast ratio. OLED pixels can be turned off completely, achieving 'true black' and extremely high contrast. LCD and LED-backlit LCDs use backlights that cannot be fully turned off, limiting black levels. VA panels offer better contrast than TN but not as good as OLED.",
        "examTip": "OLEDs are the kings of black levels and contrast. Their ability to turn off individual pixels is what makes 'true black' possible."
      },
      {
        "id": 43,
        "question": "What is the primary disadvantage of using RAID 0 configuration for data storage?",
        "options": [
          "Reduced read/write performance.",
          "Increased complexity in setup and management.",
          "Lack of fault tolerance and data redundancy.",
          "Higher cost per gigabyte compared to other RAID levels."
        ],
        "correctAnswerIndex": 3,
        "explanation": "The primary disadvantage of RAID 0 is the lack of fault tolerance and data redundancy. In RAID 0, data is striped across drives for performance, but if any single drive fails, all data in the array is lost. RAID 0 excels in speed but sacrifices data protection. Complexity might be slightly increased compared to single drives, but it's relatively simple compared to RAID 5/6/10. Cost per gigabyte is usually lower or similar to non-RAID setups.",
        "examTip": "RAID 0 offers great speed but ZERO data protection. Drive failure means total data loss. It's a risk-reward trade-off."
      },
      {
        "id": 44,
        "question": "Which tool is used to test and certify the data transfer speed capability of network cabling installations?",
        "options": [
          "Cable tester",
          "Bandwidth tester",
          "Network certifier",
          "Toner probe"
        ],
        "correctAnswerIndex": 2,
        "explanation": "A Network certifier is specifically designed to test and certify the data transfer speed capability of network cabling installations. Certifiers go beyond basic continuity testing and verify if cabling meets standards for specific speeds (like Cat 5e, Cat 6, etc.). Cable testers check wiring, bandwidth testers measure network throughput in active networks, and toner probes trace cables.",
        "examTip": "Network certifiers are professional-grade tools for verifying if cabling installations meet industry standards for speed and performance. They are used for certification purposes."
      },
      {
        "id": 45,
        "question": "Which of the following hypervisor types runs directly on the hardware, often used in enterprise server virtualization, and is also known as a 'bare-metal' hypervisor?",
        "options": [
          "Type 2 Hypervisor",
          "Hosted Hypervisor",
          "Application Hypervisor",
          "Type 1 Hypervisor"
        ],
        "correctAnswerIndex": 3,
        "explanation": "Type 1 Hypervisors, also known as 'bare-metal' hypervisors, run directly on the system hardware without an underlying operating system. They are typically used in enterprise server virtualization for their performance and efficiency. Type 2 hypervisors run on top of a host OS.",
        "examTip": "Type 1 hypervisors are 'bare-metal' – they install directly on hardware. VMware ESXi and Microsoft Hyper-V Server are examples. They are designed for server virtualization efficiency."
      },
      {
        "id": 46,
        "question": "Which type of expansion slot is commonly used for installing Wi-Fi adapters in laptops?",
        "options": [
          "PCIe x16",
          "PCIe x1",
          "Mini PCIe or M.2",
          "AGP"
        ],
        "correctAnswerIndex": 3,
        "explanation": "Mini PCIe or M.2 slots are commonly used for installing Wi-Fi adapters in laptops and notebooks. These are compact form factors suitable for mobile devices. PCIe x16 is for graphics cards, PCIe x1 for other expansion cards in desktops, and AGP is an older graphics card slot.",
        "examTip": "Laptops use smaller expansion slots for Wi-Fi cards – Mini PCIe and the even smaller M.2 are common. They are designed for space-constrained mobile devices."
      },
      {
        "id": 47,
        "question": "What is the purpose of 'Secure Boot' in UEFI firmware?",
        "options": [
          "To encrypt the entire hard drive.",
          "To speed up the system boot process.",
          "To ensure only digitally signed and trusted operating systems can boot.",
          "To set a BIOS administrator password."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Secure Boot in UEFI firmware ensures that only digitally signed and trusted operating systems can boot. It verifies the digital signatures of bootloaders and OS kernels to prevent malware or unauthorized OSes from loading during startup. It's a security feature to prevent boot-level attacks. It doesn't encrypt the drive (BitLocker or similar does that), speed up boot times, or set BIOS passwords.",
        "examTip": "Secure Boot is a security feature to protect the boot process. It verifies the digital signatures of bootloaders to ensure only trusted OSes can load, preventing rootkits and boot-level malware."
      },
      {
        "id": 48,
        "question": "Which of the following network devices operates as a repeater at the Physical Layer (Layer 1) of the OSI model but also adds basic filtering and collision domain separation?",
        "options": [
          "Hub",
          "Switch",
          "Router",
          "Bridge"
        ],
        "correctAnswerIndex": 3,
        "explanation": "A Bridge operates at the Data Link Layer (Layer 2) and acts as a repeater at the Physical Layer, but importantly, it also adds basic filtering and collision domain separation. Bridges divide a network into segments, reducing collisions and improving efficiency compared to hubs. Switches are more advanced Layer 2 devices, and routers are Layer 3.",
        "examTip": "Bridges are 'smarter' repeaters. They operate at Layer 2 and help reduce collisions by segmenting a network, unlike hubs which just broadcast everything."
      },
      {
        "id": 49,
        "question": "Which connector type is commonly used for internal power connections to case fans and smaller peripherals that require less power?",
        "options": [
          "SATA power connector",
          "PCIe power connector",
          "Molex connector",
          "Berg connector (4-pin floppy connector)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "Berg connectors (4-pin floppy drive power connectors) are commonly used for internal power connections to case fans and smaller peripherals that require less power. While Molex can also power fans, Berg connectors are often smaller and more appropriate for low-power devices like fans. SATA power is for drives, and PCIe power for GPUs.",
        "examTip": "Berg connectors are small, 4-pin power connectors. They are often used for case fans and other low-power internal peripherals."
      },
      {
        "id": 50,
        "question": "A laser printer is producing prints with repeating defects or marks at regular intervals down the page. Which printer component is MOST likely causing this repeating defect pattern?",
        "options": [
          "Toner Cartridge",
          "Paper Tray",
          "Imaging Drum",
          "Print Driver"
        ],
        "correctAnswerIndex": 2,
        "explanation": "The Imaging Drum is MOST likely causing repeating defects or marks at regular intervals down the page. Repeating defects often correspond to the circumference of a drum or roller. If the imaging drum has a scratch or defect, it will repeat its imperfection with each rotation, creating a repeating pattern on prints. Toner cartridge, paper tray, and driver issues are less likely to cause such regular, repeating defects.",
        "examTip": "Repeating defects in laser prints, especially at regular intervals, often point to a damaged or dirty imaging drum. Look for scratches or debris on the drum surface."
      },
      {
        "id": 51,
        "question": "What is the standard port number range for 'ephemeral ports' or 'dynamic ports', which are used for temporary client-side connections?",
        "options": [
          "0-1023",
          "1024-49151",
          "49152-65535",
          "1024-65535"
        ],
        "correctAnswerIndex": 3,
        "explanation": "The standard port number range for ephemeral ports or dynamic ports is 1024-65535. These ports are used for temporary client-side connections when a client initiates a network connection. Ports 0-1023 are well-known ports, and 1024-49151 are registered ports. The officially registered ephemeral port range is 49152-65535, but commonly, the range 1024-65535 is considered 'dynamic' or 'ephemeral'.",
        "examTip": "Ephemeral ports (or dynamic ports) are temporary ports used by client applications for outgoing connections. Remember the common range is 1024-65535, although the registered ephemeral range starts higher."
      },
      {
        "id": 52,
        "question": "Which display technology is known for its ability to achieve very high refresh rates and fast response times, making it popular for competitive gaming monitors?",
        "options": [
          "IPS (In-Plane Switching)",
          "VA (Vertical Alignment)",
          "OLED (Organic Light Emitting Diode)",
          "TN (Twisted Nematic)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "TN (Twisted Nematic) display technology is primarily known for its ability to achieve very high refresh rates and fast response times, making it popular for competitive gaming monitors where motion clarity and low latency are paramount. While other technologies are improving, TN still typically leads in raw speed. IPS is for color, VA for contrast, and OLED for blacks and contrast, but TN is fastest.",
        "examTip": "For gaming monitors prioritizing speed and refresh rate, TN panels are often the choice due to their fast response times, even if they sacrifice some color accuracy and viewing angles."
      },
      {
        "id": 53,
        "question": "What is the purpose of implementing 'RAID 6' configuration?",
        "options": [
          "To improve read/write performance by striping data.",
          "To provide data redundancy by mirroring.",
          "To provide fault tolerance with dual parity, allowing for up to two drive failures.",
          "To combine multiple drives into a single large volume without redundancy."
        ],
        "correctAnswerIndex": 2,
        "explanation": "RAID 6 provides fault tolerance with dual parity, allowing for up to two drive failures without data loss. It stripes data across at least four drives and uses two sets of parity data for enhanced redundancy compared to RAID 5 (single parity). RAID 0 is striping only, RAID 1 is mirroring, and spanning (JBOD) is volume aggregation without RAID.",
        "examTip": "RAID 6 is 'extra fault-tolerant' RAID 5. It uses dual parity to survive up to two drive failures, making it very robust for critical data storage."
      },
      {
        "id": 54,
        "question": "Which tool is used to measure the voltage, current, and resistance in electronic circuits and components?",
        "options": [
          "Cable tester",
          "Toner probe",
          "Multimeter",
          "Loopback plug"
        ],
        "correctAnswerIndex": 2,
        "explanation": "A Multimeter is used to measure voltage, current, and resistance in electronic circuits and components. It's a versatile diagnostic tool for electrical troubleshooting. Cable testers check cable wiring, toner probes trace cables, and loopback plugs test ports.",
        "examTip": "A multimeter is your essential tool for electrical diagnostics. It can measure voltage, current, resistance, and more – fundamental for electronics troubleshooting."
      },
      {
        "id": 55,
        "question": "Which virtualization technology allows multiple operating systems to run concurrently on a single physical machine by abstracting hardware resources?",
        "options": [
          "Application Virtualization",
          "Containerization",
          "Operating System Virtualization",
          "Hardware Virtualization (using Hypervisors)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "Hardware Virtualization (using Hypervisors) allows multiple operating systems to run concurrently on a single physical machine by abstracting hardware resources. Hypervisors create virtual machines, each with its own OS and resources, sharing the underlying physical hardware. Application virtualization virtualizes apps, and containerization virtualizes at the OS level, but hardware virtualization with hypervisors provides full OS virtualization.",
        "examTip": "Hardware virtualization with hypervisors is the foundation of traditional VMs. It allows you to run multiple, completely separate operating systems on one physical machine."
      },
      {
        "id": 56,
        "question": "Which expansion slot is commonly used for installing sound cards in desktop computers, especially when PCIe x1 slots are limited or unavailable?",
        "options": [
          "PCIe x16",
          "PCIe x1",
          "PCI (Conventional PCI)",
          "AGP"
        ],
        "correctAnswerIndex": 2,
        "explanation": "PCI (Conventional PCI) slots are still sometimes used for installing sound cards in desktop computers, especially in older systems or when PCIe x1 slots are limited or unavailable. While PCIe x1 is preferred for newer sound cards, PCI slots offer backward compatibility. PCIe x16 is for GPUs, PCIe x1 for other expansion cards, and AGP is for older graphics cards.",
        "examTip": "While PCIe x1 is preferred for modern sound cards, PCI slots are still relevant and can be used for sound cards, especially in older systems."
      },
      {
        "id": 57,
        "question": "What is the purpose of enabling 'Virtualization Technology' (VT-x or AMD-V) in BIOS/UEFI settings?",
        "options": [
          "To improve system boot speed.",
          "To enhance graphics card performance.",
          "To enable hardware virtualization support for virtual machines.",
          "To secure the boot process against malware."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Enabling Virtualization Technology (VT-x for Intel or AMD-V for AMD) in BIOS/UEFI settings is necessary to enable hardware virtualization support for virtual machines. These CPU extensions allow hypervisors to run VMs more efficiently by directly utilizing hardware resources. It's not for boot speed, GPU performance, or boot security (that's Secure Boot).",
        "examTip": "VT-x (Intel) or AMD-V (AMD) are hardware virtualization extensions. You MUST enable them in BIOS/UEFI to run virtual machines effectively."
      },
      {
        "id": 58,
        "question": "Which of the following network devices is capable of operating at all layers of the OSI model, from Physical Layer up to Application Layer?",
        "options": [
          "Hub",
          "Switch",
          "Router",
          "Firewall (Advanced Next-Generation Firewall)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "Advanced Next-Generation Firewalls are capable of operating at all layers of the OSI model, from the Physical Layer up to the Application Layer. These sophisticated firewalls can perform deep packet inspection, application-level filtering, and intrusion prevention, requiring functionality across the entire OSI stack. Hubs are Layer 1, Switches Layer 2, and Routers primarily Layer 3.",
        "examTip": "Next-Generation Firewalls (NGFWs) are 'layer-aware' firewalls. They can inspect traffic up to the Application Layer (Layer 7), going beyond basic port and protocol filtering."
      },
      {
        "id": 59,
        "question": "Which connector type is used for older parallel printer connections on desktop computers?",
        "options": [
          "USB Type-A",
          "PS/2",
          "Centronics (36-pin Parallel)",
          "DB9 Serial"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Centronics (36-pin Parallel) connectors are used for older parallel printer connections on desktop computers. They are large, 36-pin connectors. USB Type-A is the modern standard, PS/2 for older mice/keyboards, and DB9 Serial for serial communication.",
        "examTip": "Centronics (36-pin) connectors are the large, bulky parallel printer ports you might see on older PCs and printers. USB has replaced them in modern systems."
      },
      {
        "id": 60,
        "question": "A laser printer is producing prints with consistently light or faded print output, even after replacing the toner cartridge. Which printer component is MOST likely faulty?",
        "options": [
          "Fuser Assembly",
          "Imaging Drum",
          "Transfer Corona Wire or Roller",
          "Paper Type Setting"
        ],
        "correctAnswerIndex": 2,
        "explanation": "A faulty Transfer Corona Wire or Roller is MOST likely causing consistently light or faded print output, even after toner replacement. The transfer corona or roller is responsible for electrostatically transferring toner from the drum to the paper. If it's weak or faulty, toner transfer will be inefficient, resulting in faded prints. Fuser issues cause smearing, drum issues cause repeating defects, and paper settings are less likely to cause consistently light prints.",
        "examTip": "Consistently faded or light laser prints, even with new toner, often point to a problem with the transfer corona wire or roller. These components are key for toner transfer to paper."
      },
      {
        "id": 61,
        "question": "What is the standard port number for NetBIOS Session Service over UDP?",
        "options": [
          "Port 137",
          "Port 138",
          "Port 139",
          "Port 445"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Port 139 is the standard TCP port number for NetBIOS Session Service. While NetBIOS services can use both UDP and TCP, session service specifically uses TCP port 139 for reliable, connection-oriented communication. Ports 137 and 138 are UDP ports for NetBIOS Name and Datagram services. Port 445 is for SMB over TCP, which is a more modern file sharing protocol.",
        "examTip": "NetBIOS Session Service primarily uses TCP port 139 for reliable, connection-oriented communication. Remember this port for NetBIOS session establishment."
      },
      {
        "id": 62,
        "question": "Which display technology benefits from 'burn-in' mitigation techniques due to its organic materials degrading over time with prolonged static images?",
        "options": [
          "TN (Twisted Nematic)",
          "VA (Vertical Alignment)",
          "LED-backlit LCD",
          "OLED (Organic Light Emitting Diode)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "OLED (Organic Light Emitting Diode) technology benefits from 'burn-in' mitigation techniques because its organic materials can degrade over time with prolonged static images. OLED pixels can suffer from uneven wear if static elements are displayed for extended periods, leading to image retention or 'burn-in'. LCD and LED-backlit LCDs are not susceptible to burn-in in the same way as OLEDs.",
        "examTip": "OLEDs are susceptible to 'burn-in' or image retention with prolonged static content. Burn-in mitigation techniques are important for OLED displays to prolong their lifespan."
      },
      {
        "id": 63,
        "question": "What is the purpose of implementing 'RAID 50' (or RAID 5+0) configuration?",
        "options": [
          "To provide data redundancy by mirroring.",
          "To improve read/write performance by striping only.",
          "To combine striping and parity with mirroring for enhanced performance and fault tolerance.",
          "To create a large storage volume by spanning drives without any redundancy."
        ],
        "correctAnswerIndex": 2,
        "explanation": "RAID 50 (or RAID 5+0) configuration combines striping (RAID 0) and parity (RAID 5) in a nested array to provide enhanced performance and fault tolerance. It stripes RAID 5 arrays, offering both the performance benefits of striping and the fault tolerance of RAID 5. RAID 1 is mirroring, RAID 0 is striping only, and spanning (JBOD) lacks redundancy.",
        "examTip": "RAID 50 (RAID 5+0) is a nested RAID level combining striping and parity, offering a good balance of performance, capacity, and fault tolerance. It's more complex but robust."
      },
      {
        "id": 64,
        "question": "Which tool is used to test and verify the speed and duplex settings of a network port on a switch or router?",
        "options": [
          "Cable tester",
          "Port scanner",
          "Network analyzer or protocol analyzer",
          "Managed Switch Interface (CLI or GUI)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "The Managed Switch Interface (CLI or GUI) is BEST suited for testing and verifying the speed and duplex settings of a network port on a switch or router. Managed switches allow administrators to configure and monitor port settings directly through their interfaces. Cable testers check cables, port scanners check open ports for security, and network analyzers capture and analyze network traffic, not directly test port settings.",
        "examTip": "Managed switch interfaces (CLI or GUI) are your primary tools for configuring and monitoring switch port settings, including speed and duplex. Access the switch's management interface to verify port configurations."
      },
      {
        "id": 65,
        "question": "Which virtualization technology isolates applications within containers, sharing the host OS kernel but providing process and resource isolation?",
        "options": [
          "Type 1 Hypervisor",
          "Type 2 Hypervisor",
          "Application Virtualization",
          "Containerization"
        ],
        "correctAnswerIndex": 3,
        "explanation": "Containerization is the virtualization technology that isolates applications within containers, sharing the host OS kernel but providing process and resource isolation. Containers are lightweight and efficient because they don't require a full OS for each instance, unlike hypervisors. Application virtualization isolates individual applications, not entire environments.",
        "examTip": "Containers are OS-level virtualization. They are lightweight, share the host OS kernel, and are excellent for application isolation and portability."
      },
      {
        "id": 66,
        "question": "Which expansion slot is designed for high-bandwidth peripherals other than graphics cards, such as high-speed network cards or storage controllers?",
        "options": [
          "PCIe x16",
          "PCIe x8",
          "PCIe x4",
          "PCIe x1"
        ],
        "correctAnswerIndex": 1,
        "explanation": "PCIe x8 (PCI Express x8) slots are designed for high-bandwidth peripherals other than graphics cards, such as high-speed network cards, storage controllers (like RAID cards), and professional audio interfaces. While PCIe x16 is for GPUs, PCIe x8 provides substantial bandwidth for other demanding peripherals. PCIe x4 and x1 are for lower-bandwidth cards.",
        "examTip": "PCIe x8 slots are for high-bandwidth expansion cards that aren't GPUs. Think of fast network cards, RAID controllers, and professional audio interfaces."
      },
      {
        "id": 67,
        "question": "What is the purpose of configuring 'Boot from LAN' or 'Network Boot' option in BIOS/UEFI settings?",
        "options": [
          "To improve network speed.",
          "To enable booting the system from a network image or server.",
          "To secure the boot process using network protocols.",
          "To manage network boot order priority."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Configuring 'Boot from LAN' or 'Network Boot' in BIOS/UEFI settings enables booting the system from a network image or server. This is used for network-based OS deployment, diskless workstations, and centralized system management. It's not primarily for network speed, boot security in itself, or just managing boot order (it's about adding network booting to the boot order options).",
        "examTip": "'Boot from LAN' or 'Network Boot' lets you start your computer from an image stored on a network server, essential for PXE booting and network OS deployments."
      },
      {
        "id": 68,
        "question": "Which of the following network devices is commonly used to connect different network segments or subnets together and route traffic between them based on IP addresses?",
        "options": [
          "Hub",
          "Switch",
          "Router",
          "Bridge"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Routers are commonly used to connect different network segments or subnets together and route traffic between them based on IP addresses (Layer 3 routing). Hubs and switches operate within a single network segment (Layer 1 and 2), and bridges segment networks at Layer 2 but don't perform IP routing across different networks.",
        "examTip": "Routers are the 'traffic directors' between different networks or subnets. They use IP addresses to route data between networks."
      },
      {
        "id": 69,
        "question": "Which connector type is used for older serial ports that were commonly used for external modems and some older peripherals?",
        "options": [
          "USB Type-A",
          "PS/2",
          "Centronics (36-pin Parallel)",
          "DB9 (9-pin Serial)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "DB9 (9-pin Serial) connectors are used for older serial ports that were commonly used for external modems, older mice, and other serial peripherals. USB Type-A is modern, PS/2 for mice/keyboards, and Centronics for parallel printers.",
        "examTip": "DB9 connectors are the classic 9-pin, D-shaped serial ports. They were standard for modems, serial mice, and older communication devices."
      },
      {
        "id": 70,
        "question": "A laser printer is producing prints with a repeating background shading or ghosting across the page. Which printer component is MOST likely causing this background issue?",
        "options": [
          "Toner Cartridge",
          "Fuser Assembly",
          "Discharge Lamp or Erase Lamp",
          "Paper Type Setting"
        ],
        "correctAnswerIndex": 2,
        "explanation": "A faulty Discharge Lamp or Erase Lamp in a laser printer is MOST likely causing repeating background shading or ghosting. The discharge lamp is responsible for neutralizing the charge on the drum after each print cycle. If it's weak or failing, residual charge remains, attracting toner and causing background shading or ghosting. Toner cartridge, fuser assembly, and paper settings are less likely to cause this specific issue.",
        "examTip": "Background shading or ghosting in laser prints often points to a problem with the discharge lamp or erase lamp. These lamps are crucial for neutralizing drum charge and preventing toner residue buildup."
      },
      {
        "id": 71,
        "question": "What is the standard port number range for 'registered ports', which are used by applications and services but are not system ports?",
        "options": [
          "0-1023",
          "1024-49151",
          "49152-65535",
          "1024-65535"
        ],
        "correctAnswerIndex": 1,
        "explanation": "The standard port number range for registered ports is 1024-49151. These ports are used by applications and services but are not considered system ports (0-1023) or dynamic/ephemeral ports (49152-65535). Well-known ports (0-1023) are for common system services.",
        "examTip": "Registered ports (1024-49151) are for applications and services that are not system-level but still need a recognized port range. Think of custom applications or less common services."
      },
      {
        "id": 72,
        "question": "Which display technology typically offers the widest viewing angles and best color accuracy, making it suitable for collaborative work and color-critical tasks?",
        "options": [
          "TN (Twisted Nematic)",
          "VA (Vertical Alignment)",
          "OLED (Organic Light Emitting Diode)",
          "IPS (In-Plane Switching)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "IPS (In-Plane Switching) display technology typically offers the widest viewing angles and best color accuracy, making it highly suitable for collaborative work and color-critical tasks. IPS panels maintain consistent color and contrast even when viewed from wide angles. TN has narrow angles, VA is in between, and OLED excels in contrast but not necessarily wider viewing angles than IPS LCDs.",
        "examTip": "IPS panels are the champions of wide viewing angles and color accuracy. They are ideal for situations where multiple people need to view the screen or for tasks needing accurate color representation."
      },
      {
        "id": 73,
        "question": "What is the purpose of implementing 'RAID 60' (or RAID 6+0) configuration?",
        "options": [
          "To provide data redundancy by mirroring.",
          "To improve read/write performance by striping only.",
          "To combine striping and dual parity with mirroring for enhanced performance and even greater fault tolerance.",
          "To create a large storage volume by spanning drives without any redundancy."
        ],
        "correctAnswerIndex": 2,
        "explanation": "RAID 60 (or RAID 6+0) configuration combines striping (RAID 0) and dual parity (RAID 6) in a nested array to provide enhanced performance and even greater fault tolerance than RAID 6 alone. It stripes RAID 6 arrays, offering both speed and high redundancy, tolerating multiple drive failures within different RAID 6 segments. RAID 1 is mirroring, RAID 0 is striping only, and spanning (JBOD) lacks redundancy.",
        "examTip": "RAID 60 (RAID 6+0) is for maximum fault tolerance and good performance. It can survive multiple drive failures and is used for very critical, high-capacity storage."
      },
      {
        "id": 74,
        "question": "Which tool is used to test the strength and coverage of a Wi-Fi network signal in different locations?",
        "options": [
          "Cable tester",
          "Bandwidth tester",
          "Wi-Fi analyzer",
          "Toner probe"
        ],
        "correctAnswerIndex": 2,
        "explanation": "A Wi-Fi analyzer is used to test the strength and coverage of a Wi-Fi network signal in different locations. Wi-Fi analyzers can map signal strength, identify dead zones, and help optimize access point placement for best coverage. Cable testers are for wired cables, bandwidth testers measure network speed, and toner probes trace cables.",
        "examTip": "Use a Wi-Fi analyzer to map your wireless signal coverage and find areas with weak signals or dead zones. It's essential for optimizing Wi-Fi network placement."
      },
      {
        "id": 75,
        "question": "Which virtualization technology allows users to run applications in isolated environments without virtualizing the entire operating system, often used for application compatibility or sandboxing?",
        "options": [
          "Type 1 Hypervisor",
          "Type 2 Hypervisor",
          "Application Virtualization",
          "Containerization"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Application Virtualization allows users to run applications in isolated environments without virtualizing the entire operating system. It focuses on virtualizing the application layer, often used for compatibility or sandboxing applications. Type 1 and 2 hypervisors virtualize entire OSes, and containerization virtualizes at the OS level.",
        "examTip": "Application virtualization isolates individual applications from the underlying OS. Think of running legacy apps in compatibility mode or sandboxing software for security."
      },
      {
        "id": 76,
        "question": "Which expansion slot is typically used for installing dedicated hardware RAID controllers in servers and high-performance workstations?",
        "options": [
          "PCIe x16",
          "PCIe x8",
          "PCIe x4",
          "PCIe x1"
        ],
        "correctAnswerIndex": 1,
        "explanation": "PCIe x8 (PCI Express x8) slots are commonly used for installing dedicated hardware RAID controllers in servers and high-performance workstations. RAID controllers often require high bandwidth to manage multiple drives efficiently, making PCIe x8 a suitable choice. PCIe x16 is for GPUs, and PCIe x4/x1 may be too limited for high-performance RAID controllers.",
        "examTip": "PCIe x8 slots are often used for hardware RAID controllers because they need substantial bandwidth to manage multiple storage drives effectively."
      },
      {
        "id": 77,
        "question": "What is the purpose of 'Secure Shell' (SSH) protocol?",
        "options": [
          "To transfer files securely over the internet.",
          "To provide secure, encrypted command-line access to remote systems.",
          "To secure web browsing sessions.",
          "To encrypt email communications."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Secure Shell (SSH) protocol is primarily used to provide secure, encrypted command-line access to remote systems. SSH encrypts the entire communication session, protecting against eavesdropping and man-in-the-middle attacks during remote administration. SFTP is for secure file transfer (over SSH), HTTPS for secure web browsing, and S/MIME or PGP for email encryption.",
        "examTip": "SSH is for secure remote command-line access. It's essential for securely managing servers and network devices remotely."
      },
      {
        "id": 78,
        "question": "Which of the following network devices operates at the Application Layer (Layer 7) of the OSI model and can perform deep packet inspection and application-level filtering?",
        "options": [
          "Hub",
          "Switch",
          "Router",
          "Next-Generation Firewall (NGFW)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "Next-Generation Firewalls (NGFWs) operate at the Application Layer (Layer 7) of the OSI model. NGFWs can perform deep packet inspection (DPI) and application-level filtering, allowing them to understand and control network traffic based on applications and content, not just ports and protocols. Hubs are Layer 1, Switches Layer 2, and Routers Layer 3.",
        "examTip": "Next-Generation Firewalls (NGFWs) are 'application-aware' firewalls. They can understand and filter traffic based on applications, going beyond basic network layer rules."
      },
      {
        "id": 79,
        "question": "Which connector type is used for older floppy disk data connections on motherboards?",
        "options": [
          "SATA data connector",
          "IDE (PATA) connector",
          "Berg connector",
          "Floppy Disk Controller (FDC) connector (34-pin ribbon)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "Floppy Disk Controller (FDC) connectors, which are 34-pin ribbon connectors, are used for older floppy disk data connections on motherboards. SATA data is for SATA drives, IDE (PATA) for older hard drives/optical drives, and Berg connectors are for floppy drive power.",
        "examTip": "FDC connectors are the 34-pin ribbon connectors specifically for floppy disk data cables. They are a legacy connector, rarely seen in modern systems."
      },
      {
        "id": 80,
        "question": "A laser printer is producing prints with areas of 'banding' or uneven toner density, especially in solid areas of color or grayscale. Which printer component is MOST likely causing this banding issue?",
        "options": [
          "Toner Cartridge",
          "Fuser Assembly",
          "Laser Scanner Assembly",
          "Paper Feed Mechanism"
        ],
        "correctAnswerIndex": 2,
        "explanation": "The Laser Scanner Assembly is MOST likely causing banding or uneven toner density in laser prints. Banding often results from inconsistencies in the laser scanning process, which can be due to a malfunctioning laser scanner assembly. Toner cartridge, fuser assembly, and paper feed issues typically cause different types of print defects.",
        "examTip": "Banding or uneven toner density in laser prints often points to a problem with the laser scanner assembly. These issues are related to the laser imaging process itself."
      },
      {
        "id": 81,
        "question": "What is the standard port number for NetBIOS Datagram Service over UDP?",
        "options": [
          "Port 137",
          "Port 138",
          "Port 139",
          "Port 445"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Port 138 is the standard UDP port number for NetBIOS Datagram Service over UDP. This port is used for connectionless data transfer in NetBIOS implementations using UDP. Port 137 is for NetBIOS Name Service (UDP), Port 139 for NetBIOS Session Service (TCP), and Port 445 for SMB over TCP.",
        "examTip": "NetBIOS Datagram Service over UDP uses port 138. Distinguish this UDP-based datagram service from the TCP-based session service (port 139)."
      },
      {
        "id": 82,
        "question": "Which display technology is known for its excellent black levels and contrast ratio, but may suffer from image retention or 'burn-in' over time?",
        "options": [
          "TN (Twisted Nematic)",
          "VA (Vertical Alignment)",
          "LED-backlit LCD",
          "OLED (Organic Light Emitting Diode)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "OLED (Organic Light Emitting Diode) technology is known for its excellent black levels and contrast ratio, but it is also susceptible to image retention or 'burn-in' over extended periods of displaying static images. This is due to the organic materials in OLEDs degrading unevenly over time. TN, VA, and LED-backlit LCDs are not prone to burn-in in the same way.",
        "examTip": "OLEDs, while offering amazing black levels and contrast, can suffer from 'burn-in' or image retention if static images are displayed for too long. Burn-in mitigation techniques are important for OLED longevity."
      },
      {
        "id": 83,
        "question": "What is the purpose of implementing 'RAID 01' (or RAID 0+1) configuration?",
        "options": [
          "To provide data redundancy using parity.",
          "To improve read/write performance by striping only.",
          "To combine striping and mirroring for both performance and redundancy.",
          "To create a large storage volume by spanning drives without any redundancy."
        ],
        "correctAnswerIndex": 2,
        "explanation": "RAID 01 (or RAID 0+1) configuration combines striping (RAID 0) and mirroring (RAID 1) to provide both improved performance and data redundancy. It mirrors striped sets, offering both speed and fault tolerance. RAID 5 and 6 use parity, RAID 0 is striping only, and spanning (JBOD) lacks redundancy. RAID 10 and RAID 01 are similar but with different underlying structures (RAID 10 stripes mirrored sets, RAID 01 mirrors striped sets).",
        "examTip": "RAID 01 (RAID 0+1) is another nested RAID level providing both performance and redundancy, similar to RAID 10, but with a different underlying structure and fault tolerance characteristics."
      },
      {
        "id": 84,
        "question": "Which tool is used to capture and analyze network traffic packets, allowing for detailed inspection of network communications?",
        "options": [
          "Cable tester",
          "Bandwidth tester",
          "Network analyzer or protocol analyzer (like Wireshark)",
          "Toner probe"
        ],
        "correctAnswerIndex": 2,
        "explanation": "A Network analyzer or protocol analyzer (like Wireshark) is used to capture and analyze network traffic packets. These tools allow for deep inspection of network communications, examining packet headers, payloads, and protocols for troubleshooting, security analysis, and network monitoring. Cable testers check cables, bandwidth testers measure speed, and toner probes trace cables.",
        "examTip": "Network analyzers (like Wireshark) are powerful tools for 'seeing' into your network traffic. They capture and decode packets, essential for advanced network troubleshooting and security analysis."
      },
      {
        "id": 85,
        "question": "Which virtualization technology focuses on isolating and virtualizing individual applications from the underlying operating system, allowing them to run in their own contained environment?",
        "options": [
          "Type 1 Hypervisor",
          "Type 2 Hypervisor",
          "Application Virtualization",
          "Containerization"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Application Virtualization focuses on isolating and virtualizing individual applications from the underlying operating system. This allows applications to run in their own contained environment, improving compatibility, portability, and manageability. Type 1 and 2 hypervisors virtualize entire OSes, and containerization virtualizes at the OS level.",
        "examTip": "Application virtualization is about isolating and virtualizing individual applications, not entire operating systems. This can be useful for compatibility, deployment, and sandboxing."
      },
      {
        "id": 86,
        "question": "Which expansion slot is typically used for installing video capture cards in desktop computers, requiring moderate bandwidth?",
        "options": [
          "PCIe x16",
          "PCIe x8",
          "PCIe x4",
          "PCIe x1"
        ],
        "correctAnswerIndex": 2,
        "explanation": "PCIe x4 (PCI Express x4) slots are often used for installing video capture cards in desktop computers, as they provide moderate bandwidth suitable for video capture and streaming. PCIe x16 is for GPUs, PCIe x8 for high-bandwidth peripherals, and PCIe x1 for lower-bandwidth cards.",
        "examTip": "PCIe x4 slots offer a middle ground – enough bandwidth for video capture cards and other peripherals that need more than x1 but less than graphics cards."
      },
      {
        "id": 87,
        "question": "What is the purpose of 'Trusted Platform Module' (TPM) in computer security?",
        "options": [
          "To manage network firewall rules.",
          "To securely store cryptographic keys and enable hardware-based encryption.",
          "To provide antivirus protection.",
          "To manage user authentication and authorization."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Trusted Platform Module (TPM) is a hardware security module used to securely store cryptographic keys and enable hardware-based encryption. TPMs enhance security for features like BitLocker, disk encryption, and secure boot by providing a tamper-resistant environment for cryptographic operations. Firewalls manage network security, antivirus protects against malware, and user authentication is a broader security function.",
        "examTip": "TPM is a hardware chip for enhanced security, especially for encryption. It securely stores cryptographic keys and is used by features like BitLocker."
      },
      {
        "id": 88,
        "question": "Which of the following network devices is also known as a 'Layer 2 firewall' and operates at the Data Link Layer of the OSI model, filtering traffic based on MAC addresses?",
        "options": [
          "Hub",
          "Switch with Access Control Lists (ACLs)",
          "Router with Firewall features",
          "Bridge with MAC filtering"
        ],
        "correctAnswerIndex": 3,
        "explanation": "A Bridge with MAC filtering is also known as a 'Layer 2 firewall' because it operates at the Data Link Layer and can filter traffic based on MAC addresses. Bridges can segment networks and control traffic flow based on MAC addresses, providing a basic form of Layer 2 security. Hubs are Layer 1, Switches with ACLs are more advanced Layer 2 firewalls, and Routers with firewalls operate at Layer 3 and above.",
        "examTip": "Bridges with MAC filtering act as basic Layer 2 firewalls. They can control network traffic based on MAC addresses, providing a simple form of network segmentation and access control."
      },
      {
        "id": 89,
        "question": "Which connector type is used for older parallel port connections, commonly used for printers and scanners on desktop computers?",
        "options": [
          "USB Type-A",
          "PS/2",
          "Centronics (36-pin Parallel)",
          "DB25 (25-pin Parallel)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "DB25 (25-pin Parallel) connectors are used for older parallel port connections, commonly used for printers and scanners on desktop computers. Centronics (36-pin) is another type of parallel printer connector, but DB25 is more associated with PC parallel ports. USB Type-A is modern, and PS/2 for mice/keyboards.",
        "examTip": "DB25 connectors are the older, D-shaped 25-pin parallel ports on PCs. They were standard for printers and scanners before USB became dominant."
      },
      {
        "id": 90,
        "question": "A laser printer is producing prints with vertical black lines or streaks down the page. Which printer consumable or component is MOST likely causing these black lines?",
        "options": [
          "Toner Cartridge",
          "Fuser Assembly",
          "Imaging Drum",
          "Transfer Belt or Roller"
        ],
        "correctAnswerIndex": 2,
        "explanation": "A damaged Imaging Drum is MOST likely causing vertical black lines or streaks on laser printer pages. Scratches or damage to the drum surface can cause excess toner to adhere in those areas, resulting in black lines in the printout. Toner cartridge issues more often cause faded prints or ghosting, fuser issues cause smearing, and transfer belt/roller problems affect image transfer consistency.",
        "examTip": "Vertical black lines or streaks on laser prints strongly indicate a scratch or damage to the imaging drum. Inspect the drum surface carefully for defects."
      },
      {
        "id": 91,
        "question": "What is the standard port number for NetBIOS Workstation Service over UDP?",
        "options": [
          "Port 137",
          "Port 138",
          "Port 139",
          "Port 445"
        ],
        "correctAnswerIndex": 0,
        "explanation": "Port 137 is the standard UDP port number for NetBIOS Name Service. While the question asks for 'NetBIOS Workstation Service over UDP', this is likely referring to the NetBIOS Name Service, which operates on UDP port 137 and is crucial for NetBIOS networking. Port 138 is for Datagram Service (UDP), Port 139 for Session Service (TCP), and Port 445 for SMB over TCP.",
        "examTip": "NetBIOS Name Service, operating on UDP port 137, is fundamental for NetBIOS networking, handling name registration and resolution."
      },
      {
        "id": 92,
        "question": "Which display technology typically offers the best combination of fast response times, wide viewing angles, and good color accuracy, making it a versatile choice for various applications?",
        "options": [
          "TN (Twisted Nematic)",
          "VA (Vertical Alignment)",
          "LED-backlit LCD",
          "IPS (In-Plane Switching)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "IPS (In-Plane Switching) display technology typically offers the best combination of fast response times (though not as fast as TN), wide viewing angles, and good color accuracy, making it a versatile choice for various applications, from general use to professional tasks. TN is fastest response but weaker colors/angles, VA has good contrast but narrower angles than IPS, and LED-backlit LCD is a backlight type, not a panel technology itself.",
        "examTip": "IPS panels are often considered the 'sweet spot' for general-purpose displays, offering a good balance of speed, viewing angles, and color accuracy for diverse uses."
      },
      {
        "id": 93,
        "question": "What is the purpose of implementing 'RAID 51' configuration?",
        "options": [
          "RAID 51 is not a standard RAID level.",
          "To provide data redundancy by mirroring.",
          "To improve read/write performance by striping only.",
          "To combine striping and parity with mirroring for enhanced performance and even greater fault tolerance."
        ],
        "correctAnswerIndex": 0,
        "explanation": "RAID 51 is not a standard, recognized RAID level in common usage. Standard RAID levels include 0, 1, 5, 6, 10 (1+0), and sometimes nested levels like 50 (5+0) and 60 (6+0). There is no widely recognized or standardized RAID level called RAID 51.",
        "examTip": "Be aware that RAID 51 is NOT a standard RAID level. Stick to the common and standardized RAID levels like 0, 1, 5, 6, and 10 for the exam."
      },
      {
        "id": 94,
        "question": "Which tool is used to test and verify the correct termination and wiring order of wires in a punchdown block or keystone jack?",
        "options": [
          "Cable tester",
          "Punchdown tool",
          "Tone generator and probe",
          "Multimeter"
        ],
        "correctAnswerIndex": 0,
        "explanation": "A Cable tester can be used to test and verify the correct termination and wiring order of wires in a punchdown block or keystone jack after using a punchdown tool. Some cable testers have features to check pinouts and wiring standards like T568A/B. Punchdown tools are for terminating wires, toner probes trace cables, and multimeters measure electrical properties.",
        "examTip": "After using a punchdown tool to terminate cables in patch panels or wall jacks, use a cable tester to verify that the wiring and pinouts are correct according to standards like T568A or T568B."
      },
      {
        "id": 95,
        "question": "Which virtualization technology allows multiple virtual machines to share the same physical hardware resources, improving resource utilization and efficiency?",
        "options": [
          "Application Virtualization",
          "Containerization",
          "Hardware Virtualization (using Hypervisors)",
          "Operating System Virtualization"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Hardware Virtualization (using Hypervisors) allows multiple virtual machines to share the same physical hardware resources, improving resource utilization and efficiency. Hypervisors enable resource sharing and allocation among VMs, maximizing hardware use. Application and containerization are different virtualization models focusing on application and OS levels, respectively.",
        "examTip": "Hardware virtualization with hypervisors is all about resource sharing. Multiple VMs run on the same physical hardware, improving efficiency and reducing hardware costs."
      },
      {
        "id": 96,
        "question": "Which expansion slot standard is commonly used for installing high-speed network interface cards (NICs) that require higher bandwidth than PCIe x1?",
        "options": [
          "PCIe x16",
          "PCIe x8",
          "PCIe x4",
          "PCIe x1"
        ],
        "correctAnswerIndex": 2,
        "explanation": "PCIe x4 (PCI Express x4) slots are commonly used for installing high-speed network interface cards (NICs) that require higher bandwidth than PCIe x1. For very high-speed networking (like 10 Gigabit Ethernet or faster), PCIe x4 provides sufficient bandwidth. PCIe x16 is for GPUs, and PCIe x8 is for even higher bandwidth peripherals.",
        "examTip": "PCIe x4 slots offer a good balance of bandwidth and size for high-speed network cards and other peripherals that need more bandwidth than x1."
      },
      {
        "id": 97,
        "question": "What is the purpose of 'Fast Boot' or 'Quick Boot' option in BIOS/UEFI settings?",
        "options": [
          "To encrypt the boot process.",
          "To speed up the system startup process by skipping some hardware initialization steps.",
          "To secure the boot process against malware.",
          "To manage the boot order priority."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Fast Boot or Quick Boot option in BIOS/UEFI settings is designed to speed up the system startup process by skipping some hardware initialization steps and POST (Power-On Self-Test) checks. While it reduces boot time, it may also skip some error detection and hardware initialization. It's not for encryption, security, or boot order management.",
        "examTip": "Fast Boot (or Quick Boot) speeds up boot times by skipping some hardware checks. It's a trade-off between speed and thoroughness of system initialization."
      },
      {
        "id": 98,
        "question": "Which of the following network devices is also known as a 'Layer 3 firewall' and operates at the Network Layer of the OSI model, filtering traffic based on IP addresses and protocols?",
        "options": [
          "Hub",
          "Switch",
          "Router with Firewall features",
          "Bridge"
        ],
        "correctAnswerIndex": 3,
        "explanation": "Routers with Firewall features are also known as 'Layer 3 firewalls'. They operate at the Network Layer and filter traffic based on IP addresses, protocols, and ports. This is the traditional type of firewall that controls network access based on network layer information. Hubs are Layer 1, Switches Layer 2, and Bridges are Layer 2 firewalls.",
        "examTip": "Routers with firewall features are the classic Layer 3 firewalls. They filter traffic based on IP addresses, ports, and protocols, controlling network access at the network layer."
      },
      {
        "id": 99,
        "question": "Which connector type is used for older serial joystick and MIDI (Musical Instrument Digital Interface) connections on desktop computers?",
        "options": [
          "USB Type-A",
          "PS/2",
          "Centronics (36-pin Parallel)",
          "DB15 (15-pin D-sub) or Gameport"
        ],
        "correctAnswerIndex": 3,
        "explanation": "DB15 (15-pin D-sub) connectors, also known as Gameports, are used for older serial joystick and MIDI (Musical Instrument Digital Interface) connections on desktop computers. USB has replaced these for modern peripherals. PS/2 is for mice/keyboards, and Centronics for parallel printers.",
        "examTip": "DB15 (Gameport) connectors are the older, 15-pin D-sub connectors used for joysticks and MIDI devices. They are legacy ports, largely replaced by USB."
      },
      {
        "id": 100,
        "question": "A laser printer is producing prints with a light gray background or 'fog' across the entire page, even in areas that should be white. Which printer consumable or component is MOST likely causing this background fog issue?",
        "options": [
          "Toner Cartridge (if toner is incompatible or low quality)",
          "Fuser Assembly",
          "Discharge Lamp or Erase Lamp (failing to neutralize drum charge)",
          "Paper Type Setting (incorrect paper type)"
        ],
        "correctAnswerIndex": 2,
        "explanation": "A failing Discharge Lamp or Erase Lamp is MOST likely causing a light gray background or 'fog' across the entire page in a laser printer. If the discharge lamp is not effectively neutralizing the charge on the drum, residual charge attracts toner even in non-image areas, resulting in background fog. Toner cartridge, fuser assembly, and paper settings are less likely to cause uniform background fog.",
        "examTip": "Background 'fog' or a light gray background on laser prints often points to a problem with the discharge lamp or erase lamp not properly neutralizing the drum charge. These are key components in the laser printing process."
      }
    ]
  },
  {
    "_id": {
      "$oid": "GENERATED_OBJECT_ID_TEST6_1"
    },
    "category": "aplus",
    "testId": 6,
    "testName": "A+ Practice Test #6 (Formidable)",
    "xpPerCorrect": 10,
    "questions": [
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
        "explanation": "RAID 5 is MOST suitable in this scenario. RAID 5 provides fault tolerance (single drive failure) and improved read performance through striping with parity, while also offering relatively good usable storage capacity compared to RAID 1 and RAID 10. RAID 1 is mirroring with 50% capacity, RAID 10 also has reduced capacity due to mirroring, and RAID 6 offers better fault tolerance (two drive failures) but can be more complex and have slightly lower write performance than RAID 5.",
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
        "examTip": "Flickering or distorted laptop displays, especially when moving the screen, often point to a loose or damaged display cable connection. Check the cable and its connections first in such cases."
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
        "examTip": "Network segmentation (VLANs, subnets) is a key security practice. It limits the 'blast radius' of security incidents and improves network organization and performance."
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
        "question": "Which display technology typically offers the best contrast ratio and color accuracy, combined with very fast response times, but is currently more expensive and less common in mainstream displays?",
        "options": [
          "TN (Twisted Nematic)",
          "VA (Vertical Alignment)",
          "LED-backlit LCD",
          "OLED (Organic Light Emitting Diode)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "OLED (Organic Light Emitting Diode) technology typically offers the best combination of contrast ratio, color accuracy, and very fast response times. OLEDs excel in all these areas but are currently more expensive to produce and less common in mainstream displays compared to LCD technologies. TN is fastest but weaker in color/contrast, VA is a balance, and LED-backlit LCD is a backlight type, not a panel technology itself.",
        "examTip": "OLEDs are 'top-tier' in display quality, combining excellent contrast, color, and response times, but they come at a higher cost and are less common in everyday displays compared to LCDs."
      },
      {
        "id": 26,
        "question": "What is the purpose of implementing 'RAID 61' (or RAID 6+1) configuration?",
        "options": [
          "RAID 61 is not a standard RAID level.",
          "To provide data redundancy by mirroring.",
          "To improve read/write performance by striping only.",
          "To combine mirroring and dual parity for enhanced fault tolerance and some performance improvement."
        ],
        "correctAnswerIndex": 0,
        "explanation": "RAID 61 (or RAID 6+1) is not a standard, recognized RAID level. While RAID 10 (1+0), RAID 50 (5+0), and RAID 60 (6+0) are nested RAID levels, RAID 61 is not a standard configuration. It might be a misnomer or a custom, non-standard configuration. Stick to recognized RAID levels for the exam.",
        "examTip": "RAID 61 is NOT a standardized RAID level. Focus on understanding and remembering the common RAID levels like 0, 1, 5, 6, 10, 50, and 60 for the CompTIA A+ exam."
      },
      {
        "id": 27,
        "question": "Which tool is used to measure the signal strength and identify channel usage of wireless networks, aiding in Wi-Fi troubleshooting and optimization?",
        "options": [
          "Cable tester",
          "Bandwidth tester",
          "Wi-Fi analyzer",
          "Multimeter"
        ],
        "correctAnswerIndex": 2,
        "explanation": "A Wi-Fi analyzer is used to measure the signal strength and identify channel usage of wireless networks. It provides detailed information about Wi-Fi signal levels, channel overlap, network SSIDs, and other parameters, which is invaluable for Wi-Fi troubleshooting and optimization. Cable testers are for wired cables, bandwidth testers measure speed, and multimeters are for electrical testing.",
        "examTip": "Wi-Fi analyzers are the 'spectrum analyzers' for wireless networks. They help you understand the wireless environment, identify interference, and optimize channel selection for better Wi-Fi performance."
      },
      {
        "id": 28,
        "question": "Which virtualization technology allows for running applications in isolated environments by creating lightweight, portable, and self-contained units that include everything needed to run an application?",
        "options": [
          "Type 1 Hypervisor",
          "Type 2 Hypervisor",
          "Application Virtualization",
          "Containerization"
        ],
        "correctAnswerIndex": 3,
        "explanation": "Containerization allows for running applications in isolated environments by creating lightweight, portable, and self-contained units called containers. Containers package applications and their dependencies, ensuring consistent execution across different environments. Type 1 and 2 hypervisors virtualize entire OSes, and application virtualization virtualizes individual applications without the same level of environment containment as containers.",
        "examTip": "Containers are 'application packages' that are lightweight, portable, and self-contained. They include everything an application needs to run, making them great for portability and consistent deployment."
      },
      {
        "id": 29,
        "question": "Which expansion slot is typically used for installing high-speed storage controllers, like NVMe SSD controllers, that require very high bandwidth?",
        "options": [
          "PCIe x16",
          "PCIe x8",
          "PCIe x4",
          "M.2 slot"
        ],
        "correctAnswerIndex": 1,
        "explanation": "PCIe x8 (PCI Express x8) slots are often used for installing high-speed storage controllers, like NVMe SSD controllers, that require very high bandwidth, especially when connecting multiple NVMe drives via a single controller card. While M.2 slots directly host M.2 NVMe SSDs, PCIe x8 slots are for controller cards that can manage multiple M.2 or other high-speed storage devices. PCIe x16 is mainly for GPUs, and PCIe x4 may be insufficient for very high-bandwidth storage controllers.",
        "examTip": "PCIe x8 slots are important for high-performance storage controllers, especially for NVMe SSDs. They offer the bandwidth needed to handle multiple fast drives."
      },
      {
        "id": 30,
        "question": "What is the purpose of enabling 'Boot Logging' in Windows Advanced Boot Options?",
        "options": [
          "To encrypt the boot process.",
          "To speed up the system boot process.",
          "To create a log file of drivers and services loaded during startup for troubleshooting boot issues.",
          "To secure the boot process against malware."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Enabling 'Boot Logging' in Windows Advanced Boot Options creates a log file (ntbtlog.txt) that records the drivers and services loaded (or failed to load) during system startup. This log file is invaluable for troubleshooting boot issues, especially startup failures or slow boot times caused by driver or service problems. It's not for encryption, boot speed, or boot security itself.",
        "examTip": "Boot Logging in Windows is a troubleshooting tool. It creates a log file of the boot process, helping you diagnose startup problems by showing which drivers or services are failing to load."
      },
      {
        "id": 31,
        "question": "What is the standard port number for SNMP Traps?",
        "options": [
          "Port 161",
          "Port 162",
          "Port 443",
          "Port 53"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Port 162 (UDP) is the standard port number for SNMP Traps. SNMP agents send unsolicited trap messages to a management station on port 162 to report events or alerts. Port 161 (UDP) is for SNMP management requests. Ports 443 and 53 are for HTTPS and DNS, respectively.",
        "examTip": "SNMP Traps use UDP port 162 to send event notifications from managed devices to a central SNMP manager. Remember 162 for SNMP traps."
      },
      {
        "id": 32,
        "question": "Which display technology is known for its emissive nature, wide viewing angles, and extremely high contrast ratio, but may suffer from 'color shifting' at extreme viewing angles?",
        "options": [
          "TN (Twisted Nematic)",
          "VA (Vertical Alignment)",
          "LED-backlit LCD",
          "OLED (Organic Light Emitting Diode)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "OLED (Organic Light Emitting Diode) technology is known for its emissive nature, wide viewing angles, and extremely high contrast ratio. While OLEDs generally have excellent viewing angles, some specific OLED panel types, especially older or lower-quality ones, can exhibit slight 'color shifting' or color inaccuracies at very extreme viewing angles. However, this is less pronounced than in TN panels and continuously improving in newer OLEDs. TN panels have significant color shifting at off-axis views, while VA panels are better but still not as angle-stable as IPS or OLED.",
        "examTip": "While OLEDs have wide viewing angles, be aware that some OLED panels may exhibit slight color shifting at very extreme off-axis views. This is a minor trade-off compared to their overall superior display quality."
      },
      {
        "id": 33,
        "question": "What is the primary purpose of implementing 'RAID 0+1' (or RAID 01) configuration?",
        "options": [
          "To provide data redundancy using parity.",
          "To improve read/write performance by striping only.",
          "To combine striping and mirroring for both performance and redundancy, prioritizing redundancy.",
          "To create a large storage volume by spanning drives without any redundancy."
        ],
        "correctAnswerIndex": 3,
        "explanation": "RAID 0+1 (or RAID 01) primarily aims to combine striping (RAID 0) and mirroring (RAID 1) for both performance and redundancy, prioritizing redundancy over raw performance compared to RAID 10. RAID 0+1 mirrors striped sets, meaning if a striped set fails, the mirrored set is still available. RAID 5 and 6 use parity, RAID 0 is striping only, and spanning (JBOD) lacks redundancy.",
        "examTip": "RAID 0+1 (RAID 01) prioritizes redundancy slightly over performance compared to RAID 10. It mirrors striped sets, offering good protection and decent speed, but can be less efficient than RAID 10 in some scenarios."
      },
      {
        "id": 34,
        "question": "Which tool is used to create and manage network cable terminations, specifically inserting wires into insulation displacement connectors (IDCs) on patch panels and keystone jacks?",
        "options": [
          "Cable tester",
          "Bandwidth tester",
          "Punchdown tool",
          "Toner probe"
        ],
        "correctAnswerIndex": 2,
        "explanation": "A Punchdown tool is specifically designed to create and manage network cable terminations by inserting wires into insulation displacement connectors (IDCs) on patch panels and keystone jacks. This tool ensures proper connection and termination of individual wires in structured cabling. Cable testers verify wiring, bandwidth testers measure speed, and toner probes trace cables.",
        "examTip": "Punchdown tools are essential for structured cabling. They are used to terminate wires into patch panels and wall jacks, ensuring solid and reliable connections."
      },
      {
        "id": 35,
        "question": "Which virtualization technology allows for running multiple instances of the same operating system on a single host, sharing the kernel and system libraries, making it lightweight and efficient?",
        "options": [
          "Type 1 Hypervisor",
          "Type 2 Hypervisor",
          "Application Virtualization",
          "Containerization"
        ],
        "correctAnswerIndex": 3,
        "explanation": "Containerization allows for running multiple instances of the same operating system on a single host, sharing the kernel and system libraries. This OS-level virtualization makes containers lightweight and efficient compared to full VMs, as they avoid the overhead of running multiple OS kernels. Type 1 and 2 hypervisors virtualize entire OSes, and application virtualization focuses on individual applications.",
        "examTip": "Containers excel at running multiple instances of the SAME OS efficiently. They are lightweight because they share the host OS kernel, unlike VMs that each need a full OS."
      },
      {
        "id": 36,
        "question": "Which expansion slot is typically used for installing legacy sound cards and other older expansion cards that are not compatible with PCIe?",
        "options": [
          "PCIe x16",
          "PCIe x8",
          "PCIe x4",
          "PCI (Conventional PCI)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "PCI (Conventional PCI) slots are typically used for installing legacy sound cards and other older expansion cards that are not compatible with the newer PCIe standard. PCI is an older, parallel bus standard, still present on some motherboards for backward compatibility. PCIe x16, x8, and x4 are all PCIe standards, not compatible with older PCI cards.",
        "examTip": "PCI slots are for legacy expansion cards that predate PCIe. They offer backward compatibility for older hardware, like some older sound cards and specialized interface cards."
      },
      {
        "id": 37,
        "question": "What is the purpose of disabling 'Wake-on-LAN' (WOL) in BIOS/UEFI settings?",
        "options": [
          "To improve network speed.",
          "To enhance system security by preventing unauthorized remote wake-ups.",
          "To speed up the system boot process.",
          "To reduce power consumption when the system is shut down."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Disabling 'Wake-on-LAN' (WOL) in BIOS/UEFI settings primarily enhances system security by preventing unauthorized remote wake-ups. WOL allows a computer to be powered on remotely via a network signal, which can be a security vulnerability if not properly controlled. Disabling WOL reduces this risk. While it might slightly reduce power consumption, security is the main reason to disable it. Boot speed and network speed are not directly affected by WOL.",
        "examTip": "Disabling Wake-on-LAN (WOL) is a security measure to prevent unauthorized remote power-ons. It closes a potential security loophole."
      },
      {
        "id": 38,
        "question": "Which of the following network devices is also known as a 'Layer 7 firewall' or 'Application Firewall' and operates at the Application Layer of the OSI model, filtering traffic based on application-specific protocols and content?",
        "options": [
          "Hub",
          "Switch",
          "Router with Firewall features",
          "Next-Generation Firewall (NGFW)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "Next-Generation Firewalls (NGFWs) are also known as 'Layer 7 firewalls' or 'Application Firewalls'. They operate at the Application Layer of the OSI model, allowing them to filter traffic based on application-specific protocols, content, and user behavior, going beyond port and protocol filtering of traditional firewalls. Hubs, switches, and routers with basic firewalls operate at lower layers.",
        "examTip": "Next-Generation Firewalls (NGFWs) are 'application-aware'. They can filter traffic based on the actual applications being used, offering much finer-grained security control."
      },
      {
        "id": 39,
        "question": "Which connector type is used for older serial printer connections on desktop computers, often using a 25-pin connector?",
        "options": [
          "USB Type-A",
          "PS/2",
          "Centronics (36-pin Parallel)",
          "DB25 (25-pin Serial)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "DB25 (25-pin Serial) connectors are used for older serial printer connections on desktop computers. Although less common for printers than parallel ports, some older printers used serial DB25 connections. Centronics (36-pin) is for parallel printers, USB Type-A is modern, and PS/2 for mice/keyboards.",
        "examTip": "DB25 connectors can be serial OR parallel, depending on context. In the context of *printers*, DB25 usually refers to older SERIAL printer connections, distinct from the more common Centronics parallel ports."
      },
      {
        "id": 40,
        "question": "A laser printer is producing prints with completely black pages. Which printer consumable or component is MOST likely causing this overprinting issue?",
        "options": [
          "Toner Cartridge (if overfilled)",
          "Fuser Assembly (stuck in fusing mode)",
          "Primary Corona Wire or Grid (failure causing continuous charge)",
          "Paper Type Setting (incorrect paper type)"
        ],
        "correctAnswerIndex": 2,
        "explanation": "A faulty Primary Corona Wire or Grid is MOST likely causing completely black pages on a laser printer. If the primary corona wire fails in a way that it continuously charges the drum uniformly without allowing for selective discharge by the laser, the entire drum will attract toner, resulting in a black page print. Toner cartridge, fuser assembly, and paper settings are less likely to cause completely black pages.",
        "examTip": "Completely black pages from a laser printer usually point to a charging system problem, most likely a fault in the primary corona wire or grid, causing the drum to be uniformly charged and attracting toner everywhere."
      },
      {
        "id": 41,
        "question": "What is the standard port number for LDAP Secure (LDAPS) protocol?",
        "options": [
          "Port 389",
          "Port 636",
          "Port 443",
          "Port 53"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Port 636 is the standard TCP port number for LDAPS (LDAP Secure), which is LDAP over SSL/TLS, providing encrypted directory access. Port 389 is for unencrypted LDAP, Port 443 for HTTPS, and Port 53 for DNS.",
        "examTip": "LDAPS (Secure LDAP) uses port 636. Remember it's the secure, encrypted version of LDAP using SSL/TLS."
      },
      {
        "id": 42,
        "question": "Which display technology often uses 'local dimming' to improve contrast ratio and black levels, especially in high-end LED-backlit LCD TVs?",
        "options": [
          "TN (Twisted Nematic)",
          "VA (Vertical Alignment)",
          "OLED (Organic Light Emitting Diode)",
          "LED-backlit LCD with Full-Array Local Dimming (FALD)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "LED-backlit LCD with Full-Array Local Dimming (FALD) is the technology that often uses 'local dimming' to significantly improve contrast ratio and black levels in high-end LED-backlit LCD TVs. FALD allows different zones of the backlight to be dimmed or turned off independently, improving black levels and contrast. TN, VA, and standard LED-backlit LCDs without local dimming do not offer this level of contrast enhancement.",
        "examTip": "Full-Array Local Dimming (FALD) is a backlight technology in LCDs that significantly improves contrast and black levels by dimming or turning off LEDs in dark areas of the screen."
      },
      {
        "id": 43,
        "question": "What is the primary purpose of implementing 'RAID 6' configuration?",
        "options": [
          "To provide data redundancy by mirroring.",
          "To improve read/write performance by striping only.",
          "To provide enhanced fault tolerance by using dual parity, allowing for up to two drive failures.",
          "To create a large storage volume by spanning drives without any redundancy."
        ],
        "correctAnswerIndex": 2,
        "explanation": "RAID 6 is primarily implemented to provide enhanced fault tolerance by using dual parity, allowing for up to two simultaneous drive failures without data loss. RAID 6 stripes data across at least four drives and uses two independent parity calculations. RAID 1 is mirroring, RAID 0 is striping only, and spanning (JBOD) lacks redundancy.",
        "examTip": "RAID 6 is for 'high fault tolerance'. It can survive two drive failures, making it very robust for critical data, but it has a higher overhead due to dual parity calculations."
      },
      {
        "id": 44,
        "question": "Which tool is used to measure and test the output power and voltage stability of a computer power supply unit (PSU) under load?",
        "options": [
          "Cable tester",
          "Power supply tester or Multimeter with load tester",
          "Wi-Fi analyzer",
          "Toner probe"
        ],
        "correctAnswerIndex": 1,
        "explanation": "A Power supply tester or a Multimeter with a load tester is BEST suited for measuring and testing the output power and voltage stability of a PSU under load. PSU testers are dedicated devices for this purpose, and multimeters with load testers allow for more detailed voltage measurements under different load conditions. Cable testers, Wi-Fi analyzers, and toner probes are not for PSU testing.",
        "examTip": "Use a PSU tester or a multimeter with a load tester to thoroughly test a power supply's output voltages and stability under load. This is crucial for diagnosing power-related issues."
      },
      {
        "id": 45,
        "question": "Which virtualization technology commonly uses 'containers' and 'container images' for application deployment and portability, often associated with Docker and Kubernetes?",
        "options": [
          "Type 1 Hypervisor",
          "Type 2 Hypervisor",
          "Application Virtualization",
          "Containerization"
        ],
        "correctAnswerIndex": 3,
        "explanation": "Containerization commonly uses 'containers' and 'container images' for application deployment and portability. Technologies like Docker and Kubernetes are built around containerization, enabling efficient packaging, deployment, and management of applications in isolated containers. Hypervisors virtualize entire OSes, and application virtualization focuses on individual applications.",
        "examTip": "Containers and container images are core concepts in containerization technologies like Docker and Kubernetes. They are designed for application portability and efficient deployment."
      },
      {
        "id": 46,
        "question": "Which expansion slot is typically used for installing TV tuner cards and other video capture devices that require moderate bandwidth?",
        "options": [
          "PCIe x16",
          "PCIe x8",
          "PCIe x4",
          "PCIe x1"
        ],
        "correctAnswerIndex": 2,
        "explanation": "PCIe x4 (PCI Express x4) slots are often used for installing TV tuner cards and other video capture devices that require moderate bandwidth for video data transfer. PCIe x16 is for GPUs, PCIe x8 for high-bandwidth peripherals, and PCIe x1 for lower-bandwidth cards. PCIe x4 offers a good balance for video capture needs.",
        "examTip": "PCIe x4 slots are a good fit for video capture cards and other peripherals that need moderate bandwidth for video or data processing, falling between x1 and x8 in terms of bandwidth capacity."
      },
      {
        "id": 47,
        "question": "What is the purpose of implementing 'Boot Guard' or 'Measured Boot' technologies in UEFI firmware?",
        "options": [
          "To improve system boot speed.",
          "To encrypt the boot process.",
          "To enhance boot process security by verifying the integrity of boot components and preventing rootkits.",
          "To manage the boot order priority."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Boot Guard or Measured Boot technologies in UEFI firmware enhance boot process security by verifying the integrity of boot components and preventing rootkits. These technologies measure and verify the digital signatures of boot components, ensuring that only trusted and unmodified bootloaders and OS components are loaded, thus protecting against boot-level malware. It's not for boot speed, encryption, or boot order management.",
        "examTip": "Boot Guard and Measured Boot are advanced security features in UEFI to protect against boot-level malware and rootkits by verifying the integrity of boot components."
      },
      {
        "id": 48,
        "question": "Which of the following network devices is considered a 'Layer 4 firewall' and operates at the Transport Layer of the OSI model, filtering traffic based on TCP and UDP ports and connection state?",
        "options": [
          "Hub",
          "Switch",
          "Router with basic Packet Filtering",
          "Stateful Firewall"
        ],
        "correctAnswerIndex": 3,
        "explanation": "Stateful Firewalls are considered 'Layer 4 firewalls' as they operate at the Transport Layer and filter traffic based on TCP and UDP ports, as well as connection state. Stateful firewalls track the state of network connections, allowing more sophisticated filtering rules based on connection context. Hubs and switches operate at lower layers, and routers with basic packet filtering are less state-aware.",
        "examTip": "Stateful firewalls are 'connection-aware'. They track the state of network connections and can filter traffic based on connection context, providing more granular security than stateless packet filters."
      },
      {
        "id": 49,
        "question": "Which connector type is used for older serial null modem cable connections, commonly used for direct computer-to-computer serial communication?",
        "options": [
          "USB Type-A",
          "PS/2",
          "Centronics (36-pin Parallel)",
          "DB9 (9-pin Serial)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "DB9 (9-pin Serial) connectors are used for older serial null modem cable connections. Null modem cables, using DB9 connectors, allow for direct computer-to-computer serial communication without modems. USB and PS/2 are not serial, and Centronics is parallel.",
        "examTip": "DB9 serial connectors and null modem cables were used for direct computer-to-computer serial communication, often for file transfer or terminal emulation in older setups."
      },
      {
        "id": 50,
        "question": "A laser printer is producing prints with a repeating pattern of random dots or speckling across the page. Which printer consumable or component is MOST likely causing this speckling issue?",
        "options": [
          "Toner Cartridge (if toner is leaking)",
          "Fuser Assembly (if uneven heating)",
          "Imaging Drum (if scratched or damaged)",
          "Paper Feed Mechanism (if picking up dust)"
        ],
        "correctAnswerIndex": 0,
        "explanation": "A Toner Cartridge issue, specifically if the toner cartridge is leaking or has a defect causing toner leakage, is MOST likely causing a repeating pattern of random dots or speckling across the page. Leaking toner can deposit randomly on the drum or paper path, resulting in speckling. Fuser, drum, and paper feed issues typically cause different types of print defects.",
        "examTip": "Speckling or random dots on laser prints often indicate a toner cartridge issue, especially if toner is leaking or the cartridge is defective. Check for toner leaks and try replacing the cartridge."
      }
    ]
  },
  {
    "_id": {
      "$oid": "GENERATED_OBJECT_ID_TEST6_17"
    },
    "category": "aplus",
    "testId": 6,
    "testName": "A+ Practice Test #6 (Formidable)",
    "xpPerCorrect": 10,
    "questions": [
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
        "examTip": "Flickering or distorted laptop displays, especially when moving the screen, often point to a loose or damaged display cable connection. Check the cable and its connections first in such cases."
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
        "examTip": "Network segmentation (VLANs, subnets) is a key security practice. It limits the 'blast radius' of security incidents and improves network organization and performance."
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
        "question": "Which of these is a cloud storage service?",
        "options": [
          "Microsoft Word",
          "Adobe Photoshop",
          "Google Drive",
          "Mozilla Firefox"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Google Drive is a cloud storage service, allowing you to store files online and access them from anywhere. Microsoft Word and Adobe Photoshop are applications, and Mozilla Firefox is a web browser. Exam tip: Google Drive, Dropbox, OneDrive are cloud storage examples.",
        "examTip": "Cloud storage like Google Drive, Dropbox, and OneDrive lets you store files online, accessible anywhere."
      },
      {
        "id": 26,
        "question": "What is the purpose of 'passwords' in computer security?",
        "options": [
          "To speed up computer startup",
          "To protect user accounts from unauthorized access",
          "To organize files and folders",
          "To enhance internet browsing speed"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Passwords are used to protect user accounts from unauthorized access, ensuring only the account owner can log in. They don't speed up startup, organize files, or enhance browsing speed. Exam tip: Passwords = account security.",
        "examTip": "Passwords are your first line of defense for your accounts. Choose strong and unique ones."
      },
      {
        "id": 27,
        "question": "Which of the following is an output device?",
        "options": [
          "Microphone",
          "Webcam",
          "Printer",
          "Scanner"
        ],
        "correctAnswerIndex": 2,
        "explanation": "A printer is an output device, producing physical copies of digital documents. Microphones and webcams are input devices, and scanners are for digitizing input. Exam tip: Output devices show results *from* the computer.",
        "examTip": "Output devices like printers and monitors show you the computer's output – what it's 'telling' you."
      },
      {
        "id": 28,
        "question": "What does 'URL' stand for?",
        "options": [
          "Universal Resource Locator",
          "Uniform Record Locator",
          "Universal Routing Link",
          "Uniform Resource Locator"
        ],
        "correctAnswerIndex": 3,
        "explanation": "URL stands for Uniform Resource Locator. It's the address of a resource on the internet, like a website. The other options are not the correct expansion. Exam tip: URLs are website addresses.",
        "examTip": "Uniform Resource Locator (URL) is the web address. It tells your browser where to go."
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
        "explanation": "Android is a mobile operating system, primarily used on smartphones and tablets. Windows 10 and macOS are desktop OSes, and Linux is versatile but not primarily mobile-focused in its common distributions. Exam tip: Android and iOS are leading mobile OSes.",
        "examTip": "Android and iOS power most smartphones. They are designed for mobile devices."
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
        "explanation": "Software updates are primarily released to improve performance, fix bugs, and enhance security. They don't delete files, change themes, or uninstall apps as their main function. Exam tip: Updates = performance + security.",
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
        "explanation": "A USB port is a common type of computer port, used to connect peripherals. Ethernet cables are cables, power cords supply power, and monitor screens are displays. Exam tip: USB, HDMI, Ethernet are common ports.",
        "examTip": "USB ports are everywhere! They're the standard for connecting most peripherals."
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
        "explanation": "ISP stands for Internet Service Provider. Companies like Comcast or Verizon are ISPs, providing internet access. The other options are not the correct expansions. Exam tip: ISP = your internet access company.",
        "examTip": "Internet Service Provider (ISP) is who you pay for internet access. Think of companies like Comcast, Verizon, etc."
      },
      {
        "id": 33,
        "question": "Which of the following is a type of computer virus?",
        "options": [
          "Web browser",
          "Firewall",
          "Trojan horse",
          "Operating system"
        ],
        "correctAnswerIndex": 2,
        "explanation": "A Trojan horse is a type of computer virus, disguised as legitimate software to trick users. Web browsers and operating systems are software types, and firewalls are security systems. Exam tip: Trojan, Worm, Ransomware are malware types.",
        "examTip": "Trojan horses, worms, and ransomware are all types of malware that can harm your system."
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
        "explanation": "A printer driver translates computer commands into a language the printer understands, enabling communication. It's not for physical installation, ink refilling, or network troubleshooting directly. Exam tip: Drivers = hardware communication facilitators.",
        "examTip": "Printer drivers act as translators, allowing your computer to 'talk' to your printer."
      },
      {
        "id": 35,
        "question": "Which of these is a common type of internet browser?",
        "options": [
          "Microsoft Word",
          "Excel",
          "Google Chrome",
          "PowerPoint"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Google Chrome is a common internet browser, used to access websites. Microsoft Word, Excel, and PowerPoint are office applications. Exam tip: Chrome, Firefox, Safari, Edge are browsers.",
        "examTip": "Chrome, Firefox, Safari, and Edge are your main web browsers. They let you surf the internet."
      },
      {
        "id": 36,
        "question": "What is 'email' used for?",
        "options": [
          "Watching videos online",
          "Sending and receiving digital messages",
          "Playing online games",
          "Creating presentations"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Email is used for sending and receiving digital messages electronically. Video watching, gaming, and presentations are different functions. Exam tip: Email = electronic mail, for messages.",
        "examTip": "Email is electronic mail – a way to send and receive messages digitally."
      },
      {
        "id": 37,
        "question": "Which of the following is a storage medium that uses flash memory?",
        "options": [
          "Hard Disk Drive (HDD)",
          "Solid State Drive (SSD)",
          "Optical Disc (DVD)",
          "Floppy Disk"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Solid State Drives (SSDs) use flash memory for data storage, offering faster speeds and durability than HDDs. HDDs are magnetic disks, DVDs are optical, and floppy disks are outdated magnetic media. Exam tip: SSDs = flash memory storage.",
        "examTip": "Solid State Drives (SSDs) are fast and use flash memory, unlike traditional Hard Disk Drives (HDDs)."
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
        "explanation": "A monitor is an output device used to display images and video from a computer. Keyboards input text, printers print, and speakers play audio. Exam tip: Monitors = visual display.",
        "examTip": "Monitors are your visual output. They display what the computer is 'showing' you."
      },
      {
        "id": 39,
        "question": "Which of these is a type of network protocol?",
        "options": [
          "Keyboard",
          "Monitor",
          "TCP/IP",
          "Mouse"
        ],
        "correctAnswerIndex": 2,
        "explanation": "TCP/IP (Transmission Control Protocol/Internet Protocol) is a fundamental network protocol, the basis of internet communication. Keyboards, monitors, and mice are hardware devices. Exam tip: TCP/IP, HTTP, FTP are network protocols.",
        "examTip": "TCP/IP is the basic language of the internet. It's the foundation for network communication."
      },
      {
        "id": 40,
        "question": "What is 'data backup'?",
        "options": [
          "Deleting unnecessary files",
          "Creating copies of important data for recovery",
          "Speeding up computer performance",
          "Organizing files into folders"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Data backup involves creating copies of important data so it can be recovered in case of data loss. It's not about deleting files, speeding up performance, or just organizing files. Exam tip: Backups = data recovery.",
        "examTip": "Data backups are your safety net. They protect you from data loss due to hardware failure or accidents."
      },
      {
        "id": 41,
        "question": "Which port is commonly used for connecting a printer to a computer?",
        "options": [
          "Ethernet port (RJ45)",
          "USB port",
          "HDMI port",
          "Audio port"
        ],
        "correctAnswerIndex": 1,
        "explanation": "USB ports are commonly used for connecting printers to computers. Ethernet is for network connections, HDMI for video, and audio for sound. Exam tip: USB is versatile for peripherals, including printers.",
        "examTip": "USB is a very common port for printers. It's a standard connection method."
      },
      {
        "id": 42,
        "question": "What is 'cloud computing'?",
        "options": [
          "Using only desktop applications",
          "Storing and accessing data and programs over the internet",
          "Using only wired network connections",
          "Processing data only on local computers"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Cloud computing is about storing and accessing data and programs over the internet, rather than directly on your computer. It's not limited to desktop apps, wired networks, or local processing. Exam tip: Cloud = internet-based services.",
        "examTip": "Cloud computing means your data and applications are in the 'cloud' – on remote servers accessible via the internet."
      },
      {
        "id": 43,
        "question": "Which of these is a function of a 'web server'?",
        "options": [
          "To browse websites",
          "To host and deliver website content",
          "To send emails",
          "To manage computer hardware"
        ],
        "correctAnswerIndex": 1,
        "explanation": "A web server's function is to host and deliver website content to users who request it through web browsers. Browsing is done by clients, email by mail servers, and hardware management by operating systems. Exam tip: Web servers = website hosts.",
        "examTip": "Web servers are the 'hosts' of websites. They store and serve up web pages to users."
      },
      {
        "id": 44,
        "question": "What is 'phishing' in cybersecurity?",
        "options": [
          "Improving network speed",
          "A type of antivirus software",
          "Deceptive attempts to steal personal information",
          "Creating strong passwords"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Phishing is a deceptive attempt to steal personal information (like passwords or credit card details) by disguising as a trustworthy entity, often via email or fake websites. It's not about speed, antivirus, or password creation itself. Exam tip: Phishing = information theft scam.",
        "examTip": "Phishing is a trick to steal your info. Be wary of emails and websites asking for personal details."
      },
      {
        "id": 45,
        "question": "Which component is essential for cooling the CPU in a computer?",
        "options": [
          "Power supply unit (PSU)",
          "Heat sink",
          "RAM module",
          "Network Interface Card (NIC)"
        ],
        "correctAnswerIndex": 1,
        "explanation": "A heat sink is essential for cooling the CPU, dissipating heat generated by the processor. PSU supplies power, RAM is memory, and NIC is for networking. Exam tip: Heat sink + fan = CPU cooling.",
        "examTip": "Heat sinks and fans are crucial for keeping your CPU cool and preventing overheating."
      },
      {
        "id": 46,
        "question": "What is the purpose of 'disk defragmentation'?",
        "options": [
          "To delete files permanently",
          "To reorganize files on a hard drive for faster access",
          "To increase storage capacity",
          "To install new software"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Disk defragmentation reorganizes files on a hard drive to improve access speed by reducing fragmentation. It doesn't delete files, increase capacity, or install software. Exam tip: Defrag = faster HDD access.",
        "examTip": "Disk defragmentation is like tidying up your hard drive to make it run faster, especially for HDDs."
      },
      {
        "id": 47,
        "question": "Which of these is a common type of optical storage media?",
        "options": [
          "SSD",
          "HDD",
          "DVD",
          "USB flash drive"
        ],
        "correctAnswerIndex": 2,
        "explanation": "DVD (Digital Versatile Disc) is a common type of optical storage media, using lasers to read and write data. SSDs are flash memory, HDDs are magnetic disks, and USB drives are flash memory too. Exam tip: DVD, CD, Blu-ray are optical media.",
        "examTip": "DVDs, CDs, and Blu-ray discs are optical storage. They use lasers to read data."
      },
      {
        "id": 48,
        "question": "What is the function of a 'graphics card' or 'GPU'?",
        "options": [
          "To manage network connections",
          "To process and display images and video",
          "To store files and documents",
          "To regulate power supply"
        ],
        "correctAnswerIndex": 1,
        "explanation": "A graphics card (GPU) is responsible for processing and displaying images and video on a monitor. NICs handle networking, storage devices store files, and PSUs regulate power. Exam tip: GPU = graphics processing.",
        "examTip": "Graphics cards (GPUs) are dedicated to processing and displaying visuals. They are essential for gaming and video editing."
      },
      {
        "id": 49,
        "question": "Which of the following is a type of computer network based on geographic scale?",
        "options": [
          "USB network",
          "Bluetooth network",
          "Local Area Network (LAN)",
          "Powerline network"
        ],
        "correctAnswerIndex": 2,
        "explanation": "A Local Area Network (LAN) is defined by its geographic scale, typically covering a small area like an office or home. USB, Bluetooth, and Powerline are connection types, not geographic network scales. Exam tip: LAN, WAN, MAN are geographic network types.",
        "examTip": "LAN (Local Area Network) is your home or office network – a network in a limited area."
      },
      {
        "id": 50,
        "question": "What is the purpose of 'cookies' in web browsing?",
        "options": [
          "To block advertisements",
          "To store small pieces of data about your browsing activity",
          "To speed up website loading times",
          "To protect against viruses"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Cookies are small pieces of data websites store on your computer to remember information about your browsing activity, like preferences or login status. They are not for ad blocking, speeding up websites directly, or virus protection. Exam tip: Cookies = website memory.",
        "examTip": "Cookies are small files websites use to remember you and your preferences, enhancing your browsing experience (and sometimes tracking you)."
      },
      {
        "id": 51,
        "question": "Which of these is a common tool for diagnosing network connectivity issues?",
        "options": [
          "Microsoft Word",
          "Ping command",
          "Adobe Photoshop",
          "Excel"
        ],
        "correctAnswerIndex": 1,
        "explanation": "The 'ping' command is a common tool for diagnosing network connectivity issues by testing if a host is reachable. Word, Photoshop, and Excel are applications, not network tools. Exam tip: Ping, Tracert, Ipconfig are network diagnostic tools.",
        "examTip": "The 'ping' command is your basic network connectivity test. It checks if you can 'reach' another computer."
      },
      {
        "id": 52,
        "question": "What does 'VPN' stand for in network security?",
        "options": [
          "Virtual Private Network",
          "Very Personal Network",
          "Volume Protection Network",
          "Verified Public Node"
        ],
        "correctAnswerIndex": 0,
        "explanation": "VPN stands for Virtual Private Network. It creates a secure, encrypted connection over a less secure network like the internet. The other options are not the correct expansions. Exam tip: VPN = secure, private network connection.",
        "examTip": "Virtual Private Network (VPN) creates a secure tunnel for your internet traffic, protecting your privacy."
      },
      {
        "id": 53,
        "question": "Which of these is a type of computer case form factor, often used for smaller PCs?",
        "options": [
          "ATX",
          "Micro-ATX",
          "Full Tower",
          "Server Rack"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Micro-ATX is a type of computer case form factor, smaller than standard ATX, and often used for compact PCs. ATX and Full Tower are larger form factors, and Server Rack is for server systems. Exam tip: ATX, Micro-ATX, Mini-ITX are common form factors.",
        "examTip": "Micro-ATX is a smaller motherboard and case form factor, good for compact PCs."
      },
      {
        "id": 54,
        "question": "What is the purpose of 'system restore' in Windows?",
        "options": [
          "To delete all personal files",
          "To revert system settings and files to a previous state",
          "To speed up system performance",
          "To install new software"
        ],
        "correctAnswerIndex": 1,
        "explanation": "System Restore in Windows allows you to revert system settings and files to a previous point in time, often used to undo system changes that caused problems. It doesn't delete files, speed up performance directly, or install software. Exam tip: System Restore = undo system changes.",
        "examTip": "System Restore is like a 'time machine' for your Windows system settings. It can undo changes if something goes wrong."
      },
      {
        "id": 55,
        "question": "Which of these is a common type of connector for audio output?",
        "options": [
          "VGA",
          "HDMI",
          "3.5mm audio jack",
          "DVI"
        ],
        "correctAnswerIndex": 2,
        "explanation": "A 3.5mm audio jack is a common connector for audio output, used for headphones and speakers. VGA, HDMI, and DVI are primarily video connectors, though HDMI can carry audio as well. Exam tip: 3.5mm jack = standard audio connector.",
        "examTip": "The 3.5mm audio jack is the standard for headphones and speakers on most computers and devices."
      },
      {
        "id": 56,
        "question": "What is 'spam' email?",
        "options": [
          "Important emails from banks",
          "Unsolicited, unwanted emails, often advertisements",
          "Emails with attachments",
          "Emails from known contacts"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Spam email is unsolicited, unwanted email, often advertisements or phishing attempts, sent in bulk. It's not important, wanted, or necessarily from known contacts. Exam tip: Spam = junk email.",
        "examTip": "Spam is junk email – unwanted and often unsolicited messages, usually trying to sell you something or scam you."
      },
      {
        "id": 57,
        "question": "Which of the following is a type of mobile device?",
        "options": [
          "Desktop tower",
          "Server rack",
          "Smartphone",
          "Mainframe computer"
        ],
        "correctAnswerIndex": 2,
        "explanation": "A smartphone is a type of mobile device, designed for portability and mobile use. Desktop towers and mainframes are stationary, and server racks are for server systems. Exam tip: Smartphones, tablets, laptops = mobile devices.",
        "examTip": "Smartphones, tablets, and laptops are all mobile devices – designed to be carried around and used on the go."
      },
      {
        "id": 58,
        "question": "What is the function of a 'power supply unit' (PSU) in a computer?",
        "options": [
          "To cool down the CPU",
          "To provide power to computer components",
          "To store data",
          "To manage network connections"
        ],
        "correctAnswerIndex": 1,
        "explanation": "The Power Supply Unit (PSU) provides power to all computer components, converting AC power from the mains and outputs multiple DC voltages (3.3V, 5V, 12V). A UPS is wrong because it provides backup power but does not directly convert AC to DC for the PC. The motherboard regulator fine-tunes voltages but doesn’t create them from AC. An LCD inverter is related to laptop displays, not desktop power. Exam tip: Remember that desktop PSUs handle AC to DC conversion.'              
      },
      {
        "id": 59,
        "question": "Which of these is a type of network cable connector?",
        "options": [
          "USB connector",
          "HDMI connector",
          "RJ45 connector",
          "Audio jack"
        ],
        "correctAnswerIndex": 2,
        "explanation": "RJ45 is a type of connector used for Ethernet network cables. USB and HDMI are for peripherals and video, and audio jacks are for sound. Exam tip: RJ45 = Ethernet cable connector.",
        "examTip": "RJ45 connectors are for Ethernet cables. Recognize them as network cable ends."
      },
      {
        "id": 60,
        "question": "What is 'computer hardware'?",
        "options": [
          "The physical parts of a computer system",
          "Software programs",
          "Online services",
          "Digital documents"
        ],
        "correctAnswerIndex": 0,
        "explanation": "Computer hardware refers to the physical parts of a computer system, like the CPU, RAM, HDD, etc. Software is programs, online services are internet-based, and documents are data files. Exam tip: Hardware = physical components.",
        "examTip": "Computer hardware is the tangible, physical parts of your computer – what you can touch."
      },
      {
        "id": 61,
        "question": "Which of these is a common type of computer software?",
        "options": [
          "Keyboard",
          "Monitor",
          "Operating system",
          "CPU"
        ],
        "correctAnswerIndex": 2,
        "explanation": "An operating system is a type of computer software, managing hardware and software resources. Keyboards, monitors, and CPUs are hardware components. Exam tip: OS, Applications, Drivers are software types.",
        "examTip": "Operating Systems, applications like Word, and drivers are all types of computer software – the instructions for the hardware."
      },
      {
        "id": 62,
        "question": "Which type of memory is volatile, meaning it loses its data when power is turned off?",
        "options": [
          "ROM (Read-Only Memory)",
          "Flash Memory",
          "RAM (Random Access Memory)",
          "Hard Disk Drive (HDD)"
        ],
        "correctAnswerIndex": 2,
        "explanation": "RAM (Random Access Memory) is volatile memory; it requires power to maintain the stored information. ROM, Flash Memory, and HDDs are non-volatile, retaining data without power. Exam tip: Volatile memory loses data when power is off.",
        "examTip": "RAM is volatile memory – it's temporary and loses data when you turn off the computer. Think of it as short-term memory."
      },
      {
        "id": 63,
        "question": "Which of the following is an example of 'system software'?",
        "options": [
          "Microsoft Word",
          "Google Chrome",
          "Operating System (like Windows)",
          "Adobe Photoshop"
        ],
        "correctAnswerIndex": 2,
        "explanation": "An Operating System (like Windows) is system software, managing hardware and providing a platform for applications. Word, Chrome, and Photoshop are application software. Exam tip: System software manages the system itself.",
        "examTip": "System software like the OS is fundamental. It makes the hardware usable and runs application software."
      },
      {
        "id": 64,
        "question": "What is the function of 'Device Manager' in Windows?",
        "options": [
          "To manage files and folders",
          "To manage hardware devices and drivers",
          "To browse the internet",
          "To edit photos"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Device Manager in Windows is used to manage hardware devices and their drivers, troubleshooting hardware issues. File management is done by File Explorer, browsing by web browsers, and photo editing by image editors. Exam tip: Device Manager = hardware management.",
        "examTip": "Device Manager is your tool to see and manage all the hardware connected to your Windows computer and their drivers."
      },
      {
        "id": 65,
        "question": "Which of these is a common type of wireless security protocol?",
        "options": [
          "HTTP",
          "FTP",
          "WPA2",
          "TCP/IP"
        ],
        "correctAnswerIndex": 2,
        "explanation": "WPA2 (Wi-Fi Protected Access 2) is a common wireless security protocol, encrypting Wi-Fi connections. HTTP and FTP are web and file transfer protocols, and TCP/IP is a network protocol suite. Exam tip: WPA2, WPA3, WEP are wireless security protocols.",
        "examTip": "WPA2 and WPA3 are security protocols for Wi-Fi. They encrypt your wireless connection to keep it safe."
      },
      {
        "id": 66,
        "question": "What is 'cloud backup'?",
        "options": [
          "Backing up data to a local hard drive",
          "Backing up data to remote servers over the internet",
          "Deleting old backups",
          "Speeding up backup process"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Cloud backup involves backing up data to remote servers accessed over the internet, providing offsite data protection. Local backups are to local drives, and deleting backups or speeding up is not the definition of cloud backup itself. Exam tip: Cloud backup = offsite, internet backup.",
        "examTip": "Cloud backup means your backups are stored remotely in the cloud, protected from local disasters."
      },
      {
        "id": 67,
        "question": "Which of these is a type of connector used for video?",
        "options": [
          "RJ45",
          "USB",
          "VGA",
          "RJ11"
        ],
        "correctAnswerIndex": 2,
        "explanation": "VGA (Video Graphics Array) is a type of connector specifically used for video signals, primarily older analog displays. RJ45 is for Ethernet, USB is versatile, and RJ11 is for telephone lines. Exam tip: VGA, HDMI, DisplayPort, DVI are video connectors.",
        "examTip": "VGA, HDMI, DisplayPort, and DVI are all types of video connectors for monitors and displays."
      },
      {
        "id": 68,
        "question": "What is the purpose of 'Task Manager' in Windows?",
        "options": [
          "To manage files and folders",
          "To manage running applications and processes",
          "To browse the internet",
          "To edit system settings"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Task Manager in Windows is used to manage running applications and processes, monitor system performance, and end unresponsive tasks. File management is by File Explorer, browsing by browsers, and system settings by Control Panel/Settings. Exam tip: Task Manager = process and performance management.",
        "examTip": "Task Manager is your Windows tool to see what programs are running and to end unresponsive applications."
      },
      {
        "id": 69,
        "question": "Which of these is a type of wired internet connection?",
        "options": [
          "Wi-Fi",
          "Cellular",
          "DSL",
          "Satellite"
        ],
        "correctAnswerIndex": 2,
        "explanation": "DSL (Digital Subscriber Line) is correct because it is a wired internet connection, using telephone lines. Wi-Fi, Cellular, and Satellite are wireless internet technologies. Exam tip: DSL, Cable, Fiber are wired internet connections.",
        "examTip": "DSL, Cable, and Fiber internet are all wired connections that come into your home or office via cables."
      },
      {
        "id": 70,
        "question": "What is 'social engineering' in cybersecurity?",
        "options": [
          "Improving social media presence",
          "Manipulating people to gain confidential information",
          "Designing social networking software",
          "Creating social media accounts"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Social engineering in cybersecurity is manipulating people into divulging confidential information or performing actions. It's not about social media presence, software design, or account creation. Exam tip: Social engineering = human manipulation for info.",
        "examTip": "Social engineering attacks target humans, tricking them into giving up information or doing something they shouldn't."
      },
      {
        "id": 71,
        "question": "Which component is responsible for storing the operating system, applications, and data files long-term?",
        "options": [
          "RAM",
          "CPU",
          "Hard Disk Drive (HDD) or Solid State Drive (SSD)",
          "Motherboard"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Hard Disk Drives (HDDs) and Solid State Drives (SSDs) are responsible for long-term storage of the OS, applications, and data files. RAM is for active memory, CPU is the processor, and the motherboard is the main circuit board. Exam tip: HDD/SSD = long-term storage.",
        "examTip": "HDDs and SSDs are your computer's long-term storage. They hold everything even when powered off."
      },
      {
        "id": 72,
        "question": "What is the function of 'Control Panel' in Windows?",
        "options": [
          "To manage files and folders",
          "To configure system settings and hardware",
          "To browse the internet",
          "To run applications"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Control Panel in Windows is used to configure system settings and hardware, manage user accounts, etc. File management is by File Explorer, browsing by browsers, and running apps directly. Exam tip: Control Panel = system settings configuration.",
        "examTip": "Control Panel is the traditional Windows tool for configuring system settings and hardware. (Settings app is the modern counterpart)."
      },
      {
        "id": 73,
        "question": "Which of these is a common type of connector for connecting peripherals like keyboards and mice?",
        "options": [
          "Ethernet port",
          "HDMI port",
          "USB port",
          "VGA port"
        ],
        "correctAnswerIndex": 2,
        "explanation": "USB ports are commonly used for connecting peripherals like keyboards and mice. Ethernet is for network, HDMI for video, and VGA for older video. Exam tip: USB is versatile for peripherals.",
        "examTip": "USB ports are the most common for connecting peripherals like keyboards, mice, printers, and more."
      },
      {
        "id": 74,
        "question": "What is 'spyware'?",
        "options": [
          "Software that protects against viruses",
          "Software that secretly monitors user activity",
          "Software for creating presentations",
          "Software for managing system updates"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Spyware is software that secretly monitors user activity and collects information without consent. It's not antivirus, presentation software, or update management software. Exam tip: Spyware = secret monitoring software.",
        "examTip": "Spyware is malicious software that secretly watches what you do on your computer, often stealing personal information."
      },
      {
        "id": 75,
        "question": "Which of the following is a type of motherboard form factor, often used in laptops?",
        "options": [
          "ATX",
          "Micro-ATX",
          "Mini-ITX",
          "Proprietary Form Factors (Smaller Laptop Boards)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "While not a standard 'form factor' name, laptops often use proprietary, smaller form factor motherboards designed to fit specific laptop models, often smaller than even Mini-ITX. ATX, Micro-ATX, and Mini-ITX are desktop form factors. Exam tip: Laptops use compact, often proprietary boards.",
        "examTip": "Laptops use smaller, often custom-designed motherboards to fit their compact size."
      },
      {
        "id": 76,
        "question": "What is the purpose of 'Safe Mode' in Windows?",
        "options": [
          "To speed up system performance",
          "To start Windows with minimal drivers and services for troubleshooting",
          "To permanently delete files",
          "To install new hardware"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Safe Mode in Windows starts the OS with minimal drivers and services, primarily for troubleshooting system issues. It's not for speeding up performance, deleting files, or installing hardware directly. Exam tip: Safe Mode = troubleshooting startup mode.",
        "examTip": "Safe Mode is your troubleshooting mode in Windows. It starts with minimal drivers to help you fix problems."
      },
      {
        "id": 77,
        "question": "Which of these is a common type of connector for connecting to a network?",
        "options": [
          "Audio jack",
          "USB port",
          "Ethernet port",
          "HDMI port"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Ethernet ports are commonly used for wired network connections. Audio jacks are for sound, USB for peripherals, and HDMI for video. Exam tip: Ethernet port = network connection.",
        "examTip": "Ethernet ports are for wired network connections. They're often labeled with a network icon."
      },
      {
        "id": 78,
        "question": "What is 'ransomware'?",
        "options": [
          "Software that improves system security",
          "Malware that encrypts files and demands payment for decryption",
          "Software for creating backups",
          "Software for managing passwords"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Ransomware is malware that encrypts a victim's files and demands a ransom (payment) for the decryption key. It's not for security, backups, or password management. Exam tip: Ransomware = file encryption malware.",
        "examTip": "Ransomware is scary malware! It locks up your files and demands money to unlock them."
      },
      {
        "id": 79,
        "question": "Which type of memory is non-volatile, retaining data even when power is off?",
        "options": [
          "RAM (Random Access Memory)",
          "Cache Memory",
          "ROM (Read-Only Memory)",
          "SDRAM"
        ],
        "correctAnswerIndex": 2,
        "explanation": "ROM (Read-Only Memory) is non-volatile memory, retaining data even when power is off. RAM, Cache, and SDRAM are volatile. Exam tip: Non-volatile memory keeps data without power.",
        "examTip": "ROM (Read-Only Memory) is non-volatile – it keeps data even when the computer is turned off. Think of it as permanent memory."
      },
      {
        "id": 80,
        "question": "Which of the following is an example of 'application software'?",
        "options": [
          "Operating System (like macOS)",
          "Device Drivers",
          "Microsoft Word",
          "BIOS/UEFI"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Microsoft Word is application software, designed for specific user tasks like document creation. Operating Systems and Device Drivers are system software, and BIOS/UEFI is firmware. Exam tip: Application software for user tasks.",
        "examTip": "Application software is what you use to do tasks – like Word for writing, Chrome for browsing, etc."
      },
      {
        "id": 81,
        "question": "What is the function of 'Disk Cleanup' in Windows?",
        "options": [
          "To manage files and folders",
          "To remove temporary files and free up disk space",
          "To browse the internet",
          "To edit system settings"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Disk Cleanup in Windows is used to remove temporary files and free up disk space, improving system performance. Device Manager handles device drivers. Task Manager monitors processes and performance. Services.msc is for managing Windows services. Exam tip: Disk Management is your go-to for disk partition tasks in Windows.'                                                    
      },
      {
        "id": 82,
        "question": "Which of these is a common type of port for connecting to a display?",
        "options": [
          "Ethernet port",
          "USB port",
          "HDMI port",
          "Audio port"
        ],
        "correctAnswerIndex": 2,
        "explanation": "HDMI ports are commonly used for connecting to displays, carrying both video and audio. Ethernet is for network, USB for peripherals, and audio for sound. Exam tip: HDMI, VGA, DisplayPort, DVI for displays.",
        "examTip": "HDMI is a key video port. It's designed for high-definition displays and carries both video and audio."
      },
      {
        "id": 83,
        "question": "What is 'adware'?",
        "options": [
          "Software that blocks advertisements",
          "Software that displays advertisements, often unwanted",
          "Software for managing system updates",
          "Software for creating documents"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Adware is software that displays advertisements, often unwanted and intrusive, sometimes bundled with free software. It's not for ad blocking, updates, or document creation. Exam tip: Adware = advertisement-displaying software.",
        "examTip": "Adware is software that bombards you with ads. It's often bundled with free programs."
      },
      {
        "id": 84,
        "question": "Which component is often referred to as the 'brain' of the computer?",
        "options": [
          "RAM",
          "CPU",
          "Hard Disk Drive (HDD)",
          "Motherboard"
        ],
        "correctAnswerIndex": 1,
        "explanation": "The CPU (Central Processing Unit) is often referred to as the 'brain' of the computer, performing calculations and executing instructions. RAM is memory, HDD is storage, and the motherboard is the circuit board. Exam tip: CPU = computer 'brain'.",
        "examTip": "The CPU is the 'brain' of the computer. It does all the processing and calculations."
      },
      {
        "id": 85,
        "question": "What is the purpose of 'file compression'?",
        "options": [
          "To delete files",
          "To reduce the size of files",
          "To speed up computer performance",
          "To encrypt files for security"
        ],
        "correctAnswerIndex": 1,
        "explanation": "File compression is used to reduce the size of files, making them easier to store and transfer. It doesn't delete files, speed up performance directly, or primarily encrypt files. Exam tip: Compression = smaller file size.",
        "examTip": "File compression makes files smaller, saving space and making them faster to transfer online."
      },
      {
        "id": 86,
        "question": "Which of these is a common type of removable storage media?",
        "options": [
          "SSD",
          "HDD",
          "USB flash drive",
          "Motherboard"
        ],
        "correctAnswerIndex": 2,
        "explanation": "USB flash drives are common removable storage media, easily portable and rewritable. SSDs and HDDs are typically internal or external fixed drives, and motherboards are internal components. Exam tip: USB drives, memory cards = removable storage.",
        "examTip": "USB flash drives and memory cards are your everyday removable storage – easy to carry and transfer data."
      },
      {
        "id": 87,
        "question": "What is the function of a 'network switch'?",
        "options": [
          "To connect multiple networks together",
          "To connect devices within a local network",
          "To provide internet access",
          "To protect against viruses"
        ],
        "correctAnswerIndex": 1,
        "explanation": "A network switch connects devices within a local network, enabling communication between them. Routers connect networks, modems provide internet access, and antivirus protects against viruses. Exam tip: Switch = local network device connector.",
        "examTip": "Network switches are like traffic cops within your local network, directing data between devices connected to the same network."
      },
      {
        "id": 88,
        "question": "What is 'pharming' in cybersecurity?",
        "options": [
          "Improving farm technology",
          "Redirecting website traffic to fake sites",
          "Creating strong passwords",
          "Scanning for viruses"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Pharming in cybersecurity is redirecting website traffic to fake (often malicious) websites, often by compromising DNS servers. It's not about farm tech, passwords, or virus scanning. Exam tip: Pharming = website redirection scam.",
        "examTip": "Pharming is a sneaky attack that redirects you to fake websites, even if you type the correct address. It's like being secretly rerouted."
      },
      {
        "id": 89,
        "question": "Which of the following is a performance-based benefit of implementing RAID 0 for storage?",
        "options": [
          "Fault tolerance",
          "Parity-based redundancy",
          "Striping for increased read/write speed",
          "Mirroring for quick recovery"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Striping for increased read/write speed is correct because RAID 0 splits data across multiple disks, boosting performance. Fault tolerance is lacking in RAID 0. Parity-based redundancy is RAID 5/6, and mirroring is RAID 1/10. Exam tip: RAID 0 trades redundancy for raw speed.'                                                                          
      },
      {
        "id": 90,
        "question": "A technician wants to boot a system from a network image rather than a local drive. Which BIOS/UEFI setting must be enabled to use PXE (Preboot eXecution Environment)?",                                                                                           
        options": [
          "Integrated NIC with PXE support",
          "VT-x (Intel) or AMD-V",
          "Secure Boot",
          "Fast Boot"
        ],
        "correctAnswerIndex": 0,
        "explanation": "Integrated NIC with PXE support is correct for network boot. VT-x/AMD-V are for virtualization. Secure Boot checks digital signatures but doesn’t handle PXE specifically. Fast Boot skips some POST checks. Exam tip: PXE requires an enabled network interface with boot ROM or “Network Boot” setting.'                                                    
      },
      {
        "id": 91,
        "question": "A user’s mobile device frequently fails to charge unless the cable is held at a certain angle. Which is the MOST likely issue?",                                       
        options": [
          "Damaged battery causing slow charging",
          "Incorrect OS version installed",
          "Faulty charging port or loose connector",
          "Insufficient mobile data signal"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Faulty charging port or loose connector is correct because if the cable must be positioned precisely, the port is likely damaged. A damaged battery typically shows quick discharges, not needing cable angles. OS version doesn’t cause physical charging issues. Mobile data signal affects connectivity, not charging. Exam tip: Worn or bent charging ports are a common hardware fault on mobile devices.'                                            
      },
      {
        "id": 92,
        "question": "Which command-line tool can help verify the path data takes from a local computer to a remote host, listing each hop along the route?",                                
        options": [
          "ping",
          "ipconfig",
          "nslookup",
          "tracert (Windows)/traceroute (Linux)"
        ],
        "correctAnswerIndex": 3,
        "explanation": "tracert (Windows) or traceroute (Linux) is correct because it shows each router hop en route to the destination. ping tests basic connectivity. ipconfig shows local IP settings. nslookup queries DNS. Exam tip: Use tracert/traceroute to diagnose where a connection fails along the path.'                                                                
      },
      {
        "id": 93,
        "question": "A technician needs to install a 2.5" HDD into a desktop. Which adapter or mounting solution is MOST commonly required?",                                               
        options": [
          "3.5" to 2.5" drive bay adapter',
          "USB to eSATA cable",
          "Server rackmount rails",
          "M.2 to PCI Express riser"
        ],
        "correctAnswerIndex": 0,
        "explanation": "A 3.5" to 2.5" drive bay adapter is correct because desktop bays are usually 3.5". A USB-to-eSATA cable is for external connectivity. Server rack rails are for rack-mounted systems. An M.2 to PCIe riser is for M.2 SSDs, not SATA 2.5" drives. Exam tip: Always match the physical form factor with an adapter or bracket if needed.'                      
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
  }
]
