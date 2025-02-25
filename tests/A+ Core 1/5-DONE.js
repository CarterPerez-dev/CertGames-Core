db.tests.insertOne({
    "category": "aplus",
    "testId": 5,
    "testName": "A+ Core 1 Practice Test #5 (Intermediate)",
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
        "question": "Performance-Based Question: A user reports they cannot access the Internet, but they can successfully ping other devices on the local network. Which sequence of troubleshooting steps is MOST logical?",
        "options": [
          "1) Power cycle the router, 2) Update the network card drivers, 3) Check TCP/IP settings, 4) Verify DNS server entries",
          "1) Check TCP/IP settings, 2) Verify DNS server entries, 3) Power cycle the router, 4) Update the network card drivers",
          "1) Check for IP conflicts, 2) Assign static IP, 3) Disable the firewall, 4) Replace the NIC",
          "1) Perform a full OS reinstall, 2) Swap out all Ethernet cables, 3) Power cycle the entire network, 4) Configure a new user account"
        ],
        "correctAnswerIndex": 1,
        "explanation": "A methodical approach to network troubleshooting begins with confirming TCP/IP settings. Next, verify DNS server configurations to ensure name resolution works. If the issue persists, power cycle the router to eliminate temporary hardware or configuration glitches. Finally, update the network card drivers to rule out driver compatibility issues.",
        "examTip": "Always rule out simple configuration errors and DNS misconfigurations before moving on to more time-consuming solutions like driver updates or hardware replacements."
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
        "question": "Performance-Based Question: A user’s Windows system boots to a blank screen after POST. You suspect a boot configuration issue. Which series of steps should be taken FIRST to diagnose and correct the problem?",
        "options": [
          "1) Replace the motherboard, 2) Replace the hard drive, 3) Reinstall Windows, 4) Run Startup Repair",
          "1) Check the power supply voltages, 2) Boot into Safe Mode, 3) Run System File Checker, 4) Defragment the system drive",
          "1) Boot from Windows installation media, 2) Open Recovery Command Prompt, 3) Run bootrec /fixmbr and bootrec /fixboot, 4) Reboot the system",
          "1) Pull the CMOS battery, 2) Boot into BIOS, 3) Disable Secure Boot, 4) Enable virtualization support"
        ],
        "correctAnswerIndex": 2,
        "explanation": "When Windows fails to boot past a blank screen, use the installation media to access repair tools. Running commands like 'bootrec /fixmbr' and 'bootrec /fixboot' repairs the Master Boot Record and boot sector, often resolving corrupted boot configuration issues. A simple reboot can confirm if the fix was successful.",
        "examTip": "Master Boot Record (MBR) and boot sector issues are common causes for Windows boot failures. Familiarize yourself with command-line repair utilities for quick fixes in a test environment—and real world scenarios!"
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
  });
