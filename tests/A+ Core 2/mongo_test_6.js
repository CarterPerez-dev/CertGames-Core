db.tests.insertOne({
  "category": "aplus2",
  "testId": 6,
  "testName": "Practice Test #6 (Formidable)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A user reports their Windows 10 workstation is intermittently losing connection to a specific network share. Other users are not experiencing this issue.  You've verified the user's credentials and permissions are correct, and `ping` tests to the file server are successful.  Network connectivity is otherwise stable. What is the MOST likely cause, and how would you address it?",
      "options": [
        "The file server is overloaded; increase its resources.",
        "The user's network cable is faulty; replace it.",
        "The SMB (Server Message Block) protocol version compatibility between the client and server is mismatched; check and adjust SMB settings on both.",
        "The user's DNS server settings are incorrect; update them."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Intermittent connectivity to a specific share, while other network functions are normal, suggests a protocol-level issue. SMB version mismatches (e.g., the server only supports SMBv3, but the client is trying SMBv1) can cause this. Server overload would likely affect all users. A faulty cable would cause more general connectivity problems. Incorrect DNS would prevent initial connection, not intermittent drops.",
      "examTip": "Be aware of SMB protocol version compatibility issues, especially in mixed environments with older and newer Windows systems."
    },
    {
      "id": 2,
      "question": "You are investigating a suspected malware infection on a Windows workstation.  You observe numerous outbound connections to unusual ports and IP addresses that you don't recognize. You need to identify the specific process responsible for these connections and determine if it's legitimate.  Which combination of command-line tools would be MOST effective for this investigation?",
      "options": [
        "`ping` and `tracert`",
        "`ipconfig /all` and `nslookup`",
        "`netstat -ano` and `tasklist /fi \"pid eq <PID>\"` (replacing `<PID>` with the actual process ID)",
        "`chkdsk` and `sfc /scannow`"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`netstat -ano` displays active connections with the owning Process ID (PID). You can then use `tasklist /fi \"pid eq <PID>\"` to filter the task list and show details for the specific process identified by netstat. The other options are less targeted for this scenario.",
      "examTip": "Combine `netstat -ano` and `tasklist` (or Task Manager) to link network connections to specific processes for malware investigation."
    },
    {
      "id": 3,
      "question": "A user reports their workstation is behaving erratically, with programs crashing and unexpected system restarts. They recently installed several new applications from various sources. You suspect a software conflict or a potentially unwanted program (PUP). What's the BEST approach to diagnose and resolve this issue?",
      "options": [
        "Immediately reinstall the operating system.",
        "Run a full system scan with antivirus and anti-malware software, then boot into Safe Mode and selectively disable recently installed applications and startup programs to identify the culprit.",
        "Run System Restore to revert to the last known good configuration.",
        "Increase the size of the paging file."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A combination of malware scans and selectively disabling software in Safe Mode is the most methodical approach. Malware scans address potential PUPs. Safe Mode isolates the problem by loading only essential drivers and services. System Restore might work, but it's a broader solution and might not pinpoint the specific cause. Reinstalling the OS is too drastic. Increasing the paging file addresses memory issues, not software conflicts.",
      "examTip": "Use a combination of malware scans and Safe Mode troubleshooting to isolate and resolve software conflicts or PUP-related issues."
    },
    {
      "id": 4,
      "question": "You are troubleshooting a network connectivity issue where users cannot access a specific website.  `ping` to the website's domain name fails, but `ping` to the website's IP address succeeds.  `nslookup` resolves the domain name to the correct IP address. What is the MOST likely cause of this problem?",
      "options": [
        "A DNS server problem.",
        "A routing problem.",
        "A firewall or web filter is blocking access to the website based on its domain name.",
        "The website's server is down."
      ],
      "correctAnswerIndex": 2,
      "explanation": "If ping to the IP address works but ping to the domain name fails and nslookup resolves correctly, the issue is not DNS resolution itself. The most likely cause is a security device (firewall, web filter, proxy) that is blocking access based on the domain name, while allowing direct IP access. A routing problem would likely prevent both pings. If the server were down, the IP ping would also fail.",
      "examTip": "If ping by IP works but ping by domain name fails, despite correct nslookup resolution, suspect filtering or blocking based on the domain name."
    },
    {
      "id": 5,
      "question": "You are configuring a secure wireless network in a corporate environment. You need to implement strong authentication and encryption, and you want to use a centralized authentication server. Which combination of technologies would BEST meet these requirements?",
      "options": [
        "WEP and a shared password.",
        "WPA2-Personal with a strong pre-shared key.",
        "WPA2-Enterprise with 802.1X authentication using a RADIUS server.",
        "WPA3-Personal with a weak password."
      ],
      "correctAnswerIndex": 2,
      "explanation": "WPA2-Enterprise (or WPA3-Enterprise) with 802.1X authentication provides the strongest security for corporate environments. It uses a RADIUS server for centralized user authentication, rather than a shared password. WEP is insecure. WPA2-Personal uses a shared key, which is less secure for a corporate setting. WPA3-Personal is good, but Enterprise is better for centralized management.",
      "examTip": "Use WPA2/WPA3-Enterprise with 802.1X and a RADIUS server for robust, centrally managed wireless security in corporate environments."
    },
    {
      "id": 6,
      "question": "A user's Windows workstation is exhibiting extremely slow performance, and the hard drive activity light is constantly illuminated. You open Task Manager and see very high disk utilization, but no single process is obviously consuming all disk resources. What tool would provide the MOST granular detail about which specific *files* are being accessed and causing the bottleneck?",
      "options": [
        "Task Manager (Performance tab)",
        "Resource Monitor (Disk tab)",
        "Performance Monitor",
        "Disk Defragmenter"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Resource Monitor's Disk tab shows detailed disk I/O activity, including the specific files being read from and written to, along with the processes accessing them. Task Manager's Performance tab shows overall disk utilization, but not file-level detail. Performance Monitor can track disk activity, but Resource Monitor is more directly suited for immediate troubleshooting. Disk Defragmenter optimizes file layout, not real-time file access.",
      "examTip": "Use Resource Monitor's Disk tab to pinpoint specific files causing high disk I/O and identify potential bottlenecks."
    },
    {
      "id": 7,
      "question": "A Linux server is experiencing intermittent network connectivity issues. You suspect a problem with the network interface card (NIC). Which command would provide the MOST detailed information about the NIC's status, including driver details, link status, and potential errors?",
      "options": [
        "ifconfig",
        "ip a",
        "ethtool <interface_name> (e.g., ethtool eth0)",
        "netstat -i"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`ethtool` is a powerful utility specifically for querying and controlling network device drivers and hardware settings. It provides detailed information about the NIC, including link speed, duplex mode, driver version, and error statistics. `ifconfig` and `ip a` show interface configuration, but less detail about the hardware itself. `netstat -i` shows interface statistics, but not as comprehensively as `ethtool`.",
      "examTip": "Use `ethtool` on Linux systems to diagnose NIC problems and gather detailed information about the network interface hardware."
    },
    {
      "id": 8,
      "question": "A user reports that their Windows computer is randomly freezing, requiring a hard reboot. This happens even when the system is idle. You've ruled out overheating and malware. What is the NEXT most likely hardware component to investigate, and what tool would you use?",
      "options": [
        "Hard drive; run `chkdsk`.",
        "RAM; run Windows Memory Diagnostic.",
        "CPU; run a CPU stress test utility.",
        "Network adapter; run the Windows Network Troubleshooter."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Random freezes, even at idle, are often caused by faulty RAM. Windows Memory Diagnostic is the built-in tool to test RAM for errors. `chkdsk` checks the hard drive, a CPU stress test would be relevant if the freezes happened under load, and the Network Troubleshooter is for connectivity issues.",
      "examTip": "Thoroughly test RAM (with Windows Memory Diagnostic or Memtest86) when troubleshooting random system freezes or instability."
    },
    {
      "id": 9,
      "question": "You are designing a backup strategy for a small business. They have a limited budget but need to ensure data recovery in case of a disaster. They have one file server with critical data. Which backup scheme provides the BEST balance of data protection, recovery speed, and cost-effectiveness?",
      "options": [
        "Full backups only, performed daily.",
        "Incremental backups only, performed daily.",
        "A combination of weekly full backups and daily differential backups, with offsite storage.",
        "No backups, relying on RAID for redundancy."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Weekly full backups combined with daily differential backups provide a good balance. Full backups create a complete copy, while differential backups only copy changes since the last full backup, making restores faster than with incremental backups (which require multiple sets). Offsite storage protects against physical disasters. Full backups only are storage-intensive. Incremental backups only are slow to restore. RAID provides redundancy, not backup.",
      "examTip": "Combine full and differential (or incremental) backups, and always store backups offsite, for a robust and cost-effective backup strategy."
    },
    {
      "id": 10,
      "question": "You are responding to a security incident where a user's workstation is suspected of being compromised. You need to preserve the system's current state for forensic analysis. What is the MOST important FIRST step?",
      "options": [
        "Run a full system scan with antivirus software.",
        "Disconnect the workstation from the network and power it off.",
        "Create a forensic image (bit-by-bit copy) of the hard drive before making any changes to the system.",
        "Reboot the workstation to see if the problem resolves itself."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Creating a forensic image before any other action is crucial to preserve the system's state exactly as it was at the time of the suspected compromise. Running antivirus, disconnecting from the network, or rebooting can alter the system's state and potentially destroy evidence. (Ideally, containment is performed immediately after imaging if required by incident response policy.)",
      "examTip": "In a security incident, prioritize preserving the system's state by creating a forensic image before taking any other actions that might alter the evidence."
    },
    {
      "id": 11,
      "question": "A user reports they can no longer access files on their encrypted external hard drive. They are prompted for a password, but they claim they never set one. The drive was working fine previously. What's the MOST likely scenario, assuming the drive isn't physically damaged?",
      "options": [
        "The hard drive has failed.",
        "The user forgot the password.",
        "The encryption software has become corrupted, or the drive's encryption metadata has been damaged.",
        "The USB port is faulty."
      ],
      "correctAnswerIndex": 2,
      "explanation": "While user error (forgetting the password) is possible, if the user never set a password and the drive was previously working, corruption of the encryption software or the drive's encryption metadata is more likely. A failed drive would usually result in different errors. A faulty USB port would likely prevent detection.",
      "examTip": "If an encrypted drive suddenly requires a password the user claims they never set, suspect encryption software or metadata corruption."
    },
    {
      "id": 12,
      "question": "You are troubleshooting a Windows computer that boots very slowly. You've already disabled unnecessary startup programs in Task Manager and msconfig. What is the NEXT most effective step to investigate potential boot-time bottlenecks?",
      "options": [
        "Run Disk Cleanup.",
        "Run `chkdsk`.",
        "Use the Windows Performance Recorder and Analyzer (part of the Windows Assessment and Deployment Kit - ADK) to capture a boot trace and analyze boot performance.",
        "Increase the size of the paging file."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The Windows Performance Recorder and Analyzer provide detailed information about the boot process, including which drivers, services, and processes are taking the longest to load. This allows you to pinpoint specific bottlenecks. Disk Cleanup and chkdsk have different purposes, and increasing the paging file addresses virtual memory, not boot time.",
      "examTip": "Use the Windows Performance Recorder and Analyzer (WPR/WPA) for in-depth analysis of boot performance issues."
    },
    {
      "id": 13,
      "question": "A user reports they accidentally deleted a critical file from a network share. The file is not in their Recycle Bin. What is the BEST way to attempt recovery, assuming the file server is running Windows Server and has the appropriate features enabled?",
      "options": [
        "Use a file recovery utility on the user's computer.",
        "Restore the file from a recent backup of the file server.",
        "Attempt to recover the file from the 'Previous Versions' (Shadow Copies) feature on the file server.",
        "Tell the user the file is permanently lost."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The 'Previous Versions' (Shadow Copies) feature on Windows Server takes periodic snapshots of files and folders, allowing users to restore previous versions of files that have been accidentally deleted or modified. This is often faster and easier than restoring from a full backup. File recovery utilities are less likely to succeed on a network share, and telling the user it's lost is premature.",
      "examTip": "Enable and configure the 'Previous Versions' (Shadow Copies) feature on Windows file servers to provide a convenient way for users to recover deleted or modified files."
    },
    {
      "id": 14,
      "question": "A user reports that their web browser is behaving erratically, displaying unexpected pop-ups and redirecting them to unfamiliar websites. You've already run a full system scan with antivirus and anti-malware software, but the problem persists. What is the NEXT most likely cause, and how would you address it?",
      "options": [
        "A hardware failure.",
        "A corrupted operating system.",
        "A browser extension or plugin is causing the issue; check and disable recently installed or suspicious extensions.",
        "Incorrect DNS settings."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Persistent browser issues even after malware scans often point to a malicious or malfunctioning browser extension. Disabling extensions one by one can help isolate the culprit. Hardware failures and OS corruption are less likely to cause these specific symptoms. Incorrect DNS settings would usually prevent access altogether, not cause redirects.",
      "examTip": "Carefully review and manage browser extensions; they can be a source of unwanted behavior and security risks."
    },
    {
      "id": 15,
      "question": "You are analyzing network traffic and notice a large number of packets with the SYN flag set, but very few corresponding ACK flags. What type of network activity does this MOST likely indicate?",
      "options": [
        "Normal web browsing.",
        "A SYN flood attack (a type of denial-of-service attack).",
        "File transfer using FTP.",
        "Email communication using SMTP."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A SYN flood attack involves sending a large number of SYN packets to a server, attempting to overwhelm it and prevent it from completing TCP handshakes. The lack of corresponding ACK packets indicates that the connections are not being completed. Normal web browsing, FTP, and SMTP involve complete handshakes.",
      "examTip": "A disproportionate number of SYN packets compared to ACK packets is a strong indicator of a SYN flood attack."
    },
    {
      "id": 16,
      "question": "A user's laptop is exhibiting signs of malware infection, including slow performance, pop-up ads, and unusual network activity. You have run multiple antivirus and anti-malware scans, but some threats persist. What is the NEXT BEST step to ensure complete malware removal?",
      "options": [
        "Reinstall the operating system.",
        "Boot into Safe Mode and run the scans again.",
        "Use a bootable antivirus/anti-malware rescue disk (from a reputable vendor) to scan the system from outside the infected operating system.",
        "Restore the system from a recent backup."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A bootable rescue disk scans the system before the infected operating system loads, allowing it to detect and remove deeply embedded malware (such as rootkits) that might hide from scans run within Windows. Reinstalling the OS is more drastic, and Safe Mode helps but may not uncover all threats. Restoring from a backup might reintroduce malware if the backup is infected.",
      "examTip": "Use a bootable antivirus/anti-malware rescue disk for thorough malware removal, especially when dealing with persistent or advanced threats."
    },
    {
      "id": 17,
      "question": "You are setting up a new Linux server and want to ensure that only authorized users can connect to it remotely via SSH. Which of the following configurations provides the BEST security?",
      "options": [
        "Allow root login via SSH and use a strong password.",
        "Disable root login via SSH, allow only specific user accounts to connect via SSH using key-based authentication (disabling password authentication), and configure a firewall to restrict SSH access to specific IP addresses.",
        "Allow all users to connect via SSH with password authentication.",
        "Use Telnet instead of SSH for remote access."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Disabling root login prevents direct attacks on the root account, key-based authentication is much more secure than passwords, restricting access to specific users and IP addresses further limits exposure, and a firewall adds an extra layer of defense. Allowing root login with a password, allowing all users with passwords, and using Telnet (which is unencrypted) are insecure practices.",
      "examTip": "For secure SSH access, disable root login, use key-based authentication, restrict access to specific users and IP addresses, and use a firewall."
    },
    {
      "id": 18,
      "question": "A user reports that their computer is displaying a 'low memory' warning. What is the FIRST action you should take?",
      "options": [
        "Add more physical RAM to the computer.",
        "Close unnecessary applications and processes.",
        "Run Disk Cleanup.",
        "Increase the size of the paging file (virtual memory)."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Closing unnecessary applications and processes frees up RAM immediately, addressing the immediate problem. Adding RAM is a longer-term solution. Disk Cleanup frees disk space, not RAM. Increasing the paging file may help but is secondary to freeing actual memory.",
      "examTip": "Before resorting to hardware upgrades, try closing unnecessary applications to free up memory."
    },
    {
      "id": 19,
      "question": "You are documenting a network configuration. What information should be included in a network topology diagram?",
      "options": [
        "Usernames and passwords.",
        "The make and model of each computer.",
        "The IP addresses, subnets, and connections between network devices (routers, switches, servers, etc.).",
        "The operating system version of each computer."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A network topology diagram visually represents the structure of a network, showing how devices are connected and how data flows between them. It includes IP addresses, subnets, device types, and connection methods. Usernames/passwords and specific hardware details are not typically included.",
      "examTip": "Create and maintain accurate network topology diagrams to aid in troubleshooting and network management."
    },
    {
      "id": 20,
      "question": "What is the purpose of the Windows Registry?",
      "options": [
        "To store user documents and files.",
        "To manage network connections.",
        "To store configuration settings and options for the operating system and installed applications.",
        "To control user access to the computer."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The Windows Registry is a hierarchical database that stores low-level settings for the operating system, device drivers, services, and applications. It is not used for storing user documents or directly managing network connections.",
      "examTip": "Exercise extreme caution when editing the Windows Registry; incorrect changes can cause system instability or failure."
    },
    {
      "id": 21,
      "question": "A user cannot access any websites, but they can ping their default gateway. What is the MOST likely cause of the issue?",
      "options": [
        "A faulty network cable.",
        "A problem with the user's DNS server settings.",
        "The user's computer is not connected to the network.",
        "The user's web browser is corrupted."
      ],
      "correctAnswerIndex": 1,
      "explanation": "If the user can ping their default gateway, basic network connectivity exists. The inability to access websites suggests a DNS resolution problem.",
      "examTip": "A situation where you can ping local devices but not access websites typically indicates a DNS configuration issue."
    },
    {
      "id": 22,
      "question": "What is a 'zero-day' attack?",
      "options": [
        "An attack that occurs on the first day a computer is connected to the internet.",
        "An attack that exploits a vulnerability that is unknown to the software vendor and for which no patch is available.",
        "An attack that uses social engineering techniques.",
        "An attack that targets outdated operating systems."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A zero-day attack exploits a security vulnerability that is unknown to the vendor, meaning no patch or fix is available. This makes such attacks particularly dangerous.",
      "examTip": "Keep your software up-to-date to minimize the risk of zero-day attacks; prompt patching is crucial once vulnerabilities are discovered."
    },
    {
      "id": 23,
      "question": "Which of the following security practices is MOST effective when using public Wi-Fi?",
      "options": [
        "Disable your computer's firewall.",
        "Use a VPN (Virtual Private Network) to encrypt your traffic.",
        "Share your files and folders with everyone on the network.",
        "Connect to any available network without a password."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A VPN encrypts your internet traffic, protecting your data from eavesdropping on unsecured public Wi-Fi networks. Disabling the firewall or sharing files can increase security risks.",
      "examTip": "Always use a VPN when connecting to public Wi-Fi to protect your privacy and data."
    },
    {
      "id": 24,
      "question": "Which Windows command-line tool can be used to manage disk partitions?",
      "options": [
        "chkdsk",
        "diskpart",
        "defrag",
        "format"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`diskpart` is a powerful command-line utility for managing disks, partitions, and volumes. `chkdsk` checks for file system errors, `defrag` defragments drives, and `format` prepares partitions for use.",
      "examTip": "Use `diskpart` with caution; incorrect commands can lead to data loss."
    },
    {
      "id": 25,
      "question": "What is the purpose of regularly reviewing system logs?",
      "options": [
        "To free up disk space.",
        "To improve system performance.",
        "To identify potential security breaches, errors, and other system issues.",
        "To back up user data."
      ],
      "correctAnswerIndex": 2,
      "explanation": "System logs record events, errors, and warnings. Regular review of these logs helps detect security incidents and system issues. They do not directly free up disk space, improve performance, or back up data.",
      "examTip": "Make log review a regular part of your system administration routine to proactively identify and address issues."
    },
    {
      "id": 26,
      "question": "A user reports that their computer is displaying a 'blue screen of death' (BSOD) error. You suspect a hardware problem. Which of the following tools can help you diagnose the issue?",
      "options": [
        "System Restore.",
        "Windows Memory Diagnostic.",
        "Disk Cleanup.",
        "Task Manager."
      ],
      "correctAnswerIndex": 1,
      "explanation": "BSODs are often caused by hardware failures—especially faulty RAM. Windows Memory Diagnostic is a built-in tool to test RAM for errors.",
      "examTip": "Use Windows Memory Diagnostic to test RAM when troubleshooting BSODs or system instability."
    },
    {
      "id": 27,
      "question": "What is the purpose of an incident response plan?",
      "options": [
        "To prevent security incidents from happening.",
        "To provide a documented, step-by-step process for handling security incidents.",
        "To punish individuals who cause security incidents.",
        "To purchase cybersecurity insurance."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An incident response plan outlines the procedures for detecting, responding to, and recovering from security incidents. It does not guarantee prevention or punishment.",
      "examTip": "Develop and regularly test an incident response plan to ensure your organization can effectively handle security incidents."
    },
    {
      "id": 28,
      "question": "You are configuring a SOHO router. What does the term 'port forwarding' mean?",
      "options": [
        "Redirecting network traffic from one port to another on the internal network.",
        "Blocking all incoming traffic on a specific port.",
        "Encrypting network traffic on a specific port.",
        "Monitoring network traffic on a specific port."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Port forwarding directs incoming traffic on a specific external port to a specific internal IP address and port, enabling external access to internal services.",
      "examTip": "Use port forwarding to make internal servers accessible from the internet, while minimizing exposure."
    },
    {
      "id": 29,
      "question": "What is a common symptom of a spyware infection?",
      "options": [
        "The computer runs faster than usual.",
        "Unexplained changes to the web browser's homepage or search engine, and increased pop-up ads.",
        "The computer refuses to boot.",
        "All files on the hard drive are encrypted."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Spyware often modifies browser settings and injects pop-up ads to generate revenue or gather information. These symptoms are typical of spyware infections.",
      "examTip": "Be alert for unexpected browser changes and increased pop-ups; these can be signs of spyware."
    },
    {
      "id": 30,
      "question": "You are configuring a network and need to ensure that specific devices (like servers and printers) always receive the same IP address from the DHCP server. What is the BEST way to achieve this?",
      "options": [
        "Configure static IP addresses on each device.",
        "Configure DHCP reservations (also known as static DHCP) on the DHCP server, mapping MAC addresses to specific IP addresses.",
        "Use a very short DHCP lease time.",
        "Disable DHCP entirely."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DHCP reservations allow the DHCP server to assign the same IP address to a device based on its MAC address. This approach provides the manageability of DHCP with the consistency of static IP addressing.",
      "examTip": "Use DHCP reservations to ensure that specific devices always receive the same IP address while still benefiting from centralized management."
    },
    {
      "id": 31,
      "question": "You are investigating a potential data breach. You need to determine when a specific user account last logged on to a Windows server. Which tool and log would you use?",
      "options": [
        "Task Manager; Security log",
        "Event Viewer; Security log",
        "Resource Monitor; Application log",
        "System Information; System log"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The Security log in Event Viewer records security-related events, including user logon and logoff activities, making it the best choice for this task.",
      "examTip": "Use the Security log in Event Viewer to audit user logon events and determine last logon times."
    },
    {
      "id": 32,
      "question": "You are configuring a SOHO router and want to allow remote access to an internal web server (running on port 8080) from the internet. The server has a private IP address of 192.168.1.100. What configuration steps are required on the router?",
      "options": [
        "Enable DMZ and set the DMZ host to 192.168.1.100.",
        "Configure port forwarding to forward external port 8080 to internal IP address 192.168.1.100, port 8080.",
        "Configure port forwarding to forward external port 80 to internal IP address 192.168.1.100, port 8080.",
        "Enable UPnP (Universal Plug and Play)."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Port forwarding directs incoming traffic on a specified external port to the designated internal IP address and port. In this case, external port 8080 should be forwarded to 192.168.1.100:8080.",
      "examTip": "Use port forwarding to expose internal services to the internet securely; avoid DMZ unless absolutely necessary."
    },
    {
      "id": 33,
      "question": "A user reports that their computer is exhibiting unusual behavior, including slow performance, unexpected pop-ups, and changes to their browser's homepage. You suspect malware, but standard antivirus scans are not detecting anything. What is the NEXT BEST step to investigate and potentially remove the malware?",
      "options": [
        "Reinstall the operating system.",
        "Run a scan with a different anti-malware tool, preferably one specializing in rootkit detection.",
        "Restore the system from a recent backup.",
        "Disconnect the computer from the network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "If standard scans are not detecting the malware, using a different anti-malware tool—especially one designed for rootkit detection—can help uncover hidden threats. Reinstalling the OS is too drastic, and restoring from backup might reintroduce malware if the backup is infected.",
      "examTip": "If one anti-malware tool fails, try another that specializes in rootkit detection before taking more drastic measures."
    },
    {
      "id": 34,
      "question": "A company wants to implement a security policy that requires users to change their passwords every 90 days. Where would you configure this setting in a Windows domain environment?",
      "options": [
        "In the user's account properties.",
        "In Group Policy, under Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Account Policies -> Password Policy.",
        "In Local Security Policy on each individual computer.",
        "In the Windows Firewall settings."
      ],
      "correctAnswerIndex": 1,
      "explanation": "In a domain environment, password policies are centrally managed through Group Policy. The relevant settings are found under Account Policies -> Password Policy in the Group Policy Management Console.",
      "examTip": "Use Group Policy to centrally manage password policies for domain users."
    },
    {
      "id": 35,
      "question": "You are troubleshooting a network connectivity issue on a Linux server. You need to determine which process is listening on a specific port (e.g., port 22 for SSH). Which command would you use?",
      "options": [
        "`netstat -tulnp | grep :22`",
        "`ip addr show`",
        "`ifconfig`",
        "`ping`"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command `netstat -tulnp | grep :22` shows active TCP/UDP connections and listening ports, including the process ID and name for those using port 22.",
      "examTip": "Use `netstat -tulnp` (or `ss -tulnp` on newer systems) to identify processes listening on specific ports in Linux."
    },
    {
      "id": 36,
      "question": "A user's laptop is exhibiting signs of malware infection, including slow performance, pop-up ads, and unusual network activity. You have run multiple antivirus and anti-malware scans, but some threats persist. What is the NEXT BEST step to ensure complete malware removal?",
      "options": [
        "Reinstall the operating system.",
        "Boot into Safe Mode and run the scans again.",
        "Use a bootable antivirus/anti-malware rescue disk (from a reputable vendor) to scan the system from outside the infected operating system.",
        "Restore the system from a recent backup."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A bootable rescue disk scans the system before the infected OS loads, allowing detection and removal of hidden malware such as rootkits. This approach is more thorough than running scans in Safe Mode.",
      "examTip": "Use a bootable antivirus/anti-malware rescue disk for thorough malware removal, especially when dealing with persistent threats."
    },
    {
      "id": 37,
      "question": "You are setting up a new Linux server and want to ensure that only authorized users can connect to it remotely via SSH. Which of the following configurations provides the BEST security?",
      "options": [
        "Allow root login via SSH and use a strong password.",
        "Disable root login via SSH, allow only specific user accounts to connect via SSH using key-based authentication (disabling password authentication), and configure a firewall to restrict SSH access to specific IP addresses.",
        "Allow all users to connect via SSH with password authentication.",
        "Use Telnet instead of SSH for remote access."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Disabling root login, using key-based authentication, and restricting SSH access to specific users and IP addresses provides multiple layers of security. Telnet is unencrypted and insecure.",
      "examTip": "For secure SSH access, disable root login, enforce key-based authentication, and restrict access using firewall rules."
    },
    {
      "id": 38,
      "question": "What is the purpose of the 'principle of least privilege' in cybersecurity?",
      "options": [
        "To give all users administrator access to simplify management.",
        "To grant users only the minimum necessary access rights (permissions) required to perform their job duties.",
        "To use the strongest possible encryption for all data.",
        "To install the latest security patches on all systems."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The principle of least privilege means granting users only the permissions they need to perform their tasks. This minimizes the risk of accidental or malicious misuse of privileges.",
      "examTip": "Apply the principle of least privilege to minimize potential damage from compromised accounts."
    },
    {
      "id": 39,
      "question": "A user complains that their computer is 'running out of memory,' even though they have plenty of RAM installed. You open Task Manager and see that a single application is consuming a very large amount of memory, and the amount is steadily increasing over time. What is the MOST likely cause?",
      "options": [
        "The hard drive is failing.",
        "The application has a memory leak.",
        "The user has too many browser tabs open.",
        "The computer is infected with a virus."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A memory leak occurs when an application continually allocates memory without releasing it, causing a steady increase in memory usage. This is a common issue in poorly coded applications.",
      "examTip": "A steadily increasing memory usage by a single application is a classic sign of a memory leak; report the issue to the software vendor."
    },
    {
      "id": 40,
      "question": "You are configuring a network and need to ensure that specific devices (like servers and printers) always receive the same IP address from the DHCP server. What is the BEST way to achieve this?",
      "options": [
        "Configure static IP addresses on each device.",
        "Configure DHCP reservations (also known as static DHCP) on the DHCP server, mapping MAC addresses to specific IP addresses.",
        "Use a very short DHCP lease time.",
        "Disable DHCP entirely."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DHCP reservations allow the DHCP server to assign the same IP address to a device based on its MAC address. This provides the consistency of static IP addresses while maintaining centralized management.",
      "examTip": "Use DHCP reservations to ensure that specific devices always receive the same IP address without manually configuring each device."
    },
    {
      "id": 41,
      "question": "You are investigating a potential data breach. You need to determine when a specific user account last logged on to a Windows server. Which tool and log would you use?",
      "options": [
        "Task Manager; Security log",
        "Event Viewer; Security log",
        "Resource Monitor; Application log",
        "System Information; System log"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The Security log in Event Viewer records security-related events, including user logon and logoff events, making it the appropriate log to check.",
      "examTip": "Use the Security log in Event Viewer to audit logon events and determine last logon times."
    },
    {
      "id": 42,
      "question": "Which of the following is an example of a 'watering hole' attack?",
      "options": [
        "Sending phishing emails to a large number of recipients.",
        "Compromising a website that is frequently visited by a specific target group, and infecting the website with malware to infect the visitors.",
        "Exploiting a vulnerability in a web server.",
        "Guessing user passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A watering hole attack involves compromising a website frequented by a target group so that visitors become infected. It relies on the trust users have in the compromised site.",
      "examTip": "Be cautious about visiting websites that are known to be frequented by specific groups; attackers may target these sites to infect their audience."
    },
    {
      "id": 43,
      "question": "Which of the following is a key security benefit of using a VPN (Virtual Private Network)?",
      "options": [
        "It speeds up your internet connection.",
        "It encrypts your internet traffic, protecting it from eavesdropping, especially on public Wi-Fi networks.",
        "It prevents viruses and malware from infecting your computer.",
        "It blocks access to specific websites."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A VPN creates an encrypted tunnel for your data, protecting your privacy and security when transmitting over untrusted networks such as public Wi-Fi.",
      "examTip": "Use a VPN when accessing sensitive information on public networks to protect your data from interception."
    },
    {
      "id": 44,
      "question": "A user reports that their computer is displaying a 'missing operating system' error message. You have verified that the hard drive is connected properly and is recognized by the BIOS. The boot order is also correct. What is the NEXT step to troubleshoot?",
      "options": [
        "Replace the hard drive.",
        "Reinstall the operating system.",
        "Use the Windows Recovery Environment (booting from installation media) to attempt to repair the boot sector or BCD (Boot Configuration Data).",
        "Run a virus scan."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A 'missing operating system' error with a recognized hard drive and correct boot order often indicates a corrupted boot sector or BCD. The Windows Recovery Environment offers tools (like bootrec.exe) to repair these issues.",
      "examTip": "Use the Windows Recovery Environment to repair boot configuration data when encountering boot errors."
    },
    {
      "id": 45,
      "question": "You are configuring a new computer and want to encrypt the entire hard drive to protect sensitive data. Which built-in Windows feature would you use?",
      "options": [
        "EFS (Encrypting File System)",
        "BitLocker Drive Encryption",
        "Windows Defender Firewall",
        "User Account Control (UAC)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "BitLocker provides full-disk encryption, protecting all data on the drive. EFS encrypts individual files and folders.",
      "examTip": "Use BitLocker to encrypt the entire drive, especially on portable devices, to secure data in case of loss or theft."
    },
    {
      "id": 46,
      "question": "Which of the following is the BEST description of 'data remanence'?",
      "options": [
        "The process of backing up data.",
        "The residual data that remains on a storage device even after it has been erased or formatted.",
        "The encryption of data.",
        "The transfer of data over a network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data remanence refers to the lingering traces of data that can remain on a storage device even after standard deletion or formatting. Specialized data recovery methods can sometimes retrieve this data.",
      "examTip": "Use secure wiping methods or physical destruction to prevent data remanence when disposing of storage devices."
    },
    {
      "id": 47,
      "question": "A user reports that they are unable to access a specific website. You can access the website from a different computer on the same network. What is the FIRST troubleshooting step you should take on the user's computer?",
      "options": [
        "Reinstall the operating system.",
        "Check the user's web browser's proxy settings, clear the browser cache and cookies, and check the 'hosts' file for any entries that might be blocking the website.",
        "Replace the network cable.",
        "Run a virus scan."
      ],
      "correctAnswerIndex": 1,
      "explanation": "If the website is accessible from another computer on the same network, the issue is likely local to the user's computer. Investigate browser settings and the hosts file to rule out misconfigurations.",
      "examTip": "When a website is inaccessible on one machine but not others, check local browser settings and the hosts file."
    },
    {
      "id": 48,
      "question": "Which Linux command would you use to find all files named 'config.txt' within the `/etc` directory and its subdirectories?",
      "options": [
        "`grep config.txt /etc`",
        "`find /etc -name config.txt`",
        "`locate config.txt`",
        "`ls /etc | grep config.txt`"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `find` command recursively searches directories. `find /etc -name config.txt` will locate all files named 'config.txt' under /etc. `grep` searches within files, and `locate` relies on a prebuilt database that may not be up-to-date.",
      "examTip": "Use the `find` command for recursive file searches in Linux."
    },
    {
      "id": 49,
      "question": "You are setting up a network and want to prevent unauthorized devices from connecting to your wireless network, even if they know the Wi-Fi password. Which security feature would you use?",
      "options": [
        "WPS (Wi-Fi Protected Setup)",
        "MAC address filtering",
        "SSID broadcast disabling",
        "WEP encryption"
      ],
      "correctAnswerIndex": 1,
      "explanation": "MAC address filtering allows only devices with approved MAC addresses to connect to the network, even if they know the Wi-Fi password. WPS is insecure, SSID broadcast disabling only hides the network name, and WEP is outdated.",
      "examTip": "Use MAC address filtering as an additional layer of security on your wireless network, in combination with strong encryption."
    },
    {
      "id": 50,
      "question": "You are troubleshooting a Windows computer that is experiencing performance issues.  You suspect a problem with the hard drive. Which command-line tool would you use to check the file system integrity and attempt to repair any errors?",
      "options": [
        "defrag",
        "diskpart",
        "chkdsk",
        "sfc /scannow"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`chkdsk` scans the hard drive for file system errors and bad sectors and can attempt to repair them. Defrag reorganizes files, diskpart manages partitions, and sfc /scannow checks system file integrity.",
      "examTip": "Run `chkdsk /f /r` to fix file system errors and recover data from bad sectors."
    },
    {
      "id": 51,
      "question": "Which type of attack involves an attacker inserting malicious code into a database query, potentially allowing them to access, modify, or delete data?",
      "options": [
        "Cross-site scripting (XSS)",
        "SQL injection",
        "Denial-of-service (DoS)",
        "Phishing"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SQL injection targets databases by inserting malicious SQL code into input fields. XSS targets client-side scripts, DoS disrupts service availability, and phishing relies on social engineering.",
      "examTip": "Protect against SQL injection by validating and sanitizing all user inputs and using parameterized queries."
    },
    {
      "id": 52,
      "question": "A user reports their computer is running slowly. Task Manager shows high CPU usage, but no single process appears to be the culprit. After further investigation, you suspect a driver issue. Which tool would BEST allow you to identify a specific driver causing high CPU utilization?",
      "options": [
        "Resource Monitor",
        "System Configuration (msconfig.exe)",
        "Windows Performance Recorder and Analyzer (WPR/WPA), specifically looking at CPU usage by modules (drivers).",
        "Device Manager"
      ],
      "correctAnswerIndex": 2,
      "explanation": "WPR/WPA provides detailed performance tracing that can break down CPU usage by driver or module, which is ideal for pinpointing a problematic driver. Resource Monitor and Device Manager don't provide this level of detail.",
      "examTip": "Use Windows Performance Recorder and Analyzer for in-depth performance analysis, including identifying resource-intensive drivers."
    },
    {
      "id": 53,
      "question": "You are configuring a server that will host multiple virtual machines. Which CPU feature is essential for optimal virtualization performance?",
      "options": [
        "Hyper-Threading",
        "Hardware-assisted virtualization (e.g., Intel VT-x or AMD-V).",
        "Overclocking",
        "A large L3 cache"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hardware-assisted virtualization (Intel VT-x or AMD-V) provides CPU extensions that greatly improve virtualization performance. Hyper-Threading can help, but virtualization extensions are critical.",
      "examTip": "Ensure that hardware virtualization (VT-x or AMD-V) is enabled in BIOS/UEFI for optimal VM performance."
    },
    {
      "id": 54,
      "question": "You are troubleshooting a network connectivity problem on a Windows workstation. The computer has a valid IP address, can ping its default gateway, but cannot access any websites. You suspect a DNS issue. Besides `nslookup`, which command-line tool can you use to test DNS resolution?",
      "options": [
        "ping <domain_name>",
        "tracert <domain_name>",
        "ipconfig /all",
        "netstat"
      ],
      "correctAnswerIndex": 0,
      "explanation": "If `ping <domain_name>` fails but ping by IP succeeds, it indicates a DNS resolution problem. While tracert would also fail if DNS is the issue, using ping directly by domain name is a simple and direct test.",
      "examTip": "A failed ping by domain name (with a successful IP ping) is a strong indicator of DNS problems."
    },
    {
      "id": 55,
      "question": "Which of the following is a key security benefit of using a VPN (Virtual Private Network)?",
      "options": [
        "It speeds up your internet connection.",
        "It encrypts your internet traffic, protecting it from eavesdropping, especially on public Wi-Fi networks.",
        "It prevents viruses and malware from infecting your computer.",
        "It blocks access to specific websites."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A VPN encrypts your traffic, securing your data from interception—especially important on untrusted networks such as public Wi-Fi.",
      "examTip": "Always use a VPN when accessing sensitive data over public networks to protect your privacy and data."
    },
    {
      "id": 56,
      "question": "You are investigating a security incident and need to determine the exact time an event occurred. The computer's system clock is not synchronized with a reliable time source. What should you do?",
      "options": [
        "Rely on the computer's system clock.",
        "Consult system logs, comparing timestamps across multiple devices and logs to establish a timeline.",
        "Ask the user when they think the event occurred.",
        "Assume the event occurred at the time the incident was reported."
      ],
      "correctAnswerIndex": 1,
      "explanation": "If the system clock is unreliable, you must correlate timestamps from multiple sources (other logs, network devices, security appliances) to accurately establish a timeline.",
      "examTip": "In security investigations, cross-reference timestamps from multiple sources to ensure accuracy."
    },
    {
      "id": 57,
      "question": "What is the function of the `chmod +x` command in Linux?",
      "options": [
        "To change the ownership of a file.",
        "To make a file executable.",
        "To delete a file.",
        "To view the contents of a file."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`chmod +x <filename>` adds execute permissions to the file, allowing it to be run as a program or script.",
      "examTip": "Use `chmod +x` to mark scripts and programs as executable in Linux."
    },
    {
      "id": 58,
      "question": "A user is working from home and needs to access files on a corporate file server. The company uses a VPN for secure remote access. The user successfully connects to the VPN, but they still cannot access the file server. What is the MOST likely cause?",
      "options": [
        "The user's home internet connection is down.",
        "The user does not have the correct permissions on the file server, or there is a firewall rule blocking access even over the VPN.",
        "The VPN software is not installed correctly.",
        "The user's computer is infected with malware."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A successful VPN connection establishes a secure tunnel, but access to resources still depends on proper permissions and firewall rules on the file server. Since the VPN is working, check permissions or firewall rules.",
      "examTip": "A VPN connection secures access but does not override file server permissions or firewall restrictions."
    },
    {
      "id": 59,
      "question": "Which Windows command-line tool is BEST for managing local user accounts and groups?",
      "options": [
        "net user",
        "net localgroup",
        "lusrmgr.msc (Local Users and Groups - accessible through Computer Management)",
        "gpedit.msc (Local Group Policy Editor)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "While `net user` and `net localgroup` can manage users and groups from the command line, lusrmgr.msc (Local Users and Groups) provides a more comprehensive graphical interface for managing local accounts.",
      "examTip": "Use lusrmgr.msc via Computer Management for detailed local user and group management."
    },
    {
      "id": 60,
      "question": "You are configuring a Linux server and need to restrict network access to specific services based on the source IP address. Which tool is BEST suited for this task?",
      "options": [
        "iptables (or nftables on newer systems)",
        "netstat",
        "ifconfig",
        "route"
      ],
      "correctAnswerIndex": 0,
      "explanation": "iptables (or nftables) is the standard Linux firewall tool that allows you to create rules to filter network traffic based on various criteria, including source IP address.",
      "examTip": "Familiarize yourself with iptables (or nftables) for configuring firewall rules on Linux systems."
    },
    {
      "id": 61,
      "question": "A user reports that they are unable to access a shared printer. You have verified that the printer is online, other users can print to it, and the user's computer has network connectivity. You've also restarted the Print Spooler service on the user's computer. What should you check NEXT?",
      "options": [
        "The printer's IP address.",
        "The user's account permissions on the printer.",
        "The network cable connecting the printer to the network.",
        "The printer's toner level."
      ],
      "correctAnswerIndex": 1,
      "explanation": "If other users can print and connectivity is confirmed, the next step is to check the user's permissions on the printer, as this is likely a configuration issue on the user’s account.",
      "examTip": "Verify printer permissions when a single user cannot access a network printer."
    },
    {
      "id": 62,
      "question": "Which of the following security practices is MOST effective in mitigating the risk of a brute-force password attack?",
      "options": [
        "Using a strong password.",
        "Enforcing account lockout policies (limiting the number of failed login attempts).",
        "Using a firewall.",
        "Using antivirus software."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Account lockout policies specifically prevent brute-force attacks by limiting the number of consecutive failed login attempts. A strong password is important but does not stop repeated attempts.",
      "examTip": "Implement account lockout policies to deter brute-force attacks."
    },
    {
      "id": 63,
      "question": "What is the purpose of the Windows System Restore feature?",
      "options": [
        "To create a backup of user data.",
        "To allow the system to be reverted to a previous state, including system files, settings, and installed applications.",
        "To scan for and remove malware.",
        "To defragment the hard drive."
      ],
      "correctAnswerIndex": 1,
      "explanation": "System Restore creates snapshots (restore points) of the system's configuration, allowing you to revert to a previous state if issues occur.",
      "examTip": "Create restore points before making significant system changes to have a fallback option."
    },
    {
      "id": 64,
      "question": "Which of the following is a BEST practice for disposing of old computer equipment?",
      "options": [
        "Throw it in the trash.",
        "Sell it online without wiping the hard drive.",
        "Recycle it through a reputable e-waste recycling program, ensuring data is securely erased.",
        "Leave it on the curb for anyone to take."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Recycling through a reputable e-waste program ensures that data is securely erased and that the equipment is disposed of in an environmentally responsible manner.",
      "examTip": "Always ensure data is securely wiped and recycle equipment through certified e-waste recyclers."
    },
    {
      "id": 65,
      "question": "What does the acronym 'BYOD' stand for, and what is a key security concern associated with it?",
      "options": [
        "Bring Your Own Device; data security and device management.",
        "Buy Your Own Data; data privacy.",
        "Bring Your Own Data; data loss.",
        "Buy Your Own Device; cost of equipment."
      ],
      "correctAnswerIndex": 0,
      "explanation": "BYOD (Bring Your Own Device) refers to employees using their personal devices for work. The key concern is securing these devices and the data they contain, as they are not under direct IT control.",
      "examTip": "Implement a BYOD policy that addresses security, management, and data protection for personal devices used for work."
    },
    {
      "id": 66,
      "question": "Which of the following actions can help prevent electrostatic discharge (ESD) damage when working inside a computer?",
      "options": [
        "Wear rubber gloves.",
        "Use an antistatic wrist strap and mat.",
        "Work on a carpeted floor.",
        "Keep the computer plugged in."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An antistatic wrist strap and mat provide a grounded path for static electricity, reducing the risk of ESD damage to sensitive components.",
      "examTip": "Always use an antistatic wrist strap and mat when working inside a computer."
    },
    {
      "id": 67,
      "question": "What is the purpose of the `tasklist` command in Windows?",
      "options": [
        "To schedule tasks to run at a specific time.",
        "To display a list of currently running processes.",
        "To manage user accounts.",
        "To configure network settings."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`tasklist` displays a list of running processes on the local or a remote computer, similar to the Processes tab in Task Manager.",
      "examTip": "Use `tasklist` to view running processes from the command line for troubleshooting."
    },
    {
      "id": 68,
      "question": "What is the primary function of DHCP (Dynamic Host Configuration Protocol)?",
      "options": [
        "To encrypt network traffic.",
        "To automatically assign IP addresses and other network configuration parameters to devices on a network.",
        "To resolve domain names to IP addresses.",
        "To filter network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DHCP automates the assignment of IP addresses and other network parameters, making network configuration simpler and reducing the risk of IP conflicts.",
      "examTip": "DHCP simplifies network management by automatically providing network configuration to devices."
    },
    {
      "id": 69,
      "question": "You need to determine if a remote server is reachable and responding. Which command-line tool is BEST suited for this basic connectivity test?",
      "options": [
        "tracert",
        "ping",
        "nslookup",
        "ipconfig"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`ping` sends ICMP echo requests to a target host and measures the response time, making it ideal for basic connectivity tests.",
      "examTip": "Use `ping` to quickly verify whether a remote host is reachable."
    },
    {
      "id": 70,
      "question": "You are configuring a server and want to ensure that it automatically synchronizes its system clock with a reliable time source. Which protocol is BEST suited for this purpose?",
      "options": [
        "FTP (File Transfer Protocol)",
        "NTP (Network Time Protocol)",
        "HTTP (Hypertext Transfer Protocol)",
        "SMTP (Simple Mail Transfer Protocol)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "NTP is specifically designed to synchronize clocks over a network, ensuring accurate timekeeping across systems.",
      "examTip": "Configure your server to synchronize with a reliable NTP server for accurate timekeeping, essential for logging and security."
    },
    {
      "id": 71,
      "question": "Which of the following actions is MOST likely to result in malware infection?",
      "options": [
        "Visiting reputable websites.",
        "Downloading and opening attachments from unknown or untrusted email senders.",
        "Keeping your operating system and software up-to-date.",
        "Using a strong, unique password for your email account."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Downloading and opening attachments from untrusted sources is a common vector for malware infections.",
      "examTip": "Be extremely cautious about email attachments from unknown senders; they are a primary malware delivery method."
    },
    {
      "id": 72,
      "question": "A user reports that they are unable to access any network resources, including shared folders, printers, and the internet. Other users on the same network are not experiencing issues. You check the user's computer and find that it has a valid IP address, subnet mask, and default gateway. What should you investigate NEXT?",
      "options": [
        "The user's network cable.",
        "The user's DNS server settings, the 'hosts' file, and potential proxy server configurations.",
        "The network switch the user is connected to.",
        "The user's account is locked out."
      ],
      "correctAnswerIndex": 1,
      "explanation": "If the computer has a valid IP configuration yet cannot access any resources, the issue may be due to misconfigured DNS settings, an incorrect 'hosts' file entry, or proxy settings blocking access.",
      "examTip": "When a computer with valid IP settings cannot access network resources, check local DNS, hosts file, and proxy configurations."
    },
    {
      "id": 73,
      "question": "Which of the following security measures is MOST effective in preventing unauthorized access to a mobile device if it is lost or stolen?",
      "options": [
        "Installing antivirus software.",
        "Enabling a strong screen lock (PIN, password, pattern, or biometric) and configuring remote wipe capabilities.",
        "Using a VPN.",
        "Avoiding public Wi-Fi."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A strong screen lock combined with remote wipe capabilities ensures that even if the device is lost or stolen, unauthorized users cannot access its data.",
      "examTip": "Enable a strong screen lock and remote wipe on mobile devices to protect sensitive data in case of loss or theft."
    },
    {
      "id": 74,
      "question": "What is the purpose of the Windows 'hosts' file?",
      "options": [
        "To store user passwords.",
        "To map hostnames to IP addresses, overriding DNS resolution for specific entries.",
        "To configure network adapter settings.",
        "To manage firewall rules."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The 'hosts' file is a local file that maps hostnames to IP addresses. Entries in this file take precedence over DNS, allowing manual overrides.",
      "examTip": "The hosts file can be used to block access to specific websites or redirect traffic; monitor it for unauthorized changes."
    },
    {
      "id": 75,
      "question": "A user reports that they are receiving an error message stating 'NTLDR is missing' when they try to boot their computer. What is the MOST likely cause?",
      "options": [
        "The monitor is not connected properly.",
        "The keyboard is not working.",
        "A problem with the boot sector, boot files, or boot configuration on an older Windows system (pre-Windows Vista).",
        "The network cable is unplugged."
      ],
      "correctAnswerIndex": 2,
      "explanation": "'NTLDR is missing' is an error specific to older Windows systems (e.g., Windows XP) that use the NTLDR boot loader, indicating a boot configuration issue.",
      "examTip": "Recognize that 'NTLDR is missing' pertains to older Windows systems; use recovery tools to repair the boot files."
    },
    {
      "id": 76,
      "question": "You are troubleshooting a network connectivity issue and suspect a problem with a specific router along the path to a destination. Which command-line tool would BEST help you identify the IP address of each router (hop) along the path?",
      "options": [
        "ping",
        "ipconfig",
        "tracert",
        "netstat"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`tracert` displays the route that packets take to reach a destination, showing the IP addresses of each router along the path.",
      "examTip": "Use `tracert` to identify each hop in a network path and locate potential connectivity bottlenecks."
    },
    {
      "id": 77,
      "question": "What is 'shoulder surfing' in the context of security?",
      "options": [
        "A type of phishing attack.",
        "Visually observing someone's screen or keyboard to steal their passwords, PINs, or other sensitive information.",
        "A type of denial-of-service attack.",
        "Exploiting a vulnerability in a software application."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Shoulder surfing is the practice of looking over someone’s shoulder to obtain confidential information such as passwords or PINs.",
      "examTip": "Be aware of your surroundings when entering sensitive information to prevent shoulder surfing."
    },
    {
      "id": 78,
      "question": "You are configuring a firewall and want to allow only specific types of network traffic to pass through. What is the BEST approach to achieve this?",
      "options": [
        "Block all traffic by default and then create rules to explicitly allow only the necessary traffic (default deny).",
        "Allow all traffic by default and then create rules to block specific types of unwanted traffic (default allow).",
        "Allow all traffic.",
        "Block all traffic."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A 'default deny' approach—blocking all traffic and then permitting only the necessary connections—is a fundamental security best practice for firewalls.",
      "examTip": "Configure firewalls with a default deny policy to ensure only explicitly allowed traffic is permitted."
    },
    {
      "id": 79,
      "question": "A user reports that their computer is exhibiting unusual behavior, including slow performance and unexpected pop-up ads. You suspect malware. What is the MOST important FIRST step before attempting to remove the malware?",
      "options": [
        "Reinstall the operating system.",
        "Disconnect the computer from the network to prevent the malware from spreading.",
        "Run a full system scan with antivirus software.",
        "Delete any suspicious-looking files."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Disconnecting the computer from the network is crucial to contain potential malware spread. This containment should be done as a first step before proceeding with removal.",
      "examTip": "In suspected malware incidents, disconnect the affected system from the network to prevent further spread, then proceed with removal steps."
    },
    {
      "id": 80,
      "question": "You are configuring a wireless router and want to hide the name of your Wi-Fi network from casual view. Which setting would you change?",
      "options": [
        "WPA2 encryption",
        "SSID broadcast (disable it)",
        "MAC address filtering",
        "WPS (Wi-Fi Protected Setup)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Disabling SSID broadcast hides the network name from casual scans. However, this is only a minor measure and does not provide robust security.",
      "examTip": "While disabling SSID broadcast hides your network name, always use strong encryption (WPA2/WPA3) and a strong password for effective security."
    },
    {
      "id": 81,
      "question": "A user reports that their computer is running slowly, and they are receiving 'low disk space' warnings. You've already run Disk Cleanup and removed unnecessary files, but the hard drive is still nearly full. The user has a large number of photos and videos stored on their computer. What is the BEST long-term solution?",
      "options": [
        "Defragment the hard drive.",
        "Move the photos and videos to an external hard drive, a network share, or a cloud storage service.",
        "Increase the size of the paging file.",
        "Reinstall the operating system."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Moving large media files to external or cloud storage frees up space on the internal drive and is the most effective long-term solution.",
      "examTip": "Encourage users to store large media files externally to keep the primary drive from filling up."
    },
    {
      "id": 82,
      "question": "Which of the following is the MOST secure way to dispose of a hard drive containing sensitive data?",
      "options": [
        "Deleting all files and emptying the Recycle Bin.",
        "Formatting the hard drive.",
        "Using a disk wiping utility to overwrite the data multiple times with random data, or physically destroying the hard drive.",
        "Reinstalling the operating system."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Secure disposal requires multiple overwrites or physical destruction. Simply deleting or formatting does not ensure that data cannot be recovered.",
      "examTip": "For sensitive data, use a reputable disk wiping utility or physically destroy the drive to ensure data is unrecoverable."
    },
    {
      "id": 83,
      "question": "What is the purpose of a 'DMZ' (demilitarized zone) in a network?",
      "options": [
        "To provide a secure area for internal servers.",
        "To host publicly accessible servers (like web servers) while isolating them from the internal network, providing an extra layer of security.",
        "To connect remote users to the internal network via VPN.",
        "To filter all incoming and outgoing network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DMZ is a separate network segment used to host publicly accessible servers while keeping them isolated from the internal network, thereby enhancing security.",
      "examTip": "Use a DMZ to protect your internal network by isolating servers that must be accessible from the internet."
    },
    {
      "id": 84,
      "question": "You are troubleshooting a computer that is randomly restarting. You suspect a hardware problem. You've already checked the RAM and the power supply. What is the NEXT component you should investigate?",
      "options": [
        "The keyboard.",
        "The monitor.",
        "The motherboard (including checking for bulging or leaking capacitors) and the CPU (checking for overheating).",
        "The network cable."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Random restarts can be caused by motherboard issues (such as failing capacitors) or CPU overheating. The keyboard, monitor, or network cable are unlikely causes.",
      "examTip": "Inspect the motherboard for physical damage and verify proper CPU cooling when diagnosing random restarts."
    },
    {
      "id": 85,
      "question": "You are configuring a wireless network and want to use the strongest possible encryption. Which encryption standard should you choose?",
      "options": [
        "WEP",
        "WPA",
        "WPA2 with AES",
        "WPA3 with TKIP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "WPA2 with AES is currently the recommended standard for strong wireless encryption. WPA3 is even stronger, but may not be supported by all devices.",
      "examTip": "Always choose WPA2 with AES (or WPA3 if available) for optimal wireless security."
    },
    {
      "id": 86,
      "question": "What is a 'zero-day' vulnerability?",
      "options": [
        "A vulnerability that is discovered on the first day a product is released.",
        "A vulnerability that is unknown to the software vendor and for which no patch is available.",
        "A vulnerability that only affects outdated software.",
        "A vulnerability that is easy to exploit."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A zero-day vulnerability is a security flaw that is unknown to the vendor, meaning there is no patch available. This makes zero-day exploits particularly dangerous.",
      "examTip": "Keep your systems updated to reduce exposure to zero-day vulnerabilities once patches become available."
    },
    {
      "id": 87,
      "question": "You are troubleshooting a network connectivity issue. You can ping local devices (by IP address and hostname) and your default gateway, but you cannot access any external websites. What is the MOST likely cause?",
      "options": [
        "A faulty network cable.",
        "A problem with your DNS server settings or a firewall/proxy blocking external access.",
        "The remote website servers are all down.",
        "Your computer's network adapter is disabled."
      ],
      "correctAnswerIndex": 1,
      "explanation": "If local connectivity is fine but external access fails, the issue is most likely related to DNS or outbound firewall/proxy restrictions.",
      "examTip": "Check DNS settings and outbound firewall/proxy rules when external connectivity fails despite local network access."
    },
    {
      "id": 88,
      "question": "What is the primary difference between a virus and a worm?",
      "options": [
        "Viruses are always more harmful than worms.",
        "Viruses require a host file to spread, while worms can self-replicate and spread automatically across networks.",
        "Worms are always more harmful than viruses.",
        "Viruses only affect Windows computers, while worms only affect Linux computers."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Viruses attach themselves to host files and rely on user action to spread, whereas worms are self-contained and can spread automatically over networks.",
      "examTip": "Understand that viruses need a host, while worms can propagate on their own."
    },
    {
      "id": 89,
      "question": "You are configuring a new computer and want to ensure that the system clock is always accurate. Which Windows setting should you configure?",
      "options": [
        "Power Options",
        "Date and Time settings, specifically configuring automatic time synchronization with an internet time server (e.g., time.windows.com).",
        "System Configuration (msconfig.exe)",
        "Task Manager"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The Date and Time settings in Windows allow you to enable automatic time synchronization with an internet time server, ensuring that the system clock is accurate.",
      "examTip": "Enable automatic time synchronization in Windows for accurate system time, which is essential for logging and security."
    },
    {
      "id": 90,
      "question": "What is 'phishing' in the context of cybersecurity?",
      "options": [
        "A type of malware that encrypts files.",
        "A social engineering attack that attempts to trick users into revealing sensitive information by disguising as a trustworthy entity, often via email.",
        "A network attack that floods a server with traffic.",
        "An attack that exploits software vulnerabilities."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Phishing is a social engineering technique where attackers send deceptive communications (usually emails) to trick users into providing sensitive information.",
      "examTip": "Be wary of unsolicited emails requesting personal information or containing suspicious links; verify sender authenticity before responding."
    },
    {
      "id": 91,
      "question": "Which command in Linux is used to display a list of all currently running processes?",
      "options": [
        "ls",
        "ps",
        "top",
        "jobs"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`ps` displays a snapshot of currently running processes. Although `top` provides a dynamic view, `ps` is the standard command for listing processes.",
      "examTip": "Use `ps aux` or similar options to get a comprehensive list of running processes in Linux."
    },
    {
      "id": 92,
      "question": "You are troubleshooting a slow computer. You open Task Manager and notice that the 'System Idle Process' is using a very high percentage of CPU time. What does this indicate?",
      "options": [
        "The computer is infected with malware.",
        "The computer is working very hard.",
        "The computer is mostly idle, and the high percentage represents the amount of CPU capacity that is not being used.",
        "The hard drive is failing."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The System Idle Process shows the percentage of CPU capacity that is not being used. A high percentage indicates that the CPU is largely idle.",
      "examTip": "A high System Idle Process percentage means there is plenty of available CPU capacity."
    },
    {
      "id": 93,
      "question": "What is the purpose of enabling 'Audit Policy' in Windows?",
      "options": [
        "To improve system performance.",
        "To encrypt user files.",
        "To track and log security-related events, such as user logons, object access, and policy changes, for auditing and security analysis.",
        "To manage user accounts and groups."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Audit Policy configures Windows to log specific security events. This provides an audit trail for security investigations and compliance, but it does not directly improve performance or encrypt data.",
      "examTip": "Configure Audit Policy to log key security events, aiding in threat detection and compliance."
    },
    {
      "id": 94,
      "question": "A user reports that they are unable to access a network share. You have verified that the user has the correct permissions, the file server is online, and other users can access the share. The user's computer has a valid IP address and can ping the file server. What is the NEXT step to troubleshoot?",
      "options": [
        "Reinstall the user's network adapter driver.",
        "Restart the user's computer.",
        "Check if the user's workstation can resolve the file server's hostname using `nslookup` or `ping <hostname>`. If not, troubleshoot DNS. If it can, investigate potential SMB protocol issues or firewall rules on the client or server.",
        "Run a virus scan on the user's computer."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Since basic connectivity is confirmed, the next step is to verify DNS resolution (by hostname) and then investigate SMB protocol issues or firewall restrictions if DNS is functioning correctly.",
      "examTip": "When troubleshooting network share issues, verify DNS resolution and then check SMB protocol and firewall configurations."
    },
    {
      "id": 95,
      "question": "What is 'credential stuffing' in the context of cybersecurity?",
      "options": [
        "A type of phishing attack.",
        "Using stolen usernames and passwords (often obtained from data breaches) to try to gain access to other accounts, assuming users reuse credentials across multiple sites.",
        "A type of denial-of-service attack.",
        "A type of malware that encrypts files."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Credential stuffing exploits the common practice of reusing passwords by using stolen credentials from one breach to gain access to other accounts.",
      "examTip": "Use unique, strong passwords for each account and consider multi-factor authentication to mitigate credential stuffing."
    },
    {
      "id": 96,
      "question": "You are using the `netstat` command in Windows. What does the `-b` switch do?",
      "options": [
        "Displays all active connections.",
        "Displays listening ports.",
        "Displays the executable involved in creating each connection or listening port.",
        "Displays numerical addresses instead of resolving hostnames."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The `-b` switch with netstat displays the executable (the program) responsible for each connection or listening port. This requires administrative privileges.",
      "examTip": "Run `netstat -b` as an administrator to identify which executable is responsible for network connections."
    },
    {
      "id": 97,
      "question": "You need to securely erase data from an SSD before disposing of it. Which method is MOST effective and appropriate for SSDs?",
      "options": [
        "Formatting the drive.",
        "Using the operating system's built-in secure erase function (if available) or the SSD manufacturer's secure erase utility, which utilizes the ATA Secure Erase command.",
        "Using a disk wiping utility that overwrites the data multiple times with random data.",
        "Physically destroying the drive."
      ],
      "correctAnswerIndex": 1,
      "explanation": "For SSDs, the best method is to use the manufacturer's secure erase utility (or a built-in secure erase function) that uses the ATA Secure Erase command, as traditional overwriting methods are less effective and can reduce the drive's lifespan.",
      "examTip": "Use the SSD manufacturer's secure erase tool to properly and safely wipe data from an SSD."
    },
    {
      "id": 98,
      "question": "A user reports that their computer is making a loud, grinding noise. What is the MOST likely cause?",
      "options": [
        "A failing cooling fan.",
        "A failing hard drive (if it's a traditional HDD).",
        "A failing power supply.",
        "A failing RAM module."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A grinding noise is most often associated with a failing traditional hard drive. Failing fans typically produce a buzzing or clicking sound, and RAM does not make noise.",
      "examTip": "A grinding noise from a computer is a serious warning sign; back up your data immediately and suspect a failing HDD."
    },
    {
      "id": 99,
      "question": "You are configuring a server and want to implement RAID for data redundancy and performance. You have four identical hard drives. Which RAID level would provide BOTH redundancy and increased performance?",
      "options": [
        "RAID 0",
        "RAID 1",
        "RAID 5",
        "RAID 10"
      ],
      "correctAnswerIndex": 3,
      "explanation": "RAID 10, which combines RAID 1 mirroring and RAID 0 striping, provides both redundancy and improved performance. RAID 0 lacks redundancy, RAID 1 provides only mirroring, and RAID 5 is also a viable choice, but RAID 10 is often preferred for performance.",
      "examTip": "Understand the trade-offs of different RAID levels; RAID 10 offers both redundancy and performance improvements."
    },
    {
      "id": 100,
      "question": "You are analyzing a system that you suspect is infected with malware. You want to see which programs are configured to start automatically when Windows boots. You've already checked Task Manager's Startup tab and msconfig. Where else should you check for autostart locations?",
      "options": [
        "The Windows Registry (specifically, the Run, RunOnce, RunServices, and RunServicesOnce keys under HKEY_LOCAL_MACHINE and HKEY_CURRENT_USER), and the Scheduled Tasks.",
        "The 'Program Files' folder.",
        "The 'Windows' folder.",
        "The user's 'Documents' folder."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Malware often uses registry keys (such as Run and RunOnce under HKEY_LOCAL_MACHINE and HKEY_CURRENT_USER) and Scheduled Tasks to persist. These are the key autostart locations to inspect.",
      "examTip": "Examine the Registry Run keys and Scheduled Tasks (or use Autoruns from Sysinternals) when investigating malware persistence."
    }
  ]
});
