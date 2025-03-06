db.tests.insertOne({
  "category": "aplus2",
  "testId": 6,
  "testName": "CompTIA A+ Core 2 (1102) Practice Test #6 (Formidable)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A user reports that their Windows 10 system shows an error stating 'No boot device found' after a recent system crash. The user attempted to reboot multiple times without success. Which of the following *should be the FIRST* troubleshooting step?",
      "options": [
        "Check and reseat the hard drive cables.",
        "Boot into recovery mode and run the 'bootrec /fixmbr' command.",
        "Run hardware diagnostics to check for hard drive failure.",
        "Access BIOS/UEFI settings to verify boot order."
      ],
      "correctAnswerIndex": 3,
      "explanation": "The FIRST step is to check the BIOS/UEFI settings to ensure the system is trying to boot from the correct drive. If the drive is not detected or listed incorrectly, the system cannot boot.",
      "examTip": "Always verify BIOS/UEFI boot settings before performing advanced recovery commands."
    },
    {
      "id": 2,
      "question": "A company’s BYOD policy allows employees to use personal smartphones for work. Which security feature would BEST ensure company data remains protected if a device is lost or stolen?",
      "options": [
        "Full-disk encryption",
        "Remote wipe capability",
        "Mobile antivirus solutions",
        "Screen lock with biometric authentication"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Remote wipe ensures that all corporate data can be erased from a lost or stolen device, preventing unauthorized access.",
      "examTip": "For mobile security, remote management features like wipe and location tracking are essential in BYOD environments."
    },
    {
      "id": 3,
      "question": "A user is unable to access network resources after changing their password. They can log in locally but cannot access mapped network drives. What is the *MOST likely* cause of this issue?",
      "options": [
        "Incorrect DNS settings",
        "Expired domain credentials cached on the local machine",
        "Outdated network drivers",
        "Corrupt Windows profile"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Mapped drives use cached domain credentials. After a password change, these credentials may no longer match, causing access issues.",
      "examTip": "Always re-authenticate mapped drives after changing domain credentials."
    },
    {
      "id": 4,
      "question": "You need to create a script that automates the process of backing up user files to a network share on a Windows machine. Which scripting language would be BEST suited for this task considering ease of integration with Windows systems?",
      "options": [
        "PowerShell",
        "Python",
        "Bash",
        "JavaScript"
      ],
      "correctAnswerIndex": 0,
      "explanation": "PowerShell is natively supported on Windows and provides cmdlets specifically designed for file system and network operations, making it the best choice for automation on Windows.",
      "examTip": "PowerShell is the go-to scripting language for advanced automation tasks in Windows environments."
    },
    {
      "id": 5,
      "question": "Given a scenario where a web browser displays certificate errors when accessing an internal web application, what is the *FIRST action* a technician should take to resolve the issue?",
      "options": [
        "Update the browser to the latest version.",
        "Verify the date and time settings on the client machine.",
        "Clear the browser’s cache and cookies.",
        "Install the root certificate from the internal CA."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Incorrect system date and time settings can cause valid certificates to appear invalid. Verifying and correcting these settings should be the first step.",
      "examTip": "Always check system time when dealing with certificate validation errors."
    },
    {
      "id": 6,
      "question": "Which of the following Control Panel utilities in Windows 10 allows you to manage user account privileges and ensure that least privilege principles are enforced?",
      "options": [
        "User Accounts",
        "Administrative Tools",
        "Device Manager",
        "System"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 'User Accounts' utility allows administrators to modify account types and privileges, helping to enforce least privilege principles.",
      "examTip": "Limiting user privileges reduces security risks and potential system misconfigurations."
    },
    {
      "id": 7,
      "question": "A user reports that their Linux system is not displaying available disk space. Which command should the user run to display the available disk space on all mounted filesystems?",
      "options": [
        "df -h",
        "du -sh",
        "lsblk",
        "mount"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 'df -h' command displays disk space usage in a human-readable format for all mounted file systems.",
      "examTip": "Use 'df -h' regularly to monitor disk usage on Linux systems."
    },
    {
      "id": 8,
      "question": "Which Windows feature allows you to encrypt the entire drive, ensuring data remains protected even if the drive is removed and connected to another system?",
      "options": [
        "Encrypting File System (EFS)",
        "BitLocker Drive Encryption",
        "NTFS Permissions",
        "Windows Defender Firewall"
      ],
      "correctAnswerIndex": 1,
      "explanation": "BitLocker encrypts entire drives, providing protection against unauthorized access even when the drive is physically removed.",
      "examTip": "BitLocker is ideal for securing portable devices like laptops that are at higher risk of theft."
    },
    {
      "id": 9,
      "question": "An administrator wants to ensure that users cannot install unauthorized software on their Windows systems. Which of the following would BEST achieve this goal?",
      "options": [
        "Use Group Policy to restrict application installations.",
        "Configure Windows Defender Firewall to block unknown applications.",
        "Disable Windows Installer Service.",
        "Configure BitLocker on all drives."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Group Policy can enforce application installation restrictions, preventing users from installing unauthorized software.",
      "examTip": "Group Policy is a powerful tool for managing user permissions and system configurations in domain environments."
    },
    {
      "id": 10,
      "question": "A technician needs to determine the MAC address of a Windows 10 machine. Which command-line tool provides this information quickly?",
      "options": [
        "ipconfig /all",
        "hostname",
        "tracert",
        "netstat -r"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'ipconfig /all' displays detailed network configuration information, including the MAC address for each network adapter.",
      "examTip": "Use 'ipconfig /all' for comprehensive network information, including IP, DNS, and MAC addresses."
    },
    {
      "id": 11,
      "question": "A user reports that their Windows 10 laptop cannot connect to the internet after a recent VPN configuration. Other devices on the network are working fine. What should be the FIRST step in resolving this issue?",
      "options": [
        "Check the VPN adapter settings and disable it temporarily.",
        "Reset the TCP/IP stack using the netsh command.",
        "Flush the DNS cache using the ipconfig /flushdns command.",
        "Restart the DHCP client service."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Disabling the VPN adapter temporarily checks if the VPN configuration is causing network issues without affecting other network configurations. Resetting the TCP/IP stack (netsh) may resolve deeper network issues but should follow simpler checks. Flushing the DNS cache (ipconfig /flushdns) is useful for DNS-related issues, which aren’t indicated here. Restarting the DHCP client service resolves IP assignment issues, but there’s no evidence of IP conflicts in this scenario.",
      "examTip": "Always try the least disruptive troubleshooting steps first before making major changes."
    },
    {
      "id": 12,
      "question": "Which Microsoft Windows tool provides detailed logs of application errors, security events, and system warnings, and is MOST helpful for diagnosing repeated application crashes?",
      "options": [
        "Event Viewer",
        "Performance Monitor",
        "Task Scheduler",
        "System Configuration"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Event Viewer provides comprehensive logs about applications, security events, and system warnings, essential for diagnosing application crashes. Performance Monitor tracks system performance but doesn’t provide event logs. Task Scheduler automates tasks, which is unrelated to event diagnostics. System Configuration helps with startup configurations but doesn’t provide detailed event analysis.",
      "examTip": "Use Event Viewer to analyze system and application behavior when troubleshooting recurring errors."
    },
    {
      "id": 13,
      "question": "A company wants to ensure that data stored on a stolen laptop is inaccessible. Which Windows feature provides full-disk encryption to protect data at rest?",
      "options": [
        "BitLocker",
        "Encrypting File System (EFS)",
        "NTFS permissions",
        "Group Policy Editor"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BitLocker provides full-disk encryption, ensuring data on the device remains inaccessible without proper authentication. Encrypting File System (EFS) encrypts individual files but doesn’t protect the entire disk. NTFS permissions control file access within Windows but don’t secure data outside the OS environment. Group Policy Editor configures security policies but doesn’t encrypt data.",
      "examTip": "For comprehensive data protection on portable devices, always enable full-disk encryption like BitLocker."
    },
    {
      "id": 14,
      "question": "A technician needs to configure a SOHO router to prevent guest devices from automatically discovering each other on the same wireless network. Which setting should be adjusted?",
      "options": [
        "Enable client isolation",
        "Disable SSID broadcast",
        "Change the default SSID",
        "Enable MAC filtering"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Client isolation prevents wireless clients from communicating with each other, enhancing network security in guest environments. Disabling SSID broadcast hides the network but doesn’t prevent device-to-device communication. Changing the SSID improves security slightly but doesn’t isolate clients. MAC filtering restricts network access by device but doesn’t prevent communication between connected devices.",
      "examTip": "Use client isolation on guest networks to stop lateral movement between connected devices."
    },
    {
      "id": 15,
      "question": "A Windows user is unable to run a script file with a .ps1 extension due to policy restrictions. Which PowerShell command can modify the execution policy to allow this script to run only for the current session?",
      "options": [
        "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass",
        "Set-ExecutionPolicy -ExecutionPolicy Unrestricted",
        "Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned",
        "Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy AllSigned"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Setting the execution policy to 'Bypass' for the 'Process' scope allows the script to run for the current session without changing machine-wide settings. The 'Unrestricted' policy affects broader security and should not be used casually. 'RemoteSigned' allows local scripts but requires signatures for downloaded scripts, which may not apply here. 'AllSigned' requires all scripts to be signed, which might not be feasible immediately.",
      "examTip": "Always choose the least permissive execution policy needed for the task, especially in PowerShell."
    },
    {
      "id": 16,
      "question": "An administrator wants to configure a Linux machine to share files with Windows clients on the network. Which service should be installed?",
      "options": [
        "Samba",
        "NFS",
        "Apache",
        "MySQL"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Samba allows Linux systems to share files with Windows machines using the SMB/CIFS protocol. NFS is primarily for Unix/Linux file sharing, not Windows compatibility. Apache is a web server and unrelated to file sharing. MySQL is a database management system, not intended for file sharing purposes.",
      "examTip": "Use Samba for cross-platform file sharing between Linux and Windows systems."
    },
    {
      "id": 17,
      "question": "A user’s browser keeps redirecting to suspicious websites, and pop-ups appear even when no browser is open. Which malware type is MOST likely responsible?",
      "options": [
        "Adware",
        "Spyware",
        "Rootkit",
        "Ransomware"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Adware generates pop-ups and redirects browsers to generate ad revenue, often displaying unwanted ads persistently. Spyware tracks user activity but doesn’t typically cause browser redirection. Rootkits hide malicious processes but aren’t directly associated with pop-ups. Ransomware encrypts files for ransom demands and doesn’t cause ad pop-ups.",
      "examTip": "Pop-ups and browser redirects without user action strongly indicate adware infections."
    },
    {
      "id": 18,
      "question": "A technician needs to ensure that unauthorized users cannot boot a system from external media. Which security setting should be configured in the BIOS/UEFI?",
      "options": [
        "Set a BIOS password and disable external boot options.",
        "Enable Secure Boot.",
        "Enable TPM.",
        "Configure drive encryption."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Setting a BIOS password and disabling external boot options prevents unauthorized boot attempts from USB or optical drives. Secure Boot ensures only signed OS bootloaders run but doesn’t block external boot methods. TPM is for encryption, not boot prevention. Drive encryption protects data but doesn’t prevent external booting.",
      "examTip": "Physical security starts at boot—use BIOS passwords and disable external boot paths."
    },
    {
      "id": 19,
      "question": "Which wireless encryption standard provides the STRONGEST security for a modern SOHO environment?",
      "options": [
        "WPA3",
        "WPA2 with AES",
        "WEP",
        "WPA with TKIP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3 is the latest wireless security standard, offering stronger encryption and protection against brute-force attacks. WPA2 with AES is secure but lacks WPA3's enhancements like forward secrecy. WEP is outdated and easily compromised. WPA with TKIP is less secure than WPA2 and WPA3.",
      "examTip": "Always select the most current wireless security standard available, currently WPA3."
    },
    {
      "id": 20,
      "question": "A technician needs to determine the IP address and subnet mask of a Windows machine from the command line. Which command should be used?",
      "options": [
        "ipconfig",
        "nslookup",
        "ping",
        "tracert"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The ipconfig command displays IP address, subnet mask, and default gateway information for Windows machines. Nslookup queries DNS records, not IP configurations. Ping tests connectivity but doesn’t display IP configurations. Tracert shows network paths, not IP configuration details.",
      "examTip": "For basic IP configuration details in Windows, ipconfig is the go-to command."
    },
    {
      "id": 21,
      "question": "A user reports that after installing a third-party application, their Windows 10 system takes significantly longer to boot. Which built-in utility should the technician use FIRST to identify and disable unnecessary startup programs?",
      "options": [
        "Task Manager",
        "System Configuration",
        "Performance Monitor",
        "Disk Management"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Task Manager provides a straightforward interface for managing startup programs in Windows 10, allowing quick identification and disabling of unnecessary applications. System Configuration can manage startup tasks but redirects users to Task Manager in Windows 10. Performance Monitor provides detailed system performance data but not direct startup management. Disk Management handles storage configurations, not startup processes.",
      "examTip": "For Windows 10 startup issues, Task Manager is the quickest way to control startup applications."
    },
    {
      "id": 22,
      "question": "A user is unable to print to a network printer but can access shared files on the same network. What is the MOST likely cause of the issue?",
      "options": [
        "The Print Spooler service is stopped.",
        "The network printer's IP address has changed.",
        "User permissions to the printer are misconfigured.",
        "The printer driver is outdated."
      ],
      "correctAnswerIndex": 0,
      "explanation": "The Print Spooler service manages print jobs; if stopped, it prevents printing even if the network connection is intact. A changed IP address would cause network-related issues, but the user can still access shared files, indicating the network is functioning. Misconfigured permissions would generate access-denied errors, which are not reported. An outdated driver typically causes print errors, not complete inability to print.",
      "examTip": "Check service status like the Print Spooler first when print jobs fail despite proper network access."
    },
    {
      "id": 23,
      "question": "A technician is setting up a dual-boot environment with Windows 10 and Ubuntu Linux on a single machine. Which partitioning scheme should be used to support drives larger than 2TB and multiple operating systems?",
      "options": [
        "GUID Partition Table (GPT)",
        "Master Boot Record (MBR)",
        "NTFS",
        "ext4"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The GUID Partition Table (GPT) supports drives larger than 2TB and multiple operating systems, making it ideal for dual-boot setups. The Master Boot Record (MBR) only supports up to 2TB drives and fewer partitions. NTFS is a file system for Windows but not a partitioning scheme. ext4 is a Linux file system and also not a partitioning scheme.",
      "examTip": "Use GPT for modern systems requiring large drives and multiple OS support."
    },
    {
      "id": 24,
      "question": "A user’s macOS device is running slowly. The technician suspects there are too many applications running at startup. Which built-in macOS tool can BEST help manage startup items?",
      "options": [
        "System Preferences > Users & Groups",
        "Terminal",
        "Activity Monitor",
        "Disk Utility"
      ],
      "correctAnswerIndex": 0,
      "explanation": "In macOS, managing startup items is done via System Preferences > Users & Groups under the Login Items tab. Terminal can control processes via commands but is not the primary method for managing startup programs. Activity Monitor shows running processes but doesn’t manage startup items. Disk Utility handles storage management, not startup configurations.",
      "examTip": "For macOS startup issues, always review Login Items in Users & Groups first."
    },
    {
      "id": 25,
      "question": "A SOHO user wants to prevent IoT devices from accessing the main network but still allow them to access the internet. Which network configuration should be implemented on the router?",
      "options": [
        "Create a guest network for the IoT devices.",
        "Enable port forwarding for IoT device IP addresses.",
        "Configure static IPs for IoT devices on the main network.",
        "Disable UPnP for IoT devices."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Creating a guest network isolates IoT devices from the main network while still providing internet access. Port forwarding allows external services to reach internal devices, which may introduce security risks. Assigning static IPs doesn’t provide network isolation. Disabling UPnP enhances security but doesn’t isolate IoT devices from the main network.",
      "examTip": "Segment IoT devices on a guest network to prevent lateral movement and secure the primary network."
    },
    {
      "id": 26,
      "question": "A technician needs to gather detailed real-time performance data on CPU, memory, disk, and network usage on a Windows 10 workstation. Which tool should be used?",
      "options": [
        "Resource Monitor",
        "System Information (msinfo32)",
        "Task Manager",
        "Event Viewer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Resource Monitor provides real-time, detailed information on CPU, memory, disk, and network usage. System Information (msinfo32) displays system specifications but not real-time performance data. Task Manager offers basic performance monitoring but lacks the detailed insights of Resource Monitor. Event Viewer logs system events but doesn’t provide live performance data.",
      "examTip": "Use Resource Monitor for granular, real-time performance insights beyond Task Manager’s overview."
    },
    {
      "id": 27,
      "question": "A technician is troubleshooting a Linux server with slow network performance. Which command will provide a summary of network connections, routing tables, and interface statistics?",
      "options": [
        "netstat",
        "ipconfig",
        "ping",
        "traceroute"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The netstat command displays active network connections, routing tables, and network statistics, making it ideal for diagnosing network performance issues. ipconfig is a Windows command and doesn’t provide network statistics on Linux. ping checks basic connectivity but not detailed network information. traceroute identifies the path packets take but doesn’t summarize network statistics.",
      "examTip": "For comprehensive network diagnostics on Linux, netstat is a key tool."
    },
    {
      "id": 28,
      "question": "A Windows 10 system displays 'BOOTMGR is missing' during startup. What is the FIRST step to attempt a fix without data loss?",
      "options": [
        "Boot from installation media and run Startup Repair.",
        "Perform a clean installation of Windows 10.",
        "Format the system partition and reinstall the OS.",
        "Replace the hard drive and restore from backup."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Running Startup Repair from installation media can restore the missing BOOTMGR without data loss. A clean installation would erase existing data. Formatting the system partition also leads to complete data loss. Replacing the hard drive is unnecessary unless hardware failure is confirmed.",
      "examTip": "Always try repair options like Startup Repair before considering data-destructive solutions."
    },
    {
      "id": 29,
      "question": "A user is unable to access secure websites (HTTPS) but can access non-secure websites (HTTP). What is the MOST likely cause of this issue?",
      "options": [
        "Incorrect system date and time settings.",
        "Faulty Ethernet cable.",
        "Outdated network driver.",
        "Corrupted web browser installation."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Incorrect date and time settings can cause HTTPS certificate validation errors, blocking secure websites. A faulty Ethernet cable would prevent all web access, not just HTTPS. An outdated network driver could cause broader connectivity issues, not just HTTPS access problems. A corrupted browser would likely prevent all browsing or cause application crashes, not selective HTTPS failures.",
      "examTip": "Check system date and time first when encountering HTTPS-specific access issues."
    },
    {
      "id": 30,
      "question": "A technician is setting up security on a Windows 10 workstation. Which feature should be enabled to ensure that only signed operating system bootloaders are allowed to run during startup?",
      "options": [
        "Secure Boot",
        "BitLocker",
        "TPM",
        "UEFI Fast Boot"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Secure Boot ensures that only signed, trusted operating system bootloaders are executed, protecting against boot-level malware. BitLocker provides drive encryption but doesn’t validate bootloaders. TPM stores encryption keys but doesn’t control bootloader execution. UEFI Fast Boot reduces boot time without adding bootloader security.",
      "examTip": "Enable Secure Boot in UEFI settings for protection against unauthorized bootloaders."
    },
    {
      "id": 31,
      "question": "A Linux administrator needs to change the permissions of a script to make it executable by all users. Which command will accomplish this?",
      "options": [
        "chmod +x script.sh",
        "chown root:root script.sh",
        "chmod 600 script.sh",
        "chmod u+x script.sh"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The chmod +x script.sh command adds execute permissions for all users on the specified script. chown root:root changes file ownership, not permissions. chmod 600 grants read/write access to the owner only, removing execute permissions. chmod u+x adds execute permission only for the owner, not all users.",
      "examTip": "Use chmod +x to make scripts executable by all users in Linux environments."
    },
    {
      "id": 32,
      "question": "A technician needs to automate daily backups on a Windows 10 machine without user intervention. Which built-in tool should the technician use to schedule the backup task?",
      "options": [
        "Task Scheduler",
        "Backup and Restore (Windows 7)",
        "System Configuration",
        "Event Viewer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Task Scheduler allows the automation of tasks like backups at specified intervals without user interaction. Backup and Restore (Windows 7) is used for manual or semi-automated backups but lacks advanced scheduling. System Configuration helps with startup settings, not scheduled backups. Event Viewer logs events but doesn’t manage scheduled tasks.",
      "examTip": "Use Task Scheduler for automating recurring tasks like backups on Windows systems."
    },
    {
      "id": 33,
      "question": "A user reports that their Windows 10 computer shows the error 'Operating System not found' at startup. The technician confirms the hard drive is functioning. What is the MOST likely cause of this issue?",
      "options": [
        "Corrupted boot sector",
        "Faulty SATA cable",
        "Incorrect display driver",
        "Insufficient RAM"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A corrupted boot sector can prevent the operating system from being located during startup. A faulty SATA cable would likely cause the hard drive to be undetectable, not just missing the OS. Display drivers do not impact system boot processes. Insufficient RAM would prevent the system from operating properly but wouldn’t cause a missing OS error.",
      "examTip": "Boot sector corruption is a common cause of missing OS errors; use boot repair tools first."
    },
    {
      "id": 34,
      "question": "A technician needs to ensure that users cannot access or modify system files on a shared Windows computer. Which method provides the MOST effective protection?",
      "options": [
        "Configure NTFS permissions to restrict access.",
        "Use share permissions on the folder containing the system files.",
        "Enable Windows Defender Firewall.",
        "Enable BitLocker on the system drive."
      ],
      "correctAnswerIndex": 0,
      "explanation": "NTFS permissions provide granular control over file access, including the ability to prevent modification or deletion. Share permissions apply only to network shares, not local access. Windows Defender Firewall protects against network-based threats but doesn’t control file access. BitLocker encrypts the drive but doesn’t control access for authenticated users.",
      "examTip": "Use NTFS permissions for precise file access control in Windows environments."
    },
    {
      "id": 35,
      "question": "Which of the following security measures provides the STRONGEST protection against brute-force attacks on user accounts in a corporate environment?",
      "options": [
        "Implement multifactor authentication (MFA).",
        "Enforce complex password policies.",
        "Disable accounts after multiple failed login attempts.",
        "Use a CAPTCHA on the login screen."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Multifactor authentication (MFA) adds an extra layer of security, making it significantly harder for brute-force attacks to succeed. Complex password policies help but can still be vulnerable to brute-force methods. Disabling accounts after failed attempts reduces attack windows but doesn’t prevent initial brute-force attempts. CAPTCHAs help block automated attacks but not manual brute-force attempts.",
      "examTip": "MFA is the gold standard for protecting user accounts against unauthorized access."
    },
    {
      "id": 36,
      "question": "A user’s laptop is experiencing intermittent Wi-Fi connectivity issues. Other devices on the same network are working fine. What should the technician check FIRST?",
      "options": [
        "Update the wireless network adapter driver.",
        "Replace the laptop’s wireless card.",
        "Reset the router to factory settings.",
        "Change the Wi-Fi channel on the router."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Updating the wireless adapter driver resolves many compatibility and connectivity issues and is the least disruptive first step. Replacing the wireless card is costly and should follow after software troubleshooting. Resetting the router affects all users and should be avoided unless necessary. Changing the Wi-Fi channel helps with interference but is a network-wide adjustment rather than a device-specific solution.",
      "examTip": "Always start troubleshooting with non-intrusive software solutions before replacing hardware."
    },
    {
      "id": 37,
      "question": "A technician suspects that a user's system has a rootkit infection. Which tool should be used to detect and remove the rootkit?",
      "options": [
        "Rootkit removal tool from a trusted security vendor.",
        "Standard antivirus software scan.",
        "Disk Cleanup utility.",
        "Windows Defender Firewall settings."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Rootkits require specialized removal tools because they operate at a low level in the OS, making them invisible to standard antivirus scans. Standard antivirus software often misses rootkits. Disk Cleanup only removes temporary files and doesn’t address malware. Windows Defender Firewall settings control network access but don’t detect rootkits.",
      "examTip": "For suspected rootkits, use specialized removal tools and consider offline scanning methods."
    },
    {
      "id": 38,
      "question": "An administrator needs to allow a Windows application through the firewall for all users. Which tool provides the MOST direct way to achieve this?",
      "options": [
        "Windows Defender Firewall with Advanced Security",
        "Local Group Policy Editor",
        "Control Panel > Programs and Features",
        "Task Manager"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Windows Defender Firewall with Advanced Security provides detailed control over firewall rules, including allowing specific applications. Local Group Policy Editor can enforce settings but is more complex for this purpose. Programs and Features is for software management, not firewall configuration. Task Manager manages processes and performance, not firewall rules.",
      "examTip": "For firewall rule adjustments, always use Windows Defender Firewall with Advanced Security for granular control."
    },
    {
      "id": 39,
      "question": "Which file system should be used on a removable USB drive to ensure compatibility with both Windows and macOS systems without file size limitations?",
      "options": [
        "exFAT",
        "FAT32",
        "NTFS",
        "APFS"
      ],
      "correctAnswerIndex": 0,
      "explanation": "exFAT supports large file sizes and is compatible with both Windows and macOS, making it ideal for cross-platform USB drives. FAT32 has a 4GB file size limit. NTFS is fully supported by Windows but macOS can only read it without third-party drivers. APFS is proprietary to macOS and unsupported by Windows.",
      "examTip": "Use exFAT for removable storage when cross-platform compatibility without file size restrictions is required."
    },
    {
      "id": 40,
      "question": "A Linux user needs to view the contents of a text file without opening a text editor. Which command will accomplish this?",
      "options": [
        "cat filename",
        "rm filename",
        "chmod filename",
        "mv filename"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The cat command displays the contents of a file directly in the terminal. rm deletes the file. chmod changes file permissions. mv moves or renames files, none of which display file contents.",
      "examTip": "Use cat for quick, read-only file viewing in Linux without launching an editor."
    },
    {
      "id": 41,
      "question": "A user’s Windows 10 PC shows frequent 'Low Virtual Memory' warnings. Which action would BEST resolve this issue without adding physical RAM?",
      "options": [
        "Increase the size of the paging file.",
        "Defragment the hard drive.",
        "Disable startup applications.",
        "Run Disk Cleanup."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Increasing the paging file size allows Windows to use more virtual memory, reducing such warnings. Defragmenting the hard drive improves disk performance but doesn’t impact virtual memory. Disabling startup applications reduces memory usage during boot but may not solve persistent memory issues. Disk Cleanup frees disk space but doesn’t affect memory allocation.",
      "examTip": "Adjust the paging file size in system settings when virtual memory warnings occur."
    },
    {
      "id": 42,
      "question": "A user reports that their Android smartphone cannot install applications from the Google Play Store. Storage space is available. What should the technician check FIRST?",
      "options": [
        "Verify that the Google account is properly synced.",
        "Perform a factory reset of the device.",
        "Replace the microSD card.",
        "Clear the app cache and data of the Google Play Store."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A misconfigured or unsynced Google account can prevent app installations. Factory resets should be a last resort. Replacing the microSD card isn’t necessary unless storage corruption is confirmed. Clearing the Play Store cache and data can help but comes after account verification.",
      "examTip": "Always check account configurations first when app installations fail on Android devices."
    },
    {
      "id": 43,
      "question": "A technician is tasked with encrypting specific files on a Windows 10 system. Which feature should be used?",
      "options": [
        "Encrypting File System (EFS)",
        "BitLocker",
        "Group Policy Editor",
        "NTFS permissions"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Encrypting File System (EFS) allows encryption of individual files and folders on NTFS volumes. BitLocker encrypts entire drives, not individual files. Group Policy Editor manages system policies, not file encryption. NTFS permissions control access but don’t encrypt data.",
      "examTip": "Use EFS for granular file-level encryption in Windows environments."
    },
    {
      "id": 44,
      "question": "Which command-line utility in Windows can be used to repair system files and potentially resolve OS corruption issues?",
      "options": [
        "sfc /scannow",
        "chkdsk /f",
        "diskpart",
        "netstat"
      ],
      "correctAnswerIndex": 0,
      "explanation": "sfc /scannow scans and repairs corrupted system files in Windows. chkdsk /f checks and fixes disk errors, not system files. diskpart manages disk partitions. netstat shows network connections but doesn’t repair files.",
      "examTip": "sfc /scannow is essential for addressing corrupted system files without reinstallation."
    },
    {
      "id": 45,
      "question": "A technician needs to connect to a remote Windows computer securely over the internet. Which tool provides encrypted access?",
      "options": [
        "Remote Desktop Protocol (RDP)",
        "Telnet",
        "FTP",
        "VNC without encryption"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RDP provides encrypted remote desktop connections in Windows environments. Telnet transmits data unencrypted. FTP is for file transfers and lacks built-in encryption. VNC without encryption doesn’t secure remote sessions.",
      "examTip": "Always choose encrypted protocols like RDP when accessing systems remotely over the internet."
    },
    {
      "id": 46,
      "question": "Which protocol is used to securely transfer files over a network and provides encryption by default?",
      "options": [
        "SFTP",
        "FTP",
        "HTTP",
        "Telnet"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SFTP (SSH File Transfer Protocol) transfers files securely using encryption. FTP lacks encryption by default. HTTP transfers web data without encryption. Telnet provides command-line access but is unencrypted.",
      "examTip": "For secure file transfers, always use SFTP or similar encrypted protocols."
    },
    {
      "id": 47,
      "question": "A user reports that their macOS system is not connecting to the company’s VPN. Which tool in macOS can provide detailed logs to troubleshoot the VPN connection?",
      "options": [
        "Console",
        "Keychain Access",
        "Activity Monitor",
        "Disk Utility"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Console provides system logs, including network and VPN connection details. Keychain Access manages passwords and certificates but doesn’t provide logs. Activity Monitor shows resource usage, not logs. Disk Utility handles storage, not network troubleshooting.",
      "examTip": "Console is the primary tool for viewing detailed system logs in macOS, including VPN errors."
    },
    {
      "id": 48,
      "question": "A user complains that their Windows laptop screen flickers after waking from sleep. Which Windows tool can BEST help diagnose and resolve this issue?",
      "options": [
        "Device Manager",
        "Performance Monitor",
        "Disk Management",
        "Resource Monitor"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Device Manager helps identify driver issues, such as outdated or incompatible display drivers that can cause screen flickering. Performance Monitor tracks performance metrics but doesn’t handle hardware drivers. Disk Management manages storage but is unrelated to display issues. Resource Monitor analyzes resource usage, not hardware compatibility.",
      "examTip": "Screen flickering after sleep often points to display driver issues; check Device Manager first."
    },
    {
      "id": 49,
      "question": "A technician needs to determine if a Linux process is consuming excessive CPU resources. Which command will display real-time process activity?",
      "options": [
        "top",
        "ls",
        "grep",
        "chmod"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The top command shows real-time system processes and resource consumption in Linux. ls lists directory contents. grep searches text patterns. chmod changes file permissions and is unrelated to process monitoring.",
      "examTip": "Use top in Linux to monitor real-time process activity and system resource usage."
    },
    {
      "id": 50,
      "question": "A user reports being unable to access a secure internal website with an HTTPS error indicating an invalid certificate. What is the MOST likely cause?",
      "options": [
        "The system’s date and time are incorrect.",
        "The website’s DNS record is missing.",
        "The user’s browser needs updating.",
        "The network firewall is blocking HTTPS traffic."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Incorrect system date and time cause SSL certificate validation failures, leading to HTTPS errors. A missing DNS record would prevent site resolution, not cause certificate errors. An outdated browser could cause compatibility issues but rarely affects certificate validity. A firewall blocking HTTPS would result in complete inaccessibility, not certificate warnings.",
      "examTip": "SSL certificate errors often relate to incorrect date and time settings on the client device."
    },
    {
      "id": 51,
      "question": "A user’s Windows PC boots to a black screen with a blinking cursor after POST. What is the MOST likely cause?",
      "options": [
        "Corrupt bootloader or missing boot files.",
        "Outdated graphics driver.",
        "Faulty RAM module.",
        "Incorrect display settings."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A black screen with a blinking cursor after POST typically indicates a corrupt bootloader or missing boot files. An outdated graphics driver would cause display issues after OS loading, not during boot. Faulty RAM would prevent POST success. Incorrect display settings wouldn’t affect the initial boot sequence.",
      "examTip": "Boot issues after POST often signal bootloader corruption—run repair tools from recovery media first."
    },
    {
      "id": 52,
      "question": "A user reports that their Windows 10 computer is displaying a 'The trust relationship between this workstation and the primary domain failed' error after rebooting. What is the BEST way to resolve this issue without losing the user profile?",
      "options": [
        "Rejoin the workstation to the domain.",
        "Reset the user profile on the workstation.",
        "Restore the system from the latest backup.",
        "Reinstall the operating system."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Rejoining the workstation to the domain resets the secure channel without affecting the user profile. Resetting the user profile may cause data loss and is unnecessary. Restoring from backup is more disruptive and should be a last resort. Reinstalling the operating system would erase the user profile and is the most drastic step.",
      "examTip": "Domain trust issues are typically resolved by rejoining the computer to the domain without impacting user data."
    },
    {
      "id": 53,
      "question": "A technician needs to deploy an application to multiple Windows 10 workstations in a corporate environment with minimal user interaction. Which deployment method is MOST appropriate?",
      "options": [
        "Use Group Policy Software Installation (GPSI).",
        "Manually install the application on each workstation.",
        "Provide installation files and instructions to users.",
        "Perform in-place upgrades on all workstations."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Group Policy Software Installation (GPSI) allows automated deployment of applications across multiple systems with minimal user interaction. Manual installations are time-consuming and prone to user error. Providing installation files to users lacks consistency. In-place upgrades relate to OS upgrades, not application deployment.",
      "examTip": "Group Policy provides centralized, automated application deployment for Windows domain environments."
    },
    {
      "id": 54,
      "question": "A user complains that their Windows laptop displays the message 'No bootable device found' after a hard shutdown. The technician confirms that the hard drive is operational. What should be checked NEXT?",
      "options": [
        "Verify the boot order in the BIOS/UEFI settings.",
        "Run a full disk check using chkdsk.",
        "Perform a memory diagnostic test.",
        "Reset Windows to factory defaults."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Verifying the boot order ensures that the system is attempting to boot from the correct device. A misconfigured boot order is common after hard shutdowns. Running chkdsk checks disk integrity but doesn’t address boot sequence issues. Memory diagnostics target RAM problems, not boot errors. Factory resets would erase user data and should be a last resort.",
      "examTip": "Always confirm BIOS/UEFI boot order first when troubleshooting 'No bootable device' errors."
    },
    {
      "id": 55,
      "question": "A user’s Android device fails to connect to a corporate Wi-Fi network that uses WPA3 encryption, while other devices connect without issues. What is the MOST likely cause?",
      "options": [
        "The device’s operating system does not support WPA3.",
        "The Wi-Fi password entered is incorrect.",
        "The Wi-Fi network is hidden and requires manual connection.",
        "The device’s MAC address is blocked on the network."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Older Android devices or those without recent updates may not support WPA3 encryption, leading to connection failures. An incorrect password would prompt authentication errors. Hidden networks still allow manual connection attempts. MAC address filtering would block the device regardless of encryption compatibility.",
      "examTip": "Ensure mobile OS updates support the latest encryption protocols like WPA3 for network compatibility."
    },
    {
      "id": 56,
      "question": "A technician needs to free up disk space on a Windows 10 computer by removing old Windows update files. Which built-in tool should be used?",
      "options": [
        "Disk Cleanup",
        "Disk Management",
        "System Restore",
        "Task Scheduler"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Disk Cleanup allows the removal of old Windows update files, freeing up space without affecting system functionality. Disk Management handles partition and volume management but doesn’t clean up files. System Restore manages restore points but doesn’t remove update files. Task Scheduler automates tasks but doesn’t remove files.",
      "examTip": "Use Disk Cleanup to safely remove unnecessary system files, including outdated Windows updates."
    },
    {
      "id": 57,
      "question": "A Linux administrator needs to search for the term 'backup' in a large log file. Which command should be used?",
      "options": [
        "grep backup logfile.txt",
        "cat logfile.txt",
        "chmod backup logfile.txt",
        "ps aux | grep backup"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The grep command searches for specific terms within files, making it ideal for locating 'backup' in a log file. The cat command displays the entire file without search functionality. chmod changes file permissions. ps aux | grep backup lists running processes matching 'backup', not file contents.",
      "examTip": "Use grep for efficient keyword searches in Linux log files and text documents."
    },
    {
      "id": 58,
      "question": "A user reports that their laptop shuts down unexpectedly when unplugged from AC power. What is the MOST likely cause of the issue?",
      "options": [
        "The battery is failing and no longer holds a charge.",
        "The laptop’s power adapter is faulty.",
        "The operating system needs a critical update.",
        "The laptop’s cooling fan is malfunctioning."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A failing battery that cannot hold a charge causes shutdowns when the AC adapter is disconnected. A faulty power adapter would prevent charging altogether. OS updates don’t typically cause shutdowns when switching power sources. A malfunctioning cooling fan would cause overheating, not immediate shutdowns upon unplugging.",
      "examTip": "Test battery health when laptops shut down immediately after being unplugged from power."
    },
    {
      "id": 59,
      "question": "Which wireless protocol provides the HIGHEST level of security for a corporate wireless network using modern encryption standards?",
      "options": [
        "WPA3-Enterprise",
        "WPA2-Personal",
        "WEP",
        "WPA with TKIP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3-Enterprise offers the highest level of wireless security with robust encryption and user authentication. WPA2-Personal is secure for home use but lacks enterprise-level features. WEP is outdated and easily compromised. WPA with TKIP uses weaker encryption compared to WPA3-Enterprise.",
      "examTip": "For corporate wireless environments, always implement WPA3-Enterprise for the strongest security."
    },
    {
      "id": 60,
      "question": "A Windows 10 user needs to view hidden files and file extensions in File Explorer. Which option should the user configure?",
      "options": [
        "File Explorer Options > View tab",
        "Control Panel > System",
        "Device Manager > View",
        "Power Options > Advanced settings"
      ],
      "correctAnswerIndex": 0,
      "explanation": "File Explorer Options under the View tab allows users to display hidden files and file extensions. Control Panel > System shows system information but doesn’t manage file visibility. Device Manager > View changes hardware view settings. Power Options > Advanced settings configures power management, not file visibility.",
      "examTip": "Access File Explorer’s View tab to manage hidden files and file extension settings quickly."
    },
    {
      "id": 61,
      "question": "A technician needs to configure a workstation so that it automatically obtains its IP address and DNS information from a DHCP server. Which setting should be adjusted?",
      "options": [
        "Network adapter properties to obtain IP and DNS automatically.",
        "Hosts file entries for IP address resolution.",
        "Static IP address configuration in the adapter settings.",
        "Manual DNS entries in the adapter properties."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Configuring the network adapter to obtain IP and DNS settings automatically ensures that the DHCP server assigns the necessary information. Editing the hosts file affects only hostname resolution, not IP configuration. Static IP configurations bypass DHCP, which is not desired here. Manual DNS entries override DHCP-provided settings.",
      "examTip": "For dynamic network configurations, set network adapters to obtain IP and DNS settings automatically."
    },
    {
      "id": 62,
      "question": "A user reports that their Windows system displays a 'Blue Screen of Death' (BSOD) referencing 'IRQL_NOT_LESS_OR_EQUAL.' What is the MOST common cause of this error?",
      "options": [
        "Faulty or incompatible drivers.",
        "Insufficient disk space.",
        "Corrupted user profile.",
        "Unpatched application software."
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 'IRQL_NOT_LESS_OR_EQUAL' BSOD typically occurs due to faulty or incompatible drivers. Insufficient disk space leads to performance issues but not this specific BSOD. A corrupted user profile causes login issues, not system crashes. Unpatched software affects application performance, not kernel-level errors.",
      "examTip": "Always check for driver issues first when encountering 'IRQL_NOT_LESS_OR_EQUAL' BSOD errors."
    },
    {
      "id": 63,
      "question": "A technician needs to ensure that files deleted from a shared network folder can be recovered. Which feature should be enabled on the file server?",
      "options": [
        "Shadow Copies",
        "BitLocker Drive Encryption",
        "EFS (Encrypting File System)",
        "NTFS compression"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Shadow Copies allow users to restore previous versions of files deleted from shared folders. BitLocker encrypts entire drives but doesn’t assist in file recovery. EFS encrypts files but doesn’t create backups. NTFS compression saves disk space but doesn’t provide recovery capabilities.",
      "examTip": "Enable Shadow Copies for effortless recovery of deleted or modified files in shared environments."
    },
    {
      "id": 64,
      "question": "A user is experiencing slow network performance when accessing cloud-based applications. Which troubleshooting step should the technician perform FIRST?",
      "options": [
        "Test the network speed using a trusted speed test tool.",
        "Replace the Ethernet cable connecting the user’s workstation.",
        "Reinstall the network adapter drivers.",
        "Perform a complete operating system reinstall."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Testing the network speed identifies whether bandwidth limitations or connectivity issues are causing slow performance. Replacing the Ethernet cable or reinstalling drivers should be considered after verifying network speed. An OS reinstall is drastic and unwarranted without further evidence.",
      "examTip": "Always verify network speed and connectivity before making hardware or software changes for network issues."
    },
    {
      "id": 65,
      "question": "A technician suspects a phishing attack after a user received an email requesting login credentials. What is the FIRST step the technician should take?",
      "options": [
        "Instruct the user not to respond to the email or click any links.",
        "Reset the user’s password immediately.",
        "Report the incident to management and IT security.",
        "Perform a malware scan on the user’s workstation."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Instructing the user not to interact with the suspicious email prevents potential credential theft or malware execution. Password resets are necessary only if credentials were compromised. Reporting the incident and scanning for malware are important but follow after ensuring user safety.",
      "examTip": "Educating users to avoid interacting with suspicious emails is the first defense against phishing."
    },
    {
      "id": 66,
      "question": "A company requires a backup strategy that allows full data restoration with minimal time and storage requirements. Which backup method should be used?",
      "options": [
        "Incremental backup",
        "Full backup",
        "Differential backup",
        "Synthetic backup"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Incremental backups only store changes made since the last backup, saving time and storage while allowing full data restoration. Full backups require more time and storage. Differential backups accumulate changes since the last full backup, using more storage than incremental. Synthetic backups combine full and incremental backups but are more complex.",
      "examTip": "Incremental backups balance restoration speed and storage efficiency, ideal for most enterprise needs."
    },
    {
      "id": 67,
      "question": "Which scripting language is commonly used in Windows environments for automating administrative tasks?",
      "options": [
        "PowerShell",
        "Bash",
        "Python",
        "JavaScript"
      ],
      "correctAnswerIndex": 0,
      "explanation": "PowerShell is designed specifically for Windows environments, providing powerful scripting capabilities for administrative automation. Bash is native to Unix/Linux systems. Python is versatile but not Windows-specific. JavaScript is used for web development, not system administration.",
      "examTip": "PowerShell is the default choice for Windows automation due to its deep integration with the OS."
    },
    {
      "id": 68,
      "question": "A user reports that their web browser frequently redirects to unknown pages and displays pop-up ads. Which is the MOST likely cause?",
      "options": [
        "Adware infection",
        "Corrupted browser cache",
        "Outdated web browser version",
        "DNS misconfiguration"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Adware causes browser redirects and persistent pop-up ads. Corrupted cache may slow browsing but doesn’t cause redirects. An outdated browser may have security risks but wouldn’t typically cause forced redirects. DNS misconfiguration affects site resolution but not browser-specific redirections.",
      "examTip": "Pop-ups and redirects are classic signs of adware—run a full malware scan to resolve."
    },
    {
      "id": 69,
      "question": "A technician needs to provide secure remote access to a company’s internal network for employees working from home. Which technology should be implemented?",
      "options": [
        "Virtual Private Network (VPN)",
        "Remote Desktop Protocol (RDP) over the internet without encryption",
        "File Transfer Protocol (FTP)",
        "Telnet"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A Virtual Private Network (VPN) securely encrypts communications, allowing safe remote access to internal resources. RDP without encryption exposes sessions to interception. FTP lacks encryption unless paired with secure protocols. Telnet transmits data unencrypted and is not secure for remote access.",
      "examTip": "Implement VPNs for secure remote access, protecting data integrity and confidentiality."
    },
    {
      "id": 70,
      "question": "A Linux user wants to edit a text file from the command line using a simple text editor. Which command should be used?",
      "options": [
        "nano filename",
        "cat filename",
        "chmod filename",
        "rm filename"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The nano command opens a simple terminal-based text editor, allowing file editing. cat displays file contents without editing capability. chmod changes file permissions. rm deletes the file, which is not related to editing.",
      "examTip": "Use nano for quick and simple text editing from the Linux terminal."
    },
    {
      "id": 71,
      "question": "A user’s mobile device is not syncing emails from the corporate mail server. Other services are working normally. What should the technician check FIRST?",
      "options": [
        "Verify the email account credentials and server settings.",
        "Restart the mobile device.",
        "Update the mobile device’s operating system.",
        "Factory reset the mobile device."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Incorrect email credentials or server settings are common causes of email sync issues. Restarting the device may help with general issues but is less likely the root cause. Updating the OS is beneficial but rarely resolves email-specific issues. Factory resets should be a last resort due to data loss risks.",
      "examTip": "Check account credentials and server settings first when dealing with email synchronization issues."
    },
    {
      "id": 72,
      "question": "A user reports that after updating their Windows 10 laptop, the system fails to boot and displays the error 'INACCESSIBLE_BOOT_DEVICE.' What is the BEST next step to resolve this issue without losing user data?",
      "options": [
        "Boot into Safe Mode and uninstall the latest updates.",
        "Perform a clean installation of Windows 10.",
        "Replace the hard drive and restore from backup.",
        "Run a full system reset from recovery options."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Booting into Safe Mode allows the user to uninstall problematic updates without losing data. A clean installation or full system reset would result in data loss. Replacing the hard drive is unnecessary unless a hardware fault is confirmed.",
      "examTip": "When dealing with boot issues after updates, always attempt Safe Mode recovery before considering data-destructive solutions."
    },
    {
      "id": 73,
      "question": "A technician needs to configure a Windows 10 system to prevent users from installing unauthorized applications while allowing standard updates. Which tool should be used?",
      "options": [
        "Local Group Policy Editor",
        "Task Scheduler",
        "Windows Defender Firewall",
        "System Configuration"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Local Group Policy Editor allows administrators to control user permissions, including restricting application installations. Task Scheduler automates tasks but doesn’t control user permissions. Windows Defender Firewall manages network access, not installation permissions. System Configuration adjusts startup settings but doesn’t restrict installations.",
      "examTip": "Use Local Group Policy Editor for granular user permission controls in Windows environments."
    },
    {
      "id": 74,
      "question": "A user’s web browser displays certificate errors when accessing internal company websites. The system date and time are correct. What is the MOST likely cause?",
      "options": [
        "Missing or outdated root certificates on the system.",
        "Corrupted browser cache and cookies.",
        "Incorrect DNS configuration.",
        "Network firewall blocking HTTPS traffic."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Missing or outdated root certificates prevent browsers from verifying website certificates. Corrupted cache may cause loading issues but not certificate errors. Incorrect DNS affects domain resolution, not certificate validation. A firewall blocking HTTPS would prevent access entirely, not just display certificate errors.",
      "examTip": "Always ensure root certificates are up to date when facing certificate-related browser errors."
    },
    {
      "id": 75,
      "question": "Which tool in macOS provides information about system processes, CPU usage, and memory utilization, similar to Task Manager in Windows?",
      "options": [
        "Activity Monitor",
        "Console",
        "Disk Utility",
        "Keychain Access"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Activity Monitor in macOS displays real-time data on system processes, CPU, memory, and network usage. Console provides system logs, Disk Utility manages storage, and Keychain Access handles passwords and certificates but doesn’t monitor system performance.",
      "examTip": "Use Activity Monitor in macOS for performance and process monitoring similar to Task Manager in Windows."
    },
    {
      "id": 76,
      "question": "A Linux user reports that they cannot execute a shell script due to permission issues. Which command will grant execute permissions to all users?",
      "options": [
        "chmod +x script.sh",
        "chown user:user script.sh",
        "rm script.sh",
        "cat script.sh"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The chmod +x command grants execute permissions to all users. chown changes file ownership, rm deletes the file, and cat displays file contents without modifying permissions.",
      "examTip": "Use chmod +x to grant execute permissions on scripts in Linux systems."
    },
    {
      "id": 77,
      "question": "A user suspects their Windows 10 PC is infected with malware after experiencing slow performance and frequent pop-ups. What is the FIRST step the technician should take to remove the malware?",
      "options": [
        "Disconnect the PC from the network.",
        "Perform a full operating system reinstall.",
        "Delete temporary files using Disk Cleanup.",
        "Update and run antivirus software."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Disconnecting the PC from the network prevents malware from spreading or communicating with external servers. Reinstalling the OS is a last resort. Disk Cleanup removes temporary files but doesn’t eliminate malware. Antivirus scans come after isolating the machine.",
      "examTip": "Always isolate suspected malware-infected systems from the network to contain potential threats."
    },
    {
      "id": 78,
      "question": "A technician needs to determine the exact version and build number of the Windows 10 operating system installed on a machine. Which command should be used?",
      "options": [
        "winver",
        "systeminfo",
        "hostname",
        "ipconfig"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The winver command opens a window displaying the exact Windows version and build number. systeminfo provides detailed system specs but is more verbose. hostname shows the computer name. ipconfig displays network configuration information.",
      "examTip": "Use winver for a quick check of the Windows version and build number."
    },
    {
      "id": 79,
      "question": "A technician is tasked with encrypting a removable USB drive to protect sensitive data. Which Windows feature should be used?",
      "options": [
        "BitLocker To Go",
        "Encrypting File System (EFS)",
        "NTFS permissions",
        "Group Policy Editor"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BitLocker To Go provides full-disk encryption for removable drives. EFS encrypts individual files but not entire drives. NTFS permissions control access but do not encrypt data. Group Policy Editor configures system policies but doesn’t encrypt storage.",
      "examTip": "Use BitLocker To Go for securing sensitive data on removable drives in Windows."
    },
    {
      "id": 80,
      "question": "Which backup type only copies files that have changed since the last full backup, minimizing storage requirements and backup time?",
      "options": [
        "Incremental backup",
        "Full backup",
        "Differential backup",
        "Synthetic full backup"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Incremental backups save only changes since the last full backup, optimizing time and storage. Full backups copy all data each time, requiring more resources. Differential backups copy changes since the last full backup, accumulating more data over time. Synthetic full backups reconstruct full backups without recopying all data but are more complex to set up.",
      "examTip": "Incremental backups provide efficient storage and backup times, ideal for daily backup strategies."
    },
    {
      "id": 81,
      "question": "A user reports that their Windows 10 PC frequently displays 'Low disk space' warnings. Which built-in utility will help free up space by removing temporary files and system junk?",
      "options": [
        "Disk Cleanup",
        "Disk Management",
        "Defragment and Optimize Drives",
        "Task Scheduler"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Disk Cleanup removes temporary files, system logs, and other unnecessary data. Disk Management handles disk partitioning, Defragment and Optimize Drives improves performance but doesn’t free up space, and Task Scheduler automates tasks but doesn’t manage storage.",
      "examTip": "Use Disk Cleanup regularly to free up disk space and maintain system performance."
    },
    {
      "id": 82,
      "question": "A user can access the internet but cannot reach specific internal company websites. Other users on the same network have no issues. What is the MOST likely cause?",
      "options": [
        "Corrupted local DNS cache.",
        "ISP routing issues.",
        "Company firewall misconfiguration.",
        "Physical network cable failure."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A corrupted DNS cache can cause issues accessing specific sites. Clearing the cache usually resolves the problem. ISP routing issues would affect all users. Firewall misconfigurations typically impact all users or specific network segments. A physical cable issue would prevent all network access, not just specific websites.",
      "examTip": "When only certain sites are inaccessible, clearing the DNS cache is a quick and effective first step."
    },
    {
      "id": 83,
      "question": "A user reports receiving continuous browser pop-ups and being redirected to unknown websites. What is the MOST likely type of malware involved?",
      "options": [
        "Adware",
        "Spyware",
        "Trojan horse",
        "Rootkit"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Adware causes excessive pop-ups and redirects to generate revenue. Spyware tracks user activity but doesn’t typically cause pop-ups. Trojans allow unauthorized access to systems. Rootkits hide malicious processes but don’t cause browser disruptions.",
      "examTip": "Persistent pop-ups and browser redirects are classic signs of adware infections."
    },
    {
      "id": 84,
      "question": "A technician needs to assign a static IP address to a Linux server. Which file should be edited in most modern Linux distributions using Netplan?",
      "options": [
        "/etc/netplan/*.yaml",
        "/etc/network/interfaces",
        "/etc/sysconfig/network-scripts/ifcfg-eth0",
        "/etc/hosts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Modern Linux distributions using Netplan store network configurations in YAML files under /etc/netplan/. The /etc/network/interfaces file is used in older distributions. /etc/sysconfig/network-scripts/ifcfg-eth0 is common in Red Hat-based distributions. /etc/hosts maps hostnames to IP addresses but doesn’t configure network interfaces.",
      "examTip": "For Ubuntu and other Netplan-based systems, configure static IPs in /etc/netplan/*.yaml files."
    },
    {
      "id": 85,
      "question": "A Windows 10 machine is experiencing slow performance. The technician suspects high disk usage by certain processes. Which built-in tool can provide real-time insights into disk activity?",
      "options": [
        "Resource Monitor",
        "Event Viewer",
        "System Configuration",
        "Disk Management"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Resource Monitor shows real-time performance metrics, including disk activity by process. Event Viewer logs system events but doesn’t provide real-time usage data. System Configuration handles startup settings. Disk Management deals with partitioning and drive configurations.",
      "examTip": "Use Resource Monitor for detailed insights into disk, CPU, and memory usage by individual processes."
    },
    {
      "id": 86,
      "question": "A technician is troubleshooting a Linux server that shows no available disk space. Which command will display disk usage statistics to identify storage consumption?",
      "options": [
        "df -h",
        "du -sh",
        "ls -lh",
        "top"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The df -h command shows disk usage statistics for all mounted filesystems in human-readable format. du -sh shows disk usage for a specific directory. ls -lh lists file details but not overall disk usage. top displays process resource usage but not storage details.",
      "examTip": "Use df -h in Linux to quickly assess disk space usage across all mounted filesystems."
    },
    {
      "id": 87,
      "question": "A user reports that their system clock resets every time the computer is powered off. What is the MOST likely cause?",
      "options": [
        "Failed CMOS battery on the motherboard.",
        "Corrupted BIOS firmware.",
        "Operating system corruption.",
        "Incorrect time zone configuration."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A failed CMOS battery causes the system clock and BIOS settings to reset after shutdown. Corrupted BIOS firmware would prevent booting or cause instability. OS corruption would manifest in system performance issues. Incorrect time zones affect displayed time but not persistent resets after power-off.",
      "examTip": "System clock resets after power-off typically indicate a depleted CMOS battery requiring replacement."
    },
    {
      "id": 88,
      "question": "A user accidentally deleted important files from a shared network drive. Which feature allows restoring previous versions without administrator intervention?",
      "options": [
        "Shadow Copies",
        "File History",
        "System Restore",
        "NTFS Permissions"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Shadow Copies enable users to restore previous versions of files from network shares. File History is for personal file backups on local drives. System Restore recovers system configurations but not user files. NTFS permissions manage access rights but don’t provide version history.",
      "examTip": "Shadow Copies simplify file recovery on network shares without needing admin support."
    },
    {
      "id": 89,
      "question": "A technician is setting up a firewall rule to allow only secure web traffic. Which port should be opened to achieve this?",
      "options": [
        "443",
        "80",
        "21",
        "25"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Port 443 is used for secure HTTPS web traffic. Port 80 handles HTTP traffic without encryption. Port 21 is used for FTP transfers. Port 25 is designated for SMTP email traffic.",
      "examTip": "Allow port 443 through firewalls for secure web traffic while blocking non-secure ports as needed."
    },
    {
      "id": 90,
      "question": "A user complains that their Windows 10 PC boots very slowly. The technician suspects startup programs are the cause. Which tool provides the MOST direct method to disable unnecessary startup applications?",
      "options": [
        "Task Manager",
        "System Configuration",
        "Performance Monitor",
        "Event Viewer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Task Manager allows direct management of startup applications in Windows 10. System Configuration previously handled startup settings but now redirects to Task Manager. Performance Monitor tracks performance metrics but doesn’t control startup apps. Event Viewer logs system events but doesn’t manage applications.",
      "examTip": "For Windows 10 startup issues, Task Manager offers the fastest way to manage startup programs."
    },
    {
      "id": 91,
      "question": "A Linux user needs to find all files in their home directory containing the word 'confidential'. Which command will achieve this?",
      "options": [
        "grep -r 'confidential' ~/",
        "find ~/ -name 'confidential'",
        "locate 'confidential'",
        "ls -R ~/ | grep 'confidential'"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The grep -r command searches recursively for the specified term within files in a directory. The find command locates files by name but doesn’t search within file contents. locate searches indexed file names, not contents. ls -R lists files recursively but doesn’t search content.",
      "examTip": "Use grep -r for powerful, recursive content searches across directories in Linux."
    },
    {
      "id": 92,
      "question": "A user reports that their Windows 10 system boots to a recovery screen after a recent feature update. The technician suspects corrupted system files. Which command should be run FIRST to attempt a repair without data loss?",
      "options": [
        "sfc /scannow",
        "chkdsk /f",
        "bootrec /fixmbr",
        "diskpart"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The sfc /scannow command scans and repairs corrupted system files, addressing issues caused by recent updates without affecting user data. chkdsk /f fixes file system errors but doesn’t target system files specifically. bootrec /fixmbr repairs the Master Boot Record, relevant for boot issues unrelated to system file corruption. diskpart manages disk partitions and isn’t used for file repair.",
      "examTip": "When system file corruption is suspected, run sfc /scannow before more intrusive repair methods."
    },
    {
      "id": 93,
      "question": "A technician needs to configure a SOHO wireless router to enhance security by ensuring only known devices can connect. Which configuration setting should be enabled?",
      "options": [
        "MAC address filtering",
        "Disabling SSID broadcast",
        "Changing the default SSID",
        "Enabling WPS"
      ],
      "correctAnswerIndex": 0,
      "explanation": "MAC address filtering allows only specified devices to connect, enhancing security by blocking unauthorized access. Disabling SSID broadcast hides the network but doesn’t prevent connections from determined attackers. Changing the default SSID reduces exposure to default settings but doesn’t restrict device access. Enabling WPS simplifies device connections but can introduce security vulnerabilities.",
      "examTip": "Use MAC filtering in SOHO environments to control which devices can join the network."
    },
    {
      "id": 94,
      "question": "A user reports that their laptop takes an unusually long time to load the desktop after login. Which Windows utility should be used to identify and disable non-essential startup applications?",
      "options": [
        "Task Manager",
        "Performance Monitor",
        "Disk Management",
        "Event Viewer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Task Manager provides an interface to view and disable startup applications that may slow down login times. Performance Monitor tracks overall system performance but doesn’t manage startup apps. Disk Management handles storage configurations and isn’t related to application loading. Event Viewer logs system events but doesn’t control startup processes.",
      "examTip": "Use Task Manager’s Startup tab to streamline boot times by disabling unnecessary applications."
    },
    {
      "id": 95,
      "question": "A technician is troubleshooting a Linux server that isn’t accessible remotely via SSH. Network connectivity is confirmed. Which command will verify if the SSH service is running?",
      "options": [
        "systemctl status ssh",
        "netstat -tuln",
        "ps aux | grep ssh",
        "ifconfig"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The systemctl status ssh command checks the current status of the SSH service, confirming whether it’s running. netstat -tuln displays listening network ports but doesn’t show service statuses. ps aux | grep ssh lists SSH processes but doesn’t indicate the service's operational state. ifconfig shows network interface details but is unrelated to SSH service status.",
      "examTip": "Check SSH service status with systemctl to ensure remote access functionality on Linux servers."
    },
    {
      "id": 96,
      "question": "A company requires that users authenticate using a fingerprint and a PIN when logging into their laptops. Which type of authentication method is being implemented?",
      "options": [
        "Multifactor authentication",
        "Single sign-on",
        "Biometric authentication only",
        "Two-step verification"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Multifactor authentication (MFA) requires two or more distinct authentication factors, such as something the user knows (PIN) and something the user is (fingerprint). Single sign-on allows access to multiple resources after one login. Biometric authentication only involves fingerprints or facial recognition, lacking a secondary factor. Two-step verification typically uses a single authentication factor verified twice, differing from MFA's distinct factors.",
      "examTip": "Implement MFA by combining authentication factors like biometrics and PINs for stronger access control."
    },
    {
      "id": 97,
      "question": "A user’s Windows 10 computer cannot access internal company resources using hostnames but can connect using IP addresses. Which command should the technician use to test DNS resolution?",
      "options": [
        "nslookup",
        "ping",
        "tracert",
        "netstat"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The nslookup command tests DNS resolution by querying DNS servers for hostnames. ping checks network connectivity but doesn’t provide DNS resolution details. tracert shows the path to a network destination but doesn’t test DNS. netstat displays active network connections without DNS information.",
      "examTip": "Use nslookup to diagnose DNS-related connectivity issues when hostnames fail to resolve."
    },
    {
      "id": 98,
      "question": "A user reports that files encrypted with EFS on their Windows 10 PC are inaccessible after reinstalling the operating system. What is the MOST likely cause?",
      "options": [
        "The encryption certificate was not backed up before reinstallation.",
        "The files were stored on a corrupted partition.",
        "The NTFS permissions were removed during reinstallation.",
        "The drive was formatted using FAT32."
      ],
      "correctAnswerIndex": 0,
      "explanation": "EFS relies on encryption certificates tied to user profiles. If these certificates aren’t backed up before reinstalling the OS, the files become inaccessible. Corrupted partitions would prevent file access entirely, not just encrypted files. NTFS permissions can be reset but don’t affect encryption. FAT32 doesn’t support EFS, but if the drive supported EFS previously, it implies NTFS formatting.",
      "examTip": "Always back up encryption certificates when using EFS to avoid permanent data loss after system reinstalls."
    },
    {
      "id": 99,
      "question": "A technician needs to deploy virtual machines on a single physical server with minimal overhead. Which virtualization solution should be implemented?",
      "options": [
        "Type 1 hypervisor",
        "Type 2 hypervisor",
        "Containerization platform",
        "Cloud-based virtual machine service"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A Type 1 hypervisor runs directly on hardware without a host operating system, offering minimal overhead and maximum performance. Type 2 hypervisors run on top of an OS, introducing additional overhead. Containerization uses shared OS kernels, suitable for applications but not full OS virtualization. Cloud-based services rely on external infrastructure rather than on-premises deployment.",
      "examTip": "Use Type 1 hypervisors for high-performance, bare-metal virtualization with minimal resource overhead."
    },
    {
      "id": 100,
      "question": "A user reports that their Windows 10 PC displays the message 'No operating system found' after connecting an external hard drive. Other devices boot correctly. What should the technician check FIRST?",
      "options": [
        "Boot order in the BIOS/UEFI settings.",
        "File system integrity of the external hard drive.",
        "Partition table of the internal drive.",
        "Power connection to the internal hard drive."
      ],
      "correctAnswerIndex": 0,
      "explanation": "An incorrect boot order in BIOS/UEFI can cause the system to attempt booting from an external drive lacking a valid OS. File system integrity on the external drive is irrelevant unless it’s intended as a boot device. The internal drive’s partition table would prevent booting altogether, regardless of external drives. A power issue would result in the internal drive being undetected, not necessarily triggering a missing OS error.",
      "examTip": "Verify BIOS/UEFI boot order when external drives cause 'No OS found' errors after connection."
    }
  ]
});
