
Exam Tip: Missing for multiple questions (e.g., #21, #67, #77, #78, #79, #100, and others). Every question is supposed to include an examTip, but many do not.


db.tests.insertOne({
  "category": "aplus2",
  "testId": 1,
  "testName": "A+ Core 2 Practice Test #1 (Normal)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "Which of the following Windows command-line tools would you use to display the current TCP/IP network configuration?",
      "options": [
        "netstat",
        "ipconfig",
        "ping",
        "tracert"
      ],
      "correctAnswerIndex": 1,
      "explanation": "ipconfig displays all current TCP/IP network configuration values, including IP address, subnet mask, and default gateway. netstat shows active connections, ping tests connectivity, and tracert traces the route to a destination.",
      "examTip": "Remember that 'ipconfig' is your go-to command for viewing network configuration details on a Windows machine."
    },
    {
      "id": 2,
      "question": "A user reports that their computer is running slowly.  What is the FIRST step you should take to troubleshoot the issue?",
      "options": [
        "Reinstall the operating system.",
        "Run a full system scan with antivirus software.",
        "Check Task Manager for high CPU or memory usage.",
        "Replace the hard drive with an SSD."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Checking Task Manager is the quickest way to identify resource bottlenecks.  Reinstalling the OS and replacing hardware are more drastic steps.  While an antivirus scan is important, it's not the *first* step for general slowness.",
      "examTip": "Always start with the least invasive troubleshooting steps before moving to more complex or time-consuming solutions."
    },
    {
      "id": 3,
      "question": "You need to configure a Windows 10 computer to join a domain. Which Control Panel utility is MOST appropriate for this task?",
      "options": [
        "Network and Sharing Center",
        "System",
        "User Accounts",
        "Programs and Features"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The System utility (specifically, the 'Change settings' option under 'Computer name, domain, and workgroup settings') allows you to join a domain. The other options manage different aspects of the system.",
      "examTip": "Remember the 'System' Control Panel utility for domain and workgroup membership changes."
    },
    {
      "id": 4,
      "question": "Which type of malware disguises itself as legitimate software but performs malicious actions in the background?",
      "options": [
        "Virus",
        "Trojan",
        "Worm",
        "Spyware"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A Trojan horse, or Trojan, disguises itself as legitimate software. Viruses attach to files, worms self-replicate, and spyware collects information.",
      "examTip": "Think of the Trojan Horse story from Greek mythology when you encounter questions about this type of malware."
    },
    {
      "id": 5,
      "question": "What is the purpose of the `sfc /scannow` command in Windows?",
      "options": [
        "To scan for and restore corrupted system files.",
        "To check the hard drive for errors.",
        "To update the system's BIOS.",
        "To display network configuration information."
      ],
      "correctAnswerIndex": 0,
      "explanation": "The System File Checker (`sfc /scannow`) scans for and attempts to repair corrupted Windows system files. The other options describe different utilities.",
      "examTip": "Remember 'sfc' stands for System File Checker, a crucial tool for maintaining system integrity."
    },
    {
      "id": 6,
      "question": "Which of the following is a characteristic of WPA2 encryption for wireless networks?",
      "options": [
        "Uses the RC4 encryption algorithm.",
        "Offers stronger security than WEP.",
        "Is vulnerable to brute-force attacks.",
        "Uses a static, pre-shared key."
      ],
      "correctAnswerIndex": 1,
      "explanation": "WPA2 provides significantly stronger security than the older WEP standard. While newer standards like WPA3 exist, WPA2 using AES is still considered secure.  It's less vulnerable to brute-force attacks than WEP and uses dynamic keys (though PSK mode uses a pre-shared key, it's not static in the same way as WEP).",
      "examTip": "WPA2 is a significant improvement over WEP, offering better encryption and authentication."
    },
    {
      "id": 7,
      "question": "A user cannot access network resources, and upon investigation, you find their computer has an IP address of 169.254.x.x. What is the MOST likely cause?",
      "options": [
        "The computer has a static IP address configured incorrectly.",
        "The computer is unable to obtain an IP address from a DHCP server.",
        "The computer's network adapter is disabled.",
        "The computer is infected with malware."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A 169.254.x.x address indicates an APIPA (Automatic Private IP Addressing) address, assigned when a DHCP server cannot be reached. While other issues *could* exist, this is the most likely cause.",
      "examTip": "Remember the 169.254.x.x range as the indicator of a failed DHCP request."
    },
    {
      "id": 8,
      "question": "What is the primary purpose of User Account Control (UAC) in Windows?",
      "options": [
        "To manage user passwords.",
        "To prevent unauthorized changes to the operating system.",
        "To control access to network resources.",
        "To encrypt user data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "UAC prompts for confirmation or administrator credentials before allowing actions that could potentially affect the OS's security or stability.  The other options describe different security features.",
      "examTip": "Think of UAC as a 'gatekeeper' that helps prevent unauthorized system modifications."
    },
    {
      "id": 9,
      "question": "Which Windows utility allows you to view and manage scheduled tasks?",
      "options": [
        "Task Manager",
        "System Configuration",
        "Task Scheduler",
        "Event Viewer"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Task Scheduler is specifically designed to create, manage, and run scheduled tasks. Task Manager focuses on running processes, System Configuration on startup settings, and Event Viewer on logs.",
      "examTip": "The name 'Task Scheduler' directly reflects its function – managing scheduled tasks."
    },
    {
      "id": 10,
      "question": "Which of the following is the BEST practice for disposing of old hard drives containing sensitive data?",
      "options": [
        "Deleting all files and folders.",
        "Formatting the hard drive.",
        "Physically destroying the hard drive.",
        "Using a file shredder program."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Physical destruction (e.g., shredding, drilling) ensures the data is irretrievable. Deleting and formatting can often be reversed. File shredders are better than simple deletion, but physical destruction is the most secure.",
      "examTip": "For truly sensitive data, physical destruction is the only guaranteed method of preventing recovery."
    },
    {
      "id": 11,
      "question": "What is the purpose of the `gpupdate /force` command?",
      "options": [
        "To force a refresh of Group Policy settings.",
        "To update the system's BIOS.",
        "To check for Windows updates.",
        "To display the current Group Policy settings."
      ],
      "correctAnswerIndex": 0,
      "explanation": "`gpupdate /force` reapplies all Group Policy settings, even if they haven't changed. `gpresult` displays settings, not `gpupdate`.",
      "examTip": "Use `gpupdate /force` to ensure immediate application of Group Policy changes."
    },
    {
      "id": 12,
      "question": "A user reports their web browser is frequently displaying unwanted pop-up advertisements. What is the MOST likely cause?",
      "options": [
        "A hardware malfunction.",
        "Adware or malware infection.",
        "Outdated browser version.",
        "Incorrect DNS settings."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Excessive pop-ups are a classic sign of adware or malware.  While an outdated browser *could* have vulnerabilities, it's less likely to *directly* cause pop-ups. Hardware and DNS issues are unlikely causes.",
      "examTip": "Pop-up ads are a strong indicator of a potential malware problem."
    },
    {
      "id": 13,
      "question": "Which type of backup copies only the files that have changed since the last full or incremental backup?",
      "options": [
        "Full backup",
        "Incremental backup",
        "Differential backup",
        "Synthetic full backup"
      ],
      "correctAnswerIndex": 1,
      "explanation": "An incremental backup copies only data changed since the *last* backup (full or incremental).  Differential backs up changes since the last *full* backup.  A synthetic full backup combines a full backup with incremental backups.",
      "examTip": "Remember 'Incremental' means building upon the previous backup, while 'Differential' always refers back to the last full backup."
    },
    {
      "id": 14,
      "question": "What is the purpose of an ESD strap?",
      "options": [
        "To secure cables and prevent tripping hazards.",
        "To prevent electrostatic discharge from damaging computer components.",
        "To lift heavy computer equipment safely.",
        "To organize and label cables."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An ESD (Electrostatic Discharge) strap grounds the technician, preventing static electricity buildup from damaging sensitive electronic components.",
      "examTip": "Always use an ESD strap when working inside a computer to protect against static damage."
    },
    {
      "id": 15,
      "question": "Which of the following is a common symptom of a failing hard drive?",
      "options": [
        "The computer displays a blue screen of death (BSOD).",
        "The computer makes clicking or grinding noises.",
        "The computer's power supply fan is noisy.",
        "The monitor displays distorted colors."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Unusual noises like clicking or grinding are often indicative of a mechanical hard drive failure. BSODs can have many causes. Fan noise is related to the PSU, and distorted colors are usually a monitor or video card issue.",
      "examTip": "Listen carefully for unusual noises from the hard drive – they can be an early warning sign of failure."
    },
    {
      "id": 16,
      "question": "Which Control Panel utility in Windows allows you to uninstall programs?",
      "options": [
        "System",
        "Programs and Features",
        "Device Manager",
        "User Accounts"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Programs and Features is specifically designed for uninstalling applications. The other options manage different system components.",
      "examTip": "Use 'Programs and Features' to cleanly remove installed software."
    },
    {
      "id": 17,
      "question": "A user is unable to connect to a wireless network.  The network SSID is not visible in the list of available networks. What should you check FIRST?",
      "options": [
        "The user's wireless adapter drivers.",
        "Whether SSID broadcast is disabled on the router.",
        "The wireless network encryption settings.",
        "The user's IP address configuration."
      ],
      "correctAnswerIndex": 1,
      "explanation": "If the SSID is not broadcasting, it won't appear in the list. Checking drivers or encryption is premature if the network isn't even visible.",
      "examTip": "Always confirm basic network visibility (SSID broadcast) before troubleshooting more complex wireless issues."
    },
    {
      "id": 18,
      "question": "Which of the following is an example of social engineering?",
      "options": [
        "Exploiting a software vulnerability to gain access to a system.",
        "Tricking a user by posing as a help desk technician.",
        "Using a brute-force attack to crack a password.",
        "Installing a keylogger on a computer."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Social engineering manipulates people into divulging information or performing actions.  The other options are technical attacks, not social manipulation.",
      "examTip": "Social engineering relies on human interaction and deception, not technical exploits."
    },
    {
      "id": 19,
      "question": "What is the purpose of Windows Defender Firewall?",
      "options": [
        "To protect the computer from viruses and malware entering or leaving the computer.",
        "To block unauthorized network traffic from entering or leaving the computer.",
        "To encrypt data on the hard drive.",
        "To manage user accounts and permissions."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Windows Defender Firewall acts as a barrier, controlling network traffic based on configured rules. While it works alongside antivirus, its primary role is network traffic control, not virus scanning.",
      "examTip": "Think of the firewall as a 'wall' that protects your computer from unwanted network connections."
    },
    {
      "id": 20,
      "question": "Which command-line tool is used to manage disk partitions in Windows?",
      "options": [
        "chkdsk",
        "diskpart",
        "format",
        "defrag"
      ],
      "correctAnswerIndex": 1,
      "explanation": "diskpart is the command-line utility for creating, deleting, and managing disk partitions. chkdsk checks for disk errors, format prepares a partition for use, and defrag optimizes file storage.",
      "examTip": "Remember 'diskpart' for all your command-line disk partitioning needs."
    },
    {
      "id": 21,
      "question": "You are troubleshooting a computer that boots to a black screen with a blinking cursor. The BIOS/UEFI setup is accessible. What is the MOST likely problem?",
      "options": [
        "Faulty RAM",
        "Corrupted boot sector",
        "Failed video card",
        "Overheating CPU"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A blinking cursor after POST usually indicates the system can't find a bootable operating system. Faulty RAM or a failed video card would typically manifest differently. Overheating usually causes shutdowns, not a failure to boot.",
      "examTip": "A blinking cursor at boot often points to a problem with the boot process or operating system files."
    },
    {
      "id": 22,
      "question": "What is the function of the `net user` command in Windows?",
      "options": [
        "Displays network connection statistics.",
        "Manages user accounts.",
        "Connects to a network share.",
        "Tests network connectivity."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `net user` command is used to create, modify, and delete user accounts from the command line. The other options describe other 'net' commands.",
      "examTip": "`net user` is your command-line tool for user account management."
    },
    {
      "id": 23,
      "question": "Which of the following is a benefit of using a strong password?",
      "options": [
        "It is easier to remember.",
        "It makes your computer run faster.",
        "It reduces the risk of unauthorized access to your accounts.",
        "It improves your internet connection speed."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Strong passwords (long, complex, and unique) are harder to guess or crack, thus protecting accounts. They don't affect computer or internet speed.",
      "examTip": "Prioritize strong, unique passwords for all your accounts."
    },
    {
      "id": 24,
      "question": "Which file system is MOST commonly used on modern Windows systems?",
      "options": [
        "FAT32",
        "NTFS",
        "exFAT",
        "ext4"
      ],
      "correctAnswerIndex": 1,
      "explanation": "NTFS (New Technology File System) is the standard file system for Windows, offering features like security permissions, journaling, and large file/partition support. FAT32 and exFAT are used for removable media, and ext4 is primarily used on Linux.",
      "examTip": "NTFS is the default and recommended file system for Windows installations."
    },
    {
      "id": 25,
      "question": "What does the acronym 'BIOS' stand for?",
      "options": [
        "Basic Input/Output System",
        "Binary Input/Output System",
        "Boot Input/Output Sequence",
        "Basic Integrated Operating System"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BIOS stands for Basic Input/Output System.  It's the firmware that initializes hardware during the boot process.",
      "examTip": "Remember BIOS as the fundamental system that starts your computer."
    },
    {
      "id": 26,
      "question": "Which of the following actions is MOST likely to expose a computer to malware?",
      "options": [
        "Installing software from a trusted vendor's website.",
        "Downloading files from unknown or suspicious websites.",
        "Updating the operating system regularly.",
        "Using a strong password for the administrator account."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Downloading files from untrusted sources is a major risk factor for malware infection.  The other options are generally good security practices.",
      "examTip": "Be extremely cautious about downloading files from sources you don't fully trust."
    },
    {
      "id": 27,
      "question": "A user reports they are receiving an error message stating 'Operating System Not Found'.  What is a likely cause?",
      "options": [
        "The computer's display adapter is malfunctioning.",
        "The boot order in the BIOS/UEFI is incorrect, or the boot drive is failing.",
        "The computer's RAM is faulty.",
        "The power supply is not providing enough power."
      ],
      "correctAnswerIndex": 1,
      "explanation": "This error indicates the system cannot locate a bootable operating system, often due to incorrect boot order or a failing boot drive. The other options are less likely to cause this specific error.",
      "examTip": "Check the BIOS/UEFI boot order and the health of the boot drive when you see 'Operating System Not Found'."
    },
    {
      "id": 28,
      "question": "Which of the following Control Panel utilities allows you to manage power settings in Windows?",
      "options": [
        "System",
        "Power Options",
        "Device Manager",
        "Network and Sharing Center"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Power Options is specifically designed to configure power plans, sleep settings, and other power-related settings.",
      "examTip": "Use 'Power Options' to manage energy consumption and battery life."
    },
    {
      "id": 29,
      "question": "What is the primary purpose of a firewall?",
      "options": [
        "To protect against viruses and malware.",
        "To filter network traffic and block unauthorized access.",
        "To speed up internet connections.",
        "To encrypt data stored on the hard drive."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Firewalls primarily control network traffic, acting as a barrier between a trusted network and untrusted networks (like the internet).  While they can work *with* antivirus, their main function is network security.",
      "examTip": "Think of a firewall as a security guard for your network, controlling who and what can come in and out."
    },
    {
      "id": 30,
      "question": "What is the purpose of System Restore in Windows?",
      "options": [
        "To back up user data.",
        "To revert the system to a previous state, undoing recent changes.",
        "To reinstall the operating system.",
        "To defragment the hard drive."
      ],
      "correctAnswerIndex": 1,
      "explanation": "System Restore allows you to roll back system files, registry settings, and installed programs to a previous point in time, helping to recover from system problems.  It doesn't back up user data (files, documents, etc.).",
      "examTip": "Think of System Restore as a 'time machine' for your system's configuration."
    },
    {
      "id": 31,
      "question": "Which command is used to display the running processes and their resource usage in Linux?",
      "options": [
        "ls",
        "ps",
        "top",
        "grep"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The 'top' command provides a dynamic, real-time view of running processes and their resource consumption (CPU, memory, etc.). 'ps' shows a snapshot, 'ls' lists files, and 'grep' searches for text.",
      "examTip": "Use 'top' in Linux to monitor system performance and identify resource-intensive processes."
    },
    {
      "id": 32,
      "question": "What is the purpose of the 'chmod' command in Linux?",
      "options": [
        "To change the ownership of a file or directory.",
        "To change the permissions of a file or directory.",
        "To create a new directory.",
        "To delete a file."
      ],
      "correctAnswerIndex": 1,
      "explanation": "'chmod' (change mode) modifies the read, write, and execute permissions for files and directories. 'chown' changes ownership.",
      "examTip": "Remember 'chmod' for changing file and directory permissions in Linux."
    },
    {
      "id": 33,
      "question": "Which type of attack involves attempting to guess a password by trying many different combinations?",
      "options": [
        "Phishing",
        "Brute-force attack",
        "Denial-of-service attack",
        "SQL injection"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A brute-force attack systematically tries every possible password combination until the correct one is found. The other options are different types of attacks.",
      "examTip": "Brute-force attacks rely on trying many password combinations, highlighting the importance of strong, complex passwords."
    },
    {
      "id": 34,
      "question": "What is the BEST way to protect against ransomware attacks?",
      "options": [
        "Install antivirus software.",
        "Regularly back up your data to an external location.",
        "Avoid clicking on suspicious links or attachments.",
        "All of the above."
      ],
      "correctAnswerIndex": 3,
      "explanation": "A combination of preventative measures (antivirus, avoiding suspicious links) and a robust backup strategy is the best defense against ransomware. Backups allow you to restore data even if you are infected.",
      "examTip": "Ransomware protection requires a multi-layered approach, including prevention and recovery (backups)."
    },
    {
      "id": 35,
      "question": "Which of the following is a characteristic of a strong password?",
      "options": [
        "It is a common word or phrase.",
        "It is short and easy to remember.",
        "It includes a combination of uppercase and lowercase letters, numbers, and symbols.",
        "It is the same password used for multiple accounts."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Strong passwords are complex and difficult to guess. Using common words, short passwords, or reusing passwords significantly weakens security.",
      "examTip": "A strong password is long, uses a mix of characters, and is unique to each account."
    },
    {
      "id": 36,
      "question": "What is the purpose of the `ping` command?",
      "options": [
        "To display network configuration information.",
        "To test network connectivity to a specific host.",
        "To manage user accounts.",
        "To shut down the computer."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`ping` sends ICMP echo request packets to a target host and measures the response time, verifying basic network connectivity. The other options describe different commands.",
      "examTip": "Use `ping` to quickly check if you can reach a specific device on the network."
    },
    {
      "id": 37,
      "question": "What information is typically found in an MSDS (Material Safety Data Sheet)?",
      "options": [
        "Instructions for installing software materials.",
        "Information about the safe handling and disposal of hazardous materials.",
        "Details about a computer's hardware configuration and materials.",
        "Troubleshooting steps for common computer problems and computer materials."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An MSDS provides crucial information about the properties, hazards, and safe handling procedures for chemical substances and other potentially hazardous materials.",
      "examTip": "Consult the MSDS before handling any unfamiliar or potentially hazardous materials."
    },
    {
      "id": 38,
      "question": "A user reports their computer is randomly restarting.  What is a likely cause, besides malware?",
      "options": [
        "Overheating CPU or other components.",
        "Incorrect DNS settings.",
        "A misconfigured firewall.",
        "Outdated web browser."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Overheating can cause system instability and unexpected restarts. The other options are less likely to cause random reboots.",
      "examTip": "Check for overheating (fans, ventilation) when troubleshooting random restarts."
    },
    {
      "id": 39,
      "question": "Which of the following is a valid IPv4 address?",
      "options": [
        "192.168.1.256",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "10.0.0.1",
        "256.256.256.256"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A valid IPv4 address consists of four octets (numbers) ranging from 0 to 255, separated by periods. Option B is an IPv6 address. Options A and D have invalid octet values.",
      "examTip": "Remember the valid range for each octet in an IPv4 address is 0-255."
    },
    {
      "id": 40,
      "question": "What is the primary function of a UPS (Uninterruptible Power Supply)?",
      "options": [
        "To provide surge protection for connected devices.",
        "To provide backup power to connected devices during a power outage.",
        "To regulate the voltage supplied to connected devices.",
        "All of the above."
      ],
      "correctAnswerIndex": 3,
      "explanation": "A UPS provides battery backup during power outages, surge protection, and often voltage regulation.  All these functions are key to protecting equipment.",
      "examTip": "A UPS is essential for protecting critical systems from power disruptions."
    },
    {
      "id": 41,
      "question": "When installing a new application, what should you verify FIRST?",
      "options": [
        "That the application is compatible with your operating system.",
        "That you have enough free disk space.",
        "That you have sufficient RAM.",
        "All of the above."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Before installing any software, always check the system requirements (OS compatibility, disk space, RAM, CPU, etc.) to ensure a successful installation and proper operation.",
      "examTip": "Always review the system requirements before installing new software."
    },
    {
      "id": 42,
      "question": "What is the purpose of Windows Event Viewer?",
      "options": [
        "To manage scheduled tasks.",
        "To view logs of system events, errors, and warnings.",
        "To configure network settings.",
        "To view logs of network diagnostics."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Event Viewer is a crucial tool for troubleshooting, providing a centralized location to view logs related to system events, application errors, security audits, and more.",
      "examTip": "Use Event Viewer to diagnose problems by examining system and application logs."
    },
    {
      "id": 43,
      "question": "Which command displays the default gateway in Windows?",
      "options": [
        "ipconfig",
        "ipconfig /all",
        "netstat -r",
        "tracert"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The ipconfig /all command will provide comprehensive network adapter information. The default gateway will be listed.",
      "examTip": "Use ipconfig /all for full adapter information."
    },
    {
      "id": 44,
      "question": "You are troubleshooting a printer that is not printing. Other users on the network can print to it. What is the MOST likely problem?",
      "options": [
        "The printer is out of paper.",
        "The printer is offline.",
        "The printer driver is not installed or is corrupted on the user's computer.",
        "The network cable is unplugged from the printer."
      ],
      "correctAnswerIndex": 2,
      "explanation": "If other users can print, the problem is likely local to the user's computer, suggesting a driver issue.  If the printer were out of paper, offline, or unplugged, *no one* could print.",
      "examTip": "If only one user has a printing problem, focus troubleshooting on their computer, not the printer itself."
    },
    {
      "id": 45,
      "question": "What is the purpose of defragmenting a hard drive (HDD)?",
      "options": [
        "To free up disk space.",
        "To improve the performance of the hard drive.",
        "To scan the hard drive for errors.",
        "To encrypt the data on the hard drive."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Defragmentation reorganizes fragmented files on a traditional HDD, placing related file pieces together, which can improve read/write speeds. It doesn't free up space, scan for errors, or encrypt data.",
      "examTip": "Defragmentation is beneficial for HDDs, but not necessary for SSDs."
    },
    {
      "id": 46,
      "question": "Which of the following is a security best practice for configuring a wireless router?",
      "options": [
        "Using the default administrator password.",
        "Disabling SSID broadcast.",
        "Using WEP encryption.",
        "Leaving the router in an easily accessible location."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Disabling SSID broadcast makes the network less visible to casual attackers (though it's not a strong security measure on its own).  The other options are security risks.",
      "examTip": "Change default router passwords, use strong encryption (WPA2 or WPA3), and consider disabling SSID broadcast for added security."
    },
    {
      "id": 47,
      "question": "Which of the following Linux commands is used to list the contents of a directory?",
      "options": [
        "pwd",
        "ls",
        "cd",
        "mkdir"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The 'ls' command lists files and directories in the current working directory (or a specified directory). 'pwd' shows the current directory, 'cd' changes directories, and 'mkdir' creates a directory.",
      "examTip": "Remember 'ls' for listing directory contents in Linux, similar to 'dir' in Windows."
    },
    {
      "id": 48,
      "question": "A user reports their computer is displaying a 'Low Disk Space' warning. What should you do FIRST?",
      "options": [
        "Run Disk Defragmenter.",
        "Run Disk Cleanup.",
        "Replace the hard drive.",
        "Reinstall the operating system."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Disk Cleanup is the quickest and easiest way to free up space by removing temporary files, emptying the Recycle Bin, and deleting other unnecessary files. Defragmentation doesn't free up space. Replacing the hard drive or reinstalling the OS are drastic measures.",
      "examTip": "Use Disk Cleanup as your first step to address low disk space warnings."
    },
    {
      "id": 49,
      "question": "What is the purpose of the 'sudo' command in Linux?",
      "options": [
        "To shut down the system.",
        "To switch to another user account.",
        "To execute a command with elevated privileges (as the superuser).",
        "To display the current user's home directory."
      ],
      "correctAnswerIndex": 2,
      "explanation": "'sudo' (superuser do) allows authorized users to run commands with root (administrator) privileges, providing a secure way to perform administrative tasks.",
      "examTip": "Use 'sudo' carefully, as it grants powerful access to the system."
    },
    {
      "id": 50,
      "question": "Which of the following best describes the purpose of a DMZ (Demilitarized Zone) in network security?",
      "options": [
        "A secure area for storing sensitive data.",
        "A network segment that is isolated from both the internal network and the internet.",
        "A network segment that provides public access to servers while protecting the internal network.",
        "A type of firewall that isolates the internal network."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A DMZ is a separate network segment that hosts publicly accessible servers (like web, email, or FTP servers). It acts as a buffer zone, preventing direct access to the internal network from the public internet.",
      "examTip": "Think of a DMZ as a 'buffer zone' between your internal network and the public internet, protecting your internal resources."
    },
    {
      "id": 51,
      "question": "Which Windows utility provides information about the computer's hardware and software configuration?",
      "options": [
        "Device Manager",
        "System Information (msinfo32.exe)",
        "Resource Monitor",
        "Task Manager"
      ],
      "correctAnswerIndex": 1,
      "explanation": "System Information (msinfo32.exe) provides a comprehensive overview of the system's hardware resources, components, and software environment. The other options provide more specific or real-time information.",
      "examTip": "Use System Information (msinfo32.exe) for a detailed report on your computer's configuration."
    },
    {
      "id": 52,
      "question": "Which of the following is a common symptom of a failing power supply?",
      "options": [
        "The computer displays distorted colors on the monitor.",
        "The computer randomly shuts down or restarts.",
        "The hard drive makes clicking noises.",
        "The network connection is intermittent."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Random shutdowns or restarts can be a sign of a failing power supply that is unable to provide consistent power. The other options point to different hardware issues.",
      "examTip": "Suspect the power supply if the computer experiences unexpected shutdowns or power issues."
    },
    {
      "id": 53,
      "question": "What is the difference between a workgroup and a domain in Windows networking?",
      "options": [
        "A workgroup is a peer-to-peer network, while a domain is a client-server network with centralized management.",
        "A workgroup requires a dedicated server, while a domain does not.",
        "A workgroup is more secure than a domain.",
        "There is no difference; the terms are interchangeable."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Workgroups are decentralized (peer-to-peer), with each computer managing its own users and resources. Domains have centralized management through a domain controller, providing features like single sign-on and Group Policy.",
      "examTip": "Remember that domains offer centralized control and management, while workgroups are decentralized."
    },
    {
      "id": 54,
      "question": "Which of the following is an example of multi-factor authentication (MFA)?",
      "options": [
        "Facial recognition with fingerprint identication.",
        "Entering a password and a PIN code.",
        "Entering a password and answering a security question.",
        "Entering a username, password, and a code generated by a mobile app."
      ],
      "correctAnswerIndex": 3,
      "explanation": "MFA requires two or more *different* types of authentication factors: something you know (password), something you have (mobile app), or something you are (biometrics). The other options only use 'something you know'.",
      "examTip": "MFA combines different authentication factors (know, have, are) for stronger security."
    },
    {
      "id": 55,
      "question": "Which type of network attack involves flooding a target system with traffic, making it unavailable to legitimate users?",
      "options": [
        "Phishing",
        "Denial-of-service (DoS) attack",
        "Man-in-the-middle attack",
        "SQL injection"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DoS attack overwhelms a system with traffic, preventing legitimate users from accessing it. The other options describe different types of attacks.",
      "examTip": "DoS attacks aim to disrupt service by overwhelming the target."
    },
    {
      "id": 56,
      "question": "You are setting up a new computer. What is the BEST practice regarding the built-in Administrator account?",
      "options": [
        "Leave the default password unchanged.",
        "Disable the account and create a new administrator account with a strong password.",
        "Rename the account but keep the default password.",
        "Use the Administrator account for everyday tasks."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The built-in Administrator account is a well-known target. Disabling it and creating a new, uniquely named administrator account with a strong password significantly improves security.",
      "examTip": "Always disable or rename the default Administrator account and use a strong, unique password for any administrator-level accounts."
    },
    {
      "id": 57,
      "question": "Which of the following describes the 'principle of least privilege'?",
      "options": [
        "Users should be given the maximum level of access to all system resources.",
        "Users should only be given the minimum necessary access rights to perform their job duties.",
        "Administrative privileges should be granted to all users.",
        "Users should be allowed to install any software they want."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The principle of least privilege limits user access to only what is essential, reducing the potential damage from accidents or malicious actions.",
      "examTip": "Apply the principle of least privilege to minimize security risks."
    },
    {
      "id": 58,
      "question": "What is the purpose of the 'chkdsk' command in Windows?",
      "options": [
        "To check the hard drive for file system errors and bad sectors.",
        "To display network configuration information.",
        "To manage disk partitions.",
        "To defragment the hard drive."
      ],
      "correctAnswerIndex": 0,
      "explanation": "'chkdsk' (Check Disk) scans the hard drive for logical and physical errors, attempting to repair them.  The other options describe different utilities.",
      "examTip": "Run 'chkdsk' periodically to check for and repair hard drive errors."
    },
    {
      "id": 59,
      "question": "Which of the following is an example of PII (Personally Identifiable Information)?",
      "options": [
        "A user's favorite color.",
        "A user's social security number.",
        "The type of computer a user owns.",
        "A user's preferred web browser."
      ],
      "correctAnswerIndex": 1,
      "explanation": "PII is any information that can be used to identify an individual, such as a social security number, name, address, or date of birth.  The other options are not identifying.",
      "examTip": "Protect PII carefully to prevent identity theft and privacy breaches."
    },
    {
      "id": 60,
      "question": "After a malware infection has been removed, what is the NEXT step in the malware removal process?",
      "options": [
        "Reinstall the operating system.",
        "Schedule scans and run updates.",
        "Disable System Restore.",
        "Educate the end-user"
      ],
      "correctAnswerIndex": 1,
      "explanation": "After removing the malware and updating definitions, schedule regular scans and ensure updates are applied to prevent reinfection. Disabling System Restore was a *prior* step. Educating the user is the *final* step. Reinstalling is drastic and usually unnecessary.",
      "examTip": "The malware removal process is a sequence; ensure all steps are followed, including post-removal actions like scheduled scans."
    },
    {
      "id": 61,
      "question": "What type of attack involves an attacker intercepting communication between two parties without their knowledge?",
      "options": [
        "Phishing",
        "On-path attack (formerly Man-in-the-middle attack)",
        "Denial-of-service attack",
        "Brute-force attack"
      ],
      "correctAnswerIndex": 1,
      "explanation": "An On-path attack (formerly Man-in-the-middle) allows the attacker to eavesdrop on or modify communication between two parties.  The other options are different types of attacks.",
      "examTip": "On-path attacks are a serious threat to communication security, emphasizing the need for secure protocols (like HTTPS)."
    },
    {
      "id": 62,
      "question": "What is a common first step when troubleshooting a 'No Boot Device Found' error?",
      "options": [
        "Replace the CMOS battery.",
        "Check the boot order in the BIOS/UEFI settings.",
        "Reseat the RAM modules.",
        "Run a memory diagnostic test."
      ],
      "correctAnswerIndex": 1,
      "explanation": "If the system cannot locate a bootable device, the BIOS/UEFI boot order might be incorrect, pointing to the wrong drive or a non-bootable device. The other steps are less likely to be the first action.",
      "examTip": "Always check the BIOS/UEFI boot order when troubleshooting boot problems."
    },
    {
      "id": 63,
      "question": "What is the purpose of an Acceptable Use Policy (AUP)?",
      "options": [
        "To define the rules and guidelines for using a company's computer systems and network resources.",
        "To describe the technical specifications of a computer system.",
        "To provide instructions for installing software.",
        "To document a user's personal preferences."
      ],
      "correctAnswerIndex": 0,
      "explanation": "An AUP outlines acceptable and unacceptable behavior when using a company's IT resources, protecting the organization and its users.",
      "examTip": "Familiarize yourself with your organization's AUP to ensure compliance."
    },
    {
      "id": 64,
      "question": "What is the purpose of using secure websites (HTTPS)?",
      "options": [
        "To make websites load faster.",
        "To encrypt communication between the user's browser and the website's server.",
        "To block pop-up advertisements.",
        "To improve the visual appearance of websites."
      ],
      "correctAnswerIndex": 1,
      "explanation": "HTTPS uses encryption (SSL/TLS) to protect data transmitted between the browser and the server, preventing eavesdropping and tampering. It doesn't affect loading speed or block ads.",
      "examTip": "Always look for the 'https://' and padlock icon in the address bar when entering sensitive information on a website."
    },
    {
      "id": 65,
      "question": "A user reports they accidentally deleted an important file. What is the FIRST thing you should check?",
      "options": [
        "The Recycle Bin (Windows) or Trash (macOS/Linux).",
        "The user's backup files.",
        "System Restore points.",
        "Run a file recovery program."
      ],
      "correctAnswerIndex": 0,
      "explanation": "The Recycle Bin/Trash is the first place to look for recently deleted files. Backups, System Restore, and recovery programs are for more complex situations.",
      "examTip": "Always check the Recycle Bin/Trash before attempting more advanced file recovery methods."
    },
    {
      "id": 66,
      "question": "Which of the following is a good practice for managing cables in a computer or server room?",
      "options": [
        "Leaving cables loose and tangled.",
        "Using cable ties or Velcro straps to bundle and organize cables.",
        "Running cables across walkways.",
        "Ignoring cable management altogether."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Proper cable management improves airflow, reduces the risk of accidental disconnections, and makes troubleshooting easier. The other options are poor practices.",
      "examTip": "Good cable management is essential for a well-organized and efficient IT environment."
    },
    {
      "id": 67,
      "question": "Which command-line tool is used to test the reachability of a host on an IP network and measure the round-trip time for messages?",
      "options": [
        "ipconfig",
        "ping",
        "tracert",
        "netstat"
      ],
      "correctAnswerIndex": 1,
      "explanation": "'ping' sends ICMP Echo Request packets to a target host, measuring round-trip time. ipconfig displays config, tracert shows the route, and netstat lists connections.",
      "examTip": "Use 'ping' to check basic network connectivity and latency."
    },
    {
      "id": 68,
      "question": "What is the purpose of using strong, unique passwords for each online account?",
      "options": [
        "To make it easier to remember all your passwords.",
        "To reduce the risk of a single compromised password affecting multiple accounts.",
        "To improve your internet connection speed.",
        "To make your computer run faster."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Using unique passwords prevents a 'domino effect' where one compromised account leads to others being compromised. It doesn't affect speed.",
      "examTip": "Never reuse passwords across multiple accounts."
    },
    {
      "id": 69,
      "question": "Which Control Panel utility (or Settings app section in Windows 10/11) allows you to configure network adapters and settings?",
      "options": [
        "System",
        "Network and Sharing Center (or Network & Internet)",
        "Device Manager",
        "Power Options"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Network and Sharing Center (or the Network & Internet section in Settings) is the central location for managing network connections, adapters, and sharing settings.",
      "examTip": "Use Network and Sharing Center (or Network & Internet settings) for network configuration."
    },
    {
      "id": 70,
      "question": "What does the acronym 'RDP' stand for?",
      "options": [
        "Remote Desktop Protocol",
        "Random Data Protocol",
        "Reliable Data Protocol",
        "Remote Data Procedure"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RDP (Remote Desktop Protocol) allows you to connect to and control a remote computer over a network.",
      "examTip": "RDP is a common tool for remote access and administration of Windows computers."
    },
    {
      "id": 71,
      "question": "What is the BEST practice for securing a wireless network?",
      "options": [
        "Using WEP encryption.",
        "Using WPA2 or WPA3 encryption with a strong password.",
        "Leaving the network open (no encryption).",
        "Disabling the wireless router's firewall."
      ],
      "correctAnswerIndex": 1,
      "explanation": "WPA2 or WPA3 with a strong, complex password provides the best security for modern wireless networks. WEP is outdated and easily cracked. Open networks and disabling the firewall are major security risks.",
      "examTip": "Always use WPA2 or WPA3 with a strong password to secure your wireless network."
    },
    {
      "id": 72,
      "question": "What should you do if you suspect a computer is infected with malware?",
      "options": [
        "Continue using the computer as normal.",
        "Disconnect the computer from the network and run a full system scan with updated antivirus software.",
        "Ignore the problem; it will likely go away on its own.",
        "Try to manually delete any suspicious files you find."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Isolating the infected computer (disconnecting from the network) prevents the malware from spreading. Running a full scan with updated antivirus is crucial for detection and removal.  Manual deletion is risky and may not be effective.",
      "examTip": "Isolate and scan any computer suspected of malware infection."
    },
    {
      "id": 73,
      "question": "Which type of malware replicates itself and spreads to other computers, often without user interaction?",
      "options": [
        "Trojan",
        "Worm",
        "Spyware",
        "Adware"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Worms are self-replicating malware that spread across networks. Trojans disguise themselves, spyware collects data, and adware displays ads.",
      "examTip": "Worms spread rapidly and automatically, making network security crucial."
    },
    {
      "id": 74,
      "question": "What is the function of the Task Manager in Windows?",
      "options": [
        "To manage scheduled tasks.",
        "To view and manage running processes, services, and performance metrics.",
        "To configure network settings.",
        "To install and uninstall programs."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Task Manager is a powerful tool for monitoring system performance, identifying resource-intensive processes, and ending unresponsive applications. The other options describe different utilities.",
      "examTip": "Use Task Manager to troubleshoot performance issues and manage running applications."
    },
    {
      "id": 75,
      "question": "What is the purpose of creating a restore point in Windows before installing new software or making significant system changes?",
      "options": [
        "To back up user data.",
        "To allow you to revert the system to its previous state if problems occur.",
        "To improve system performance.",
        "To free up disk space."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Restore points act as 'snapshots' of the system's configuration, allowing you to roll back changes if something goes wrong.  They don't back up user data.",
      "examTip": "Always create a restore point before major system changes."
    },
    {
      "id": 76,
      "question": "Which of the following is the *safest* way to handle a suspicious email attachment?",
      "options": [
        "Open the attachment to see what it contains.",
        "Forward the email to a friend for their opinion.",
        "Do not open the attachment; delete the email or report it as spam/phishing.",
        "Reply to the sender and ask if the attachment is safe."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Never open attachments from unknown or untrusted senders.  Deleting or reporting the email is the safest course of action.  Forwarding or replying increases the risk.",
      "examTip": "When in doubt, do not open email attachments from unknown sources."
    },
    {
      "id": 77,
      "question": "What is the purpose of the 'tracert' (or 'traceroute' on Linux/macOS) command?",
      "options": [
        "To display network configuration information.",
        "To test network connectivity to a specific host.",
        "To trace the route that packets take to reach a destination host.",
        "To manage user accounts."
      ],
      "correctAnswerIndex": 2,
      "explanation": "'tracert' shows the path (hops) that packets take to reach a destination, helping to identify network bottlenecks or routing problems. The other options describe different commands.",
      "examTip": "Use 'tracert' to diagnose network routing issues."
    },
    {
      "id": 78,
      "question": "Which type of social engineering attack involves following someone through a secure door without their permission?",
      "options": [
        "Phishing",
        "Tailgating",
        "Shoulder surfing",
        "Dumpster diving"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Tailgating is gaining unauthorized physical access by following someone who has legitimate access. Phishing is via email, shoulder surfing is looking over someone's shoulder, and dumpster diving is searching through trash.",
      "examTip": "Be aware of your surroundings and prevent tailgating to maintain physical security."
    },
    {
      "id": 79,
      "question": "Which file system is commonly used for removable storage devices like USB flash drives?",
      "options": [
        "NTFS",
        "FAT32 or exFAT",
        "ext4",
        "HFS+"
      ],
      "correctAnswerIndex": 1,
      "explanation": "FAT32 and exFAT are widely compatible with different operating systems, making them suitable for removable storage. NTFS is primarily for Windows, ext4 for Linux, and HFS+ for older macOS.",
      "examTip": "FAT32 and exFAT are common choices for cross-platform compatibility on removable drives."
    },
    {
      "id": 80,
      "question": "What is a 'zero-day' attack?",
      "options": [
        "An attack that occurs on the first day a computer is used.",
        "An attack that exploits a software vulnerability that is unknown to the vendor or for which no patch is yet available.",
        "An attack that is easily prevented with basic security measures.",
        "An attack that only affects outdated operating systems."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Zero-day attacks exploit vulnerabilities before the vendor is aware of them or has released a fix, making them particularly dangerous. The other options are incorrect.",
      "examTip": "Zero-day attacks highlight the importance of proactive security measures and rapid patching."
    },
    {
      "id": 81,
      "question": "You receive a phone call from someone claiming to be from Microsoft support, stating your computer is infected and they need remote access to fix it. What should you do?",
      "options": [
        "Provide them with remote access.",
        "Give them your username and password.",
        "Hang up the phone; this is likely a scam.",
        "Follow their instructions carefully."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Unsolicited tech support calls are almost always scams. Legitimate companies will not call you out of the blue to report problems with your computer.",
      "examTip": "Never grant remote access or provide personal information to unsolicited callers."
    },
    {
      "id": 82,
      "question": "Which Windows feature allows you to encrypt individual files and folders?",
      "options": [
        "BitLocker",
        "EFS (Encrypting File System)",
        "Windows Defender Firewall",
        "User Account Control"
      ],
      "correctAnswerIndex": 1,
      "explanation": "EFS allows you to encrypt files and folders on an NTFS volume, protecting them from unauthorized access even if someone gains physical access to the computer. BitLocker encrypts entire volumes.",
      "examTip": "Use EFS for file-level encryption and BitLocker for full-disk encryption."
    },
    {
      "id": 83,
      "question": "What is a keylogger?",
      "options": [
        "A device that monitors network traffic.",
        "A type of malware that records keystrokes, potentially capturing passwords and other sensitive information.",
        "A program that protects against viruses.",
        "A tool for managing user accounts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Keyloggers are a serious threat, as they can capture sensitive data typed by the user.  The other options describe different security tools or concepts.",
      "examTip": "Be aware of the risk of keyloggers, especially on public or untrusted computers."
    },
    {
      "id": 84,
      "question": "Which command is used to change the current directory in both Windows command prompt and Linux terminal?",
      "options": [
        "ls",
        "cd",
        "dir",
        "pwd"
      ],
      "correctAnswerIndex": 1,
      "explanation": "'cd' (change directory) is used to navigate the file system in both Windows and Linux. 'ls' (Linux) and 'dir' (Windows) list directory contents, and 'pwd' shows the current directory.",
      "examTip": "The 'cd' command is fundamental for navigating directories in both Windows and Linux."
    },
    {
      "id": 85,
      "question": "What is shoulder surfing?",
      "options": [
        "A type of network attack.",
        "A social engineering technique where someone secretly observes a user entering their password or other sensitive information.",
        "A method for encrypting data.",
        "A way to improve internet connection speed."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Shoulder surfing is a low-tech but effective way to steal credentials by looking over someone's shoulder. The other options are unrelated.",
      "examTip": "Be aware of your surroundings when entering passwords or accessing sensitive information in public places."
    },
    {
      "id": 86,
      "question": "Which of the following is a characteristic of a phishing attack?",
      "options": [
        "It involves physically stealing a computer.",
        "It attempts to trick users into revealing sensitive information (like passwords or credit card numbers) through deceptive emails or websites.",
        "It exploits a software vulnerability to gain access to a system.",
        "It floods a network with traffic, making it unavailable."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Phishing relies on deception and social engineering to trick users into giving up their information. The other options describe different attack methods.",
      "examTip": "Be skeptical of emails asking for personal information, and always verify the sender's authenticity."
    },
    {
      "id": 87,
      "question": "Which of the following is the MOST important practice to protect against data loss?",
      "options": [
        "Installing antivirus software.",
        "Using a strong password.",
        "Regularly backing up your data.",
        "Keeping your operating system up to date."
      ],
      "correctAnswerIndex": 2,
      "explanation": "While all options contribute to security, regular backups are the *most* critical for data loss *prevention*. They provide a way to recover data in case of hardware failure, malware infection, accidental deletion, or other disasters.",
      "examTip": "Implement a robust backup strategy, including offsite backups, to protect against data loss."
    },
    {
      "id": 88,
      "question": "What is the purpose of the `ipconfig /release` and `ipconfig /renew` commands in Windows?",
      "options": [
        "To display network configuration information.",
        "To release the current IP address and obtain a new one from a DHCP server.",
        "To flush the DNS resolver cache.",
        "To repair network connection problems."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`ipconfig /release` releases the current IP address obtained from a DHCP server, and `ipconfig /renew` requests a new IP address. These are useful for troubleshooting DHCP-related issues.",
      "examTip": "Use `ipconfig /release` and `ipconfig /renew` to troubleshoot dynamic IP addressing problems."
    },
    {
      "id": 89,
      "question": "What is the purpose of a screened subnet (also sometimes called a DMZ) in a network configuration?",
      "options": [
        "To provide a secure area for storing sensitive data.",
        "To isolate a segment of the network that hosts publicly accessible servers, providing an extra layer of security.",
        "To connect wireless devices to the network.",
        "To speed up network connections."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A screened subnet (DMZ) acts as a buffer zone between the internal network and the internet, hosting public-facing servers while protecting the internal network from direct external access.",
      "examTip": "Use a screened subnet/DMZ to protect your internal network while providing public access to specific servers."
    },
    {
      "id": 90,
      "question": "Which of the following is an example of good password hygiene?",
      "options": [
        "Using the same password for all your accounts.",
        "Using a short and simple password.",
        "Using a password manager to generate and store strong, unique passwords.",
        "Writing down your passwords on a piece of paper."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Password managers help create and manage strong, unique passwords for each account, significantly improving security. The other options are poor password practices.",
      "examTip": "Consider using a reputable password manager to improve your password security."
    },
    {
      "id": 91,
      "question": "What is the function of Device Manager in Windows?",
      "options": [
        "To manage user accounts and permissions.",
        "To view and manage hardware devices installed on the computer, including updating drivers.",
        "To configure network settings.",
        "To monitor system performance."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Device Manager allows you to see all connected hardware, check their status, update or troubleshoot drivers, and disable or uninstall devices.",
      "examTip": "Use Device Manager to troubleshoot hardware problems and manage device drivers."
    },
    {
      "id": 92,
      "question": "Which Linux command is used to display the present working directory?",
      "options": [
        "ls",
        "pwd",
        "cd",
        "mkdir"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The 'pwd' (print working directory) command shows the full path of the current directory you are in. 'ls' lists contents, 'cd' changes directory, and 'mkdir' creates a directory.",
      "examTip": "Use 'pwd' in Linux to quickly see your current location in the file system."
    },
    {
      "id": 93,
      "question": "Which of the following is the MOST effective method to prevent the spread of malware?",
      "options": [
        "Only opening emails from people you know.",
        "Keeping your operating system and antivirus software up to date, and practicing safe browsing habits.",
        "Using a strong password.",
        "Never downloading files from the internet."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A multi-faceted approach is *most* effective. Keeping software updated patches vulnerabilities, antivirus detects and removes malware, and safe browsing (avoiding suspicious links/downloads) reduces exposure. The other options are helpful but not comprehensive.",
      "examTip": "Malware prevention requires a layered approach: updates, antivirus, and safe practices."
    },
    {
      "id": 94,
      "question": "What does 'BYOD' stand for in the context of workplace technology?",
      "options": [
        "Bring Your Own Device",
        "Backup Your Online Data",
        "Build Your Own Desktop",
        "Browse Your Online Documents"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BYOD (Bring Your Own Device) refers to the policy of allowing employees to use their personal devices (laptops, smartphones, tablets) for work purposes.",
      "examTip": "BYOD policies require careful security considerations to protect company data on personal devices."
    },
    {
      "id": 95,
      "question": "A user reports their computer is running very slowly, and the hard drive activity light is constantly on. What is a likely cause?",
      "options": [
        "The computer has a virus.",
        "The hard drive is failing or is excessively fragmented.",
        "The power supply is faulty.",
        "The monitor needs to be replaced."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Constant hard drive activity combined with slowness often indicates a problem with the hard drive itself – either failing or needing defragmentation (if it's an HDD). A virus *could* cause this, but the hard drive activity is a strong clue.",
      "examTip": "Constant hard drive activity and slow performance often point to a hard drive issue."
    },
    {
      "id": 96,
      "question": "Which of the following is a characteristic of a strong password?",
      "options": [
        "It is a word found in the dictionary.",
        "It is short and easy to remember.",
        "It is a combination of uppercase and lowercase letters, numbers, and symbols.",
        "It is the user's name or birthdate."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Strong passwords are complex, making them difficult to guess or crack through brute-force methods.  The other options describe weak passwords.",
      "examTip": "Use a mix of character types and make your passwords long (at least 12 characters) for better security."
    },
    {
      "id": 97,
      "question": "Which Windows utility allows you to manage local user accounts and groups?",
      "options": [
        "Task Manager",
        "System Configuration",
        "Computer Management (specifically, Local Users and Groups)",
        "Device Manager"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The 'Local Users and Groups' snap-in within Computer Management provides tools to create, modify, and delete user accounts and groups on a local computer.",
      "examTip": "Use Computer Management (Local Users and Groups) for local account administration."
    },
    {
      "id": 98,
      "question": "What is the purpose of a software firewall?",
      "options": [
        "To protect against physical damage to the computer.",
        "To filter network traffic and block unauthorized access to or from a computer.",
        "To speed up internet connections.",
        "To prevent data loss from hard drive failure."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A software firewall, like Windows Defender Firewall, runs on the computer itself and controls network traffic based on configured rules, protecting against unauthorized access.",
      "examTip": "Enable and configure a software firewall on every computer for an additional layer of network security."
    },
    {
      "id": 99,
      "question": "You need to quickly determine the IP address of a website. Which command-line tool is BEST suited for this?",
      "options": [
        "ipconfig",
        "ping",
        "nslookup",
        "tracert"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`nslookup` (name server lookup) is specifically designed to query DNS servers and retrieve information about domain names, including their IP addresses. `ping` can also *sometimes* show the IP, but nslookup is more reliable for this purpose.",
      "examTip": "Use `nslookup` for DNS queries, including finding the IP address of a hostname."
    },
    {
      "id": 100,
      "question": "Which of the following is a recommended safety precaution when working inside a computer case?",
      "options": [
        "Wearing an ESD strap.",
        "Disconnecting the power cord from the power supply.",
        "Avoiding touching any metal components.",
        "All of the above"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Wearing an ESD strap is the recommended precaution because it grounds any static electricity on your body, preventing damage to sensitive electronic components inside the computer. While disconnecting the power cord and being cautious about touching metal parts are also important safety measures, the ESD strap specifically protects against electrostatic discharge.",
      "examTip": "Always wear an ESD strap when working inside a computer case to prevent static electricity from damaging critical components."
    }
  ]
});
