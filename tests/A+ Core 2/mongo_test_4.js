
{
  "category": "aplus2",
  "testId": 4,
  "testName": "XYZ Practice Test #4 (Moderate)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A user reports that their Windows 10 computer is running slowly.  You open Task Manager and notice that a process called 'svchost.exe' is consuming a large amount of CPU.  What is the MOST appropriate next step to diagnose this issue?",
      "options": [
        "Immediately end the 'svchost.exe' process.",
        "Restart the computer.",
        "Use Resource Monitor to identify which specific service hosted by svchost.exe is causing the high CPU usage.",
        "Run a full system scan with antivirus software."
      ],
      "correctAnswerIndex": 2,
      "explanation": "svchost.exe is a generic host process for services.  Ending it directly can cause system instability.  Resource Monitor allows you to drill down and see which *specific* service within svchost.exe is the culprit.  Restarting might temporarily help, but doesn't diagnose the root cause.  An antivirus scan is a good general step, but less targeted for this specific symptom.",
      "examTip": "Remember that 'svchost.exe' is a *container* for multiple services; use Resource Monitor to pinpoint the problematic one."
    },
    {
      "id": 2,
      "question": "You need to configure a Windows 10 workstation to automatically connect to a corporate VPN whenever it's on an external network.  Which of the following is the BEST way to achieve this?",
      "options": [
        "Manually create a VPN connection in Network and Sharing Center and instruct the user to connect each time.",
        "Configure a scheduled task to launch the VPN connection at startup.",
        "Use the 'Always On VPN' feature in Windows 10.",
        "Create a batch script that connects to the VPN and place it in the Startup folder."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Always On VPN is a Windows feature specifically designed for this purpose, providing automatic and seamless VPN connectivity. The other options are less reliable or require manual intervention.",
      "examTip": "Look for built-in Windows features like 'Always On VPN' for robust and user-friendly solutions to common networking tasks."
    },
    {
      "id": 3,
      "question": "A user reports that they cannot access shared folders on the network.  Other users are not experiencing the same issue.  You suspect a problem with the user's network configuration.  Which command-line tool would be MOST helpful in initially diagnosing the problem?",
      "options": [
        "gpupdate",
        "ipconfig /all",
        "netstat -a",
        "chkdsk"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`ipconfig /all` displays detailed network configuration information, including IP address, subnet mask, default gateway, and DNS servers. This is crucial for troubleshooting basic network connectivity.  `gpupdate` refreshes Group Policy, `netstat -a` shows active connections, and `chkdsk` checks the hard drive for errors.",
      "examTip": "Use `ipconfig /all` as a first step in diagnosing network connectivity issues on a Windows machine."
    },
    {
      "id": 4,
      "question": "You are setting up a new Windows 10 computer and want to prevent users from installing unauthorized software.  What is the MOST effective method to achieve this?",
      "options": [
        "Create standard user accounts for all users.",
        "Disable the Windows Store.",
        "Install antivirus software.",
        "Enable User Account Control (UAC) and set it to the highest level."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Standard user accounts, by default, cannot install software that requires system-wide changes.  Disabling the Windows Store only prevents Store app installations.  Antivirus helps with malware, but not unauthorized installations.  UAC provides notifications, but doesn't inherently *prevent* installations by itself.",
      "examTip": "The principle of least privilege (using standard user accounts) is fundamental for securing a workstation."
    },
    {
      "id": 5,
      "question": "You are troubleshooting a computer that intermittently displays a Blue Screen of Death (BSOD).  You suspect a hardware issue.  Which of the following tools would be MOST useful in identifying a potential RAM problem?",
      "options": [
        "System File Checker (sfc /scannow)",
        "Windows Memory Diagnostic",
        "Disk Cleanup",
        "Event Viewer"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Windows Memory Diagnostic is a built-in tool specifically designed to test RAM for errors.  `sfc /scannow` checks system files, Disk Cleanup removes temporary files, and Event Viewer logs system events (which *could* include memory errors, but isn't a direct diagnostic tool).",
      "examTip": "Use Windows Memory Diagnostic to directly test RAM when suspecting memory-related BSODs or instability."
    },
    {
      "id": 6,
      "question": "A user reports that their previously working printer is no longer available.  The printer is connected via USB.  What is the FIRST step you should take?",
      "options": [
        "Reinstall the printer driver.",
        "Check the physical connection of the USB cable.",
        "Restart the Print Spooler service.",
        "Run the printer troubleshooter in Windows."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Always check the physical connection first.  A loose or disconnected cable is a common and easily overlooked cause of printer problems.  The other options are valid troubleshooting steps, but should be performed *after* verifying the physical connection.",
      "examTip": "Start with the simplest and most obvious solutions (like physical connections) before moving to more complex troubleshooting."
    },
    {
      "id": 7,
      "question": "Which of the following file systems is MOST commonly used on modern Windows installations?",
      "options": [
        "FAT32",
        "NTFS",
        "exFAT",
        "ext4"
      ],
      "correctAnswerIndex": 1,
      "explanation": "NTFS (New Technology File System) is the standard file system for modern Windows installations, offering features like security permissions, journaling, and large file support. FAT32 and exFAT are used for removable drives, and ext4 is primarily used in Linux.",
      "examTip": "NTFS is the default and preferred file system for internal hard drives on Windows systems."
    },
    {
      "id": 8,
      "question": "You are configuring a SOHO wireless network.  Which of the following encryption standards provides the BEST security?",
      "options": [
        "WEP",
        "WPA",
        "WPA2 with AES",
        "WPA3 with TKIP"
      ],
      "correctAnswerIndex": 2,
      "explanation": "WPA2 with AES is currently the recommended standard for securing wireless networks. WPA3 is newer and more secure, but not always compatible. WEP and WPA (especially with TKIP) are outdated and vulnerable.",
      "examTip": "Always choose WPA2 with AES or WPA3 (if supported) for the strongest wireless security."
    },
    {
      "id": 9,
      "question": "You are responding to a suspected malware infection on a workstation.  Which of the following steps should be performed BEFORE running an anti-malware scan?",
      "options": [
        "Disable System Restore.",
        "Update the anti-malware software's definitions.",
        "Quarantine the infected system.",
        "Create a restore point."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Quarantining the infected system (isolating it from the network) prevents the malware from spreading. Disabling System Restore prevents malware from being backed up. Updating definitions is important, but *after* isolating the system. Creating a restore point before removing malware is counterproductive.",
      "examTip": "The first priority in a malware incident is to *contain* the spread; quarantine the system immediately."
    },
    {
      "id": 10,
      "question": "A user is unable to access a specific website, but other websites are working normally.  Which command-line tool can help determine if the issue is with DNS resolution?",
      "options": [
        "ping",
        "tracert",
        "nslookup",
        "ipconfig"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`nslookup` is specifically designed to query DNS servers and resolve domain names to IP addresses. `ping` tests basic connectivity, `tracert` traces the route to a destination, and `ipconfig` displays network configuration.",
      "examTip": "Use `nslookup` to troubleshoot DNS resolution problems when a specific website is inaccessible."
    },
     {
      "id": 11,
      "question": "Which type of social engineering attack involves an attacker physically following an authorized person into a restricted area?",
      "options": [
        "Phishing",
        "Tailgating",
        "Shoulder surfing",
        "Impersonation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Tailgating is the act of following someone through a secured entrance without proper authorization. Phishing involves deceptive emails, shoulder surfing is looking over someone's shoulder, and impersonation is pretending to be someone else.",
      "examTip": "Be aware of physical security threats like tailgating, even in seemingly secure environments."
    },
    {
      "id": 12,
      "question": "A user reports that their computer is displaying numerous pop-up ads, even when they are not actively browsing the internet.  What is the MOST likely cause?",
      "options": [
        "A hardware failure",
        "Adware infection",
        "A corrupted operating system",
        "A network configuration problem"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Excessive pop-up ads, especially outside of a web browser, are a strong indicator of adware, a type of malware that displays unwanted advertisements. The other options are less likely to cause this specific symptom.",
      "examTip": "Unexpected and intrusive pop-up ads are a hallmark of adware infections."
    },
    {
      "id": 13,
      "question": "You want to prevent users from changing the system time on a Windows 10 workstation.  Where would you configure this restriction?",
      "options": [
        "Control Panel > Date and Time",
        "Local Group Policy Editor (gpedit.msc)",
        "System Configuration (msconfig.exe)",
        "Task Manager"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The Local Group Policy Editor (gpedit.msc) allows you to configure a wide range of user and computer settings, including restricting access to system settings like date and time. The other options do not provide this level of control.",
      "examTip": "Use the Local Group Policy Editor (gpedit.msc) to enforce granular restrictions on user actions and system settings."
    },
    {
      "id": 14,
      "question": "Which of the following is a valid reason to use a static IP address instead of DHCP on a server?",
      "options": [
        "To simplify network management.",
        "To ensure the server always has the same IP address.",
        "To improve network security.",
        "To reduce network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Servers often require static IP addresses so that other devices on the network can reliably access them. DHCP simplifies management for *clients*, not servers. Static IPs don't inherently improve security or reduce traffic.",
      "examTip": "Servers that provide services to other devices typically need static IP addresses for consistent accessibility."
    },
    {
      "id": 15,
      "question": "You are troubleshooting a computer that is experiencing slow performance.  You open Task Manager and notice high disk utilization.  Which tool would be MOST useful in identifying the specific files or processes causing the high disk activity?",
      "options": [
        "Disk Defragmenter",
        "Resource Monitor",
        "Performance Monitor",
        "System Information"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Resource Monitor provides detailed information about disk I/O, including which processes are reading and writing to the disk. Disk Defragmenter optimizes file storage, Performance Monitor tracks overall system performance, and System Information provides hardware and software details.",
      "examTip": "Use Resource Monitor to diagnose disk I/O bottlenecks and identify the processes responsible."
    },
        {
      "id": 16,
      "question": "You need to copy a large number of files from one network share to another, preserving the file permissions and attributes. Which command-line tool is BEST suited for this task?",
      "options": [
        "copy",
        "xcopy",
        "robocopy",
        "move"
      ],
      "correctAnswerIndex": 2,
      "explanation": "robocopy (Robust File Copy) is designed for reliable copying of files and directories, including permissions, attributes, and timestamps.  `copy` and `xcopy` are simpler, and `move` *moves* files rather than copying them.",
      "examTip": "Use `robocopy` for advanced file copying tasks, especially when preserving permissions and attributes is critical."
    },
    {
      "id": 17,
      "question": "What is the primary purpose of the `gpupdate /force` command?",
      "options": [
        "To immediately apply all Group Policy settings, bypassing the normal refresh interval.",
        "To update the local user's password.",
        "To force a system restart.",
        "To check for Windows updates."
      ],
      "correctAnswerIndex": 0,
      "explanation": "`gpupdate /force` forces an immediate refresh of all Group Policy settings, both computer and user.  The other options are unrelated to Group Policy.",
      "examTip": "Use `gpupdate /force` to ensure that Group Policy changes are applied immediately without waiting for the default refresh cycle."
    },
    {
      "id": 18,
      "question": "You are setting up a new user account on a Windows 10 computer.  Which type of account provides the MOST restrictive access to system resources?",
      "options": [
        "Administrator",
        "Standard User",
        "Guest",
        "Power User"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The Guest account has the most limited privileges, designed for temporary access. Standard users have more rights than Guest but less than Administrator or Power User.",
      "examTip": "Use the Guest account sparingly, only for very temporary and limited access to a computer."
    },
    {
      "id": 19,
      "question": "Which Windows feature allows you to encrypt individual files and folders, providing an extra layer of security even if the computer is compromised?",
      "options": [
        "BitLocker",
        "EFS (Encrypting File System)",
        "Windows Defender Firewall",
        "User Account Control (UAC)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "EFS (Encrypting File System) allows you to encrypt individual files and folders, protecting them from unauthorized access. BitLocker encrypts entire drives, Firewall protects against network threats, and UAC controls application privileges.",
      "examTip": "Use EFS to protect sensitive files and folders on a granular level, complementing full-disk encryption like BitLocker."
    },
    {
      "id": 20,
      "question": "A user reports that they are unable to print to a network printer.  You can ping the printer's IP address successfully.  What is the MOST likely cause of the problem?",
      "options": [
        "The printer is physically disconnected from the network.",
        "The printer driver is not installed or is corrupted.",
        "The user's computer has no network connectivity.",
        "The printer is out of paper."
      ],
      "correctAnswerIndex": 1,
      "explanation": "If you can ping the printer, it's on the network and reachable.  The most likely issue is a driver problem on the user's computer.  Being out of paper would usually generate a specific error message.",
      "examTip": "Successful ping to a printer confirms network connectivity; driver issues are the next likely culprit for printing problems."
    },
        {
      "id": 21,
      "question": "You are troubleshooting a slow internet connection on a user's computer.  Which command-line tool can help you identify potential bottlenecks in the network path?",
      "options": [
        "ping",
        "tracert",
        "ipconfig",
        "netstat"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`tracert` (traceroute) displays the route that packets take to reach a destination, showing the latency at each hop. This can help identify slow network segments. `ping` tests basic connectivity, `ipconfig` shows network configuration, and `netstat` shows active connections.",
      "examTip": "Use `tracert` to diagnose slow network connections by identifying points of high latency along the path to the destination."
    },
    {
      "id": 22,
      "question": "Which Windows utility allows you to manage local user accounts and groups, including setting password policies and group memberships?",
      "options": [
        "User Accounts in Control Panel",
        "Computer Management (compmgmt.msc)",
        "System Configuration (msconfig.exe)",
        "Task Manager"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Computer Management (compmgmt.msc) provides access to the Local Users and Groups snap-in, where you can manage user accounts and groups in detail. The User Accounts Control Panel applet offers a simplified interface. msconfig manages startup, and Task Manager manages running processes.",
      "examTip": "Use Computer Management (compmgmt.msc) for advanced user and group management tasks on a local Windows system."
    },
    {
      "id": 23,
      "question": "What is the purpose of the System File Checker (sfc /scannow) command?",
      "options": [
        "To check the hard drive for errors.",
        "To scan for and restore corrupted Windows system files.",
        "To defragment the hard drive.",
        "To update device drivers."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`sfc /scannow` scans protected system files and replaces corrupted or missing files with cached copies. It doesn't check the *entire* hard drive for errors (chkdsk does that), defragment, or update drivers.",
      "examTip": "Run `sfc /scannow` if you suspect corruption of core Windows system files, often after a malware infection or system crash."
    },
    {
      "id": 24,
      "question": "A user reports that their computer is running slowly, and they suspect a virus.  You run a full system scan with the installed antivirus software, but it finds nothing.  What should you do NEXT?",
      "options": [
        "Tell the user that their computer is fine.",
        "Run a scan with a different anti-malware tool.",
        "Reinstall the operating system.",
        "Ignore the user's complaint."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Different anti-malware tools use different detection methods and databases.  Running a scan with a second tool (or a bootable rescue scanner) increases the chances of finding malware that the first tool missed.  Reinstalling the OS is a drastic step, and ignoring the user is unprofessional.",
      "examTip": "If one anti-malware tool finds nothing, consider using a second opinion from a different tool, especially if symptoms persist."
    },
    {
      "id": 25,
      "question": "Which of the following is the MOST secure method for disposing of an old hard drive containing sensitive data?",
      "options": [
        "Deleting all files and emptying the Recycle Bin.",
        "Formatting the hard drive.",
        "Using a disk wiping utility to overwrite the data multiple times.",
        "Physically destroying the hard drive."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Physical destruction (e.g., shredding, drilling) is the most secure method, ensuring the data is unrecoverable.  Deleting and formatting do *not* securely erase data; disk wiping utilities are good, but physical destruction is the ultimate solution.",
      "examTip": "For truly sensitive data, physical destruction of the hard drive is the most reliable method of disposal."
    },
    {
    "id": 26,
    "question": "A user's mobile device is experiencing rapid battery drain, even when not in use. What is a LIKELY cause, besides a failing battery?",
    "options": [
        "A cracked screen.",
        "Too many apps running in the background.",
        "A weak Wi-Fi signal.",
        "Low screen brightness."
    ],
    "correctAnswerIndex": 1,
    "explanation": "Numerous apps running in the background consume processing power and, therefore, battery life. A cracked screen doesn't directly impact battery drain, and *low* brightness would *increase* battery life. A weak Wi-Fi signal can contribute, but background apps are a more common culprit.",
    "examTip": "Advise users to close unnecessary background apps and manage app permissions to conserve battery life on mobile devices."
},
{
    "id": 27,
    "question": "Which of the following is a characteristic of a strong password?",
    "options": [
        "It is a common word found in the dictionary.",
        "It is short and easy to remember.",
        "It includes a combination of uppercase and lowercase letters, numbers, and symbols.",
        "It is the user's name or birthday."
    ],
    "correctAnswerIndex": 2,
    "explanation": "Strong passwords are complex, using a mix of character types to make them difficult to guess or crack. The other options describe weak passwords that are easily compromised.",
    "examTip": "Emphasize the importance of using long, complex, and unique passwords for all accounts."
},
{
    "id": 28,
    "question": "You are configuring a wireless router and want to prevent unauthorized devices from connecting to the network, even if they know the Wi-Fi password. What feature can you use?",
    "options": [
        "MAC address filtering",
        "SSID broadcast disabling",
        "Changing the default router password",
        "WPS (Wi-Fi Protected Setup)"
    ],
    "correctAnswerIndex": 0,
    "explanation": "MAC address filtering allows you to create a list of allowed devices based on their unique MAC addresses. Disabling SSID broadcast hides the network name, but doesn't prevent connections if the SSID is known. Changing the router password protects the *router's* configuration, not the Wi-Fi. WPS is notoriously insecure.",
    "examTip": "MAC address filtering adds a layer of security to wireless networks, but it's not foolproof (MAC addresses can be spoofed)."
},
{
    "id": 29,
    "question": "What is the FIRST step you should take when you encounter suspected prohibited content or activity on a user's computer?",
    "options": [
        "Immediately delete the content.",
        "Confront the user.",
        "Disconnect the computer from the network.",
        "Follow your organization's incident response procedures."
    ],
    "correctAnswerIndex": 3,
    "explanation": "Always follow your organization's established incident response procedures. This typically involves documenting the incident, preserving evidence, and reporting to the appropriate authorities (IT security, HR, or law enforcement).  Taking immediate action without following procedures can compromise evidence or violate policies.",
    "examTip": "Never take unilateral action when dealing with suspected prohibited content; follow established incident response procedures."
},
{
    "id": 30,
    "question": "Which command is used in Linux to change the ownership of a file?",
    "options": [
        "chmod",
        "chown",
        "chgrp",
        "sudo"
    ],
    "correctAnswerIndex": 1,
    "explanation": "`chown` (change owner) is used to change the user and/or group ownership of a file or directory in Linux. `chmod` changes permissions, `chgrp` changes group ownership only, and `sudo` elevates privileges.",
    "examTip": "Remember the distinction: `chown` changes ownership, `chmod` changes permissions."
},
{
        "id": 31,
        "question": "What is the primary purpose of an Acceptable Use Policy (AUP)?",
        "options": [
           "To define the rules and guidelines for using an organization's IT resources.",
           "To list all the hardware and software assets of an organization.",
           "To document the network topology.",
           "To track user activity on the network."
       ],
        "correctAnswerIndex": 0,
        "explanation": "An AUP outlines acceptable and unacceptable uses of company computers, networks, and other resources, helping to protect the organization and its data. The other options describe different types of IT documentation.",
        "examTip": "Ensure users understand and sign the AUP to promote responsible use of IT resources and minimize legal risks."
    },
    {
        "id": 32,
        "question": "You are troubleshooting a computer that boots very slowly.  Which Windows utility allows you to manage the programs that start automatically when Windows loads?",
        "options": [
            "Task Manager",
            "System Configuration (msconfig.exe)",
            "Device Manager",
            "Resource Monitor"
        ],
        "correctAnswerIndex": 1,
        "explanation": "The System Configuration utility (msconfig.exe), specifically the Startup tab, allows you to disable or enable startup programs. Task Manager also has a Startup tab, but msconfig provides more comprehensive control. Device Manager manages hardware, and Resource Monitor shows real-time resource usage.",
        "examTip": "Use msconfig (or Task Manager's Startup tab) to optimize boot times by disabling unnecessary startup programs."
    },
    {
        "id": 33,
        "question": "What is the purpose of a 'rollback plan' in change management?",
        "options": [
           "To document the steps required to implement a change.",
           "To outline the potential risks of a change.",
           "To describe how to revert a change if it fails or causes problems.",
           "To obtain approval for a change."
       ],
        "correctAnswerIndex": 2,
        "explanation": "A rollback plan is a crucial part of change management, detailing the steps to undo a change and restore the system to its previous state if something goes wrong. The other options describe other aspects of change management.",
        "examTip": "Always have a well-documented rollback plan before implementing any significant system changes."
    },
    {
        "id": 34,
        "question": "You are using a multimeter to test a power supply.  What voltage should you expect to see on the yellow wire of a Molex connector?",
        "options": [
            "+3.3V",
            "+5V",
            "+12V",
            "-12V"
        ],
        "correctAnswerIndex": 2,
        "explanation": "The yellow wire on a Molex connector carries +12V. +3.3V is typically orange, +5V is red, and -12V is blue (though not always present on Molex).",
        "examTip": "Remember the standard color-coding for power supply wires: Yellow = +12V, Red = +5V, Orange = +3.3V."
    },
    {
        "id": 35,
        "question": "Which type of backup copies only the files that have changed since the last *full* backup?",
        "options": [
           "Full backup",
           "Incremental backup",
           "Differential backup",
           "Synthetic backup"
       ],
        "correctAnswerIndex": 2,
        "explanation": "A differential backup copies all changes made *since the last full backup*. An incremental backup only copies changes since the last backup (full *or* incremental). A full backup copies everything, and a synthetic backup creates a new full backup from existing full and incremental backups.",
        "examTip": "Understand the difference between incremental and differential backups: Incremental backs up since the *last* backup; differential backs up since the last *full* backup."
    },
     {
        "id": 36,
        "question": "What is the purpose of using an antistatic wrist strap when working inside a computer?",
        "options": [
            "To prevent electric shock.",
            "To prevent damage to components from electrostatic discharge (ESD).",
            "To keep the computer grounded.",
            "To organize cables."
        ],
        "correctAnswerIndex": 1,
        "explanation": "An antistatic wrist strap equalizes the electrical potential between you and the computer, preventing ESD damage to sensitive electronic components. It doesn't prevent electric shock from mains power, and while it contributes to grounding, that's not its primary purpose.",
        "examTip": "Always use an antistatic wrist strap when working inside a computer to protect components from ESD."
    },
    {
        "id": 37,
        "question": "What is the recommended humidity level for a computer room or data center?",
        "options": [
            "0% - 10%",
            "20% - 30%",
            "40% - 60%",
            "70% - 80%"
        ],
        "correctAnswerIndex": 2,
        "explanation": "A humidity level between 40% and 60% is generally recommended to prevent both static electricity buildup (too dry) and condensation/corrosion (too humid).",
        "examTip": "Maintain proper temperature and humidity levels in computer rooms to prevent hardware damage and ensure optimal performance."
    },
    {
        "id": 38,
        "question": "What does 'chain of custody' refer to in incident response?",
        "options": [
           "The order in which individuals are notified of an incident.",
           "The documentation of the handling and control of evidence from collection to presentation.",
           "The process of restoring systems after an incident.",
           "The list of authorized personnel who can access a system."
       ],
        "correctAnswerIndex": 1,
        "explanation": "Chain of custody is the meticulous documentation of evidence handling, ensuring its integrity and admissibility in legal proceedings. It tracks who had access to the evidence, when, and what was done with it.",
        "examTip": "Maintain a strict chain of custody for any evidence collected during an incident response to ensure its legal validity."
    },
    {
        "id": 39,
        "question": "What is the difference between an open-source license and a commercial software license?",
        "options": [
            "Open-source licenses are always free, while commercial licenses always cost money.",
            "Open-source licenses allow modification and redistribution of the source code, while commercial licenses typically do not.",
            "Open-source software is less secure than commercial software.",
            "Commercial software is always better quality than open-source software."
        ],
        "correctAnswerIndex": 1,
        "explanation": "The key difference lies in the freedom to modify and redistribute. Open-source licenses grant these rights (often with conditions), while commercial licenses usually restrict them. Cost, security, and quality can vary widely in both categories.",
        "examTip": "Understand the fundamental differences between open-source and commercial software licensing models, particularly regarding source code access and modification rights."
    },
    {
        "id": 40,
        "question": "You are setting up a remote desktop connection to a Windows 10 computer.  Which port needs to be open on the firewall to allow RDP traffic?",
        "options": [
            "22",
            "23",
            "80",
            "3389"
        ],
        "correctAnswerIndex": 3,
        "explanation": "RDP (Remote Desktop Protocol) uses port 3389 by default. Port 22 is for SSH, 23 is for Telnet (insecure), and 80 is for HTTP.",
        "examTip": "Remember that RDP uses port 3389; ensure this port is open on firewalls to allow remote desktop connections."
    },
    {
      "id": 41,
      "question": "When troubleshooting a computer, you find a file named 'pagefile.sys' that is taking up a significant amount of disk space. What is the purpose of this file?",
      "options": [
        "It stores user documents and settings.",
        "It is a temporary file used by applications.",
        "It is used as virtual memory, extending the system's RAM.",
        "It contains the operating system's core files."
      ],
      "correctAnswerIndex": 2,
      "explanation": "pagefile.sys is the Windows paging file, used as virtual memory. It allows the system to use more memory than physically available by swapping data between RAM and the hard drive. The other options describe different types of files.",
      "examTip": "Understand that pagefile.sys is essential for virtual memory; do not delete it, but you can adjust its size if necessary."
    },
    {
      "id": 42,
      "question": "A user complains that their web browser is frequently redirecting them to unwanted websites. What is the MOST likely cause?",
      "options": [
        "A hardware malfunction.",
        "A corrupted operating system.",
        "Malware infection (browser hijacker).",
        "Incorrect DNS settings."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Browser hijacking is a common symptom of malware that modifies browser settings to redirect users to malicious or unwanted websites. The other options are less likely to cause this specific behavior.",
      "examTip": "Unexplained browser redirects are a strong indicator of a browser hijacker; run anti-malware scans to remove it."
    },
    {
      "id": 43,
      "question": "Which of the following is a BEST practice when creating a backup of a workstation?",
      "options": [
        "Store the backup media in the same location as the workstation.",
        "Test the backup regularly to ensure it can be restored.",
        "Only back up user documents, not system files.",
        "Use the same backup media for all computers in the office."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Regularly testing backups is crucial to verify their integrity and ensure they can be successfully restored in case of data loss. Storing backups in the same location defeats the purpose (if the location is compromised, so is the backup).  System files are essential for a full recovery. Using the same media for multiple computers is inefficient and risky.",
      "examTip": "Always test your backups!  A backup that can't be restored is useless."
    },
    {
      "id": 44,
      "question": "You are troubleshooting a network connectivity issue on a Windows computer. The `ipconfig` command shows an IP address of 169.254.x.x. What does this indicate?",
      "options": [
        "The computer has a static IP address.",
        "The computer is successfully connected to the network.",
        "The computer is unable to obtain an IP address from a DHCP server.",
        "The computer is configured for a VPN connection."
      ],
      "correctAnswerIndex": 2,
      "explanation": "An IP address in the 169.254.x.x range is an APIPA (Automatic Private IP Addressing) address, assigned when a computer is configured for DHCP but cannot reach a DHCP server. The other options are incorrect.",
      "examTip": "An APIPA address (169.254.x.x) indicates a failure to obtain an IP address from a DHCP server."
    },
    {
      "id": 45,
      "question": "Which Linux command displays the contents of a text file one screen at a time?",
      "options": [
        "cat",
        "more",
        "less",
        "grep"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`more` displays the contents of a file one screenful at a time, allowing the user to page through it. `cat` displays the entire file at once, `less` is similar to `more` but offers more features (like backward navigation), and `grep` searches for patterns within a file.",
      "examTip": "Use `more` or `less` to view large text files in Linux without overwhelming the terminal."
    },
        {
      "id": 46,
      "question": "Which of the following is an example of PII (Personally Identifiable Information)?",
      "options": [
        "A user's favorite color.",
        "A user's operating system.",
        "A user's social security number.",
        "A user's computer's MAC address."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A social security number is a classic example of PII, as it can be used to identify an individual and potentially cause harm if misused. The other options are not considered PII in most contexts.",
      "examTip": "Protect PII carefully, as its exposure can lead to identity theft and other serious consequences."
    },
    {
      "id": 47,
      "question": "What is the purpose of the `sfc /verifyonly` command?",
        "options":[
            "Checks for system file integrity without making any changes.",
            "Scans for and fixes ONLY errors, ignoring warnings.",
            "Checks for and installs any missing system components.",
            "Checks for and installs any missing drivers."
        ],
        "correctAnswerIndex": 0,
        "explanation": "`/verifyonly` performs a dry run, reporting any integrity violations without actually repairing them. This is useful for checking the system's state without making changes.",
        "examTip": "Use `/verifyonly` to determine the extent of system corruption without committing to repairs, allowing for a rollback strategy"
    },
    {
      "id": 48,
      "question": "A user reports that they accidentally deleted an important file.  What is the FIRST place you should check to attempt recovery?",
      "options": [
        "The Recycle Bin (Windows) or Trash (macOS/Linux).",
        "A recent backup.",
        "The user's Documents folder.",
        "A file recovery utility."
      ],
      "correctAnswerIndex": 0,
      "explanation": "The Recycle Bin/Trash is the default location for deleted files, and recovery is usually simple. Checking backups or using recovery utilities are later steps if the file is not in the Recycle Bin/Trash.",
      "examTip": "Always check the Recycle Bin/Trash first for accidentally deleted files; it's the easiest and quickest recovery method."
    },
    {
      "id": 49,
      "question": "What is the purpose of disk defragmentation?",
      "options": [
        "To free up disk space by deleting unnecessary files.",
        "To organize fragmented files on a hard drive to improve performance.",
        "To scan for and repair disk errors.",
        "To encrypt the hard drive."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Disk defragmentation rearranges fragmented files on a traditional hard drive (HDD) to improve read/write speeds. It doesn't delete files, repair errors, or encrypt the drive. Note: Defragmenting SSDs is generally not recommended.",
      "examTip": "Defragment traditional HDDs regularly to optimize performance; do *not* defragment SSDs."
    },
    {
      "id": 50,
      "question": "You are troubleshooting a computer that is not booting.  You hear a series of beeps during the POST (Power-On Self-Test). What do these beeps indicate?",
      "options": [
        "The computer is successfully booting.",
        "A hardware error has been detected.",
        "The operating system is loading.",
        "The network connection is established."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Beep codes during POST are diagnostic signals indicating specific hardware problems (e.g., RAM, video card). The specific beep pattern varies by BIOS manufacturer.",
      "examTip": "Listen carefully to beep codes during POST; they can provide valuable clues about hardware failures."
    },
        {
      "id": 51,
      "question": "Which Windows utility allows you to view and manage scheduled tasks?",
      "options": [
        "Task Manager",
        "Task Scheduler",
        "System Configuration (msconfig.exe)",
        "Resource Monitor"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Task Scheduler is the dedicated tool for creating, managing, and deleting scheduled tasks. Task Manager shows running processes, msconfig manages startup programs, and Resource Monitor shows resource usage.",
      "examTip": "Use Task Scheduler to automate tasks and schedule programs to run at specific times or intervals."
    },
    {
      "id": 52,
      "question": "What is the purpose of User Account Control (UAC) in Windows?",
      "options": [
        "To prevent users from accessing the internet.",
        "To encrypt user files.",
        "To prompt users for confirmation before allowing potentially harmful actions.",
        "To manage user accounts and passwords."
      ],
      "correctAnswerIndex": 2,
      "explanation": "UAC provides a security layer by prompting users for administrator credentials or confirmation before making system-wide changes, helping to prevent malware from silently installing or making unauthorized changes.",
      "examTip": "Leave UAC enabled (at least at the default level) to help protect your system from unauthorized changes."
    },
    {
      "id": 53,
      "question": "Which of the following is a common symptom of a failing hard drive?",
      "options": [
        "The computer boots faster than usual.",
        "Unusual clicking or grinding noises.",
        "The screen displays brighter colors.",
        "The keyboard becomes more responsive."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Unusual noises (clicking, grinding, whirring) are often a sign of mechanical failure in a traditional hard drive. The other options are not typical symptoms of a failing hard drive.",
      "examTip": "Back up your data immediately if you hear unusual noises coming from your hard drive; it may be failing."
    },
    {
      "id": 54,
      "question": "You are configuring a SOHO network and want to assign a static IP address to a printer.  Where would you typically configure this setting?",
      "options": [
        "On the printer's control panel.",
        "In the Windows Control Panel.",
        "In the router's DHCP settings.",
        "In the printer driver settings on each computer."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Static IP addresses for network devices like printers are usually configured directly on the device itself, through its control panel or web interface. Configuring it on the router would be a DHCP reservation, not a true static IP. The other options are incorrect.",
      "examTip": "Configure static IP addresses directly on the network device (printer, server, etc.) for reliable access."
    },
    {
      "id": 55,
      "question": "What is the purpose of a 'restore point' in Windows?",
      "options": [
        "To create a backup of user files.",
        "To allow the system to be reverted to a previous state, including system files and settings.",
        "To defragment the hard drive.",
        "To scan for malware."
      ],
      "correctAnswerIndex": 1,
      "explanation": "System Restore creates snapshots (restore points) of the system's state, allowing you to roll back to a previous working configuration if problems arise after installing software, drivers, or updates. It doesn't back up *all* user files, defragment, or scan for malware.",
      "examTip": "Create restore points before making significant system changes (like installing new software) to provide a safety net."
    },
    {
      "id": 56,
      "question": "Which of the following is the MOST appropriate action to take if you suspect a computer is infected with a rootkit?",
      "options":[
        "Run a standard antivirus scan.",
        "Reboot the computer.",
        "Use a specialized rootkit removal tool or perform a clean OS reinstall.",
        "Disable System Restore."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Rootkits are notoriously difficult to detect and remove with standard antivirus software. Specialized tools or a clean OS reinstall are often necessary.",
      "examTip": "Rootkits require advanced removal techniques; if suspected, consider a clean OS reinstall for complete eradication."

    },
     {
      "id": 57,
      "question": "A user reports that their computer is displaying a 'No boot device found' error message. What is the MOST likely cause?",
      "options": [
        "The monitor is not connected properly.",
        "The keyboard is not working.",
        "The hard drive or boot order is incorrect.",
        "The network cable is unplugged."
      ],
      "correctAnswerIndex": 2,
      "explanation": "This error message indicates that the BIOS cannot find a bootable operating system, usually due to a hard drive failure, incorrect boot order in the BIOS settings, or a corrupted boot sector. The other options are unrelated to the boot process.",
      "examTip": "Check the BIOS boot order and hard drive connections when encountering a 'No boot device found' error."
    },
    {
      "id": 58,
      "question": "What is the purpose of the `ipconfig /release` and `ipconfig /renew` commands?",
      "options": [
        "To display the current IP address.",
        "To release the current DHCP-assigned IP address and request a new one.",
        "To flush the DNS resolver cache.",
        "To repair network adapter drivers."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`ipconfig /release` releases the current IP address obtained from a DHCP server, and `ipconfig /renew` requests a new IP address.  `ipconfig /flushdns` flushes the DNS cache. The other options are incorrect.",
      "examTip": "Use `ipconfig /release` and `ipconfig /renew` to troubleshoot DHCP-related network connectivity issues."
    },
    {
      "id": 59,
      "question": "Which Windows feature allows you to create a virtual hard disk (VHD) file?",
      "options": [
        "Disk Management",
        "System Configuration",
        "File Explorer",
        "Task Manager"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Disk Management (diskmgmt.msc) allows you to create, attach, and manage VHD files, which can be used for virtual machines or as additional storage. The other options are unrelated to VHD creation.",
      "examTip": "Use Disk Management to create and manage VHD files for virtual machines or additional storage."
    },
    {
      "id": 60,
      "question": "A user reports that their external hard drive is not recognized by their Windows computer.  The drive makes a clicking sound when plugged in.  What is the MOST likely cause?",
      "options": [
        "The USB port is faulty.",
        "The drive is not formatted correctly.",
        "The drive has a physical problem (likely a head crash).",
        "The drive is not compatible with the operating system."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A clicking sound from an external hard drive usually indicates a serious mechanical problem, such as a head crash.  While a faulty USB port or formatting issue is *possible*, the clicking sound is a strong indicator of hardware failure.",
      "examTip": "A clicking external hard drive is a critical sign of failure; do not attempt to use it further and seek professional data recovery if necessary."
    },
     {
        "id": 61,
        "question": "What is a key benefit of using Group Policy in a Windows domain environment?",
        "options":[
            "It allows centralized management of user and computer settings.",
            "It provides enhanced security against malware.",
            "It improves network performance.",
            "It simplifies software installation on individual computers."
        ],
        "correctAnswerIndex": 0,
        "explanation": "Group Policy provides a centralized way to manage settings and configurations for users and computers within a domain, ensuring consistency and reducing administrative overhead. While it *can* enhance security and simplify software deployment, its primary benefit is centralized management.",
        "examTip": "Group Policy is a powerful tool for managing Windows environments; understand its capabilities for configuration management and security enforcement."
     },
     {
        "id": 62,
        "question": "What is the main function of Windows Defender Firewall?",
        "options":[
            "To protect against viruses and malware.",
            "To block unauthorized network access to and from the computer.",
            "To encrypt files and folders.",
            "To manage user accounts."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Windows Defender Firewall acts as a barrier, controlling network traffic in and out of the computer based on predefined rules. It helps prevent unauthorized access. Windows Defender *Antivirus* handles viruses and malware. The other options describe different security features.",
        "examTip": "Configure Windows Defender Firewall carefully, allowing necessary traffic while blocking potentially harmful connections."
     },
     {
        "id": 63,
        "question": "A user's computer is experiencing frequent system crashes. You suspect a problem with a recently installed device driver. What is the BEST way to troubleshoot this?",
        "options":[
            "Reinstall the operating system.",
            "Roll back the driver to the previous version in Device Manager.",
            "Run System File Checker (sfc /scannow).",
            "Disable the device in Device Manager."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Device Manager allows you to roll back a driver to the previously installed version, which can resolve issues caused by a faulty or incompatible update. Reinstalling the OS is a drastic step. `sfc /scannow` checks system files, not drivers. Disabling the device prevents it from functioning.",
        "examTip": "Use the driver rollback feature in Device Manager to revert to a previous driver version when troubleshooting newly installed hardware."
     },
     {
       "id": 64,
        "question": "Which tool would you use to view detailed logs of system events, application errors, and security audits in Windows?",
        "options":[
            "Task Manager",
            "Event Viewer",
            "Resource Monitor",
            "System Information"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Event Viewer is the central repository for system logs, providing detailed information about various events, errors, and warnings. Task Manager shows running processes, Resource Monitor shows resource usage, and System Information provides hardware and software details.",
        "examTip": "Familiarize yourself with Event Viewer; it's a powerful tool for diagnosing system problems and security issues."
     },
     {
        "id": 65,
        "question": "A user is unable to access a network share that they could previously access.  You verify that the user's account is not locked out and that they have the correct permissions.  What is the NEXT step you should take?",
        "options":[
            "Restart the user's computer.",
            "Check if the file server hosting the share is online and accessible.",
            "Reinstall the network adapter driver.",
            "Run a virus scan."
        ],
        "correctAnswerIndex": 1,
        "explanation": "If the user's account and permissions are correct, the next logical step is to verify that the file server itself is accessible. Restarting the user's computer might help, but checking the server is a more direct approach. The other options are less likely to be the immediate cause.",
        "examTip": "When troubleshooting network share access, always verify the availability of the file server hosting the share."
     },
     {
        "id": 66,
        "question": "What is the primary purpose of a DMZ (demilitarized zone) in a network?",
        "options":[
            "To provide a secure area for internal servers.",
            "To host publicly accessible servers, isolating them from the internal network.",
            "To connect remote users to the internal network via VPN.",
            "To filter all incoming and outgoing network traffic."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A DMZ is a separate network segment that hosts publicly accessible servers (like web servers) while isolating them from the more sensitive internal network. This provides an extra layer of security. The other options describe different network security concepts.",
        "examTip": "Use a DMZ to protect your internal network while still allowing public access to specific servers."
     },
     {
        "id": 67,
        "question": "Which command in Linux is used to list the files and directories in the current directory?",
     "options": [
            "pwd",
            "ls",
            "dir",
            "cd"
        ],
        "correctAnswerIndex": 1,
        "explanation": "`ls` (list) is the standard command for listing files and directories in Linux. `pwd` shows the current working directory, `dir` is a Windows command (though it *might* work on some Linux systems as an alias for `ls`), and `cd` changes the directory.",
        "examTip": "The `ls` command is fundamental for navigating the Linux file system; learn its various options (like `-l` for detailed listing, `-a` for showing hidden files)."
     },
      {
        "id": 68,
        "question": "Which of the following is the MOST effective way to prevent the spread of malware through email?",
        "options":[
            "Install antivirus software.",
            "Use a strong password for your email account.",
            "Educate users about phishing scams and suspicious attachments.",
            "Enable two-factor authentication for your email account."
        ],
        "correctAnswerIndex": 2,
        "explanation": "User education is crucial, as many malware infections occur through social engineering (tricking users into opening malicious attachments or clicking on phishing links). While antivirus, strong passwords, and 2FA are important, they don't directly address the *human* element of email security.",
        "examTip": "Regular security awareness training for users is one of the most effective defenses against malware and phishing attacks."
      },
      {
        "id": 69,
        "question": "What is the purpose of regularly updating the definitions (signatures) of your antivirus software?",
        "options":[
           "To improve the performance of the antivirus software.",
           "To ensure the software can detect the latest malware threats.",
           "To free up disk space.",
           "To change the user interface of the antivirus software."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Antivirus definitions contain information about known malware. Regular updates ensure the software can recognize and protect against new and emerging threats. The other options are not the primary purpose of definition updates.",
        "examTip": "Keep your antivirus definitions up-to-date; this is critical for effective malware protection."
     },
     {
        "id": 70,
        "question": "A user reports that their computer is running very slowly after installing a new application.  You suspect the application is consuming excessive system resources.  Which tool would you use to confirm this and identify the specific resources being used?",
        "options":[
          "System Information",
          "Resource Monitor",
          "Disk Defragmenter",
          "Event Viewer"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Resource Monitor provides detailed, real-time information about CPU, memory, disk, and network usage by individual processes. System Information provides hardware/software details, Disk Defragmenter optimizes HDDs, and Event Viewer logs system events.",
        "examTip": "Use Resource Monitor to diagnose performance bottlenecks and identify resource-intensive applications."
      },
      {
        "id": 71,
        "question": "What is the function of the `ping` command?",
        "options":[
           "To display the current network configuration.",
           "To test connectivity to a remote host by sending ICMP echo request packets.",
           "To resolve a domain name to an IP address.",
           "To display active network connections."
        ],
        "correctAnswerIndex": 1,
        "explanation": "`ping` sends ICMP echo request packets to a target host and measures the response time. This verifies basic network connectivity. `ipconfig` displays configuration, `nslookup` resolves domain names, and `netstat` shows active connections.",
        "examTip": "`ping` is a fundamental tool for testing network reachability; learn to interpret its output (response times, packet loss)."
      },
      {
        "id": 72,
        "question": "Which of the following is a security best practice for configuring a wireless router?",
        "options":[
            "Use the default administrator password.",
            "Disable encryption.",
            "Change the default SSID and administrator password.",
            "Enable WPS (Wi-Fi Protected Setup)."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Changing the default SSID and administrator password are *essential* first steps to secure a wireless router. Default passwords are widely known, and WPS is vulnerable to attacks. Disabling encryption leaves the network completely open.",
        "examTip": "Always change the default SSID and administrator password on any new router; this is a basic but critical security measure."
       },
      {
      "id": 73,
      "question":"A user is unable to connect to the internet. Their network icon shows a limited connection. Other users on the same network are not experiencing any issues. What is the FIRST step you should take to start troubleshooting?",
      "options":[
        "Reinstall the operating system.",
        "Replace the network cable.",
        "Check the IP address configuration on the user's computer.",
        "Restart the router."
      ],
      "correctAnswerIndex": 2,
      "explanation":"Checking the IP configuration is the most logical first step. Since other users are not experiencing issues, the problem is likely local to the affected computer. A limited connection often indicates an IP addressing problem. The other options are more drastic or less targeted.",
      "examTip":"Start troubleshooting network connectivity issues by examining the IP configuration of the affected device."
      },
      {
        "id": 74,
        "question": "Which type of malware disguises itself as legitimate software but performs malicious actions in the background?",
        "options":[
            "Virus",
            "Trojan horse",
            "Worm",
            "Spyware"
        ],
        "correctAnswerIndex": 1,
        "explanation": "A Trojan horse (or simply Trojan) pretends to be a harmless program while secretly carrying out malicious activities. Viruses attach to files, worms self-replicate, and spyware gathers information without the user's knowledge.",
        "examTip": "Be cautious about downloading and installing software from untrusted sources; Trojans often masquerade as legitimate applications."
      },
      {
        "id": 75,
        "question": "What is the purpose of enabling file and printer sharing in Windows?",
        "options":[
            "To allow other computers on the network to access files and printers connected to your computer.",
            "To improve the security of your computer.",
            "To speed up your internet connection.",
            "To automatically back up your files."
        ],
        "correctAnswerIndex": 0,
        "explanation": "File and printer sharing allows other devices on the same network to access resources (files, folders, printers) hosted on your computer. It doesn't inherently improve security or internet speed, and it's not a backup solution.",
        "examTip": "Enable file and printer sharing only on trusted networks and configure appropriate permissions to control access."
       },
        {
        "id": 76,
        "question": "You are troubleshooting a computer that is randomly restarting.  Which of the following is the LEAST likely cause?",
        "options": [
          "Overheating",
          "A failing power supply",
          "A faulty RAM module",
          "An outdated keyboard driver"
        ],
        "correctAnswerIndex": 3,
        "explanation": "An outdated keyboard driver is highly unlikely to cause random system restarts. Overheating, a failing power supply, and faulty RAM are all common causes of this type of instability.",
        "examTip": "Random restarts are often hardware-related; focus on power, temperature, and RAM when troubleshooting."
      },
       {
        "id": 77,
        "question": "Which of the following commands would you use to display the routing table on a Windows computer?",
        "options": [
            "ipconfig /all",
            "route print",
            "netstat -r",
            "tracert"
        ],
        "correctAnswerIndex": 1,
        "explanation": "`route print` displays the current routing table, showing how network traffic is directed. `ipconfig /all` shows network configuration, `netstat -r` is another way to view the routing table, and `tracert` traces the route to a specific destination. Both route print and netstat -r work.",
        "examTip": "Use `route print` (or `netstat -r`) to view the routing table and understand how network traffic is being routed."
       },
       {
        "id": 78,
        "question": "A user reports that their computer is displaying a 'low disk space' warning.  Which Windows utility can you use to quickly identify and remove unnecessary files?",
        "options":[
          "Disk Defragmenter",
          "Disk Cleanup",
          "System Restore",
          "Resource Monitor"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Disk Cleanup is designed to free up disk space by removing temporary files, emptying the Recycle Bin, and deleting other unnecessary files. Disk Defragmenter optimizes file storage, System Restore reverts the system to a previous state, and Resource Monitor shows resource usage.",
        "examTip": "Run Disk Cleanup regularly to remove temporary files and free up disk space."
      },
      {
        "id": 79,
        "question": "What is the primary purpose of an ESD mat?",
        "options":[
          "To provide a comfortable surface to work on.",
          "To prevent damage to components from electrostatic discharge.",
          "To organize tools and small parts.",
          "To insulate against electrical shock."
        ],
        "correctAnswerIndex": 1,
        "explanation": "An ESD mat, like an ESD wrist strap, provides a grounded surface to dissipate static electricity, protecting sensitive electronic components from damage. It's not primarily for comfort, organization, or protection from mains voltage.",
        "examTip": "Use an ESD mat and wrist strap when working with internal computer components to prevent ESD damage."
      },
     {
       "id": 80,
        "question": "Which of the following is a characteristic of a phishing attack?",
        "options":[
           "It involves exploiting vulnerabilities in software.",
           "It attempts to trick users into revealing sensitive information through deceptive emails or websites.",
           "It involves physically accessing a computer to steal data.",
           "It involves flooding a network with traffic to disrupt service."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Phishing relies on social engineering to deceive users into providing credentials, financial information, or other sensitive data. It doesn't directly exploit software vulnerabilities (though it might link to malicious websites that do), involve physical access, or flood networks (that's a DoS attack).",
        "examTip": "Be suspicious of unsolicited emails asking for personal information or containing links to unfamiliar websites; this is a common phishing tactic."
     },
     {
        "id":81,
        "question": "Which setting in windows is primarily used to control how frequently the computer checks for and installs updates?",
        "options":[
            "Power Options",
            "Update & Security",
            "System",
            "Privacy"
        ],
        "correctAnswerIndex": 1,
        "explanation": "The `Update & Security` settings in Windows are where you configure Windows Update, including automatic update schedules, active hours, and restart options. Power Options control sleep/hibernate, System provides general system information, and Privacy controls app permissions and data collection.",
        "examTip":"Regularly check for and install Windows updates to ensure your system has the latest security patches and feature improvements."
     },
      {
        "id":82,
        "question": "After you resolve a difficult technical problem, what is a BEST practice to do before closing the support ticket?",
        "options":[
            "Immediately close the ticket to improve your metrics.",
            "Document the solution clearly and concisely in the ticketing system.",
            "Ask the user to close the ticket themselves.",
            "Move on to the next issue without documenting."
        ],
        "correctAnswerIndex": 1,
        "explanation":"Thorough documentation is crucial for knowledge sharing, future troubleshooting, and auditing. It helps other technicians resolve similar issues and provides a record of the problem and its resolution. The other options are not best practices.",
        "examTip": "Always document your solutions in the ticketing system; this is a vital part of professional IT support."

      },
      {
        "id":83,
        "question":"You want to prevent specific applications from accessing the internet. Which Windows feature allows you to configure these restrictions?",
        "options":[
            "User Account Control (UAC)",
            "Windows Defender Firewall",
            "Device Manager",
            "Task Manager"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Windows Defender Firewall allows you to create rules to block or allow specific applications from accessing the network (and therefore the internet). UAC controls application privileges, Device Manager manages hardware, and Task Manager manages running processes.",
        "examTip": "Use Windows Defender Firewall to control network access for individual applications, enhancing security and preventing unwanted communication."

      },
      {
        "id":84,
        "question": "You are using the `net use` command in Windows. What is its primary function?",
        "options":[
          "To display active network connections.",
          "To map a network drive or share to a local drive letter.",
          "To test network connectivity to a remote host.",
          "To configure network adapter settings."
        ],
        "correctAnswerIndex": 1,
        "explanation": "`net use` is used to connect to, disconnect from, and manage network shares, typically mapping them to a drive letter for easier access. It doesn't display active connections (netstat does that), test connectivity (ping does that), or configure adapters (ipconfig does that).",
        "examTip": "Use `net use` to map network drives for convenient access to shared resources."
      },
       {
        "id":85,
        "question": "You are troubleshooting a computer with multiple hard drives. Which tool would you use to check the SMART status of each drive?",
        "options":[
          "Disk Defragmenter",
          "Disk Cleanup",
          "A third-party SMART monitoring tool or the drive manufacturer's utility.",
          "System Restore"
        ],
        "correctAnswerIndex": 2,
        "explanation":"While Windows doesn't have a built-in tool to display detailed SMART data, many third-party utilities and manufacturer-provided tools can read and interpret SMART attributes, providing insights into drive health and potential failure prediction. Disk Defragmenter and Disk Cleanup are for file system management, and System Restore is for system recovery.",
        "examTip":"Regularly monitor the SMART status of your hard drives to detect potential failures before they occur."
       },
        {
        "id": 86,
        "question": "What information does the command 'hostname' display in Windows Command Prompt?",
        "options":[
            "The IP address of the computer.",
            "The name of the current user.",
            "The computer's name on the network.",
            "The operating system version."
        ],
        "correctAnswerIndex": 2,
        "explanation": "The `hostname` command simply displays the computer's name (also known as the NetBIOS name or hostname). It doesn't show the IP address (`ipconfig` does that), the current user (environment variables or other tools do that), or the OS version (`ver` or System Information does that).",
        "examTip": "Use the `hostname` command to quickly identify the computer's name, especially useful in network environments."
      },
      {
        "id":87,
        "question": "You are configuring a computer to join a Windows domain. What information do you typically need?",
        "options":[
          "The domain name and the credentials of a domain user account with permission to join computers to the domain.",
          "The computer's IP address and subnet mask.",
          "The name of the workgroup the computer is currently in.",
          "The computer's serial number."
        ],
        "correctAnswerIndex": 0,
        "explanation":"To join a domain, you need the domain name and a valid user account (with appropriate permissions) within that domain. The IP address and subnet mask are for network connectivity (usually handled by DHCP), the workgroup name is irrelevant when joining a domain, and the serial number is not needed for domain joining.",
        "examTip":"Ensure you have the correct domain name and credentials before attempting to join a computer to a Windows domain."
      {
      }
        "id": 88,
        "question": "Which of the following is the MOST appropriate action to take when disposing of old toner cartridges?",
        "options": [
            "Throw them in the regular trash.",
            "Recycle them through a designated program or vendor.",
            "Burn them.",
            "Bury them in the ground."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Toner cartridges contain chemicals and materials that should not be disposed of in landfills. Recycling programs are designed to handle these materials properly and prevent environmental harm. Burning or burying them is harmful and potentially illegal.",
        "examTip": "Always recycle toner cartridges responsibly; many manufacturers and office supply stores offer recycling programs."
    },
    {
        "id": 89,
        "question": "What is the primary purpose of a UPS (Uninterruptible Power Supply)?",
        "options": [
            "To provide surge protection.",
            "To provide backup power during a power outage.",
            "To regulate voltage fluctuations.",
            "To cool down computer components."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A UPS's main function is to provide temporary battery power to connected devices during a power outage, allowing for a graceful shutdown and preventing data loss. While many UPS units also offer surge protection and voltage regulation, those are secondary functions.",
        "examTip": "Use a UPS for critical systems (servers, workstations with important data) to protect against data loss and equipment damage during power outages."
    },
    {
        "id": 90,
        "question": "A user reports that their computer is making a loud, buzzing noise.  The noise seems to be coming from inside the computer case.  What is the MOST likely cause?",
        "options": [
            "A failing hard drive.",
            "A failing cooling fan.",
            "A loose cable.",
            "A failing power supply."
        ],
        "correctAnswerIndex": 1, //Could be 3.  I marked this one, but the other is a VERY possible answer
        "explanation": "A loud buzzing noise is often caused by a failing cooling fan (CPU fan, case fan, or power supply fan) whose bearings are wearing out. While a failing hard drive *can* make noise, it's usually more of a clicking or grinding sound. A loose cable is less likely to cause a consistent buzzing. A Failing power supply could also be the culprit.",
        "examTip": "Isolate the source of unusual noises inside a computer case; failing fans are a common cause of buzzing or rattling sounds."
    },
    {
       "id": 91,
        "question":"Which of the following is the best example of multi-factor authentication (MFA)?",
        "options":[
            "Entering a username and password.",
            "Entering a password and scanning a fingerprint.",
            "Entering a password twice.",
            "Using a strong password."
        ],
        "correctAnswerIndex": 1,
        "explanation": "MFA requires two or more *different* factors of authentication: something you know (password), something you have (smart card, token), or something you are (biometric). Entering a password and scanning a fingerprint combines two different factors. The other options only use one factor.",
        "examTip":"Enable MFA whenever possible to significantly enhance account security."
    },
    {
        "id":92,
        "question": "What is the function of the command `gpresult /r`?",
        "options":[
            "Forces an immediate update of group policies.",
            "Displays all currently running processes.",
            "Displays the Resultant Set of Policy (RSoP) for the current user and computer.",
            "Checks for Windows updates."
        ],
        "correctAnswerIndex": 2,
        "explanation": "The command `gpresult /r` is used to display the Resultant Set of Policy (RSoP) for the current user, providing information on which Group Policy settings are applied.",
        "examTip":"Use `gpresult` to verify and troubleshoot Group Policy application on a specific computer or user."
     },
     {
        "id":93,
        "question": "Which of the following file extensions is commonly associated with a script that can be executed in the Windows Command Prompt?",
        "options":[
          ".txt",
          ".docx",
          ".bat",
          ".exe"
        ],
        "correctAnswerIndex": 2,
        "explanation":".bat (batch file) is a text file containing a series of commands that are executed sequentially by the Windows Command Prompt. .txt is a plain text file, .docx is a Word document, and .exe is an executable program.",
        "examTip":"Batch files (.bat) are a simple way to automate tasks in Windows using command-line commands."
      },
      {
        "id": 94,
        "question": "You need to quickly determine the IP address and MAC address of a network adapter on a Windows computer. Which command is the MOST efficient way to obtain this information?",
        "options":[
          "ping",
          "tracert",
          "ipconfig /all",
          "netstat"
        ],
        "correctAnswerIndex": 2,
        "explanation": "`ipconfig /all` displays detailed network configuration information, including the IP address, MAC address (Physical Address), subnet mask, default gateway, and DNS servers for each network adapter. `ping` tests connectivity, `tracert` traces routes, and `netstat` shows active connections.",
        "examTip": "`ipconfig /all` is your go-to command for comprehensive network adapter information in Windows."
      },
      {
        "id":95,
        "question": "You are helping a user troubleshoot a problem over the phone. They are not very technical. What is a good communication technique to use?",
        "options":[
            "Use technical jargon to demonstrate your expertise.",
            "Speak quickly to save time.",
            "Ask open-ended questions and use simple, non-technical language.",
            "Interrupt the user frequently to get to the point."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Using clear, non-technical language and asking open-ended questions (questions that can't be answered with a simple 'yes' or 'no') helps you understand the problem from the user's perspective and gather necessary information. Avoid jargon, speak at a moderate pace, and listen actively.",
        "examTip":"Effective communication is crucial for successful troubleshooting, especially when dealing with non-technical users."
      },
      {
        "id": 96,
        "question": "You are setting up a new computer and want to partition the hard drive. You plan to install multiple operating systems. Which partitioning scheme should you use?",
        "options": [
            "MBR (Master Boot Record)",
            "GPT (GUID Partition Table)",
            "FAT32",
            "NTFS"
        ],
        "correctAnswerIndex": 1,
        "explanation": "GPT (GUID Partition Table) is the modern partitioning scheme that supports larger hard drives and more partitions than MBR. It's also required for UEFI-based systems, which are common in newer computers. FAT32 and NTFS are file systems, not partitioning schemes.",
        "examTip": "Use GPT for new installations, especially on larger drives or systems with UEFI firmware."
    },
    {
        "id":97,
        "question": "What is the main purpose of the `chkdsk` command in Windows?",
        "options":[
          "To defragment the hard drive.",
          "To check the hard drive for file system errors and bad sectors.",
          "To display disk usage information.",
          "To create a new partition."
        ],
        "correctAnswerIndex": 1,
        "explanation": "`chkdsk` (Check Disk) scans the hard drive for file system errors (like lost clusters or cross-linked files) and bad sectors (physical damage on the disk). It can attempt to repair these errors. It doesn't defragment, display usage information (beyond basic free space), or create partitions.",
        "examTip": "Run `chkdsk` periodically, especially if you suspect file system corruption or hard drive problems."
      },
      {
        "id":98,
        "question": "Which Windows utility can be used to manage local security policies, such as password complexity requirements and account lockout policies?",
        "options":[
          "Local Security Policy (secpol.msc)",
          "System Configuration (msconfig.exe)",
          "Task Manager",
          "Computer Management"
        ],
        "correctAnswerIndex": 0,
        "explanation":"Local Security Policy (secpol.msc) provides a centralized interface for managing various security settings on a local computer, including password policies, account lockout policies, audit policies, and user rights assignments. The other options are for different system management tasks.",
        "examTip":"Use Local Security Policy (secpol.msc) to configure detailed security settings on a standalone Windows computer or a computer not joined to a domain."
      },
      {
        "id":99,
        "question": "What is the purpose of Safe Mode in Windows?",
        "options":[
          "To improve system performance.",
          "To run the operating system with a minimal set of drivers and services, for troubleshooting purposes.",
          "To encrypt the hard drive.",
          "To install Windows updates."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Safe Mode loads Windows with only essential drivers and services, disabling most third-party software. This helps diagnose problems caused by faulty drivers, software conflicts, or malware. It's not for performance improvement, encryption, or installing updates (although updates *can* sometimes be installed in Safe Mode).",
        "examTip": "Boot into Safe Mode when troubleshooting startup problems or issues caused by recently installed software or drivers."
      },
      {
        "id": 100,
        "question": "You suspect that a specific Windows service is causing a problem.  How can you quickly stop and restart the service?",
        "options":[
          "Reboot the computer.",
          "Use the Services console (services.msc) or the `net stop` and `net start` commands.",
          "Uninstall and reinstall the application associated with the service.",
          "Run System Restore."
        ],
        "correctAnswerIndex": 1,
        "explanation": "The Services console (services.msc) provides a graphical interface for managing services, including starting, stopping, restarting, and configuring them. You can also use the command-line commands `net stop <service name>` and `net start <service name>`. Rebooting is less efficient, uninstalling/reinstalling is usually unnecessary, and System Restore is for larger system changes.",
        "examTip": "Use the Services console (services.msc) or `net stop`/`net start` commands to manage individual Windows services."
      }
  ]
}
