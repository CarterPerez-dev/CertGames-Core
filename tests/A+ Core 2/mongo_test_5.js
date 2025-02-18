db.tests.insertOne({
  "category": "aplus2",
  "testId": 5,
  "testName": "Practice Test #5 (Intermediate)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A user reports that their Windows 10 computer is experiencing intermittent network connectivity.  They can sometimes access websites, but the connection frequently drops.  You suspect a driver issue.  Which of the following is the BEST approach to troubleshoot this?",
      "options": [
        "Reinstall the operating system.",
        "Roll back the network adapter driver in Device Manager, and if that doesn't work, try updating to the latest driver from the manufacturer's website.",
        "Run the Windows Network Troubleshooter.",
        "Replace the network adapter."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Rolling back the driver is a good first step, as a recent update might be causing the problem. If that fails, updating to the *manufacturer's* latest driver (not just relying on Windows Update) is recommended. Reinstalling the OS is too drastic. The Network Troubleshooter is helpful, but less targeted than driver management. Replacing the adapter is premature.",
      "examTip": "When troubleshooting driver issues, consider both rolling back *and* updating to the manufacturer's latest driver."
    },
    {
      "id": 2,
      "question": "You are investigating a potential malware infection on a workstation.  You notice unusual network activity to unfamiliar IP addresses.  Which command-line tool can help you identify the process associated with a specific network connection?",
      "options": [
        "netstat -ano",
        "ipconfig /all",
        "tracert",
        "nslookup"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`netstat -ano` displays active network connections, including the Process ID (PID) associated with each connection. You can then use Task Manager to identify the process name corresponding to the PID. `ipconfig /all` shows network configuration, `tracert` traces routes, and `nslookup` resolves domain names.",
      "examTip": "Use `netstat -ano` to link network connections to specific processes, aiding in malware investigation."
    },
    {
      "id": 3,
      "question": "A user reports that they are unable to access a specific network resource.  You suspect a DNS issue.  Which of the following steps would be MOST helpful in confirming this?",
      "options": [
        "Ping the resource by its IP address.",
        "Ping the resource by its hostname.",
        "Run `ipconfig /release` and `ipconfig /renew`.",
        "Restart the user's computer."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If you can ping the resource by its IP address but *not* by its hostname, this strongly suggests a DNS resolution problem. Pinging by hostname tests both connectivity *and* DNS. `ipconfig /release` and `ipconfig /renew` address DHCP issues, not DNS resolution. Restarting might temporarily help, but doesn't diagnose the root cause.",
      "examTip": "Compare pinging by IP address and hostname to differentiate between network connectivity and DNS resolution issues."
    },
    {
      "id": 4,
      "question": "A user's computer is displaying a 'BOOTMGR is missing' error message.  What is the MOST likely cause?",
      "options": [
        "The monitor is not connected properly.",
        "The keyboard is not working.",
        "The boot sector is corrupted or the boot configuration data (BCD) is incorrect.",
        "The network cable is unplugged."
      ],
      "correctAnswerIndex": 2,
      "explanation": "BOOTMGR (Boot Manager) is responsible for starting the Windows boot process. This error indicates a problem with the boot sector or BCD, often caused by malware, improper shutdowns, or disk errors. The other options are unrelated to the boot process.",
      "examTip": "Use the Windows Recovery Environment (boot from installation media) to repair the boot sector or BCD when encountering a 'BOOTMGR is missing' error."
    },
    {
      "id": 5,
      "question": "You are setting up a RAID 1 array for data redundancy.  How many drives are required, at a minimum?",
      "options": [
        "1",
        "2",
        "3",
        "4"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RAID 1 (mirroring) requires at least two drives, as data is duplicated across both drives. One drive provides no redundancy, and three or four drives are used in other RAID configurations (like RAID 5 or RAID 10).",
      "examTip": "RAID 1 (mirroring) provides data redundancy by duplicating data across at least two drives."
    },
    {
      "id": 6,
      "question": "Which Windows tool allows you to create a custom MMC console with specific snap-ins for managing various aspects of the system?",
      "options": [
        "Computer Management",
        "System Configuration",
        "mmc.exe",
        "regedit.exe"
      ],
      "correctAnswerIndex": 2,
      "explanation": "You can create a custom console using the Microsoft Management Console (mmc.exe) by starting it with a blank console and then adding the desired snap-ins. Computer Management is a pre-built MMC, System Configuration manages startup settings, and regedit edits the registry.",
      "examTip": "Create custom MMCs to streamline your system administration tasks by combining the tools you use most frequently."
    },
    {
      "id": 7,
      "question": "What command is used to schedule a task to run at a specific time in Windows Command Prompt?",
      "options": [
        "schtasks",
        "at",
        "runas",
        "tasklist"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `schtasks` command is the primary command-line tool for creating, managing, and deleting scheduled tasks in modern Windows systems. The `at` command is older and largely deprecated. `runas` executes a command as a different user, and `tasklist` displays running processes.",
      "examTip": "Familiarize yourself with `schtasks` for automating tasks via the command line in Windows."
    },
    {
      "id": 8,
      "question": "Which type of social engineering attack involves sending deceptive emails that appear to be from a legitimate source, in an attempt to steal sensitive information?",
      "options": [
        "Tailgating",
        "Phishing",
        "Shoulder surfing",
        "Dumpster diving"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Phishing attacks use deceptive emails, often mimicking trusted organizations, to trick users into revealing credentials, financial data, or other personal information. Tailgating is physical intrusion, shoulder surfing is visual spying, and dumpster diving is searching through trash.",
      "examTip": "Be highly skeptical of unsolicited emails asking for personal information or containing suspicious links or attachments; this is the hallmark of phishing."
    },
    {
      "id": 9,
      "question": "A user's computer is exhibiting slow performance, and you suspect a failing hard drive. Which of the following is the BEST way to confirm this suspicion without specialized hardware tools?",
      "options": [
        "Run Disk Defragmenter.",
        "Check the SMART status of the drive using a third-party utility or the drive manufacturer's tool.",
        "Run Disk Cleanup.",
        "Reinstall the operating system."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Checking the SMART (Self-Monitoring, Analysis, and Reporting Technology) status provides insights into the drive's health and can often predict impending failure. Disk Defragmenter and Disk Cleanup are for file system management, and reinstalling the OS is a drastic and unnecessary step at this point.",
      "examTip": "Use SMART data to proactively monitor hard drive health and identify potential failures before they lead to data loss."
    },
    {
      "id": 10,
      "question": "What is the primary function of the `tracert` (or `traceroute`) command?",
      "options": [
        "To display the current IP address configuration.",
        "To test network connectivity to a remote host.",
        "To trace the route that packets take to reach a destination, showing each hop along the way.",
        "To display active network connections."
      ],
      "correctAnswerIndex": 2,
      "explanation": "`tracert` shows the path (hops) that packets take to reach a destination, along with the latency at each hop. This helps identify network bottlenecks or routing problems. `ipconfig` displays configuration, `ping` tests basic connectivity, and `netstat` shows active connections.",
      "examTip": "Use `tracert` to diagnose slow network connections or identify points of failure along the network path."
    },
    {
      "id": 11,
      "question": "Which of the following security measures is MOST effective in preventing unauthorized physical access to a server room?",
      "options": [
        "A strong password policy.",
        "A firewall.",
        "A biometric access control system.",
        "Antivirus software."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Biometric access control (fingerprint, retina scan, etc.) provides a high level of physical security, restricting access to authorized individuals based on unique biological traits. Password policies, firewalls, and antivirus software address logical security, not physical access.",
      "examTip": "Implement robust physical security measures, like biometric access control, to protect sensitive areas like server rooms."
    },
    {
      "id": 12,
      "question": "You are troubleshooting a computer that is unable to connect to a wireless network. The network is broadcasting its SSID, and other devices can connect successfully. What is a likely cause?",
      "options": [
        "The router is malfunctioning.",
        "The wireless network adapter is disabled on the computer.",
        "The internet service provider (ISP) is experiencing an outage.",
        "The computer's firewall is blocking all network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "If other devices can connect, the problem is likely local to the affected computer. A disabled wireless adapter is a common cause of connectivity issues. The other options are less likely given the scenario.",
      "examTip": "Check if the wireless adapter is enabled (in Device Manager or through a physical switch on the laptop) when troubleshooting wireless connectivity problems."
    },
    {
      "id": 13,
      "question": "Which of the following is a characteristic of a strong password policy?",
      "options": [
        "Allowing users to reuse passwords across multiple accounts.",
        "Requiring passwords to be changed infrequently (e.g., once a year).",
        "Enforcing minimum password length, complexity (uppercase, lowercase, numbers, symbols), and regular changes.",
        "Allowing users to choose simple, easy-to-remember passwords."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A strong password policy mandates complexity (a mix of character types), minimum length, and regular changes to minimize the risk of password cracking. Reusing passwords, infrequent changes, and simple passwords are all security weaknesses.",
      "examTip": "Implement and enforce a strong password policy to protect user accounts and system security."
    },
    {
      "id": 14,
      "question": "You are setting up a new wireless network. Which security protocol provides the BEST protection against unauthorized access?",
      "options": [
        "WEP (Wired Equivalent Privacy)",
        "WPA (Wi-Fi Protected Access)",
        "WPA2 with AES encryption",
        "WPA3 with TKIP encryption"
      ],
      "correctAnswerIndex": 2,
      "explanation": "WPA2 with AES encryption is currently the recommended standard for securing wireless networks. WPA3 is newer and more secure, but compatibility might be an issue. WEP and WPA (especially with TKIP) are outdated and vulnerable.",
      "examTip": "Always choose WPA2 with AES or WPA3 (if all devices support it) for the strongest wireless security."
    },
    {
      "id": 15,
      "question": "A user is receiving numerous spam emails. What is the BEST way to reduce the amount of spam they receive, besides using a spam filter?",
      "options": [
        "Reply to the spam emails and ask to be removed from the mailing list.",
        "Click on the links in the spam emails to unsubscribe.",
        "Avoid posting their email address publicly and be cautious about sharing it online.",
        "Change their email address frequently."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Limiting the exposure of your email address is a proactive way to reduce spam. Replying to or clicking links in spam emails can actually *increase* the amount of spam you receive, as it confirms your address is active. Changing your address frequently is inconvenient.",
      "examTip": "Be mindful of where you share your email address online to minimize spam."
    },
    {
      "id": 16,
      "question": "What is a key advantage of using a differential backup over an incremental backup?",
      "options": [
        "Differential backups are faster to perform.",
        "Differential backups require less storage space.",
        "Restoring from a differential backup is faster because it requires fewer backup sets.",
        "Differential backups are more secure."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Differential backups copy everything that's changed since the last *full* backup. This means a restore only needs the full backup *and* the latest differential backup. Incremental backups only copy changes since the *last* backup (full or incremental), so a restore might need many incremental sets, making the restore process slower and more complex. While faster to *perform* than a *full* backup, a differential is not necessarily faster to perform than an *incremental* backup.",
      "examTip": "Choose differential backups when restore speed is a priority; choose incremental backups when minimizing backup storage space is more important."
    },
    {
      "id": 17,
      "question": "You need to remotely access a Windows computer using the command line.  Which protocol and tool would you MOST likely use?",
      "options": [
        "RDP (Remote Desktop Protocol) and the Remote Desktop Connection client.",
        "SSH (Secure Shell) and a client like PuTTY.",
        "Telnet and a Telnet client.",
        "VNC (Virtual Network Computing) and a VNC viewer."
      ],
      "correctAnswerIndex": 1,
      "explanation": "While RDP provides a graphical interface, SSH is the preferred method for command-line remote access to a Windows system (assuming the SSH server is installed and configured on the target machine). Telnet is insecure. VNC provides a graphical interface.",
      "examTip": "Use SSH for secure command-line remote access to systems; avoid Telnet due to its lack of encryption."
    },
    {
      "id": 18,
      "question": "A user reports that their computer is displaying a 'low memory' warning.  What is the FIRST action you should take?",
      "options": [
        "Add more physical RAM to the computer.",
        "Close unnecessary applications and processes.",
        "Run Disk Cleanup.",
        "Increase the size of the paging file (virtual memory)."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Closing unnecessary applications and processes frees up RAM immediately, addressing the immediate problem. Adding RAM is a longer-term solution. Disk Cleanup frees up disk space, not RAM. Increasing the paging file can help, but closing unnecessary programs is the quickest first step.",
      "examTip": "Before resorting to hardware upgrades or complex configurations, try closing unnecessary applications to free up RAM."
    },
    {
      "id": 19,
      "question": "You are documenting a network configuration.  What information should be included in a network topology diagram?",
      "options": [
        "Usernames and passwords.",
        "The make and model of each computer.",
        "The IP addresses, subnets, and connections between network devices (routers, switches, servers, etc.).",
        "The operating system version of each computer."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A network topology diagram visually represents the network's structure, showing how devices are connected and how data flows. It includes IP addresses, subnets, device types, and connection types. Usernames/passwords are security credentials, not topology information. Make/model and OS version are less critical for a topology diagram.",
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
      "explanation": "The Windows Registry is a hierarchical database that stores low-level settings for the OS, device drivers, services, and applications. It's not for user files, network connections, or directly for controlling user access (although some security settings are stored there).",
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
      "explanation": "If the user can ping their default gateway, they have basic network connectivity. The inability to access websites while still being able to ping the gateway strongly points toward a DNS resolution problem.",
      "examTip": "The ability to ping a local device but not access websites is a classic symptom of a DNS configuration problem."
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
      "explanation": "A zero-day attack exploits a software vulnerability that is unknown to the vendor, meaning there's no patch available to fix it. This makes these attacks particularly dangerous. The other options describe different types of attacks or vulnerabilities.",
      "examTip": "Keep your software up-to-date to minimize the risk of zero-day attacks; prompt patching is crucial when vulnerabilities are discovered."
    },
    {
      "id": 23,
      "question": "Which of the following is a good security practice when using public Wi-Fi?",
      "options": [
        "Disable your computer's firewall.",
        "Use a VPN (Virtual Private Network) to encrypt your traffic.",
        "Share your files and folders with everyone on the network.",
        "Connect to any available network without a password."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A VPN encrypts your internet traffic, protecting your data from eavesdropping on unsecured public Wi-Fi networks. Disabling the firewall, sharing files, and connecting to open networks are all security risks.",
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
      "explanation": "`diskpart` is a powerful command-line utility for managing disks, partitions, and volumes. `chkdsk` checks for file system errors, `defrag` defragments, and `format` prepares a partition for use (but doesn't create or manage partitions themselves).",
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
      "explanation": "System logs record events, errors, and warnings. Regularly reviewing them helps detect security incidents, diagnose problems, and monitor system health. They don't directly free up space, improve performance, or back up user data.",
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
      "explanation": "BSODs are often caused by hardware failures, particularly RAM. Windows Memory Diagnostic is a built-in tool to test RAM for errors. System Restore reverts system files, Disk Cleanup removes temporary files, and Task Manager shows running processes.",
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
      "explanation": "An incident response plan (IRP) outlines the procedures for detecting, responding to, and recovering from security incidents (data breaches, malware infections, etc.). It doesn't prevent incidents (though good security practices do), punish individuals, or deal with insurance.",
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
      "explanation": "Port forwarding allows external devices (on the internet) to access specific services running on devices within your local network. You forward traffic arriving on a specific external port to a specific internal IP address and port. The other options describe different network security or management functions.",
      "examTip": "Use port forwarding to make internal servers (web server, game server, etc.) accessible from the internet."
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
      "explanation": "Spyware often modifies browser settings to track user activity and display targeted advertisements. Faster performance is the opposite of what spyware usually causes. A non-booting computer or encrypted files are more indicative of other types of malware (or hardware failure).",
      "examTip": "Be alert for unexpected browser changes and increased pop-ups; these can be signs of spyware."
    },
    {
      "id": 30,
      "question": "You are configuring email security. What is the purpose of an SPF (Sender Policy Framework) record?",
      "options": [
        "To encrypt email messages.",
        "To prevent spam emails from being delivered.",
        "To specify which mail servers are authorized to send email on behalf of a domain, helping to prevent email spoofing.",
        "To digitally sign email messages."
      ],
      "correctAnswerIndex": 2,
      "explanation": "An SPF record is a DNS record that lists the mail servers permitted to send email for a specific domain. This helps receiving mail servers verify the sender's authenticity and reduce email spoofing (forging the sender address). It doesn't encrypt emails, directly block spam, or digitally sign messages (DKIM does that).",
      "examTip": "Configure SPF records for your domain to improve email deliverability and reduce the risk of your domain being used for spoofing."
    },
    {
      "id": 31,
      "question": "A user reports they are unable to print. The printer is online and other users can print to it. You suspect a problem with the print spooler service on the user's computer. How can you restart this service?",
      "options": [
        "Reinstall the printer driver.",
        "Restart the computer.",
        "Open the Services console (services.msc), locate the Print Spooler service, and restart it.",
        "Run the printer troubleshooter."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The Services console (services.msc) allows direct management of Windows services, including the Print Spooler. Restarting the service can often resolve printing issues. Reinstalling the driver or restarting the computer might also work, but restarting the service is a more targeted and less disruptive first step.",
      "examTip": "Use the Services console (services.msc) to manage Windows services; restarting a service can often resolve related problems."
    },
    {
      "id": 32,
      "question": "Which Linux command is used to change the permissions of a file?",
      "options": [
        "chown",
        "chmod",
        "chgrp",
        "passwd"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`chmod` (change mode) is used to modify the read, write, and execute permissions of files and directories in Linux. `chown` changes ownership, `chgrp` changes group ownership, and `passwd` changes a user's password.",
      "examTip": "Understand the numeric and symbolic modes of `chmod` for setting file permissions in Linux."
    },
    {
      "id": 33,
      "question": "What is the purpose of a Material Safety Data Sheet (MSDS) or Safety Data Sheet (SDS)?",
      "options": [
        "To provide instructions on how to install a piece of hardware.",
        "To provide information about the safe handling, storage, and disposal of hazardous materials.",
        "To list the specifications of a computer component.",
        "To provide warranty information for a product."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An MSDS/SDS contains crucial information about chemical substances, including their hazards, safe handling procedures, first aid measures, and disposal guidelines. It's not about installation, specifications, or warranties.",
      "examTip": "Consult the MSDS/SDS before handling any potentially hazardous materials."
    },
    {
      "id": 34,
      "question": "Which of the following is a valid security concern related to IoT (Internet of Things) devices?",
      "options": [
        "IoT devices are typically very expensive.",
        "Many IoT devices have weak default security settings and are vulnerable to attacks.",
        "IoT devices require a constant internet connection to function.",
        "IoT devices are difficult to install."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Many IoT devices (smart thermostats, cameras, etc.) have weak default passwords and lack regular security updates, making them easy targets for attackers. While cost, internet dependency, and installation difficulty can be issues, weak security is the primary concern.",
      "examTip": "Change default passwords and keep firmware updated on all IoT devices to improve their security."
    },
    {
      "id": 35,
      "question": "You want to ensure that a specific program always runs with administrator privileges. How can you configure this in Windows?",
      "options": [
        "Create a standard user account for the program.",
        "Right-click the program's shortcut, go to Properties > Compatibility, and check 'Run this program as an administrator'.",
        "Add the program to the Startup folder.",
        "Use Task Manager to elevate the program's privileges."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The Compatibility tab in the program's properties allows you to set it to always run with administrator privileges. Creating a standard user account would prevent this. The Startup folder controls automatic startup, and Task Manager can elevate a running process, but not persistently.",
      "examTip": "Use the Compatibility settings to configure programs to run with elevated privileges if they require them."
    },
    {
      "id": 36,
      "question": "A user reports their computer is running slowly. Upon investigation, you find the hard drive is almost full. Besides deleting unnecessary files, what else could you do to potentially improve performance?",
      "options": [
        "Run Disk Defragmenter (if it's an HDD).",
        "Add more RAM.",
        "Run a virus scan.",
        "Reinstall the operating system."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If the hard drive is a traditional HDD, defragmenting it can improve performance by consolidating fragmented files. Adding RAM helps with overall system performance, but won't directly address a full hard drive. A virus scan is a good idea, but not directly related to disk space. Reinstalling the OS is a drastic measure.",
      "examTip": "Keep sufficient free space on your hard drive; a nearly full drive can significantly slow down performance."
    },
    {
      "id": 37,
      "question": "What is the primary benefit of using a KVM (Keyboard, Video, Mouse) switch?",
      "options": [
        "To connect multiple computers to a single monitor, keyboard, and mouse.",
        "To extend the desktop across multiple monitors.",
        "To share files between computers.",
        "To improve network performance."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A KVM switch allows you to control multiple computers using a single set of peripherals (monitor, keyboard, mouse), saving space and reducing clutter. It's not for extending desktops, sharing files, or improving network performance.",
      "examTip": "Use a KVM switch to manage multiple computers efficiently with a single set of peripherals."
    },
    {
      "id": 38,
      "question": "Which Windows command is used to display and modify the local ARP (Address Resolution Protocol) cache?",
      "options": [
        "arp -a",
        "ipconfig /all",
        "netstat -r",
        "ping"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`arp -a` displays the current ARP cache, which maps IP addresses to MAC addresses on the local network. `ipconfig /all` shows network configuration, `netstat -r` shows the routing table, and `ping` tests connectivity.",
      "examTip": "Use `arp -a` to view or troubleshoot the ARP cache, which is used to resolve IP addresses to MAC addresses."
    },
    {
      "id": 39,
      "question": "What is the purpose of a 'sandbox' in software development and security?",
      "options": [
        "To provide a secure environment for testing potentially malicious code or untrusted applications.",
        "To store backups of important data.",
        "To create a virtual machine.",
        "To develop new software features."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A sandbox is an isolated environment where you can run potentially unsafe code (like downloaded files or new software) without risking harm to the main operating system or data. It's not for backups, creating VMs (though sandboxes can be implemented within VMs), or general software development (though it can be used in development).",
      "examTip": "Use sandboxes to test untrusted software or files safely, isolating them from your main system."
    },
    {
      "id": 40,
      "question": "You are setting up a new computer and want to create a local user account. Which tool is BEST for managing local users and groups in a detailed manner?",
      "options": [
        "User Accounts in Control Panel",
        "Computer Management (compmgmt.msc)",
        "System Configuration (msconfig.exe)",
        "Task Manager"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Computer Management provides access to the Local Users and Groups snap-in, which offers comprehensive control over user accounts and groups, including password policies, group memberships, and advanced settings. The User Accounts Control Panel applet is a simplified interface. msconfig manages startup, and Task Manager manages running processes.",
      "examTip": "Use Computer Management (compmgmt.msc) for advanced user and group management tasks on a local Windows system."
    },
    {
      "id": 41,
      "question": "Which Windows feature allows you to encrypt an entire hard drive, protecting all data on the drive from unauthorized access?",
      "options": [
        "EFS (Encrypting File System)",
        "BitLocker",
        "Windows Defender Firewall",
        "User Account Control (UAC)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "BitLocker provides full-disk encryption, protecting the entire drive. EFS encrypts individual files and folders, Firewall protects against network threats, and UAC controls application privileges.",
      "examTip": "Use BitLocker to encrypt entire drives, especially on laptops or other portable devices, to protect data in case of loss or theft."
    },
    {
      "id": 42,
      "question": "What is the purpose of regularly checking for and installing operating system updates?",
      "options": [
        "To improve the computer's processing speed.",
        "To free up disk space.",
        "To patch security vulnerabilities, fix bugs, and sometimes add new features.",
        "To change the appearance of the desktop."
      ],
      "correctAnswerIndex": 2,
      "explanation": "OS updates are crucial for security (patching vulnerabilities), stability (fixing bugs), and sometimes functionality (adding new features). They don't inherently improve processing speed, free up disk space, or change the desktop appearance.",
      "examTip": "Enable automatic updates or regularly check for and install OS updates to keep your system secure and stable."
    },
    {
      "id": 43,
      "question": "A user reports that they are unable to access a specific shared folder on the network, even though they have the correct permissions. Other users can access the folder. What should you check NEXT?",
      "options": [
        "The user's account is locked out.",
        "The file server is offline.",
        "The share permissions and the NTFS permissions on the folder.",
        "The user's network cable is unplugged."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Both share permissions (controlling network access) and NTFS permissions (controlling file/folder access) must be configured correctly for a user to access a shared folder. If other users can access it, the server is likely online and the user's account is probably not locked out. A network cable problem would likely prevent all network access.",
      "examTip": "Remember that both share permissions and NTFS permissions control access to shared folders; both must be set correctly."
    },
    {
      "id": 44,
      "question": "You are using a Linux system. Which command displays the current working directory?",
      "options": [
        "ls",
        "cd",
        "pwd",
        "dir"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`pwd` (print working directory) shows the full path of the current directory you're in. `ls` lists files, `cd` changes directories, and `dir` is primarily a Windows command (though it might work on some Linux systems as an alias for `ls`).",
      "examTip": "Use `pwd` to quickly determine your current location within the Linux file system."
    },
    {
      "id": 45,
      "question": "What is a common security risk associated with using weak or default passwords on network devices (routers, switches, etc.)?",
      "options": [
        "Unauthorized users can gain access to the device's configuration and potentially compromise the entire network.",
        "The device will run slower.",
        "The device will consume more power.",
        "The device will be unable to connect to the internet."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Weak or default passwords are easily guessed or found online, allowing attackers to gain control of network devices and potentially reconfigure them, monitor traffic, or launch attacks on other devices on the network. The other options are not direct consequences of weak passwords.",
      "examTip": "Always change default passwords on all network devices to strong, unique passwords."
    },
    {
      "id": 46,
      "question": "Which of the following is a characteristic of a 'man-in-the-middle' (MitM) attack?",
      "options": [
        "The attacker floods a network with traffic.",
        "The attacker intercepts communication between two parties, potentially eavesdropping on or altering the data.",
        "The attacker exploits a vulnerability in a software application.",
        "The attacker guesses user passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "In a MitM attack, the attacker secretly relays and possibly alters communication between two parties who believe they are directly communicating with each other. This can allow the attacker to steal data, inject malicious code, or manipulate the communication. The other options describe different types of attacks.",
      "examTip": "Use secure protocols (like HTTPS) and be cautious about using public Wi-Fi to protect against MitM attacks."
    },
    {
      "id": 47,
      "question": "Which Windows tool allows you to view and manage device drivers?",
      "options": [
        "Task Manager",
        "Device Manager",
        "System Configuration (msconfig.exe)",
        "Resource Monitor"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Device Manager provides a centralized interface for managing hardware devices and their drivers, including updating, rolling back, disabling, and uninstalling drivers. Task Manager manages running processes, msconfig manages startup, and Resource Monitor shows resource usage.",
      "examTip": "Use Device Manager to troubleshoot hardware problems and manage device drivers."
    },
    {
      "id": 48,
      "question": "You are troubleshooting a computer that is experiencing intermittent problems. You suspect a failing power supply. What is a symptom that would support this suspicion?",
      "options": [
        "The computer boots up normally.",
        "The computer randomly shuts down or restarts, especially under heavy load.",
        "The monitor displays distorted colors.",
        "The keyboard is unresponsive."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Random shutdowns or restarts, particularly when the system is under stress, can indicate a failing power supply that's unable to provide sufficient power. A consistently booting computer, distorted monitor colors, or an unresponsive keyboard are less likely to be caused by a PSU problem.",
      "examTip": "Suspect a failing power supply if the computer experiences random shutdowns or restarts, especially under load."
    },
    {
      "id": 49,
      "question": "What is 'social engineering' in the context of cybersecurity?",
      "options": [
        "Using specialized software to crack passwords.",
        "Exploiting vulnerabilities in network protocols.",
        "Manipulating people into divulging confidential information or performing actions that compromise security.",
        "Building relationships with employees to gain access to a company's network."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Social engineering relies on human psychology rather than technical hacking techniques. Attackers trick users into revealing passwords, clicking on malicious links, or granting access to restricted areas. While building relationships can be a part of social engineering, the core concept is manipulation.",
      "examTip": "Be aware of social engineering tactics; attackers often target human weaknesses rather than technical vulnerabilities."
    },
    {
      "id": 50,
      "question": "Which of the following is a BEST practice for securing a SOHO (small office/home office) wireless network?",
      "options": [
        "Disable SSID broadcast.",
        "Use WEP encryption.",
        "Use a strong, unique password (pre-shared key) with WPA2 or WPA3 encryption.",
        "Leave the default administrator password unchanged."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Using a strong, unique password with WPA2 (or WPA3 if supported) is the most important security measure for a wireless network. Disabling SSID broadcast only hides the network name; it doesn't prevent connections if the SSID is known. WEP is outdated and insecure. The default administrator password should always be changed.",
      "examTip": "Secure your wireless network with a strong password and WPA2/WPA3 encryption; this is the foundation of wireless security."
    },
    {
      "id": 51,
      "question": "You are configuring a new workstation and want to ensure that all users, except for administrators, are restricted from installing software. What's the BEST method to enforce this?",
      "options": [
        "Create standard user accounts for all non-administrator users.",
        "Enable User Account Control (UAC) and set it to the highest level.",
        "Install antivirus software.",
        "Disable Windows Installer service."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Standard user accounts, by default, cannot install software that makes system-wide changes. UAC provides notifications but doesn't inherently prevent installations. Antivirus helps with malware. Disabling Windows Installer is too drastic and would prevent all installations, even by administrators.",
      "examTip": "Utilize the principle of least privilege; create standard user accounts for day-to-day use and reserve administrator accounts for system management tasks."
    },
    {
      "id": 52,
      "question": "Which of the following commands in a Linux terminal would allow you to view the contents of a file named 'document.txt'?",
      "options": [
        "cd document.txt",
        "mkdir document.txt",
        "cat document.txt",
        "rm document.txt"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`cat` (concatenate) is used to display the contents of a file. `cd` changes directories, `mkdir` creates a directory, and `rm` removes a file.",
      "examTip": "Use `cat` to quickly view the contents of a text file in Linux."
    },
    {
      "id": 53,
      "question": "What is the purpose of a 'digital certificate' in website security?",
      "options": [
        "To encrypt all data transmitted between the user and the website.",
        "To verify the identity of the website and establish a secure, encrypted connection (HTTPS).",
        "To block access to the website from unauthorized users.",
        "To store user login credentials."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Digital certificates are used in HTTPS to verify the website's authenticity and enable encrypted communication. While encryption is a result of using a certificate, the certificate itself verifies identity. It doesn't block access based on users or store credentials.",
      "examTip": "Look for the padlock icon and 'https' in the address bar to ensure a secure connection to a website; this indicates the use of a digital certificate."
    },
    {
      "id": 54,
      "question": "A user reports that their computer is running slowly, and they notice unfamiliar processes running in Task Manager. What should you do FIRST?",
      "options": [
        "Reinstall the operating system.",
        "Run a full system scan with updated antivirus and anti-malware software.",
        "Delete the unfamiliar processes from Task Manager.",
        "Disable System Restore."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Unfamiliar processes, combined with slow performance, are strong indicators of a potential malware infection. Running a full system scan with updated security software is the most appropriate first step. Reinstalling the OS is too drastic. Deleting processes without knowing what they are can cause instability. Disabling System Restore is part of malware removal, not initial investigation.",
      "examTip": "If you suspect malware, run a full system scan with up-to-date antivirus and anti-malware tools before taking other actions."
    },
    {
      "id": 55,
      "question": "What is the primary purpose of a firewall?",
      "options": [
        "To protect against viruses and malware.",
        "To filter network traffic, blocking unauthorized access to or from a private network.",
        "To encrypt data transmitted over the network.",
        "To speed up internet connections."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A firewall acts as a barrier between a trusted network and untrusted networks, controlling incoming and outgoing traffic based on predefined rules. It doesn't directly protect against viruses (antivirus software does that), encrypt data (VPNs or encryption protocols do that), or speed up connections.",
      "examTip": "Enable and configure a firewall (both hardware and software firewalls) to protect your network from unauthorized access."
    },
    {
      "id": 56,
      "question": "A user reports that their computer is displaying a 'no operating system found' error message. You have already verified that the hard drive is properly connected and recognized by the BIOS. What should you check NEXT?",
      "options": [
        "The monitor cable.",
        "The keyboard connection.",
        "The boot order in the BIOS settings.",
        "The network connection."
      ],
      "correctAnswerIndex": 2,
      "explanation": "If the hard drive is detected but the OS isn't found, the BIOS might be trying to boot from the wrong device (e.g., a USB drive or network). Checking the boot order ensures the BIOS is attempting to boot from the correct hard drive partition. The other options are unrelated to the boot process.",
      "examTip": "Verify the BIOS boot order when troubleshooting 'no operating system found' errors, especially after hardware changes or BIOS updates."
    },
    {
      "id": 57,
      "question": "Which of the following is a good practice for managing user accounts on a shared computer?",
      "options": [
        "Use a single administrator account for all users.",
        "Create individual standard user accounts for each user.",
        "Share passwords between users.",
        "Disable User Account Control (UAC)."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Creating separate standard user accounts provides accountability, restricts access to system-wide settings, and helps prevent accidental or malicious damage. Using a single administrator account for everyone is a major security risk. Sharing passwords and disabling UAC are also bad practices.",
      "examTip": "Follow the principle of least privilege: give users only the access they need, and use separate accounts for accountability."
    },
    {
      "id": 58,
      "question": "What is the function of the `nslookup` command?",
      "options": [
        "To display the current IP address configuration.",
        "To test network connectivity to a remote host.",
        "To query DNS servers to resolve domain names to IP addresses (and vice versa).",
        "To display active network connections."
      ],
      "correctAnswerIndex": 2,
      "explanation": "`nslookup` is specifically designed for DNS lookups. It allows you to query DNS servers to find the IP address associated with a domain name or vice versa. The other options describe different networking commands.",
      "examTip": "Use `nslookup` to troubleshoot DNS resolution problems or to verify DNS records."
    },
    {
      "id": 59,
      "question": "A user reports that their computer is very slow to start up. You suspect that too many programs are configured to run automatically at startup. How can you manage these startup programs in Windows?",
      "options": [
        "Use Disk Cleanup.",
        "Use System Configuration (msconfig.exe) or Task Manager (Startup tab).",
        "Use Device Manager.",
        "Use Event Viewer."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Both System Configuration (msconfig.exe) and the Startup tab in Task Manager allow you to disable or enable programs that run automatically when Windows starts. Disk Cleanup removes files, Device Manager manages hardware, and Event Viewer shows system logs.",
      "examTip": "Optimize boot times by disabling unnecessary startup programs using msconfig or Task Manager."
    },
    {
      "id": 60,
      "question": "Which Linux command is used to create a new directory?",
      "options": [
        "cd",
        "ls",
        "mkdir",
        "rmdir"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`mkdir` (make directory) creates a new directory. `cd` changes the current directory, `ls` lists files and directories, and `rmdir` removes an empty directory.",
      "examTip": "Use `mkdir` to create new directories in the Linux file system."
    },
    {
      "id": 61,
      "question": "Which of the following is a characteristic of ransomware?",
      "options": [
        "It steals user data without their knowledge.",
        "It encrypts files on the victim's computer and demands a ransom payment to decrypt them.",
        "It displays unwanted pop-up advertisements.",
        "It redirects web traffic to malicious websites."
      ],
      "correctAnswerIndex": 1,
      "explanation": "This is the classic description of a ransomware attack. Ransomware encrypts files and demands payment (usually in cryptocurrency) for the decryption key. Spyware gathers information, Trojans disguise themselves as legitimate software, and worms self-replicate.",
      "examTip": "The best defense against ransomware is regular backups; do not pay the ransom without consulting security professionals."
    },
    {
      "id": 62,
      "question": "What is the purpose of the 'chain of custody' in digital forensics?",
      "options": [
        "To track the location of a stolen device.",
        "To document the handling of evidence, ensuring its integrity and admissibility in court.",
        "To encrypt sensitive data.",
        "To identify the perpetrator of a cybercrime."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Chain of custody is the meticulous documentation of evidence handling—from collection through analysis to presentation in court. It proves that the evidence hasn't been tampered with. It's not about tracking devices, encrypting data, or identifying perpetrators (though it can help with identification).",
      "examTip": "Maintain a strict chain of custody for any digital evidence to ensure its legal validity."
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
      "explanation": "System Restore takes snapshots (restore points) of the system's configuration, allowing you to roll back to an earlier state if problems occur. It doesn't back up all user data, scan for malware, or defragment.",
      "examTip": "Create restore points before making major system changes (like installing new software or drivers) to have a fallback option."
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
      "explanation": "E-waste recycling programs handle electronic waste responsibly, preventing environmental damage and ensuring data destruction. Throwing it away, selling it without wiping, or leaving it out are irresponsible and may risk data breaches.",
      "examTip": "Always recycle old computer equipment responsibly and ensure all data is securely wiped before disposal."
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
      "explanation": "BYOD (Bring Your Own Device) refers to employees using their personal devices for work purposes. The main security concern is managing and securing these devices, which are outside the direct control of the IT department, and protecting sensitive company data on them.",
      "examTip": "Implement a clear BYOD policy that addresses security, device management, and data ownership to mitigate risks."
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
      "explanation": "An antistatic wrist strap and mat provide a grounded path for static electricity, protecting sensitive components from ESD damage. Rubber gloves don't prevent static buildup, working on carpet increases static, and keeping the computer plugged in is less reliable than using proper ESD protection.",
      "examTip": "Always use proper ESD protection (wrist strap, mat) when working inside a computer."
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
      "explanation": "`tasklist` displays a list of processes running on the local or a remote computer, similar to the Processes tab in Task Manager. `schtasks` schedules tasks, user accounts are managed elsewhere, and `ipconfig` configures network settings.",
      "examTip": "Use `tasklist` to identify running processes from the command line, which is helpful for troubleshooting or scripting."
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
      "explanation": "DHCP simplifies network administration by automatically assigning IP addresses, subnet masks, default gateways, and DNS server addresses to devices. It doesn't encrypt traffic, resolve domain names, or filter traffic.",
      "examTip": "Use DHCP to simplify IP address management on your network; it avoids manual configuration and prevents IP address conflicts."
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
      "explanation": "`ping` sends ICMP echo request packets to a target host and measures the response time. This is the simplest and most direct way to test basic network reachability. `tracert` traces routes, `nslookup` resolves domain names, and `ipconfig` displays local network configuration.",
      "examTip": "`ping` is your go-to tool for quickly checking if a remote host is reachable."
    },
    {
      "id": 70,
      "question": "What does it mean if a software application or operating system is considered 'end-of-life' (EOL)?",
      "options": [
        "The software is no longer supported by the vendor, meaning no security updates, bug fixes, or technical support are provided.",
        "The software is free to use.",
        "The software is open source.",
        "The software is no longer available for purchase."
      ],
      "correctAnswerIndex": 0,
      "explanation": "EOL means the vendor has stopped supporting the product. This is a major security risk because vulnerabilities discovered after the EOL date will not be patched. While EOL software might become free or open source, that's not the defining characteristic.",
      "examTip": "Avoid using EOL software or operating systems; they pose a significant security risk due to unpatched vulnerabilities."
    },
    {
      "id": 71,
      "question": "Which of the following is an example of regulated data that requires special handling and protection?",
      "options": [
        "A user's favorite color.",
        "A user's computer's MAC address.",
        "A user's credit card number and expiration date.",
        "A user's operating system."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Credit card information is considered PII (Personally Identifiable Information) and is subject to regulations like PCI DSS. The other options are not typically considered regulated data.",
      "examTip": "Handle regulated data (PII, PHI, financial data) with extreme care and comply with relevant regulations such as GDPR, HIPAA, or PCI DSS."
    },
    {
      "id": 72,
      "question": "A user reports that they are unable to access a website. You can ping the website's IP address successfully, but you cannot access the website in a web browser. What is a LIKELY cause, besides a problem with the web server itself?",
      "options": [
        "The user's computer is not connected to the network.",
        "The user's DNS server is not resolving the website's domain name correctly.",
        "The user's web browser is not configured to use a proxy server (if required).",
        "The user's network cable is faulty."
      ],
      "correctAnswerIndex": 2,
      "explanation": "If the website is pingable by IP, DNS resolution has occurred. However, if a proxy server is required and the browser isn’t configured to use it, access may be blocked. A faulty cable would typically affect all network access.",
      "examTip": "Consider proxy server configurations when troubleshooting website access issues, especially in corporate environments."
    },
    {
      "id": 73,
      "question": "Which command in Linux is used to change the current directory?",
      "options": [
        "ls",
        "pwd",
        "cd",
        "mkdir"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`cd` (change directory) is used to navigate the file system in Linux. `ls` lists files, `pwd` shows the current directory, and `mkdir` creates a directory.",
      "examTip": "Use `cd` followed by the directory path to move between directories in the Linux terminal."
    },
    {
      "id": 74,
      "question": "What is the purpose of data backups?",
      "options": [
        "To improve the performance of a computer.",
        "To protect against data loss due to hardware failure, software corruption, accidental deletion, malware, or other disasters.",
        "To free up disk space.",
        "To encrypt sensitive data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Backups create copies of data, allowing you to restore it if the original data is lost or damaged. They don't inherently improve performance, free up disk space, or encrypt data (though backups can be encrypted).",
      "examTip": "Implement a regular backup schedule and store backups in a separate location (offsite or in the cloud) to protect against data loss."
    },
    {
      "id": 75,
      "question": "You are troubleshooting a network printer that is not printing. You have verified that the printer is powered on, connected to the network, and has paper and toner. What should you check NEXT?",
      "options": [
        "The printer's IP address configuration.",
        "The user's computer's firewall settings.",
        "The print queue on the user's computer.",
        "The network cable."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Checking the print queue on the user's computer can reveal if print jobs are stuck, paused, or encountering errors. While the IP address, firewall, and cable are possible causes, the print queue is a more direct place to check after verifying the basics.",
      "examTip": "Check the print queue for stuck or erroring print jobs when troubleshooting printing problems."
    },
    {
      "id": 76,
      "question": "Which of the following is a good practice for creating strong, secure passwords?",
      "options": [
        "Use a word found in the dictionary.",
        "Use your name or birthday.",
        "Use a combination of uppercase and lowercase letters, numbers, and symbols, and make the password at least 12 characters long.",
        "Use the same password for all your accounts."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Strong passwords are complex (using a mix of character types), long (at least 12 characters, ideally longer), and unique (not reused across accounts). Dictionary words, personal information, and reused passwords are weak and easily compromised.",
      "examTip": "Use a password manager to generate and store strong, unique passwords for all your accounts."
    },
    {
      "id": 77,
      "question": "What is the purpose of two-factor authentication (2FA)?",
      "options": [
        "To make it easier to remember your password.",
        "To add an extra layer of security by requiring two different forms of authentication (e.g., password and a code from a mobile app).",
        "To speed up the login process.",
        "To encrypt your password."
      ],
      "correctAnswerIndex": 1,
      "explanation": "2FA requires something you know (password) and something you have (phone, token) or something you are (biometric), making it much harder for attackers to gain unauthorized access even if they have your password. It doesn't make passwords easier to remember, speed up login, or encrypt the password itself.",
      "examTip": "Enable 2FA (or MFA) whenever possible, especially for important accounts like email and banking."
    },
    {
      "id": 78,
      "question": "Which Windows utility allows you to view detailed information about system hardware and software, including installed drivers, running services, and startup programs?",
      "options": [
        "Task Manager",
        "Resource Monitor",
        "System Information (msinfo32.exe)",
        "Event Viewer"
      ],
      "correctAnswerIndex": 2,
      "explanation": "System Information (msinfo32.exe) provides a comprehensive overview of the system's hardware and software configuration. Task Manager shows running processes and performance, Resource Monitor shows real-time resource usage, and Event Viewer shows system logs.",
      "examTip": "Use System Information (msinfo32.exe) to gather detailed information about a computer's hardware and software configuration."
    },
    {
      "id": 79,
      "question": "What is a 'whitelist' in the context of application control?",
      "options": [
        "A list of blocked websites.",
        "A list of approved applications that are allowed to run on a system, while all others are blocked.",
        "A list of known malware.",
        "A list of user accounts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An application whitelist is a security measure that only allows pre-approved programs to run, blocking all others. This helps prevent malware and unauthorized software from executing. The other options describe different security concepts.",
      "examTip": "Application whitelisting is a strong security control, though it may require more administrative overhead than blacklisting."
    },
    {
      "id": 80,
      "question": "You are setting up a VPN (Virtual Private Network) connection. What is the primary purpose of a VPN?",
      "options": [
        "To speed up your internet connection.",
        "To provide a secure, encrypted connection between your computer and a remote network (or the internet), protecting your data from eavesdropping.",
        "To block access to certain websites.",
        "To filter spam emails."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A VPN creates an encrypted tunnel for your internet traffic, protecting it from interception—especially on untrusted networks like public Wi-Fi. It doesn't inherently speed up connections, block websites (though some VPNs may offer that as an extra feature), or filter spam.",
      "examTip": "Use a VPN to secure your internet connection when using public Wi-Fi or accessing sensitive data remotely."
    },
    {
      "id": 81,
      "question": "Which of the following is a potential sign of a compromised computer system?",
      "options": [
        "The computer runs faster than usual.",
        "Unexpected changes to system settings, appearance of new and unknown files or programs, or unusual network activity.",
        "The computer boots up normally.",
        "The keyboard and mouse are responsive."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Unexplained changes to the system, new files or programs, and unusual network traffic can indicate a malware infection or unauthorized access. Faster performance, normal booting, and responsive peripherals are not typical signs of compromise.",
      "examTip": "Be vigilant for any unusual behavior on your computer—it could be a sign of a security breach."
    },
    {
      "id": 82,
      "question": "What is the function of the Windows Registry Editor (regedit.exe)?",
      "options": [
        "To manage user accounts and groups.",
        "To view and modify the contents of the Windows Registry.",
        "To configure network settings.",
        "To install and uninstall software."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`regedit.exe` is the tool used to directly view and edit the Windows Registry, which is a hierarchical database containing low-level settings for the operating system and installed applications.",
      "examTip": "Use extreme caution when editing the Registry; incorrect changes can cause system instability or prevent Windows from booting."
    },
    {
      "id": 83,
      "question": "Which type of malware replicates itself across a network, often without any user interaction?",
      "options": [
        "Virus",
        "Trojan horse",
        "Worm",
        "Spyware"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Worms are self-replicating malware that spread across networks by exploiting vulnerabilities. Viruses require a host file, Trojans disguise themselves as legitimate software, and spyware is used to gather information.",
      "examTip": "Keep your operating system and software up-to-date with security patches to protect against worms, which often exploit known vulnerabilities."
    },
    {
      "id": 84,
      "question": "You are troubleshooting a slow computer. You open Task Manager and notice that the CPU utilization is consistently high (close to 100%). What should you do NEXT?",
      "options": [
        "Reinstall the operating system.",
        "Identify the process(es) consuming the most CPU resources and investigate why.",
        "Add more RAM to the computer.",
        "Run Disk Cleanup."
      ],
      "correctAnswerIndex": 1,
      "explanation": "High CPU utilization indicates that one or more processes are demanding excessive processing power. The next step is to identify which processes are responsible and investigate their cause. Reinstalling the OS is too drastic; adding RAM addresses memory issues; Disk Cleanup frees disk space.",
      "examTip": "Use Task Manager to identify resource-intensive processes when troubleshooting performance problems."
    },
    {
      "id": 85,
      "question": "Which Linux command is used to display the manual page (help information) for a specific command?",
      "options": [
        "help",
        "man",
        "info",
        "whatis"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`man` (manual) displays the manual page for a command, providing detailed information about its usage, options, and syntax. `help` is typically a built-in shell command for brief help, `info` may provide more detailed documentation, and `whatis` gives a one-line description.",
      "examTip": "Use the `man` command (e.g., `man ls`) to access detailed documentation for Linux commands."
    },
    {
      "id": 86,
      "question": "What is the purpose of using strong, unique passwords for online accounts?",
      "options": [
        "To make it easier to remember your passwords.",
        "To protect your accounts from unauthorized access, even if one of your passwords is compromised.",
        "To speed up the login process.",
        "To comply with website regulations."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Unique passwords prevent a single compromised password from granting access to multiple accounts. Strong passwords make them harder to guess or crack. While regulatory compliance is important, the primary reason is security.",
      "examTip": "Never reuse passwords across different accounts; use a password manager to keep them secure."
    },
    {
      "id": 87,
      "question": "A user reports they are unable to access files on a network share. They receive an 'access denied' error message. You've verified their user account is not disabled or locked out. What is the NEXT step?",
      "options": [
        "Reboot the user's computer.",
        "Check the share and NTFS permissions on the shared folder to ensure the user or their group has the necessary access rights.",
        "Reinstall the network adapter driver.",
        "Run a virus scan."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An 'access denied' error usually indicates a permissions problem. You need to check both the share permissions (for network access) and the NTFS permissions (for file/folder access) to ensure the user has the required rights.",
      "examTip": "Carefully review both share and NTFS permissions when troubleshooting access to network shares."
    },
    {
      "id": 88,
      "question": "Which of the following is a characteristic of a 'denial-of-service' (DoS) attack?",
      "options": [
        "The attacker steals sensitive data from a server.",
        "The attacker attempts to make a network resource (website, server) unavailable to legitimate users by overwhelming it with traffic.",
        "The attacker encrypts files on a computer and demands a ransom.",
        "The attacker tricks users into revealing their passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DoS attack aims to disrupt service by flooding a target with traffic or requests, making it unavailable to legitimate users. Data theft, encryption (ransomware), and tricking users (social engineering) are different types of attacks.",
      "examTip": "DoS attacks disrupt service availability; DDoS attacks use multiple systems to amplify the impact."
    },
    {
      "id": 89,
      "question": "What is a 'security group' in Windows Active Directory?",
      "options": [
        "A collection of user accounts that are assigned the same permissions and rights.",
        "A group of computers that are managed by the same Group Policy settings.",
        "A type of firewall rule.",
        "A list of authorized users."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Security groups simplify permissions management. You assign permissions to the group, and any user account that's a member automatically inherits those permissions. The other options describe different Active Directory concepts.",
      "examTip": "Use security groups to efficiently manage permissions in an Active Directory environment; assign permissions to groups rather than individual users."
    },
    {
      "id": 90,
      "question": "Which Windows command-line tool can be used to troubleshoot network connectivity by displaying the route that packets take to reach a destination?",
      "options": [
        "ping",
        "ipconfig",
        "tracert",
        "netstat"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`tracert` (traceroute) shows the path (hops) that packets take to a destination, including the latency at each hop. This helps identify network bottlenecks. `ping` tests connectivity, `ipconfig` shows configuration, and `netstat` shows active connections.",
      "examTip": "Use `tracert` to diagnose network latency issues or to map the network path to a remote host."
    },
    {
      "id": 91,
      "question": "What is the purpose of regularly auditing security logs?",
      "options": [
        "To improve system performance.",
        "To free up disk space.",
        "To detect security breaches, unauthorized access attempts, and other suspicious activity.",
        "To back up user data."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Security logs record events, errors, and warnings related to system and network activity. Regular auditing helps detect potential security incidents and policy violations.",
      "examTip": "Implement a security log auditing process to proactively detect and respond to security threats."
    },
    {
      "id": 92,
      "question": "You are configuring a wireless router and see an option for 'WPS' (Wi-Fi Protected Setup). What is the BEST security practice regarding WPS?",
      "options": [
        "Enable WPS for easy setup.",
        "Disable WPS, as it has known security vulnerabilities.",
        "Use WPS only with WPA2 encryption.",
        "Change the default WPS PIN."
      ],
      "correctAnswerIndex": 1,
      "explanation": "WPS is notoriously vulnerable to brute-force attacks, making it easy for attackers to gain access to your wireless network. It is generally recommended to disable WPS entirely.",
      "examTip": "Disable WPS on your wireless router to improve security; the convenience is not worth the risk."
    },
    {
      "id": 93,
      "question": "What is the primary purpose of a UPS (Uninterruptible Power Supply) in a server room?",
      "options": [
        "To cool down the servers.",
        "To provide backup power to servers during a power outage, allowing for a graceful shutdown and preventing data loss.",
        "To filter network traffic.",
        "To increase network bandwidth."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A UPS provides temporary battery power to critical equipment during power outages, allowing time to save data and shut down systems properly. It doesn't cool servers, filter traffic, or increase bandwidth.",
      "examTip": "Use UPS systems for all critical servers and network devices to ensure business continuity during power failures."
    },
    {
      "id": 94,
      "question": "What is the purpose of the `gpupdate /force` command in Windows?",
      "options": [
        "To check for Windows updates.",
        "To force an immediate refresh of all Group Policy settings, both computer and user, bypassing the normal refresh interval.",
        "To update the local user's password.",
        "To restart the computer."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`gpupdate /force` forces the computer to immediately reapply all Group Policy settings, overriding the default refresh schedule. This is useful for testing policy changes or ensuring new policies are applied promptly.",
      "examTip": "Use `gpupdate /force` to ensure that Group Policy changes are applied immediately without waiting for the default refresh cycle."
    },
    {
      "id": 95,
      "question": "Which of the following is an example of PII (Personally Identifiable Information)?",
      "options": [
        "A user's favorite website.",
        "A user's computer's hostname.",
        "A user's full name, address, and date of birth.",
        "A user's web browser version."
      ],
      "correctAnswerIndex": 2,
      "explanation": "PII is any information that can be used to identify a specific individual. A combination of name, address, and date of birth is a clear example of PII. The other options are not typically considered PII on their own.",
      "examTip": "Protect PII carefully to prevent identity theft and comply with privacy regulations."
    },
    {
      "id": 96,
      "question": "A user reports that their computer is displaying a message stating that their files have been encrypted and they need to pay a ransom to get them back. What type of malware is MOST likely responsible?",
      "options": [
        "Spyware",
        "Ransomware",
        "Trojan horse",
        "Worm"
      ],
      "correctAnswerIndex": 1,
      "explanation": "This is the classic description of a ransomware attack. Ransomware encrypts files and demands payment (usually in cryptocurrency) for the decryption key. Spyware gathers information, Trojans disguise themselves as legitimate software, and worms self-replicate.",
      "examTip": "The best defense against ransomware is regular backups; do not pay the ransom without consulting security professionals."
    },
    {
      "id": 97,
      "question": "Which Linux command is used to display the contents of a text file one screen at a time, allowing you to scroll through it?",
      "options": [
        "cat",
        "more",
        "less",
        "grep"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`less` is a pager that displays file contents one screenful at a time, allowing scrolling (both forward and backward) and searching. `more` is similar but offers fewer features. `cat` displays the entire file at once, and `grep` searches for patterns within files.",
      "examTip": "Use `less` to view large text files in Linux; it provides more features than `more`."
    },
    {
      "id": 98,
      "question": "You need to copy files from one directory to another on a Windows system, preserving all file attributes and security permissions. Which command-line tool is BEST suited for this task?",
      "options": [
        "copy",
        "xcopy",
        "robocopy",
        "move"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`robocopy` (Robust File Copy) is designed for reliable and advanced file copying, including preserving permissions, attributes, timestamps, and retrying failed copies. `copy` and `xcopy` are simpler, and `move` moves files rather than copying them.",
      "examTip": "Use `robocopy` for complex file copying tasks, especially when preserving metadata and handling errors are important."
    },
    {
      "id": 99,
      "question": "What is the purpose of enabling 'Remote Desktop' on a Windows computer?",
      "options": [
        "To allow the computer to connect to the internet.",
        "To allow other users on the network to access files and printers on the computer.",
        "To allow users to connect to the computer's desktop remotely, using the Remote Desktop Protocol (RDP).",
        "To improve the computer's performance."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Enabling Remote Desktop allows users to connect to and control the computer from another location using RDP. It is not for general internet access, file/printer sharing, or performance improvement.",
      "examTip": "Enable Remote Desktop only on trusted networks and configure appropriate security settings (such as strong passwords and network-level authentication) to prevent unauthorized access."
    },
    {
      "id": 100,
      "question": "You suspect that a particular Windows service is causing system instability. How can you prevent this service from starting automatically when Windows boots?",
      "options": [
        "Delete the service's executable file.",
        "Use the Services console (services.msc) or the `net stop` and `net start` commands to manage the service, changing its startup type to 'Disabled' or 'Manual'.",
        "Rename the service in Task Manager.",
        "Uninstall the application associated with the service."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The Services console (services.msc) allows you to configure how services start. Changing the startup type to 'Disabled' prevents it from starting automatically, while 'Manual' allows it to be started as needed. Deleting the executable is dangerous, renaming in Task Manager doesn't affect startup, and uninstalling the application may be unnecessary.",
      "examTip": "Use the Services console (services.msc) or `net stop`/`net start` commands to manage Windows services and control their startup behavior."
    }
  ]
});
