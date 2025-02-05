db.tests.insertOne({
  "category": "aplus2",
  "testId": 3,
  "testName": "A+ Practice Test #3 (Easy)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A user reports that every time they boot their Windows 10 laptop connected to a projector in a conference room, the screen resolution becomes very low. They have to manually adjust it back to a higher resolution after each reboot. What is MOST likely causing this scenario?",
      "options": [
        "An outdated video card driver that cannot remember new settings",
        "Windows is detecting the external display first and applying a default resolution",
        "A damaged HDMI cable causing forced low-resolution mode",
        "The user’s account password is preventing resolution changes from saving"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Windows is detecting the external display first and applying a default resolution each time, which commonly happens if the projector's EDID (Extended Display Identification Data) reports a lower native resolution. An outdated video card driver might cause instability, but it typically wouldn't revert settings on each boot. A damaged HDMI cable would more likely cause intermittent signal or display issues, not a consistent low-resolution mode. The user’s account password has no relevance to screen resolution persistence.\nExam Tip: When external displays are involved, Windows often reverts to what the external display reports as its preferred resolution. Manually setting an extended or duplicated display mode and saving that configuration can help maintain resolution settings.",
      "examTip": "When external displays are involved, Windows often reverts to what the external display reports as its preferred resolution. Manually setting an extended or duplicated display mode and saving that configuration can help maintain resolution settings."
    },
    {
      "id": 2,
      "question": "Which of the following security practices is the BEST way to mitigate unauthorized physical access to server racks in an open office environment?",
      "options": [
        "Implement user account lockouts after three failed logins",
        "Place surveillance cameras pointing at each server rack",
        "Use a key-based lock on the server rack doors and keep keys secured",
        "Enable strong file permissions for all shared folders"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Using a key-based lock (or combination lock) for server racks is the best method to prevent physical tampering. Account lockouts prevent repeated password attempts but do not restrict direct access to hardware. Surveillance cameras can deter crime but do not physically stop someone with ill intentions. Strong file permissions are crucial for data security but do not prevent someone from directly opening a server chassis and removing drives.\nExam Tip: Physical security (locked doors, server racks, and restricted areas) is just as critical as logical security measures when protecting sensitive equipment.",
      "examTip": "Physical security (locked doors, server racks, and restricted areas) is just as critical as logical security measures when protecting sensitive equipment."
    },
    {
      "id": 3,
      "question": "Which Windows command displays all active TCP connections and listening ports, making it helpful for troubleshooting network-related issues on a local machine?",
      "options": [
        "ipconfig",
        "netstat",
        "diskpart",
        "sfc"
      ],
      "correctAnswerIndex": 1,
      "explanation": "netstat shows active TCP connections, listening ports, and other protocol statistics. ipconfig displays network interface configurations. diskpart manages disk partitions, and sfc checks the integrity of system files.\nExam Tip: Use 'netstat -a' to view all connections, 'netstat -b' to see which processes are using specific ports, and 'netstat -n' to display addresses in numeric form.",
      "examTip": "Use 'netstat -a' to view all connections, 'netstat -b' to see which processes are using specific ports, and 'netstat -n' to display addresses in numeric form."
    },
    {
      "id": 4,
      "question": "A remote employee says their Windows 11 laptop fails to connect to the company VPN after a system update. After rolling back the update, the VPN works fine again. Based on this scenario, which of the following steps is MOST likely needed next?",
      "options": [
        "Reinstall the laptop's operating system from scratch",
        "Stop applying all future Windows Updates to that laptop",
        "Identify and apply a compatible VPN client or patch for the new system update",
        "Disable the hardware firewall at the user’s home router"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Identifying and applying a compatible VPN client or a patch addresses the new system update’s conflict without permanently avoiding updates. Reinstalling the OS is an extreme step. Stopping all updates leaves the system vulnerable. Disabling a home router firewall usually does not affect a properly configured VPN unless specific ports are blocked, but that’s not the core issue here.\nExam Tip: When a system update conflicts with a VPN client, check for updated client software or known compatibility fixes to maintain secure remote access and the latest OS patches.",
      "examTip": "When a system update conflicts with a VPN client, check for updated client software or known compatibility fixes to maintain secure remote access and the latest OS patches."
    },
    {
      "id": 5,
      "question": "Which of the following antivirus deployment strategies is MOST effective for ensuring consistent protection across a company's Windows desktops?",
      "options": [
        "Allow each user to install any antivirus they prefer",
        "Deploy a centrally managed antivirus solution with scheduled updates",
        "Rely on the built-in Windows Defender without daily signature updates",
        "Use only offline, manual virus scanning once a month"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A centrally managed antivirus solution with scheduled updates ensures standardization and up-to-date protection. Allowing each user to choose their AV can create inconsistency. Using Windows Defender can be effective but only if it is properly updated and centrally managed or monitored. Offline scans once a month is insufficient for prompt threat detection.\nExam Tip: Centralized management of antivirus in a corporate setting ensures uniform policy enforcement, real-time updates, and consolidated reporting to IT administrators.",
      "examTip": "Centralized management of antivirus in a corporate setting ensures uniform policy enforcement, real-time updates, and consolidated reporting to IT administrators."
    },
    {
      "id": 6,
      "question": "A company laptop shows signs of being infected with keylogging malware. What should the IT specialist do FIRST to prevent potential data breaches?",
      "options": [
        "Delete the user’s profile immediately",
        "Replace the hard drive with a new one",
        "Disconnect the laptop from the network",
        "Install a third-party keyboard driver"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Disconnecting the laptop from the network is the first step to isolate it and prevent the malware from transmitting captured data or spreading laterally. Deleting the user’s profile does not guarantee removal of the malware. Replacing the hard drive is premature before confirming the infection type and location. Installing a new driver does not address keylogging at its source.\nExam Tip: Always isolate a system suspected of malware to contain the threat, then proceed with thorough scans, removal, and revalidation steps.",
      "examTip": "Always isolate a system suspected of malware to contain the threat, then proceed with thorough scans, removal, and revalidation steps."
    },
    {
      "id": 7,
      "question": "A technician is called to a user’s cubicle because the user’s Windows PC suddenly cannot print to a network printer in the same department. No other users are affected. Scenario: The user receives a message 'Access Denied' when trying to print. Which action should the technician take NEXT?",
      "options": [
        "Reinstall the operating system on the user’s PC",
        "Ask the user to try printing from another software application",
        "Verify the user's permissions on the printer share have not been revoked",
        "Unplug the printer and reconnect it to the network switch"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Verifying the user's permissions on the printer share is the logical next step, because an 'Access Denied' error typically indicates a permission or security issue. Reinstalling the OS is an extreme measure. Trying another software application might not help if it is truly a permission problem. Unplugging and reconnecting the printer would affect everyone if the printer was physically offline, but the scenario states only one user is affected.\nExam Tip: For shared printer issues, always confirm that the user's permissions and group memberships are correct, especially if only one user experiences denied access.",
      "examTip": "For shared printer issues, always confirm that the user's permissions and group memberships are correct, especially if only one user experiences denied access."
    },
    {
      "id": 8,
      "question": "Which Linux command is used to install packages on Debian-based distributions, making it a common method of obtaining and updating software?",
      "options": [
        "apt-get",
        "ifconfig",
        "echo",
        "chmod"
      ],
      "correctAnswerIndex": 0,
      "explanation": "apt-get is the package management command for Debian-based systems like Ubuntu, used to install, remove, and update software. ifconfig displays and configures network interfaces. echo outputs the given text or variables. chmod modifies file permissions.\nExam Tip: Newer Linux systems may use 'apt' instead of 'apt-get,' but the functionality is largely similar for installing and updating packages on Debian-based distributions.",
      "examTip": "Newer Linux systems may use 'apt' instead of 'apt-get,' but the functionality is largely similar for installing and updating packages on Debian-based distributions."
    },
    {
      "id": 9,
      "question": "Which of the following is the MOST effective method to ensure a Windows workstation automatically locks when an authorized user steps away unexpectedly?",
      "options": [
        "Enable full disk encryption",
        "Set UAC prompts to maximum",
        "Use a password-protected screensaver with a short timeout",
        "Place the workstation into the DMZ on the router"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Using a password-protected screensaver with a short timeout is the most direct and effective way to lock an unattended system after inactivity. Full disk encryption protects data at rest but does not auto-lock an active session. UAC prompts do not lock the screen. Placing the workstation in a DMZ has no relevance to physical or local session security.\nExam Tip: Automatically locking workstations when idle is a basic but powerful security measure that prevents unauthorized access in busy office environments.",
      "examTip": "Automatically locking workstations when idle is a basic but powerful security measure that prevents unauthorized access in busy office environments."
    },
    {
      "id": 10,
      "question": "A user complains that their Windows 10 PC hangs during the login process after entering credentials. Scenario: The user sees the 'Welcome' spinning wheel for several minutes. If they unplug the network cable, the login finishes. Which issue is the technician MOST likely to investigate?",
      "options": [
        "A short in the PC's Ethernet port hardware",
        "Group Policy processing delays from the domain controller",
        "Low disk space preventing user profile loading",
        "An incorrect default gateway IP on the router"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Group Policy processing delays can cause long login times, especially in domain environments, and disconnecting the network can force local cached credentials to load. A hardware short in the Ethernet port typically causes no network connectivity, not a login hang. Low disk space can slow profile loading, but removing the network cable would not likely fix that. An incorrect gateway IP might affect internet routing but typically wouldn't cause infinite login hangs.\nExam Tip: If domain logins are very slow, confirm the PC can properly reach the domain controller and that Group Policy objects are not misconfigured or excessively large.",
      "examTip": "If domain logins are very slow, confirm the PC can properly reach the domain controller and that Group Policy objects are not misconfigured or excessively large."
    },
    {
      "id": 11,
      "question": "Which file system is commonly used by macOS for its internal drives, offering improvements in snapshots and file integrity compared to older formats?",
      "options": [
        "NTFS",
        "exFAT",
        "APFS",
        "ext4"
      ],
      "correctAnswerIndex": 2,
      "explanation": "APFS (Apple File System) is commonly used on macOS internal volumes for better performance and advanced features like snapshots. NTFS is primarily Windows. exFAT is used often on removable drives for cross-platform compatibility. ext4 is primarily a Linux file system.\nExam Tip: APFS replaced HFS+ for newer macOS systems. It’s designed for SSDs but works on traditional hard drives, supporting encryption, snapshots, and space sharing natively.",
      "examTip": "APFS replaced HFS+ for newer macOS systems. It’s designed for SSDs but works on traditional hard drives, supporting encryption, snapshots, and space sharing natively."
    },
    {
      "id": 12,
      "question": "Which of the following password policies is the BEST method to prevent an attacker from repeatedly guessing user passwords via brute force?",
      "options": [
        "Setting an eight-character maximum password length",
        "Disabling password complexity requirements",
        "Enabling account lockout after several failed attempts",
        "Sharing one strong password among all users"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Enabling account lockout after a certain number of failed attempts is the best way to thwart brute-force attempts by limiting how many guesses can be made. An eight-character maximum actually weakens potential password strength. Disabling complexity requirements makes passwords easier to guess. Sharing one password for everyone is an enormous security risk.\nExam Tip: Account lockouts deter brute-force attacks, but set them with caution to avoid denial of service if legitimate users repeatedly lock themselves out.",
      "examTip": "Account lockouts deter brute-force attacks, but set them with caution to avoid denial of service if legitimate users repeatedly lock themselves out."
    },
    {
      "id": 13,
      "question": "A manager’s laptop abruptly displays a Ransomware screen demanding payment. Scenario: The manager says they clicked a strange link in an email. Which action should the technician take NEXT according to standard incident response procedures?",
      "options": [
        "Pay the ransom to quickly recover the files",
        "Delete the infected files from the user’s profile folder immediately",
        "Power down all servers in the network to prevent infiltration",
        "Isolate the laptop from the network to prevent further spread"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Isolating the laptop from the network is essential to keep the ransomware from propagating. Paying the ransom is never guaranteed to restore files and encourages further attacks. Deleting infected files could compromise potential forensic evidence. Powering down all servers is a drastic measure and may not be necessary if the infection is contained.\nExam Tip: Ransomware is a critical threat—disconnecting affected systems is priority one. Then begin investigation, reporting, and recovery steps using backups if possible.",
      "examTip": "Ransomware is a critical threat—disconnecting affected systems is priority one. Then begin investigation, reporting, and recovery steps using backups if possible."
    },
    {
      "id": 14,
      "question": "You are called to a user’s workstation that fails to power on. The user mentions there was a brief power outage earlier. What should you check FIRST?",
      "options": [
        "Replace the motherboard battery",
        "Test the power supply unit with a known-good PSU tester",
        "Reinstall the operating system",
        "Update all device drivers"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Testing the power supply unit with a PSU tester is the first logical step when a PC does not power on after a power outage. A failed or malfunctioning PSU can prevent the system from turning on entirely. Replacing the motherboard battery addresses CMOS/UEFI settings but not the primary power feed. Reinstalling the OS is impossible if the machine cannot power up. Updating drivers is also irrelevant without power.\nExam Tip: Always verify the PSU and external power connections before moving to more advanced hardware replacement. Power issues are often the simplest fix.",
      "examTip": "Always verify the PSU and external power connections before moving to more advanced hardware replacement. Power issues are often the simplest fix."
    },
    {
      "id": 15,
      "question": "Which Linux command changes file or directory permissions by specifying read (r), write (w), and execute (x) bits for the owner, group, and others?",
      "options": [
        "tar",
        "chmod",
        "ps",
        "touch"
      ],
      "correctAnswerIndex": 1,
      "explanation": "chmod modifies the access permissions (r, w, x) for owner, group, and others. tar archives and compresses files. ps lists current processes. touch updates file timestamps or creates empty files.\nExam Tip: Permissions in Linux can be set using symbolic (e.g., chmod u+w file) or numeric notation (e.g., chmod 755 file). Understand how each corresponds to read, write, and execute bits.",
      "examTip": "Permissions in Linux can be set using symbolic (e.g., chmod u+w file) or numeric notation (e.g., chmod 755 file). Understand how each corresponds to read, write, and execute bits."
    },
    {
      "id": 16,
      "question": "Which of the following options is the BEST way to ensure that an organization's sensitive data is destroyed when decommissioning old solid-state drives (SSDs)?",
      "options": [
        "Quick format each SSD before disposal",
        "Use built-in Windows 'delete' command on all sensitive files",
        "Overwrite the drive with random data multiple times using secure erase software",
        "Rename all confidential files and store them on the same disk"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Overwriting the drive using secure erase software is the best practice for SSDs because it accounts for wear-leveling and ensures data is truly removed. A quick format only clears file allocation data, not the actual contents. Deleting files alone leaves recoverable traces. Renaming files does nothing to remove data.\nExam Tip: SSD sanitization often differs from traditional hard drives due to wear-leveling. Look for dedicated 'secure erase' tools that support SSDs explicitly to guarantee data removal.",
      "examTip": "SSD sanitization often differs from traditional hard drives due to wear-leveling. Look for dedicated 'secure erase' tools that support SSDs explicitly to guarantee data removal."
    },
    {
      "id": 17,
      "question": "A user complains their macOS laptop repeatedly prompts for a Keychain password after resetting their Apple ID. Scenario: The user changed their Apple ID password online but never updated it locally. Which step will MOST likely resolve the repeated Keychain prompts?",
      "options": [
        "Performing an SMC reset on the laptop",
        "Deleting the entire user profile from the system",
        "Updating or resetting the local Keychain to match the new Apple ID password",
        "Reformatting the laptop with a new partition scheme"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Updating or resetting the local Keychain to match the new Apple ID password will resolve repeated prompts. An SMC (System Management Controller) reset deals with hardware power functions, not Keychain passwords. Deleting the user profile is extreme and unnecessary for Keychain issues. Reformatting is also excessive.\nExam Tip: The macOS Keychain is tied to the user’s credentials. If passwords fall out of sync, Keychain prompts keep appearing until they match or the Keychain is reset.",
      "examTip": "The macOS Keychain is tied to the user’s credentials. If passwords fall out of sync, Keychain prompts keep appearing until they match or the Keychain is reset."
    },
    {
      "id": 18,
      "question": "A client PC in a small office is suddenly very slow and generating unusual network traffic. The antivirus software is out of date. What should the technician do FIRST?",
      "options": [
        "Disable User Account Control",
        "Update the antivirus definitions and run a full scan",
        "Delete the suspected infected files from the hard drive",
        "Reboot into Safe Mode with Networking"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Updating antivirus definitions and running a full scan is the first step when malware is suspected, ensuring the scanning engine recognizes recent threats. Disabling UAC reduces security layers. Deleting files prematurely may remove partial infections but can overlook hidden malware. Rebooting into Safe Mode with Networking is an option for stubborn infections but typically done after updating the AV to ensure the latest definitions.\nExam Tip: Keep antivirus software current, as outdated definitions might fail to detect recent malware. Always update before scanning.",
      "examTip": "Keep antivirus software current, as outdated definitions might fail to detect recent malware. Always update before scanning."
    },
    {
      "id": 19,
      "question": "A user complains that after installing a new USB keyboard, no keystrokes are detected in Windows. The keyboard lights do not illuminate. What should you check FIRST?",
      "options": [
        "Replace the motherboard",
        "Ensure the keyboard is firmly connected or try another USB port",
        "Remove all other USB devices to avoid conflicts",
        "Reinstall the Windows operating system"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Ensuring the keyboard is firmly connected or trying another USB port is the first step to rule out a simple connection issue. Replacing the motherboard is extreme without other evidence of hardware failure. Removing all other USB devices is not necessary unless there’s a known USB bandwidth or power issue. Reinstalling Windows is not warranted for a single unrecognized keyboard.\nExam Tip: Always verify cables, ports, and connection points before suspecting deeper hardware or software problems. The simplest issue is often the cause.",
      "examTip": "Always verify cables, ports, and connection points before suspecting deeper hardware or software problems. The simplest issue is often the cause."
    },
    {
      "id": 20,
      "question": "A user states that whenever they open a specific spreadsheet, Excel crashes with no error message. Scenario: Other spreadsheets work fine. Which troubleshooting action might isolate the issue?",
      "options": [
        "Uninstall and reinstall the operating system",
        "Delete Excel’s registry keys",
        "Check the problematic file on a different computer to see if it crashes Excel",
        "Clear all Windows Update history"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Testing the file on a different computer helps determine if the spreadsheet itself is corrupted or if the user’s Excel installation is problematic. Reinstalling the entire OS for one corrupted file is too drastic. Deleting Excel’s registry keys might cause more issues. Clearing the Windows Update history is not likely related.\nExam Tip: When a single file acts up, confirm if the file is corrupted by opening it elsewhere. If it fails on all systems, the file is likely the culprit.",
      "examTip": "When a single file acts up, confirm if the file is corrupted by opening it elsewhere. If it fails on all systems, the file is likely the culprit."
    },
    {
      "id": 21,
      "question": "Which of the following features is MOST crucial to implement when creating user accounts for a new help desk team in Windows?",
      "options": [
        "Ensure all help desk accounts have local administrator rights on every workstation",
        "Use group-based security to assign only the necessary permissions",
        "Disable password requirements to expedite user access",
        "Store credentials in a public spreadsheet for quick reference"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Using group-based security to assign only necessary permissions follows the principle of least privilege and makes administration more efficient. Granting local administrator rights to all help desk staff on every machine is excessive and risky. Disabling password requirements is insecure. Storing credentials in a public spreadsheet is also a major security risk.\nExam Tip: Group-based security streamlines management and auditing. Assign privileges based on roles rather than giving each user broad permissions.",
      "examTip": "Group-based security streamlines management and auditing. Assign privileges based on roles rather than giving each user broad permissions."
    },
    {
      "id": 22,
      "question": "A technician is helping a remote client who reports that their Windows system experiences random restarts after Windows updates. Scenario: The updates installed successfully, but restarts occur even when the user is simply browsing the web. What is the NEXT reasonable step?",
      "options": [
        "Re-enable every startup process with msconfig",
        "Ask the user to send a screenshot of their desktop icons",
        "Check Event Viewer for critical errors or warnings related to hardware or drivers",
        "Disable the network adapter to see if restarts stop"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Checking Event Viewer for critical errors or warnings is the next logical step to gather clues about hardware or driver issues possibly triggered by the updates. Re-enabling every startup process might complicate the scenario if the system restarts frequently. Requesting a screenshot of desktop icons does not offer diagnostic value for random restarts. Disabling the network adapter is unrelated unless you suspect network driver conflicts, but it’s less direct than examining logs.\nExam Tip: Use Event Viewer or reliability history in Windows to identify patterns and potential driver/hardware failures after updates. Collecting data is key before more drastic measures.",
      "examTip": "Use Event Viewer or reliability history in Windows to identify patterns and potential driver/hardware failures after updates. Collecting data is key before more drastic measures."
    },
    {
      "id": 23,
      "question": "A user calls the help desk complaining that their external USB drive suddenly shows 'Access Denied' when they try to open any folder. They claim the drive worked fine yesterday. What should the technician do FIRST to troubleshoot?",
      "options": [
        "Reformat the external drive immediately",
        "Replace the USB cable with a newer model",
        "Check the drive’s security tab permissions or ownership settings",
        "Disable the antivirus software temporarily"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Checking the drive’s security permissions or ownership is the first step because corruption or changed permissions can cause an 'Access Denied' error. Reformatting erases all data, which is too drastic before confirming the cause. Replacing the USB cable may help if the drive isn’t recognized, but it wouldn’t typically cause permissions errors. Disabling the antivirus might not address a permissions or ownership mismatch.\nExam Tip: Always consider NTFS ownership and permission inheritance issues on external drives, especially if used on multiple computers or after a system reinstall.",
      "examTip": "Always consider NTFS ownership and permission inheritance issues on external drives, especially if used on multiple computers or after a system reinstall."
    },
    {
      "id": 24,
      "question": "Which Linux command shows a list of currently running processes and their process IDs (PIDs), without the interactive features of a command like 'top'?",
      "options": [
        "ls",
        "ps",
        "sudo",
        "chown"
      ],
      "correctAnswerIndex": 1,
      "explanation": "ps shows a snapshot of currently running processes and their PIDs. ls lists directory contents. sudo grants elevated privileges. chown changes file or directory ownership.\nExam Tip: 'ps aux' or 'ps -ef' are common variations to see detailed process info. Pairing ps with grep helps filter specific processes of interest (e.g., 'ps aux | grep apache').",
      "examTip": "'ps aux' or 'ps -ef' are common variations to see detailed process info. Pairing ps with grep helps filter specific processes of interest (e.g., 'ps aux | grep apache')."
    },
    {
      "id": 25,
      "question": "Which Windows tool allows you to create a scheduled task that automatically launches a specific script or program at designated times, enabling regular maintenance or reports?",
      "options": [
        "Services.msc",
        "Task Scheduler",
        "Windows Defender Firewall",
        "Disk Management"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Task Scheduler enables you to configure scripts or programs to run at specific intervals or triggers. Services.msc is for modifying Windows services. Windows Defender Firewall manages network traffic rules. Disk Management is for managing partitions and volumes.\nExam Tip: Use Task Scheduler for automating routine jobs such as running backups, system cleanups, or custom reporting scripts on a defined schedule.",
      "examTip": "Use Task Scheduler for automating routine jobs such as running backups, system cleanups, or custom reporting scripts on a defined schedule."
    }
  ]
})

db.tests.insertOne({
  "category": "aplus2",
  "testId": 3,
  "testName": "A+ Practice Test #3 (Easy)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 26,
      "question": "Which Windows feature lets administrators control which programs can run on specific user accounts by creating rules that allow or deny software execution?",
      "options": [
        "Disk Management",
        "Software Restriction Policies or AppLocker",
        "Internet Information Services (IIS)",
        "Microsoft Store"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Software Restriction Policies or AppLocker (depending on the Windows edition) allows administrators to define rules that permit or block certain applications from running. Disk Management handles storage partitions and volumes. IIS is a web server component, not a software execution control tool. The Microsoft Store is an online marketplace for Windows apps.\nExam Tip: In a managed domain environment, AppLocker rules are often more robust, while Software Restriction Policies exist in older versions. Both aim to limit unauthorized software on corporate systems.",
      "examTip": "In a managed domain environment, AppLocker rules are often more robust, while Software Restriction Policies exist in older versions. Both aim to limit unauthorized software on corporate systems."
    },
    {
      "id": 27,
      "question": "A user complains that their laptop's screen flickers after waking from sleep. Scenario: They've tried updating the graphics driver, but the issue persists. What should the technician check NEXT?",
      "options": [
        "Verify that the laptop’s BIOS/UEFI is up to date",
        "Remove all Wi-Fi network profiles",
        "Disable Windows Update entirely",
        "Perform a clean install of the operating system"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Verifying the laptop’s BIOS/UEFI is up to date is a logical next step. Sleep-wake issues can sometimes be resolved by firmware updates that address hardware power states. Removing Wi-Fi profiles is not related to display flickering. Disabling Windows Update is not recommended and won’t likely fix a hardware/firmware issue. A clean OS install should be a last resort.\nExam Tip: Always consider hardware firmware or BIOS updates when troubleshooting system power state problems, especially if driver updates don’t solve the issue.",
      "examTip": "Always consider hardware firmware or BIOS updates when troubleshooting system power state problems, especially if driver updates don’t solve the issue."
    },
    {
      "id": 28,
      "question": "Which of the following commands in macOS launches a terminal-based shell for entering text commands?",
      "options": [
        "Finder",
        "Spotlight",
        "Terminal",
        "Mission Control"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Terminal is the macOS utility that provides a shell for running text-based commands. Finder is the file management interface. Spotlight is a system-wide search feature. Mission Control manages virtual desktops and open windows.\nExam Tip: The macOS Terminal supports various shells like bash, zsh, etc. You can customize which shell is used by default under user preferences.",
      "examTip": "The macOS Terminal supports various shells like bash, zsh, etc. You can customize which shell is used by default under user preferences."
    },
    {
      "id": 29,
      "question": "A company's security policy states that only specific users can access certain file shares during business hours. Scenario: A user cannot open a file share even though they are in the correct group. Which of the following should the administrator check FIRST?",
      "options": [
        "Whether the user’s password has recently expired",
        "If the file share is using the exFAT file system",
        "Time-based access restrictions for that user account",
        "Whether the user is on the Wi-Fi network"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Time-based access restrictions should be checked first because the scenario explicitly mentions a policy limiting access to business hours. An expired password usually prevents any domain login, not just file shares. exFAT is uncommon for corporate file shares and does not handle standard Windows permission issues in this manner. Being on Wi-Fi or wired typically doesn’t cause timed restriction problems.\nExam Tip: In multi-layer policies, time-based restrictions can block user or group permissions outside specified hours. Always verify user accounts match the correct schedule settings.",
      "examTip": "In multi-layer policies, time-based restrictions can block user or group permissions outside specified hours. Always verify user accounts match the correct schedule settings."
    },
    {
      "id": 30,
      "question": "When installing a fresh copy of Windows on a GPT-partitioned drive, which firmware interface is typically required to support booting from that partition style?",
      "options": [
        "Legacy BIOS only",
        "UEFI",
        "PXE boot environment",
        "POST extension module"
      ],
      "correctAnswerIndex": 1,
      "explanation": "UEFI is required to fully support booting from a GUID Partition Table (GPT) drive without workarounds. Legacy BIOS supports MBR more naturally; GPT can be used on data drives, but booting from GPT typically requires UEFI. PXE is a network boot environment, not a firmware interface. POST extension module is not a recognized separate interface.\nExam Tip: UEFI + GPT allows larger partitions and more modern boot features compared to BIOS + MBR, which has partition and size limitations.",
      "examTip": "UEFI + GPT allows larger partitions and more modern boot features compared to BIOS + MBR, which has partition and size limitations."
    },
    {
      "id": 31,
      "question": "Which Windows command is used to copy entire directories, subdirectories, and files while retaining file attributes and can be considered more advanced than the basic 'copy' command?",
      "options": [
        "robocopy",
        "xcopy",
        "move",
        "net use"
      ],
      "correctAnswerIndex": 0,
      "explanation": "robocopy (robust copy) is designed for high-performance file and directory copying, preserving attributes and NTFS permissions with the right switches. xcopy also copies directories but lacks some advanced features of robocopy. move simply moves files/folders, not copying them with all attributes. net use maps network drives.\nExam Tip: robocopy is frequently used in scripts for backups or migrations due to its ability to mirror directories and handle network interruptions gracefully.",
      "examTip": "robocopy is frequently used in scripts for backups or migrations due to its ability to mirror directories and handle network interruptions gracefully."
    },
    {
      "id": 32,
      "question": "A user complains that after installing a new third-party software, their Windows PC refuses to boot. Scenario: The system gets stuck at the manufacturer logo. Which FIRST step might help isolate the problem?",
      "options": [
        "Reimage the system from the latest full backup",
        "Enter Safe Mode or use 'msconfig' to disable the new software from startup",
        "Edit the Windows Registry to remove all references to the new software",
        "Restore default BIOS settings"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Entering Safe Mode or using msconfig to disable the startup process for the new software is the first step in diagnosing a boot hang. Reimaging is a broader solution that may be premature if it wipes out all changes. Editing the Registry without Safe Mode access can be risky if you cannot even boot. Restoring BIOS defaults typically won’t remove a software-level conflict.\nExam Tip: If Windows cannot start normally, Safe Mode or msconfig are key tools to remove or disable problematic software or drivers.",
      "examTip": "If Windows cannot start normally, Safe Mode or msconfig are key tools to remove or disable problematic software or drivers."
    },
    {
      "id": 33,
      "question": "On a Linux system, which command is used to display the path of the current working directory?",
      "options": [
        "pwd",
        "ls",
        "cd",
        "man"
      ],
      "correctAnswerIndex": 0,
      "explanation": "pwd (print working directory) displays the full path of the current directory. ls lists files/folders, cd changes directories, and man displays help pages.\nExam Tip: Combining pwd, ls, and cd is fundamental for navigation in a Linux shell. Always confirm your working directory to avoid accidental changes in the wrong place.",
      "examTip": "Combining pwd, ls, and cd is fundamental for navigation in a Linux shell. Always confirm your working directory to avoid accidental changes in the wrong place."
    },
    {
      "id": 34,
      "question": "A user notices that their login screen appears in a different language after changing some localization settings in Windows. Scenario: They want the login screen to match their normal display language. Which area can fix system-wide language settings on Windows?",
      "options": [
        "Control Panel > System > Device Manager",
        "Control Panel > Clock and Region > Region > Administrative tab",
        "Settings > Personalization > Colors",
        "Settings > Update & Security > Windows Security"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Control Panel > Clock and Region > Region > Administrative tab allows you to change system locale settings that affect the login screen language. Device Manager manages hardware drivers, not language. Personalization > Colors modifies theme colors. Update & Security > Windows Security is for antivirus and OS updates, not languages.\nExam Tip: Language changes for the entire system, including the login screen, often require adjusting region settings in both Region and Administrative sections and a system reboot.",
      "examTip": "Language changes for the entire system, including the login screen, often require adjusting region settings in both Region and Administrative sections and a system reboot."
    },
    {
      "id": 35,
      "question": "Which approach should a technician use when disposing of old company PCs to ensure no data can be recovered from the internal drives?",
      "options": [
        "Run Disk Cleanup on each PC",
        "Physically destroy the drives or securely wipe them",
        "Keep the PCs powered on for one week before disposal",
        "Remove and donate the motherboards but leave drives intact"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Physically destroying or securely wiping the drives ensures data cannot be recovered. Simply running Disk Cleanup only removes temporary files. Leaving the PCs powered on does nothing to erase data. Removing motherboards but leaving drives intact still leaves the data vulnerable.\nExam Tip: Many organizations use professional shredding services or NIST-compliant wipe methods to ensure no trace of data remains on decommissioned drives.",
      "examTip": "Many organizations use professional shredding services or NIST-compliant wipe methods to ensure no trace of data remains on decommissioned drives."
    },
    {
      "id": 36,
      "question": "What is the command line tool in Windows for managing disk partitions, such as creating and deleting volumes on a drive?",
      "options": [
        "tracert",
        "diskpart",
        "net user",
        "format"
      ],
      "correctAnswerIndex": 1,
      "explanation": "diskpart is the Windows command line utility for managing partitions and volumes on a disk. tracert traces network routes, net user manages user accounts, and format initializes or reformats a disk partition with a specified file system but doesn't manage partition structures.\nExam Tip: Use diskpart carefully—accidentally choosing the wrong disk or volume can destroy data. Always confirm the active selection with 'list disk' or 'list volume'.",
      "examTip": "Use diskpart carefully—accidentally choosing the wrong disk or volume can destroy data. Always confirm the active selection with 'list disk' or 'list volume'."
    },
    {
      "id": 37,
      "question": "A user complains that their new external USB hard drive is not showing up in Windows Explorer. Scenario: The drive is detected in Device Manager, but it has no drive letter. Which step might the technician take FIRST to fix this?",
      "options": [
        "Use Disk Management to assign a drive letter",
        "Replace the SATA cable",
        "Copy USB drivers from another PC",
        "Disable the integrated firewall"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Assigning a drive letter in Disk Management is the logical first step if the drive is visible but not mounted to any path. Replacing the SATA cable is irrelevant because the drive is external USB. Copying USB drivers is not necessary if the drive is recognized in Device Manager. The firewall generally does not affect local drive mapping.\nExam Tip: When external drives are detected but not visible in Explorer, check Disk Management for an uninitialized or letterless partition.",
      "examTip": "When external drives are detected but not visible in Explorer, check Disk Management for an uninitialized or letterless partition."
    },
    {
      "id": 38,
      "question": "Which command in Windows repairs the boot sector on the system partition, often used after 'bootrec /fixmbr' if the system still fails to boot?",
      "options": [
        "bootrec /fixboot",
        "sfc /scannow",
        "chkdsk /r",
        "gpupdate /force"
      ],
      "correctAnswerIndex": 0,
      "explanation": "bootrec /fixboot writes a new boot sector to the system partition. sfc /scannow checks for and restores corrupted system files. chkdsk /r locates bad sectors and recovers readable information. gpupdate /force applies new or changed Group Policy settings.\nExam Tip: Use 'bootrec /fixmbr' to repair the Master Boot Record and 'bootrec /fixboot' for the partition boot sector. 'bootrec /rebuildbcd' can rebuild the entire boot configuration data.",
      "examTip": "Use 'bootrec /fixmbr' to repair the Master Boot Record and 'bootrec /fixboot' for the partition boot sector. 'bootrec /rebuildbcd' can rebuild the entire boot configuration data."
    },
    {
      "id": 39,
      "question": "A technician logs into a Windows PC and notices the user is a local Administrator. The user regularly installs unauthorized software. Which is the MOST straightforward method to reduce this risk?",
      "options": [
        "Set the system to automatically format after every login",
        "Force the BIOS to only allow signed executables",
        "Demote the user to a standard account and use a separate admin account for installs",
        "Create a script that uninstalls all non-Microsoft applications daily"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Demoting the user to a standard account and having a separate admin account is the best approach for least privilege. Forcing the BIOS to only allow signed executables is not standard practice for user-level software. Automatic formatting after each login is impractical. Uninstalling all non-Microsoft applications daily would be disruptive and not address the root problem of privilege.\nExam Tip: Maintain separate standard and administrative accounts. Only use the latter when necessary for installations or configuration changes.",
      "examTip": "Maintain separate standard and administrative accounts. Only use the latter when necessary for installations or configuration changes."
    },
    {
      "id": 40,
      "question": "On a Windows 10 system, what is the purpose of the 'gpupdate' command?",
      "options": [
        "It updates Group Policy settings on the local or domain-joined machine",
        "It scans the system files for corruption",
        "It launches the graphical firewall configuration interface",
        "It initiates a BIOS update"
      ],
      "correctAnswerIndex": 0,
      "explanation": "gpupdate refreshes Group Policy settings from the local GPO or domain controllers. sfc (System File Checker) scans system files. Windows Defender Firewall is configured through Control Panel or 'wf.msc'. BIOS updates are manufacturer-specific and not triggered by gpupdate.\nExam Tip: Use 'gpupdate /force' to immediately reapply all policies. Without parameters, gpupdate only refreshes those changed since the last cycle.",
      "examTip": "Use 'gpupdate /force' to immediately reapply all policies. Without parameters, gpupdate only refreshes those changed since the last cycle."
    },
    {
      "id": 41,
      "question": "Which Windows service is primarily responsible for providing file and print sharing support for network clients, using protocols like SMB?",
      "options": [
        "Print Spooler",
        "Server service",
        "DHCP Client",
        "Remote Desktop Services"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The Server service in Windows allows other machines to access file shares and printers via SMB. Print Spooler manages local and network print jobs but is not the main service providing the share itself. DHCP Client is for obtaining IP configurations. Remote Desktop Services manages RDP sessions.\nExam Tip: If file and print shares stop working, verify the Server service is running alongside File and Printer Sharing settings on the network adapter.",
      "examTip": "If file and print shares stop working, verify the Server service is running alongside File and Printer Sharing settings on the network adapter."
    },
    {
      "id": 42,
      "question": "A user installed an unknown browser extension and is now experiencing numerous unwanted pop-up ads. Scenario: The user’s antivirus scan is clean. What is the FIRST practical step to remove the source of the ads?",
      "options": [
        "Reinstall the operating system completely",
        "Disable or remove the suspicious extension from the browser",
        "Replace the network router and configure new Wi-Fi credentials",
        "Update the system BIOS to the latest version"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Disabling or removing the suspicious extension is the immediate step to stop pop-up ads if the antivirus indicates no broader system infection. Reinstalling the entire OS is too drastic for a browser-related issue. Replacing the router does not affect a malicious extension. Updating the BIOS is unrelated to ad pop-ups.\nExam Tip: Browser hijackers often come in the form of malicious extensions. Removing them and resetting the browser is frequently enough to resolve ad injection.",
      "examTip": "Browser hijackers often come in the form of malicious extensions. Removing them and resetting the browser is frequently enough to resolve ad injection."
    },
    {
      "id": 43,
      "question": "Which straightforward command-line utility in Windows is used to display or modify the network configuration of the local machine, including IP address and DNS settings?",
      "options": [
        "ipconfig",
        "ping",
        "dir",
        "chkdsk"
      ],
      "correctAnswerIndex": 0,
      "explanation": "ipconfig displays or refreshes IP configuration for network adapters, including DNS and DHCP details. ping checks connectivity to a host. dir lists files in a directory. chkdsk checks disk integrity.\nExam Tip: 'ipconfig /all' shows detailed adapter info, while 'ipconfig /release' and 'ipconfig /renew' reacquire IP addresses from DHCP. For DNS issues, 'ipconfig /flushdns' clears the cache.",
      "examTip": "'ipconfig /all' shows detailed adapter info, while 'ipconfig /release' and 'ipconfig /renew' reacquire IP addresses from DHCP. For DNS issues, 'ipconfig /flushdns' clears the cache."
    },
    {
      "id": 44,
      "question": "A Windows user consistently receives a 'Low Virtual Memory' warning while running memory-intensive software. Which of the following steps should the user consider FIRST?",
      "options": [
        "Disabling the page file entirely",
        "Increasing the size of the virtual memory (page file)",
        "Disconnecting from the internet to free up memory",
        "Removing administrative privileges from their account"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Increasing the size of the virtual memory (page file) or setting it to 'system managed' is the first practical step to handle memory-intensive tasks. Disabling the page file would worsen low memory issues. Disconnecting from the internet does not significantly reduce memory usage for local processes. Removing admin privileges does not solve the low-memory warnings.\nExam Tip: If physical RAM is insufficient, Windows uses disk space (page file) as virtual memory. Ensuring the page file is large enough can mitigate out-of-memory errors.",
      "examTip": "If physical RAM is insufficient, Windows uses disk space (page file) as virtual memory. Ensuring the page file is large enough can mitigate out-of-memory errors."
    },
    {
      "id": 45,
      "question": "Which of the following is a recommended practice to ensure a Windows operating system can be quickly recovered if the primary boot partition becomes unbootable?",
      "options": [
        "Disabling System Restore to save disk space",
        "Maintaining a recovery partition or bootable recovery media",
        "Relying solely on the default boot configuration in BIOS",
        "Forcing the system to start in Safe Mode at all times"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Maintaining a dedicated recovery partition or having bootable recovery media (USB/DVD) ensures you can perform repairs if the main OS partition fails. Disabling System Restore removes a useful recovery option. Relying solely on default BIOS boot settings does not help if the OS partition is corrupted. Forcing Safe Mode permanently is not a typical solution for major boot issues.\nExam Tip: Windows installations often come with or can create a recovery partition or media. This is crucial for startup repairs, system resets, and advanced troubleshooting.",
      "examTip": "Windows installations often come with or can create a recovery partition or media. This is crucial for startup repairs, system resets, and advanced troubleshooting."
    },
    {
      "id": 46,
      "question": "A technician needs to remove a stubborn piece of malware that prevents installation of new security software on a Windows machine. What should the technician do FIRST?",
      "options": [
        "Rename the Windows folder to isolate malware",
        "Boot into Safe Mode or a preinstallation environment to perform the malware scan",
        "Delete all scheduled tasks in Task Scheduler",
        "Open multiple copies of Task Manager to attempt to kill processes"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Booting into Safe Mode or a preinstallation environment allows loading minimal drivers or an offline OS environment, preventing the malware from actively blocking the security software. Renaming the Windows folder can cause major system issues. Deleting all scheduled tasks is indiscriminate and might break legitimate tasks. Opening multiple Task Managers is not a reliable method.\nExam Tip: Some malware resists removal in normal boot. Offline scans or Safe Mode can bypass the malware’s self-defense routines for more effective cleanup.",
      "examTip": "Some malware resists removal in normal boot. Offline scans or Safe Mode can bypass the malware’s self-defense routines for more effective cleanup."
    },
    {
      "id": 47,
      "question": "A user needs to encrypt a single sensitive file on their NTFS-formatted Windows drive, but cannot enable full BitLocker on the computer. Which feature is BEST for this scenario?",
      "options": [
        "Diskpart scripting",
        "System File Checker",
        "Encrypting File System (EFS)",
        "User Account Control (UAC)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Encrypting File System (EFS) allows per-file or per-folder encryption on NTFS volumes. Diskpart manages disk partitions, not encryption. System File Checker verifies and repairs system files, while UAC prompts for privilege elevations but does not encrypt files.\nExam Tip: EFS is tied to a user’s account credentials. If the user’s profile or keys are lost, data may be irrecoverable. Always back up encryption certificates.",
      "examTip": "EFS is tied to a user’s account credentials. If the user’s profile or keys are lost, data may be irrecoverable. Always back up encryption certificates."
    },
    {
      "id": 48,
      "question": "Which of the following straightforward commands in Windows displays the version, build number, and edition of the operating system currently in use?",
      "options": [
        "winver",
        "hostname",
        "msinfo32",
        "ipconfig /version"
      ],
      "correctAnswerIndex": 0,
      "explanation": "winver opens a window showing detailed information about the Windows version, build, and edition. hostname shows the computer’s name. msinfo32 (System Information) provides more expansive hardware and software details, but not as quickly for the version build. ipconfig /version is not a valid parameter and wouldn’t show OS version.\nExam Tip: 'winver' is a quick way to confirm exact build numbers. msinfo32 can also reveal additional hardware and OS details if needed.",
      "examTip": "'winver' is a quick way to confirm exact build numbers. msinfo32 can also reveal additional hardware and OS details if needed."
    },
    {
      "id": 49,
      "question": "A user complains about a newly installed program automatically launching at startup, slowing down their PC. Which Windows tool allows them to directly manage startup items and disable the unwanted application?",
      "options": [
        "System Configuration (msconfig)",
        "Event Viewer",
        "Disk Cleanup",
        "Remote Desktop Connection"
      ],
      "correctAnswerIndex": 0,
      "explanation": "System Configuration (msconfig) includes a Startup tab (on older Windows versions) or it redirects to Task Manager’s Startup tab on newer versions. This is where startup items can be enabled or disabled. Event Viewer checks logs, Disk Cleanup frees disk space, and Remote Desktop Connection is for remote access.\nExam Tip: On Windows 10 and later, the Startup tab in Task Manager is the primary place to manage startup items, but msconfig can also route you there.",
      "examTip": "On Windows 10 and later, the Startup tab in Task Manager is the primary place to manage startup items, but msconfig can also route you there."
    },
    {
      "id": 50,
      "question": "Which of the following is MOST important when implementing BYOD (Bring Your Own Device) policies to maintain company data security on employee-owned smartphones?",
      "options": [
        "Ensuring that the devices have screen lock or passcode enabled",
        "Allowing free access to all network shares",
        "Disabling device encryption to simplify remote management",
        "Enforcing mandatory guest account usage on each phone"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Enforcing a screen lock or passcode is critical on employee-owned devices to protect corporate data in case of device loss or theft. Allowing free access to all shares poses a security risk. Disabling device encryption weakens security. Smartphones do not typically have a 'guest account' concept relevant to BYOD policies.\nExam Tip: BYOD policies should mandate passcodes, remote wipe, and possibly MDM (Mobile Device Management) solutions to protect corporate data on personal devices.",
      "examTip": "BYOD policies should mandate passcodes, remote wipe, and possibly MDM (Mobile Device Management) solutions to protect corporate data on personal devices."
    }
  ]
})

