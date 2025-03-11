db.tests.insertOne({
  "category": "aplus2",
  "testId": 7,
  "testName": "CompTIA A+ Core 2 (1102) Practice Test #7 (Challenging)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A technician is troubleshooting a Windows 10 system that fails to boot after enabling BitLocker. The user did not back up the recovery key. What is the BEST option to regain access to the system without data loss?",
      "options": [
        "Attempt recovery using the BitLocker recovery key from Azure AD if the device is domain-joined.",
        "Perform a clean installation of Windows 10 and restore data from backup.",
        "Disable BitLocker from Windows Recovery Environment (WinRE).",
        "Reset the TPM chip in BIOS/UEFI settings."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If the system is domain-joined, the BitLocker recovery key may be stored in Azure AD, providing the easiest method to regain access without data loss. A clean installation would result in data loss unless backups exist. Disabling BitLocker from WinRE requires the recovery key, which isn’t available. Resetting the TPM chip would make recovery impossible as it clears encryption keys.",
      "examTip": "Always ensure BitLocker recovery keys are backed up to a secure location before enabling encryption."
    },
    {
      "id": 2,
      "question": "A Linux administrator needs to diagnose why a user cannot SSH into a server. Network connectivity is confirmed. Which command will BEST provide real-time logs for SSH connection attempts?",
      "options": [
        "tail -f /var/log/auth.log",
        "systemctl status ssh",
        "netstat -tuln",
        "journalctl -u ssh"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The tail -f /var/log/auth.log command shows real-time authentication logs, including SSH connection attempts. systemctl status ssh only shows service status, not detailed logs. netstat -tuln lists open ports but doesn’t provide authentication logs. journalctl -u ssh provides historical logs but not real-time updates.",
      "examTip": "Monitor /var/log/auth.log for real-time authentication attempts when troubleshooting SSH access issues in Linux."
    },
    {
      "id": 3,
      "question": "A user reports that after a recent Windows update, they receive 'Boot Configuration Data (BCD) missing' errors. What is the FIRST command a technician should run to attempt a repair?",
      "options": [
        "bootrec /rebuildbcd",
        "chkdsk /r",
        "sfc /scannow",
        "bcdedit /set {current} recoveryenabled Yes"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The bootrec /rebuildbcd command rebuilds the Boot Configuration Data, resolving missing BCD errors. chkdsk /r repairs disk errors but doesn’t address BCD issues. sfc /scannow repairs system files but not boot configurations. bcdedit modifies BCD settings but won’t recreate missing entries.",
      "examTip": "Use bootrec /rebuildbcd when encountering BCD-related boot errors after Windows updates."
    },
    {
      "id": 4,
      "question": "A company’s users are experiencing slow authentication when connecting to internal services. The network team suspects DNS resolution issues. Which tool can BEST verify if DNS latency is causing the problem?",
      "options": [
        "nslookup with internal hostnames",
        "ping the internal DNS server",
        "tracert to the authentication server",
        "ipconfig /all on user machines"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Using nslookup with internal hostnames tests DNS resolution directly and can reveal latency issues. ping checks connectivity but not DNS performance. tracert shows network path latency but doesn’t focus on DNS. ipconfig /all provides configuration details without testing DNS performance.",
      "examTip": "For suspected DNS issues, nslookup provides direct insight into resolution speed and accuracy."
    },
    {
      "id": 5,
      "question": "A user suspects their Windows 10 machine has been compromised due to slow performance and unauthorized software installations. What should the technician do FIRST to mitigate potential damage?",
      "options": [
        "Disconnect the device from the network.",
        "Run a full malware scan using updated definitions.",
        "Boot the system into Safe Mode for further analysis.",
        "Review installed applications for suspicious software."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Disconnecting the device from the network immediately prevents malware from communicating externally or spreading. Running a malware scan is essential but should follow isolation. Booting into Safe Mode helps analysis but doesn’t prevent external communication. Reviewing installed applications is important but secondary to isolation.",
      "examTip": "Isolate suspected compromised systems from the network first to contain potential threats."
    },
    {
      "id": 6,
      "question": "A Windows 10 user cannot access secure websites but can access standard HTTP sites. The system time and date are correct. What is the MOST likely cause of this issue?",
      "options": [
        "Corrupted or outdated root certificates.",
        "Misconfigured proxy settings.",
        "Outdated web browser version.",
        "Faulty network interface driver."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Corrupted or outdated root certificates prevent secure connections by causing SSL/TLS errors. Misconfigured proxies usually block all web traffic, not just HTTPS. Outdated browsers could cause compatibility issues but wouldn’t specifically block HTTPS. Network driver issues would affect all network access, not selectively HTTPS traffic.",
      "examTip": "SSL issues on specific devices often stem from outdated or missing root certificates—ensure timely updates."
    },
    {
      "id": 7,
      "question": "A technician needs to secure a small office wireless network against brute-force attacks while maintaining ease of access for employees. Which security method provides the BEST balance of security and usability?",
      "options": [
        "WPA3-Personal with a strong passphrase.",
        "WEP with a complex key.",
        "WPA2-Enterprise with RADIUS authentication.",
        "Disabling SSID broadcast."
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA3-Personal offers the strongest security for SOHO environments while using a single passphrase, balancing security and ease of use. WEP is outdated and insecure. WPA2-Enterprise with RADIUS provides robust security but adds complexity unsuitable for small offices. Disabling SSID broadcast provides minimal security benefits and can complicate legitimate access.",
      "examTip": "Use WPA3-Personal for SOHO networks to achieve strong encryption with simple user management."
    },
    {
      "id": 8,
      "question": "A Linux administrator needs to terminate a process consuming excessive CPU resources without rebooting the server. Which command should be used?",
      "options": [
        "kill -9 <PID>",
        "top",
        "ps aux",
        "nice -n 10 <PID>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The kill -9 command forcefully terminates processes by PID. top and ps aux provide process details but do not terminate processes. The nice command adjusts process priority but doesn’t stop it.",
      "examTip": "Use kill -9 cautiously to force-stop unresponsive processes when graceful termination fails."
    },
    {
      "id": 9,
      "question": "A technician needs to configure file sharing between a Linux server and Windows clients on the same network. Which service must be installed and configured on the Linux server?",
      "options": [
        "Samba",
        "NFS",
        "Apache",
        "MySQL"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Samba enables file and printer sharing between Linux and Windows systems using the SMB protocol. NFS is more suitable for Unix/Linux file sharing. Apache serves web content. MySQL is a database management system.",
      "examTip": "Samba bridges Linux and Windows file-sharing needs by implementing SMB/CIFS protocols."
    },
    {
      "id": 10,
      "question": "A user’s Windows 10 computer displays 'Access Denied' when attempting to delete a file they created. The file is on an NTFS partition. What is the MOST likely cause?",
      "options": [
        "Ownership of the file has changed to another user or system process.",
        "The user lacks write permissions on the file’s directory.",
        "The file is encrypted using EFS, and the encryption key is missing.",
        "The disk is mounted as read-only due to file system errors."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If file ownership changes, even the creator may lose access rights. Write permission issues typically prevent file creation, not deletion of existing files. EFS encryption issues result in access errors, not just deletion issues. Read-only disk mounts would block all write operations, not selectively deny access.",
      "examTip": "Check file ownership and permissions when users encounter unexpected 'Access Denied' errors."
    },
    {
      "id": 11,
      "question": "A Windows 10 laptop connected to a corporate domain is unable to apply group policies. Which command should be used to force a group policy update and view the results?",
      "options": [
        "gpupdate /force && gpresult /r",
        "net user domain",
        "sfc /scannow",
        "chkdsk /f"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The gpupdate /force command refreshes group policies, and gpresult /r shows applied policies. net user domain manages user accounts. sfc /scannow checks for system file integrity issues. chkdsk /f fixes file system errors but doesn’t affect group policies.",
      "examTip": "Combine gpupdate and gpresult for efficient troubleshooting of group policy issues in domain environments."
    },
    {
      "id": 12,
      "question": "A technician suspects DNS issues after users report slow website loading. Which command will provide detailed DNS resolution steps for a given domain?",
      "options": [
        "nslookup",
        "tracert",
        "ipconfig /flushdns",
        "netstat -an"
      ],
      "correctAnswerIndex": 0,
      "explanation": "nslookup queries DNS servers to show resolution details. tracert identifies network routing paths. ipconfig /flushdns clears local DNS cache but doesn’t analyze resolution. netstat -an shows active connections without DNS resolution details.",
      "examTip": "Use nslookup for detailed DNS resolution insights when troubleshooting slow web access."
    },
    {
      "id": 13,
      "question": "A user’s Windows 10 system boots to a black screen with a blinking cursor. The technician suspects a missing or corrupted bootloader. Which command is BEST to attempt a repair?",
      "options": [
        "bootrec /fixboot",
        "bcdedit /export C:\\bcdbackup",
        "diskpart",
        "sfc /scannow"
      ],
      "correctAnswerIndex": 0,
      "explanation": "bootrec /fixboot repairs boot sector issues responsible for missing bootloader errors. bcdedit /export backs up boot configurations but doesn’t repair them. diskpart manages partitions. sfc /scannow checks system files but not the bootloader.",
      "examTip": "When bootloader issues arise, bootrec /fixboot is the primary tool for restoration."
    },
    {
      "id": 14,
      "question": "A macOS user needs to enable full-disk encryption to protect sensitive data. Which built-in tool should they use?",
      "options": [
        "FileVault",
        "Disk Utility",
        "Keychain Access",
        "Time Machine"
      ],
      "correctAnswerIndex": 0,
      "explanation": "FileVault provides full-disk encryption on macOS, protecting data from unauthorized access. Disk Utility manages storage but doesn’t encrypt the entire disk. Keychain Access stores passwords and certificates. Time Machine handles backups, not encryption.",
      "examTip": "Enable FileVault on macOS for seamless full-disk encryption without third-party tools."
    },
    {
      "id": 15,
      "question": "A Linux user needs to identify the IP address assigned to their system’s primary network interface. Which command provides this information?",
      "options": [
        "ip addr show",
        "ifconfig -a",
        "hostname -I",
        "netstat -r"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The ip addr show command displays IP address assignments and is preferred in modern distributions. ifconfig -a provides similar information but is deprecated. hostname -I shows only the IP address without interface details. netstat -r displays routing tables, not interface addresses.",
      "examTip": "Use ip addr show in modern Linux systems for detailed network interface information."
    },
    {
      "id": 16,
      "question": "A Windows 10 system fails to install updates and shows error 0x80070002. What is the BEST initial troubleshooting step?",
      "options": [
        "Run the Windows Update Troubleshooter.",
        "Perform a clean boot of the system.",
        "Delete the SoftwareDistribution folder.",
        "Check Windows Event Viewer for update errors."
      ],
      "correctAnswerIndex": 0,
      "explanation": "The Windows Update Troubleshooter automatically detects and resolves common update errors, including 0x80070002. A clean boot isolates software conflicts but is more advanced. Deleting the SoftwareDistribution folder forces update re-download but should follow less invasive steps. Event Viewer analysis is useful but secondary to automated tools.",
      "examTip": "Start with built-in troubleshooters for Windows Update errors before attempting manual fixes."
    },
    {
      "id": 17,
      "question": "A user complains that their Android smartphone cannot connect to the corporate Wi-Fi after a recent security upgrade requiring WPA3. Other devices connect fine. What is the MOST likely cause?",
      "options": [
        "The Android device does not support WPA3 encryption.",
        "The corporate Wi-Fi password is incorrect.",
        "The access point is out of range for the device.",
        "MAC filtering is enabled for the network."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Many older Android devices lack WPA3 support, causing connection failures. An incorrect password would prompt authentication errors. An out-of-range access point would prevent all devices from connecting, not just one. MAC filtering would block the device regardless of encryption protocol.",
      "examTip": "Always verify device compatibility with the latest Wi-Fi encryption protocols when connectivity issues arise."
    },
    {
      "id": 18,
      "question": "A user reports that their Windows system cannot access internal web applications using hostnames, but IP access works. Which command will MOST LIKELY resolve the issue?",
      "options": [
        "ipconfig /flushdns",
        "netsh winsock reset",
        "nslookup <hostname>",
        "tracert <hostname>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "ipconfig /flushdns clears the local DNS resolver cache, often resolving hostname access issues. netsh winsock reset resets the Winsock catalog but is unrelated to DNS caching. nslookup tests DNS resolution but doesn’t fix issues. tracert maps network routes but doesn’t affect DNS resolution.",
      "examTip": "Flush the DNS cache first when hostname resolution fails but IP connectivity remains functional."
    },
    {
      "id": 19,
      "question": "A technician needs to prevent a Windows 10 user from installing unauthorized software without affecting system updates. Which tool provides the MOST effective solution?",
      "options": [
        "AppLocker via Local Security Policy",
        "Windows Defender Firewall",
        "Group Policy Preferences",
        "Task Scheduler"
      ],
      "correctAnswerIndex": 0,
      "explanation": "AppLocker provides application control, preventing unauthorized installations while allowing system updates. Windows Defender Firewall manages network traffic, not application permissions. Group Policy Preferences manage user configurations but aren’t focused on software restrictions. Task Scheduler automates tasks but doesn’t control installations.",
      "examTip": "Use AppLocker for precise control over permitted applications in Windows enterprise environments."
    },
    {
      "id": 20,
      "question": "A Windows 10 user is experiencing sluggish performance. The Task Manager shows high disk usage by the 'Windows Search' process. What is the BEST way to reduce the impact without disabling search functionality?",
      "options": [
        "Modify indexing options to exclude non-essential locations.",
        "Disable Windows Search service entirely.",
        "Upgrade the hard drive to an SSD.",
        "Perform a system restore to a previous state."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Modifying indexing options reduces disk usage by limiting search indexing to essential areas. Disabling the service removes search functionality. Upgrading to an SSD improves performance but is a hardware solution. System restore may not resolve indexing performance issues if indexing settings remain unchanged.",
      "examTip": "Adjust indexing options for optimal balance between search performance and system resource usage."
    },
    {
      "id": 21,
      "question": "A user reports that after enabling Secure Boot on their Windows 10 PC, the system fails to boot. What is the MOST likely cause of this issue?",
      "options": [
        "The operating system does not have a valid digital signature for Secure Boot.",
        "The TPM module was disabled in the BIOS settings.",
        "The system partition was formatted as FAT32 instead of NTFS.",
        "Fast Boot was enabled along with Secure Boot, causing a conflict."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Secure Boot requires a valid, signed operating system bootloader. If the OS or bootloader lacks a valid digital signature, the system will not boot. The TPM module handles encryption keys for BitLocker, not Secure Boot validation. Partition formatting affects file system compatibility but doesn’t cause Secure Boot failures. Fast Boot reduces boot times but doesn’t interfere with Secure Boot functionality.",
      "examTip": "Always verify Secure Boot compatibility and digital signatures before enabling the feature in BIOS."
    },
    {
      "id": 22,
      "question": "A technician is troubleshooting a Linux server experiencing slow SSH login times. Network latency is ruled out. Which configuration file is MOST likely misconfigured, causing the delay?",
      "options": [
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/fstab",
        "/etc/ssh/sshd_config"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Slow SSH logins can occur when the server attempts DNS resolution of the client’s IP. If /etc/hosts is misconfigured, the server may wait for DNS timeouts. /etc/resolv.conf manages DNS settings but would affect broader connectivity, not just SSH. /etc/fstab handles file system mounting at boot. /etc/ssh/sshd_config manages SSH settings but wouldn’t cause DNS-related delays unless authentication methods are misconfigured.",
      "examTip": "Ensure accurate hostname resolution settings in /etc/hosts to prevent SSH login delays."
    },
    {
      "id": 23,
      "question": "A user’s Windows 10 machine displays frequent BSOD errors after a recent graphics driver update. What is the BEST next step to resolve the issue without data loss?",
      "options": [
        "Roll back the driver from Device Manager.",
        "Boot into Safe Mode and perform a system restore.",
        "Update Windows to the latest version.",
        "Run the System File Checker (sfc /scannow)."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Rolling back the driver from Device Manager reverses the recent update while preserving data. Booting into Safe Mode and performing a system restore could work but is more intrusive. Updating Windows may help but doesn’t address the specific driver issue. The System File Checker repairs system files but not driver conflicts.",
      "examTip": "Use the rollback feature in Device Manager to quickly resolve driver-related BSOD issues."
    },
    {
      "id": 24,
      "question": "A SOHO user reports intermittent connectivity on their wireless network. Other nearby networks share the same channel. What is the MOST effective solution to improve network stability?",
      "options": [
        "Change the wireless channel to one with less interference.",
        "Upgrade the router’s firmware to the latest version.",
        "Reduce the router’s transmission power.",
        "Disable the router’s 5 GHz frequency band."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Changing the wireless channel reduces interference from nearby networks using the same frequency. Firmware upgrades improve features and security but may not resolve channel interference. Reducing transmission power would decrease coverage. Disabling the 5 GHz band would limit performance rather than improve stability.",
      "examTip": "Analyze and adjust wireless channels to minimize interference for optimal network performance."
    },
    {
      "id": 25,
      "question": "A user’s macOS system fails to boot after a recent update, showing a prohibitory symbol. Which built-in tool should the technician use FIRST to attempt a repair?",
      "options": [
        "Disk Utility’s First Aid feature in macOS Recovery.",
        "Terminal in macOS Recovery to reset PRAM.",
        "Reinstall macOS using macOS Recovery.",
        "Restore from Time Machine backup."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Disk Utility’s First Aid can detect and repair file system issues that cause boot failures. Resetting PRAM rarely resolves bootloader problems. Reinstalling macOS or restoring from Time Machine are more drastic and should be considered after attempting repairs.",
      "examTip": "Start with Disk Utility’s First Aid for non-destructive recovery attempts on macOS systems."
    },
    {
      "id": 26,
      "question": "A Windows 10 user reports that their PC shows 'Limited connectivity' when connecting to the corporate network. Other devices are working fine. Which command should the technician run FIRST to renew the IP configuration?",
      "options": [
        "ipconfig /release && ipconfig /renew",
        "ping 127.0.0.1",
        "netsh int ip reset",
        "ipconfig /flushdns"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The ipconfig /release and ipconfig /renew commands reset and request new IP addresses, often resolving limited connectivity issues. ping 127.0.0.1 tests the local network stack but not DHCP functionality. netsh int ip reset resets TCP/IP but is more invasive. ipconfig /flushdns clears DNS cache, unrelated to IP lease issues.",
      "examTip": "Renew IP configurations first when troubleshooting 'Limited connectivity' network errors."
    },
    {
      "id": 27,
      "question": "A Linux administrator notices high disk usage due to large log files. Which command will empty the contents of a specific log file without deleting it?",
      "options": [
        "> /var/log/syslog",
        "rm /var/log/syslog",
        "truncate -s 0 /var/log/syslog",
        "echo '' > /var/log/syslog"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The > operator truncates the file without deleting it, preserving permissions and ownership. rm deletes the file, which could affect running processes. truncate -s 0 is also valid but less commonly used. echo '' > achieves a similar result but is not the standard approach.",
      "examTip": "Use the redirection operator (>) to safely clear file contents without altering permissions or ownership."
    },
    {
      "id": 28,
      "question": "A user cannot access an internal web application after a recent proxy server configuration change. What is the MOST likely cause?",
      "options": [
        "Incorrect proxy settings in the user’s browser.",
        "Expired SSL certificate for the internal application.",
        "The user’s DNS cache contains outdated entries.",
        "Firewall rules were modified to block internal traffic."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Incorrect proxy settings often prevent access to internal applications dependent on the proxy. Expired SSL certificates would generate security warnings but not block access. Outdated DNS caches would cause resolution issues but not specifically after proxy changes. Firewall modifications would typically affect multiple users, not just one.",
      "examTip": "Verify browser proxy settings when access to internal web applications is disrupted after proxy changes."
    },
    {
      "id": 29,
      "question": "A technician is configuring a Windows 10 workstation to run a critical legacy application that requires Windows 7. What is the BEST way to achieve this without affecting the existing installation?",
      "options": [
        "Set up a virtual machine running Windows 7 using Hyper-V.",
        "Use compatibility mode for Windows 7 on the application executable.",
        "Perform a dual-boot installation with Windows 7 and Windows 10.",
        "Downgrade the workstation to Windows 7."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A virtual machine using Hyper-V allows Windows 7 to run alongside Windows 10 without affecting the host OS. Compatibility mode may work for some applications but not complex legacy software. Dual-boot setups risk partition changes and are less efficient. Downgrading the system compromises security and support.",
      "examTip": "Use virtualization for legacy applications to avoid compromising primary system integrity."
    },
    {
      "id": 30,
      "question": "A user is concerned about unauthorized access to their smartphone. Which security measure provides the STRONGEST protection?",
      "options": [
        "Biometric authentication combined with a complex PIN.",
        "Single biometric authentication (fingerprint or face recognition).",
        "PIN code with a timeout after several failed attempts.",
        "Pattern lock with a daily password change."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Combining biometrics with a complex PIN provides two layers of protection, making unauthorized access significantly harder. Single biometric authentication lacks redundancy. PIN codes alone are vulnerable without additional factors. Pattern locks are easier to guess and provide weaker security.",
      "examTip": "Combine biometrics with strong PINs or passwords for robust mobile device security."
    },
    {
      "id": 31,
      "question": "A Windows 10 PC fails to detect a newly installed SSD. The BIOS shows no record of the drive. What is the MOST likely cause?",
      "options": [
        "The SATA port is disabled in BIOS settings.",
        "The SSD requires a driver not included with Windows 10.",
        "The SSD must be initialized using Disk Management.",
        "The SSD uses a file system incompatible with Windows 10."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If BIOS doesn’t detect the SSD, the SATA port may be disabled. Drivers and file systems only become relevant once the OS recognizes the hardware. Disk Management initialization requires BIOS-level detection first.",
      "examTip": "Check BIOS hardware settings when new drives are not detected during system boot."
    },
    {
      "id": 32,
      "question": "A company requires full-disk encryption for all corporate laptops. Which Windows 10 feature should the IT department use to meet this requirement without additional software?",
      "options": [
        "BitLocker",
        "Encrypting File System (EFS)",
        "Windows Defender Credential Guard",
        "Secure Boot"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BitLocker provides full-disk encryption, ensuring data is protected at rest. EFS only encrypts individual files. Credential Guard protects credentials, not disk data. Secure Boot prevents unauthorized OS loading but doesn’t encrypt storage.",
      "examTip": "Enable BitLocker for robust, native full-disk encryption on Windows 10 systems."
    },
    {
      "id": 33,
      "question": "A user is unable to access a shared network printer after a recent IP change. Other users can print without issues. What should the technician do FIRST?",
      "options": [
        "Update the printer’s IP address in the user’s printer settings.",
        "Reinstall the printer driver on the user’s computer.",
        "Restart the print spooler service on the user’s PC.",
        "Verify the user’s network connectivity to the printer’s subnet."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If the printer’s IP has changed, updating the connection settings resolves the issue. Reinstalling drivers or restarting services won’t help if the IP address isn’t corrected. Network connectivity issues would prevent all network access, not just printing.",
      "examTip": "Always verify and update printer network settings after IP address changes."
    },
    {
      "id": 34,
      "question": "An administrator needs to track system performance metrics on a Windows 10 machine over several days. Which tool is BEST suited for this task?",
      "options": [
        "Performance Monitor with data collector sets",
        "Task Manager’s Performance tab",
        "Resource Monitor for real-time analysis",
        "System Configuration utility"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Performance Monitor allows the creation of data collector sets to track performance metrics over time. Task Manager and Resource Monitor provide real-time data without long-term tracking. System Configuration adjusts startup settings and doesn’t monitor performance.",
      "examTip": "Use Performance Monitor for historical tracking of performance data on Windows systems."
    },
    {
      "id": 35,
      "question": "A Linux user needs to schedule a script to run every day at 3 AM. Which command allows this configuration?",
      "options": [
        "crontab -e",
        "at 3:00",
        "systemctl enable script.service",
        "nohup ./script.sh &"
      ],
      "correctAnswerIndex": 0,
      "explanation": "crontab -e opens the cron table for scheduling recurring tasks like daily scripts. The at command schedules one-time tasks. systemctl enables services, not scheduled scripts. nohup runs processes independently of the terminal but doesn’t schedule them.",
      "examTip": "Configure recurring Linux tasks using cron with crontab -e for precise scheduling control."
    },
    {
      "id": 36,
      "question": "A user’s web browser frequently redirects to suspicious websites. Antivirus software detects no threats. What is the MOST likely cause?",
      "options": [
        "Browser hijacker malware",
        "DNS cache poisoning",
        "Corrupted browser installation",
        "Proxy settings misconfiguration"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Browser hijackers modify browser settings to redirect traffic. DNS cache poisoning affects multiple applications, not just the browser. Corrupted installations cause crashes rather than redirects. Proxy misconfigurations impact all web traffic, not selectively redirecting.",
      "examTip": "Reset browser settings and check for malicious extensions when facing suspicious redirects."
    },
    {
      "id": 37,
      "question": "A technician needs to verify if an email server supports encrypted communication. Which protocol and port combination should they test?",
      "options": [
        "SMTP over TLS on port 587",
        "POP3 on port 110",
        "IMAP on port 143",
        "SMTP on port 25"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SMTP over TLS (port 587) provides encrypted outbound email. POP3 (port 110) and IMAP (port 143) are used for inbound mail without encryption by default. SMTP on port 25 is traditionally unencrypted and often blocked by ISPs.",
      "examTip": "Ensure email servers use port 587 with TLS for secure outbound mail delivery."
    },
    {
      "id": 38,
      "question": "A user reports that their laptop’s screen does not auto-rotate despite enabling rotation lock. Other features work normally. What is the MOST likely cause?",
      "options": [
        "Outdated accelerometer driver",
        "Damaged screen rotation sensor",
        "Disabled gyroscope hardware in BIOS",
        "Incorrect display resolution settings"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An outdated accelerometer driver can prevent auto-rotation functionality. Sensor damage would likely affect other features. Gyroscopes are uncommon in laptops for rotation and typically don’t have BIOS settings. Display resolution settings don’t impact rotation.",
      "examTip": "Update motion sensor drivers when auto-rotation fails while other hardware functions normally."
    },
    {
      "id": 39,
      "question": "A user cannot access HTTPS websites but can access HTTP sites. The date and time are correct. What is the MOST likely cause?",
      "options": [
        "Corrupted root certificates",
        "Faulty Ethernet cable",
        "Browser cache corruption",
        "Outdated network drivers"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Corrupted or outdated root certificates prevent HTTPS connections due to failed SSL verification. Network or cable issues would affect all connections. Browser cache problems wouldn’t selectively block HTTPS. Outdated drivers typically affect all network functions, not just secure connections.",
      "examTip": "Check and update root certificates when HTTPS connections fail but HTTP access remains unaffected."
    },
    {
      "id": 40,
      "question": "A technician needs to enable file sharing between a Windows 10 PC and a macOS system. Which file sharing protocol should be used for the BEST compatibility?",
      "options": [
        "SMB (Server Message Block)",
        "AFP (Apple Filing Protocol)",
        "NFS (Network File System)",
        "FTP (File Transfer Protocol)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SMB is natively supported by both Windows and macOS, providing the best compatibility for file sharing. AFP is specific to macOS. NFS is commonly used in Unix/Linux environments. FTP is suitable for file transfers but lacks integration for seamless file sharing between these platforms.",
      "examTip": "Use SMB for cross-platform file sharing between Windows and macOS systems for maximum compatibility."
    },
    {
      "id": 41,
      "question": "A Windows 10 system shows the error 'Operating System not found' after a failed BIOS update. The hard drive is functional and connected. What is the MOST likely cause?",
      "options": [
        "The boot order in BIOS was reset to prioritize an empty device.",
        "The system partition was accidentally formatted during the update.",
        "The MBR (Master Boot Record) was overwritten by the BIOS update.",
        "A critical Windows system file became corrupted during the update."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A BIOS update can reset boot order settings, causing the system to boot from an incorrect device. Formatting the system partition would cause permanent data loss, unlikely during a BIOS update. MBR corruption is possible but less likely linked directly to BIOS flashing. Corrupted system files wouldn’t prevent BIOS from detecting the OS partition entirely.",
      "examTip": "Always check and correct BIOS boot order after firmware updates if the OS becomes unbootable."
    },
    {
      "id": 42,
      "question": "A user reports that their corporate laptop frequently disconnects from the company’s Wi-Fi network after recent driver updates. What is the FIRST step a technician should take?",
      "options": [
        "Roll back the wireless network driver to a previous version.",
        "Reinstall the Wi-Fi driver with the latest OEM version.",
        "Perform a Windows network reset to restore default settings.",
        "Disable the power-saving feature for the wireless adapter."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Rolling back the driver addresses potential incompatibilities introduced by the recent update. Reinstalling the latest version is useful but should be tried after rollback. Resetting network settings is a more intrusive approach. Power-saving settings may impact connectivity but typically cause issues only when on battery power.",
      "examTip": "Use the rollback driver option first when connectivity issues occur immediately after driver updates."
    },
    {
      "id": 43,
      "question": "A technician is configuring a Windows 10 system for dual-boot with Linux. Which file system should be selected for the Linux partition to ensure maximum compatibility with Linux utilities and performance?",
      "options": [
        "ext4",
        "FAT32",
        "NTFS",
        "exFAT"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The ext4 file system is optimized for Linux, offering robust performance and compatibility with native tools. FAT32 and exFAT lack journaling and have size limitations. NTFS is designed for Windows and may not provide optimal performance or compatibility for Linux installations.",
      "examTip": "Choose ext4 for Linux installations to ensure efficient performance and compatibility with Linux applications."
    },
    {
      "id": 44,
      "question": "A Linux administrator suspects that the firewall is blocking SSH traffic. Which command will BEST confirm whether port 22 is open and listening for connections?",
      "options": [
        "sudo netstat -tuln | grep 22",
        "iptables -L -n",
        "systemctl status sshd",
        "ps aux | grep ssh"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The netstat -tuln command shows active ports, allowing confirmation that port 22 is listening for SSH connections. iptables -L -n lists firewall rules but doesn’t confirm active port listening. systemctl status sshd checks the SSH service status but not firewall configurations. ps aux | grep ssh lists SSH processes but doesn’t provide network port details.",
      "examTip": "Use netstat to verify whether essential ports like 22 are open and listening for connections."
    },
    {
      "id": 45,
      "question": "A user reports slow application response times on a Windows 10 machine. Resource Monitor shows high disk activity by the 'Windows Search' process. What is the BEST approach to improve performance without disabling search functionality?",
      "options": [
        "Modify indexing options to limit indexed locations.",
        "Completely disable the Windows Search service.",
        "Upgrade the disk from HDD to SSD.",
        "Perform a clean installation of Windows 10."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Limiting the number of indexed locations reduces disk activity while preserving search capabilities. Disabling Windows Search would eliminate useful functionality. Upgrading to an SSD improves overall performance but is a hardware-based solution. A clean installation is extreme and unnecessary for this issue.",
      "examTip": "Optimize Windows Search indexing locations to balance system performance and search speed."
    },
    {
      "id": 46,
      "question": "An administrator needs to deploy an application to multiple Windows 10 workstations in a domain environment without user interaction. Which method is MOST efficient?",
      "options": [
        "Group Policy Software Installation (GPSI).",
        "Manual installation on each workstation.",
        "Provide installation instructions to users.",
        "Use Remote Desktop to perform installations."
      ],
      "correctAnswerIndex": 0,
      "explanation": "GPSI automates software deployment across multiple systems within a domain, requiring minimal user intervention. Manual installation is time-consuming. Providing instructions relies on users, risking inconsistency. Remote Desktop installations would still require manual steps on each machine.",
      "examTip": "Use Group Policy for scalable, automated software deployment in domain environments."
    },
    {
      "id": 47,
      "question": "A Windows user reports receiving frequent certificate warnings when visiting internal web applications. The system’s time and date are correct. What is the MOST likely cause?",
      "options": [
        "Missing or outdated root certificates on the workstation.",
        "Improper DNS configuration for internal domains.",
        "The internal web server’s SSL certificate has expired.",
        "The firewall is blocking HTTPS traffic to internal servers."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Outdated or missing root certificates prevent proper SSL certificate validation, leading to warnings. DNS issues would cause resolution failures rather than certificate errors. An expired server certificate would impact all users, not just one. Firewall restrictions typically block access altogether, not just trigger certificate warnings.",
      "examTip": "Ensure root certificates are regularly updated to prevent SSL validation issues for internal applications."
    },
    {
      "id": 48,
      "question": "A technician needs to troubleshoot a user’s inability to connect to internal resources by hostname but can connect via IP. What is the FIRST command they should run?",
      "options": [
        "ipconfig /flushdns",
        "nslookup internal_hostname",
        "ping internal_hostname",
        "tracert internal_hostname"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Flushing the DNS cache resolves issues with stale or corrupt DNS entries. nslookup tests DNS resolution but doesn’t fix issues. ping and tracert test connectivity but don’t address DNS resolution problems directly.",
      "examTip": "Flush DNS cache first when hostname resolution issues occur but IP connectivity is functional."
    },
    {
      "id": 49,
      "question": "A Linux administrator needs to find all files owned by a specific user in the /var directory. Which command will accomplish this?",
      "options": [
        "find /var -user username",
        "grep username /var",
        "ls -al /var | grep username",
        "locate /var/username"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The find command with the -user option searches for files based on ownership. grep searches file contents, not ownership. ls -al lists directory contents but doesn’t recursively search. locate searches indexed file names, not ownership.",
      "examTip": "Use the find command with -user to locate all files owned by a specific user across directories."
    },
    {
      "id": 50,
      "question": "A user’s Windows 10 PC has multiple failed logins, resulting in a locked account. The technician needs to unlock the account. Which tool should they use in a domain environment?",
      "options": [
        "Active Directory Users and Computers (ADUC)",
        "Local Users and Groups (lusrmgr.msc)",
        "Computer Management console",
        "net user command in Command Prompt"
      ],
      "correctAnswerIndex": 0,
      "explanation": "In a domain environment, ADUC provides tools to unlock user accounts. Local Users and Groups manage local accounts only. The Computer Management console is limited to local settings. net user commands can manage accounts but aren’t the primary tool for domain environments.",
      "examTip": "Use ADUC in domain environments to manage user accounts, including unlocking after failed logins."
    },
    {
      "id": 51,
      "question": "A user’s web browser on a Windows 10 system is redirecting searches to unknown sites. Antivirus scans show no malware. What is the MOST likely cause?",
      "options": [
        "Malicious browser extension",
        "Corrupted DNS resolver cache",
        "Modified hosts file",
        "Outdated web browser version"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Malicious browser extensions can cause redirection without traditional malware signatures. DNS cache issues would affect multiple applications. Modified hosts files would redirect all traffic to certain domains, not just browser searches. Outdated browsers could have security issues but typically don’t cause redirects.",
      "examTip": "Check for and remove suspicious browser extensions when facing unexplained redirects."
    },
    {
      "id": 52,
      "question": "A technician needs to ensure that backups are stored both locally and offsite for disaster recovery. Which strategy should they implement?",
      "options": [
        "3-2-1 backup strategy",
        "Full backup only",
        "Incremental backup only",
        "Differential backup combined with full backups"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 3-2-1 strategy involves three copies of data, on two different media, with one copy offsite—ensuring robust disaster recovery. Full backups alone are storage-intensive. Incremental and differential backups have their benefits but don’t specify offsite storage requirements.",
      "examTip": "Adopt the 3-2-1 backup strategy for comprehensive protection against data loss and disasters."
    },
    {
      "id": 53,
      "question": "A Linux server shows that the /home partition is 100% full. Which command will help identify the largest files consuming space?",
      "options": [
        "du -ah /home | sort -rh | head -n 10",
        "df -h /home",
        "ls -lh /home",
        "find /home -type f -size +100M"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The du command with sorting displays disk usage by file size, showing the largest files. df -h shows partition usage but not file-level details. ls -lh lists files but doesn’t summarize disk usage. find can locate large files but won’t rank them by size.",
      "examTip": "Use du with sorting options to efficiently locate and manage large files on Linux systems."
    },
    {
      "id": 54,
      "question": "A user’s Android device fails to sync corporate emails after a recent password change. What is the MOST likely cause?",
      "options": [
        "Outdated email credentials stored in the email client",
        "Device storage running out of available space",
        "Disabled background data for the email application",
        "Corrupted cache of the email application"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Email clients often store credentials, and password changes require updating these details. Storage issues or disabled background data may cause syncing issues but wouldn’t correlate directly with password changes. Cache corruption may cause performance issues but less likely immediate syncing failures after credential updates.",
      "examTip": "Always verify updated credentials in email applications following password changes."
    },
    {
      "id": 55,
      "question": "A Windows 10 system boots slowly, and the Task Manager shows several high-impact startup applications. What is the MOST efficient step to improve boot performance?",
      "options": [
        "Disable unnecessary startup applications in Task Manager.",
        "Upgrade the system’s RAM.",
        "Run Disk Cleanup and defragment the hard drive.",
        "Perform a system restore to a previous state."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Disabling non-essential startup applications reduces boot time without hardware upgrades or drastic recovery steps. RAM upgrades enhance multitasking but don’t specifically target slow boots. Disk cleanup and defragmentation help storage performance but less so with startup delays. System restore is too disruptive for a performance issue.",
      "examTip": "Review and manage startup applications in Task Manager to optimize Windows boot times."
    },
    {
      "id": 56,
      "question": "A company wants to implement two-factor authentication (2FA) for remote users accessing internal systems. Which method provides the BEST balance of security and user convenience?",
      "options": [
        "Authenticator app-based codes with a strong password",
        "Email-based verification codes",
        "Hardware tokens for all users",
        "Biometric authentication only"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Authenticator apps generate time-based codes, providing robust 2FA without additional hardware. Email verification can be less secure if email accounts are compromised. Hardware tokens add security but are costly and cumbersome. Biometrics alone do not qualify as two-factor without another distinct factor.",
      "examTip": "Combine strong passwords with authenticator apps for scalable, user-friendly 2FA solutions."
    },
    {
      "id": 57,
      "question": "A Linux administrator wants to ensure a script runs every time the system boots. Which directory should the script be placed in for most modern distributions using systemd?",
      "options": [
        "/etc/systemd/system/",
        "/etc/init.d/",
        "/usr/local/bin/",
        "/etc/rc.local"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Modern Linux distributions using systemd store custom service files in /etc/systemd/system/ for boot-time execution. /etc/init.d/ was used by older init systems. /usr/local/bin/ holds executables but doesn’t ensure execution at boot. /etc/rc.local is deprecated in many modern systems.",
      "examTip": "For systemd-enabled Linux systems, use /etc/systemd/system/ to manage boot-time scripts and services."
    },
    {
      "id": 58,
      "question": "A user reports that after updating their macOS system, third-party applications display 'App is damaged and can’t be opened' errors. What is the MOST likely cause?",
      "options": [
        "Gatekeeper settings blocking non-App Store applications",
        "Corrupted application binaries after the update",
        "Expired digital certificates for the applications",
        "Insufficient disk permissions for application directories"
      ],
      "correctAnswerIndex": 0,
      "explanation": "macOS Gatekeeper restricts apps from unidentified developers. Updates can reset these settings, causing access errors. Corrupted binaries would cause crashes, not consistent access errors. Expired certificates would generate warning messages but not claim apps are damaged. Disk permissions issues usually generate access-denied errors, not corruption messages.",
      "examTip": "Adjust Gatekeeper settings via System Preferences to restore access to third-party apps after macOS updates."
    },
    {
      "id": 59,
      "question": "A technician needs to verify that a web server’s SSL certificate matches its private key. Which Linux command should they use?",
      "options": [
        "openssl x509 -noout -modulus -in certificate.crt && openssl rsa -noout -modulus -in private.key",
        "openssl verify certificate.crt",
        "openssl s_client -connect server:443",
        "cat certificate.crt | grep BEGIN"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Comparing the modulus output of the certificate and private key confirms they match. The verify command checks certificate validity but not key pairing. s_client tests server SSL connections but doesn’t compare keys. The grep command checks file content headers, not key matches.",
      "examTip": "Use OpenSSL’s modulus comparison to ensure SSL certificates match their private keys before deployment."
    },
    {
      "id": 60,
      "question": "A user reports that their mobile device’s battery drains rapidly after a recent app installation. Which step should the technician take FIRST?",
      "options": [
        "Check battery usage statistics for the problematic app.",
        "Reset the device to factory settings.",
        "Disable background data usage for all apps.",
        "Perform a full device OS update."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Reviewing battery statistics identifies apps consuming excessive power, helping pinpoint the issue. Factory resets are drastic and should follow other troubleshooting. Disabling background data affects usability. OS updates may help but are less likely to directly address app-specific battery drain.",
      "examTip": "Check app battery usage stats first when diagnosing rapid battery drain issues on mobile devices."
    },
    {
      "id": 61,
      "question": "A Windows 10 user reports that after installing new software, the system frequently displays 'Kernel Security Check Failure' BSOD errors. What is the BEST next step to resolve the issue without data loss?",
      "options": [
        "Uninstall the recently installed software in Safe Mode.",
        "Perform a full Windows reset, keeping user files.",
        "Run the sfc /scannow command to repair system files.",
        "Update all device drivers using Windows Update."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Uninstalling the recently added software in Safe Mode addresses compatibility issues that may cause kernel errors without data loss. Running sfc /scannow helps repair system files but may not fix driver conflicts caused by third-party software. Performing a Windows reset is a more drastic step that should follow less invasive troubleshooting. Updating drivers is beneficial but may not resolve software-specific kernel errors.",
      "examTip": "Always attempt Safe Mode troubleshooting first to remove recently installed software causing kernel-level errors."
    },
    {
      "id": 62,
      "question": "A Linux user reports that a backup script fails with a 'Permission denied' error. The user runs the script with sudo but the error persists. What is the MOST likely cause?",
      "options": [
        "Incorrect file permissions on the script itself.",
        "Missing execute permissions on the destination folder.",
        "The sudoers file does not grant the user the necessary privileges.",
        "The shell interpreter specified in the script is unavailable."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If the script lacks execute permissions, it will fail even when using sudo. Missing destination folder permissions would cause write errors, not execution failures. The sudoers file would prevent sudo from running at all, not produce a 'Permission denied' message for a specific script. An unavailable shell interpreter would result in a 'command not found' or interpreter-related error.",
      "examTip": "Always verify script permissions using chmod before troubleshooting deeper privilege issues."
    },
    {
      "id": 63,
      "question": "A user complains that their macOS system is running slowly after a recent update. Activity Monitor shows high CPU usage by 'kernel_task.' What is the MOST likely cause?",
      "options": [
        "macOS is managing the CPU temperature to prevent overheating.",
        "A background Time Machine backup is consuming system resources.",
        "The Spotlight index is being rebuilt after the update.",
        "A third-party kernel extension is causing a CPU conflict."
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 'kernel_task' process regulates CPU temperature by occupying resources to prevent overheating. Time Machine backups would show different processes consuming resources. Spotlight indexing impacts storage and CPU but is listed as a separate process. While third-party kernel extensions can cause issues, 'kernel_task' specifically relates to thermal management.",
      "examTip": "High 'kernel_task' CPU usage often indicates thermal throttling; check for dust buildup or cooling issues."
    },
    {
      "id": 64,
      "question": "A Windows 10 PC connected to a corporate domain cannot apply new group policies. The network connection is stable. Which command should the technician use to identify applied policies and errors?",
      "options": [
        "gpresult /h report.html",
        "gpupdate /force",
        "net user /domain",
        "rsop.msc"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The gpresult /h report.html command generates a comprehensive HTML report showing applied policies and any errors. gpupdate /force refreshes policies but doesn’t provide diagnostic information. net user /domain manages user accounts but doesn’t display policy data. rsop.msc shows Resultant Set of Policy but may not highlight underlying errors as clearly as gpresult.",
      "examTip": "Use gpresult with the /h switch for detailed group policy troubleshooting reports in Windows domains."
    },
    {
      "id": 65,
      "question": "A Linux administrator receives complaints that an internal web server is not responding. Which command should be used FIRST to check if the server is listening on the appropriate port?",
      "options": [
        "netstat -tuln | grep 80",
        "ping server_ip",
        "systemctl status apache2",
        "traceroute server_ip"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Using netstat with the appropriate port checks if the web server is actively listening for HTTP traffic. ping tests connectivity but not service status. systemctl checks service status but doesn’t confirm port bindings. traceroute identifies network path issues, not port-level availability.",
      "examTip": "Always confirm port availability with netstat or ss when diagnosing web server responsiveness issues."
    },
    {
      "id": 66,
      "question": "A user reports being redirected to a suspicious website whenever attempting to visit a trusted banking site. Antivirus scans return clean. What is the MOST likely cause?",
      "options": [
        "The hosts file has been modified to redirect traffic.",
        "The DNS resolver cache is corrupted.",
        "A proxy server is intercepting web requests.",
        "The browser has cached an old DNS entry."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Malicious modifications to the hosts file can redirect traffic at the local system level, bypassing DNS settings. DNS cache corruption would affect multiple sites, not just one. A proxy server would likely affect all browsing activity, not selectively redirect trusted sites. Browser cache issues typically lead to loading errors, not redirects.",
      "examTip": "Check the hosts file for unauthorized entries when facing suspicious, site-specific redirections."
    },
    {
      "id": 67,
      "question": "A Windows 10 system is unable to access shared folders on the local network after a recent update. Which Windows feature should be checked FIRST?",
      "options": [
        "Network Discovery settings",
        "Windows Firewall inbound rules",
        "SMB protocol configuration",
        "File and Printer Sharing settings"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Network Discovery allows the computer to see and access network resources. Windows Firewall rules and SMB settings affect access but are less likely to change after standard updates. File and Printer Sharing impacts resource availability rather than the ability to detect shared resources.",
      "examTip": "Re-enable Network Discovery after major Windows updates to restore access to local network shares."
    },
    {
      "id": 68,
      "question": "A technician needs to encrypt sensitive files on a Windows 10 PC so only the logged-in user can access them. Which built-in feature should be used?",
      "options": [
        "Encrypting File System (EFS)",
        "BitLocker Drive Encryption",
        "Windows Defender Credential Guard",
        "Windows Information Protection (WIP)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "EFS encrypts individual files and folders, restricting access to the user who encrypted them. BitLocker encrypts entire drives rather than specific files. Credential Guard protects authentication credentials, not files. WIP controls corporate data usage but isn’t focused on file encryption.",
      "examTip": "Use EFS for per-user file encryption on NTFS volumes when full-disk encryption isn’t required."
    },
    {
      "id": 69,
      "question": "A user’s Android smartphone displays a message stating 'Device storage almost full.' Which step should be taken FIRST to free up space without affecting user data?",
      "options": [
        "Clear the cache for installed applications.",
        "Uninstall infrequently used applications.",
        "Move media files to cloud storage.",
        "Perform a factory reset after backup."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Clearing app caches frees up space without deleting user data or apps. Uninstalling apps removes data and settings. Cloud storage solutions help but require additional configuration. Factory resets should be the last resort due to their disruptive nature.",
      "examTip": "Start with non-destructive actions like clearing caches when addressing mobile storage limitations."
    },
    {
      "id": 70,
      "question": "A technician needs to troubleshoot a Windows 10 system that freezes intermittently. Which built-in utility provides detailed information on hardware errors and system crashes?",
      "options": [
        "Event Viewer",
        "Performance Monitor",
        "Resource Monitor",
        "Task Manager"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Event Viewer logs critical system events, including hardware errors and crash details. Performance Monitor tracks performance metrics but doesn’t log errors. Resource Monitor shows real-time resource usage. Task Manager assists in real-time troubleshooting but lacks detailed historical error logs.",
      "examTip": "Use Event Viewer for deep insights into system-level events when diagnosing intermittent system freezes."
    },
    {
      "id": 71,
      "question": "A company requires remote desktop access for its employees while ensuring data encryption during transmission. Which protocol provides secure remote access with encryption?",
      "options": [
        "Remote Desktop Protocol (RDP) over TLS",
        "Telnet over TCP port 23",
        "Virtual Network Computing (VNC) without tunneling",
        "Simple Network Management Protocol (SNMP) v1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "RDP over TLS provides encrypted communication for secure remote desktop access. Telnet transmits data in plain text, offering no encryption. VNC without tunneling lacks encryption by default. SNMP v1 is used for network management and transmits data without encryption.",
      "examTip": "Always ensure RDP connections are secured with TLS for encrypted remote desktop sessions."
    },
    {
      "id": 72,
      "question": "A Windows 10 system connected to a domain shows the error 'Trust relationship between this workstation and the primary domain failed.' What is the MOST effective way to restore access without rejoining the domain?",
      "options": [
        "Reset the computer account in Active Directory and reboot the workstation.",
        "Remove the workstation from the domain and rejoin it.",
        "Run gpupdate /force to reapply domain policies.",
        "Restart the Netlogon service on the workstation."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Resetting the computer account in Active Directory reestablishes trust without requiring rejoining, preserving configurations. Removing and rejoining the domain works but is more time-consuming. gpupdate re-applies policies but doesn’t fix trust issues. Restarting Netlogon won’t resolve broken trust relationships.",
      "examTip": "Reset the computer account in AD to fix domain trust issues efficiently without reconfiguration."
    },
    {
      "id": 73,
      "question": "A user’s Windows 10 laptop fails to detect any available Wi-Fi networks. Other devices connect normally. What should the technician check FIRST?",
      "options": [
        "Ensure the wireless adapter is enabled in Network Connections.",
        "Update the wireless adapter driver from Device Manager.",
        "Reset TCP/IP stack using netsh commands.",
        "Disable and re-enable the wireless adapter in BIOS."
      ],
      "correctAnswerIndex": 0,
      "explanation": "The most immediate step is confirming the wireless adapter is enabled. Driver updates help if detection fails due to compatibility issues. Resetting the TCP/IP stack is more relevant for connectivity issues rather than detection. BIOS settings rarely disable wireless adapters unless specifically configured.",
      "examTip": "Always verify hardware-level enablement of wireless adapters before deeper network troubleshooting."
    },
    {
      "id": 74,
      "question": "A user reports that every time they open their web browser, multiple tabs open with random advertisements. Antivirus scans show no infections. What is the MOST likely cause?",
      "options": [
        "A browser extension has installed adware.",
        "The browser’s home page settings have been modified.",
        "The operating system’s DNS settings have been hijacked.",
        "The user’s profile in the browser is corrupted."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Adware-infected browser extensions often cause unwanted tabs and ads to load automatically. Modified home page settings would lead to specific, not random, pages opening. DNS hijacking affects network-wide browsing, not just one browser. Profile corruption may cause crashes, not ad-based behavior.",
      "examTip": "Check for and remove suspicious browser extensions when facing persistent unwanted browser behavior."
    },
    {
      "id": 75,
      "question": "A Linux server administrator needs to schedule a one-time backup at 3 AM. Which command should be used?",
      "options": [
        "at 03:00",
        "cron -e",
        "systemctl timer",
        "nohup backup.sh &"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The at command schedules one-time tasks. cron handles recurring tasks. systemctl timers provide scheduled executions in systemd environments but are more complex for one-time tasks. nohup runs a command in the background but doesn’t schedule execution.",
      "examTip": "Use the at command for simple, one-time task scheduling in Linux environments."
    },
    {
      "id": 76,
      "question": "A technician suspects that a Windows 10 machine’s slow boot times are caused by disk errors. Which built-in utility should be used to detect and repair these issues?",
      "options": [
        "chkdsk /f",
        "sfc /scannow",
        "diskpart",
        "defrag C:"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The chkdsk /f command checks for and fixes disk-related file system errors that can slow boot times. sfc /scannow verifies system file integrity but not disk health. diskpart manages partitions but doesn’t diagnose disk errors. Defrag optimizes drive layout but doesn’t fix errors.",
      "examTip": "Run chkdsk with the /f parameter to resolve disk errors causing slow boots or performance issues."
    },
    {
      "id": 77,
      "question": "A user reports that their Linux server is running out of disk space in the /var directory. Which command will identify the largest directories consuming space?",
      "options": [
        "du -sh /var/* | sort -rh | head -n 5",
        "df -h /var",
        "ls -lh /var",
        "find /var -size +100M"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The du command with sorting identifies the largest directories, allowing for targeted cleanup. df -h shows disk usage by partition but lacks directory breakdown. ls -lh lists file sizes but doesn’t summarize directory usage. find locates large files but doesn’t group them by directory size.",
      "examTip": "Use du with sorting options to pinpoint storage hogs in Linux directories efficiently."
    },
    {
      "id": 78,
      "question": "A Windows 10 user reports that USB devices are not being recognized when connected. Other systems detect the same devices without issue. What should the technician check FIRST?",
      "options": [
        "Verify that USB controllers are enabled and functioning in Device Manager.",
        "Check if the USB ports are disabled in BIOS settings.",
        "Reinstall USB controller drivers from the manufacturer’s website.",
        "Run Windows Update to download the latest system patches."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Checking Device Manager ensures that USB controllers are properly installed and functional. BIOS settings rarely disable USB ports unless manually configured. Driver reinstallation and Windows Updates are secondary steps if hardware-level issues aren’t detected.",
      "examTip": "Start USB troubleshooting by confirming the operational status of controllers in Device Manager."
    },
    {
      "id": 79,
      "question": "A technician is configuring backup strategies for a file server. The business requires the fastest recovery time while minimizing storage use. Which backup approach should be implemented?",
      "options": [
        "Full backup weekly with daily incremental backups.",
        "Full backup daily.",
        "Full backup weekly with daily differential backups.",
        "Incremental backups only."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Weekly full backups combined with daily incremental backups balance storage efficiency and fast recovery times, requiring only the latest full backup plus all subsequent incrementals. Daily full backups consume more storage. Differential backups grow larger over time. Incremental-only strategies complicate recovery due to dependency chains.",
      "examTip": "Combine full and incremental backups for optimal recovery speed and storage efficiency."
    },
    {
      "id": 80,
      "question": "A macOS user needs to encrypt their entire disk for data protection. Which built-in macOS tool should be used?",
      "options": [
        "FileVault",
        "Disk Utility encryption",
        "Time Machine",
        "Keychain Access"
      ],
      "correctAnswerIndex": 0,
      "explanation": "FileVault provides full-disk encryption on macOS, securing data even if the device is stolen. Disk Utility encryption applies to specific external drives or partitions. Time Machine handles backups, not encryption. Keychain Access manages passwords and certificates but doesn’t encrypt storage volumes.",
      "examTip": "Enable FileVault for robust, system-wide encryption on macOS devices without third-party tools."
    },
    {
      "id": 81,
      "question": "A user reports that their Windows 10 system takes significantly longer to load the desktop after logging in. Task Manager shows high disk usage from the 'Superfetch' (SysMain) process. What is the BEST action to improve performance without disabling essential services?",
      "options": [
        "Upgrade the hard drive to an SSD.",
        "Adjust SysMain service settings to 'Manual' start.",
        "Perform a clean boot to disable all non-Microsoft services.",
        "Increase the system’s RAM capacity."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Upgrading to an SSD significantly reduces disk bottlenecks, improving boot times without disabling beneficial services like SysMain. Setting SysMain to manual may speed boot but affects application preloading benefits. A clean boot identifies software issues but doesn't address disk speed. Increasing RAM helps with multitasking but won’t solve disk performance issues linked to Superfetch.",
      "examTip": "SSD upgrades provide the most noticeable performance boost on systems hindered by disk-intensive processes like Superfetch."
    },
    {
      "id": 82,
      "question": "A Linux administrator discovers that a service is not starting at boot despite working when started manually. Which command should be used to enable the service at boot on a system using systemd?",
      "options": [
        "systemctl enable servicename",
        "systemctl start servicename",
        "chkconfig servicename on",
        "update-rc.d servicename defaults"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The systemctl enable command configures services to start at boot in systemd-based distributions. systemctl start runs the service only for the current session. chkconfig and update-rc.d are used in older init systems, not systemd.",
      "examTip": "Use 'systemctl enable' on systemd-based Linux systems to ensure services persist across reboots."
    },
    {
      "id": 83,
      "question": "A Windows 10 user cannot open encrypted files after reinstalling the operating system. The files were encrypted with EFS. What is the MOST likely reason?",
      "options": [
        "The encryption certificate was not backed up before reinstallation.",
        "The file permissions were removed during OS reinstallation.",
        "The files were stored on a FAT32 partition incompatible with EFS.",
        "The user’s new profile lacks administrator privileges."
      ],
      "correctAnswerIndex": 0,
      "explanation": "EFS relies on user-specific encryption certificates. Without backing up and restoring the certificate, the files become inaccessible after OS reinstallation. File permissions or administrator rights don’t affect EFS access. FAT32 partitions don’t support EFS, but existing EFS files indicate the use of NTFS.",
      "examTip": "Always back up EFS certificates when encrypting files; without them, recovery after OS changes is impossible."
    },
    {
      "id": 84,
      "question": "A technician needs to perform a secure data wipe on a decommissioned SSD before disposal. Which method ensures the BEST balance between security and SSD longevity?",
      "options": [
        "Use the manufacturer's secure erase utility.",
        "Perform multiple overwrites with random data using dd.",
        "Encrypt the entire disk and delete the encryption key.",
        "Format the drive using quick format in Disk Management."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Manufacturer-provided secure erase utilities trigger SSD’s internal erase commands optimized for secure deletion without excessive wear. Multiple overwrites strain SSD cells unnecessarily. Encryption plus key deletion is secure but leaves encrypted data physically intact. Quick format only removes file system references, not data.",
      "examTip": "Use SSD-specific secure erase tools from manufacturers for secure and efficient data removal."
    },
    {
      "id": 85,
      "question": "A company mandates that all laptops use full-disk encryption. Which Windows 10 feature BEST meets this requirement while integrating with TPM for seamless operation?",
      "options": [
        "BitLocker",
        "Encrypting File System (EFS)",
        "Windows Hello for Business",
        "Windows Defender Application Control"
      ],
      "correctAnswerIndex": 0,
      "explanation": "BitLocker provides full-disk encryption and integrates with TPM for secure key storage and automatic unlocking during boot. EFS encrypts individual files, not entire drives. Windows Hello manages authentication but doesn’t encrypt data. Windows Defender Application Control restricts app execution but doesn’t handle encryption.",
      "examTip": "Enable BitLocker with TPM for enterprise-grade, seamless full-disk encryption on Windows 10 devices."
    },
    {
      "id": 86,
      "question": "A user is unable to access HTTPS websites on a Windows 10 PC. HTTP sites load correctly. The date and time settings are correct. What is the MOST likely cause?",
      "options": [
        "Corrupted or missing root certificates.",
        "Faulty network adapter driver.",
        "Incorrect DNS configuration.",
        "Misconfigured proxy server settings."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Corrupted or outdated root certificates prevent SSL/TLS validation required for HTTPS connections. Network driver issues would affect all traffic, not just HTTPS. DNS misconfigurations impact both HTTP and HTTPS. Proxy misconfigurations would typically block all web access or specific domains, not just HTTPS.",
      "examTip": "If HTTPS sites fail while HTTP works, check and update root certificates for SSL/TLS validation."
    },
    {
      "id": 87,
      "question": "A technician needs to block outbound traffic from a specific application on a Windows 10 workstation. Which tool should be used?",
      "options": [
        "Windows Defender Firewall with Advanced Security",
        "Local Security Policy Editor",
        "User Account Control (UAC) settings",
        "Task Scheduler"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Windows Defender Firewall with Advanced Security allows creation of outbound rules targeting specific applications. The Local Security Policy Editor focuses on account and system policies, not network traffic. UAC manages privilege elevation, not application networking. Task Scheduler automates tasks, not traffic management.",
      "examTip": "Use Windows Defender Firewall's advanced settings to control application-specific network traffic."
    },
    {
      "id": 88,
      "question": "A Linux server experiences intermittent network connectivity. The administrator suspects a faulty NIC. Which command provides real-time network interface statistics to aid diagnosis?",
      "options": [
        "ifstat",
        "ifconfig",
        "ip addr show",
        "netstat -i"
      ],
      "correctAnswerIndex": 0,
      "explanation": "ifstat displays real-time network interface statistics, ideal for identifying connectivity issues. ifconfig shows configuration details but not live statistics. ip addr show lists interface addresses but doesn’t provide performance data. netstat -i shows interface statistics but lacks real-time updates like ifstat.",
      "examTip": "Use 'ifstat' on Linux servers to monitor network performance metrics in real time for connectivity diagnostics."
    },
    {
      "id": 89,
      "question": "A user reports that all email messages are being marked as spam in their email client after a recent configuration change. What is the MOST likely cause?",
      "options": [
        "The spam filter sensitivity settings were set too high.",
        "The mail server’s DNS records are incorrectly configured.",
        "The user’s email account has been blacklisted.",
        "The email client’s synchronization settings were altered."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Overly sensitive spam filter settings in the client can misclassify legitimate emails. Incorrect DNS records would affect delivery rather than classification. Blacklisting affects inbound emails, not local spam categorization. Synchronization settings issues cause delays but don’t impact spam filtering directly.",
      "examTip": "Check client-side spam filter thresholds when legitimate emails are consistently misclassified as spam."
    },
    {
      "id": 90,
      "question": "A technician needs to configure a Windows 10 workstation to prevent users from installing unauthorized applications without affecting critical system updates. Which feature provides the MOST effective solution?",
      "options": [
        "AppLocker",
        "Windows Defender SmartScreen",
        "User Account Control (UAC)",
        "Local Group Policy for software restrictions"
      ],
      "correctAnswerIndex": 0,
      "explanation": "AppLocker allows precise control over which applications users can run, preventing unauthorized installations while permitting system updates. SmartScreen warns against suspicious downloads but doesn’t enforce strict controls. UAC controls privilege elevation but can be bypassed. Software restrictions via Group Policy are less granular than AppLocker’s rules.",
      "examTip": "Implement AppLocker for robust application whitelisting in enterprise Windows environments."
    },
    {
      "id": 91,
      "question": "A Linux administrator needs to create a compressed archive of a directory for transfer. Which command accomplishes this using gzip compression?",
      "options": [
        "tar -czvf archive.tar.gz /path/to/directory",
        "zip -r archive.zip /path/to/directory",
        "gzip -r /path/to/directory",
        "tar -xvzf archive.tar.gz"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The tar -czvf command creates a compressed archive (.tar.gz) using gzip. zip -r creates a .zip archive but doesn’t use tar. gzip -r compresses files but doesn’t bundle them into a single archive. tar -xvzf extracts archives, not creates them.",
      "examTip": "Use 'tar -czvf' for creating compressed .tar.gz archives combining multiple files and directories."
    },
    {
      "id": 92,
      "question": "A user’s Windows 10 machine shows a 'No Boot Device Found' error after connecting an external hard drive. Other devices boot correctly. What should the technician check FIRST?",
      "options": [
        "The boot order in BIOS/UEFI settings.",
        "The partition table of the internal drive.",
        "The integrity of the external hard drive.",
        "The power connection to the internal hard drive."
      ],
      "correctAnswerIndex": 0,
      "explanation": "An incorrect boot order in BIOS/UEFI can cause the system to attempt booting from an external drive without an OS. Partition table or power issues would affect the internal drive regardless of the external connection. External drive integrity doesn’t impact the system’s boot sequence unless incorrectly prioritized.",
      "examTip": "Always confirm BIOS boot priority when external drives cause boot errors after connection."
    },
    {
      "id": 93,
      "question": "A technician needs to prevent a Windows 10 workstation from automatically installing driver updates via Windows Update. Which configuration path allows this change?",
      "options": [
        "System Properties > Hardware > Device Installation Settings",
        "Windows Update Settings > Advanced Options",
        "Group Policy Editor > Windows Components > Windows Update",
        "Device Manager > Driver Settings"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Device Installation Settings in System Properties control whether Windows Update can automatically install drivers. Windows Update settings control general updates but not specific driver installations. Group Policy can control updates enterprise-wide but is more complex. Device Manager allows manual driver management but doesn’t prevent auto-updates.",
      "examTip": "Access Device Installation Settings to control automatic driver updates on standalone Windows systems."
    },
    {
      "id": 94,
      "question": "A Linux server fails to boot after a kernel update. The administrator needs to boot into a previous working kernel. Which bootloader screen key should be pressed during startup on most distributions?",
      "options": [
        "Shift (or Esc for some distributions) to access the GRUB menu.",
        "Ctrl+Alt+Del to reload the boot process.",
        "F12 to select an alternate boot device.",
        "Tab to edit kernel parameters temporarily."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Pressing Shift or Esc during boot brings up the GRUB menu, allowing selection of a previous kernel. Ctrl+Alt+Del reboots the system. F12 selects boot devices but doesn’t provide kernel options. Tab edits kernel parameters but doesn’t display kernel versions for selection.",
      "examTip": "Use GRUB’s kernel selection to revert to a previously working Linux kernel after problematic updates."
    },
    {
      "id": 95,
      "question": "A user reports that their Windows 10 PC frequently shows 'Low Virtual Memory' warnings. Which step should the technician take FIRST to resolve the issue?",
      "options": [
        "Increase the size of the paging file in system settings.",
        "Upgrade the system’s physical RAM.",
        "Disable memory-intensive applications from startup.",
        "Run memory diagnostics to check for faulty RAM."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Increasing the paging file size provides immediate relief for virtual memory shortages. RAM upgrades improve physical memory but are hardware-dependent. Disabling startup applications reduces memory load but doesn’t directly increase virtual memory. Memory diagnostics detect faults but aren’t related to virtual memory configuration.",
      "examTip": "Adjust paging file settings first when addressing virtual memory warnings before considering hardware upgrades."
    },
    {
      "id": 96,
      "question": "A company requires that all mobile devices accessing corporate resources enforce data encryption. Which mobile security solution BEST meets this requirement?",
      "options": [
        "Mobile Device Management (MDM) with enforced encryption policies.",
        "User-configured encryption settings on each device.",
        "Installing third-party encryption apps on mobile devices.",
        "Requiring VPN usage for all mobile network connections."
      ],
      "correctAnswerIndex": 0,
      "explanation": "MDM allows centralized enforcement of encryption policies, ensuring consistency across devices. User-configured settings may be inconsistent. Third-party apps lack centralized management. VPNs encrypt network traffic, not device storage.",
      "examTip": "Implement MDM solutions to centrally manage and enforce mobile encryption for enterprise security."
    },
    {
      "id": 97,
      "question": "A Windows 10 PC experiences frequent 'Blue Screen of Death' (BSOD) errors after hardware upgrades. Which built-in tool can help identify hardware compatibility issues?",
      "options": [
        "Windows Memory Diagnostic",
        "Device Manager",
        "Reliability Monitor",
        "System Configuration (msconfig)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Windows Memory Diagnostic tests RAM for errors that often cause BSODs after hardware changes. Device Manager shows device status but doesn’t run diagnostics. Reliability Monitor tracks error history but doesn’t diagnose hardware. msconfig manages startup processes but doesn’t test hardware.",
      "examTip": "Run Windows Memory Diagnostic when BSOD errors suggest memory issues after hardware upgrades."
    },
    {
      "id": 98,
      "question": "A Linux administrator needs to monitor disk I/O performance in real-time on a production server. Which command provides the BEST output for this purpose?",
      "options": [
        "iostat",
        "df -h",
        "du -sh",
        "vmstat"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The iostat command provides real-time disk I/O statistics, essential for performance monitoring. df -h shows disk usage but not performance. du -sh summarizes directory sizes, not I/O data. vmstat reports system performance but focuses on memory and CPU rather than detailed disk I/O.",
      "examTip": "Use 'iostat' for detailed, real-time disk I/O statistics when diagnosing Linux server performance issues."
    },
    {
      "id": 99,
      "question": "A user reports that their Windows 10 system shows the error 'Operating System not found' after a BIOS update. The hard drive is functional. What should the technician check FIRST?",
      "options": [
        "BIOS boot order settings.",
        "Master Boot Record (MBR) integrity.",
        "Hard drive cable connections.",
        "UEFI Secure Boot configuration."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A BIOS update may reset boot order settings, preventing the system from booting the correct drive. MBR integrity issues would require repair tools if boot order is correct. Cable issues would prevent drive detection entirely. Secure Boot configurations affect OS validation but not basic detection.",
      "examTip": "Verify and correct boot order settings in BIOS after firmware updates that impact boot sequences."
    },
    {
      "id": 100,
      "question": "A user’s Windows 10 laptop fails to resume from sleep mode. The screen remains black, though power indicators are on. What is the MOST likely cause?",
      "options": [
        "Outdated graphics driver causing display issues.",
        "Corrupted system files preventing proper wake-up.",
        "Hard drive entering hibernation mode unexpectedly.",
        "Insufficient RAM preventing sleep recovery."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Outdated or incompatible graphics drivers commonly cause black screens after sleep due to display initialization failures. Corrupted system files typically cause boot issues, not wake failures. Hard drive hibernation affects storage states but not display resumption. RAM shortages impact performance, not sleep recovery directly.",
      "examTip": "Update graphics drivers when laptops fail to resume from sleep, presenting black screen issues."
    }
  ]
});
