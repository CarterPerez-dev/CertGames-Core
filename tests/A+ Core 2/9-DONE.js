db.tests.insertOne({
  "category": "aplus2",
  "testId": 9,
  "testName": "A+ Core 2 Practice Test #9 (Ruthless)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A Windows 11 laptop intermittently fails to authenticate to a WPA3-Enterprise wireless network. Logs indicate EAP-TLS handshake failures. Other devices authenticate without issue. What is the MOST likely cause?",
      "options": [
        "The client certificate on the laptop has expired or is missing.",
        "The wireless adapter does not support WPA3-Enterprise.",
        "The RADIUS server’s certificate has been revoked.",
        "Group Policy settings have disabled 802.1X authentication."
      ],
      "correctAnswerIndex": 0,
      "explanation": "EAP-TLS authentication failures typically occur when the client certificate is invalid, expired, or missing. If the wireless adapter lacked WPA3 support, the network wouldn’t be detected. A revoked RADIUS certificate would impact all users. Group Policy misconfigurations would prevent all authentication attempts, not cause intermittent failures.",
      "examTip": "Always verify client certificates and renewal schedules when troubleshooting EAP-TLS authentication issues."
    },
    {
      "id": 2,
      "question": "A Linux server shows frequent kernel panics after a recent kernel update. The administrator must restore stability immediately. What is the BEST immediate action?",
      "options": [
        "Reboot and select the previous stable kernel from the GRUB menu.",
        "Use 'yum downgrade kernel' to roll back the kernel version.",
        "Recompile the kernel with custom configurations.",
        "Perform a live patch to update kernel components."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Booting into a previously stable kernel via GRUB provides an immediate solution. Downgrading the kernel using package managers takes more time and may introduce additional dependencies. Kernel recompilation is complex and time-consuming. Live patches are typically for minor updates, not major instability issues.",
      "examTip": "Use GRUB to revert to a known good kernel before attempting more invasive rollback procedures."
    },
    {
      "id": 3,
      "question": "A user reports that BitLocker on their Windows 10 device asks for the recovery key after every reboot. TPM is enabled and functioning. What is the MOST likely cause?",
      "options": [
        "The boot order in BIOS/UEFI was altered after a firmware update.",
        "The BitLocker encryption key has been corrupted.",
        "A recent Windows update reset TPM ownership settings.",
        "Secure Boot was disabled, affecting boot measurement values."
      ],
      "correctAnswerIndex": 0,
      "explanation": "An altered boot order changes the TPM’s expected measurements, triggering BitLocker to request the recovery key. Key corruption would prevent decryption altogether. Resetting TPM ownership would prompt key backup processes. Secure Boot issues affect boot verification, not necessarily repeated recovery key prompts.",
      "examTip": "Always verify boot order after firmware updates to ensure TPM measurements match expected BitLocker configurations."
    },
    {
      "id": 4,
      "question": "A critical web application on a Linux server shows '502 Bad Gateway' errors. Nginx serves as a reverse proxy. What is the FIRST troubleshooting step?",
      "options": [
        "Check the status of the backend application server.",
        "Restart the Nginx service to reset proxy connections.",
        "Inspect Nginx configuration files for syntax errors.",
        "Review firewall rules blocking backend server ports."
      ],
      "correctAnswerIndex": 0,
      "explanation": "'502 Bad Gateway' errors generally indicate that Nginx cannot reach the upstream server. Confirming the backend server’s availability is the fastest initial check. Restarting Nginx doesn’t resolve upstream issues. Configuration errors would prevent Nginx from restarting rather than cause a 502 error. Firewall issues typically cause timeouts, not 502 errors.",
      "examTip": "Focus on backend server health when encountering 502 errors in reverse proxy setups like Nginx."
    },
    {
      "id": 5,
      "question": "A user’s Android device overheats and rapidly drains the battery after installing a specific app. What should the technician do FIRST?",
      "options": [
        "Check battery usage statistics for the specific app’s resource consumption.",
        "Force stop the application and clear its cache and data.",
        "Boot the device into safe mode to prevent third-party app execution.",
        "Check for system updates that may resolve compatibility issues."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Analyzing battery usage per app provides immediate insights into resource consumption. Force stopping or clearing cache addresses symptoms without understanding the cause. Safe mode disables all third-party apps but delays app-specific analysis. System updates help if OS compatibility is at fault but are secondary checks.",
      "examTip": "Always assess per-app battery statistics when troubleshooting overheating and rapid battery drain on Android."
    },
    {
      "id": 6,
      "question": "A Windows user reports slow performance and constant hard drive activity. Task Manager shows 'Windows Defender Antivirus' consuming high disk I/O. What is the MOST likely reason?",
      "options": [
        "A full system scan is running in the background.",
        "The hard drive is failing, causing excessive read retries.",
        "Windows Update is downloading large cumulative patches.",
        "The system is infected with malware avoiding detection."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Windows Defender performing a full system scan leads to high disk I/O. Drive failures would manifest in SMART warnings. Windows Update activity would show in its process. Malware avoiding detection would require broader behavioral signs, not just Defender activity.",
      "examTip": "Check for scheduled or active scans when Windows Defender shows high resource usage in Task Manager."
    },
    {
      "id": 7,
      "question": "A macOS user reports that Spotlight search fails to return recent documents. The indexing process shows incomplete progress. What command can the technician use to rebuild the Spotlight index?",
      "options": [
        "sudo mdutil -E /",
        "sudo diskutil verifyVolume /",
        "sudo fsck_hfs -fy /dev/disk1",
        "sudo launchctl load /System/Library/LaunchDaemons/com.apple.metadata.mds.plist"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'mdutil -E /' erases and rebuilds the Spotlight index. 'diskutil verifyVolume' checks disk integrity but doesn’t affect indexing. 'fsck_hfs' repairs file systems but isn’t related to metadata indexing. 'launchctl' manages system services but won’t rebuild the index directly.",
      "examTip": "Use 'mdutil -E' to reset and rebuild Spotlight indexes when search issues arise on macOS."
    },
    {
      "id": 8,
      "question": "A technician suspects that a Windows 10 system's performance issues are due to insufficient virtual memory. What should be checked FIRST?",
      "options": [
        "Paging file size settings in System Properties.",
        "Available physical RAM installed in the system.",
        "Background applications running in Task Manager.",
        "Disk health using CHKDSK."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Virtual memory relies on the paging file; incorrect size settings can cause performance degradation. RAM availability affects physical memory, but virtual memory issues persist regardless of installed RAM. Background processes impact CPU/RAM more directly. Disk health issues lead to broader system instability, not specifically virtual memory warnings.",
      "examTip": "Verify that Windows manages the paging file size automatically to prevent virtual memory errors."
    },
    {
      "id": 9,
      "question": "An administrator needs to configure a Linux server to retain only the last seven days of logs and compress older logs automatically. Which tool is BEST suited for this task?",
      "options": [
        "logrotate",
        "cron with gzip and find commands",
        "rsyslog with manual retention scripts",
        "systemd-journald with retention settings"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'logrotate' automates log rotation, compression, and retention based on specified timeframes. cron with gzip/find is functional but less efficient. rsyslog focuses on log storage and forwarding, not rotation. systemd-journald handles journal logs but lacks compression and flexible retention policies for external logs.",
      "examTip": "Use 'logrotate' for automated log management, including compression and retention policies on Linux."
    },
    {
      "id": 10,
      "question": "A user’s Windows 10 PC cannot access HTTPS websites but can access HTTP sites. DNS resolution works, and the firewall is not blocking ports. What is the MOST likely reason?",
      "options": [
        "Corrupted or missing root certificates on the user’s machine.",
        "The TLS/SSL protocols have been disabled in the browser settings.",
        "A proxy server is intercepting and blocking SSL connections.",
        "Outdated network drivers are causing packet loss on secure ports."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Missing or corrupted root certificates prevent SSL/TLS validation, breaking HTTPS connections while leaving HTTP unaffected. Disabling TLS/SSL in browsers affects secure connections globally but typically prompts user warnings. Proxy interception would impact multiple systems or generate proxy-specific errors. Outdated drivers would cause broader network instability.",
      "examTip": "Ensure root certificates are updated when HTTPS access fails despite proper network connectivity."
    },
    {
      "id": 11,
      "question": "A user’s Windows 11 machine displays frequent 'CRITICAL_PROCESS_DIED' BSOD errors. What is the MOST likely cause?",
      "options": [
        "Corrupted system files or failed updates affecting critical processes.",
        "Hardware failures in storage devices affecting OS operations.",
        "Malware infections corrupting essential process binaries.",
        "Faulty memory modules causing intermittent process crashes."
      ],
      "correctAnswerIndex": 0,
      "explanation": "'CRITICAL_PROCESS_DIED' BSOD errors usually result from essential Windows processes being terminated due to file corruption or failed updates. Hardware failures lead to different error codes. Malware and memory issues are possibilities but less common as primary causes for this specific BSOD.",
      "examTip": "Run SFC and DISM tools first when 'CRITICAL_PROCESS_DIED' BSOD errors occur after updates or system changes."
    },
    {
      "id": 12,
      "question": "An organization uses a Linux server as a web host. After a recent security update, the Apache web server fails to start. What is the MOST likely cause?",
      "options": [
        "Changes in SELinux policies preventing Apache from binding to ports.",
        "Corrupted SSL certificates after the update process.",
        "A syntax error in the Apache configuration file.",
        "Firewall rules resetting after the security update."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Security updates often adjust SELinux policies, preventing services from accessing required ports. Corrupted certificates would generate TLS errors rather than prevent Apache from starting. Syntax errors cause Apache to fail configuration tests before starting, unrelated to updates. Firewall resets would block access but wouldn’t stop service initiation.",
      "examTip": "Check SELinux contexts and permissions when services fail post-security updates on Linux systems."
    },
    {
      "id": 13,
      "question": "A macOS user reports kernel panic errors after installing a third-party kernel extension. What is the FIRST troubleshooting step?",
      "options": [
        "Boot into Safe Mode and remove the problematic extension.",
        "Perform an NVRAM reset to restore default hardware settings.",
        "Reinstall macOS to ensure system integrity.",
        "Run First Aid from Disk Utility to check for file system errors."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Safe Mode disables non-essential kernel extensions, allowing for their removal. NVRAM resets address hardware configuration issues, not kernel extensions. Reinstalling macOS is excessive for extension-related issues. Disk Utility checks don’t impact kernel module integrity.",
      "examTip": "Use Safe Mode to isolate and remove faulty kernel extensions causing kernel panics on macOS."
    },
    {
      "id": 14,
      "question": "A Windows system fails to boot with a 'BOOTMGR is missing' error after adding a secondary hard drive. What should the technician check FIRST?",
      "options": [
        "Boot order settings in BIOS/UEFI.",
        "Rebuild the master boot record (MBR).",
        "Run the Startup Repair tool from recovery options.",
        "Disconnect the secondary drive and reboot."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Adding a new hard drive can change boot priorities. Verifying boot order ensures the correct drive is selected. Rebuilding MBR or running Startup Repair are valid but more time-consuming. Disconnecting the drive may help temporarily but doesn’t address the underlying boot sequence issue.",
      "examTip": "Check and correct BIOS/UEFI boot order first when boot errors occur after hardware additions."
    },
    {
      "id": 15,
      "question": "A user’s Linux laptop randomly suspends while connected to AC power. Which setting is MOST likely misconfigured?",
      "options": [
        "Power management settings for AC power mode.",
        "System sleep timer set too low for active sessions.",
        "Display manager session settings overriding default policies.",
        "Kernel power management modules causing suspend triggers."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Power management settings may be incorrectly set to suspend even when connected to AC power. Sleep timers typically apply when idle. Display manager settings usually affect login sessions, not system suspension. Kernel modules rarely cause such behavior unless misconfigured at a low level.",
      "examTip": "Review power management profiles to ensure proper behavior when connected to AC power on Linux systems."
    },
    {
      "id": 16,
      "question": "A Windows 10 machine with TPM-enabled BitLocker requests a recovery key after BIOS/UEFI updates. How can future recovery prompts be prevented during firmware updates?",
      "options": [
        "Suspend BitLocker protection before applying firmware updates.",
        "Disable TPM ownership before firmware updates and re-enable after.",
        "Export the BitLocker recovery key and store it locally.",
        "Configure Secure Boot policies to bypass TPM measurement changes."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Suspending BitLocker prevents TPM measurement discrepancies during firmware updates. Disabling TPM ownership adds unnecessary complexity. Locally storing recovery keys is risky and doesn’t prevent prompts. Secure Boot doesn’t affect TPM measurement behaviors related to BitLocker.",
      "examTip": "Always suspend BitLocker before firmware updates to avoid unnecessary recovery key prompts post-update."
    },
    {
      "id": 17,
      "question": "A technician observes that after upgrading a Linux kernel, certain hardware drivers no longer function. What is the MOST likely cause?",
      "options": [
        "The new kernel lacks support for specific third-party modules.",
        "System firmware (BIOS/UEFI) is incompatible with the new kernel.",
        "Persistent kernel parameters were overwritten during the update.",
        "Hardware components require updated firmware after kernel changes."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Kernel updates may omit third-party drivers requiring manual recompilation. Firmware incompatibility typically prevents booting, not driver functionality. Kernel parameters affect behavior, not hardware driver compatibility. Hardware firmware updates are unrelated unless specifically documented by manufacturers.",
      "examTip": "After kernel upgrades, recompile third-party drivers or install updated modules to restore hardware functionality."
    },
    {
      "id": 18,
      "question": "A user’s mobile device repeatedly prompts for authentication when accessing a corporate VPN. The VPN uses IKEv2 with EAP-MSCHAPv2. What is the MOST likely cause?",
      "options": [
        "Incorrect user credentials or expired passwords.",
        "Outdated VPN client software on the mobile device.",
        "The mobile OS version lacks support for IKEv2 protocols.",
        "VPN server certificate validation issues on the client device."
      ],
      "correctAnswerIndex": 0,
      "explanation": "EAP-MSCHAPv2 requires correct credentials for authentication. Expired passwords trigger repeated prompts. Outdated clients would fail outright, not loop prompts. Protocol support issues prevent connection attempts entirely. Certificate validation issues would result in explicit trust warnings, not repeated prompts.",
      "examTip": "Validate user credentials and password expiration policies when troubleshooting repeated VPN authentication prompts."
    },
    {
      "id": 19,
      "question": "A Windows 10 user reports slow access to network shares. Ping tests show low latency, but file transfers are slow. What should the technician check NEXT?",
      "options": [
        "Network adapter duplex settings on both client and server.",
        "SMB signing settings affecting file transfer performance.",
        "DNS resolution times for the file server’s hostname.",
        "Client-side antivirus scanning network shares in real time."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Duplex mismatches between NICs and switches can cause slow data transfer despite low latency. SMB signing impacts performance but would typically affect all users. DNS resolution issues cause connection failures, not slow transfers. Antivirus scanning impacts performance but wouldn’t consistently cause slow transfers if configured correctly.",
      "examTip": "Check for duplex mismatches when file transfers are slow but network latency appears normal."
    },
    {
      "id": 20,
      "question": "A Linux administrator needs to ensure that critical system services restart automatically if they fail. Which systemd configuration should be used?",
      "options": [
        "Set 'Restart=always' in the service’s unit file.",
        "Configure a cron job to monitor and restart services.",
        "Enable watchdog timers for all system-critical services.",
        "Create custom bash scripts with looped service restart logic."
      ],
      "correctAnswerIndex": 0,
      "explanation": "'Restart=always' in a systemd unit file ensures automatic service restarts after failure. Cron jobs are inefficient for real-time monitoring. Watchdog timers detect hangs, not necessarily service failures. Custom scripts introduce unnecessary complexity compared to systemd’s native features.",
      "examTip": "Use 'Restart=always' in systemd unit files for reliable, automatic service recovery after unexpected failures."
    },
    {
      "id": 21,
      "question": "A user reports that their Windows 11 system intermittently freezes after waking from sleep. The Event Viewer shows kernel power errors. What is the MOST likely cause?",
      "options": [
        "Outdated chipset drivers affecting power management.",
        "Corrupted system files impacting resume processes.",
        "Faulty RAM causing instability after wake.",
        "A misconfigured BIOS setting for ACPI support."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Kernel power errors related to wake issues often result from outdated chipset drivers that handle power management functions. Corrupted system files typically cause broader stability issues. Faulty RAM leads to random crashes, not specifically after sleep. ACPI misconfigurations generally prevent sleep altogether, not cause freezes after waking.",
      "examTip": "Update chipset drivers when addressing power-related kernel errors, especially after sleep or hibernation events."
    },
    {
      "id": 22,
      "question": "A Linux server’s SSH service becomes unresponsive after several failed login attempts. What is the MOST likely cause?",
      "options": [
        "Fail2ban has triggered and temporarily blocked access.",
        "The SSH daemon crashed due to excessive connections.",
        "SELinux is preventing SSH from running correctly.",
        "The firewall dynamically blocked SSH traffic."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Fail2ban is commonly used to block IPs after repeated failed login attempts, preventing brute-force attacks. An SSH daemon crash would typically show relevant logs. SELinux would block SSH from starting, not from accepting new connections. Dynamic firewall rules rarely apply without explicit configuration.",
      "examTip": "Check Fail2ban and similar security tools when SSH access becomes unavailable following failed login attempts."
    },
    {
      "id": 23,
      "question": "A user reports that their macOS system fails to recognize external USB drives. The drives function on other systems. What should the technician check FIRST?",
      "options": [
        "Reset the SMC (System Management Controller).",
        "Verify Finder preferences for external drives visibility.",
        "Run First Aid in Disk Utility for potential file system errors.",
        "Check system logs for USB device detection failures."
      ],
      "correctAnswerIndex": 1,
      "explanation": "If external drives are not visible in Finder, the visibility setting may be disabled. Resetting the SMC helps with hardware-level issues but is a broader step. Disk Utility is used for repairing recognized drives. Reviewing logs is useful but less immediate than checking user interface settings.",
      "examTip": "Always verify Finder settings when external drives are not appearing on macOS before proceeding with deeper diagnostics."
    },
    {
      "id": 24,
      "question": "A Linux administrator notices that a critical service fails after reboot but can be started manually without errors. What is the MOST likely cause?",
      "options": [
        "The systemd service file lacks the 'WantedBy=multi-user.target' directive.",
        "SELinux policies are preventing the service from starting automatically.",
        "Dependency services are loading after the critical service.",
        "The service requires elevated privileges not granted at startup."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Without the 'WantedBy=multi-user.target' directive, systemd services won’t start automatically during boot. SELinux issues would prevent both manual and automatic starts. Dependency issues would cause delayed starts but would appear in logs. Privilege issues would prevent the service from starting manually as well.",
      "examTip": "Ensure systemd service files include the appropriate 'WantedBy' directive for automatic startup."
    },
    {
      "id": 25,
      "question": "A Windows 10 laptop with BitLocker enabled requests a recovery key after hardware changes. How can future prompts be prevented during hardware upgrades?",
      "options": [
        "Suspend BitLocker before making hardware changes.",
        "Disable TPM in BIOS/UEFI before upgrades and re-enable after.",
        "Export and store the recovery key locally for reuse.",
        "Reset Secure Boot settings to default before hardware changes."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Suspending BitLocker prevents TPM measurement changes from triggering recovery key prompts during hardware upgrades. Disabling TPM affects more than just BitLocker and adds complexity. Storing the key locally introduces security risks. Secure Boot settings are unrelated to BitLocker TPM measurements.",
      "examTip": "Always suspend BitLocker before hardware upgrades to avoid unnecessary recovery key requests."
    },
    {
      "id": 26,
      "question": "A user reports slow file transfers on a wired Windows network. Pings to the file server show normal latency. What should the technician check NEXT?",
      "options": [
        "Verify network adapter duplex settings for mismatches.",
        "Inspect DNS resolution times for the file server’s hostname.",
        "Review SMB protocol versions enabled on the server.",
        "Check for local firewall rules throttling network performance."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Duplex mismatches between network interfaces and switches can significantly slow file transfers without affecting latency. DNS resolution issues would impact connectivity. SMB version mismatches cause compatibility errors, not slowness. Firewall throttling would affect all traffic, not just file transfers.",
      "examTip": "Always check duplex settings on network interfaces when facing slow file transfers despite normal latency readings."
    },
    {
      "id": 27,
      "question": "A Windows 11 system cannot complete updates due to insufficient disk space. The user has cleared temporary files but still lacks enough space. What should be done NEXT?",
      "options": [
        "Move personal files to external storage or cloud services.",
        "Perform a disk cleanup targeting system files and update caches.",
        "Extend the system partition using Disk Management.",
        "Run the Windows Update Troubleshooter for advanced diagnostics."
      ],
      "correctAnswerIndex": 1,
      "explanation": "System file cleanup removes old updates and system restore files, freeing significant space. Moving personal files helps but is less impactful for update-specific space issues. Extending partitions is more complex and may not be feasible. The troubleshooter addresses functional issues, not storage limitations.",
      "examTip": "Target system files and update caches using Disk Cleanup for effective space recovery during Windows updates."
    },
    {
      "id": 28,
      "question": "A Linux server experiences frequent SSH session timeouts. The network is stable. What configuration change can reduce these timeouts?",
      "options": [
        "Set 'ClientAliveInterval' and 'ClientAliveCountMax' in sshd_config.",
        "Increase TCP keepalive timeouts in the kernel configuration.",
        "Configure iptables to allow longer SSH session durations.",
        "Enable SSH compression to reduce session data size."
      ],
      "correctAnswerIndex": 0,
      "explanation": "'ClientAliveInterval' and 'ClientAliveCountMax' prevent SSH sessions from timing out by sending periodic messages. TCP keepalive changes affect broader connections. iptables adjustments handle traffic control, not session longevity. Compression reduces data size but doesn’t impact timeout behavior.",
      "examTip": "Adjust 'ClientAliveInterval' in sshd_config to maintain persistent SSH sessions and avoid timeouts."
    },
    {
      "id": 29,
      "question": "A user’s Windows PC cannot access internal resources by hostname but can by IP address. What is the MOST likely cause?",
      "options": [
        "Incorrect DNS server settings on the client device.",
        "A misconfigured DHCP scope option for DNS suffixes.",
        "Corrupted local DNS resolver cache.",
        "Firewall rules blocking DNS traffic on the client."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Incorrect DNS server settings prevent hostname resolution. DHCP misconfigurations impact domain appending but wouldn’t block known hostnames. DNS cache corruption causes isolated issues but is easily cleared. Firewall DNS blocks would prevent all hostname resolution, including external sites.",
      "examTip": "Ensure DNS server settings are correct when internal hostname resolution fails despite IP connectivity."
    },
    {
      "id": 30,
      "question": "A macOS user reports the system takes longer to boot after enabling FileVault encryption. The Mac uses a traditional HDD. What is the MOST likely cause?",
      "options": [
        "Disk encryption overhead slowing read/write operations on HDDs.",
        "The encryption key retrieval process requires network access at boot.",
        "Firmware incompatibility with FileVault causing decryption delays.",
        "A partial encryption process still running during system startup."
      ],
      "correctAnswerIndex": 0,
      "explanation": "FileVault introduces encryption overhead, especially noticeable on slower HDDs. Network-based key retrieval is not typical for FileVault. Firmware issues would prevent booting, not slow it. Partial encryption would show explicit status notifications.",
      "examTip": "Consider upgrading to SSDs when enabling FileVault encryption to mitigate boot performance degradation."
    },
    {
      "id": 31,
      "question": "A Linux administrator needs to configure a service to restart automatically if it crashes. Which systemd configuration directive should be used?",
      "options": [
        "Restart=always",
        "ExecReload",
        "RestartSec",
        "RemainAfterExit=yes"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'Restart=always' ensures the service restarts automatically after failure. 'ExecReload' specifies how to reload without restarting. 'RestartSec' defines delay intervals but doesn’t enable restarts. 'RemainAfterExit' keeps the service status active without ensuring restarts.",
      "examTip": "Use 'Restart=always' in systemd service files for automatic recovery from unexpected service failures."
    },
    {
      "id": 32,
      "question": "A Windows 10 machine fails to access HTTPS sites but can access HTTP. The firewall and proxy settings are correct. What is the MOST likely cause?",
      "options": [
        "Corrupted or missing root certificates.",
        "Disabled TLS protocols in browser settings.",
        "Outdated browser lacking modern encryption support.",
        "Expired SSL certificates on external websites."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Missing or corrupted root certificates prevent HTTPS validation. Browser TLS settings and outdated versions would cause widespread issues, not selective failures. Expired external certificates would impact specific sites, not all HTTPS access.",
      "examTip": "Verify root certificate integrity when HTTPS access fails while HTTP remains functional."
    },
    {
      "id": 33,
      "question": "A technician needs to ensure Linux system logs older than 30 days are automatically deleted. Which tool is BEST suited for this task?",
      "options": [
        "logrotate",
        "cron with find command",
        "systemd-journald",
        "rsyslog configuration"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'logrotate' automates log rotation and deletion based on retention policies. Cron with find achieves similar results but lacks integrated management. systemd-journald manages journal logs only. rsyslog forwards logs but doesn’t handle deletion.",
      "examTip": "Configure 'logrotate' for automated log management and retention on Linux systems."
    },
    {
      "id": 34,
      "question": "A Windows 11 user reports that their machine enters BitLocker recovery mode after every reboot. TPM and Secure Boot are enabled. What is the MOST likely reason?",
      "options": [
        "Firmware updates altered TPM measurements.",
        "Corrupted BitLocker encryption keys.",
        "The boot partition was resized incorrectly.",
        "Group Policy mandates recovery key authentication."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Firmware updates change TPM measurements, triggering BitLocker recovery. Corrupted keys prevent decryption altogether. Boot partition resizing would show boot errors. Group Policy settings typically prompt during configuration, not after every reboot.",
      "examTip": "Suspend BitLocker before firmware updates to avoid repeated recovery prompts caused by TPM measurement changes."
    },
    {
      "id": 35,
      "question": "A user’s Android device uses excessive mobile data, despite Wi-Fi being available. What should the technician check FIRST?",
      "options": [
        "Background data settings for the affected apps.",
        "Wi-Fi assist features that switch to mobile data.",
        "Mobile data limits and warnings in device settings.",
        "App update settings allowing downloads over mobile data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Wi-Fi assist switches to mobile data during weak Wi-Fi signals, increasing mobile data usage. Background data settings impact overall data usage but wouldn’t override Wi-Fi. Data limits provide notifications, not control. App update settings typically apply during store updates only.",
      "examTip": "Disable Wi-Fi assist features on mobile devices to prevent unnecessary mobile data consumption."
    },
    {
      "id": 36,
      "question": "A user reports slow application launches on a Windows 10 machine. Resource usage appears normal. What should the technician check NEXT?",
      "options": [
        "Corruption in the application’s prefetch files.",
        "Startup impact scores in Task Manager.",
        "Event Viewer for application-specific error logs.",
        "Hard drive health using SMART status checks."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Corrupted prefetch files delay application launches by affecting cached loading optimizations. Startup impact affects boot performance, not application launch times. Event Viewer errors provide clues but don’t directly resolve performance issues. SMART checks detect hardware issues unrelated to specific application performance.",
      "examTip": "Clear and rebuild prefetch files to restore optimal application launch speeds on Windows systems."
    },
    {
      "id": 37,
      "question": "A Linux server’s web application shows 502 Bad Gateway errors. Nginx is acting as a reverse proxy. What is the FIRST troubleshooting step?",
      "options": [
        "Verify that the upstream application server is running and reachable.",
        "Restart Nginx to refresh proxy connections.",
        "Check Nginx configuration files for syntax errors.",
        "Review firewall rules between Nginx and the backend server."
      ],
      "correctAnswerIndex": 0,
      "explanation": "502 errors often occur when the proxy server cannot reach the upstream application. Restarting Nginx addresses connection issues only if the backend is functional. Syntax errors would prevent Nginx from running at all. Firewall issues would typically cause timeouts, not 502 errors.",
      "examTip": "When troubleshooting 502 errors in Nginx setups, confirm upstream server availability first."
    },
    {
      "id": 38,
      "question": "A user’s Windows 10 laptop cannot connect to a VPN using L2TP/IPSec. The error states 'Negotiation failed.' What is the MOST likely cause?",
      "options": [
        "UDP ports 500 and 4500 are blocked by a firewall.",
        "The VPN client’s configuration file is corrupted.",
        "The VPN server’s certificate has expired.",
        "The user’s network adapter drivers are outdated."
      ],
      "correctAnswerIndex": 0,
      "explanation": "L2TP/IPSec requires UDP ports 500 and 4500 for key exchange. Blocking these ports causes negotiation failures. Corrupted configurations produce different error messages. Certificate issues cause authentication errors. Driver problems generally affect overall connectivity, not specifically VPN negotiation.",
      "examTip": "Ensure firewall settings allow UDP ports 500 and 4500 when configuring L2TP/IPSec VPN connections."
    },
    {
      "id": 39,
      "question": "A Linux administrator needs to configure SSH for key-based authentication only, disabling password logins. Which configuration change is required?",
      "options": [
        "Set 'PasswordAuthentication no' in sshd_config.",
        "Change 'PermitRootLogin' to 'without-password'.",
        "Enable 'ChallengeResponseAuthentication' in sshd_config.",
        "Disable 'UsePAM' in the SSH server configuration."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Disabling 'PasswordAuthentication' ensures that only key-based authentication is accepted. Changing 'PermitRootLogin' affects root access only. 'ChallengeResponseAuthentication' manages alternative methods like two-factor. Disabling 'UsePAM' impacts authentication management but is not required to disable passwords.",
      "examTip": "Set 'PasswordAuthentication no' in sshd_config to enforce SSH key-based authentication exclusively."
    },
    {
      "id": 40,
      "question": "A user reports that their Windows 11 PC frequently freezes during intensive tasks. Memory tests pass without errors. What should the technician check NEXT?",
      "options": [
        "Check CPU temperatures and cooling system performance.",
        "Analyze disk performance for read/write bottlenecks.",
        "Inspect power supply voltages for irregularities.",
        "Review Windows Event Viewer for hardware-related logs."
      ],
      "correctAnswerIndex": 0,
      "explanation": "High CPU temperatures during intensive tasks can cause system freezes due to thermal throttling. Disk performance issues manifest as slowdowns, not freezes. Power supply irregularities typically cause reboots or shutdowns. Event Viewer analysis is useful but less immediate than checking hardware temperatures.",
      "examTip": "Monitor CPU temperatures and ensure effective cooling when troubleshooting freezes during high workloads."
    },
    {
      "id": 41,
      "question": "A Linux server using systemd fails to start a critical service during boot. Manual service start works without issues. What is the MOST likely cause?",
      "options": [
        "Missing 'After=network.target' dependency in the service unit file.",
        "SELinux preventing the service from running at boot.",
        "Corrupted service binary requiring reinstallation.",
        "File system corruption delaying service initialization."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A missing 'After=network.target' line causes systemd to start services before networking is ready, leading to boot-time failures. SELinux would prevent manual starts as well. Corrupted binaries fail in all contexts. File system issues impact overall boot time, not just a specific service.",
      "examTip": "Add 'After=network.target' in systemd unit files for services that depend on network readiness at boot."
    },
    {
      "id": 42,
      "question": "A macOS user cannot install applications from third-party developers due to Gatekeeper restrictions. What is the MOST secure way to enable installation temporarily?",
      "options": [
        "Right-click the application and select 'Open' to bypass Gatekeeper for this instance.",
        "Disable Gatekeeper entirely using 'sudo spctl --master-disable'.",
        "Modify system preferences to allow apps from 'Anywhere' permanently.",
        "Run the application using Terminal with sudo privileges."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Right-clicking and selecting 'Open' bypasses Gatekeeper for the specific app without weakening system-wide security. Disabling Gatekeeper or allowing apps from anywhere reduces overall security. Using sudo in Terminal doesn't bypass Gatekeeper policies effectively.",
      "examTip": "Bypass Gatekeeper per app by using 'Open' from the context menu for safer third-party app installations on macOS."
    },
    {
      "id": 43,
      "question": "A Windows 11 user cannot access any HTTPS websites, though HTTP works fine. The system time is correct. What is the MOST likely cause?",
      "options": [
        "Corrupted or missing root certificates on the system.",
        "Misconfigured proxy server intercepting SSL connections.",
        "Disabled TLS protocols in the browser settings.",
        "Outdated network adapter drivers causing secure connection failures."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Root certificate issues break HTTPS validation while leaving HTTP unaffected. Proxy misconfigurations usually affect both HTTP and HTTPS. Disabled TLS would cause specific browser warnings. Outdated drivers impact broader network functionality, not solely HTTPS traffic.",
      "examTip": "Update root certificates or reinstall trusted certificate authorities when HTTPS access fails despite proper time settings."
    },
    {
      "id": 44,
      "question": "A Linux administrator needs to ensure SSH connections persist despite intermittent network issues. Which SSH client option achieves this?",
      "options": [
        "Use 'ServerAliveInterval' and 'ServerAliveCountMax' in SSH configuration.",
        "Enable TCP keepalives at the kernel level.",
        "Configure 'PermitKeepAlive' in the SSH server configuration.",
        "Set up autossh to handle automatic reconnections."
      ],
      "correctAnswerIndex": 0,
      "explanation": "'ServerAliveInterval' and 'ServerAliveCountMax' send keepalive messages from the client, maintaining the connection. TCP keepalives require kernel tuning, which is broader than SSH needs. 'PermitKeepAlive' is not a valid server directive. autossh handles reconnections but doesn't maintain an existing session during minor outages.",
      "examTip": "Set 'ServerAliveInterval' and 'ServerAliveCountMax' in SSH client settings to prevent session drops due to temporary network disruptions."
    },
    {
      "id": 45,
      "question": "A Windows 10 machine fails to boot, displaying 'Operating System not found.' What should the technician check FIRST?",
      "options": [
        "Verify boot order settings in BIOS/UEFI.",
        "Rebuild the master boot record using recovery tools.",
        "Check disk health using SMART diagnostics.",
        "Disconnect external drives to avoid boot conflicts."
      ],
      "correctAnswerIndex": 0,
      "explanation": "The most common cause is incorrect boot order settings pointing to non-bootable devices. Rebuilding the MBR or running diagnostics are valid secondary steps. Disconnecting peripherals helps but isn't the most direct initial solution.",
      "examTip": "Always verify BIOS/UEFI boot priority before deeper troubleshooting when OS not found errors occur."
    },
    {
      "id": 46,
      "question": "A Linux server shows high disk I/O wait times but normal CPU and memory usage. What is the MOST likely cause?",
      "options": [
        "A failing disk causing slow read/write operations.",
        "Inadequate swap space utilization by processes.",
        "Heavy network traffic leading to disk bottlenecks.",
        "Improper filesystem mounting options reducing performance."
      ],
      "correctAnswerIndex": 0,
      "explanation": "High I/O wait times indicate disk-level issues, often from failing drives. Swap space issues affect memory, not I/O wait specifically. Network traffic doesn't impact local disk performance. Filesystem mounting options typically degrade performance uniformly, not cause sudden I/O spikes.",
      "examTip": "Check disk health using 'smartctl' or 'iostat' when high disk I/O wait times occur without CPU or memory issues."
    },
    {
      "id": 47,
      "question": "A user’s Android device drains battery rapidly after installing a new app. What should the technician do FIRST?",
      "options": [
        "Review battery usage statistics to confirm the app’s resource consumption.",
        "Clear the app’s cache and force stop it.",
        "Check app permissions for excessive background activity.",
        "Uninstall and reinstall the app from a trusted source."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Battery usage statistics reveal if the app is responsible for excessive consumption. Force stopping or clearing cache addresses symptoms, not causes. Checking permissions is useful but secondary. Reinstallation helps if corruption is suspected but isn't the immediate next step.",
      "examTip": "Always start with battery usage data to identify resource-heavy apps causing battery drain issues."
    },
    {
      "id": 48,
      "question": "A macOS system shows slow performance, and Activity Monitor reveals high kernel_task CPU usage. What is the MOST likely cause?",
      "options": [
        "Thermal throttling triggered by high system temperatures.",
        "Malicious background processes consuming system resources.",
        "Insufficient RAM forcing excessive swap file usage.",
        "Corrupted macOS system files requiring reinstallation."
      ],
      "correctAnswerIndex": 0,
      "explanation": "kernel_task high CPU usage is often linked to thermal management processes reducing system temperature. Malware or RAM issues manifest differently. System file corruption would cause broader operational issues beyond kernel_task spikes.",
      "examTip": "Check for dust buildup or cooling issues when kernel_task shows high CPU utilization on macOS systems."
    },
    {
      "id": 49,
      "question": "A Windows system displays 'BOOTMGR is missing' after adding a new hard drive. What is the MOST likely cause?",
      "options": [
        "BIOS/UEFI boot order now prioritizes the new non-bootable drive.",
        "The boot partition on the primary drive was accidentally deleted.",
        "The system drive’s MBR has become corrupted.",
        "A SATA cable to the boot drive has become disconnected."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Adding a new drive often changes the boot order, causing the system to attempt booting from a non-bootable disk. Partition deletion or MBR corruption would require more extensive recovery. A disconnected SATA cable would result in the drive not being detected at all.",
      "examTip": "Verify boot priorities in BIOS after hardware changes, especially when boot errors reference missing boot managers."
    },
    {
      "id": 50,
      "question": "A Linux administrator wants to ensure that log files are compressed after a week and deleted after a month. Which tool BEST achieves this?",
      "options": [
        "logrotate with appropriate configuration settings.",
        "cron jobs using gzip and rm commands for manual control.",
        "systemd-journald configured with log retention settings.",
        "rsyslog with custom scripting for compression and deletion."
      ],
      "correctAnswerIndex": 0,
      "explanation": "logrotate automates log rotation, compression, and deletion with minimal overhead. Cron jobs offer flexibility but require manual scripting. systemd-journald handles only journal logs. rsyslog focuses on log forwarding, not lifecycle management.",
      "examTip": "Use logrotate for automated log management, specifying compression and retention policies in its configuration file."
    },
    {
      "id": 51,
      "question": "A Windows 10 machine cannot connect to any VPN using L2TP/IPSec. The error indicates 'negotiation failed.' What is the MOST likely cause?",
      "options": [
        "UDP ports 500 and 4500 are blocked by a firewall.",
        "The VPN server certificate has expired.",
        "The VPN client configuration file is corrupted.",
        "Network adapter drivers require updates."
      ],
      "correctAnswerIndex": 0,
      "explanation": "L2TP/IPSec relies on UDP ports 500 and 4500 for key exchange. Firewall blocks on these ports result in negotiation failures. Expired certificates would produce authentication errors. Configuration file corruption leads to immediate connection errors. Outdated drivers impact overall connectivity, not just VPNs.",
      "examTip": "Ensure firewall rules permit UDP ports 500 and 4500 when configuring L2TP/IPSec VPN connections."
    },
    {
      "id": 52,
      "question": "A Linux system’s SSH connections drop after five minutes of inactivity. How can persistent sessions be maintained?",
      "options": [
        "Configure 'ClientAliveInterval' and 'ClientAliveCountMax' in sshd_config.",
        "Enable TCP keepalive settings in the kernel configuration.",
        "Switch from SSH to persistent Mosh sessions for terminal access.",
        "Configure firewall rules to allow longer connection persistence."
      ],
      "correctAnswerIndex": 0,
      "explanation": "'ClientAliveInterval' and 'ClientAliveCountMax' prevent SSH timeouts by sending periodic keepalive messages. Kernel TCP settings address broader network behavior. Mosh is an alternative but not a fix for SSH. Firewall adjustments would only help if session drops resulted from timeout policies.",
      "examTip": "Set appropriate keepalive intervals in SSH server configuration to maintain long-lived connections."
    },
    {
      "id": 53,
      "question": "A Windows 11 machine frequently prompts for BitLocker recovery keys after reboot. TPM is enabled and functioning. What could prevent future prompts?",
      "options": [
        "Suspending BitLocker before firmware updates.",
        "Disabling TPM prior to system restarts.",
        "Exporting recovery keys to a secure USB drive.",
        "Resetting Secure Boot policies to factory defaults."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Firmware updates alter TPM measurements, triggering BitLocker recovery prompts. Suspending BitLocker before updates avoids these prompts. Disabling TPM disrupts other security features. Exporting recovery keys doesn’t prevent future prompts. Secure Boot policies don’t affect TPM measurement discrepancies.",
      "examTip": "Suspend BitLocker protection before firmware updates to avoid repeated recovery key prompts after system restarts."
    },
    {
      "id": 54,
      "question": "A user reports that after changing their Windows password, mapped network drives fail to reconnect. What is the MOST likely cause?",
      "options": [
        "Cached credentials no longer match the new password.",
        "Network drive permissions were reset after the password change.",
        "Group Policy objects (GPOs) prevent drive mapping for password changes.",
        "DNS resolution issues are preventing access to the file server."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Windows stores credentials for mapped drives. Password changes invalidate these cached credentials, requiring manual updates. Permission resets are rare unless configured. GPOs typically enforce drive mappings rather than restrict them post-password change. DNS issues affect connectivity broadly, not just mapped drives.",
      "examTip": "After password changes, ensure cached credentials for network drives are updated to match new authentication details."
    },
    {
      "id": 55,
      "question": "A Linux administrator observes that user processes fail due to insufficient open file descriptors. How can this issue be resolved?",
      "options": [
        "Increase the 'nofile' limit in '/etc/security/limits.conf'.",
        "Raise 'ulimit' values dynamically for user sessions.",
        "Edit '/proc/sys/fs/file-max' for global file descriptor limits.",
        "Adjust systemd service files with 'LimitNOFILE' parameters."
      ],
      "correctAnswerIndex": 0,
      "explanation": "'nofile' in 'limits.conf' sets user-level open file limits persistently. 'ulimit' changes are session-based. Modifying 'file-max' affects global kernel settings, not per-user limits. 'LimitNOFILE' applies to systemd services, not general user processes.",
      "examTip": "Modify '/etc/security/limits.conf' for persistent user-level open file descriptor limit adjustments on Linux systems."
    },
    {
      "id": 56,
      "question": "A user reports their Windows 11 laptop has slow boot times after enabling full-disk encryption with BitLocker. The laptop uses an HDD. What is the MOST likely cause?",
      "options": [
        "Full-disk encryption overhead slowing read/write operations on HDDs.",
        "Encryption key retrieval delays due to TPM misconfiguration.",
        "Corrupted boot sector requiring recovery procedures.",
        "Secure Boot conflicts with BitLocker encryption during startup."
      ],
      "correctAnswerIndex": 0,
      "explanation": "BitLocker encryption adds processing overhead, especially noticeable on slower HDDs. TPM issues typically prompt for recovery keys. Boot sector corruption prevents booting altogether. Secure Boot conflicts cause boot failures, not delays.",
      "examTip": "Consider SSD upgrades for systems with full-disk encryption to reduce boot times caused by encryption overhead."
    },
    {
      "id": 57,
      "question": "A Linux administrator needs to configure a cron job to run a script at 1 AM on the first day of every month. What crontab entry is correct?",
      "options": [
        "0 1 1 * * /path/to/script.sh",
        "0 1 * * 1 /path/to/script.sh",
        "0 1 1 1 * /path/to/script.sh",
        "0 1 */1 * * /path/to/script.sh"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'0 1 1 * *' schedules the script at 1 AM on the first day of each month. '0 1 * * 1' runs every Monday at 1 AM. '0 1 1 1 *' runs only on January 1. '*/1' implies daily execution, not monthly.",
      "examTip": "Use the proper day and month fields in crontab for precise monthly scheduling requirements."
    },
    {
      "id": 58,
      "question": "A user reports slow access to shared network drives after a hostname change. Pings by IP succeed, but hostname pings fail. What is the MOST likely cause?",
      "options": [
        "DNS records have not been updated to reflect the new hostname.",
        "The DHCP server is still associating the old hostname with the client’s IP.",
        "WINS server entries were not refreshed after the hostname change.",
        "Local DNS resolver cache needs to be flushed on the client device."
      ],
      "correctAnswerIndex": 0,
      "explanation": "DNS records must be updated when hostnames change to ensure proper resolution. DHCP typically handles IP assignments, not DNS updates. WINS is legacy and unlikely in modern environments. Local cache flushing helps if DNS updates are complete but doesn’t solve missing records.",
      "examTip": "Ensure DNS records are refreshed following hostname changes to maintain consistent network resource accessibility."
    },
    {
      "id": 59,
      "question": "A Linux administrator needs to monitor real-time CPU usage per process. Which command is BEST suited for this purpose?",
      "options": [
        "top",
        "htop",
        "ps aux --sort=-%cpu",
        "vmstat 1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'top' provides real-time CPU usage per process and is available on most Linux distributions. 'htop' offers enhanced visuals but may not be installed by default. 'ps aux' gives snapshots, not real-time updates. 'vmstat' shows system-wide stats, not per-process details.",
      "examTip": "Use 'top' for quick, real-time monitoring of CPU utilization per process on Linux systems."
    },
    {
      "id": 60,
      "question": "A Windows system shows the error 'NTLDR is missing' after reboot. What is the FIRST troubleshooting step?",
      "options": [
        "Check BIOS/UEFI boot order for incorrect priorities.",
        "Rebuild the boot sector using recovery media.",
        "Replace corrupted NTLDR files from installation media.",
        "Run CHKDSK to check for disk integrity issues."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Incorrect boot order causes the system to look for boot files on non-bootable media, leading to the NTLDR error. Rebuilding the boot sector or replacing files is secondary if the drive isn't set as primary. CHKDSK addresses disk issues, not boot configuration errors.",
      "examTip": "Start troubleshooting boot errors by verifying BIOS boot sequence to ensure the correct drive is prioritized."
    },
    {
      "id": 61,
      "question": "A Windows 11 system consistently shows a 'CRITICAL_PROCESS_DIED' BSOD during boot after a failed update. What is the MOST effective FIRST step to resolve this issue?",
      "options": [
        "Boot into Safe Mode and run the 'sfc /scannow' command.",
        "Perform a system restore to a point before the update.",
        "Use the Windows Startup Repair utility from recovery options.",
        "Reinstall the latest cumulative Windows update manually."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Booting into Safe Mode and running 'sfc /scannow' checks for and repairs corrupted system files that may have caused the BSOD. System restore is effective but should follow simpler file repair attempts. Startup Repair may help but doesn't specifically address corrupted files. Reinstalling updates may reintroduce the same issues without file integrity checks.",
      "examTip": "When encountering 'CRITICAL_PROCESS_DIED' errors, always validate system file integrity using SFC as the initial troubleshooting step."
    },
    {
      "id": 62,
      "question": "A Linux administrator observes slow performance and discovers that the swap partition is fully utilized despite having sufficient RAM. What is the MOST likely cause?",
      "options": [
        "The 'swappiness' value is set too high, causing aggressive swapping.",
        "A memory leak in an application is consuming available RAM.",
        "The kernel version lacks proper memory management support.",
        "Disk I/O bandwidth is saturated due to high read/write operations."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A high 'swappiness' value forces the system to use swap space more aggressively, leading to performance issues. Memory leaks would completely consume RAM, leaving swap as a secondary symptom. Kernel issues are rare and would likely cause broader system instability. Disk I/O saturation would cause swap delays but not necessarily full utilization without swappiness misconfiguration.",
      "examTip": "Check and adjust the 'swappiness' parameter to optimize swap usage and improve overall performance on Linux systems."
    },
    {
      "id": 63,
      "question": "A macOS user reports that Time Machine backups to a network drive fail after a recent OS update. The network path is accessible. What is the MOST likely cause?",
      "options": [
        "The OS update modified SMB protocol requirements for Time Machine.",
        "The network share lost the appropriate permissions for backup operations.",
        "The Time Machine preference file became corrupted during the update.",
        "The network drive lacks sufficient storage space for new backups."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Recent macOS updates have enforced stricter SMB protocol versions for Time Machine compatibility. Permission issues would prevent network drive access entirely. Preference file corruption would impact the Time Machine UI, not connection. Storage shortages would show clear disk space errors rather than failed backups.",
      "examTip": "Verify SMB protocol compatibility after macOS updates when network Time Machine backups fail unexpectedly."
    },
    {
      "id": 64,
      "question": "A user’s Windows 10 machine fails to access internal web applications via hostname but works with IP addresses. External sites resolve without issue. What is the MOST likely cause?",
      "options": [
        "Missing or incorrect DNS suffix configuration in network settings.",
        "Corrupted local DNS cache preventing proper hostname resolution.",
        "The user’s system hosts file has incorrect entries for internal addresses.",
        "The internal DNS server is unreachable due to network segmentation."
      ],
      "correctAnswerIndex": 0,
      "explanation": "DNS suffix misconfigurations cause failures when resolving internal hostnames, especially when IP-based access still works. A corrupted DNS cache typically affects all hostname lookups. Hosts file issues would impact only specified entries. Network segmentation would block both IP and hostname access.",
      "examTip": "Check DNS suffixes in advanced network settings when internal hostname resolution fails while IP connectivity remains functional."
    },
    {
      "id": 65,
      "question": "A Linux system shows repeated authentication failures via SSH after a recent key rotation. What is the MOST likely cause?",
      "options": [
        "The authorized_keys file was not updated with the new public key.",
        "The private key permissions are too permissive, causing SSH to reject it.",
        "SSH daemon configuration does not allow key-based authentication.",
        "The key pair is using an unsupported encryption algorithm."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If the authorized_keys file isn't updated after key rotation, the server won’t recognize the new public key. Permission issues would prompt explicit errors regarding insecure file access. SSH daemon configurations rarely change unintentionally. Unsupported algorithms typically produce immediate connection rejections, not silent failures.",
      "examTip": "Always ensure the correct public key is present in the authorized_keys file after rotating SSH keys."
    },
    {
      "id": 66,
      "question": "A technician receives a report that a Windows system’s applications fail to launch, returning 'Side-by-Side Configuration Error.' What is the BEST solution?",
      "options": [
        "Reinstall the appropriate Microsoft Visual C++ Redistributable package.",
        "Perform a system restore to a point before the issue started.",
        "Run the System File Checker (sfc /scannow) to fix potential corruption.",
        "Update the operating system to ensure all dependencies are current."
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 'Side-by-Side Configuration Error' typically occurs when the required Visual C++ Redistributable is missing or mismatched. System restore or SFC are secondary options if redistribution installation fails. OS updates rarely address redistributable issues directly.",
      "examTip": "When encountering 'Side-by-Side Configuration' errors, reinstall the correct Visual C++ Redistributable version first."
    },
    {
      "id": 67,
      "question": "A Windows 11 device connected to a corporate VPN cannot access internal resources, though the VPN connection shows as active. What should the technician check FIRST?",
      "options": [
        "Verify that split tunneling is configured correctly in the VPN settings.",
        "Check if DNS resolution is correctly routing internal hostnames through the VPN.",
        "Confirm that the user’s access permissions align with internal resource requirements.",
        "Inspect the VPN client logs for authentication token renewal failures."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DNS misconfigurations often cause active VPN connections to fail at resolving internal hostnames. Split tunneling affects traffic routing but wouldn't prevent all internal access. Access permissions would block only restricted resources. Authentication issues would prevent VPN connection establishment entirely.",
      "examTip": "Always verify internal DNS resolution settings when VPN connections appear active but internal access fails."
    },
    {
      "id": 68,
      "question": "A Linux administrator needs to track real-time disk I/O performance for troubleshooting. Which command should be used?",
      "options": [
        "iostat -x 1",
        "vmstat 1",
        "iotop",
        "dstat -d 1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'iostat -x 1' provides extended I/O statistics per second, ideal for real-time disk performance analysis. 'vmstat' focuses on memory and CPU. 'iotop' tracks real-time I/O per process but may not be installed by default. 'dstat' offers broad performance metrics but isn't as disk-focused as iostat.",
      "examTip": "Use 'iostat -x 1' for detailed, real-time disk I/O performance insights during Linux troubleshooting."
    },
    {
      "id": 69,
      "question": "A user’s Android device shows excessive data consumption despite being connected to Wi-Fi. What is the MOST likely reason?",
      "options": [
        "The 'Wi-Fi Assist' feature is enabled, switching to mobile data when Wi-Fi is weak.",
        "Background applications are bypassing Wi-Fi restrictions due to outdated firmware.",
        "The device's DNS settings are misconfigured, forcing cellular data usage.",
        "The carrier's mobile data proxy is overriding device data routing preferences."
      ],
      "correctAnswerIndex": 0,
      "explanation": "'Wi-Fi Assist' allows devices to switch to mobile data automatically when Wi-Fi signals are weak, leading to unexpected data usage. Background apps respect Wi-Fi settings unless manually overridden. DNS issues affect resolution speed but not data source choice. Carrier proxies don’t force mobile data use when Wi-Fi is available.",
      "examTip": "Disable 'Wi-Fi Assist' or similar features to prevent mobile data use when Wi-Fi connections weaken on mobile devices."
    },
    {
      "id": 70,
      "question": "A Windows system reports 'The trust relationship between this workstation and the primary domain failed.' What is the MOST efficient resolution?",
      "options": [
        "Rejoin the workstation to the domain using administrator credentials.",
        "Reset the computer account in Active Directory and reboot the workstation.",
        "Clear cached credentials and restart the system.",
        "Sync the system clock with the domain controller’s time source."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Rejoining the domain resets the trust relationship most efficiently. Resetting the computer account may also work but requires domain controller access. Clearing cached credentials doesn’t resolve trust issues. Time synchronization addresses Kerberos authentication but not broken trust relationships.",
      "examTip": "When domain trust relationships fail, rejoin the workstation to the domain using valid administrator credentials as the quickest fix."
    },
    {
      "id": 71,
      "question": "A Linux server configured with systemd-journald is consuming excessive disk space due to large log files. How can this be mitigated?",
      "options": [
        "Configure 'SystemMaxUse' in journald.conf to limit disk usage.",
        "Manually delete old logs from /var/log/journal/ directory.",
        "Set up cron jobs to clear journal logs daily.",
        "Redirect journal logs to an external syslog server."
      ],
      "correctAnswerIndex": 0,
      "explanation": "'SystemMaxUse' limits the maximum disk space used by journald, providing automated control. Manual deletions are temporary. Cron jobs add complexity without persistent control. External syslog servers offload logs but may not address local disk constraints effectively.",
      "examTip": "Configure 'SystemMaxUse' in journald.conf for persistent disk space management when using systemd-journald."
    },
    {
      "id": 72,
      "question": "A user complains that their Windows 10 machine experiences slow logins, especially after network interruptions. What should the technician check FIRST?",
      "options": [
        "Verify if roaming profiles are being used, causing network-dependent logins.",
        "Check group policy processing delays during login.",
        "Examine the Event Viewer for profile corruption warnings.",
        "Review DNS configuration for the domain controller’s availability."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Roaming profiles rely on network connectivity; slowdowns occur when access to profile storage is delayed. Group policies impact login times but are less sensitive to network interruptions. Profile corruption would prevent successful logins. DNS issues affect broader domain access, not just login speed.",
      "examTip": "Confirm whether roaming profiles are in use when troubleshooting slow network-dependent login processes."
    },
    {
      "id": 73,
      "question": "A Linux server's SSH service is running, but users experience 'Connection refused' errors. What is the MOST likely cause?",
      "options": [
        "The firewall is blocking port 22.",
        "SELinux is preventing SSH from binding to the network interface.",
        "The SSH configuration file contains syntax errors.",
        "TCP wrappers are restricting SSH access based on user policies."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Firewall rules blocking port 22 commonly cause 'Connection refused' errors despite the SSH service running. SELinux restrictions usually log denials. Syntax errors in sshd_config prevent the service from starting. TCP wrappers typically result in 'Permission denied' rather than connection refusal.",
      "examTip": "Check firewall rules first when 'Connection refused' errors occur despite SSH services running."
    },
    {
      "id": 74,
      "question": "A Windows system's performance is severely impacted during startup. Resource Monitor shows high disk usage by 'MsMpEng.exe.' What is the MOST likely reason?",
      "options": [
        "Windows Defender is running a full system scan during startup.",
        "Malware infection is disguising itself as MsMpEng.exe.",
        "Windows Update is installing cumulative patches in the background.",
        "Disk fragmentation is causing inefficient file access patterns."
      ],
      "correctAnswerIndex": 0,
      "explanation": "MsMpEng.exe is the Windows Defender process, which performs scans during startup, causing high disk activity. Malware masquerading as this process is rare and would exhibit additional suspicious behavior. Windows Update activity shows under a different process. Modern systems defragment automatically, making manual fragmentation less common.",
      "examTip": "Check Windows Defender scan schedules when MsMpEng.exe shows high disk usage during startup."
    },
    {
      "id": 75,
      "question": "A user’s macOS device fails to connect to a Wi-Fi network after upgrading to the latest OS version. Other devices connect without issues. What is the MOST likely cause?",
      "options": [
        "Corrupted network preferences requiring a reset of Wi-Fi configurations.",
        "Outdated wireless network drivers incompatible with the new OS version.",
        "The keychain entry for the Wi-Fi network is corrupted and needs deletion.",
        "Changes in security protocols on the router incompatible with macOS updates."
      ],
      "correctAnswerIndex": 0,
      "explanation": "macOS updates can corrupt network preference files, leading to Wi-Fi connection issues. Outdated drivers would typically result in missing network interfaces. Keychain corruption affects authentication, not network visibility. Router security protocol mismatches would impact all devices, not just one macOS system.",
      "examTip": "Reset network preferences on macOS after major OS upgrades to resolve unexplained Wi-Fi connectivity issues."
    },
    {
      "id": 76,
      "question": "A Windows 10 machine displays 'No Boot Device Found' after a BIOS firmware update. What is the MOST likely cause?",
      "options": [
        "The BIOS boot mode reverted from UEFI to Legacy after the update.",
        "The system's boot partition was inadvertently deleted during the update.",
        "Secure Boot settings were reset, causing the system to fail boot verification.",
        "The master boot record (MBR) was corrupted during the update process."
      ],
      "correctAnswerIndex": 0,
      "explanation": "BIOS updates sometimes reset configurations, including boot mode, causing UEFI-based systems to fail in Legacy mode. Boot partition deletion or MBR corruption would result in different error messages. Secure Boot resets typically prompt specific Secure Boot errors.",
      "examTip": "Verify BIOS boot mode settings after firmware updates to ensure consistency with existing boot configurations."
    },
    {
      "id": 77,
      "question": "A Linux administrator needs to monitor persistent log entries across reboots. Which command is BEST for this purpose?",
      "options": [
        "journalctl --boot -1",
        "dmesg -T",
        "tail -f /var/log/syslog",
        "cat /proc/kmsg"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'journalctl --boot -1' retrieves logs from the previous boot, providing persistent data across reboots. 'dmesg' shows current kernel logs. 'tail -f' provides real-time updates but only for the current session. 'cat /proc/kmsg' shows live kernel messages without historical context.",
      "examTip": "Use 'journalctl --boot -1' to access persistent logs from previous boot sessions on systemd-managed Linux systems."
    },
    {
      "id": 78,
      "question": "A user’s Windows system cannot connect to HTTPS websites but has no issues with HTTP. The time and date are correct. What is the MOST likely cause?",
      "options": [
        "Corrupted or outdated root certificates on the system.",
        "Disabled TLS settings in the browser’s configuration.",
        "Incorrect proxy settings preventing secure traffic.",
        "Network firewall blocking port 443 traffic selectively."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Root certificates validate HTTPS connections; outdated or corrupted certificates cause HTTPS failures while HTTP works. Disabled TLS settings affect all secure sites and typically prompt browser warnings. Proxy misconfigurations and selective firewall blocks usually prevent all secure traffic and raise broader connectivity alerts.",
      "examTip": "Update or reinstall root certificates when HTTPS connections fail despite accurate time settings and network accessibility."
    },
    {
      "id": 79,
      "question": "A Linux administrator needs to enforce automatic restart of a critical service if it fails. What systemd directive should be added?",
      "options": [
        "Restart=always",
        "RestartSec=5",
        "RemainAfterExit=yes",
        "ExecStartPre=/bin/true"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'Restart=always' ensures that systemd restarts the service regardless of exit status. 'RestartSec' adds a delay between restart attempts. 'RemainAfterExit' keeps the unit active after the service stops, without restarting. 'ExecStartPre' runs commands before service start but doesn’t impact restarts.",
      "examTip": "Set 'Restart=always' in systemd unit files for critical services requiring automatic recovery after unexpected failures."
    },
    {
      "id": 80,
      "question": "A Windows 11 machine shows a BitLocker recovery screen after a BIOS update. TPM is enabled and operational. What could have prevented this prompt?",
      "options": [
        "Suspending BitLocker encryption before performing the BIOS update.",
        "Changing the Secure Boot policy to accommodate BIOS changes.",
        "Reconfiguring UEFI boot order to prioritize encrypted partitions.",
        "Manually exporting and importing TPM keys post-update."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Suspending BitLocker before BIOS updates avoids TPM measurement mismatches that trigger recovery prompts. Secure Boot policies relate to signature validation, not BitLocker. Boot order changes wouldn't cause recovery requests unless the drive wasn’t found. TPM key management is automated with BitLocker and rarely requires manual intervention.",
      "examTip": "Suspend BitLocker before BIOS or firmware updates to prevent unnecessary recovery key prompts after system restarts."
    },
    {
      "id": 81,
      "question": "A Linux administrator observes that after rebooting, a critical service fails to start automatically but can be started manually without errors. What is the MOST likely cause?",
      "options": [
        "The systemd service file lacks the 'WantedBy=multi-user.target' directive.",
        "SELinux policies are preventing the service from loading at boot.",
        "The service requires a dependency that loads after it during startup.",
        "Permissions on the service’s executable file are too restrictive."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Without the 'WantedBy=multi-user.target' directive, systemd does not start the service at boot. SELinux would block manual starts as well. Dependency loading issues would show explicit dependency errors. File permissions would prevent manual execution, not just autostart.",
      "examTip": "Ensure proper 'WantedBy' directives in systemd unit files for services that must start automatically during boot."
    },
    {
      "id": 82,
      "question": "A Windows 10 system displays repeated 'BOOTMGR is missing' errors after adding a secondary storage drive. What should the technician check FIRST?",
      "options": [
        "BIOS/UEFI boot order configuration.",
        "Master boot record integrity on the primary drive.",
        "Secondary drive partitioning for active boot flags.",
        "Drive cable connections for the primary storage device."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Adding a secondary drive often alters boot order, causing the BIOS to prioritize a non-bootable drive. MBR integrity issues typically require recovery commands. Active boot flags on secondary drives are rarely needed. Cable disconnections would result in the drive not appearing at all, not boot errors.",
      "examTip": "Always confirm BIOS boot priorities after hardware changes to prevent boot-related errors like 'BOOTMGR is missing.'"
    },
    {
      "id": 83,
      "question": "A macOS user reports kernel panics after installing third-party kernel extensions. What is the FIRST step to resolve the issue?",
      "options": [
        "Boot into Safe Mode and remove the problematic kernel extension.",
        "Reset the NVRAM to clear potential hardware configuration issues.",
        "Reinstall macOS to restore system integrity.",
        "Run Disk Utility First Aid to check for file system corruption."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Safe Mode disables third-party kernel extensions, allowing the user to remove problematic ones. NVRAM resets address hardware misconfigurations but not kernel extension issues. Disk Utility and macOS reinstallation are more drastic and typically unnecessary for this issue.",
      "examTip": "Use Safe Mode to isolate and remove faulty kernel extensions when dealing with kernel panics on macOS."
    },
    {
      "id": 84,
      "question": "A Linux server’s web application shows '502 Bad Gateway' errors when accessed. Nginx is configured as a reverse proxy. What should the administrator check FIRST?",
      "options": [
        "Status and availability of the backend application server.",
        "Syntax errors in the Nginx configuration files.",
        "Firewall rules between the reverse proxy and backend server.",
        "Nginx service logs for recent proxy-related errors."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A '502 Bad Gateway' error indicates that Nginx cannot reach the upstream server. Backend server availability is the most immediate factor. Configuration errors or firewall issues would typically cause broader access problems. Logs help but are secondary to confirming server availability.",
      "examTip": "Check backend server status first when '502 Bad Gateway' errors occur in reverse proxy configurations."
    },
    {
      "id": 85,
      "question": "A user’s Android device consumes mobile data despite being connected to Wi-Fi. What is the MOST likely cause?",
      "options": [
        "The 'Wi-Fi Assist' feature is enabled, switching to mobile data during weak Wi-Fi signals.",
        "Background applications have unrestricted data permissions.",
        "The Wi-Fi network requires reauthentication to maintain the connection.",
        "The device is set to prioritize mobile networks over Wi-Fi for specific applications."
      ],
      "correctAnswerIndex": 0,
      "explanation": "'Wi-Fi Assist' enables the device to switch to mobile data when Wi-Fi is weak, leading to unexpected data usage. Background apps typically defer to Wi-Fi unless configured otherwise. Reauthentication prompts would block all network access, not selectively switch. Prioritization settings are uncommon and would affect specific apps only.",
      "examTip": "Disable 'Wi-Fi Assist' to prevent unintended mobile data use when Wi-Fi connectivity fluctuates."
    },
    {
      "id": 86,
      "question": "A Linux administrator needs to ensure SSH sessions persist despite network disruptions. Which SSH client setting should be adjusted?",
      "options": [
        "Configure 'ServerAliveInterval' and 'ServerAliveCountMax' in SSH settings.",
        "Enable TCP keepalives in the kernel network stack.",
        "Set 'PermitKeepAlive' in sshd_config on the server side.",
        "Implement autossh to maintain persistent SSH tunnels."
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 'ServerAliveInterval' and 'ServerAliveCountMax' options send periodic keepalive messages from the client, maintaining session continuity. Kernel TCP settings apply at a lower level and affect all connections. 'PermitKeepAlive' is not a valid sshd_config option. autossh handles reconnections rather than maintaining active sessions.",
      "examTip": "Use SSH client keepalive settings to ensure persistent connections during temporary network interruptions."
    },
    {
      "id": 87,
      "question": "A Windows 10 user reports slow file transfers to a network server, though pings to the server show low latency. What should the technician check NEXT?",
      "options": [
        "Network adapter duplex settings on both the client and the server.",
        "Server-side SMB protocol versions for compatibility issues.",
        "Local antivirus settings scanning network shares in real time.",
        "Disk performance metrics on both the client and the server."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Duplex mismatches between network adapters and switches cause slow data transfers despite low latency. SMB protocol issues typically cause outright incompatibility errors. Real-time antivirus scanning affects performance but would cause broader slowdowns. Disk performance issues would be suspected only after ruling out network configuration issues.",
      "examTip": "Check for duplex mismatches first when file transfers are slow despite normal network latency readings."
    },
    {
      "id": 88,
      "question": "A Linux server's SSH service stops responding after multiple failed login attempts. Other services remain unaffected. What is the MOST likely cause?",
      "options": [
        "Fail2ban triggered after detecting brute-force attempts, temporarily blocking SSH access.",
        "SSH daemon configuration limits concurrent sessions, causing a denial of service.",
        "SELinux policies were updated, preventing SSH access without explicit permissions.",
        "iptables firewall rules were dynamically adjusted to block repeated failed logins."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Fail2ban is commonly used to detect brute-force login attempts and temporarily block offending IP addresses. Session limits in SSH would produce explicit errors. SELinux policy changes would prevent SSH access entirely, not temporarily. Dynamic firewall adjustments are uncommon without explicit configuration.",
      "examTip": "Check Fail2ban logs when SSH becomes unresponsive following multiple failed login attempts."
    },
    {
      "id": 89,
      "question": "A macOS user reports that Spotlight search fails to locate recent files. Indexing appears incomplete. What terminal command can rebuild the Spotlight index?",
      "options": [
        "sudo mdutil -E /",
        "sudo diskutil repairVolume /",
        "sudo fsck_hfs -fy /dev/disk1",
        "sudo launchctl load /System/Library/LaunchDaemons/com.apple.metadata.mds.plist"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'sudo mdutil -E /' erases and rebuilds the Spotlight index, addressing indexing issues. 'diskutil repairVolume' fixes file system errors. 'fsck_hfs' checks and repairs HFS+ file systems. 'launchctl load' restarts background services but doesn't rebuild Spotlight indexes directly.",
      "examTip": "Use 'mdutil -E /' in Terminal to reset and rebuild Spotlight indexes when search issues arise on macOS."
    },
    {
      "id": 90,
      "question": "A Windows 11 user cannot access HTTPS websites, though HTTP works fine. DNS settings and firewall rules appear correct. What is the MOST likely cause?",
      "options": [
        "Corrupted or outdated root certificates on the local system.",
        "Disabled TLS protocols in the browser’s configuration settings.",
        "Network proxy settings intercepting and blocking HTTPS traffic.",
        "Outdated network drivers causing packet loss on secure connections."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Root certificates are essential for HTTPS validation; corrupted or outdated certificates block HTTPS access. Browser TLS settings would trigger explicit protocol errors. Network proxies blocking HTTPS would affect multiple users. Driver issues would cause broader network instability, not just HTTPS failures.",
      "examTip": "Update or reinstall root certificates when HTTPS access fails despite proper network and browser configurations."
    },
    {
      "id": 91,
      "question": "A Linux administrator wants to ensure critical services restart automatically if they fail. Which systemd directive should be configured?",
      "options": [
        "Restart=always",
        "RestartSec=5",
        "RemainAfterExit=yes",
        "ExecStartPre=/bin/true"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'Restart=always' ensures automatic service restarts regardless of exit status. 'RestartSec' sets the delay before restart but doesn't enable it. 'RemainAfterExit' retains the unit’s active state without restarting. 'ExecStartPre' runs preparatory commands but doesn’t affect restart behavior.",
      "examTip": "Set 'Restart=always' in systemd unit files to ensure automatic recovery for critical services after unexpected failures."
    },
    {
      "id": 92,
      "question": "A user’s Android device consumes mobile data rapidly even when connected to Wi-Fi. What setting should the technician check FIRST?",
      "options": [
        "Wi-Fi Assist or similar feature that switches to mobile data when Wi-Fi is weak.",
        "App settings allowing background data usage without Wi-Fi restrictions.",
        "Network priority settings that default to mobile networks for streaming apps.",
        "DNS configuration forcing cellular fallback for data-intensive applications."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Wi-Fi Assist causes automatic mobile data use when Wi-Fi signals weaken. Background data settings typically respect Wi-Fi connections unless explicitly overridden. Network priority settings rarely override default behavior unless configured. DNS settings impact resolution speed, not data source selection.",
      "examTip": "Disable Wi-Fi assist or equivalent features on mobile devices to prevent unintended mobile data consumption during weak Wi-Fi signals."
    },
    {
      "id": 93,
      "question": "A Windows 10 system fails to boot with an 'NTLDR is missing' error after a BIOS firmware update. What is the MOST likely cause?",
      "options": [
        "The BIOS reverted from UEFI to Legacy boot mode after the firmware update.",
        "The master boot record became corrupted during the update process.",
        "The system's boot partition was accidentally deleted.",
        "Secure Boot settings were reset, preventing bootloader verification."
      ],
      "correctAnswerIndex": 0,
      "explanation": "BIOS updates sometimes reset boot modes, causing legacy systems to fail without NTLDR in UEFI configurations. MBR corruption or partition deletion would prevent detection altogether. Secure Boot resets would produce signature-related errors, not missing bootloader messages.",
      "examTip": "Verify BIOS boot mode settings after firmware updates to ensure compatibility with existing boot configurations."
    },
    {
      "id": 94,
      "question": "A Windows 11 device prompts for BitLocker recovery keys after each reboot. TPM is enabled and functional. What could prevent future prompts?",
      "options": [
        "Suspending BitLocker protection before performing firmware updates.",
        "Resetting Secure Boot settings to factory defaults.",
        "Manually exporting TPM keys before shutdown.",
        "Reinstalling Windows updates related to BitLocker encryption modules."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Suspending BitLocker avoids TPM measurement discrepancies after firmware updates, preventing repeated recovery key prompts. Secure Boot resets affect signature validation, not BitLocker. TPM key exports are rarely necessary for standard operations. Reinstalling updates wouldn’t prevent future prompts triggered by TPM checks.",
      "examTip": "Suspend BitLocker before performing firmware updates to maintain consistent TPM measurements and prevent recovery key prompts."
    },
    {
      "id": 95,
      "question": "A Linux system's SSH sessions are dropping after a few minutes of inactivity. How can this issue be resolved?",
      "options": [
        "Configure 'ClientAliveInterval' and 'ClientAliveCountMax' in sshd_config.",
        "Increase TCP keepalive timeouts in kernel settings.",
        "Switch from SSH to Mosh for persistent terminal sessions.",
        "Set 'PermitRootLogin' to 'yes' in SSH configurations."
      ],
      "correctAnswerIndex": 0,
      "explanation": "'ClientAliveInterval' and 'ClientAliveCountMax' maintain SSH sessions by sending periodic messages. Kernel-level TCP keepalive changes affect all network traffic, which may not be necessary. Mosh provides persistent sessions but requires installation on both client and server. Root login settings do not influence session longevity.",
      "examTip": "Use 'ClientAliveInterval' and 'ClientAliveCountMax' in sshd_config to maintain SSH session stability during idle periods."
    },
    {
      "id": 96,
      "question": "A Windows 10 machine is slow to boot and shows high disk activity from 'MsMpEng.exe' in Task Manager. What is the MOST likely cause?",
      "options": [
        "Windows Defender is running a full system scan during startup.",
        "The system drive is failing, causing read retries during startup.",
        "Windows Update is installing patches in the background.",
        "A malware infection is masquerading as the Defender process."
      ],
      "correctAnswerIndex": 0,
      "explanation": "'MsMpEng.exe' represents Windows Defender, which runs full scans at startup, causing high disk utilization. Drive failure would manifest in SMART errors. Windows Update activities appear under separate processes. Malware would exhibit other suspicious behaviors, not just high disk usage from Defender.",
      "examTip": "Check Windows Defender scan schedules and adjust them if necessary to avoid performance impacts during system startup."
    },
    {
      "id": 97,
      "question": "A macOS device fails to reconnect to a Wi-Fi network after an OS update. Other devices connect successfully. What is the MOST likely cause?",
      "options": [
        "Corrupted network preferences requiring reset.",
        "Outdated wireless drivers incompatible with the latest OS.",
        "Keychain corruption affecting Wi-Fi credentials.",
        "Router security settings incompatible with updated macOS protocols."
      ],
      "correctAnswerIndex": 0,
      "explanation": "macOS updates sometimes corrupt network preferences, preventing Wi-Fi reconnections. Wireless drivers are managed via system updates, making incompatibility rare. Keychain issues affect authentication but not network visibility. Router settings would affect all devices, not just one.",
      "examTip": "Reset network preferences in macOS when Wi-Fi connectivity issues arise after major system updates."
    },
    {
      "id": 98,
      "question": "A Windows user reports that mapped network drives fail to reconnect after a password change. What should be checked FIRST?",
      "options": [
        "Cached credentials for mapped network drives in Credential Manager.",
        "DNS resolution times for the file server hostname.",
        "Group Policy settings enforcing network drive mappings.",
        "Windows Firewall rules affecting SMB traffic."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Password changes invalidate cached credentials used for network drive mappings. DNS issues would prevent hostname resolution entirely. Group Policy configurations generally reapply at login. Firewall rules would block all SMB traffic, not just reconnections.",
      "examTip": "Update cached credentials in Credential Manager after password changes to restore access to mapped network drives."
    },
    {
      "id": 99,
      "question": "A Linux administrator must schedule a script to run at 1 AM on the first day of every month. What is the correct crontab entry?",
      "options": [
        "0 1 1 * * /path/to/script.sh",
        "0 1 * * 1 /path/to/script.sh",
        "0 1 1 1 * /path/to/script.sh",
        "0 1 */1 * * /path/to/script.sh"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'0 1 1 * *' runs the script at 1 AM on the first day of every month. '0 1 * * 1' runs weekly on Mondays. '0 1 1 1 *' runs only on January 1. '*/1' denotes daily execution, not monthly.",
      "examTip": "Double-check the day and month fields in crontab entries to ensure accurate monthly scheduling."
    },
    {
      "id": 100,
      "question": "A Windows system shows 'Operating System Not Found' after adding a second hard drive. What is the MOST likely cause?",
      "options": [
        "BIOS boot order prioritizing the new drive, which lacks an OS.",
        "The system partition on the primary drive was accidentally deleted.",
        "The master boot record (MBR) on the primary drive became corrupted.",
        "SATA cable for the primary drive became disconnected during installation."
      ],
      "correctAnswerIndex": 0,
      "explanation": "New hard drives can alter BIOS boot priorities, causing the system to attempt booting from a non-bootable drive. Partition deletion and MBR corruption would prevent any drive detection. SATA disconnections would make the drive invisible to the system entirely.",
      "examTip": "Check and correct BIOS boot order after adding hardware to ensure the system boots from the correct drive."
    }
  ]
});
