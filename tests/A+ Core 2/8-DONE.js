db.tests.insertOne({
  "category": "aplus2",
  "testId": 8,
  "testName": "A+ Core 2 Practice Test #8 (Very Challenging)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A technician receives a Windows 10 machine that boots directly into BIOS after a failed system update. The hard drive is detected in BIOS, but the OS does not load. What is the MOST likely cause?",
      "options": [
        "The bootloader was corrupted during the update process.",
        "The BIOS was reset to factory settings, changing the SATA mode.",
        "The partition table on the hard drive is damaged.",
        "UEFI Secure Boot is preventing the OS from loading."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A corrupted bootloader during an update commonly causes the system to bypass OS loading and enter BIOS. While a reset SATA mode can cause boot issues, BIOS still detecting the drive suggests the connection is intact. A damaged partition table would typically result in a 'no OS found' message rather than booting to BIOS. Secure Boot prevents unauthorized OS loading but usually prompts an error screen, not direct BIOS access.",
      "examTip": "When Windows updates fail and the system boots to BIOS, repair the bootloader using bootrec commands from recovery tools."
    },
    {
      "id": 2,
      "question": "A Linux administrator finds that a critical service is failing to start on boot. The service runs when started manually. The service file exists in /etc/systemd/system/. What is the MOST likely cause?",
      "options": [
        "The service has not been enabled with systemctl enable.",
        "The service depends on another service that fails during boot.",
        "File permissions on the service file are incorrect.",
        "The system is using SysVinit instead of systemd."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If a systemd service starts manually but not at boot, it is often because it has not been enabled with systemctl enable. While service dependencies can cause startup failures, this would typically trigger dependency-related errors. Incorrect file permissions would prevent manual starts as well. SysVinit is outdated in most modern Linux distributions and unlikely in current environments.",
      "examTip": "Always run 'systemctl enable' after creating a systemd service to ensure it starts on boot."
    },
    {
      "id": 3,
      "question": "A user reports that after enabling BitLocker on their laptop, the system prompts for a recovery key on every boot. TPM is present and enabled. What is the MOST likely cause?",
      "options": [
        "The BIOS/UEFI firmware was updated after BitLocker was enabled.",
        "The boot partition was resized post-encryption.",
        "Group Policy settings do not permit TPM-only unlock.",
        "The BitLocker recovery key was not properly saved."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Firmware updates can cause BitLocker to prompt for recovery keys because the TPM detects changes in boot configuration. Partition resizing could cause boot failures, not consistent recovery key prompts. Group Policy settings that disallow TPM-only unlock would have caused prompts from the start. The saved recovery key affects the ability to unlock but does not cause repeated prompts if it was never lost.",
      "examTip": "After firmware updates, suspend and resume BitLocker to reset TPM baseline measurements."
    },
    {
      "id": 4,
      "question": "An Android device user complains that newly installed corporate apps do not launch and display 'Not allowed by admin' errors. What is the MOST likely cause?",
      "options": [
        "Mobile Device Management (MDM) policies restrict application permissions.",
        "The Android device is running in Developer Mode.",
        "The apps require a newer version of the Android OS.",
        "Google Play Protect is blocking the applications."
      ],
      "correctAnswerIndex": 0,
      "explanation": "MDM policies control corporate app permissions and can block app execution if security requirements are not met. Developer Mode would not block apps but rather enable debugging options. An outdated OS typically leads to compatibility errors, not admin restriction messages. Google Play Protect scans for malware, not enforcing admin-level restrictions on legitimate corporate apps.",
      "examTip": "Ensure MDM profiles are correctly applied when corporate apps show administrative restriction errors."
    },
    {
      "id": 5,
      "question": "A user reports that their macOS system’s Time Machine backups are failing with 'Backup disk not available.' The backup disk is connected and accessible. What is the MOST likely cause?",
      "options": [
        "Time Machine's backup disk permissions have been altered.",
        "The macOS system clock is incorrect, causing authentication failures.",
        "Spotlight indexing is incomplete, delaying backup processes.",
        "The backup disk is formatted with FAT32, which is incompatible with Time Machine."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Time Machine requires proper permissions on the backup disk; altered permissions can prevent backups. While clock discrepancies can cause network authentication issues, local backups are unaffected. Spotlight indexing does not impact Time Machine disk detection. FAT32 is incompatible, but since the disk is accessible, it’s likely correctly formatted.",
      "examTip": "Verify and repair disk permissions using Disk Utility when Time Machine fails to recognize accessible disks."
    },
    {
      "id": 6,
      "question": "A Windows 10 user complains that after installing a new VPN client, they cannot browse internal resources, though internet access works. What is the MOST likely reason?",
      "options": [
        "The VPN client is misconfigured to route only external traffic.",
        "DNS settings are pointing to external resolvers instead of internal ones.",
        "The local firewall is blocking VPN tunnel traffic.",
        "The VPN uses a split-tunneling configuration preventing internal access."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DNS misconfiguration that points to external servers prevents resolution of internal resources. VPN clients often change DNS settings. Misconfigured routing would block all traffic. A local firewall would typically block the VPN connection entirely, not just internal browsing. Split-tunneling allows external traffic outside the VPN but should still permit internal resource access.",
      "examTip": "Check DNS settings after VPN installation to ensure internal resource resolution works correctly."
    },
    {
      "id": 7,
      "question": "A Linux administrator suspects that an SSH service is being targeted by brute-force attacks. Which command will BEST confirm repeated failed login attempts?",
      "options": [
        "grep 'Failed password' /var/log/auth.log",
        "netstat -tuln | grep 22",
        "lastb",
        "journalctl -u ssh"
      ],
      "correctAnswerIndex": 0,
      "explanation": "grep 'Failed password' in /var/log/auth.log reveals failed SSH authentication attempts. netstat shows listening ports, not login attempts. lastb shows failed login history but may lack details per attempt. journalctl -u ssh gives service logs but may require filtering to show failed attempts specifically.",
      "examTip": "Review /var/log/auth.log regularly to detect unauthorized SSH access attempts on Linux servers."
    },
    {
      "id": 8,
      "question": "A user complains that their Windows 10 device cannot sync with a network time server. The network is stable, and the time server is reachable. What is the MOST likely cause?",
      "options": [
        "The Windows Time (W32Time) service is stopped.",
        "The firewall is blocking NTP traffic on port 123.",
        "The system's time zone settings are incorrect.",
        "Group Policy enforces a different time server."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If the Windows Time service is stopped, time synchronization fails despite network availability. A blocked port 123 affects NTP but would show network errors. Incorrect time zone settings don’t prevent synchronization but cause displayed time differences. Group Policy-enforced servers cause mismatched time if the assigned server is unreachable, but that wasn’t specified here.",
      "examTip": "Ensure the Windows Time service is running when diagnosing NTP synchronization issues on Windows."
    },
    {
      "id": 9,
      "question": "A technician needs to prevent sensitive data on mobile devices from being accessible if the device is lost. Which method provides the STRONGEST protection?",
      "options": [
        "Enable full-device encryption with enforced passcodes.",
        "Configure biometric authentication for device unlock.",
        "Set remote wipe policies through MDM solutions.",
        "Require complex passwords for device access."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Full-device encryption ensures data is unreadable without proper authentication, offering the strongest protection. Biometric methods can fail under legal circumstances. Remote wipe is reactive, relying on connectivity. Complex passwords help but can be bypassed without encryption if the storage medium is accessed directly.",
      "examTip": "Combine full-device encryption with strong authentication methods for optimal mobile data protection."
    },
    {
      "id": 10,
      "question": "A company deploys Windows 10 laptops with BitLocker enabled. Some users report being prompted for recovery keys after firmware updates. What should IT configure to prevent this issue in future deployments?",
      "options": [
        "Enable 'Suspend BitLocker' before performing firmware updates.",
        "Store BitLocker recovery keys in Active Directory automatically.",
        "Configure TPM PCR settings to ignore firmware changes.",
        "Switch from TPM-only mode to TPM+PIN mode for BitLocker."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Suspending BitLocker before firmware updates prevents TPM from detecting unexpected changes, avoiding recovery key prompts. Storing keys aids recovery but doesn’t prevent prompts. Adjusting PCR settings risks weakening security. TPM+PIN enhances security but doesn’t address firmware-triggered key requests.",
      "examTip": "Always suspend BitLocker encryption before BIOS or firmware updates to avoid repeated recovery prompts."
    },
    {
      "id": 11,
      "question": "A Windows 10 user reports 'Access Denied' errors when attempting to modify files they previously created on a shared NTFS partition. What is the MOST likely cause?",
      "options": [
        "File ownership was transferred to another user or process.",
        "The NTFS permissions for the user account were removed.",
        "The disk was mounted as read-only due to file system errors.",
        "BitLocker encryption was applied to the partition without the user’s credentials."
      ],
      "correctAnswerIndex": 0,
      "explanation": "File ownership changes prevent previous owners from modifying files unless permissions are reassigned. If NTFS permissions were removed, the user wouldn’t see the files. A read-only mount affects all write operations, not just specific files. BitLocker would block all access without credentials, not generate simple 'Access Denied' messages for selected files.",
      "examTip": "Check and reassign file ownership on NTFS partitions when users encounter unexpected 'Access Denied' errors."
    },
    {
      "id": 12,
      "question": "A technician is configuring an application to run on startup for all users on a Windows 10 machine. Which location is the BEST place to add the application shortcut?",
      "options": [
        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
        "C:\\Users\\Default\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Placing the shortcut in C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp ensures the application runs for all users. The Default user profile affects only new user profiles. HKEY_LOCAL_MACHINE affects all users but is more suited for system-wide configurations. HKEY_CURRENT_USER applies changes per user, not system-wide.",
      "examTip": "Use the ProgramData Startup folder for user-independent startup applications in Windows environments."
    },
    {
      "id": 13,
      "question": "A user’s Windows system boots into recovery mode with a 'BOOTMGR is missing' error. Which command should the technician run FIRST to resolve this issue?",
      "options": [
        "bootrec /fixmbr",
        "bootrec /fixboot",
        "bootrec /rebuildbcd",
        "chkdsk /r"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The /rebuildbcd option recreates the boot configuration data, addressing 'BOOTMGR is missing' errors. /fixmbr repairs the master boot record, typically for malware infections. /fixboot writes a new boot sector but doesn’t rebuild boot configurations. chkdsk checks disk integrity but doesn’t restore BOOTMGR.",
      "examTip": "For 'BOOTMGR is missing' errors, rebuilding the BCD with bootrec /rebuildbcd is often the quickest resolution."
    },
    {
      "id": 14,
      "question": "An organization mandates that all emails sent externally must be digitally signed. Which technology BEST ensures compliance with this policy?",
      "options": [
        "S/MIME certificates installed on client email applications.",
        "Transport Layer Security (TLS) enforced on the mail server.",
        "DomainKeys Identified Mail (DKIM) configuration on the mail server.",
        "Sender Policy Framework (SPF) entries in DNS."
      ],
      "correctAnswerIndex": 0,
      "explanation": "S/MIME provides end-to-end email encryption and digital signatures, ensuring message authenticity. TLS secures transport but doesn’t sign messages. DKIM verifies server-level authenticity, not user-level signatures. SPF prevents spoofing but doesn’t sign or encrypt messages.",
      "examTip": "Deploy S/MIME for user-level digital signatures and encryption in enterprise email environments."
    },
    {
      "id": 15,
      "question": "A technician needs to securely dispose of multiple decommissioned hard drives. Which method BEST ensures that data cannot be recovered?",
      "options": [
        "Degaussing the hard drives before physical destruction.",
        "Low-level formatting each hard drive twice.",
        "Running a DoD 5220.22-M compliant overwrite process.",
        "Deleting all partitions and performing a standard format."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Degaussing disrupts magnetic fields, rendering data unrecoverable. Low-level formatting may leave residual data. DoD overwrite standards are effective but time-consuming and less reliable than degaussing. Standard formatting and partition deletion only remove file pointers, not actual data.",
      "examTip": "Combine degaussing and physical destruction for the most secure hard drive disposal in sensitive environments."
    },
    {
      "id": 16,
      "question": "A Linux administrator needs to limit SSH access to specific IP addresses for security. Which configuration file should be modified?",
      "options": [
        "/etc/hosts.allow",
        "/etc/ssh/sshd_config",
        "/etc/hosts.deny",
        "/etc/iptables/rules.v4"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Editing /etc/hosts.allow can whitelist specific IPs for SSH access. sshd_config changes global SSH settings but doesn’t control IP-level access. hosts.deny blocks IPs but is less secure than explicit allow rules. iptables rules provide firewall-level restrictions but are more complex to maintain.",
      "examTip": "For simple SSH access control, configure /etc/hosts.allow to specify permitted IP addresses."
    },
    {
      "id": 17,
      "question": "A Windows 10 system fails to install security updates and returns error 0x80070005. What is the MOST likely cause?",
      "options": [
        "Insufficient permissions to access required files or folders.",
        "Corrupted Windows Update components.",
        "Outdated hardware drivers causing compatibility issues.",
        "Insufficient disk space for update installation."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Error 0x80070005 is an 'Access Denied' error, commonly caused by insufficient permissions. Corrupted components produce different error codes. Hardware drivers cause compatibility issues but not access denial. Disk space issues generate storage-related errors, not permission errors.",
      "examTip": "Run Windows Update Troubleshooter and ensure proper permissions for system folders to resolve 0x80070005 errors."
    },
    {
      "id": 18,
      "question": "An Android device connected to a corporate network cannot access internal web services but can browse the internet. What is the MOST likely cause?",
      "options": [
        "Incorrect DNS settings pointing to external resolvers.",
        "Wi-Fi isolation enabled on the access point.",
        "Expired SSL certificates on internal web services.",
        "VPN tunnel configuration issues."
      ],
      "correctAnswerIndex": 0,
      "explanation": "DNS misconfiguration prevents internal resource resolution while still allowing internet browsing. Wi-Fi isolation blocks device-to-device communication, not server access. Expired SSL certificates affect trust but not accessibility. VPN misconfigurations would block all internal resources, typically including IP-level access.",
      "examTip": "Verify DNS configurations on mobile devices when internal resources are inaccessible but internet browsing works."
    },
    {
      "id": 19,
      "question": "A Linux server shows slow disk I/O performance. Which command provides real-time statistics to identify bottlenecks?",
      "options": [
        "iostat -x 1",
        "df -h",
        "du -sh /",
        "vmstat 1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "iostat -x 1 provides detailed, real-time disk I/O statistics, including utilization and wait times. df -h shows disk usage but not performance. du -sh provides directory size summaries without performance data. vmstat shows overall system performance but not detailed disk I/O statistics.",
      "examTip": "Use 'iostat' with the -x option for in-depth disk I/O performance analysis on Linux systems."
    },
    {
      "id": 20,
      "question": "A technician needs to ensure that a critical service on a Linux server restarts automatically after a crash. Which systemd configuration achieves this?",
      "options": [
        "Add 'Restart=always' in the service's systemd unit file.",
        "Enable the service using 'systemctl enable servicename'.",
        "Create a cron job to check and restart the service.",
        "Configure watchdog settings in the kernel parameters."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Adding 'Restart=always' in the service’s systemd unit file ensures automatic restarts after crashes. systemctl enable ensures startup at boot, not after crashes. Cron jobs for service restarts are inefficient and may miss immediate failures. Watchdog settings monitor kernel issues, not specific service crashes.",
      "examTip": "Use the 'Restart=always' directive in systemd unit files for reliable automatic service recovery after failures."
    },
    {
      "id": 21,
      "question": "A Windows 10 system fails to boot after converting its disk from MBR to GPT. The BIOS is set to legacy mode. What is the MOST likely cause of the boot failure?",
      "options": [
        "UEFI is required to boot from a GPT disk.",
        "The MBR boot sector was not properly deleted.",
        "The boot partition needs to be reformatted to NTFS.",
        "Secure Boot must be enabled after GPT conversion."
      ],
      "correctAnswerIndex": 0,
      "explanation": "GPT disks require UEFI firmware for booting. Legacy BIOS cannot handle GPT partitions for boot drives. MBR boot sector remnants do not impact GPT booting if the BIOS is configured correctly. NTFS formatting affects file system compatibility but not firmware compatibility. Secure Boot enhances security but is not required for GPT disk booting.",
      "examTip": "Ensure UEFI mode is enabled when converting system disks from MBR to GPT to maintain boot capability."
    },
    {
      "id": 22,
      "question": "A Linux administrator needs to prevent all SSH access from external networks while still allowing internal SSH communication. Which firewall configuration would BEST achieve this?",
      "options": [
        "Block port 22 on the external interface using iptables.",
        "Disable SSH service and rely on VPN access.",
        "Limit SSH access to localhost in sshd_config.",
        "Change the default SSH port to a higher, unprivileged port."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Blocking port 22 on the external interface using iptables allows internal SSH traffic while preventing external access. Disabling SSH service would block all connections, including internal. Limiting SSH to localhost would allow only local machine access. Changing the port adds obscurity but doesn’t prevent external access if the port is discovered.",
      "examTip": "Configure firewall rules on external interfaces to limit SSH access to trusted internal networks."
    },
    {
      "id": 23,
      "question": "A user’s Windows 10 laptop fails to wake from sleep after a recent graphics driver update. What is the MOST likely cause of this behavior?",
      "options": [
        "The updated graphics driver is incompatible with the laptop’s hardware.",
        "Fast Startup is conflicting with the updated driver settings.",
        "Hibernation mode is enabled, overriding sleep settings.",
        "The laptop’s power plan settings were reset after the update."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Incompatible graphics drivers often cause display initialization failures after sleep. Fast Startup issues affect booting, not sleep wake behavior. Hibernation overrides sleep but typically doesn’t prevent waking from sleep if not used. Power plan resets impact performance but rarely prevent waking.",
      "examTip": "Roll back or update graphics drivers when laptops fail to resume from sleep after display-related updates."
    },
    {
      "id": 24,
      "question": "A user reports slow file access on a Windows 10 network share. Other users have normal access. Network connectivity is stable. What should the technician check FIRST?",
      "options": [
        "SMB signing settings on the user’s workstation.",
        "Local antivirus software scanning network files.",
        "Network adapter speed and duplex settings.",
        "DNS resolution for the file server hostname."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Local antivirus scanning can slow file access significantly, especially for network shares. SMB signing issues would affect all users if required. Speed and duplex mismatches typically result in broader network issues. DNS resolution problems would prevent access rather than just slowing it.",
      "examTip": "Temporarily disable antivirus scanning for network paths to isolate file access performance issues."
    },
    {
      "id": 25,
      "question": "A technician attempts to install a 64-bit application on a Windows 10 system but encounters compatibility errors. The system shows only 4 GB of usable RAM despite having 8 GB installed. What is the MOST likely cause?",
      "options": [
        "The operating system is 32-bit, limiting RAM and application compatibility.",
        "The system’s BIOS settings restrict RAM usage to 4 GB.",
        "The additional RAM modules are not properly seated.",
        "The system is running in safe mode, limiting driver support."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A 32-bit OS limits RAM usage to 4 GB and cannot run 64-bit applications. BIOS settings affecting RAM would typically show all RAM as hardware reserved. Improperly seated RAM would result in the OS not detecting additional RAM at all. Safe mode limits drivers but doesn’t affect installed RAM capacity readings.",
      "examTip": "Verify OS architecture when encountering RAM limitations and 64-bit application compatibility issues."
    },
    {
      "id": 26,
      "question": "A Linux server’s disk usage is unexpectedly full. The administrator runs 'du' but cannot account for the missing space. What is the MOST likely cause?",
      "options": [
        "A deleted file is still held open by a running process.",
        "The file system journal is corrupted, misreporting usage.",
        "A hidden partition is mounted under the file system.",
        "Disk quotas are reserving space for root user operations."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Deleted files held by active processes continue occupying disk space until the process is terminated. File system journal corruption would lead to broader errors, not silent space usage. Hidden partitions appear as separate mounts. Disk quotas reserve space but are accounted for in standard usage checks.",
      "examTip": "Use 'lsof | grep deleted' to identify and release disk space occupied by deleted files on Linux systems."
    },
    {
      "id": 27,
      "question": "A user complains that an application crashes on launch with a 'missing DLL' error after a recent Windows update. What should the technician do FIRST?",
      "options": [
        "Reinstall the application to restore missing dependencies.",
        "Run sfc /scannow to repair Windows system files.",
        "Check Windows Update history for failed updates.",
        "Use DISM to repair the Windows image."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Reinstalling the application restores missing DLLs associated with the program. sfc /scannow repairs system files, not application-specific dependencies. Checking update history and using DISM are appropriate for broader system issues, not isolated application errors.",
      "examTip": "Reinstall the affected application before performing system-wide repairs for missing dependency errors."
    },
    {
      "id": 28,
      "question": "A macOS user reports being unable to open third-party apps after a major OS upgrade, receiving 'App is damaged and can’t be opened' messages. What is the MOST likely cause?",
      "options": [
        "Gatekeeper settings have reverted to default, blocking non-App Store apps.",
        "FileVault encryption is preventing the execution of unsigned apps.",
        "The apps require updated versions compatible with the new OS.",
        "The apps’ permissions were reset during the OS upgrade."
      ],
      "correctAnswerIndex": 0,
      "explanation": "macOS Gatekeeper resets its settings after major upgrades, potentially blocking unsigned applications. FileVault affects disk encryption, not app execution policies. Compatibility issues typically produce different error messages. Permission resets would cause access errors, not corruption messages.",
      "examTip": "Adjust Gatekeeper settings via System Preferences to allow trusted third-party applications after macOS upgrades."
    },
    {
      "id": 29,
      "question": "A user’s Windows 10 PC cannot access HTTPS websites but can access HTTP sites. What is the MOST likely reason?",
      "options": [
        "Corrupted or missing root certificates.",
        "Firewall rules blocking port 443.",
        "Outdated network drivers.",
        "Browser extensions causing HTTPS redirection issues."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Corrupted or missing root certificates prevent proper SSL/TLS validation for HTTPS connections. Firewall misconfigurations would block all applications using port 443, not just browsers. Outdated network drivers affect all network traffic, not selectively HTTPS. Browser extensions typically cause redirection, not total HTTPS inaccessibility.",
      "examTip": "Update root certificates when HTTPS access fails while HTTP connections remain unaffected."
    },
    {
      "id": 30,
      "question": "A user cannot access a shared network printer after its IP address was changed. Other users can print without issues. What is the FIRST step the technician should take?",
      "options": [
        "Update the printer’s IP address in the user’s printer settings.",
        "Ping the new printer IP address from the user’s workstation.",
        "Reinstall the printer drivers on the user’s computer.",
        "Restart the print spooler service on the user’s workstation."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Updating the IP address in the printer’s settings on the user’s machine resolves access issues after an IP change. Ping tests connectivity but doesn’t resolve configuration mismatches. Reinstalling drivers and restarting spooler services address driver and print queue issues, not network address discrepancies.",
      "examTip": "Always verify and update network printer configurations on user devices following IP address changes."
    },
    {
      "id": 31,
      "question": "A technician suspects that a workstation’s performance issues are caused by malware. The antivirus application has been disabled and cannot be re-enabled. What should the technician do FIRST?",
      "options": [
        "Boot the workstation into Safe Mode with Networking and run a malware scan.",
        "Attempt to reinstall the antivirus application from a trusted source.",
        "Disconnect the workstation from the network and perform a full OS reinstall.",
        "Run the System File Checker (sfc /scannow) to detect corrupted system files."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Booting into Safe Mode with Networking minimizes malware impact while allowing access to updated definitions for scanning. Reinstalling antivirus might fail if malware actively blocks installations. Disconnecting and reinstalling the OS is more drastic. sfc repairs system files but doesn’t remove malware.",
      "examTip": "Start malware remediation by scanning in Safe Mode with Networking to disable persistent malicious processes."
    },
    {
      "id": 32,
      "question": "A Linux administrator observes a sudden drop in available disk space. Which command should they run FIRST to locate large files or directories consuming space?",
      "options": [
        "du -sh /* | sort -rh | head -n 10",
        "df -h",
        "find / -type f -size +100M",
        "ls -lhR /"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The du command summarizes disk usage per directory, sorted to display the largest consumers. df -h shows disk usage per partition, not per directory. find locates large files but doesn’t provide directory-level insights. ls -lhR lists files recursively but isn’t optimized for size summaries.",
      "examTip": "Use 'du' with sorting to efficiently identify disk space hogs in Linux environments."
    },
    {
      "id": 33,
      "question": "A user reports receiving continuous certificate warnings when accessing internal web applications. The system’s date and time are correct. What is the MOST likely cause?",
      "options": [
        "The root certificate for the internal CA is missing from the user’s trusted store.",
        "The internal web server’s SSL certificate has expired.",
        "The user’s browser requires an update to support newer encryption protocols.",
        "A proxy server is intercepting SSL traffic, causing validation errors."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Missing root certificates prevent proper SSL validation. An expired server certificate affects all users, not just one. Browser updates are necessary for new protocols but would block access altogether rather than generate validation warnings. Proxy servers affecting SSL would likely impact multiple users or services.",
      "examTip": "Ensure internal CA root certificates are correctly installed in user systems to prevent SSL validation errors."
    },
    {
      "id": 34,
      "question": "A user’s smartphone battery drains rapidly after installing a new application. What should the technician check FIRST?",
      "options": [
        "Battery usage statistics to determine if the new app consumes excessive power.",
        "Background data usage settings for the installed application.",
        "The latest firmware update availability for the smartphone.",
        "Uninstall and reinstall the application to clear potential corruption."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Reviewing battery usage identifies apps consuming excessive power. Background data settings affect network usage more than battery consumption. Firmware updates may improve performance but are less likely related to a single app’s battery drain. Reinstallation fixes corruption but should follow diagnostic checks.",
      "examTip": "Analyze battery usage per app to pinpoint energy-hungry applications on mobile devices."
    },
    {
      "id": 35,
      "question": "A user reports that after enabling disk encryption on macOS using FileVault, system performance has noticeably decreased. What is the MOST likely reason?",
      "options": [
        "The Mac uses an HDD, which slows performance with full-disk encryption.",
        "The encryption key is stored in user credentials rather than hardware.",
        "FileVault is reindexing the system, temporarily affecting performance.",
        "The macOS version lacks optimized encryption routines for the hardware."
      ],
      "correctAnswerIndex": 0,
      "explanation": "FileVault encryption significantly impacts performance on HDDs due to slower read/write speeds compared to SSDs. Key storage methods don’t affect performance. System reindexing affects search speed but not overall performance. Modern macOS versions have optimized encryption for supported hardware.",
      "examTip": "Consider upgrading to an SSD when enabling FileVault on macOS systems using traditional hard drives."
    },
    {
      "id": 36,
      "question": "A user reports that every time they open their web browser, multiple tabs open with random advertisements. Antivirus scans show no infections. What is the MOST likely cause?",
      "options": [
        "Malicious browser extensions causing unwanted behavior.",
        "Browser’s home page settings were modified by adware.",
        "DNS settings have been hijacked by malicious software.",
        "Corrupted browser profiles triggering incorrect startup behavior."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Malicious browser extensions often cause persistent ads and pop-ups without traditional malware signatures. Home page modifications lead to predictable site redirects, not random ads. DNS hijacking would impact all network traffic, not just the browser. Corrupted profiles would cause loading issues rather than ads.",
      "examTip": "Review and remove suspicious browser extensions when troubleshooting unexplained browser ad behavior."
    },
    {
      "id": 37,
      "question": "A Windows 10 system fails to complete updates, rolling back changes with error 0x8024200D. What is the MOST likely cause?",
      "options": [
        "Corrupted files within the Windows Update download cache.",
        "Insufficient disk space for update installation.",
        "Group Policy preventing specific updates from installing.",
        "Incompatible third-party drivers causing conflicts."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Error 0x8024200D indicates corrupted update downloads. Disk space shortages generate different errors. Group Policy blocks would show access-denied messages. Driver conflicts usually trigger different rollback errors related to hardware compatibility.",
      "examTip": "Clear the SoftwareDistribution folder when facing Windows Update download corruption issues."
    },
    {
      "id": 38,
      "question": "A Linux administrator wants to ensure that critical system logs are archived daily and older archives are automatically deleted after 30 days. Which tool should they use?",
      "options": [
        "logrotate",
        "cron combined with tar and rm commands",
        "systemd-journald built-in rotation",
        "rsyslog with custom retention scripts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "logrotate automates log rotation, compression, and retention policies based on schedules. While cron with tar/rm is possible, it’s less efficient. systemd-journald handles journaling, not advanced retention policies. rsyslog manages log forwarding and storage but lacks built-in rotation features.",
      "examTip": "Configure logrotate for automated log management, including retention, compression, and deletion policies."
    },
    {
      "id": 39,
      "question": "A user cannot authenticate to a corporate wireless network using WPA2-Enterprise. Other devices connect without issue. What is the MOST likely cause?",
      "options": [
        "Incorrect client certificate or expired credentials on the user’s device.",
        "The user’s wireless adapter does not support 802.1X authentication.",
        "A misconfigured RADIUS server preventing proper user validation.",
        "The wireless access point has outdated firmware affecting authentication."
      ],
      "correctAnswerIndex": 0,
      "explanation": "WPA2-Enterprise relies on proper client certificates or credentials for 802.1X authentication. Adapter incompatibility would prevent the network from being visible, not block authentication alone. RADIUS misconfigurations affect all users, not just one. Firmware issues typically cause broader connectivity failures.",
      "examTip": "Verify user certificates and credentials first when individual WPA2-Enterprise authentication issues occur."
    },
    {
      "id": 40,
      "question": "A technician needs to ensure that a critical Windows 10 service restarts automatically after crashing. Which configuration setting should be modified?",
      "options": [
        "Recovery options in the service’s properties within Services.msc.",
        "Enable automatic startup in the service’s registry entry.",
        "Create a scheduled task triggered by service termination events.",
        "Configure the service as a dependency for a stable, always-on service."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Recovery options in Services.msc allow services to restart automatically after failure. Registry modifications are more prone to errors. Scheduled tasks can monitor failures but are less integrated. Service dependencies ensure sequence but don’t restart failed services.",
      "examTip": "Set appropriate recovery actions in service properties to ensure automatic restarts after unexpected failures."
    },
    {
      "id": 41,
      "question": "A Windows 10 user reports that their computer shows a 'The trust relationship between this workstation and the primary domain failed' error. The network is stable, and the domain controller is accessible. What is the MOST efficient method to resolve this without rejoining the domain?",
      "options": [
        "Reset the computer account in Active Directory and reboot the workstation.",
        "Run the 'gpupdate /force' command to reapply group policies.",
        "Remove the computer from the domain and rejoin it after a reboot.",
        "Restart the Netlogon service on the workstation."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Resetting the computer account in Active Directory reestablishes the trust relationship without rejoining the domain. Running gpupdate only refreshes policies but won’t fix trust issues. Removing and rejoining the domain works but is more time-consuming. Restarting Netlogon won’t resolve a broken trust relationship.",
      "examTip": "Reset the computer account in AD for a quick fix to trust relationship errors without rejoining the domain."
    },
    {
      "id": 42,
      "question": "A Linux server is running low on available memory. The administrator needs to identify the top memory-consuming processes. Which command should be used?",
      "options": [
        "top",
        "free -m",
        "ps aux --sort=-%mem",
        "vmstat"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The 'ps aux --sort=-%mem' command lists running processes sorted by memory usage, showing the top consumers. The 'top' command provides real-time process monitoring but requires manual sorting. 'free -m' shows overall memory usage without process breakdown. 'vmstat' shows memory, CPU, and I/O stats but not per-process details.",
      "examTip": "Use 'ps aux --sort=-%mem' for a quick snapshot of top memory-consuming processes in Linux."
    },
    {
      "id": 43,
      "question": "A user complains that their Windows 10 laptop intermittently loses Wi-Fi connectivity after resuming from sleep. Other devices work fine. What should the technician check FIRST?",
      "options": [
        "Power management settings for the wireless adapter.",
        "The latest wireless driver from the laptop manufacturer.",
        "Wi-Fi channel congestion using a network analyzer.",
        "Windows Event Viewer for network-related logs."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Power management settings can disable the wireless adapter during sleep to save power, causing connection loss after wake. Driver issues can cause connectivity problems but are secondary to power settings. Wi-Fi congestion affects performance, not reconnection. Event logs help for broader diagnostics but not immediate reconnection issues.",
      "examTip": "Disable power-saving options for network adapters to maintain Wi-Fi connectivity after sleep."
    },
    {
      "id": 44,
      "question": "A macOS user reports that their computer is running slowly. Activity Monitor shows high CPU usage by the 'kernel_task' process. What is the MOST likely reason?",
      "options": [
        "macOS is managing CPU temperature to prevent overheating.",
        "A third-party kernel extension is causing system instability.",
        "The Spotlight index is being rebuilt after a recent update.",
        "FileVault encryption is consuming CPU during background encryption."
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 'kernel_task' process regulates CPU temperature by occupying processor resources, preventing hardware damage. Third-party kernel extensions can cause instability but would show kernel panics. Spotlight indexing impacts storage, not CPU thermal management. FileVault encryption impacts disk I/O, not kernel CPU regulation.",
      "examTip": "High 'kernel_task' CPU usage usually indicates thermal throttling; check for dust or cooling issues."
    },
    {
      "id": 45,
      "question": "A technician receives reports that multiple users cannot access a shared network drive. However, they can access the internet. What should be checked FIRST?",
      "options": [
        "DNS resolution for the file server’s hostname.",
        "Local firewall settings on user machines.",
        "Permissions on the shared drive.",
        "SMB protocol configuration on the server."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If users can access the internet but not the shared drive, DNS resolution issues are likely preventing them from locating the file server. Firewall settings would typically block all network connections, not just file shares. Permission issues affect specific users, not all. SMB configuration errors would prevent all network file sharing, including internal connections.",
      "examTip": "Check DNS settings first when internal network resources become unreachable while internet access remains available."
    },
    {
      "id": 46,
      "question": "A Linux user reports that they cannot run a script due to 'Permission denied' errors. The script's permissions are '-rw-r--r--'. What is the MOST likely cause?",
      "options": [
        "The script lacks execute permissions.",
        "The user is not the owner of the script file.",
        "The script references an unavailable interpreter.",
        "SELinux is enforcing execution policies."
      ],
      "correctAnswerIndex": 0,
      "explanation": "The '-rw-r--r--' permissions indicate that the execute bit is missing. Without execute permission, the script cannot run. Ownership affects editing rights but not execution if permissions are set. Missing interpreters would cause 'command not found' errors. SELinux enforcement would produce audit logs, not simple permission errors.",
      "examTip": "Use 'chmod +x scriptname' to add execute permissions when encountering script execution errors in Linux."
    },
    {
      "id": 47,
      "question": "A user cannot connect to a VPN that uses L2TP/IPSec. The error states 'Negotiation failed.' What is the MOST likely cause?",
      "options": [
        "UDP ports 500 and 4500 are blocked by the firewall.",
        "The VPN client configuration file is corrupted.",
        "The VPN server’s certificate has expired.",
        "The user's network adapter driver is outdated."
      ],
      "correctAnswerIndex": 0,
      "explanation": "L2TP/IPSec relies on UDP ports 500 and 4500 for key exchange. If these ports are blocked, negotiation fails. A corrupted configuration would typically result in different error messages. An expired server certificate would cause authentication errors, not negotiation failures. Outdated drivers affect connectivity but not negotiation specifically.",
      "examTip": "Ensure UDP ports 500 and 4500 are open when troubleshooting L2TP/IPSec VPN connectivity issues."
    },
    {
      "id": 48,
      "question": "A technician needs to back up a Linux server daily and retain the backups for 7 days, automatically deleting older files. Which tool is BEST suited for this task?",
      "options": [
        "cron with rsync and find commands.",
        "tar with gzip compression manually scheduled.",
        "dd command for full disk imaging.",
        "scp for remote backup transfers."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A cron job using rsync for efficient backups and find to delete backups older than seven days provides an automated solution. tar and gzip handle compression but lack automation. dd is used for full disk images and is inefficient for daily backups. scp transfers files but does not handle scheduling or retention.",
      "examTip": "Automate Linux backups using cron combined with rsync and find for efficient scheduling and retention management."
    },
    {
      "id": 49,
      "question": "A user reports being redirected to phishing websites when entering valid URLs. Clearing the browser cache does not resolve the issue. What is the MOST likely cause?",
      "options": [
        "Malicious entries in the system’s hosts file.",
        "Corrupted browser extensions causing redirection.",
        "DNS cache poisoning at the local resolver level.",
        "Network-level DNS hijacking by an external actor."
      ],
      "correctAnswerIndex": 0,
      "explanation": "The system's hosts file can redirect URLs locally, bypassing DNS settings. Browser extensions typically cause pop-ups or overlays, not persistent redirection. DNS cache poisoning affects multiple sites but may resolve with flushing. Network-level hijacking would affect all devices on the same network.",
      "examTip": "Check the hosts file for unauthorized entries when facing persistent redirection to malicious sites."
    },
    {
      "id": 50,
      "question": "A Windows 10 user’s computer shows 'No Boot Device Found' after connecting an external USB drive. What should the technician check FIRST?",
      "options": [
        "Boot order settings in BIOS/UEFI.",
        "Health status of the external USB drive.",
        "Partition structure of the internal hard drive.",
        "Secure Boot settings in BIOS/UEFI."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A BIOS/UEFI boot order that prioritizes the external USB drive can cause boot issues if the drive is non-bootable. The health of the USB drive is irrelevant if the internal drive is functional. The partition structure affects boot if corrupted but would not cause issues solely after USB connection. Secure Boot settings impact OS validation, not drive prioritization.",
      "examTip": "Check and correct boot order in BIOS after adding new storage devices that may take boot priority."
    },
    {
      "id": 51,
      "question": "A Linux administrator needs to determine which process is using the most CPU over time. Which command provides this information in real time?",
      "options": [
        "top",
        "htop",
        "ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu",
        "vmstat 1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 'top' command provides real-time monitoring of CPU usage per process. 'htop' offers similar functionality but may not be installed by default. 'ps' provides a snapshot but lacks real-time updates. 'vmstat' shows overall system performance but not per-process CPU usage.",
      "examTip": "Use 'top' for real-time process-level CPU usage analysis on Linux systems."
    },
    {
      "id": 52,
      "question": "A user’s Windows 10 PC is experiencing frequent 'Blue Screen of Death' (BSOD) errors after a recent memory upgrade. Which built-in tool can help diagnose the issue?",
      "options": [
        "Windows Memory Diagnostic",
        "System File Checker (sfc /scannow)",
        "Device Manager",
        "Reliability Monitor"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Windows Memory Diagnostic tests RAM for errors, which commonly cause BSODs after memory upgrades. System File Checker scans for corrupted system files but does not test hardware. Device Manager shows hardware status but lacks diagnostic capabilities. Reliability Monitor tracks error history but cannot run hardware diagnostics.",
      "examTip": "Run Windows Memory Diagnostic after memory upgrades when BSOD errors suggest hardware compatibility issues."
    },
    {
      "id": 53,
      "question": "A Linux administrator needs to archive and compress a directory. Which command accomplishes this in a single step using gzip compression?",
      "options": [
        "tar -czvf archive.tar.gz /path/to/directory",
        "zip -r archive.zip /path/to/directory",
        "gzip /path/to/directory",
        "tar -xvzf archive.tar.gz"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 'tar -czvf' command creates a compressed archive in gzip format. 'zip -r' creates a zip archive but is not gzip. 'gzip' compresses individual files but does not archive directories. 'tar -xvzf' extracts compressed tar archives, not create them.",
      "examTip": "Use 'tar -czvf' for efficient archiving and compression of directories in Linux."
    },
    {
      "id": 54,
      "question": "A technician must ensure that an application runs at startup for all users on a Windows 10 system. Where should the application shortcut be placed?",
      "options": [
        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "C:\\Users\\Default\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Placing the shortcut in 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup' ensures the application runs for all users. The 'Default' user folder affects only new profiles. Registry entries in HKEY_LOCAL_MACHINE affect all users but are more complex. HKEY_CURRENT_USER applies to individual user profiles.",
      "examTip": "Use the ProgramData Startup folder for user-independent application startup configurations."
    },
    {
      "id": 55,
      "question": "A user’s Linux system fails to boot after a kernel update. Which action allows the system to boot using a previous kernel version?",
      "options": [
        "Select the previous kernel from the GRUB menu during boot.",
        "Use 'systemctl default' to reset the boot target.",
        "Boot into rescue mode and reinstall the kernel.",
        "Execute 'update-grub' to rebuild the GRUB configuration."
      ],
      "correctAnswerIndex": 0,
      "explanation": "The GRUB menu allows users to select previous kernels if the latest update causes boot failures. 'systemctl default' resets boot targets but doesn’t change kernels. Rescue mode and kernel reinstallation are more advanced recovery methods. 'update-grub' rebuilds the menu but doesn’t address kernel issues directly.",
      "examTip": "Access the GRUB menu during boot to revert to a previous kernel after problematic updates."
    },
    {
      "id": 56,
      "question": "A user reports they cannot access any HTTPS websites, but HTTP sites load without issue. What is the MOST likely cause?",
      "options": [
        "Corrupted root certificates on the user’s machine.",
        "ISP-level restrictions on secure web traffic.",
        "A disabled SSL/TLS protocol in the web browser settings.",
        "Outdated browser version lacking modern encryption support."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Corrupted root certificates prevent SSL/TLS handshakes required for HTTPS connections. ISP restrictions on HTTPS traffic are rare and would affect multiple users. Browser settings disabling SSL/TLS would impact a specific browser, not system-wide access. Outdated browsers usually show version-related warnings, not total HTTPS failure.",
      "examTip": "Verify root certificate integrity when HTTPS access fails but HTTP remains functional."
    },
    {
      "id": 57,
      "question": "A Windows 10 machine is stuck in a continuous reboot loop after a failed update. Which option in the Advanced Startup settings can break the loop?",
      "options": [
        "Boot into Safe Mode and uninstall recent updates.",
        "Perform a system restore to a previous point.",
        "Use 'Startup Repair' to fix boot issues.",
        "Enable 'Disable automatic restart on system failure' to view errors."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Disabling automatic restart reveals the underlying error message, assisting in troubleshooting. Safe Mode and System Restore are corrective actions but require identifying the issue first. Startup Repair fixes boot issues but may not resolve problems related to recent updates.",
      "examTip": "Disable automatic restarts during continuous reboot loops to identify critical error messages."
    },
    {
      "id": 58,
      "question": "A user’s Windows 10 laptop prompts for a BitLocker recovery key on every startup. TPM is enabled. What is the MOST likely reason?",
      "options": [
        "A firmware update changed the system's boot measurements.",
        "The boot partition was resized without suspending BitLocker.",
        "Group Policy is enforcing additional authentication steps.",
        "The recovery key storage location is no longer accessible."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Firmware updates modify the TPM’s measured boot environment, triggering BitLocker recovery key prompts. Partition resizing affects boot configurations but not TPM measurements. Group Policy changes would have applied consistently from the start. Key storage issues prevent access entirely, not cause repeated prompts.",
      "examTip": "Suspend and resume BitLocker after firmware updates to reset TPM measurements and avoid recovery key prompts."
    },
    {
      "id": 59,
      "question": "A technician needs to configure a Windows system to prevent unauthorized USB storage devices from mounting. Which method BEST achieves this?",
      "options": [
        "Modify Group Policy to disable removable storage classes.",
        "Disable USB ports in BIOS/UEFI settings.",
        "Install endpoint protection software to block external media.",
        "Enable BitLocker on all USB devices."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Group Policy allows granular control over USB device classes without physically disabling ports. BIOS settings remove all USB functionality, including keyboards and mice. Endpoint protection solutions may not provide the required granularity. BitLocker encrypts devices but does not prevent mounting.",
      "examTip": "Use Group Policy to block unauthorized USB storage while preserving other USB functionalities."
    },
    {
      "id": 60,
      "question": "A user’s smartphone fails to install OS updates due to 'Insufficient storage.' Clearing the cache and deleting unused apps have not freed enough space. What should be done NEXT?",
      "options": [
        "Move media files to cloud storage or an SD card.",
        "Perform a factory reset and restore from backup.",
        "Use developer options to enable lightweight update mode.",
        "Root the device to manually remove system bloatware."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Moving media to cloud storage or SD cards frees significant space without affecting the OS. Factory resets are disruptive and should be a last resort. Developer options don’t typically impact update installation size. Rooting voids warranties and risks device stability.",
      "examTip": "Prioritize non-destructive storage management methods like offloading media when addressing mobile storage limitations."
    },
    {
      "id": 61,
      "question": "A user reports that after a recent Windows update, their system hangs on the manufacturer’s logo and doesn’t proceed to the login screen. Safe Mode also fails to load. What is the MOST likely cause?",
      "options": [
        "Corrupted boot configuration data (BCD).",
        "Incompatible driver installed during the update.",
        "BitLocker encryption requiring a recovery key.",
        "A disabled Secure Boot setting in UEFI firmware."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An incompatible driver installed during the update can prevent both normal and Safe Mode boot, as essential drivers load early in the boot process. Corrupted BCD typically shows a 'BOOTMGR missing' error. BitLocker issues would prompt for a recovery key, not cause a hang. Secure Boot being disabled doesn’t cause a hang unless specific security policies are enforced.",
      "examTip": "If Safe Mode fails after an update, suspect critical driver issues; roll back updates using recovery tools."
    },
    {
      "id": 62,
      "question": "A Linux administrator wants to configure a cron job to run a script every Sunday at midnight. Which crontab entry is correct?",
      "options": [
        "0 0 * * 0 /path/to/script.sh",
        "0 0 7 * * /path/to/script.sh",
        "0 0 * * 7 /path/to/script.sh",
        "0 0 */7 * * /path/to/script.sh"
      ],
      "correctAnswerIndex": 0,
      "explanation": "In cron syntax, '0 0 * * 0' runs a script at midnight on Sundays. '7' for the day-of-week field is invalid in many cron implementations. '0 0 7 * *' runs the script on the 7th day of every month. '*/7' means every 7 days, not specifically Sundays.",
      "examTip": "Use '0' in the day-of-week field for Sunday in crontab schedules for standard Linux cron implementations."
    },
    {
      "id": 63,
      "question": "A user cannot access an internal web application over HTTPS, but HTTP access works fine. Other users have no issues. What is the MOST likely cause?",
      "options": [
        "Corrupted SSL certificates on the user's device.",
        "The user’s browser does not support the server’s encryption protocols.",
        "Network firewall blocking TCP port 443 for the user’s device.",
        "Incorrect DNS settings redirecting HTTPS requests."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Corrupted SSL certificates on the user’s system can prevent proper HTTPS handshake, while HTTP remains unaffected. If the browser lacked support for encryption protocols, all secure sites would be inaccessible. A firewall blocking port 443 would prevent all HTTPS connections, but this would likely impact other services. DNS misconfiguration would prevent access entirely, not just HTTPS.",
      "examTip": "Reinstall root certificates or reset the browser’s SSL cache when HTTPS fails but HTTP remains accessible."
    },
    {
      "id": 64,
      "question": "A Windows 10 system displays 'Operating System not found' after replacing the motherboard. What is the MOST likely reason?",
      "options": [
        "UEFI/BIOS boot mode mismatch (UEFI vs. Legacy).",
        "The drive partition is no longer marked as active.",
        "Corrupted master boot record (MBR).",
        "A missing bootloader due to drive formatting."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Replacing the motherboard may reset UEFI/BIOS settings. If the new motherboard defaults to a different boot mode (Legacy instead of UEFI or vice versa), the system won’t detect the OS. A missing active partition or corrupted MBR typically causes boot errors but not complete OS detection failure. A missing bootloader would result from disk formatting, which wasn’t indicated here.",
      "examTip": "Always check BIOS boot mode settings after motherboard replacement to ensure OS compatibility."
    },
    {
      "id": 65,
      "question": "A user’s computer shows the error 'NTLDR is missing' during boot. What is the FIRST action the technician should take?",
      "options": [
        "Check BIOS settings for correct boot order.",
        "Replace the NTLDR file using recovery tools.",
        "Rebuild the master boot record (MBR).",
        "Run the chkdsk utility to fix disk errors."
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 'NTLDR is missing' error often occurs when the BIOS attempts to boot from a non-bootable drive. Verifying boot order is the quickest check. Replacing NTLDR or rebuilding the MBR may be necessary but are secondary steps. Disk errors typically result in read/write failures, not NTLDR-specific errors.",
      "examTip": "Start boot-related troubleshooting by verifying BIOS boot sequence before performing file or disk repairs."
    },
    {
      "id": 66,
      "question": "A user complains that their Android device’s battery drains rapidly after installing a new app. What should the technician check FIRST?",
      "options": [
        "Battery usage statistics for the app in device settings.",
        "Background data permissions for the app.",
        "App updates that may optimize battery consumption.",
        "Power-saving mode status on the device."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Battery usage statistics help identify if the new app is the cause. Background data settings affect network use more than battery life. While app updates may help, the root cause must first be confirmed. Power-saving modes impact performance but don’t directly indicate which app is draining the battery.",
      "examTip": "Always review per-app battery usage data when troubleshooting rapid battery drain after app installation."
    },
    {
      "id": 67,
      "question": "A Linux server shows high disk I/O latency. The administrator wants real-time statistics to identify the issue. Which command provides this information?",
      "options": [
        "iostat -x 1",
        "df -h",
        "du -sh /*",
        "vmstat 1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 'iostat -x 1' command gives extended I/O statistics, showing real-time device utilization and wait times. 'df -h' shows disk space usage but not I/O performance. 'du -sh' summarizes directory sizes but provides no performance data. 'vmstat 1' offers general system performance but lacks detailed disk I/O data.",
      "examTip": "Use 'iostat' with the '-x' flag for detailed disk performance diagnostics on Linux systems."
    },
    {
      "id": 68,
      "question": "A technician needs to configure a system to prevent users from installing unauthorized applications. Which Windows feature provides the MOST granular control for this requirement?",
      "options": [
        "AppLocker",
        "User Account Control (UAC)",
        "Group Policy software restrictions",
        "Windows Defender Application Control"
      ],
      "correctAnswerIndex": 0,
      "explanation": "AppLocker allows specific whitelisting or blacklisting of applications based on publisher, path, or file hash, providing granular control. UAC manages privilege elevation but doesn’t control which apps can be installed. Group Policy software restrictions are less flexible than AppLocker. Windows Defender Application Control is powerful but more complex to implement for basic needs.",
      "examTip": "Deploy AppLocker for precise application control without affecting user productivity on Windows systems."
    },
    {
      "id": 69,
      "question": "A Windows 10 system displays frequent BSODs with the error 'IRQL_NOT_LESS_OR_EQUAL.' What is the MOST likely cause?",
      "options": [
        "Faulty or incompatible device drivers.",
        "Bad sectors on the hard drive.",
        "Memory corruption in system RAM.",
        "Corrupted Windows system files."
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 'IRQL_NOT_LESS_OR_EQUAL' BSOD usually points to driver conflicts or hardware addressing issues. While memory corruption could also cause this, driver issues are more common. Hard drive problems typically cause file access errors, not BSODs with this specific message. System file corruption shows different error codes.",
      "examTip": "Update or roll back drivers when 'IRQL_NOT_LESS_OR_EQUAL' BSOD errors occur to resolve compatibility issues."
    },
    {
      "id": 70,
      "question": "A user reports that their browser displays a 'certificate not trusted' warning when accessing an internal company website. Other users have no issues. What should the technician check FIRST?",
      "options": [
        "Ensure the user’s device has the internal CA’s root certificate installed.",
        "Verify the server’s SSL certificate expiration date.",
        "Check if the user’s browser supports the encryption protocol used by the server.",
        "Flush the DNS cache on the user’s device."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If only one user experiences trust warnings, the likely cause is the absence of the internal certificate authority’s root certificate. Server certificate expiration would affect all users. Encryption protocol issues typically impact entire browser sessions, not specific internal sites. DNS cache problems wouldn’t cause SSL trust issues.",
      "examTip": "Install internal CA root certificates on client devices to prevent trust warnings for internal web services."
    },
    {
      "id": 71,
      "question": "A Linux administrator suspects a rootkit on a server. Which command can help detect unauthorized kernel modules?",
      "options": [
        "lsmod",
        "modprobe -l",
        "dmesg | grep rootkit",
        "chkrootkit"
      ],
      "correctAnswerIndex": 3,
      "explanation": "'chkrootkit' scans for common rootkits, including hidden kernel modules. 'lsmod' lists current kernel modules but doesn’t detect malicious ones. 'modprobe -l' lists available modules, not active ones. 'dmesg' shows kernel messages but requires manual inspection, which may miss subtle rootkits.",
      "examTip": "Use specialized tools like 'chkrootkit' for comprehensive rootkit detection on Linux systems."
    },
    {
      "id": 72,
      "question": "A user’s mobile device is overheating during normal use. Which setting is MOST likely contributing to this issue?",
      "options": [
        "Constant GPS usage by background apps.",
        "Wi-Fi always scanning for networks.",
        "Screen brightness set to maximum.",
        "Frequent push notifications from multiple apps."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Continuous GPS use is resource-intensive, generating heat due to constant hardware engagement. Wi-Fi scanning uses less power and heat. Screen brightness affects battery more than temperature. Push notifications have minimal impact on temperature unless linked to resource-heavy apps.",
      "examTip": "Disable GPS access for non-essential apps to reduce overheating and battery drain on mobile devices."
    },
    {
      "id": 73,
      "question": "A Windows 10 user reports slow system performance after installing a legacy 32-bit application. What should the technician check FIRST?",
      "options": [
        "Resource consumption in Task Manager.",
        "Compatibility settings for the application.",
        "Available disk space on the system drive.",
        "Windows Event Viewer for application errors."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Task Manager reveals whether the legacy application consumes excessive CPU, RAM, or disk resources. Compatibility settings help with execution but not performance. Disk space shortages impact storage-related performance, not CPU load. Event Viewer tracks errors but may not highlight performance issues.",
      "examTip": "Use Task Manager to identify resource-heavy applications causing system slowdowns after installations."
    },
    {
      "id": 74,
      "question": "A technician needs to ensure sensitive data on decommissioned SSDs cannot be recovered. Which method is MOST effective?",
      "options": [
        "Use the SSD manufacturer’s secure erase utility.",
        "Perform multiple overwrites with random data using dd.",
        "Encrypt the entire drive and delete the encryption key.",
        "Physically destroy the SSD using specialized shredders."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Manufacturer-specific secure erase utilities trigger the SSD's internal commands to effectively remove all data. Overwriting data may not impact hidden areas due to SSD wear leveling. Encryption key deletion leaves encrypted data but may not be accepted for high-security disposal. Physical destruction is effective but more costly and unnecessary for lower security levels.",
      "examTip": "Use SSD-specific secure erase tools for efficient and complete data removal before disposal."
    },
    {
      "id": 75,
      "question": "A Windows 10 laptop cannot connect to the corporate Wi-Fi after changing its hostname. Other devices work fine. What is the MOST likely cause?",
      "options": [
        "The DHCP server still associates the old hostname with the device's MAC address.",
        "802.1X authentication settings were reset during hostname change.",
        "The wireless profile became corrupted after the hostname change.",
        "Static IP settings were lost, preventing proper DHCP assignment."
      ],
      "correctAnswerIndex": 0,
      "explanation": "The DHCP server may have cached the device’s old hostname, leading to conflicts in IP assignment. Authentication settings typically don’t rely on hostname. Corrupted wireless profiles would affect all networks, not just one. Static IP loss would result in no network assignment at all, not just Wi-Fi issues.",
      "examTip": "Release and renew DHCP leases after hostname changes to avoid IP conflicts in enterprise networks."
    },
    {
      "id": 76,
      "question": "A technician is troubleshooting slow access to shared files on a Windows network. Pings to the file server show normal latency. What should the technician check NEXT?",
      "options": [
        "SMB signing settings on the file server and client.",
        "Network switch port duplex mismatches.",
        "DNS resolution times for the file server’s hostname.",
        "Disk performance metrics on the file server."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Duplex mismatches between network switches and NICs cause significant slowdowns despite normal ping times. SMB signing affects security, not speed, unless misconfigured. DNS resolution issues would show longer ping times. Disk performance would impact all file server clients, not just one connection.",
      "examTip": "Verify network port duplex settings when troubleshooting slow file transfers despite normal latency."
    },
    {
      "id": 77,
      "question": "A user reports that their Windows 10 system is stuck at 'Preparing Automatic Repair.' What is the MOST efficient next step?",
      "options": [
        "Boot into recovery mode and run 'chkdsk /f /r' on the system drive.",
        "Perform a full OS reinstall from installation media.",
        "Boot into Safe Mode and uninstall recent drivers or updates.",
        "Use System Restore from Advanced Startup options."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Running 'chkdsk' can fix disk-related errors causing startup loops without affecting data. OS reinstallations are last-resort measures. Safe Mode may not be accessible if the system is stuck in the repair loop. System Restore is useful but requires restore points, which may not exist.",
      "examTip": "Run 'chkdsk' first when Windows enters an automatic repair loop, addressing potential disk corruption quickly."
    },
    {
      "id": 78,
      "question": "A Linux administrator needs to check which services are enabled to start at boot. Which command provides this information on a system using systemd?",
      "options": [
        "systemctl list-unit-files --type=service",
        "chkconfig --list",
        "service --status-all",
        "rc-status"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'systemctl list-unit-files --type=service' shows all services and their startup status on systemd systems. 'chkconfig' is used with SysVinit. 'service --status-all' shows running services but not boot status. 'rc-status' is specific to OpenRC systems.",
      "examTip": "Use 'systemctl list-unit-files' for startup service management on systemd-based Linux distributions."
    },
    {
      "id": 79,
      "question": "A user reports that after enabling FileVault on their Mac, system boot times have increased significantly. The Mac uses a traditional HDD. What is the MOST likely cause?",
      "options": [
        "Disk encryption overhead impacting read/write performance on HDDs.",
        "FileVault reindexing the file system for encryption consistency.",
        "Firmware issues causing encryption conflicts during startup.",
        "Insufficient RAM slowing encryption key loading during boot."
      ],
      "correctAnswerIndex": 0,
      "explanation": "FileVault encryption significantly affects performance on HDDs due to slower disk access compared to SSDs. Reindexing affects Spotlight search performance, not boot times. Firmware issues would prevent encryption loading altogether. RAM shortages affect multitasking, not specifically encryption processes.",
      "examTip": "Consider SSD upgrades when enabling full-disk encryption on macOS systems using traditional hard drives."
    },
    {
      "id": 80,
      "question": "A technician needs to ensure that a Linux script runs immediately after the system finishes booting. Which method is MOST appropriate?",
      "options": [
        "Create a systemd service with 'After=network.target' and enable it.",
        "Place the script in '/etc/init.d/' and create symbolic links in '/etc/rc.d/'.",
        "Add the script to '/etc/rc.local' with executable permissions.",
        "Schedule the script using 'cron @reboot'."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Using systemd ensures that the script runs at the proper time after boot, respecting dependencies like network availability. init.d methods are outdated. '/etc/rc.local' may not exist in modern distributions. 'cron @reboot' executes scripts but lacks dependency management.",
      "examTip": "Create systemd services for reliable, dependency-aware startup script execution on modern Linux systems."
    },
    {
      "id": 81,
      "question": "A user reports that after upgrading to Windows 11, some legacy applications fail to launch with compatibility errors. The applications worked fine on Windows 10. What should the technician do FIRST to resolve the issue?",
      "options": [
        "Run the applications in compatibility mode for Windows 10.",
        "Install the latest patches and updates for Windows 11.",
        "Reinstall the legacy applications using administrator privileges.",
        "Use Hyper-V to create a virtual machine running Windows 10."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Running the applications in compatibility mode for Windows 10 allows legacy software to function without complex changes. Updating Windows 11 may help, but compatibility mode is quicker. Reinstallation doesn’t address OS compatibility. Creating a virtual machine adds unnecessary complexity unless all else fails.",
      "examTip": "Always try compatibility mode for legacy applications before implementing time-consuming solutions like virtualization."
    },
    {
      "id": 82,
      "question": "A Linux server fails to mount a network file system (NFS) share during boot but mounts correctly when done manually after boot. What is the MOST likely cause?",
      "options": [
        "The network service starts after the NFS mount attempt during boot.",
        "Incorrect permissions on the NFS export directory.",
        "NFS client utilities are missing from the server.",
        "The firewall blocks NFS-related ports during system boot."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If the NFS share mounts manually but not at boot, it suggests that the network service starts after the mount attempt. Permissions issues would prevent manual mounts. Missing NFS utilities would fail all mount attempts. Firewall configurations typically affect all network connections, not just boot-time mounts.",
      "examTip": "Use the 'network-online.target' dependency in systemd unit files to ensure network availability before mounting NFS shares."
    },
    {
      "id": 83,
      "question": "A Windows 10 machine cannot connect to a secured Wi-Fi network after a recent driver update. The error states 'Cannot connect to this network.' Other devices connect without issues. What is the MOST likely cause?",
      "options": [
        "The updated wireless driver is incompatible with the access point’s security settings.",
        "The wireless adapter was disabled during the update process.",
        "The network profile was corrupted and needs to be recreated.",
        "The Wi-Fi adapter firmware is outdated and requires an update."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Driver incompatibilities with specific security protocols (like WPA3) can prevent connections. Disabling the adapter would show no networks. Corrupted profiles often cause prompt errors rather than connection denial. Outdated firmware issues would impact all networks, not just secured ones.",
      "examTip": "Roll back wireless drivers when connectivity issues arise immediately after driver updates."
    },
    {
      "id": 84,
      "question": "A user reports that every time they open their web browser, multiple tabs open with advertisements. Antivirus scans show no infections. What is the MOST likely cause?",
      "options": [
        "Malicious browser extensions causing ad injections.",
        "Corrupted browser cache leading to incorrect startup behavior.",
        "DNS cache poisoning redirecting legitimate URLs to ad networks.",
        "A compromised hosts file redirecting traffic to ad-related domains."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Malicious browser extensions can inject ads and override default homepages without traditional malware signatures. Browser cache corruption wouldn’t cause consistent ad tab opening. DNS cache poisoning affects multiple applications, not just the browser. Hosts file modifications typically redirect specific URLs rather than open multiple ad tabs on startup.",
      "examTip": "Always check and remove suspicious browser extensions when troubleshooting unexplained advertising behavior."
    },
    {
      "id": 85,
      "question": "A Linux user reports that after mounting a Windows-formatted NTFS drive, they have read-only access despite correct permissions. What is the MOST likely reason?",
      "options": [
        "The NTFS partition was mounted without specifying write permissions.",
        "The user lacks proper NTFS ownership for write operations.",
        "The drive is marked as dirty and needs chkdsk on a Windows system.",
        "Linux kernel support for NTFS write operations is missing."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If the NTFS drive was mounted without 'rw' (read-write) specified, it defaults to read-only mode. Ownership issues would typically present as permission errors. A dirty bit would prevent mounting entirely, requiring Windows repair. Modern Linux kernels have built-in NTFS write support, making missing kernel support unlikely.",
      "examTip": "Ensure 'rw' is specified when mounting NTFS drives on Linux to enable write operations."
    },
    {
      "id": 86,
      "question": "A user’s Windows system throws an error stating 'Boot configuration data file is missing' after a failed update. What command should the technician use FIRST to resolve this issue?",
      "options": [
        "bootrec /rebuildbcd",
        "bootrec /fixmbr",
        "sfc /scannow",
        "chkdsk /r"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 'bootrec /rebuildbcd' command rebuilds the Boot Configuration Data (BCD), resolving missing BCD errors. The '/fixmbr' command repairs the master boot record but doesn’t address BCD. 'sfc /scannow' repairs system files, not boot records. 'chkdsk /r' checks disk integrity but doesn’t fix boot configuration problems.",
      "examTip": "For missing BCD errors, prioritize the 'bootrec /rebuildbcd' command before exploring other boot repair options."
    },
    {
      "id": 87,
      "question": "A macOS user reports being unable to install applications from outside the App Store due to a 'cannot be opened because it is from an unidentified developer' error. What should the technician recommend?",
      "options": [
        "Temporarily disable Gatekeeper in Security & Privacy settings.",
        "Enable FileVault to allow application installations.",
        "Install applications via Terminal using sudo privileges.",
        "Modify the application’s permissions using chmod."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Gatekeeper prevents the installation of apps from unidentified developers. Temporarily disabling it allows installation. FileVault concerns encryption, not installation policies. sudo in Terminal doesn’t bypass Gatekeeper restrictions. chmod adjusts permissions but doesn’t impact developer verification.",
      "examTip": "Temporarily adjust Gatekeeper settings in macOS to allow trusted third-party application installations."
    },
    {
      "id": 88,
      "question": "A user reports frequent SSL certificate warnings when accessing internal web services. The system’s time and date are correct. What is the MOST likely cause?",
      "options": [
        "The root certificate for the internal CA is missing from the user’s trusted store.",
        "The internal web server’s SSL certificate has expired.",
        "The user’s browser requires updates to support newer encryption protocols.",
        "A proxy server is intercepting SSL traffic, causing validation errors."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Missing root certificates prevent proper SSL validation. An expired certificate would affect all users, not just one. Browser updates would typically block all secure sites, not specific internal services. Proxy interception affects multiple users unless user-specific policies are applied.",
      "examTip": "Ensure internal root certificates are correctly installed on all clients accessing internal secure services."
    },
    {
      "id": 89,
      "question": "A user complains that after a Windows update, the laptop prompts for a BitLocker recovery key on every reboot. TPM is enabled. What is the MOST likely cause?",
      "options": [
        "Firmware update changed TPM measurements, triggering recovery mode.",
        "The boot partition was resized during the update process.",
        "Group Policy now enforces multi-factor authentication on boot.",
        "The recovery key storage location is no longer accessible."
      ],
      "correctAnswerIndex": 0,
      "explanation": "TPM measurements change after firmware updates, causing BitLocker to prompt for a recovery key. Boot partition resizing impacts OS loading, not necessarily triggering recovery prompts. Group Policy changes would impact all systems under its scope. Recovery key storage issues would cause a single failed attempt, not repeated prompts.",
      "examTip": "Always suspend BitLocker before firmware updates to avoid TPM measurement mismatches requiring recovery keys."
    },
    {
      "id": 90,
      "question": "A technician needs to automate backups on a Linux server and delete backups older than 7 days. Which approach is BEST?",
      "options": [
        "Create a cron job using rsync for backups and 'find' for cleanup.",
        "Schedule tar compression with cron and manually delete old files.",
        "Use dd for disk cloning and create a cleanup bash script.",
        "Implement SCP transfers with cron and manually prune files."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Combining rsync with cron provides efficient incremental backups, and 'find' automates the deletion of older backups. tar and dd are less flexible and efficient for daily backups. SCP handles transfers but doesn’t manage local retention.",
      "examTip": "Combine rsync and find in cron jobs for efficient automated backups and retention management in Linux."
    },
    {
      "id": 91,
      "question": "A Linux administrator wants to identify processes consuming the most CPU in real time. Which command is BEST suited for this purpose?",
      "options": [
        "top",
        "ps aux --sort=-%cpu",
        "vmstat 1",
        "iostat -x 1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'top' provides real-time process information, including CPU consumption. 'ps aux' gives a snapshot but not continuous updates. 'vmstat' shows system-wide statistics, not process-specific. 'iostat' focuses on I/O statistics, not CPU usage.",
      "examTip": "Use 'top' for real-time process monitoring, focusing on CPU consumption in Linux environments."
    },
    {
      "id": 92,
      "question": "A user complains that after installing a third-party antivirus, Windows Defender remains active. What is the MOST likely reason?",
      "options": [
        "Windows Defender stays active for periodic scans even when third-party antivirus is installed.",
        "The third-party antivirus is incompatible with Windows Security Center.",
        "Windows Defender real-time protection must be disabled manually.",
        "Group Policy settings enforce Windows Defender protection."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Windows Defender can perform limited periodic scans for additional protection even when third-party antivirus software is present. Incompatibility issues would typically block installation. Real-time protection is automatically disabled unless Group Policy dictates otherwise.",
      "examTip": "Windows Defender may perform periodic scans alongside third-party antivirus unless explicitly disabled via policy."
    },
    {
      "id": 93,
      "question": "A Windows 10 user reports that after changing their account password, they can no longer access mapped network drives. What is the MOST likely cause?",
      "options": [
        "Cached credentials for mapped drives were invalidated after the password change.",
        "The user’s permissions on the file server were removed during the password update.",
        "DNS cache must be flushed to resolve updated network paths.",
        "Offline file synchronization failed due to mismatched credentials."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Password changes invalidate cached credentials used for network resource access. Permissions removal would block access entirely, not just after a password change. DNS caching affects host resolution, not authentication. Offline sync issues don’t impact immediate access.",
      "examTip": "Remap network drives or update cached credentials after account password changes in Windows."
    },
    {
      "id": 94,
      "question": "A user’s Android device displays high data usage for an app that should only function over Wi-Fi. What setting should the technician check FIRST?",
      "options": [
        "Disable background data usage for the app over mobile networks.",
        "Restrict app permissions related to mobile data access.",
        "Verify that mobile data limit warnings are enabled.",
        "Clear the app’s cache to reset network usage counters."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Background data settings can cause apps to use mobile data unexpectedly. Permission restrictions typically affect app functionality rather than data usage specifically. Data limit warnings notify users but don’t prevent usage. Clearing the cache doesn’t impact data consumption.",
      "examTip": "Always check and disable background mobile data usage settings when addressing unexpected data consumption."
    },
    {
      "id": 95,
      "question": "A user’s Windows 10 system frequently shows low virtual memory warnings. The machine has sufficient RAM installed. What should the technician check FIRST?",
      "options": [
        "Verify the system’s paging file size settings.",
        "Run memory diagnostics to check for hardware issues.",
        "Check for malware consuming excessive memory.",
        "Increase the maximum virtual memory allocation manually."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Virtual memory warnings occur if the paging file size is insufficient. Hardware issues would result in errors or crashes, not memory warnings. Malware checks are important but less likely if RAM is underutilized. Increasing maximum virtual memory is a solution but confirming current settings is faster.",
      "examTip": "Ensure Windows is managing paging file size automatically or adjust settings based on workload demands."
    },
    {
      "id": 96,
      "question": "A Linux administrator notices that system logs are missing entries after a power outage. Which tool can help recover or analyze what went wrong during the outage?",
      "options": [
        "journalctl",
        "syslog",
        "dmesg",
        "last"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'journalctl' accesses persistent logs managed by systemd, which may contain pre-outage data. 'syslog' may not retain logs if improperly configured. 'dmesg' shows current kernel messages, not historical ones. 'last' shows login records but not system logs.",
      "examTip": "Use 'journalctl' to access system logs that persist across reboots and outages in systemd-managed Linux environments."
    },
    {
      "id": 97,
      "question": "A technician needs to securely dispose of a hard drive containing sensitive data. What is the MOST secure method for ensuring data cannot be recovered?",
      "options": [
        "Degauss the drive before physical destruction.",
        "Overwrite the drive with random data multiple times.",
        "Delete all partitions and format the drive using full format.",
        "Use disk-wiping software compliant with DoD 5220.22-M standards."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Degaussing destroys the magnetic fields on the drive, making data recovery impossible, especially when followed by physical destruction. Overwriting data may still leave traces recoverable with advanced tools. Formatting removes file pointers but not underlying data. DoD-compliant wiping is effective but not as final as degaussing followed by destruction.",
      "examTip": "Combine degaussing with physical destruction for the most secure hard drive disposal when handling sensitive data."
    },
    {
      "id": 98,
      "question": "A Windows 10 machine shows 'No boot device found' after adding a second hard drive. What should the technician check FIRST?",
      "options": [
        "Verify boot order settings in BIOS/UEFI.",
        "Ensure that the new hard drive is properly connected.",
        "Rebuild the master boot record on the primary drive.",
        "Check for partition conflicts between the two drives."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Adding a new hard drive may change boot priorities, causing the system to attempt booting from a non-bootable disk. Improper connections would prevent drive detection altogether. Partition conflicts would not prevent BIOS from recognizing bootable media. Rebuilding MBR isn’t necessary unless corruption is evident.",
      "examTip": "After adding storage devices, always confirm that BIOS/UEFI boot order still points to the correct primary drive."
    },
    {
      "id": 99,
      "question": "A Linux system administrator wants to enforce password expiration policies. Which file should be modified to set default password aging settings for all users?",
      "options": [
        "/etc/login.defs",
        "/etc/shadow",
        "/etc/passwd",
        "/etc/security/pwquality.conf"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'/etc/login.defs' sets system-wide password aging policies. '/etc/shadow' stores individual user password aging data but isn’t used for default settings. '/etc/passwd' manages user account information without password aging details. 'pwquality.conf' controls password complexity, not expiration.",
      "examTip": "Modify '/etc/login.defs' to enforce global password aging policies on Linux systems."
    },
    {
      "id": 100,
      "question": "A user reports that their Windows 10 system takes significantly longer to boot after enabling full-disk encryption. The system uses an HDD. What is the MOST likely reason?",
      "options": [
        "Full-disk encryption adds overhead during read/write operations, especially on HDDs.",
        "The encryption key storage location requires network connectivity at boot.",
        "System restore points are being created at every boot due to encryption policies.",
        "The encryption process is incomplete, causing delayed boot times until finished."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Full-disk encryption like BitLocker introduces read/write overhead, which is more noticeable on slower HDDs compared to SSDs. Key storage requirements would prevent booting altogether, not just slow it. System restore creation doesn’t occur at every boot by default. Incomplete encryption would prompt status messages, not continuous slowness.",
      "examTip": "Consider upgrading to SSDs when enabling full-disk encryption to mitigate boot performance degradation."
    }
  ]
});    
