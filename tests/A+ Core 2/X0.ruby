db.tests.insertOne({
  "category": "aplus2",
  "testId": 10,
  "testName": "CompTIA A+ Core 2 (1102) Practice Test #10 (Ultra Level)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A Windows 11 system intermittently freezes after waking from hibernation. Kernel-Power errors appear in Event Viewer. What is the MOST likely cause?",
      "options": [
        "Outdated chipset drivers impacting power management.",
        "Corrupted hibernation file preventing proper resume.",
        "Insufficient virtual memory allocation after wake.",
        "Faulty RAM modules causing wake-up instability."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Kernel-Power errors following wake events commonly indicate outdated chipset drivers responsible for managing power states. Corrupted hibernation files typically prevent resumption altogether. Insufficient virtual memory would cause application crashes rather than system freezes. Faulty RAM results in random crashes rather than consistent freeze patterns post-hibernation.",
      "examTip": "Update chipset drivers when troubleshooting Kernel-Power errors related to sleep and hibernation issues."
    },
    {
      "id": 2,
      "question": "A Linux server's SSH sessions drop after a few minutes of inactivity. The network is stable. What configuration change is required to maintain persistent connections?",
      "options": [
        "Set 'ClientAliveInterval' and 'ClientAliveCountMax' in sshd_config.",
        "Increase TCP keepalive intervals in kernel parameters.",
        "Configure iptables to allow persistent SSH connections.",
        "Enable compression for SSH sessions to reduce timeouts."
      ],
      "correctAnswerIndex": 0,
      "explanation": "'ClientAliveInterval' and 'ClientAliveCountMax' ensure the SSH server sends keepalive messages, preventing idle session drops. Kernel TCP keepalive adjustments affect all connections system-wide and may not resolve the specific SSH issue. iptables rules control access but do not influence session persistence. Compression optimizes bandwidth usage but does not prevent timeouts.",
      "examTip": "Adjust 'ClientAliveInterval' and 'ClientAliveCountMax' in sshd_config to maintain persistent SSH sessions."
    },
    {
      "id": 3,
      "question": "A macOS user reports that external USB drives are no longer recognized. The drives function on other systems. What is the FIRST action a technician should take?",
      "options": [
        "Verify Finder preferences for external drive visibility.",
        "Reset the System Management Controller (SMC).",
        "Run Disk Utility First Aid to repair disk permissions.",
        "Check system logs for hardware detection errors."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If the external drives function elsewhere but not on the macOS system, checking Finder preferences for external drive visibility is the quickest initial step. Resetting the SMC addresses power and hardware management but is a broader solution. Disk Utility repairs disk-related issues but won't make invisible drives appear. Reviewing logs is informative but less immediate.",
      "examTip": "Always check Finder preferences first when external drives fail to appear on macOS."
    },
    {
      "id": 4,
      "question": "A Windows 10 laptop with BitLocker enabled requests the recovery key after hardware upgrades. How can future prompts during upgrades be avoided?",
      "options": [
        "Suspend BitLocker before performing hardware upgrades.",
        "Disable TPM from BIOS before hardware changes.",
        "Export and store the recovery key on external storage.",
        "Reset Secure Boot settings to factory defaults."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Suspending BitLocker ensures TPM does not detect unauthorized changes during hardware upgrades, preventing recovery key prompts. Disabling TPM affects system security more broadly. Exporting the recovery key aids recovery but does not prevent prompts. Secure Boot settings ensure firmware integrity but are unrelated to BitLocker triggers.",
      "examTip": "Always suspend BitLocker before hardware upgrades to avoid unnecessary recovery key prompts."
    },
    {
      "id": 5,
      "question": "A Linux administrator notices high I/O wait times on a server while CPU and memory usage remain normal. What is the MOST likely cause?",
      "options": [
        "A failing disk causing slow read/write operations.",
        "Swap partition being overutilized due to insufficient RAM.",
        "High network traffic leading to storage bottlenecks.",
        "Improper filesystem mounting options reducing throughput."
      ],
      "correctAnswerIndex": 0,
      "explanation": "High I/O wait times with normal CPU and memory usage often indicate disk issues, such as a failing drive. Swap overutilization would correlate with high memory usage. Network traffic affects bandwidth, not local disk I/O. Mounting options influence performance but typically cause consistent, not intermittent, slowness.",
      "examTip": "Check disk health using 'smartctl' or 'iostat' when encountering elevated I/O wait times on Linux systems."
    },
    {
      "id": 6,
      "question": "A user’s Windows 10 machine cannot access any HTTPS websites, though HTTP works fine. DNS and firewall settings are correct. What is the MOST likely cause?",
      "options": [
        "Corrupted or missing root certificates on the system.",
        "Disabled TLS protocols in browser settings.",
        "Expired SSL certificates on accessed websites.",
        "Network driver issues affecting secure traffic."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Root certificates validate HTTPS connections; missing or corrupted certificates prevent access. TLS protocol settings would cause browser-specific warnings. Expired site certificates would affect only specific sites, not all HTTPS connections. Network driver issues typically cause broader connectivity problems.",
      "examTip": "Validate the integrity of root certificates when HTTPS access fails but HTTP remains functional."
    },
    {
      "id": 7,
      "question": "A Linux administrator needs to ensure log files older than 30 days are automatically deleted. Which tool should be used?",
      "options": [
        "logrotate with proper configuration settings.",
        "cron jobs utilizing find and rm commands.",
        "rsyslog with custom retention policies.",
        "systemd-journald with persistent storage limits."
      ],
      "correctAnswerIndex": 0,
      "explanation": "'logrotate' handles automated log management, including rotation and deletion based on retention periods. Cron jobs provide flexibility but require custom scripts. rsyslog focuses on log forwarding, not deletion. systemd-journald manages journal logs but not traditional log files.",
      "examTip": "Configure 'logrotate' for automated log file retention and deletion based on organizational requirements."
    },
    {
      "id": 8,
      "question": "A Windows 11 machine prompts for a BitLocker recovery key after every reboot. TPM is enabled and operational. What could prevent this prompt in the future?",
      "options": [
        "Suspending BitLocker before firmware updates.",
        "Manually clearing TPM keys after each update.",
        "Resetting Secure Boot configurations before reboots.",
        "Changing boot order priorities to encrypted drives first."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Suspending BitLocker ensures TPM measurement changes during firmware updates do not trigger recovery prompts. Clearing TPM keys removes essential decryption data. Secure Boot changes address firmware validation, not BitLocker operations. Boot order changes are unrelated unless the OS partition is inaccessible.",
      "examTip": "Suspend BitLocker encryption before firmware changes to avoid recurring recovery key prompts."
    },
    {
      "id": 9,
      "question": "A macOS user reports kernel panics after installing third-party software. Safe Mode boots successfully. What is the MOST probable cause?",
      "options": [
        "Third-party kernel extensions (kexts) causing system instability.",
        "Insufficient system RAM for new software requirements.",
        "Corrupted system preference files affecting kernel operations.",
        "Outdated firmware requiring updates for compatibility."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Third-party kernel extensions are common causes of kernel panics, especially if incompatible with the current macOS version. RAM shortages lead to performance issues, not panics. Preference file corruption typically affects user interface operations. Firmware issues would prevent booting altogether.",
      "examTip": "Remove or update third-party kernel extensions when diagnosing kernel panics on macOS."
    },
    {
      "id": 10,
      "question": "A Windows 10 machine shows a 'BOOTMGR is missing' error after adding a new hard drive. What is the MOST likely cause?",
      "options": [
        "BIOS boot order prioritizing the new drive lacking an OS.",
        "Corrupted boot sector on the primary drive requiring repair.",
        "Disconnected SATA cables preventing drive detection.",
        "Damaged boot partition necessitating recovery operations."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Adding a new drive can cause BIOS to default to it, resulting in the 'BOOTMGR is missing' error if the drive lacks an OS. Corrupted boot sectors and disconnected cables would cause different, more critical errors. A damaged boot partition would prevent OS detection altogether.",
      "examTip": "Always verify and correct BIOS boot order after adding new hardware to prevent boot errors."
    },
    {
      "id": 11,
      "question": "A Linux server’s web service returns a '503 Service Unavailable' error. The web server is running. What should the administrator check NEXT?",
      "options": [
        "Status of the backend application server.",
        "Server's available disk space for logs and temporary files.",
        "Firewall configurations for blocked application ports.",
        "Web server configuration files for syntax errors."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A '503 Service Unavailable' error typically indicates that the backend application server is down or unreachable, despite the web server running. Disk space shortages or firewall issues would cause broader service failures. Configuration errors generally prevent the web server from starting at all.",
      "examTip": "Always confirm backend service availability when '503 Service Unavailable' errors occur in multi-tier environments."
    },
    {
      "id": 12,
      "question": "A Windows system reports 'The trust relationship between this workstation and the primary domain failed.' What is the FASTEST resolution?",
      "options": [
        "Rejoin the workstation to the domain using admin credentials.",
        "Reset the computer account in Active Directory Users and Computers.",
        "Flush DNS cache to resolve hostname trust issues.",
        "Restart the Netlogon service to reestablish domain communication."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Rejoining the workstation to the domain resets the secure channel between the client and domain controller. Resetting the computer account also works but takes more time. DNS flushing and Netlogon restarts address different authentication issues, not trust relationships.",
      "examTip": "Rejoin domain membership when encountering trust relationship errors for the fastest resolution."
    },
    {
      "id": 13,
      "question": "A Windows 10 laptop fails to connect to any VPN using L2TP/IPSec, displaying 'Negotiation failed.' What is the MOST likely cause?",
      "options": [
        "UDP ports 500 and 4500 are blocked by firewall settings.",
        "VPN client configuration file is corrupted.",
        "VPN server certificate has expired, preventing authentication.",
        "Outdated network adapter drivers causing VPN negotiation failure."
      ],
      "correctAnswerIndex": 0,
      "explanation": "L2TP/IPSec requires UDP ports 500 and 4500 for key exchange. Blocking these ports leads to negotiation failures. Corrupted configuration files would cause immediate errors during connection attempts. Expired certificates produce authentication errors. Network driver issues would affect broader connectivity, not solely VPN negotiation.",
      "examTip": "Ensure firewall configurations allow UDP ports 500 and 4500 for successful L2TP/IPSec VPN negotiations."
    },
    {
      "id": 14,
      "question": "A Linux server's SSH service is running, but users report 'Connection refused' errors. What is the MOST likely cause?",
      "options": [
        "Firewall rules blocking port 22 on the server.",
        "SSH daemon configuration errors preventing connections.",
        "SELinux contexts blocking SSH access after updates.",
        "Host-based access controls in /etc/hosts.deny denying user access."
      ],
      "correctAnswerIndex": 0,
      "explanation": "'Connection refused' typically indicates that port 22 is blocked by a firewall, even if the SSH service is running. Configuration errors would prevent the SSH daemon from running entirely. SELinux issues generally log access denials rather than outright connection refusals. /etc/hosts.deny restrictions result in 'Permission denied' errors, not connection refusals.",
      "examTip": "Always confirm firewall access on port 22 when SSH services are active but connections are refused."
    },
    {
      "id": 15,
      "question": "A Windows 11 user reports slow logins when disconnected from the corporate network. The user has a domain account. What is the MOST likely cause?",
      "options": [
        "The user profile is configured as a roaming profile dependent on network availability.",
        "Group Policy Objects (GPOs) are failing to apply due to network unavailability.",
        "The user’s DNS settings are incorrect, preventing domain controller lookups.",
        "Network drive mappings are timing out during login attempts."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Roaming profiles rely on network access; slow logins occur when the profile cannot be downloaded. GPO failures affect applied settings, not login speed. DNS issues prevent domain logins but not slow them. Network drive mapping timeouts may cause delays but are secondary to roaming profile dependencies.",
      "examTip": "Convert roaming profiles to local profiles when users require frequent offline access to reduce login delays."
    },
    {
      "id": 16,
      "question": "A Windows 10 machine cannot access internal resources by hostname but can by IP address. What is the MOST likely cause?",
      "options": [
        "Incorrect DNS server settings on the client machine.",
        "Corrupted local DNS cache preventing proper hostname resolution.",
        "DHCP scope misconfigurations causing incorrect DNS suffix assignments.",
        "Windows Firewall blocking outbound DNS traffic from the client."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Incorrect DNS server settings prevent hostname resolution, while IP access remains functional. DNS cache corruption would cause intermittent issues rather than consistent hostname resolution failures. DHCP misconfigurations would affect multiple clients. Firewall issues would block DNS lookups entirely, including external ones.",
      "examTip": "Always validate DNS server settings on client devices when internal hostname resolution fails."
    },
    {
      "id": 17,
      "question": "A Linux server experiences frequent SSH session drops during file transfers. The network connection is stable. What configuration change could prevent this?",
      "options": [
        "Increase 'ClientAliveInterval' and 'ClientAliveCountMax' values in sshd_config.",
        "Switch from SSH to SFTP for file transfers to maintain session stability.",
        "Enable compression in SSH sessions to reduce data transfer times.",
        "Adjust TCP keepalive settings in the server's kernel configuration."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Increasing 'ClientAliveInterval' and 'ClientAliveCountMax' sends keepalive packets that prevent session timeouts during long transfers. SFTP uses SSH and wouldn’t resolve session drops. Compression improves speed but doesn’t maintain sessions. Kernel TCP keepalive settings affect all connections and are not SSH-specific solutions.",
      "examTip": "Modify SSH keepalive settings in sshd_config to maintain persistent connections during long file transfers."
    },
    {
      "id": 18,
      "question": "A user’s Android device shows increased data usage, even when connected to Wi-Fi. What setting should be checked FIRST?",
      "options": [
        "'Wi-Fi Assist' or similar feature that uses mobile data when Wi-Fi is weak.",
        "App background data settings allowing cellular data usage.",
        "DNS configuration issues causing fallback to mobile networks.",
        "Carrier network preferences overriding device data settings."
      ],
      "correctAnswerIndex": 0,
      "explanation": "'Wi-Fi Assist' allows devices to switch to mobile data when Wi-Fi signal strength weakens, increasing data consumption. Background data settings generally prioritize Wi-Fi by default. DNS configuration affects resolution times, not network choice. Carrier preferences would not override device network settings for Wi-Fi connectivity.",
      "examTip": "Disable 'Wi-Fi Assist' to prevent unintended mobile data consumption when Wi-Fi connectivity fluctuates."
    },
    {
      "id": 19,
      "question": "A macOS user reports that Spotlight cannot find recently saved files. Indexing appears incomplete. What is the correct command to rebuild the Spotlight index?",
      "options": [
        "sudo mdutil -E /",
        "sudo diskutil repairVolume /",
        "sudo fsck -fy /dev/disk1",
        "sudo launchctl load /System/Library/LaunchDaemons/com.apple.metadata.mds.plist"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'sudo mdutil -E /' erases and rebuilds the Spotlight index, resolving search issues. 'diskutil repairVolume' and 'fsck' address disk corruption, not search indexing. 'launchctl load' restarts the indexing daemon but does not rebuild indexes.",
      "examTip": "Use 'mdutil -E /' to reset and rebuild Spotlight indexes when search fails to locate recent files."
    },
    {
      "id": 20,
      "question": "A Linux administrator must configure a cron job to run a script at 1 AM on the first day of each month. What is the correct crontab entry?",
      "options": [
        "0 1 1 * * /path/to/script.sh",
        "0 1 * * 1 /path/to/script.sh",
        "0 1 1 1 * /path/to/script.sh",
        "0 1 */1 * * /path/to/script.sh"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'0 1 1 * *' runs the script at 1 AM on the first day of every month. '0 1 * * 1' runs weekly on Mondays. '0 1 1 1 *' runs only on January 1. '*/1' denotes daily execution rather than monthly scheduling.",
      "examTip": "Always confirm crontab fields for correct scheduling when configuring recurring automated tasks."
    },
    {
      "id": 21,
      "question": "A Linux administrator finds that after a recent kernel update, a critical application fails to load due to missing kernel modules. What is the BEST way to resolve this issue while keeping the new kernel?",
      "options": [
        "Rebuild kernel modules for the updated kernel version.",
        "Roll back to the previous kernel until modules are updated.",
        "Reinstall the critical application to restore dependencies.",
        "Compile the kernel from source with all necessary modules."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Rebuilding kernel modules ensures compatibility with the updated kernel without rolling back or recompiling. Rolling back loses the benefits of the latest kernel. Reinstalling the application doesn't resolve kernel module dependencies. Compiling from source is time-consuming and unnecessary for module issues.",
      "examTip": "Use 'dkms' or relevant build tools to rebuild kernel modules after kernel upgrades to maintain application compatibility."
    },
    {
      "id": 22,
      "question": "A Windows 11 user reports that after joining a domain, the system displays 'User profile service failed the sign-in.' What is the MOST likely cause?",
      "options": [
        "Corrupt default user profile on the domain controller.",
        "DNS misconfiguration preventing domain authentication.",
        "Disabled user account in Active Directory.",
        "Corrupt local user profile on the workstation."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A corrupt default user profile on the domain controller prevents new domain profiles from being created. DNS misconfiguration would block domain authentication altogether. Disabled accounts prevent login, not profile creation. Local profile corruption affects only existing profiles, not new ones from the domain.",
      "examTip": "Replace or repair the default user profile on the domain controller when domain-joined systems fail to create profiles."
    },
    {
      "id": 23,
      "question": "A Windows 10 system shows 'The trust relationship between this workstation and the primary domain failed' after restoring from a backup. What is the FASTEST fix?",
      "options": [
        "Rejoin the workstation to the domain using administrator credentials.",
        "Reset the computer object in Active Directory.",
        "Manually update the machine password using PowerShell.",
        "Restore the system from a more recent backup."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Rejoining the domain resets the secure channel efficiently. Resetting the computer object may cause profile mismatches. PowerShell commands are more complex and time-consuming. Restoring from another backup doesn't guarantee the trust relationship will be fixed.",
      "examTip": "When restoring domain-joined systems, rejoin the domain if trust relationship errors occur."
    },
    {
      "id": 24,
      "question": "An Android device shows high battery usage from 'Google Play Services.' What should the technician check FIRST?",
      "options": [
        "Pending system updates affecting background services.",
        "Outdated apps dependent on Google Play Services APIs.",
        "Malware disguised as legitimate Google services.",
        "Battery optimization settings disabled for critical apps."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Pending system updates can cause Google Play Services to consume more battery due to background syncing. Outdated apps cause issues but generally not excessive battery drain. Malware disguised as Play Services would exhibit additional suspicious behaviors. Battery optimization settings don’t usually cause such high drain from system services.",
      "examTip": "Always check for pending system updates when core services like Google Play Services consume excessive battery."
    },
    {
      "id": 25,
      "question": "A Linux server fails to boot after an unexpected power outage, showing 'GRUB rescue>' prompt. What is the FIRST step to recover?",
      "options": [
        "Identify and set the correct boot partition using GRUB commands.",
        "Reinstall GRUB from a live CD environment.",
        "Check disk integrity using fsck from a rescue shell.",
        "Restore the master boot record from a recent backup."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Setting the correct boot partition using GRUB commands allows quick recovery if GRUB cannot find its files. Reinstalling GRUB or running fsck should follow if partition correction fails. MBR restoration is a last resort if the MBR is actually damaged.",
      "examTip": "Use 'set prefix' and 'set root' commands at the GRUB rescue prompt to recover from missing or misconfigured boot paths."
    },
    {
      "id": 26,
      "question": "A user reports that after enabling BitLocker on their Windows 11 laptop, boot times have significantly increased. The device uses a traditional HDD. What is the MOST likely reason?",
      "options": [
        "Full-disk encryption overhead on HDDs impacts read/write performance.",
        "BitLocker is waiting for user PIN input, delaying automatic startup.",
        "TPM misconfigurations are causing extended authentication times.",
        "Secure Boot conflicts are slowing down the boot process."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Full-disk encryption adds overhead, especially noticeable on HDDs. TPM issues usually prompt for recovery keys rather than slowing boots. Secure Boot conflicts result in different boot errors. PIN prompts delay boot only if configured explicitly.",
      "examTip": "Use SSDs for systems with BitLocker enabled to minimize encryption-related boot delays."
    },
    {
      "id": 27,
      "question": "A Windows 10 machine fails to install cumulative updates, returning '0x800f0922' error. What is the MOST likely cause?",
      "options": [
        "Insufficient space in the system-reserved partition.",
        "Corrupted Windows Update components.",
        "Active third-party antivirus software blocking updates.",
        "Faulty network connectivity to update servers."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Error '0x800f0922' is commonly due to lack of space in the system-reserved partition. Corrupted components cause different error codes. Antivirus software issues typically produce rollback errors. Network connectivity issues would lead to download failures, not installation errors.",
      "examTip": "Expand the system-reserved partition when encountering '0x800f0922' Windows Update errors."
    },
    {
      "id": 28,
      "question": "A Linux system shows 'Permission denied' errors when running a script, even though the user has execute permissions. What is the MOST likely cause?",
      "options": [
        "Incorrect shebang (#!) line specifying a non-existent interpreter.",
        "SELinux is enforcing policies that prevent execution.",
        "Filesystem mount options disallowing script execution.",
        "User lacks permissions for required dependencies."
      ],
      "correctAnswerIndex": 0,
      "explanation": "An incorrect shebang line prevents the OS from finding the script interpreter, resulting in 'Permission denied' despite correct file permissions. SELinux denials would be logged explicitly. Mount options would block all script execution, not just one. Missing dependencies usually yield different runtime errors.",
      "examTip": "Verify the shebang line points to the correct interpreter when scripts fail with 'Permission denied' despite execute permissions."
    },
    {
      "id": 29,
      "question": "A Windows user reports slow network drive access after a hostname change. Pings by IP address work fine, but hostname pings fail. What is the MOST likely cause?",
      "options": [
        "DNS records were not updated to reflect the new hostname.",
        "DHCP server is associating the old hostname with the current IP.",
        "WINS server entries were not refreshed post-hostname change.",
        "Local DNS resolver cache needs to be flushed on the client."
      ],
      "correctAnswerIndex": 0,
      "explanation": "DNS records must be updated after a hostname change; otherwise, clients cannot resolve the new name. DHCP typically doesn’t handle DNS registrations directly. WINS is deprecated in most environments. Flushing the DNS cache helps only after DNS records are correctly updated.",
      "examTip": "Update DNS records following hostname changes to ensure proper network resource resolution."
    },
    {
      "id": 30,
      "question": "A Linux administrator finds that a critical web service restarts automatically after failure but doesn’t stay running. What systemd directive ensures repeated restarts do not occur indefinitely?",
      "options": [
        "RestartSec=5",
        "Restart=on-failure",
        "StartLimitBurst=3",
        "TimeoutStartSec=10"
      ],
      "correctAnswerIndex": 2,
      "explanation": "'StartLimitBurst' limits the number of restarts in a given time period, preventing endless loops. 'Restart=on-failure' ensures restarts but without limits. 'RestartSec' sets the delay between restarts. 'TimeoutStartSec' defines the maximum time to consider the service started, unrelated to restart limits.",
      "examTip": "Set 'StartLimitBurst' in systemd service files to prevent endless restart loops after repeated service failures."
    },
    {
      "id": 31,
      "question": "A macOS user reports that Spotlight cannot locate newly saved documents. Indexing seems stuck. Which command rebuilds the Spotlight index for the entire disk?",
      "options": [
        "sudo mdutil -E /",
        "sudo diskutil verifyVolume /",
        "sudo fsck_apfs -n /dev/disk1",
        "sudo launchctl kickstart -k system/com.apple.metadata.mds"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'sudo mdutil -E /' erases and rebuilds the Spotlight index, resolving indexing issues. 'diskutil verifyVolume' checks disk integrity. 'fsck_apfs' checks APFS volumes for errors. 'launchctl kickstart' restarts services but doesn’t rebuild indexes.",
      "examTip": "Use 'mdutil -E /' to force a full Spotlight reindex when search issues persist on macOS."
    },
    {
      "id": 32,
      "question": "A Windows 11 system with full-disk BitLocker encryption repeatedly asks for the recovery key after firmware updates. TPM is functioning. How can future prompts be prevented?",
      "options": [
        "Suspend BitLocker protection before performing firmware updates.",
        "Reset TPM ownership after updates complete.",
        "Disable Secure Boot during firmware updates.",
        "Move recovery keys to a hardware security module (HSM)."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Suspending BitLocker ensures that TPM measurement changes during firmware updates don’t trigger recovery prompts. Resetting TPM ownership affects all encrypted data. Secure Boot changes don’t impact BitLocker’s TPM integration. HSMs store keys securely but don’t prevent prompts related to TPM measurement changes.",
      "examTip": "Always suspend BitLocker before firmware updates to maintain TPM measurement consistency and avoid recovery key prompts."
    },
    {
      "id": 33,
      "question": "A Linux system’s SSH connections drop after short idle periods. The network is stable. How can this be prevented?",
      "options": [
        "Configure 'ClientAliveInterval' and 'ClientAliveCountMax' in sshd_config.",
        "Enable TCP keepalives globally via sysctl parameters.",
        "Switch from SSH to Mosh for persistent remote sessions.",
        "Use 'screen' or 'tmux' to maintain session persistence."
      ],
      "correctAnswerIndex": 0,
      "explanation": "'ClientAliveInterval' and 'ClientAliveCountMax' ensure the server sends keepalive messages, preventing timeouts. TCP keepalives apply system-wide, not just SSH. Mosh requires client and server configuration changes. 'screen' and 'tmux' maintain sessions but don’t prevent connection drops.",
      "examTip": "Adjust SSH server keepalive settings for persistent connections during idle periods on Linux systems."
    },
    {
      "id": 34,
      "question": "A Windows 10 system shows 'Operating System not found' after adding a second drive. BIOS detects both drives. What is the MOST likely cause?",
      "options": [
        "Incorrect boot order prioritizing the new, non-bootable drive.",
        "Corrupted master boot record (MBR) on the primary drive.",
        "Disconnected SATA cables on the primary drive.",
        "Damaged boot partition requiring repair."
      ],
      "correctAnswerIndex": 0,
      "explanation": "New drive installations can cause BIOS to prioritize the wrong drive, leading to boot errors. MBR corruption and partition damage would prevent detection or prompt different errors. Disconnected cables would result in the drive being undetected in BIOS.",
      "examTip": "Verify BIOS boot order after hardware changes to ensure the correct boot drive is prioritized."
    },
    {
      "id": 35,
      "question": "A Linux administrator needs to ensure a critical service automatically restarts on failure but stops attempting after three failures in ten minutes. What is the correct systemd configuration?",
      "options": [
        "Restart=on-failure, StartLimitIntervalSec=600, StartLimitBurst=3",
        "Restart=always, RestartSec=5, TimeoutStartSec=600",
        "Restart=on-abort, StartLimitBurst=3, RestartSec=10",
        "Restart=on-failure, TimeoutStartSec=600, RestartSec=5"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This configuration ensures restarts on failure but limits attempts to three within ten minutes. 'Restart=always' doesn’t differentiate failure causes. 'Restart=on-abort' is for abnormal terminations. 'TimeoutStartSec' controls startup timing, not restart frequency.",
      "examTip": "Combine 'Restart=on-failure' with 'StartLimitBurst' and 'StartLimitIntervalSec' for controlled restart attempts in systemd."
    },
    {
      "id": 36,
      "question": "A user reports that after changing their Windows password, mapped network drives fail to reconnect. What is the MOST likely cause?",
      "options": [
        "Cached credentials no longer match the updated password.",
        "Group Policy Objects (GPOs) blocking drive mappings after password changes.",
        "DNS resolution failures preventing server access.",
        "Network adapter driver corruption affecting SMB traffic."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Password changes invalidate cached credentials, preventing drive reconnections. GPOs typically enforce, not block, mappings. DNS issues would affect all network access. Driver corruption would impact overall connectivity, not just drive mappings.",
      "examTip": "Update cached credentials in Credential Manager after password changes to restore mapped drive access."
    },
    {
      "id": 37,
      "question": "A Windows 11 laptop has slow startup times after enabling full-disk encryption. The device uses a mechanical hard drive. What is the MOST likely cause?",
      "options": [
        "BitLocker encryption overhead affecting HDD performance.",
        "TPM authentication delays during the pre-boot phase.",
        "BIOS boot order scanning non-bootable devices first.",
        "Corrupted bootloader requiring repair."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Full-disk encryption adds processing overhead that is more pronounced on HDDs compared to SSDs. TPM delays usually involve recovery prompts. BIOS scanning delays affect all boot processes. Bootloader corruption prevents booting entirely.",
      "examTip": "Upgrade to SSD storage when using full-disk encryption on Windows systems to reduce boot times."
    },
    {
      "id": 38,
      "question": "A Linux administrator needs to monitor real-time CPU usage per process. Which command is BEST suited?",
      "options": [
        "top",
        "htop",
        "ps aux --sort=-%cpu",
        "vmstat 1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'top' provides real-time per-process CPU usage and is universally available. 'htop' offers enhanced visualization but may not be installed by default. 'ps aux' provides snapshots, not continuous monitoring. 'vmstat' focuses on system-wide metrics, not per-process details.",
      "examTip": "Use 'top' for immediate, real-time insights into per-process CPU usage on Linux systems."
    },
    {
      "id": 39,
      "question": "A macOS user reports persistent prompts for iCloud password after an OS update. What is the MOST likely cause?",
      "options": [
        "Keychain corruption preventing iCloud authentication.",
        "Expired Apple ID credentials requiring reset.",
        "Firewall settings blocking iCloud services.",
        "Corrupted iCloud preference files in the user library."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Keychain corruption is a common cause of repeated iCloud authentication prompts. Expired Apple ID credentials would prevent login across all Apple services. Firewall issues would block access rather than cause repeated prompts. Corrupted preference files typically affect only the iCloud UI, not authentication.",
      "examTip": "Reset or repair Keychain Access when encountering repeated iCloud authentication prompts on macOS."
    },
    {
      "id": 40,
      "question": "A Windows 10 system shows 'NTLDR is missing' after changing BIOS settings. What is the FIRST troubleshooting step?",
      "options": [
        "Check and correct the BIOS boot order.",
        "Repair the master boot record using recovery tools.",
        "Restore BIOS settings to default configuration.",
        "Reinstall Windows bootloader from installation media."
      ],
      "correctAnswerIndex": 0,
      "explanation": "The 'NTLDR is missing' error typically occurs when the BIOS boot order points to a non-bootable device. Repairing the MBR or bootloader is secondary. Restoring BIOS defaults may not address the specific boot order issue. Reinstallation is a last-resort step.",
      "examTip": "Verify BIOS boot sequence after configuration changes when encountering boot errors like 'NTLDR is missing.'"
    },
    {
      "id": 41,
      "question": "A Linux web server running Apache is returning a '403 Forbidden' error after a configuration change. The website files have correct permissions. What is the MOST likely cause?",
      "options": [
        "SELinux is enforcing policies blocking access to web content.",
        "The Apache service lacks proper read permissions on the web directory.",
        "The firewall is blocking inbound HTTP requests on port 80.",
        "The .htaccess file has incorrect directives preventing access."
      ],
      "correctAnswerIndex": 0,
      "explanation": "SELinux commonly causes '403 Forbidden' errors if proper contexts are not set, even when file permissions are correct. Apache read permission issues would present as '403' but typically show explicit permission errors. Firewall misconfigurations would block requests entirely, resulting in connection errors, not '403.' Misconfigured .htaccess files cause '403' errors but would not coincide directly with a known SELinux-enforced environment unless explicitly modified.",
      "examTip": "Use 'ls -Z' to check SELinux contexts and 'restorecon -R /var/www/html' to correct them for Apache web directories."
    },
    {
      "id": 42,
      "question": "A user reports that their Windows 11 system boots into BitLocker recovery mode after a BIOS update. TPM is enabled and operational. How can future recovery prompts after such updates be prevented?",
      "options": [
        "Suspend BitLocker encryption before performing BIOS updates.",
        "Clear the TPM and reinitialize it after the update.",
        "Disable Secure Boot before updating the BIOS.",
        "Manually export and import the BitLocker recovery key after each update."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Suspending BitLocker before BIOS updates ensures TPM measurements remain consistent, preventing recovery prompts. Clearing TPM can lead to data loss if not properly managed. Secure Boot is unrelated to BitLocker TPM measurements. Exporting the recovery key helps in recovery but does not prevent future prompts.",
      "examTip": "Always suspend BitLocker before firmware or BIOS updates to avoid unnecessary recovery key prompts."
    },
    {
      "id": 43,
      "question": "A macOS user reports slow performance and frequent beachball icons after upgrading to the latest version. The system shows high disk activity. What is the MOST likely cause?",
      "options": [
        "Spotlight is reindexing the file system after the upgrade.",
        "The file system is corrupted and requires First Aid via Disk Utility.",
        "The macOS upgrade failed to complete, leaving temporary files.",
        "A third-party kernel extension is causing resource contention."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Spotlight reindexing after macOS upgrades causes high disk activity and temporary slow performance. File system corruption would show mounting errors. Failed upgrades typically result in missing features or boot loops. Third-party kernel extensions cause instability rather than persistent disk activity.",
      "examTip": "Allow Spotlight to complete reindexing post-upgrade; performance typically normalizes afterward."
    },
    {
      "id": 44,
      "question": "A Linux administrator needs to ensure that a critical service restarts automatically on failure but stops trying after three failures within five minutes. What is the correct systemd configuration?",
      "options": [
        "Restart=on-failure\nStartLimitIntervalSec=300\nStartLimitBurst=3",
        "Restart=always\nRestartSec=60\nTimeoutStartSec=300",
        "Restart=on-abort\nStartLimitBurst=3\nRestartSec=10",
        "Restart=on-failure\nTimeoutStopSec=300\nRestartSec=5"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This combination ensures the service restarts on failure but stops after three attempts in five minutes. 'Restart=always' doesn’t consider failure types. 'on-abort' applies only to abnormal exits. 'TimeoutStopSec' and 'RestartSec' manage timing but not restart limits.",
      "examTip": "Set 'StartLimitBurst' and 'StartLimitIntervalSec' together with 'Restart=on-failure' for controlled automatic restarts."
    },
    {
      "id": 45,
      "question": "A Windows 10 machine shows a 'BOOTMGR is missing' error after connecting an external USB drive. What is the MOST likely cause?",
      "options": [
        "The BIOS boot order prioritizes the external USB drive.",
        "The master boot record on the internal drive is corrupted.",
        "The external drive contains an incomplete boot sector.",
        "The boot partition on the internal drive has been deleted."
      ],
      "correctAnswerIndex": 0,
      "explanation": "External drives can change the BIOS boot priority. If the external drive lacks a bootable OS, a 'BOOTMGR is missing' error appears. MBR corruption or partition deletion would cause persistent boot issues regardless of external drives. Incomplete boot sectors on external drives wouldn’t affect internal boot orders unless prioritized by BIOS.",
      "examTip": "Check and correct BIOS boot priorities after adding new storage devices to avoid boot errors."
    },
    {
      "id": 46,
      "question": "A Linux administrator is troubleshooting SSH session drops after several minutes of inactivity. Network connectivity is stable. What configuration should be adjusted?",
      "options": [
        "Set 'ClientAliveInterval' and 'ClientAliveCountMax' in sshd_config.",
        "Increase TCP keepalive timeouts in kernel settings.",
        "Switch from SSH to Mosh for persistent remote sessions.",
        "Implement 'PermitRootLogin' to maintain administrative sessions."
      ],
      "correctAnswerIndex": 0,
      "explanation": "'ClientAliveInterval' and 'ClientAliveCountMax' prevent SSH timeouts by sending periodic keepalives. Kernel TCP settings affect all connections, which may not be desirable. Mosh can maintain sessions but requires additional software. 'PermitRootLogin' is a security risk and unrelated to session persistence.",
      "examTip": "Modify SSH keepalive settings to maintain idle connections without relying on broader network-level changes."
    },
    {
      "id": 47,
      "question": "A user reports that after updating their Android OS, the device experiences rapid battery drain. What is the MOST likely reason?",
      "options": [
        "Background app optimization settings were reset during the update.",
        "The battery has reached end-of-life and cannot hold charge efficiently.",
        "A rogue application is bypassing system battery optimization policies.",
        "The update included enhanced encryption increasing CPU cycles."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Android updates can reset app optimization settings, causing apps to run persistently. Battery end-of-life would result in poor charging behavior, not just drain. Rogue apps would need to be confirmed with resource usage tools. Encryption upgrades would have minimal impact on idle battery performance.",
      "examTip": "Review and reapply battery optimization settings after OS updates to restore normal power consumption."
    },
    {
      "id": 48,
      "question": "A Windows 11 device connected to a VPN shows successful connection but cannot access internal resources by hostname. What should the technician check FIRST?",
      "options": [
        "DNS settings to ensure internal hostnames are routed through the VPN.",
        "Split-tunneling configurations that may route traffic incorrectly.",
        "Active Directory permissions for resource access authorization.",
        "Firewall rules that may block internal DNS requests."
      ],
      "correctAnswerIndex": 0,
      "explanation": "DNS misconfigurations are a common reason internal hostnames fail while IP-based access remains functional. Split-tunneling issues affect all traffic types, not just DNS resolution. Active Directory permissions govern resource access but wouldn’t prevent name resolution. Firewall rules would impact both hostname and IP resolution.",
      "examTip": "Verify DNS routing settings when VPN connections allow IP traffic but fail for hostname resolutions."
    },
    {
      "id": 49,
      "question": "A macOS user reports that after connecting to public Wi-Fi, all network traffic is being redirected to a suspicious login page. What is the MOST likely cause?",
      "options": [
        "An 'Evil Twin' access point is mimicking a legitimate network.",
        "The ISP's captive portal requires authentication before internet access.",
        "The user’s DNS settings have been altered to redirect traffic.",
        "The firewall has been disabled, allowing unsolicited traffic."
      ],
      "correctAnswerIndex": 0,
      "explanation": "An 'Evil Twin' access point is designed to capture user credentials by mimicking legitimate networks. ISPs typically display branded captive portals. DNS changes wouldn’t redirect all traffic, especially HTTPS. Firewalls affect inbound traffic, not initial redirects.",
      "examTip": "Verify SSID authenticity and avoid unsecured networks to mitigate risks from 'Evil Twin' attacks."
    },
    {
      "id": 50,
      "question": "A Windows 10 system fails to apply Group Policy settings after a recent domain migration. What is the MOST likely cause?",
      "options": [
        "The client’s secure channel with the new domain controller is broken.",
        "The SYSVOL folder on the domain controller is inaccessible.",
        "DNS entries for the domain controller are incorrect.",
        "The user lacks permissions to apply specific GPO settings."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A broken secure channel prevents Group Policy from applying because authentication to the domain controller fails. SYSVOL inaccessibility impacts all GPO distribution, not just selective failure. DNS issues would prevent domain controller detection entirely. Permissions issues would cause partial GPO failures, not a complete absence of policy applications.",
      "examTip": "Use the 'Test-ComputerSecureChannel' PowerShell cmdlet to validate secure channel status after domain migrations."
    },
    {
      "id": 51,
      "question": "A Linux server is configured with fail2ban but is still experiencing brute-force SSH attacks. What configuration adjustment will MOST effectively reduce attack success?",
      "options": [
        "Lower the 'maxretry' value in the fail2ban SSH filter settings.",
        "Increase the 'bantime' duration in the fail2ban jail configuration.",
        "Change the default SSH port from 22 to a non-standard port.",
        "Disable password authentication in favor of SSH key-based authentication."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Disabling password authentication entirely eliminates brute-force attack vectors regardless of fail2ban configurations. Lowering 'maxretry' or increasing 'bantime' delays attackers but doesn’t prevent attempts. Changing the default SSH port provides security through obscurity, which isn’t a robust solution.",
      "examTip": "Use SSH key-based authentication and disable passwords to render brute-force attempts ineffective."
    },
    {
      "id": 52,
      "question": "A Windows 11 user reports frequent 'Credential Manager' errors after changing Active Directory passwords. What is the FIRST step to resolve this?",
      "options": [
        "Clear cached credentials in Windows Credential Manager.",
        "Rejoin the computer to the domain to reset secure channels.",
        "Run 'gpupdate /force' to refresh domain policies.",
        "Delete and recreate the user profile locally."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Credential Manager retains passwords for network resources. After AD password changes, outdated credentials cause authentication errors. Rejoining domains or recreating profiles is excessive. 'gpupdate' affects policy settings, not cached credentials.",
      "examTip": "Always clear cached credentials after AD password changes to prevent authentication errors."
    },
    {
      "id": 53,
      "question": "A Linux administrator discovers high CPU usage from the 'journald' process. Log files are consuming most of the available disk space. How can this be mitigated?",
      "options": [
        "Set 'SystemMaxUse' in journald.conf to limit disk usage.",
        "Manually clear logs in '/var/log/journal/'.",
        "Switch to rsyslog for all system logging needs.",
        "Disable persistent logging in journald."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Setting 'SystemMaxUse' in 'journald.conf' enforces automatic disk usage limits, preventing logs from consuming excessive space. Manual deletion is temporary. rsyslog can supplement but doesn’t resolve journald issues. Disabling persistent logging sacrifices valuable audit trails.",
      "examTip": "Configure disk usage limits for journald to prevent uncontrolled log growth on Linux systems."
    },
    {
      "id": 54,
      "question": "A Windows 10 system shows 'No Boot Device Found' after adding a secondary SSD. BIOS detects both drives. What should the technician check FIRST?",
      "options": [
        "BIOS boot order to ensure the primary OS drive is prioritized.",
        "UEFI Secure Boot settings for compatibility with the boot drive.",
        "SATA mode settings (AHCI vs. RAID) affecting drive recognition.",
        "Corruption of the EFI system partition on the primary drive."
      ],
      "correctAnswerIndex": 0,
      "explanation": "BIOS may default to booting from the new drive if prioritized incorrectly, causing 'No Boot Device Found' errors. Secure Boot or SATA mode issues produce more specific errors. EFI partition corruption would prevent booting but wouldn’t impact drive detection in BIOS.",
      "examTip": "After adding new storage, always verify BIOS boot priorities to prevent boot path disruptions."
    },
    {
      "id": 55,
      "question": "A user complains that their Windows 11 device is unable to connect to any HTTPS websites, but HTTP works fine. The system date and time are correct. What is the MOST likely cause?",
      "options": [
        "Corrupted or outdated root certificates on the local machine.",
        "Browser TLS settings misconfigured after recent updates.",
        "Network firewall blocking port 443 specifically.",
        "DNS resolution failures causing secure connections to time out."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Root certificates are essential for validating HTTPS connections. If they’re corrupted or outdated, secure websites fail to load. TLS settings misconfigurations would produce explicit browser warnings. Firewall port blocking would affect all secure traffic regardless of certificate status. DNS failures would affect both HTTP and HTTPS.",
      "examTip": "Check and update root certificates if HTTPS traffic fails despite functional HTTP connectivity and correct system time."
    },
    {
      "id": 56,
      "question": "A Linux administrator wants to enforce a restart of a service after failure but avoid infinite restarts. Which systemd directive achieves this?",
      "options": [
        "Restart=on-failure\nStartLimitBurst=3\nStartLimitIntervalSec=600",
        "Restart=always\nRestartSec=10\nTimeoutStartSec=300",
        "Restart=on-abort\nRestartSec=5\nStartLimitBurst=5",
        "Restart=always\nTimeoutStopSec=120\nRestartSec=15"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This combination ensures services restart on failure but stop after three attempts within ten minutes, preventing infinite loops. 'Restart=always' forces restarts regardless of exit reasons. 'on-abort' applies only to abnormal terminations. Timeout directives regulate timing, not restart limitations.",
      "examTip": "Combine 'Restart=on-failure' with 'StartLimit' directives for controlled restart behavior in systemd-managed services."
    },
    {
      "id": 57,
      "question": "A user’s macOS device fails to connect to Wi-Fi networks after an OS update. Other devices connect without issues. What is the MOST likely cause?",
      "options": [
        "Corrupted network preference files requiring reset.",
        "Outdated wireless adapter firmware incompatible with the new OS.",
        "Router incompatibility with updated macOS security protocols.",
        "Keychain corruption affecting Wi-Fi password storage."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Corrupted network preference files often prevent Wi-Fi reconnections post-update. Firmware incompatibility would prevent the adapter from appearing entirely. Router incompatibility would affect all connected devices. Keychain issues would impact password authentication, not network detection.",
      "examTip": "Reset network preferences on macOS if Wi-Fi issues persist after system updates."
    },
    {
      "id": 58,
      "question": "A Windows user reports that mapped network drives fail to reconnect after a password change. What is the MOST likely cause?",
      "options": [
        "Cached credentials in Credential Manager no longer match the new password.",
        "Group Policy mappings are not refreshing after credential updates.",
        "DNS entries for the file server are outdated or incorrect.",
        "SMB protocol mismatches between the client and file server."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Credential Manager caches passwords for network resources. After password changes, outdated credentials prevent reconnection. GPO issues would affect all users equally. DNS mismatches would prevent all access, not just mapped drives. SMB protocol issues typically cause connection rejections, not authentication failures.",
      "examTip": "Clear and update Credential Manager entries after password changes to restore network drive mappings."
    },
    {
      "id": 59,
      "question": "A Linux server’s SSH connections drop after short idle periods. The administrator confirms stable network connectivity. What configuration change prevents this?",
      "options": [
        "Set 'ClientAliveInterval' and 'ClientAliveCountMax' in sshd_config.",
        "Increase TCP keepalive settings globally in sysctl.conf.",
        "Switch from SSH to Mosh for persistent remote sessions.",
        "Use 'screen' or 'tmux' to maintain session persistence."
      ],
      "correctAnswerIndex": 0,
      "explanation": "'ClientAliveInterval' and 'ClientAliveCountMax' send periodic keepalive packets, preventing session drops. Kernel TCP keepalive adjustments affect all network traffic. Mosh offers persistent sessions but requires additional software. 'screen' and 'tmux' maintain session states but don’t prevent connection drops.",
      "examTip": "Configure SSH server keepalive settings for stable, persistent connections during idle periods."
    },
    {
      "id": 60,
      "question": "A Windows 10 system fails to boot, displaying 'NTLDR is missing' after a firmware update. What is the FIRST troubleshooting step?",
      "options": [
        "Check and correct BIOS boot order settings.",
        "Reinstall the Windows bootloader using recovery media.",
        "Restore default BIOS settings to correct boot mode changes.",
        "Repair the master boot record using 'bootrec /fixmbr'."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Firmware updates can reset boot priorities, causing 'NTLDR is missing' errors when the BIOS attempts to boot from non-bootable devices. Reinstalling bootloaders or repairing MBRs are subsequent actions if boot order adjustments fail. Restoring default BIOS settings may not address specific boot order issues.",
      "examTip": "Always verify BIOS boot order after firmware updates to ensure the correct drive is prioritized for booting."
    },
    {
      "id": 61,
      "question": "A Linux administrator needs to limit the disk space used by system logs without disabling persistent logging. What is the MOST effective method?",
      "options": [
        "Set 'SystemMaxUse' in journald.conf to cap log size.",
        "Manually delete logs from /var/log directory weekly.",
        "Disable persistent logging in journald to limit disk usage.",
        "Configure rsyslog to overwrite logs after a set period."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Setting 'SystemMaxUse' in 'journald.conf' limits the disk space used by logs automatically, providing a scalable and persistent solution. Manual deletion is prone to human error. Disabling persistent logging sacrifices essential logs. rsyslog overwriting can complement but doesn't control journald usage directly.",
      "examTip": "Set 'SystemMaxUse' in journald for automatic disk usage management without losing critical logs."
    },
    {
      "id": 62,
      "question": "A Windows 11 machine fails to access HTTPS websites, while HTTP works fine. The system clock is accurate, and the firewall is disabled. What is the MOST likely cause?",
      "options": [
        "Corrupted or outdated root certificates on the system.",
        "Browser cache corruption preventing secure site loading.",
        "Malware intercepting HTTPS traffic for man-in-the-middle attacks.",
        "Network router firmware blocking TLS traffic."
      ],
      "correctAnswerIndex": 0,
      "explanation": "HTTPS relies on valid root certificates for encryption. Corrupted or outdated certificates prevent secure site access. Cache corruption affects browsing generally but not specifically HTTPS. Malware would exhibit additional suspicious activity. Router issues typically impact all network traffic, not just secure connections.",
      "examTip": "Check and update root certificates when HTTPS traffic fails while HTTP remains unaffected."
    },
    {
      "id": 63,
      "question": "A macOS user notices significantly slower performance after upgrading the OS. Disk activity is unusually high. What is the MOST likely cause?",
      "options": [
        "Spotlight reindexing files after the upgrade.",
        "FileVault encryption process running in the background.",
        "Corrupted system caches slowing down performance.",
        "Outdated kernel extensions causing kernel task spikes."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Spotlight indexing causes high disk activity after an OS upgrade as it rebuilds its database. FileVault encryption affects CPU usage differently. Corrupted caches cause specific application issues. Kernel extension issues would trigger kernel panics, not just slow performance.",
      "examTip": "Allow Spotlight indexing to complete after macOS upgrades; performance typically improves afterward."
    },
    {
      "id": 64,
      "question": "A Linux administrator observes repeated 'Permission denied' errors while executing a shell script, despite having execute permissions. What is the MOST likely cause?",
      "options": [
        "The shebang line references a non-existent interpreter.",
        "The script lacks the correct SELinux context for execution.",
        "Filesystem mount options prevent execution of scripts.",
        "User lacks permissions for dependent system binaries."
      ],
      "correctAnswerIndex": 0,
      "explanation": "An incorrect shebang line prevents the system from finding the interpreter, resulting in 'Permission denied.' SELinux context issues would be logged separately. Mount options typically prevent execution entirely, not selectively. Missing binary permissions would yield 'command not found' or similar errors.",
      "examTip": "Verify the shebang (#!) line to ensure it points to a valid interpreter when execution permissions are present but errors persist."
    },
    {
      "id": 65,
      "question": "A Windows 10 device connected to a VPN reports successful connection but cannot access internal resources by hostname. IP-based access works fine. What should be checked FIRST?",
      "options": [
        "VPN DNS settings to ensure proper internal resolution.",
        "Split-tunneling configurations that may bypass DNS requests.",
        "Firewall rules potentially blocking internal DNS traffic.",
        "Network adapter binding order affecting DNS prioritization."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If IP access works but hostname resolution fails, VPN DNS settings are likely misconfigured. Split-tunneling issues typically affect all internal access, not just DNS. Firewall rules blocking DNS would prevent all DNS lookups. Adapter binding issues would affect all network resolution processes, not just VPN-specific ones.",
      "examTip": "Confirm VPN DNS settings to ensure internal hostname resolution functions correctly after establishing connections."
    },
    {
      "id": 66,
      "question": "A Windows 11 laptop boots into BitLocker recovery mode after a firmware update. TPM is enabled and functional. How can future recovery prompts be avoided?",
      "options": [
        "Suspend BitLocker protection before firmware updates.",
        "Disable Secure Boot prior to updating firmware.",
        "Clear TPM and restore it after completing updates.",
        "Store recovery keys on a hardware security module (HSM)."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Suspending BitLocker before firmware updates maintains TPM measurement consistency, preventing recovery prompts. Disabling Secure Boot affects firmware integrity checks, not TPM. Clearing TPM risks data loss if not handled properly. Storing keys externally doesn’t prevent recovery prompts caused by TPM measurement changes.",
      "examTip": "Always suspend BitLocker before firmware updates to maintain TPM measurement consistency and avoid recovery key prompts."
    },
    {
      "id": 67,
      "question": "A Linux administrator discovers that SSH sessions terminate after a few minutes of inactivity. Network connectivity is stable. What configuration change prevents this?",
      "options": [
        "Set 'ClientAliveInterval' and 'ClientAliveCountMax' in sshd_config.",
        "Increase TCP keepalive intervals at the kernel level.",
        "Switch to Mosh for maintaining persistent sessions.",
        "Enable compression in SSH to reduce idle disconnections."
      ],
      "correctAnswerIndex": 0,
      "explanation": "'ClientAliveInterval' and 'ClientAliveCountMax' send periodic keepalives from the server, maintaining SSH sessions during idle periods. Kernel TCP keepalive adjustments affect all connections. Mosh requires separate client and server configuration. SSH compression improves transfer speeds, not session persistence.",
      "examTip": "Configure SSH keepalive settings in sshd_config to maintain persistent SSH sessions during periods of inactivity."
    },
    {
      "id": 68,
      "question": "A user’s Windows 10 machine fails to reconnect mapped network drives after changing their Active Directory password. What is the MOST likely cause?",
      "options": [
        "Outdated cached credentials stored in Windows Credential Manager.",
        "Group Policy settings preventing automatic network drive reconnections.",
        "DNS resolution issues preventing access to file servers by hostname.",
        "SMB protocol version mismatches between the client and server."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Credential Manager caches old credentials. After a password change, reconnection fails unless the cache is updated. GPO issues typically affect all users. DNS issues would impact hostname access regardless of authentication. SMB mismatches would result in access denial errors, not authentication failures.",
      "examTip": "Clear and update cached credentials in Credential Manager following password changes to restore network drive access."
    },
    {
      "id": 69,
      "question": "A Windows 10 laptop connected to a VPN can access internal resources by IP but not by hostname. What should be the technician's FIRST troubleshooting step?",
      "options": [
        "Verify that the VPN client is correctly pushing DNS settings.",
        "Flush the local DNS resolver cache on the laptop.",
        "Manually set DNS server addresses provided by the network administrator.",
        "Restart the DNS Client service on the local machine."
      ],
      "correctAnswerIndex": 0,
      "explanation": "VPN clients often push DNS settings required for internal name resolution. If these settings aren’t applied, hostname resolution fails despite IP access. Flushing DNS resolves cached issues, not misconfigurations. Manually setting DNS addresses is secondary. Restarting DNS services clears temporary issues, not configuration ones.",
      "examTip": "Always verify VPN DNS configurations first when hostname resolution issues arise despite successful VPN connections."
    },
    {
      "id": 70,
      "question": "A macOS user cannot unlock their encrypted external drive with FileVault. The correct password returns an authentication error. What is the MOST likely cause?",
      "options": [
        "The encryption key file on the drive has been corrupted.",
        "The macOS Keychain has lost synchronization with FileVault.",
        "The drive's file system is damaged, preventing decryption.",
        "FileVault is disabled on the system, preventing access to encrypted drives."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Corruption of the encryption key file prevents successful decryption even with the correct password. Keychain issues impact login credentials, not drive encryption. File system damage affects data access after decryption. FileVault being disabled on the host system does not affect previously encrypted drives.",
      "examTip": "Always back up FileVault recovery keys and regularly check external drives for integrity to prevent permanent data loss."
    },
    {
      "id": 71,
      "question": "A Linux administrator must ensure a critical service restarts automatically after failure but limits restart attempts to three times within 10 minutes. What systemd configuration is correct?",
      "options": [
        "Restart=on-failure\nStartLimitIntervalSec=600\nStartLimitBurst=3",
        "Restart=always\nRestartSec=5\nTimeoutStartSec=600",
        "Restart=on-abort\nStartLimitBurst=3\nRestartSec=10",
        "Restart=on-failure\nRestartSec=5\nTimeoutStopSec=300"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The specified configuration ensures the service restarts on failure but halts after three failures within ten minutes. 'Restart=always' would restart the service regardless of the reason. 'on-abort' applies to abnormal exits. Timeout directives impact start/stop timing but not restart limits.",
      "examTip": "Use 'StartLimitBurst' and 'StartLimitIntervalSec' in systemd service units to prevent uncontrolled restart loops."
    },
    {
      "id": 72,
      "question": "A Windows 11 user reports frequent 'NTLDR is missing' errors after adding a secondary hard drive. BIOS detects both drives. What is the MOST likely cause?",
      "options": [
        "The BIOS boot order prioritizes the new, non-bootable drive.",
        "The system partition on the primary drive was accidentally deleted.",
        "The master boot record on the primary drive is corrupted.",
        "Secure Boot settings were reset, causing boot validation failures."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Adding a new drive may shift BIOS boot order. If the new drive is prioritized but lacks a bootloader, 'NTLDR is missing' errors occur. Partition deletion or MBR corruption would prevent drive detection or produce different errors. Secure Boot issues affect signature validations, not NTLDR errors.",
      "examTip": "Always verify BIOS boot order after hardware changes to ensure the correct drive boots first."
    },
    {
      "id": 73,
      "question": "A Windows system repeatedly prompts for a BitLocker recovery key after every reboot. TPM is functional, and firmware updates were recently performed. How can this be resolved?",
      "options": [
        "Suspend BitLocker before future firmware updates.",
        "Reset the TPM and re-enable BitLocker encryption.",
        "Disable Secure Boot to prevent recovery key prompts.",
        "Reinstall Windows Boot Manager using recovery tools."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Suspending BitLocker before firmware updates maintains TPM measurements, preventing recovery prompts. Resetting TPM risks data loss. Secure Boot disables firmware security checks but doesn’t affect BitLocker. Reinstalling the boot manager is unnecessary unless corruption is detected.",
      "examTip": "Always suspend BitLocker before firmware upgrades to avoid repeated recovery key prompts after reboot."
    },
    {
      "id": 74,
      "question": "A Linux system's SSH sessions frequently disconnect during long file transfers. Network connectivity tests show no issues. What configuration should be adjusted?",
      "options": [
        "Increase 'ClientAliveInterval' and 'ClientAliveCountMax' in sshd_config.",
        "Enable TCP keepalive globally via sysctl configurations.",
        "Switch to SFTP for more stable file transfers.",
        "Use SCP with compression enabled for faster transfers."
      ],
      "correctAnswerIndex": 0,
      "explanation": "'ClientAliveInterval' and 'ClientAliveCountMax' send periodic messages that keep SSH connections alive during extended operations. Kernel-level TCP keepalives affect all traffic. SFTP and SCP changes may optimize performance but won’t prevent session drops without proper keepalive configurations.",
      "examTip": "Modify SSH server keepalive settings to prevent idle disconnects during long file transfers."
    },
    {
      "id": 75,
      "question": "A macOS user reports their device is prompting repeatedly for iCloud password after an OS update. What is the MOST likely cause?",
      "options": [
        "Keychain corruption preventing iCloud credential retrieval.",
        "Expired iCloud credentials requiring reauthentication.",
        "iCloud servers experiencing temporary outages.",
        "Firewall settings blocking authentication traffic."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Keychain corruption after system updates can cause persistent authentication prompts. Expired credentials would block access across all devices. Server outages would impact all users globally. Firewall issues would block all network access, not just iCloud authentication.",
      "examTip": "Reset or repair Keychain Access when experiencing repeated iCloud authentication prompts post-macOS updates."
    },
    {
      "id": 76,
      "question": "A Linux administrator notices that the SSH service restarts infinitely after failure. What systemd configuration prevents infinite restart loops?",
      "options": [
        "Restart=on-failure\nStartLimitBurst=3\nStartLimitIntervalSec=600",
        "Restart=always\nRestartSec=5\nTimeoutStopSec=120",
        "Restart=on-abort\nRestartSec=10\nTimeoutStartSec=300",
        "Restart=always\nTimeoutStartSec=600\nRestartSec=15"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This configuration limits restart attempts to three within ten minutes, preventing endless loops. 'Restart=always' restarts services regardless of exit status. 'on-abort' applies only to abnormal exits. Timeout directives control timing, not restart frequencies.",
      "examTip": "Use 'StartLimitBurst' and 'StartLimitIntervalSec' together in systemd units to cap restart attempts after service failures."
    },
    {
      "id": 77,
      "question": "A Windows 10 machine is unable to connect to any HTTPS websites after installing new security updates. HTTP access works fine. What is the MOST likely cause?",
      "options": [
        "Corrupted root certificates following the security update.",
        "TLS protocol settings disabled during the update process.",
        "ISP restrictions impacting secure web traffic.",
        "DNS misconfigurations causing secure connection failures."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Root certificates ensure HTTPS validation. Corruption or removal during updates prevents secure site access. TLS settings misconfigurations would display explicit protocol errors. ISP restrictions rarely target HTTPS specifically. DNS issues affect both HTTP and HTTPS traffic.",
      "examTip": "Check and restore root certificates when HTTPS traffic fails after applying security updates."
    },
    {
      "id": 78,
      "question": "A Windows 11 device experiences long boot times after enabling full-disk BitLocker encryption. The system uses a traditional HDD. What is the MOST likely cause?",
      "options": [
        "Encryption overhead impacting HDD read/write speeds during boot.",
        "TPM misconfiguration delaying authentication during the boot process.",
        "Secure Boot interfering with the BitLocker encryption process.",
        "Boot partition misalignment causing slow OS loading times."
      ],
      "correctAnswerIndex": 0,
      "explanation": "BitLocker encryption adds performance overhead during startup, more pronounced on HDDs than SSDs. TPM misconfigurations usually prompt for recovery keys. Secure Boot ensures firmware integrity but doesn’t slow down encryption processes. Partition misalignment affects performance but is less likely after encryption.",
      "examTip": "Use SSD storage when enabling full-disk encryption on Windows devices to minimize boot delays."
    },
    {
      "id": 79,
      "question": "A Linux server reports repeated '503 Service Unavailable' errors for a web application. The web server is running without issues. What is the MOST likely cause?",
      "options": [
        "The backend application server is down or unreachable.",
        "Firewall settings are blocking backend server communication.",
        "Incorrect proxy configurations in the web server settings.",
        "Insufficient permissions for the web server to access backend APIs."
      ],
      "correctAnswerIndex": 0,
      "explanation": "'503 Service Unavailable' indicates that the web server cannot connect to the upstream server. Firewall settings would block traffic entirely. Proxy misconfigurations would result in connection errors. Permission issues typically produce '403' or '401' errors instead.",
      "examTip": "Check backend server health first when encountering '503' errors from reverse proxy setups."
    },
    {
      "id": 80,
      "question": "A user reports that their Windows 10 laptop fails to boot after a recent BIOS update, showing a 'No Boot Device Found' error. What should the technician check FIRST?",
      "options": [
        "BIOS boot order settings to ensure the correct drive is prioritized.",
        "SATA mode configurations (AHCI vs. RAID) in BIOS settings.",
        "UEFI Secure Boot settings conflicting with boot loader signatures.",
        "Potential corruption of the EFI system partition on the boot drive."
      ],
      "correctAnswerIndex": 0,
      "explanation": "BIOS updates can reset boot order priorities, causing the system to attempt booting from non-bootable devices. SATA mode changes affect OS recognition but not initial drive detection. Secure Boot errors typically display signature-related warnings. EFI partition corruption would produce different boot error messages.",
      "examTip": "Always verify BIOS boot priorities after firmware updates to ensure the correct drive boots first."
    },
    {
      "id": 81,
      "question": "A Linux server’s Apache web service is running, but users receive a '403 Forbidden' error when accessing the website. File permissions are correct. What is the MOST likely cause?",
      "options": [
        "SELinux is enforcing security policies blocking access.",
        "Apache’s configuration file has incorrect directory indexes.",
        "The web server firewall is blocking HTTP traffic.",
        "The document root directory is missing an index file."
      ],
      "correctAnswerIndex": 0,
      "explanation": "SELinux contexts can prevent web access even with correct file permissions. Apache directory index issues typically show a directory listing error. Firewall blocks cause connection failures, not '403' errors. Missing index files return listing errors, not permission-related messages.",
      "examTip": "Use 'ls -Z' to check SELinux contexts and 'restorecon' if necessary for Apache web directories."
    },
    {
      "id": 82,
      "question": "A Windows 11 user reports that after enabling BitLocker, the system takes significantly longer to boot. The device uses a traditional HDD. What is the MOST likely reason?",
      "options": [
        "Full-disk encryption overhead on HDDs slows read/write operations.",
        "BitLocker is waiting for a user-entered PIN at each startup.",
        "The Trusted Platform Module (TPM) is misconfigured, delaying authentication.",
        "The Secure Boot configuration is conflicting with BitLocker settings."
      ],
      "correctAnswerIndex": 0,
      "explanation": "BitLocker encryption imposes additional read/write demands, significantly affecting HDD performance. TPM misconfigurations would typically result in recovery prompts. Secure Boot conflicts manifest as boot failures, not slowdowns. PIN prompts delay startup only if configured, not by default.",
      "examTip": "For better performance with BitLocker, use SSDs instead of HDDs to minimize encryption overhead."
    },
    {
      "id": 83,
      "question": "A user reports that their Android device uses excessive mobile data even when connected to Wi-Fi. What setting should be checked FIRST?",
      "options": [
        "Wi-Fi Assist, which may use mobile data when Wi-Fi signals are weak.",
        "Background data permissions for specific applications.",
        "Carrier-specific data management settings overriding Wi-Fi preferences.",
        "VPN configurations that could force mobile data routing."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Wi-Fi Assist allows mobile data use when Wi-Fi is weak, leading to unexpected data usage. Background data settings generally prioritize Wi-Fi. Carrier management settings rarely override active Wi-Fi. VPN configurations impact routing but don’t default to mobile data unless specified.",
      "examTip": "Disable Wi-Fi Assist on Android devices to prevent mobile data usage when Wi-Fi connections are weak."
    },
    {
      "id": 84,
      "question": "A Linux administrator observes that SSH sessions drop after several minutes of inactivity, despite stable network connectivity. What configuration prevents this?",
      "options": [
        "Set 'ClientAliveInterval' and 'ClientAliveCountMax' in sshd_config.",
        "Enable TCP keepalive globally via sysctl settings.",
        "Switch from SSH to Mosh for persistent session management.",
        "Use 'screen' or 'tmux' to maintain active sessions."
      ],
      "correctAnswerIndex": 0,
      "explanation": "'ClientAliveInterval' and 'ClientAliveCountMax' settings ensure the SSH server keeps idle connections alive. Kernel TCP keepalives affect all network connections and may not be appropriate. Mosh requires additional installations. 'screen' and 'tmux' manage session persistence locally, not connection drops.",
      "examTip": "Adjust SSH keepalive parameters to maintain stable connections during periods of inactivity."
    },
    {
      "id": 85,
      "question": "A Windows 10 system shows 'NTLDR is missing' after adding a new hard drive. BIOS detects both drives. What is the MOST likely cause?",
      "options": [
        "The BIOS boot order prioritizes the non-bootable new drive.",
        "The master boot record (MBR) on the primary drive is corrupted.",
        "The new drive's partition table conflicts with the system partition.",
        "The boot partition was deleted during the new drive's installation."
      ],
      "correctAnswerIndex": 0,
      "explanation": "BIOS may prioritize the new drive after hardware changes, leading to the 'NTLDR is missing' error if that drive lacks a bootloader. MBR corruption results in different boot failures. Partition table conflicts wouldn’t cause this specific error. Deleting the boot partition would prevent BIOS from detecting any OS.",
      "examTip": "Check BIOS boot order after adding drives to ensure the correct drive is selected as the primary boot device."
    },
    {
      "id": 86,
      "question": "A macOS user reports that Spotlight cannot find recently added files. Indexing seems stuck. What is the correct command to rebuild the Spotlight index?",
      "options": [
        "sudo mdutil -E /",
        "sudo diskutil repairVolume /",
        "sudo fsck -fy /dev/disk1",
        "sudo launchctl load /System/Library/LaunchDaemons/com.apple.metadata.mds.plist"
      ],
      "correctAnswerIndex": 0,
      "explanation": "'sudo mdutil -E /' forces Spotlight to erase and rebuild its index, resolving search issues. 'diskutil repairVolume' and 'fsck' check disk integrity but don’t affect indexing. 'launchctl load' restarts indexing services but won’t rebuild the index.",
      "examTip": "Use 'mdutil -E /' on macOS to rebuild Spotlight indexes when search issues persist."
    },
    {
      "id": 87,
      "question": "A Linux administrator must ensure a web application restarts automatically but stops attempting after three failures within 10 minutes. What systemd configuration is correct?",
      "options": [
        "Restart=on-failure\nStartLimitBurst=3\nStartLimitIntervalSec=600",
        "Restart=always\nRestartSec=10\nTimeoutStartSec=300",
        "Restart=on-abort\nStartLimitBurst=3\nRestartSec=5",
        "Restart=on-failure\nTimeoutStopSec=300\nRestartSec=5"
      ],
      "correctAnswerIndex": 0,
      "explanation": "This configuration ensures automatic restarts but prevents endless loops by limiting attempts to three within ten minutes. 'Restart=always' ignores failure types. 'on-abort' applies only to abnormal terminations. Timeout settings affect start/stop timing, not restart control.",
      "examTip": "Use 'StartLimitBurst' and 'StartLimitIntervalSec' to manage controlled service restarts with systemd."
    },
    {
      "id": 88,
      "question": "A Windows 11 system connected to a VPN can access internal resources via IP but not by hostname. What is the FIRST step to resolve this?",
      "options": [
        "Verify VPN DNS settings to ensure proper hostname resolution.",
        "Restart the DNS Client service on the machine.",
        "Flush the local DNS resolver cache using ipconfig.",
        "Manually add host entries to the local hosts file."
      ],
      "correctAnswerIndex": 0,
      "explanation": "VPN DNS misconfigurations commonly cause hostname resolution failures despite IP connectivity. Restarting DNS services and flushing caches address temporary issues, not configuration problems. Manually editing host files is a last resort for persistent issues.",
      "examTip": "Always verify that VPN-provided DNS settings are applied correctly when hostname resolution fails."
    },
    {
      "id": 89,
      "question": "A user reports that their macOS device repeatedly prompts for an iCloud password after a macOS update. What is the MOST likely cause?",
      "options": [
        "Keychain corruption preventing iCloud credential retrieval.",
        "Outdated Apple ID requiring re-authentication after updates.",
        "Firewall rules blocking iCloud authentication requests.",
        "Incorrect iCloud server configurations after the update."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Keychain corruption is a common cause of repeated authentication prompts after macOS updates. Outdated Apple IDs affect all Apple services, not just iCloud. Firewall rules would block all traffic, not cause repeated prompts. Server configurations are managed by Apple and rarely affect individual devices.",
      "examTip": "Reset or repair Keychain Access when encountering repeated iCloud password prompts after macOS updates."
    },
    {
      "id": 90,
      "question": "A Windows 10 laptop connected to a VPN fails to reconnect mapped network drives after a password change. What is the MOST likely cause?",
      "options": [
        "Outdated cached credentials in Windows Credential Manager.",
        "DNS resolution failures preventing hostname mapping.",
        "SMB protocol version mismatches between client and server.",
        "Group Policy Object (GPO) restrictions blocking reconnections."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Credential Manager retains old passwords. After a change, reconnections fail unless updated. DNS issues prevent hostname resolution entirely. SMB mismatches cause connection refusals but would provide specific protocol errors. GPO restrictions typically affect all users, not just one after a password change.",
      "examTip": "Clear and update cached credentials in Credential Manager after password changes to restore network drive access."
    },
    {
      "id": 91,
      "question": "A Linux administrator notices SSH connections dropping after several minutes of inactivity, despite stable network conditions. What should be adjusted to fix this?",
      "options": [
        "Configure 'ClientAliveInterval' and 'ClientAliveCountMax' in sshd_config.",
        "Enable TCP keepalive settings in /etc/sysctl.conf.",
        "Switch from SSH to Mosh for more robust session management.",
        "Use 'screen' or 'tmux' to maintain persistent session environments."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Configuring 'ClientAliveInterval' and 'ClientAliveCountMax' ensures SSH sends periodic keepalive signals, preventing timeouts. Kernel TCP keepalives affect all traffic and may have unintended effects. Mosh is an alternative but requires additional configuration. 'screen' and 'tmux' manage terminal sessions, not underlying connection drops.",
      "examTip": "Set SSH keepalive parameters in sshd_config to prevent connection drops due to inactivity."
    },
    {
      "id": 92,
      "question": "A Windows 11 machine shows 'No Boot Device Found' after a firmware update. BIOS detects all drives. What is the MOST likely cause?",
      "options": [
        "BIOS boot order reset to prioritize a non-bootable device.",
        "Secure Boot settings conflict with the OS bootloader signature.",
        "SATA mode settings changed from AHCI to RAID, affecting boot.",
        "EFI system partition corruption on the boot drive."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Firmware updates often reset BIOS settings, including boot order. If the primary drive isn’t prioritized, boot failures occur. Secure Boot issues generate signature-related errors. SATA mode changes lead to blue screens rather than missing boot device messages. EFI partition corruption prevents bootloader detection, showing different errors.",
      "examTip": "Always check and correct BIOS boot order after firmware updates to ensure proper boot sequencing."
    },
    {
      "id": 93,
      "question": "A Linux server's SSH sessions frequently disconnect during large file transfers. Network connectivity tests pass without issues. What configuration should be adjusted?",
      "options": [
        "Increase 'ClientAliveInterval' and 'ClientAliveCountMax' in sshd_config.",
        "Enable compression in SSH connections for faster transfers.",
        "Switch to SFTP instead of SCP for more stable file transfers.",
        "Implement TCP keepalive adjustments at the kernel level."
      ],
      "correctAnswerIndex": 0,
      "explanation": "SSH keepalive settings ensure active sessions during lengthy operations like file transfers. Compression improves transfer speeds but doesn’t prevent disconnections. SFTP provides reliability but doesn’t inherently fix connection drops. Kernel TCP keepalive adjustments impact all traffic, not just SSH.",
      "examTip": "Configure SSH server keepalive settings to maintain stable connections during long-running file transfers."
    },
    {
      "id": 94,
      "question": "A macOS user reports slow performance and frequent beachball icons after a recent OS update. Disk usage appears unusually high. What is the MOST likely cause?",
      "options": [
        "Spotlight indexing is rebuilding the search database post-update.",
        "The file system requires repair via Disk Utility's First Aid feature.",
        "Third-party kernel extensions are causing kernel task spikes.",
        "A background Time Machine backup is consuming system resources."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Spotlight reindexing is common after macOS updates, causing high disk activity and temporary slowness. File system corruption would show mounting errors. Kernel extension issues lead to kernel panics, not consistent slowdowns. Time Machine backups impact network traffic more than disk performance.",
      "examTip": "Allow Spotlight indexing to complete after macOS updates; performance typically improves once indexing is done."
    },
    {
      "id": 95,
      "question": "A Windows 10 user reports inability to connect to HTTPS websites, though HTTP sites load fine. The system clock is correct. What is the MOST likely cause?",
      "options": [
        "Corrupted root certificates on the local machine.",
        "TLS protocols disabled in browser security settings.",
        "Firewall rules blocking secure port 443 traffic.",
        "DNS issues preventing secure name resolutions."
      ],
      "correctAnswerIndex": 0,
      "explanation": "HTTPS relies on valid root certificates. If these are corrupted, secure sites will fail while HTTP works. TLS misconfigurations would produce browser protocol errors. Firewall issues would block port 443 entirely, affecting all secure traffic. DNS issues affect both HTTP and HTTPS traffic equally.",
      "examTip": "Validate and restore root certificates when HTTPS access fails but HTTP connectivity remains unaffected."
    },
    {
      "id": 96,
      "question": "A Linux server’s web application returns a '503 Service Unavailable' error. The web server is running without issues. What is the MOST likely cause?",
      "options": [
        "The backend application server is down or unreachable.",
        "Firewall configurations are blocking traffic to backend services.",
        "The web server lacks permissions to access backend resources.",
        "DNS resolution issues prevent the web server from reaching the backend."
      ],
      "correctAnswerIndex": 0,
      "explanation": "'503 Service Unavailable' typically indicates that the web server cannot connect to its backend services. Firewall issues would cause connection errors. Permission issues would result in '403 Forbidden' errors. DNS resolution problems would display hostname-related errors, not service unavailability messages.",
      "examTip": "Check backend application server health first when '503' errors occur on web front-end systems."
    },
    {
      "id": 97,
      "question": "A Windows 11 user reports slow boot times after enabling full-disk encryption with BitLocker. The system uses an HDD. What is the MOST likely reason?",
      "options": [
        "Encryption overhead during startup slows HDD performance.",
        "TPM authentication delays are extending pre-boot phases.",
        "Secure Boot conflicts with BitLocker encryption processes.",
        "Boot partition misalignment is causing prolonged loading times."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Full-disk encryption imposes processing overhead that is more noticeable on HDDs than SSDs. TPM delays typically manifest as recovery key prompts. Secure Boot ensures firmware integrity and doesn’t slow down boot times. Partition misalignment affects overall performance but is less likely after BitLocker implementation.",
      "examTip": "Use SSDs for systems with BitLocker to minimize encryption-related boot slowdowns."
    },
    {
      "id": 98,
      "question": "A Linux administrator finds that fail2ban is enabled but SSH brute-force attempts continue. What action will BEST mitigate these attacks?",
      "options": [
        "Disable password authentication and use SSH key pairs exclusively.",
        "Change the default SSH port from 22 to a non-standard port.",
        "Lower the 'maxretry' value in fail2ban configuration.",
        "Increase 'bantime' in fail2ban jail settings to extend block duration."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Disabling password authentication eliminates brute-force vectors. Changing ports provides only obscurity, not security. Adjusting fail2ban parameters delays attackers but doesn’t prevent them. SSH keys provide robust protection against brute-force attempts.",
      "examTip": "Implement SSH key-based authentication and disable password login to eliminate brute-force SSH vulnerabilities."
    },
    {
      "id": 99,
      "question": "A user reports their macOS device fails to connect to Wi-Fi networks after an OS update. Other devices connect without issues. What is the MOST likely cause?",
      "options": [
        "Corrupted network preference files requiring reset.",
        "Outdated wireless adapter firmware incompatible with the update.",
        "Router incompatibility with the latest macOS security protocols.",
        "Keychain corruption affecting Wi-Fi password storage."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Corrupted network preferences prevent Wi-Fi reconnections after macOS updates. Firmware incompatibility affects hardware detection entirely. Router incompatibility would affect all devices. Keychain issues impact saved passwords, not Wi-Fi detection.",
      "examTip": "Reset network preferences in macOS when Wi-Fi issues persist after system updates."
    },
    {
      "id": 100,
      "question": "A Windows 10 user reports that mapped network drives no longer reconnect automatically after a password change. What is the MOST likely cause?",
      "options": [
        "Cached credentials in Credential Manager no longer match the new password.",
        "DNS resolution failures preventing drive access by hostname.",
        "Group Policy restrictions preventing automatic drive mapping.",
        "SMB protocol version mismatches between the client and server."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Credential Manager stores network credentials. After a password change, reconnections fail unless the cache is updated. DNS issues would prevent all hostname resolutions. GPO restrictions typically affect all users. SMB mismatches would show protocol errors, not authentication issues.",
      "examTip": "Clear and update Credential Manager after password changes to restore mapped drive connectivity."
    }
  ]
});
