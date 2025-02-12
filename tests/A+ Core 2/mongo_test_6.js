{
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
      "explanation": "Intermittent connectivity to a *specific* share, while other network functions are normal, suggests a protocol-level issue. SMB version mismatches (e.g., the server only supports SMBv3, but the client is trying SMBv1) can cause this. Server overload would likely affect all users. A faulty cable would cause more general connectivity problems. Incorrect DNS would prevent *initial* connection, not intermittent drops.",
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
      "explanation": "`netstat -ano` displays active connections with the owning Process ID (PID).  You can then use `tasklist /fi \"pid eq <PID>\"` to filter the `tasklist` output and show details for the specific process identified by `netstat`. The other options are less targeted for this scenario.",
      "examTip": "Combine `netstat -ano` and `tasklist` (or Task Manager) to link network connections to specific processes for malware investigation."
    },
    {
        "id": 3,
        "question": "A user reports their workstation is behaving erratically, with programs crashing and unexpected system restarts. They recently installed several new applications from various sources. You suspect a software conflict or a potentially unwanted program (PUP). What's the BEST approach to diagnose and resolve this issue?",
        "options":[
            "Immediately reinstall the operating system.",
            "Run a full system scan with antivirus and anti-malware software, then boot into Safe Mode and selectively disable recently installed applications and startup programs to identify the culprit.",
            "Run System Restore to revert to the last known good configuration.",
            "Increase the size of the paging file."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A combination of malware scans and selectively disabling software in Safe Mode is the most methodical approach. Malware scans address potential PUPs. Safe Mode isolates the problem by loading only essential drivers and services.  System Restore *might* work, but it's a broader solution and might not pinpoint the specific cause. Reinstalling the OS is too drastic. Increasing the paging file addresses memory issues, not software conflicts.",
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
      "explanation": "If `ping` to the IP address works but `ping` to the domain name fails *and* `nslookup` resolves correctly, the issue is *not* DNS resolution itself. The most likely cause is a security device (firewall, web filter, proxy) that is blocking access based on the domain name, while allowing direct IP access. A routing problem would likely prevent *both* pings. If the server were down, the IP ping would also fail.",
      "examTip": "If ping by IP works but ping by domain name fails, *despite* correct `nslookup` resolution, suspect filtering or blocking based on the domain name."
    },
     {
        "id": 5,
        "question": "You are configuring a secure wireless network in a corporate environment. You need to implement strong authentication and encryption, and you want to use a centralized authentication server. Which combination of technologies would BEST meet these requirements?",
        "options":[
            "WEP and a shared password.",
            "WPA2-Personal with a strong pre-shared key.",
            "WPA2-Enterprise with 802.1X authentication using a RADIUS server.",
            "WPA3-Personal with a weak password."
        ],
        "correctAnswerIndex": 2,
        "explanation": "WPA2-Enterprise (or WPA3-Enterprise) with 802.1X authentication provides the strongest security for corporate environments. It uses a RADIUS (or similar) server for centralized user authentication, rather than a shared password. WEP is insecure. WPA2-Personal uses a shared key, which is less secure for a corporate setting. WPA3-Personal is good, but Enterprise is better for centralized management.",
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
        "explanation": "Resource Monitor's Disk tab shows detailed disk I/O activity, including the specific files being read from and written to, along with the processes accessing them. Task Manager's Performance tab shows overall disk utilization, but not file-level detail. Performance *Monitor* can track disk activity, but Resource Monitor is more directly suited for this *immediate* troubleshooting. Disk Defragmenter optimizes file layout, but doesn't show real-time file access.",
        "examTip": "Use Resource Monitor's Disk tab to pinpoint specific files causing high disk I/O and identify potential bottlenecks."
    },
     {
        "id": 7,
        "question": "A Linux server is experiencing intermittent network connectivity issues. You suspect a problem with the network interface card (NIC). Which command would provide the MOST detailed information about the NIC's status, including driver details, link status, and potential errors?",
        "options":[
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
        "options":[
            "Hard drive; run `chkdsk`.",
            "RAM; run Windows Memory Diagnostic.",
            "CPU; run a CPU stress test utility.",
            "Network adapter; run the Windows Network Troubleshooter."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Random freezes, even at idle, are often caused by faulty RAM. Windows Memory Diagnostic is the built-in tool to test RAM for errors. `chkdsk` checks the hard drive, a CPU stress test would be relevant if the freezes happened *under load*, and the Network Troubleshooter is for network connectivity.",
        "examTip": "Thoroughly test RAM (with Windows Memory Diagnostic or Memtest86) when troubleshooting random system freezes or instability."
    },
    {
       "id": 9,
       "question": "You are designing a backup strategy for a small business. They have a limited budget but need to ensure data recovery in case of a disaster. They have one file server with critical data. Which backup scheme provides the BEST balance of data protection, recovery speed, and cost-effectiveness?",
       "options":[
        "Full backups only, performed daily.",
        "Incremental backups only, performed daily.",
        "A combination of weekly full backups and daily differential backups, with offsite storage.",
        "No backups, relying on RAID for redundancy."
       ],
       "correctAnswerIndex": 2,
       "explanation": "Weekly full backups combined with daily differential backups provide a good balance. Full backups create a complete copy, while differential backups only copy changes *since the last full backup*, making restores faster than with incremental backups (which only copy changes since the *last* backup). Offsite storage protects against physical disasters. Full backups only are storage-intensive. Incremental backups only are slow to restore. RAID provides redundancy, *not* backup.",
       "examTip": "Combine full and differential (or incremental) backups, and always store backups offsite, for a robust and cost-effective backup strategy."
    },
     {
        "id": 10,
        "question":"You are responding to a security incident where a user's workstation is suspected of being compromised. You need to preserve the system's current state for forensic analysis. What is the MOST important FIRST step?",
        "options":[
            "Run a full system scan with antivirus software.",
            "Disconnect the workstation from the network and power it off.",
            "Create a forensic image (bit-by-bit copy) of the hard drive before making any changes to the system.",
            "Reboot the workstation to see if the problem resolves itself."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Creating a forensic image *before* any other action is crucial to preserve the system's state *exactly* as it was at the time of the suspected compromise. Running antivirus, disconnecting from the network (though important), or rebooting can alter the system's state and potentially destroy evidence.  Note, disconnecting it from the network is vital as well, this should be done *after* the image, or *before* if there is an immediate threat to other systems.",
        "examTip": "In a security incident, prioritize preserving the system's state by creating a forensic image before taking any other actions that might alter the evidence."
    },
    {
        "id": 11,
        "question": "A user reports they can no longer access files on their encrypted external hard drive. They are prompted for a password, but they claim they never set one. The drive was working fine previously. What's the MOST likely scenario, assuming the drive isn't physically damaged?",
        "options":[
           "The hard drive has failed.",
            "The user forgot the password.",
            "The encryption software has become corrupted, or the drive's encryption metadata has been damaged.",
            "The USB port is faulty."
        ],
        "correctAnswerIndex": 2,
        "explanation": "While user error (forgetting the password) is *possible*, if the user *never* set a password, and the drive was previously working, corruption of the encryption software or the drive's encryption metadata (the information that describes how the drive is encrypted) is more likely. A failed drive would usually result in different errors (not being recognized at all, clicking noises, etc.). A faulty USB port would likely prevent the drive from being detected.",
        "examTip": "If an encrypted drive suddenly requires a password the user claims they never set, suspect encryption software or metadata corruption."

    },
    {
        "id": 12,
        "question": "You are troubleshooting a Windows computer that boots very slowly. You've already disabled unnecessary startup programs in Task Manager and msconfig. What is the NEXT most effective step to investigate potential boot-time bottlenecks?",
        "options":[
            "Run Disk Cleanup.",
            "Run `chkdsk`.",
            "Use the Windows Performance Recorder and Analyzer (part of the Windows Assessment and Deployment Kit - ADK) to capture a boot trace and analyze boot performance.",
            "Increase the size of the paging file."
        ],
        "correctAnswerIndex": 2,
        "explanation": "The Windows Performance Recorder and Analyzer provide *detailed* information about the boot process, including which drivers, services, and processes are taking the longest to load. This allows you to pinpoint specific bottlenecks. Disk Cleanup removes files, `chkdsk` checks for disk errors, and increasing the paging file addresses virtual memory, not boot time directly.",
        "examTip": "Use the Windows Performance Recorder and Analyzer (WPR/WPA) for in-depth analysis of boot performance issues."
    },
    {
        "id": 13,
        "question": "A user reports they accidentally deleted a critical file from a network share. The file is not in their Recycle Bin. What is the BEST way to attempt recovery, assuming the file server is running Windows Server and has the appropriate features enabled?",
        "options":[
            "Use a file recovery utility on the user's computer.",
            "Restore the file from a recent backup of the file server.",
            "Attempt to recover the file from the 'Previous Versions' (Shadow Copies) feature on the file server.",
            "Tell the user the file is permanently lost."
        ],
        "correctAnswerIndex": 2,
        "explanation": "The 'Previous Versions' (Shadow Copies) feature on Windows Server takes periodic snapshots of files and folders, allowing users to restore previous versions of files that have been accidentally deleted or modified. This is often faster and easier than restoring from a full backup. File recovery utilities are less likely to be successful on a network share. Telling the user the file is lost is premature.",
        "examTip": "Enable and configure the 'Previous Versions' (Shadow Copies) feature on Windows file servers to provide a convenient way for users to recover deleted or modified files."
    },
     {
        "id": 14,
        "question": "A user reports that their web browser is behaving erratically, displaying unexpected pop-ups and redirecting them to unfamiliar websites. You've already run a full system scan with antivirus and anti-malware software, but the problem persists. What is the NEXT most likely cause, and how would you address it?",
        "options":[
            "A hardware failure.",
            "A corrupted operating system.",
            "A browser extension or plugin is causing the issue; check and disable recently installed or suspicious extensions.",
            "Incorrect DNS settings."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Persistent browser issues, even after malware scans, often point to a malicious or malfunctioning browser extension. Disabling extensions one by one can help isolate the culprit. Hardware failures and OS corruption are less likely to cause these specific symptoms. Incorrect DNS settings would usually prevent access to websites altogether, not cause redirects.",
        "examTip": "Carefully review and manage browser extensions; they can be a source of unwanted behavior and security risks."
    },
    {
        "id": 15,
        "question": "You are analyzing network traffic and notice a large number of packets with the SYN flag set, but very few corresponding ACK flags. What type of network activity does this MOST likely indicate?",
        "options":[
          "Normal web browsing.",
          "A SYN flood attack (a type of denial-of-service attack).",
          "File transfer using FTP.",
          "Email communication using SMTP."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A SYN flood attack involves sending a large number of SYN (synchronize) packets to a server, attempting to overwhelm it and prevent it from responding to legitimate requests. The lack of corresponding ACK (acknowledgment) packets indicates that the connections are not being completed. Normal web browsing, FTP, and SMTP involve complete TCP handshakes (SYN, SYN-ACK, ACK).",
        "examTip": "A disproportionate number of SYN packets compared to ACK packets is a strong indicator of a SYN flood attack."
    },
    {
        "id":16,
        "question":"A user is unable to connect to the corporate wireless network. They are using the correct SSID and password. Other users in the same area are connecting successfully. You check the user's laptop and find that it has an IP address in the 169.254.x.x range. What does this tell you, and what should you do?",
        "options":[
            "The user's laptop has a static IP address configured incorrectly; change it to obtain an IP address automatically (DHCP).",
           "The user's laptop is not receiving an IP address from the DHCP server; troubleshoot DHCP server connectivity or configuration.",
            "The user's wireless network adapter is disabled; enable it.",
            "The wireless router is malfunctioning; reboot it."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A 169.254.x.x address is an APIPA (Automatic Private IP Addressing) address, assigned when a computer is configured for DHCP but cannot reach a DHCP server.  Since other users are connecting, the router is likely working.  The problem is likely the DHCP server or the client's ability to communicate with it. While a *static* IP *could* be wrong, the 169.254.x.x address indicates a *DHCP* failure.",
        "examTip": "An APIPA address (169.254.x.x) almost always indicates a DHCP failure; focus your troubleshooting on DHCP server reachability and configuration."
    },
	{
        "id": 17,
        "question": "You are troubleshooting a computer that is experiencing frequent 'blue screen of death' (BSOD) errors. You want to examine the memory dump files created during these crashes to identify the potential cause. Where are these dump files typically located in Windows?",
        "options":[
            "C:\\Windows\\Temp",
            "C:\\Users\\<username>\\AppData\\Local\\Temp",
            "C:\\Windows\\Minidump (for small memory dumps) and C:\\Windows\\MEMORY.DMP (for complete memory dumps)",
            "C:\\Program Files\\Debugging Tools for Windows"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Windows stores memory dump files (created during BSODs) in specific locations.  Small memory dumps (minidumps) are usually in C:\\Windows\\Minidump, while a complete memory dump (if configured) is saved as C:\\Windows\\MEMORY.DMP. The other locations are temporary directories or contain debugging tools, but not the *dump files* themselves.",
        "examTip": "Analyze memory dump files (using tools like WinDbg) to diagnose the root cause of BSOD errors."
    },
    {
        "id": 18,
        "question": "You are setting up a Linux server and need to configure a static IP address. You are using a distribution that uses the `ip` command (not `ifconfig`). Which command sequence would you use to assign the IP address 192.168.1.100, netmask 255.255.255.0, and gateway 192.168.1.1 to the interface `eth0`?",
        "options":[
            "`ip addr add 192.168.1.100/24 dev eth0` and `ip route add default via 192.168.1.1`",
            "`ifconfig eth0 192.168.1.100 netmask 255.255.255.0` and `route add default gw 192.168.1.1`",
            "`ip address add 192.168.1.100/255.255.255.0 dev eth0` and `ip gateway add 192.168.1.1`",
            "`ifconfig eth0 up 192.168.1.100 netmask 255.255.255.0 gateway 192.168.1.1`"
        ],
        "correctAnswerIndex": 0,
        "explanation": "With the `ip` command, you use `ip addr add` to assign the IP address and subnet mask (using CIDR notation: /24), and `ip route add` to set the default gateway.  Option B uses the older `ifconfig` and `route` commands. Options C and D have incorrect syntax for the `ip` command.",
        "examTip": "Familiarize yourself with both the older `ifconfig`/`route` commands and the newer `ip` command for managing network interfaces in Linux."
    },
     {
        "id":19,
        "question": "A user reports that their Outlook email client is repeatedly prompting them for their password, even though they are entering the correct password. They can access their email through webmail without any issues. What is the MOST likely cause, and how would you address it?",
        "options":[
          "The user's email account is locked out.",
          "The user's computer is infected with malware.",
          "There is a problem with the Outlook profile or cached credentials; try recreating the Outlook profile or clearing cached credentials.",
          "The email server is down."
        ],
        "correctAnswerIndex": 2,
        "explanation":"Repeated password prompts in Outlook, despite the correct password being entered, often indicate a problem with the Outlook profile or stored credentials. Since webmail works, the account itself isn't locked, and the server is likely up. Malware *could* interfere, but a profile/credential issue is more directly related to this specific symptom.",
        "examTip":"Corrupted Outlook profiles or cached credentials can cause repeated password prompts; recreating the profile is often a quick solution."

    },
    {
        "id": 20,
        "question": "You are hardening a Windows Server. You want to restrict which user accounts can log on locally to the server. Which security policy setting would you configure?",
        "options":[
           "Password Policy",
           "Account Lockout Policy",
            "User Rights Assignment: Allow log on locally",
            "Audit Policy"
        ],
        "correctAnswerIndex": 2,
        "explanation": "The 'Allow log on locally' user right (under User Rights Assignment in Local Security Policy or Group Policy) determines which users and groups are permitted to log on directly to the computer's console. Password Policy and Account Lockout Policy control password characteristics and lockout behavior. Audit Policy configures event logging.",
        "examTip": "Use User Rights Assignment settings to control how users can access a computer (locally, over the network, as a service, etc.)."
    },
     {
        "id": 21,
        "question": "You are troubleshooting a system and need to examine the running processes in detail, including their memory usage, handles, and threads. Which tool BEST provides this level of information?",
        "options":[
            "Task Manager",
            "Resource Monitor",
            "Process Explorer (from Sysinternals)",
            "Performance Monitor"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Process Explorer (a free tool from Microsoft Sysinternals) provides significantly more detailed information about running processes than Task Manager or Resource Monitor, including handles, threads, DLLs loaded, and more. It's a powerful tool for advanced troubleshooting.  Performance Monitor tracks performance counters, not process details *to this extent*.",
        "examTip": "Download and familiarize yourself with Process Explorer (from Sysinternals); it's an invaluable tool for in-depth process analysis."
    },
	 {
        "id": 22,
        "question": "A user reports that they are receiving bounce-back messages (delivery failure notifications) for emails they never sent. What is the MOST likely cause?",
        "options":[
            "The user's email account has been compromised and is being used to send spam.",
            "The user's email client is misconfigured.",
            "The recipient's email server is down.",
            "The user's internet connection is unstable."
        ],
        "correctAnswerIndex": 0,
        "explanation": "Receiving bounce-backs for unsent emails is a strong indication that the user's email account has been compromised and is being used by spammers.  A misconfigured client would usually prevent *sending* emails, not cause bounce-backs for unsent messages.  A recipient server problem would only affect emails *to* that server.  An unstable connection wouldn't cause fake bounce-backs.",
        "examTip": "If a user receives bounce-backs for emails they didn't send, immediately suspect account compromise and change the password."
    },
    {
        "id": 23,
        "question": "Which of the following security practices is MOST effective in mitigating the risk of a brute-force password attack?",
        "options":[
           "Using a strong password.",
            "Enforcing account lockout policies (limiting the number of failed login attempts).",
            "Using a firewall.",
            "Using antivirus software."
        ],
        "correctAnswerIndex": 1, //Both A and B are very good choices
        "explanation": "Account lockout policies are *specifically* designed to counter brute-force attacks by temporarily locking an account after a certain number of failed login attempts. While a strong password makes cracking *harder*, it doesn't *prevent* repeated attempts. Firewalls and antivirus are less directly related to password attacks.",
        "examTip": "Always implement account lockout policies to protect against brute-force password attacks."
    },
     {
        "id":24,
        "question":"You are configuring a firewall and need to allow inbound traffic to a web server running on port 80 and 443. What type of firewall rule would you create?",
        "options":[
           "An outbound rule.",
            "An inbound rule.",
            "A port forwarding rule.",
            "A NAT rule."
        ],
        "correctAnswerIndex": 1,
        "explanation": "To allow *inbound* traffic to a server, you need to create an *inbound* firewall rule that permits traffic on the specified ports (80 for HTTP, 443 for HTTPS). An outbound rule controls traffic *leaving* the network. Port forwarding is a specific type of inbound rule often used on home routers. NAT (Network Address Translation) translates IP addresses, but doesn't inherently *allow* or *block* traffic.",
        "examTip":"Understand the difference between inbound and outbound firewall rules: inbound rules control traffic *coming into* a network or computer, outbound rules control traffic *leaving* it."
    },
     {
        "id": 25,
        "question": "What is the primary purpose of the `/flushdns` switch used with the `ipconfig` command in Windows?",
        "options":[
            "To release the current IP address.",
            "To renew the IP address.",
            "To clear the DNS resolver cache, forcing the system to requery DNS servers for name resolution.",
            "To display detailed network configuration information."
        ],
        "correctAnswerIndex": 2,
        "explanation": "`ipconfig /flushdns` clears the local DNS cache.  This forces the computer to perform fresh DNS lookups, which can resolve problems caused by outdated or incorrect cached DNS entries.  `ipconfig /release` releases the IP, `ipconfig /renew` renews it, and `ipconfig /all` displays information.",
        "examTip": "Use `ipconfig /flushdns` to troubleshoot DNS resolution issues, especially after making changes to DNS records."
    },
    {
        "id": 26,
        "question":"A user's laptop is exhibiting signs of malware infection, including slow performance, pop-up ads, and unusual network activity. You have run multiple antivirus and anti-malware scans, but some threats persist. What is the NEXT BEST step to ensure complete malware removal?",
        "options":[
            "Reinstall the operating system.",
            "Boot into Safe Mode and run the scans again.",
            "Use a bootable antivirus/anti-malware rescue disk (from a reputable vendor) to scan the system from outside the infected operating system.",
            "Restore the system from a recent backup."
        ],
        "correctAnswerIndex": 2,
        "explanation": "A bootable rescue disk scans the system *before* the infected operating system loads, allowing it to detect and remove rootkits and other deeply embedded malware that might be hiding from scans run *within* Windows. Reinstalling the OS is a more drastic step. Safe Mode helps, but a bootable disk is more thorough. Restoring from a backup *might* work, but if the backup is also infected, the problem will return.",
        "examTip": "Use a bootable antivirus/anti-malware rescue disk for thorough malware removal, especially when dealing with persistent or advanced threats."
    },
     {
        "id": 27,
        "question": "You are setting up a new Linux server and want to ensure that only authorized users can connect to it remotely via SSH. Which of the following configurations provides the BEST security?",
        "options":[
          "Allow root login via SSH and use a strong password.",
          "Disable root login via SSH, allow only specific user accounts to connect via SSH using key-based authentication (disabling password authentication), and configure a firewall to restrict SSH access to specific IP addresses.",
          "Allow all users to connect via SSH with password authentication.",
          "Use Telnet instead of SSH for remote access."
        ],
        "correctAnswerIndex": 1,
        "explanation": "This combination provides multiple layers of security: disabling root login prevents direct attacks on the root account, key-based authentication is much more secure than passwords, allowing only specific users restricts access further, and a firewall adds another layer of defense. Allowing root login with a password, allowing all users with passwords, and using Telnet (which is unencrypted) are all *insecure* practices.",
        "examTip": "For secure SSH access, disable root login, use key-based authentication, restrict access to specific users and IP addresses, and use a firewall."
    },
	{
        "id": 28,
        "question": "What is the purpose of the 'principle of least privilege' in cybersecurity?",
        "options":[
           "To give all users administrator access to simplify management.",
            "To grant users only the minimum necessary access rights (permissions) required to perform their job duties.",
            "To use the strongest possible encryption for all data.",
            "To install the latest security patches on all systems."
        ],
        "correctAnswerIndex": 1,
        "explanation": "The principle of least privilege minimizes the potential damage from security breaches or insider threats by limiting user access to only what's essential. Giving everyone administrator access is a major security risk. Encryption and patching are important, but they don't directly address the *scope* of user access.",
        "examTip": "Always apply the principle of least privilege when assigning user permissions; grant only the necessary access, and no more."
    },
    {
        "id":29,
        "question": "A user complains that their computer is 'running out of memory,' even though they have plenty of RAM installed. You open Task Manager and see that a single application is consuming a very large amount of memory, and the amount is steadily increasing over time. What is the MOST likely cause?",
        "options":[
          "The hard drive is failing.",
          "The application has a memory leak.",
          "The user has too many browser tabs open.",
          "The computer is infected with a virus."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A memory leak occurs when an application allocates memory but fails to release it when it's no longer needed. This causes the application's memory usage to grow continuously over time, eventually leading to performance problems or crashes. A failing hard drive wouldn't cause this specific symptom. Too many browser tabs *can* consume a lot of memory, but a single application with *steadily increasing* usage is more indicative of a leak. A virus *could* cause memory issues, but a leak is the *most* direct explanation.",
        "examTip": "A steadily increasing memory usage by a single application is a classic sign of a memory leak; report the issue to the application developer."
    },
    {
       "id": 30,
       "question":"You are configuring a network and need to ensure that specific devices (like servers and printers) always receive the same IP address from the DHCP server. What is the BEST way to achieve this?",
       "options":[
        "Configure static IP addresses on each device.",
        "Configure DHCP reservations (also known as static DHCP) on the DHCP server, mapping MAC addresses to specific IP addresses.",
        "Use a very short DHCP lease time.",
        "Disable DHCP entirely."
       ],
       "correctAnswerIndex": 1,
       "explanation":"DHCP reservations (or static DHCP) allow you to combine the benefits of DHCP (centralized management) with the consistency of static IP addresses. The DHCP server assigns the *same* IP address to a device based on its MAC address. Configuring static IPs directly on each device works, but is less manageable. Short lease times don't guarantee the *same* address, and disabling DHCP is not a solution.",
       "examTip":"Use DHCP reservations to ensure that specific devices always receive the same IP address while still benefiting from centralized DHCP management."
          {
        "id": 31,
        "question": "You are investigating a potential data breach. You need to determine when a specific user account last logged on to a Windows server. Which tool and log would you use?",
        "options":[
           "Task Manager; Security log",
            "Event Viewer; Security log",
            "Resource Monitor; Application log",
            "System Information; System log"
        ],
        "correctAnswerIndex": 1,
        "explanation": "The Security log in Event Viewer records security-related events, including user logon and logoff activity. Task Manager shows running processes, Resource Monitor shows resource usage, and System Information provides system details. The *Security* log is key for auditing.",
        "examTip": "Familiarize yourself with the different types of Windows event logs (System, Application, Security) and the information they contain."
    },
    {
        "id": 32,
        "question": "You are configuring a SOHO router and want to allow remote access to an internal web server (running on port 8080) from the internet. The server has a private IP address of 192.168.1.100.  What configuration steps are required on the router?",
        "options":[
          "Enable DMZ and set the DMZ host to 192.168.1.100.",
          "Configure port forwarding to forward external port 8080 to internal IP address 192.168.1.100, port 8080.",
          "Configure port forwarding to forward external port 80 to internal IP address 192.168.1.100, port 8080",
          "Enable UPnP (Universal Plug and Play)."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Port forwarding directs incoming traffic on a specific external port (8080 in this case) to a specific internal IP address and port (192.168.1.100:8080).  Using DMZ exposes the *entire* server to the internet, which is a security risk. Option C forwards the *wrong* external port. UPnP can automate port forwarding, but it's often a security risk and should be disabled unless absolutely necessary.",
        "examTip": "Use port forwarding to allow specific inbound traffic to internal servers; avoid using DMZ unless absolutely necessary due to the security risks."
    },
    {
        "id": 33,
        "question": "A user reports that their computer is exhibiting unusual behavior, including slow performance, unexpected pop-ups, and changes to their browser's homepage. You suspect malware, but standard antivirus scans are not detecting anything. What is the NEXT BEST step to investigate and potentially remove the malware?",
        "options":[
            "Reinstall the operating system.",
            "Run a scan with a different anti-malware tool, preferably one specializing in rootkit detection.",
            "Restore the system from a recent backup.",
            "Disconnect the computer from the network."
        ],
        "correctAnswerIndex": 1,
        "explanation": "If standard scans are failing, using a *different* anti-malware tool, especially one designed to detect rootkits (which can hide from standard scans), is the next logical step. Reinstalling the OS is more drastic. Restoring from a backup might reintroduce the malware if the backup is infected. Disconnecting from the network is a containment measure, not a removal step.",
        "examTip": "If one anti-malware tool fails, try another, particularly one specializing in rootkit detection, before resorting to more drastic measures."
    },
    {
        "id": 34,
        "question":"A company wants to implement a security policy that requires users to change their passwords every 90 days. Where would you configure this setting in a Windows domain environment?",
        "options":[
            "In the user's account properties.",
            "In Group Policy, under Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Account Policies -> Password Policy.",
            "In Local Security Policy on each individual computer.",
            "In the Windows Firewall settings."
        ],
        "correctAnswerIndex": 1,
        "explanation": "In a domain environment, password policies are typically managed centrally through Group Policy. The specific location is within the Computer Configuration section, under Account Policies -> Password Policy.  Individual user account properties might have *some* password settings, but the domain policy takes precedence. Local Security Policy applies only to the local computer, not domain users. Firewall settings are unrelated.",
        "examTip": "Use Group Policy to centrally manage password policies and other security settings in a Windows domain environment."
    },
    {
        "id":35,
        "question": "You are troubleshooting a network connectivity issue on a Linux server. You need to determine which process is listening on a specific port (e.g., port 22 for SSH). Which command would you use?",
        "options":[
            "`netstat -tulnp | grep :22`",
            "`ip addr show`",
            "`ifconfig`",
            "`ping`"
        ],
        "correctAnswerIndex": 0,
        "explanation": "`netstat -tulnp` shows listening TCP and UDP ports, along with the owning process ID and name. The `grep :22` filters the output to show only lines related to port 22. `ip addr show` and `ifconfig` show interface information, and `ping` tests connectivity, not listening ports.",
        "examTip": "Use `netstat -tulnp` (or `ss -tulnp` on newer systems) on Linux to identify processes listening on specific ports."
    },
    {
        "id": 36,
        "question": "A user reports that their computer suddenly shut down without warning and will not power back on. You suspect a hardware problem. What is the FIRST component you should check?",
        "options":[
            "The RAM.",
            "The hard drive.",
            "The power supply unit (PSU).",
            "The CPU."
        ],
        "correctAnswerIndex": 2,
        "explanation": "A complete failure to power on is most often caused by a faulty power supply. While RAM, hard drive, or CPU failures *can* occur, they usually manifest with different symptoms (errors during boot, crashes, etc.). A dead PSU prevents the system from powering on at all.",
        "examTip": "Suspect the power supply first when a computer completely fails to power on."
    },
    {
        "id":37,
        "question":"What is the purpose of the `/all` switch used with the `ipconfig` command in Windows?",
        "options":[
           "To release the current IP address.",
            "To renew the IP address.",
            "To display detailed network configuration information for all network adapters, including IP address, subnet mask, default gateway, DNS servers, and MAC address.",
            "To flush the DNS resolver cache."
        ],
        "correctAnswerIndex": 2,
        "explanation": "`ipconfig /all` provides comprehensive network adapter information, including everything `ipconfig` shows, plus details like the MAC address, DHCP lease information, and DNS server list. The other options describe other `ipconfig` switches.",
        "examTip": "`ipconfig /all` is your go-to command for gathering detailed network configuration information in Windows."
    },
	 {
        "id": 38,
        "question": "You are concerned about the security of a wireless network. You want to determine if any unauthorized devices are connected to the network. Which of the following tools or techniques would be MOST effective for identifying connected devices?",
        "options":[
           "Ping each device on the network.",
            "Check the router's DHCP client list (which shows devices that have obtained IP addresses from the router) and/or use a network scanning tool (like Nmap or Angry IP Scanner) to discover all devices on the network.",
            "Use the `tracert` command.",
            "Check the Windows Event Viewer."
        ],
        "correctAnswerIndex": 1,
        "explanation": "The router's DHCP client list shows devices that have received IP addresses from the router. Network scanning tools actively probe the network to discover all connected devices, even those with static IPs.  `ping` requires knowing the IP address beforehand. `tracert` traces routes. Event Viewer is for system logs, not network device discovery.",
        "examTip": "Use a combination of the router's DHCP client list and a network scanning tool for comprehensive device discovery on a network."
    },
    {
       "id":39,
       "question":"A user is unable to access a website.  You suspect a DNS problem.  You use the `nslookup` command to query the user's configured DNS server for the website's IP address, and it returns a 'non-existent domain' error. What does this indicate?",
       "options":[
        "The user's computer is not connected to the network.",
        "The user's DNS server is not functioning correctly, or the website's domain name is not registered or has expired.",
        "The website's server is down.",
        "The user's web browser is malfunctioning."
       ],
       "correctAnswerIndex": 1,
       "explanation": "A 'non-existent domain' error from `nslookup` means the queried DNS server cannot find a record for the specified domain name.  This could be because the DNS server itself is having problems, or because the domain name is invalid, unregistered, or has expired.  It doesn't necessarily mean the *user's* computer has no network, the *website's* server is down (though that's a *possibility*), or the browser is broken.",
       "examTip":"A 'non-existent domain' error from `nslookup` points to a problem with the domain name itself or the DNS server's ability to resolve it."
    },
     {
        "id": 40,
        "question": "You are configuring a new email server. You want to implement measures to reduce spam and prevent email spoofing. Which of the following combinations of DNS records would be MOST effective?",
        "options":[
            "MX records only.",
            "SPF, DKIM, and DMARC records.",
            "A records and CNAME records.",
            "PTR records only."
        ],
        "correctAnswerIndex": 1,
        "explanation": "SPF (Sender Policy Framework), DKIM (DomainKeys Identified Mail), and DMARC (Domain-based Message Authentication, Reporting & Conformance) work together to authenticate email senders and prevent spoofing. MX records specify mail servers. A and CNAME records are for general hostname-to-IP mapping. PTR records are for reverse DNS lookups.",
        "examTip": "Implement SPF, DKIM, and DMARC records to improve email security and reduce the risk of your domain being used for spam or phishing."
    },
    {
        "id": 41,
        "question": "Which of the following is an example of a 'watering hole' attack?",
        "options":[
            "Sending phishing emails to a large number of recipients.",
            "Compromising a website that is frequently visited by a specific target group, and infecting the website with malware to infect the visitors.",
            "Exploiting a vulnerability in a web server.",
            "Guessing user passwords."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A watering hole attack targets a specific group by compromising a website they are known to visit.  It's like poisoning a watering hole that animals (the targets) frequent.  Phishing is sending deceptive emails. Exploiting a web server vulnerability is a direct attack, and password guessing is a brute-force attack.",
        "examTip": "Watering hole attacks are targeted and exploit the trust users have in legitimate websites; keep software updated and be cautious about visiting unfamiliar sites."
    },
    {
        "id": 42,
        "question": "You are troubleshooting a slow internet connection. Using the `tracert` command, you observe high latency (response times) at a specific hop along the route to a destination. What does this indicate?",
        "options":[
            "The destination server is down.",
          "There is a network problem or congestion at that specific hop, or at a point immediately preceding it.",
          "Your computer's network adapter is faulty.",
          "Your DNS server is slow."
        ],
        "correctAnswerIndex": 1,
        "explanation": "High latency at a particular hop in a `tracert` output indicates a problem *at that hop* or *immediately before it*. It could be a congested router, a faulty network link, or a problem with the ISP's network. It doesn't necessarily mean the *destination* server is down (though that's *possible*), and it's unlikely to be your *local* network adapter or DNS server.",
        "examTip": "Use `tracert` to identify points of high latency or packet loss along a network path; this helps pinpoint the source of network slowdowns."
    },
	{
        "id": 43,
        "question":"What is the purpose of a 'honeypot' in cybersecurity?",
        "options":[
            "To encrypt sensitive data.",
          "To attract and trap attackers, allowing you to study their methods and gather information about their activities.",
            "To provide a secure connection for remote access.",
            "To filter network traffic."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A honeypot is a decoy system designed to look like a legitimate target, luring attackers and allowing security professionals to observe their techniques and gather intelligence.  It's not for encryption, secure remote access (VPNs do that), or general traffic filtering (firewalls do that).",
        "examTip": "Honeypots are used for threat research and detection; they can provide valuable insights into attacker behavior."
    },
     {
        "id": 44,
        "question":"A user reports that their computer is displaying a 'missing operating system' error message. You have verified that the hard drive is connected properly and is recognized by the BIOS. The boot order is also correct. What is the NEXT step to troubleshoot?",
        "options":[
           "Replace the hard drive.",
            "Reinstall the operating system.",
            "Use the Windows Recovery Environment (booting from installation media) to attempt to repair the boot sector or BCD (Boot Configuration Data).",
            "Run a virus scan."
        ],
        "correctAnswerIndex": 2,
        "explanation": "A 'missing operating system' error, with a recognized hard drive and correct boot order, often indicates a corrupted boot sector or BCD. The Windows Recovery Environment provides tools (like `bootrec.exe`) to repair these. Replacing the hard drive or reinstalling the OS are more drastic steps. A virus scan is less likely to be effective at this stage.",
        "examTip": "Use the Windows Recovery Environment (boot from installation media) and tools like `bootrec.exe` to repair boot problems."
    },
    {
        "id": 45,
        "question": "You are configuring a new computer and want to encrypt the entire hard drive to protect sensitive data. Which built-in Windows feature would you use?",
        "options":[
           "EFS (Encrypting File System)",
            "BitLocker Drive Encryption",
            "Windows Defender Firewall",
            "User Account Control (UAC)"
        ],
        "correctAnswerIndex": 1,
        "explanation": "BitLocker provides full-disk encryption, protecting the entire drive and its contents. EFS encrypts individual files and folders. Windows Defender Firewall is for network security, and UAC controls application privileges.",
        "examTip": "Use BitLocker for full-disk encryption, especially on laptops or other portable devices, to protect data in case of loss or theft."
    },
	{
        "id": 46,
        "question": "Which of the following is the BEST description of 'data remanence'?",
        "options":[
            "The process of backing up data.",
           "The residual data that remains on a storage device even after it has been erased or formatted.",
            "The encryption of data.",
            "The transfer of data over a network."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Data remanence refers to the lingering traces of data that can persist on a storage medium (hard drive, SSD, USB drive) even after standard deletion or formatting.  Specialized data recovery techniques can sometimes recover this data.",
        "examTip": "Use secure data wiping methods (overwriting multiple times with random data) or physical destruction to prevent data remanence when disposing of storage devices."
    },
    {
        "id": 47,
        "question":"A user reports that they are unable to access a specific website.  You can access the website from a different computer on the same network. What is the FIRST troubleshooting step you should take on the user's computer?",
        "options":[
           "Reinstall the operating system.",
           "Check the user's web browser's proxy settings, clear the browser cache and cookies, and check the 'hosts' file for any entries that might be blocking the website.",
            "Replace the network cable.",
            "Run a virus scan."
        ],
        "correctAnswerIndex": 1,
        "explanation": "If the website is accessible from another computer on the *same* network, the problem is likely local to the user's computer.  Checking proxy settings, clearing the browser cache/cookies, and examining the 'hosts' file (which can override DNS) are common troubleshooting steps for website access issues. Reinstalling the OS is too drastic. A faulty cable would likely cause *more general* network problems. A virus scan is good practice, but less targeted to this *specific* issue.",
        "examTip": "When troubleshooting website access problems, check browser settings (proxy, cache, cookies) and the 'hosts' file before assuming network-wide issues."
    },
    {
        "id":48,
        "question":"Which Linux command would you use to find all files named 'config.txt' within the `/etc` directory and its subdirectories?",
        "options":[
           "`grep config.txt /etc`",
            "`find /etc -name config.txt`",
            "`locate config.txt`",
            "`ls /etc | grep config.txt`"
        ],
        "correctAnswerIndex": 1,
        "explanation": "`find /etc -name config.txt` is the correct command.  `find` is used to locate files based on various criteria. `/etc` specifies the starting directory, and `-name config.txt` specifies the filename to search for. `grep` searches *within* files, `locate` uses a pre-built database (which might be outdated), and `ls /etc | grep config.txt` would only find files *directly* within `/etc`, not subdirectories.",
        "examTip": "Use the `find` command for powerful file searching in Linux, specifying the starting directory and search criteria."
    },
     {
        "id": 49,
        "question": "You are setting up a network and want to prevent unauthorized devices from connecting to your wireless network, even if they know the Wi-Fi password. Which security feature would you use?",
        "options":[
           "WPS (Wi-Fi Protected Setup)",
            "MAC address filtering",
            "SSID broadcast disabling",
            "WEP encryption"
        ],
        "correctAnswerIndex": 1,
        "explanation": "MAC address filtering allows you to create a list of allowed devices based on their unique MAC addresses.  Only devices on the list will be able to connect, even if they have the Wi-Fi password. WPS is insecure. Disabling SSID broadcast hides the network name, but doesn't prevent connections if the SSID is known. WEP is outdated and insecure.",
        "examTip": "While MAC address filtering can add a layer of security, it's not foolproof (MAC addresses can be spoofed); it's best used in combination with strong WPA2/WPA3 encryption and a strong password."
    },
    {
        "id": 50,
        "question": "You are troubleshooting a Windows computer that is experiencing performance issues.  You suspect a problem with the hard drive. Which command-line tool would you use to check the file system integrity and attempt to repair any errors?",
        "options":[
           "defrag",
            "diskpart",
            "chkdsk",
            "sfc /scannow"
        ],
        "correctAnswerIndex": 2,
        "explanation": "`chkdsk` (Check Disk) scans the hard drive for file system errors and bad sectors, and can attempt to repair them. `defrag` defragments the drive, `diskpart` manages partitions, and `sfc /scannow` checks system files, not the file system *structure* itself.",
        "examTip": "Run `chkdsk` periodically, especially if you suspect file system corruption or hard drive problems; use the `/f` switch to fix errors and the `/r` switch to locate bad sectors and recover readable information."
    },
    {
        "id":51,
        "question":"Which type of attack involves an attacker inserting malicious code into a database query, potentially allowing them to access, modify, or delete data?",
        "options":[
          "Cross-site scripting (XSS)",
          "SQL injection",
          "Denial-of-service (DoS)",
          "Phishing"
        ],
        "correctAnswerIndex": 1,
        "explanation":"SQL injection specifically targets databases by injecting malicious SQL code into input fields.  XSS targets web applications and injects client-side scripts. DoS attacks disrupt service. Phishing is social engineering.",
        "examTip": "Protect against SQL injection by validating and sanitizing all user input and using parameterized queries (prepared statements)."

    },
    {
        "id": 52,
        "question": "A user reports their computer is running slowly. Task Manager shows high CPU usage, but no single process appears to be the culprit. After further investigation, you suspect a driver issue. Which tool would BEST allow you to identify a specific driver causing high CPU utilization?",
        "options":[
            "Resource Monitor",
            "System Configuration (msconfig.exe)",
            "Windows Performance Recorder and Analyzer (WPR/WPA), specifically looking at CPU usage by modules (drivers).",
            "Device Manager"
        ],
        "correctAnswerIndex": 2,
        "explanation": "WPR/WPA allows for detailed performance tracing, including CPU usage broken down by individual drivers and modules. Resource Monitor shows overall resource usage, msconfig manages startup, and Device Manager manages hardware and drivers, but doesn't provide this level of *performance* analysis.",
        "examTip": "Use WPR/WPA for in-depth performance analysis, including identifying resource-intensive drivers."
    },
     {
        "id": 53,
        "question": "You are configuring a server that will host multiple virtual machines. Which CPU feature is essential for optimal virtualization performance?",
        "options":[
            "Hyper-Threading",
          "Hardware-assisted virtualization (e.g., Intel VT-x or AMD-V).",
            "Overclocking",
            "A large L3 cache"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Hardware-assisted virtualization (Intel VT-x or AMD-V) provides CPU extensions that significantly improve the performance and efficiency of virtual machines. Hyper-Threading allows a single core to handle multiple threads, which *can* help, but hardware virtualization is *more* fundamental. Overclocking is generally not recommended for servers. A large cache is beneficial, but secondary to hardware virtualization support.",
        "examTip": "Ensure that hardware-assisted virtualization (VT-x or AMD-V) is enabled in the BIOS/UEFI settings for optimal virtual machine performance."
    },
    {
        "id": 54,
        "question": "You are troubleshooting a network connectivity problem on a Windows workstation. The computer has a valid IP address, can ping its default gateway, but cannot access any websites. You suspect a DNS issue. Besides `nslookup`, which command-line tool can you use to test DNS resolution?",
        "options":[
          "ping <domain_name>",
          "tracert <domain_name>",
          "ipconfig /all",
          "netstat"
        ],
        "correctAnswerIndex": 0, //Both A and B can provide clues
        "explanation": "If `ping <domain_name>` fails but `ping <ip_address>` works, it suggests a DNS resolution issue, even without using `nslookup` directly. `tracert` will *also* likely fail if DNS resolution is the root cause. `ipconfig /all` shows network configuration, and `netstat` shows active connections, but they don't directly test DNS resolution in the same way.",
        "examTip": "While `nslookup` is the primary DNS troubleshooting tool, a failing `ping` by domain name (but successful ping by IP) is a strong indicator of a DNS problem."
    },
     {
        "id": 55,
        "question": "Which of the following is a key security benefit of using a VPN (Virtual Private Network)?",
        "options":[
           "It speeds up your internet connection.",
            "It encrypts your internet traffic, protecting it from eavesdropping, especially on public Wi-Fi networks.",
            "It prevents viruses and malware from infecting your computer.",
            "It blocks access to specific websites."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A VPN's primary security benefit is encryption. It creates a secure tunnel for your data, protecting it from interception, particularly on untrusted networks. It doesn't inherently speed up connections (it can sometimes slow them down), prevent viruses (antivirus software does that), or block websites (though some VPNs offer this as an additional feature).",
        "examTip": "Use a VPN whenever connecting to public Wi-Fi or accessing sensitive data remotely to protect your privacy and security."
    },
	 {
        "id": 56,
        "question":"You are investigating a security incident and need to determine the exact time an event occurred. The computer's system clock is not synchronized with a reliable time source. What should you do?",
        "options":[
            "Rely on the computer's system clock.",
           "Consult system logs, comparing timestamps across multiple devices and logs (if available) and looking for corroborating evidence to establish a timeline.",
            "Ask the user when they think the event occurred.",
            "Assume the event occurred at the time the incident was reported."
        ],
        "correctAnswerIndex": 1,
        "explanation":"If the system clock is unreliable, you cannot trust its timestamps.  The best approach is to correlate timestamps from *multiple* sources (other logs, network devices, security appliances) to establish a more accurate timeline. User reports can be helpful, but are subjective. Assuming the time of reporting is inaccurate.",
        "examTip":"In security investigations, always consider the reliability of timestamps and correlate information from multiple sources when possible."
    },
    {
        "id":57,
        "question": "What is the function of the `chmod +x` command in Linux?",
        "options":[
            "To change the ownership of a file.",
          "To make a file executable.",
            "To delete a file.",
            "To view the contents of a file."
        ],
        "correctAnswerIndex": 1,
        "explanation": "`chmod +x <filename>` adds the execute permission to a file, allowing it to be run as a program or script. `chown` changes ownership, deleting is done with `rm`, and viewing contents is typically done with `cat`, `less`, or `more`.",
        "examTip": "Use `chmod +x` to make scripts or programs executable in Linux."
    },
     {
        "id":58,
        "question":"A user is working from home and needs to access files on a corporate file server. The company uses a VPN for secure remote access. The user successfully connects to the VPN, but they still cannot access the file server. What is the MOST likely cause?",
        "options":[
            "The user's home internet connection is down.",
           "The user does not have the correct permissions on the file server, or there is a firewall rule blocking access even over the VPN.",
            "The VPN software is not installed correctly.",
            "The user's computer is infected with malware."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Successful VPN connection establishes the secure tunnel, but it doesn't automatically grant access to *all* resources. The user still needs the correct permissions on the file server itself, and there might be firewall rules (either on the server or on a network firewall) that are blocking access even *over* the VPN. If the internet were down, the VPN wouldn't connect. Incorrect VPN installation would likely prevent the VPN connection itself.",
        "examTip": "Remember that a VPN connection provides *secure access*, but it doesn't bypass existing permissions or firewall rules on the target network."
    },
    {
        "id": 59,
        "question":"Which Windows command-line tool is BEST for managing local user accounts and groups?",
        "options":[
          "net user",
          "net localgroup",
          "lusrmgr.msc (Local Users and Groups - accessible through Computer Management)",
          "gpedit.msc (Local Group Policy Editor)"
        ],
        "correctAnswerIndex": 2,
        "explanation": "While `net user` and `net localgroup` can manage *some* aspects of users and groups from the command line, `lusrmgr.msc` (Local Users and Groups, accessed through Computer Management) provides the most comprehensive and user-friendly interface for managing local user accounts and groups. `gpedit.msc` is for Group Policy, not direct user/group management.",
        "examTip": "Use `lusrmgr.msc` (Local Users and Groups) for comprehensive local user and group management on Windows systems."
    },
    {
        "id": 60,
        "question":"You are configuring a Linux server and need to restrict network access to specific services based on the source IP address. Which tool is BEST suited for this task?",
        "options":[
          "iptables (or nftables on newer systems)",
          "netstat",
          "ifconfig",
          "route"
        ],
        "correctAnswerIndex": 0,
        "explanation": "`iptables` (or its successor, `nftables`) is the standard firewall utility in Linux, allowing you to create rules to filter network traffic based on various criteria, including source and destination IP addresses, ports, and protocols. `netstat` shows network connections, `ifconfig` configures interfaces, and `route` manages routing tables.",
        "examTip": "Familiarize yourself with `iptables` (or `nftables`) for configuring firewall rules on Linux systems."
    },
    {
        "id": 61,
        "question":"A user reports that they are unable to access a shared printer.  You have verified that the printer is online, other users can print to it, and the user's computer has network connectivity.  You've also restarted the Print Spooler service on the user's computer. What should you check NEXT?",
        "options": [
            "The printer's IP address.",
            "The user's account permissions on the printer.",
            "The network cable connecting the printer to the network.",
            "The printer's toner level."
        ],
        "correctAnswerIndex": 1,
        "explanation": "If other users can print and you've verified basic connectivity and the Print Spooler, the next logical step is to check the user's *permissions* on the printer itself.  Printer permissions can restrict access to specific users or groups. The printer's IP, network cable, and toner level are less likely to be the issue if *other* users can print.",
        "examTip": "Printer access is controlled by permissions; ensure the user or their group has the necessary rights to use the printer."
    },
     {
        "id": 62,
        "question": "You are investigating a suspected security incident and need to analyze network traffic captured in a PCAP (packet capture) file. Which tool is BEST suited for this task?",
        "options":[
            "netstat",
            "Wireshark",
            "ping",
            "tracert"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Wireshark is a powerful and widely used network protocol analyzer that allows you to capture and interactively browse network traffic, including analyzing PCAP files. `netstat` shows active connections, `ping` tests connectivity, and `tracert` traces routes; none of these analyze captured packet data.",
        "examTip": "Learn to use Wireshark; it's an essential tool for network troubleshooting and security analysis."
    },
     {
        "id":63,
        "question": "A user reports slow performance on their Windows computer. You open Task Manager and notice high disk I/O, but no single process is consuming all disk resources. You suspect fragmentation. However, the user's primary drive is an SSD. What should you do?",
        "options":[
            "Run Disk Defragmenter.",
           "Do NOT run Disk Defragmenter; SSDs should not be defragmented. Investigate other potential causes of high disk I/O, such as a failing drive or malware.",
            "Run Disk Cleanup.",
            "Increase the size of the paging file."
        ],
        "correctAnswerIndex": 1,
        "explanation": "SSDs (Solid State Drives) do *not* benefit from defragmentation, and it can actually *reduce* their lifespan.  High disk I/O on an SSD could indicate a failing drive, malware activity, or other issues. Disk Cleanup removes files, and increasing the paging file addresses virtual memory, not disk I/O directly.",
        "examTip": "Never defragment an SSD; it's unnecessary and can be harmful."
    },
    {
        "id": 64,
        "question": "What is the purpose of a 'digital signature' in the context of software distribution?",
        "options":[
          "To encrypt the software.",
            "To verify the authenticity and integrity of the software, ensuring it hasn't been tampered with and comes from a trusted source.",
            "To speed up the software installation process.",
            "To track the number of times the software has been installed."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A digital signature uses cryptography to verify that the software is genuine and hasn't been modified since it was signed by the developer.  It's like a digital seal of approval. It doesn't *encrypt* the software itself (though the software *might* be distributed in an encrypted package), speed up installation, or track installations.",
        "examTip": "Check for valid digital signatures before installing software to ensure it's legitimate and hasn't been tampered with."
    },
        {
        "id": 65,
        "question":"A user is unable to connect to a website. You suspect a DNS issue. You've already tried `ping <domain_name>` (which failed) and `ipconfig /flushdns`. What is the NEXT BEST step to troubleshoot?",
        "options":[
          "Reinstall the user's web browser.",
          "Use `nslookup` to query different DNS servers (e.g., Google Public DNS - 8.8.8.8) to see if the issue is with the user's configured DNS server.",
          "Restart the user's computer.",
          "Replace the user's network cable."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Trying different DNS servers with `nslookup` helps isolate the problem. If `nslookup` works with a different server (like 8.8.8.8), the issue is likely with the user's *original* DNS server configuration. Reinstalling the browser is unlikely to help with DNS. Restarting *might* help, but is less targeted. A cable problem would likely cause *more general* connectivity issues.",
        "examTip": "When troubleshooting DNS problems, test with different DNS servers (like Google Public DNS - 8.8.8.8) to isolate the issue."
    },
    {
        "id": 66,
        "question": "You are implementing a security policy that requires users to choose strong passwords. Which of the following password characteristics would be MOST important to enforce?",
        "options":[
          "Minimum password length of 8 characters.",
          "Minimum password length of 12 characters, a mix of uppercase and lowercase letters, numbers, and symbols, and disallowing common words or patterns.",
          "Requiring users to change their passwords every 30 days.",
          "Allowing users to write down their passwords."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A long, complex password (at least 12 characters, with a mix of character types) that avoids common words or patterns is the *most* important factor in password strength. While frequent changes *can* be helpful, overly frequent changes can lead to users choosing weaker passwords. Allowing written passwords is a major security risk.",
        "examTip": "Enforce strong password policies: long, complex, and unique passwords are the best defense against password cracking."
    },
    {
        "id": 67,
        "question":"You are troubleshooting a computer that is experiencing intermittent network connectivity. You suspect a problem with the network adapter. Which Windows command-line tool would provide the MOST detailed information about the network adapter's configuration, driver details, and status?",
        "options":[
           "ping",
            "ipconfig /all",
            "netstat",
            "tracert"
        ],
        "correctAnswerIndex": 1,
        "explanation": "`ipconfig /all` provides comprehensive information about all network adapters, including IP address, MAC address, driver version, DHCP settings, and more. `ping` tests connectivity, `netstat` shows active connections, and `tracert` traces routes. While those can be *helpful*, `ipconfig /all` is the *most* direct for adapter details.",
        "examTip": "`ipconfig /all` is your primary tool for gathering detailed network adapter configuration information in Windows."
    },
    {
        "id": 68,
        "question": "You are setting up a home network and want to separate your guest Wi-Fi network from your main home network for security reasons. Which feature on your router would BEST accomplish this?",
        "options":[
           "WPS (Wi-Fi Protected Setup)",
            "Guest network (or guest Wi-Fi) feature, which creates a separate SSID and network segment with limited access to your main network.",
            "MAC address filtering",
            "Port forwarding"
        ],
        "correctAnswerIndex": 1,
        "explanation": "A guest network feature creates a separate, isolated wireless network for guests. This prevents them from accessing devices on your main network (like file shares or printers). WPS is insecure. MAC filtering restricts access based on device, but doesn't create a *separate* network. Port forwarding is for allowing inbound access to specific services.",
        "examTip": "Use the guest network feature on your router to isolate guest Wi-Fi access from your main home network."
    },
    {
        "id": 69,
        "question": "A user reports that their computer is running extremely slowly, and they see a message indicating that their hard drive is almost full. You've already run Disk Cleanup and removed unnecessary files, but the drive is still nearly full. What is the NEXT BEST step to investigate?",
        "options":[
           "Defragment the hard drive.",
            "Run `chkdsk`.",
            "Use a disk space analyzer tool (like WinDirStat, TreeSize, or WizTree) to visualize disk usage and identify which files and folders are consuming the most space.",
            "Reinstall the operating system."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Disk space analyzer tools provide a visual representation of disk usage, making it easy to identify large files or folders that might be taking up unnecessary space. Defragmenting is only useful for HDDs, not SSDs. `chkdsk` checks for file system errors. Reinstalling the OS is too drastic.",
        "examTip": "Use a disk space analyzer tool to quickly identify which files and folders are consuming the most space on a hard drive."
    },
    {
        "id": 70,
        "question": "You are configuring a server and want to ensure that it automatically synchronizes its system clock with a reliable time source. Which protocol is BEST suited for this purpose?",
        "options":[
           "FTP (File Transfer Protocol)",
            "NTP (Network Time Protocol)",
            "HTTP (Hypertext Transfer Protocol)",
            "SMTP (Simple Mail Transfer Protocol)"
        ],
        "correctAnswerIndex": 1,
        "explanation": "NTP (Network Time Protocol) is specifically designed for time synchronization across a network.  FTP is for file transfer, HTTP is for web browsing, and SMTP is for email.",
        "examTip": "Configure your systems to synchronize with a reliable NTP server (either a public server or an internal server) to ensure accurate timekeeping, which is crucial for logging, security, and other functions."
    },
     {
        "id": 71,
        "question": "Which of the following actions is MOST likely to result in malware infection?",
        "options":[
            "Visiting reputable websites.",
          "Downloading and opening attachments from unknown or untrusted email senders.",
            "Keeping your operating system and software up-to-date.",
            "Using a strong, unique password for your email account."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Opening attachments from untrusted sources is a *very* common way to get infected with malware. Reputable websites, updates, and strong passwords *reduce* the risk of infection.",
        "examTip": "Be extremely cautious about opening email attachments, especially from unknown or unexpected senders; this is a primary vector for malware distribution."
    },
     {
        "id": 72,
        "question":"A user reports that they are unable to access any network resources, including shared folders, printers, and the internet. Other users on the same network are not experiencing issues. You check the user's computer and find that it has a valid IP address, subnet mask, and default gateway. What should you investigate NEXT?",
        "options":[
            "The user's network cable.",
           "The user's DNS server settings, the 'hosts' file, and potential proxy server configurations.",
            "The network switch the user is connected to.",
            "The user's account is locked out."
        ],
        "correctAnswerIndex": 1, //Could also be A
        "explanation": "If the user has a valid IP configuration and *other* users are working, the problem is likely local to the user's computer *or* their specific network path. Incorrect DNS, a misconfigured 'hosts' file, or proxy settings can prevent access to *all* network resources, even with a valid IP. While a cable *could* be an issue, it's more likely to be something in the network config on this specific machine. A switch issue would likely affect *more* users. An account lockout would usually prevent *login*, not network access after successful login.",
        "examTip": "When troubleshooting complete network inaccessibility despite a valid IP configuration, check DNS settings, the 'hosts' file, and proxy settings on the affected computer."
    },
    {
       "id": 73,
        "question": "Which of the following security measures is MOST effective in preventing unauthorized access to a mobile device if it is lost or stolen?",
        "options":[
           "Installing antivirus software.",
            "Enabling a strong screen lock (PIN, password, pattern, or biometric) and configuring remote wipe capabilities.",
            "Using a VPN.",
            "Avoiding public Wi-Fi."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A strong screen lock prevents immediate access to the device, and remote wipe allows you to erase the data remotely if the device is lost or stolen. Antivirus helps with malware, a VPN protects network traffic, and avoiding public Wi-Fi improves *network* security, but they don't directly prevent *physical* access to the device.",
        "examTip": "Always enable a strong screen lock and remote wipe capabilities on mobile devices to protect your data in case of loss or theft."
    },
    {
        "id": 74,
        "question":"What is the purpose of the Windows 'hosts' file?",
        "options":[
            "To store user passwords.",
          "To map hostnames to IP addresses, overriding DNS resolution for specific entries.",
            "To configure network adapter settings.",
            "To manage firewall rules."
        ],
        "correctAnswerIndex": 1,
        "explanation": "The 'hosts' file is a local text file that contains a list of hostname-to-IP address mappings. Entries in the 'hosts' file take precedence over DNS resolution, allowing you to manually override DNS for specific websites or hosts. It doesn't store passwords, configure adapters, or manage firewalls.",
        "examTip": "The 'hosts' file can be used to block access to specific websites or to redirect traffic to a different server (e.g., for testing purposes); it's also a potential target for malware."
    },
    {
        "id": 75,
        "question":"A user reports that they are receiving an error message stating 'NTLDR is missing' when they try to boot their computer. What is the MOST likely cause?",
        "options":[
          "The monitor is not connected properly.",
          "The keyboard is not working.",
          "A problem with the boot sector, boot files, or boot configuration on an older Windows system (pre-Windows Vista).",
          "The network cable is unplugged."
        ],
        "correctAnswerIndex": 2,
        "explanation": "'NTLDR is missing' is an error message specific to *older* Windows systems (Windows XP and earlier) that use the NTLDR boot loader. It indicates a problem with the files needed to start the operating system. The other options are unrelated to the boot process.  Note:  Modern Windows systems use BOOTMGR, not NTLDR.",
        "examTip": "Recognize 'NTLDR is missing' as an error specific to older Windows systems; use the Recovery Console (from installation media) to attempt repairs."
    },
    {
        "id": 76,
        "question":"You are troubleshooting a network connectivity issue and suspect a problem with a specific router along the path to a destination. Which command-line tool would BEST help you identify the IP address of each router (hop) along the path?",
        "options":[
          "ping",
          "ipconfig",
          "tracert",
          "netstat"
        ],
        "correctAnswerIndex": 2,
        "explanation": "`tracert` (traceroute) displays the route that packets take to reach a destination, showing the IP address of each router (hop) along the way. `ping` tests connectivity, `ipconfig` shows local network configuration, and `netstat` shows active connections.",
        "examTip": "Use `tracert` to identify the routers along a network path and pinpoint potential points of failure or congestion."
    },
    {
        "id":77,
        "question":"What is 'shoulder surfing' in the context of security?",
        "options":[
          "A type of phishing attack.",
            "Visually observing someone's screen or keyboard to steal their passwords, PINs, or other sensitive information.",
            "A type of denial-of-service attack.",
            "Exploiting a vulnerability in a software application."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Shoulder surfing is a low-tech but effective way to steal information by simply looking over someone's shoulder as they enter passwords, PINs, or view sensitive data. It's not a phishing attack (which uses deceptive emails), a DoS attack (which disrupts service), or a software exploit.",
        "examTip": "Be aware of your surroundings when entering passwords or viewing sensitive information, especially in public places, to prevent shoulder surfing."
    },
    {
        "id": 78,
        "question":"You are configuring a firewall and want to allow only specific types of network traffic to pass through. What is the BEST approach to achieve this?",
        "options":[
           "Block all traffic by default and then create rules to explicitly allow only the necessary traffic (default deny).",
            "Allow all traffic by default and then create rules to block specific types of unwanted traffic (default allow).",
            "Allow all traffic.",
            "Block all traffic."
        ],
        "correctAnswerIndex": 0,
        "explanation": "The principle of 'default deny' (blocking everything by default and then explicitly allowing only what's needed) is a fundamental security best practice for firewalls.  'Default allow' is much less secure, as it leaves the network open to unexpected traffic. Allowing *all* or blocking *all* are not practical solutions.",
        "examTip": "Configure firewalls with a 'default deny' approach for maximum security; only allow the traffic that is explicitly required."
    },
     {
        "id":79,
        "question": "A user reports that their computer is exhibiting unusual behavior, including slow performance and unexpected pop-up ads. You suspect malware. What is the MOST important FIRST step before attempting to remove the malware?",
        "options":[
          "Reinstall the operating system.",
            "Disconnect the computer from the network to prevent the malware from spreading.",
            "Run a full system scan with antivirus software.",
            "Delete any suspicious-looking files."
        ],
        "correctAnswerIndex": 1, //After forensic image if incident response policy
        "explanation": "Disconnecting the computer from the network is crucial to *contain* the potential spread of malware to other systems. While running a scan is *important*, *containment* is the priority. Reinstalling the OS is a more drastic step. Deleting files without knowing what they are can cause further problems. *Ideally*, you would take a forensic image *first*, then disconnect.",
        "examTip": "In a suspected malware incident, prioritize containment by disconnecting the infected system from the network *before* attempting removal (after imaging if required by policy)."
    },
     {
        "id": 80,
        "question": "You are configuring a wireless router and want to hide the name of your Wi-Fi network from casual view. Which setting would you change?",
        "options":[
           "WPA2 encryption",
            "SSID broadcast (disable it)",
            "MAC address filtering",
            "WPS (Wi-Fi Protected Setup)"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Disabling SSID broadcast hides the network name (SSID) from being displayed in the list of available networks.  However, it doesn't prevent connections if the SSID is *known*. WPA2 is for encryption, MAC filtering restricts access by device, and WPS is a (vulnerable) setup feature.",
        "examTip": "Disabling SSID broadcast provides a *small* degree of obscurity, but it's not a strong security measure; rely on strong encryption (WPA2/WPA3) and a strong password instead."
    },
	 {
        "id": 81,
        "question": "A user reports that their computer is running slowly, and they are receiving 'low disk space' warnings. You've already run Disk Cleanup and removed unnecessary files, but the hard drive is still nearly full. The user has a large number of photos and videos stored on their computer. What is the BEST long-term solution?",
        "options":[
           "Defragment the hard drive.",
          "Move the photos and videos to an external hard drive, a network share, or a cloud storage service.",
            "Increase the size of the paging file.",
            "Reinstall the operating system."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Moving large files (like photos and videos) to external storage (external drive, network share, or cloud) frees up space on the internal drive. Defragmenting is only useful for HDDs. Increasing the paging file addresses virtual memory, not disk space. Reinstalling the OS is too drastic.",
        "examTip": "Encourage users to store large media files on external storage or cloud services to avoid filling up their primary hard drive."
    },
    {
        "id": 82,
        "question": "Which of the following is the MOST secure way to dispose of a hard drive containing sensitive data?",
        "options":[
           "Deleting all files and emptying the Recycle Bin.",
            "Formatting the hard drive.",
           "Using a disk wiping utility to overwrite the data multiple times with random data, or physically destroying the hard drive.",
            "Reinstalling the operating system."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Secure data destruction requires either *multiple* overwrites with random data (using a specialized disk wiping utility) or *physical destruction* (shredding, drilling, etc.). Deleting files and formatting only remove the file system's *pointers* to the data, not the data itself. Reinstalling the OS doesn't securely erase the *previous* data.",
        "examTip": "For truly sensitive data, physical destruction of the hard drive is the most reliable method of disposal; otherwise, use a reputable disk wiping utility that performs multiple overwrites."
    },
    {
        "id": 83,
        "question":"What is the purpose of a 'DMZ' (demilitarized zone) in a network?",
        "options":[
           "To provide a secure area for internal servers.",
          "To host publicly accessible servers (like web servers) while isolating them from the internal network, providing an extra layer of security.",
            "To connect remote users to the internal network via VPN.",
            "To filter all incoming and outgoing network traffic."
        ],
        "correctAnswerIndex": 1,
        "explanation":"A DMZ is a separate network segment that sits between the internal network and the internet. It hosts servers that need to be accessible from the internet (web servers, email servers, etc.) but isolates them from the more sensitive internal network. This protects the internal network even if a server in the DMZ is compromised. The other options describe different network security concepts.",
        "examTip": "Use a DMZ to protect your internal network while still allowing public access to specific servers."
    },
     {
        "id": 84,
        "question": "You are troubleshooting a computer that is randomly restarting. You suspect a hardware problem. You've already checked the RAM and the power supply. What is the NEXT component you should investigate?",
        "options":[
          "The keyboard.",
            "The monitor.",
           "The motherboard (including checking for bulging or leaking capacitors) and the CPU (checking for overheating).",
            "The network cable."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Random restarts can be caused by motherboard or CPU problems. Check the motherboard for physical damage (bulging capacitors are a common sign of failure) and ensure the CPU is not overheating (check cooling fan and thermal paste). The keyboard, monitor, and network cable are unlikely to cause random restarts.",
        "examTip": "Inspect the motherboard carefully for any signs of physical damage, especially bulging or leaking capacitors, when troubleshooting random restarts."
    },
    {
        "id": 85,
        "question":"You are configuring a wireless network and want to use the strongest possible encryption. Which encryption standard should you choose?",
        "options":[
          "WEP",
          "WPA",
          "WPA2 with AES",
          "WPA3 with TKIP"
        ],
        "correctAnswerIndex": 2, //WPA3 is stronger, if it's an option use it
        "explanation": "WPA2 with AES is the currently recommended standard. WPA3 is newer and more secure, but might not be supported by all devices. WEP and WPA (especially with TKIP) are outdated and have known vulnerabilities. When in doubt, WPA3 is generally stronger, with WPA2 with AES a close second.",
        "examTip": "Always use WPA2 with AES (or WPA3 if available and compatible) for the strongest wireless encryption."
    },
		{
            "id": 86,
            "question":"What is a 'zero-day' vulnerability?",
            "options":[
              "A vulnerability that is discovered on the first day a product is released.",
                "A vulnerability that is unknown to the software vendor and for which no patch is available.",
                "A vulnerability that only affects outdated software.",
                "A vulnerability that is easy to exploit."
            ],
            "correctAnswerIndex": 1,
            "explanation": "A zero-day vulnerability is a security flaw that is unknown to the software vendor, meaning there's no patch available to fix it. This makes zero-day exploits particularly dangerous. The other options describe different types of vulnerabilities, but not the defining characteristic of a zero-day.",
            "examTip": "Keep your software up-to-date to minimize the risk of zero-day attacks; prompt patching is crucial once vulnerabilities are discovered and patches are released."
        },
         {
            "id": 87,
            "question": "You are troubleshooting a network connectivity issue. You can ping local devices (by IP address and hostname) and your default gateway, but you cannot access any external websites. What is the MOST likely cause?",
            "options":[
               "A faulty network cable.",
                "A problem with your DNS server settings or a firewall/proxy blocking external access.",
                "The remote website servers are all down.",
                "Your computer's network adapter is disabled."
            ],
            "correctAnswerIndex": 1,
            "explanation": "If you can ping local devices and your gateway, you have basic network connectivity. The inability to access *any* external websites, while local communication works, strongly points to a DNS resolution problem, a firewall blocking outbound traffic, or a misconfigured proxy server. It's highly unlikely that *all* external websites are down simultaneously. A faulty cable or disabled adapter would likely prevent *all* network access.",
            "examTip": "When troubleshooting internet access problems, always consider DNS resolution, firewall rules, and proxy settings if local network communication is working."
        },
        {
            "id": 88,
            "question":"What is the primary difference between a virus and a worm?",
            "options":[
              "Viruses are always more harmful than worms.",
                "Viruses require a host file (like an executable or document) to spread, while worms can self-replicate and spread across networks without user interaction.",
                "Worms are always more harmful than viruses.",
                "Viruses only affect Windows computers, while worms only affect Linux computers."
            ],
            "correctAnswerIndex": 1,
            "explanation": "The key difference is in how they spread.  Viruses attach themselves to files and require user action (opening the infected file) to propagate. Worms are self-contained and can spread automatically across networks, exploiting vulnerabilities to infect other systems.  Harm levels vary, and both can affect various operating systems.",
            "examTip": "Understand the difference between viruses and worms: viruses need a host, worms self-replicate."
        },
         {
            "id": 89,
            "question": "You are configuring a new computer and want to ensure that the system clock is always accurate. Which Windows setting should you configure?",
            "options":[
              "Power Options",
              "Date and Time settings, specifically configuring automatic time synchronization with an internet time server (e.g., time.windows.com).",
              "System Configuration (msconfig.exe)",
              "Task Manager"
            ],
            "correctAnswerIndex": 1,
            "explanation": "The Date and Time settings in Windows allow you to enable automatic time synchronization with an internet time server (using NTP). This ensures the system clock is kept accurate. Power Options control sleep/hibernate, msconfig manages startup, and Task Manager manages running processes.",
            "examTip": "Enable automatic time synchronization in Windows to ensure your system clock is accurate; this is important for logging, security, and other time-sensitive operations."
        },
        {
            "id": 90,
            "question":"What is 'phishing' in the context of cybersecurity?",
            "options":[
               "A type of malware that encrypts files.",
              "A social engineering attack that attempts to trick users into revealing sensitive information (passwords, credit card numbers, etc.) by disguising as a trustworthy entity, often through email.",
                "A type of network attack that floods a server with traffic.",
                "A type of attack that exploits vulnerabilities in software."
            ],
            "correctAnswerIndex": 1,
            "explanation": "Phishing is a *social engineering* technique, relying on deception to trick users. It's not malware itself (though phishing emails might *contain* links to malware), a network flood (DoS), or a direct software exploit.",
            "examTip": "Be extremely cautious of unsolicited emails asking for personal information or containing suspicious links; this is a common phishing tactic.  Always verify the sender's authenticity."
        },
		 {
            "id": 91,
            "question": "Which command in Linux is used to display a list of all currently running processes?",
            "options":[
               "ls",
                "ps",
                "top",
                "jobs"
            ],
            "correctAnswerIndex": 1, //both 1 and 2 work
            "explanation": "`ps` (process status) displays a snapshot of currently running processes.  `top` provides a dynamic, real-time view of processes (and is also correct). `ls` lists files, and `jobs` shows background processes in the current shell (not *all* processes).",
            "examTip": "Use `ps` (or `top` for a dynamic view) to see running processes in Linux; use options like `ps aux` for a comprehensive list."
        },
        {
            "id": 92,
            "question":"You are troubleshooting a slow computer. You open Task Manager and notice that the 'System Idle Process' is using a very high percentage of CPU time. What does this indicate?",
            "options":[
              "The computer is infected with malware.",
              "The computer is working very hard.",
               "The computer is mostly idle, and the high percentage represents the amount of CPU capacity that is *not* being used.",
                "The hard drive is failing."
            ],
            "correctAnswerIndex": 2,
            "explanation": "The System Idle Process represents the *unused* CPU capacity. A high percentage for the System Idle Process means the CPU is *not* heavily loaded. It's a common misconception that a high System Idle Process percentage is a problem.",
            "examTip": "A high percentage for the System Idle Process in Task Manager indicates that the CPU is *not* heavily loaded; it represents *available* CPU resources."
        },
        {
          "id": 93,
          "question": "What is the purpose of enabling 'Audit Policy' in Windows?",
            "options":[
                "To improve system performance.",
                "To encrypt user files.",
               "To track and log security-related events, such as user logons, object access, and policy changes, for auditing and security analysis.",
                "To manage user accounts and groups."
            ],
          "correctAnswerIndex": 2,
          "explanation": "Audit Policy allows you to configure Windows to record specific security events in the Security log. This provides an audit trail for security investigations and compliance reporting. It doesn't improve performance, encrypt files, or manage user accounts directly (though it *tracks* account-related events).",
          "examTip": "Configure Audit Policy carefully to track relevant security events; excessive auditing can generate large log files and impact performance."
        },
		{
            "id": 94,
            "question":"A user reports that they are unable to access a network share.  You have verified that the user has the correct permissions, the file server is online, and other users can access the share. The user's computer has a valid IP address and can ping the file server. What is the NEXT step to troubleshoot?",
            "options":[
               "Reinstall the user's network adapter driver.",
                "Restart the user's computer.",
               "Check if the user's workstation can resolve the file server's hostname using `nslookup` or `ping <hostname>`.  If not, troubleshoot DNS. If it can, investigate potential SMB protocol issues or firewall rules on the client or server.",
                "Run a virus scan on the user's computer."
            ],
            "correctAnswerIndex": 2,
            "explanation": "Since basic connectivity (ping by IP) is working, the next step is to verify DNS resolution (can the computer translate the server's *name* to its IP address?). If DNS is working, then investigate potential issues with the SMB protocol (used for Windows file sharing) or firewall rules that might be blocking access even *with* a valid connection. Reinstalling drivers or restarting might help, but are less targeted. A virus scan is less likely to be the direct cause.",
            "examTip": "Systematically troubleshoot network share access: verify permissions, server availability, basic connectivity (ping by IP), DNS resolution (ping by name), and then investigate protocol-specific issues (SMB) or firewalls."
        },
        {
            "id": 95,
            "question":"What is 'credential stuffing' in the context of cybersecurity?",
            "options":[
              "A type of phishing attack.",
                "Using stolen usernames and passwords (often obtained from data breaches) to try to gain access to other accounts, assuming users reuse credentials across multiple sites.",
                "A type of denial-of-service attack.",
                "A type of malware that encrypts files."
            ],
            "correctAnswerIndex": 1,
            "explanation": "Credential stuffing exploits the common (but bad) practice of password reuse. Attackers take lists of compromised credentials (from data breaches) and try them on other websites, hoping users have used the same username and password combination. It's not phishing itself (though phishing can *lead* to credential theft), a DoS attack, or malware.",
            "examTip": "Never reuse passwords across different accounts; this is the primary vulnerability exploited by credential stuffing attacks. Use a password manager."
        },
         {
            "id": 96,
            "question": "You are using the `netstat` command in Windows. What does the `-b` switch do?",
            "options":[
               "Displays all active connections.",
               "Displays listening ports.",
                "Displays the executable involved in creating each connection or listening port.",
                "Displays numerical addresses instead of resolving hostnames."
            ],
            "correctAnswerIndex": 2,
            "explanation": "The `-b` switch with `netstat` (requires running as administrator) shows the *executable name* (the program) associated with each connection or listening port. This is extremely helpful for identifying the process responsible for network activity. `-a` shows all connections, `-l` (on Linux) shows listening ports, and `-n` shows numerical addresses.",
            "examTip": "Use `netstat -b` (as administrator) in Windows to identify the program responsible for specific network connections or listening ports."
        },
        {
            "id": 97,
            "question": "You need to securely erase data from an SSD (Solid State Drive) before disposing of it. Which method is MOST effective and appropriate for SSDs?",
            "options":[
               "Formatting the drive.",
               "Using the operating system's built-in secure erase function (if available) or the SSD manufacturer's secure erase utility, which utilizes the ATA Secure Erase command.",
                "Using a disk wiping utility that overwrites the data multiple times with random data.",
                "Physically destroying the drive."
            ],
            "correctAnswerIndex": 1, // 3 also works
            "explanation": "SSDs use different technology than HDDs, and traditional overwriting methods are *less effective* and can *reduce the lifespan* of the SSD. The BEST approach is to use the manufacturer's secure erase utility, which typically utilizes the ATA Secure Erase command built into the SSD's firmware. This command instructs the SSD controller to electronically erase all data blocks, making data recovery virtually impossible. Formatting is insufficient. Overwriting *can* work, but is less efficient and potentially harmful to the SSD. Physical destruction *always* works, but is often unnecessary if secure erase is available.",
            "examTip": "Use the SSD manufacturer's secure erase utility (or the operating system's built-in tool, if available) to securely erase data from an SSD; avoid traditional overwriting methods."
        },
         {
            "id": 98,
            "question": "A user reports that their computer is making a loud, grinding noise. What is the MOST likely cause?",
            "options":[
               "A failing cooling fan.",
              "A failing hard drive (if it's a traditional HDD).",
                "A failing power supply.",
                "A failing RAM module."
            ],
            "correctAnswerIndex": 1,
            "explanation": "A grinding noise is *most often* associated with a failing hard drive (specifically, a traditional mechanical HDD with moving parts). Failing fans usually make more of a buzzing, clicking, or whirring sound. Power supplies can make buzzing or whining noises. RAM failures typically don't produce *audible* noise.",
            "examTip": "A grinding noise from a computer is a serious warning sign; immediately back up any important data and suspect a failing hard drive (if it's an HDD)."
        },
        {
            "id": 99,
            "question": "You are configuring a server and want to implement RAID for data redundancy and performance. You have four identical hard drives. Which RAID level would provide BOTH redundancy and increased performance?",
            "options":[
               "RAID 0",
                "RAID 1",
                "RAID 5",
                "RAID 10"
            ],
            "correctAnswerIndex": 3, //RAID 5 is also correct
            "explanation": "RAID 10 (a combination of RAID 1 mirroring and RAID 0 striping) provides *both* redundancy (data is mirrored) and increased performance (data is striped across multiple drives). RAID 0 provides performance but *no* redundancy. RAID 1 provides redundancy but *no* performance increase. RAID 5 is correct as it provides both.",
            "examTip": "Understand the different RAID levels and their trade-offs between redundancy, performance, and cost."
        },
        {
            "id": 100,
            "question": "You are analyzing a system that you suspect is infected with malware. You want to see which programs are configured to start automatically when Windows boots. You've already checked Task Manager's Startup tab and the `msconfig` Startup tab. Where else should you check for autostart locations?",
            "options":[
               "The Windows Registry (specifically, the Run, RunOnce, RunServices, and RunServicesOnce keys under HKEY_LOCAL_MACHINE and HKEY_CURRENT_USER), and the Scheduled Tasks.",
               "The 'Program Files' folder.",
                "The 'Windows' folder.",
                "The user's 'Documents' folder."
            ],
            "correctAnswerIndex": 0,
            "explanation": "Malware often uses various registry keys and scheduled tasks to ensure it starts automatically. The `Run`, `RunOnce`, `RunServices`, and `RunServicesOnce` keys in both `HKEY_LOCAL_MACHINE` (system-wide) and `HKEY_CURRENT_USER` (user-specific) are common autostart locations. Scheduled Tasks can also be used to launch programs at boot or at specific times. The other folders listed are not typical *automatic* startup locations (though malware *might* place files there).",
            "examTip": "Thoroughly investigate autostart locations (Task Manager, msconfig, Registry Run keys, Scheduled Tasks) when hunting for malware or troubleshooting startup problems. Tools like Autoruns (from Sysinternals) can help."
        }
  ]
}
