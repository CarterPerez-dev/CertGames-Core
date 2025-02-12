{
  "category": "aplus2",
  "testId": 7,
  "testName": "Practice Test #7 (Challenging)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A user reports intermittent network connectivity problems. They can sometimes access websites, but the connection frequently drops. `ping` tests to the default gateway are consistently successful, but `ping` tests to external websites are intermittent.  `nslookup` resolves domain names correctly *most* of the time, but occasionally fails. What is the MOST likely cause?",
      "options": [
        "A faulty network cable.",
        "An intermittent problem with the user's configured DNS server, or packet loss/latency issues between the user's computer and the DNS server.",
        "The user's web browser is corrupted.",
        "The user's computer has a virus."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Intermittent `nslookup` failures, combined with intermittent website access while local connectivity (ping to gateway) is stable, strongly suggests a problem with the *reliability* of the DNS resolution process. This could be due to an issue with the configured DNS server itself (intermittent outages, high load) or network problems (packet loss, high latency) *between* the user's computer and the DNS server. A faulty cable would likely cause more consistent problems. A browser issue or virus is less likely to cause intermittent *DNS resolution* failures.",
      "examTip": "When troubleshooting intermittent network issues, carefully analyze the consistency of DNS resolution; intermittent `nslookup` failures point to DNS server or network path problems."
    },
    {
      "id": 2,
      "question": "You are investigating a suspected malware infection on a Windows workstation. You need to examine the system's registry for unusual or unauthorized autostart entries. Which command-line tool provides the MOST comprehensive and flexible way to search the registry for specific values or keys?",
      "options": [
        "regedit.exe",
        "reg query",
        "msconfig.exe",
        "tasklist"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`reg query` is a powerful command-line tool for searching and retrieving registry data.  It allows you to specify search keys, value names, data types, and recursion options. `regedit.exe` is a graphical editor, better for browsing and manual editing, but less efficient for *searching*. `msconfig.exe` manages startup *programs*, but doesn't provide general registry searching. `tasklist` shows running processes.",
      "examTip": "Learn to use `reg query` for efficient and flexible searching of the Windows registry from the command line."
    },
    {
      "id": 3,
      "question": "A user reports that their Windows computer is extremely slow to boot. You've already disabled unnecessary startup programs and checked for malware. Using the Windows Performance Recorder (WPR), you identify a specific driver that is taking an unusually long time to load during the boot process. What is the BEST approach to address this?",
      "options": [
        "Reinstall the operating system.",
        "Roll back the driver to a previous version (if available), and if that doesn't work, try updating to the *latest* driver from the *manufacturer's* website (not just relying on Windows Update). If the problem persists, consider contacting the device manufacturer for support.",
        "Disable the device in Device Manager.",
        "Run `chkdsk`."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A methodical approach to driver problems involves trying a rollback (if a previous version worked), then trying the *manufacturer's* latest driver (which might have fixes not yet in Windows Update), and finally, if the issue persists, contacting the manufacturer. Reinstalling the OS is too drastic. Disabling the device might resolve the boot issue but disables the device's functionality. `chkdsk` checks for disk errors, not driver loading times.",
      "examTip": "When troubleshooting driver-related performance problems, consider rollback, updating (from the manufacturer), and contacting the manufacturer for support."
    },
    {
      "id": 4,
      "question": "You are troubleshooting a network connectivity issue where users cannot access a specific internal web server. You can ping the server's IP address from the affected computers, but you cannot access the web server in a browser. `nslookup` resolves the server's hostname correctly. What is the NEXT step to investigate?",
      "options": [
        "Check the DNS server configuration.",
        "Check if the web server's service (e.g., IIS, Apache) is running and listening on the correct port (typically 80 or 443). Use `netstat -ano` on the *server* to verify.",
        "Reinstall the network adapter driver on the affected computers.",
        "Restart the affected computers."
      ],
      "correctAnswerIndex": 1,
      "explanation": "If you can ping the server by IP *and* DNS resolves correctly, the problem is likely with the *web server service itself* (e.g., IIS, Apache) or a firewall blocking access to the specific port (80 for HTTP, 443 for HTTPS). Checking if the service is running and listening on the correct port *on the server* is the next logical step. DNS is already ruled out. Driver reinstallation or restarting clients are less likely to be helpful at this point.",
      "examTip": "When troubleshooting web server access issues, verify that the web server service is running and listening on the correct port *on the server itself*."
    },
    {
      "id": 5,
      "question": "You are configuring a Linux server and need to set up a cron job to run a script called `backup.sh` every day at 3:00 AM. Which of the following `crontab` entries would accomplish this?",
      "options": [
        "`0 3 * * * /path/to/backup.sh`",
        "`3 0 * * * /path/to/backup.sh`",
        "`* * * * * /path/to/backup.sh`",
        "`0 3 * * 0 /path/to/backup.sh`"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The correct `crontab` entry format is: `minute hour day_of_month month day_of_week command`. `0 3 * * *` means: minute 0, hour 3 (3:00 AM), every day of the month, every month, every day of the week. Option B has the hour and minute reversed. Option C runs every minute. Option D runs only on Sundays.",
      "examTip": "Understand the `crontab` entry format: minute, hour, day of month, month, day of week, command."
    },
        {
      "id": 6,
      "question": "A user reports that they are receiving bounce-back messages (delivery status notifications) for emails they did not send, and their sent items folder shows emails they don't recognize.  What is the MOST likely cause, and what IMMEDIATE actions should you take?",
      "options": [
        "The user's email client is misconfigured; reconfigure it.",
        "The user's email account has been compromised; immediately change the password, enable multi-factor authentication (if available), and scan the user's computer for malware.",
        "The recipient's email server is rejecting the user's emails; contact the recipient's IT support.",
        "The user's internet connection is unstable; troubleshoot the connection."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Bounce-backs for unsent emails, and unfamiliar emails in the sent items folder, are strong indicators of account compromise. Immediate action should be taken: change the password, enable MFA (if possible) to prevent further unauthorized access, and scan for malware that might have stolen the credentials. A misconfigured client wouldn't cause *fake* bounce-backs. A recipient server issue wouldn't explain the unfamiliar sent items. An unstable connection wouldn't cause fake bounce-backs.",
      "examTip": "Treat receiving bounce-backs for unsent emails as a critical security incident; assume account compromise and take immediate action to secure the account."
    },
    {
      "id": 7,
      "question":"A user reports that their Windows computer is exhibiting slow performance. Task Manager shows high CPU utilization, and Resource Monitor indicates that the `svchost.exe` process is consuming a significant amount of CPU. You need to determine which specific *service* hosted within `svchost.exe` is causing the high CPU usage. What is the BEST way to do this?",
      "options":[
        "End the `svchost.exe` process in Task Manager.",
        "Use Resource Monitor's CPU tab, expand the 'Services' section, and look for the service(s) associated with the specific `svchost.exe` instance that is consuming high CPU. You can also use the command `tasklist /svc` to see which services are hosted by each `svchost.exe` process.",
        "Run a full system scan with antivirus software.",
        "Reinstall the operating system."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`svchost.exe` is a generic host process for Windows services. Multiple services run within a single `svchost.exe` instance. Resource Monitor allows you to see which *specific* service is associated with each `svchost.exe` and its resource usage. The command `tasklist /svc` also provides this information. Ending the process directly can cause instability. Antivirus is a good general step, but less targeted. Reinstalling the OS is too drastic.",
      "examTip": "Use Resource Monitor or `tasklist /svc` to identify the specific service running within `svchost.exe` that is causing high resource utilization."
    },
     {
        "id": 8,
        "question": "You are configuring a SOHO router and need to forward incoming traffic on port 25 (SMTP) to an internal mail server with the private IP address 192.168.1.50. However, you also need to forward incoming traffic on port 80 (HTTP) to a *different* internal web server with the private IP address 192.168.1.60. How would you configure this on the router?",
        "options":[
          "Enable DMZ and set the DMZ host to 192.168.1.50.",
          "Configure port forwarding: forward external port 25 to internal IP 192.168.1.50, port 25, and forward external port 80 to internal IP 192.168.1.60, port 80.",
          "Configure port forwarding: forward external port 25 to internal IP 192.168.1.50, port 80, and forward external port 80 to internal IP 192.168.1.60, port 25.",
          "Enable UPnP (Universal Plug and Play)."
        ],
        "correctAnswerIndex": 1,
        "explanation": "You need to create *two separate* port forwarding rules: one for port 25 (SMTP) to the mail server (192.168.1.50:25), and another for port 80 (HTTP) to the web server (192.168.1.60:80). DMZ exposes a *single* host entirely, which is a security risk. Option C has the port mappings incorrect. UPnP can automate this, but it's often a security risk.",
        "examTip": "Understand how to configure multiple port forwarding rules on a router to direct traffic to different internal servers based on the external port."
    },
    {
        "id": 9,
        "question": "A user reports that their previously working external hard drive is no longer recognized by their Windows computer. The drive does not appear in File Explorer or Disk Management. You've tried different USB ports and cables, with no success. What is the NEXT step to investigate?",
        "options":[
          "Reinstall the operating system.",
           "Check if the drive is detected in the BIOS/UEFI settings of the computer. If not, the drive itself (or its enclosure's controller) has likely failed.",
            "Run `chkdsk`.",
            "Format the drive."
        ],
        "correctAnswerIndex": 1,
        "explanation": "If the drive isn't detected in the BIOS/UEFI, it indicates a problem with the drive itself (hardware failure) or its enclosure (if it's an external drive). The operating system can't see a drive that the BIOS/UEFI doesn't detect. Reinstalling the OS is pointless. `chkdsk` and formatting require the drive to be *recognized* first.",
        "examTip": "If a storage device is not recognized by the operating system, check if it's detected in the BIOS/UEFI settings; this helps differentiate between a software/driver problem and a hardware failure."
    },
     {
        "id": 10,
        "question": "You are troubleshooting a network connectivity issue on a Linux server. You need to view the current routing table to understand how network traffic is being directed. Which command would you use?",
        "options":[
           "ifconfig",
            "ip addr show",
            "route -n (or `ip route show`)",
            "netstat -i"
        ],
        "correctAnswerIndex": 2,
        "explanation": "`route -n` (or the newer `ip route show`) displays the routing table, showing which networks are reachable through which interfaces and gateways. `ifconfig` and `ip addr show` display interface configuration. `netstat -i` shows interface statistics.",
        "examTip": "Use `route -n` (or `ip route show`) on Linux to view the routing table and understand how network traffic is being routed."
    },
    {
        "id": 11,
        "question":"You have a Windows system with multiple hard drives. You want to combine two of these drives into a single, larger volume without losing any data. Which Windows feature would allow you to do this, assuming the drives are *dynamic* disks?",
        "options": [
            "Disk Defragmenter",
            "Disk Cleanup",
           "Spanned Volume (in Disk Management)",
            "RAID 0"
        ],
        "correctAnswerIndex": 2,
        "explanation": "A *spanned* volume (created in Disk Management) allows you to combine the space from multiple *dynamic* disks into a single logical volume. This does *not* provide redundancy, but it allows you to use the combined space. Disk Defragmenter optimizes file layout. Disk Cleanup removes files. RAID 0 *stripes* data across drives for performance, but it *does not* preserve existing data on those drives (creating a RAID 0 array typically requires wiping the drives).",
        "examTip": "Use spanned volumes in Windows (on *dynamic* disks) to combine the space from multiple physical disks into a single logical volume *without* data loss (but also *without* redundancy)."
    },
    {
        "id": 12,
        "question": "A user's computer is experiencing frequent BSOD (Blue Screen of Death) errors. You've checked for overheating and run Windows Memory Diagnostic (which found no errors). You suspect a driver problem. What is the NEXT BEST step to investigate and potentially isolate the faulty driver?",
        "options":[
           "Reinstall the operating system.",
            "Use Driver Verifier (verifier.exe) to stress-test drivers and identify potential issues.",
            "Run System Restore.",
            "Run `chkdsk`."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Driver Verifier is a built-in Windows tool that puts extra stress on drivers, making it more likely to expose problems that might not be apparent under normal use.  This can help identify unstable or buggy drivers that are causing BSODs. Reinstalling the OS is too drastic. System Restore might help, but Driver Verifier is more targeted. `chkdsk` checks for disk errors.",
        "examTip": "Use Driver Verifier to help diagnose BSODs caused by faulty drivers; be aware that it can make the system unstable, so use it with caution and have a way to disable it (e.g., Safe Mode)."
    },
     {
        "id": 13,
        "question":"A user reports they are unable to access a specific network share. You've verified the user has the correct permissions, the file server is online, other users can access the share, DNS resolves correctly, and the user can ping the server by IP and hostname. What is a *less common*, but still possible, cause you should investigate?",
        "options":[
           "The user's network cable is faulty.",
            "SMB (Server Message Block) signing mismatch or incompatibility between the client and server.",
            "The user's account is locked out.",
            "The file server is out of disk space."
        ],
        "correctAnswerIndex": 1,
        "explanation": "SMB signing is a security feature that helps prevent man-in-the-middle attacks.  If there's a mismatch in SMB signing settings (e.g., the server *requires* it, but the client doesn't support it, or vice-versa), it can prevent access to network shares, even with correct permissions and connectivity. A faulty cable is less likely if *other* network functions work. An account lockout usually prevents *login*, not access after login.  Server disk space would likely affect *all* users.",
        "examTip": "Be aware of SMB signing and potential compatibility issues, especially in mixed Windows environments; it can cause access problems to network shares even when other factors seem correct."
    },
    {
        "id": 14,
        "question":"You are analyzing network traffic with Wireshark and notice a large number of TCP packets with the RST (reset) flag set. What does this typically indicate?",
        "options":[
           "Normal TCP connection establishment.",
            "An abrupt termination of a TCP connection, often due to an error or a refusal to connect.",
            "Successful file transfer.",
            "Encrypted communication."
        ],
        "correctAnswerIndex": 1,
        "explanation": "The RST (reset) flag in a TCP packet indicates an immediate termination of the connection.  This can happen for various reasons, including a connection attempt to a closed port, a problem with the connection, or a deliberate refusal to connect. It's *not* part of normal connection establishment (SYN, SYN-ACK, ACK) or file transfer. Encryption doesn't inherently involve RST packets.",
        "examTip": "A high number of TCP RST packets in Wireshark can indicate connection problems, port scanning, or application-level issues."
    },
    {
        "id": 15,
        "question": "A user reports they are unable to access any websites. They have a valid IP address, can ping their default gateway, and can ping external IP addresses (like 8.8.8.8), but `ping <domain_name>` fails for all websites. `nslookup` also fails to resolve any domain names. What is the MOST likely cause?",
        "options":[
           "The user's web browser is corrupted.",
          "The user's configured DNS servers are unreachable or malfunctioning.",
            "The user's network cable is faulty.",
            "The user's computer has a virus."
        ],
        "correctAnswerIndex": 1,
        "explanation": "If the user can ping external IP addresses but *all* DNS resolution (`ping <domain_name>` and `nslookup`) fails, the problem is almost certainly with the *configured DNS servers* themselves (they might be down, unreachable, or misconfigured). A corrupted browser is less likely to cause *system-wide* DNS failures. A cable problem would likely prevent *all* network access. A virus *could* interfere with DNS, but unreachable DNS servers are the *most direct* cause.",
        "examTip": "When troubleshooting internet access problems where you can ping IP addresses but not domain names, focus on the DNS server configuration and reachability."
    },
        {
            "id": 16,
            "question": "Which of the following is an example of 'defense in depth' in cybersecurity?",
            "options":[
               "Using a strong password for your email account.",
                "Implementing multiple layers of security controls (e.g., firewall, antivirus, intrusion detection system, strong passwords, user training) so that if one layer fails, others are still in place to protect the system.",
                "Regularly backing up your data.",
                "Keeping your software up-to-date."
            ],
            "correctAnswerIndex": 1,
            "explanation": "Defense in depth is a security strategy that uses multiple, overlapping layers of security. This way, if one control is bypassed or fails, other controls are still in place to prevent or mitigate an attack. Strong passwords, backups, and updates are *part* of defense in depth, but they don't represent the *entire* concept.",
            "examTip": "Implement a defense-in-depth strategy; don't rely on a single security control to protect your systems and data."
        },
        {
           "id": 17,
           "question":"You are using the `netstat` command in Windows.  You want to see all active TCP connections, the owning process ID for each connection, *and* the numerical form of addresses and ports (without resolving hostnames).  Which command would you use?",
           "options":[
            "netstat -a",
            "netstat -b",
            "netstat -ano",
            "netstat -o"
           ],
           "correctAnswerIndex": 2,
           "explanation": "`netstat -ano` provides all the required information: `-a` shows all connections, `-n` shows numerical addresses and ports, and `-o` displays the owning process ID. `-b` shows the executable name (requires administrator privileges), but not *numerical* addresses.",
           "examTip": "Memorize the common `netstat` switches: `-a` (all), `-n` (numerical), `-o` (process ID), `-b` (executable name), `-l` (listening - Linux)."
        },
		 {
            "id": 18,
            "question": "You are configuring a new Linux server. You want to ensure that the system clock is automatically synchronized with a reliable time source. You decide to use the NTP (Network Time Protocol) service. Which configuration file would you typically edit to specify the NTP servers to use?",
            "options":[
               "/etc/hosts",
                "/etc/ntp.conf (or /etc/chrony.conf on some newer systems)",
                "/etc/resolv.conf",
                "/etc/network/interfaces"
            ],
            "correctAnswerIndex": 1,
            "explanation": "The NTP configuration file is typically `/etc/ntp.conf` (though some newer systems use `chrony` and `/etc/chrony.conf`). This file specifies the NTP servers to synchronize with. `/etc/hosts` is for static hostname-to-IP mappings, `/etc/resolv.conf` is for DNS server configuration, and `/etc/network/interfaces` is for network interface configuration (though this can *vary* by distribution).",
            "examTip": "Configure NTP (or chrony) on Linux servers to ensure accurate timekeeping; edit the `/etc/ntp.conf` (or `/etc/chrony.conf`) file to specify the NTP servers."
        },
        {
            "id": 19,
            "question":"What is the purpose of a 'security baseline' in system configuration?",
            "options":[
             "To provide a minimum level of security that all systems must meet, ensuring a consistent and secure configuration across the organization.",
                "To track changes made to a system's configuration.",
                "To encrypt sensitive data on a system.",
                "To monitor system performance."
            ],
            "correctAnswerIndex": 0,
            "explanation": "A security baseline defines a standard, secure configuration for systems. This ensures consistency and helps prevent misconfigurations that could create vulnerabilities. It's not just about tracking changes (though that's *part* of configuration management), encrypting data, or monitoring performance.",
            "examTip": "Establish security baselines for your systems to ensure a consistent and secure configuration; regularly review and update these baselines."
        },
        {
            "id": 20,
            "question": "You are troubleshooting a network connectivity issue and suspect a problem with a specific router along the path to a destination. You use the `tracert` command, and the output shows a series of asterisks (*) for one particular hop. What does this indicate?",
            "options":[
                "The destination server is down.",
                "Your computer's network adapter is faulty.",
               "The router at that hop is not responding to the ICMP echo requests (pings) used by `tracert`, or there's a firewall blocking the responses. It doesn't necessarily mean the router is *down*, just that it's not providing the information `tracert` needs.",
                "Your DNS server is slow."
            ],
            "correctAnswerIndex": 2,
            "explanation": "Asterisks (*) in `tracert` output mean that the router at that hop did *not* respond to the ICMP echo requests (or the responses were blocked). This could be due to firewall rules, router configuration, or network congestion. It doesn't necessarily mean the router is *completely* down, just that it's not providing the information `tracert` expects. The destination server being down or local issues (adapter, DNS) are less likely.",
            "examTip": "Asterisks (*) in `tracert` output indicate a hop that is not responding to ICMP requests; this could be due to firewall rules, router configuration, or network issues."
        },
        {
            "id": 21,
            "question": "A user reports that every time they restart their Windows computer, a specific unwanted program automatically starts, even though they have removed it from the Startup folder in Task Manager and from the Startup tab in msconfig. Where else should you check for autostart entries?",
            "options":[
               "The user's Documents folder.",
                "The Windows Registry (specifically Run, RunOnce keys in HKLM and HKCU), Scheduled Tasks, and Services.",
                "The Program Files folder.",
                "The Control Panel."
            ],
            "correctAnswerIndex": 1,
            "explanation": "Besides Task Manager and msconfig, programs can be configured to autostart through the Windows Registry (Run, RunOnce, RunServices, RunServicesOnce keys under HKEY_LOCAL_MACHINE and HKEY_CURRENT_USER), Scheduled Tasks, and as Windows Services. These are common locations for malware to persist. The other options are less relevant for *automatic* startup.",
            "examTip": "Thoroughly investigate *all* potential autostart locations in Windows (Task Manager, msconfig, Registry Run keys, Scheduled Tasks, Services) when troubleshooting unwanted startup programs or hunting for malware."
        },
         {
            "id": 22,
            "question": "You are using Wireshark to analyze network traffic. You want to filter the displayed packets to show only traffic to or from a specific IP address (e.g., 192.168.1.100). Which Wireshark display filter would you use?",
            "options":[
              "`ip.addr == 192.168.1.100`",
              "`tcp.port == 80`",
              "`http`",
              "`icmp`"
            ],
            "correctAnswerIndex": 0,
            "explanation": "`ip.addr == 192.168.1.100` is the correct Wireshark display filter to show only packets where the source *or* destination IP address is 192.168.1.100. `tcp.port == 80` filters for traffic on port 80, `http` filters for HTTP traffic, and `icmp` filters for ICMP traffic.",
            "examTip": "Learn the basic Wireshark display filter syntax; it's essential for analyzing captured network traffic effectively. `ip.addr`, `tcp.port`, `udp.port`, and protocol names (http, dns, etc.) are common filters."
        },
        {
            "id": 23,
            "question": "You are configuring a Linux server and want to limit the amount of disk space that a particular user can use. Which feature would you use?",
            "options":[
              "File permissions",
              "Disk quotas",
              "SELinux",
              "AppArmor"
            ],
            "correctAnswerIndex": 1,
            "explanation": "Disk quotas allow you to restrict the amount of disk space and the number of files (inodes) that a user or group can consume. File permissions control *access* to files, not overall space usage. SELinux and AppArmor are mandatory access control systems that enhance security, but don't directly manage disk quotas.",
            "examTip": "Use disk quotas on Linux systems to prevent users from consuming excessive disk space."
        },
        {
            "id": 24,
            "question":"You suspect that a user's computer might be part of a botnet. What is a botnet?",
            "options":[
               "A network of compromised computers (bots) controlled by a remote attacker, often used for malicious purposes like sending spam, launching DDoS attacks, or stealing data.",
                "A type of antivirus software.",
                "A type of firewall.",
                "A secure way to connect to the internet."
            ],
            "correctAnswerIndex": 0,
            "explanation": "A botnet is a network of compromised computers (often without the owners' knowledge) that are controlled remotely by an attacker. These "bots" can be used for various malicious activities. It's not antivirus, a firewall, or a secure connection method.",
            "examTip": "Be aware of the signs of botnet infection (unusual network activity, slow performance, unexplained outbound connections); keep your security software up-to-date and practice safe browsing habits."
        },
        {
            "id":25,
            "question": "Which of the following is a good practice for securing a Windows computer against malware?",
            "options":[
                "Disable User Account Control (UAC).",
                "Keep your operating system, web browser, and other software up-to-date with the latest security patches, use a reputable antivirus and anti-malware solution, and practice safe browsing habits.",
                "Use the same password for all your accounts.",
                "Download and install software from any website."
            ],
            "correctAnswerIndex": 1,
            "explanation": "A multi-faceted approach is best: updates patch vulnerabilities, antivirus/anti-malware detects and removes threats, and safe browsing minimizes exposure. Disabling UAC, reusing passwords, and downloading from untrusted sources are all *bad* practices.",
            "examTip": "Security is a layered approach: updates, antivirus, safe browsing, and strong passwords all work together to protect your system."
        },
        {
            "id": 26,
            "question": "You are troubleshooting a network connectivity issue. You use the `ping` command to test connectivity to a remote host, and you receive the response 'Destination host unreachable.' What does this indicate?",
            "options":[
              "The remote host is up and running, but there is a firewall blocking the connection.",
                "The remote host is down, or there is no route to the destination network from your computer or from an intermediate router.",
                "Your DNS server is not working.",
                "Your network adapter is disabled."
            ],
            "correctAnswerIndex": 1,
            "explanation": "'Destination host unreachable' means that your computer (or a router along the path) doesn't know *how to reach* the destination network. It's a routing problem, not necessarily that the *host itself* is down (though that's *possible*). A firewall might block *specific* traffic, but 'unreachable' implies a more fundamental routing issue. DNS is for name resolution, not routing. A disabled adapter would prevent *all* network communication.",
            "examTip": "Understand the different `ping` responses: 'Request timed out' means the host didn't respond within a time limit; 'Destination host unreachable' means there's no route to the destination."
        },
        {
            "id": 27,
            "question": "You are using the `nslookup` command to troubleshoot DNS resolution. You want to specifically query a particular DNS server (e.g., Google's public DNS server at 8.8.8.8) for the IP address of a domain name (e.g., google.com). Which command would you use?",
            "options":[
              "`nslookup google.com`",
              "`nslookup google.com 8.8.8.8`",
              "`nslookup 8.8.8.8 google.com`",
              "`ping google.com`"
            ],
            "correctAnswerIndex": 1,
            "explanation": "`nslookup <domain_name> <dns_server>` is the correct syntax.  The first argument is the domain name to resolve, and the *second* (optional) argument is the DNS server to query.  If you omit the second argument, `nslookup` uses your default configured DNS server.",
            "examTip": "Use `nslookup <domain_name> <dns_server>` to query a specific DNS server for troubleshooting or testing."
        },
        {
            "id": 28,
            "question":"What is 'cross-site scripting' (XSS)?",
            "options":[
               "A type of denial-of-service attack.",
              "A type of web application vulnerability that allows attackers to inject malicious client-side scripts into web pages viewed by other users.",
                "A type of malware that encrypts files.",
                "A type of social engineering attack."
            ],
            "correctAnswerIndex": 1,
            "explanation": "XSS involves injecting malicious scripts into websites. When other users visit the compromised website, their browsers execute the malicious script, potentially allowing the attacker to steal cookies, session tokens, or redirect the user to a phishing site. It's not a DoS attack, malware that encrypts files, or social engineering *directly* (though it can be *used* as part of a social engineering attack).",
            "examTip": "Web developers must properly sanitize user input to prevent XSS vulnerabilities; users should be cautious about clicking on links from untrusted sources."
        },
            {
        "id": 29,
        "question":"You are configuring a firewall and want to implement the principle of least privilege. Which approach is BEST?",
        "options":[
            "Allow all traffic by default.",
           "Block all traffic by default and then create rules to explicitly allow only the necessary traffic.",
            "Allow all inbound traffic and block all outbound traffic.",
            "Allow all outbound traffic and block all inbound traffic."
        ],
        "correctAnswerIndex": 1,
        "explanation": "The principle of least privilege dictates that you should only grant the *minimum* necessary access. For firewalls, this translates to a 'default deny' approach: block everything by default and then create specific rules to *allow* only the required traffic. Allowing all traffic by default is the *opposite* of least privilege. The other options are too restrictive and impractical.",
        "examTip": "Always configure firewalls with a 'default deny' policy; this is a fundamental security best practice."
    },
    {
        "id": 30,
        "question": "A user reports that their Windows computer is randomly freezing, and they have to perform a hard reset. You've already checked for overheating, run Windows Memory Diagnostic (which found no errors), and run a full system scan with antivirus software (which found no threats). You suspect a hardware problem. What is the NEXT component you should investigate?",
        "options":[
            "The keyboard.",
           "The motherboard (checking for bulging/leaking capacitors, BIOS issues) or a failing hard drive (even if it's an SSD).",
            "The monitor.",
            "The network cable."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Random freezes, especially after ruling out overheating, RAM, and malware, often point to motherboard issues (capacitor plague, BIOS problems) or a failing storage device (even SSDs can fail, though they usually don't make grinding noises like HDDs). The keyboard, monitor, and network cable are much less likely to cause *system freezes*.",
        "examTip": "Thoroughly inspect the motherboard for physical damage (bulging/leaking capacitors) and consider potential storage device failures (even SSDs) when troubleshooting random system freezes."
    },
    {
      "id": 31,
      "question":"You are troubleshooting a slow website. Using `tracert`, you identify high latency at a specific hop *before* the final destination (the web server). You contact the ISP responsible for that hop, and they report no issues. What is a LIKELY next step to investigate *further*?",
      "options":[
        "Reinstall your web browser.",
        "Run a virus scan on your computer.",
        "Use a tool like `mtr` (My Traceroute) or `pathping` (Windows) which combines the functionality of `ping` and `tracert`, providing more detailed statistics about packet loss and latency at each hop over an extended period.",
        "Change your DNS server."
      ],
      "correctAnswerIndex": 2,
      "explanation": "If a single `tracert` shows high latency at a hop, but the ISP reports no issues, you need *more data*. Tools like `mtr` (Linux) and `pathping` (Windows) perform repeated tests over time, providing statistics on packet loss and latency *at each hop*. This can reveal intermittent problems or congestion that a single `tracert` might miss. Reinstalling the browser, running a virus scan, or changing DNS are less likely to be helpful *after* you've already identified a specific hop with high latency.",
      "examTip":"Use `mtr` (Linux) or `pathping` (Windows) for more detailed network path analysis than `tracert` alone; they provide statistics over time, revealing intermittent issues."
    },
    {
        "id": 32,
        "question": "A user reports that they are unable to access a network share. You've verified their permissions, network connectivity, and DNS resolution. The file server is online, and other users can access the share. You suspect an issue with the SMB (Server Message Block) protocol. What Windows command-line tool can you use on the *client* computer to check the status of SMB connections and potentially diagnose the problem?",
        "options":[
          "`ping`",
          "`ipconfig`",
          "`netstat -b` on client, look for connections to the file server.",
          "`tracert`"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Using netstat on the client can help determine what could be the cause of the SMB issue.",
        "examTip": "Use `netstat -b` to track down the SMB issue. "
    },
     {
        "id":33,
        "question": "You are using Wireshark to capture and analyze network traffic. You want to filter the displayed packets to show only traffic using the HTTP protocol. Which Wireshark display filter would you use?",
        "options":[
            "`tcp.port == 80`",
          "`http`",
          "`ip.addr == 192.168.1.1`",
          "`tcp`
        ],
        "correctAnswerIndex": 1, //Both A and B could work
        "explanation": "The simplest and most direct way to filter for HTTP traffic in Wireshark is to use the display filter `http`.  This filter understands the HTTP protocol and will show all HTTP requests and responses. While `tcp.port == 80` would *often* show HTTP traffic (as port 80 is the standard HTTP port), it wouldn't capture HTTP traffic on *other* ports, and it might include *non*-HTTP traffic that happens to use port 80. `ip.addr` filters by IP address, and `tcp` shows all TCP traffic.",
        "examTip": "Use protocol names (http, dns, ftp, ssh, etc.) directly as Wireshark display filters to easily isolate traffic for specific protocols."
    },
     {
        "id": 34,
        "question": "A user reports that their computer is exhibiting unusual behavior, including unexpected pop-ups, slow performance, and changes to their browser's homepage. You suspect a malware infection, but standard antivirus scans are not detecting anything. You decide to use a bootable antivirus rescue disk. Why is this approach often MORE effective than running scans from within the infected operating system?",
        "options":[
            "Bootable rescue disks are faster.",
           "Bootable rescue disks can scan the system *before* the potentially infected operating system loads, allowing them to detect and remove rootkits and other advanced malware that might be hiding from scans run *within* Windows.",
            "Bootable rescue disks have more up-to-date virus definitions.",
            "Bootable rescue disks can repair the operating system."
        ],
        "correctAnswerIndex": 1,
        "explanation": "The key advantage of a bootable rescue disk is that it operates *outside* the potentially compromised operating system. This allows it to bypass any rootkits or other malware that might be actively hiding from scans run *within* Windows. While speed and updated definitions *can* be factors, the *independent operating environment* is the primary benefit.",
        "examTip": "Use a bootable antivirus rescue disk for thorough malware removal, especially when dealing with persistent or advanced threats that evade standard scans."
    },
    {
        "id": 35,
        "question":"What is 'credential harvesting' in the context of cybersecurity?",
        "options":[
           "A type of denial-of-service attack.",
          "The process of gathering usernames, passwords, and other authentication credentials, often through phishing, malware, or data breaches.",
            "A type of encryption.",
            "A type of network protocol."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Credential harvesting is the act of collecting login credentials (usernames, passwords, etc.). Attackers use various methods, including phishing emails, keyloggers, and exploiting data breaches, to gather this information. It's not a DoS attack, encryption, or a network protocol.",
        "examTip": "Protect your credentials fiercely; use strong, unique passwords, enable multi-factor authentication, and be wary of phishing attempts."
    },
		 {
        "id": 36,
        "question": "You are configuring a Linux server and want to schedule a script to run automatically every day at 2:30 AM. Which utility would you use?",
        "options":[
            "at",
           "cron",
            "systemd-run",
            "nohup"
        ],
        "correctAnswerIndex": 1,
        "explanation": "`cron` is the standard utility in Linux for scheduling recurring tasks (cron jobs). `at` is for scheduling a task to run *once* at a specific time. `systemd-run` can be used to run commands as transient systemd units, and `nohup` prevents a command from being terminated when you log out.",
        "examTip": "Use `cron` to schedule recurring tasks on Linux systems; edit the crontab file (using `crontab -e`) to define the schedule and the command to run."
    },
    {
        "id": 37,
        "question": "A user is unable to access a website. You can ping the website's IP address successfully, but `ping <domain_name>` fails. `nslookup <domain_name>` *also* fails. What is the MOST likely cause?",
        "options":[
          "The user's web browser is corrupted.",
            "A DNS resolution problem; either the user's configured DNS servers are unreachable/malfunctioning, or the domain name is not registered or has expired.",
            "The website's server is down.",
            "The user's network cable is faulty."
        ],
        "correctAnswerIndex": 1,
        "explanation": "If you can ping the IP address but *both* `ping <domain_name>` and `nslookup` fail, the problem is *definitely* with DNS resolution. Either the user's configured DNS servers aren't working, or there's a problem with the domain name itself (not registered, expired, etc.). A corrupted browser is less likely to cause *system-wide* DNS failures.  If the *website's server* were down, the IP ping would likely also fail. A cable problem would likely prevent *all* network access.",
        "examTip": "When troubleshooting website access, distinguish between connectivity problems (can you ping the IP?) and DNS resolution problems (can you ping the domain name, and does `nslookup` work?)."
    },
    {
        "id": 38,
        "question":"You are analyzing a system and suspect that a malicious process is hiding itself from standard process listing tools (like Task Manager). Which tool is BEST suited for detecting hidden processes and rootkits?",
        "options":[
           "Task Manager",
            "Resource Monitor",
            "A specialized rootkit detection tool (e.g., GMER, TDSSKiller) or a tool like Process Explorer (from Sysinternals) that provides more advanced process analysis capabilities.",
            "System Information (msinfo32.exe)"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Rootkits often use techniques to hide themselves from standard process listing tools. Specialized rootkit detectors and advanced process analysis tools (like Process Explorer) are designed to uncover these hidden processes. Task Manager and Resource Monitor are less likely to reveal well-hidden rootkits. System Information provides general system details, not specifically hidden process detection.",
        "examTip": "Use specialized rootkit detection tools and advanced process analysis tools (like Process Explorer) to uncover hidden processes and potential rootkit infections."
    },
    {
        "id": 39,
        "question": "A user reports that their computer is displaying an error message stating 'SMART Failure Predicted on Hard Disk.' What does this indicate, and what is the BEST course of action?",
        "options":[
            "The computer's RAM is failing.",
           "The hard drive is reporting potential imminent failure based on its internal SMART (Self-Monitoring, Analysis, and Reporting Technology) diagnostics; immediately back up all data from the drive and replace the drive as soon as possible.",
            "The computer's power supply is failing.",
            "The operating system needs to be reinstalled."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A SMART failure warning indicates that the hard drive's internal diagnostics have detected problems that suggest the drive is likely to fail soon. *Immediate* data backup is critical, followed by replacing the drive. It's not a RAM, power supply, or OS reinstallation issue.",
        "examTip": "Treat SMART failure warnings seriously; back up data immediately and replace the failing hard drive."
    },
    {
        "id": 40,
        "question": "You are troubleshooting a network connectivity issue on a Windows workstation.  The computer has a valid IP address, can ping its default gateway, but can't access *any* websites.  `nslookup` resolves domain names to IP addresses *correctly*. What is the NEXT step to investigate?",
        "options":[
           "Reinstall the network adapter driver.",
            "Check the web browser's proxy settings, the Windows Firewall settings (to ensure the browser is allowed to access the internet), and the 'hosts' file for any incorrect entries.",
            "Restart the computer.",
            "Run a virus scan."
        ],
        "correctAnswerIndex": 1,
        "explanation": "If the computer has a valid IP, can ping the gateway, and DNS resolution is working (confirmed by `nslookup`), the problem is likely with the *browser's* ability to connect to the internet.  Incorrect proxy settings, firewall rules blocking the browser, or entries in the 'hosts' file could cause this. Reinstalling the driver or restarting might help, but are less targeted. A virus *could* be the cause, but the other factors are more directly related to browser connectivity *after* successful DNS resolution.",
        "examTip": "When troubleshooting website access issues where basic connectivity and DNS resolution are working, focus on browser-specific settings (proxy, firewall) and the 'hosts' file."
    },
        {
            "id": 41,
            "question": "You need to determine the version of the Windows operating system running on a remote computer. You have command-line access to the remote system. Which command would provide this information MOST directly?",
            "options":[
                "systeminfo",
                "ver",
                "winver",
                "hostname"
            ],
            "correctAnswerIndex": 2, //ver also works. systeminfo is more robust
            "explanation": "`winver` displays a graphical dialog box showing the Windows version, build number, and registered user. `ver` shows a more basic version string at the command line. Both would work, but `winver` is designed for a GUI, while `ver` works better on the command line. `systeminfo` provides a wealth of system info but `winver` answers the direct question.",
            "examTip": "Use `winver` or `ver` to quickly determine the Windows version from the command line."
        },
         {
            "id": 42,
            "question":"What is 'tailgating' in the context of physical security?",
            "options":[
              "A type of phishing attack.",
                "Following an authorized person into a restricted area without proper authorization.",
                "A type of malware.",
                "A type of network attack."
            ],
            "correctAnswerIndex": 1,
            "explanation": "Tailgating is a physical security breach where someone follows an authorized person through a secured door or entrance without proper credentials or authorization. It's not a phishing attack (which is digital), malware, or a network attack.",
            "examTip": "Be aware of tailgating attempts and enforce strict access control policies to prevent unauthorized physical entry."
        },
        {
           "id":43,
           "question": "Which command in Linux is used to change the ownership of a file or directory?",
           "options":[
            "chmod",
            "chown",
            "chgrp",
            "sudo"
           ],
           "correctAnswerIndex": 1,
           "explanation": "`chown` (change owner) is used to change the user and/or group ownership of files and directories in Linux. `chmod` changes permissions, `chgrp` changes *only* the group ownership, and `sudo` elevates privileges.",
           "examTip": "Use `chown` to change file/directory ownership in Linux; the syntax is typically `chown <new_owner>:<new_group> <file_or_directory>`."
        },
        {
            "id":44,
            "question": "You are setting up a wireless network and want to use WPA2 encryption. You have the choice between WPA2-Personal and WPA2-Enterprise. What is the KEY difference between these two modes?",
            "options":[
             "WPA2-Personal is faster than WPA2-Enterprise.",
                "WPA2-Personal uses a pre-shared key (PSK) for authentication, while WPA2-Enterprise uses 802.1X authentication with a RADIUS server (or similar) for individual user authentication.",
                "WPA2-Enterprise is only for large businesses.",
                "WPA2-Personal is more secure than WPA2-Enterprise."
            ],
            "correctAnswerIndex": 1,
            "explanation": "The main difference is the authentication method. WPA2-Personal (suitable for home or small office) uses a single, shared password (PSK). WPA2-Enterprise (better for larger organizations) uses 802.1X with a RADIUS server (or similar) to authenticate *individual users* with unique credentials. This provides better security and accountability. WPA2-Enterprise is generally *more* secure, not less.",
            "examTip": "Use WPA2-Personal for home networks (with a strong PSK) and WPA2-Enterprise with 802.1X/RADIUS for corporate networks requiring stronger, user-based authentication."
        },
         {
            "id":45,
            "question": "You are troubleshooting a computer and suspect a problem with a specific Windows service. You want to stop the service, then restart it to see if that resolves the issue. Which command-line tools can you use to manage Windows services?",
            "options":[
                "`net start` and `net stop` (or `sc start` and `sc stop`)",
                "`tasklist` and `taskkill`",
                "`ipconfig` and `ping`",
                "`chkdsk` and `sfc`"
            ],
            "correctAnswerIndex": 0,
            "explanation": "The `net start` and `net stop` commands (or the more powerful `sc start` and `sc stop` commands) are used to manage Windows services from the command line. `tasklist` and `taskkill` manage *processes*, not services. `ipconfig` and `ping` are for network troubleshooting. `chkdsk` and `sfc` are for disk and system file checking.",
            "examTip": "Use `net start` and `net stop` (or `sc start` and `sc stop`) to manage Windows services from the command line, or use the Services console (services.msc) for a graphical interface."
        },
        {
            "id":46,
            "question": "Which type of malware often masquerades as legitimate software but performs malicious actions in the background?",
            "options":[
              "Virus",
                "Trojan horse",
                "Worm",
                "Spyware"
            ],
            "correctAnswerIndex": 1,
            "explanation": "A Trojan horse (or simply Trojan) disguises itself as a harmless or desirable program to trick users into installing it. Once installed, it carries out malicious activities without the user's knowledge. Viruses attach to files, worms self-replicate over networks, and spyware gathers information.",
            "examTip":"Be extremely cautious about downloading and installing software from untrusted sources; Trojans often hide within seemingly legitimate programs."
        },
        {
            "id": 47,
            "question": "A user reports that their computer is displaying unusual error messages and behaving erratically. You suspect a problem with the system files. Which Windows command-line tool can you use to scan for and automatically repair corrupted system files?",
            "options":[
              "chkdsk",
              "sfc /scannow",
              "defrag",
              "diskpart"
            ],
            "correctAnswerIndex": 1,
            "explanation": "`sfc /scannow` (System File Checker) scans protected system files and replaces corrupted or missing files with cached copies. `chkdsk` checks for file system *errors* (not necessarily corrupted *files*), `defrag` defragments the hard drive, and `diskpart` manages partitions.",
            "examTip": "Run `sfc /scannow` if you suspect corruption of core Windows system files; it can often resolve system instability issues."
        },
        {
            "id":48,
            "question": "What is the purpose of using a VPN (Virtual Private Network) when connecting to a public Wi-Fi hotspot?",
            "options":[
              "To speed up your internet connection.",
                "To encrypt your internet traffic and protect your data from eavesdropping by others on the same network.",
                "To block access to certain websites.",
                "To prevent viruses from infecting your computer."
            ],
            "correctAnswerIndex": 1,
            "explanation": "A VPN creates a secure, encrypted tunnel for your internet traffic. This is particularly important on public Wi-Fi, where others on the same network could potentially intercept your data. A VPN doesn't inherently speed up connections (it can sometimes slow them down), block websites (though some VPNs offer this as a feature), or *directly* prevent viruses (though it can help by preventing access to malicious sites).",
            "examTip": "Always use a VPN when connecting to public Wi-Fi to protect your privacy and data from eavesdropping."
        },
         {
            "id": 49,
            "question":"You are troubleshooting a network connectivity issue where a computer cannot access any network resources. The computer has an IP address in the 169.254.x.x range. What does this indicate?",
            "options":[
               "The computer has a static IP address configured.",
                "The computer is successfully connected to the network.",
               "The computer is configured to obtain an IP address automatically (DHCP), but it is unable to reach a DHCP server.",
                "The computer has a virus."
            ],
            "correctAnswerIndex": 2,
            "explanation": "An IP address in the 169.254.x.x range is an APIPA (Automatic Private IP Addressing) address. Windows assigns an APIPA address when a computer is set to obtain an IP address automatically (DHCP) but cannot find a DHCP server on the network. It indicates a *failure* to obtain a valid IP address from a DHCP server.  It's not a static IP, successful connection, or necessarily a virus.",
            "examTip": "An APIPA address (169.254.x.x) almost always indicates a DHCP failure; troubleshoot DHCP server availability and network connectivity."
        },
        {
            "id": 50,
            "question":"You are configuring user accounts on a Windows computer. What is the KEY difference between a 'Standard User' account and an 'Administrator' account?",
            "options":[
              "Standard User accounts can only access the internet.",
                "Administrator accounts have full control over the computer and can make system-wide changes (install software, change settings, etc.), while Standard User accounts have limited privileges and cannot make changes that affect other users or the security of the system.",
                "Standard User accounts are for temporary use only.",
                "Administrator accounts are only for IT professionals."
            ],
            "correctAnswerIndex": 1,
            "explanation": "The fundamental difference is the level of *privilege*. Administrators have unrestricted access and can make system-wide changes. Standard users have limited rights, preventing them from installing software, changing critical system settings, or accessing other users' files without permission. This helps protect the system from accidental or malicious damage.",
            "examTip": "Use Standard User accounts for day-to-day tasks; only use Administrator accounts when necessary to make system changes. This follows the principle of least privilege."
        },
         {
            "id": 51,
            "question": "A user reports that their computer is running slowly. You open Task Manager and notice that a process called `explorer.exe` is consuming an unusually high amount of CPU resources. What is `explorer.exe` normally responsible for, and what might be causing the high CPU usage in this case?",
            "options":[
                "`explorer.exe` is a web browser; the user probably has too many tabs open.",
                "`explorer.exe` is the Windows File Explorer and the Windows shell (desktop, taskbar, etc.); high CPU usage could be caused by a corrupted shell extension, a malfunctioning third-party program that integrates with Explorer, or potentially malware.",
                "`explorer.exe` is a system process that cannot be safely terminated; high CPU usage is normal.",
                "`explorer.exe` is a virus; you should immediately delete it."
            ],
            "correctAnswerIndex": 1,
            "explanation": "`explorer.exe` is the core process for the Windows File Explorer (browsing files and folders) *and* the Windows shell (the desktop, taskbar, Start menu, etc.).  High CPU usage by `explorer.exe` is *not* normal and can indicate a problem with a shell extension (a program that adds functionality to Explorer), a corrupted system file, a conflict with another program, or even malware. It's *not* a web browser, and while it's a *critical* system process, high CPU usage is a problem.",
            "examTip": "Troubleshooting high CPU usage by `explorer.exe` often involves checking for corrupted shell extensions, conflicting software, and potential malware.  Tools like ShellExView can help manage shell extensions."
        },
        {
            "id":52,
            "question": "What is the function of the BIOS (Basic Input/Output System) or UEFI (Unified Extensible Firmware Interface) on a computer?",
            "options":[
                "To store user data.",
               "To initialize and test the system hardware during startup (POST - Power-On Self-Test) and to load the boot loader (which then loads the operating system).",
                "To manage network connections.",
                "To provide a graphical user interface for the operating system."
            ],
            "correctAnswerIndex": 1,
            "explanation": "The BIOS/UEFI is firmware (low-level software) stored on a chip on the motherboard. Its primary roles are to initialize the hardware, perform the POST (checking for basic hardware functionality), and then load the boot loader (like BOOTMGR or GRUB) from a storage device, which in turn starts the operating system. It doesn't store user data, manage network connections *directly* (though it *initializes* network adapters), or provide the OS's GUI.",
            "examTip": "The BIOS/UEFI is the *first* code that runs when a computer starts; it's responsible for initializing the hardware and starting the boot process."
        },
        {
           "id": 53,
            "question": "You are configuring a new hard drive in Windows. You have the choice between using MBR (Master Boot Record) and GPT (GUID Partition Table) partitioning schemes. What is a KEY advantage of GPT over MBR?",
            "options":[
               "GPT is compatible with older operating systems.",
                "GPT supports larger hard drives (above 2TB) and more partitions, and it includes features for data integrity and recovery.",
                "MBR is more secure than GPT.",
                "MBR is easier to use than GPT."
            ],
            "correctAnswerIndex": 1,
            "explanation": "GPT is the modern partitioning scheme and overcomes the limitations of MBR. It supports much larger drives (beyond MBR's 2TB limit), allows for a significantly larger number of partitions, and includes features like a protective MBR and CRC checksums for data integrity. MBR is older and has limitations. GPT is generally *more* secure due to its data integrity features.",
            "examTip": "Use GPT for new hard drive installations, especially for drives larger than 2TB or systems with UEFI firmware; MBR is only needed for compatibility with very old systems."
        },
         {
            "id": 54,
            "question": "You are troubleshooting a computer that is not booting. You hear a series of beeps during the POST (Power-On Self-Test). What do these beeps typically indicate?",
            "options":[
              "The computer is successfully booting.",
                "A hardware error has been detected; the specific beep code (pattern of beeps) often corresponds to a particular type of hardware problem (RAM, video card, etc.).",
                "The operating system is loading.",
                "The network connection is established."
            ],
            "correctAnswerIndex": 1,
            "explanation": "Beep codes are diagnostic signals emitted by the BIOS/UEFI during the POST. Different beep patterns indicate different hardware problems.  Consult the motherboard manufacturer's documentation to interpret the specific beep code. It's not a sign of successful booting, OS loading, or network connection.",
            "examTip": "Listen carefully to beep codes during POST; they can provide valuable clues about hardware failures.  Refer to the motherboard manual for the specific beep code meanings."
        },
         {
            "id": 55,
            "question":"What is the 'principle of least privilege' in the context of user account management?",
            "options":[
               "Giving all users administrator access to simplify management.",
              "Granting users only the minimum necessary access rights (permissions) required to perform their job duties, and no more.",
                "Using the strongest possible encryption for all user data.",
                "Regularly auditing user activity."
            ],
            "correctAnswerIndex": 1,
            "explanation": "The principle of least privilege is a fundamental security concept. It minimizes the potential damage from accidents, errors, or malicious activity by limiting user access to only what's essential for their tasks.  Giving everyone administrator access is the *opposite* of least privilege. Encryption and auditing are important, but they don't directly address the *scope* of user access.",
            "examTip": "Always apply the principle of least privilege when creating and managing user accounts; grant only the necessary permissions."
        },
        {
            "id": 56,
            "question": "You are troubleshooting a network connectivity issue.  A computer can ping its default gateway and other devices on the local network, but it cannot access any websites.  `nslookup` resolves domain names to IP addresses correctly. What is the NEXT most likely area to investigate?",
            "options":[
                "The network cable.",
               "The computer's firewall settings, proxy server settings (if applicable), and the 'hosts' file.",
                "The DNS server configuration.",
                "The computer's network adapter driver."
            ],
            "correctAnswerIndex": 1,
            "explanation": "If the computer has basic network connectivity (can ping local devices) and DNS resolution is working (confirmed by `nslookup`), the problem is likely with the *browser's* ability to access the internet. Firewall rules (blocking the browser), incorrect proxy settings, or entries in the 'hosts' file could cause this. A cable problem would likely prevent *all* network access. DNS is already ruled out. A driver problem is less likely if *local* pings work.",
            "examTip": "When troubleshooting website access issues where basic connectivity and DNS resolution are working, focus on browser-specific settings (firewall, proxy, 'hosts' file)."
        },
         {
            "id": 57,
            "question": "What is 'data exfiltration' in the context of cybersecurity?",
            "options":[
             "The process of backing up data.",
               "The unauthorized transfer of data from a computer or network to an external location, often by an attacker.",
                "The encryption of data.",
                "The process of deleting data."
            ],
            "correctAnswerIndex": 1,
            "explanation": "Data exfiltration is the unauthorized removal of data from a system. Attackers might steal sensitive information (customer data, intellectual property, etc.) and transmit it to their own servers. It's not backup, encryption, or deletion (though attackers *might* delete data *after* exfiltrating it).",
            "examTip": "Monitor network traffic for unusual outbound connections and large data transfers; these can be indicators of data exfiltration attempts."
        },
        {
           "id": 58,
           "question": "You are configuring a new Linux server and want to ensure that only specific users are allowed to log in remotely via SSH. Which configuration file would you edit to control SSH access?",
           "options":[
            "/etc/hosts",
            "/etc/passwd",
            "/etc/ssh/sshd_config",
            "/etc/group"
           ],
           "correctAnswerIndex": 2,
           "explanation": "The SSH server configuration file is `/etc/ssh/sshd_config`. This file controls various aspects of SSH server behavior, including allowed users, authentication methods, and port settings. `/etc/hosts` is for static hostname mappings, `/etc/passwd` stores user account information (but doesn't directly control SSH access), and `/etc/group` stores group information.",
           "examTip": "Edit the `/etc/ssh/sshd_config` file to configure SSH server settings on a Linux system, including access control, authentication, and security options."
        },
        {
            "id": 59,
            "question": "You are troubleshooting a computer that is exhibiting slow performance. You open Task Manager and observe that the disk utilization is consistently very high (close to 100%), even when the system is idle. What is the BEST tool to use to identify *which specific files* are being accessed and causing the high disk I/O?",
            "options":[
             "Task Manager",
                "Resource Monitor (specifically the Disk tab)",
                "Performance Monitor",
                "Disk Defragmenter"
            ],
            "correctAnswerIndex": 1,
            "explanation": "Resource Monitor's Disk tab provides detailed information about disk activity, including the *specific files* being read from and written to, along with the processes accessing them. This allows you to pinpoint the source of the high disk I/O. Task Manager shows overall disk utilization, but not file-level detail. Performance Monitor can *track* disk activity, but Resource Monitor is more directly suited for *immediate* troubleshooting of this kind. Disk Defragmenter is for optimizing file layout (and should not be used on SSDs).",
            "examTip": "Use Resource Monitor's Disk tab to identify the specific files and processes responsible for high disk I/O activity."
        },
		{
            "id": 60,
            "question": "What is the purpose of using a 'sandbox' environment in software testing or security analysis?",
            "options":[
                "To provide a high-performance environment for running applications.",
               "To isolate potentially untrusted or malicious code from the main operating system and other applications, allowing it to be run and analyzed safely.",
                "To back up important data.",
                "To encrypt sensitive data."
            ],
            "correctAnswerIndex": 1,
            "explanation": "A sandbox is an isolated environment that restricts the actions of the code running within it. This prevents potentially malicious or buggy code from harming the host system or accessing sensitive data. It's not for performance enhancement, backups, or encryption (though sandboxes *can* be used to test encryption *implementations*).",
            "examTip": "Use sandboxes to test untrusted software, analyze malware, or develop software in a controlled environment, isolating it from your main system."
        },
            {
        "id": 61,
        "question":"You are troubleshooting a Windows computer that is experiencing intermittent problems. You suspect a problem with a device driver. Which Windows utility allows you to enable 'Driver Verifier' to stress-test drivers and identify potential issues?",
        "options":[
            "Device Manager",
           "verifier.exe",
            "msconfig.exe",
            "devmgmt.msc"
        ],
        "correctAnswerIndex": 1,
        "explanation": "`verifier.exe` is the command-line and GUI tool to launch Driver Verifier. Device Manager (`devmgmt.msc`) allows you to manage drivers (update, rollback, disable), but not to enable Driver Verifier. `msconfig.exe` is for system configuration, primarily startup.",
        "examTip": "Use Driver Verifier (`verifier.exe`) to help diagnose driver-related problems, but be aware that it can make the system unstable; have a plan to disable it (e.g., Safe Mode) if necessary."
    },
    {
        "id": 62,
        "question": "A user reports that their computer is making a beeping sound during startup, and the system fails to boot. You suspect a hardware problem. What is the FIRST thing you should do?",
        "options":[
           "Reinstall the operating system.",
            "Consult the motherboard manufacturer's documentation to determine the meaning of the specific beep code (the pattern of beeps).",
            "Replace the hard drive.",
            "Replace the RAM."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Beep codes are diagnostic signals from the BIOS/UEFI. Different beep patterns correspond to different hardware problems. *Before* taking any action (like replacing parts), you need to *identify* the problem indicated by the beep code. The motherboard manual (or the manufacturer's website) will have a table explaining the beep codes.",
        "examTip": "Listen carefully to beep codes during POST and consult the motherboard documentation to interpret their meaning; they provide valuable clues about hardware failures."
    },
    {
        "id": 63,
        "question": "You are configuring a web server and want to ensure that all communication between clients and the server is encrypted. Which protocol should you use?",
        "options":[
           "HTTP",
            "HTTPS",
            "FTP",
            "Telnet"
        ],
        "correctAnswerIndex": 1,
        "explanation": "HTTPS (Hypertext Transfer Protocol Secure) uses SSL/TLS to encrypt communication between a web browser and a web server, protecting data from eavesdropping. HTTP is unencrypted. FTP and Telnet are also unencrypted and should not be used for sensitive data.",
        "examTip": "Always use HTTPS for websites that handle sensitive information (logins, personal data, financial transactions); look for the padlock icon in the browser's address bar."
    },
     {
        "id": 64,
        "question": "You are troubleshooting a network printer that is not printing. You can ping the printer's IP address successfully, and other users can print to it. The user's computer has a valid IP address and network connectivity. What is the NEXT step to investigate?",
        "options":[
            "Check the printer's toner level.",
           "Check the print queue on the user's computer, verify that the correct printer is selected as the default, and check the printer driver on the user's computer.",
            "Restart the printer.",
            "Replace the network cable connecting the printer to the network."
        ],
        "correctAnswerIndex": 1,
        "explanation": "If you can ping the printer and *other* users can print, the problem is likely local to the *user's* computer. Checking the print queue (for stuck jobs), verifying the default printer selection, and checking the driver are logical next steps. Toner level, restarting the printer, or the network cable are less likely to be the issue if *other* users can print.",
        "examTip": "When troubleshooting printing problems where the printer is online and accessible to others, focus on the user's computer's print queue, printer selection, and driver."
    },
    {
        "id": 65,
        "question": "You are using the `ipconfig` command in Windows. What is the purpose of the `/release` and `/renew` switches?",
        "options":[
            "To display detailed network configuration information.",
           "To release the current DHCP-assigned IP address (/release) and request a new IP address from the DHCP server (/renew).",
            "To flush the DNS resolver cache.",
            "To register the computer's hostname with the DNS server."
        ],
        "correctAnswerIndex": 1,
        "explanation": "`ipconfig /release` releases the current IP address obtained from a DHCP server. `ipconfig /renew` then requests a new IP address. These commands are used to troubleshoot DHCP-related connectivity issues. `/all` displays detailed information, `/flushdns` clears the DNS cache, and `/registerdns` (not a standard `ipconfig` switch by itself) can be used with other tools to force DNS registration.",
        "examTip": "Use `ipconfig /release` and `ipconfig /renew` to troubleshoot DHCP problems; releasing and renewing the IP address can often resolve connectivity issues."
    },
    {
        "id": 66,
        "question": "A user reports that they are unable to access files on a network share. You've verified that the file server is online, other users can access the share, and the user has the correct permissions. You suspect a problem with the user's workstation. Which of the following is LEAST likely to be the cause?",
        "options":[
           "The user's computer is not connected to the network.",
            "The user's workstation has a firewall rule blocking access to the file server or the SMB protocol.",
            "There is an SMB protocol version incompatibility or signing mismatch between the client and server.",
            "The user's account is locked out."
        ],
        "correctAnswerIndex": 0, //if it's not connected, most likely, can't troubleshoot other issues
        "explanation": "If the computer wasn't connected to the network, they wouldn't be able to perform other network functions. The other options are common issues, but the question asks for the LEAST likely.",
        "examTip": "When all other issues have been checked, and the user is connected to the network, look at SMB or firewall issues."
    },
    {
        "id":67,
        "question": "You are analyzing network traffic with Wireshark. You see a large number of packets with the SYN flag set, but relatively few corresponding SYN-ACK or ACK packets. What type of network activity does this MOST likely indicate?",
        "options":[
            "Normal web browsing.",
           "A SYN flood attack (a type of denial-of-service attack).",
            "File transfer using FTP.",
            "Email communication."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A SYN flood attack involves sending a flood of SYN (synchronize) packets to a server, attempting to overwhelm it and consume its resources. The attacker doesn't complete the TCP three-way handshake (SYN, SYN-ACK, ACK), leaving many half-open connections. Normal web browsing, FTP, and email involve complete handshakes.",
        "examTip": "A disproportionately large number of SYN packets compared to SYN-ACK and ACK packets is a strong indicator of a SYN flood attack."
    },
    {
        "id": 68,
        "question": "You are troubleshooting a Windows computer that is experiencing performance issues. You open Task Manager and notice that a process named `csrss.exe` is consuming a significant amount of CPU resources. What is `csrss.exe` normally responsible for, and is high CPU usage by this process typically a cause for concern?",
        "options":[
          "`csrss.exe` is a web browser; high CPU usage is normal.",
          "`csrss.exe` (Client Server Runtime Subsystem) is a critical Windows system process involved in console windows, creating/deleting threads, and some aspects of the 16-bit virtual MS-DOS environment; high CPU usage by `csrss.exe` is *usually* a sign of a serious problem (malware, system file corruption, or a hardware issue).",
          "`csrss.exe` is a third-party application; you should uninstall it.",
          "`csrss.exe` is a virus; you should immediately delete it."
        ],
        "correctAnswerIndex": 1,
        "explanation": "`csrss.exe` is a *critical* Windows system process. While it *should* be running, consistently high CPU usage by `csrss.exe` is *abnormal* and often indicates a serious underlying problem. It's not a web browser, a third-party application (normally), or a virus *itself* (though malware *might* try to disguise itself as `csrss.exe`).",
        "examTip": "High CPU usage by the *legitimate* `csrss.exe` process is usually a sign of a serious system problem; investigate thoroughly (malware scans, system file checks, hardware diagnostics)."
    },
    {
        "id": 69,
        "question": "What is the purpose of the `chkdsk` command in Windows?",
        "options":[
           "To defragment the hard drive.",
            "To check the hard drive for file system errors and bad sectors, and optionally attempt to repair them.",
            "To display disk usage information.",
            "To create a new partition."
        ],
        "correctAnswerIndex": 1,
        "explanation": "`chkdsk` (Check Disk) scans the hard drive for logical file system errors (like lost clusters, cross-linked files, directory errors) and physical bad sectors. It can attempt to *repair* errors (`/f` switch) and recover readable information from bad sectors (`/r` switch). It's not for defragmenting, displaying detailed usage, or creating partitions.",
        "examTip": "Run `chkdsk /f` to fix file system errors and `chkdsk /r` to check for and attempt to recover data from bad sectors; run it periodically, especially if you suspect hard drive problems."
    },
    {
        "id": 70,
        "question": "You are configuring a Linux system and want to view the currently mounted file systems, their mount points, and their usage statistics. Which command would you use?",
        "options":[
          "lsblk",
          "df -h",
          "du -sh",
          "mount"
        ],
        "correctAnswerIndex": 1, //Both 1 and 3 can provide this
        "explanation": "`df -h` (disk free) displays information about mounted file systems, including their total size, used space, available space, and mount points. The `-h` option shows the sizes in human-readable format (e.g., KB, MB, GB).  `lsblk` lists block devices. `du -sh` shows disk usage of *directories*, not mounted filesystems. `mount` without arguments will *list* mounted file systems but won't show usage statistics.",
        "examTip": "Use `df -h` on Linux to quickly check disk space usage on mounted file systems."
    },
     {
        "id": 71,
        "question": "Which of the following is a characteristic of a 'distributed denial-of-service' (DDoS) attack?",
        "options":[
            "The attacker steals sensitive data from a server.",
           "The attacker uses multiple compromised computers (a botnet) to flood a target server or network with traffic, making it unavailable to legitimate users.",
            "The attacker encrypts files on a computer and demands a ransom.",
            "The attacker tricks users into revealing their passwords."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A DDoS attack uses a *distributed* network of compromised systems (bots) to overwhelm a target with traffic, causing a denial of service. Data theft is a data breach, encryption is ransomware, and tricking users is social engineering.",
        "examTip": "DDoS attacks are difficult to prevent completely; mitigation strategies often involve using specialized network infrastructure and services to absorb and filter the attack traffic."
    },
    {
        "id": 72,
        "question": "You are troubleshooting a slow Windows computer.  You suspect a problem with the hard drive.  You've already run `chkdsk`, which found and fixed some errors, but the system is still slow.  What is the NEXT BEST step to investigate potential hard drive issues?",
        "options":[
            "Defragment the hard drive (if it's an HDD).",
           "Check the SMART status of the hard drive using a third-party utility or the drive manufacturer's tool.",
            "Run Disk Cleanup.",
            "Reinstall the operating system."
        ],
        "correctAnswerIndex": 1,
        "explanation": "If `chkdsk` found errors, but the system is still slow, checking the SMART (Self-Monitoring, Analysis, and Reporting Technology) status is crucial. SMART data provides insights into the drive's internal health and can often predict impending failure. Defragmenting is only useful for HDDs (and shouldn't be done on SSDs). Disk Cleanup removes files, not diagnose hardware. Reinstalling the OS is too drastic at this point.",
        "examTip": "Regularly monitor the SMART status of your hard drives (especially if you suspect problems); it can provide early warning of potential failure."
    },
    {
        "id": 73,
        "question": "What is 'multi-factor authentication' (MFA), and why is it important for security?",
        "options":[
            "Using a very long password.",
           "Requiring users to provide two or more independent authentication factors (something they know, something they have, something they are) to verify their identity, significantly increasing security even if one factor is compromised.",
            "Encrypting all network traffic.",
            "Using a firewall."
        ],
        "correctAnswerIndex": 1,
        "explanation": "MFA adds a significant layer of security by requiring *multiple* forms of authentication. This makes it much harder for attackers to gain unauthorized access, even if they have stolen a password (something you *know*).  A long password is *part* of good security, but MFA goes beyond that. Encryption protects data in transit, and firewalls control network access; these are *separate* security measures.",
        "examTip": "Enable multi-factor authentication (MFA) whenever possible, especially for critical accounts (email, banking, cloud services); it's one of the most effective ways to prevent unauthorized access."
    },
     {
        "id": 74,
        "question":"You are configuring a secure wireless network.  Which of the following combinations of settings provides the STRONGEST security?",
        "options":[
           "WEP encryption with a shared password.",
            "WPA2-Personal with a strong pre-shared key (PSK).",
            "WPA2-Enterprise with 802.1X authentication using a RADIUS server, and AES encryption.",
            "Open network (no encryption)."
        ],
        "correctAnswerIndex": 2,
        "explanation": "WPA2-Enterprise with 802.1X/RADIUS and AES encryption provides the strongest security for wireless networks. It uses individual user authentication (not a shared password) and strong encryption. WEP is outdated and insecure. WPA2-Personal is good for home use, but Enterprise is better for organizations. An open network is completely insecure.",
        "examTip": "Use WPA2-Enterprise with 802.1X/RADIUS and AES for the strongest wireless security in a corporate environment; use WPA2-Personal with a strong PSK for home networks."
    },
    {
        "id": 75,
        "question": "You are troubleshooting a computer that is not booting. The system powers on, but you see no display on the monitor, and you hear no beep codes. You've already checked the monitor and its cable. What is the NEXT step to investigate?",
        "options":[
          "Reinstall the operating system.",
            "Check the power supply connections to the motherboard, reseat the RAM modules, reseat the video card (if applicable), and check for any loose connections. If possible, try a different power supply.",
            "Replace the hard drive.",
            "Replace the network cable."
        ],
        "correctAnswerIndex": 1,
        "explanation": "No display and no beeps, after verifying the monitor, often indicates a fundamental hardware problem: power supply, motherboard, RAM, or video card. Reseating components (RAM, video card) ensures they have good connections. Checking power connections is crucial. Trying a *known-good* power supply can help rule out a PSU failure. Reinstalling the OS, replacing the hard drive, or the network cable are irrelevant at this stage.",
        "examTip": "When troubleshooting a no-boot situation with no display and no beeps, focus on core hardware: power supply, motherboard, RAM, and video card."
    },
    {
        "id": 76,
        "question":"You are configuring a Linux server and need to find all files named 'error.log' that have been modified within the last 7 days. Which command would you use?",
        "options":[
            "`grep error.log / -mtime -7`",
           "`find / -name error.log -mtime -7`",
            "`locate error.log -mtime -7`",
            "`ls -l / | grep error.log`"
        ],
        "correctAnswerIndex": 1,
        "explanation": "`find / -name error.log -mtime -7` is the correct command. `find` is used to locate files. `/` specifies the root directory (search the entire system). `-name error.log` specifies the filename. `-mtime -7` finds files modified within the last 7 days (less than 7 days ago). `grep` searches *within* files, `locate` uses a pre-built database (which might be outdated), and `ls` lists files in a directory.",
        "examTip": "Use the `find` command for powerful file searching in Linux; learn its various options for specifying search criteria (name, type, size, modification time, etc.)."
    },
     {
        "id": 77,
        "question":"What is 'spear phishing'?",
        "options":[
            "A type of malware that encrypts files.",
           "A highly targeted phishing attack that focuses on a specific individual or organization, often using personalized information to make the attack more convincing.",
            "A type of network attack that floods a server with traffic.",
            "A type of attack that exploits vulnerabilities in software."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Spear phishing is a more sophisticated form of phishing. Instead of sending generic emails to many people, attackers research their target and craft personalized emails that appear to be from a trusted source, making the victim more likely to fall for the scam. It's not malware itself (though spear phishing emails might *contain* links to malware), a network flood, or a direct software exploit.",
        "examTip": "Be extremely cautious of emails, even if they appear to be from someone you know, if they ask for sensitive information, contain unexpected attachments, or have suspicious links; spear phishing attacks are highly targeted and convincing."
    },
     {
        "id": 78,
        "question": "A user reports that they are unable to access a website that they were able to access yesterday. You can access the website from a different computer on the same network. You've already checked the user's browser settings, cleared the cache and cookies, and verified DNS resolution with `nslookup`. What is the NEXT step to investigate on the user's computer?",
        "options":[
            "Reinstall the operating system.",
           "Check the Windows 'hosts' file for any entries that might be blocking or redirecting the website, and check for any third-party firewall or security software that might be blocking access.",
            "Replace the network cable.",
            "Run a virus scan."
        ],
        "correctAnswerIndex": 1,
        "explanation": "If other computers on the *same* network can access the website, and you've ruled out basic browser issues and DNS resolution, the problem is likely local to the *user's* computer. The 'hosts' file can override DNS, redirecting or blocking specific websites. Third-party security software (firewalls, web filters) could also be blocking access. Reinstalling the OS is too drastic. A cable problem would likely cause *more general* connectivity issues. A virus scan is a good idea, but less targeted to this specific scenario *after* ruling out other likely causes.",
        "examTip": "The Windows 'hosts' file can override DNS resolution; check it for incorrect or malicious entries when troubleshooting website access problems."
    },
    {
        "id":79,
        "question": "You are configuring a new server and want to implement a strong password policy. Which of the following settings would be MOST effective in improving password security?",
        "options":[
           "Minimum password length of 6 characters.",
           "Require passwords to be changed every 365 days.",
            "Enforce a minimum password length of at least 12 characters, require a mix of uppercase and lowercase letters, numbers, and symbols, disallow common words or patterns, and enforce regular password changes (e.g., every 90 days).",
            "Allow users to write down their passwords."

        ],
        "correctAnswerIndex": 2,
        "explanation": "A strong password policy combines multiple factors: *length* (at least 12 characters, ideally longer), *complexity* (mix of character types), *uniqueness* (avoiding common words and patterns), and *regular changes* (to mitigate the risk of compromised passwords being used for extended periods).  Shorter lengths, infrequent changes, and written passwords are all security weaknesses.",
        "examTip": "Implement a comprehensive password policy that enforces length, complexity, uniqueness, and regular changes; educate users about the importance of strong passwords."
    },
     {
        "id": 80,
        "question": "What is the purpose of the `traceroute` (or `tracert` in Windows) command?",
        "options":[
           "To display the current IP address configuration.",
            "To test network connectivity to a remote host.",
            "To trace the route that packets take to reach a destination, showing each hop (router) along the way and the latency at each hop.",
            "To display active network connections."
        ],
        "correctAnswerIndex": 2,
        "explanation": "`traceroute`/`tracert` is used for network path diagnostics. It shows the sequence of routers (hops) that packets traverse to reach a destination, along with the time it takes for packets to reach each hop. This helps identify network bottlenecks or routing problems. `ipconfig` shows configuration, `ping` tests *basic* connectivity, and `netstat` shows active connections.",
        "examTip": "Use `traceroute`/`tracert` to diagnose network latency issues and to map the network path to a remote host."
    },
     {
        "id":81,
        "question": "You are working on a Linux system and need to find all files that contain the string 'password' within their content. Which command is BEST suited for this task?",
        "options":[
            "`find / -name password`",
            "`grep -r 'password' /`",
            "`locate password`",
            "`ls -l | grep password`"
        ],
        "correctAnswerIndex": 1,
        "explanation": " `grep -r 'password' /` recursively searches for files containing. `find` will locate a file, but won't search within, `locate` uses an inex, and `ls` lists files.",
        "examTip": "Use `grep -r` to recursively search through all files."
     },
      {
        "id": 82,
        "question": "You are troubleshooting a Windows computer and suspect that a recently installed program is causing system instability. You want to prevent this program from starting automatically when Windows boots. Which of the following methods is LEAST effective for achieving this?",
        "options":[
           "Disabling the program in Task Manager's Startup tab.",
            "Removing the program's shortcut from the Startup folder in the Start Menu.",
          "Deleting the program's executable file.",
            "Using the System Configuration utility (msconfig.exe) to disable the program's startup entry."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Deleting the program's executable file is a drastic and potentially dangerous approach. It could damage the program's installation, prevent proper uninstallation, and might not even prevent it from starting if it has other autostart mechanisms. The other options (Task Manager, Startup folder, msconfig) are standard and safer ways to manage startup programs.",
        "examTip": "Manage startup programs using standard Windows tools (Task Manager, msconfig, Startup folder); avoid deleting executable files directly unless you are absolutely sure it's safe and necessary."
    },
    {
        "id":83,
        "question": "What is the purpose of enabling 'two-factor authentication' (2FA) or 'multi-factor authentication' (MFA) on an account?",
        "options":[
           "To make it easier to remember your password.",
            "To add an extra layer of security by requiring two or more independent authentication factors (something you know, something you have, something you are) to verify your identity.",
            "To speed up the login process.",
            "To encrypt your password."
        ],
        "correctAnswerIndex": 1,
        "explanation": "2FA/MFA significantly enhances security by requiring *more than just a password* to log in.  This makes it much harder for attackers to gain unauthorized access, even if they have stolen your password. It doesn't make passwords easier to remember, speed up login, or encrypt the password *itself*.",
        "examTip": "Enable 2FA/MFA whenever possible, especially for important accounts (email, banking, cloud storage); it's one of the most effective ways to prevent unauthorized access."
    },
    {
        "id": 84,
        "question": "A user reports that their computer is displaying a message stating that their files have been encrypted and they need to pay a ransom to get them back. The user does NOT have any recent backups. What is the BEST course of action?",
        "options":[
          "Pay the ransom immediately.",
            "Disconnect the computer from the network, contact a cybersecurity professional or law enforcement, and do NOT pay the ransom without expert advice. There is no guarantee that paying the ransom will result in file recovery, and it encourages further criminal activity.",
            "Reinstall the operating system.",
            "Run a virus scan."
        ],
        "correctAnswerIndex": 1,
        "explanation": "This is a ransomware attack. *Never* pay the ransom without consulting security professionals. There's no guarantee you'll get your files back, and you'll be funding criminal activity. Disconnecting from the network is crucial to prevent further spread. Reinstalling the OS will *remove* the malware, but it won't *decrypt* your files. A virus scan might remove the *malware*, but it won't *recover* the encrypted files.",
        "examTip": "The best defense against ransomware is regular, *offline* backups. If infected, disconnect from the network, seek professional help, and do *not* pay the ransom without expert guidance."
    },
     {
        "id":85,
        "question": "You are using the `netstat` command in Windows to analyze network connections.  You want to see all listening ports and the associated process IDs. Which command would you use?",
        "options":[
            "netstat -a",
          "netstat -an",
          "netstat -b",
          "netstat -o"
        ],
        "correctAnswerIndex": 1,
        "explanation": "To get listening ports and process IDs in numerical format, use `netstat -an`",
        "examTip": "Use `netstat -an` as the command to view network processes."
    },
	{
        "id": 86,
        "question": "Which of the following actions would be MOST helpful in preventing social engineering attacks?",
        "options":[
          "Installing antivirus software.",
            "Educating users about common social engineering tactics (phishing, pretexting, baiting, etc.) and how to recognize and avoid them.",
            "Using a strong firewall.",
            "Encrypting all network traffic."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Social engineering relies on manipulating *people*, not exploiting technical vulnerabilities. User education is the *most effective* defense. Antivirus, firewalls, and encryption are important, but they don't directly address the *human* element of social engineering.",
        "examTip": "Regular security awareness training for users is crucial to combat social engineering attacks; teach them to be skeptical and to verify requests for information."
    },
    {
        "id": 87,
        "question":"What is the primary purpose of a 'honeypot' in network security?",
        "options":[
           "To encrypt sensitive data.",
            "To filter network traffic.",
           "To attract and trap attackers, allowing security professionals to study their methods, gather intelligence, and potentially divert them from real targets.",
            "To provide a secure connection for remote access."
        ],
        "correctAnswerIndex": 2,
        "explanation": "A honeypot is a decoy system designed to look like a legitimate target, luring attackers and allowing security researchers to observe their behavior and gather information about attack techniques. It's not for encryption, filtering traffic (firewalls do that), or secure remote access (VPNs do that).",
        "examTip": "Honeypots are used for threat research and deception; they can provide valuable insights into attacker behavior and help improve defenses."
    },
    {
        "id": 88,
        "question":"A user reports that their computer is running slowly. You open Task Manager and see that the CPU utilization is consistently high, and a process named 'svchost.exe' is consuming a large amount of resources. You've already determined that multiple services are running within that `svchost.exe` instance. What is the NEXT step to identify the specific *service* causing the high CPU usage?",
        "options":[
          "End the `svchost.exe` process.",
          "Reinstall the operating system.",
            "Use Resource Monitor (resmon.exe), expand the CPU section, and then expand the 'Services' section.  This will show you the CPU usage of individual services, including those running within `svchost.exe` instances. You can also use `tasklist /svc /fi \"imagename eq svchost.exe\"` to see which services are in which `svchost.exe` process, and then use Task Manager to see CPU by PID.",
            "Run Disk Cleanup."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Resource Monitor provides a more granular view of resource usage than Task Manager, allowing you to see the CPU consumption of *individual services* running within `svchost.exe`. Ending the process directly could crash the system. Reinstalling the OS is too drastic. Disk Cleanup addresses disk space, not CPU usage.",
        "examTip": "Use Resource Monitor (resmon.exe) to drill down into `svchost.exe` resource usage and identify the specific service causing high CPU or memory consumption."
    },
     {
        "id": 89,
        "question":"You are configuring a firewall and want to allow users on your internal network to access websites on the internet. Which type of firewall rule should you create?",
        "options":[
          "An inbound rule.",
          "An outbound rule allowing traffic on ports 80 (HTTP) and 443 (HTTPS).",
            "A port forwarding rule.",
            "A DMZ rule."
        ],
        "correctAnswerIndex": 1,
        "explanation": "To allow users to access websites, you need to create *outbound* rules that permit traffic *from* your internal network *to* the internet on the standard web ports (80 for HTTP, 443 for HTTPS). Inbound rules control traffic *coming into* your network. Port forwarding is for allowing *inbound* access to specific internal servers. A DMZ is a separate network segment for publicly accessible servers.",
        "examTip": "Understand the difference between inbound and outbound firewall rules: outbound rules control traffic *initiated from* your network, inbound rules control traffic *initiated from outside* your network."
    },
     {
        "id": 90,
        "question":"What is 'cross-site request forgery' (CSRF or XSRF)?",
        "options":[
          "A type of malware that encrypts files.",
            "An attack that forces an end user to execute unwanted actions on a web application in which they are currently authenticated.",
            "A type of social engineering attack.",
            "A type of denial-of-service attack."
        ],
        "correctAnswerIndex": 1,
        "explanation": "CSRF exploits the trust a web application has in a user's browser.  An attacker tricks the user's browser into sending a malicious request to a website where the user is already logged in, causing an unwanted action (like changing a password, transferring funds, etc.) to be performed *without the user's knowledge*.  It's not malware that encrypts files, social engineering *directly* (though it can be *combined* with social engineering), or a DoS attack.",
        "examTip": "Web developers should implement CSRF protection mechanisms (like anti-CSRF tokens) to prevent this type of attack; users should be cautious about clicking on links from untrusted sources."
    },
    {
        "id": 91,
        "question": "You are working with a Linux system and need to determine the IP address, subnet mask, and default gateway configured on a network interface.  Which command provides this information in a clear and concise format?",
        "options":[
           "ifconfig",
           "ip addr show",
            "netstat -r",
            "route -n"
        ],
        "correctAnswerIndex": 1, 
        "explanation": "`ip addr show` (or the older `ifconfig`, though `ip` is preferred on modern systems) displays detailed information about network interfaces, including IP address, subnet mask (in CIDR notation), and other configuration details. `netstat -r` and `route -n` show the routing table, not the interface configuration itself.",
        "examTip": "Use `ip addr show` (or `ifconfig` on older systems) to view network interface configuration details on Linux."
    },
    {
        "id": 92,
        "question":"What is a 'rainbow table' in the context of password cracking?",
        "options":[
           "A table of common passwords.",
            "A precomputed table of password hashes that can be used to quickly look up the plaintext password corresponding to a given hash.",
            "A table of encryption keys.",
            "A table of network addresses."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Rainbow tables are precalculated lists of password hashes.  Instead of *brute-forcing* (trying every possible password combination), attackers can use a rainbow table to quickly look up a given password hash and find the corresponding plaintext password (if it's in the table). This significantly speeds up password cracking for common or weak passwords. It's not a list of *plaintext* passwords, encryption keys, or network addresses.",
        "examTip": "Rainbow tables are a threat to weak or common passwords; using strong, unique passwords and salting password hashes are effective defenses."
    },
       {
        "id": 93,
        "question":"You are troubleshooting a Windows computer that is experiencing network connectivity problems. You suspect a problem with the TCP/IP stack. Which command-line tool can you use to reset the TCP/IP stack to its default configuration?",
        "options":[
            "`ipconfig /release`",
            "`ipconfig /renew`",
           "`netsh int ip reset`",
            "`ipconfig /flushdns`"
        ],
        "correctAnswerIndex": 2,
        "explanation": "`netsh int ip reset` is the command to reset the TCP/IP stack in Windows. This can resolve various network connectivity issues caused by corrupted or misconfigured TCP/IP settings. `ipconfig /release` and `/renew` manage DHCP leases, and `/flushdns` clears the DNS cache; these are useful, but they don't reset the *entire* TCP/IP stack.",
        "examTip": "Use `netsh int ip reset` to reset the Windows TCP/IP stack to its default configuration as a troubleshooting step for network connectivity problems."
    },
    {
        "id": 94,
        "question": "A user reports that their computer is running slowly, and they notice unusual network activity. You suspect a malware infection. You've already run a full system scan with the installed antivirus software, but it didn't detect anything. What is the NEXT BEST step?",
        "options":[
            "Reinstall the operating system.",
           "Run a scan with a *different* anti-malware tool, preferably one that specializes in rootkit detection, and/or use a bootable antivirus rescue disk.",
            "Disconnect the computer from the network.",
            "Delete any unfamiliar files or programs."
        ],
        "correctAnswerIndex": 1,
        "explanation": "If one anti-malware tool doesn't find anything, trying a *different* one (especially one known for rootkit detection) or using a *bootable* rescue disk is the next logical step.  Different tools use different detection methods and databases. Reinstalling the OS is more drastic. Disconnecting from the network is a good *containment* measure, but not a *removal* step. Deleting files without knowing what they are is risky.",
        "examTip": "If one anti-malware scan comes up clean, but symptoms persist, try a second opinion from a different tool or a bootable rescue disk."
    },
    {
        "id": 95,
        "question": "You are configuring a web server and want to ensure secure communication using HTTPS. You've obtained an SSL/TLS certificate from a Certificate Authority (CA). What is the NEXT step to enable HTTPS on the server?",
        "options":[
           "Install the SSL/TLS certificate on the web server and configure the web server software (e.g., IIS, Apache) to use the certificate for HTTPS connections (typically on port 443).",
            "Install the certificate on all client computers.",
            "Change the website's URL to use 'https://'.",
            "Configure the firewall to block all traffic on port 80."
        ],
        "correctAnswerIndex": 0,
        "explanation": "The SSL/TLS certificate needs to be installed *on the web server itself*, and the web server software (IIS, Apache, Nginx, etc.) must be configured to use that certificate for HTTPS connections. Installing it on *clients* is not necessary (the client's browser trusts the CA that issued the certificate). Changing the URL to 'https://' is important, but the server must be *configured* to listen for and handle HTTPS connections. Blocking port 80 might be done *after* HTTPS is working, to force secure connections.",
        "examTip": "Enabling HTTPS requires installing an SSL/TLS certificate *on the web server* and configuring the web server software to use it."
    },
     {
        "id": 96,
        "question": "You are troubleshooting a network connectivity problem on a Linux server. You want to see which processes are currently listening for incoming network connections. Which command would you use?",
        "options":[
            "ifconfig",
            "ip addr show",
           "`netstat -tulnp` (or `ss -tulnp` on newer systems)",
            "route -n"
        ],
        "correctAnswerIndex": 2,
        "explanation": "`netstat -tulnp` (or the newer `ss -tulnp`) shows listening TCP (`-t`) and UDP (`-u`) ports (`-l`), along with the owning process ID and name (`-n` shows numerical addresses, `-p` shows the program name). `ifconfig` and `ip addr show` display interface configuration, and `route -n` shows the routing table.",
        "examTip": "Use `netstat -tulnp` (or `ss -tulnp`) on Linux to identify processes listening on specific network ports."
    },
    {
        "id": 97,
        "question": "You are investigating a potential security breach on a Windows server. You need to review the security audit logs to see who has been accessing specific files and folders. Where would you find these logs?",
        "options":[
           "Task Manager",
            "Resource Monitor",
            "Event Viewer (specifically the Security log), assuming that object access auditing has been enabled.",
            "System Information (msinfo32.exe)"
        ],
        "correctAnswerIndex": 2,
        "explanation": "The Security log in Event Viewer records security-related events, *including file and folder access*, but *only if object access auditing has been enabled* (through Local Security Policy or Group Policy). Task Manager shows running processes, Resource Monitor shows resource usage, and System Information provides system details.  The *Security* log is key, but *auditing must be configured*.",
        "examTip": "Enable object access auditing in Windows (through Local Security Policy or Group Policy) to track file and folder access events in the Security log."
    },
    {
       "id": 98,
       "question":"A user reports that their computer is displaying a 'Bootmgr is missing' error message when they try to start their Windows computer. What is the recommended FIRST step to attempt to repair this issue?",
       "options":[
        "Reinstall the operating system.",
        "Replace the hard drive.",
        "Boot from the Windows installation media (DVD or USB) and use the Recovery Environment to run Startup Repair.",
        "Run a virus scan."
       ],
       "correctAnswerIndex": 2,
       "explanation":"'Bootmgr is missing' indicates a problem with the Windows boot loader. Booting from the Windows installation media and using Startup Repair is the recommended first step. This tool can often automatically fix common boot problems, including a missing or corrupted Bootmgr. Reinstalling the OS is more drastic and time-consuming. Replacing the hard drive is unlikely to be necessary unless the drive itself has failed. A virus scan is less relevant at this *boot* stage.",
       "examTip": "Use the Windows Recovery Environment (boot from installation media) and Startup Repair to fix common boot problems like 'Bootmgr is missing'."
    },
    {
        "id":99,
        "question": "You are configuring a new wireless network. You want to use WPA2 encryption. You have the choice of using TKIP or AES for the encryption algorithm. Which algorithm should you choose, and why?",
        "options":[
           "TKIP, because it is faster than AES.",
            "AES, because it is a stronger and more secure encryption algorithm than TKIP.",
            "TKIP, because it is compatible with older devices.",
            "AES, because it is easier to configure than TKIP."
        ],
        "correctAnswerIndex": 1,
        "explanation": "AES (Advanced Encryption Standard) is a much stronger and more secure encryption algorithm than TKIP (Temporal Key Integrity Protocol). TKIP was an interim solution introduced with WPA to address the weaknesses of WEP, but it has its own vulnerabilities. WPA2 with AES is the recommended configuration. While *compatibility* with older devices *might* be a concern, security should be the priority.",
        "examTip": "Always choose AES over TKIP for WPA2 encryption; AES provides significantly stronger security."
    },
    {
        "id": 100,
        "question": "A user reports their Windows laptop is running very slowly. You open Task Manager and notice that the disk activity is constantly 100%, even when the system is idle. You've already ruled out malware and checked the SMART status of the hard drive (which is healthy). The laptop has an SSD. What is the NEXT BEST step to investigate?",
        "options":[
          "Run Disk Defragmenter.",
            "Use Resource Monitor (resmon.exe) to identify which specific processes and files are causing the high disk I/O, and investigate those processes. Also, consider checking for driver issues, and ensure the SSD firmware is up-to-date.",
            "Run Disk Cleanup.",
            "Increase the size of the paging file."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Constant 100% disk activity on an SSD, even at idle, is *abnormal*. Resource Monitor provides detailed information about disk I/O, allowing you to pinpoint the specific processes and files causing the activity.  You should *never* defragment an SSD. Disk Cleanup removes files, which might help if the drive is *full*, but doesn't address the *cause* of constant high activity. Increasing the paging file addresses virtual memory, not disk I/O directly.  Checking for driver issues (especially storage controllers) and updating SSD firmware are also good troubleshooting steps for SSD performance.",
        "examTip": "Use Resource Monitor to diagnose high disk I/O on SSDs; constant 100% activity is unusual and warrants investigation. Consider driver issues and firmware updates for SSDs."
    }
  ]
}
