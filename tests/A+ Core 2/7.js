db.tests.insertOne({
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
      "explanation": "`reg query` is a powerful command-line tool for searching and retrieving registry data. It allows you to specify search keys, value names, data types, and recursion options. `regedit.exe` is a graphical editor, better for browsing and manual editing, but less efficient for *searching*. `msconfig.exe` manages startup *programs*, but doesn't provide general registry searching. `tasklist` shows running processes.",
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
      "question": "A user reports that their Windows computer is exhibiting slow performance. Task Manager shows high CPU utilization, and Resource Monitor indicates that the `svchost.exe` process is consuming a significant amount of CPU. You need to determine which specific *service* hosted within `svchost.exe` is causing the high CPU usage. What is the BEST way to do this?",
      "options": [
        "End the `svchost.exe` process in Task Manager.",
        "Use Resource Monitor's CPU tab, expand the 'Services' section, and look for the service(s) associated with the specific `svchost.exe` instance that is consuming high CPU. You can also use the command `tasklist /svc` to see which services are hosted by each `svchost.exe` process.",
        "Run a full system scan with antivirus software.",
        "Reinstall the operating system."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Resource Monitor provides a more granular view of resource usage than Task Manager, allowing you to see the CPU consumption of *individual services* running within `svchost.exe`. Ending the process directly could crash the system. Antivirus is a good general step, but less targeted. Reinstalling the OS is too drastic.",
      "examTip": "Use Resource Monitor (resmon.exe) or the command `tasklist /svc` to identify which service within `svchost.exe` is consuming excessive resources."
    },
    {
      "id": 8,
      "question": "You are configuring a SOHO router and need to forward incoming traffic on port 25 (SMTP) to an internal mail server with the private IP address 192.168.1.50. However, you also need to forward incoming traffic on port 80 (HTTP) to a *different* internal web server with the private IP address 192.168.1.60. How would you configure this on the router?",
      "options": [
        "Enable DMZ and set the DMZ host to 192.168.1.50.",
        "Configure port forwarding: forward external port 25 to internal IP 192.168.1.50, port 25, and forward external port 80 to internal IP 192.168.1.60, port 80.",
        "Configure port forwarding: forward external port 25 to internal IP 192.168.1.50, port 80, and forward external port 80 to internal IP 192.168.1.60, port 25.",
        "Enable UPnP (Universal Plug and Play)."
      ],
      "correctAnswerIndex": 1,
      "explanation": "You need to create two separate port forwarding rules: one for port 25 (SMTP) to the mail server (192.168.1.50:25), and another for port 80 (HTTP) to the web server (192.168.1.60:80). DMZ exposes a single host entirely, which is a security risk. Option C has the port mappings incorrect. UPnP can automate this, but it is often a security risk.",
      "examTip": "Configure individual port forwarding rules for different services to direct traffic appropriately."
    },
    {
      "id": 9,
      "question": "A user reports that their previously working external hard drive is no longer recognized by their Windows computer. The drive does not appear in File Explorer or Disk Management. You've tried different USB ports and cables, with no success. What is the NEXT step to investigate?",
      "options": [
        "Reinstall the operating system.",
        "Check if the drive is detected in the BIOS/UEFI settings of the computer. If not, the drive itself (or its enclosure's controller) has likely failed.",
        "Run `chkdsk`.",
        "Format the drive."
      ],
      "correctAnswerIndex": 1,
      "explanation": "If the drive isn't detected in the BIOS/UEFI, it indicates a hardware problem with the drive or its enclosure's controller. The operating system cannot see a drive that the BIOS/UEFI doesn't detect. Reinstalling the OS is not relevant, and running chkdsk or formatting requires the drive to be recognized first.",
      "examTip": "If an external drive is not detected by the BIOS/UEFI, suspect hardware failure and consider replacing the drive or its enclosure."
    },
    {
      "id": 10,
      "question": "You are troubleshooting a network connectivity issue on a Linux server. You need to view the current routing table to understand how network traffic is being directed. Which command would you use?",
      "options": [
        "ifconfig",
        "ip addr show",
        "route -n (or `ip route show`)",
        "netstat -i"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`route -n` (or `ip route show`) displays the routing table, showing which networks are reachable via which interfaces and gateways. `ifconfig` and `ip addr show` display interface configuration, while `netstat -i` shows interface statistics.",
      "examTip": "Use `route -n` or `ip route show` on Linux to view the routing table and diagnose network path issues."
    },
    {
      "id": 11,
      "question": "You have a Windows system with multiple hard drives. You want to combine two of these drives into a single, larger volume without losing any data. Which Windows feature would allow you to do this, assuming the drives are *dynamic* disks?",
      "options": [
        "Disk Defragmenter",
        "Disk Cleanup",
        "Spanned Volume (in Disk Management)",
        "RAID 0"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A spanned volume (created in Disk Management on dynamic disks) allows you to combine space from multiple drives into one logical volume without data loss, though it provides no redundancy.",
      "examTip": "Use spanned volumes for combining disk space on dynamic disks when data redundancy is not required."
    },
    {
      "id": 12,
      "question": "A user's computer is experiencing frequent BSOD (Blue Screen of Death) errors. You've checked for overheating and run Windows Memory Diagnostic (which found no errors). You suspect a driver problem. What is the NEXT BEST step to investigate and potentially isolate the faulty driver?",
      "options": [
        "Reinstall the operating system.",
        "Use Driver Verifier (verifier.exe) to stress-test drivers and identify potential issues.",
        "Run System Restore.",
        "Run `chkdsk`."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Driver Verifier (verifier.exe) stresses drivers to expose problems that might not be evident during normal operation. This tool is particularly useful in diagnosing driver-related BSODs.",
      "examTip": "Use Driver Verifier to pinpoint problematic drivers, but remember to disable it if the system becomes unstable."
    },
    {
      "id": 13,
      "question": "A user reports they are unable to access a specific network share. You've verified the user has the correct permissions, the file server is online, other users can access the share, DNS resolves correctly, and the user can ping the server by IP and hostname. What is a *less common*, but still possible, cause you should investigate?",
      "options": [
        "The user's network cable is faulty.",
        "SMB (Server Message Block) signing mismatch or incompatibility between the client and server.",
        "The user's account is locked out.",
        "The file server is out of disk space."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An SMB signing mismatch between the client and server can prevent access to network shares even when all other factors (permissions, connectivity, DNS) are correct.",
      "examTip": "Investigate SMB signing and compatibility issues if all basic network checks are successful yet share access fails."
    },
    {
      "id": 14,
      "question": "You are analyzing network traffic with Wireshark and notice a large number of TCP packets with the RST (reset) flag set. What does this typically indicate?",
      "options": [
        "Normal TCP connection establishment.",
        "An abrupt termination of a TCP connection, often due to an error or a refusal to connect.",
        "Successful file transfer.",
        "Encrypted communication."
      ],
      "correctAnswerIndex": 1,
      "explanation": "RST packets indicate that a TCP connection is being abruptly terminated. This can occur when a host refuses a connection or when an error occurs during the TCP handshake.",
      "examTip": "A high number of RST packets may indicate issues with connectivity or misconfigured services; analyze the context to determine the cause."
    },
    {
      "id": 15,
      "question": "A user reports they are unable to access any websites. They have a valid IP address, can ping their default gateway, and can ping external IP addresses (like 8.8.8.8), but `ping <domain_name>` fails for all websites. `nslookup` also fails to resolve any domain names. What is the MOST likely cause?",
      "options": [
        "The user's web browser is corrupted.",
        "The user's configured DNS servers are unreachable or malfunctioning.",
        "The user's network cable is faulty.",
        "The user's computer has a virus."
      ],
      "correctAnswerIndex": 1,
      "explanation": "If the user can ping external IPs but cannot resolve domain names (as indicated by ping and nslookup failures), the issue is most likely with the configured DNS servers.",
      "examTip": "When domain name resolution fails but IP connectivity works, focus on diagnosing DNS server issues."
    },
    {
      "id": 16,
      "question": "Which of the following is an example of 'defense in depth' in cybersecurity?",
      "options": [
        "Using a strong password for your email account.",
        "Implementing multiple layers of security controls (e.g., firewall, antivirus, intrusion detection system, strong passwords, user training) so that if one layer fails, others are still in place to protect the system.",
        "Regularly backing up your data.",
        "Keeping your software up-to-date."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Defense in depth is a security strategy that employs multiple overlapping layers of security so that if one fails, additional layers continue to protect the system.",
      "examTip": "Adopt a defense-in-depth strategy by combining various security measures to protect your network and systems."
    },
    {
      "id": 17,
      "question": "You are using the `netstat` command in Windows.  You want to see all active TCP connections, the owning process ID for each connection, *and* the numerical form of addresses and ports (without resolving hostnames).  Which command would you use?",
      "options": [
        "netstat -a",
        "netstat -b",
        "netstat -ano",
        "netstat -o"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`netstat -ano` displays all active connections (`-a`), in numerical form (`-n`), along with the owning process ID (`-o`).",
      "examTip": "Remember: `-a` shows all connections, `-n` prevents hostname resolution, and `-o` shows process IDs."
    },
    {
      "id": 18,
      "question": "You are configuring a new Linux server. You want to ensure that the system clock is automatically synchronized with a reliable time source. You decide to use the NTP (Network Time Protocol) service. Which configuration file would you typically edit to specify the NTP servers to use?",
      "options": [
        "/etc/hosts",
        "/etc/ntp.conf (or /etc/chrony.conf on some newer systems)",
        "/etc/resolv.conf",
        "/etc/network/interfaces"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The NTP configuration file (commonly `/etc/ntp.conf` or `/etc/chrony.conf`) specifies the NTP servers for time synchronization.",
      "examTip": "Edit `/etc/ntp.conf` (or `/etc/chrony.conf`) to configure NTP on Linux servers."
    },
    {
      "id": 19,
      "question": "What is the purpose of a 'security baseline' in system configuration?",
      "options": [
        "To provide a minimum level of security that all systems must meet, ensuring a consistent and secure configuration across the organization.",
        "To track changes made to a system's configuration.",
        "To encrypt sensitive data on a system.",
        "To monitor system performance."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A security baseline defines a standard, secure configuration for systems to ensure consistency and reduce vulnerabilities.",
      "examTip": "Establish and maintain security baselines to ensure systems adhere to minimum security standards."
    },
    {
      "id": 20,
      "question": "You are troubleshooting a network connectivity issue and suspect a problem with a specific router along the path to a destination. You use the `tracert` command, and the output shows a series of asterisks (*) for one particular hop. What does this indicate?",
      "options": [
        "The destination server is down.",
        "Your computer's network adapter is faulty.",
        "The router at that hop is not responding to the ICMP echo requests (pings) used by `tracert`, or there's a firewall blocking the responses. It doesn't necessarily mean the router is down, just that it's not providing the information `tracert` needs.",
        "Your DNS server is slow."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Asterisks (*) in `tracert` output indicate that the router at that hop did not respond to the ICMP echo requests, possibly due to firewall rules or configuration, but it doesn't mean the router is necessarily down.",
      "examTip": "Asterisks in tracert output often point to filtering or non-responsive routers; further investigation may be needed if connectivity issues persist."
    },
    {
      "id": 21,
      "question": "A user reports that every time they restart their Windows computer, a specific unwanted program automatically starts, even though they have removed it from the Startup folder in Task Manager and from the Startup tab in msconfig. Where else should you check for autostart entries?",
      "options": [
        "The user's Documents folder.",
        "The Windows Registry (specifically Run, RunOnce keys in HKLM and HKCU), Scheduled Tasks, and Services.",
        "The Program Files folder.",
        "The Control Panel."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Autostart entries can be set in the Registry, Scheduled Tasks, and as Windows Services. These are common places where malware or unwanted software may persist.",
      "examTip": "Investigate all potential autostart locations—including Registry Run keys, Scheduled Tasks, and Services—when unwanted programs persist after standard removal methods."
    },
    {
      "id": 22,
      "question": "You are using Wireshark to analyze network traffic. You want to filter the displayed packets to show only traffic to or from a specific IP address (e.g., 192.168.1.100). Which Wireshark display filter would you use?",
      "options": [
        "`ip.addr == 192.168.1.100`",
        "`tcp.port == 80`",
        "`http`",
        "`icmp`"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The display filter `ip.addr == 192.168.1.100` will show packets where the source or destination IP matches 192.168.1.100.",
      "examTip": "Use display filters in Wireshark like `ip.addr == <IP>` to isolate traffic for specific IP addresses."
    },
    {
      "id": 23,
      "question": "You are configuring a Linux server and want to limit the amount of disk space that a particular user can use. Which feature would you use?",
      "options": [
        "File permissions",
        "Disk quotas",
        "SELinux",
        "AppArmor"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Disk quotas allow you to restrict the amount of disk space and number of inodes a user or group can consume.",
      "examTip": "Implement disk quotas on Linux systems to prevent any single user from consuming excessive disk space."
    },
    {
      "id": 24,
      "question": "You suspect that a user's computer might be part of a botnet. What is a botnet?",
      "options": [
        "A network of compromised computers (bots) controlled by a remote attacker, often used for malicious purposes like sending spam, launching DDoS attacks, or stealing data.",
        "A type of antivirus software.",
        "A type of firewall.",
        "A secure way to connect to the internet."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A botnet is a network of compromised computers, often used without the owner's knowledge to perform malicious tasks.",
      "examTip": "Watch for signs of botnet infection such as unexplained outbound traffic and poor system performance."
    },
    {
      "id": 25,
      "question": "Which of the following is a good practice for securing a Windows computer against malware?",
      "options": [
        "Disable User Account Control (UAC).",
        "Keep your operating system, web browser, and other software up-to-date with the latest security patches, use a reputable antivirus and anti-malware solution, and practice safe browsing habits.",
        "Use the same password for all your accounts.",
        "Download and install software from any website."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A layered approach that includes up-to-date software, antivirus, and safe browsing is best for securing a system against malware.",
      "examTip": "Security is most effective when combining updates, antivirus protection, and user awareness."
    },
    {
      "id": 26,
      "question": "You are troubleshooting a network connectivity issue. You use the `ping` command to test connectivity to a remote host, and you receive the response 'Destination host unreachable.' What does this indicate?",
      "options": [
        "The remote host is up and running, but there is a firewall blocking the connection.",
        "The remote host is down, or there is no route to the destination network from your computer or from an intermediate router.",
        "Your DNS server is not working.",
        "Your network adapter is disabled."
      ],
      "correctAnswerIndex": 1,
      "explanation": "'Destination host unreachable' indicates that no route to the destination exists from your system or an intermediate router, often a routing issue.",
      "examTip": "Interpret 'Destination host unreachable' as a routing or network path problem."
    },
    {
      "id": 27,
      "question": "You are using the `nslookup` command to troubleshoot DNS resolution. You want to specifically query a particular DNS server (e.g., Google's public DNS server at 8.8.8.8) for the IP address of a domain name (e.g., google.com). Which command would you use?",
      "options": [
        "`nslookup google.com`",
        "`nslookup google.com 8.8.8.8`",
        "`nslookup 8.8.8.8 google.com`",
        "`ping google.com`"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The correct syntax is `nslookup <domain_name> <dns_server>`, so `nslookup google.com 8.8.8.8` queries Google's DNS server.",
      "examTip": "Use `nslookup google.com 8.8.8.8` to query a specific DNS server."
    },
    {
      "id": 28,
      "question": "What is 'cross-site scripting' (XSS)?",
      "options": [
        "A type of denial-of-service attack.",
        "A type of web application vulnerability that allows attackers to inject malicious client-side scripts into web pages viewed by other users.",
        "A type of malware that encrypts files.",
        "A type of social engineering attack."
      ],
      "correctAnswerIndex": 1,
      "explanation": "XSS is a vulnerability that allows attackers to inject malicious scripts into webpages, affecting users who view the pages.",
      "examTip": "Developers should sanitize user input to prevent XSS vulnerabilities."
    },
    {
      "id": 29,
      "question": "You are configuring a firewall and want to implement the principle of least privilege. Which approach is BEST?",
      "options": [
        "Allow all traffic by default.",
        "Block all traffic by default and then create rules to explicitly allow only the necessary traffic.",
        "Allow all inbound traffic and block all outbound traffic.",
        "Allow all outbound traffic and block all inbound traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A 'default deny' strategy—blocking all traffic by default and then allowing only what is necessary—is the essence of the principle of least privilege in network security.",
      "examTip": "Always use a default deny policy for firewalls and then create specific allow rules."
    },
    {
      "id": 30,
      "question": "A user reports that their Windows computer is randomly freezing, and they have to perform a hard reset. You've already checked for overheating, run Windows Memory Diagnostic (which found no errors), and run a full system scan with antivirus software (which found no threats). You suspect a hardware problem. What is the NEXT component you should investigate?",
      "options": [
        "The keyboard.",
        "The motherboard (checking for bulging/leaking capacitors, BIOS issues) or a failing hard drive (even if it's an SSD).",
        "The monitor.",
        "The network cable."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Random freezes after ruling out overheating, RAM, and malware point toward potential motherboard issues (such as failing capacitors) or a failing storage device. The keyboard, monitor, and network cable are less likely culprits.",
      "examTip": "Inspect the motherboard and storage device when a system freezes unexpectedly."
    },
    {
      "id": 31,
      "question": "You are troubleshooting a slow website. Using `tracert`, you identify high latency at a specific hop *before* the final destination (the web server). You contact the ISP responsible for that hop, and they report no issues. What is a LIKELY next step to investigate *further*?",
      "options": [
        "Reinstall your web browser.",
        "Run a virus scan on your computer.",
        "Use a tool like `mtr` (My Traceroute) or `pathping` (Windows) which combines the functionality of `ping` and `tracert`, providing more detailed statistics about packet loss and latency at each hop over an extended period.",
        "Change your DNS server."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Tools like `mtr` or `pathping` provide more detailed, time-based statistics than a single run of `tracert`, helping to reveal intermittent issues or congestion.",
      "examTip": "Use `mtr` or `pathping` for in-depth network path analysis when a single `tracert` doesn't reveal the full picture."
    },
    {
      "id": 32,
      "question": "A user reports that they are unable to access a network share. You've verified their permissions, network connectivity, and DNS resolution. The file server is online, and other users can access the share. You suspect an issue with the SMB (Server Message Block) protocol. What Windows command-line tool can you use on the *client* computer to check the status of SMB connections and potentially diagnose the problem?",
      "options": [
        "`ping`",
        "`ipconfig`",
        "`netstat -b` on client, look for connections to the file server.",
        "`tracert`"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Using `netstat -b` (with administrator privileges) can show which executables (and by extension, services) are handling SMB connections on the client. This helps diagnose SMB-related issues.",
      "examTip": "Use `netstat -b` to check the applications associated with SMB connections."
    },
    {
      "id": 33,
      "question": "You are using Wireshark to capture and analyze network traffic. You want to filter the displayed packets to show only traffic using the HTTP protocol. Which Wireshark display filter would you use?",
      "options": [
        "`tcp.port == 80`",
        "`http`",
        "`ip.addr == 192.168.1.1`",
        "`tcp`"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The display filter `http` directly filters for HTTP protocol traffic. Although `tcp.port == 80` would capture most HTTP traffic, it might miss HTTP on non-standard ports.",
      "examTip": "Use protocol names (like http) directly as Wireshark filters for simplicity and accuracy."
    },
    {
      "id": 34,
      "question": "A user reports that their computer is exhibiting unusual behavior, including unexpected pop-ups, slow performance, and changes to their browser's homepage. You suspect a malware infection, but standard antivirus scans are not detecting anything. You decide to use a bootable antivirus rescue disk. Why is this approach often MORE effective than running scans from within the infected operating system?",
      "options": [
        "Bootable rescue disks are faster.",
        "Bootable rescue disks can scan the system *before* the potentially infected operating system loads, allowing them to detect and remove rootkits and other advanced malware that might be hiding from scans run *within* Windows.",
        "Bootable rescue disks have more up-to-date virus definitions.",
        "Bootable rescue disks can repair the operating system."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A bootable rescue disk operates outside of the infected OS, bypassing malware that may hide from in-OS scanners. This can reveal threats that remain undetected by traditional antivirus software.",
      "examTip": "For persistent malware, especially rootkits, use a bootable rescue disk to scan the system in a clean environment."
    },
    {
      "id": 35,
      "question": "What is 'credential harvesting' in the context of cybersecurity?",
      "options": [
        "A type of denial-of-service attack.",
        "The process of gathering usernames, passwords, and other authentication credentials, often through phishing, malware, or data breaches.",
        "A type of encryption.",
        "A type of network protocol."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Credential harvesting involves collecting login credentials—often through phishing or malware—to later use for unauthorized access.",
      "examTip": "Protect your credentials with strong, unique passwords and multi-factor authentication to mitigate credential harvesting risks."
    },
    {
      "id": 36,
      "question": "You are configuring a Linux server and want to schedule a script to run automatically every day at 2:30 AM. Which utility would you use?",
      "options": [
        "at",
        "cron",
        "systemd-run",
        "nohup"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Cron is the standard utility for scheduling recurring tasks on Linux. The `at` command is for one-time tasks.",
      "examTip": "Use cron jobs (configured via `crontab -e`) for recurring scheduled tasks on Linux."
    },
    {
      "id": 37,
      "question": "A user is unable to access a website. You can ping the website's IP address successfully, but `ping <domain_name>` fails. `nslookup <domain_name>` *also* fails. What is the MOST likely cause?",
      "options": [
        "The user's web browser is corrupted.",
        "A DNS resolution problem; either the user's configured DNS servers are unreachable/malfunctioning, or the domain name is not registered or has expired.",
        "The website's server is down.",
        "The user's network cable is faulty."
      ],
      "correctAnswerIndex": 1,
      "explanation": "If the IP address is reachable but both ping and nslookup fail for the domain, it is almost certainly a DNS resolution issue.",
      "examTip": "Focus on DNS server settings and domain registration status when domain name resolution fails despite IP connectivity."
    },
    {
      "id": 38,
      "question": "You are analyzing a system and suspect that a malicious process is hiding itself from standard process listing tools (like Task Manager). Which tool is BEST suited for detecting hidden processes and rootkits?",
      "options": [
        "Task Manager",
        "Resource Monitor",
        "A specialized rootkit detection tool (e.g., GMER, TDSSKiller) or a tool like Process Explorer (from Sysinternals) that provides more advanced process analysis capabilities.",
        "System Information (msinfo32.exe)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Specialized rootkit detection tools or advanced process explorers (like Process Explorer) are designed to reveal processes that may be hidden from standard tools.",
      "examTip": "For detecting hidden processes, use advanced tools such as Process Explorer or dedicated rootkit scanners."
    },
    {
      "id": 39,
      "question": "A user reports that their computer is displaying an error message stating 'SMART Failure Predicted on Hard Disk.' What does this indicate, and what is the BEST course of action?",
      "options": [
        "The computer's RAM is failing.",
        "The hard drive is reporting potential imminent failure based on its internal SMART diagnostics; immediately back up all data and replace the drive as soon as possible.",
        "The computer's power supply is failing.",
        "The operating system needs to be reinstalled."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A SMART failure warning signals that the hard drive's self-monitoring has detected conditions that may lead to drive failure. Immediate data backup and drive replacement are essential.",
      "examTip": "Treat SMART warnings as urgent; back up your data immediately and plan for drive replacement."
    },
    {
      "id": 40,
      "question": "You are troubleshooting a network connectivity issue on a Windows workstation. The computer has a valid IP address, can ping its default gateway, but can't access *any* websites. `nslookup` resolves domain names to IP addresses *correctly*. What is the NEXT step to investigate?",
      "options": [
        "Reinstall the network adapter driver.",
        "Check the web browser's proxy settings, the Windows Firewall settings, and the 'hosts' file for any incorrect entries.",
        "Restart the computer.",
        "Run a virus scan."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Since IP connectivity and DNS resolution are working, the issue is likely with the browser's configuration (proxy settings, firewall, hosts file) preventing web access.",
      "examTip": "When basic connectivity is confirmed but web access fails, check browser-specific settings and the hosts file."
    },
    {
      "id": 41,
      "question": "You need to determine the version of the Windows operating system running on a remote computer. You have command-line access to the remote system. Which command would provide this information MOST directly?",
      "options": [
        "systeminfo",
        "ver",
        "winver",
        "hostname"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`winver` displays a window with the Windows version, build number, and other details. Although `ver` provides a basic version string, `winver` is the dedicated tool for this purpose.",
      "examTip": "Use `winver` to quickly determine the Windows version on a remote system."
    },
    {
      "id": 42,
      "question": "What is 'tailgating' in the context of physical security?",
      "options": [
        "A type of phishing attack.",
        "Following an authorized person into a restricted area without proper authorization.",
        "A type of malware.",
        "A type of network attack."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Tailgating involves physically following an authorized person into a secure area without proper credentials.",
      "examTip": "Ensure strict access controls and vigilance to prevent tailgating in secure areas."
    },
    {
      "id": 43,
      "question": "Which command in Linux is used to change the ownership of a file or directory?",
      "options": [
        "chmod",
        "chown",
        "chgrp",
        "sudo"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`chown` changes the owner (and optionally the group) of a file or directory.",
      "examTip": "Use `chown` to change file or directory ownership; remember the syntax: `chown <owner>:<group> <file>`."
    },
    {
      "id": 44,
      "question": "You are setting up a wireless network and want to use WPA2 encryption. You have the choice between WPA2-Personal and WPA2-Enterprise. What is the KEY difference between these two modes?",
      "options": [
        "WPA2-Personal is faster than WPA2-Enterprise.",
        "WPA2-Personal uses a pre-shared key (PSK) for authentication, while WPA2-Enterprise uses 802.1X authentication with a RADIUS server for individual user authentication.",
        "WPA2-Enterprise is only for large businesses.",
        "WPA2-Personal is more secure than WPA2-Enterprise."
      ],
      "correctAnswerIndex": 1,
      "explanation": "WPA2-Personal uses a shared key for authentication, making it suitable for home networks, whereas WPA2-Enterprise uses 802.1X and a RADIUS server for individual authentication, which is more secure for enterprise environments.",
      "examTip": "For corporate networks, use WPA2-Enterprise with 802.1X/RADIUS for stronger, individualized security."
    },
    {
      "id": 45,
      "question": "You are troubleshooting a computer and suspect a problem with a specific Windows service. You want to stop the service, then restart it to see if that resolves the issue. Which command-line tools can you use to manage Windows services?",
      "options": [
        "`net start` and `net stop` (or `sc start` and `sc stop`)",
        "`tasklist` and `taskkill`",
        "`ipconfig` and `ping`",
        "`chkdsk` and `sfc`"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`net start` and `net stop` (or the more detailed `sc start` and `sc stop`) are used to control Windows services.",
      "examTip": "Manage services via the command line using `net start` and `net stop` or `sc` commands, or via the Services console."
    },
    {
      "id": 46,
      "question": "Which type of malware often masquerades as legitimate software but performs malicious actions in the background?",
      "options": [
        "Virus",
        "Trojan horse",
        "Worm",
        "Spyware"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A Trojan horse disguises itself as a legitimate program to trick users into installing it, after which it performs malicious activities in the background.",
      "examTip": "Be cautious when downloading software from untrusted sources; Trojans often hide within seemingly legitimate applications."
    },
    {
      "id": 47,
      "question": "A user reports that their computer is displaying unusual error messages and behaving erratically. You suspect a problem with the system files. Which Windows command-line tool can you use to scan for and automatically repair corrupted system files?",
      "options": [
        "chkdsk",
        "sfc /scannow",
        "defrag",
        "diskpart"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`sfc /scannow` scans and repairs protected system files on Windows.",
      "examTip": "Run `sfc /scannow` to repair corrupted system files if you suspect system instability due to file corruption."
    },
    {
      "id": 48,
      "question": "What is the purpose of using a VPN (Virtual Private Network) when connecting to a public Wi-Fi hotspot?",
      "options": [
        "To speed up your internet connection.",
        "To encrypt your internet traffic and protect your data from eavesdropping by others on the same network.",
        "To block access to certain websites.",
        "To prevent viruses from infecting your computer."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A VPN encrypts your network traffic, which is especially important on unsecured public Wi-Fi, protecting your data from potential eavesdroppers.",
      "examTip": "Always use a VPN on public Wi-Fi to safeguard your data from interception."
    },
    {
      "id": 49,
      "question": "You are troubleshooting a network connectivity issue where a computer cannot access any network resources. The computer has an IP address in the 169.254.x.x range. What does this indicate?",
      "options": [
        "The computer has a static IP address configured.",
        "The computer is successfully connected to the network.",
        "The computer is configured to obtain an IP address automatically (DHCP), but it is unable to reach a DHCP server.",
        "The computer has a virus."
      ],
      "correctAnswerIndex": 2,
      "explanation": "An IP address in the 169.254.x.x range indicates that the computer has assigned itself an APIPA address because it was unable to obtain one from a DHCP server.",
      "examTip": "An APIPA address (169.254.x.x) almost always points to a DHCP issue."
    },
    {
      "id": 50,
      "question": "You are configuring user accounts on a Windows computer. What is the KEY difference between a 'Standard User' account and an 'Administrator' account?",
      "options": [
        "Standard User accounts can only access the internet.",
        "Administrator accounts have full control over the computer and can make system-wide changes (install software, change settings, etc.), while Standard User accounts have limited privileges.",
        "Standard User accounts are for temporary use only.",
        "Administrator accounts are only for IT professionals."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Administrator accounts have full privileges and control over the system, whereas Standard User accounts have limited rights to prevent unauthorized system changes, following the principle of least privilege.",
      "examTip": "Always use Standard User accounts for everyday tasks and reserve Administrator accounts for system management."
    },    
    {
      "id": 51,
      "question": "A user reports that their computer is running slowly. You open Task Manager and notice that a process called `explorer.exe` is consuming an unusually high amount of CPU resources. What is `explorer.exe` normally responsible for, and what might be causing the high CPU usage in this case?",
      "options": [
        "`explorer.exe` is a web browser; the user probably has too many tabs open.",
        "`explorer.exe` is the Windows File Explorer and the Windows shell (desktop, taskbar, etc.); high CPU usage could be caused by a corrupted shell extension, a malfunctioning third-party program that integrates with Explorer, or potentially malware.",
        "`explorer.exe` is a system process that cannot be safely terminated; high CPU usage is normal.",
        "`explorer.exe` is a virus; you should immediately delete it."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`explorer.exe` is the core process for the Windows File Explorer (browsing files and folders) *and* the Windows shell (the desktop, taskbar, Start menu, etc.). High CPU usage by `explorer.exe` is not normal and can indicate a problem with a shell extension, a corrupted system file, a conflict with another program, or even malware.",
      "examTip": "Troubleshoot high CPU usage by `explorer.exe` by checking for corrupted shell extensions using tools like ShellExView and investigating potential software conflicts or malware."
    },
    {
      "id": 52,
      "question": "What is the function of the BIOS (Basic Input/Output System) or UEFI (Unified Extensible Firmware Interface) on a computer?",
      "options": [
        "To store user data.",
        "To initialize and test the system hardware during startup (POST - Power-On Self-Test) and to load the boot loader (which then loads the operating system).",
        "To manage network connections.",
        "To provide a graphical user interface for the operating system."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The BIOS/UEFI is firmware on the motherboard that initializes hardware during startup (POST) and loads the boot loader to start the operating system.",
      "examTip": "Remember that BIOS/UEFI is the first code that runs at startup, responsible for hardware initialization and booting the OS."
    },
    {
      "id": 53,
      "question": "You are configuring a new hard drive in Windows. You have the choice between using MBR (Master Boot Record) and GPT (GUID Partition Table) partitioning schemes. What is a KEY advantage of GPT over MBR?",
      "options": [
        "GPT is compatible with older operating systems.",
        "GPT supports larger hard drives (above 2TB) and more partitions, and it includes features for data integrity and recovery.",
        "MBR is more secure than GPT.",
        "MBR is easier to use than GPT."
      ],
      "correctAnswerIndex": 1,
      "explanation": "GPT supports drives larger than 2TB, more partitions, and includes data integrity features such as CRC checksums—advantages that MBR does not offer.",
      "examTip": "Use GPT for new hard drive installations, especially when dealing with drives larger than 2TB or on systems with UEFI firmware."
    },
    {
      "id": 54,
      "question": "You are troubleshooting a computer that is not booting. You hear a series of beeps during the POST (Power-On Self-Test). What do these beeps typically indicate?",
      "options": [
        "The computer is successfully booting.",
        "A hardware error has been detected; the specific beep code often corresponds to a particular type of hardware problem (RAM, video card, etc.).",
        "The operating system is loading.",
        "The network connection is established."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Beep codes during POST are diagnostic signals that indicate hardware issues. The specific pattern of beeps can help pinpoint the faulty component.",
      "examTip": "Consult the motherboard documentation to interpret beep codes; they provide valuable clues about hardware failures."
    },
    {
      "id": 55,
      "question": "What is the 'principle of least privilege' in the context of user account management?",
      "options": [
        "Standard User accounts can only access the internet.",
        "Administrator accounts have full control over the computer and can make system-wide changes, while Standard User accounts have limited privileges.",
        "Standard User accounts are for temporary use only.",
        "Administrator accounts are only for IT professionals."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The principle of least privilege means granting users only the access necessary to perform their tasks, thereby reducing the risk of accidental or malicious changes.",
      "examTip": "Always use Standard User accounts for day-to-day tasks and reserve Administrator accounts for system management."
    },
    {
      "id": 56,
      "question": "You are troubleshooting a network connectivity issue. A computer can ping its default gateway and other local devices, but it cannot access any websites. `nslookup` resolves domain names correctly. What is the NEXT most likely area to investigate?",
      "options": [
        "The network cable.",
        "The computer's firewall settings, proxy server settings, and the 'hosts' file.",
        "The DNS server configuration.",
        "The computer's network adapter driver."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Since basic connectivity and DNS resolution are working, the issue is likely related to the browser or local configuration (such as firewall or proxy settings, or an altered 'hosts' file).",
      "examTip": "When connectivity and DNS are confirmed, examine browser settings, proxy configurations, and the 'hosts' file."
    },
    {
      "id": 57,
      "question": "What is 'data exfiltration' in the context of cybersecurity?",
      "options": [
        "The process of backing up data.",
        "The unauthorized transfer of data from a computer or network to an external location.",
        "The encryption of data.",
        "The process of deleting data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Data exfiltration refers to the unauthorized transfer of data out of a network, often by an attacker aiming to steal sensitive information.",
      "examTip": "Monitor for unusual outbound traffic and large data transfers as possible signs of data exfiltration."
    },
    {
      "id": 58,
      "question": "You are configuring a new Linux server and want to ensure that only specific users are allowed to log in remotely via SSH. Which configuration file would you edit to control SSH access?",
      "options": [
        "/etc/hosts",
        "/etc/passwd",
        "/etc/ssh/sshd_config",
        "/etc/group"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The SSH server configuration file (`/etc/ssh/sshd_config`) is used to control access settings for SSH, including allowed users and authentication methods.",
      "examTip": "Edit `/etc/ssh/sshd_config` to configure and secure SSH access on Linux."
    },
    {
      "id": 59,
      "question": "You are troubleshooting a computer that is exhibiting slow performance. You open Task Manager and observe that the disk utilization is consistently very high (close to 100%), even when the system is idle. What is the BEST tool to use to identify which specific files are being accessed and causing the high disk I/O?",
      "options": [
        "Task Manager",
        "Resource Monitor (specifically the Disk tab)",
        "Performance Monitor",
        "Disk Defragmenter"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Resource Monitor's Disk tab provides detailed information on disk I/O at the file level, which helps pinpoint the source of high disk activity.",
      "examTip": "Use Resource Monitor to drill down into disk I/O issues and identify the specific files and processes responsible."
    },
    {
      "id": 60,
      "question": "What is the purpose of using a 'sandbox' environment in software testing or security analysis?",
      "options": [
        "To provide a high-performance environment for running applications.",
        "To isolate potentially untrusted or malicious code from the main operating system, allowing it to be run and analyzed safely.",
        "To back up important data.",
        "To encrypt sensitive data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A sandbox isolates code execution in a controlled environment, preventing potentially malicious software from affecting the main system.",
      "examTip": "Use sandbox environments to safely test untrusted software or analyze malware without risking your production system."
    },
    {
      "id": 61,
      "question": "You are troubleshooting a Windows computer that is experiencing intermittent problems. You suspect a problem with a device driver. Which Windows utility allows you to enable 'Driver Verifier' to stress-test drivers and identify potential issues?",
      "options": [
        "Device Manager",
        "verifier.exe",
        "msconfig.exe",
        "devmgmt.msc"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`verifier.exe` is the tool used to enable Driver Verifier, which stresses drivers to reveal problematic ones.",
      "examTip": "Use Driver Verifier (via `verifier.exe`) to diagnose driver-related issues, but be prepared to disable it if the system becomes unstable."
    },
    {
      "id": 62,
      "question": "A user reports that their computer is making a beeping sound during startup, and the system fails to boot. You suspect a hardware problem. What is the FIRST thing you should do?",
      "options": [
        "Reinstall the operating system.",
        "Consult the motherboard manufacturer's documentation to determine the meaning of the specific beep code.",
        "Replace the hard drive.",
        "Replace the RAM."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Before taking any hardware replacement action, consult the motherboard documentation to decode the beep code, which will indicate the likely faulty component.",
      "examTip": "Beep codes during POST provide diagnostic clues; always refer to the motherboard manual for interpretation."
    },
    {
      "id": 63,
      "question": "You are configuring a web server and want to ensure that all communication between clients and the server is encrypted. Which protocol should you use?",
      "options": [
        "HTTP",
        "HTTPS",
        "FTP",
        "Telnet"
      ],
      "correctAnswerIndex": 1,
      "explanation": "HTTPS uses SSL/TLS to encrypt communication between a web server and clients, protecting data from interception.",
      "examTip": "Always use HTTPS for secure communication on websites, especially when transmitting sensitive data."
    },
    {
      "id": 64,
      "question": "You are troubleshooting a network printer that is not printing. You can ping the printer's IP address successfully, and other users can print to it. The user's computer has a valid IP address and network connectivity. What is the NEXT step to investigate?",
      "options": [
        "Check the printer's toner level.",
        "Check the print queue on the user's computer, verify that the correct printer is selected as the default, and check the printer driver on the user's computer.",
        "Restart the printer.",
        "Replace the network cable connecting the printer to the network."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Since the printer is reachable and working for other users, the issue is likely local to the user's computer (e.g., print queue or driver issues).",
      "examTip": "When troubleshooting printing issues that appear isolated to one computer, first check the print queue and printer configuration on that system."
    },
    {
      "id": 65,
      "question": "You are using the `ipconfig` command in Windows. What is the purpose of the `/release` and `/renew` switches?",
      "options": [
        "To display detailed network configuration information.",
        "To release the current DHCP-assigned IP address (/release) and request a new IP address from the DHCP server (/renew).",
        "To flush the DNS resolver cache.",
        "To register the computer's hostname with the DNS server."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`ipconfig /release` and `/renew` are used to drop the current DHCP lease and request a new one, which can help resolve IP configuration issues.",
      "examTip": "Use `ipconfig /release` and `/renew` when troubleshooting DHCP-related connectivity problems."
    },
    {
      "id": 66,
      "question": "A user reports that they are unable to access files on a network share. You've verified that the file server is online, other users can access the share, and the user has the correct permissions. You suspect a problem with the user's workstation. Which of the following is LEAST likely to be the cause?",
      "options": [
        "The user's computer is not connected to the network.",
        "The user's workstation has a firewall rule blocking access to the file server or the SMB protocol.",
        "There is an SMB protocol version incompatibility or signing mismatch between the client and server.",
        "The user's account is locked out."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If the computer were not connected to the network, basic connectivity tests (like ping) would fail. Since other network functions work, the connectivity is likely fine.",
      "examTip": "If the computer is connected (as verified by pings), then issues like SMB settings or firewall rules are more likely causes than network disconnection."
    },
    {
      "id": 67,
      "question": "You are analyzing network traffic with Wireshark. You see a large number of packets with the SYN flag set, but relatively few corresponding SYN-ACK or ACK packets. What type of network activity does this MOST likely indicate?",
      "options": [
        "Normal web browsing.",
        "A SYN flood attack (a type of denial-of-service attack).",
        "File transfer using FTP.",
        "Email communication."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A SYN flood attack involves sending many SYN packets without completing the handshake, overwhelming the target with half-open connections.",
      "examTip": "A high number of SYN packets compared to SYN-ACK/ACK responses is indicative of a SYN flood attack."
    },
    {
      "id": 68,
      "question": "You are troubleshooting a Windows computer that is experiencing performance issues. You open Task Manager and notice that a process named `csrss.exe` is consuming a significant amount of CPU resources. What is `csrss.exe` normally responsible for, and is high CPU usage by this process typically a cause for concern?",
      "options": [
        "`csrss.exe` is a web browser; high CPU usage is normal.",
        "`csrss.exe` (Client Server Runtime Subsystem) is a critical Windows system process involved in console windows, thread management, and aspects of the 16-bit virtual MS-DOS environment; high CPU usage is usually a sign of a serious problem.",
        "`csrss.exe` is a third-party application; you should uninstall it.",
        "`csrss.exe` is a virus; you should immediately delete it."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`csrss.exe` is a critical Windows system process. Although it should run continuously, abnormally high CPU usage by it can indicate serious issues such as system file corruption or malware interference.",
      "examTip": "Investigate high CPU usage by `csrss.exe` carefully—it may indicate a deeper system problem requiring further diagnosis."
    },
    {
      "id": 69,
      "question": "What is the purpose of the `chkdsk` command in Windows?",
      "options": [
        "To defragment the hard drive.",
        "To check the hard drive for file system errors and bad sectors, and optionally attempt to repair them.",
        "To display disk usage information.",
        "To create a new partition."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`chkdsk` scans the hard drive for file system and physical errors and can repair issues if run with appropriate switches.",
      "examTip": "Run `chkdsk /f` and `chkdsk /r` to fix file system errors and check for bad sectors, respectively."
    },
    {
      "id": 70,
      "question": "You are configuring a Linux system and want to view the currently mounted file systems, their mount points, and their usage statistics. Which command would you use?",
      "options": [
        "lsblk",
        "df -h",
        "du -sh",
        "mount"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`df -h` provides human-readable disk usage information for all mounted file systems, including mount points and available space.",
      "examTip": "Use `df -h` on Linux to quickly assess disk usage on all mounted file systems."
    },
    {
      "id": 71,
      "question": "Which of the following is a characteristic of a 'distributed denial-of-service' (DDoS) attack?",
      "options": [
        "The attacker steals sensitive data from a server.",
        "The attacker uses multiple compromised computers (a botnet) to flood a target with traffic, making it unavailable to legitimate users.",
        "The attacker encrypts files on a computer and demands a ransom.",
        "The attacker tricks users into revealing their passwords."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A DDoS attack involves a distributed network of compromised devices flooding a target with traffic, thereby overwhelming it and denying service to legitimate users.",
      "examTip": "Mitigating DDoS attacks often requires specialized network solutions; monitoring for unusual traffic patterns is key."
    },
    {
      "id": 72,
      "question": "You are troubleshooting a slow Windows computer. You suspect a problem with the hard drive. You've already run `chkdsk`, which found and fixed some errors, but the system is still slow. What is the NEXT BEST step to investigate potential hard drive issues?",
      "options": [
        "Defragment the hard drive (if it's an HDD).",
        "Check the SMART status of the hard drive using a third-party utility or the drive manufacturer's tool.",
        "Run Disk Cleanup.",
        "Reinstall the operating system."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Checking the SMART status provides insights into the drive's internal health and can signal impending failure even if `chkdsk` fixed some errors.",
      "examTip": "Regularly monitor SMART data on hard drives to catch early signs of failure."
    },
    {
      "id": 73,
      "question": "What is 'multi-factor authentication' (MFA), and why is it important for security?",
      "options": [
        "Using a very long password.",
        "Requiring users to provide two or more independent authentication factors (something they know, something they have, something they are) to verify their identity.",
        "Encrypting all network traffic.",
        "Using a firewall."
      ],
      "correctAnswerIndex": 1,
      "explanation": "MFA significantly increases security by requiring multiple forms of verification, making it much harder for attackers to gain access even if one factor is compromised.",
      "examTip": "Implement MFA for critical accounts to add a robust layer of security against unauthorized access."
    },
    {
      "id": 74,
      "question": "You are configuring a secure wireless network. Which of the following combinations of settings provides the STRONGEST security?",
      "options": [
        "WEP encryption with a shared password.",
        "WPA2-Personal with a strong pre-shared key (PSK).",
        "WPA2-Enterprise with 802.1X authentication using a RADIUS server, and AES encryption.",
        "Open network (no encryption)."
      ],
      "correctAnswerIndex": 2,
      "explanation": "WPA2-Enterprise with 802.1X and AES encryption provides robust security through individual user authentication and strong encryption.",
      "examTip": "For corporate environments, choose WPA2-Enterprise (or WPA3-Enterprise) over personal modes for improved security."
    },
    {
      "id": 75,
      "question": "You are troubleshooting a computer that is not booting. The system powers on, but you see no display on the monitor, and you hear no beep codes. You've already checked the monitor and its cable. What is the NEXT step to investigate?",
      "options": [
        "Reinstall the operating system.",
        "Check the power supply connections to the motherboard, reseat the RAM modules, reseat the video card (if applicable), and check for any loose connections. If possible, try a different power supply.",
        "Replace the hard drive.",
        "Replace the network cable."
      ],
      "correctAnswerIndex": 1,
      "explanation": "With no display and no beep codes, the issue is likely with core hardware components such as the power supply, motherboard, RAM, or video card. Reseating components and checking power connections is the next logical step.",
      "examTip": "In a no-display scenario, inspect the internal hardware connections—especially the power supply, motherboard, RAM, and video card."
    },
    {
      "id": 76,
      "question": "You are configuring a Linux server and need to find all files named 'error.log' that have been modified within the last 7 days. Which command would you use?",
      "options": [
        "`grep error.log / -mtime -7`",
        "`find / -name error.log -mtime -7`",
        "`locate error.log -mtime -7`",
        "`ls -l / | grep error.log`"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`find / -name error.log -mtime -7` searches from the root directory for files named 'error.log' modified within the last 7 days.",
      "examTip": "Use `find` with the `-mtime` flag to locate files modified within a specific timeframe on Linux."
    },
    {
      "id": 77,
      "question": "What is 'spear phishing'?",
      "options": [
        "A type of malware that encrypts files.",
        "A highly targeted phishing attack that focuses on a specific individual or organization, often using personalized information to make the attack more convincing.",
        "A type of network attack that floods a server with traffic.",
        "A type of attack that exploits vulnerabilities in software."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Spear phishing involves crafting highly targeted emails using personalized information to deceive a specific individual or group into divulging sensitive data.",
      "examTip": "Be vigilant with emails even if they appear personal; spear phishing attacks are designed to look credible."
    },
    {
      "id": 78,
      "question": "A user reports that they are unable to access a website that they were able to access yesterday. You can access the website from a different computer on the same network. You've already checked the user's browser settings, cleared the cache and cookies, and verified DNS resolution with `nslookup`. What is the NEXT step to investigate on the user's computer?",
      "options": [
        "Reinstall the operating system.",
        "Check the Windows 'hosts' file for any entries that might be blocking or redirecting the website, and check for any third-party firewall or security software that might be blocking access.",
        "Replace the network cable.",
        "Run a virus scan."
      ],
      "correctAnswerIndex": 1,
      "explanation": "If other devices on the same network can access the website, the issue is likely local. The 'hosts' file or third-party security software may be interfering with access.",
      "examTip": "Examine the 'hosts' file and any local firewall or security software when a single computer cannot access a website."
    },
    {
      "id": 79,
      "question": "You are configuring a new server and want to implement a strong password policy. Which of the following settings would be MOST effective in improving password security?",
      "options": [
        "Minimum password length of 6 characters.",
        "Require passwords to be changed every 365 days.",
        "Enforce a minimum password length of at least 12 characters, require a mix of uppercase and lowercase letters, numbers, and symbols, disallow common words or patterns, and enforce regular password changes (e.g., every 90 days).",
        "Allow users to write down their passwords."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A strong password policy requires long, complex, and regularly changed passwords to reduce the risk of unauthorized access.",
      "examTip": "Implement a comprehensive password policy with strict complexity and change requirements to bolster security."
    },
    {
      "id": 80,
      "question": "What is the purpose of the `traceroute` (or `tracert` in Windows) command?",
      "options": [
        "To display the current IP address configuration.",
        "To test network connectivity to a remote host.",
        "To trace the route that packets take to reach a destination, showing each hop and the latency at each hop.",
        "To display active network connections."
      ],
      "correctAnswerIndex": 2,
      "explanation": "`traceroute`/`tracert` maps the path packets take to a destination and measures the time to each hop, helping diagnose network issues.",
      "examTip": "Use `traceroute`/`tracert` to identify network path issues and pinpoint where latency or packet loss is occurring."
    },
    {
      "id": 81,
      "question": "You are working on a Linux system and need to find all files that contain the string 'password' within their content. Which command is BEST suited for this task?",
      "options": [
        "`find / -name password`",
        "`grep -r 'password' /`",
        "`locate password`",
        "`ls -l | grep password`"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`grep -r 'password' /` recursively searches through files for the string 'password', making it ideal for this task.",
      "examTip": "Use `grep -r` to search recursively within files on Linux."
    },
    {
      "id": 82,
      "question": "You are troubleshooting a Windows computer and suspect that a recently installed program is causing system instability. You want to prevent this program from starting automatically when Windows boots. Which of the following methods is LEAST effective for achieving this?",
      "options": [
        "Disabling the program in Task Manager's Startup tab.",
        "Removing the program's shortcut from the Startup folder in the Start Menu.",
        "Deleting the program's executable file.",
        "Using the System Configuration utility (msconfig.exe) to disable the program's startup entry."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Deleting the program's executable file is a risky and drastic measure that can lead to further issues. Standard methods such as disabling startup entries are preferable.",
      "examTip": "Manage startup programs using Task Manager, Startup folder, or msconfig rather than deleting executable files."
    },
    {
      "id": 83,
      "question": "What is the purpose of enabling 'two-factor authentication' (2FA) or 'multi-factor authentication' (MFA) on an account?",
      "options": [
        "To make it easier to remember your password.",
        "To add an extra layer of security by requiring two or more independent authentication factors to verify your identity.",
        "To speed up the login process.",
        "To encrypt your password."
      ],
      "correctAnswerIndex": 1,
      "explanation": "2FA/MFA increases security by requiring multiple forms of verification, significantly reducing the risk of unauthorized access even if one factor (like a password) is compromised.",
      "examTip": "Enable MFA for critical accounts to add a robust layer of security."
    },
    {
      "id": 84,
      "question": "A user reports that their computer is displaying a message stating that their files have been encrypted and they need to pay a ransom to get them back. The user does NOT have any recent backups. What is the BEST course of action?",
      "options": [
        "Pay the ransom immediately.",
        "Disconnect the computer from the network, contact a cybersecurity professional or law enforcement, and do NOT pay the ransom without expert advice.",
        "Reinstall the operating system.",
        "Run a virus scan."
      ],
      "correctAnswerIndex": 1,
      "explanation": "This scenario indicates a ransomware attack. The recommended action is to disconnect the machine, seek expert guidance, and avoid paying the ransom as it doesn't guarantee file recovery.",
      "examTip": "Always keep offline backups and consult professionals when faced with ransomware; paying the ransom is not advised."
    },
    {
      "id": 85,
      "question": "You are using the `netstat` command in Windows to analyze network connections. You want to see all listening ports and the associated process IDs in numerical form. Which command would you use?",
      "options": [
        "netstat -a",
        "netstat -an",
        "netstat -b",
        "netstat -o"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`netstat -an` displays all active connections and listening ports in numerical format, including process IDs.",
      "examTip": "Use `netstat -an` to view network connections with numerical addresses and process IDs."
    },
    {
      "id": 86,
      "question": "Which of the following actions would be MOST helpful in preventing social engineering attacks?",
      "options": [
        "Installing antivirus software.",
        "Educating users about common social engineering tactics and how to recognize and avoid them.",
        "Using a strong firewall.",
        "Encrypting all network traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Social engineering targets human vulnerabilities. Educating users is the most effective way to prevent such attacks.",
      "examTip": "Regular security training is crucial to defend against social engineering."
    },
    {
      "id": 87,
      "question": "What is the primary purpose of a 'honeypot' in network security?",
      "options": [
        "To encrypt sensitive data.",
        "To filter network traffic.",
        "To attract and trap attackers, allowing security professionals to study their methods and gather intelligence.",
        "To provide a secure connection for remote access."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A honeypot is designed as a decoy system to lure attackers, enabling analysis of their techniques and intentions.",
      "examTip": "Honeypots can be invaluable for understanding attacker behavior and improving overall security defenses."
    },
    {
      "id": 88,
      "question": "A user reports that their computer is running slowly. You open Task Manager and see that the CPU utilization is consistently high, and a process named `svchost.exe` is consuming a large amount of resources. What is the NEXT step to identify the specific service causing the high CPU usage?",
      "options": [
        "End the `svchost.exe` process.",
        "Reinstall the operating system.",
        "Use Resource Monitor (resmon.exe) to expand the CPU section and the 'Services' subsection, or use `tasklist /svc` to see which services are running within `svchost.exe`.",
        "Run Disk Cleanup."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Resource Monitor or the `tasklist /svc` command will provide details about which specific service within `svchost.exe` is responsible for high CPU usage.",
      "examTip": "Drill down into `svchost.exe` using Resource Monitor or `tasklist /svc` to pinpoint the problematic service."
    },
    {
      "id": 89,
      "question": "You are configuring a firewall and want to allow users on your internal network to access websites on the internet. Which type of firewall rule should you create?",
      "options": [
        "An inbound rule.",
        "An outbound rule allowing traffic on ports 80 (HTTP) and 443 (HTTPS).",
        "A port forwarding rule.",
        "A DMZ rule."
      ],
      "correctAnswerIndex": 1,
      "explanation": "To allow internal users to access the internet, create an outbound rule permitting traffic on HTTP and HTTPS ports.",
      "examTip": "Differentiate between inbound and outbound rules: outbound rules control traffic leaving your network."
    },
    {
      "id": 90,
      "question": "What is 'cross-site request forgery' (CSRF or XSRF)?",
      "options": [
        "A type of malware that encrypts files.",
        "An attack that forces an end user to execute unwanted actions on a web application in which they are currently authenticated.",
        "A type of social engineering attack.",
        "A type of denial-of-service attack."
      ],
      "correctAnswerIndex": 1,
      "explanation": "CSRF is a web attack that tricks an authenticated user into submitting a request that they did not intend, potentially causing unwanted actions on a web application.",
      "examTip": "Implement anti-CSRF tokens in web applications to prevent these types of attacks."
    },
    {
      "id": 91,
      "question": "You are working with a Linux system and need to determine the IP address, subnet mask, and default gateway configured on a network interface. Which command provides this information in a clear and concise format?",
      "options": [
        "ifconfig",
        "ip addr show",
        "netstat -r",
        "route -n"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`ip addr show` displays detailed network interface information including IP address and subnet mask. (Note: `ifconfig` can also be used on older systems.)",
      "examTip": "Use `ip addr show` on modern Linux systems to view interface configurations."
    },
    {
      "id": 92,
      "question": "What is a 'rainbow table' in the context of password cracking?",
      "options": [
        "A table of common passwords.",
        "A precomputed table of password hashes used to quickly look up the plaintext password corresponding to a given hash.",
        "A table of encryption keys.",
        "A table of network addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Rainbow tables are precomputed tables of hash values that allow attackers to reverse cryptographic hash functions for common passwords.",
      "examTip": "Strong, unique passwords and salting hashes are effective defenses against rainbow table attacks."
    },
    {
      "id": 93,
      "question": "You are troubleshooting a Windows computer that is experiencing network connectivity problems. You suspect a problem with the TCP/IP stack. Which command-line tool can you use to reset the TCP/IP stack to its default configuration?",
      "options": [
        "`ipconfig /release`",
        "`ipconfig /renew`",
        "`netsh int ip reset`",
        "`ipconfig /flushdns`"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`netsh int ip reset` resets the TCP/IP stack to its default settings, which can resolve many network connectivity issues.",
      "examTip": "Use `netsh int ip reset` when TCP/IP settings appear to be causing network problems."
    },
    {
      "id": 94,
      "question": "A user reports that their computer is running slowly and showing unusual network activity. You suspect malware. You've already run a full system scan with your antivirus, but nothing was detected. What is the NEXT BEST step?",
      "options": [
        "Reinstall the operating system.",
        "Run a scan with a different anti-malware tool, preferably one that specializes in rootkit detection or use a bootable rescue disk.",
        "Disconnect the computer from the network.",
        "Delete any unfamiliar files or programs."
      ],
      "correctAnswerIndex": 1,
      "explanation": "If one tool doesn't detect malware, a second opinion from another anti-malware program (especially one that targets rootkits) or a bootable rescue disk can be very effective.",
      "examTip": "Try a different anti-malware solution if initial scans come up clean, particularly for stubborn or hidden threats."
    },
    {
      "id": 95,
      "question": "You are configuring a web server and want to ensure secure communication using HTTPS. You've obtained an SSL/TLS certificate from a Certificate Authority (CA). What is the NEXT step to enable HTTPS on the server?",
      "options": [
        "Install the SSL/TLS certificate on the web server and configure the web server software (e.g., IIS, Apache) to use the certificate for HTTPS connections (typically on port 443).",
        "Install the certificate on all client computers.",
        "Change the website's URL to use 'https://'.",
        "Configure the firewall to block all traffic on port 80."
      ],
      "correctAnswerIndex": 0,
      "explanation": "After obtaining the certificate, you must install it on the web server and configure your web server software to enable HTTPS connections.",
      "examTip": "Ensure your web server is properly configured with your SSL/TLS certificate to support secure HTTPS connections."
    },
    {
      "id": 96,
      "question": "You are troubleshooting a network connectivity problem on a Linux server. You want to see which processes are currently listening for incoming network connections. Which command would you use?",
      "options": [
        "ifconfig",
        "ip addr show",
        "`netstat -tulnp` (or `ss -tulnp` on newer systems)",
        "route -n"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`netstat -tulnp` (or `ss -tulnp`) displays all listening TCP and UDP ports along with the associated process IDs, which is ideal for troubleshooting.",
      "examTip": "Use `netstat -tulnp` (or `ss -tulnp`) to identify which processes are listening on specific ports in Linux."
    },
    {
      "id": 97,
      "question": "You are investigating a potential security breach on a Windows server. You need to review the security audit logs to see who has been accessing specific files and folders. Where would you find these logs?",
      "options": [
        "Task Manager",
        "Resource Monitor",
        "Event Viewer (specifically the Security log), assuming that object access auditing has been enabled.",
        "System Information (msinfo32.exe)"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Security-related events, including file and folder accesses (if auditing is enabled), are logged in the Security log in Event Viewer.",
      "examTip": "Ensure object access auditing is enabled to capture file and folder access events in the Security log."
    },
    {
      "id": 98,
      "question": "A user reports that their computer is displaying a 'Bootmgr is missing' error message when they try to start their Windows computer. What is the recommended FIRST step to attempt to repair this issue?",
      "options": [
        "Reinstall the operating system.",
        "Replace the hard drive.",
        "Boot from the Windows installation media (DVD or USB) and use the Recovery Environment to run Startup Repair.",
        "Run a virus scan."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Booting from installation media and using Startup Repair is the recommended first step to fix Bootmgr issues without resorting to a complete OS reinstall.",
      "examTip": "Use the Windows Recovery Environment and Startup Repair to address Bootmgr errors before considering more drastic measures."
    },
    {
      "id": 99,
      "question": "You are configuring a new wireless network. You want to use WPA2 encryption. You have the choice of using TKIP or AES for the encryption algorithm. Which algorithm should you choose, and why?",
      "options": [
        "TKIP, because it is faster than AES.",
        "AES, because it is a stronger and more secure encryption algorithm than TKIP.",
        "TKIP, because it is compatible with older devices.",
        "AES, because it is easier to configure than TKIP."
      ],
      "correctAnswerIndex": 1,
      "explanation": "AES is a far stronger encryption standard than TKIP. Although TKIP was an interim solution, AES is recommended for modern WPA2 networks due to its enhanced security.",
      "examTip": "For WPA2 networks, always choose AES over TKIP for optimal security."
    },
    {
      "id": 100,
      "question": "You are troubleshooting a Windows laptop that is running very slowly. You open Task Manager and notice that disk activity is constantly at 100%, even when the system is idle. The laptop uses an SSD, and you've already ruled out malware and verified that SMART status is healthy. What is the NEXT BEST step to investigate?",
      "options": [
        "Run Disk Defragmenter.",
        "Use Resource Monitor (resmon.exe) to identify which specific processes and files are causing high disk I/O; also check for driver issues and update SSD firmware if necessary.",
        "Run Disk Cleanup.",
        "Increase the size of the paging file."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Constant 100% disk activity on an SSD is unusual. Using Resource Monitor will help pinpoint the process or file causing the issue. Additionally, verifying storage driver functionality and SSD firmware can help resolve such performance problems.",
      "examTip": "Never defragment an SSD; instead, use Resource Monitor to investigate high disk I/O and consider updating drivers and firmware."
    }
  ]
});
