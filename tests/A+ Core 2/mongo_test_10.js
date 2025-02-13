db.tests.insertOne({
  "category": "aplus2",
  "testId": 10,
  "testName": "Practice Test #10 (Ultra Level)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A Windows server is experiencing intermittent performance degradation. Users report that applications are slow to respond, and file access is sluggish.  You've ruled out common causes like high CPU utilization, memory exhaustion, and disk I/O bottlenecks.  Network connectivity is stable.  You suspect a problem with the *kernel-mode* handling of I/O requests. Which tool, and what specific technique, would provide the MOST detailed, low-level insight into the kernel's I/O operations, allowing you to potentially identify a driver or hardware issue causing the slowdown?",
      "options": [
        "Task Manager; examine CPU usage.",
        "Resource Monitor; examine disk I/O.",
        "Event Viewer; examine the System log.",
        "Windows Performance Recorder (WPR) to capture an *Xperf trace* with detailed I/O stack traces, and then analyze the trace using Windows Performance Analyzer (WPA).  Specifically, look for long I/O request packet (IRP) completion times and examine the stack traces to identify the responsible drivers or components.",
        "Process Explorer, Check running processes"
      ],
      "correctAnswerIndex": 3,
      "explanation": "For deep, kernel-level I/O analysis, WPR/WPA with Xperf tracing is required. Xperf captures *extremely* detailed information about kernel-mode operations, including I/O request packets (IRPs) and their associated stack traces. Analyzing the IRP completion times and stack traces in WPA can reveal which drivers or hardware components are causing delays in I/O processing. Task Manager and Resource Monitor provide higher-level performance data. Event Viewer *might* contain relevant error messages, but WPR/WPA provides much more granular, real-time tracing. Process Explorer checks running processes.",
      "examTip": "For deep dives into Windows kernel-mode behavior, learn to use WPR/WPA with Xperf tracing; it provides unparalleled visibility into I/O operations, driver behavior, and other low-level system activity."
    },
    {
      "id": 2,
      "question": "You are investigating a potential security breach on a Linux server. You suspect that an attacker might have gained root access and installed a rootkit to conceal their activities.  You've already checked common system directories and log files. What is a MORE ADVANCED technique, involving examining the *kernel's* loaded modules, that you can use to try to detect a potentially malicious kernel module?",
      "options": [
        "Run `ps aux` to view running processes.",
        "Examine the output of `lsmod` (which lists loaded kernel modules) and compare it to a known-good baseline (if available). Look for modules with unusual names, unexpected dependencies, or missing information.  Also, consider using a specialized rootkit detection tool (like `chkrootkit` or `rkhunter`), but be aware that advanced rootkits can sometimes evade these tools.",
        "Check the `/etc/passwd` file for new user accounts.",
        "Examine the `/var/log/auth.log` file for login attempts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Kernel-mode rootkits often operate by modifying or adding kernel modules. Examining the loaded kernel modules (`lsmod`) and comparing them to a known-good baseline (a list of expected modules on a clean system) can help identify suspicious modules. Look for modules with unusual names, unexpected dependencies, or missing version information. Specialized rootkit detection tools can help, but advanced rootkits might be able to evade them. `ps aux` shows running processes, not kernel modules. `/etc/passwd` shows user accounts. `/var/log/auth.log` shows authentication events. While these are important for security investigations, they don't directly reveal loaded kernel modules.",
      "examTip": "Be aware of kernel-mode rootkits and techniques for detecting them, including examining loaded kernel modules (`lsmod`) and comparing them to a known-good baseline."
    },
    {
      "id": 3,
      "question": "A user reports that their Windows computer is intermittently unable to access *any* websites, even though they can ping their default gateway and other devices on their local network. `nslookup` commands *also* fail to resolve *any* domain names.  You've already checked the network cable, and it's good. The user's IP address, subnet mask, and default gateway are correctly configured. What is a specific Windows service that, if stopped or malfunctioning, would cause this *complete* failure of DNS resolution, and how would you check its status?",
      "options": [
        "The 'Network Location Awareness' service; check its status in Control Panel.",
        "The 'DHCP Client' service; check its status in Device Manager.",
        "The 'DNS Client' service (Dnscache); check its status and restart it if necessary using the Services console (`services.msc`) or the command line (`net stop dnscache` and `net start dnscache`).",
        "The 'Windows Firewall' service; check its status in Windows Defender Firewall settings."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The 'DNS Client' service (`Dnscache`) is responsible for resolving and caching DNS names on Windows computers. If this service is stopped or malfunctioning, the computer will be unable to resolve any domain names, even if basic network connectivity (pinging IP addresses) is working. The Network Location Awareness service is for determining network location. The DHCP Client service obtains IP addresses. The Windows Firewall controls network access, but wouldn't directly cause a complete DNS resolution failure.",
      "examTip": "The 'DNS Client' service (`Dnscache`) is crucial for DNS resolution in Windows; if it's stopped or malfunctioning, the computer will be unable to resolve domain names."
    },
    {
      "id": 4,
      "question": "You are troubleshooting a network connectivity issue on a Linux server. You suspect a problem with the routing table. You want to view the routing table, but you also want to see the *interface* associated with each route and have the output displayed *numerically* (without resolving hostnames to IP addresses). Which command is BEST suited for this?",
      "options": [
        "ifconfig",
        "ip addr show",
        "route -n",
        "ip route show"
      ],
      "correctAnswerIndex": 3,
      "explanation": "`ip route show` is the preferred command on modern Linux systems for displaying the kernel's routing table. It provides detailed and accurate information—including the associated interface and numerical addresses—without resolving hostnames.",
      "examTip": "Use `ip route show` on modern Linux systems to view the routing table in detail, including interface associations and numerical addresses."
    },
    {
      "id": 5,
      "question": "You are configuring a web server to use HTTPS. You've obtained a valid SSL/TLS certificate and private key, and you've configured the web server software (e.g., Apache, IIS, Nginx) to use them. However, when you access the website using `https://`, you get a browser error indicating a problem with the certificate *chain*. What does this mean, and how would you resolve it?",
      "options": [
        "The certificate is expired.",
        "The certificate's Common Name (CN) or Subject Alternative Name (SAN) does not match the website's domain name that you are using in the URL.",
        "The browser doesn't trust the Certificate Authority (CA) that issued the certificate, or there's a missing or incorrect intermediate certificate in the chain of trust. You need to ensure that the complete certificate chain (including any intermediate certificates) is properly installed on the web server.",
        "The web server is not listening on port 443."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A 'certificate chain' error means the browser cannot validate the full chain of trust from your certificate back to a trusted root certificate. This usually occurs if an intermediate certificate is missing or misconfigured. The solution is to ensure that the complete certificate chain is correctly installed on the web server.",
      "examTip": "Ensure that the complete certificate chain (including any intermediate certificates) is installed on your web server to avoid certificate chain errors."
    },
    {
      "id": 6,
      "question": "A user reports that their Windows computer is exhibiting very slow performance. Task Manager shows high CPU utilization, but no single process is consuming all the CPU resources. Resource Monitor also shows high CPU, but no specific process stands out. You suspect a driver problem. You've already tried updating and rolling back common drivers (video, network). What is a MORE ADVANCED technique, using built-in Windows tools, to try to pinpoint the *specific driver* causing the high CPU usage?",
      "options": [
        "Run System Restore.",
        "Run Disk Cleanup.",
        "Use the Windows Performance Recorder (WPR) to capture a CPU usage trace, and then analyze the trace using the Windows Performance Analyzer (WPA). This allows you to see CPU usage broken down by process, thread, and module (including drivers), and identify which driver is consuming the most CPU time.",
        "Increase the size of the paging file."
      ],
      "correctAnswerIndex": 2,
      "explanation": "WPR/WPA provides extremely detailed performance tracing. Capturing a CPU trace with WPR and analyzing it in WPA can reveal which modules, including drivers, are consuming CPU time, helping pinpoint the issue.",
      "examTip": "Learn to use WPR and WPA to diagnose CPU usage issues at a low level, including identifying problematic drivers."
    },
    {
      "id": 7,
      "question": "You are troubleshooting a network connectivity issue where a computer can access *some* websites but not others. Pings to the IP addresses of all websites (both working and non-working) are successful. `nslookup` also resolves all domain names correctly. You've checked the 'hosts' file, firewall rules, and proxy settings. You've also reset the TCP/IP stack using `netsh int ip reset`. What is a *very specific* Windows networking component, often associated with security software or VPNs, that could be selectively interfering with network traffic after DNS resolution and before it reaches the application layer, and how would you investigate it?",
      "options": [
        "The Windows Registry.",
        "A potentially misconfigured or malicious LSP (Layered Service Provider). Use the command `netsh winsock show catalog` to list the installed LSPs. Investigate any unfamiliar or suspicious LSPs. You can also try resetting the Winsock catalog with `netsh winsock reset`.",
        "The DNS Client service.",
        "The DHCP Client service."
      ],
      "correctAnswerIndex": 1,
      "explanation": "LSPs (Layered Service Providers) can intercept and modify network traffic. A misconfigured or malicious LSP could selectively interfere with traffic after DNS resolution. Use `netsh winsock show catalog` to list installed LSPs and investigate any anomalies. Resetting with `netsh winsock reset` can help if necessary.",
      "examTip": "Be aware of LSPs in Windows; they can cause selective network interference. Use `netsh winsock show catalog` to review them, and reset if needed."
    },
    {
      "id": 8,
      "question": "You are investigating a potential security incident on a Linux server. You suspect that an attacker might have modified system files to maintain persistence or hide their activities. You want to verify the integrity of critical system files against a known-good baseline. Which tool is BEST suited for this task, assuming it has been properly configured and a baseline has been previously established?",
      "options": [
        "ls -l",
        "AIDE (Advanced Intrusion Detection Environment) or Tripwire.",
        "grep",
        "find"
      ],
      "correctAnswerIndex": 1,
      "explanation": "AIDE and Tripwire are file integrity monitoring tools that compare current file states against a pre-established baseline to detect unauthorized changes.",
      "examTip": "Use file integrity monitoring tools like AIDE or Tripwire on Linux to detect unauthorized modifications to critical system files."
    },
    {
      "id": 9,
      "question": "You are troubleshooting a website that is intermittently unavailable. You've ruled out DNS issues and network connectivity problems. You suspect a problem with the web server itself. You have access to the server's logs. What specific types of log files, and what specific entries or patterns within those logs, would you examine to try to diagnose the cause of the intermittent unavailability?",
      "options": [
        "The Windows System log.",
        "The web server's access logs (to see if requests are reaching the server), error logs (to identify any errors or exceptions occurring on the server), and potentially application-specific logs (if the website uses a framework or CMS that has its own logging). Look for error messages, timeouts, resource exhaustion indicators, and unusual patterns of requests.",
        "The user's browser history.",
        "The DHCP server logs."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Web server access and error logs (and any application-specific logs) can reveal whether requests are reaching the server and what errors or resource issues are occurring. This information is key to diagnosing intermittent availability problems.",
      "examTip": "Examine the web server's access logs, error logs, and application logs to identify issues like timeouts, errors, or resource exhaustion."
    },
    {
      "id": 10,
      "question": "You are using the `tcpdump` command on a Linux system to capture network traffic. You want to capture *only* traffic that is destined for a specific IP address (192.168.1.100) or originates from that IP address, regardless of the port or protocol. Which `tcpdump` command would achieve this?",
      "options": [
        "`tcpdump -i any port 80`",
        "`tcpdump -i any host 192.168.1.100`",
        "`tcpdump -i any src host 192.168.1.100`",
        "`tcpdump -i any dst host 192.168.1.100`"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Using `tcpdump -i any host 192.168.1.100` captures traffic that has 192.168.1.100 as either the source or the destination IP address, regardless of port or protocol.",
      "examTip": "Use the `host` filter in tcpdump to capture all traffic to or from a specific IP address."
    },
    {
      "id": 11,
      "question": "A user reports that their Windows computer is exhibiting slow performance and unusual behavior. You suspect a malware infection, but standard antivirus scans have not detected anything. You want to examine the system's network connections to see if there are any suspicious connections to unknown or malicious hosts. Which command-line tool, combined with thorough research of the identified IP addresses and ports, is BEST suited for this task on a Windows system?",
      "options": [
        "ping",
        "tracert",
        "`netstat -ano` (and then use Task Manager or Process Explorer to identify the processes associated with suspicious connections) combined with online research of the identified IP addresses and ports.",
        "ipconfig /all"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`netstat -ano` displays active network connections along with process IDs. This information, when combined with further research into the IP addresses and ports, can help identify suspicious activity.",
      "examTip": "Use `netstat -ano` on Windows to view active network connections and their process IDs; then research the external IPs and ports to identify potential threats."
    },
    {
      "id": 12,
      "question": "You are troubleshooting a network connectivity issue on a Linux server. The server has multiple network interfaces. You need to determine which network interface is currently being used as the *default gateway* for outgoing traffic. Which command is BEST suited for this task?",
      "options": [
        "ifconfig",
        "ip addr show",
        "ip route show | grep default",
        "netstat -i"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Using `ip route show | grep default` quickly displays the default route along with the associated interface, indicating which interface is used for outgoing traffic.",
      "examTip": "Use `ip route show | grep default` on Linux to identify the default gateway and its associated interface."
    },
    {
      "id": 13,
      "question": "You are configuring a web server to use HTTPS. You've obtained an SSL/TLS certificate. What is the purpose of the *private key* associated with the certificate, and why is it CRUCIAL to keep it secure?",
      "options": [
        "The private key is used to encrypt all data sent from the client to the server; it must be kept secret to prevent unauthorized decryption.",
        "The private key is kept secret on the server and is used to *decrypt* data encrypted by the client with the server's *public* key (which is part of the certificate). It is also used to digitally *sign* data sent from the server, proving its authenticity. If the private key is compromised, an attacker can impersonate the server or decrypt sensitive data.",
        "The private key is used to encrypt all data sent from the server to the client; it must be kept secret to prevent unauthorized decryption.",
        "The private key is used to authenticate users to the web server; it must be kept secret to prevent unauthorized access."
      ],
      "correctAnswerIndex": 1,
      "explanation": "In an SSL/TLS certificate pair, the private key is used to decrypt data encrypted with the public key and to digitally sign data sent from the server. Keeping it secure is essential, because if it is compromised, an attacker can impersonate the server or decrypt sensitive information.",
      "examTip": "Protect the private key associated with your SSL/TLS certificate with utmost care; its compromise undermines your HTTPS security."
    },
    {
      "id": 14,
      "question": "A user reports that their Windows computer is displaying a 'Your connection is not private' error message in their web browser when they try to access a specific website. The website uses HTTPS. You've verified that the website's SSL/TLS certificate is *not* expired. What are some OTHER potential causes of this error, and how would you troubleshoot them?",
      "options": [
        "The user's computer has a faulty network cable.",
        "The website's server is down.",
        "The user's DNS server settings are incorrect.",
        "The website's SSL/TLS certificate's Common Name (CN) or Subject Alternative Name (SAN) does not match the domain name the user is trying to access; or the browser does not trust the Certificate Authority (CA) that issued the certificate (or an intermediate CA in the chain); or the user's computer's date and time are incorrect; or there's a man-in-the-middle attack in progress.  Troubleshooting steps: Check the certificate details in the browser, verify the date/time, check for intermediate certificates, try a different browser, and investigate potential MitM attacks."
      ],
      "correctAnswerIndex": 3,
      "explanation": "A 'Your connection is not private' error may be due to a certificate name mismatch, untrusted CA, incorrect system date/time, or a man-in-the-middle attack. The solution is to check the certificate details, system settings, and the certificate chain.",
      "examTip": "Examine certificate details, verify the system's date/time, and ensure the complete certificate chain is installed if you encounter connection privacy errors."
    },
    {
      "id": 15,
      "question": "You are troubleshooting a network connectivity issue on a Linux server. You want to see *all* active network connections, including the local and remote IP addresses and ports, the connection state (ESTABLISHED, LISTEN, etc.), *and* the process ID (PID) and program name associated with each connection. Which command, with appropriate options, is BEST suited for this task?",
      "options": [
        "ifconfig",
        "ip addr show",
        "route -n",
        "`netstat -tulnp` (or `ss -tulnp` on newer systems) is good, but `lsof -i` can provide additional context, especially for identifying potentially hidden processes.",
        "`ss -tunapl`"
      ],
      "correctAnswerIndex": 3,
      "explanation": "While `ss -tunapl` is a powerful command that provides detailed information about active network connections, it is the best single command option listed for this purpose.",
      "examTip": "Use `ss -tunapl` to view active network connections along with process IDs and names on Linux."
    },
    {
      "id": 16,
      "question": "You are investigating a potential security incident on a Windows server. You need to determine if any unauthorized user accounts have been created on the system. You've already checked the Local Users and Groups snap-in (lusrmgr.msc). What is a MORE RELIABLE method to enumerate *all* local user accounts, including potentially hidden ones, and what is a specific technique attackers might use to hide a user account from the standard user management tools?",
      "options": [
        "Check the 'Users' folder on the C: drive.",
        "Use the `net user` command from an elevated command prompt, or use PowerShell: `Get-LocalUser`. Attackers might create an account with a name ending in a '$' (dollar sign), which can make it hidden from some management tools, or they might manipulate the SAM registry hive directly.",
        "Check the Windows Registry.",
        "Look for suspicious files in the 'Program Files' folder."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Using `net user` (or PowerShell's `Get-LocalUser`) from an elevated command prompt will list all local user accounts, including those that might be hidden from the graphical interface. Attackers sometimes append a '$' to a username or manipulate the SAM directly to hide accounts.",
      "examTip": "For complete enumeration of local user accounts on Windows, use `net user` (or `Get-LocalUser`) from an elevated prompt; be aware of techniques like appending '$' to hide accounts."
    },
    {
      "id": 17,
      "question": "You are working on a Linux server and need to analyze the system's memory usage in detail. You want to see not only the total and free memory, but also the amount of memory used by buffers and caches, and the amount of swap space used. Which command provides this information in a human-readable format?",
      "options": [
        "top",
        "free -h",
        "vmstat",
        "df -h"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`free -h` displays memory usage in a human-readable format, including details on RAM, swap, buffers, and caches.",
      "examTip": "Use `free -h` on Linux to quickly view detailed memory usage statistics."
    },
    {
      "id": 18,
      "question": "A user reports that their Windows computer is exhibiting very slow performance when accessing files on a network share. Other users are not experiencing the same problem. You've verified basic network connectivity (ping, nslookup), and the user has the correct permissions to access the share. What is a Windows-specific feature, related to offline file access, that could be causing the slowdown, and how would you check/disable it?",
      "options": [
        "The user's network cable is faulty.",
        "Offline Files (also known as Client-Side Caching or CSC) might be enabled, and the synchronization process might be causing the slowdown. Check the status of Offline Files in the Sync Center (search for 'Sync Center' in the Start menu) and, if necessary, disable it for the specific network share or disable Offline Files entirely.",
        "The user's DNS server settings are incorrect.",
        "The file server is overloaded."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Offline Files is a Windows feature that caches network files locally for offline access. If it is misbehaving, the synchronization process can slow down file access.",
      "examTip": "Check the Sync Center in Windows to determine if Offline Files are affecting network share performance."
    },
    {
      "id": 19,
      "question": "You are troubleshooting a network connectivity issue on a Linux server. A computer can access some websites but not others. Pings to the IP addresses of all websites are successful, and `nslookup` also resolves all domain names correctly. You've checked the 'hosts' file, firewall rules, proxy settings, and for malicious LSPs, and they all appear to be correct or have been addressed. What is a *very specific*, low-level network setting, related to the size of network packets, that could be causing this selective website access problem, and how would you test it?",
      "options": [
        "The user's network cable is faulty.",
        "The user's web browser is corrupted.",
        "The user's DNS server is misconfigured.",
        "There's a problem with the MTU (Maximum Transmission Unit) settings or Path MTU Discovery along the path to the affected websites. Use the `ping` command with the `-l` option (Windows) or the `-s` option (Linux) to specify different packet sizes, and the `-f` option (Windows) or the Don't Fragment bit set (Linux) to test for MTU issues. Start with a small packet size and gradually increase it until you find the maximum size that works without fragmentation or packet loss."
      ],
      "correctAnswerIndex": 3,
      "explanation": "MTU issues can cause selective connectivity problems if packets exceeding the MTU are dropped or fragmented. Using ping with the Don't Fragment option and varying packet sizes can help determine the maximum packet size that works along the network path.",
      "examTip": "Test for MTU mismatches by using ping with options to prevent fragmentation and gradually increasing packet size."
    },
    {
      "id": 20,
      "question": "You are investigating a suspected security breach on a Linux server. You believe an attacker might have gained root access and installed a rootkit to conceal their activities. You've already checked common system directories and log files. What is a more advanced technique, involving comparing system binaries with known-good copies, that can help detect tampered-with system files?",
      "options": [
        "Run `ps aux` to view running processes.",
        "Check the `/etc/passwd` file for new user accounts.",
        "Use a file integrity checking tool like AIDE, Tripwire, or Samhain (assuming one was previously configured and a baseline was established before the suspected compromise). If a file integrity checker wasn't pre-configured, you could try comparing the checksums (e.g., using `md5sum` or `sha256sum`) of critical system binaries (like `/bin/ls`, `/bin/ps`, `/usr/sbin/sshd`, etc.) against known-good checksums from a trusted source.",
        "Examine the `/var/log/auth.log` file for login attempts."
      ],
      "correctAnswerIndex": 2,
      "explanation": "File integrity checking is crucial for detecting unauthorized modifications to system binaries. Using tools like AIDE or Tripwire, or manually comparing checksums of critical binaries against known-good values, can help identify tampering. This process is more effective if a baseline was established before the incident.",
      "examTip": "Use file integrity monitoring tools or manual checksum comparisons to verify the integrity of critical system binaries."
    },
    {
      "id": 21,
      "question": "You are troubleshooting a Windows computer that is exhibiting slow performance. You open Task Manager and notice that the 'Interrupts' process is consuming a significant amount of CPU time. What does the 'Interrupts' process represent, and what could high CPU usage by this process indicate?",
      "options": [
        "The 'Interrupts' process represents a web browser; high CPU usage is normal.",
        "The 'Interrupts' process represents the CPU time spent handling hardware interrupts. High CPU usage by 'Interrupts' can indicate a hardware problem (a malfunctioning device constantly interrupting the CPU), a driver issue, or, less commonly, a software conflict.",
        "The 'Interrupts' process is a third-party application; you should uninstall it.",
        "The 'Interrupts' process is a virus; you should immediately delete it."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The 'Interrupts' process reflects the CPU time used to handle hardware interrupts. Excessive usage usually suggests a hardware or driver problem causing frequent interrupts.",
      "examTip": "High CPU usage by 'Interrupts' typically indicates hardware or driver issues; investigate connected devices and drivers."
    },
    {
      "id": 22,
      "question": "You are configuring a SOHO router. You want to allow remote access to an internal web server (running on port 8080) from the internet. The server has a private IP address of 192.168.1.100. You also have a second internal server running on 192.168.2.100. You do NOT want to expose any other internal resources to the internet. Which router configuration would achieve this securely, and why is it important to avoid using the DMZ in this scenario?",
      "options": [
        "Enable UPnP (Universal Plug and Play) on the router.",
        "Configure port forwarding to forward external port 8080 to the internal IP address 192.168.1.100, port 8080. Do not forward any traffic to 192.168.2.100. Avoid using the DMZ, as it would expose the entire designated DMZ host to the internet, increasing risk.",
        "Enable the DMZ (demilitarized zone) feature and set the DMZ host to 192.168.1.100.",
        "Configure the router's firewall to block all incoming traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Port forwarding is the secure method to allow external access to a specific internal server without exposing the entire network. The DMZ would expose the entire host, increasing risk.",
      "examTip": "Use port forwarding to restrict external access to a specific internal server, avoiding the broader exposure of a DMZ."
    },
    {
      "id": 23,
      "question": "You are using the `tcpdump` command on a Linux system to capture and analyze network traffic. You want to capture all traffic *to or from* a specific host (IP address 192.168.1.50) and a specific port (port 22), and you want to save the captured packets in a PCAP file named `ssh_traffic.pcap` for later analysis with Wireshark. Which `tcpdump` command would accomplish this?",
      "options": [
        "`tcpdump -i any host 192.168.1.50`",
        "`tcpdump -i any port 22`",
        "`tcpdump -i any host 192.168.1.50 and port 22 -w ssh_traffic.pcap`",
        "`tcpdump -i any host 192.168.1.50 or port 22`"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The command `tcpdump -i any host 192.168.1.50 and port 22 -w ssh_traffic.pcap` captures only traffic that meets both criteria (traffic to/from IP 192.168.1.50 and on port 22) and writes it to the specified file.",
      "examTip": "Combine tcpdump filters with the `-w` option to capture specific traffic for later analysis."
    },
    {
      "id": 24,
      "question": "A user calls in with a computer that blue screens every time on boot. They can get into Safe Mode. What would be the best way to determine what is causing the computer to blue screen?",
      "options": [
        "Event Viewer",
        "MSCONFIG",
        "Resource Monitor",
        "WinDbg Preview and analyze the dump file"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Memory dump files created during BSODs contain detailed information about the crash. Analyzing the dump file with WinDbg Preview is the best way to determine the cause.",
      "examTip": "Use WinDbg to analyze BSOD memory dump files for detailed crash diagnostics."
    },
    {
      "id": 25,
      "question": "You are troubleshooting a computer with multiple hard drives. The computer will not boot and displays the message 'No Operating System Found.' You enter the BIOS and verify that it can see both drives, and the boot order is set to the correct drive. What is the next step?",
      "options": [
        "Replace the hard drive.",
        "Reinstall the operating system.",
        "Boot to installation media, enter the recovery environment and attempt to repair the BCD.",
        "Run a virus scan."
      ],
      "correctAnswerIndex": 2,
      "explanation": "If the BIOS sees the drives and the boot order is correct, but no OS is found, the boot configuration is likely the problem. Booting to installation media and repairing the BCD is the next step.",
      "examTip": "If BIOS detects the drive but no OS is found, attempt to repair the boot configuration using recovery tools."
    },
    {
      "id": 26,
      "question": "You are working on a system that uses BitLocker. The owner forgot their password, and also lost their recovery key. What can you do?",
      "options": [
        "Use a password reset tool.",
        "Reinstall the operating system and restore from a backup. Without the password or recovery key, the data is unrecoverable.",
        "Contact Microsoft for assistance.",
        "Format the drive."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Without the BitLocker password or recovery key, the encrypted data cannot be decrypted and is unrecoverable. The only option is to reinstall the OS and restore from backup.",
      "examTip": "BitLocker requires the password or recovery key to access data; if both are lost, the data cannot be recovered."
    },
    {
      "id": 27,
      "question": "A user calls in complaining that sometimes when they print, the printer prints random characters instead of the document. They are using a USB printer, and the cable is connected securely. You have already reinstalled the print driver. What should you check NEXT?",
      "options": [
        "Check the toner levels.",
        "Run a virus scan.",
        "Try a different USB port and, if possible, a different USB cable. Also check for any physical damage on the printer. Finally attempt to update the printer's firmware.",
        "Restart the print spooler."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Random characters when printing often indicate a communication problem, which can be due to a faulty USB port, cable, or physical damage. Since the driver has been reinstalled, the next step is to check the physical connection and update firmware if needed.",
      "examTip": "Check physical connections (USB port/cable) and update firmware when printing issues produce random characters."
    },
    {
      "id": 28,
      "question": "A technician is plugging in an external hard drive. It has a USB-C port on the drive, and a USB-C port on the computer. Upon plugging in the drive the system is unresponsive. After a reboot the system displays a message about over current on USB port. What could be the cause?",
      "options": [
        "Faulty Motherboard",
        "The USB-C cable is likely only rated for power, and not data. Use a cable rated for both power and data.",
        "Faulty hard drive",
        "Faulty RAM"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A USB-C cable that is only rated for power may not support data transfer properly, leading to over current errors.",
      "examTip": "If over current errors occur with a USB-C device, try a cable rated for both power and data."
    },
    {
      "id": 29,
      "question": "A user is trying to go to your company's website and is receiving an error that says 'This site can't be reached, DNS_PROBE_FINISHED_NXDOMAIN.' You can go to the website just fine. What is likely the cause?",
      "options": [
        "Server is down",
        "Firewall is blocking the user",
        "User has a bad network cable",
        "User has a bad DNS server or the DNS record is incorrect"
      ],
      "correctAnswerIndex": 3,
      "explanation": "NXDOMAIN is a DNS error indicating that the domain name cannot be resolved. Since you can access the site, the user's DNS settings are likely misconfigured or the DNS record is problematic.",
      "examTip": "NXDOMAIN errors point to DNS resolution issues; check the user's DNS configuration."
    },
    {
      "id": 30,
      "question": "A user reports that a computer suddenly shuts off with no warning or error messages, and it does this often. RAM has been tested and is good, CPU temperatures are normal, and the system isn't under load. What is the likely cause?",
      "options": [
        "Motherboard or PSU",
        "CPU",
        "Hard Drive",
        "GPU"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Frequent, sudden shutdowns with no warning typically point to power issues (PSU) or motherboard faults.",
      "examTip": "Investigate the PSU and motherboard when a computer shuts down suddenly without errors."
    },
    {
      "id": 31,
      "question": "A technician is called in to work on a computer, and they get shocked when touching the case. What is the likely cause?",
      "options": [
        "Bad power supply.",
        "Improper grounding of the electrical outlet, or a faulty power supply.",
        "Bad RAM.",
        "Bad motherboard."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A shock when touching the computer case typically indicates an issue with grounding or a faulty power supply.",
      "examTip": "If a computer case gives you a shock, check the outlet's grounding and the PSU for faults."
    },
    {
      "id": 32,
      "question": "A user reports that anytime they go to a website with video, the video plays very choppy, and the audio is out of sync. What is the MOST likely cause?",
      "options": [
        "The user's network connection is slow or unstable.",
        "Outdated or incompatible video drivers, insufficient system resources (especially RAM or GPU), or a misconfigured media player.",
        "The user's computer has a virus.",
        "The website's server is overloaded."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Choppy video and out-of-sync audio are typically caused by local performance issues such as outdated drivers or insufficient system resources, rather than a network problem (assuming basic connectivity is fine).",
      "examTip": "Investigate video driver updates, system resource usage, and media player settings when facing video playback issues."
    },
    {
      "id": 33,
      "question": "A user reports that their Windows computer is experiencing network connectivity problems. `ipconfig /all` shows a valid IP address, subnet mask, default gateway, and DNS servers. You can ping the default gateway and other devices on the local network, but you cannot access any websites. `nslookup` commands consistently fail to resolve domain names. What is the MOST likely cause, and how would you confirm your suspicion?",
      "options": [
        "The user's web browser is corrupted.",
        "The DNS Client service (Dnscache) on the user's computer is stopped or malfunctioning, or there's a problem with the configured DNS servers themselves. Use `nslookup` to query different DNS servers (e.g., Google Public DNS - 8.8.8.8, Cloudflare - 1.1.1.1) to see if the problem is specific to the user's configured DNS servers. Also, check the status of the DNS Client service.",
        "The user's network cable is faulty.",
        "The user's computer has a virus."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Valid network configuration and local connectivity paired with DNS resolution failure point to a DNS-related issue, likely involving the DNS Client service or DNS server problems. Testing with alternative DNS servers can help confirm the problem.",
      "examTip": "When DNS resolution fails despite correct IP configuration, verify the DNS Client service and test using alternative DNS servers with `nslookup`."
    },
    {
      "id": 34,
      "question": "A user reports that their computer will not boot and displays the message 'No Operating System Found.' You have verified in the BIOS that the computer can detect all hard drives, and the boot order is set to the correct drive. What is the next step?",
      "options": [
        "Replace the hard drive.",
        "Reinstall the operating system.",
        "Boot to installation media, enter the recovery environment, and attempt to repair the boot configuration (e.g., using bootrec commands).",
        "Run a virus scan."
      ],
      "correctAnswerIndex": 2,
      "explanation": "If the BIOS detects the drives and the boot order is correct, the issue is likely with the boot configuration. Booting into the recovery environment and repairing the boot configuration is the appropriate next step.",
      "examTip": "Repair the boot configuration if BIOS sees the drive but no operating system is found."
    },
    {
      "id": 35,
      "question": "You are working on a system that uses BitLocker. The owner forgot their password, and also lost their recovery key. What can you do?",
      "options": [
        "Use a password reset tool.",
        "Reinstall the operating system and restore from a backup. Without the password or recovery key, the data is unrecoverable.",
        "Contact Microsoft for assistance.",
        "Format the drive."
      ],
      "correctAnswerIndex": 1,
      "explanation": "BitLocker is designed to protect data. Without the password or recovery key, the data remains encrypted and is unrecoverable.",
      "examTip": "Without the BitLocker password or recovery key, the encrypted data cannot be accessed."
    },
    {
      "id": 36,
      "question": "A user calls in complaining that sometimes when they print, the printer prints random characters instead of the document. They are using a USB printer, and the cable is connected securely. You have already reinstalled the print driver. What should you check NEXT?",
      "options": [
        "Check the toner levels.",
        "Run a virus scan.",
        "Try a different USB port and, if possible, a different USB cable. Also check for any physical damage on the printer. Finally attempt to update the printer's firmware.",
        "Restart the print spooler."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Random characters often indicate a communication issue, so checking the physical connection (USB port, cable) and updating the firmware is the next step.",
      "examTip": "If printing issues persist after reinstalling drivers, verify physical connections and update firmware."
    },
    {
      "id": 37,
      "question": "A user calls complaining that their computer blue screens every time on boot. They can get into Safe Mode. What would be the best way to determine what is causing the computer to blue screen?",
      "options": [
        "Event Viewer",
        "MSCONFIG",
        "Resource Monitor",
        "WinDbg Preview and analyze the dump file"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Analyzing the memory dump (minidump) using WinDbg Preview provides detailed insights into the cause of the blue screen.",
      "examTip": "Use WinDbg to analyze the memory dump file from a BSOD for detailed diagnostics."
    },
    {
      "id": 38,
      "question": "A computer has multiple hard drives but will not boot and displays 'No Operating System Found.' The BIOS detects the drives, and the boot order is correct. What is the next step?",
      "options": [
        "Replace the hard drive.",
        "Reinstall the operating system.",
        "Boot to installation media, enter the recovery environment, and attempt to repair the boot configuration.",
        "Run a virus scan."
      ],
      "correctAnswerIndex": 2,
      "explanation": "If the BIOS sees the drives and the boot order is correct, the problem likely lies with the boot configuration. The next step is to repair the boot configuration using recovery media.",
      "examTip": "If BIOS detects the drive but no OS is found, use recovery tools to repair the boot configuration."
    },
    {
      "id": 39,
      "question": "A technician is working on a system with BitLocker enabled. The owner forgot their BitLocker password and lost the recovery key. What can the technician do to access the data?",
      "options": [
        "Use a password reset tool.",
        "Reinstall the operating system and restore from a backup. Without the password or recovery key, the data is unrecoverable.",
        "Contact Microsoft for assistance.",
        "Format the drive."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Without the BitLocker password or recovery key, the data remains encrypted and is unrecoverable.",
      "examTip": "BitLocker encryption is strong; without the password or recovery key, the data cannot be accessed."
    },
    {
      "id": 40,
      "question": "A user calls complaining that sometimes when they print, the printer prints random characters instead of the document. They are using a USB printer, and the cable is connected securely. You have already reinstalled the print driver. What should you check NEXT?",
      "options": [
        "Check the toner levels.",
        "Run a virus scan.",
        "Try a different USB port and cable, and check for physical damage on the printer. Update the printer's firmware if available.",
        "Restart the print spooler."
      ],
      "correctAnswerIndex": 2,
      "explanation": "This is similar to a previous printing issue; after reinstalling the driver, the next step is to check the physical connection and update firmware.",
      "examTip": "Investigate physical connection issues and update firmware if printing random characters persists."
    },
    {
      "id": 41,
      "question": "A computer suddenly shuts off with no warning or error codes, and it does so frequently. RAM is good, CPU temperatures are normal, and the system is lightly loaded. What is the likely cause?",
      "options": [
        "Motherboard or PSU",
        "CPU",
        "Hard Drive",
        "GPU"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Frequent, sudden shutdowns with no error messages typically point to power issues or motherboard faults.",
      "examTip": "Investigate the PSU and motherboard when a computer shuts off suddenly without warning."
    },
    {
      "id": 42,
      "question": "A technician is called in to work on a computer, and they get shocked when touching the case. What is the likely cause?",
      "options": [
        "Bad power supply.",
        "Improper grounding of the electrical outlet, or a faulty power supply.",
        "Bad RAM.",
        "Bad motherboard."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A shock when touching the computer case indicates improper grounding or a faulty power supply.",
      "examTip": "If you get shocked by a computer case, check for proper grounding and test the PSU."
    },
    {
      "id": 43,
      "question": "A user reports that anytime they go to a website with video, the video plays very choppy, and the audio is out of sync. What is the MOST likely cause?",
      "options": [
        "The user's network connection is slow or unstable.",
        "Outdated or incompatible video drivers, insufficient system resources (especially RAM or GPU), or a misconfigured media player.",
        "The user's computer has a virus.",
        "The website's server is overloaded."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Choppy video playback and audio sync issues are most often due to local performance problems such as outdated drivers or insufficient resources.",
      "examTip": "Check for updated video drivers, verify system resource availability, and review media player settings when troubleshooting video playback issues."
    },
    {
      "id": 44,
      "question": "A user reports that their Windows computer is experiencing network connectivity problems. `ipconfig /all` shows a valid IP configuration, and you can ping local devices, but you cannot access any websites. `nslookup` commands consistently fail to resolve domain names. What is the MOST likely cause, and how would you confirm your suspicion?",
      "options": [
        "The user's web browser is corrupted.",
        "The DNS Client service (Dnscache) on the user's computer is stopped or malfunctioning, or there's a problem with the configured DNS servers themselves. Use `nslookup` to query different DNS servers (e.g., 8.8.8.8, 1.1.1.1) and check the DNS Client service status.",
        "The user's network cable is faulty.",
        "The user's computer has a virus."
      ],
      "correctAnswerIndex": 1,
      "explanation": "If network configuration is valid and local connectivity works but DNS resolution fails, the issue likely lies with the DNS Client service or DNS server settings. Testing with alternative DNS servers can help confirm the cause.",
      "examTip": "When DNS resolution fails despite valid IP settings, verify the DNS Client service and test with different DNS servers using `nslookup`."
    },
    {
      "id": 45,
      "question": "A technician is plugging in an external hard drive. It has a USB-C port on the drive, and a USB-C port on the computer. Upon plugging in the drive, the system becomes unresponsive. After a reboot, the system displays a message about over current on the USB port. What could be the cause?",
      "options": [
        "Faulty Motherboard",
        "The USB-C cable is likely only rated for power, and not data. Use a cable rated for both power and data.",
        "Faulty hard drive",
        "Faulty RAM"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A USB-C cable that supports only power may not properly handle data transmission, leading to over current errors.",
      "examTip": "If you encounter over current errors with USB-C devices, try a cable that supports both power and data."
    },
    {
      "id": 46,
      "question": "A user is trying to go to your company's website and receives an error 'This site can't be reached, DNS_PROBE_FINISHED_NXDOMAIN.' You can access the website fine. What is likely the cause?",
      "options": [
        "Server is down",
        "Firewall is blocking the user",
        "User has a bad network cable",
        "User has a bad DNS server or the DNS record is incorrect"
      ],
      "correctAnswerIndex": 3,
      "explanation": "NXDOMAIN errors indicate that the domain name could not be resolved, pointing to a DNS configuration issue on the user's side.",
      "examTip": "NXDOMAIN typically signals a DNS problem; check the user's DNS server settings."
    },
    {
      "id": 47,
      "question": "A computer suddenly shuts off with no warning or error codes, and it does this often. RAM has been tested and is good, CPU temperatures are normal, and the system is lightly loaded. What is the likely cause?",
      "options": [
        "Motherboard or PSU",
        "CPU",
        "Hard Drive",
        "GPU"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Sudden shutdowns without warning are usually due to power issues (PSU) or motherboard faults.",
      "examTip": "Investigate the PSU and motherboard when a computer shuts down unexpectedly."
    },
    {
      "id": 48,
      "question": "A technician is called in to work on a computer, and they get shocked when touching the case. What is the likely cause?",
      "options": [
        "Bad power supply.",
        "Improper grounding of the electrical outlet, or a faulty power supply.",
        "Bad RAM.",
        "Bad motherboard."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Getting shocked when touching a computer case typically indicates a grounding issue or a faulty power supply.",
      "examTip": "If a computer case shocks you, check for proper grounding and test the power supply."
    },
    {
      "id": 49,
      "question": "A user reports that anytime they go to a website with video, the video plays very choppy, and the audio is out of sync. What is the MOST likely cause?",
      "options": [
        "The user's network connection is slow or unstable.",
        "Outdated or incompatible video drivers, insufficient system resources (especially RAM or GPU), or a misconfigured media player.",
        "The user's computer has a virus.",
        "The website's server is overloaded."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Choppy video and out-of-sync audio are typically due to local system issues such as outdated drivers or insufficient resources, rather than network problems, assuming basic connectivity is working.",
      "examTip": "When video playback is choppy, check for updated video drivers and verify that the system has sufficient resources."
    },
    {
      "id": 50,
      "question": "A computer will power on, the fans spin, but there is no display, and no POST beeps. You've verified the monitor and cable are working. What is the MOST likely cause?",
      "options": [
        "Operating system corruption.",
        "Faulty RAM.",
        "Hard drive failure.",
        "Motherboard, CPU, or RAM failure (or potentially a PSU issue, though the fans spinning makes that slightly less likely). A complete lack of POST beeps can sometimes indicate a severe motherboard or CPU problem.",
        "PSU Failure"
      ],
      "correctAnswerIndex": 3,
      "explanation": "No display and no POST beeps typically indicate a fundamental hardware issue occurring before the OS loads—commonly a motherboard, CPU, or RAM failure. Although PSU issues are possible, the fans spinning make a complete PSU failure less likely.",
      "examTip": "A lack of POST beeps and no display usually point to severe hardware issues (motherboard, CPU, or RAM); systematically test or swap components to isolate the cause."
    }
  ]
});



















db.tests.insertOne({
  "category": "aplus2",
  "testId": 10,
  "testName": "Practice Test #10 (Ultra Level)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 51,
      "question": "A user reports that their Windows computer is displaying a message stating, 'Operating System Not Found' when they try to boot the system.  You've verified that the hard drive is detected in the BIOS/UEFI settings, and the boot order is correct. What are some potential causes, and what troubleshooting steps would you take?",
      "options": [
        "The monitor cable is disconnected.",
        "The keyboard is not working.",
        "The network cable is unplugged.",
        "The boot sector on the hard drive is corrupted or missing, the BCD (Boot Configuration Data) store is corrupted or missing, the active partition is not set correctly, or the Master Boot Record (MBR) is damaged (on older systems). Troubleshooting steps: Boot from Windows installation media, enter the Recovery Environment, and try Startup Repair. If that fails, use `bootrec` commands (`/fixmbr`, `/fixboot`, `/rebuildbcd`). In more complex cases, you might need to use `bcdedit` to manually configure the BCD. If those fail, you might need to consider data recovery and a clean OS installation."
      ],
      "correctAnswerIndex": 3,
      "explanation": "An 'Operating System Not Found' error, when the hard drive is detected and the boot order is correct, indicates a problem with the boot files or the boot configuration on the hard drive. The most common causes are: Corrupted or Missing Boot Sector, Corrupted or Missing BCD, Incorrect Active Partition, or a Damaged MBR (on older systems). Troubleshooting steps involve booting from Windows installation media, entering the Recovery Environment, and using tools like Startup Repair, bootrec commands, and possibly bcdedit.",
      "examTip": "The 'Operating System Not Found' error often indicates a problem with the boot sector, BCD, or active partition; use the Windows Recovery Environment and tools like bootrec and bcdedit to attempt repairs."
    },
    {
      "id": 52,
      "question": "You are troubleshooting a network connectivity issue on a Linux server. The server has multiple network interfaces. You need to determine the specific network interface that is currently being used as the default gateway for outgoing traffic. Which command is BEST suited for this task, and how would you interpret the output?",
      "options": [
        "ifconfig",
        "ip addr show",
        "route -n",
        "ip route show | grep default"
      ],
      "correctAnswerIndex": 3,
      "explanation": "The command `ip route show | grep default` displays the default route along with the associated interface. For example, an output like `default via 192.168.1.1 dev eth0` tells you that 192.168.1.1 is the default gateway and `eth0` is the interface used.",
      "examTip": "Use `ip route show | grep default` on Linux to quickly identify the default gateway and the network interface it's using."
    },
    {
      "id": 53,
      "question": "You are configuring a new Windows computer and want to ensure that the system clock is automatically and accurately synchronized with a reliable time source. You know that Windows uses the Windows Time service (w32time) for this purpose. What are some of the key command-line options for the `w32tm` utility that you can use to configure and troubleshoot time synchronization?",
      "options": [
        "`w32tm /register` and `w32tm /unregister`",
        "`w32tm /query /source`, `w32tm /config /manualpeerlist:<peers> /syncfromflags:manual /reliable:yes`, `w32tm /resync`, and `w32tm /monitor`",
        "`w32tm /stripchart`",
        "All of the above"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Key options include: `w32tm /query /source` to show the current time source; `w32tm /config /manualpeerlist:<peers> /syncfromflags:manual /reliable:yes` to configure synchronization with specific NTP servers; `w32tm /resync` to force a time sync; and `w32tm /monitor` to monitor synchronization status.",
      "examTip": "Familiarize yourself with `w32tm` options for configuring and troubleshooting time synchronization in Windows."
    },
    {
      "id": 54,
      "question": "A user reports that their Windows computer is exhibiting very slow performance when accessing files on a network share. Other users are not experiencing the same problem. You've verified basic network connectivity (ping, nslookup), and the user has the correct permissions to access the share. You suspect a problem specific to the SMB (Server Message Block) protocol on the user's computer. What is a specific Windows feature, related to SMB and file sharing, that could be causing the slowdown, and how would you check its status and potentially disable it?",
      "options": [
        "The Windows Firewall.",
        "Offline Files (Client-Side Caching or CSC) might be enabled, and the synchronization process might be causing the slowdown. Check the status of Offline Files in the Sync Center and, if necessary, disable it for the specific share or entirely.",
        "The DNS Client service.",
        "The DHCP Client service."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Offline Files caches network files for offline access. If it malfunctions or the synchronization process is slow or corrupted, it can slow file access even if the network is functioning correctly.",
      "examTip": "Check the Sync Center in Windows to determine if Offline Files is affecting network share performance."
    },
    {
      "id": 55,
      "question": "You are investigating a security incident where an attacker might have gained unauthorized access to a Linux server. You want to see a list of all user accounts on the system, including those that might be hidden or not typically used for interactive logins. Which command is BEST suited for this task, and what are some specific techniques attackers might use to hide user accounts on a Linux system?",
      "options": [
        "ls -l /home",
        "cat /etc/passwd (and potentially examine /etc/shadow for password hashes). Attackers might create accounts with names similar to existing system accounts, use names that start with a dot to hide them, or modify /etc/passwd and /etc/shadow directly.",
        "who",
        "last"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The /etc/passwd file lists all user accounts on a Linux system, including system accounts and those not used for interactive logins. Attackers might hide accounts by using names that start with a dot or ones that closely mimic system accounts.",
      "examTip": "Examine /etc/passwd (and /etc/shadow) on Linux to list all user accounts and detect potentially hidden ones."
    },
    {
      "id": 56,
      "question": "You are troubleshooting a Windows computer that is not booting. You receive an error that bootmgr is missing or corrupt. You attempt to use the recovery console with a Windows installation disk, but the system will not boot to the disk. What should you verify?",
      "options": [
        "Verify the hard drive is functional",
        "Verify the optical drive is functional and that the BIOS/UEFI is set to boot to the optical drive first.",
        "Verify the monitor is functional",
        "Verify the RAM is functional"
      ],
      "correctAnswerIndex": 1,
      "explanation": "If the system will not boot from the installation media, you must ensure the optical drive is working and the BIOS/UEFI boot order is set to boot from it first.",
      "examTip": "Verify the optical drive and boot order if the system will not boot from installation media."
    },
    {
      "id": 57,
      "question": "You are troubleshooting a server and believe there to be an issue with a network card. You have already updated drivers. What would be the next best action to take?",
      "options": [
        "Replace the network card",
        "Run diagnostics on the network card. If possible, test the card in a different system, or test with a known-good network card in the original system. Also, check Event Viewer logs and consider using a cable tester.",
        "Restart the server",
        "Reinstall the OS"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Before replacing the network card, further diagnostics (such as testing in another system, checking logs, or using a cable tester) should be performed to confirm the issue.",
      "examTip": "Test hardware components in another system or swap in a known-good card to isolate network issues."
    },
    {
      "id": 58,
      "question": "A technician is working on a computer, and they smell a burning smell. They immediately unplug the computer. What should the technician do NEXT?",
      "options": [
        "Turn the computer back on to see if it boots.",
        "Visually inspect the internal components for signs of damage (burned components, melted plastic, etc.). If the source is not immediately obvious, systematically test or replace components as needed.",
        "Replace the hard drive.",
        "Replace the RAM."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A burning smell indicates likely internal damage. The technician should inspect for damage before attempting to power the computer on.",
      "examTip": "A burning smell is a serious warning; immediately unplug the system and inspect for damage."
    },
    {
      "id": 59,
      "question": "A computer you are working on has an Intel processor. What built in feature allows the processor to run multiple operating systems simultaneously?",
      "options": [
        "Hyper-V",
        "Hyperthreading",
        "VT-x",
        "Virtual PC"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Intel VT-x is the hardware virtualization technology that allows a processor to efficiently support multiple virtual machines. Hyperthreading improves multitasking but does not provide virtualization.",
      "examTip": "Ensure Intel VT-x is enabled in the BIOS/UEFI for optimal virtualization performance."
    },
    {
      "id": 60,
      "question": "You are troubleshooting a network connectivity issue on a Windows computer. A computer can access some websites but not others. Pings and nslookup work for all websites. The user's 'hosts' file is clean, and basic firewall settings appear correct. The problem is isolated to this one computer; other devices can access all websites. What is a very specific Windows networking component, often associated with security software or VPNs, that could be selectively interfering with network traffic after DNS resolution and before it reaches the web browser, and how would you investigate it?",
      "options": [
        "The Windows Registry.",
        "A corrupted web browser.",
        "A misconfigured or malicious LSP (Layered Service Provider). Use `netsh winsock show catalog` to list installed LSPs. Investigate any unfamiliar entries. You can also try `netsh winsock reset`.",
        "The DNS Client service is stopped."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A misconfigured or malicious LSP can intercept and modify network traffic after DNS resolution. The Winsock catalog can be viewed with `netsh winsock show catalog` and reset with `netsh winsock reset` if needed.",
      "examTip": "Inspect the Winsock catalog for suspicious LSPs using `netsh winsock show catalog` if selective network issues occur."
    },
    {
      "id": 61,
      "question": "You are working on a Linux server and need to examine the kernel's message buffer for recent system messages, including hardware detection, driver loading, and kernel errors. Which command is specifically designed for this purpose?",
      "options": [
        "journalctl",
        "dmesg",
        "syslog",
        "messages"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`dmesg` prints the kernel's ring buffer, which includes messages from hardware detection, driver loading, and kernel errors.",
      "examTip": "Use `dmesg` on Linux to view the kernel message buffer for troubleshooting."
    },
    {
      "id": 62,
      "question": "You are troubleshooting a Windows computer that is experiencing intermittent Blue Screen of Death (BSOD) errors. You've obtained the memory dump file (.dmp) from a recent crash and are using WinDbg to analyze it. You run the `!analyze -v` command, and the output indicates a likely cause of `DRIVER_IRQL_NOT_LESS_OR_EQUAL` with a specific driver file implicated (e.g., `ntkrnlmp.exe`). What does this error typically indicate, and what are some common causes?",
      "options": [
        "A problem with the hard drive.",
        "A problem with network connectivity.",
        "This error typically indicates that a kernel-mode driver attempted to access paged-out memory at an IRQL that was too high. Common causes include faulty or incompatible device drivers, memory corruption, or hardware problems.",
        "A problem with the user's web browser."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The DRIVER_IRQL_NOT_LESS_OR_EQUAL error indicates that a kernel-mode driver accessed memory at an invalid IRQL. This is most commonly due to a faulty or incompatible driver, memory corruption, or hardware issues.",
      "examTip": "Investigate drivers, memory, and hardware when you see DRIVER_IRQL_NOT_LESS_OR_EQUAL BSOD errors."
    },
    {
      "id": 63,
      "question": "You are investigating a potential security incident on a Linux server. You suspect that an attacker might have used a technique called 'log tampering' to cover their tracks. What does 'log tampering' mean, and what are some techniques you can use to detect or prevent it?",
      "options": [
        "Log tampering means encrypting log files.",
        "Log tampering involves modifying or deleting log files to hide evidence of malicious activity. Techniques to detect or prevent it include using a centralized log server, implementing file integrity monitoring, and configuring logs to be write-once.",
        "Log tampering means backing up log files.",
        "Log tampering means compressing log files to save disk space."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Log tampering is when an attacker alters or deletes log files to hide their activities. Preventative measures include centralized logging, file integrity monitoring, and using write-once logs.",
      "examTip": "Implement centralized logging and file integrity monitoring to help detect and prevent log tampering."
    },
    {
      "id": 64,
      "question": "You are troubleshooting a Windows computer that is exhibiting slow performance. You open Task Manager and notice that a process named `SearchIndexer.exe` (or related processes) is consuming a significant amount of CPU and disk I/O. What is the normal function of these processes, and in what situations might they legitimately cause high resource utilization? What troubleshooting steps could you consider?",
      "options": [
        "These processes are related to a web browser; high resource usage is normal.",
        "These processes are part of the Windows Search service, which indexes files for faster search. High resource usage is normal during initial indexing or after large file changes. Troubleshooting steps include rebuilding the search index or excluding certain folders from indexing.",
        "These processes are related to network connectivity; high resource usage indicates a network problem.",
        "These processes are part of the Windows Update service; high resource usage indicates updates are being installed."
      ],
      "correctAnswerIndex": 1,
      "explanation": "SearchIndexer.exe and its related processes belong to the Windows Search service. They index files to facilitate faster searches, and high resource usage is expected during the initial indexing process or after significant file changes.",
      "examTip": "If Windows Search processes cause high resource usage, consider rebuilding the index or adjusting indexing options."
    },
    {
      "id": 65,
      "question": "You are configuring a web server to use HTTPS. You have a valid SSL/TLS certificate and private key. You are using Nginx as your web server. What are the essential directives you need to include in your Nginx configuration file to enable HTTPS and use the certificate?",
      "options": [
        "`listen 80;` and `root /var/www/html;`",
        "`listen 443 ssl;`, `ssl_certificate /path/to/your/certificate.crt;`, `ssl_certificate_key /path/to/your/private.key;`, and a server block configured for your domain.",
        "`server_name example.com;` and `index index.html;`",
        "`error_log /var/log/nginx/error.log;` and `access_log /var/log/nginx/access.log;`"
      ],
      "correctAnswerIndex": 1,
      "explanation": "For HTTPS in Nginx, you need to set the server block to listen on port 443 with SSL enabled, and specify the paths to your SSL certificate and private key.",
      "examTip": "Ensure your Nginx configuration includes `listen 443 ssl;`, `ssl_certificate`, and `ssl_certificate_key` for HTTPS."
    },
    {
      "id": 66,
      "question": "You are troubleshooting a network connectivity issue on a Linux server. A computer can access some websites but not others. Pings and nslookup work for all websites. You've checked the hosts file, firewall, proxy settings, and LSPs, and reset the TCP/IP stack. What is a very specific, low-level network parameter, related to TCP, that could be causing selective access issues, and how would you investigate it?",
      "options": [
        "The computer's hostname.",
        "A problem with TCP window scaling or other TCP parameters. Use Wireshark to capture traffic for both successful and unsuccessful connections and compare TCP options, window sizes, and signs of packet loss.",
        "The computer's default gateway.",
        "The computer's DNS server settings."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Advanced TCP parameters, such as window scaling, can affect connectivity. Using Wireshark to analyze TCP handshakes and options can reveal subtle differences that might cause selective access issues.",
      "examTip": "Use Wireshark to analyze TCP handshakes and options if you suspect advanced TCP issues affecting connectivity."
    },
    {
      "id": 67,
      "question": "You are working on a Linux server and need to determine the complete command line used to launch a running process (including all arguments). Given the process ID (e.g., 1234), which command is BEST suited for this task?",
      "options": [
        "ps -ef | grep 1234",
        "top -p 1234",
        "cat /proc/1234/cmdline",
        "lsof -p 1234"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The file `/proc/1234/cmdline` contains the full command line that was used to launch the process with PID 1234.",
      "examTip": "Use `cat /proc/<PID>/cmdline` on Linux to retrieve the full command line for a process."
    },
    {
      "id": 68,
      "question": "You are investigating a potential security incident on a Windows server. You want to see a list of all network shares on the server, including hidden shares. Which command-line tool is BEST suited for this task?",
      "options": [
        "net view",
        "net share",
        "netstat",
        "nbtstat"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `net share` command lists all shared resources on a Windows system, including hidden shares (those ending with a '$').",
      "examTip": "Use `net share` to list all shared resources on a Windows server, including hidden ones."
    },
    {
      "id": 69,
      "question": "You are troubleshooting a network connectivity issue on a Windows computer that intermittently cannot access network resources despite having valid IP configuration. You suspect a problem with the network adapter or its driver. What is a more advanced technique using built-in Windows tools to diagnose intermittent network adapter issues?",
      "options": [
        "Reinstall the network adapter driver.",
        "Use the Network Adapter Troubleshooter in Windows.",
        "Enable and analyze the 'Microsoft-Windows-NDIS-PacketCapture' provider in Event Tracing for Windows (ETW) using tools like `netsh trace` to capture detailed network adapter events.",
        "Run System Restore."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Using ETW with the 'Microsoft-Windows-NDIS-PacketCapture' provider (via tools like `netsh trace`) enables detailed capture of network adapter events, which is invaluable for diagnosing intermittent issues.",
      "examTip": "For advanced network adapter troubleshooting in Windows, use ETW tracing with the NDIS-PacketCapture provider."
    },
    {
      "id": 70,
      "question": "You are investigating a potential security incident on a Windows computer. You want to see a list of all currently logged-on user sessions, including local, Remote Desktop, and network share sessions. Which command-line tool is BEST suited for this task?",
      "options": [
        "net user",
        "query user /server:<servername> (or quser)",
        "tasklist",
        "netstat"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `query user` (or `quser`) command displays detailed information about all user sessions on a Windows computer, including session state and logon time.",
      "examTip": "Use `query user` (or `quser`) to list all active user sessions on a Windows computer."
    },
    {
      "id": 71,
      "question": "You are troubleshooting a network connectivity issue on a Linux server. The server has multiple network interfaces. You need to determine which interface is used as the default gateway for outgoing traffic. Which command is BEST suited for this?",
      "options": [
        "ifconfig",
        "ip addr show",
        "ip route show | grep default",
        "netstat -r"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Using `ip route show | grep default` displays the default route and the associated interface used for outgoing traffic.",
      "examTip": "Use `ip route show | grep default` on Linux to identify the default gateway and its corresponding interface."
    },
    {
      "id": 72,
      "question": "You are investigating a potential security incident on a Windows computer. You suspect that malware might have installed a malicious Layered Service Provider (LSP) to intercept network traffic. Which command can you use to display the list of installed LSPs, and how can you reset them if necessary?",
      "options": [
        "ipconfig /all",
        "netsh winsock show catalog",
        "netstat -ano",
        "tasklist"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The command `netsh winsock show catalog` displays the list of installed LSPs. To reset them, you can use `netsh winsock reset`.",
      "examTip": "Use `netsh winsock show catalog` to view installed LSPs and `netsh winsock reset` to reset the Winsock catalog if necessary."
    },
    {
      "id": 73,
      "question": "You are investigating a potential security incident on a Linux server. You need to monitor disk I/O activity in real-time, broken down by process, to identify potential performance issues or malicious activity. Which command is BEST suited for this task?",
      "options": [
        "top",
        "free -m",
        "df -h",
        "iotop"
      ],
      "correctAnswerIndex": 3,
      "explanation": "`iotop` is specifically designed for real-time monitoring of disk I/O activity on a per-process basis in Linux.",
      "examTip": "Use `iotop` on Linux to monitor disk I/O activity by process."
    },
    {
      "id": 74,
      "question": "You are investigating a potential security incident on a Windows computer. You suspect that malware might be using a technique called 'process hollowing' to hide its activities. What is process hollowing, and how might you detect it using a combination of tools?",
      "options": [
        "Process hollowing is a type of social engineering attack.",
        "Process hollowing is a technique where an attacker creates a legitimate process in a suspended state, removes its memory, and replaces it with malicious code. Use Process Explorer and Process Monitor to detect discrepancies.",
        "Process hollowing is a type of denial-of-service attack.",
        "Process hollowing is a technique for optimizing application performance."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Process hollowing involves creating a legitimate process in a suspended state, hollowing out its memory, and injecting malicious code so that the malicious code runs under the guise of the legitimate process. Tools such as Process Explorer and Process Monitor can help detect anomalies between the process's on-disk image and its in-memory image.",
      "examTip": "Use Process Explorer and Process Monitor to detect discrepancies that may indicate process hollowing."
    },
    {
      "id": 75,
      "question": "You are troubleshooting a network connectivity issue on a Windows computer. A computer can access local network resources but cannot access any internet resources. `ipconfig /all` shows a valid IP configuration, but `nslookup` fails to resolve domain names. What is the MOST likely cause?",
      "options": [
        "The computer's network cable is unplugged.",
        "The computer's web browser is corrupted.",
        "The DNS Client service (Dnscache) is malfunctioning or stopped, or the configured DNS servers are unreachable. Verify the status of the DNS Client service and test with alternative DNS servers using nslookup.",
        "The computer has a virus."
      ],
      "correctAnswerIndex": 2,
      "explanation": "When local connectivity is fine but DNS resolution fails, the issue is typically with the DNS Client service or the DNS server configuration. Testing with different DNS servers helps isolate the problem.",
      "examTip": "If DNS resolution fails despite valid IP settings, verify the DNS Client service and test with alternative DNS servers using nslookup."
    },
    {
      "id": 76,
      "question": "You are investigating a potential security incident on a Windows computer. You want to determine if an attacker has installed a malicious kernel module. Which command is BEST suited for listing all currently loaded kernel modules, and what should you look for?",
      "options": [
        "ps aux",
        "ls -l /proc/modules",
        "lsmod",
        "dmesg"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The `lsmod` command lists all currently loaded kernel modules on a Linux system. (Note: While Windows does not use lsmod, this question appears in the context of a mixed environment.) When investigating a Windows system, you would use tools like Driver Verifier or Process Explorer; however, in Linux, lsmod is used to check for suspicious or unexpected modules.",
      "examTip": "Use lsmod on Linux to check for unexpected kernel modules; for Windows, consider using tools like Driver Verifier and Process Explorer."
    },
    {
      "id": 77,
      "question": "You are investigating a potential security incident on a Windows computer. You suspect that an attacker might have installed a malicious scheduled task to maintain persistence. Which command-line tool is BEST suited for enumerating all scheduled tasks, including those that may not be visible in the Task Scheduler GUI?",
      "options": [
        "tasklist",
        "schtasks /query /fo LIST /v",
        "msconfig",
        "netstat"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `schtasks /query /fo LIST /v` command displays all scheduled tasks with detailed information in a list format, including those that might be hidden from the GUI.",
      "examTip": "Use `schtasks /query /fo LIST /v` on Windows to enumerate all scheduled tasks and identify potential persistence mechanisms."
    },
    {
      "id": 78,
      "question": "You are investigating a potential security incident on a Windows computer. You need to view the kernel's routing table in detail, including numeric IP addresses, associated interfaces, and route metrics. Which command is BEST suited for this task?",
      "options": [
        "ifconfig",
        "ip addr show",
        "route -n",
        "ip route show"
      ],
      "correctAnswerIndex": 3,
      "explanation": "`ip route show` is the modern and preferred command on Linux to display the kernel's routing table with numeric addresses, interfaces, and metrics.",
      "examTip": "Use `ip route show` on Linux to view a detailed routing table with numeric information."
    },
    {
      "id": 79,
      "question": "You are investigating a potential security incident on a Windows computer. You want to verify the integrity of a critical system file (e.g., kernel32.dll). Which built-in command-line tool can you use to compute the cryptographic hash of the file, and how would you use it?",
      "options": [
        "certutil -hashfile kernel32.dll MD5",
        "sigcheck -h kernel32.dll",
        "fc /b kernel32.dll",
        "checksum kernel32.dll"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `certutil` command with the `-hashfile` option computes a file's cryptographic hash. For example, `certutil -hashfile kernel32.dll MD5` will generate the MD5 hash of the file.",
      "examTip": "Use `certutil -hashfile <filename> <hash algorithm>` on Windows to verify file integrity by comparing hashes."
    },
    {
      "id": 80,
      "question": "You are investigating a potential security incident on a Linux server and need to monitor disk I/O activity in real-time, broken down by process. Which command is BEST suited for this task?",
      "options": [
        "top",
        "free -m",
        "df -h",
        "iotop"
      ],
      "correctAnswerIndex": 3,
      "explanation": "`iotop` is specifically designed for real-time monitoring of disk I/O activity per process on Linux.",
      "examTip": "Use `iotop` to identify processes with high disk I/O on Linux."
    },
    {
      "id": 81,
      "question": "You are investigating a potential security incident on a Windows computer. You suspect that malware might be using a technique called 'process hollowing' to hide its activities. What is process hollowing, and how might you detect it using a combination of tools?",
      "options": [
        "Process hollowing is a type of social engineering attack.",
        "Process hollowing is a technique where an attacker creates a legitimate process in a suspended state, unmaps its memory, and replaces it with malicious code. Use Process Explorer and Process Monitor to detect discrepancies.",
        "Process hollowing is a type of denial-of-service attack.",
        "Process hollowing is a technique for optimizing application performance."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Process hollowing involves creating a legitimate process in a suspended state, hollowing out its memory, and injecting malicious code so that the code runs within a trusted process. Tools such as Process Explorer and Process Monitor can help detect such anomalies.",
      "examTip": "Use Process Explorer and Process Monitor to compare the in-memory image of a process to its on-disk image to detect process hollowing."
    },
    {
      "id": 82,
      "question": "You are investigating a potential security incident on a Windows computer. You need to check the integrity of a critical system file (e.g., kernel32.dll) against a known-good baseline. Without a pre-existing baseline, what manual technique can you use, and what are its limitations?",
      "options": [
        "Check file permissions with ls -l",
        "Manually compare checksums of critical files (using md5sum or sha256sum) against known-good checksums from a trusted source. Limitations include the need for a reliable baseline and the manual effort required.",
        "Use ps aux to view running processes",
        "Examine /var/log/auth.log for suspicious activity"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Manually comparing file checksums is a valid technique for verifying file integrity, but it is time-consuming and relies on having access to trustworthy known-good hashes.",
      "examTip": "Manually verify file integrity by comparing checksums, but this method is labor-intensive without a pre-established baseline."
    },
    {
      "id": 83,
      "question": "You are investigating a potential security incident on a Windows computer. You want to determine the fully qualified domain name (FQDN) of the system. Which command-line tool provides this information most directly?",
      "options": [
        "ipconfig /all",
        "hostname",
        "systeminfo | findstr /C:\"Domain\"",
        "PowerShell: [System.Net.Dns]::GetHostByName(($env:computername)).HostName"
      ],
      "correctAnswerIndex": 3,
      "explanation": "While several commands show parts of the information, the provided PowerShell command returns the FQDN directly in a clear manner.",
      "examTip": "Use PowerShell to retrieve the fully qualified domain name of a Windows computer."
    },
    {
      "id": 84,
      "question": "You are investigating a potential security incident on a Linux server. You suspect that an attacker might have modified critical system files to install a backdoor. Without a pre-existing file integrity baseline, what manual technique can you use to verify file integrity, and what are its limitations?",
      "options": [
        "Check file sizes with ls -l",
        "Manually compare checksums of critical files (using md5sum or sha256sum) against known-good checksums from a trusted source. Limitations include reliance on having a trustworthy baseline and the manual effort required.",
        "Use ps aux to view running processes",
        "Examine /var/log/auth.log for suspicious login attempts"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Manually comparing checksums is a valid approach to verify file integrity, but it is time-consuming and depends on having a trusted source of known-good checksums.",
      "examTip": "Manually verify file integrity by comparing checksums, but note that this approach is labor-intensive without a pre-existing baseline."
    },
    {
      "id": 85,
      "question": "You are investigating a potential security incident on a Windows computer and need to determine the exact version and build number of the operating system, including service packs and updates. Which command-line tool provides this information in a concise manner?",
      "options": [
        "systeminfo",
        "winver",
        "ver",
        "msinfo32"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The winver command displays a dialog with the Windows version, build number, and service pack information in a clear format.",
      "examTip": "Use winver to quickly determine the Windows version, build number, and service pack level."
    },
    {
      "id": 86,
      "question": "You are investigating a potential security incident on a Linux server. You suspect that an attacker may have modified critical system files to install a backdoor. You don't have a pre-existing file integrity baseline. What manual technique can you use to verify file integrity, and what are its limitations?",
      "options": [
        "Use ls -l to check file sizes",
        "Manually compare checksums (using md5sum or sha256sum) of critical files against known-good values from a trusted source. Limitations include the need for a reliable baseline and the manual process involved.",
        "Run ps aux to check running processes",
        "Examine /var/log/syslog for file changes"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Manually comparing checksums is a valid method for verifying file integrity; however, it requires a trusted source of known-good checksums and is a manual, time-consuming process.",
      "examTip": "Manually compare checksums to verify file integrity, but be aware of its limitations without a pre-established baseline."
    },
    {
      "id": 87,
      "question": "You are investigating a potential security incident on a Windows computer. You suspect that malware might have installed a malicious scheduled task to maintain persistence. Which command-line tool is BEST suited for enumerating all scheduled tasks, including those that may not be visible in the Task Scheduler GUI?",
      "options": [
        "tasklist",
        "schtasks /query /fo LIST /v",
        "msconfig",
        "netstat"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The `schtasks /query /fo LIST /v` command lists all scheduled tasks with detailed information, which helps reveal tasks that might not be visible in the GUI.",
      "examTip": "Use `schtasks /query /fo LIST /v` on Windows to enumerate all scheduled tasks and detect potential persistence mechanisms."
    },
    {
      "id": 88,
      "question": "You are investigating a potential security incident on a Windows computer. You want to check the integrity of a critical system file (e.g., kernel32.dll). Which built-in command-line tool can you use to compute the file's cryptographic hash, and how would you use it?",
      "options": [
        "certutil -hashfile kernel32.dll MD5",
        "sigcheck -h kernel32.dll",
        "fc /b kernel32.dll",
        "checksum kernel32.dll"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command `certutil -hashfile kernel32.dll MD5` computes the MD5 hash of kernel32.dll. You can replace MD5 with SHA1 or SHA256 as needed.",
      "examTip": "Use `certutil -hashfile <filename> <hash algorithm>` on Windows to verify the integrity of critical files."
    },
    {
      "id": 89,
      "question": "You are investigating a potential security incident on a Linux server and need to copy a large directory structure from one location to another while preserving all file permissions, ownership, timestamps, and symbolic links. Which command, with appropriate options, is BEST suited for this task?",
      "options": [
        "cp",
        "cp -r",
        "cp -a (or cp --preserve=all)",
        "mv"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`cp -a` (or `cp --preserve=all`) copies directories recursively while preserving all attributes, making it ideal for archiving files.",
      "examTip": "Use `cp -a` on Linux to copy directory structures while preserving all file attributes."
    },
    {
      "id": 90,
      "question": "You are investigating a potential security incident on a Windows computer. You suspect that malware might be using a technique called 'process hollowing' to hide its activities. What is process hollowing, and how might you detect it using a combination of tools?",
      "options": [
        "Process hollowing is a type of social engineering attack.",
        "Process hollowing is a technique where an attacker creates a legitimate process in a suspended state, unmaps its memory, and replaces it with malicious code. Use Process Explorer and Process Monitor to detect discrepancies.",
        "Process hollowing is a type of denial-of-service attack.",
        "Process hollowing is a technique for optimizing application performance."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Process hollowing involves creating a legitimate process in a suspended state, removing its memory, and injecting malicious code. Tools like Process Explorer and Process Monitor can help detect discrepancies between the process's in-memory image and its on-disk image.",
      "examTip": "Use Process Explorer and Process Monitor to compare the memory image of a process with its on-disk image to detect process hollowing."
    },
    {
      "id": 91,
      "question": "You are troubleshooting a Windows computer and need to determine the fully qualified domain name (FQDN) of the system. Which command-line tool provides this information most directly?",
      "options": [
        "ipconfig /all",
        "hostname",
        "systeminfo | findstr /C:\"Domain\"",
        "PowerShell: [System.Net.Dns]::GetHostByName(($env:computername)).HostName"
      ],
      "correctAnswerIndex": 3,
      "explanation": "The provided PowerShell command returns the system's fully qualified domain name (FQDN) directly and reliably.",
      "examTip": "Use PowerShell to retrieve the FQDN of a Windows computer."
    },
    {
      "id": 92,
      "question": "You are investigating a potential security incident on a Linux server. You want to check the integrity of critical system binaries against a known-good baseline, but you don't have a pre-existing baseline. What manual technique can you use, and what are its limitations?",
      "options": [
        "Check file permissions with ls -l",
        "Manually compare checksums (using md5sum or sha256sum) of critical files against known-good checksums from a trusted source. Limitations include the need for a reliable baseline and the manual effort required.",
        "Use ps aux to view running processes",
        "Examine /var/log/auth.log for suspicious activity"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Manually comparing checksums is a valid method for verifying file integrity, but it is labor-intensive and relies on having access to trustworthy known-good checksums.",
      "examTip": "Manually verify file integrity by comparing checksums, keeping in mind that this approach is time-consuming without a pre-established baseline."
    },
    {
      "id": 93,
      "question": "You are investigating a potential security incident on a Windows computer and need to determine the exact version and build number of the operating system, including service packs and updates. Which command-line tool provides this information in a concise manner?",
      "options": [
        "systeminfo",
        "winver",
        "ver",
        "msinfo32"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The winver command displays a dialog box with the Windows version, build number, and service pack information in a clear format.",
      "examTip": "Use winver to quickly determine the Windows version, build number, and service pack details."
    },
    {
      "id": 94,
      "question": "You are investigating a potential security incident on a Linux server. You suspect that an attacker may have modified critical system files to install a backdoor. What manual technique can you use to verify file integrity, and what are its limitations?",
      "options": [
        "Use ls -l to check file sizes",
        "Manually compare checksums of critical files (using md5sum or sha256sum) against known-good values from a trusted source. Limitations include reliance on a trustworthy baseline and the manual process required.",
        "Use ps aux to check running processes",
        "Examine /var/log/syslog for file changes"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Manually comparing checksums of critical files is effective for verifying file integrity, but it requires a reliable source of known-good checksums and can be very time-consuming.",
      "examTip": "Manually verify file integrity by comparing checksums, but this method is labor-intensive without a pre-established baseline."
    },
    {
      "id": 95,
      "question": "You are investigating a potential security incident on a Windows computer and need to determine the operating system's version, build number, and service pack level. Which command-line tool provides this information concisely?",
      "options": [
        "systeminfo",
        "winver",
        "ver",
        "msinfo32"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The winver command provides a concise dialog box showing the Windows version, build number, and service pack level.",
      "examTip": "Use winver to quickly determine the Windows version and build details."
    },
    {
      "id": 96,
      "question": "You are investigating a potential security incident on a Windows computer running a custom application. The application is crashing intermittently, and you suspect a race condition or other concurrency bug. Standard debugging has not revealed the cause. What advanced technique, involving modifying the application's execution environment, can help expose the bug more reliably?",
      "options": [
        "Run the application with increased memory.",
        "Run the application as a different user.",
        "Use the `strace` command to trace system calls made by the application.",
        "Use the ThreadSanitizer (TSan) tool to dynamically analyze the application's execution for data races and concurrency issues, which requires recompiling with TSan instrumentation."
      ],
      "correctAnswerIndex": 3,
      "explanation": "ThreadSanitizer (TSan) is a dynamic analysis tool that detects race conditions and other concurrency issues. It requires recompiling the application with TSan instrumentation but is highly effective in exposing subtle race conditions.",
      "examTip": "For concurrency bugs, consider using ThreadSanitizer (TSan), but be aware that it usually requires recompiling the application."
    },
    {
      "id": 97,
      "question": "You are investigating a potential security incident on a Linux server. You need to copy a large directory structure from one location to another while preserving all file permissions, ownership, timestamps, and symbolic links. Which command, with appropriate options, is BEST suited for this task?",
      "options": [
        "cp",
        "cp -r",
        "cp -a (or cp --preserve=all)",
        "mv"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The `cp -a` command (or `cp --preserve=all`) recursively copies a directory while preserving all file attributes, making it ideal for archiving files.",
      "examTip": "Use `cp -a` on Linux to copy directories while preserving permissions, ownership, timestamps, and symbolic links."
    },
    {
      "id": 98,
      "question": "You are investigating a potential security incident on a Windows computer. You suspect that malware might be using a technique called 'process hollowing' to hide its activities. What is process hollowing, and how might you detect it?",
      "options": [
        "Process hollowing is a type of social engineering attack.",
        "Process hollowing is a technique where an attacker creates a legitimate process in a suspended state, removes its memory, and replaces it with malicious code. Use Process Explorer and Process Monitor to detect discrepancies.",
        "Process hollowing is a type of denial-of-service attack.",
        "Process hollowing is a technique for optimizing application performance."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Process hollowing is a stealthy code injection technique in which a legitimate process is created in a suspended state, its memory is cleared, and malicious code is injected. Tools like Process Explorer and Process Monitor can help detect discrepancies between a process's expected and actual memory images.",
      "examTip": "Use Process Explorer and Process Monitor to detect process hollowing by comparing the in-memory and on-disk images of processes."
    },
    {
      "id": 99,
      "question": "You are investigating a potential security incident on a Windows computer. You suspect that malware might have modified system files to install a backdoor. Without a pre-existing file integrity baseline, what manual technique can you use to check file integrity, and what are its limitations?",
      "options": [
        "Check file permissions with ls -l",
        "Manually compare checksums (using md5sum or sha256sum) of critical files against known-good checksums from a trusted source. Limitations include the need for a reliable baseline and the manual effort required.",
        "Use ps aux to view running processes",
        "Examine /var/log/auth.log for suspicious activity"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Manually comparing checksums of critical system files is a valid way to verify file integrity, but it requires a trustworthy source of known-good hashes and can be very time-consuming without an automated baseline.",
      "examTip": "Manually verify file integrity by comparing checksums, keeping in mind this method is labor-intensive without a pre-established baseline."
    },
    {
      "id": 100,
      "question": "You are investigating a potential security incident on a Windows computer running a custom application. The application is experiencing intermittent crashes, and you suspect a race condition or other concurrency bug. Standard debugging tools have not revealed the cause. What advanced technique, involving modifying the application's execution environment, can help expose the bug more reliably?",
      "options": [
        "Run the application with increased memory.",
        "Run the application as a different user.",
        "Use the `strace` command to trace system calls made by the application.",
        "Use the ThreadSanitizer (TSan) tool to dynamically analyze the application's execution for data races and concurrency issues, which requires recompiling with TSan instrumentation."
      ],
      "correctAnswerIndex": 3,
      "explanation": "ThreadSanitizer (TSan) is a dynamic analysis tool that can detect data races and concurrency bugs by instrumenting the code. It requires recompiling the application but is highly effective in exposing race conditions.",
      "examTip": "For detecting race conditions, use ThreadSanitizer (TSan) to dynamically analyze the application; note that this often requires recompiling the application with TSan instrumentation."
    }
  ]
});
